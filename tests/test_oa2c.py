"""OA2C OAuth 2.0 Client config harvesting.

Modern S/4 stores OAuth 2.0 clients in OA2C_CLIENT (CLIENT_UUID,
CLIENT_ID, TOKEN_ENDPOINT, …) joined with OA2C_CLIENT_EXT (GRANTTYPE)
on CLIENT_UUID.  The matching client_secret lives in RSECTAB under
/OA2C/CS_<CLIENT_UUID-no-hyphens>_<NN>.  These tests cover the
reader, the secstore matcher, the categoriser, and the on-prem -> BTP
harvester pickup that joins them all together.
"""
from __future__ import annotations

from unittest.mock import patch

import modules  # noqa: F401  (registers package paths)
from sap_oa2c import (
    read_oa2c_profiles, find_secret_for_profile, _normalise_uuid,
)
from sapmap_models import SAPNode, SAPMAPState
from sapmap_secstore import categorise_entry


# ---- _normalise_uuid -------------------------------------------------

def test_normalise_uuid_strips_hyphens_and_lowers():
    assert _normalise_uuid("000C29A9-97DC-1FD1-92BD-715B4A56C000") == \
        "000c29a997dc1fd192bd715b4a56c000"


def test_normalise_uuid_handles_empty():
    assert _normalise_uuid("") == ""
    assert _normalise_uuid(None or "") == ""


# ---- find_secret_for_profile ----------------------------------------

_UUID_LOWER = "000c29a997dc1fd192bd715b4a56c000"
_IDENT_UPPER = ("/OA2C/CS_000C29A997DC1FD192BD715B4A56C000_00")


def test_find_secret_matches_canonical_secstore_key():
    """Real key shape: ident is upper, UUID we look up is lower —
    matcher must case-fold both sides so the join works."""
    entries = [{"ident_clean": _IDENT_UPPER, "password": "the-secret",
                 "category": "oauth2_client"}]
    assert find_secret_for_profile(entries, _UUID_LOWER) == "the-secret"


def test_find_secret_returns_empty_when_no_match():
    entries = [{"ident_clean": _IDENT_UPPER, "password": "the-secret"}]
    assert find_secret_for_profile(
        entries, "ffffffffffffffffffffffffffffffff") == ""


def test_find_secret_handles_hyphenated_uuid_input():
    """Caller passes a hyphenated UUID — matcher should still find the
    no-hyphen secstore key."""
    entries = [{"ident_clean": _IDENT_UPPER, "password": "the-secret"}]
    assert find_secret_for_profile(
        entries, "000C29A9-97DC-1FD1-92BD-715B4A56C000") == "the-secret"


def test_find_secret_skips_non_oauth_secstore_rows():
    """RFC + DBCON rows must not accidentally satisfy the matcher
    even when their identifiers happen to contain similar substrings."""
    entries = [
        {"ident_clean": "/RFC/SOMETHING@S4P000", "password": "wrong"},
        {"ident_clean": _IDENT_UPPER, "password": "right"},
    ]
    assert find_secret_for_profile(entries, _UUID_LOWER) == "right"


# ---- categorise_entry ------------------------------------------------

def test_categoriser_labels_oa2c_secret_correctly():
    """The "?" the operator saw in the GUI was the categoriser
    falling through to "other".  After the regex addition the row
    should land in the oauth2_client bucket with the parsed UUID."""
    e = categorise_entry({"ident": "001 " + _IDENT_UPPER})
    assert e["category"] == "oauth2_client"
    assert e["client_uuid"] == _UUID_LOWER
    assert e["secret_seq"] == "00"


def test_categoriser_does_not_misfire_on_other_oa2c_namespace_keys():
    """OA2C namespace might hold other entry types in future kernels —
    our regex requires the CS_ prefix + 32-hex + _NN to keep this
    targeted."""
    e = categorise_entry({"ident": "/OA2C/SOMETHING_ELSE"})
    assert e["category"] == "other"


# ---- read_oa2c_profiles (mocked sapmap_rfc.read_table) ---------------

def _patch_read_table(table_to_rows: dict):
    """Build a fake `sapmap_rfc.read_table(node, table, ...)` that
    returns the rows we mapped per table name.  Matches whichever
    table name the caller passes (since the OA2C reader only reads
    OA2C_CLIENT and OA2C_CLIENT_EXT)."""
    def fake(node, table_name, **kw):
        return list(table_to_rows.get(table_name, []))
    return patch("sapmap_rfc.read_table", side_effect=fake)


def test_read_oa2c_joins_client_with_client_ext_on_uuid():
    node = SAPNode(sid="S4H", system_type="ABAP",
                    hostname="s4hanadev", ip="192.168.2.209")
    rows = {
        "OA2C_CLIENT": [
            {"CLIENT_UUID": "AAAA-BBBB-CCCC-DDDD-EEEEFFFF1234",
             "CLIENT_ID": "sb-clone!b1234",
             "TOKEN_ENDPOINT":
                 "https://researchlab-yehctg7m.authentication.eu10-004"
                 ".hana.ondemand.com/oauth/token",
             "DESCRIPTION": "BTP Researchlab",
             "CLIENT_AUTHENTICATION": "CLIENT_SECRET_BASIC"},
        ],
        "OA2C_CLIENT_EXT": [
            {"CLIENT_UUID": "AAAA-BBBB-CCCC-DDDD-EEEEFFFF1234",
             "GRANTTYPE": "CLIENT_CREDENTIALS"},
        ],
    }
    with _patch_read_table(rows):
        profiles = read_oa2c_profiles(node)
    assert len(profiles) == 1
    p = profiles[0]
    # Hyphens stripped, lowered — ready to match secstore keys.
    assert p["client_uuid"] == "aaaabbbbccccddddeeeeffff1234"
    assert p["client_id"] == "sb-clone!b1234"
    assert "/oauth/token" in p["token_endpoint"]
    assert p["grant_type"] == "CLIENT_CREDENTIALS"
    assert p["auth_method"] == "CLIENT_SECRET_BASIC"
    assert p["description"] == "BTP Researchlab"


def test_read_oa2c_handles_missing_extension_rows():
    """Some kernels don't populate OA2C_CLIENT_EXT for legacy
    profiles — grant_type just stays empty, the rest of the row
    must still come through so the operator can edit it manually."""
    node = SAPNode(sid="S4H", system_type="ABAP",
                    hostname="s4hanadev", ip="192.168.2.209")
    rows = {
        "OA2C_CLIENT": [
            {"CLIENT_UUID": "AAAA",
             "CLIENT_ID": "cid", "TOKEN_ENDPOINT": "https://x"},
        ],
        "OA2C_CLIENT_EXT": [],
    }
    with _patch_read_table(rows):
        profiles = read_oa2c_profiles(node)
    assert len(profiles) == 1
    assert profiles[0]["grant_type"] == ""


def test_read_oa2c_returns_empty_list_when_oa2c_client_unreadable():
    """No S_TABU_DIS / S_RFC for OA2C_CLIENT ⇒ harmless empty list,
    not a crash that would block the rest of the data-extraction
    workflow."""
    node = SAPNode(sid="S4H", system_type="ABAP",
                    hostname="s4hanadev", ip="192.168.2.209")
    with _patch_read_table({"OA2C_CLIENT": [], "OA2C_CLIENT_EXT": []}):
        assert read_oa2c_profiles(node) == []


def test_read_oa2c_falls_back_to_token_url_field():
    """Older kernels expose TOKEN_URL instead of TOKEN_ENDPOINT —
    parser must accept either."""
    node = SAPNode(sid="S4H", system_type="ABAP",
                    hostname="s4hanadev", ip="192.168.2.209")
    rows = {
        "OA2C_CLIENT": [
            {"CLIENT_UUID": "AAAA", "CLIENT_ID": "cid",
             "TOKEN_URL": "https://legacy/oauth/token"},
        ],
        "OA2C_CLIENT_EXT": [],
    }
    with _patch_read_table(rows):
        profiles = read_oa2c_profiles(node)
    assert profiles[0]["token_endpoint"] == "https://legacy/oauth/token"


def test_read_oa2c_falls_back_to_oa2c_config_when_oa2c_client_errors():
    """User's S4H showed OA2C_CLIENT raising RFC_READ_TABLE message
    AD718 (TABLE_WITHOUT_DATA).  The reader should fall through to
    the next table-name variant instead of giving up."""
    node = SAPNode(sid="S4H", system_type="ABAP",
                    hostname="s4hanadev", ip="192.168.2.209")

    def fake(node, table_name, **kw):
        if table_name == "OA2C_CLIENT":
            raise RuntimeError(
                "RFC_ABAP_EXCEPTION: ID:AD Type:E Number:718 OA2C_CLIENT")
        if table_name == "OA2C_CONFIG":
            return [{"CLIENT_UUID": "BB", "CLIENT_ID": "fallback-cid",
                     "TOKEN_ENDPOINT": "https://fb/oauth/token"}]
        return []

    with patch("sapmap_rfc.read_table", side_effect=fake):
        profiles = read_oa2c_profiles(node)
    assert len(profiles) == 1
    assert profiles[0]["client_id"] == "fallback-cid"


def test_read_oa2c_heuristically_matches_kernel_specific_column_names():
    """A kernel patch that names the token endpoint
    ``OAUTH2_TOKEN_URL`` (substring-matches our hint ``TOKEN_URL``)
    should still be picked up — that's the whole point of dropping
    the hardcoded field list."""
    node = SAPNode(sid="S4H", system_type="ABAP",
                    hostname="s4hanadev", ip="192.168.2.209")
    rows = {
        "OA2C_CLIENT": [{
            "CONFIG_ID":         "CC",   # alt CLIENT_UUID name
            "CLIENT_ID":         "cid",
            "OAUTH2_TOKEN_URL":  "https://k/oauth/token",
            "CLIENT_SECRET_METHOD": "BASIC",
        }],
        "OA2C_CLIENT_EXT": [],
    }
    with _patch_read_table(rows):
        profiles = read_oa2c_profiles(node)
    assert len(profiles) == 1
    p = profiles[0]
    assert p["client_uuid"] == "cc"
    assert p["token_endpoint"] == "https://k/oauth/token"
    assert p["auth_method"] == "BASIC"


def test_read_oa2c_first_pass_is_discovery_with_no_field_list():
    """RFC_READ_TABLE message AD718 fires when ANY pre-listed FIELDS
    entry doesn't exist on the target kernel.  The discovery pass
    (the FIRST call against any candidate table) must therefore use
    fields=None.  Later passes may re-read with explicit columns
    once we've seen what the kernel actually exposes."""
    node = SAPNode(sid="S4H", system_type="ABAP",
                    hostname="s4hanadev", ip="192.168.2.209")
    calls = []   # [(table_name, fields), ...]

    def fake(node, table_name, **kw):
        calls.append((table_name, kw.get("fields")))
        return []

    with patch("sapmap_rfc.read_table", side_effect=fake):
        read_oa2c_profiles(node)
    assert calls, "read_table was never called"
    # The first invocation against any table is the all-columns
    # discovery pass — fields must be None there.
    seen_first_per_table: dict = {}
    for table, fields in calls:
        if table not in seen_first_per_table:
            seen_first_per_table[table] = fields
    for table, fields in seen_first_per_table.items():
        assert fields is None, (
            f"first read of {table} pre-lists fields={fields!r} — "
            f"the discovery pass must use fields=None to dodge "
            f"AD718 on kernel-specific column drift")


def test_read_oa2c_does_targeted_reread_when_first_pass_returns_rows():
    """When the all-columns discovery returns ≥1 row, the reader
    must reissue RFC_READ_TABLE asking ONLY for the matched columns
    — RFC_READ_TABLE's 512-byte WA truncates wide STRING fields when
    every column is read at once, so wide URL columns silently come
    back empty.  Operator hit this exact bug on an S/4 box where
    OA2C_CLIENT exposed CHANGED_*, CREATED_*, CS_SEGMENT_COUNT,
    CONFIGURATION… and the URL columns (alphabetically last) lost
    their values."""
    node = SAPNode(sid="S4H", system_type="ABAP",
                    hostname="s4hanadev", ip="192.168.2.209")
    calls = []

    def fake(node, table_name, **kw):
        calls.append((table_name, kw.get("fields")))
        if table_name != "OA2C_CLIENT":
            return []
        if kw.get("fields") is None:
            # First pass: all columns, but URL came back empty due to
            # WA buffer truncation.
            return [{
                "CLIENT_UUID":          "AABBCCDD",
                "CLIENT_ID":            "cid-from-discovery",
                "AUTHENTICATION_METHOD": "BASIC",
                "TOKEN_ENDPOINT":       "",
                "CONFIGURATION":        "",
                "CHANGED_AT":           "20260101",
                "MANDT":                "001",
            }]
        # Targeted re-read: only the wanted columns, full values.
        return [{
            "CLIENT_UUID":           "AABBCCDD",
            "CLIENT_ID":             "cid-from-discovery",
            "AUTHENTICATION_METHOD": "BASIC",
            "TOKEN_ENDPOINT":
                "https://x.authentication.eu10.hana.ondemand.com/oauth/token",
        }]

    with patch("sapmap_rfc.read_table", side_effect=fake):
        profiles = read_oa2c_profiles(node)
    # Targeted re-read happened → URL field is populated.
    assert len(profiles) == 1
    assert profiles[0]["token_endpoint"].endswith("/oauth/token")
    # First call to OA2C_CLIENT had fields=None (discovery), a later
    # call had explicit field names (targeted).
    fields_for_oa2c_client = [f for t, f in calls if t == "OA2C_CLIENT"]
    assert fields_for_oa2c_client[0] is None
    assert any(f is not None and "TOKEN_ENDPOINT" in f
                for f in fields_for_oa2c_client[1:])


# ---- end-to-end: harvester sees OA2C profile + secstore secret ------

def test_harvester_picks_up_oa2c_profile_with_matched_secret():
    from sap_onprem_to_btp import harvest_btp_candidates

    state = SAPMAPState()
    node = SAPNode(sid="S4H", system_type="ABAP",
                    hostname="s4hanadev", ip="192.168.2.209")
    state.add_node(node)

    node.oauth2_profiles = [{
        "client_uuid":   _UUID_LOWER,
        "client_id":     "sb-clone!b1234",
        "token_endpoint":
            "https://researchlab-yehctg7m.authentication.eu10-004"
            ".hana.ondemand.com/oauth/token",
        "grant_type":    "CLIENT_CREDENTIALS",
        "auth_method":   "CLIENT_SECRET_BASIC",
        "description":   "BTP_RESEARCHLAB",
        "profile":       "BTP_RL",
        "issuer":        "",
        "auth_endpoint": "",
    }]
    node.secstore_entries = [{
        "ident_clean": _IDENT_UPPER,
        "password":    "lifted-from-secstore",
        "category":    "oauth2_client",
    }]

    cands = harvest_btp_candidates(state, node)
    assert len(cands) == 1
    c = cands[0]
    assert c["source"] == "abap-oa2c"
    assert c["client_id"] == "sb-clone!b1234"
    assert c["client_secret"] == "lifted-from-secstore"
    assert "/oauth/token" in c["uaa_url"]
    assert c["region_hint"] == "eu10-004"
    # Operator-facing label should mention the human-readable
    # description, not the raw UUID.
    assert "BTP_RESEARCHLAB" in c["label"]
    assert "CLIENT_CREDENTIALS" in c["label"]


def test_harvester_skips_oa2c_profile_when_secret_not_yet_decrypted():
    """Profile is in OA2C_CLIENT but the operator hasn't run
    Download SecStore yet ⇒ no candidate (we don't surface rows the
    operator can't actually mint with)."""
    from sap_onprem_to_btp import harvest_btp_candidates

    state = SAPMAPState()
    node = SAPNode(sid="S4H", system_type="ABAP",
                    hostname="s4hanadev", ip="192.168.2.209")
    state.add_node(node)
    node.oauth2_profiles = [{
        "client_uuid":   _UUID_LOWER,
        "client_id":     "cid",
        "token_endpoint":
            "https://x.authentication.eu10.hana.ondemand.com/oauth/token",
        "grant_type":    "CLIENT_CREDENTIALS",
    }]
    node.secstore_entries = []   # <-- secstore not yet pulled
    assert harvest_btp_candidates(state, node) == []


def test_harvester_skips_oa2c_profile_pointing_at_non_btp_endpoint():
    """A corp-internal OAuth profile (not BTP) should NOT be
    surfaced — the candidate list is BTP-pivot-specific."""
    from sap_onprem_to_btp import harvest_btp_candidates

    state = SAPMAPState()
    node = SAPNode(sid="S4H", system_type="ABAP",
                    hostname="s4hanadev", ip="192.168.2.209")
    state.add_node(node)
    node.oauth2_profiles = [{
        "client_uuid":   _UUID_LOWER,
        "client_id":     "cid",
        "token_endpoint": "https://corp-idp.example.com/oauth/token",
        "grant_type":    "CLIENT_CREDENTIALS",
    }]
    node.secstore_entries = [{
        "ident_clean": _IDENT_UPPER, "password": "s",
    }]
    assert harvest_btp_candidates(state, node) == []


def test_oauth2_profiles_round_trip_through_state_serialization():
    """The new SAPNode field must survive save/load so a long
    engagement that pulls OA2C in one session and harvests in the
    next doesn't lose the profile data."""
    n = SAPNode(sid="S4H", system_type="ABAP",
                 hostname="s4h", ip="10.0.0.1")
    n.oauth2_profiles = [{
        "client_uuid": _UUID_LOWER, "client_id": "cid",
        "token_endpoint": "https://x", "grant_type": "CLIENT_CREDENTIALS",
    }]
    d = n.to_dict()
    assert d["oauth2_profiles"][0]["client_uuid"] == _UUID_LOWER
    n2 = SAPNode.from_dict(d)
    assert n2.oauth2_profiles[0]["client_id"] == "cid"
