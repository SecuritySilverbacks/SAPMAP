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

class _Patcher:
    """Combine read_table + get_table_columns mocks into one
    context manager so tests don't have to nest two patches.

    Args:
      table_to_rows: {table_name: [row_dict, ...]}.  Used as the
        return value for both get_table_columns (extracts column
        names from the first row's keys) and read_table.
    """

    def __init__(self, table_to_rows: dict):
        self.rows = table_to_rows

    def __enter__(self):
        self._read_patch = patch(
            "sapmap_rfc.read_table",
            side_effect=lambda node, name, **kw:
                list(self.rows.get(name, [])))
        self._cols_patch = patch(
            "sapmap_rfc.get_table_columns",
            side_effect=lambda node, name, **kw:
                (list(self.rows.get(name, [{}])[0].keys())
                 if self.rows.get(name) else []))
        self._read_patch.start()
        self._cols_patch.start()
        return self

    def __exit__(self, *exc):
        self._read_patch.stop()
        self._cols_patch.stop()


def _patch_read_table(table_to_rows: dict):
    return _Patcher(table_to_rows)


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


def test_read_oa2c_falls_back_to_oa2c_config_when_oa2c_client_absent():
    """When DDIF says OA2C_CLIENT doesn't exist on this kernel, the
    reader should walk through the table-name variants until one is
    populated (operator's S4H showed OA2C_CLIENT existing, but
    older or specialised systems may only carry OA2C_CONFIG)."""
    node = SAPNode(sid="S4H", system_type="ABAP",
                    hostname="s4hanadev", ip="192.168.2.209")

    def fake_cols(node, table_name, **kw):
        return ["CLIENT_UUID", "CLIENT_ID", "TOKEN_ENDPOINT"] \
            if table_name == "OA2C_CONFIG" else []

    def fake_read(node, table_name, **kw):
        if table_name == "OA2C_CONFIG":
            return [{"CLIENT_UUID": "BB", "CLIENT_ID": "fallback-cid",
                     "TOKEN_ENDPOINT": "https://fb/oauth/token"}]
        return []

    with patch("sapmap_rfc.get_table_columns", side_effect=fake_cols), \
         patch("sapmap_rfc.read_table", side_effect=fake_read):
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


def test_read_oa2c_uses_ddif_for_column_discovery_then_targeted_read():
    """The bulk RFC_READ_TABLE call drops trailing columns when the
    row exceeds its 512-byte work area — operator's S/4 OA2C_CLIENT
    has 25+ columns, so the all-columns probe missed CLIENT_ID and
    TOKEN_ENDPOINT entirely.  Reader must use DDIF_FIELDINFO_GET to
    enumerate ALL columns first, then issue an explicit-FIELDS
    RFC_READ_TABLE for just the matched ones."""
    node = SAPNode(sid="S4H", system_type="ABAP",
                    hostname="s4hanadev", ip="192.168.2.209")
    full_columns = [
        "MANDT", "CLIENT_UUID", "PROFILE", "SPS_NAME", "CLIENT_ID",
        "CREATED_BY", "CREATED_ON", "CREATED_AT", "CHANGED_BY",
        "CHANGED_ON", "CHANGED_AT", "AUTHORIZATION_ENDPOINT",
        "TOKEN_ENDPOINT", "REVOCATION_ENDPOINT",
        "AUTHENTICATION_METHOD", "AUTH_CODE_ALLOWED",
        "SAML20_ALLOWED", "REFRESH_ALLOWED", "RT_VALIDITY",
        "REDIRECT_URI_HOST", "REDIRECT_URI_PORT",
        "CS_SEGMENT_COUNT", "TARGET_PATH", "RESOURCE_ACCESS",
    ]
    ddif_calls = []
    read_calls = []

    def fake_cols(node, table_name, **kw):
        ddif_calls.append(table_name)
        return list(full_columns) if table_name == "OA2C_CLIENT" else []

    def fake_read(node, table_name, **kw):
        read_calls.append((table_name, kw.get("fields")))
        if table_name != "OA2C_CLIENT":
            return []
        return [{
            "CLIENT_UUID":           "AABBCCDD",
            "CLIENT_ID":             "cid-from-targeted-read",
            "AUTHENTICATION_METHOD": "BASIC",
            "TOKEN_ENDPOINT":
                "https://x.authentication.eu10.hana.ondemand.com",
        }]

    with patch("sapmap_rfc.get_table_columns", side_effect=fake_cols), \
         patch("sapmap_rfc.read_table", side_effect=fake_read):
        profiles = read_oa2c_profiles(node)

    # DDIF discovered the schema first (independent of WA cut-off).
    assert "OA2C_CLIENT" in ddif_calls
    # The actual data read used a targeted FIELDS list that included
    # CLIENT_ID and TOKEN_ENDPOINT — columns that the all-columns
    # probe was hiding.
    oa2c_reads = [(t, f) for t, f in read_calls if t == "OA2C_CLIENT"]
    assert oa2c_reads, "OA2C_CLIENT was never read"
    fields_used = oa2c_reads[0][1]
    assert fields_used is not None, \
        "reader must pass explicit FIELDS, not None"
    assert "CLIENT_ID" in fields_used
    assert "TOKEN_ENDPOINT" in fields_used
    assert "CLIENT_UUID" in fields_used
    # End-to-end: profile has the URL.
    assert len(profiles) == 1
    assert profiles[0]["token_endpoint"].startswith("https://x.")
    assert profiles[0]["client_id"] == "cid-from-targeted-read"


def test_read_oa2c_uses_long_strings_flag_on_first_data_read():
    """Tier-1 path: pass USE_ET_DATA_4_RETURN='X' to RFC_READ_TABLE
    so the kernel streams STRING-typed columns back through ET_DATA.
    Older kernels (S/4 patches that drop STRING columns silently
    even when listed as FIELDS) trigger Tier-2; this test verifies
    Tier-1 is attempted first."""
    node = SAPNode(sid="S4H", system_type="ABAP",
                    hostname="s4hanadev", ip="192.168.2.209")
    cols = ["CLIENT_UUID", "CLIENT_ID", "TOKEN_ENDPOINT"]
    saw_long_strings = []

    def fake_cols(node, table_name, **kw):
        return cols if table_name == "OA2C_CLIENT" else []

    def fake_read(node, table_name, **kw):
        saw_long_strings.append(kw.get("long_strings"))
        if table_name != "OA2C_CLIENT":
            return []
        # Newer kernel — long_strings honoured, STRING columns
        # returned via ET_DATA.
        return [{
            "CLIENT_UUID":     "AABB",
            "CLIENT_ID":       "cid-via-et-data",
            "TOKEN_ENDPOINT":  "https://x.hana.ondemand.com/oauth/token",
        }]

    with patch("sapmap_rfc.get_table_columns", side_effect=fake_cols), \
         patch("sapmap_rfc.read_table", side_effect=fake_read):
        profiles = read_oa2c_profiles(node)
    # The OA2C_CLIENT data read used long_strings=True (Tier-1).
    oa2c_calls = [v for v in saw_long_strings if v is not None]
    assert any(v is True for v in oa2c_calls), \
        f"Tier-1 (USE_ET_DATA_4_RETURN) was never attempted: " \
        f"long_strings flags seen = {saw_long_strings}"
    # End-to-end: Tier-1 returned populated rows so no fallback fired.
    assert profiles[0]["client_id"] == "cid-via-et-data"
    assert profiles[0]["token_endpoint"].endswith("/oauth/token")


def test_read_oa2c_falls_through_to_abap_when_string_cols_still_missing():
    """When the kernel ignores USE_ET_DATA_4_RETURN, STRING columns
    stay missing from row 0.  Reader should detect that and run
    RFC_ABAP_INSTALL_AND_RUN as Tier-2."""
    node = SAPNode(sid="S4H", system_type="ABAP",
                    hostname="s4hanadev", ip="192.168.2.209")
    full_cols = ["MANDT", "CLIENT_UUID", "CLIENT_ID", "TOKEN_ENDPOINT"]

    def fake_cols(node, table_name, **kw):
        return list(full_cols) if table_name == "OA2C_CLIENT" else []

    def fake_read(node, table_name, **kw):
        if table_name != "OA2C_CLIENT":
            return []
        # Older kernel — STRING columns still dropped from row 0
        # even with long_strings=True.
        return [{"CLIENT_UUID": "AABB"}]

    abap_calls = []

    def fake_run_abap(conn, abap_lines, program_name="ZSAPMAP"):
        abap_calls.append(program_name)
        return {
            "success": True,
            "fm_name": "RFC_ABAP_INSTALL_AND_RUN",
            "error": "",
            "output": [
                "~~~ROW",
                "CLIENT_UUID| AABB",
                "CLIENT_ID| cid-from-abap",
                "TOKEN_ENDPOINT| https://abap.hana.ondemand.com/oauth/token",
            ],
        }

    class _StubConn:
        def __enter__(self): return self
        def __exit__(self, *a): return False

    with patch("sapmap_rfc.get_table_columns", side_effect=fake_cols), \
         patch("sapmap_rfc.read_table", side_effect=fake_read), \
         patch("sapmap_rfc._get_connection", return_value=_StubConn()), \
         patch("sapmap_rfc._run_abap_program", side_effect=fake_run_abap):
        profiles = read_oa2c_profiles(node)
    assert abap_calls == ["ZSAPMAP_OA2C"], \
        f"ABAP fallback didn't fire: {abap_calls}"
    assert profiles[0]["client_id"] == "cid-from-abap"
    assert profiles[0]["token_endpoint"].endswith("/oauth/token")


def test_read_oa2c_falls_through_when_et_data_returned_keys_but_empty_values():
    """Operator's S/4: USE_ET_DATA_4_RETURN was honoured (Tier-1
    returned `→ 1 row(s)` with all 7 keys present), but the actual
    VALUES for STRING columns came back empty.  Reader must still
    detect this and fall through to Tier-2 — checking for
    "missing key" alone isn't enough."""
    node = SAPNode(sid="S4H", system_type="ABAP",
                    hostname="s4hanadev", ip="192.168.2.209")
    cols = ["CLIENT_UUID", "CLIENT_ID", "TOKEN_ENDPOINT"]

    def fake_cols(node, table_name, **kw):
        return cols if table_name == "OA2C_CLIENT" else []

    def fake_read(node, table_name, **kw):
        if table_name != "OA2C_CLIENT":
            return []
        # Keys present, but the STRING values are empty — exact
        # symptom seen in the operator's run.
        return [{"CLIENT_UUID": "AABB", "CLIENT_ID": "",
                 "TOKEN_ENDPOINT": ""}]

    abap_calls = []

    def fake_run_abap(conn, abap_lines, program_name="ZSAPMAP"):
        abap_calls.append(program_name)
        return {
            "success": True,
            "fm_name": "RFC_ABAP_INSTALL_AND_RUN",
            "error": "",
            "output": [
                "~~~ROW",
                "CLIENT_UUID| AABB",
                "CLIENT_ID| cid-from-abap",
                "TOKEN_ENDPOINT| https://x.hana.ondemand.com/oauth/token",
            ],
        }

    class _StubConn:
        def __enter__(self): return self
        def __exit__(self, *a): return False

    with patch("sapmap_rfc.get_table_columns", side_effect=fake_cols), \
         patch("sapmap_rfc.read_table", side_effect=fake_read), \
         patch("sapmap_rfc._get_connection", return_value=_StubConn()), \
         patch("sapmap_rfc._run_abap_program", side_effect=fake_run_abap):
        profiles = read_oa2c_profiles(node)
    assert abap_calls == ["ZSAPMAP_OA2C"], (
        "Tier-2 didn't fire even though Tier-1 returned empty "
        f"STRING values: {abap_calls}")
    assert profiles[0]["client_id"] == "cid-from-abap"
    assert profiles[0]["token_endpoint"].endswith("/oauth/token")


def test_read_oa2c_skips_abap_when_kernel_already_returned_strings():
    """Counter-test: when Tier-1 (long-strings) returns every column
    populated, Tier-2 (ABAP) must NOT fire.  Avoids unnecessary
    RFC_ABAP_INSTALL_AND_RUN calls (which need SDIFRUNTIME auth and
    light up audit logs)."""
    node = SAPNode(sid="S4H", system_type="ABAP",
                    hostname="s4hanadev", ip="192.168.2.209")
    cols = ["CLIENT_UUID", "CLIENT_ID", "TOKEN_ENDPOINT"]

    def fake_cols(node, table_name, **kw):
        return cols if table_name == "OA2C_CLIENT" else []

    def fake_read(node, table_name, **kw):
        if table_name != "OA2C_CLIENT":
            return []
        return [{"CLIENT_UUID": "AA", "CLIENT_ID": "cid",
                 "TOKEN_ENDPOINT": "https://x.hana.ondemand.com"}]

    abap_calls = []

    def fake_run_abap(*a, **kw):
        abap_calls.append("called")
        return {"success": False, "output": [], "error": "must-not-run"}

    with patch("sapmap_rfc.get_table_columns", side_effect=fake_cols), \
         patch("sapmap_rfc.read_table", side_effect=fake_read), \
         patch("sapmap_rfc._run_abap_program", side_effect=fake_run_abap):
        profiles = read_oa2c_profiles(node)
    assert abap_calls == [], \
        "ABAP fallback fired unnecessarily"
    assert profiles[0]["token_endpoint"].endswith("hana.ondemand.com")


def test_read_oa2c_picks_up_authentication_method_explicitly():
    """AUTHENTICATION_METHOD doesn't substring-match AUTH_METHOD
    (no underscore between AUTH and ENTICATION).  The hint table
    must list AUTHENTICATION_METHOD directly so S/4's column gets
    matched."""
    node = SAPNode(sid="S4H", system_type="ABAP",
                    hostname="s4hanadev", ip="192.168.2.209")
    cols = ["CLIENT_UUID", "CLIENT_ID", "TOKEN_ENDPOINT",
             "AUTHENTICATION_METHOD"]

    def fake_cols(node, name, **kw):
        return cols if name == "OA2C_CLIENT" else []

    def fake_read(node, name, **kw):
        if name != "OA2C_CLIENT":
            return []
        return [{"CLIENT_UUID": "AA", "CLIENT_ID": "cid",
                 "TOKEN_ENDPOINT": "https://x.hana.ondemand.com",
                 "AUTHENTICATION_METHOD": "1"}]

    with patch("sapmap_rfc.get_table_columns", side_effect=fake_cols), \
         patch("sapmap_rfc.read_table", side_effect=fake_read):
        profiles = read_oa2c_profiles(node)
    assert profiles[0]["auth_method"] == "1"


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
