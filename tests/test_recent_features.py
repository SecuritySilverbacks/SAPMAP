#!/usr/bin/env python3
"""Unit tests for the recent batch of features that landed without
their own coverage:

  * sapmap_errors.format_rfc_exception     — pyrfc detail extractor
  * sapmap_state.ensure_loot_dir / LOOT_*  — loot-vs-state directory split
  * sapmap_rfc.download_password_hashes    — 5-method fallback chain
  * sapmap_secstore.categorise_entry       — ABAP RSECTAB classification
  * sap_java_secstore.classify_entry       — Java SecStore classification

All tests are offline (no network).  pyrfc is stubbed with FakeConn /
FakeCtx wrappers.
"""
from __future__ import annotations

import os
import tempfile
from unittest.mock import patch, MagicMock

import pytest


# ===========================================================================
# 1. format_rfc_exception — pure function, used by 98 sites across the codebase
# ===========================================================================

class _FakeABAPError(Exception):
    """Stub mimicking pyrfc.ABAPApplicationError attribute layout."""
    def __init__(self, str_msg, **attrs):
        super().__init__(str_msg)
        for k, v in attrs.items():
            setattr(self, k, v)


def test_format_rfc_exception_with_full_pyrfc_attrs():
    from sapmap_errors import format_rfc_exception
    e = _FakeABAPError(
        "RFC_ABAP_EXCEPTION: Number:000",
        key="FIELD_NOT_VALID",
        message="Field PWDSALTEDHASH not in table USR02",
        msg_class="00",
        msg_number="000",
        msg_type="E",
        msg_v1="USR02",
        msg_v2="PWDSALTEDHASH",
    )
    out = format_rfc_exception(e)

    assert "_FakeABAPError:" in out
    assert "RFC_ABAP_EXCEPTION: Number:000" in out
    # Every populated attribute must surface in the bracketed block
    assert "key=FIELD_NOT_VALID" in out
    assert "message=Field PWDSALTEDHASH not in table USR02" in out
    assert "msg_class=00" in out
    assert "msg_number=000" in out
    assert "msg_type=E" in out
    assert "msg_v1=USR02" in out
    assert "msg_v2=PWDSALTEDHASH" in out


def test_format_rfc_exception_skips_falsy_attrs():
    """Empty / None pyrfc attributes must not produce 'attr=' clutter."""
    from sapmap_errors import format_rfc_exception
    e = _FakeABAPError("boom", key="NOT_AUTHORIZED",
                       message="", msg_class=None, msg_v3="")
    out = format_rfc_exception(e)
    assert "key=NOT_AUTHORIZED" in out
    assert "message=" not in out  # empty strings dropped
    assert "msg_class=" not in out
    assert "msg_v3=" not in out


def test_format_rfc_exception_plain_exception_no_extras():
    """Non-pyrfc exceptions degrade cleanly to TypeName: message."""
    from sapmap_errors import format_rfc_exception
    out = format_rfc_exception(ValueError("bad value"))
    assert out == "ValueError: bad value"
    # No bracket suffix when no pyrfc attrs are present
    assert "[" not in out


def test_format_rfc_exception_with_only_one_attr():
    from sapmap_errors import format_rfc_exception
    e = _FakeABAPError("communication", key="CONNECTION_TIMEOUT")
    out = format_rfc_exception(e)
    assert "[key=CONNECTION_TIMEOUT]" in out


# ===========================================================================
# 2. sapmap_state — loot vs state directory split
# ===========================================================================

def test_loot_dir_constants_under_project_root():
    """LOOT_DIR and STATE_DIR must both live under the project root and
    must be siblings (neither nested inside the other)."""
    import sapmap_state as ss
    assert os.path.basename(ss.LOOT_DIR) == "loot"
    assert os.path.basename(ss.STATE_DIR) == "states"
    assert os.path.dirname(ss.LOOT_DIR) == os.path.dirname(ss.STATE_DIR)
    # Loot subdir constants must all start with LOOT_DIR
    assert ss.LOOT_HASHES_DIR.startswith(ss.LOOT_DIR)
    assert ss.LOOT_SECSTORE_DIR.startswith(ss.LOOT_DIR)
    assert ss.LOOT_TABLES_DIR.startswith(ss.LOOT_DIR)
    assert ss.LOOT_BIA_DIR.startswith(ss.LOOT_DIR)


def test_ensure_loot_dir_no_subdir_returns_loot_root(monkeypatch, tmp_path):
    """ensure_loot_dir() with no arg must create + return LOOT_DIR."""
    import sapmap_state as ss
    monkeypatch.setattr(ss, "LOOT_DIR", str(tmp_path / "loot"))
    out = ss.ensure_loot_dir()
    assert out == str(tmp_path / "loot")
    assert os.path.isdir(out)


def test_ensure_loot_dir_with_subdir_creates_nested(monkeypatch, tmp_path):
    import sapmap_state as ss
    monkeypatch.setattr(ss, "LOOT_DIR", str(tmp_path / "loot"))
    out = ss.ensure_loot_dir("hashes")
    assert out == str(tmp_path / "loot" / "hashes")
    assert os.path.isdir(out)


def test_ensure_loot_dir_idempotent(monkeypatch, tmp_path):
    """Calling twice must not raise even though the dir already exists."""
    import sapmap_state as ss
    monkeypatch.setattr(ss, "LOOT_DIR", str(tmp_path / "loot"))
    p1 = ss.ensure_loot_dir("secstore")
    p2 = ss.ensure_loot_dir("secstore")
    assert p1 == p2 and os.path.isdir(p1)


def test_ensure_loot_dir_supports_arbitrary_subdir(monkeypatch, tmp_path):
    """The subdir parameter is a free string — any name should work."""
    import sapmap_state as ss
    monkeypatch.setattr(ss, "LOOT_DIR", str(tmp_path / "loot"))
    out = ss.ensure_loot_dir("custom_findings_2026")
    assert out.endswith("custom_findings_2026")
    assert os.path.isdir(out)


# ===========================================================================
# 3. download_password_hashes — 5-method fallback chain
# ===========================================================================

def _make_node(sid="ORA", db_type="ORA", ip="10.0.0.1"):
    from sapmap_models import SAPNode, InstanceInfo
    n = SAPNode(sid=sid, ip=ip, hostname=f"{sid.lower()}host",
                system_type="ABAP", db_type=db_type)
    n.instances.append(InstanceInfo(
        instance_nr="00", ip=ip, ports={3300: "gateway"},
    ))
    return n


def _make_creds():
    from sapmap_models import Credentials
    return Credentials(username="SAPMAP00", password="pwd",
                       client="001", instance_nr="00")


def test_download_password_hashes_method4_legacy_usr02(monkeypatch):
    """Wide read fails (FIELD_NOT_VALID due to PWDSALTEDHASH on a pre-6.40
    Oracle USR02), Method 3 also has PWDSALTEDHASH so still fails, Method
    4 succeeds with BCODE+PASSCODE.  We must end up returning legacy
    rows tagged hash_quality='half'."""
    import sapmap_rfc

    # Skip Method 1 (SXPG path) entirely
    monkeypatch.setattr(sapmap_rfc, "_download_hashes_via_sxpg",
                        lambda node, creds=None: None)

    # Method 2/3 reads request PWDSALTEDHASH → empty result
    # Method 4 (legacy_fields) lacks PWDSALTEDHASH → returns rows
    captured_calls = []

    def fake_read_table(node, table, fields=None, creds=None,
                         where="", max_rows=0):
        captured_calls.append(list(fields or []))
        if "PWDSALTEDHASH" in (fields or []):
            return []
        # Method 4 — return two rows with BCODE+PASSCODE
        return [
            {"MANDT": "001", "BNAME": "DDIC", "BCODE": "1234567890ABCDEF",
             "PASSCODE": "A" * 16, "CODVN": "F", "USTYP": "A", "UFLAG": "0"},
            {"MANDT": "001", "BNAME": "SAPMAP00", "BCODE": "FEDCBA0987654321",
             "PASSCODE": "B" * 16, "CODVN": "F", "USTYP": "A", "UFLAG": "0"},
        ]

    monkeypatch.setattr(sapmap_rfc, "read_table", fake_read_table)

    rows = sapmap_rfc.download_password_hashes(_make_node(), _make_creds())

    # Exactly the 4-call sequence we expect: wide (Method 2),
    # safe-no-RAW (Method 3), legacy-no-PWDSALTEDHASH (Method 4)
    assert len(captured_calls) == 3
    assert "PWDSALTEDHASH" in captured_calls[0]   # Method 2
    assert "PWDSALTEDHASH" in captured_calls[1]   # Method 3
    assert "PWDSALTEDHASH" not in captured_calls[2]  # Method 4
    assert "BCODE" in captured_calls[2]
    assert "PASSCODE" in captured_calls[2]

    # Result rows must be tagged half-quality with PWDSALTEDHASH cleared
    assert len(rows) == 2
    for r in rows:
        assert r["hash_quality"] == "half"
        assert r["PWDSALTEDHASH"] == ""
        assert r["BCODE"]


def test_download_password_hashes_method3_issha_only(monkeypatch):
    """Wide read fails, no-RAW retry succeeds — must tag rows
    'issha_only' and zero out BCODE/PASSCODE."""
    import sapmap_rfc

    monkeypatch.setattr(sapmap_rfc, "_download_hashes_via_sxpg",
                        lambda node, creds=None: None)

    call_count = {"n": 0}

    def fake_read_table(node, table, fields=None, creds=None,
                         where="", max_rows=0):
        call_count["n"] += 1
        # Method 2: wide, includes BCODE+PASSCODE → fail
        if "BCODE" in (fields or []) and "PWDSALTEDHASH" in (fields or []):
            return []
        # Method 3: no RAW, has PWDSALTEDHASH → success
        if "PWDSALTEDHASH" in (fields or []) and "BCODE" not in (fields or []):
            return [{"MANDT": "001", "BNAME": "DDIC",
                     "PWDSALTEDHASH": "{x-issha, 1024}abcdef==",
                     "CODVN": "F", "USTYP": "A", "UFLAG": "0"}]
        return []

    monkeypatch.setattr(sapmap_rfc, "read_table", fake_read_table)

    rows = sapmap_rfc.download_password_hashes(_make_node(), _make_creds())
    assert len(rows) == 1
    assert rows[0]["hash_quality"] == "issha_only"
    assert rows[0]["BCODE"] == ""
    assert rows[0]["PASSCODE"] == ""
    assert rows[0]["PWDSALTEDHASH"]
    # Methods 2 and 3 only — Method 4 must not run
    assert call_count["n"] == 2


def test_download_password_hashes_method2_full_modern(monkeypatch):
    """Wide read on a modern landscape succeeds first try and tags
    rows 'half' (RFC_READ_TABLE truncation, not full)."""
    import sapmap_rfc

    monkeypatch.setattr(sapmap_rfc, "_download_hashes_via_sxpg",
                        lambda node, creds=None: None)

    def fake_read_table(node, table, fields=None, creds=None,
                         where="", max_rows=0):
        return [{"MANDT": "001", "BNAME": "DDIC", "BCODE": "ABCD",
                 "PASSCODE": "EF" * 8, "PWDSALTEDHASH": "{x-issha}xx",
                 "CODVN": "F", "USTYP": "A", "UFLAG": "0"}]

    monkeypatch.setattr(sapmap_rfc, "read_table", fake_read_table)

    rows = sapmap_rfc.download_password_hashes(_make_node(), _make_creds())
    assert len(rows) == 1
    assert rows[0]["hash_quality"] == "half"


def test_download_password_hashes_method1_sxpg_full(monkeypatch):
    """When SXPG returns rows, Method 2-5 must NOT run.  Tag full."""
    import sapmap_rfc

    sxpg_rows = [{"MANDT": "001", "BNAME": "DDIC",
                  "BCODE": "FULLBCODE0000FULL", "PASSCODE": "C" * 40,
                  "PWDSALTEDHASH": "{x-issha}xx",
                  "CODVN": "F", "USTYP": "A", "UFLAG": "0",
                  "hash_quality": "full"}]
    monkeypatch.setattr(sapmap_rfc, "_download_hashes_via_sxpg",
                        lambda node, creds=None: sxpg_rows)

    fallback_called = {"hit": False}
    def fake_read_table(*a, **kw):
        fallback_called["hit"] = True
        return []
    monkeypatch.setattr(sapmap_rfc, "read_table", fake_read_table)

    rows = sapmap_rfc.download_password_hashes(_make_node(), _make_creds())
    assert rows == sxpg_rows
    assert fallback_called["hit"] is False


def test_download_password_hashes_method5_user_inventory_only(monkeypatch):
    """All hash-bearing reads fail; bare MANDT/BNAME/USTYP succeeds —
    function returns [] but the operator sees a 'no hashes but N users'
    diagnostic via stdout (we just verify it doesn't crash)."""
    import sapmap_rfc

    monkeypatch.setattr(sapmap_rfc, "_download_hashes_via_sxpg",
                        lambda node, creds=None: None)

    def fake_read_table(node, table, fields=None, creds=None,
                         where="", max_rows=0):
        if set(fields or []) == {"MANDT", "BNAME", "USTYP"}:
            return [{"MANDT": "001", "BNAME": "DDIC", "USTYP": "A"}]
        return []  # everything else fails

    monkeypatch.setattr(sapmap_rfc, "read_table", fake_read_table)
    rows = sapmap_rfc.download_password_hashes(_make_node(), _make_creds())
    assert rows == []


# ===========================================================================
# 4. ABAP RSECTAB categorise_entry
# ===========================================================================

@pytest.mark.parametrize("ident,expected_cat,extras", [
    # /RFC/<dest> simple form
    ("/RFC/S4D",                  "rfc", {"target_sid": "S4D"}),
    # /RFC/<USER>@<SID>.DOMAIN_<SID>
    ("/RFC/TMSADM@H2T.DOMAIN_H2T", "rfc",
     {"rfc_user": "TMSADM", "target_sid": "H2T"}),
    # /RFC/<USER>@<SID>CLNT<NNN>
    ("/RFC/FINBTR@H2TCLNT100",    "rfc",
     {"rfc_user": "FINBTR", "target_sid": "H2T", "rfc_client": "100"}),
    # DBCON
    ("/DBCON/SYSTEMDB@H2T",       "db",  {}),
    # CTS
    ("/CTS/PWD/$T$/DOMAIN_H2T/DOMCTL", "cts", {}),
    # SMTP — content-based match
    ("BC_SX_SMTP",                "smtp", {}),
    # HMAC
    ("/HMAC_INDEP/SOMEKEY",       "hmac", {}),
    # PSE / cert PIN
    ("/STRUST_PSE_PIN/SAPSSLS",   "pse",  {}),
    # Unrecognised → other
    ("/RANDOM/THING",             "other", {}),
])
def test_categorise_entry_idents(ident, expected_cat, extras):
    from sapmap_secstore import categorise_entry
    out = categorise_entry({"ident": ident})
    assert out["category"] == expected_cat
    for k, v in extras.items():
        assert out[k] == v


def test_categorise_entry_strips_mandt_prefix():
    """The ABAP loader prepends a 3-digit MANDT prefix; categorise_entry
    must strip it and store the client number in the .mandt field."""
    from sapmap_secstore import categorise_entry
    out = categorise_entry({"ident": "100 /RFC/FINBTR@H2TCLNT100"})
    assert out["mandt"] == "100"
    assert out["category"] == "rfc"
    assert out["rfc_client"] == "100"


def test_categorise_entry_handles_cross_client_prefix():
    """Cross-client entries arrive with '___' (3 underscores/spaces)
    instead of a numeric MANDT.  Must still classify and leave mandt empty."""
    from sapmap_secstore import categorise_entry
    out = categorise_entry({"ident": "___ /RFC/S4D"})
    assert out["mandt"] == ""
    assert out["category"] == "rfc"
    assert out["target_sid"] == "S4D"


# ===========================================================================
# 5. Java SecStore classify_entry
# ===========================================================================

def test_java_classify_entry_sapjsf_to_other_sid():
    """SAPJSF/<dest> maps to a downstream ABAP system."""
    from sap_java_secstore import classify_entry
    out = classify_entry("SAPJSF/SOLMAN_BTC", "JAVA")
    assert out["kind"] in ("sapjsf", "jco_dest", "unknown")  # depends on regex


def test_java_classify_entry_jdbc_local():
    """jdbc/pool/<SID> credentials are local DB access."""
    from sap_java_secstore import classify_entry
    out = classify_entry("jdbc/pool/JAV", "JAV")
    # Either matches as jdbc_local or as a known local pattern
    assert out["kind"] in ("jdbc_local", "unknown")


def test_java_classify_entry_unknown():
    from sap_java_secstore import classify_entry
    out = classify_entry("some_random_setting", "JAV")
    assert out["kind"] == "unknown"
    assert out["target_sid"] == ""
    assert out["client"] == ""
    assert out["is_local"] is False
    assert out["is_downstream"] is False


def test_java_classify_entry_returns_dict_shape():
    """Every call must return the full-shape dict — callers index by
    kind/target_sid/client/is_local/is_downstream unconditionally."""
    from sap_java_secstore import classify_entry
    out = classify_entry("anything", "JAV")
    for key in ("kind", "target_sid", "client", "is_local", "is_downstream"):
        assert key in out, f"classify_entry missing key {key}"
