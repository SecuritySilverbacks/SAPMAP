#!/usr/bin/env python3
"""Regression tests for sapmap_rfc.read_table's long-strings path.

Operator-surfaced bug: with ``long_strings=True`` and
``USE_ET_DATA_4_RETURN='X'`` some S/4 kernels populate ET_DATA but
leave the FIELDS metadata table empty.  read_table used to parse the
WA against an empty column list, returning a list of empty dicts —
visible downstream as "rows exist but every BNAME / EXTID / TYPE is
missing".  USREXTID on S4H was the canonical victim because no other
column-name-aware caller used the long_strings flag.

Fix: fall back to the caller's requested ``fields`` as the column
ordering when the kernel returns no FIELDS metadata.
"""
from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import MagicMock


@contextmanager
def _fake_conn(rfc_result):
    """Yield a fake _get_connection() context whose .call() returns
    the given RFC_READ_TABLE result dict."""
    conn = MagicMock()
    conn.call.return_value = rfc_result
    @contextmanager
    def _ctx(*_a, **_kw):
        yield conn
    yield _ctx


def _node():
    from sapmap_models import SAPNode, InstanceInfo
    n = SAPNode(sid="S4H", ip="10.0.0.5", hostname="s4h",
                 system_type="ABAP")
    n.instances.append(InstanceInfo(instance_nr="00", ip="10.0.0.5",
                                     ports={3300: "gateway"}))
    return n


def test_read_table_long_strings_recovers_when_kernel_omits_fields_meta(
        monkeypatch):
    """Real S/4 quirk: ET_DATA populated, FIELDS empty.  read_table
    should fall back to the caller's requested fields as the column
    ordering and produce populated row dicts."""
    import sapmap_rfc
    rfc_result = {
        "FIELDS":  [],                  # <-- empty metadata
        "ET_DATA": [
            {"WA": "001|DDIC|testuser@example.com|DN|000"},
            {"WA": "001|JORIS|jvdv@example.com|DN|000"},
        ],
    }
    with _fake_conn(rfc_result) as ctx_factory:
        monkeypatch.setattr(sapmap_rfc, "_get_connection", ctx_factory)
        rows = sapmap_rfc.read_table(
            _node(), "USREXTID",
            fields=["MANDT", "BNAME", "EXTID", "TYPE", "SEQNO"],
            long_strings=True)
    assert len(rows) == 2
    assert rows[0]["MANDT"] == "001"
    assert rows[0]["BNAME"] == "DDIC"
    assert rows[0]["EXTID"] == "testuser@example.com"
    assert rows[0]["TYPE"] == "DN"
    assert rows[0]["SEQNO"] == "000"
    assert rows[1]["BNAME"] == "JORIS"


def test_read_table_long_strings_honours_kernel_fields_when_present(
        monkeypatch):
    """When FIELDS IS populated by the kernel, we keep using it (the
    kernel might have reordered our request).  Confirms the fallback
    doesn't override valid metadata."""
    import sapmap_rfc
    rfc_result = {
        # Kernel returned fields in a different order than requested.
        "FIELDS":  [{"FIELDNAME": "BNAME", "OFFSET": 0, "LENGTH": 12},
                    {"FIELDNAME": "EXTID", "OFFSET": 0, "LENGTH": 1024},
                    {"FIELDNAME": "TYPE",  "OFFSET": 0, "LENGTH": 1}],
        "ET_DATA": [{"WA": "DDIC|testuser@example.com|DN"}],
    }
    with _fake_conn(rfc_result) as ctx_factory:
        monkeypatch.setattr(sapmap_rfc, "_get_connection", ctx_factory)
        rows = sapmap_rfc.read_table(
            _node(), "USREXTID",
            fields=["MANDT", "BNAME", "EXTID", "TYPE", "SEQNO"],
            long_strings=True)
    assert len(rows) == 1
    assert rows[0]["BNAME"] == "DDIC"
    assert rows[0]["EXTID"] == "testuser@example.com"
    assert rows[0]["TYPE"] == "DN"


def test_read_table_typed_struct_rows_still_work(monkeypatch):
    """Some S/4 patches return ET_DATA as typed-struct rows (column
    name → value) instead of delimited WA.  Ensure that path still
    matches even with empty FIELDS metadata."""
    import sapmap_rfc
    rfc_result = {
        "FIELDS":  [],
        "ET_DATA": [
            {"MANDT": "001", "BNAME": "DDIC",
             "EXTID": "testuser@example.com",
             "TYPE": "DN", "SEQNO": "000"},
        ],
    }
    with _fake_conn(rfc_result) as ctx_factory:
        monkeypatch.setattr(sapmap_rfc, "_get_connection", ctx_factory)
        rows = sapmap_rfc.read_table(
            _node(), "USREXTID",
            fields=["MANDT", "BNAME", "EXTID", "TYPE", "SEQNO"],
            long_strings=True)
    assert len(rows) == 1
    assert rows[0]["BNAME"] == "DDIC"


def test_read_table_typed_struct_lowercase_keys(monkeypatch):
    """Regression for the S4H operator bug: kernel returned ET_DATA
    rows as typed structs with lowercase column names — our case-
    sensitive lookup missed them and emitted empty dicts.  The fix
    normalises lookup to uppercase before comparing."""
    import sapmap_rfc
    rfc_result = {
        "FIELDS":  [],
        "ET_DATA": [
            {"mandt": "001", "bname": "DDIC",
             "extid": "testuser@example.com",
             "type":  "DN", "seqno": "000"},
            {"mandt": "001", "bname": "JORIS",
             "extid": "joris@example.com",
             "type":  "LD", "seqno": "000"},
        ],
    }
    with _fake_conn(rfc_result) as ctx_factory:
        monkeypatch.setattr(sapmap_rfc, "_get_connection", ctx_factory)
        rows = sapmap_rfc.read_table(
            _node(), "USREXTID",
            fields=["MANDT", "BNAME", "EXTID", "TYPE", "SEQNO"],
            long_strings=True)
    assert len(rows) == 2
    assert rows[0]["BNAME"] == "DDIC"
    assert rows[0]["EXTID"] == "testuser@example.com"
    assert rows[0]["TYPE"] == "DN"
    assert rows[1]["BNAME"] == "JORIS"
    assert rows[1]["TYPE"] == "LD"


def test_read_table_where_splits_at_word_boundary(monkeypatch):
    """Operator-surfaced bug: capability analyser AGR_1251 reads with
    8+ OR-joined role names produced OPTION_NOT_VALID / "A Boolean
    expression …".  Cause: read_table sliced the WHERE clause at
    exactly 72 chars, breaking a role-name token in half.  ABAP
    concatenates the OPTIONS rows and sees garbage.

    Fix asserts every emitted OPTIONS row ends at a whitespace
    boundary so no token gets split across rows."""
    import sapmap_rfc
    captured = {}
    def _capture(*_args, **params):
        captured.update(params)
        return {"FIELDS": [], "DATA": []}
    class _C:
        call = staticmethod(_capture)
    from contextlib import contextmanager
    @contextmanager
    def _ctx(*a, **kw): yield _C()
    monkeypatch.setattr(sapmap_rfc, "_get_connection", _ctx)
    where = " OR ".join(
        f"AGR_NAME = 'SAP_BC_BASIS_ADMINISTRATOR_{i}'" for i in range(6))
    sapmap_rfc.read_table(
        _node(), "AGR_1251", fields=["AGR_NAME", "OBJECT"],
        where=where, max_rows=100)
    opts = captured.get("OPTIONS") or []
    assert opts, "OPTIONS should be populated for non-empty WHERE"
    # Each row ≤ 72 chars
    for row in opts:
        assert len(row["TEXT"]) <= 72, \
            f"row exceeds 72 chars: {row['TEXT']!r}"
    # No mid-token split — no row ends with an unbalanced quote or
    # partial role name.  Concatenating rows back with spaces must
    # reproduce the original clause (modulo whitespace normalisation).
    joined = " ".join(r["TEXT"] for r in opts)
    # Every role name from the original clause is present intact
    for i in range(6):
        role = f"SAP_BC_BASIS_ADMINISTRATOR_{i}"
        assert role in joined, \
            f"role {role!r} split across OPTIONS rows: {joined!r}"


def test_read_table_where_hard_split_when_no_whitespace(monkeypatch):
    """Degenerate case: a single token >72 chars.  Hard-split at 72
    is the only option — assert we still emit rows and don't hang."""
    import sapmap_rfc
    captured = {}
    def _capture(*_args, **params):
        captured.update(params); return {"FIELDS": [], "DATA": []}
    class _C: call = staticmethod(_capture)
    from contextlib import contextmanager
    @contextmanager
    def _ctx(*a, **kw): yield _C()
    monkeypatch.setattr(sapmap_rfc, "_get_connection", _ctx)
    huge = "A" * 200   # 200-char token, no whitespace
    sapmap_rfc.read_table(_node(), "T", fields=["F"],
                           where=huge, max_rows=1)
    opts = captured["OPTIONS"]
    assert len(opts) == 3   # 200 / 72 = 2.78 → 3 rows
    for row in opts[:-1]:
        assert len(row["TEXT"]) == 72
    assert "".join(r["TEXT"] for r in opts) == huge


def test_read_table_typed_struct_with_wa_present_but_no_delim(monkeypatch):
    """Edge case: kernel returns BOTH a WA (empty / non-delimited) and
    typed-struct keys.  Parser should prefer the typed-struct payload
    so the columns get populated correctly."""
    import sapmap_rfc
    rfc_result = {
        "FIELDS":  [],
        "ET_DATA": [
            {"WA": "", "BNAME": "DDIC", "EXTID": "x",
             "TYPE": "DN", "MANDT": "001", "SEQNO": "0"},
        ],
    }
    with _fake_conn(rfc_result) as ctx_factory:
        monkeypatch.setattr(sapmap_rfc, "_get_connection", ctx_factory)
        rows = sapmap_rfc.read_table(
            _node(), "USREXTID",
            fields=["MANDT", "BNAME", "EXTID", "TYPE", "SEQNO"],
            long_strings=True)
    assert rows[0]["BNAME"] == "DDIC"
