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
            {"WA": "001|DDIC|joris.vdvis@securitybridge.com|DN|000"},
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
    assert rows[0]["EXTID"] == "joris.vdvis@securitybridge.com"
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
        "ET_DATA": [{"WA": "DDIC|joris.vdvis@securitybridge.com|DN"}],
    }
    with _fake_conn(rfc_result) as ctx_factory:
        monkeypatch.setattr(sapmap_rfc, "_get_connection", ctx_factory)
        rows = sapmap_rfc.read_table(
            _node(), "USREXTID",
            fields=["MANDT", "BNAME", "EXTID", "TYPE", "SEQNO"],
            long_strings=True)
    assert len(rows) == 1
    assert rows[0]["BNAME"] == "DDIC"
    assert rows[0]["EXTID"] == "joris.vdvis@securitybridge.com"
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
             "EXTID": "joris.vdvis@securitybridge.com",
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
