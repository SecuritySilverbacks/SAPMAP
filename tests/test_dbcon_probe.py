"""Tests for the DBCON direct-DB pivot primitive (issue #21).

Covers the wire-side field parsing, RSECTAB pairing, and the driver
probe branches that do NOT require hdbcli to be installed.  The
hdbcli-dependent probe path is exercised with a fake dbapi module.
"""
from __future__ import annotations

import sys
import types

import sapmap_exploit  # noqa: F401 — break circular import first
import sap_dbcon_probe as dbcon
from sapmap_models import (
    DBCONConnection, SAPMAPState, SAPNode,
)


# ---------------------------------------------------------------------------
# Model round-trip
# ---------------------------------------------------------------------------

def test_dbcon_connection_roundtrip():
    e = DBCONConnection(
        source_sid="S4H", con_name="HDB_DWH", dbms="HDB",
        host="10.0.0.14", port=30215, user="SAPMAP",
        password="s3cret", dbname="HDB",
        tested=True, reachable=True, is_sap_shape=True,
        target_sid="DWH", pwned=True,
    )
    d = e.to_dict()
    r = DBCONConnection.from_dict(d)
    assert r.source_sid == "S4H" and r.con_name == "HDB_DWH"
    assert r.dbms == "HDB" and r.host == "10.0.0.14" and r.port == 30215
    assert r.user == "SAPMAP" and r.password == "s3cret"
    assert r.dbname == "HDB"
    assert r.tested and r.reachable and r.is_sap_shape and r.pwned
    assert r.target_sid == "DWH"


def test_dbcon_connection_from_dict_ignores_unknown_fields():
    r = DBCONConnection.from_dict({
        "source_sid": "S4H", "con_name": "X",
        "future_field_added_later": "should not raise",
    })
    assert r.source_sid == "S4H" and r.con_name == "X"


def test_sapnode_roundtrip_carries_dbcon_edges():
    n = SAPNode(sid="S4H", ip="10.0.0.1")
    n.dbcon_edges = [DBCONConnection(
        source_sid="S4H", con_name="HDB_DWH", dbms="HDB",
        host="10.0.0.14", port=30215, user="SAPMAP",
        password="x", is_sap_shape=True,
    )]
    d = n.to_dict()
    r = SAPNode.from_dict(d)
    assert len(r.dbcon_edges) == 1
    edge = r.dbcon_edges[0]
    assert edge.con_name == "HDB_DWH" and edge.host == "10.0.0.14"
    assert edge.port == 30215 and edge.is_sap_shape is True


# ---------------------------------------------------------------------------
# CON_ENV parsing
# ---------------------------------------------------------------------------

def test_parse_con_env_hdb_hostport():
    r = dbcon.parse_con_env("HDB", "10.0.0.14:30215")
    assert r == {"host": "10.0.0.14", "port": 30215, "dbname": ""}


def test_parse_con_env_hdb_with_tenant():
    r = dbcon.parse_con_env("HDB", "hana.corp:30015?databaseName=HDW")
    assert r["host"] == "hana.corp" and r["port"] == 30015
    assert r["dbname"] == "HDW"


def test_parse_con_env_hdb_dbname_case_insensitive():
    r = dbcon.parse_con_env("HDB", "h:30013 DATABASENAME=TENANT1")
    assert r["dbname"] == "TENANT1"


def test_parse_con_env_empty_string_safe():
    assert dbcon.parse_con_env("HDB", "") == {
        "host": "", "port": 0, "dbname": ""}


def test_parse_con_env_mssql_best_effort():
    # v1 fallback catches host via SERVER=; port encoded as
    # SERVER=host,port is not parsed (best-effort only).
    r = dbcon.parse_con_env("MSS", "SERVER=sql01.corp;DATABASE=SAPQAS;PORT=1433")
    assert r["host"] == "sql01.corp" and r["port"] == 1433


def test_parse_con_env_oracle_easy_connect_hostport():
    # ORA CON_ENV can be an Easy-Connect string; the fallback catches
    # the first host:port sequence via the generic regex.
    r = dbcon.parse_con_env("ORA", "HOST=oracle01.corp PORT=1521 SID=ERP")
    assert r["host"] == "oracle01.corp" and r["port"] == 1521


def test_parse_con_env_non_hdb_no_match_returns_empty():
    r = dbcon.parse_con_env("DB6", "opaque garbage string")
    assert r == {"host": "", "port": 0, "dbname": ""}


# ---------------------------------------------------------------------------
# read_dbcon — result-bucket handling (DATA vs ET_DATA_4_RETURN)
# ---------------------------------------------------------------------------

class _FakeRFCConn:
    def __init__(self, result_by_kwargs_pred):
        self._pred = result_by_kwargs_pred
        self.calls = []

    def __enter__(self): return self
    def __exit__(self, *a): return False

    def call(self, fm, **kw):
        self.calls.append((fm, kw))
        r = self._pred(kw)
        if isinstance(r, Exception): raise r
        return r


def _install_fake_rfc(monkeypatch, conn):
    """Wire dbcon.read_dbcon to use a fake connection."""
    import sap_dbcon_probe as _dbcon
    import sys as _sys
    fake_rfc_mod = types.ModuleType("sapmap_rfc")
    fake_rfc_mod._get_connection = lambda node, creds: conn
    fake_errors = types.ModuleType("sapmap_errors")
    fake_errors.format_rfc_exception = lambda e: f"{type(e).__name__}: {e}"
    monkeypatch.setitem(_sys.modules, "sapmap_rfc", fake_rfc_mod)
    monkeypatch.setitem(_sys.modules, "sapmap_errors", fake_errors)


def test_read_dbcon_prefers_wide_bucket_when_flag_accepted(monkeypatch):
    """Modern S/4 fills ET_DATA_4_RETURN when USE_ET_DATA_4_RETURN='X'
    is passed; DATA stays empty.  Bug that shipped in v1: we read only
    DATA and got 0 rows.  This regression test locks in the fix."""
    def _pred(kw):
        assert kw.get("USE_ET_DATA_4_RETURN") == "X"
        return {
            "DATA": [],
            "ET_DATA": [
                {"WA": "HDB_DWH|HDB|SAPMAP|10.0.0.14:30215"},
                {"WA": "ORA_LEG|ORA|SYS|HOST=oracle01 PORT=1521"},
            ],
        }
    conn = _FakeRFCConn(_pred)
    _install_fake_rfc(monkeypatch, conn)
    rows = dbcon.read_dbcon(SAPNode(sid="S4H", ip="10.0.0.1"), None)
    assert len(rows) == 2
    assert rows[0]["con_name"] == "HDB_DWH" and rows[0]["dbms"] == "HDB"
    assert rows[0]["user"] == "SAPMAP"
    assert rows[0]["con_env"] == "10.0.0.14:30215"
    assert rows[1]["con_name"] == "ORA_LEG"


def test_read_dbcon_falls_back_to_narrow_bucket(monkeypatch):
    """Older kernels ignore USE_ET_DATA_4_RETURN and populate DATA."""
    def _pred(kw):
        return {
            "DATA": [{"WA": "HDB_DWH|HDB|SAPMAP|10.0.0.14:30215"}],
            "ET_DATA": [],
        }
    conn = _FakeRFCConn(_pred)
    _install_fake_rfc(monkeypatch, conn)
    rows = dbcon.read_dbcon(SAPNode(sid="S4H", ip="10.0.0.1"), None)
    assert len(rows) == 1 and rows[0]["con_name"] == "HDB_DWH"
    assert rows[0]["con_env"] == "10.0.0.14:30215"


def test_read_dbcon_retries_without_flag_on_kwarg_reject(monkeypatch):
    """Older kernels raise when the kwarg is unknown to the FM
    signature — we retry without and read from DATA."""
    call_state = {"n": 0}
    def _pred(kw):
        call_state["n"] += 1
        if call_state["n"] == 1:
            assert kw.get("USE_ET_DATA_4_RETURN") == "X"
            raise Exception("parameter USE_ET_DATA_4_RETURN not found")
        assert "USE_ET_DATA_4_RETURN" not in kw
        return {"DATA": [{"WA": "HDB_X|HDB|X|h:30015"}]}
    conn = _FakeRFCConn(_pred)
    _install_fake_rfc(monkeypatch, conn)
    rows = dbcon.read_dbcon(SAPNode(sid="S4H", ip="10.0.0.1"), None)
    assert call_state["n"] == 2
    assert len(rows) == 1 and rows[0]["con_name"] == "HDB_X"


def test_read_dbcon_empty_both_buckets_returns_empty(monkeypatch):
    """When both RFC_READ_TABLE and the ABAP fallback return empty,
    read_dbcon returns []."""
    conn = _FakeRFCConn(lambda kw: {"DATA": [], "ET_DATA": []})
    _install_fake_rfc(monkeypatch, conn)
    monkeypatch.setattr(dbcon, "_read_dbcon_via_abap",
                          lambda node, creds: [])
    assert dbcon.read_dbcon(SAPNode(sid="S4H", ip="10.0.0.1"), None) == []


def test_read_dbcon_falls_back_to_abap_on_undelimited_line(monkeypatch):
    """S/4 2025 fingerprint (from operator SE37 capture, 2026-08-12):
    ET_DATA rows come back as {'LINE': 'concatenated-fields'} with
    DELIMITER ignored and each field TRIMMED, e.g.
    'TEST_S4DHDBsystems4hanadev:3021500' — unparseable by field
    boundary.  We must recognise the shape, discard the row, and
    escalate to the ABAP-SELECT fallback so the operator still gets
    their DBCON edges."""
    conn = _FakeRFCConn(lambda kw: {
        "DATA": [],
        "ET_DATA": [{"LINE": "TEST_S4DHDBsystems4hanadev:3021500"}],
    })
    _install_fake_rfc(monkeypatch, conn)
    called = {"n": 0}
    def _fake_abap(node, creds):
        called["n"] += 1
        return [{"con_name": "TEST_S4D", "dbms": "HDB",
                 "user": "system", "con_env": "s4hanadev:30215"}]
    monkeypatch.setattr(dbcon, "_read_dbcon_via_abap", _fake_abap)
    rows = dbcon.read_dbcon(SAPNode(sid="S4H", ip="10.0.0.1"), None)
    assert called["n"] == 1, "ABAP fallback must fire on unparseable LINE"
    assert len(rows) == 1
    assert rows[0]["con_name"] == "TEST_S4D"
    assert rows[0]["con_env"] == "s4hanadev:30215"


def test_read_dbcon_falls_back_to_abap_when_all_rfc_empty(monkeypatch):
    """Modern-S/4 hardening symptom: RFC_READ_TABLE succeeds with 0
    rows on every candidate table because DBCON is on the FM's
    protected-tables deny-list.  We must fall through to the
    RFC_ABAP_INSTALL_AND_RUN direct-SELECT path."""
    conn = _FakeRFCConn(lambda kw: {"DATA": [], "ET_DATA": []})
    _install_fake_rfc(monkeypatch, conn)
    called = {"n": 0}
    def _fake_abap(node, creds):
        called["n"] += 1
        return [{"con_name": "TEST_S4D", "dbms": "HDB",
                 "user": "system", "con_env": "s4hanadev:30215"}]
    monkeypatch.setattr(dbcon, "_read_dbcon_via_abap", _fake_abap)
    rows = dbcon.read_dbcon(SAPNode(sid="S4H", ip="10.0.0.1"), None)
    assert called["n"] == 1
    assert len(rows) == 1 and rows[0]["con_name"] == "TEST_S4D"
    assert rows[0]["con_env"] == "s4hanadev:30215"


def test_read_dbcon_via_abap_parses_output(monkeypatch):
    """Direct unit test on the ABAP fallback — verify the '~~~'
    delimited output from RFC_ABAP_INSTALL_AND_RUN's WRITES is
    correctly parsed."""
    import sap_dbcon_probe as _dbcon
    import sys as _sys
    fake_rfc_mod = types.ModuleType("sapmap_rfc")

    class _CM:
        def __enter__(self): return self
        def __exit__(self, *a): return False

    fake_rfc_mod._get_connection = lambda node, creds: _CM()
    def _fake_run(conn, abap, name):
        return {
            "success": True,
            "output": [
                "TEST_S4D~~~HDB~~~system~~~s4hanadev:30215",
                "ORA_LEG~~~ORA~~~SYS~~~HOST=oracle01 PORT=1521",
                "",   # blank lines from ABAP list padding
                "MALFORMED~~~ONLY_TWO",
            ],
            "error": "", "fm_name": "RFC_ABAP_INSTALL_AND_RUN",
        }
    fake_rfc_mod._run_abap_program = _fake_run
    fake_errors = types.ModuleType("sapmap_errors")
    fake_errors.format_rfc_exception = lambda e: str(e)
    monkeypatch.setitem(_sys.modules, "sapmap_rfc", fake_rfc_mod)
    monkeypatch.setitem(_sys.modules, "sapmap_errors", fake_errors)
    rows = _dbcon._read_dbcon_via_abap(SAPNode(sid="S4H", ip="10.0.0.1"), None)
    assert len(rows) == 2
    assert rows[0]["con_name"] == "TEST_S4D" and rows[0]["dbms"] == "HDB"
    assert rows[1]["con_name"] == "ORA_LEG"


def test_read_dbcon_via_abap_failure_returns_empty(monkeypatch):
    import sap_dbcon_probe as _dbcon
    import sys as _sys
    class _CM:
        def __enter__(self): return self
        def __exit__(self, *a): return False
    fake_rfc_mod = types.ModuleType("sapmap_rfc")
    fake_rfc_mod._get_connection = lambda node, creds: _CM()
    fake_rfc_mod._run_abap_program = lambda *a, **kw: {
        "success": False, "output": [],
        "error": "S_DEVELOP denied", "fm_name": None}
    fake_errors = types.ModuleType("sapmap_errors")
    fake_errors.format_rfc_exception = lambda e: str(e)
    monkeypatch.setitem(_sys.modules, "sapmap_rfc", fake_rfc_mod)
    monkeypatch.setitem(_sys.modules, "sapmap_errors", fake_errors)
    assert _dbcon._read_dbcon_via_abap(SAPNode(sid="S4H", ip="10.0.0.1"),
                                          None) == []


def test_read_dbcon_malformed_row_skipped(monkeypatch):
    conn = _FakeRFCConn(lambda kw: {"ET_DATA": [
        {"WA": "GOOD|HDB|U|h:30015"},
        {"WA": "|HDB|U|h:30015"},           # empty con_name
        {"WA": "TOO|FEW"},                   # missing fields
    ]})
    _install_fake_rfc(monkeypatch, conn)
    rows = dbcon.read_dbcon(SAPNode(sid="S4H", ip="10.0.0.1"), None)
    assert len(rows) == 1 and rows[0]["con_name"] == "GOOD"


# ---------------------------------------------------------------------------
# SecStore <-> DBCON pairing
# ---------------------------------------------------------------------------

def _entry(ident_clean, pw="s3cret"):
    return {
        "ident_clean": ident_clean,
        "category": "db",
        "password": pw,
    }


def test_integrate_no_secstore_entries_returns_empty(monkeypatch):
    n = SAPNode(sid="S4H", ip="10.0.0.1")
    state = SAPMAPState()
    added = dbcon.integrate_dbcon_from_secstore(n, state, None)
    assert added == []
    assert n.dbcon_edges == []


def test_integrate_secstore_no_dbcon_read_returns_empty(monkeypatch):
    n = SAPNode(sid="S4H", ip="10.0.0.1")
    n.secstore_entries = [_entry("/DBCON/HDB_DWH")]
    state = SAPMAPState()
    monkeypatch.setattr(dbcon, "read_dbcon", lambda *a, **kw: [])
    added = dbcon.integrate_dbcon_from_secstore(n, state, None)
    assert added == []
    assert n.dbcon_edges == []


def test_integrate_pairs_and_parses(monkeypatch):
    n = SAPNode(sid="S4H", ip="10.0.0.1")
    n.secstore_entries = [
        _entry("/DBCON/HDB_DWH", pw="hana-pw"),
        _entry("/DBCON/ORA_LEGACY", pw="ora-pw"),
        _entry("/RFC/SOME_OTHER"),         # non-DB category slot
    ]
    n.secstore_entries[2]["category"] = "rfc"
    monkeypatch.setattr(dbcon, "read_dbcon", lambda *a, **kw: [
        {"con_name": "HDB_DWH", "dbms": "HDB", "user": "SAPMAP",
         "con_env": "10.0.0.14:30215"},
        {"con_name": "ORA_LEGACY", "dbms": "ORA", "user": "SYS",
         "con_env": "HOST=oracle01 PORT=1521 SID=ERP"},
    ])
    state = SAPMAPState()
    added = dbcon.integrate_dbcon_from_secstore(n, state, None)
    assert len(added) == 2
    assert len(n.dbcon_edges) == 2
    hdb = next(e for e in n.dbcon_edges if e.con_name == "HDB_DWH")
    assert hdb.host == "10.0.0.14" and hdb.port == 30215
    assert hdb.user == "SAPMAP" and hdb.password == "hana-pw"
    ora = next(e for e in n.dbcon_edges if e.con_name == "ORA_LEGACY")
    assert ora.host == "oracle01" and ora.port == 1521
    assert ora.password == "ora-pw"


def test_integrate_rerun_preserves_probe_state(monkeypatch):
    n = SAPNode(sid="S4H", ip="10.0.0.1")
    n.secstore_entries = [_entry("/DBCON/HDB_DWH", pw="new-pw")]
    n.dbcon_edges = [DBCONConnection(
        source_sid="S4H", con_name="HDB_DWH", dbms="HDB",
        host="old", port=1, user="old", password="old-pw",
        tested=True, reachable=True, is_sap_shape=True,
        target_sid="DWH", pwned=True, tested_at="2026-08-11T10:00:00+00:00",
    )]
    monkeypatch.setattr(dbcon, "read_dbcon", lambda *a, **kw: [
        {"con_name": "HDB_DWH", "dbms": "HDB", "user": "SAPMAP",
         "con_env": "10.0.0.14:30215"},
    ])
    added = dbcon.integrate_dbcon_from_secstore(n, SAPMAPState(), None)
    assert len(added) == 1
    e = n.dbcon_edges[0]
    # New host/port/user picked up:
    assert e.host == "10.0.0.14" and e.port == 30215 and e.user == "SAPMAP"
    assert e.password == "new-pw"
    # Prior probe verdict preserved:
    assert e.tested is True and e.reachable is True
    assert e.is_sap_shape is True and e.target_sid == "DWH"
    assert e.pwned is True and e.tested_at.startswith("2026-08-11")


def test_integrate_secstore_orphan_entry_skipped(monkeypatch):
    """SecStore has /DBCON/FOO but DBCON table has no matching row —
    skip, don't crash."""
    n = SAPNode(sid="S4H", ip="10.0.0.1")
    n.secstore_entries = [_entry("/DBCON/GONE")]
    monkeypatch.setattr(dbcon, "read_dbcon", lambda *a, **kw: [
        {"con_name": "STILL_HERE", "dbms": "HDB", "user": "x",
         "con_env": "h:30015"},
    ])
    added = dbcon.integrate_dbcon_from_secstore(n, SAPMAPState(), None)
    assert added == []
    assert n.dbcon_edges == []


def test_integrate_non_dbcon_ident_ignored(monkeypatch):
    """A db-category entry whose ident_clean is NOT /DBCON/... (e.g. a
    legacy pattern) must not be paired."""
    n = SAPNode(sid="S4H", ip="10.0.0.1")
    n.secstore_entries = [_entry("/HTTP/foo", pw="x")]
    monkeypatch.setattr(dbcon, "read_dbcon", lambda *a, **kw: [
        {"con_name": "HDB_DWH", "dbms": "HDB", "user": "x",
         "con_env": "h:30015"}])
    added = dbcon.integrate_dbcon_from_secstore(n, SAPMAPState(), None)
    assert added == []


# ---------------------------------------------------------------------------
# probe_dbcon_edge — hdbcli-independent branches
# ---------------------------------------------------------------------------

def test_probe_non_hdb_marks_unsupported():
    e = DBCONConnection(
        source_sid="S4H", con_name="ORA_LEGACY", dbms="ORA",
        host="oracle01", port=1521, user="SYS", password="x")
    dbcon.probe_dbcon_edge(e)
    assert e.tested is True
    assert e.reachable is False
    assert "v1 supports HDB only" in e.error


def test_probe_hdb_no_driver_installed(monkeypatch):
    e = DBCONConnection(
        source_sid="S4H", con_name="HDB_DWH", dbms="HDB",
        host="10.0.0.14", port=30215, user="SAPMAP", password="x")
    monkeypatch.setattr(
        dbcon, "_import_hdbcli", lambda: (None, "hdbcli not installed"))
    dbcon.probe_dbcon_edge(e)
    assert e.tested is True and e.reachable is False
    assert "hdbcli not installed" in e.error


# ---------------------------------------------------------------------------
# probe_dbcon_edge — with a fake hdbcli module
# ---------------------------------------------------------------------------

class _FakeCursor:
    def __init__(self, table_map):
        self._map = table_map          # sql (upper first-15 chars) → row list
        self._rows = []

    def execute(self, sql, params=None):
        s = sql.strip().upper()
        for key, rows in self._map.items():
            if s.startswith(key):
                self._rows = list(rows)
                return
        raise Exception(f"no such table (test): {sql}")

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def close(self):
        pass


class _FakeConn:
    def __init__(self, table_map, connected=True):
        self._map = table_map
        self._connected = connected

    def isconnected(self):
        return self._connected

    def cursor(self):
        return _FakeCursor(self._map)

    def close(self):
        pass


def _fake_dbapi_module(conn):
    m = types.ModuleType("hdbcli.dbapi")
    m.connect = lambda **kw: conn
    return m


def test_probe_hdb_sap_shape_reads_sid(monkeypatch):
    conn = _FakeConn({
        "SELECT COUNT(*) FROM USR02": [(42,)],
        "SELECT SYSID FROM T000":    [("DWH",)],
    })
    monkeypatch.setattr(
        dbcon, "_import_hdbcli",
        lambda: (_fake_dbapi_module(conn), None))
    e = DBCONConnection(
        source_sid="S4H", con_name="HDB_DWH", dbms="HDB",
        host="10.0.0.14", port=30215, user="SAPMAP", password="x")
    dbcon.probe_dbcon_edge(e)
    assert e.tested is True and e.reachable is True
    assert e.is_sap_shape is True
    assert e.target_sid == "DWH"
    assert e.error == ""


def test_probe_hdb_non_sap_shape(monkeypatch):
    class _NoUsr02Cur(_FakeCursor):
        def execute(self, sql, params=None):
            if "USR02" in sql.upper():
                # HANA 259 — invalid table name
                exc = Exception("(259, 'invalid table name: USR02')")
                exc.errorcode = 259
                raise exc
            super().execute(sql, params)

    class _Conn(_FakeConn):
        def cursor(self):
            return _NoUsr02Cur(self._map)

    conn = _Conn({})
    monkeypatch.setattr(
        dbcon, "_import_hdbcli",
        lambda: (_fake_dbapi_module(conn), None))
    e = DBCONConnection(
        source_sid="S4H", con_name="ANALYTICS", dbms="HDB",
        host="dw.corp", port=30015, user="x", password="y")
    dbcon.probe_dbcon_edge(e)
    assert e.tested is True and e.reachable is True
    assert e.is_sap_shape is False
    assert e.sap_shape_reason == "usr02_missing"
    assert e.target_sid == ""


def test_probe_hdb_no_permission_is_inconclusive(monkeypatch):
    """HANA 258 (insufficient privilege) means SAP-shape verdict is
    INCONCLUSIVE, not definitively non-SAP — a hardened SAP DB with
    a restricted DBCON user looks identical to a real non-SAP DB
    otherwise."""
    class _NoAuthCur(_FakeCursor):
        def execute(self, sql, params=None):
            if "USR02" in sql.upper():
                exc = Exception("(258, 'insufficient privilege: Not authorized')")
                exc.errorcode = 258
                raise exc
            super().execute(sql, params)

    class _Conn(_FakeConn):
        def cursor(self):
            return _NoAuthCur(self._map)

    conn = _Conn({})
    monkeypatch.setattr(
        dbcon, "_import_hdbcli",
        lambda: (_fake_dbapi_module(conn), None))
    e = DBCONConnection(
        source_sid="S4H", con_name="X", dbms="HDB",
        host="h", port=30015, user="x", password="y")
    dbcon.probe_dbcon_edge(e)
    assert e.tested is True and e.reachable is True
    assert e.is_sap_shape is False
    assert e.sap_shape_reason == "no_permission"
    assert "258" in e.error


def test_probe_hdb_sap_shape_records_reason(monkeypatch):
    conn = _FakeConn({
        "SELECT COUNT(*) FROM USR02": [(42,)],
        "SELECT SYSID FROM T000":    [("DWH",)],
    })
    monkeypatch.setattr(
        dbcon, "_import_hdbcli",
        lambda: (_fake_dbapi_module(conn), None))
    e = DBCONConnection(
        source_sid="S4H", con_name="HDB_DWH", dbms="HDB",
        host="10.0.0.14", port=30215, user="SAPMAP", password="x")
    dbcon.probe_dbcon_edge(e)
    assert e.is_sap_shape is True
    assert e.sap_shape_reason == "usr02_present"


def test_hana_error_code_parses_from_errorcode_attr():
    class _E(Exception):
        def __init__(self, msg, code):
            super().__init__(msg); self.errorcode = code
    assert dbcon._hana_error_code(_E("boom", 259)) == 259
    assert dbcon._hana_error_code(_E("nope", 258)) == 258


def test_hana_error_code_parses_from_message_tuple():
    e = Exception("(259, 'invalid table name: USR02')")
    assert dbcon._hana_error_code(e) == 259


def test_hana_error_code_returns_none_on_plain_exception():
    assert dbcon._hana_error_code(Exception("random failure")) is None


def test_probe_hdb_connect_raises(monkeypatch):
    m = types.ModuleType("hdbcli.dbapi")
    def _explode(**_kw): raise Exception("connection refused")
    m.connect = _explode
    monkeypatch.setattr(dbcon, "_import_hdbcli", lambda: (m, None))
    e = DBCONConnection(
        source_sid="S4H", con_name="HDB_DWH", dbms="HDB",
        host="10.0.0.14", port=30215, user="SAPMAP", password="x")
    dbcon.probe_dbcon_edge(e)
    assert e.tested is True and e.reachable is False
    assert "connection refused" in e.error


# ---------------------------------------------------------------------------
# create_sapmap_user_via_dbcon — guard rails
# ---------------------------------------------------------------------------

def test_create_user_refuses_non_hdb():
    e = DBCONConnection(source_sid="S4H", con_name="X", dbms="MSS",
                          reachable=True, is_sap_shape=True)
    r = dbcon.create_sapmap_user_via_dbcon(e, "DWH", "000")
    assert r["ok"] is False and "HDB only" in r["error"]


def test_create_user_refuses_unreachable():
    e = DBCONConnection(source_sid="S4H", con_name="X", dbms="HDB",
                          reachable=False)
    r = dbcon.create_sapmap_user_via_dbcon(e, "DWH", "000")
    assert r["ok"] is False and "not reachable" in r["error"]


def test_create_user_refuses_non_sap_shape():
    e = DBCONConnection(source_sid="S4H", con_name="X", dbms="HDB",
                          reachable=True, is_sap_shape=False)
    r = dbcon.create_sapmap_user_via_dbcon(e, "DWH", "000")
    assert r["ok"] is False and "not a SAP-shape" in r["error"]


def test_create_user_missing_hdbcli():
    e = DBCONConnection(source_sid="S4H", con_name="X", dbms="HDB",
                          reachable=True, is_sap_shape=True)
    # Guarantee real dbcon._import_hdbcli returns (None, err) by
    # transient monkeypatch — mirrors "hdbcli truly missing".
    import unittest.mock as _mock
    with _mock.patch.object(dbcon, "_import_hdbcli",
                              return_value=(None, "hdbcli not installed")):
        r = dbcon.create_sapmap_user_via_dbcon(e, "DWH", "000")
    assert r["ok"] is False and "hdbcli" in r["error"]


# ---------------------------------------------------------------------------
# create_sapmap_user_via_dbcon — full happy path with fake driver
# ---------------------------------------------------------------------------

class _RecordingCursor:
    def __init__(self, executed, verify_count):
        self._executed = executed
        self._verify_count = verify_count
        self._pending_row = None

    def execute(self, sql, params=None):
        self._executed.append((sql, params))
        s = sql.strip().upper()
        if s.startswith("SELECT COUNT(*) FROM USR02"):
            self._pending_row = (self._verify_count,)
        else:
            self._pending_row = None

    def fetchone(self):
        return self._pending_row

    def close(self):
        pass


class _RecordingConn:
    def __init__(self, executed, verify_count=1):
        self._executed = executed
        self._verify_count = verify_count

    def cursor(self):
        return _RecordingCursor(self._executed, self._verify_count)

    def close(self):
        pass


def test_create_user_happy_path_records_created_user(monkeypatch):
    executed = []
    conn = _RecordingConn(executed, verify_count=1)
    monkeypatch.setattr(
        dbcon, "_import_hdbcli",
        lambda: (_fake_dbapi_module(conn), None))
    e = DBCONConnection(
        source_sid="S4H", con_name="HDB_DWH", dbms="HDB",
        host="10.0.0.14", port=30215, user="SAPMAP", password="x",
        reachable=True, is_sap_shape=True)
    src = SAPNode(sid="S4H", ip="10.0.0.1")
    r = dbcon.create_sapmap_user_via_dbcon(
        e, target_sid="DWH", client="000", source_node=src)
    assert r["ok"] is True and r["verified"] is True
    assert r["statements_total"] > 0
    assert r["statements_ok"] == r["statements_total"]
    assert e.pwned is True
    # CreatedUser landed on the source node:
    assert len(src.created_users) == 1
    cu = src.created_users[0]
    assert cu.username == "SAPMAP00" and cu.sid == "DWH"
    assert cu.client == "000" and cu.method == "dbcon_direct"


def test_enumerate_hana_tables_happy_path(monkeypatch):
    """SYS.M_TABLES returns rows sorted by row-count desc; the fn
    caches them onto edge.enumerated_tables and returns a summary."""
    class _MtCur(_FakeCursor):
        def execute(self, sql, params=None):
            self._executed_sql = sql.upper()

        def fetchall(self):
            if "M_TABLES" in getattr(self, "_executed_sql", ""):
                return [
                    ("SAPQAS", "BKPF",    1234567, "COLUMN"),
                    ("SAPQAS", "BSEG",     987654, "COLUMN"),
                    ("PROJECT", "AUDIT_LOG", 100, "ROW"),
                ]
            return []

    class _Conn(_FakeConn):
        def cursor(self):
            return _MtCur(self._map)

    conn = _Conn({})
    monkeypatch.setattr(
        dbcon, "_import_hdbcli",
        lambda: (_fake_dbapi_module(conn), None))
    e = DBCONConnection(
        source_sid="S4H", con_name="HDB_DWH", dbms="HDB",
        host="10.0.0.14", port=30215, user="x", password="y",
        reachable=True)
    res = dbcon.enumerate_hana_tables(e, limit=50)
    assert res["ok"] is True and res["count"] == 3
    assert res["tables"][0]["schema"] == "SAPQAS"
    assert res["tables"][0]["table"] == "BKPF"
    assert res["tables"][0]["rows"] == 1234567
    # Cached onto the edge for later panel re-render
    assert len(e.enumerated_tables) == 3


def test_enumerate_hana_tables_unreachable_short_circuits():
    e = DBCONConnection(source_sid="S4H", con_name="X", dbms="HDB",
                          reachable=False)
    r = dbcon.enumerate_hana_tables(e)
    assert r["ok"] is False and "not reachable" in r["error"]


def test_enumerate_hana_tables_non_hdb_refused():
    e = DBCONConnection(source_sid="S4H", con_name="X", dbms="ORA",
                          reachable=True)
    r = dbcon.enumerate_hana_tables(e)
    assert r["ok"] is False and "HDB only" in r["error"]


def test_peek_hana_table_rejects_bad_identifier():
    e = DBCONConnection(source_sid="S4H", con_name="X", dbms="HDB",
                          reachable=True)
    r = dbcon.peek_hana_table(e, 'ok', 'BAD"; DROP TABLE X --')
    assert r["ok"] is False and "invalid table identifier" in r["error"]
    r = dbcon.peek_hana_table(e, 'BAD"; DROP', 'ok')
    assert r["ok"] is False and "invalid schema identifier" in r["error"]


def test_peek_hana_table_hex_encodes_binary_columns(monkeypatch):
    """RAW/BLOB columns come back as memoryview / bytes from hdbcli.
    str(v) → '<memory at 0x…>' which is useless in a CSV.  We must
    hex-encode instead so the value round-trips."""
    class _Cur(_FakeCursor):
        description = [("BNAME",), ("BCODE",), ("PASSCODE",)]
        def execute(self, sql, params=None): pass
        def fetchall(self):
            return [
                ("DDIC", memoryview(b"\xde\xad\xbe\xef"),
                 b"\xca\xfe\xba\xbe\xff"),
                ("SAPADM", None, bytearray(b"\x00\x11")),
            ]
    class _Conn(_FakeConn):
        def cursor(self): return _Cur(self._map)
    conn = _Conn({})
    monkeypatch.setattr(dbcon, "_import_hdbcli",
                          lambda: (_fake_dbapi_module(conn), None))
    e = DBCONConnection(source_sid="S4H", con_name="X", dbms="HDB",
                          host="h", port=30215, user="x", password="y",
                          reachable=True)
    r = dbcon.peek_hana_table(e, "SAPHANADB", "USR02", limit=5)
    assert r["ok"] is True
    assert r["rows"][0] == ["DDIC", "DEADBEEF", "CAFEBABEFF"]
    assert r["rows"][1] == ["SAPADM", None, "0011"]
    # Absolutely never the Python repr
    for row in r["rows"]:
        for v in row:
            if v is not None:
                assert "<memory" not in v, \
                    f"binary column leaked Python repr: {v!r}"


def test_peek_hana_table_happy_path(monkeypatch):
    class _Cur(_FakeCursor):
        description = [("COL1",), ("COL2",)]
        def execute(self, sql, params=None):
            assert '"SAPQAS"."BKPF"' in sql, \
                f"identifier not properly quoted: {sql}"
            assert "LIMIT 5" in sql
        def fetchall(self):
            return [(1, "hello"), (2, None), (3, "world")]

    class _Conn(_FakeConn):
        def cursor(self):
            return _Cur(self._map)

    conn = _Conn({})
    monkeypatch.setattr(
        dbcon, "_import_hdbcli",
        lambda: (_fake_dbapi_module(conn), None))
    e = DBCONConnection(
        source_sid="S4H", con_name="HDB_DWH", dbms="HDB",
        host="h", port=30215, user="x", password="y",
        reachable=True)
    r = dbcon.peek_hana_table(e, "SAPQAS", "BKPF", limit=5)
    assert r["ok"] is True
    assert r["columns"] == ["COL1", "COL2"]
    assert len(r["rows"]) == 3
    # None survives round-trip; other values become strings
    assert r["rows"][0] == ["1", "hello"]
    assert r["rows"][1] == ["2", None]


def test_dbcon_connection_roundtrip_carries_new_fields():
    e = DBCONConnection(
        source_sid="S4H", con_name="HDB_DWH", dbms="HDB",
        sap_shape_reason="no_permission",
        enumerated_tables=[{"schema": "S", "table": "T", "rows": 1, "table_type": "ROW"}],
        recon_facts={"license": {"columns": ["SID"], "rows": [["DWH"]], "count": 1}},
        usr02_hashes_loot_path="/tmp/x.txt")
    d = e.to_dict()
    r = DBCONConnection.from_dict(d)
    assert r.sap_shape_reason == "no_permission"
    assert len(r.enumerated_tables) == 1
    assert r.enumerated_tables[0]["schema"] == "S"
    assert r.recon_facts["license"]["count"] == 1
    assert r.usr02_hashes_loot_path == "/tmp/x.txt"


# ---------------------------------------------------------------------------
# describe_hana_table, hana_recon_sweep, dump_usr02_hashes
# ---------------------------------------------------------------------------

def test_describe_hana_table_rejects_bad_identifier():
    e = DBCONConnection(source_sid="S4H", con_name="X", dbms="HDB",
                          reachable=True)
    r = dbcon.describe_hana_table(e, 'BAD"; DROP', 'ok')
    assert r["ok"] is False and "invalid schema identifier" in r["error"]


def test_describe_hana_table_happy_path(monkeypatch):
    class _Cur(_FakeCursor):
        def execute(self, sql, params=None):
            assert "TABLE_COLUMNS" in sql
        def fetchall(self):
            return [
                ("BNAME", "NVARCHAR", 12, "FALSE", 1),
                ("BCODE", "VARBINARY", 8, "TRUE", 2),
            ]
    class _Conn(_FakeConn):
        def cursor(self): return _Cur(self._map)
    conn = _Conn({})
    monkeypatch.setattr(dbcon, "_import_hdbcli",
                          lambda: (_fake_dbapi_module(conn), None))
    e = DBCONConnection(source_sid="S4H", con_name="X", dbms="HDB",
                          host="h", port=30215, user="x", password="y",
                          reachable=True)
    r = dbcon.describe_hana_table(e, "SAPHANADB", "USR02")
    assert r["ok"] is True and len(r["columns"]) == 2
    assert r["columns"][0]["name"] == "BNAME"
    assert r["columns"][0]["nullable"] is False
    assert r["columns"][1]["nullable"] is True


def test_hana_recon_sweep_captures_per_query_errors(monkeypatch):
    """Individual query failures must be stored per-key without
    aborting the whole sweep."""
    call_log = []
    class _Cur(_FakeCursor):
        description = [("HOST",), ("VALUE",)]
        def execute(self, sql, params=None):
            call_log.append(sql[:60])
            if "T000" in sql:
                exc = Exception("(258, 'insufficient privilege: T000')")
                exc.errorcode = 258
                raise exc
        def fetchall(self):
            return [("srv01", "2.00.070")]
    class _Conn(_FakeConn):
        def cursor(self): return _Cur(self._map)
    conn = _Conn({})
    monkeypatch.setattr(dbcon, "_import_hdbcli",
                          lambda: (_fake_dbapi_module(conn), None))
    e = DBCONConnection(source_sid="S4H", con_name="X", dbms="HDB",
                          host="h", port=30215, user="x", password="y",
                          reachable=True)
    r = dbcon.hana_recon_sweep(e)
    assert r["ok"] is True
    # T000 (clients query) should have an error captured, others rows
    assert "error" in r["facts"]["clients"]
    assert "258" in r["facts"]["clients"]["error"]
    assert r["facts"]["host_info"]["count"] == 1
    # Ensure cached back onto the edge
    assert e.recon_facts["host_info"]["count"] == 1


def test_hana_recon_sweep_unreachable_short_circuits():
    e = DBCONConnection(source_sid="S4H", con_name="X", dbms="HDB",
                          reachable=False)
    r = dbcon.hana_recon_sweep(e)
    assert r["ok"] is False and "not reachable" in r["error"]


def test_dump_usr02_refuses_non_sap_shape():
    e = DBCONConnection(source_sid="S4H", con_name="X", dbms="HDB",
                          reachable=True, is_sap_shape=False)
    r = dbcon.dump_usr02_hashes(e)
    assert r["ok"] is False and "SAP-shape" in r["error"]


def test_dump_usr02_writes_hashcat_file(monkeypatch, tmp_path):
    """SELECT + write loot flow — verify header format and row layout."""
    class _Cur(_FakeCursor):
        def execute(self, sql, params=None):
            self._last_sql = sql
        def fetchone(self):
            # Called for schema resolution: SYS.TABLES probe
            return (1,) if "SYS.TABLES" in getattr(self, "_last_sql", "") else None
        def fetchall(self):
            if "USR02" in getattr(self, "_last_sql", "") \
               and "SELECT MANDT" in getattr(self, "_last_sql", ""):
                return [
                    ("000", "SAP*", None, None, ""),          # dropped: BNAME=SAP*
                    ("000", "DDIC",
                     b"\xde\xad\xbe\xef",           # BCODE
                     b"\xca\xfe\xba\xbe\xff",       # PASSCODE
                     "{x-issha, 1024}abc="),
                    ("100", "SAPMAP00", b"", b"", "{x-issha}xyz="),
                ]
            return []
    class _Conn(_FakeConn):
        def cursor(self): return _Cur(self._map)
    conn = _Conn({})
    monkeypatch.setattr(dbcon, "_import_hdbcli",
                          lambda: (_fake_dbapi_module(conn), None))
    monkeypatch.setattr(dbcon, "_resolve_sap_schema",
                          lambda *a, **kw: "SAPHANADB")
    e = DBCONConnection(source_sid="S4H", con_name="HDB_DWH", dbms="HDB",
                          host="h", port=30215, user="x", password="y",
                          reachable=True, is_sap_shape=True,
                          target_sid="DWH")
    r = dbcon.dump_usr02_hashes(e, loot_dir=str(tmp_path))
    assert r["ok"] is True
    assert r["count"] == 3         # SAP* row now kept (filter removed)
    assert r["hash_types"]["bcode"] == 1
    assert r["hash_types"]["passcode"] == 1
    assert r["hash_types"]["pwdsaltedhash"] == 2
    assert e.usr02_hashes_loot_path == r["loot_path"]
    content = open(r["loot_path"]).read()
    assert "SAPMAP DBCON USR02" in content
    assert "DEADBEEF" in content   # BCODE hex
    assert "CAFEBABEFF" in content # PASSCODE hex
    assert "{x-issha, 1024}abc=" in content


# ---------------------------------------------------------------------------
# materialize_target_as_sap_node
# ---------------------------------------------------------------------------

def test_materialize_creates_new_sap_node(monkeypatch):
    from sapmap_models import SAPMAPState
    state = SAPMAPState()
    state.add_node(SAPNode(sid="S4H", ip="10.0.0.1"))
    edge = DBCONConnection(source_sid="S4H", con_name="HDB_DWH",
                              dbms="HDB", host="s4hanadev", port=30215,
                              reachable=True, is_sap_shape=True,
                              target_sid="DWH")
    node = dbcon.materialize_target_as_sap_node(edge, state)
    assert node is not None
    assert node.sid == "DWH"
    assert node.ip == "s4hanadev"
    assert node.discovered_via_dbcon is True
    assert node.dbcon_parent_sid == "S4H"
    assert node.dbcon_parent_con_name == "HDB_DWH"
    assert state.get_node("DWH") is not None


def test_materialize_idempotent_tags_existing_node():
    from sapmap_models import SAPMAPState
    state = SAPMAPState()
    state.add_node(SAPNode(sid="DWH", ip="10.0.0.14",
                             discovered_via_dbcon=False))
    edge = DBCONConnection(source_sid="S4H", con_name="X", dbms="HDB",
                              reachable=True, is_sap_shape=True,
                              target_sid="DWH", host="10.0.0.14")
    node = dbcon.materialize_target_as_sap_node(edge, state)
    # Same node — tagged but not duplicated
    assert node is state.get_node("DWH")
    assert node.discovered_via_dbcon is True
    assert node.dbcon_parent_sid == "S4H"
    # Still exactly one node in state
    assert len([n for n in state.nodes.values() if n.sid == "DWH"]) == 1


def test_materialize_skips_when_not_sap_shape():
    from sapmap_models import SAPMAPState
    state = SAPMAPState()
    edge = DBCONConnection(source_sid="S4H", con_name="X", dbms="HDB",
                              reachable=True, is_sap_shape=False,
                              target_sid="DWH")
    assert dbcon.materialize_target_as_sap_node(edge, state) is None
    assert state.get_node("DWH") is None


def test_probe_dbcon_edge_auto_materializes_with_state(monkeypatch):
    """probe_dbcon_edge with state= should auto-add the target SAPNode
    when SAP-shape + target_sid land."""
    from sapmap_models import SAPMAPState
    conn = _FakeConn({
        "SELECT COUNT(*) FROM USR02": [(1,)],
        "SELECT SYSID FROM T000":    [("DWH",)],
    })
    monkeypatch.setattr(dbcon, "_import_hdbcli",
                          lambda: (_fake_dbapi_module(conn), None))
    state = SAPMAPState()
    state.add_node(SAPNode(sid="S4H", ip="10.0.0.1"))
    e = DBCONConnection(source_sid="S4H", con_name="HDB_DWH",
                          dbms="HDB", host="s4hanadev", port=30215,
                          user="x", password="y")
    dbcon.probe_dbcon_edge(e, state=state)
    assert e.is_sap_shape is True and e.target_sid == "DWH"
    dwh = state.get_node("DWH")
    assert dwh is not None
    assert dwh.discovered_via_dbcon is True


def test_probe_dbcon_edge_skips_materialize_without_state(monkeypatch):
    """Backwards-compat: probe without state=state stays a no-op on
    the state side, just mutates the edge (original v1 contract)."""
    conn = _FakeConn({
        "SELECT COUNT(*) FROM USR02": [(1,)],
        "SELECT SYSID FROM T000":    [("DWH",)],
    })
    monkeypatch.setattr(dbcon, "_import_hdbcli",
                          lambda: (_fake_dbapi_module(conn), None))
    e = DBCONConnection(source_sid="S4H", con_name="HDB_DWH",
                          dbms="HDB", host="h", port=30215,
                          user="x", password="y")
    dbcon.probe_dbcon_edge(e)   # no state arg
    assert e.is_sap_shape is True and e.target_sid == "DWH"


def test_create_user_verify_missing_row_marks_failure(monkeypatch):
    executed = []
    conn = _RecordingConn(executed, verify_count=0)
    monkeypatch.setattr(
        dbcon, "_import_hdbcli",
        lambda: (_fake_dbapi_module(conn), None))
    e = DBCONConnection(
        source_sid="S4H", con_name="HDB_DWH", dbms="HDB",
        host="10.0.0.14", port=30215, user="SAPMAP", password="x",
        reachable=True, is_sap_shape=True)
    r = dbcon.create_sapmap_user_via_dbcon(e, "DWH", "000")
    assert r["ok"] is False
    assert "verify" in r["error"] or "0 rows" in r["error"]
    assert e.pwned is False
