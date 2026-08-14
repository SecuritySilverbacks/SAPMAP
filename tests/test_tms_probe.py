"""Tests for CTS/TMS pivot Bundle 1 (sap_tms_probe.py)."""
from __future__ import annotations

import sys
import types

import sapmap_exploit  # noqa: F401 — break circular import first
import sap_tms_probe as tms
from sapmap_models import (
    TMSDestination, SAPNode, SAPMAPState,
)


# ---------------------------------------------------------------------------
# Model round-trip
# ---------------------------------------------------------------------------

def test_tms_destination_roundtrip():
    d = TMSDestination(
        source_sid="S4H", target_sid="Q01", target_host="q01host",
        target_client="000", domain="DEV", is_controller=True,
        password="s3cret", tested=True, logon_ok=True,
        tmsadm_roles=["SAP_ALL", "S_CTS_ALL"], tmsadm_has_sap_all=True,
        buffer_count=3, pwned=False)
    j = d.to_dict()
    r = TMSDestination.from_dict(j)
    assert r.target_sid == "Q01" and r.is_controller
    assert r.tmsadm_has_sap_all is True
    assert r.buffer_count == 3
    assert "SAP_ALL" in r.tmsadm_roles


def test_sapnode_roundtrip_carries_tms_destinations():
    n = SAPNode(sid="S4H", ip="10.0.0.1", tms_domain="DEV",
                  is_tms_controller=False)
    n.tms_destinations = [TMSDestination(
        source_sid="S4H", target_sid="P01", target_host="p01host",
        domain="DEV", is_controller=True, password="x")]
    d = n.to_dict()
    r = SAPNode.from_dict(d)
    assert len(r.tms_destinations) == 1
    assert r.tms_destinations[0].target_sid == "P01"
    assert r.tms_destinations[0].is_controller is True
    assert r.tms_domain == "DEV"


# ---------------------------------------------------------------------------
# read_tms_config — TMSCSYS + TMSMCONF parsing
# ---------------------------------------------------------------------------

class _FakeConn:
    def __init__(self, table_responses):
        self._map = table_responses
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def call(self, fm, **kw):
        qt = kw.get("QUERY_TABLE", "")
        r = self._map.get(qt)
        if isinstance(r, Exception): raise r
        return r or {"ET_DATA": [], "DATA": []}


def _install_fake_rfc(monkeypatch, conn):
    fake_mod = types.ModuleType("sapmap_rfc")
    fake_mod._get_connection = lambda node, creds: conn
    fake_errors = types.ModuleType("sapmap_errors")
    fake_errors.format_rfc_exception = lambda e: f"{type(e).__name__}: {e}"
    monkeypatch.setitem(sys.modules, "sapmap_rfc", fake_mod)
    monkeypatch.setitem(sys.modules, "sapmap_errors", fake_errors)


def test_read_tms_config_parses_domain_and_members(monkeypatch):
    conn = _FakeConn({
        "TMSMCONF": {
            "ET_DATA": [{"WA": "DOMAIN_DEV|P01"}],
        },
        "TMSCSYS": {
            "ET_DATA": [
                {"WA": "S4H|SAP-Dev|SAP|s4hanadev"},
                {"WA": "Q01|SAP-QA|SAP|q01host"},
                {"WA": "P01|SAP-Prd|SAP|p01host"},
            ],
        },
    })
    _install_fake_rfc(monkeypatch, conn)
    node = SAPNode(sid="S4H", ip="10.0.0.1")
    out = tms.read_tms_config(node)
    assert out["domain"] == "DOMAIN_DEV"
    assert out["controller"] == "P01"
    assert len(out["members"]) == 3
    sids = [m["sid"] for m in out["members"]]
    assert "S4H" in sids and "Q01" in sids and "P01" in sids
    p01 = next(m for m in out["members"] if m["sid"] == "P01")
    assert p01["host"] == "p01host"


def test_read_tms_config_handles_tmscsys_read_failure(monkeypatch):
    """If TMSCSYS read raises, error is surfaced but members[] stays empty."""
    conn = _FakeConn({
        "TMSMCONF": {"ET_DATA": [{"WA": "DOMAIN_X|Y01"}]},
        "TMSCSYS":  Exception("(258, 'insufficient privilege')"),
    })
    _install_fake_rfc(monkeypatch, conn)
    node = SAPNode(sid="S4H", ip="10.0.0.1")
    out = tms.read_tms_config(node)
    assert out["members"] == []
    assert "TMSCSYS read failed" in out["error"]


# ---------------------------------------------------------------------------
# integrate_tms_from_secstore
# ---------------------------------------------------------------------------

def _tmsadm_entry(ident_clean, pw="pw"):
    return {"ident_clean": ident_clean,
            "category": "rfc",
            "password": pw}


def test_integrate_pairs_tmsadm_with_tms_topology(monkeypatch):
    node = SAPNode(sid="S4H", ip="10.0.0.1")
    node.secstore_entries = [
        _tmsadm_entry("/RFC/TMSADM@Q01.DOMAIN_DEV", pw="pw-q01"),
        _tmsadm_entry("/RFC/TMSADM@P01.DOMAIN_DEV", pw="pw-p01"),
        _tmsadm_entry("/RFC/SOMEOTHER"),   # not TMSADM — skipped
    ]
    monkeypatch.setattr(tms, "read_tms_config", lambda *a, **kw: {
        "domain": "DOMAIN_DEV", "controller": "P01",
        "members": [
            {"sid": "S4H", "host": "s4hanadev"},
            {"sid": "Q01", "host": "q01host"},
            {"sid": "P01", "host": "p01host"},
        ],
        "error": ""})
    added = tms.integrate_tms_from_secstore(node, SAPMAPState(), None)
    assert len(added) == 2
    q = next(d for d in added if d.target_sid == "Q01")
    p = next(d for d in added if d.target_sid == "P01")
    assert q.target_host == "q01host" and q.password == "pw-q01"
    assert q.is_controller is False
    assert p.is_controller is True   # matches TMSMCONF controller
    assert p.password == "pw-p01"
    # Node itself got tagged with its domain
    assert node.tms_domain == "DOMAIN_DEV"


def test_integrate_no_tmsadm_entries_returns_empty(monkeypatch):
    node = SAPNode(sid="S4H", ip="10.0.0.1")
    node.secstore_entries = [{"ident_clean": "/RFC/OTHER",
                                 "category": "rfc", "password": "x"}]
    added = tms.integrate_tms_from_secstore(node, SAPMAPState(), None)
    assert added == []


def test_integrate_rerun_preserves_probe_state(monkeypatch):
    node = SAPNode(sid="S4H", ip="10.0.0.1")
    node.secstore_entries = [_tmsadm_entry("/RFC/TMSADM@Q01.DOMAIN_DEV",
                                              pw="new-pw")]
    # Prior state — already tested, logon_ok, has SAP_ALL
    node.tms_destinations = [TMSDestination(
        source_sid="S4H", target_sid="Q01", target_host="old",
        domain="DOMAIN_DEV", is_controller=False,
        password="old-pw", tested=True, logon_ok=True,
        tmsadm_has_sap_all=True, tmsadm_roles=["SAP_ALL"],
        tested_at="2026-08-13T09:00:00+00:00")]
    monkeypatch.setattr(tms, "read_tms_config", lambda *a, **kw: {
        "domain": "DOMAIN_DEV", "controller": "P01",
        "members": [{"sid": "Q01", "host": "q01host-new"}],
        "error": ""})
    added = tms.integrate_tms_from_secstore(node, SAPMAPState(), None)
    assert len(added) == 1
    d = node.tms_destinations[0]
    assert d.target_host == "q01host-new"
    assert d.password == "new-pw"
    # Probe verdict preserved
    assert d.tested and d.logon_ok
    assert d.tmsadm_has_sap_all
    assert d.tmsadm_roles == ["SAP_ALL"]


# ---------------------------------------------------------------------------
# probe_tms_destination + materialize
# ---------------------------------------------------------------------------

def test_probe_no_host_short_circuits():
    d = TMSDestination(source_sid="S4H", target_sid="Q01",
                          target_host="", domain="X", password="p")
    tms.probe_tms_destination(d)
    assert d.tested is True and d.logon_ok is False
    assert "no target host" in d.error


def test_probe_self_reference_resolves_host_from_source(monkeypatch):
    """TMSADM@S4H.DOMAIN_S4H on S4H itself — the discovery read may
    have returned no TMSCSYS row (empty domain, or TMSADM had no read
    rights).  The Test action must fall back to using the SOURCE's
    own host — it's literally the same server."""
    class _OK:
        def __enter__(self): return self
        def __exit__(self, *a): pass
    fake_mod = types.ModuleType("sapmap_rfc")
    fake_mod._get_connection = lambda node, creds: _OK()
    fake_mod.get_user_details = lambda *a, **kw: {"profiles": [],
                                                     "has_sap_all": False}
    monkeypatch.setitem(sys.modules, "sapmap_rfc", fake_mod)
    state = SAPMAPState()
    state.add_node(SAPNode(sid="S4H", ip="192.168.2.209",
                             hostname="s4hanadev"))
    d = TMSDestination(source_sid="S4H", target_sid="S4H",
                          target_host="", domain="DOMAIN_S4H",
                          password="p")
    tms.probe_tms_destination(d, state=state)
    assert d.target_host == "192.168.2.209", \
        "self-reference should resolve to source's own host"
    assert d.logon_ok is True


def test_probe_missing_host_resolves_from_existing_map_node(monkeypatch):
    """When target already exists on the map (from earlier scan) and
    dest.target_host is empty, Test should pick up the host from the
    existing SAPNode instead of failing."""
    class _OK:
        def __enter__(self): return self
        def __exit__(self, *a): pass
    fake_mod = types.ModuleType("sapmap_rfc")
    fake_mod._get_connection = lambda node, creds: _OK()
    fake_mod.get_user_details = lambda *a, **kw: {"profiles": [],
                                                     "has_sap_all": False}
    monkeypatch.setitem(sys.modules, "sapmap_rfc", fake_mod)
    state = SAPMAPState()
    state.add_node(SAPNode(sid="S4H", ip="10.0.0.1"))
    state.add_node(SAPNode(sid="Q01", ip="10.0.0.2", hostname="q01host"))
    d = TMSDestination(source_sid="S4H", target_sid="Q01",
                          target_host="", domain="X", password="p")
    tms.probe_tms_destination(d, state=state)
    assert d.target_host == "10.0.0.2"
    assert d.logon_ok is True


def test_probe_logon_failure_captured(monkeypatch):
    """When the RFC connect raises, dest.error carries the reason."""
    class _Boom:
        def __enter__(self): raise Exception("logon refused")
        def __exit__(self, *a): pass
    fake_mod = types.ModuleType("sapmap_rfc")
    fake_mod._get_connection = lambda node, creds: _Boom()
    fake_mod.get_user_details = lambda *a, **kw: {}
    monkeypatch.setitem(sys.modules, "sapmap_rfc", fake_mod)
    d = TMSDestination(source_sid="S4H", target_sid="Q01",
                          target_host="q01host", domain="X",
                          password="p")
    tms.probe_tms_destination(d)
    assert d.logon_ok is False
    assert "logon failed" in d.error


def test_probe_logon_success_records_roles_and_materialises(monkeypatch):
    class _OK:
        def __enter__(self): return self
        def __exit__(self, *a): pass
    fake_mod = types.ModuleType("sapmap_rfc")
    fake_mod._get_connection = lambda node, creds: _OK()
    fake_mod.get_user_details = lambda *a, **kw: {
        "profiles": ["SAP_ALL", "S_CTS_ALL"], "has_sap_all": True}
    monkeypatch.setitem(sys.modules, "sapmap_rfc", fake_mod)
    state = SAPMAPState()
    state.add_node(SAPNode(sid="S4H", ip="10.0.0.1"))
    d = TMSDestination(source_sid="S4H", target_sid="P01",
                          target_host="p01host", domain="DEV",
                          is_controller=True, password="p")
    tms.probe_tms_destination(d, state=state)
    assert d.logon_ok is True
    assert d.tmsadm_has_sap_all is True
    assert "SAP_ALL" in d.tmsadm_roles
    # Materialised as SAPNode
    p01 = state.get_node("P01")
    assert p01 is not None
    assert p01.discovered_via_tms is True
    assert p01.is_tms_controller is True
    assert p01.tms_parent_sid == "S4H"


def test_probe_logon_success_without_state_skips_materialise(monkeypatch):
    class _OK:
        def __enter__(self): return self
        def __exit__(self, *a): pass
    fake_mod = types.ModuleType("sapmap_rfc")
    fake_mod._get_connection = lambda node, creds: _OK()
    fake_mod.get_user_details = lambda *a, **kw: {"profiles": [],
                                                     "has_sap_all": False}
    monkeypatch.setitem(sys.modules, "sapmap_rfc", fake_mod)
    d = TMSDestination(source_sid="S4H", target_sid="Q01",
                          target_host="q01host", domain="X", password="p")
    tms.probe_tms_destination(d)  # no state
    assert d.logon_ok is True


# ---------------------------------------------------------------------------
# read_tms_buffer + read_recent_transports guard rails
# ---------------------------------------------------------------------------

def test_read_tms_buffer_refuses_unverified_logon():
    d = TMSDestination(source_sid="S4H", target_sid="Q01",
                          target_host="q01host", domain="X",
                          password="p", logon_ok=False)
    r = tms.read_tms_buffer(d)
    assert r["ok"] is False and "logon not verified" in r["error"]


def test_read_recent_transports_refuses_unverified_logon():
    d = TMSDestination(source_sid="S4H", target_sid="Q01",
                          target_host="q01host", domain="X",
                          password="p", logon_ok=False)
    r = tms.read_recent_transports(d)
    assert r["ok"] is False and "logon not verified" in r["error"]


def test_read_tms_buffer_prefers_target_over_tmsadm(monkeypatch):
    """RFC_READ_TABLE with TMSADM triggers RFC_COMMUNICATION_FAILURE
    ("no conversation found") because TMSADM is only authorised for
    RFC_PING + TMS-specific FMs.  read_tms_buffer must therefore
    prefer the target node's real credentials over TMSADM's password.
    """
    from sapmap_models import Credentials
    captured_creds = {}
    conn = _FakeConn({"TMSBUFFER": {"ET_DATA": []}})
    fake_mod = types.ModuleType("sapmap_rfc")
    def _get_conn(node, creds):
        captured_creds["username"] = creds.username
        return conn
    fake_mod._get_connection = _get_conn
    fake_errors = types.ModuleType("sapmap_errors")
    fake_errors.format_rfc_exception = lambda e: str(e)
    monkeypatch.setitem(sys.modules, "sapmap_rfc", fake_mod)
    monkeypatch.setitem(sys.modules, "sapmap_errors", fake_errors)

    state = SAPMAPState()
    q01 = SAPNode(sid="Q01", ip="q01host")
    # Verified cred on the target node — should be picked
    q01.credentials = [Credentials(
        username="SAPMAP00", password="pw",
        client="000", instance_nr="00", verified=True)]
    state.add_node(q01)
    d = TMSDestination(source_sid="S4H", target_sid="Q01",
                          target_host="q01host", domain="X",
                          password="tmsadm-pw", logon_ok=True)
    tms.read_tms_buffer(d, state=state)
    assert captured_creds["username"] == "SAPMAP00", \
        "should prefer target's verified cred over TMSADM"


def test_read_tms_buffer_falls_back_to_source_creds(monkeypatch):
    """When target has no verified cred but source does (self-
    reference case: TMSADM@S4H.DOMAIN_S4H on S4H itself), read_tms_
    buffer should use source's cred.  This is the primary operator
    flow — S4H's own SAPMAP00 has TMSCSYS + TMSBUFFER read rights."""
    from sapmap_models import Credentials
    captured = {}
    conn = _FakeConn({"TMSBUFFER": {"ET_DATA": []}})
    fake_mod = types.ModuleType("sapmap_rfc")
    def _get_conn(node, creds):
        captured["username"] = creds.username
        return conn
    fake_mod._get_connection = _get_conn
    fake_errors = types.ModuleType("sapmap_errors")
    fake_errors.format_rfc_exception = lambda e: str(e)
    monkeypatch.setitem(sys.modules, "sapmap_rfc", fake_mod)
    monkeypatch.setitem(sys.modules, "sapmap_errors", fake_errors)

    state = SAPMAPState()
    s4h = SAPNode(sid="S4H", ip="s4hanadev")
    s4h.credentials = [Credentials(
        username="joris", password="pw",
        client="100", instance_nr="00", verified=True)]
    state.add_node(s4h)
    d = TMSDestination(source_sid="S4H", target_sid="S4H",
                          target_host="s4hanadev", domain="DOMAIN_S4H",
                          password="tmsadm-pw", logon_ok=True)
    tms.read_tms_buffer(d, state=state)
    assert captured["username"] == "joris"


def test_read_tms_buffer_falls_back_to_tmsadm_when_no_other_cred(monkeypatch):
    """No verified cred anywhere → TMSADM is used (last resort;
    caller will likely see RFC_COMMUNICATION_FAILURE but at least a
    real error, not a silent misfire)."""
    captured = {}
    conn = _FakeConn({"TMSBUFFER": {"ET_DATA": []}})
    fake_mod = types.ModuleType("sapmap_rfc")
    def _get_conn(node, creds):
        captured["username"] = creds.username
        return conn
    fake_mod._get_connection = _get_conn
    fake_errors = types.ModuleType("sapmap_errors")
    fake_errors.format_rfc_exception = lambda e: str(e)
    monkeypatch.setitem(sys.modules, "sapmap_rfc", fake_mod)
    monkeypatch.setitem(sys.modules, "sapmap_errors", fake_errors)
    d = TMSDestination(source_sid="S4H", target_sid="Q01",
                          target_host="q01host", domain="X",
                          password="tmsadm-pw", logon_ok=True)
    tms.read_tms_buffer(d, state=None)
    assert captured["username"] == "TMSADM"


def test_read_tms_buffer_table_without_data_treated_as_zero_rows(monkeypatch):
    """SAP AD 718 / TABLE_WITHOUT_DATA on TMSBUFFER is a legitimate
    empty result on single-system landscapes (S4H alone, no other
    domain members to queue transports for).  Operator screenshot:
    ABAPApplicationError: RFC_ABAP_EXCEPTION: ID:AD Type:E Number:718
    Must be treated as success-with-zero-rows, NOT as a hard error."""
    class _ThrowsAD718:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def call(self, *a, **kw):
            raise Exception(
                "ABAPApplicationError: RFC_ABAP_EXCEPTION: ID:AD "
                "Type:E Number:718 TMSBUFFER "
                "[key=TABLE_WITHOUT_DATA, msg_class=AD, "
                "msg_number=718, msg_type=E, msg_v1=TMSBUFFER]")
    fake_mod = types.ModuleType("sapmap_rfc")
    fake_mod._get_connection = lambda node, creds: _ThrowsAD718()
    fake_errors = types.ModuleType("sapmap_errors")
    fake_errors.format_rfc_exception = lambda e: str(e)
    monkeypatch.setitem(sys.modules, "sapmap_rfc", fake_mod)
    monkeypatch.setitem(sys.modules, "sapmap_errors", fake_errors)

    d = TMSDestination(source_sid="S4H", target_sid="S4H",
                          target_host="s4hanadev",
                          domain="DOMAIN_S4H", password="p",
                          logon_ok=True)
    r = tms.read_tms_buffer(d)
    assert r["ok"] is True, (
        f"AD 718 must not surface as an error — {r.get('error')!r}")
    assert r["count"] == 0
    assert d.buffer_count == 0


def test_read_recent_transports_table_without_data_treated_as_zero_rows(monkeypatch):
    class _ThrowsAD718:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def call(self, *a, **kw):
            raise Exception(
                "ABAPApplicationError: RFC_ABAP_EXCEPTION: ID:AD "
                "Type:E Number:718 E070 [key=TABLE_WITHOUT_DATA]")
    fake_mod = types.ModuleType("sapmap_rfc")
    fake_mod._get_connection = lambda node, creds: _ThrowsAD718()
    fake_errors = types.ModuleType("sapmap_errors")
    fake_errors.format_rfc_exception = lambda e: str(e)
    monkeypatch.setitem(sys.modules, "sapmap_rfc", fake_mod)
    monkeypatch.setitem(sys.modules, "sapmap_errors", fake_errors)

    d = TMSDestination(source_sid="S4H", target_sid="S4H",
                          target_host="s4hanadev",
                          domain="DOMAIN_S4H", password="p",
                          logon_ok=True)
    r = tms.read_recent_transports(d)
    assert r["ok"] is True
    assert r["count"] == 0


def test_read_tms_buffer_happy_path(monkeypatch):
    conn = _FakeConn({
        "TMSBUFFER": {"ET_DATA": [
            {"WA": "DEVK900001|Q01|0|1|B|I"},
            {"WA": "DEVK900002|Q01|0|1|B|I"},
        ]},
    })
    fake_mod = types.ModuleType("sapmap_rfc")
    fake_mod._get_connection = lambda node, creds: conn
    fake_errors = types.ModuleType("sapmap_errors")
    fake_errors.format_rfc_exception = lambda e: str(e)
    monkeypatch.setitem(sys.modules, "sapmap_rfc", fake_mod)
    monkeypatch.setitem(sys.modules, "sapmap_errors", fake_errors)
    d = TMSDestination(source_sid="S4H", target_sid="Q01",
                          target_host="q01host", domain="X",
                          password="p", logon_ok=True)
    r = tms.read_tms_buffer(d)
    assert r["ok"] is True and r["count"] == 2
    assert d.buffer_count == 2
    assert r["rows"][0]["TRKORR"] == "DEVK900001"
