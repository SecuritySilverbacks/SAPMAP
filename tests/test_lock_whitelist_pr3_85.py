"""Issue #85 PR3 — auto-lock whitelist + auto-relock + pre-scan filter.

A discovered host matching the editable ``lock_whitelist`` is auto-locked on
discovery (excluded from contact, still visible) and dropped before scanning.
These tests cover the model (seed + serialization), the policy primitives
(``whitelist_match`` / ``apply_auto_lock``, host-scoped / idempotent), the
node-creation funnel (``add_node`` auto-lock + auto-relock), the scanner
pre-scan filter, and the whitelist CRUD API.
"""
from __future__ import annotations

import inspect
import io
import json

import pytest

import modules  # noqa: F401  (registers subpackage paths)
import sapmap_lock as L
from sapmap_models import (SAPMAPState, SAPNode, RFCConnection,
                           DEFAULT_LOCK_WHITELIST)


# ---------------------------------------------------------------------------
# model: seed + serialization
# ---------------------------------------------------------------------------

def test_fresh_state_is_seeded():
    st = SAPMAPState()
    assert st.lock_whitelist == DEFAULT_LOCK_WHITELIST
    # a distinct list per instance (default_factory copy, not shared)
    st.lock_whitelist.append("x.example.com")
    assert "x.example.com" not in SAPMAPState().lock_whitelist


def test_serialization_honours_stored_and_seeds_legacy():
    st = SAPMAPState()
    d = st.to_dict()
    assert "lock_whitelist" in d
    # stored list honoured verbatim
    assert SAPMAPState.from_dict(d).lock_whitelist == st.lock_whitelist
    # a stored EMPTY list stays empty (operator cleared it)
    cleared = dict(d, lock_whitelist=[])
    assert SAPMAPState.from_dict(cleared).lock_whitelist == []
    # a legacy file WITHOUT the key is seeded (new protection)
    legacy = {k: v for k, v in d.items() if k != "lock_whitelist"}
    assert SAPMAPState.from_dict(legacy).lock_whitelist == DEFAULT_LOCK_WHITELIST


# ---------------------------------------------------------------------------
# policy: whitelist_match + apply_auto_lock
# ---------------------------------------------------------------------------

def test_whitelist_match_semantics():
    st = SAPMAPState()
    st.lock_whitelist = ["apps.support.sap.com", "10.0.0.0/24"]
    assert L.whitelist_match(st, "apps.support.sap.com") == "apps.support.sap.com"
    # dot-anchored subdomain matches, sibling domain does NOT
    assert L.whitelist_match(st, "x.apps.support.sap.com") == "apps.support.sap.com"
    assert L.whitelist_match(st, "evil-apps.support.sap.com") is None
    assert L.whitelist_match(st, "apps.support.sap.com.evil.com") is None
    # CIDR membership
    assert L.whitelist_match(st, "10.0.0.7") == "10.0.0.0/24"
    assert L.whitelist_match(st, "10.0.1.7") is None
    assert L.whitelist_match(st, "") is None


def test_apply_auto_lock_locks_whole_box():
    st = SAPMAPState()
    st.lock_whitelist = ["ec2.amazonaws.com"]
    n = SAPNode(sid="EC2", ip="10.9.9.9", hostname="ec2.amazonaws.com")
    recs = L.apply_auto_lock(st, n)
    # whole box: both the matching hostname AND the reachable IP are locked
    assert L.is_host_locked(st, "ec2.amazonaws.com")
    assert L.is_host_locked(st, "10.9.9.9")
    assert all(r["auto"] and r["whitelist_pattern"] == "ec2.amazonaws.com"
               for r in recs)


def test_apply_auto_lock_no_match_is_noop():
    st = SAPMAPState()
    st.lock_whitelist = ["ec2.amazonaws.com"]
    n = SAPNode(sid="PRD", ip="10.0.0.2", hostname="prd.corp.local")
    assert L.apply_auto_lock(st, n) == []
    assert not L.is_locked(st, n)


def test_apply_auto_lock_preserves_a_manual_lock_reason():
    st = SAPMAPState()
    st.lock_whitelist = ["ec2.amazonaws.com"]
    n = SAPNode(sid="EC2", ip="10.9.9.9", hostname="ec2.amazonaws.com")
    L.lock_node(st, n, "manual quarantine")          # manual, all hosts
    L.apply_auto_lock(st, n)                          # must not clobber
    rec = L.locked_record_for(st, n)
    assert rec["reason"] == "manual quarantine" and rec["auto"] is False


# ---------------------------------------------------------------------------
# funnel: add_node auto-lock + auto-relock
# ---------------------------------------------------------------------------

def test_add_node_auto_locks_whitelisted_and_relocks():
    st = SAPMAPState()
    n = SAPNode(sid="EC2", ip="10.9.9.9", hostname="ec2.amazonaws.com")
    st.add_node(n)
    assert L.is_locked(st, n)                         # auto-locked on discovery
    # manual unlock then rediscovery → auto-relock (the ratified behaviour)
    L.unlock_node(st, n, "operator override")
    assert not L.is_locked(st, n)
    st.add_node(n)
    assert L.is_locked(st, n)
    # removing the whitelist entry makes a subsequent unlock permanent
    st.lock_whitelist = [p for p in st.lock_whitelist if p != "ec2.amazonaws.com"]
    L.unlock_node(st, n, "permanent override")
    st.add_node(n)
    assert not L.is_locked(st, n)


def test_add_node_does_not_lock_normal_host():
    st = SAPMAPState()
    n = SAPNode(sid="PRD", ip="10.0.0.2", hostname="prd.corp.local")
    st.add_node(n)
    assert not L.is_locked(st, n)
    assert "PRD" in st.nodes                          # still visible


def test_materialise_type_g_target_auto_locks_cloud_placeholder():
    st = SAPMAPState()
    conn = RFCConnection(source_sid="SRC", source_host="src.lab",
                         destination_name="G1", conn_type="http",
                         http_url="https://ec2.amazonaws.com:443/sap")
    st.materialise_type_g_target(conn, allow_placeholder=True)
    assert conn.target_sid, "a placeholder should have been materialised"
    placeholder = st.get_node(conn.target_sid)
    assert placeholder is not None
    assert L.is_locked(st, placeholder), "cloud Type-G placeholder must auto-lock"


# ---------------------------------------------------------------------------
# funnel-bypass wiring (source pins — behaviour is _auto_lock, pinned above)
# ---------------------------------------------------------------------------

def test_bypass_sites_call_auto_lock():
    import sapmap_models
    import sapmap_gui
    import sapmap_autopwn
    rename_src = inspect.getsource(sapmap_models.SAPMAPState.rename_node_sid)
    assert "self._auto_lock(node)" in rename_src
    gtg_src = inspect.getsource(sapmap_models.SAPMAPState.materialise_type_g_target)
    assert "self._auto_lock(placeholder)" in gtg_src
    gui_src = inspect.getsource(sapmap_gui.create_app)
    assert "api.state._auto_lock(promoted)" in gui_src
    autopwn_src = inspect.getsource(sapmap_autopwn)
    assert "state._auto_lock(promoted)" in autopwn_src
    import sap_btp
    assert "state._auto_lock(placeholder)" in inspect.getsource(sap_btp)


# ---------------------------------------------------------------------------
# scanner pre-scan filter
# ---------------------------------------------------------------------------

def test_filter_scan_targets_drops_whitelist_and_locked():
    import sapmap_scanner as S
    st = SAPMAPState()
    st.lock_whitelist = ["apps.support.sap.com", "10.0.0.0/24"]
    # a locked host (bare IP) outside the whitelist CIDR
    locked = SAPNode(sid="LCK", ip="192.0.2.5", hostname="lck.lab")
    st.add_node(locked)
    L.lock_node(st, locked, "quarantine")
    allowed, skipped = S.filter_scan_targets(
        "apps.support.sap.com,10.0.0.9,192.0.2.5,198.51.100.7", st)
    assert "198.51.100.7" in allowed            # free host survives
    assert "10.0.0.9" not in allowed            # inside whitelist CIDR
    assert "192.0.2.5" not in allowed           # locked host
    reasons = {h: r for h, r in skipped}
    assert reasons.get("apps.support.sap.com") == "whitelist"   # pre-resolution
    assert reasons.get("10.0.0.9") == "whitelist"
    assert reasons.get("192.0.2.5") == "locked"


def test_filter_scan_targets_none_state_is_passthrough():
    import sapmap_scanner as S
    allowed, skipped = S.filter_scan_targets("10.0.0.1,10.0.0.2", None)
    assert allowed == ["10.0.0.1", "10.0.0.2"] and skipped == []


def test_filter_hostname_stage_still_fires_without_ip_rules():
    """The IP-stage short-circuit (no IP/CIDR rule → skip per-IP checks) must
    NOT disable the stage-1 literal-hostname filter: a whitelisted hostname is
    still dropped, while a bare IP (no IP rule) passes untouched."""
    import sapmap_scanner as S
    st = SAPMAPState()                       # default: 5 hostname seeds only
    assert L.has_ip_scoped_rules(st) is False
    allowed, skipped = S.filter_scan_targets(
        "apps.support.sap.com,198.51.100.7", st)
    assert "198.51.100.7" in allowed
    assert any(h == "apps.support.sap.com" and r == "whitelist"
               for h, r in skipped)


# ---------------------------------------------------------------------------
# whitelist CRUD API
# ---------------------------------------------------------------------------

def _wsgi(app, method, path, body=None):
    raw = json.dumps(body).encode() if body is not None else b""
    environ = {
        "REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": "",
        "SERVER_NAME": "localhost", "SERVER_PORT": "8080",
        "SERVER_PROTOCOL": "HTTP/1.1", "CONTENT_TYPE": "application/json",
        "CONTENT_LENGTH": str(len(raw)),
        "wsgi.version": (1, 0), "wsgi.url_scheme": "http",
        "wsgi.input": io.BytesIO(raw), "wsgi.errors": io.StringIO(),
        "wsgi.multithread": False, "wsgi.multiprocess": False,
        "wsgi.run_once": False,
    }
    cap = {}

    def start_response(status, headers, exc_info=None):
        cap["status"] = status

    chunks = app(environ, start_response)
    out = b"".join(c if isinstance(c, bytes) else str(c).encode()
                   for c in chunks)
    return int(cap.get("status", "200 OK").split()[0]), json.loads(out.decode())


@pytest.fixture
def api_app():
    import sapmap_gui
    api = sapmap_gui.SAPMAPApi()
    app = sapmap_gui.create_app(api)
    return sapmap_gui, api, app


def test_router_scan_filters_locked_targets(api_app, monkeypatch):
    """Adversarial-review regression (important): the SAProuter internal scan
    is a first-contact path and must apply the same pre-scan lock/whitelist
    filter — the HTTP gate only checks the ROUTER node's lock, not the scan
    targets behind it."""
    sapmap_gui, api, app = api_app
    import sapmap_scanner
    # Router node (UNLOCKED, so the gate lets the route through).
    api.state.add_node(SAPNode(sid="SR1", ip="10.0.0.1", hostname="router.lab",
                               system_type="SAPROUTER"))
    # A locked on-prem target behind the router.
    tgt = SAPNode(sid="TGT", ip="192.0.2.50", hostname="tgt.lab")
    api.state.add_node(tgt)
    L.lock_node(api.state, tgt, "quarantine")

    captured = {}
    monkeypatch.setattr(sapmap_scanner, "scan_network_via_saprouter",
                        lambda **kw: captured.setdefault("targets", kw.get("targets")) or [])
    monkeypatch.setattr(sapmap_gui, "_bg", lambda key, label, fn: fn())

    code, _ = _wsgi(app, "POST", "/api/node/SR1/router_scan",
                    {"targets": "192.0.2.50,198.51.100.9", "auto_targets": False})
    assert code == 200
    assert captured.get("targets") == ["198.51.100.9"]   # locked host dropped


def test_api_get_seed(api_app):
    _gui, _api, app = api_app
    code, d = _wsgi(app, "GET", "/api/lock_whitelist")
    assert code == 200 and "ec2.amazonaws.com" in d["lock_whitelist"]


def test_api_add_retroactively_locks(api_app):
    _gui, api, app = api_app
    api.state.add_node(SAPNode(sid="WEB", ip="10.0.0.9",
                               hostname="x.example.com"))
    assert not L.is_locked(api.state, api.state.nodes["WEB"])
    code, d = _wsgi(app, "POST", "/api/lock_whitelist",
                    {"pattern": "x.example.com"})
    assert code == 200 and d["added"] is True
    assert d["auto_locked_hosts"]
    assert L.is_locked(api.state, api.state.nodes["WEB"])
    # duplicate add is a no-op
    code, d = _wsgi(app, "POST", "/api/lock_whitelist",
                    {"pattern": "x.example.com"})
    assert code == 200 and d["added"] is False
    # empty → 400
    code, _ = _wsgi(app, "POST", "/api/lock_whitelist", {"pattern": "  "})
    assert code == 400


def test_api_delete_removes_pattern_but_does_not_unlock(api_app):
    _gui, api, app = api_app
    api.state.add_node(SAPNode(sid="WEB", ip="10.0.0.9",
                               hostname="x.example.com"))
    _wsgi(app, "POST", "/api/lock_whitelist", {"pattern": "x.example.com"})
    assert L.is_locked(api.state, api.state.nodes["WEB"])
    code, d = _wsgi(app, "DELETE", "/api/lock_whitelist",
                    {"pattern": "x.example.com"})
    assert code == 200 and d["removed"] == 1
    assert "x.example.com" not in d["lock_whitelist"]
    # removing a pattern must NOT silently unlock (unlock needs a reason)
    assert L.is_locked(api.state, api.state.nodes["WEB"])
