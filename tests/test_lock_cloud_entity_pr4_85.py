"""Issue #85 PR4 — cloud/relay entity lock + visibility.

Extends the host-scoped lock guardrail to the cloud/relay tier:

* **SAP Cloud Connector (SCC)** — host-keyed like the Host Agent, but it has
  its OWN active ``/api/scc/<host>/*`` routes that the <sid> before_request
  gate can't see, so each contact route guards in-handler.  Lock/unlock routes
  mirror the Host-Agent pattern; the whole box (connector + co-located SAP
  nodes) locks together.
* **BTP subaccount** — identified ONLY by a UUID (no host the matcher can key
  on), so it gets a dedicated UUID-keyed lock store + routes, and the
  region-API destination pulls refuse a locked subaccount (resolving the UUID
  offline from the destination-token claim where it isn't a path param).
* **Force-show** — a locked ec2/s3 placeholder is no longer hidden by the
  bare-AWS filter (it must stay visible while quarantined).
* **Diff / report** — lock state surfaces as a delta section + KPI + badge.
"""
from __future__ import annotations

import base64
import io
import json

import pytest

import modules  # noqa: F401  (registers subpackage paths)
import sapmap_gui
from sapmap_models import (SAPMAPState, SAPNode, SCCNode, BTPSubaccountNode,
                           _is_bare_aws_default_node)
from sapmap_gui import SAPMAPApi, create_app
import sapmap_lock as L
import sapmap_diff
import sapmap_report


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
    out = b"".join(
        c if isinstance(c, bytes) else str(c).encode() for c in chunks)
    code = int(cap.get("status", "200 OK").split()[0])
    return code, out.decode("utf-8", "replace")


def _fake_dest_token(sub_uuid: str) -> str:
    """A minimal JWT whose payload carries ext_attr.subaccountid — enough for
    decode_token_claims + extract_subaccount_id_from_destination_token (both
    pure-offline)."""
    payload = {"ext_attr": {"subaccountid": sub_uuid}}
    body = base64.urlsafe_b64encode(
        json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"xx.{body}.yy"


@pytest.fixture
def api_app():
    api = SAPMAPApi()
    app = create_app(api)
    # SAP node + SCC on the SAME host (shared hostname) → one box.
    api.state.add_node(SAPNode(sid="SB1", ip="10.0.0.1", hostname="box01.lab"))
    api.state.scc_nodes["box01.lab"] = SCCNode(host="box01.lab", ip="10.0.0.1")
    # A standalone BTP subaccount (UUID-keyed, no host).
    api.state.btp_subaccounts["uuid-abc-123"] = BTPSubaccountNode(
        uuid="uuid-abc-123", region="eu10", subdomain="acme")
    api.btp_tokens = getattr(api, "btp_tokens", {}) or {}
    return api, app


# ===========================================================================
# BTP subaccount — UUID-keyed lock policy + serialization
# ===========================================================================

def test_btp_lock_roundtrip_and_reason():
    st = SAPMAPState()
    assert L.lock_btp_subaccount(st, "u1", "quarantine", by="op") is not None
    assert L.is_btp_subaccount_locked(st, "u1")
    assert not L.is_btp_subaccount_locked(st, "u2")
    # re-lock is idempotent (one record)
    L.lock_btp_subaccount(st, "u1", "again")
    assert sum(1 for r in st.locked_btp_subaccounts
               if r["uuid"] == "u1") == 1
    # unlock requires a recorded reason
    with pytest.raises(ValueError):
        L.unlock_btp_subaccount(st, "u1", "")
    assert L.unlock_btp_subaccount(st, "u1", "cleared", by="op") == 1
    assert not L.is_btp_subaccount_locked(st, "u1")
    assert any(r.get("host") == "BTP:u1" and r.get("reason") == "cleared"
               for r in st.unlock_log)


def test_btp_lock_survives_serialization_roundtrip():
    st = SAPMAPState()
    L.lock_btp_subaccount(st, "u1", "keep me")
    st2 = SAPMAPState.from_dict(st.to_dict())
    assert L.is_btp_subaccount_locked(st2, "u1")
    rec = L.locked_btp_record_for(st2, "u1")
    assert rec and rec.get("reason") == "keep me"


def test_btp_legacy_file_loads_unlocked():
    """A .sapmap predating PR4 has no locked_btp_subaccounts key → loads with
    an empty store (back-compat, no migration)."""
    d = SAPMAPState().to_dict()
    d.pop("locked_btp_subaccounts", None)
    st = SAPMAPState.from_dict(d)
    assert st.locked_btp_subaccounts == []


def test_empty_btp_lock_uuid_is_noop():
    st = SAPMAPState()
    assert L.lock_btp_subaccount(st, "", "x") is None
    assert st.locked_btp_subaccounts == []


# ===========================================================================
# SCC — resolves through the host-scoped machinery for free
# ===========================================================================

def test_scc_resolves_via_canonical_hosts():
    st = SAPMAPState()
    st.scc_nodes["scc.corp"] = SCCNode(host="scc.corp", ip="10.9.9.9")
    L.lock_host(st, "10.9.9.9", "by ip")
    assert L.is_locked(st, st.scc_nodes["scc.corp"])   # IP match via .ip
    st.locked_hosts.clear()
    L.lock_host(st, "scc.corp", "by host")
    assert L.is_locked(st, st.scc_nodes["scc.corp"])   # hostname match via .host


# ===========================================================================
# Force-show locked cloud placeholders
# ===========================================================================

def test_force_show_locked_bare_aws_placeholder():
    st = SAPMAPState()
    ec2 = SAPNode(sid="X", ip="", hostname="ec2.amazonaws.com",
                  system_type="ABAP")
    # Without state the function can't see the lock → bare (hidden).
    assert _is_bare_aws_default_node(ec2) is True
    # Locked → force-shown (not bare) when state is supplied.
    L.lock_host(st, "ec2.amazonaws.com", "quarantine")
    assert _is_bare_aws_default_node(ec2, st) is False
    # Unlocked placeholder on a passed state is still bare.
    st.locked_hosts.clear()
    assert _is_bare_aws_default_node(ec2, st) is True


def test_force_show_js_twin_source_pin():
    with open("modules/core/sapmap_html.py", encoding="utf-8") as f:
        src = f.read()
    # n.locked folded into the bare-AWS enrichment check → locked = shown.
    assert "|| n.locked);" in src


# ===========================================================================
# SCC lock / unlock routes + co-located coupling
# ===========================================================================

def test_scc_lock_route_locks_colocated_sap_node(api_app):
    api, app = api_app
    code, body = _wsgi(app, "POST", "/api/scc/box01.lab/lock",
                       {"reason": "third-party connector"})
    assert code == 200, body
    assert L.is_locked(api.state, api.state.nodes["SB1"])   # box-wide
    # the SAP node's gated route is now refused too
    code, _ = _wsgi(app, "GET", "/api/node/SB1/fs/drives")
    assert code == 423


def test_locking_sap_node_locks_colocated_scc(api_app):
    api, _app = api_app
    L.lock_node(api.state, api.state.nodes["SB1"], "shared box")
    assert L.is_locked(api.state, api.state.scc_nodes["box01.lab"])


def test_scc_lock_unknown_host_404(api_app):
    _api, app = api_app
    code, _ = _wsgi(app, "POST", "/api/scc/nope.lab/lock", {"reason": "x"})
    assert code == 404


def test_scc_unlock_requires_reason(api_app):
    _api, app = api_app
    _wsgi(app, "POST", "/api/scc/box01.lab/lock", {"reason": "x"})
    code, body = _wsgi(app, "POST", "/api/scc/box01.lab/unlock",
                       {"reason": ""})
    assert code == 400
    assert "reason_required" in body


def test_scc_unlock_with_reason_lifts_and_logs(api_app):
    api, app = api_app
    _wsgi(app, "POST", "/api/scc/box01.lab/lock", {"reason": "x"})
    code, body = _wsgi(app, "POST", "/api/scc/box01.lab/unlock",
                       {"reason": "cleared by lead"})
    assert code == 200, body
    assert not L.is_locked(api.state, api.state.scc_nodes["box01.lab"])
    assert any(r.get("reason") == "cleared by lead"
               for r in api.state.unlock_log)


def test_scc_locked_flag_in_state_dict(api_app):
    api, _app = api_app
    L.lock_host(api.state, "box01.lab", "quarantine")
    d = api.get_state_dict()
    scd = (d.get("scc_nodes") or {}).get("box01.lab")
    assert scd is not None
    assert scd["locked"] is True
    assert scd["lock_reason"] == "quarantine"


def test_scc_unlocked_by_default_in_state_dict(api_app):
    api, _app = api_app
    d = api.get_state_dict()
    scd = (d.get("scc_nodes") or {}).get("box01.lab")
    assert scd["locked"] is False


# ===========================================================================
# SCC active routes refuse a locked host (in-handler guard)
# ===========================================================================

SCC_ACTIVE_ROUTES = [
    "/api/scc/box01.lab/probe_creds",
    "/api/scc/box01.lab/pull_mappings",
    "/api/scc/box01.lab/extract_keystore",
    "/api/scc/box01.lab/probe_mappings",
    "/api/scc/box01.lab/download_user_hashes",
]


@pytest.mark.parametrize("route", SCC_ACTIVE_ROUTES)
def test_scc_active_route_blocked_when_locked(api_app, route):
    api, app = api_app
    L.lock_host(api.state, "box01.lab", "quarantine")
    code, body = _wsgi(app, "POST", route, {"username": "a", "password": "b"})
    assert code == 423, (route, body)
    assert "host_locked" in body


def test_scc_passive_route_allowed_when_locked(api_app):
    """analyse_pp only reads already-downloaded loot on disk — it makes no
    fresh contact, so it must stay reachable on a locked host (mirrors
    impact vs impact/export)."""
    api, app = api_app
    L.lock_host(api.state, "box01.lab", "quarantine")
    code, body = _wsgi(app, "POST", "/api/scc/box01.lab/analyse_pp", {})
    assert code != 423, body   # returns its own "run Extract Keystore first"


def test_scc_active_route_writes_console_line(api_app):
    api, app = api_app
    L.lock_host(api.state, "box01.lab", "quarantine")
    before = len(sapmap_gui._console_lines)
    _wsgi(app, "POST", "/api/scc/box01.lab/probe_creds", {})
    new = sapmap_gui._console_lines[before:]
    assert any("LOCKED" in ln["text"] and ln["cls"] == "cl-warn"
               for ln in new), new


def test_scc_lock_routes_not_sid_gated(api_app):
    _api, app = api_app
    rules = {r.rule for r in app.routes}
    assert "/api/scc/<host>/lock" in rules
    assert "/api/scc/<host>/unlock" in rules


# ===========================================================================
# BTP subaccount lock / unlock routes + region-API enforcement
# ===========================================================================

def test_btp_lock_unlock_routes(api_app):
    api, app = api_app
    code, body = _wsgi(app, "POST",
                       "/api/btp/subaccount/uuid-abc-123/lock",
                       {"reason": "cloud quarantine"})
    assert code == 200, body
    assert L.is_btp_subaccount_locked(api.state, "uuid-abc-123")
    # unlock needs a reason
    code, body = _wsgi(app, "POST",
                       "/api/btp/subaccount/uuid-abc-123/unlock",
                       {"reason": ""})
    assert code == 400 and "reason_required" in body
    code, _ = _wsgi(app, "POST",
                    "/api/btp/subaccount/uuid-abc-123/unlock",
                    {"reason": "done"})
    assert not L.is_btp_subaccount_locked(api.state, "uuid-abc-123")


def test_btp_lock_unknown_uuid_404(api_app):
    _api, app = api_app
    code, _ = _wsgi(app, "POST", "/api/btp/subaccount/nope/lock",
                    {"reason": "x"})
    assert code == 404


def test_btp_locked_flag_in_state_dict(api_app):
    api, _app = api_app
    L.lock_btp_subaccount(api.state, "uuid-abc-123", "quarantine")
    d = api.get_state_dict()
    bd = (d.get("btp_subaccounts") or {}).get("uuid-abc-123")
    assert bd is not None
    assert bd["locked"] is True
    assert bd["lock_reason"] == "quarantine"


def test_btp_pull_destinations_uuid_blocked_when_locked(api_app):
    api, app = api_app
    L.lock_btp_subaccount(api.state, "uuid-abc-123", "quarantine")
    code, body = _wsgi(app, "POST",
                       "/api/btp/pull_destinations/uuid-abc-123", {})
    assert code == 423, body
    assert "host_locked" in body


def test_btp_pull_for_token_blocked_when_locked(api_app):
    """The destination-service token carries the subaccount UUID offline in its
    ext_attr.subaccountid claim — a locked subaccount is refused BEFORE the
    region-API call."""
    api, app = api_app
    L.lock_btp_subaccount(api.state, "uuid-abc-123", "quarantine")
    api.btp_tokens["eu10"] = _fake_dest_token("uuid-abc-123")
    code, body = _wsgi(app, "POST",
                       "/api/btp/pull_destinations_for_token",
                       {"region": "eu10"})
    assert code == 423, body
    assert "host_locked" in body


def test_btp_lock_routes_not_sid_gated(api_app):
    _api, app = api_app
    rules = {r.rule for r in app.routes}
    assert "/api/btp/subaccount/<uuid>/lock" in rules
    assert "/api/btp/subaccount/<uuid>/unlock" in rules


# ===========================================================================
# Diff + report surfacing
# ===========================================================================

def test_diff_surfaces_host_and_btp_locks():
    base = SAPMAPState()
    cur = SAPMAPState()
    L.lock_host(cur, "scc.corp", "quarantine scc")
    L.lock_btp_subaccount(cur, "u-sub", "quarantine btp")
    d = sapmap_diff.compute_state_diff(base, cur)
    assert d["summary"]["hosts_locked_added"] == 1
    assert d["summary"]["btp_locked_added"] == 1
    assert any(h["host"] == "scc.corp" for h in d["locked_hosts"]["added"])
    assert any(b["uuid"] == "u-sub"
               for b in d["locked_btp_subaccounts"]["added"])
    md = sapmap_diff.build_diff_markdown(d)
    assert "Host-lock guardrail" in md and "scc.corp" in md
    html = sapmap_diff.build_diff_html(d)
    assert "Host-lock guardrail" in html


def test_report_has_quarantined_kpi_and_badge():
    st = SAPMAPState()
    st.add_node(SAPNode(sid="PRD", ip="10.0.0.2", hostname="prd.lab",
                        system_type="ABAP"))
    L.lock_host(st, "prd.lab", "quarantine")
    rep = sapmap_report.build_html_report(st, engagement_name="t")
    assert "Hosts quarantined" in rep
    # SVG lock badge glyph present on the landscape snapshot
    assert "🔒" in rep


# ===========================================================================
# Frontend wiring (source pins)
# ===========================================================================

def test_frontend_wires_scc_and_btp_lock():
    with open("modules/core/sapmap_html.py", encoding="utf-8") as f:
        src = f.read()
    # ctx-menu items
    assert 'id="scc-ctx-lock"' in src and 'id="scc-ctx-unlock"' in src
    assert 'id="btp-ctx-lock"' in src and 'id="btp-ctx-unlock"' in src
    # route wiring
    assert "scc/${encodeURIComponent(host)}/lock" in src
    assert "btp/subaccount/${encodeURIComponent(uuid)}/lock" in src
    # badges read the derived flags
    assert "sn.locked" in src and "bn.locked" in src


# ===========================================================================
# Adversarial-review regressions (PR4)
# ===========================================================================

def test_verify_pp_blocked_when_btp_subaccount_locked(api_app):
    """A locked BTP subaccount must not be contacted via the PP-impersonation
    verify route (which CREATES + reads + DELETES a destination on its region
    API).  That route is a <sid> route the gate only blocks when the ON-PREM
    node is locked, so the in-handler BTP-UUID guard is what catches it."""
    api, app = api_app
    api.state.nodes["SB1"].scc_links = ["box01.lab"]
    api.state.scc_nodes["box01.lab"].subaccount_uuids = ["uuid-abc-123"]
    L.lock_btp_subaccount(api.state, "uuid-abc-123", "cloud quarantine")
    assert not L.is_locked(api.state, api.state.nodes["SB1"])   # node still free
    code, body = _wsgi(app, "POST",
                       "/api/node/SB1/verify_pp_impersonation", {})
    assert code == 423, body
    assert "host_locked" in body


def test_verify_pp_blocked_when_scc_locked(api_app):
    """Same route, locked via the SCC instead.  The SCC lives on a DIFFERENT
    host from the node so the <sid> gate does NOT fire — the in-handler SCC
    guard must."""
    api, app = api_app
    api.state.scc_nodes["scc99.lab"] = SCCNode(host="scc99.lab", ip="10.9.9.9")
    api.state.scc_nodes["scc99.lab"].subaccount_uuids = ["uuid-abc-123"]
    api.state.nodes["SB1"].scc_links = ["scc99.lab"]
    L.lock_host(api.state, "scc99.lab", "connector quarantine")
    assert not L.is_locked(api.state, api.state.nodes["SB1"])
    code, body = _wsgi(app, "POST",
                       "/api/node/SB1/verify_pp_impersonation", {})
    assert code == 423, body
    assert "host_locked" in body


def test_extractor_coerces_nonstring_subaccountid():
    """A crafted destination-service token can carry a non-string
    ext_attr.subaccountid; the extractor must honour its -> str contract so the
    lock guards can't crash."""
    from sap_btp import extract_subaccount_id_from_destination_token as ex
    assert ex({"ext_attr": {"subaccountid": 12345}}) == "12345"
    assert ex({"ext_attr": {"subaccountid": ""}}) == ""
    assert ex({"ext_attr": {}}) == ""
    assert ex({}) == ""


def test_btp_lock_fns_tolerate_nonstring_uuid():
    st = SAPMAPState()
    # must not raise on non-string / falsy inputs
    assert L.is_btp_subaccount_locked(st, 12345) is False
    assert L.locked_btp_record_for(st, [1, 2]) is None
    assert L.lock_btp_subaccount(st, 0) is None        # 0 -> "" -> no-op
    assert L.lock_btp_subaccount(st, 999) is not None  # 999 -> "999"
    assert L.is_btp_subaccount_locked(st, "999")


def test_btp_pull_for_token_nonstring_claim_no_crash(api_app):
    """End-to-end: a token whose subaccountid claim is a number must not 500 the
    pull route.  We lock the coerced uuid so the guard short-circuits (423)
    without any network pull — proving it's handled, not crashed."""
    api, app = api_app
    L.lock_btp_subaccount(api.state, "12345", "q")
    payload = {"ext_attr": {"subaccountid": 12345}}
    body64 = base64.urlsafe_b64encode(
        json.dumps(payload).encode()).rstrip(b"=").decode()
    api.btp_tokens["eu10"] = f"xx.{body64}.yy"
    code, body = _wsgi(app, "POST", "/api/btp/pull_destinations_for_token",
                       {"region": "eu10"})
    assert code == 423, body
    assert "host_locked" in body
