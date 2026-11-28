"""Issue #85 PR1 follow-ups (operator feedback):

1. **Host Agent (#91) boxes are lockable and show their lock status.**  A
   Host Agent lives OUTSIDE ``state.nodes`` (keyed by host), so PR1's SAP-node
   lock did not cover it.  It now locks off the SAME host-scoped record as a
   co-located SAP node, so one lock covers the whole box both ways, and the
   state dict carries a derived ``locked`` flag for the frontend badge.

2. **A blocked active route is no longer silent.**  The before_request gate
   drops a ``cl-warn`` line in the operator console when it refuses a locked
   host (the 423 alone was easy to miss), and the frontend ``api()`` helper
   raises a toast on any 423 ``host_locked``.
"""
from __future__ import annotations

import io
import json

import pytest

import modules  # noqa: F401  (registers subpackage paths)
import sapmap_gui
from sapmap_models import SAPNode, HostControlNode
from sapmap_gui import SAPMAPApi, create_app
import sapmap_lock as L


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


@pytest.fixture
def api_app():
    api = SAPMAPApi()
    app = create_app(api)
    # A SAP node and a Host Agent on the SAME host (shared hostname).
    api.state.add_node(SAPNode(sid="SB1", ip="10.0.0.1", hostname="box01.lab"))
    api.state.host_control_nodes["box01.lab"] = HostControlNode(
        host="box01.lab", ip="10.0.0.1")
    return api, app


# --- host-scoped coupling (the whole point of host-, not SID-, scoping) ----

def test_locking_sap_node_locks_colocated_host_agent(api_app):
    api, _app = api_app
    node = api.state.nodes["SB1"]
    hc = api.state.host_control_nodes["box01.lab"]
    assert not L.is_locked(api.state, hc)
    L.lock_node(api.state, node, "shared box")
    assert L.is_locked(api.state, hc)   # host-scoped → agent covered too


def test_locking_host_agent_locks_colocated_sap_node(api_app):
    api, app = api_app
    code, body = _wsgi(app, "POST", "/api/hostcontrol/box01.lab/lock",
                       {"reason": "third-party host"})
    assert code == 200, body
    node = api.state.nodes["SB1"]
    assert L.is_locked(api.state, node)   # agent lock covers the SAP node
    # ...and the SAP node's active route is now refused through the gate.
    code, _ = _wsgi(app, "GET", "/api/node/SB1/fs/drives")
    assert code == 423


# --- Host Agent lock status surfaces in the state dict (the badge source) --

def test_host_agent_locked_flag_in_state_dict(api_app):
    api, _app = api_app
    L.lock_host(api.state, "box01.lab", "quarantine")
    d = api.get_state_dict()
    hcd = (d.get("host_control_nodes") or {}).get("box01.lab")
    assert hcd is not None
    assert hcd["locked"] is True
    assert hcd["lock_reason"] == "quarantine"


def test_host_agent_unlocked_by_default_in_state_dict(api_app):
    api, _app = api_app
    d = api.get_state_dict()
    hcd = (d.get("host_control_nodes") or {}).get("box01.lab")
    assert hcd["locked"] is False


def test_host_agent_ip_only_lock_still_flags_the_box(api_app):
    """A lock recorded against the box's IP must still mark the Host Agent
    (canonical_hosts reads the agent's IP as well as its host)."""
    api, _app = api_app
    L.lock_host(api.state, "10.0.0.1", "locked by IP")
    d = api.get_state_dict()
    hcd = (d.get("host_control_nodes") or {}).get("box01.lab")
    assert hcd["locked"] is True


# --- Host Agent lock / unlock routes --------------------------------------

def test_host_agent_unlock_requires_reason(api_app):
    _api, app = api_app
    _wsgi(app, "POST", "/api/hostcontrol/box01.lab/lock", {"reason": "x"})
    code, body = _wsgi(app, "POST", "/api/hostcontrol/box01.lab/unlock",
                       {"reason": ""})
    assert code == 400
    assert "reason_required" in body


def test_host_agent_unlock_with_reason_lifts_lock_and_logs(api_app):
    api, app = api_app
    _wsgi(app, "POST", "/api/hostcontrol/box01.lab/lock", {"reason": "x"})
    code, body = _wsgi(app, "POST", "/api/hostcontrol/box01.lab/unlock",
                       {"reason": "cleared by lead"})
    assert code == 200, body
    hc = api.state.host_control_nodes["box01.lab"]
    assert not L.is_locked(api.state, hc)
    assert any(r.get("reason") == "cleared by lead"
               for r in api.state.unlock_log)


def test_host_agent_lock_unknown_host_404(api_app):
    _api, app = api_app
    code, _ = _wsgi(app, "POST", "/api/hostcontrol/nope.lab/lock",
                    {"reason": "x"})
    assert code == 404


def test_unlock_via_agent_lifts_colocated_node_hostname_record(api_app):
    """Adversarial-review regression: a discovery-built Host Agent is keyed by
    a single IP (host == ip, scanner builds it that way) while a co-located
    SAP node ALSO carries its resolved hostname.  Lock the box via the SAP
    node (two records: ip + hostname), then unlock via the Agent — BOTH
    records must be lifted, or the node stays at 423 while the agent badge and
    toast say re-armed."""
    api, app = api_app
    # Rebuild the agent the way discovery does: host == ip, IP only.
    api.state.host_control_nodes.pop("box01.lab", None)
    api.state.host_control_nodes["10.0.0.1"] = HostControlNode(
        host="10.0.0.1", ip="10.0.0.1")
    node = api.state.nodes["SB1"]                     # ip 10.0.0.1 + box01.lab
    L.lock_node(api.state, node, "locked via node")   # -> {10.0.0.1, box01.lab}
    assert L.is_locked(api.state, node)
    code, body = _wsgi(app, "POST", "/api/hostcontrol/10.0.0.1/unlock",
                       {"reason": "cleared"})
    assert code == 200, body
    assert not L.is_locked(api.state, node), api.state.locked_hosts
    code, _ = _wsgi(app, "GET", "/api/node/SB1/fs/drives")
    assert code != 423


def test_host_agent_lock_routes_are_not_sid_gated(api_app):
    """The /api/hostcontrol/<host>/lock routes must NOT be <sid> routes — the
    before_request gate only enumerates <sid> routes, so lock management stays
    reachable even once the host is locked."""
    _api, app = api_app
    rules = {r.rule for r in app.routes}
    assert "/api/hostcontrol/<host>/lock" in rules
    assert "/api/hostcontrol/<host>/unlock" in rules
    assert "<sid>" not in "/api/hostcontrol/<host>/lock"


# --- a blocked action is no longer silent ---------------------------------

def test_blocked_active_route_writes_console_line(api_app):
    api, app = api_app
    L.lock_node(api.state, api.state.nodes["SB1"], "quarantine")
    before = len(sapmap_gui._console_lines)
    code, _ = _wsgi(app, "GET", "/api/node/SB1/fs/drives")
    assert code == 423
    new = sapmap_gui._console_lines[before:]
    assert any("LOCKED" in ln["text"] and "Blocked" in ln["text"]
               for ln in new), new
    assert any(ln["cls"] == "cl-warn" for ln in new)


def test_console_line_escapes_crafted_hostname(api_app):
    """Adversarial-review XSS regression: a target self-reports an HTML/JS
    hostname during discovery; the console buffer is rendered via innerHTML,
    so the gate's console line MUST escape the host (and method/path).  A
    hostname-only node makes the crafted host the lock record's host."""
    api, app = api_app
    api.state.add_node(SAPNode(sid="EVIL", ip="",
                               hostname="x<img src=y onerror=alert(1)>"))
    L.lock_node(api.state, api.state.nodes["EVIL"], "crafted")
    before = len(sapmap_gui._console_lines)
    code, _ = _wsgi(app, "GET", "/api/node/EVIL/fs/drives")
    assert code == 423
    joined = " ".join(ln["text"] for ln in sapmap_gui._console_lines[before:])
    assert "<img" not in joined and "<script" not in joined, joined
    assert "&lt;img" in joined   # escaped form is what reaches the DOM


# --- frontend wiring (source pins) ----------------------------------------

def test_frontend_wires_host_agent_lock_and_423_toast():
    with open("modules/core/sapmap_html.py", encoding="utf-8") as f:
        src = f.read()
    # 423 handled centrally in api() → uniform toast, no per-call wiring
    assert "res.status === 423" in src
    assert "host_locked" in src
    # host-agent ctx-menu lock/unlock items + dispatch
    assert 'id="hc-ctx-lock"' in src and 'id="hc-ctx-unlock"' in src
    assert "hostcontrol/${encodeURIComponent(host)}/lock" in src
    assert "hostcontrol/${encodeURIComponent(host)}/unlock" in src
    # badge + details row read the derived hn.locked flag
    assert "hn.locked" in src
    assert '>Locked</span>' in src   # Host Agent details-panel lock row
