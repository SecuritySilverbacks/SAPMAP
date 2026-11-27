"""Issue #85 PR1 — the HTTP lock gate: the DURABLE-INVARIANT coverage test
plus a real WSGI-level enforcement test.

The coverage test is the regression guard the reporter explicitly asked for:
it enumerates every node-scoped (<sid>) route the app registers and fails if
any GET route is not explicitly classified (passive = reads cached data,
active = contacts the target).  A new active route that someone forgets to
classify therefore turns the suite red instead of silently leaking contact
against a locked host.

The WSGI test drives the Bottle app end-to-end: a locked node's active route
returns 423, a passive route is allowed, and unlock without a reason is
refused.
"""
from __future__ import annotations

import io
import json

import pytest

import modules  # noqa: F401  (registers subpackage paths)
from sapmap_models import SAPNode, SAPMAPState
from sapmap_gui import SAPMAPApi, create_app
import sapmap_lock as L


# ---------------------------------------------------------------------------
# Coverage invariant
# ---------------------------------------------------------------------------

def _sid_routes(app):
    """{rule: set(methods)} for every registered <sid> route."""
    out = {}
    for r in app.routes:
        if "<sid>" in r.rule:
            out.setdefault(r.rule, set()).add(r.method)
    return out


def _app():
    return create_app(SAPMAPApi())


def test_every_get_sid_route_is_explicitly_reviewed():
    """DURABLE INVARIANT: no GET <sid> route may be un-classified.  If this
    fails, add the printed route(s) to sapmap_lock.PASSIVE_GET_ROUTES (reads
    cached data — safe on a locked host) or ACTIVE_GET_ROUTES (contacts the
    target — must be denied)."""
    app = _app()
    unreviewed = []
    for rule, methods in _sid_routes(app).items():
        for m in methods:
            if not L.route_is_reviewed(rule, m):
                unreviewed.append(f"{m} {rule}")
    assert not unreviewed, (
        "un-classified node-scoped GET route(s) — classify in sapmap_lock:\n  "
        + "\n  ".join(sorted(unreviewed)))


def test_classification_sets_reference_only_real_routes():
    """No stale entries: every classified rule must be a registered <sid>
    route (guards against a typo or a renamed/removed route)."""
    app = _app()
    rules = set(_sid_routes(app))
    for name, s in (("PASSIVE_NONGET_ROUTES", L.PASSIVE_NONGET_ROUTES),
                    ("ACTIVE_GET_ROUTES", L.ACTIVE_GET_ROUTES),
                    ("PASSIVE_GET_ROUTES", L.PASSIVE_GET_ROUTES)):
        stale = [r for r in s if r not in rules]
        assert not stale, f"{name} references unregistered routes: {stale}"


def test_lock_unlock_routes_are_passive_and_registered():
    app = _app()
    rules = set(_sid_routes(app))
    assert "/api/node/<sid>/lock" in rules
    assert "/api/node/<sid>/unlock" in rules
    assert L.route_is_passive("/api/node/<sid>/lock", "POST")
    assert L.route_is_passive("/api/node/<sid>/unlock", "POST")


def test_active_routes_are_not_passive():
    # a representative mutation and a contacting GET must both be denied
    assert not L.route_is_passive("/api/node/<sid>/create_user", "POST")
    assert not L.route_is_passive("/api/node/<sid>/fs/drives", "GET")
    # an un-reviewed hypothetical GET fails closed
    assert not L.route_is_passive("/api/node/<sid>/some_new_probe", "GET")


# ---------------------------------------------------------------------------
# WSGI end-to-end enforcement
# ---------------------------------------------------------------------------

def _wsgi(app, method, path, body=None):
    raw = json.dumps(body).encode() if body is not None else b""
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "8080",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "CONTENT_TYPE": "application/json",
        "CONTENT_LENGTH": str(len(raw)),
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": "http",
        "wsgi.input": io.BytesIO(raw),
        "wsgi.errors": io.StringIO(),
        "wsgi.multithread": False,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
    }
    captured = {}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status

    chunks = app(environ, start_response)
    out = b"".join(
        c if isinstance(c, bytes) else str(c).encode() for c in chunks)
    code = int(captured.get("status", "200 OK").split()[0])
    return code, out.decode("utf-8", "replace")


@pytest.fixture
def locked_app():
    api = SAPMAPApi()
    app = create_app(api)
    node = SAPNode(sid="SB1", ip="10.0.0.1", hostname="app01.lab")
    api.state.add_node(node)
    L.lock_node(api.state, node, "third-party support host")
    return api, app


def test_gate_denies_active_route_on_locked_host(locked_app):
    _api, app = locked_app
    # GET that contacts the target → 423 Locked
    code, body = _wsgi(app, "GET", "/api/node/SB1/fs/drives")
    assert code == 423, body
    assert "host_locked" in body
    # a mutation → 423 too
    code, _ = _wsgi(app, "POST", "/api/node/SB1/create_user", {})
    assert code == 423


def test_gate_allows_passive_route_on_locked_host(locked_app):
    _api, app = locked_app
    # a cached-data GET is NOT gated (not 423) — stays viewable while locked
    code, _ = _wsgi(app, "GET", "/api/node/SB1/get_attacker_ip")
    assert code != 423


def test_impact_export_is_denied_but_view_is_allowed(locked_app):
    """Adversarial-review regression: /impact/export re-runs RFC on a cache
    miss (sapmap_impact.assess_one), so it is ACTIVE and denied on a locked
    host — while the view-only /impact read stays allowed."""
    _api, app = locked_app
    assert not L.route_is_passive("/api/node/<sid>/impact/export", "GET")
    assert not L.route_is_passive(
        "/api/node/<sid>/impact/export/<scenario_name>", "GET")
    assert L.route_is_passive("/api/node/<sid>/impact", "GET")
    # over HTTP against the locked node
    code, _ = _wsgi(app, "GET", "/api/node/SB1/impact/export/RFC_AUTH_BOMB")
    assert code == 423
    code, _ = _wsgi(app, "GET", "/api/node/SB1/impact")
    assert code != 423


def test_gate_allows_everything_on_unlocked_host():
    api = SAPMAPApi()
    app = create_app(api)
    api.state.add_node(SAPNode(sid="FREE", ip="10.9.9.9", hostname="free.lab"))
    code, _ = _wsgi(app, "GET", "/api/node/FREE/fs/drives")
    assert code != 423  # not locked → gate does not apply


def test_unlock_requires_reason_over_http(locked_app):
    _api, app = locked_app
    code, body = _wsgi(app, "POST", "/api/node/SB1/unlock", {"reason": ""})
    assert code == 400
    assert "reason_required" in body


def test_frontend_wires_lock_ui():
    """Source-pin: the ctx-menu lock/unlock items, their dispatch cases, the
    node padlock badge and the details-panel row are all present."""
    with open("modules/core/sapmap_html.py", encoding="utf-8") as f:
        src = f.read()
    assert 'data-action="lock_host"' in src
    assert 'data-action="unlock_host"' in src
    assert 'id="ctx-lock-host"' in src and 'id="ctx-unlock-host"' in src
    assert "case 'lock_host'" in src and "case 'unlock_host'" in src
    assert "node/${sid}/lock" in src and "node/${sid}/unlock" in src
    assert "n.locked" in src          # badge + details row read the flag
    assert "Locked (#85)" in src


def test_get_html_still_renders_with_lock_ui():
    """The HTML edits must not break the page string — get_html() returns a
    non-trivial document that contains the lock controls."""
    from sapmap_html import get_html
    html = get_html()
    assert isinstance(html, str) and len(html) > 100000
    assert 'data-action="lock_host"' in html
    assert "ctx-unlock-host" in html


def test_unlock_with_reason_lifts_the_lock(locked_app):
    api, app = locked_app
    code, body = _wsgi(app, "POST", "/api/node/SB1/unlock",
                       {"reason": "cleared by lead", "by": "op2"})
    assert code == 200, body
    node = api.state.nodes["SB1"]
    assert not L.is_locked(api.state, node)
    # ...and now the previously-denied route is reachable
    code, _ = _wsgi(app, "GET", "/api/node/SB1/fs/drives")
    assert code != 423
