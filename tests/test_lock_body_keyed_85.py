"""Issue #85 — body-/connection-keyed + create-then-probe lock enforcement.

The PR1 HTTP before_request gate keys on the PATH (``/api/node/<sid>/…``).
Two families of contact never reach it with a usable target:

* the **BTP family** — ``/api/btp/test_destination`` and
  ``/api/btp/create_user_on_target`` carry the target in the request BODY
  (``source_sid='BTP:<uuid8>'`` + ``destination_name`` / ``target_sid``), and
  ``_btp_test_conn_body`` is *also* driven by the cert-auth-mint auto-sweep,
  an internal caller that bypasses the HTTP layer entirely;
* the **create-then-probe** paths — ``/api/node/add`` and the landscape-XML
  post-import sweep ADD a node and then probe it (RFC_SYSTEM_INFO) inside the
  same admitted request, and a BTP destination pull auto-scans a freshly
  linked on-prem placeholder via ``_kick_standard_scan``.

So enforcement lives at the in-process contact chokepoints, each emitting a
visible operator console line.  These tests lock a host and assert the
per-contact function is never invoked against it (while an unlocked sibling
still is), and that the shared feedback helper HTML-escapes its inputs.
"""
from __future__ import annotations

import io
import json

import pytest

import modules  # noqa: F401  (registers subpackage paths)
import sapmap_lock as L
from sapmap_models import SAPNode, SAPMAPState, RFCConnection, InstanceInfo


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
    return int(cap.get("status", "200 OK").split()[0]), out.decode()


# ---------------------------------------------------------------------------
# BTP test-connection  (_btp_test_conn_body — route + cert-auth auto-sweep)
# ---------------------------------------------------------------------------

def test_btp_test_skips_locked_rfc_target(monkeypatch):
    import sapmap_gui
    import sapmap_rfc
    import sapmap_exploit
    api = sapmap_gui.SAPMAPApi()
    app = sapmap_gui.create_app(api)          # noqa: F841 (wires api._btp_*)
    tgt = SAPNode(sid="TGT", ip="10.0.0.2", hostname="tgt.lab",
                  system_type="ABAP")
    api.state.add_node(tgt)
    L.lock_node(api.state, tgt, "quarantine")

    def _boom(*a, **k):
        raise AssertionError("contacted a LOCKED RFC target")
    monkeypatch.setattr(sapmap_rfc, "test_connection", _boom)
    monkeypatch.setattr(sapmap_exploit, "_gateway_port_reachable", _boom)

    conn = RFCConnection(source_sid="BTP:deadbeef", source_host="",
                         destination_name="D1",
                         target_sid="TGT", conn_type="rfc",
                         rfc_user="u", secstore_password="p")
    api.state.connections.append(conn)
    api._btp_test_conn_body(conn, "BTP:deadbeef", "D1")
    assert conn.tested is True
    assert "LOCKED" in conn.check_error


def test_btp_test_skips_locked_http_url_host(monkeypatch):
    import sapmap_gui
    api = sapmap_gui.SAPMAPApi()
    app = sapmap_gui.create_app(api)          # noqa: F841
    # Lock a bare host via a node whose canonical hosts include web.lab.
    web = SAPNode(sid="WEB", ip="10.0.0.3", hostname="web.lab")
    api.state.add_node(web)
    L.lock_node(api.state, web, "quarantine")

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("contacted a LOCKED URL host")))

    conn = RFCConnection(source_sid="BTP:feedface", source_host="",
                         destination_name="D2",
                         target_sid="", conn_type="http",
                         rfc_user="u", secstore_password="p",
                         http_url="https://web.lab:44300/sap/bc/gui/sap/its/")
    api.state.connections.append(conn)
    api._btp_test_conn_body(conn, "BTP:feedface", "D2")
    assert conn.tested is True
    assert "LOCKED" in conn.check_error


def test_btp_test_tolerates_malformed_http_url(monkeypatch):
    """Adversarial-review regression: a malformed destination URL (e.g. a bad
    IPv6 literal) must not make the connection-keyed guard raise — that would
    kill the _bg thread, leave conn.tested False and hang the modal.  The
    guard treats an unparseable URL as 'no host' and falls through."""
    import sapmap_gui
    api = sapmap_gui.SAPMAPApi()
    app = sapmap_gui.create_app(api)          # noqa: F841
    # Unmapped target (target None) + malformed IPv6 URL → the elif branch
    # runs urlparse on the crafted value.  conn_type rfc + target None then
    # short-circuits cleanly ("target not on the map") with no network.
    conn = RFCConnection(source_sid="BTP:beef0000", source_host="",
                         destination_name="DM", target_sid="",
                         conn_type="rfc", rfc_user="u", secstore_password="p",
                         http_url="http://[::1")   # malformed IPv6 literal
    api.state.connections.append(conn)
    api._btp_test_conn_body(conn, "BTP:beef0000", "DM")   # must not raise
    assert conn.tested is True
    assert "LOCKED" not in conn.check_error    # fell through, not a crash-mask


def test_btp_test_allows_unlocked_target(monkeypatch):
    """The guard must not OVER-block: an unlocked target is still contacted."""
    import sapmap_gui
    import sapmap_rfc
    import sapmap_exploit
    api = sapmap_gui.SAPMAPApi()
    app = sapmap_gui.create_app(api)          # noqa: F841
    tgt = SAPNode(sid="FRE", ip="10.0.0.4", hostname="fre.lab",
                  system_type="ABAP")
    api.state.add_node(tgt)                    # NOT locked

    hit = []
    monkeypatch.setattr(sapmap_exploit, "_gateway_port_reachable",
                        lambda *a, **k: True)
    monkeypatch.setattr(sapmap_rfc, "test_connection",
                        lambda *a, **k: hit.append(True) or True)

    conn = RFCConnection(source_sid="BTP:11112222", source_host="",
                         destination_name="D3",
                         target_sid="FRE", conn_type="rfc",
                         rfc_user="u", secstore_password="p")
    api.state.connections.append(conn)
    api._btp_test_conn_body(conn, "BTP:11112222", "D3")
    assert hit, "unlocked target should have been contacted"
    assert conn.logon_successful is True


# ---------------------------------------------------------------------------
# BTP create-user-on-target  (body-keyed target_sid → visible 423)
# ---------------------------------------------------------------------------

def test_btp_create_user_423_for_locked_target(monkeypatch):
    import sapmap_gui
    import sapmap_exploit
    api = sapmap_gui.SAPMAPApi()
    app = sapmap_gui.create_app(api)
    tgt = SAPNode(sid="TGT", ip="10.0.0.8", hostname="tgt.lab",
                  system_type="ABAP")
    api.state.add_node(tgt)
    L.lock_node(api.state, tgt, "quarantine")

    conn = RFCConnection(source_sid="BTP:abcd1234", source_host="",
                         destination_name="D9",
                         target_sid="TGT", conn_type="rfc",
                         logon_successful=True)
    api.state.connections.append(conn)

    called = []
    monkeypatch.setattr(sapmap_exploit, "propagate_from_node",
                        lambda *a, **k: called.append(True) or [])
    monkeypatch.setattr(sapmap_gui, "_bg", lambda key, label, fn: fn())

    code, body = _wsgi(app, "POST", "/api/btp/create_user_on_target",
                       {"source_sid": "BTP:abcd1234",
                        "destination_name": "D9", "target_sid": "TGT"})
    assert code == 423
    assert json.loads(body)["error"] == "host_locked"
    assert called == []          # background propagate never spun up


# ---------------------------------------------------------------------------
# _kick_standard_scan  (the auto-scan chokepoint — BTP-linked placeholder)
# ---------------------------------------------------------------------------

def test_kick_standard_scan_skips_locked_scans_free(monkeypatch):
    import sapmap_gui
    api = sapmap_gui.SAPMAPApi()
    app = sapmap_gui.create_app(api)          # noqa: F841
    locked = SAPNode(sid="LCK", ip="10.0.0.5", hostname="lck.lab")
    free = SAPNode(sid="FRE", ip="10.0.0.6", hostname="fre.lab")
    api.state.add_node(locked)
    api.state.add_node(free)
    L.lock_node(api.state, locked, "quarantine")

    scheduled = []
    monkeypatch.setattr(sapmap_gui, "_bg",
                        lambda key, label, fn: scheduled.append(key))

    assert api._kick_standard_scan("LCK") is False
    assert not any("LCK" in k for k in scheduled)   # no scan task scheduled
    assert api._kick_standard_scan("FRE") is True
    assert any("FRE" in k for k in scheduled)


# ---------------------------------------------------------------------------
# /api/node/add  (create-then-probe: add node, skip RFC enrich if locked)
# ---------------------------------------------------------------------------

def test_node_add_enrich_skips_locked_host(monkeypatch):
    import sapmap_gui
    import sapmap_scanner
    api = sapmap_gui.SAPMAPApi()
    app = sapmap_gui.create_app(api)
    # Lock host 10.0.0.9 via an existing SID, then add a DIFFERENT SID on the
    # same host — host-scoped, so the new node is born locked.
    existing = SAPNode(sid="AAA", ip="10.0.0.9", hostname="10.0.0.9")
    api.state.add_node(existing)
    L.lock_node(api.state, existing, "quarantine")

    monkeypatch.setattr(sapmap_gui, "_bg", lambda key, label, fn: fn())
    probed = []
    monkeypatch.setattr(sapmap_gui, "_resolve_gateway_port",
                        lambda *a, **k: probed.append("gw") or (0, ""))
    monkeypatch.setattr(sapmap_scanner, "enrich_system_info",
                        lambda *a, **k: probed.append("rfcsi") or {})
    monkeypatch.setattr(sapmap_scanner, "check_ms_betrusted",
                        lambda *a, **k: probed.append("ms"))
    monkeypatch.setattr(sapmap_scanner, "check_cve_2026_58240",
                        lambda *a, **k: probed.append("cve"))

    code, _ = _wsgi(app, "POST", "/api/node/add",
                    {"sid": "BBB", "ip": "10.0.0.9", "instance_nr": "00"})
    assert code == 200
    assert api.state.get_node("BBB") is not None    # added → visible
    assert probed == []                             # but never probed


def test_node_add_enrich_runs_for_unlocked_host(monkeypatch):
    import sapmap_gui
    import sapmap_scanner
    api = sapmap_gui.SAPMAPApi()
    app = sapmap_gui.create_app(api)
    monkeypatch.setattr(sapmap_gui, "_bg", lambda key, label, fn: fn())
    probed = []
    monkeypatch.setattr(sapmap_gui, "_resolve_gateway_port",
                        lambda *a, **k: probed.append("gw") or (0, ""))
    monkeypatch.setattr(sapmap_scanner, "enrich_system_info",
                        lambda *a, **k: probed.append("rfcsi") or {})
    monkeypatch.setattr(sapmap_scanner, "check_ms_betrusted",
                        lambda *a, **k: None)
    monkeypatch.setattr(sapmap_scanner, "check_cve_2026_58240",
                        lambda *a, **k: None)
    code, _ = _wsgi(app, "POST", "/api/node/add",
                    {"sid": "CCC", "ip": "10.0.0.10", "instance_nr": "00"})
    assert code == 200
    assert "gw" in probed            # enrich proceeded on an unlocked host


# ---------------------------------------------------------------------------
# landscape_post_import_discover  (create-then-probe: XML import sweep)
# ---------------------------------------------------------------------------

def test_landscape_post_import_skips_locked():
    import sapmap_gui
    state = SAPMAPState()
    node = SAPNode(sid="IMP", ip="10.0.0.7", hostname="imp.lab",
                   instances=[InstanceInfo(instance_nr="00", ip="10.0.0.7",
                                           ports={3200: "dispatcher"})])
    state.add_node(node)
    L.lock_node(state, node, "quarantine")

    enriched, enumed = [], []
    res = sapmap_gui.landscape_post_import_discover(
        state, "IMP",
        enrich_fn=lambda *a, **k: enriched.append(True) or {},
        client_enum_fn=lambda *a, **k: enumed.append(True) or [])
    assert res == {"status": "skip", "reason": "host_locked"}
    assert enriched == [] and enumed == []


def test_landscape_post_import_runs_for_unlocked():
    import sapmap_gui
    state = SAPMAPState()
    node = SAPNode(sid="IMQ", ip="10.0.0.12", hostname="imq.lab",
                   instances=[InstanceInfo(instance_nr="00", ip="10.0.0.12",
                                           ports={3200: "dispatcher"})])
    state.add_node(node)                        # NOT locked

    enriched = []
    sapmap_gui.landscape_post_import_discover(
        state, "IMQ",
        enrich_fn=lambda *a, **k: enriched.append(True) or {
            "hostname": "imq.lab"},
        client_enum_fn=lambda *a, **k: [],
        liveness_fn=lambda *a, **k: True,
        gateway_resolve_fn=lambda *a, **k: (0, ""))
    assert enriched, "unlocked import node should have been enriched"


# ---------------------------------------------------------------------------
# shared feedback helper — HTML-escapes host AND action (stored-XSS guard)
# ---------------------------------------------------------------------------

def test_console_lock_blocked_escapes_crafted_inputs():
    import sapmap_gui
    before = len(sapmap_gui._console_lines)
    sapmap_gui._console_lock_blocked("<script>alert(1)</script>",
                                     "BTP test <img src=x>")
    new = sapmap_gui._console_lines[before:]
    assert new, "helper must emit a console line"
    txt = new[-1]["text"]
    assert "<script>" not in txt and "<img" not in txt
    assert "&lt;script&gt;" in txt and "&lt;img" in txt
    # and it carries no internal issue ref in the operator-facing text
    assert "#85" not in txt
