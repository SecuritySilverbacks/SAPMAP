"""Issue #85 PR2 — in-process lock enforcement.

The HTTP before_request gate only sees ``/api/node/<sid>/*`` routes.  The
bulk/automated actions select targets IN-PROCESS straight from
``state.nodes.values()`` (autopwn phases, the ``/api/actions/check_all_*``
routes, ``propagate_all``/``propagate_from_node``, password spray), so PR2
threads ``sapmap_lock.actionable_nodes`` / ``is_locked`` through every one.

These are spy tests: they lock a host and assert the per-node CONTACT function
is never invoked against it, while an unlocked sibling still is.
"""
from __future__ import annotations

import io
import json

import pytest

import modules  # noqa: F401  (registers subpackage paths)
import sapmap_lock as L
from sapmap_models import SAPNode, SAPMAPState, RFCConnection


# ---------------------------------------------------------------------------
# propagate_all / propagate_from_node  (modules/exploitation/sapmap_exploit.py)
# ---------------------------------------------------------------------------

def test_propagate_all_skips_locked_source(monkeypatch):
    import sapmap_exploit
    state = SAPMAPState()
    a = SAPNode(sid="AAA", ip="10.0.0.1", hostname="a.lab")
    b = SAPNode(sid="BBB", ip="10.0.0.2", hostname="b.lab")
    a.pwned = b.pwned = True
    state.add_node(a)
    state.add_node(b)
    L.lock_node(state, a, "quarantine")

    sources = []
    monkeypatch.setattr(sapmap_exploit, "propagate_from_node",
                        lambda node, st, **kw: sources.append(node.sid) or [])
    sapmap_exploit.propagate_all(state)
    assert "AAA" not in sources          # locked source never propagated from
    assert "BBB" in sources


def test_propagate_from_node_skips_locked_target(monkeypatch):
    import sapmap_exploit
    import sapmap_rfc
    state = SAPMAPState()
    src = SAPNode(sid="SRC", ip="10.0.0.1", hostname="src.lab")
    tgt = SAPNode(sid="TGT", ip="10.0.0.2", hostname="tgt.lab")
    src.pwned = True
    src.credentials = [__import__("sapmap_models").Credentials(
        username="x", password="y", verified=True)]
    state.add_node(src)
    state.add_node(tgt)
    L.lock_node(state, tgt, "quarantine")

    # Any live RFC contact would blow up the test — the guard must return first.
    def _boom(*a, **k):
        raise AssertionError("contacted a locked target")
    monkeypatch.setattr(sapmap_rfc, "retrieve_rfc_connections", _boom)
    monkeypatch.setattr(sapmap_rfc, "test_rfc_destination", _boom)

    out = sapmap_exploit.propagate_from_node(src, state, target_sid="TGT")
    assert out == []


def test_propagate_from_node_skips_locked_source(monkeypatch):
    import sapmap_exploit
    import sapmap_rfc
    state = SAPMAPState()
    src = SAPNode(sid="SRC", ip="10.0.0.1", hostname="src.lab")
    src.pwned = True
    state.add_node(src)
    L.lock_node(state, src, "quarantine")
    monkeypatch.setattr(sapmap_rfc, "retrieve_rfc_connections",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("contacted from a locked source")))
    assert sapmap_exploit.propagate_from_node(src, state) == []


# ---------------------------------------------------------------------------
# /api/actions/check_all_*  (modules/core/sapmap_gui.py)
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
    return int(cap.get("status", "200 OK").split()[0]), out.decode()


@pytest.fixture
def two_node_api(monkeypatch):
    import sapmap_gui
    api = sapmap_gui.SAPMAPApi()
    app = sapmap_gui.create_app(api)
    api.state.add_node(SAPNode(sid="ABA", ip="10.0.0.1", hostname="a.lab",
                               system_type="ABAP"))
    api.state.add_node(SAPNode(sid="ABB", ip="10.0.0.2", hostname="b.lab",
                               system_type="ABAP"))
    L.lock_node(api.state, api.state.nodes["ABA"], "quarantine")
    # Run the background work synchronously so the spy is deterministic.
    monkeypatch.setattr(sapmap_gui, "_bg", lambda key, label, fn: fn())
    return sapmap_gui, api, app


def test_check_all_gw_skips_locked_host(two_node_api, monkeypatch):
    sapmap_gui, api, app = two_node_api
    import sapmap_exploit
    # check_all_gw needs >= 2 ACTIONABLE nodes; add a second free one.
    api.state.add_node(SAPNode(sid="ABC", ip="10.0.0.3", hostname="c.lab",
                               system_type="ABAP"))
    hit = []
    monkeypatch.setattr(sapmap_exploit, "check_gw_vulnerable",
                        lambda node: hit.append(node.sid))
    code, _ = _wsgi(app, "POST", "/api/actions/check_all_gw")
    assert code == 200
    assert "ABA" not in hit                 # locked host skipped
    assert {"ABB", "ABC"} <= set(hit)


def test_check_all_cve_58240_skips_locked_host(two_node_api, monkeypatch):
    sapmap_gui, _api, app = two_node_api
    import sapmap_scanner
    hit = []
    monkeypatch.setattr(sapmap_scanner, "check_cve_2026_58240",
                        lambda node: hit.append(node.sid))
    code, _ = _wsgi(app, "POST", "/api/actions/check_all_cve_58240")
    assert code == 200
    assert "ABA" not in hit and "ABB" in hit


# ---------------------------------------------------------------------------
# autopwn phase2_exploit  (modules/exploitation/sapmap_autopwn.py)
# ---------------------------------------------------------------------------

def test_phase2_exploit_skips_locked_vulnerable_node(monkeypatch):
    import sapmap_autopwn
    import sapmap_exploit
    state = SAPMAPState()
    locked = SAPNode(sid="LCK", ip="10.0.0.1", hostname="lck.lab",
                     system_type="ABAP")
    free = SAPNode(sid="FRE", ip="10.0.0.2", hostname="fre.lab",
                   system_type="ABAP")
    for n in (locked, free):
        n.gw_vulnerable = True
    state.add_node(locked)
    state.add_node(free)
    L.lock_node(state, locked, "quarantine")

    exploited = []
    monkeypatch.setattr(sapmap_exploit, "create_user_gw_exploit",
                        lambda node, st, **kw: exploited.append(node.sid))
    cfg = sapmap_autopwn.AutoPwnConfig()
    sapmap_autopwn.phase2_exploit(state, cfg, wave=1)
    assert "LCK" not in exploited          # locked vuln node not exploited
    assert "FRE" in exploited


def test_dest_target_locked_helper():
    """Adversarial-review regression: phase3_enrich must recognise a
    destination whose TARGET is a locked host — both a mapped locked node
    (via target_sid) and a bare locked host/IP string."""
    import sapmap_autopwn
    from sapmap_models import RFCConnection
    state = SAPMAPState()
    b = SAPNode(sid="BBB", ip="10.0.0.2", hostname="b.lab")
    state.add_node(b)
    L.lock_node(state, b, "quarantine")
    by_sid = RFCConnection(source_sid="AAA", source_host="a.lab",
                           destination_name="D1", target_sid="BBB")
    by_host = RFCConnection(source_sid="AAA", source_host="a.lab",
                            destination_name="D2", target_host="b.lab")
    by_ip = RFCConnection(source_sid="AAA", source_host="a.lab",
                          destination_name="D3", target_ip="10.0.0.2")
    free = RFCConnection(source_sid="AAA", source_host="a.lab",
                         destination_name="D4", target_host="other.lab")
    assert sapmap_autopwn._dest_target_locked(state, by_sid) is True
    assert sapmap_autopwn._dest_target_locked(state, by_host) is True
    assert sapmap_autopwn._dest_target_locked(state, by_ip) is True
    assert sapmap_autopwn._dest_target_locked(state, free) is False


def test_phase3_non_self_filters_locked_targets_sourcepin():
    """Adversarial-review regression (wiring): phase3_enrich's non_self
    liveness list — the one every ping/discovery probe iterates — must be
    filtered through _dest_target_locked, so a destination to a locked host
    is never contacted.  A source-pin (the behavioural path drags in slow
    SecStore enrichment); the logic itself is covered by
    test_dest_target_locked_helper above."""
    import inspect
    import sapmap_autopwn
    src = inspect.getsource(sapmap_autopwn.phase3_enrich)
    # the liveness list is built AND filtered on the locked-target helper
    assert "non_self = [" in src
    assert "_dest_target_locked(state, c)" in src


def test_detection_pass_skips_locked_host(monkeypatch):
    import sapmap_autopwn
    import sapmap_scanner
    state = SAPMAPState()
    locked = SAPNode(sid="LCK", ip="10.0.0.1", hostname="lck.lab",
                     system_type="ABAP")
    free = SAPNode(sid="FRE", ip="10.0.0.2", hostname="fre.lab",
                   system_type="ABAP")
    state.add_node(locked)
    state.add_node(free)
    L.lock_node(state, locked, "quarantine")
    probed = []
    monkeypatch.setattr(sapmap_scanner, "check_cve_2022_22536",
                        lambda node: probed.append(node.sid))
    cfg = sapmap_autopwn.AutoPwnConfig(include_icmad_detection=True,
                                       include_router_info_detection=False)
    sapmap_autopwn.detection_pass(state, cfg)
    assert "LCK" not in probed


# ---------------------------------------------------------------------------
# password spray target matrix  (modules/discovery/sapmap_pwspray.py)
# ---------------------------------------------------------------------------

def test_pwspray_target_matrix_marks_locked_ineligible():
    import sapmap_pwspray
    state = SAPMAPState()
    locked = SAPNode(sid="LCK", ip="10.0.0.1", hostname="lck.lab",
                     system_type="ABAP")
    free = SAPNode(sid="FRE", ip="10.0.0.2", hostname="fre.lab",
                   system_type="ABAP")
    # give both a dispatcher port so they'd otherwise be eligible
    from sapmap_models import InstanceInfo
    for n in (locked, free):
        n.instances = [InstanceInfo(instance_nr="00", ip=n.ip,
                                    ports={3200: "dispatcher"})]
    state.add_node(locked)
    state.add_node(free)
    L.lock_node(state, locked, "quarantine")

    tm = sapmap_pwspray.build_target_matrix(state)
    eligible_sids = {t.sid for t in tm["eligible"]}
    assert "LCK" not in eligible_sids
    assert any(getattr(n, "sid", "") == "LCK" and reason == "host_locked"
               for n, reason in tm["ineligible"])


# ---------------------------------------------------------------------------
# visibility — locked hosts still COUNT (the guarantee the filter must respect)
# ---------------------------------------------------------------------------

def test_locked_host_still_visible_in_actionable_complement():
    state = SAPMAPState()
    a = SAPNode(sid="AAA", ip="10.0.0.1", hostname="a.lab")
    b = SAPNode(sid="BBB", ip="10.0.0.2", hostname="b.lab")
    state.add_node(a)
    state.add_node(b)
    L.lock_node(state, a, "quarantine")
    # excluded from the actionable (contact) set ...
    assert {n.sid for n in L.actionable_nodes(state)} == {"BBB"}
    # ... but still present in state.nodes (counts / map / report unaffected)
    assert set(state.nodes) == {"AAA", "BBB"}
