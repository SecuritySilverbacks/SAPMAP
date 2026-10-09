"""Tests for landscape_post_import_discover() — issue #109.

After landscape XML import, the operator cannot do anything with the
imported systems (login, default-cred check, pwspray) because the
clients field stays empty.  Issue #109's accepted plan:

  * Run RFC_SYSTEM_INFO on each newly-added system to discover the
    real SID (addresses issue #114's residual gap for pure app-server
    entries that don't carry systemid in the XML).
  * Enumerate clients via DIAG on each newly-added system.
  * Only do the above when the operator did NOT tick "no scan for app
    servers, only file import" (default: unticked -> scan on).

Covers the module-level helper landscape_post_import_discover(state,
sid, enrich_fn, client_enum_fn) which the route's background sweep
calls per newly-added node.  Scanner functions are injected as mocks
so tests don't open sockets.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import modules  # noqa: F401

from sapmap_models import SAPMAPState, SAPNode, InstanceInfo
from sapmap_gui import (
    landscape_post_import_discover,
    parse_landscape_xml_into_state,
    run_landscape_post_import_sweep,
)


# ---------------------------------------------------------------------------
# Autouse fixture: default sapmap_scanner._scan_port to "alive" so the
# ~90% of tests that exercise non-liveness behaviour don't need an
# explicit liveness_fn argument.  Tests specifically about the liveness
# probe pass their own liveness_fn and bypass this default.
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _default_liveness_alive(monkeypatch):
    """Make sapmap_scanner._scan_port always report 'alive' so tests
    that don't care about liveness don't trip the dead-host short-
    circuit added for issue #109 follow-up (operator-reported 68-
    system landscape with mostly dead hosts, 2026-10-09)."""
    import sapmap_scanner
    monkeypatch.setattr(sapmap_scanner, "_scan_port",
                         lambda host, port, timeout=2.0,
                         saprouter="": True)


# ---------------------------------------------------------------------------
# Fixtures: scanner-function mocks that record calls
# ---------------------------------------------------------------------------

def _mk_enrich_mock(return_info=None):
    """Return (fn, calls) — fn mimics sapmap_scanner.enrich_system_info,
    calls is a list the test can inspect afterwards."""
    calls = []
    info = return_info or {}
    def fn(host, gw_port, timeout=10, instance_nrs=None,
            sid_hint="", saprouter=""):
        calls.append({"host": host, "gw_port": gw_port,
                       "timeout": timeout, "instance_nrs": instance_nrs,
                       "sid_hint": sid_hint, "saprouter": saprouter})
        return dict(info)
    return fn, calls


def _mk_client_enum_mock(return_clients=None):
    """Return (fn, calls) — fn mimics
    sapmap_scanner.enumerate_system_clients."""
    calls = []
    clients = list(return_clients) if return_clients is not None else []
    def fn(host, disp_port, saprouter="", sid_hint=""):
        calls.append({"host": host, "disp_port": disp_port,
                       "saprouter": saprouter, "sid_hint": sid_hint})
        return list(clients)
    return fn, calls


def _mk_state_with_node(sid, host="10.0.0.1", inst_nr="00",
                         discovered_via_xml=False,
                         sentinel_sid="", port=3200,
                         port_label="dispatcher"):
    """Build a fresh state carrying a single node — mirrors the shape
    parse_landscape_xml_into_state produces for an imported entry."""
    state = SAPMAPState()
    inst = InstanceInfo(instance_nr=inst_nr, ip=host,
                         ports={port: port_label})
    node = SAPNode(
        sid=sid, hostname=host, ip=host,
        instances=[inst],
        sapology_data={"xml_sentinel_sid": sentinel_sid}
                        if discovered_via_xml else {},
        discovered_via_xml=discovered_via_xml,
    )
    state.add_node(node)
    return state, node


# ---------------------------------------------------------------------------
# Primary ask: client enumeration populates node.clients
# ---------------------------------------------------------------------------

def test_discover_populates_clients_from_enum():
    """The main #109 ask — after import, node.clients was empty, this
    helper fills it from the DIAG enumeration result."""
    state, node = _mk_state_with_node("NPL", inst_nr="00")
    enrich_fn, _ = _mk_enrich_mock({"sysinfo_source": "legacy_leak"})
    client_fn, client_calls = _mk_client_enum_mock(["000", "001", "100"])

    result = landscape_post_import_discover(
        state, "NPL", enrich_fn=enrich_fn, client_enum_fn=client_fn)

    assert result["status"] == "ok"
    assert result["clients_added"] == 3
    assert node.clients == [
        {"nr": "000", "category": ""},
        {"nr": "001", "category": ""},
        {"nr": "100", "category": ""},
    ]
    # Dispatcher port was derived from inst_nr=00 -> 3200.
    assert client_calls[0]["disp_port"] == 3200


def test_discover_preserves_existing_client_categories():
    """When a prior scan populated client CATEGORY hints
    (P=production, T=test), a later post-import enum must preserve
    them for clients that are still present — only new clients get
    the empty category default."""
    state, node = _mk_state_with_node("NPL", inst_nr="00")
    node.clients = [
        {"nr": "000", "category": "T"},
        {"nr": "001", "category": "P"},
    ]
    enrich_fn, _ = _mk_enrich_mock()
    # Fresh enum returns 000 (preserve), 001 (preserve), 100 (new).
    client_fn, _ = _mk_client_enum_mock(["000", "001", "100"])

    landscape_post_import_discover(
        state, "NPL", enrich_fn=enrich_fn, client_enum_fn=client_fn)

    nrs_to_cat = {c["nr"]: c["category"] for c in node.clients}
    assert nrs_to_cat == {"000": "T", "001": "P", "100": ""}


# ---------------------------------------------------------------------------
# RFC_SYSTEM_INFO enrichment (issue #114 — real SID for placeholders)
# ---------------------------------------------------------------------------

def test_discover_promotes_placeholder_sid_to_real_sid():
    """XML-imported placeholder nodes (discovered_via_xml=True +
    sapology_data['xml_sentinel_sid'] non-empty) must have their SID
    REPLACED with the real one from RFC_SYSTEM_INFO — this is issue
    #114's gap for pure app-server entries that don't carry systemid.
    """
    state, node = _mk_state_with_node(
        "XML_FOO", discovered_via_xml=True, sentinel_sid="@01")
    enrich_fn, _ = _mk_enrich_mock({
        "sid": "NPL",
        "hostname": "srv01npl",
        "os_type": "Linux",
        "kernel": "753",
        "sysinfo_source": "rfcsi_anon",
    })
    client_fn, _ = _mk_client_enum_mock([])

    result = landscape_post_import_discover(
        state, "XML_FOO", enrich_fn=enrich_fn, client_enum_fn=client_fn)

    assert result["new_sid"] == "NPL"
    # State key was renamed.
    assert state.get_node("XML_FOO") is None
    npl = state.get_node("NPL")
    assert npl is not None
    assert npl.sid == "NPL"
    # Enriched fields applied.
    assert npl.hostname == "srv01npl"
    assert npl.os_type == "Linux"
    assert npl.kernel == "753"


def test_discover_does_not_rename_real_sid_from_xml():
    """When the XML carried a real systemid (non-placeholder), the
    node's SID must NOT be renamed even if RFC_SYSTEM_INFO returns a
    different value — the XML is authoritative for named systems.
    This mirrors the convention in the per-node rfc_system_info
    route."""
    state, node = _mk_state_with_node(
        "NPL", discovered_via_xml=False, sentinel_sid="")
    enrich_fn, _ = _mk_enrich_mock({
        "sid": "SURPRISE",       # scanner returns a different SID
        "hostname": "srv01npl",
    })
    client_fn, _ = _mk_client_enum_mock([])

    result = landscape_post_import_discover(
        state, "NPL", enrich_fn=enrich_fn, client_enum_fn=client_fn)

    assert "new_sid" not in result
    assert state.get_node("NPL") is not None
    assert state.get_node("SURPRISE") is None
    assert node.sid == "NPL"


def test_discover_handles_rename_collision_gracefully():
    """If RFC_SYSTEM_INFO's real SID COLLIDES with a node already on
    the map (e.g. a prior scan populated it), the rename must fail
    without raising — the placeholder stays in place and the operator
    sees a log line."""
    state, _ = _mk_state_with_node(
        "XML_NPL", discovered_via_xml=True, sentinel_sid="@01")
    # Pre-existing "NPL" node (from a prior scan).
    pre_inst = InstanceInfo(instance_nr="00", ip="10.0.0.99",
                             ports={3200: "dispatcher"})
    pre_node = SAPNode(sid="NPL", hostname="pre", ip="10.0.0.99",
                        instances=[pre_inst])
    state.add_node(pre_node)

    enrich_fn, _ = _mk_enrich_mock({"sid": "NPL"})
    client_fn, _ = _mk_client_enum_mock([])

    result = landscape_post_import_discover(
        state, "XML_NPL", enrich_fn=enrich_fn, client_enum_fn=client_fn)

    # Collision -> no new_sid in result, both nodes still present.
    assert "new_sid" not in result
    assert state.get_node("XML_NPL") is not None
    assert state.get_node("NPL") is pre_node


# ---------------------------------------------------------------------------
# Field enrichment (hostname, os_type, db_type, kernel, sap_release)
# ---------------------------------------------------------------------------

def test_discover_applies_enriched_fields():
    """RFC_SYSTEM_INFO's enriched fields (hostname, os_type, db_type,
    kernel, sap_release, sysinfo_source) must land on the node even
    when SID stays unchanged."""
    state, node = _mk_state_with_node("NPL")
    enrich_fn, _ = _mk_enrich_mock({
        "hostname": "srv01npl.lan",
        "os_type": "Linux",
        "db_type": "SYB",
        "kernel": "753",
        "sap_release": "7.53",
        "sysinfo_source": "rfcsi_anon",
    })
    client_fn, _ = _mk_client_enum_mock([])

    landscape_post_import_discover(
        state, "NPL", enrich_fn=enrich_fn, client_enum_fn=client_fn)

    assert node.hostname == "srv01npl.lan"
    assert node.os_type == "Linux"
    assert node.db_type == "SYB"
    assert node.kernel == "753"
    assert node.sap_release == "7.53"
    assert node.sysinfo_source == "rfcsi_anon"


def test_discover_derives_gw_port_from_instance_nr():
    """Gateway port = 3300 + instance_nr; dispatcher port = 3200 +
    instance_nr.  Verify the derivation for a non-default inst_nr."""
    state, _ = _mk_state_with_node("NPL", inst_nr="42")
    enrich_fn, enrich_calls = _mk_enrich_mock()
    client_fn, client_calls = _mk_client_enum_mock(["000"])

    landscape_post_import_discover(
        state, "NPL", enrich_fn=enrich_fn, client_enum_fn=client_fn)

    assert enrich_calls[0]["gw_port"] == 3342
    assert client_calls[0]["disp_port"] == 3242


def test_discover_passes_saprouter_through():
    """SAProuter strings on the node must be threaded through to both
    the enrich call and the client-enum call so routed landscapes
    work end-to-end."""
    state, node = _mk_state_with_node("NPL")
    node.saprouter = "/H/router.host/S/3299/H/"
    enrich_fn, enrich_calls = _mk_enrich_mock()
    client_fn, client_calls = _mk_client_enum_mock([])

    landscape_post_import_discover(
        state, "NPL", enrich_fn=enrich_fn, client_enum_fn=client_fn)

    assert enrich_calls[0]["saprouter"] == "/H/router.host/S/3299/H/"
    assert client_calls[0]["saprouter"] == "/H/router.host/S/3299/H/"


# ---------------------------------------------------------------------------
# Defensive paths
# ---------------------------------------------------------------------------

def test_discover_skips_missing_node_gracefully():
    """If the node has been deleted between the parser and the
    background sweep (e.g. operator hit STOP and cleared state), the
    helper must return a skip status without raising."""
    state = SAPMAPState()
    result = landscape_post_import_discover(state, "GHOST")
    assert result == {"status": "skip", "reason": "node_not_found"}


def test_discover_skips_node_with_no_host():
    """A node with neither ip nor hostname can't be reached — skip
    without opening any sockets."""
    state = SAPMAPState()
    inst = InstanceInfo(instance_nr="00", ip="",
                         ports={3200: "dispatcher"})
    node = SAPNode(sid="EMPTY", hostname="", ip="",
                    instances=[inst])
    state.add_node(node)
    enrich_fn, enrich_calls = _mk_enrich_mock()
    client_fn, client_calls = _mk_client_enum_mock([])

    result = landscape_post_import_discover(
        state, "EMPTY", enrich_fn=enrich_fn, client_enum_fn=client_fn)

    assert result == {"status": "skip", "reason": "no_host"}
    assert enrich_calls == []
    assert client_calls == []


def test_discover_skips_node_with_no_instance_nr():
    """A node that somehow has instances but none with a parseable
    instance_nr can't have ports derived — skip rather than crash."""
    state = SAPMAPState()
    inst = InstanceInfo(instance_nr=None, ip="10.0.0.1", ports={})
    node = SAPNode(sid="NOINST", hostname="h", ip="10.0.0.1",
                    instances=[inst])
    state.add_node(node)
    enrich_fn, enrich_calls = _mk_enrich_mock()
    client_fn, client_calls = _mk_client_enum_mock([])

    result = landscape_post_import_discover(
        state, "NOINST", enrich_fn=enrich_fn, client_enum_fn=client_fn)

    assert result == {"status": "skip", "reason": "no_instance_nr"}
    assert enrich_calls == []
    assert client_calls == []


def test_discover_swallows_enrich_exceptions():
    """A raising enrich_fn (network error, SDK crash) must not break
    the client-enum step that follows — operator still gets clients
    even when RFC probe fails."""
    state, node = _mk_state_with_node("NPL")
    def enrich_boom(*a, **k):
        raise ConnectionError("test boom")
    client_fn, _ = _mk_client_enum_mock(["000", "100"])

    result = landscape_post_import_discover(
        state, "NPL", enrich_fn=enrich_boom, client_enum_fn=client_fn)

    assert result["status"] == "ok"
    assert result["clients_added"] == 2
    assert len(node.clients) == 2


def test_discover_swallows_client_enum_exceptions():
    """Symmetric to above: a raising client enum must not break the
    enrich step's field population."""
    state, node = _mk_state_with_node("NPL")
    enrich_fn, _ = _mk_enrich_mock({"hostname": "srv01npl"})
    def client_boom(*a, **k):
        raise ConnectionError("test boom")

    result = landscape_post_import_discover(
        state, "NPL", enrich_fn=enrich_fn, client_enum_fn=client_boom)

    assert result["status"] == "ok"
    assert node.hostname == "srv01npl"
    # clients_added absent -> no clients landed, node.clients untouched.
    assert "clients_added" not in result


# ---------------------------------------------------------------------------
# End-to-end: parser output flows into the discover helper
# ---------------------------------------------------------------------------

def test_e2e_parser_added_sids_feed_discover():
    """Smoke-test the integration: run the parser on a tiny landscape,
    then feed each `added` SID into landscape_post_import_discover
    with mocked scanner functions.  Asserts the parser's output shape
    matches what the discover helper expects."""
    state = SAPMAPState()
    xml = """<?xml version='1.0' encoding='UTF-8'?>
<Landscape version='1'>
  <Services>
    <Service name='Lab NPL' type='SAPGUI' uuid='e1'
             server='10.0.0.1:3200' mode='1'/>
    <Service name='Lab SM1' type='SAPGUI' uuid='e2'
             server='10.0.0.2:3200' mode='1'/>
  </Services>
</Landscape>"""
    summary = parse_landscape_xml_into_state(state, xml,
                                              no_scan_appservers=True)
    added = summary["added"]
    assert len(added) == 2

    # Mocks per SID so we can confirm each got discovered.
    discovered = []
    def enrich_fn(host, gw_port, **k):
        discovered.append(host)
        return {"sysinfo_source": "legacy_leak"}
    def client_fn(host, disp_port, **k):
        return ["000"]

    for s in added:
        landscape_post_import_discover(
            state, s, enrich_fn=enrich_fn, client_enum_fn=client_fn)

    assert sorted(discovered) == ["10.0.0.1", "10.0.0.2"]
    for s in added:
        n = state.get_node(s)
        assert n.clients == [{"nr": "000", "category": ""}], (
            f"node {s} should have clients populated by the discover "
            f"helper")


# ---------------------------------------------------------------------------
# Route-level: no_scan=1 flag suppresses the auto-scan
# ---------------------------------------------------------------------------

def _gui_source():
    """Read the sapmap_gui.py source so route-level assertions can
    pin the wiring without having to spin up a Bottle server."""
    import sapmap_gui
    import inspect
    return inspect.getsource(sapmap_gui)


def test_sweep_calls_real_sapmap_stop_api():
    """Regression pin from adversarial review 2026-10-09.  The first
    cut of the sweep closure called `sapmap_stop.should_stop()`, which
    doesn't exist on the sapmap_stop module (real API is
    `is_stop_requested()`).  `_bg`'s wrapper has no except around
    `fn()`, so the daemon thread died silently with AttributeError on
    the FIRST iteration — the entire issue #109 feature was a no-op
    in production.

    The ORIGINAL test here only did `assert
    'sapmap_stop.should_stop()' in src`, which ENCODED the bug.  Lesson:
    source-string tests pin spelling but not RUNTIME SEMANTICS; this
    replacement test imports the real sapmap_stop module and asserts
    the actual API shape, plus the companion
    `test_sweep_runs_without_raising` executes the sweep end-to-end.
    """
    import sapmap_stop
    assert hasattr(sapmap_stop, "is_stop_requested"), (
        "sapmap_stop must expose is_stop_requested() — the sweep "
        "depends on it")
    assert not hasattr(sapmap_stop, "should_stop"), (
        "sapmap_stop does NOT expose should_stop(); if someone adds "
        "it as an alias, remove this guard and update the sweep")


def test_sweep_runs_without_raising_and_calls_discover_per_sid():
    """End-to-end: invoke run_landscape_post_import_sweep directly
    with an injected mock discover_fn + task_update_fn.  This catches
    the class of API-drift bug (sapmap_stop.should_stop) that source-
    string tests cannot — the sweep must EXECUTE without raising and
    must call the discover helper for every provided SID."""
    state = SAPMAPState()
    discovered = []
    updates = []
    def _fake_discover(st, sid, **k):
        discovered.append(sid)
        return {"status": "ok"}
    def _fake_task_update(key, label):
        updates.append((key, label))

    processed = run_landscape_post_import_sweep(
        state, ["A", "B", "C"],
        task_update_fn=_fake_task_update,
        discover_fn=_fake_discover)

    assert processed == ["A", "B", "C"]
    assert discovered == ["A", "B", "C"], (
        "sweep must call discover_fn for every provided SID — if this "
        "fails the sweep thread is likely dying on an AttributeError "
        "or similar runtime symbol error")
    # Progress label fired per iteration under the stable task key.
    assert len(updates) == 3
    assert all(k == "landscape:post_import_scan" for k, _ in updates)
    assert updates[0][1].startswith("(1/3) A:")
    assert updates[2][1].startswith("(3/3) C:")


def test_sweep_breaks_cleanly_on_stop_request(monkeypatch):
    """When the operator hits STOP mid-sweep, the loop must consult
    sapmap_stop.is_stop_requested() BEFORE each iteration and break
    cleanly without raising.  Pins the real-API call behaviour."""
    import sapmap_stop
    # Signal stop before the loop runs.
    monkeypatch.setattr(sapmap_stop, "is_stop_requested",
                         lambda: True)
    state = SAPMAPState()
    discovered = []
    def _fake_discover(st, sid, **k):
        discovered.append(sid)
    processed = run_landscape_post_import_sweep(
        state, ["A", "B", "C"], discover_fn=_fake_discover)
    assert processed == []
    assert discovered == [], (
        "stop-flag check must fire BEFORE the discover call so no "
        "node is processed when stop is set")


def test_sweep_continues_past_per_node_discover_crash():
    """If landscape_post_import_discover raises on one SID (shouldn't
    happen — it swallows internal exceptions — but structural errors
    like OOM or an import crash could), the sweep must log + continue
    to the remaining SIDs."""
    state = SAPMAPState()
    discovered = []
    def _flaky(st, sid, **k):
        discovered.append(sid)
        if sid == "B":
            raise RuntimeError("structural failure")
    processed = run_landscape_post_import_sweep(
        state, ["A", "B", "C"], discover_fn=_flaky)
    assert processed == ["A", "B", "C"], (
        "a per-node crash must not abort the sweep for the remaining "
        "nodes")
    assert discovered == ["A", "B", "C"]


def test_sweep_handles_empty_added_sids():
    """Zero added SIDs → sweep returns empty, no updates fired, no
    discover calls, no raise."""
    state = SAPMAPState()
    discovered = []
    updates = []
    processed = run_landscape_post_import_sweep(
        state, [],
        task_update_fn=lambda k, l: updates.append((k, l)),
        discover_fn=lambda st, s, **k: discovered.append(s))
    assert processed == []
    assert discovered == []
    assert updates == []


def test_route_gates_sweep_on_no_scan_flag_via_source():
    """Pin that the import route still branches on no_scan_appservers
    before spawning the sweep — this is the operator-facing opt-out."""
    src = _gui_source()
    assert "not no_scan_appservers and added_sids" in src, (
        "route must gate the sweep on no_scan_appservers so a ticked "
        "checkbox stays silent")


def test_route_spawns_bg_task_delegating_to_module_level_sweep():
    """Pin that the route's _bg call delegates to the module-level
    run_landscape_post_import_sweep (not an inline closure) so the
    sweep is directly testable without Bottle plumbing."""
    src = _gui_source()
    assert "_bg(\"landscape:post_import_scan\"" in src, (
        "route must spawn _bg under the stable 'landscape:post_"
        "import_scan' key")
    assert "run_landscape_post_import_sweep(" in src, (
        "route's _bg body must delegate to the module-level sweep "
        "helper — regression pin after lifting the closure to module "
        "scope for testability")


def test_route_summary_carries_post_import_scan_started_flag():
    """The HTTP response must tell the GUI whether a background sweep
    was spawned — so the UI can show 'scan in progress' chrome and
    poll the active-tasks panel for completion."""
    src = _gui_source()
    assert 'summary["post_import_scan_started"] = True' in src
    assert 'summary["post_import_scan_started"] = False' in src


# ---------------------------------------------------------------------------
# Logic fix #2 (adversarial review): no-systemid placeholder promotion
# ---------------------------------------------------------------------------

def test_discover_promotes_no_systemid_placeholder_sid():
    """Adversarial-review finding: the common SAPGUILandscape.xml
    form (`<Service server='host:port'/>` with NO systemid attribute
    at all) is treated as a placeholder by the parser
    (discovered_via_xml=True) BUT `xml_sentinel_sid` lands as ""
    because `svc_sid` is empty.

    An earlier version AND-ed `bool(xml_sentinel_sid)` into the
    is_placeholder gate — which false-negatived this common case,
    skipping SID promotion.  The fix bases the gate on
    discovered_via_xml alone.  This test pins the fix.
    """
    state = SAPMAPState()
    inst = InstanceInfo(instance_nr="00", ip="10.0.0.1",
                         ports={3200: "dispatcher"})
    # Mirror what the parser produces for `<Service server='...'/>`:
    # discovered_via_xml=True, sapology_data has empty
    # xml_sentinel_sid.
    node = SAPNode(
        sid="XML_LAB", hostname="10.0.0.1", ip="10.0.0.1",
        instances=[inst],
        sapology_data={"xml_sentinel_sid": "",
                        "xml_service_name": "Lab"},
        discovered_via_xml=True,
    )
    state.add_node(node)

    enrich_fn, _ = _mk_enrich_mock({"sid": "NPL", "hostname": "srv01"})
    client_fn, _ = _mk_client_enum_mock([])

    result = landscape_post_import_discover(
        state, "XML_LAB", enrich_fn=enrich_fn, client_enum_fn=client_fn)

    assert result.get("new_sid") == "NPL", (
        "SID promotion must fire for discovered_via_xml=True nodes "
        "even when xml_sentinel_sid is empty — the parser sets "
        "xml_sentinel_sid='' for `<Service server=...>` entries with "
        "no systemid attribute (the common SAPGUILandscape.xml form)")
    assert state.get_node("NPL") is not None
    assert state.get_node("XML_LAB") is None


# ---------------------------------------------------------------------------
# Logic fix #3 (adversarial review): MS fan-out instance selection
# ---------------------------------------------------------------------------

def test_discover_prefers_dispatcher_instance_over_sapms_placeholder():
    """Adversarial-review finding: for `<Service msid=.../>` entries,
    the parser builds a sapms placeholder instance first (ports map
    = {3601: 'sapms'} on the MS host) and _import_appserver_instances
    then APPENDS real app-server instances (each with its own `ip` +
    ports map containing 32NN dispatcher + 33NN gateway).

    An earlier version of the helper broke on the FIRST parseable
    instance_nr, picking the sapms placeholder.  gw_port and
    disp_port were then derived from the MS instance_nr (01 for a
    3601 port) and probed on the MS host — but neither 3301 nor 3201
    is listening on the MS host (which typically runs no dialog
    instance).  The sweep silently returned nothing.

    The fix: prefer instances whose ports map contains a 3200-3299
    or 3300-3399 entry (real dispatcher/gateway), fall back to any
    parseable instance_nr only when none exists.  This test pins
    the preference logic + the fact that the picked instance's own
    `ip` is used (not node.ip).
    """
    state = SAPMAPState()
    # Placeholder sapms instance built by parser (MS host).
    ms_inst = InstanceInfo(instance_nr="01", ip="10.0.0.1",
                            ports={3601: "sapms"})
    # Real app-server instance appended by _import_appserver_instances
    # on a DIFFERENT host (common in 3-tier landscapes).
    app_inst = InstanceInfo(instance_nr="42", ip="10.0.0.99",
                             ports={3242: "dispatcher",
                                     3342: "gateway"})
    node = SAPNode(sid="MSNODE", hostname="10.0.0.1", ip="10.0.0.1",
                    instances=[ms_inst, app_inst])
    state.add_node(node)

    enrich_fn, enrich_calls = _mk_enrich_mock({"sysinfo_source": "ok"})
    client_fn, client_calls = _mk_client_enum_mock(["000"])

    landscape_post_import_discover(
        state, "MSNODE", enrich_fn=enrich_fn,
        client_enum_fn=client_fn)

    # Both probes must have hit the app-server instance's host + its
    # derived gw/disp ports — NOT the MS host at MS ports.
    assert enrich_calls[0]["host"] == "10.0.0.99", (
        "enrich must probe the app-server's own ip, not the MS host")
    assert enrich_calls[0]["gw_port"] == 3342, (
        "gw_port must be derived from the app-server's instance_nr "
        "(42 -> 3342), not the sapms placeholder (01 -> 3301)")
    assert client_calls[0]["host"] == "10.0.0.99"
    assert client_calls[0]["disp_port"] == 3242


def test_discover_falls_back_to_any_instance_when_no_real_ports():
    """When NO instance carries a dispatcher/gateway port (bare MS
    placeholder on an MS-only node that fan-out couldn't resolve),
    the helper must still fall back to the first parseable
    instance_nr rather than aborting — a sapms-only probe at least
    establishes connectivity."""
    state = SAPMAPState()
    ms_only = InstanceInfo(instance_nr="05", ip="10.0.0.1",
                            ports={3605: "sapms"})
    node = SAPNode(sid="MSONLY", hostname="10.0.0.1", ip="10.0.0.1",
                    instances=[ms_only])
    state.add_node(node)

    enrich_fn, enrich_calls = _mk_enrich_mock()
    client_fn, _ = _mk_client_enum_mock([])

    landscape_post_import_discover(
        state, "MSONLY", enrich_fn=enrich_fn,
        client_enum_fn=client_fn)

    # Fallback picked the sapms placeholder → gw_port = 3305.  This
    # probe will probably fail in production, but the helper didn't
    # ABORT — the enrich call was still attempted so the operator at
    # least sees a connect-error diagnostic instead of a silent skip.
    assert enrich_calls[0]["gw_port"] == 3305


def test_sweep_reports_progress_via_task_update_fn():
    """The sweep must call its task_update_fn with a '(i/N) sid:...'
    label per iteration under the stable task key — covered by
    `test_sweep_runs_without_raising_and_calls_discover_per_sid`
    which inspects the recorded updates list directly.  This slim
    test pins only the task-key spelling at module-level so
    source-string drift is still caught."""
    src = _gui_source()
    assert '"landscape:post_import_scan"' in src, (
        "task_update key must stay 'landscape:post_import_scan' so "
        "the GUI active-tasks panel can match it")


# ---------------------------------------------------------------------------
# Liveness probe — operator follow-up on issue #109 (2026-10-09)
# ---------------------------------------------------------------------------

def test_liveness_probe_skips_dead_host_before_enrichment():
    """Operator ran issue #109 on a 68-system landscape; most hosts
    were historic/demo VMs long gone.  Each dead host wasted ~90s
    cycling through RFC + ICM + DIAG + MS + client-enum chains before
    failing.  The liveness probe cuts dead hosts to ~4s (2 ports x 2s
    TCP connect).  Pins: when liveness_fn returns False for both the
    dispatcher and gateway ports, the helper returns a skip without
    calling enrich_fn or client_enum_fn.
    """
    state, _node = _mk_state_with_node("DEAD", inst_nr="00")
    probed = []
    def _dead(host, port, timeout=2.0, saprouter=""):
        probed.append(port)
        return False
    enrich_fn, enrich_calls = _mk_enrich_mock()
    client_fn, client_calls = _mk_client_enum_mock(["000"])

    result = landscape_post_import_discover(
        state, "DEAD",
        enrich_fn=enrich_fn, client_enum_fn=client_fn,
        liveness_fn=_dead)

    assert result == {"status": "skip", "reason": "host_unreachable"}
    # BOTH ports probed before giving up.
    assert sorted(probed) == [3200, 3300], (
        f"liveness probe must try both dispatcher and gateway before "
        f"giving up; got {sorted(probed)}")
    # Enrich + client-enum NEVER called — the whole point of the fix.
    assert enrich_calls == []
    assert client_calls == []


def test_liveness_probe_proceeds_when_dispatcher_alive():
    """When the dispatcher port answers (first probe), the helper
    short-circuits the probe and runs the full enrichment — no second
    port probe needed."""
    state, _ = _mk_state_with_node("ALIVE", inst_nr="00")
    probed = []
    def _disp_alive(host, port, timeout=2.0, saprouter=""):
        probed.append(port)
        return port == 3200  # only dispatcher answers
    enrich_fn, enrich_calls = _mk_enrich_mock(
        {"hostname": "srv01alive", "sysinfo_source": "ok"})
    client_fn, _ = _mk_client_enum_mock(["000", "100"])

    result = landscape_post_import_discover(
        state, "ALIVE",
        enrich_fn=enrich_fn, client_enum_fn=client_fn,
        liveness_fn=_disp_alive)

    assert result["status"] == "ok"
    assert result["clients_added"] == 2
    # Only dispatcher probed — gateway probe short-circuited by the
    # first-match-wins break.
    assert probed == [3200]
    assert enrich_calls, "enrich must run when liveness succeeds"


def test_liveness_probe_proceeds_when_only_gateway_alive():
    """Some hardened installs close the dispatcher (SNC-only) but
    leave the gateway open.  Either-port-alive counts as alive — the
    helper falls through to full enrichment so the operator gets a
    diagnostic from the deeper probes."""
    state, _ = _mk_state_with_node("GWONLY", inst_nr="00")
    probed = []
    def _gw_alive(host, port, timeout=2.0, saprouter=""):
        probed.append(port)
        return port == 3300  # only gateway answers
    enrich_fn, enrich_calls = _mk_enrich_mock()
    client_fn, _ = _mk_client_enum_mock([])

    result = landscape_post_import_discover(
        state, "GWONLY",
        enrich_fn=enrich_fn, client_enum_fn=client_fn,
        liveness_fn=_gw_alive)

    assert result["status"] == "ok"
    # Dispatcher probed first (closed), then gateway (open).
    assert probed == [3200, 3300]
    assert enrich_calls, "enrich must run when gateway port is alive"


def test_liveness_probe_passes_saprouter_through():
    """node.saprouter must be threaded into the liveness_fn call so
    the probe tunnels through the SAP NI route — otherwise raw TCP
    probes would always fail for saprouter-tunneled targets and
    silently skip every one of them."""
    state, node = _mk_state_with_node("ROUTED", inst_nr="00")
    node.saprouter = "/H/router.lan/S/3299/H/"
    probed = []
    def _probe(host, port, timeout=2.0, saprouter=""):
        probed.append({"host": host, "port": port,
                        "saprouter": saprouter})
        return True
    enrich_fn, _ = _mk_enrich_mock()
    client_fn, _ = _mk_client_enum_mock([])

    landscape_post_import_discover(
        state, "ROUTED",
        enrich_fn=enrich_fn, client_enum_fn=client_fn,
        liveness_fn=_probe)

    assert probed, "liveness probe must run for saprouter-tunneled nodes"
    assert probed[0]["saprouter"] == "/H/router.lan/S/3299/H/", (
        "node.saprouter must be threaded to liveness_fn so the probe "
        "tunnels through NI route (which _scan_port handles natively)")


def test_liveness_probe_exception_falls_through_to_enrichment():
    """A liveness probe that RAISES (DNS failure, route-string parse
    error, exotic network stack) must not block the enrichment chain
    — treat 'unknown' as 'proceed' so the operator still gets a
    diagnostic from the deeper probes rather than a silent skip."""
    state, _ = _mk_state_with_node("DNS_FAIL", inst_nr="00")
    def _boom(host, port, timeout=2.0, saprouter=""):
        raise OSError("DNS resolution failed")
    enrich_fn, enrich_calls = _mk_enrich_mock({"sysinfo_source": "ok"})
    client_fn, _ = _mk_client_enum_mock([])

    result = landscape_post_import_discover(
        state, "DNS_FAIL",
        enrich_fn=enrich_fn, client_enum_fn=client_fn,
        liveness_fn=_boom)

    assert result["status"] == "ok", (
        "liveness-probe exception must fall through to enrichment, "
        "not skip the node")
    assert enrich_calls, "enrich must still run after liveness probe raises"


def test_liveness_probe_uses_scan_port_by_default():
    """Default liveness_fn must be sapmap_scanner._scan_port so
    operators get the probe for free — not a dedicated per-helper
    socket implementation."""
    import sapmap_scanner
    import inspect
    src = inspect.getsource(landscape_post_import_discover)
    assert "sapmap_scanner._scan_port" in src, (
        "default liveness_fn must be sapmap_scanner._scan_port — it "
        "already handles saprouter-tunnelled probes natively")


def test_parser_defaults_system_type_abap_for_xml_imports():
    """SAP Logon landscape XML describes SAPGUI (ABAP dialog)
    connections — SAPGUI is the ABAP client, not Java.  Parser must
    default system_type='ABAP' on every newly-imported node so
    operators can immediately run ABAP-only tooling (default-cred
    check, pwspray, user creation) before RFC_SYSTEM_INFO enrichment
    completes.  Operator ask 2026-10-09: client enumeration was gated
    on system_type being set, so unknown-type XML imports couldn't
    enumerate clients.
    """
    state = SAPMAPState()
    xml = """<?xml version='1.0' encoding='UTF-8'?>
<Landscape version='1'>
  <Services>
    <Service name='Lab A' type='SAPGUI' uuid='a1'
             server='10.0.0.1:3200'/>
    <Service name='NPL' type='SAPGUI' uuid='b1'
             systemid='NPL' server='10.0.0.2:3200'/>
  </Services>
</Landscape>"""
    summary = parse_landscape_xml_into_state(state, xml,
                                              no_scan_appservers=True)
    for sid in summary["added"]:
        node = state.get_node(sid)
        assert node.system_type == "ABAP", (
            f"XML-imported node {sid} must default system_type=ABAP "
            f"(SAP Logon = SAPGUI = ABAP dialog); got "
            f"{node.system_type!r}")


def test_discover_overrides_abap_default_to_java_when_detected():
    """When enrich_system_info returns _is_java=True (SAPControl
    detected a JAVA stack), the discover helper must override the
    parser's ABAP default — same convention as the per-node
    rfc_system_info route."""
    state, node = _mk_state_with_node("JVNODE", inst_nr="00")
    node.system_type = "ABAP"  # parser's default
    enrich_fn, _ = _mk_enrich_mock({"_is_java": True})
    client_fn, _ = _mk_client_enum_mock([])

    result = landscape_post_import_discover(
        state, "JVNODE", enrich_fn=enrich_fn,
        client_enum_fn=client_fn)

    assert result["system_type"] == "JAVA"
    assert node.system_type == "JAVA", (
        "enrichment must override parser's ABAP default when "
        "SAPControl reports JAVA")


def test_discover_overrides_to_dual_stack_when_abap_and_java_both_detected():
    """When SAPControl reports BOTH stacks (dual-stack 7.0x systems),
    override to ABAP+JAVA."""
    state, node = _mk_state_with_node("DUAL", inst_nr="00")
    node.system_type = "ABAP"
    enrich_fn, _ = _mk_enrich_mock(
        {"_is_abap": True, "_is_java": True})
    client_fn, _ = _mk_client_enum_mock([])

    landscape_post_import_discover(
        state, "DUAL", enrich_fn=enrich_fn,
        client_enum_fn=client_fn)

    assert node.system_type == "ABAP+JAVA"


def test_discover_leaves_abap_default_when_enrich_returns_neither_flag():
    """When enrichment doesn't carry a stack-detection result (common
    when SAPControl is firewalled), leave the parser's ABAP default
    intact — don't accidentally blank it to '' on partial enrich."""
    state, node = _mk_state_with_node("UNKFL", inst_nr="00")
    node.system_type = "ABAP"
    enrich_fn, _ = _mk_enrich_mock(
        {"hostname": "srv01unk", "sysinfo_source": "legacy_leak"})
    client_fn, _ = _mk_client_enum_mock([])

    landscape_post_import_discover(
        state, "UNKFL", enrich_fn=enrich_fn,
        client_enum_fn=client_fn)

    assert node.system_type == "ABAP", (
        "system_type must stay ABAP when enrich returns neither "
        "_is_abap nor _is_java — don't blank the parser's default")


def test_liveness_probe_respects_timeout_parameter():
    """liveness_timeout must flow through to the liveness_fn call so
    operators / tests can tune the dead-host short-circuit speed."""
    state, _ = _mk_state_with_node("TIMED", inst_nr="00")
    seen_timeouts = []
    def _probe(host, port, timeout=2.0, saprouter=""):
        seen_timeouts.append(timeout)
        return True
    landscape_post_import_discover(
        state, "TIMED",
        enrich_fn=_mk_enrich_mock()[0],
        client_enum_fn=_mk_client_enum_mock([])[0],
        liveness_fn=_probe,
        liveness_timeout=5.5)
    assert 5.5 in seen_timeouts, (
        f"liveness_timeout must thread through to liveness_fn; "
        f"saw {seen_timeouts}")
