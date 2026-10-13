"""Tests for issue #135 — don't record a phantom gateway port.

Importing a landscape XML (or manually adding a system) used to stamp an
app-server node with BOTH a dispatcher 32XX and a gateway 33XX port
unconditionally.  That's wrong for SNC-only systems: plain 33XX is closed
(the gateway listens on the SNC port 48XX), so the node showed a false
gateway and the front-end enabled GW actions that can't work.

`_resolve_gateway_port` probes the gateway and returns the real, reachable
one (33XX confirmed via CPIC -> "gateway"; else 48XX TCP-open ->
"gateway_snc"; else nothing), mirroring the scanner's Pass-2 split.  Both
the XML-import sweep and the manual-add _enrich route through it.

Pure-helper tests (inject the probe fns) + source pins for the two
operator node-creation paths (route closures can't be called directly —
same constraint as tests/test_manual_wd_discovery.py).
"""
from __future__ import annotations

import inspect
import re

import pytest

import modules  # noqa: F401 — registers package paths

import sapmap_gui
from sapmap_models import SAPNode


# ===========================================================================
# _resolve_gateway_port — pure helper
# ===========================================================================

def _true(*a, **k):
    return True


def _false(*a, **k):
    return False


def test_resolve_plain_gateway_confirmed():
    assert sapmap_gui._resolve_gateway_port(
        "h", 0, gw_verify_fn=_true, snc_probe_fn=_false) == (3300, "gateway")
    assert sapmap_gui._resolve_gateway_port(
        "h", 42, gw_verify_fn=_true, snc_probe_fn=_false) == (3342, "gateway")


def test_resolve_falls_back_to_snc_gateway_when_33_closed():
    """SNC-only system: plain 33XX not a gateway (CPIC fails / closed), but
    the SNC port 48XX is open -> gateway_snc."""
    assert sapmap_gui._resolve_gateway_port(
        "h", 11, gw_verify_fn=_false, snc_probe_fn=_true) == (4811, "gateway_snc")


def test_resolve_none_when_neither_answers():
    """No reachable gateway -> no phantom port (the issue's core)."""
    assert sapmap_gui._resolve_gateway_port(
        "h", 11, gw_verify_fn=_false, snc_probe_fn=_false) == (0, "")


def test_resolve_prefers_plain_over_snc():
    """When BOTH answer, the confirmed plain gateway wins (33XX)."""
    assert sapmap_gui._resolve_gateway_port(
        "h", 5, gw_verify_fn=_true, snc_probe_fn=_true) == (3305, "gateway")


@pytest.mark.parametrize("bad", ["XX", "", None, -1, 100, 999])
def test_resolve_bad_instance_nr(bad):
    assert sapmap_gui._resolve_gateway_port(
        "h", bad, gw_verify_fn=_true, snc_probe_fn=_true) == (0, "")


def test_resolve_accepts_string_instance_nr():
    assert sapmap_gui._resolve_gateway_port(
        "h", "07", gw_verify_fn=_true, snc_probe_fn=_false) == (3307, "gateway")


def test_resolve_passes_host_port_timeout_saprouter():
    seen = {}
    def vf(host, port, timeout=None, saprouter=None):
        seen["gw"] = (host, port, timeout, saprouter)
        return False
    def sf(host, port, timeout=None, saprouter=None):
        seen["snc"] = (host, port, timeout, saprouter)
        return False
    sapmap_gui._resolve_gateway_port(
        "H1", 42, saprouter="ROUTE", timeout=5, gw_verify_fn=vf, snc_probe_fn=sf)
    assert seen["gw"] == ("H1", 3342, 5, "ROUTE")
    assert seen["snc"] == ("H1", 4842, 5, "ROUTE")


def test_resolve_swallows_probe_exceptions():
    """A probe that raises must not crash — fall through to the next / none."""
    def boom(*a, **k):
        raise OSError("network down")
    assert sapmap_gui._resolve_gateway_port(
        "h", 11, gw_verify_fn=boom, snc_probe_fn=boom) == (0, "")
    # plain raises, SNC open -> still finds SNC
    assert sapmap_gui._resolve_gateway_port(
        "h", 11, gw_verify_fn=boom, snc_probe_fn=_true) == (4811, "gateway_snc")


# ===========================================================================
# Source pins — the two operator node-creation paths no longer assume 33XX
# ===========================================================================

def _src():
    return inspect.getsource(sapmap_gui)


def _route_body(name):
    """Extract a route closure's body from create_app so a source-pin is
    SCOPED to that function — not the whole module (which would make a
    bare '_resolve_gateway_port(' match the module-level def and be
    vacuous).  Same pattern as tests/test_manual_wd_discovery.py."""
    m = re.search(rf"def {name}\([^)]*\):.*?(?=\n    @app\.route|\n    def )",
                  _src(), re.DOTALL)
    assert m, f"{name} route body not found"
    return m.group(0)


def test_import_fanout_creates_dispatcher_only():
    src = _src()
    assert 'ports={3200 + nn: "dispatcher"}' in src
    # the old unconditional pair must be gone from the fan-out
    assert 'ports={3200 + nn: "dispatcher", 3300 + nn: "gateway"}' not in src


def test_node_add_creates_dispatcher_only_and_resolves_gateway():
    """SCOPED to the node_add route body, so these fail if the gateway
    probe/record block is removed (the previous module-wide
    '_resolve_gateway_port(' pin was vacuous — it matched the def line)."""
    body = _route_body("node_add")
    assert 'int(f"32{nr}"): "dispatcher",' in body
    # no hard-coded 33NN gateway in the ports dict any more
    assert 'int(f"33{nr}"): "gateway",' not in body
    # the _enrich closure must CALL the resolver AND RECORD its result
    assert "_resolve_gateway_port(" in body, (
        "node_add must call the gateway resolver")
    assert ".setdefault(_gp, _gl)" in body, (
        "node_add must record the resolved gateway on the instance")


def test_sweep_records_resolved_gateway():
    src = _src()
    # XML post-import sweep records the resolved gateway (specific tokens,
    # not vacuous: the call site + the record)
    assert "gateway_resolve_fn(" in src
    assert "picked.ports.setdefault(gport, glabel)" in src


# ===========================================================================
# _import_appserver_instances — the MS fan-out now creates dispatcher only
# ===========================================================================

def test_import_appserver_instances_creates_dispatcher_only(monkeypatch):
    """The MS fan-out must append an instance with ONLY the dispatcher
    port (32NN) — no speculative 33NN gateway (issue #135).  The gateway
    is probed + recorded later by the post-import sweep."""
    import sap_ms_serverlist
    monkeypatch.setattr(sap_ms_serverlist, "query_app_servers",
                        lambda ms_host, port=0: {
                            "success": True,
                            "servers": [
                                {"name": "srv_NPL_11", "host": "srv1",
                                 "ip": "10.0.0.5", "wp_types": ["DIA"]},
                                {"name": "srv_NPL_12", "host": "srv2",
                                 "ip": "10.0.0.6", "wp_types": ["BTC"]},  # no DIA → skipped
                            ],
                        })
    node = SAPNode(sid="NPL", ip="10.0.0.1", hostname="ms.example.com")
    node.instances = []
    n = sapmap_gui._import_appserver_instances(node, "ms.example.com", 3600)
    assert n == 1, "only the DIA app server should be imported"
    assert len(node.instances) == 1
    ports = node.instances[0].ports
    assert ports == {3211: "dispatcher"}, (
        f"fan-out must create dispatcher-only (no phantom 3311 gateway); "
        f"got {ports}")
    assert 3311 not in ports


def test_import_appserver_instances_skips_on_query_failure(monkeypatch):
    import sap_ms_serverlist
    monkeypatch.setattr(sap_ms_serverlist, "query_app_servers",
                        lambda ms_host, port=0: {"success": False,
                                                 "error": "no reply"})
    node = SAPNode(sid="NPL", ip="10.0.0.1", hostname="h")
    node.instances = []
    assert sapmap_gui._import_appserver_instances(node, "h", 3600) == 0
    assert node.instances == []
