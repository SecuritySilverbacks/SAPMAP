"""Tests for issue #93 — reclassifying a node to WEB_DISPATCHER must
trigger the WD topology rediscovery.

Root cause: `node_set_type` set `system_type` + `is_web_dispatcher` but
never spawned the WD rediscovery (the working logic lived only in the
separate `node_wd_rediscover` route), and that route bails when the node
has no `wd_`-labelled port — which a misclassified ABAP/SAPROUTER node
never has.

Two test layers (the route closures live inside create_app's scope and
can't be reached directly — see tests/test_mint_btp_token_via_cert_route
for the same constraint):
  * PURE HELPERS — _icm_ports_from_instance_nr + _resolve_wd_probe_port
    called directly on hand-built SAPNode/InstanceInfo.
  * SOURCE PINS — assertions against the served py/HTML that the trigger
    is wired (node_set_type → _run_wd_rediscovery via _bg) and the modal
    sends the WD port fields.

Live verification (real cache/backend discovery needs a real WD) is
documented in the plan, not unit-tested here.
"""
from __future__ import annotations

import inspect

import pytest

import modules  # noqa: F401 — registers package paths

from sapmap_models import SAPNode, InstanceInfo
import sapmap_gui


def _node(sid="WD", ip="10.0.0.1", instances=None):
    n = SAPNode(sid=sid, ip=ip, hostname="h")
    n.instances = instances if instances is not None else []
    return n


def _inst(instance_nr="00", ports=None, ip="10.0.0.1"):
    return InstanceInfo(instance_nr=instance_nr, ip=ip,
                        ports=dict(ports or {}))


# ===========================================================================
# _icm_ports_from_instance_nr
# ===========================================================================

@pytest.mark.parametrize("nr,expected", [
    ("90", (8090, 44390)),
    ("00", (8000, 44300)),
    ("01", (8001, 44301)),
    ("", (0, 0)),
    ("XX", (0, 0)),
    (None, (0, 0)),
    ("100", (0, 0)),       # out of 00..99 range
])
def test_icm_ports_from_instance_nr(nr, expected):
    assert sapmap_gui._icm_ports_from_instance_nr(nr) == expected


# ===========================================================================
# _resolve_wd_probe_port — resolution order
# ===========================================================================

def test_resolve_existing_wd_port_used_as_is():
    """(a) An existing wd_https port is authoritative — use it, no
    mutation."""
    node = _node(instances=[_inst("00", {8000: "wd_https"})])
    res = sapmap_gui._resolve_wd_probe_port(node, {})
    assert res["source"] == "existing_wd"
    assert res["wd_port"] == 8000
    assert res["wd_https"] is True
    # Unchanged.
    assert node.instances[0].ports[8000] == "wd_https"


def test_resolve_existing_wd_http_port_is_not_https():
    """(a) An existing wd_http port must probe over PLAIN HTTP — wd_https
    False.  Guards the `wd_https=(low == "wd_https")` computation against
    regressing to a hard-coded True, which would probe an HTTP-only Web
    Dispatcher over TLS and make the rediscovery silently return nothing
    (issue #93's own failure mode).  The https-port case alone can't
    catch that — both values must be asserted."""
    node = _node(instances=[_inst("00", {8000: "wd_http"})])
    res = sapmap_gui._resolve_wd_probe_port(node, {})
    assert res["source"] == "existing_wd"
    assert res["wd_port"] == 8000
    assert res["wd_https"] is False
    # Unchanged.
    assert node.instances[0].ports[8000] == "wd_http"


def test_resolve_relabels_icm_http_to_wd_http():
    """(b) An icm_http port is relabelled to wd_http — the operator has
    declared this is a WD, overriding the scanner's fingerprint."""
    node = _node(instances=[_inst("00", {8000: "icm_http"})])
    res = sapmap_gui._resolve_wd_probe_port(node, {})
    assert res["source"] == "relabel_icm"
    assert res["wd_port"] == 8000
    assert res["wd_https"] is False
    assert node.instances[0].ports[8000] == "wd_http"


def test_resolve_relabels_icm_https_to_wd_https():
    node = _node(instances=[_inst("00", {44300: "icm_https"})])
    res = sapmap_gui._resolve_wd_probe_port(node, {})
    assert res["source"] == "relabel_icm"
    assert res["wd_port"] == 44300
    assert res["wd_https"] is True
    assert node.instances[0].ports[44300] == "wd_https"


def test_resolve_relabels_wd_candidate():
    node = _node(instances=[_inst("80", {8080: "wd_candidate"})])
    res = sapmap_gui._resolve_wd_probe_port(node, {})
    assert res["source"] == "relabel_icm"
    assert res["wd_port"] == 8080
    assert node.instances[0].ports[8080] == "wd_http"


def test_resolve_existing_wd_wins_over_icm():
    """Resolution order: an existing wd_ port is used before any icm_
    relabel."""
    node = _node(instances=[_inst("00", {8000: "icm_http",
                                         44300: "wd_https"})])
    res = sapmap_gui._resolve_wd_probe_port(node, {})
    assert res["source"] == "existing_wd"
    assert res["wd_port"] == 44300
    # icm_http left untouched.
    assert node.instances[0].ports[8000] == "icm_http"


def test_resolve_adds_operator_supplied_ports_prefers_https():
    """(c) No icm/wd port; operator supplies both — add both, probe the
    HTTPS one, place on the instance whose nr derives to the port."""
    node = _node(instances=[_inst("90", {3200: "dispatcher"})])
    res = sapmap_gui._resolve_wd_probe_port(
        node, {"wd_http_port": 8090, "wd_https_port": 44390})
    assert res["source"] == "added_supplied"
    assert res["wd_port"] == 44390       # HTTPS preferred as probe
    assert res["wd_https"] is True
    ports = node.instances[0].ports
    assert ports[8090] == "wd_http"
    assert ports[44390] == "wd_https"


def test_resolve_adds_http_only_when_no_https_supplied():
    node = _node(instances=[_inst("90", {3200: "dispatcher"})])
    res = sapmap_gui._resolve_wd_probe_port(node, {"wd_http_port": 8090})
    assert res["source"] == "added_supplied"
    assert res["wd_port"] == 8090
    assert res["wd_https"] is False
    assert node.instances[0].ports[8090] == "wd_http"


def test_resolve_supplied_port_creates_instance_when_node_has_none():
    """(c) with no instances at all — a new InstanceInfo is appended
    carrying the supplied port, instance_nr derived from the port."""
    node = _node(instances=[])
    res = sapmap_gui._resolve_wd_probe_port(node, {"wd_http_port": 8090})
    assert res["source"] == "added_supplied"
    assert res["wd_port"] == 8090
    assert len(node.instances) == 1
    assert node.instances[0].ports[8090] == "wd_http"
    assert node.instances[0].instance_nr == "90"


def test_resolve_none_when_no_port_and_dispatcher_only():
    """(d) A node misclassified as ABAP (dispatcher only) with no
    supplied port → source='none', error='no_wd_port', ports
    untouched."""
    node = _node(instances=[_inst("00", {3200: "dispatcher",
                                         3300: "gateway"})])
    res = sapmap_gui._resolve_wd_probe_port(node, {})
    assert res["source"] == "none"
    assert res["error"] == "no_wd_port"
    assert node.instances[0].ports == {3200: "dispatcher",
                                       3300: "gateway"}


def test_resolve_none_when_saprouter_only():
    node = _node(instances=[_inst("99", {3299: "saprouter"})])
    res = sapmap_gui._resolve_wd_probe_port(node, {})
    assert res["source"] == "none"


def test_resolve_idempotent_second_call_takes_existing_wd():
    """After the first call relabels icm_→wd_, a second call takes the
    (a) existing-wd branch — no double mutation, stable verdict."""
    node = _node(instances=[_inst("00", {8000: "icm_http"})])
    r1 = sapmap_gui._resolve_wd_probe_port(node, {})
    assert r1["source"] == "relabel_icm"
    r2 = sapmap_gui._resolve_wd_probe_port(node, {})
    assert r2["source"] == "existing_wd"
    assert r2["wd_port"] == 8000
    assert r2["wd_https"] is False      # relabelled from icm_http -> wd_http
    assert node.instances[0].ports[8000] == "wd_http"


# ===========================================================================
# Source pins — trigger wiring + DRY extraction + modal
# ===========================================================================

def _gui_src():
    return inspect.getsource(sapmap_gui)


def test_shared_rediscovery_helper_exists():
    src = _gui_src()
    assert "def _run_wd_rediscovery(node, state, wd_port" in src, (
        "shared WD rediscovery helper must exist at module scope")


def test_node_set_type_triggers_rediscovery():
    """node_set_type must resolve a WD port + spawn the rediscovery via
    _bg when WEB_DISPATCHER is picked, and signal need_wd_port when no
    port is resolvable."""
    src = _gui_src()
    m = __import__("re").search(
        r"def node_set_type\(sid\):.*?(?=\n    @app\.route|\n    def )",
        src, __import__("re").DOTALL)
    assert m, "node_set_type route body not found"
    body = m.group(0)
    assert "_resolve_wd_probe_port(node, data)" in body
    assert "_run_wd_rediscovery(" in body
    assert "_bg(f\"{sid}:wd_rediscover\"" in body
    assert "need_wd_port" in body
    assert '"wd_rediscover": True' in body


def test_node_wd_rediscover_delegates_to_shared_helper():
    """The original route must now DELEGATE to _run_wd_rediscovery, not
    inline the cache/backends sequence (DRY — both entry points run the
    same discovery)."""
    src = _gui_src()
    import re
    m = re.search(
        r"def node_wd_rediscover\(sid\):.*?(?=\n    @app\.route|\n    def )",
        src, re.DOTALL)
    assert m, "node_wd_rediscover route body not found"
    body = m.group(0)
    assert "_run_wd_rediscovery(node, api.state, wd_port, wd_https)" in body
    # The cache/backends calls must NOT be inlined here any more.
    assert "detect_wd_cache(" not in body, (
        "cache/backends sequence must live in the shared helper, not be "
        "duplicated in the route")
    assert "discover_wd_backends(" not in body


def test_modal_has_wd_port_fields_and_sends_them():
    import sapmap_html
    html = sapmap_html.get_html()
    # Fields present + toggled only for WEB_DISPATCHER.
    assert 'id="type-wd-http"' in html
    assert 'id="type-wd-https"' in html
    assert "_toggleWdPortFields" in html
    assert "onchange=\"_toggleWdPortFields()\"" in html
    # saveSystemType sends the ports + shows the started toast.
    assert "body.wd_http_port" in html
    assert "body.wd_https_port" in html
    assert "WD topology rediscovery started" in html
    assert "need_wd_port" in html
