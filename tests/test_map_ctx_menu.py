#!/usr/bin/env python3
"""Tests for the empty-map right-click context menu.

Locks the per-vulnerability "Check All XX" menu entries:

  * Each entry has an `id` attribute used by showMapCtxMenu to
    gate visibility on the presence of eligible target nodes.
    Without this, the operator sees no-op entries that would
    iterate zero candidates.

  * Each entry's click handler maps to a JS function that
    eventually fires the matching backend endpoint.

  * Each backend endpoint exists.

Operator scenario: open SAPMAP, scan a landscape with only ABAP
nodes (no Java).  The "Check All CVE-2025-31324" entry must not
appear in the right-click menu — there's nothing to scan against.
Same for CVE-2020-6287, ICMAD, etc.

These tests guard against future refactors silently dropping a
menu entry, gating signal, click-handler case, or backend
endpoint.
"""
from __future__ import annotations

import re

import pytest


def _html():
    import sapmap_html
    return sapmap_html.get_html()


# ===========================================================================
# Menu entries present in HTML + each has a stable id for gating
# ===========================================================================

@pytest.mark.parametrize("entry_id,entry_label_fragment", [
    ("map-ctx-check-all-gw",          "GW Vulnerabilities"),
    ("map-ctx-check-all-betrusted",   "10KBlaze"),
    ("map-ctx-check-all-cve-31324",   "CVE-2025-31324"),
    ("map-ctx-check-all-cve-6287",    "CVE-2020-6287"),
    ("map-ctx-check-all-cve-22536",   "CVE-2022-22536"),
    ("map-ctx-check-all-router-info", "SAProuter Info Leak"),
])
def test_check_all_entry_present_with_stable_id(entry_id, entry_label_fragment):
    """Every Check All XX entry needs a stable id so the JS gating
    code can show/hide it based on whether the map has eligible
    nodes.  Label fragment must be present so the operator can
    visually find the entry."""
    html = _html()
    assert f'id="{entry_id}"' in html, (
        f"Missing id={entry_id!r} on a Check All menu entry; "
        f"gating wiring will silently break")
    assert entry_label_fragment in html, (
        f"Missing label fragment {entry_label_fragment!r} on the "
        f"corresponding Check All menu entry")


# ===========================================================================
# Per-entry gating logic references the right "hasAny" signal
# ===========================================================================

@pytest.mark.parametrize("entry_id,gate_var", [
    ("map-ctx-check-all-gw",          "hasAnyGwPort"),
    ("map-ctx-check-all-betrusted",   "hasAnyMsPort"),
    ("map-ctx-check-all-cve-31324",   "hasAnyJava"),
    ("map-ctx-check-all-cve-6287",    "hasAnyJava"),
    ("map-ctx-check-all-cve-22536",   "hasAnyHttp"),
    ("map-ctx-check-all-router-info", "hasAnySaprouter"),
])
def test_entry_gating_uses_correct_signal(entry_id, gate_var):
    """showMapCtxMenu must compute each per-vuln eligibility signal
    AND apply it to the matching entry's style.display.  Without
    the matching `<id>.style.display = <gate_var> ? '' : 'none'`
    line, the entry is always visible (operator can trigger a
    no-op scan).
    """
    html = _html()
    # The gating signal must be computed in showMapCtxMenu.
    assert f"const {gate_var}" in html, (
        f"Gating variable `const {gate_var} = ...` not computed "
        f"in showMapCtxMenu; entry {entry_id} would have no live "
        f"gating signal")
    # And the variable must be applied to the entry's display style.
    pattern = re.compile(
        re.escape(f"document.getElementById('{entry_id}').style.display")
        + r".*?"
        + re.escape(gate_var),
        re.DOTALL)
    assert pattern.search(html), (
        f"Entry {entry_id!r} not gated by signal {gate_var!r}; "
        f"the style.display assignment is missing or wired to "
        f"a different variable")


# ===========================================================================
# Click handler routes each data-action to the JS function
# ===========================================================================

@pytest.mark.parametrize("action,js_fn", [
    ("map_check_all_gw",          "checkAllGateways"),
    ("map_check_all_betrusted",   "checkAllBetrusted"),
    ("map_check_all_cve_31324",   "checkAllCve31324"),
    ("map_check_all_cve_6287",    "checkAllCve6287"),
    ("map_check_all_cve_22536",   "checkAllCve22536"),
    ("map_check_all_router_info", "checkAllRouterInfo"),
])
def test_action_routes_to_js_function(action, js_fn):
    """The map-ctx-menu's click handler must have a `case 'X': fn()`
    line for each data-action; without it, clicking the menu
    entry silently no-ops."""
    html = _html()
    # case in the switch
    case_pattern = f"case '{action}':"
    assert case_pattern in html, (
        f"No `{case_pattern}` in map-ctx-menu click handler")
    # function definition exists
    assert f"async function {js_fn}(" in html or f"function {js_fn}(" in html, (
        f"JS function `{js_fn}` not defined; the click handler "
        f"would throw ReferenceError when the operator clicks "
        f"the menu entry")


# ===========================================================================
# Each JS function fires the matching backend endpoint
# ===========================================================================

@pytest.mark.parametrize("js_fn,endpoint", [
    ("checkAllGateways",    "actions/check_all_gw"),
    ("checkAllBetrusted",   "actions/check_all_betrusted"),
    ("checkAllCve31324",    "actions/check_all_cve_31324"),
    ("checkAllCve6287",     "actions/check_all_cve_6287"),
    ("checkAllCve22536",    "actions/check_all_cve_22536"),
    ("checkAllRouterInfo",  "actions/check_all_router_info"),
])
def test_js_function_calls_correct_backend_endpoint(js_fn, endpoint):
    """Lock the JS → backend mapping so a refactor that renames an
    endpoint also notices the JS side needs to update."""
    html = _html()
    # Find the function body and verify the endpoint is referenced
    # within it (within ~1500 chars of the def — these functions
    # are short).
    fn_match = re.search(
        rf"function\s+{re.escape(js_fn)}\s*\(",
        html)
    assert fn_match, f"JS function {js_fn} not found"
    body = html[fn_match.start(): fn_match.start() + 1500]
    assert endpoint in body, (
        f"JS function {js_fn} does not reference "
        f"endpoint {endpoint!r}; the click would fire the wrong "
        f"backend or 404")


# ===========================================================================
# Backend endpoints exist
# ===========================================================================

# ===========================================================================
# Regression: 10KBlaze gating reads port list, NOT just ms_port
# ===========================================================================

def test_router_info_gating_targets_saprouter_nodes_not_sap_nodes():
    """Critical attribution fix: the SAProuter Info Leak sweep
    must iterate SAProuter nodes (which actually listen on the
    router port + can respond to ROUTER_ADM info requests), NOT
    non-SAProuter SAP nodes.

    Operator-reported regression: on a landscape where multiple
    SAP systems share a host with the SAProuter (S4D, S4H, RD1
    all on 192.168.2.209), the previous sweep iterated S4D and
    S4H, probed each on :3299, HIT the actual SAProuter (RD1)
    every time, and attributed the HIGH finding to S4D / S4H -
    coloring them red while RD1 (the real culprit) stayed green.

    The gating signal name (hasAnySaprouter) AND the eligibility
    test (system_type SAPROUTER or 'saprouter'-tagged port) must
    both be SAProuter-positive, not SAP-positive."""
    import sapmap_html
    html = sapmap_html.get_html()
    # The signal name itself must be the positive form so future
    # operators reading the code don't double-take.
    assert "hasAnySaprouter" in html, (
        "hasAnySaprouter gating signal not found - the SAProuter "
        "Info Leak sweep would iterate the wrong nodes")
    assert "hasAnyNonSaprouter" not in html, (
        "Old hasAnyNonSaprouter signal still present - this was "
        "the regression that mis-attributed findings on shared-"
        "host landscapes")
    # The gating expression must look for SAProuter membership
    # positively, not negatively.
    import re
    pat = re.compile(
        r"const\s+hasAnySaprouter\s*=\s*nodes\.some\(",
        re.DOTALL)
    assert pat.search(html), (
        "hasAnySaprouter must be defined via nodes.some(...) "
        "to check at least one SAProuter is on the map")


def test_betrusted_gating_reads_instance_ports_not_just_ms_port():
    """Critical chicken-and-egg fix: the 10KBlaze entry's gating
    must inspect the instance.ports dict for 39XX, NOT rely on
    n.ms_port being already populated.

    Why this matters: n.ms_port only gets set AFTER the MS
    betrusted check has run against a node and confirmed the
    port answers.  Gating the menu on n.ms_port means the menu
    HIDES the check that would populate ms_port - operator
    can never run the sweep on a freshly-scanned landscape.

    Operator-reported regression on S4H: node had port 3901
    in n.instances[0].ports (discovered by standard scan), but
    "Check All 10KBlaze" was hidden from the empty-map context
    menu because n.ms_port was still 0.

    The fix mirrors the GW gating pattern: walk instance.ports
    looking for 3900-3999 OR the explicit 'ms_internal'
    service tag.  Either signal counts as "this node could
    be 10KBlaze-vulnerable, show the sweep option"."""
    import sapmap_html
    html = sapmap_html.get_html()
    # The hasAnyMsPort definition must walk n.instances[].ports
    # rather than checking n.ms_port directly.
    import re
    pat = re.compile(
        r"const\s+hasAnyMsPort\s*=\s*nodes\.some\([^;]*\)",
        re.DOTALL)
    m = pat.search(html)
    assert m, "hasAnyMsPort definition not found in showMapCtxMenu"
    body = m.group(0)
    # Must inspect instances + ports - not just n.ms_port.
    assert "instances" in body, (
        f"hasAnyMsPort must walk n.instances[].ports to find 39XX "
        f"ports - relying on n.ms_port alone is the chicken-and-"
        f"egg bug.  Definition: {body!r}")
    assert "ports" in body, (
        f"hasAnyMsPort must inspect instance.ports dict; "
        f"definition: {body!r}")
    # Must recognise the 39XX port range.
    assert "3900" in body and "3999" in body, (
        f"hasAnyMsPort must match port range 3900-3999; "
        f"definition: {body!r}")


@pytest.mark.parametrize("endpoint_path", [
    "/api/actions/check_all_gw",
    "/api/actions/check_all_betrusted",
    "/api/actions/check_all_cve_31324",
    "/api/actions/check_all_cve_6287",
    "/api/actions/check_all_cve_22536",
    "/api/actions/check_all_router_info",
])
def test_backend_endpoint_exists(endpoint_path):
    """Each Check-All endpoint must be wired in create_app.
    Without this, the JS function fires a POST that 404s and the
    operator sees no progress."""
    with open(
            "modules/core/sapmap_gui.py",
            encoding="utf-8") as f:
        gui_source = f.read()
    route_decorator = f'@app.route("{endpoint_path}", method="POST")'
    assert route_decorator in gui_source, (
        f"Backend route for {endpoint_path} not found in "
        f"modules/core/sapmap_gui.py")
