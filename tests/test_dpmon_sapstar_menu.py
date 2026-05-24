#!/usr/bin/env python3
"""Tests for the right-click "Create User (dpmon SAP*)" menu entry.

Lets the operator test the dpmon Phase-2 exploit path on a single
node without launching the full AutoPwn loop.  The entry is gated
on GW vulnerability + ABAP stack + kernel >= 790 (via the
dpmon_sap_star_available flag set by the scanner).
"""
from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "core"))


def _html():
    import sapmap_html
    return sapmap_html.get_html()


def _gui_src():
    path = os.path.join(os.path.dirname(__file__), "..", "modules",
                         "core", "sapmap_gui.py")
    with open(path, encoding="utf-8") as f:
        return f.read()


def test_menu_entry_present():
    """A right-click menu entry with action 'create_user_dpmon_sapstar'
    must exist so the operator can fire the Phase-2 dpmon exploit
    on a single node."""
    html = _html()
    assert 'data-action="create_user_dpmon_sapstar"' in html, (
        "Right-click menu must include the dpmon-SAP* exploit entry")
    # Label text should mention the kernel gate
    idx = html.find('data-action="create_user_dpmon_sapstar"')
    window = html[idx:idx + 200]
    assert "dpmon" in window.lower()
    assert "790" in window, (
        "Menu label should call out the kernel ≥ 790 prerequisite")


def test_menu_entry_gated_on_gw_abap_kernel():
    """The menu visibility filter for 'create_user_dpmon_sapstar'
    must require GW vuln + ABAP stack + dpmon_sap_star_available."""
    html = _html()
    # Look for the visibility-filter row
    m = re.search(
        r"'create_user_dpmon_sapstar':\s*([^,\n]+)",
        html)
    assert m, "Visibility filter for create_user_dpmon_sapstar not found"
    expr = m.group(1)
    assert "hasGwVuln" in expr, (
        "Menu must require GW vulnerability — that's the OS-exec channel")
    assert "isAbapStack" in expr, (
        "Menu must require ABAP stack")
    assert "dpmon_sap_star_available" in expr, (
        "Menu must check the scanner-set kernel/stack eligibility flag")


def test_click_handler_validates_abap_and_kernel():
    """The JS click handler must do client-side pre-flight checks
    so the operator gets a friendly alert instead of a backend
    error when invoking on an ineligible node."""
    html = _html()
    m = re.search(
        r"case 'create_user_dpmon_sapstar':[\s\S]*?case '[^']+':",
        html)
    assert m, "Click handler for create_user_dpmon_sapstar not found"
    handler = m.group(0)
    assert "ABAP" in handler, "Handler must validate ABAP stack"
    assert "790" in handler, "Handler must validate kernel >= 790"
    # POST should fire create_user with method=dpmon_sap_star
    assert "method: 'dpmon_sap_star'" in handler
    assert "node/${sid}/create_user" in handler


def test_click_handler_surfaces_audit_log_warning():
    """Operator must be warned BEFORE firing — dpmon SAP*
    activation creates an EUP audit-log entry (not stealthy)."""
    html = _html()
    m = re.search(
        r"case 'create_user_dpmon_sapstar':[\s\S]*?case '[^']+':",
        html)
    assert m
    handler = m.group(0)
    assert "EUP" in handler or "audit" in handler.lower(), (
        "Click handler must call out the EUP audit log entry "
        "before firing, so operator can opt out on stealth-sensitive "
        "engagements")


def test_backend_endpoint_routes_dpmon_method():
    """The /api/node/<sid>/create_user endpoint must accept
    method='dpmon_sap_star' and dispatch to
    create_user_via_dpmon_sap_star."""
    src = _gui_src()
    # Find the create_user endpoint body — extends to the next
    # @app.route or end of function.
    m = re.search(
        r'@app\.route\("/api/node/<sid>/create_user",\s*method="POST"\)'
        r'[\s\S]*?(?=@app\.route\()',
        src)
    assert m, "create_user endpoint not found"
    endpoint = m.group(0)
    assert 'method == "dpmon_sap_star"' in endpoint, (
        "Endpoint must branch on method=='dpmon_sap_star'")
    assert "create_user_via_dpmon_sap_star" in endpoint, (
        "Endpoint must dispatch to create_user_via_dpmon_sap_star")
