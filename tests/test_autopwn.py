#!/usr/bin/env python3
"""Tests for the AutoPwn orchestration feature.

Validates:
  * AutoPwn config modal is present in the HTML with all controls
  * AutoPwn progress modal is present with phase tracker, stats, log
  * JS functions (showAutoPwnModal, launchAutoPwn, stopAutoPwn) exist
  * Backend endpoints (/api/actions/autopwn, /api/actions/autopwn/status)
  * Map context menu has the AutoPwn entry + click handler wiring
  * Actions menu has the AutoPwn entry
  * Phase tracker has all 6 phases
  * sapmap_autopwn module structure: AutoPwnConfig, autopwn_run, get_status
  * Phase functions exist and accept correct signatures
  * ICMAD and SAProuter Info Leak are in detection_pass, NOT in the
    convergence loop (phase1_scan)
"""
from __future__ import annotations

import re
import sys
import os

import pytest

# Ensure modules are importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules", "core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules", "exploitation"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules", "discovery"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules", "data_extraction"))


def _html():
    import sapmap_html
    return sapmap_html.get_html()


def _gui_src():
    with open("modules/core/sapmap_gui.py", encoding="utf-8") as f:
        return f.read()


def _autopwn_src():
    with open("modules/exploitation/sapmap_autopwn.py", encoding="utf-8") as f:
        return f.read()


# ===========================================================================
# HTML — Config modal
# ===========================================================================

def test_autopwn_config_modal_exists():
    """The AutoPwn config modal must be present in the HTML."""
    html = _html()
    assert 'id="autopwn-config-modal"' in html


@pytest.mark.parametrize("checkbox_id,label_fragment", [
    ("apwn-scan-gw",      "Gateway SAPXPG"),
    ("apwn-scan-10k",     "10KBlaze"),
    ("apwn-scan-31324",   "CVE-2025-31324"),
    ("apwn-scan-recon",   "CVE-2020-6287"),
    ("apwn-det-icmad",    "CVE-2022-22536"),
    ("apwn-det-router",   "SAProuter Info Leak"),
    ("apwn-lpe",          "Privilege Escalation"),
    ("apwn-btp",          "BTP"),
])
def test_autopwn_config_checkboxes(checkbox_id, label_fragment):
    """Each vulnerability/option toggle must have a checkbox with
    stable id and a visible label so the operator knows what they
    are enabling/disabling."""
    html = _html()
    assert f'id="{checkbox_id}"' in html, (
        f"Missing checkbox id={checkbox_id!r}")
    assert label_fragment in html, (
        f"Missing label fragment {label_fragment!r}")


def test_autopwn_config_max_waves_selector():
    """The max-waves dropdown must exist with sensible defaults."""
    html = _html()
    assert 'id="apwn-max-waves"' in html
    assert 'value="5" selected' in html, (
        "Default max_waves should be 5")


def test_autopwn_config_warning_present():
    """The config modal must warn about SAPMAP00 user creation."""
    html = _html()
    assert "SAPMAP00" in html or "SAP_ALL" in html, (
        "Config modal must warn about user creation with SAP_ALL")


# ===========================================================================
# HTML — Progress modal
# ===========================================================================

def test_autopwn_progress_panel_exists():
    """The AutoPwn progress panel must be present in the HTML.
    It's a docked side panel (not a blocking modal) so the map
    stays visible and interactive while AutoPwn runs."""
    html = _html()
    assert 'id="autopwn-progress-panel"' in html
    assert 'autopwn-panel' in html, (
        "Progress panel must use the autopwn-panel CSS class "
        "(docked right, not modal-overlay)")


@pytest.mark.parametrize("phase_id", [
    "apwn-ph-scan",
    "apwn-ph-exploit",
    "apwn-ph-enrich",
    "apwn-ph-propagate",
    "apwn-ph-btp",
    "apwn-ph-lpe",
])
def test_autopwn_phase_tracker_phases(phase_id):
    """Each phase must have a tracker element in the progress modal."""
    html = _html()
    assert f'id="{phase_id}"' in html, (
        f"Missing phase tracker element {phase_id!r}")


@pytest.mark.parametrize("stat_id", [
    "apwn-st-scanned",
    "apwn-st-vulnerable",
    "apwn-st-pwned",
    "apwn-st-users",
])
def test_autopwn_stats_tiles(stat_id):
    """Each stat tile must exist in the progress modal."""
    html = _html()
    assert f'id="{stat_id}"' in html, (
        f"Missing stat tile {stat_id!r}")


def test_autopwn_progress_bar():
    """The progress bar elements must exist."""
    html = _html()
    assert 'id="apwn-bar"' in html
    assert 'id="apwn-pct"' in html


def test_autopwn_log_area():
    """The scrollable log area must exist."""
    html = _html()
    assert 'id="apwn-log"' in html


def test_autopwn_stop_button():
    """The STOP button must exist in the progress modal."""
    html = _html()
    assert 'id="apwn-stop-btn"' in html
    assert "stopAutoPwn" in html


# ===========================================================================
# HTML — Menu entries
# ===========================================================================

def test_autopwn_in_actions_menu():
    """AutoPwn must appear in the Actions dropdown menu."""
    html = _html()
    assert "showAutoPwnModal()" in html
    assert "AutoPwn" in html


def test_autopwn_in_map_context_menu():
    """AutoPwn must appear in the map background context menu."""
    html = _html()
    assert 'data-action="map_autopwn"' in html


def test_autopwn_context_menu_click_handler():
    """The map context menu click handler must route map_autopwn
    to showAutoPwnModal."""
    html = _html()
    assert "case 'map_autopwn':" in html


# ===========================================================================
# JS functions
# ===========================================================================

@pytest.mark.parametrize("fn_name", [
    "showAutoPwnModal",
    "launchAutoPwn",
    "stopAutoPwn",
    "closeAutoPwnPanel",
    "_apwnPollAutoPwnStatus",
])
def test_autopwn_js_functions_defined(fn_name):
    """Each AutoPwn JS function must be defined."""
    html = _html()
    assert f"function {fn_name}" in html, (
        f"JS function {fn_name} not defined")


def test_launch_autopwn_reads_all_config_checkboxes():
    """launchAutoPwn must read every config checkbox to build the
    request payload."""
    html = _html()
    m = re.search(r"function launchAutoPwn\(\).*?await api\(",
                  html, re.DOTALL)
    assert m, "launchAutoPwn function body not found"
    body = m.group(0)
    for cb_id in ["apwn-scan-gw", "apwn-scan-10k", "apwn-scan-31324",
                   "apwn-scan-recon", "apwn-lpe", "apwn-btp",
                   "apwn-det-icmad", "apwn-det-router"]:
        assert cb_id in body, (
            f"launchAutoPwn does not read checkbox {cb_id!r}")


def test_launch_autopwn_fires_correct_endpoint():
    """launchAutoPwn must POST to actions/autopwn."""
    html = _html()
    m = re.search(r"function launchAutoPwn\(\).*?function",
                  html, re.DOTALL)
    assert m, "launchAutoPwn body not found"
    body = m.group(0)
    assert "actions/autopwn" in body, (
        "launchAutoPwn must fire POST to actions/autopwn")


def test_poll_reads_autopwn_status_endpoint():
    """The polling function must read /api/actions/autopwn/status."""
    html = _html()
    assert "actions/autopwn/status" in html, (
        "Polling function must read /api/actions/autopwn/status")


# ===========================================================================
# Backend endpoints
# ===========================================================================

def test_autopwn_endpoint_exists():
    """POST /api/actions/autopwn must be wired in sapmap_gui.py."""
    src = _gui_src()
    assert '/api/actions/autopwn"' in src, (
        "Autopwn POST endpoint not found in sapmap_gui.py")


def test_autopwn_status_endpoint_exists():
    """GET /api/actions/autopwn/status must be wired."""
    src = _gui_src()
    assert '/api/actions/autopwn/status' in src, (
        "Autopwn status endpoint not found in sapmap_gui.py")


# ===========================================================================
# sapmap_autopwn module structure
# ===========================================================================

def test_autopwn_module_importable():
    """sapmap_autopwn must be importable."""
    import sapmap_autopwn
    assert hasattr(sapmap_autopwn, "autopwn_run")
    assert hasattr(sapmap_autopwn, "AutoPwnConfig")
    assert hasattr(sapmap_autopwn, "get_status")


def test_autopwn_config_defaults():
    """AutoPwnConfig must have sensible defaults."""
    from sapmap_autopwn import AutoPwnConfig
    cfg = AutoPwnConfig()
    assert cfg.max_waves == 5
    assert cfg.include_lpe is False
    assert cfg.include_btp is False
    assert cfg.scan_gw is True
    assert cfg.scan_10kblaze is True
    assert cfg.scan_cve_31324 is True
    assert cfg.scan_recon is True
    assert cfg.include_icmad_detection is True
    assert cfg.include_router_info_detection is True


def test_autopwn_status_initial():
    """get_status must return a dict with expected keys."""
    from sapmap_autopwn import get_status
    st = get_status()
    assert "running" in st
    assert "wave" in st
    assert "phase" in st
    assert "stats" in st
    assert "finished" in st


def test_autopwn_phase_functions_exist():
    """All phase functions must exist with correct names."""
    import sapmap_autopwn
    for fn_name in ["phase1_scan", "phase2_exploit", "phase3_enrich",
                     "phase4_propagate", "phase5_btp", "phase6_lpe",
                     "detection_pass"]:
        assert hasattr(sapmap_autopwn, fn_name), (
            f"Missing function: sapmap_autopwn.{fn_name}")


# ===========================================================================
# Critical: ICMAD + SAProuter NOT in convergence loop
# ===========================================================================

def test_icmad_not_in_phase1_scan():
    """ICMAD (CVE-2022-22536) must NOT be checked in phase1_scan.
    It has no exploitation chain and would waste time on every wave.
    It belongs in the detection_pass only."""
    src = _autopwn_src()
    # Find phase1_scan function body
    m = re.search(r"def phase1_scan\(.*?\ndef ", src, re.DOTALL)
    assert m, "phase1_scan not found"
    body = m.group(0)
    assert "cve_2022_22536" not in body.lower(), (
        "phase1_scan must NOT check ICMAD — it's non-exploitable "
        "and belongs in detection_pass only")
    assert "icmad" not in body.lower(), (
        "phase1_scan must NOT reference ICMAD")


def test_router_info_not_in_phase1_scan():
    """SAProuter Info Leak must NOT be in phase1_scan."""
    src = _autopwn_src()
    m = re.search(r"def phase1_scan\(.*?\ndef ", src, re.DOTALL)
    assert m, "phase1_scan not found"
    body = m.group(0)
    assert "saprouter_info_request" not in body, (
        "phase1_scan must NOT check SAProuter Info Leak — "
        "it's non-exploitable")
    assert "router_info" not in body.lower(), (
        "phase1_scan must NOT reference router_info")


def test_icmad_in_detection_pass():
    """ICMAD must be checked in detection_pass (post-convergence)."""
    src = _autopwn_src()
    m = re.search(r"def detection_pass\(.*?\ndef ", src, re.DOTALL)
    if not m:
        # detection_pass might be the last function
        m = re.search(r"def detection_pass\(.*", src, re.DOTALL)
    assert m, "detection_pass not found"
    body = m.group(0)
    assert "cve_2022_22536" in body.lower() or "icmad" in body.lower(), (
        "detection_pass must check ICMAD (CVE-2022-22536)")


def test_router_info_in_detection_pass():
    """SAProuter Info Leak must be checked in detection_pass."""
    src = _autopwn_src()
    m = re.search(r"def detection_pass\(.*?\ndef ", src, re.DOTALL)
    if not m:
        m = re.search(r"def detection_pass\(.*", src, re.DOTALL)
    assert m, "detection_pass not found"
    body = m.group(0)
    assert "saprouter_info_request" in body or "router_info" in body.lower(), (
        "detection_pass must check SAProuter Info Leak")


# ===========================================================================
# Phase 2 exploit ordering
# ===========================================================================

def test_exploit_phase_priority_order():
    """Phase 2 must try exploits in priority order:
    GW (1) -> CVE-31324 (2) -> RECON (3) -> 10KBlaze (4).
    Each Priority comment must come AFTER the previous one."""
    src = _autopwn_src()
    m = re.search(r"def phase2_exploit\(.*?\ndef ", src, re.DOTALL)
    assert m, "phase2_exploit not found"
    body = m.group(0)

    # The code uses "# Priority N:" comments to mark each exploit
    p1 = body.find("Priority 1")
    p2 = body.find("Priority 2")
    p3 = body.find("Priority 3")
    p4 = body.find("Priority 4")

    assert p1 > 0, "Priority 1 (GW) marker not found in phase2"
    assert p2 > 0, "Priority 2 (CVE-31324) marker not found in phase2"
    assert p3 > 0, "Priority 3 (RECON) marker not found in phase2"
    assert p4 > 0, "Priority 4 (10KBlaze) marker not found in phase2"

    assert p1 < p2 < p3 < p4, (
        "Exploit priority must be: GW (1) -> CVE-31324 (2) -> "
        "RECON (3) -> 10KBlaze (4)")


# ===========================================================================
# Stop safety
# ===========================================================================

def test_stop_checks_in_all_phases():
    """Every phase function must check _stop_requested() so the
    operator can halt AutoPwn at any point."""
    src = _autopwn_src()
    for fn_name in ["phase1_scan", "phase2_exploit", "phase3_enrich",
                     "phase4_propagate", "phase5_btp", "phase6_lpe",
                     "detection_pass"]:
        m = re.search(rf"def {fn_name}\(.*?\ndef ", src, re.DOTALL)
        if not m:
            m = re.search(rf"def {fn_name}\(.*", src, re.DOTALL)
        assert m, f"{fn_name} not found"
        body = m.group(0)
        assert "_stop_requested()" in body, (
            f"{fn_name} must check _stop_requested() for STOP safety")


# ===========================================================================
# Convergence loop
# ===========================================================================

def test_convergence_check_in_autopwn_run():
    """autopwn_run must break when no new nodes are pwned in a wave."""
    src = _autopwn_src()
    m = re.search(r"def autopwn_run\(.*", src, re.DOTALL)
    assert m, "autopwn_run not found"
    body = m.group(0)
    # Must track pwned count before/after and break on no change
    assert "new_this_wave" in body or "pwned_before" in body, (
        "autopwn_run must compare pwned count to detect convergence")
    assert "break" in body, (
        "autopwn_run must break out of the loop on convergence")


# ===========================================================================
# CSS
# ===========================================================================

def test_autopwn_css_classes():
    """AutoPwn CSS classes must be defined."""
    html = _html()
    for cls in [".autopwn-panel", ".autopwn-phases", ".autopwn-phase",
                ".autopwn-stats", ".autopwn-bar-track", ".autopwn-bar-fill",
                ".autopwn-log"]:
        assert cls in html, f"CSS class {cls!r} not defined"


def test_autopwn_phase_active_styling():
    """The active phase must have distinct styling."""
    html = _html()
    assert ".autopwn-phase.active" in html
    assert ".autopwn-phase.done" in html
    assert ".autopwn-phase.skipped" in html


def test_autopwn_panel_is_docked_not_modal():
    """The progress panel must be docked to the side (position: fixed,
    right: 0) NOT a centered modal-overlay.  This is critical so the
    operator can see the map update live while AutoPwn runs."""
    html = _html()
    assert "autopwn-panel" in html
    # The PROGRESS panel must NOT be a modal-overlay (the CONFIG
    # dialog is a modal and that's fine — it's shown once before launch)
    assert 'class="modal-overlay" id="autopwn-progress' not in html, (
        "AutoPwn progress must be a docked panel, not a modal-overlay")
    # CSS must position it as a fixed side panel
    import re
    m = re.search(r"\.autopwn-panel\s*\{([^}]*)\}", html)
    assert m, ".autopwn-panel CSS rule not found"
    rule = m.group(1)
    assert "position: fixed" in rule or "position:fixed" in rule, (
        ".autopwn-panel must be position:fixed")
    assert "right:" in rule, (
        ".autopwn-panel must be docked to the right side")


def test_autopwn_close_panel_button():
    """The close button (visible when finished) must call
    closeAutoPwnPanel to dismiss the panel."""
    html = _html()
    assert "closeAutoPwnPanel()" in html
    assert 'id="apwn-close-btn"' in html


# ===========================================================================
# GW exploit post-exploit wiring
# ===========================================================================

def test_phase2_gw_calls_track_and_enrich():
    """Phase 2 GW exploit must call state.track_created_user AND
    _post_exploit_enrichment after a successful create_user_gw_exploit.

    create_user_gw_exploit returns a CreatedUser but does NOT set
    node.pwned — the caller is responsible for tracking + enrichment.
    Without this, the exploit succeeds silently but the node stays
    un-pwned on the map (operator-reported bug)."""
    src = _autopwn_src()
    m = re.search(r"Priority 1.*?Priority 2", src, re.DOTALL)
    assert m, "Priority 1 (GW) block not found in phase2"
    body = m.group(0)
    assert "track_created_user" in body, (
        "Phase 2 GW block must call state.track_created_user(created)")
    assert "_post_exploit_enrichment" in body, (
        "Phase 2 GW block must call _post_exploit_enrichment to set "
        "node.pwned=True")
    # Must check the return value, not node.pwned
    assert "if created:" in body, (
        "Phase 2 must check 'if created:' (return value), not "
        "'if node.pwned:' — create_user_gw_exploit does not set pwned")


# ===========================================================================
# Phase 3 enrichment: RFC retrieval pipeline
# ===========================================================================

def test_phase3_uses_add_connection_not_extend():
    """Phase 3 must use state.add_connection(conn) for each connection,
    NOT state.connections.extend().

    add_connection does dedup and finding emission; extend bypasses it
    and leaves connections without proper target_sid resolution, so they
    don't render as edges on the map (operator-reported bug)."""
    src = _autopwn_src()
    m = re.search(r"def phase3_enrich.*?(?=\ndef )", src, re.DOTALL)
    assert m, "phase3_enrich function not found"
    body = m.group(0)
    assert "state.add_connection(conn)" in body, (
        "phase3_enrich must use state.add_connection(conn) — not "
        "state.connections.extend()")
    assert "state.connections.extend" not in body, (
        "phase3_enrich must NOT use state.connections.extend() — "
        "use state.add_connection(conn) per connection instead")


def test_phase3_pings_non_self_connections():
    """Phase 3 must ping non-self RFC connections to resolve remote SIDs
    and test liveness, matching the GUI's 'Retrieve RFC Destinations'
    handler.  Without pinging, connections lack target_sid and ping_ok,
    so the map can't draw resolved edges."""
    src = _autopwn_src()
    m = re.search(r"def phase3_enrich.*?(?=\ndef )", src, re.DOTALL)
    assert m, "phase3_enrich function not found"
    body = m.group(0)
    assert "ping_rfc_destination" in body, (
        "phase3_enrich must call sapmap_rfc.ping_rfc_destination() "
        "to resolve remote SIDs and test liveness")
    assert "non_self" in body, (
        "phase3_enrich must separate non-self connections for pinging")


def test_phase3_self_detection():
    """Phase 3 must detect self-referencing RFC connections (where
    target_host matches the source node) and tag them with the node's
    own SID, so they don't get pinged or auto-discovered."""
    src = _autopwn_src()
    m = re.search(r"def phase3_enrich.*?(?=\ndef )", src, re.DOTALL)
    assert m, "phase3_enrich function not found"
    body = m.group(0)
    assert "is_self" in body, (
        "phase3_enrich must detect self-referencing connections")
    assert "all_hostnames" in body, (
        "Self-detection must check node.all_hostnames()")
    assert "all_ips" in body, (
        "Self-detection must check node.all_ips()")


def test_phase3_auto_discovers_unknown_targets():
    """Phase 3 must auto-discover new SAP systems when a pinged RFC
    destination returns a remote SID that isn't on the map yet.  This
    mirrors the GUI handler's auto-discovery so the convergence loop
    picks up the new node in the next wave."""
    src = _autopwn_src()
    m = re.search(r"def phase3_enrich.*?(?=\ndef )", src, re.DOTALL)
    assert m, "phase3_enrich function not found"
    body = m.group(0)
    assert "state.add_node(" in body, (
        "phase3_enrich must call state.add_node() for newly-discovered "
        "target systems")
    assert "InstanceInfo(" in body, (
        "Auto-discovery must create an InstanceInfo for the new node")


def test_phase2_updates_users_stat():
    """Phase 2 must update the 'users_created' stat so the progress
    panel shows the correct user count after exploitation."""
    src = _autopwn_src()
    m = re.search(r"def phase2_exploit.*?(?=\ndef )", src, re.DOTALL)
    assert m, "phase2_exploit function not found"
    body = m.group(0)
    assert "users_created" in body, (
        "phase2_exploit must update the 'users_created' stat")
