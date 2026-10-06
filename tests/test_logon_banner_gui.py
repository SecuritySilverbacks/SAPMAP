"""Pins for the logon-banner secret-scan GUI surface (issue #68 PR3).

Static source-text checks for:
  * The per-node POST route exists on sapmap_gui.py with the right
    shape (ABAP gate, dispatcher gate, _bg hand-off, emit_finding
    wrapping, capability key usage)
  * The HTML ctx-menu entry lives in the Scanning submenu, is wired
    into rules / hints / hidden maps, dispatches via ctxAction
  * The modal + side-panel renderer + pollUpdates refresh branch exist
  * The route is NOT in WRITE_ROUTES (the user picked "ship without the
    standard write-op pattern — this is not intrusive at all")
  * CAPABILITY_MAP registers the three new keys and every T-ID resolves
    (the generic catalog test already covers this; this is a PR3-local
    fail-fast)
"""
from __future__ import annotations

import pathlib
import re

import pytest

import modules  # noqa: F401 — path registration

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Backend route — sapmap_gui.py
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def gui_src() -> str:
    return (REPO_ROOT / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")


def test_route_scan_logon_banners_registered(gui_src: str):
    """POST /api/node/<sid>/scan_logon_banners must be registered."""
    assert '@app.route("/api/node/<sid>/scan_logon_banners", method="POST")' \
        in gui_src
    assert "def node_scan_logon_banners(sid):" in gui_src


def test_route_sets_404_on_missing_node(gui_src: str):
    """Current-era 404/400 style — set response.status BEFORE
    returning the error dict."""
    # Find the route body and assert the 404 + 400 pattern lives inside it.
    body = _route_body(gui_src, "scan_logon_banners")
    assert 'response.status = 404' in body
    assert '"error": "node_not_found"' in body


def test_route_rejects_non_abap_nodes_with_400(gui_src: str):
    body = _route_body(gui_src, "scan_logon_banners")
    assert 'response.status = 400' in body
    assert '"error": "not_abap"' in body
    # ABAP gate must use substring match (lets ABAP+JAVA through).
    assert '"ABAP" not in system_type' in body


def test_route_rejects_no_dispatcher_port_with_400(gui_src: str):
    body = _route_body(gui_src, "scan_logon_banners")
    assert '"error": "no_dispatcher"' in body


def test_route_uses_bg_background_hand_off(gui_src: str):
    body = _route_body(gui_src, "scan_logon_banners")
    assert '_bg(f"{sid}:scan_logon_banners"' in body


def test_route_lazy_imports_scanner_and_loot_dir(gui_src: str):
    """Lazy-import inside _run so GUI startup stays fast and an
    ImportError degrades gracefully without crashing the Bottle app."""
    body = _route_body(gui_src, "scan_logon_banners")
    assert "from sap_logon_banner_scan import scan_node" in body
    assert "from sapmap_state import ensure_loot_dir" in body


def test_route_calls_scan_node_with_identity_kwargs(gui_src: str):
    """scan_node must be called with sid/instance_nr/saprouter so
    the context dict + loot path are tagged correctly."""
    body = _route_body(gui_src, "scan_logon_banners")
    assert "scan_node(" in body
    # These positional/keyword hints must appear in the body.  The
    # exact arg order can shift, but each of these names must land
    # in the call site.
    for kw in ("sid=sid", "instance_nr=instance_nr",
               "saprouter=node.saprouter",
               "custom_patterns=custom_patterns",
               "loot_dir="):
        assert kw in body, f"missing {kw}"


def test_route_mutates_node_logon_banner_scan_and_findings(gui_src: str):
    """GUI readback relies on these two fields; the route must set
    both or the side-panel never updates."""
    body = _route_body(gui_src, "scan_logon_banners")
    assert "node.logon_banner_scan =" in body
    assert "node.logon_banner_findings =" in body


def test_route_summary_dict_strips_cleartext_context(gui_src: str):
    """node.logon_banner_scan is the SUMMARY — the per-finding
    `context` key duplicates sid/host/port which the node already
    carries, so the route strips it.  Guard the invariant."""
    body = _route_body(gui_src, "scan_logon_banners")
    # The dict comprehension that drops `context` from each finding
    # before storing it on the node.
    assert '{k: v for k, v in f.items() if k != "context"}' in body


def test_route_emits_findings_with_capability_key(gui_src: str):
    body = _route_body(gui_src, "scan_logon_banners")
    assert "emit_finding(" in body
    # The capability key fallback must be the data.* namespace key.
    assert '"data.diag_login_screen_leak"' in body


def test_route_bus_message_redacts_match_as_sha256_prefix(gui_src: str):
    """Review finding #7 — the cleartext match CANNOT appear in the
    emit_finding bus message.  CRITICAL/HIGH bus events are mirrored
    onto node.findings (persisted in .sapmap state + the engagement
    report), and the (sev, node, msg) tuple drives the dedup window —
    two different leaked creds with the same severity would collapse
    into one finding if the message carried the match.  The route
    emits a sha256:<12-hex> prefix instead; the operator still sees
    the full cleartext in the side-panel (via node.logon_banner_findings)
    and in the gitignored loot JSON.
    """
    body = _route_body(gui_src, "scan_logon_banners")
    # Positive — the redacted shape must be present.
    assert "sha256:" in body
    assert "_hashlib.sha256(" in body or "hashlib.sha256(" in body
    assert "match_sha256_prefix" in body
    assert "match_length" in body
    # Negative — the raw f.get('match') must NOT be spliced into
    # the message string any more.
    assert "\"{f.get('match')}\"" not in body
    assert '"{f.get(\'match\')}"' not in body


def test_route_rejects_non_dict_body_with_400(gui_src: str):
    """Review finding #2 — Bottle hands us whatever JSON parsed to.
    A client posting `[1,2]` or `42` must not crash the route."""
    body = _route_body(gui_src, "scan_logon_banners")
    assert "not isinstance(_raw_body, dict)" in body
    assert '"error": "bad_body"' in body


def test_route_rejects_non_list_non_string_custom_patterns_with_400(
        gui_src: str):
    """Review finding #1 — custom_patterns=42 or custom_patterns=True
    must land as a controlled 400, not a 500 TypeError."""
    body = _route_body(gui_src, "scan_logon_banners")
    assert '"error": "bad_custom_patterns"' in body
    # The accept-list is explicit: str OR list/tuple, nothing else.
    assert "isinstance(raw_patterns, (list, tuple))" in body


def test_route_wires_cancel_check_from_sapmap_stop(gui_src: str):
    """Review finding #10 — scan_node accepts cancel_check but the
    route previously did not pass it, so an operator STOP could not
    abort an in-flight scan.  Must wire sapmap_stop.is_stop_requested."""
    body = _route_body(gui_src, "scan_logon_banners")
    assert "import sapmap_stop" in body
    assert "cancel_check=" in body
    assert "is_stop_requested" in body


def test_route_emits_coverage_marker_on_clean_banner(gui_src: str):
    """Operator wants to tell 'we checked this node and it was clean'
    from 'we never checked this node' — INFO coverage marker required."""
    body = _route_body(gui_src, "scan_logon_banners")
    assert 'ref="logon_banner.no_hits"' in body
    assert '"recon.logon_banner_scan"' in body


def test_route_not_in_write_routes(gui_src: str):
    """User explicitly green-lit shipping without the write-op
    pattern because the scan is purely read-only."""
    m = re.search(r"WRITE_ROUTES = frozenset\(\{(.*?)\}\)",
                   gui_src, re.DOTALL)
    assert m, "WRITE_ROUTES frozenset not found"
    body = m.group(1)
    assert '/scan_logon_banners' not in body


def test_route_accepts_both_list_and_string_custom_patterns(gui_src: str):
    """The frontend sends the textarea blob as a single string; the
    backend ought to accept both shapes (list from MCP calls, string
    from the modal)."""
    body = _route_body(gui_src, "scan_logon_banners")
    assert "isinstance(raw_patterns, str)" in body


def test_route_handles_scan_node_exception_with_warning_finding(gui_src: str):
    """A crash inside scan_node must not die silently in the daemon
    thread — the route wraps the call and emits a bus warning so the
    operator sees the failure."""
    body = _route_body(gui_src, "scan_logon_banners")
    assert 'ref="logon_banner.exception"' in body


# ---------------------------------------------------------------------------
# Frontend wiring — sapmap_html.py
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def html_src() -> str:
    return (REPO_ROOT / "modules" / "core" / "sapmap_html.py").read_text(
        encoding="utf-8")


def test_ctx_menu_entry_under_scanning_submenu(html_src: str):
    """data-action="scan_logon_banners" must appear in the per-node
    Scanning submenu block (the one anchored by the Scanning header)."""
    # The ctx-menu div block that owns the Scanning header + sub.
    m = re.search(
        r'<!-- Scanning submenu -->(.*?)<!-- Exploitation submenu',
        html_src, re.DOTALL)
    assert m, "Scanning submenu block not found"
    assert 'data-action="scan_logon_banners"' in m.group(1)


def test_ctx_menu_entry_has_no_write_op_class(html_src: str):
    """Scanning is a pure DIAG read — must NOT carry write-op
    (that would hide it under --read-only)."""
    # Find the entry line and check its classes.
    m = re.search(
        r'<div class="([^"]+)" data-action="scan_logon_banners"',
        html_src)
    assert m, "scan_logon_banners entry not found"
    classes = m.group(1).split()
    assert "write-op" not in classes, (
        "scan_logon_banners must not have write-op class")


def test_rules_hints_hidden_maps_contain_scan_logon_banners(html_src: str):
    """ctx-menu enable/hide logic triplet."""
    assert "'scan_logon_banners': hasDispPort" in html_src   # rules
    assert "'scan_logon_banners': (!hasDispPort" in html_src  # hints
    assert "'scan_logon_banners': !isAbapStack" in html_src   # hidden


def test_ctxaction_dispatches_scan_logon_banners(html_src: str):
    """The dispatcher switch opens the modal (not a direct POST) so
    the operator can type optional tenant-specific patterns first."""
    assert "case 'scan_logon_banners':" in html_src
    assert "showScanLogonBannersModal(sid);" in html_src


def test_modal_dom_anchor_present(html_src: str):
    assert 'id="scan-logon-banners-modal"' in html_src
    assert 'id="scan-logon-banners-patterns"' in html_src
    assert 'id="scan-logon-banners-info"' in html_src


def test_start_scan_posts_to_route_and_opens_results_panel(html_src: str):
    """startScanLogonBanners must POST then open the side-panel with
    a scanning-in-progress state (so operators don't see a stale/empty
    panel while the DIAG round-trip is in flight)."""
    assert "async function startScanLogonBanners()" in html_src
    assert "`node/${sid}/scan_logon_banners`" in html_src
    assert "showLogonBannerResults(sid, {scanning: true})" in html_src


def test_start_scan_reads_sid_from_modal_dataset_not_global_selected(
        html_src: str):
    """Rescan from the side-panel opens the modal pre-bound to the
    scan's own SID; by the time the operator hits "Scan Now" the
    globally-selected node may have changed.  startScanLogonBanners
    MUST read the modal's dataset.sid first (and fall back to
    selectedNodeSid only when the dataset is unset)."""
    assert "modal.dataset.sid" in html_src
    # The read side — ensure the function reads modal.dataset.sid.
    m = re.search(
        r"async function startScanLogonBanners\(\).*?closeModal",
        html_src, re.DOTALL)
    assert m, "startScanLogonBanners body not found"
    body = m.group(0)
    assert "dataset.sid" in body, (
        "startScanLogonBanners must read modal.dataset.sid before POSTing")


def test_rescan_button_uses_dom_listener_not_inline_onclick(html_src: str):
    """SIDs can contain characters that break a naive JS-string
    splice (quotes, backslashes); the Rescan button in the side-panel
    binds via addEventListener with sid captured by closure, not via
    an onclick=\"showScanLogonBannersModal('<sid>')\" HTML attribute."""
    assert "id=\"logon-banner-rescan-btn\"" in html_src
    assert "logon-banner-rescan-btn" in html_src
    # Positive — the DOM listener is wired:
    assert "rescanBtn.addEventListener('click'" in html_src
    # Negative — no inline onclick splicing of _esc(sid) into
    # showScanLogonBannersModal():
    assert "showScanLogonBannersModal(\\'" not in html_src
    assert "showScanLogonBannersModal('\" + _esc(sid)" not in html_src


def test_side_panel_renderer_sets_data_view_logon_banners(html_src: str):
    assert "function showLogonBannerResults(sid" in html_src
    assert "panel.setAttribute('data-view', 'logon-banners')" in html_src
    assert "panel.classList.add('visible')" in html_src


def test_poll_updates_live_refresh_branch_wired(html_src: str):
    """A new scan from the backend must repaint the open side-panel
    on the next /api/state poll — otherwise the operator sits looking
    at stale 'no scan yet' until they re-open the panel."""
    assert "view === 'logon-banners'" in html_src
    assert "_detailsRefreshKind === 'logon-banners'" in html_src
    assert "showLogonBannerResults(_detailsRefreshKey, {refresh: true})" in html_src


# ---------------------------------------------------------------------------
# Attack-mapping — the three keys must exist in CAPABILITY_MAP and all
# their T-IDs must resolve.  The repo-wide catalog test
# (tests/test_attack_mapping.test_every_mapped_technique_resolves) already
# covers this transitively, but failing fast here with a focused
# diagnostic is much friendlier when PR3 breaks it.
# ---------------------------------------------------------------------------

def test_three_pr3_capability_keys_land_in_capability_map():
    import sapmap_attack
    for cap in {"recon.logon_banner_scan",
                "creds.diag_login_screen_leak",
                "data.diag_login_screen_leak"}:
        assert cap in sapmap_attack.CAPABILITY_MAP, cap


def test_three_pr3_capability_keys_resolve_to_known_techniques():
    import sapmap_attack
    for cap in {"recon.logon_banner_scan",
                "creds.diag_login_screen_leak",
                "data.diag_login_screen_leak"}:
        for tid in sapmap_attack.CAPABILITY_MAP[cap]:
            assert tid in sapmap_attack.TECHNIQUES, (cap, tid)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _route_body(src: str, action: str) -> str:
    """Extract the route handler body (up to the next @app.route).
    Simple heuristic; good enough for pin tests."""
    marker = f'@app.route("/api/node/<sid>/{action}", method="POST")'
    i = src.find(marker)
    assert i >= 0, f"route {action} not found"
    j = src.find("@app.route(", i + len(marker))
    return src[i:j if j > 0 else len(src)]
