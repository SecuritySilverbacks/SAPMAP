"""Pins for the password-spray LANDSCAPE sweep surface (PR 3 of #69).

Covers the backend half of PR3:
  * Status singleton — PwSprayStatus dataclass + get_status()
    + phase emits + reset-on-launch semantics
  * spray_landscape wires the status singleton as it progresses
    (collect_pool -> profile_probe -> spray -> report -> done),
    bumps targets/attempts/hits/locks counters, and the finished
    flag flips at the end
  * Reset-history semantics — three fields wiped in a single call,
    double-confirm enforced server-side, operator-OPS HIGH audit
    finding emitted
  * Preview-shape pins — the exact JSON shape the config modal
    frontend consumes

Follows the existing SAPMAP route-shape test style (source-level
grep + pure-engine helper assertions) — no Bottle test client.

NOTE (issue #69 de-gate): the kernel arm flag (--allow-pwspray /
sapmap_mode.set_pwspray_armed / PWSPRAY_ROUTES / _pwspray_gate hook /
body.pwspray-armed) was removed per operator request — the confirm
dialogs + accept_lockout_risk strict-bool + --read-only WRITE_ROUTES
gate are the real safety.  Tests pinning those arm-gate artefacts
were removed; see tests/test_pwspray_gui.py for the negative pins
guarding against their reintroduction.
"""
from __future__ import annotations

import json
import pathlib
import re
from typing import List, Tuple
from unittest.mock import patch

import pytest

import modules  # noqa: F401
from sapmap_models import SAPMAPState, SAPNode, InstanceInfo
import sapmap_pwspray


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _reset_pwspray_state():
    """Every test starts with a fresh status singleton so a stray
    leak cannot mask a regression."""
    sapmap_pwspray._status = sapmap_pwspray.PwSprayStatus()
    yield
    sapmap_pwspray._status = sapmap_pwspray.PwSprayStatus()


# ---------------------------------------------------------------------------
# Status singleton
# ---------------------------------------------------------------------------

def test_status_singleton_default_idle():
    s = sapmap_pwspray.get_status()
    assert s["running"] is False
    assert s["finished"] is False
    assert s["phase"] == "idle"
    assert s["phase_progress"] == [0, 0]
    assert s["hits"] == 0
    assert s["locks"] == 0
    assert s["log_tail"] == []


def test_reset_status_seeds_with_run_metadata():
    sapmap_pwspray._reset_status(
        run_id="r1", scope="landscape",
        dry_run=False, cap_per_user=2,
        started_at="2026-10-04T10:00:00")
    s = sapmap_pwspray.get_status()
    assert s["running"] is True
    assert s["run_id"] == "r1"
    assert s["scope"] == "landscape"
    assert s["dry_run"] is False
    assert s["cap_per_user"] == 2
    assert s["started_at"] == "2026-10-04T10:00:00"


def test_set_phase_advances_and_resets_progress():
    sapmap_pwspray._reset_status()
    sapmap_pwspray._set_phase_progress(3, 5)
    assert sapmap_pwspray.get_status()["phase_progress"] == [3, 5]
    sapmap_pwspray._set_phase("spray")
    s = sapmap_pwspray.get_status()
    assert s["phase"] == "spray"
    # Phase change must reset the within-phase progress bar.
    assert s["phase_progress"] == [0, 0]


def test_set_phase_ignores_unknown_phase_name():
    """Tests shouldn't be able to break the singleton by typo'ing a
    phase.  Unknown names are a no-op (phase stays put)."""
    sapmap_pwspray._reset_status()
    sapmap_pwspray._set_phase("spray")
    sapmap_pwspray._set_phase("not_a_phase")
    assert sapmap_pwspray.get_status()["phase"] == "spray"


def test_append_log_tails_at_cap():
    sapmap_pwspray._reset_status()
    for i in range(250):
        sapmap_pwspray._append_log(f"line {i}", cap=200)
    tail = sapmap_pwspray.get_status()["log_tail"]
    assert len(tail) == 200
    # The oldest 50 should be gone; latest line present.
    assert tail[-1] == "line 249"
    assert "line 0" not in tail


# ---------------------------------------------------------------------------
# spray_landscape phase emits
# ---------------------------------------------------------------------------

def _mk_state_with_abap_node(sid="NPL", client="001", ip="10.0.0.1"):
    """Minimal state with one ABAP target that build_target_matrix
    accepts (ABAP + 32XX dispatcher + host + enumerated client)."""
    state = SAPMAPState()
    node = SAPNode(sid=sid, ip=ip, hostname="npl", system_type="ABAP")
    node.clients = [{"nr": client}]
    inst = InstanceInfo(instance_nr="00")
    inst.ports = {3200: "dispatcher"}
    node.instances = [inst]
    state.nodes[sid] = node
    return state, node


def test_spray_landscape_emits_phase_transitions_on_dry_run():
    """Dry-run doesn't open sockets but the engine must still move
    through the phases so the progress panel reflects the run."""
    state, _ = _mk_state_with_abap_node()
    cfg = sapmap_pwspray.SprayConfig(dry_run=True, cap_per_user=1)

    phases_seen = []
    original_set_phase = sapmap_pwspray._set_phase

    def _tracking_set_phase(p):
        phases_seen.append(p)
        original_set_phase(p)

    with patch.object(sapmap_pwspray, "_set_phase",
                       side_effect=_tracking_set_phase):
        run = sapmap_pwspray.spray_landscape(state, cfg)

    assert "collect_pool" in phases_seen
    assert "profile_probe" in phases_seen
    assert "report" in phases_seen
    # Finished status reads 'done' because _finalise_status flips it.
    final = sapmap_pwspray.get_status()
    assert final["phase"] == "done"
    assert final["finished"] is True
    assert final["running"] is False
    assert final["run_id"] == run.run_id


def test_spray_landscape_finalise_pulls_tallies_from_sprayrun():
    """At the end of a run the status singleton must reflect
    SprayRun.hits / attempts_done / locked_users / aborted — otherwise
    a hit that landed appears as zero in the progress panel."""
    state, _ = _mk_state_with_abap_node()
    cfg = sapmap_pwspray.SprayConfig(dry_run=True, cap_per_user=1)
    run = sapmap_pwspray.spray_landscape(state, cfg)
    # Hand-inject a hit onto the SprayRun to prove _finalise_status
    # reads from it (dry-run naturally has zero hits).
    run.hits = [{"sid": "NPL", "client": "001", "user": "DDIC"}]
    run.locked_users = ["LOCKED1"]
    run.attempts_done = 7
    run.aborted = ""
    sapmap_pwspray._finalise_status(run)
    s = sapmap_pwspray.get_status()
    assert s["hits"] == 1
    assert s["locks"] == 1
    assert s["attempts_done"] == 7
    assert s["phase"] == "done"


def test_spray_landscape_aborted_dry_run_default_still_finalises():
    """When accept_lockout_risk is missing the orchestrator bails
    with aborted='dry_run_default_active' — _finalise_status still
    has to fire so the GUI sees finished=True and the panel can
    close."""
    state, _ = _mk_state_with_abap_node()
    cfg = sapmap_pwspray.SprayConfig(
        dry_run=False, accept_lockout_risk=False, cap_per_user=1)
    run = sapmap_pwspray.spray_landscape(state, cfg)
    assert run.aborted == "dry_run_default_active"
    s = sapmap_pwspray.get_status()
    assert s["finished"] is True
    assert s["running"] is False
    assert s["aborted"] == "dry_run_default_active"


# ---------------------------------------------------------------------------
# WRITE_ROUTES gating (--read-only mode)
# ---------------------------------------------------------------------------

def _gui_src() -> str:
    return (REPO_ROOT / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")


def test_pwspray_write_routes_still_in_write_routes():
    """The two POST routes that mutate target state (per-node spray,
    wordlist upload) + the new landscape POST + the new reset_history
    must be listed in WRITE_ROUTES too so --read-only refuses them
    FIRST.  Omission reopens the hole PR2 closed."""
    src = _gui_src()
    m = re.search(r"WRITE_ROUTES = frozenset\(\{(.*?)\}\)",
                  src, re.DOTALL)
    assert m, "WRITE_ROUTES frozenset not found"
    body = m.group(1)
    for required in (
        '"/api/node/<sid>/password_spray",',
        '"/api/actions/password_spray",',
        '"/api/actions/password_spray/pool/wordlist",',
        '"/api/actions/password_spray/reset_history",',
    ):
        assert required in body, (
            f"WRITE_ROUTES is missing {required!r} — --read-only mode "
            f"will not refuse this destructive route")


def test_pwspray_write_routes_omits_status_and_runs_and_pool_get():
    """Three read-only pwspray surfaces (GET pool, GET status, GET
    runs) must NOT be in WRITE_ROUTES — read-only sessions should
    still be able to inspect what wordlist is loaded, what spray
    is running, and what history exists."""
    src = _gui_src()
    m = re.search(r"WRITE_ROUTES = frozenset\(\{(.*?)\}\)",
                  src, re.DOTALL)
    assert m
    body = m.group(1)
    assert '"/api/actions/password_spray/pool",' not in body
    assert '"/api/actions/password_spray/status",' not in body
    assert '"/api/actions/password_spray/runs",' not in body


# ---------------------------------------------------------------------------
# Reset-history semantics (PR3)
# ---------------------------------------------------------------------------

def test_reset_history_wipes_three_fields():
    """reset_history must clear spray_attempts_counter AND
    pwspray_locked_users AND spray_runs.  The task-spec gotcha
    flagged the three-field invariant — spray_runs must be included
    or the GET /runs endpoint keeps returning stale data."""
    src = _gui_src()
    # Isolate the reset_history handler body.
    m = re.search(
        r"def actions_password_spray_reset_history\(\):(.*?)@app\.route",
        src, re.DOTALL)
    assert m, "reset_history handler not found"
    body = m.group(1)
    assert "api.state.spray_attempts_counter = {}" in body
    assert "api.state.pwspray_locked_users = {}" in body
    assert "api.state.spray_runs = []" in body


def test_reset_history_requires_double_confirm_server_side():
    """The frontend chains two confirm() calls but the server must
    ALSO enforce the double-confirm so a scripted POST can't bypass
    it.  PR3 adversarial-review LOW #4 tightened this to strict
    JSON ``true``."""
    src = _gui_src()
    m = re.search(
        r"def actions_password_spray_reset_history\(\):(.*?)@app\.route",
        src, re.DOTALL)
    assert m
    body = m.group(1)
    assert 'body.get("confirm") is not True' in body
    assert 'body.get("i_accept") is not True' in body
    # And must respond 400 with double_confirm_required when either
    # is missing.
    assert '"error": "double_confirm_required"' in body


def test_reset_history_emits_high_audit_finding():
    """OPS-noise events get HIGH, not CRITICAL (which is reserved for
    target vulnerabilities).  reset_history is operator action, not
    a target vuln — pin the severity and the ref so the engagement
    report can group operator actions correctly."""
    src = _gui_src()
    m = re.search(
        r"def actions_password_spray_reset_history\(\):(.*?)@app\.route",
        src, re.DOTALL)
    assert m
    body = m.group(1)
    assert 'emit_finding(' in body
    assert '"HIGH"' in body
    assert 'ref="pwspray.reset_history"' in body
    assert 'attack_capability="creds.password_spray"' in body


# ---------------------------------------------------------------------------
# Preview JSON shape (consumed by pwsprayPreview() frontend)
# ---------------------------------------------------------------------------

def test_preview_route_returns_documented_shape_fields():
    """The frontend's _pwspray_renderPreview reads a specific set of
    fields; pin them so a backend refactor can't silently drop one."""
    src = _gui_src()
    m = re.search(
        r"def actions_password_spray_preview\(\):(.*?)@app\.route",
        src, re.DOTALL)
    assert m, "preview handler not found"
    body = m.group(1)
    for field in (
        '"pool_size":',
        '"source_breakdown":',
        '"operator_wordlist_entries":',
        '"targets_eligible":',
        '"targets_ineligible":',
        '"per_target":',
        '"skipped":',
        '"estimated_attempts_upper_bound":',
        '"dry_run_preview": True',
    ):
        assert field in body, (
            f"Preview response is missing {field!r} — the frontend "
            f"pwsprayPreview() renderer reads this field directly")


def test_landscape_launch_refuses_live_without_accept_lockout_risk():
    """Server-side defence-in-depth: even if a scripted caller sets
    dry_run=False, the engine must refuse without accept_lockout_risk."""
    src = _gui_src()
    m = re.search(
        r"def actions_password_spray\(\):(.*?)@app\.route",
        src, re.DOTALL)
    assert m
    body = m.group(1)
    assert 'if not dry_run and not accept_risk:' in body
    assert '"error": "accept_lockout_risk_required"' in body


def test_landscape_launch_strict_bool_parse():
    """PR3 adversarial-review MED #2: ``dry_run=null`` must NOT flip
    to LIVE via ``bool(None)=False``.  The launch route uses a
    _strict_bool helper that treats null as the default and rejects
    non-bool with 400."""
    src = _gui_src()
    m = re.search(
        r"def actions_password_spray\(\):(.*?)@app\.route",
        src, re.DOTALL)
    assert m
    body = m.group(1)
    assert "_strict_bool(" in body, (
        "Launch route must parse dry_run / accept_lockout_risk / "
        "include_production via a strict JSON-bool helper; "
        "bool(None) is False and would flip dry_run=null → LIVE")
    assert '"error": "bad_request_body"' in body


def test_landscape_launch_requires_accept_production_risk():
    """PR3 adversarial-review LOW #5: include_production=true needs
    a second-factor accept_production_risk=true, parallel to
    accept_lockout_risk."""
    src = _gui_src()
    m = re.search(
        r"def actions_password_spray\(\):(.*?)@app\.route",
        src, re.DOTALL)
    assert m
    body = m.group(1)
    assert "accept_production_risk" in body
    assert '"error": "accept_production_risk_required"' in body


def test_landscape_launch_refuses_concurrent_with_409():
    """PR3 adversarial-review MED #1: refuse a second launch while
    one is already running so the status singleton's single-writer
    invariant holds AND _bg's reset_stop can't clobber the active
    sweep's STOP flag."""
    src = _gui_src()
    m = re.search(
        r"def actions_password_spray\(\):(.*?)@app\.route",
        src, re.DOTALL)
    assert m
    body = m.group(1)
    assert 'response.status = 409' in body
    assert '"error": "pwspray_already_running"' in body


def test_landscape_launch_seeds_status_synchronously():
    """PR3 adversarial-review LOW #7: seed _status before _bg hands
    off, so the first GET /status (fired by the frontend right after
    the POST returns) doesn't observe running=False and early-return
    the poller."""
    src = _gui_src()
    m = re.search(
        r"def actions_password_spray\(\):(.*?)@app\.route",
        src, re.DOTALL)
    assert m
    body = m.group(1)
    # The seeding call must appear BEFORE _bg's hand-off.
    seed_at = body.find("_pws._reset_status(")
    bg_at = body.find('_bg("_password_spray",')
    assert seed_at > 0, "status singleton not seeded synchronously"
    assert bg_at > seed_at, (
        "_reset_status must be called BEFORE _bg so the first "
        "GET /status sees running=True")


def test_reset_history_requires_strict_true():
    """PR3 adversarial-review LOW #4: reset_history must require
    strict JSON ``true``, not any truthy value — 1 / "yes" / {} must
    not trip the gate."""
    src = _gui_src()
    m = re.search(
        r"def actions_password_spray_reset_history\(\):(.*?)@app\.route",
        src, re.DOTALL)
    assert m
    body = m.group(1)
    assert 'body.get("confirm") is not True' in body
    assert 'body.get("i_accept") is not True' in body


def test_reset_history_resets_status_singleton():
    """PR3 adversarial-review LOW #12: reset_history must also reset
    the status singleton so a subsequent GET /status doesn't keep
    reporting the last finished run's tallies after a wipe."""
    src = _gui_src()
    m = re.search(
        r"def actions_password_spray_reset_history\(\):(.*?)@app\.route",
        src, re.DOTALL)
    assert m
    body = m.group(1)
    assert "_pws._status = _pws.PwSprayStatus()" in body, (
        "reset_history must wipe the status singleton too — "
        "otherwise GET /status returns stale tallies after a reset")


# ---------------------------------------------------------------------------
# Frontend XSS fixes (PR3 adversarial-review HIGH #8 / MED #9 / LOW #10)
# ---------------------------------------------------------------------------

def test_pwspray_preview_escapes_per_target_fields():
    """Every attacker-reachable field in pwsprayPreview must pass
    through _escapeHtml before concatenation into innerHTML."""
    src = _html_src()
    m = re.search(
        r"async function pwsprayPreview\(\) \{(.*?)^\}",
        src, re.MULTILINE | re.DOTALL)
    assert m, "pwsprayPreview function not found"
    body = m.group(1)
    # Fields that previously landed unescaped:
    for raw in (
        "+ t.sid +", "+ t.host +", "+ t.cap_source +", "+ t.dispatcher_port +",
        "+ s.sid +", "+ s.reason +",
        "+ ((d && d.error) || 'unknown error') +",
    ):
        assert raw not in body, (
            f"pwsprayPreview still interpolates {raw!r} unescaped — "
            f"MUST wrap it with _escapeHtml()")
    # Positive check: escapes appear on the right fields.
    for esc in (
        "_escapeHtml(t.sid",
        "_escapeHtml(String(t.host",
        "_escapeHtml(t.cap_source",
        "_escapeHtml(s.sid",
        "_escapeHtml(s.reason",
    ):
        assert esc in body, (
            f"pwsprayPreview missing _escapeHtml wrapper on "
            f"{esc!r} — innerHTML injection sink")


# ---------------------------------------------------------------------------
# Progress panel + autopwn panel UX
# ---------------------------------------------------------------------------

def test_pwspray_panel_closes_autopwn_before_opening():
    """Both panels share the same docked-right rectangle; opening
    one must close the other to avoid an invisible-covered sibling."""
    src = _html_src()
    assert "try { closeAutoPwnPanel(); } catch (_) {}" in src, (
        "_pwsprayShowProgressPanel must close the autopwn panel "
        "before opening its own — same fixed-position rectangle")
    assert "try { closePwsprayPanel(); } catch (_) {}" in src, (
        "launchAutoPwn must close the pwspray panel symmetrically")


def test_pwspray_panel_surfaces_aborted_reason():
    """cascade_abort / user_stop / dry_run_default_active must land
    visibly in the panel header — otherwise an aborted run looks
    like a normal clean finish."""
    src = _html_src()
    assert "— aborted: " in src, (
        "Progress-panel poller must surface st.aborted in the "
        "scope-label when non-empty — otherwise the operator can't "
        "tell cascade_abort from a normal clean finish")


# ---------------------------------------------------------------------------
# Frontend wiring (source-level)
# ---------------------------------------------------------------------------

def _html_src() -> str:
    return (REPO_ROOT / "modules" / "core" / "sapmap_html.py").read_text(
        encoding="utf-8")


def test_top_nav_actions_entry_sits_between_autopwn_and_propagate():
    """New Actions-dropdown entry should land between AutoPwn and
    Auto-Propagate All so the three landscape writes group together."""
    src = _html_src()
    autopwn_at = src.find('showAutoPwnModal()')
    pwspray_at = src.find('showPwsprayModal()')
    propagate_at = src.find('propagateAll()')
    assert autopwn_at < pwspray_at < propagate_at, (
        "Dropdown order must be AutoPwn → Spray → Propagate so the "
        "three landscape-write entries read in increasing noisiness")


def test_map_ctx_menu_entry_dispatches_through_switch():
    """The right-click entry on the map background must appear in
    both the DOM list AND the switch dispatcher."""
    src = _html_src()
    assert 'data-action="map_password_spray"' in src
    assert "case 'map_password_spray': showPwsprayModal();" in src


def test_config_modal_has_scope_cap_and_wordlist_textarea():
    """Minimal shape check so a wholesale refactor can't lose the
    primary user controls the modal exists to expose."""
    src = _html_src()
    assert 'id="pwspray-config-modal"' in src
    # Scope radios + cap slider + dry-run + accept-risk + wordlist
    assert 'name="pws-scope"' in src
    assert 'id="pws-cap"' in src
    assert 'id="pws-dry-run"' in src
    assert 'id="pws-accept-risk"' in src
    assert 'id="pws-wordlist"' in src


def test_progress_panel_mirrors_autopwn_phase_classes():
    """Pin: the progress panel uses the autopwn CSS classes (.active
    / .done) so the existing phase-indicator styles work.  Panel
    body carries all four phase blocks."""
    src = _html_src()
    assert 'id="pwspray-progress-panel"' in src
    for ph in ('pws-ph-collect_pool', 'pws-ph-profile_probe',
                'pws-ph-spray', 'pws-ph-report'):
        assert f'id="{ph}"' in src
    # Stop button wires to the global stop (same as AutoPwn).
    assert "fetch('/api/scan/stop'" in src


def test_results_modal_has_hit_matrix_and_defender_tabs():
    src = _html_src()
    assert 'id="pwspray-results-modal"' in src
    assert 'id="pws-tab-matrix"' in src
    assert 'id="pws-tab-defender"' in src
    # PR4 shipped the Defender View live — the stub placeholder is
    # gone and the renderer handles the non-purple case explicitly.
    assert "Placeholder for PR4" not in src
    assert "function _renderDefenderView(run)" in src


def test_status_phase_order_shared_with_frontend():
    """Backend PHASE_ORDER and frontend phaseOrder are both the
    source of truth for the progress panel.  PR4 extended both to
    include 'baseline' + 'readback' phases for purple mode."""
    src = _html_src()
    assert "phaseOrder = ['idle', 'collect_pool', 'profile_probe', " \
           "'baseline', 'spray', 'readback', 'report', 'done']" in src
    # And the backend PHASE_ORDER has the same shape.
    backend_phases = sapmap_pwspray.PHASE_ORDER
    assert backend_phases == [
        "idle", "collect_pool", "profile_probe",
        "baseline", "spray", "readback", "report", "done",
    ]
