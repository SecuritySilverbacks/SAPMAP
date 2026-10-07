"""Tests for modules.discovery.sapmap_logon_sweep — PR4 landscape sweep.

Covers the engine orchestrator that iterates every ABAP node with an
observed dispatcher, runs scan_node per node sequentially, writes the
run-scoped loot bundle, maintains the status singleton the GUI polls,
and appends a redacted run summary to ``state.logon_banner_runs``.

No real DIAG socket is opened — all tests pass a ``_scan_node_fn`` DI
hook so scan_node is never actually called.
"""

import json
import types

import pytest

import modules  # noqa: F401 — path registration

import sapmap_logon_sweep as sw
from sapmap_logon_sweep import (
    LogonSweepConfig,
    LogonSweepStatus,
    PHASE_ORDER,
    enumerate_targets,
    get_status,
    make_run_id,
    sweep_landscape,
    _append_run_to_state,
    _build_summary,
    _reset_status,
    _node_dispatcher_port,
    _is_abap,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _reset_singleton():
    """Clear the module-global _status between tests — the engine
    relies on the launch route calling _reset_status, which the
    unit tests emulate here."""
    sw._status = LogonSweepStatus()


def _node(sid, system_type="ABAP", ports=None, hostname=None, saprouter=""):
    inst = types.SimpleNamespace(
        instance_nr="00",
        ports=(ports or {}))
    return types.SimpleNamespace(
        sid=sid,
        system_type=system_type,
        instances=[inst],
        ip="10.0.0." + (sid[-1] if sid[-1].isdigit() else "1"),
        hostname=hostname or sid.lower(),
        saprouter=saprouter)


def _state(**nodes):
    s = types.SimpleNamespace(nodes=nodes, logon_banner_runs=[])
    return s


def _ok_scan_node(host, port, **kwargs):
    """DI-hook replacement for sap_logon_banner_scan.scan_node — fakes
    a CRITICAL hit when the SID starts with 'HIT', clean otherwise."""
    sid = kwargs["sid"]
    is_hit = sid.startswith("HIT")
    hits = ({"CRITICAL": 1, "HIGH": 0, "MEDIUM": 1, "INFO": 0}
            if is_hit else {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0})
    return {
        "ok": True,
        "sid": sid,
        "host": host,
        "port": port,
        "instance_nr": kwargs.get("instance_nr", ""),
        "run_id": kwargs.get("run_id", "r"),
        "ts": "2026-10-06T13:00:00Z",
        "elapsed_s": 0.05,
        "pair_count": 5 if is_hit else 3,
        "raw_text_bytes": 100 if is_hit else 50,
        "hits_by_severity": hits,
        "loot_text_path": "/tmp/t.txt" if is_hit else "",
        "loot_json_path": "/tmp/t.json" if is_hit else "",
        "error_kind": None,
        "error": None,
        "findings": [
            {"severity": "CRITICAL", "pattern_name": "user_password_adjacent",
             "category": "credentials", "match": "SAPMAP00/Andinyougo",
             "snippet": "...", "offset": 0,
             "attack_capability": "creds.diag_login_screen_leak"},
        ] if is_hit else [],
    }


# ---------------------------------------------------------------------------
# Helpers (dispatcher / abap gates — mirror the per-node tests)
# ---------------------------------------------------------------------------

def test_phase_order_mirrors_frontend_contract():
    """PR4.4 frontend's phaseOrder array (sweepLogonPollStatus in
    sapmap_html.py) must mirror this engine-side tuple.  A rename on
    one side would silently desync the UI."""
    assert PHASE_ORDER == (
        "idle", "collect_targets", "scan", "report", "done")


def test_node_dispatcher_port_happy_path():
    n = _node("NPL", ports={3200: "dispatcher"})
    assert _node_dispatcher_port(n) == (3200, "00")


def test_node_dispatcher_port_falls_back_to_32xx_range():
    n = _node("NPL", ports={3207: "open"})
    assert _node_dispatcher_port(n) == (3207, "00")


def test_node_dispatcher_port_zero_without_known_dispatcher():
    n = _node("NPL", ports={1128: "ms_http"})
    assert _node_dispatcher_port(n) == (0, "")


def test_is_abap_accepts_dual_stack_and_rejects_java_only():
    assert _is_abap(_node("A", "ABAP"))
    assert _is_abap(_node("A", "ABAP+JAVA"))
    assert _is_abap(_node("A", "abap"))         # case-insensitive
    assert not _is_abap(_node("J", "JAVA"))
    assert not _is_abap(_node("B", "BUSINESSOBJECTS"))
    assert not _is_abap(_node("R", "SAPROUTER"))
    assert not _is_abap(_node("E", ""))


# ---------------------------------------------------------------------------
# enumerate_targets — scope rules
# ---------------------------------------------------------------------------

def test_enumerate_landscape_defaults_to_every_eligible_abap_sorted():
    state = _state(
        NPL=_node("NPL", "ABAP",      {3200: "dispatcher"}),
        S4H=_node("S4H", "ABAP+JAVA", {3205: "open"}),
        JAV=_node("JAV", "JAVA",      {3300: "gateway"}),  # excluded (not ABAP)
        NOP=_node("NOP", "ABAP",      {1128: "ms_http"}),   # excluded (no dispatcher)
    )
    cfg = LogonSweepConfig(jitter_max_s=0.0)
    sids = [t["sid"] for t in enumerate_targets(state, cfg)]
    assert sids == ["NPL", "S4H"]


def test_enumerate_single_sid_scope_overrides_landscape():
    state = _state(
        NPL=_node("NPL", "ABAP", {3200: "dispatcher"}),
        S4H=_node("S4H", "ABAP", {3200: "dispatcher"}),
    )
    cfg = LogonSweepConfig(single_sid="S4H", jitter_max_s=0.0)
    sids = [t["sid"] for t in enumerate_targets(state, cfg)]
    assert sids == ["S4H"]


def test_enumerate_sids_list_filters_ineligible_entries():
    state = _state(
        NPL=_node("NPL", "ABAP", {3200: "dispatcher"}),
        JAV=_node("JAV", "JAVA", {3300: "gateway"}),       # dropped
        NON=_node("NON", "ABAP", {}),                       # dropped
    )
    cfg = LogonSweepConfig(sids=["NPL", "JAV", "NON", "GHOST"],
                            jitter_max_s=0.0)
    sids = [t["sid"] for t in enumerate_targets(state, cfg)]
    # GHOST isn't on the map, JAV + NON don't pass the filters.
    assert sids == ["NPL"]


def test_enumerate_sids_list_takes_precedence_over_single_sid():
    state = _state(
        NPL=_node("NPL", "ABAP", {3200: "dispatcher"}),
        S4H=_node("S4H", "ABAP", {3200: "dispatcher"}),
    )
    cfg = LogonSweepConfig(
        single_sid="NPL",
        sids=["S4H"],
        jitter_max_s=0.0)
    sids = [t["sid"] for t in enumerate_targets(state, cfg)]
    assert sids == ["S4H"]


# ---------------------------------------------------------------------------
# make_run_id — collision guard
# ---------------------------------------------------------------------------

def test_make_run_id_prefix_and_shape():
    rid = make_run_id()
    assert rid.startswith("logonsweep_"), rid
    tail = rid.split("_")[-1]
    assert len(tail) == 6
    int(tail, 16)  # hex


def test_make_run_id_distinct_on_back_to_back_calls():
    """A double-click launch is defended against anyway by the 409
    guard on the route, but the engine's run_id must still be unique
    across repeat calls so loot subdirs can't collide."""
    seen = {make_run_id() for _ in range(100)}
    assert len(seen) == 100


# ---------------------------------------------------------------------------
# sweep_landscape — happy path + status + run history
# ---------------------------------------------------------------------------

def test_sweep_landscape_scans_every_eligible_node_and_tallies(tmp_path):
    _reset_singleton()
    _reset_status(scope="landscape")
    state = _state(
        HIT1=_node("HIT1", "ABAP", {3200: "dispatcher"}),
        NPL=_node("NPL", "ABAP",   {3200: "dispatcher"}),
    )
    summary = sweep_landscape(
        state,
        LogonSweepConfig(jitter_max_s=0.0),
        _scan_node_fn=_ok_scan_node,
        _sleep_fn=lambda s: None,
    )
    assert summary["targets_total"] == 2
    assert summary["targets_done"] == 2
    # HIT1 scored one CRITICAL + one MEDIUM; NPL was clean.
    assert summary["findings_by_severity"]["CRITICAL"] == 1
    assert summary["findings_by_severity"]["MEDIUM"] == 1
    assert summary["errors_count"] == 0
    assert summary["aborted"] == ""
    # And the summary was appended to state.logon_banner_runs.
    assert state.logon_banner_runs == [summary]


def test_sweep_landscape_status_singleton_lifecycle(tmp_path):
    _reset_singleton()
    _reset_status(scope="landscape")
    state = _state(HIT1=_node("HIT1", "ABAP", {3200: "dispatcher"}))
    sweep_landscape(
        state,
        LogonSweepConfig(jitter_max_s=0.0),
        _scan_node_fn=_ok_scan_node,
        _sleep_fn=lambda s: None,
    )
    st = get_status()
    assert st["running"] is False
    assert st["finished"] is True
    assert st["phase"] == "done"
    assert st["targets_total"] == 1
    assert st["targets_done"] == 1
    assert st["findings_critical"] == 1
    assert st["findings_medium"] == 1
    # The phase_progress field must serialise as a list, not a tuple
    # — downstream Python callers of get_status() depend on it and
    # the pwspray contract pins the same shape.
    assert isinstance(st["phase_progress"], list)
    assert st["log_tail"], "the engine must emit at least one log line"


def test_sweep_landscape_cancel_check_before_loop_short_circuits(tmp_path):
    _reset_singleton()
    _reset_status(scope="landscape")
    state = _state(NPL=_node("NPL", "ABAP", {3200: "dispatcher"}))
    # Cancel probes True on the first call → sweep aborts BEFORE any
    # scan_node fires.  No scans → no state.logon_banner_runs entry
    # beyond the aborted summary.
    def _fail_if_called(host, port, **kwargs):
        raise AssertionError("scan_node must not fire when cancelled early")
    summary = sweep_landscape(
        state,
        LogonSweepConfig(jitter_max_s=0.0),
        cancel_check=lambda: True,
        _scan_node_fn=_fail_if_called,
        _sleep_fn=lambda s: None,
    )
    assert summary["aborted"].startswith("cancelled")
    assert summary["targets_done"] == 0
    st = get_status()
    assert st["running"] is False
    assert st["aborted"] == "cancelled before scan"


def test_sweep_landscape_cancel_check_mid_sweep_persists_partial_state(tmp_path):
    _reset_singleton()
    _reset_status(scope="landscape")
    state = _state(
        HIT1=_node("HIT1", "ABAP", {3200: "dispatcher"}),
        HIT2=_node("HIT2", "ABAP", {3200: "dispatcher"}),
        HIT3=_node("HIT3", "ABAP", {3200: "dispatcher"}),
    )
    # Cancel probe sequence: pre-loop (ignore), iter0 (ignore), iter1
    # trips.  So HIT1 scans; HIT2 + HIT3 don't.
    probes = {"n": 0}
    def _cancel():
        probes["n"] += 1
        return probes["n"] >= 3   # third call aborts (post-first-scan)
    summary = sweep_landscape(
        state,
        LogonSweepConfig(jitter_max_s=0.0),
        cancel_check=_cancel,
        _scan_node_fn=_ok_scan_node,
        _sleep_fn=lambda s: None,
    )
    assert summary["aborted"].startswith("cancelled")
    assert summary["targets_done"] == 1
    assert summary["targets_total"] == 3
    # Partial state DOES land on state.logon_banner_runs (so the GUI
    # history tab still shows aborted sweeps).
    assert state.logon_banner_runs == [summary]


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_sweep_landscape_scan_node_exception_counted_not_fatal(tmp_path):
    _reset_singleton()
    _reset_status(scope="landscape")
    state = _state(
        BAD=_node("BAD", "ABAP", {3200: "dispatcher"}),
        OK1=_node("OK1", "ABAP", {3200: "dispatcher"}),
    )
    def _scan(host, port, **kwargs):
        if kwargs["sid"] == "BAD":
            raise RuntimeError("simulated DIAG crash")
        return _ok_scan_node(host, port, **kwargs)
    summary = sweep_landscape(
        state,
        LogonSweepConfig(jitter_max_s=0.0),
        _scan_node_fn=_scan,
        _sleep_fn=lambda s: None,
    )
    assert summary["errors_count"] == 1
    assert summary["targets_done"] == 2  # both counted; the crash is tallied
    assert summary["aborted"] == ""      # engine doesn't abort on scan errors


def test_sweep_landscape_scan_node_error_kind_counted_in_errors(tmp_path):
    _reset_singleton()
    _reset_status(scope="landscape")
    state = _state(ERR=_node("ERR", "ABAP", {3200: "dispatcher"}))
    def _scan(host, port, **kwargs):
        return {
            "ok": False,
            "error_kind": "connect",
            "error": "ConnectionRefusedError: [Errno 61]",
            "hits_by_severity": {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"INFO":0},
            "findings": [],
            "pair_count": 0,
            "run_id": kwargs["run_id"],
        }
    summary = sweep_landscape(
        state, LogonSweepConfig(jitter_max_s=0.0),
        _scan_node_fn=_scan, _sleep_fn=lambda s: None,
    )
    assert summary["errors_count"] == 1
    assert summary["targets_done"] == 1


# ---------------------------------------------------------------------------
# on_node_finding callback — the route's emit_finding + node-persist hook
# ---------------------------------------------------------------------------

def test_sweep_landscape_calls_on_node_finding_for_every_scanned_node(
        tmp_path):
    _reset_singleton()
    _reset_status(scope="landscape")
    state = _state(
        HIT1=_node("HIT1", "ABAP", {3200: "dispatcher"}),
        NPL=_node("NPL", "ABAP",   {3200: "dispatcher"}),
    )
    callbacks = []
    def _on(sid, result, node):
        callbacks.append((sid, result.get("ok"), node.sid))
    sweep_landscape(
        state, LogonSweepConfig(jitter_max_s=0.0),
        on_node_finding=_on,
        _scan_node_fn=_ok_scan_node,
        _sleep_fn=lambda s: None,
    )
    sids = {c[0] for c in callbacks}
    assert sids == {"HIT1", "NPL"}
    # The node ref is passed through verbatim (so the route can
    # mutate node.logon_banner_scan / _findings).
    for sid, ok, node_sid in callbacks:
        assert ok is True
        assert node_sid == sid


# ---------------------------------------------------------------------------
# No-cleartext invariant
# ---------------------------------------------------------------------------

def test_status_singleton_never_carries_match_cleartext(tmp_path):
    """The sweep status is the GUI poll surface + the engagement
    report's primary roll-up input — it must NEVER carry the raw
    matched text.  Cleartext lives only on per-node side-panel state
    and on the gitignored loot JSON."""
    _reset_singleton()
    _reset_status(scope="landscape")
    state = _state(HIT1=_node("HIT1", "ABAP", {3200: "dispatcher"}))
    sweep_landscape(
        state, LogonSweepConfig(jitter_max_s=0.0),
        _scan_node_fn=_ok_scan_node,
        _sleep_fn=lambda s: None,
    )
    status_blob = json.dumps(get_status())
    for secret in ("SAPMAP00", "Andinyougo"):
        assert secret not in status_blob, (
            f"status singleton leaked cleartext: {secret!r}")
    # And the state.logon_banner_runs history summary is equally clean.
    runs_blob = json.dumps(state.logon_banner_runs)
    for secret in ("SAPMAP00", "Andinyougo"):
        assert secret not in runs_blob, (
            f"state.logon_banner_runs leaked cleartext: {secret!r}")


# ---------------------------------------------------------------------------
# scope label / summary shape
# ---------------------------------------------------------------------------

def test_normalised_scope_for_landscape_single_and_list():
    assert LogonSweepConfig().normalised_scope() == "landscape"
    assert LogonSweepConfig(single_sid="NPL").normalised_scope() == "single:NPL"
    assert LogonSweepConfig(sids=["A", "B"]).normalised_scope() == "sids:2"


def test_build_summary_contains_the_contract_shape_the_route_persists():
    """The ``_build_summary`` dict is what gets appended to
    ``state.logon_banner_runs`` and streamed back via GET /runs — pin
    the key set so a future refactor can't drop a field the GUI /
    report / MCP consume."""
    _reset_singleton()
    _reset_status(scope="landscape")
    s = _build_summary("rid_x", "2026-10-06T13:00:00Z", "landscape",
                        3, 2, "/loot/x", aborted="")
    for key in (
        "run_id", "started_at", "finished_at", "scope",
        "targets_total", "targets_done",
        "findings_by_severity", "errors_count", "loot_dir",
        "aborted", "per_node",
    ):
        assert key in s, f"missing summary key: {key}"
    assert set(s["findings_by_severity"].keys()) == {
        "CRITICAL", "HIGH", "MEDIUM", "INFO"}


def test_append_run_to_state_is_defensive_against_missing_field():
    """A legacy state loaded without ``logon_banner_runs`` must not
    crash the sweep end — the engine checks hasattr first."""
    legacy = types.SimpleNamespace()  # no logon_banner_runs
    _append_run_to_state(legacy, {"run_id": "x"})   # does not raise
    # And accepts None state (startup-ish race) without blowing up.
    _append_run_to_state(None, {"run_id": "x"})


# ---------------------------------------------------------------------------
# PR4 route pins — static source checks (lightweight)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def gui_src() -> str:
    import pathlib
    return (pathlib.Path(__file__).resolve().parent.parent
            / "modules" / "core" / "sapmap_gui.py").read_text(encoding="utf-8")


def test_actions_scan_logon_banners_route_registered(gui_src: str):
    assert ('@app.route("/api/actions/scan_logon_banners", method="POST")'
            in gui_src)
    assert '@app.route("/api/actions/scan_logon_banners/status")' in gui_src
    assert '@app.route("/api/actions/scan_logon_banners/runs")' in gui_src


def test_actions_sweep_has_409_concurrent_launch_guard(gui_src: str):
    """Load-bearing: _bg unconditionally resets sapmap_stop, so a
    second launch while the first is running would clobber the global
    STOP flag.  The 409 guard must stay."""
    assert "scan_logon_banners_already_running" in gui_src
    assert "response.status = 409" in gui_src


def test_actions_sweep_seeds_status_synchronously_before_bg(gui_src: str):
    """The frontend's first /status poll fires immediately after the
    POST returns — the status singleton must be seeded (via the
    lock-wrapped ``acquire_launch_slot``) BEFORE ``_bg`` hands off,
    or the poll loop sees running=False and early-returns."""
    idx = gui_src.find(
        '@app.route("/api/actions/scan_logon_banners", method="POST")')
    end = gui_src.find('@app.route(', idx + 1)
    body = gui_src[idx:end]
    acquire_pos = body.find("acquire_launch_slot(")
    bg_pos = body.find("_bg(")
    assert 0 <= acquire_pos < bg_pos, (
        "status singleton must be seeded (via acquire_launch_slot) "
        "BEFORE _bg hand-off")


def test_actions_sweep_bg_key_lands_in_active_tasks(gui_src: str):
    """The MCP tool's _wait_for_tasks polls state.active_tasks for the
    key to disappear.  The _bg key format must match the convention."""
    idx = gui_src.find(
        '@app.route("/api/actions/scan_logon_banners", method="POST")')
    end = gui_src.find('@app.route(', idx + 1)
    body = gui_src[idx:end]
    assert '_bg("_scan_logon_banners_sweep"' in body


def test_route_rejects_non_string_single_sid_with_400(gui_src: str):
    """Review finding #7 — a client posting
    ``{"single_sid": 42}`` previously tripped the ``.strip()`` call
    with AttributeError → 500 HTML.  Must land as a controlled 400."""
    idx = gui_src.find(
        '@app.route("/api/actions/scan_logon_banners", method="POST")')
    end = gui_src.find('@app.route(', idx + 1)
    body = gui_src[idx:end]
    assert "bad_single_sid" in body
    assert "isinstance(raw_single_sid, str)" in body


def test_route_launch_uses_atomic_acquire_launch_slot(gui_src: str):
    """Review finding #6 — the launch route must use
    ``acquire_launch_slot`` (the lock-guarded transition) instead of
    the separate ``get_status`` + ``_reset_status`` pair, which was
    a TOCTOU race under concurrent POSTs."""
    idx = gui_src.find(
        '@app.route("/api/actions/scan_logon_banners", method="POST")')
    end = gui_src.find('@app.route(', idx + 1)
    body = gui_src[idx:end]
    assert "acquire_launch_slot(" in body


def test_reset_history_refuses_during_running_sweep(gui_src: str):
    """Review finding #8 — resetting the status singleton while a
    sweep is in flight would clobber its single-writer target_done
    bookkeeping.  Must 409 instead."""
    idx = gui_src.find(
        '@app.route(\n        "/api/actions/scan_logon_banners/reset_history"')
    end = gui_src.find('@app.route(', idx + 1)
    body = gui_src[idx:end]
    assert '"scan_logon_banners_running"' in body
    assert "response.status = 409" in body


def test_reset_history_rejects_non_dict_body(gui_src: str):
    """Review finding #9 — the reset_history route used to call
    ``.get`` on request.json unconditionally, 500-ing on a bare
    JSON array / scalar."""
    idx = gui_src.find(
        '@app.route(\n        "/api/actions/scan_logon_banners/reset_history"')
    end = gui_src.find('@app.route(', idx + 1)
    body = gui_src[idx:end]
    assert "isinstance(_body, dict)" in body
    assert '"error": "bad_body"' in body


def test_write_routes_contain_scan_logon_banners_launcher(gui_src: str):
    """--read-only mode must refuse the POST launcher."""
    assert '"/api/actions/scan_logon_banners",' in gui_src
    # But NOT the GET /status or /runs — those stay out so operators
    # in --read-only can still watch and inspect.
    import re
    m = re.search(r"WRITE_ROUTES = frozenset\(\{(.*?)\}\)", gui_src, re.DOTALL)
    assert m
    body = m.group(1)
    assert "/api/actions/scan_logon_banners/status" not in body
    assert "/api/actions/scan_logon_banners/runs" not in body


# ---------------------------------------------------------------------------
# PR4 frontend pins — static source checks
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def html_src() -> str:
    import pathlib
    return (pathlib.Path(__file__).resolve().parent.parent
            / "modules" / "core" / "sapmap_html.py").read_text(encoding="utf-8")


def test_top_nav_entry_present_without_write_op_class(html_src: str):
    """Pure-read sweep — must NOT carry the write-op class or
    --read-only will hide it (and the scanAllVulns sibling at line
    915 is also no-write-op)."""
    assert "onclick=\"showScanAllLogonBannersModal()\"" in html_src
    assert "Scan All Logon Banners for Secrets" in html_src
    # Negative pin — the top-nav entry row must not include write-op.
    import re
    m = re.search(
        r'<div class="dd-item"[^>]*onclick="showScanAllLogonBannersModal\(\)"',
        html_src)
    assert m, "top-nav entry not found"


def test_map_ctx_menu_entry_wired(html_src: str):
    assert 'data-action="map_scan_all_logon_banners"' in html_src
    assert ("case 'map_scan_all_logon_banners':"
            " showScanAllLogonBannersModal();" in html_src)


def test_frontend_phase_order_matches_backend(html_src: str):
    """phaseOrder in _sweepLogonPollStatus must mirror
    sapmap_logon_sweep.PHASE_ORDER verbatim — a rename on one side
    silently desyncs the progress-panel phase strip."""
    assert ("const phaseOrder = ['idle', 'collect_targets', 'scan', "
            "'report', 'done'];" in html_src)


def test_launch_closes_sibling_panels_first(html_src: str):
    """Shared fixed-position rectangle — if sibling panels aren't
    closed first, a running sweep is invisibly covered by (or covers)
    pwspray / AutoPwn panels."""
    import re
    m = re.search(r"function _sweepLogonShowProgressPanel\([^)]*\) \{.*?panel\.classList\.add\('visible'\);",
                   html_src, re.DOTALL)
    assert m, "_sweepLogonShowProgressPanel body not found"
    body = m.group(0)
    assert "closeAutoPwnPanel()" in body
    assert "closePwsprayPanel()" in body


def test_stop_hits_global_scan_stop_channel(html_src: str):
    """STOP must post to /api/scan/stop so sapmap_stop.is_stop_requested
    sees the flag — the engine's cancel_check reads that same global."""
    assert "function stopLogonBannersSweep()" in html_src
    import re
    m = re.search(r"function stopLogonBannersSweep\(\) \{.*?\n\}",
                   html_src, re.DOTALL)
    assert m
    assert "/api/scan/stop" in m.group(0)


def test_reset_history_uses_double_confirm(html_src: str):
    """Operator must read the warning + confirm twice."""
    import re
    m = re.search(r"async function resetLogonBannerSweepHistory\(\) \{.*?\n\}",
                   html_src, re.DOTALL)
    assert m
    body = m.group(0)
    assert body.count("confirm(") >= 2


def test_results_tabs_carry_user_select_text_wkwebview_override(html_src: str):
    """WKWebView defaults to -webkit-user-select:none; the tab body
    divs MUST explicitly enable text selection or operator copy-paste
    out of the findings table breaks on pywebview-on-macOS."""
    assert (
        'id="sweep-logon-tab-body-findings" style="user-select:text;'
        '-webkit-user-select:text;cursor:text"' in html_src)
    assert (
        'id="sweep-logon-tab-body-history" style="display:none;'
        'user-select:text;-webkit-user-select:text;cursor:text"' in html_src)


# ---------------------------------------------------------------------------
# PR4 script-step registration pins
# ---------------------------------------------------------------------------

def test_script_step_scan_logon_banners_registered():
    from sapmap_script import _map_step
    out = _map_step({"action": "scan_logon_banners",
                      "single_sid": "NPL",
                      "custom_patterns": "CRITICAL: FOO_\\d+"})
    assert out == (
        "POST", "/api/actions/scan_logon_banners",
        {"single_sid": "NPL", "custom_patterns": "CRITICAL: FOO_\\d+"},
        True)


def test_script_step_defaults_to_whole_landscape_no_patterns():
    from sapmap_script import _map_step
    out = _map_step({"action": "scan_logon_banners"})
    assert out == (
        "POST", "/api/actions/scan_logon_banners",
        {"single_sid": "", "custom_patterns": ""},
        True)


def test_script_action_labels_includes_scan_logon_banners():
    from sapmap_script import _ACTION_LABELS
    assert "scan_logon_banners" in _ACTION_LABELS


def test_script_module_docstring_lists_scan_logon_banners():
    import sapmap_script
    assert "scan_logon_banners" in (sapmap_script.__doc__ or "")


def test_script_scan_logon_banners_not_destructive():
    """Pure-read sweep — must NOT be in DESTRUCTIVE_ACTIONS or
    --confirm will be required (regression against the user's
    'okay to ship without the standard write-op pattern' decision)."""
    from sapmap_script import DESTRUCTIVE_ACTIONS
    assert "scan_logon_banners" not in DESTRUCTIVE_ACTIONS


# ---------------------------------------------------------------------------
# PR4 MCP tool pins
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def mcp_src() -> str:
    import pathlib
    return (pathlib.Path(__file__).resolve().parent.parent
            / "modules" / "mcp" / "sapmap_mcp_server.py").read_text(
        encoding="utf-8")


def test_mcp_tool_triplet_registered(mcp_src: str):
    """scan_logon_banners_sweep + scan_logon_banners_status +
    scan_logon_banners_runs — mirrors pwspray_sweep/_status/_runs."""
    assert "def scan_logon_banners_sweep(" in mcp_src
    assert "def scan_logon_banners_status(" in mcp_src
    assert "def scan_logon_banners_runs(" in mcp_src


def _mcp_sweep_body(src: str) -> str:
    """Extract the full body of scan_logon_banners_sweep up to the
    next @mcp.tool() decorator so the pin tests see the whole fn."""
    i = src.find("def scan_logon_banners_sweep(")
    assert i >= 0, "scan_logon_banners_sweep not found"
    j = src.find("@mcp.tool()", i + 1)
    return src[i:j if j > 0 else len(src)]


def test_mcp_sweep_posts_to_right_path_and_waits(mcp_src: str):
    body = _mcp_sweep_body(mcp_src)
    assert "_api(\"POST\", \"/api/actions/scan_logon_banners\"," in body
    assert "_wait_for_tasks(" in body


def test_mcp_tool_has_no_read_only_guard(mcp_src: str):
    """Pure-read sweep — adding _read_only_guard() would needlessly
    block the tool in --read-only engagements where the whole point
    is read-only recon.  Compare with pwspray_sweep (write-op → has
    the guard)."""
    assert "_read_only_guard" not in _mcp_sweep_body(mcp_src)


# ---------------------------------------------------------------------------
# PR4 report section pins
# ---------------------------------------------------------------------------

def test_report_section_appears_only_when_runs_present():
    from sapmap_models import SAPMAPState
    import sapmap_report as rpt
    empty = SAPMAPState()
    assert rpt._logon_banners_section(empty) == []
    assert rpt._html_logon_banners_section(empty) == ""


def test_report_section_lists_run_summary_and_per_node_table():
    from sapmap_models import SAPMAPState
    import sapmap_report as rpt
    s = SAPMAPState()
    s.logon_banner_runs = [{
        "run_id": "logonsweep_test_abcdef",
        "started_at": "2026-10-06T13:00:00Z",
        "finished_at": "2026-10-06T13:00:30Z",
        "scope": "landscape",
        "targets_total": 2,
        "targets_done": 2,
        "findings_by_severity": {
            "CRITICAL": 1, "HIGH": 0, "MEDIUM": 2, "INFO": 0},
        "errors_count": 0,
        "loot_dir": "loot/logon_banners/logonsweep_test_abcdef",
        "aborted": "",
        "per_node": [
            {"sid": "NPL", "ok": True, "error_kind": None,
             "hits_by_severity": {
                 "CRITICAL":1,"HIGH":0,"MEDIUM":2,"INFO":0},
             "pair_count": 7, "loot_text_path": "/x.txt",
             "loot_json_path": "/x.json", "elapsed_s": 0.1},
            {"sid": "S4H", "ok": True, "error_kind": None,
             "hits_by_severity": {
                 "CRITICAL":0,"HIGH":0,"MEDIUM":0,"INFO":0},
             "pair_count": 3, "elapsed_s": 0.05},
        ],
    }]
    md = "\n".join(rpt._logon_banners_section(s))
    assert "## Logon-banner secret sweep (issue #68)" in md
    assert "logonsweep_test_abcdef" in md
    assert "CRITICAL findings | 1" in md
    assert "| NPL |" in md
    assert "| S4H |" in md
    html = rpt._html_logon_banners_section(s)
    assert 'id="sec-logon-banners"' in html
    assert "logonsweep_test_abcdef" in html
    assert "NPL" in html


def test_report_section_never_contains_cleartext_match():
    """Report sections roll up severity counts only — raw match text
    stays on per-node side-panel + on gitignored loot JSON.  Pin the
    invariant so a future refactor can't accidentally expose
    cleartext via the engagement report (which operators email /
    archive)."""
    from sapmap_models import SAPMAPState
    import sapmap_report as rpt
    s = SAPMAPState()
    s.logon_banner_runs = [{
        "run_id": "r_x", "started_at": "", "finished_at": "",
        "scope": "landscape", "targets_total": 1, "targets_done": 1,
        "findings_by_severity": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0,
                                 "INFO": 0},
        "errors_count": 0, "loot_dir": "", "aborted": "",
        "per_node": [{"sid": "NPL", "ok": True,
                      "hits_by_severity":
                          {"CRITICAL":1,"HIGH":0,"MEDIUM":0,"INFO":0},
                      "pair_count": 5}],
    }]
    md = "\n".join(rpt._logon_banners_section(s))
    html = rpt._html_logon_banners_section(s)
    # Even if a future author adds back "match" to per_node, this
    # pin would fire if any obvious cleartext leaked.
    for secret in ("SAPMAP00", "Andinyougo", "basis@example.com"):
        assert secret not in md
        assert secret not in html


# ---------------------------------------------------------------------------
# PR4 state model pins — state.logon_banner_runs roundtrip
# ---------------------------------------------------------------------------

def test_state_logon_banner_runs_roundtrips_through_to_from_dict():
    from sapmap_models import SAPMAPState
    s = SAPMAPState()
    s.logon_banner_runs = [{
        "run_id": "logonsweep_x", "scope": "landscape",
        "targets_total": 3, "targets_done": 3,
        "findings_by_severity": {"CRITICAL":1,"HIGH":0,"MEDIUM":0,"INFO":0},
    }]
    d = s.to_dict()
    assert "logon_banner_runs" in d
    restored = SAPMAPState.from_dict(d)
    assert restored.logon_banner_runs == s.logon_banner_runs


# ---------------------------------------------------------------------------
# Adversarial-review follow-ups (verified findings → pinned regressions)
# ---------------------------------------------------------------------------

def test_cancel_mid_sweep_preserves_per_node_results_in_summary(tmp_path):
    """Review finding #1 — the mid-sweep cancel branch previously
    omitted ``per_node=per_node_results`` from ``_build_summary``, so
    the aborted summary landed in ``state.logon_banner_runs`` with
    an empty ``per_node`` list and the pre-cancel per-node breakdown
    disappeared from the GUI history + engagement report."""
    _reset_singleton()
    _reset_status(scope="landscape")
    state = _state(
        HIT1=_node("HIT1", "ABAP", {3200: "dispatcher"}),
        HIT2=_node("HIT2", "ABAP", {3200: "dispatcher"}),
        HIT3=_node("HIT3", "ABAP", {3200: "dispatcher"}),
    )
    probes = {"n": 0}
    def _cancel():
        probes["n"] += 1
        return probes["n"] >= 3   # cancel AFTER the first scan lands
    sweep_landscape(
        state, LogonSweepConfig(jitter_max_s=0.0),
        cancel_check=_cancel,
        _scan_node_fn=_ok_scan_node, _sleep_fn=lambda s: None,
    )
    assert len(state.logon_banner_runs) == 1
    summary = state.logon_banner_runs[0]
    assert summary["aborted"].startswith("cancelled")
    # Previously summary['per_node'] == [] — now it carries the 1
    # node that completed before the cancel probe tripped.
    assert len(summary["per_node"]) == summary["targets_done"] == 1
    assert summary["per_node"][0]["sid"] == "HIT1"


def test_pre_loop_cancel_also_persists_summary(tmp_path):
    """Review finding #5 — the pre-loop cancel branch previously
    returned without appending to state.logon_banner_runs, so a
    cancelled-before-scan sweep vanished from the history view."""
    _reset_singleton()
    _reset_status(scope="landscape")
    state = _state(HIT1=_node("HIT1", "ABAP", {3200: "dispatcher"}))
    sweep_landscape(
        state, LogonSweepConfig(jitter_max_s=0.0),
        cancel_check=lambda: True,   # trip the pre-loop check
        _scan_node_fn=_ok_scan_node, _sleep_fn=lambda s: None,
    )
    # Even the trivial "cancelled before scan" case lands in the
    # history so the operator can see "I started it and I stopped it".
    assert len(state.logon_banner_runs) == 1
    assert state.logon_banner_runs[0]["aborted"] == "cancelled before scan"
    assert state.logon_banner_runs[0]["targets_done"] == 0


def test_scan_node_exception_still_calls_on_node_finding_and_sleeps(tmp_path):
    """Review finding #2 — the exception path previously `continue`d,
    skipping both the host callback (so per-node side-panel kept
    showing stale pre-crash data) AND the inter-node jitter (so a
    sweep whose scans all crashed burst the dispatchers back-to-back,
    looking indistinguishable from a password spray in the target
    SAL)."""
    _reset_singleton()
    _reset_status(scope="landscape")
    state = _state(
        BAD1=_node("BAD1", "ABAP", {3200: "dispatcher"}),
        BAD2=_node("BAD2", "ABAP", {3200: "dispatcher"}),
    )
    def _scan(host, port, **kwargs):
        raise RuntimeError("boom")
    cb_calls = []
    sleep_calls = []
    sweep_landscape(
        state,
        LogonSweepConfig(jitter_min_s=0.1, jitter_max_s=0.3),
        on_node_finding=lambda sid, result, node: cb_calls.append(
            (sid, result.get("error_kind"))),
        _scan_node_fn=_scan,
        _sleep_fn=lambda s: sleep_calls.append(s),
    )
    # Both nodes get the callback with error_kind='exception'.
    assert cb_calls == [("BAD1", "exception"), ("BAD2", "exception")]
    # And the inter-node sleep fires between them (one sleep call,
    # since there are 2 nodes).
    assert len(sleep_calls) == 1


def test_cancelled_scan_result_not_counted_as_error(tmp_path):
    """Review finding #3 — when the per-node scan_node returns
    ``{error_kind: 'cancelled'}`` because the operator's STOP tripped
    its own cancel probe mid-flight, the sweep MUST NOT double-count
    it as a hard error.  The outer sweep's cancel_check will see the
    same STOP flag and finalise next iter."""
    _reset_singleton()
    _reset_status(scope="landscape")
    state = _state(CAN1=_node("CAN1", "ABAP", {3200: "dispatcher"}))
    def _scan(host, port, **kwargs):
        return {
            "ok": False,
            "sid": kwargs["sid"],
            "host": host, "port": port,
            "error_kind": "cancelled",
            "error": "scan cancelled mid-flight",
            "hits_by_severity": {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"INFO":0},
            "findings": [], "pair_count": 0,
            "run_id": kwargs["run_id"],
        }
    sweep_landscape(
        state, LogonSweepConfig(jitter_max_s=0.0),
        _scan_node_fn=_scan, _sleep_fn=lambda s: None,
    )
    # errors_count stays 0 — cancelled is not a hard error.
    assert state.logon_banner_runs[0]["errors_count"] == 0


def test_enumerate_targets_dedupes_sids_preserving_order(tmp_path):
    """Review finding #4 — a duplicate SID in cfg.sids previously
    enumerated the same node twice, scanning it twice."""
    state = _state(
        A=_node("A", "ABAP", {3200: "dispatcher"}),
        B=_node("B", "ABAP", {3200: "dispatcher"}),
    )
    cfg = LogonSweepConfig(sids=["A", "B", "A", "B", "A"],
                            jitter_max_s=0.0)
    sids = [t["sid"] for t in enumerate_targets(state, cfg)]
    # Dedup preserves the first-occurrence order.
    assert sids == ["A", "B"]


def test_acquire_launch_slot_atomic_concurrent_launch_refused():
    """Review finding #6 — the (check running + seed running=True)
    pair must be atomic, otherwise two near-simultaneous POSTs can
    both read running=False and both spawn _bg threads.  Pin by
    exercising the lock-wrapped helper directly."""
    sw._status = LogonSweepStatus()
    assert sw.acquire_launch_slot(scope="landscape") is True
    # Second call must refuse — the first marked _status.running=True.
    assert sw.acquire_launch_slot(scope="landscape") is False
    # And a true parallel race, hammered through a thread pool, must
    # produce exactly one successful acquire.
    sw._status = LogonSweepStatus()
    import threading as _t
    results = []
    def _try():
        results.append(sw.acquire_launch_slot(scope="landscape"))
    threads = [_t.Thread(target=_try) for _ in range(16)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert sum(1 for r in results if r) == 1, (
        f"exactly one thread must win the slot; got {results}")


def test_rmdir_if_empty_removes_empty_dir(tmp_path):
    from sapmap_logon_sweep import rmdir_if_empty
    empty = tmp_path / "empty"
    empty.mkdir()
    assert rmdir_if_empty(str(empty)) is True
    assert not empty.exists()


def test_rmdir_if_empty_keeps_non_empty_dir(tmp_path):
    from sapmap_logon_sweep import rmdir_if_empty
    nonempty = tmp_path / "nonempty"
    nonempty.mkdir()
    (nonempty / "x.txt").write_text("hello")
    assert rmdir_if_empty(str(nonempty)) is False
    assert nonempty.exists()


def test_rmdir_if_empty_tolerates_missing_or_blank_path(tmp_path):
    from sapmap_logon_sweep import rmdir_if_empty
    assert rmdir_if_empty("") is False
    assert rmdir_if_empty(str(tmp_path / "does_not_exist")) is False
    # Also a FILE (not a dir) must be left alone.
    f = tmp_path / "regular_file.txt"
    f.write_text("x")
    assert rmdir_if_empty(str(f)) is False
    assert f.exists()


def test_sweep_with_no_eligible_targets_removes_loot_husk(tmp_path):
    """Regression pin — the sweep used to leave an empty
    ``loot/logon_banners/<run_id>/`` directory behind every time the
    scope resolved to zero eligible targets, every scan errored out,
    or every banner was clean (operator observed ~20 husks after a
    series of trial runs, screenshot 2026-10-06).  The engine must
    now rmdir the per-run loot dir when it exits with no files
    written to it, and blank the summary's ``loot_dir`` field so the
    GUI history doesn't link to a vanished path.
    """
    import os
    _reset_singleton()
    _reset_status(scope="landscape")
    # No ABAP+dispatcher nodes on the map → sweep ends with zero
    # eligible targets.
    state = _state()
    summary = sw.sweep_landscape(
        state,
        LogonSweepConfig(jitter_max_s=0.0),
        _scan_node_fn=lambda *a, **kw: {
            "ok": True, "findings": [], "pair_count": 0,
            "hits_by_severity": {"CRITICAL": 0, "HIGH": 0,
                                  "MEDIUM": 0, "INFO": 0},
            "loot_text_path": "", "loot_json_path": "",
        },
        _sleep_fn=lambda s: None,
    )
    # No husk left on disk.
    if summary["loot_dir"]:
        assert not os.path.isdir(summary["loot_dir"]), (
            f"empty husk {summary['loot_dir']!r} should have been removed")
    # Summary's loot_dir field is blanked when the husk was removed,
    # so the GUI history + MCP /runs don't link to a vanished path.
    assert summary["loot_dir"] == "" or not os.path.isdir(summary["loot_dir"])


def test_sweep_with_content_keeps_loot_dir(tmp_path):
    """Positive pin — when a per-node scan actually writes files, the
    sweep's loot dir must be preserved (not accidentally rmdir'd)."""
    import os
    _reset_singleton()
    _reset_status(scope="landscape")
    inst = types.SimpleNamespace(instance_nr="00", ports={3200: "dispatcher"})
    state = _state(
        HIT=types.SimpleNamespace(
            sid="HIT", system_type="ABAP",
            instances=[inst], ip="10.0.0.1", hostname="h",
            saprouter=""))

    def _scan_with_real_file(host, port, **kw):
        loot_dir = kw.get("loot_dir") or ""
        if loot_dir:
            os.makedirs(loot_dir, exist_ok=True)
            with open(os.path.join(loot_dir, "witness.txt"), "w") as fh:
                fh.write("real content")
        return {
            "ok": True, "findings": [], "pair_count": 1,
            "raw_text_bytes": 10,
            "hits_by_severity": {"CRITICAL": 0, "HIGH": 0,
                                  "MEDIUM": 0, "INFO": 0},
            "loot_text_path": os.path.join(loot_dir, "witness.txt"),
            "loot_json_path": "",
        }

    summary = sw.sweep_landscape(
        state, LogonSweepConfig(jitter_max_s=0.0),
        _scan_node_fn=_scan_with_real_file,
        _sleep_fn=lambda s: None,
    )
    assert summary["loot_dir"]
    assert os.path.isdir(summary["loot_dir"])
    # Cleanup the real-file lab bowl the test created.
    import shutil
    shutil.rmtree(summary["loot_dir"], ignore_errors=True)


def test_state_logon_banner_runs_default_empty_list():
    """A legacy state loaded without the field roundtrips with an
    empty list, not with KeyError or None."""
    from sapmap_models import SAPMAPState
    s = SAPMAPState()
    assert s.logon_banner_runs == []
    d = s.to_dict()
    assert d["logon_banner_runs"] == []
    restored = SAPMAPState.from_dict(d)
    assert restored.logon_banner_runs == []
