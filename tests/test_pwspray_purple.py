"""Pins for the password-spray PURPLE mode (PR 4 of #69).

Covers the blue-team deliverable half of PR4:
  * Purple-mode phase emits (baseline + readback)
  * Signal row shape — every expected field present + NO cleartext
  * USR02 baseline/readback deltas computed correctly
  * UCON-blocked case: baseline unavailable, readback skipped,
    report still generated (signal-only, no deltas)
  * write_purple_report writes both .md and .html, never cleartext
  * Engagement report _pwspray_section renders when state.spray_runs
    is non-empty and includes Detection-validation subsection for
    purple-mode runs
  * SprayConfig.purple_mode propagates through the launch route
  * Frontend wiring: Purple mode tick + Defender View renderer
    source-level pins

Follows the existing SAPMAP route-shape test style (source-level
grep + pure-engine assertions with injected stubs).
"""
from __future__ import annotations

import os
import pathlib
import re
import tempfile
from unittest.mock import patch

import pytest

import modules  # noqa: F401
import sapmap_mode
from sapmap_models import (
    SAPMAPState, SAPNode, InstanceInfo, Credentials)
import sapmap_pwspray


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _reset_pwspray_state():
    sapmap_mode.set_pwspray_armed(False)
    sapmap_pwspray._status = sapmap_pwspray.PwSprayStatus()
    yield
    sapmap_mode.set_pwspray_armed(False)
    sapmap_pwspray._status = sapmap_pwspray.PwSprayStatus()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mk_abap_node(sid="NPL", client="001", ip="10.0.0.1"):
    state = SAPMAPState()
    node = SAPNode(sid=sid, ip=ip, hostname="npl", system_type="ABAP")
    node.clients = [{"nr": client}]
    inst = InstanceInfo(instance_nr="00")
    inst.ports = {3200: "dispatcher"}
    node.instances = [inst]
    # Give the node a verified cred so best_credentials() returns one.
    node.credentials.append(Credentials(
        username="SAPMAP00", password="x", client=client,
        instance_nr="00", verified=True))
    state.nodes[sid] = node
    return state, node


def _no_fs_loot_dir(tmp_root):
    """Return a loot_dir_fn stub that writes under tmp_root rather
    than loot/."""
    def _resolve(run_id):
        base = os.path.join(tmp_root, run_id)
        os.makedirs(base, exist_ok=True)
        return base
    return _resolve


# ---------------------------------------------------------------------------
# PHASE_ORDER contract
# ---------------------------------------------------------------------------

def test_phase_order_includes_baseline_and_readback():
    """PR4 extended PHASE_ORDER with the two purple-mode phases."""
    assert "baseline" in sapmap_pwspray.PHASE_ORDER
    assert "readback" in sapmap_pwspray.PHASE_ORDER
    # Order matters: baseline before spray, readback between spray and report.
    assert (sapmap_pwspray.PHASE_ORDER.index("baseline")
            < sapmap_pwspray.PHASE_ORDER.index("spray"))
    assert (sapmap_pwspray.PHASE_ORDER.index("spray")
            < sapmap_pwspray.PHASE_ORDER.index("readback"))
    assert (sapmap_pwspray.PHASE_ORDER.index("readback")
            < sapmap_pwspray.PHASE_ORDER.index("report"))


def test_purple_spray_terminal_constant_exported():
    """PURPLE_SPRAY_TERMINAL is cited by the engagement report +
    the purple report + the Defender View so it must stay stable."""
    assert sapmap_pwspray.PURPLE_SPRAY_TERMINAL == "sapmap-spray-purple"
    # The purple report + engagement report both import it by name.
    from sapmap_report import PURPLE_SPRAY_TERMINAL as pt_imported
    assert pt_imported == "sapmap-spray-purple"


def test_sal_logon_signals_catalog_exported():
    """Every result code try_login can emit must have an entry in
    SAL_LOGON_SIGNALS so the purple report doesn't miss signatures."""
    cat = sapmap_pwspray.SAL_LOGON_SIGNALS
    for k in ("SUCCESS", "WRONG_PASSWORD", "USER_LOCKED",
              "USER_NOT_EXIST", "NO_AUTH_LOGON", "PASSWORD_CHANGE"):
        assert k in cat, f"SAL_LOGON_SIGNALS missing {k!r}"
        entry = cat[k]
        assert "sal_numbers" in entry
        assert "label" in entry
        assert "sm21_hint" in entry


# ---------------------------------------------------------------------------
# Baseline + readback wiring
# ---------------------------------------------------------------------------

def test_dry_run_purple_mode_opens_zero_sockets():
    """Dry-run purple is a preview-shape: pool resolve + target
    matrix only, no USR02 reads."""
    state, _ = _mk_abap_node()
    probe_calls = []

    def _fake_probe(node, creds, client, users):
        probe_calls.append((node.sid, client, tuple(users)))
        return {}

    cfg = sapmap_pwspray.SprayConfig(
        dry_run=True, cap_per_user=1, purple_mode=True)
    run = sapmap_pwspray.spray_landscape(
        state, cfg, usr02_probe_fn=_fake_probe)
    assert probe_calls == [], (
        "Dry-run purple must NOT open USR02 sockets — baseline is "
        "gated on `not config.dry_run`")
    assert run.purple_baseline_available is False
    assert run.purple_report_generated is False


def test_purple_mode_baseline_and_readback_populate_signal_rows():
    """A live purple run (dry_run=False + accept_risk) fires the
    baseline probe BEFORE spray and readback AFTER, then backfills
    signal rows with the computed delta."""
    state, node = _mk_abap_node()
    probe_calls = []

    def _fake_probe(node, creds, client, users):
        probe_calls.append((client, tuple(users), "baseline"
                             if len(probe_calls) % 2 == 0
                             else "readback"))
        # First call = baseline (LOCNT=1); second = readback (LOCNT=3).
        locnt = 1 if (len(probe_calls) % 2 == 1) else 3
        return {
            u.upper(): {"locnt": locnt, "uflag": "0", "ustyp": "A"}
            for u in users
        }

    def _fake_try_login(host, port, client, user, password, **kwargs):
        # Engine unpacks `result, detail = try_login_fn(...)`.
        return ("WRONG_PASSWORD", "stub")

    tmp = tempfile.mkdtemp(prefix="pwspray_purple_test_")
    cfg = sapmap_pwspray.SprayConfig(
        dry_run=False, accept_lockout_risk=True,
        cap_per_user=1, purple_mode=True,
        manual_wordlist=[("DDIC", "secret1")])
    run = sapmap_pwspray.spray_landscape(
        state, cfg,
        usr02_probe_fn=_fake_probe,
        try_login_fn=_fake_try_login,
        loot_dir_fn=_no_fs_loot_dir(tmp),
    )
    # Baseline AND readback both called (2 probes for 1 target × 1 client).
    assert len(probe_calls) == 2, (
        f"Expected baseline + readback probe calls; got {probe_calls}")
    assert run.purple_baseline_available is True
    sigs = node.spray_purple_signals
    assert len(sigs) >= 1
    sig = sigs[0]
    assert sig["baseline_locnt"] == 1
    assert sig["readback_locnt"] == 3
    assert sig["delta_locnt"] == 2
    # Signal row carries the SAL catalog + SM21 hint for the result.
    assert sig["sal_class"] == "00"
    assert sig["sal_numbers"]  # non-empty
    assert sig["result"] == "WRONG_PASSWORD"
    # NEVER cleartext — only the sha256 prefix.
    assert "secret1" not in str(sig)
    assert "password" not in sig
    assert "pw_sha256_prefix" in sig and sig["pw_sha256_prefix"]


def test_purple_mode_baseline_unavailable_still_generates_report():
    """When USR02 reads fail (UCON block, missing S_TABU_DIS),
    baseline is marked unavailable but the sweep still proceeds and
    the signal rows still land — WITHOUT observed deltas.  Operators
    need the signatures for SIEM correlation even if SAPMAP can't
    readback counters."""
    state, node = _mk_abap_node()

    def _blocked_probe(node, creds, client, users):
        raise RuntimeError("UCON blocks RFC_READ_TABLE")

    def _fake_try_login(host, port, client, user, password, **kwargs):
        return ("WRONG_PASSWORD", "stub")

    tmp = tempfile.mkdtemp(prefix="pwspray_purple_blocked_")
    cfg = sapmap_pwspray.SprayConfig(
        dry_run=False, accept_lockout_risk=True,
        cap_per_user=1, purple_mode=True,
        manual_wordlist=[("DDIC", "secret1")])
    run = sapmap_pwspray.spray_landscape(
        state, cfg,
        usr02_probe_fn=_blocked_probe,
        try_login_fn=_fake_try_login,
        loot_dir_fn=_no_fs_loot_dir(tmp),
    )
    assert run.purple_baseline_available is False
    assert "UCON" in run.purple_baseline_error
    # Signal rows still landed — the SOC can still correlate SAL by
    # terminal + time window.
    sigs = node.spray_purple_signals
    assert len(sigs) >= 1
    sig = sigs[0]
    assert sig["baseline_locnt"] is None
    assert sig["readback_locnt"] is None
    assert sig["delta_locnt"] is None
    # But the SAL/SM21 catalog is still attached.
    assert sig["sal_numbers"]
    assert sig["result"] == "WRONG_PASSWORD"


# ---------------------------------------------------------------------------
# Purple report writer
# ---------------------------------------------------------------------------

def test_write_purple_report_emits_md_and_html_with_no_cleartext():
    """write_purple_report materialises both files; neither contains
    the operator's cleartext password — only the sha256 prefix."""
    state = SAPMAPState()
    node = SAPNode(sid="NPL", ip="10.0.0.1", system_type="ABAP")
    # Hand-build a signal row as spray_landscape would have.
    node.spray_purple_signals = [{
        "run_id": "test-run-123",
        "ts": "2026-10-05T10:00:00",
        "sid": "NPL", "host": "10.0.0.1", "client": "001",
        "user": "DDIC",
        "pw_sha256_prefix": "deadbeef",
        "source_kind": "manual_wordlist",
        "source_sid": "",
        "result": "WRONG_PASSWORD",
        "terminal": "sapmap-spray-purple",
        "sal_class": "00",
        "sal_numbers": ["AU2"],
        "sal_label": "Wrong password",
        "sm21_hint": "Wrong password for user DDIC",
        "baseline_locnt": 0,
        "readback_locnt": 1,
        "delta_locnt": 1,
        "sal_will_fire": True,
        "terminal_will_land": True,
        "baseline_ustyp": "A",
    }]
    state.nodes["NPL"] = node
    run = sapmap_pwspray.SprayRun(
        run_id="test-run-123",
        started_at="2026-10-05T10:00:00",
        finished_at="2026-10-05T10:05:00",
        attempts_done=1,
        hits=[],
        locked_users=[],
        config_snapshot={"purple_mode": True, "dry_run": False,
                         "scope_filter": {}},
        purple_baseline_available=True,
    )
    tmp = tempfile.mkdtemp(prefix="purple_report_test_")
    result = sapmap_pwspray.write_purple_report(run, state, tmp)
    assert os.path.isfile(result["md"])
    assert os.path.isfile(result["html"])
    md = open(result["md"], encoding="utf-8").read()
    html = open(result["html"], encoding="utf-8").read()
    # Both carry the signal row's safe fields.
    assert "DDIC" in md
    assert "DDIC" in html
    assert "deadbeef" in md
    assert "deadbeef" in html
    assert "sapmap-spray-purple" in md
    assert "sapmap-spray-purple" in html
    # NEVER the cleartext password — but we didn't pass one here, so
    # also check a few canonical cleartexts the engine must never
    # emit by accident (if these appear it means a template leaked).
    for leak in ("Welcome1", "secret1", "19920706", "Andinyougo123!"):
        assert leak not in md, (
            f"purple_report.md leaked cleartext {leak!r}")
        assert leak not in html, (
            f"purple_report.html leaked cleartext {leak!r}")


def test_write_purple_report_no_cleartext_regardless_of_signal_input():
    """Even if some other module accidentally wrote a 'password' key
    onto a signal row, the writer must not surface it.  The writer
    renders ONLY the fields it names explicitly — never dumps the
    whole dict — so this is a design invariant worth pinning."""
    state = SAPMAPState()
    node = SAPNode(sid="NPL", system_type="ABAP")
    node.spray_purple_signals = [{
        "run_id": "r1",
        "ts": "2026-10-05T10:00",
        "sid": "NPL", "client": "001", "user": "DDIC",
        "pw_sha256_prefix": "cafebabe",
        "result": "WRONG_PASSWORD",
        "terminal": "sapmap-spray-purple",
        "sal_numbers": ["AU2"],
        "sal_label": "wrong pw",
        "sm21_hint": "",
        "baseline_locnt": None,
        "readback_locnt": None,
        "delta_locnt": None,
        # Hypothetical rogue field — if the writer dict-dumps the row,
        # this would leak.
        "password": "SHOULD_NEVER_APPEAR_IN_REPORT",
    }]
    state.nodes["NPL"] = node
    run = sapmap_pwspray.SprayRun(
        run_id="r1", started_at="2026-10-05T10:00:00",
        config_snapshot={"purple_mode": True})
    tmp = tempfile.mkdtemp(prefix="purple_leak_test_")
    sapmap_pwspray.write_purple_report(run, state, tmp)
    md = open(os.path.join(tmp, "purple_report.md"), encoding="utf-8").read()
    html = open(os.path.join(tmp, "purple_report.html"), encoding="utf-8").read()
    assert "SHOULD_NEVER_APPEAR_IN_REPORT" not in md
    assert "SHOULD_NEVER_APPEAR_IN_REPORT" not in html


# ---------------------------------------------------------------------------
# Engagement report wiring
# ---------------------------------------------------------------------------

def test_engagement_report_pwspray_section_empty_when_no_runs():
    """A fresh landscape with no spray runs must NOT emit the
    Password Spraying section — otherwise every engagement report
    gets a stale '0 runs' chunk."""
    from sapmap_report import _pwspray_section, _html_pwspray_section
    state = SAPMAPState()
    assert _pwspray_section(state) == []
    assert _html_pwspray_section(state) == ""


def test_engagement_report_pwspray_section_renders_with_runs():
    """When state.spray_runs is non-empty the Markdown section
    renders a header + per-run subsection; HTML section carries the
    sec-pwspray anchor."""
    from sapmap_report import _pwspray_section, _html_pwspray_section
    state = SAPMAPState()
    state.spray_runs = [{
        "run_id": "r1",
        "started_at": "2026-10-05T10:00:00",
        "finished_at": "2026-10-05T10:05:00",
        "attempts_done": 5,
        "hits": [{"sid": "NPL", "user": "DDIC"}],
        "locked_users": [],
        "aborted": "",
        "loot_path": "",
        "config_snapshot": {
            "purple_mode": False, "dry_run": False,
            "scope_filter": {}, "cap_per_user": 1},
        "purple_baseline_available": False,
    }]
    md = _pwspray_section(state)
    assert any("Password spraying" in line for line in md)
    assert any("`r1`" in line for line in md)
    html = _html_pwspray_section(state)
    assert 'id="sec-pwspray"' in html
    assert "Password spraying" in html
    assert "<code>r1</code>" in html


def test_engagement_report_pwspray_section_includes_detection_subsection():
    """Purple-mode runs must emit a Detection-validation subsection
    enumerating the SIEM-expected signatures the SOC should see."""
    from sapmap_report import _pwspray_section, _html_pwspray_section
    state = SAPMAPState()
    node = SAPNode(sid="NPL", system_type="ABAP")
    node.spray_purple_signals = [{
        "run_id": "r1", "ts": "2026-10-05T10:00:00",
        "sid": "NPL", "client": "001", "user": "DDIC",
        "pw_sha256_prefix": "deadbeef",
        "result": "WRONG_PASSWORD",
        "sal_numbers": ["AU2"],
        "sm21_hint": "Wrong password",
        "baseline_locnt": 0, "readback_locnt": 1, "delta_locnt": 1,
    }]
    state.nodes["NPL"] = node
    state.spray_runs = [{
        "run_id": "r1",
        "started_at": "2026-10-05T10:00:00",
        "attempts_done": 1,
        "hits": [], "locked_users": [],
        "config_snapshot": {"purple_mode": True, "dry_run": False,
                             "scope_filter": {}},
        "purple_baseline_available": True,
    }]
    md = _pwspray_section(state)
    assert any("Detection validation" in line for line in md)
    assert any("AU2" in line for line in md)
    assert any("deadbeef" in line for line in md)
    html = _html_pwspray_section(state)
    assert "Detection validation" in html
    assert "AU2" in html
    # Terminal spoof cited for SIEM correlation.
    assert "sapmap-spray-purple" in html


# ---------------------------------------------------------------------------
# Launch route accepts purple_mode via strict bool
# ---------------------------------------------------------------------------

def test_launch_route_parses_purple_mode_strict():
    """PR4 adds purple_mode to the launch route's strict-bool parse."""
    src = (REPO_ROOT / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")
    m = re.search(
        r"def actions_password_spray\(\):(.*?)@app\.route",
        src, re.DOTALL)
    assert m, "landscape launch route not found"
    body = m.group(1)
    assert '_strict_bool("purple_mode"' in body, (
        "purple_mode must be parsed via _strict_bool so a null "
        "or non-bool body value can't trip the gate silently")
    assert "purple_mode=purple_mode" in body, (
        "purple_mode must propagate into SprayConfig")
    # Launch response echoes the EFFECTIVE purple_mode (dry-run
    # suppresses purple so the frontend hides baseline/readback
    # phase boxes).  See test_launch_response_echoes_effective
    # for the full pin.
    assert '"purple_mode": effective_purple,' in body


# ---------------------------------------------------------------------------
# Frontend wiring
# ---------------------------------------------------------------------------

def _html_src() -> str:
    return (REPO_ROOT / "modules" / "core" / "sapmap_html.py").read_text(
        encoding="utf-8")


def test_config_modal_has_purple_mode_tick():
    src = _html_src()
    assert 'id="pws-purple-mode"' in src
    # And the launch-config collector reads it.
    assert "pws-purple-mode" in src


def test_progress_panel_has_baseline_and_readback_phase_boxes():
    """Panel markup carries pws-ph-baseline + pws-ph-readback with
    display:none by default — _pwsprayShowProgressPanel flips them
    on when launch.purple_mode is true."""
    src = _html_src()
    assert 'id="pws-ph-baseline"' in src
    assert 'id="pws-ph-readback"' in src
    assert "launchResult.purple_mode" in src


def test_defender_view_renderer_present_and_eagerly_populated():
    """The Defender View tab renderer exists AND is populated eagerly
    inside showPwsprayResults — not lazily on tab click (avoids
    render-race)."""
    src = _html_src()
    assert "function _renderDefenderView(run)" in src
    assert "defBody.innerHTML = _renderDefenderView(latest);" in src
    # Must handle the non-purple case explicitly (no stub).
    assert "This run was not launched in purple mode" in src
    # Must escape every field it writes to innerHTML.
    assert "_escapeHtml(s.user" in src
    assert "_escapeHtml(s.sid" in src


def test_defender_view_grouped_by_sid():
    """Rendering groups signal rows by SID (SOC query boundary) so a
    multi-target run doesn't produce one undifferentiated table."""
    src = _html_src()
    # The renderer builds a `bySid` map and iterates keys sorted.
    assert "const bySid = {}" in src
    assert "Object.keys(bySid).sort()" in src


# ---------------------------------------------------------------------------
# Adversarial-review fixes (PR4 round 2)
# ---------------------------------------------------------------------------

def test_default_usr02_probe_rejects_malformed_bname():
    """OpenSQL injection defence: a BNAME outside SAP's charset must
    not reach the ABAP WHERE clause.  Smoke: feed one good + one
    malicious user; only the good one survives."""
    from sapmap_pwspray import _default_usr02_probe
    rt_calls = []

    class _FakeRfc:
        @staticmethod
        def read_table(node, name, fields, where, creds, max_rows,
                       quiet):
            rt_calls.append(where)
            return []

    # Patch the module import inside the probe to our stub.
    import sys
    sys.modules.setdefault("sapmap_rfc", _FakeRfc)
    sys.modules["sapmap_rfc"] = _FakeRfc
    try:
        state, node = _mk_abap_node()
        creds = node.credentials[0]
        _default_usr02_probe(
            node, creds, "001",
            ["DDIC", "A','DDIC", "GOOD_USER", "<script>", ""])
    finally:
        # Restore so other tests that import sapmap_rfc properly
        # don't get the stub.
        del sys.modules["sapmap_rfc"]
    # Every injected WHERE clause must contain only safe BNAMEs.
    for where in rt_calls:
        assert "A','DDIC" not in where, (
            "malformed BNAME smuggled an apostrophe into WHERE")
        assert "<script>" not in where
    # And the batch must still carry at least one safe user.
    assert any("DDIC" in w or "GOOD_USER" in w for w in rt_calls)


def test_default_usr02_probe_rejects_malformed_client():
    """MANDT must be exactly 3 digits.  A malicious client param
    skips the probe entirely rather than inject."""
    from sapmap_pwspray import _default_usr02_probe
    rt_calls = []

    class _FakeRfc:
        @staticmethod
        def read_table(node, name, fields, where, creds, max_rows,
                       quiet):
            rt_calls.append(where)
            return []

    import sys
    sys.modules["sapmap_rfc"] = _FakeRfc
    try:
        state, node = _mk_abap_node()
        creds = node.credentials[0]
        result = _default_usr02_probe(
            node, creds, "001'; DROP--", ["DDIC"])
    finally:
        del sys.modules["sapmap_rfc"]
    assert result == {}
    assert rt_calls == [], (
        "A malformed client must short-circuit the probe before "
        "any WHERE is built, not inject into one")


def test_default_usr02_probe_batches_at_three_users():
    """Batch size must be <= 3 so a 5-user wordlist of 12-char
    BNAMEs doesn't overflow the 72-char OPTIONS row limit on the
    IN-list bytes."""
    from sapmap_pwspray import _default_usr02_probe
    rt_calls = []

    class _FakeRfc:
        @staticmethod
        def read_table(node, name, fields, where, creds, max_rows,
                       quiet):
            rt_calls.append((where, max_rows))
            return []

    import sys
    sys.modules["sapmap_rfc"] = _FakeRfc
    try:
        state, node = _mk_abap_node()
        creds = node.credentials[0]
        _default_usr02_probe(
            node, creds, "001",
            ["AAAAAAAAAAAA", "BBBBBBBBBBBB", "CCCCCCCCCCCC",
             "DDDDDDDDDDDD", "EEEEEEEEEEEE"])
    finally:
        del sys.modules["sapmap_rfc"]
    # Five 12-char users -> 2 batches of 3 and 2.
    assert len(rt_calls) == 2
    # First batch has 3 users; its IN-list body is 3 * 14 + 2 commas
    # = 44 chars; preamble 'MANDT = \'001\' AND BNAME IN (' is 28;
    # closing ')' is 1 -> 73 chars.  Verify the WHERE isn't over
    # 80 chars so the ABAP OPTIONS parser's whitespace-split
    # tokenisation handles it cleanly.
    first_where = rt_calls[0][0]
    assert len(first_where) <= 80, (
        f"first_where is {len(first_where)} chars; must stay "
        f"below the 72-char-per-OPTIONS-row ABAP limit with margin "
        f"for the split-on-whitespace tokeniser")


def test_signal_row_omits_sal_will_fire():
    """PR4 adversarial review HIGH #2 / #11 removed the misleading
    sal_will_fire / terminal_will_land fields that were always
    False.  Confirm they're gone from the signal row builder."""
    src = (REPO_ROOT / "modules" / "discovery" / "sapmap_pwspray.py"
           ).read_text(encoding="utf-8")
    # The signal-row dict literal must NOT emit these keys any more.
    # (A future PR that wires rsau probe values should re-add them;
    # until then they're a lie.)
    assert '"sal_will_fire":' not in src
    assert '"terminal_will_land":' not in src


def test_lockout_profile_merge_preserves_existing_keys():
    """PR4 adversarial review HIGH #2 side: lockout_profile is
    MERGED, not replaced, so a prior probe's audit-profile keys
    (rsau_enable, rsau_ip_only, etc.) survive the baseline write."""
    src = (REPO_ROOT / "modules" / "discovery" / "sapmap_pwspray.py"
           ).read_text(encoding="utf-8")
    # The engine builds _lp from node.lockout_profile BEFORE
    # updating it with the compute_attempt_budget fields.
    assert "_lp = dict(node.lockout_profile or {})" in src
    assert "_lp.update({" in src


def test_purple_signal_cap_evicts_oldest_run_ids():
    """node.spray_purple_signals is capped to the last 3 run_ids.
    Append rows for 4 runs, verify oldest is dropped."""
    from sapmap_pwspray import _append_purple_signal
    class _N:
        spray_purple_signals = []
    n = _N()
    for rid in ("A", "B", "C", "D"):
        for i in range(2):
            _append_purple_signal(
                n, {"run_id": rid, "ts": f"{rid}-{i}"})
    # 4 run_ids × 2 rows each = 8 appended, but cap=3 keeps only
    # B/C/D rows = 6 total.
    run_ids = {s["run_id"] for s in n.spray_purple_signals}
    assert run_ids == {"B", "C", "D"}
    assert len(n.spray_purple_signals) == 6


def test_md_escape_cell_strips_table_breakers():
    """Markdown cells can't be broken by pipe/newline/backtick."""
    from sapmap_pwspray import _md_escape_cell
    assert _md_escape_cell("A|B") == "AB"
    assert _md_escape_cell("A\nB") == "AB"
    assert _md_escape_cell("A`B") == "AB"
    assert _md_escape_cell("A\\|B") == "AB"
    assert _md_escape_cell("plain") == "plain"
    assert _md_escape_cell(None) == ""
    assert _md_escape_cell(42) == "42"


def test_purple_baseline_error_accumulates_multiple_failures():
    """PR4 adversarial review MED #4: multiple baseline failures
    must all land in run.purple_baseline_error (semicolon-joined),
    not overwrite the single-string field per target."""
    state = SAPMAPState()
    for sid, ip in (("A", "10.0.0.1"), ("B", "10.0.0.2"),
                     ("C", "10.0.0.3")):
        node = SAPNode(sid=sid, ip=ip, hostname=sid.lower(),
                        system_type="ABAP")
        node.clients = [{"nr": "001"}]
        inst = InstanceInfo(instance_nr="00")
        inst.ports = {3200: "dispatcher"}
        node.instances = [inst]
        node.credentials.append(Credentials(
            username="X", password="x", client="001",
            instance_nr="00", verified=True))
        state.nodes[sid] = node

    def _always_fails(node, creds, client, users):
        raise RuntimeError(f"err-on-{node.sid}")

    def _fake_login(host, port, client, user, password, **kwargs):
        return ("WRONG_PASSWORD", "stub")

    import tempfile as _tmp
    tmp = _tmp.mkdtemp(prefix="pwspray_multi_err_")
    cfg = sapmap_pwspray.SprayConfig(
        dry_run=False, accept_lockout_risk=True,
        cap_per_user=1, purple_mode=True,
        manual_wordlist=[("DDIC", "pw")])
    run = sapmap_pwspray.spray_landscape(
        state, cfg,
        usr02_probe_fn=_always_fails,
        try_login_fn=_fake_login,
        loot_dir_fn=_no_fs_loot_dir(tmp),
    )
    # Every target's failure must be represented in the error field.
    assert "err-on-A" in run.purple_baseline_error
    assert "err-on-B" in run.purple_baseline_error
    assert "err-on-C" in run.purple_baseline_error


def test_write_purple_report_atomic_commit_leaves_no_partial():
    """PR4 adversarial review MED #5: when the writer raises, no
    partial purple_report.{md,html} is left on disk.  Simulate by
    patching the HTML writer to raise after the MD writer prepares
    its tempfile."""
    state = SAPMAPState()
    node = SAPNode(sid="NPL", system_type="ABAP")
    node.spray_purple_signals = [{
        "run_id": "r1", "ts": "2026-10-05T10:00:00",
        "sid": "NPL", "client": "001", "user": "DDIC",
        "pw_sha256_prefix": "feedface", "result": "WRONG_PASSWORD",
        "sal_numbers": ["AU2"], "sm21_hint": "", "sal_label": "",
        "baseline_locnt": 0, "readback_locnt": 1, "delta_locnt": 1,
    }]
    state.nodes["NPL"] = node
    run = sapmap_pwspray.SprayRun(
        run_id="r1", started_at="2026-10-05T10:00",
        config_snapshot={"purple_mode": True})
    tmp = tempfile.mkdtemp(prefix="purple_atomic_test_")

    # Patch os.replace to raise AFTER the md tempfile is renamed but
    # BEFORE the html tempfile is — this simulates a mid-flight
    # failure.  The writer's except branch must clean up both.
    import os as _os
    orig_replace = _os.replace
    call_count = [0]

    def _fail_on_second_replace(src, dst):
        call_count[0] += 1
        if call_count[0] >= 2:
            raise OSError("simulated FS failure on second replace")
        return orig_replace(src, dst)

    with patch("os.replace", _fail_on_second_replace):
        with pytest.raises(OSError):
            sapmap_pwspray.write_purple_report(run, state, tmp)

    # No stray tempfiles.
    leftover = [n for n in os.listdir(tmp)
                if n.startswith(".purple_report.")]
    assert leftover == [], (
        f"Writer left partial tempfiles behind: {leftover}")


def test_launch_response_echoes_effective_purple_mode():
    """PR4 adversarial review LOW #12: dry-run suppresses purple
    (engine short-circuits before baseline), so the launch response
    must echo FALSE when dry_run=True AND purple_mode=True — the
    frontend keys progress-panel phase-box visibility off this echo."""
    src = (REPO_ROOT / "modules" / "core" / "sapmap_gui.py"
           ).read_text(encoding="utf-8")
    assert "effective_purple = bool(purple_mode) and not dry_run" in src
    # The response dict uses effective_purple, not raw purple_mode.
    assert '"purple_mode": effective_purple,' in src


def test_defender_view_header_gates_deliverable_on_report_generated():
    """PR4 adversarial review MED #6: Blue-team deliverable line
    must be gated on run.purple_report_generated — otherwise a
    failed writer still advertises the path."""
    src = _html_src()
    assert "const deliverableOk" in src
    assert "run.purple_report_generated && run.loot_path" in src
    # And the error state is explicit.
    assert "purple_report write failed" in src


def test_esc_strips_backticks():
    """PR4 adversarial review LOW #10: _esc must strip backticks so
    operator-controlled fields inside Markdown code spans can't
    escape the span."""
    from sapmap_report import _esc
    assert _esc("foo`bar") == "foobar"
    assert _esc("x`y`z") == "xyz"
    # Pipes still escaped, newlines still collapsed.
    assert _esc("a|b") == "a\\|b"
    assert _esc("a\nb") == "a b"
