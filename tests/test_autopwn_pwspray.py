"""Pins for the AutoPwn + script + MCP + diff pwspray integration
(PR 5 of #69) — the final piece that wires the engine into the rest
of the SAPMAP workflow.

Covers:
  * AutoPwnConfig gains the four pwspray fields
  * phase3b_password_spray exists, returns the bi-state summary,
    no-ops cleanly when disabled
  * autopwn_run calls phase3b TWICE per wave (symmetric with the
    two phase3_enrich passes) + banner lists PWSPRAY
  * SAPNode._pwspray_tested_triples field + to_dict/from_dict
    round-trip (sorted list)
  * engine writes to _pwspray_tested_triples on every real attempt
  * reset_history wipes the per-node triples (four fields now)
  * script-step password_spray action in sapmap_script.py
  * MCP tools pwspray_sweep / pwspray_status / pwspray_runs
  * diff integration — spray_runs delta section + KPIs

NOTE (issue #69 de-gate): the kernel arm flag was removed; tests
pinning its unarmed / coerce / disable-on-unarmed behaviour were
deleted here.  The confirm dialogs + accept_lockout_risk strict-bool
+ --read-only WRITE_ROUTES gate remain as the real safety.
"""
from __future__ import annotations

import json
import pathlib
import re
import tempfile
from unittest.mock import patch

import pytest

import modules  # noqa: F401
from sapmap_models import (
    SAPMAPState, SAPNode, InstanceInfo, Credentials)
import sapmap_pwspray
import sapmap_autopwn


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _reset_pwspray_state():
    sapmap_pwspray._status = sapmap_pwspray.PwSprayStatus()
    yield
    sapmap_pwspray._status = sapmap_pwspray.PwSprayStatus()


# ---------------------------------------------------------------------------
# AutoPwnConfig fields
# ---------------------------------------------------------------------------

def test_autopwn_config_has_four_pwspray_fields():
    """PR5 adds include_password_spray / pwspray_cap_per_user /
    pwspray_abort_on_lockout / pwspray_purple_mode to AutoPwnConfig
    with safe defaults (off / cap=1 / abort / standard)."""
    cfg = sapmap_autopwn.AutoPwnConfig()
    assert cfg.include_password_spray is False
    assert cfg.pwspray_cap_per_user == 1
    assert cfg.pwspray_abort_on_lockout is True
    assert cfg.pwspray_purple_mode is False


# ---------------------------------------------------------------------------
# phase3b_password_spray tri-state
# ---------------------------------------------------------------------------

def test_phase3b_disabled_returns_disabled():
    """Toggle off → no-op with reason=disabled.  Never reaches the
    arm-gate check or the engine."""
    state = SAPMAPState()
    cfg = sapmap_autopwn.AutoPwnConfig(include_password_spray=False)
    result = sapmap_autopwn.phase3b_password_spray(state, cfg, wave=1)
    assert result == {"ran": False, "reason": "disabled"}


def test_phase3b_enabled_runs_spray_landscape():
    """Toggle on → engine fires.  Patch spray_landscape to prove
    phase3b calls it with the right SprayConfig (dry_run=False,
    accept_risk=True, purple_mode propagated, max_total_locks_per_run
    derived from pwspray_abort_on_lockout)."""
    state = SAPMAPState()
    cfg = sapmap_autopwn.AutoPwnConfig(
        include_password_spray=True,
        pwspray_cap_per_user=2,
        pwspray_abort_on_lockout=True,
        pwspray_purple_mode=True,
    )

    captured = {}

    def _fake_spray(state_arg, cfg_arg, **kw):
        captured["cfg"] = cfg_arg
        # Fabricate a SprayRun-ish return.
        return sapmap_pwspray.SprayRun(
            run_id="r1",
            started_at="2026-10-05T10:00",
            finished_at="2026-10-05T10:05",
            attempts_done=3,
            hits=[{"sid": "A"}],
            locked_users=[],
            aborted="",
        )

    with patch.object(sapmap_pwspray, "spray_landscape", _fake_spray):
        result = sapmap_autopwn.phase3b_password_spray(
            state, cfg, wave=1)

    assert result["ran"] is True
    assert result["attempts"] == 3
    assert result["hits"] == 1
    assert result["locks"] == 0
    assert result["run_id"] == "r1"
    # SprayConfig was built with the toggle values.
    sc = captured["cfg"]
    assert sc.dry_run is False
    assert sc.accept_lockout_risk is True
    assert sc.cap_per_user == 2
    assert sc.purple_mode is True
    # abort_on_lockout=True → max_total_locks_per_run=1
    assert sc.max_total_locks_per_run == 1


def test_phase3b_abort_on_lockout_false_uses_default_breaker():
    """abort_on_lockout=False → engine's default
    DEFAULT_MAX_TOTAL_LOCKS_PER_RUN (3)."""
    cfg = sapmap_autopwn.AutoPwnConfig(
        include_password_spray=True,
        pwspray_abort_on_lockout=False,
    )

    captured = {}

    def _fake_spray(state_arg, cfg_arg, **kw):
        captured["cfg"] = cfg_arg
        return sapmap_pwspray.SprayRun(
            run_id="r2", started_at="2026-10-05T10:00",
            attempts_done=0, hits=[], locked_users=[])

    with patch.object(sapmap_pwspray, "spray_landscape", _fake_spray):
        sapmap_autopwn.phase3b_password_spray(
            SAPMAPState(), cfg, wave=1)
    assert (captured["cfg"].max_total_locks_per_run
            == sapmap_pwspray.DEFAULT_MAX_TOTAL_LOCKS_PER_RUN)


# ---------------------------------------------------------------------------
# autopwn_run orchestrator — phase3b called twice per wave
# ---------------------------------------------------------------------------

def test_autopwn_run_calls_phase3b_twice_per_wave_in_source():
    """Source-level pin: phase3b_password_spray is called BOTH
    after the first phase3_enrich (newly-pwned) AND after the
    second phase3_enrich (propagated-pwned).  The two-call pattern
    mirrors phase4b/4c and relies on _pwspray_tested_triples
    idempotency so wave N doesn't re-burn triples from wave N-1."""
    src = (REPO_ROOT / "modules" / "exploitation" /
           "sapmap_autopwn.py").read_text(encoding="utf-8")
    # Count assignment-invocation sites — the pattern 'X = phase3b_
    # password_spray(' appears exactly where autopwn_run calls the
    # phase.  The definition itself ('def phase3b_password_spray(...)
    # ') uses no assignment so it's naturally excluded.  Allows the
    # second call to be split across lines.
    call_sites = len(re.findall(
        r"=\s*phase3b_password_spray\(", src))
    assert call_sites >= 2, (
        f"autopwn_run must invoke phase3b_password_spray twice per "
        f"wave — once after newly-pwned enrich, once after "
        f"propagated enrich — found {call_sites} call site(s)")


def test_autopwn_banner_lists_pwspray_when_enabled():
    """Startup banner must list PWSPRAY among optional phases so the
    operator can confirm their toggle landed."""
    src = (REPO_ROOT / "modules" / "exploitation" /
           "sapmap_autopwn.py").read_text(encoding="utf-8")
    assert 'opts.append(\n            "PWSPRAY"' in src or \
            'opts.append("PWSPRAY"' in src
    # Purple mode is reflected in the banner too.
    assert "+purple" in src


def test_autopwn_launch_route_has_no_arm_coercion():
    """De-gate (issue #69): /api/actions/autopwn no longer coerces
    include_password_spray against an arm bit — it passes the raw
    body boolean straight through to AutoPwnConfig.  Negative pin."""
    src = (REPO_ROOT / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")
    m = re.search(
        r"def actions_autopwn\(\):(.*?)def _run\(\):",
        src, re.DOTALL)
    assert m, "actions_autopwn handler not found"
    body = m.group(1)
    # No arm-gate wiring any more.
    assert "is_pwspray_armed as _is_pw_armed" not in body
    assert "_effective_pw" not in body
    assert "autopwn.pwspray_coerced" not in body
    # Raw body bool reaches AutoPwnConfig (newline-tolerant match
    # because the call wraps across two lines).
    collapsed = re.sub(r"\s+", " ", body)
    assert ('include_password_spray=bool( '
            'data.get("include_password_spray", False))') in collapsed


# ---------------------------------------------------------------------------
# SAPNode._pwspray_tested_triples idempotency
# ---------------------------------------------------------------------------

def test_sapnode_pwspray_tested_triples_default_empty_set():
    n = SAPNode(sid="A")
    assert isinstance(n._pwspray_tested_triples, set)
    assert n._pwspray_tested_triples == set()


def test_sapnode_pwspray_tested_triples_round_trip():
    """to_dict → from_dict preserves the triples set (serialised as
    a sorted list for deterministic JSON).  Keys use the FULL sha256
    (not the 8-char prefix) to prevent weak-password brute-force
    from a leaked .sapmap (PR5 adversarial review LOW #11)."""
    n = SAPNode(sid="A")
    k1 = "001|DDIC|" + ("de" * 32)
    k2 = "001|SAPMAP00|" + ("ca" * 32)
    n._pwspray_tested_triples = {k1, k2}
    d = n.to_dict()
    assert d["_pwspray_tested_triples"] == sorted([k1, k2])
    n2 = SAPNode.from_dict(d)
    assert n2._pwspray_tested_triples == {k1, k2}


def test_engine_records_triples_on_real_attempts():
    """Engine must write to node._pwspray_tested_triples on every
    non-skipped attempt so a wave-N re-run skips those triples."""
    state = SAPMAPState()
    node = SAPNode(sid="NPL", ip="10.0.0.1", system_type="ABAP")
    node.clients = [{"nr": "001"}]
    inst = InstanceInfo(instance_nr="00")
    inst.ports = {3200: "dispatcher"}
    node.instances = [inst]
    state.nodes["NPL"] = node

    def _fake_try(host, port, client, user, password, **kw):
        return ("WRONG_PASSWORD", "stub")

    tmp = tempfile.mkdtemp(prefix="triples_test_")

    def _loot_dir(run_id):
        import os
        base = tmp + "/" + run_id
        os.makedirs(base, exist_ok=True)
        return base

    # TESTUSER is NOT in DEFAULT_SKIP_USERS, so the engine actually
    # dials this (client, user) and records the triple.  DDIC would
    # be short-circuited to kind=skipped.
    cfg = sapmap_pwspray.SprayConfig(
        dry_run=False, accept_lockout_risk=True,
        cap_per_user=1,
        manual_wordlist=[("TESTUSER", "wrongpw")])
    sapmap_pwspray.spray_landscape(
        state, cfg,
        try_login_fn=_fake_try,
        loot_dir_fn=_loot_dir)
    # Node now has the (client, user, full_sha256) triple recorded.
    assert len(node._pwspray_tested_triples) == 1
    key = next(iter(node._pwspray_tested_triples))
    assert key.startswith("001|TESTUSER|")
    # Full sha256 is 64 hex chars (not the 8-char prefix) — PR5
    # LOW #11 made this change to prevent weak-password brute-force
    # from a leaked .sapmap.
    pw_part = key.rsplit("|", 1)[1]
    assert len(pw_part) == 64, (
        f"Triple key must use the FULL sha256 (64 hex chars) — got "
        f"{len(pw_part)} chars.  See PR5 adversarial review LOW #11.")


# ---------------------------------------------------------------------------
# reset_history wipes the fourth field
# ---------------------------------------------------------------------------

def test_reset_history_wipes_four_fields_in_source():
    """PR5 extends reset_history to also wipe
    node._pwspray_tested_triples.  Source-level pin."""
    src = (REPO_ROOT / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")
    m = re.search(
        r"def actions_password_spray_reset_history\(\):(.*?)@app\.route",
        src, re.DOTALL)
    assert m, "reset_history handler not found"
    body = m.group(1)
    assert "api.state.spray_attempts_counter = {}" in body
    assert "api.state.pwspray_locked_users = {}" in body
    assert "api.state.spray_runs = []" in body
    # Per-node triples cleared via a loop.
    assert "_pwspray_tested_triples = set()" in body
    # Response reports the new counter.
    assert '"triples_cleared": triples_cleared,' in body


# ---------------------------------------------------------------------------
# Script-step password_spray action
# ---------------------------------------------------------------------------

def test_script_step_password_spray_action():
    """sapmap_script._map_step must recognise 'password_spray' and
    emit a POST to /api/actions/password_spray with the full set
    of knobs the backend's strict-bool parser accepts.

    Scope wire-fields (post-#107): the step reads EITHER `sids`
    (new, multi-SID) OR `single_sid` (legacy) from the YAML, and
    forwards whichever is set as the matching HTTP body key.  Both
    source references must stay present so new YAML can use `sids`
    and pre-#107 YAML keeps working."""
    src = (REPO_ROOT / "modules" / "automation" /
           "sapmap_script.py").read_text(encoding="utf-8")
    assert 'if action == "password_spray":' in src
    assert '"/api/actions/password_spray"' in src
    # Non-scope fields — stay as literal keys in the payload dict.
    for field in (
        '"dry_run":',
        '"accept_lockout_risk":',
        '"include_production":',
        '"accept_production_risk":',
        '"cap_per_user":',
        '"purple_mode":',
    ):
        assert field in src, (
            f"script-step payload missing field: {field}")
    # Scope wire-fields (#107): both are read from the YAML step so
    # new multi-SID playbooks and legacy single-SID playbooks both work.
    assert 'step.get("sids")' in src, (
        "script-step must read `sids` from YAML (post-#107 multi-SID)")
    assert 'step.get("single_sid")' in src, (
        "script-step must still read `single_sid` from YAML (legacy "
        "wire-field, back-compat with pre-#107 playbooks)")
    # Both are forwarded as HTTP body keys when set.
    assert '"sids"' in src
    assert '"single_sid"' in src


def test_script_action_label_registered():
    """GUI activity bar needs a human-readable label."""
    src = (REPO_ROOT / "modules" / "automation" /
           "sapmap_script.py").read_text(encoding="utf-8")
    assert '"password_spray":             "Running password spray",' in src


def test_demo_pwspray_yaml_exists_and_is_dry_run_default():
    """scripts/demo_pwspray.yaml ships a safe-default playbook."""
    path = REPO_ROOT / "scripts" / "demo_pwspray.yaml"
    assert path.exists(), "scripts/demo_pwspray.yaml not shipped"
    text = path.read_text(encoding="utf-8")
    assert "- action: password_spray" in text
    assert "dry_run: true" in text
    # Live block is COMMENTED OUT so a user running the demo doesn't
    # accidentally go live.
    assert "# - action: password_spray" in text


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------

def test_mcp_pwspray_sweep_tool_exposed():
    """MCP server exposes pwspray_sweep with the full knob set.

    Post-#107 adds a `sids: str = ""` kwarg (comma-separated SIDs
    for multi-SID runs — flat type for LLM agents) alongside the
    legacy `single_sid` kwarg which stays for back-compat with
    pre-#107 LLM-generated tool calls."""
    src = (REPO_ROOT / "modules" / "mcp" /
           "sapmap_mcp_server.py").read_text(encoding="utf-8")
    assert "def pwspray_sweep(dry_run: bool = True," in src
    for kw in (
        "cap_per_user:", "purple_mode:", "single_sid:",
        "accept_lockout_risk:", "include_production:",
        "accept_production_risk:",
    ):
        assert kw in src
    # Default safe = dry_run True (model can't accidentally go live).
    assert "def pwspray_sweep(dry_run: bool = True" in src
    # Issue #107 — new multi-SID kwarg
    assert "sids: str = \"\"" in src, (
        "pwspray_sweep MCP tool must expose `sids: str = \"\"` kwarg "
        "for multi-SID runs (issue #107)")


def test_mcp_pwspray_status_and_runs_tools_exposed():
    src = (REPO_ROOT / "modules" / "mcp" /
           "sapmap_mcp_server.py").read_text(encoding="utf-8")
    assert "def pwspray_status()" in src
    assert "def pwspray_runs()" in src
    # Both GET endpoints — no _wait_for_tasks (read-only).
    import re as _re
    m = _re.search(
        r"def pwspray_status\(\).*?def pwspray_runs\(",
        src, _re.DOTALL)
    assert m
    status_body = m.group(0)
    assert "_wait_for_tasks" not in status_body


# ---------------------------------------------------------------------------
# Diff integration
# ---------------------------------------------------------------------------

def test_diff_spray_runs_key_added_to_dict():
    """compute_state_diff emits a 'spray_runs' key with the three
    buckets."""
    from sapmap_diff import compute_state_diff
    a = SAPMAPState()
    b = SAPMAPState()
    diff = compute_state_diff(a, b)
    assert "spray_runs" in diff
    assert set(diff["spray_runs"].keys()) == {
        "added", "removed", "locked_users_added",
    }


def test_diff_spray_runs_delta_populates_on_new_run():
    """A SprayRun added between snapshots lands in diff.spray_runs.added
    + the summary KPIs reflect it."""
    from sapmap_diff import compute_state_diff
    a = SAPMAPState()
    b = SAPMAPState()
    b.spray_runs = [{
        "run_id": "r1",
        "started_at": "2026-10-05T10:00:00",
        "finished_at": "2026-10-05T10:05:00",
        "attempts_done": 5,
        "hits": [{"sid": "A"}, {"sid": "B"}],
        "locked_users": [],
        "aborted": "",
        "config_snapshot": {"purple_mode": True, "dry_run": False,
                             "scope_filter": {}},
        "purple_report_generated": True,
        "loot_path": "/tmp/loot/spray/r1",
    }]
    diff = compute_state_diff(a, b)
    assert len(diff["spray_runs"]["added"]) == 1
    added = diff["spray_runs"]["added"][0]
    assert added["run_id"] == "r1"
    assert added["hits_count"] == 2
    assert added["purple_mode"] is True
    s = diff["summary"]
    assert s["spray_runs_added"] == 1
    assert s["spray_hits_added"] == 2
    assert s["purple_runs_added"] == 1


def test_diff_newly_locked_users_populate():
    """Users added to state.pwspray_locked_users between snapshots
    surface in diff.spray_runs.locked_users_added."""
    from sapmap_diff import compute_state_diff
    a = SAPMAPState()
    b = SAPMAPState()
    b.pwspray_locked_users = {
        "DDIC": {
            "username": "DDIC",
            "locked_on": [["NPL", "001", "2026-10-05T10:00:00"]],
            "unlock_eta": None,
        },
    }
    diff = compute_state_diff(a, b)
    assert len(diff["spray_runs"]["locked_users_added"]) == 1
    u = diff["spray_runs"]["locked_users_added"][0]
    assert u["username"] == "DDIC"
    assert u["first_locked_sid"] == "NPL"
    assert diff["summary"]["newly_locked_users"] == 1


def test_diff_markdown_renders_pwspray_section():
    """build_diff_markdown emits a '## 🔓 Password spraying (delta)'
    section when spray_runs.added or locked_users_added is non-empty."""
    from sapmap_diff import compute_state_diff, build_diff_markdown
    a = SAPMAPState()
    b = SAPMAPState()
    b.spray_runs = [{
        "run_id": "rr",
        "started_at": "2026-10-05T10:00:00",
        "finished_at": "2026-10-05T10:05:00",
        "attempts_done": 1,
        "hits": [], "locked_users": [], "aborted": "",
        "config_snapshot": {"purple_mode": False, "dry_run": False,
                             "scope_filter": {}},
    }]
    diff = compute_state_diff(a, b)
    md = build_diff_markdown(diff)
    assert "Password spraying" in md
    assert "`rr`" in md
    # KPI table rows.
    assert "Password-spray runs (delta)" in md
    assert "Newly-locked users (defender-visible)" in md


# ---------------------------------------------------------------------------
# Frontend wiring (source-level)
# ---------------------------------------------------------------------------

def test_autopwn_modal_has_pwspray_group():
    """AutoPwn modal exposes the four pwspray controls.  De-gate
    (issue #69): the apwn-pwspray-unarmed-hint helper and the
    unarmed-disable logic were removed with the arm gate."""
    src = (REPO_ROOT / "modules" / "core" /
           "sapmap_html.py").read_text(encoding="utf-8")
    assert 'id="apwn-pwspray-group"' in src
    for id_ in (
        'id="apwn-pwspray"',
        'id="apwn-pwspray-cap"',
        'id="apwn-pwspray-abort-on-lockout"',
        'id="apwn-pwspray-purple"',
    ):
        assert id_ in src
    # Negative pins — none of the arm-gate wiring may regress in.
    assert 'id="apwn-pwspray-unarmed-hint"' not in src
    assert "el.disabled = !pwsprayArmed" not in src


def test_autopwn_launch_posts_pwspray_fields():
    """launchAutoPwn() posts the four pwspray fields in its body."""
    src = (REPO_ROOT / "modules" / "core" /
           "sapmap_html.py").read_text(encoding="utf-8")
    for field in (
        "include_password_spray:",
        "pwspray_cap_per_user:",
        "pwspray_abort_on_lockout:",
        "pwspray_purple_mode:",
    ):
        assert field in src


# ---------------------------------------------------------------------------
# PR5 adversarial-review fixes
# ---------------------------------------------------------------------------

def test_engine_dedup_actually_skips_already_tested_triples():
    """CRITICAL fix: check_sprayed_credentials accepts a
    tested_triples set and emits kind=skipped with reason=
    already_tested_triple when a (client, user, sha256) is
    already in the set.  Without this, multi-wave AutoPwn eats
    the per-user cap afresh each wave."""
    import hashlib as _hl
    from sapmap_pwspray import (
        check_sprayed_credentials, SprayCandidate,
    )
    calls = []

    def _fake_try(host, port, client, user, password, **kw):
        calls.append((client, user, password))
        return ("WRONG_PASSWORD", "stub")

    pw = "pw1"
    pw_full = _hl.sha256(pw.encode()).hexdigest()
    tested = {f"001|BOB|{pw_full}"}
    results = []

    def _on_result(row):
        results.append(row)

    check_sprayed_credentials(
        "10.0.0.1", 3200, ["001"],
        [SprayCandidate(username="BOB", password=pw,
                         source_kind="manual_wordlist", source_sid="",
                         verified_somewhere=False)],
        cap_per_user=1,
        skip_users=set(),
        try_login_fn=_fake_try,
        tested_triples=tested,
        inter_attempt_sleep_range=(0.0, 0.0),
        on_result=_on_result,
    )
    # No dial should have fired for an already-tested triple.
    assert calls == [], (
        f"check_sprayed_credentials should have skipped the "
        f"already-tested triple, but try_login was called: {calls}")
    # And the row emitted carries the dedup reason.
    assert any(r.get("skipped_reason") == "already_tested_triple"
                for r in results)


def test_spray_landscape_passes_tested_triples_to_engine():
    """Source-level pin: spray_landscape forwards
    node._pwspray_tested_triples to check_sprayed_credentials so
    the dedup READ actually fires."""
    src = (REPO_ROOT / "modules" / "discovery" /
           "sapmap_pwspray.py").read_text(encoding="utf-8")
    assert "tested_triples=(node._pwspray_tested_triples" in src


def test_phase3b_run_wide_lock_budget_blocks_second_wave():
    """abort_on_lockout now holds for the WHOLE run, not just
    per-wave.  _PWSPRAY_RUN_LOCKS carries locks across waves;
    phase3b returns run_wide_lock_budget_exhausted on wave 2+ when
    the list is non-empty and abort_on_lockout is True."""
    # Hand-pollute the run-wide lock list to simulate wave 1
    # having locked a user.
    sapmap_autopwn._PWSPRAY_RUN_LOCKS[:] = ["DDIC"]
    cfg = sapmap_autopwn.AutoPwnConfig(
        include_password_spray=True,
        pwspray_abort_on_lockout=True,
    )
    result = sapmap_autopwn.phase3b_password_spray(
        SAPMAPState(), cfg, wave=2)
    assert result["ran"] is False
    assert result["reason"] == "run_wide_lock_budget_exhausted"
    assert result["run_locks_so_far"] == ["DDIC"]
    sapmap_autopwn._PWSPRAY_RUN_LOCKS.clear()


def test_phase3b_run_wide_lock_budget_disabled_when_abort_off():
    """When abort_on_lockout=False, the engine's default breaker (3)
    applies and the cross-wave check is skipped — multi-wave sprays
    are allowed to accumulate locks."""
    sapmap_autopwn._PWSPRAY_RUN_LOCKS[:] = ["X", "Y"]
    cfg = sapmap_autopwn.AutoPwnConfig(
        include_password_spray=True,
        pwspray_abort_on_lockout=False,
    )

    def _fake_spray(state_arg, cfg_arg, **kw):
        return sapmap_pwspray.SprayRun(
            run_id="r", started_at="t", attempts_done=0,
            hits=[], locked_users=[])

    with patch.object(sapmap_pwspray, "spray_landscape", _fake_spray):
        result = sapmap_autopwn.phase3b_password_spray(
            SAPMAPState(), cfg, wave=2)
    assert result["ran"] is True
    sapmap_autopwn._PWSPRAY_RUN_LOCKS.clear()


def test_autopwn_run_resets_pwspray_lock_budget():
    """autopwn_run must call _pwspray_reset_run_locks() so each
    operator-initiated run starts with a fresh budget."""
    src = (REPO_ROOT / "modules" / "exploitation" /
           "sapmap_autopwn.py").read_text(encoding="utf-8")
    assert "_pwspray_reset_run_locks()" in src
    assert "def _pwspray_reset_run_locks(" in src


def test_demo_pwspray_yaml_actions_exist():
    """scripts/demo_pwspray.yaml must reference actions that actually
    exist in _map_step so the playbook doesn't crash on step 1."""
    yaml_text = (REPO_ROOT / "scripts" / "demo_pwspray.yaml"
                  ).read_text(encoding="utf-8")
    script_src = (REPO_ROOT / "modules" / "automation" /
                   "sapmap_script.py").read_text(encoding="utf-8")
    import re
    # Pull every 'action: <name>' not in a comment.
    actions = set()
    for line in yaml_text.splitlines():
        s = line.strip()
        if s.startswith("#"):
            continue
        m = re.match(r"-\s*action:\s*(\w+)", s)
        if m:
            actions.add(m.group(1))
    # Every action string must appear in sapmap_script.py's dispatcher.
    assert actions, "no actions found in demo_pwspray.yaml"
    for a in actions:
        assert f'action == "{a}"' in script_src, (
            f"demo_pwspray.yaml references unknown action: {a!r} "
            f"(not registered in sapmap_script._map_step)")


def test_sapmap_script_docstring_lists_password_spray():
    """Operator-facing supported-actions catalog in the module
    docstring must include password_spray so grep + pydoc find it."""
    src = (REPO_ROOT / "modules" / "automation" /
           "sapmap_script.py").read_text(encoding="utf-8")
    # Pull the first docstring (the module one).
    import re
    m = re.search(r'^"""(.*?)"""', src, re.DOTALL | re.MULTILINE)
    assert m, "sapmap_script module docstring not found"
    doc = m.group(1)
    assert "password_spray" in doc


def test_diff_markdown_renders_removed_runs_case():
    """Markdown diff emits a '🧹 Runs removed from history' section
    when sr.removed is non-empty — PR5 adversarial review LOW #5.
    Simulate reset_history fired between the two snapshots: baseline
    has a run, current doesn't."""
    from sapmap_diff import compute_state_diff, build_diff_markdown
    base = SAPMAPState()
    base.spray_runs = [{
        "run_id": "r_gone",
        "started_at": "2026-10-05T09:00:00",
        "finished_at": "2026-10-05T09:05:00",
        "attempts_done": 7, "hits": [{"sid": "A"}],
        "locked_users": [], "aborted": "",
        "config_snapshot": {"purple_mode": False, "dry_run": False,
                             "scope_filter": {}},
    }]
    curr = SAPMAPState()  # reset_history wiped it
    diff = compute_state_diff(base, curr)
    md = build_diff_markdown(diff)
    assert "Runs removed from history" in md
    assert "`r_gone`" in md


def test_diff_html_renders_pwspray_section_and_kpis():
    """build_diff_html carries a '🔓 Password spraying' section +
    four pwspray KPI cards.  PR5 adversarial review MED #9."""
    src = (REPO_ROOT / "modules" / "core" /
           "sapmap_diff.py").read_text(encoding="utf-8")
    assert '<h2>🔓 Password spraying (issue #69)</h2>' in src
    for label in (
        "Password-spray runs", "Spray hits",
        "Newly-locked users", "Purple-mode runs",
    ):
        assert f'_delta_kpi("{label}' in src
