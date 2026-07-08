"""ScriptRunner: Tier 3 Death Star action mappings.

Two YAML actions expose Julian Petersohn's ptrace SAL suppressor to
scripted scenarios so an operator can wrap a noisy exploit block
between arm/disarm without clicking through the GUI:

  - action: tier3_arm_death_star     # writes hook binary, ptrace-attaches
  - action: <noisy exploit steps>
  - action: tier3_disarm_death_star  # SIGTERM, restore INT3 bytes

Arming is destructive (writes 91 KB binary + patches disp+work text)
so it lives in DESTRUCTIVE_ACTIONS — a dry-run playbook silently skips
it, only re-runs with --confirm perform the mutation.
"""
from __future__ import annotations

import modules  # noqa: F401  (registers package paths)
from sapmap_script import (
    _map_step, _ACTION_LABELS, DESTRUCTIVE_ACTIONS)


def _step(action, **kw):
    s = {"action": action}
    s.update(kw)
    return s


def test_tier3_arm_death_star_maps_to_launch_endpoint():
    """Empty filter_classes means "suppress ALL event classes" —
    that's the operator-friendly default the GUI already ships."""
    method, path, body, wait = _map_step(_step(
        "tier3_arm_death_star", target="S4H"))
    assert method == "POST"
    assert path == "/api/node/S4H/tier3_sal_death_star_launch"
    assert body == {
        "filter_classes": "",
        "target_pid": "",
        "skip_upload": False,
        "skip_compile": False,
        "verbose": True,
    }
    assert wait is True


def test_tier3_arm_death_star_forwards_filter_classes():
    """Comma-separated SAL classes (e.g. AUW,AU3) narrow the hook to
    only drop matching events — the operator sees everything else in
    SM20 verbatim, which is useful for staged red-team exercises."""
    method, path, body, _ = _map_step(_step(
        "tier3_arm_death_star", target="S4H",
        filter_classes="AUW,AU3"))
    assert body["filter_classes"] == "AUW,AU3"


def test_tier3_arm_death_star_supports_manual_pid_override():
    """When target_pid is set, the C hook attaches ONLY to that PID
    — used for targeted-session scenarios where auto-attaching to
    every worker would be too noisy."""
    method, path, body, _ = _map_step(_step(
        "tier3_arm_death_star", target="S4H", target_pid=7959))
    assert body["target_pid"] == 7959


def test_tier3_arm_death_star_skip_upload_reuses_prior_binary():
    """After a first arm on a target, the binary sits at
    /tmp/sap_audit_hook — skip_upload lets the operator re-arm
    without the 7-minute chunk-upload cost."""
    method, path, body, _ = _map_step(_step(
        "tier3_arm_death_star", target="S4H", skip_upload=True))
    assert body["skip_upload"] is True


def test_tier3_disarm_death_star_maps_to_stop_endpoint():
    """Disarm needs no payload — the target-side stopper reads
    /tmp/sap_audit_hook.pid to find which hook to signal, then
    SIGTERM's it.  Idempotent: safe to run when no hook is armed."""
    method, path, body, wait = _map_step(_step(
        "tier3_disarm_death_star", target="S4H"))
    assert method == "POST"
    assert path == "/api/node/S4H/tier3_sal_death_star_stop"
    assert body == {}
    assert wait is True


def test_tier3_arm_death_star_is_destructive():
    """DESTRUCTIVE_ACTIONS gates require --confirm on the CLI —
    without it the runner logs SKIP and moves on.  Arming Death
    Star writes a 91 KB binary and patches disp+work text, both
    of which are irreversible without a paired disarm, so it
    MUST be in this set.  Regression pin: a future refactor that
    silently removes it would let dry-runs accidentally arm."""
    assert "tier3_arm_death_star" in DESTRUCTIVE_ACTIONS


def test_tier3_disarm_death_star_is_NOT_destructive():
    """Disarming restores state — it's the anti-destructive.  If
    something added it to DESTRUCTIVE_ACTIONS by mistake, a
    dry-run playbook that failed halfway through would never be
    able to clean up its hooks."""
    assert "tier3_disarm_death_star" not in DESTRUCTIVE_ACTIONS


def test_tier3_actions_have_human_labels():
    """The GUI activity bar shows _ACTION_LABELS[action] when the
    runner fires a step.  Missing entries render as raw action
    strings — ugly and inconsistent with the rest of the tool."""
    assert "tier3_arm_death_star" in _ACTION_LABELS
    assert "tier3_disarm_death_star" in _ACTION_LABELS
    assert "Death Star" in _ACTION_LABELS["tier3_arm_death_star"]
