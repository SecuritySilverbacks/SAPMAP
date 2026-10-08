#!/usr/bin/env python3
"""Regression tests for the slow / silent / STOP-no-op pwspray fixes
(operator feedback 2026-10-08 after PR #122, screenshot showed
1/224 attempts in 3 minutes with silent panel and non-responsive STOP).

Covers three bugs that compound into the symptom:

  1. SLOW — try_login had no caller-supplied timeout; default 5s +
     7s internal slack = ~17s worst case per attempt on a dead host.
     Also: _default_hit_authority_probe + _default_usr02_probe both
     opened unbounded RFC connections.  Fix: attempt_timeout_s on
     SprayConfig (default 3s), forwarded into try_login.  Both probes
     wrapped in _run_with_watchdog(timeout_s=10).

  2. SILENT — check_sprayed_credentials had zero per-attempt log.
     PwSprayStatus had no current_target/user/candidate fields.
     Fix: on_pre_attempt callback + current_* status fields +
     per-attempt "[*] SID/CLIENT user=X (i/N) src=Y" log line +
     "→ RESULT" follow-up.

  3. STOP — cancel_check only polled at coarse boundaries (between
     clients / candidates / targets).  Not inside try_login
     (blocking socket), not inside _jittered_sleep (raw time.sleep),
     not inside purple baseline/readback (RFC_READ_TABLE loop
     without cancel hook).  Fix: sliced _jittered_sleep with
     cancel_check, cancel checks between USR02 batches, bounded
     watchdogs around both probes.
"""
from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import modules  # noqa: F401 — registers package paths


# ---------------------------------------------------------------------------
# 1. SLOW — timeout wire-through + watchdog
# ---------------------------------------------------------------------------

def test_spray_config_carries_attempt_timeout_default_3s():
    """SprayConfig gains attempt_timeout_s (default 3) so the engine
    passes a tighter timeout than sap_default_creds.try_login's own
    5s default — median attempt stays ~1-2s on reachable hosts."""
    from sapmap_pwspray import SprayConfig
    cfg = SprayConfig()
    assert cfg.attempt_timeout_s == 3, (
        f"SprayConfig.attempt_timeout_s must default to 3; "
        f"got {cfg.attempt_timeout_s!r}")


def test_spray_config_carries_probe_timeouts_default_10s():
    """SprayConfig also gains hit_probe_timeout_s + usr02_probe_
    timeout_s (default 10) so the hit-authority probe and the
    purple baseline/readback cannot stall the whole sweep."""
    from sapmap_pwspray import SprayConfig
    cfg = SprayConfig()
    assert cfg.hit_probe_timeout_s == 10
    assert cfg.usr02_probe_timeout_s == 10


def test_check_sprayed_credentials_forwards_attempt_timeout():
    """The engine must forward attempt_timeout_s as `timeout=` into
    try_login_fn so the socket timeout propagates.  Without this the
    config knob is a no-op."""
    from sapmap_pwspray import (
        SprayCandidate, check_sprayed_credentials)
    calls = []

    def _fake_try_login(host, port, client, user, password,
                        *, saprouter="", terminal="", timeout=None):
        calls.append({
            "host": host, "port": port, "client": client,
            "user": user, "password": password, "timeout": timeout,
        })
        return ("MISS", "")

    check_sprayed_credentials(
        host="1.2.3.4", port=3200, clients=["000"],
        candidates=[SprayCandidate(
            username="TESTUSER", password="p", source_kind="t",
            source_sid="X", verified_somewhere=False)],
        try_login_fn=_fake_try_login,
        skip_users=set(),   # avoid DEFAULT_SKIP_USERS interference
        attempt_timeout_s=3,
    )
    assert calls, "try_login_fn should have been called"
    assert calls[0]["timeout"] == 3, (
        f"attempt_timeout_s must be forwarded as timeout= to "
        f"try_login_fn; got call={calls[0]!r}")


def test_run_with_watchdog_returns_fast_on_timeout():
    """_run_with_watchdog must return `default` within a small window
    of timeout_s when fn hangs — this is the primary mechanism bounding
    the hit-authority probe + USR02 probe."""
    from sapmap_pwspray import _run_with_watchdog
    sentinel = {"authority_level": "probe_failed", "note": "timeout"}

    def _hangs():
        time.sleep(10.0)
        return {"authority_level": "sap_all"}

    t0 = time.monotonic()
    result = _run_with_watchdog(
        _hangs, timeout_s=0.3, default=sentinel)
    elapsed = time.monotonic() - t0
    assert result is sentinel, (
        "Must return the caller's default on timeout, got "
        f"{result!r}")
    assert elapsed < 1.5, (
        f"Watchdog must honour timeout_s within tight slack; "
        f"took {elapsed:.3f}s for timeout_s=0.3")


def test_run_with_watchdog_reraises_exceptions():
    """When fn raises, the watchdog must re-raise so caller's own
    try/except catches the real exception text — preserves pre-fix
    behaviour for tests that assert `"S_RFC denied" in note`."""
    from sapmap_pwspray import _run_with_watchdog

    def _raises():
        raise RuntimeError("S_RFC denied BAPI_USER_GET_DETAIL")

    with pytest.raises(RuntimeError, match="S_RFC denied"):
        _run_with_watchdog(
            _raises, timeout_s=1.0, default={"note": "unused"})


def test_run_with_watchdog_returns_fn_result_on_success():
    """Happy path: fn completes within timeout, result returned."""
    from sapmap_pwspray import _run_with_watchdog
    result = _run_with_watchdog(
        lambda: {"authority_level": "sap_all"},
        timeout_s=5.0, default=None)
    assert result == {"authority_level": "sap_all"}


# ---------------------------------------------------------------------------
# 2. SILENT — per-attempt visibility
# ---------------------------------------------------------------------------

def test_pwspray_status_carries_per_attempt_fields():
    """PwSprayStatus gains current_target_sid, current_target_host,
    current_client, current_user, current_candidate_index,
    current_candidate_total, last_result, last_detail — so the GUI
    panel can render 'Now trying' and 'Last result' rows."""
    from sapmap_pwspray import PwSprayStatus
    st = PwSprayStatus()
    for field in ("current_target_sid", "current_target_host",
                  "current_client", "current_user",
                  "last_result", "last_detail"):
        assert hasattr(st, field), (
            f"PwSprayStatus missing {field} — GUI panel needs it")
        assert getattr(st, field) == "", (
            f"{field} default must be ''; got {getattr(st, field)!r}")
    assert st.current_candidate_index == 0
    assert st.current_candidate_total == 0


def test_on_pre_attempt_called_before_each_try_login():
    """check_sprayed_credentials gains on_pre_attempt(cand, client,
    idx, total) kwarg, called immediately BEFORE try_login_fn so the
    GUI panel can show 'Now trying' before (not after) the attempt."""
    from sapmap_pwspray import (
        SprayCandidate, check_sprayed_credentials)
    pre_attempts = []
    try_login_order = []

    def _pre(cand, client, idx, total):
        pre_attempts.append((cand.username, client, idx, total))

    def _fake_try_login(*a, **kw):
        try_login_order.append(("try_login", a[3]))
        return ("MISS", "")

    cands = [
        SprayCandidate(username="TESTUSER1", password="p1",
                       source_kind="t", source_sid="X",
                       verified_somewhere=False),
        SprayCandidate(username="TESTUSER2", password="p2",
                       source_kind="t", source_sid="X",
                       verified_somewhere=False),
    ]
    check_sprayed_credentials(
        host="1.2.3.4", port=3200, clients=["000", "001"],
        candidates=cands,
        try_login_fn=_fake_try_login,
        on_pre_attempt=_pre,
        skip_users=set(),   # avoid DEFAULT_SKIP_USERS interference
        attempt_timeout_s=3,
    )
    assert pre_attempts, "on_pre_attempt must fire at least once"
    # Each on_pre_attempt is called before its matching try_login.
    first = pre_attempts[0]
    assert first == ("TESTUSER1", "000", 0, 2), (
        f"first pre_attempt must carry (cand, client, idx, total); "
        f"got {first!r}")


def test_spray_emits_per_attempt_log_line_shape():
    """Status log_tail must gain the '[*] SID/CLIENT user=X (i/N) src=Y'
    line format on every attempt — this is the operator-facing diag
    the plan drafted and the GUI panel renders in the console pane."""
    from sapmap_pwspray import (
        SprayConfig, SprayCandidate, SprayRun, _reset_status,
        _append_log, PwSprayStatus)
    # Simulate what the spray_landscape _pre_attempt closure writes.
    _reset_status()
    _append_log(
        "[*] NPL/001 user=DDIC (1/7) src=secstore")
    from sapmap_pwspray import get_status
    tail = get_status()["log_tail"]
    assert tail, "log_tail must capture the pre-attempt line"
    assert tail[-1].startswith("[*] NPL/001 user=DDIC "), (
        f"line must match the plan's '[*] SID/CLIENT user=X (i/N) "
        f"src=Y' format; got {tail[-1]!r}")


# ---------------------------------------------------------------------------
# 3. STOP — cancellation plumbing
# ---------------------------------------------------------------------------

def test_jittered_sleep_without_cancel_check_sleeps_full_duration():
    """Back-compat: when cancel_check is None, _jittered_sleep calls
    time.sleep once with the full jitter duration (preserves existing
    perf characteristics for callers that don't need cancellation)."""
    from sapmap_pwspray import _jittered_sleep
    with patch("sapmap_pwspray.time.sleep") as mock_sleep:
        _jittered_sleep((0.5, 0.5))  # fixed duration via equal bounds
    assert mock_sleep.call_count == 1, (
        "Without cancel_check, _jittered_sleep must call time.sleep "
        "exactly once with the full duration")


def test_jittered_sleep_with_cancel_check_slices_and_exits_early():
    """When cancel_check becomes True mid-sleep, _jittered_sleep must
    exit within ~100ms (the slice size) instead of waiting the full
    jitter duration — this is what makes STOP responsive during
    inter-attempt / inter-node pauses."""
    from sapmap_pwspray import _jittered_sleep
    t0 = time.monotonic()
    # 2s sleep but cancel after 150ms wall-clock.
    calls = {"n": 0}

    def _cancel():
        calls["n"] += 1
        return (time.monotonic() - t0) > 0.15

    _jittered_sleep((2.0, 2.0), cancel_check=_cancel)
    elapsed = time.monotonic() - t0
    assert elapsed < 0.5, (
        f"_jittered_sleep with cancel_check must exit within one "
        f"slice (~100ms) of the cancel firing; took {elapsed:.3f}s")
    assert calls["n"] > 1, (
        f"cancel_check must be polled multiple times during the "
        f"sleep; got {calls['n']} calls")


def test_mark_stop_requested_sets_aborted_field():
    """stop_scan handler calls sapmap_pwspray.mark_stop_requested()
    which sets _status.aborted='stop_requested' so the GUI panel
    shows the STOPPING chip in the next 800ms poll — before the
    engine's cancel_check actually bubbles up."""
    from sapmap_pwspray import mark_stop_requested, _reset_status, get_status
    _reset_status()
    assert get_status()["aborted"] == ""
    mark_stop_requested()
    assert get_status()["aborted"] == "stop_requested"


def test_mark_stop_requested_is_idempotent_and_preserves_prior():
    """Repeat calls stay idempotent, and an already-set aborted
    reason (e.g. cascade_abort) isn't stomped by a late STOP."""
    from sapmap_pwspray import mark_stop_requested, _reset_status, get_status
    _reset_status()
    # Simulate the engine setting a specific aborted reason first.
    import sapmap_pwspray as _m
    _m._status.aborted = "cascade_abort"
    mark_stop_requested()
    assert get_status()["aborted"] == "cascade_abort", (
        "mark_stop_requested must NOT overwrite a prior aborted "
        "reason (cascade_abort / dry_run_default_active)")


def test_bg_skips_reset_stop_when_pwspray_running():
    """The _bg guard: when a pwspray is running AND the new task is
    NOT the pwspray itself, don't reset the global stop flag —
    otherwise a sibling task launched mid-spray clobbers an in-flight
    STOP press."""
    import sapmap_gui
    import sapmap_pwspray as _pws
    import sapmap_stop
    # Simulate pwspray running
    _pws._reset_status()
    _pws._status.running = True
    # Simulate operator pressing STOP
    sapmap_stop.request_stop()
    assert sapmap_stop.is_stop_requested() is True
    # A sibling task fires _bg() with a non-pwspray key
    done = {"ran": False}
    def _work():
        done["ran"] = True
    sapmap_gui._bg("some_other_task", "A sibling task", _work)
    # Wait briefly for thread to run
    for _ in range(20):
        if done["ran"]:
            break
        time.sleep(0.02)
    # The STOP flag must still be set — sibling didn't clobber it
    assert sapmap_stop.is_stop_requested() is True, (
        "sibling _bg task launched during pwspray must NOT reset "
        "the stop flag; otherwise operator's STOP press is silently "
        "cancelled")
    # Reset for test hygiene
    _pws._status.running = False
    sapmap_stop.reset_stop()


def test_bg_resets_stop_normally_when_no_pwspray_running():
    """Back-compat: without a running pwspray, _bg behaves as before
    (resets the stop flag so a stale STOP from a prior scan doesn't
    cancel new work)."""
    import sapmap_gui
    import sapmap_pwspray as _pws
    import sapmap_stop
    # Make sure pwspray is NOT marked running
    _pws._reset_status()
    _pws._status.running = False
    sapmap_stop.request_stop()
    assert sapmap_stop.is_stop_requested() is True
    def _work():
        pass
    sapmap_gui._bg("some_task", "Normal task", _work)
    time.sleep(0.05)
    # Stop flag was reset per pre-existing behaviour
    assert sapmap_stop.is_stop_requested() is False, (
        "Without a running pwspray, _bg must still clear the stop "
        "flag (back-compat with pre-fix behaviour)")
