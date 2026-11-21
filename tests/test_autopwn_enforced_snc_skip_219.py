"""AutoPwn skips the plain-RFC exploit pass on enforced-SNC nodes.

Issue #219 — Phase H of the #167 SNC classifier arc.  A node whose
``snc_posture`` is one of ``enforced_no_creds``,
``enforced_handshake_failed`` or ``enforced_logon_failed`` has the
plain 33NN dispatcher closed by definition; AutoPwn should skip the
whole phase-2 pass for those nodes with a clear one-liner so the
operator sees the SNC posture is shaping the plan — not read a
confusing "connection refused" five seconds per attempt.

Tests:
  1. an enforced_no_creds node is skipped from phase2 with the correct
     log line and no exploit dispatch;
  2. the three enforced_* variants all skip, and the skip message
     carries the posture value;
  3. a reachable_auth node is NOT skipped (regression floor);
  4. the config toggle (default True) can be flipped OFF to re-enable
     the plain-RFC pass for defender probing;
  5. the phase summary line carries the skipped count.

These tests patch every exploit entry-point on ``sapmap_exploit`` with
a sentinel that fails the test if invoked.  That way "skipped" means
"exploit code was never reached" — the strongest possible assertion.
"""
import sys
import os

import pytest

from sapmap_models import SAPMAPState, SAPNode
import sapmap_autopwn
from sapmap_autopwn import AutoPwnConfig, phase2_exploit


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _vuln_node(sid: str, snc_posture: str = "") -> SAPNode:
    """Build a node whose ``gw_vulnerable`` flag is True — phase2 will
    try to dispatch GW SAPXPG against it unless an earlier guard
    intervenes."""
    n = SAPNode(sid=sid, hostname=f"{sid.lower()}host",
                ip=f"10.0.0.{len(sid)}")
    n.gw_vulnerable = True
    n.snc_posture = snc_posture
    n.system_type = "ABAP"   # eligible for GW SAPXPG
    return n


@pytest.fixture
def no_dispatch(monkeypatch):
    """Make every exploit entry-point on sapmap_exploit explode if
    invoked — so phase2 skipping translates to zero calls, strongly."""
    import sapmap_exploit

    def _never(*args, **kwargs):
        raise AssertionError(
            f"exploit dispatched against an enforced-SNC node — "
            f"the skip guard did not fire. args={args!r} kwargs={kwargs!r}")

    for name in (
        "create_user_gw_exploit",
        "create_user_via_dpmon_sap_star",
        "drop_cve_2025_31324_shell",
        "create_user_java",
        "run_recon_chain",
        "run_10kblaze_chain",
        "_post_exploit_enrichment",
    ):
        if hasattr(sapmap_exploit, name):
            monkeypatch.setattr(sapmap_exploit, name, _never)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("posture", [
    "enforced_no_creds",
    "enforced_handshake_failed",
    "enforced_logon_failed",
])
def test_phase2_skips_enforced_snc_variants(no_dispatch, capsys, posture):
    """All three enforced_* postures must skip phase2 with a message
    that names the posture so the operator understands which guard
    fired.  Zero exploit dispatches (no_dispatch fixture assertions)."""
    state = SAPMAPState()
    state.add_node(_vuln_node("NPL", snc_posture=posture))

    cfg = AutoPwnConfig()
    newly_pwned = phase2_exploit(state, cfg, wave=1)

    assert newly_pwned == 0, "no exploitation should have happened"
    out = capsys.readouterr().out
    assert f"SNC enforced ({posture})" in out, (
        f"skip message missing posture={posture!r}; got: {out!r}")
    assert "plain-RFC exploits skipped" in out
    # enforced_logon_failed carries a different hint than the other two.
    if posture == "enforced_logon_failed":
        assert "credentials" in out.lower()


def test_phase2_does_not_skip_reachable_auth(monkeypatch, capsys):
    """A node that resolves to ``reachable_auth`` (SNC handshake +
    logon both succeed) must NOT be skipped — AutoPwn should still
    dispatch exploits there.  Regression floor."""
    state = SAPMAPState()
    node = _vuln_node("S4H", snc_posture="reachable_auth")
    state.add_node(node)

    dispatched = []
    import sapmap_exploit
    def _fake_gw(node_arg, state_arg):
        dispatched.append(node_arg.sid)
        return None  # no user created — keeps the rest of the loop quiet
    monkeypatch.setattr(sapmap_exploit, "create_user_gw_exploit", _fake_gw)
    # Don't need to patch the dpmon path; node doesn't carry
    # dpmon_sap_star_available so Priority 1b won't fire.

    cfg = AutoPwnConfig()
    phase2_exploit(state, cfg, wave=1)

    assert "S4H" in dispatched, (
        "a reachable_auth node must still be dispatched to phase-2 "
        "exploits — otherwise the skip guard is too greedy")
    out = capsys.readouterr().out
    assert "plain-RFC exploits skipped" not in out


def test_phase2_does_not_skip_empty_posture(monkeypatch, capsys):
    """A node whose classifier never ran (snc_posture = "") must NOT
    be skipped — the guard only fires on authoritative enforced_* verdicts.
    Guards against the classifier being disabled flipping every node to
    a silent skip."""
    state = SAPMAPState()
    node = _vuln_node("ABA", snc_posture="")   # classifier never ran
    state.add_node(node)

    dispatched = []
    import sapmap_exploit
    def _fake_gw(node_arg, state_arg):
        dispatched.append(node_arg.sid)
        return None
    monkeypatch.setattr(sapmap_exploit, "create_user_gw_exploit", _fake_gw)

    cfg = AutoPwnConfig()
    phase2_exploit(state, cfg, wave=1)

    assert "ABA" in dispatched
    out = capsys.readouterr().out
    assert "plain-RFC exploits skipped" not in out


def test_toggle_off_restores_dispatch(monkeypatch, capsys):
    """``config.skip_enforced_snc_plain_rfc = False`` must re-enable
    the plain-RFC pass for defender probing (confirm the SNC gate is
    actually closing the plain port)."""
    state = SAPMAPState()
    node = _vuln_node("NPL", snc_posture="enforced_no_creds")
    state.add_node(node)

    dispatched = []
    import sapmap_exploit
    def _fake_gw(node_arg, state_arg):
        dispatched.append(node_arg.sid)
        return None
    monkeypatch.setattr(sapmap_exploit, "create_user_gw_exploit", _fake_gw)

    cfg = AutoPwnConfig()
    cfg.skip_enforced_snc_plain_rfc = False
    phase2_exploit(state, cfg, wave=1)

    assert "NPL" in dispatched, (
        "with skip_enforced_snc_plain_rfc=False, the guard must not fire")
    out = capsys.readouterr().out
    assert "plain-RFC exploits skipped" not in out


def test_phase_summary_reports_skipped_count(no_dispatch, capsys):
    """When one or more nodes get skipped, the phase-complete summary
    must surface the count + the issue number so the operator attributes
    the no-op to the SNC posture rather than a crash."""
    state = SAPMAPState()
    state.add_node(_vuln_node("NPL", snc_posture="enforced_no_creds"))
    state.add_node(_vuln_node("S4H", snc_posture="enforced_handshake_failed"))

    cfg = AutoPwnConfig()
    phase2_exploit(state, cfg, wave=1)

    out = capsys.readouterr().out
    assert "Phase 2 complete" in out
    assert "skipped 2 enforced-SNC node(s)" in out
    assert "#219" in out


def test_default_config_opts_in():
    """The config default is ON — a fresh AutoPwnConfig skips enforced-
    SNC nodes without the operator having to touch anything.  Defender
    probing requires the explicit opt-out.  (Covered in #219.)"""
    cfg = AutoPwnConfig()
    assert cfg.skip_enforced_snc_plain_rfc is True


def test_skip_message_carries_remediation_hint(no_dispatch, capsys):
    """The skip message must suggest what unlocks the node again —
    either 'configure a trusted PSE' (enforced_no_creds /
    enforced_handshake_failed) or 'verify the active wallet entry's
    credentials' (enforced_logon_failed).  Without this hint the
    operator sees a blocked phase with no recovery path."""
    state = SAPMAPState()
    state.add_node(_vuln_node("NPL", snc_posture="enforced_no_creds"))
    state.add_node(_vuln_node("LGF",
                               snc_posture="enforced_logon_failed"))

    cfg = AutoPwnConfig()
    phase2_exploit(state, cfg, wave=1)

    out = capsys.readouterr().out
    assert "configure a trusted PSE to unlock" in out, (
        "enforced_no_creds skip must point at the PSE-wallet remediation"
    )
    assert "verify the active wallet entry's credentials" in out, (
        "enforced_logon_failed skip must point at credential remediation"
    )
