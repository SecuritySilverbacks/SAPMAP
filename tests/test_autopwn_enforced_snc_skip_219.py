"""AutoPwn filters plain-RFC vulns on enforced-SNC nodes (issue #219).

Phase H of the #167 SNC classifier arc.  A node whose ``snc_posture``
is one of ``enforced_no_creds``, ``enforced_handshake_failed`` or
``enforced_logon_failed`` has the 33NN RFC dispatcher closed, so the
GW SAPXPG and dpmon paths that ride that port will just time out.

NARROW skip: only the plain-RFC-only vulns (``gw``) are filtered.
CVE-2025-31324 (HTTPS/ICM JSP), RECON / CVE-2020-6287 (SOAP/HTTPS),
SAPControl pivot (HTTPS/SOAP) and 10KBlaze (MS port 36NN) travel over
transports independent of 33NN, so the dual-stack foothold they can
give us must still be attempted.  ``_post_exploit_enrichment`` sets
``node.pwned=True`` before any RFC call and swallows RFC errors, so
the HTTP foothold survives even when the follow-up RFC enrichment
fails on the enforced dispatcher.

This was tightened after an adversarial pre-merge review on PR #227
caught that the first version of the gate skipped the whole node and
silently lost HTTP footholds on dual-stack enforced-SNC systems.

Tests:
  1. three enforced_* variants on a gw-only node all WHOLE-skip, with
     zero exploit dispatches and the posture-specific hint;
  2. a reachable_auth node is NOT skipped (regression floor);
  3. an empty posture (classifier never ran) is NOT skipped;
  4. the config toggle (default True) can be flipped OFF;
  5. phase summary surfaces the whole-skip count;
  6. default config opts in;
  7. skip message carries per-posture remediation hint;
  8. enforced + CVE-31324 keeps dispatching (HTTPS unaffected by SNC);
  9. enforced + RECON keeps dispatching (SOAP unaffected by SNC);
 10. enforced + 10KBlaze keeps dispatching (MS 36NN != 33NN);
 11. enforced + sapcontrol keeps dispatching (SAPControl HTTPS);
 12. enforced + gw + cve_31324 filters gw but dispatches HTTP path;
 13. the partial-skip log line names which vulns were filtered and
     which were kept, so the operator audit-trails the posture call.

The gw-only tests patch every exploit entry on ``sapmap_exploit`` with
a sentinel that fails if invoked — "skipped" means "exploit code was
never reached."  The keep-dispatching tests patch only the specific
exploit entry they expect to fire + collect its call.
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


# ---------------------------------------------------------------------------
# Narrow-skip coverage — dual-stack enforced nodes with HTTP/SOAP/MS vulns
# must STILL dispatch those exploits.  Caught by adversarial pre-merge
# review on PR #227 — the first version of the gate silently lost CVE-
# 2025-31324 / RECON / SAPControl / 10KBlaze footholds on dual-stack
# enforced-SNC systems.  _post_exploit_enrichment sets node.pwned=True
# before any RFC call, so the HTTP foothold survives a follow-up RFC
# enrichment failure on the enforced dispatcher.
# ---------------------------------------------------------------------------

def _no_gw_dispatch(monkeypatch):
    """Patch the GW SAPXPG entry so the test fails if it fires."""
    import sapmap_exploit

    def _never(*args, **kwargs):
        raise AssertionError(
            "GW SAPXPG dispatched on an enforced-SNC node — the plain-"
            "RFC filter did not fire.")

    monkeypatch.setattr(sapmap_exploit, "create_user_gw_exploit", _never)
    if hasattr(sapmap_exploit, "create_user_via_dpmon_sap_star"):
        monkeypatch.setattr(sapmap_exploit,
                            "create_user_via_dpmon_sap_star", _never)


def test_enforced_plus_cve_31324_still_dispatches(monkeypatch, capsys):
    """Dual-stack enforced-SNC node whose only reachable vuln is
    CVE-2025-31324.  The JSP webshell drops over HTTPS/ICM (50000 /
    443NN), untouched by the enforced 33NN dispatcher.  Pre-fix PR#227
    would silently skip this node; post-fix the HTTP path dispatches."""
    _no_gw_dispatch(monkeypatch)
    import sapmap_exploit

    shell_calls = []
    def _fake_shell(node):
        shell_calls.append(node.sid)
        return {"success": False}       # doesn't matter — only testing dispatch
    monkeypatch.setattr(sapmap_exploit,
                        "drop_cve_2025_31324_shell", _fake_shell)

    node = _vuln_node("NPL", snc_posture="enforced_no_creds")
    node.gw_vulnerable = False        # HTTP-only exposure
    node.cve_2025_31324_vulnerable = True
    state = SAPMAPState()
    state.add_node(node)

    phase2_exploit(state, AutoPwnConfig(), wave=1)

    assert shell_calls == ["NPL"], (
        "CVE-2025-31324 (HTTPS/ICM) must still dispatch on an "
        "enforced-SNC node — the port it uses is not 33NN")
    out = capsys.readouterr().out
    # Whole-node skip line must NOT appear.
    assert "plain-RFC exploits skipped" not in out


def test_enforced_plus_recon_still_dispatches(monkeypatch, capsys):
    """CVE-2020-6287 RECON travels over SOAP/HTTPS, not 33NN RFC —
    enforced posture must not drop it."""
    _no_gw_dispatch(monkeypatch)
    import sap_cve_2020_6287

    recon_calls = []
    def _fake_recon(node):
        recon_calls.append(node.sid)
        return {"success": False}
    monkeypatch.setattr(sap_cve_2020_6287,
                        "exploit_create_user", _fake_recon)

    node = _vuln_node("REC", snc_posture="enforced_handshake_failed")
    node.gw_vulnerable = False
    node.cve_2020_6287_vulnerable = True
    state = SAPMAPState()
    state.add_node(node)

    phase2_exploit(state, AutoPwnConfig(), wave=1)

    assert recon_calls == ["REC"], (
        "CVE-2020-6287 RECON (SOAP/HTTPS) must still dispatch on an "
        "enforced-SNC node — the port it uses is not 33NN")
    out = capsys.readouterr().out
    assert "plain-RFC exploits skipped" not in out


def test_enforced_plus_10kblaze_still_dispatches(monkeypatch, capsys):
    """10KBlaze betrusted chain uses the Message Server port (36NN),
    independent of the 33NN RFC dispatcher the SNC posture closes."""
    _no_gw_dispatch(monkeypatch)
    import sap_betrusted_chain

    chain_calls = []
    def _fake_chain(node, state):
        chain_calls.append(node.sid)
        return None
    monkeypatch.setattr(sap_betrusted_chain,
                        "create_user_betrusted_chain", _fake_chain)

    node = _vuln_node("BLZ", snc_posture="enforced_logon_failed")
    node.gw_vulnerable = False
    node.ms_vulnerable = True
    state = SAPMAPState()
    state.add_node(node)

    phase2_exploit(state, AutoPwnConfig(), wave=1)

    assert chain_calls == ["BLZ"], (
        "10KBlaze (MS 36NN) must still dispatch on an enforced-SNC "
        "node — the port it uses is not 33NN")
    out = capsys.readouterr().out
    assert "plain-RFC exploits skipped" not in out


def test_enforced_gw_plus_cve_filters_gw_keeps_http(monkeypatch, capsys):
    """Dual-vuln node: gw + cve_31324, enforced SNC.  Must FILTER the
    gw entry (plain-RFC 33NN) but KEEP the cve_31324 entry (HTTPS).
    The partial-skip log line must name both the filtered and the
    kept vulns so the operator audit-trails the posture decision."""
    import sapmap_exploit

    gw_calls = []
    shell_calls = []

    def _fake_gw(node, state):
        gw_calls.append(node.sid)
        return None

    def _fake_shell(node):
        shell_calls.append(node.sid)
        return {"success": False}

    monkeypatch.setattr(sapmap_exploit,
                        "create_user_gw_exploit", _fake_gw)
    monkeypatch.setattr(sapmap_exploit,
                        "drop_cve_2025_31324_shell", _fake_shell)

    node = _vuln_node("DUAL", snc_posture="enforced_no_creds")
    # gw_vulnerable already True from the fixture
    node.cve_2025_31324_vulnerable = True
    state = SAPMAPState()
    state.add_node(node)

    phase2_exploit(state, AutoPwnConfig(), wave=1)

    assert gw_calls == [], (
        "GW SAPXPG must be filtered on an enforced-SNC node even when "
        "paired with cve_31324"
    )
    assert shell_calls == ["DUAL"], (
        "cve_31324 (HTTPS) must STILL dispatch on an enforced-SNC node "
        "after gw is filtered out"
    )
    out = capsys.readouterr().out
    # Partial-skip line must name BOTH filtered and kept vulns.
    assert "skipping plain-RFC exploit path(s) gw" in out, (
        f"partial-skip line must name the filtered vuln; got: {out!r}"
    )
    assert "continuing with cve_31324" in out, (
        f"partial-skip line must name the kept vuln; got: {out!r}"
    )
    # Whole-node skip line must NOT appear — the node had non-RFC vulns.
    assert "plain-RFC exploits skipped" not in out


def test_partial_skip_does_not_bump_whole_skip_counter(monkeypatch, capsys):
    """When gw is filtered but HTTP vulns dispatch, the phase-summary
    enforced-SNC counter must NOT increment.  That counter is scoped
    to WHOLE-node skips; a partial filter is a logged note only.
    Prevents the summary from over-reporting 'nothing happened' when
    something did happen."""
    import sapmap_exploit
    monkeypatch.setattr(sapmap_exploit, "create_user_gw_exploit",
                        lambda node, state: None)
    monkeypatch.setattr(sapmap_exploit, "drop_cve_2025_31324_shell",
                        lambda node: {"success": False})

    node = _vuln_node("PRT", snc_posture="enforced_no_creds")
    node.cve_2025_31324_vulnerable = True
    state = SAPMAPState()
    state.add_node(node)

    phase2_exploit(state, AutoPwnConfig(), wave=1)

    out = capsys.readouterr().out
    # No "(skipped N enforced-SNC node(s) — #219)" trailer.
    assert "skipped" not in out.split("Phase 2 complete")[1], (
        "partial-skip must not bump the whole-node enforced-SNC counter"
    )


def test_toggle_off_restores_gw_dispatch_on_dual_vuln(monkeypatch, capsys):
    """``skip_enforced_snc_plain_rfc = False`` must re-enable the gw
    dispatch even on a dual-vuln enforced-SNC node — defender probing
    wants to confirm the SNC gate actually refuses the plain-RFC auth."""
    import sapmap_exploit

    gw_calls = []
    shell_calls = []
    monkeypatch.setattr(sapmap_exploit, "create_user_gw_exploit",
                        lambda node, state: gw_calls.append(node.sid) or None)
    monkeypatch.setattr(sapmap_exploit, "drop_cve_2025_31324_shell",
                        lambda node: shell_calls.append(node.sid)
                                      or {"success": False})

    node = _vuln_node("PRB", snc_posture="enforced_no_creds")
    node.cve_2025_31324_vulnerable = True
    state = SAPMAPState()
    state.add_node(node)

    cfg = AutoPwnConfig()
    cfg.skip_enforced_snc_plain_rfc = False
    phase2_exploit(state, cfg, wave=1)

    assert gw_calls == ["PRB"], (
        "toggle off must restore gw dispatch for defender probing"
    )
    assert shell_calls == ["PRB"], (
        "toggle off must not interfere with the non-RFC dispatch"
    )
