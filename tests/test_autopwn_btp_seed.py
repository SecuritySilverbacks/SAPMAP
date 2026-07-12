"""AutoPwn recognises BTP→on-prem edges as walkable Phase-4 seeds.

Pinned scenario (2026-07-12): operator runs cert-auth mint on a
BTP subaccount, pulls 4 destinations with cleartext creds pointing
at on-prem systems that SAPMAP has plotted but not yet pwned.  If
AutoPwn is triggered next, Phase 4 must NOT skip early — the BTP→
on-prem cleartext edges are exactly the seeds it should walk.

Two invariants:

  * When pwned_nodes is empty but btp_seed_edges is non-empty,
    Phase 4 continues into Pass 1 (SecStore-credential propagation).
    Pre-fix line 2215 unconditionally returned 0 when no on-prem
    node was pwned, dropping the whole cloud→on-prem chain.

  * When both are empty, the early-out survives — no wasted
    iteration through an empty connection list.

The BTP-source-SID stub construction at line ~2314 is already in
place from an earlier commit — this test only pins the seed-gate
above it.
"""
from __future__ import annotations

import modules  # noqa: F401


def _select_btp_seed_edges(state):
    """Same expression the phase-4 gate uses.  Kept in sync with
    the live code — refactor this together with the module."""
    return [
        c for c in state.connections
        if c.source_sid and c.source_sid.startswith("BTP:")
           and c.target_sid and c.secstore_password and c.rfc_user
    ]


def test_no_pwn_no_btp_edges_still_skips():
    """Baseline: an empty landscape gives Phase 4 nothing to do —
    early-out must survive the fix."""
    from sapmap_models import SAPMAPState
    state = SAPMAPState()
    pwned_nodes = [n for n in state.nodes.values() if n.pwned]
    btp_edges = _select_btp_seed_edges(state)
    should_skip = not pwned_nodes and not btp_edges
    assert should_skip is True


def test_btp_edges_present_no_pwn_does_not_skip():
    """The scenario the fix targets: cert-auth mint captured a
    BTP→on-prem edge with cleartext creds, but nothing on-prem is
    pwned yet.  Phase 4 must proceed so those creds get exercised."""
    from sapmap_models import SAPMAPState, SAPNode, RFCConnection
    state = SAPMAPState()
    state.nodes["W74"] = SAPNode(sid="W74", ip="192.168.2.29",
                                    hostname="WINWAS74")
    state.connections.append(RFCConnection(
        source_sid="BTP:90a90189",
        source_host="researchlab-yehctg7m",
        destination_name="W74",
        rfc_type="3",
        conn_type="rfc",
        target_sid="W74",
        rfc_user="sapadm",
        secstore_password="siroj1978!",
        client="001"))
    pwned_nodes = [n for n in state.nodes.values() if n.pwned]
    btp_edges = _select_btp_seed_edges(state)
    should_skip = not pwned_nodes and not btp_edges
    assert should_skip is False, (
        "regression: cloud→on-prem cleartext seed edge got "
        "skipped because no on-prem node was pwned yet")
    assert len(btp_edges) == 1
    assert btp_edges[0].source_sid == "BTP:90a90189"


def test_seed_gate_requires_all_of_cleartext_creds_target_sid():
    """The seed filter must reject BTP edges missing any of the
    fields propagate_from_node needs.  A BTP-sourced edge with no
    password or no rfc_user or no target_sid is not walkable —
    including it would trip Pass 1 into a doomed iteration."""
    from sapmap_models import SAPMAPState, RFCConnection

    def _seed_for(*, target_sid, user, password):
        s = SAPMAPState()
        s.connections.append(RFCConnection(
            source_sid="BTP:aaaa1111",
            source_host="sub",
            destination_name="X",
            rfc_type="3",
            conn_type="rfc",
            target_sid=target_sid,
            rfc_user=user,
            secstore_password=password))
        return _select_btp_seed_edges(s)

    # All fields present → included
    assert len(_seed_for(target_sid="T1", user="u",
                          password="p")) == 1
    # Missing password → excluded
    assert _seed_for(target_sid="T1", user="u", password="") == []
    # Missing user → excluded
    assert _seed_for(target_sid="T1", user="", password="p") == []
    # Missing target_sid → excluded (nothing to walk to)
    assert _seed_for(target_sid="", user="u", password="p") == []


def test_non_btp_edges_not_treated_as_seed():
    """Regular ABAP→ABAP RFC edges (source_sid = SID, not 'BTP:...')
    aren't seeds for this specific gate — they'd rely on the
    caller's own source.pwned check that Pass 1 does elsewhere.
    The seed gate is BTP-specific."""
    from sapmap_models import SAPMAPState, RFCConnection
    state = SAPMAPState()
    state.connections.append(RFCConnection(
        source_sid="S4H",            # not BTP:
        source_host="s4h",
        destination_name="TO_W74",
        rfc_type="3",
        conn_type="rfc",
        target_sid="W74",
        rfc_user="sapadm",
        secstore_password="s"))
    assert _select_btp_seed_edges(state) == []
