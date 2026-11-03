"""Tests for the kill-chain *per-hop* contract in sapmap_chain.py.

The animated kill-chain player (and the engagement-report storyboard)
replay a ranked attack path hop-by-hop, colouring each step by how bad
*that* step is.  That needs two things the chain engine did not used to
expose:

    * ``ChainHop.severity``  — 5 (CRITICAL) .. 2 (LOW), scored per hop
    * ``ChainHop.untested``  — the hop is a candidate, not a proven step

Whole-chain severity already lives on ``TrustChain``; these tests pin
down the *per-hop* layer: the pure ``_hop_severity`` rule, the new field
defaults and JSON shape, end-to-end population for every edge type, the
lockstep between the ``— UNTESTED`` caption / the ``untested`` flag / the
severity clamp, and the ordered-hops contract the player consumes.

All tests are offline (no network): they build mock SAPMAPState objects
and assert on the returned TrustChain/ChainHop structures.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sapmap_chain import (
    ChainHop, TrustChain,
    find_all_chains, analyze_chains,
    _hop_severity,
    _HOP_SEV_CRITICAL, _HOP_SEV_HIGH, _HOP_SEV_MEDIUM, _HOP_SEV_LOW,
)
from sapmap_models import (
    SAPMAPState, SAPNode, RFCConnection,
    DBCONConnection, TMSDestination, TrustRelation,
)


class _FakeConn:
    """Minimal connection stand-in for direct _hop_severity unit tests —
    only the two attributes the helper reads."""
    def __init__(self, has_sap_all=False, tested=False):
        self.has_sap_all = has_sap_all
        self.tested = tested


# ---------------------------------------------------------------------------
# _hop_severity — the pure rule, exercised directly
# ---------------------------------------------------------------------------

class TestHopSeverityRule:

    def test_trusted_is_critical(self):
        assert _hop_severity(_FakeConn(), is_trusted=True, is_sso2=False,
                             is_dbcon=False, is_tms=False) == _HOP_SEV_CRITICAL

    def test_sso2_is_critical(self):
        assert _hop_severity(_FakeConn(), is_trusted=False, is_sso2=True,
                             is_dbcon=False, is_tms=False) == _HOP_SEV_CRITICAL

    def test_sap_all_tested_is_high(self):
        assert _hop_severity(_FakeConn(has_sap_all=True, tested=True),
                             False, False, False, False) == _HOP_SEV_HIGH

    def test_dbcon_is_high(self):
        assert _hop_severity(_FakeConn(), False, False,
                             is_dbcon=True, is_tms=False) == _HOP_SEV_HIGH

    def test_tms_is_high(self):
        assert _hop_severity(_FakeConn(), False, False,
                             is_dbcon=False, is_tms=True) == _HOP_SEV_HIGH

    def test_plain_rfc_logon_tested_is_medium(self):
        assert _hop_severity(_FakeConn(has_sap_all=False, tested=True),
                             False, False, False, False) == _HOP_SEV_MEDIUM

    def test_untested_clamps_sap_all_down_one(self):
        # SAP_ALL (4) but never proven → MEDIUM (3), not HIGH.
        assert _hop_severity(_FakeConn(has_sap_all=True, tested=False),
                             False, False, False, False) == _HOP_SEV_MEDIUM

    def test_untested_clamps_plain_rfc_to_the_low_floor(self):
        # Plain RFC (3) untested → LOW (2); the clamp never goes below LOW.
        assert _hop_severity(_FakeConn(has_sap_all=False, tested=False),
                             False, False, False, False) == _HOP_SEV_LOW

    def test_trusted_edge_not_clamped_when_conn_untested(self):
        # Passwordless hops are never treated as "untested".
        assert _hop_severity(_FakeConn(tested=False), is_trusted=True,
                             is_sso2=False, is_dbcon=False,
                             is_tms=False) == _HOP_SEV_CRITICAL

    def test_dbcon_edge_not_clamped_when_conn_untested(self):
        assert _hop_severity(_FakeConn(tested=False), False, False,
                             is_dbcon=True, is_tms=False) == _HOP_SEV_HIGH

    def test_tms_edge_not_clamped_when_conn_untested(self):
        assert _hop_severity(_FakeConn(tested=False), False, False,
                             is_dbcon=False, is_tms=True) == _HOP_SEV_HIGH

    def test_severity_never_below_low_floor(self):
        # Exhaustive: no combination of flags produces < LOW or > CRITICAL.
        for sap_all in (True, False):
            for tested in (True, False):
                for flags in [(False, False, False, False),
                              (True, False, False, False),
                              (False, True, False, False),
                              (False, False, True, False),
                              (False, False, False, True)]:
                    sev = _hop_severity(
                        _FakeConn(has_sap_all=sap_all, tested=tested), *flags)
                    assert _HOP_SEV_LOW <= sev <= _HOP_SEV_CRITICAL


# ---------------------------------------------------------------------------
# ChainHop — new fields: defaults and JSON shape
# ---------------------------------------------------------------------------

class TestChainHopFields:

    def test_defaults(self):
        """A bare hop defaults to the LOW floor and not-untested, so
        existing callers that build ChainHop positionally don't break."""
        h = ChainHop(source_sid="A", target_sid="B")
        assert h.severity == _HOP_SEV_LOW
        assert h.untested is False

    def test_to_dict_carries_new_fields(self):
        h = ChainHop(source_sid="A", target_sid="B",
                     method="Trusted RFC (no password)",
                     severity=5, untested=False)
        d = h.to_dict()
        assert d["severity"] == 5
        assert d["untested"] is False
        # and the pre-existing keys are untouched
        assert d["source_sid"] == "A"
        assert d["method"] == "Trusted RFC (no password)"

    def test_to_dict_roundtrips_untested(self):
        h = ChainHop(source_sid="A", target_sid="B",
                     severity=2, untested=True)
        d = h.to_dict()
        assert d["severity"] == 2
        assert d["untested"] is True


# ---------------------------------------------------------------------------
# End-to-end: per-hop severity populated by find_all_chains, by edge type
# ---------------------------------------------------------------------------

def _hop_to(chains, target_sid):
    """Return the (single) hop landing on target_sid across all chains."""
    for c in chains:
        for h in c.hops:
            if h.target_sid == target_sid:
                return h
    return None


def _landscape_one_entry_many_edges():
    """A single pwned entry 'DEV' with a distinct 1-hop edge of each
    kind, so one find_all_chains pass yields every hop type to assert on.

        DEV --SAP_ALL (tested)----> AQA     severity 4, untested False
        DEV --plain RFC (tested)--> ARF     severity 3, untested False
        DEV --SAP_ALL (untested)--> AUT     severity 3, untested True  (clamped)
        DEV --plain RFC (untested)> AUP     severity 2, untested True  (clamped floor)
        DEV --trusted RFC---------> ATR     severity 5, untested False
        DEV --DBCON (conn untested)> ADB    severity 4, untested False (carve-out)
        DEV --TMS controller------> ATM     severity 4, untested False (carve-out)
    """
    state = SAPMAPState()
    dev = SAPNode(sid="DEV", ip="10.0.0.1", hostname="dev", pwned=True)
    state.add_node(dev)
    for sid in ("AQA", "ARF", "AUT", "AUP", "ATR", "ADB", "ATM"):
        state.add_node(SAPNode(sid=sid, ip="10.0.0.9", hostname=sid.lower()))

    state.add_connection(RFCConnection(
        source_sid="DEV", source_host="dev", target_sid="AQA", target_host="aqa",
        destination_name="D_AQA", rfc_user="RFC",
        has_sap_all=True, tested=True, logon_successful=True))
    state.add_connection(RFCConnection(
        source_sid="DEV", source_host="dev", target_sid="ARF", target_host="arf",
        destination_name="D_ARF", rfc_user="RFC",
        has_sap_all=False, tested=True, logon_successful=True))
    state.add_connection(RFCConnection(
        source_sid="DEV", source_host="dev", target_sid="AUT", target_host="aut",
        destination_name="D_AUT", rfc_user="RFC",
        has_sap_all=True, tested=False, logon_successful=False))
    state.add_connection(RFCConnection(
        source_sid="DEV", source_host="dev", target_sid="AUP", target_host="aup",
        destination_name="D_AUP", rfc_user="RFC",
        has_sap_all=False, tested=False, logon_successful=False))
    state.add_connection(RFCConnection(
        source_sid="DEV", source_host="dev", target_sid="ATR", target_host="atr",
        destination_name="D_ATR", rfc_user="RFC",
        has_sap_all=False, trusted_system=True))

    dev.dbcon_edges = [DBCONConnection(
        source_sid="DEV", con_name="C_ADB", dbms="HDB",
        host="adb", port=30215, user="saphanadb", password="pw",
        tested=False, reachable=True, is_sap_shape=True,
        target_sid="ADB", pwned=True)]
    dev.tms_destinations = [TMSDestination(
        source_sid="DEV", target_sid="ATM", target_host="atm",
        domain="DOMAIN_DEV", is_controller=True, password="x",
        tested=False, logon_ok=False, tmsadm_has_sap_all=False)]
    return state


class TestPerHopSeverityEndToEnd:

    def setup_method(self):
        self.chains = find_all_chains(
            _landscape_one_entry_many_edges(), print_fn=lambda *a: None)

    def test_sap_all_tested_hop_is_high(self):
        h = _hop_to(self.chains, "AQA")
        assert h is not None and h.severity == _HOP_SEV_HIGH
        assert h.untested is False

    def test_plain_rfc_tested_hop_is_medium(self):
        h = _hop_to(self.chains, "ARF")
        assert h is not None and h.severity == _HOP_SEV_MEDIUM
        assert h.untested is False

    def test_sap_all_untested_hop_is_clamped_to_medium(self):
        h = _hop_to(self.chains, "AUT")
        assert h is not None and h.severity == _HOP_SEV_MEDIUM
        assert h.untested is True

    def test_plain_rfc_untested_hop_is_clamped_to_low(self):
        h = _hop_to(self.chains, "AUP")
        assert h is not None and h.severity == _HOP_SEV_LOW
        assert h.untested is True

    def test_trusted_hop_is_critical(self):
        h = _hop_to(self.chains, "ATR")
        assert h is not None and h.severity == _HOP_SEV_CRITICAL
        assert h.untested is False

    def test_dbcon_hop_is_high_and_not_untested(self):
        # conn.tested is False, but a DBCON edge is never a "candidate"
        # untested hop — we hold the DB creds and can plant any time.
        h = _hop_to(self.chains, "ADB")
        assert h is not None and h.severity == _HOP_SEV_HIGH
        assert h.untested is False

    def test_tms_hop_is_high_and_not_untested(self):
        h = _hop_to(self.chains, "ATM")
        assert h is not None and h.severity == _HOP_SEV_HIGH
        assert h.untested is False


def test_sso2_hop_is_critical():
    """A forged-MYSAPSSO2 (STRUSTSSO2) hop is passwordless lateral
    movement → CRITICAL, and never flagged untested."""
    state = SAPMAPState()
    # issuer holds the stolen SAPSYS PSE (pwned entry point); it can
    # forge tickets accepted by the trusting receiver.
    state.add_node(SAPNode(sid="ISS", ip="10.0.0.1", pwned=True))
    state.add_node(SAPNode(sid="RCV", ip="10.0.0.2", is_production=True))
    state.trust_relations = [TrustRelation(
        trusting_sid="RCV", issuer_sid="ISS",
        discovered_via="STRUSTSSO2")]
    chains = find_all_chains(state, print_fn=lambda *a: None)
    h = _hop_to(chains, "RCV")
    assert h is not None, "expected an ISS -> RCV STRUSTSSO2 hop"
    assert "STRUSTSSO2" in h.method
    assert h.severity == _HOP_SEV_CRITICAL
    assert h.untested is False


# ---------------------------------------------------------------------------
# Lockstep: the untested flag, the caption suffix, and the clamp agree
# ---------------------------------------------------------------------------

class TestCaptionFlagLockstep:

    def test_untested_flag_matches_caption_suffix(self):
        """ChainHop.untested is True exactly when the method caption
        carries the '— UNTESTED' suffix — the two must never diverge,
        since the player styles the caption from the flag."""
        chains = find_all_chains(
            _landscape_one_entry_many_edges(), print_fn=lambda *a: None)
        hops = [h for c in chains for h in c.hops]
        assert hops
        for h in hops:
            assert h.untested == ("UNTESTED" in h.method), h.method

    def test_untested_hop_is_never_above_medium(self):
        """An untested candidate hop can never read as HIGH/CRITICAL —
        the clamp guarantees it."""
        chains = find_all_chains(
            _landscape_one_entry_many_edges(), print_fn=lambda *a: None)
        for h in (h for c in chains for h in c.hops):
            if h.untested:
                assert h.severity <= _HOP_SEV_MEDIUM


# ---------------------------------------------------------------------------
# Ordered-hops contract — the player replays entry -> crown jewel in order
# ---------------------------------------------------------------------------

def test_hops_are_ordered_entry_first_target_last():
    """DEV -> QA -> PRD must come back as ordered hops so the player can
    step through them; hops[i].target_sid == hops[i+1].source_sid."""
    state = SAPMAPState()
    state.add_node(SAPNode(sid="DEV", ip="1", hostname="dev", pwned=True))
    state.add_node(SAPNode(sid="QA", ip="2", hostname="qa"))
    state.add_node(SAPNode(sid="PRD", ip="3", hostname="prd", is_production=True))
    state.add_connection(RFCConnection(
        source_sid="DEV", source_host="dev", target_sid="QA", target_host="qa",
        has_sap_all=True, tested=True, logon_successful=True))
    state.add_connection(RFCConnection(
        source_sid="QA", source_host="qa", target_sid="PRD", target_host="prd",
        has_sap_all=True, tested=True, logon_successful=True))
    chains = find_all_chains(state, print_fn=lambda *a: None)
    full = [c for c in chains if c.end_sid == "PRD" and c.total_hops == 2]
    assert full, "expected a 2-hop DEV -> QA -> PRD chain"
    c = full[0]
    assert c.hops[0].source_sid == "DEV"
    assert c.hops[0].target_sid == "QA"
    assert c.hops[1].source_sid == "QA"
    assert c.hops[1].target_sid == "PRD"
    assert c.path_sids == ["DEV", "QA", "PRD"]
    # contiguity: each hop's target is the next hop's source
    for a, b in zip(c.hops, c.hops[1:]):
        assert a.target_sid == b.source_sid


def test_per_hop_severity_is_independent_of_chain_severity():
    """A chain can reach production (chain severity HIGH) on a single
    plain, untested RFC hop whose own severity is LOW — the per-hop and
    whole-chain scores are deliberately independent."""
    state = SAPMAPState()
    state.add_node(SAPNode(sid="DEV", ip="1", hostname="dev", pwned=True))
    state.add_node(SAPNode(sid="PRD", ip="2", hostname="prd", is_production=True))
    state.add_connection(RFCConnection(
        source_sid="DEV", source_host="dev", target_sid="PRD", target_host="prd",
        destination_name="D_PRD", rfc_user="RFC",
        has_sap_all=False, tested=False, logon_successful=False))
    chains = find_all_chains(state, print_fn=lambda *a: None)
    assert len(chains) == 1
    c = chains[0]
    assert c.end_is_production is True
    assert c.severity == _HOP_SEV_HIGH          # chain: production reached
    assert c.hops[0].severity == _HOP_SEV_LOW   # hop: plain + untested
    assert c.hops[0].untested is True


# ---------------------------------------------------------------------------
# JSON: the new per-hop fields survive TrustChain.to_dict() (the GUI route
# stores [c.to_dict() for c in chains]; the player reads them back)
# ---------------------------------------------------------------------------

def test_trustchain_to_dict_carries_per_hop_severity_and_untested():
    chains = analyze_chains(
        _landscape_one_entry_many_edges(), print_fn=lambda *a: None)
    assert chains
    for c in chains:
        d = c.to_dict()
        assert len(d["hops"]) == len(c.hops)
        for hop_dict, hop in zip(d["hops"], c.hops):
            assert hop_dict["severity"] == hop.severity
            assert hop_dict["untested"] == hop.untested
            assert isinstance(hop_dict["severity"], int)
            assert isinstance(hop_dict["untested"], bool)
