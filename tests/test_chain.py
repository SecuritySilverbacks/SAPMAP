"""Tests for sapmap_chain.py — RFC trust chain analysis.

All tests are offline (no network). They build mock SAPMAPState objects
with nodes and connections, then verify the BFS chain discovery, ranking,
filtering, and headline generation.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sapmap_chain import (
    ChainHop, TrustChain,
    find_all_chains, rank_chains, filter_critical,
    analyze_chains, _entry_method, _entry_description,
)
from sapmap_models import SAPMAPState, SAPNode, RFCConnection, Credentials


def _state_with_chain():
    """Build a 3-node landscape: DEV → QA → PRD with SAP_ALL RFC links."""
    state = SAPMAPState()
    dev = SAPNode(sid="DEV", ip="10.0.0.1", hostname="devhost",
                  pwned=True, gw_vulnerable=True)
    qa = SAPNode(sid="QA", ip="10.0.0.2", hostname="qahost")
    prd = SAPNode(sid="PRD", ip="10.0.0.3", hostname="prdhost",
                  is_production=True)
    state.add_node(dev)
    state.add_node(qa)
    state.add_node(prd)

    c1 = RFCConnection(source_sid="DEV", source_host="devhost", target_sid="QA",
                       target_host="qahost", destination_name="QA_TRUSTED",
                       rfc_user="RFCUSER", has_sap_all=True, logon_successful=True)
    c2 = RFCConnection(source_sid="QA", source_host="qahost", target_sid="PRD",
                       target_host="prdhost", destination_name="PRD_CONNECT",
                       rfc_user="DDIC", has_sap_all=True, logon_successful=True)
    state.add_connection(c1)
    state.add_connection(c2)
    return state


def _state_no_links():
    """Two nodes, no RFC connections."""
    state = SAPMAPState()
    state.add_node(SAPNode(sid="A", ip="10.0.0.1", pwned=True))
    state.add_node(SAPNode(sid="B", ip="10.0.0.2"))
    return state


def _state_no_entry():
    """Two nodes with RFC link but no entry point (not pwned/vulnerable)."""
    state = SAPMAPState()
    state.add_node(SAPNode(sid="X", ip="10.0.0.1"))
    state.add_node(SAPNode(sid="Y", ip="10.0.0.2"))
    state.add_connection(RFCConnection(
        source_sid="X", source_host="x", target_sid="Y", target_host="y",
        destination_name="TO_Y", rfc_user="RFC",
        has_sap_all=True, logon_successful=True))
    return state


# ---------------------------------------------------------------------------
# ChainHop
# ---------------------------------------------------------------------------

class TestChainHop:

    def test_to_dict(self):
        h = ChainHop(source_sid="A", target_sid="B", destination_name="D1",
                      rfc_user="USR", has_sap_all=True, method="BAPI")
        d = h.to_dict()
        assert d["source_sid"] == "A"
        assert d["target_sid"] == "B"
        assert d["has_sap_all"] is True

    def test_defaults(self):
        h = ChainHop(source_sid="X", target_sid="Y")
        assert h.destination_name == ""
        assert h.has_sap_all is False


# ---------------------------------------------------------------------------
# TrustChain
# ---------------------------------------------------------------------------

class TestTrustChain:

    def test_total_hops(self):
        c = TrustChain(hops=[
            ChainHop("A", "B"), ChainHop("B", "C"),
        ])
        assert c.total_hops == 2

    def test_path_sids(self):
        c = TrustChain(hops=[
            ChainHop("DEV", "QA"), ChainHop("QA", "PRD"),
        ])
        assert c.path_sids == ["DEV", "QA", "PRD"]

    def test_path_sids_empty(self):
        c = TrustChain()
        assert c.path_sids == []

    def test_severity_critical_production_sap_all(self):
        c = TrustChain(end_is_production=True, sap_all_throughout=True)
        assert c.severity == 5

    def test_severity_high_production_no_sap_all(self):
        c = TrustChain(end_is_production=True, sap_all_throughout=False)
        assert c.severity == 4

    def test_severity_medium_sap_all_multi_hop(self):
        c = TrustChain(end_is_production=False, sap_all_throughout=True,
                        hops=[ChainHop("A","B"), ChainHop("B","C")])
        assert c.severity == 3

    def test_to_dict(self):
        c = TrustChain(
            hops=[ChainHop("A", "B")],
            start_sid="A", end_sid="B",
            headline="test", risk_label="HIGH",
        )
        d = c.to_dict()
        assert d["total_hops"] == 1
        assert d["path_sids"] == ["A", "B"]
        assert d["headline"] == "test"
        assert len(d["hops"]) == 1


# ---------------------------------------------------------------------------
# find_all_chains
# ---------------------------------------------------------------------------

class TestFindAllChains:

    def test_finds_chain_dev_qa_prd(self):
        state = _state_with_chain()
        chains = find_all_chains(state, print_fn=lambda *a: None)
        # Should find: DEV→QA, DEV→QA→PRD
        end_sids = {c.end_sid for c in chains}
        assert "QA" in end_sids
        assert "PRD" in end_sids

    def test_no_links_returns_empty(self):
        state = _state_no_links()
        chains = find_all_chains(state, print_fn=lambda *a: None)
        assert len(chains) == 0

    def test_no_entry_returns_empty(self):
        state = _state_no_entry()
        chains = find_all_chains(state, print_fn=lambda *a: None)
        assert len(chains) == 0

    def test_max_depth_limits_hops(self):
        state = _state_with_chain()
        chains = find_all_chains(state, max_depth=1, print_fn=lambda *a: None)
        assert all(c.total_hops <= 1 for c in chains)

    def test_no_cycles(self):
        state = SAPMAPState()
        state.add_node(SAPNode(sid="A", ip="1", pwned=True))
        state.add_node(SAPNode(sid="B", ip="2"))
        state.add_connection(RFCConnection(
            source_sid="A", source_host="a", target_sid="B", target_host="b", has_sap_all=True, logon_successful=True))
        state.add_connection(RFCConnection(
            source_sid="B", source_host="b", target_sid="A", target_host="a", has_sap_all=True, logon_successful=True))
        chains = find_all_chains(state, print_fn=lambda *a: None)
        for c in chains:
            assert len(set(c.path_sids)) == len(c.path_sids)

    def test_logon_unsuccessful_not_traversed(self):
        state = SAPMAPState()
        state.add_node(SAPNode(sid="A", ip="1", pwned=True))
        state.add_node(SAPNode(sid="B", ip="2"))
        state.add_connection(RFCConnection(
            source_sid="A", source_host="a", target_sid="B", target_host="b",
            has_sap_all=True, logon_successful=False))
        chains = find_all_chains(state, print_fn=lambda *a: None)
        assert len(chains) == 0

    def test_self_connections_skipped(self):
        state = SAPMAPState()
        state.add_node(SAPNode(sid="A", ip="1", pwned=True))
        state.add_connection(RFCConnection(
            source_sid="A", source_host="a", target_sid="A", target_host="a", has_sap_all=True, logon_successful=True))
        chains = find_all_chains(state, print_fn=lambda *a: None)
        assert len(chains) == 0


# ---------------------------------------------------------------------------
# Ranking and filtering
# ---------------------------------------------------------------------------

class TestRankAndFilter:

    def test_rank_production_first(self):
        c1 = TrustChain(end_is_production=False, end_sid="QA",
                         hops=[ChainHop("A","B")])
        c2 = TrustChain(end_is_production=True, end_sid="PRD",
                         hops=[ChainHop("A","B")])
        ranked = rank_chains([c1, c2])
        assert ranked[0].end_sid == "PRD"

    def test_filter_critical_keeps_production(self):
        c1 = TrustChain(end_is_production=True, hops=[ChainHop("A","B")])
        c2 = TrustChain(end_is_production=False, hops=[ChainHop("A","B")])
        filtered = filter_critical([c1, c2])
        assert len(filtered) == 1
        assert filtered[0].end_is_production

    def test_filter_critical_keeps_multi_hop_sap_all(self):
        c = TrustChain(end_is_production=False, sap_all_throughout=True,
                        hops=[ChainHop("A","B"), ChainHop("B","C")])
        assert c in filter_critical([c])


# ---------------------------------------------------------------------------
# analyze_chains (full pipeline)
# ---------------------------------------------------------------------------

class TestAnalyzeChains:

    def test_full_pipeline(self):
        state = _state_with_chain()
        chains = analyze_chains(state, print_fn=lambda *a: None)
        assert len(chains) > 0
        # Should find the DEV→PRD chain
        prd_chains = [c for c in chains if c.end_sid == "PRD"]
        assert len(prd_chains) >= 1
        assert prd_chains[0].end_is_production
        assert prd_chains[0].risk_label == "CRITICAL"

    def test_headline_contains_path(self):
        state = _state_with_chain()
        chains = analyze_chains(state, print_fn=lambda *a: None)
        prd_chain = [c for c in chains if c.end_sid == "PRD"][0]
        assert "DEV" in prd_chain.headline
        assert "PRD" in prd_chain.headline

    def test_empty_state(self):
        state = SAPMAPState()
        chains = analyze_chains(state, print_fn=lambda *a: None)
        assert chains == []


# ---------------------------------------------------------------------------
# Entry point detection
# ---------------------------------------------------------------------------

class TestEntryMethod:

    def test_pwned(self):
        n = SAPNode(sid="X", ip="1", pwned=True)
        assert _entry_method(n) == "compromised"

    def test_gw_vulnerable(self):
        n = SAPNode(sid="X", ip="1", gw_vulnerable=True)
        assert _entry_method(n) == "gw_exploit"

    def test_ms_vulnerable(self):
        n = SAPNode(sid="X", ip="1", ms_vulnerable=True)
        assert _entry_method(n) == "betrusted_10kblaze"

    def test_credentials(self):
        n = SAPNode(sid="X", ip="1",
                    credentials=[Credentials(username="u", password="p",
                                             client="001", verified=True)])
        assert _entry_method(n) == "credentials"

    def test_description(self):
        assert "unauthenticated" in _entry_description("gw_exploit").lower()
        assert "10KBlaze" in _entry_description("betrusted_10kblaze")
