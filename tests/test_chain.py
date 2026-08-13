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
        """A destination that has been TESTED and explicitly failed
        logon must NOT appear in any chain — it's known-broken."""
        state = SAPMAPState()
        state.add_node(SAPNode(sid="A", ip="1", pwned=True))
        state.add_node(SAPNode(sid="B", ip="2"))
        state.add_connection(RFCConnection(
            source_sid="A", source_host="a", target_sid="B", target_host="b",
            has_sap_all=True,
            tested=True, logon_successful=False))
        chains = find_all_chains(state, print_fn=lambda *a: None)
        assert len(chains) == 0

    def test_untested_edge_is_traversed_and_marked(self):
        """An edge that has NEVER been tested (tested=False) must
        still appear as a chain — the destination is configured on
        disk and may very well work — but the hop is flagged so the
        report reader sees it isn't validated yet.  Without this
        carve-out, every blue 'RFC (untested)' arrow on the map was
        silently dropped from chain analysis (regression observed
        live: chains landing on PRD never surfaced)."""
        state = SAPMAPState()
        state.add_node(SAPNode(sid="A", ip="1", pwned=True))
        state.add_node(SAPNode(sid="P", ip="2", is_production=True))
        state.add_connection(RFCConnection(
            source_sid="A", source_host="a", target_sid="P", target_host="p",
            destination_name="A_TO_P", rfc_user="JORIS",
            has_sap_all=True,
            tested=False, logon_successful=False))
        chains = find_all_chains(state, print_fn=lambda *a: None)
        assert len(chains) == 1
        c = chains[0]
        assert c.start_sid == "A" and c.end_sid == "P"
        assert c.end_is_production is True
        # Hop method is annotated — operator can tell it isn't validated
        assert "UNTESTED" in c.hops[0].method
        assert "[untested]" in c.hops[0].description

    def test_self_connections_skipped(self):
        state = SAPMAPState()
        state.add_node(SAPNode(sid="A", ip="1", pwned=True))
        state.add_connection(RFCConnection(
            source_sid="A", source_host="a", target_sid="A", target_host="a", has_sap_all=True, logon_successful=True))
        chains = find_all_chains(state, print_fn=lambda *a: None)
        assert len(chains) == 0

    def test_btp_subaccount_with_cleartext_is_an_entry_point(self):
        """Operator's symptom: 4 cleartext-captured BTP destinations
        landed on a PRD-flagged S4H, but Analyse Chains returned
        zero paths — BTP subaccounts weren't being collected as
        entry points even when their pwned flag was True.  Synthetic
        BTP→on-prem edges in state.connections were a dead-end
        loop because BFS never seeded a "BTP:..." starting SID."""
        from sapmap_models import BTPSubaccountNode

        state = SAPMAPState()
        # On-prem PRD target — the same shape we'd expect for an
        # S4H box that an operator just minted creds for.
        state.add_node(SAPNode(sid="S4H", ip="192.168.2.209",
                                hostname="s4hanadev",
                                is_production=True))
        # BTP subaccount that captured a cleartext destination
        # password during link_destinations_to_onprem.  pwned=True
        # is the canonical "this BTP entry point is exploitable"
        # signal.
        sub = BTPSubaccountNode(
            uuid="90a90189-aaaa-bbbb-cccc-dddddddddddd",
            subdomain="researchlab-yehctg7m", region="eu10",
            pwned=True)
        state.btp_subaccounts[sub.uuid] = sub
        # Synthetic edge written by link_destinations_to_onprem:
        # source_sid uses the BTP:<uuid8> sentinel; tested=False
        # so the analyser walks it with the UNTESTED flag.
        state.connections.append(RFCConnection(
            source_sid=f"BTP:{sub.uuid[:8]}",
            source_host=sub.subdomain,
            target_sid="S4H", target_host="s4hanadev",
            destination_name=f"BTP:{sub.uuid[:8]}::DemoDest",
            rfc_user="joris", client="001",
            conn_type="http",
            tested=False, logon_successful=False,
        ))

        chains = find_all_chains(state, print_fn=lambda *a: None)
        assert len(chains) == 1, (
            "BTP subaccount with cleartext destinations must be a "
            "valid chain entry point")
        c = chains[0]
        # Chain reads BTP:<uuid8> → S4H, lands on production.
        assert c.start_sid == f"BTP:{sub.uuid[:8]}"
        assert c.end_sid == "S4H"
        assert c.end_is_production is True
        assert c.entry_method == "btp_destination_leak"
        # Hop is annotated UNTESTED so the report reader knows the
        # cred hasn't been validated yet (clicking Test Connection
        # in the GUI would flip that).
        assert "UNTESTED" in c.hops[0].method

    def test_btp_subaccount_without_cleartext_is_not_an_entry_point(self):
        """A BTP subaccount that's been enumerated but produced no
        cleartext credentials (token lacked ApiAccess) MUST NOT seed
        a chain — there's nothing exploitable on it."""
        from sapmap_models import BTPSubaccountNode

        state = SAPMAPState()
        state.add_node(SAPNode(sid="S4H", ip="192.168.2.209",
                                is_production=True))
        sub = BTPSubaccountNode(
            uuid="00000000-1111-2222-3333-444444444444",
            subdomain="empty-sub", region="eu10",
            pwned=False)   # <-- key bit
        state.btp_subaccounts[sub.uuid] = sub
        state.connections.append(RFCConnection(
            source_sid=f"BTP:{sub.uuid[:8]}",
            source_host=sub.subdomain,
            target_sid="S4H", target_host="s4hanadev",
            destination_name=f"BTP:{sub.uuid[:8]}::SomeDest",
            tested=False, logon_successful=False,
        ))
        chains = find_all_chains(state, print_fn=lambda *a: None)
        assert chains == []


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


# ---------------------------------------------------------------------------
# DBCON direct-DB pivot as a first-class chain edge (issue #21)
# ---------------------------------------------------------------------------

def test_dbcon_edge_appears_in_chain():
    """A pwned SAP source with a SAP-shape DBCON edge to another SID
    should yield a chain hop labeled DBCON."""
    from sapmap_models import DBCONConnection
    state = SAPMAPState()
    s4h = SAPNode(sid="S4H", ip="10.0.0.1", pwned=True, is_production=True)
    s4h.dbcon_edges = [DBCONConnection(
        source_sid="S4H", con_name="TEST_S4D", dbms="HDB",
        host="s4hanadev", port=30215, user="saphanadb",
        password="pw", tested=True, reachable=True,
        is_sap_shape=True, target_sid="S4D", pwned=True)]
    s4d = SAPNode(sid="S4D", ip="s4hanadev", hostname="s4hanadev",
                    discovered_via_dbcon=True)
    state.add_node(s4h); state.add_node(s4d)
    chains = find_all_chains(state)
    dbcon_chains = [c for c in chains
                    if any(h.target_sid == "S4D" for h in c.hops)]
    assert dbcon_chains, "expected at least one chain reaching S4D via DBCON"
    hop = [h for h in dbcon_chains[0].hops if h.target_sid == "S4D"][0]
    assert "DBCON" in hop.method
    assert "PWNED" in hop.method   # edge.pwned reflects has_sap_all
    assert "[dbcon]" in hop.description


def test_dbcon_non_sap_shape_edge_skipped_in_chain():
    """A non-SAP-shape DBCON is data-extraction only — not a
    user-plantable lateral hop.  The chain BFS must skip it."""
    from sapmap_models import DBCONConnection
    state = SAPMAPState()
    src = SAPNode(sid="S4H", ip="10.0.0.1", pwned=True)
    src.dbcon_edges = [DBCONConnection(
        source_sid="S4H", con_name="TEST_S4D", dbms="HDB",
        host="10.9.9.9", port=30215, user="x", password="y",
        tested=True, reachable=True, is_sap_shape=False,
        target_sid="DWH")]
    tgt = SAPNode(sid="DWH", ip="10.9.9.9")
    state.add_node(src); state.add_node(tgt)
    chains = find_all_chains(state)
    assert not any(
        any(h.target_sid == "DWH" and "DBCON" in h.method for h in c.hops)
        for c in chains), \
        "non-SAP-shape DBCON should not yield a chain hop"
