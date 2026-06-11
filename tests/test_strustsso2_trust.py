#!/usr/bin/env python3
"""Tests for Tier 2: STRUSTSSO2 trust discovery, TrustRelation model,
TRUSTS_ISSUER chain edges, and fanout target derivation."""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sapmap_models import (
    RFCConnection,
    SAPNode,
    SAPMAPState,
    TrustRelation,
    ForgedTicket,
)


# ---------------------------------------------------------------------------
# TrustRelation dataclass
# ---------------------------------------------------------------------------

class TestTrustRelation:

    def test_minimal_init(self):
        rel = TrustRelation(trusting_sid="TWT", issuer_sid="S4H")
        assert rel.trusting_sid == "TWT"
        assert rel.issuer_sid == "S4H"
        assert rel.trust_method == "strustsso2"
        assert rel.discovered_at  # auto-populated

    def test_roundtrip(self):
        rel = TrustRelation(
            trusting_sid="TWT",
            trusting_client="100",
            issuer_sid="S4H",
            issuer_cert_subject_dn="CN=SAPSYS, O=SAP, C=DE",
            issuer_cert_serial="0A1B2C3D",
            trust_method="strustsso2",
            discovered_via="USREXTID",
        )
        d = rel.to_dict()
        restored = TrustRelation.from_dict(d)
        assert restored.trusting_sid == "TWT"
        assert restored.issuer_sid == "S4H"
        assert restored.issuer_cert_subject_dn == "CN=SAPSYS, O=SAP, C=DE"
        assert restored.issuer_cert_serial == "0A1B2C3D"
        assert restored.trust_method == "strustsso2"
        assert restored.discovered_via == "USREXTID"

    def test_from_dict_minimal(self):
        d = {"trusting_sid": "T", "issuer_sid": "I"}
        rel = TrustRelation.from_dict(d)
        assert rel.trusting_sid == "T"
        assert rel.issuer_sid == "I"
        assert rel.trust_method == "strustsso2"  # default


# ---------------------------------------------------------------------------
# SAPMAPState — trust_relations storage
# ---------------------------------------------------------------------------

class TestSAPMAPStateTrust:

    def test_trust_relations_default_empty(self):
        state = SAPMAPState()
        assert state.trust_relations == []

    def test_trust_relations_roundtrip(self):
        state = SAPMAPState()
        state.trust_relations.append(
            TrustRelation(trusting_sid="TWT", issuer_sid="S4H"))
        state.trust_relations.append(
            TrustRelation(trusting_sid="PRD", issuer_sid="S4H",
                          discovered_via="USRACL"))
        d = state.to_dict()
        assert len(d["trust_relations"]) == 2
        assert d["trust_relations"][0]["trusting_sid"] == "TWT"

        restored = SAPMAPState.from_dict(d)
        assert len(restored.trust_relations) == 2
        assert restored.trust_relations[1].discovered_via == "USRACL"

    def test_trust_relations_from_dict_missing(self):
        d = {"version": "1.0"}
        state = SAPMAPState.from_dict(d)
        assert state.trust_relations == []


# ---------------------------------------------------------------------------
# SAPNode — SAPSYS cert provenance
# ---------------------------------------------------------------------------

class TestSAPNodeCertProvenance:

    def test_cert_fields_default_empty(self):
        node = SAPNode(sid="TST")
        assert node.sapsys_cert_subject_dn == ""
        assert node.sapsys_cert_issuer_dn == ""
        assert node.sapsys_cert_serial == ""

    def test_cert_fields_roundtrip(self):
        node = SAPNode(
            sid="S4H",
            sapsys_cert_subject_dn="CN=SAPSYS, O=SAP",
            sapsys_cert_issuer_dn="CN=SAP CA, O=SAP",
            sapsys_cert_serial="A1B2C3",
        )
        d = node.to_dict()
        assert d["sapsys_cert_subject_dn"] == "CN=SAPSYS, O=SAP"
        assert d["sapsys_cert_issuer_dn"] == "CN=SAP CA, O=SAP"
        assert d["sapsys_cert_serial"] == "A1B2C3"

        restored = SAPNode.from_dict(d)
        assert restored.sapsys_cert_subject_dn == "CN=SAPSYS, O=SAP"
        assert restored.sapsys_cert_serial == "A1B2C3"

    def test_cert_fields_from_dict_missing(self):
        d = {"sid": "TST", "hostname": "host"}
        node = SAPNode.from_dict(d)
        assert node.sapsys_cert_subject_dn == ""


# ---------------------------------------------------------------------------
# Chain analysis — TRUSTS_ISSUER edges
# ---------------------------------------------------------------------------

class TestChainAnalysisStrustsso2:

    def _make_state(self, connections, nodes_dict,
                    trust_relations=None):
        state = SAPMAPState()
        for sid, node in nodes_dict.items():
            state.add_node(node)
        for conn in connections:
            state.add_connection(conn)
        if trust_relations:
            state.trust_relations.extend(trust_relations)
        return state

    def test_pse_stolen_is_entry_point(self):
        """Node with forged_tickets becomes an entry point."""
        from sapmap_chain import find_all_chains

        nodes = {
            "S4H": SAPNode(sid="S4H"),  # not pwned, no creds
            "TWT": SAPNode(sid="TWT"),
        }
        nodes["S4H"].forged_tickets.append(ForgedTicket(
            user="SAP*", client="100", sid="S4H",
            cookie_b64="dGVzdA==",
        ))
        trust = [
            TrustRelation(trusting_sid="TWT", issuer_sid="S4H"),
        ]
        state = self._make_state([], nodes, trust)
        chains = find_all_chains(state, print_fn=lambda *a: None)

        twt_chains = [c for c in chains if c.end_sid == "TWT"]
        assert len(twt_chains) >= 1
        assert twt_chains[0].start_sid == "S4H"
        assert "STRUSTSSO2" in twt_chains[0].hops[0].method

    def test_sso2_hop_method_labelled(self):
        from sapmap_chain import find_all_chains

        nodes = {
            "S4H": SAPNode(sid="S4H", pwned=True),
            "TWT": SAPNode(sid="TWT"),
        }
        trust = [
            TrustRelation(trusting_sid="TWT", issuer_sid="S4H",
                          discovered_via="USREXTID"),
        ]
        state = self._make_state([], nodes, trust)
        chains = find_all_chains(state, print_fn=lambda *a: None)
        twt_chains = [c for c in chains if c.end_sid == "TWT"]
        assert len(twt_chains) >= 1
        assert twt_chains[0].hops[0].method == \
            "Forged MYSAPSSO2 ticket (STRUSTSSO2)"

    def test_sso2_hop_allows_propagation(self):
        """After STRUSTSSO2 hop, BFS continues (impersonated user has SAP_ALL)."""
        from sapmap_chain import find_all_chains

        nodes = {
            "S4H": SAPNode(sid="S4H", pwned=True),
            "TWT": SAPNode(sid="TWT"),
            "PRD": SAPNode(sid="PRD", is_production=True),
        }
        trust = [
            TrustRelation(trusting_sid="TWT", issuer_sid="S4H"),
        ]
        conns = [
            RFCConnection(
                source_sid="TWT", source_host="twt",
                target_sid="PRD", target_host="prd",
                destination_name="PRD_RFC",
                has_sap_all=True, logon_successful=True, tested=True,
            ),
        ]
        state = self._make_state(conns, nodes, trust)
        chains = find_all_chains(state, print_fn=lambda *a: None)
        prd_chains = [c for c in chains if c.end_sid == "PRD"
                      and c.start_sid == "S4H"]
        assert len(prd_chains) >= 1
        assert prd_chains[0].total_hops == 2

    def test_sso2_chain_severity_to_production(self):
        from sapmap_chain import find_all_chains

        nodes = {
            "S4H": SAPNode(sid="S4H", pwned=True),
            "PRD": SAPNode(sid="PRD", is_production=True),
        }
        trust = [
            TrustRelation(trusting_sid="PRD", issuer_sid="S4H"),
        ]
        state = self._make_state([], nodes, trust)
        chains = find_all_chains(state, print_fn=lambda *a: None)
        prd_chains = [c for c in chains if c.end_sid == "PRD"]
        assert prd_chains[0].severity == 5  # CRITICAL

    def test_sso2_chain_severity_non_production(self):
        from sapmap_chain import find_all_chains

        nodes = {
            "S4H": SAPNode(sid="S4H", pwned=True),
            "QAS": SAPNode(sid="QAS"),
        }
        trust = [
            TrustRelation(trusting_sid="QAS", issuer_sid="S4H"),
        ]
        state = self._make_state([], nodes, trust)
        chains = find_all_chains(state, print_fn=lambda *a: None)
        qas_chains = [c for c in chains if c.end_sid == "QAS"]
        assert qas_chains[0].severity == 4  # HIGH

    def test_sso2_headline_tag(self):
        from sapmap_chain import find_all_chains

        nodes = {
            "S4H": SAPNode(sid="S4H", pwned=True),
            "PRD": SAPNode(sid="PRD", is_production=True),
        }
        trust = [
            TrustRelation(trusting_sid="PRD", issuer_sid="S4H"),
        ]
        state = self._make_state([], nodes, trust)
        chains = find_all_chains(state, print_fn=lambda *a: None)
        prd_chains = [c for c in chains if c.end_sid == "PRD"]
        assert "[STRUSTSSO2 ticket]" in prd_chains[0].headline

    def test_has_sso2_hop_property(self):
        from sapmap_chain import ChainHop, TrustChain

        chain_with = TrustChain(hops=[
            ChainHop(source_sid="A", target_sid="B",
                     method="Forged MYSAPSSO2 ticket (STRUSTSSO2)"),
        ])
        assert chain_with.has_sso2_hop is True

        chain_without = TrustChain(hops=[
            ChainHop(source_sid="A", target_sid="B",
                     method="RFC logon"),
        ])
        assert chain_without.has_sso2_hop is False

    def test_self_trust_edge_skipped(self):
        """A TrustRelation where trusting_sid == issuer_sid shouldn't loop."""
        from sapmap_chain import find_all_chains

        nodes = {
            "S4H": SAPNode(sid="S4H", pwned=True),
        }
        trust = [
            TrustRelation(trusting_sid="S4H", issuer_sid="S4H"),
        ]
        state = self._make_state([], nodes, trust)
        chains = find_all_chains(state, print_fn=lambda *a: None)
        # No chain to self
        assert not any(c.end_sid == "S4H" for c in chains)


# ---------------------------------------------------------------------------
# Fanout target derivation
# ---------------------------------------------------------------------------

class TestFanoutTargetDerivation:

    def test_fanout_from_trust_relations(self):
        """Given a state with trust relations, derive fanout targets."""
        state = SAPMAPState()
        state.trust_relations.extend([
            TrustRelation(trusting_sid="TWT", issuer_sid="S4H"),
            TrustRelation(trusting_sid="PRD", issuer_sid="S4H"),
            TrustRelation(trusting_sid="QAS", issuer_sid="OTHER"),
            TrustRelation(trusting_sid="S4H", issuer_sid="S4H"),  # self
        ])
        fanout_sids = []
        for rel in state.trust_relations:
            if rel.issuer_sid != "S4H":
                continue
            if rel.trusting_sid == "S4H":
                continue
            if rel.trusting_sid not in fanout_sids:
                fanout_sids.append(rel.trusting_sid)
        assert fanout_sids == ["TWT", "PRD"]

    def test_fanout_empty_when_no_trust(self):
        state = SAPMAPState()
        fanout = [r.trusting_sid for r in state.trust_relations
                  if r.issuer_sid == "S4H"]
        assert fanout == []


# ---------------------------------------------------------------------------
# Cross-reference cert DN to SID
# ---------------------------------------------------------------------------

class TestCertDnCrossReference:

    def test_cross_reference_subject_to_sid(self):
        """Build cert_dn → sid lookup and resolve issuer."""
        state = SAPMAPState()
        state.add_node(SAPNode(
            sid="S4H",
            sapsys_cert_subject_dn="CN=S4H_SAPSYS, O=SAP"))
        state.add_node(SAPNode(
            sid="TWT",
            sapsys_cert_subject_dn="CN=TWT_SAPSYS, O=SAP"))

        cert_to_sid = {n.sapsys_cert_subject_dn: sid
                       for sid, n in state.nodes.items()
                       if n.sapsys_cert_subject_dn}
        assert cert_to_sid["CN=S4H_SAPSYS, O=SAP"] == "S4H"
        assert cert_to_sid["CN=TWT_SAPSYS, O=SAP"] == "TWT"

    def test_unresolved_cert_dn(self):
        """If cert DN doesn't match any node, issuer_sid stays empty."""
        state = SAPMAPState()
        state.add_node(SAPNode(
            sid="S4H",
            sapsys_cert_subject_dn="CN=S4H_SAPSYS"))
        cert_to_sid = {n.sapsys_cert_subject_dn: sid
                       for sid, n in state.nodes.items()
                       if n.sapsys_cert_subject_dn}
        assert cert_to_sid.get("CN=UNKNOWN", "") == ""


# ---------------------------------------------------------------------------
# Entry method description
# ---------------------------------------------------------------------------

class TestEntryMethodPseStolen:

    def test_pse_stolen_description(self):
        from sapmap_chain import _entry_description
        desc = _entry_description("pse_stolen")
        assert "PSE" in desc
        assert "MYSAPSSO2" in desc or "ticket" in desc.lower()
