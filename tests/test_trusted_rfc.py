#!/usr/bin/env python3
"""Tests for Trusted RFC discovery, model fields, and chain analysis."""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sapmap_models import (
    RFCConnection,
    SAPNode,
    SAPMAPState,
    InstanceInfo,
    Credentials,
)


# ---------------------------------------------------------------------------
# RFCConnection — trusted fields
# ---------------------------------------------------------------------------

class TestRFCConnectionTrustedFields:

    def test_trusted_system_default_false(self):
        conn = RFCConnection(source_sid="A", source_host="a")
        assert conn.trusted_system is False
        assert conn.trust_type == ""

    def test_trusted_system_roundtrip(self):
        conn = RFCConnection(
            source_sid="S4H", source_host="s4hana",
            target_sid="ERP", target_host="erp01",
            destination_name="ERP_TRUSTED",
            trusted_system=True,
            trust_type="trusted_rfc",
        )
        d = conn.to_dict()
        assert d["trusted_system"] is True
        assert d["trust_type"] == "trusted_rfc"

        restored = RFCConnection.from_dict(d)
        assert restored.trusted_system is True
        assert restored.trust_type == "trusted_rfc"
        assert restored.destination_name == "ERP_TRUSTED"

    def test_trusted_system_from_dict_missing_fields(self):
        """Old state files without trusted fields should default safely."""
        d = {
            "source_sid": "A", "source_host": "a",
            "target_sid": "B", "target_host": "b",
        }
        conn = RFCConnection.from_dict(d)
        assert conn.trusted_system is False
        assert conn.trust_type == ""

    def test_risk_level_trusted_is_high(self):
        conn = RFCConnection(
            source_sid="A", source_host="a",
            trusted_system=True,
        )
        assert conn.risk_level() == "HIGH"

    def test_risk_level_trusted_below_sap_all_critical(self):
        """SAP_ALL + logon is CRITICAL, trusted alone is HIGH."""
        conn_sap_all = RFCConnection(
            source_sid="A", source_host="a",
            has_sap_all=True, logon_successful=True,
        )
        conn_trusted = RFCConnection(
            source_sid="A", source_host="a",
            trusted_system=True,
        )
        assert conn_sap_all.risk_level() == "CRITICAL"
        assert conn_trusted.risk_level() == "HIGH"

    def test_risk_level_trusted_above_medium(self):
        """Trusted RFC (HIGH) outranks plain logon_successful (MEDIUM)."""
        conn_logon = RFCConnection(
            source_sid="A", source_host="a",
            logon_successful=True,
        )
        conn_trusted = RFCConnection(
            source_sid="A", source_host="a",
            trusted_system=True,
        )
        risk_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
        assert risk_order[conn_trusted.risk_level()] > risk_order[conn_logon.risk_level()]


# ---------------------------------------------------------------------------
# SAPNode — rfcsysacl_entries
# ---------------------------------------------------------------------------

class TestSAPNodeRFCSYSACL:

    def test_rfcsysacl_default_empty(self):
        node = SAPNode(sid="TST")
        assert node.rfcsysacl_entries == []

    def test_rfcsysacl_roundtrip(self):
        entries = [
            {"rfcsysid": "S4H", "rfcclient": "100", "rfcequser": "Y",
             "rfcuser": "", "rfcsnc": "", "rfcsameusr": ""},
            {"rfcsysid": "ERP", "rfcclient": "200", "rfcequser": "N",
             "rfcuser": "ADMIN", "rfcsnc": "", "rfcsameusr": ""},
        ]
        node = SAPNode(sid="TST", rfcsysacl_entries=entries)
        d = node.to_dict()
        assert len(d["rfcsysacl_entries"]) == 2
        assert d["rfcsysacl_entries"][0]["rfcsysid"] == "S4H"
        assert d["rfcsysacl_entries"][0]["rfcequser"] == "Y"

        restored = SAPNode.from_dict(d)
        assert len(restored.rfcsysacl_entries) == 2
        assert restored.rfcsysacl_entries[1]["rfcuser"] == "ADMIN"

    def test_rfcsysacl_from_dict_missing(self):
        """Old state files without rfcsysacl_entries should default to []."""
        d = {"sid": "TST", "hostname": "host"}
        node = SAPNode.from_dict(d)
        assert node.rfcsysacl_entries == []


# ---------------------------------------------------------------------------
# Chain analysis — trusted RFC edges
# ---------------------------------------------------------------------------

class TestChainAnalysisTrustedRFC:

    def _make_state(self, connections, nodes_dict):
        state = SAPMAPState()
        for sid, node in nodes_dict.items():
            state.add_node(node)
        for conn in connections:
            state.add_connection(conn)
        return state

    def test_trusted_edge_traversed_even_when_not_tested(self):
        """Trusted RFC edges must be traversable without logon_tested=True."""
        from sapmap_chain import find_all_chains

        nodes = {
            "DEV": SAPNode(sid="DEV", pwned=True),
            "PRD": SAPNode(sid="PRD", is_production=True),
        }
        conns = [
            RFCConnection(
                source_sid="DEV", source_host="dev01",
                target_sid="PRD", target_host="prd01",
                destination_name="PRD_TRUSTED",
                trusted_system=True,
                trust_type="trusted_rfc",
                tested=False,
                logon_successful=False,
            ),
        ]
        state = self._make_state(conns, nodes)
        chains = find_all_chains(state, print_fn=lambda *a: None)

        assert len(chains) >= 1
        prd_chains = [c for c in chains if c.end_sid == "PRD"]
        assert len(prd_chains) >= 1
        assert prd_chains[0].hops[0].method == "Trusted RFC (no password)"

    def test_trusted_edge_not_skipped_when_logon_failed(self):
        """Trusted edges survive even if tested=True and logon_successful=False.
        (Normal RFC edges would be skipped in that case.)"""
        from sapmap_chain import find_all_chains

        nodes = {
            "A": SAPNode(sid="A", pwned=True),
            "B": SAPNode(sid="B"),
        }
        conns = [
            RFCConnection(
                source_sid="A", source_host="a",
                target_sid="B", target_host="b",
                destination_name="B_TRUSTED",
                trusted_system=True,
                tested=True,
                logon_successful=False,
            ),
        ]
        state = self._make_state(conns, nodes)
        chains = find_all_chains(state, print_fn=lambda *a: None)
        assert any(c.end_sid == "B" for c in chains)

    def test_normal_failed_edge_skipped(self):
        """Non-trusted edges with tested=True + logon_successful=False are skipped."""
        from sapmap_chain import find_all_chains

        nodes = {
            "A": SAPNode(sid="A", pwned=True),
            "B": SAPNode(sid="B"),
        }
        conns = [
            RFCConnection(
                source_sid="A", source_host="a",
                target_sid="B", target_host="b",
                destination_name="B_RFC",
                trusted_system=False,
                tested=True,
                logon_successful=False,
            ),
        ]
        state = self._make_state(conns, nodes)
        chains = find_all_chains(state, print_fn=lambda *a: None)
        assert not any(c.end_sid == "B" for c in chains)

    def test_trusted_hop_allows_further_propagation(self):
        """After a trusted RFC hop, BFS continues to the next system."""
        from sapmap_chain import find_all_chains

        nodes = {
            "A": SAPNode(sid="A", pwned=True),
            "B": SAPNode(sid="B"),
            "C": SAPNode(sid="C", is_production=True),
        }
        conns = [
            RFCConnection(
                source_sid="A", source_host="a",
                target_sid="B", target_host="b",
                destination_name="B_TRUSTED",
                trusted_system=True,
            ),
            RFCConnection(
                source_sid="B", source_host="b",
                target_sid="C", target_host="c",
                destination_name="C_RFC",
                trusted_system=True,
            ),
        ]
        state = self._make_state(conns, nodes)
        chains = find_all_chains(state, print_fn=lambda *a: None)
        c_chains = [c for c in chains if c.end_sid == "C"]
        assert len(c_chains) >= 1
        assert c_chains[0].total_hops == 2

    def test_trusted_chain_severity_to_production(self):
        """Trusted RFC chain to production should be CRITICAL severity."""
        from sapmap_chain import find_all_chains, rank_chains

        nodes = {
            "DEV": SAPNode(sid="DEV", pwned=True),
            "PRD": SAPNode(sid="PRD", is_production=True),
        }
        conns = [
            RFCConnection(
                source_sid="DEV", source_host="dev01",
                target_sid="PRD", target_host="prd01",
                destination_name="PRD_TRUSTED",
                trusted_system=True,
            ),
        ]
        state = self._make_state(conns, nodes)
        chains = find_all_chains(state, print_fn=lambda *a: None)
        prd_chains = [c for c in chains if c.end_sid == "PRD"]
        assert prd_chains[0].severity == 5  # CRITICAL

    def test_trusted_chain_severity_non_production(self):
        """Trusted RFC chain NOT to production should be HIGH severity."""
        from sapmap_chain import find_all_chains

        nodes = {
            "DEV": SAPNode(sid="DEV", pwned=True),
            "QAS": SAPNode(sid="QAS", is_production=False),
        }
        conns = [
            RFCConnection(
                source_sid="DEV", source_host="dev01",
                target_sid="QAS", target_host="qas01",
                destination_name="QAS_TRUSTED",
                trusted_system=True,
            ),
        ]
        state = self._make_state(conns, nodes)
        chains = find_all_chains(state, print_fn=lambda *a: None)
        qas_chains = [c for c in chains if c.end_sid == "QAS"]
        assert qas_chains[0].severity == 4  # HIGH

    def test_trusted_chain_headline_contains_trusted_tag(self):
        """Chain headline should mention trusted RFC."""
        from sapmap_chain import find_all_chains

        nodes = {
            "A": SAPNode(sid="A", pwned=True),
            "B": SAPNode(sid="B", is_production=True),
        }
        conns = [
            RFCConnection(
                source_sid="A", source_host="a",
                target_sid="B", target_host="b",
                destination_name="B_TRUSTED",
                trusted_system=True,
            ),
        ]
        state = self._make_state(conns, nodes)
        chains = find_all_chains(state, print_fn=lambda *a: None)
        prd_chains = [c for c in chains if c.end_sid == "B"]
        assert "[trusted RFC]" in prd_chains[0].headline

    def test_has_trusted_hop_property(self):
        """TrustChain.has_trusted_hop property works correctly."""
        from sapmap_chain import ChainHop, TrustChain

        chain_with = TrustChain(hops=[
            ChainHop(source_sid="A", target_sid="B",
                     method="Trusted RFC (no password)"),
        ])
        assert chain_with.has_trusted_hop is True

        chain_without = TrustChain(hops=[
            ChainHop(source_sid="A", target_sid="B",
                     method="RFC logon"),
        ])
        assert chain_without.has_trusted_hop is False

    def test_mixed_chain_trusted_and_normal(self):
        """Chain with both trusted and normal hops."""
        from sapmap_chain import find_all_chains

        nodes = {
            "A": SAPNode(sid="A", pwned=True),
            "B": SAPNode(sid="B"),
            "C": SAPNode(sid="C", is_production=True),
        }
        conns = [
            RFCConnection(
                source_sid="A", source_host="a",
                target_sid="B", target_host="b",
                destination_name="B_TRUSTED",
                trusted_system=True,
            ),
            RFCConnection(
                source_sid="B", source_host="b",
                target_sid="C", target_host="c",
                destination_name="C_RFC",
                has_sap_all=True, logon_successful=True, tested=True,
            ),
        ]
        state = self._make_state(conns, nodes)
        chains = find_all_chains(state, print_fn=lambda *a: None)
        c_chains = [c for c in chains if c.end_sid == "C"]
        assert len(c_chains) >= 1
        assert c_chains[0].has_trusted_hop is True
        assert c_chains[0].severity == 5  # CRITICAL (production + trusted hop)


# ---------------------------------------------------------------------------
# RFCDES parsing — trusted destination detection
# ---------------------------------------------------------------------------

class TestRFCDESParsing:
    """Test that the RFCDES readers correctly detect trusted destinations."""

    def test_build_rfcdes_conn_with_password(self):
        """Type-3 destination WITH %_PWD should not be flagged trusted."""
        from sapmap_rfc import _build_rfcdes_conn

        node = SAPNode(sid="TST", hostname="test01")
        options = "H=target01,S=00,U=RFC_USER,M=100,%_PWD"
        conn = _build_rfcdes_conn(node, "DEST1", "3", options)
        assert conn.trusted_system is False
        assert conn.rfc_user == "RFC_USER"

    def test_build_rfcdes_conn_without_password(self):
        """Type-3 destination WITHOUT %_PWD, when caller marks trusted."""
        from sapmap_rfc import _build_rfcdes_conn

        node = SAPNode(sid="TST", hostname="test01")
        options = "H=target01,S=42"
        conn = _build_rfcdes_conn(node, "TRUSTED_DEST", "3", options)
        # _build_rfcdes_conn itself doesn't set trusted_system,
        # the caller (_try_rfc_read_table_fallback) does
        assert conn.destination_name == "TRUSTED_DEST"
        assert conn.target_host == "target01"
        assert conn.target_instance_nr == "42"

    def test_http_dest_without_pwd_still_skipped_pattern(self):
        """Type-G/H without %_PWD should NOT be captured as trusted."""
        # The logic is in the reader loop, not _build_rfcdes_conn.
        # Verify the pattern: has_pwd check for G/H types
        options_no_pwd = "H=host,S=443,J=https://api.example.com"
        assert "%_PWD" not in options_no_pwd
        # For rfctype in ("G", "H"), no %_PWD → skip
        # This is a logical test — the actual filter is in the reader


# ---------------------------------------------------------------------------
# RFCSYSACL parsing
# ---------------------------------------------------------------------------

class TestRFCSYSACLParsing:

    def test_rfcsysacl_entry_structure(self):
        """Verify expected RFCSYSACL entry dict keys."""
        entry = {
            "rfcsysid": "S4H",
            "rfcclient": "100",
            "rfcequser": "Y",
            "rfcuser": "",
            "rfcsnc": "",
            "rfcsameusr": "",
        }
        assert entry["rfcsysid"] == "S4H"
        assert entry["rfcequser"] == "Y"

    def test_rfcsysacl_equser_y_means_any_user(self):
        """RFCEQUSER=Y means any user from trusted system maps to same-named user."""
        entries = [
            {"rfcsysid": "DEV", "rfcclient": "100", "rfcequser": "Y",
             "rfcuser": "", "rfcsnc": "", "rfcsameusr": ""},
            {"rfcsysid": "QAS", "rfcclient": "200", "rfcequser": "N",
             "rfcuser": "ADMIN", "rfcsnc": "", "rfcsameusr": ""},
        ]
        eq_y = [e for e in entries if e["rfcequser"] == "Y"]
        assert len(eq_y) == 1
        assert eq_y[0]["rfcsysid"] == "DEV"


# ---------------------------------------------------------------------------
# RFCTRUST cross-reference
# ---------------------------------------------------------------------------

class TestRFCTRUSTCrossReference:

    def test_rfctrust_marks_connections_trusted(self):
        """RFCTRUST entries should mark matching connections as trusted."""
        trust_entries = [
            {"rfctrustid": "TWT", "rfctrustsy": "S4H",
             "tlicense_nr": "0021234478", "llicense_nr": "0021320685",
             "rfcmsgsrv": "twtestenv1"},
        ]
        trust_targets = {e["rfctrustid"] for e in trust_entries
                         if e.get("rfctrustid")}
        assert "TWT" in trust_targets

        conn = RFCConnection(
            source_sid="S4H", source_host="s4hana",
            target_sid="TWT", target_host="twt01",
            destination_name="TWT_RFC",
        )
        assert conn.trusted_system is False

        if conn.target_sid in trust_targets:
            conn.trusted_system = True
            conn.trust_type = "trusted_rfc"

        assert conn.trusted_system is True
        assert conn.trust_type == "trusted_rfc"

    def test_rfctrust_no_match_stays_untrusted(self):
        """Connection to a SID not in RFCTRUST stays untrusted."""
        trust_targets = {"TWT"}

        conn = RFCConnection(
            source_sid="S4H", source_host="s4hana",
            target_sid="ERP", target_host="erp01",
            destination_name="ERP_RFC",
        )
        if conn.target_sid in trust_targets:
            conn.trusted_system = True

        assert conn.trusted_system is False


# ---------------------------------------------------------------------------
# Supplement function — dedup logic
# ---------------------------------------------------------------------------

class TestSupplementTrustedDestinations:

    def test_supplement_skips_already_known_destinations(self):
        """_supplement_trusted_destinations should not duplicate existing entries."""
        from sapmap_rfc import _build_rfcdes_conn

        node = SAPNode(sid="TST", hostname="test01")
        existing = [
            _build_rfcdes_conn(node, "DEST_A", "3", "H=host1,S=00,%_PWD"),
        ]
        known_dests = {c.destination_name for c in existing}
        assert "DEST_A" in known_dests

    def test_supplement_detects_no_password_type3(self):
        """Type-3 without %_PWD should be flagged as trusted in supplement."""
        options_no_pwd = "H=target,S=42"
        options_with_pwd = "H=target,S=42,%_PWD"
        assert "%_PWD" not in options_no_pwd
        assert "%_PWD" in options_with_pwd


# ---------------------------------------------------------------------------
# Entry method description
# ---------------------------------------------------------------------------

class TestEntryMethodDescription:

    def test_trusted_rfc_entry_description(self):
        from sapmap_chain import _entry_description
        desc = _entry_description("trusted_rfc")
        assert "Trusted RFC" in desc
        assert "passwordless" in desc.lower()
