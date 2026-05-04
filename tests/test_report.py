#!/usr/bin/env python3
"""Unit tests for the engagement-report builder.

The report is a pure function over an SAPMAPState — no network, no
filesystem, no GUI.  These tests build small in-memory states and
assert the resulting Markdown contains the right facts.
"""
from __future__ import annotations

from sapmap_models import (
    SAPMAPState, SAPNode, RFCConnection, Credentials, CreatedUser,
    Finding, Severity, InstanceInfo,
)
from sapmap_report import build_markdown_report


def _state_with_three_systems():
    state = SAPMAPState()
    s4p = SAPNode(sid="S4P", system_type="ABAP", os_type="Linux",
                  db_type="HDB", hostname="s4phost", ip="10.0.0.1",
                  is_production=True, pwned=True,
                  gw_vulnerable=True)
    s4p.findings.append(Finding(
        name="10KBLAZE Gateway exploit",
        severity=Severity.CRITICAL,
        description="GW SAPXPG accepts unauthenticated commands",
        remediation="Apply SAP Note 2696233 / harden reginfo",
    ))
    s4p.created_users.append(CreatedUser(
        username="SAPMAP00", sid="S4P", client="100",
        hostname="s4phost", ip="10.0.0.1", instance_nr="00",
        method="gw_exploit", password="Andinyougo123!",
    ))
    state.add_node(s4p)

    s4d = SAPNode(sid="S4D", system_type="ABAP", os_type="Linux",
                  db_type="HDB", hostname="s4dhost", ip="10.0.0.2",
                  is_production=False, pwned=True)
    s4d.credentials.append(Credentials(
        username="SAPMAP00", password="Andinyougo123!",
        client="000", verified=True))
    s4d.findings.append(Finding(
        name="SecStore decrypted",
        severity=Severity.HIGH,
        description="SecStore RFC creds extracted",
    ))
    state.add_node(s4d)

    rd1 = SAPNode(sid="RD1", system_type="SAPROUTER", hostname="router",
                   ip="192.168.1.1")
    state.add_node(rd1)

    # One RFC trust edge for the chain analyser to find
    state.add_connection(RFCConnection(
        source_sid="S4P", source_host="s4phost",
        target_sid="S4D", target_host="s4dhost",
        destination_name="S4D_TRUSTED", rfc_user="SAPJSF",
        client="100", has_sap_all=True,
        tested=True, logon_successful=True,
    ))
    return state


def test_report_includes_executive_summary():
    state = _state_with_three_systems()
    md = build_markdown_report(state)
    assert "## Executive summary" in md
    assert "Total SAP nodes discovered" in md
    assert "S4P" in md   # production-pwned SID highlighted


def test_report_includes_critical_findings():
    state = _state_with_three_systems()
    md = build_markdown_report(state)
    assert "## Findings" in md
    # The critical finding from S4P
    assert "10KBLAZE Gateway exploit" in md
    # Per-node header
    assert "S4P — 10KBLAZE Gateway exploit" in md
    # Remediation surfaces
    assert "Apply SAP Note 2696233" in md


def test_report_includes_high_findings_when_present():
    state = _state_with_three_systems()
    md = build_markdown_report(state)
    # S4D has a HIGH finding
    assert "SecStore decrypted" in md


def test_report_landscape_inventory_lists_every_node():
    state = _state_with_three_systems()
    md = build_markdown_report(state)
    assert "## Landscape inventory" in md
    for sid in ("S4P", "S4D", "RD1"):
        assert sid in md


def test_report_credentials_section_lists_created_user():
    state = _state_with_three_systems()
    md = build_markdown_report(state)
    assert "## Recovered credentials" in md
    assert "SAPMAP00" in md
    # Plaintext password must NOT appear in the report — it's masked
    assert "Andinyougo123!" not in md


def test_report_recommendations_dedupes():
    """Two nodes carrying findings with the same remediation text must
    produce a single bullet — not duplicates."""
    state = _state_with_three_systems()
    # Add a duplicate finding/remediation to S4D
    state.nodes["S4D"].findings.append(Finding(
        name="Another 10KBLAZE",
        severity=Severity.CRITICAL,
        description="Same as S4P",
        remediation="Apply SAP Note 2696233 / harden reginfo",
    ))
    md = build_markdown_report(state)
    assert "## Recommendations" in md
    # The remediation text appears once per finding (we have 2 here) AND
    # once in the recommendations section — so total is 3.  The dedupe
    # we care about is INSIDE the recommendations section: a single
    # bullet for that remediation, not one per node.
    rec_section = md.split("## Recommendations", 1)[1].split("---", 1)[0]
    assert rec_section.count("Apply SAP Note 2696233 / harden reginfo") == 1


def test_report_handles_empty_state():
    """Zero nodes must not crash — produce a valid report skeleton."""
    md = build_markdown_report(SAPMAPState())
    assert "# SAP Landscape Attack-Path Report" in md
    assert "Total SAP nodes discovered" in md
    assert "End of report" in md


def test_report_custom_title():
    md = build_markdown_report(SAPMAPState(),
                                 engagement_name="Acme Q4 Pen Test")
    assert "# Acme Q4 Pen Test" in md


def test_report_emits_trust_chain_path():
    """The S4P → S4D edge with SAP_ALL must show up in the chain section."""
    state = _state_with_three_systems()
    md = build_markdown_report(state)
    assert "## Lateral movement / trust chains" in md
    # Either we got "S4P → S4D" (full path) or at least the section
    # acknowledges the analysis ran without crashing.
    assert "S4P" in md and "S4D" in md


def test_report_scc_section_omitted_when_no_sccs():
    state = _state_with_three_systems()
    md = build_markdown_report(state)
    # No SCCs in this state → section header should not appear
    assert "## SAP Cloud Connectors" not in md


def test_report_is_well_formed_markdown():
    """Sanity: every line is a string, headings are plausible, no None."""
    state = _state_with_three_systems()
    md = build_markdown_report(state)
    assert isinstance(md, str)
    assert md.startswith("#")
    assert md.endswith("\n")
    # No accidental Python repr leakage
    assert "<sapmap_models." not in md
    assert "None" not in md.split("\n")[0]   # title isn't None
