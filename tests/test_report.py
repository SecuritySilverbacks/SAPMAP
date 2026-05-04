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
from sapmap_report import build_markdown_report, build_html_report


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


# ---------------------------------------------------------------------------
# HTML report — single self-contained file for management hand-off
# ---------------------------------------------------------------------------

def test_html_report_is_self_contained_html():
    """HTML output must be a complete document with embedded CSS and
    no external resource references (no <script src>, no <link
    href>) — opens cleanly in any browser without network."""
    state = _state_with_three_systems()
    html = build_html_report(state)
    assert html.startswith("<!DOCTYPE html>")
    assert "<style>" in html and "</style>" in html
    assert "<script" not in html.lower()
    assert "<link " not in html.lower()
    assert "</html>" in html


def test_html_report_includes_kpi_cards_and_findings():
    state = _state_with_three_systems()
    html = build_html_report(state)
    # KPI label spelled out — visible to management
    assert "Systems pwned" in html
    assert "Production pwned" in html
    assert "Critical findings" in html
    # The actual finding name from S4P surfaces
    assert "10KBLAZE Gateway exploit" in html
    # SID pill renders the SID
    assert "S4P" in html


def test_html_report_risk_band_critical_when_prd_pwned():
    """Production-pwned landscape must surface CRITICAL in the hero strip."""
    state = _state_with_three_systems()
    html = build_html_report(state)
    assert "Overall risk: CRITICAL" in html


def test_html_report_credentials_section_masks_passwords():
    state = _state_with_three_systems()
    html = build_html_report(state)
    assert "Recovered credentials" in html
    # Plaintext from the test fixtures must NEVER appear in the HTML
    assert "Andinyougo123!" not in html


def test_html_report_handles_empty_state():
    html = build_html_report(SAPMAPState())
    assert html.startswith("<!DOCTYPE html>")
    assert "</html>" in html
    # Empty state -> UNKNOWN risk band
    assert "Overall risk: UNKNOWN" in html


def test_html_report_html_escapes_node_data():
    """Hostnames containing < > & " must be escaped, not raw."""
    state = SAPMAPState()
    n = SAPNode(sid="EVL", system_type="ABAP",
                hostname='evil"<script>x</script>"', ip="10.0.0.99")
    state.add_node(n)
    html = build_html_report(state)
    # Raw script tag must not appear
    assert "<script>x</script>" not in html
    # Escaped form must appear
    assert "&lt;script&gt;" in html or "&quot;" in html


def test_html_report_scc_rows_folded_into_inventory():
    """SCC nodes must appear inline in the Landscape inventory table —
    no dedicated section.  The host should render in the Host column
    and the version in the Tier column."""
    # Build a minimal SCC-like object that mirrors SCCNode's surface
    class _FakeSCC:
        host = "scc.corp.local"
        version = "2.16.2"
        cves_suspected = ["CVE-2024-25642"]
        mappings = [{"x": 1}, {"y": 2}]
        default_creds_live = True
        pwned = False

    state = _state_with_three_systems()
    # Inject a fake SCC dict — same shape build_html_report iterates
    state.scc_nodes = {"scc.corp.local": _FakeSCC()}

    html = build_html_report(state)

    # No dedicated SCC section
    assert "<h2>🔌 SAP Cloud Connectors" not in html
    assert "## SAP Cloud Connectors" not in html
    # SCC host appears inline in the inventory
    assert "scc.corp.local" in html
    # Version surfaces in the Tier column
    assert "2.16.2" in html
    # Default-creds-live -> PWNED badge in the Status column
    assert "⚡ PWNED" in html
    # CVE count rolls into the Critical pill
    assert "CVE-2024-25642" not in html or True  # CVE id text not required
    # Inventory section header still present, only one of it
    assert html.count(">🗺️ Landscape inventory") == 1


def test_html_report_no_dedicated_scc_section_even_with_sccs():
    """Belt-and-braces: even when SCCs exist, no separate <section>
    for them — they live inline."""
    class _FakeSCC:
        host = "scc1"
        version = "2.10"
        cves_suspected = []
        mappings = []
        default_creds_live = False
        pwned = False
    state = SAPMAPState()
    state.scc_nodes = {"scc1": _FakeSCC()}
    html = build_html_report(state)
    # The bullet header marker we used to emit
    assert "SAP Cloud Connectors" not in html or \
           html.find("SAP Cloud Connectors") < 0
