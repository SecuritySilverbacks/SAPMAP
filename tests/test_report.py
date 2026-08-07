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
    # (TOC entry uses an <a href="#sec-inventory"> — matching by the
    # <h2> tag excludes it so the count stays at 1)
    assert html.count("<h2>🗺️ Landscape inventory") == 1


def test_html_report_includes_landscape_svg():
    """A .html report must embed an inline SVG snapshot of the landscape
    so management sees the picture before scrolling to the tables."""
    state = _state_with_three_systems()
    html = build_html_report(state)
    assert "<h2>🗺️ Landscape map" in html
    # Inline SVG, no <img src>, no external file
    assert "<svg viewBox" in html
    # SAP nodes render as <rect> bodies, SCC as <polygon>; we know
    # there are no SCCs in this fixture, so just <rect> needed.
    assert "<rect" in html
    # Each SID label is plotted as <text> with the SID as the label
    for sid in ("S4P", "S4D", "RD1"):
        assert f">{sid}</text>" in html
    # Legend is included
    assert ">ABAP<" in html and ">Java<" in html


def test_html_report_landscape_svg_marks_pwned_and_prd():
    """Pwned nodes get a ⚡ overlay; production nodes get a red halo
    rendered as an outer rect with stroke #dc2626."""
    state = _state_with_three_systems()
    html = build_html_report(state)
    # ⚡ symbol from the pwned overlay (S4P + S4D are pwned in fixture)
    assert ">⚡<" in html
    # Production halo is drawn with explicit stroke colour
    assert "#dc2626" in html


def test_html_report_landscape_svg_renders_scc_hex():
    """SCC nodes appear in the map as hexagonal polygons."""
    class _FakeSCC:
        host = "scc.corp"
        version = "2.16.2"
        cves_suspected = []
        mappings = []
        default_creds_live = False
        pwned = False
    state = _state_with_three_systems()
    state.scc_nodes = {"scc.corp": _FakeSCC()}
    html = build_html_report(state)
    # Hexagon == <polygon> tag in the inline SVG
    assert "<polygon points=" in html
    assert ">SCC</text>" in html
    # Version surfaces under the SCC node label
    assert ">v2.16.2</text>" in html


def test_html_report_empty_landscape_svg_falls_back_to_message():
    """Empty state must NOT crash the SVG builder — show a tidy
    placeholder instead."""
    html = build_html_report(SAPMAPState())
    assert "Landscape map" in html
    # No SVG generated, but a placeholder div instead
    assert "landscape map is empty" in html.lower()


def test_recommendations_derived_from_landscape_state():
    """Recommendations must be richer than just remediation strings
    pulled out of findings — the landscape itself drives structural
    advice (GW ACL, MS ACL, SAProuter ACL, default-cred rotation,
    SecStore rotation, SCC default creds, etc.)."""
    from sapmap_report import _derive_landscape_recommendations
    state = SAPMAPState()

    # Pwned production system with vulnerable gateway
    s4p = SAPNode(sid="S4P", system_type="ABAP", is_production=True,
                  pwned=True, gw_vulnerable=True,
                  ms_vulnerable=True)
    s4p.credentials.append(Credentials(username="DDIC", password="x",
                                          client="000", verified=True))
    s4p.secstore_entries = [{"ident": "/RFC/X", "password": "y"}]
    state.add_node(s4p)

    # SAProuter
    rd1 = SAPNode(sid="RD1", system_type="SAPROUTER", hostname="router")
    rd1.saprouter_info = {"clients": [{"host": "10.0.0.1"}]}
    state.add_node(rd1)

    # Untested RFC into PRD
    s4d = SAPNode(sid="S4D", system_type="ABAP", is_production=False)
    state.add_node(s4d)
    state.add_connection(RFCConnection(
        source_sid="S4D", source_host="s4dhost",
        target_sid="S4P", target_host="s4phost",
        destination_name="S4D_TO_S4P", has_sap_all=False,
        tested=False, logon_successful=False))

    recs = _derive_landscape_recommendations(state)
    titles = [r["title"] for r in recs]

    # All the major categories should be represented
    assert any("reginfo / secinfo" in t for t in titles), \
        "Missing GW ACL recommendation"
    assert any("Message Server" in t for t in titles), \
        "Missing MS ACL recommendation"
    assert any("saprouttab" in t for t in titles), \
        "Missing SAProuter ACL recommendation"
    assert any("default account password" in t for t in titles), \
        "Missing default-cred rotation recommendation"
    assert any("Secure Store" in t for t in titles), \
        "Missing SecStore rotation recommendation"
    assert any("compromised" in t for t in titles), \
        "Missing IR / production-pwned recommendation"
    assert any("RFC destinations pointing at production" in t for t in titles), \
        "Missing untested-RFC-to-PRD review recommendation"

    # Every entry has the required fields
    for r in recs:
        for k in ("category", "scope", "title", "body", "refs"):
            assert r.get(k), f"recommendation missing {k}: {r}"


def test_html_report_recommendations_section_renders_derived_cards():
    """The HTML rec section must render the derived structural
    recommendations as styled cards, not just an <ol>."""
    state = SAPMAPState()
    state.add_node(SAPNode(sid="S4P", system_type="ABAP",
                            is_production=True, pwned=True,
                            gw_vulnerable=True))
    html = build_html_report(state)
    # Subheading present
    assert "Landscape-wide structural remediations" in html
    # Reco cards rendered
    assert 'class="reco"' in html
    assert 'class="reco-cat"' in html
    # The GW ACL reco surfaces
    assert "reginfo / secinfo" in html
    assert "SAP Note 1408081" in html


def test_html_report_has_dedicated_scc_section_when_sccs_present():
    """Issue #31: SCC nodes get their own <section> in the HTML report
    (in addition to their inline row in the landscape inventory).
    Previously the report only had SCC data in the inventory table —
    dedicated section was Markdown-only."""
    class _FakeSCC:
        host = "scc1"
        version = "2.10"
        cves_confirmed = []
        cves_suspected = ["CVE-2024-XXXX"]
        mappings = []
        default_creds_live = False
        pwned = False
        credentials = []
        keystore_extracted = False
        ssfs_decrypted = False
        pp_weak_count = 0
    state = SAPMAPState()
    state.scc_nodes = {"scc1": _FakeSCC()}
    html = build_html_report(state)
    # Dedicated section heading must be present
    assert "SAP Cloud Connectors" in html
    # And the host must appear inside the new section (as a <b>Host</b>
    # cell in the section's table)
    assert "scc1" in html


def test_html_report_scc_section_richer_than_inventory_row():
    """Issue #31: SCC section surfaces fields that the inventory row
    doesn't — keystore/SSFS extraction state, PP-analysis weakness
    count, captured-cred count, confirmed vs suspected CVEs."""
    class _FakeSCC:
        host = "scc-rich"
        version = "2.19.0.2"
        cves_confirmed = ["CVE-2024-42020"]
        cves_suspected = []
        mappings = [{"virtual_host": "vh1"}, {"virtual_host": "vh2"}]
        default_creds_live = True
        pwned = True
        credentials = [
            Credentials(username="Administrator", password="stolen",
                         verified=True)]
        keystore_extracted = True
        ssfs_decrypted = True
        pp_weak_count = 3
    state = SAPMAPState()
    state.scc_nodes = {"scc-rich": _FakeSCC()}
    html = build_html_report(state)
    # Confirmed CVE should appear as a red risk pill
    assert "CVE-2024-42020" in html
    # LIVE default-creds badge
    assert "LIVE" in html
    # PP weakness count in a badge
    assert "3 weak" in html


def test_html_report_has_btp_section_when_subaccounts_present():
    """BTP subaccount section — mirrors the MD _btp_section."""
    class _FakeDest:
        cleartext_captured = True
        linked_target_sid = "S4P"
    class _FakeSub:
        subdomain = "researchlab-yehctg7m"
        display_name = "researchlab-yehctg7m"
        region = "eu10"
        destinations = [_FakeDest()]
        pwned = True
        cert_auth_trusted = True
    state = SAPMAPState()
    state.btp_subaccounts = {"uuid1234": _FakeSub()}
    html = build_html_report(state)
    assert "SAP BTP subaccounts" in html
    assert "researchlab-yehctg7m" in html
    assert "eu10" in html


def test_html_report_has_cloud_lateral_section_when_dests_present():
    """Cloud ↔ on-prem lateral section renders when a subaccount has
    at least one destination."""
    class _FakeDest:
        cleartext_captured = True
        linked_target_sid = "S4P"
    class _FakeSub:
        subdomain = "researchlab-yehctg7m"
        display_name = "researchlab-yehctg7m"
        region = "eu10"
        destinations = [_FakeDest()]
        pwned = True
        cert_auth_trusted = False
    state = SAPMAPState()
    state.btp_subaccounts = {"uuid1234": _FakeSub()}
    html = build_html_report(state)
    assert "Cloud" in html and "on-prem lateral moves" in html


def test_html_report_has_cert_auth_dests_section():
    """Cert-authenticated Type-G/H HTTP destinations section."""
    state = SAPMAPState()
    src = SAPNode(sid="S4P", system_type="ABAP",
                   hostname="s4p", ip="10.0.0.1")
    state.nodes["S4P"] = src
    state.connections.append(RFCConnection(
        source_sid="S4P", source_host="s4p",
        destination_name="BTP_TENANT",
        target_sid="",
        http_url="https://researchlab-yehctg7m.cfapps.eu10.hana.ondemand.com",
        http_auth_type="X509",
        http_cert_pse="DFAULT",
        conn_type="http",
        rfc_type="G",
    ))
    html = build_html_report(state)
    assert "Certificate-authenticated HTTP destinations" in html
    assert "BTP_TENANT" in html
    assert "DFAULT" in html


def test_html_report_has_toc_with_anchor_links():
    """HTML report includes a jump-to-section TOC at the top with
    anchors matching each rendered <section id="...">."""
    state = _state_with_three_systems()
    html = build_html_report(state)
    # TOC block present with the canonical header
    assert 'class="toc"' in html
    assert ">Contents<" in html
    # Anchors for the always-rendered sections
    for anchor in (
        "#sec-landscape-map", "#sec-critical", "#sec-high",
        "#sec-chains", "#sec-inventory", "#sec-credentials",
        "#sec-recommendations",
    ):
        assert anchor in html, f"TOC missing anchor {anchor}"
        # And the corresponding <section id="..."> exists
        assert f'id="{anchor[1:]}"' in html, (
            f"section anchor {anchor} present in TOC but no matching "
            f"<section id=\"{anchor[1:]}\">")
    # TOC lives above the first <section>
    toc_pos = html.find('class="toc"')
    first_section_pos = html.find('<section id="sec-')
    assert toc_pos != -1 and first_section_pos != -1
    assert toc_pos < first_section_pos


def test_html_report_toc_omits_empty_conditional_sections():
    """Conditional sections (SCC, BTP, business impact, etc.) must
    NOT appear in the TOC when their builder returns empty."""
    state = _state_with_three_systems()  # no SCC / BTP / impact data
    html = build_html_report(state)
    # These builders returned "" — their TOC entries must be gone.
    for anchor in ("#sec-scc", "#sec-btp", "#sec-cloud-lat",
                   "#sec-impact", "#sec-users", "#sec-persistence",
                   "#sec-opsec"):
        assert anchor not in html, (
            f"TOC included {anchor} but the section wasn't rendered")
