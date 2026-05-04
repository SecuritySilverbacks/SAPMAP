#!/usr/bin/env python3
"""Tests for sapmap_diff — pure-function diff between two SAPMAPState
snapshots plus Markdown / HTML rendering."""
from __future__ import annotations

import pytest

from sapmap_models import (
    SAPMAPState, SAPNode, RFCConnection, Credentials, CreatedUser,
    Finding, Severity,
)
from sapmap_diff import (
    compute_state_diff, build_diff_markdown, build_diff_html,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _baseline_state():
    """A small landscape: 2 SAP nodes, 1 RFC connection, 1 finding."""
    s = SAPMAPState()
    s.add_node(SAPNode(sid="S4P", system_type="ABAP",
                        is_production=True, pwned=False,
                        hostname="s4phost", ip="10.0.0.1"))
    s4d = SAPNode(sid="S4D", system_type="ABAP",
                   is_production=False, pwned=False,
                   hostname="s4dhost", ip="10.0.0.2")
    s4d.findings.append(Finding(
        name="MS Internal Port Without ACL (CVE-2020-6207)",
        severity=Severity.HIGH, description="MS port open"))
    s.add_node(s4d)
    s.add_connection(RFCConnection(
        source_sid="S4D", source_host="s4dhost",
        target_sid="S4P", target_host="s4phost",
        destination_name="S4D_TO_S4P", rfc_user="JORIS",
        has_sap_all=False, tested=False))
    return s


def _current_state():
    """Same landscape but: S4P now pwned, new finding, new SAP_ALL
    edge to PRD, S4D's old finding remediated, plus a fresh node JAV."""
    s = SAPMAPState()
    s4p = SAPNode(sid="S4P", system_type="ABAP",
                   is_production=True, pwned=True,    # newly pwned
                   has_critical_finding=True,
                   hostname="s4phost", ip="10.0.0.1")
    s4p.findings.append(Finding(
        name="SAPMAP User Created", severity=Severity.CRITICAL,
        description="SAPMAP00 created with SAP_ALL"))
    s4p.created_users.append(CreatedUser(
        username="SAPMAP00", sid="S4P", client="100",
        hostname="s4phost", ip="10.0.0.1",
        instance_nr="00", method="gw_exploit"))
    s.add_node(s4p)
    # S4D has a verified credential — makes it an entry point for the
    # chain analyser, so the new SAP_ALL edge S4D -> S4P (PRD) below
    # actually surfaces in trust_chains["added"].
    s4d_curr = SAPNode(sid="S4D", system_type="ABAP",
                        is_production=False, pwned=False,
                        hostname="s4dhost", ip="10.0.0.2")
    s4d_curr.credentials.append(Credentials(
        username="SAPMAP00", password="x",
        client="000", verified=True))
    s.add_node(s4d_curr)
    s.add_node(SAPNode(sid="JAV", system_type="JAVA",
                        is_production=False, pwned=False,
                        hostname="javhost", ip="10.0.0.3"))
    s.created_users.append(CreatedUser(
        username="SAPMAP00", sid="S4P", client="100",
        hostname="s4phost", ip="10.0.0.1",
        instance_nr="00", method="gw_exploit"))
    s.add_connection(RFCConnection(
        source_sid="S4D", source_host="s4dhost",
        target_sid="S4P", target_host="s4phost",
        destination_name="S4D_TO_S4P", rfc_user="JORIS",
        has_sap_all=True,                              # promoted!
        tested=True, logon_successful=True))
    return s


# ---------------------------------------------------------------------------
# compute_state_diff — structural correctness
# ---------------------------------------------------------------------------

def test_diff_detects_newly_pwned_node():
    diff = compute_state_diff(_baseline_state(), _current_state())
    assert diff["summary"]["newly_pwned_count"] == 1
    assert diff["summary"]["newly_pwned_sids"] == ["S4P"]


def test_diff_detects_added_node():
    diff = compute_state_diff(_baseline_state(), _current_state())
    sids_added = [n["sid"] for n in diff["nodes"]["added"]]
    assert "JAV" in sids_added
    assert diff["summary"]["nodes_added"] == 1


def test_diff_detects_removed_node():
    """Going the other direction should report the new node as removed."""
    diff = compute_state_diff(_current_state(), _baseline_state())
    sids_removed = [n["sid"] for n in diff["nodes"]["removed"]]
    assert "JAV" in sids_removed
    assert diff["summary"]["nodes_removed"] == 1


def test_diff_findings_added_and_removed():
    diff = compute_state_diff(_baseline_state(), _current_state())
    added_names = [f["name"] for f in diff["findings"]["added"]]
    removed_names = [f["name"] for f in diff["findings"]["removed"]]
    assert "SAPMAP User Created" in added_names
    assert "MS Internal Port Without ACL (CVE-2020-6207)" in removed_names


def test_diff_summary_includes_newly_critical_count():
    diff = compute_state_diff(_baseline_state(), _current_state())
    assert diff["summary"]["newly_critical"] == 1


def test_diff_connection_promotion_to_sap_all():
    """The S4D -> S4P edge changed from has_sap_all=False/untested
    to has_sap_all=True/tested+logon_ok.  Diff should record both
    field flips in the changes list."""
    diff = compute_state_diff(_baseline_state(), _current_state())
    changed = diff["connections"]["changed"]
    assert len(changed) == 1
    fields = {ch["field"]: (ch["before"], ch["after"])
              for ch in changed[0]["changes"]}
    assert fields["has_sap_all"] == (False, True)
    assert fields["logon_successful"] == (False, True)
    assert fields["tested"] == (False, True)


def test_diff_trust_chains_records_new_chain_to_prd():
    """The current state has a SAP_ALL edge S4D -> S4P (PRD).  Trust
    chain analysis on the current state finds it; baseline doesn't.
    Summary should report >= 1 new chain reaching PRD."""
    diff = compute_state_diff(_baseline_state(), _current_state())
    assert diff["summary"]["new_chains_to_prd"] >= 1
    assert any(c["ends_in_production"] for c in diff["trust_chains"]["added"])


def test_diff_no_change_when_states_identical():
    base = _baseline_state()
    diff = compute_state_diff(base, base)
    s = diff["summary"]
    for k in ("nodes_added", "nodes_removed", "nodes_changed",
              "findings_added", "findings_removed",
              "connections_added", "connections_removed",
              "trust_chains_added", "trust_chains_removed",
              "newly_pwned_count", "newly_critical",
              "scc_added", "scc_removed", "users_created",
              "users_removed"):
        assert s[k] == 0, f"non-zero summary[{k}]={s[k]} on identical states"


def test_diff_handles_empty_states():
    diff = compute_state_diff(SAPMAPState(), SAPMAPState())
    assert diff["summary"]["nodes_added"] == 0
    assert diff["nodes"]["added"] == []
    assert diff["findings"]["added"] == []


def test_diff_created_users_added_tracked():
    diff = compute_state_diff(_baseline_state(), _current_state())
    assert diff["summary"]["users_created"] == 1
    added = diff["created_users"]["added"]
    assert len(added) == 1
    assert added[0]["username"] == "SAPMAP00"
    assert added[0]["sid"] == "S4P"


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------

def test_markdown_render_includes_headline_metrics():
    diff = compute_state_diff(_baseline_state(), _current_state())
    md = build_diff_markdown(diff)
    assert "# SAPMAP Engagement Diff" in md
    assert "Headline" in md
    assert "Newly pwned" in md
    assert "S4P" in md   # the newly-pwned SID
    assert "_End of diff._" in md


def test_markdown_render_lists_added_findings():
    diff = compute_state_diff(_baseline_state(), _current_state())
    md = build_diff_markdown(diff)
    assert "SAPMAP User Created" in md
    # Section headers present
    assert "## Findings" in md
    assert "## SAP nodes" in md


def test_markdown_render_skips_empty_sections():
    """When there are no SCC changes, the SCC section should NOT
    appear in the markdown."""
    diff = compute_state_diff(_baseline_state(), _current_state())
    md = build_diff_markdown(diff)
    assert "## SAP Cloud Connectors" not in md


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------

def test_html_render_self_contained():
    diff = compute_state_diff(_baseline_state(), _current_state())
    html = build_diff_html(diff)
    assert html.startswith("<!DOCTYPE html>")
    # No external resources
    assert "<script" not in html.lower()
    assert "<link " not in html.lower()
    assert "<style>" in html
    assert "</html>" in html


def test_html_render_shows_major_regression_band_when_prd_pwned():
    """Newly-pwned PRD -> hero strip says MAJOR REGRESSION."""
    diff = compute_state_diff(_baseline_state(), _current_state())
    html = build_diff_html(diff)
    assert "MAJOR REGRESSION" in html


def test_html_render_no_change_band_when_states_equal():
    base = _baseline_state()
    diff = compute_state_diff(base, base)
    html = build_diff_html(diff)
    assert "No major change" in html


def test_html_render_kpi_signs():
    """KPI cards use signed values (+ / -) for delta clarity."""
    diff = compute_state_diff(_baseline_state(), _current_state())
    html = build_diff_html(diff)
    # newly_pwned = 1 -> "+1"
    assert "+1" in html
    # nodes_removed = 0 -> "+0"
    assert "+0" in html


def test_html_render_finding_severity_colour_coded():
    diff = compute_state_diff(_baseline_state(), _current_state())
    html = build_diff_html(diff)
    # Critical finding's severity-coloured pill appears
    assert "CRITICAL" in html
    # And the SID pill renders for the new finding
    assert ">S4P</span>" in html or "S4P" in html


def test_html_render_handles_empty_diff():
    html = build_diff_html(compute_state_diff(SAPMAPState(), SAPMAPState()))
    assert html.startswith("<!DOCTYPE html>")
    assert "No major change" in html
    assert "</html>" in html
