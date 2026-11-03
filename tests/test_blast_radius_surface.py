#!/usr/bin/env python3
"""Surfacing tests for blast-radius (#197, PR3): scripting verb, engagement
report sections, the MCP tool, and the GUI command dispatch.

These pin that the feature is reachable from every surface SAPMAP exposes a
capability through — not just the GUI flood (PR2) and the raw route (PR1).
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pathlib
import pytest

import sapmap_script
import sapmap_report
import sapmap_html
from sapmap_models import SAPMAPState, SAPNode, RFCConnection

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Scripting engine verb
# ---------------------------------------------------------------------------

class TestScriptVerb:

    def test_forward_maps_to_ui_command(self):
        m = sapmap_script._map_step({"action": "blast_radius", "sid": "PRD"})
        assert m == ("BLAST_RADIUS", "", {"sid": "PRD", "mode": "forward"}, False)

    def test_inverse_maps(self):
        m = sapmap_script._map_step(
            {"action": "blast_radius", "sid": "PRD", "mode": "inverse"})
        assert m[0] == "BLAST_RADIUS" and m[2]["mode"] == "inverse"

    def test_sid_aliases(self):
        for key in ("sid", "node", "target"):
            m = sapmap_script._map_step({"action": "blast_radius", key: "X"})
            assert m[2]["sid"] == "X"

    def test_missing_sid_raises(self):
        with pytest.raises(ValueError):
            sapmap_script._map_step({"action": "blast_radius"})

    def test_bad_mode_raises(self):
        with pytest.raises(ValueError):
            sapmap_script._map_step(
                {"action": "blast_radius", "sid": "X", "mode": "sideways"})

    def test_has_action_label(self):
        assert sapmap_script._ACTION_LABELS.get("blast_radius")

    def test_executor_pushes_ui_command(self):
        src = (REPO_ROOT / "modules" / "automation"
               / "sapmap_script.py").read_text(encoding="utf-8")
        assert 'if method == "BLAST_RADIUS":' in src
        assert 'ui_command("blast_radius", sid=sid, mode=mode)' in src


# ---------------------------------------------------------------------------
# GUI command dispatch (the map turns the ui_command into a flood)
# ---------------------------------------------------------------------------

def test_gui_dispatches_blast_radius_command():
    html = sapmap_html.get_html()
    assert "c.cmd === 'blast_radius'" in html
    assert "floodBlastRadius(c.sid, c.mode)" in html


# ---------------------------------------------------------------------------
# Engagement report (Markdown + HTML)
# ---------------------------------------------------------------------------

def _foothold_state():
    st = SAPMAPState()
    st.add_node(SAPNode(sid="DEV", ip="10.0.0.1", hostname="dev",
                        pwned=True, system_type="ABAP"))
    st.add_node(SAPNode(sid="PRD", ip="10.0.0.2", hostname="prd",
                        is_production=True, system_type="ABAP"))
    st.add_connection(RFCConnection(
        source_sid="DEV", source_host="dev", target_sid="PRD", target_host="prd",
        destination_name="D_PRD", rfc_user="RFC",
        has_sap_all=True, tested=True, logon_successful=True))
    return st


class TestReport:

    def test_markdown_section_present_with_foothold(self):
        md = sapmap_report.build_markdown_report(_foothold_state())
        assert "## Blast radius (reachable landscape per foothold)" in md
        assert "Crown-jewel exposure" in md
        # DEV reaches PRD (1 system, 1 hop); PRD is exposed to 1 system
        assert "| DEV | 1 | 1 |" in md

    def test_markdown_section_handles_no_footholds(self):
        st = SAPMAPState()
        st.add_node(SAPNode(sid="AAA", ip="10.0.0.9", system_type="ABAP"))
        md = sapmap_report.build_markdown_report(st)
        assert "No footholds" in md

    def test_html_section_present_with_foothold(self):
        html = sapmap_report.build_html_report(_foothold_state())
        assert 'id="sec-blast"' in html
        assert "💥 Blast radius" in html            # heading + nav entry
        assert html.count("sec-blast") >= 2          # section + nav anchor

    def test_html_section_empty_without_footholds(self):
        assert sapmap_report._html_blast_radius_section(SAPMAPState()) == ""


# ---------------------------------------------------------------------------
# MCP tool
# ---------------------------------------------------------------------------

def test_mcp_tool_defined():
    src = (REPO_ROOT / "modules" / "mcp"
           / "sapmap_mcp_server.py").read_text(encoding="utf-8")
    assert "def get_blast_radius(sid: str, mode: str = \"forward\")" in src
    assert '"/api/actions/blast_radius"' in src
