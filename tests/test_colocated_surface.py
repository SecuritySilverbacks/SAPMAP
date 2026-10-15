#!/usr/bin/env python3
"""Tests for surfacing the same-host co-located pivot (issue #70) across the
scripting engine, the MCP server, and the engagement report.

The pivot mechanism itself is covered by ``tests/test_colocation_local_pivot.py``;
this file only asserts that the feature is *reachable* and *reported*:

  * the scripting engine maps ``discover_colocated`` / ``pivot_colocated`` to
    the existing GUI API routes (and gates the pivot as destructive),
  * the MCP server exposes a ``colocated_pivot`` tool wired to those routes,
  * the engagement report renders a "Same-host co-located systems" section
    (Markdown + HTML) derived from ``node.colocated_sids``.
"""
from __future__ import annotations

import ast
import pathlib

import sapmap_script                                    # noqa: E402
from sapmap_models import SAPMAPState, SAPNode          # noqa: E402
from sapmap_report import (                             # noqa: E402
    build_markdown_report, build_html_report,
)

_REPO = pathlib.Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Scripting engine
# ---------------------------------------------------------------------------

def test_discover_colocated_maps_to_route():
    assert sapmap_script._map_step(
        {"action": "discover_colocated", "target": "AE1"}
    ) == ("POST", "/api/node/AE1/discover_colocated", {}, True)


def test_pivot_colocated_maps_and_passes_sibling():
    # restricted to one sibling -> target_sid wire-field carries it
    assert sapmap_script._map_step(
        {"action": "pivot_colocated", "target": "AE1", "colocated_sid": "AE3"}
    ) == ("POST", "/api/node/AE1/pivot_colocated",
          {"target_sid": "AE3"}, True)
    # blank sibling -> whole-host pivot (every plotted same-host sibling)
    assert sapmap_script._map_step(
        {"action": "pivot_colocated", "target": "AE1"}
    ) == ("POST", "/api/node/AE1/pivot_colocated",
          {"target_sid": ""}, True)


def test_pivot_is_destructive_discovery_is_not():
    assert "pivot_colocated" in sapmap_script.DESTRUCTIVE_ACTIONS
    assert "discover_colocated" not in sapmap_script.DESTRUCTIVE_ACTIONS


def test_both_actions_have_progress_labels():
    assert sapmap_script._ACTION_LABELS.get("discover_colocated")
    assert sapmap_script._ACTION_LABELS.get("pivot_colocated")


# ---------------------------------------------------------------------------
# MCP server (SDK is an optional dep, so assert via source AST, not import)
# ---------------------------------------------------------------------------

def test_mcp_exposes_colocated_pivot_tool():
    src_path = _REPO / "modules" / "mcp" / "sapmap_mcp_server.py"
    text = src_path.read_text()
    tree = ast.parse(text)
    fns = {n.name: n for n in ast.walk(tree)
           if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    assert "colocated_pivot" in fns, "colocated_pivot MCP tool is missing"
    fn = fns["colocated_pivot"]
    # decorated with @mcp.tool()
    assert any(
        isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
        and d.func.attr == "tool"
        for d in fn.decorator_list), "colocated_pivot is not an @mcp.tool()"
    body = ast.get_source_segment(text, fn)
    # wired to both GUI routes + gated by a confirm flag on the pivot
    assert "/discover_colocated" in body
    assert "/pivot_colocated" in body
    assert "confirm" in body and "target_sid" in body


# ---------------------------------------------------------------------------
# Engagement report
# ---------------------------------------------------------------------------

def _colocated_state(ae2_pwned: bool = False) -> SAPMAPState:
    st = SAPMAPState()
    ae1 = SAPNode(sid="AE1", system_type="ABAP", ip="10.0.0.1",
                  hostname="sapbox", pwned=True)
    ae1.colocated_sids = [
        {"sid": "AE3", "ip": "10.0.0.1", "plotted": True},
        {"sid": "AE2", "ip": "10.0.0.1", "plotted": True},
    ]
    ae3 = SAPNode(sid="AE3", system_type="ABAP", ip="10.0.0.1",
                  hostname="sapbox", pwned=True)
    ae3.discovered_via_colocation = True
    ae2 = SAPNode(sid="AE2", system_type="ABAP", ip="10.0.0.1",
                  hostname="sapbox", pwned=ae2_pwned)
    ae2.discovered_via_colocation = True
    for n in (ae1, ae3, ae2):
        st.add_node(n)
    return st


def _colocated_row(md: str) -> str:
    sec = md[md.index("## Same-host co-located systems"):]
    return next(ln for ln in sec.splitlines() if ln.startswith("| 10.0.0.1"))


def test_md_report_has_colocated_section():
    md = build_markdown_report(_colocated_state())
    assert "## Same-host co-located systems" in md
    assert "`AE1`" in md and "`AE3`" in md and "`AE2`" in md
    # both AE2 + AE3 were materialised via co-location discovery
    assert "2 system(s) first surfaced via co-location" in md


def test_md_marks_only_compromised_siblings():
    # AE3 pwned, AE2 not: the "Siblings compromised" (last) column lists AE3 only
    compromised = _colocated_row(build_markdown_report(
        _colocated_state(ae2_pwned=False))).split("|")[-2]
    assert "AE3" in compromised and "AE2" not in compromised
    # once AE2 is owned too, both show
    both = _colocated_row(build_markdown_report(
        _colocated_state(ae2_pwned=True))).split("|")[-2]
    assert "AE3" in both and "AE2" in both


def test_html_report_has_colocated_section():
    html = build_html_report(_colocated_state())
    assert 'id="sec-colocated"' in html
    assert "Same-host co-located" in html
    assert "AE3" in html and "AE2" in html


def test_report_omits_colocated_when_none():
    st = SAPMAPState()
    st.add_node(SAPNode(sid="AE1", ip="10.0.0.1"))
    assert "## Same-host co-located systems" not in build_markdown_report(st)
    assert 'id="sec-colocated"' not in build_html_report(st)
