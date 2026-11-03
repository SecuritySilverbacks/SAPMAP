#!/usr/bin/env python3
"""Engagement report: the static kill-chain storyboard figure (#196, PR3).

_build_killchain_svg() renders ONE attack chain as an inline SVG strip —
a box per system joined by a severity-coloured arrow per hop, captioned
with the technique, dashed + faint for untested hops. It's the static
report counterpart of the animated GUI player. These tests pin the figure
shape directly and its embedding in build_html_report's chains section.

Pure function over an SAPMAPState / TrustChain — no network, no GUI.
"""
from __future__ import annotations

import modules  # noqa: F401  (registers package paths)
from sapmap_chain import ChainHop, TrustChain
from sapmap_report import _build_killchain_svg, build_html_report
from sapmap_models import SAPMAPState, SAPNode, RFCConnection


def _two_hop_chain():
    """DEV --SAP_ALL(4)--> QA --untested(2)--> PRD(production)."""
    return TrustChain(
        hops=[
            ChainHop("DEV", "QA", method="BAPI (SAP_ALL)",
                     severity=4, untested=False),
            ChainHop("QA", "PRD", method="RFC logon — UNTESTED",
                     severity=2, untested=True),
        ],
        start_sid="DEV", end_sid="PRD", end_is_production=True)


# ---------------------------------------------------------------------------
# _build_killchain_svg — the figure itself
# ---------------------------------------------------------------------------

class TestKillchainSvg:

    def test_renders_inline_responsive_svg(self):
        svg = _build_killchain_svg(_two_hop_chain())
        assert svg.startswith("<svg viewBox")
        assert 'width="100%"' in svg
        assert "<script" not in svg.lower()   # self-contained, no JS

    def test_every_node_box_and_sid_rendered(self):
        svg = _build_killchain_svg(_two_hop_chain())
        assert svg.count("<rect") == 3        # DEV, QA, PRD
        for sid in ("DEV", "QA", "PRD"):
            assert ">%s</text>" % sid in svg

    def test_per_hop_severity_colours(self):
        svg = _build_killchain_svg(_two_hop_chain())
        assert "#db6d28" in svg               # hop 1 severity 4 (HIGH)
        assert "#3fb950" in svg               # hop 2 severity 2 (LOW)

    def test_hop_method_captions_present(self):
        svg = _build_killchain_svg(_two_hop_chain())
        assert "BAPI (SAP_ALL)" in svg
        assert "hop 1" in svg and "hop 2" in svg

    def test_untested_hop_is_dashed_and_italic(self):
        svg = _build_killchain_svg(_two_hop_chain())
        assert 'stroke-dasharray="7,5"' in svg
        assert 'font-style="italic"' in svg

    def test_entry_and_crown_jewel_roles(self):
        svg = _build_killchain_svg(_two_hop_chain())
        assert "entry" in svg
        assert "crown jewel" in svg           # PRD is production

    def test_long_method_truncated_with_full_text_in_title(self):
        long = "Forged MYSAPSSO2 ticket (STRUSTSSO2) via stolen PSE"
        chain = TrustChain(
            hops=[ChainHop("A", "B", method=long, severity=5,
                           untested=False)],
            start_sid="A", end_sid="B")
        svg = _build_killchain_svg(chain)
        # Full technique preserved in a <title> tooltip...
        assert "<title>%s</title>" % long in svg
        # ...while the visible label is truncated with an ellipsis.
        assert "…" in svg

    def test_markup_in_sid_and_method_is_escaped(self):
        # The SVG is embedded RAW into the operator-opened HTML report, and
        # sids / hop methods derive from scanned-system + chain-engine data
        # (attacker-influenceable in an engagement).  Every path-derived
        # string must be _hesc-escaped — a dropped escape would inject
        # markup/script into the report.  (Guards against a regression that
        # the markup-free DEV/QA/PRD fixtures above would not catch.)
        evil = 'm<img src=x onerror=alert(1)></title><script>alert(1)</script>'
        chain = TrustChain(
            hops=[ChainHop("D<x>", "E", method=evil, severity=5,
                           untested=False)],
            start_sid="D<x>", end_sid="E")
        svg = _build_killchain_svg(chain)
        # No raw markup from the sid (box text), the method label, or its
        # <title> tooltip survives...
        assert "<img" not in svg
        assert "<script" not in svg.lower()
        assert "</title><script>" not in svg
        assert "D<x>" not in svg
        # ...it's HTML-escaped instead.
        assert "&lt;img" in svg          # method label + <title>
        assert "&lt;x&gt;" in svg        # sid box text

    def test_empty_or_degenerate_chain_returns_empty(self):
        assert _build_killchain_svg(None) == ""
        assert _build_killchain_svg(TrustChain()) == ""        # no hops
        # one SID (no hop) -> nothing to draw
        assert _build_killchain_svg(
            TrustChain(hops=[], start_sid="A", end_sid="A")) == ""


# ---------------------------------------------------------------------------
# build_html_report — the figure is embedded in the chains section
# ---------------------------------------------------------------------------

def _state_with_chain():
    state = SAPMAPState()
    state.add_node(SAPNode(sid="DEV", ip="10.0.0.1", hostname="dev",
                           pwned=True, gw_vulnerable=True))
    state.add_node(SAPNode(sid="QA", ip="10.0.0.2", hostname="qa"))
    state.add_node(SAPNode(sid="PRD", ip="10.0.0.3", hostname="prd",
                           is_production=True))
    state.add_connection(RFCConnection(
        source_sid="DEV", source_host="dev", target_sid="QA",
        target_host="qa", destination_name="D1", has_sap_all=True,
        tested=True, logon_successful=True))
    state.add_connection(RFCConnection(
        source_sid="QA", source_host="qa", target_sid="PRD",
        target_host="prd", destination_name="D2", has_sap_all=True,
        tested=False, logon_successful=False))
    return state


class TestReportEmbedsStoryboard:

    def test_storyboard_rendered_in_chains_section(self):
        html = build_html_report(_state_with_chain())
        assert "Highest-severity attack path" in html
        # The storyboard sits inside the trust-chains section, before the
        # chains table.
        section = html.split('id="sec-chains"', 1)[1].split("</section>", 1)[0]
        assert "<svg viewBox" in section
        assert "hop 1" in section
        assert "crown jewel" in section

    def test_storyboard_absent_for_empty_landscape(self):
        html = build_html_report(SAPMAPState())
        assert "Highest-severity attack path" not in html
