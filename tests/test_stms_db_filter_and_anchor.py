#!/usr/bin/env python3
"""Issue #191 — map ergonomics for STMS/DB accessories.

Two GUI-only behaviours, both wired into the rendered single-page app
(`sapmap_html.get_html()`):

  1. Re-anchor on re-layout — every View -> Layout command drops the
     cached DBCON cylinder / TMS truck positions (via
     `_loReanchorSatellites()`) so the accessories re-walk next to their
     source SAP box's NEW position instead of being stranded.
  2. A "Hide STMS & DB" toggle (`#hide-satellites`, off by default) that
     suppresses the cylinders, trucks, their edges, and their host-zone
     contribution.

These assert on the rendered markup/JS markers.  JS *syntax* validity is
covered separately by tests/test_rendered_js.py (node --check).
"""
from __future__ import annotations

import re

import modules  # noqa: F401 — registers package paths

import sapmap_html


def _html() -> str:
    return sapmap_html.get_html()


def test_hide_satellites_checkbox_present_and_off_by_default():
    html = _html()
    # The checkbox exists, is wired to re-render, and sits in the legend bar.
    assert 'id="hide-satellites"' in html
    assert "Hide STMS &amp; DB" in html
    # Mirrors the show-unknown toggle: onchange re-renders the map.
    m = re.search(r'<input[^>]*id="hide-satellites"[^>]*>', html)
    assert m, "hide-satellites input not found"
    assert 'onchange="updateMap()"' in m.group(0)
    # Off by default — no `checked` attribute on the input.
    assert "checked" not in m.group(0)


def test_hide_satellites_state_is_read_and_guards_render():
    html = _html()
    # State read once in updateMap().
    assert "const hideSatellites" in html
    # Guards the DBCON loop, the TMS loop, and the host-zone expansion.
    assert html.count("if (hideSatellites) return;") >= 2
    assert "if (!hideSatellites) {" in html


def test_reanchor_helper_defined_and_called_by_every_layout():
    html = _html()
    # Helper defined, and it clears BOTH accessory caches (pinned included,
    # per the "explicit layout = global re-arrange" decision).
    assert "function _loReanchorSatellites()" in html
    # Window from the def over the small helper body (it clears two dicts).
    body = html[html.index("function _loReanchorSatellites()"):][:300]
    assert "dbconPositions = {}" in body
    assert "tmsPositions = {}" in body
    # Called by all seven layout entry points (circle, star, hierarchy,
    # by-stack, fit-canvas, fixed-columns, reset).
    assert html.count("_loReanchorSatellites();") >= 7
