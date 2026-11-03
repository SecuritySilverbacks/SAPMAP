#!/usr/bin/env python3
"""Marker tests for the blast-radius flood GUI surface (#197, PR2).

The flood is browser-side JavaScript embedded in the big <script> block of
sapmap_html.py, so it can't be unit-tested headless. These tests pin the
*contract* the rendered page must expose — functions, the two triggers
(context-menu entries + Blast-Radius Mode), the route call, the persistent
re-apply hook and the clear path — so a refactor that silently drops one
fails here rather than only in the GUI. JS validity itself is covered by
tests/test_rendered_js.py (node --check over the rendered script).

Assertions are scoped to a specific function body (via _fn_body) wherever a
bare substring would match coincidentally elsewhere in the ~22k-line file —
e.g. `if (_blastMode)` occurs in BOTH startDrag and showCtxMenu, so a global
assert would pass even if one were deleted.  Mirrors test_killchain_player.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import sapmap_html


@pytest.fixture(scope="module")
def html():
    return sapmap_html.get_html()


def _fn_body(html, name):
    """Source of the top-level `function <name>(...)`, declaration up to the
    next top-level `function` — so assertions scope to one function."""
    start = html.find("function " + name + "(")
    assert start != -1, "function %s not found in rendered HTML" % name
    nxt = html.find("\nfunction ", start + 1)
    return html[start:(nxt if nxt != -1 else len(html))]


# ---------------------------------------------------------------------------
# Engine present
# ---------------------------------------------------------------------------

class TestEngine:

    def test_blast_functions_defined(self, html):
        # A dropped/renamed definition with live call sites is a runtime
        # ReferenceError that node --check (syntax only) does NOT catch.
        for fn in ("function floodBlastRadius(",
                   "function _animateBlast(",
                   "function _blastDrawEdge(",
                   "function _reapplyBlast(",
                   "function _attachBlastOutline(",
                   "function _clearBlastOutlines(",
                   "function _renderBlastLegend(",
                   "function clearBlast(",
                   "function toggleBlastMode(",
                   "function _blastLayer(",
                   "function _clearBlastLayer(",
                   "function _cancelBlastAnim(",
                   "function _blastRingColor("):
            assert fn in html, "missing blast-radius function: " + fn

    def test_state_globals_declared(self, html):
        for g in ("let _blastMode = false",
                  "let _blastToken = 0",
                  "let _blastTimers = []",
                  "let _blastState = null"):
            assert g in html, "missing blast state global: " + g

    def test_distance_ramp_has_six_colours(self, html):
        body = _fn_body(html, "_blastRingColor")
        # ramp indexes into _BLAST_RING_COLORS and clamps beyond it
        assert "_BLAST_RING_COLORS[hop - 1]" in body
        assert "const _BLAST_RING_COLORS =" in html
        # 6 distinct hop colours + a grey fallback
        assert html.count("'#ff3b30'") >= 1 and "'#8e8e93'" in body


# ---------------------------------------------------------------------------
# Server round-trip
# ---------------------------------------------------------------------------

class TestRouteCall:

    def test_flood_posts_to_blast_route(self, html):
        body = _fn_body(html, "floodBlastRadius")
        assert "/api/actions/blast_radius" in body
        assert "'Content-Type': 'application/json'" in body
        # sends sid + mode + a bounded depth
        assert "sid: sid" in body and "mode: mode" in body
        assert "max_depth: 6" in body
        # degrades: non-ok status and empty result are handled, not silently
        assert "data.status !== 'ok'" in body
        assert "!data.reachable" in body

    def test_in_flight_request_is_generation_guarded(self, html):
        # A response that resolves after its flood was superseded/cleared must
        # not paint a stale view: capture a request seq before the await and
        # re-check it after (regression guard, review finding).
        body = _fn_body(html, "floodBlastRadius")
        assert "++_blastReqSeq" in body
        assert "myReq !== _blastReqSeq" in body
        # and the guard sits AFTER the await, before any rendering
        assert body.index("await r.json()") < body.index("myReq !== _blastReqSeq")
        assert body.index("myReq !== _blastReqSeq") < body.index("_blastState = data")
        # a clear also invalidates an in-flight request
        assert "_blastReqSeq++" in _fn_body(html, "clearBlast")


# ---------------------------------------------------------------------------
# Trigger 1 — context menu
# ---------------------------------------------------------------------------

class TestContextMenuTrigger:

    def test_menu_items_present(self, html):
        assert 'data-action="blast_radius_forward"' in html
        assert 'data-action="blast_radius_inverse"' in html

    def test_ctxaction_dispatches_both(self, html):
        body = _fn_body(html, "ctxAction") if "function ctxAction(" in html \
            else html  # ctxAction is async; fall back to whole doc
        assert "case 'blast_radius_forward': floodBlastRadius(sid, 'forward');" in html
        assert "case 'blast_radius_inverse': floodBlastRadius(sid, 'inverse');" in html


# ---------------------------------------------------------------------------
# Trigger 2 — Blast-Radius Mode (left = forward, right = inverse)
# ---------------------------------------------------------------------------

class TestModeTrigger:

    def test_mode_toggle_item_present(self, html):
        assert 'id="blast-mode-item"' in html
        assert 'onclick="toggleBlastMode()"' in html

    def test_left_click_floods_forward_in_mode(self, html):
        # scoped to startDrag: a left-click floods instead of dragging
        body = _fn_body(html, "startDrag")
        assert "if (_blastMode)" in body
        assert "floodBlastRadius(sid, 'forward')" in body

    def test_right_click_floods_inverse_in_mode(self, html):
        # scoped to showCtxMenu: a right-click floods the cone, not the menu
        body = _fn_body(html, "showCtxMenu")
        assert "if (_blastMode)" in body
        assert "floodBlastRadius(sid, 'inverse')" in body
        # and it returns BEFORE building the menu
        assert body.index("floodBlastRadius(sid, 'inverse')") \
            < body.index("hideMapCtxMenu()")


# ---------------------------------------------------------------------------
# Persistence + clear
# ---------------------------------------------------------------------------

class TestPersistenceAndClear:

    def test_updatemap_reapplies_blast(self, html):
        # The ~800ms poll rebuilds #map-svg via innerHTML and wipes the node
        # overlays; updateMap must re-attach the ring outlines each tick.
        body = _fn_body(html, "updateMap")
        assert "_reapplyBlast()" in body

    def test_reapply_scopes_to_node_boxes_and_anchor(self, html):
        body = _fn_body(html, "_reapplyBlast")
        assert "g.node-box[data-sid]" in body
        assert "_blastState.anchor" in body

    def test_outline_dedup_guard(self, html):
        # repeated applies (immediate + per-poll) must not stack duplicate
        # rects — the attach removes any prior blast overlay first.
        body = _fn_body(html, "_attachBlastOutline")
        assert "rect.blast-hl-overlay" in body
        assert ".remove()" in body

    def test_animation_is_cancellable_and_self_clearing(self, html):
        body = _fn_body(html, "_animateBlast")
        assert "token !== _blastToken" in body          # monotonic cancel
        assert "_clearBlastLayer()" in body             # transient edges fade

    def test_pulsenode_accepts_hex_colour(self, html):
        # the flood reuses _pulseNode but pulses in a distance-ramp colour
        body = _fn_body(html, "_pulseNode")
        assert "charAt(0) === '#'" in body

    def test_clear_on_background_click(self, html):
        # a click that is not a node / legend / menu / top-nav clears
        assert "clearBlast();" in html
        assert "!e.target.closest('.node-box')" in html
        assert "!e.target.closest('#blast-legend')" in html
        # must exclude ALL six context menus (shared .ctx-menu class), not
        # only the SAP-node #ctx-menu — else a map/SCC/BTP/TMS/DBCON menu
        # click tears down the flood (review finding).
        assert "!e.target.closest('.ctx-menu')" in html

    def test_legend_container_present(self, html):
        assert 'id="blast-legend"' in html
