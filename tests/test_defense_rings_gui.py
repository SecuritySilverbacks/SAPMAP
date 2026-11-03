#!/usr/bin/env python3
"""Marker tests for the defense-in-depth rings layout GUI (#198, PR2).

The layout is browser-side JavaScript in sapmap_html.py, so it can't be
unit-tested headless. These pin the contract the rendered page must expose —
the functions, the menu toggle, the route call, the snapshot/restore, the
golden-angle spread, the other-layouts clear hook, and the script dispatch —
so a refactor that drops one fails here rather than only in the GUI. JS
validity is covered by tests/test_rendered_js.py (node --check).

Assertions are scoped to a function body (via _fn_body) where a bare
substring could match elsewhere. Mirrors test_killchain_player /
test_blast_radius_player.
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
    start = html.find("function " + name + "(")
    assert start != -1, "function %s not found" % name
    nxt = html.find("\nfunction ", start + 1)
    return html[start:(nxt if nxt != -1 else len(html))]


class TestEngine:

    def test_functions_defined(self, html):
        for fn in ("function layoutDefenseRings(",
                   "function toggleDefenseRings(",
                   "function _snapshotPositions(",
                   "function _restorePositions(",
                   "function _clearRingsMode(",
                   "function _syncRingsButton("):
            assert fn in html, "missing rings function: " + fn

    def test_state_globals(self, html):
        assert "let _ringsActive = false" in html
        assert "let _ringsSavedPositions = null" in html


class TestRouteCall:

    def test_fetches_exploit_distances(self, html):
        body = _fn_body(html, "layoutDefenseRings")
        assert "/api/actions/exploit_distances" in body
        assert "data.status !== 'ok'" in body
        # degrades cleanly when there are no entry points
        assert "!entries.length" in body

    def test_uses_center_and_distances(self, html):
        body = _fn_body(html, "layoutDefenseRings")
        assert "data.center_sid" in body
        assert "data.distances" in body
        assert "data.unreachable" in body
        # ring index inverts distance so entries land outermost, jewel centre
        assert "(maxDist - distances[sid]) + 1" in body
        # golden-angle per-ring rotation so sparse rings don't collapse
        assert "2.399963" in body


class TestToggleAndRestore:

    def test_menu_item_present(self, html):
        assert 'id="defense-rings-item"' in html
        assert 'onclick="toggleDefenseRings()"' in html

    def test_toggle_snapshots_then_restores(self, html):
        tog = _fn_body(html, "toggleDefenseRings")
        # toggling OFF restores the snapshot before anything else
        assert "_restorePositions(_ringsSavedPositions)" in tog
        lay = _fn_body(html, "layoutDefenseRings")
        # entering snapshots current positions
        assert "_ringsSavedPositions = _snapshotPositions()" in lay

    def test_snapshot_covers_all_node_kinds(self, html):
        body = _fn_body(html, "_snapshotPositions")
        assert "mapState.nodes" in body
        assert "mapState.scc_nodes" in body
        assert "mapState.btp_subaccounts" in body

    def test_other_layouts_clear_rings_mode(self, html):
        # switching to any other layout must drop the rings state so the menu
        # label + restore snapshot reflect reality (not restore on re-layout).
        for fn in ("resetLayout", "layoutCircle", "layoutStar",
                   "layoutHierarchy", "layoutByStack"):
            assert "_clearRingsMode();" in _fn_body(html, fn), \
                fn + " does not clear rings mode"

    def test_snapshot_guarded_against_reentry(self, html):
        # re-entering rings while already active must NOT re-snapshot (which
        # would overwrite the saved original layout with ring coords) — review
        # finding.  The snapshot is guarded by !_ringsActive and taken before
        # the fetch.
        body = _fn_body(html, "layoutDefenseRings")
        assert "if (!_ringsActive) _ringsSavedPositions = _snapshotPositions()" in body
        assert body.index("_ringsSavedPositions = _snapshotPositions()") \
            < body.index("await fetch(")

    def test_in_flight_request_is_generation_guarded(self, html):
        # a stale exploit_distances response that resolves after its run was
        # superseded (newer rings run / switched to another layout / toggled
        # off) must not paint — a request-generation guard, like blast-radius.
        assert "let _ringsReqSeq = 0" in html
        body = _fn_body(html, "layoutDefenseRings")
        assert "++_ringsReqSeq" in body
        assert "myReq !== _ringsReqSeq" in body
        assert body.index("await fetch(") < body.index("myReq !== _ringsReqSeq")
        # the paint happens only after the guard
        assert body.index("myReq !== _ringsReqSeq") < body.index("_ringsActive = true")
        # switching layouts / toggling off bumps the generation
        assert "_ringsReqSeq++" in _fn_body(html, "_clearRingsMode")
        assert "_ringsReqSeq++" in _fn_body(html, "toggleDefenseRings")


class TestScriptDispatch:

    def test_relayout_dispatch_handles_rings(self, html):
        # the scripting engine's relayout ui_command must reach the layout
        assert "m === 'rings'" in html
        assert "layoutDefenseRings()" in html

    def test_layout_script_verb_accepts_rings(self):
        import sapmap_script
        for mode in ("rings", "defense", "defense_rings"):
            m = sapmap_script._map_step({"action": "layout", "mode": mode})
            assert m == ("LAYOUT", "", {"mode": mode}, False)
        with pytest.raises(ValueError):
            sapmap_script._map_step({"action": "layout", "mode": "bogus"})
