#!/usr/bin/env python3
"""Marker tests for the kill-chain player JS surface (#196, PR2).

The player is browser-side JavaScript embedded in the big <script> block
of sapmap_html.py, so it can't be unit-tested headless. These tests pin
the *contract* that the rendered page must expose, so a refactor that
silently drops a function, a control, or a guard fails here rather than
only in the GUI. JS validity itself is covered by tests/test_rendered_js.py
(node --check over the rendered script).

Assertions are scoped to a specific function body (via _fn_body) wherever a
bare substring would match coincidentally elsewhere in the 22k-line file —
e.g. getElementById('pulse-svg'), getTotalLength and stroke-dasharray all
occur in unrelated code, so asserting them globally would pass even if the
player's own use of them were deleted.

Mirrors the marker-assertion style of the other GUI tests.
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
    """Return the source of the top-level `function <name>(...)` — from its
    declaration up to the next top-level function — so assertions can be
    scoped to one function instead of the whole script."""
    start = html.find("function " + name + "(")
    assert start != -1, "function %s not found in rendered HTML" % name
    nxt = html.find("\nfunction ", start + 1)
    return html[start:(nxt if nxt != -1 else len(html))]


# ---------------------------------------------------------------------------
# Player engine present
# ---------------------------------------------------------------------------

class TestPlayerEngine:

    def test_player_functions_defined(self, html):
        # Every function on the Play hot path — a dropped/renamed definition
        # with live call sites is a runtime ReferenceError that node --check
        # (syntax-only) does NOT catch, so pin them all here.
        for fn in ("function playChain(",
                   "function _playStep(",
                   "function _playCaption(",
                   "function togglePlayPause(",
                   "function replayChain(",
                   "function stopPlay(",
                   "function setPlaySpeed(",
                   "function _playResolveCenter(",
                   "function _playLayer(",
                   "function _clearPlayLayer(",
                   "function _cancelPlay(",
                   "function _syncPlayButtons("):
            assert fn in html, "missing player function: %s" % fn

    def test_player_state_globals(self, html):
        # Declared exactly once each (a second `let` in the same scope is a
        # JS SyntaxError — node --check would catch it, but pin it anyway).
        for g in ("let _lastChains", "let _playToken",
                  "let _playTimers", "let _playState", "let _playSpeed"):
            assert html.count(g) == 1, "expected exactly one `%s`" % g

    def test_play_layer_anchored_to_pulse_overlay(self, html):
        # The player's layer MUST resolve #pulse-svg and append itself there
        # (not #map-svg, which updateMap() rebuilds via innerHTML every ~800ms
        # and would wipe the animation).  Scope to _playLayer's body so the
        # four unrelated getElementById('pulse-svg') call sites can't satisfy
        # this by accident.
        body = _fn_body(html, "_playLayer")
        assert "getElementById('pulse-svg')" in body
        assert "appendChild(g)" in body
        assert "map-svg" not in body, "player layer must not attach to #map-svg"
        assert "kc-play-layer" in body

    def test_player_draw_on_recipe_in_playstep(self, html):
        # The edge draw-on (getTotalLength + stroke-dashoffset transition) and
        # the node emphasis (_pulseNode) must live in _playStep specifically —
        # getTotalLength also pre-exists in the new-connection animation, so a
        # global assertion would not notice the player losing its own copy.
        body = _fn_body(html, "_playStep")
        assert "getTotalLength" in body
        # The draw-on *trigger* specifically — resetting the offset to 0 is
        # what animates the stroke in; without it the edge stays hidden.
        # (A bare "strokeDashoffset" also matches the dash *setup* line, so it
        # would survive deleting the trigger — pin the trigger itself.)
        assert "line.style.strokeDashoffset = '0'" in body
        assert "_pulseNode(hop.target_sid" in body

    def test_cancel_token_guards_every_scheduled_step(self, html):
        # All three scheduled continuations (the _playStep head, the pulse
        # timer, the advance timer) must bail when the token moved on, and the
        # 6s post-completion clear must only fire for the still-current run.
        assert html.count("token !== _playToken") == 3
        assert html.count("_playToken++") == 1
        assert "token === _playToken) _clearPlayLayer" in html

    def test_draw_once_guard_prevents_pause_resume_duplicates(self, html):
        # Resuming re-enters _playStep on the same hop; the st.drawn guard
        # stops it stacking duplicate glow/line/caption elements.
        assert "drawn: -1" in html
        body = _fn_body(html, "_playStep")
        assert "st.drawn !== st.i" in body
        assert "st.drawn = st.i" in body

    def test_btp_sentinel_resolution(self, html):
        # BTP-rooted chains start with a 'BTP:<uuid8>' sentinel absent from
        # mapState.nodes; the resolver falls back to btp_subaccounts.
        body = _fn_body(html, "_playResolveCenter")
        assert "mapState.btp_subaccounts" in body
        assert "'BTP:'" in body

    def test_per_hop_severity_palette(self, html):
        assert "_PLAY_SEV_COLOR" in html
        assert "_PLAY_SEV_NAME" in html

    def test_untested_hops_rendered_dashed_and_faint(self, html):
        # The player's own dashed styling for untested hops — pin the
        # player-local marker (stroke-dasharray also occurs ~22x in legend/
        # edge code, so a bare assertion would pass even if this were removed).
        body = _fn_body(html, "_playStep")
        assert "hop.untested" in body
        assert "'stroke-dasharray', '9,6'" in body


# ---------------------------------------------------------------------------
# Chain-card controls wired correctly
# ---------------------------------------------------------------------------

class TestChainCardControls:

    def test_control_buttons_present(self, html):
        for cls in ("kc-play-btn", "kc-pause-btn", "kc-replay-btn", "kc-speed"):
            assert cls in html, "missing control: %s" % cls

    def test_controls_call_player_entrypoints(self, html):
        assert "playChain(' + idx + ')" in html
        assert "replayChain(' + idx + ')" in html
        assert "togglePlayPause()" in html
        assert "setPlaySpeed(this.value)" in html

    def test_speed_selector_offers_three_rates(self, html):
        assert 'value="0.5"' in html
        assert 'value="1" selected' in html
        assert 'value="2"' in html

    def test_controls_stop_propagation(self, html):
        # The card's root div already has onclick=highlightChain(...); every
        # control MUST stopPropagation so clicking Play doesn't also fire the
        # whole-path static highlight.
        assert "event.stopPropagation(); playChain(" in html
        assert "event.stopPropagation(); togglePlayPause()" in html
        assert "event.stopPropagation(); replayChain(" in html
        assert "event.stopPropagation(); setPlaySpeed(this.value)" in html

    def test_showChainResults_feeds_the_player(self, html):
        # The panel renderer hands its chains to the player so Play works with
        # no extra server round-trip.
        assert "_lastChains = chains" in html

    def test_card_primary_click_still_highlights(self, html):
        # Regression: the existing click-to-highlight behaviour is untouched.
        assert "onclick='highlightChain(" in html


# ---------------------------------------------------------------------------
# hop.method surfaced in the static panel rows (plan requirement)
# ---------------------------------------------------------------------------

class TestPanelHopMethod:

    def test_method_caption_in_hop_rows(self, html):
        # Each hop row now shows its technique caption, coloured by the
        # per-hop severity from PR1 and faint when untested.
        assert "escHtml(h.method)" in html
        assert "sevColors[h.severity]" in html
        assert "h.untested" in html

    def test_preexisting_hop_fields_still_rendered(self, html):
        # Regression: the fields the panel already showed are intact.
        assert "escHtml(h.source_sid)" in html
        assert "escHtml(h.target_sid)" in html
        assert "SAP_ALL" in html
