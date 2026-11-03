#!/usr/bin/env python3
"""ScriptRunner: the play_chain verb (#196, PR3).

Mirrors highlight_chain — same selector args (start/end SID pair or
index) — but maps to a PLAY_CHAIN step that pushes the whole chain object
to the GUI kill-chain player (so the player has the per-hop methods +
severities, not just the path SIDs):

  - action: play_chain
    start: DEV
    end: PRD

Read-only (a presentation/replay action), so NOT in DESTRUCTIVE_ACTIONS —
dry-run playbooks fire it normally.
"""
from __future__ import annotations

import modules  # noqa: F401  (registers package paths)
from sapmap_script import (
    _map_step, _ACTION_LABELS, DESTRUCTIVE_ACTIONS, _pick_chain)


def _step(action, **kw):
    s = {"action": action}
    s.update(kw)
    return s


# ---------------------------------------------------------------------------
# YAML -> step mapping
# ---------------------------------------------------------------------------

def test_play_chain_maps_to_play_chain_method():
    method, path, body, wait = _map_step(_step(
        "play_chain", start="DEV", end="PRD", index=2))
    assert method == "PLAY_CHAIN"
    assert path == ""
    assert body == {"start": "DEV", "end": "PRD", "index": 2}
    # Client-side GUI command, not a server task -> no wait.
    assert wait is False


def test_play_chain_defaults_when_no_selector_given():
    method, _p, body, _w = _map_step(_step("play_chain"))
    assert method == "PLAY_CHAIN"
    assert body == {"start": "", "end": "", "index": 0}


def test_play_chain_has_human_label():
    assert "play_chain" in _ACTION_LABELS
    assert "chain" in _ACTION_LABELS["play_chain"].lower()


def test_play_chain_is_not_destructive():
    # Replay of a precomputed path on the map — nothing touches a target.
    assert "play_chain" not in DESTRUCTIVE_ACTIONS


# ---------------------------------------------------------------------------
# _pick_chain — shared selector for highlight_chain + play_chain
# ---------------------------------------------------------------------------

_CHAINS = [
    {"start_sid": "DEV", "end_sid": "PRD",
     "path_sids": ["DEV", "QA", "PRD"]},
    {"start_sid": "A", "end_sid": "B", "path_sids": ["A", "B"]},
]


def test_pick_chain_by_start_end_pair():
    c = _pick_chain(_CHAINS, "DEV", "PRD", 0)
    assert c is not None and c["path_sids"] == ["DEV", "QA", "PRD"]


def test_pick_chain_falls_back_to_index():
    c = _pick_chain(_CHAINS, "", "", 1)
    assert c is not None and c["start_sid"] == "A"


def test_pick_chain_start_end_miss_falls_back_to_index():
    # A start/end pair that matches nothing drops to the index selector.
    c = _pick_chain(_CHAINS, "NOPE", "GONE", 0)
    assert c is not None and c["start_sid"] == "DEV"


def test_pick_chain_index_out_of_range_returns_none():
    assert _pick_chain(_CHAINS, "", "", 9) is None
    assert _pick_chain([], "", "", 0) is None
    # A negative index must NOT wrap around to the last (lowest-ranked)
    # chain — the `0 <= idx` lower bound. The old inline `idx < len` logic
    # this replaced returned chain_list[-1] for index: -1, playing the
    # wrong chain.
    assert _pick_chain(_CHAINS, "", "", -1) is None
    assert _pick_chain(_CHAINS, "", "", -99) is None
