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

import os

import pytest

import modules  # noqa: F401  (registers package paths)
from sapmap_script import (
    _map_step, _ACTION_LABELS, DESTRUCTIVE_ACTIONS, _pick_chain)

_DEMO_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    os.pardir, "scripts", "killchain_demo.yaml")


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


# ---------------------------------------------------------------------------
# scripts/killchain_demo.yaml — the shipped ready-to-run demo (#196)
# ---------------------------------------------------------------------------
# A real .yaml under scripts/ that a user runs as-is.  If a later rename
# breaks an action it uses, the demo silently stops working in the field --
# these tests parse the shipped file the same way ScriptRunner does and map
# every step, so such a break fails CI instead.

def _load_demo_steps():
    yaml = pytest.importorskip("yaml")
    with open(_DEMO_SCRIPT) as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict) and isinstance(data.get("steps"), list)
    return data["steps"]


def test_demo_script_exists_and_parses():
    steps = _load_demo_steps()
    assert steps, "demo script has no steps"


def test_demo_script_every_step_maps():
    # Every action in the shipped demo must still be a known verb -- _map_step
    # raises on an unknown/invalid action, so this catches a renamed verb.
    for step in _load_demo_steps():
        method, _p, _b, _w = _map_step(step)
        assert method, "step produced no method: %r" % (step,)


def test_demo_script_exercises_analyze_then_play():
    actions = [s.get("action") for s in _load_demo_steps()]
    assert "analyze_chains" in actions
    assert "play_chain" in actions
    # The player can only replay chains the engine has already ranked.
    assert actions.index("analyze_chains") < actions.index("play_chain")


def test_demo_script_leaks_no_private_lab_ips():
    # The script ships in the public repo, so its placeholder targets must be
    # RFC 5737 documentation addresses, never a real/private lab range.
    import re
    with open(_DEMO_SCRIPT) as f:
        text = f.read()
    ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)
    assert ips, "expected placeholder target IPs in the demo"
    for ip in ips:
        assert ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")), (
            "non-documentation IP %s in a public demo script" % ip)
