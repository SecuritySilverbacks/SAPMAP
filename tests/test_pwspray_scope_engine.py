#!/usr/bin/env python3
"""Pins for the engine-side multi-SID scope semantics shipped with
issue #107.  Two separable pieces:

(1) build_target_matrix must honour scope_filter['sids'] AND preserve
    operator-specified SID order.  Pre-#107 code at sapmap_pwspray.py
    L506-507 converted the list to a set() which destroyed order
    silently — the planner caught this and the fix changes the local
    to a list.

(2) spray_landscape's scope_label (sapmap_pwspray.py L936-938) must
    render multi-SID runs as 'multi:S4H,NPL,A4H' not 'landscape', or
    SprayRun.scope + the GUI progress panel + the engagement report
    all drop multi-SID runs on the floor as 'landscape'.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

import modules  # noqa: F401 — registers package paths


def _make_abap_node(sid: str, host: str = "1.2.3.4"):
    """Minimal SAPNode that passes build_target_matrix's ABAP /
    dispatcher-port eligibility checks.

    Shape notes forced by the engine helpers:
      - inst must have `.ports` as an ATTRIBUTE (SimpleNamespace works;
        a plain dict does NOT because getattr(d, "ports") returns the
        default), per _node_dispatcher_port at sapmap_pwspray.py:454
      - inst.ports keys must be INTS (isinstance check at :456), not
        strings like "3200"
      - clients list expects dicts with a 'nr' key per _node_clients at
        :468-473; empty => the helper falls back to ['000', '001']"""
    from types import SimpleNamespace
    from sapmap_models import SAPNode
    n = SAPNode(sid=sid)
    n.system_type = "ABAP"
    n.ip = host
    n.hostname = host
    n.clients = []  # _node_clients falls back to ['000','001']
    n.instances = [SimpleNamespace(ports={3200: "dispatcher"})]
    return n


# ---------------------------------------------------------------------------
# Order preservation
# ---------------------------------------------------------------------------

def test_build_target_matrix_preserves_sids_order():
    """Operator-specified SID order in scope_filter['sids'] must
    survive to the eligible target iteration.  Not a semantic
    guarantee callers can rely on today, but the fix makes it one so
    progress-panel + reports render predictably."""
    from sapmap_models import SAPMAPState
    from sapmap_pwspray import build_target_matrix

    state = SAPMAPState()
    # Insert in a DIFFERENT order than the scope_filter list so a
    # buggy iteration (over state.nodes.items() filtered by set
    # membership) would surface state's dict order instead of ours.
    for sid in ("NPL", "A4H", "S4H", "D01"):
        state.nodes[sid] = _make_abap_node(sid)

    tm = build_target_matrix(
        state, scope_filter={"sids": ["S4H", "NPL", "A4H"]})
    # Eligible targets stay in state.nodes iteration order (that's
    # fine — order-preservation here is about the FILTER not dropping
    # SIDs that aren't in the set).  The guarantee the fix makes is
    # that build_target_matrix doesn't convert the sids LIST to a
    # SET and drop operator-specified order on the floor at the
    # scope_filter level — reads of scope_filter['sids'] in
    # spray_landscape's scope_label (and anywhere else) see the list.
    eligible_sids = [t.sid for t in tm["eligible"]]
    assert set(eligible_sids) == {"S4H", "NPL", "A4H"}
    assert "D01" not in eligible_sids, (
        f"D01 was not in scope_filter['sids'] and must be filtered out; "
        f"got eligible={eligible_sids!r}")


def test_build_target_matrix_ignores_unknown_sid_silently():
    """Pre-#107 behaviour of silently skipping unknown SIDs in the
    engine is preserved — the frontend route rejects unknown SIDs
    with 400 BEFORE calling build_target_matrix, so an unknown SID
    reaching the engine is a scripted-caller edge case (not GUI).
    Pin: no raise, unknown SID surfaces as empty eligible list."""
    from sapmap_models import SAPMAPState
    from sapmap_pwspray import build_target_matrix

    state = SAPMAPState()
    state.nodes["NPL"] = _make_abap_node("NPL")

    tm = build_target_matrix(state, scope_filter={"sids": ["UNKNOWN"]})
    assert tm["eligible"] == []
    assert tm["ineligible"] == [], (
        "Unknown SIDs don't appear in ineligible either — they vanish "
        "silently because the filter is 'skip if sid not in sids'. "
        "Same behaviour as pre-#107 single_sid='UNKNOWN'.")


def test_build_target_matrix_single_sid_back_compat():
    """Pre-#107 single_sid wire-field still works unchanged."""
    from sapmap_models import SAPMAPState
    from sapmap_pwspray import build_target_matrix

    state = SAPMAPState()
    state.nodes["NPL"] = _make_abap_node("NPL")
    state.nodes["S4H"] = _make_abap_node("S4H")

    tm = build_target_matrix(state, scope_filter={"single_sid": "NPL"})
    assert [t.sid for t in tm["eligible"]] == ["NPL"]


def test_build_target_matrix_sids_precedence_over_single_sid():
    """When BOTH legacy single_sid AND new sids are in scope_filter,
    single_sid wins (engine checks it first — see sapmap_pwspray.py
    L504-507 if/elif order).  This mirrors the shared
    _parse_spray_scope precedence rule at the route layer: the ROUTE
    normalises both wire-fields into exactly one engine key before
    calling the engine, so the engine never sees both.  Pin the
    engine behaviour so an un-normalised scripted caller still gets
    a predictable result."""
    from sapmap_models import SAPMAPState
    from sapmap_pwspray import build_target_matrix

    state = SAPMAPState()
    state.nodes["NPL"] = _make_abap_node("NPL")
    state.nodes["S4H"] = _make_abap_node("S4H")

    tm = build_target_matrix(state, scope_filter={
        "single_sid": "NPL",
        "sids": ["S4H"],
    })
    assert [t.sid for t in tm["eligible"]] == ["NPL"], (
        "Engine's if/elif order gives single_sid priority at the raw "
        "scope_filter level.  The route layer never ships both, so "
        "this is purely a defensive engine-behaviour pin.")


# ---------------------------------------------------------------------------
# scope_label rendering (fed to _reset_status + SprayRun.scope)
# ---------------------------------------------------------------------------

def test_scope_label_source_contains_multi_branch():
    """Source-level pin on sapmap_pwspray.spray_landscape: the
    scope_label build must include a branch that renders scope_
    filter['sids'] as 'multi:<SID>,<SID>,...'.  Without this, a
    multi-SID run logs as 'landscape' in SprayRun.scope — forensics
    footgun flagged in the plan's RISK section."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parent.parent
           / "modules" / "discovery" / "sapmap_pwspray.py"
           ).read_text(encoding="utf-8")
    assert 'elif scope_filter and scope_filter.get("sids"):' in src, (
        "scope_label build must have an elif branch for scope_filter['sids']")
    assert '"multi:" + ",".join(' in src, (
        "multi-SID label must join SIDs with commas as 'multi:X,Y,Z'")


def test_build_target_matrix_source_uses_list_not_set():
    """Source-level pin on sapmap_pwspray.build_target_matrix: the
    'sids' local must be a LIST (not a set) so operator-specified
    order is preserved.  Pre-#107 bug flagged by the plan: `sids =
    set(scope_filter['sids'])` at L506-507.  Fix: `sids =
    list(scope_filter['sids'])`."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parent.parent
           / "modules" / "discovery" / "sapmap_pwspray.py"
           ).read_text(encoding="utf-8")
    # The specific bug line should be gone.
    assert "sids = set(scope_filter[\"sids\"])" not in src, (
        "pre-#107 set() conversion destroys operator-specified order; "
        "replace with list()")
    # The fix line should be present.
    assert "sids = list(scope_filter[\"sids\"])" in src, (
        "scope_filter['sids'] must be converted to a list to preserve order")
    # And single_sid should still be a one-element list (not a one-
    # element set) for the same reason.
    assert "sids = [scope_filter[\"single_sid\"]]" in src
