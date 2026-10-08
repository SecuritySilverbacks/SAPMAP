#!/usr/bin/env python3
"""Pins for _parse_spray_scope — the shared pwspray scope parser shipped
with GitHub issue #107 (allow comma-separated SIDs in password spray).

The helper lives in modules/core/sapmap_gui.py and is consumed by BOTH
POST /api/actions/password_spray and POST /api/actions/password_spray/
preview so the two routes can't drift.  Returns a 3-tuple:
  (sids_list, scope_label, error_or_None)
    - sids_list == []        => landscape, scope_label == "landscape"
    - len == 1               => scope_label == "single:<SID>"
    - len > 1                => scope_label == "multi:<SID>,<SID>,..."
On validation failure: (None, None, {"code": str, "message": str, ...}).

Precedence: ``sids`` wins when both are present (operator picked the
newer wire-field explicitly).
"""
from __future__ import annotations

import pytest

import modules  # noqa: F401 — registers package paths


@pytest.fixture
def known_sids():
    """Discovered SIDs for all tests except the explicit-unknown case."""
    return {"NPL", "S4H", "A4H", "D01"}


# ---------------------------------------------------------------------------
# landscape (empty) + legacy single_sid back-compat
# ---------------------------------------------------------------------------

def test_parse_scope_empty_is_landscape(known_sids):
    """Blank body => landscape mode (no filter)."""
    from sapmap_gui import _parse_spray_scope
    sids, label, err = _parse_spray_scope({}, known_sids)
    assert err is None
    assert sids == []
    assert label == "landscape"


def test_parse_scope_single_sid_legacy_scalar(known_sids):
    """Legacy wire-field single_sid: str still works, uppercases."""
    from sapmap_gui import _parse_spray_scope
    sids, label, err = _parse_spray_scope({"single_sid": "npl"}, known_sids)
    assert err is None
    assert sids == ["NPL"]
    assert label == "single:NPL"


# ---------------------------------------------------------------------------
# sids list / comma-string parsing
# ---------------------------------------------------------------------------

def test_parse_scope_sids_list(known_sids):
    """New wire-field sids: list[str] — multi-SID happy path."""
    from sapmap_gui import _parse_spray_scope
    sids, label, err = _parse_spray_scope(
        {"sids": ["S4H", "NPL", "A4H"]}, known_sids)
    assert err is None
    assert sids == ["S4H", "NPL", "A4H"]
    assert label == "multi:S4H,NPL,A4H"


def test_parse_scope_comma_string(known_sids):
    """sids as comma-separated string — same result as the list form."""
    from sapmap_gui import _parse_spray_scope
    sids, label, err = _parse_spray_scope(
        {"sids": "S4H,NPL,A4H"}, known_sids)
    assert err is None
    assert sids == ["S4H", "NPL", "A4H"]
    assert label == "multi:S4H,NPL,A4H"


def test_parse_scope_whitespace_tolerance(known_sids):
    """Leading/trailing whitespace per-token must be stripped silently."""
    from sapmap_gui import _parse_spray_scope
    sids, label, err = _parse_spray_scope(
        {"sids": " s4h , npl "}, known_sids)
    assert err is None
    assert sids == ["S4H", "NPL"]
    assert label == "multi:S4H,NPL"


def test_parse_scope_dedup(known_sids):
    """Case-insensitive dedup collapses S4H,s4h,S4H => single S4H."""
    from sapmap_gui import _parse_spray_scope
    sids, label, err = _parse_spray_scope(
        {"sids": "S4H,s4h,S4H"}, known_sids)
    assert err is None
    assert sids == ["S4H"]
    assert label == "single:S4H", (
        "A single surviving SID after dedup must label as 'single:' not "
        "'multi:' — SprayRun.scope stays diff-clean against pre-#107 "
        "snapshots when the operator dedups to one target.")


def test_parse_scope_preserves_order(known_sids):
    """Operator-specified order survives (set() would destroy it).
    Pins the fix for sapmap_pwspray.py:506-507 order-loss bug flagged
    during planning."""
    from sapmap_gui import _parse_spray_scope
    sids, label, err = _parse_spray_scope(
        {"sids": "A4H,NPL,S4H"}, known_sids)
    assert err is None
    assert sids == ["A4H", "NPL", "S4H"], (
        f"Operator-specified order must survive; got {sids!r}")
    assert label == "multi:A4H,NPL,S4H"


# ---------------------------------------------------------------------------
# empty-after-strip + validation errors
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    {"sids": ","},
    {"sids": ""},
    {"sids": []},
    {"sids": "  ,  ,  "},
])
def test_parse_scope_empty_after_strip_is_landscape(payload, known_sids):
    """Empty-token payloads are treated as landscape, not an error.
    Matches the 'blank textbox = whole landscape' operator intent."""
    from sapmap_gui import _parse_spray_scope
    sids, label, err = _parse_spray_scope(payload, known_sids)
    assert err is None, (
        f"Payload {payload!r} must be treated as landscape (no 400); "
        f"got error {err!r}")
    assert sids == []
    assert label == "landscape"


def test_parse_scope_unknown_sid_rejected(known_sids):
    """Unknown SID => 400-shaped error with the specific SID named."""
    from sapmap_gui import _parse_spray_scope
    sids, label, err = _parse_spray_scope(
        {"sids": ["XYZ"]}, known_sids)
    assert sids is None
    assert label is None
    assert err is not None
    assert err.get("code") == "unknown_sid"
    assert "XYZ" in err.get("message", "")
    assert err.get("unknown") == ["XYZ"]


def test_parse_scope_mixed_known_unknown(known_sids):
    """Partial unknown => error listing ONLY the unknown ones.
    Preserves order for operator clarity."""
    from sapmap_gui import _parse_spray_scope
    sids, label, err = _parse_spray_scope(
        {"sids": "NPL,XYZ,S4H,ZZZ"}, known_sids)
    assert sids is None
    assert err is not None
    assert err.get("code") == "unknown_sid"
    assert err.get("unknown") == ["XYZ", "ZZZ"]
    assert "NPL" not in err.get("unknown", [])
    assert "S4H" not in err.get("unknown", [])


@pytest.mark.parametrize("payload", [
    {"sids": 123},
    {"sids": {"S4H": True}},
    {"sids": [123]},
    {"sids": ["S4H", 999]},
    {"single_sid": 42},
    {"single_sid": ["S4H"]},
])
def test_parse_scope_bad_type(payload, known_sids):
    """Non-string / non-list payloads => bad_sids error.  Defensive
    guard against scripted or MCP callers sending garbage."""
    from sapmap_gui import _parse_spray_scope
    sids, label, err = _parse_spray_scope(payload, known_sids)
    assert sids is None
    assert err is not None
    assert err.get("code") == "bad_sids"


def test_parse_scope_sids_wins_over_single_sid(known_sids):
    """When both wire-fields are present, 'sids' (the newer, more
    expressive one) wins.  Documented precedence rule — operator who
    explicitly passed sids:[...] shouldn't be silently overridden by
    a leftover single_sid field."""
    from sapmap_gui import _parse_spray_scope
    sids, label, err = _parse_spray_scope(
        {"sids": ["NPL"], "single_sid": "S4H"}, known_sids)
    assert err is None
    assert sids == ["NPL"], (
        f"'sids' must take precedence over 'single_sid'; got {sids!r}")


# ---------------------------------------------------------------------------
# known_sids edge cases
# ---------------------------------------------------------------------------

def test_parse_scope_handles_empty_known_sids():
    """Fresh landscape (no nodes yet) + sids request => unknown_sid
    error naming every requested SID.  Guards against the probe
    firing before discovery."""
    from sapmap_gui import _parse_spray_scope
    sids, label, err = _parse_spray_scope({"sids": ["S4H"]}, set())
    assert err is not None
    assert err.get("code") == "unknown_sid"
    assert err.get("unknown") == ["S4H"]


def test_parse_scope_landscape_mode_works_without_known_sids():
    """Landscape mode doesn't need known_sids at all — the engine
    does its own eligibility walk later.  Pin that an empty-set
    known_sids + empty body => (clean landscape, no error).  Prevents
    a chicken-and-egg bug where an empty known_sids would 400 even
    for landscape requests."""
    from sapmap_gui import _parse_spray_scope
    sids, label, err = _parse_spray_scope({}, set())
    assert err is None
    assert sids == []
    assert label == "landscape"
