#!/usr/bin/env python3
"""Source-level pins for the GUI multi-SID wire shape shipped with
issue #107.  These complement test_pwspray_scope_multi.py (which pins
the backend _parse_spray_scope helper) by locking the frontend side
of the contract: modal textbox id + collector output + POST payloads.

Running the pwspray modal end-to-end requires a browser; these tests
rely on source-grep assertions in the same style as the sibling
test_pwspray_gui.py pins.
"""
from __future__ import annotations

import pathlib

import pytest


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _html_src() -> str:
    import sapmap_html
    return sapmap_html.get_html()


# ---------------------------------------------------------------------------
# Modal — textbox + radio shape
# ---------------------------------------------------------------------------

def test_modal_scope_textbox_renamed_to_sids():
    """Pre-#107 textbox id was `pws-scope-sid` (singular, width 80px).
    Post-#107 is `pws-scope-sids` (plural, widened) with a placeholder
    that advertises comma-separated input.  Operator feedback 2026-10-08."""
    src = _html_src()
    assert 'id="pws-scope-sids"' in src, (
        "Modal textbox must be renamed to pws-scope-sids so greps "
        "can't confuse old vs new wire-field semantics")
    # Pre-#107 singular id removed to prevent collector/seed collisions.
    assert 'id="pws-scope-sid"' not in src, (
        "Pre-#107 singular pws-scope-sid id leaked back in — "
        "showPwsprayModal + _pwsprayCollectConfig now read "
        "pws-scope-sids")
    assert "SID or SID,SID,SID" in src, (
        "Placeholder must advertise comma-separated input")
    assert "blank = whole landscape" in src, (
        "Placeholder must explain the blank-textbox meaning")


def test_modal_scope_radio_value_is_list_not_single():
    """Scope radio value renamed 'single' -> 'list' internally.
    Keeps the UX label 'SID list' and signals that multiple SIDs are
    now accepted."""
    src = _html_src()
    assert '<input type="radio" name="pws-scope" value="list">' in src, (
        "Scope radio must use value='list' (post-#107 multi-SID "
        "semantics), not 'single'")
    assert '>\n        SID list\n      </label>' in src, (
        "Radio label text must be 'SID list', not 'Single SID'")


# ---------------------------------------------------------------------------
# Collector — _pwsprayCollectConfig
# ---------------------------------------------------------------------------

def test_collector_emits_sids_array_not_single_sid_scalar():
    """_pwsprayCollectConfig must return `sids: [...]` (array), NOT
    `single_sid: "..."` (scalar).  Backend's _parse_spray_scope
    accepts both wire-fields for back-compat, but the GUI's own
    client emits the newer field exclusively."""
    src = _html_src()
    # The function returns an object with a sids key, derived from the
    # comma-split-upper-dedup pipeline over the textbox value.
    assert "function _pwsprayCollectConfig()" in src
    # Isolate the _pwsprayCollectConfig block so the assertion doesn't
    # match a same-named key in a different modal's collector (the
    # scan_logon_banners modal has its own single_sid wire-field that
    # is intentionally untouched by this PR — logon-banner-sweep
    # multi-SID parity is explicitly deferred to a follow-up issue).
    import re
    block = re.search(
        r"function _pwsprayCollectConfig\(\).*?^\}",
        src, re.DOTALL | re.MULTILINE)
    assert block, "_pwsprayCollectConfig function body not found"
    body = block.group(0)
    assert "sids: sids," in body, (
        "pwspray collector return object must carry `sids: sids,` as "
        "the scope field")
    assert "single_sid" not in body, (
        "pwspray collector return object must NOT emit single_sid any "
        "more — the backend's _parse_spray_scope still accepts it for "
        "legacy scripted callers, but the GUI client uses sids:[...] "
        "exclusively")


def test_collector_normalises_strip_upper_dedup():
    """Collector must apply the same normalisation the backend helper
    does (strip + upper + dedup) so the preview/launch POST payload
    is already in canonical form before transit."""
    src = _html_src()
    # Must split on comma
    assert "raw.split(',')" in src
    # Must trim and uppercase per token
    assert ".trim().toUpperCase()" in src
    # Must drop empty tokens (operator typed "A,," -> ["A"])
    # and dedup (seen set)
    assert "const seen = {};" in src
    assert "seen[s] = true;" in src


def test_collector_alerts_when_list_scope_with_empty_textbox():
    """UX guard rail: if operator checks 'list' radio but leaves
    textbox empty, show a client-side alert instead of posting an
    empty-sids request that would 400 server-side."""
    src = _html_src()
    assert ("Enter at least one SID, or switch scope to Whole "
            "landscape.") in src, (
        "Client-side alert for empty-list-radio case must stay — "
        "pre-#107 had the equivalent 'Pick a SID for single-scope "
        "spray.' alert")


# ---------------------------------------------------------------------------
# POST payload shape — preview + launch send sids array
# ---------------------------------------------------------------------------

def test_preview_post_sends_sids_not_single_sid():
    """pwsprayPreview() must POST { sids: [...], include_production,
    cap_per_user } — the pre-#107 single_sid scalar wire-field is
    gone from the preview request body."""
    src = _html_src()
    # Grep the pwsprayPreview block for the POST body shape.
    import re
    preview_block = re.search(
        r"async function pwsprayPreview\(\).*?body: JSON.stringify\((\{[^}]+\})\)",
        src, re.DOTALL)
    assert preview_block, "pwsprayPreview POST body not found in source"
    body = preview_block.group(1)
    assert "sids: cfg.sids," in body, (
        f"Preview POST body must carry `sids: cfg.sids,`; got {body!r}")
    assert "single_sid: cfg.single_sid" not in body, (
        f"Pre-#107 single_sid wire-field leaked into preview POST; "
        f"got {body!r}")


def test_launch_post_sends_sids_not_single_sid():
    """Same contract as preview — launch POST body carries `sids: [...]`
    not `single_sid: "..."`.  Legitimate single_sid references still
    exist elsewhere in the HTML (scan_logon_banners modal — deferred;
    per-node ctx-menu dispatcher; showPwsprayModal back-compat shim)
    so this test isolates the launch POST body to grep inside it only."""
    src = _html_src()
    assert "sids: cfg.sids," in src, (
        "Launch POST must carry `sids: cfg.sids,` in its body")
    import re
    # Capture the launch POST body text — from the fetch call start to
    # the closing `}),` of its JSON.stringify body.  Allows multi-line
    # bodies (which the launch POST uses).
    launch_match = re.search(
        r"fetch\('/api/actions/password_spray',(.*?)JSON\.stringify\((.*?)\)",
        src, re.DOTALL)
    assert launch_match, "Launch POST block not found in source"
    body = launch_match.group(2)
    assert "sids: cfg.sids," in body, (
        f"Launch POST body must emit `sids: cfg.sids,`; got {body[:300]!r}")
    assert "single_sid" not in body, (
        f"Launch POST body must NOT emit single_sid any more; got "
        f"{body[:300]!r}")


# ---------------------------------------------------------------------------
# Confirm dialog — multi-SID scope formatting
# ---------------------------------------------------------------------------

def test_launch_confirm_dialog_handles_multi_sid_scope_label():
    """The LIVE confirm dialog shows the scope the operator is about
    to spray.  Pre-#107 showed `single:<SID>` or `landscape`; post-#107
    must also handle `multi:<SID>,<SID>,...` for the N-SID case."""
    src = _html_src()
    assert "'multi:' + cfg.sids.join(',')" in src, (
        "LIVE confirm dialog must render multi-SID scope as "
        "'multi:S4H,NPL,...' when cfg.sids.length > 1")
    assert "'single:' + cfg.sids[0]" in src, (
        "LIVE confirm dialog must render single-SID scope as "
        "'single:<SID>' when cfg.sids.length === 1 (clean back-compat)")


# ---------------------------------------------------------------------------
# Modal seed back-compat
# ---------------------------------------------------------------------------

def test_modal_seed_accepts_sids_array_post_107():
    """showPwsprayModal({sids: ['NPL', 'S4H']}) must pre-fill the
    textbox with 'NPL,S4H' and select the 'list' radio.  Enables
    future callers (e.g. an engagement-report rerun button) to seed
    a multi-SID run directly."""
    src = _html_src()
    assert "Array.isArray(opts.sids)" in src, (
        "showPwsprayModal must accept opts.sids as an array")
    assert "seedSids.join(',')" in src, (
        "showPwsprayModal must join seed SIDs with commas when "
        "writing to the textbox")


def test_modal_error_display_prefers_message_over_bare_error_code():
    """When the backend returns a 400 with `message: 'Unknown SID(s):
    XYZ'`, the preview panel must show the message not just the bare
    error code 'unknown_sid' — operators shouldn't have to decode."""
    src = _html_src()
    assert "d.message || d.error" in src, (
        "Preview error renderer must prefer d.message over d.error "
        "so operators see 'Unknown SID(s): XYZ' instead of just "
        "'unknown_sid'")
