"""Pins for the password-spray GUI surface (issue #69).

Covers (post-de-gate):
  * parse_pwspray_wordlist semantics (user:pass, dedup, mode,
    blank/comment skip, malformed line counting)
  * HTML ctx-menu entry under the Exploitation submenu with the
    write-op class
  * Frontend confirm-dialog + fetch dispatch for data-action=
    password_spray (always starts a DRY-RUN from the ctx-menu)
  * Negative pin: --allow-pwspray is NOT a CLI flag any more
    (user asked to drop the kernel arm gate — the confirm dialogs +
    accept_lockout_risk second-factor are the actual safety layer)
  * Negative pin: /api/mode payload does NOT carry pwspray_armed
"""
from __future__ import annotations

import json
import pathlib
import re

import pytest

import modules  # noqa: F401  (registers package paths)


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# /api/mode + WRITE_ROUTES source-level wiring
# ---------------------------------------------------------------------------

def test_api_mode_handler_does_not_expose_pwspray_armed():
    """De-gate: /api/mode no longer carries pwspray_armed.  Negative
    pin so no one re-introduces the field + its gating implications."""
    src = (REPO_ROOT / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")
    assert "is_pwspray_armed as _pws" not in src
    assert '"pwspray_armed":' not in src


def test_write_routes_contain_destructive_pwspray_routes():
    """Both destructive pwspray routes must stay in WRITE_ROUTES so
    --read-only mode still refuses them with the existing 403 hook."""
    src = (REPO_ROOT / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")
    assert '"/api/node/<sid>/password_spray",' in src
    assert '"/api/actions/password_spray/pool/wordlist",' in src


def test_write_routes_omit_pool_get():
    """GET /api/actions/password_spray/pool must NOT be in
    WRITE_ROUTES — operators in --read-only mode should still be
    able to inspect what wordlist is loaded."""
    src = (REPO_ROOT / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")
    m = re.search(r"WRITE_ROUTES = frozenset\(\{(.*?)\}\)",
                  src, re.DOTALL)
    assert m, "WRITE_ROUTES frozenset not found"
    body = m.group(1)
    assert '"/api/actions/password_spray/pool",' not in body


def test_no_pwspray_arm_gate_hook_in_source():
    """De-gate: no PWSPRAY_ROUTES / _pwspray_gate / 403
    pwspray_not_armed anywhere."""
    src = (REPO_ROOT / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")
    assert "PWSPRAY_ROUTES" not in src
    assert "def _pwspray_gate" not in src
    assert "pwspray_not_armed" not in src


# ---------------------------------------------------------------------------
# Wordlist parser semantics
# ---------------------------------------------------------------------------

def test_parse_pwspray_wordlist_user_pass_lines():
    from sapmap_gui import parse_pwspray_wordlist
    text = "DDIC:19920706\nSAP*:06071992\n"
    merged, summary = parse_pwspray_wordlist(text, [], mode="replace")
    assert [(u, p) for (u, p) in merged] == [
        ("DDIC", "19920706"), ("SAP*", "06071992")]
    assert summary["added"] == 2
    assert summary["skipped_blank_or_comment"] == 0
    assert summary["skipped_malformed"] == 0
    assert summary["total_in_store"] == 2


def test_parse_pwspray_wordlist_skips_blank_and_comments():
    from sapmap_gui import parse_pwspray_wordlist
    text = "\n# comment\nDDIC:19920706\n\n   \n# trailing\n"
    merged, summary = parse_pwspray_wordlist(text, [], mode="replace")
    assert merged == [("DDIC", "19920706")]
    assert summary["added"] == 1
    assert summary["skipped_blank_or_comment"] == 5
    assert summary["skipped_malformed"] == 0


def test_parse_pwspray_wordlist_marks_malformed_lines():
    from sapmap_gui import parse_pwspray_wordlist
    text = ("no_colon_here\n"
            ":missing_user\n"
            "missing_pass:\n"
            "DDIC:19920706\n")
    merged, summary = parse_pwspray_wordlist(text, [], mode="replace")
    assert merged == [("DDIC", "19920706")]
    assert summary["skipped_malformed"] == 3
    assert summary["added"] == 1


def test_parse_pwspray_wordlist_dedup_within_batch_case_insensitive_user():
    from sapmap_gui import parse_pwspray_wordlist
    text = ("DDIC:19920706\n"
            "ddic:19920706\n"       # same user case-folded + same pw
            "Ddic:19920706\n")      # same again
    merged, summary = parse_pwspray_wordlist(text, [], mode="replace")
    assert len(merged) == 1
    assert merged[0] == ("DDIC", "19920706")  # first spelling wins
    assert summary["added"] == 1


def test_parse_pwspray_wordlist_same_user_different_passwords_both_kept():
    from sapmap_gui import parse_pwspray_wordlist
    text = "DDIC:19920706\nDDIC:Welcome1\n"
    merged, _ = parse_pwspray_wordlist(text, [], mode="replace")
    assert len(merged) == 2


def test_parse_pwspray_wordlist_append_dedups_against_existing():
    from sapmap_gui import parse_pwspray_wordlist
    existing = [("DDIC", "19920706"), ("SAPMAP00", "Andinyougo123!")]
    text = ("DDIC:19920706\n"
            "ddic:19920706\n"
            "DDIC:AnotherPw\n"
            "NEWUSER:newpw\n")
    merged, summary = parse_pwspray_wordlist(text, existing, mode="append")
    assert ("DDIC", "AnotherPw") in merged
    assert ("NEWUSER", "newpw") in merged
    assert summary["added"] == 2
    assert summary["duplicates_vs_existing"] == 1
    assert summary["total_in_store"] == 4


def test_parse_pwspray_wordlist_replace_wipes_existing():
    from sapmap_gui import parse_pwspray_wordlist
    existing = [("OLD", "oldpw")]
    text = "NEW:newpw\n"
    merged, summary = parse_pwspray_wordlist(text, existing, mode="replace")
    assert merged == [("NEW", "newpw")]
    assert summary["total_in_store"] == 1


def test_parse_pwspray_wordlist_empty_text_returns_empty_summary():
    from sapmap_gui import parse_pwspray_wordlist
    merged, summary = parse_pwspray_wordlist("", [], mode="replace")
    assert merged == []
    assert summary == {
        "added": 0, "skipped_blank_or_comment": 0,
        "skipped_malformed": 0, "duplicates_vs_existing": 0,
        "total_in_store": 0,
    }


# ---------------------------------------------------------------------------
# Frontend wiring (source-level)
# ---------------------------------------------------------------------------

def _html_src() -> str:
    return (REPO_ROOT / "modules" / "core" / "sapmap_html.py").read_text(
        encoding="utf-8")


def test_ctx_menu_entry_sits_under_exploitation_submenu():
    """Per-node ctx-menu row 'Spray Harvested Credentials' moved
    from Scanning to Exploitation per user request.  The
    row must appear AFTER '<!-- Exploitation submenu -->' and
    BEFORE the next submenu-group marker."""
    src = _html_src()
    expl_at = src.find("<!-- Exploitation submenu -->")
    spray_at = src.find('data-action="password_spray"')
    scanning_at = src.find("<!-- Scanning submenu -->")
    assert expl_at > 0 and spray_at > 0
    assert spray_at > expl_at, (
        "password_spray ctx row must appear AFTER the "
        "'<!-- Exploitation submenu -->' marker — the user asked "
        "for it to live in Exploitation, not Scanning")
    # And the first password_spray occurrence should NOT fall inside
    # the Scanning block.  The Exploitation marker should come AFTER
    # Scanning in file order; password_spray should come after the
    # Exploitation marker.
    assert expl_at > scanning_at, (
        "unexpected ctx-menu layout — Exploitation marker should "
        "come after Scanning in file order")


def test_ctx_menu_entry_carries_write_op_class():
    """--read-only mode hides .write-op by CSS; the password-spray
    entry must inherit that automatic-hide behaviour."""
    src = _html_src()
    m = re.search(
        r'<div class="([^"]*)" data-action="password_spray"', src)
    assert m, "password_spray ctx-menu row not found"
    classes = m.group(1).split()
    assert "write-op" in classes
    assert "ctx-item" in classes


def test_ctx_action_switch_opens_pwspray_modal_pre_scoped():
    """Per-node ctx entry opens the Password Spray config modal
    pre-scoped to this node's SID — rather than firing a dry-run
    POST behind a confirm (operator feedback 2026-10-05).

    The modal already defaults to dry-run (pws-dry-run checked),
    so the invariant "a mis-click cannot burn the lockout budget"
    is preserved via showPwsprayModal's own reset."""
    src = _html_src()
    assert "case 'password_spray':" in src
    assert "showPwsprayModal({ single_sid: sid });" in src, (
        "ctx entry must open the config modal pre-scoped to the "
        "right-clicked SID, not fire a bare POST")
    # Negative pin: no stray dry-run POST short-cut on this case.
    # Grep is intentionally scoped to the ctxAction switch body.
    import re as _re
    m = _re.search(
        r"case 'password_spray':(.*?)break;", src, _re.DOTALL)
    assert m
    case_body = m.group(1)
    assert "api('POST'" not in case_body
    assert "dry_run" not in case_body


def test_show_pwspray_modal_accepts_single_sid_seed():
    """showPwsprayModal takes an optional {single_sid} that pre-
    selects the 'single'-scope radio and fills #pws-scope-sid.  The
    top-nav Actions entry calls showPwsprayModal() with no args
    (seedSid=='' → landscape scope); the per-node ctx entry calls
    it with {single_sid: sid}."""
    src = _html_src()
    assert "function showPwsprayModal(opts)" in src
    assert "opts.single_sid" in src
    # The scope radio is seeded via a computed value, not hard-coded
    # to 'landscape' any more.
    assert "const scopeVal = seedSid ? 'single' : 'landscape';" in src


# ---------------------------------------------------------------------------
# De-gate negative pins — don't re-introduce the kernel arm flag
# ---------------------------------------------------------------------------

def test_cli_does_not_declare_allow_pwspray_flag():
    """De-gate: --allow-pwspray must NOT reappear.  The user asked
    for the password-spray surface to be always available — the
    confirm dialogs + accept_lockout_risk strict-bool on the live
    path are the actual safety.  --read-only still gates write
    routes via WRITE_ROUTES."""
    src = (REPO_ROOT / "sapmap.py").read_text(encoding="utf-8")
    assert '"--allow-pwspray"' not in src
    assert "PASSWORD SPRAY ARMED" not in src


def test_sapmap_mode_does_not_carry_pwspray_bit():
    """De-gate: sapmap_mode module globals no longer carry
    _pwspray_armed / set_pwspray_armed / is_pwspray_armed."""
    src = (REPO_ROOT / "modules" / "core" / "sapmap_mode.py"
           ).read_text(encoding="utf-8")
    assert "_pwspray_armed" not in src
    assert "set_pwspray_armed" not in src
    assert "is_pwspray_armed" not in src


def test_frontend_has_no_pwspray_armed_class_or_bar():
    """De-gate: body.pwspray-armed class + #pwspray-armed-bar strip
    are gone."""
    src = _html_src()
    assert "body.pwspray-armed" not in src
    assert "pwspray-armed-bar" not in src
    assert "classList.contains('pwspray-armed')" not in src


# ---------------------------------------------------------------------------
# Option B — tiered node rim colouring on spray hits (issue #69)
# ---------------------------------------------------------------------------

def test_rim_colour_logic_reads_spray_hit_users_tier():
    """Node-rim renderer must inspect n.spray_hit_users and pick a
    rim colour by the highest authority tier seen there.  sap_all
    goes through node.pwned (red); privileged → orange (#f0883e);
    unprivileged / probe_failed → yellow (#d4a72c)."""
    src = _html_src()
    assert "n.spray_hit_users" in src, (
        "frontend node renderer must read n.spray_hit_users to pick "
        "a tiered rim colour")
    # Rank table in the renderer so the max-authority tier wins when
    # a node has mixed hits.
    assert "sap_all: 3, privileged: 2" in src
    # Two rim colours for the two non-pwned tiers.
    assert "#f0883e" in src   # privileged (orange)
    assert "#d4a72c" in src   # unprivileged / probe_failed (yellow)
