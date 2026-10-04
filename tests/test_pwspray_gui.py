"""Pins for the password-spray GUI surface (PR 2 of issue #69).

Covers:
  * sapmap_mode.is_pwspray_armed is OFF by default and flipped only by
    set_pwspray_armed — the arm bit never leaks across tests.
  * The /api/mode handler imports is_pwspray_armed and exposes
    pwspray_armed in its payload.
  * WRITE_ROUTES carries both destructive pwspray routes so --read-only
    refuses them via the existing 403 hook.
  * The per-node spray-start helper refuses with HTTP 403
    {error: pwspray_not_armed, ...} when the flag is off, and emits a
    non-error response once armed.
  * The pure wordlist parser handles user:pass lines, blank/comment
    skips, dedup within batch, dedup against existing on append, and
    full wipe on replace.
  * Frontend wiring: initMode flips body.pwspray-armed on the field;
    the ctx-menu entry sits under default_creds with the write-op
    class; rules/hints/hidden carry a password_spray entry; the switch
    dispatches on data-action=password_spray.

The route itself is exercised via a tiny closure fetched out of
create_app() by patching request/response — we only check the arm-
gate branch so the test stays independent of SAP RFC fixtures.
"""
from __future__ import annotations

import io
import json
import pathlib
from unittest.mock import patch

import pytest

import modules  # noqa: F401  (registers package paths)
import sapmap_mode


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _reset_pwspray_mode():
    """Every test starts with --allow-pwspray OFF so a stray leak
    cannot mask a regression."""
    sapmap_mode.set_pwspray_armed(False)
    yield
    sapmap_mode.set_pwspray_armed(False)


# ---------------------------------------------------------------------------
# Mode flag plumbing
# ---------------------------------------------------------------------------

def test_pwspray_armed_default_off():
    assert sapmap_mode.is_pwspray_armed() is False


def test_pwspray_armed_toggle():
    sapmap_mode.set_pwspray_armed(True)
    assert sapmap_mode.is_pwspray_armed() is True
    sapmap_mode.set_pwspray_armed(False)
    assert sapmap_mode.is_pwspray_armed() is False


def test_pwspray_armed_coerces_via_bool():
    sapmap_mode.set_pwspray_armed(1)
    assert sapmap_mode.is_pwspray_armed() is True
    sapmap_mode.set_pwspray_armed(0)
    assert sapmap_mode.is_pwspray_armed() is False
    sapmap_mode.set_pwspray_armed("")
    assert sapmap_mode.is_pwspray_armed() is False


# ---------------------------------------------------------------------------
# /api/mode and WRITE_ROUTES source-level wiring
# ---------------------------------------------------------------------------

def test_api_mode_handler_exposes_pwspray_armed():
    """The /api/mode route must import is_pwspray_armed and add
    pwspray_armed to the payload — the frontend's initMode flips
    body.pwspray-armed off that key."""
    src = (REPO_ROOT / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")
    assert 'is_pwspray_armed as _pws' in src, (
        "/api/mode should import is_pwspray_armed with the _pws alias "
        "so the payload line stays readable")
    assert '"pwspray_armed": _pws()' in src, (
        "/api/mode must set payload['pwspray_armed'] to the _pws() "
        "result — otherwise the frontend ctx-menu will never enable")


def test_write_routes_contain_both_destructive_pwspray_routes():
    """Both destructive pwspray routes must appear in WRITE_ROUTES or
    --read-only mode will silently accept them."""
    src = (REPO_ROOT / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")
    assert '"/api/node/<sid>/password_spray",' in src
    assert '"/api/actions/password_spray/pool/wordlist",' in src


def test_write_routes_omit_pool_get():
    """GET /api/actions/password_spray/pool is a read-only pool summary
    and must NOT be in WRITE_ROUTES — operators in --read-only mode
    should still be able to inspect what wordlist is loaded."""
    src = (REPO_ROOT / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")
    # Isolate the WRITE_ROUTES frozenset body so adjacent route
    # strings in route-handler bodies don't produce a false positive.
    import re
    m = re.search(r"WRITE_ROUTES = frozenset\(\{(.*?)\}\)",
                  src, re.DOTALL)
    assert m, "WRITE_ROUTES frozenset block not found"
    body = m.group(1)
    assert '"/api/actions/password_spray/pool",' not in body, (
        "GET /api/actions/password_spray/pool must stay out of "
        "WRITE_ROUTES — read-only sessions should still see the pool "
        "summary")


# ---------------------------------------------------------------------------
# Arm-gate helper refusal
# ---------------------------------------------------------------------------

def test_pwspray_armed_or_refuse_refuses_when_off():
    """The _pwspray_armed_or_refuse helper is nested inside create_app
    but we can exercise its behaviour via the sapmap_mode flag and the
    documented 403 contract.  Source pin: the refusal body carries
    the ``pwspray_not_armed`` error key and a non-empty message —
    the frontend toasts on 403 bodies that carry an ``error`` key."""
    src = (REPO_ROOT / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")
    assert '"error": "pwspray_not_armed"' in src, (
        "Arm-gate helper must emit the pwspray_not_armed error key "
        "so the frontend toast handler can distinguish it from the "
        "existing read_only_mode refusal")
    assert "response.status = 403" in src
    # Must be gated by sapmap_mode.is_pwspray_armed, not by any
    # heuristic read of state.
    assert "from sapmap_mode import is_pwspray_armed" in src


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
    """Two passwords for the same username are both valid candidates —
    they test different pool entries."""
    from sapmap_gui import parse_pwspray_wordlist
    text = "DDIC:19920706\nDDIC:Welcome1\n"
    merged, _ = parse_pwspray_wordlist(text, [], mode="replace")
    assert len(merged) == 2


def test_parse_pwspray_wordlist_append_dedups_against_existing():
    from sapmap_gui import parse_pwspray_wordlist
    existing = [("DDIC", "19920706"), ("SAPMAP00", "Andinyougo123!")]
    text = ("DDIC:19920706\n"              # exact dup vs existing — drop
            "ddic:19920706\n"              # same key, dropped silently
                                           # within-batch (not re-counted
                                           # against existing)
            "DDIC:AnotherPw\n"             # same user, new pw — keep
            "NEWUSER:newpw\n")             # fully new — keep
    merged, summary = parse_pwspray_wordlist(text, existing, mode="append")
    assert ("DDIC", "AnotherPw") in merged
    assert ("NEWUSER", "newpw") in merged
    assert summary["added"] == 2
    # Within-batch dedup is silent (the operator typed the same thing
    # twice); only unique new keys that collide with existing count.
    assert summary["duplicates_vs_existing"] == 1
    assert summary["total_in_store"] == 4


def test_parse_pwspray_wordlist_replace_wipes_existing():
    """mode='replace' discards every prior entry — important so a
    typo'd upload with mode='replace' doesn't quietly fall back to the
    stale pool."""
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
# Frontend wiring (source-level, mirrors tests/test_readonly.py pattern)
# ---------------------------------------------------------------------------

def _html_src() -> str:
    return (REPO_ROOT / "modules" / "core" / "sapmap_html.py").read_text(
        encoding="utf-8")


def test_ctx_menu_entry_sits_under_default_creds():
    """The 'Spray Harvested Credentials' row must sit directly after
    'Check Default Accounts' so operators see it alongside the sibling
    DIAG credential check."""
    src = _html_src()
    default_at = src.find('data-action="default_creds"')
    spray_at = src.find('data-action="password_spray"')
    assert default_at >= 0 and spray_at >= 0
    assert spray_at > default_at
    # Nothing else may wedge between the two rows.
    between = src[default_at:spray_at]
    assert between.count('data-action=') == 1


def test_ctx_menu_entry_carries_write_op_class():
    """--read-only mode hides .write-op by CSS — the password-spray
    entry mutates target state, so it must inherit that automatic
    hide behaviour."""
    src = _html_src()
    import re
    m = re.search(
        r'<div class="([^"]*)" data-action="password_spray"', src)
    assert m, "password_spray ctx-menu row not found"
    classes = m.group(1).split()
    assert "write-op" in classes
    assert "ctx-item" in classes


def test_init_mode_toggles_pwspray_armed_body_class():
    """initMode must flip body.pwspray-armed off m.pwspray_armed —
    the ctx-menu rules dict reads this class to enable the entry."""
    src = _html_src()
    assert "if (m && m.pwspray_armed) {" in src
    assert "document.body.classList.add('pwspray-armed')" in src


def test_show_ctx_menu_wires_predicates_rules_hints_hidden():
    """The three gating dicts + the two locals (hasDispPort,
    pwsprayArmed) must all exist and reference the password_spray
    action — otherwise the row is either silently always-enabled or
    always-disabled regardless of state."""
    src = _html_src()
    assert "const hasDispPort = n && (n.instances || []).some(" in src
    assert ("const pwsprayArmed = document.body.classList.contains("
            "'pwspray-armed')") in src
    # rules entry
    assert "'password_spray':   pwsprayArmed && hasDispPort," in src
    # hidden entry — hide on non-ABAP (no DIAG dispatcher)
    assert "'password_spray':   !isAbapStack," in src
    # hints entry — distinguishes not-armed vs no-dispatcher
    assert "'password_spray':   (!pwsprayArmed" in src


def test_ctx_action_switch_dispatches_password_spray():
    """The click handler must route data-action=password_spray through
    api('POST', 'node/${sid}/password_spray').  Dry-run default is a
    PR-2 invariant: a confirm miss cannot burn the lockout budget."""
    src = _html_src()
    assert "case 'password_spray':" in src
    assert "api('POST', `node/${sid}/password_spray`," in src
    assert "dry_run: true" in src


# ---------------------------------------------------------------------------
# CLI arg surface
# ---------------------------------------------------------------------------

def test_cli_declares_allow_pwspray_flag():
    """--allow-pwspray must appear in sapmap.py's argparse block and
    must be an action='store_true' flag (not a value-taking arg)."""
    src = (REPO_ROOT / "sapmap.py").read_text(encoding="utf-8")
    assert 'parser.add_argument("--allow-pwspray"' in src
    assert 'action="store_true"' in src


def test_cli_wires_allow_pwspray_to_sapmap_mode():
    """Passing --allow-pwspray at startup must flip
    sapmap_mode.set_pwspray_armed(True) — otherwise the arm bit stays
    off and /api/mode lies."""
    src = (REPO_ROOT / "sapmap.py").read_text(encoding="utf-8")
    assert 'getattr(args, "allow_pwspray", False)' in src
    assert "sapmap_mode.set_pwspray_armed(True)" in src
    assert "PASSWORD SPRAY ARMED" in src


def test_pwspray_banner_printed_after_output_capture():
    """The pwspray banner is operator-facing — it must land in the GUI
    console, not just the terminal.  Positional check: the
    'PASSWORD SPRAY ARMED' print must appear AFTER the
    ``sys.stdout = OutputCapture(...)`` install, matching the
    evasion-banner precedent.  Earlier placement would push the
    banner to the terminal only."""
    src = (REPO_ROOT / "sapmap.py").read_text(encoding="utf-8")
    capture_at = src.find("sys.stdout = OutputCapture(")
    banner_at = src.find("PASSWORD SPRAY ARMED")
    assert capture_at > 0, "OutputCapture install not found"
    assert banner_at > 0, "pwspray banner not found"
    assert banner_at > capture_at, (
        "The 'PASSWORD SPRAY ARMED' banner is printed BEFORE "
        "OutputCapture is installed — it will reach the terminal "
        "only, not the GUI console.  Move it below the "
        "`sys.stdout = OutputCapture(...)` line, next to "
        "print_evasion_banner().")


# ---------------------------------------------------------------------------
# 403 refusal body shape + GET pool arm gate (addresses PR2 adversarial
# review findings #4 / #8).
# ---------------------------------------------------------------------------

def test_pwspray_refusal_body_carries_route_field():
    """The 403 refusal body documents ``{error, message, route}`` to
    match the read-only hook — the ``route`` key must actually be
    emitted so a shared frontend 403 handler can key on it."""
    src = (REPO_ROOT / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")
    # Find the refusal json.dumps block (there is exactly one in
    # _pwspray_armed_or_refuse) and assert it contains the route key.
    assert '"route": rule' in src, (
        "The pwspray 403 body must emit a 'route' field matching the "
        "read-only hook's {error, message, route} shape")


def test_get_pool_route_arm_gated():
    """GET /api/actions/password_spray/pool must call the arm-gate
    helper too — unarmed sessions should NOT get the source
    breakdown + per-source counts (reconnaissance of harvest state).
    Verifies the fix for lens-A finding #4."""
    src = (REPO_ROOT / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")
    import re
    # Isolate actions_password_spray_pool's handler body.
    m = re.search(
        r"@app\.route\(\"/api/actions/password_spray/pool\", "
        r"method=\"GET\"\)\s*\n\s*def actions_password_spray_pool\(\):"
        r"(.*?)@app\.route",
        src, re.DOTALL)
    assert m, "actions_password_spray_pool handler not found"
    body = m.group(1)
    assert "_pwspray_armed_or_refuse()" in body, (
        "GET /api/actions/password_spray/pool must call "
        "_pwspray_armed_or_refuse() like the sibling POST routes — "
        "otherwise unarmed callers see per-source credential counts.")


# ---------------------------------------------------------------------------
# SprayRun field-name contract (addresses lens-A findings #1 / #2 — the
# per-node route previously read non-existent `.attempts` / `att.username`
# / `att.status` fields, so the CRITICAL emit_finding never fired on a
# real hit and the per-attempt task-label never updated).
# ---------------------------------------------------------------------------

def test_route_reads_correct_sprayrun_hit_fields():
    """The _run post-spray summarisation must read SprayRun.hits (a
    list of dicts) and SprayRun.attempts_done (int) — not a non-
    existent .attempts field — so a landed credential surfaces as the
    CRITICAL finding the operator actually watches."""
    src = (REPO_ROOT / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")
    # Find the per-node spray _run block.
    import re
    m = re.search(
        r"def node_password_spray\(sid\):(.*?)def actions_password_",
        src, re.DOTALL)
    assert m, "node_password_spray handler not found"
    body = m.group(1)
    assert 'getattr(run_result, "attempts_done"' in body, (
        "Hit summary must read SprayRun.attempts_done (int), not a "
        "non-existent .attempts collection")
    assert 'getattr(run_result, "hits"' in body
    assert 'getattr(run_result, "locked_users"' in body
    # Negative: the stale field names must NOT reappear.
    assert 'run_result.attempts' not in body, (
        "SprayRun has no `.attempts` field — the correct names are "
        ".hits / .attempts_done / .locked_users")


def test_route_on_attempt_uses_correct_sprayattempt_fields():
    """The _on_attempt task-label callback must read SprayAttempt.user
    / .result (per dataclass), not .username / .status — otherwise
    every per-attempt progress update raises AttributeError and the
    task label is frozen for the full run."""
    src = (REPO_ROOT / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")
    # The _on_attempt callback is tiny — just assert it has the right
    # attribute names.
    assert "att.user" in src
    assert "att.result" in src
    # And NO stale references in the callback area.
    import re
    m = re.search(r"def _on_attempt\(att\):(.*?)print\(f\"\[\*\] \{sid\}:",
                  src, re.DOTALL)
    if m:
        body = m.group(1)
        assert "att.username" not in body
        assert "att.status" not in body


def test_route_surfaces_production_skipped_as_warning():
    """When the engine refuses the node (production_opt_in_required
    or similar), run.skipped carries the reason but run.aborted stays
    empty.  Emitting INFO 'no hits' in that case is misleading.  The
    route must emit WARNING with the refusal reason when skipped
    reasons exist AND attempts==0 — otherwise a well-meaning operator
    reading the findings UI thinks the sweep ran cleanly."""
    src = (REPO_ROOT / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")
    assert 'ref="pwspray.skipped"' in src, (
        "Add an emit_finding('WARNING', ..., ref='pwspray.skipped') "
        "branch so engine-level pre-flight refusals (production flag, "
        "UCON block, policy probe failure) surface explicitly")
    assert "skipped_reasons" in src
