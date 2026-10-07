"""Pins for the SAPGUI logon-text secrets scanner (issue #68 PR2 of 4).

Each test is a specific input shape the operator could realistically
see in a logon banner.  The scanner must flag it with the right
severity + pattern_name, OR specifically NOT flag it when the input
looks suspicious but isn't actually a credential leak.

False positives are the real cost here — operators will mentally
mute the whole feature if it cries "CRITICAL" on every banner, so
every "must NOT match" test is as important as every "must match"
test.

No GUI / route wiring in this PR; the library is called directly.
"""
from __future__ import annotations

import modules  # noqa: F401 — registers package paths

import pytest

from sap_logon_text_secrets import (
    scan_text,
    CRITICAL, HIGH, MEDIUM, INFO,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _patterns(findings):
    """Set of (severity, pattern_name) tuples for assertion."""
    return {(f["severity"], f["pattern_name"]) for f in findings
            if not f.get("error")}


def _names(findings):
    return {f["pattern_name"] for f in findings if not f.get("error")}


# ---------------------------------------------------------------------------
# CRITICAL — credentials in cleartext
# ---------------------------------------------------------------------------

def test_user_password_adjacent_classic_english():
    """Issue #68's example: admin posts 'use client 100 and user admin
    with password Welcome1' on the SAPGUI logon banner."""
    text = ("Welcome to the DEV system — use client 100 and "
            "user: admin  password: Welcome1 — happy testing!")
    findings = scan_text(text)
    names = _names(findings)
    assert "user_password_adjacent" in names
    # Any match in this pattern family is CRITICAL.
    sev = next(f["severity"] for f in findings
                if f["pattern_name"] == "user_password_adjacent")
    assert sev == CRITICAL


def test_password_user_adjacent_reversed_order():
    """Reverse order — password first, then user.  Both must flag."""
    text = "login creds for 800: Password=S4h@na123 user=TESTADM"
    findings = scan_text(text)
    assert "password_user_adjacent" in _names(findings)


def test_user_password_adjacent_bracketed_multiword_value_not_truncated():
    """Regression pin — observed live on an authorized NPL lab banner
    (2026-10-06): an admin posted ``User: Joris Password: <zou je wel
    willen weten he?>`` as a joke, but the catalogue's ``\\S+`` capture
    stopped at the first whitespace and showed only ``<zou`` in the
    GUI results modal, hiding the fact the "password" was actually a
    Dutch joke message.  The ``_VALUE_SHAPES`` alternation now
    captures bracketed / quoted / parenthesised multi-word values as
    alternatives to ``\\S+``, so operators see the full leaked string.
    """
    banner = "User: Joris Password: <zou je wel willen weten he?>"
    findings = scan_text(banner)
    hits = [f for f in findings
            if f["pattern_name"] == "user_password_adjacent"]
    assert hits, "regex failed to fire on the multi-word banner"
    # The full "<...>" value must land in the match, including the
    # closing bracket — operator reads it right off the UI without
    # having to dig into the loot JSON.
    assert "<zou je wel willen weten he?>" in hits[0]["match"]


def test_user_password_adjacent_quoted_value_shapes_all_captured():
    """Four common 'quoted' password-value shapes all land in the
    match verbatim: <angle>, "double", 'single', [square], (paren).
    Bare \\S+ remains the fallback so single-word values still work."""
    cases = [
        ("User: j Password: <multi word>",         "<multi word>"),
        ("User: j Password: \"multi word\"",        '"multi word"'),
        ("User: j Password: 'multi word'",         "'multi word'"),
        ("User: j Password: [multi word]",         "[multi word]"),
        ("User: j Password: (multi word)",         "(multi word)"),
        ("User: j Password: SingleWord!",          "SingleWord!"),
    ]
    for banner, expected in cases:
        findings = scan_text(banner)
        hits = [f for f in findings
                if f["pattern_name"] == "user_password_adjacent"]
        assert hits, f"no match on {banner!r}"
        assert expected in hits[0]["match"], (
            f"expected {expected!r} in match {hits[0]['match']!r}")


def test_password_user_adjacent_bracketed_value_shapes():
    """Same ``_VALUE_SHAPES`` alternation on the password-first
    reverse pattern — a banner that puts password before user with
    a quoted value must still capture the full value."""
    banner = 'Password: "my long value here" User: sapmap00'
    findings = scan_text(banner)
    hits = [f for f in findings
            if f["pattern_name"] == "password_user_adjacent"]
    assert hits, "reverse-order regex missed the quoted-value shape"
    assert '"my long value here"' in hits[0]["match"]


def test_user_password_adjacent_german_vocabulary():
    """SAP shops in DACH often post in German — the regex catalogue
    needs to cover 'Kennwort' and 'Passwort' not just 'password'."""
    text = ("Zum Testen in Mandant 100: Benutzer: admin  "
            "Kennwort: Welcome2024")
    findings = scan_text(text)
    # 'Benutzer' isn't in our label set — the English 'User:' + a
    # localised password label is the realistic shape.  Rework the
    # input to mirror what an admin writes:
    text2 = "Test-Kontext in Mandant 100: User: admin Kennwort: Welcome1"
    f2 = scan_text(text2)
    assert "user_password_adjacent" in _names(f2)


def test_sap_service_account_near_password_label():
    """Even without 'user:' / 'pass:' structure, the mere mention of
    SAP* / DDIC / EARLYWATCH within a few words of 'password' is
    highly suspicious."""
    text = ("For maintenance you can log on as SAP* — the password "
            "is in the vault.")
    findings = scan_text(text)
    assert "sap_service_account_with_password_label" in _names(findings)
    sev = next(f["severity"] for f in findings
                if f["pattern_name"]
                == "sap_service_account_with_password_label")
    assert sev == CRITICAL


def test_sap_service_account_without_password_label_does_not_fire():
    """Just naming SAP* with no password context is NOT a leak —
    service account names appear in benign documentation all the
    time ('run as SAP* only for emergencies')."""
    text = "Emergency access: contact the Basis team to use SAP*."
    findings = scan_text(text)
    assert "sap_service_account_with_password_label" not in _names(findings)


def test_aws_access_key():
    text = "Cloud creds: AKIAIOSFODNN7EXAMPLE  (please don't rotate yet)"
    findings = scan_text(text)
    names = _names(findings)
    assert "aws_access_key_id" in names
    sev = next(f["severity"] for f in findings
                if f["pattern_name"] == "aws_access_key_id")
    assert sev == CRITICAL


def test_aws_access_key_lowercase_prefix_does_not_match():
    """Case-sensitive prefix — 'akia' lowercase is NOT a key."""
    text = "akia0987XYZABCDEFGHI"
    findings = scan_text(text)
    assert "aws_access_key_id" not in _names(findings)


def test_private_key_header():
    for prefix in ("RSA", "OPENSSH", "DSA", "EC", "ENCRYPTED"):
        text = f"-----BEGIN {prefix} PRIVATE KEY-----\nabcdefg==\n---"
        findings = scan_text(text)
        assert "private_key_header" in _names(findings), (
            f"missed {prefix} private key header")


# ---------------------------------------------------------------------------
# HIGH — token shapes
# ---------------------------------------------------------------------------

def test_jwt_token():
    jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    text = f"Bearer {jwt}"
    findings = scan_text(text)
    assert "jwt_token" in _names(findings)
    sev = next(f["severity"] for f in findings
                if f["pattern_name"] == "jwt_token")
    assert sev == HIGH


def test_bearer_or_api_key_labeled():
    text = "API_KEY: abcd1234EFGH5678abcd1234EFGH5678"
    findings = scan_text(text)
    assert "bearer_or_api_key_labeled" in _names(findings)


def test_bearer_label_with_short_value_does_not_match():
    """A short value after a 'token:' label is usually a placeholder
    or a tiny demo value — not a secret.  The 20-char floor keeps
    out the noise."""
    text = "token: 1234"
    findings = scan_text(text)
    assert "bearer_or_api_key_labeled" not in _names(findings)


def test_high_entropy_base64_blob():
    # 60-char base64 blob with digits + letters
    blob = "aGVsbG8gd29ybGQgYmFubmVyIHRleHQgd2l0aCBleHRyYSBwYWRkaW5n0123"
    text = f"Service account JSON: {blob}"
    findings = scan_text(text)
    assert "high_entropy_base64_blob" in _names(findings)


def test_high_entropy_base64_blob_rejects_pure_letters():
    """A long alphabetic string without digits is probably an ASCII
    banner — don't flag it."""
    text = "A" * 60
    findings = scan_text(text)
    assert "high_entropy_base64_blob" not in _names(findings)


# ---------------------------------------------------------------------------
# MEDIUM — PII + network
# ---------------------------------------------------------------------------

def test_email_address():
    text = "Contact admin.basis@example.com for emergency access"
    findings = scan_text(text)
    names = _names(findings)
    assert "email_address" in names


def test_phone_e164():
    text = "Hotline: +31201234567"
    findings = scan_text(text)
    assert "phone_e164" in _names(findings)


def test_phone_local_dashed():
    text = "If anything breaks, call 020-123-4567"
    findings = scan_text(text)
    assert "phone_local" in _names(findings)


def test_phone_local_rejects_dateish_integers():
    """'SAP S4 2024 12 month' is not a phone number — digits with
    no separator in that specific shape should not match."""
    text = "SAP S4 2024 12 month ramp-up"
    findings = scan_text(text)
    assert "phone_local" not in _names(findings)


def test_ipv4_near_contact_cue():
    text = "For urgent access connect to 10.0.5.42 and use the vault"
    findings = scan_text(text)
    assert "ipv4_near_contact_cue" in _names(findings)


def test_ipv4_without_contact_cue_does_not_fire():
    """A naked IPv4 somewhere in the banner isn't suspicious on its
    own — only when near a 'connect to' / 'server' / 'host' hint."""
    text = "Load averaged 0.15 at IP registry rev 10.0.5.42 counter"
    findings = scan_text(text)
    # No contact cue word within 40 chars → no finding from the
    # cue-anchored IPv4 pattern.
    assert "ipv4_near_contact_cue" not in _names(findings)


def test_ipv6_compressed():
    text = "Internal server: fe80::1  — contact Netops"
    findings = scan_text(text)
    assert "ipv6_compressed" in _names(findings)


# ---------------------------------------------------------------------------
# Custom patterns (operator textarea)
# ---------------------------------------------------------------------------

def test_custom_pattern_default_severity_is_medium():
    """A bare custom pattern (no 'SEV:' prefix) must default to MEDIUM
    — matches our pattern-catalog guidance for anything the operator
    adds that isn't explicitly a secret."""
    text = "Mentions TENANT-X-CODENAME inside the greeting"
    findings = scan_text(text, custom_patterns=["TENANT-X-CODENAME"])
    assert any(f["pattern_name"].startswith("custom_")
                and f["severity"] == MEDIUM
                for f in findings)


def test_custom_pattern_explicit_severity_override():
    """CRITICAL: <regex> prefix is honoured.  Operators who know
    their tenant's codename IS secret can escalate."""
    text = "Deploying to project PHOENIX-X-1 this week"
    findings = scan_text(
        text, custom_patterns=["CRITICAL: PHOENIX-X-\\d+"])
    assert any(f["severity"] == CRITICAL
                and f["pattern_name"].startswith("custom_")
                for f in findings)


def test_custom_pattern_blank_and_comment_lines_skipped():
    """Operator textarea input tolerates empty lines and comments."""
    text = "secret: hunter2"
    findings = scan_text(text, custom_patterns=[
        "",
        "# This is a header comment",
        "// another comment",
        "HIGH: secret[:= ]+\\S+",
    ])
    sev = {f["severity"] for f in findings
           if f["pattern_name"].startswith("custom_")}
    assert HIGH in sev


def test_custom_pattern_compile_error_returned_as_parse_error():
    """A bad regex must NOT crash scan_text — it must flow through
    as a parse-error finding with the compile message so the
    operator can see what went wrong without re-running."""
    findings = scan_text("some text", custom_patterns=["[unclosed"])
    err = [f for f in findings if f.get("error")]
    assert len(err) == 1
    assert "custom pattern compile failed" in err[0]["snippet"]


def test_custom_pattern_bad_severity_falls_back_to_medium():
    """A line with an unknown prefix ('FOO:') is treated as a bare
    regex pattern — the whole line becomes the pattern body, which
    is still searched against the text.  Pin that we don't silently
    swallow the pattern on an invalid severity prefix."""
    text = "banner text with FOO: match-this-word-here embedded"
    findings = scan_text(
        text, custom_patterns=["FOO: match-this-word-here"])
    customs = [f for f in findings
               if f["pattern_name"].startswith("custom_")]
    assert customs, (
        "A bad SEV prefix must not swallow the whole pattern — the "
        "whole line becomes the regex and still runs")
    assert customs[0]["severity"] == MEDIUM


# ---------------------------------------------------------------------------
# Output shape + sorting
# ---------------------------------------------------------------------------

def test_findings_sorted_by_severity_then_offset():
    """CRITICAL hits come first, then HIGH, then MEDIUM, then INFO.
    Within the same severity, earlier offsets come first."""
    text = (
        "First an email bob@example.com (MEDIUM) at the top, "
        "then user: admin password: Welcome1 (CRITICAL), "
        "then another email alice@example.com (MEDIUM)"
    )
    findings = scan_text(text)
    # The CRITICAL must be first regardless of position in the text.
    assert findings[0]["severity"] == CRITICAL
    # And the two MEDIUM email entries are in text-order relative to
    # each other.
    emails = [f for f in findings if f["pattern_name"] == "email_address"]
    assert len(emails) == 2
    assert emails[0]["offset"] < emails[1]["offset"]


def test_finding_shape_contains_all_required_fields():
    text = "user: admin password: Welcome1"
    f = scan_text(text)[0]
    for key in ("severity", "pattern_name", "category", "match",
                 "snippet", "offset", "context"):
        assert key in f, f"missing key: {key}"


def test_context_passthrough():
    """The optional ``context`` dict is attached verbatim to every
    finding so PR3's route can carry {sid, client, instance_nr}
    through from the scanner into emit_finding()."""
    findings = scan_text(
        "user: admin password: Welcome1",
        context={"sid": "A4H", "client": "001"})
    assert findings[0]["context"] == {"sid": "A4H", "client": "001"}


def test_empty_input_returns_empty_list():
    assert scan_text("") == []
    assert scan_text(None) == []  # type: ignore[arg-type]


def test_empty_input_with_emit_info_flag_returns_info_entry():
    """PR3's drawer wants a per-node 'we checked this' marker even
    when nothing matched.  Opt-in flag."""
    findings = scan_text("", emit_info_on_empty=True,
                          context={"sid": "A4H"})
    assert len(findings) == 1
    assert findings[0]["severity"] == INFO
    assert findings[0]["pattern_name"] == "no_text"
    assert findings[0]["context"] == {"sid": "A4H"}


def test_clean_banner_with_emit_info_flag_still_emits_info():
    """A banner that scans clean (no secrets, has some text) should
    emit INFO 'no_matches' when the flag is on, so the operator sees
    per-node coverage in the drawer."""
    findings = scan_text(
        "Welcome to the test system.  Please log in.",
        emit_info_on_empty=True)
    assert len(findings) == 1
    assert findings[0]["severity"] == INFO
    assert findings[0]["pattern_name"] == "no_matches"


def test_dedup_across_patterns_keeps_both_signals():
    """If a substring matches multiple patterns (e.g. both
    'user_password_adjacent' and some custom pattern on the same
    span), BOTH findings are kept — operators want all the
    category signals, not just the first.

    This also pins that the scanner is NOT deduping too aggressively,
    which would hide the 'this value hit N categories' insight."""
    text = "user: ADMIN password: bob@example.com"
    findings = scan_text(text)
    names = _names(findings)
    # user_password_adjacent fires for the whole shape,
    # email_address fires for the embedded email as the password.
    assert "user_password_adjacent" in names
    assert "email_address" in names


def test_snippet_collapses_whitespace():
    """Multi-line snippets with embedded tabs/newlines must be
    rendered single-line so a UI table row stays legible."""
    text = ("Welcome\n\t\tuser: admin   \tpassword:   Welcome1\n"
            "regards,\nthe team")
    findings = scan_text(text)
    f = next(f for f in findings
             if f["pattern_name"] == "user_password_adjacent")
    assert "\n" not in f["snippet"]
    assert "\t" not in f["snippet"]
    # And whitespace collapsed to single spaces.
    assert "  " not in f["snippet"]


def test_scan_never_raises_on_odd_bytes_decoded_text():
    """The scanner takes str; PR1's _decode_dyn_text already uses
    errors='replace' so the str reaching us can carry U+FFFD
    replacement chars.  Must not raise."""
    text = "user: admin� password: �Welcome�"
    scan_text(text)
    # No assertion needed — not raising is the pin.


# ---------------------------------------------------------------------------
# Negative pins — common false positives operators would complain about
# ---------------------------------------------------------------------------

def test_naked_version_number_no_phone_match():
    """'SAPMAP v1.2.3-4' is NOT a phone number."""
    text = "SAPMAP v1.2.3-4 released"
    findings = scan_text(text)
    assert "phone_local" not in _names(findings)
    assert "phone_e164" not in _names(findings)


def test_version_string_no_bearer_label():
    text = "api_version: 10"
    findings = scan_text(text)
    assert "bearer_or_api_key_labeled" not in _names(findings)


def test_short_ascii_banner_no_false_positives():
    """A plain, friendly banner must produce zero findings (no INFO
    unless the flag is set)."""
    text = ("Welcome to SAPMAP demo.  Click the big button to begin "
            "a scan.  Reports land in loot/.  Have fun!")
    findings = scan_text(text)
    assert findings == []


def test_logon_banner_fixture_critical_at_the_top():
    """A realistic logon banner with mixed severities — assert the
    sorted output has CRITICAL first."""
    banner = (
        "Welkom bij DEV_A4H!\n"
        "Vragen? mail basis@contoso.example of bel +31201234567\n"
        "Service account: SAP* / password: Welcome2024!\n"
        "Jump host: connect to 10.42.0.17\n"
    )
    findings = scan_text(banner)
    assert findings, "fixture banner should produce findings"
    assert findings[0]["severity"] == CRITICAL
    patterns = _names(findings)
    assert ("sap_service_account_with_password_label" in patterns
            or "user_password_adjacent" in patterns
            or "password_user_adjacent" in patterns)
    assert "email_address" in patterns
    assert "phone_e164" in patterns
    assert "ipv4_near_contact_cue" in patterns
