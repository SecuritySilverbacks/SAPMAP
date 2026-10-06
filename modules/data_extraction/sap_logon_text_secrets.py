"""Secrets / PII scanner for SAPGUI logon-screen text (issue #68 PR2 of 4).

Pure library.  No I/O, no socket, no GUI — just an ordered regex
catalogue + ``scan_text()`` entry point that returns structured
findings for a given string.  PR3 wires this into the per-node
``/api/node/<sid>/scan_logon_banners`` route and ``emit_finding()``
calls; PR4 adds the landscape sweep + custom-pattern textarea in the
config modal.

Why a dedicated module instead of growing an existing regex pile:

  * ``sapmap_secstore.py:1693-1704`` has domain-specific DN parsers
    (``_RE_RFC_WITH_USER`` etc.) that only make sense inside SecStore
    envelopes — not reusable here.
  * ``sap_btp.py`` has just ``_REGION_RE`` + an IPv4 shape, nothing
    for passwords / tokens / PII.
  * No existing module scans free-form text for the "admin posted
    credentials on the logon banner" case that issue #68 is about.

Severity tiers follow the pwspray / secstore precedents in
``sapmap_findings.py`` (CRITICAL / HIGH / MEDIUM / INFO):

  CRITICAL  user/password adjacent, SAP service account named with
            a nearby password-looking string, AWS access key,
            private-key header
  HIGH      bearer / JWT / long high-entropy base64 blob
  MEDIUM    e-mail, phone, hostname-adjacent IP, "connect to <host>"
  INFO      no secrets found but scan ran (per-node coverage marker)

Operator-supplied custom patterns (issue #68, operator feedback —
mirrors the pwspray wordlist textarea) are compiled and run after
the built-in catalogue.  They default to MEDIUM severity; prefix
with ``SEV:`` where SEV is one of CRITICAL / HIGH / MEDIUM / INFO
to override (``CRITICAL: my-tenant-codename``).
"""
from __future__ import annotations

import re
from typing import Iterable, Optional


# ---------------------------------------------------------------------------
# Severity model — matches sapmap_findings.SEVERITY_LEVELS.
# ---------------------------------------------------------------------------

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
INFO = "INFO"
_VALID_SEVERITIES = {CRITICAL, HIGH, MEDIUM, INFO}


# ---------------------------------------------------------------------------
# Built-in catalogue.
#
# Each entry: (severity, name, category, compiled_pattern, group_idx).
# ``group_idx`` tells scan_text which capture group holds the matched
# secret value for the ``match`` field (0 = whole match).  Patterns use
# re.IGNORECASE except where capitalisation is load-bearing (e.g.
# AWS key prefix "AKIA" is always upper, JWT prefix "eyJ" case-sensitive).
#
# The ordering is informational only — scan_text runs all patterns
# against the input and returns every hit.  Deduplication happens on
# (pattern_name, offset).  Multiple patterns matching the same
# substring are returned once per pattern so the operator sees all
# the categories at a glance.
# ---------------------------------------------------------------------------

# CRITICAL -----------------------------------------------------------------

# "quoted" shape for the user / password value — tried as alternatives
# BEFORE the bare \S+ fallback so admins who write multi-word values
# in brackets or quotes don't get truncated at the first space:
#
#   "User: Joris Password: <zou je wel willen weten he?>"
#    (observed live on an authorized NPL lab banner, 2026-10-06)
#
# Covers the common wrapper chars: <...>, "...", '...', [...], (...).
# Each wrapper is bounded at 200 chars to keep the regex engine
# well-behaved on hostile input (no .+ catastrophic backtracking).
# Ordered longest-first so the regex engine prefers wrapped forms
# over the bare \S+.
_VALUE_SHAPES = (
    r"(?:"
    r"<[^>\n\r]{1,200}>"
    r"|\"[^\"\n\r]{1,200}\""
    r"|'[^'\n\r]{1,200}'"
    r"|\[[^\]\n\r]{1,200}\]"
    r"|\([^)\n\r]{1,200}\)"
    r"|\S+"
    r")"
)

# "user: XXX ... password: YYY" and reverse order.  The 0-80 char
# distance between the two labels catches:
#   - inline ("user: admin  password: Welcome1")
#   - across whitespace on the logon banner ("User: admin\nPassword: ...")
# Short enough that we don't match "user admin, meet me at the park;
# phone number is passport ..." kind of coincidences.
_RE_USER_THEN_PASSWORD = re.compile(
    r"\buser[:\s=]+" + _VALUE_SHAPES + r"[^\n\r]{0,80}?\b"
    r"(?:pass(?:word|wort)?|pw|pwd|kennwort|contrase[nñ]a|wachtwoord)"
    r"[:\s=]+" + _VALUE_SHAPES,
    re.IGNORECASE,
)
_RE_PASSWORD_THEN_USER = re.compile(
    r"\b(?:pass(?:word|wort)?|pw|pwd|kennwort|contrase[nñ]a|wachtwoord)"
    r"[:\s=]+" + _VALUE_SHAPES + r"[^\n\r]{0,80}?\buser[:\s=]+"
    + _VALUE_SHAPES,
    re.IGNORECASE,
)

# Named SAP admin / service account within 40 chars of a password-looking
# label.  Catches admins posting "login as SAP* with ****" style banners
# even when the structural "user: X pass: Y" shape doesn't match.
#
# Can't use \b around "SAP\*" because * is non-word — \b wouldn't match
# between * and the following whitespace.  Use (?:^|\W) + (?=\W|$) as
# explicit word-boundary surrogates that accept * as a boundary too.
_RE_SAP_SVC_NEAR_PASSWORD = re.compile(
    r"(?:^|\W)(SAP\*|DDIC|EARLYWATCH|SOLMAN_ADMIN|SOLMAN_BTC|CSMREG|"
    r"TMSADM|SAPCPIC|SAPJSF|WF-BATCH)(?=\W|$)[^\n\r]{0,40}?"
    r"(?:pass(?:word|wort)?|pw|pwd|kennwort|contrase[nñ]a|wachtwoord)",
    re.IGNORECASE,
)

# AWS access-key id — the prefix is always uppercase.  No IGNORECASE.
_RE_AWS_KEY = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")

# Private key headers of all common flavours.
_RE_PRIVATE_KEY = re.compile(
    r"-----BEGIN\s+(?:RSA|OPENSSH|DSA|EC|PGP|ENCRYPTED)\s+PRIVATE\s+KEY-----",
    re.IGNORECASE,
)

# HIGH ---------------------------------------------------------------------

# JWT: three base64-url segments separated by dots.  The "eyJ" prefix is
# the base64 encoding of '{"' so it's load-bearing (no IGNORECASE).
_RE_JWT = re.compile(
    r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"
)

# Bearer / API-key / token labels with a long enough value to be a real
# secret (short values are usually examples/placeholders).
_RE_BEARER_TOKEN = re.compile(
    r"\b(?:bearer|token|api[_\-]?key|access[_\-]?token|secret[_\-]?key)"
    r"[:\s=]+[\"']?([A-Za-z0-9_\-\.]{20,})[\"']?",
    re.IGNORECASE,
)

# High-entropy base64 blob (40+ chars) — a weak signal but captures the
# "we pasted the service-account JSON into the logon banner" case.  We
# require that the match CONTAINS at least one digit AND one letter so
# we don't trip on wide ASCII art / long dashes.
_RE_BASE64_BLOB = re.compile(
    r"(?<![A-Za-z0-9+/=])(?=[A-Za-z0-9+/]*[0-9])(?=[A-Za-z0-9+/]*[A-Za-z])"
    r"([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])"
)

# MEDIUM -------------------------------------------------------------------

_RE_EMAIL = re.compile(
    r"\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b"
)

# E.164 phone number (starts with +, 8-15 digits total).
_RE_PHONE_E164 = re.compile(r"\+[1-9]\d{7,14}\b")

# "Loose" local phone number: at least two separator-delimited digit
# groups totalling ≥ 8 digits (10-15 incl. separators).  Requires the
# delimiters so we don't match "SAP S4 2024 12 month" accidentally.
_RE_PHONE_LOCAL = re.compile(
    r"(?<!\d)(?:\(?\d{2,4}\)?[\s.\-]+)\d{3,}(?:[\s.\-]+\d{2,})+(?!\d)"
)

# IPv4 that reads like a "connect to <ip>" admin hint — look for the IP
# within 40 chars of connect / server / host / goto / besuchen / contact
# style keywords.
_RE_IPV4 = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_RE_CONTACT_CUE_NEAR_IPV4 = re.compile(
    r"\b(?:connect|server|host|goto|contact|besuchen|verbinde|login|logon|url)"
    r"[^\n\r]{0,40}?\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b",
    re.IGNORECASE,
)

# IPv6 — compressed form only; the full form is both rare in logon
# banners and quite false-positive-prone (any long hex string hits).
_RE_IPV6_COMPRESSED = re.compile(
    r"\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b", re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Pattern catalogue table — iterate order matters only for stable
# output ordering (findings are sorted by severity then by offset in
# scan_text).  Add new patterns by appending to this table.
# ---------------------------------------------------------------------------
#
# Fields:
#   severity      — one of CRITICAL / HIGH / MEDIUM / INFO
#   name          — short machine-readable slug ("user_password_adjacent")
#   category      — "credentials" / "token" / "pii" / "network" / "custom"
#   pattern       — a compiled re.Pattern
#   group_idx     — which capture group holds the "match" value for the
#                   output dict.  0 = whole match.  For 2-group patterns
#                   (user+password adjacent) use None and the output's
#                   ``match`` field will be the whole match substring so
#                   the operator sees both tokens.

_CATALOGUE: list[tuple[str, str, str, re.Pattern[str], Optional[int]]] = [
    # CRITICAL
    (CRITICAL, "user_password_adjacent", "credentials",
     _RE_USER_THEN_PASSWORD, None),
    (CRITICAL, "password_user_adjacent", "credentials",
     _RE_PASSWORD_THEN_USER, None),
    (CRITICAL, "sap_service_account_with_password_label", "credentials",
     _RE_SAP_SVC_NEAR_PASSWORD, None),
    (CRITICAL, "aws_access_key_id", "token",
     _RE_AWS_KEY, 1),
    (CRITICAL, "private_key_header", "token",
     _RE_PRIVATE_KEY, 0),
    # HIGH
    (HIGH, "jwt_token", "token",
     _RE_JWT, 0),
    (HIGH, "bearer_or_api_key_labeled", "token",
     _RE_BEARER_TOKEN, 1),
    (HIGH, "high_entropy_base64_blob", "token",
     _RE_BASE64_BLOB, 1),
    # MEDIUM
    (MEDIUM, "email_address", "pii",
     _RE_EMAIL, 1),
    (MEDIUM, "phone_e164", "pii",
     _RE_PHONE_E164, 0),
    (MEDIUM, "phone_local", "pii",
     _RE_PHONE_LOCAL, 0),
    (MEDIUM, "ipv4_near_contact_cue", "network",
     _RE_CONTACT_CUE_NEAR_IPV4, 1),
    (MEDIUM, "ipv6_compressed", "network",
     _RE_IPV6_COMPRESSED, 0),
]


# ---------------------------------------------------------------------------
# Custom pattern parsing (operator textarea in the PR4 config modal).
#
# Each line is either:
#   "pattern"                — defaults to MEDIUM severity
#   "SEV: pattern"           — explicit severity override (SEV in
#                              {CRITICAL, HIGH, MEDIUM, INFO})
#   "" / "#..." / "// ..."   — blank or comment, skipped
#
# Patterns are compiled with re.IGNORECASE | re.UNICODE.  A compile
# failure returns a parse-error finding so the operator sees why their
# regex was ignored, rather than silently dropping it.
# ---------------------------------------------------------------------------


_CUSTOM_PREFIX = re.compile(
    r"^\s*(CRITICAL|HIGH|MEDIUM|INFO)\s*:\s*(.+?)\s*$",
    re.IGNORECASE,
)


def _compile_custom_patterns(lines: Iterable[str]):
    """Yield (severity, name, pattern) tuples (or parse-error dicts).

    Parse errors are yielded as the dict shape ``scan_text`` returns,
    so the caller gets them in the same list as real findings and can
    render them with the same code path.
    """
    for idx, raw in enumerate(lines, start=1):
        if raw is None:
            continue
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        m = _CUSTOM_PREFIX.match(line)
        if m:
            severity = m.group(1).upper()
            body = m.group(2)
        else:
            severity = MEDIUM
            body = line
        if severity not in _VALID_SEVERITIES:
            severity = MEDIUM
        try:
            pat = re.compile(body, re.IGNORECASE | re.UNICODE)
        except re.error as exc:
            yield {"error": True, "line_no": idx, "raw": raw,
                   "msg": f"custom pattern compile failed: {exc}"}
            continue
        name = f"custom_{idx:02d}"
        yield (severity, name, pat)


# ---------------------------------------------------------------------------
# Snippet rendering
# ---------------------------------------------------------------------------


def _snippet(text: str, start: int, end: int, context: int = 32) -> str:
    """Return a one-line context window around ``[start:end)`` for
    display in findings.  Newlines inside the window collapse to spaces
    so a UI table row stays single-line."""
    lo = max(0, start - context)
    hi = min(len(text), end + context)
    s = text[lo:hi]
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    s = re.sub(r"\s+", " ", s).strip()
    prefix = "…" if lo > 0 else ""
    suffix = "…" if hi < len(text) else ""
    return f"{prefix}{s}{suffix}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, INFO: 3}


def scan_text(text: str,
              custom_patterns: Optional[Iterable[str]] = None,
              context: Optional[dict] = None,
              emit_info_on_empty: bool = False) -> list[dict]:
    """Scan ``text`` for secrets / PII and return structured findings.

    Args:
        text              Free-form string from the SAPGUI logon banner.
                          None / "" returns [] (or an INFO entry if
                          ``emit_info_on_empty`` and some context is
                          provided — see below).
        custom_patterns   Optional iterable of operator-supplied regex
                          lines (one per line, "SEV: pattern" or just
                          "pattern").  Compiled with IGNORECASE | UNICODE.
                          Compile failures surface as parse-error entries
                          in the output list.
        context           Opaque dict (``{"sid": "...", "client": "..."}``)
                          attached verbatim to every finding so the PR3
                          route handler can route them to the right
                          ``emit_finding(..., node=sid, ...)``.
        emit_info_on_empty  When True AND no patterns matched AND some
                          text was scanned, append a single INFO entry
                          so operators see per-node coverage even when
                          nothing suspicious was found (PR3 wants this
                          for the drawer "we checked this box" marker).

    Returns:
        A list of dicts, sorted by (severity_rank, offset).  Each has:
          severity        CRITICAL / HIGH / MEDIUM / INFO
          pattern_name    machine-readable slug
          category        credentials / token / pii / network / custom
          match           the matched substring (first capture group
                          if the pattern has one, else whole match)
          snippet         one-line context window around the match
          offset          byte position of the match in `text`
          context         the ``context`` arg verbatim, or {}
        Plus, for compile-failure custom patterns:
          error: True, msg: "...", line_no: int, raw: str
    """
    results: list[dict] = []
    if not text:
        if emit_info_on_empty:
            results.append({
                "severity": INFO,
                "pattern_name": "no_text",
                "category": "coverage",
                "match": "",
                "snippet": "",
                "offset": 0,
                "context": dict(context or {}),
            })
        return results

    ctx = dict(context or {})

    # Built-in catalogue.
    for severity, name, category, pat, group_idx in _CATALOGUE:
        for m in pat.finditer(text):
            if group_idx is None:
                matched_val = m.group(0)
            else:
                try:
                    matched_val = m.group(group_idx)
                except (IndexError, re.error):
                    matched_val = m.group(0)
            results.append({
                "severity": severity,
                "pattern_name": name,
                "category": category,
                "match": matched_val,
                "snippet": _snippet(text, m.start(), m.end()),
                "offset": m.start(),
                "context": dict(ctx),
            })

    # Custom patterns.
    if custom_patterns is not None:
        for item in _compile_custom_patterns(custom_patterns):
            if isinstance(item, dict):
                # Compile-error pass-through — attach context + a stable
                # shape so the UI can render it alongside real findings.
                item = {
                    "severity": INFO,
                    "pattern_name": f"custom_parse_error_{item['line_no']}",
                    "category": "custom",
                    "match": item["raw"],
                    "snippet": item["msg"],
                    "offset": 0,
                    "context": dict(ctx),
                    "error": True,
                }
                results.append(item)
                continue
            severity, name, pat = item
            for m in pat.finditer(text):
                results.append({
                    "severity": severity,
                    "pattern_name": name,
                    "category": "custom",
                    "match": m.group(0),
                    "snippet": _snippet(text, m.start(), m.end()),
                    "offset": m.start(),
                    "context": dict(ctx),
                })

    # INFO baseline (opt-in) when nothing matched.
    if not results and emit_info_on_empty:
        results.append({
            "severity": INFO,
            "pattern_name": "no_matches",
            "category": "coverage",
            "match": "",
            "snippet": _snippet(text, 0, min(len(text), 80)),
            "offset": 0,
            "context": dict(ctx),
        })

    results.sort(key=lambda r: (_SEVERITY_RANK.get(r["severity"], 99),
                                 r["offset"]))
    return results


__all__ = [
    "scan_text",
    "CRITICAL", "HIGH", "MEDIUM", "INFO",
]
