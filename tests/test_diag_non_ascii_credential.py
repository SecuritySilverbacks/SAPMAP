#!/usr/bin/env python3
"""Regression tests for issue #121: password spray crashes with
``'ascii' codec can't encode characters in position X-Y`` when the
pool contains a credential with a non-ASCII character.

Root cause: modules/discovery/sap_client_enum.py:252 (and :189) used
``.encode('ascii')`` without an error handler, so any non-ASCII char
in the DIAG client/username/password/terminal field raised
UnicodeEncodeError at packet-build time — well before the DIAG
session was opened — and the exception bubbled out of
``spray_landscape``, killing the whole landscape sweep on a single
bad candidate.

Fix: encode as Latin-1 (ISO-8859-1) with ``errors='replace'`` to
match the ``code_page=1100`` the DIAG init negotiates with the
server.  Chars outside Latin-1 become ``?`` — they will silently
fail to authenticate on the server, but no longer crash the sweep.
Pure-ASCII input is byte-identical (Latin-1 is a superset).

These tests exercise the packet builders directly — the pwspray
engine's exception path is harder to pin without live sockets, but
the builder is the exact spot that threw.
"""
from __future__ import annotations

import pytest

import modules  # noqa: F401 — registers package paths


# ---------------------------------------------------------------------------
# build_efield2_atom — the exact line that crashed in issue #121
# ---------------------------------------------------------------------------

def test_build_efield2_atom_ascii_text_unchanged():
    """Latin-1 is a superset of ASCII — pure-ASCII input must produce
    byte-identical output to the pre-fix behaviour, so existing
    integration tests (and real DIAG logins on ASCII creds) stay
    byte-perfect."""
    from sap_client_enum import build_efield2_atom
    atom = build_efield2_atom(
        block=1, row=3, col=20,
        text="PASSWORD", maxnrchars=40, mlen=12,
        dlg_flag_1=4, dlg_flag_2=1, invisible=True)
    # The atom is bytes — ASCII 'PASSWORD' appears verbatim in it.
    assert b"PASSWORD" in atom, (
        f"ASCII text must still appear verbatim in the atom; got {atom!r}")


@pytest.mark.parametrize("password", [
    "pöl1cy",           # German umlaut at position 1
    "AB®CD",            # Position 2 — matches the exact issue #121 report
    "aßword",           # German sharp s
    "mañana",           # Spanish tilde
    "café123",          # French accent
    "北京",              # CJK (outside Latin-1 — will be '??')
    "passéword",   # Explicit Unicode escape
    "ÿ" * 3,       # Edge of Latin-1
])
def test_build_efield2_atom_non_ascii_text_no_crash(password):
    """Pre-fix: these would raise ``UnicodeEncodeError: 'ascii' codec
    can't encode character ... in position N: ordinal not in
    range(128)``, taking the whole landscape pwspray down.  Post-fix:
    builder returns bytes without raising.  Whether the auth
    succeeds on the server is a separate question — this test only
    pins that the client doesn't crash."""
    from sap_client_enum import build_efield2_atom
    try:
        atom = build_efield2_atom(
            block=1, row=3, col=20,
            text=password, maxnrchars=40, mlen=12,
            dlg_flag_1=4, dlg_flag_2=1, invisible=True)
    except UnicodeEncodeError as e:
        pytest.fail(
            f"build_efield2_atom({password!r}) must not raise "
            f"UnicodeEncodeError — this was the issue #121 crash. "
            f"Got: {e}")
    assert isinstance(atom, (bytes, bytearray))
    assert len(atom) > 0


def test_build_efield2_atom_bytes_passthrough_unchanged():
    """When text is already bytes (caller pre-encoded), the function
    must pass it through unchanged — the Latin-1 encode is only for
    str input.  Guard against a regression where the fix accidentally
    double-encoded or dropped the bytes branch."""
    from sap_client_enum import build_efield2_atom
    atom = build_efield2_atom(
        block=1, row=3, col=20,
        text=b"RAW_BYTES", maxnrchars=40, mlen=12)
    assert b"RAW_BYTES" in atom


# ---------------------------------------------------------------------------
# build_dp_header — the sibling .encode("ascii") at line 189
# ---------------------------------------------------------------------------

def test_build_dp_header_default_terminal_unchanged():
    """Default terminal ``sapscanner`` is pure ASCII — byte-identical
    output post-fix (Latin-1 is a superset of ASCII)."""
    from sap_client_enum import build_dp_header
    dp = build_dp_header("sapscanner")
    # Terminal lives at bytes [81:96], ASCII, null-padded to 15 bytes.
    assert dp[81:96] == b"sapscanner".ljust(15, b"\x00")


@pytest.mark.parametrize("terminal", [
    "sapmap-spräy",     # umlaut
    "scänner",          # umlaut
    "pwspé",       # accented e
    "北京-term",         # CJK — gets '?' replacement in Latin-1
])
def test_build_dp_header_non_ascii_terminal_no_crash(terminal):
    """Pre-fix: a non-ASCII terminal name crashed with the same
    UnicodeEncodeError.  Default callers always pass ASCII
    (``sapscanner``, ``sapmap-spray-purple``) so this is defensive —
    protects against a future caller or operator-customised
    terminal name that happens to have a non-ASCII char."""
    from sap_client_enum import build_dp_header
    try:
        dp = build_dp_header(terminal)
    except UnicodeEncodeError as e:
        pytest.fail(
            f"build_dp_header({terminal!r}) must not raise "
            f"UnicodeEncodeError. Got: {e}")
    assert len(dp) >= 96
    # Terminal slot stays 15 bytes, null-padded.
    assert len(dp[81:96]) == 15


# ---------------------------------------------------------------------------
# End-to-end — try_login must not propagate UnicodeEncodeError
# ---------------------------------------------------------------------------

def test_try_login_non_ascii_password_does_not_crash_at_packet_build():
    """End-to-end regression — pre-fix, try_login(..., password='pö')
    crashed in build_diag_login_packet -> build_efield2_atom before
    the socket even connected.  Post-fix, it reaches the socket
    layer and fails with a connect-timeout against a bogus host.

    Monkeypatch: redirect to an unreachable address so try_login
    returns a networking error instead of actually attempting a
    DIAG handshake.  The point is to prove no UnicodeEncodeError
    bubbles out of the builder path."""
    from sap_default_creds import try_login
    # Unroutable TEST-NET-1 address (RFC 5737) with a 1s timeout.
    # Any error EXCEPT UnicodeEncodeError is acceptable here —
    # the test is about client-side safety, not reachability.
    try:
        result = try_login(
            host="192.0.2.1",
            port=3200,
            client="000",
            user="DDIC",
            password="pöl1cy",   # non-ASCII at position 1
            timeout=1)
    except UnicodeEncodeError as e:
        pytest.fail(
            f"try_login with a non-ASCII password must not raise "
            f"UnicodeEncodeError — this was the issue #121 crash in "
            f"the pwspray landscape sweep.  Got: {e}")
    # Expected shape: (result_code, detail_string) — some kind of
    # connection failure.
    assert isinstance(result, tuple)
    assert len(result) == 2
