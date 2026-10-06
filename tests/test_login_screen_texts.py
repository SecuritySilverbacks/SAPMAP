"""Pins for the pysap-port fixes to sap_login_screen_texts.py
(issue #68, PR1 of 4).

The module itself is unchanged in intent — it still fetches a SAP
NetWeaver dispatcher's DIAG login-screen banner and parses the
server info + DYNT atom text.  This PR fixes three latent bugs
that would surface as soon as the module is wired into the GUI's
``_bg`` background runner (planned for PR3):

  * dual-path import so the GUI backend doesn't ModuleNotFoundError
    the first time an operator triggers a login-screen scan
  * compressed-DIAG response is caught + returned as None rather
    than crashing the whole ``_bg`` worker on a ValueError
  * UTF-16LE fallback decoder on both the SERV_INFO fields and
    the DYNT atom text, so modern Unicode-kernel targets don't
    silently decode as ``"S\\x00A\\x00P\\x00..."`` and starve the
    secrets-regex scan planned for PR2

No behaviour change in the standalone CLI run against classic
non-Unicode kernels; the fallback decoder picks the UTF-16LE path
only when the heuristic (NUL in first 16 B + even length + ASCII
first byte) is met.
"""
from __future__ import annotations

import pathlib
import struct

import pytest

import modules  # noqa: F401 — registers package paths

from sap_login_screen_texts import (
    _decode_dyn_text, _to_str, collect_text_info, walk_items,
    fetch_login_items,
    DIAG_ITEM_APPL, DIAG_ITEM_APPL4, DIAG_ITEM_EOM,
    DIAG_APPL_DYNT, DIAG_DYNT_ATOM, DIAG_APPL_ST_R3INFO,
    DIAG_R3INFO_DBNAME,
)


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Fix 1 — dual-path import
# ---------------------------------------------------------------------------

def test_module_import_tolerates_files_namespace():
    """The GUI backend sometimes loads SAPMAP modules via the packaged
    ``files.*`` layout before ``modules/__init__.py`` injects the
    discovery subpackage onto sys.path.  The bare ``from
    sap_client_enum import ...`` form would crash with
    ModuleNotFoundError in that case; the dual-path try/except mirrors
    the pattern already in ``sap_default_creds.py:26-31`` so both
    load orders work."""
    src = (REPO_ROOT / "modules" / "discovery"
           / "sap_login_screen_texts.py").read_text(encoding="utf-8")
    # Must have the fallback branch, matching sap_default_creds's shape.
    assert "try:" in src
    assert "from sap_client_enum import" in src
    assert "except ImportError:" in src
    assert "from files.sap_client_enum import" in src


# ---------------------------------------------------------------------------
# Fix 2 — compressed-DIAG response is caught, not raised
# ---------------------------------------------------------------------------

def test_walk_items_still_raises_on_compressed_response():
    """``walk_items`` keeps its old contract (raise ValueError on
    compressed response) — the suppression lives one level up in
    ``fetch_login_items``.  Pin so a future refactor doesn't move
    the suppression into walk_items itself and lose the signal."""
    # 8-byte DIAG header with compress byte != 0 (byte 7 == 1).
    header = bytes([0] * 7 + [1])
    body = bytes([DIAG_ITEM_EOM])
    with pytest.raises(ValueError, match="compressed"):
        list(walk_items(header + body))


def test_fetch_login_items_catches_compressed_response(monkeypatch):
    """When the DIAG response is compressed, ``walk_items`` raises;
    ``fetch_login_items`` must catch that and return None rather than
    letting the exception bubble out of the ``_bg`` worker.  Simulate
    by monkey-patching ``_diag_connect`` + the NI helpers so no real
    socket work happens."""
    import sap_login_screen_texts as mod
    import types

    class _FakeSock:
        def close(self):
            pass

    def _fake_connect(host, port, timeout, saprouter=""):
        return _FakeSock()

    def _fake_send(sock, data):
        return None

    def _fake_recv(sock, timeout):
        # 8-byte DIAG header with compress byte != 0 + a byte of body
        # (long enough to pass the 50-byte "short response" guard).
        header = bytes([0] * 7 + [1])
        return header + bytes(100)   # pad to 108 B total

    monkeypatch.setattr(mod, "_diag_connect", _fake_connect)
    monkeypatch.setattr(mod, "ni_send", _fake_send)
    monkeypatch.setattr(mod, "ni_recv", _fake_recv)

    opts = types.SimpleNamespace(route_string="", timeout=1, verbose=False)
    result = mod.fetch_login_items("10.0.0.1", 3200, opts, "term01")
    assert result is None, (
        "fetch_login_items must swallow the ValueError raised by "
        "walk_items on a compressed response and return None, so the "
        "background scan task does not crash")


def test_fetch_login_items_returns_none_on_short_reply(monkeypatch):
    """Unchanged behaviour: < 50 B response still returns None (SNC-
    enforced or non-DIAG port).  Pin so the new compressed-response
    catch doesn't accidentally regress the short-reply path."""
    import sap_login_screen_texts as mod
    import types

    class _FakeSock:
        def close(self):
            pass

    def _fake_connect(host, port, timeout, saprouter=""):
        return _FakeSock()

    def _fake_recv(sock, timeout):
        return bytes(10)   # 10 B — well below the 50 B threshold

    monkeypatch.setattr(mod, "_diag_connect", _fake_connect)
    monkeypatch.setattr(mod, "ni_send", lambda s, d: None)
    monkeypatch.setattr(mod, "ni_recv", _fake_recv)

    opts = types.SimpleNamespace(route_string="", timeout=1, verbose=False)
    assert mod.fetch_login_items("10.0.0.1", 3200, opts, "term01") is None


# ---------------------------------------------------------------------------
# Fix 3 — UTF-16LE fallback decoder
# ---------------------------------------------------------------------------

def test_decode_dyn_text_handles_utf16le_bytes():
    """Modern Unicode kernels (7.5x+) return DYNT atom text as
    UTF-16LE regardless of the DIAG codepage=1100 handshake.  The
    old decoder (``bytes.decode('utf-8', errors='replace')``) turned
    'SAP' into 'S\\x00A\\x00P\\x00' which the secrets-regex catalog
    planned for PR2 would miss entirely."""
    utf16 = "SAP: use client 100 user ADMIN password Welcome1".encode(
        "utf-16-le")
    out = _decode_dyn_text(utf16)
    assert out == "SAP: use client 100 user ADMIN password Welcome1"
    # No embedded NULs survived.
    assert "\x00" not in out


def test_decode_dyn_text_keeps_utf8_working():
    """Classic non-Unicode kernels return UTF-8-shaped bytes.  The
    heuristic must NOT false-positive and route them through
    UTF-16LE."""
    utf8 = "SAP banner".encode("utf-8")
    out = _decode_dyn_text(utf8)
    assert out == "SAP banner"


def test_decode_dyn_text_strips_trailing_nuls():
    """DIAG fixed-width strings are NUL-padded; strip trailing NULs
    the same way the old _to_str did."""
    assert _decode_dyn_text(b"ABCD\x00\x00\x00") == "ABCD"
    assert _decode_dyn_text("ABCD\x00".encode("utf-16-le")) == "ABCD"


def test_decode_dyn_text_tolerates_malformed_bytes():
    """The decoder must never raise — pathological byte sequences
    get ``errors='replace'`` handling on both paths so ONE bad
    atom cannot kill the whole item walk."""
    assert _decode_dyn_text(b"\xff\xfe\xfd\xfc") is not None   # UTF-8 path
    # UTF-16LE path with trailing odd byte would raise on strict
    # decode; our length-even heuristic routes it to UTF-8 so no raise.
    assert _decode_dyn_text(b"A\x00B\x00C") is not None


def test_decode_dyn_text_passes_through_non_bytes():
    """Non-bytes input is returned verbatim (callers sometimes pass
    an already-decoded string during tests / replay)."""
    assert _decode_dyn_text("already a str") == "already a str"
    assert _decode_dyn_text(None) is None


def test_decode_dyn_text_short_payload_uses_utf8():
    """A 2- or 3-byte payload has no room for the NUL-interleaved
    pattern — route to UTF-8 directly rather than guessing."""
    assert _decode_dyn_text(b"OK") == "OK"
    assert _decode_dyn_text(b"\x00\x41") != "A", (
        "A 2-byte starting-with-NUL payload must NOT be interpreted "
        "as UTF-16LE 'A' — the heuristic requires an ASCII-printable "
        "first byte")


def test_decode_dyn_text_classic_ascii_with_nul_padding_stays_utf8():
    """DIAG fixed-width fields (DBNAME, CPUNAME, etc.) are UTF-8
    ASCII padded with trailing NULs on classic non-Unicode kernels.
    The early draft of the heuristic ("NUL in first 16 bytes +
    even length + ASCII first byte") false-positived on those,
    mis-decoding b'DBNAME_VALUE\\x00\\x00' as UTF-16LE and producing
    garbage.  The fix is to check ``data[1] == 0`` — in UTF-16LE
    ASCII every odd byte is NUL (high byte of the code unit), in
    NUL-padded UTF-8 ASCII only the trailing bytes are NUL.  Pin so
    the heuristic doesn't regress."""
    assert _decode_dyn_text(b"DBNAME_VALUE\x00\x00") == "DBNAME_VALUE"
    assert _decode_dyn_text(b"HDB\x00") == "HDB"
    assert _decode_dyn_text(b"vhcala4hci\x00\x00\x00") == "vhcala4hci"
    # Also make sure a value where byte 1 happens to be NUL but the
    # rest isn't still routes through UTF-16LE correctly (real UTF-16).
    assert _decode_dyn_text(b"A\x00B\x00C\x00D\x00") == "ABCD"


# ---------------------------------------------------------------------------
# _to_str now delegates to _decode_dyn_text — so SERV_INFO rendering
# also gets the fallback (DBNAME, CPUNAME, KERNEL_VERSION, LANGUAGE).
# ---------------------------------------------------------------------------

def test_to_str_delegates_to_decode_dyn_text():
    """A Unicode-kernel ST_R3INFO/DBNAME field reaches operators via
    _to_str (not _decode_dyn_text directly) — pin that the delegation
    is wired so SERV_INFO output is correct too, not just the DYNT
    atoms behind collect_text_info."""
    utf16 = "HDB".encode("utf-16-le")
    assert _to_str(utf16) == "HDB"


# ---------------------------------------------------------------------------
# collect_text_info end-to-end — a mock DIAG items list with a UTF-16LE
# DYNT atom round-trips cleanly through the secrets-ready output.
# ---------------------------------------------------------------------------

def _build_dynt_atom(row, col, etype, field_bytes):
    """Build one minimal DYNT atom carrying field_bytes as FIELD1
    text.  Layout (from parse_dynt_atoms):
        atom_length(2) attr(2) etype(1) ...(3) row(2) col(2)
        field1_flag1(1) dlen(1) mlen(1) maxnrchars(2) text(dlen)
    """
    dlen = len(field_bytes)
    # 13-byte common header + 5-byte field1 header + text
    body = bytearray(18 + dlen)
    # atom[0:2] = atom_length (will be filled below)
    body[2:4] = b"\x00\x00"   # attr
    body[4] = etype
    # body[5:8] reserved
    body[8:10] = struct.pack("!H", row)
    body[10:12] = struct.pack("!H", col)
    # body[12] reserved
    body[13] = 0              # field1_flag1
    body[14] = dlen           # dlen
    body[15] = dlen           # mlen
    body[16:18] = struct.pack("!H", dlen)  # maxnrchars
    body[18:18 + dlen] = field_bytes
    atom_length = len(body)
    body[0:2] = struct.pack("!H", atom_length)
    return bytes(body)


def test_collect_text_info_decodes_utf16le_dynt_atom():
    """End-to-end: a DIAG items list containing a UTF-16LE DYNT atom
    text must come out as a normal Python string, with no embedded
    NULs that would break the PR2 secrets-regex scan.

    etype=121 is EFIELD_1 (in ATOM_FIELD1), routed through the
    FIELD1 branch of parse_dynt_atoms: dlen at atom[14], text at
    atom[18:18+dlen]."""
    utf16_payload = "pw=Welcome1".encode("utf-16-le")
    atom = _build_dynt_atom(row=5, col=10, etype=121,
                             field_bytes=utf16_payload)
    items = [
        (DIAG_ITEM_APPL4, DIAG_APPL_DYNT, DIAG_DYNT_ATOM, atom),
    ]
    results = collect_text_info(items)
    assert len(results) == 1
    _var, value = results[0]
    assert value == "pw=Welcome1", (
        f"UTF-16LE DYNT atom didn't decode cleanly; got {value!r}")
    assert "\x00" not in value
