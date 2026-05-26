#!/usr/bin/env python3
"""Tests for the PSE extraction primitive (commit 1 of the
MYSAPSSO2 ticket-forgery series).

Pure-Python — no live SAP needed.  Every test uses a mocked
gw_exec_fn that returns canned (program, args) -> {success, output,
error} responses.
"""
from __future__ import annotations

import base64
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "postex"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "core"))


# ===========================================================================
# A pluggable fake gw_exec_fn
# ===========================================================================

def _make_fake_gw(filesystem):
    """Build a gw_exec_fn that simulates `ls`, `base64`, `sudo`, `whoami`
    against an in-memory filesystem dict.

    filesystem = {
        "/path/dir": [list of filenames],          # for ls
        "/path/file": b"contents",                  # for base64
        "_whoami": "s4hadm",                         # whoami output
        "_sudo_files": {"/path/file": b"contents"}, # files only readable via sudo
    }
    """
    calls = []

    def gw_exec(program, args):
        calls.append((program, args))
        program = (program or "").strip()
        args = (args or "").strip()

        if program == "whoami":
            who = filesystem.get("_whoami")
            if who is None:
                return {"success": False, "output": [], "error": "no whoami"}
            return {"success": True, "output": [who], "error": ""}

        if program == "ls":
            files = filesystem.get(args)
            if files is None:
                return {"success": False,
                        "output": ["ls: cannot access '" + args
                                    + "': No such file or directory"],
                        "error": ""}
            return {"success": True, "output": files, "error": ""}

        if program == "base64":
            data = filesystem.get(args)
            if data is None:
                return {"success": True,
                        "output": ["base64: " + args + ": No such file"],
                        "error": ""}
            b64 = base64.b64encode(data).decode("ascii")
            # base64 coreutils wraps at 76 cols
            chunks = [b64[i:i + 76] for i in range(0, len(b64), 76)]
            return {"success": True, "output": chunks, "error": ""}

        if program == "sudo":
            # args is "base64 /some/path"
            if not args.startswith("base64 "):
                return {"success": False, "output": [], "error": ""}
            path = args[len("base64 "):]
            sudo_files = filesystem.get("_sudo_files", {})
            data = sudo_files.get(path) or filesystem.get(path)
            if data is None:
                return {"success": True,
                        "output": ["sudo: a password is required"],
                        "error": ""}
            b64 = base64.b64encode(data).decode("ascii")
            chunks = [b64[i:i + 76] for i in range(0, len(b64), 76)]
            return {"success": True, "output": chunks, "error": ""}

        return {"success": False, "output": [], "error": "unknown program"}

    gw_exec.calls = calls
    return gw_exec


# ===========================================================================
# SECUDIR path resolution
# ===========================================================================

def test_instance_secudir_layout():
    from sap_pse_loot import _instance_secudir
    assert _instance_secudir("S4H", "D00") == "/usr/sap/S4H/D00/sec"
    assert _instance_secudir("s4h", "D00") == "/usr/sap/S4H/D00/sec", (
        "SID must be uppercased to match /usr/sap convention")
    assert (_instance_secudir("PRD", "DVEBMGS01")
            == "/usr/sap/PRD/DVEBMGS01/sec"), (
        "Non-trivial instance dir names must pass through verbatim")


def test_global_secudir_layout():
    from sap_pse_loot import _global_secudir
    assert (_global_secudir("S4H")
            == "/usr/sap/S4H/SYS/global/security/data")


def test_candidate_secudirs_ordering():
    """Per-instance must be tried BEFORE global -- it's the layout
    that's specific to the dispatcher we have OS-exec on."""
    from sap_pse_loot import candidate_secudirs
    cands = candidate_secudirs("S4H", "D00")
    assert len(cands) == 2
    assert cands[0] == "/usr/sap/S4H/D00/sec"
    assert cands[1] == "/usr/sap/S4H/SYS/global/security/data"


# ===========================================================================
# Shell-line interpretation helpers
# ===========================================================================

@pytest.mark.parametrize("text,expected", [
    ("",                                           False),
    ("AAAAAAAAAAAAAAAA",                            False),
    ("base64: /tmp/x: No such file or directory",   True),
    ("sudo: a password is required",                True),
    ("[sudo] password for s4hadm:",                 True),
    ("Permission denied",                           True),
    ("ls: cannot open /etc/sec/SAPSYS.pse: Is a directory", True),
    ("AAAAAAAAAAcannot open foo",                   True),
])
def test_looks_like_error(text, expected):
    from sap_pse_loot import _looks_like_error
    assert _looks_like_error(text) is expected


def test_decode_b64_lines_concatenates_and_decodes():
    from sap_pse_loot import _decode_b64_lines
    original = bytes(range(256))
    b64 = base64.b64encode(original).decode("ascii")
    # Split into 76-char lines like coreutils
    lines = [b64[i:i + 76] for i in range(0, len(b64), 76)]
    decoded = _decode_b64_lines(lines)
    assert decoded == original


def test_decode_b64_lines_empty_returns_empty_bytes():
    from sap_pse_loot import _decode_b64_lines
    assert _decode_b64_lines([]) is None  # no lines = no read attempted
    assert _decode_b64_lines(["   ", ""]) == b""


def test_decode_b64_lines_garbage_returns_none():
    """Invalid base64 (e.g. picked up an error line) returns None,
    not garbage bytes."""
    from sap_pse_loot import _decode_b64_lines
    assert _decode_b64_lines(["No such file or directory"]) is None


# ===========================================================================
# _read_file_b64
# ===========================================================================

def test_read_file_b64_happy_path():
    """File exists, base64 returns clean output, no sudo retry."""
    from sap_pse_loot import _read_file_b64
    test_bytes = b"hello world\x00\x01\xff"
    gw = _make_fake_gw({"/tmp/x": test_bytes})
    r = _read_file_b64(gw, "/tmp/x")
    assert r["success"] is True
    assert r["bytes"] == test_bytes
    # Should be exactly one base64 call (no sudo retry)
    assert len([c for c in gw.calls if c[0] == "base64"]) == 1
    assert len([c for c in gw.calls if c[0] == "sudo"]) == 0


def test_read_file_b64_missing_file_returns_failure():
    from sap_pse_loot import _read_file_b64
    gw = _make_fake_gw({})
    r = _read_file_b64(gw, "/tmp/nope")
    assert r["success"] is False
    assert "No such file" in r["error"]


def test_read_file_b64_sudo_fallback():
    """Plain base64 hits 'permission denied' (we fake this by NOT
    putting the file in the filesystem dict for base64, but putting
    it in _sudo_files for sudo retrieval).  The function should
    fall back to sudo and succeed."""
    from sap_pse_loot import _read_file_b64
    test_bytes = b"hardened PSE bytes"
    gw = _make_fake_gw({
        "_sudo_files": {"/tmp/x": test_bytes},
    })
    r = _read_file_b64(gw, "/tmp/x")
    assert r["success"] is True
    assert r["bytes"] == test_bytes
    # Sudo retry must have happened
    assert any(c[0] == "sudo" for c in gw.calls)


def test_read_file_b64_disable_sudo_retry():
    """With try_sudo=False, the function gives up on the first
    failure -- used in tests / contexts where we don't want to
    invoke sudo."""
    from sap_pse_loot import _read_file_b64
    gw = _make_fake_gw({"_sudo_files": {"/tmp/x": b"abc"}})
    r = _read_file_b64(gw, "/tmp/x", try_sudo=False)
    assert r["success"] is False
    assert not any(c[0] == "sudo" for c in gw.calls)


# ===========================================================================
# _list_dir
# ===========================================================================

def test_list_dir_returns_names():
    from sap_pse_loot import _list_dir
    gw = _make_fake_gw({
        "/usr/sap/S4H/D00/sec": ["SAPSYS.pse", "cred_v2", "SAPSSLS.pse"],
    })
    files = _list_dir(gw, "/usr/sap/S4H/D00/sec")
    assert set(files) == {"SAPSYS.pse", "cred_v2", "SAPSSLS.pse"}


def test_list_dir_missing_returns_empty():
    from sap_pse_loot import _list_dir
    gw = _make_fake_gw({})
    assert _list_dir(gw, "/tmp/nope") == []


# ===========================================================================
# extract_pse_bundle — end-to-end
# ===========================================================================

def test_extract_bundle_happy_path_instance_secudir(tmp_path,
                                                       monkeypatch):
    """The canonical case: per-instance SECUDIR has both SAPSYS.pse
    and cred_v2.  Function returns both byte blobs and saves to
    loot dir."""
    # Use tmp_path as a fake PROJECT_ROOT so the loot save doesn't
    # touch the real loot directory.
    import sapmap_state
    monkeypatch.setattr(sapmap_state, "LOOT_DIR",
                        os.path.join(tmp_path, "loot"))
    pse_bytes = b"\x06\x09" + b"\x00" * 300  # fake PSE-ish blob
    cred_bytes = b"\x30\x82" + b"\x01" * 100  # fake cred_v2-ish ASN.1

    gw = _make_fake_gw({
        "_whoami": "s4hadm",
        "/usr/sap/S4H/D00/sec": ["SAPSYS.pse", "cred_v2"],
        "/usr/sap/S4H/D00/sec/SAPSYS.pse": pse_bytes,
        "/usr/sap/S4H/D00/sec/cred_v2": cred_bytes,
    })

    from sap_pse_loot import extract_pse_bundle
    r = extract_pse_bundle(gw, "S4H", instance_dir="D00",
                            label="S4H")
    assert r["success"] is True
    assert r["pse_bytes"] == pse_bytes
    assert r["cred_v2_bytes"] == cred_bytes
    assert r["secudir"] == "/usr/sap/S4H/D00/sec"
    assert r["sidadm_user"] == "s4hadm"
    assert r["error"] == ""
    # Loot saved
    assert "/loot/pse/S4H_" in r["loot_path"]
    assert os.path.exists(
        os.path.join(r["loot_path"], "SAPSYS.pse"))
    assert os.path.exists(
        os.path.join(r["loot_path"], "cred_v2"))
    with open(os.path.join(r["loot_path"], "SAPSYS.pse"), "rb") as f:
        assert f.read() == pse_bytes


def test_extract_bundle_falls_back_to_global_secudir(tmp_path,
                                                       monkeypatch):
    """When per-instance SECUDIR is empty (HA layout where the
    instance dir is a symlink that doesn't exist on this node),
    the function falls back to the global path."""
    import sapmap_state
    monkeypatch.setattr(sapmap_state, "LOOT_DIR",
                        os.path.join(tmp_path, "loot"))
    gw = _make_fake_gw({
        "_whoami": "s4hadm",
        # Per-instance: returns empty / not found
        # (no entry in the dict)
        "/usr/sap/S4H/SYS/global/security/data":
            ["SAPSYS.pse", "cred_v2"],
        "/usr/sap/S4H/SYS/global/security/data/SAPSYS.pse": b"GLOBAL",
        "/usr/sap/S4H/SYS/global/security/data/cred_v2": b"CGLOBAL",
    })
    from sap_pse_loot import extract_pse_bundle
    r = extract_pse_bundle(gw, "S4H", instance_dir="D00",
                            label="S4H", save_loot=False)
    assert r["success"] is True
    assert r["secudir"] == "/usr/sap/S4H/SYS/global/security/data"
    assert r["pse_bytes"] == b"GLOBAL"
    assert r["cred_v2_bytes"] == b"CGLOBAL"


def test_extract_bundle_no_pse_found_returns_error():
    """Neither candidate SECUDIR contains SAPSYS.pse -- typical
    non-ABAP host or a hardened install where the PSE has been
    moved.  Function returns success=False with a clear error."""
    gw = _make_fake_gw({
        "_whoami": "s4hadm",
        "/usr/sap/S4H/D00/sec": ["SAPSSLS.pse", "SAPSSLC.pse"],
        "/usr/sap/S4H/SYS/global/security/data": [],
    })
    from sap_pse_loot import extract_pse_bundle
    r = extract_pse_bundle(gw, "S4H", instance_dir="D00",
                            save_loot=False)
    assert r["success"] is False
    assert "no SECUDIR with SAPSYS.pse" in r["error"]


def test_extract_bundle_pse_without_cred_v2_still_succeeds():
    """SAPSYS.pse found but cred_v2 absent -- the function still
    returns the PSE bytes (operator can supply PIN manually).
    success=True with cred_v2_bytes=None."""
    gw = _make_fake_gw({
        "_whoami": "s4hadm",
        "/usr/sap/S4H/D00/sec": ["SAPSYS.pse"],
        "/usr/sap/S4H/D00/sec/SAPSYS.pse": b"PSE",
    })
    from sap_pse_loot import extract_pse_bundle
    r = extract_pse_bundle(gw, "S4H", instance_dir="D00",
                            save_loot=False)
    assert r["success"] is True
    assert r["pse_bytes"] == b"PSE"
    assert r["cred_v2_bytes"] is None


def test_extract_bundle_records_other_files():
    """Non-SAPSYS / non-cred files in SECUDIR are surfaced as
    `other_files` so the operator can spot unusual PSE names
    (e.g. SAPSYS_ABAP.pse, SAPSYS_PROD.pse).  Out of scope for
    automatic retrieval but visible."""
    gw = _make_fake_gw({
        "_whoami": "s4hadm",
        "/usr/sap/S4H/D00/sec": ["SAPSYS.pse", "cred_v2",
                                   "SAPSSLS.pse", "SAPSSLC.pse",
                                   "weird_custom.pse"],
        "/usr/sap/S4H/D00/sec/SAPSYS.pse": b"PSE",
        "/usr/sap/S4H/D00/sec/cred_v2": b"CR",
    })
    from sap_pse_loot import extract_pse_bundle
    r = extract_pse_bundle(gw, "S4H", instance_dir="D00",
                            save_loot=False)
    assert r["success"] is True
    assert "weird_custom.pse" in r["other_files"]
    assert "SAPSSLS.pse" in r["other_files"]
    assert "SAPSYS.pse" not in r["other_files"]


def test_extract_bundle_explicit_secudir_override():
    """Caller can pass secudir=... to skip auto-discovery -- useful
    when the operator knows the install uses a non-standard layout."""
    gw = _make_fake_gw({
        "_whoami": "s4hadm",
        "/opt/sap/sec": ["SAPSYS.pse", "cred_v2"],
        "/opt/sap/sec/SAPSYS.pse": b"P",
        "/opt/sap/sec/cred_v2": b"C",
    })
    from sap_pse_loot import extract_pse_bundle
    r = extract_pse_bundle(gw, "S4H", instance_dir="D00",
                            secudir="/opt/sap/sec", save_loot=False)
    assert r["success"] is True
    assert r["secudir"] == "/opt/sap/sec"
    # Standard paths must NOT have been queried -- explicit override
    ls_calls = [c for c in gw.calls if c[0] == "ls"]
    paths = [c[1] for c in ls_calls]
    assert "/usr/sap/S4H/D00/sec" not in paths


def test_extract_bundle_whoami_failure_falls_back():
    """When whoami fails entirely, the function uses the
    `<sid>adm` convention as a fallback -- this is required for
    cred_v2 decryption in commit 2 (the OS user name is part of
    the key-derivation input)."""
    gw = _make_fake_gw({
        # _whoami absent -- whoami returns failure
        "/usr/sap/S4H/D00/sec": ["SAPSYS.pse"],
        "/usr/sap/S4H/D00/sec/SAPSYS.pse": b"P",
    })
    from sap_pse_loot import extract_pse_bundle
    r = extract_pse_bundle(gw, "S4H", instance_dir="D00",
                            save_loot=False)
    assert r["sidadm_user"] == "s4hadm"


def test_extract_bundle_uppercases_sid_in_paths():
    """Lowercase sid arg must still match the uppercase
    /usr/sap/<SID>/ convention."""
    gw = _make_fake_gw({
        "_whoami": "s4hadm",
        "/usr/sap/S4H/D00/sec": ["SAPSYS.pse"],
        "/usr/sap/S4H/D00/sec/SAPSYS.pse": b"P",
    })
    from sap_pse_loot import extract_pse_bundle
    r = extract_pse_bundle(gw, "s4h", instance_dir="D00",
                            save_loot=False)
    assert r["success"] is True
    assert "/usr/sap/S4H/" in r["secudir"]


# ===========================================================================
# Loot dir handling
# ===========================================================================

def test_save_to_loot_creates_meta_file(tmp_path, monkeypatch):
    """The _save_to_loot helper writes a _meta.txt with provenance
    info -- so the operator (or a later SAPMAP run) can see where
    the bytes came from."""
    import sapmap_state
    monkeypatch.setattr(sapmap_state, "LOOT_DIR",
                        os.path.join(tmp_path, "loot"))
    from sap_pse_loot import _save_to_loot
    bundle = {
        "pse_bytes": b"PSE_DATA",
        "cred_v2_bytes": b"CRED_DATA",
        "secudir": "/usr/sap/S4H/D00/sec",
        "sidadm_user": "s4hadm",
        "other_files": ["SAPSSLS.pse", "SAPSSLC.pse"],
    }
    r = _save_to_loot(bundle, "S4H")
    assert r["saved"] is True
    meta_path = os.path.join(r["loot_path"], "_meta.txt")
    assert os.path.exists(meta_path)
    with open(meta_path) as f:
        meta = f.read()
    assert "S4H" in meta
    assert "s4hadm" in meta
    assert "/usr/sap/S4H/D00/sec" in meta
    assert "SAPSSLS.pse" in meta  # other_files surfaced


# ===================================================================
# cred_v2 decryption tests (commit 2)
# ===================================================================

# ---------------------------------------------------------------------------
# BER parser / builder
# ---------------------------------------------------------------------------

class TestBerParser:
    """Minimal BER encoder / decoder round-trips."""

    def test_ber_tlv_short_length(self):
        from sap_pse_loot import _ber_tlv, _ber_read_tl
        # IA5String "hello"
        data = _ber_tlv(0x16, b"hello")
        assert data == b"\x16\x05hello"
        tag, voff, vlen, nxt = _ber_read_tl(data, 0)
        assert tag == 0x16
        assert data[voff:voff + vlen] == b"hello"
        assert nxt == len(data)

    def test_ber_tlv_long_length(self):
        from sap_pse_loot import _ber_tlv, _ber_read_tl
        # 200-byte value
        payload = b"\xAA" * 200
        data = _ber_tlv(0x04, payload)
        assert data[0] == 0x04
        assert data[1] == 0x81  # long-form: 1 length byte
        assert data[2] == 200
        tag, voff, vlen, nxt = _ber_read_tl(data, 0)
        assert tag == 0x04
        assert vlen == 200
        assert data[voff:voff + vlen] == payload

    def test_ber_sequence_children(self):
        from sap_pse_loot import (_ber_tlv, _ber_read_tl,
                                   _ber_children,
                                   _BER_SEQUENCE, _BER_IA5STRING)
        inner = (_ber_tlv(_BER_IA5STRING, b"one") +
                 _ber_tlv(_BER_IA5STRING, b"two"))
        seq = _ber_tlv(_BER_SEQUENCE, inner)
        tag, voff, vlen, nxt = _ber_read_tl(seq, 0)
        assert tag == _BER_SEQUENCE
        kids = list(_ber_children(seq, voff, voff + vlen))
        assert len(kids) == 2
        assert kids[0] == (_BER_IA5STRING, b"one")
        assert kids[1] == (_BER_IA5STRING, b"two")

    def test_ber_read_tl_truncated(self):
        from sap_pse_loot import _ber_read_tl
        with pytest.raises(ValueError, match="past end"):
            _ber_read_tl(b"", 0)
        with pytest.raises(ValueError, match="truncated"):
            _ber_read_tl(b"\x30", 0)

    def test_ber_read_tl_indefinite_rejected(self):
        from sap_pse_loot import _ber_read_tl
        with pytest.raises(ValueError, match="indefinite"):
            _ber_read_tl(b"\x30\x80", 0)


# ---------------------------------------------------------------------------
# LCG XOR stream
# ---------------------------------------------------------------------------

class TestLcgXor:

    def test_lcg_xor_deterministic(self):
        from sap_pse_loot import _lcg_xor
        data = b"hello"
        r1 = _lcg_xor(data, 42)
        r2 = _lcg_xor(data, 42)
        assert r1 == r2, "same seed must produce same output"

    def test_lcg_xor_different_seeds(self):
        from sap_pse_loot import _lcg_xor
        data = b"hello"
        r1 = _lcg_xor(data, 0)
        r2 = _lcg_xor(data, 1)
        assert r1 != r2, "different seeds must differ"

    def test_lcg_xor_round_trip(self):
        """XOR is involutory with the same seed."""
        from sap_pse_loot import _lcg_xor
        data = b"the quick brown fox"
        seed = 0x12345678
        encrypted = _lcg_xor(data, seed)
        assert encrypted != data
        decrypted = _lcg_xor(encrypted, seed)
        assert decrypted == data

    def test_lcg_xor_empty(self):
        from sap_pse_loot import _lcg_xor
        assert _lcg_xor(b"", 99) == b""

    def test_lcg_xor_known_vector(self):
        """Verify the LCG constants produce a predictable first byte.
        LCG: state = (seed * 0x15A4E35 + 1) & 0xFFFFFFFF
        seed=0: state = 1, output_byte = 1, xor(0x41, 0x01) = 0x40."""
        from sap_pse_loot import _lcg_xor
        result = _lcg_xor(b"\x41", 0)
        assert result == bytes([0x41 ^ 0x01])


# ---------------------------------------------------------------------------
# cred_v2 envelope parsing
# ---------------------------------------------------------------------------

class TestCredV2Envelope:

    def test_parse_single_nonlps_record(self):
        from sap_pse_loot import (_ber_tlv, _BER_SEQUENCE,
                                   _BER_IA5STRING, _BER_BITSTRING,
                                   _parse_cred_v2_envelope)
        cipher = b"\xDE\xAD\xBE\xEF"
        record = _ber_tlv(_BER_SEQUENCE, b"".join([
            _ber_tlv(_BER_IA5STRING, b"CN=S4H"),
            _ber_tlv(_BER_IA5STRING, b""),
            _ber_tlv(_BER_IA5STRING,
                     b"/usr/sap/S4H/D00/sec/SAPSYS.pse"),
            _ber_tlv(_BER_IA5STRING, b""),
            _ber_tlv(_BER_BITSTRING, b"\x00" + cipher),
        ]))
        blob = _ber_tlv(_BER_SEQUENCE, record)
        records = _parse_cred_v2_envelope(blob)
        assert len(records) == 1
        assert records[0].pse_path == \
            "/usr/sap/S4H/D00/sec/SAPSYS.pse"
        assert records[0].cipher_bytes == cipher
        assert records[0].is_lps is False

    def test_parse_multiple_records(self):
        from sap_pse_loot import (_ber_tlv, _BER_SEQUENCE,
                                   _BER_IA5STRING, _BER_BITSTRING,
                                   _parse_cred_v2_envelope)

        def _make_rec(path, cipher):
            return _ber_tlv(_BER_SEQUENCE, b"".join([
                _ber_tlv(_BER_IA5STRING, b"CN=test"),
                _ber_tlv(_BER_IA5STRING, b""),
                _ber_tlv(_BER_IA5STRING, path.encode("ascii")),
                _ber_tlv(_BER_IA5STRING, b""),
                _ber_tlv(_BER_BITSTRING, b"\x00" + cipher),
            ]))

        blob = _ber_tlv(_BER_SEQUENCE,
                        _make_rec("/pse1", b"\x01") +
                        _make_rec("/pse2", b"\x02"))
        records = _parse_cred_v2_envelope(blob)
        assert len(records) == 2
        assert records[0].pse_path == "/pse1"
        assert records[1].pse_path == "/pse2"

    def test_parse_lps_record_detected(self):
        from sap_pse_loot import (_ber_tlv, _BER_SEQUENCE,
                                   _BER_INTEGER, _BER_UTF8STRING,
                                   _BER_BITSTRING,
                                   _parse_cred_v2_envelope)
        # LPS: first child is INTEGER(2)
        record = _ber_tlv(_BER_SEQUENCE, b"".join([
            _ber_tlv(_BER_INTEGER, b"\x02"),
            _ber_tlv(_BER_SEQUENCE, b""),  # subject RDN
            _ber_tlv(_BER_UTF8STRING,
                     b"/usr/sap/S4H/D00/sec/SAPSYS.pse"),
            _ber_tlv(_BER_BITSTRING, b"\x00\xFF"),
        ]))
        blob = _ber_tlv(_BER_SEQUENCE, record)
        records = _parse_cred_v2_envelope(blob)
        assert len(records) == 1
        assert records[0].is_lps is True
        assert records[0].pse_path == \
            "/usr/sap/S4H/D00/sec/SAPSYS.pse"

    def test_parse_empty_sequence(self):
        from sap_pse_loot import (_ber_tlv, _BER_SEQUENCE,
                                   _parse_cred_v2_envelope)
        blob = _ber_tlv(_BER_SEQUENCE, b"")
        records = _parse_cred_v2_envelope(blob)
        assert records == []

    def test_parse_invalid_outer_tag(self):
        from sap_pse_loot import _parse_cred_v2_envelope
        with pytest.raises(ValueError, match="expected outer SEQUENCE"):
            _parse_cred_v2_envelope(b"\x16\x03abc")


# ---------------------------------------------------------------------------
# Round-trip decrypt: build → decrypt → verify PIN
# ---------------------------------------------------------------------------

class TestCredV2Decrypt:

    def test_round_trip_3des(self):
        """Build a synthetic cred_v2 with 3DES, decrypt it, verify PIN."""
        from sap_pse_loot import (_build_cred_v2_blob,
                                   decrypt_cred_v2)
        pin = "MySecretPIN123"
        pse_path = "/usr/sap/S4H/D00/sec/SAPSYS.pse"
        username = "s4hadm"
        blob = _build_cred_v2_blob(pin, pse_path, username,
                                    algo=0)
        r = decrypt_cred_v2(blob, username)
        assert r["success"] is True, f"decrypt failed: {r['error']}"
        assert r["pin"] == pin
        assert r["pse_path"] == pse_path

    def test_round_trip_aes256(self):
        """Build a synthetic cred_v2 with AES-256, decrypt, verify."""
        from sap_pse_loot import (_build_cred_v2_blob,
                                   decrypt_cred_v2)
        pin = "AES-256-test-pin!"
        pse_path = "/usr/sap/PRD/DVEBMGS01/sec/SAPSYS.pse"
        username = "prdadm"
        blob = _build_cred_v2_blob(pin, pse_path, username,
                                    algo=1)
        r = decrypt_cred_v2(blob, username)
        assert r["success"] is True, f"decrypt failed: {r['error']}"
        assert r["pin"] == pin

    def test_round_trip_fixed_salt_iv(self):
        """Deterministic: same salt+IV produce same ciphertext."""
        from sap_pse_loot import (_build_cred_v2_blob,
                                   decrypt_cred_v2)
        salt = b"\x01" * 16
        iv = b"\x02" * 16
        blob1 = _build_cred_v2_blob("pin1", "/pse", "user",
                                     algo=0, salt=salt, iv=iv)
        blob2 = _build_cred_v2_blob("pin1", "/pse", "user",
                                     algo=0, salt=salt, iv=iv)
        assert blob1 == blob2

    def test_different_usernames_produce_different_results(self):
        """Key derivation depends on the username — wrong user fails."""
        from sap_pse_loot import (_build_cred_v2_blob,
                                   decrypt_cred_v2)
        pin = "RightPin"
        blob = _build_cred_v2_blob(pin, "/pse", "s4hadm",
                                    algo=0)
        # Correct username recovers PIN
        r = decrypt_cred_v2(blob, "s4hadm")
        assert r["success"] is True
        assert r["pin"] == pin
        # Wrong username: either fails or returns garbage
        r2 = decrypt_cred_v2(blob, "prdadm")
        assert not r2["success"] or r2["pin"] != pin

    def test_pse_path_filter(self):
        """When pse_path is given, only matching record is tried."""
        from sap_pse_loot import (_build_cred_v2_blob,
                                   decrypt_cred_v2,
                                   _ber_tlv, _BER_SEQUENCE,
                                   _BER_IA5STRING, _BER_BITSTRING)
        # Build blob with path="/usr/sap/S4H/..."
        pin = "FilterMe"
        blob = _build_cred_v2_blob(
            pin, "/usr/sap/S4H/D00/sec/SAPSYS.pse", "s4hadm")
        # Matching filter → success
        r = decrypt_cred_v2(
            blob, "s4hadm",
            pse_path="/usr/sap/S4H/D00/sec/SAPSYS.pse")
        assert r["success"] is True
        # Non-matching filter → fails
        r2 = decrypt_cred_v2(
            blob, "s4hadm",
            pse_path="/usr/sap/PRD/D00/sec/SAPSYS.pse")
        assert r2["success"] is False
        assert "no credential matching path" in r2["error"]

    def test_empty_blob_returns_error(self):
        from sap_pse_loot import decrypt_cred_v2
        r = decrypt_cred_v2(b"", "s4hadm")
        assert r["success"] is False
        assert "empty" in r["error"]

    def test_garbage_blob_returns_error(self):
        from sap_pse_loot import decrypt_cred_v2
        r = decrypt_cred_v2(b"\xff\xff\xff", "s4hadm")
        assert r["success"] is False
        assert r["error"]  # some error message present

    def test_lps_only_returns_unsupported_error(self):
        """File with only LPS credentials → clear error message."""
        from sap_pse_loot import (_ber_tlv, _BER_SEQUENCE,
                                   _BER_INTEGER, _BER_UTF8STRING,
                                   _BER_BITSTRING,
                                   decrypt_cred_v2)
        record = _ber_tlv(_BER_SEQUENCE, b"".join([
            _ber_tlv(_BER_INTEGER, b"\x02"),
            _ber_tlv(_BER_SEQUENCE, b""),
            _ber_tlv(_BER_UTF8STRING,
                     b"/usr/sap/S4H/D00/sec/SAPSYS.pse"),
            _ber_tlv(_BER_BITSTRING, b"\x00\xFF\xFE"),
        ]))
        blob = _ber_tlv(_BER_SEQUENCE, record)
        r = decrypt_cred_v2(blob, "s4hadm")
        assert r["success"] is False
        assert "LPS" in r["error"]

    def test_credentials_list_populated(self):
        """The credentials list describes all records in the file."""
        from sap_pse_loot import (_build_cred_v2_blob,
                                   decrypt_cred_v2)
        blob = _build_cred_v2_blob(
            "pin", "/usr/sap/S4H/D00/sec/SAPSYS.pse",
            "s4hadm")
        r = decrypt_cred_v2(blob, "s4hadm")
        assert len(r["credentials"]) == 1
        cred = r["credentials"][0]
        assert cred["pse_path"] == \
            "/usr/sap/S4H/D00/sec/SAPSYS.pse"
        assert cred["cipher_len"] > 0
        assert cred["is_lps"] is False

    def test_round_trip_long_pin(self):
        """PINs can be up to ~128 chars on modern kernels."""
        from sap_pse_loot import (_build_cred_v2_blob,
                                   decrypt_cred_v2)
        pin = "A" * 100
        blob = _build_cred_v2_blob(pin, "/pse", "s4hadm",
                                    algo=1)
        r = decrypt_cred_v2(blob, "s4hadm")
        assert r["success"] is True
        assert r["pin"] == pin

    def test_round_trip_special_chars_in_pin(self):
        """PINs with special ASCII chars survive the round-trip."""
        from sap_pse_loot import (_build_cred_v2_blob,
                                   decrypt_cred_v2)
        pin = "P@$$w0rd!#%^&*()_+-=[]{}|"
        blob = _build_cred_v2_blob(pin, "/pse", "s4hadm",
                                    algo=0)
        r = decrypt_cred_v2(blob, "s4hadm")
        assert r["success"] is True
        assert r["pin"] == pin


# ---------------------------------------------------------------------------
# PIN extraction from plaintext
# ---------------------------------------------------------------------------

class TestPinExtraction:

    def test_ber_wrapped_pin(self):
        from sap_pse_loot import (_ber_tlv, _BER_SEQUENCE,
                                   _BER_IA5STRING,
                                   _extract_pin_from_plaintext)
        plain = _ber_tlv(_BER_SEQUENCE,
                         _ber_tlv(_BER_IA5STRING, b"mypin"))
        assert _extract_pin_from_plaintext(plain) == "mypin"

    def test_ber_wrapped_pin_with_nul_padding(self):
        from sap_pse_loot import (_ber_tlv, _BER_SEQUENCE,
                                   _BER_IA5STRING,
                                   _extract_pin_from_plaintext)
        plain = _ber_tlv(_BER_SEQUENCE,
                         _ber_tlv(_BER_IA5STRING,
                                  b"mypin\x00\x00"))
        assert _extract_pin_from_plaintext(plain) == "mypin"

    def test_fallback_printable_extraction(self):
        """Non-BER plaintext: first printable run is returned."""
        from sap_pse_loot import _extract_pin_from_plaintext
        plain = b"\x00\x01plainpin\x00\xFF"
        assert _extract_pin_from_plaintext(plain) == "plainpin"

    def test_empty_plaintext(self):
        from sap_pse_loot import _extract_pin_from_plaintext
        assert _extract_pin_from_plaintext(b"") == ""


# ===================================================================
# PSE signing-key extractor tests (commit 3)
# ===================================================================

# Helper: generate a self-signed RSA key + cert for testing

def _generate_test_key_and_cert():
    """Generate a 2048-bit RSA key + self-signed X.509 cert.

    Returns (private_key, cert, key_der, cert_der).
    """
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048)
    key_der = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                           "SAP Trust Community"),
        x509.NameAttribute(NameOID.COMMON_NAME,
                           "CN=S4H, OU=I0019604999, "
                           "O=SAP Trust Community, C=DE"),
    ])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    return key, cert, key_der, cert_der


# ---------------------------------------------------------------------------
# OID encoding / decoding
# ---------------------------------------------------------------------------

class TestOidCodec:

    def test_round_trip_simple_oid(self):
        from sap_pse_loot import _ber_encode_oid, _ber_decode_oid
        oid = "1.2.3.4"
        encoded = _ber_encode_oid(oid)
        assert _ber_decode_oid(encoded) == oid

    def test_round_trip_pbe1_oid(self):
        from sap_pse_loot import _ber_encode_oid, _ber_decode_oid
        oid = "1.2.840.113549.1.12.1.3"
        encoded = _ber_encode_oid(oid)
        assert _ber_decode_oid(encoded) == oid

    def test_round_trip_teletrust_oids(self):
        from sap_pse_loot import _ber_encode_oid, _ber_decode_oid
        for oid in ["1.3.36.2.3.1", "1.3.36.2.3.4",
                     "1.3.36.2.1.1", "1.3.36.2.1.3"]:
            encoded = _ber_encode_oid(oid)
            assert _ber_decode_oid(encoded) == oid, \
                f"round-trip failed for {oid}"

    def test_encode_oid_large_component(self):
        """Components > 127 use base-128 varint encoding."""
        from sap_pse_loot import _ber_encode_oid, _ber_decode_oid
        oid = "1.2.840.113549"
        encoded = _ber_encode_oid(oid)
        assert _ber_decode_oid(encoded) == oid
        # 840 and 113549 both require multi-byte encoding
        assert len(encoded) > 4


# ---------------------------------------------------------------------------
# PKCS#12 PBKDF1
# ---------------------------------------------------------------------------

class TestPkcs12Pbkdf1:

    def test_password_encoding(self):
        from sap_pse_loot import _pkcs12_password
        # Empty → just NUL-NUL
        assert _pkcs12_password("") == b"\x00\x00"
        # ASCII → UTF-16BE + NUL-NUL
        p = _pkcs12_password("abc")
        assert p == b"\x00a\x00b\x00c\x00\x00"

    def test_pbkdf1_deterministic(self):
        from sap_pse_loot import _pkcs12_pbkdf1, _pkcs12_password
        pwd = _pkcs12_password("test")
        salt = b"\x01" * 8
        k1 = _pkcs12_pbkdf1(pwd, salt, 2048, 1, 24)
        k2 = _pkcs12_pbkdf1(pwd, salt, 2048, 1, 24)
        assert k1 == k2
        assert len(k1) == 24

    def test_different_passwords_different_keys(self):
        from sap_pse_loot import _pkcs12_pbkdf1, _pkcs12_password
        salt = b"\x02" * 8
        k1 = _pkcs12_pbkdf1(_pkcs12_password("abc"), salt,
                             2048, 1, 24)
        k2 = _pkcs12_pbkdf1(_pkcs12_password("xyz"), salt,
                             2048, 1, 24)
        assert k1 != k2

    def test_key_vs_iv_derivation_differ(self):
        from sap_pse_loot import _pkcs12_pbkdf1, _pkcs12_password
        pwd = _pkcs12_password("test")
        salt = b"\x03" * 8
        key = _pkcs12_pbkdf1(pwd, salt, 2048, 1, 24)
        iv = _pkcs12_pbkdf1(pwd, salt, 2048, 2, 8)
        # Key (24B) and IV (8B) must not be the same prefix
        assert key[:8] != iv


# ---------------------------------------------------------------------------
# PSE build → extract round-trip
# ---------------------------------------------------------------------------

class TestExtractSigningKey:

    def test_round_trip_rsa(self):
        """Build a synthetic PSE, extract key + cert, verify match."""
        from sap_pse_loot import (_build_test_pse,
                                   extract_signing_key)
        key, cert, key_der, cert_der = _generate_test_key_and_cert()

        pin = "TestPIN123"
        pse = _build_test_pse(key_der, cert_der, pin)
        assert len(pse) > 100  # sanity

        r = extract_signing_key(pse, pin)
        assert r["success"] is True, f"failed: {r['error']}"
        assert r["key_type"] == "RSA"
        assert r["key_size"] == 2048
        assert r["private_key"] is not None
        assert r["certificate"] is not None
        # Verify the extracted key matches the original
        from cryptography.hazmat.primitives import serialization
        extracted_der = r["private_key"].private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        assert extracted_der == key_der
        # Verify cert match
        extracted_cert_der = r["certificate"].public_bytes(
            serialization.Encoding.DER)
        assert extracted_cert_der == cert_der

    def test_subject_dn_populated(self):
        from sap_pse_loot import (_build_test_pse,
                                   extract_signing_key)
        _, cert, key_der, cert_der = _generate_test_key_and_cert()

        r = extract_signing_key(
            _build_test_pse(key_der, cert_der, "pin"), "pin")
        assert r["success"] is True
        assert r["subject_dn"]  # non-empty
        assert r["issuer_dn"]   # non-empty
        assert r["serial_number"] > 0

    def test_wrong_pin_fails(self):
        from sap_pse_loot import (_build_test_pse,
                                   extract_signing_key)
        _, _, key_der, cert_der = _generate_test_key_and_cert()
        pse = _build_test_pse(key_der, cert_der, "correct")
        r = extract_signing_key(pse, "wrong")
        assert r["success"] is False

    def test_empty_pse_returns_error(self):
        from sap_pse_loot import extract_signing_key
        r = extract_signing_key(b"", "pin")
        assert r["success"] is False
        assert "empty" in r["error"]

    def test_garbage_pse_returns_error(self):
        from sap_pse_loot import extract_signing_key
        r = extract_signing_key(b"\xff\xfe\xfd", "pin")
        assert r["success"] is False

    def test_objects_list_populated(self):
        from sap_pse_loot import (_build_test_pse,
                                   extract_signing_key)
        _, _, key_der, cert_der = _generate_test_key_and_cert()
        r = extract_signing_key(
            _build_test_pse(key_der, cert_der, "pin"), "pin")
        assert r["success"] is True
        names = [o["name"] for o in r["objects"]]
        assert "SKnew" in names
        assert "SignCert" in names

    def test_different_salt_produces_different_pse(self):
        from sap_pse_loot import (_build_test_pse,
                                   extract_signing_key)
        _, _, key_der, cert_der = _generate_test_key_and_cert()
        pse1 = _build_test_pse(key_der, cert_der, "pin",
                                salt=b"\x01" * 8)
        pse2 = _build_test_pse(key_der, cert_der, "pin",
                                salt=b"\x02" * 8)
        assert pse1 != pse2
        # Both decrypt successfully
        r1 = extract_signing_key(pse1, "pin")
        r2 = extract_signing_key(pse2, "pin")
        assert r1["success"] is True
        assert r2["success"] is True

    def test_high_iteration_count(self):
        """Higher iterations slow derivation but must still work."""
        from sap_pse_loot import (_build_test_pse,
                                   extract_signing_key)
        _, _, key_der, cert_der = _generate_test_key_and_cert()
        pse = _build_test_pse(key_der, cert_der, "pin",
                               iterations=10000)
        r = extract_signing_key(pse, "pin")
        assert r["success"] is True
