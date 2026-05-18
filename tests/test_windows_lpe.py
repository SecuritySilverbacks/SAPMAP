#!/usr/bin/env python3
"""Tests for the Windows LPE auto-picker + MiniPlasma prereq probe.

All offline; SAPXPG calls and the MiniPlasma binary blob are mocked.
"""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest


# ===========================================================================
# Helpers
# ===========================================================================

def _node(os_type="Windows Server 2019"):
    from sapmap_models import SAPNode
    return SAPNode(sid="WIN", ip="10.0.0.2", hostname="winhost",
                   system_type="ABAP", os_type=os_type)


def _exec_gw_canned(map_in_out):
    """Build a fake execute_gw_command that pattern-matches (prog, params)
    pairs.  Match by substring on params so we don't have to know the
    exact /C flag ordering.  IMPORTANT: keys must be discriminating
    enough that they don't accidentally substring-match unrelated
    probes (e.g. "ver" appears inside "drivers"); use full distinguishing
    fragments like "/C ver" / "cldflt.sys" / "Release".
    """
    def _fake(node, prog, params, long_params=""):
        for (p, a), out in map_in_out.items():
            if prog == p and (a is None or a in params):
                return {"output": out, "success": True}
        return {"output": [], "success": True}
    return _fake


# ===========================================================================
# OS version parser
# ===========================================================================

@pytest.mark.parametrize("text,expected_build,expected_has_cldflt", [
    # Win10 22H2 — fully in scope
    ("Microsoft Windows [Version 10.0.19045.3803]", 19045, True),
    # Server 2022 — fully in scope
    ("Microsoft Windows [Version 10.0.20348.2031]", 20348, True),
    # Win10 1709 — first build with cldflt.sys (boundary)
    ("Microsoft Windows [Version 10.0.16299.1]",   16299, True),
    # Win10 1703 — one build below, no cldflt
    ("Microsoft Windows [Version 10.0.15063.2046]", 15063, False),
    # Server 2012 R2 — way too old, no cldflt
    ("Microsoft Windows [Version 6.3.9600]",        9600,  False),
    # Win11 24H2
    ("Microsoft Windows [Version 10.0.26100.1742]", 26100, True),
])
def test_parse_ver_output(text, expected_build, expected_has_cldflt):
    from sapmap_miniplasma import _parse_ver_output
    out = _parse_ver_output(text)
    assert out["build"] == expected_build
    assert out["has_cldflt"] == expected_has_cldflt


def test_parse_ver_output_returns_zeroes_on_garbage():
    from sapmap_miniplasma import _parse_ver_output
    out = _parse_ver_output("")
    assert out["build"] == 0
    assert out["has_cldflt"] is False
    out = _parse_ver_output("not-a-windows-banner")
    assert out["build"] == 0


# ===========================================================================
# .NET Release parser
# ===========================================================================

@pytest.mark.parametrize("text,expected_release,expected_version,expected_ok", [
    # 4.8 on Win10 1903+
    ("    Release    REG_DWORD    0x80ed8", 528_088, "4.8", True),
    # 4.7.2 boundary — below threshold returns satisfied=False
    ("    Release    REG_DWORD    0x70b70", 461_680, "4.7", False),  # 4.7 — below 4.7.2
    ("    Release    REG_DWORD    0x70bb0", 461_744, "4.7", False),  # 4.7 still
    ("    Release    REG_DWORD    0x70bf0", 461_808, "4.7.2", True), # 4.7.2 exact
    # 4.6.2 (Win10 1607)
    ("    Release    REG_DWORD    0x60632", 394_802, "4.6.2", False),
    # 4.8.1 (Win11 22H2)
    ("    Release    REG_DWORD    0x82348", 533_320, "4.8.1+", True),
])
def test_parse_net_release(text, expected_release, expected_version, expected_ok):
    from sapmap_miniplasma import _parse_net_release
    out = _parse_net_release(text)
    assert out["release"] == expected_release
    assert out["version"] == expected_version
    assert out["satisfied"] == expected_ok


def test_parse_net_release_empty_input_returns_zeroes():
    from sapmap_miniplasma import _parse_net_release
    out = _parse_net_release("")
    assert out["release"] == 0
    assert out["satisfied"] is False


# ===========================================================================
# certutil -encode output decoder
# ===========================================================================

def test_decode_certutil_b64_strips_pem_wrappers():
    from sapmap_miniplasma import _decode_certutil_b64
    body = (
        "-----BEGIN CERTIFICATE-----\r\n"
        "SGVsbG8gV29ybGQ=\r\n"   # "Hello World"
        "-----END CERTIFICATE-----\r\n"
    )
    assert _decode_certutil_b64(body) == b"Hello World"


def test_decode_certutil_b64_handles_multiline_b64():
    """certutil wraps base64 at 64 chars — the decoder must join lines."""
    from sapmap_miniplasma import _decode_certutil_b64
    body = (
        "-----BEGIN CERTIFICATE-----\r\n"
        "SGVsbG8gV29ybGQsIHRoaXMgaXMgYSBsb25nZXIgcGF5\r\n"
        "bG9hZCB0aGF0IHdyYXBzIGFjcm9zcyBsaW5lcw==\r\n"
        "-----END CERTIFICATE-----\r\n"
    )
    out = _decode_certutil_b64(body)
    assert out == b"Hello World, this is a longer payload that wraps across lines"


def test_decode_certutil_b64_returns_none_on_garbage():
    from sapmap_miniplasma import _decode_certutil_b64
    assert _decode_certutil_b64("") is None
    assert _decode_certutil_b64("no-begin-marker SGVsbG8=") is None


# ===========================================================================
# Base64 chunker
# ===========================================================================

def test_chunk_b64_splits_below_cmd_limit():
    """cmd.exe caps the command line at 8191 chars.  Each chunk must
    fit comfortably below that even after we wrap it in the
    `cmd.exe /C echo CHUNK >> FILE` invocation."""
    from sapmap_miniplasma import _chunk_b64
    payload = b"X" * 20_000
    chunks = _chunk_b64(payload, chunk_size=6000)
    assert all(len(c) <= 6000 for c in chunks)
    # All chunks reassembled must round-trip
    import base64
    rebuilt = base64.b64decode("".join(chunks))
    assert rebuilt == payload


def test_chunk_b64_handles_small_payload():
    from sapmap_miniplasma import _chunk_b64
    chunks = _chunk_b64(b"abc")
    assert len(chunks) == 1
    import base64
    assert base64.b64decode(chunks[0]) == b"abc"


# ===========================================================================
# MiniPlasma viability check
# ===========================================================================

def test_miniplasma_linux_short_circuits_with_reason():
    """Linux hosts must early-exit without firing SAPXPG."""
    from sapmap_miniplasma import check_miniplasma
    with patch("sapmap_exploit.execute_gw_command") as gw:
        out = check_miniplasma(_node(os_type="Linux"))
    assert out["vulnerable"] is False
    assert "Windows" in out["reason"]
    gw.assert_not_called()


def test_miniplasma_unknown_os_proceeds_to_probe():
    """When os_type is empty/unknown, the check must still attempt the
    cmd /C ver probe.  If it returns nothing, we report 'not Windows'."""
    from sapmap_miniplasma import check_miniplasma
    fake = _exec_gw_canned({("cmd.exe", "/C ver"): []})
    with patch("sapmap_exploit.execute_gw_command", side_effect=fake):
        out = check_miniplasma(_node(os_type=""))
    assert out["vulnerable"] is False
    assert "ver" in out["reason"] or "Windows" in out["reason"]


def test_miniplasma_old_windows_below_cldflt_threshold():
    """Win10 1703 (build 15063) — no cldflt.sys, must fail viability."""
    from sapmap_miniplasma import check_miniplasma
    fake = _exec_gw_canned({
        ("cmd.exe", "/C ver"): ["Microsoft Windows [Version 10.0.15063.2046]"],
    })
    with patch("sapmap_exploit.execute_gw_command", side_effect=fake):
        out = check_miniplasma(_node(os_type="Windows 10"))
    assert out["vulnerable"] is False
    assert out["has_cldflt"] is False
    assert "16299" in out["reason"]


def test_miniplasma_missing_cldflt_driver_fails():
    """Build is high enough, but operator stripped cldflt.sys from
    the image (rare hardening)."""
    from sapmap_miniplasma import check_miniplasma
    fake = _exec_gw_canned({
        ("cmd.exe", "/C ver"):    ["Microsoft Windows [Version 10.0.19045.3803]"],
        ("cmd.exe", "cldflt.sys"): ["File Not Found"],   # dir returned empty
    })
    with patch("sapmap_exploit.execute_gw_command", side_effect=fake):
        out = check_miniplasma(_node())
    assert out["vulnerable"] is False
    assert out["has_cldflt"] is False
    assert "cldflt.sys not found" in out["reason"]


def test_miniplasma_net_below_472_fails():
    """Win10 1607 ships with .NET 4.6.x — too old."""
    from sapmap_miniplasma import check_miniplasma
    fake = _exec_gw_canned({
        ("cmd.exe", "/C ver"):    ["Microsoft Windows [Version 10.0.19045.3803]"],
        ("cmd.exe", "cldflt.sys"): ["cldflt.sys"],
        ("cmd.exe", "Release"): ["    Release    REG_DWORD    0x60632"],
    })
    with patch("sapmap_exploit.execute_gw_command", side_effect=fake):
        out = check_miniplasma(_node())
    assert out["vulnerable"] is False
    assert "4.7.2" in out["reason"]


def test_miniplasma_blob_missing_makes_vulnerable_false():
    """All probes pass but blob isn't vendored → vulnerable=False with
    explicit operator-actionable reason."""
    from sapmap_miniplasma import check_miniplasma
    fake = _exec_gw_canned({
        ("cmd.exe", "/C ver"):    ["Microsoft Windows [Version 10.0.19045.3803]"],
        ("cmd.exe", "cldflt.sys"): ["cldflt.sys"],
        ("cmd.exe", "Release"): ["    Release    REG_DWORD    0x80ed8"],
    })
    with patch("sapmap_exploit.execute_gw_command", side_effect=fake), \
         patch("sapmap_miniplasma.is_blob_available", return_value=False):
        out = check_miniplasma(_node())
    assert out["vulnerable"] is False
    assert "blob isn't vendored" in out["reason"] or "build" in out["reason"]


def test_miniplasma_full_viability_with_blob():
    """Everything green: Win10 22H2, cldflt present, .NET 4.8, blob vendored."""
    from sapmap_miniplasma import check_miniplasma
    fake = _exec_gw_canned({
        ("cmd.exe", "/C ver"):    ["Microsoft Windows [Version 10.0.19045.3803]"],
        ("cmd.exe", "cldflt.sys"): ["cldflt.sys"],
        ("cmd.exe", "Release"): ["    Release    REG_DWORD    0x80ed8"],
    })
    with patch("sapmap_exploit.execute_gw_command", side_effect=fake), \
         patch("sapmap_miniplasma.is_blob_available", return_value=True):
        out = check_miniplasma(_node())
    assert out["vulnerable"] is True
    assert out["has_cldflt"] is True
    assert out["net_version"] == "4.8"
    assert out["os_build"] == "10.0.19045"


# ===========================================================================
# Auto-picker
# ===========================================================================

def test_auto_picker_selects_miniplasma_when_viable():
    """Currently the only Windows LPE technique — picker picks it
    whenever miniplasma.check_miniplasma reports vulnerable."""
    from sapmap_winlpe_auto import check_windows_lpe
    n = _node()
    with patch("sapmap_miniplasma.check_miniplasma", return_value={
            "vulnerable": True, "os_build": "10.0.19045",
            "has_cldflt": True, "net_version": "4.8",
            "blob_available": True, "reason": "OK", "details": {}}):
        out = check_windows_lpe(n)
    assert out["method"] == "miniplasma"
    assert n.miniplasma_vulnerable is True
    assert n.windows_lpe_method == "miniplasma"
    assert "MiniPlasma viable" in out["summary"]


def test_auto_picker_returns_none_when_miniplasma_not_viable():
    from sapmap_winlpe_auto import check_windows_lpe
    n = _node()
    with patch("sapmap_miniplasma.check_miniplasma", return_value={
            "vulnerable": False, "os_build": "6.3.9600",
            "has_cldflt": False, "net_version": "",
            "blob_available": True,
            "reason": "OS build too old", "details": {}}):
        out = check_windows_lpe(n)
    assert out["method"] is None
    assert n.miniplasma_vulnerable is False
    assert n.windows_lpe_method == ""
    assert "No working Windows LPE" in out["summary"]


def test_force_env_overrides_auto():
    """SAPMAP_WINLPE_FORCE=miniplasma forces selection even when the
    viability check says no (operator override for staging tests)."""
    from sapmap_winlpe_auto import check_windows_lpe
    n = _node()
    with patch.dict(os.environ, {"SAPMAP_WINLPE_FORCE": "miniplasma"}), \
         patch("sapmap_miniplasma.check_miniplasma", return_value={
            "vulnerable": False, "os_build": "10.0.15063",
            "has_cldflt": False, "net_version": "4.6.2",
            "blob_available": True,
            "reason": "OS too old", "details": {}}):
        out = check_windows_lpe(n)
    assert out["method"] == "miniplasma"   # forced


def test_run_windows_lpe_dispatches_to_picked_method():
    """run_windows_lpe must invoke sapmap_miniplasma.run_as_system when
    the picker says miniplasma, propagate its result, and set
    miniplasma_system_obtained on success."""
    from sapmap_winlpe_auto import run_windows_lpe
    n = _node()
    with patch("sapmap_miniplasma.check_miniplasma", return_value={
            "vulnerable": True, "os_build": "10.0.19045",
            "has_cldflt": True, "net_version": "4.8",
            "blob_available": True, "reason": "OK", "details": {}}), \
         patch("sapmap_miniplasma.run_as_system", return_value={
            "ok": True, "stdout": "nt authority\\system", "error": ""}):
        out = run_windows_lpe(n, "whoami")
    assert out["ok"] is True
    assert out["method"] == "miniplasma"
    assert out["stdout"] == "nt authority\\system"
    assert n.miniplasma_system_obtained is True


def test_run_windows_lpe_no_method_returns_clean_error():
    """When no technique is viable, run_windows_lpe must NOT call any
    exploit module, just return a structured error from the picker."""
    from sapmap_winlpe_auto import run_windows_lpe
    n = _node()
    with patch("sapmap_miniplasma.check_miniplasma", return_value={
            "vulnerable": False, "os_build": "", "has_cldflt": False,
            "net_version": "", "blob_available": False,
            "reason": "Linux host", "details": {}}), \
         patch("sapmap_miniplasma.run_as_system") as mp_run:
        out = run_windows_lpe(n, "whoami")
    assert out["ok"] is False
    assert out["method"] == ""
    assert "No working Windows LPE" in out["error"]
    mp_run.assert_not_called()
