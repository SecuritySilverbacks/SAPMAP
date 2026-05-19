#!/usr/bin/env python3
"""Tests for the Linux LPE auto-picker + Dirty Frag prereq probe.

All offline; SAPXPG and the dirtyfrag binary delivery are mocked.
"""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest


# ===========================================================================
# Helpers
# ===========================================================================

def _node(os_type="Linux"):
    from sapmap_models import SAPNode
    return SAPNode(sid="LIN", ip="10.0.0.1", hostname="linhost",
                   system_type="ABAP", os_type=os_type)


def _exec_gw_canned(map_in_out):
    """Build a fake execute_gw_command that pattern-matches (prog, params)
    pairs from ``map_in_out`` (dict {(prog, params): output_lines}).
    Unknown calls return empty output."""
    def _fake(node, prog, params, long_params=""):
        for (p, a), out in map_in_out.items():
            if prog == p and (a is None or params == a):
                return {"output": out, "success": True}
        return {"output": [], "success": True}
    return _fake


# ===========================================================================
# Dirty Frag prereq probe
# ===========================================================================

def test_dirtyfrag_windows_short_circuits():
    """Windows hosts must early-exit with reason set, no SAPXPG calls."""
    from sapmap_dirtyfrag import check_dirtyfrag
    with patch("sapmap_exploit.execute_gw_command") as gw:
        out = check_dirtyfrag(_node(os_type="Windows Server 2019"))
    assert out["vulnerable"] is False
    assert "Windows" in out["reason"]
    gw.assert_not_called()


def test_dirtyfrag_non_x86_arch_fails():
    """ARM64 / aarch64 hosts must report the unsupported-arch reason."""
    from sapmap_dirtyfrag import check_dirtyfrag
    fake = _exec_gw_canned({
        ("uname", "-r"): ["6.12.0-generic"],
        ("uname", "-m"): ["aarch64"],
    })
    with patch("sapmap_exploit.execute_gw_command", side_effect=fake):
        out = check_dirtyfrag(_node())
    assert out["vulnerable"] is False
    assert "x86_64" in out["reason"]


def test_dirtyfrag_modprobe_blacklist_short_circuits():
    """If /etc/modprobe.d/dirtyfrag.conf has the upstream-recommended
    blacklist, neither variant will load — must report mitigation."""
    from sapmap_dirtyfrag import check_dirtyfrag
    fake = _exec_gw_canned({
        ("uname", "-r"): ["6.17.0-23-generic"],
        ("uname", "-m"): ["x86_64"],
        ("cat",   "/etc/modprobe.d/dirtyfrag.conf"): [
            "install esp4 /bin/false",
            "install esp6 /bin/false",
            "install rxrpc /bin/false",
        ],
    })
    with patch("sapmap_exploit.execute_gw_command", side_effect=fake):
        out = check_dirtyfrag(_node())
    assert out["vulnerable"] is False
    assert out["mitigation_applied"] is True
    assert "blacklist" in out["reason"].lower()


def test_dirtyfrag_neither_path_viable_when_unshare_blocked_no_rxrpc():
    """If unshare(-U) fails (AppArmor) AND rxrpc.ko is unavailable,
    the host is effectively immune."""
    from sapmap_dirtyfrag import check_dirtyfrag
    fake = _exec_gw_canned({
        ("uname", "-r"): ["6.12.0-generic"],
        ("uname", "-m"): ["x86_64"],
        ("cat",   "/etc/modprobe.d/dirtyfrag.conf"): [],
        ("unshare", None): ["unshare: namespace creation failed"],
        ("lsmod",   ""): ["Module Size Used by"],
        ("modinfo", "rxrpc"): ["modinfo: ERROR: Module rxrpc not found"],
    })
    with patch("sapmap_exploit.execute_gw_command", side_effect=fake):
        out = check_dirtyfrag(_node())
    assert out["vulnerable"] is False
    assert out["esp_path_ok"] is False
    assert out["rxrpc_path_ok"] is False


def test_dirtyfrag_blob_missing_makes_vulnerable_false():
    """Even with viable kernel + path, if the vendored binary blob isn't
    built yet, we must report not-vulnerable + tell the operator how to
    build it."""
    from sapmap_dirtyfrag import check_dirtyfrag
    fake = _exec_gw_canned({
        ("uname", "-r"): ["6.17.0-23-generic"],
        ("uname", "-m"): ["x86_64"],
        ("cat",   "/etc/modprobe.d/dirtyfrag.conf"): [],
        ("unshare", None): ["DF_NS_OK_12345"],
        ("lsmod",   ""): ["rxrpc 81920 0"],
        ("modinfo", "rxrpc"): ["filename: /lib/modules/.../rxrpc.ko"],
    })
    # Force "blob missing" regardless of repo state
    with patch("sapmap_exploit.execute_gw_command", side_effect=fake), \
         patch("sapmap_dirtyfrag._load_blob", return_value=None):
        out = check_dirtyfrag(_node())
    assert out["vulnerable"] is False
    assert out["blob_available"] is False
    assert "build.sh" in out["reason"]


def test_dirtyfrag_full_viability_with_blob():
    """When kernel + esp/rxrpc + blob are all present, vulnerable=True."""
    from sapmap_dirtyfrag import check_dirtyfrag
    fake = _exec_gw_canned({
        ("uname", "-r"): ["6.17.0-23-generic"],
        ("uname", "-m"): ["x86_64"],
        ("cat",   "/etc/modprobe.d/dirtyfrag.conf"): [],
        ("unshare", None): ["DF_NS_OK_99"],
        ("lsmod",   ""): ["rxrpc 81920 0"],
        ("modinfo", "rxrpc"): ["filename: /lib/modules/.../rxrpc.ko"],
    })
    with patch("sapmap_exploit.execute_gw_command", side_effect=fake), \
         patch("sapmap_dirtyfrag._load_blob",
               return_value={"hex": "00", "size": 1, "sha256": "abc"}):
        out = check_dirtyfrag(_node())
    assert out["vulnerable"] is True
    assert out["esp_path_ok"] is True
    assert out["rxrpc_path_ok"] is True


# ===========================================================================
# Auto-picker priority
# ===========================================================================

def test_auto_picker_prefers_copyfail_when_both_viable():
    """Copy Fail wins precedence — pure-Python, smaller blast radius."""
    from sapmap_lpe_auto import check_linux_lpe
    cf_res = {"vulnerable": True, "kernel": "6.4.0", "reason": "ok"}
    df_res = {"vulnerable": True, "kernel": "6.4.0", "arch": "x86_64",
              "reason": "ok", "mitigation_applied": False}
    with patch("sapmap_copyfail.check_copyfail", return_value=cf_res), \
         patch("sapmap_dirtyfrag.check_dirtyfrag", return_value=df_res):
        out = check_linux_lpe(_node())
    assert out["method"] == "copyfail"


def test_auto_picker_falls_back_to_dirtyfrag_when_copyfail_patched():
    """Patched-against-Copy-Fail kernel => Dirty Frag picks up the slack."""
    from sapmap_lpe_auto import check_linux_lpe
    cf_res = {"vulnerable": False, "kernel": "6.18.22", "reason": "patched"}
    df_res = {"vulnerable": True, "kernel": "6.18.22", "arch": "x86_64",
              "reason": "ok", "mitigation_applied": False}
    with patch("sapmap_copyfail.check_copyfail", return_value=cf_res), \
         patch("sapmap_dirtyfrag.check_dirtyfrag", return_value=df_res):
        out = check_linux_lpe(_node())
    assert out["method"] == "dirtyfrag"


def test_auto_picker_returns_none_when_neither_viable():
    """Both unavailable => no method, no run_linux_lpe attempt."""
    from sapmap_lpe_auto import check_linux_lpe
    cf_res = {"vulnerable": False, "kernel": "6.18.22", "reason": "patched"}
    df_res = {"vulnerable": False, "kernel": "6.18.22", "arch": "x86_64",
              "reason": "no rxrpc, no userns",
              "mitigation_applied": False}
    with patch("sapmap_copyfail.check_copyfail", return_value=cf_res), \
         patch("sapmap_dirtyfrag.check_dirtyfrag", return_value=df_res):
        out = check_linux_lpe(_node())
    assert out["method"] is None
    assert "Copy Fail" in out["summary"]
    assert "Dirty Frag" in out["summary"]


def test_force_env_overrides_auto():
    """SAPMAP_LPE_FORCE=dirtyfrag forces Dirty Frag even when Copy Fail
    is viable (operator override)."""
    from sapmap_lpe_auto import check_linux_lpe
    cf_res = {"vulnerable": True, "kernel": "6.4.0", "reason": "ok"}
    df_res = {"vulnerable": True, "kernel": "6.4.0", "arch": "x86_64",
              "reason": "ok", "mitigation_applied": False}
    with patch("sapmap_copyfail.check_copyfail", return_value=cf_res), \
         patch("sapmap_dirtyfrag.check_dirtyfrag", return_value=df_res), \
         patch.dict(os.environ, {"SAPMAP_LPE_FORCE": "dirtyfrag"}):
        out = check_linux_lpe(_node())
    assert out["method"] == "dirtyfrag"


def test_run_linux_lpe_dispatches_to_picked_method():
    """run_linux_lpe must call the picked method's run_as_root and tag
    the corresponding *_root_obtained on the node."""
    from sapmap_lpe_auto import run_linux_lpe
    cf_res = {"vulnerable": False, "kernel": "6.18.22", "reason": "patched"}
    df_res = {"vulnerable": True, "kernel": "6.18.22", "arch": "x86_64",
              "reason": "ok", "mitigation_applied": False}
    n = _node()
    with patch("sapmap_copyfail.check_copyfail", return_value=cf_res), \
         patch("sapmap_dirtyfrag.check_dirtyfrag", return_value=df_res), \
         patch("sapmap_dirtyfrag.run_as_root",
               return_value={"ok": True, "stdout": "uid=0", "error": ""}) \
             as df_run, \
         patch("sapmap_copyfail.run_as_root",
               return_value={"ok": False, "stdout": "", "error": "x"}) \
             as cf_run:
        out = run_linux_lpe(n, "id")
    assert out["ok"] is True
    assert out["method"] == "dirtyfrag"
    df_run.assert_called_once()
    cf_run.assert_not_called()
    assert n.dirtyfrag_root_obtained is True
    assert n.copyfail_root_obtained is False


def test_run_linux_lpe_no_method_returns_clean_error():
    """Both methods unviable -> error response, no run_as_root call."""
    from sapmap_lpe_auto import run_linux_lpe
    cf_res = {"vulnerable": False, "kernel": "?", "reason": "x"}
    df_res = {"vulnerable": False, "kernel": "?", "arch": "x86_64",
              "reason": "y", "mitigation_applied": False}
    n = _node()
    with patch("sapmap_copyfail.check_copyfail", return_value=cf_res), \
         patch("sapmap_dirtyfrag.check_dirtyfrag", return_value=df_res), \
         patch("sapmap_dirtyfrag.run_as_root") as df_run, \
         patch("sapmap_copyfail.run_as_root") as cf_run:
        out = run_linux_lpe(n, "id")
    assert out["ok"] is False
    assert out["method"] == ""
    df_run.assert_not_called()
    cf_run.assert_not_called()
