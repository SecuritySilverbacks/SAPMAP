#!/usr/bin/env python3
"""Tests for the @lpe_method('dpmon_sap_star') wiring in sapmap_lpe.

Source-level invariants only — actual RFC + SXPG side effects are
covered by integration tests run separately on the live SAP system.
"""
from __future__ import annotations

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "postex"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "exploitation"))


def _lpe_src():
    path = os.path.join(os.path.dirname(__file__), "..", "modules",
                         "postex", "sapmap_lpe.py")
    with open(path, encoding="utf-8") as f:
        return f.read()


def test_dpmon_lpe_method_registered():
    """`get_lpe_methods()` must include the new dpmon_sap_star method."""
    import sapmap_lpe
    methods = {m.name: m for m in sapmap_lpe.get_lpe_methods()}
    assert "dpmon_sap_star" in methods, (
        f"dpmon_sap_star LPE method not registered; got: "
        f"{list(methods.keys())}")


def test_dpmon_lpe_priority_between_bapi_and_sm49():
    """Priority order matters: try the cheap direct BAPI first (10),
    then dpmon SAP* (20, kernel >= 790 only), then the heavier
    WebGUI SM49 SQL chain (50)."""
    import sapmap_lpe
    methods = {m.name: m for m in sapmap_lpe.get_lpe_methods()}
    assert methods["dpmon_sap_star"].priority == 20
    assert methods["bapi_profiles_assign"].priority < 20 < methods["webgui_sm49"].priority


def test_dpmon_lpe_consults_kernel_gate():
    """The method body must call is_dpmon_sap_star_available to
    skip on kernel < 790 or non-ABAP nodes."""
    src = _lpe_src()
    m = re.search(
        r"def lpe_dpmon_sap_star\(.*?(?=^def |^@lpe_method|\Z)",
        src, re.DOTALL | re.MULTILINE)
    assert m, "lpe_dpmon_sap_star function body not found"
    body = m.group(0)
    assert "is_dpmon_sap_star_available" in body, (
        "LPE method must gate on is_dpmon_sap_star_available()")


def test_dpmon_lpe_uses_sxpg_exec_channel():
    """The exec_fn must wrap SXPG_STEP_XPG_START via execute_local_command —
    that's the only ABAP-authenticated channel that runs OS commands
    via the SAP gateway without S_RFC.  The shell pipeline is driven
    via chunked_drop_and_run (workaround for the sapxpg PARAMS
    tokenizer that mangles `sh -c '<pipeline>'`)."""
    src = _lpe_src()
    m = re.search(
        r"def lpe_dpmon_sap_star\(.*?(?=^def |^@lpe_method|\Z)",
        src, re.DOTALL | re.MULTILINE)
    assert m, "lpe_dpmon_sap_star function body not found"
    body = m.group(0)
    assert "execute_local_command" in body, (
        "exec_fn must use sapmap_rfc.execute_local_command (SXPG path)")
    assert "chunked_drop_and_run" in body, (
        "exec_fn must use chunked_drop_and_run -- direct sh -c is "
        "mangled by sapxpg's PARAMS tokenizer")


def test_dpmon_lpe_bapi_assign_after_otp():
    """The method must call BAPI_USER_PROFILES_ASSIGN with the
    original user's name + SAP_ALL + SAP_NEW profiles."""
    src = _lpe_src()
    m = re.search(
        r"def lpe_dpmon_sap_star\(.*?(?=^def |^@lpe_method|\Z)",
        src, re.DOTALL | re.MULTILINE)
    assert m
    body = m.group(0)
    assert "BAPI_USER_PROFILES_ASSIGN" in body
    assert "SAP_ALL" in body
    assert "SAP_NEW" in body
    assert "BAPI_TRANSACTION_COMMIT" in body


def test_dpmon_lpe_sets_used_flag_on_success():
    """After a successful OTP-driven SAP_ALL assign, the method must
    set node.dpmon_sap_star_used = True so the engagement report
    can highlight nodes reached via this path."""
    src = _lpe_src()
    m = re.search(
        r"def lpe_dpmon_sap_star\(.*?(?=^def |^@lpe_method|\Z)",
        src, re.DOTALL | re.MULTILINE)
    assert m
    body = m.group(0)
    assert "node.dpmon_sap_star_used = True" in body, (
        "LPE method must tag the node when SAP_ALL assignment succeeds")


def test_dpmon_lpe_does_not_retry_after_otp_burned():
    """The CRITICAL OTP-handling rule: any failed password attempt
    burns the OTP, so the BAPI call is a single-shot — no retries.
    Source-level invariant: there should be exactly ONE BAPI_USER_PROFILES_ASSIGN
    invocation in the function body (no retry loop)."""
    src = _lpe_src()
    m = re.search(
        r"def lpe_dpmon_sap_star\(.*?(?=^def |^@lpe_method|\Z)",
        src, re.DOTALL | re.MULTILINE)
    assert m
    body = m.group(0)
    # Count actual call sites (conn.call("BAPI_USER_PROFILES_ASSIGN", ...)),
    # not occurrences inside the docstring.
    call_sites = len(re.findall(
        r'conn\.call\(\s*\n?\s*"BAPI_USER_PROFILES_ASSIGN"', body))
    assert call_sites == 1, (
        f"There must be exactly one BAPI_USER_PROFILES_ASSIGN call "
        f"site — OTP is single-use, retries burn it.  Found "
        f"{call_sites}.")


def test_dpmon_lpe_handles_exec_fn_exceptions():
    """The exec_fn raises RuntimeError on SXPG failure (we want the
    error string to flow into the parser's `error` field for the
    operator).  The outer try/except must convert it to a clean
    LPE-method False return rather than propagating."""
    src = _lpe_src()
    m = re.search(
        r"def lpe_dpmon_sap_star\(.*?(?=^def |^@lpe_method|\Z)",
        src, re.DOTALL | re.MULTILINE)
    assert m
    body = m.group(0)
    # The outer try around activate_virtual_sap_star must exist
    assert "try:" in body
    assert "activate_virtual_sap_star" in body
    # And the result.success branch must return False on failure
    assert 'result["success"]' in body or "result['success']" in body
