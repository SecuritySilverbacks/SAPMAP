#!/usr/bin/env python3
"""Tests for SAPNode `dpmon_sap_star_*` fields + scanner-side detection
gate.

Covers:
  * SAPNode default values for the two new fields
  * to_dict / from_dict round-trip preserves them
  * Scanner code path sets `dpmon_sap_star_available` when both the
    kernel and the ABAP stack qualify (smoke-checked at the call-site
    level — full scanner integration is exercised by the existing
    scanner test suite indirectly)
"""
from __future__ import annotations

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "discovery"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "exploitation"))


# ===========================================================================
# Model defaults & serialisation
# ===========================================================================

def test_sapnode_dpmon_fields_default_false():
    from sapmap_models import SAPNode
    n = SAPNode(sid="TST")
    assert n.dpmon_sap_star_available is False
    assert n.dpmon_sap_star_used is False


def test_sapnode_dpmon_fields_round_trip():
    from sapmap_models import SAPNode
    n = SAPNode(sid="TST")
    n.dpmon_sap_star_available = True
    n.dpmon_sap_star_used = True
    d = n.to_dict()
    assert d["dpmon_sap_star_available"] is True
    assert d["dpmon_sap_star_used"] is True
    n2 = SAPNode.from_dict(d)
    assert n2.dpmon_sap_star_available is True
    assert n2.dpmon_sap_star_used is True


def test_sapnode_dpmon_fields_back_compat_from_old_state():
    """Old .sapmap files written before this commit don't carry the
    field.  from_dict must default to False, not raise."""
    from sapmap_models import SAPNode
    legacy = {"sid": "TST"}   # the minimum
    n = SAPNode.from_dict(legacy)
    assert n.dpmon_sap_star_available is False
    assert n.dpmon_sap_star_used is False


# ===========================================================================
# Scanner integration — source-level invariant: both build paths
# call is_dpmon_sap_star_available(node.kernel, node.system_type).
# ===========================================================================

def _scanner_src():
    path = os.path.join(os.path.dirname(__file__), "..", "modules",
                         "discovery", "sapmap_scanner.py")
    with open(path, encoding="utf-8") as f:
        return f.read()


def test_fast_scan_calls_dpmon_eligibility_gate():
    """The fast-scan node builder (_build_nodes_from_fast_scan) must
    consult is_dpmon_sap_star_available() to tag node eligibility."""
    src = _scanner_src()
    m = re.search(r"def _build_nodes_from_fast_scan.*?(?=^def )",
                  src, re.DOTALL | re.MULTILINE)
    assert m, "_build_nodes_from_fast_scan function not found"
    body = m.group(0)
    assert "is_dpmon_sap_star_available" in body, (
        "fast-scan node builder must call is_dpmon_sap_star_available()")
    assert "node.dpmon_sap_star_available" in body, (
        "fast-scan node builder must assign the flag onto the node")


def test_deep_scan_calls_dpmon_eligibility_gate():
    """The SAPology-deep-scan node builder must also tag eligibility."""
    src = _scanner_src()
    m = re.search(r"def _sapology_system_to_node.*?(?=^def )",
                  src, re.DOTALL | re.MULTILINE)
    assert m, "_sapology_system_to_node function not found"
    body = m.group(0)
    assert "is_dpmon_sap_star_available" in body, (
        "deep-scan node builder must call is_dpmon_sap_star_available()")


# ===========================================================================
# Behavioural — invoke is_dpmon_sap_star_available directly with the
# exact kernel/system_type combos the scanner will see in the wild.
# ===========================================================================

@pytest.mark.parametrize("kernel,system_type,expected", [
    # Real-world ABAP / dual-stack on supported kernel
    ("790", "ABAP",      True),
    ("793", "ABAP",      True),
    ("790", "ABAP+JAVA", True),
    # Same kernel, ineligible stacks
    ("790", "JAVA",            False),
    ("790", "HANA",            False),
    ("790", "WEB_DISPATCHER",  False),
    ("790", "SAPROUTER",       False),
    ("790", "SAP",             False),   # generic SAP fallback isn't ABAP
    # ABAP but kernel too old
    ("753", "ABAP",      False),
    ("749", "ABAP+JAVA", False),
])
def test_eligibility_matrix(kernel, system_type, expected):
    from sap_dpmon_sapstar import is_dpmon_sap_star_available
    assert is_dpmon_sap_star_available(kernel, system_type) is expected
