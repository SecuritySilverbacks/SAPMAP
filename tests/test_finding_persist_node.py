"""Tests for issue #151 — emit_finding's persist_node opt-out.

emit_finding auto-mirrors every CRITICAL/HIGH bus event onto the node as a
Finding (_persist_to_node). A callsite that appends its OWN richer node Finding
for the same detection used to get BOTH — two findings for one detection. The
new persist_node=False lets such a callsite suppress the auto-mirror while
keeping its manual Finding; emit-only callsites keep the default (True) and
still get their mirror.

The auto-mirror only runs when a state is attached, so these tests attach one
and clear the global bus between emits (the 60s (severity, node, msg) bus-dedup
would otherwise suppress later emits), mirroring tests/test_wd_finding_dedup.py.
"""
from __future__ import annotations

import inspect

import pytest

import modules  # noqa: F401 — registers package paths

import sapmap_findings
from sapmap_models import SAPMAPState, SAPNode, Severity, Finding


@pytest.fixture
def attached():
    sapmap_findings._findings.clear()
    sid = "N151"
    node = SAPNode(sid=sid, ip="10.0.0.1")
    state = SAPMAPState()
    state.nodes[sid] = node
    sapmap_findings.attach_state(state)
    try:
        yield sid, node
    finally:
        sapmap_findings.attach_state(None)
        sapmap_findings._findings.clear()


# ---------------------------------------------------------------------------
# the flag itself
# ---------------------------------------------------------------------------

def test_persist_node_false_skips_mirror(attached):
    sid, node = attached
    sapmap_findings.emit_finding("CRITICAL", sid, "msg A", persist_node=False)
    assert node.findings == [], "persist_node=False must not auto-mirror onto the node"


def test_default_still_mirrors(attached):
    """Emit-only callsites (the large majority) rely on the auto-mirror."""
    sid, node = attached
    sapmap_findings.emit_finding("CRITICAL", sid, "msg B")
    assert len(node.findings) == 1


# ---------------------------------------------------------------------------
# the dual-callsite pattern the fix targets
# ---------------------------------------------------------------------------

def test_dual_callsite_single_finding_with_flag(attached):
    sid, node = attached
    node.findings.append(Finding(name="Rich CRITICAL finding",
                                 severity=Severity.CRITICAL))
    sapmap_findings.emit_finding("HIGH", sid, "a different bus message",
                                 persist_node=False)
    assert len(node.findings) == 1, \
        "the manual Finding must be the only node finding"


def test_dual_callsite_duplicates_without_flag(attached):
    """Non-vacuity: the pre-fix behaviour (default True) produces two findings."""
    sid, node = attached
    node.findings.append(Finding(name="Rich CRITICAL finding",
                                 severity=Severity.CRITICAL))
    sapmap_findings.emit_finding("HIGH", sid, "a different bus message")
    assert len(node.findings) == 2


# ---------------------------------------------------------------------------
# the 4 dual callsites opt out (source guards)
# ---------------------------------------------------------------------------

def test_scanner_ms_sites_opt_out():
    import sapmap_scanner
    for fn in (sapmap_scanner.check_ms_betrusted,
               sapmap_scanner.check_ms_info_disclosure):
        src = inspect.getsource(fn)
        assert "persist_node=False" in src, \
            f"{fn.__name__} must opt out of the auto-mirror (issue #151)"


def test_gui_icmad_sites_opt_out():
    import sapmap_gui
    src = inspect.getsource(sapmap_gui)
    # Window generously (the two ICMAD emits are >100 lines apart, so this
    # cannot bleed into the other site's persist_node=False); the only risk a
    # tight window carries is a spurious failure when the call grows.
    for marker in ("ICMAD ACL bypass:", "ICMAD: HPROF heap dump captured"):
        i = src.index(marker)
        assert "persist_node=False" in src[i:i + 2000], \
            f"the {marker!r} emit must pass persist_node=False"
