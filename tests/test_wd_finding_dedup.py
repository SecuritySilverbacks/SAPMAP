"""Tests for issue #64 — one Web-Dispatcher-specific finding, no duplicate,
no generic ABAP default-account remediation.

A confirmed WD default-cred hit used to produce TWO CRITICAL node Findings:
`emit_finding` auto-mirrors one onto the node (via `_persist_to_node`, name =
the bus msg, carrying the generic `creds.default_probe` remediation
SAP*/DDIC/RSUSR003), and the callsite ALSO manually appended a WD-specific one
under a different name ("…live…" vs "…LIVE…"), so the name-dedup did not
collapse them.  The fix keys the manual Finding to the same `msg` (appended
before `emit_finding`, so the mirror dedups) and drops the generic-remediation
capability from the WD emits (ATT&CK kept via `attack_techniques`).

The auto-mirror only runs when a state is attached (`sapmap_findings.attach_state`),
so these behavioural tests attach one.
"""
from __future__ import annotations

import inspect

import pytest

import modules  # noqa: F401 — registers package paths

import sapmap_gui
import sapmap_findings
from sapmap_models import SAPMAPState, SAPNode, Severity


@pytest.fixture
def attached():
    """A node registered in a state attached to the findings bus, so
    emit_finding's CRITICAL/HIGH auto-mirror to node.findings is active.

    The global findings bus is cleared so emit_finding's 60s (severity, node,
    msg) bus-dedup does not suppress the auto-mirror in later tests (which would
    make the dedup assertions vacuous) — every test must genuinely exercise the
    auto-mirror vs. the manual append.
    """
    sapmap_findings._findings.clear()
    sid = "WDX"
    node = SAPNode(sid=sid, ip="10.0.0.5")
    state = SAPMAPState()
    state.nodes[sid] = node
    sapmap_findings.attach_state(state)
    try:
        yield sid, node
    finally:
        sapmap_findings.attach_state(None)
        sapmap_findings._findings.clear()


def _attempt():
    return {"user": "webadm", "live": True, "status": 200, "realm": "WEB ADMIN",
            "https": True, "verify_path": "/sap/wdisp/admin/", "confidence": "gated"}


def _probe(node, sid):
    return sapmap_gui._record_wd_default_probe_result(
        node, sid, 44300, True, True, ("webadm", "webadm"), [_attempt()])


def test_single_wd_finding_no_duplicate(attached):
    sid, node = attached
    _probe(node, sid)
    crit = [f for f in node.findings if f.severity == Severity.CRITICAL]
    assert len(crit) == 1, \
        "a WD default-cred hit must produce exactly one CRITICAL finding"


def test_wd_finding_has_wd_remediation_not_generic(attached):
    sid, node = attached
    _probe(node, sid)
    f = next(f for f in node.findings if f.severity == Severity.CRITICAL)
    rem = str(f.remediation)
    assert "/sap/wdisp/admin" in rem or "icm/HTTP/admin" in rem, \
        "the WD finding should keep its Web Dispatcher remediation"
    for tok in ("SAP*", "DDIC", "TMSADM", "EARLYWATCH", "RSUSR003",
                "no_automatic_user_sapstar"):
        assert tok not in rem, \
            f"generic ABAP default-account token {tok!r} leaked onto the WD finding"


def test_wd_finding_keeps_attack_techniques(attached):
    """The persistent node Finding (what the report/heatmap/Navigator read) must
    keep the ATT&CK tags — not only the transient bus record."""
    sid, node = attached
    _probe(node, sid)
    f = next(f for f in node.findings if f.severity == Severity.CRITICAL)
    assert list(f.attack_techniques) == ["T1078.001", "T1110.001"], \
        "the WD node Finding must carry the ATT&CK technique ids"


def test_idempotent_on_reprobe(attached):
    sid, node = attached
    for _ in range(3):
        _probe(node, sid)
    crit = [f for f in node.findings if f.severity == Severity.CRITICAL]
    assert len(crit) == 1, "re-probing must not grow the findings list"


def test_helper_source_uses_attack_techniques_not_generic_capability():
    src = inspect.getsource(sapmap_gui._record_wd_default_probe_result)
    assert 'attack_capability="creds.default_probe"' not in src, \
        "the WD emit must not pull the generic default-account remediation"
    assert 'attack_techniques=["T1078.001", "T1110.001"]' in src
    # the WD Finding is appended BEFORE the bus emit, so the auto-mirror dedups
    assert src.index("node.findings.append(Finding(") < src.index("emit_finding("), \
        "the manual WD Finding must be appended before emit_finding"
