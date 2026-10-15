#!/usr/bin/env python3
"""Regression tests for issue #155 — multi-SID host gateway attribution.

Scenario (operator-reported by @supersache while testing #70): a single
host runs **two** ABAP SIDs on different instance numbers — e.g. AE1 on
instance 00 (gateway 3300) and AE3 on instance 02 (gateway 3302).  ``nmap``
confirms both 3300 and 3302 open, yet SAPMAP plotted AE3 with *no gateway*
(and no dispatcher), because the gateway ``RFC_SYSTEM_INFO`` probe for
instance 02 returned the **primary** SID (AE1) — gateway proxying /
``sid_hint`` contamination on a multi-SID host.  ``instance_sid_map`` is the
single authority downstream (Phase C groups instances by it, Phase D builds
one node per SID with only that SID's instance ports), so the wrong map
dumped 3202/3302 onto AE1 and left AE3 empty.

Fix: ``_reconcile_instance_sid`` cross-checks each instance's SID against
the authoritative per-instance SAPControl reading (``50000+NN*100+13``) and
trusts SAPControl when it conflicts with the gateway RFC SID.  The gateway
``3300+NN`` and SAPControl ``50000+NN*100+13`` ports are keyed by the same
instance number, and an instance belongs to exactly one SID, so SAPControl
is ground truth; the RFC probe returning the primary SID is the anomaly.

Covered here:
  * ``_reconcile_instance_sid`` unit behaviour — override-on-conflict,
    keep-on-agreement (case-insensitive), keep-on-empty, keep-on-error,
    no-op for non-digit instances, correct SAPControl port, RFC-enrichment
    preserved in the merge.
  * Integration through ``_build_nodes_from_fast_scan`` — the secondary
    SID's gateway + dispatcher follow it to its own node (the bug repro),
    plus the no-regression guards (single-SID host unchanged; SAPControl
    silent → conservative fallback to the RFC SID).
"""
from __future__ import annotations

import os
import sys

import pytest

# Ensure modules are importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "discovery"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "core"))

import sapmap_scanner  # noqa: E402


# ---------------------------------------------------------------------------
# Unit tests: _reconcile_instance_sid (pure, SAPControl stubbed)
# ---------------------------------------------------------------------------

def _stub_sapcontrol(monkeypatch, mapping, record=None):
    """Patch _query_sapcontrol_sid to return canned (sid, j, a, db, http,
    https) tuples keyed by port.  `mapping` maps port -> that tuple (or a
    bare sid string, expanded to an ABAP tuple).  Unlisted ports -> empty."""
    def fake(host, port, timeout=3, saprouter=""):
        if record is not None:
            record.append(port)
        val = mapping.get(port, "")
        if isinstance(val, str):
            return (val, False, bool(val), "", 0, 0)
        return val
    monkeypatch.setattr(sapmap_scanner, "_query_sapcontrol_sid", fake)


def test_reconcile_overrides_rfc_sid_on_conflict(monkeypatch):
    """SAPControl (50213) says AE3, gateway RFC said AE1 -> trust AE3."""
    _stub_sapcontrol(monkeypatch, {50213: "AE3"})
    sid, info = sapmap_scanner._reconcile_instance_sid(
        "10.10.1.6", "02", "AE1",
        {"sid": "AE1", "kernel": "753", "hostname": "ae3host"})
    assert sid == "AE3"
    assert info["sid"] == "AE3"


def test_reconcile_merge_preserves_rfc_enrichment(monkeypatch):
    """The override keeps the RFC probe's kernel/hostname (SAPControl
    doesn't carry them) and fills the stack/db it does know."""
    _stub_sapcontrol(monkeypatch,
                     {50213: ("AE3", False, True, "HDB", 0, 0)})
    sid, info = sapmap_scanner._reconcile_instance_sid(
        "10.10.1.6", "02", "AE1",
        {"sid": "AE1", "kernel": "753", "hostname": "ae3host"})
    assert sid == "AE3"
    assert info["kernel"] == "753"          # RFC enrichment preserved
    assert info["hostname"] == "ae3host"
    assert info["_is_abap"] is True         # SAPControl stack hint merged
    assert info["db_type"] == "HDB"         # SAPControl db filled in


def test_reconcile_merge_does_not_clobber_existing_db(monkeypatch):
    """A db_type the RFC probe already resolved is not overwritten."""
    _stub_sapcontrol(monkeypatch,
                     {50213: ("AE3", False, True, "HDB", 0, 0)})
    _, info = sapmap_scanner._reconcile_instance_sid(
        "10.10.1.6", "02", "AE1", {"sid": "AE1", "db_type": "ORA"})
    assert info["db_type"] == "ORA"


def test_reconcile_keeps_rfc_sid_on_agreement(monkeypatch):
    """SAPControl agrees with the gateway RFC SID -> no change, same dict."""
    _stub_sapcontrol(monkeypatch, {50013: "AE1"})
    original = {"sid": "AE1", "kernel": "753"}
    sid, info = sapmap_scanner._reconcile_instance_sid(
        "10.10.1.6", "00", "AE1", original)
    assert sid == "AE1"
    assert info is original                 # untouched, not a copy


def test_reconcile_agreement_is_case_insensitive(monkeypatch):
    """SAPControl 'ae1' vs RFC 'AE1' is agreement, not a conflict."""
    _stub_sapcontrol(monkeypatch, {50013: "ae1"})
    original = {"sid": "AE1"}
    sid, info = sapmap_scanner._reconcile_instance_sid(
        "10.10.1.6", "00", "AE1", original)
    assert sid == "AE1"
    assert info is original


def test_reconcile_keeps_rfc_sid_when_sapcontrol_silent(monkeypatch):
    """SAPControl firewalled/absent (empty SID) -> preserve RFC behaviour."""
    _stub_sapcontrol(monkeypatch, {})       # every port -> ""
    original = {"sid": "AE1"}
    sid, info = sapmap_scanner._reconcile_instance_sid(
        "10.10.1.6", "02", "AE1", original)
    assert sid == "AE1"
    assert info is original


def test_reconcile_keeps_rfc_sid_on_sapcontrol_error(monkeypatch):
    """A SAPControl probe that raises must not break discovery."""
    def boom(*a, **k):
        raise OSError("connection reset")
    monkeypatch.setattr(sapmap_scanner, "_query_sapcontrol_sid", boom)
    original = {"sid": "AE1"}
    sid, info = sapmap_scanner._reconcile_instance_sid(
        "10.10.1.6", "02", "AE1", original)
    assert sid == "AE1"
    assert info is original


def test_reconcile_noop_for_non_digit_instance(monkeypatch):
    """A WD/placeholder instance_nr ('WD') has no 50N13 agent -> no probe,
    no change."""
    called = []
    _stub_sapcontrol(monkeypatch, {}, record=called)
    original = {"sid": "W74"}
    sid, info = sapmap_scanner._reconcile_instance_sid(
        "192.168.2.29", "WD", "W74", original)
    assert sid == "W74"
    assert info is original
    assert called == []                     # SAPControl never queried


def test_reconcile_queries_canonical_sapcontrol_port(monkeypatch):
    """The SAPControl port must be 50000 + NN*100 + 13 for instance NN."""
    called = []
    _stub_sapcontrol(monkeypatch, {50213: "AE3"}, record=called)
    sapmap_scanner._reconcile_instance_sid(
        "10.10.1.6", "02", "AE1", {"sid": "AE1"})
    assert called == [50213]


# ---------------------------------------------------------------------------
# Integration: _build_nodes_from_fast_scan end-to-end
# ---------------------------------------------------------------------------

def _two_sid_scan():
    """Host 10.10.1.6: AE1 on instance 00, AE3 on instance 02 — both with
    dispatcher + gateway + SAPControl open (nmap-confirmed)."""
    return {
        "host": "10.10.1.6",
        "open_ports": {
            3200:  {"service": "dispatcher", "instance_nr": "00"},
            3300:  {"service": "gateway",    "instance_nr": "00"},
            50013: {"service": "sapcontrol", "instance_nr": "00"},
            3202:  {"service": "dispatcher", "instance_nr": "02"},
            3302:  {"service": "gateway",    "instance_nr": "02"},
            50213: {"service": "sapcontrol", "instance_nr": "02"},
        },
    }


def _patch_build_probes(monkeypatch, gw_sid_by_port, sapctl_sid_by_port):
    """Stub the network-touching helpers _build_nodes_from_fast_scan calls:
    the gateway RFC enrichment, the SAPControl reconciliation reading, and
    client enumeration (always empty here)."""
    def fake_enrich(host, port, timeout=10, verbose=False, sid_hint="",
                    saprouter=""):
        sid = gw_sid_by_port.get(port, "")
        if not sid:
            return {}
        return {"sid": sid, "kernel": "753", "hostname": f"{host}"}
    monkeypatch.setattr(sapmap_scanner, "enrich_system_info", fake_enrich)

    def fake_sapctl(host, port, timeout=3, saprouter=""):
        sid = sapctl_sid_by_port.get(port, "")
        return (sid, False, bool(sid), "", 0, 0)
    monkeypatch.setattr(sapmap_scanner, "_query_sapcontrol_sid", fake_sapctl)

    monkeypatch.setattr(sapmap_scanner, "enumerate_system_clients",
                        lambda *a, **k: [])


def _ports_of(node):
    out = set()
    for inst in node.instances:
        out |= set(inst.ports.keys())
    return out


def test_secondary_sid_keeps_its_own_gateway_and_dispatcher(monkeypatch):
    """THE BUG (#155): the gateway RFC probe reports the PRIMARY SID (AE1)
    for BOTH instances (the multi-SID wire anomaly), but SAPControl 50213
    correctly reports AE3 for instance 02.  After the fix, AE3 owns its
    dispatcher 3202 + gateway 3302 instead of them being dumped on AE1."""
    _patch_build_probes(
        monkeypatch,
        gw_sid_by_port={3300: "AE1", 3302: "AE1"},   # anomaly: both say AE1
        sapctl_sid_by_port={50013: "AE1", 50213: "AE3"},
    )
    nodes = sapmap_scanner._build_nodes_from_fast_scan(_two_sid_scan(),
                                                       timeout=0.1)
    by_sid = {n.sid: n for n in nodes}
    assert set(by_sid) == {"AE1", "AE3"}, (
        f"expected two distinct SID nodes, got {sorted(by_sid)}")

    ae1_ports, ae3_ports = _ports_of(by_sid["AE1"]), _ports_of(by_sid["AE3"])
    # AE3 must carry instance 02's gateway + dispatcher (the regression).
    assert 3302 in ae3_ports, f"AE3 lost its gateway 3302 (got {sorted(ae3_ports)})"
    assert 3202 in ae3_ports, f"AE3 lost its dispatcher 3202 (got {sorted(ae3_ports)})"
    assert 50213 in ae3_ports
    # AE1 keeps only instance 00's ports — no cross-contamination.
    assert {3300, 3200, 50013} <= ae1_ports
    assert 3302 not in ae1_ports, "AE1 wrongly kept AE3's gateway 3302"
    assert 3202 not in ae1_ports, "AE1 wrongly kept AE3's dispatcher 3202"


def test_single_sid_host_unaffected_by_reconciliation(monkeypatch):
    """No-regression: on a single-SID host the gateway RFC SID and the
    SAPControl SID agree, so reconciliation is a no-op and the one node
    keeps all its ports."""
    scan = {
        "host": "10.10.1.5",
        "open_ports": {
            3200:  {"service": "dispatcher", "instance_nr": "00"},
            3300:  {"service": "gateway",    "instance_nr": "00"},
            50013: {"service": "sapcontrol", "instance_nr": "00"},
        },
    }
    _patch_build_probes(
        monkeypatch,
        gw_sid_by_port={3300: "NPL"},
        sapctl_sid_by_port={50013: "NPL"},
    )
    nodes = sapmap_scanner._build_nodes_from_fast_scan(scan, timeout=0.1)
    assert len(nodes) == 1
    assert nodes[0].sid == "NPL"
    assert {3200, 3300, 50013} <= _ports_of(nodes[0])


def test_reconcile_applies_on_dispatcher_plus_100_call_site(monkeypatch):
    """Cover the SECOND reconcile call site (the dispatcher+100 fallback).

    When the secondary system's gateway port was dropped by the CPIC verifier
    (3302 absent from open_ports) but is reachable via dispatcher+100, control
    skips the gateway branch and lands in the dispatcher+100 block — a
    structurally separate copy of the reconcile wiring that also feeds the
    CPIC port-recovery.  The RFC probe on the derived gateway still reports the
    PRIMARY SID (AE1); SAPControl 50213 reports AE3.  AE3 must own its
    dispatcher 3202 AND the recovered gateway 3302 — proving the reconciled SID
    (not the mis-reported AE1) drives the port-recovery attribution."""
    scan = {
        "host": "10.10.1.6",
        "open_ports": {
            3200:  {"service": "dispatcher", "instance_nr": "00"},
            3300:  {"service": "gateway",    "instance_nr": "00"},
            50013: {"service": "sapcontrol", "instance_nr": "00"},
            3202:  {"service": "dispatcher", "instance_nr": "02"},  # no 3302!
            50213: {"service": "sapcontrol", "instance_nr": "02"},
        },
    }
    _patch_build_probes(
        monkeypatch,
        # enrich on the derived gateway 3302 (3202+100) returns the PRIMARY SID.
        gw_sid_by_port={3300: "AE1", 3302: "AE1"},
        sapctl_sid_by_port={50013: "AE1", 50213: "AE3"},
    )
    nodes = sapmap_scanner._build_nodes_from_fast_scan(scan, timeout=0.1)
    by_sid = {n.sid: n for n in nodes}
    assert set(by_sid) == {"AE1", "AE3"}, (
        f"expected two distinct SID nodes, got {sorted(by_sid)}")
    ae3_ports = _ports_of(by_sid["AE3"])
    assert 3202 in ae3_ports, f"AE3 lost its dispatcher 3202 (got {sorted(ae3_ports)})"
    assert 3302 in ae3_ports, (
        f"AE3 did not receive the CPIC-recovered gateway 3302 — the "
        f"reconciled SID must drive the port-recovery attribution "
        f"(got {sorted(ae3_ports)})")
    ae1_ports = _ports_of(by_sid["AE1"])
    assert 3302 not in ae1_ports, "recovered gateway 3302 wrongly landed on AE1"
    assert 3202 not in ae1_ports, "AE3's dispatcher 3202 wrongly landed on AE1"


def test_sapcontrol_silent_falls_back_to_rfc_sid(monkeypatch):
    """Conservative degradation: when SAPControl is firewalled (silent) for
    the secondary instance, the builder can't know better and preserves the
    pre-fix RFC attribution rather than inventing a split.  Documents that
    the fix only acts on a POSITIVE SAPControl conflict."""
    _patch_build_probes(
        monkeypatch,
        gw_sid_by_port={3300: "AE1", 3302: "AE1"},   # both report AE1
        sapctl_sid_by_port={50013: "AE1"},           # 50213 silent -> ""
    )
    nodes = sapmap_scanner._build_nodes_from_fast_scan(_two_sid_scan(),
                                                       timeout=0.1)
    # Only AE1 resolves; both instances collapse onto it (unchanged legacy
    # behaviour — not the fix's job to guess without SAPControl).
    assert {n.sid for n in nodes} == {"AE1"}
    assert {3300, 3302, 3200, 3202} <= _ports_of(nodes[0])
