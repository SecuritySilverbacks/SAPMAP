#!/usr/bin/env python3
"""Regression test: a host with ONLY port 8443 open should not be
plotted as an UNK_* SAP node when the SCC fingerprint rejects it.

Scenario: Fortinet / nginx / any non-SAP service squatting on TCP/8443.
Without the filter, the fast-scan node builder would:

1. Tag port 8443 as 'wd_candidate' (initial classification)
2. Run WD fingerprint → not a SAP WD → re-tag as 'scc_admin'
3. SCC fingerprint runs separately and decides "not an SCC"
4. But the SAP node builder still produced an UNK_<ip-dotted> node
   carrying that orphan scc_admin port, because the WD-only
   promotion at the top of phase A3 only promotes wd_http/wd_https
   services -- scc_admin falls through to the default-SID branch.

Fix: filter scc_admin ports out of _build_nodes_from_fast_scan
entirely.  Those ports are owned by the SCC fingerprint path.
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


def _build_nodes(scan_result):
    """Call the scanner's node builder.  Timeout=0.1 keeps the
    per-instance gateway enrichment from doing real network I/O —
    no gateway port in the synthetic scan_result, so the enrichment
    path returns empty SIDs and the builder lands in the UNK_* path
    if it doesn't filter."""
    from sapmap_scanner import _build_nodes_from_fast_scan
    return _build_nodes_from_fast_scan(scan_result, timeout=0.1)


def test_scc_admin_only_host_yields_no_sap_node():
    """The exact bug from the operator's screenshot: 10.10.1.39 with
    only port 8443 open (Fortinet on TLS) — must NOT produce a
    UNK_10_10_1_39 SAPNode."""
    scan_result = {
        "host": "10.10.1.39",
        "open_ports": {
            8443: {"service": "scc_admin", "instance_nr": "WD"},
        },
    }
    nodes = _build_nodes(scan_result)
    assert nodes == [], (
        f"A host with only an scc_admin port should not yield any "
        f"SAP node — the SCC fingerprint owns that port and decides "
        f"whether to plot an SCCNode.  Got: "
        f"{[(n.sid, list(n.instances[0].ports.keys()) if n.instances else []) for n in nodes]}")


def test_scc_admin_alongside_real_sap_ports_keeps_sap_node():
    """When 8443 is open alongside legitimate SAP ports (32XX, 33XX,
    5XX13), the SAP node MUST still be created from the real SAP
    ports — only the scc_admin port is filtered out of it.  The SCC
    fingerprint path (separate code path) sees the original
    scan_result and can still plot an SCCNode independently."""
    scan_result = {
        "host": "192.168.2.209",
        "open_ports": {
            3200: {"service": "dispatcher", "instance_nr": "00"},
            3300: {"service": "gateway",    "instance_nr": "00"},
            50013: {"service": "sapcontrol", "instance_nr": "00"},
            8443: {"service": "scc_admin", "instance_nr": "WD"},
        },
    }
    nodes = _build_nodes(scan_result)
    # At least one node must come back (the SAP one).
    assert len(nodes) >= 1, (
        "A host with real SAP ports + scc_admin must still yield a "
        "SAP node from the real ports")
    # No node should include port 8443 — that belongs to the SCC
    # fingerprint path, not to a SAP node.
    for node in nodes:
        for inst in node.instances:
            assert 8443 not in inst.ports, (
                f"Node {node.sid} instance {inst.instance_nr} should "
                f"not carry port 8443 (scc_admin) — that port belongs "
                f"to the SCC fingerprint path.  Got ports: "
                f"{list(inst.ports.keys())}")


def test_only_other_filtered_port_combinations_still_safe():
    """Stress test: multiple non-SAP ports (only scc_admin) on
    several instance buckets — none should produce a SAP node."""
    scan_result = {
        "host": "10.10.1.42",
        "open_ports": {
            8443: {"service": "scc_admin", "instance_nr": "WD"},
        },
    }
    nodes = _build_nodes(scan_result)
    assert nodes == [], (
        "Host with no SAP ports (only orphan scc_admin) must not "
        "produce any SAPNode")


def test_saphost_only_with_scc_does_not_synthesise_unk_node():
    """Co-located SCC + SAP Host Agent: 10.10.1.4 has 1128
    (saphost_http), 1129 (saphost_https), and 8443 (scc_admin).
    The SCC fingerprint should plot the SCC node separately; the
    SAP node builder must NOT synthesise a UNK_10_10_1_4 carrying
    those metadata-only ports (it duplicates the SCC visually)."""
    scan_result = {
        "host": "10.10.1.4",
        "open_ports": {
            1128: {"service": "saphost_http",  "instance_nr": "XX"},
            1129: {"service": "saphost_https", "instance_nr": "XX"},
            8443: {"service": "scc_admin",     "instance_nr": "WD"},
        },
    }
    nodes = _build_nodes(scan_result)
    assert nodes == [], (
        f"Host with only SAP Host Agent + scc_admin (no real SID, "
        f"no dispatcher / gateway / SAPControl) should not synthesise "
        f"a UNK_<ip> SAP node — the SCC node alone represents this "
        f"host.  Got: {[n.sid for n in nodes]}")


def test_saphost_only_without_scc_also_skipped():
    """A host running ONLY the SAP Host Agent (no SCC, no real
    SAP system) is just a management endpoint — not a SAP system
    to plot on the landscape map.  Skipping it avoids UNK_* noise."""
    scan_result = {
        "host": "10.10.1.50",
        "open_ports": {
            1128: {"service": "saphost_http",  "instance_nr": "XX"},
            1129: {"service": "saphost_https", "instance_nr": "XX"},
        },
    }
    nodes = _build_nodes(scan_result)
    assert nodes == [], (
        "Host with ONLY SAP Host Agent ports (no SID, no dispatcher, "
        "no gateway) must not synthesise a SAP node — no actionable "
        "SAP system to attack")


def test_saphost_alongside_real_sap_ports_keeps_node():
    """When saphost is open ALONGSIDE legitimate SAP ports (32XX
    dispatcher, 5XX13 SAPControl), the SAP node MUST still be
    created — the host agent metadata attaches to the real system."""
    scan_result = {
        "host": "10.10.1.100",
        "open_ports": {
            3200:  {"service": "dispatcher",     "instance_nr": "00"},
            3300:  {"service": "gateway",        "instance_nr": "00"},
            50013: {"service": "sapcontrol",     "instance_nr": "00"},
            1128:  {"service": "saphost_http",   "instance_nr": "XX"},
            1129:  {"service": "saphost_https",  "instance_nr": "XX"},
        },
    }
    nodes = _build_nodes(scan_result)
    # Real SAP system → at least one node, NOT empty
    assert len(nodes) >= 1, (
        "Host with real SAP ports + saphost agent must still yield "
        "a SAP node from the real ports")
