"""Standard Scan rescan-merge semantics for already-fingerprinted nodes.

Pinned request (2026-07-09): the operator ran a Type-G SAPControl
destination against SJJ (Windows Java stack, only port 50200
recorded via the SAPControl.CGI URL), then wanted Check GW
Vulnerability — which needs a gateway port (33NN) on the node.
Standard Scan is the natural way to sweep for more ports, but the
menu option was hidden because SJJ was already fingerprinted (no
``discovered_via_btp`` / ``_via_wd_sid`` / ``_via_rfc_g`` flag).

Enabling Standard Scan on real nodes had a hidden cost: the pre-fix
node-callback replaced the whole SAPNode with the scanner's output,
wiping credentials / findings / pwned / CVE flags on any node the
operator had already worked.

Fix: the scan callback branches on the node's discovery flags —
placeholders continue to be PROMOTED (destructive replace);
already-fingerprinted nodes are RESCANNED (merge new ports and
instances into place, preserve everything else).  The pin here is
on the pure merge helper.

We test the merge in isolation via a small copy of the closure —
the closure isn't exposed as a module-level function to keep the
GUI wiring compact, but its shape is small enough to re-express and
verify against the SJJ scenario.
"""
from __future__ import annotations

import modules  # noqa: F401  (registers package paths)
from sapmap_models import (
    SAPNode, InstanceInfo, Credentials, Finding, Severity)


def _merge_scan_into_existing(existing, scanned):
    """Same shape as the inline helper in
    modules/core/sapmap_gui.py::_kick_standard_scan._merge_scan_into_existing.
    Keep the two in sync — the test pins the contract."""
    for si in (scanned.instances or []):
        match = None
        for ei in (existing.instances or []):
            if ei.instance_nr == si.instance_nr:
                match = ei
                break
        if match is None:
            existing.instances.append(si)
        else:
            for p, lbl in (si.ports or {}).items():
                match.ports.setdefault(p, lbl)
            if not match.ip and si.ip:
                match.ip = si.ip
    for attr in ("hostname", "ip", "os_type", "system_type",
                 "sap_release", "kernel", "database"):
        if not getattr(existing, attr, "") and getattr(scanned, attr, ""):
            setattr(existing, attr, getattr(scanned, attr))


# ---------------------------------------------------------------------------
# Ports merge
# ---------------------------------------------------------------------------

def test_rescan_adds_new_ports_on_existing_instance():
    """SJJ live scenario: Inst 02 currently has only :50200/icm-http;
    the sweep discovers :3302/gateway.  Merge must add the gateway
    port to the same InstanceInfo — the operator can then run
    Check GW Vulnerability."""
    sjj = SAPNode(sid="SJJ", ip="192.168.2.192",
                   instances=[InstanceInfo(
                       instance_nr="02", ip="192.168.2.192",
                       ports={50200: "icm-http"})])
    scanned = SAPNode(sid="SJJ", ip="192.168.2.192",
                       instances=[InstanceInfo(
                           instance_nr="02", ip="192.168.2.192",
                           ports={3302: "gateway",
                                  3202: "dispatcher"})])

    _merge_scan_into_existing(sjj, scanned)

    ports = sjj.instances[0].ports
    assert 50200 in ports and ports[50200] == "icm-http", (
        "existing port must be preserved")
    assert 3302 in ports and ports[3302] == "gateway", (
        "gateway port must be merged in — this is the whole point "
        "of the rescan (enables Check GW Vulnerability)")
    assert 3202 in ports and ports[3202] == "dispatcher"


def test_rescan_appends_new_instance_when_nr_differs():
    """A rescan may discover a sibling instance (e.g. Inst 00
    alongside the known Inst 02).  Append rather than clobber."""
    n = SAPNode(sid="SJJ", ip="192.168.2.192",
                 instances=[InstanceInfo(
                     instance_nr="02", ip="192.168.2.192",
                     ports={50200: "icm-http"})])
    scanned = SAPNode(sid="SJJ", ip="192.168.2.192",
                       instances=[InstanceInfo(
                           instance_nr="00", ip="192.168.2.192",
                           ports={3300: "gateway"})])
    _merge_scan_into_existing(n, scanned)

    insts = {i.instance_nr for i in n.instances}
    assert insts == {"00", "02"}


def test_rescan_does_not_overwrite_existing_port_label():
    """When a port already carries a label, keep it — the scanner's
    heuristic label is usually less accurate than what a previous
    fingerprint recorded."""
    n = SAPNode(sid="SJJ",
                 instances=[InstanceInfo(
                     instance_nr="02",
                     ports={50200: "icm-http"})])
    scanned = SAPNode(sid="SJJ",
                       instances=[InstanceInfo(
                           instance_nr="02",
                           ports={50200: "http"})])  # weaker label
    _merge_scan_into_existing(n, scanned)
    assert n.instances[0].ports[50200] == "icm-http"


# ---------------------------------------------------------------------------
# Enrichment preservation
# ---------------------------------------------------------------------------

def test_rescan_preserves_credentials():
    """Rescan must not touch credentials — the SAPMAP-created user
    on SJJ (visible in the modal's Created Users block) must survive
    a rescan; wiping it would break every subsequent RFC operation."""
    n = SAPNode(sid="SJJ", ip="192.168.2.192",
                 instances=[InstanceInfo(
                     instance_nr="02", ports={50200: "icm-http"})])
    n.credentials.append(Credentials(
        username="SAPMAP00", password="Andinyougo123!",
        client="000", verified=True))

    scanned = SAPNode(sid="SJJ",
                       instances=[InstanceInfo(
                           instance_nr="02", ports={3302: "gateway"})])
    _merge_scan_into_existing(n, scanned)

    assert len(n.credentials) == 1
    assert n.credentials[0].username == "SAPMAP00"
    assert n.credentials[0].verified is True


def test_rescan_preserves_findings():
    """Findings drive the map's severity styling and the report.
    Rescan must not drop them."""
    n = SAPNode(sid="SJJ",
                 instances=[InstanceInfo(instance_nr="02")])
    n.findings.append(Finding(
        name="CVE-2025-31324 exploited",
        severity=Severity.CRITICAL,
        description="JSP webshell dropped on :50200"))
    scanned = SAPNode(sid="SJJ",
                       instances=[InstanceInfo(
                           instance_nr="02", ports={3302: "gateway"})])
    _merge_scan_into_existing(n, scanned)
    assert len(n.findings) == 1
    assert n.findings[0].name == "CVE-2025-31324 exploited"


def test_rescan_preserves_pwned_and_cve_flags():
    """Attack markers (``pwned``, CVE flags, etc.) are set by
    exploit paths, not discovery.  Rescan must leave them alone."""
    n = SAPNode(sid="SJJ", pwned=True,
                 cve_2025_31324_vulnerable=True,
                 cve_2025_31324_port=50200,
                 instances=[InstanceInfo(instance_nr="02")])
    scanned = SAPNode(sid="SJJ",
                       instances=[InstanceInfo(instance_nr="02")])
    _merge_scan_into_existing(n, scanned)
    assert n.pwned is True
    assert n.cve_2025_31324_vulnerable is True
    assert n.cve_2025_31324_port == 50200


# ---------------------------------------------------------------------------
# Metadata backfill
# ---------------------------------------------------------------------------

def test_rescan_fills_missing_metadata():
    """When existing has empty hostname / os_type / kernel etc.,
    a rescan that discovers them should backfill."""
    n = SAPNode(sid="SJJ", ip="192.168.2.192",
                 instances=[InstanceInfo(instance_nr="02")])
    scanned = SAPNode(sid="SJJ", ip="192.168.2.192",
                       hostname="sjj.corp",
                       os_type="Windows NT",
                       kernel="753",
                       instances=[InstanceInfo(instance_nr="02")])
    _merge_scan_into_existing(n, scanned)
    assert n.hostname == "sjj.corp"
    assert n.os_type == "Windows NT"
    assert n.kernel == "753"


def test_rescan_does_not_overwrite_populated_metadata():
    """When existing already knows os_type / kernel, don't let a
    weaker fingerprint clobber."""
    n = SAPNode(sid="SJJ", os_type="Windows NT", kernel="753",
                 instances=[InstanceInfo(instance_nr="02")])
    scanned = SAPNode(sid="SJJ", os_type="Windows",
                       kernel="750",   # older / weaker guess
                       instances=[InstanceInfo(instance_nr="02")])
    _merge_scan_into_existing(n, scanned)
    assert n.os_type == "Windows NT"
    assert n.kernel == "753"
