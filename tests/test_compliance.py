#!/usr/bin/env python3
"""Tests for compliance-framework tagging on findings + reports (issue #28).

Mirrors the MITRE ATT&CK tagging: a central catalog keyed on the same
capability keys, tags threaded through emit_finding -> record -> node Finding,
and rendered in the Markdown/HTML report.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "core"))

import sapmap_attack as A          # noqa: E402
import sapmap_compliance as C      # noqa: E402
import sapmap_findings             # noqa: E402
from sapmap_findings import emit_finding  # noqa: E402
from sapmap_models import (        # noqa: E402
    SAPMAPState, SAPNode, Finding, Severity,
)
from sapmap_report import build_markdown_report, build_html_report  # noqa: E402


# ---------------------------------------------------------------------------
# Catalog integrity
# ---------------------------------------------------------------------------

def test_compliance_map_keys_are_real_capabilities():
    """Every COMPLIANCE_MAP key must exist in sapmap_attack.CAPABILITY_MAP —
    the two catalogs stay in lockstep (one capability taxonomy)."""
    dangling = set(C.COMPLIANCE_MAP) - set(A.CAPABILITY_MAP)
    assert not dangling, f"compliance keys not in CAPABILITY_MAP: {sorted(dangling)}"


def test_every_framework_id_used_is_registered():
    used = {f for ids in C.COMPLIANCE_MAP.values() for f in ids}
    unknown = used - set(C.FRAMEWORKS)
    assert not unknown, f"framework IDs used but not in FRAMEWORKS: {sorted(unknown)}"


def test_shipped_frameworks_present():
    for fid in ("SOX", "GDPR", "NIS2", "ISO27001", "DORA"):
        assert fid in C.FRAMEWORKS
        assert C.FRAMEWORKS[fid].get("url", "").startswith("http")
        assert C.FRAMEWORKS[fid].get("control_area")


def test_frameworks_for_resolution():
    assert C.frameworks_for("exploit.sapxpg") == ["SOX", "GDPR", "NIS2",
                                                  "ISO27001", "DORA"]
    assert C.frameworks_for("recon.fast_scan") == []    # deliberately un-mapped
    assert C.frameworks_for("does.not.exist") == []     # unknown -> []


def test_framework_details_resolves_and_orders():
    det = C.framework_details(["DORA", "SOX", "BOGUS", "SOX"])
    ids = [d["id"] for d in det]
    assert ids == ["SOX", "DORA"]              # ordered + deduped + unknown dropped
    assert det[0]["name"] == "SOX" and det[0]["url"].startswith("http")


# ---------------------------------------------------------------------------
# emit_finding -> record -> node Finding
# ---------------------------------------------------------------------------

@pytest.fixture
def clean_bus():
    sapmap_findings.clear()
    yield
    sapmap_findings.clear()


def test_emit_finding_tags_from_capability(clean_bus):
    state = SAPMAPState()
    state.add_node(SAPNode(sid="AE1", ip="10.0.0.1"))
    sapmap_findings.attach_state(state)
    rec = emit_finding("CRITICAL", "AE1", "Gateway RCE",
                       attack_capability="exploit.sapxpg")
    assert rec["compliance_tags"] == ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"]
    # mirrored onto the node Finding
    node = state.get_node("AE1")
    assert node.findings and node.findings[-1].compliance_tags == \
        ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"]


def test_emit_finding_merges_explicit_tags(clean_bus):
    rec = emit_finding("HIGH", "AE1", "client enum",
                       attack_capability="recon.client_enum",
                       compliance=["PCI-DSS"])
    # map gives NIS2/ISO27001; explicit adds PCI-DSS (unknown IDs allowed in)
    assert rec["compliance_tags"] == ["NIS2", "ISO27001", "PCI-DSS"]


def test_emit_finding_without_capability_has_no_tags(clean_bus):
    rec = emit_finding("INFO", "AE1", "informational note")
    assert rec["compliance_tags"] == []


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def test_finding_serialization_roundtrip():
    f = Finding(name="x", severity=Severity.HIGH,
                compliance_tags=["SOX", "GDPR"])
    d = f.to_dict()
    assert d["compliance_tags"] == ["SOX", "GDPR"]
    assert Finding.from_dict(d).compliance_tags == ["SOX", "GDPR"]


def test_legacy_finding_without_field_loads():
    """Old .sapmap files have no compliance_tags key -> defaults to []."""
    f = Finding.from_dict({"name": "y", "severity": 5})
    assert f.compliance_tags == []


# ---------------------------------------------------------------------------
# Aggregation helpers
# ---------------------------------------------------------------------------

def test_collect_and_counts_from_findings():
    fs = [
        Finding(name="a", severity=Severity.CRITICAL,
                compliance_tags=["SOX", "GDPR", "NIS2"]),
        Finding(name="b", severity=Severity.HIGH,
                compliance_tags=["NIS2", "ISO27001"]),
        Finding(name="c", severity=Severity.INFO, compliance_tags=[]),
    ]
    assert C.collect_from_findings(fs) == ["SOX", "GDPR", "NIS2", "ISO27001"]
    counts = C.counts_from_findings(fs)
    assert counts == {"SOX": 1, "GDPR": 1, "NIS2": 2, "ISO27001": 1}


# ---------------------------------------------------------------------------
# Report rendering (Markdown + HTML)
# ---------------------------------------------------------------------------

def _state_with_tagged_findings():
    state = SAPMAPState()
    n = SAPNode(sid="AE1", system_type="ABAP", ip="10.0.0.1",
                hostname="abex3", pwned=True)
    n.findings.append(Finding(
        name="Gateway SAPXPG unauth RCE", severity=Severity.CRITICAL,
        description="unauth OS command execution",
        compliance_tags=["SOX", "GDPR", "NIS2", "ISO27001", "DORA"]))
    n.findings.append(Finding(
        name="SecStore decrypted", severity=Severity.HIGH,
        description="RFC destination passwords recovered",
        compliance_tags=["SOX", "GDPR", "NIS2", "ISO27001"]))
    state.add_node(n)
    return state


def test_markdown_report_has_compliance_line_and_section():
    import re
    md = build_markdown_report(_state_with_tagged_findings())
    assert "**Compliance:**" in md                 # per-finding line
    assert "## Compliance coverage" in md           # coverage section
    # Coverage table must report the ACTUAL per-framework counts: SOX appears
    # on both findings (2), DORA on only the first (1).
    assert re.search(r"\|\s*\[SOX\]\([^)]+\)\s*\|\s*2\s*\|", md)
    assert re.search(r"\|\s*\[DORA\]\([^)]+\)\s*\|\s*1\s*\|", md)
    assert re.search(r"\|\s*\[GDPR\]\([^)]+\)\s*\|\s*2\s*\|", md)


def test_report_renders_non_catalog_framework_tag():
    """An explicit framework ID not in the registry (the advertised extension
    path) must appear in the per-finding line AND the coverage table — not just
    one of them."""
    import re
    state = SAPMAPState()
    n = SAPNode(sid="AE1", ip="10.0.0.1")
    n.findings.append(Finding(name="client enum", severity=Severity.HIGH,
                              compliance_tags=["NIS2", "PCI-DSS"]))
    state.add_node(n)
    md = build_markdown_report(state)
    # coverage table counts it
    assert re.search(r"PCI-DSS\s*\|\s*1\s*\|", md)
    # per-finding Compliance line (before the coverage section) also carries it
    per_finding = md[md.index("**Compliance:**"):md.index("## Compliance coverage")]
    assert "PCI-DSS" in per_finding and "NIS2" in per_finding


def _fw_block(md, name):
    """Extract a framework's subsection from the 'Findings by framework' list
    — from its '**NAME** (' header to the next framework header or disclaimer."""
    import re
    start = md.index(f"**{name}** (")
    rest = md[start + 2:]
    nxt = re.search(r"\n\*\*|\n_Tags are indicative", rest)
    end = start + 2 + nxt.start() if nxt else len(md)
    return md[start:end]


def test_report_lists_which_findings_per_framework():
    """The reverse index: a reader can see WHICH findings map to each
    framework, not just a count."""
    state = _state_with_tagged_findings()
    md = build_markdown_report(state)
    assert "### Findings by framework" in md
    # DORA tags only the RCE finding; SecStore is NOT under DORA.
    dora = _fw_block(md, "DORA")
    assert "Gateway SAPXPG unauth RCE" in dora
    assert "SecStore decrypted" not in dora
    # NIS2 tags both.
    nis2 = _fw_block(md, "NIS2")
    assert ("Gateway SAPXPG unauth RCE" in nis2
            and "SecStore decrypted" in nis2)
    # the SID is shown so the reader can locate the finding
    assert "`AE1`" in nis2

    html = build_html_report(state)
    assert "Findings by framework" in html
    assert "<details" in html
    assert "Gateway SAPXPG unauth RCE" in html and "SecStore decrypted" in html


def test_html_report_has_compliance_section():
    html = build_html_report(_state_with_tagged_findings())
    assert 'id="sec-compliance"' in html
    assert "Compliance coverage" in html
    assert "ISO 27001" in html                      # resolved display name


def test_report_omits_compliance_when_no_tags():
    state = SAPMAPState()
    n = SAPNode(sid="AE1", ip="10.0.0.1")
    n.findings.append(Finding(name="untagged", severity=Severity.HIGH))
    state.add_node(n)
    md = build_markdown_report(state)
    assert "## Compliance coverage" not in md
    assert 'id="sec-compliance"' not in build_html_report(state)
