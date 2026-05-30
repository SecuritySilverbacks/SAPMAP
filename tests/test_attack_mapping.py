"""Tests for the MITRE ATT&CK mapping layer.

Covers:
  * Catalog integrity (every capability maps to real techniques; every
    technique points to a real tactic).
  * Finding round-trip preserves attack_techniques.
  * emit_finding() resolves capability key → technique IDs.
  * to_navigator_layer() emits a schema-conformant v4.5 layer.
  * heatmap_grid() aggregates correctly across findings.
  * collect_from_findings() works on both dataclasses and dicts.
"""
import json

import sapmap_attack
import sapmap_findings
from sapmap_models import Finding, SAPNode, SAPMAPState, Severity


# ---------------------------------------------------------------------------
# Catalog integrity
# ---------------------------------------------------------------------------

def test_every_mapped_technique_resolves():
    """Every T-ID listed in CAPABILITY_MAP must exist in TECHNIQUES."""
    bad = []
    for cap, tids in sapmap_attack.CAPABILITY_MAP.items():
        for tid in tids:
            if tid not in sapmap_attack.TECHNIQUES:
                bad.append((cap, tid))
    assert not bad, f"Unresolved T-IDs in CAPABILITY_MAP: {bad}"


def test_every_technique_points_to_real_tactic():
    bad = []
    for tid, info in sapmap_attack.TECHNIQUES.items():
        if info["tactic"] not in sapmap_attack.TACTICS:
            bad.append((tid, info["tactic"]))
    assert not bad, f"Techniques with unknown tactic: {bad}"


def test_subtechnique_parents_exist():
    """A sub-technique's ``sub_of`` must reference a parent technique."""
    bad = []
    for tid, info in sapmap_attack.TECHNIQUES.items():
        parent = info.get("sub_of")
        if parent and parent not in sapmap_attack.TECHNIQUES:
            bad.append((tid, parent))
    assert not bad, f"Sub-techniques pointing at unknown parents: {bad}"


def test_explicit_empty_mappings_present():
    """The plan explicitly enumerates which capabilities are un-mapped
    (info-only) — protect against accidental drop."""
    # SNC scan was added to the catalog after the initial round.
    assert "snc.scan" in sapmap_attack.CAPABILITY_MAP
    # Client enum is corrected to T1082, NOT T1087.002.
    assert sapmap_attack.CAPABILITY_MAP["recon.client_enum"] == ["T1082"]


def test_pinned_attack_version_set():
    assert sapmap_attack.ATTACK_VERSION.startswith("v")
    assert sapmap_attack.ATTACK_DOMAIN == "enterprise-attack"


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

def test_lookup_resolves_known():
    info = sapmap_attack.lookup("T1190")
    assert info is not None
    assert info["id"] == "T1190"
    assert info["name"] == "Exploit Public-Facing Application"
    assert info["tactic"] == "TA0001"
    assert info["tactic_name"] == "Initial Access"
    assert info["url"].startswith("https://attack.mitre.org/techniques/T1190/")


def test_lookup_subtechnique_url_uses_slash():
    info = sapmap_attack.lookup("T1078.001")
    assert info is not None
    assert info["url"] == "https://attack.mitre.org/techniques/T1078/001/"
    assert info["sub_of"] == "T1078"


def test_lookup_unknown_returns_none():
    assert sapmap_attack.lookup("T9999") is None


def test_techniques_for_capability():
    assert sapmap_attack.techniques_for("exploit.cve_2020_6287") == \
        ["T1190", "T1136.001"]
    # Unknown capability → empty (silent)
    assert sapmap_attack.techniques_for("nonexistent.thing") == []


def test_aggregate_by_tactic_groups_correctly():
    grouped = sapmap_attack.aggregate_by_tactic(
        ["T1190", "T1059", "T1078.001", "T1190"])
    assert grouped["TA0001"] == ["T1078.001", "T1190"]
    assert grouped["TA0002"] == ["T1059"]


# ---------------------------------------------------------------------------
# Finding model integration
# ---------------------------------------------------------------------------

def test_finding_attack_techniques_round_trips():
    f = Finding(
        name="test", severity=Severity.CRITICAL,
        attack_techniques=["T1190", "T1078.001"])
    d = f.to_dict()
    assert d["attack_techniques"] == ["T1190", "T1078.001"]
    revived = Finding.from_dict(d)
    assert revived.attack_techniques == ["T1190", "T1078.001"]


def test_finding_default_attack_techniques_is_empty():
    f = Finding(name="x", severity=Severity.INFO)
    assert f.attack_techniques == []


def test_finding_from_dict_backwards_compat_no_attack_field():
    """Old .sapmap state files predate attack_techniques — must still load."""
    revived = Finding.from_dict({
        "name": "legacy", "severity": int(Severity.HIGH),
        "description": "", "remediation": "", "detail": "",
    })
    assert revived.attack_techniques == []


# ---------------------------------------------------------------------------
# emit_finding integration
# ---------------------------------------------------------------------------

def test_emit_finding_resolves_capability_key():
    sapmap_findings.clear()
    rec = sapmap_findings.emit_finding(
        "CRITICAL", "S4H", "test finding",
        cve="CVE-XXX",
        attack_capability="exploit.cve_2020_6287",
    )
    assert rec is not None
    assert rec["attack_capability"] == "exploit.cve_2020_6287"
    assert rec["attack_techniques"] == ["T1190", "T1136.001"]


def test_emit_finding_accepts_explicit_technique_list():
    sapmap_findings.clear()
    rec = sapmap_findings.emit_finding(
        "HIGH", "S4D", "explicit test",
        attack_techniques=["T1059", "T1190"],
    )
    assert rec is not None
    # Order preserved, dedup applied
    assert rec["attack_techniques"] == ["T1059", "T1190"]


def test_emit_finding_merges_capability_and_explicit():
    sapmap_findings.clear()
    rec = sapmap_findings.emit_finding(
        "MEDIUM", "S4H", "merged test",
        attack_capability="exploit.cve_2025_31324",  # T1190, T1505.003
        attack_techniques=["T1078"],
    )
    assert "T1190" in rec["attack_techniques"]
    assert "T1505.003" in rec["attack_techniques"]
    assert "T1078" in rec["attack_techniques"]


def test_emit_finding_without_attack_kwargs_works():
    sapmap_findings.clear()
    rec = sapmap_findings.emit_finding(
        "INFO", "S4D", "no attack tag")
    assert rec is not None
    assert rec["attack_techniques"] == []
    assert rec["attack_capability"] == ""


# ---------------------------------------------------------------------------
# Bus → node.findings mirroring (so "View Findings" picks up live events)
# ---------------------------------------------------------------------------

def test_attach_state_mirrors_high_emit_to_node_findings():
    state = SAPMAPState()
    state.add_node(SAPNode(sid="S4H", ip="10.0.0.1"))
    sapmap_findings.attach_state(state)
    sapmap_findings.clear()

    sapmap_findings.emit_finding(
        "HIGH", "S4H", "Gateway SAPXPG accepted P1-P3",
        attack_capability="exploit.10kblaze")

    node = state.get_node("S4H")
    assert len(node.findings) == 1
    f = node.findings[0]
    assert f.name == "Gateway SAPXPG accepted P1-P3"
    assert f.severity == Severity.HIGH
    assert f.attack_techniques == ["T1190", "T1059"]

    sapmap_findings.attach_state(None)   # detach so other tests don't leak


def test_attach_state_skips_info_severity():
    state = SAPMAPState()
    state.add_node(SAPNode(sid="S4H", ip="10.0.0.1"))
    sapmap_findings.attach_state(state)
    sapmap_findings.clear()

    sapmap_findings.emit_finding("INFO", "S4H", "Auto-picker selected: copyfail")
    sapmap_findings.emit_finding("MEDIUM", "S4H", "Some medium event")

    node = state.get_node("S4H")
    assert node.findings == []   # neither INFO nor MEDIUM persist
    sapmap_findings.attach_state(None)


def test_attach_state_dedupes_repeat_emits():
    state = SAPMAPState()
    state.add_node(SAPNode(sid="S4H", ip="10.0.0.1"))
    sapmap_findings.attach_state(state)
    sapmap_findings.clear()

    for _ in range(3):
        sapmap_findings.emit_finding(
            "CRITICAL", "S4H", "Same exact message",
            attack_capability="exploit.cve_2020_6287")

    node = state.get_node("S4H")
    # One persistent entry even though we emitted 3 times.  Bus
    # may also dedupe within 60s — but the mirror is independent.
    assert len(node.findings) == 1
    sapmap_findings.attach_state(None)


def test_attach_state_unknown_sid_does_nothing():
    state = SAPMAPState()
    state.add_node(SAPNode(sid="S4H", ip="10.0.0.1"))
    sapmap_findings.attach_state(state)
    sapmap_findings.clear()

    sapmap_findings.emit_finding(
        "HIGH", "UNKNOWN_SID", "no such node",
        attack_capability="exploit.10kblaze")

    assert state.get_node("S4H").findings == []
    sapmap_findings.attach_state(None)


# ---------------------------------------------------------------------------
# Navigator JSON layer
# ---------------------------------------------------------------------------

def _make_state_with_findings():
    state = SAPMAPState()
    s4h = SAPNode(sid="S4H", ip="10.0.0.1")
    s4h.findings.append(Finding(
        name="RECON", severity=Severity.CRITICAL,
        detail="CVE-2020-6287",
        attack_techniques=["T1190", "T1136.001"]))
    s4d = SAPNode(sid="S4D", ip="10.0.0.2")
    s4d.findings.append(Finding(
        name="ICMAD", severity=Severity.HIGH,
        detail="CVE-2022-22536",
        attack_techniques=["T1190", "T1574"]))
    state.add_node(s4h)
    state.add_node(s4d)
    return state


def test_navigator_layer_schema_fields():
    state = _make_state_with_findings()
    layer = sapmap_attack.to_navigator_layer(state, name="t")
    # Required Navigator v4.5 fields
    assert layer["domain"] == "enterprise-attack"
    assert "techniques" in layer
    assert layer["versions"]["navigator"] == "4.5"
    assert layer["versions"]["layer"] == "4.5"
    # T1190 appears twice (CRITICAL on S4H, HIGH on S4D) — max wins
    t1190 = next(t for t in layer["techniques"]
                 if t["techniqueID"] == "T1190")
    assert t1190["score"] == int(Severity.CRITICAL)
    # T1574 only on S4D (HIGH)
    t1574 = next(t for t in layer["techniques"]
                 if t["techniqueID"] == "T1574")
    assert t1574["score"] == int(Severity.HIGH)


def test_navigator_layer_serialises():
    state = _make_state_with_findings()
    layer = sapmap_attack.to_navigator_layer(state)
    # Round-trips through JSON cleanly
    s = json.dumps(layer)
    assert json.loads(s) == layer


def test_navigator_layer_empty_state():
    state = SAPMAPState()
    layer = sapmap_attack.to_navigator_layer(state)
    assert layer["techniques"] == []


# ---------------------------------------------------------------------------
# Heatmap grid
# ---------------------------------------------------------------------------

def test_heatmap_grid_totals():
    state = _make_state_with_findings()
    g = sapmap_attack.heatmap_grid(state)
    # 3 unique techniques exercised: T1190, T1136.001, T1574
    assert g["totals"]["techniques"] == 3
    # Tactics: TA0001 (T1190, T1136.001 sub of T1078? actually T1136.001 parent T1136 in tactic TA0003) + TA0005 (T1574)
    # Actually T1190→TA0001, T1136.001→TA0003, T1574→TA0005
    assert g["totals"]["tactics"] == 3


def test_heatmap_grid_columns_in_tactic_order():
    state = _make_state_with_findings()
    g = sapmap_attack.heatmap_grid(state)
    tactic_ids = [col["tactic_id"] for col in g["columns"]]
    # Initial Access should come before Persistence per TACTIC_ORDER
    assert tactic_ids.index("TA0001") < tactic_ids.index("TA0003")


def test_heatmap_grid_cell_score_max_severity():
    state = _make_state_with_findings()
    g = sapmap_attack.heatmap_grid(state)
    # Find T1190 cell — must carry CRITICAL = 5
    for col in g["columns"]:
        for cell in col["cells"]:
            if cell["id"] == "T1190":
                assert cell["score"] == int(Severity.CRITICAL)
                assert set(cell["sids"]) == {"S4H", "S4D"}
                return
    raise AssertionError("T1190 cell not found")


# ---------------------------------------------------------------------------
# Collection helpers
# ---------------------------------------------------------------------------

def test_collect_from_findings_dedupes_and_handles_both_shapes():
    f1 = Finding(name="a", severity=Severity.HIGH,
                 attack_techniques=["T1190", "T1059"])
    f2_dict = {"attack_techniques": ["T1059", "T1078"]}
    tids = sapmap_attack.collect_from_findings([f1, f2_dict])
    # Dedup, order preserved
    assert tids == ["T1190", "T1059", "T1078"]


def test_collect_from_findings_skips_invalid_entries():
    tids = sapmap_attack.collect_from_findings([None, 42, "junk"])
    assert tids == []
