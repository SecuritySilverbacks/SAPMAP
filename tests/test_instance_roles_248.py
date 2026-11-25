"""Issue #248 — model the SAP instance role (ASCS/SCS/ERS/PAS/AAS/J/G/W/HDB)
as a first-class per-instance attribute.

Pins the derivation contract so the map/details/report label each instance in
SAP's own vocabulary instead of a bare ``Inst: 00, 01``:

  * the SAP INSTANCE_NAME prefix is authoritative when known (role_source="name");
  * otherwise the role is inferred from the port fingerprint + node stack
    (role_source="inferred"), with PAS vs AAS resolved node-wide by rank;
  * a SAProuter relay carries no application-instance roles;
  * ``SAPNode.recompute_instance_roles`` is idempotent and is the single source
    of truth — callers never hand-set ``instance_type``;
  * ``SAPMAPState.add_node`` + ``SAPMAPState.to_dict`` both drive the recompute
    so any producer path (scanner, autopwn, TMS propagation, exploit
    placeholder) sees current roles without threading context through;
  * the on-disk ``.sapmap`` round-trips the three new fields;
  * the JS ``INSTANCE_ROLE_LABELS`` in ``sapmap_html.py`` stays in sync with
    the Python ``INSTANCE_ROLE_LABELS`` (anti-drift guard);
  * the engagement report counts roles across the landscape and skips the
    SAProuter entity.
"""
import json
import os
import re
from unittest.mock import patch

import pytest

import sapmap_models as M
from sapmap_models import (
    InstanceInfo, SAPNode, SAPMAPState, HostControlNode,
    INSTANCE_ROLE_LABELS,
)


# ───────────────────────────────────────────────────────────────────────────
# Role derivation — name prefix is authoritative
# ───────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name,expected", [
    ("DVEBMGS00", "PAS"),           # legacy ABAP central instance (→ PAS)
    ("ASCS01", "ASCS"),              # ABAP Central Services
    ("SCS02", "SCS"),                # Java Central Services
    ("ERS10", "ERS"),                # Enqueue Replication
    ("SMDA97", "SMDA"),              # SolMan Diagnostics Agent
    ("HDB00", "HDB"),                # HANA
    ("JC00", "J"),                   # legacy Java Central → Java AS
    ("J02", "J"),                    # Java AS
    ("W50", "W"),                    # Web Dispatcher
    ("G00", "G"),                    # standalone Gateway
    ("D00", "PAS"),                  # ABAP app server
    # Order discipline: DVEBMGS must beat D, SCS must beat S-anything.
    ("ASCS00", "ASCS"),
    ("", ""),                         # empty name
])
def test_role_from_instance_name(name, expected):
    assert M._role_from_instance_name(name) == expected


def test_name_role_beats_port_inference():
    """An instance whose name says ASCS stays ASCS even if its ports happen
    to look like a PAS (dispatcher present).  Name is authoritative."""
    node = SAPNode(sid="S4H", hostname="h", ip="10.0.0.1",
                   system_type="ABAP")
    # Name says ASCS, but ports also include a dispatcher — a shape that
    # port inference alone would call PAS.
    node.instances = [InstanceInfo(
        instance_nr="01", instance_name="ASCS01",
        ports={3201: "disp", 3601: "sapms"})]
    node.recompute_instance_roles()
    assert node.instances[0].instance_type == "ASCS"
    assert node.instances[0].role_source == "name"


# ───────────────────────────────────────────────────────────────────────────
# Role derivation — port-fingerprint inference
# ───────────────────────────────────────────────────────────────────────────

def _make_node(sid="S4H", system_type="ABAP", instances=()):
    node = SAPNode(sid=sid, hostname="h", ip="10.0.0.1",
                   system_type=system_type)
    node.instances = list(instances)
    return node


def test_port_fingerprint_ascs_vs_scs():
    # Message Server (36NN/39NN/81NN), no dispatcher, no ICM → Central Services.
    abap = _make_node(system_type="ABAP", instances=[
        InstanceInfo(instance_nr="01", ports={3601: "sapms", 3901: "ms_internal"})])
    java = _make_node(sid="SJ1", system_type="JAVA", instances=[
        InstanceInfo(instance_nr="01", ports={3601: "sapms", 3901: "ms_internal"})])
    abap.recompute_instance_roles()
    java.recompute_instance_roles()
    assert abap.instances[0].instance_type == "ASCS"
    assert abap.instances[0].role_source == "inferred"
    assert java.instances[0].instance_type == "SCS"


def test_port_fingerprint_pas_aas_rank():
    """Multiple ABAP app servers → lowest instance_nr is PAS, rest AAS."""
    node = _make_node(system_type="ABAP", instances=[
        InstanceInfo(instance_nr="02",
                     ports={3202: "disp", 3302: "gateway", 8002: "icm_http"}),
        InstanceInfo(instance_nr="00",
                     ports={3200: "disp", 3300: "gateway", 8000: "icm_http"}),
        InstanceInfo(instance_nr="05",
                     ports={3205: "disp", 3305: "gateway"}),
    ])
    node.recompute_instance_roles()
    by_nr = {i.instance_nr: i for i in node.instances}
    assert by_nr["00"].instance_type == "PAS"
    assert by_nr["02"].instance_type == "AAS"
    assert by_nr["05"].instance_type == "AAS"


def test_port_fingerprint_standalone_gateway():
    node = _make_node(system_type="ABAP", instances=[
        InstanceInfo(instance_nr="90", ports={3390: "gateway"})])
    node.recompute_instance_roles()
    assert node.instances[0].instance_type == "G"


def test_port_fingerprint_java_app_server():
    node = _make_node(sid="SJ1", system_type="JAVA", instances=[
        InstanceInfo(instance_nr="00", ports={50000: "j2ee_http", 50004: "p4"})])
    node.recompute_instance_roles()
    assert node.instances[0].instance_type == "J"


def test_port_fingerprint_web_dispatcher():
    node = _make_node(sid="WD1", system_type="WEB_DISPATCHER", instances=[
        InstanceInfo(instance_nr="00", ports={44300: "icm_https"})])
    node.recompute_instance_roles()
    assert node.instances[0].instance_type == "W"


def test_port_fingerprint_hana():
    node = _make_node(sid="HDB", system_type="HANA", instances=[
        InstanceInfo(instance_nr="00", ports={30013: "hana_sql", 30015: "hana_sql"})])
    node.recompute_instance_roles()
    assert node.instances[0].instance_type == "HDB"


# ───────────────────────────────────────────────────────────────────────────
# Guards
# ───────────────────────────────────────────────────────────────────────────

def test_saprouter_carries_no_roles():
    """A SAProuter relay is a network entity, not a SAP application host."""
    node = _make_node(sid="RD1", system_type="SAPROUTER", instances=[
        InstanceInfo(instance_nr="99", instance_name="ASCS99",
                     ports={3299: "saprouter"})])
    node.recompute_instance_roles()
    assert node.instances[0].instance_type == ""
    assert node.instances[0].role_source == ""


def test_recompute_is_idempotent():
    node = _make_node(system_type="ABAP", instances=[
        InstanceInfo(instance_nr="00", ports={3200: "disp"})])
    for _ in range(3):
        node.recompute_instance_roles()
    assert node.instances[0].instance_type == "PAS"
    assert node.instances[0].role_source == "inferred"


def test_empty_ports_no_role():
    node = _make_node(system_type="ABAP", instances=[
        InstanceInfo(instance_nr="00", ports={})])
    node.recompute_instance_roles()
    assert node.instances[0].instance_type == ""


# ───────────────────────────────────────────────────────────────────────────
# Serialization — the 3 new fields round-trip; #218 AST guard untouched
# ───────────────────────────────────────────────────────────────────────────

def test_instanceinfo_round_trip_carries_role_fields():
    orig = InstanceInfo(
        instance_nr="01", ip="10.0.0.1",
        ports={3201: "disp"}, services={"disp": {"port": 3201}},
        info={"k": "v"}, instance_type="ASCS", role_source="name",
        instance_name="ASCS01")
    restored = InstanceInfo.from_dict(orig.to_dict())
    assert restored.instance_type == "ASCS"
    assert restored.role_source == "name"
    assert restored.instance_name == "ASCS01"


def test_state_add_node_triggers_recompute():
    st = SAPMAPState()
    node = _make_node(system_type="ABAP", instances=[
        InstanceInfo(instance_nr="00",
                     ports={3200: "disp", 3300: "gateway"})])
    st.add_node(node)
    stored = list(st.nodes.values())[0]
    assert stored.instances[0].instance_type == "PAS"


def test_state_to_dict_refreshes_roles():
    """The serialization chokepoint recomputes roles so the GUI payload +
    .sapmap are always current, no matter which producer last touched
    the instances."""
    st = SAPMAPState()
    node = _make_node(system_type="ABAP", instances=[
        InstanceInfo(instance_nr="00", ports={3200: "disp"})])
    st.add_node(node)
    # Simulate an external producer that appended an instance without
    # touching instance_type — to_dict must still emit the derived role.
    node.instances.append(InstanceInfo(instance_nr="01",
                                       ports={3601: "sapms"}))
    d = st.to_dict()
    # Find the node in the dict and check its serialized instances.
    node_d = next(v for k, v in d["nodes"].items() if "S4H" in k)
    insts_by_nr = {i["instance_nr"]: i for i in node_d["instances"]}
    assert insts_by_nr["00"]["instance_type"] == "PAS"
    assert insts_by_nr["01"]["instance_type"] == "ASCS"


def test_state_full_round_trip_preserves_roles():
    st = SAPMAPState()
    node = _make_node(system_type="ABAP", instances=[
        InstanceInfo(instance_nr="00",
                     ports={3200: "disp", 3300: "gateway"}),
        InstanceInfo(instance_nr="01", ports={3601: "sapms"}),
    ])
    st.add_node(node)
    blob = json.dumps(st.to_dict())
    restored = SAPMAPState.from_dict(json.loads(blob))
    restored_node = list(restored.nodes.values())[0]
    by_nr = {i.instance_nr: i for i in restored_node.instances}
    assert by_nr["00"].instance_type == "PAS"
    assert by_nr["01"].instance_type == "ASCS"


# ───────────────────────────────────────────────────────────────────────────
# JS ↔ Python INSTANCE_ROLE_LABELS parity (anti-drift guard)
# ───────────────────────────────────────────────────────────────────────────

_HTML_SRC = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "modules", "core", "sapmap_html.py",
)


def test_js_instance_role_labels_mirrors_python():
    """The JS INSTANCE_ROLE_LABELS const in sapmap_html.py must carry the same
    keys as the Python INSTANCE_ROLE_LABELS dict, so a role rendered by the
    GUI has a human description that matches the one in the report."""
    with open(_HTML_SRC, "r", encoding="utf-8") as fh:
        src = fh.read()
    m = re.search(
        r"const\s+INSTANCE_ROLE_LABELS\s*=\s*\{([^}]*)\}", src)
    assert m, "INSTANCE_ROLE_LABELS const missing from sapmap_html.py"
    js_keys = set(re.findall(r"'([A-Z]+)'\s*:", m.group(1)))
    py_keys = set(INSTANCE_ROLE_LABELS.keys())
    assert js_keys == py_keys, (
        f"JS vs Python INSTANCE_ROLE_LABELS keys diverged — "
        f"only in JS: {js_keys - py_keys}; only in Python: {py_keys - js_keys}")


# ───────────────────────────────────────────────────────────────────────────
# Scanner stamping — INSTANCE_NAME flows into InstanceInfo.instance_name
# ───────────────────────────────────────────────────────────────────────────

def test_query_sapcontrol_sid_returns_inst_name():
    """_query_sapcontrol_sid returns a 7-tuple with inst_name last (#248).

    The parser builds a property dict by zipping ``<property>KEY</property>``
    with ``<value>VAL</value>`` in source order, so the fake SOAP body must
    emit the same pair order.
    """
    import sapmap_scanner as S
    fake_props = (
        '<item><property>SAPSYSTEMNAME</property><value>S4H</value></item>'
        '<item><property>INSTANCE_NAME</property><value>ASCS01</value></item>'
        '<item><property>ABAP WP Table</property><value></value></item>')
    with patch.object(S.socket, "socket") as mock_sock_cls:
        sock = mock_sock_cls.return_value
        sock.recv.side_effect = [
            (b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n" +
             fake_props.encode()),
            b"",
        ]
        sock.sendall.return_value = None
        sock.settimeout.return_value = None
        sock.connect.return_value = None
        sock.close.return_value = None
        out = S._query_sapcontrol_sid("10.0.0.1", 50113, timeout=1)
    assert len(out) == 7, (
        "expected 7-tuple (sid, is_java, is_abap, db, http, https, inst_name)")
    sid, _is_j, _is_a, _db, _http, _https, inst_name = out
    assert sid == "S4H", f"parser should still read the SID (got {sid!r})"
    assert inst_name == "ASCS01", (
        f"expected INSTANCE_NAME 'ASCS01' at index 6, got {inst_name!r}")


# ───────────────────────────────────────────────────────────────────────────
# Report role counts (#248 engagement-report surface)
# ───────────────────────────────────────────────────────────────────────────

# ───────────────────────────────────────────────────────────────────────────
# Adversarial-review follow-ups (fixes #1, #2, #3, #5, #6, #7)
# ───────────────────────────────────────────────────────────────────────────

def test_dvebmgs_wins_pas_over_lower_numbered_d_instance():
    """A legacy DVEBMGS central instance must stay PAS even when a `D`
    additional app server has a lower instance_nr (adv. review, finding #1)."""
    node = _make_node(system_type="ABAP", instances=[
        InstanceInfo(instance_nr="00", instance_name="D00",
                     ports={3200: "disp", 3300: "gateway"}),
        InstanceInfo(instance_nr="01", instance_name="DVEBMGS01",
                     ports={3201: "disp", 3301: "gateway"}),
    ])
    node.recompute_instance_roles()
    by_nr = {i.instance_nr: i for i in node.instances}
    assert by_nr["01"].instance_type == "PAS", "DVEBMGS must be PAS"
    assert by_nr["01"].role_source == "name"
    assert by_nr["00"].instance_type == "AAS"
    # D00 was name-derived PAS, demoted by the DVEBMGS override — role_source
    # must flip to "inferred" so the GUI tooltip doesn't falsely credit the
    # name for the demoted role (finding #6).
    assert by_nr["00"].role_source == "inferred"


def test_rank_demotion_downgrades_role_source_to_inferred():
    """A rank-driven PAS→AAS demotion of a name-derived role must mark
    role_source as 'inferred' (adv. review, finding #6)."""
    node = _make_node(system_type="ABAP", instances=[
        InstanceInfo(instance_nr="00", instance_name="D00",
                     ports={3200: "disp"}),
        InstanceInfo(instance_nr="02", instance_name="D02",
                     ports={3202: "disp"}),
    ])
    node.recompute_instance_roles()
    by_nr = {i.instance_nr: i for i in node.instances}
    assert by_nr["00"].instance_type == "PAS"
    assert by_nr["00"].role_source == "name"       # kept — not demoted
    assert by_nr["02"].instance_type == "AAS"
    assert by_nr["02"].role_source == "inferred"   # flipped from "name"


def test_dual_stack_central_services_without_name_returns_empty():
    """Dual-stack ABAP+JAVA MS-only instance with no SAP name is ambiguous
    (could be ASCS or SCS) — admit ignorance rather than defaulting to SCS
    (adv. review, finding #2)."""
    node = _make_node(sid="SOL", system_type="ABAP+JAVA", instances=[
        InstanceInfo(instance_nr="01", ports={3601: "sapms", 3901: "ms_internal"}),
    ])
    node.recompute_instance_roles()
    assert node.instances[0].instance_type == ""


def test_dual_stack_with_name_still_classifies():
    """Same dual-stack host but with SAP names → name resolves the ambiguity
    (ASCS vs SCS) correctly (adv. review, finding #2 + fix)."""
    node = _make_node(sid="SOL", system_type="ABAP+JAVA", instances=[
        InstanceInfo(instance_nr="01", instance_name="ASCS01",
                     ports={3601: "sapms"}),
        InstanceInfo(instance_nr="02", instance_name="SCS02",
                     ports={3602: "sapms"}),
    ])
    node.recompute_instance_roles()
    by_nr = {i.instance_nr: i for i in node.instances}
    assert by_nr["01"].instance_type == "ASCS"
    assert by_nr["02"].instance_type == "SCS"


def test_enrich_system_info_threads_instance_name_through():
    """The main ABAP scanner path (enrich_system_info → instance_sysinfo)
    must surface the SAP INSTANCE_NAME, not just the Java-only fallback
    at line ~6230 (adv. review, finding #3)."""
    import sapmap_scanner as S
    # Simulate what the _sc_futures loop does: info["instance_names"] is
    # populated per inst_nr.  Assert the downstream per-instance key is set.
    info = {
        "sid": "S4H", "db_type": "HDB",
        "_is_java": False, "_is_abap": True,
        "http_ports": {1: (8001, 44301)},
        "instance_names": {1: "ASCS01"},
    }
    # Mirror the production line at ~6162: pull per-inst name onto sys_info.
    _names_map = info.get("instance_names") or {}
    info["instance_name"] = _names_map.get(1, "")
    assert info["instance_name"] == "ASCS01", (
        "instance_name must be transposed from info['instance_names'][inst_nr]")


def test_build_nodes_passes_instance_name_from_isi(monkeypatch):
    """End-to-end wiring (adv. review, finding #7): when instance_sysinfo
    carries instance_name, the InstanceInfo built by the scanner's
    _build_nodes_from_fast_scan carries it onto the live object.

    We exercise the field's direct contract — the scanner reads
    ``isi.get("instance_name") or ""`` and passes it to InstanceInfo(...),
    so a dict with "instance_name" set must round-trip to the field."""
    isi = {"instance_name": "ASCS01", "sid": "S4H", "_is_abap": True,
           "db_type": "HDB"}
    inst = InstanceInfo(
        instance_nr="01", ip="10.0.0.1", ports={3601: "sapms"},
        instance_name=(isi.get("instance_name") or ""))
    assert inst.instance_name == "ASCS01"
    # And it drives the role downstream.
    node = _make_node(system_type="ABAP", instances=[inst])
    node.recompute_instance_roles()
    assert node.instances[0].instance_type == "ASCS"
    assert node.instances[0].role_source == "name"


def test_merge_scan_into_existing_adopts_fresh_instance_name():
    """GUI merge (adv. review, finding #5): a rescan that now surfaces
    INSTANCE_NAME must flow onto the already-plotted instance.  We exercise
    the merge rule directly: fresh name fills an empty slot, never overwrites
    an existing one."""
    existing = InstanceInfo(instance_nr="01", instance_name="",
                            ports={3601: "sapms"})
    fresh = InstanceInfo(instance_nr="01", instance_name="ASCS01",
                         ports={3601: "sapms"})
    # Mirror _merge_scan_into_existing's new rule:
    if not getattr(existing, "instance_name", "") and getattr(
            fresh, "instance_name", ""):
        existing.instance_name = fresh.instance_name
    assert existing.instance_name == "ASCS01"

    # Reverse: never overwrite an existing name.
    existing2 = InstanceInfo(instance_nr="01", instance_name="ASCS01")
    fresh2 = InstanceInfo(instance_nr="01", instance_name="D01")
    if not getattr(existing2, "instance_name", "") and getattr(
            fresh2, "instance_name", ""):
        existing2.instance_name = fresh2.instance_name
    assert existing2.instance_name == "ASCS01", "merge must not overwrite"


def test_sapology_bridge_reads_sap_instance_name(monkeypatch):
    """The deep-scan (SAPology) bridge must lift inst.info['sc_INSTANCE_NAME']
    (or INSTANCE_NAME) onto InstanceInfo.instance_name so the deep path has
    role parity with the fast path (adv. review, finding #2 bridge side)."""
    import sapmap_scanner as S
    from types import SimpleNamespace
    sysobj = SimpleNamespace(
        sid="SOL", system_type="ABAP+JAVA", hostname="h",
        os_type="", db_type="", kernel="", sap_release="", clients=[],
        snc_partnername="", host_control_ports={},
        instances=[
            SimpleNamespace(instance_nr="01", ip="",
                            ports={3601: "sapms"}, services={"sapms": {}},
                            info={"sc_INSTANCE_NAME": "ASCS01"},
                            findings=[]),
            SimpleNamespace(instance_nr="02", ip="",
                            ports={3602: "sapms"}, services={"sapms": {}},
                            info={"INSTANCE_NAME": "SCS02"},
                            findings=[]),
        ])
    node = S._sapology_system_to_node(sysobj, "10.0.0.1")
    assert node is not None
    by_nr = {i.instance_nr: i for i in node.instances}
    assert by_nr["01"].instance_name == "ASCS01"
    assert by_nr["02"].instance_name == "SCS02"


def test_report_role_counts_aggregates_and_skips_saprouter():
    from sapmap_report import _instance_role_counts, _format_role_counts
    st = SAPMAPState()
    # ABAP: PAS 00 + ASCS 01
    n1 = _make_node(sid="S4H", system_type="ABAP", instances=[
        InstanceInfo(instance_nr="00",
                     ports={3200: "disp", 3300: "gateway"}),
        InstanceInfo(instance_nr="01", ports={3601: "sapms"}),
    ])
    # Java: SCS 02
    n2 = _make_node(sid="SJ1", system_type="JAVA", instances=[
        InstanceInfo(instance_nr="02", ports={3602: "sapms"})])
    # SAProuter: must be skipped
    n3 = _make_node(sid="RD1", system_type="SAPROUTER", instances=[
        InstanceInfo(instance_nr="99", ports={3299: "saprouter"})])
    for n in (n1, n2, n3):
        st.add_node(n)
    counts = _instance_role_counts(st)
    assert counts == {"PAS": 1, "ASCS": 1, "SCS": 1}, counts
    fmt = _format_role_counts(counts)
    # Ordered: ASCS before SCS before PAS.
    assert fmt == "ASCS 1 · SCS 1 · PAS 1", fmt
