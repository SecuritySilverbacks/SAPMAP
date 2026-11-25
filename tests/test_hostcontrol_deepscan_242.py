"""Issue #242 — deep-scan (SAPology) parity for SAP(Host)Control.

The deep path delegates to SAPology.  SAPology probes the SAP Host Agent
(1128/1129) and, before SAPology 1.2.0, folded those ports onto the first SAP
instance's port map — so the SAMAP->SAPology bridge (`_sapology_system_to_node`)
reproduced the exact #91 mis-attribution on a deep scan.

These tests pin the bridge behaviour:
  * host-agent ports are read from `sys_obj.host_control_ports` (SAPology >=
    1.2.0) OR scanned out of the instance ports (older SAPology), and stripped
    from the SAPNode either way;
  * a HostControlNode is emitted via the `hostcontrol_sink`;
  * a host exposing ONLY the Host Agent yields no SAP node (just the entity);
  * a SAProuter is never linked to the Host Agent.

A lightweight mock `sys_obj` stands in for a SAPology SAPSystem so the suite
needs no SAPology install.  Dispatcher-only ports (32XX, no 33XX gateway) keep
the deep-scan SNC classifier from attempting a network probe.
"""
from types import SimpleNamespace

import pytest

import sapmap_scanner as S


def _inst(instance_nr, ports, services=None):
    return SimpleNamespace(instance_nr=instance_nr, ip="", ports=dict(ports),
                           services=services or {}, info={}, findings=[])


def _sys(sid, system_type="ABAP", instances=None, host_control_ports=None):
    return SimpleNamespace(
        sid=sid, system_type=system_type, instances=instances or [],
        hostname="", os_type="", db_type="", kernel="", sap_release="",
        clients=[], snc_partnername="",
        host_control_ports=host_control_ports or {})


def test_deep_colocated_new_sapology_strips_and_emits():
    # SAPology >= 1.2.0 exposes host_control_ports and keeps instances clean.
    sysobj = _sys("S4H", instances=[_inst("00", {3200: "disp"},
                                          {"dispatcher": {"port": 3200}})],
                  host_control_ports={1128: "SAPHostControl HTTP",
                                      1129: "SAPHostControl HTTPS"})
    hcs = []
    node = S._sapology_system_to_node(sysobj, "10.0.0.1",
                                      hostcontrol_sink=hcs.append)
    assert node is not None
    leaked = [p for i in node.instances for p in i.ports if p in (1128, 1129)]
    assert leaked == []
    assert len(hcs) == 1
    assert hcs[0].ports == {1128: "SAPHostControl HTTP",
                            1129: "SAPHostControl HTTPS"}
    assert hcs[0].linked_sids == ["S4H"]
    assert hcs[0].fingerprint_source == "sapology_deep"


def test_deep_old_sapology_fallback_strips_from_instance():
    # Older SAPology folded 1128/1129 onto the first instance and has no
    # host_control_ports field -> the bridge must scan + strip them.
    sysobj = _sys("ERP", instances=[_inst(
        "00", {3200: "disp", 1128: "saphost_http", 1129: "saphost_https"},
        {"dispatcher": {"port": 3200}})])
    hcs = []
    node = S._sapology_system_to_node(sysobj, "10.0.0.2",
                                      hostcontrol_sink=hcs.append)
    leaked = [p for i in node.instances for p in i.ports if p in (1128, 1129)]
    assert leaked == []
    assert len(hcs) == 1 and hcs[0].linked_sids == ["ERP"]


def test_deep_host_agent_only_returns_none():
    sysobj = _sys("UNKNOWN", instances=[],
                  host_control_ports={1128: "SAPHostControl HTTP"})
    hcs = []
    node = S._sapology_system_to_node(sysobj, "10.0.0.3",
                                      hostcontrol_sink=hcs.append)
    assert node is None
    assert len(hcs) == 1 and hcs[0].linked_sids == []


def test_deep_saprouter_emits_unlinked(monkeypatch):
    # A SAProuter co-located with a Host Agent: still plot the agent, but never
    # LINK the relay to it (mirrors the fast-path rule).
    monkeypatch.setattr(S, "_verify_saprouter", lambda *a, **k: True)
    sysobj = _sys("RD1", system_type="SAPROUTER",
                  instances=[_inst("99", {3299: "router"},
                                   {"saprouter": {"port": 3299}})],
                  host_control_ports={1128: "SAPHostControl HTTP"})
    hcs = []
    node = S._sapology_system_to_node(sysobj, "10.0.0.4",
                                      hostcontrol_sink=hcs.append)
    assert node is not None and node.system_type == "SAPROUTER"
    assert len(hcs) == 1 and hcs[0].linked_sids == []


def test_deep_no_sink_still_strips():
    # Even without a sink, 1128/1129 must not ride on the SAP node.
    sysobj = _sys("S4H", instances=[_inst("00", {3200: "disp"},
                                          {"dispatcher": {"port": 3200}})],
                  host_control_ports={1128: "SAPHostControl HTTP"})
    node = S._sapology_system_to_node(sysobj, "10.0.0.5")
    leaked = [p for i in node.instances for p in i.ports if p in (1128, 1129)]
    assert leaked == []


def test_upsert_merge_preserves_enrichment_and_unions_sids():
    # The clobber guard (adversarial review): a discovery pass must never wipe
    # an enriched/pwned entity or the operator's map position; SIDs accumulate.
    from sapmap_models import SAPMAPState, HostControlNode
    st = SAPMAPState()
    rich = HostControlNode(
        host="10.0.0.1", ip="10.0.0.1",
        ports={1128: "saphost_http"}, version="753", pwned=True,
        cves_confirmed=["CVE-2019-0330"], os_access_type="hostagent_sapadm",
        os_exec_capable=True, linked_sids=["S4H"], managed_sids=["S4H"],
        position=(42.0, 99.0), notes="operator note")
    st.host_control_nodes["10.0.0.1"] = rich
    # A minimal discovery node (deep scan) for the same host, different SID.
    disco = HostControlNode(
        host="10.0.0.1", ip="10.0.0.1", ports={1129: "saphost_https"},
        linked_sids=["ERP"], managed_sids=["ERP"],
        fingerprint_source="sapology_deep", reachable=True)
    merged = st.upsert_host_control_node(disco)
    assert merged is rich  # merged into the existing entity, not replaced
    # Enrichment preserved.
    assert rich.pwned is True and rich.version == "753"
    assert rich.cves_confirmed == ["CVE-2019-0330"]
    assert rich.os_access_type == "hostagent_sapadm" and rich.os_exec_capable
    assert rich.position == (42.0, 99.0) and rich.notes == "operator note"
    # Discovery fields accumulated.
    assert rich.ports == {1128: "saphost_http", 1129: "saphost_https"}
    assert rich.linked_sids == ["S4H", "ERP"]
    assert rich.managed_sids == ["S4H", "ERP"]
    assert rich.reachable is True
    assert len(st.host_control_nodes) == 1


def test_upsert_insert_when_new():
    from sapmap_models import SAPMAPState, HostControlNode
    st = SAPMAPState()
    hc = HostControlNode(host="10.0.0.2", ports={1128: "x"})
    st.upsert_host_control_node(hc)
    assert st.host_control_nodes["10.0.0.2"] is hc


def test_upsert_empty_host_is_noop():
    from sapmap_models import SAPMAPState, HostControlNode
    st = SAPMAPState()
    st.upsert_host_control_node(HostControlNode(host=""))
    assert st.host_control_nodes == {}


def test_deep_hostcontrol_node_helper():
    hc = S._deep_hostcontrol_node("10.0.0.9",
                                  {1128: "SAPHostControl HTTP"}, "S4H")
    assert hc.host == "10.0.0.9" and hc.linked_sids == ["S4H"]
    assert hc.managed_sids == ["S4H"] and hc.fingerprint_source == "sapology_deep"
    assert hc.findings and hc.findings[0].name.startswith("SAP Host Agent")
