"""Issue #91 — SAP(Host)Control as a first-class entity.

The SAP Host Agent (SAPHostControl, TCP 1128 HTTP / 1129 HTTPS) is a
HOST-level service.  Historically its ports were folded onto whichever SAP
SID shared the host (the "Inst XX / ports 1128,1129" symptom).  This suite
pins the fix:

  * the SAP node builder NO LONGER attaches an 'XX' host-agent instance to a
    co-located SAP node (the ports are stripped before the pseudo-instance
    can form), while real SAP nodes are still built;
  * _maybe_build_hostcontrol_node plots a dedicated HostControlNode (gated to
    avoid clutter on a bare non-SAP 1128/1129);
  * HostControlNode and the new state.host_control_nodes collection
    round-trip through .sapmap and count toward stats();
  * the exploit-discovery path (_probe_and_add_host) stops stamping 1128 onto
    a SAP instance and registers a HostControlNode instead.

These are ADDITIVE assertions — the existing
tests/test_scanner_false_positive_scc_only.py contract (saphost-only -> no
SAP node) is deliberately left untouched and still green.
"""
import pytest

import sapmap_scanner as S
import sapmap_models as M
from sapmap_models import (SAPMAPState, SAPNode, HostControlNode, InstanceInfo)


# ---------------------------------------------------------------------------
# HostControlNode model round-trip
# ---------------------------------------------------------------------------

def test_hostcontrol_node_roundtrip():
    h = HostControlNode(
        host="10.0.0.1", ip="10.0.0.1",
        ports={1128: "saphost_http", 1129: "saphost_https"},
        version="753", sid_primary="S4H",
        managed_sids=["S4H"], linked_sids=["S4H", "ERP"],
        os_access_type="hostagent_sapadm", os_exec_capable=True,
        fingerprint_source="hostagent_soap", pwned=True,
        position=(10.0, 20.0),
    )
    d = h.to_dict()
    assert d["kind"] == "hostcontrol"
    # JSON serializes dict keys as strings — round-trip must restore int keys.
    assert set(d["ports"].keys()) == {"1128", "1129"}
    h2 = HostControlNode.from_dict(d)
    assert h2.ports == {1128: "saphost_http", 1129: "saphost_https"}
    assert h2.linked_sids == ["S4H", "ERP"]
    assert h2.os_exec_capable is True and h2.pwned is True
    assert h2.position == (10.0, 20.0)


def test_hostcontrol_from_dict_tolerates_garbage():
    # Unknown keys dropped; missing keys defaulted; never raises.
    h = HostControlNode.from_dict({"host": "x", "bogus": 1, "ports": "nope"})
    assert h.host == "x"


# ---------------------------------------------------------------------------
# State collection round-trip + stats
# ---------------------------------------------------------------------------

def test_state_roundtrip_and_stats_count():
    st = SAPMAPState()
    st.nodes["S4H"] = SAPNode(sid="S4H", system_type="ABAP", ip="10.0.0.1")
    st.host_control_nodes["10.0.0.1"] = HostControlNode(
        host="10.0.0.1", ip="10.0.0.1",
        ports={1128: "saphost_http"}, pwned=True)
    d = st.to_dict()
    assert "host_control_nodes" in d
    st2 = SAPMAPState.from_dict(d)
    assert "10.0.0.1" in st2.host_control_nodes
    assert st2.host_control_nodes["10.0.0.1"].ports == {1128: "saphost_http"}
    # 1 SAP node + 1 host-control entity = 2 systems; the pwned agent counts.
    s = st2.stats()
    assert s["systems"] == 2
    assert s["pwned"] == 1


def test_old_state_without_key_loads_clean():
    # Back-compat: a .sapmap saved before #91 has no host_control_nodes key.
    st = SAPMAPState.from_dict({"nodes": {}, "connections": []})
    assert st.host_control_nodes == {}


# ---------------------------------------------------------------------------
# Scanner: the SAP node no longer carries the 'XX' host-agent instance
# ---------------------------------------------------------------------------

def _mixed_scan():
    return {
        "host": "10.1.1.100",
        "open_ports": {
            3200:  {"service": "dispatcher",    "instance_nr": "00"},
            3300:  {"service": "gateway",       "instance_nr": "00"},
            50013: {"service": "sapcontrol",    "instance_nr": "00"},
            1128:  {"service": "saphost_http",  "instance_nr": "XX"},
            1129:  {"service": "saphost_https", "instance_nr": "XX"},
        },
    }


def test_saphost_ports_not_attached_to_sap_node():
    nodes = S._build_nodes_from_fast_scan(_mixed_scan(), timeout=1,
                                          verbose=False)
    assert nodes, "a real SAP system must still be built from 32xx/33xx"
    xx = [i for n in nodes for i in n.instances if i.instance_nr == "XX"]
    assert xx == [], "host-agent 'XX' instance must not ride on the SAP node"
    # And no SAP instance should carry 1128/1129 under any instance number.
    leaked = [p for n in nodes for i in n.instances
              for p in (i.ports or {}) if p in (1128, 1129)]
    assert leaked == [], f"host-agent ports leaked onto a SAP instance: {leaked}"


# ---------------------------------------------------------------------------
# Scanner: _maybe_build_hostcontrol_node
#   (saprouter='/H/x' is passed to SKIP the live SOAP probe so the test does
#    no network I/O and relies purely on co-located corroboration)
# ---------------------------------------------------------------------------

def test_hostcontrol_builds_with_colocated_sid():
    hc = S._maybe_build_hostcontrol_node(
        _mixed_scan(), co_located_sids=["S4H"], saprouter="/H/x")
    assert hc is not None
    assert hc.ports == {1128: "saphost_http", 1129: "saphost_https"}
    assert hc.linked_sids == ["S4H"]
    assert hc.fingerprint_source == "scan"
    assert hc.findings and hc.findings[0].name.startswith("SAP Host Agent")


def test_hostcontrol_excludes_saprouter_from_managed():
    # A SAProuter co-located on the host is a network relay, not a SAP
    # system the Host Agent manages — it must NOT appear in the Host
    # Agent's managed/linked list or earn a topology edge to it
    # (operator-reported on 192.168.2.209: RD1 SAProuter wrongly linked).
    nodes = [SAPNode(sid="S4H", system_type="ABAP"),
             SAPNode(sid="S4D", system_type="HANA"),
             SAPNode(sid="RD1", system_type="SAPROUTER")]
    sids = S._hostcontrol_colocated_sids(nodes)
    assert sids == ["S4H", "S4D"]
    hc = S._maybe_build_hostcontrol_node(
        _mixed_scan(), co_located_sids=sids, saprouter="/H/x")
    assert hc is not None
    assert "RD1" not in hc.linked_sids
    assert hc.linked_sids == ["S4H", "S4D"]


def test_hostcontrol_not_built_without_signal():
    # Bare 1128/1129, no SAP system discovered, no agent answer -> no node.
    bare = {"host": "10.9.9.9",
            "open_ports": {1128: {"service": "saphost_http",
                                  "instance_nr": "XX"}}}
    assert S._maybe_build_hostcontrol_node(
        bare, co_located_sids=[], saprouter="/H/x") is None


def test_hostcontrol_none_when_no_saphost_ports():
    # A host with only an SCC admin port (no saphost) must not produce a
    # HostControlNode — the saphost filter must not divert scc_admin.
    scc_only = {"host": "10.1.1.4",
                "open_ports": {8443: {"service": "scc_admin",
                                      "instance_nr": "WD"}}}
    assert S._maybe_build_hostcontrol_node(
        scc_only, co_located_sids=["S4H"], saprouter="/H/x") is None


# ---------------------------------------------------------------------------
# Exploit-discovery path: _probe_and_add_host (issue #91)
# ---------------------------------------------------------------------------

def test_probe_and_add_host_routes_1128_to_hostcontrol(monkeypatch):
    import sapmap_exploit as E
    import sapmap_scanner as _scn

    # Discovery via the Host Agent: quick_probe_sid returns source_port 1128.
    monkeypatch.setattr(_scn, "quick_probe_sid", lambda *a, **k: {
        "sid": "HCX", "instance_nr": "00",
        "is_abap": True, "is_java": False,
        "source_port": 1128,
    })
    # Make sure the per-process cache doesn't short-circuit us.
    E._sid_probe_cache.clear()

    st = SAPMAPState()
    sid = E._probe_and_add_host(st, "10.2.2.2")
    assert sid == "HCX"

    node = st.nodes.get("HCX")
    assert node is not None
    leaked = [p for i in node.instances for p in (i.ports or {})
              if p in (1128, 1129)]
    assert leaked == [], ("1128/1129 must not be stamped onto the SAP "
                          f"instance; got {leaked}")

    # The Host Agent fact is preserved as a dedicated entity instead.
    assert "10.2.2.2" in st.host_control_nodes
    hc = st.host_control_nodes["10.2.2.2"]
    assert hc.ports.get(1128) == "saphost_http"
    assert "HCX" in hc.linked_sids
    assert hc.fingerprint_source == "exploit_probe"


def test_rename_node_sid_rewrites_hostcontrol_links():
    st = SAPMAPState()
    st.nodes["UNK_10_0_0_1"] = SAPNode(sid="UNK_10_0_0_1", ip="10.0.0.1")
    st.host_control_nodes["10.0.0.1"] = HostControlNode(
        host="10.0.0.1", ports={1128: "saphost_http"},
        sid_primary="UNK_10_0_0_1",
        linked_sids=["UNK_10_0_0_1"], managed_sids=["UNK_10_0_0_1"])
    err = st.rename_node_sid("UNK_10_0_0_1", "S4H")
    assert err == ""
    hc = st.host_control_nodes["10.0.0.1"]
    assert hc.linked_sids == ["S4H"]
    assert hc.managed_sids == ["S4H"]
    assert hc.sid_primary == "S4H"


def test_report_surfaces_hostcontrol():
    import sapmap_report as R
    st = SAPMAPState()
    st.nodes["S4H"] = SAPNode(sid="S4H", system_type="ABAP", ip="10.0.0.1")
    st.host_control_nodes["10.0.0.1"] = HostControlNode(
        host="10.0.0.1", ports={1128: "saphost_http", 1129: "saphost_https"},
        version="793", linked_sids=["S4H"], os_exec_capable=True)
    # Dedicated section lists the host agent.
    sec = "\n".join(R._hostcontrol_section(st))
    assert "SAP(Host)Control" in sec and "10.0.0.1" in sec and "S4H" in sec
    # Executive-summary KPI counts it as a system (1 SAP + 1 host agent).
    es = "\n".join(R._executive_summary(st))
    assert "SAP(Host)Control (Host Agent)" in es
    # HTML report KPI total must include it: with 1 SAP + 1 host agent the
    # "Systems pwned" card reads 0/2 (regression guard for the HTML
    # undercount the review caught — it previously omitted host_control_nodes).
    html = R.build_html_report(st)
    assert "0/2" in html


def test_probe_and_add_host_non_hostagent_unaffected(monkeypatch):
    import sapmap_exploit as E
    import sapmap_scanner as _scn

    # SID discovered via SAPControl (source_port 50013) — NOT the Host Agent.
    monkeypatch.setattr(_scn, "quick_probe_sid", lambda *a, **k: {
        "sid": "SCT", "instance_nr": "00",
        "is_abap": True, "is_java": False,
        "source_port": 50013,
    })
    E._sid_probe_cache.clear()

    st = SAPMAPState()
    sid = E._probe_and_add_host(st, "10.3.3.3")
    assert sid == "SCT"
    # No host-agent discovery -> no HostControl entity, 50013 kept as before.
    assert "10.3.3.3" not in st.host_control_nodes
    node = st.nodes["SCT"]
    has_sapcontrol = any(p == 50013 for i in node.instances
                         for p in (i.ports or {}))
    assert has_sapcontrol
