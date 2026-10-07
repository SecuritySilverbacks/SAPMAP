"""Tests for parse_landscape_xml_into_state() — issue
SecuritySilverbacks/SAPMAP#105.

Covers three cases a real SAPGUILandscape.xml / SAP UI Landscape XML can carry:
  (A) <Service msid="…"/> linked to a <Messageserver uuid="…"/> with a real
      `systemid="SID"` attribute                                  → real SID
  (B) <Service msid="…"/> linked to a <Messageserver uuid="…"/> but with
      the SAP Logon placeholder `systemid="@01"` ("SID unknown")  → placeholder
  (C) <Service server="host:port"/> direct-connect, no messageserver link
      (the common case in SAPGUILandscape.xml exports)            → placeholder

Pre-#105 the importer only handled (A); (B) was imported with the literal
"@01" as SID, and (C) was silently dropped.  Both bugs manifested in the
operator's screenshot (only ONE node named "@01" after importing a 70-entry
landscape XML with multiple real SAP systems).
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import modules  # noqa: F401 — registers package paths

from sapmap_models import SAPMAPState, SAPNode, InstanceInfo
from sapmap_gui import parse_landscape_xml_into_state


# ---------------------------------------------------------------------------
# Shared synthetic landscape fixture
# ---------------------------------------------------------------------------

# All hostnames + UUIDs below are synthetic — do NOT replace with real
# operator landscape data.  Covers the three Service shapes documented
# in issue #105.
_SYNTHETIC_LANDSCAPE_XML = """<?xml version='1.0' encoding='UTF-8'?>
<Landscape version='1'>
  <Services>
    <!-- (C) three direct-connect services (no msid), unique endpoints -->
    <Service name='DEV sandbox' type='SAPGUI' uuid='c1-aaa'
             server='10.0.0.11:3200' mode='1'/>
    <Service name='PRD finance' type='SAPGUI' uuid='c2-aaa'
             server='10.0.0.12:3200' mode='1'/>
    <Service name='AT sandbox'  type='SAPGUI' uuid='c3-aaa'
             server='10.0.0.13:3210' mode='1'/>

    <!-- (C') duplicate endpoint — same host:port, different friendly name;
         should be deduped so we end up with one node for the endpoint -->
    <Service name='DEV sandbox (via SAProuter)' type='SAPGUI' uuid='c4-aaa'
             routerid='r1' server='10.0.0.11:3200' mode='1'/>

    <!-- (B) messageserver-linked service with SAP Logon sentinel SID -->
    <Service name='S4H msgserver friendly' type='SAPGUI' uuid='b1-aaa'
             systemid='@01' msid='msg-s4h' server='SPACE' mode='1'/>

    <!-- (A) messageserver-linked service with a real SID -->
    <Service name='NPL via msg' type='SAPGUI' uuid='a1-aaa'
             systemid='NPL' msid='msg-npl' server='SPACE' mode='1'/>

    <!-- Empty / sentinel server string ("SPACE") on direct-connect — skip -->
    <Service name='nothing to connect to' type='SAPGUI' uuid='x1-aaa'
             server='SPACE' mode='1'/>
  </Services>
  <Messageservers>
    <!-- Empty host — should NOT crash the importer -->
    <Messageserver uuid='msg-empty' name='MS' host='' port='0'/>
    <Messageserver uuid='msg-s4h'   name='@01' host='192.168.2.209' port='3601'/>
    <Messageserver uuid='msg-npl'   name='NPL' host='192.168.2.106' port='3601'/>
  </Messageservers>
</Landscape>
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def _import(xml_text, state=None):
    if state is None:
        state = SAPMAPState()
    summary = parse_landscape_xml_into_state(state, xml_text,
                                              no_scan_appservers=True)
    return state, summary


def test_direct_connect_services_are_imported():
    """Pre-#105 bug: <Service server="host:port"/> entries without a
    messageserver link were silently dropped — the operator's 70-entry
    landscape file produced ONE node.  Verify we now plot one node per
    unique direct-connect endpoint."""
    state, summary = _import(_SYNTHETIC_LANDSCAPE_XML)
    assert summary["status"] == "ok"
    # Three unique direct-connect endpoints + one messageserver-linked
    # NPL + one messageserver-linked @01-placeholder = 5 total.  The
    # fourth direct-connect ("via SAProuter") is a dup of the DEV one
    # and must be deduped.  The "SPACE"-only entry is skipped.
    assert len(summary["added"]) == 5, (
        f"expected 5 nodes, got {summary['added']}")
    assert len(summary["dupes"]) == 1, (
        "duplicate (10.0.0.11, 3200) endpoint must be deduped — got "
        f"{summary['dupes']}")


def test_at01_sentinel_sid_becomes_placeholder():
    """Pre-#105 bug: <Service systemid="@01" .../> was imported with
    the literal "@01" as the node's SID.  Verify we synthesize a
    placeholder SID (XML_<name-prefix>) and flag the node so a
    Standard Scan promotes it to the real SID via RFC_SYSTEM_INFO."""
    state, summary = _import(_SYNTHETIC_LANDSCAPE_XML)
    # No node should carry the literal "@01" SID any more.
    assert state.get_node("@01") is None, (
        "literal '@01' SID must NEVER make it into state — it's a SAP "
        "Logon sentinel, not a real SID")
    # The placeholder SID should start with XML_ and the node should
    # carry discovered_via_xml=True.
    placeholder_sids = [n.sid for n in state.nodes.values()
                        if n.discovered_via_xml]
    assert any(s.startswith("XML_") for s in placeholder_sids), (
        f"expected XML_ prefixed placeholder, got {placeholder_sids}")
    # The specific "@01" entry's name was "S4H msgserver friendly" →
    # placeholder SID derives to XML_S4H (first 3 alnum chars upper).
    assert "XML_S4H" in placeholder_sids


def test_real_systemid_imported_verbatim_without_placeholder_flag():
    """<Service systemid="NPL" .../> (NON-sentinel SID) must be
    imported with SID="NPL" and must NOT be flagged as a placeholder —
    the SID is already known, Standard Scan should MERGE new ports
    into it, not promote-replace."""
    state, _ = _import(_SYNTHETIC_LANDSCAPE_XML)
    npl = state.get_node("NPL")
    assert npl is not None, "real SID must be imported verbatim"
    assert npl.discovered_via_xml is False, (
        "a real systemid must NOT be flagged placeholder — the Standard "
        "Scan path would otherwise promote-replace a legitimate node")
    assert npl.ip == "192.168.2.106"


def test_space_literal_server_is_skipped():
    """SAP Logon writes `server="SPACE"` as a sentinel for "no server
    configured" on direct-connect entries.  Must not materialize a
    node with host="SPACE"."""
    state, _ = _import(_SYNTHETIC_LANDSCAPE_XML)
    assert not any(n.ip == "SPACE" for n in state.nodes.values()), (
        "`server=\"SPACE\"` is a SAP Logon sentinel — must be skipped")


def test_duplicate_endpoint_deduped_within_one_import():
    """Many landscape files carry a "direct" entry AND a sibling
    "via SAProuter" entry for the same backend.  (host, port) dedup
    collapses them so the map doesn't show two cards for the same
    endpoint; the first-seen entry wins."""
    state, _ = _import(_SYNTHETIC_LANDSCAPE_XML)
    # Exactly one DEV sandbox node even though the XML has it twice.
    dev_nodes = [n for n in state.nodes.values()
                 if n.ip == "10.0.0.11"
                 and n.instances
                 and 3200 in (n.instances[0].ports or {})]
    assert len(dev_nodes) == 1


def test_existing_real_sid_is_not_clobbered():
    """If a node with the same SID already exists in state (e.g. from
    a prior scan), the import must skip it — never overwrite a
    discovered node with a landscape-file guess."""
    state = SAPMAPState()
    # Pre-populate a real NPL node (as if a scan had already found it).
    state.add_node(SAPNode(sid="NPL", hostname="pre-existing.example",
                           ip="192.168.2.106",
                           instances=[InstanceInfo(instance_nr="00",
                                                   ip="192.168.2.106",
                                                   ports={3300: "gateway"})]))
    _, summary = _import(_SYNTHETIC_LANDSCAPE_XML, state=state)
    assert "NPL" in summary["skipped"], (
        "already-present SID must appear in `skipped` list, not clobbered")
    # The pre-existing node must still carry the original enrichment.
    npl = state.get_node("NPL")
    assert npl.hostname == "pre-existing.example"
    assert 3300 in (npl.instances[0].ports or {})


def test_messageserver_port_decoded_to_sapms_label():
    """A messageserver-linked service's port (3601) must be labeled
    "sapms" on the instance's ports map, not left blank."""
    state, _ = _import(_SYNTHETIC_LANDSCAPE_XML)
    npl = state.get_node("NPL")
    assert npl.instances[0].ports.get(3601) == "sapms"


def test_direct_connect_dispatcher_port_decoded_as_dispatcher():
    """A direct-connect service pointing at a 3200-3299 port is a
    SAPGUI dispatcher endpoint; label accordingly."""
    state, _ = _import(_SYNTHETIC_LANDSCAPE_XML)
    dev = [n for n in state.nodes.values() if n.ip == "10.0.0.11"][0]
    assert dev.instances[0].ports.get(3200) == "dispatcher"


def test_discovered_via_xml_survives_sapmap_roundtrip():
    """The new flag must be persisted in .sapmap state files so an
    operator can save+reload mid-engagement without losing the
    placeholder marker (and therefore the Standard Scan promotion
    semantics)."""
    node = SAPNode(sid="XML_S4H", hostname="192.168.2.209",
                   ip="192.168.2.209",
                   discovered_via_xml=True)
    state = SAPMAPState()
    state.add_node(node)
    reloaded = SAPMAPState.from_dict(json.loads(json.dumps(state.to_dict())))
    assert reloaded.get_node("XML_S4H").discovered_via_xml is True


def test_bad_xml_raises_value_error():
    """Malformed XML must raise ValueError (the Bottle route turns
    this into an error JSON reply)."""
    with pytest.raises(ValueError):
        parse_landscape_xml_into_state(SAPMAPState(), "<not valid xml")


def test_empty_messageserver_host_does_not_crash():
    """SAP Logon sometimes writes a stub <Messageserver host='' port='0'/>
    for a pending/unresolved entry.  The importer must not plot a
    node from such a messageserver, even if a Service points at it."""
    xml = """<?xml version='1.0' encoding='UTF-8'?>
<Landscape version='1'>
  <Services>
    <Service name='orphan msg-linked' type='SAPGUI' uuid='o1'
             systemid='ORP' msid='msg-empty' server='SPACE'/>
    <Service name='fine direct' type='SAPGUI' uuid='o2'
             server='10.0.0.99:3200'/>
  </Services>
  <Messageservers>
    <Messageserver uuid='msg-empty' name='MS' host='' port='0'/>
  </Messageservers>
</Landscape>"""
    state, summary = _import(xml)
    # ORP must NOT appear (empty-host messageserver → nothing to connect to).
    assert state.get_node("ORP") is None
    # The sibling direct-connect still works.
    assert len(summary["added"]) == 1
    assert summary["added"][0].startswith("XML_FIN")
