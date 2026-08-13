#!/usr/bin/env python3
"""Tests for sapmap_models.py — dataclass round-trips, risk levels, state management."""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sapmap_models import (
    Credentials,
    CreatedUser,
    InstanceInfo,
    RFCConnection,
    SAPNode,
    SAPMAPState,
)


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

def test_credentials_roundtrip():
    cred = Credentials(
        username="SAPMAP00",
        password="Secret123!",
        client="100",
        instance_nr="01",
        verified=True,
    )
    d = cred.to_dict()
    restored = Credentials.from_dict(d)
    assert restored.username == cred.username
    assert restored.password == cred.password
    assert restored.client == cred.client
    assert restored.instance_nr == cred.instance_nr
    assert restored.verified == cred.verified


# ---------------------------------------------------------------------------
# SAPNode
# ---------------------------------------------------------------------------

def test_sapnode_roundtrip():
    inst = InstanceInfo(instance_nr="00", ip="10.0.0.1", ports={3200: "open"})
    cred = Credentials(username="DDIC", password="pass", client="000", verified=True)
    secstore = [{"ident": "RFC_DEST", "password": "s3cret", "category": "RFC"}]

    node = SAPNode(
        sid="S4H",
        system_type="ABAP",
        hostname="s4hana",
        ip="10.0.0.1",
        instances=[inst],
        credentials=[cred],
        secstore_entries=secstore,
        gw_vulnerable=True,
        gw_vulnerable_port=3300,
    )
    d = node.to_dict()
    restored = SAPNode.from_dict(d)

    assert restored.sid == "S4H"
    assert restored.system_type == "ABAP"
    assert restored.hostname == "s4hana"
    assert restored.ip == "10.0.0.1"
    assert len(restored.instances) == 1
    assert restored.instances[0].instance_nr == "00"
    assert restored.instances[0].ports == {3200: "open"}
    assert len(restored.credentials) == 1
    assert restored.credentials[0].username == "DDIC"
    assert restored.secstore_entries == secstore
    assert restored.gw_vulnerable is True
    assert restored.gw_vulnerable_port == 3300
    # MS betrusted fields default to safe values
    assert restored.ms_port == 0
    assert restored.ms_vulnerable is False
    assert restored.ms_acl_protected is False


def test_sapnode_ms_fields_roundtrip():
    node = SAPNode(
        sid="S4H",
        ms_port=3901,
        ms_vulnerable=True,
        ms_acl_protected=False,
    )
    d = node.to_dict()
    restored = SAPNode.from_dict(d)
    assert restored.ms_port == 3901
    assert restored.ms_vulnerable is True
    assert restored.ms_acl_protected is False


def test_sapnode_ms_acl_protected_roundtrip():
    node = SAPNode(sid="ERP", ms_port=3900, ms_acl_protected=True)
    d = node.to_dict()
    restored = SAPNode.from_dict(d)
    assert restored.ms_port == 3900
    assert restored.ms_vulnerable is False
    assert restored.ms_acl_protected is True


def test_sapnode_from_dict_missing_ms_fields_defaults():
    """Older saved states without MS fields load cleanly with defaults."""
    d = SAPNode(sid="OLD").to_dict()
    del d["ms_port"]
    del d["ms_vulnerable"]
    del d["ms_acl_protected"]
    restored = SAPNode.from_dict(d)
    assert restored.ms_port == 0
    assert restored.ms_vulnerable is False
    assert restored.ms_acl_protected is False


# ---------------------------------------------------------------------------
# RFCConnection
# ---------------------------------------------------------------------------

def test_rfcconnection_roundtrip():
    conn = RFCConnection(
        source_sid="S4H",
        source_host="s4hana",
        target_sid="ERP",
        target_host="erp01",
        destination_name="ERP_100",
        rfc_user="RFC_USER",
        has_sap_all=True,
        logon_successful=True,
        tested=True,
        secstore_password="decrypted_pw",
    )
    d = conn.to_dict()
    restored = RFCConnection.from_dict(d)

    assert restored.source_sid == "S4H"
    assert restored.target_sid == "ERP"
    assert restored.destination_name == "ERP_100"
    assert restored.has_sap_all is True
    assert restored.logon_successful is True
    assert restored.secstore_password == "decrypted_pw"


def test_rfcconnection_create_user_reach_fields_roundtrip():
    """Issue #23 — the fine-grained create-user reach signal survives
    to_dict / from_dict, including the None sentinel for the never-
    probed state."""
    conn = RFCConnection(
        source_sid="S4H", source_host="s4hana",
        target_sid="ERP", destination_name="ERP_100",
        rfc_user="RFC_USER",
        can_create_user=True,
        can_assign_sap_all=True,
        can_assign_role=False,
        create_user_probe="authority_check",
        create_user_evidence="S_USER_GRP 01/SUPER + S_USER_PRO 22/SAP_ALL",
        create_user_probe_at="2026-08-08T12:00:00+00:00",
    )
    d = conn.to_dict()
    restored = RFCConnection.from_dict(d)
    assert restored.can_create_user is True
    assert restored.can_assign_sap_all is True
    assert restored.can_assign_role is False
    assert restored.create_user_probe == "authority_check"
    assert "S_USER_GRP" in restored.create_user_evidence
    assert restored.create_user_probe_at.startswith("2026-08-08")

    # Default (never probed) round-trips as None
    fresh = RFCConnection(source_sid="X", source_host="x")
    assert fresh.can_create_user is None
    d2 = fresh.to_dict()
    restored2 = RFCConnection.from_dict(d2)
    assert restored2.can_create_user is None
    assert restored2.create_user_probe == ""


def test_rfcconnection_from_dict_unknown_keys():
    d = {
        "source_sid": "S4H",
        "source_host": "s4hana",
        "future_field": "some_value",
        "another_unknown": 42,
    }
    conn = RFCConnection.from_dict(d)
    assert conn.source_sid == "S4H"
    assert conn.source_host == "s4hana"
    # Unknown keys silently ignored — no crash
    assert not hasattr(conn, "future_field")


def test_rfcconnection_risk_level():
    # CRITICAL: has_sap_all + logon_successful
    conn = RFCConnection(
        source_sid="A", source_host="a",
        has_sap_all=True, logon_successful=True,
    )
    assert conn.risk_level() == "CRITICAL"

    # MEDIUM: logon_successful only
    conn = RFCConnection(
        source_sid="A", source_host="a",
        logon_successful=True,
    )
    assert conn.risk_level() == "MEDIUM"

    # LOW: tested but logon failed
    conn = RFCConnection(
        source_sid="A", source_host="a",
        tested=True, logon_successful=False,
    )
    assert conn.risk_level() == "LOW"

    # UNKNOWN: default
    conn = RFCConnection(source_sid="A", source_host="a")
    assert conn.risk_level() == "UNKNOWN"


# ---------------------------------------------------------------------------
# SAPNode.best_credentials priority
# ---------------------------------------------------------------------------

def test_best_credentials_priority():
    # 1) Created users take priority
    cu = CreatedUser(
        username="SAPMAP00", sid="S4H", client="000",
        hostname="s4hana", ip="10.0.0.1", instance_nr="00",
        method="gw_exploit", password="Exploit123!",
    )
    verified_cred = Credentials(
        username="DDIC", password="pass", client="000", verified=True,
    )
    unverified_cred = Credentials(
        username="SAP*", password="pass2", client="000", verified=False,
    )
    node = SAPNode(
        sid="S4H",
        created_users=[cu],
        credentials=[verified_cred, unverified_cred],
    )
    best = node.best_credentials()
    assert best is not None
    assert best.username == "SAPMAP00"
    assert best.password == "Exploit123!"
    assert best.verified is True

    # 2) Without created users, verified credentials first
    node2 = SAPNode(sid="ERP", credentials=[unverified_cred, verified_cred])
    best2 = node2.best_credentials()
    assert best2 is not None
    assert best2.username == "DDIC"
    assert best2.verified is True

    # 3) Only unverified — returns first anyway
    node3 = SAPNode(sid="DEV", credentials=[unverified_cred])
    best3 = node3.best_credentials()
    assert best3 is not None
    assert best3.username == "SAP*"

    # 4) Empty node — None
    node4 = SAPNode(sid="QAS")
    assert node4.best_credentials() is None


# ---------------------------------------------------------------------------
# SAPMAPState — node management
# ---------------------------------------------------------------------------

def test_sapmapstate_add_node():
    state = SAPMAPState()
    node = SAPNode(sid="S4H", hostname="s4hana", ip="10.0.0.1")
    state.add_node(node)

    retrieved = state.get_node("S4H")
    assert retrieved is not None
    assert retrieved.sid == "S4H"
    assert retrieved.hostname == "s4hana"


def test_sapmapstate_add_connection():
    state = SAPMAPState()
    state.add_node(SAPNode(sid="S4H", ip="10.0.0.1"))
    state.add_node(SAPNode(sid="ERP", ip="10.0.0.2"))

    conn = RFCConnection(
        source_sid="S4H", source_host="s4hana",
        target_sid="ERP", destination_name="ERP_100",
    )
    state.add_connection(conn)

    from_s4h = state.get_connections_from("S4H")
    assert len(from_s4h) == 1
    assert from_s4h[0].destination_name == "ERP_100"

    to_erp = state.get_connections_to("ERP")
    assert len(to_erp) == 1
    assert to_erp[0].source_sid == "S4H"


def test_sapmapstate_dedup_connection():
    state = SAPMAPState()
    conn1 = RFCConnection(
        source_sid="S4H", source_host="s4hana",
        target_sid="ERP", destination_name="ERP_100",
        rfc_user="USER1",
    )
    conn2 = RFCConnection(
        source_sid="S4H", source_host="s4hana",
        target_sid="ERP", destination_name="ERP_100",
        rfc_user="USER2",
    )
    state.add_connection(conn1)
    state.add_connection(conn2)

    # Should not duplicate — second call updates in place
    assert len(state.connections) == 1
    assert state.connections[0].rfc_user == "USER2"


def test_state_stats_pwned_includes_sccs():
    """Status bar should count SCCs with .pwned = True alongside SAP
    nodes.  Without this, the live map shows N lightning bolts but the
    counter shows N-k where k is the number of pwned SCCs (off-by-one
    surprise observed in the field)."""
    state = SAPMAPState()
    n1 = SAPNode(sid="S4P", system_type="ABAP", pwned=True)
    n2 = SAPNode(sid="S4D", system_type="ABAP", pwned=False)
    state.add_node(n1)
    state.add_node(n2)

    class _SCC:
        def __init__(self, host, pwned):
            self.host = host
            self.pwned = pwned
        def to_dict(self):
            return {"host": self.host, "pwned": self.pwned}

    state.scc_nodes["scc1"] = _SCC("scc1", pwned=True)
    state.scc_nodes["scc2"] = _SCC("scc2", pwned=False)

    s = state.stats()
    # 1 SAP pwned + 1 SCC pwned = 2 (SAP-only count would be 1)
    assert s["pwned"] == 2


def test_state_stats_pwned_zero_when_no_sccs_no_pwned_nodes():
    state = SAPMAPState()
    state.add_node(SAPNode(sid="S4D", system_type="ABAP", pwned=False))
    assert state.stats()["pwned"] == 0


def test_track_created_user_enriches_node_clients_with_verified_client():
    """When a user is successfully created on a client we didn't have
    a T000 read for, the client gets added to node.clients with
    category 'V' (verified-via-user-creation).  Without this the System
    Details modal shows "None enumerated" even after we've proven the
    client exists by creating a user there — operator screenshot
    showed exactly this: SAPMAP00 listed under Created Users with
    "Client 001", but Clients section said None."""
    from sapmap_models import CreatedUser
    state = SAPMAPState()
    state.add_node(SAPNode(sid="W74", system_type="ABAP"))

    state.track_created_user(CreatedUser(
        username="SAPMAP00", sid="W74", client="001",
        hostname="winwas74", ip="192.168.2.29",
        instance_nr="40", method="soap_rfc_via_secstore"))

    node = state.get_node("W74")
    assert any(c["nr"] == "001" and c["category"] == "V"
               for c in node.clients)


def test_track_created_user_does_not_duplicate_existing_client():
    """If the client was already enumerated via T000 (category 'P' or
    'C'), track_created_user must not append a second entry — the modal
    would render the same client twice."""
    from sapmap_models import CreatedUser
    state = SAPMAPState()
    n = SAPNode(sid="W74", system_type="ABAP")
    n.clients = [{"nr": "001", "category": "P"}]
    state.add_node(n)

    state.track_created_user(CreatedUser(
        username="SAPMAP00", sid="W74", client="001",
        hostname="h", ip="i", instance_nr="40",
        method="soap_rfc_via_secstore"))

    nrs = [c["nr"] for c in state.get_node("W74").clients]
    assert nrs == ["001"]
    # Category 'P' must NOT get downgraded to 'V'
    assert state.get_node("W74").clients[0]["category"] == "P"


def test_track_created_user_pads_short_client_to_three_digits():
    """Operators (or SecStore data) sometimes carry the client as '1'
    or '10'.  Node.clients always stores 3-digit form so dedup and
    the modal display are consistent."""
    from sapmap_models import CreatedUser
    state = SAPMAPState()
    state.add_node(SAPNode(sid="W74", system_type="ABAP"))
    state.track_created_user(CreatedUser(
        username="U", sid="W74", client="1",
        hostname="h", ip="i", instance_nr="40",
        method="bapi_create"))
    assert state.get_node("W74").clients[0]["nr"] == "001"


def test_state_stats_pwned_includes_dbcon_edges():
    """Same off-by-one class as SCCs and BTP: the map draws ⚡ on
    every DBCONConnection.pwned=True cylinder.  Status-bar counter
    must include those or operator sees N+k bolts vs N count
    (operator screenshot: 7 ⚡ on the map, status bar said 6 pwned
    — the missing one was TEST_S4D2 pwned via direct SQL)."""
    from sapmap_models import DBCONConnection
    state = SAPMAPState()
    s4h = SAPNode(sid="S4H", system_type="ABAP", pwned=True)
    s4h.dbcon_edges = [
        DBCONConnection(source_sid="S4H", con_name="TEST_S4D2",
                          dbms="HDB", host="s4hanadev", port=30215,
                          pwned=True),
        DBCONConnection(source_sid="S4H", con_name="TEST_S4D",
                          dbms="HDB", pwned=False),
    ]
    state.add_node(s4h)
    s = state.stats()
    # 1 SAP pwned + 1 DBCON pwned = 2 (SAP-only count would be 1)
    assert s["pwned"] == 2


def test_state_stats_pwned_includes_btp_subaccounts():
    """Same off-by-one risk as SCCs: the map draws a ⚡ over any
    BTPSubaccountNode.pwned=True, so the status-bar Pwned counter
    has to include those or operator sees N+k bolts vs N count
    (operator screenshot showed S4H + BTP both ⚡ but counter said 1)."""
    from sapmap_models import BTPSubaccountNode
    state = SAPMAPState()
    state.add_node(SAPNode(sid="S4H", system_type="ABAP", pwned=True))
    state.btp_subaccounts["aa-bb"] = BTPSubaccountNode(
        uuid="aa-bb", subdomain="researchlab",
        region="eu10", pwned=True)
    state.btp_subaccounts["cc-dd"] = BTPSubaccountNode(
        uuid="cc-dd", subdomain="empty", region="eu10", pwned=False)
    s = state.stats()
    # 1 SAP pwned + 1 BTP pwned = 2 (SAP-only count would be 1)
    assert s["pwned"] == 2


def test_add_node_suppresses_plotted_finding_for_bare_aws_default():
    """SAPMAP auto-materialises placeholder SAP nodes for the two
    SAP-shipped CSI_AWS_EC2 / CSI_AWS_S3 Type-G destinations, then
    the frontend explicitly hides them from the map.  The
    "New … system plotted" INFO finding used to fire regardless,
    confusing the operator with a ping about a system they'd never
    see.  The finding must be suppressed for bare AWS placeholders
    but still emit for real systems and for AWS nodes that have
    accumulated any real enrichment."""
    from sapmap_models import SAPMAPState, SAPNode
    import sapmap_findings

    def _bare_aws(sid, host):
        return SAPNode(sid=sid, system_type="SAP", hostname=host, ip="")

    # 1. Bare AWS default → no finding emitted
    state = SAPMAPState()
    sapmap_findings.clear()
    state.add_node(_bare_aws("CSI1", "ec2.amazonaws.com"))
    plotted = [f for f in sapmap_findings.get_since(0)["findings"]
               if "plotted" in (f.get("msg") or "")]
    assert plotted == [], (
        f"bare AWS default emitted plotted finding: {plotted}")

    # 2. Different bare AWS default (s3) → also suppressed
    sapmap_findings.clear()
    state = SAPMAPState()
    state.add_node(_bare_aws("CSI2", "s3.amazonaws.com"))
    plotted = [f for f in sapmap_findings.get_since(0)["findings"]
               if "plotted" in (f.get("msg") or "")]
    assert plotted == []

    # 3. Real system (non-AWS host) → finding still emitted
    sapmap_findings.clear()
    state = SAPMAPState()
    state.add_node(SAPNode(sid="S4H", system_type="ABAP",
                            hostname="s4hanadev", ip="10.0.0.1"))
    plotted = [f for f in sapmap_findings.get_since(0)["findings"]
               if "plotted" in (f.get("msg") or "")]
    assert len(plotted) == 1, (
        f"real system should have emitted plotted finding, got: {plotted}")

    # 4. AWS host that HAS acquired enrichment (pwned) → still emits
    sapmap_findings.clear()
    state = SAPMAPState()
    enriched = _bare_aws("CSI3", "ec2.amazonaws.com")
    enriched.pwned = True
    state.add_node(enriched)
    plotted = [f for f in sapmap_findings.get_since(0)["findings"]
               if "plotted" in (f.get("msg") or "")]
    assert len(plotted) == 1, (
        f"enriched AWS node should still emit plotted finding, "
        f"got: {plotted}")
