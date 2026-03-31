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
