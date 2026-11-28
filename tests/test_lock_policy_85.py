"""Issue #85 PR1 — host-scoped lock policy core (data model + sapmap_lock).

Covers the pure policy primitives the enforcement hooks build on: the host
matcher, canonical-host resolution, is_locked / actionable_nodes, lock/unlock
(host-scoped, reason-required), the artifact warn-count, and persistence
round-trip (incl. legacy files loading unlocked).
"""
from __future__ import annotations

import pytest

from sapmap_models import SAPNode, InstanceInfo, SAPMAPState, CreatedUser
import sapmap_lock as L


# --- host matcher ----------------------------------------------------------

def test_host_matches_exact_and_dot_anchored_domain():
    assert L.host_matches("sap.com", "sap.com")
    assert L.host_matches("apps.support.sap.com", "sap.com")       # subdomain
    assert L.host_matches("apps.support.sap.com", "support.sap.com")
    assert not L.host_matches("evilsap.com", "sap.com")            # NOT a suffix
    assert not L.host_matches("sap.com.evil.net", "sap.com")       # dot-anchored


def test_host_matches_cidr_and_ip():
    assert L.host_matches("10.0.0.5", "10.0.0.0/24")
    assert L.host_matches("10.0.0.5", "10.0.0.5")
    assert not L.host_matches("10.0.1.5", "10.0.0.0/24")
    # hostname vs IP pattern (and vice-versa) never cross-match
    assert not L.host_matches("app.lab", "10.0.0.0/24")
    assert not L.host_matches("10.0.0.5", "app.lab")


def test_host_matches_blank_is_false():
    assert not L.host_matches("", "sap.com")
    assert not L.host_matches("app.lab", "")


# --- canonical hosts -------------------------------------------------------

def _node(sid="SB1", ip="10.0.0.1", hostname="app01.lab", instances=None,
          reported_ip=""):
    n = SAPNode(sid=sid, ip=ip, hostname=hostname,
                instances=instances or [])
    if reported_ip:
        n.reported_ip = reported_ip
    return n


def test_canonical_hosts_covers_node_instance_and_ips():
    n = _node(instances=[InstanceInfo(instance_nr="04", ip="10.0.0.5",
                                      hostname="app04.lab")])
    ch = L.canonical_hosts(n)
    assert "app01.lab" in ch       # node hostname
    assert "app04.lab" in ch       # per-instance hostname (all_hostnames misses it)
    assert "10.0.0.1" in ch        # node ip
    assert "10.0.0.5" in ch        # instance ip


def test_canonical_hosts_excludes_reported_ip():
    n = _node(reported_ip="172.17.0.9")
    assert "172.17.0.9" not in L.canonical_hosts(n), (
        "reported_ip (NAT/Docker self-report) must not seed a CIDR lock")


# --- is_locked / locked_record_for / actionable_nodes ----------------------

def test_lock_node_blocks_and_is_host_scoped():
    state = SAPMAPState()
    a = _node(sid="AAA", ip="10.0.0.1", hostname="shared.lab")
    b = _node(sid="BBB", ip="10.0.0.1", hostname="shared.lab")   # same host
    c = _node(sid="CCC", ip="10.9.9.9", hostname="other.lab")
    for n in (a, b, c):
        state.add_node(n)
    assert not L.is_locked(state, a)
    L.lock_node(state, a, "sensitive prod")
    # host-scoped: the sibling SID on the same host is locked too
    assert L.is_locked(state, a)
    assert L.is_locked(state, b)
    assert not L.is_locked(state, c)
    actionable = {n.sid for n in L.actionable_nodes(state)}
    assert actionable == {"CCC"}


def test_locked_record_carries_reason():
    state = SAPMAPState()
    n = _node()
    state.add_node(n)
    L.lock_node(state, n, "third-party SAP support host")
    rec = L.locked_record_for(state, n)
    assert rec is not None
    assert rec["reason"] == "third-party SAP support host"
    assert rec["auto"] is False


def test_is_host_locked_bare_string():
    state = SAPMAPState()
    n = _node(hostname="app01.lab", ip="10.0.0.1")
    state.add_node(n)
    L.lock_node(state, n, "x")
    assert L.is_host_locked(state, "app01.lab")
    assert L.is_host_locked(state, "10.0.0.1")
    assert not L.is_host_locked(state, "elsewhere.lab")


# --- unlock: reason required + audit log + auto (no) relock here -----------

def test_unlock_requires_reason():
    state = SAPMAPState()
    n = _node()
    state.add_node(n)
    L.lock_node(state, n, "x")
    with pytest.raises(ValueError):
        L.unlock_node(state, n, "")
    with pytest.raises(ValueError):
        L.unlock_node(state, n, "   ")
    # still locked after the rejected unlocks
    assert L.is_locked(state, n)


def test_unlock_removes_and_records_reason():
    state = SAPMAPState()
    n = _node(hostname="app01.lab", ip="10.0.0.1")
    state.add_node(n)
    L.lock_node(state, n, "x")
    removed = L.unlock_node(state, n, "cleared by engagement lead",
                            by="operator2")
    assert removed >= 1
    assert not L.is_locked(state, n)
    assert state.unlock_log, "unlock must leave an audit trail"
    entry = state.unlock_log[-1]
    assert entry["reason"] == "cleared by engagement lead"
    assert entry["by"] == "operator2"


# --- warn-count ------------------------------------------------------------

def test_pending_artifacts_counts_planted_users():
    state = SAPMAPState()
    n = _node(sid="SB1")
    state.add_node(n)
    assert L.pending_artifacts_for(state, n) == 0
    state.created_users.append(
        CreatedUser(username="SAPMAP00", sid="SB1", client="001",
                    hostname="app01.lab", ip="10.0.0.1", instance_nr="00",
                    method="gw_sapxpg", password="x"))
    assert L.pending_artifacts_for(state, n) == 1


# --- persistence -----------------------------------------------------------

def test_lock_state_round_trips_through_sapmap_json():
    state = SAPMAPState()
    n = _node(hostname="app01.lab", ip="10.0.0.1")
    state.add_node(n)
    L.lock_node(state, n, "prod — do not touch", by="op1")
    L.unlock_host(state, "app01.lab", "re-arm for test", by="op1")
    # app01.lab unlocked, 10.0.0.1 still locked
    d = state.to_dict()
    back = SAPMAPState.from_dict(d)
    assert any(r["host"] == "10.0.0.1" for r in back.locked_hosts)
    assert all(r["host"] != "app01.lab" for r in back.locked_hosts)
    assert back.unlock_log and back.unlock_log[-1]["reason"] == "re-arm for test"


def test_legacy_state_loads_unlocked():
    """A .sapmap written before #85 has no lock keys → loads unlocked."""
    legacy = {"version": "1.0", "nodes": {}}
    back = SAPMAPState.from_dict(legacy)
    assert back.locked_hosts == []
    assert back.unlock_log == []
