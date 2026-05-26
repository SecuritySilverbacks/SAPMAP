#!/usr/bin/env python3
"""Tests for the ForgedTicket state model (MYSAPSSO2 ticket forgery, commit 7).

Covers:
  - ForgedTicket dataclass: construction, defaults, post-init
  - to_dict / from_dict round-trip
  - Expiry logic (is_expired, remaining_minutes)
  - Display label formatting
  - record_use append-only tracking
  - SAPNode.forged_tickets persistence
  - SAPMAPState.forged_tickets global mirror via track_forged_ticket
  - get_forged_tickets_for / get_forged_tickets_targeting filters
  - remove_node drops issuer's tickets
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                "modules", "core"))

from sapmap_models import (
    ForgedTicket, SAPNode, SAPMAPState,
)


# ===================================================================
# Helpers
# ===================================================================

def _make_ticket(user="SAP*", client="100", sid="PRD",
                 forged_at="", validity_min=120,
                 recipient_sid="", recipient_client="",
                 **kwargs):
    return ForgedTicket(
        user=user,
        client=client,
        sid=sid,
        cookie_b64="AgQxMDMAAQAIUwBBAFAAKgACAAADAAMAUzRI",  # fake b64
        ticket_size=512,
        forged_at=forged_at,
        validity_min=validity_min,
        recipient_sid=recipient_sid,
        recipient_client=recipient_client,
        **kwargs,
    )


# ===================================================================
# Construction + defaults
# ===================================================================

class TestForgedTicketBasics:

    def test_minimal_construction(self):
        t = ForgedTicket(user="SAP*", client="100", sid="PRD",
                          cookie_b64="abc")
        assert t.user == "SAP*"
        assert t.client == "100"
        assert t.sid == "PRD"
        assert t.cookie_b64 == "abc"
        assert t.method == "ticket_forge"
        # forged_at is auto-stamped by __post_init__
        assert t.forged_at
        # source_sid defaults to sid when not provided
        assert t.source_sid == "PRD"

    def test_source_sid_when_provided(self):
        t = ForgedTicket(user="SAP*", client="100", sid="PRD",
                          cookie_b64="abc", source_sid="QAS")
        assert t.source_sid == "QAS"

    def test_forged_at_preserved_when_supplied(self):
        custom_ts = "2024-01-01T00:00:00"
        t = ForgedTicket(user="x", client="000", sid="X",
                          cookie_b64="a", forged_at=custom_ts)
        assert t.forged_at == custom_ts

    def test_default_validity(self):
        t = _make_ticket()
        assert t.validity_min == 120

    def test_default_collections_empty(self):
        t = _make_ticket()
        assert t.used_on == []


# ===================================================================
# Expiry logic
# ===================================================================

class TestExpiry:

    def test_fresh_ticket_not_expired(self):
        t = _make_ticket()
        assert not t.is_expired()
        assert t.remaining_minutes() > 0
        assert t.remaining_minutes() <= 120

    def test_expired_ticket(self):
        # Forged 200 min ago, valid 120 min → expired
        old = (datetime.now() - timedelta(minutes=200)).isoformat()
        t = _make_ticket(forged_at=old, validity_min=120)
        assert t.is_expired()
        assert t.remaining_minutes() < 0

    def test_boundary_just_expired(self):
        # 121 min ago, validity 120 → expired by 1 min
        old = (datetime.now() - timedelta(minutes=121)).isoformat()
        t = _make_ticket(forged_at=old, validity_min=120)
        assert t.is_expired()

    def test_boundary_just_valid(self):
        # 119 min ago, validity 120 → still valid
        old = (datetime.now() - timedelta(minutes=119)).isoformat()
        t = _make_ticket(forged_at=old, validity_min=120)
        assert not t.is_expired()

    def test_zero_validity_treated_as_no_expiry(self):
        """validity_min <= 0 means 'no expiry tracked' (legacy)."""
        old = (datetime.now() - timedelta(days=30)).isoformat()
        t = _make_ticket(forged_at=old, validity_min=0)
        assert not t.is_expired()
        t2 = _make_ticket(forged_at=old, validity_min=-1)
        assert not t2.is_expired()

    def test_explicit_now(self):
        """is_expired() accepts an explicit reference time."""
        t = _make_ticket(forged_at="2024-01-01T00:00:00",
                          validity_min=60)
        # 30 min after the forge time — still valid
        assert not t.is_expired(now=datetime(2024, 1, 1, 0, 30))
        # 70 min after — expired
        assert t.is_expired(now=datetime(2024, 1, 1, 1, 10))

    def test_malformed_timestamp_doesnt_crash(self):
        t = _make_ticket(forged_at="not-a-timestamp")
        # Should not raise — returns False (can't tell, treat as valid)
        assert not t.is_expired()
        assert t.remaining_minutes() == t.validity_min


# ===================================================================
# Display label
# ===================================================================

class TestDisplayLabel:

    def test_basic_label(self):
        t = _make_ticket(user="SAP*", client="100", sid="PRD")
        label = t.display_label()
        assert "SAP*" in label
        assert "PRD" in label
        assert "100" in label
        assert "min left" in label

    def test_pinned_label(self):
        t = _make_ticket(user="DDIC", client="000", sid="PRD",
                         recipient_sid="QAS", recipient_client="200")
        label = t.display_label()
        # Should mention both issuer + receiver
        assert "DDIC" in label
        assert "PRD" in label
        assert "QAS" in label
        assert "200" in label

    def test_expired_label(self):
        old = (datetime.now() - timedelta(minutes=999)).isoformat()
        t = _make_ticket(forged_at=old, validity_min=60)
        label = t.display_label()
        assert "expired" in label.lower()


# ===================================================================
# Use tracking
# ===================================================================

class TestRecordUse:

    def test_record_use_appends(self):
        t = _make_ticket()
        assert t.used_on == []
        t.record_use(sid="QAS", client="200", result="success",
                     channel="http")
        assert len(t.used_on) == 1
        entry = t.used_on[0]
        assert entry["sid"] == "QAS"
        assert entry["client"] == "200"
        assert entry["result"] == "success"
        assert entry["channel"] == "http"
        assert entry["at"]  # timestamp populated

    def test_multiple_uses(self):
        t = _make_ticket()
        t.record_use("QAS", "200", "success", "http")
        t.record_use("DEV", "100", "rejected", "pyrfc")
        t.record_use("QAS", "200", "success", "sapgui")
        assert len(t.used_on) == 3
        assert t.used_on[1]["result"] == "rejected"


# ===================================================================
# Serialization round-trip
# ===================================================================

class TestRoundTrip:

    def test_minimal_roundtrip(self):
        t = ForgedTicket(user="SAP*", client="100", sid="PRD",
                          cookie_b64="abc")
        d = t.to_dict()
        t2 = ForgedTicket.from_dict(d)
        assert t2.user == t.user
        assert t2.client == t.client
        assert t2.sid == t.sid
        assert t2.cookie_b64 == t.cookie_b64
        assert t2.forged_at == t.forged_at
        assert t2.source_sid == t.source_sid

    def test_full_roundtrip(self):
        t = _make_ticket(
            user="DDIC", client="000", sid="PRD",
            recipient_sid="QAS", recipient_client="200",
            signer_dn="CN=PRD, OU=SAP Web AS",
            signer_serial="1A2B3C4D",
            source_sid="PRD", source_node_ip="10.0.0.1",
            loot_path="/tmp/loot/PRD_x_y/",
            label="prod-impersonation-2024",
        )
        t.record_use("QAS", "200", "success", "http")
        t.record_use("DEV", "100", "expired", "pyrfc")
        d = t.to_dict()
        t2 = ForgedTicket.from_dict(d)
        assert t2.recipient_sid == "QAS"
        assert t2.recipient_client == "200"
        assert t2.signer_dn == "CN=PRD, OU=SAP Web AS"
        assert t2.signer_serial == "1A2B3C4D"
        assert t2.source_node_ip == "10.0.0.1"
        assert t2.loot_path == "/tmp/loot/PRD_x_y/"
        assert t2.label == "prod-impersonation-2024"
        assert len(t2.used_on) == 2
        assert t2.used_on[0]["sid"] == "QAS"
        assert t2.used_on[1]["result"] == "expired"

    def test_missing_optional_fields_default(self):
        """from_dict tolerates legacy dicts missing newer fields."""
        d = {
            "user": "SAP*",
            "client": "100",
            "sid": "PRD",
            "cookie_b64": "abc",
        }
        t = ForgedTicket.from_dict(d)
        assert t.user == "SAP*"
        assert t.method == "ticket_forge"  # default
        assert t.validity_min == 120  # default
        assert t.used_on == []


# ===================================================================
# SAPNode integration
# ===================================================================

class TestSAPNodeIntegration:

    def test_node_starts_with_empty_tickets(self):
        node = SAPNode(sid="PRD")
        assert node.forged_tickets == []

    def test_append_ticket_to_node(self):
        node = SAPNode(sid="PRD")
        t = _make_ticket(sid="PRD")
        node.forged_tickets.append(t)
        assert len(node.forged_tickets) == 1
        assert node.forged_tickets[0].user == "SAP*"

    def test_node_roundtrip_preserves_tickets(self):
        node = SAPNode(sid="PRD", hostname="prdhost")
        node.forged_tickets.append(_make_ticket(sid="PRD",
                                                user="SAP*"))
        node.forged_tickets.append(_make_ticket(sid="PRD",
                                                user="DDIC"))
        d = node.to_dict()
        assert "forged_tickets" in d
        assert len(d["forged_tickets"]) == 2

        node2 = SAPNode.from_dict(d)
        assert len(node2.forged_tickets) == 2
        assert node2.forged_tickets[0].user == "SAP*"
        assert node2.forged_tickets[1].user == "DDIC"

    def test_node_roundtrip_legacy_dict_no_tickets(self):
        """Old saved state files without forged_tickets still load."""
        d = {
            "sid": "PRD",
            "hostname": "prdhost",
            # no forged_tickets key
        }
        node = SAPNode.from_dict(d)
        assert node.forged_tickets == []


# ===================================================================
# SAPMAPState integration
# ===================================================================

class TestSAPMAPStateIntegration:

    def test_state_starts_with_empty_tickets(self):
        state = SAPMAPState()
        assert state.forged_tickets == []

    def test_track_forged_ticket_mirrors_to_node(self):
        state = SAPMAPState()
        node = SAPNode(sid="PRD")
        state.add_node(node)

        t = _make_ticket(sid="PRD", user="SAP*")
        state.track_forged_ticket(t)

        # Both global and node-local
        assert len(state.forged_tickets) == 1
        assert len(state.nodes["PRD"].forged_tickets) == 1
        # Node should be marked pwned (ticket forgery is critical)
        assert state.nodes["PRD"].pwned

    def test_track_forged_ticket_no_node(self):
        """A ticket whose issuer isn't on the map still gets tracked."""
        state = SAPMAPState()
        t = _make_ticket(sid="GHOST")
        state.track_forged_ticket(t)
        assert len(state.forged_tickets) == 1
        # No node to mirror to, but global list still populated
        assert "GHOST" not in state.nodes

    def test_get_forged_tickets_for_issuer(self):
        state = SAPMAPState()
        state.track_forged_ticket(_make_ticket(sid="PRD", user="SAP*"))
        state.track_forged_ticket(_make_ticket(sid="QAS", user="DDIC"))
        state.track_forged_ticket(_make_ticket(sid="PRD", user="ADM"))

        prd = state.get_forged_tickets_for("PRD")
        assert len(prd) == 2
        assert {t.user for t in prd} == {"SAP*", "ADM"}

        qas = state.get_forged_tickets_for("QAS")
        assert len(qas) == 1
        assert qas[0].user == "DDIC"

    def test_get_forged_tickets_targeting_pinned(self):
        state = SAPMAPState()
        # Pinned to QAS/200
        state.track_forged_ticket(_make_ticket(
            sid="PRD", recipient_sid="QAS", recipient_client="200"))
        # Pinned to DEV (any client)
        state.track_forged_ticket(_make_ticket(
            sid="PRD", recipient_sid="DEV"))
        # Open scope (no pinning)
        state.track_forged_ticket(_make_ticket(sid="PRD"))

        # QAS/200 receives: explicit pin + open scope = 2
        qas = state.get_forged_tickets_targeting("QAS", "200")
        assert len(qas) == 2

        # DEV/100 receives: DEV pin (no client filter) + open = 2
        dev = state.get_forged_tickets_targeting("DEV", "100")
        assert len(dev) == 2

        # ABC/123 (unknown receiver): only open-scope = 1
        abc = state.get_forged_tickets_targeting("ABC", "123")
        assert len(abc) == 1

    def test_get_forged_tickets_targeting_excludes_expired(self):
        state = SAPMAPState()
        old = (datetime.now() - timedelta(hours=24)).isoformat()
        state.track_forged_ticket(_make_ticket(
            sid="PRD", forged_at=old, validity_min=60))  # expired
        state.track_forged_ticket(_make_ticket(sid="PRD"))  # fresh

        # Only the fresh one shows up
        results = state.get_forged_tickets_targeting("ANY")
        assert len(results) == 1

    def test_remove_node_drops_issuer_tickets(self):
        state = SAPMAPState()
        state.add_node(SAPNode(sid="PRD"))
        state.add_node(SAPNode(sid="QAS"))
        state.track_forged_ticket(_make_ticket(sid="PRD"))
        state.track_forged_ticket(_make_ticket(sid="QAS"))
        state.track_forged_ticket(_make_ticket(sid="PRD"))

        state.remove_node("PRD")

        # PRD tickets gone, QAS ticket kept
        assert len(state.forged_tickets) == 1
        assert state.forged_tickets[0].sid == "QAS"

    def test_remove_node_keeps_tickets_targeting_it(self):
        """Tickets pinned to a node's SID survive when that node is
        deleted — the receiver may come back, and the tickets are
        still valid against any other trusted system.
        """
        state = SAPMAPState()
        state.add_node(SAPNode(sid="PRD"))
        state.add_node(SAPNode(sid="QAS"))
        # PRD-issued, QAS-pinned
        state.track_forged_ticket(_make_ticket(
            sid="PRD", recipient_sid="QAS"))

        state.remove_node("QAS")  # remove the RECEIVER, not issuer

        # Ticket survives
        assert len(state.forged_tickets) == 1
        assert state.forged_tickets[0].recipient_sid == "QAS"

    def test_state_roundtrip_preserves_tickets(self):
        state = SAPMAPState()
        state.add_node(SAPNode(sid="PRD"))
        state.track_forged_ticket(_make_ticket(
            sid="PRD", user="SAP*"))
        state.track_forged_ticket(_make_ticket(
            sid="PRD", user="DDIC",
            recipient_sid="QAS", recipient_client="200"))

        d = state.to_dict()
        state2 = SAPMAPState.from_dict(d)

        assert len(state2.forged_tickets) == 2
        assert state2.forged_tickets[0].user == "SAP*"
        assert state2.forged_tickets[1].recipient_sid == "QAS"
        # And the node-local mirror loaded too
        assert len(state2.nodes["PRD"].forged_tickets) >= 1

    def test_state_roundtrip_legacy_dict_no_tickets(self):
        """SAPMAPState.from_dict tolerates state files predating
        ForgedTicket (no forged_tickets key)."""
        d = {
            "version": "1.0",
            "nodes": {"PRD": {"sid": "PRD"}},
            "connections": [],
            "created_users": [],
            "created_destinations": [],
            "rfc_check_cache": {},
            "scc_nodes": {},
            "btp_subaccounts": {},
        }
        state = SAPMAPState.from_dict(d)
        assert state.forged_tickets == []
