#!/usr/bin/env python3
"""Tests for the AutoPwn MYSAPSSO2 ticket-forgery hook (commit 11).

The hook lives inside phase3_enrich and runs `extract_and_forge_ticket`
for each impersonation target in `_AUTOPWN_TICKET_USERS` on every
eligible ABAP node.  These tests cover:

  - Eligibility predicate (`_ticket_forgery_eligible`) — matches the
    intended channel set (gw / cve_2025_31324 / dpmon SAP*), rejects
    pure-Java systems and ABAP nodes with no OS-exec channel
  - `_forge_default_tickets` calls the orchestrator once per target
    user, tolerates per-target failures, surfaces per-stage audit
    output on failure, and respects the stop flag mid-loop
"""
from __future__ import annotations

import io
from unittest.mock import patch, MagicMock

import pytest


# ===================================================================
# Eligibility predicate
# ===================================================================

def _make_node(sid="PRD", system_type="ABAP",
               gw_vulnerable=False,
               cve_2025_31324_vulnerable=False,
               dpmon_sap_star_available=False):
    from sapmap_models import SAPNode
    n = SAPNode(sid=sid, system_type=system_type,
                gw_vulnerable=gw_vulnerable,
                cve_2025_31324_vulnerable=cve_2025_31324_vulnerable,
                dpmon_sap_star_available=dpmon_sap_star_available)
    return n


class TestEligibility:

    def test_abap_with_gw_eligible(self):
        from sapmap_autopwn import _ticket_forgery_eligible
        n = _make_node(system_type="ABAP", gw_vulnerable=True)
        assert _ticket_forgery_eligible(n) is True

    def test_abap_with_cve_31324_eligible(self):
        from sapmap_autopwn import _ticket_forgery_eligible
        n = _make_node(system_type="ABAP",
                       cve_2025_31324_vulnerable=True)
        assert _ticket_forgery_eligible(n) is True

    def test_abap_with_dpmon_eligible(self):
        from sapmap_autopwn import _ticket_forgery_eligible
        n = _make_node(system_type="ABAP",
                       dpmon_sap_star_available=True)
        assert _ticket_forgery_eligible(n) is True

    def test_abap_without_channel_rejected(self):
        """ABAP node with NO OS-exec channel — there's no way to read
        SAPSYS.pse, so forgery would just fail."""
        from sapmap_autopwn import _ticket_forgery_eligible
        n = _make_node(system_type="ABAP")
        assert _ticket_forgery_eligible(n) is False

    def test_pure_java_rejected(self):
        """Java-only systems have no SAPSYS.pse."""
        from sapmap_autopwn import _ticket_forgery_eligible
        n = _make_node(system_type="JAVA", gw_vulnerable=True)
        assert _ticket_forgery_eligible(n) is False

    def test_dual_stack_eligible(self):
        """ABAP+JAVA dual-stack still has SAPSYS.pse on the ABAP side."""
        from sapmap_autopwn import _ticket_forgery_eligible
        n = _make_node(system_type="ABAP+JAVA",
                       gw_vulnerable=True)
        assert _ticket_forgery_eligible(n) is True

    def test_empty_system_type_rejected(self):
        """Without an explicit ABAP marker, skip — we don't know what
        we're dealing with and it's safer not to extract."""
        from sapmap_autopwn import _ticket_forgery_eligible
        n = _make_node(system_type="", gw_vulnerable=True)
        assert _ticket_forgery_eligible(n) is False


# ===================================================================
# _forge_default_tickets — driver behaviour
# ===================================================================

class TestForgeDefaultTickets:

    def test_calls_orchestrator_per_user(self, capsys):
        from sapmap_autopwn import (
            _forge_default_tickets, _AUTOPWN_TICKET_USERS,
        )
        from sapmap_models import SAPMAPState
        node = _make_node("PRD", gw_vulnerable=True)
        state = SAPMAPState()
        state.add_node(node)

        captured_users = []

        def fake_orchestrator(node, state, user, **kw):
            captured_users.append(user)
            return {"success": False, "error": "stub",
                    "steps": [], "ticket": None,
                    "cookie_b64": "", "ticket_size": 0,
                    "loot_path": ""}

        with patch("sapmap_exploit.extract_and_forge_ticket",
                   side_effect=fake_orchestrator):
            _forge_default_tickets(node, state)

        # Once per default user
        assert captured_users == list(_AUTOPWN_TICKET_USERS)

    def test_continues_after_per_user_failure(self):
        """A failure on SAP* doesn't prevent the DDIC attempt."""
        from sapmap_autopwn import (
            _forge_default_tickets, _AUTOPWN_TICKET_USERS,
        )
        from sapmap_models import SAPMAPState
        node = _make_node("PRD", gw_vulnerable=True)
        state = SAPMAPState()
        state.add_node(node)

        seen = []

        def fake_orchestrator(node, state, user, **kw):
            seen.append(user)
            if user == "SAP*":
                # SAP* fails
                return {"success": False, "error": "PSE locked",
                        "steps": [{"name": "key_extract", "ok": False,
                                   "detail": "all PINs rejected"}],
                        "ticket": None, "cookie_b64": "",
                        "ticket_size": 0, "loot_path": ""}
            # DDIC succeeds
            from sapmap_models import ForgedTicket
            t = ForgedTicket(user=user, client="100", sid="PRD",
                              cookie_b64="abc", ticket_size=512)
            return {"success": True, "ticket": t,
                    "cookie_b64": "abc", "ticket_size": 512,
                    "loot_path": "/tmp/loot/x",
                    "steps": [], "error": ""}

        with patch("sapmap_exploit.extract_and_forge_ticket",
                   side_effect=fake_orchestrator):
            _forge_default_tickets(node, state)

        # Both attempted despite the first one failing
        assert seen == list(_AUTOPWN_TICKET_USERS)

    def test_orchestrator_exception_does_not_propagate(self):
        """A raise inside the orchestrator is caught — we still try
        the next user."""
        from sapmap_autopwn import (
            _forge_default_tickets, _AUTOPWN_TICKET_USERS,
        )
        from sapmap_models import SAPMAPState
        node = _make_node("PRD", gw_vulnerable=True)
        state = SAPMAPState()
        state.add_node(node)

        seen = []

        def fake_orchestrator(node, state, user, **kw):
            seen.append(user)
            raise RuntimeError("kaboom")

        with patch("sapmap_exploit.extract_and_forge_ticket",
                   side_effect=fake_orchestrator):
            # Must NOT raise
            _forge_default_tickets(node, state)
        # Both attempted despite both raising
        assert seen == list(_AUTOPWN_TICKET_USERS)

    def test_stop_aborts_remaining_users(self):
        """A STOP flag mid-loop bails on remaining impersonation targets."""
        from sapmap_autopwn import (
            _forge_default_tickets, _AUTOPWN_TICKET_USERS,
        )
        from sapmap_models import SAPMAPState
        node = _make_node("PRD", gw_vulnerable=True)
        state = SAPMAPState()
        state.add_node(node)

        seen = []
        # Trip the stop flag after the first call so DDIC never runs
        call_count = {"n": 0}

        def fake_orchestrator(node, state, user, **kw):
            seen.append(user)
            call_count["n"] += 1
            return {"success": False, "error": "stub",
                    "steps": [], "ticket": None, "cookie_b64": "",
                    "ticket_size": 0, "loot_path": ""}

        stop_calls = {"n": 0}

        def fake_stop_requested():
            stop_calls["n"] += 1
            # First two checks: before SAP* (False), before DDIC (True)
            return stop_calls["n"] >= 2

        with patch("sapmap_exploit.extract_and_forge_ticket",
                   side_effect=fake_orchestrator), \
             patch("sapmap_autopwn._stop_requested",
                   side_effect=fake_stop_requested):
            _forge_default_tickets(node, state)

        # Only SAP* attempted; DDIC blocked by stop
        assert seen == ["SAP*"]

    def test_orchestrator_import_failure_logged(self, capsys):
        """When sapmap_exploit can't be imported, log + return."""
        from sapmap_models import SAPMAPState
        node = _make_node("PRD", gw_vulnerable=True)
        state = SAPMAPState()
        state.add_node(node)

        import builtins
        original = builtins.__import__

        def block_exploit(name, *a, **kw):
            if name == "sapmap_exploit":
                raise ImportError("no module")
            return original(name, *a, **kw)

        with patch("builtins.__import__", side_effect=block_exploit):
            # Re-import to force the inner import
            import importlib
            import sapmap_autopwn
            importlib.reload(sapmap_autopwn)
            sapmap_autopwn._forge_default_tickets(node, state)

        captured = capsys.readouterr()
        assert "unavailable" in captured.out.lower()


# ===================================================================
# Integration smoke — the helpers are wired into phase3_enrich
# ===================================================================

class TestPhase3Integration:

    def test_phase3_invokes_forge_on_eligible_abap(self):
        """phase3_enrich calls _forge_default_tickets exactly for
        eligible nodes."""
        from sapmap_models import SAPMAPState, SAPNode, Credentials

        # An eligible ABAP with creds + a Java-only node (skipped)
        abap = _make_node("PRD", system_type="ABAP",
                           gw_vulnerable=True)
        abap.hostname = "prdhost"
        abap.ip = "10.0.0.1"
        abap.credentials = [Credentials(
            username="SAPMAP00", password="x", client="100",
            instance_nr="00", verified=True)]
        java = _make_node("JAV", system_type="JAVA",
                           gw_vulnerable=True)
        java.credentials = [Credentials(
            username="Administrator", password="y", client="",
            instance_nr="00", verified=True)]

        state = SAPMAPState()
        state.add_node(abap)
        state.add_node(java)

        forge_calls = []

        def fake_forge(n, s):
            forge_calls.append(n.sid)

        # We want to short-circuit every OTHER side-effecting bit of
        # phase3 (RFC retrieval, SecStore, Java SecStore, etc.) so the
        # test only verifies the forgery hook fires on the right nodes.
        with patch("sapmap_autopwn._forge_default_tickets",
                   side_effect=fake_forge), \
             patch("sapmap_autopwn._stop_requested",
                   return_value=False), \
             patch("sapmap_rfc.retrieve_rfc_connections",
                   return_value=[]), \
             patch("sapmap_secstore.download_and_decrypt",
                   return_value=[]):
            from sapmap_autopwn import phase3_enrich
            phase3_enrich(state, ["PRD", "JAV"], wave=1)

        # ABAP got a forgery call; Java did NOT
        assert forge_calls == ["PRD"]
