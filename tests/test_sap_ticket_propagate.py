#!/usr/bin/env python3
"""Tests for MYSAPSSO2 ticket propagation (commit 9 — Phase D).

Verifies that ``propagate_via_forged_ticket`` correctly:
  - Replays a forged ticket over HTTP cookie + RFC channels
  - Records the attempt on ``ForgedTicket.used_on``
  - Returns the right verdict for each response shape (auth markers,
    login redirect, 401/403 rejection, network errors)
  - Honours pinning, expiry, and channel selection
  - Drives `propagate_to_trusted_subgraph` across multiple nodes

All HTTP calls are intercepted via ``urllib.request.build_opener``
+ a custom handler so the tests don't need a real SAP server.
"""
from __future__ import annotations

import io
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest


# ===================================================================
# Helpers
# ===================================================================

def _make_ticket(user="SAP*", client="100", sid="PRD",
                 forged_at="", validity_min=120,
                 recipient_sid="", recipient_client=""):
    from sapmap_models import ForgedTicket
    return ForgedTicket(
        user=user, client=client, sid=sid,
        cookie_b64="AgQxMDMAAQAIUwBBAFAAKgACAAADAAMAUzRI",
        ticket_size=512,
        forged_at=forged_at, validity_min=validity_min,
        recipient_sid=recipient_sid,
        recipient_client=recipient_client,
    )


def _make_node(sid="PRD", instance_nr="00", host="prdhost", ip="10.0.0.1"):
    from sapmap_models import SAPNode, InstanceInfo
    inst = InstanceInfo(
        instance_nr=instance_nr,
        ip=ip,
        ports={3300 + int(instance_nr): "gateway",
               44300 + int(instance_nr): "https"},
    )
    return SAPNode(
        sid=sid, hostname=host, ip=ip,
        instances=[inst], system_type="ABAP",
    )


def _fake_http_response(status: int, body: str = "",
                        headers: dict = None):
    """Build a urlopen-style object the propagation code can read."""
    class FakeResp:
        def __init__(self):
            self.status = status
            self._body = body.encode()
            self.headers = type("H", (), {
                "items": lambda *a, **kw: list(
                    (headers or {}).items()),
            })()

        def read(self, n=None):
            data = self._body
            self._body = b""
            return data[:n] if n else data

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    return FakeResp()


def _patch_urlopen(responses):
    """Patch urllib.request.urlopen to return queued responses.

    `responses` is a list of (status, body, headers) tuples OR
    HTTPError / URLError instances to raise.
    """
    iterator = iter(responses)

    def fake_urlopen(req, timeout=None, context=None):
        try:
            r = next(iterator)
        except StopIteration:
            raise urllib.error.URLError("queue exhausted")
        if isinstance(r, Exception):
            raise r
        status, body, headers = r
        return _fake_http_response(status, body, headers or {})

    return patch("urllib.request.urlopen", side_effect=fake_urlopen)


# ===================================================================
# Heuristic helpers
# ===================================================================

class TestHeuristics:

    def test_login_page_detected(self):
        from sap_ticket_propagate import _looks_like_login_page
        assert _looks_like_login_page(
            "<form><input name='j_username'></form>")
        assert _looks_like_login_page(
            "<title>Logon</title>")
        assert _looks_like_login_page(
            'name="sap-user"')

    def test_login_page_negative(self):
        from sap_ticket_propagate import _looks_like_login_page
        assert not _looks_like_login_page("<html>OK</html>")
        assert not _looks_like_login_page("")
        assert not _looks_like_login_page("SAP Web GUI")

    def test_authenticated_detected_via_cookie(self):
        from sap_ticket_propagate import _looks_like_sap_authenticated
        assert _looks_like_sap_authenticated(
            "<html></html>",
            {"Set-Cookie": "MYSAPSSO2=newvalue; Path=/"})
        assert _looks_like_sap_authenticated(
            "<html></html>",
            {"set-cookie": "SAP_SESSIONID_PRD_100=abc; Path=/"})

    def test_authenticated_detected_via_body_marker(self):
        from sap_ticket_propagate import _looks_like_sap_authenticated
        assert _looks_like_sap_authenticated(
            "Server reached. ICF service /sap/bc/ping is active.", {})
        assert _looks_like_sap_authenticated(
            "<title>SAP WebGUI</title>", {})

    def test_authenticated_negative(self):
        from sap_ticket_propagate import _looks_like_sap_authenticated
        assert not _looks_like_sap_authenticated("", {})
        assert not _looks_like_sap_authenticated(
            "<form name=login></form>", {})


# ===================================================================
# http_replay_ticket
# ===================================================================

class TestHttpReplay:

    def test_success_via_session_cookie(self):
        """A fresh Set-Cookie MYSAPSSO2 means SAP accepted our ticket."""
        from sap_ticket_propagate import http_replay_ticket
        ticket = _make_ticket()
        with _patch_urlopen([(200, "", {
                "Set-Cookie": "MYSAPSSO2=newvalue"})]):
            r = http_replay_ticket(ticket, "host", 44300)
        assert r["success"]
        assert r["status"] == 200
        assert "session cookie" in r["evidence"]

    def test_success_via_ping_body(self):
        from sap_ticket_propagate import http_replay_ticket
        ticket = _make_ticket()
        with _patch_urlopen([(200,
                "Server reached. ICF service /sap/bc/ping is active.",
                {})]):
            r = http_replay_ticket(ticket, "host", 44300)
        assert r["success"]
        assert "ping" in r["evidence"]

    def test_failure_login_redirect(self):
        from sap_ticket_propagate import http_replay_ticket
        ticket = _make_ticket()
        with _patch_urlopen([(200,
                "<form><input name=j_username></form>", {})]):
            r = http_replay_ticket(ticket, "host", 44300)
        assert not r["success"]
        assert "login" in r["evidence"].lower()

    def test_failure_401(self):
        from sap_ticket_propagate import http_replay_ticket
        ticket = _make_ticket()
        err = urllib.error.HTTPError(
            "url", 401, "Unauthorized", {}, None)
        with _patch_urlopen([err]):
            r = http_replay_ticket(ticket, "host", 44300)
        assert not r["success"]
        assert r["status"] == 401
        assert "rejected" in r["evidence"].lower()

    def test_failure_403(self):
        from sap_ticket_propagate import http_replay_ticket
        ticket = _make_ticket()
        err = urllib.error.HTTPError(
            "url", 403, "Forbidden", {}, None)
        with _patch_urlopen([err]):
            r = http_replay_ticket(ticket, "host", 44300)
        assert not r["success"]
        assert r["status"] == 403

    def test_network_failure(self):
        from sap_ticket_propagate import http_replay_ticket
        ticket = _make_ticket()
        err = urllib.error.URLError("Connection refused")
        with _patch_urlopen([err]):
            r = http_replay_ticket(ticket, "host", 44300)
        assert not r["success"]
        assert "network" in r["error"].lower()

    def test_url_contains_client_when_set(self):
        from sap_ticket_propagate import http_replay_ticket
        ticket = _make_ticket()
        captured = {}

        def grab(req, **kw):
            captured["url"] = req.full_url
            return _fake_http_response(200, "Server reached", {})

        with patch("urllib.request.urlopen", side_effect=grab):
            http_replay_ticket(ticket, "host", 44300, client="200")
        assert "sap-client=200" in captured["url"]

    def test_cookie_header_set(self):
        from sap_ticket_propagate import http_replay_ticket
        ticket = _make_ticket()
        captured = {}

        def grab(req, **kw):
            captured["cookie"] = req.headers.get("Cookie")
            return _fake_http_response(200, "Server reached", {})

        with patch("urllib.request.urlopen", side_effect=grab):
            http_replay_ticket(ticket, "host", 44300)
        assert captured["cookie"]
        assert "MYSAPSSO2=" in captured["cookie"]


# ===================================================================
# rfc_replay_ticket
# ===================================================================

class TestRfcReplay:

    def test_pyrfc_missing(self):
        """Without pyrfc the function returns a clean error."""
        from sap_ticket_propagate import rfc_replay_ticket
        ticket = _make_ticket()
        # Simulate ImportError
        import builtins
        original_import = builtins.__import__

        def block_pyrfc(name, *a, **kw):
            if name == "pyrfc":
                raise ImportError("pyrfc not available")
            return original_import(name, *a, **kw)

        with patch("builtins.__import__", side_effect=block_pyrfc):
            r = rfc_replay_ticket(ticket, "host", "00", "100")
        assert not r["success"]
        assert "pyrfc" in r["error"].lower()


# ===================================================================
# propagate_via_forged_ticket
# ===================================================================

class TestPropagate:

    def test_expired_ticket_skipped(self):
        from sap_ticket_propagate import propagate_via_forged_ticket
        from sapmap_models import SAPMAPState

        old = (datetime.now() - timedelta(hours=24)).isoformat()
        ticket = _make_ticket(forged_at=old, validity_min=60)
        node = _make_node("PRD")
        state = SAPMAPState()
        state.add_node(node)

        r = propagate_via_forged_ticket(ticket, node, state)
        assert not r["success"]
        assert "expired" in r["error"].lower()
        # The expiry was recorded on the ticket
        assert len(ticket.used_on) == 1
        assert ticket.used_on[0]["result"] == "expired"

    def test_http_success_records_use(self):
        from sap_ticket_propagate import propagate_via_forged_ticket
        from sapmap_models import SAPMAPState
        ticket = _make_ticket()
        node = _make_node("PRD")
        state = SAPMAPState()
        state.add_node(node)

        with _patch_urlopen([(200, "Server reached", {})]):
            r = propagate_via_forged_ticket(ticket, node, state)
        assert r["success"]
        assert r["channel"] == "http"
        assert len(ticket.used_on) == 1
        assert ticket.used_on[0]["result"] == "success"
        assert ticket.used_on[0]["sid"] == "PRD"
        assert ticket.used_on[0]["channel"] == "http"

    def test_http_failure_then_rfc_skipped(self):
        """When HTTP gets a 401, propagation stops without trying RFC
        (the ticket is rejected — RFC won't help)."""
        from sap_ticket_propagate import propagate_via_forged_ticket
        from sapmap_models import SAPMAPState
        ticket = _make_ticket()
        node = _make_node("PRD")
        state = SAPMAPState()
        state.add_node(node)

        err = urllib.error.HTTPError(
            "url", 401, "Unauthorized", {}, None)
        with _patch_urlopen([err]):
            r = propagate_via_forged_ticket(
                ticket, node, state, channels=["http"])
        assert not r["success"]
        # Used_on entry recorded with rejection
        assert ticket.used_on[-1]["result"] in ("rejected", "error")

    def test_no_host_resolution(self):
        from sap_ticket_propagate import propagate_via_forged_ticket
        from sapmap_models import SAPMAPState, SAPNode
        ticket = _make_ticket()
        node = SAPNode(sid="GHOST", hostname="", ip="")
        state = SAPMAPState()
        state.add_node(node)
        r = propagate_via_forged_ticket(ticket, node, state)
        assert not r["success"]
        assert "no IP/hostname" in r["error"]

    def test_pyrfc_missing_dropped_from_channels_early(self):
        """When the operator asks for RFC but pyrfc isn't installed,
        the propagation should drop "rfc" from the channels list
        BEFORE attempting any replay, and surface a clear
        ``rfc_skipped_reason`` in the result.  Previously this was
        counted as a failed attempt whose error ("pyrfc not
        available") then "won" the last-evidence race when HTTP also
        failed — masking the real HTTP failure reason."""
        import sys
        from sap_ticket_propagate import propagate_via_forged_ticket
        from sapmap_models import SAPMAPState
        ticket = _make_ticket()
        node = _make_node("PRD")
        state = SAPMAPState()
        state.add_node(node)

        # Force the ImportError path inside propagate_via_forged_ticket
        # by removing pyrfc from sys.modules and shadowing it as None.
        saved = sys.modules.get("pyrfc")
        sys.modules["pyrfc"] = None
        try:
            err = urllib.error.HTTPError(
                "url", 401, "Unauthorized", {}, None)
            with _patch_urlopen([err]):
                r = propagate_via_forged_ticket(
                    ticket, node, state,
                    channels=["http", "rfc"])
        finally:
            if saved is None:
                sys.modules.pop("pyrfc", None)
            else:
                sys.modules["pyrfc"] = saved

        # RFC was requested but dropped — the evidence should NOT be
        # "pyrfc not available" alone; it should reflect the HTTP
        # outcome (with the pyrfc note appended).
        assert "rfc" in r["channels_requested"]
        assert "rfc" not in r["channels_tried"]
        assert "pyrfc" in r["rfc_skipped_reason"].lower()
        # No RFC attempts logged
        assert all(att["channel"] != "rfc" for att in r["attempts"])

    def test_discovered_http_port_tried_before_443NN_fallback(self):
        """When the node has instance.ports listing port 8000 (HTTP),
        the propagation must try that port — not just the
        SAP-convention HTTPS 443NN.  Many production systems only
        expose HTTP, so the old hard-coded HTTPS-only fallback
        meant propagation failed against those targets even when
        the cookie was perfectly valid.
        """
        from sap_ticket_propagate import propagate_via_forged_ticket
        from sapmap_models import SAPMAPState, SAPNode, InstanceInfo
        ticket = _make_ticket()
        # Node has BOTH 8000 (HTTP) and 44300 (HTTPS) discovered
        inst = InstanceInfo(
            instance_nr="00",
            ip="10.0.0.1",
            ports={8000: "ICM_HTTP", 44300: "ICM_HTTPS"},
        )
        node = SAPNode(
            sid="PRD", hostname="h", ip="10.0.0.1",
            instances=[inst], system_type="ABAP")
        state = SAPMAPState()
        state.add_node(node)

        # Queue a "rejected" response for the first attempt (44300
        # HTTPS) and a successful one for the next attempt (8000
        # HTTP) — only valid if the propagation actually tries both
        # ports.
        success_body = (
            "<html><title>SAP NetWeaver</title>"
            "<body>logged in</body></html>")
        headers = {"Set-Cookie": "SAP_SESSIONID_PRD_001=abc123"}
        with _patch_urlopen([
                # 1st attempt: rejected on 44300 HTTPS
                urllib.error.HTTPError("url", 401, "Unauth", {}, None),
                # 2nd attempt: success on 8000 HTTP
                (200, success_body, headers),
        ]):
            r = propagate_via_forged_ticket(
                ticket, node, state, channels=["http"])

        # At least 2 attempts should have been made: one per port
        ports_tried = {att.get("port") for att in r["attempts"]
                       if att.get("channel") == "http"}
        assert 8000 in ports_tried, (
            f"Expected HTTP port 8000 to be tried; got {ports_tried}")
        assert 44300 in ports_tried, (
            f"Expected HTTPS port 44300 to be tried; got {ports_tried}")

    def test_aggregate_evidence_prefers_rejected_over_network_error(self):
        """When HTTP gets a 401 (rejected) on one port and a
        connection refused on another, the aggregate evidence
        should be the 401 — "rejected" is more useful diagnostic
        information than "connection refused" because it tells the
        operator the target IS reachable but didn't accept the
        ticket."""
        from sap_ticket_propagate import propagate_via_forged_ticket
        from sapmap_models import SAPMAPState, SAPNode, InstanceInfo
        ticket = _make_ticket()
        inst = InstanceInfo(
            instance_nr="00", ip="h",
            ports={8000: "ICM_HTTP", 44300: "ICM_HTTPS"})
        node = SAPNode(sid="PRD", hostname="h", ip="h",
                        instances=[inst], system_type="ABAP")
        state = SAPMAPState()
        state.add_node(node)

        with _patch_urlopen([
                urllib.error.HTTPError("url", 401, "Unauth", {}, None),
                urllib.error.URLError("Connection refused"),
        ]):
            r = propagate_via_forged_ticket(
                ticket, node, state, channels=["http"])

        assert not r["success"]
        # Aggregate evidence prefers "rejected" hit
        assert "rejected" in r["evidence"].lower(), \
            f"Expected rejected evidence; got {r['evidence']!r}"

    def test_pinned_ticket_uses_pin_client(self):
        """Pinned recipient_client overrides the ticket's own client
        for the receiver URL."""
        from sap_ticket_propagate import propagate_via_forged_ticket
        from sapmap_models import SAPMAPState
        ticket = _make_ticket(client="100",
                              recipient_sid="PRD",
                              recipient_client="200")
        node = _make_node("PRD")
        state = SAPMAPState()
        state.add_node(node)

        captured = {}

        def grab(req, **kw):
            captured["url"] = req.full_url
            return _fake_http_response(200, "Server reached", {})

        with patch("urllib.request.urlopen", side_effect=grab):
            propagate_via_forged_ticket(
                ticket, node, state, channels=["http"])

        # URL must include sap-client=200 (the pinned client), not 100
        assert "sap-client=200" in captured["url"]

    def test_channels_subset_respected(self):
        """channels=['http'] does not attempt RFC."""
        from sap_ticket_propagate import propagate_via_forged_ticket
        from sapmap_models import SAPMAPState

        ticket = _make_ticket()
        node = _make_node("PRD")
        state = SAPMAPState()
        state.add_node(node)

        with _patch_urlopen([(200, "<form name=login>", {})]):
            r = propagate_via_forged_ticket(
                ticket, node, state, channels=["http"])
        # Only http attempts in results
        assert all(a["channel"] == "http" for a in r["attempts"])

    def test_breaks_out_on_rejection(self):
        """A 401 stops further HTTP path probes."""
        from sap_ticket_propagate import propagate_via_forged_ticket
        from sapmap_models import SAPMAPState

        ticket = _make_ticket()
        node = _make_node("PRD")
        state = SAPMAPState()
        state.add_node(node)

        err = urllib.error.HTTPError(
            "url", 401, "Unauthorized", {}, None)
        # Queue ONE response — the second path probe should never fire
        with _patch_urlopen([err]):
            r = propagate_via_forged_ticket(
                ticket, node, state, channels=["http"])
        # Exactly one attempt (the 401), then bailed
        assert len(r["attempts"]) == 1

    def test_emits_finding_on_success(self):
        from sap_ticket_propagate import propagate_via_forged_ticket
        from sapmap_models import SAPMAPState
        ticket = _make_ticket()
        node = _make_node("PRD")
        state = SAPMAPState()
        state.add_node(node)

        with _patch_urlopen([(200, "Server reached", {})]):
            with patch(
                    "sapmap_findings.emit_finding") as mock_emit:
                r = propagate_via_forged_ticket(ticket, node, state)
        assert r["success"]
        # The emit_finding should be called with a CRITICAL severity
        # for a successful replay
        assert mock_emit.called
        args, kwargs = mock_emit.call_args
        assert args[0] == "CRITICAL"
        assert "REPLAY SUCCEEDED" in args[2].upper()


# ===================================================================
# propagate_to_trusted_subgraph
# ===================================================================

class TestPropagateSubgraph:

    def test_pinned_ticket_only_pinned_receiver(self):
        from sap_ticket_propagate import propagate_to_trusted_subgraph
        from sapmap_models import SAPMAPState

        ticket = _make_ticket(sid="PRD",
                              recipient_sid="QAS",
                              recipient_client="200")
        state = SAPMAPState()
        state.add_node(_make_node("PRD"))
        state.add_node(_make_node("QAS"))
        state.add_node(_make_node("DEV"))

        with _patch_urlopen([(200, "Server reached", {})]):
            r = propagate_to_trusted_subgraph(ticket, state)

        # Only QAS gets tried (pinned)
        assert r["tried"] == 1
        assert r["results"][0]["sid"] == "QAS"

    def test_open_ticket_includes_self_and_candidates(self):
        from sap_ticket_propagate import propagate_to_trusted_subgraph
        from sapmap_models import SAPMAPState

        ticket = _make_ticket(sid="PRD")  # open scope
        state = SAPMAPState()
        state.add_node(_make_node("PRD"))
        state.add_node(_make_node("QAS"))

        # Provide PRD-as-itself plus QAS as a candidate trust receiver
        with _patch_urlopen([
                (401, "", {}),    # PRD 401
                urllib.error.HTTPError(
                    "url", 401, "no", {}, None),   # QAS 401
        ]):
            r = propagate_to_trusted_subgraph(
                ticket, state, candidate_sids=["QAS"])

        assert r["tried"] == 2
        assert {x["sid"] for x in r["results"]} == {"PRD", "QAS"}

    def test_missing_candidate_node_is_skipped(self):
        from sap_ticket_propagate import propagate_to_trusted_subgraph
        from sapmap_models import SAPMAPState

        ticket = _make_ticket(sid="PRD")
        state = SAPMAPState()
        state.add_node(_make_node("PRD"))
        # QAS is mentioned but NOT on the map
        with _patch_urlopen([(200, "Server reached", {})]):
            r = propagate_to_trusted_subgraph(
                ticket, state, candidate_sids=["QAS"])
        # Only PRD got tried (QAS skipped silently)
        assert r["tried"] == 1
        assert r["results"][0]["sid"] == "PRD"

    def test_counts_succeeded(self):
        from sap_ticket_propagate import propagate_to_trusted_subgraph
        from sapmap_models import SAPMAPState

        ticket = _make_ticket(sid="PRD")
        state = SAPMAPState()
        state.add_node(_make_node("PRD"))
        state.add_node(_make_node("QAS"))

        with _patch_urlopen([
                (200, "Server reached", {}),   # PRD success
                urllib.error.HTTPError(
                    "url", 401, "no", {}, None),   # QAS rejected
        ]):
            r = propagate_to_trusted_subgraph(
                ticket, state, candidate_sids=["QAS"])

        assert r["tried"] == 2
        assert r["succeeded"] == 1
