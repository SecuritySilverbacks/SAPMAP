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

        # Queue connection-refused for every attempt — that way we
        # see EVERY candidate the propagation generated, regardless
        # of break-on-success behaviour.  With dual-scheme port
        # probing each non-ICM port gets TWO candidates (HTTPS + HTTP)
        # so a 2-port discovery yields up to 4 attempts × 3 paths.
        # We don't care which order; we care that both 8000 and 44300
        # appear in the final candidate set.
        with _patch_urlopen([
                urllib.error.URLError("queue") for _ in range(40)]):
            r = propagate_via_forged_ticket(
                ticket, node, state, channels=["http"])

        # Both discovered ports must appear in the attempts list
        ports_tried = {att.get("port") for att in r["attempts"]
                       if att.get("channel") == "http"}
        assert 8000 in ports_tried, (
            f"Expected HTTP port 8000 to be tried; got {ports_tried}")
        assert 44300 in ports_tried, (
            f"Expected HTTPS port 44300 to be tried; got {ports_tried}")
        # And both schemes get probed for each non-ICM port — a
        # scanner-tagged "http" port might actually be HTTPS in an
        # operator-customised install (the S4H lab case we hit).
        schemes_for_8000 = {att.get("use_https")
                             for att in r["attempts"]
                             if att.get("port") == 8000}
        assert schemes_for_8000 == {True, False}, (
            f"Expected port 8000 probed with BOTH schemes; "
            f"got {schemes_for_8000}")

    def test_dual_scheme_probe_finds_https_on_conventional_http_port(self):
        """Operator-customised installs can flip the conventional
        port/scheme association.  Real-world case (S4H lab):
        port 8000 served HTTPS, not the conventional HTTP.

        Before the dual-scheme fix, propagation hardcoded
        (8000, http) and got a TCP reset every time — the SSL
        handshake never started because we sent plain HTTP to an
        HTTPS-only listener.  With dual-scheme, each non-ICM port
        now gets BOTH (port, https) and (port, http) candidates,
        so port 8000 gets probed as HTTPS too and succeeds.
        """
        from sap_ticket_propagate import propagate_via_forged_ticket
        from sapmap_models import SAPMAPState, SAPNode, InstanceInfo
        ticket = _make_ticket()
        # Scanner discovered port 8000 and (incorrectly) tagged it
        # ICM_HTTP — operator's actual ICM has it on HTTPS.
        inst = InstanceInfo(
            instance_nr="00", ip="h",
            ports={8000: "ICM_HTTP"})
        node = SAPNode(sid="PRD", hostname="h", ip="h",
                        instances=[inst], system_type="ABAP")
        state = SAPMAPState()
        state.add_node(node)

        # Queue: connection-refused 20 times so we see every
        # candidate the propagation generates.
        with _patch_urlopen([
                urllib.error.URLError("queue") for _ in range(20)]):
            r = propagate_via_forged_ticket(
                ticket, node, state, channels=["http"])

        # Verify port 8000 was probed with BOTH schemes — without
        # the dual-scheme fix only one (the convention-based
        # http) would appear.
        candidates_for_8000 = {
            att.get("use_https") for att in r["attempts"]
            if att.get("port") == 8000 and att.get("channel") == "http"
        }
        assert candidates_for_8000 == {True, False}, (
            f"port 8000 must be probed with BOTH HTTPS and HTTP "
            f"(scheme isn't authoritative for non-ICM ports); "
            f"got {candidates_for_8000}")

    def test_authoritative_icm_port_uses_declared_scheme_only(self):
        """When ICM port info comes from the SAP profile
        (icm/server_port_<N>), the protocol is authoritative —
        don't waste an attempt probing the other scheme.
        """
        from sap_ticket_propagate import propagate_via_forged_ticket
        from sapmap_models import SAPMAPState, SAPNode
        ticket = _make_ticket()
        node = SAPNode(sid="PRD", hostname="h", ip="h",
                        system_type="ABAP")
        # ICM profile says port 8000 is HTTPS.  Authoritative.
        node.icm_ports = [
            {"port": 8000, "protocol": "https", "index": 0,
             "raw": "PROT=HTTPS,PORT=8000"},
        ]
        state = SAPMAPState()
        state.add_node(node)

        with _patch_urlopen([
                urllib.error.URLError("queue") for _ in range(20)]):
            r = propagate_via_forged_ticket(
                ticket, node, state, channels=["http"])

        # Find probes against port 8000
        icm_attempts = [att for att in r["attempts"]
                         if att.get("port") == 8000
                         and att.get("channel") == "http"]
        # ICM-declared port must be probed with HTTPS only
        # (no wasted HTTP probe — authoritative).
        schemes = {att.get("use_https") for att in icm_attempts}
        assert schemes == {True}, (
            f"ICM-declared HTTPS port 8000 must be probed with "
            f"HTTPS only; got schemes {schemes}")

    def test_network_error_breaks_path_loop(self):
        """When a (port, scheme) attempt returns a network error
        (TCP reset, connection refused, SSL handshake failure),
        the per-path loop must break — all paths to a closed port
        will fail identically, so probing more is wasted round
        trips.  Previously the break only fired on auth rejection.
        """
        from sap_ticket_propagate import propagate_via_forged_ticket
        from sapmap_models import SAPMAPState, SAPNode, InstanceInfo
        ticket = _make_ticket()
        inst = InstanceInfo(
            instance_nr="00", ip="h",
            ports={44300: "ICM_HTTPS"})   # Only one port discovered
        node = SAPNode(sid="PRD", hostname="h", ip="h",
                        instances=[inst], system_type="ABAP")
        state = SAPMAPState()
        state.add_node(node)

        # 44300 will yield connection-refused for every probe.
        # Without the network-error break, we'd hit it 3 times
        # (one per path in _DEFAULT_HTTP_PATHS) per scheme — 6
        # round trips for one dead port.  With the break, exactly
        # 1 attempt per (port, scheme) combo.
        with _patch_urlopen([
                urllib.error.URLError("Connection refused")
                for _ in range(40)]):
            r = propagate_via_forged_ticket(
                ticket, node, state, channels=["http"])

        # Group by (port, scheme) — each candidate should have
        # exactly one path probe before breaking.
        per_candidate = {}
        for att in r["attempts"]:
            if att.get("port") != 44300:
                continue
            key = att.get("use_https")
            per_candidate.setdefault(key, []).append(att)
        for scheme, atts in per_candidate.items():
            assert len(atts) == 1, (
                f"Port 44300 scheme={scheme} got {len(atts)} "
                f"path probes despite connection-refused on the "
                f"first — break-on-network-error didn't fire")

    def test_icm_admin_ports_filtered(self):
        """The scanner sometimes tags ICM admin ports (1128 HTTP,
        1129 HTTPS) with HTTP-ish service names because they
        respond to HTTP probes — but they only host /sap/admin/*
        status pages, never accept MYSAPSSO2 cookies for app auth.
        Propagation must NOT attempt these ports."""
        from sap_ticket_propagate import propagate_via_forged_ticket
        from sapmap_models import SAPMAPState, SAPNode, InstanceInfo
        ticket = _make_ticket()
        # The pathological case the operator reported: scanner only
        # caught the ICM admin ports.  No 8000 / 44300.
        inst = InstanceInfo(
            instance_nr="00", ip="h",
            ports={1128: "ICM_HTTP_ADMIN",
                   1129: "ICM_HTTPS_ADMIN"})
        node = SAPNode(sid="PRD", hostname="h", ip="h",
                        instances=[inst], system_type="ABAP")
        state = SAPMAPState()
        state.add_node(node)
        # Provide enough fake responses for ANY ports that might be
        # tried — but inspect what actually got probed.
        with _patch_urlopen([
                urllib.error.URLError("queue") for _ in range(40)]):
            r = propagate_via_forged_ticket(
                ticket, node, state, channels=["http"])
        # Verify 1128/1129 were skipped
        ports_tried = {att.get("port") for att in r["attempts"]
                       if att.get("channel") == "http"}
        assert 1128 not in ports_tried, \
            f"ICM admin port 1128 must be filtered; got {ports_tried}"
        assert 1129 not in ports_tried, \
            f"ICM admin port 1129 must be filtered; got {ports_tried}"
        # And the SAP-convention fallback still got tried
        assert 8000 in ports_tried, \
            f"Convention HTTP port 8000 missing from {ports_tried}"
        assert 44300 in ports_tried, \
            f"Convention HTTPS port 44300 missing from {ports_tried}"

    def test_icm_ports_from_profile_preferred(self):
        """When ``node.icm_ports`` lists the canonical ports from
        SAP's profile (icm/server_port_<N>), those should be tried
        FIRST — before the scanner-discovered ports and the SAP
        convention fallback.  This is the authoritative source:
        comes straight from the profile via the SSO2 pre-flight
        check that runs as step 2.5 of forge."""
        from sap_ticket_propagate import propagate_via_forged_ticket
        from sapmap_models import SAPMAPState, SAPNode, InstanceInfo
        ticket = _make_ticket()
        inst = InstanceInfo(
            instance_nr="00", ip="h",
            ports={1128: "ICM_HTTP", 1129: "ICM_HTTPS"})
        node = SAPNode(sid="PRD", hostname="h", ip="h",
                        instances=[inst], system_type="ABAP")
        # Simulate: SSO2 profile check ran during a previous forge
        # and extracted real ICM ports from icm/server_port_0 =
        # PROT=HTTP,PORT=8081 and icm/server_port_1 =
        # PROT=HTTPS,PORT=8443.  These are NON-conventional ports —
        # the only way to know about them is to read the SAP
        # profile (via RFC PFL_GET_SINGLE_PARAMETER or the
        # sapxpg-based fallback).
        node.icm_ports = [
            {"port": 8081, "protocol": "http", "index": 0,
             "raw": "PROT=HTTP,PORT=8081"},
            {"port": 8443, "protocol": "https", "index": 1,
             "raw": "PROT=HTTPS,PORT=8443"},
        ]
        state = SAPMAPState()
        state.add_node(node)

        with _patch_urlopen([
                urllib.error.URLError("queue") for _ in range(40)]):
            r = propagate_via_forged_ticket(
                ticket, node, state, channels=["http"])

        # The first HTTP attempt must be one of the
        # profile-discovered ports (most reliable info).
        http_attempts = [a for a in r["attempts"]
                          if a.get("channel") == "http"]
        assert http_attempts, "No HTTP attempts at all"
        first_port = http_attempts[0].get("port")
        assert first_port in (8081, 8443), \
            f"First attempt should be a profile-discovered port; got {first_port}"
        # All profile-discovered ports got tried before the
        # convention fallback.
        ports_in_order = [a.get("port") for a in http_attempts]
        idx_8081 = ports_in_order.index(8081)
        idx_8443 = ports_in_order.index(8443)
        # 8000 / 44300 (convention) should come AFTER the profile
        # ports — they're the fallback.
        if 8000 in ports_in_order:
            assert ports_in_order.index(8000) > idx_8081
        if 44300 in ports_in_order:
            assert ports_in_order.index(44300) > idx_8443

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

    def test_breaks_out_on_rejection_per_port(self):
        """A 401 on one port stops further PATH probes against that
        same port (no point exhausting 3 paths if the first already
        got a definitive auth rejection), but propagation MOVES ON
        to the next port candidate.  Different ICM listeners on the
        same node can have different auth ACLs (e.g. 44300 requires
        client cert SNC; 8000 accepts cookies), so we keep trying.

        Updated for dual-scheme port probing — each non-ICM port
        now generates TWO candidate tuples (HTTPS + HTTP variants)
        because the scanner's scheme tag isn't authoritative.  The
        break-on-rejection happens PER CANDIDATE (i.e. per
        (port, scheme) pair), not per port.  Without the break, a
        single rejection would chew through every path in
        _DEFAULT_HTTP_PATHS; with the break, each (port, scheme)
        gets exactly one path probe before we advance.
        """
        from sap_ticket_propagate import propagate_via_forged_ticket
        from sapmap_models import SAPMAPState

        ticket = _make_ticket()
        node = _make_node("PRD")
        state = SAPMAPState()
        state.add_node(node)

        # Queue a 401 for every URL the propagation tries.  Without
        # the per-(port, scheme) break, each candidate would chew
        # through all 3 paths in _DEFAULT_HTTP_PATHS; with the
        # break we expect exactly 1 path per candidate.
        err = urllib.error.HTTPError(
            "url", 401, "Unauthorized", {}, None)
        with _patch_urlopen([err] * 40):
            r = propagate_via_forged_ticket(
                ticket, node, state, channels=["http"])

        # Group attempts by (port, scheme) and check each candidate
        # saw at most ONE probe — the break-on-rejection behaviour
        # caps each (port, scheme) at 1 attempt, then advances.
        per_candidate = {}
        for att in r["attempts"]:
            key = (att.get("port"), att.get("use_https"))
            per_candidate.setdefault(key, []).append(att)
        for (port, https), attempts in per_candidate.items():
            assert len(attempts) == 1, (
                f"Candidate (port={port}, https={https}) got "
                f"{len(attempts)} probes after a 401 — "
                f"break-on-rejection should cap at 1")
        # Multi-port iteration: more than one distinct port
        # appeared (dual-scheme variants of the SAME port don't
        # count as "different ports" for this assertion).
        distinct_ports = {p for p, _ in per_candidate}
        assert len(distinct_ports) > 1, (
            f"Expected multiple ports tried; only got "
            f"{distinct_ports}")

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
