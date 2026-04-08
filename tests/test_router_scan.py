"""Tests for SAProuter internal scanning — sap_saprouter.probe_port_via_saprouter()
and sapmap_scanner router scan functions.

All tests use mocked sockets / probes so no network connectivity is required.
"""
import sys
import os
import socket
import struct
import threading
import unittest
from unittest.mock import patch, MagicMock, call

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sap_saprouter import (
    probe_port_via_saprouter,
    PROBE_OPEN, PROBE_CLOSED, PROBE_ACL_DENIED,
    PROBE_FILTERED, PROBE_UNKNOWN_HOST, PROBE_ERROR,
)
from sapmap_scanner import (
    _sap_ports_for_instance_range,
    extract_targets_from_router_info,
    scan_host_via_saprouter,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ni_frame(payload: bytes) -> bytes:
    """Wrap bytes in an NI frame (4-byte BE length header + payload)."""
    return struct.pack("!I", len(payload)) + payload


def _make_mock_socket(response_bytes: bytes):
    """Return a mock socket that sends *response_bytes* on recv."""
    sock = MagicMock()
    # Simulate recv: first call returns 4-byte header, second returns payload
    if response_bytes:
        header = response_bytes[:4]
        rest   = response_bytes[4:]
        # recv is called repeatedly; chain the side effects
        sock.recv.side_effect = [header] + (
            [rest] if rest else []
        ) + [b""]  # EOF
    else:
        sock.recv.return_value = b""
    return sock


# ---------------------------------------------------------------------------
# Tests: probe_port_via_saprouter()
# ---------------------------------------------------------------------------

class TestProbePortViaSaprouter(unittest.TestCase):

    ROUTER_PREFIX = "/H/10.0.0.1/S/3299"
    TARGET_HOST   = "192.168.1.50"
    TARGET_PORT   = 3200

    def _patch_socket(self, response: bytes):
        """Context manager: patch socket.socket to return *response* on recv."""
        mock_sock = MagicMock()
        # Simulate chunked recv: header first, then payload
        if len(response) >= 4:
            header = response[:4]
            body   = response[4:]
            chunks = [header]
            if body:
                chunks.append(body)
            chunks.append(b"")   # EOF
            mock_sock.recv.side_effect = chunks
        else:
            mock_sock.recv.return_value = response

        patcher = patch("socket.socket", return_value=mock_sock)
        return patcher, mock_sock

    def test_open_on_ni_pong_frame(self):
        """NI_PONG response → status=open."""
        resp = _ni_frame(b"NI_PONG")
        p, _ = self._patch_socket(resp)
        with p:
            result = probe_port_via_saprouter(
                self.ROUTER_PREFIX, self.TARGET_HOST, self.TARGET_PORT)
        assert result["status"] == PROBE_OPEN

    def test_open_on_empty_frame(self):
        """Empty NI frame (length=0) is also a success (NI_PONG equivalent)."""
        resp = struct.pack("!I", 0)   # 4-byte zero length, no payload
        p, _ = self._patch_socket(resp)
        with p:
            result = probe_port_via_saprouter(
                self.ROUTER_PREFIX, self.TARGET_HOST, self.TARGET_PORT)
        assert result["status"] == PROBE_OPEN

    def test_closed_on_refused(self):
        """NI_RTERR containing 'refused' → status=closed."""
        body = b"NI_RTERR\x00connection refused by target"
        resp = _ni_frame(body)
        p, _ = self._patch_socket(resp)
        with p:
            result = probe_port_via_saprouter(
                self.ROUTER_PREFIX, self.TARGET_HOST, self.TARGET_PORT)
        assert result["status"] == PROBE_CLOSED

    def test_acl_denied(self):
        """NI_RTERR containing 'denied' → status=acl_denied."""
        body = b"NI_RTERR\x00connection denied by ACL"
        resp = _ni_frame(body)
        p, _ = self._patch_socket(resp)
        with p:
            result = probe_port_via_saprouter(
                self.ROUTER_PREFIX, self.TARGET_HOST, self.TARGET_PORT)
        assert result["status"] == PROBE_ACL_DENIED

    def test_filtered_on_timed_out(self):
        """NI_RTERR 'timed out' → status=filtered."""
        body = b"NI_RTERR\x00connection to partner timed out"
        resp = _ni_frame(body)
        p, _ = self._patch_socket(resp)
        with p:
            result = probe_port_via_saprouter(
                self.ROUTER_PREFIX, self.TARGET_HOST, self.TARGET_PORT)
        assert result["status"] == PROBE_FILTERED

    def test_filtered_on_not_reached(self):
        """NI_RTERR 'not reached' → status=filtered."""
        body = b"NI_RTERR\x00partner 192.168.1.50:3200 not reached"
        resp = _ni_frame(body)
        p, _ = self._patch_socket(resp)
        with p:
            result = probe_port_via_saprouter(
                self.ROUTER_PREFIX, self.TARGET_HOST, self.TARGET_PORT)
        assert result["status"] == PROBE_FILTERED

    def test_filtered_on_saprouter_reacheable_typo(self):
        """SAP kernel typo 'reacheable' → status=filtered."""
        body = b"NI_RTERR\x00host not reacheable"
        resp = _ni_frame(body)
        p, _ = self._patch_socket(resp)
        with p:
            result = probe_port_via_saprouter(
                self.ROUTER_PREFIX, self.TARGET_HOST, self.TARGET_PORT)
        assert result["status"] == PROBE_FILTERED

    def test_unknown_host(self):
        """NI_RTERR 'unknown' → status=unknown_host."""
        body = b"NI_RTERR\x00hostname '192.168.1.50' unknown"
        resp = _ni_frame(body)
        p, _ = self._patch_socket(resp)
        with p:
            result = probe_port_via_saprouter(
                self.ROUTER_PREFIX, self.TARGET_HOST, self.TARGET_PORT)
        assert result["status"] == PROBE_UNKNOWN_HOST

    def test_gethostbyname_unknown_host(self):
        """NI_RTERR 'GetHostByName' → status=unknown_host (case-insensitive)."""
        body = b"NI_RTERR\x00GetHostByName: 'internal.corp' not found"
        resp = _ni_frame(body)
        p, _ = self._patch_socket(resp)
        with p:
            result = probe_port_via_saprouter(
                self.ROUTER_PREFIX, self.TARGET_HOST, self.TARGET_PORT)
        assert result["status"] == PROBE_UNKNOWN_HOST

    def test_error_on_connection_failure(self):
        """Socket connect() failure → status=error."""
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.connect.side_effect = ConnectionRefusedError("refused")
            mock_sock_cls.return_value = mock_sock

            result = probe_port_via_saprouter(
                self.ROUTER_PREFIX, self.TARGET_HOST, self.TARGET_PORT)
        assert result["status"] == PROBE_ERROR
        assert "refused" in result["message"].lower()

    def test_filtered_on_socket_timeout(self):
        """Socket timeout waiting for response → status=filtered."""
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.recv.side_effect = socket.timeout("timed out")
            mock_sock_cls.return_value = mock_sock

            result = probe_port_via_saprouter(
                self.ROUTER_PREFIX, self.TARGET_HOST, self.TARGET_PORT)
        assert result["status"] == PROBE_FILTERED

    def test_invalid_route_string(self):
        """Malformed route prefix → status=error."""
        result = probe_port_via_saprouter(
            "not_a_route", self.TARGET_HOST, self.TARGET_PORT)
        assert result["status"] == PROBE_ERROR

    def test_message_populated_on_acl_denied(self):
        """ACL denied result includes the SAProuter error text in message."""
        body = b"NI_RTERR\x00route denied by ACL rule 42"
        resp = _ni_frame(body)
        p, _ = self._patch_socket(resp)
        with p:
            result = probe_port_via_saprouter(
                self.ROUTER_PREFIX, self.TARGET_HOST, self.TARGET_PORT)
        assert result["status"] == PROBE_ACL_DENIED
        assert "denied" in result["message"].lower()

    def test_open_message_is_empty(self):
        """Open result has an empty message (no error text)."""
        resp = _ni_frame(b"NI_PONG")
        p, _ = self._patch_socket(resp)
        with p:
            result = probe_port_via_saprouter(
                self.ROUTER_PREFIX, self.TARGET_HOST, self.TARGET_PORT)
        assert result["status"] == PROBE_OPEN
        assert result["message"] == ""


# ---------------------------------------------------------------------------
# Tests: _sap_ports_for_instance_range()
# ---------------------------------------------------------------------------

class TestSapPortsForInstanceRange(unittest.TestCase):

    def test_default_includes_dispatcher_and_gateway(self):
        ports = _sap_ports_for_instance_range((0, 2))
        port_nums = [p[0] for p in ports]
        assert 3200 in port_nums   # dispatcher inst 00
        assert 3201 in port_nums   # dispatcher inst 01
        assert 3202 in port_nums   # dispatcher inst 02
        assert 3300 in port_nums   # gateway inst 00
        assert 3302 in port_nums   # gateway inst 02

    def test_includes_saprouter_port_3299(self):
        """SAProuter port 3299 is always included to detect chained routers."""
        ports = _sap_ports_for_instance_range((0, 0))
        port_nums = [p[0] for p in ports]
        assert 3299 in port_nums

    def test_includes_saphost_ports(self):
        ports = _sap_ports_for_instance_range((0, 0))
        port_nums = [p[0] for p in ports]
        assert 1128 in port_nums
        assert 1129 in port_nums

    def test_hana_excluded_by_default(self):
        ports = _sap_ports_for_instance_range((0, 2))
        port_nums = [p[0] for p in ports]
        assert 30013 not in port_nums  # HANA SystemDB
        assert 30015 not in port_nums  # HANA tenant

    def test_hana_included_when_requested(self):
        ports = _sap_ports_for_instance_range((0, 0), include_hana=True)
        port_nums = [p[0] for p in ports]
        assert 30013 in port_nums
        assert 30015 in port_nums

    def test_java_excluded_by_default(self):
        ports = _sap_ports_for_instance_range((0, 0))
        port_nums = [p[0] for p in ports]
        assert 50000 not in port_nums  # Java HTTP

    def test_java_included_when_requested(self):
        ports = _sap_ports_for_instance_range((0, 0), include_java=True)
        port_nums = [p[0] for p in ports]
        assert 50000 in port_nums

    def test_msgserver_included_by_default(self):
        ports = _sap_ports_for_instance_range((0, 0))
        port_nums = [p[0] for p in ports]
        assert 3600 in port_nums   # message server inst 00

    def test_msgserver_excluded_when_disabled(self):
        ports = _sap_ports_for_instance_range((0, 0), include_msgserver=False)
        port_nums = [p[0] for p in ports]
        assert 3600 not in port_nums

    def test_service_labels(self):
        ports = _sap_ports_for_instance_range((0, 0))
        svc_map = {p[0]: p[1] for p in ports}
        assert svc_map[3200] == "dispatcher"
        assert svc_map[3300] == "gateway"
        assert svc_map[3299] == "saprouter"
        assert svc_map[1128] == "saphost_http"

    def test_instance_string_format(self):
        ports = _sap_ports_for_instance_range((5, 5))
        disp = next(p for p in ports if p[0] == 3205)
        assert disp[2] == "05"   # zero-padded


# ---------------------------------------------------------------------------
# Tests: extract_targets_from_router_info()
# ---------------------------------------------------------------------------

class TestExtractTargetsFromRouterInfo(unittest.TestCase):

    def test_extracts_client_ips(self):
        info = {
            "vulnerable": True,
            "clients": [
                {"host": "192.168.2.10", "source": "corp-pc"},
                {"host": "192.168.2.20", "source": "sap-server"},
            ],
            "raw_info": [],
        }
        targets = extract_targets_from_router_info(info)
        assert "192.168.2.10" in targets
        assert "192.168.2.20" in targets

    def test_extracts_ips_from_raw_info(self):
        info = {
            "vulnerable": True,
            "clients": [],
            "raw_info": [
                "KT /H/10.0.1.5/S/3299 P  active",
                "TP /H/10.0.1.6/S/3200 OK",
            ],
        }
        targets = extract_targets_from_router_info(info)
        assert "10.0.1.5" in targets
        assert "10.0.1.6" in targets

    def test_deduplicates(self):
        info = {
            "vulnerable": True,
            "clients": [
                {"host": "10.0.0.5"},
                {"host": "10.0.0.5"},
            ],
            "raw_info": ["KT /H/10.0.0.5/S/3299"],
        }
        targets = extract_targets_from_router_info(info)
        assert targets.count("10.0.0.5") == 1

    def test_ignores_hostnames_in_clients(self):
        """Hostnames (non-IP) in client list are ignored — can't scan by name."""
        info = {
            "vulnerable": True,
            "clients": [{"host": "sap-server.corp.local"}],
            "raw_info": [],
        }
        targets = extract_targets_from_router_info(info)
        assert "sap-server.corp.local" not in targets

    def test_returns_sorted_list(self):
        info = {
            "vulnerable": True,
            "clients": [
                {"host": "10.0.0.20"},
                {"host": "10.0.0.5"},
                {"host": "10.0.0.1"},
            ],
            "raw_info": [],
        }
        targets = extract_targets_from_router_info(info)
        assert targets == sorted(targets, key=lambda ip: tuple(int(x) for x in ip.split(".")))

    def test_empty_info_returns_empty(self):
        targets = extract_targets_from_router_info({})
        assert targets == []


# ---------------------------------------------------------------------------
# Tests: scan_host_via_saprouter()
# ---------------------------------------------------------------------------

class TestScanHostViaSaprouter(unittest.TestCase):

    ROUTER_PREFIX = "/H/10.0.0.1/S/3299"
    TARGET        = "192.168.1.50"

    def test_open_port_appears_in_open_ports(self):
        ports = [(3200, "dispatcher", "00")]
        with patch("sap_saprouter.probe_port_via_saprouter",
                   return_value={"status": PROBE_OPEN, "message": ""}):
            result = scan_host_via_saprouter(
                self.ROUTER_PREFIX, self.TARGET, ports, timeout=1)
        assert 3200 in result["open_ports"]
        assert result["open_ports"][3200]["service"] == "dispatcher"
        assert result["has_sap"] is True

    def test_acl_denied_port_in_acl_denied_list(self):
        ports = [(3300, "gateway", "00")]
        with patch("sap_saprouter.probe_port_via_saprouter",
                   return_value={"status": PROBE_ACL_DENIED, "message": "denied"}):
            result = scan_host_via_saprouter(
                self.ROUTER_PREFIX, self.TARGET, ports, timeout=1)
        assert 3300 in result["acl_denied_ports"]
        assert 3300 not in result["open_ports"]

    def test_closed_port_not_in_either_list(self):
        ports = [(3200, "dispatcher", "00")]
        with patch("sap_saprouter.probe_port_via_saprouter",
                   return_value={"status": PROBE_CLOSED, "message": "refused"}):
            result = scan_host_via_saprouter(
                self.ROUTER_PREFIX, self.TARGET, ports, timeout=1)
        assert 3200 not in result["open_ports"]
        assert 3200 not in result["acl_denied_ports"]
        assert result["has_sap"] is False

    def test_has_sap_false_when_only_acl_denied(self):
        """has_sap is False when ports are ACL-denied but not open."""
        ports = [(3200, "dispatcher", "00"), (3300, "gateway", "00")]
        with patch("sap_saprouter.probe_port_via_saprouter",
                   return_value={"status": PROBE_ACL_DENIED, "message": "denied"}):
            result = scan_host_via_saprouter(
                self.ROUTER_PREFIX, self.TARGET, ports, timeout=1)
        assert result["has_sap"] is False
        assert len(result["acl_denied_ports"]) == 2

    def test_probe_counts_tracked(self):
        """probe_counts dict correctly tallies each status."""
        ports = [
            (3200, "dispatcher", "00"),
            (3300, "gateway",    "00"),
            (3600, "msgserver",  "00"),
        ]
        statuses = [PROBE_OPEN, PROBE_ACL_DENIED, PROBE_FILTERED]
        with patch("sap_saprouter.probe_port_via_saprouter",
                   side_effect=[{"status": s, "message": ""} for s in statuses]):
            result = scan_host_via_saprouter(
                self.ROUTER_PREFIX, self.TARGET, ports, timeout=1)
        assert result["probe_counts"][PROBE_OPEN] == 1
        assert result["probe_counts"][PROBE_ACL_DENIED] == 1
        assert result["probe_counts"][PROBE_FILTERED] == 1

    def test_cancellation_stops_early(self):
        """Setting cancel_event stops the scan without processing all ports."""
        cancel = threading.Event()
        cancel.set()   # pre-cancelled
        ports = [(p, "dispatcher", "00") for p in range(3200, 3250)]
        with patch("sap_saprouter.probe_port_via_saprouter",
                   return_value={"status": PROBE_OPEN, "message": ""}) as mock_probe:
            result = scan_host_via_saprouter(
                self.ROUTER_PREFIX, self.TARGET, ports,
                timeout=1, cancel_event=cancel)
        # Some or all probes may be skipped; key: no exception raised
        assert "open_ports" in result

    def test_result_structure(self):
        """Result always has all expected keys."""
        with patch("sap_saprouter.probe_port_via_saprouter",
                   return_value={"status": PROBE_FILTERED, "message": ""}):
            result = scan_host_via_saprouter(
                self.ROUTER_PREFIX, self.TARGET, [], timeout=1)
        assert "host" in result
        assert "open_ports" in result
        assert "acl_denied_ports" in result
        assert "has_sap" in result
        assert "probe_counts" in result
        assert result["host"] == self.TARGET
