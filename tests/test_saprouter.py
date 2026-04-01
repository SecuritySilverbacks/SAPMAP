"""Tests for sap_saprouter.py — SAProuter NI protocol."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import struct
import pytest
from sap_saprouter import parse_route_string, build_ni_route_packet, build_route_for_port


class TestParseRouteString:

    def test_two_hops(self):
        hops = parse_route_string("/H/10.0.0.1/S/3299/H/192.168.1.5/S/3200")
        assert len(hops) == 2
        assert hops[0]["host"] == "10.0.0.1"
        assert hops[0]["port"] == "3299"
        assert hops[0]["password"] == ""
        assert hops[1]["host"] == "192.168.1.5"
        assert hops[1]["port"] == "3200"

    def test_with_password(self):
        hops = parse_route_string("/H/router/S/3299/W/secret123/H/target/S/3300")
        assert len(hops) == 2
        assert hops[0]["password"] == "secret123"
        assert hops[1]["password"] == ""

    def test_three_hops(self):
        hops = parse_route_string("/H/r1/S/3299/H/r2/S/3299/H/target/S/3200")
        assert len(hops) == 3

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            parse_route_string("")

    def test_single_hop_raises(self):
        with pytest.raises(ValueError):
            parse_route_string("/H/only_one/S/3299")

    def test_no_slash_raises(self):
        with pytest.raises(ValueError):
            parse_route_string("invalid")

    def test_complex_password(self):
        hops = parse_route_string(
            "/H/3.221.134.53/S/3299/W/abab-experts_now_SecuirtyBridge/H/172.31.14.107/S/3200"
        )
        assert hops[0]["password"] == "abab-experts_now_SecuirtyBridge"
        assert hops[1]["host"] == "172.31.14.107"


class TestBuildNiRoutePacket:

    def test_packet_starts_with_ni_header(self):
        hops = [
            {"host": "10.0.0.1", "port": "3299", "password": ""},
            {"host": "192.168.1.5", "port": "3200", "password": ""},
        ]
        pkt = build_ni_route_packet(hops)
        # First 4 bytes = NI length (big-endian)
        ni_len = struct.unpack("!I", pkt[:4])[0]
        assert ni_len == len(pkt) - 4

    def test_payload_contains_ni_route(self):
        hops = [
            {"host": "r", "port": "3299", "password": ""},
            {"host": "t", "port": "3200", "password": ""},
        ]
        pkt = build_ni_route_packet(hops)
        assert b"NI_ROUTE\x00" in pkt

    def test_version_bytes(self):
        hops = [
            {"host": "r", "port": "3299", "password": ""},
            {"host": "t", "port": "3200", "password": ""},
        ]
        pkt = build_ni_route_packet(hops)
        # After NI header (4) + "NI_ROUTE\0" (9): byte 13 = version=2, byte 14 = ni_version=0x27
        assert pkt[4 + 9] == 0x02  # route protocol version
        assert pkt[4 + 10] == 0x27  # NI version = 39

    def test_entries_count(self):
        hops = [
            {"host": "r", "port": "3299", "password": ""},
            {"host": "t", "port": "3200", "password": ""},
        ]
        pkt = build_ni_route_packet(hops)
        assert pkt[4 + 11] == 2  # 2 entries

    def test_hop_data_contains_hosts(self):
        hops = [
            {"host": "10.0.0.1", "port": "3299", "password": "pass"},
            {"host": "192.168.1.5", "port": "3200", "password": ""},
        ]
        pkt = build_ni_route_packet(hops)
        assert b"10.0.0.1\x00" in pkt
        assert b"3299\x00" in pkt
        assert b"pass\x00" in pkt
        assert b"192.168.1.5\x00" in pkt
        assert b"3200\x00" in pkt


class TestBuildRouteForPort:

    def test_basic(self):
        route = build_route_for_port("/H/router/S/3299", "target", 3200)
        assert route == "/H/router/S/3299/H/target/S/3200"

    def test_with_password(self):
        route = build_route_for_port("/H/r/S/3299/W/pass", "t", 3300)
        assert route == "/H/r/S/3299/W/pass/H/t/S/3300"

    def test_strips_trailing_slash(self):
        route = build_route_for_port("/H/r/S/3299/", "t", 3200)
        assert route == "/H/r/S/3299/H/t/S/3200"
