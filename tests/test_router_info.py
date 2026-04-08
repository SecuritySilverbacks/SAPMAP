"""Tests for sap_router_info.py — connection table parsing."""
import sys
import os
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sap_router_info import (
    _parse_conn_table,
    _parse_conn_table_text,
    _looks_like_ip,
    _read_null_str,
)


# ---------------------------------------------------------------------------
# Helper: build a binary connection entry in the pysap format
#   [4 LE uint32: id][4 bytes: src_ip][null-term: partner][null-term: svc][null-term: host]
# ---------------------------------------------------------------------------

def _make_entry(conn_id: int, src_ip: str, partner: str = "",
                service: str = "", host: str = "") -> bytes:
    data  = struct.pack("<I", conn_id)
    data += bytes(int(x) for x in src_ip.split("."))
    data += partner.encode("ascii") + b"\x00"
    data += service.encode("ascii") + b"\x00"
    data += host.encode("ascii") + b"\x00"
    return data


# ---------------------------------------------------------------------------
# _looks_like_ip
# ---------------------------------------------------------------------------

class TestLooksLikeIp:

    def test_valid_ip(self):
        assert _looks_like_ip("192.168.2.209") is True

    def test_localhost(self):
        assert _looks_like_ip("127.0.0.1") is True

    def test_hostname(self):
        assert _looks_like_ip("localhost") is False

    def test_empty(self):
        assert _looks_like_ip("") is False

    def test_partial(self):
        assert _looks_like_ip("192.168.1") is False

    def test_out_of_range(self):
        assert _looks_like_ip("256.0.0.1") is False


# ---------------------------------------------------------------------------
# _read_null_str
# ---------------------------------------------------------------------------

class TestReadNullStr:

    def test_basic(self):
        data = b"hello\x00world\x00"
        s, new_i = _read_null_str(data, 0)
        assert s == "hello"
        assert new_i == 6

    def test_empty_string(self):
        data = b"\x00rest"
        s, new_i = _read_null_str(data, 0)
        assert s == ""
        assert new_i == 1

    def test_no_null(self):
        data = b"no null here"
        s, new_i = _read_null_str(data, 0)
        assert s == ""
        assert new_i == -1

    def test_offset(self):
        data = b"skip\x00hello\x00"
        s, new_i = _read_null_str(data, 5)
        assert s == "hello"
        assert new_i == 11


# ---------------------------------------------------------------------------
# _parse_conn_table (binary format)
# ---------------------------------------------------------------------------

class TestParseConnTable:

    def test_single_entry_no_partner(self):
        """Entry with no partner and no service (like a monitoring connection)."""
        data = _make_entry(188, "127.0.0.1", partner="", service="", host="localhost")
        clients = _parse_conn_table(data, 1)
        assert len(clients) == 1
        c = clients[0]
        assert c["id"] == 188
        assert c["ip"] == "127.0.0.1"
        assert c["source"] == "localhost"    # hostname preferred over IP
        assert c["partner"] == "(no partner)"
        assert c["service"] == ""

    def test_single_entry_with_partner(self):
        """Entry with destination IP and service port."""
        data = _make_entry(208, "178.230.159.115",
                           partner="192.168.2.209", service="3200",
                           host="178.230.159.115")
        clients = _parse_conn_table(data, 1)
        assert len(clients) == 1
        c = clients[0]
        assert c["id"] == 208
        assert c["ip"] == "178.230.159.115"
        assert c["partner"] == "192.168.2.209"
        assert c["partner_ip"] == "192.168.2.209"
        assert c["service"] == "3200"

    def test_two_entries(self):
        """Two entries — mirrors the example from the user's saprouter -l output."""
        data  = _make_entry(188, "127.0.0.1",       partner="",              service="",     host="localhost")
        data += _make_entry(208, "178.230.159.115",  partner="192.168.2.209", service="3200", host="")
        clients = _parse_conn_table(data, 2)
        assert len(clients) == 2
        assert clients[0]["id"] == 188
        assert clients[0]["source"] == "localhost"
        assert clients[0]["partner"] == "(no partner)"
        assert clients[1]["id"] == 208
        assert clients[1]["partner"] == "192.168.2.209"
        assert clients[1]["service"] == "3200"

    def test_source_falls_back_to_ip_when_no_hostname(self):
        """If hostname is empty, source should show the IP instead."""
        data = _make_entry(100, "10.0.0.5", partner="10.0.1.1", service="3299", host="")
        clients = _parse_conn_table(data, 1)
        assert clients[0]["source"] == "10.0.0.5"

    def test_partner_ip_empty_for_hostname_partner(self):
        """partner_ip should be empty when the partner field is a hostname, not an IP."""
        data = _make_entry(50, "10.0.0.1", partner="sap-server.corp", service="3200", host="")
        clients = _parse_conn_table(data, 1)
        assert clients[0]["partner"] == "sap-server.corp"
        assert clients[0]["partner_ip"] == ""   # not an IP → no partner_ip

    def test_empty_data_returns_empty(self):
        clients = _parse_conn_table(b"", 5)
        assert clients == []

    def test_truncated_data_does_not_crash(self):
        """Partial data (truncated mid-entry) must not raise an exception."""
        data = _make_entry(1, "1.2.3.4", "5.6.7.8", "3200", "host")[:10]
        clients = _parse_conn_table(data, 1)
        # May produce 0 or partial entries — just must not crash
        assert isinstance(clients, list)

    def test_conn_id_in_each_entry_dict(self):
        """Every parsed entry must have an 'id' key."""
        data = _make_entry(42, "10.10.10.1", "", "", "")
        clients = _parse_conn_table(data, 1)
        assert "id" in clients[0]
        assert clients[0]["id"] == 42

    def test_all_required_keys_present(self):
        """All expected keys must be present in every client dict."""
        data = _make_entry(1, "10.0.0.1", "10.0.1.1", "3200", "client-host")
        clients = _parse_conn_table(data, 1)
        c = clients[0]
        for key in ("id", "source", "ip", "partner", "partner_ip", "service"):
            assert key in c, f"Missing key: {key}"

    def test_ignores_implausibly_large_conn_id(self):
        """A connection ID > 0xFFFF probably means the format is wrong — stop parsing."""
        bad_id = 0xDEADBEEF  # > 65535
        data = struct.pack("<I", bad_id) + b"\x01\x02\x03\x04" + b"\x00\x00\x00"
        clients = _parse_conn_table(data, 1)
        assert clients == []


# ---------------------------------------------------------------------------
# _parse_conn_table_text (text fallback)
# ---------------------------------------------------------------------------

class TestParseConnTableText:

    def test_no_partner_line(self):
        lines = ["188 localhost                     | (no partner)"]
        clients = _parse_conn_table_text(lines)
        assert len(clients) == 1
        assert clients[0]["id"] == 188
        assert clients[0]["source"] == "localhost"
        assert "(no partner)" in clients[0]["partner"]

    def test_with_partner_and_service(self):
        lines = ["208 178.230.159.115         | 192.168.2.209                  3200"]
        clients = _parse_conn_table_text(lines)
        assert len(clients) == 1
        c = clients[0]
        assert c["id"] == 208
        assert c["source"] == "178.230.159.115"
        assert c["partner"] == "192.168.2.209"
        assert c["service"] == "3200"

    def test_two_lines(self):
        lines = [
            "188 localhost                     | (no partner)",
            "208 178.230.159.115         | 192.168.2.209                  3200",
        ]
        clients = _parse_conn_table_text(lines)
        assert len(clients) == 2

    def test_non_matching_lines_ignored(self):
        lines = [
            "Total no. of clients:         2",
            "Working directory  :          /usr/sap/saprouter/",
            "188 localhost                     | (no partner)",
        ]
        clients = _parse_conn_table_text(lines)
        assert len(clients) == 1

    def test_empty_lines_ignored(self):
        clients = _parse_conn_table_text(["", "   ", "\t"])
        assert clients == []

    def test_partner_ip_set_for_ip_addresses(self):
        lines = ["1 10.0.0.1 | 10.0.0.2 3300"]
        clients = _parse_conn_table_text(lines)
        assert clients[0]["partner_ip"] == "10.0.0.2"

    def test_partner_ip_empty_for_no_partner(self):
        lines = ["1 10.0.0.1 | (no partner)"]
        clients = _parse_conn_table_text(lines)
        assert clients[0]["partner_ip"] == ""

    def test_all_required_keys_present(self):
        lines = ["208 178.230.159.115 | 192.168.2.209 3200"]
        clients = _parse_conn_table_text(lines)
        c = clients[0]
        for key in ("id", "source", "ip", "partner", "partner_ip", "service"):
            assert key in c, f"Missing key: {key}"
