"""Tests for sap_router_info.py — connection table parsing.

The binary format is the SAProuter wire format: exactly 137 bytes per entry:
    [4]  id             big-endian int
    [1]  flags
    [8]  connected_on   (skipped)
    [46] address        null-padded source hostname/IP (+ optional DNS suffix)
    [46] partner        null-padded destination hostname/IP (+ optional DNS suffix)
    [30] service        null-padded destination port/service
    [2]  padding

Note: pysap StrNullFixedLenField(length=45) occupies 46 bytes on the wire
(45 usable chars + 1 mandatory null).  Partner therefore starts at offset 59,
not 58 as pysap's stated field length would suggest.
"""
import sys
import os
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sap_router_info import (
    _parse_conn_table,
    _fixed_str,
    _looks_like_ip,
    _looks_printable,
    _ENTRY_SIZE,
    _FLAG_ROUTED,
    _FLAG_CONNECTED,
)


# ---------------------------------------------------------------------------
# Helper: build a single 137-byte binary entry
# ---------------------------------------------------------------------------

def _make_entry(conn_id: int, address: str, partner: str = "",
                service: str = "", flags: int = 0,
                connected_on: int = 0) -> bytes:
    """Build one SAProuter wire-format entry (137 bytes).

    Wire layout (confirmed against a live SAProuter):
        [0:4]    id             big-endian uint32
        [4]      flags          uint8
        [5:13]   connected_on   big-endian uint64 (skipped by parser)
        [13:59]  address        46-byte null-padded field  (45 usable + 1 null)
        [59:105] partner        46-byte null-padded field
        [105:135] service       30-byte null-padded field
        [135:137] padding       2 bytes
    """
    assert _ENTRY_SIZE == 137
    data  = struct.pack(">I", conn_id)           # [0:4]   id (big-endian)
    data += bytes([flags])                        # [4]     flags
    data += struct.pack(">Q", connected_on)       # [5:13]  connected_on (8 bytes)
    data += address.encode("ascii").ljust(46, b"\x00")[:46]   # [13:59]   address (46 bytes)
    data += partner.encode("ascii").ljust(46, b"\x00")[:46]   # [59:105]  partner (46 bytes)
    data += service.encode("ascii").ljust(30, b"\x00")[:30]   # [105:135] service (30 bytes)
    data += b"\x00" * 2                           # [135:137] padding
    assert len(data) == 137, f"Entry size is {len(data)}, expected 137"
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
# _looks_printable
# ---------------------------------------------------------------------------

class TestLooksPrintable:

    def test_ip_is_printable(self):
        assert _looks_printable("192.168.1.1") is True

    def test_hostname_is_printable(self):
        assert _looks_printable("localhost") is True

    def test_empty_is_not_printable(self):
        assert _looks_printable("") is False

    def test_control_chars_are_not_printable(self):
        assert _looks_printable("\x00abc") is False


# ---------------------------------------------------------------------------
# _fixed_str
# ---------------------------------------------------------------------------

class TestFixedStr:

    def test_reads_null_terminated_string(self):
        data = b"hello\x00" + b"\x00" * 39
        assert _fixed_str(data, 0, 45) == "hello"

    def test_handles_no_null(self):
        data = b"A" * 45
        assert _fixed_str(data, 0, 45) == "A" * 45

    def test_all_null(self):
        data = b"\x00" * 45
        assert _fixed_str(data, 0, 45) == ""

    def test_with_offset(self):
        data = b"\x00" * 13 + b"192.168.1.1\x00" + b"\x00" * 34
        assert _fixed_str(data, 13, 45) == "192.168.1.1"


# ---------------------------------------------------------------------------
# _parse_conn_table  — exact saprouter -l test cases
# ---------------------------------------------------------------------------

class TestParseConnTable:

    def test_single_entry_no_partner(self):
        """
        Mirrors: 188 localhost | (no partner)
        """
        frame = _make_entry(188, "localhost", partner="", service="")
        clients = _parse_conn_table(frame)
        assert len(clients) == 1
        c = clients[0]
        assert c["id"] == 188
        assert c["source"] == "localhost"
        assert c["partner"] == "(no partner)"
        assert c["service"] == ""

    def test_single_entry_with_partner_and_service(self):
        """
        Mirrors: 208 198.51.100.115 | 192.168.2.209   3200
        """
        frame = _make_entry(208, "198.51.100.115",
                            partner="192.168.2.209", service="3200")
        clients = _parse_conn_table(frame)
        assert len(clients) == 1
        c = clients[0]
        assert c["id"] == 208
        assert c["source"] == "198.51.100.115"
        assert c["partner"] == "192.168.2.209"
        assert c["partner_ip"] == "192.168.2.209"
        assert c["service"] == "3200"

    def test_two_entries_exact_user_example(self):
        """
        Mirrors the exact saprouter -l output the user showed:
            188 localhost                     | (no partner)
            208 198.51.100.115         | 192.168.2.209    3200
        """
        frame  = _make_entry(188, "localhost",       partner="",              service="")
        frame += _make_entry(208, "198.51.100.115", partner="192.168.2.209", service="3200")
        clients = _parse_conn_table(frame)
        assert len(clients) == 2

        assert clients[0]["id"] == 188
        assert clients[0]["source"] == "localhost"
        assert clients[0]["partner"] == "(no partner)"
        assert clients[0]["service"] == ""

        assert clients[1]["id"] == 208
        assert clients[1]["source"] == "198.51.100.115"
        assert clients[1]["partner"] == "192.168.2.209"
        assert clients[1]["service"] == "3200"

    def test_entries_with_header_prefix(self):
        """Frame may have a short header before the first entry; parser skips it."""
        header = b"\x00" * 9        # e.g. old num_clients header bytes
        frame  = header + _make_entry(42, "10.0.0.1", "10.0.1.1", "3299")
        clients = _parse_conn_table(frame)
        assert len(clients) == 1
        assert clients[0]["id"] == 42

    def test_partner_ip_empty_for_hostname_partner(self):
        """When the partner field is a hostname (not an IP), partner_ip is empty."""
        frame = _make_entry(5, "10.0.0.1", partner="sap-server.corp", service="3200")
        clients = _parse_conn_table(frame)
        assert clients[0]["partner"] == "sap-server.corp"
        assert clients[0]["partner_ip"] == ""    # not an IP

    def test_partner_ip_set_for_ip_partner(self):
        """partner_ip is populated when the partner field contains an IP."""
        frame = _make_entry(7, "10.0.0.1", partner="192.168.2.50", service="3300")
        clients = _parse_conn_table(frame)
        assert clients[0]["partner_ip"] == "192.168.2.50"

    def test_flag_routed_parsed(self):
        """flag_routed is set when the ROUTED bit is set in the flags byte."""
        frame = _make_entry(1, "10.0.0.1", "10.0.0.2", "3200",
                            flags=_FLAG_ROUTED | _FLAG_CONNECTED)
        clients = _parse_conn_table(frame)
        assert clients[0]["flag_routed"] is True

    def test_flag_routed_false_by_default(self):
        frame = _make_entry(1, "10.0.0.1", flags=0)
        clients = _parse_conn_table(frame)
        assert clients[0]["flag_routed"] is False

    def test_all_required_keys_present(self):
        """Every client dict must have all expected keys."""
        frame = _make_entry(1, "10.0.0.1", "10.0.1.1", "3200")
        clients = _parse_conn_table(frame)
        c = clients[0]
        for key in ("id", "source", "partner", "partner_ip", "service", "flag_routed"):
            assert key in c, f"Missing key: {key}"

    def test_empty_frame_returns_empty(self):
        clients = _parse_conn_table(b"")
        assert clients == []

    def test_too_short_frame_returns_empty(self):
        """Frame shorter than one entry (137 bytes) returns empty list."""
        clients = _parse_conn_table(b"\x00" * 100)
        assert clients == []

    def test_all_zero_entries_skipped(self):
        """An all-zero entry (empty address and partner) is skipped."""
        frame = b"\x00" * 137
        clients = _parse_conn_table(frame)
        assert clients == []

    def test_three_entries(self):
        """Three consecutive entries are all parsed."""
        frame  = _make_entry(1, "10.0.0.1", "10.0.1.1", "3200")
        frame += _make_entry(2, "10.0.0.2", "",          "")
        frame += _make_entry(3, "10.0.0.3", "10.0.1.3",  "3300")
        clients = _parse_conn_table(frame)
        assert len(clients) == 3
        assert clients[0]["id"] == 1
        assert clients[1]["id"] == 2
        assert clients[2]["id"] == 3

    def test_entry_size_constant_is_137(self):
        """Verify that _ENTRY_SIZE matches the actual built entry size."""
        entry = _make_entry(1, "x")
        assert len(entry) == _ENTRY_SIZE == 137

    def test_source_address_fills_field(self):
        """A 44-char address fits in the 46-byte field; parser returns it intact."""
        addr = "A" * 44   # 44 chars + null terminator within the 46-byte field
        frame = _make_entry(1, addr)
        clients = _parse_conn_table(frame)
        assert clients[0]["source"] == addr

    def test_id_zero_is_valid(self):
        """Connection ID 0 is a valid value and should be kept."""
        frame = _make_entry(0, "localhost")
        clients = _parse_conn_table(frame)
        assert len(clients) == 1
        assert clients[0]["id"] == 0
