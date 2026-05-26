#!/usr/bin/env python3
"""Tests for the MYSAPSSO2 ticket builder + parser (commit 4).

Pure-Python — no live SAP needed.  Tests verify:
  - TLV encoding / decoding round-trips
  - build_ticket → parse_ticket preserves all fields
  - Codepage handling (UTF-16LE, UTF-8, Latin-1)
  - Validity time encoding (hours + minutes)
  - Open vs. recipient-pinned tickets
  - Cookie encoding / decoding
  - Edge cases (max-length user, empty fields, truncated tickets)
"""
from __future__ import annotations

import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                "modules", "exploitation"))


# ===================================================================
# InfoUnit TLV encoding / decoding
# ===================================================================

class TestInfoUnitTlv:

    def test_encode_infounit_basic(self):
        from sap_mysapsso2 import _encode_infounit
        result = _encode_infounit(0x01, b"hello")
        # ID=0x01, length=0x0005, payload="hello"
        assert result == b"\x01\x00\x05hello"

    def test_encode_infounit_empty_payload(self):
        from sap_mysapsso2 import _encode_infounit
        result = _encode_infounit(0x06, b"")
        assert result == b"\x06\x00\x00"

    def test_encode_infounit_large_payload(self):
        from sap_mysapsso2 import _encode_infounit
        payload = b"\xAA" * 1000
        result = _encode_infounit(0x03, payload)
        assert result[0] == 0x03
        length = struct.unpack(">H", result[1:3])[0]
        assert length == 1000
        assert result[3:] == payload

    def test_parse_infounits_round_trip(self):
        from sap_mysapsso2 import _encode_infounit, _parse_infounits
        data = (
            _encode_infounit(0x01, b"SAP*") +
            _encode_infounit(0x02, b"000") +
            _encode_infounit(0x03, b"S4H")
        )
        units = _parse_infounits(data)
        assert len(units) == 3
        assert units[0] == (0x01, b"SAP*")
        assert units[1] == (0x02, b"000")
        assert units[2] == (0x03, b"S4H")

    def test_parse_infounits_empty(self):
        from sap_mysapsso2 import _parse_infounits
        assert _parse_infounits(b"") == []

    def test_parse_infounits_truncated(self):
        """Truncated data is handled gracefully (no crash)."""
        from sap_mysapsso2 import _parse_infounits
        # Only 1 byte — not enough for a full TLV header
        units = _parse_infounits(b"\x01")
        assert units == []


# ===================================================================
# Codepage handling
# ===================================================================

class TestCodepage:

    def test_utf16le_encode_decode(self):
        from sap_mysapsso2 import _encode_text, _decode_text
        text = "SAP*"
        encoded = _encode_text(text, "4103")
        assert encoded == b"S\x00A\x00P\x00*\x00"
        assert _decode_text(encoded, "4103") == text

    def test_utf8_encode_decode(self):
        from sap_mysapsso2 import _encode_text, _decode_text
        text = "DDIC"
        encoded = _encode_text(text, "4110")
        assert encoded == b"DDIC"
        assert _decode_text(encoded, "4110") == text

    def test_latin1_encode_decode(self):
        from sap_mysapsso2 import _encode_text, _decode_text
        text = "USER"
        encoded = _encode_text(text, "1100")
        assert encoded == b"USER"
        assert _decode_text(encoded, "1100") == text


# ===================================================================
# build_ticket → parse_ticket round-trip
# ===================================================================

class TestBuildAndParse:

    def test_basic_round_trip(self):
        from sap_mysapsso2 import build_ticket, parse_ticket
        prefix = build_ticket(
            user="SAP*", client="000", sid="S4H",
            validity_min=120, language="E",
            create_time="202601011200")
        parsed = parse_ticket(prefix)
        assert parsed["error"] == ""
        assert parsed["magic"] == 0x02
        assert parsed["codepage"] == "4103"
        assert parsed["user"] == "SAP*"
        assert parsed["client"] == "000"
        assert parsed["sid"] == "S4H"
        assert parsed["create_time"] == "202601011200"
        assert parsed["validity_min"] == 120
        assert parsed["language"] == "E"
        assert parsed["rfc_enabled"] is True
        assert parsed["has_signature"] is False

    def test_user_uppercased(self):
        from sap_mysapsso2 import build_ticket, parse_ticket
        prefix = build_ticket(
            user="sapstar", client="100", sid="prd",
            create_time="202601011200")
        parsed = parse_ticket(prefix)
        assert parsed["user"] == "SAPSTAR"
        assert parsed["sid"] == "PRD"

    def test_client_zero_padded(self):
        from sap_mysapsso2 import build_ticket, parse_ticket
        prefix = build_ticket(
            user="SAP*", client="1", sid="S4H",
            create_time="202601011200")
        parsed = parse_ticket(prefix)
        assert parsed["client"] == "001"

    def test_utf8_codepage(self):
        from sap_mysapsso2 import (build_ticket, parse_ticket,
                                    CODEPAGE_UTF8)
        prefix = build_ticket(
            user="DDIC", client="000", sid="S4H",
            codepage=CODEPAGE_UTF8,
            create_time="202601011200")
        parsed = parse_ticket(prefix)
        assert parsed["codepage"] == "4110"
        assert parsed["user"] == "DDIC"

    def test_validity_hours_and_minutes(self):
        """When validity >= 60min, hours + minutes are split."""
        from sap_mysapsso2 import build_ticket, parse_ticket
        prefix = build_ticket(
            user="SAP*", client="000", sid="S4H",
            validity_min=150,  # 2h30m
            create_time="202601011200")
        parsed = parse_ticket(prefix)
        assert parsed["validity_min"] == 150

    def test_validity_minutes_only(self):
        """When validity < 60min, only ValidTimeInM is set."""
        from sap_mysapsso2 import build_ticket, parse_ticket
        prefix = build_ticket(
            user="SAP*", client="000", sid="S4H",
            validity_min=30,
            create_time="202601011200")
        parsed = parse_ticket(prefix)
        assert parsed["validity_min"] == 30
        # No ValidTimeInH unit
        unit_ids = [u["id"] for u in parsed["units"]]
        assert 0x05 not in unit_ids  # no VALID_TIME_H
        assert 0x07 in unit_ids      # VALID_TIME_M present

    def test_rfc_disabled(self):
        from sap_mysapsso2 import build_ticket, parse_ticket
        prefix = build_ticket(
            user="SAP*", client="000", sid="S4H",
            rfc_enabled=False,
            create_time="202601011200")
        parsed = parse_ticket(prefix)
        assert parsed["rfc_enabled"] is False

    def test_recipient_pinned_ticket(self):
        """Assertion ticket with recipient SID + client."""
        from sap_mysapsso2 import build_ticket, parse_ticket
        prefix = build_ticket(
            user="SAP*", client="000", sid="S4H",
            recipient_sid="PRD",
            recipient_client="100",
            create_time="202601011200")
        parsed = parse_ticket(prefix)
        assert parsed["recipient_sid"] == "PRD"
        assert parsed["recipient_client"] == "100"

    def test_open_ticket_no_recipient(self):
        """Open ticket: no recipient fields present."""
        from sap_mysapsso2 import build_ticket, parse_ticket
        prefix = build_ticket(
            user="SAP*", client="000", sid="S4H",
            create_time="202601011200")
        parsed = parse_ticket(prefix)
        assert parsed["recipient_sid"] == ""
        assert parsed["recipient_client"] == ""

    def test_max_length_user(self):
        """User is truncated to 12 chars."""
        from sap_mysapsso2 import build_ticket, parse_ticket
        prefix = build_ticket(
            user="ABCDEFGHIJKLMNOP", client="000", sid="S4H",
            create_time="202601011200")
        parsed = parse_ticket(prefix)
        assert parsed["user"] == "ABCDEFGHIJKL"
        assert len(parsed["user"]) == 12

    def test_utf8_mirrors_present(self):
        """UTF-8 mirror fields (0x0A-0x0E) are included."""
        from sap_mysapsso2 import build_ticket, parse_ticket
        prefix = build_ticket(
            user="SAP*", client="000", sid="S4H",
            create_time="202601011200")
        parsed = parse_ticket(prefix)
        unit_ids = [u["id"] for u in parsed["units"]]
        assert 0x0A in unit_ids  # UTF8User
        assert 0x0B in unit_ids  # UTF8Client
        assert 0x0C in unit_ids  # UTF8SID

    def test_prefix_bytes_is_full_unsigned_ticket(self):
        """prefix_bytes equals the full ticket when unsigned."""
        from sap_mysapsso2 import build_ticket, parse_ticket
        prefix = build_ticket(
            user="SAP*", client="000", sid="S4H",
            create_time="202601011200")
        parsed = parse_ticket(prefix)
        assert parsed["prefix_bytes"] == prefix

    def test_default_create_time_is_utc_now(self):
        """When create_time is None, current UTC is used."""
        import time
        from sap_mysapsso2 import build_ticket, parse_ticket
        prefix = build_ticket(
            user="SAP*", client="000", sid="S4H")
        parsed = parse_ticket(prefix)
        # The time should be close to now (within 1 minute)
        now = time.strftime("%Y%m%d%H%M", time.gmtime())
        assert parsed["create_time"][:10] == now[:10]


# ===================================================================
# parse_ticket error handling
# ===================================================================

class TestParseErrors:

    def test_empty_ticket(self):
        from sap_mysapsso2 import parse_ticket
        r = parse_ticket(b"")
        assert r["error"]

    def test_wrong_magic(self):
        from sap_mysapsso2 import parse_ticket
        r = parse_ticket(b"\x01" + b"4103" + b"\x00" * 10)
        assert "magic" in r["error"].lower()

    def test_too_short(self):
        from sap_mysapsso2 import parse_ticket
        r = parse_ticket(b"\x02\x41")
        assert r["error"]


# ===================================================================
# Cookie encoding / decoding
# ===================================================================

class TestCookieEncoding:

    def test_encode_for_cookie(self):
        from sap_mysapsso2 import encode_for_cookie
        import base64
        data = b"\x02\x41\x31\x30\x33"
        result = encode_for_cookie(data)
        assert base64.b64decode(result) == data

    def test_encode_for_http_header(self):
        from sap_mysapsso2 import encode_for_http_header
        data = b"\x02\x41\x31\x30\x33"
        header = encode_for_http_header(data)
        assert header.startswith("MYSAPSSO2=")

    def test_decode_from_cookie_plain(self):
        from sap_mysapsso2 import (encode_for_cookie,
                                    decode_from_cookie)
        data = b"test ticket bytes"
        cookie = encode_for_cookie(data)
        assert decode_from_cookie(cookie) == data

    def test_decode_from_cookie_with_prefix(self):
        from sap_mysapsso2 import (encode_for_http_header,
                                    decode_from_cookie)
        data = b"test ticket bytes"
        header = encode_for_http_header(data)
        assert decode_from_cookie(header) == data

    def test_round_trip_build_encode_decode_parse(self):
        """Full chain: build → encode → decode → parse."""
        from sap_mysapsso2 import (build_ticket, parse_ticket,
                                    encode_for_cookie,
                                    decode_from_cookie)
        prefix = build_ticket(
            user="SAP*", client="000", sid="S4H",
            create_time="202601011200")
        cookie = encode_for_cookie(prefix)
        decoded = decode_from_cookie(cookie)
        parsed = parse_ticket(decoded)
        assert parsed["user"] == "SAP*"
        assert parsed["sid"] == "S4H"
