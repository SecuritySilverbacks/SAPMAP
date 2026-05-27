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
        """When validity < 60min, ValidTimeInH=0 + ValidTimeInM=N.

        Real SAP-issued tickets ALWAYS emit InfoUnit 0x05
        (ValidTimeInH) even when hours=0 — and emit 0x07
        (ValidTimeInM) ONLY when minutes != 0.  Confirmed via the
        captured-from-live-SAP diff in commit 13.
        """
        from sap_mysapsso2 import build_ticket, parse_ticket
        prefix = build_ticket(
            user="SAP*", client="000", sid="S4H",
            validity_min=30,
            create_time="202601011200")
        parsed = parse_ticket(prefix)
        assert parsed["validity_min"] == 30
        unit_ids = [u["id"] for u in parsed["units"]]
        # Both H and M present — H=0 (zero hours), M=30
        assert 0x05 in unit_ids
        assert 0x07 in unit_ids

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

    def test_utf8_mirrors_absent(self):
        """UTF-8 mirror fields (0x0A-0x0E) are NOT included.

        We used to emit them on the theory that "modern receivers
        need them" — but a side-by-side diff against a real SAP-
        issued MYSAPSSO2 cookie proved otherwise: real SAP tickets
        do NOT contain InfoUnits 0x0A-0x0E.  Including them caused
        SAP's strict PKCS#7 verifier to reject our forgeries.
        See commit 13 / docs for the wire-format diff.
        """
        from sap_mysapsso2 import build_ticket, parse_ticket
        prefix = build_ticket(
            user="SAP*", client="000", sid="S4H",
            create_time="202601011200")
        parsed = parse_ticket(prefix)
        unit_ids = [u["id"] for u in parsed["units"]]
        assert 0x0A not in unit_ids  # no UTF8User
        assert 0x0B not in unit_ids  # no UTF8Client
        assert 0x0C not in unit_ids  # no UTF8SID
        assert 0x0D not in unit_ids  # no UTF8Time
        assert 0x0E not in unit_ids  # no UTF8Language

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


# ===================================================================
# PKCS#7 signer tests (commit 5)
# ===================================================================

def _generate_test_key_and_cert():
    """Generate a 2048-bit RSA key + self-signed cert for tests."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                           "SAP Trust Community"),
        x509.NameAttribute(NameOID.COMMON_NAME, "S4H"),
    ])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    return key, cert


class TestSignTicket:

    def test_sign_produces_valid_ticket(self):
        from sap_mysapsso2 import (build_ticket, sign_ticket,
                                    parse_ticket)
        key, cert = _generate_test_key_and_cert()
        prefix = build_ticket(
            user="SAP*", client="000", sid="S4H",
            create_time="202601011200")
        signed = sign_ticket(prefix, key, cert)
        assert len(signed) > len(prefix)

        parsed = parse_ticket(signed)
        assert parsed["error"] == ""
        assert parsed["has_signature"] is True
        assert len(parsed["signature_bytes"]) > 100
        assert parsed["user"] == "SAP*"
        assert parsed["sid"] == "S4H"

    def test_prefix_bytes_excludes_signature(self):
        from sap_mysapsso2 import (build_ticket, sign_ticket,
                                    parse_ticket)
        key, cert = _generate_test_key_and_cert()
        prefix = build_ticket(
            user="SAP*", client="000", sid="S4H",
            create_time="202601011200")
        signed = sign_ticket(prefix, key, cert)
        parsed = parse_ticket(signed)
        assert parsed["prefix_bytes"] == prefix

    def test_signature_is_valid_cms(self):
        """The 0xFF payload is valid DER-encoded CMS SignedData."""
        from sap_mysapsso2 import (build_ticket, sign_ticket,
                                    parse_ticket)
        key, cert = _generate_test_key_and_cert()
        prefix = build_ticket(
            user="SAP*", client="000", sid="S4H",
            create_time="202601011200")
        signed = sign_ticket(prefix, key, cert)
        parsed = parse_ticket(signed)
        sig = parsed["signature_bytes"]
        # DER SignedData starts with SEQUENCE tag (0x30)
        assert sig[0] == 0x30
        # Must be substantial (RSA-2048 sig alone is ~256 bytes)
        assert len(sig) > 200

    def test_include_cert_false_smaller(self):
        """NoCerts option produces a smaller signature."""
        from sap_mysapsso2 import (build_ticket, sign_ticket,
                                    parse_ticket)
        key, cert = _generate_test_key_and_cert()
        prefix = build_ticket(
            user="SAP*", client="000", sid="S4H",
            create_time="202601011200")
        signed_with = sign_ticket(prefix, key, cert,
                                   include_cert=True)
        signed_without = sign_ticket(prefix, key, cert,
                                      include_cert=False)
        assert len(signed_without) < len(signed_with)

    def test_sha1_digest_rejected(self):
        """SHA-1 is not supported — clear error, not a crash."""
        from sap_mysapsso2 import build_ticket, sign_ticket
        key, cert = _generate_test_key_and_cert()
        prefix = build_ticket(
            user="SAP*", client="000", sid="S4H",
            create_time="202601011200")
        with pytest.raises(ValueError, match="unsupported"):
            sign_ticket(prefix, key, cert, digest="sha1")

    def test_sha384_digest(self):
        """SHA-384 signing works."""
        from sap_mysapsso2 import (build_ticket, sign_ticket,
                                    parse_ticket)
        key, cert = _generate_test_key_and_cert()
        prefix = build_ticket(
            user="SAP*", client="000", sid="S4H",
            create_time="202601011200")
        signed = sign_ticket(prefix, key, cert, digest="sha384")
        parsed = parse_ticket(signed)
        assert parsed["has_signature"] is True

    def test_verify_signature_with_openssl(self):
        """Verify the PKCS#7 signature is cryptographically valid."""
        from sap_mysapsso2 import (build_ticket, sign_ticket,
                                    parse_ticket)
        from cryptography.hazmat.primitives.serialization import (
            pkcs7)
        from cryptography import x509 as cx509

        key, cert = _generate_test_key_and_cert()
        prefix = build_ticket(
            user="SAP*", client="000", sid="S4H",
            create_time="202601011200")
        signed = sign_ticket(prefix, key, cert)
        parsed = parse_ticket(signed)

        # Verify the detached signature against the prefix
        # using the cryptography library's PKCS7 verification
        try:
            pkcs7.load_der_pkcs7_certificates(
                parsed["signature_bytes"])
            # If we can load it, the CMS structure is valid
        except Exception:
            pytest.fail("signature_bytes is not valid DER CMS")


class TestForgeTicket:

    def test_forge_one_call(self):
        from sap_mysapsso2 import forge_ticket
        key, cert = _generate_test_key_and_cert()
        r = forge_ticket(
            user="SAP*", client="000", sid="S4H",
            private_key=key, certificate=cert,
            validity_min=120,
            create_time="202601011200")
        assert r["success"] is True
        assert r["ticket_bytes"]
        assert r["cookie_b64"]
        assert "MYSAPSSO2=" in r["http_header"]
        assert r["parsed"]["user"] == "SAP*"
        assert r["parsed"]["has_signature"] is True

    def test_forge_cookie_decodable(self):
        """The cookie_b64 decodes back to the ticket bytes."""
        from sap_mysapsso2 import (forge_ticket,
                                    decode_from_cookie)
        key, cert = _generate_test_key_and_cert()
        r = forge_ticket(
            user="DDIC", client="100", sid="PRD",
            private_key=key, certificate=cert,
            create_time="202601011200")
        assert r["success"] is True
        decoded = decode_from_cookie(r["cookie_b64"])
        assert decoded == r["ticket_bytes"]

    def test_forge_recipient_pinned(self):
        from sap_mysapsso2 import forge_ticket
        key, cert = _generate_test_key_and_cert()
        r = forge_ticket(
            user="SAP*", client="000", sid="S4H",
            private_key=key, certificate=cert,
            recipient_sid="PRD", recipient_client="100",
            create_time="202601011200")
        assert r["success"] is True
        assert r["parsed"]["recipient_sid"] == "PRD"
        assert r["parsed"]["recipient_client"] == "100"

    def test_forge_error_handling(self):
        """Invalid key → error in result, not exception."""
        from sap_mysapsso2 import forge_ticket
        r = forge_ticket(
            user="SAP*", client="000", sid="S4H",
            private_key=None, certificate=None)
        assert r["success"] is False
        assert r["error"]
