"""
Tests for sapmap_secstore.py — RSECTAB decryption, key derivation,
entry categorisation, and SSFS key extraction.
"""

import hashlib
import os
import sys

import pytest

# Allow imports from the parent directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sapmap_secstore import (
    DEFAULT_KEY_HEX,
    _derive_keyprime,
    categorise_entry,
    decrypt_entry,
    extract_ssfs_key,
)


# =========================================================================
# decrypt_entry — bad-input handling and return-structure validation
# =========================================================================

class TestDecryptEntry:

    def test_return_keys_present(self):
        """decrypt_entry should always return the canonical result keys."""
        # Use a valid-length but meaningless hex string (368 hex chars = 184 bytes)
        data_hex = "00" * 184
        result = decrypt_entry(data_hex)
        for key in ("password", "password_len", "sid", "instance_nr", "error"):
            assert key in result, f"Missing key {key!r} in result dict"

    def test_empty_data_returns_error(self):
        result = decrypt_entry("")
        assert result["error"] is not None
        assert result["password"] is None

    def test_too_short_data_returns_error(self):
        # 10 bytes = 20 hex chars — well below the 136-byte minimum
        result = decrypt_entry("aa" * 10)
        assert result["error"] is not None
        assert "too short" in result["error"].lower()

    def test_odd_length_hex_returns_error(self):
        # Odd-length hex string is invalid for bytes.fromhex
        result = decrypt_entry("abc")
        assert result["error"] is not None

    def test_valid_length_does_not_crash(self):
        """368 hex chars (184 bytes) should not raise; may fail to decrypt
        but the function should return gracefully."""
        data_hex = "ff" * 184
        result = decrypt_entry(data_hex)
        # Should return a dict — no uncaught exception
        assert isinstance(result, dict)

    def test_custom_key_accepted(self):
        """Passing an explicit key_hex should not crash."""
        data_hex = "00" * 184
        custom_key = "ab" * 24  # 24 bytes
        result = decrypt_entry(data_hex, key_hex=custom_key)
        assert isinstance(result, dict)


# =========================================================================
# _derive_keyprime — MD5-based key derivation
# =========================================================================

class TestDeriveKeyprime:

    def test_output_length(self):
        """keyprime must be 24 bytes, same length as the input keydef."""
        keydef = bytes.fromhex(DEFAULT_KEY_HEX)
        # Build a fake data_pass1 (>= 153 bytes so slicing works).
        # SID at [-44:-41], instno at [-41:-31]
        fake = bytearray(184)
        fake[-44:-41] = b"S4D"
        fake[-41:-31] = b"00\x00\x00\x00\x00\x00\x00\x00\x00"
        kp = _derive_keyprime(keydef, bytes(fake))
        assert len(kp) == 24

    def test_different_sid_gives_different_key(self):
        keydef = bytes.fromhex(DEFAULT_KEY_HEX)
        fake1 = bytearray(184)
        fake1[-44:-41] = b"S4D"
        fake1[-41:-31] = b"00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

        fake2 = bytearray(184)
        fake2[-44:-41] = b"PRD"
        fake2[-41:-31] = b"00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

        kp1 = _derive_keyprime(keydef, bytes(fake1))
        kp2 = _derive_keyprime(keydef, bytes(fake2))
        assert kp1 != kp2

    def test_same_input_is_deterministic(self):
        keydef = bytes.fromhex(DEFAULT_KEY_HEX)
        fake = bytearray(184)
        fake[-44:-41] = b"ABC"
        fake[-41:-31] = b"01\x00\x00\x00\x00\x00\x00\x00\x00"
        kp_a = _derive_keyprime(keydef, bytes(fake))
        kp_b = _derive_keyprime(keydef, bytes(fake))
        assert kp_a == kp_b

    def test_xor_positions_modified(self):
        """keyprime should differ from the original keydef at the XOR positions."""
        keydef = bytes.fromhex(DEFAULT_KEY_HEX)
        # Use a SID/instno that produce a non-zero MD5
        fake = bytearray(184)
        fake[-44:-41] = b"XYZ"
        fake[-41:-31] = b"99\x00\x00\x00\x00\x00\x00\x00\x00"
        kp = _derive_keyprime(keydef, bytes(fake))
        # At least one of the XOR positions (1, 6, 7, 10, 13, 16, 19, 20)
        # should differ from keydef (unless the MD5 nibble happened to be 0).
        xor_positions = [1, 6, 7, 10, 13, 16, 19, 20]
        diffs = [i for i in xor_positions if kp[i] != keydef[i]]
        assert len(diffs) > 0, "Expected at least one XOR position to differ"


# =========================================================================
# categorise_entry — IDENT pattern classification
# =========================================================================

class TestCategoriseEntry:

    def _make_entry(self, ident):
        return {"ident": ident}

    # --- RFC patterns ---

    def test_rfc_simple_sid(self):
        e = categorise_entry(self._make_entry("/RFC/S4D"))
        assert e["category"] == "rfc"
        assert e["target_sid"] == "S4D"
        assert e["dest_name"] == "S4D"

    def test_rfc_with_user_and_domain(self):
        e = categorise_entry(self._make_entry("/RFC/TMSADM@H2T.DOMAIN_H2T"))
        assert e["category"] == "rfc"
        assert e["rfc_user"] == "TMSADM"
        assert e["target_sid"] == "H2T"

    def test_rfc_with_user_and_client(self):
        e = categorise_entry(self._make_entry("/RFC/FINBTR@H2TCLNT100"))
        assert e["category"] == "rfc"
        assert e["rfc_user"] == "FINBTR"
        assert e["target_sid"] == "H2T"
        assert e["rfc_client"] == "100"

    # --- DB connections ---

    def test_dbcon(self):
        e = categorise_entry(self._make_entry("/DBCON/SYSTEMDB@H2T"))
        assert e["category"] == "db"

    # --- CTS transport ---

    def test_cts(self):
        e = categorise_entry(self._make_entry("/CTS/PWD/$T$/DOMAIN_H2T/DOMCTL"))
        assert e["category"] == "cts"

    # --- SMTP ---

    def test_smtp(self):
        e = categorise_entry(self._make_entry("BC_SX_SMTP"))
        assert e["category"] == "smtp"

    # --- HMAC ---

    def test_hmac(self):
        e = categorise_entry(self._make_entry("/HMAC_INDEP/VIRTUAL_USER"))
        assert e["category"] == "hmac"

    # --- PSE / certificate PIN ---

    def test_pse(self):
        e = categorise_entry(self._make_entry("/STRUST_PSE_PIN/164611"))
        assert e["category"] == "pse"

    # --- MANDT prefix stripping ---

    def test_mandt_prefix_underscores(self):
        """Underscore/space MANDT prefix should be stripped."""
        e = categorise_entry(self._make_entry("___ /RFC/S4D"))
        assert e["category"] == "rfc"
        assert e["mandt"] == ""  # underscores stripped to empty
        assert e["target_sid"] == "S4D"

    def test_mandt_prefix_numeric(self):
        e = categorise_entry(self._make_entry("100 BC_SX_SMTP"))
        assert e["mandt"] == "100"
        assert e["category"] == "smtp"

    # --- Other / fallback ---

    def test_unknown_category(self):
        e = categorise_entry(self._make_entry("SOME_RANDOM_IDENT"))
        assert e["category"] == "other"


# =========================================================================
# extract_ssfs_key — plaintext SSFS key file extraction
# =========================================================================

class TestExtractSSFSKey:

    def _build_plaintext_key_file(self, key_bytes):
        """Build a fake 92-byte plaintext SSFS key file."""
        buf = bytearray(92)
        buf[0:11] = b"RSecSSFsKey"       # preamble
        buf[11] = 1                        # type byte
        buf[12:36] = key_bytes             # 24-byte key
        # bytes 36-91: timestamp + user + host padding (leave zeroed)
        return bytes(buf)

    def test_extract_plaintext_key(self):
        known_key = bytes(range(10, 34))  # 24 arbitrary bytes
        key_file = self._build_plaintext_key_file(known_key)
        assert len(key_file) == 92
        extracted = extract_ssfs_key(key_file)
        assert extracted == known_key

    def test_extract_plaintext_key_length(self):
        known_key = b"\xaa" * 24
        key_file = self._build_plaintext_key_file(known_key)
        extracted = extract_ssfs_key(key_file)
        assert len(extracted) == 24

    def test_bad_preamble_raises(self):
        bad = b"NotSSFSKeyX" + b"\x00" * 81
        with pytest.raises(ValueError, match="Not an SSFS key file"):
            extract_ssfs_key(bad)

    def test_wrong_size_raises(self):
        """A file with the right preamble but wrong size should raise."""
        buf = bytearray(50)
        buf[0:11] = b"RSecSSFsKey"
        with pytest.raises(ValueError, match="Unknown SSFS key file size"):
            extract_ssfs_key(bytes(buf))
