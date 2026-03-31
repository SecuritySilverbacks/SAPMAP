"""
Tests for sap_rsec_cipher.py — SAP RSECCipher (custom TripleDES for SSFS).
"""

import os
import sys

import pytest

# Allow imports from the parent directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sap_rsec_cipher import RSECCipher, rsec_decrypt, rsec_decrypt_key


# =========================================================================
# RSECCipher.crypt — single-round encode/decode
# =========================================================================

class TestRSECCipherCrypt:

    def test_mode_encode_decode_roundtrip(self):
        """Encode then decode an 8-byte block should return the original."""
        cipher = RSECCipher()
        key = list(range(8))          # 8-byte key as list of ints
        plaintext = [0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48]  # "ABCDEFGH"

        encoded = cipher.crypt(RSECCipher.MODE_ENCODE, plaintext, key, len(plaintext))
        decoded = cipher.crypt(RSECCipher.MODE_DECODE, encoded, key, len(encoded))
        assert decoded == plaintext

    def test_deterministic_output(self):
        """Same input and key must always produce the same encoded output."""
        cipher = RSECCipher()
        key = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]
        data = [0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88]

        out1 = cipher.crypt(RSECCipher.MODE_ENCODE, data, key, len(data))
        out2 = cipher.crypt(RSECCipher.MODE_ENCODE, data, key, len(data))
        assert out1 == out2

    def test_encode_changes_data(self):
        """Encoding should produce output different from the plaintext."""
        cipher = RSECCipher()
        key = [1, 2, 3, 4, 5, 6, 7, 8]
        data = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

        encoded = cipher.crypt(RSECCipher.MODE_ENCODE, data, key, len(data))
        assert encoded != data

    def test_invalid_mode_raises(self):
        cipher = RSECCipher()
        with pytest.raises(AttributeError, match="Invalid mode"):
            cipher.crypt(99, [0] * 8, [0] * 8, 8)

    def test_multi_block_roundtrip(self):
        """Encode and decode multiple 8-byte blocks (24 bytes)."""
        cipher = RSECCipher()
        key = [0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x01, 0x02]
        plaintext = list(range(24))  # 3 blocks of 8 bytes

        encoded = cipher.crypt(RSECCipher.MODE_ENCODE, plaintext, key, len(plaintext))
        decoded = cipher.crypt(RSECCipher.MODE_DECODE, encoded, key, len(encoded))
        assert decoded == plaintext


# =========================================================================
# rsec_decrypt — 3-pass Decode-Encode-Decode
# =========================================================================

class TestRsecDecrypt:

    def test_encrypt_decrypt_roundtrip(self):
        """Manually encrypt (Encode-Decode-Encode) then rsec_decrypt should
        return the original data (for 8-byte aligned data)."""
        key = bytes(range(10, 34))  # 24-byte key
        plaintext = bytes(range(56))  # 56 bytes = 7 blocks of 8

        key_list = list(key)
        key1 = key_list[0:8]
        key2 = key_list[8:16]
        key3 = key_list[16:24]

        # rsec_decrypt does: Decode(key3) -> Encode(key2) -> Decode(key1)
        # So the inverse (encrypt) is: Encode(key1) -> Decode(key2) -> Encode(key3)
        cipher = RSECCipher()
        r1 = cipher.crypt(RSECCipher.MODE_ENCODE, list(plaintext), key1, len(plaintext))
        r2 = cipher.crypt(RSECCipher.MODE_DECODE, r1, key2, len(r1))
        r3 = cipher.crypt(RSECCipher.MODE_ENCODE, r2, key3, len(r2))
        ciphertext = bytes(r3)

        decrypted = rsec_decrypt(ciphertext, key)
        assert decrypted == plaintext

    def test_key_length_validation(self):
        """rsec_decrypt should reject keys that are not 24 bytes."""
        with pytest.raises(ValueError, match="Key must be 24 bytes"):
            rsec_decrypt(b"\x00" * 16, b"\x00" * 16)

    def test_empty_blob(self):
        """Decrypting an empty blob should return empty bytes."""
        key = b"\x00" * 24
        result = rsec_decrypt(b"", key)
        assert result == b""

    def test_deterministic(self):
        """Same blob and key should always produce the same output."""
        key = bytes(range(24))
        blob = bytes([0xAA] * 16)
        r1 = rsec_decrypt(blob, key)
        r2 = rsec_decrypt(blob, key)
        assert r1 == r2


# =========================================================================
# rsec_decrypt_key — SSFS key file decryption
# =========================================================================

class TestRsecDecryptKey:

    def test_output_length(self):
        """rsec_decrypt_key on a 57-byte blob should return exactly 24 bytes."""
        # Use 57 bytes of dummy data — the output won't be a valid key
        # but the function should execute and return 24 bytes.
        blob = bytes([0x42] * 57)
        result = rsec_decrypt_key(blob)
        assert len(result) == 24

    def test_deterministic(self):
        """Same input should produce the same output."""
        blob = bytes(range(57))
        r1 = rsec_decrypt_key(blob)
        r2 = rsec_decrypt_key(blob)
        assert r1 == r2
