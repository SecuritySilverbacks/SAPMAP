#!/usr/bin/env python3
"""Tests for sap_java_secstore_offline.

Covers:
  * PKCS#12 v1.0 KDF correctness against RFC 7292 test vectors.
  * Deobfuscation of a synthetic SecStore.key.
  * Round-trip: encrypt a value via our own PBE primitive, decrypt it
    back through the public decrypt_vbytes() path.
"""

from __future__ import annotations

import base64
import pytest

from sap_java_secstore_offline import (
    _pkcs12_kdf,
    _pbe_decrypt_3des_cbc,
    _pwd_to_bmp,
    _SECRET_XOR,
    _ALPHABET_LEN,
    _ALPHABET_SKIP,
    _strip_alphabet_and_length,
    deobfuscate_seckey,
    decrypt_vbytes,
    decrypt_secstore_properties,
)


def _build_plain(payload: bytes) -> bytes:
    """Build a plaintext matching SAP's actual layout:
       <16B alphabet> <2B BE length> <payload bytes>"""
    return b"ABCDEFGHIJKLMNOP" + len(payload).to_bytes(2, "big") + payload


# ---------------------------------------------------------------------------
# KDF — RFC 7292 Appendix B.2 test vectors
# ---------------------------------------------------------------------------

# Test vector reproduced from RFC 7292 Appendix B.2:
#   password: "smeg" as BMPString with null terminator
#   salt:     0A 58 CF 64 53 0D 82 3F
#   iter:     1
#   purpose:  1 (encryption key)
#   key_len:  24 (3DES key size)
#   expected: 8A AA E6 29 7B 6C B0 46 42 AB 5B 07 78 51 28 4E B7 12 8F 1A 2A 7F BC A3

def test_pkcs12_kdf_rfc7292_vector():
    pw = _pwd_to_bmp("smeg")
    salt = bytes.fromhex("0A58CF64530D823F")
    key = _pkcs12_kdf(pw, salt, iterations=1, purpose_id=1, out_len=24)
    expected = bytes.fromhex("8AAAE6297B6CB04642AB5B077851284EB7128F1A2A7FBCA3")
    assert key == expected


def test_pkcs12_kdf_iterations_zero_equivalent_to_one():
    """ERPScan's code passes iterations=0; pyjks treats that as 1.  We
    must match or every real decrypt fails."""
    pw = _pwd_to_bmp("anything")
    salt = b"\x00" * 16
    k0 = _pkcs12_kdf(pw, salt, 0, purpose_id=1, out_len=24)
    k1 = _pkcs12_kdf(pw, salt, 1, purpose_id=1, out_len=24)
    assert k0 == k1


def test_pkcs12_kdf_output_length_honoured():
    pw = _pwd_to_bmp("x")
    salt = b"\x01" * 8
    # Request more bytes than a single SHA-1 block (20 B) so the KDF
    # must iterate and apply the (I + B + 1) mod update step.
    key = _pkcs12_kdf(pw, salt, 1, purpose_id=1, out_len=40)
    assert len(key) == 40
    key2 = _pkcs12_kdf(pw, salt, 1, purpose_id=1, out_len=40)
    assert key == key2  # deterministic


# ---------------------------------------------------------------------------
# Round-trip via a known Java-compatible encryption
# ---------------------------------------------------------------------------

def _pbe_encrypt_3des_cbc(plaintext: bytes, password,
                            salt: bytes = b"\x00" * 16,
                            iterations: int = 1) -> bytes:
    """Encrypt with the same primitive we decrypt — for round-trip tests."""
    from Crypto.Cipher import DES3
    pw_bmp = _pwd_to_bmp(password)
    key = _pkcs12_kdf(pw_bmp, salt, iterations, 1, 24)
    iv = _pkcs12_kdf(pw_bmp, salt, iterations, 2, 8)
    # PKCS#7 pad
    pad_len = 8 - (len(plaintext) % 8)
    padded = plaintext + bytes([pad_len]) * pad_len
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return cipher.encrypt(padded)


def test_round_trip_decrypt():
    plaintext = b"hello_SAPJSF_password!"
    ct = _pbe_encrypt_3des_cbc(plaintext, "masterkey")
    assert _pbe_decrypt_3des_cbc(ct, "masterkey") == plaintext


def test_round_trip_empty_payload():
    ct = _pbe_encrypt_3des_cbc(b"", "x")
    assert _pbe_decrypt_3des_cbc(ct, "x") == b""


def test_round_trip_wrong_password_does_not_return_plaintext():
    ct = _pbe_encrypt_3des_cbc(b"secret", "right")
    # Wrong password shouldn't raise (CBC always produces 8-byte blocks)
    # but the result must not be the original plaintext.
    try:
        out = _pbe_decrypt_3des_cbc(ct, "wrong")
    except Exception:
        out = b"<exception>"
    assert out != b"secret"


# ---------------------------------------------------------------------------
# SecStore.key deobfuscation
# ---------------------------------------------------------------------------

def test_deobfuscate_seckey_roundtrip():
    # Synthesize a SecStore.key we could have written ourselves.
    keyphrase = b"MyMasterKey123!"
    obf = bytes(keyphrase[i] ^ _SECRET_XOR[i % len(_SECRET_XOR)]
                for i in range(len(keyphrase)))
    seckey = b"7.50.122.065|" + obf
    extracted, is_v7plus = deobfuscate_seckey(seckey)
    assert extracted == keyphrase
    assert is_v7plus is True


def test_deobfuscate_seckey_strips_trailing_whitespace():
    keyphrase = b"pw"
    obf = bytes(keyphrase[i] ^ _SECRET_XOR[i % len(_SECRET_XOR)]
                for i in range(len(keyphrase)))
    seckey = b"7.50.111.000|" + obf + b"\r\n"
    extracted, _ = deobfuscate_seckey(seckey)
    assert extracted == keyphrase


def test_deobfuscate_seckey_rejects_bad_format():
    with pytest.raises(ValueError):
        deobfuscate_seckey(b"not a seckey file at all")


def test_deobfuscate_seckey_marks_pre_v7_false():
    # Strictly < "7.00.000" — e.g. "6.40.012"
    keyphrase = b"x"
    obf = bytes([keyphrase[0] ^ _SECRET_XOR[0]])
    seckey = b"6.40.012.000|" + obf
    _, is_v7plus = deobfuscate_seckey(seckey)
    assert is_v7plus is False


# ---------------------------------------------------------------------------
# VBYTES format dispatch
# ---------------------------------------------------------------------------

def _make_vbytes_cleartext(payload: bytes) -> str:
    """Build a fake VBYTES hex for format 0x00 (cleartext base64 with
    16-byte alphabet + 2-byte BE length prefix)."""
    b64_content = base64.b64encode(_build_plain(payload))
    # Format byte 0x00, flag byte 0x00, then the base64 bytes.
    vb = b"\x00\x00" + b64_content
    return vb.hex()


def _make_vbytes_encrypted(payload: bytes, password) -> str:
    """Build a fake VBYTES hex for format 0x01 (PBE-encrypted), with
    the SAP plaintext layout: 16B alphabet + 2B BE length + payload."""
    ct = _pbe_encrypt_3des_cbc(_build_plain(payload), password)
    vb = b"\x01\x00" + ct
    return vb.hex()


def test_decrypt_vbytes_cleartext_format():
    payload = b"Siroj1978#"
    hex_vb = _make_vbytes_cleartext(payload)
    result = decrypt_vbytes(hex_vb, keyphrase=b"unused")
    assert result == payload


def test_decrypt_vbytes_encrypted_format():
    payload = b"Siroj1978#"
    pwd = b"MyMasterKey"
    hex_vb = _make_vbytes_encrypted(payload, pwd)
    result = decrypt_vbytes(hex_vb, keyphrase=pwd)
    assert result == payload


def test_decrypt_vbytes_unknown_format_returns_none():
    # Format byte 0x42 isn't SecStoreFS — should return None quietly
    fake = b"\x42\x00" + b"nonsense"
    assert decrypt_vbytes(fake.hex(), keyphrase=b"x") is None


def test_decrypt_vbytes_tolerates_whitespace_in_hex():
    payload = b"hello"
    hex_vb = _make_vbytes_cleartext(payload)
    # Insert whitespace the MaxDB driver might include
    spaced = " ".join(hex_vb[i:i+2] for i in range(0, len(hex_vb), 2))
    result = decrypt_vbytes(spaced, keyphrase=b"x")
    assert result == payload


def test_decrypt_vbytes_rejects_invalid_hex():
    assert decrypt_vbytes("not hex!!!", keyphrase=b"x") is None


def test_decrypt_vbytes_empty_input():
    assert decrypt_vbytes("", keyphrase=b"x") is None


def test_strip_alphabet_honours_length_prefix():
    # Plaintext has real payload followed by junk; length prefix says
    # take only the first 4 bytes of payload.  The rest (even if not
    # zero) must not be returned.
    plain = b"ABCDEFGHIJKLMNOP" + (4).to_bytes(2, "big") + b"PASS" + b"GARBAGE"
    assert _strip_alphabet_and_length(plain) == b"PASS"


def test_decrypt_vbytes_truncates_to_declared_length():
    # Emulates SAP's real payload layout when the PBE plaintext has
    # trailing padding left behind after PKCS#7 strip.  decrypt_vbytes
    # must return ONLY the declared-length bytes, not the full tail.
    payload = b"Down1oad"   # 8 bytes, real SAP default keyphrase length
    hex_vb = _make_vbytes_encrypted(payload, b"masterkey")
    # Decrypt → plaintext has extra bytes past the 8-byte payload
    # (the next 3DES-CBC block); length prefix says 8.
    result = decrypt_vbytes(hex_vb, keyphrase=b"masterkey")
    assert result == payload  # exactly 8 bytes, not 8+padding


# ---------------------------------------------------------------------------
# SecStore.properties
# ---------------------------------------------------------------------------

def test_decrypt_secstore_properties_round_trip():
    pwd = b"masterkey"
    # Build a fake "key=base64(enc(prefix|len|value))" line
    prop_value = b"J2EE_DB_PASSWORD_EXAMPLE"
    plain = b"PREFIX|" + str(len(prop_value)).encode() + b"|" + prop_value
    ct = _pbe_encrypt_3des_cbc(plain, pwd)
    b64 = base64.b64encode(ct).decode("ascii")
    props_text = (
        "# comment line\n"
        "$internal/version=ignored\n"
        f"jdbc/pool/SJ1/Password={b64}\n"
    )
    out = decrypt_secstore_properties(props_text, pwd)
    assert out == {"jdbc/pool/SJ1/Password": "J2EE_DB_PASSWORD_EXAMPLE"}


def test_decrypt_secstore_properties_skips_malformed():
    out = decrypt_secstore_properties("onlykey\nother=not-base64-really?!\n",
                                        keyphrase=b"x")
    assert out == {}


# ---------------------------------------------------------------------------
# Full-stack: SecStore.key → keyphrase → VBYTES decrypt
# ---------------------------------------------------------------------------

def test_full_stack_key_to_vbytes():
    """Simulate the whole recovery path end-to-end."""
    keyphrase = b"SjOneMaster99"

    # Synthesize a SecStore.key
    obf = bytes(keyphrase[i] ^ _SECRET_XOR[i % len(_SECRET_XOR)]
                for i in range(len(keyphrase)))
    seckey_file = b"7.50.022.045|" + obf + b"\n"

    # Deobfuscate
    recovered_pw, _ = deobfuscate_seckey(seckey_file)
    assert recovered_pw == keyphrase

    # Build a VBYTES hex for a realistic UMEBackendConnection password
    payload = b"ABAPSideServicePassword2026"
    vb_hex = _make_vbytes_encrypted(payload, recovered_pw)

    # Decrypt with the recovered keyphrase
    plain = decrypt_vbytes(vb_hex, recovered_pw)
    assert plain == payload
