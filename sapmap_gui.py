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

from sapmap_models import SAPMAPState, SAPNode, Credentials, CreatedUser
from sapmap_html import get_html
import sapmap_scanner
import sapmap_rfc
import sapmap_exploit
import sapmap_cleanup
import sapmap_state as state_mgr

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

        self.scan_thread = threading.Thread(
            target=self._run_scan, args=(config,), daemon=True
        )
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
            concurrent_hosts = config.get("concurrent_hosts", 3)
            port_timeout = config.get("port_timeout", 2.0)
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
            )

            for node in nodes:
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
        return {"status": "stopping"}

    def get_state_dict(self):
        """Get current state as a dict for the frontend."""
        d = self.state.to_dict()
        d["scan_state"] = self.scan_state
        d["scan_error"] = self.scan_error
        d["stats"] = self.state.stats()
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
        return get_html()

    # -- Console polling --
    @app.route("/api/console")
    def get_console():
        response.content_type = "application/json"
        cursor = int(request.params.get("cursor", 0))
        with _console_lock:
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
        threading.Thread(target=_run, daemon=True).start()
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

        threading.Thread(target=_run, daemon=True).start()
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
            for conn in conns:
                # Try to resolve target
                target = api.state.find_node_by_host(
                    hostname=conn.target_host, ip=conn.target_ip
                )
                if target:
                    conn.target_sid = target.sid
                api.state.add_connection(conn)
            print(f"[+] Added {len(conns)} connections from {sid}")

        threading.Thread(target=_run, daemon=True).start()
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
            for conn in conns:
                if not conn.tested and not api.state.is_rfc_checked(conn.destination_name):
                    print(f"[*] Testing {conn.destination_name}...")
                    result = sapmap_rfc.test_rfc_destination(
                        node, conn.destination_name, creds, api.state.rfc_check_cache
                    )
                    conn.logon_successful = result.get("logon_ok", False)
                    conn.ping_ok = result.get("ping_ok", False)
                    conn.latency_ms = result.get("latency_ms", 0)
                    conn.tested = True

                    if conn.logon_successful:
                        print(f"[+] {conn.destination_name}: Logon successful!")
                        # Mark target
                        target = api.state.get_node(conn.target_sid)
                        if target:
                            target.has_critical_finding = True

                # Get user details
                if conn.rfc_user and not conn.profiles:
                    info = sapmap_rfc.get_user_details(node, conn.rfc_user, creds)
                    conn.profiles = info.get("profiles", [])
                    conn.roles = info.get("roles", [])
                    conn.has_sap_all = info.get("has_sap_all", False)
                    conn.user_detail_error = info.get("error", "")
                    if conn.has_sap_all:
                        print(f"[!] {conn.rfc_user} in {conn.destination_name} has SAP_ALL!")

        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/download_hashes", method="POST")
    def node_download_hashes(sid):
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            creds = node.best_credentials()
            hashes = sapmap_rfc.download_password_hashes(node, creds)
            if hashes:
                # Save to file
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                outfile = os.path.join(
                    os.path.dirname(__file__), "states",
                    f"hashes_{sid}_{ts}.json"
                )
                os.makedirs(os.path.dirname(outfile), exist_ok=True)
                with open(outfile, "w") as f:
                    json.dump(hashes, f, indent=2)
                print(f"[+] Hashes saved to {outfile}")

        threading.Thread(target=_run, daemon=True).start()
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

        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/create_tcpip_dest", method="POST")
    def node_create_tcpip(sid):
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            creds = node.best_credentials()
            # Create TCP/IP dest to all connected targets
            conns = api.state.get_connections_from(sid)
            for conn in conns:
                if conn.target_host:
                    result = sapmap_rfc.create_tcpip_destination(
                        node, conn.target_host, creds=creds
                    )
                    if result["success"]:
                        conn.sapxpg_remote_works = True
                        target = api.state.get_node(conn.target_sid)
                        if target:
                            target.has_critical_finding = True

        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/propagate", method="POST")
    def node_propagate(sid):
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            sapmap_exploit.propagate_from_node(node, api.state)

        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/cleanup", method="POST")
    def node_cleanup(sid):
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            sapmap_cleanup.cleanup_node_users(node, api.state)

        threading.Thread(target=_run, daemon=True).start()
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

        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started"})

    # -- Global actions --
    @app.route("/api/actions/propagate_all", method="POST")
    def actions_propagate_all():
        response.content_type = "application/json"

        def _run():
            sapmap_exploit.propagate_all(api.state)

        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started"})

    @app.route("/api/actions/cleanup_all", method="POST")
    def actions_cleanup_all():
        response.content_type = "application/json"

        def _run():
            sapmap_cleanup.cleanup_all_users(api.state)

        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started"})

    @app.route("/api/actions/reset_rfc_cache", method="POST")
    def actions_reset_rfc_cache():
        response.content_type = "application/json"
        state_mgr.reset_rfc_cache(api.state)
        return json.dumps({"status": "ok"})

    @app.route("/api/actions/created_users")
    def actions_created_users():
        response.content_type = "application/json"
        users = sapmap_cleanup.list_created_users(api.state)
        return json.dumps({"users": users})

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
