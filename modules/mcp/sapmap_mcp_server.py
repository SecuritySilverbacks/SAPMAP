#!/usr/bin/env python3
"""
SAPMAP MCP Server — Model Context Protocol interface for SAPMAP.

Runs as a separate process alongside the SAPMAP HTTP server, exposing
SAPMAP's capabilities as MCP tools and resources over stdio transport.
Connects to the running SAPMAP Bottle server via HTTP on localhost.

Usage:
    python3 -m modules.mcp.sapmap_mcp_server --port 8080

Or start SAPMAP with --mcp to auto-launch alongside the GUI.
"""

import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from typing import Any

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# HTTP helper — talks to the running SAPMAP Bottle server
# ---------------------------------------------------------------------------

_BASE_URL = "http://127.0.0.1:8080"


def _set_base_url(port: int):
    global _BASE_URL
    _BASE_URL = f"http://127.0.0.1:{port}"


def _api(method: str, path: str, payload: dict = None,
         timeout: float = 15.0) -> dict:
    url = _BASE_URL + path
    if method.upper() == "GET":
        req = urllib.request.Request(url, method="GET")
    else:
        body = json.dumps(payload or {}).encode("utf-8")
        req = urllib.request.Request(
            url, data=body, method=method,
            headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode()
            return {"error": f"HTTP {e.code}: {body}"}
        except Exception:
            return {"error": f"HTTP {e.code}: {e.reason}"}
    except urllib.error.URLError as e:
        return {"error": f"Cannot reach SAPMAP server at {_BASE_URL}: {e.reason}"}
    except Exception as e:
        return {"error": str(e)}


def _wait_for_tasks(timeout: float = 600.0) -> bool:
    """Poll /api/state until active_tasks is empty."""
    deadline = time.time() + timeout
    time.sleep(1)
    while time.time() < deadline:
        try:
            state = _api("GET", "/api/state")
            tasks = state.get("active_tasks", {})
            if not tasks:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Read-only mode probe
# ---------------------------------------------------------------------------
# The MCP server runs as a separate process; the read-only flag lives in
# the main SAPMAP process's memory.  We ask the server for its mode over
# HTTP the first time a write tool is called, cache the result, and short-
# circuit further attempts with a helpful error the model sees inline.
# The backend still enforces via a 403, so this is a UX layer — the model
# doesn't have to fumble through an HTTP error to learn a whole class of
# tools is off.
_READ_ONLY_CACHE: dict = {"checked": False, "read_only": False}


def _is_read_only() -> bool:
    if not _READ_ONLY_CACHE["checked"]:
        try:
            data = _api("GET", "/api/mode", timeout=3.0)
            _READ_ONLY_CACHE["read_only"] = bool(data.get("read_only"))
        except Exception:
            _READ_ONLY_CACHE["read_only"] = False
        _READ_ONLY_CACHE["checked"] = True
    return _READ_ONLY_CACHE["read_only"]


_READ_ONLY_REPLY = (
    "ERROR: SAPMAP is running in --read-only mode.  Destructive actions "
    "(create-user, exploit, autopwn, cleanup, ransapware, SecStore / "
    "DBCON dumps) are disabled.  Restart SAPMAP without --read-only to "
    "enable this tool."
)


def _read_only_guard() -> str:
    """Return an error string if read-only is on, or '' if the tool may proceed."""
    if _is_read_only():
        return _READ_ONLY_REPLY
    return ""


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "SAPMAP",
    instructions=(
        "SAPMAP is an SAP Landscape Attack Path Mapper for authorized "
        "security assessments. This MCP server exposes SAPMAP's "
        "capabilities as tools. SAPMAP must be running (python3 sapmap.py) "
        "before using these tools. Exploitation tools require explicit "
        "confirm=true. Use get_landscape to understand current state "
        "before taking actions."
    ),
)


# ===== RESOURCES =====

@mcp.resource("sapmap://landscape")
def resource_landscape() -> str:
    """Current landscape state: all discovered SAP systems, connections,
    findings, and created users."""
    state = _api("GET", "/api/state")
    nodes = state.get("nodes", {})
    summary = {
        "total_systems": len(nodes),
        "pwned_systems": sum(1 for n in nodes.values()
                             if n.get("is_pwned")),
        "total_connections": len(state.get("connections", [])),
        "total_findings": len(state.get("findings", [])),
        "created_users": len(state.get("created_users", [])),
        "active_tasks": state.get("active_tasks", {}),
    }
    systems = []
    for sid, n in nodes.items():
        systems.append({
            "sid": sid,
            "ip": n.get("ip"),
            "hostname": n.get("hostname"),
            "system_type": n.get("system_type"),
            "os_type": n.get("os_type"),
            "db_type": n.get("db_type"),
            "is_pwned": n.get("is_pwned", False),
            "is_production": any(c.get("role") == "P"
                                 for c in n.get("clients", [])),
            "has_credentials": bool(n.get("credentials")),
            "findings_count": len(n.get("findings", [])),
            "instances": n.get("instances", []),
        })
    return json.dumps({"summary": summary, "systems": systems}, indent=2)


@mcp.resource("sapmap://findings")
def resource_findings() -> str:
    """All security findings across the landscape, sorted by severity."""
    resp = _api("GET", "/api/findings")
    return json.dumps(resp, indent=2)


@mcp.resource("sapmap://console")
def resource_console() -> str:
    """Recent console output from SAPMAP operations."""
    resp = _api("GET", "/api/console")
    return json.dumps(resp, indent=2)


@mcp.resource("sapmap://chains")
def resource_chains() -> str:
    """RFC trust-chain attack paths across the landscape."""
    resp = _api("GET", "/api/chains")
    return json.dumps(resp, indent=2)


# ===== TOOLS: Landscape & State =====

@mcp.tool()
def get_landscape() -> str:
    """Get the current SAPMAP landscape state: all discovered systems,
    their status, connections, findings, and active tasks.
    Call this first to understand what systems are known."""
    state = _api("GET", "/api/state")
    nodes = state.get("nodes", {})
    summary = {
        "total_systems": len(nodes),
        "pwned_systems": sum(1 for n in nodes.values()
                             if n.get("is_pwned")),
        "connections": len(state.get("connections", [])),
        "findings": len(state.get("findings", [])),
        "created_users": len(state.get("created_users", [])),
        "active_tasks": list(state.get("active_tasks", {}).keys()),
    }
    systems = []
    for sid, n in nodes.items():
        sys_info = {
            "sid": sid,
            "ip": n.get("ip"),
            "hostname": n.get("hostname"),
            "type": n.get("system_type"),
            "os": n.get("os_type"),
            "db": n.get("db_type"),
            "pwned": n.get("is_pwned", False),
            "credentials": bool(n.get("credentials")),
            "findings": len(n.get("findings", [])),
        }
        systems.append(sys_info)
    return json.dumps({"summary": summary, "systems": systems}, indent=2)


@mcp.tool()
def get_system_detail(sid: str) -> str:
    """Get detailed information about a specific SAP system by SID.
    Includes instances, credentials (masked), findings, and RFC connections."""
    state = _api("GET", "/api/state")
    nodes = state.get("nodes", {})
    node = nodes.get(sid)
    if not node:
        return json.dumps({"error": f"System {sid} not found"})

    creds = node.get("credentials", [])
    masked_creds = []
    for c in creds:
        masked_creds.append({
            "username": c.get("username"),
            "client": c.get("client"),
            "has_sap_all": c.get("has_sap_all", False),
            "source": c.get("source", ""),
        })

    connections = [c for c in state.get("connections", [])
                   if c.get("source_sid") == sid or c.get("target_sid") == sid]

    return json.dumps({
        "sid": sid,
        "ip": node.get("ip"),
        "hostname": node.get("hostname"),
        "system_type": node.get("system_type"),
        "os_type": node.get("os_type"),
        "db_type": node.get("db_type"),
        "kernel_release": node.get("kernel_release"),
        "sap_release": node.get("sap_release"),
        "is_pwned": node.get("is_pwned", False),
        "instances": node.get("instances", []),
        "credentials": masked_creds,
        "findings": node.get("findings", []),
        "clients": node.get("clients", []),
        "connections": len(connections),
    }, indent=2)


@mcp.tool()
def get_findings() -> str:
    """Get all security findings across the landscape, grouped by severity."""
    resp = _api("GET", "/api/findings")
    return json.dumps(resp, indent=2)


@mcp.tool()
def get_attack_chains() -> str:
    """Analyze and return RFC trust-chain attack paths across the landscape.
    Shows how lateral movement can reach production systems."""
    _api("POST", "/api/actions/analyze_chains", {})
    _wait_for_tasks(timeout=60)
    resp = _api("GET", "/api/chains")
    return json.dumps(resp, indent=2)


@mcp.tool()
def save_state(name: str = "") -> str:
    """Save the current SAPMAP session to a .sapmap file.
    If name is empty, auto-generates a timestamped filename."""
    payload = {"name": name} if name else {}
    return json.dumps(_api("POST", "/api/state/save", payload))


# ===== TOOLS: System Management =====

@mcp.tool()
def add_system(sid: str, ip: str, instance: str = "00",
               saprouter: str = "") -> str:
    """Add an SAP system to the landscape map.

    Args:
        sid: SAP System ID (e.g. S4H, ECC, BW1)
        ip: IP address or hostname of the SAP system
        instance: SAP instance number, 2 digits (default 00)
        saprouter: Optional SAProuter route string (/H/host/S/port)
    """
    resp = _api("POST", "/api/node/add", {
        "sid": sid, "ip": ip,
        "instance_nr": str(instance),
        "saprouter": saprouter,
    })
    _wait_for_tasks(timeout=10)
    return json.dumps(resp)


@mcp.tool()
def set_credentials(sid: str, username: str, password: str,
                    client: str = "001") -> str:
    """Set credentials for an SAP system.

    Args:
        sid: Target system SID
        username: SAP username
        password: SAP password
        client: SAP client number (default 001)
    """
    return json.dumps(_api("POST", f"/api/node/{sid}/credentials", {
        "username": username, "password": password,
        "client": str(client),
    }))


@mcp.tool()
def configure_system(sid: str, system_type: str = "",
                     db_type: str = "", os_type: str = "",
                     saprouter: str = "") -> str:
    """Configure system metadata for a node (type, DB, OS, SAProuter).

    Args:
        sid: Target system SID
        system_type: ABAP, JAVA, ABAP+JAVA, or WEB_DISPATCHER
        db_type: HDB (HANA), ADA (MaxDB), MSS (MSSQL), ORA (Oracle), DB6 (DB2)
        os_type: Linux, Windows NT, AIX, etc.
        saprouter: SAProuter route string
    """
    results = {}
    if system_type:
        results["type"] = _api("POST", f"/api/node/{sid}/set_type",
                               {"system_type": system_type})
    if db_type:
        results["db"] = _api("POST", f"/api/node/{sid}/set_db_type",
                             {"db_type": db_type})
    if os_type:
        results["os"] = _api("POST", f"/api/node/{sid}/set_os_type",
                             {"os_type": os_type})
    if saprouter:
        results["saprouter"] = _api("POST", f"/api/node/{sid}/set_saprouter",
                                    {"saprouter": saprouter})
    return json.dumps(results)


# ===== TOOLS: Scanning & Discovery =====

@mcp.tool()
def scan_network(targets: str, mode: str = "fast",
                 concurrent_hosts: int = 5) -> str:
    """Scan a network for SAP systems.

    Args:
        targets: CIDR, IP range, comma-separated IPs, or @file.txt
        mode: 'fast' (dispatcher+gateway ports) or 'deep' (full SAPology)
        concurrent_hosts: Parallel hosts to scan (default 5)
    """
    resp = _api("POST", "/api/scan/start", {
        "targets": targets,
        "mode": mode,
        "concurrent_hosts": concurrent_hosts,
    })
    _wait_for_tasks(timeout=600)
    return json.dumps(_api("GET", "/api/state"))


@mcp.tool()
def probe_system(sid: str, action: str = "rfc_system_info") -> str:
    """Probe an SAP system for information.

    Args:
        sid: Target system SID
        action: One of:
            - rfc_system_info: Unauthenticated SID/OS/DB/kernel probe
            - enum_clients: Enumerate SAP clients via DIAG
            - client_roles: Read T000 client roles (needs credentials)
            - check_snc: Read SNC configuration
            - standard_scan: Port + service scan
            - deep_scan: Full SAPology vulnerability scan
    """
    action = action.lower().strip()
    route_map = {
        "rfc_system_info": ("POST", f"/api/node/{sid}/rfc_system_info", {}),
        "enum_clients": ("POST", f"/api/node/{sid}/enum_clients", {}),
        "client_roles": ("POST", f"/api/node/{sid}/client_roles", {}),
        "check_snc": ("POST", f"/api/node/{sid}/check_snc", {}),
        "standard_scan": ("POST", f"/api/node/{sid}/standard_scan", {}),
        "deep_scan": ("POST", f"/api/node/{sid}/deep_scan", {}),
    }
    if action not in route_map:
        return json.dumps({"error": f"Unknown probe action: {action}",
                           "valid_actions": list(route_map.keys())})
    method, path, payload = route_map[action]
    resp = _api(method, path, payload)
    _wait_for_tasks(timeout=300)
    return json.dumps(resp)


@mcp.tool()
def check_default_credentials(sid: str) -> str:
    """Test 16 well-known SAP default credentials via DIAG.
    WARNING: Failed logins may lock SAP accounts.

    Args:
        sid: Target system SID
    """
    resp = _api("POST", f"/api/node/{sid}/check_default_creds", {})
    _wait_for_tasks(timeout=300)
    return json.dumps(resp)


# ===== TOOLS: Vulnerability Checking =====

@mcp.tool()
def check_vulnerability(sid: str, vuln: str) -> str:
    """Check a specific vulnerability on an SAP system.

    Args:
        sid: Target system SID (or empty for landscape-wide checks)
        vuln: Vulnerability to check:
            - gw: Gateway SAPXPG (10KBlaze)
            - ms: Message Server betrusted (CVE-2020-6207)
            - ms_info: Message Server text/dump info disclosure
                (missing ms/acl_info + ms/HTTP/acl_info — SAP Notes
                1421005 / 2696233; ms/* profile parameters and kernel
                build identity leaked pre-auth on port 81NN)
            - cve_2025_31324: VisualComposer JSP RCE
            - cve_2020_6287: RECON Java user creation
            - cve_2022_22536: ICMAD HTTP smuggling
            - linux_lpe: Linux root LPE viability
            - windows_lpe: Windows SYSTEM LPE viability
            - all_gw: Check all systems for GW vulnerability
            - all_ms: Check all for MS betrusted
            - all_ms_info: Sweep MS text/dump info disclosure
            - all_vulns: Full vulnerability sweep on all systems
              (includes ms_info)
    """
    vuln = vuln.lower().strip()

    landscape_wide = {
        "all_gw": "/api/actions/check_all_gw",
        "all_ms": "/api/actions/check_all_ms",
        "all_ms_info": "/api/actions/check_all_ms_info_disclosure",
        "all_cve_31324": "/api/actions/check_all_cve_31324",
        "all_cve_6287": "/api/actions/check_all_cve_6287",
        "all_cve_22536": "/api/actions/check_all_cve_22536",
        "all_vulns": "/api/actions/check_all_vulns",
    }
    per_system = {
        "gw": f"/api/node/{sid}/check_gw",
        "ms": f"/api/node/{sid}/check_ms",
        "ms_info": f"/api/node/{sid}/check_ms_info_disclosure",
        "cve_2025_31324": f"/api/node/{sid}/check_cve_2025_31324",
        "cve_2020_6287": f"/api/node/{sid}/check_cve_2020_6287",
        "cve_2022_22536": f"/api/node/{sid}/check_cve_2022_22536",
        "linux_lpe": f"/api/node/{sid}/check_linux_lpe",
        "windows_lpe": f"/api/node/{sid}/check_windows_lpe",
    }

    if vuln in landscape_wide:
        resp = _api("POST", landscape_wide[vuln], {})
    elif vuln in per_system:
        resp = _api("POST", per_system[vuln], {})
    else:
        return json.dumps({"error": f"Unknown vuln: {vuln}",
                           "per_system": list(per_system.keys()),
                           "landscape_wide": list(landscape_wide.keys())})
    _wait_for_tasks(timeout=600)
    return json.dumps(resp)


# ===== TOOLS: Exploitation =====

@mcp.tool()
def exploit(sid: str, action: str, method: str = "",
            client: str = "001", confirm: bool = False,
            attacker_ip: str = "auto",
            command: str = "") -> str:
    """Execute an exploitation action on an SAP system.
    REQUIRES confirm=true to actually execute — without it, returns
    a preview of what would happen.

    Args:
        sid: Target system SID
        action: Exploitation action:
            - create_user: Create SAPMAP user with SAP_ALL (ABAP)
            - create_user_java: Create SAPMAP user on Java stack
            - betrusted: Inject attacker IP into GW trust (10KBlaze step 1)
            - betrusted_chain: Full 10KBlaze chain (betrusted → GW → user)
            - exploit_cve_31324: CVE-2025-31324 JSP shell command
            - lpe: Local privilege escalation (assign SAP_ALL)
            - exploit_linux_lpe: Root LPE on Linux
            - exploit_windows_lpe: SYSTEM LPE on Windows
        method: Sub-method (e.g. gw_exploit, credentials, cve_31324, gw)
        client: SAP client (default 001)
        confirm: Must be true to execute exploitation actions
        attacker_ip: For betrusted — your IP or 'auto'
        command: For exploit_cve_31324/linux_lpe/windows_lpe — OS command
    """
    if (ro := _read_only_guard()):
        return ro
    if not confirm:
        return json.dumps({
            "status": "blocked",
            "message": f"Exploitation action '{action}' requires "
                       f"confirm=true to execute. This is a safety gate "
                       f"to prevent accidental exploitation."
        })

    action = action.lower().strip()

    if action == "create_user":
        payload = {"method": method or "gw_exploit",
                   "client": str(client)}
        resp = _api("POST", f"/api/node/{sid}/create_user", payload)
    elif action == "create_user_java":
        resp = _api("POST", f"/api/node/{sid}/create_user_java",
                    {"method": method or "auto"})
    elif action == "betrusted":
        ip = attacker_ip if attacker_ip != "auto" else _local_ip()
        resp = _api("POST", f"/api/node/{sid}/betrusted",
                    {"attacker_ip": ip})
    elif action == "betrusted_chain":
        ip = attacker_ip if attacker_ip != "auto" else _local_ip()
        resp = _api("POST", f"/api/node/{sid}/betrusted_chain",
                    {"attacker_ip": ip, "client": str(client)})
    elif action == "exploit_cve_31324":
        resp = _api("POST", f"/api/node/{sid}/exploit_cve_2025_31324",
                    {"command": command or "whoami"})
    elif action == "lpe":
        resp = _api("POST", f"/api/node/{sid}/lpe",
                    {"method": method} if method else {})
    elif action == "exploit_linux_lpe":
        resp = _api("POST", f"/api/node/{sid}/exploit_linux_lpe",
                    {"command": command or "id"})
    elif action == "exploit_windows_lpe":
        resp = _api("POST", f"/api/node/{sid}/exploit_windows_lpe",
                    {"command": command or "whoami"})
    else:
        return json.dumps({"error": f"Unknown exploit action: {action}"})

    _wait_for_tasks(timeout=600)
    return json.dumps(resp)


@mcp.tool()
def exec_command(sid: str, cmdline: str, method: str = "gateway",
                 confirm: bool = False) -> str:
    """Execute an OS command on a compromised SAP system.
    REQUIRES confirm=true.

    Args:
        sid: Target system SID (must be pwned)
        cmdline: Shell command to execute
        method: Execution channel — gateway, sxpg, cve_31324, sapcontrol
        confirm: Must be true to execute
    """
    if (ro := _read_only_guard()):
        return ro
    if not confirm:
        return json.dumps({
            "status": "blocked",
            "message": "OS command execution requires confirm=true."
        })
    resp = _api("POST", f"/api/node/{sid}/exec_command", {
        "method": method, "cmdline": cmdline,
    })
    _wait_for_tasks(timeout=120)
    return json.dumps(resp)


# ===== TOOLS: RFC & Lateral Movement =====

@mcp.tool()
def manage_rfcs(sid: str, action: str = "retrieve",
                destination: str = "") -> str:
    """Manage RFC connections for lateral movement.

    Args:
        sid: Source system SID
        action: One of:
            - retrieve: Discover all RFC destinations (SM59/RFCDES)
            - test: Test/ping all discovered destinations
            - test_single: Test one specific destination
            - propagate: Exploit RFC links to reach other systems
            - propagate_all: Propagate from all pwned systems
        destination: For test_single — the destination name
    """
    action = action.lower().strip()
    # Propagation is destructive; retrieve/test are OK to run in read-only.
    if action in ("propagate", "propagate_all"):
        if (ro := _read_only_guard()):
            return ro
    if action == "retrieve":
        resp = _api("POST", f"/api/node/{sid}/retrieve_rfcs", {})
    elif action == "test":
        resp = _api("POST", f"/api/node/{sid}/test_rfcs", {})
    elif action == "test_single":
        resp = _api("POST", f"/api/node/{sid}/test_rfc_single",
                    {"destination": destination})
    elif action == "propagate":
        resp = _api("POST", f"/api/node/{sid}/propagate", {})
    elif action == "propagate_all":
        resp = _api("POST", "/api/actions/propagate_all", {})
    else:
        return json.dumps({"error": f"Unknown RFC action: {action}"})
    _wait_for_tasks(timeout=600)
    return json.dumps(resp)


@mcp.tool()
def create_user_via_rfc(sid: str, destination: str,
                        target_sid: str = "",
                        confirm: bool = False) -> str:
    """Create the SAPMAP user on a remote system via an RFC destination.
    Uses an existing Type-3 (ABAP) RFC connection from the source system
    to reach the target — no direct network access needed.
    REQUIRES confirm=true.

    Args:
        sid: Source system SID (must be pwned with credentials)
        destination: RFC destination name (from SM59/RFCDES)
        target_sid: Expected target SID (for verification)
        confirm: Must be true to execute
    """
    if (ro := _read_only_guard()):
        return ro
    if not confirm:
        return json.dumps({
            "status": "blocked",
            "message": "User creation via RFC requires confirm=true."
        })
    resp = _api("POST", f"/api/node/{sid}/create_user_via_rfc", {
        "destination_name": destination,
        "target_sid": target_sid,
    })
    _wait_for_tasks(timeout=300)
    return json.dumps(resp)


@mcp.tool()
def create_tcpip_dest(sid: str, destination: str, host: str,
                      program: str = "",
                      confirm: bool = False) -> str:
    """Create a TCP/IP (Type-T) RFC destination on a pwned ABAP system.
    Used to seed a destination that SXPG_STEP_XPG_START or SAPControl
    OSExecute can bounce through for lateral movement.
    REQUIRES confirm=true.

    Args:
        sid: Source system SID (must be pwned with credentials)
        destination: Destination name to create (e.g. SAPMAP_PIVOT)
        host: Target host IP or hostname
        program: Registered server program ID (optional)
        confirm: Must be true to execute
    """
    if (ro := _read_only_guard()):
        return ro
    if not confirm:
        return json.dumps({
            "status": "blocked",
            "message": "TCP/IP destination creation requires confirm=true."
        })
    resp = _api("POST", f"/api/node/{sid}/create_tcpip_dest", {
        "destination": destination,
        "host": host,
        "program": program,
    })
    _wait_for_tasks(timeout=120)
    return json.dumps(resp)


@mcp.tool()
def sapcontrol_osexecute(sid: str, destination_name: str,
                         command: str, timeout: int = 30,
                         confirm: bool = False) -> str:
    """Execute an OS command via SAPControl OSExecute on a remote system.
    Uses a Type-G RFC destination that has been verified as os_exec capable
    (run manage_rfcs test_single first). The SOAP call blocks until the
    command completes.
    REQUIRES confirm=true.

    Args:
        sid: Source system SID (must be pwned)
        destination_name: Type-G RFC destination name
        command: Shell command to execute on the remote host
        timeout: Command timeout in seconds (default 30)
        confirm: Must be true to execute
    """
    if (ro := _read_only_guard()):
        return ro
    if not confirm:
        return json.dumps({
            "status": "blocked",
            "message": "SAPControl OSExecute requires confirm=true."
        })
    resp = _api("POST", f"/api/node/{sid}/sapcontrol_osexecute", {
        "destination_name": destination_name,
        "command": command,
        "timeout": timeout,
    })
    _wait_for_tasks(timeout=max(timeout + 30, 120))
    return json.dumps(resp)


@mcp.tool()
def autopwn(max_waves: int = 5, scan_gw: bool = True,
            scan_10kblaze: bool = False,
            scan_cve_31324: bool = True,
            scan_recon: bool = True,
            include_lpe: bool = False,
            include_btp: bool = True,
            confirm: bool = False) -> str:
    """Launch the full AutoPwn convergence loop: scan → exploit → enrich →
    propagate across all systems until no new ground is taken.
    REQUIRES confirm=true.

    Args:
        max_waves: Maximum convergence waves (default 5)
        scan_gw: Check Gateway SAPXPG vulnerability
        scan_10kblaze: Check 10KBlaze MS betrusted
        scan_cve_31324: Check CVE-2025-31324 VisualComposer
        scan_recon: Check CVE-2020-6287 RECON
        include_lpe: Run OS privilege escalation phase
        include_btp: Run BTP cloud lateral movement phase
        confirm: Must be true to execute
    """
    if (ro := _read_only_guard()):
        return ro
    if not confirm:
        return json.dumps({
            "status": "blocked",
            "message": "AutoPwn requires confirm=true. It will scan, "
                       "exploit, and propagate across the entire landscape."
        })
    resp = _api("POST", "/api/actions/autopwn", {
        "max_waves": max_waves,
        "scan_gw": scan_gw,
        "scan_10kblaze": scan_10kblaze,
        "scan_cve_31324": scan_cve_31324,
        "scan_recon": scan_recon,
        "include_lpe": include_lpe,
        "include_btp": include_btp,
    })
    _wait_for_tasks(timeout=3600)
    return json.dumps(resp)


# ===== TOOLS: Data Extraction =====

@mcp.tool()
def extract_data(sid: str, action: str, table: str = "",
                 fields: str = "", where: str = "",
                 max_rows: int = 500) -> str:
    """Extract data from a compromised SAP system.

    Args:
        sid: Target system SID (must be pwned or have credentials)
        action: Extraction action:
            - hashes: Download USR02 password hashes
            - secstore: Decrypt ABAP SecStore (RSECTAB)
            - java_secstore: Decrypt Java SecStoreFS
            - java_hashes: Extract Java UME password hashes
            - java_destinations: Read Java JCo destinations
            - table: Download an arbitrary SAP table
            - java_table: Download a Java DB table
            - oa2c: Read OA2C OAuth2 profiles
            - usrextid: Read USREXTID cert mappings
        table: For table/java_table — table name
        fields: For table — comma-separated field list (empty = all)
        where: For table — WHERE clause
        max_rows: Max rows to read (default 500)
    """
    if (ro := _read_only_guard()):
        return ro
    action = action.lower().strip()

    if action == "hashes":
        resp = _api("POST", f"/api/node/{sid}/download_hashes", {})
    elif action == "secstore":
        resp = _api("POST", f"/api/node/{sid}/download_secstore", {})
    elif action == "java_secstore":
        resp = _api("POST", f"/api/node/{sid}/java_secstore", {})
    elif action == "java_hashes":
        resp = _api("POST", f"/api/node/{sid}/extract_java_hashes", {})
    elif action == "java_destinations":
        resp = _api("POST", f"/api/node/{sid}/read_java_destinations", {})
    elif action == "table":
        if not table:
            return json.dumps({"error": "table parameter required"})
        payload = {"table": table, "max_rows": max_rows}
        if fields:
            payload["fields"] = fields
        if where:
            payload["where"] = where
        resp = _api("POST", f"/api/node/{sid}/download_table", payload)
    elif action == "java_table":
        if not table:
            return json.dumps({"error": "table parameter required"})
        resp = _api("POST", f"/api/node/{sid}/download_java_table",
                    {"table": table, "fields": fields or "*",
                     "max_rows": max_rows})
    elif action == "oa2c":
        resp = _api("POST", f"/api/node/{sid}/read_oa2c", {})
    elif action == "usrextid":
        resp = _api("POST", f"/api/node/{sid}/read_usrextid", {})
    else:
        return json.dumps({"error": f"Unknown extraction action: {action}"})

    _wait_for_tasks(timeout=300)
    return json.dumps(resp)


# ===== TOOLS: SCC (Cloud Connector) =====

@mcp.tool()
def scc_action(target: str, action: str, username: str = "",
               password: str = "", backup_password: str = "",
               confirm: bool = False) -> str:
    """Operate on an SAP Cloud Connector (SCC) node.

    Args:
        target: SCC host IP (for scc_* actions) or SAP SID (for harvest_*)
        action: SCC action:
            - probe_creds: Test default Administrator/manage
            - set_credentials: Store SCC admin credentials
            - pull_mappings: Pull cloud-to-on-prem mappings
            - probe_mappings: Smoke-test backend reachability
            - extract_keystore: Full backup + SSFS extraction (needs confirm)
            - download_hashes: Download SCC user password hashes
            - decrypt_ssfs: Decrypt SSFS from backup
            - harvest_mappings: Read backends.xml via OS-exec (SAP SID target)
            - harvest_ssfs: Read on-host SSFS via OS-exec (SAP SID target)
        username: SCC admin username
        password: SCC admin password
        backup_password: For extract_keystore
        confirm: Required for extract_keystore
    """
    if (ro := _read_only_guard()):
        return ro
    action = action.lower().strip()

    if action == "extract_keystore" and not confirm:
        return json.dumps({
            "status": "blocked",
            "message": "SCC keystore extraction requires confirm=true."
        })

    route_map = {
        "probe_creds": (f"/api/scc/{target}/probe_creds", {}),
        "set_credentials": (f"/api/scc/{target}/set_credentials",
                            {"username": username, "password": password}),
        "pull_mappings": (f"/api/scc/{target}/pull_mappings",
                          {"username": username, "password": password}),
        "probe_mappings": (f"/api/scc/{target}/probe_mappings", {}),
        "extract_keystore": (f"/api/scc/{target}/extract_keystore",
                             {"username": username, "password": password,
                              "backup_password": backup_password}),
        "download_hashes": (f"/api/scc/{target}/download_user_hashes", {}),
        "decrypt_ssfs": (f"/api/scc/{target}/decrypt_ssfs", {}),
        "harvest_mappings": (f"/api/node/{target}/harvest_scc_mappings", {}),
        "harvest_ssfs": (f"/api/node/{target}/harvest_scc_ssfs", {}),
    }

    if action not in route_map:
        return json.dumps({"error": f"Unknown SCC action: {action}",
                           "valid": list(route_map.keys())})

    path, payload = route_map[action]
    resp = _api("POST", path, payload)
    _wait_for_tasks(timeout=300)
    return json.dumps(resp)


# ===== TOOLS: BTP Cloud =====

@mcp.tool()
def btp_action(action: str, region: str = "", token: str = "",
               source_sid: str = "", destination_name: str = "",
               target_sid: str = "", uaa_url: str = "",
               client_id: str = "", client_secret: str = "",
               confirm: bool = False) -> str:
    """SAP BTP (Cloud) operations — token management, enumeration,
    and on-prem-to-cloud lateral movement.

    Args:
        action: BTP action:
            - set_token: Store a BTP access token
            - enumerate: Enumerate cloud resources with stored token
            - pull_destinations: Pull destinations for a dest-service token
            - test_destination: Test a BTP-to-on-prem edge
            - create_user_on_target: Create SAPMAP user via BTP edge (confirm)
            - harvest_creds: Mine on-prem system for BTP credentials
            - mint_token: Exchange client_id/secret for BTP token
        region: BTP region (auto-derived from token if omitted)
        token: JWT access token (for set_token)
        source_sid: Source node SID (for harvest/mint/test)
        destination_name: BTP destination name
        target_sid: Target ABAP SID (for create_user_on_target)
        uaa_url: XSUAA token endpoint (for mint_token)
        client_id: OAuth2 client ID (for mint_token)
        client_secret: OAuth2 client secret (for mint_token)
        confirm: Required for create_user_on_target
    """
    action = action.lower().strip()

    # Destructive sub-actions require operator + writable mode; read
    # actions (set_token, enumerate, pull_destinations, test_destination)
    # stay available.
    if action in ("create_user_on_target", "harvest_creds", "mint_token"):
        if (ro := _read_only_guard()):
            return ro
    if action == "create_user_on_target" and not confirm:
        return json.dumps({
            "status": "blocked",
            "message": "BTP user creation requires confirm=true."
        })

    if action == "set_token":
        resp = _api("POST", "/api/btp/set_token",
                    {"token": token, "region": region})
    elif action == "enumerate":
        resp = _api("POST", "/api/btp/enumerate",
                    {"region": region})
    elif action == "pull_destinations":
        resp = _api("POST", "/api/btp/pull_destinations_for_token",
                    {"region": region})
    elif action == "test_destination":
        resp = _api("POST", "/api/btp/test_destination",
                    {"source_sid": source_sid,
                     "destination_name": destination_name})
    elif action == "create_user_on_target":
        resp = _api("POST", "/api/btp/create_user_on_target",
                    {"source_sid": source_sid,
                     "destination_name": destination_name,
                     "target_sid": target_sid})
    elif action == "harvest_creds":
        resp = _api("POST", f"/api/node/{source_sid}/harvest_btp_creds", {})
    elif action == "mint_token":
        resp = _api("POST", f"/api/node/{source_sid}/mint_btp_token", {
            "uaa_url": uaa_url, "client_id": client_id,
            "client_secret": client_secret,
        })
    else:
        return json.dumps({"error": f"Unknown BTP action: {action}"})

    _wait_for_tasks(timeout=300)
    return json.dumps(resp)


# ===== TOOLS: MYSAPSSO2 Ticket Forgery =====

@mcp.tool()
def ticket_forgery(sid: str, action: str = "forge",
                   user: str = "SAP*", client: str = "100",
                   validity_min: int = 120,
                   confirm: bool = False) -> str:
    """MYSAPSSO2 ticket forgery — forge SSO tickets signed by a
    compromised system's SAPSYS.pse.
    REQUIRES confirm=true for forge and fanout actions.

    Args:
        sid: Source system SID (must be pwned with PSE extracted)
        action: One of:
            - discover_trust: Read STRUSTSSO2 trust relationships
            - forge: Forge a MYSAPSSO2 ticket (needs confirm)
            - fanout: Forge + replay against all trusted receivers (needs confirm)
        user: User to impersonate (default SAP*)
        client: Client for the forged ticket
        validity_min: Ticket validity in minutes
        confirm: Required for forge and fanout
    """
    action = action.lower().strip()
    if action in ("forge", "fanout"):
        if (ro := _read_only_guard()):
            return ro

    if action in ("forge", "fanout") and not confirm:
        return json.dumps({
            "status": "blocked",
            "message": f"Ticket {action} requires confirm=true."
        })

    if action == "discover_trust":
        resp = _api("POST", f"/api/node/{sid}/discover_strustsso2", {})
    elif action == "forge":
        resp = _api("POST", f"/api/node/{sid}/forge_ticket", {
            "user": user, "client": client,
            "validity_min": validity_min,
        })
    elif action == "fanout":
        resp = _api("POST", f"/api/node/{sid}/forge_and_fanout", {
            "user": user, "client": client,
            "validity_min": validity_min,
        })
    else:
        return json.dumps({"error": f"Unknown ticket action: {action}"})

    _wait_for_tasks(timeout=300)
    return json.dumps(resp)


# ===== TOOLS: SSH =====

@mcp.tool()
def ssh_lateral(sid: str, action: str = "harvest",
                confirm: bool = False) -> str:
    """SSH lateral movement — harvest keys, test targets, plant keys.

    Args:
        sid: Source system SID (must be pwned)
        action: One of:
            - harvest: Exfiltrate SSH keys and known_hosts
            - test_keys: Test harvested keys against known targets
            - plant_key: Plant SAPMAP SSH pubkey for persistence (needs confirm)
        confirm: Required for plant_key
    """
    action = action.lower().strip()
    if (ro := _read_only_guard()):
        return ro
    if action == "plant_key" and not confirm:
        return json.dumps({
            "status": "blocked",
            "message": "SSH key planting requires confirm=true."
        })

    if action == "harvest":
        resp = _api("POST", f"/api/node/{sid}/ssh_harvest", {})
    elif action == "test_keys":
        resp = _api("POST", f"/api/node/{sid}/ssh_test_keys", {})
    elif action == "plant_key":
        resp = _api("POST", f"/api/node/{sid}/ssh_plant_key", {})
    else:
        return json.dumps({"error": f"Unknown SSH action: {action}"})

    _wait_for_tasks(timeout=300)
    return json.dumps(resp)


# ===== TOOLS: RanSAPware =====

@mcp.tool()
def ransapware(sid: str, action: str = "list_tables",
               table: str = "", max_rows: int = 5000,
               send_popup: bool = True,
               manifest_path: str = "",
               confirm: bool = False) -> str:
    """RanSAPware Awareness PoC — table data encryption/decryption
    for security awareness demonstrations.

    Args:
        sid: Target system SID
        action: One of:
            - list_tables: Show suggested high-impact tables
            - get_fields: Get encryptable fields for a table
            - encrypt: Encrypt a table (needs confirm)
            - decrypt: Decrypt using a manifest
            - list_manifests: List encryption manifests
        table: Table name (for get_fields/encrypt)
        max_rows: Max rows to encrypt (default 5000)
        send_popup: Send TH_POPUP ransom note after encryption
        manifest_path: Manifest file path (for decrypt)
        confirm: Required for encrypt
    """
    action = action.lower().strip()
    if action in ("encrypt", "decrypt", "get_fields"):
        if (ro := _read_only_guard()):
            return ro

    if action == "encrypt" and not confirm:
        return json.dumps({
            "status": "blocked",
            "message": "Table encryption requires confirm=true."
        })

    if action == "list_tables":
        resp = _api("GET", "/api/ransapware/suggested_tables")
    elif action == "get_fields":
        resp = _api("POST", f"/api/node/{sid}/ransapware/fields",
                    {"table": table})
        _wait_for_tasks(timeout=60)
    elif action == "encrypt":
        if not table:
            return json.dumps({"error": "table parameter required"})
        fields_resp = _api("POST", f"/api/node/{sid}/ransapware/fields",
                           {"table": table})
        _wait_for_tasks(timeout=60)
        fields_resp = _api("GET",
                           f"/api/node/{sid}/ransapware/fields?table={table}")
        fields = fields_resp.get("fields", [])
        target_fields = [f["name"] for f in fields if f.get("selected")]
        key_fields = fields_resp.get("key_fields", [])
        if not target_fields:
            target_fields = [f["name"] for f in fields]
        resp = _api("POST", f"/api/node/{sid}/ransapware/encrypt", {
            "table": table,
            "fields": target_fields,
            "key_fields": key_fields,
            "max_rows": max_rows,
            "send_popup": send_popup,
        })
        _wait_for_tasks(timeout=300)
    elif action == "decrypt":
        if not manifest_path:
            return json.dumps({"error": "manifest_path required"})
        resp = _api("POST", f"/api/node/{sid}/ransapware/decrypt",
                    {"manifest_path": manifest_path})
        _wait_for_tasks(timeout=300)
    elif action == "list_manifests":
        resp = _api("GET", f"/api/node/{sid}/ransapware/manifests")
    else:
        return json.dumps({"error": f"Unknown ransapware action: {action}"})

    return json.dumps(resp)


# ===== TOOLS: Business Impact & Reports =====

@mcp.tool()
def business_impact(sid: str, action: str = "assess",
                    client: str = "001",
                    scenario: str = "") -> str:
    """Run business impact assessment scenarios on a compromised system.

    Args:
        sid: Target system SID (must have credentials)
        action: One of:
            - assess: Run impact assessment (all scenarios or specific)
            - show: Show results of a previous assessment
            - export: Export results to CSV
            - scenarios: List available scenarios
        client: SAP client (default 001)
        scenario: Specific scenario name (empty = all)
    """
    action = action.lower().strip()
    if action == "assess":
        payload = {"client": str(client)}
        if scenario:
            payload["scenario"] = scenario
        resp = _api("POST", f"/api/node/{sid}/impact/assess", payload)
        _wait_for_tasks(timeout=300)
    elif action == "show":
        resp = _api("GET", f"/api/node/{sid}/impact")
    elif action == "export":
        if scenario:
            resp = _api("GET",
                        f"/api/node/{sid}/impact/export/{scenario}")
        else:
            resp = _api("GET", f"/api/node/{sid}/impact")
    elif action == "scenarios":
        resp = _api("GET", "/api/impact/scenarios")
    else:
        return json.dumps({"error": f"Unknown impact action: {action}"})
    return json.dumps(resp)


@mcp.tool()
def export_report() -> str:
    """Generate an engagement report (HTML + Markdown) with findings,
    attack paths, KPIs, and recommendations. Saved to loot/reports/."""
    resp = _api("POST", "/api/export/report", {})
    _wait_for_tasks(timeout=120)
    return json.dumps(resp)


# ===== TOOLS: Cleanup =====

@mcp.tool()
def cleanup(sid: str = "", confirm: bool = False) -> str:
    """Delete SAPMAP-created users and clean up artifacts.
    REQUIRES confirm=true.

    Args:
        sid: System SID to clean up (empty = all systems)
        confirm: Must be true to execute
    """
    if (ro := _read_only_guard()):
        return ro
    if not confirm:
        return json.dumps({
            "status": "blocked",
            "message": "Cleanup requires confirm=true."
        })
    if sid:
        resp = _api("POST", f"/api/node/{sid}/cleanup", {})
    else:
        resp = _api("POST", "/api/actions/cleanup_all", {})
    _wait_for_tasks(timeout=300)
    return json.dumps(resp)


# ===== TOOLS: Generic passthrough =====

@mcp.tool()
def run_sapmap_action(action: str, target: str = "",
                      params: dict = None,
                      confirm: bool = False) -> str:
    """Run any SAPMAP scripting action by name. This is the generic
    passthrough for actions not covered by the curated tools above.
    See SAPMAP's scripted-scenarios documentation for the full action list.

    Args:
        action: Action name (e.g. 'check_gw', 'retrieve_rfcs', etc.)
        target: Target SID or IP
        params: Additional parameters as a dict
        confirm: Required for destructive actions
    """
    DESTRUCTIVE = {
        "exploit_cve_31324", "create_user_java", "scc_extract_keystore",
        "harvest_scc", "exploit_copyfail", "exploit_linux_lpe",
        "exploit_windows_lpe", "forge_ticket", "forge_and_fanout",
        "ssh_plant_key", "import_transport", "autopwn",
        "tier3_arm_death_star", "create_user", "betrusted",
        "betrusted_chain", "exec_command", "ransapware_encrypt",
        "btp_create_user_on_target", "lpe",
    }

    if action in DESTRUCTIVE:
        if (ro := _read_only_guard()):
            return ro
    if action in DESTRUCTIVE and not confirm:
        return json.dumps({
            "status": "blocked",
            "message": f"Action '{action}' is destructive — set confirm=true."
        })

    step = {"action": action, "target": target}
    if params:
        step.update(params)

    # Use the script engine's _map_step to resolve the route
    # but we inline the most common patterns here
    p = params or {}

    # Try to forward to the SAPMAP API using common patterns
    if target:
        path = f"/api/node/{target}/{action}"
    else:
        path = f"/api/actions/{action}"

    resp = _api("POST", path, p)
    if "error" in resp and "404" in str(resp.get("error", "")):
        return json.dumps({
            "error": f"Action '{action}' could not be mapped to an API route. "
                     f"Use one of the curated tools instead, or check the "
                     f"SAPMAP scripting documentation for valid action names."
        })
    _wait_for_tasks(timeout=600)
    return json.dumps(resp)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="SAPMAP MCP Server — Model Context Protocol interface")
    parser.add_argument("--port", type=int, default=8080,
                        help="SAPMAP HTTP server port (default: 8080)")
    args = parser.parse_args()
    _set_base_url(args.port)

    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
