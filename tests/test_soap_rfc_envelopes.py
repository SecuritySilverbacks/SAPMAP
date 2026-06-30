"""Tests for sap_soap_envelopes — SOAP envelope builders + response parser.

Phase 3a only — covers the four FMs we need for "Create Remote User over
HTTP": RFC_PING, BAPI_USER_CREATE1, BAPI_USER_PROFILES_ASSIGN,
BAPI_TRANSACTION_COMMIT.
"""
from __future__ import annotations

import modules  # noqa: F401  registers package paths
from sap_soap_envelopes import (
    build_bapi_transaction_commit,
    build_bapi_user_create1,
    build_bapi_user_delete,
    build_bapi_user_get_detail,
    build_bapi_user_profiles_assign,
    build_dest_check_connection,
    build_dest_rfc_tcpip_create,
    build_rfc_abap_install_and_run,
    build_rfc_get_system_info,
    build_rfc_ping,
    build_rfc_read_table,
    build_sxpg_step_xpg_start,
    build_sxpg_step_xpg_start_no_mxrow,
    parse_response,
)


# ---------------------------------------------------------------------------
# Builder shape: SAP rejects envelopes with the wrong namespace, missing
# xml prolog, or items outside an <item> wrapper — these tests lock that.
# ---------------------------------------------------------------------------

def test_envelope_has_xml_prolog_and_soap_namespace():
    """SAP's ICM rejects envelopes without the xml declaration; the SOAP
    namespace must be soap/envelope/ (the SAP-specific urn: namespace is
    layered on top with the urn: prefix)."""
    env = build_rfc_ping()
    assert env.startswith('<?xml version="1.0" encoding="UTF-8"?>')
    assert ('xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"'
            in env)
    assert ('xmlns:urn="urn:sap-com:document:sap:rfc:functions"'
            in env)


def test_rfc_ping_envelope_minimal():
    """RFC_PING is parameter-less; envelope must be a single empty
    element with the urn: prefix."""
    env = build_rfc_ping()
    assert "<urn:RFC_PING/>" in env


def test_bapi_user_create1_password_is_a_structure():
    """The most common builder mistake — passing the password as a
    scalar.  PASSWORD is a BAPIPWD structure with a single BAPIPWD CHAR40
    field; SAP returns RFC_DESERIALIZE_ERROR if you flatten it."""
    env = build_bapi_user_create1("SAPMAP00", "Andinyougo123!")
    assert "<PASSWORD><BAPIPWD>Andinyougo123!</BAPIPWD></PASSWORD>" in env


def test_bapi_user_create1_passes_address_and_logondata():
    """ADDRESS and LOGONDATA are required structures even when we only
    set FIRSTNAME/LASTNAME and USTYP — sending an empty PASSWORD with
    no other structures triggers a different code path that rejects
    the user-type default."""
    env = build_bapi_user_create1(
        "SAPMAP00", "pw", firstname="SAP", lastname="Map",
        user_type="A")
    assert "<USERNAME>SAPMAP00</USERNAME>" in env
    assert ("<ADDRESS><FIRSTNAME>SAP</FIRSTNAME>"
            "<LASTNAME>Map</LASTNAME></ADDRESS>") in env
    assert "<LOGONDATA><USTYP>A</USTYP></LOGONDATA>" in env


def test_bapi_user_create1_escapes_xml_special_chars():
    """Passwords often contain &, <, >, '.  Unescaped they break the
    XML parser on the SAP side — at best the call fails, at worst we
    inject elements into the envelope."""
    env = build_bapi_user_create1(
        "U", "pw<&>\"'!", lastname="O'Reilly")
    assert "pw&lt;&amp;&gt;&quot;&apos;!" in env
    assert "<LASTNAME>O&apos;Reilly</LASTNAME>" in env


def test_bapi_user_profiles_assign_wraps_each_profile_in_item():
    """PROFILES is a TABLE OF BAPIPROF; each row must be wrapped in
    <item> and the field name inside is BAPIPROF — confusingly the
    same name as the row type."""
    env = build_bapi_user_profiles_assign("SAPMAP00", ["SAP_ALL"])
    assert ("<PROFILES><item><BAPIPROF>SAP_ALL</BAPIPROF>"
            "</item></PROFILES>") in env


def test_bapi_user_profiles_assign_multiple_profiles():
    """Multi-profile assign: order is preserved, each in its own item."""
    env = build_bapi_user_profiles_assign(
        "U", ["SAP_ALL", "SAP_NEW", "S_A.SYSTEM"])
    profiles_section = env[env.index("<PROFILES>"):
                            env.index("</PROFILES>") + len("</PROFILES>")]
    assert profiles_section.count("<item>") == 3
    assert ("<item><BAPIPROF>SAP_ALL</BAPIPROF></item>"
            "<item><BAPIPROF>SAP_NEW</BAPIPROF></item>"
            "<item><BAPIPROF>S_A.SYSTEM</BAPIPROF></item>"
            ) in profiles_section


def test_bapi_user_get_detail_envelope_declares_output_tables():
    """SAP's SOAP-RFC kernel only emits TABLES in the response when
    the request DECLARES them as empty placeholders.  Without these,
    PROFILES + ACTIVITYGROUPS + RETURN come back missing from the
    response — even though the BAPI populated them server-side."""
    env = build_bapi_user_get_detail("SAPADM")
    assert "<urn:BAPI_USER_GET_DETAIL>" in env
    assert "<USERNAME>SAPADM</USERNAME>" in env
    # Empty-table placeholders — critical for response shape
    assert "<PROFILES/>" in env
    assert "<ACTIVITYGROUPS/>" in env
    assert "<RETURN/>" in env
    assert "</urn:BAPI_USER_GET_DETAIL>" in env


def test_bapi_user_get_detail_sends_cache_results_x():
    """CACHE_RESULTS='X' forces a fresh read of USR04/UST04 rather than
    serving stale SAP_USER buffer entries — relevant right after a
    profile change."""
    env = build_bapi_user_get_detail("U")
    assert "<CACHE_RESULTS>X</CACHE_RESULTS>" in env


def test_bapi_user_get_detail_escapes_username():
    """Usernames containing < > & must be escaped — defensive: real
    usernames don't have these chars but we don't want a malformed
    envelope if test data is junk."""
    env = build_bapi_user_get_detail("U<&>")
    assert "<USERNAME>U&lt;&amp;&gt;</USERNAME>" in env


def test_bapi_transaction_commit_wait_x():
    """WAIT='X' makes COMMIT WORK synchronous so the next BAPI sees
    the new user.  Empty WAIT is async — the user might not yet exist
    when BAPI_USER_PROFILES_ASSIGN fires."""
    env_sync = build_bapi_transaction_commit(wait=True)
    env_async = build_bapi_transaction_commit(wait=False)
    assert "<WAIT>X</WAIT>" in env_sync
    assert "<WAIT></WAIT>" in env_async


# ---------------------------------------------------------------------------
# Parser — uses fixed response strings to lock the parsing contract.
# ---------------------------------------------------------------------------

_RESP_RFC_PING_OK = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body>'
    '<rfc:RFC_PING.Response '
    'xmlns:rfc="urn:sap-com:document:sap:rfc:functions"/>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>'
)


def test_parse_rfc_ping_success():
    """Empty .Response element = ok=True, no params, no tables."""
    r = parse_response(_RESP_RFC_PING_OK, "RFC_PING")
    assert r["ok"] is True
    assert r["error"] == ""
    assert r["params"] == {}
    assert r["tables"] == {}


_RESP_USER_CREATE_OK = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body>'
    '<rfc:BAPI_USER_CREATE1.Response '
    'xmlns:rfc="urn:sap-com:document:sap:rfc:functions">'
    '<RETURN>'
    '<item>'
    '<TYPE>S</TYPE>'
    '<ID>01</ID>'
    '<NUMBER>105</NUMBER>'
    '<MESSAGE>User SAPMAP00 was created</MESSAGE>'
    '</item>'
    '</RETURN>'
    '</rfc:BAPI_USER_CREATE1.Response>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>'
)


def test_parse_bapi_user_create1_success():
    """S-type RETURN row = success even though RETURN table is non-empty."""
    r = parse_response(_RESP_USER_CREATE_OK, "BAPI_USER_CREATE1")
    assert r["ok"] is True
    assert r["error"] == ""
    assert "RETURN" in r["tables"]
    assert r["tables"]["RETURN"][0]["TYPE"] == "S"
    assert "SAPMAP00 was created" in r["tables"]["RETURN"][0]["MESSAGE"]


_RESP_USER_CREATE_DUPLICATE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body>'
    '<rfc:BAPI_USER_CREATE1.Response '
    'xmlns:rfc="urn:sap-com:document:sap:rfc:functions">'
    '<RETURN>'
    '<item>'
    '<TYPE>E</TYPE>'
    '<ID>01</ID>'
    '<NUMBER>102</NUMBER>'
    '<MESSAGE>User SAPMAP00 already exists</MESSAGE>'
    '</item>'
    '</RETURN>'
    '</rfc:BAPI_USER_CREATE1.Response>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>'
)


def test_parse_bapi_user_create1_logical_error():
    """E-type in RETURN = ok=False with message exposed.  This is the
    most common 'user already exists' branch; the caller may choose to
    treat it as success and continue with PROFILES_ASSIGN."""
    r = parse_response(_RESP_USER_CREATE_DUPLICATE, "BAPI_USER_CREATE1")
    assert r["ok"] is False
    assert "already exists" in r["error"]
    assert "E " in r["error"]   # type prefix


_RESP_SOAP_FAULT_AUTH = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body>'
    '<SOAP-ENV:Fault>'
    '<faultcode>SOAP-ENV:Client</faultcode>'
    '<faultstring>RFC_AUTHORIZATION_FAILURE: User has no '
    'authorization for function module</faultstring>'
    '</SOAP-ENV:Fault>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>'
)


_RESP_SOAP_FAULT_WITH_DETAIL = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body>'
    '<SOAP-ENV:Fault>'
    '<faultcode>SOAP-ENV:Client</faultcode>'
    '<faultstring>Internal Server Error</faultstring>'
    '<detail>'
    '<rfc:Error xmlns:rfc="urn:sap-com:document:sap:soap:functions">'
    '<type>ERROR_MESSAGE_STATE</type>'
    '<message>Changes to repository objects are not permitted '
    'in this client</message>'
    '</rfc:Error></detail>'
    '</SOAP-ENV:Fault>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>'
)


def test_parse_soap_fault_extracts_sap_detail_message():
    """SAP wraps the actually-useful kernel error info in
    <detail><rfc:Error><message> — generic faultstring just says
    'Internal Server Error' which is useless for triage.  Parser must
    flatten the detail into the error string so callers can branch on
    'not permitted in this client' vs 'no authorization' vs 'syntax
    error' without bespoke XML parsing."""
    r = parse_response(
        _RESP_SOAP_FAULT_WITH_DETAIL, "RFC_ABAP_INSTALL_AND_RUN")
    assert r["ok"] is False
    assert "Internal Server Error" in r["error"]
    assert ("Changes to repository objects are not permitted "
            "in this client") in r["error"]
    assert "ERROR_MESSAGE_STATE" in r["error"]


def test_parse_soap_fault_returns_error():
    """SOAP fault = ok=False and error contains both faultcode and
    faultstring so the caller can distinguish auth-rejected from
    system-error."""
    r = parse_response(_RESP_SOAP_FAULT_AUTH, "BAPI_USER_CREATE1")
    assert r["ok"] is False
    assert "RFC_AUTHORIZATION_FAILURE" in r["error"]
    assert "SOAP-ENV:Client" in r["error"]


def test_parse_bad_xml_returns_error():
    """Garbage in (e.g. HTML error page from an upstream proxy) must
    not raise — caller relies on r['error']."""
    r = parse_response("<html>nope</html>", "RFC_PING")
    assert r["ok"] is False
    assert "No <RFC_PING.Response>" in r["error"]


def test_parse_unparseable_xml_returns_error():
    """Truly unparseable XML must surface as an error, not raise."""
    r = parse_response("not xml at all", "RFC_PING")
    assert r["ok"] is False
    assert "XML parse error" in r["error"]


_RESP_PROFILES_ASSIGN_OK = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body>'
    '<rfc:BAPI_USER_PROFILES_ASSIGN.Response '
    'xmlns:rfc="urn:sap-com:document:sap:rfc:functions">'
    '<RETURN>'
    '<item><TYPE>S</TYPE><ID>01</ID><NUMBER>122</NUMBER>'
    '<MESSAGE>Profile assignment changed</MESSAGE></item>'
    '</RETURN>'
    '</rfc:BAPI_USER_PROFILES_ASSIGN.Response>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>'
)


def test_parse_profiles_assign_success():
    r = parse_response(
        _RESP_PROFILES_ASSIGN_OK, "BAPI_USER_PROFILES_ASSIGN")
    assert r["ok"] is True
    assert r["tables"]["RETURN"][0]["TYPE"] == "S"


_RESP_BAPIRET2_AS_STRUCT = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body>'
    '<rfc:BAPI_TRANSACTION_COMMIT.Response '
    'xmlns:rfc="urn:sap-com:document:sap:rfc:functions">'
    '<RETURN>'
    '<TYPE></TYPE><ID></ID><NUMBER>000</NUMBER>'
    '<MESSAGE></MESSAGE>'
    '</RETURN>'
    '</rfc:BAPI_TRANSACTION_COMMIT.Response>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>'
)


def test_parse_bapi_transaction_commit_returns_structure_not_table():
    """BAPI_TRANSACTION_COMMIT's RETURN is a BAPIRET2 *structure*, not
    a table — no <item> wrapper.  Empty TYPE = ok per BAPI conventions."""
    r = parse_response(
        _RESP_BAPIRET2_AS_STRUCT, "BAPI_TRANSACTION_COMMIT")
    assert r["ok"] is True
    assert r["params"]["RETURN"]["NUMBER"] == "000"


# ---------------------------------------------------------------------------
# Roundtrip — every builder produces XML that is itself parseable, even
# if it doesn't match the response shape.  Cheap guard against malformed
# templates slipping through.
# ---------------------------------------------------------------------------

_RESP_USER_GET_DETAIL_SAP_ALL = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body>'
    '<rfc:BAPI_USER_GET_DETAIL.Response '
    'xmlns:rfc="urn:sap-com:document:sap:rfc:functions">'
    '<PROFILES>'
    '<item><BAPIPROF>SAP_ALL</BAPIPROF>'
    '<BAPIPTEXT>All authorisations</BAPIPTEXT></item>'
    '<item><BAPIPROF>SAP_NEW</BAPIPROF>'
    '<BAPIPTEXT>New authorisations</BAPIPTEXT></item>'
    '</PROFILES>'
    '<ACTIVITYGROUPS>'
    '<item><AGR_NAME>SAP_BC_BASIS_ADMIN</AGR_NAME>'
    '<AGR_TEXT>Basis Admin</AGR_TEXT></item>'
    '</ACTIVITYGROUPS>'
    '<RETURN/>'
    '</rfc:BAPI_USER_GET_DETAIL.Response>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>'
)


def test_parse_user_get_detail_extracts_profiles_and_roles():
    """The key parse: PROFILES + ACTIVITYGROUPS land in tables; each
    is a list of structures keyed by their inner field names."""
    r = parse_response(
        _RESP_USER_GET_DETAIL_SAP_ALL, "BAPI_USER_GET_DETAIL")
    assert r["ok"] is True
    profiles = [row["BAPIPROF"] for row in r["tables"]["PROFILES"]]
    assert profiles == ["SAP_ALL", "SAP_NEW"]
    roles = [row["AGR_NAME"] for row in r["tables"]["ACTIVITYGROUPS"]]
    assert roles == ["SAP_BC_BASIS_ADMIN"]


def test_all_builders_produce_parseable_xml():
    """If a builder ever emits malformed XML (unbalanced tag, missing
    namespace, etc.), this test fails fast."""
    from xml.etree import ElementTree as ET
    for env in (
            build_rfc_ping(),
            build_rfc_get_system_info(),
            build_dest_check_connection("S4H_SVC"),
            build_dest_rfc_tcpip_create(
                "X", "h", "h", "3340"),
            build_rfc_abap_install_and_run(
                ["REPORT t.", "WRITE 'x'."]),
            build_bapi_user_create1("U", "P"),
            build_bapi_user_delete("U"),
            build_bapi_user_get_detail("U"),
            build_bapi_user_profiles_assign("U", ["SAP_ALL"]),
            build_bapi_transaction_commit(),
            build_bapi_transaction_commit(wait=False),
            build_sxpg_step_xpg_start("/bin/sh", "-c whoami"),
            build_sxpg_step_xpg_start_no_mxrow("cmd.exe", "/c dir"),
            build_rfc_read_table("T000"),
            build_rfc_read_table("T000", fields=["MANDT"],
                                 where=["MANDT NE '000'"]),
            ):
        ET.fromstring(env)  # raises ParseError on malformed XML


# ---------------------------------------------------------------------------
# SXPG / RFC_READ_TABLE / RFC_GET_SYSTEM_INFO envelopes
# ---------------------------------------------------------------------------

def test_sxpg_envelope_includes_required_kernel_controls():
    """STDOUTCNTL=M / STDERRCNTL=M merges OS stdout+stderr into LOG;
    skipping these makes the kernel use the default 'F' (file) which
    drops output to a /usr/sap log file the caller can't see."""
    env = build_sxpg_step_xpg_start(
        "/bin/sh", params="-c whoami")
    assert "<EXTPROG>/bin/sh</EXTPROG>" in env
    assert "<PARAMS>-c whoami</PARAMS>" in env
    assert "<STDOUTCNTL>M</STDOUTCNTL>" in env
    assert "<STDERRCNTL>M</STDERRCNTL>" in env
    # Must declare LOG/ as a placeholder — same kernel quirk as
    # BAPI_USER_GET_DETAIL.PROFILES; without it the output is lost.
    assert "<LOG/>" in env
    # MXROW default — present in the standard builder
    assert "<MXROW>9999</MXROW>" in env


def test_sxpg_envelope_no_mxrow_variant_for_old_kernels():
    """The fallback builder must NOT include MXROW — older kernels
    (Basis 7.0x) raise RFC_INVALID_PARAMETER if it's present."""
    env = build_sxpg_step_xpg_start_no_mxrow(
        "cmd.exe", params="/c whoami")
    assert "<MXROW>" not in env
    assert "<EXTPROG>cmd.exe</EXTPROG>" in env


def test_sxpg_envelope_carries_long_params_separately():
    """Big payloads (Python -c '<800 chars hex>') go in LONG_PARAMS
    while a short marker stays in PARAMS — without this split, the
    SAP kernel either truncates at CHAR255 or rejects."""
    env = build_sxpg_step_xpg_start(
        "python3", params="-c",
        long_params="import base64; print(base64.b64decode('XYZ'))")
    assert "<PARAMS>-c</PARAMS>" in env
    assert "<LONG_PARAMS>import base64" in env


def test_sxpg_envelope_escapes_dangerous_command_characters():
    """Real commands contain & < > etc. — unescaped they break the
    request envelope.  Defensive: prevents the operator's command from
    silently turning into something else due to XML reinterpretation."""
    env = build_sxpg_step_xpg_start(
        "/bin/sh", params="-c 'echo a&b<c>d'")
    assert "echo a&amp;b&lt;c&gt;d" in env


def test_rfc_read_table_envelope_basic():
    """Field-less / where-less table read — bare QUERY_TABLE +
    DELIMITER suffice when caller wants all fields, all rows."""
    env = build_rfc_read_table("T000")
    assert "<QUERY_TABLE>T000</QUERY_TABLE>" in env
    assert "<DELIMITER>|</DELIMITER>" in env
    assert "<NO_DATA></NO_DATA>" in env
    assert "<OPTIONS></OPTIONS>" in env
    assert "<FIELDS></FIELDS>" in env
    assert "<DATA/>" in env  # output placeholder


def test_rfc_read_table_envelope_with_fields_and_options():
    """FIELDS and OPTIONS are TABLEs in RFC_READ_TABLE's interface;
    each row wrapped in <item> with FIELDNAME / TEXT field name."""
    env = build_rfc_read_table(
        "USR02", fields=["BNAME", "BCODE"],
        where=["BNAME LIKE 'SAP%'", "MANDT EQ '000'"])
    assert ("<FIELDS>"
            "<item><FIELDNAME>BNAME</FIELDNAME></item>"
            "<item><FIELDNAME>BCODE</FIELDNAME></item>"
            "</FIELDS>") in env
    assert "<item><TEXT>BNAME LIKE &apos;SAP%&apos;</TEXT></item>" in env
    assert "<item><TEXT>MANDT EQ &apos;000&apos;</TEXT></item>" in env


def test_rfc_read_table_no_data_flag():
    """NO_DATA='X' = return only FIELDS metadata, skip DATA — used
    by DDIF lookups when the caller wants the column list."""
    env = build_rfc_read_table("T000", no_data=True)
    assert "<NO_DATA>X</NO_DATA>" in env


def test_rfc_read_table_pagination_via_rowcount_and_rowskips():
    """When dumping large tables (USR02) we page; both fields must be
    serialized so the kernel honors them."""
    env = build_rfc_read_table(
        "USR02", rowcount=100, rowskips=200)
    assert "<ROWCOUNT>100</ROWCOUNT>" in env
    assert "<ROWSKIPS>200</ROWSKIPS>" in env


def test_bapi_user_delete_envelope_declares_return_table():
    """Like every BAPI with output tables, RETURN must be declared as
    a placeholder in the request or the kernel strips it from the
    response and we can't distinguish 'user didn't exist' from 'no
    S_USER_GRP authorization' from clean success."""
    env = build_bapi_user_delete("SAPMAP00")
    assert "<urn:BAPI_USER_DELETE>" in env
    assert "<USERNAME>SAPMAP00</USERNAME>" in env
    assert "<RETURN/>" in env


def test_rfc_abap_install_and_run_envelope_wraps_each_line_in_item():
    """PROGRAM is a TABLE of program lines.  Each line must be wrapped
    in <item><LINE>...</LINE></item> — sending a flat string of code
    triggers RFC_INVALID_TABLE_FORMAT and the kernel rejects it before
    syntax-checking the ABAP."""
    env = build_rfc_abap_install_and_run([
        "REPORT zsapmap.", "WRITE 'hello'.",
    ])
    assert "<PROGRAMNAME>ZSAPMAP</PROGRAMNAME>" in env
    assert "<MODE>F</MODE>" in env
    assert ("<PROGRAM>"
            "<item><LINE>REPORT zsapmap.</LINE></item>"
            "<item><LINE>WRITE &apos;hello&apos;.</LINE></item>"
            "</PROGRAM>") in env
    # Output placeholders — same kernel quirk as every other BAPI in
    # this module; omit them and WRITES comes back missing
    assert "<WRITES/>" in env
    assert "<MESSAGES/>" in env


def test_rfc_abap_install_and_run_escapes_program_lines():
    """ABAP source can contain < > & ' (CONCATENATE 'a' '<b>' INTO x)
    — defensive: real code routinely has these characters, and an
    unescaped < turns into a malformed envelope and 400-error."""
    env = build_rfc_abap_install_and_run([
        "CONCATENATE 'a' '<b>' INTO x.",
    ])
    assert "&lt;b&gt;" in env
    assert "<b>" not in env.replace("<b>'", "")  # not the raw chars


def test_dest_rfc_tcpip_create_envelope_carries_all_required_fields():
    """DEST_RFC_TCPIP_CREATE rejects calls missing any of SERVER_NAME /
    GATEWAY_HOST / GATEWAY_SERVICE / METHOD / PROGRAM — older kernels
    raise FIELD_MISSING, newer ones silently no-op the create.  Pin all
    of them in the envelope shape."""
    env = build_dest_rfc_tcpip_create(
        name="SAPMAP_W74_20260630",
        server_name="winwas740",
        gateway_host="winwas740",
        gateway_service="3340")
    assert "<NAME>SAPMAP_W74_20260630</NAME>" in env
    assert "<SERVER_NAME>winwas740</SERVER_NAME>" in env
    assert "<GATEWAY_HOST>winwas740</GATEWAY_HOST>" in env
    assert "<GATEWAY_SERVICE>3340</GATEWAY_SERVICE>" in env
    assert "<METHOD>E</METHOD>" in env
    assert "<PROGRAM>sapxpg</PROGRAM>" in env
    assert "<CPIC_TIMEOUT>20</CPIC_TIMEOUT>" in env
    # RETURN placeholder so the kernel emits BAPIRET2 in the response
    assert "<RETURN/>" in env


def test_dest_check_connection_envelope():
    """Single NAME parameter naming the SM59 destination to ping."""
    env = build_dest_check_connection("S4H_SVC")
    assert "<urn:DEST_CHECK_CONNECTION>" in env
    assert "<NAME>S4H_SVC</NAME>" in env
    assert "</urn:DEST_CHECK_CONNECTION>" in env


def test_dest_check_connection_escapes_name():
    """Destination names are CHAR32 — operators don't put XML special
    chars in them, but defensive escape guards against typos."""
    env = build_dest_check_connection("WEIRD<&>NAME")
    assert "<NAME>WEIRD&lt;&amp;&gt;NAME</NAME>" in env


def test_rfc_get_system_info_envelope_no_destination():
    """When called locally (over SOAP we always are — there's no
    'forwarded RFC' concept), DESTINATION is omitted entirely, not
    sent as empty.  Some kernels treat empty DESTINATION as 'route
    to default RFC server' which is not what we want."""
    env = build_rfc_get_system_info()
    assert "<urn:RFC_GET_SYSTEM_INFO/>" in env
    assert "<DESTINATION>" not in env
