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
    build_bapi_user_profiles_assign,
    build_rfc_ping,
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

def test_all_builders_produce_parseable_xml():
    """If a builder ever emits malformed XML (unbalanced tag, missing
    namespace, etc.), this test fails fast."""
    from xml.etree import ElementTree as ET
    for env in (
            build_rfc_ping(),
            build_bapi_user_create1("U", "P"),
            build_bapi_user_profiles_assign("U", ["SAP_ALL"]),
            build_bapi_transaction_commit(),
            build_bapi_transaction_commit(wait=False)):
        ET.fromstring(env)  # raises ParseError on malformed XML
