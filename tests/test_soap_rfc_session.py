"""Tests for SOAPRFCSession — verify HTTP wire format + orchestration.

We spin up a small http.server in a thread that records every incoming
request and replies with canned SAP-shaped XML.  This keeps the tests
offline-safe and fast without mocking out urllib.
"""
from __future__ import annotations

import base64
import http.server
import socket
import threading
import time

import modules  # noqa: F401  registers package paths
from sap_soap_basic import (
    SOAPRFCError, SOAPRFCSession,
    create_user_via_soap, delete_user_via_soap,
)


# ---------------------------------------------------------------------------
# Mock SAP ICM
# ---------------------------------------------------------------------------

class _MockSAPHandler(http.server.BaseHTTPRequestHandler):
    """Per-request handler that delegates to the server's `responder`."""

    def log_message(self, *_a, **_k):  # silence noisy stderr
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        # Record the request on the server so tests can assert on it
        self.server.requests.append({
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
        })
        status, response_body = self.server.responder(self.path, body)
        self.send_response(status)
        self.send_header("Content-Type", "text/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body.encode("utf-8"))


class _MockSAP:
    """Threaded HTTP server preconfigured to act like SAP's SOAP-RFC ICF."""

    def __init__(self, responder):
        self.requests = []
        # Bind to a free port on localhost
        self.server = http.server.HTTPServer(
            ("127.0.0.1", 0), _MockSAPHandler)
        self.server.requests = self.requests
        self.server.responder = responder
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        # Don't join — daemon thread, serve_forever loop has already exited.


def _make_responder(reply_map):
    """Build a responder closure from a path/body → response map.

    reply_map: dict of FM_NAME → (http_status, xml_string).
    The FM name is sniffed from the request body so tests don't need
    to map by URL.
    """
    def responder(path, body):
        for fm, (status, xml) in reply_map.items():
            if f":{fm}>" in body or f":{fm}/" in body:
                return status, xml
        return 500, (
            '<?xml version="1.0"?><SOAP-ENV:Envelope '
            'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
            '<SOAP-ENV:Body><SOAP-ENV:Fault><faultcode>Server</faultcode>'
            '<faultstring>unmocked FM</faultstring></SOAP-ENV:Fault>'
            '</SOAP-ENV:Body></SOAP-ENV:Envelope>')
    return responder


# Canned response bodies for the four FMs we support in 3a.
_PING_OK = (
    '<?xml version="1.0"?><SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body><rfc:RFC_PING.Response '
    'xmlns:rfc="urn:sap-com:document:sap:rfc:functions"/>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>')

_USER_CREATE_OK = (
    '<?xml version="1.0"?><SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body><rfc:BAPI_USER_CREATE1.Response '
    'xmlns:rfc="urn:sap-com:document:sap:rfc:functions">'
    '<RETURN><item><TYPE>S</TYPE><ID>01</ID><NUMBER>105</NUMBER>'
    '<MESSAGE>created</MESSAGE></item></RETURN>'
    '</rfc:BAPI_USER_CREATE1.Response>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>')

_USER_CREATE_DUP = (
    '<?xml version="1.0"?><SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body><rfc:BAPI_USER_CREATE1.Response '
    'xmlns:rfc="urn:sap-com:document:sap:rfc:functions">'
    '<RETURN><item><TYPE>E</TYPE><ID>01</ID><NUMBER>102</NUMBER>'
    '<MESSAGE>User SAPMAP00 already exists</MESSAGE></item>'
    '</RETURN></rfc:BAPI_USER_CREATE1.Response>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>')

_PROFILES_OK = (
    '<?xml version="1.0"?><SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body><rfc:BAPI_USER_PROFILES_ASSIGN.Response '
    'xmlns:rfc="urn:sap-com:document:sap:rfc:functions">'
    '<RETURN><item><TYPE>S</TYPE><ID>01</ID><NUMBER>122</NUMBER>'
    '<MESSAGE>Profile changed</MESSAGE></item></RETURN>'
    '</rfc:BAPI_USER_PROFILES_ASSIGN.Response>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>')

_COMMIT_OK = (
    '<?xml version="1.0"?><SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body><rfc:BAPI_TRANSACTION_COMMIT.Response '
    'xmlns:rfc="urn:sap-com:document:sap:rfc:functions">'
    '<RETURN><TYPE></TYPE><ID></ID><NUMBER>000</NUMBER>'
    '<MESSAGE></MESSAGE></RETURN>'
    '</rfc:BAPI_TRANSACTION_COMMIT.Response>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>')

_AUTH_FAULT = (
    '<?xml version="1.0"?><SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body><SOAP-ENV:Fault><faultcode>Client</faultcode>'
    '<faultstring>RFC_AUTHORIZATION_FAILURE</faultstring>'
    '</SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>')

_USER_DELETE_OK = (
    '<?xml version="1.0"?><SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body>'
    '<rfc:BAPI_USER_DELETE.Response '
    'xmlns:rfc="urn:sap-com:document:sap:rfc:functions">'
    '<RETURN><item><TYPE>S</TYPE><ID>01</ID><NUMBER>123</NUMBER>'
    '<MESSAGE>User SAPMAP00 deleted</MESSAGE></item></RETURN>'
    '</rfc:BAPI_USER_DELETE.Response>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>')

_USER_DELETE_NOT_FOUND = (
    '<?xml version="1.0"?><SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body>'
    '<rfc:BAPI_USER_DELETE.Response '
    'xmlns:rfc="urn:sap-com:document:sap:rfc:functions">'
    '<RETURN><item><TYPE>E</TYPE><ID>01</ID><NUMBER>124</NUMBER>'
    '<MESSAGE>User SAPMAP00 does not exist</MESSAGE>'
    '</item></RETURN>'
    '</rfc:BAPI_USER_DELETE.Response>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>')


_USER_GET_DETAIL_SAP_ALL = (
    '<?xml version="1.0"?><SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body>'
    '<rfc:BAPI_USER_GET_DETAIL.Response '
    'xmlns:rfc="urn:sap-com:document:sap:rfc:functions">'
    '<PROFILES>'
    '<item><BAPIPROF>SAP_ALL</BAPIPROF></item>'
    '<item><BAPIPROF>SAP_NEW</BAPIPROF></item>'
    '</PROFILES>'
    '<ACTIVITYGROUPS>'
    '<item><AGR_NAME>SAP_BC_BASIS_ADMIN</AGR_NAME></item>'
    '</ACTIVITYGROUPS>'
    '<RETURN/>'
    '</rfc:BAPI_USER_GET_DETAIL.Response>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>')

_USER_GET_DETAIL_NO_SAP_ALL = (
    '<?xml version="1.0"?><SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body>'
    '<rfc:BAPI_USER_GET_DETAIL.Response '
    'xmlns:rfc="urn:sap-com:document:sap:rfc:functions">'
    '<PROFILES>'
    '<item><BAPIPROF>S_A.CUSTOMIZ</BAPIPROF></item>'
    '</PROFILES>'
    '<RETURN/>'
    '</rfc:BAPI_USER_GET_DETAIL.Response>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>')


# ---------------------------------------------------------------------------
# Wire format — auth header, endpoint, SOAPAction
# ---------------------------------------------------------------------------

def test_endpoint_includes_client_and_language():
    """The sap-client and sap-language query params are how the ICM
    routes the request to the right SAP client — drop them and you
    get logged into client 000 with language EN regardless of intent."""
    sess = SOAPRFCSession(
        host="h.example", port=8000, client="100",
        user="u", password="p", language="DE")
    assert "sap-client=100" in sess.endpoint
    assert "sap-language=DE" in sess.endpoint
    assert sess.endpoint.startswith("http://h.example:8000/sap/bc/soap/rfc")


def test_endpoint_uses_https_when_set():
    sess = SOAPRFCSession(
        host="h", port=443, client="000",
        user="u", password="p", https=True)
    assert sess.endpoint.startswith("https://h:443/")


def test_post_sends_basic_auth_header():
    mock = _MockSAP(_make_responder({"RFC_PING": (200, _PING_OK)}))
    try:
        sess = SOAPRFCSession(
            host="127.0.0.1", port=mock.port, client="001",
            user="SAPADM", password="siroj1978")
        sess.test_connection()
        req = mock.requests[0]
        # Authorization header — exact base64 of the user:pass pair
        expected = "Basic " + base64.b64encode(
            b"SAPADM:siroj1978").decode("ascii")
        assert req["headers"]["Authorization"] == expected
    finally:
        mock.stop()


def test_post_sends_soapaction_and_content_type():
    """SAP rejects calls with a non-empty SOAPAction or the wrong
    Content-Type (text/plain etc.) — these are the most common
    reasons a hand-rolled SOAP client gets a 400 from SAP."""
    mock = _MockSAP(_make_responder({"RFC_PING": (200, _PING_OK)}))
    try:
        sess = SOAPRFCSession(
            host="127.0.0.1", port=mock.port, client="000",
            user="u", password="p")
        sess.test_connection()
        # urllib normalizes header casing — look up case-insensitively
        headers_ci = {k.lower(): v for k, v in
                      mock.requests[0]["headers"].items()}
        assert headers_ci["soapaction"] == '""'
        assert headers_ci["content-type"].startswith("text/xml")
    finally:
        mock.stop()


def test_test_connection_returns_ok_on_ping_response():
    mock = _MockSAP(_make_responder({"RFC_PING": (200, _PING_OK)}))
    try:
        sess = SOAPRFCSession(
            host="127.0.0.1", port=mock.port, client="000",
            user="u", password="p")
        r = sess.test_connection()
        assert r["ok"] is True
        assert r["error"] == ""
    finally:
        mock.stop()


def test_test_connection_returns_error_on_auth_fault():
    """Auth failure arrives as a SOAP fault (HTTP 500 body).  Should
    surface as ok=False with the fault text, not raise."""
    mock = _MockSAP(_make_responder({"RFC_PING": (500, _AUTH_FAULT)}))
    try:
        sess = SOAPRFCSession(
            host="127.0.0.1", port=mock.port, client="000",
            user="u", password="bad")
        r = sess.test_connection()
        assert r["ok"] is False
        assert "RFC_AUTHORIZATION_FAILURE" in r["error"]
    finally:
        mock.stop()


def test_test_connection_returns_transport_error_on_dead_host():
    """When the host doesn't accept TCP at all (port closed), the
    SOAPRFCError is caught and surfaced as a structured result — the
    GUI thread should never see a bare exception bubble up."""
    # Bind a temporary socket to grab a port, then close it so it's
    # guaranteed unreachable for the duration of the test.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    dead_port = s.getsockname()[1]
    s.close()
    sess = SOAPRFCSession(
        host="127.0.0.1", port=dead_port, client="000",
        user="u", password="p", timeout=2.0)
    r = sess.test_connection()
    assert r["ok"] is False
    assert "transport" in r["error"].lower()


# ---------------------------------------------------------------------------
# High-level orchestration — create_user_with_sap_all
# ---------------------------------------------------------------------------

def test_create_user_with_sap_all_happy_path():
    """All four FMs succeed → ok=True, step=='done', details has 4 entries."""
    mock = _MockSAP(_make_responder({
        "RFC_PING":                 (200, _PING_OK),
        "BAPI_USER_CREATE1":        (200, _USER_CREATE_OK),
        "BAPI_USER_PROFILES_ASSIGN": (200, _PROFILES_OK),
        "BAPI_TRANSACTION_COMMIT":  (200, _COMMIT_OK),
    }))
    try:
        sess = SOAPRFCSession(
            host="127.0.0.1", port=mock.port, client="000",
            user="SAPADM", password="siroj1978")
        r = sess.create_user_with_sap_all("SAPMAP00", "Andinyougo123!")
        assert r["ok"] is True
        assert r["step"] == "done"
        # Each FM was called exactly once
        steps = [s for s, _ in r["details"]]
        assert steps == ["ping", "create", "profiles", "commit"]
        # Mock saw 4 requests total
        assert len(mock.requests) == 4
    finally:
        mock.stop()


def test_create_user_with_sap_all_continues_when_user_exists():
    """01/102 'user already exists' must NOT abort — we still want
    SAP_ALL on the existing user.  The flow continues into profile
    assignment and reports ok=True if the rest succeed."""
    mock = _MockSAP(_make_responder({
        "RFC_PING":                 (200, _PING_OK),
        "BAPI_USER_CREATE1":        (200, _USER_CREATE_DUP),
        "BAPI_USER_PROFILES_ASSIGN": (200, _PROFILES_OK),
        "BAPI_TRANSACTION_COMMIT":  (200, _COMMIT_OK),
    }))
    try:
        sess = SOAPRFCSession(
            host="127.0.0.1", port=mock.port, client="000",
            user="u", password="p")
        r = sess.create_user_with_sap_all("SAPMAP00", "x")
        assert r["ok"] is True
        assert r["step"] == "done"
        # Details still captures the create attempt with its error
        create_step = dict(r["details"])["create"]
        assert "already exists" in create_step["error"].lower()
    finally:
        mock.stop()


def test_create_user_with_sap_all_aborts_on_ping_failure():
    """If RFC_PING fails (bad creds), we don't proceed to CREATE — we
    don't want to risk creating a partial user with the wrong account."""
    mock = _MockSAP(_make_responder({"RFC_PING": (500, _AUTH_FAULT)}))
    try:
        sess = SOAPRFCSession(
            host="127.0.0.1", port=mock.port, client="000",
            user="u", password="bad")
        r = sess.create_user_with_sap_all("SAPMAP00", "x")
        assert r["ok"] is False
        assert r["step"] == "ping"
        # Only one request was made — no create, profiles, commit
        assert len(mock.requests) == 1
    finally:
        mock.stop()


def test_create_user_with_sap_all_aborts_on_profile_failure():
    """User created but SAP_ALL assignment rejected (no S_USER_GRP) —
    surface step='profiles' so the GUI can show a useful error."""
    mock = _MockSAP(_make_responder({
        "RFC_PING":                 (200, _PING_OK),
        "BAPI_USER_CREATE1":        (200, _USER_CREATE_OK),
        "BAPI_USER_PROFILES_ASSIGN": (500, _AUTH_FAULT),
        "BAPI_TRANSACTION_COMMIT":  (200, _COMMIT_OK),
    }))
    try:
        sess = SOAPRFCSession(
            host="127.0.0.1", port=mock.port, client="000",
            user="u", password="p")
        r = sess.create_user_with_sap_all("SAPMAP00", "x")
        assert r["ok"] is False
        assert r["step"] == "profiles"
        # Commit should NOT have been called after a failed assign
        steps = [s for s, _ in r["details"]]
        assert "commit" not in steps
    finally:
        mock.stop()


# ---------------------------------------------------------------------------
# delete_user_via_soap — drop-in for sapmap_rfc.delete_user
# ---------------------------------------------------------------------------

def test_delete_user_via_soap_happy_path():
    """Ping + delete + commit must all succeed → success=True with the
    same {success, message, username} dict shape the GUI cleanup loop
    branches on."""
    mock = _MockSAP(_make_responder({
        "RFC_PING":                (200, _PING_OK),
        "BAPI_USER_DELETE":        (200, _USER_DELETE_OK),
        "BAPI_TRANSACTION_COMMIT": (200, _COMMIT_OK),
    }))
    try:
        r = delete_user_via_soap(
            host="127.0.0.1", port=mock.port, client="000",
            user="SAPADM", password="siroj1978",
            victim_username="SAPMAP00")
        assert r == {
            "success": True,
            "message": "User SAPMAP00 deleted via SOAP-RFC",
            "username": "SAPMAP00",
        }
    finally:
        mock.stop()


def test_delete_user_via_soap_treats_not_exists_as_success():
    """BAPI error 01/124 'User does not exist' means the goal state
    (absent on target) is ALREADY satisfied.  Cleanup should report
    success — telling the operator it failed when the user simply
    wasn't there leads to false-positive 'cleanup failed' badges."""
    mock = _MockSAP(_make_responder({
        "RFC_PING":                (200, _PING_OK),
        "BAPI_USER_DELETE":        (200, _USER_DELETE_NOT_FOUND),
        "BAPI_TRANSACTION_COMMIT": (200, _COMMIT_OK),
    }))
    try:
        r = delete_user_via_soap(
            host="127.0.0.1", port=mock.port, client="000",
            user="u", password="p", victim_username="SAPMAP00")
        assert r["success"] is True
    finally:
        mock.stop()


def test_delete_user_via_soap_aborts_on_bad_creds():
    """RFC_PING failing (bad password etc.) must not proceed into
    BAPI_USER_DELETE — we'd lock the SAP user out by hitting bad-
    password thresholds on what should have been a single failed
    auth."""
    mock = _MockSAP(_make_responder({"RFC_PING": (500, _AUTH_FAULT)}))
    try:
        r = delete_user_via_soap(
            host="127.0.0.1", port=mock.port, client="000",
            user="u", password="bad", victim_username="SAPMAP00")
        assert r["success"] is False
        assert "RFC_PING failed" in r["message"]
        # Mock saw only the ping — no DELETE attempted
        assert len(mock.requests) == 1
    finally:
        mock.stop()


# ---------------------------------------------------------------------------
# create_user_via_soap — drop-in for sapmap_rfc.create_user_via_bapi
# ---------------------------------------------------------------------------

def test_create_user_via_soap_returns_bapi_compatible_shape_on_success():
    """propagate_from_node already speaks the {success, message,
    username} dict from create_user_via_bapi.  create_user_via_soap
    must return the exact same shape so the call sites can swap the
    two transports without other changes."""
    mock = _MockSAP(_make_responder({
        "RFC_PING":                 (200, _PING_OK),
        "BAPI_USER_CREATE1":        (200, _USER_CREATE_OK),
        "BAPI_USER_PROFILES_ASSIGN": (200, _PROFILES_OK),
        "BAPI_TRANSACTION_COMMIT":  (200, _COMMIT_OK),
    }))
    try:
        r = create_user_via_soap(
            host="127.0.0.1", port=mock.port, client="000",
            user="SAPADM", password="siroj1978",
            new_username="SAPMAP00", new_password="Andinyougo123!",
        )
        assert r == {
            "success": True,
            "message": ("User SAPMAP00 created with SAP_ALL "
                        "via SOAP-RFC"),
            "username": "SAPMAP00",
        }
    finally:
        mock.stop()


def test_get_user_profiles_extracts_sap_all_flag():
    """get_user_profiles must distil PROFILES/ACTIVITYGROUPS into the
    same shape as the pyrfc-based get_direct_user_profiles helper:
    {ok, profiles, roles, has_sap_all, error}.  Caller flips
    conn.has_sap_all directly from has_sap_all, so the dict key name
    matters."""
    mock = _MockSAP(_make_responder({
        "BAPI_USER_GET_DETAIL": (200, _USER_GET_DETAIL_SAP_ALL),
    }))
    try:
        sess = SOAPRFCSession(
            host="127.0.0.1", port=mock.port, client="000",
            user="SAPADM", password="siroj1978")
        r = sess.get_user_profiles("SAPADM")
        assert r["ok"] is True
        assert r["error"] == ""
        assert r["profiles"] == ["SAP_ALL", "SAP_NEW"]
        assert r["roles"] == ["SAP_BC_BASIS_ADMIN"]
        assert r["has_sap_all"] is True
    finally:
        mock.stop()


def test_get_user_profiles_returns_false_when_no_sap_all():
    """User with profiles but not SAP_ALL must report has_sap_all=False
    — the create-remote-user button only fires on the SAP_ALL branch
    (or the still-shippable click-time-check branch)."""
    mock = _MockSAP(_make_responder({
        "BAPI_USER_GET_DETAIL": (200, _USER_GET_DETAIL_NO_SAP_ALL),
    }))
    try:
        sess = SOAPRFCSession(
            host="127.0.0.1", port=mock.port, client="000",
            user="u", password="p")
        r = sess.get_user_profiles("U")
        assert r["ok"] is True
        assert r["profiles"] == ["S_A.CUSTOMIZ"]
        assert r["has_sap_all"] is False
    finally:
        mock.stop()


def test_get_user_profiles_handles_auth_rejection_gracefully():
    """If the calling user lacks S_USER_GRP, the BAPI rejects with an
    RFC_AUTHORIZATION_FAILURE — must come back as ok=False with the
    fault text, not raise.  Click-time check then becomes the only
    path, but we never crash the Test Connection flow."""
    mock = _MockSAP(_make_responder({
        "BAPI_USER_GET_DETAIL": (500, _AUTH_FAULT),
    }))
    try:
        sess = SOAPRFCSession(
            host="127.0.0.1", port=mock.port, client="000",
            user="u", password="p")
        r = sess.get_user_profiles("U")
        assert r["ok"] is False
        assert r["has_sap_all"] is False
        assert r["profiles"] == []
        assert "RFC_AUTHORIZATION_FAILURE" in r["error"]
    finally:
        mock.stop()


# ---------------------------------------------------------------------------
# Phase 3b: SXPG OS exec, RFC_READ_TABLE, RFC_GET_SYSTEM_INFO
# ---------------------------------------------------------------------------

_SXPG_OK_TWO_LINES = (
    '<?xml version="1.0"?><SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body>'
    '<rfc:SXPG_STEP_XPG_START.Response '
    'xmlns:rfc="urn:sap-com:document:sap:rfc:functions">'
    '<STATUS>O</STATUS>'
    '<LOG>'
    '<item><MESSAGE>line one</MESSAGE></item>'
    '<item><MESSAGE>line two</MESSAGE></item>'
    '</LOG>'
    '</rfc:SXPG_STEP_XPG_START.Response>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>')

_SXPG_MXROW_REJECTED = (
    '<?xml version="1.0"?><SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body>'
    '<SOAP-ENV:Fault><faultcode>Client</faultcode>'
    '<faultstring>RFC_INVALID_PARAMETER: '
    'Field MXROW unknown</faultstring></SOAP-ENV:Fault>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>')


def test_execute_os_command_collects_log_lines():
    """SXPG output lives in the LOG table, one MESSAGE per line.
    execute_os_command must aggregate them into result["output"]."""
    mock = _MockSAP(_make_responder({
        "SXPG_STEP_XPG_START": (200, _SXPG_OK_TWO_LINES),
    }))
    try:
        sess = SOAPRFCSession(
            host="127.0.0.1", port=mock.port, client="000",
            user="u", password="p")
        r = sess.execute_os_command("/bin/sh", "-c whoami")
        assert r["success"] is True
        assert r["output"] == ["line one", "line two"]
        assert r["error"] == ""
    finally:
        mock.stop()


def test_execute_os_command_falls_back_when_mxrow_rejected():
    """Older kernels reject MXROW.  Session must auto-retry with the
    no-mxrow variant — we'd lose every output line on legacy systems
    otherwise."""
    # Track which envelope was sent
    bodies_seen = []

    def responder(path, body):
        bodies_seen.append(body)
        if len(bodies_seen) == 1:
            # First call: pretend kernel rejected MXROW
            return 500, _SXPG_MXROW_REJECTED
        # Second call: succeed
        return 200, _SXPG_OK_TWO_LINES

    mock = _MockSAP(responder)
    try:
        sess = SOAPRFCSession(
            host="127.0.0.1", port=mock.port, client="000",
            user="u", password="p")
        r = sess.execute_os_command("/bin/sh", "-c whoami")
        assert r["success"] is True
        assert r["output"] == ["line one", "line two"]
        assert len(bodies_seen) == 2
        # First envelope had MXROW, second didn't
        assert "<MXROW>" in bodies_seen[0]
        assert "<MXROW>" not in bodies_seen[1]
    finally:
        mock.stop()


_READ_TABLE_T000_TWO_CLIENTS = (
    '<?xml version="1.0"?><SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body>'
    '<rfc:RFC_READ_TABLE.Response '
    'xmlns:rfc="urn:sap-com:document:sap:rfc:functions">'
    '<FIELDS>'
    '<item><FIELDNAME>MANDT</FIELDNAME><OFFSET>0</OFFSET>'
    '<LENGTH>3</LENGTH><TYPE>C</TYPE><FIELDTEXT>Client</FIELDTEXT>'
    '</item>'
    '<item><FIELDNAME>CCCATEGORY</FIELDNAME><OFFSET>3</OFFSET>'
    '<LENGTH>1</LENGTH><TYPE>C</TYPE><FIELDTEXT>Role</FIELDTEXT>'
    '</item>'
    '</FIELDS>'
    '<DATA>'
    '<item><WA>000|S</WA></item>'
    '<item><WA>001|P</WA></item>'
    '</DATA>'
    '</rfc:RFC_READ_TABLE.Response>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>')


def test_read_table_returns_field_keyed_dicts():
    """read_table must hide the WA-string format from callers — the
    convenience of dict[FIELDNAME] is the whole point."""
    mock = _MockSAP(_make_responder({
        "RFC_READ_TABLE": (200, _READ_TABLE_T000_TWO_CLIENTS),
    }))
    try:
        sess = SOAPRFCSession(
            host="127.0.0.1", port=mock.port, client="000",
            user="u", password="p")
        r = sess.read_table("T000", fields=["MANDT", "CCCATEGORY"])
        assert r["ok"] is True
        assert r["fields"] == ["MANDT", "CCCATEGORY"]
        assert r["rows"] == [
            {"MANDT": "000", "CCCATEGORY": "S"},
            {"MANDT": "001", "CCCATEGORY": "P"},
        ]
    finally:
        mock.stop()


def test_read_table_handles_auth_rejection():
    """RFC_READ_TABLE on certain tables requires S_TABU_DIS — when the
    caller lacks it, the BAPI returns an exception (not an empty DATA
    table).  Session must surface it as ok=False, not crash on missing
    fields."""
    mock = _MockSAP(_make_responder({
        "RFC_READ_TABLE": (500, _AUTH_FAULT),
    }))
    try:
        sess = SOAPRFCSession(
            host="127.0.0.1", port=mock.port, client="000",
            user="u", password="p")
        r = sess.read_table("USR02", fields=["BNAME"])
        assert r["ok"] is False
        assert "RFC_AUTHORIZATION_FAILURE" in r["error"]
        assert r["rows"] == []
    finally:
        mock.stop()


_GET_SYSTEM_INFO_OK = (
    '<?xml version="1.0"?><SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body>'
    '<rfc:RFC_GET_SYSTEM_INFO.Response '
    'xmlns:rfc="urn:sap-com:document:sap:rfc:functions">'
    '<RFCSI_EXPORT>'
    '<RFCSYSID>W74</RFCSYSID>'
    '<RFCSAPRL>754</RFCSAPRL>'
    '<RFCKERNRL>742</RFCKERNRL>'
    '<RFCOPSYS>Windows NT</RFCOPSYS>'
    '<RFCDBSYS>ADABAS D</RFCDBSYS>'
    '<RFCDBHOST>WINWAS740</RFCDBHOST>'
    '<RFCHOST>WINWAS74</RFCHOST>'
    '<RFCIPADDR>192.168.2.29</RFCIPADDR>'
    '</RFCSI_EXPORT>'
    '</rfc:RFC_GET_SYSTEM_INFO.Response>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>')


_INSTALL_AND_RUN_OK = (
    '<?xml version="1.0"?><SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body>'
    '<rfc:RFC_ABAP_INSTALL_AND_RUN.Response '
    'xmlns:rfc="urn:sap-com:document:sap:rfc:functions">'
    '<WRITES>'
    '<item><ZEILE>~~~I 000 /RFC/MY_DEST</ZEILE></item>'
    '<item><ZEILE>~~~A 4F5051525354</ZEILE></item>'
    '<item><ZEILE>~~~B 5556575859</ZEILE></item>'
    '<item><ZEILE>~~~TOTAL: 1</ZEILE></item>'
    '</WRITES>'
    '</rfc:RFC_ABAP_INSTALL_AND_RUN.Response>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>')


def test_install_and_run_collects_writes_output():
    """ABAP WRITE output comes back in the WRITES table; each row's
    ZEILE / LINE / WA carries one line.  The session helper aggregates
    them into output[] so call sites can grep for ~~~I / ~~~A markers
    same as the pyrfc path."""
    mock = _MockSAP(_make_responder({
        "RFC_ABAP_INSTALL_AND_RUN": (200, _INSTALL_AND_RUN_OK),
    }))
    try:
        sess = SOAPRFCSession(
            host="127.0.0.1", port=mock.port, client="000",
            user="u", password="p")
        r = sess.install_and_run(
            ["REPORT z.", "WRITE 'hi'."])
        assert r["success"] is True
        assert r["fm_name"] == "RFC_ABAP_INSTALL_AND_RUN"
        assert r["output"] == [
            "~~~I 000 /RFC/MY_DEST",
            "~~~A 4F5051525354",
            "~~~B 5556575859",
            "~~~TOTAL: 1",
        ]
    finally:
        mock.stop()


def test_install_and_run_surfaces_auth_failure_in_shape():
    """No S_C_FUNCT for ABAP exec → SOAP fault; result keeps the
    {success, output, error, fm_name} shape so callers don't have to
    special-case the SOAP path's failure mode."""
    mock = _MockSAP(_make_responder({
        "RFC_ABAP_INSTALL_AND_RUN": (500, _AUTH_FAULT),
    }))
    try:
        sess = SOAPRFCSession(
            host="127.0.0.1", port=mock.port, client="000",
            user="u", password="p")
        r = sess.install_and_run(["REPORT z."])
        assert r["success"] is False
        assert "RFC_AUTHORIZATION_FAILURE" in r["error"]
        assert r["output"] == []
    finally:
        mock.stop()


_DEST_CHECK_OK = (
    '<?xml version="1.0"?><SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body>'
    '<rfc:DEST_CHECK_CONNECTION.Response '
    'xmlns:rfc="urn:sap-com:document:sap:rfc:functions">'
    '<CONNECTION_TEST_RESULT></CONNECTION_TEST_RESULT>'
    '<AUTHORIZATION_TEST_RESULT></AUTHORIZATION_TEST_RESULT>'
    '<CONNECTION_ERROR_TEXT></CONNECTION_ERROR_TEXT>'
    '<CONNECTION_PROPERTIES>'
    '<SYSID>S4H</SYSID>'
    '<RFCHOST>s4hanadev</RFCHOST>'
    '<RFCDEST>S4HANADEV_S4H_00</RFCDEST>'
    '</CONNECTION_PROPERTIES>'
    '</rfc:DEST_CHECK_CONNECTION.Response>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>')


_DEST_CHECK_FAIL = (
    '<?xml version="1.0"?><SOAP-ENV:Envelope '
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP-ENV:Body>'
    '<rfc:DEST_CHECK_CONNECTION.Response '
    'xmlns:rfc="urn:sap-com:document:sap:rfc:functions">'
    '<CONNECTION_TEST_RESULT>E</CONNECTION_TEST_RESULT>'
    '<AUTHORIZATION_TEST_RESULT>X</AUTHORIZATION_TEST_RESULT>'
    '<CONNECTION_ERROR_TEXT>partner not reached</CONNECTION_ERROR_TEXT>'
    '</rfc:DEST_CHECK_CONNECTION.Response>'
    '</SOAP-ENV:Body></SOAP-ENV:Envelope>')


def test_dest_check_connection_success_extracts_sid_and_instance():
    """Ping OK → result shape matches the pyrfc path's shape exactly
    so the GUI Retrieve loop can swap transports transparently.  SID
    and instance (from RFCDEST suffix) drive node-mapping downstream."""
    mock = _MockSAP(_make_responder({
        "DEST_CHECK_CONNECTION": (200, _DEST_CHECK_OK),
    }))
    try:
        sess = SOAPRFCSession(
            host="127.0.0.1", port=mock.port, client="000",
            user="u", password="p")
        r = sess.dest_check_connection("S4H_SVC")
        assert r["ping_ok"] is True
        assert r["logon_ok"] is True
        assert r["remote_sid"] == "S4H"
        assert r["remote_hostname"] == "s4hanadev"
        assert r["remote_instance_nr"] == "00"   # from _NN suffix
        assert r["error"] == ""
    finally:
        mock.stop()


def test_dest_check_connection_failure_surfaces_error_text():
    """Non-empty CONNECTION_TEST_RESULT = ping failed; the actual
    error text comes from CONNECTION_ERROR_TEXT.  Caller uses this
    to decide whether to skip the destination or treat it as alive."""
    mock = _MockSAP(_make_responder({
        "DEST_CHECK_CONNECTION": (200, _DEST_CHECK_FAIL),
    }))
    try:
        sess = SOAPRFCSession(
            host="127.0.0.1", port=mock.port, client="000",
            user="u", password="p")
        r = sess.dest_check_connection("DEAD_DEST")
        assert r["ping_ok"] is False
        assert "partner not reached" in r["ping_message"]
    finally:
        mock.stop()


def test_get_system_info_unpacks_rfcsi_export():
    """The interesting fields all live inside RFCSI_EXPORT.  Caller
    gets a flat dict so populating node fields is one assignment per
    column rather than nested traversal."""
    mock = _MockSAP(_make_responder({
        "RFC_GET_SYSTEM_INFO": (200, _GET_SYSTEM_INFO_OK),
    }))
    try:
        sess = SOAPRFCSession(
            host="127.0.0.1", port=mock.port, client="000",
            user="u", password="p")
        r = sess.get_system_info()
        assert r["ok"] is True
        info = r["info"]
        assert info["RFCSYSID"] == "W74"
        assert info["RFCSAPRL"] == "754"
        assert info["RFCKERNRL"] == "742"
        assert info["RFCOPSYS"] == "Windows NT"
        assert info["RFCDBSYS"] == "ADABAS D"
        assert info["RFCIPADDR"] == "192.168.2.29"
    finally:
        mock.stop()


def test_create_user_via_soap_returns_bapi_compatible_shape_on_failure():
    """Same dict shape, success=False, message names the failing step."""
    mock = _MockSAP(_make_responder({"RFC_PING": (500, _AUTH_FAULT)}))
    try:
        r = create_user_via_soap(
            host="127.0.0.1", port=mock.port, client="000",
            user="SAPADM", password="WRONG",
            new_username="SAPMAP00", new_password="x",
        )
        assert r["success"] is False
        assert r["username"] == "SAPMAP00"
        assert "step=ping" in r["message"]
        assert "RFC_AUTHORIZATION_FAILURE" in r["message"]
    finally:
        mock.stop()
