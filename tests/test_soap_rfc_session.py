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
    SOAPRFCError, SOAPRFCSession, create_user_via_soap,
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
