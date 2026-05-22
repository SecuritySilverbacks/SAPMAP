#!/usr/bin/env python3
"""Regression test: the Web Dispatcher fingerprint must NOT flag a
generic HTTP service that happens to return 401/403 for
/sap/wdisp/admin as a SAP WD.

Operator-reported: W1B on 10.10.1.27:80 plotted as WEB_DISPATCHER
but was actually a non-SAP service.  Root cause: the fingerprint
treated ANY 401/403 (without ICMENOSERVERFOUND/SYSTEMFOUND) on the
admin path as "definitive" WD evidence — but a generic HTTP server
with global basic auth, or one that returns 403 for unknown paths,
would match the same way.

Fix: require an SAP-specific corroborating marker — WWW-Authenticate
realm mentioning "WEB ADMIN" / "SAP*", OR an x-sap-icm-err-id
header anywhere, OR a Server header containing "SAP".
"""
from __future__ import annotations

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "discovery"))


def _wd_source():
    """Read the fingerprint_web_dispatcher source so we can assert
    structural invariants without spinning up a TCP server."""
    path = os.path.join(os.path.dirname(__file__), "..", "modules",
                         "discovery", "sapmap_scanner.py")
    with open(path, encoding="utf-8") as f:
        src = f.read()
    m = re.search(r"def fingerprint_web_dispatcher\(.*?\n(?=def \w)",
                  src, re.DOTALL)
    assert m, "fingerprint_web_dispatcher not found"
    return m.group(0)


def test_wd_fingerprint_requires_sap_marker_for_401_403():
    """A 401/403 response on /sap/wdisp/admin must NOT promote to
    is_wd=True unless an SAP-specific marker is also present
    (realm, ICM header, or SAP Server banner)."""
    body = _wd_source()
    # The promote-to-WD gate must require a sap_marker variable.
    assert "sap_marker" in body, (
        "Promotion of 401/403 to is_wd must consult a sap_marker — "
        "without it, generic auth-protected services false-positive")
    # The realm regex must look for 'WEB ADMIN' or 'SAP'.
    realm_match = re.search(
        r"WWW-Authenticate.*?WEB\\s\+ADMIN|SAP", body, re.DOTALL)
    assert realm_match, (
        "WD realm check must specifically test for the WD admin "
        "realm 'WEB ADMIN' (or any SAP-prefixed realm) instead of "
        "trusting any Basic-realm response")


def test_wd_fingerprint_check_not_just_status():
    """The 401/403 gate must combine status check with sap_marker —
    not be a standalone status-only branch."""
    body = _wd_source()
    # Find the if-block that sets is_wd around 401/403.
    m = re.search(
        r"if\s*\(?\s*probe_status\s+in\s+\(401,\s*403\).*?out\[\"is_wd\"\]\s*=\s*True",
        body, re.DOTALL)
    assert m, "401/403 → is_wd promotion block not found"
    gate = m.group(0)
    # The gate must reference sap_marker.
    assert "sap_marker" in gate, (
        "401/403 promotion must include sap_marker in its condition — "
        f"current gate: {gate[:200]}...")


def test_wd_fingerprint_final_gate_demotes_unconfirmed():
    """The final gate must demote is_wd=True back to False when the
    only matching pattern was a softer one (error_page_comment /
    wdisp_admin_redirect) AND no x-sap-icm-err-id appeared anywhere
    across the probe session.  server_banner is the only pattern
    allowed to stand alone (it literally identifies the binary)."""
    body = _wd_source()
    assert "server_banner" in body, (
        "server_banner pattern must be referenced in the final gate")
    # The gate must clear is_wd when not server_banner AND no sap-icm.
    # Look for the demote block.
    m = re.search(
        r'if\s+out\["is_wd"\]\s+and\s+out\["evidence"\]\s*!=\s*"server_banner".*?'
        r'out\["is_wd"\]\s*=\s*False',
        body, re.DOTALL)
    assert m, (
        "Final demotion gate not found — softer patterns must require "
        "is_sap_icm corroboration before is_wd=True survives")


# ---------------------------------------------------------------------------
# Behavioural: spin up a fake non-SAP HTTP server and verify is_wd=False
# ---------------------------------------------------------------------------

import socket
import threading


class _FakeServer:
    """Minimal non-SAP HTTP server for fingerprint testing.

    `response_for(path)` returns the raw HTTP/1.0 response bytes for
    that request path — subclasses override to simulate different
    server behaviours.
    """

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(5)
        self.sock.settimeout(2)
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                c, _ = self.sock.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            try:
                c.settimeout(2)
                data = c.recv(4096)
                if not data:
                    c.close(); continue
                # Parse request line
                first_line = data.split(b"\r\n", 1)[0].decode(
                    "iso-8859-1", "replace")
                path = "/"
                parts = first_line.split()
                if len(parts) >= 2:
                    path = parts[1]
                c.sendall(self.response_for(path))
            except Exception:
                pass
            try:
                c.close()
            except Exception:
                pass

    def response_for(self, path: str) -> bytes:
        # Override in subclasses
        return (b"HTTP/1.0 200 OK\r\n"
                b"Server: TestServer/1.0\r\n"
                b"Content-Length: 2\r\n\r\nOK")

    def close(self):
        self._stop.set()
        try:
            self.sock.close()
        except Exception:
            pass


def _call_fingerprint(port):
    from sapmap_scanner import fingerprint_web_dispatcher
    return fingerprint_web_dispatcher("127.0.0.1", port,
                                        https=False, timeout=2)


def test_non_sap_server_200_ok_not_classified_as_wd():
    """A vanilla web server returning 200 OK on every path, no
    SAP headers, no SAP markers → is_wd must be False."""
    srv = _FakeServer()
    try:
        result = _call_fingerprint(srv.port)
    finally:
        srv.close()
    assert result["is_wd"] is False, (
        f"Vanilla 200-OK server should not be flagged as WD; "
        f"got {result}")
    assert result["is_sap_icm"] is False, (
        f"No SAP markers expected; got is_sap_icm=True ({result})")


def test_non_sap_server_with_basic_auth_not_classified_as_wd():
    """A web server with global basic auth returning 401 on every
    path with a generic realm → is_wd must be False (the operator-
    reported W1B regression)."""

    class _AuthServer(_FakeServer):
        def response_for(self, path):
            return (b"HTTP/1.0 401 Unauthorized\r\n"
                    b"Server: nginx/1.20\r\n"
                    b'WWW-Authenticate: Basic realm="Restricted"\r\n'
                    b"Content-Length: 0\r\n\r\n")

    srv = _AuthServer()
    try:
        result = _call_fingerprint(srv.port)
    finally:
        srv.close()
    assert result["is_wd"] is False, (
        f"Generic-auth server should not be flagged as WD; "
        f"got {result}")


def test_non_sap_server_with_sap_text_in_body_demoted_without_icm_header():
    """Even if the response body happens to contain the literal
    text 'SAP Web Dispatcher' (e.g. a documentation page, a leaked
    error message), without an x-sap-icm-err-id header anywhere in
    the probe session the final gate must demote is_wd to False."""

    class _SAPTextInBodyServer(_FakeServer):
        def response_for(self, path):
            body = (b"<html><body>This error page was generated by SAP "
                    b"Web Dispatcher (just kidding, it's nginx)</body></html>")
            return (b"HTTP/1.0 200 OK\r\n"
                    b"Server: nginx/1.20\r\n"
                    b"Content-Type: text/html\r\n"
                    b"Content-Length: " + str(len(body)).encode() +
                    b"\r\n\r\n" + body)

    srv = _SAPTextInBodyServer()
    try:
        result = _call_fingerprint(srv.port)
    finally:
        srv.close()
    assert result["is_wd"] is False, (
        f"Server with 'SAP Web Dispatcher' in body but no ICM header "
        f"must be demoted by the final gate; got {result}")


def test_real_wd_with_server_banner_still_detected():
    """A server emitting 'Server: SAP Web Dispatcher 7.53' on / must
    be detected even without an ICM header — server_banner is the
    one pattern allowed to stand alone."""

    class _RealWDServer(_FakeServer):
        def response_for(self, path):
            return (b"HTTP/1.0 200 OK\r\n"
                    b"Server: SAP Web Dispatcher 7.53.0\r\n"
                    b"Content-Length: 5\r\n\r\nhello")

    srv = _RealWDServer()
    try:
        result = _call_fingerprint(srv.port)
    finally:
        srv.close()
    assert result["is_wd"] is True, (
        f"Real WD with server_banner must be detected even without "
        f"ICM corroboration (banner is self-sufficient); got {result}")
    assert result["evidence"] == "server_banner"


def test_real_wd_with_icm_err_on_bogus_path_detected():
    """A WD that suppresses the Server header but emits
    x-sap-icm-err-id: ICMENOSERVERFOUND on the bogus-path probe
    must still be detected via icm_no_server_err pattern."""

    class _HardenedWDServer(_FakeServer):
        def response_for(self, path):
            if "sapmap-no-such-path" in path:
                return (b"HTTP/1.0 503 Service Unavailable\r\n"
                        b"x-sap-icm-err-id: ICMENOSERVERFOUND\r\n"
                        b"Content-Length: 0\r\n\r\n")
            return (b"HTTP/1.0 200 OK\r\n"
                    b"Content-Length: 0\r\n\r\n")

    srv = _HardenedWDServer()
    try:
        result = _call_fingerprint(srv.port)
    finally:
        srv.close()
    assert result["is_wd"] is True, (
        f"Hardened WD that suppresses Server header but emits "
        f"x-sap-icm-err-id on bogus path must still be detected; "
        f"got {result}")
    assert result["is_sap_icm"] is True


def test_wd_fingerprint_realm_regex_excludes_generic_realms():
    """The realm regex must be specific to WEB ADMIN or SAP* — must
    not accept generic realms like 'Restricted', 'Login', 'protected'.
    The literal can be split across multiple adjacent string literals,
    so we search the whole function body."""
    body = _wd_source()
    # The m_wd_realm assignment must exist.
    assert "m_wd_realm" in body, (
        "WD realm regex (m_wd_realm) not found in fingerprint function")
    # The combined pattern must reference WEB ADMIN and SAP — and
    # must NOT be a bare 'Basic\\s+realm=' catch-all.
    realm_assign_idx = body.index("m_wd_realm")
    # Look ahead ~300 chars (the regex literal + concat strings sit
    # right after the assignment).
    window = body[realm_assign_idx:realm_assign_idx + 400]
    assert "WEB" in window and "ADMIN" in window, (
        f"WD realm regex must include 'WEB ADMIN' — got window: "
        f"{window[:200]}...")
    assert "SAP" in window, (
        f"WD realm regex should also accept SAP-prefixed realms — "
        f"got window: {window[:200]}...")
