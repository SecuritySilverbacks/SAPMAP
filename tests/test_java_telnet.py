"""Tests for sap_java_telnet — SAP AS-Java telnet console client.

All tests are offline.  Socket I/O is stubbed via a FakeSocket that
scripts recv() responses and records what was sent.
"""

import base64
import socket
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import sap_java_telnet as tel


# ---------------------------------------------------------------------------
# default_port_for_instance
# ---------------------------------------------------------------------------

class TestDefaultPort:

    def test_instance_0(self):
        assert tel.default_port_for_instance(0) == 50008

    def test_instance_1(self):
        assert tel.default_port_for_instance(1) == 50108

    def test_instance_99(self):
        assert tel.default_port_for_instance(99) == 59908


# ---------------------------------------------------------------------------
# _chunked_b64
# ---------------------------------------------------------------------------

class TestChunkedB64:

    def test_yields_all_bytes(self):
        data = b"A" * 350
        chunks = list(tel._chunked_b64(data, chunk_size=50))
        joined = "".join(c for _, c in chunks)
        assert base64.b64decode(joined) == data

    def test_chunk_size_respected(self):
        chunks = list(tel._chunked_b64(b"x" * 100, chunk_size=16))
        # Every chunk except possibly the last should be <=16 chars
        for i, c in chunks[:-1]:
            assert len(c) == 16

    def test_index_is_zero_based_and_sequential(self):
        chunks = list(tel._chunked_b64(b"y" * 30, chunk_size=5))
        idxs = [i for i, _ in chunks]
        assert idxs == list(range(len(chunks)))


# ---------------------------------------------------------------------------
# probe_port
# ---------------------------------------------------------------------------

class TestProbePort:

    def test_open_port_returns_true(self, monkeypatch):
        class _FakeSock:
            def __enter__(self): return self
            def __exit__(self, *a): pass
        monkeypatch.setattr(socket, "create_connection",
                             lambda *a, **k: _FakeSock())
        assert tel.probe_port("h", 50008) is True

    def test_refused_returns_false(self, monkeypatch):
        def _raise(*a, **k):
            raise ConnectionRefusedError("nope")
        monkeypatch.setattr(socket, "create_connection", _raise)
        assert tel.probe_port("h", 50008) is False

    def test_timeout_returns_false(self, monkeypatch):
        def _raise(*a, **k):
            raise TimeoutError("slow")
        monkeypatch.setattr(socket, "create_connection", _raise)
        assert tel.probe_port("h", 50008) is False


# ---------------------------------------------------------------------------
# find_java_admin_user — preference ordering in created_users
# ---------------------------------------------------------------------------

class _FakeUser:
    def __init__(self, method, password="pw", username="SAPMAP00"):
        self.method = method
        self.username = username
        self.password = password


class _FakeNode:
    def __init__(self, users):
        self.created_users = users


class TestFindJavaAdmin:

    def test_empty_returns_blanks(self):
        n = _FakeNode([])
        assert tel.find_java_admin_user(n) == ("", "")

    def test_prefers_java_recon_over_java_cve(self):
        n = _FakeNode([
            _FakeUser("java_cve_31324", "pwA", "USR_A"),
            _FakeUser("java_recon",    "pwB", "USR_B"),
        ])
        u, p = tel.find_java_admin_user(n)
        assert u == "USR_B" and p == "pwB"

    def test_falls_back_to_any_user_with_password(self):
        n = _FakeNode([
            _FakeUser("bapi_create", "pwZ", "USR_Z"),
        ])
        u, p = tel.find_java_admin_user(n)
        assert u == "USR_Z" and p == "pwZ"

    def test_skips_users_without_password(self):
        n = _FakeNode([
            _FakeUser("java_recon", "", "NOPW"),
            _FakeUser("java_cve_31324", "pwK", "OK"),
        ])
        u, p = tel.find_java_admin_user(n)
        # Preferred method 'java_recon' found but no password → falls
        # through to 'java_cve_31324' which has one.
        assert u == "OK" and p == "pwK"


# ---------------------------------------------------------------------------
# SAPTelnetClient — scripted FakeSocket-backed session
# ---------------------------------------------------------------------------

class _FakeSocket:
    """Scripted recv/send telnet peer.

    Feed it a list of byte payloads; each recv() call pops one.  Sent
    bytes are captured in ``sent`` (bytes).  settimeout is a no-op.
    """

    def __init__(self, script):
        self._script = list(script)
        self.sent = b""
        self._closed = False

    def settimeout(self, t):  # noqa: D401 - stub
        pass

    def recv(self, n):
        if not self._script:
            raise socket.timeout("end of script")
        return self._script.pop(0)

    def sendall(self, data):
        self.sent += data

    def close(self):
        self._closed = True


@pytest.fixture
def patched_connect(monkeypatch):
    """Return a helper that patches socket.create_connection to return
    a FakeSocket seeded with a script of server responses."""
    def _patch(script):
        sock = _FakeSocket(script)
        monkeypatch.setattr(socket, "create_connection",
                             lambda *a, **k: sock)
        return sock
    return _patch


class TestSAPTelnetClient:

    def test_connect_reads_banner(self, patched_connect):
        sock = patched_connect([
            b"Welcome to SAP J2EE Engine >",
        ])
        c = tel.SAPTelnetClient("h", 50008, timeout=1.0)
        banner = c.connect()
        assert "Welcome" in banner

    def test_login_interactive_accepts_password_prompt(self, patched_connect):
        sock = patched_connect([
            b"> ",                               # initial banner
            b"Password: ",                       # prompt after "login alice"
            b"\nLogin successful.\n> ",          # after password
        ])
        c = tel.SAPTelnetClient("h", 50008, timeout=1.0)
        c.connect()
        ok = c.login("alice", "pw")
        assert ok is True
        assert b"login alice" in sock.sent
        assert b"pw" in sock.sent

    def test_login_rejects_on_failed_keyword(self, patched_connect):
        patched_connect([
            b"> ",
            b"Password: ",
            b"Login failed.\n> ",
        ])
        c = tel.SAPTelnetClient("h", 50008, timeout=1.0)
        c.connect()
        assert c.login("a", "b") is False

    def test_login_single_line_fallback(self, patched_connect):
        # No 'Password:' in response → client retries with single-line
        # "login user pass" form.  We feed a successful banner afterwards.
        patched_connect([
            b"> ",
            b"unknown command\n> ",       # first attempt: no password prompt
            b"Login successful.\n> ",     # retry with 'login user pass'
        ])
        c = tel.SAPTelnetClient("h", 50008, timeout=1.0)
        c.connect()
        assert c.login("a", "b") is True

    def test_exec_cmd_sends_and_reads_until_prompt(self, patched_connect):
        sock = patched_connect([
            b"> ",                          # banner
            b"output-of-cmd\n> ",           # response
        ])
        c = tel.SAPTelnetClient("h", 50008, timeout=1.0)
        c.connect()
        out = c.exec_cmd("whoami")
        assert b"whoami" in sock.sent
        assert "output-of-cmd" in out

    def test_list_services_invokes_lsc(self, patched_connect):
        sock = patched_connect([
            b"> ",
            b"DEPLOY\nSHELL\nOSGi\n> ",
        ])
        c = tel.SAPTelnetClient("h", 50008, timeout=1.0)
        c.connect()
        svc = c.list_services()
        assert "DEPLOY" in svc
        assert b"lsc" in sock.sent
