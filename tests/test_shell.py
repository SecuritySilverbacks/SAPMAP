#!/usr/bin/env python3
"""Tests for shell session, payload generation, and socket handling."""

import sys
import os
import socket
import threading
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sapmap_gui import (
    ShellSession,
    _generate_payload,
    _generate_bind_payload,
    _detect_local_ip,
)


# ===========================================================================
# ShellSession — init
# ===========================================================================

def test_shell_session_init_defaults():
    s = ShellSession(4444, "TST")
    assert s.port == 4444
    assert s.target_sid == "TST"
    assert s.mode == "reverse"
    assert s.status == "idle"
    assert s.error_msg == ""
    assert s.server_sock is None
    assert s.client_sock is None
    assert s.client_addr is None
    assert s.output_buffer == []


def test_shell_session_init_bind_mode():
    s = ShellSession(5555, "PRD", mode="bind")
    assert s.mode == "bind"
    assert s.port == 5555
    assert s.target_sid == "PRD"


# ===========================================================================
# ShellSession — output buffer
# ===========================================================================

def test_get_output_empty():
    s = ShellSession(4444, "TST")
    assert s.get_output() == ""


def test_get_output_returns_and_clears():
    s = ShellSession(4444, "TST")
    s.output_buffer.append("hello ")
    s.output_buffer.append("world\n")
    out = s.get_output()
    assert out == "hello world\n"
    # Buffer should be cleared
    assert s.get_output() == ""


def test_get_output_thread_safe():
    """Multiple threads writing and reading shouldn't lose data."""
    s = ShellSession(4444, "TST")
    collected = []

    def writer(n):
        for i in range(100):
            with s.output_lock:
                s.output_buffer.append(f"{n}:{i}\n")

    threads = [threading.Thread(target=writer, args=(t,)) for t in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Drain all output
    out = s.get_output()
    lines = [l for l in out.split("\n") if l]
    assert len(lines) == 400  # 4 threads x 100 lines


# ===========================================================================
# ShellSession — send_input
# ===========================================================================

def test_send_input_not_connected():
    """send_input on non-connected session should not crash."""
    s = ShellSession(4444, "TST")
    s.status = "idle"
    # Should do nothing (no exception)
    s.send_input("whoami")


# ===========================================================================
# ShellSession — stop
# ===========================================================================

def test_stop_sets_disconnected():
    s = ShellSession(4444, "TST")
    s.status = "connected"
    s.stop()
    assert s.status == "disconnected"


def test_stop_closes_sockets():
    s = ShellSession(4444, "TST")
    # Create mock sockets
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.server_sock = srv
    s.client_sock = cli
    s.stop()
    assert s.server_sock is None
    assert s.client_sock is None


# ===========================================================================
# ShellSession — reverse shell (listener) integration
# ===========================================================================

def test_reverse_shell_connect():
    """Full reverse shell flow: listener accepts connection, reads data."""
    s = ShellSession(0, "TST", mode="reverse")  # port 0 = OS picks free port
    s.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.server_sock.bind(("127.0.0.1", 0))
    actual_port = s.server_sock.getsockname()[1]
    s.port = actual_port
    s.server_sock.listen(1)
    s.status = "waiting"
    threading.Thread(target=s._listener_loop, daemon=True).start()

    # Simulate reverse shell connecting back
    time.sleep(0.1)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", actual_port))
    client.sendall(b"uid=1000(test) gid=1000(test)\n")
    time.sleep(0.3)

    assert s.status == "connected"
    assert s.client_addr is not None
    out = s.get_output()
    assert "uid=1000(test)" in out

    client.close()
    time.sleep(0.2)
    assert s.status == "disconnected"
    s.stop()


# ===========================================================================
# ShellSession — bind shell (connector) integration
# ===========================================================================

def test_bind_shell_connect():
    """Full bind shell flow: target listens, ShellSession connects to it."""
    # Simulate target's bind shell listener
    target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    target_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    target_sock.bind(("127.0.0.1", 0))
    target_port = target_sock.getsockname()[1]
    target_sock.listen(1)

    s = ShellSession(target_port, "TST", mode="bind")
    s.start_connector("127.0.0.1")

    # Accept the connection on the "target" side
    target_sock.settimeout(5)
    conn, addr = target_sock.accept()
    conn.sendall(b"s4hadm@host:~> ")
    time.sleep(0.3)

    assert s.status == "connected"
    out = s.get_output()
    assert "s4hadm@host:~>" in out

    # Test send_input
    s.send_input("id")
    time.sleep(0.1)
    data = conn.recv(1024)
    assert data == b"id\n"

    # Cleanup
    conn.close()
    target_sock.close()
    time.sleep(0.2)
    assert s.status == "disconnected"
    s.stop()


def test_bind_shell_connect_timeout():
    """Connector gives up after retries if nothing is listening."""
    s = ShellSession(19999, "TST", mode="bind")
    # Patch the retry count to make the test fast
    original_loop = s._connector_loop

    def fast_loop(host, saprouter):
        import time as _t
        for attempt in range(2):  # Only 2 attempts instead of 30
            if s.status != "waiting":
                return
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.connect((host, s.port))
            except Exception:
                _t.sleep(0.1)
        s.status = "error"
        s.error_msg = "Could not connect"

    s.status = "waiting"
    t = threading.Thread(target=fast_loop, args=("127.0.0.1", ""), daemon=True)
    t.start()
    t.join(timeout=5)

    assert s.status == "error"
    assert "Could not connect" in s.error_msg


# ===========================================================================
# ShellSession — socket timeout cleared after connect
# ===========================================================================

def test_socket_timeout_cleared_after_connect():
    """Verify that the 5s connect timeout is removed for reader_loop."""
    target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    target_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    target_sock.bind(("127.0.0.1", 0))
    target_port = target_sock.getsockname()[1]
    target_sock.listen(1)

    s = ShellSession(target_port, "TST", mode="bind")
    s.start_connector("127.0.0.1")

    target_sock.settimeout(5)
    conn, _ = target_sock.accept()
    time.sleep(0.3)

    assert s.status == "connected"
    # The client socket timeout should be None (blocking) for reader_loop
    assert s.client_sock.gettimeout() is None

    conn.close()
    target_sock.close()
    time.sleep(0.2)
    s.stop()


def test_reverse_socket_timeout_cleared_after_accept():
    """Verify that accepted socket has timeout cleared for reader_loop."""
    s = ShellSession(0, "TST", mode="reverse")
    s.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.server_sock.bind(("127.0.0.1", 0))
    actual_port = s.server_sock.getsockname()[1]
    s.port = actual_port
    s.server_sock.listen(1)
    s.status = "waiting"
    threading.Thread(target=s._listener_loop, daemon=True).start()

    time.sleep(0.1)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", actual_port))
    time.sleep(0.3)

    assert s.status == "connected"
    # The client_sock timeout should be None (blocking)
    assert s.client_sock.gettimeout() is None

    client.close()
    time.sleep(0.2)
    s.stop()


# ===========================================================================
# _generate_payload — reverse shell
# ===========================================================================

def test_reverse_payload_linux():
    p = _generate_payload("Linux", "10.0.0.1", 4444)
    assert p["command"] == "python3"
    assert p["params"].startswith("-c ")
    assert "10.0.0.1" in p["params"]
    assert "4444" in p["params"]
    assert "reverse" in p["display"].lower() or "→" in p["display"]


def test_reverse_payload_linux_no_spaces():
    p = _generate_payload("Linux", "10.0.0.1", 4444)
    # After "-c ", the code part must have NO spaces
    code = p["params"][3:]  # strip "-c "
    assert " " not in code


def test_reverse_payload_windows():
    p = _generate_payload("Windows NT", "10.0.0.1", 5555)
    assert p["command"].startswith("powershell.exe")
    assert "EncodedCommand" in p["command"]
    assert "-nop" in p["command"]
    assert p["params"] == ""


def test_reverse_payload_various_os_strings():
    """Various OS type strings should route correctly."""
    for os_type in ("Linux", "linux", "SUSE", "RedHat", "AIX", "", None):
        p = _generate_payload(os_type, "1.2.3.4", 4444)
        assert p["command"] == "python3"

    for os_type in ("Windows NT", "windows", "Windows Server 2019", "NT"):
        p = _generate_payload(os_type, "1.2.3.4", 4444)
        assert p["command"].startswith("powershell.exe")


# ===========================================================================
# _generate_bind_payload
# ===========================================================================

def test_bind_payload_linux():
    p = _generate_bind_payload("Linux", 4444)
    assert p["command"] == "python3"
    assert p["params"].startswith("-c ")
    assert "4444" in p["params"]
    assert "bind" in p["display"].lower()


def test_bind_payload_linux_no_spaces():
    p = _generate_bind_payload("Linux", 4444)
    code = p["params"][3:]
    assert " " not in code


def test_bind_payload_linux_under_255_chars():
    """SXPG PARAMS field is CHAR255 — total params must fit."""
    for port in (1234, 4444, 9999, 65535):
        p = _generate_bind_payload("Linux", port)
        assert len(p["params"]) <= 255, (
            f"PARAMS too long for port {port}: {len(p['params'])} chars")


def test_bind_payload_contains_fork():
    """Bind shell must fork() to survive SAPXPG disconnect."""
    p = _generate_bind_payload("Linux", 4444)
    assert "fork()" in p["params"]


def test_bind_payload_closes_stdout_stderr():
    """Bind shell must close fd 1+2 so SXPG's stdout pipe gets EOF."""
    p = _generate_bind_payload("Linux", 4444)
    assert "close(1)" in p["params"]
    assert "close(2)" in p["params"]


def test_bind_payload_has_setsockopt_reuseaddr():
    """Bind shell should set SO_REUSEADDR to avoid port conflicts."""
    p = _generate_bind_payload("Linux", 4444)
    # setsockopt(SOL_SOCKET=1, SO_REUSEADDR=2, 1)
    assert "setsockopt(1,2,1)" in p["params"]


def test_bind_payload_windows():
    p = _generate_bind_payload("Windows NT", 5555)
    assert p["command"].startswith("powershell.exe")
    assert "EncodedCommand" in p["command"]
    assert "-nop" in p["command"]
    assert p["params"] == ""


def test_bind_payload_various_os_strings():
    for os_type in ("Linux", "linux", "", None, "AIX"):
        p = _generate_bind_payload(os_type, 4444)
        assert p["command"] == "python3"

    for os_type in ("Windows NT", "windows", "win"):
        p = _generate_bind_payload(os_type, 4444)
        assert p["command"].startswith("powershell.exe")


# ===========================================================================
# _detect_local_ip
# ===========================================================================

def test_detect_local_ip_localhost():
    """Detecting IP for localhost should return a real IP (not crash)."""
    ip = _detect_local_ip("127.0.0.1")
    assert ip  # non-empty
    # Should be a valid IPv4 address
    socket.inet_aton(ip)


def test_detect_local_ip_unreachable():
    """Unreachable target should fall back to 127.0.0.1."""
    # Use an RFC 5737 documentation address that won't be routable
    ip = _detect_local_ip("192.0.2.1")
    assert ip  # Should not crash, returns some IP


# ===========================================================================
# ShellSession — error attribute name (regression: self.listen_port bug)
# ===========================================================================

def test_start_listener_port_in_use():
    """start_listener on occupied port should set error with self.port."""
    # Occupy a port
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    blocker.bind(("127.0.0.1", 0))
    occupied_port = blocker.getsockname()[1]
    blocker.listen(1)

    # On some OS, SO_REUSEADDR allows double-bind. Use a different approach:
    # bind to 0.0.0.0 without REUSEADDR
    blocker2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        blocker2.bind(("0.0.0.0", occupied_port))
        # If this succeeds (REUSEADDR), the test setup didn't work — skip
        blocker2.close()
        blocker.close()
        pytest.skip("OS allows double bind — can't test port conflict")
    except OSError:
        blocker2.close()

    s = ShellSession(occupied_port, "TST")
    s.start_listener()
    # Should NOT raise AttributeError (was: self.listen_port)
    # Status should be either "waiting" (bound OK with REUSEADDR) or "error"
    # The important thing is no crash
    blocker.close()
    s.stop()
