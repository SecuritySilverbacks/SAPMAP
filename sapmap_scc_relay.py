#!/usr/bin/env python3
"""SAPMAP — SCC tunnel-relay smoke test.

Verifies that each configured Cloud-To-On-Premise mapping in an SCC
actually points at a reachable backend.  We probe the *internal* side of
the mapping (i.e. ``internal_host:internal_port`` from the SCC's
perspective) directly from the operator's host — same network the SCC
itself sits on, so this mirrors the reachability check the tunnel would
perform when a cloud peer dials the virtual_host.

Per-mapping outcomes feed back into the GUI via SCCMapping fields:

    reachable        -> True | False | None (not yet probed)
    last_probed_at   -> ISO timestamp
    probe_latency_ms -> RTT of the successful probe
    probe_signature  -> compact banner/TLS/TCP-OK string
    probe_error      -> stringified failure reason

Probes are protocol-aware:

    HTTP / HTTPS  -> TCP connect + HEAD /  (1xx-5xx == reachable backend)
    RFC           -> TCP connect (any TCP success == sapdisp listening)
    TCP / LDAP    -> TCP connect
    MAIL          -> TCP connect (no SMTP banner read; read stays optional)
    other / blank -> TCP connect, signature == "tcp-ok"

Notes:

* This is a **smoke test**, not an authenticated request.  We never send
  credentials; HTTPS uses a no-verify SSL context because SCC backends
  routinely speak self-signed TLS.
* We deliberately don't go through the cloud-side virtual endpoint
  (``virtual_host:virtual_port``) — that requires an established tunnel
  with a subaccount-bound certificate, which is out of scope for the
  read-only mapping audit.  TCP reachability of the internal side is
  what determines whether a cloud peer's request would actually land.
"""
from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime
from typing import Dict, Optional, Tuple

# Protocols that are JSON-serialised on SCCMapping.protocol — keep the
# string compare case-insensitive against this set.
HTTP_PROTOS = {"HTTP", "HTTPS"}
RFC_PROTOS = {"RFC", "RFCS"}
TCP_PROTOS = {"TCP", "TCPS", "LDAP", "LDAPS", "MAIL"}


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _tcp_connect(host: str, port: int, timeout: float) -> Tuple[bool, float, str]:
    """Open a plain TCP socket; return (ok, rtt_ms, error)."""
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            rtt = (time.monotonic() - t0) * 1000.0
            return True, rtt, ""
    except (socket.timeout, TimeoutError) as e:
        return False, 0.0, f"timeout after {timeout:.1f}s"
    except (ConnectionRefusedError, ConnectionResetError) as e:
        return False, 0.0, f"refused ({e.__class__.__name__})"
    except socket.gaierror as e:
        return False, 0.0, f"dns: {e}"
    except OSError as e:
        return False, 0.0, f"oserror: {e}"


def _http_head(host: str, port: int, use_tls: bool, timeout: float
               ) -> Tuple[bool, float, str, str]:
    """Send HEAD / and read the first response line.

    Returns (ok, rtt_ms, signature, error).  ``ok`` is True for any
    well-formed HTTP status (1xx-5xx) — even 401/403/404 mean *something*
    is listening on the backend, which is what reachability asks.
    """
    t0 = time.monotonic()
    sig = ""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            req = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                "User-Agent: SAPMAP-SCC-Relay/1.0\r\n"
                "Connection: close\r\n"
                "Accept: */*\r\n"
                "\r\n"
            ).encode("ascii", errors="replace")
            sock.sendall(req)
            sock.settimeout(timeout)
            data = sock.recv(512)
            rtt = (time.monotonic() - t0) * 1000.0
            line = (data.split(b"\r\n", 1)[0] if data else b"").decode("latin-1", "replace")
            if line.startswith("HTTP/"):
                # Extract just "HTTP/1.1 200 OK" up to ~80 chars.
                sig = line[:80]
                return True, rtt, sig, ""
            # Not HTTP but something accepted the bytes; still reachable.
            sig = (line[:60] or "tcp-ok")
            return True, rtt, sig, ""
        finally:
            try:
                sock.close()
            except Exception:
                pass
    except (socket.timeout, TimeoutError):
        return False, 0.0, "", f"timeout after {timeout:.1f}s"
    except ssl.SSLError as e:
        rtt = (time.monotonic() - t0) * 1000.0
        # TLS handshake failures still prove the port is listening,
        # but they're often the user's signal that the wrong protocol
        # is configured (e.g. HTTPS targeted at an HTTP backend).
        return True, rtt, f"tls-error: {e.reason or e}", ""
    except (ConnectionRefusedError, ConnectionResetError) as e:
        return False, 0.0, "", f"refused ({e.__class__.__name__})"
    except socket.gaierror as e:
        return False, 0.0, "", f"dns: {e}"
    except OSError as e:
        return False, 0.0, "", f"oserror: {e}"


def probe_mapping(mapping: Dict, timeout: float = 4.0) -> Dict:
    """Probe one mapping's internal endpoint.

    Mutates *mapping* in place with the probe-result fields the GUI
    drawer reads, and also returns those fields for callers that want
    to log them separately.

    Safe to call concurrently — no shared state.
    """
    host = (mapping.get("internal_host") or "").strip()
    port = int(mapping.get("internal_port") or 0)
    proto = (mapping.get("protocol") or "").strip().upper()

    result = {
        "reachable": False,
        "last_probed_at": _now_iso(),
        "probe_latency_ms": 0,
        "probe_signature": "",
        "probe_error": "",
    }
    if not host or not port:
        result["probe_error"] = "missing internal_host / internal_port"
        mapping.update(result)
        return result

    if proto in HTTP_PROTOS:
        ok, rtt, sig, err = _http_head(
            host, port, use_tls=(proto == "HTTPS"), timeout=timeout)
        result["reachable"] = ok
        result["probe_latency_ms"] = int(rtt)
        result["probe_signature"] = sig if ok else ""
        result["probe_error"] = err
    elif proto in RFC_PROTOS or proto in TCP_PROTOS or not proto:
        ok, rtt, err = _tcp_connect(host, port, timeout=timeout)
        result["reachable"] = ok
        result["probe_latency_ms"] = int(rtt)
        result["probe_signature"] = "tcp-ok" if ok else ""
        result["probe_error"] = err
    else:
        # Unknown protocol — fall back to TCP connect so we still
        # produce a useful reachability bit.
        ok, rtt, err = _tcp_connect(host, port, timeout=timeout)
        result["reachable"] = ok
        result["probe_latency_ms"] = int(rtt)
        result["probe_signature"] = (f"tcp-ok ({proto})" if ok else "")
        result["probe_error"] = err

    mapping.update(result)
    return result


def probe_all(mappings, timeout: float = 4.0):
    """Probe every mapping; yields (index, mapping, result) tuples.

    Sequential (not threaded) on purpose: the typical SCC has < 30
    mappings, total wall time is bounded by ``timeout * len(mappings)``,
    and the SCC backend network is small enough that we don't want to
    saturate it with parallel sockets.
    """
    for idx, m in enumerate(mappings or []):
        if not isinstance(m, dict):
            continue
        yield idx, m, probe_mapping(m, timeout=timeout)
