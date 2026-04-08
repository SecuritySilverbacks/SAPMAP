"""
sap_saprouter.py – SAProuter NI protocol tunnel for SAPMAP.

Establishes TCP tunnels through SAP Router using the NI_ROUTE protocol.
After the tunnel is established (NI_PONG received), the socket becomes
a transparent TCP pipe to the target — all existing code (port scanning,
protocol probes, RFC connections) works unchanged through it.

Route string format:
  /H/<router_ip>/S/<router_port>/W/<password>/H/<target_ip>/S/<target_port>

Protocol reference:
  - pysap SAPRouter.py (OWASP CBAS project)
  - Wireshark SAP Router dissector (packet-saprouter.c)

License: Same as SAPMAP project.
"""

import re
import socket
import struct


def parse_route_string(route_str: str) -> list:
    """Parse a SAProuter route string into a list of hop dicts.

    Input:  "/H/10.0.0.1/S/3299/W/secret/H/192.168.1.5/S/3200"
    Output: [
        {"host": "10.0.0.1", "port": "3299", "password": "secret"},
        {"host": "192.168.1.5", "port": "3200", "password": ""},
    ]

    Supported tokens: /H/ (host), /S/ (service/port), /W/ (password).
    """
    if not route_str or not route_str.startswith("/"):
        raise ValueError(f"Invalid route string: {route_str!r}")

    # Tokenise: split on /X/ markers (case-insensitive)
    tokens = re.split(r"/([HSWhsw])/", route_str)
    # tokens[0] is empty (before first /), then alternating key, value
    tokens = tokens[1:]  # drop leading empty

    hops = []
    current = {"host": "", "port": "", "password": ""}

    i = 0
    while i < len(tokens) - 1:
        key = tokens[i].upper()
        val = tokens[i + 1]
        if key == "H":
            # New hop starts with /H/
            if current["host"]:
                hops.append(current)
                current = {"host": "", "port": "", "password": ""}
            current["host"] = val
        elif key == "S":
            current["port"] = val
        elif key == "W":
            current["password"] = val
        i += 2

    if current["host"]:
        hops.append(current)

    if len(hops) < 2:
        raise ValueError(
            f"Route string must have at least 2 hops (router + target), "
            f"got {len(hops)}: {route_str!r}"
        )

    return hops


def build_ni_route_packet(hops: list, talk_mode: int = 1) -> bytes:
    """Build an NI_ROUTE packet from a list of hop dicts.

    Args:
        hops: list of {"host", "port", "password"} dicts
        talk_mode: 0=NI_MSG_IO, 1=NI_RAW_IO (transparent tunnel)

    Returns the complete NI packet (including 4-byte length prefix).
    """
    # Build hop data: each hop = "host\0" + "port\0" + "password\0"
    # SAProuter protocol: the password goes on the TARGET hop (the one
    # being routed TO), NOT on the router's own entry.  If the parser
    # placed /W/ on hop 0 (the router), move it to hop 1 (the target).
    if len(hops) >= 2 and hops[0].get("password") and not hops[1].get("password"):
        hops[1]["password"] = hops[0]["password"]
        hops[0]["password"] = ""

    hop_entries = []
    for hop in hops:
        entry = (hop["host"].encode("ascii") + b"\x00"
                 + hop["port"].encode("ascii") + b"\x00"
                 + hop.get("password", "").encode("ascii") + b"\x00")
        hop_entries.append(entry)

    route_data = b"".join(hop_entries)
    first_hop_len = len(hop_entries[0])

    # NI_ROUTE payload
    # Format matches the working implementation in sap_rfc_system_info.py:
    #   byte  0-8: "NI_ROUTE\0"
    #   byte  9:   route protocol version (2)
    #   byte 10:   NI version (0x27 = 39)
    #   byte 11:   entries count
    #   byte 12:   talk mode (0=NI_MSG_IO, 1=NI_RAW_IO)
    #   byte 13-14: padding
    #   byte 15:   rest_nodes (entries - 1)
    #   byte 16-19: route_length (uint32 BE)
    #   byte 20-23: route_offset (uint32 BE)
    #   byte 24+:  route data
    payload = b""
    payload += b"NI_ROUTE\x00"          # type (9 bytes, null-terminated)
    payload += struct.pack("B", 0x02)    # route protocol version = 2
    payload += struct.pack("B", 0x27)    # NI version = 39
    payload += struct.pack("B", len(hops))  # route_entries
    payload += struct.pack("B", talk_mode)  # route_talk_mode
    payload += b"\x00\x00"              # padding
    payload += struct.pack("B", len(hops) - 1)  # route_rest_nodes
    payload += struct.pack("!I", len(route_data))    # route_length
    payload += struct.pack("!I", first_hop_len)      # route_offset
    payload += route_data

    # NI frame: 4-byte big-endian length + payload
    return struct.pack("!I", len(payload)) + payload


def connect_through_saprouter(route_str: str, timeout: float = 10,
                              talk_mode: int = 0) -> socket.socket:
    """Establish a TCP tunnel through SAProuter.

    1. Parse route string into hops
    2. Connect to first hop (SAProuter IP:port)
    3. Send NI_ROUTE packet
    4. Wait for NI_PONG (success) or error
    5. Return the tunneled socket (transparent TCP pipe)

    Args:
        route_str: Full SAProuter route string
                   (e.g., "/H/router/S/3299/W/pass/H/target/S/3200")
        timeout: Connection and response timeout in seconds
        talk_mode: 0=NI_MSG_IO (SAP protocol with NI framing, default),
                   1=NI_RAW_IO (pure transparent TCP — use for raw shells)

    Returns:
        Connected socket (transparent tunnel to target)

    Raises:
        ConnectionError: If route fails (ACL denied, target unreachable, etc.)
        TimeoutError: If connection or response times out
        ValueError: If route string is malformed
    """
    hops = parse_route_string(route_str)

    # First hop = the SAProuter itself
    router_host = hops[0]["host"]
    router_port = int(hops[0]["port"])

    # Connect to SAProuter
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((router_host, router_port))
    except Exception as e:
        sock.close()
        raise ConnectionError(
            f"Cannot connect to SAProuter {router_host}:{router_port}: {e}"
        ) from e

    # Send NI_ROUTE packet
    ni_route = build_ni_route_packet(hops, talk_mode=talk_mode)
    try:
        sock.sendall(ni_route)
    except Exception as e:
        sock.close()
        raise ConnectionError(f"Failed to send NI_ROUTE: {e}") from e

    # Read NI response
    try:
        # Read 4-byte NI length header
        hdr = b""
        while len(hdr) < 4:
            chunk = sock.recv(4 - len(hdr))
            if not chunk:
                raise ConnectionError("SAProuter closed connection")
            hdr += chunk

        resp_len = struct.unpack("!I", hdr)[0]
        if resp_len > 65536:
            raise ConnectionError(f"SAProuter response too large: {resp_len}")

        # Read payload
        resp = b""
        while len(resp) < resp_len:
            chunk = sock.recv(min(resp_len - len(resp), 65536))
            if not chunk:
                raise ConnectionError("SAProuter closed connection during response")
            resp += chunk

    except socket.timeout:
        sock.close()
        raise TimeoutError("SAProuter did not respond in time")
    except Exception as e:
        sock.close()
        raise

    # Check for NI_PONG or empty frame (both = success)
    if resp_len == 0 or resp.startswith(b"NI_PONG"):
        # Tunnel established — socket is now a transparent TCP pipe
        return sock

    # Check for error
    if b"NI_RTERR" in resp or b"*ERR*" in resp:
        sock.close()
        # Try to extract error message
        try:
            err_text = resp.decode("ascii", errors="replace")
        except Exception:
            err_text = resp[:100].hex()
        raise ConnectionError(f"SAProuter route denied: {err_text[:200]}")

    # Unknown response
    sock.close()
    raise ConnectionError(
        f"Unexpected SAProuter response ({len(resp)} bytes): "
        f"{resp[:40].hex()}"
    )


def build_route_for_port(saprouter_prefix: str, target_host: str,
                         target_port: int) -> str:
    """Build a complete route string for a specific target port.

    Args:
        saprouter_prefix: The SAProuter part of the route
                          (e.g., "/H/3.221.134.53/S/3299/W/password")
        target_host: Target SAP system IP/hostname
        target_port: Target port number

    Returns:
        Complete route string (e.g., "/H/router/S/3299/W/pass/H/target/S/3200")
    """
    prefix = saprouter_prefix.rstrip("/")
    return f"{prefix}/H/{target_host}/S/{target_port}"


# ---------------------------------------------------------------------------
# Port probing via SAProuter (lightweight — no full tunnel needed)
# ---------------------------------------------------------------------------

# Status codes returned by probe_port_via_saprouter()
PROBE_OPEN         = "open"          # NI_PONG — SAProuter reached target + port open
PROBE_CLOSED       = "closed"        # NI_RTERR: connection refused — port closed (host reachable)
PROBE_ACL_DENIED   = "acl_denied"    # NI_RTERR: connection denied — SAProuter ACL blocks this dest
PROBE_FILTERED     = "filtered"      # NI_RTERR: timed out / not reached — firewall or dead host
PROBE_UNKNOWN_HOST = "unknown_host"  # NI_RTERR: unknown host / GetHostByName failed
PROBE_ERROR        = "error"         # connection to SAProuter itself failed

# NI_RTERR keyword → status mapping (checked in order; first match wins)
_RTERR_STATUS_MAP = [
    ("refused",     PROBE_CLOSED),
    ("denied",      PROBE_ACL_DENIED),
    ("timed out",   PROBE_FILTERED),
    ("not reached", PROBE_FILTERED),
    # SAP spells "reachable" as "reacheable" in some kernel versions
    ("reacheable",  PROBE_FILTERED),
    ("reachable",   PROBE_FILTERED),
    ("unknown",     PROBE_UNKNOWN_HOST),
    ("not found",   PROBE_UNKNOWN_HOST),
    ("gethostbyname", PROBE_UNKNOWN_HOST),
    ("invalid",     PROBE_FILTERED),
]


def probe_port_via_saprouter(saprouter_prefix: str, target_host: str,
                             target_port: int,
                             timeout: float = 5.0) -> dict:
    """Probe whether a port is accessible through a SAProuter.

    Sends one NI_ROUTE packet and reads the response — cheaper than
    connect_through_saprouter() because no full tunnel is established.
    The SAProuter's NI_RTERR error text reveals whether the port is
    open, closed, blocked by ACL, or the host is unreachable.

    This is the core primitive for internal network scanning through a
    SAProuter: the ACL distinction (acl_denied vs closed vs filtered)
    reveals the SAProuter routing policy even for unreachable targets.

    Args:
        saprouter_prefix: Route prefix up to (but not including) the target,
                          e.g. "/H/10.0.0.1/S/3299/W/secret"
        target_host:      Internal IP or hostname to probe
        target_port:      TCP port to probe
        timeout:          Socket timeout in seconds

    Returns dict:
        status:   one of PROBE_OPEN / PROBE_CLOSED / PROBE_ACL_DENIED /
                  PROBE_FILTERED / PROBE_UNKNOWN_HOST / PROBE_ERROR
        message:  human-readable SAProuter error text (empty for OPEN)
    """
    result = {"status": PROBE_ERROR, "message": ""}

    try:
        route_str = build_route_for_port(saprouter_prefix, target_host, target_port)
        hops = parse_route_string(route_str)
    except ValueError as e:
        result["message"] = str(e)
        return result

    router_host = hops[0]["host"]
    router_port_str = hops[0]["port"]
    try:
        router_port = int(router_port_str)
    except ValueError:
        result["message"] = f"Invalid router port: {router_port_str!r}"
        return result

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((router_host, router_port))
    except Exception as e:
        sock.close()
        result["message"] = f"Cannot connect to SAProuter {router_host}:{router_port}: {e}"
        return result

    # Send NI_ROUTE packet (talk_mode=0 = NI_MSG_IO; same as connect_through_saprouter)
    ni_pkt = build_ni_route_packet(hops, talk_mode=0)
    try:
        sock.sendall(ni_pkt)
    except Exception as e:
        sock.close()
        result["message"] = f"Send failed: {e}"
        return result

    # Read NI response: 4-byte length header + payload
    try:
        hdr = b""
        while len(hdr) < 4:
            chunk = sock.recv(4 - len(hdr))
            if not chunk:
                # Connection closed without response — treat as filtered
                sock.close()
                result["status"] = PROBE_FILTERED
                result["message"] = "SAProuter closed connection without response"
                return result
            hdr += chunk

        resp_len = struct.unpack("!I", hdr)[0]

        if resp_len == 0:
            # Empty NI frame = NI_PONG equivalent → port open
            sock.close()
            result["status"] = PROBE_OPEN
            return result

        # Read payload (cap at 4 KB — error messages are always short)
        resp = b""
        max_read = min(resp_len, 4096)
        while len(resp) < max_read:
            chunk = sock.recv(max_read - len(resp))
            if not chunk:
                break
            resp += chunk

    except socket.timeout:
        sock.close()
        result["status"] = PROBE_FILTERED
        result["message"] = "Timeout waiting for SAProuter response"
        return result
    except Exception as e:
        sock.close()
        result["message"] = str(e)
        return result
    finally:
        try:
            sock.close()
        except Exception:
            pass

    # NI_PONG → open
    if resp.startswith(b"NI_PONG"):
        result["status"] = PROBE_OPEN
        return result

    # NI_RTERR → classify by error text
    if b"NI_RTERR" in resp or b"*ERR*" in resp:
        try:
            err_text = resp.decode("ascii", errors="replace").lower()
        except Exception:
            err_text = ""
        result["message"] = resp.decode("ascii", errors="replace").strip()

        for keyword, status in _RTERR_STATUS_MAP:
            if keyword in err_text:
                result["status"] = status
                return result

        # Unknown NI_RTERR — treat as filtered
        result["status"] = PROBE_FILTERED
        return result

    # Unexpected response
    result["status"] = PROBE_FILTERED
    result["message"] = f"Unexpected response ({resp_len} bytes): {resp[:40].hex()}"
    return result
