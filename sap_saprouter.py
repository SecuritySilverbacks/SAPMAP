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


def connect_through_saprouter(route_str: str, timeout: float = 10) -> socket.socket:
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

    # Send NI_ROUTE packet (talk_mode=0 for NI_MSG_IO)
    ni_route = build_ni_route_packet(hops, talk_mode=0)
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
