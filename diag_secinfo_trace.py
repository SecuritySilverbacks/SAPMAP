#!/usr/bin/env python3
"""
diag_secinfo_trace.py — Read secinfo rules, GW profile params, and current GwHostTab.
Also sends SIGUSR2 to GW to increase trace level, then runs a SAPXPG attempt
so dev_rd shows the exact secinfo check failure at trace level 3.
"""
import sys, time, socket, struct
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')

from sap_rfc_ctypes import RFCConnection
from sap_gw_xpg_standalone import (
    build_p1, build_p2, ni_send, ni_recv, ni_drain, hexdump,
)

SDK    = '/home/joris/Desktop/nwrfc750P_18-70002752/nwrfcsdk/lib/libsapnwrfc.so'
HOST   = '192.168.2.209'
SYSNR  = '00'
CLIENT = '001'
USER   = 'joris'
PASSWD = 'Schaap123!'

GW_HOST  = '192.168.2.209'
GW_PORT  = 3300
INSTANCE = '00'
DEST     = 'T_75'
HOSTNAME = 's4hanadev'
TIMEOUT  = 10


def xpg(conn, prog, params, label):
    print(f"\n{'='*60}")
    print(f"[CMD] {label}")
    print(f"  {prog} {params}")
    print('='*60)
    kw = dict(TARGET='', DESTINATION='', EXTPROG=prog, PARAMS=params,
              STDINCNTL='R', STDOUTCNTL='M', STDERRCNTL='M', TRACECNTL='0',
              TERMCNTL='C', TRACELEVEL='0', LONG_PARAMS='', CONNCNTL='H')
    try:
        try:
            r = conn.call('SXPG_STEP_XPG_START', MXROW=9999, **kw)
        except Exception as e:
            if 'MXROW' in str(e) or 'RFC_INVALID_PARAMETER' in str(e):
                r = conn.call('SXPG_STEP_XPG_START', **kw)
            else:
                print(f'  [RFC error] {e}'); return None
    except Exception as e:
        print(f'  [call failed] {e}'); return None

    status = r.get('STATUS', '?')
    log = r.get('LOG', [])
    if not log:
        print(f'  (no output, status={status!r})')
        return None
    lines = []
    for row in log:
        line = (row.get('MESSAGE') or row.get('LINE') or row.get('TEXT') or '').rstrip() \
               if isinstance(row, dict) else str(row).rstrip()
        if line:
            print(f'  {line}')
            lines.append(line)
    print(f'  [status={status!r}]')
    return lines


def try_sapxpg_p2():
    """Send just P1+P2 to GW and show the raw P2 response."""
    print(f"\n{'='*60}")
    print("[TEST] SAPXPG P1+P2 probe (trace secinfo check)")
    print('='*60)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.connect((GW_HOST, GW_PORT))
    except socket.error as e:
        print(f"  Connect failed: {e}"); return

    local_ip = sock.getsockname()[0]
    print(f"  Local IP: {local_ip}")

    # P1
    ni_send(sock, build_p1(GW_HOST, INSTANCE))
    try:
        resp = ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 0.5)
        print(f"  P1: {len(frames)} frame(s)")
    except socket.timeout:
        print("  P1 timeout"); sock.close(); return

    # P2
    p2 = build_p2(GW_HOST, DEST, local_ip=local_ip, target_hostname=HOSTNAME)
    ni_send(sock, p2)
    try:
        resp = ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 0.5)
        raw = frames[0]
        print(f"  P2 first frame ({len(raw)} bytes):")
        print(f"  hex[0:80]: {raw[:80].hex()}")
        if len(raw) >= 40:
            appc_rc = struct.unpack("!I", raw[32:36])[0]
            sap_rc  = struct.unpack("!I", raw[36:40])[0]
            print(f"  appc_rc={appc_rc}  sap_rc={sap_rc}")
            # conv_id at offset 40-47 (8 bytes ASCII decimal)
            if len(raw) >= 48:
                conv_id_raw = raw[40:48]
                print(f"  conv_id bytes: {conv_id_raw!r}")
    except socket.timeout:
        print("  P2 timeout")
    sock.close()


def get_gw_pid(conn):
    """Get current GW PID."""
    lines = xpg(conn, '/bin/ps', '-e -o pid,comm', 'GW PID via ps')
    if not lines:
        return None
    for line in lines:
        if 'SAP_S4H_00_GW' in line:
            try:
                return int(line.split()[0])
            except (ValueError, IndexError):
                pass
    return None


def main():
    with RFCConnection(sdk_path=SDK, ashost=HOST, sysnr=SYSNR,
                       client=CLIENT, user=USER, passwd=PASSWD, lang='EN') as conn:
        print('[+] RFC connected')

        # 1. Read secinfo file
        xpg(conn, '/bin/cat', '/usr/sap/S4H/SYS/global/secinfo',
            'secinfo rules (no .dat extension)')

        # Also try with .dat extension
        xpg(conn, '/bin/cat', '/usr/sap/S4H/SYS/global/secinfo.dat',
            'secinfo.dat')

        # 2. Read GW profile params relevant to secinfo/hosttab
        xpg(conn, '/usr/bin/grep', '-i "secinfo\|gw/trace\|gw/reg\|gw/acl\|internal\|hosttab\|gwsys" /usr/sap/S4H/SYS/profile/DEFAULT.PFL',
            'DEFAULT.PFL: secinfo/trace/gw params')

        xpg(conn, '/usr/bin/grep', '-i "secinfo\|gw/trace\|gw/reg\|gw/acl\|internal\|hosttab\|gwsys" /usr/sap/S4H/SYS/profile/S4H_D00_s4hanadev',
            'Instance profile: secinfo/trace/gw params')

        # 3. Check for gw/internal_hosts or similar parameters
        xpg(conn, '/usr/bin/grep', '-ri "gw/internal\|internal_host\|gw/trust\|gw_trust" /usr/sap/S4H/SYS/profile/',
            'profile: grep internal_hosts / trust params')

        # 4. Current dev_rd GWSYST snapshot
        xpg(conn, '/usr/bin/grep', '-A20 "SERVER SNAPSHOT\|GWSYST" /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: GWSYST snapshot')

        # 5. Get GW PID
        pid = get_gw_pid(conn)
        print(f"\n[*] Current GW PID: {pid}")

        # 6. Check current trace level in dev_rd header
        xpg(conn, '/usr/bin/head', '-20 /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd head-20 (trace level header)')

        # 7. Increase GW trace to level 3 via SIGUSR2
        # SIGUSR2 cycles: level 0 → 1 → 2 → 3 → 0
        # Current level is probably 1 (default). Send 2x to reach 3.
        if pid:
            print(f"\n[*] Sending SIGUSR2 x2 to GW pid={pid} to increase trace to level 3...")
            xpg(conn, '/bin/kill', f'-USR2 {pid}', f'SIGUSR2 x1 to GW pid={pid}')
            time.sleep(0.5)
            xpg(conn, '/bin/kill', f'-USR2 {pid}', f'SIGUSR2 x2 to GW pid={pid}')
            time.sleep(1)
            print("[*] Trace should now be at level 3 (or higher)")

        # 8. Now trigger SAPXPG P1+P2 so the trace records the secinfo check
        print("\n[*] Triggering SAPXPG P1+P2 to generate secinfo trace...")
        try_sapxpg_p2()
        time.sleep(1)  # let GW write trace

        # 9. Read last 100 lines of dev_rd to see the secinfo check trace
        xpg(conn, '/usr/bin/tail', '-100 /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd tail-100 (post-SAPXPG trace at level 3)')

        # 10. Look for secinfo-related terms in dev_rd
        xpg(conn, '/usr/bin/grep', '-n "secinfo\|GwSec\|appc_rc\|USER-HOST\|gwhosttab\|GwHostTab\|internal\|trusted\|gwsyst\|GWSYST" /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: grep secinfo/hosttab terms')

        # 11. Check if there's a separate GW trace file
        xpg(conn, '/bin/ls', '-la /usr/sap/S4H/D00/work/ | grep -i "gw\|dev_rd"',
            'D00/work: GW trace files')

        print('\n[*] Done.')


if __name__ == '__main__':
    main()
