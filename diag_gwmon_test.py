#!/usr/bin/env python3
"""
diag_gwmon_test.py — Test gwmon interactivity and discover GWSYST add commands.
Also tests external GW monitor connection (req_type probe).
"""
import sys, time, socket, struct
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')

from sap_rfc_ctypes import RFCConnection
from sap_gw_xpg_standalone import ni_send, ni_recv, ni_drain

SDK    = '/home/joris/Desktop/nwrfc750P_18-70002752/nwrfcsdk/lib/libsapnwrfc.so'
HOST   = '192.168.2.209'
SYSNR  = '00'
CLIENT = '001'
USER   = 'joris'
PASSWD = 'SccAdmin123!'

GW_HOST = '192.168.2.209'
GW_PORT = 3300


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


def probe_gw_monitor_quick():
    """Quickly probe GW port 3300 with req_type=0x02 (GW_MONITOR)."""
    print(f"\n{'='*60}")
    print("[PROBE] External GW monitor connection (req_type=0x02)")
    print('='*60)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((GW_HOST, GW_PORT))

        # Build P1 with req_type=0x02 (GW_MONITOR)
        ip_bytes = socket.inet_aton(GW_HOST)
        p1 = bytes([0x02, 0x02]) + ip_bytes + b"\x00"*4
        p1 += b"sapgw00   "   # service (10 bytes)
        p1 += b"4103" + b"\x00"*6
        p1 += b"sapserve"
        p1 += b"sapgw00 "
        p1 += b" " * 8
        p1 += bytes([0x06, 0x00])
        p1 += struct.pack("!h", -1) + struct.pack("!I", 0)
        p1 += bytes([0x00, 0x00])
        assert len(p1) == 64

        ni_send(sock, p1)
        print(f"  Sent monitor P1 (req_type=0x02)")

        try:
            resp = ni_recv(sock, 5)
            print(f"  Response ({len(resp)} bytes): {resp[:80].hex()}")
            # Check if it looks like an OK
            if len(resp) >= 4:
                appc_rc = struct.unpack("!I", resp[32:36])[0] if len(resp) >= 36 else 0
                print(f"  appc_rc={appc_rc}")
            # Try decoded
            try:
                print(f"  ASCII: {resp[:80].decode('latin-1', errors='replace')!r}")
            except: pass
        except socket.timeout:
            print("  Timeout (no response from GW for req_type=0x02)")
        except ConnectionError as e:
            print(f"  Connection closed: {e}")

        sock.close()
    except Exception as e:
        print(f"  Error: {e}")


def main():
    print("=== GWmon Test + Monitor Probe ===\n")

    with RFCConnection(sdk_path=SDK, ashost=HOST, sysnr=SYSNR,
                       client=CLIENT, user=USER, passwd=PASSWD, lang='EN') as conn:
        print('[+] RFC connected')

        # 1. Run gwmon with -h or help argument to get usage
        xpg(conn, '/usr/sap/S4H/SYS/exe/run/gwmon', '-h',
            'gwmon -h (help flag)')

        # 2. Try gwmon with profile flag to get info
        xpg(conn, '/usr/sap/S4H/SYS/exe/run/gwmon',
            '-H 192.168.2.209 -G sapgw00 -f getsta',
            'gwmon -H host -G serv -f getsta (non-interactive)')

        # 3. Check gw/monitor in DEFAULT.PFL (single grep without pipe)
        xpg(conn, '/usr/bin/grep', 'gw/monitor /usr/sap/S4H/SYS/profile/DEFAULT.PFL',
            'DEFAULT.PFL: gw/monitor')

        # 4. Check all gw/* params in DEFAULT.PFL
        xpg(conn, '/usr/bin/grep', 'gw/ /usr/sap/S4H/SYS/profile/DEFAULT.PFL',
            'DEFAULT.PFL: all gw/* params')

        # 5. Check what TCP ports the GW is listening on
        xpg(conn, '/bin/ss', '-tlnp',
            'TCP listening ports')

        # 6. Read the gateway.lst file (shows what ports/services gwrd uses)
        xpg(conn, '/bin/cat', '/usr/sap/S4H/SYS/exe/run/gateway.lst',
            'gateway.lst (GW service list)')

        # 7. Try writing a gwmon command file and executing it
        # First, write a command file to /tmp
        xpg(conn, '/bin/bash', '-c "echo getsta > /tmp/gwmon_cmds.txt && echo -n end >> /tmp/gwmon_cmds.txt"',
            'Write gwmon command file to /tmp')

        # 8. Run gwmon with command file input
        xpg(conn, '/bin/bash',
            '-c "/usr/sap/S4H/SYS/exe/run/gwmon -H 192.168.2.209 -G sapgw00 < /tmp/gwmon_cmds.txt"',
            'gwmon with command file input')

        # 9. Check dev_rd for recent GWSYST snapshot (using simple grep)
        xpg(conn, '/usr/bin/grep', 'GWSYST /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: grep GWSYST')

        # 10. Read last 5 lines of gw_log to check current state
        xpg(conn, '/usr/bin/tail', '-5 /usr/sap/S4H/D00/work/gw_log-2026-04-11',
            'gw_log tail-5 (current state)')

    # External monitor probe
    probe_gw_monitor_quick()

    print("\n[*] Done.")


if __name__ == '__main__':
    main()
