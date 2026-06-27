#!/usr/bin/env python3
"""
diag_gwmon_probe.py — Find gwmon binary, probe GW monitor protocol.
"""
import sys, time, socket, struct
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')

from sap_rfc_ctypes import RFCConnection
from sap_gw_xpg_standalone import ni_send, ni_recv, ni_drain, hexdump

SDK    = '/home/joris/Desktop/nwrfc750P_18-70002752/nwrfcsdk/lib/libsapnwrfc.so'
HOST   = '192.168.2.209'
SYSNR  = '00'
CLIENT = '001'
USER   = 'joris'
PASSWD = 'Schaap123!'

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


def probe_gw_monitor():
    """Try to connect to GW port 3300 with various monitor connection types."""
    # The GW protocol P1 uses:
    # byte 0: version=2, byte 1: req_type, bytes 2-5: IP
    # req_type=0x03: GW_NORMAL_CLIENT
    # req_type=0x02: GW_MONITOR (monitor/admin connection)
    # req_type=0x01: GW_REGISTER (RFC server registration)

    for req_type in [0x02, 0x04, 0x05, 0x06]:
        print(f"\n{'='*50}")
        print(f"[PROBE] GW port 3300 with req_type=0x{req_type:02x}")
        print('='*50)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((GW_HOST, GW_PORT))

            # Build P1 with this req_type
            ip_bytes = socket.inet_aton(GW_HOST)
            service = b"sapgw00   "  # 10 bytes space-padded
            p1 = bytes([0x02, req_type]) + ip_bytes + b"\x00"*4 + service
            p1 += b"4103" + b"\x00"*6  # codepage + padd2
            p1 += b"sapserve"         # lu (8 bytes)
            p1 += b"sapgw00 "         # tp (8 bytes)
            p1 += b" " * 8            # conv_id
            p1 += bytes([0x06, 0x00]) # appc_header_version, accept_info
            p1 += struct.pack("!h", -1) + struct.pack("!I", 0)  # idx, rc
            p1 += bytes([0x00, 0x00])  # echo_data, filler
            assert len(p1) == 64, f"P1 len={len(p1)}"

            ni_send(sock, p1)
            print(f"  Sent P1 (64 bytes, req_type=0x{req_type:02x})")

            try:
                resp = ni_recv(sock, 5)
                frames = [resp] + ni_drain(sock, 1)
                for i, f in enumerate(frames):
                    print(f"  Response frame {i+1} ({len(f)} bytes): {f[:64].hex()}")
                    if len(f) >= 8:
                        print(f"    Bytes 0-7: {f[:8].hex()}")
                        print(f"    appc_rc: {struct.unpack('!I', f[32:36])[0] if len(f)>=36 else 'N/A'}")
            except socket.timeout:
                print("  Timeout (no response)")
            except ConnectionError as e:
                print(f"  Connection closed: {e}")

            sock.close()
        except Exception as e:
            print(f"  Error: {e}")


def try_gw_monitor_commands():
    """Try to connect as GW_MONITOR and send test commands."""
    print(f"\n{'='*60}")
    print("[MONITOR] Attempting GW monitor connection (req_type=0x02)")
    print('='*60)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((GW_HOST, GW_PORT))

        # Monitor P1 with req_type=0x02
        ip_bytes = socket.inet_aton(GW_HOST)
        p1 = bytes([0x02, 0x02]) + ip_bytes + b"\x00"*4  # version=2, req_type=0x02
        p1 += b"sapgw00   "   # service
        p1 += b"4103" + b"\x00"*6
        p1 += b"sapserve"
        p1 += b"sapgw00 "
        p1 += b" " * 8
        p1 += bytes([0x06, 0x00])
        p1 += struct.pack("!h", -1) + struct.pack("!I", 0)
        p1 += bytes([0x00, 0x00])
        assert len(p1) == 64

        ni_send(sock, p1)
        print(f"  Sent monitor P1")

        try:
            resp = ni_recv(sock, 5)
            frames = [resp] + ni_drain(sock, 1)
            for i, f in enumerate(frames):
                print(f"  Response {i+1} ({len(f)} bytes): {f[:80].hex()}")
                # Try to decode as ASCII
                try:
                    print(f"    ASCII: {f[:80].decode('ascii', errors='replace')!r}")
                except: pass
        except socket.timeout:
            print("  Timeout on P1 response")
            # Try sending a command anyway

        # Try sending a monitor command
        # From SAP documentation, gwmon commands can be sent after handshake
        # Format might be: 4-byte length + ASCII command
        # or specific binary format
        print("\n  Sending test monitor commands...")

        # Try various formats for monitor commands
        test_cmds = [
            b"getsta all",
            b"GETSTA ALL",
            b"info",
            b"INFO",
            b"status",
        ]
        for cmd in test_cmds[:2]:
            try:
                ni_send(sock, cmd)
                resp2 = ni_recv(sock, 3)
                print(f"  Cmd {cmd!r} response ({len(resp2)}B): {resp2[:60].hex()}")
                try:
                    print(f"    ASCII: {resp2[:60].decode('ascii', errors='replace')!r}")
                except: pass
            except (socket.timeout, ConnectionError, OSError) as e:
                print(f"  Cmd {cmd!r}: {e}")
                break

        sock.close()
    except Exception as e:
        print(f"  Error: {e}")


def main():
    print("=== GW Monitor Protocol Probe ===\n")

    # 1. Find gwmon binary on SAP server
    with RFCConnection(sdk_path=SDK, ashost=HOST, sysnr=SYSNR,
                       client=CLIENT, user=USER, passwd=PASSWD, lang='EN') as conn:
        print('[+] RFC connected')

        xpg(conn, '/usr/bin/find', '/usr/sap/S4H/SYS/exe -name "gwmon" -type f',
            'Find gwmon in SAP exe dir')

        xpg(conn, '/usr/bin/find', '/usr/sap -maxdepth 8 -name "gwmon" -type f',
            'Find gwmon anywhere under /usr/sap')

        xpg(conn, '/bin/ls', '-la /usr/sap/S4H/SYS/exe/run/',
            'SAP run directory (check for gwmon)')

        # Also check if there's a gw/monitor profile parameter
        xpg(conn, '/usr/bin/grep', '-ri "gw/monitor" /usr/sap/S4H/SYS/profile/',
            'profile: gw/monitor parameter')

        # What is the current gw/monitor value?
        xpg(conn, '/usr/bin/grep', '-ri "gw/monitor\|gw/trace\|gw/acl" /usr/sap/S4H/SYS/profile/DEFAULT.PFL',
            'DEFAULT.PFL: gw/monitor + gw/trace + gw/acl')

        # Run gwmon with help if found
        # gwmon is typically run as: gwmon pf=<profile>
        xpg(conn, '/usr/sap/S4H/SYS/exe/run/gwmon', 'help',
            'gwmon help (direct call)')

        # Try gwmon via gwrd path
        xpg(conn, '/usr/bin/find', '/sapmnt -name "gwmon" -type f',
            'Find gwmon in /sapmnt')

        # Check if gwmon is in PATH for s4hadm
        xpg(conn, '/usr/bin/which', 'gwmon',
            'which gwmon')

        # Check for SAP_S4H_00_GW port listeners
        xpg(conn, '/bin/ss', '-tlnp',
            'TCP listening ports (with process)')

        # Also check gwmon can connect to local GW
        # Run gwmon with gwrd profile to send getsta
        xpg(conn, '/usr/bin/ls', '-la /usr/sap/S4H/D00/exe/',
            'D00 exe directory (GW-specific executables)')

    # 2. Probe GW monitor protocol externally
    probe_gw_monitor()
    try_gw_monitor_commands()

    print("\n[*] Done.")


if __name__ == '__main__':
    main()
