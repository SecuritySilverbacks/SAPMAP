#!/usr/bin/env python3
"""
investigate_w74.py — Read MS/disp logs and profile parameters on W74 system
to debug why betrusted doesn't propagate to disp+work.
"""
import sys
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')
from sap_rfc_ctypes import RFCConnection

SDK_PATH = '/home/joris/Desktop/nwrfc750P_18-70002752/nwrfcsdk/lib/libsapnwrfc.so'
HOST = '192.168.2.29'
SYSNR = '40'
CLIENT = '001'
USER = 'sapadm'
PASSWD = 'TestPass123'

BASE = dict(TARGET="", DESTINATION="", STDINCNTL="R", STDOUTCNTL="M",
            STDERRCNTL="M", TRACECNTL="0", TERMCNTL="C", TRACELEVEL="0",
            LONG_PARAMS="", CONNCNTL="H")

def sxpg(conn, prog, params, label):
    print(f"\n{'='*70}")
    print(f"[CMD] {label}")
    print(f"  {prog} {params}")
    print(f"{'='*70}")
    kw = dict(BASE, EXTPROG=prog, PARAMS=params)
    try:
        try:
            r = conn.call("SXPG_STEP_XPG_START", MXROW=9999, **kw)
        except Exception as e:
            if "MXROW" in str(e) or "RFC_INVALID" in str(e):
                r = conn.call("SXPG_STEP_XPG_START", **kw)
            else:
                print(f"  ERROR: {e}")
                return None
    except Exception as e:
        print(f"  ERROR: {e}")
        return None
    for row in r.get("LOG", []):
        line = (row.get("MESSAGE") or row.get("LINE") or row.get("TEXT") or "") if isinstance(row, dict) else str(row)
        line = line.rstrip()
        if line:
            print(f"  {line}")
    status = r.get("STATUS", "?")
    print(f"  [exit={status!r}]")
    return r

def main():
    print(f"[*] Connecting to W74 at {HOST}:{SYSNR} client={CLIENT} user={USER}")
    with RFCConnection(sdk_path=SDK_PATH, ashost=HOST, sysnr=SYSNR,
                       client=CLIENT, user=USER, passwd=PASSWD, lang="EN") as conn:
        print("[+] Connected\n")

        # 1. Find the SAP directory structure on W74
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c dir C:\usr\sap\W74 /b',
             "List W74 SAP directory")

        # 2. Find MS work directory (SCS41 instance)
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c dir C:\usr\sap\W74\SCS41\work /b',
             "List SCS41 work directory (MS)")

        # 3. Read MS log (dev_ms) - last 100 lines
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c type C:\usr\sap\W74\SCS41\work\dev_ms | more +0',
             "Read dev_ms (MS log)")

        # 4. Find the D40 work directory
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c dir C:\usr\sap\W74\D40\work /b',
             "List D40 work directory")

        # 5. Read dev_disp (dispatcher log) - look for SERVER_ADD
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c type C:\usr\sap\W74\D40\work\dev_disp',
             "Read dev_disp (dispatcher log)")

        # 6. Read dev_w0 (work process log)
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c type C:\usr\sap\W74\D40\work\dev_w0',
             "Read dev_w0 (work process 0 log)")

        # 7. Read profile parameters
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c dir C:\usr\sap\W74\SYS\profile /b',
             "List profile directory")

        # 8. Read DEFAULT.PFL
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c type C:\usr\sap\W74\SYS\profile\DEFAULT.PFL',
             "Read DEFAULT.PFL (profile params)")

        # 9. Read secinfo on this system
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c dir C:\usr\sap\W74\SYS\global /b',
             "List global directory")

        # 10. Read the secinfo file
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c type C:\usr\sap\W74\SYS\global\secinfo',
             "Read secinfo file")

        # 11. Read instance profile for D40
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c dir C:\usr\sap\W74\SYS\profile\W74_D40* /b',
             "Find D40 instance profile")

        # 12. Check MS parameters - ms/monitor, ms/server_port_0
        sxpg(conn, r"C:\Windows\System32\findstr.exe",
             r'/i "ms/" C:\usr\sap\W74\SYS\profile\DEFAULT.PFL',
             "MS-related params in DEFAULT.PFL")

        # 13. Check GW parameters
        sxpg(conn, r"C:\Windows\System32\findstr.exe",
             r'/i "gw/" C:\usr\sap\W74\SYS\profile\DEFAULT.PFL',
             "GW-related params in DEFAULT.PFL")

        # 14. Check for reg_info / reg_no_conn_info
        sxpg(conn, r"C:\Windows\System32\findstr.exe",
             r'/i "reg_" C:\usr\sap\W74\SYS\profile\DEFAULT.PFL',
             "reg_ params in DEFAULT.PFL")

        print("\n\n[*] Investigation complete.")

if __name__ == '__main__':
    main()
