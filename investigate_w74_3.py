#!/usr/bin/env python3
"""
investigate_w74_3.py — Read secinfo.DAT, dev_rd details, check gw/reg_no_conn_info
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

        # 1. Read the secinfo.DAT
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c type C:\usr\sap\W74\DVEBMGS40\data\secinfo.DAT',
             "Read secinfo.DAT")

        # 2. Read the gw_log files
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c dir C:\usr\sap\W74\DVEBMGS40\work\gw_log* /b',
             "List gw_log files")

        # 3. Read the latest gw_log
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c dir C:\usr\sap\W74\DVEBMGS40\work\gw_log* /b /o-d',
             "List gw_log files (newest first)")

        # 4. Read dev_rd - search for our IP and for reg_no_conn_info and hosttab
        sxpg(conn, r"C:\Windows\System32\findstr.exe",
             r'/i "192.168.2.210 192.168.2.11 ubuntu reg_no_conn local_addr hosttab HOSTTAB NILIST nilist intern" C:\usr\sap\W74\DVEBMGS40\work\dev_rd',
             "Search dev_rd for relevant entries")

        # 5. Read dev_rd header to see GW configuration
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c more /e +0 C:\usr\sap\W74\DVEBMGS40\work\dev_rd',
             "Read dev_rd (first part)")

        # 6. Read the DVEBMGS40 instance profile for all params
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c type C:\usr\sap\W74\SYS\profile\W74_DVEBMGS40_WINWAS740',
             "Read DVEBMGS40 instance profile")

        # 7. Check DVEBMGS40 variations (there are .1 through .6)
        sxpg(conn, r"C:\Windows\System32\findstr.exe",
             r'/i /s "gw/ secinfo activate_keyword reg_no" C:\usr\sap\W74\SYS\profile\W74_DVEBMGS40*',
             "Search gw/secinfo/activate params in DVEBMGS40 profiles")

        # 8. What does the MS log say about our betrusted registrations?
        # Search for ubuntu or 192.168.2.210 in dev_ms
        sxpg(conn, r"C:\Windows\System32\findstr.exe",
             r'/i "ubuntu 192.168.2.210 192.168.2.11 MS_SERVER_ADD NILIST DpInfo dp_version MsSendDpInfo" C:\usr\sap\W74\ASCS41\work\dev_ms',
             "Search dev_ms for our registrations")

        # 9. Check the hostname resolution
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c nslookup ubuntu 2>&1',
             "Resolve 'ubuntu' hostname on W74")

        # 10. Check hosts file
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c type C:\Windows\System32\drivers\etc\hosts',
             "Read Windows hosts file")

        print("\n\n[*] Investigation complete.")

if __name__ == '__main__':
    main()
