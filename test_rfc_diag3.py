#!/usr/bin/env python3
"""
test_rfc_diag3.py — GW trace + profile check (D00 instance path).
"""
import sys
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')
from sap_rfc_ctypes import RFCConnection

SDK_PATH = '/home/joris/Desktop/nwrfc750P_18-70002752/nwrfcsdk/lib/libsapnwrfc.so'
HOST='192.168.2.209'; SYSNR='00'; CLIENT='001'; USER='joris'; PASSWD='SccAdmin123!'
ATT_IP='192.168.2.210'

BASE = dict(TARGET="", DESTINATION="", STDINCNTL="R", STDOUTCNTL="M",
            STDERRCNTL="M", TRACECNTL="0", TERMCNTL="C", TRACELEVEL="0",
            LONG_PARAMS="", CONNCNTL="H")

def sxpg(conn, prog, params, label):
    print(f"\n[CMD] {label}")
    print(f"  {prog} {params}")
    kw = dict(BASE, EXTPROG=prog, PARAMS=params)
    try:
        try:   r = conn.call("SXPG_STEP_XPG_START", MXROW=9999, **kw)
        except Exception as e:
            if "MXROW" in str(e) or "RFC_INVALID" in str(e):
                r = conn.call("SXPG_STEP_XPG_START", **kw)
            else:
                print(f"  ERROR: {e}"); return
    except Exception as e:
        print(f"  ERROR: {e}"); return
    lines = []
    for row in r.get("LOG", []):
        line = (row.get("MESSAGE") or row.get("LINE") or row.get("TEXT") or "") if isinstance(row, dict) else str(row)
        line = line.rstrip()
        if line: lines.append(line)
    for l in lines: print(f"  {l}")
    if not lines: print(f"  (no output)")
    print(f"  [exit={r.get('STATUS','?')!r}]")

def main():
    print(f"[*] Connecting...")
    with RFCConnection(sdk_path=SDK_PATH, ashost=HOST, sysnr=SYSNR,
                       client=CLIENT, user=USER, passwd=PASSWD, lang="EN") as conn:
        print("[+] OK\n")

        # GW work dir is D00, not DVEBMGS00
        sxpg(conn, "/bin/ls", "/usr/sap/S4H/D00/work/",
             "List D00 work dir")

        # dev_gw trace - last 80 lines
        sxpg(conn, "/usr/bin/tail", "-80 /usr/sap/S4H/D00/work/dev_gw",
             "GW trace: last 80 lines")

        # Grep GW trace for nilist/trust entries
        sxpg(conn, "/usr/bin/grep",
             f"-i nilist /usr/sap/S4H/D00/work/dev_gw",
             "GW trace: nilist entries")

        sxpg(conn, "/usr/bin/grep",
             f"-i trusted /usr/sap/S4H/D00/work/dev_gw",
             "GW trace: trusted entries")

        sxpg(conn, "/usr/bin/grep",
             f"-i {ATT_IP} /usr/sap/S4H/D00/work/dev_gw",
             f"GW trace: entries for {ATT_IP}")

        # Read GW profile - D00 instance
        sxpg(conn, "/bin/ls", "/usr/sap/S4H/SYS/profile/",
             "List profile directory")

        # GW profile gw/reg_no_conn_info (key 10KBlaze mitigation param)
        sxpg(conn, "/usr/bin/grep",
             "-ri gw/ /usr/sap/S4H/SYS/profile/",
             "GW parameters from profile")

        # Read the DEFAULT.PFL
        sxpg(conn, "/usr/bin/find",
             "/usr/sap/S4H/SYS/profile/ -maxdepth 1 -type f",
             "Profile files list")

        # Check gw/reg_no_conn_info specifically (SAP Note 2408073)
        sxpg(conn, "/usr/bin/grep",
             "-ri reg_no_conn /usr/sap/S4H/",
             "gw/reg_no_conn_info parameter (10KBlaze mitigation)")

        # Also check gw/acl_mode and gw/sec_info
        sxpg(conn, "/usr/bin/grep",
             "-ri gw/acl /usr/sap/S4H/",
             "gw/acl_mode parameter")

        print("\n[*] Done.")

if __name__ == '__main__':
    main()
