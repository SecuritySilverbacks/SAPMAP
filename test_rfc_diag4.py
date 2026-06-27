#!/usr/bin/env python3
"""
test_rfc_diag4.py — Read GW log + secinfo/reginfo + try dynamic param change.
"""
import sys
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')
from sap_rfc_ctypes import RFCConnection

SDK_PATH = '/home/joris/Desktop/nwrfc750P_18-70002752/nwrfcsdk/lib/libsapnwrfc.so'
HOST='192.168.2.209'; SYSNR='00'; CLIENT='001'; USER='joris'; PASSWD='Schaap123!'

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
    for row in r.get("LOG", []):
        line = (row.get("MESSAGE") or row.get("LINE") or row.get("TEXT") or "") if isinstance(row, dict) else str(row)
        line = line.rstrip()
        if line: print(f"  {line}")
    print(f"  [exit={r.get('STATUS','?')!r}]")

def main():
    print(f"[*] Connecting...")
    with RFCConnection(sdk_path=SDK_PATH, ashost=HOST, sysnr=SYSNR,
                       client=CLIENT, user=USER, passwd=PASSWD, lang="EN") as conn:
        print("[+] OK\n")

        # Read today's GW log
        sxpg(conn, "/usr/bin/tail", "-100 /usr/sap/S4H/D00/work/gw_log-2026-04-11",
             "GW log today (last 100 lines)")

        # Read secinfo and reginfo files (GW ACL)
        sxpg(conn, "/usr/bin/find",
             "/usr/sap/S4H/SYS/global/ -name secinfo -o -name reginfo",
             "Find secinfo/reginfo ACL files")

        sxpg(conn, "/usr/bin/find",
             "/usr/sap/S4H/ -name secinfo.dat -maxdepth 5",
             "Find secinfo.dat")

        sxpg(conn, "/usr/bin/find",
             "/usr/sap/S4H/ -name reginfo.dat -maxdepth 5",
             "Find reginfo.dat")

        # Read instance profile for D00
        sxpg(conn, "/usr/bin/grep",
             "-i gw/ /usr/sap/S4H/SYS/profile/S4H_D00_s4hanadev",
             "Instance profile GW params (D00)")

        # Try dynamic parameter change via dpmon / gwmon
        # The GW monitor allows changing gw/ params at runtime
        sxpg(conn, "/usr/bin/find",
             "/usr/sap/S4H/D00/exe/ -name gwmon",
             "Find gwmon binary")

        # Try calling SUSR_INTERNET_USERADR directly to get secinfo path
        # Or use rsparam to read parameter value
        sxpg(conn, "/usr/sap/S4H/D00/exe/rsparam",
             "gw/reg_no_conn_info",
             "Current gw/reg_no_conn_info value via rsparam")

        sxpg(conn, "/usr/sap/S4H/D00/exe/rsparam",
             "gw/sec_info",
             "secinfo file path via rsparam")

        sxpg(conn, "/usr/sap/S4H/D00/exe/rsparam",
             "gw/reg_info",
             "reginfo file path via rsparam")

        # Read dev_rd (GW registration trace)
        sxpg(conn, "/usr/bin/tail",
             "-50 /usr/sap/S4H/D00/work/dev_rd",
             "GW registration trace (dev_rd) - last 50 lines")

        # Read dev_ms (MS trace - shows server registration)
        sxpg(conn, "/usr/bin/tail",
             "-50 /usr/sap/S4H/D00/work/dev_ms",
             "MS trace (dev_ms) - last 50 lines")

        print("\n[*] Done.")

if __name__ == '__main__':
    main()
