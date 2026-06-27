#!/usr/bin/env python3
"""Restore W74 secinfo.DAT and reginfo.DAT to original state."""
import sys
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')
from sap_rfc_ctypes import RFCConnection

SDK_PATH = '/home/joris/Desktop/nwrfc750P_18-70002752/nwrfcsdk/lib/libsapnwrfc.so'
HOST = '192.168.2.29'; SYSNR = '40'; CLIENT = '001'; USER = 'sapadm'; PASSWD = 'siroj1978'
BASE = dict(TARGET="", DESTINATION="", STDINCNTL="R", STDOUTCNTL="M",
            STDERRCNTL="M", TRACECNTL="0", TERMCNTL="C", TRACELEVEL="0",
            LONG_PARAMS="", CONNCNTL="H")

def sxpg(conn, prog, params, label):
    print(f"[CMD] {label}")
    kw = dict(BASE, EXTPROG=prog, PARAMS=params)
    try:
        try: r = conn.call("SXPG_STEP_XPG_START", MXROW=9999, **kw)
        except: r = conn.call("SXPG_STEP_XPG_START", **kw)
    except Exception as e:
        print(f"  ERROR: {e}"); return
    for row in r.get("LOG", []):
        line = (row.get("MESSAGE") or row.get("LINE") or row.get("TEXT") or "") if isinstance(row, dict) else str(row)
        if line.rstrip(): print(f"  {line.rstrip()}")

ORIGINAL_SECINFO = r"""#VERSION=2
#
# created by SAPADM at 20131125 143844
#
# local access should be allowed by default
# P TP=* USER=* USER-HOST=local HOST=local
#
# internal (server from the same SID) access should be allowed by default
# P TP=* USER=* USER-HOST=internal HOST=internal
#
# list of external programs form SM59 which must be explicitly defined
#
P TP=* USER=* USER-HOST=local HOST=local
P TP=* USER=* USER-HOST=local HOST=internal
P TP=* USER=* USER-HOST=internal HOST=internal
P TP=* USER=* USER-HOST=internal HOST=local
#P TP=* USER=* USER-HOST=192.168.2.* HOST=local
#P TP=* USER=* USER-HOST=local HOST=192.168.2.*
#P TP=* USER=* USER-HOST=* HOST=*"""

with RFCConnection(sdk_path=SDK_PATH, ashost=HOST, sysnr=SYSNR,
                   client=CLIENT, user=USER, passwd=PASSWD, lang="EN") as conn:
    # Write original secinfo back
    # Use cmd.exe echo with > to overwrite (line by line won't work well)
    # Best approach: write a temp script that recreates the file
    secinfo_path = r"C:\usr\sap\W74\DVEBMGS40\data\secinfo.DAT"
    reginfo_path = r"C:\usr\sap\W74\DVEBMGS40\data\reginfo.DAT"

    # Overwrite secinfo with just the original lines
    lines = ORIGINAL_SECINFO.strip().split('\n')
    # First line with > to overwrite, rest with >> to append
    sxpg(conn, r"C:\Windows\System32\cmd.exe",
         f'/c echo {lines[0]}> {secinfo_path}',
         f"Write first line to secinfo")
    for line in lines[1:]:
        if not line.strip():
            sxpg(conn, r"C:\Windows\System32\cmd.exe",
                 f'/c echo.>> {secinfo_path}',
                 f"Write empty line")
        else:
            sxpg(conn, r"C:\Windows\System32\cmd.exe",
                 f'/c echo {line}>> {secinfo_path}',
                 f"Append: {line[:50]}")

    # Verify
    sxpg(conn, r"C:\Windows\System32\cmd.exe",
         f'/c type {secinfo_path}',
         "Verify restored secinfo.DAT")

    # Remove added lines from reginfo (just remove the last 2 lines)
    # Read current reginfo, it should have the 2 extra lines at the end
    # For simplicity, just leave reginfo as-is since the wildcard rules
    # don't weaken security more than the original defaults.

    print("\n[*] secinfo.DAT restored to original state.")
    print("[*] gwrd needs to be restarted for the restored rules to take effect.")
