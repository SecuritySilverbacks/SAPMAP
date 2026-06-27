#!/usr/bin/env python3
"""
diag_ms_login.py — Check ASCS01 dev_ms after a betrusted registration.
"""
import sys
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')

from sap_rfc_ctypes import RFCConnection

SDK    = '/home/joris/Desktop/nwrfc750P_18-70002752/nwrfcsdk/lib/libsapnwrfc.so'
HOST   = '192.168.2.209'
SYSNR  = '00'
CLIENT = '001'
USER   = 'joris'
PASSWD = 'Schaap123!'


def xpg(conn, prog, params, label):
    print(f"\n{'='*60}")
    print(f"[CMD] {label}")
    print('='*60)
    kw = dict(TARGET='', DESTINATION='', EXTPROG=prog, PARAMS=params,
              STDINCNTL='R', STDOUTCNTL='M', STDERRCNTL='M', TRACECNTL='0',
              TERMCNTL='C', TRACELEVEL='0', LONG_PARAMS='', CONNCNTL='H')
    try:
        try:
            r = conn.call('SXPG_STEP_XPG_START', MXROW=9999, **kw)
        except Exception as e:
            if 'MXROW' in str(e) or 'RFC_INVALID_PARAMETER' in str(e):
                r = conn.call('SXPG_STEP_XPG_START', **kw)
            else:
                print(f'  [RFC error] {e}'); return
    except Exception as e:
        print(f'  [call failed] {e}'); return

    status = r.get('STATUS', '?')
    log = r.get('LOG', [])
    if not log:
        print(f'  (no output, status={status!r})')
        return
    for row in log:
        line = (row.get('MESSAGE') or row.get('LINE') or row.get('TEXT') or '').rstrip() \
               if isinstance(row, dict) else str(row).rstrip()
        if line:
            print(f'  {line}')
    print(f'  [status={status!r}]')


def main():
    with RFCConnection(sdk_path=SDK, ashost=HOST, sysnr=SYSNR,
                       client=CLIENT, user=USER, passwd=PASSWD, lang='EN') as conn:
        print('[+] RFC connected')

        # Check ASCS01 dev_ms for recent entries (betrusted just ran)
        xpg(conn, '/usr/bin/tail', '-100 /usr/sap/S4H/ASCS01/work/dev_ms',
            'ASCS01 dev_ms tail-100 (post-betrusted test)')

        # Grep for our server name or connection-related terms
        xpg(conn, '/usr/bin/grep', '-i "192_168_2_210\|f55b\|client 2\|client 3\|LOGIN\|MsSLogin\|NiIAccept\|new conn\|LOGOUT\|disconnect\|REJECT" /usr/sap/S4H/ASCS01/work/dev_ms',
            'dev_ms: grep for betrusted server name or login events')

        # MS audit log — might show LOGIN/LOGOUT events
        xpg(conn, '/usr/bin/tail', '-50 /usr/sap/S4H/ASCS01/work/dev_ms_audit',
            'ASCS01 dev_ms_audit tail-50')

        # grep audit log for our IP/login
        xpg(conn, '/usr/bin/grep', '-i "192.168.2.210\|192_168\|LOGIN\|LOGOUT" /usr/sap/S4H/ASCS01/work/dev_ms_audit',
            'dev_ms_audit: grep our IP / login')

        print('\n[*] Done.')


if __name__ == '__main__':
    main()
