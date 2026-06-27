#!/usr/bin/env python3
"""
diag_gwhosttab2.py — Find GW/MS trace files and read GwHostTab data.
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
    print(f"  {prog} {params}")
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

        # Find all dev_gw and dev_ms files anywhere
        xpg(conn, '/usr/bin/find', '/usr/sap -name "dev_gw*" -o -name "dev_ms*" 2>/dev/null',
            'find all dev_gw* and dev_ms* files')

        # Broader search
        xpg(conn, '/usr/bin/find', '/usr/sap -name "dev_*" -newer /usr/sap/S4H/D00/data/prxyinfo',
            'find dev_* files newer than prxyinfo (recent activity)')

        # List work directories
        xpg(conn, '/bin/ls', '-la /usr/sap/S4H/D00/work/',
            'D00/work listing')

        xpg(conn, '/bin/ls', '-la /usr/sap/S4H/',
            'S4H instance dirs')

        # dev_ms.new — current MS trace
        xpg(conn, '/usr/bin/tail', '-200 /usr/sap/S4H/D00/work/dev_ms.new',
            'dev_ms.new tail-200')

        # grep our IP and nilist in dev_ms.new
        xpg(conn, '/usr/bin/grep', '-i "192.168.2.210\|nilist\|GwHostTab\|hostadr\|NILIST" /usr/sap/S4H/D00/work/dev_ms.new',
            'dev_ms.new: grep our IP / NILIST')

        # Instance profile — find the right name
        xpg(conn, '/bin/ls', '-la /usr/sap/S4H/SYS/profile/',
            'SYS/profile listing')

        # GW executable location
        xpg(conn, '/usr/bin/find', '/usr/sap -name "gwrd" -ls 2>/dev/null',
            'find gwrd binary')

        # GW process info
        xpg(conn, '/bin/ps', 'aux',
            'ps aux (find gwrd PID)')

        print('\n[*] Done.')


if __name__ == '__main__':
    main()
