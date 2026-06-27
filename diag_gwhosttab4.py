#!/usr/bin/env python3
"""
diag_gwhosttab4.py — Deeper dev_rd and ASCS01/dev_ms inspection.
"""
import sys
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')

from sap_rfc_ctypes import RFCConnection

SDK    = '/home/joris/Desktop/nwrfc750P_18-70002752/nwrfcsdk/lib/libsapnwrfc.so'
HOST   = '192.168.2.209'
SYSNR  = '00'
CLIENT = '001'
USER   = 'joris'
PASSWD = 'SccAdmin123!'


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

        # 1. dev_rd — last 300 lines (GW startup activities)
        xpg(conn, '/usr/bin/tail', '-300 /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd tail-300 (GW trace)')

        # 2. dev_rd — search for any keyword suggesting MS queries or host list
        xpg(conn, '/usr/bin/grep', '-i "192.168.2.210\|gwsys\|dispatcher\|register\|gwrd\|hosttab\|gwhost\|GwGetCon\|getNi\|getni\|nihost\|reg_no" /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: grep host/register/nilist keywords')

        # 3. ASCS01/dev_ms — last 100 lines
        xpg(conn, '/usr/bin/tail', '-100 /usr/sap/S4H/ASCS01/work/dev_ms',
            'ASCS01 dev_ms tail-100')

        # 4. ASCS01/dev_ms — any trace of our betrusted fake server?
        xpg(conn, '/usr/bin/grep', '-c "." /usr/sap/S4H/ASCS01/work/dev_ms',
            'ASCS01 dev_ms: line count')

        # 5. List ASCS01 work dir
        xpg(conn, '/bin/ls', '-la /usr/sap/S4H/ASCS01/work/',
            'ASCS01 work dir listing')

        # 6. What GW parameters are actually active at runtime?
        #    Try: gw monitor via gwrd -dp pipe
        #    Alt: read sapxpg.trc or dev_xpg
        xpg(conn, '/bin/cat', '/usr/sap/S4H/D00/work/dev_xpg',
            'dev_xpg content')

        # 7. GW monitor - check what IPs are in gwsys table
        #    The gwrd responds to SIGINT/SIGUSR with table dumps
        #    Try checking /usr/sap/S4H/D00/work for any gwmon output
        xpg(conn, '/bin/ls', '-la /usr/sap/S4H/D00/',
            'D00 instance dir listing')

        # 8. Check rdisp mshost to confirm which MS the GW connects to
        xpg(conn, '/usr/bin/grep', '-i "mshost\|msserv\|gw/" /usr/sap/S4H/SYS/profile/S4H_D00_s4hanadev',
            'Instance profile: mshost/gw params')

        print('\n[*] Done.')


if __name__ == '__main__':
    main()
