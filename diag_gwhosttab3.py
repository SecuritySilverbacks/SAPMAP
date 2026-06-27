#!/usr/bin/env python3
"""
diag_gwhosttab3.py — Read GW log, instance profile, and ASCS01 MS trace.
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

        # 1. Instance profile — GW parameters
        xpg(conn, '/bin/cat', '/usr/sap/S4H/SYS/profile/S4H_D00_s4hanadev',
            'Instance profile S4H_D00_s4hanadev')

        # 2. Today's GW log — startup and NILIST/GwHostTab activity
        xpg(conn, '/bin/cat', '/usr/sap/S4H/D00/work/gw_log-2026-04-11',
            'gw_log-2026-04-11 (full)')

        # 3. ASCS01 work directory
        xpg(conn, '/bin/ls', '-la /usr/sap/S4H/ASCS01/work/',
            'ASCS01/work listing')

        # 4. MS trace in ASCS01
        xpg(conn, '/usr/bin/tail', '-100 /usr/sap/S4H/ASCS01/work/dev_ms',
            'ASCS01 dev_ms tail-100')

        # 5. Grep for our IP and nilist in ASCS01 MS trace
        xpg(conn, '/usr/bin/grep', '-i "192.168.2.210\|nilist\|GwHostTab\|LOGIN" /usr/sap/S4H/ASCS01/work/dev_ms',
            'ASCS01 dev_ms: grep our IP / LOGIN / NILIST')

        # 6. Instance profile for ASCS01 (MS)
        xpg(conn, '/bin/cat', '/usr/sap/S4H/SYS/profile/S4H_ASCS01_s4hanadev',
            'ASCS01 instance profile')

        # 7. gw/acl_info file (static GwHostTab override)
        xpg(conn, '/bin/cat', '/usr/sap/S4H/SYS/global/gw_acl_info',
            'gw_acl_info (if exists)')

        xpg(conn, '/bin/cat', '/usr/sap/S4H/SYS/global/acl_info',
            'acl_info (if exists)')

        # 8. GW trace (dev_rd = Road in old versions)
        xpg(conn, '/usr/bin/grep', '-i "nilist\|GwHost\|hostadr\|trusted\|internal" /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: grep GwHostTab/nilist')

        print('\n[*] Done.')


if __name__ == '__main__':
    main()
