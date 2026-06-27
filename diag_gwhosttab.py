#!/usr/bin/env python3
"""
diag_gwhosttab.py — Read GwHostTab, /etc/hosts, dev_ms, dev_gw0 via RFC.
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

        # 1. /etc/hosts — why does "ubuntu" resolve to both IPs?
        xpg(conn, '/bin/cat', '/etc/hosts', '/etc/hosts')

        # 2. GW trace — startup NILIST / GwHostTab population
        xpg(conn, '/usr/bin/grep', '-i "nilist\|GwHost\|hostadr\|trusted\|internal\|host_tab\|NILIST" /usr/sap/S4H/D00/work/dev_gw0',
            'dev_gw0: grep nilist/GwHostTab')

        # 3. GW trace — last 150 lines (latest restart info)
        xpg(conn, '/usr/bin/tail', '-150 /usr/sap/S4H/D00/work/dev_gw0',
            'dev_gw0 tail-150')

        # 4. MS trace — does MS know about our fake server? Look for our IP and NILIST
        xpg(conn, '/usr/bin/grep', '-i "192.168.2.210\|nilist\|betrusted\|fake\|GwHostTab" /usr/sap/S4H/D00/work/dev_ms',
            'dev_ms: grep our IP / nilist')

        # 5. MS trace — last 100 lines
        xpg(conn, '/usr/bin/tail', '-100 /usr/sap/S4H/D00/work/dev_ms',
            'dev_ms tail-100')

        # 6. DEFAULT.PFL current state
        xpg(conn, '/bin/cat', '/usr/sap/S4H/SYS/profile/DEFAULT.PFL',
            'DEFAULT.PFL')

        # 7. Instance profile (may override DEFAULT.PFL)
        xpg(conn, '/bin/cat', '/usr/sap/S4H/SYS/profile/S4H_DVEBMGS00_s4hanadev',
            'Instance profile S4H_DVEBMGS00_s4hanadev')

        # 8. data dir listing
        xpg(conn, '/bin/ls', '-la /usr/sap/S4H/D00/data/',
            'data dir listing')

        # 9. GW trace path — find dev_gw* files
        xpg(conn, '/usr/bin/find', '/usr/sap/S4H -name "dev_gw*" -ls',
            'find dev_gw* files')

        print('\n[*] Done.')


if __name__ == '__main__':
    main()
