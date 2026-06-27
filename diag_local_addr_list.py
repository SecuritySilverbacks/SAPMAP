#!/usr/bin/env python3
"""
diag_local_addr_list.py — Investigate gw/local_gw_addr_list parameter.

Found in gwrd binary: local_gw_addr_list, localalias, localhost_addr, localhostfull_addr.
These are likely profile parameters for extending the GW's LOCAL IP classification.

gw/local_gw_addr_list = 192.168.2.210 could be the key:
  Adds 192.168.2.210 to LOCAL IP set without /etc/hosts modification.
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
                print(f'  [RFC error] {e}'); return None
    except Exception as e:
        print(f'  [call failed] {e}'); return None

    status = r.get('STATUS', '?')
    log = r.get('LOG', [])
    if not log:
        print(f'  (no output, status={status!r})')
        return None
    lines = []
    for row in log:
        line = (row.get('MESSAGE') or row.get('LINE') or row.get('TEXT') or '').rstrip() \
               if isinstance(row, dict) else str(row).rstrip()
        if line:
            print(f'  {line}')
            lines.append(line)
    print(f'  [status={status!r}]')
    return lines


def main():
    with RFCConnection(sdk_path=SDK, ashost=HOST, sysnr=SYSNR,
                       client=CLIENT, user=USER, passwd=PASSWD, lang='EN') as conn:
        print('[+] RFC connected\n')

        # 1. Search dev_rd for ANY occurrence of local_gw_addr_list
        xpg(conn, '/usr/bin/grep',
            '-n local_gw_addr_list /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: local_gw_addr_list occurrences')

        # 2. Search dev_rd for localalias
        xpg(conn, '/usr/bin/grep',
            '-n localalias /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: localalias occurrences')

        # 3. Search gw_log for local_gw_addr_list
        xpg(conn, '/usr/bin/grep',
            '-n local_gw_addr_list /usr/sap/S4H/D00/work/gw_log-2026-04-11',
            'gw_log: local_gw_addr_list occurrences')

        # 4. Count local_gw_addr_list occurrences in gwrd binary
        xpg(conn, '/usr/bin/grep',
            '-ao local_gw_addr_list /usr/sap/S4H/D00/exe/gwrd',
            'gwrd binary: local_gw_addr_list all matches (count them)')

        # 5. Count localalias in gwrd binary
        xpg(conn, '/usr/bin/grep',
            '-ao localalias /usr/sap/S4H/D00/exe/gwrd',
            'gwrd binary: localalias all matches')

        # 6. Check if sapcontrol shows current value of gw/local_gw_addr_list
        xpg(conn, '/usr/sap/S4H/D00/exe/sapcontrol',
            '-nr 00 -function ParameterValue gw/local_gw_addr_list',
            'sapcontrol: current value of gw/local_gw_addr_list')

        # 7. Check sapcontrol for localalias
        xpg(conn, '/usr/sap/S4H/D00/exe/sapcontrol',
            '-nr 00 -function ParameterValue gw/localalias',
            'sapcontrol: current value of gw/localalias')

        # 8. Try sapcontrol AllConfigParameters to see all GW params
        xpg(conn, '/usr/sap/S4H/D00/exe/sapcontrol',
            '-nr 00 -function AllConfigParameters',
            'sapcontrol: all config parameters')

        # 9. Check if there's a profile_snapshot with current GW config
        xpg(conn, '/bin/ls',
            '-la /usr/sap/S4H/SYS/global/profile_snapshot/',
            'profile_snapshot directory contents')

        # 10. Read the profile snapshot for GW-related entries
        xpg(conn, '/usr/bin/grep',
            '-i local /usr/sap/S4H/SYS/global/profile_snapshot/default.pfl',
            'profile snapshot: local entries')

        # 11. Check prxyinfo file (recently written Apr 11)
        xpg(conn, '/bin/cat',
            '/usr/sap/S4H/SYS/global/prxyinfo',
            'prxyinfo file content')

        # 12. Check ms_acl_info
        xpg(conn, '/bin/cat',
            '/usr/sap/S4H/SYS/global/ms_acl_info',
            'ms_acl_info content')

        # 13. sapcontrol ParameterValue for gw/local_gw_addr_list (via gwrd path)
        xpg(conn, '/usr/sap/host/exe/sapcontrol',
            '-nr 00 -function ParameterValue gw/local_gw_addr_list',
            'host sapcontrol: gw/local_gw_addr_list')

        # 14. Look at ms/server_addr_list (might be relevant for MS)
        xpg(conn, '/usr/bin/grep',
            '-ao local_gw_addr_list /usr/sap/S4H/D00/exe/disp+work',
            'disp+work binary: local_gw_addr_list')

        # 15. Look for localalias in disp+work
        xpg(conn, '/usr/bin/grep',
            '-ao localalias /usr/sap/S4H/D00/exe/disp+work',
            'disp+work binary: localalias')

        print('\n[*] Done.')


if __name__ == '__main__':
    main()
