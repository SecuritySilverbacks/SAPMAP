#!/usr/bin/env python3
"""
diag_gw_params.py — Enumerate all valid gw/* profile parameters from snapshot
and test local_gw_addr_list / localalias.
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

        # 1. Read the ABAP instance profile snapshot (lists ALL known params)
        #    This is the most recent snapshot, contains all gw/* params the GW knows
        snapshot = '/usr/sap/S4H/SYS/global/profile_snapshot/S4H_D00_s4hanadev-20260408215829-ABAP_Instance.snapshot'
        xpg(conn, '/usr/bin/grep', f'-i gw/ {snapshot}',
            'Profile snapshot: all gw/* parameters')

        # 2. Search snapshot for local-related entries
        xpg(conn, '/usr/bin/grep', f'-i local {snapshot}',
            'Profile snapshot: local-related parameters')

        # 3. Look for localalias specifically in the snapshot
        xpg(conn, '/usr/bin/grep', f'localalias {snapshot}',
            'Profile snapshot: localalias entries')

        # 4. Try sapcontrol to list all GW parameters
        xpg(conn, '/usr/sap/S4H/D00/exe/sapcontrol',
            '-nr 00 -function GetProcessList',
            'sapcontrol: GetProcessList (check gwrd process)')

        # 5. Try sapcontrol ParameterValue for known-valid gw params
        xpg(conn, '/usr/sap/S4H/D00/exe/sapcontrol',
            '-nr 00 -function ParameterValue gw/sec_info',
            'sapcontrol: gw/sec_info (verify ParameterValue works)')

        xpg(conn, '/usr/sap/S4H/D00/exe/sapcontrol',
            '-nr 00 -function ParameterValue gw/acl_mode',
            'sapcontrol: gw/acl_mode')

        # 6. Now test gw/local_gw_addr_list (might be read from profile at startup)
        xpg(conn, '/usr/sap/S4H/D00/exe/sapcontrol',
            '-nr 00 -function ParameterValue gw/local_gw_addr_list',
            'sapcontrol: gw/local_gw_addr_list')

        # 7. Try different parameter name variants
        xpg(conn, '/usr/sap/S4H/D00/exe/sapcontrol',
            '-nr 00 -function ParameterValue gw/localalias',
            'sapcontrol: gw/localalias')

        xpg(conn, '/usr/sap/S4H/D00/exe/sapcontrol',
            '-nr 00 -function ParameterValue icm/local_addresses',
            'sapcontrol: icm/local_addresses')

        # 8. Check sapcontrol ListDynParameters (shows dynamically changeable params)
        xpg(conn, '/usr/sap/S4H/D00/exe/sapcontrol',
            '-nr 00 -function ListDynParameters',
            'sapcontrol: dynamically changeable parameters')

        # 9. Read the SNAPSHOT file - look at its format
        xpg(conn, '/usr/bin/head', f'-100 {snapshot}',
            'Profile snapshot: first 100 lines (format check)')

        # 10. Check dev_rd for "localalias" — even if parameter name differs in profile,
        #     the internal variable might appear in logs
        xpg(conn, '/usr/bin/grep',
            '-n localalias /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: localalias occurrences')

        # 11. Look for any gw/gwaddr or gw/gw_addr in snapshot or gwrd
        xpg(conn, '/usr/bin/grep',
            '-ao gwaddr /usr/sap/S4H/D00/exe/gwrd',
            'gwrd binary: gwaddr string')

        # 12. Look for "trusted" parameter in snapshot
        xpg(conn, '/usr/bin/grep',
            f'-i trusted {snapshot}',
            'Profile snapshot: trusted parameters')

        # 13. Check gw_log for any messages about local addr list
        xpg(conn, '/usr/bin/grep',
            '-i addr_list /usr/sap/S4H/D00/work/gw_log-2026-04-11',
            'gw_log: addr_list messages')

        # 14. Try to read a few lines around line where local_gw_addr_list appears in gwrd
        #     binary offset — use od to look at nearby bytes
        #     First find the byte offset
        xpg(conn, '/usr/bin/grep',
            '-aob local_gw_addr_list /usr/sap/S4H/D00/exe/gwrd',
            'gwrd binary: byte offset of local_gw_addr_list')

        print('\n[*] Done.')


if __name__ == '__main__':
    main()
