#!/usr/bin/env python3
"""
diag_internal_keyword.py — Investigate gw/activate_keyword_internal.

Also check gw/local_addr, and read dev_rd for the new gwrd startup to understand
how LOCAL and INTERNAL are built.
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
    print(f"\n[CMD] {label}")
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
    log = r.get('LOG', [])
    lines = []
    for row in log:
        line = (row.get('MESSAGE') or row.get('LINE') or row.get('TEXT') or '').rstrip() \
               if isinstance(row, dict) else str(row).rstrip()
        if line:
            print(f'  {line}')
            lines.append(line)
    if not lines:
        print(f'  (no output)')
    return lines


def main():
    with RFCConnection(sdk_path=SDK, ashost=HOST, sysnr=SYSNR,
                       client=CLIENT, user=USER, passwd=PASSWD, lang='EN') as conn:
        print('[+] RFC connected\n')

        # 1. Check current value of gw/activate_keyword_internal
        xpg(conn, '/usr/sap/S4H/D00/exe/sapcontrol',
            '-nr 00 -function ParameterValue gw/activate_keyword_internal',
            'Current gw/activate_keyword_internal')

        # 2. Check current gw/local_addr
        xpg(conn, '/usr/sap/S4H/D00/exe/sapcontrol',
            '-nr 00 -function ParameterValue gw/local_addr',
            'Current gw/local_addr')

        # 3. Check current gw/alternative_hostnames
        xpg(conn, '/usr/sap/S4H/D00/exe/sapcontrol',
            '-nr 00 -function ParameterValue gw/alternative_hostnames',
            'Current gw/alternative_hostnames')

        # 4. Get line count of dev_rd (to know where new startup begins)
        xpg(conn, '/usr/bin/wc', '-l /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd line count (total)')

        # 5. Read last 100 lines of dev_rd (should include new gwrd startup)
        xpg(conn, '/usr/bin/tail',
            '-100 /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: last 100 lines (new gwrd startup)')

        # 6. Search dev_rd for "alternative" keyword (did gwrd log it?)
        xpg(conn, '/usr/bin/grep',
            '-n alternative /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: alternative_hostnames in startup log')

        # 7. Search dev_rd for "activate" keyword
        xpg(conn, '/usr/bin/grep',
            '-n activate /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: activate keyword in log')

        # 8. Search dev_rd for "keyword_internal" in log
        xpg(conn, '/usr/bin/grep',
            '-n keyword_internal /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: keyword_internal occurrences')

        # 9. Search for "INTERNAL" population messages in dev_rd
        xpg(conn, '/usr/bin/grep',
            '-n GWSYST /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: GWSYST table population messages')

        # 10. Check gw/local_addr in gwrd binary for context
        xpg(conn, '/usr/bin/grep',
            '-ao local_addr /usr/sap/S4H/D00/exe/gwrd',
            'gwrd binary: local_addr occurrences')

        # 11. Check what gw/alternative_hostnames string context is in gwrd binary
        #     Get byte offset to examine surrounding data
        xpg(conn, '/usr/bin/grep',
            '-aob alternative_hostnames /usr/sap/S4H/D00/exe/gwrd',
            'gwrd binary: alternative_hostnames byte offset')

        # 12. Check activate_keyword_internal in gwrd binary
        xpg(conn, '/usr/bin/grep',
            '-aob activate_keyword_internal /usr/sap/S4H/D00/exe/gwrd',
            'gwrd binary: activate_keyword_internal byte offset')

        # 13. Check what GW knows about alternative_hostnames
        #     Try adding the IP directly to gw/alternative_hostnames
        #     If it resolves to IPs, those would be LOCAL
        xpg(conn, '/usr/bin/getent',
            'hosts ubuntu',
            'getent hosts ubuntu (what IPs GW would add to LOCAL from alt_hostnames)')

        # 14. Check dev_rd right after new gwrd startup at 17:51:57
        #     Look for how GW determines LOCAL IPs at startup
        xpg(conn, '/usr/bin/grep',
            '-n "192.168.2" /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: all lines mentioning 192.168.2.* IPs')

        print('\n[*] Done.')


if __name__ == '__main__':
    main()
