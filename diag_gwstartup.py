#!/usr/bin/env python3
"""
diag_gwstartup.py — Read the current GW startup sequence from dev_rd,
check what happens with MS SYSLIST queries, and look at GwICheckSecInfo
context.
"""
import sys, time
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
        print('[+] RFC connected')

        # 1. How many lines is dev_rd total?
        xpg(conn, '/usr/bin/wc', '-l /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: line count')

        # 2. Read lines around the latest GW startup (DpShMCreate at line ~24980)
        #    The startup of the CURRENT GW (pid 25642) started around line 24975
        #    Read lines 24800-25400 to see full startup sequence
        xpg(conn, '/usr/bin/sed', '-n "24800,25400p" /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: lines 24800-25400 (current GW startup)')

        # 3. Read context around GwICheckSecInfo at line 26987
        #    Read lines 26900-27100 to see full secinfo check context
        xpg(conn, '/usr/bin/sed', '-n "26900,27100p" /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: lines 26900-27100 (GwICheckSecInfo context)')

        # 4. Search for ALL GwICheckSecInfo occurrences and surrounding lines
        xpg(conn, '/usr/bin/grep', '-n "GwICheckSecInfo" /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: all GwICheckSecInfo occurrences')

        # 5. Search for all GwSendRcToDp occurrences (these mark SAPXPG attempt results)
        xpg(conn, '/usr/bin/grep', '-n "GwSendRcToDp" /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: all GwSendRcToDp occurrences')

        # 6. Find the GW monitor port (gwmon) if available
        xpg(conn, '/usr/bin/find', '/usr/sap/S4H -name "gwmon*" -type f 2>/dev/null',
            'Find gwmon tool')

        # 7. Check if gwmon is in PATH
        xpg(conn, '/usr/bin/find', '/usr/sap/S4H/SYS/exe -type f -name "gwmon*" 2>/dev/null',
            'gwmon in SAP exe dir')

        # 8. Check the ms dev_ms for SERVER_ADD or GW-related messages
        xpg(conn, '/usr/bin/grep', '-n "SERVER_ADD\|MS_SERVER_ADD\|GwSys\|GwAdd\|gwsys" /usr/sap/S4H/ASCS01/work/dev_ms',
            'dev_ms: grep SERVER_ADD / GwSys')

        # 9. List dev_ms entries that mention GW or "trusted" or "hosttab"
        xpg(conn, '/usr/bin/grep', '-c "." /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: line count (sanity check)')

        # 10. Check if there's a gw_log with useful info (MS queries at startup)
        xpg(conn, '/usr/bin/tail', '-50 /usr/sap/S4H/D00/work/gw_log-2026-04-11',
            'gw_log tail-50')

        # 11. grep gw_log for any SYSLIST / MS / hosttab keywords
        xpg(conn, '/usr/bin/grep', '-i "syslist\|sys_list\|MS_GET\|hosttab\|internal\|gwsyst\|nilist" /usr/sap/S4H/D00/work/gw_log-2026-04-11',
            'gw_log: grep SYSLIST/hosttab/NILIST keywords')

        print('\n[*] Done.')


if __name__ == '__main__':
    main()
