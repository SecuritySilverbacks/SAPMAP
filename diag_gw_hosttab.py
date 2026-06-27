#!/usr/bin/env python3
"""
diag_gw_hosttab.py — Check dev_rd for GW-MS connection and trace GwHostTab updates.

Also read the full SERVER SNAPSHOT to find other table sections.
And check: does the GW connect to the MS as a client (which would mean it
receives MS_SERVER_ADD)?
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

        # 1. dev_rd: check if GW appears as a CLIENT in the MS trace
        #    The GW would connect to MS and receive SERVER_ADD events
        #    Look for GW connecting outbound to MS
        xpg(conn, '/usr/bin/grep', '-n "SERVER_ADD\|SERVER_SUB\|SERVER_MOD\|HOSTADR\|hosttab\|GwAddSys\|GwDelSys\|GwModSys\|CLIENT\|sysadd\|sysmod\|sysdel\|connect.*3901\|3901.*connect" /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: grep SERVER events / GwAddSys / MS connect')

        # 2. dev_rd: look for all GW → MS interaction
        xpg(conn, '/usr/bin/grep', '-c "." /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd line count')

        # 3. Check if the GW connects to the MS at all (ss -tn)
        xpg(conn, '/bin/ss', '-tnp',
            'Active TCP connections with process info')

        # 4. Check what port the GW is connected to (should be 3901 for MS)
        xpg(conn, '/bin/ss', '-tn',
            'All TCP connections')

        # 5. dev_rd: search for MS hostname/port references
        xpg(conn, '/usr/bin/grep', '-i "3901\|39NN\|msserv\|msg_server\|ms_connect\|GwMsCon\|gwmscon" /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: grep MS port 3901 / MS connect')

        # 6. Check the ASCS01 dev_ms to see if the GW (hdl?) is connected
        #    GW connects to MS as client; look for 'gwrd' or 's4hanadev' as client
        xpg(conn, '/usr/bin/grep', '-n "client 1\|gwrd\|gateway" /usr/sap/S4H/ASCS01/work/dev_ms',
            'ASCS01 dev_ms: grep GW connection as client')

        # 7. List all registered servers from the MS currently
        #    Use RFC: read SMLG or use SAPXPG to dump MS server list
        xpg(conn, '/usr/bin/grep', '-n "LOGIN\|LOGOUT\|client" /usr/sap/S4H/ASCS01/work/dev_ms_audit',
            'dev_ms_audit: grep LOGIN/LOGOUT events')

        print('\n[*] Done.')


if __name__ == '__main__':
    main()
