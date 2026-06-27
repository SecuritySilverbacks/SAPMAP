#!/usr/bin/env python3
"""
diag_ms_trace.py — Read ASCS01 MS trace and dev_rd around GW startup.
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

        # 1. ASCS01 dev_ms - tail to see current entries
        xpg(conn, '/usr/bin/tail', '-200 /usr/sap/S4H/ASCS01/work/dev_ms',
            'ASCS01 dev_ms tail-200')

        # 2. ASCS01 dev_ms.new if exists
        xpg(conn, '/usr/bin/tail', '-100 /usr/sap/S4H/ASCS01/work/dev_ms.new',
            'ASCS01 dev_ms.new tail-100')

        # 3. ASCS01 work dir listing
        xpg(conn, '/bin/ls', '-la /usr/sap/S4H/ASCS01/work/',
            'ASCS01 work dir')

        # 4. dev_rd - grep for key GW startup terms (MS query, dispatcher register, gwsys)
        xpg(conn, '/usr/bin/grep', '-i "MsGet\|MsSet\|ms_get\|ms_send\|nilist\|gwsyst\|gwsys\|dispatcher\|SYSLIST\|syslist\|GwSys\|gwhost\|GetSys\|getsys" /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: grep MS query / syslist / GwSys terms')

        # 5. dev_rd - first 100 lines (GW initialization, shows what it does at startup)
        xpg(conn, '/usr/bin/head', '-100 /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd head-100 (GW startup)')

        # 6. Check if gw/acl_info parameter exists or can be set
        xpg(conn, '/usr/bin/grep', '-r "gw/acl_info\|gw_acl\|acl_info" /usr/sap/S4H/SYS/profile/',
            'profile: grep gw/acl_info')

        # 7. Check gwsys.dat or similar static host files
        xpg(conn, '/usr/bin/find', '/usr/sap/S4H -name "gwsys*" -o -name "*.acl" -o -name "gwhost*"',
            'find gwsys/gwhost/acl files')

        print('\n[*] Done.')


if __name__ == '__main__':
    main()
