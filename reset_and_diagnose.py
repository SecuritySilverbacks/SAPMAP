#!/usr/bin/env python3
"""
reset_and_diagnose.py — Reset secinfo to default, then deep-dive into
why gw/activate_keyword_internal stays at 0 despite DEFAULT.PFL.

Steps:
  1. Revert secinfo to the 3 default lines
  2. Check instance profile (may override DEFAULT.PFL)
  3. List ALL profile files gwrd reads at startup
  4. Check sapstartsrv's view vs. running gwrd via SMGW-ish monitor commands
"""
import sys
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')
from sap_rfc_ctypes import RFCConnection

SDK  = '/home/joris/Desktop/nwrfc750P_18-70002752/nwrfcsdk/lib/libsapnwrfc.so'
HOST = '192.168.2.209'

SECINFO = '/usr/sap/S4H/SYS/global/secinfo'
DEFAULT_PFL = '/usr/sap/S4H/SYS/profile/DEFAULT.PFL'
INSTANCE_PFL = '/usr/sap/S4H/SYS/profile/S4H_D00_s4hanadev'


def xpg(conn, prog, params, label=''):
    if label:
        print(f'[CMD] {label}')
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
                print(f'  [RFC error] {e}'); return []
    except Exception as e:
        print(f'  [call failed] {e}'); return []
    out = []
    for row in r.get('LOG', []):
        line = (row.get('MESSAGE') or row.get('LINE') or row.get('TEXT') or '').rstrip() \
               if isinstance(row, dict) else str(row).rstrip()
        if line:
            print(f'  {line}')
            out.append(line)
    if not out:
        print('  (no output)')
    return out


def reset_secinfo(conn):
    """Overwrite secinfo with the original 3 rules only."""
    print('\n[1] Resetting secinfo to default')
    # Python one-liner that overwrites secinfo — no spaces allowed
    # Lines are: #VERSION=2, 3 default rules
    # Encode spaces as \x20, newlines as \n — both interpreted by remote python3
    lines = (
        '#VERSION=2\\n'
        'P\\x20USER=*\\x20USER-HOST=local\\x20HOST=local\\x20TP=*\\n'
        'P\\x20USER=*\\x20USER-HOST=local\\x20HOST=internal\\x20TP=*\\n'
        'P\\x20USER=*\\x20USER-HOST=internal\\x20HOST=local\\x20TP=*\\n'
    )
    py_code = (
        'f=open("' + SECINFO + '","w");'
        'f.write("' + lines + '");'
        'f.close()'
    )
    assert ' ' not in py_code, f'Space in py_code: {py_code!r}'
    xpg(conn, '/usr/bin/python3', f'-c {py_code}', 'Reset secinfo')
    xpg(conn, '/bin/cat', SECINFO, 'Verify secinfo content')


def diagnose_profile(conn):
    """Check whether the instance profile overrides gw/activate_keyword_internal."""
    print('\n[2] Inspecting profile overrides')

    # Instance profile existence
    xpg(conn, '/bin/ls', '-la /usr/sap/S4H/SYS/profile/', 'Profile directory')

    # Check DEFAULT.PFL for activate_keyword_internal
    xpg(conn, '/usr/bin/grep', f'activate_keyword_internal {DEFAULT_PFL}',
        'DEFAULT.PFL: activate_keyword_internal')

    # Check instance profile for activate_keyword_internal
    xpg(conn, '/usr/bin/grep', f'activate_keyword_internal {INSTANCE_PFL}',
        'Instance profile: activate_keyword_internal')

    # Check instance profile for all gw/ settings
    xpg(conn, '/usr/bin/grep', f'^gw/ {INSTANCE_PFL}',
        'Instance profile: all gw/ parameters')

    # Check ASCS instance profile too (S4H_ASCS01_s4hanadev?)
    xpg(conn, '/bin/ls', '/usr/sap/S4H/SYS/profile/',
        'Profile file list')

    # Check which profile gwrd uses
    xpg(conn, '/usr/bin/grep', 'profile /usr/sap/S4H/D00/work/dev_rd',
        'dev_rd: profile references')

    # Dev_rd startup: what profile file is read?
    xpg(conn, '/usr/bin/grep', '-n PFL /usr/sap/S4H/D00/work/dev_rd',
        'dev_rd: PFL mentions')


def check_gwrd_runtime(conn):
    """Query gwrd's actual runtime state via sapcontrol."""
    print('\n[3] Querying gwrd runtime state')
    # ParameterValue queries the PROFILE, not the running process!
    # But ParameterValue with the specific process via 'GetProcessParameter' hits the process.
    xpg(conn, '/usr/sap/S4H/D00/exe/sapcontrol',
        '-nr 00 -function ParameterValue gw/activate_keyword_internal',
        'ParameterValue (profile view)')

    # Try the snapshot
    xpg(conn, '/usr/bin/grep', 'activate_keyword_internal /usr/sap/S4H/SYS/global/profile_snapshot/',
        'profile_snapshot: activate_keyword_internal')

    # Check environment of running gwrd process
    lines = xpg(conn, '/usr/sap/S4H/D00/exe/sapcontrol',
                '-nr 00 -function GetProcessList', 'GetProcessList')
    gwrd_pid = None
    for l in lines:
        if 'gwrd' in l and ',' in l:
            parts = l.split(',')
            if len(parts) >= 7:
                try:
                    gwrd_pid = int(parts[6].strip())
                except Exception:
                    pass
    if gwrd_pid:
        print(f'  gwrd PID: {gwrd_pid}')
        # Check /proc/<pid>/cmdline
        xpg(conn, '/bin/cat', f'/proc/{gwrd_pid}/cmdline', 'gwrd cmdline')


def main():
    with RFCConnection(sdk_path=SDK, ashost=HOST, sysnr='00',
                       client='001', user='joris', passwd='Schaap123!', lang='EN') as conn:
        print('[+] RFC connected')
        reset_secinfo(conn)
        diagnose_profile(conn)
        check_gwrd_runtime(conn)


if __name__ == '__main__':
    main()
