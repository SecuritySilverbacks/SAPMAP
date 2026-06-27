#!/usr/bin/env python3
"""
test_rfc_diag.py — Use RFC to run diagnostic commands on the SAP server.

Diagnoses why the SAP GW never connects to our NILIST listener.
Credentials: client=001, user=joris, passwd=Schaap123!
"""
import sys
sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')

from sap_rfc_ctypes import RFCConnection

SDK_PATH = '/home/joris/Desktop/nwrfc750P_18-70002752/nwrfcsdk/lib/libsapnwrfc.so'
HOST     = '192.168.2.209'
SYSNR    = '00'
CLIENT   = '001'
USER     = 'joris'
PASSWD   = 'Schaap123!'
ATT_IP   = '192.168.2.210'

# SXPG_STEP_XPG_START with DESTINATION="" runs locally.
# EXTPROG and PARAMS: SAP passes them directly to execv, NOT through a shell.
# PARAMS is split on whitespace into individual argv elements.
# Do NOT use shell features (pipes, &&, quotes) — call programs directly.

def run_prog(conn, extprog: str, params: str, label: str):
    print(f"\n{'='*60}")
    print(f"[CMD] {label}")
    print(f"  {extprog} {params}")
    print('='*60)
    kwargs = dict(
        TARGET="",
        DESTINATION="",
        EXTPROG=extprog,
        PARAMS=params,
        STDINCNTL="R",
        STDOUTCNTL="M",
        STDERRCNTL="M",
        TRACECNTL="0",
        TERMCNTL="C",
        TRACELEVEL="0",
        LONG_PARAMS="",
        CONNCNTL="H",
    )
    try:
        try:
            r = conn.call("SXPG_STEP_XPG_START", MXROW=9999, **kwargs)
        except Exception as e:
            if "MXROW" in str(e) or "RFC_INVALID_PARAMETER" in str(e):
                r = conn.call("SXPG_STEP_XPG_START", **kwargs)
            else:
                print(f"  [!] RFC error: {e}")
                return
    except Exception as e:
        print(f"  [!] Call failed: {e}")
        return

    status = r.get("STATUS", "?")
    log = r.get("LOG", [])
    if not log:
        print(f"  (no output, status={status!r})")
        return
    for row in log:
        if isinstance(row, dict):
            line = (row.get("MESSAGE") or row.get("LINE") or row.get("TEXT") or "").rstrip()
        else:
            line = str(row).rstrip()
        if line:
            print(f"  {line}")
    print(f"  [status={status!r}]")


def main():
    print(f"[*] Connecting to {HOST}:{SYSNR} client={CLIENT} user={USER}")
    with RFCConnection(sdk_path=SDK_PATH, ashost=HOST, sysnr=SYSNR,
                       client=CLIENT, user=USER, passwd=PASSWD, lang="EN") as conn:
        print("[+] RFC connected!\n")

        # 1. Who we are on the SAP server
        run_prog(conn, "/usr/bin/id", "", "Identity (id)")
        run_prog(conn, "/bin/hostname", "", "Hostname")

        # 2. iptables outbound rules — does SAP server block TCP to 192.168.2.210?
        run_prog(conn, "/sbin/iptables", "-L OUTPUT -n -v",
                 "iptables OUTPUT chain")

        # 3. ip route — can the SAP server route to our IP?
        run_prog(conn, "/sbin/ip", f"route get {ATT_IP}",
                 f"Route to {ATT_IP}")

        # 4. Ping test — is there L3 connectivity?
        run_prog(conn, "/bin/ping", f"-c 3 -W 2 {ATT_IP}",
                 f"Ping {ATT_IP}")

        # 5. GW developer trace — grep for nilist / host requests
        run_prog(conn, "/usr/bin/grep",
                 f"-i nilist /usr/sap/S4H/DVEBMGS00/work/dev_gw",
                 "GW trace: nilist entries")

        run_prog(conn, "/usr/bin/tail",
                 "-50 /usr/sap/S4H/DVEBMGS00/work/dev_gw",
                 "GW trace: last 50 lines")

        # 6. GW security profile parameters
        run_prog(conn, "/bin/grep",
                 "-i gw/sec /usr/sap/S4H/SYS/profile/S4H_DVEBMGS00_s4hanadev",
                 "GW security profile parameters")

        # 7. Active TCP connections from SAP → our IP
        run_prog(conn, "/bin/ss", f"-tn dst {ATT_IP}",
                 f"Active TCP conns to {ATT_IP}")

        # 8. netstat — check any connections to our IP
        run_prog(conn, "/bin/netstat", f"-tn",
                 "All established TCP connections")

        # 9. Check if we can TCP connect to our port (Python tcp test)
        # Write a small Python script to /tmp then execute it
        import base64
        py_code = (
            f"import socket,sys\n"
            f"s=socket.socket()\n"
            f"s.settimeout(5)\n"
            f"try:\n"
            f"    s.connect(('{ATT_IP}',33200))\n"
            f"    print('TCP_CONNECT_OK_33200')\n"
            f"    s.close()\n"
            f"except Exception as e:\n"
            f"    print('TCP_CONNECT_FAIL_33200: '+str(e))\n"
        )
        # Write script using tee (stdin piped, but no stdin here — use Python directly)
        # Try python3 -c approach via LONG_PARAMS (may bypass the 255-char PARAMS limit)
        py_oneliner = (
            f"import socket,sys;"
            f"s=socket.socket();"
            f"s.settimeout(5);"
            f"s.connect(('{ATT_IP}',33200));"
            f"print('TCP_OK');"
            f"s.close()"
        )
        kwargs2 = dict(
            TARGET="",
            DESTINATION="",
            EXTPROG="/usr/bin/python3",
            PARAMS="",
            LONG_PARAMS=f"-c {py_oneliner}",
            STDINCNTL="R",
            STDOUTCNTL="M",
            STDERRCNTL="M",
            TRACECNTL="0",
            TERMCNTL="C",
            TRACELEVEL="0",
            CONNCNTL="H",
        )
        print(f"\n{'='*60}")
        print(f"[CMD] TCP connectivity test to {ATT_IP}:33200 (Python via LONG_PARAMS)")
        print('='*60)
        try:
            try:
                r2 = conn.call("SXPG_STEP_XPG_START", MXROW=9999, **kwargs2)
            except Exception as e2:
                if "MXROW" in str(e2) or "RFC_INVALID_PARAMETER" in str(e2):
                    r2 = conn.call("SXPG_STEP_XPG_START", **kwargs2)
                else:
                    print(f"  [!] RFC error: {e2}")
                    r2 = {}
            for row in r2.get("LOG", []):
                if isinstance(row, dict):
                    line = (row.get("MESSAGE") or row.get("LINE") or row.get("TEXT") or "").rstrip()
                else:
                    line = str(row).rstrip()
                if line:
                    print(f"  {line}")
            print(f"  [status={r2.get('STATUS','?')!r}]")
        except Exception as e:
            print(f"  [!] {e}")

        print("\n[*] Diagnostics complete.")


if __name__ == '__main__':
    main()
