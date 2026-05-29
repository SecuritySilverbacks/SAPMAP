"""
sap_snc.py — Pure-Python SAP SNC posture scanner.

Reimplementation of usdAG's sncscan (https://github.com/usdAG/sncscan) without
the pysap/scapy dependency.  Two probes, both unauthenticated and
non-disruptive:

    scan_snc_diag(host, port, timeout, saprouter="")    DIAG / port 32NN
    scan_snc_router(host, port, timeout, saprouter="")  SAProuter / port 3299

The probe sends one SAPSNCFrame INIT_REQ wrapped in the appropriate carrier
(SAPDiag with compress=2 / SAPRouter CONTROL opcode=70) and inspects the
reply.  Frame type 0x04 (ACCEPT) in the response means SNC is enabled and we
read mech_id (e.g. Kerberos), QoP byte (snc/data_protection/use|max|min) and
CryptoLib banner.  Anything else means SNC is disabled or unavailable.

DIAG-only bonus: a second plaintext TERM_INI is sent on a fresh connection.
If the server rejects it with err_no=1 the kernel parameter
``snc/only_encrypted_gui`` is enforced.

The 97-byte SNC token and the ext_fields blobs are copied verbatim from
sncscan — they are a fixed Kerberos GSS-API skeleton that every SAP server
accepts for the INIT exchange.

Wire format derived from pysap (GPLv2 — Martin Gallo / SecureAuth, OWASP CBAS):

    SAPSNCFrame layout (all big-endian):
       0  StrFixed   eye_catcher       8 bytes  "SNCFRAME"
       8  Byte       frame_type        1 byte
       9  Byte       protocol_version  1 byte
      10  Short      header_length     2 bytes
      12  Int        token_length      4 bytes
      16  Int        data_length       4 bytes
      20  Short      mech_id           2 bytes
      22  Short      flags             2 bytes  (QoP byte in low octet)
      -- if header_length > 24 --
      24  Int        ext_flags         4 bytes
      28  Short      ext_field_length  2 bytes
      30  StrLen     ext_fields        ext_field_length bytes
      -- token + data --
       +  StrLen     token             token_length bytes
       +  StrLen     data              data_length bytes
"""

from __future__ import annotations

import socket
import struct
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Fixed 97-byte Kerberos GSS-API token used by sncscan for the INIT_REQ.
# OID 1.3.6.1.4.5.21.1 (SAP's GSS-API namespace) + dummy authenticator.
SNC_TOKEN = (
    b"\x30\x82\x00\x61\x06\x06\x2b\x24\x03\x01\x25\x01\xa0\x82\x00\x55"
    b"\xa1\x53\x04\x15\x04\x01\x01\x01\x00\x02\x01\x03\x02\x01\x02\x02"
    b"\x02\x03\x02\x02\x03\x01\x02\x01\x04\x04\x20\x64\x9d\x49\xe3\x4a"
    b"\x7d\xf7\xc8\x79\x0b\x59\x12\x5b\x7d\xc8\xda\xc8\xd7\x79\xa2\xfe"
    b"\xd1\xe5\xd7\xaf\x29\x03\x07\x94\x58\x4f\x55\xa1\x18\x30\x0b\x02"
    b"\x01\x03\x04\x06\x00\x09\x00\x0a\x00\x0b\x30\x09\x02\x01\x02\x04"
    b"\x04\x24\x3b\x9d\x64"
)
# Token is a single ASN.1 SEQUENCE: 0x30 0x82 0x00 0x61 = SEQUENCE,
# length-of-content 0x61 (97), so total length is 4 header + 97 = 101 bytes.
assert len(SNC_TOKEN) == 101

# DIAG ext_fields: X.500 DN "CN=NPL".  34 bytes.
SNC_EXT_DIAG = (
    b"\x00\x03\x04\x01\x00\x08\x06\x06\x2b\x24\x03\x01\x25\x01\x00\x00"
    b"\x00\x10\x30\x0e\x31\x0c\x30\x0a\x06\x03\x55\x04\x03\x13\x03\x4e"
    b"\x50\x4c"
)
assert len(SNC_EXT_DIAG) == 34

# Router ext_fields: X.500 DN "CN=MYSAPROUTER2".  43 bytes.
SNC_EXT_ROUTER = (
    b"\x00\x03\x04\x01\x00\x08\x06\x06\x2b\x24\x03\x01\x25\x01\x00\x00"
    b"\x00\x19\x30\x17\x31\x15\x30\x13\x06\x03\x55\x04\x03\x13\x0c\x4d"
    b"\x59\x53\x41\x50\x52\x4f\x55\x54\x45\x52\x32"
)
assert len(SNC_EXT_ROUTER) == 43

SNC_DATA = b"Internal SNC-Adapter (Rev 1.1) to CommonCryptoLib\x00\x00\x00\x00"

SNC_EYE_CATCHER = b"SNCFRAME"

# Frame types
SNC_FRAME_REVERSE_REQ = 0x00
SNC_FRAME_INIT_REQ    = 0x01
SNC_FRAME_INIT        = 0x02   # what pysap (and sncscan) send for the client INIT
SNC_FRAME_INIT_ACK    = 0x03
SNC_FRAME_ACCEPT      = 0x04
SNC_FRAME_REJECTED    = 0x0c

# Mechanism IDs (server-side identifier of the SNC library in use).
SNC_MECH_ID = {
    0x00: "No security",
    0x01: "Generic GSS-API v2",
    0x02: "Kerberos 5 / GSS-API v2",
    0x03: "Secude 5 / GSS-API v2",
    0x04: "SAP NTLM (SSPI)",
    0x05: "SPKM1 GSS-API v2",
    0x06: "SPKM2 GSS-API v2",
    0x07: "reserved",
    0x08: "itsec",
    0x09: "SDTI Connect Agent",
    0x0a: "AccessMaster DCE",
}

# QoP levels (2-bit groups inside the flags byte)
SNC_QOP = {
    0: "INVALID",
    1: "OPEN",
    2: "INTEGRITY",
    3: "PRIVACY",
}


# ---------------------------------------------------------------------------
# SAPSNCFrame builder / parser
# ---------------------------------------------------------------------------

def _build_snc_frame(*, flags: int, ext_fields: bytes,
                     frame_type: int = SNC_FRAME_INIT,
                     protocol_version: int = 6,
                     mech_id: int = 3,
                     token: bytes = SNC_TOKEN,
                     data: bytes = SNC_DATA) -> bytes:
    """Pack a SAPSNCFrame.  Header length is computed from ext_fields presence."""
    fixed_header_len = 24                       # bytes 0..23 (no ext)
    if ext_fields:
        header_length = fixed_header_len + 4 + 2 + len(ext_fields)
    else:
        header_length = fixed_header_len

    out = bytearray()
    out += SNC_EYE_CATCHER                                   # 0..7
    out += struct.pack("!B", frame_type)                     # 8
    out += struct.pack("!B", protocol_version)               # 9
    out += struct.pack("!H", header_length)                  # 10..11
    out += struct.pack("!I", len(token))                     # 12..15
    out += struct.pack("!I", len(data))                      # 16..19
    out += struct.pack("!H", mech_id)                        # 20..21
    out += struct.pack("!H", flags)                          # 22..23
    if ext_fields:
        out += struct.pack("!I", 1)                          # ext_flags
        out += struct.pack("!H", len(ext_fields))            # ext_field_length
        out += ext_fields
    out += token
    out += data
    return bytes(out)


def _parse_snc_frame(blob: bytes) -> Optional[dict]:
    """Locate and parse a SAPSNCFrame inside ``blob``.

    Searches for the ``SNCFRAME`` eye-catcher rather than assuming a
    fixed offset, since responses come back wrapped in different carriers
    (DIAG: DP+SAPDiag header; Router: NI_RTERR header).  Returns None if
    no valid frame is found.
    """
    idx = blob.find(SNC_EYE_CATCHER)
    if idx < 0 or len(blob) - idx < 24:
        return None

    p = blob[idx:]
    try:
        frame_type       = p[8]
        protocol_version = p[9]
        header_length    = struct.unpack("!H", p[10:12])[0]
        token_length     = struct.unpack("!I", p[12:16])[0]
        data_length      = struct.unpack("!I", p[16:20])[0]
        mech_id          = struct.unpack("!H", p[20:22])[0]
        flags            = struct.unpack("!H", p[22:24])[0]
    except struct.error:
        return None

    ext_flags = 0
    ext_fields = b""
    cursor = 24
    if header_length > 24:
        if len(p) < cursor + 6:
            return None
        try:
            ext_flags = struct.unpack("!I", p[cursor:cursor + 4])[0]
            ext_field_length = struct.unpack(
                "!H", p[cursor + 4:cursor + 6])[0]
        except struct.error:
            return None
        cursor += 6
        if len(p) < cursor + ext_field_length:
            return None
        ext_fields = p[cursor:cursor + ext_field_length]
        cursor += ext_field_length

    if len(p) < cursor + token_length + data_length:
        # Truncated — keep what we can but flag incomplete
        token = p[cursor:cursor + token_length] \
            if len(p) >= cursor + token_length else b""
        data  = b""
    else:
        token = p[cursor:cursor + token_length]
        data  = p[cursor + token_length:cursor + token_length + data_length]

    qop_byte = flags & 0xFF
    qop_use = (qop_byte & 0b1100000) >> 5
    qop_max = (qop_byte & 0b0011000) >> 3
    qop_min = (qop_byte & 0b0000110) >> 1

    cryptolib = ""
    if data:
        try:
            cryptolib = data.split(b"\x00", 1)[0].decode("utf-8", "replace")
        except UnicodeDecodeError:
            cryptolib = data[:64].decode("latin-1", "replace")

    return {
        "frame_type":       frame_type,
        "protocol_version": protocol_version,
        "header_length":    header_length,
        "token_length":     token_length,
        "data_length":      data_length,
        "mech_id":          mech_id,
        "mech_id_label":    SNC_MECH_ID.get(mech_id, f"unknown (0x{mech_id:02x})"),
        "flags":            flags,
        "qop_use":          qop_use,
        "qop_max":          qop_max,
        "qop_min":          qop_min,
        "qop_use_label":    SNC_QOP.get(qop_use, "unknown"),
        "qop_max_label":    SNC_QOP.get(qop_max, "unknown"),
        "qop_min_label":    SNC_QOP.get(qop_min, "unknown"),
        "ext_flags":        ext_flags,
        "ext_fields":       ext_fields,
        "token":            token,
        "data":             data,
        "cryptolib":        cryptolib,
    }


# ---------------------------------------------------------------------------
# DIAG carrier
# ---------------------------------------------------------------------------

def _build_diag_dp_header(payload_len: int, terminal: str = "sncscan") -> bytes:
    """200-byte SAPDiagDP header.  Mirrors build_diag_term_ini() in
    sap_rfc_system_info.py — request_id=-1, retcode=0x0a, length=payload_len."""
    dp = bytearray()
    dp += struct.pack("<i", -1)
    dp += b"\x0a"
    dp += b"\x00"
    dp += b"\x00"
    dp += struct.pack("<I", 0)
    dp += struct.pack("<i", -1)
    dp += struct.pack("<h", -1)
    dp += b"\xff"
    dp += struct.pack("<i", -1)
    dp += struct.pack("<i", -1)
    dp += struct.pack("<i", -1)
    dp += struct.pack("<I", payload_len)
    dp += b"\x00"
    dp += struct.pack("<i", -1)
    dp += struct.pack("<h", -1)
    dp += b"\x20" * 40
    dp += terminal.encode("ascii")[:15].ljust(15, b"\x00")
    dp += b"\x00" * 10
    dp += b"\x20" * 20
    dp += struct.pack("<I", 0)
    dp += struct.pack("<I", 0)
    dp += struct.pack("<i", -1)
    dp += struct.pack("<I", 0)
    dp += b"\x01"
    dp += b"\x00" * 57
    assert len(dp) == 200
    return bytes(dp)


def _build_diag_snc_init() -> bytes:
    """SAPDiagDP + SAPDiag(compress=2, TERM_INI) + SAPSNCFrame, wrapped in NI."""
    snc_frame = _build_snc_frame(flags=0x2a, ext_fields=SNC_EXT_DIAG)

    diag = bytearray()
    diag += b"\x00"        # mode
    diag += b"\x10"        # com_flag_TERM_INI bit (bit 4 from MSB)
    diag += b"\x00"        # mode_stat
    diag += b"\x00"        # err_no
    diag += b"\x00"        # msg_type
    diag += b"\x00"        # msg_info
    diag += b"\x00"        # msg_rc
    diag += b"\x02"        # compress = 2 → SNC frame follows
    diag += snc_frame

    payload = _build_diag_dp_header(len(diag)) + bytes(diag)
    return struct.pack("!I", len(payload)) + payload


def _build_diag_plain_term_ini() -> bytes:
    """Plain (no-SNC) TERM_INI used to probe ``snc/only_encrypted_gui``."""
    # Minimal items: UserConnect (DIALOG_STEP) + SupportData.  Server with
    # snc/only_encrypted_gui=1 rejects this with err_no=1.
    diag = bytearray()
    diag += b"\x00"        # mode
    diag += b"\x10"        # com_flag_TERM_INI
    diag += b"\x00\x00\x00\x00\x00"   # mode_stat..msg_rc
    diag += b"\x00"        # compress = 0

    # UserConnect item: APPL / ST_USER / DIALOG_STEP / 12 bytes
    diag += b"\x10\x04\x02"
    diag += struct.pack("!H", 12)
    diag += struct.pack("!I", 100200)   # protocol_version
    diag += struct.pack("!I", 1100)     # code_page
    diag += struct.pack("!I", 3000)     # ws_type

    # SupportData item: APPL / ST_USER / 0x0B / 32 bytes
    diag += b"\x10\x04\x0b"
    diag += struct.pack("!H", 32)
    diag += bytes.fromhex(
        "ff7ffa0d78b737def6196e9325bf1593ef73feebdb5501000000000000000000")

    payload = _build_diag_dp_header(len(diag)) + bytes(diag)
    return struct.pack("!I", len(payload)) + payload


# ---------------------------------------------------------------------------
# SAProuter carrier
# ---------------------------------------------------------------------------

def _build_router_snc_init() -> bytes:
    """SAPRouter CONTROL opcode=70 carrying a SAPSNCFrame, wrapped in NI."""
    snc_frame = _build_snc_frame(flags=0x7e, ext_fields=SNC_EXT_ROUTER)

    pkt = bytearray()
    pkt += b"NI_RTERR\x00"             # type
    pkt += struct.pack("!B", 40)       # version
    pkt += struct.pack("!B", 70)       # opcode = SNC init
    pkt += struct.pack("!B", 0)        # opcode_padd
    pkt += struct.pack("!i", 0)        # return_code
    pkt += struct.pack("!I", 0)        # control_text_length
    pkt += snc_frame
    return struct.pack("!I", len(pkt)) + bytes(pkt)


# ---------------------------------------------------------------------------
# Socket plumbing — direct or via SAProuter tunnel
# ---------------------------------------------------------------------------

def _open_socket(host: str, port: int, timeout: float,
                 saprouter: str = "") -> socket.socket:
    """Direct TCP, or NI_ROUTE tunnel through a SAProuter prefix.

    The tunneled socket from connect_through_saprouter() is a transparent TCP
    pipe — DIAG / Router bytes flow over it unchanged.
    """
    if saprouter:
        # Lazy import to keep sap_snc usable in tests without the module path
        # being set up via modules/__init__.py side-effects.
        from sap_saprouter import (
            build_route_for_port, connect_through_saprouter,
        )
        route = build_route_for_port(saprouter, host, port)
        return connect_through_saprouter(route, timeout=timeout, talk_mode=0)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    return sock


def _send_recv(sock: socket.socket, packet: bytes,
               max_bytes: int = 16384) -> bytes:
    """Send one NI-framed packet, read one NI-framed reply.

    Returns the full reply including the 4-byte NI length header so callers
    can use the same parsing helpers on either carrier.
    """
    sock.sendall(packet)

    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            return hdr
        hdr += chunk

    resp_len = struct.unpack("!I", hdr)[0]
    if resp_len <= 0 or resp_len > max_bytes:
        return hdr

    body = b""
    remaining = resp_len
    while remaining > 0:
        chunk = sock.recv(min(remaining, 65536))
        if not chunk:
            break
        body += chunk
        remaining -= len(chunk)
    return hdr + body


# ---------------------------------------------------------------------------
# Result helpers
# ---------------------------------------------------------------------------

def _empty_result(protocol: str, host: str, port: int) -> dict:
    return {
        "checked":    True,
        "protocol":   protocol,
        "host":       host,
        "port":       port,
        "enabled":    False,
        "enforced":   False,           # DIAG-only — snc/only_encrypted_gui
        "qop_use":    0,
        "qop_max":    0,
        "qop_min":    0,
        "qop_flag":   0,
        "mech_id":    0,
        "mech_label": "",
        "cryptolib":  "",
        "error":      "",
    }


def _result_from_frame(base: dict, frame: dict) -> dict:
    base["enabled"]    = (frame["frame_type"] == SNC_FRAME_ACCEPT)
    base["qop_flag"]   = frame["flags"] & 0xFF
    base["qop_use"]    = frame["qop_use"]
    base["qop_max"]    = frame["qop_max"]
    base["qop_min"]    = frame["qop_min"]
    base["mech_id"]    = frame["mech_id"]
    base["mech_label"] = frame["mech_id_label"]
    base["cryptolib"]  = frame["cryptolib"]
    return base


# ---------------------------------------------------------------------------
# Public probes
# ---------------------------------------------------------------------------

def scan_snc_diag(host: str, port: int, timeout: float = 8.0,
                  saprouter: str = "") -> dict:
    """Probe SNC on an ABAP dispatcher port (32NN).

    Returns a dict with keys:
        checked, protocol, host, port, enabled, enforced, qop_use, qop_max,
        qop_min, qop_flag, mech_id, mech_label, cryptolib, error
    """
    result = _empty_result("diag", host, port)

    # ---- Probe 1: SNC INIT_REQ ----
    sock = None
    try:
        sock = _open_socket(host, port, timeout, saprouter)
        reply = _send_recv(sock, _build_diag_snc_init())
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
        return result
    except (ConnectionError, OSError) as e:
        result["error"] = f"connect_error: {e}"
        return result
    finally:
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass

    if len(reply) < 12:
        result["error"] = "short_response"
        return result

    frame = _parse_snc_frame(reply)
    if frame:
        _result_from_frame(result, frame)
    else:
        # No SNCFrame in response → SNC disabled.  We could look for the
        # literal "SNC" substring in the DIAG info field as additional
        # negative-confirmation, but its absence does not change the
        # verdict — keep it simple.
        result["enabled"] = False

    if not result["enabled"]:
        return result

    # ---- Probe 2: only_encrypted_gui (DIAG-only) ----
    sock2 = None
    try:
        sock2 = _open_socket(host, port, timeout, saprouter)
        reply2 = _send_recv(sock2, _build_diag_plain_term_ini())
    except Exception:
        # Failure here just means we couldn't confirm enforcement — leave
        # ``enforced`` as False rather than masking the primary success.
        return result
    finally:
        try:
            if sock2 is not None:
                sock2.close()
        except Exception:
            pass

    # Locate the SAPDiag header in the reply (4B NI len + 200B DP or no DP
    # for error responses).  err_no lives at byte 3 of the SAPDiag header.
    if len(reply2) >= 4:
        ni_len = struct.unpack("!I", reply2[:4])[0]
        body = reply2[4:4 + ni_len]
        # Short error response: 8B Diag header directly after NI.
        # Long login response: 200B DP header + 8B Diag header.
        for diag_off in (0, 200):
            if len(body) >= diag_off + 8:
                err_no = body[diag_off + 3]
                if err_no == 1:
                    result["enforced"] = True
                    break

    return result


def scan_snc_router(host: str, port: int = 3299, timeout: float = 8.0,
                    saprouter: str = "") -> dict:
    """Probe SNC on a SAProuter (default port 3299).

    Returns the same dict shape as scan_snc_diag().  The ``enforced`` field is
    not meaningful for routers and stays False.
    """
    result = _empty_result("router", host, port)

    sock = None
    try:
        sock = _open_socket(host, port, timeout, saprouter)
        reply = _send_recv(sock, _build_router_snc_init())
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
        return result
    except (ConnectionError, OSError) as e:
        result["error"] = f"connect_error: {e}"
        return result
    finally:
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass

    frame = _parse_snc_frame(reply)
    if frame:
        _result_from_frame(result, frame)
    else:
        result["enabled"] = False
    return result


# ---------------------------------------------------------------------------
# Human-readable summary (used by GUI / report)
# ---------------------------------------------------------------------------

def format_summary(info: dict) -> str:
    """One-line summary, e.g. 'SNC: enabled (Kerberos, QoP 3/3/3, enforced)'."""
    if not info or not info.get("checked"):
        return "SNC: not checked"
    if info.get("error") and not info.get("enabled"):
        return f"SNC: probe failed ({info['error']})"
    if not info.get("enabled"):
        return "SNC: not enabled"
    parts = []
    if info.get("mech_label"):
        parts.append(info["mech_label"])
    parts.append(
        f"QoP {info.get('qop_use', 0)}/"
        f"{info.get('qop_max', 0)}/{info.get('qop_min', 0)}"
    )
    if info.get("protocol") == "diag":
        parts.append("enforced" if info.get("enforced") else "not enforced")
    return "SNC: enabled (" + ", ".join(parts) + ")"
