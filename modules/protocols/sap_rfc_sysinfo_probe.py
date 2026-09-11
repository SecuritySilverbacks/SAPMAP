"""sap_rfc_sysinfo_probe — anonymous RFC_SYSTEM_INFO probe (stdlib only).

Importable variant of tools/rfc_sysinfo.py for use inside SAPMAP's
enrichment pipeline.  Public API:

    probe_rfcsi(host, port=3300, timeout=5.0, client="001") -> dict

Returns the 20-field RFCSI_EXPORT record on success, or
``{"error": "<reason>"}`` on failure.  **Never raises** — callers
don't need try/except for the happy path.

Zero external deps — no pysap, no scapy, no NW RFC SDK, no
saprfclib.  Speaks SAP NI framing (4-byte big-endian length prefix)
directly over TCP.

Credit / prior art
==================
Extracted from Julian's randomstr1ng/sap-rfm-enum:
    https://github.com/randomstr1ng/sap-rfm-enum

Julian reverse-engineered the 80-byte APPC v6 header layout against
kernel 7.93 and demonstrated that the anonymous connect path can
dispatch RFC_SYSTEM_INFO, RFC_PING, and SYSTEM_INVISIBLE_GUI
pre-logon — returning real replies, not just error banners.

This module keeps only the RFC_SYSTEM_INFO path, drops the multi-FM
enumeration harness, and swaps pysap/scapy for stdlib NI framing +
a hand-rolled GW_NORMAL_CLIENT template (verified byte-identical
to what pysap emits).  Verified live against kernel 7.42, 7.53,
7.93.  A parallel standalone CLI lives at tools/rfc_sysinfo.py.

SAProuter tunneling is not implemented in this build.  If a
saprouter is passed, callers should fall back to the existing
sap_rfc_system_info chain, which handles it.
"""
from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import time


# ---------------------------------------------------------------------------
# EBCDIC / TLV codec
# ---------------------------------------------------------------------------

E2A = bytes(range(256)).decode("cp037").encode("latin-1")
A2E = bytes(range(256)).decode("latin-1").encode("cp037", "replace")

EYECATCHER = "RFC000000000".encode("cp037")
END_TAG = 0xFFFF

TAG_FLAGS1 = 0x0101
TAG_FLAGS2 = 0x0103
TAG_FLAGS3 = 0x0106
TAG_NONCE = 0x0514
TAG_CLIENT = 0x0114
TAG_USER = 0x0111
TAG_PASSWD = 0x0117
TAG_LANG = 0x0115
TAG_TRACE = 0x0501
TAG_LOCAL_IP = 0x0007
TAG_LOCAL_IP6 = 0x0018
TAG_LANG2 = 0x0011
TAG_REL = 0x0012
TAG_REL2 = 0x0013
TAG_HOSTNAME = 0x0008
TAG_OS = 0x0006
TAG_PROGRAM = 0x0130
TAG_UNKNOWN_0502 = 0x0502
TAG_REL3 = 0x000B
TAG_FUNCTION = 0x0102

CONNECT_ORDER = [
    TAG_FLAGS1, TAG_FLAGS2, TAG_FLAGS3, TAG_NONCE, TAG_CLIENT,
    TAG_USER, TAG_PASSWD, TAG_LANG, TAG_TRACE, TAG_LOCAL_IP,
    TAG_LOCAL_IP6, TAG_LANG2, TAG_REL, TAG_REL2, TAG_HOSTNAME,
    TAG_OS, TAG_PROGRAM, TAG_UNKNOWN_0502, TAG_REL3, TAG_FUNCTION,
]


def to_ebcdic(s):
    if isinstance(s, str):
        return s.encode("latin-1").translate(A2E)
    return s.translate(A2E)


def from_ebcdic(b):
    return b.translate(E2A).decode("latin-1")


def tlv(tag, value):
    if isinstance(value, str):
        value = value.encode("latin-1")
    return struct.pack("!HH", tag, len(value)) + value + struct.pack("!H", tag)


def parse_tlvs(payload):
    out, off = [], 0
    while off + 4 <= len(payload):
        tag, n = struct.unpack("!HH", payload[off:off + 4])
        if tag == END_TAG:
            off += 4
            break
        if off + 6 + n > len(payload):
            break
        if payload[off + 4 + n:off + 6 + n] != struct.pack("!H", tag):
            break
        out.append((tag, payload[off + 4:off + 4 + n]))
        off += 6 + n
    return out, payload[off:]


def nonce(now=None):
    t = int(now if now is not None else time.time())
    return (struct.pack("!I", t & 0xFFFFFFFF)
            + b"\xd1\xa9\xba\x7b"
            + struct.pack("!I", (t * 2654435761) & 0xFFFFFFFF)
            + b"\x00\x05\x14\x00"[:4])


def build_connect(function, client="001", lang="E", hostname="localhost",
                   program="pysap", local_ip="127.0.0.1", local_ip6="::1",
                   release="793", os_name="<unknown>"):
    values = {
        TAG_FLAGS1: bytes.fromhex("0301010101010000"),
        TAG_FLAGS2: bytes.fromhex("00000e0b"),
        TAG_FLAGS3: bytes.fromhex("04010003000a0200000023"),
        TAG_NONCE: nonce(),
        TAG_CLIENT: client,
        TAG_LANG: lang,
        TAG_TRACE: b"\x01",
        TAG_LOCAL_IP: local_ip,
        TAG_LOCAL_IP6: local_ip6,
        TAG_LANG2: lang,
        TAG_REL: release, TAG_REL2: release,
        TAG_HOSTNAME: hostname, TAG_OS: os_name, TAG_PROGRAM: program,
        TAG_UNKNOWN_0502: b"", TAG_REL3: release, TAG_FUNCTION: function,
    }
    body = b"".join(tlv(t, values[t]) for t in CONNECT_ORDER if t in values)
    body += tlv(END_TAG, b"")
    payload = EYECATCHER + body
    return payload + struct.pack("!I", len(payload)) + b"\x00\x00\x85\x00"


class RFCError:
    MAGIC = to_ebcdic("FREE")

    def __init__(self, payload):
        self.raw = payload
        self.code = from_ebcdic(payload[12:17]).strip()
        chars = []
        for ch in from_ebcdic(payload[17:]):
            if ch == "\t" or 0x20 <= ord(ch) < 0x7F:
                chars.append(ch)
            else:
                break
        self.message = "".join(chars).rstrip()

    @classmethod
    def matches(cls, payload):
        return payload[:4] == cls.MAGIC


def decode_reply(payload):
    if RFCError.matches(payload):
        return "error", RFCError(payload)
    tlvs, _ = parse_tlvs(payload)
    return "data", tlvs


def as_text(value):
    if len(value) >= 2 and value[1::2].count(0) > len(value) // 4:
        try:
            return value.decode("utf-16-le").rstrip("\x00 ")
        except UnicodeDecodeError:
            pass
    if all(0x20 <= c < 0x7F or c == 0 for c in value):
        return value.decode("latin-1").rstrip("\x00 ")
    return value.hex()


# ---------------------------------------------------------------------------
# APPC layer (80-byte v6 frames)
# ---------------------------------------------------------------------------

FUNC_INITIALIZE_CONVERSATION = 0x01
FUNC_ALLOCATE = 0x05
FUNC_DEALLOCATE = 0x0B
FUNC_SET_PARTNER_LU_NAME = 0x0F
FUNC_SAP_SEND = 0xCB

HDR_LEN = 80
CONV_ID_OFF = 0x28
EXTEND_OFF = 0x30

_HDR_CONST = {
    FUNC_INITIALIZE_CONVERSATION: {0x0A: 0x01, 0x10: 0xC0, 0x15: 0x04,
                                    0x1A: 0x01, 0x1B: 0x75, 0x1E: 0x05},
    FUNC_SET_PARTNER_LU_NAME:     {0x0A: 0x01, 0x1B: 0x90, 0x1E: 0x04},
    FUNC_ALLOCATE:                {0x1E: 0x01},
    FUNC_SAP_SEND:                {0x1B: 0x08, 0x1E: 0x05, 0x1F: 0x0C},
    FUNC_DEALLOCATE:              {},
}


def _pad(s, n, fill=b"\x00"):
    b = s.encode("latin-1") if isinstance(s, str) else s
    return b[:n] + fill * max(0, n - len(b))


def appc_header(func_type, conv_id=b"", extend=None):
    h = bytearray(HDR_LEN)
    h[0x00] = 0x06
    h[0x01] = func_type
    h[0x02] = 0x02
    h[0x04:0x06] = b"\xff\xff"
    for off, val in _HDR_CONST.get(func_type, {}).items():
        h[off] = val
    h[CONV_ID_OFF:CONV_ID_OFF + 8] = _pad(conv_id, 8)
    h[EXTEND_OFF:HDR_LEN] = (extend if extend is not None
                              else _pad(b"", 28) + b"\xff\xff\x00\x00")
    return bytes(h)


def extend_block(short_dest="NWRFC", lu="", tp="", ctype=0x49,
                  client_info=0x01):
    return (_pad(short_dest, 8, b" ")
            + _pad(lu, 8)
            + _pad(tp, 8, b" ")
            + bytes([ctype, client_info])
            + b"\x00\x00"
            + b"\x00\x00"
            + b"\xff\xff")


def initialize_conversation(local_ip="127.0.0.1", os_user="pysap",
                              service="sapdp00", guid=None):
    if guid is None:
        t = "%08X" % (int(time.time()) & 0xFFFFFFFF)
        guid = t + t + t + t
    body = bytearray(373)
    body[0x000:0x020] = _pad("NWRFC", 32, b" ")
    body[0x020:0x022] = b"\x01\x01"
    body[0x022:0x02A] = _pad("CPIC", 8)
    body[0x02A:0x04A] = _pad(guid, 32)
    body[0x04A:0x04E] = b"\x00\x00\x00\x01"
    body[0x04E:0x056] = b"\xff\xff\xff\xfe\xff\xff\xff\xfe"
    body[0x056:0x058] = b"\x02\x00"
    body[0x069:0x069 + len(local_ip)] = local_ip.encode("latin-1")
    body[0x0F9:0x0F9 + len(os_user)] = os_user.encode("latin-1")[:32]
    body[0x135:0x135 + len(service)] = service.encode("latin-1")[:32]
    ext = extend_block(lu=local_ip, tp=service)
    return appc_header(FUNC_INITIALIZE_CONVERSATION, b" " * 8, ext) + bytes(body)


def set_partner_lu_name(conv_id, partner="127.0.0.1"):
    ext = bytearray(_pad(partner[:8], 8) + b"\x00" * 24)
    ext[0x08:0x0C] = struct.pack("!I", len(partner))
    ext[0x1C:0x1E] = b"\xff\xff"
    return (appc_header(FUNC_SET_PARTNER_LU_NAME, conv_id, bytes(ext))
            + _pad(partner, 128, b" ") + b"\x00" * 16)


def allocate(conv_id):
    return appc_header(FUNC_ALLOCATE, conv_id)


def sap_send(conv_id, payload):
    return appc_header(FUNC_SAP_SEND, conv_id) + payload


def appc_parse(frame):
    if len(frame) < HDR_LEN:
        return None, b"", frame
    conv = frame[CONV_ID_OFF:CONV_ID_OFF + 8].rstrip(b"\x00 ")
    return frame[1], conv, frame[HDR_LEN:]


# ---------------------------------------------------------------------------
# GW_NORMAL_CLIENT frame — hand-rolled from a pysap SAPRFC(version=2) dump.
#
# 64 bytes, layout:
#   0x00       version           = 0x02
#   0x01       req_type          = 0x03
#   0x02-0x05  address (v4)      — patched to local IP at runtime
#   0x06-0x09  reserved / idx    = 00 00 00 00
#   0x0a-0x13  service           — patched to program name (10 bytes)
#   0x14-0x17  codepage          = "1100"
#   0x18-0x1d  reserved          — patched to 00 00 00 00 00 06
#   0x1e-0x25  lu (hostname)     — 8 bytes, patched to local hostname
#   0x26-0x35  tp                — 16 bytes, "pysap" + spaces (kept static)
#   0x36       appc_hdr_version  = 0x06
#   0x37       accept_info       = 0xcb
#   0x38-0x39  idx = -1          = ff ff
#   0x3a-0x3f  rc / echo / filler
# ---------------------------------------------------------------------------

_GW_NORMAL_CLIENT_TEMPLATE = bytes.fromhex(
    "0203" "01020304" "00000000"           # ver, req, addr@2, pad@6
    "70797361702020202020" "31313030"      # service@a (10 B), codepage@14
    "000000000000"                          # reserved@18 (6 B)
    "7468656865687431"                     # lu@1e (8 B, will overwrite)
    "70797361702020202020202020202020"     # tp@26 (16 B)
    "06" "cb" "ffff" "0000" "0000" "0000"  # trailer
)

assert len(_GW_NORMAL_CLIENT_TEMPLATE) == 64, len(_GW_NORMAL_CLIENT_TEMPLATE)


def build_gw_normal_client(program: str, local_ip: str, hostname: str) -> bytes:
    """Assemble the GW_NORMAL_CLIENT payload without pysap.

    Patches the same three fields the reference tool patches on top
    of pysap's SAPRFC packet: local IP, program name, hostname."""
    b = bytearray(_GW_NORMAL_CLIENT_TEMPLATE)
    b[0x02:0x06] = socket.inet_aton(local_ip)
    b[0x0A:0x14] = _pad(program, 10, b" ")
    b[0x18:0x1E] = b"\x00\x00\x00\x00\x00\x06"
    b[0x1E:0x26] = _pad(hostname, 8, b" ")
    b[0x26:0x36] = _pad(program, 16, b" ")
    return bytes(b)


# ---------------------------------------------------------------------------
# NI framing over plain TCP — 4-byte big-endian length prefix.
# ---------------------------------------------------------------------------

class NIStreamSocket:
    """Minimal SAP NI transport over TCP.

    Each on-wire frame is `<uint32 be length><payload of that length>`.
    SAProuter tunneling is NOT implemented here.  If you need one,
    swap in a socket that has already completed NI_ROUTE."""

    def __init__(self, sock: socket.socket):
        self._sock = sock

    @classmethod
    def connect(cls, host: str, port: int, timeout: float) -> "NIStreamSocket":
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        return cls(s)

    def settimeout(self, timeout: float) -> None:
        self._sock.settimeout(timeout)

    def getsockname(self):
        return self._sock.getsockname()

    def send(self, payload: bytes) -> None:
        frame = struct.pack("!I", len(payload)) + payload
        # sendall guards against partial writes on TCP.
        self._sock.sendall(frame)

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise EOFError("peer closed")
            buf.extend(chunk)
        return bytes(buf)

    def recv(self) -> bytes:
        hdr = self._recv_exact(4)
        (n,) = struct.unpack("!I", hdr)
        if n == 0:
            return b""
        if n > 16 * 1024 * 1024:                            # 16 MB guard
            raise ValueError(f"NI frame length looks bogus: {n}")
        return self._recv_exact(n)

    def close(self) -> None:
        try:
            self._sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# RFCSI record
# ---------------------------------------------------------------------------

RFCSI_FIELDS = [
    ("RFCPROTO", 3), ("RFCCHARTYP", 4), ("RFCINTTYP", 3), ("RFCFLOTYP", 3),
    ("RFCDEST", 32), ("RFCHOST", 8), ("RFCSYSID", 8), ("RFCDATABS", 8),
    ("RFCDBHOST", 32), ("RFCDBSYS", 10), ("RFCSAPRL", 4), ("RFCMACH", 5),
    ("RFCOPSYS", 10), ("RFCTZONE", 6), ("RFCDAYST", 1), ("RFCIPADDR", 15),
    ("RFCKERNRL", 4), ("RFCHOST2", 32), ("RFCSI_RESV", 12),
    ("RFCIPV6ADDR", 45),
]


def parse_rfcsi(record):
    if not isinstance(record, str):
        record = as_text(record)
    out, off = {}, 0
    for name, width in RFCSI_FIELDS:
        out[name] = record[off:off + width].strip()
        off += width
    return out


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class RFCProbeError(Exception):
    pass


class RFCClient:
    def __init__(self, host, port=3300, timeout=5.0,
                  client="001", lang="E", program="pysap"):
        self.host = host
        self.port = int(port)
        self.timeout = timeout
        self.client = client
        self.lang = lang
        self.program = program
        self.hostname = socket.gethostname()
        if 3300 <= self.port <= 3399:
            self.sysnr = "%02d" % (self.port - 3300)
        else:
            self.sysnr = "00"
        self.conn: NIStreamSocket | None = None
        self.conv_id = b""
        self.codepage = b""

    def _open(self):
        self.conn = NIStreamSocket.connect(self.host, self.port, self.timeout)

    def _send(self, data):
        self.conn.send(bytes(data))

    def _recv(self):
        try:
            return self.conn.recv()
        except (socket.timeout, EOFError, ConnectionResetError,
                struct.error, ValueError):
            return None

    def _local_ip(self):
        try:
            return self.conn.getsockname()[0]
        except OSError:
            return "127.0.0.1"

    def _gw_normal_client(self):
        payload = build_gw_normal_client(
            program=self.program,
            local_ip=self._local_ip(),
            hostname=self.hostname)
        self._send(payload)
        r = self._recv()
        if r is None:
            raise RFCProbeError("gateway did not answer GW_NORMAL_CLIENT")
        # Codepage field at offset 0x14 of the reply — used to be stashed
        # for reference; not read anywhere in this build.
        self.codepage = r[0x14:0x18] if len(r) >= 0x18 else b""
        return r

    def connect(self):
        self._open()
        self._gw_normal_client()
        self._send(initialize_conversation(
            local_ip=self._local_ip(), os_user=self.program,
            service="sapdp%s" % self.sysnr))
        r = self._recv()
        if r is None:
            raise RFCProbeError(
                "gateway did not answer F_INITIALIZE_CONVERSATION")
        _, self.conv_id, _ = appc_parse(r)
        if not self.conv_id:
            raise RFCProbeError("gateway assigned no conversation id")
        self._send(set_partner_lu_name(self.conv_id, self.host))
        self._send(allocate(self.conv_id))
        r = self._recv()
        if r is None:
            raise RFCProbeError("gateway did not answer F_ALLOCATE")
        return self

    def probe_system_info(self):
        payload = build_connect(
            "RFC_SYSTEM_INFO", client=self.client, lang=self.lang,
            hostname=self.hostname, program=self.program,
            local_ip=self._local_ip())
        self._send(sap_send(self.conv_id, payload))
        for _ in range(4):
            r = self._recv()
            if r is None:
                break
            _, _, body = appc_parse(r)
            if not body:
                continue
            kind, detail = decode_reply(body)
            if kind == "error":
                raise RFCProbeError(
                    f"kernel refused RFC_SYSTEM_INFO: {detail.code} "
                    f"{detail.message}")
            record = max((v for _, v in detail), key=len, default=b"")
            return parse_rfcsi(record)
        raise RFCProbeError("no reply after F_SAP_SEND")

    def close(self):
        try:
            if self.conn is not None:
                self.conn.close()
        except Exception:
            pass


def probe(host, port=3300, timeout=5.0, client="001"):
    """One-shot: connect, probe, close. Returns the parsed RFCSI dict.

    Raises RFCProbeError / socket errors on failure — this is the
    variant used by main().  Enrichment callers should use
    probe_rfcsi() instead, which never raises."""
    c = RFCClient(host, port=port, timeout=timeout, client=client)
    try:
        c.connect()
        return c.probe_system_info()
    finally:
        c.close()


def probe_rfcsi(host, port=3300, timeout=5.0, client="001"):
    """Never-raises wrapper for use inside enrich_system_info.

    Returns the 20-field RFCSI_EXPORT dict on success, or
    ``{"error": "<reason>"}`` on ANY failure (network timeout,
    kernel rejects the connect, template doesn't fit older kernel,
    reply is truncated, etc.)."""
    try:
        info = probe(host, port=port, timeout=timeout, client=client)
    except RFCProbeError as e:
        return {"error": str(e)}
    except (socket.timeout, ConnectionRefusedError, ConnectionResetError,
             OSError) as e:
        return {"error": f"{type(e).__name__}: {e}"}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    if not info:
        return {"error": "empty RFCSI reply"}
    # Sanity: a non-ABAP endpoint may return a reply that parses but
    # has no SID.  Callers use this to decide whether to trust the
    # data; keep the fields but flag it.
    if not info.get("RFCSYSID"):
        info["_note"] = "no RFCSYSID in reply — target may not be ABAP"
    return info


def main():
    ap = argparse.ArgumentParser(description="Anonymous RFC_SYSTEM_INFO probe")
    ap.add_argument("host")
    ap.add_argument("port", nargs="?", default=3300, type=int)
    ap.add_argument("--timeout", default=5.0, type=float)
    ap.add_argument("--client", default="001")
    ap.add_argument("--json", action="store_true",
                     help="Emit JSON only")
    args = ap.parse_args()

    started = time.time()
    try:
        info = probe(args.host, args.port, timeout=args.timeout,
                      client=args.client)
    except RFCProbeError as e:
        if args.json:
            print(json.dumps({"ok": False, "error": str(e)}))
        else:
            print(f"[-] {args.host}:{args.port} — {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        if args.json:
            print(json.dumps({"ok": False,
                              "error": f"{type(e).__name__}: {e}"}))
        else:
            print(f"[-] {args.host}:{args.port} — "
                  f"{type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(2)

    elapsed = time.time() - started
    if args.json:
        info["ok"] = True
        info["elapsed_s"] = round(elapsed, 3)
        print(json.dumps(info, indent=2))
        return

    print(f"[+] {args.host}:{args.port} → RFC_SYSTEM_INFO "
          f"({elapsed:.2f}s)")
    width = max(len(k) for k in info) if info else 0
    for name, _ in RFCSI_FIELDS:
        val = info.get(name, "")
        if val:
            print(f"    {name:<{width}} = {val}")


if __name__ == "__main__":
    main()
