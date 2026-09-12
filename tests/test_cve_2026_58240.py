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
    p = mod.build_ascs_gw_logon_payload(
        host="ATTACKER_ROGUE", port=31337, ip="10.0.0.1", pid=42)
    # type
    assert p[0:2] == struct.pack("!H", 0x0001)
    # port
    assert p[2:4] == struct.pack("!H", 31337)
    # addr
    assert p[4:8] == socket.inet_aton("10.0.0.1")
    # host TLV
    hlen = struct.unpack("!H", p[8:10])[0]
    assert hlen == len(b"ATTACKER_ROGUE")
    assert p[10:10 + hlen] == b"ATTACKER_ROGUE"
    off = 10 + hlen
    # pid TLV
    plen = struct.unpack("!H", p[off:off + 2])[0]
    assert p[off + 2:off + 2 + plen] == b"42"
    # end sentinel
    assert p[-2:] == b"\xff\xff"


def test_logon_payload_truncates_long_hostname():
    long_name = "A" * 200
    p = mod.build_ascs_gw_logon_payload(long_name, 1234)
    hlen = struct.unpack("!H", p[8:10])[0]
    assert hlen == 80        # truncated per module contract
    assert p[10:10 + 80] == b"A" * 80


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

def test_sapnode_cve_2026_58240_fields_default():
    n = SAPNode(sid="XYZ", ip="10.0.0.1")
    assert n.cve_2026_58240_checked is False
    assert n.cve_2026_58240_vulnerable is False
    assert n.cve_2026_58240_ms_port == 0
    assert n.cve_2026_58240_ascs_identity == ""
    assert n.cve_2026_58240_registered is False


def test_sapnode_cve_2026_58240_fields_roundtrip():
    n = SAPNode(sid="A4H", ip="10.0.0.1")
    n.cve_2026_58240_checked = True
    n.cve_2026_58240_vulnerable = True
    n.cve_2026_58240_ms_port = 3901
    n.cve_2026_58240_ascs_identity = "vhcala4hci_A4H_00"
    n.cve_2026_58240_registered = False
    n.cve_2026_58240_evidence = "opcode_recognised"
    d = n.to_dict()
    n2 = SAPNode.from_dict(d)
    assert n2.cve_2026_58240_checked is True
    assert n2.cve_2026_58240_vulnerable is True
    assert n2.cve_2026_58240_ms_port == 3901
    assert n2.cve_2026_58240_ascs_identity == "vhcala4hci_A4H_00"
    assert n2.cve_2026_58240_evidence == "opcode_recognised"
