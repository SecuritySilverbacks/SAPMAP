"""Tests for modules.protocols.sap_snc — frame builder/parser + result shape.

Network-level scan_snc_diag / scan_snc_router are exercised by
monkey-patching socket.socket so we never touch a real SAP instance.
"""
import socket
import struct

import sap_snc


# ---------------------------------------------------------------------------
# Frame round-trip
# ---------------------------------------------------------------------------

def test_build_snc_frame_diag_layout():
    frame = sap_snc._build_snc_frame(
        flags=0x2a, ext_fields=sap_snc.SNC_EXT_DIAG)

    # Eye-catcher first 8 bytes
    assert frame[:8] == b"SNCFRAME"
    # frame_type INIT_REQ
    assert frame[8] == sap_snc.SNC_FRAME_INIT_REQ
    # protocol_version 6
    assert frame[9] == 6
    # header_length = 24 fixed + 6 ext-prefix + 34 ext_fields = 64
    assert struct.unpack("!H", frame[10:12])[0] == 64
    # token_length matches the 101-byte hardcoded ASN.1 SEQUENCE token
    assert struct.unpack("!I", frame[12:16])[0] == 101
    # mech_id default = 3
    assert struct.unpack("!H", frame[20:22])[0] == 3
    # flags 0x2a in the low octet
    assert struct.unpack("!H", frame[22:24])[0] == 0x2a


def test_build_snc_frame_router_layout():
    frame = sap_snc._build_snc_frame(
        flags=0x7e, ext_fields=sap_snc.SNC_EXT_ROUTER)
    # header_length = 24 + 6 + 43 = 73
    assert struct.unpack("!H", frame[10:12])[0] == 73
    assert struct.unpack("!H", frame[22:24])[0] == 0x7e


def test_parse_snc_frame_round_trip_diag():
    frame = sap_snc._build_snc_frame(
        flags=0x2a, ext_fields=sap_snc.SNC_EXT_DIAG)
    parsed = sap_snc._parse_snc_frame(frame)
    assert parsed is not None
    assert parsed["frame_type"] == sap_snc.SNC_FRAME_INIT_REQ
    assert parsed["protocol_version"] == 6
    assert parsed["header_length"] == 64
    assert parsed["token_length"] == 101
    assert parsed["token"] == sap_snc.SNC_TOKEN
    assert parsed["data"] == sap_snc.SNC_DATA
    assert parsed["mech_id"] == 3
    assert parsed["flags"] == 0x2a
    assert "CommonCryptoLib" in parsed["cryptolib"]


def test_parse_snc_frame_finds_eye_catcher_with_prefix():
    # Simulate a response that comes wrapped in some carrier bytes
    junk = b"\x00" * 50 + b"NI_RTERR\x00\x28\x46\x00" + b"\x00" * 8
    frame = sap_snc._build_snc_frame(
        flags=0x7e, ext_fields=sap_snc.SNC_EXT_ROUTER,
        frame_type=sap_snc.SNC_FRAME_ACCEPT, mech_id=2)
    parsed = sap_snc._parse_snc_frame(junk + frame)
    assert parsed is not None
    assert parsed["frame_type"] == sap_snc.SNC_FRAME_ACCEPT
    assert parsed["mech_id"] == 2
    assert parsed["mech_id_label"] == "Kerberos 5 / GSS-API v2"


def test_parse_snc_frame_returns_none_when_missing():
    assert sap_snc._parse_snc_frame(b"\x00" * 100) is None
    assert sap_snc._parse_snc_frame(b"SNCFRAME") is None      # too short
    assert sap_snc._parse_snc_frame(b"") is None


# ---------------------------------------------------------------------------
# QoP bit decoding
# ---------------------------------------------------------------------------

def test_parse_qop_max_protection():
    """flags=0x7e → use=3, max=3, min=3 (PRIVACY everywhere)."""
    frame = sap_snc._build_snc_frame(
        flags=0x7e, ext_fields=sap_snc.SNC_EXT_ROUTER,
        frame_type=sap_snc.SNC_FRAME_ACCEPT)
    parsed = sap_snc._parse_snc_frame(frame)
    assert parsed["qop_use"] == 3
    assert parsed["qop_max"] == 3
    assert parsed["qop_min"] == 3
    assert parsed["qop_use_label"] == "PRIVACY"


def test_parse_qop_min_protection():
    """flags=0x2a → use=1, max=1, min=1 (OPEN — no real protection)."""
    frame = sap_snc._build_snc_frame(
        flags=0x2a, ext_fields=sap_snc.SNC_EXT_DIAG,
        frame_type=sap_snc.SNC_FRAME_ACCEPT)
    parsed = sap_snc._parse_snc_frame(frame)
    assert parsed["qop_use"] == 1
    assert parsed["qop_max"] == 1
    assert parsed["qop_min"] == 1
    assert parsed["qop_use_label"] == "OPEN"


# ---------------------------------------------------------------------------
# Carrier wire format
# ---------------------------------------------------------------------------

def test_build_diag_snc_init_wraps_in_ni_dp_diag():
    pkt = sap_snc._build_diag_snc_init()
    # NI length prefix
    ni_len = struct.unpack("!I", pkt[:4])[0]
    assert len(pkt) == 4 + ni_len
    body = pkt[4:]
    # 200B DP header + 8B SAPDiag header + SNCFrame
    assert len(body) > 200 + 8 + 64
    diag_header = body[200:208]
    assert diag_header[1] == 0x10           # TERM_INI bit
    assert diag_header[7] == 0x02           # compress=2 → SNC follows
    assert body[208:208 + 8] == b"SNCFRAME"


def test_build_router_snc_init_layout():
    pkt = sap_snc._build_router_snc_init()
    ni_len = struct.unpack("!I", pkt[:4])[0]
    assert len(pkt) == 4 + ni_len
    body = pkt[4:]
    # "NI_RTERR\0" + version + opcode + opcode_padd + return_code(4) +
    # control_text_length(4) + SNCFrame
    assert body.startswith(b"NI_RTERR\x00")
    assert body[9] == 40                    # version
    assert body[10] == 70                   # opcode = SNC init
    # control_text_length = 0 → SNCFrame begins at offset 20
    # (9B type + 1B version + 1B opcode + 1B opcode_padd
    #  + 4B return_code + 4B control_text_length)
    assert body[20:28] == b"SNCFRAME"


# ---------------------------------------------------------------------------
# Result shape
# ---------------------------------------------------------------------------

def test_format_summary_states():
    assert sap_snc.format_summary({}) == "SNC: not checked"
    assert sap_snc.format_summary({"checked": True, "enabled": False,
                                    "error": ""}) == "SNC: not enabled"
    assert "probe failed" in sap_snc.format_summary({
        "checked": True, "enabled": False, "error": "timeout"})

    enabled = {
        "checked": True, "enabled": True, "protocol": "diag",
        "qop_use": 3, "qop_max": 3, "qop_min": 3,
        "mech_label": "Kerberos 5 / GSS-API v2", "enforced": True,
    }
    s = sap_snc.format_summary(enabled)
    assert "enabled" in s and "Kerberos" in s and "3/3/3" in s and "enforced" in s


# ---------------------------------------------------------------------------
# Live probe via fake socket
# ---------------------------------------------------------------------------

class _FakeSocket:
    """Minimal socket stand-in: records sends, returns a scripted reply."""

    def __init__(self, reply_bytes: bytes):
        self.reply = reply_bytes
        self.sent = b""
        self._read_pos = 0
        self.closed = False

    # socket.socket(...) is called with (AF_INET, SOCK_STREAM)
    def settimeout(self, t):  # noqa: D401
        pass

    def connect(self, addr):  # noqa: D401
        self.addr = addr

    def sendall(self, b):  # noqa: D401
        self.sent += b

    def recv(self, n):
        if self._read_pos >= len(self.reply):
            return b""
        chunk = self.reply[self._read_pos:self._read_pos + n]
        self._read_pos += len(chunk)
        return chunk

    def close(self):
        self.closed = True


def _wrap_diag_response(snc_frame: bytes) -> bytes:
    """Build a fake DIAG SNC ACCEPT response: NI len + 200B DP + 8B Diag + SNC."""
    dp = b"\x00" * 200
    diag = bytearray(b"\x00" * 8)
    diag[7] = 0x02   # compress = 2 → SNC frame follows
    body = dp + bytes(diag) + snc_frame
    return struct.pack("!I", len(body)) + body


def _wrap_router_response(snc_frame: bytes) -> bytes:
    """Fake router CONTROL response carrying an SNC ACCEPT frame."""
    body = (b"NI_RTERR\x00"
            + struct.pack("!B", 40)
            + struct.pack("!B", 70)
            + struct.pack("!B", 0)
            + struct.pack("!i", 0)
            + struct.pack("!I", 0)
            + snc_frame)
    return struct.pack("!I", len(body)) + body


def test_scan_snc_diag_enabled(monkeypatch):
    accept_frame = sap_snc._build_snc_frame(
        flags=0x7e, ext_fields=sap_snc.SNC_EXT_DIAG,
        frame_type=sap_snc.SNC_FRAME_ACCEPT, mech_id=2)
    fake = _FakeSocket(_wrap_diag_response(accept_frame))
    monkeypatch.setattr(socket, "socket",
                        lambda *a, **kw: fake)

    result = sap_snc.scan_snc_diag("1.2.3.4", 3200, timeout=1.0)
    # Skip the second-probe error path by checking primary result only
    assert result["checked"]
    assert result["enabled"]
    assert result["mech_id"] == 2
    assert result["mech_label"] == "Kerberos 5 / GSS-API v2"
    assert result["qop_use"] == 3
    assert result["qop_max"] == 3
    assert result["qop_min"] == 3
    assert "CommonCryptoLib" in result["cryptolib"]


def test_scan_snc_diag_disabled(monkeypatch):
    # Plain DIAG error response (no SNC frame, no DP header).
    err_body = b"\x00\x02\x00\x01\x00\x00\x00\x00" + b"SNC not enabled\x0c"
    reply = struct.pack("!I", len(err_body)) + err_body
    fake = _FakeSocket(reply)
    monkeypatch.setattr(socket, "socket",
                        lambda *a, **kw: fake)

    result = sap_snc.scan_snc_diag("1.2.3.4", 3200, timeout=1.0)
    assert result["checked"]
    assert result["enabled"] is False
    assert result["qop_use"] == 0


def test_scan_snc_router_enabled(monkeypatch):
    accept_frame = sap_snc._build_snc_frame(
        flags=0x7e, ext_fields=sap_snc.SNC_EXT_ROUTER,
        frame_type=sap_snc.SNC_FRAME_ACCEPT, mech_id=2)
    fake = _FakeSocket(_wrap_router_response(accept_frame))
    monkeypatch.setattr(socket, "socket",
                        lambda *a, **kw: fake)

    result = sap_snc.scan_snc_router("1.2.3.4", 3299, timeout=1.0)
    assert result["enabled"]
    assert result["protocol"] == "router"
    assert result["mech_id"] == 2
    assert result["qop_use"] == 3
    # Router probe never sets enforced
    assert result["enforced"] is False


def test_scan_snc_diag_connect_error(monkeypatch):
    class _Boom:
        def settimeout(self, t): pass
        def connect(self, addr): raise ConnectionRefusedError("nope")
        def close(self): pass
    monkeypatch.setattr(socket, "socket",
                        lambda *a, **kw: _Boom())
    result = sap_snc.scan_snc_diag("127.0.0.1", 3200, timeout=0.5)
    assert result["checked"]
    assert result["enabled"] is False
    assert "connect_error" in result["error"]


# ---------------------------------------------------------------------------
# Integration with SAPNode
# ---------------------------------------------------------------------------

def test_sapnode_snc_info_roundtrips():
    from sapmap_models import SAPNode
    n = SAPNode(sid="ABC")
    n.snc_info = {
        "checked": True, "enabled": True, "protocol": "diag",
        "qop_use": 3, "qop_max": 3, "qop_min": 3,
        "mech_id": 2, "mech_label": "Kerberos 5 / GSS-API v2",
        "cryptolib": "Internal SNC-Adapter ...", "enforced": True,
        "error": "", "host": "1.2.3.4", "port": 3200, "qop_flag": 0x7e,
    }
    serialised = n.to_dict()
    assert "snc_info" in serialised
    revived = SAPNode.from_dict(serialised)
    assert revived.snc_info["enabled"] is True
    assert revived.snc_info["mech_id"] == 2
