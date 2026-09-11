"""Offline tests for the pure-stdlib anonymous RFC_SYSTEM_INFO probe.

Covers:
- TLV codec round-trip
- APPC v6 header layout (80 bytes, patched fields land at expected offsets)
- GW_NORMAL_CLIENT template byte-identical to what pysap emitted when
  the reference bytes were captured (bytes-baseline, no pysap import)
- RFCSI_EXPORT 245-byte field parser against synthetic + captured records
- probe_rfcsi never-raises contract (returns dict on any failure)
"""
from __future__ import annotations

import socket
import struct

import sap_rfc_sysinfo_probe as probe


# ---------------------------------------------------------------------------
# TLV codec
# ---------------------------------------------------------------------------

def test_tlv_encoder_layout():
    """Each TLV = <uint16 tag><uint16 len><value><uint16 tag>."""
    b = probe.tlv(0x0114, "001")
    assert b == struct.pack("!HH", 0x0114, 3) + b"001" + struct.pack("!H", 0x0114)


def test_tlv_encoder_accepts_bytes_and_str():
    a = probe.tlv(0x0102, "RFC_SYSTEM_INFO")
    b = probe.tlv(0x0102, b"RFC_SYSTEM_INFO")
    assert a == b


def test_parse_tlvs_roundtrip():
    payload = (probe.tlv(0x0114, "001")
                + probe.tlv(0x0115, "E")
                + probe.tlv(0x0102, "RFC_SYSTEM_INFO")
                + struct.pack("!HH", 0xFFFF, 0))
    parsed, tail = probe.parse_tlvs(payload)
    assert tail == b""
    assert parsed == [(0x0114, b"001"), (0x0115, b"E"),
                       (0x0102, b"RFC_SYSTEM_INFO")]


def test_parse_tlvs_stops_at_end_marker():
    payload = (probe.tlv(0x0114, "abc")
                + struct.pack("!HH", 0xFFFF, 0)
                + b"garbage-after-end")
    parsed, _ = probe.parse_tlvs(payload)
    assert parsed == [(0x0114, b"abc")]


# ---------------------------------------------------------------------------
# APPC v6 layout
# ---------------------------------------------------------------------------

def test_appc_header_is_80_bytes():
    for func in (probe.FUNC_INITIALIZE_CONVERSATION,
                  probe.FUNC_ALLOCATE, probe.FUNC_SAP_SEND,
                  probe.FUNC_DEALLOCATE):
        assert len(probe.appc_header(func)) == 80


def test_appc_header_carries_func_type_and_conv_id():
    h = probe.appc_header(probe.FUNC_SAP_SEND, b"12345678")
    assert h[0] == 0x06                        # v6 magic
    assert h[1] == probe.FUNC_SAP_SEND
    assert h[probe.CONV_ID_OFF:probe.CONV_ID_OFF + 8] == b"12345678"


def test_appc_parse_extracts_conv_id():
    frame = probe.appc_header(probe.FUNC_ALLOCATE, b"ABCDEFGH")
    ft, conv, body = probe.appc_parse(frame + b"tail")
    assert ft == probe.FUNC_ALLOCATE
    assert conv == b"ABCDEFGH"
    assert body == b"tail"


# ---------------------------------------------------------------------------
# GW_NORMAL_CLIENT byte-identical to pysap-generated baseline
# ---------------------------------------------------------------------------

def test_gw_normal_client_matches_pysap_baseline():
    """This baseline was captured from
        SAPRFC(version=2, req_type=3, address='10.0.0.9', service='myprog',
               codepage=b'1100', lu='myhost', tp='myprog', ...)
    after applying the same three patches the reference tool applies
    (address, service, [0x18:0x1e]).  If this test breaks after a change
    to build_gw_normal_client, the template drifted from pysap's output."""
    baseline = bytes.fromhex(
        "02 03 0a 00 00 09 00 00 00 00"                             # 0x00 header + address
        "6d 79 70 72 6f 67 20 20 20 20"                             # 0x0a service "myprog"
        "31 31 30 30"                                                # 0x14 codepage "1100"
        "00 00 00 00 00 06"                                          # 0x18 reserved
        "6d 79 68 6f 73 74 20 20"                                    # 0x1e lu (8 B) "myhost"
        "6d 79 70 72 6f 67 20 20 20 20 20 20 20 20 20 20"           # 0x26 tp (16 B) "myprog"
        "06 cb ff ff 00 00 00 00 00 00"                              # 0x36 trailer
        .replace(" ", ""))
    assert len(baseline) == 64
    got = probe.build_gw_normal_client(
        program="myprog", local_ip="10.0.0.9", hostname="myhost")
    assert got == baseline


def test_gw_normal_client_length_is_64():
    got = probe.build_gw_normal_client(
        program="pysap", local_ip="127.0.0.1", hostname="somehost")
    assert len(got) == 64


# ---------------------------------------------------------------------------
# RFCSI_EXPORT record parser
# ---------------------------------------------------------------------------

def _rfcsi_record(fields: dict) -> str:
    """Pack a dict of RFCSI fields into the fixed-width 245-char record."""
    out = ""
    for name, width in probe.RFCSI_FIELDS:
        val = str(fields.get(name, "")).ljust(width)[:width]
        out += val
    return out


def test_parse_rfcsi_extracts_20_fields():
    fields = {"RFCPROTO": "011", "RFCCHARTYP": "4103",
               "RFCSYSID": "S4H", "RFCHOST": "s4hanade",
               "RFCHOST2": "s4hanadev", "RFCDBSYS": "HDB",
               "RFCSAPRL": "758", "RFCKERNRL": "793",
               "RFCOPSYS": "Linux", "RFCIPADDR": "192.168.2.209",
               "RFCIPV6ADDR": "192.168.2.209"}
    record = _rfcsi_record(fields)
    parsed = probe.parse_rfcsi(record)
    assert parsed["RFCSYSID"] == "S4H"
    assert parsed["RFCKERNRL"] == "793"
    assert parsed["RFCOPSYS"] == "Linux"
    assert parsed["RFCDBSYS"] == "HDB"
    assert parsed["RFCIPADDR"] == "192.168.2.209"
    assert parsed["RFCHOST2"] == "s4hanadev"


def test_parse_rfcsi_all_field_widths_sum_to_245():
    assert sum(w for _, w in probe.RFCSI_FIELDS) == 245


def test_parse_rfcsi_strips_padding():
    record = _rfcsi_record({"RFCSYSID": "W74"})
    parsed = probe.parse_rfcsi(record)
    assert parsed["RFCSYSID"] == "W74"     # trailing spaces stripped


def test_parse_rfcsi_accepts_utf16le_bytes():
    """as_text auto-detects UTF-16LE encoding (kernel unicode reply)."""
    record = _rfcsi_record({"RFCSYSID": "TWP", "RFCDBSYS": "MSSQL"})
    bytes_utf16 = record.encode("utf-16-le")
    parsed = probe.parse_rfcsi(bytes_utf16)
    assert parsed["RFCSYSID"] == "TWP"
    assert parsed["RFCDBSYS"] == "MSSQL"


# ---------------------------------------------------------------------------
# EBCDIC / RFCError
# ---------------------------------------------------------------------------

def test_ebcdic_roundtrip():
    for s in ("RFC_SYSTEM_INFO", "SAPMAP00", "abc123", ""):
        assert probe.from_ebcdic(probe.to_ebcdic(s)) == s


def test_rfc_error_matches_free_prefix():
    payload = probe.to_ebcdic("FREE" + " " * 8 + "00024" + "logon failed")
    assert probe.RFCError.matches(payload)
    err = probe.RFCError(payload)
    assert err.code == "00024"
    assert "logon" in err.message


# ---------------------------------------------------------------------------
# probe_rfcsi never-raises contract
# ---------------------------------------------------------------------------

def test_probe_rfcsi_returns_error_on_unreachable_host():
    """RFC1918 TEST-NET-1 always drops — expect a clean error dict."""
    r = probe.probe_rfcsi("192.0.2.1", 3300, timeout=1.0)
    assert isinstance(r, dict)
    assert r.get("error")
    assert "RFCSYSID" not in r        # partial data not present


def test_probe_rfcsi_returns_error_on_refused_port():
    """Loopback with nothing listening — connect refused, clean dict."""
    r = probe.probe_rfcsi("127.0.0.1", 1, timeout=1.0)
    assert isinstance(r, dict)
    assert r.get("error")


def test_probe_rfcsi_never_raises_on_gibberish_target():
    """Even bogus hostnames must not raise — must return an error dict."""
    r = probe.probe_rfcsi("this-host-does-not-exist.invalid", 3300,
                            timeout=1.0)
    assert isinstance(r, dict)
    assert r.get("error")


# ---------------------------------------------------------------------------
# NIStreamSocket transport
# ---------------------------------------------------------------------------

def test_ni_framing_send_prepends_length():
    """A crafted socket-pair confirms the 4-byte big-endian length prefix."""
    a, b = socket.socketpair()
    try:
        ni = probe.NIStreamSocket(a)
        ni.send(b"hello")
        got = b.recv(9)
        assert got == struct.pack("!I", 5) + b"hello"
    finally:
        a.close(); b.close()


def test_ni_framing_recv_reads_length_prefixed_frame():
    a, b = socket.socketpair()
    try:
        b.sendall(struct.pack("!I", 3) + b"foo")
        ni = probe.NIStreamSocket(a)
        assert ni.recv() == b"foo"
    finally:
        a.close(); b.close()


def test_ni_framing_rejects_oversized_frame():
    """A 20 MB advertised length exceeds the 16 MB sanity cap — refuse it."""
    a, b = socket.socketpair()
    try:
        b.sendall(struct.pack("!I", 20 * 1024 * 1024))
        ni = probe.NIStreamSocket(a)
        try:
            ni.recv()
            assert False, "expected ValueError"
        except ValueError as e:
            assert "bogus" in str(e).lower()
    finally:
        a.close(); b.close()
