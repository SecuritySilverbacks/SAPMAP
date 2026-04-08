"""Tests for sap_ms_betrusted.py — protocol packet building and parsing.

All tests are offline (no network access).  They validate:
  - SAPMS header build/parse round-trip (110-byte fixed layout)
  - ADM packet structure (eyecatcher + recno + recsize + records)
  - ADM record payloads (CHANGE_IP, NILIST, SERVER_LONG_LIST)
  - DP info blob structure for MOD_STATE
  - NI NILIST detection helper logic (flag/opcode classification)
  - CLI argument derivation (ms_port)
"""
import sys
import os
import socket
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sap_ms_betrusted import (
    # Constants
    _MS_EYE, _ADM_EYE,
    _HEADER_LEN, _ADM_HDR_LEN, _ADM_REC_SIZE,
    FLAG_UNKNOWN, FLAG_ONE_WAY, FLAG_REQUEST, FLAG_REPLY, FLAG_ADMIN,
    IFLAG_LOGIN_2, IFLAG_MOD_STATE, IFLAG_LOGOUT,
    MSG_DIA, MSG_DIA_ENQ, MSG_ALL,
    DOMAIN_ABAP,
    ADM_CHANGE_IP, ADM_NILIST, ADM_SERVER_LONG_LIST,
    DP_VERSION_V11, DP_VERSION_V13, DP_VERSION_V14,
    DP_SIZE_V11, DP_SIZE_V13,
    DEFAULT_REG_NAME, DEFAULT_DIAG_PORT,
    # Functions
    ms_port,
    ms_build_header, ms_parse_header, ms_parse_opcode,
    pkt_login_2, pkt_logout, pkt_mod_state, pkt_adm,
    _adm_record,
    adm_change_ip_record, adm_nilist_record, adm_server_long_list_record,
    build_dp_info,
    build_nilist_reply,
)


# ---------------------------------------------------------------------------
# ms_port()
# ---------------------------------------------------------------------------

class TestMsPort:

    def test_instance_0(self):
        assert ms_port(0) == 3900

    def test_instance_1(self):
        assert ms_port(1) == 3901

    def test_instance_10(self):
        assert ms_port(10) == 3910

    def test_instance_99(self):
        assert ms_port(99) == 3999


# ---------------------------------------------------------------------------
# ms_build_header / ms_parse_header — round-trip
# ---------------------------------------------------------------------------

class TestMsHeader:

    def _roundtrip(self, **kwargs):
        data = ms_build_header(**kwargs)
        return data, ms_parse_header(data)

    def test_header_is_110_bytes(self):
        data = ms_build_header("", "", MSG_DIA, FLAG_REQUEST, IFLAG_LOGIN_2)
        assert len(data) == 110

    def test_starts_with_eyecatcher(self):
        data = ms_build_header("", "", MSG_DIA, FLAG_REQUEST, IFLAG_LOGIN_2)
        assert data[:12] == _MS_EYE

    def test_version_is_4(self):
        data = ms_build_header("", "", MSG_DIA, FLAG_REQUEST, IFLAG_LOGIN_2)
        assert data[12] == 4

    def test_errorno_is_0(self):
        data = ms_build_header("", "", MSG_DIA, FLAG_REQUEST, IFLAG_LOGIN_2)
        assert data[13] == 0

    def test_toname_padded_to_40_bytes(self):
        data = ms_build_header("abc", "", MSG_DIA, FLAG_REQUEST, IFLAG_LOGIN_2)
        toname_field = data[14:54]
        assert len(toname_field) == 40
        assert toname_field[:3] == b"abc"
        assert toname_field[3:] == b" " * 37

    def test_fromname_padded_to_40_bytes(self):
        data = ms_build_header("", "msg_server", MSG_DIA, FLAG_REQUEST, IFLAG_LOGIN_2)
        fromname_field = data[68:108]
        assert len(fromname_field) == 40
        assert fromname_field[:10] == b"msg_server"
        assert fromname_field[10:] == b" " * 30

    def test_msgtype_at_offset_54(self):
        data = ms_build_header("", "", MSG_DIA_ENQ, FLAG_REQUEST, IFLAG_LOGIN_2)
        assert data[54] == MSG_DIA_ENQ

    def test_domain_at_offset_56(self):
        data = ms_build_header("", "", MSG_DIA, FLAG_REQUEST, IFLAG_LOGIN_2,
                               domain=DOMAIN_ABAP)
        assert data[56] == DOMAIN_ABAP

    def test_key_at_offset_58(self):
        key = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        data = ms_build_header("", "", MSG_DIA, FLAG_REQUEST, IFLAG_LOGIN_2, key=key)
        assert data[58:66] == key

    def test_flag_at_offset_66(self):
        data = ms_build_header("", "", MSG_DIA, FLAG_ADMIN, IFLAG_LOGIN_2)
        assert data[66] == FLAG_ADMIN

    def test_iflag_at_offset_67(self):
        data = ms_build_header("", "", MSG_DIA, FLAG_REQUEST, IFLAG_MOD_STATE)
        assert data[67] == IFLAG_MOD_STATE

    def test_diag_port_at_offset_108(self):
        data = ms_build_header("", "", MSG_DIA, FLAG_REQUEST, IFLAG_LOGIN_2,
                               diag_port=3201)
        assert struct.unpack("!H", data[108:110])[0] == 3201

    def test_parse_empty_names(self):
        data = ms_build_header("", "", MSG_DIA, FLAG_REQUEST, IFLAG_LOGIN_2)
        hdr = ms_parse_header(data)
        assert hdr["toname"] == ""
        assert hdr["fromname"] == ""

    def test_parse_names(self):
        data = ms_build_header("target", "source", MSG_DIA, FLAG_REQUEST, IFLAG_LOGIN_2)
        hdr = ms_parse_header(data)
        assert hdr["toname"] == "target"
        assert hdr["fromname"] == "source"

    def test_parse_key(self):
        key = b"\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11"
        data = ms_build_header("", "", MSG_DIA, FLAG_REQUEST, IFLAG_LOGIN_2, key=key)
        hdr = ms_parse_header(data)
        assert hdr["key"] == key

    def test_parse_returns_empty_dict_on_wrong_eyecatcher(self):
        bad = b"BAD_EYECATCH\x00" + b"\x00" * 98
        assert ms_parse_header(bad) == {}

    def test_parse_returns_empty_dict_on_short_data(self):
        assert ms_parse_header(b"\x00" * 50) == {}

    def test_parse_diag_port_round_trip(self):
        data = ms_build_header("", "", MSG_DIA, FLAG_REQUEST, IFLAG_LOGIN_2,
                               diag_port=8765)
        assert ms_parse_header(data)["diag_port"] == 8765

    def test_key_must_be_8_bytes(self):
        with pytest.raises(AssertionError):
            ms_build_header("", "", MSG_DIA, FLAG_REQUEST, IFLAG_LOGIN_2,
                            key=b"\x00" * 7)


# ---------------------------------------------------------------------------
# pkt_login_2
# ---------------------------------------------------------------------------

class TestPktLogin2:

    def test_size_is_110_bytes(self):
        assert len(pkt_login_2("msg_server")) == 110

    def test_flag_is_request(self):
        pkt = pkt_login_2("msg_server")
        assert pkt[66] == FLAG_REQUEST

    def test_iflag_is_login_2(self):
        pkt = pkt_login_2("msg_server")
        assert pkt[67] == IFLAG_LOGIN_2

    def test_diag_port_encoded(self):
        pkt = pkt_login_2("msg_server", diag_port=3200)
        assert struct.unpack("!H", pkt[108:110])[0] == 3200

    def test_fromname_in_packet(self):
        pkt = pkt_login_2("msg_server")
        assert pkt[68:78] == b"msg_server"

    def test_toname_is_empty(self):
        pkt = pkt_login_2("msg_server")
        assert pkt[14:54] == b" " * 40


# ---------------------------------------------------------------------------
# pkt_logout
# ---------------------------------------------------------------------------

class TestPktLogout:

    def test_size_is_110_bytes(self):
        assert len(pkt_logout("server", b"\x00" * 8)) == 110

    def test_flag_is_one_way(self):
        pkt = pkt_logout("server", b"\x00" * 8)
        assert pkt[66] == FLAG_ONE_WAY

    def test_iflag_is_logout(self):
        pkt = pkt_logout("server", b"\x00" * 8)
        assert pkt[67] == IFLAG_LOGOUT


# ---------------------------------------------------------------------------
# pkt_mod_state
# ---------------------------------------------------------------------------

class TestPktModState:

    def _dp(self):
        return build_dp_info("msg_server", 0, DP_VERSION_V13)

    def test_size_is_110_plus_dp_info(self):
        dp = self._dp()
        pkt = pkt_mod_state("msg_server", b"\x00" * 8, MSG_DIA_ENQ, dp)
        assert len(pkt) == 110 + len(dp)

    def test_flag_is_one_way(self):
        pkt = pkt_mod_state("msg_server", b"\x00" * 8, MSG_DIA_ENQ, self._dp())
        assert pkt[66] == FLAG_ONE_WAY

    def test_iflag_is_mod_state(self):
        pkt = pkt_mod_state("msg_server", b"\x00" * 8, MSG_DIA_ENQ, self._dp())
        assert pkt[67] == IFLAG_MOD_STATE

    def test_msgtype_start_is_dia_enq(self):
        pkt = pkt_mod_state("msg_server", b"\x00" * 8, MSG_DIA_ENQ, self._dp())
        assert pkt[54] == MSG_DIA_ENQ

    def test_msgtype_active_is_dia(self):
        pkt = pkt_mod_state("msg_server", b"\x00" * 8, MSG_DIA, self._dp())
        assert pkt[54] == MSG_DIA

    def test_dp_info_appended_verbatim(self):
        dp = self._dp()
        pkt = pkt_mod_state("msg_server", b"\x00" * 8, MSG_DIA, dp)
        assert pkt[110:] == dp


# ---------------------------------------------------------------------------
# _adm_record
# ---------------------------------------------------------------------------

class TestAdmRecord:

    def test_size_is_104_bytes(self):
        rec = _adm_record(ADM_NILIST, b"\x00" * 101)
        assert len(rec) == 104

    def test_opcode_at_offset_0(self):
        rec = _adm_record(ADM_CHANGE_IP, b"\x00" * 101)
        assert rec[0] == ADM_CHANGE_IP

    def test_executed_at_offset_1(self):
        rec = _adm_record(ADM_NILIST, b"\x00" * 101, executed=1)
        assert rec[1] == 1

    def test_errorno_at_offset_2_is_zero(self):
        rec = _adm_record(ADM_NILIST, b"\x00" * 101)
        assert rec[2] == 0

    def test_record_body_truncated_to_101(self):
        rec = _adm_record(ADM_NILIST, b"\xAA" * 200)
        assert len(rec) == 104
        assert rec[3:104] == b"\xAA" * 101

    def test_record_body_padded_to_101(self):
        rec = _adm_record(ADM_NILIST, b"\xBB" * 50)
        assert len(rec) == 104
        assert rec[3:53] == b"\xBB" * 50
        assert rec[53:] == b"\x00" * 51


# ---------------------------------------------------------------------------
# pkt_adm
# ---------------------------------------------------------------------------

class TestPktAdm:

    def _rec(self):
        return _adm_record(ADM_NILIST, b"\x00" * 101)

    def test_starts_with_ms_header(self):
        pkt = pkt_adm("server", b"\x00" * 8, [self._rec()])
        assert pkt[:12] == _MS_EYE

    def test_flag_is_admin(self):
        pkt = pkt_adm("server", b"\x00" * 8, [self._rec()])
        assert pkt[66] == FLAG_ADMIN

    def test_adm_eyecatcher_after_header(self):
        pkt = pkt_adm("server", b"\x00" * 8, [self._rec()])
        assert pkt[110:122] == _ADM_EYE

    def test_recno_is_right_justified_decimal(self):
        recs = [self._rec(), self._rec()]
        pkt = pkt_adm("server", b"\x00" * 8, recs)
        recno_field = pkt[122:133]   # 12 + 11 = 23 offset from adm start, so 110+12=122
        assert recno_field == b"          2"

    def test_recsize_is_104(self):
        pkt = pkt_adm("server", b"\x00" * 8, [self._rec()])
        recsize_field = pkt[133:144]  # 110 + 12 + 11 = 133
        assert recsize_field == b"        104"

    def test_records_appended_after_adm_header(self):
        rec = self._rec()
        pkt = pkt_adm("server", b"\x00" * 8, [rec])
        assert pkt[144:248] == rec   # 110 + 34 = 144

    def test_two_records_both_present(self):
        rec1 = _adm_record(ADM_CHANGE_IP, b"\x01" * 101)
        rec2 = _adm_record(ADM_NILIST, b"\x02" * 101)
        pkt = pkt_adm("server", b"\x00" * 8, [rec1, rec2])
        assert pkt[144:248] == rec1
        assert pkt[248:352] == rec2

    def test_total_size_with_one_record(self):
        pkt = pkt_adm("server", b"\x00" * 8, [self._rec()])
        # 110 header + 34 adm header + 104 record = 248
        assert len(pkt) == 248


# ---------------------------------------------------------------------------
# adm_change_ip_record
# ---------------------------------------------------------------------------

class TestAdmChangeIpRecord:

    def test_size_is_104_bytes(self):
        assert len(adm_change_ip_record("1.2.3.4")) == 104

    def test_opcode_is_change_ip(self):
        rec = adm_change_ip_record("1.2.3.4")
        assert rec[0] == ADM_CHANGE_IP

    def test_new_ip_at_offset_3(self):
        rec = adm_change_ip_record("192.168.1.100")
        new_ip = socket.inet_ntoa(rec[3:7])
        assert new_ip == "192.168.1.100"

    def test_old_ip_at_offset_7(self):
        rec = adm_change_ip_record("192.168.1.100", old_ip="10.0.0.1")
        old_ip = socket.inet_ntoa(rec[7:11])
        assert old_ip == "10.0.0.1"

    def test_old_ip_defaults_to_zero(self):
        rec = adm_change_ip_record("1.2.3.4")
        old_ip = socket.inet_ntoa(rec[7:11])
        assert old_ip == "0.0.0.0"

    def test_padding_is_zero(self):
        rec = adm_change_ip_record("1.2.3.4")
        assert rec[11:104] == b"\x00" * 93


# ---------------------------------------------------------------------------
# adm_nilist_record
# ---------------------------------------------------------------------------

class TestAdmNilistRecord:

    def test_size_is_104_bytes_new_format(self):
        assert len(adm_nilist_record("1.2.3.4", kernel_new=True)) == 104

    def test_size_is_104_bytes_old_format(self):
        assert len(adm_nilist_record("1.2.3.4", kernel_new=False)) == 104

    def test_opcode_is_nilist(self):
        rec = adm_nilist_record("1.2.3.4")
        assert rec[0] == ADM_NILIST

    def test_new_format_contains_ip(self):
        ip = "192.168.50.1"
        rec = adm_nilist_record(ip, kernel_new=True)
        # IP is at offset 3+16 = 19 (after opcode/exec/err + count/zero/zero/mask)
        ip_bytes = socket.inet_aton(ip)
        assert ip_bytes in rec[3:]

    def test_old_format_contains_ip(self):
        ip = "10.0.0.99"
        rec = adm_nilist_record(ip, kernel_new=False)
        ip_bytes = socket.inet_aton(ip)
        assert ip_bytes in rec[3:]

    def test_new_format_subnet_mask_present(self):
        rec = adm_nilist_record("1.2.3.4", kernel_new=True)
        mask = socket.inet_aton("0.0.255.255")
        assert mask in rec[3:]

    def test_old_format_subnet_mask_present(self):
        rec = adm_nilist_record("1.2.3.4", kernel_new=False)
        mask = socket.inet_aton("0.0.255.255")
        assert mask in rec[3:]


# ---------------------------------------------------------------------------
# adm_server_long_list_record
# ---------------------------------------------------------------------------

class TestAdmServerLongListRecord:

    def test_size_is_104_bytes(self):
        assert len(adm_server_long_list_record()) == 104

    def test_opcode_is_server_long_list(self):
        rec = adm_server_long_list_record()
        assert rec[0] == ADM_SERVER_LONG_LIST


# ---------------------------------------------------------------------------
# build_dp_info
# ---------------------------------------------------------------------------

class TestBuildDpInfo:

    def test_v13_size_is_507_bytes(self):
        blob = build_dp_info("msg_server", 0, DP_VERSION_V13)
        assert len(blob) == DP_SIZE_V13

    def test_v11_size_is_203_bytes(self):
        blob = build_dp_info("msg_server", 0, DP_VERSION_V11)
        assert len(blob) == DP_SIZE_V11

    def test_v14_size_is_507_bytes(self):
        blob = build_dp_info("msg_server", 0, DP_VERSION_V14)
        assert len(blob) == DP_SIZE_V13   # same size as v13

    def test_dp_version_at_offset_1(self):
        blob = build_dp_info("msg_server", 0, DP_VERSION_V13)
        assert blob[1] == 13

    def test_dp_type_is_dispatcher(self):
        blob = build_dp_info("msg_server", 0, DP_VERSION_V13)
        assert blob[6] == 0x01   # dp_type = 1 (dispatcher)

    def test_instance_nr_at_offset_11(self):
        blob = build_dp_info("msg_server", 42, DP_VERSION_V13)
        inst = struct.unpack("!H", blob[11:13])[0]
        assert inst == 42

    def test_fromname_at_offset_13(self):
        blob = build_dp_info("msg_server", 0, DP_VERSION_V13)
        name = blob[13:23]
        assert name == b"msg_server"

    def test_fromname_space_padded_to_40(self):
        blob = build_dp_info("abc", 0, DP_VERSION_V13)
        name_field = blob[13:53]
        assert name_field[:3] == b"abc"
        assert name_field[3:] == b" " * 37

    def test_attacker_ip_embedded_in_v13(self):
        blob = build_dp_info("server", 0, DP_VERSION_V13, attacker_ip="10.1.2.3")
        ip_bytes = socket.inet_aton("10.1.2.3")
        assert ip_bytes in blob

    def test_no_ip_all_zeros_at_offset_69(self):
        blob = build_dp_info("server", 0, DP_VERSION_V13, attacker_ip="")
        # Without attacker_ip, offset 69 should be zero
        assert blob[69:73] == b"\x00" * 4

    def test_instance_zero_is_valid(self):
        blob = build_dp_info("srv", 0, DP_VERSION_V13)
        inst = struct.unpack("!H", blob[11:13])[0]
        assert inst == 0


# ---------------------------------------------------------------------------
# build_nilist_reply
# ---------------------------------------------------------------------------

class TestBuildNilistReply:

    def test_starts_with_ms_header(self):
        pkt = build_nilist_reply("server", b"\x00" * 8, "1.2.3.4")
        assert pkt[:12] == _MS_EYE

    def test_flag_is_admin(self):
        pkt = build_nilist_reply("server", b"\x00" * 8, "1.2.3.4")
        assert pkt[66] == FLAG_ADMIN

    def test_adm_eyecatcher_present(self):
        pkt = build_nilist_reply("server", b"\x00" * 8, "1.2.3.4")
        assert pkt[110:122] == _ADM_EYE

    def test_nilist_opcode_in_record(self):
        pkt = build_nilist_reply("server", b"\x00" * 8, "1.2.3.4")
        # First record opcode at offset 110 (header) + 34 (adm hdr) = 144
        assert pkt[144] == ADM_NILIST

    def test_attacker_ip_in_packet(self):
        ip = "192.168.100.200"
        pkt = build_nilist_reply("server", b"\x00" * 8, ip)
        assert socket.inet_aton(ip) in pkt


# ---------------------------------------------------------------------------
# ms_parse_opcode
# ---------------------------------------------------------------------------

class TestMsParseOpcode:

    def test_parses_opcode_after_header(self):
        hdr = ms_build_header("", "", MSG_DIA, FLAG_REQUEST, 0)
        opc_bytes = bytes([0x07, 0x00, 0x01, 0x00])  # NILIST opcode
        data = hdr + opc_bytes
        result = ms_parse_opcode(data)
        assert result["opcode"] == 0x07

    def test_returns_empty_if_too_short(self):
        hdr = ms_build_header("", "", MSG_DIA, FLAG_REQUEST, 0)
        result = ms_parse_opcode(hdr)  # no opcode bytes appended
        assert result == {}

    def test_all_four_opcode_bytes_parsed(self):
        hdr = ms_build_header("", "", MSG_DIA, FLAG_REQUEST, 0)
        data = hdr + bytes([0x05, 0x01, 0x02, 0x03])
        result = ms_parse_opcode(data)
        assert result == {"opcode": 5, "error": 1, "version": 2, "charset": 3}


# ---------------------------------------------------------------------------
# Constant sanity checks
# ---------------------------------------------------------------------------

class TestConstants:

    def test_ms_eyecatcher_is_12_bytes(self):
        assert len(_MS_EYE) == 12

    def test_adm_eyecatcher_is_12_bytes(self):
        assert len(_ADM_EYE) == 12

    def test_header_len_constant_matches_build(self):
        hdr = ms_build_header("", "", MSG_DIA, FLAG_REQUEST, IFLAG_LOGIN_2)
        assert len(hdr) == _HEADER_LEN

    def test_adm_rec_size_constant(self):
        rec = _adm_record(ADM_NILIST, b"\x00" * 101)
        assert len(rec) == _ADM_REC_SIZE

    def test_adm_hdr_len_constant(self):
        # ADM header: 12 (eye) + 11 (recno) + 11 (recsize) = 34
        assert _ADM_HDR_LEN == 34

    def test_msg_all_is_0xBB(self):
        assert MSG_ALL == 0xBB

    def test_msg_dia_enq_is_0x05(self):
        assert MSG_DIA_ENQ == 0x05

    def test_dp_size_v13_is_507(self):
        assert DP_SIZE_V13 == 507

    def test_dp_size_v11_is_203(self):
        assert DP_SIZE_V11 == 203

    def test_default_reg_name(self):
        assert DEFAULT_REG_NAME == "msg_server"

    def test_default_diag_port(self):
        assert DEFAULT_DIAG_PORT == 3200
