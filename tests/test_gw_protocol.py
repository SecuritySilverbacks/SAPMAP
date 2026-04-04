#!/usr/bin/env python3
"""Tests for sap_gw_xpg_standalone.py — packet building, parsing, helpers."""

import sys
import os
import struct
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sap_gw_xpg_standalone import (
    build_p1,
    build_p2,
    build_tlv,
    parse_response,
    hexdump,
    extract_p4_output,
)


# ---------------------------------------------------------------------------
# build_p1
# ---------------------------------------------------------------------------

def test_build_p1_size():
    p1 = build_p1("10.0.0.1", "00")
    assert len(p1) == 64


def test_build_p1_service_field():
    p1 = build_p1("10.0.0.1", "00")
    # bytes 10-19: service field = "sapgw00" space-padded to 10 bytes
    service = p1[10:20]
    assert service == b"sapgw00   "


# ---------------------------------------------------------------------------
# build_p2
# ---------------------------------------------------------------------------

def test_build_p2_size():
    p2 = build_p2("10.0.0.1")
    assert len(p2) == 452


def test_build_p2_func_type():
    p2 = build_p2("10.0.0.1")
    # byte 1 in the SAPRFC v6 header is func_type = 0xCA (F_SAP_INIT)
    assert p2[1] == 0xCA


# ---------------------------------------------------------------------------
# parse_response
# ---------------------------------------------------------------------------

def test_parse_response_error():
    # Craft bytes that contain the *ERR* marker
    data = b"\x00" * 20 + b"*ERR* something went wrong" + b"\x00" * 20
    info = parse_response(data)
    assert info["error"] is True


def test_parse_response_no_error():
    data = b"\x00" * 50 + b"all good here" + b"\x00" * 50
    info = parse_response(data)
    assert info["error"] is False


def test_parse_response_conv_id():
    # Embed an 8-digit conversation ID in ASCII
    conv_id = b"12345678"
    data = b"\x00" * 10 + conv_id + b"\x00" * 50
    info = parse_response(data)
    assert info["conv_id"] == "12345678"


# ---------------------------------------------------------------------------
# hexdump
# ---------------------------------------------------------------------------

def test_hexdump_format():
    data = bytes(range(32))
    output = hexdump(data, length=16)
    lines = output.strip().split("\n")
    assert len(lines) == 2
    # First line starts with offset "0000"
    assert lines[0].startswith("0000")
    # Second line starts with offset "0010"
    assert lines[1].startswith("0010")
    # Each line has hex section and ASCII section
    for line in lines:
        parts = line.split("  ")
        # At least: offset, hex, ascii
        assert len(parts) >= 3


# ---------------------------------------------------------------------------
# build_tlv
# ---------------------------------------------------------------------------

def test_build_tlv():
    tag = b"\x10\x04\x09"
    value = b"test"
    result = build_tlv(tag, value)
    # Expected: 3-byte tag + 2-byte big-endian length (4) + 4-byte value
    assert len(result) == 3 + 2 + 4
    # Check the length field
    length_field = struct.unpack("!H", result[3:5])[0]
    assert length_field == 4
    # Check the value
    assert result[5:] == b"test"
    # Check the tag
    assert result[:3] == tag


# ---------------------------------------------------------------------------
# extract_p4_output — new kernel format (03 XX 03 03, 128-byte padded blocks)
# ---------------------------------------------------------------------------

def _build_p4_response_new_kernel(lines, block_size=128):
    """Build a fake P4 response with new-kernel padded TLV blocks."""
    # 80 bytes header (48 RFC + 32 cm_ok)
    header = b"\x00" * 80
    # Some filler before TLVs (offset 80..100)
    filler = b"\x00" * 21
    body = b""
    for idx, line in enumerate(lines):
        # First line: 03 02 03 03, subsequent: 03 03 03 03
        tag = b"\x03\x02\x03\x03" if idx == 0 else b"\x03\x03\x03\x03"
        padded = line.encode("ascii").ljust(block_size, b" ")
        length = struct.pack("!H", block_size)
        body += tag + length + padded
    return header + filler + body


def test_extract_p4_output_new_kernel_single_line():
    data = _build_p4_response_new_kernel(["s4hadm"])
    lines = extract_p4_output(data)
    assert lines == ["s4hadm"]


def test_extract_p4_output_new_kernel_multi_line():
    """Multiple output lines must all be extracted (regression: 03 04 03 03)."""
    input_lines = [
        "total 772",
        "drwxr-xr-x 2 root root 4096 Jan  1 00:00 bin",
        "drwxr-xr-x 3 root root 4096 Jan  1 00:00 etc",
        "-rw-r--r-- 1 root root  220 Jan  1 00:00 .bashrc",
    ]
    data = _build_p4_response_new_kernel(input_lines)
    lines = extract_p4_output(data)
    assert len(lines) == 4
    assert lines[0] == "total 772"
    assert "bin" in lines[1]
    assert "etc" in lines[2]
    assert ".bashrc" in lines[3]


def test_extract_p4_output_new_kernel_empty_lines_skipped():
    """Lines that are all spaces (empty after stripping) should be skipped."""
    data = _build_p4_response_new_kernel(["line1", "", "line3"])
    lines = extract_p4_output(data)
    assert lines == ["line1", "line3"]


# ---------------------------------------------------------------------------
# extract_p4_output — old kernel format (03 XX 03 04, exact-length TLVs)
# ---------------------------------------------------------------------------

def _build_p4_response_old_kernel(lines):
    """Build a fake P4 response with old-kernel TLV format."""
    header = b"\x00" * 80
    filler = b"\x00" * 21
    body = b""
    for idx, line in enumerate(lines):
        tag = b"\x03\x02\x03\x04" if idx == 0 else b"\x03\x04\x03\x04"
        encoded = line.encode("ascii")
        length = struct.pack("!H", len(encoded))
        body += tag + length + encoded
    return header + filler + body


def test_extract_p4_output_old_kernel_multi_line():
    input_lines = ["uid=1000(test)", "gid=1000(test)", "groups=1000(test)"]
    data = _build_p4_response_old_kernel(input_lines)
    lines = extract_p4_output(data)
    assert len(lines) == 3
    assert lines[0] == "uid=1000(test)"
