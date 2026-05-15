#!/usr/bin/env python3
"""Tests for CVE-2022-22536 (ICMAD) Day 1 — detection module foundation.

Covers:
  * _parse_kernel normalisation (compact "749", full "7.49 64-BIT UNICODE",
    variants 7.22 EXT / 7.22 EX2, leading-zero patch levels).
  * lookup_patch_status verdicts at every boundary in the SAP Note
    3123396 v22 patch table — one PL below = vulnerable, exact = fixed,
    one above = fixed.
  * _build_detect_payload byte structure (length, CL header, inner smuggle).
  * _count_response_lines parser (single response = patched signature,
    >=2 responses = vulnerable signature, garbage tolerated).
  * assess_icmad severity ladder (info → high → critical / no finding).
  * fingerprint_web_dispatcher discrimination on real-shape responses.
"""

from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from sap_cve_2022_22536 import (
    ICMAD_FIXED_PATCHES,
    _build_detect_payload,
    _count_response_lines,
    _parse_kernel,
    assess_icmad,
    lookup_patch_status,
)


# ---------------------------------------------------------------------------
# _parse_kernel
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("release,patch,expected", [
    # Compact form from Onapsis fingerprints
    ("749", "1036", ("7.49", "", 1036)),
    ("753", "915",  ("7.53", "", 915)),
    # Full-form from SAP Note table
    ("7.49 64-BIT UNICODE", "001036", ("7.49", "", 1036)),
    ("7.53 64-BIT", "915", ("7.53", "", 915)),
    # Variant disambiguation
    ("7.22 EXT", "1101", ("7.22", "EXT", 1101)),
    ("7.22_EX2", "1115", ("7.22", "EX2", 1115)),
    ("7.22EXT", 1100, ("7.22", "EXT", 1100)),
    # Leading-zero PL (SAP launchpad format)
    ("7.85", "000069", ("7.85", "", 69)),
    # Int PL
    ("8.04", 207, ("8.04", "", 207)),
    # Bogus PL falls back to -1
    ("7.53", "", ("7.53", "", -1)),
    ("7.53", None, ("7.53", "", -1)),
])
def test_parse_kernel(release, patch, expected):
    assert _parse_kernel(release, patch) == expected


# ---------------------------------------------------------------------------
# lookup_patch_status — one test per row in the patch table, at every
# boundary (PL-1 = vulnerable, PL = fixed, PL+1 = fixed).
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("release,variant,fixed_at", [
    ("7.22", "",    1101),
    ("7.22", "EXT", 1101),
    ("7.22", "EX2", 1101),
    ("7.49", "",    1036),
    ("7.53", "",    915),
    ("7.77", "",    429),
    ("7.81", "",    227),
    ("7.85", "",    69),
    ("7.86", "",    15),
    ("7.87", "",    4),
    ("8.04", "",    207),
])
def test_patch_boundary_each_row(release, variant, fixed_at):
    # Format the release as the canonical "7.49" or "7.49 EXT" form
    rel_str = f"{release} {variant}".strip() if variant else release

    v_below = lookup_patch_status(rel_str, fixed_at - 1)
    v_exact = lookup_patch_status(rel_str, fixed_at)
    v_above = lookup_patch_status(rel_str, fixed_at + 1)

    assert v_below["status"] == "vulnerable", (
        f"PL {fixed_at - 1} should be vulnerable for {rel_str} "
        f"(fixed_at={fixed_at}), got {v_below}")
    assert v_exact["status"] == "fixed", (
        f"PL {fixed_at} should be fixed for {rel_str}, got {v_exact}")
    assert v_above["status"] == "fixed", (
        f"PL {fixed_at + 1} should be fixed for {rel_str}, got {v_above}")
    # fixed_at echo is consistent
    assert v_exact["fixed_at"] == fixed_at


def test_patch_status_unknown_release():
    s = lookup_patch_status("7.99", 100)
    assert s["status"] == "unknown"
    assert s["fixed_at"] is None


def test_patch_status_unparseable_pl_returns_unknown_when_pl_negative():
    s = lookup_patch_status("7.53", "")
    # Release IS in the table — but PL couldn't be parsed.
    assert s["status"] == "unknown"
    assert s["fixed_at"] == 915


def test_patch_table_has_no_unexpected_entries():
    """Lock the table contents — every kernel row in SAP Note 3123396 v22
    should be present and nothing extra should appear.  Update this list
    if SAP re-issues the note with new versions."""
    expected = {
        ("7.22", ""), ("7.22", "EXT"), ("7.22", "EX2"),
        ("7.49", ""), ("7.53", ""), ("7.77", ""), ("7.81", ""),
        ("7.85", ""), ("7.86", ""), ("7.87", ""), ("8.04", ""),
    }
    assert set(ICMAD_FIXED_PATCHES.keys()) == expected


# ---------------------------------------------------------------------------
# Payload construction
# ---------------------------------------------------------------------------

def test_detect_payload_advertises_canonical_cl():
    payload = _build_detect_payload("example.host", 8000)
    assert b"Content-Length: 82646\r\n" in payload
    assert b"Connection: close\r\n" in payload
    assert b"Host: example.host:8000\r\n" in payload
    assert payload.startswith(
        b"POST /sap/admin/public/default.html HTTP/1.1\r\n")


def test_detect_payload_honours_custom_outer_path():
    """When the Onapsis canonical path 503's on a target (because the
    WD's URL filter denies it), the operator can point the smuggle at
    a path that actually forwards to the backend — e.g. /nwa/ on an
    AS Java WD config."""
    payload = _build_detect_payload("h", 1, outer_path="/nwa/")
    assert payload.startswith(b"POST /nwa/ HTTP/1.1\r\n")
    # CL header still the canonical Onapsis magic number
    assert b"Content-Length: 82646\r\n" in payload
    # Inner smuggle still lives in the tail
    assert payload.endswith(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")


def test_detect_payload_contains_smuggled_inner_request():
    payload = _build_detect_payload("h", 1)
    # Inner request lives in the trailing bytes
    assert payload.endswith(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")


def test_detect_payload_total_length_consistent():
    """Payload = header_len + 82646 body bytes."""
    payload = _build_detect_payload("h", 1)
    head_end = payload.find(b"\r\n\r\n") + 4
    body = payload[head_end:]
    assert len(body) == 82646 + len(b"\r\n\r\n" + b"GET / HTTP/1.1\r\n"
                                       b"Host: x\r\n\r\n") - 4
    # The advertised CL exactly equals 82646 — the "lie" is that body is
    # actually 82646 + 4 + len(inner), but the outer parser stops at 82646.


# ---------------------------------------------------------------------------
# Response-line parser
# ---------------------------------------------------------------------------

def test_count_responses_vulnerable_buffer():
    buf = (b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloHTTP/1.1 "
           b"503 Service Unavailable\r\n\r\n")
    assert _count_response_lines(buf) == [200, 503]


def test_count_responses_patched_buffer():
    buf = b"HTTP/1.0 503 Service Unavailable\r\ncontent-length: 9672\r\n\r\n<html>..."
    assert _count_response_lines(buf) == [503]


def test_count_responses_empty_buffer():
    assert _count_response_lines(b"") == []


def test_count_responses_garbage_buffer():
    assert _count_response_lines(b"random gibberish without status lines") == []


def test_count_responses_three_response_smuggle():
    """Some kernels emit a 3rd response when the smuggle wraps."""
    buf = (b"HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 200 OK\r\n\r\n"
           b"HTTP/1.1 404 Not Found\r\n\r\n")
    assert _count_response_lines(buf) == [200, 200, 404]


# ---------------------------------------------------------------------------
# assess_icmad — severity ladder
# ---------------------------------------------------------------------------

def _stub_probe(vulnerable=False, error="", count=1, statuses=None):
    """Inline factory for a probe_icmad replacement."""
    def fake(host, port, **kw):
        statuses_ = statuses if statuses is not None else (
            [200, 200] if vulnerable else ([503] if count == 1 else []))
        return {
            "vulnerable": vulnerable,
            "responses": statuses_,
            "response_count": len(statuses_),
            "raw_head": b"",
            "evidence": "test",
            "elapsed_ms": 1,
            "error": error,
        }
    return fake


def test_assess_severity_high_when_probe_confirms_against_wd(monkeypatch):
    import sap_cve_2022_22536 as mod
    monkeypatch.setattr(mod, "probe_icmad", _stub_probe(vulnerable=True))
    v = mod.assess_icmad("h", 44311, https=True,
                          kernel_release="7.53", kernel_patch="900",
                          is_web_dispatcher=True, verbose=False)
    assert v["severity"] == "high"
    assert "CONFIRMED" in v["summary"]


def test_assess_severity_high_when_probe_confirms_direct_icm(monkeypatch):
    import sap_cve_2022_22536 as mod
    monkeypatch.setattr(mod, "probe_icmad", _stub_probe(vulnerable=True))
    v = mod.assess_icmad("h", 8000, https=False,
                          kernel_release="7.53", kernel_patch="900",
                          is_web_dispatcher=False, verbose=False)
    assert v["severity"] == "high"
    assert "direct ICM" in v["summary"]


def test_assess_severity_info_when_only_patch_table_flags(monkeypatch):
    import sap_cve_2022_22536 as mod
    monkeypatch.setattr(mod, "probe_icmad", _stub_probe(vulnerable=False))
    v = mod.assess_icmad("h", 44311, https=True,
                          kernel_release="7.53", kernel_patch="900",
                          verbose=False)
    assert v["severity"] == "info"
    assert "behind ICMAD fix boundary" in v["summary"]


def test_assess_severity_empty_when_patched_and_probe_clean(monkeypatch):
    import sap_cve_2022_22536 as mod
    monkeypatch.setattr(mod, "probe_icmad", _stub_probe(vulnerable=False))
    v = mod.assess_icmad("h", 44311, https=True,
                          kernel_release="7.53", kernel_patch="999",
                          verbose=False)
    assert v["severity"] == ""
    assert "patched" in v["summary"]


def test_assess_severity_info_when_kernel_unknown(monkeypatch):
    import sap_cve_2022_22536 as mod
    monkeypatch.setattr(mod, "probe_icmad", _stub_probe(vulnerable=False))
    v = mod.assess_icmad("h", 44311, https=True,
                          kernel_release="", kernel_patch="",
                          verbose=False)
    assert v["severity"] == "info"
    assert "not in ICMAD patch table" in v["summary"]


def test_assess_severity_empty_when_probe_errors_and_kernel_unknown(
        monkeypatch):
    import sap_cve_2022_22536 as mod
    monkeypatch.setattr(mod, "probe_icmad",
                         _stub_probe(vulnerable=False,
                                      error="connect_ConnectionResetError"))
    v = mod.assess_icmad("h", 44311, https=True,
                          kernel_release="", kernel_patch="",
                          verbose=False)
    # No probe signal AND no patch info — refuse to flag
    assert v["severity"] == ""


# ---------------------------------------------------------------------------
# fingerprint_web_dispatcher
# ---------------------------------------------------------------------------

class _ScriptedSock:
    """Tiny scriptable socket — feeds canned response bytes to recv()."""
    def __init__(self, payload):
        self._payload = payload
    def settimeout(self, *a): pass
    def connect(self, *a): pass
    def sendall(self, *a): pass
    def recv(self, n):
        if not self._payload: return b""
        chunk, self._payload = self._payload[:n], self._payload[n:]
        return chunk
    def close(self): pass


@pytest.mark.parametrize("body,expected_is_wd,expected_evidence", [
    # Definitive WD banner
    (b"HTTP/1.1 200 OK\r\nServer: SAP Web Dispatcher 7.53/8.04\r\n"
     b"Content-Length: 0\r\n\r\n", True, "server_banner"),
    # ICMENOSERVERFOUND signature on the no-such-path probe
    (b"HTTP/1.0 503 Service Unavailable\r\nx-sap-icm-err-id: "
     b"ICMENOSERVERFOUND\r\n\r\n<html>err</html>", True, "icm_no_server_err"),
    # Plain ABAP ICM — no WD signals
    (b"HTTP/1.1 200 OK\r\nServer: SAP NetWeaver Application Server / "
     b"ABAP 758\r\n\r\n", False, ""),
    # Nginx in front — no WD signals
    (b"HTTP/1.1 404 Not Found\r\nServer: nginx/1.20.1\r\n\r\n", False, ""),
])
def test_fingerprint_web_dispatcher(monkeypatch, body, expected_is_wd,
                                      expected_evidence):
    import sapmap_scanner

    def fake_socket(*a, **k):
        return _ScriptedSock(body)
    monkeypatch.setattr(sapmap_scanner.socket, "socket", fake_socket)
    out = sapmap_scanner.fingerprint_web_dispatcher("h", 80, https=False,
                                                      timeout=2)
    assert out["is_wd"] is expected_is_wd
    assert out["evidence"] == expected_evidence


def test_fingerprint_web_dispatcher_connect_failure(monkeypatch):
    import sapmap_scanner
    def raise_(*a, **k): raise ConnectionRefusedError("nope")
    monkeypatch.setattr(sapmap_scanner.socket, "socket", raise_)
    out = sapmap_scanner.fingerprint_web_dispatcher("dead.example", 80,
                                                      timeout=2)
    assert out["is_wd"] is False
    assert out["evidence"] == ""
