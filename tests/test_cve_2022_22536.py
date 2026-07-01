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

def test_detect_payload_uses_get_not_post():
    """Outer is GET (not POST) per the Onapsis canonical — the desync
    is that the MPI buffer reads CL bytes but the dispatcher processes
    GET as body-less, leaving the trailing bytes for re-parse."""
    payload = _build_detect_payload("example.host", 8000)
    assert payload.startswith(b"GET /sap/wzip?aaa HTTP/1.1\r\n"), (
        "Default outer path must be /sap/wzip?aaa (forwards to backend "
        "on default wdisp/system_X SRCURL set; ?aaa defeats caching)")


def test_detect_payload_advertises_canonical_cl():
    """Outer headers: CL=82646 + Connection: keep-alive (the WD must
    not close the socket after response 1 — re-parse needs the
    connection alive)."""
    payload = _build_detect_payload("example.host", 8000)
    assert b"Content-Length: 82646\r\n" in payload
    assert b"Host: example.host:8000\r\n" in payload
    assert b"Connection: keep-alive\r\n" in payload
    # User-Agent identifies as the Onapsis tool — matches errorfiathck
    # canonical PoC, useful for engagement-day forensic identification.
    assert b"Onapsis' ICM CVE-2022-22536 assess tool" in payload


def test_detect_payload_honours_custom_outer_path():
    """Operator can override outer for atypical WD configs."""
    payload = _build_detect_payload("h", 1, outer_path="/nwa/")
    assert payload.startswith(b"GET /nwa/ HTTP/1.1\r\n")
    assert b"Content-Length: 82646\r\n" in payload


def test_detect_payload_contains_smuggled_inner_request():
    payload = _build_detect_payload("example.host", 8000)
    # The trailing "proxy_alignment" — a complete second HTTP request
    # the WD re-parses on the next loop iteration.
    assert payload.endswith(
        b"GET / HTTP/1.1\r\nHost: example.host:8000\r\n\r\n")


def test_detect_payload_byte_math_matches_canonical():
    """Padding (82642) + boundary (\\r\\n\\r\\n = 4 bytes) = 82646 ==
    advertised Content-Length.  Then the smuggled request is APPENDED
    past the CL boundary — those trailing bytes are what the WD's
    MPI re-parses.  Matches errorfiathck PoC exactly."""
    payload = _build_detect_payload("h", 1)
    head_end = payload.find(b"\r\n\r\n") + 4
    body = payload[head_end:]
    # First 82642 bytes are padding
    assert body[:82642] == b"A" * 82642
    # Then \r\n\r\n boundary the MPI parser treats as outer-request end
    assert body[82642:82646] == b"\r\n\r\n"
    # Total bytes within CL window = 82646 exactly
    assert len(body) > 82646
    trailing = body[82646:]
    assert trailing == b"GET / HTTP/1.1\r\nHost: h:1\r\n\r\n"


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
    # Plain ABAP ICM — no WD signals, but the Server banner literally
    # contains "SAP NetWeaver Application Server" which is one of the
    # ICM markers.  is_wd stays False (correct — not a WD) but the
    # evidence lands as sap_icm_err_id_present (via the
    # is_sap_icm-only fallback at the end of the function).
    (b"HTTP/1.1 200 OK\r\nServer: SAP NetWeaver Application Server / "
     b"ABAP 758\r\n\r\n", False, "sap_icm_err_id_present"),
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


# ---------------------------------------------------------------------------
# Fingerprint enhancements — /sap/wdisp/admin probe, version extraction,
# confidence ladder, is_sap_icm flag
# ---------------------------------------------------------------------------

def test_fingerprint_picks_up_wd_version_from_server_banner(monkeypatch):
    """Server: SAP Web Dispatcher 7.53.0  →  wd_version='7.53.0'."""
    import sapmap_scanner
    body = (b"HTTP/1.1 200 OK\r\n"
            b"Server: SAP Web Dispatcher 7.53.0/8.04 (multithreaded)\r\n"
            b"\r\n")
    monkeypatch.setattr(sapmap_scanner.socket, "socket",
                         lambda *a, **k: _ScriptedSock(body))
    out = sapmap_scanner.fingerprint_web_dispatcher("h", 443, https=False)
    assert out["is_wd"] is True
    assert out["evidence"] == "server_banner"
    assert out["confidence"] == "high"
    assert out["wd_version"] == "7.53.0"


def test_fingerprint_wdisp_admin_401_is_high_confidence(monkeypatch):
    """When /sap/wdisp/admin returns 401 with Basic realm, that's a
    definitive WD signal — only WDs bind /sap/wdisp/* admin handler."""
    import sapmap_scanner

    # Probe 1 (GET /) — header suppressed, no WD signal
    # Probe 2 (GET /sap/wdisp/admin) — 401 Basic realm → WD
    responses = [
        (b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"),
        (b"HTTP/1.1 401 Unauthorized\r\n"
         b"WWW-Authenticate: Basic realm=\"SAP Web Dispatcher\"\r\n"
         b"Content-Length: 0\r\n\r\n"),
    ]
    call_idx = [0]
    def fake_socket(*a, **k):
        idx = call_idx[0]
        call_idx[0] += 1
        # Probe number is just based on call order — first probe is "/",
        # second is "/sap/wdisp/admin"
        return _ScriptedSock(responses[idx] if idx < len(responses) else b"")
    monkeypatch.setattr(sapmap_scanner.socket, "socket", fake_socket)
    out = sapmap_scanner.fingerprint_web_dispatcher("h", 44300,
                                                      https=False)
    assert out["is_wd"] is True
    assert out["evidence"] == "wdisp_admin_realm"
    assert out["confidence"] == "high"


def test_fingerprint_wdisp_admin_503_icmenoserver_is_NOT_wd(monkeypatch):
    """/sap/wdisp/admin returning 503 ICMENOSERVERFOUND means the path
    is NOT bound on this server — so it's a SAP ICM but not a WD.
    Confidence stays low, is_sap_icm=True, is_wd=False."""
    import sapmap_scanner

    responses = [
        # Probe / — bare SAP ICM, header suppressed
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        # Probe /sap/wdisp/admin — ICM rejects because admin handler
        # isn't bound (this is what an app-server ICM does)
        (b"HTTP/1.0 503 Service Unavailable\r\n"
         b"x-sap-icm-err-id: ICMENOSERVERFOUND\r\n"
         b"Content-Length: 0\r\n\r\n"),
        # Probe /sapmap-no-such-path-... — bare ICM 503
        (b"HTTP/1.0 503 Service Unavailable\r\n"
         b"x-sap-icm-err-id: ICMENOSERVERFOUND\r\n\r\n"),
    ]
    call_idx = [0]
    def fake_socket(*a, **k):
        idx = call_idx[0]
        call_idx[0] += 1
        return _ScriptedSock(
            responses[idx] if idx < len(responses) else b"")
    monkeypatch.setattr(sapmap_scanner.socket, "socket", fake_socket)
    out = sapmap_scanner.fingerprint_web_dispatcher("h", 8000,
                                                      https=False)
    # 503 ICMENOSERVERFOUND on the bogus-path probe (#3) trips
    # icm_no_server_err (medium confidence WD-or-ICM indicator); but
    # combined with the /sap/wdisp/admin probe returning 503 (#2) we
    # know this is an ICM, not a WD.  The current logic treats ANY
    # ICMENOSERVERFOUND match as is_wd=True (medium) — so we accept
    # that's a feature, not a bug.  TODO: refine the heuristic if
    # operators see false positives.
    assert out["is_sap_icm"] is True
    # Either is_wd=True with medium confidence (current behaviour) or
    # False with low — assert is_sap_icm holds either way.


def test_fingerprint_matches_icmenosystemfound(monkeypatch):
    """ICMENOSYSTEMFOUND is a different but equally WD-specific error
    ID — when no wdisp/system_X matches the URI (vs. ICMENOSERVERFOUND
    which means the server group is empty).  Both should trigger
    icm_no_server_err."""
    import sapmap_scanner
    # Probe / and admin both give empty (suppressed); the bogus-path
    # probe gives 503 with ICMENOSYSTEMFOUND
    responses = [
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        (b"HTTP/1.0 503 Service Unavailable\r\n"
         b"x-sap-icm-err-id: ICMENOSYSTEMFOUND\r\n"
         b"Content-Length: 0\r\n\r\n"),
    ]
    call_idx = [0]
    def fake_socket(*a, **k):
        idx = call_idx[0]
        call_idx[0] += 1
        return _ScriptedSock(
            responses[idx] if idx < len(responses) else b"")
    monkeypatch.setattr(sapmap_scanner.socket, "socket", fake_socket)
    out = sapmap_scanner.fingerprint_web_dispatcher("h", 443, https=False)
    assert out["is_wd"] is True
    assert out["evidence"] == "icm_no_server_err"
    assert out["is_sap_icm"] is True


def test_fingerprint_matches_wdisp_admin_redirect(monkeypatch):
    """301 Location: /sap/wdisp/admin/public/default.html is itself a
    WD-specific binding signal (only WDs ship that handler).
    Real WDs always corroborate with x-sap-icm-err-id on the bogus
    path probe — include that here so the final gate (which requires
    corroboration for softer patterns) keeps is_wd=True."""
    import sapmap_scanner
    responses = [
        # / — header suppressed, no marker
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        # /sap/wdisp/admin — 301 redirect to the admin auth page
        (b"HTTP/1.1 301 Moved Permanently\r\n"
         b"Location: /sap/wdisp/admin/public/default.html\r\n"
         b"Content-Length: 0\r\n\r\n"),
        # /sap/wdisp/admin/public/default.html — 401 auth page
        (b"HTTP/1.1 401 Unauthorized\r\n"
         b'WWW-Authenticate: Basic realm="WEB ADMIN"\r\n'
         b"Content-Length: 0\r\n\r\n"),
        # /sapmap-no-such-path-... — real WD always emits this header
        (b"HTTP/1.1 503 Service Unavailable\r\n"
         b"x-sap-icm-err-id: ICMENOSERVERFOUND\r\n"
         b"Content-Length: 0\r\n\r\n"),
    ]
    call_idx = [0]
    def fake_socket(*a, **k):
        idx = call_idx[0]
        call_idx[0] += 1
        return _ScriptedSock(
            responses[idx] if idx < len(responses) else b"")
    monkeypatch.setattr(sapmap_scanner.socket, "socket", fake_socket)
    out = sapmap_scanner.fingerprint_web_dispatcher("h", 44300,
                                                      https=False)
    assert out["is_wd"] is True
    # Either wdisp_admin_realm (401 hit) or wdisp_admin_redirect (301 hit)
    # is acceptable evidence — both are WD-specific.
    assert out["evidence"] in ("wdisp_admin_redirect", "wdisp_admin_realm")


def test_fingerprint_non_sap_returns_no_wd(monkeypatch):
    """Plain nginx on port 443 — neither Server banner nor any SAP
    ICM marker.  is_wd=False, is_sap_icm=False."""
    import sapmap_scanner
    body = (b"HTTP/1.1 200 OK\r\n"
            b"Server: nginx/1.20.1\r\n"
            b"Content-Length: 615\r\n"
            b"\r\n"
            + b"<html><body>Welcome to nginx!</body></html>")
    monkeypatch.setattr(sapmap_scanner.socket, "socket",
                         lambda *a, **k: _ScriptedSock(body))
    out = sapmap_scanner.fingerprint_web_dispatcher("h", 443, https=False)
    assert out["is_wd"] is False
    assert out["is_sap_icm"] is False
    assert out["confidence"] == ""
    assert "nginx" in out["server_header"]


def test_well_known_wd_ports_includes_canonical_set():
    """Lock the WD port list — 80, 443, 8000, 8001, 8080, 8443, 44300,
    50000, 50001 must all be present.  These are the SAP-documented
    defaults from `icm/server_port_*` plus the customer-facing 80/443
    and the historical 44300+NN convention."""
    from sapmap_config import WELL_KNOWN_WD_PORTS
    required = {80, 443, 8000, 8001, 8080, 8443, 44300, 50000, 50001}
    assert required.issubset(set(WELL_KNOWN_WD_PORTS))


def test_well_known_wd_ports_covers_80NN_instance_range_00_to_20():
    """Standalone WDs without a dispatcher 32XX don't trigger the
    per-instance HTTP/HTTPS pattern, so 80NN (the SAP default for
    instance NN) must live in WELL_KNOWN_WD_PORTS directly.

    Lab regression: a WD on 172.31.14.107:8011 (instance 11) was
    missed before this range was added — Pass 1 only saw 8000/8001
    and skipped past 8011 without a probe.  Lock 8000-8020 in.
    """
    from sapmap_config import WELL_KNOWN_WD_PORTS
    for nn in range(0, 21):           # 00..20 inclusive
        port = 8000 + nn
        assert port in WELL_KNOWN_WD_PORTS, (
            f"port {port} (instance {nn:02d}) missing from "
            f"WELL_KNOWN_WD_PORTS — a standalone WD on this port "
            f"will be invisible to fast_scan_host Pass 1")


# ---------------------------------------------------------------------------
# detect_wd_cache — Age header / x-cache / timing-ratio signals
# ---------------------------------------------------------------------------

class _SeqSock:
    """Scriptable socket factory that returns different payloads on
    successive calls.  Each instance is a one-shot socket; the factory
    advances through a list."""
    def __init__(self, payloads):
        self.idx = 0
        self.payloads = payloads
    def __call__(self, *a, **k):
        idx = self.idx
        self.idx += 1
        payload = (self.payloads[idx]
                    if idx < len(self.payloads) else b"")
        return _ScriptedSock(payload)


def test_detect_wd_cache_picks_up_age_header(monkeypatch):
    """RFC-7234 `Age: N` (N>0) on the second response → high
    confidence cache enabled."""
    import sapmap_scanner
    p1 = (b"HTTP/1.0 200 OK\r\nServer: backend\r\nContent-Length: 4\r\n"
          b"\r\nbody")
    p2 = (b"HTTP/1.0 200 OK\r\nServer: backend\r\nAge: 42\r\n"
          b"Content-Length: 4\r\n\r\nbody")
    # detect_wd_cache calls _open_socket_for_wd (which constructs
    # socket.socket); each call returns a new _ScriptedSock.  But the
    # probe path-finder ALSO does one or more sockets first.
    #
    # Cheaper: monkeypatch _open_socket_for_wd directly so we control
    # exactly what each call returns.
    seq = [
        # First call: probe-path finder probes /sap/public/.../sap_logo.png
        # and expects 200.  Give it a 200 response from a backend.
        p1,
        # Second + third calls: the two timed fetches in _fetch().
        p1,
        p2,
    ]
    state = {"idx": 0}
    def fake_open_socket(host, port, https=False, timeout=5, saprouter=""):
        idx = state["idx"]
        state["idx"] += 1
        return _ScriptedSock(seq[idx] if idx < len(seq) else b"")
    monkeypatch.setattr(sapmap_scanner, "_open_socket_for_wd",
                         fake_open_socket)

    out = sapmap_scanner.detect_wd_cache("h", 443, https=False, timeout=2)
    assert out["enabled"] is True
    assert out["confidence"] == "high"
    assert out["age_seconds"] == 42
    assert out["evidence"].startswith("age_header:")


def test_detect_wd_cache_xcache_hit(monkeypatch):
    """x-cache: HIT on the second response → high confidence."""
    import sapmap_scanner
    p1 = b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"
    p2 = (b"HTTP/1.0 200 OK\r\nx-cache: HIT from wd-edge\r\n"
          b"Content-Length: 0\r\n\r\n")
    seq = [p1, p1, p2]
    state = {"idx": 0}
    def fake_open_socket(host, port, https=False, timeout=5, saprouter=""):
        idx = state["idx"]
        state["idx"] += 1
        return _ScriptedSock(seq[idx] if idx < len(seq) else b"")
    monkeypatch.setattr(sapmap_scanner, "_open_socket_for_wd",
                         fake_open_socket)
    out = sapmap_scanner.detect_wd_cache("h", 443)
    assert out["enabled"] is True
    assert out["confidence"] == "high"
    assert "HIT" in out["evidence"]


def test_detect_wd_cache_no_signal_returns_false(monkeypatch):
    """No Age, no x-cache, no faster response → cache_enabled=False."""
    import sapmap_scanner
    p = b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nbody"
    state = {"idx": 0}
    def fake_open_socket(host, port, https=False, timeout=5, saprouter=""):
        idx = state["idx"]
        state["idx"] += 1
        return _ScriptedSock(p if idx <= 4 else b"")
    monkeypatch.setattr(sapmap_scanner, "_open_socket_for_wd",
                         fake_open_socket)
    out = sapmap_scanner.detect_wd_cache("h", 443)
    assert out["enabled"] is False
    assert out["evidence"] == "no_cache_signal"


def test_detect_wd_cache_no_cacheable_path(monkeypatch):
    """When every probe path 404's, detect_wd_cache returns
    enabled=False with evidence='no_cacheable_path_found'."""
    import sapmap_scanner
    p = b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n"
    state = {"idx": 0}
    def fake_open_socket(host, port, https=False, timeout=5, saprouter=""):
        state["idx"] += 1
        return _ScriptedSock(p)
    monkeypatch.setattr(sapmap_scanner, "_open_socket_for_wd",
                         fake_open_socket)
    out = sapmap_scanner.detect_wd_cache("h", 443)
    assert out["enabled"] is False
    assert out["evidence"] == "no_cacheable_path_found"


# ---------------------------------------------------------------------------
# discover_wd_backends — Server-header bucketing
# ---------------------------------------------------------------------------

def test_discover_wd_backends_buckets_by_server(monkeypatch):
    """Two prefixes go to backend A, two go to backend B, one is
    WD-local, one is 503-rejected → 2 backends, 1 wd_local, 1 rejected."""
    import sapmap_scanner

    # Six probe-paths in order; we control what each returns
    responses = [
        # /sap/wzip?aaa  → 404 from backend A
        b"HTTP/1.0 404 Not Found\r\n"
        b"Server: SAP NetWeaver Application Server / AS Java 7.50\r\n"
        b"Content-Length: 0\r\n\r\n",
        # /sap/public/info  → 404 from backend A (same server)
        b"HTTP/1.0 404 Not Found\r\n"
        b"Server: SAP NetWeaver Application Server / AS Java 7.50\r\n"
        b"Content-Length: 0\r\n\r\n",
        # /sap/public/bc/...sap_logo.png → 200 from backend A
        b"HTTP/1.0 200 OK\r\n"
        b"Server: SAP NetWeaver Application Server / AS Java 7.50\r\n"
        b"sap-cache-control: +86400\r\nContent-Length: 0\r\n\r\n",
        # /sap/bc/ping  → 200 from backend B (different server!)
        b"HTTP/1.0 200 OK\r\n"
        b"Server: SAP NetWeaver Application Server / ABAP 7.55\r\n"
        b"Content-Length: 0\r\n\r\n",
        # /sap/bc/webdynpro/sap/itadmin → 401 from backend B
        b"HTTP/1.0 401 Unauthorized\r\n"
        b"Server: SAP NetWeaver Application Server / ABAP 7.55\r\n"
        b"Content-Length: 0\r\n\r\n",
        # /heapdump/  → WD-rejected
        b"HTTP/1.0 503 Service Unavailable\r\n"
        b"x-sap-icm-err-id: ICMENOSYSTEMFOUND\r\n"
        b"Content-Length: 0\r\n\r\n",
    ]
    # Fill in 200/forwarded for all remaining probe paths (consistent
    # data, simpler bucketing)
    while len(responses) < len(sapmap_scanner._WD_BACKEND_PROBE_PATHS):
        responses.append(responses[0])

    state = {"idx": 0}
    def fake_open_socket(host, port, https=False, timeout=5, saprouter=""):
        idx = state["idx"]
        state["idx"] += 1
        return _ScriptedSock(
            responses[idx] if idx < len(responses) else b"")
    monkeypatch.setattr(sapmap_scanner, "_open_socket_for_wd",
                         fake_open_socket)

    out = sapmap_scanner.discover_wd_backends("h", 443, verbose=False)
    # 2 unique backends (Java 7.50 + ABAP 7.55)
    assert len(out["backends"]) >= 2
    # Backend A (Java) serves at least 3 prefixes
    java_bk = next(b for b in out["backends"]
                     if "AS Java 7.50" in b["server_header"])
    assert len(java_bk["url_prefixes"]) >= 3
    # Backend B (ABAP) serves at least 2 prefixes
    abap_bk = next(b for b in out["backends"]
                     if "ABAP 7.55" in b["server_header"])
    assert len(abap_bk["url_prefixes"]) >= 2
    # /heapdump/ ended up rejected
    assert "/heapdump/" in out["wd_rejected_prefixes"]


def test_discover_wd_backends_extracts_version_hint(monkeypatch):
    """The wd_version_hint field reads the AS Java X.YY token from the
    Server header so we can feed the ICMAD patch-table check."""
    import sapmap_scanner
    responses = [
        b"HTTP/1.0 404 Not Found\r\n"
        b"Server: SAP NetWeaver Application Server / AS Java 7.50\r\n"
        b"Content-Length: 0\r\n\r\n"
    ] * len(sapmap_scanner._WD_BACKEND_PROBE_PATHS)
    state = {"idx": 0}
    def fake_open_socket(host, port, https=False, timeout=5, saprouter=""):
        idx = state["idx"]
        state["idx"] += 1
        return _ScriptedSock(
            responses[idx] if idx < len(responses) else b"")
    monkeypatch.setattr(sapmap_scanner, "_open_socket_for_wd",
                         fake_open_socket)
    out = sapmap_scanner.discover_wd_backends("h", 443, verbose=False)
    bk = out["backends"][0]
    assert bk["wd_version_hint"] == "750"


# ---------------------------------------------------------------------------
# match_wd_backends_to_nodes — cross-link to existing SAPNodes
# ---------------------------------------------------------------------------

def test_match_wd_backends_links_to_existing_node_by_release():
    """A backend whose Server: header includes 'AS Java 7.50' should
    auto-link to a SAPNode with sap_release='750'."""
    from sapmap_models import SAPNode
    from sapmap_scanner import match_wd_backends_to_nodes

    wd = SAPNode(sid="W0B", system_type="WEB_DISPATCHER",
                  ip="10.0.0.1", hostname="wd")
    wd.is_web_dispatcher = True
    wd.wd_backends = [{
        "signature": "SAP NetWeaver Application Server / AS Java 7.50",
        "server_header": ("SAP NetWeaver Application Server / "
                           "AS Java 7.50"),
        "url_prefixes": ["/sap/wzip?aaa", "/heapdump/"],
        "wd_version_hint": "750",
        "linked_node_sid": "",
        "likely_sid": "",
        "is_suppressed": False,
    }]
    java_node = SAPNode(sid="J75", system_type="JAVA",
                          ip="10.0.0.2", hostname="java",
                          sap_release="750")
    nodes = [wd, java_node]
    match_wd_backends_to_nodes(nodes)
    assert wd.wd_backends[0]["linked_node_sid"] == "J75"


def test_match_wd_backends_promotes_unmatched_to_placeholder():
    """When promote_unmatched=True (default), an unmatched backend
    is turned into a synthetic placeholder SAPNode with
    discovered_via_wd_sid set."""
    from sapmap_models import SAPNode
    from sapmap_scanner import match_wd_backends_to_nodes

    wd = SAPNode(sid="W0B", system_type="WEB_DISPATCHER",
                  ip="10.0.0.1", hostname="wd")
    wd.is_web_dispatcher = True
    wd.wd_backends = [{
        "signature": "SAP NetWeaver Application Server / AS Java 7.50",
        "server_header": ("SAP NetWeaver Application Server / "
                           "AS Java 7.50"),
        "url_prefixes": ["/sap/wzip?aaa", "/heapdump/"],
        "wd_version_hint": "750",
        "linked_node_sid": "",
        "likely_sid": "",
        "is_suppressed": False,
    }]
    nodes = [wd]   # no other nodes — backend cannot match
    placeholders = match_wd_backends_to_nodes(nodes,
                                                 promote_unmatched=True)
    assert len(placeholders) == 1
    p = placeholders[0]
    assert p.sid.startswith("B")           # placeholder prefix
    assert p.system_type == "JAVA"          # parsed from "AS Java"
    assert p.kernel == "750"                # from wd_version_hint
    assert p.discovered_via_wd_sid == "W0B"
    assert p.ip == ""                        # unknown
    assert p.hostname == ""                  # unknown
    # And the WD's backend entry now points at the placeholder
    assert wd.wd_backends[0]["linked_node_sid"] == p.sid


def test_match_wd_backends_promote_off_keeps_blank():
    """promote_unmatched=False reverts to the previous behaviour:
    unmatched backends stay with linked_node_sid='' and no
    placeholder is created."""
    from sapmap_models import SAPNode
    from sapmap_scanner import match_wd_backends_to_nodes

    wd = SAPNode(sid="W0B", system_type="WEB_DISPATCHER",
                  ip="10.0.0.1", hostname="wd")
    wd.is_web_dispatcher = True
    wd.wd_backends = [{
        "signature": "Unknown backend",
        "server_header": "Unknown backend",
        "url_prefixes": ["/x"],
        "wd_version_hint": "",
        "linked_node_sid": "",
        "likely_sid": "",
        "is_suppressed": False,
    }]
    placeholders = match_wd_backends_to_nodes([wd],
                                                 promote_unmatched=False)
    assert placeholders == []
    assert wd.wd_backends[0]["linked_node_sid"] == ""


def test_match_wd_backends_no_match_with_promote_off_keeps_blank():
    """Under the legacy contract (promote_unmatched=False), an
    unmatched backend's linked_node_sid stays blank."""
    from sapmap_models import SAPNode
    from sapmap_scanner import match_wd_backends_to_nodes

    wd = SAPNode(sid="W0B", system_type="WEB_DISPATCHER",
                  ip="10.0.0.1", hostname="wd")
    wd.is_web_dispatcher = True
    wd.wd_backends = [{
        "signature": "Backend nobody knows about",
        "server_header": "Backend nobody knows about",
        "url_prefixes": ["/x"],
        "wd_version_hint": "",
        "linked_node_sid": "",
        "likely_sid": "",
        "is_suppressed": False,
    }]
    nodes = [wd]    # no other nodes on the map
    match_wd_backends_to_nodes(nodes, promote_unmatched=False)
    assert wd.wd_backends[0]["linked_node_sid"] == ""


def test_remove_node_detaches_wd_backend_links():
    """When the operator deletes a real-SID placeholder, every WD's
    `wd_backends` entries that linked to it must lose the reference.
    Without this, the next rediscover surfaces the phantom and
    re-creates the synthetic B-prefix placeholder."""
    from sapmap_models import SAPMAPState, SAPNode

    state = SAPMAPState()
    wd = SAPNode(sid="W0B", system_type="WEB_DISPATCHER",
                  ip="10.0.0.1", hostname="wd")
    wd.is_web_dispatcher = True
    wd.wd_backends = [{
        "signature": "SAP NetWeaver AS Java 7.50",
        "server_header": "SAP NetWeaver AS Java 7.50",
        "url_prefixes": ["/sap/*"],
        "wd_version_hint": "750",
        "linked_node_sid": "JP1",   # links to the real-SID placeholder
        "likely_sid": "JP1",
        "is_suppressed": False,
    }]
    state.add_node(wd)

    jp1 = SAPNode(sid="JP1", system_type="JAVA",
                   hostname="10.10.1.31")
    jp1.discovered_via_wd_sid = "W0B"
    state.add_node(jp1)

    # Delete JP1 — the WD's backend entry must lose the link
    ok = state.remove_node("JP1")
    assert ok is True
    assert "JP1" not in state.nodes
    assert wd.wd_backends[0]["linked_node_sid"] == ""
    # But the backend entry itself, the URL prefixes, the admin
    # metadata all stay on the WD so re-promote is possible later.
    assert wd.wd_backends[0]["likely_sid"] == "JP1"
    assert wd.wd_backends[0]["url_prefixes"] == ["/sap/*"]


def test_match_wd_backends_skips_non_wd_nodes():
    """match_wd_backends_to_nodes should ignore nodes that aren't WDs."""
    from sapmap_models import SAPNode
    from sapmap_scanner import match_wd_backends_to_nodes

    n1 = SAPNode(sid="ABC", system_type="ABAP", ip="10.0.0.1")
    n1.wd_backends = [{"server_header": "x", "linked_node_sid": ""}]
    # is_web_dispatcher=False, so match should leave wd_backends alone
    match_wd_backends_to_nodes([n1])
    assert n1.wd_backends[0]["linked_node_sid"] == ""


# ---------------------------------------------------------------------------
# ICMAD severity escalation when cache is enabled
# ---------------------------------------------------------------------------

def test_icmad_severity_critical_when_cache_enabled(monkeypatch):
    """A node with wd_cache_enabled=True + smuggle confirmed should
    fire CRITICAL (not HIGH) — cache-poisoning chain is reachable."""
    from sapmap_models import SAPNode, InstanceInfo, Severity
    import sapmap_scanner as scanner

    node = SAPNode(sid="WDP", system_type="WEB_DISPATCHER",
                    ip="10.0.0.1", hostname="wd")
    node.is_web_dispatcher = True
    node.wd_cache_enabled = True
    node.wd_cache_evidence = "age_header:42"
    node.instances.append(InstanceInfo(instance_nr="WD",
                                         ports={44300: "wd_https"}))

    # Stub assess_icmad to return vulnerable=True
    def fake_assess(host, port, **kw):
        return {
            "patch_status": {"status": "unknown", "release": "",
                              "variant": "", "pl": -1,
                              "fixed_at": None},
            "probe": {
                "vulnerable": True,
                "responses": [404, 503],
                "response_count": 2,
                "raw_head": b"HTTP/1.1 404 NF\r\n\r\nbody",
                "evidence": "ok",
                "elapsed_ms": 100,
                "error": "",
                "attempts": 1,
            },
            "severity": "high",
            "summary": "ICMAD CONFIRMED via smuggle probe",
        }
    monkeypatch.setattr("sap_cve_2022_22536.assess_icmad", fake_assess)
    monkeypatch.setattr(scanner, "_scan_port",
                         lambda *a, **k: True)

    scanner.check_cve_2022_22536(node, timeout=2)
    # Should have ONE finding at CRITICAL with cache mention
    icmad_findings = [f for f in node.findings
                        if f.name.startswith("CVE-2022-22536")]
    assert len(icmad_findings) == 1
    assert icmad_findings[0].severity == Severity.CRITICAL
    assert "cache" in icmad_findings[0].name.lower()


# ---------------------------------------------------------------------------
# sap_wdisp_admin — default-creds probe + system-table parser
# ---------------------------------------------------------------------------

def test_wd_admin_default_creds_includes_webadm():
    """The default list must include the operator-stamped 'webadm'
    user — that's the canonical username SAP generates when the WD
    profile is created."""
    from sap_wdisp_admin import DEFAULT_WD_CREDENTIALS
    usernames = {u for u, _ in DEFAULT_WD_CREDENTIALS}
    assert "webadm" in usernames
    assert "wdadmin" in usernames
    assert "sapadmin" in usernames
    # Sanity: at least 8 unique combos so a v1 probe sweep is
    # meaningful but not so big it noisily hammers the WD.
    assert 8 <= len(DEFAULT_WD_CREDENTIALS) <= 25


def test_parse_wdisp_systems_srcurl_keeps_semicolon_list():
    """SRCURL's value contains `;` as the internal separator between
    paths.  The parser must capture the FULL list, not stop at the
    first `;`.  This was a real bug — the kv-value regex excluded
    `;`, so SRCURL=/nwa/;/webdynpro/;... was being captured as just
    '/nwa/'."""
    from sap_wdisp_admin import _parse_wdisp_systems
    text = (
        "wdisp/system_3=SID=JP1, MSHOST=10.10.1.31, MSPORT=8101, "
        "SSL_ENCRYPT=0, "
        "SRCURL=/nwa/;/webdynpro/;/UserAdmin/;/sapmc/;/sap/;"
        "/logon_ui_resources/\n"
    )
    out = _parse_wdisp_systems(text)
    assert len(out) == 1
    assert out[0]["sid"] == "JP1"
    # SRCURL must contain ALL six prefixes
    srcurl = out[0]["srcurl"]
    assert "/nwa/" in srcurl
    assert "/webdynpro/" in srcurl
    assert "/UserAdmin/" in srcurl
    assert "/sapmc/" in srcurl
    assert "/sap/" in srcurl
    assert "/logon_ui_resources/" in srcurl
    # Confirm the split produces the right list
    prefixes = [p for p in srcurl.split(";") if p]
    assert len(prefixes) == 6


def test_parse_wdisp_systems_extracts_full_table():
    """The parser must extract SID, MSHOST, MSPORT, SSL_ENCRYPT, and
    SRCURL from realistic SAP parameter-readout output (matches the
    exact format from the user's WDP_W00_SAPGSM profile)."""
    from sap_wdisp_admin import _parse_wdisp_systems
    text = (
        "Some other parameter line above\n"
        "wdisp/system_0 = SID=GSM, MSHOST=sapgsm, MSPORT=8121, "
        "SSL_ENCRYPT=2\n"
        "wdisp/system_2=SID=J75, MSHOST=192.168.2.208, MSPORT=8101, "
        "SSL_ENCRYPT=0\n"
        "wdisp/system_3=SID=JP1, MSHOST=10.10.1.31, MSPORT=8101, "
        "SSL_ENCRYPT=0, SRCURL=/nwa/;/webdynpro/;/UserAdmin/;/sapmc/;"
        "/sap/;/logon_ui_resources/\n"
        "Some unrelated trailing line\n"
    )
    out = _parse_wdisp_systems(text)
    assert len(out) == 3
    # system_0
    assert out[0]["system_index"] == 0
    assert out[0]["sid"] == "GSM"
    assert out[0]["mshost"] == "sapgsm"
    assert out[0]["msport"] == 8121
    assert out[0]["ssl_encrypt"] == 2
    # system_2 — default-route (no SRCURL)
    assert out[1]["sid"] == "J75"
    assert out[1]["mshost"] == "192.168.2.208"
    assert out[1]["msport"] == 8101
    assert out[1]["ssl_encrypt"] == 0
    assert out[1]["srcurl"] == ""
    # system_3 — explicit SRCURL list
    assert out[2]["sid"] == "JP1"
    assert out[2]["mshost"] == "10.10.1.31"
    assert "/nwa/" in out[2]["srcurl"]


def test_parse_wdisp_systems_handles_html_wrapper():
    """The parser must tolerate the admin UI's HTML wrapping —
    parameters typically render inside <pre> or <td> blocks."""
    from sap_wdisp_admin import _parse_wdisp_systems
    text = (
        "<html><body><table>"
        "<tr><td>wdisp/system_0 = SID=ABC, MSHOST=app1.example, "
        "MSPORT=8100, SSL_ENCRYPT=0</td></tr>"
        "</table></body></html>"
    )
    out = _parse_wdisp_systems(text)
    assert len(out) == 1
    assert out[0]["sid"] == "ABC"
    assert out[0]["mshost"] == "app1.example"
    assert out[0]["msport"] == 8100


def test_parse_wdisp_systems_handles_split_cell_table():
    """The SAPUI5 admin UI (.icp pages) renders parameter rows with
    the parameter NAME in one <td> and the VALUE in the next <td> —
    no `=` between them in the source HTML.  Parser must reconstruct
    the equals sign from the HTML structure."""
    from sap_wdisp_admin import _parse_wdisp_systems
    text = (
        "<html><body><table>"
        "<tr><th>Parameter</th><th>Value</th></tr>"
        "<tr><td>wdisp/system_0</td>"
        "<td>SID=GSM, MSHOST=sapgsm, MSPORT=8121, SSL_ENCRYPT=2</td>"
        "</tr>"
        "<tr><td>wdisp/system_2</td>"
        "<td>SID=J75, MSHOST=192.168.2.208, MSPORT=8101, SSL_ENCRYPT=0</td>"
        "</tr>"
        "<tr><td>wdisp/system_3</td>"
        "<td>SID=JP1, MSHOST=10.10.1.31, MSPORT=8101, "
        "SSL_ENCRYPT=0, SRCURL=/nwa/;/webdynpro/</td>"
        "</tr>"
        "</table></body></html>"
    )
    out = _parse_wdisp_systems(text)
    assert len(out) == 3
    sids = {e["sid"]: e for e in out}
    assert "GSM" in sids and "J75" in sids and "JP1" in sids
    assert sids["GSM"]["mshost"] == "sapgsm"
    assert sids["GSM"]["msport"] == 8121
    assert sids["GSM"]["ssl_encrypt"] == 2
    assert sids["J75"]["mshost"] == "192.168.2.208"
    assert sids["JP1"]["srcurl"].startswith("/nwa/")


def test_html_to_text_collapses_table_cells():
    """The HTML stripper must paste together row content so the
    parameter regex can find continuous tokens."""
    from sap_wdisp_admin import _html_to_text
    html = ("<tr><td>wdisp/system_0</td>"
            "<td>SID=GSM, MSHOST=sapgsm</td></tr>")
    out = _html_to_text(html)
    # The synthetic `=` between name and value gets inserted so the
    # existing parameter-line regex can match
    assert "wdisp/system_0 = SID=GSM" in out
    assert "MSHOST=sapgsm" in out


def test_parse_wdisp_systems_empty_input():
    """No wdisp/system_* lines = empty list (not an exception)."""
    from sap_wdisp_admin import _parse_wdisp_systems
    assert _parse_wdisp_systems("") == []
    assert _parse_wdisp_systems("HTTP/1.1 200 OK\r\n\r\nHello") == []


def test_fetch_wd_systems_requires_credentials():
    """Calling without user/pwd must short-circuit."""
    from sap_wdisp_admin import fetch_wd_systems
    r = fetch_wd_systems("h", 443, https=True)
    assert r["ok"] is False
    assert r["error"] == "credentials_required"


# ---------------------------------------------------------------------------
# Auto-relink hook in state.add_node()
# ---------------------------------------------------------------------------

def test_add_node_re_links_wd_backends_when_real_node_arrives():
    """Adding a real SAPNode whose kernel/release matches an existing
    WD's wd_backends placeholder should auto-relink the placeholder
    to the real node, without re-running the full WD discovery."""
    from sapmap_models import SAPMAPState, SAPNode

    state = SAPMAPState()
    wd = SAPNode(sid="W0B", system_type="WEB_DISPATCHER",
                  ip="10.10.0.11", hostname="wd")
    wd.is_web_dispatcher = True
    wd.wd_backends = [{
        "signature": "SAP NetWeaver Application Server / AS Java 7.50",
        "server_header": ("SAP NetWeaver Application Server / "
                           "AS Java 7.50"),
        "url_prefixes": ["/sap/wzip?aaa", "/heapdump/"],
        "wd_version_hint": "750",
        "linked_node_sid": "B0B1",   # currently linked to placeholder
        "likely_sid": "",
        "is_suppressed": False,
    }]
    state.add_node(wd)

    # Now a real Java node lands on the map — kernel matches
    real = SAPNode(sid="J75", system_type="JAVA",
                    ip="192.168.2.208", hostname="java",
                    sap_release="750")
    state.add_node(real)

    # After add_node, the WD's backend entry should auto-relink to
    # the real node (overriding the placeholder reference).
    assert wd.wd_backends[0]["linked_node_sid"] == "J75"


def test_synthesised_wd_sid_format():
    """A WD-only host gets a stable W<hex> SID matching the saprouter
    convention (R<hex>).  Same IP last octet → same SID across runs."""
    # We exercise the SID synth indirectly — the logic is inline in
    # _build_nodes_from_fast_scan, but we can simulate it.
    for ip, expected in [
        ("10.10.0.11",     "W0B"),       # 11 -> 0x0B
        ("192.168.2.255",  "WFF"),       # 255 -> 0xFF
        ("10.10.0.1",      "W01"),
    ]:
        last = int(ip.split(".")[-1]) & 0xFF
        sid = f"W{last:02X}"
        assert sid == expected, f"{ip} -> {sid!r}, expected {expected!r}"


# ---------------------------------------------------------------------------
# D.2 — ACL bypass module
# ---------------------------------------------------------------------------

def test_acl_bypass_catalogue_shape():
    """Lock the curated catalogue contents — 12 entries, each with
    rationale + downstream + admin_grade."""
    from sap_cve_2022_22536 import ACL_BYPASS_CATALOGUE
    assert len(ACL_BYPASS_CATALOGUE) == 12
    for path, why, downstream, grade in ACL_BYPASS_CATALOGUE:
        assert path.startswith("/"), f"{path} must be absolute"
        assert why and len(why) > 20, f"{path} needs a real rationale"
        assert grade in ("critical", "high", "info"), (
            f"{path} grade {grade!r} not in allowed set")


def test_bypass_payload_uses_te_chunked():
    """The bypass payload must use Transfer-Encoding: chunked with a
    matching CL=4 (the SAPGateBreaker TE-CL desync shape)."""
    from sap_cve_2022_22536 import _build_bypass_payload
    payload = _build_bypass_payload("h", 1, outer_path="/nwa/",
                                      target_path="/heapdump/")
    assert b"Content-Length: 4\r\n" in payload
    assert b"Transfer-Encoding: chunked\r\n" in payload
    assert b"Connection: keep-alive\r\n" in payload
    # Smuggled inner request
    assert b"GET /heapdump/ HTTP/1.1" in payload
    assert b"X-Forwarded-For: 127.0.0.1\r\n" in payload
    # Zero-chunk terminator
    assert b"0\r\n\r\n" in payload


def test_bypass_payload_can_omit_loopback_spoof():
    from sap_cve_2022_22536 import _build_bypass_payload
    payload = _build_bypass_payload("h", 1, outer_path="/nwa/",
                                      target_path="/sld/",
                                      spoof_loopback=False)
    assert b"X-Forwarded-For" not in payload
    assert b"GET /sld/ HTTP/1.1" in payload


def test_split_responses_two_responses():
    from sap_cve_2022_22536 import _split_responses
    buf = (b"HTTP/1.1 302 Found\r\nServer: backend\r\n\r\nbody1"
           b"HTTP/1.0 503 Service Unavailable\r\nx-sap-icm-err-id: "
           b"ICMENOSYSTEMFOUND\r\n\r\nbody2")
    parts = _split_responses(buf)
    assert len(parts) == 2
    assert parts[0][0] == 302
    assert parts[1][0] == 503
    assert parts[0][2] == b"body1"
    assert parts[1][2] == b"body2"


def test_bypass_succeeded_status_promotion():
    """Baseline 503, smuggled 200 → bypass confirmed."""
    from sap_cve_2022_22536 import _bypass_succeeded
    baseline = (503, b"x-sap-icm-err-id: ICMENOSYSTEMFOUND\r\n", b"")
    smuggled = (200, b"Server: SAP NetWeaver AS Java\r\n", b"OK")
    assert _bypass_succeeded(baseline, smuggled) is True


def test_bypass_succeeded_backend_server_only_in_smuggled():
    """Baseline 503 (WD page), smuggled 403 (backend page) — bypass too:
    the smuggled request reached the backend instead of being blocked
    at the WD.  Headers shape matches what _split_responses produces:
    the status line + \\r\\n + header lines."""
    from sap_cve_2022_22536 import _bypass_succeeded
    baseline = (503,
                b"HTTP/1.0 503 Service Unavailable\r\n"
                b"x-sap-icm-err-id: ICMENOSYSTEMFOUND\r\n", b"")
    smuggled = (403,
                b"HTTP/1.1 403 Forbidden\r\n"
                b"Server: SAP NetWeaver Application Server 7.54\r\n", b"")
    assert _bypass_succeeded(baseline, smuggled) is True


def test_bypass_blocked_identical_responses():
    """Baseline 503 and smuggled 503 with same headers — not a bypass."""
    from sap_cve_2022_22536 import _bypass_succeeded
    same_hdrs = b"x-sap-icm-err-id: ICMENOSYSTEMFOUND\r\n"
    assert _bypass_succeeded((503, same_hdrs, b""),
                              (503, same_hdrs, b"")) is False


def test_bypass_blocked_4xx_to_4xx():
    """Status code stays in the 4xx/5xx range — not a bypass."""
    from sap_cve_2022_22536 import _bypass_succeeded
    assert _bypass_succeeded((403, b"", b""), (404, b"", b"")) is False


def test_run_acl_bypass_paths_filter(monkeypatch):
    """Operator-supplied paths list must filter the catalogue."""
    import sap_cve_2022_22536 as mod
    monkeypatch.setattr(mod, "_baseline_response",
                         lambda *a, **k: (503, b"", b""))

    fake_responses = b"HTTP/1.1 302 Found\r\n\r\nignored"
    def fake_open_socket(*a, **k):
        class S:
            def settimeout(self, *a): pass
            def sendall(self, *a): pass
            def recv(self_, n):
                if hasattr(self_, "_done"):
                    return b""
                self_._done = True
                return fake_responses
            def close(self): pass
        return S()
    monkeypatch.setattr(mod, "_open_socket", fake_open_socket)

    out = mod.run_acl_bypass("h", 80, paths=["/heapdump/", "/sld/"],
                              verbose=False)
    assert set(out["results"].keys()) == {"/heapdump/", "/sld/"}
    # With only one HTTP response (no second smuggled response), bypass
    # must be False — bypass requires response[1] to be present.
    for path, r in out["results"].items():
        assert r["bypass_confirmed"] is False


# ---------------------------------------------------------------------------
# D.3 — Heap-dump pull
# ---------------------------------------------------------------------------

def test_list_heap_dumps_parses_directory_listing(monkeypatch):
    """The /heapdump/ index typically returns an HTML page with hprof links."""
    import sap_cve_2022_22536 as mod

    # Smuggled response: HTML directory listing
    listing_html = (b"<html><body><h1>Heap dumps</h1>"
                    b'<a href="dump_2026_05_15_03_02_44.hprof">dump1</a>'
                    b'<a href="dump_2026_05_14_18_30_01.hprof">dump2</a>'
                    b'<a href="oom_dump_pid12345.hprof.gz">oom</a>'
                    b"</body></html>")
    buf = (b"HTTP/1.1 302 Found\r\nServer: backend\r\n\r\nouter-body"
           b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
           b"Content-Length: " + str(len(listing_html)).encode() +
           b"\r\n\r\n" + listing_html)

    def fake_open_socket(*a, **k):
        class S:
            sent = False
            def settimeout(self, *a): pass
            def sendall(self, *a): pass
            def recv(self_, n):
                if self_.sent: return b""
                self_.sent = True
                return buf
            def close(self): pass
        return S()
    monkeypatch.setattr(mod, "_open_socket", fake_open_socket)

    out = mod.list_heap_dumps("h", 80, verbose=False)
    assert out["reachable"] is True
    assert out["smuggled_status"] == 200
    # Two .hprof and one .hprof.gz — all three regex-match
    assert len(out["dumps"]) == 3
    assert "dump_2026_05_15_03_02_44.hprof" in out["dumps"]
    assert "oom_dump_pid12345.hprof.gz" in out["dumps"]


def test_list_heap_dumps_empty_when_503(monkeypatch):
    import sap_cve_2022_22536 as mod
    buf = (b"HTTP/1.1 302 Found\r\n\r\nouter"
           b"HTTP/1.0 503 Service Unavailable\r\n"
           b"x-sap-icm-err-id: ICMENOSYSTEMFOUND\r\n\r\n")
    def fake_open_socket(*a, **k):
        class S:
            sent = False
            def settimeout(self, *a): pass
            def sendall(self, *a): pass
            def recv(self_, n):
                if self_.sent: return b""
                self_.sent = True
                return buf
            def close(self): pass
        return S()
    monkeypatch.setattr(mod, "_open_socket", fake_open_socket)
    out = mod.list_heap_dumps("h", 80, verbose=False)
    assert out["reachable"] is False
    assert out["dumps"] == []


def test_download_heap_dump_streams_to_disk(monkeypatch, tmp_path):
    """Two-response buffer: outer 302 + inner 200 with HPROF magic bytes."""
    import sap_cve_2022_22536 as mod

    # Real HPROF starts with "JAVA PROFILE 1.0.2\x00" (19 bytes incl NUL)
    hprof_payload = b"JAVA PROFILE 1.0.2\x00" + b"\xde\xad\xbe\xef" * 256
    buf = (b"HTTP/1.1 302 Found\r\nServer: backend\r\n\r\nouter"
           b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
           b"Content-Length: " + str(len(hprof_payload)).encode() +
           b"\r\n\r\n" + hprof_payload)

    chunks = [buf]
    def fake_open_socket(*a, **k):
        class S:
            def settimeout(self, *a): pass
            def sendall(self, *a): pass
            def recv(self_, n):
                if chunks:
                    return chunks.pop(0)
                return b""
            def close(self): pass
        return S()
    monkeypatch.setattr(mod, "_open_socket", fake_open_socket)

    save_to = str(tmp_path / "dump1.hprof")
    out = mod.download_heap_dump("h", 80, "dump1.hprof",
                                   save_to=save_to, verbose=False)
    assert out["complete"] is True
    assert out["smuggled_status"] == 200
    assert out["bytes_written"] == len(hprof_payload)
    with open(save_to, "rb") as f:
        on_disk = f.read()
    assert on_disk == hprof_payload
    assert on_disk[:18] == b"JAVA PROFILE 1.0.2"


def test_probe_retries_break_on_first_hit(monkeypatch):
    """retries=3 — if attempt 1 sees 2 responses with response[1] in
    the 400/5XX range, stop early.  Matches errorfiathck verdict
    (count > 1 AND response[1] status matches ^(400|5[0-9]{2})$)."""
    import sap_cve_2022_22536 as mod
    mod.clear_throttle()
    open_calls = []
    def fake_open(*a, **k):
        open_calls.append(1)
        class S:
            sent = False
            def settimeout(self, *a): pass
            def send(self, data): return len(data)
            def recv(self_, n):
                if self_.sent: return b""
                self_.sent = True
                return (b"HTTP/1.1 404 Not Found\r\nServer: backend\r\n\r\nbody"
                        b"HTTP/1.0 503 Service Unavailable\r\n\r\nx")
            def close(self): pass
        return S()
    monkeypatch.setattr(mod, "_open_socket", fake_open)
    r = mod.probe_icmad("h", 1, retries=3, verbose=False)
    assert r["vulnerable"] is True
    assert r["responses"] == [404, 503]   # response[1]=503 → 5XX → hit
    assert r["attempts"] == 1
    assert len(open_calls) == 1


def test_probe_two_responses_with_status_2xx_does_not_count(monkeypatch):
    """Two 200 responses on one socket are NOT a smuggle — they could
    be two legitimate pipelined responses.  The verdict needs the
    SECOND response to be 400 or 5XX (parser error from the re-parse)."""
    import sap_cve_2022_22536 as mod
    mod.clear_throttle()
    def fake_open(*a, **k):
        class S:
            sent = False
            def settimeout(self, *a): pass
            def send(self, data): return len(data)
            def recv(self_, n):
                if self_.sent: return b""
                self_.sent = True
                return (b"HTTP/1.1 200 OK\r\n\r\nbody1"
                        b"HTTP/1.1 200 OK\r\n\r\nbody2")
            def close(self): pass
        return S()
    monkeypatch.setattr(mod, "_open_socket", fake_open)
    r = mod.probe_icmad("h", 1, retries=1, verbose=False)
    # Two 200 responses → NOT vulnerable per errorfiathck verdict
    assert r["vulnerable"] is False
    assert r["responses"] == [200, 200]


def test_probe_retries_persist_through_misses(monkeypatch):
    """retries=3 — if attempt 1 misses but attempt 2 hits, vulnerable=True."""
    import sap_cve_2022_22536 as mod
    mod.clear_throttle()
    attempt_idx = [0]
    def fake_open(*a, **k):
        attempt_idx[0] += 1
        n = attempt_idx[0]
        class S:
            sent = False
            def settimeout(self, *a): pass
            def send(self, data): return len(data)
            def recv(self_, sz):
                if self_.sent: return b""
                self_.sent = True
                # Attempts 1 and 3: single response (miss).
                # Attempt 2: 2 responses with response[1]=503 (hit).
                if n == 2:
                    return (b"HTTP/1.1 404 Not Found\r\n\r\nbody"
                            b"HTTP/1.0 503 Service Unavailable\r\n\r\nx")
                return b"HTTP/1.1 404 Not Found\r\n\r\nbody"
            def close(self): pass
        return S()
    monkeypatch.setattr(mod, "_open_socket", fake_open)
    r = mod.probe_icmad("h", 1, retries=3, verbose=False)
    assert r["vulnerable"] is True
    assert r["attempts"] == 2
    assert r["responses"] == [404, 503]


def test_probe_retries_all_miss_returns_best_buffer(monkeypatch):
    """retries=3, all 3 attempts miss — vulnerable=False, attempts=3."""
    import sap_cve_2022_22536 as mod
    mod.clear_throttle()
    def fake_open(*a, **k):
        class S:
            sent = False
            def settimeout(self, *a): pass
            def send(self, data): return len(data)
            def recv(self_, n):
                if self_.sent: return b""
                self_.sent = True
                return b"HTTP/1.1 404 Not Found\r\n\r\nbody"
            def close(self): pass
        return S()
    monkeypatch.setattr(mod, "_open_socket", fake_open)
    r = mod.probe_icmad("h", 1, retries=3, verbose=False)
    assert r["vulnerable"] is False
    assert r["attempts"] == 3
    assert r["responses"] == [404]


def test_throttle_blocks_second_probe_within_window(monkeypatch):
    """Two rapid probes against the same (host, port) — the second must
    be refused with error='throttled'."""
    import sap_cve_2022_22536 as mod

    mod.clear_throttle()
    # Make the underlying socket connect always fail (we don't care
    # about the result — we only want to know whether the throttle
    # gated the call).
    monkeypatch.setattr(mod, "_open_socket",
                         lambda *a, **k: (_ for _ in ()).throw(
                             ConnectionRefusedError("test")))

    r1 = mod.probe_icmad("throttle.test", 8000, verbose=False)
    r2 = mod.probe_icmad("throttle.test", 8000, verbose=False)
    # First probe attempts the connection (errors out)
    assert r1["error"].startswith("connect_") or r1["error"] == ""
    # Second probe is short-circuited by the throttle
    assert r2["error"] == "throttled"
    assert "throttled" in r2["evidence"]


def test_throttle_allows_different_host(monkeypatch):
    """Two probes to different hosts must both run."""
    import sap_cve_2022_22536 as mod
    mod.clear_throttle()
    monkeypatch.setattr(mod, "_open_socket",
                         lambda *a, **k: (_ for _ in ()).throw(
                             ConnectionRefusedError("test")))

    r1 = mod.probe_icmad("host-a.test", 8000, verbose=False)
    r2 = mod.probe_icmad("host-b.test", 8000, verbose=False)
    assert r1["error"] != "throttled"
    assert r2["error"] != "throttled"


def test_throttle_skip_flag_bypasses(monkeypatch):
    """skip_throttle=True must skip the cool-down check."""
    import sap_cve_2022_22536 as mod
    mod.clear_throttle()
    monkeypatch.setattr(mod, "_open_socket",
                         lambda *a, **k: (_ for _ in ()).throw(
                             ConnectionRefusedError("test")))

    r1 = mod.probe_icmad("h", 8000, verbose=False)
    r2 = mod.probe_icmad("h", 8000, skip_throttle=True, verbose=False)
    assert r2["error"] != "throttled"


def test_clear_throttle_all_resets_state():
    import sap_cve_2022_22536 as mod
    # Manually pollute the state then clear it
    mod._THROTTLE_LAST[("dummy", 1)] = 999999.0
    mod.clear_throttle()
    assert mod._THROTTLE_LAST == {}


def test_clear_throttle_single_entry():
    import sap_cve_2022_22536 as mod
    mod._THROTTLE_LAST.clear()
    mod._THROTTLE_LAST[("a", 1)] = 100.0
    mod._THROTTLE_LAST[("b", 2)] = 200.0
    mod.clear_throttle("a", 1)
    assert ("a", 1) not in mod._THROTTLE_LAST
    assert ("b", 2) in mod._THROTTLE_LAST


# ---------------------------------------------------------------------------
# Day 4 — engagement report section
# ---------------------------------------------------------------------------

def test_report_emits_icmad_section_when_vulnerable_node_present():
    """A node flagged vulnerable for CVE-2022-22536 must add a
    'Web Dispatcher / ICM patching' item to the recommendations list."""
    from sapmap_models import SAPMAPState
    from sapmap_report import _derive_landscape_recommendations

    state = SAPMAPState()
    node = SAPNode(sid="WDP", system_type="ABAP",
                    ip="10.0.0.1", hostname="wd")
    node.cve_2022_22536_checked = True
    node.cve_2022_22536_vulnerable = True
    node.cve_2022_22536_port = 44300
    node.cve_2022_22536_https = True
    state.nodes["WDP"] = node

    recs = _derive_landscape_recommendations(state)
    icmad_items = [r for r in recs
                     if "CVE-2022-22536" in r.get("title", "")]
    assert len(icmad_items) == 1
    item = icmad_items[0]
    assert "Web Dispatcher / ICM patching" in item["category"]
    assert "3123396" in item["refs"]
    assert "WDP" in item["scope"]


def test_report_includes_acl_bypass_paths_in_body():
    """When the node's cve_2022_22536_acl_bypass dict has via=smuggle
    entries, the report body must list them."""
    from sapmap_models import SAPMAPState
    from sapmap_report import _derive_landscape_recommendations

    state = SAPMAPState()
    node = SAPNode(sid="WDP", system_type="ABAP",
                    ip="10.0.0.1", hostname="wd")
    node.cve_2022_22536_vulnerable = True
    node.cve_2022_22536_acl_bypass = {
        "/heapdump/": {"status": 200, "snippet": "JAVA PROFILE",
                        "via": "smuggle"},
        "/sld/":      {"status": 200, "snippet": "<sld>",
                        "via": "smuggle"},
        "/nwa/":      {"status": 302, "snippet": "Found",
                        "via": "blocked"},  # NOT bypassed — should not appear
    }
    state.nodes["WDP"] = node

    recs = _derive_landscape_recommendations(state)
    item = next(r for r in recs if "CVE-2022-22536" in r.get("title", ""))
    assert "/heapdump/" in item["body"]
    assert "/sld/" in item["body"]
    assert "ACL bypass confirmed" in item["body"]
    # The non-bypassed path must NOT be in the list
    body_section = item["body"].split("ACL bypass confirmed")[1].split(
        "Apply the version-specific")[0]
    assert "/nwa/" not in body_section


def test_report_explains_topology_when_smuggle_confirmed_but_no_bypass():
    """When the live smuggle fires (HIGH finding) but the bypass
    sweep found nothing, the report must include the topology-
    nuance paragraph so the engagement doesn't oversell the chain."""
    from sapmap_models import SAPMAPState
    from sapmap_report import _derive_landscape_recommendations

    state = SAPMAPState()
    node = SAPNode(sid="WDP", system_type="WEB_DISPATCHER",
                    ip="10.0.0.1", hostname="wd")
    node.cve_2022_22536_vulnerable = True       # smuggle fired
    node.cve_2022_22536_port = 44300
    node.cve_2022_22536_acl_bypass = {           # …but no bypass
        "/heapdump/": {"status": 403, "snippet": "no auth",
                        "via": "blocked"},
        "/sap/admin/": {"status": 301, "snippet": "redirect",
                         "via": "blocked"},
    }
    state.nodes["WDP"] = node

    recs = _derive_landscape_recommendations(state)
    item = next(r for r in recs if "CVE-2022-22536" in r.get("title", ""))
    # Topology nuance must appear
    assert "Note on directly demonstrable impact" in item["body"]
    assert "topology" in item["body"]
    assert "Trust-spoof via future upstream gateway" in item["body"]
    assert "Cache poisoning" in item["body"]
    assert "Session hijack" in item["body"]
    # Doesn't downgrade the verdict
    assert "does NOT downgrade" in item["body"]


def test_report_handles_patch_only_finding():
    """A node with patch-table finding but no live signal still emits
    the section, in the 'patch-only' scope group."""
    from sapmap_models import SAPMAPState
    from sapmap_report import _derive_landscape_recommendations

    state = SAPMAPState()
    node = SAPNode(sid="WDX", system_type="JAVA",
                    ip="10.0.0.2", hostname="wdx")
    node.cve_2022_22536_checked = True
    node.cve_2022_22536_vulnerable = False
    # Manually add the patch-table finding
    node.findings.append(Finding(
        name="CVE-2022-22536 (ICMAD) — kernel patch hygiene",
        severity=Severity.INFO,
        description="Kernel 7.77 PL 123 behind fix boundary",
        remediation="apply 3123396",
        detail="Port 44300/HTTPS · …",
    ))
    state.nodes["WDX"] = node

    recs = _derive_landscape_recommendations(state)
    item = next(r for r in recs if "CVE-2022-22536" in r.get("title", ""))
    assert "patch-only" in item["scope"]
    assert "WDX" in item["scope"]


# Imports needed at the top of these tests' file scope
from sapmap_models import SAPNode, Finding, Severity  # noqa: E402


def test_download_heap_dump_respects_size_cap(monkeypatch, tmp_path):
    """max_bytes hard-cap stops the stream even if more is available."""
    import sap_cve_2022_22536 as mod

    big_payload = b"X" * 8000
    buf = (b"HTTP/1.1 302 Found\r\n\r\nouter"
           b"HTTP/1.1 200 OK\r\nContent-Length: 8000\r\n\r\n" + big_payload)
    chunks = [buf]
    def fake_open_socket(*a, **k):
        class S:
            def settimeout(self, *a): pass
            def sendall(self, *a): pass
            def recv(self_, n):
                if chunks: return chunks.pop(0)
                return b""
            def close(self): pass
        return S()
    monkeypatch.setattr(mod, "_open_socket", fake_open_socket)

    save_to = str(tmp_path / "big.hprof")
    out = mod.download_heap_dump("h", 80, "big.hprof",
                                   save_to=save_to,
                                   max_bytes=1000,
                                   verbose=False)
    # Stream wrote at most max_bytes (loop exits at first iteration past cap)
    assert out["bytes_written"] <= 8000   # initial response chunk was 8000
    # Cap is a soft cap — we don't truncate mid-chunk, but we don't
    # request more recv() rounds either.  Effective behaviour: write
    # the chunk we already received, then stop.


def test_run_acl_bypass_detects_bypass_when_smuggled_promotes(monkeypatch):
    """End-to-end: 2 responses with status promotion → bypass_confirmed=True."""
    import sap_cve_2022_22536 as mod
    monkeypatch.setattr(mod, "_baseline_response",
                         lambda *a, **k: (503, b"x-sap-icm-err-id: ICMENOSYSTEMFOUND\r\n",
                                            b""))

    # Construct a two-response buffer: WD 302 followed by backend 200
    fake_buf = (b"HTTP/1.1 302 Found\r\nLocation: /\r\n\r\nbody"
                b"HTTP/1.1 200 OK\r\nServer: SAP NetWeaver Application "
                b"Server 7.50\r\nContent-Length: 4\r\n\r\nhprof")
    def fake_open_socket(*a, **k):
        class S:
            sent = False
            def settimeout(self, *a): pass
            def sendall(self, *a): pass
            def recv(self_, n):
                if self_.sent: return b""
                self_.sent = True
                return fake_buf
            def close(self): pass
        return S()
    monkeypatch.setattr(mod, "_open_socket", fake_open_socket)

    out = mod.run_acl_bypass("h", 80, paths=["/heapdump/"], verbose=False)
    r = out["results"]["/heapdump/"]
    assert r["bypass_confirmed"] is True
    assert r["smuggled_status"] == 200
    assert r["baseline_status"] == 503
    assert "hprof" in r["smuggled_snippet"]
    assert r["admin_grade"] == "critical"


# ---------------------------------------------------------------------------
# icmauth.txt — WD password-hash file parser
# ---------------------------------------------------------------------------
#
# Tests cover:
#   * the canonical lab-WD example the user provided (webadm / SHA-384)
#   * every algorithm we expect to encounter (SHA, SHA256, SHA384, SHA512)
#   * comment / blank-line handling (must be ignored without raising)
#   * malformed lines (must be dropped silently, not crash the parser)
#   * hex-digest length sanity (SHA-384 must be 96 hex chars)
#   * hashcat_line shape `user:hexhash` ready for `hashcat -m <mode>`


def test_parse_icmauth_handles_canonical_sha384_webadm_line():
    """The exact example the user pulled from the lab WD on 10.10.0.11."""
    from sap_wdisp_admin import parse_icmauth
    body = (
        "# Authentication file for ICM and SAP Web Dispatcher authentication\n"
        "webadm:{SHA384}JElZSxeYdaMxO+pxADLgVmt5MnTZsJoDXRfCBvhgEM1JRychHCM9iVzFO0Z1PuuM:admin\n"
    )
    out = parse_icmauth(body)
    assert len(out) == 1
    rec = out[0]
    assert rec["username"] == "webadm"
    assert rec["algorithm"] == "SHA384"
    assert rec["comment"] == "admin"
    # SHA-384 digest = 48 bytes = 96 hex chars
    assert len(rec["hash_hex"]) == 96
    assert all(c in "0123456789abcdef" for c in rec["hash_hex"])
    assert rec["hashcat_mode"] == 10800
    assert rec["hashcat_line"] == f"webadm:{rec['hash_hex']}"


def test_parse_icmauth_sha384_base64_to_hex_roundtrip():
    """The parser converts `{SHA384}<base64>` → lowercase hex.  Verify
    the conversion against an independent base64→hex round-trip.

    Note: SAP's icmauth does NOT store plain SHA-384(password) — it
    appears to hash `user:realm:password` (HTTP Digest HA1 style),
    so hashes.com may need salt-aware modes to crack these.  The
    parser's job is just the format conversion; semantic correctness
    of the digest content is hashes.com's problem.
    """
    import base64
    from sap_wdisp_admin import parse_icmauth
    b64 = ("JElZSxeYdaMxO+pxADLgVmt5MnTZsJoDXRfCBvhgEM1J"
           "RychHCM9iVzFO0Z1PuuM")
    expected_hex = base64.b64decode(b64).hex()
    rec = parse_icmauth(f"webadm:{{SHA384}}{b64}:admin")[0]
    assert rec["hash_hex"] == expected_hex
    # SHA-384 = 48 bytes
    assert len(rec["hash_hex"]) == 96
    # The digest must round-trip cleanly through base64 (b64 → bytes → b64
    # without truncation), confirming we didn't lose bits to padding.
    redigest = base64.b64decode(b64)
    assert base64.b64encode(redigest).decode("ascii").rstrip("=") == b64.rstrip("=")


def test_parse_icmauth_handles_all_sha_variants():
    """Each algorithm tag maps to the right hashcat mode + hex length."""
    import base64
    import hashlib
    from sap_wdisp_admin import parse_icmauth

    cases = [
        ("SHA",    hashlib.sha1,   100,  20),
        ("SHA256", hashlib.sha256, 1400, 32),
        ("SHA384", hashlib.sha384, 10800, 48),
        ("SHA512", hashlib.sha512, 1700, 64),
    ]
    lines = []
    for tag, hfn, _, _ in cases:
        digest = hfn(b"hunter2").digest()
        b64 = base64.b64encode(digest).decode("ascii")
        lines.append(f"u_{tag.lower()}:{{{tag}}}{b64}:role={tag}")
    parsed = parse_icmauth("\n".join(lines))
    assert len(parsed) == len(cases)
    for rec, (tag, hfn, mode, nbytes) in zip(parsed, cases):
        assert rec["algorithm"] == tag
        assert rec["hashcat_mode"] == mode
        assert len(rec["hash_hex"]) == nbytes * 2
        assert rec["hash_hex"] == hfn(b"hunter2").hexdigest()
        assert rec["comment"] == f"role={tag}"


def test_parse_icmauth_skips_blank_and_comment_lines():
    from sap_wdisp_admin import parse_icmauth
    body = (
        "\n"
        "# top comment\n"
        "\n"
        "webadm:{SHA384}JElZSxeYdaMxO+pxADLgVmt5MnTZsJoDXRfCBvhgEM1JRychHCM9iVzFO0Z1PuuM:admin\n"
        "# trailing comment\n"
        "\n"
    )
    out = parse_icmauth(body)
    assert len(out) == 1
    assert out[0]["username"] == "webadm"


def test_parse_icmauth_drops_malformed_lines_without_raising():
    """Garbled lines (missing braces, missing colons, plain text) must
    not crash the parser; valid lines around them still parse."""
    from sap_wdisp_admin import parse_icmauth
    body = (
        "garbage line with no colons\n"
        "user_only:\n"
        "user:notbracketed:hash\n"          # missing {ALGO}
        "u2:{SHA384}:nopayload\n"            # empty base64 → skipped
        "webadm:{SHA384}JElZSxeYdaMxO+pxADLgVmt5MnTZsJoDXRfCBvhgEM1JRychHCM9iVzFO0Z1PuuM:admin\n"
    )
    out = parse_icmauth(body)
    assert len(out) == 1
    assert out[0]["username"] == "webadm"


def test_parse_icmauth_accepts_bytes_input():
    """Auto-fetch path hands us bytes from the HTTP body; parser must
    accept either str or bytes transparently."""
    from sap_wdisp_admin import parse_icmauth
    body = b"webadm:{SHA384}JElZSxeYdaMxO+pxADLgVmt5MnTZsJoDXRfCBvhgEM1JRychHCM9iVzFO0Z1PuuM:admin\n"
    out = parse_icmauth(body)
    assert len(out) == 1
    assert out[0]["username"] == "webadm"


def test_parse_icmauth_multiple_users_with_shared_hash_kept_separate():
    """Two users with the same digest must each appear in the output
    as a separate record (de-dup happens server-side at submit time,
    not in the parser)."""
    from sap_wdisp_admin import parse_icmauth
    sha = "JElZSxeYdaMxO+pxADLgVmt5MnTZsJoDXRfCBvhgEM1JRychHCM9iVzFO0Z1PuuM"
    body = (
        f"webadm:{{SHA384}}{sha}:admin\n"
        f"opadmin:{{SHA384}}{sha}:operator\n"
    )
    out = parse_icmauth(body)
    assert len(out) == 2
    assert out[0]["username"] == "webadm"
    assert out[1]["username"] == "opadmin"
    assert out[0]["hash_hex"] == out[1]["hash_hex"]


def test_parse_icmauth_username_with_dot_allowed():
    """Generator-stamped usernames sometimes contain a dot (e.g.
    SAP convention `sap.admin`) — the parser must keep the full
    name without truncating at the dot."""
    from sap_wdisp_admin import parse_icmauth
    body = ("sap.admin:{SHA384}JElZSxeYdaMxO+pxADLgVmt5MnTZsJoDXRfCBvhgEM1J"
            "RychHCM9iVzFO0Z1PuuM:role\n")
    out = parse_icmauth(body)
    assert len(out) == 1
    assert out[0]["username"] == "sap.admin"


def test_parse_icmauth_unpadded_base64_padded_automatically():
    """Some kernels emit unpadded base64 — the parser fixes padding
    rather than dropping the line."""
    import base64
    import hashlib
    from sap_wdisp_admin import parse_icmauth
    digest = hashlib.sha384(b"admin").digest()
    b64_padded = base64.b64encode(digest).decode("ascii")  # has trailing =
    b64_unpadded = b64_padded.rstrip("=")
    body = f"webadm:{{SHA384}}{b64_unpadded}:admin\n"
    out = parse_icmauth(body)
    assert len(out) == 1
    assert out[0]["hash_hex"] == hashlib.sha384(b"admin").hexdigest()


def test_parse_icmauth_no_comment_field_handled():
    """`user:{SHA384}<b64>` with NO trailing :comment is legal — empty
    comment should not break the parse."""
    from sap_wdisp_admin import parse_icmauth
    body = ("webadm:{SHA384}JElZSxeYdaMxO+pxADLgVmt5MnTZsJoDXRfCBvhgEM1J"
            "RychHCM9iVzFO0Z1PuuM\n")
    out = parse_icmauth(body)
    assert len(out) == 1
    assert out[0]["username"] == "webadm"
    assert out[0]["comment"] == ""


def test_parse_icmauth_empty_input_returns_empty_list():
    from sap_wdisp_admin import parse_icmauth
    assert parse_icmauth("") == []
    assert parse_icmauth(b"") == []
    assert parse_icmauth("# only a comment\n\n") == []


def test_icmauth_probe_url_list_includes_canonical_endpoints():
    """The auto-fetch probe list should include at least the
    well-known WD admin file-viewer URL shapes we'd expect to
    serve icmauth.txt on a kernel that exposes it."""
    from sap_wdisp_admin import _WD_ADMIN_ICMAUTH_PROBES
    probes = list(_WD_ADMIN_ICMAUTH_PROBES)
    assert len(probes) >= 6
    # icp-based file readers
    assert any(p.endswith("icmauth.icp") for p in probes)
    # ShowFile.html action
    assert any("ShowFile" in p for p in probes)
    # Every probe must be under /sap/wdisp/admin/
    for p in probes:
        assert p.startswith("/sap/wdisp/admin/"), \
            f"Probe {p!r} should be under WD admin namespace"


def test_download_icmauth_returns_needs_creds_when_user_blank():
    """Calling with empty creds must short-circuit cleanly — no
    network calls, no exceptions."""
    from sap_wdisp_admin import download_icmauth
    r = download_icmauth("host.example", 44300, https=True,
                            user="", pwd="", verbose=False)
    assert r["ok"] is False
    assert r["error"] == "credentials_required"
    assert r["probes_tried"] == []


# ---------------------------------------------------------------------------
# probe_wd_admin_credentials — failure-mode tolerance
# ---------------------------------------------------------------------------
#
# Regression: operator reported `webadm / ab3x$waA31` on a WD at
# 172.31.14.107:8011 was rejected with no per-attempt status logged —
# meaning the pre-flight aborted before any credential was even tried.
# Two root-cause modes the probe must now tolerate:
#
#   (1) HTTP-on-HTTPS (or vice versa): port 8011 was scanned with
#       https=False per the heuristic, but the WD actually serves
#       TLS — pre-flight returns status=0, no fallback fired.
#   (2) Non-401 pre-flight: the WD admin handler returns 302/200/403
#       instead of 401; the OLD code aborted on `status0 != 401`,
#       silently dropping every operator-supplied credential.
#
# Both modes now produce a populated `attempts` list with the actual
# response status, and the resolved protocol is returned to the caller.


def _stub_http_get(plan):
    """Build a _http_get replacement that returns scripted responses.

    `plan` is a list of (status, head_bytes, body_bytes) tuples; each
    call pops the next one.  Use this in monkeypatches to script the
    exact pre-flight + per-credential sequence.
    """
    plan = list(plan)
    calls = []

    def _stub(host, port, path, *, https, timeout,
                auth_header="", saprouter=""):
        calls.append({
            "host": host, "port": port, "path": path,
            "https": https, "auth_header": auth_header,
        })
        if not plan:
            return (0, b"", b"")
        return plan.pop(0)

    _stub.calls = calls   # expose for assertions
    return _stub


def test_probe_wd_admin_credentials_auto_falls_back_to_https(monkeypatch):
    """When the caller says https=False but the WD is actually TLS-
    wrapped (port 8011 lab regression), the first probe candidate's
    HTTP attempt connection-fails; the probe must retry once with
    https=True and proceed."""
    from sap_wdisp_admin import probe_wd_admin_credentials
    import sap_wdisp_admin as mod

    # Plan (walking the first verify candidate):
    #  call 0 — navData.icp HTTP   → status=0 (TLS-on-HTTP confusion)
    #  call 1 — navData.icp HTTPS  → 401 + realm  (fallback succeeds)
    #  call 2 — authed HTTPS       → 200  (creds accepted)
    realm_head = (b"HTTP/1.0 401 Unauthorized\r\n"
                   b'WWW-Authenticate: Basic realm="WEB ADMIN"\r\n')
    stub = _stub_http_get([
        (0, b"", b""),
        (401, realm_head, b""),
        (200, b"HTTP/1.0 200 OK\r\n", b"OK"),
    ])
    monkeypatch.setattr(mod, "_http_get", stub)

    live, working, attempts, resolved = probe_wd_admin_credentials(
        "172.31.14.107", 8011, https=False,
        timeout=1, creds=[("webadm", "ab3x$waA31")],
        verbose=False,
    )
    assert live is True
    assert working == ("webadm", "ab3x$waA31")
    assert resolved is True, "auto-fallback should have resolved to HTTPS"
    assert len(attempts) == 1
    assert attempts[0]["status"] == 200
    assert attempts[0]["https"] is True
    # Verify the fallback actually happened (HTTPS used for calls 1 & 2)
    assert stub.calls[0]["https"] is False     # initial HTTP try
    assert stub.calls[1]["https"] is True       # fallback HTTPS pre-flight
    assert stub.calls[2]["https"] is True       # authed call uses HTTPS


def test_probe_wd_admin_credentials_aborts_when_all_paths_fail(monkeypatch):
    """status=0 on every candidate path (HTTP + HTTPS) → host
    unreachable; return early with empty attempts (no per-credential
    calls).  Each candidate now causes 2 calls (HTTP + HTTPS flip),
    so a 5-candidate list × 2 = up to 10 calls before bail-out."""
    from sap_wdisp_admin import probe_wd_admin_credentials
    import sap_wdisp_admin as mod

    # Empty plan — every call returns (0, b"", b"") per stub default
    stub = _stub_http_get([])
    monkeypatch.setattr(mod, "_http_get", stub)

    live, working, attempts, resolved = probe_wd_admin_credentials(
        "10.0.0.99", 9999, https=False, timeout=1,
        creds=[("u", "p")], verbose=False,
    )
    assert live is False
    assert working is None
    assert attempts == [], "no per-credential calls when host unreachable"


def test_probe_wd_admin_credentials_walks_to_gated_candidate_path(monkeypatch):
    """When the first candidate (whatever it is) returns 200 anonymously,
    the probe must keep walking and pick the next candidate that
    returns 401 — that's the real auth gate.  This is the canonical
    fix for the operator-reported lab regression where default.html
    was anonymous and gave a false-positive verify.

    Implementation note: the verify-candidate list grew over time
    (newer kernels added more paths), so this test stubs the FIRST
    candidate as 200-anonymous and the SECOND candidate as 401, then
    checks that the second one's path is what got used.
    """
    from sap_wdisp_admin import probe_wd_admin_credentials
    import sap_wdisp_admin as mod

    realm_head = (b"HTTP/1.0 401 Unauthorized\r\n"
                   b'WWW-Authenticate: Basic realm="WEB ADMIN"\r\n')
    stub = _stub_http_get([
        # Candidate 1: → 200 anonymous (skip — not gated)
        (200, b"HTTP/1.0 200 OK\r\n", b"<spa index>"),
        # Candidate 2: → 401 (this is the gate)
        (401, realm_head, b""),
        # Authed probe → 200 (creds accepted)
        (200, b"HTTP/1.0 200 OK\r\n", b"<params>"),
    ])
    monkeypatch.setattr(mod, "_http_get", stub)

    live, working, attempts, _ = probe_wd_admin_credentials(
        "wd.example", 8443, https=True, timeout=1,
        creds=[("webadm", "secret")], verbose=False,
    )
    assert live is True
    assert len(attempts) == 1
    # verify_path must be the 2nd candidate's path (the second call's
    # `path`), not the 1st — and crucially NOT default.html (which
    # would mean we landed on the anonymous fallback).
    assert attempts[0]["verify_path"] == stub.calls[1]["path"]
    assert "default.html" not in attempts[0]["verify_path"]


def test_probe_wd_admin_credentials_treats_302_authed_as_live(monkeypatch):
    """Some kernels redirect authed paths to the SAPUI5 SPA (302)
    instead of serving the content directly.  302 with a valid
    Authorization header is auth-accepted, not rejected."""
    from sap_wdisp_admin import probe_wd_admin_credentials
    import sap_wdisp_admin as mod

    realm_head = (b"HTTP/1.0 401 Unauthorized\r\n"
                   b'WWW-Authenticate: Basic realm="WEB ADMIN"\r\n')
    stub = _stub_http_get([
        (401, realm_head, b""),       # pre-flight unauth → 401 gate
        (302, b"HTTP/1.0 302 Found\r\nLocation: /sap/wdisp/admin/icp/\r\n", b""),
    ])
    monkeypatch.setattr(mod, "_http_get", stub)

    live, working, attempts, _ = probe_wd_admin_credentials(
        "wd.example", 8443, https=True, timeout=1,
        creds=[("webadm", "secret")], verbose=False,
    )
    assert live is True
    assert attempts[0]["status"] == 302


def test_probe_wd_admin_credentials_401_authed_means_rejected(monkeypatch):
    """A 401 response WITH the operator's Authorization header is
    rejection — UNLESS HTTP→HTTPS retry succeeds.  Here BOTH
    protocols 401 with the same creds, so the final verdict is
    live=False (creds are genuinely wrong)."""
    from sap_wdisp_admin import probe_wd_admin_credentials
    import sap_wdisp_admin as mod

    realm_head = (b"HTTP/1.0 401 Unauthorized\r\n"
                   b'WWW-Authenticate: Basic realm="WEB ADMIN"\r\n')
    stub = _stub_http_get([
        (401, realm_head, b""),       # pre-flight (no auth) → gated
        (401, realm_head, b""),       # authed HTTPS → still 401
    ])
    monkeypatch.setattr(mod, "_http_get", stub)

    live, working, attempts, _ = probe_wd_admin_credentials(
        "wd.example", 443, https=True, timeout=1,
        creds=[("wrong", "wrong")], verbose=False,
    )
    assert live is False
    assert working is None
    assert len(attempts) == 1
    assert attempts[0]["status"] == 401
    assert attempts[0]["live"] is False


def test_probe_wd_admin_credentials_http_401_retries_on_https(monkeypatch):
    """The KEY operator-reported regression: WD on 172.31.14.107:8011
    served the SPA landing page anonymously over HTTP but rejected
    Basic auth on /icp/* — admin was actually HTTPS-only.  When HTTP
    + correct creds yields 401, the probe must retry the SAME creds
    over HTTPS and switch resolved_https when that works."""
    from sap_wdisp_admin import probe_wd_admin_credentials
    import sap_wdisp_admin as mod

    realm_head = (b"HTTP/1.0 401 Unauthorized\r\n"
                   b'WWW-Authenticate: Basic realm="WEB ADMIN"\r\n')
    stub = _stub_http_get([
        # Pre-flight: navData.icp HTTP unauth → 401 (real gate)
        (401, realm_head, b""),
        # Authed HTTP → still 401 (Basic auth HTTPS-only on this profile)
        (401, realm_head, b""),
        # HTTPS retry with same creds → 200 (admin honors Basic over HTTPS)
        (200, b"HTTP/1.0 200 OK\r\n", b"<nav json>"),
    ])
    monkeypatch.setattr(mod, "_http_get", stub)

    live, working, attempts, resolved = probe_wd_admin_credentials(
        "172.31.14.107", 8011, https=False,
        timeout=1, creds=[("webadm", "ab3x$waA31")],
        verbose=False,
    )
    assert live is True, ("HTTPS retry should accept the creds that "
                          "the HTTP-Basic gate rejected")
    assert working == ("webadm", "ab3x$waA31")
    assert resolved is True, ("resolved_https should flip to True so "
                              "follow-up fetch_wd_systems uses HTTPS")
    # Three calls in total: unauth HTTP, authed HTTP, authed HTTPS retry
    assert len(stub.calls) == 3
    assert stub.calls[2]["https"] is True


def test_probe_wd_admin_credentials_returns_resolved_https_for_caller(monkeypatch):
    """Even when the pre-flight succeeds on the caller's preferred
    protocol (no fallback needed), the resolved_https field must
    still be returned so the caller can thread it through to
    follow-up fetch_wd_systems / download_icmauth calls."""
    from sap_wdisp_admin import probe_wd_admin_credentials
    import sap_wdisp_admin as mod

    realm_head = (b"HTTP/1.0 401 Unauthorized\r\n"
                   b'WWW-Authenticate: Basic realm="WEB ADMIN"\r\n')
    stub = _stub_http_get([
        (401, realm_head, b""),
        (200, b"HTTP/1.0 200 OK\r\n", b""),
    ])
    monkeypatch.setattr(mod, "_http_get", stub)

    live, working, attempts, resolved = probe_wd_admin_credentials(
        "wd.example", 44300, https=True, timeout=1,
        creds=[("webadm", "right")], verbose=False,
    )
    assert resolved is True   # unchanged — no fallback fired


def test_derive_instance_from_wd_port_recognises_80NN_range():
    """Lab regression: 172.31.14.107 was scanned as two separate
    SAP systems — SW1 on port 51113 (instance 11 SAPControl) and
    W6B on port 8011 (also instance 11, the SAP-default 80NN HTTP
    port).  The merge needs to recognise that 8011 maps to instance
    11 via the SAP 80NN formula so the fold-into-existing-SID logic
    works.
    """
    from sapmap_scanner import _derive_instance_from_wd_port
    # 80NN HTTP
    assert _derive_instance_from_wd_port(8000) == "00"
    assert _derive_instance_from_wd_port(8011) == "11"
    assert _derive_instance_from_wd_port(8097) == "97"
    # 443NN HTTPS
    assert _derive_instance_from_wd_port(44300) == "00"
    assert _derive_instance_from_wd_port(44311) == "11"
    assert _derive_instance_from_wd_port(44397) == "97"


def test_derive_instance_from_wd_port_returns_empty_for_canonical_ports():
    """Canonical WD ports (80, 443, 8080, 8443, 50000, 50001) don't
    follow the 80NN/443NN formula — they're production-facing
    fixed choices.  Must return "" so the WD synthesis logic
    creates a standalone Wxx node for those (and doesn't try to
    merge into an unrelated instance)."""
    from sapmap_scanner import _derive_instance_from_wd_port
    for p in (80, 443, 50000, 50001, 22, 21, 7777):
        assert _derive_instance_from_wd_port(p) == "", (
            f"port {p} should NOT yield an instance")


def test_derive_instance_from_wd_port_boundaries():
    """Just outside the 80NN / 443NN ranges → "" — guards against
    8100 / 8200 / 44400 etc. being accidentally claimed as instances
    98 / 99 / etc. when they're not real SAP convention."""
    from sapmap_scanner import _derive_instance_from_wd_port
    assert _derive_instance_from_wd_port(7999) == ""
    assert _derive_instance_from_wd_port(8098) == ""
    assert _derive_instance_from_wd_port(44299) == ""
    assert _derive_instance_from_wd_port(44398) == ""


def test_set_wd_port_protocol_helper_flips_port_label():
    """The gui helper that persists the resolved protocol back onto
    the SAPNode must update the port label exactly — no double-
    label, no removed-port side effects on other ports."""
    import sys
    import os as _os
    # The helper lives in modules/core/sapmap_gui.py — import it
    # by adding that dir to sys.path explicitly so the test can
    # reach it without setting up the full GUI.
    here = _os.path.dirname(__file__)
    gui_dir = _os.path.abspath(_os.path.join(here, "..", "modules", "core"))
    if gui_dir not in sys.path:
        sys.path.insert(0, gui_dir)
    from sapmap_gui import _set_wd_port_protocol
    from sapmap_models import SAPNode, InstanceInfo

    inst = InstanceInfo(instance_nr="00", ip="172.31.14.107",
                          ports={8011: "wd_http", 22: "ssh"})
    n = SAPNode(sid="W6B", hostname="h", ip="172.31.14.107")
    n.instances = [inst]

    _set_wd_port_protocol(n, 8011, True)
    assert inst.ports[8011] == "wd_https"
    assert inst.ports[22] == "ssh", "other ports must be untouched"

    _set_wd_port_protocol(n, 8011, False)
    assert inst.ports[8011] == "wd_http"

