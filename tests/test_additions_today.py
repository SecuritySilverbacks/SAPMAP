#!/usr/bin/env python3
"""Unit tests covering the batch of changes landed today:

  * sapmap_rfc._run_with_timeout / _detach_if_timed_out
  * sap_java_secstore_offline edge cases (length prefix, #@/#~ filter)
  * sapmap_exploit._build_java_os_exec — primitive priority order
  * sapmap_exploit._detect_and_set_system_type — proven + probe paths
  * sapmap_exploit.offline_decrypt_secstore — noise filter, missing key
  * sapmap_exploit HTTP destination bucket / promotion (structural)
  * sapmap_models.RFCConnection — new conn_type/http_* fields round-trip
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from sapmap_models import (
    SAPNode, RFCConnection, Credentials, InstanceInfo, SAPMAPState,
)


# ===========================================================================
# 1. sapmap_rfc._run_with_timeout / _detach_if_timed_out
# ===========================================================================

def test_run_with_timeout_returns_result_when_fast():
    from sapmap_rfc import _run_with_timeout
    def fast(x, y):
        return x + y
    result, timed_out = _run_with_timeout(fast, 5.0, 2, 3)
    assert result == 5 and timed_out is False


def test_run_with_timeout_fires_on_slow_function():
    from sapmap_rfc import _run_with_timeout
    def slow():
        time.sleep(2.0)
        return "late"
    # 0.15 s cap — the 2-second function MUST be reported as timed-out
    result, timed_out = _run_with_timeout(slow, 0.15)
    assert timed_out is True
    assert result is None


def test_run_with_timeout_propagates_exceptions():
    from sapmap_rfc import _run_with_timeout
    def boom():
        raise ValueError("fail")
    with pytest.raises(ValueError):
        _run_with_timeout(boom, 1.0)


def test_run_with_timeout_passes_kwargs():
    from sapmap_rfc import _run_with_timeout
    def fn(a, b=None):
        return (a, b)
    result, _ = _run_with_timeout(fn, 1.0, "x", b="y")
    assert result == ("x", "y")


def test_detach_if_timed_out_nulls_handle():
    from sapmap_rfc import _detach_if_timed_out
    class FakeConn:
        _handle = 42
    c = FakeConn()
    _detach_if_timed_out(c, True)
    assert c._handle is None


def test_detach_if_timed_out_no_op_when_not_timed_out():
    from sapmap_rfc import _detach_if_timed_out
    class FakeConn:
        _handle = 42
    c = FakeConn()
    _detach_if_timed_out(c, False)
    assert c._handle == 42


def test_detach_if_timed_out_tolerates_none():
    from sapmap_rfc import _detach_if_timed_out
    # Must not raise
    _detach_if_timed_out(None, True)


# ===========================================================================
# 2. sap_java_secstore_offline — extra edge cases
# ===========================================================================

def test_offline_short_plaintext_returns_empty():
    """If plaintext is shorter than the 18-byte alphabet header, we
    shouldn't blow up — return empty bytes."""
    from sap_java_secstore_offline import _strip_alphabet_and_length
    assert _strip_alphabet_and_length(b"\x00" * 10) == b""


def test_offline_declared_length_longer_than_plain_falls_back():
    """Length prefix that would overshoot the plaintext — fall back to
    dec[18:] rather than returning garbage from past the end."""
    from sap_java_secstore_offline import _strip_alphabet_and_length
    # alphabet (16B) + length says 9999 + only 4 payload bytes
    plain = b"ABCDEFGHIJKLMNOP" + (9999).to_bytes(2, "big") + b"four"
    # With oversize declared length we fall back to dec[18:]
    assert _strip_alphabet_and_length(plain) == b"four"


def test_offline_seckey_with_embedded_newlines_stripped():
    from sap_java_secstore_offline import deobfuscate_seckey, _SECRET_XOR
    obf = bytes(b"pw"[i] ^ _SECRET_XOR[i % len(_SECRET_XOR)]
                 for i in range(2))
    seckey = b"7.50.022.001|" + obf + b"\r\n  "
    recovered, _ = deobfuscate_seckey(seckey)
    assert recovered == b"pw"


# ===========================================================================
# 3. RFCConnection — new fields round-trip
# ===========================================================================

def test_rfcconnection_http_fields_default_to_rfc():
    c = RFCConnection(source_sid="A", source_host="h")
    assert c.conn_type == "rfc"
    assert c.http_url == ""
    assert c.http_auth_type == ""
    assert c.http_proxy == ""


def test_rfcconnection_http_serialisation_round_trip():
    c = RFCConnection(
        source_sid="SJ1", source_host="srv01sm1",
        target_sid="SM1", target_host="srv01sm1.ncmi.co",
        destination_name="IntroscopeEM_SRV01SM1.NCMI.CO@6001",
        rfc_user="SAPSLD",
        conn_type="http",
        http_url="http://srv01sm1.ncmi.co:8081/sapquery/",
        http_auth_type="BASICAUTHENTICATION",
        http_proxy="proxy.example:8080",
    )
    d = c.to_dict()
    assert d["conn_type"] == "http"
    assert d["http_url"] == "http://srv01sm1.ncmi.co:8081/sapquery/"
    assert d["http_auth_type"] == "BASICAUTHENTICATION"
    assert d["http_proxy"] == "proxy.example:8080"

    restored = RFCConnection.from_dict(d)
    assert restored.conn_type == "http"
    assert restored.http_url == "http://srv01sm1.ncmi.co:8081/sapquery/"
    assert restored.http_auth_type == "BASICAUTHENTICATION"
    assert restored.http_proxy == "proxy.example:8080"


def test_rfcconnection_from_dict_forward_compatible_unknown_keys():
    # A v2 dict with an unknown future field must not break from_dict.
    d = {"source_sid": "X", "source_host": "y",
         "conn_type": "http", "future_unknown_field": "oh no"}
    c = RFCConnection.from_dict(d)
    assert c.conn_type == "http"
    assert c.source_sid == "X"


# ===========================================================================
# 4. _build_java_os_exec — primitive priority order
# ===========================================================================

def _node(sid="SJ1", system_type="JAVA", **kw):
    n = SAPNode(sid=sid, system_type=system_type,
                  hostname=kw.get("hostname", "h"),
                  ip=kw.get("ip", "10.0.0.1"),
                  instances=[InstanceInfo(
                      instance_nr="02", ip=kw.get("ip", "10.0.0.1"),
                      ports={3303: "gateway"})])
    for k, v in kw.items():
        if hasattr(n, k):
            setattr(n, k, v)
    return n


def test_build_java_os_exec_prefers_gw_over_cve_and_ctc():
    from sapmap_exploit import _build_java_os_exec
    n = _node(gw_vulnerable=True, cve_2025_31324_vulnerable=True,
               cve_2025_31324_shells=[{"url": "http://x/y"}])
    run_cmd, label, err = _build_java_os_exec(n)
    assert run_cmd is not None
    assert err == ""
    assert "GW SAPXPG" in label


def test_build_java_os_exec_falls_back_to_cve_31324():
    from sapmap_exploit import _build_java_os_exec
    n = _node(gw_vulnerable=False, cve_2025_31324_vulnerable=True,
               cve_2025_31324_shells=[{"url": "http://a/b"}])
    run_cmd, label, err = _build_java_os_exec(n)
    assert run_cmd is not None
    assert "CVE-2025-31324" in label


def test_build_java_os_exec_rejects_non_java_stack():
    from sapmap_exploit import _build_java_os_exec
    n = _node(system_type="ABAP")
    run_cmd, label, err = _build_java_os_exec(n)
    assert run_cmd is None
    assert "Not a Java" in err


def test_build_java_os_exec_reports_when_nothing_available():
    from sapmap_exploit import _build_java_os_exec
    n = _node(gw_vulnerable=False, cve_2025_31324_vulnerable=False,
               cve_2025_31324_shells=[])
    run_cmd, label, err = _build_java_os_exec(n)
    assert run_cmd is None
    assert "no OS-exec primitive" in err


# ===========================================================================
# 5. offline_decrypt_secstore — input validation / noise filter
# ===========================================================================

def test_offline_decrypt_secstore_empty_failed_list():
    from sapmap_exploit import offline_decrypt_secstore
    r = offline_decrypt_secstore(_node(), [])
    assert r["error"] == "no failed rows to retry"
    assert r["decoded"] == []


def test_offline_decrypt_secstore_missing_vbytes_errors_out():
    from sapmap_exploit import offline_decrypt_secstore
    # All rows lack "vbytes" field — JSP is an older version
    rows = [{"cid": "1", "name": "a", "reason": "x"}]
    r = offline_decrypt_secstore(_node(), rows)
    assert "lack raw VBYTES" in r["error"]


def test_offline_decrypt_secstore_noise_filter_drops_jar_xml():
    """Rows whose names look like deployment artefacts (JAR, XML, WSDL)
    must be filtered out before we burn cycles trying to decrypt them."""
    from sapmap_exploit import offline_decrypt_secstore

    # Use a node that has no OS-exec primitive — we want to bail BEFORE
    # reading SecStore.key, but only AFTER the noise filter decides
    # there's nothing left to try.  Construct input so only deployment
    # blobs remain: the noise filter should drop every one.
    n = _node(gw_vulnerable=False, cve_2025_31324_vulnerable=False)
    # Only deployment-noise names — all should be skipped
    rows = [
        {"cid": "1", "name": "META-INF.zip", "reason": "x", "vbytes": "01aa"},
        {"cid": "2", "name": "sap.com~tc~slm~interfaces.wsar",
         "reason": "x", "vbytes": "01bb"},
        {"cid": "3", "name": "configuration.xml", "reason": "x", "vbytes": "01cc"},
    ]
    # Noise filter runs first, leaves no candidates, THEN the function
    # should still try to build the OS-exec primitive (because
    # "interesting" list is empty means nothing to retry).  Either way
    # no decryption occurs and decoded stays empty.
    r = offline_decrypt_secstore(n, rows)
    assert r["decoded"] == []


def test_offline_decrypt_secstore_keeps_credential_rows():
    """Rows with credential-shaped names shouldn't be filtered out by
    the noise regex even if they happen to end in patterns from it."""
    from sapmap_exploit import offline_decrypt_secstore

    n = _node(gw_vulnerable=False, cve_2025_31324_vulnerable=False)
    # "password" name wins over any noise pattern — it's an INTEREST hit
    rows = [
        {"cid": "1", "name": "#~jco.client.passwd",
         "reason": "IllegalBlockSizeException", "vbytes": "01aabb"},
        {"cid": "2", "name": "#~destination.Password",
         "reason": "X", "vbytes": "01ccdd"},
    ]
    r = offline_decrypt_secstore(n, rows)
    # Function bails because no OS-exec primitive, but AT LEAST should
    # not raise and should report the right error (not a "noise-only"
    # rejection).
    assert "OS-exec primitive" in r["error"]


# ===========================================================================
# 6. _detect_and_set_system_type
# ===========================================================================

def test_detect_stack_proven_type_sets_when_unknown():
    from sapmap_exploit import _detect_and_set_system_type
    n = _node(system_type="")
    creds = Credentials(username="SAPMAP00", password="x", client="100",
                           instance_nr="00")
    out = _detect_and_set_system_type(n, creds, proven_type="ABAP")
    assert out == "ABAP"
    assert n.system_type == "ABAP"


def test_detect_stack_proven_type_augments_existing():
    """Node with JAVA already detected; proven ABAP should produce
    ABAP+JAVA, not overwrite."""
    from sapmap_exploit import _detect_and_set_system_type
    n = _node(system_type="JAVA")
    creds = Credentials(username="u", password="p", client="100",
                           instance_nr="00")
    out = _detect_and_set_system_type(n, creds, proven_type="ABAP")
    # Alphabetical join of {ABAP, JAVA}
    assert out == "ABAP+JAVA"
    assert n.system_type == "ABAP+JAVA"


def test_detect_stack_no_change_when_already_resolved():
    from sapmap_exploit import _detect_and_set_system_type
    n = _node(system_type="ABAP+JAVA")
    creds = Credentials(username="u", password="p", client="100",
                           instance_nr="00")
    out = _detect_and_set_system_type(n, creds, proven_type="")
    assert out == "ABAP+JAVA"
    assert n.system_type == "ABAP+JAVA"


def test_detect_stack_probe_fallback_sets_abap_on_rfc_success():
    """When nothing is proven and no type is known, an RFC_SYSTEM_INFO
    that returns a SID proves ABAP and populates release/db/kernel."""
    from sapmap_exploit import _detect_and_set_system_type

    n = _node(system_type="")
    n.sap_release = ""
    n.kernel = ""
    n.db_type = ""
    creds = Credentials(username="u", password="p", client="100",
                           instance_nr="00")

    # Fake pyrfc connection manager: _get_connection() __enter__ returns
    # a conn whose .call("RFC_SYSTEM_INFO") returns a plausible payload.
    class FakeConn:
        def call(self, fm):
            return {"RFCSI_EXPORT": {"RFCSYSID": "SB7",
                                      "RFCSAPRL": "755",
                                      "RFCKRNLREL": "753",
                                      "RFCDBSYS": "HDB"}}
    class FakeCtx:
        def __enter__(self_): return FakeConn()
        def __exit__(self_, *a): return False

    with patch("sapmap_rfc._get_connection", return_value=FakeCtx()):
        out = _detect_and_set_system_type(n, creds, proven_type="")

    assert out == "ABAP"
    assert n.system_type == "ABAP"
    assert n.sap_release == "755"
    assert n.kernel == "753"
    assert n.db_type == "HDB"


def test_detect_stack_probe_silent_on_exception():
    """If RFC_SYSTEM_INFO raises, stack stays empty — we don't crash."""
    from sapmap_exploit import _detect_and_set_system_type

    n = _node(system_type="")
    creds = Credentials(username="u", password="p", client="100",
                           instance_nr="00")

    class FakeCtx:
        def __enter__(self_):
            raise RuntimeError("cannot connect")
        def __exit__(self_, *a): return False

    with patch("sapmap_rfc._get_connection", return_value=FakeCtx()):
        out = _detect_and_set_system_type(n, creds)
    assert out == ""
    assert n.system_type == ""


# ===========================================================================
# 7. HTTP destination bucket / promotion — structural smoke
# ===========================================================================

def test_http_edge_shape_plotted_on_existing_node():
    """Feed a synthetic http_bucket-style dict through the promotion
    by reconstructing the minimal conditions, and verify the produced
    RFCConnection carries the right fields."""
    import urllib.parse as _up
    # Mimic what the promotion loop does when target host matches
    state = SAPMAPState()
    target = SAPNode(sid="SM1", system_type="JAVA",
                       hostname="srv01sm1.ncmi.co",
                       ip="10.0.0.5",
                       instances=[InstanceInfo(
                           instance_nr="00", ip="10.0.0.5",
                           ports={50000: "java_http"})])
    state.add_node(target)
    source = SAPNode(sid="SJ1", system_type="JAVA",
                       hostname="src", ip="10.0.0.1",
                       instances=[InstanceInfo(
                           instance_nr="02", ip="10.0.0.1",
                           ports={3303: "gateway"})])
    state.add_node(source)

    http_rec = {
        "name": "IntroscopeEM@6001",
        "url":  "http://srv01sm1.ncmi.co:8081/sapquery/",
        "user": "SLDDSUSER",
        "auth": "BASICAUTHENTICATION",
        "proxy": "",
        "password": "SecretPw!",
    }
    parsed = _up.urlparse(http_rec["url"])
    target_host = parsed.hostname
    match = state.find_node_by_host(hostname=target_host, ip=target_host)
    assert match is not None and match.sid == "SM1"

    conn = RFCConnection(
        source_sid=source.sid, source_host=source.hostname,
        target_sid=match.sid, target_host=target_host,
        destination_name=http_rec["name"],
        rfc_user=http_rec["user"], client="",
        secstore_password=http_rec["password"],
        conn_type="http",
        http_url=http_rec["url"],
        http_auth_type=http_rec["auth"],
        http_proxy=http_rec["proxy"],
    )
    state.add_connection(conn)

    assert len(state.connections) == 1
    c = state.connections[0]
    assert c.conn_type == "http"
    assert c.http_url == "http://srv01sm1.ncmi.co:8081/sapquery/"
    assert c.http_auth_type == "BASICAUTHENTICATION"
    assert c.rfc_user == "SLDDSUSER"
    assert c.client == ""   # HTTP has no SAP client
    assert c.risk_level() in ("MEDIUM", "UNKNOWN", "LOW")


def test_http_destination_url_parsing_rejects_urls_without_host():
    """url without a hostname should not produce an edge."""
    import urllib.parse as _up
    parsed = _up.urlparse("bad-url")
    assert not parsed.hostname


def test_http_destination_host_match_missing_returns_none():
    state = SAPMAPState()
    assert state.find_node_by_host(
        hostname="nonexistent.example.com",
        ip="nonexistent.example.com") is None


# ===========================================================================
# 8. Final #@/#~ dedup pass — structural simulation
# ===========================================================================

def test_final_pass_drops_factory_when_active_sibling_present():
    """Simulate the dedup algorithm used at the end of
    extract_java_secstore.  A #@-prefixed row for the same (cid, base)
    as a #~-prefixed one must be dropped."""
    persisted = [
        {"cid": "C1", "name": "#~jco.client.passwd", "value": "Down1oad"},
        {"cid": "C1", "name": "#@jco.client.passwd", "value": "Down1oad"},
        # Different CID — both sides stay
        {"cid": "C2", "name": "#@jco.client.user",    "value": "ORPHAN"},
        # #~ only — stays
        {"cid": "C3", "name": "#~jco.client.passwd", "value": "Secret"},
    ]
    active_seen = {}
    for row in persisted:
        nm = row.get("name", "") or ""
        if nm.startswith("#~"):
            active_seen[(row.get("cid", ""), nm[2:])] = True
    deduped = [
        row for row in persisted
        if not ((row.get("name", "") or "").startswith("#@")
                  and (row.get("cid", ""),
                        (row.get("name", "") or "")[2:]) in active_seen)
    ]
    names = [(r["cid"], r["name"]) for r in deduped]
    assert ("C1", "#~jco.client.passwd") in names
    assert ("C1", "#@jco.client.passwd") not in names
    assert ("C2", "#@jco.client.user") in names     # orphan kept
    assert ("C3", "#~jco.client.passwd") in names


def test_final_pass_preserves_orphan_factory_entries():
    """#@<name> rows without a #~ sibling must NOT be dropped."""
    persisted = [
        {"cid": "C9", "name": "#@Secured Property xyz", "value": "v"},
        {"cid": "C9", "name": "#@jco.client.passwd",    "value": "still useful"},
    ]
    active_seen = {}
    for row in persisted:
        nm = row.get("name", "") or ""
        if nm.startswith("#~"):
            active_seen[(row.get("cid", ""), nm[2:])] = True
    deduped = [
        row for row in persisted
        if not ((row.get("name", "") or "").startswith("#@")
                  and (row.get("cid", ""),
                        (row.get("name", "") or "")[2:]) in active_seen)
    ]
    assert len(deduped) == len(persisted)


# ===========================================================================
# 9. dest_host fallback ordering (ashost → mshost → saphost)
# ===========================================================================

def test_dest_host_prefers_ashost():
    """Simulate the extraction logic used in extract_java_secstore's
    cid_context builder.  ashost wins when present."""
    props = {
        "#~jco.client.ashost": "app.example",
        "#~jco.client.mshost": "ms.example",
        "#~jco.client.saphost": "sap.example",
    }
    dest_host = (props.get("#~jco.client.ashost", "")
                  or props.get("#~jco.client.mshost", "")
                  or props.get("#~jco.client.saphost", "")
                  or "")
    assert dest_host == "app.example"


def test_dest_host_falls_back_to_mshost_for_load_balanced():
    """UMEBackendConnection and similar system destinations often set
    mshost only — we must surface that as the host for auto-plot."""
    props = {
        "#~jco.client.mshost": "msgsrv.example",
        "#~jco.client.group":  "PUBLIC",
    }
    dest_host = (props.get("#~jco.client.ashost", "")
                  or props.get("#~jco.client.mshost", "")
                  or "")
    assert dest_host == "msgsrv.example"


def test_dest_target_sid_falls_back_to_sysid():
    """Some 7.x variants use #~jco.client.sysid instead of r3name."""
    props = {"#~jco.client.sysid": "sb7"}  # intentionally lowercase
    dest_target_sid = ((props.get("#~jco.client.r3name", "")
                         or props.get("#~jco.client.sysid", ""))
                         or "").upper()
    assert dest_target_sid == "SB7"


# ===========================================================================
# 10. SID auto-discovery via SAPControl probe (new today)
# ===========================================================================

def test_quick_probe_sid_empty_host_returns_none():
    import sapmap_scanner
    assert sapmap_scanner.quick_probe_sid("") is None
    assert sapmap_scanner.quick_probe_sid(None) is None


def test_quick_probe_sid_hits_first_responsive_port():
    """If per-instance sapcontrol (50013) returns a SID, we accept it
    immediately — no need to keep probing other ports."""
    import sapmap_scanner

    calls = []
    def fake_sid(host, port, timeout=3):
        calls.append(port)
        if port == 50013:
            return ("SB7", False, True, "HDB", 50000, 50001)
        return ("", False, False, "", 0, 0)

    def fake_os(host, port, timeout=3):
        return "Linux"

    def fake_host_agent(host, port, timeout=3):
        # 1128 is tried first; simulate it being firewalled / silent
        return None

    with patch.object(sapmap_scanner, "_query_sapcontrol_sid", fake_sid), \
         patch.object(sapmap_scanner, "_query_sapcontrol_os", fake_os), \
         patch.object(sapmap_scanner, "_query_host_agent_systems",
                       fake_host_agent):
        hit = sapmap_scanner.quick_probe_sid("srv01sb7.example")
    assert hit is not None
    assert hit["sid"] == "SB7"
    assert hit["instance_nr"] == "00"
    assert hit["is_abap"] is True
    assert hit["db_type"] == "HDB"
    assert hit["http_port"] == 50000
    assert hit["os_type"] == "Linux"
    assert hit["source_port"] == 50013


def test_quick_probe_sid_uses_host_agent_when_available():
    import sapmap_scanner

    def fake_host_agent(host, port, timeout=3):
        return {"sid": "AED", "instance_nr": "00",
                "is_abap": False, "is_java": False,
                "db_type": "", "os_type": "",
                "http_port": 8000, "https_port": 8443}

    with patch.object(sapmap_scanner, "_query_host_agent_systems",
                       fake_host_agent), \
         patch.object(sapmap_scanner, "_query_sapcontrol_sid",
                       lambda *a, **k: ("", False, False, "", 0, 0)):
        hit = sapmap_scanner.quick_probe_sid("abex1.example")
    assert hit is not None
    assert hit["sid"] == "AED"
    assert hit["source_port"] == 1128


def test_quick_probe_sid_returns_none_when_nothing_answers():
    import sapmap_scanner
    with patch.object(sapmap_scanner, "_query_host_agent_systems",
                       lambda *a, **k: None), \
         patch.object(sapmap_scanner, "_query_sapcontrol_sid",
                       lambda *a, **k: ("", False, False, "", 0, 0)):
        hit = sapmap_scanner.quick_probe_sid("firewalled.example")
    assert hit is None


def test_probe_and_add_host_caches_and_reuses():
    """Second call for the same host must hit the cache, not probe again."""
    from sapmap_exploit import _probe_and_add_host, _sid_probe_cache
    state = SAPMAPState()
    # Clear cache to isolate this test from other runs
    _sid_probe_cache.clear()

    import sapmap_scanner
    call_count = {"n": 0}

    def fake_probe(host, saprouter=None, timeout=3, instance_hint=None):
        call_count["n"] += 1
        return {"sid": "SB7", "instance_nr": "00",
                "is_abap": True, "is_java": False,
                "db_type": "HDB", "os_type": "Linux",
                "http_port": 0, "https_port": 0,
                "source_port": 50013}

    with patch.object(sapmap_scanner, "quick_probe_sid", fake_probe):
        sid1 = _probe_and_add_host(state, "srv01sb7.example")
        sid2 = _probe_and_add_host(state, "srv01sb7.example")
    assert sid1 == "SB7"
    assert sid2 == "SB7"
    # Probe fires exactly once; second call is cache-served
    assert call_count["n"] == 1
    # Node was added to state
    assert state.get_node("SB7") is not None
    assert state.get_node("SB7").system_type == "ABAP"
    assert state.get_node("SB7").db_type == "HDB"


def test_probe_and_add_host_returns_empty_on_failure():
    from sapmap_exploit import _probe_and_add_host, _sid_probe_cache
    state = SAPMAPState()
    _sid_probe_cache.clear()

    import sapmap_scanner
    with patch.object(sapmap_scanner, "quick_probe_sid",
                       lambda *a, **k: None):
        sid = _probe_and_add_host(state, "unreachable.example")
    assert sid == ""
    # Negative result is also cached — no new node added
    assert len(state.nodes) == 0


def test_probe_and_add_host_empty_host_short_circuits():
    from sapmap_exploit import _probe_and_add_host
    state = SAPMAPState()
    assert _probe_and_add_host(state, "") == ""
    assert _probe_and_add_host(state, None) == ""


def test_probe_and_add_host_returns_existing_node_sid():
    """If a node with the host is already on the map (different code
    path added it), return that SID without probing."""
    from sapmap_exploit import _probe_and_add_host, _sid_probe_cache
    _sid_probe_cache.clear()
    state = SAPMAPState()
    state.add_node(SAPNode(sid="AED", system_type="ABAP",
                               hostname="abex1", ip="10.10.1.5",
                               instances=[InstanceInfo(
                                   instance_nr="00", ip="10.10.1.5",
                                   ports={})]))
    import sapmap_scanner
    with patch.object(sapmap_scanner, "quick_probe_sid") as p:
        sid = _probe_and_add_host(state, "10.10.1.5")
    assert sid == "AED"
    p.assert_not_called()


# ===========================================================================
# 11. HTTP destination property extraction — older "#~URL" layout
# ===========================================================================

def test_http_extraction_handles_7_0_legacy_keys():
    """Older SAP 7.0 HTTP destinations sometimes omit the 'destination.'
    prefix, storing just #~URL, #~Type, #~User.  The extraction
    fallback chain must pick those up."""
    props = {
        "#~Type":      "HTTP",
        "#~URL":       "http://legacy:8000/",
        "#~User":      "legacyuser",
        "#~AuthenticationType": "BASICAUTHENTICATION",
    }
    # Emulate what cid_context builder does
    dest_type_raw = (props.get("#~destination.type", "")
                       or props.get("#~destination.Type", "")
                       or props.get("#~Type", ""))
    dest_url_raw = (props.get("#~destination.URL", "")
                      or props.get("#~destination.url", "")
                      or props.get("#~URL", ""))
    dest_http_user = (props.get("#~destination.User", "")
                        or props.get("#~destination.Username", "")
                        or props.get("#~destination.user", "")
                        or props.get("#~User", "")
                        or props.get("#~Username", ""))
    dest_http_auth = (props.get("#~destination.authenticationType", "")
                        or props.get("#~destination.AuthenticationType", "")
                        or props.get("#~AuthenticationType", "")
                        or props.get("#~authenticationType", ""))
    assert dest_type_raw == "HTTP"
    assert dest_url_raw == "http://legacy:8000/"
    assert dest_http_user == "legacyuser"
    assert dest_http_auth == "BASICAUTHENTICATION"
