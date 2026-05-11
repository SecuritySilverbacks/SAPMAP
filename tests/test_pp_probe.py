#!/usr/bin/env python3
"""Tests for sap_pp_probe — the live PP-impersonation verifier.

All network traffic is mocked.  The two interesting paths are:

  * HTTP CONNECT handshake parsing + tunnelled GET response parsing
    (verified via low-level byte buffers fed into the parser helpers).
  * Whoami detection — header sniffing across the documented variants.
"""
from __future__ import annotations

from unittest.mock import patch


# ===========================================================================
# Helpers
# ===========================================================================

def _node(sid="TGT", ip="10.0.0.5", hostname="tgt.example.com"):
    from sapmap_models import SAPNode, InstanceInfo
    n = SAPNode(sid=sid, ip=ip, hostname=hostname, system_type="ABAP")
    n.instances.append(InstanceInfo(instance_nr="00", ip=ip,
                                     ports={8080: "http"}))
    return n


def _scc(host="10.0.0.99"):
    from sapmap_models import SCCNode
    return SCCNode(host=host, ip=host,
                   subaccount_uuids=["00000000-0000-0000-0000-000000000001"])


# ===========================================================================
# Parser primitives — header / status / body splitting
# ===========================================================================

def test_parse_status_line_basic():
    from sap_pp_probe import _parse_status_line
    assert _parse_status_line(b"HTTP/1.1 200 OK\r\nfoo: bar") == 200
    assert _parse_status_line(b"HTTP/1.1 401 Unauthorized\r\n") == 401
    assert _parse_status_line(b"HTTP/1.1 502 Bad Gateway\r\n") == 502
    assert _parse_status_line(b"") == 0
    assert _parse_status_line(b"garbage") == 0


def test_parse_headers_lowercases_and_strips():
    from sap_pp_probe import _parse_headers
    head = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type:  text/plain  \r\n"
        b"SAP-Username: JORIS\r\n"
        b"Set-Cookie: foo=bar; Path=/\r\n")
    out = _parse_headers(head)
    assert out["content-type"] == "text/plain"
    assert out["sap-username"] == "JORIS"
    assert "set-cookie" in out


# ===========================================================================
# Whoami detection
# ===========================================================================

def test_detect_user_sap_username_header_high_confidence():
    from sap_pp_probe import detect_user_in_response
    probe = {"headers": {"sap-username": "JORIS"}, "body_snippet": ""}
    user, conf = detect_user_in_response(probe)
    assert user == "JORIS"
    assert conf == "HIGH"


def test_detect_user_x_sap_user_name_header():
    from sap_pp_probe import detect_user_in_response
    probe = {"headers": {"x-sap-user-name": "DDIC"}, "body_snippet": ""}
    user, conf = detect_user_in_response(probe)
    assert user == "DDIC"
    assert conf == "HIGH"


def test_detect_user_falls_back_to_body_match():
    from sap_pp_probe import detect_user_in_response
    body = '{"data":{"sap-username":"BATCH1","client":"100"}}'
    probe = {"headers": {}, "body_snippet": body}
    user, conf = detect_user_in_response(probe)
    assert user == "BATCH1"
    assert conf == "HIGH"


def test_detect_user_no_signal_returns_blank():
    from sap_pp_probe import detect_user_in_response
    probe = {"headers": {"content-type": "text/plain"}, "body_snippet": "ok"}
    user, conf = detect_user_in_response(probe)
    assert user == ""
    assert conf == ""


# ===========================================================================
# find_pp_destination — picks the right destination shape
# ===========================================================================

def test_find_pp_destination_matches_principal_propagation_onprem():
    from sapmap_models import SAPMAPState, BTPSubaccountNode
    from sap_pp_probe import find_pp_destination
    state = SAPMAPState()
    sub_uuid = "00000000-0000-0000-0000-000000000001"
    state.btp_subaccounts[sub_uuid] = BTPSubaccountNode(
        uuid=sub_uuid, region="eu10",
        destinations=[
            {"name": "WRONG_AUTH", "authentication": "BasicAuthentication",
             "proxy_type": "OnPremise", "url": "http://10.0.0.5:8080"},
            {"name": "WRONG_PROXY", "authentication": "PrincipalPropagation",
             "proxy_type": "Internet", "url": "http://10.0.0.5:8080"},
            {"name": "RIGHT", "authentication": "PrincipalPropagation",
             "proxy_type": "OnPremise", "url": "http://10.0.0.5:8080"},
            {"name": "WRONG_HOST", "authentication": "PrincipalPropagation",
             "proxy_type": "OnPremise", "url": "http://10.0.0.99:8080"},
        ],
    )
    target = _node()
    d = find_pp_destination(state, sub_uuid, target)
    assert d is not None
    assert d["name"] == "RIGHT"


def test_find_pp_destination_returns_none_when_no_match():
    from sapmap_models import SAPMAPState, BTPSubaccountNode
    from sap_pp_probe import find_pp_destination
    state = SAPMAPState()
    sub_uuid = "00000000-0000-0000-0000-000000000001"
    state.btp_subaccounts[sub_uuid] = BTPSubaccountNode(
        uuid=sub_uuid, region="eu10",
        destinations=[
            {"name": "OTHER", "authentication": "PrincipalPropagation",
             "proxy_type": "OnPremise", "url": "http://other.example.com:8080"},
        ],
    )
    assert find_pp_destination(state, sub_uuid, _node()) is None


# ===========================================================================
# End-to-end orchestration — mock the network helpers
# ===========================================================================

def _mock_state_with_pp_dest(scc_host="10.0.0.99"):
    """Build SAPMAPState with one SCC, one bound BTP subaccount, and a
    PP-typed destination pointing at the target."""
    from sapmap_models import SAPMAPState, BTPSubaccountNode
    state = SAPMAPState()
    sub_uuid = "00000000-0000-0000-0000-000000000001"
    state.btp_subaccounts[sub_uuid] = BTPSubaccountNode(
        uuid=sub_uuid, region="eu10",
        destinations=[{
            "name": "S4H_PP", "authentication": "PrincipalPropagation",
            "proxy_type": "OnPremise", "url": "http://10.0.0.5:8080",
        }],
    )
    return state, sub_uuid


def test_verify_pp_confirmed_with_header_whoami():
    from sap_pp_probe import verify_pp
    state, sub_uuid = _mock_state_with_pp_dest()
    target, scc = _node(), _scc()

    fake_cfg = {"ok": True, "status": 200, "url": "http://10.0.0.5:8080",
                "auth_tokens": [], "destination": {}, "raw": {}, "error": ""}
    fake_primary = {"status": 200, "headers": {"sap-username": "DDIC"},
                    "body_snippet": "", "latency_ms": 42, "error": "",
                    "connect_status": 200, "connect_error": ""}
    fake_whoami = {"status": 200, "headers": {}, "body_snippet": "",
                    "latency_ms": 38, "error": "",
                    "connect_status": 200, "connect_error": ""}

    with patch("sap_pp_probe.fetch_destination_config", return_value=fake_cfg), \
         patch("sap_pp_probe.http_probe_via_connectivity_proxy",
               side_effect=[fake_primary, fake_whoami]):
        # Token doesn't matter for the mocks but must parse for region.
        out = verify_pp(state, target, scc, sub_uuid,
                         token=_fake_jwt("eu10"), cleanup_after=False)
    assert out["ok"] is True
    assert out["verdict"] == "confirmed"
    assert out["user"] == "DDIC"
    assert out["confidence"] == "HIGH"
    assert out["http_status"] == 200
    assert out["destination_used"] == "S4H_PP"
    assert out["destination_was_temp"] is False
    assert "verified_at" in out and out["verified_at"]


def test_verify_pp_returns_auth_rejected_on_401():
    from sap_pp_probe import verify_pp
    state, sub_uuid = _mock_state_with_pp_dest()
    fake_cfg = {"ok": True, "url": "http://10.0.0.5:8080",
                "auth_tokens": [], "destination": {}, "raw": {}, "error": ""}
    fake_primary = {"status": 401, "headers": {},
                    "body_snippet": "", "latency_ms": 22, "error": "",
                    "connect_status": 200, "connect_error": ""}

    with patch("sap_pp_probe.fetch_destination_config", return_value=fake_cfg), \
         patch("sap_pp_probe.http_probe_via_connectivity_proxy",
               return_value=fake_primary):
        out = verify_pp(state, _node(), _scc(), sub_uuid,
                         token=_fake_jwt("eu10"), cleanup_after=False)
    assert out["ok"] is False
    assert out["verdict"] == "auth_rejected"
    assert "401" in (out.get("error") or "")


def test_verify_pp_logs_verdict_line_on_no_status_path(capsys):
    """Regression: when the probe returns with no HTTP status (e.g.
    proxy closed the connection without responding), the operator
    must still see a single ``[-] PP-verify ...`` line — earlier
    versions exited silently after the ``[*] probing...`` line."""
    from sap_pp_probe import verify_pp
    state, sub_uuid = _mock_state_with_pp_dest()
    fake_cfg = {"ok": True, "url": "http://10.0.0.5:8080",
                "auth_tokens": [], "destination": {}, "raw": {}, "error": ""}
    fake_primary = {
        "status": 0, "headers": {}, "body_snippet": "",
        "latency_ms": 5,
        "error": "OSError: connection reset by peer",
        "proxy_host": "localhost", "proxy_port": 20003,
    }
    with patch("sap_pp_probe.fetch_destination_config", return_value=fake_cfg), \
         patch("sap_pp_probe.http_probe_via_connectivity_proxy",
               return_value=fake_primary):
        out = verify_pp(state, _node(), _scc(), sub_uuid,
                         token=_fake_jwt("eu10"), cleanup_after=False)
    assert out["verdict"] == "tunnel_unreachable"
    captured = capsys.readouterr().out
    assert "[-] PP-verify" in captured
    assert "probe failed" in captured
    assert "localhost:20003" in captured


def test_verify_pp_verified_at_always_set():
    """verified_at must be populated on every return path so the
    findings dedupe sees a unique timestamp suffix per attempt."""
    from sap_pp_probe import verify_pp
    state, sub_uuid = _mock_state_with_pp_dest()
    fake_cfg = {"ok": True, "url": "http://10.0.0.5:8080",
                "auth_tokens": [], "destination": {}, "raw": {}, "error": ""}
    fake_primary = {
        "status": 0, "headers": {}, "body_snippet": "",
        "latency_ms": 5,
        "error": "TimeoutError: timed out",
        "proxy_host": "localhost", "proxy_port": 20003,
    }
    with patch("sap_pp_probe.fetch_destination_config", return_value=fake_cfg), \
         patch("sap_pp_probe.http_probe_via_connectivity_proxy",
               return_value=fake_primary):
        out = verify_pp(state, _node(), _scc(), sub_uuid,
                         token=_fake_jwt("eu10"), cleanup_after=False)
    assert out["verified_at"], (
        "verified_at must be set even on the tunnel_unreachable "
        "early-return so the route handler can append it to the "
        "emit_finding message and bypass dedupe.")


def test_verify_pp_returns_tunnel_unreachable_when_connect_fails():
    from sap_pp_probe import verify_pp
    state, sub_uuid = _mock_state_with_pp_dest()
    fake_cfg = {"ok": True, "url": "http://10.0.0.5:8080",
                "auth_tokens": [], "destination": {}, "raw": {}, "error": ""}
    fake_primary = {"status": 0, "headers": {}, "body_snippet": "",
                    "latency_ms": 0, "error": "CONNECT returned HTTP 407",
                    "connect_status": 407,
                    "connect_error": "CONNECT returned HTTP 407"}

    with patch("sap_pp_probe.fetch_destination_config", return_value=fake_cfg), \
         patch("sap_pp_probe.http_probe_via_connectivity_proxy",
               return_value=fake_primary):
        out = verify_pp(state, _node(), _scc(), sub_uuid,
                         token=_fake_jwt("eu10"), cleanup_after=False)
    assert out["ok"] is False
    assert out["verdict"] == "tunnel_unreachable"


def test_verify_pp_creates_temp_destination_when_none_exists():
    """If the subaccount has no matching PP destination, the probe
    should auto-create a temp one and clean it up afterwards."""
    from sapmap_models import SAPMAPState, BTPSubaccountNode
    from sap_pp_probe import verify_pp
    state = SAPMAPState()
    sub_uuid = "00000000-0000-0000-0000-000000000001"
    state.btp_subaccounts[sub_uuid] = BTPSubaccountNode(
        uuid=sub_uuid, region="eu10", destinations=[])

    fake_cfg = {"ok": True, "url": "http://10.0.0.5:8080",
                "auth_tokens": [], "destination": {}, "raw": {}, "error": ""}
    fake_primary = {"status": 200, "headers": {"sap-username": "JORIS"},
                    "body_snippet": "", "latency_ms": 30, "error": "",
                    "connect_status": 200, "connect_error": ""}
    fake_whoami = {"status": 200, "headers": {}, "body_snippet": "",
                    "latency_ms": 28, "error": "",
                    "connect_status": 200, "connect_error": ""}

    with patch("sap_pp_probe.create_temp_pp_destination",
               return_value={"ok": True, "message": "created",
                              "dest_name": "SAPMAP_PP_PROBE_FAKE_TGT"}) as mk, \
         patch("sap_pp_probe.fetch_destination_config", return_value=fake_cfg), \
         patch("sap_pp_probe.http_probe_via_connectivity_proxy",
               side_effect=[fake_primary, fake_whoami]), \
         patch("sap_pp_probe.delete_destination",
               return_value={"status": 204, "body": ""}) as rm:
        out = verify_pp(state, _node(), _scc(), sub_uuid,
                         token=_fake_jwt("eu10"), cleanup_after=True)
    assert out["ok"] is True
    assert out["destination_was_temp"] is True
    mk.assert_called_once()
    rm.assert_called_once()


# ===========================================================================
# Connectivity-proxy resolution
# ===========================================================================

def test_resolve_proxy_endpoint_defaults_to_internal_hostname():
    """No override → use the documented internal CF hostname.  This
    won't resolve from outside BTP, but the verify_pp orchestrator
    catches the timeout and surfaces the cf-ssh workaround."""
    from sap_pp_probe import _resolve_proxy_endpoint
    h, p = _resolve_proxy_endpoint("eu10", use_tls=False)
    assert h == "connectivityproxy.internal.cf.eu10.hana.ondemand.com"
    assert p == 20003
    h, p = _resolve_proxy_endpoint("eu10", use_tls=True)
    assert p == 20004


def test_resolve_proxy_endpoint_env_override_host_only(monkeypatch):
    """SAPMAP_BTP_PROXY=localhost → host=localhost, port default."""
    from sap_pp_probe import _resolve_proxy_endpoint
    monkeypatch.setenv("SAPMAP_BTP_PROXY", "localhost")
    h, p = _resolve_proxy_endpoint("eu10", use_tls=False)
    assert h == "localhost"
    assert p == 20003


def test_resolve_proxy_endpoint_env_override_host_and_port(monkeypatch):
    """SAPMAP_BTP_PROXY=localhost:20003 — cf-ssh tunnel pattern."""
    from sap_pp_probe import _resolve_proxy_endpoint
    monkeypatch.setenv("SAPMAP_BTP_PROXY", "localhost:20003")
    h, p = _resolve_proxy_endpoint("eu10", use_tls=False)
    assert h == "localhost"
    assert p == 20003


def test_resolve_proxy_endpoint_env_override_bad_port_falls_back(monkeypatch):
    """Malformed port suffix → take the whole thing as host, fall back
    to the default port."""
    from sap_pp_probe import _resolve_proxy_endpoint
    monkeypatch.setenv("SAPMAP_BTP_PROXY", "proxy.example.com:notaport")
    h, p = _resolve_proxy_endpoint("eu10", use_tls=False)
    # Falls back to default port; host kept as the literal string
    assert p == 20003


def test_verify_pp_tunnel_unreachable_surfaces_cf_ssh_hint():
    """When the CONNECT phase times out, the orchestrator's error
    message should mention the cf-ssh tunnel workaround so the
    operator can act on it without having to re-read SAP docs."""
    from sap_pp_probe import verify_pp
    state, sub_uuid = _mock_state_with_pp_dest()
    fake_cfg = {"ok": True, "url": "http://10.0.0.5:8080",
                "auth_tokens": [], "destination": {}, "raw": {}, "error": ""}
    fake_primary = {
        "status": 0, "headers": {}, "body_snippet": "",
        "latency_ms": 0,
        "error": "TimeoutError: timed out",
        "connect_status": 0, "connect_error": "TimeoutError: timed out",
        "proxy_host": "connectivityproxy.internal.cf.eu10.hana.ondemand.com",
        "proxy_port": 20003,
    }
    with patch("sap_pp_probe.fetch_destination_config", return_value=fake_cfg), \
         patch("sap_pp_probe.http_probe_via_connectivity_proxy",
               return_value=fake_primary):
        out = verify_pp(state, _node(), _scc(), sub_uuid,
                         token=_fake_jwt("eu10"), cleanup_after=False)
    assert out["verdict"] == "tunnel_unreachable"
    err = out["error"]
    assert "cf ssh" in err.lower()
    assert "SAPMAP_BTP_PROXY" in err
    assert "20003" in err


# ===========================================================================
# Forward-proxy wire format — absolute URI in request line, no CONNECT
# ===========================================================================

def test_http_probe_uses_forward_proxy_not_connect(monkeypatch):
    """Regression: BTP's connectivity proxy on port 20003 is a plain
    HTTP forward proxy.  Earlier versions sent ``CONNECT host:port``
    and got HTTP 405 back ("HTTPS proxying is not supported").  The
    fix uses an absolute URI in the request line.  This test pins
    the wire format by capturing the bytes sent to the socket."""
    import sap_pp_probe
    captured = {"sent": b""}

    class FakeSocket:
        def __init__(self):
            self.recv_buf = (
                b"HTTP/1.1 200 OK\r\n"
                b"sap-username: DDIC\r\n"
                b"content-length: 2\r\n"
                b"connection: close\r\n\r\n"
                b"OK")
        def settimeout(self, _): pass
        def sendall(self, data): captured["sent"] += data
        def recv(self, n):
            chunk, self.recv_buf = self.recv_buf[:n], self.recv_buf[n:]
            return chunk
        def close(self): pass

    monkeypatch.setattr(sap_pp_probe.socket, "create_connection",
                         lambda addr, timeout=None: FakeSocket())

    out = sap_pp_probe.http_probe_via_connectivity_proxy(
        user_jwt="eyJ.fake.jwt",
        region="eu10",
        target_url="http://192.168.2.209:8080",
        path="/sap/bc/ping",
        scc_location_id="",
    )
    sent = captured["sent"].decode("utf-8", "replace")
    # Must NOT use CONNECT
    assert not sent.startswith("CONNECT "), (
        "Probe regressed to CONNECT-style tunneling — proxy rejects "
        "that with 405.  Wire bytes:\n" + sent[:200])
    # Must use forward-proxy absolute URI
    assert sent.startswith(
        "GET http://192.168.2.209:8080/sap/bc/ping HTTP/1.1\r\n"), (
        "Wire format wrong.  First line should be the absolute URI:\n"
        + sent[:120])
    # Required headers
    assert "Proxy-Authorization: Bearer eyJ.fake.jwt" in sent
    assert "Host: 192.168.2.209:8080" in sent
    # Response was parsed cleanly
    assert out["status"] == 200
    assert out["headers"]["sap-username"] == "DDIC"


def test_http_probe_includes_scc_location_id_header(monkeypatch):
    """When the operator's subaccount has a custom SCC location_id,
    the probe must include ``SAP-Connectivity-SCC-Location_ID``."""
    import sap_pp_probe
    captured = {"sent": b""}

    class FakeSocket:
        def __init__(self):
            self.recv_buf = b"HTTP/1.1 200 OK\r\n\r\n"
        def settimeout(self, _): pass
        def sendall(self, d): captured["sent"] += d
        def recv(self, n):
            chunk, self.recv_buf = self.recv_buf[:n], self.recv_buf[n:]
            return chunk
        def close(self): pass

    monkeypatch.setattr(sap_pp_probe.socket, "create_connection",
                         lambda addr, timeout=None: FakeSocket())
    sap_pp_probe.http_probe_via_connectivity_proxy(
        user_jwt="t", region="eu10",
        target_url="http://10.0.0.5:8080",
        path="/sap/bc/ping",
        scc_location_id="DC01",
    )
    sent = captured["sent"].decode("utf-8", "replace")
    assert "SAP-Connectivity-SCC-Location_ID: DC01" in sent


# ===========================================================================
# Test helpers
# ===========================================================================

def _fake_jwt(region: str) -> str:
    """Build a JWT-shaped string whose payload has the iss field that
    extract_region_from_token recognises.  Signature is a dummy."""
    import base64, json
    payload = {"iss": f"https://example.authentication.{region}.hana.ondemand.com/oauth/token"}
    h = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{h}.{p}.sig"
