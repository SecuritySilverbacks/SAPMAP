"""Workstation-side mint of a BTP access token via local cert files.

Live diagnostic (2026-07-12) — kernel 7.53 on S4H can't read XSUAA
response bodies even after every ABAP-side workaround:

  * icm/HTTP/client/support_http2 = FALSE      (h2 gone)
  * ~server_protocol: HTTP/1.0                 (chunked gone)
  * 5 dynamic h2-disable / downgrade hints     (each caught)

Response arrives with the correct 200 + Content-Type headers but
get_data / get_cdata both return empty bytes.  The bug is deep in
the kernel's HTTP client and no ABAP-level workaround was found.

Escape hatch: SAPMAP's Python process does the POST directly.  The
operator supplies cert + key files from the SAPMAP host (typical
for X509_GENERATED bindings where `cf create-service-key` produces
both).  Same RFC-8705 x5t#S256 cert-binding on the resulting
token — same security model as the kernel-proxied path, just no
SAP kernel in the request path.

Test coverage:
  * happy path against a mocked requests.post
  * missing cert / key / uaa / client_id → clean errors
  * cert or key file not present on disk → clear error
  * XSUAA errors (invalid_client, invalid_scope) → surfaced verbatim
  * malformed JSON response → surfaced with body snippet
  * TLS handshake failure → distinguished from HTTP-layer failure
"""
from __future__ import annotations

from unittest.mock import patch, MagicMock

import modules  # noqa: F401
import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tmp_cert_key(tmp_path):
    """Write dummy PEM files so os.path.isfile passes.  Contents
    don't matter for the tests — requests.post is mocked."""
    cert = tmp_path / "btp-client.crt"
    key = tmp_path / "btp-client.key"
    cert.write_text("-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n")
    key.write_text("-----BEGIN PRIVATE KEY-----\nBBB\n-----END PRIVATE KEY-----\n")
    return str(cert), str(key)


def _fake_response(status=200, json_data=None, text=""):
    r = MagicMock()
    r.status_code = status
    if json_data is not None:
        r.json.return_value = json_data
        r.text = str(json_data)
    else:
        r.json.side_effect = ValueError("not JSON")
        r.text = text
    return r


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_happy_path_returns_token(tmp_path):
    """The successful shape from XSUAA when the cert-auth handshake
    lands and the client is valid: 200 with access_token in the
    JSON body."""
    from sap_onprem_to_btp import mint_btp_token_via_local_cert
    cert, key = _tmp_cert_key(tmp_path)
    # Handcraft a minimal JWT so decode_token_claims parses cleanly.
    jwt = (
        "eyJhbGciOiJSUzI1NiJ9."          # {"alg":"RS256"}
        "eyJ6aWQiOiI5MGE5MDE4OS04Yzk"    # {"zid":"90a90189-8c94-44ff-..."}
        "0LTQ0ZmYtOWY3Ni1iNTBhNDJjMG"
        "ZkOTgifQ."
        "sig"
    )
    with patch("requests.post",
                return_value=_fake_response(
                    200,
                    {"access_token": jwt, "token_type": "bearer",
                     "expires_in": 43199, "scope": "uaa.resource"})):
        token, err, claims = mint_btp_token_via_local_cert(
            uaa_url=("https://sub.authentication.cert.eu10."
                      "hana.ondemand.com/oauth/token"),
            client_id="sb-x!b1|destination-xsappname!b4",
            cert_path=cert, key_path=key)
    assert err == ""
    assert token == jwt
    # decode_token_claims parsed the zid claim through
    assert claims.get("zid") == "90a90189-8c94-44ff-9f76-b50a42c0fd98"


def test_scope_param_flows_into_form_body(tmp_path):
    """When the caller asks for a specific scope, it goes into the
    POST body as scope=<value>."""
    from sap_onprem_to_btp import mint_btp_token_via_local_cert
    cert, key = _tmp_cert_key(tmp_path)
    captured = {}
    def _fake_post(url, data=None, cert=None, headers=None,
                    timeout=None, verify=None):
        captured["data"] = data
        return _fake_response(200, {"access_token": "tok"})
    with patch("requests.post",
                side_effect=_fake_post):
        token, err, _ = mint_btp_token_via_local_cert(
            uaa_url="https://sub.authentication.cert.eu10.hana.ondemand.com/oauth/token",
            client_id="sb-x!b1", cert_path=cert, key_path=key,
            scope="destination_configuration.ApiAccess")
    assert err == ""
    assert token == "tok"
    assert captured["data"]["scope"] == "destination_configuration.ApiAccess"
    assert captured["data"]["grant_type"] == "client_credentials"


def test_cert_and_key_passed_to_requests(tmp_path):
    """The cert+key pair reaches requests.post as `cert=(<crt>,
    <key>)` — requests uses that for the mTLS handshake."""
    from sap_onprem_to_btp import mint_btp_token_via_local_cert
    cert, key = _tmp_cert_key(tmp_path)
    captured = {}
    def _fake_post(url, data=None, cert=None, headers=None,
                    timeout=None, verify=None):
        captured["cert"] = cert
        return _fake_response(200, {"access_token": "t"})
    with patch("requests.post",
                side_effect=_fake_post):
        mint_btp_token_via_local_cert(
            uaa_url="https://x/", client_id="c",
            cert_path=cert, key_path=key)
    assert captured["cert"] == (cert, key)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def test_missing_client_id_short_circuits(tmp_path):
    from sap_onprem_to_btp import mint_btp_token_via_local_cert
    cert, key = _tmp_cert_key(tmp_path)
    with patch("requests.post") as m:
        token, err, _ = mint_btp_token_via_local_cert(
            uaa_url="https://x/", client_id="",
            cert_path=cert, key_path=key)
    assert token == ""
    assert "client_id" in err
    m.assert_not_called()


def test_missing_uaa_url_short_circuits(tmp_path):
    from sap_onprem_to_btp import mint_btp_token_via_local_cert
    cert, key = _tmp_cert_key(tmp_path)
    with patch("requests.post") as m:
        token, err, _ = mint_btp_token_via_local_cert(
            uaa_url="", client_id="c",
            cert_path=cert, key_path=key)
    assert token == ""
    assert "uaa_url" in err
    m.assert_not_called()


def test_cert_file_missing_gives_clean_error(tmp_path):
    """Operator typo in the cert path — must fail fast with a
    "file not found" message, not a cryptic requests exception."""
    from sap_onprem_to_btp import mint_btp_token_via_local_cert
    _, key = _tmp_cert_key(tmp_path)
    with patch("requests.post") as m:
        token, err, _ = mint_btp_token_via_local_cert(
            uaa_url="https://x/", client_id="c",
            cert_path="/nonexistent.crt", key_path=key)
    assert token == ""
    assert "cert_path" in err
    assert "not found" in err
    m.assert_not_called()


def test_key_file_missing_gives_clean_error(tmp_path):
    from sap_onprem_to_btp import mint_btp_token_via_local_cert
    cert, _ = _tmp_cert_key(tmp_path)
    with patch("requests.post") as m:
        token, err, _ = mint_btp_token_via_local_cert(
            uaa_url="https://x/", client_id="c",
            cert_path=cert, key_path="/nonexistent.key")
    assert token == ""
    assert "key_path" in err
    assert "not found" in err
    m.assert_not_called()


# ---------------------------------------------------------------------------
# XSUAA error shapes
# ---------------------------------------------------------------------------

def test_invalid_client_error_surfaced_verbatim(tmp_path):
    """XSUAA returns 401 {"error":"invalid_client",...} when the
    cert doesn't match a registered x509 binding.  Surface both
    the error code AND the description so the operator can tell
    cert-mismatch from client_id typo."""
    from sap_onprem_to_btp import mint_btp_token_via_local_cert
    cert, key = _tmp_cert_key(tmp_path)
    with patch("requests.post",
                return_value=_fake_response(
                    401,
                    {"error": "invalid_client",
                     "error_description": "Bad credentials"})):
        _, err, _ = mint_btp_token_via_local_cert(
            uaa_url="https://x/", client_id="sb-wrong!b1",
            cert_path=cert, key_path=key)
    assert "invalid_client" in err
    assert "Bad credentials" in err
    assert "401" in err


def test_invalid_scope_error_surfaced(tmp_path):
    from sap_onprem_to_btp import mint_btp_token_via_local_cert
    cert, key = _tmp_cert_key(tmp_path)
    with patch("requests.post",
                return_value=_fake_response(
                    400,
                    {"error": "invalid_scope",
                     "error_description": "scope xyz not granted"})):
        _, err, _ = mint_btp_token_via_local_cert(
            uaa_url="https://x/", client_id="c",
            cert_path=cert, key_path=key,
            scope="destination_configuration.ApiAccess")
    assert "invalid_scope" in err


# ---------------------------------------------------------------------------
# Non-JSON / malformed / transport failure
# ---------------------------------------------------------------------------

def test_non_json_response_surfaces_snippet(tmp_path):
    """A reverse proxy (or intermediate WAF) returning HTML instead
    of the expected JSON must not silently return an empty token.
    Surface the first 300 chars so the operator can identify
    who's intercepting."""
    from sap_onprem_to_btp import mint_btp_token_via_local_cert
    cert, key = _tmp_cert_key(tmp_path)
    with patch("requests.post",
                return_value=_fake_response(
                    200, json_data=None,
                    text="<html><body>WAF blocked</body></html>")):
        token, err, _ = mint_btp_token_via_local_cert(
            uaa_url="https://x/", client_id="c",
            cert_path=cert, key_path=key)
    assert token == ""
    assert "non-JSON" in err
    assert "WAF" in err


def test_tls_error_surfaced_with_type(tmp_path):
    """TLS handshake failed on the wire — cert not matched, TLS
    version mismatch, etc.  Distinguish from HTTP-layer errors."""
    from sap_onprem_to_btp import mint_btp_token_via_local_cert
    import requests as _req
    cert, key = _tmp_cert_key(tmp_path)
    with patch(
            "requests.post",
            side_effect=_req.exceptions.SSLError(
                "hostname mismatch: expected 'x' got 'y'")):
        token, err, _ = mint_btp_token_via_local_cert(
            uaa_url="https://x/", client_id="c",
            cert_path=cert, key_path=key)
    assert token == ""
    assert "TLS handshake failed" in err
    assert "hostname mismatch" in err


def test_generic_connection_failure_surfaced(tmp_path):
    from sap_onprem_to_btp import mint_btp_token_via_local_cert
    cert, key = _tmp_cert_key(tmp_path)
    with patch("requests.post",
                side_effect=ConnectionRefusedError(
                    "Connection refused")):
        token, err, _ = mint_btp_token_via_local_cert(
            uaa_url="https://x/", client_id="c",
            cert_path=cert, key_path=key)
    assert token == ""
    assert "unreachable" in err
    assert "ConnectionRefusedError" in err
