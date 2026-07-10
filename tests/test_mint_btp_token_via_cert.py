"""RFC-8705 cert-auth BTP token mint (Phase 2 of the plan).

Pins the helper that turns a working X509 SM59 destination + a BTP
client_id into a JWT — no client_secret required.  Mirrors the live
run against ``researchlab-yehctg7m``:

    POST https://<sub>.authentication.cert.<region>.hana.ondemand.com/oauth/token
    Content-Type: application/x-www-form-urlencoded
    <mTLS with PSE DFAULT cert>

    grant_type=client_credentials&client_id=sb-...!b...|destination-xsappname!b...

    → 200 {"access_token":"eyJ...","token_type":"bearer",...}

Coverage:

  * happy path: token extracted + claims decoded
  * scope pass-through when the operator requests one explicitly
  * XSUAA error shapes: invalid_client, invalid_scope, generic 4xx
  * malformed / empty / non-JSON body
  * URL-encoding of the ! and | characters in real BTP client_ids
  * client_id required
  * kernel-proxy failure short-circuits before parse

We mock the kernel-proxy layer (``call_via_destination``) since it
requires a live RFC connection.  The Phase 1 wrapper tests cover
the ABAP-side shape; this file is about the helper's HTTP-response
handling.
"""
from __future__ import annotations

from unittest.mock import patch

import modules  # noqa: F401  (registers package paths)
import pytest
from sap_onprem_to_btp import mint_btp_token_via_cert
from sapmap_models import SAPNode


def _node():
    return SAPNode(sid="S4H", ip="192.168.2.209", system_type="ABAP")


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_happy_path_returns_token_and_decoded_claims():
    """The real response shape from XSUAA when the cert-auth handshake
    succeeded and the client is valid.  Header + payload here mirror
    the researchlab-yehctg7m JWT.  Signature is truncated (not
    verified by SAPMAP — the trust chain is the mTLS handshake, not
    the JWT signature)."""
    # Handcrafted JWT: header + payload + signature, base64url'd.
    # Payload: {"zid":"90a90189-...","cid":"sb-...","scope":["uaa.resource"]}
    jwt = (
        "eyJhbGciOiJSUzI1NiJ9."          # header (alg:RS256)
        "eyJ6aWQiOiI5MGE5MDE4OS04Yzk"    # payload start (base64url)
        "0LTQ0ZmYtOWY3Ni1iNTBhNDJjMG"
        "ZkOTgiLCJjaWQiOiJzYi1jbG9uZ"
        "SIsInNjb3BlIjpbInVhYS5yZXNv"
        "dXJjZSJdfQ."
        "sig_omitted"
    )
    resp = {"ok": True, "status": 200, "reason": "OK",
             "body": (f'{{"access_token":"{jwt}",'
                       f'"token_type":"bearer",'
                       f'"expires_in":43199,'
                       f'"scope":"uaa.resource"}}'),
             "error": ""}
    with patch("sap_onprem_to_btp.call_via_destination",
                return_value=resp):
        token, err, claims = mint_btp_token_via_cert(
            _node(), "TO_BTP", "sb-x!b1|destination-xsappname!b4")
    assert err == ""
    assert token == jwt
    # decode_token_claims parsed the payload
    assert claims.get("zid") == "90a90189-8c94-44ff-9f76-b50a42c0fd98"
    assert claims.get("cid") == "sb-clone"
    assert "uaa.resource" in (claims.get("scope") or [])


def test_scope_param_included_in_form_body():
    """When the caller requests a specific scope, it flows into the
    form body verbatim.  Used when the default (aud-only) grants
    aren't enough for a downstream API."""
    captured = {}
    def _fake(node, dest, method, path, creds, body, content_type):
        captured["body"] = body
        captured["content_type"] = content_type
        return {"ok": True, "status": 200,
                "body": '{"access_token":"tok"}', "error": ""}
    with patch("sap_onprem_to_btp.call_via_destination",
                side_effect=_fake):
        token, err, _ = mint_btp_token_via_cert(
            _node(), "TO_BTP", "sb-x!b1",
            scope="destination_configuration.ApiAccess")
    assert err == ""
    assert token == "tok"
    assert "scope=destination_configuration.ApiAccess" in captured["body"]
    assert captured["content_type"] == "application/x-www-form-urlencoded"


# ---------------------------------------------------------------------------
# URL-encoding of ! and | in the client_id
# ---------------------------------------------------------------------------

def test_client_id_special_chars_url_encoded():
    """BTP client_ids look like sb-<uuid>!b609810|destination-xsappname!b404.
    urllib.parse.urlencode escapes ! and | to %21 and %7C — XSUAA
    accepts either form but the encoded shape is safer through
    intermediate proxies and doesn't trigger ABAP-literal edge cases."""
    captured = {}
    def _fake(node, dest, method, path, creds, body, content_type):
        captured["body"] = body
        return {"ok": True, "status": 200,
                "body": '{"access_token":"t"}', "error": ""}
    real_cid = ("sb-clonef0e76cf4991f41369c69286725705654!b609810"
                "|destination-xsappname!b404")
    with patch("sap_onprem_to_btp.call_via_destination",
                side_effect=_fake):
        mint_btp_token_via_cert(_node(), "TO_BTP", real_cid)
    # ! encoded as %21, | encoded as %7C
    assert "%21" in captured["body"]
    assert "%7C" in captured["body"]
    # Raw ! and | must NOT appear (they'd survive as-is if we forgot
    # to urlencode, which XSUAA tolerates but is a robustness bug)
    assert "!" not in captured["body"]
    assert "|" not in captured["body"]


# ---------------------------------------------------------------------------
# XSUAA error shapes
# ---------------------------------------------------------------------------

def test_invalid_client_surfaces_error_and_description():
    """Cert didn't match a registered x509 binding → XSUAA returns
    401 with {"error":"invalid_client","error_description":"..."}.
    The helper must surface both parts so the operator can tell
    "cert mismatch" from "scope missing"."""
    resp = {"ok": True, "status": 401,
             "body": ('{"error":"invalid_client",'
                       '"error_description":"Bad credentials"}'),
             "error": ""}
    with patch("sap_onprem_to_btp.call_via_destination",
                return_value=resp):
        token, err, claims = mint_btp_token_via_cert(
            _node(), "TO_BTP", "sb-wrong!b1")
    assert token == ""
    assert "invalid_client" in err
    assert "Bad credentials" in err
    assert "401" in err
    assert claims == {}


def test_invalid_scope_surfaces_error():
    """Explicit scope request that the client isn't entitled to →
    invalid_scope.  Operator needs to see the exact string so they
    know whether to remove --scope or recreate the service key
    with additional authorities."""
    resp = {"ok": True, "status": 400,
             "body": ('{"error":"invalid_scope",'
                       '"error_description":"scope xyz not granted"}'),
             "error": ""}
    with patch("sap_onprem_to_btp.call_via_destination",
                return_value=resp):
        _, err, _ = mint_btp_token_via_cert(
            _node(), "TO_BTP", "sb-x!b1",
            scope="destination_configuration.ApiAccess")
    assert "invalid_scope" in err


def test_generic_non_oauth_error_still_surfaced():
    """When XSUAA (or a reverse proxy in front of it) returns a
    non-OAuth JSON shape, the raw payload is dumped so the operator
    has something to grep."""
    resp = {"ok": True, "status": 500,
             "body": '{"message":"internal error","trace_id":"abc"}',
             "error": ""}
    with patch("sap_onprem_to_btp.call_via_destination",
                return_value=resp):
        _, err, _ = mint_btp_token_via_cert(
            _node(), "TO_BTP", "sb-x!b1")
    assert "500" in err
    assert "internal error" in err


# ---------------------------------------------------------------------------
# Malformed / non-JSON / empty body
# ---------------------------------------------------------------------------

def test_non_json_body_surfaces_snippet():
    """When something upstream (reverse proxy, WAF) returns HTML
    instead of JSON, we must not silently return an empty token.
    Show the first 300 chars so the operator can identify who's
    intercepting."""
    resp = {"ok": True, "status": 200,
             "body": "<html><body>WAF blocked</body></html>",
             "error": ""}
    with patch("sap_onprem_to_btp.call_via_destination",
                return_value=resp):
        token, err, _ = mint_btp_token_via_cert(
            _node(), "TO_BTP", "sb-x!b1")
    assert token == ""
    assert "non-JSON" in err
    assert "WAF" in err


def test_2xx_without_access_token_is_error():
    """200 with a JSON body that lacks access_token — unusual, but
    XSUAA could theoretically return a challenge instead.  Must
    surface as error, not silently store an empty token."""
    resp = {"ok": True, "status": 200,
             "body": '{"token_type":"bearer","expires_in":43199}',
             "error": ""}
    with patch("sap_onprem_to_btp.call_via_destination",
                return_value=resp):
        token, err, _ = mint_btp_token_via_cert(
            _node(), "TO_BTP", "sb-x!b1")
    assert token == ""
    assert "no access_token" in err


def test_2xx_with_empty_wire_body_names_compression_cause():
    """The bug we chased down live: some SAP kernels return empty
    from get_cdata() when XSUAA replies with Content-Encoding: gzip.
    The wrapper now surfaces content_length + content_encoding +
    wire_bytes as diagnostic fields; the mint helper uses them to
    render a specific error naming compression as the likely cause
    (instead of the previous cryptic "returned no access_token
    field: {}")."""
    resp = {"ok": True, "status": 200,
             "body": "",                # get_cdata came back empty
             "error": "",
             "content_encoding": "gzip",
             "content_length": "1183",   # server DID send bytes
             "wire_bytes": 0}
    with patch("sap_onprem_to_btp.call_via_destination",
                return_value=resp):
        token, err, _ = mint_btp_token_via_cert(
            _node(), "TO_BTP", "sb-x!b1")
    assert token == ""
    assert "empty on the wire" in err
    assert "gzip" in err
    assert "1183" in err
    assert "Accept-Encoding: identity" in err


# ---------------------------------------------------------------------------
# Argument + kernel-proxy failure guards
# ---------------------------------------------------------------------------

def test_empty_client_id_rejected_before_rfc_call():
    """No client_id = no OAuth request possible.  Guard before we
    burn an RFC session on a doomed call."""
    with patch("sap_onprem_to_btp.call_via_destination") as m:
        token, err, _ = mint_btp_token_via_cert(
            _node(), "TO_BTP", "")
    assert token == ""
    assert "client_id" in err
    m.assert_not_called()


def test_kernel_proxy_failure_short_circuits():
    """When call_via_destination returns ok=False (RFC session died,
    ABAP report failed to install, etc.), don't try to parse the
    body — pass the underlying error up."""
    resp = {"ok": False, "status": 0, "reason": "",
             "body": "",
             "error": "RFC exec failed: connection refused"}
    with patch("sap_onprem_to_btp.call_via_destination",
                return_value=resp):
        token, err, _ = mint_btp_token_via_cert(
            _node(), "TO_BTP", "sb-x!b1")
    assert token == ""
    assert "kernel-proxy" in err
    assert "connection refused" in err


def test_wrapper_input_validation_error_becomes_helper_error():
    """When the ABAP wrapper rejects the input (e.g. quotes in the
    body), the helper returns a clean error instead of letting the
    HttpViaDestError propagate to the route handler."""
    from sap_http_via_dest import HttpViaDestError
    with patch("sap_onprem_to_btp.call_via_destination",
                side_effect=HttpViaDestError("bad body")):
        token, err, _ = mint_btp_token_via_cert(
            _node(), "TO_BTP", "sb-x!b1")
    assert token == ""
    assert "bad body" in err
