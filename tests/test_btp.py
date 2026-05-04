#!/usr/bin/env python3
"""Tests for sap_btp + the BTP data model.

All tests are offline — the BTP REST helper functions are stubbed via
unittest.mock.patch on _btp_get so we can feed canned API responses
without ever talking to BTP.
"""
from __future__ import annotations

import base64
import json
import time
from unittest.mock import patch

import pytest

from sapmap_models import (
    SAPMAPState, SAPNode, BTPSubaccountNode, BTPDestination,
    Severity, Credentials,
)
from sap_btp import (
    decode_token_claims, extract_region_from_token, validate_token,
    enumerate_subaccounts, pull_scc_mappings, pull_destinations,
    link_destinations_to_onprem, _hostname_in_url, _rate_limit_check,
    _RATE_LIMIT_BUCKETS,
)


# ---------------------------------------------------------------------------
# Token parsing helpers — offline JWT decode
# ---------------------------------------------------------------------------

def _make_jwt(payload: dict) -> str:
    """Build a fake unsigned JWT — header.payload.signature with the
    payload as base64url JSON.  Signature segment is junk because we
    never verify."""
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}.X"


def test_decode_token_claims_returns_payload():
    tok = _make_jwt({"user_name": "alice", "scope": ["x"]})
    out = decode_token_claims(tok)
    assert out["user_name"] == "alice"
    assert out["scope"] == ["x"]


def test_decode_token_claims_handles_garbage():
    assert decode_token_claims("not-a-jwt") == {}
    assert decode_token_claims("") == {}


def test_extract_region_from_iss_claim():
    tok = _make_jwt({
        "iss": "https://api.authentication.eu10.hana.ondemand.com/oauth/token",
    })
    assert extract_region_from_token(tok) == "eu10"


def test_extract_region_handles_us_region():
    tok = _make_jwt({
        "iss": "https://api.authentication.us10.hana.ondemand.com/oauth/token",
    })
    assert extract_region_from_token(tok) == "us10"


def test_extract_region_handles_unparseable_iss():
    tok = _make_jwt({"iss": "https://nonsense.example.com"})
    assert extract_region_from_token(tok) == ""


def test_validate_token_returns_summary():
    tok = _make_jwt({
        "iss": "https://api.authentication.eu10.hana.ondemand.com/oauth/token",
        "user_name": "alice@example.com",
        "email": "alice@example.com",
        "scope": ["destination_configuration.ApiAccess"],
        "exp": int(time.time()) + 3600,
    })
    out = validate_token(tok)
    assert out["ok"] is True
    assert out["region"] == "eu10"
    assert out["user"] == "alice@example.com"
    assert out["email"] == "alice@example.com"
    assert "destination_configuration.ApiAccess" in out["scopes"]
    assert out["expired"] is False
    assert out["fingerprint"]   # non-empty


def test_validate_token_flags_expired():
    tok = _make_jwt({
        "iss": "https://api.authentication.eu10.hana.ondemand.com/oauth/token",
        "exp": int(time.time()) - 60,
    })
    out = validate_token(tok)
    assert out["expired"] is True
    assert out["expires_in_seconds"] <= 0


def test_validate_token_rejects_garbage():
    out = validate_token("garbage-not-jwt")
    assert out["ok"] is False
    assert "decode" in out["error"]


# ---------------------------------------------------------------------------
# Rate limiter — basic sanity
# ---------------------------------------------------------------------------

def test_rate_limit_allows_normal_traffic():
    _RATE_LIMIT_BUCKETS.clear()
    for _ in range(5):
        rl = _rate_limit_check("fp1")
        assert rl is None


def test_rate_limit_hard_caps_at_200_per_minute():
    _RATE_LIMIT_BUCKETS.clear()
    # Pre-fill the bucket directly to avoid the inter-request sleep
    import sap_btp
    now = time.monotonic()
    sap_btp._RATE_LIMIT_BUCKETS["fp_overflow"] = [now] * 200
    rl = _rate_limit_check("fp_overflow")
    assert rl is not None
    assert "hard-cap" in rl


# ---------------------------------------------------------------------------
# enumerate_subaccounts / pull_scc_mappings / pull_destinations —
# canned-response API tests
# ---------------------------------------------------------------------------

def test_enumerate_subaccounts_parses_value_array():
    canned_body = json.dumps({
        "value": [
            {"guid": "abcd-1234", "displayName": "Test Sub",
             "subdomain": "test-sub", "globalAccountGUID": "gacc-1"},
            {"guid": "efgh-5678", "name": "Other Sub",
             "subdomain": "other"},
        ]
    }).encode()
    with patch("sap_btp._btp_get",
               return_value=(200, {}, canned_body)):
        out = enumerate_subaccounts("token", "eu10")
    assert len(out) == 2
    assert out[0]["uuid"] == "abcd-1234"
    assert out[0]["display_name"] == "Test Sub"
    assert out[0]["subdomain"] == "test-sub"
    assert out[1]["uuid"] == "efgh-5678"
    assert out[1]["display_name"] == "Other Sub"


def test_enumerate_subaccounts_returns_empty_on_auth_failure():
    with patch("sap_btp._btp_get",
               return_value=(401, {}, b'{"error":"unauthorized"}')):
        out = enumerate_subaccounts("token", "eu10")
    assert out == []


def test_enumerate_subaccounts_rejects_unknown_region():
    out = enumerate_subaccounts("token", "totally-bogus")
    assert out == []


def test_pull_scc_mappings_parses_response():
    canned = json.dumps({"value": [
        {"locationId": "MAIN",
         "sccUuid": "scc-uuid-1",
         "subaccount": "abcd-1234",
         "version": "2.16.2"},
    ]}).encode()
    with patch("sap_btp._btp_get",
               return_value=(200, {}, canned)):
        out = pull_scc_mappings("token", "eu10")
    assert len(out) == 1
    assert out[0]["location_id"] == "MAIN"
    assert out[0]["scc_host_uuid"] == "scc-uuid-1"
    assert out[0]["subaccount_uuid"] == "abcd-1234"


def test_pull_destinations_captures_basic_cleartext():
    """Listing returns metadata; per-destination "find" call exposes
    the cleartext password.  Verify both are wired together."""
    listing = json.dumps([
        {"Name": "S4P_BACKEND", "Type": "HTTP",
         "URL": "http://s4phost:8000",
         "Authentication": "BasicAuthentication"}
    ]).encode()
    detail = json.dumps({
        "destinationConfiguration": {
            "Name": "S4P_BACKEND", "Type": "HTTP",
            "URL": "http://s4phost:8000",
            "Authentication": "BasicAuthentication",
            "User": "RFC_BTP_PROD",
            "Password": "Sup3rSecr3t!",
            "ProxyType": "OnPremise",
            "Description": "BTP→S4P production destination",
        }
    }).encode()
    call_count = {"n": 0}

    def fake_get(url, token, **kw):
        call_count["n"] += 1
        if "/subaccountDestinations" in url:
            return (200, {}, listing)
        return (200, {}, detail)

    with patch("sap_btp._btp_get", side_effect=fake_get):
        dests, err = pull_destinations("token", "eu10", "abcd-1234")
    assert err == ""
    assert len(dests) == 1
    d = dests[0]
    assert d.name == "S4P_BACKEND"
    assert d.user == "RFC_BTP_PROD"
    assert d.password == "Sup3rSecr3t!"
    assert d.cleartext_captured is True
    assert d.url == "http://s4phost:8000"
    assert d.authentication == "BasicAuthentication"
    assert d.proxy_type == "OnPremise"
    # Subaccount identity propagates
    assert d.subaccount_uuid == "abcd-1234"


def test_pull_destinations_no_password_when_scope_absent():
    """When the token lacks ApiAccess, the find endpoint returns
    metadata WITHOUT a Password field.  cleartext_captured must
    stay False."""
    listing = json.dumps([
        {"Name": "X", "Type": "HTTP", "URL": "http://x"}
    ]).encode()
    detail = json.dumps({
        "destinationConfiguration": {
            "Name": "X", "Type": "HTTP",
            "URL": "http://x",
            "Authentication": "BasicAuthentication",
            "User": "u",
            # no Password
        }
    }).encode()

    def fake_get(url, token, **kw):
        if "/subaccountDestinations" in url:
            return (200, {}, listing)
        return (200, {}, detail)

    with patch("sap_btp._btp_get", side_effect=fake_get):
        dests, err = pull_destinations("token", "eu10", "abcd-1234")
    assert err == ""
    assert len(dests) == 1
    assert dests[0].cleartext_captured is False
    assert dests[0].password == ""


def test_pull_destinations_handles_oauth_client_credentials():
    """OAuth2ClientCredentials destinations carry clientId + clientSecret
    instead of User + Password.  Both must surface as user / password
    in the captured BTPDestination."""
    listing = json.dumps([{"Name": "API_X", "Type": "HTTP",
                            "URL": "https://api.x"}]).encode()
    detail = json.dumps({
        "destinationConfiguration": {
            "Name": "API_X", "Type": "HTTP",
            "URL": "https://api.x",
            "Authentication": "OAuth2ClientCredentials",
            "clientId": "btp-client-id",
            "clientSecret": "btp-client-secret-XYZ",
        }
    }).encode()

    def fake_get(url, token, **kw):
        return (200, {}, listing if "subaccountDestinations" in url else detail)

    with patch("sap_btp._btp_get", side_effect=fake_get):
        dests, err = pull_destinations("token", "eu10", "abcd-1234")
    assert dests[0].user == "btp-client-id"
    assert dests[0].password == "btp-client-secret-XYZ"
    assert dests[0].cleartext_captured is True
    assert dests[0].authentication == "OAuth2ClientCredentials"


def test_pull_destinations_listing_failure_returns_error():
    with patch("sap_btp._btp_get",
               return_value=(403, {}, b'{"error":"forbidden"}')):
        dests, err = pull_destinations("token", "eu10", "abcd")
    assert dests == []
    assert "listing failed" in err


# ---------------------------------------------------------------------------
# link_destinations_to_onprem — promotes cleartext into SAPNode creds
# ---------------------------------------------------------------------------

def _state_with_s4p():
    s = SAPMAPState()
    s.add_node(SAPNode(sid="S4P", system_type="ABAP",
                        is_production=True, hostname="s4phost",
                        ip="10.0.0.1"))
    return s


def test_link_to_onprem_appends_credential_and_finding():
    state = _state_with_s4p()
    sub = BTPSubaccountNode(uuid="abcd-1234", region="eu10")
    sub.destinations.append(BTPDestination(
        subaccount_uuid="abcd-1234",
        name="S4P_DEST", type="HTTP",
        url="http://s4phost:8000",
        authentication="BasicAuthentication",
        user="RFC_BTP_PROD", password="Sup3rSecr3t!",
        cleartext_captured=True,
    ))
    linked = link_destinations_to_onprem(state, sub)
    assert linked == 1
    s4p = state.nodes["S4P"]
    # Credential was added
    assert any(c.username == "RFC_BTP_PROD" and c.password == "Sup3rSecr3t!"
               for c in s4p.credentials)
    # Finding describes the BTP origin
    names = [f.name for f in s4p.findings]
    assert "BTP destination leaked on-prem credential" in names
    # Subaccount marked pwned
    assert sub.pwned is True
    # destination's linked_target_sid populated
    assert sub.destinations[0].linked_target_sid == "S4P"


def test_link_to_onprem_creates_synthetic_rfc_edge():
    state = _state_with_s4p()
    sub = BTPSubaccountNode(uuid="abcd-1234", region="eu10")
    sub.destinations.append(BTPDestination(
        subaccount_uuid="abcd-1234",
        name="S4P_DEST", url="http://s4phost",
        authentication="BasicAuthentication",
        user="u", password="p", cleartext_captured=True,
    ))
    link_destinations_to_onprem(state, sub)
    # Synthetic edge from BTP:abcd-123 → S4P
    edge = next((c for c in state.connections
                 if c.target_sid == "S4P"
                 and c.source_sid.startswith("BTP:")), None)
    assert edge is not None
    assert edge.tested is False
    assert edge.has_sap_all is False
    assert edge.rfc_user == "u"
    # secstore_password carries the captured cleartext for later test
    assert edge.secstore_password == "p"


def test_link_to_onprem_dedupes_repeated_calls():
    state = _state_with_s4p()
    sub = BTPSubaccountNode(uuid="abcd-1234", region="eu10")
    sub.destinations.append(BTPDestination(
        subaccount_uuid="abcd-1234",
        name="S4P_DEST", url="http://s4phost",
        authentication="BasicAuthentication",
        user="u", password="p", cleartext_captured=True,
    ))
    link_destinations_to_onprem(state, sub)
    link_destinations_to_onprem(state, sub)
    # Credential added once, edge added once
    assert sum(1 for c in state.nodes["S4P"].credentials
               if c.username == "u") == 1
    assert sum(1 for c in state.connections
               if c.target_sid == "S4P"
               and c.source_sid.startswith("BTP:")) == 1


def test_link_to_onprem_skips_destinations_with_unknown_target():
    state = _state_with_s4p()
    sub = BTPSubaccountNode(uuid="abcd-1234", region="eu10")
    sub.destinations.append(BTPDestination(
        subaccount_uuid="abcd-1234",
        name="UNKNOWN_TARGET", url="http://nowhere.example.com",
        authentication="BasicAuthentication",
        user="u", password="p", cleartext_captured=True,
    ))
    linked = link_destinations_to_onprem(state, sub)
    assert linked == 0
    assert not any(c.username == "u"
                   for c in state.nodes["S4P"].credentials)


def test_hostname_in_url_handles_http_and_rfc_forms():
    assert _hostname_in_url("http://host.example:8080/x") == "host.example"
    assert _hostname_in_url("https://other.example") == "other.example"
    assert _hostname_in_url("rfc-host:3300") == "rfc-host"
    assert _hostname_in_url("") == ""


# ---------------------------------------------------------------------------
# Data model — round-trip BTPSubaccountNode through to_dict / from_dict
# ---------------------------------------------------------------------------

def test_btp_subaccount_node_roundtrip():
    sub = BTPSubaccountNode(
        uuid="abcd-1234",
        display_name="Test Sub",
        region="eu10", subdomain="test",
        parent_global_account="gacc",
        scc_locations=[{"location_id": "MAIN"}],
        ias_tenant="tenant.accounts.ondemand.com",
        enumerated_via_user="alice",
        pwned=True,
    )
    sub.destinations.append(BTPDestination(
        subaccount_uuid="abcd-1234", name="X",
        url="http://x", user="u", password="p",
        cleartext_captured=True,
    ))
    d = sub.to_dict()
    restored = BTPSubaccountNode.from_dict(d)
    assert restored.uuid == sub.uuid
    assert restored.region == sub.region
    assert restored.pwned is True
    assert len(restored.destinations) == 1
    assert restored.destinations[0].password == "p"
    assert restored.destinations[0].cleartext_captured is True


def test_state_roundtrip_includes_btp_subaccounts():
    s = SAPMAPState()
    s.btp_subaccounts["uuid1"] = BTPSubaccountNode(
        uuid="uuid1", region="eu10", display_name="X")
    json_str = s.to_json()
    s2 = SAPMAPState.from_json(json_str)
    assert "uuid1" in s2.btp_subaccounts
    assert s2.btp_subaccounts["uuid1"].region == "eu10"


def test_btp_destination_password_does_serialize_to_disk():
    """Per design: passwords on captured destinations DO serialize
    (state save/load preserves engagement loot).  The TOKEN itself
    never serialises — that's separately enforced because it lives
    on SAPMAPApi, not on SAPMAPState."""
    sub = BTPSubaccountNode(uuid="x", region="eu10")
    sub.destinations.append(BTPDestination(
        name="d", password="p1", cleartext_captured=True))
    d = sub.to_dict()
    assert d["destinations"][0]["password"] == "p1"
