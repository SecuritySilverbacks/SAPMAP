"""On-prem → BTP lateral move: harvest captured BTP-bound creds and
exchange at XSUAA for a BTP access token."""
from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest

import modules  # noqa: F401  (registers package paths)
from sap_onprem_to_btp import (
    harvest_btp_candidates, mint_btp_token,
    _normalise_uaa_url, _region_from_host, _is_btp_host,
)
from sapmap_models import (SAPMAPState, SAPNode, RFCConnection)


# --- helpers ---------------------------------------------------------

def _abap_node():
    return SAPNode(sid="S4P", system_type="ABAP",
                    hostname="s4phost", ip="10.0.0.1")


def _btp_http_dest_conn(*, source_sid="S4P",
                          name="OAUTH_BTP",
                          url="https://researchlab-yehctg7m.authentication.eu10-004.hana.ondemand.com",
                          client_id="sb-clone!b1234|destination-xsappname!b404",
                          client_secret="theSecret"):
    return RFCConnection(
        source_sid=source_sid, source_host="s4phost",
        target_sid="", target_host="",
        destination_name=name,
        rfc_user=client_id,
        conn_type="http",
        http_url=url,
        http_auth_type="OAUTH2_CLIENT_CREDENTIALS",
        secstore_password=client_secret,
    )


# --- _is_btp_host / _region_from_host --------------------------------

def test_is_btp_host_matches_only_btp_suffix():
    assert _is_btp_host("api.cf.eu10.hana.ondemand.com") is True
    assert _is_btp_host("FOO.HANA.ONDEMAND.COM") is True
    assert _is_btp_host("api.example.com") is False
    assert _is_btp_host("") is False


def test_region_from_host_handles_sub_regions():
    assert _region_from_host("api.cf.eu10.hana.ondemand.com") == "eu10"
    assert _region_from_host("api.cf.eu10-004.hana.ondemand.com") == "eu10-004"
    assert _region_from_host("foo.bar.us10.hana.ondemand.com") == "us10"
    assert _region_from_host("api.example.com") == ""


# --- _normalise_uaa_url ----------------------------------------------

def test_normalise_uaa_appends_oauth_token_for_auth_hosts():
    out = _normalise_uaa_url(
        "https://researchlab-yehctg7m.authentication.eu10-004.hana.ondemand.com")
    assert out == ("https://researchlab-yehctg7m.authentication.eu10-004"
                    ".hana.ondemand.com/oauth/token")


def test_normalise_uaa_passthrough_when_already_token_endpoint():
    url = "https://x.authentication.eu10.hana.ondemand.com/oauth/token"
    assert _normalise_uaa_url(url) == url


def test_normalise_uaa_leaves_non_auth_urls_alone():
    """Service URLs (not authentication subdomain) shouldn't be
    silently rewritten — operators may need to edit them manually."""
    url = "https://researchlab.cfapps.eu10.hana.ondemand.com/api"
    assert _normalise_uaa_url(url) == url


# --- harvest_btp_candidates ------------------------------------------

def test_harvest_picks_up_btp_destinations_on_node():
    state = SAPMAPState()
    node = _abap_node()
    state.add_node(node)
    state.connections.append(_btp_http_dest_conn())
    cands = harvest_btp_candidates(state, node)
    assert len(cands) == 1
    c = cands[0]
    assert c["source"] == "connection"
    assert c["client_id"].startswith("sb-clone")
    assert c["client_secret"] == "theSecret"
    assert "/oauth/token" in c["uaa_url"]
    assert c["region_hint"] == "eu10-004"


def test_harvest_skips_destinations_without_secstore_password():
    """A destination without a recovered cleartext password isn't
    actionable — exclude it so the operator's UI doesn't list rows
    they can't mint with."""
    state = SAPMAPState()
    node = _abap_node()
    state.add_node(node)
    conn = _btp_http_dest_conn(client_secret="")
    state.connections.append(conn)
    assert harvest_btp_candidates(state, node) == []


def test_harvest_skips_non_btp_destinations():
    state = SAPMAPState()
    node = _abap_node()
    state.add_node(node)
    state.connections.append(_btp_http_dest_conn(
        url="https://internal.corp.example/oauth/token"))
    assert harvest_btp_candidates(state, node) == []


def test_harvest_dedupes_across_artefact_sources():
    """The same (uaa_url, client_id) pair appearing in a connection
    AND a Java SecStore entry shouldn't show up twice."""
    state = SAPMAPState()
    node = _abap_node()
    state.add_node(node)
    state.connections.append(_btp_http_dest_conn())
    node.java_secstore_entries = [{
        "name": "btp-cpi-dest",
        "target_sid": ("https://researchlab-yehctg7m.authentication."
                        "eu10-004.hana.ondemand.com"),
        "client_id": "sb-clone!b1234|destination-xsappname!b404",
        "client_secret": "theSecret",
    }]
    cands = harvest_btp_candidates(state, node)
    assert len(cands) == 1


def test_harvest_picks_up_java_secstore_entry():
    state = SAPMAPState()
    node = _abap_node()
    state.add_node(node)
    node.java_secstore_entries = [{
        "name": "btp-dest",
        "target_sid": ("https://researchlab-yehctg7m.authentication."
                        "eu10-004.hana.ondemand.com"),
        "client_id": "sb-foo!b1",
        "client_secret": "javaSecret",
    }]
    cands = harvest_btp_candidates(state, node)
    assert len(cands) == 1
    assert cands[0]["source"] == "java-secstore"
    assert cands[0]["client_secret"] == "javaSecret"


# --- mint_btp_token --------------------------------------------------

def _mock_urlopen_returning(payload: dict, code: int = 200):
    """Build a context-manager that mimics urllib.request.urlopen()."""
    body = json.dumps(payload).encode("utf-8")
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=MagicMock(
        read=MagicMock(return_value=body),
        getcode=MagicMock(return_value=code)))
    cm.__exit__ = MagicMock(return_value=False)
    return cm


def test_mint_returns_access_token_on_200():
    cm = _mock_urlopen_returning({"access_token": "tok123"})
    with patch("sap_onprem_to_btp.urllib.request.urlopen",
                return_value=cm) as up:
        token, err = mint_btp_token(
            "https://x.authentication.eu10.hana.ondemand.com/oauth/token",
            "cid", "csec")
    assert err == ""
    assert token == "tok123"
    # Verify the request actually carried a basic-auth header and the
    # client_credentials body — without those it'd be a meaningless
    # call.
    req = up.call_args[0][0]
    assert req.get_header("Authorization", "").startswith("Basic ")
    assert req.data == b"grant_type=client_credentials"


def test_mint_rejects_missing_inputs():
    token, err = mint_btp_token("", "cid", "csec")
    assert token == ""
    assert "uaa_url" in err


def test_mint_returns_error_on_no_access_token_in_payload():
    cm = _mock_urlopen_returning({"unexpected": "shape"})
    with patch("sap_onprem_to_btp.urllib.request.urlopen",
                return_value=cm):
        token, err = mint_btp_token(
            "https://x.authentication.eu10.hana.ondemand.com/oauth/token",
            "cid", "csec")
    assert token == ""
    assert "access_token" in err


def test_mint_surfaces_http_error_body():
    import urllib.error
    he = urllib.error.HTTPError(
        url="https://x", code=401,
        msg="Unauthorized", hdrs=None,
        fp=MagicMock(read=MagicMock(
            return_value=b'{"error":"invalid_client"}')))
    with patch("sap_onprem_to_btp.urllib.request.urlopen",
                side_effect=he):
        token, err = mint_btp_token(
            "https://x.authentication.eu10.hana.ondemand.com/oauth/token",
            "cid", "wrong")
    assert token == ""
    assert "401" in err
    assert "invalid_client" in err
