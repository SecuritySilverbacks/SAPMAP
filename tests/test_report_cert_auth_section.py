"""Engagement report — cert-auth destinations section.

Verifies that the new _cert_auth_destinations_section renders
X.509 rows in a clear table with the BTP indicator, and stays
silent when the landscape has none (no header noise).
"""
from __future__ import annotations

import modules  # noqa: F401  (registers package paths)
from sapmap_report import _cert_auth_destinations_section
from sapmap_models import SAPMAPState, SAPNode, RFCConnection


def _state_with_conns(conns):
    st = SAPMAPState()
    st.nodes["AE1"] = SAPNode(sid="AE1", ip="10.10.1.6")
    st.connections = list(conns)
    return st


def test_empty_state_produces_no_section():
    """No cert-auth destinations anywhere → no section at all.
    Prevents an empty "X.509 destinations" header on landscapes
    that don't have any (avoids report noise)."""
    assert _cert_auth_destinations_section(SAPMAPState()) == []


def test_single_btp_cert_auth_destination_renders():
    """One TEST_MARCH-shaped edge to BTP produces a section with
    the URL, PSE, and cloud indicator."""
    conn = RFCConnection(
        source_sid="AE1", source_host="10.10.1.6",
        destination_name="TEST_MARCH", rfc_type="G",
        conn_type="http", http_auth_type="X509",
        http_cert_pse="DFAULT",
        http_url="https://api.eu1.hana.ondemand.com")
    lines = _cert_auth_destinations_section(_state_with_conns([conn]))

    assert lines, "expected a section body, got nothing"
    body = "\n".join(lines)
    assert "Certificate-authenticated HTTP destinations" in body
    assert "TEST_MARCH" in body
    assert "DFAULT" in body
    assert "api.eu1.hana.ondemand.com" in body
    # BTP indicator emoji must be present for the *.hana.ondemand.com
    # target — that's how the audience visually spots on-prem-to-cloud
    # trust edges at a glance.
    assert "☁️" in body


def test_basic_auth_destination_excluded():
    """Regression pin — the section MUST only include X509 rows.
    A BASICAUTHENTICATION destination alongside a cert-auth one
    would confuse the impact story if it showed up here."""
    cert = RFCConnection(
        source_sid="AE1", source_host="10.10.1.6",
        destination_name="TEST_MARCH", rfc_type="G",
        conn_type="http", http_auth_type="X509",
        http_cert_pse="DFAULT",
        http_url="https://api.eu1.hana.ondemand.com")
    basic = RFCConnection(
        source_sid="AE1", source_host="10.10.1.6",
        destination_name="OLD_BASIC", rfc_type="G",
        conn_type="http", http_auth_type="BASICAUTHENTICATION",
        http_url="https://basic.example.com")
    body = "\n".join(_cert_auth_destinations_section(
        _state_with_conns([cert, basic])))

    assert "TEST_MARCH" in body
    assert "OLD_BASIC" not in body


def test_non_btp_cert_auth_uses_no_cloud_indicator():
    """A cert-auth destination to a third-party SaaS (not BTP)
    must still appear but WITHOUT the cloud emoji — reserves the
    ☁️ marker for genuine on-prem→BTP edges so the exec summary
    isn't over-reported."""
    conn = RFCConnection(
        source_sid="AE1", source_host="10.10.1.6",
        destination_name="HTTPS_FORTINET_TEST", rfc_type="G",
        conn_type="http", http_auth_type="X509",
        http_cert_pse="DFAULT",
        http_url="https://securitybridge.float-zone.com:4444")
    body = "\n".join(_cert_auth_destinations_section(
        _state_with_conns([conn])))

    assert "HTTPS_FORTINET_TEST" in body
    assert "securitybridge.float-zone.com" in body
    # No BTP cloud indicator — this is a third-party SaaS.
    assert "☁️" not in body
