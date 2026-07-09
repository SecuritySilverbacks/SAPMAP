"""Type-G / Type-H RFCDES rows with X.509 client-cert authentication.

SAPMAP historically dropped every Type-G / Type-H RFCDES row that
lacked ``%_PWD`` on the theory "no stored password = nothing useful".
That threw away certificate-authenticated destinations — which are
precisely the ones we want to plot because they can be exploited by
proxying an HTTP call through the SAP kernel via
``HTTP_CLIENT_CREATE_BY_DESTINATION`` (kernel does mTLS with the
STRUST PSE, attacker never touches the private key).

These tests pin down the parser + reader-gate behaviour against real
RFCOPTIONS fixtures the operator captured from SM59 / RFCDES:

  TEST_MARCH          → G → SAP → BTP (api.eu1.hana.ondemand.com), DFAULT PSE
  HTTPS_FORTINET_TEST → G → SAP → 3rd-party (securitybridge.float-zone.com), DFAULT PSE
  STANDARD_BASIC      → G → basic-auth destination with %_PWD (regression pin)
  ASSERTION_SSO       → G → assertion-ticket destination with J= (used to be misread as URL)

Anchored to the RFCDES2RFCDISPLAY ABAP function module the operator
shared, so key semantics are kernel-authoritative rather than guessed.
"""
from __future__ import annotations

import modules  # noqa: F401  (registers package paths)
from sapmap_rfc import (
    _build_rfcdes_conn,
    _parse_rfcdes_http_options,
    _rfcdes_row_has_creds,
    _rfcdes_row_is_cert_auth,
)
from sapmap_models import SAPNode, RFCConnection


def _node():
    return SAPNode(sid="AE1", ip="10.10.1.6")


# ---------------------------------------------------------------------------
# _rfcdes_row_has_creds / _rfcdes_row_is_cert_auth
# ---------------------------------------------------------------------------

def test_type3_row_always_passes_gate():
    """Non-G/H rows never triggered the %_PWD gate; keep it that way.
    Broadening the G/H acceptance must not accidentally relax the
    Type-3 path (which the trusted-RFC readers rely on)."""
    # No %_PWD, no cert markers — Type 3 still passes because
    # trusted-RFC edges are useful without stored creds.
    assert _rfcdes_row_has_creds("3", "H=host1,S=00")


def test_gh_row_with_pwd_passes_gate():
    """Basic-auth Type-G with %_PWD is the pre-existing happy path —
    must still be accepted after the gate broadening."""
    assert _rfcdes_row_has_creds(
        "G", "H=api.example.com,I=443,T=%_PWD,U=svcuser,Q=Y")


def test_gh_row_with_cert_pse_passes_gate():
    """The regression this whole change fixes: TEST_MARCH-shaped rows
    used to be silently dropped because they have T=N (no %_PWD)
    instead of T=%_PWD.  ``t=DFAULT`` alone must now keep the row."""
    opts = ("H=api.eu1.hana.ondemand.com,W=Y,B=N,C=N,E=N,T=N,K=Y,"
             "Q=A,s=Y,u=N,1=00,q=0,b=N,k=N,F=0      0000,j=N,t=DFAULT,")
    assert _rfcdes_row_has_creds("G", opts)
    assert _rfcdes_row_is_cert_auth(opts)


def test_gh_row_with_q_a_but_no_t_passes_gate():
    """``Q=A`` alone (without ``t=``) should still be recognised as
    cert-auth — some older kernels may omit the ``t=`` field when
    the PSE is the DFAULT one implicit for the client."""
    opts = "H=api.example.com,I=443,Q=A,T=N,U=,D="
    assert _rfcdes_row_has_creds("G", opts)
    assert _rfcdes_row_is_cert_auth(opts)


def test_gh_row_with_empty_t_field_is_not_cert_auth():
    """``t=`` with an empty value is a leftover / init marker — not a
    real PSE.  Must not be misclassified as cert-auth (would result
    in a bogus edge with http_auth_type=X509)."""
    opts = "H=api.example.com,I=443,T=N,t=,Q=N"
    assert not _rfcdes_row_is_cert_auth(opts)
    # And the row still gets dropped because there's no %_PWD either.
    assert not _rfcdes_row_has_creds("G", opts)


def test_gh_row_without_any_auth_marker_still_dropped():
    """A Type-G row with neither %_PWD nor cert markers is genuinely
    unusable — must still be filtered out.  Broadening the gate too
    far would flood the map with empty destinations."""
    opts = "H=nowhere.example.com,I=443"
    assert not _rfcdes_row_has_creds("G", opts)


# ---------------------------------------------------------------------------
# _parse_rfcdes_http_options — X.509 + PSE extraction
# ---------------------------------------------------------------------------

def test_parses_test_march_btp_cert_auth_destination():
    """The primary target scenario — a Type-G destination to BTP
    authenticated via the DFAULT SSL Client PSE.  Every field the
    downstream exploit primitive will need must be populated."""
    conn = RFCConnection(source_sid="AE1", source_host="10.10.1.6", destination_name="TEST_MARCH",
                          rfc_type="G")
    opts = ("H=api.eu1.hana.ondemand.com,W=Y,B=N,C=N,E=N,T=N,K=Y,"
             "Q=A,s=Y,u=N,1=00,q=0,b=N,k=N,F=0      0000,j=N,t=DFAULT,")
    _parse_rfcdes_http_options(conn, opts)

    assert conn.conn_type == "http"
    assert conn.http_auth_type == "X509"
    assert conn.http_cert_pse == "DFAULT"
    # URL must be https (kernel does mTLS) and reach the BTP API host.
    assert conn.http_url.startswith("https://api.eu1.hana.ondemand.com"), (
        f"expected https URL to BTP; got {conn.http_url!r}")


def test_parses_fortinet_cert_auth_destination():
    """The other real-world example — cert-auth Type-G to a 3rd-party
    SaaS (SecurityBridge Fortinet integration).  Same DFAULT PSE.
    Port I=4444 must be honoured (non-standard HTTPS port)."""
    conn = RFCConnection(source_sid="AE1", source_host="10.10.1.6",
                          destination_name="HTTPS_FORTINET_TEST",
                          rfc_type="G")
    opts = ("H=securitybridge.float-zone.com,I=4444,W=Y,B=N,C=N,E=N,"
             "T=N,K=Y,Q=A,s=Y,u=N,1=00,q=0,b=N,k=N,F=0      0000,"
             "j=N,t=DFAULT,")
    _parse_rfcdes_http_options(conn, opts)

    assert conn.http_auth_type == "X509"
    assert conn.http_cert_pse == "DFAULT"
    assert conn.http_url == (
        "https://securitybridge.float-zone.com:4444"), (
        f"expected https + :4444; got {conn.http_url!r}")


def test_basic_auth_destination_unchanged():
    """Regression pin: pre-existing basic-auth destinations must
    still parse the same way — the parser rewrite kept the URL
    assembly + auth-type default at BASICAUTHENTICATION when no
    cert markers are present."""
    conn = RFCConnection(source_sid="AE1", source_host="10.10.1.6", destination_name="OLD_BASIC",
                          rfc_type="G")
    _parse_rfcdes_http_options(
        conn, "H=api.example.com,I=443,T=%_PWD,U=svcuser,Q=Y")

    assert conn.http_auth_type == "BASICAUTHENTICATION"
    assert conn.http_cert_pse == ""
    assert conn.rfc_user == "svcuser"
    assert conn.http_url == "https://api.example.com"


def test_j_flag_no_longer_misinterpreted_as_url():
    """Historic bug: kernels stashing the assertion-ticket flag in J=
    got their whole RFCOPTIONS parsed as if J= carried a URL, producing
    ``http://https://…`` or similar nonsense.  With the parser rewrite
    J= is treated as an SSO2 marker only, and the URL comes from
    H+I/S+M+N verbatim."""
    conn = RFCConnection(source_sid="AE1", source_host="10.10.1.6", destination_name="ASSERTION_SSO",
                          rfc_type="G")
    _parse_rfcdes_http_options(
        conn,
        "H=abap-target.example.com,I=443,J=X,n=TGT,p=100,T=N")

    # No cert markers → not X509.  J= present → SSO2.
    assert conn.http_auth_type == "SSO2"
    # URL must NOT contain "https://https" or any J-value smuggling.
    assert conn.http_url == "https://abap-target.example.com"


def test_path_prefix_from_N_field_is_included():
    """New in Phase 1 — N=<prefix> was previously unparsed.  Some
    kernels use N= for the whole request path when M= is empty; we
    must fold it into the URL so downstream probes hit the right
    endpoint."""
    conn = RFCConnection(source_sid="AE1", source_host="10.10.1.6", destination_name="WITH_PREFIX",
                          rfc_type="G")
    _parse_rfcdes_http_options(
        conn,
        "H=svc.example.com,I=443,N=/api/v2,Q=A,t=DFAULT")

    assert conn.http_url == "https://svc.example.com/api/v2"


def test_build_rfcdes_conn_keeps_cert_auth_destination():
    """End-to-end: from the raw options string to a RFCConnection
    that survives the reader-gate and has http_cert_pse populated."""
    node = _node()
    opts = ("H=api.eu1.hana.ondemand.com,W=Y,B=N,C=N,E=N,T=N,K=Y,"
             "Q=A,s=Y,u=N,1=00,q=0,b=N,k=N,F=0      0000,j=N,t=DFAULT,")
    conn = _build_rfcdes_conn(node, "TEST_MARCH", "G", opts)

    assert conn.conn_type == "http"
    assert conn.rfc_type == "G"
    assert conn.http_auth_type == "X509"
    assert conn.http_cert_pse == "DFAULT"
    assert conn.destination_name == "TEST_MARCH"


def test_http_cert_pse_field_roundtrips_through_json():
    """Session save/load must preserve the new field or it silently
    vanishes across a state file save.  ``fields(cls)`` in
    ``from_dict`` already handles auto-discovery — this test locks
    the round-trip behaviour so a future refactor can't drop it."""
    src = RFCConnection(
        source_sid="AE1", source_host="10.10.1.6",
        destination_name="TEST_MARCH", rfc_type="G",
        conn_type="http", http_auth_type="X509",
        http_cert_pse="DFAULT",
        http_url="https://api.eu1.hana.ondemand.com")
    d = src.to_dict()
    assert d["http_cert_pse"] == "DFAULT"

    restored = RFCConnection.from_dict(d)
    assert restored.http_cert_pse == "DFAULT"
    assert restored.http_auth_type == "X509"
