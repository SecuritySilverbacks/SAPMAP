"""RFCDES Type-G/H URL scheme normalisation by port.

Pinned bug (2026-07-09): destinations to SJJ on the HTTP variant of
SAPControl (port 50213) and Java (port 50200) were being parsed as
``https://…`` because the RFCDES row still carried a stale
``t=<pse>`` STRUST marker.  Direct probes then failed with
``[SSL: WRONG_VERSION_NUMBER]`` — SAPMAP was speaking TLS to a plain
HTTP server:

  16:22:03 [-] S4H_TO_SJJ: HTTP probe failed
             (SSLError: [SSL: WRONG_VERSION_NUMBER] …)
  16:22:10 [-] to_SJJ_SAPControl: SAPControl auth probe failed
             (SSLError: [SSL: WRONG_VERSION_NUMBER] …)

Fix: after applying the ``t=``/``Q=`` scheme hints, override the
scheme from the port when it unambiguously identifies one of the SAP
port families:

  * ``443`` / ``5NN14`` / ``5NN01`` / ``44300+NN`` / ``1129`` → HTTPS
  * ``80``  / ``5NN13`` / ``5NN00`` / ``80NN``   / ``1128``   → HTTP

``Q=A`` (mTLS) keeps HTTPS regardless — cert-auth on an HTTP port is
a real misconfiguration and the failure should surface, not silently
downgrade.
"""
from __future__ import annotations

import modules  # noqa: F401  (registers package paths)
import sapmap_models  # noqa: F401
from modules.discovery.sapmap_rfc import _parse_rfcdes_http_options
from sapmap_models import RFCConnection as RFCConn


def _parse(options: str) -> RFCConn:
    conn = RFCConn(source_sid="AE1", source_host="10.10.1.6",
                    destination_name="TEST", rfc_type="G")
    _parse_rfcdes_http_options(conn, options)
    return conn


# ---------------------------------------------------------------------------
# The failing cases from live logs
# ---------------------------------------------------------------------------

def test_sapcontrol_http_port_downgrades_despite_pse():
    """to_SJJ_SAPControl: I=50213 with t=DFAULT must resolve to
    ``http://`` — SAPControl HTTP lives on 5NN13, HTTPS on 5NN14.

    Before the fix, ``t=DFAULT`` (STRUST default PSE) forced HTTPS
    and every direct probe hit ``[SSL: WRONG_VERSION_NUMBER]``."""
    conn = _parse("H=192.168.2.192,I=50213,t=DFAULT,U=sjjadm,"
                  "M=/SAPControl.CGI")
    assert conn.http_url == (
        "http://192.168.2.192:50213/SAPControl.CGI"), (
        f"expected http:// on SAPControl HTTP port 50213, got "
        f"{conn.http_url!r}")


def test_java_http_port_downgrades_despite_pse():
    """S4H_TO_SJJ: I=50200 with t=DFAULT must resolve to
    ``http://`` — Java HTTP lives on 5NN00, HTTPS on 5NN01."""
    conn = _parse("H=192.168.2.192,I=50200,t=DFAULT,U=joris,"
                  "M=/wssproc/plain?style=document")
    assert conn.http_url.startswith("http://192.168.2.192:50200"), (
        f"expected http:// on Java HTTP port 50200, got "
        f"{conn.http_url!r}")
    assert not conn.http_url.startswith("https://")


def test_abap_icm_http_port_downgrades_despite_pse():
    """ABAP ICM HTTP is 80NN; stale ``t=`` must not force HTTPS."""
    conn = _parse("H=host,I=8002,t=DFAULT,U=user,M=/sap/bc/")
    assert conn.http_url.startswith("http://host:8002")


def test_hostagent_http_port_downgrades_despite_pse():
    """Host Agent HTTP is 1128, HTTPS is 1129."""
    conn = _parse("H=host,I=1128,t=DFAULT,U=sapadm,M=/")
    assert conn.http_url.startswith("http://host:1128")


# ---------------------------------------------------------------------------
# HTTPS ports still promoted correctly
# ---------------------------------------------------------------------------

def test_sapcontrol_https_port_stays_https():
    """5NN14 = SAPControl HTTPS — must stay HTTPS."""
    conn = _parse("H=host,I=50214,U=sjjadm,M=/SAPControl.CGI")
    assert conn.http_url.startswith("https://host:50214")


def test_java_https_port_stays_https():
    """5NN01 = Java HTTPS — must stay HTTPS."""
    conn = _parse("H=host,I=50201,U=joris,M=/wssproc/plain")
    assert conn.http_url.startswith("https://host:50201")


def test_abap_icm_https_port_stays_https():
    """44300+NN = ABAP ICM HTTPS — must stay HTTPS."""
    conn = _parse("H=host,I=44302,U=user,M=/sap/bc/")
    assert conn.http_url.startswith("https://host:44302")


def test_hostagent_https_port_stays_https():
    """Host Agent HTTPS is 1129."""
    conn = _parse("H=host,I=1129,U=sapadm,M=/")
    assert conn.http_url.startswith("https://host:1129")


def test_port_443_stays_https_no_pse():
    """Bare :443 with no marker must still resolve HTTPS."""
    conn = _parse("H=host,I=443,U=user,M=/")
    assert conn.http_url.startswith("https://host/")


# ---------------------------------------------------------------------------
# Cert-auth (Q=A) keeps HTTPS even on HTTP-only ports (visible fail)
# ---------------------------------------------------------------------------

def test_cert_auth_on_http_port_stays_https():
    """Q=A demands TLS on the wire.  A destination configured with
    Q=A on port 50213 is misconfigured, but downgrading would hide
    the error — keep https:// so the SSLError is loud and
    diagnosable."""
    conn = _parse("H=host,I=50213,Q=A,t=DFAULT,U=user,"
                  "M=/SAPControl.CGI")
    assert conn.http_url.startswith("https://host:50213"), (
        "Q=A (cert-auth) MUST keep https:// even on an HTTP-only "
        "port — cert-auth requires TLS on the wire")
    assert conn.http_auth_type == "X509"


def test_sso2_ticket_on_http_port_stays_https():
    """Q=Y (SSO2 ticket) also demands TLS — an SSO2 ticket sent over
    plain HTTP would leak the credential.  Downgrading is a security
    regression, so keep https:// even when the port (8000, 50200,
    etc.) says HTTP.

    Auth-type stays BASICAUTHENTICATION here because SSO2 auth_type
    is reserved for J=<ticket>-carrying rows (existing convention);
    the fix only guards the scheme, not the auth-type label."""
    conn = _parse("H=peer.corp,S=8000,M=/sap/bc/icf,Q=Y,"
                  "U=ICF_USER,T=%_PWD")
    assert conn.http_url == (
        "https://peer.corp:8000/sap/bc/icf"), (
        f"Q=Y (SSO2) MUST keep https:// on any port to avoid ticket "
        f"leakage; got {conn.http_url!r}")


def test_assertion_ticket_plus_pse_on_http_port_stays_https():
    """J= alone doesn't promote to HTTPS (existing behaviour — the
    parser has never treated J= as an https signal).  But when the
    row ALSO carries a ``t=<pse>`` marker — the common case, since
    assertion-ticket destinations always run over TLS — the tls-
    required guard must keep https:// even on an HTTP-family port.
    Otherwise the ticket would leak."""
    conn = _parse("H=peer.corp,I=8000,M=/sap/bc/soap,J=X,t=DFAULT,"
                  "n=TGT,p=100,U=ICF_USER,T=%_PWD")
    assert conn.http_url.startswith(
        "https://peer.corp:8000/sap/bc/soap"), (
        f"J= + t=<pse> MUST keep https://; got {conn.http_url!r}")
    assert conn.http_auth_type == "SSO2"


# ---------------------------------------------------------------------------
# Unknown ports fall back to the existing t=/Q= heuristic
# ---------------------------------------------------------------------------

def test_unknown_port_with_pse_stays_https():
    """A non-standard HTTPS port (e.g. custom reverse proxy on 9443)
    still gets ``https://`` from the ``t=<pse>`` hint — the port
    override only fires on well-known SAP families."""
    conn = _parse("H=host,I=9443,t=DFAULT,U=user,M=/")
    assert conn.http_url.startswith("https://host:9443")


def test_unknown_port_no_hints_stays_http():
    """No PSE, no Q=, non-standard port → defaults to http (parser
    was HTTP-first before the fix; keep that behaviour)."""
    conn = _parse("H=host,I=9080,U=user,M=/")
    assert conn.http_url.startswith("http://host:9080")
