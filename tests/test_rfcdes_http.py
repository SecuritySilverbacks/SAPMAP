"""RFCDES Type-G / Type-H parsing.

retrieve_rfcs originally only pulled Type-3 (classic RFC) destinations
from RFCDES.  After extending the filter to include Type-G (HTTP-to-
external) and Type-H (HTTP-to-ABAP), the new options parser
synthesises an http_url + sets conn_type='http' so the on-prem -> BTP
harvester can mine these rows for BTP-bound credentials.
"""
from __future__ import annotations

import modules  # noqa: F401  (registers package paths)
from sapmap_models import SAPNode
from sapmap_rfc import (
    _parse_rfcdes_http_options, _parse_rfcdes_options,
    _build_rfcdes_conn, _RFCDES_TYPE_FILTER, RFCConn,
)


# ---- _RFCDES_TYPE_FILTER ----------------------------------------------

def test_filter_covers_type_3_g_h():
    """Filter must accept all three destination types we now read."""
    assert "RFCTYPE = '3'" in _RFCDES_TYPE_FILTER
    assert "RFCTYPE = 'G'" in _RFCDES_TYPE_FILTER
    assert "RFCTYPE = 'H'" in _RFCDES_TYPE_FILTER
    # And no other types — we don't want, say, Type-T edges leaking
    # into the HTTP parser path.
    assert "'T'" not in _RFCDES_TYPE_FILTER
    assert "'L'" not in _RFCDES_TYPE_FILTER


# ---- _parse_rfcdes_http_options --------------------------------------

def _new_conn():
    return RFCConn(source_sid="S4P", source_host="s4p",
                    destination_name="X")


def test_http_options_https_with_explicit_port_and_path():
    """Common Type-G shape: H=host,S=port,M=path,Q=Y,U=user.
    Q=Y means the destination uses TLS."""
    c = _new_conn()
    _parse_rfcdes_http_options(
        c, "H=foo.example.com,S=8443,M=/sap/bc/srt/rfc,Q=Y,U=svc,T=%_PWD")
    assert c.conn_type == "http"
    assert c.http_url == "https://foo.example.com:8443/sap/bc/srt/rfc"
    assert c.rfc_user == "svc"
    assert c.http_auth_type == "BASICAUTHENTICATION"


def test_http_options_handles_btp_authentication_url():
    """The whole point of this work — Type-G destinations to BTP UAA.
    A standard 443/HTTPS path should land on the canonical
    https://<host>/oauth/token URL the BTP harvester filters on."""
    c = _new_conn()
    _parse_rfcdes_http_options(
        c, "H=researchlab-yehctg7m.authentication.eu10-004.hana.ondemand.com,"
           "S=443,M=/oauth/token,Q=Y,U=sb-clone!b1234,T=%_PWD")
    assert c.http_url == ("https://researchlab-yehctg7m.authentication."
                           "eu10-004.hana.ondemand.com/oauth/token")
    assert c.rfc_user == "sb-clone!b1234"


def test_http_options_skips_default_port_in_url():
    """When the destination is on the standard TLS port, dropping the
    explicit :443 keeps the URL cleaner — and matches what the BTP
    harvester's hostname matcher already expects."""
    c = _new_conn()
    _parse_rfcdes_http_options(
        c, "H=auth.eu10.hana.ondemand.com,S=443,M=/oauth/token,Q=Y,U=u")
    assert c.http_url == ("https://auth.eu10.hana.ondemand.com/oauth/token")


def test_http_options_plain_http_no_q_flag():
    """No Q= and no scheme hint ⇒ default to http://."""
    c = _new_conn()
    _parse_rfcdes_http_options(c, "H=internal,S=8080,M=/app,U=alice")
    assert c.http_url == "http://internal:8080/app"


def test_http_options_j_field_is_assertion_ticket_not_url():
    """Regression pin for the parser rewrite (2026-07-09).

    An earlier iteration of the parser had a speculative branch that
    treated ``J=https://…`` as a full target URL.  The RFCDES2RFCDISPLAY
    ABAP FM the operator shared showed that assumption was wrong: on
    G/H rows ``J=`` is the "Send Assertion Ticket for Dedicated Target
    System" flag (SM59 → Logon & Security), and its value is not a
    URL at all.  Kernels that actually use assertion tickets pair J=
    with ``n=<sysid>`` and ``p=<client>``.

    The URL must be assembled from H+I/S+M+N verbatim; when H= is
    absent the URL simply has no host (empty).  Auth type flips to
    SSO2 because J= was present.
    """
    c = _new_conn()
    _parse_rfcdes_http_options(
        c, "H=abap.target.example,I=443,J=X,n=SID,p=100,T=N,U=u")
    assert c.http_url == "https://abap.target.example"
    assert c.http_auth_type == "SSO2"


def test_http_options_path_without_leading_slash_gets_normalised():
    """SM59 sometimes stores paths without a leading slash (M=foo).
    Resulting URL must still be a valid URI."""
    c = _new_conn()
    _parse_rfcdes_http_options(
        c, "H=h.example,S=443,M=sap/bc,Q=Y,U=u")
    assert c.http_url == "https://h.example/sap/bc"


def test_http_options_three_digit_path_treated_as_sap_client():
    """When M= is a bare 3-digit number with no slashes, SM59 was
    almost certainly using it to carry the SAP client (Mandant), not
    a real URL path — http://host/001 wouldn't route to any ICF
    service anyway.  Promote it to conn.client; URL must not carry it."""
    c = _new_conn()
    _parse_rfcdes_http_options(
        c, "H=192.168.2.29,M=001,U=SAPADM,T=%_PWD")
    assert c.client == "001"
    # /001 must not leak into the URL — would cause a 404 on probe
    assert c.http_url == "http://192.168.2.29"


def test_http_options_short_client_padded_to_three_digits():
    """SAP clients are always 3 digits — operators sometimes type
    just '1' or '10' in SM59 and the kernel pads.  Mirror that
    so the SOAP request's sap-client query param is well-formed."""
    c = _new_conn()
    _parse_rfcdes_http_options(c, "H=h,M=1,U=u")
    assert c.client == "001"


def test_http_options_d_field_takes_precedence_for_client():
    """Some kernels store the client in a dedicated D= option.  When
    both D= and a digit-looking M= are present, D= wins — it's the
    documented field for client, M= as client is the fallback heuristic."""
    c = _new_conn()
    _parse_rfcdes_http_options(
        c, "H=h,M=200,D=100,U=u")
    assert c.client == "100"
    # M=200 is then treated as a real path, not a client
    assert c.http_url == "http://h/200"


def test_http_options_non_digit_path_does_not_set_client():
    """Real URL paths must NOT be interpreted as client.  Only bare
    3-digit M= values trigger the client heuristic."""
    c = _new_conn()
    _parse_rfcdes_http_options(
        c, "H=h,M=/sap/bc/srt/rfc,U=u")
    assert c.client == ""   # untouched
    assert c.http_url == "http://h/sap/bc/srt/rfc"


# ---- _build_rfcdes_conn dispatch -------------------------------------

def test_dispatch_uses_http_parser_for_type_g():
    """Sanity check: rows tagged Type-G end up with conn_type='http'
    and a synthesised http_url, not the Type-3 fields."""
    node = SAPNode(sid="S4P", system_type="ABAP",
                    hostname="s4p", ip="10.0.0.1")
    c = _build_rfcdes_conn(
        node, "BTP_OAUTH", "G",
        "H=auth.eu10.hana.ondemand.com,S=443,M=/oauth/token,Q=Y,U=svc,T=%_PWD")
    assert c.conn_type == "http"
    assert "/oauth/token" in c.http_url
    assert c.target_host == ""   # Type-3 field, must stay empty
    assert c.rfc_user == "svc"


def test_dispatch_uses_http_parser_for_type_h():
    """Type-H is HTTP-to-ABAP; same parser path as Type-G."""
    node = SAPNode(sid="S4P", system_type="ABAP",
                    hostname="s4p", ip="10.0.0.1")
    c = _build_rfcdes_conn(
        node, "ICF_PEER", "H",
        "H=peer.corp,S=8000,M=/sap/bc/icf,Q=Y,U=ICF_USER,T=%_PWD")
    assert c.conn_type == "http"
    assert c.http_url == "https://peer.corp:8000/sap/bc/icf"


def test_dispatch_keeps_type_3_parser_for_classic_rfc():
    """Existing Type-3 path must keep its current shape — we set
    target_host / target_instance_nr / client / rfc_user, NOT
    http_url."""
    node = SAPNode(sid="S4P", system_type="ABAP",
                    hostname="s4p", ip="10.0.0.1")
    c = _build_rfcdes_conn(
        node, "PRD_PROD", "3",
        "H=prdhost,S=00,M=001,U=joris,T=%_PWD")
    assert c.conn_type == "rfc"
    assert c.target_host == "prdhost"
    assert c.target_instance_nr == "00"
    assert c.client == "001"
    assert c.rfc_user == "joris"
    assert c.http_url == ""


# ---- harvester integration -------------------------------------------

def test_harvester_picks_up_type_g_btp_destination_after_capture():
    """The whole point: a Type-G SM59 destination pointing at BTP
    UAA, parsed from RFCDES, should be picked up by the on-prem
    BTP-credential harvester once secstore has filled in the
    cleartext password."""
    from sap_onprem_to_btp import harvest_btp_candidates
    from sapmap_models import SAPMAPState

    node = SAPNode(sid="S4P", system_type="ABAP",
                    hostname="s4p", ip="10.0.0.1")
    state = SAPMAPState()
    state.add_node(node)
    conn = _build_rfcdes_conn(
        node, "BTP_OAUTH", "G",
        "H=researchlab-yehctg7m.authentication.eu10-004.hana.ondemand.com,"
        "S=443,M=/oauth/token,Q=Y,U=sb-clone!b1234,T=%_PWD")
    # Secstore extraction would normally fill this in afterwards.
    conn.secstore_password = "theSecret"
    state.connections.append(conn)

    cands = harvest_btp_candidates(state, node)
    assert len(cands) == 1
    c = cands[0]
    assert c["client_id"] == "sb-clone!b1234"
    assert c["client_secret"] == "theSecret"
    assert "/oauth/token" in c["uaa_url"]
    assert c["region_hint"] == "eu10-004"


# ---- secstore integrate_results for HTTP dests ---------------------------

def test_integrate_results_enriches_http_connection():
    """integrate_results must set secstore_password on Type-G/H
    connections, not just Type-3."""
    from sapmap_secstore import integrate_results
    from sapmap_models import SAPMAPState

    node = SAPNode(sid="S4P", system_type="ABAP",
                    hostname="s4p", ip="10.0.0.1")
    state = SAPMAPState()
    state.add_node(node)
    conn = _build_rfcdes_conn(
        node, "MY_HTTP_DEST", "G",
        "H=java.corp,S=50001,M=/nwa,Q=Y,U=Administrator,T=%_PWD")
    state.connections.append(conn)

    results = [{"ident": "000 /RFC/MY_HTTP_DEST", "password": "Hunter2!"}]
    integrate_results(node, state, results)

    assert conn.secstore_password == "Hunter2!"


def test_integrate_results_resolves_type_h_target():
    """For a Type-H HTTP connection pointing at a known ABAP node,
    integrate_results should resolve target_sid and add credentials
    on the target node so the RFC chain can pivot through."""
    from sapmap_secstore import integrate_results
    from sapmap_models import SAPMAPState

    src = SAPNode(sid="DEV", system_type="ABAP",
                   hostname="devhost", ip="10.0.0.1")
    tgt = SAPNode(sid="PRD", system_type="ABAP",
                   hostname="prdhost", ip="10.0.0.2")
    state = SAPMAPState()
    state.add_node(src)
    state.add_node(tgt)

    conn = _build_rfcdes_conn(
        src, "PRD_ICF", "H",
        "H=prdhost,S=8000,M=/sap/bc/srt/rfc,Q=Y,U=RFC_USER,T=%_PWD")
    state.connections.append(conn)

    results = [{"ident": "000 /RFC/PRD_ICF", "password": "Secret123"}]
    integrate_results(src, state, results)

    # Connection should be enriched + resolved
    assert conn.secstore_password == "Secret123"
    assert conn.target_sid == "PRD"
    assert conn.target_host == "prdhost"

    # Credentials should be added to the target node
    assert any(c.username == "RFC_USER" and c.password == "Secret123"
               for c in tgt.credentials)


def test_integrate_results_skips_unresolvable_http_target():
    """Type-G destination pointing at an unknown host should NOT create
    spurious credentials or crash — just leave target_sid empty."""
    from sapmap_secstore import integrate_results
    from sapmap_models import SAPMAPState

    node = SAPNode(sid="S4P", system_type="ABAP",
                    hostname="s4p", ip="10.0.0.1")
    state = SAPMAPState()
    state.add_node(node)

    conn = _build_rfcdes_conn(
        node, "UNKNOWN_EXT", "G",
        "H=mystery.example.com,S=443,M=/api,Q=Y,U=svc_user,T=%_PWD")
    state.connections.append(conn)

    results = [{"ident": "000 /RFC/UNKNOWN_EXT", "password": "pw123"}]
    integrate_results(node, state, results)

    assert conn.secstore_password == "pw123"
    assert conn.target_sid == ""  # not resolved — no node matches
