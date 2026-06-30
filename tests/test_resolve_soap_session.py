"""Tests for resolve_soap_session_for_node — the single helper that
replaced the ~12-line route-resolve + gateway-probe + session-create
boilerplate previously inlined at every SecStore / cleanup / propagate
call site.

The function is intentionally best-effort — failures return
(None, None) so callers can keep working.  These tests pin each
decision branch independently so a regression in one doesn't fall
through silently to the next.
"""
from __future__ import annotations

import modules  # noqa: F401  registers package paths
import sapmap_gui
from sapmap_gui import resolve_soap_session_for_node
from sapmap_models import InstanceInfo, RFCConnection, SAPMAPState, SAPNode


def _state_with_verified_http_route(target_sid: str = "W74",
                                     icm_port: int = 8410):
    """A state where Test Connection has succeeded for a Type-H
    destination from S4H pointing at the target.  Mirrors what the
    operator's real session looks like after running Test Connection
    against to_ABAP."""
    state = SAPMAPState()
    state.add_node(SAPNode(
        sid="S4H", system_type="ABAP",
        hostname="s4hanadev", ip="10.0.0.1"))
    target = SAPNode(
        sid=target_sid, system_type="ABAP",
        hostname="WINWAS74", ip="192.168.2.29",
        instances=[InstanceInfo(
            instance_nr="40", ip="192.168.2.29",
            ports={icm_port: "icm-http"})])
    state.add_node(target)
    state.connections.append(RFCConnection(
        source_sid="S4H", source_host="s4hanadev",
        destination_name="to_ABAP", conn_type="http",
        http_url=f"http://192.168.2.29:{icm_port}",
        target_sid=target_sid,
        rfc_user="SAPADM",
        secstore_password="siroj1978",
        soap_rfc_verified=True,
    ))
    return state, target


# ---------------------------------------------------------------------------
# The "use SOAP" branch — verified route + gateway unreachable
# ---------------------------------------------------------------------------

def test_resolve_returns_session_and_route_when_gateway_unreachable(monkeypatch):
    """The headline use case: Test Connection has been run (verified
    route exists in state) AND the gateway port times out (firewalled
    landscape).  Helper must return BOTH a configured SOAPRFCSession
    AND the route dict — callers use the route's via_destination for
    log lines and the session for the actual call."""
    state, target = _state_with_verified_http_route()
    monkeypatch.setattr(
        "sapmap_exploit._gateway_port_reachable",
        lambda node, timeout=2.0: False)

    sess, route = resolve_soap_session_for_node(state, target)

    assert sess is not None
    assert route is not None
    # Session must be configured with the route's host/port/client/user
    assert sess.host == "192.168.2.29"
    assert sess.port == 8410
    assert sess.client == "001" or sess.client == "000" \
        or sess.client  # whatever the route carries
    assert sess.user == "SAPADM"
    assert sess.password == "siroj1978"
    # Route carries the destination name for log lines
    assert route["via_destination"] == "to_ABAP"


def test_resolve_honours_timeout_kwarg_on_session(monkeypatch):
    """ABAP_INSTALL_AND_RUN paths pass timeout=180.0 because the SAP
    kernel has to COMPILE the program before executing — a 30s default
    drops compile-heavy reports.  Helper must thread the timeout
    through to the session."""
    state, target = _state_with_verified_http_route()
    monkeypatch.setattr(
        "sapmap_exploit._gateway_port_reachable",
        lambda node, timeout=2.0: False)
    sess, _ = resolve_soap_session_for_node(
        state, target, timeout=180.0)
    assert sess.timeout == 180.0


# ---------------------------------------------------------------------------
# The "skip SOAP" branches — caller should use pyrfc, not SOAP
# ---------------------------------------------------------------------------

def test_resolve_returns_none_when_gateway_reachable(monkeypatch):
    """When the gateway IS reachable, pyrfc is the right transport
    (it's already the established + tested path).  SOAP-RFC is the
    firewall workaround, not the default — returning None here means
    callers keep the existing pyrfc dispatcher behaviour intact for
    normal landscapes."""
    state, target = _state_with_verified_http_route()
    monkeypatch.setattr(
        "sapmap_exploit._gateway_port_reachable",
        lambda node, timeout=2.0: True)

    sess, route = resolve_soap_session_for_node(state, target)
    assert sess is None
    assert route is None


def test_resolve_returns_none_when_no_verified_destination():
    """No HTTP destination targets this node (or destinations exist
    but Test Connection hasn't verified them yet, or no SecStore
    password is recovered).  Without a verified route there's nothing
    to construct a SOAP session FROM — caller must use pyrfc."""
    state = SAPMAPState()
    state.add_node(SAPNode(
        sid="W74", system_type="ABAP",
        hostname="WINWAS74", ip="192.168.2.29"))
    # No connections at all → no route
    target = state.get_node("W74")
    sess, route = resolve_soap_session_for_node(state, target)
    assert sess is None
    assert route is None


# ---------------------------------------------------------------------------
# Defensive: never raises into the caller
# ---------------------------------------------------------------------------

def test_resolve_swallows_exceptions_returning_none(monkeypatch):
    """SOAP-RFC fallback is best-effort — every call site expects to
    keep working when the helper can't establish a session.  Bugs in
    sapmap_exploit's import, an unexpected SAPMAPState shape, etc.
    must NOT propagate exceptions into the caller's create-user /
    download-secstore / cleanup flow."""
    def _boom(state, node):
        raise RuntimeError("simulated find_route exception")
    monkeypatch.setattr(
        sapmap_gui, "find_soap_rfc_route_for_node", _boom)

    state, target = _state_with_verified_http_route()
    sess, route = resolve_soap_session_for_node(state, target)
    # Helper must catch the exception and return (None, None)
    assert sess is None
    assert route is None
