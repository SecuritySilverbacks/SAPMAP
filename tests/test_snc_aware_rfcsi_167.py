"""Issue #167 — SNC-aware RFC_SYSTEM_INFO probe.

Phase A tests: SAPNode.snc_posture field basics.
Phase B tests: ``_tcp_reach`` helper in sapmap_scanner.

The rest of the suite (helper contract, classifier branches, GUI route
wiring, report rendering, autopwn skip) is added in later phases.
"""

import json
import socket

import pytest

import sapmap_scanner
from sapmap_models import SAPNode


SNC_POSTURE_VALUES = (
    "",
    "no_sap_signal",
    "none",
    "optional",
    "enforced_no_creds",
    "enforced_handshake_failed",
    "enforced_logon_failed",
    "reachable_auth",
)


def test_sapnode_snc_posture_default_is_empty_string():
    """A fresh SAPNode has snc_posture == '' — never classified."""
    node = SAPNode(sid="TST")
    assert node.snc_posture == ""


@pytest.mark.parametrize("posture", SNC_POSTURE_VALUES)
def test_sapnode_snc_posture_roundtrip_through_json(posture):
    """Every verdict value survives the .sapmap JSON round-trip."""
    original = SAPNode(sid="S4H", snc_posture=posture)
    restored = SAPNode.from_dict(json.loads(json.dumps(original.to_dict())))
    assert restored.snc_posture == posture


def test_sapnode_snc_posture_from_dict_defaults_to_empty_when_missing():
    """Older .sapmap files (no snc_posture key) still load cleanly."""
    legacy_dict = {"sid": "NPL"}            # no snc_posture key at all
    loaded = SAPNode.from_dict(legacy_dict)
    assert loaded.snc_posture == ""


def test_sapnode_snc_posture_appears_in_to_dict_output():
    """to_dict always emits snc_posture — consumers can rely on the key."""
    node = SAPNode(sid="TST")               # default posture
    d = node.to_dict()
    assert "snc_posture" in d
    assert d["snc_posture"] == ""


# ------------------------------------------------------------------
# Phase B — _tcp_reach helper
# ------------------------------------------------------------------


def test_tcp_reach_direct_returns_true_when_socket_connects(monkeypatch):
    """Plain-socket path returns True on a successful create_connection."""
    class _FakeSock:
        def close(self):
            pass

    captured = {}

    def _fake_create_connection(address, timeout=None):
        captured["address"] = address
        captured["timeout"] = timeout
        return _FakeSock()

    monkeypatch.setattr(sapmap_scanner.socket, "create_connection",
                        _fake_create_connection)
    assert sapmap_scanner._tcp_reach("10.0.0.1", 4800, timeout=3.0) is True
    assert captured["address"] == ("10.0.0.1", 4800)


def test_tcp_reach_direct_returns_false_on_connect_refused(monkeypatch):
    """Plain-socket path returns False on ConnectionRefusedError."""
    def _fake_create_connection(address, timeout=None):
        raise ConnectionRefusedError("ECONNREFUSED")

    monkeypatch.setattr(sapmap_scanner.socket, "create_connection",
                        _fake_create_connection)
    assert sapmap_scanner._tcp_reach("10.0.0.1", 4800, timeout=3.0) is False


def test_tcp_reach_direct_returns_false_on_timeout(monkeypatch):
    """Plain-socket path returns False on socket.timeout, never raises."""
    def _fake_create_connection(address, timeout=None):
        raise socket.timeout("timed out")

    monkeypatch.setattr(sapmap_scanner.socket, "create_connection",
                        _fake_create_connection)
    assert sapmap_scanner._tcp_reach("10.0.0.1", 4800, timeout=3.0) is False


def test_tcp_reach_clamps_timeout_to_4_seconds(monkeypatch):
    """A 60s caller timeout is capped at 4s — _tcp_reach is a diagnostic
    probe, not the main scan budget."""
    captured = {}

    class _FakeSock:
        def close(self):
            pass

    def _fake_create_connection(address, timeout=None):
        captured["timeout"] = timeout
        return _FakeSock()

    monkeypatch.setattr(sapmap_scanner.socket, "create_connection",
                        _fake_create_connection)
    sapmap_scanner._tcp_reach("10.0.0.1", 4800, timeout=60.0)
    assert captured["timeout"] == 4.0


def test_tcp_reach_tunnels_through_saprouter_when_set(monkeypatch):
    """When saprouter is set, the probe goes via connect_through_saprouter —
    NOT a bare socket (which would always fail on a router'd target)."""
    captured = {"direct_calls": 0}

    class _FakeSock:
        def close(self):
            pass

    def _fake_create_connection(address, timeout=None):
        captured["direct_calls"] += 1
        return _FakeSock()

    def _fake_build_route(saprouter, host, port):
        captured["route_args"] = (saprouter, host, port)
        return "route-token"

    def _fake_connect_through_saprouter(route, timeout):
        captured["router_call"] = (route, timeout)
        return _FakeSock()

    import sap_saprouter
    monkeypatch.setattr(sapmap_scanner.socket, "create_connection",
                        _fake_create_connection)
    monkeypatch.setattr(sap_saprouter, "build_route_for_port",
                        _fake_build_route)
    monkeypatch.setattr(sap_saprouter, "connect_through_saprouter",
                        _fake_connect_through_saprouter)

    ok = sapmap_scanner._tcp_reach("10.0.0.1", 4800, timeout=3.0,
                                   saprouter="10.0.0.254:3299")
    assert ok is True
    assert captured["route_args"] == ("10.0.0.254:3299", "10.0.0.1", 4800)
    assert captured["router_call"] == ("route-token", 3.0)
    assert captured["direct_calls"] == 0  # Direct path not used.


def test_tcp_reach_saprouter_path_returns_false_on_failure(monkeypatch):
    """SAProuter denial / NI_RTERR → False, never raises."""
    def _fake_build_route(saprouter, host, port):
        return "route-token"

    def _fake_connect_through_saprouter(route, timeout):
        raise OSError("NI_RTERR: route denied")

    import sap_saprouter
    monkeypatch.setattr(sap_saprouter, "build_route_for_port",
                        _fake_build_route)
    monkeypatch.setattr(sap_saprouter, "connect_through_saprouter",
                        _fake_connect_through_saprouter)

    ok = sapmap_scanner._tcp_reach("10.0.0.1", 4800, timeout=3.0,
                                   saprouter="10.0.0.254:3299")
    assert ok is False


def test_tcp_reach_never_raises_on_arbitrary_exception(monkeypatch):
    """Even a nonsense exception type from the underlying stack is caught."""
    def _fake_create_connection(address, timeout=None):
        raise RuntimeError("boom")

    monkeypatch.setattr(sapmap_scanner.socket, "create_connection",
                        _fake_create_connection)
    assert sapmap_scanner._tcp_reach("10.0.0.1", 4800, timeout=3.0) is False
