"""Tests for issue #90 — a partial/deep scan must not turn a Web Dispatcher
into a fictitious SAPROUTER.

Root cause: port 3299 being TCP-open was trusted as a SAProuter with no
protocol handshake (unlike dispatcher/gateway/WD, which are verified), and
the fast-scan stack decision had no ICM-only branch, so a WD fingerprinted
as SAP ICM (tagged icm_http, not wd_http) fell through WEB_DISPATCHER into
SAPROUTER.

Fixes verified here:
  * _verify_saprouter — a host is SAPROUTER only on a positive NI handshake.
  * _build_nodes_from_fast_scan — an ICM-only host classifies WEB_DISPATCHER,
    not SAPROUTER; a genuine saprouter label still classifies SAPROUTER.
  * fast_scan_host drops an unconfirmed saprouter port (source-pinned — the
    verify-drop runs inside the live Pass-1 scan).
  * _sapology_system_to_node — a copied SAPROUTER verdict is demoted when the
    NI handshake fails (defense-in-depth against an older SAPology).
"""
from __future__ import annotations

import inspect
import socket as _socket
import types

import pytest

import modules  # noqa: F401 — registers package paths

import sapmap_scanner


# ===========================================================================
# _verify_saprouter — the NI handshake gate
# ===========================================================================

class _FakeSock:
    def __init__(self, resp):
        self._resp = resp
    def settimeout(self, *a):
        pass
    def connect(self, *a):
        pass
    def sendall(self, *a):
        pass
    def recv(self, n):
        r, self._resp = self._resp, b""
        return r
    def close(self):
        pass


def _patch_socket(monkeypatch, resp=None, raise_exc=None):
    def ctor(*a, **k):
        if raise_exc:
            raise raise_exc
        return _FakeSock(resp if resp is not None else b"")
    monkeypatch.setattr(sapmap_scanner.socket, "socket", ctor)


def test_verify_saprouter_true_on_banner(monkeypatch):
    _patch_socket(monkeypatch, resp=b"\x00\x00\x00\x2aSAProuter 40.4 on 'rtr01'")
    assert sapmap_scanner._verify_saprouter("10.0.0.1", 3299, timeout=1) is True


def test_verify_saprouter_false_on_web_server(monkeypatch):
    # A Web Dispatcher / web server on 3299 answers HTTP, not the NI banner.
    _patch_socket(monkeypatch, resp=b"HTTP/1.1 200 OK\r\nServer: SAP Web Dispatcher\r\n")
    assert sapmap_scanner._verify_saprouter("10.0.0.1", 3299, timeout=1) is False


def test_verify_saprouter_false_on_empty(monkeypatch):
    _patch_socket(monkeypatch, resp=b"")
    assert sapmap_scanner._verify_saprouter("10.0.0.1", 3299, timeout=1) is False


def test_verify_saprouter_false_on_connect_refused(monkeypatch):
    _patch_socket(monkeypatch, raise_exc=ConnectionRefusedError())
    assert sapmap_scanner._verify_saprouter("10.0.0.1", 3299, timeout=1) is False


def test_verify_saprouter_falls_back_when_primary_probe_resets(monkeypatch):
    """REGRESSION (adversarial review, HIGH): a real SAProuter that RESETS
    the raw null probe but answers the NI_ROUTE fallback must still be
    confirmed — a primary-probe exception must NOT abort before the
    fallback is tried."""
    calls = {"n": 0}

    class _ResetThenBanner:
        def __init__(self, idx):
            self.idx, self._sent = idx, False
        def settimeout(self, *a):
            pass
        def connect(self, *a):
            pass
        def sendall(self, *a):
            pass
        def recv(self, n):
            if self.idx == 0:                      # 1st probe: reset
                raise ConnectionResetError("reset on null probe")
            if self._sent:                         # 2nd probe: NI_ROUTE banner
                return b""
            self._sent = True
            return b"\x00\x00\x00\xe2NI_RTERR ... SAProuter 40.4"
        def close(self):
            pass

    def ctor(*a, **k):
        idx = calls["n"]
        calls["n"] += 1
        return _ResetThenBanner(idx)

    monkeypatch.setattr(sapmap_scanner.socket, "socket", ctor)
    assert sapmap_scanner._verify_saprouter("10.0.0.1", 3299, timeout=1) is True
    assert calls["n"] == 2, "both probes must be attempted (fallback not skipped)"


# ===========================================================================
# _build_nodes_from_fast_scan — classification precedence
# ===========================================================================

def _build(scan_result):
    return sapmap_scanner._build_nodes_from_fast_scan(scan_result, timeout=0.1)


def test_icm_only_host_classifies_web_dispatcher_not_saprouter():
    """REGRESSION: an ICM-only host (icm_http, no dispatcher/wd) must be
    WEB_DISPATCHER.  Before the fix it fell through to 'SAP' (or, with 3299
    also open, to SAPROUTER)."""
    nodes = _build({"host": "10.0.0.6",
                    "open_ports": {8090: {"service": "icm_http",
                                          "instance_nr": "90"}}})
    assert len(nodes) == 1
    assert nodes[0].system_type == "WEB_DISPATCHER", (
        f"icm-only host should be WEB_DISPATCHER, got {nodes[0].system_type}")


def test_icm_port_not_demoted_to_saprouter_when_3299_present():
    """A WD's ICM instance and a (separate) 3299 must not merge into one
    SAPROUTER system — the ICM node stays WEB_DISPATCHER."""
    nodes = _build({"host": "10.0.0.7",
                    "open_ports": {8090: {"service": "icm_http",
                                          "instance_nr": "90"},
                                   3299: {"service": "saprouter",
                                          "instance_nr": "99"}}})
    wd = [n for n in nodes if n.system_type == "WEB_DISPATCHER"]
    assert len(wd) == 1 and 8090 in wd[0].instances[0].ports


def test_hana_host_with_icm_port_stays_hana():
    """REGRESSION (adversarial review, LOW): a HANA host that also exposes an
    ICM HTTP port must stay HANA — the has_icm_only branch sits AFTER
    has_hana_port, so HANA wins."""
    nodes = _build({"host": "10.0.0.9",
                    "open_ports": {8090: {"service": "icm_http",
                                          "instance_nr": "90"},
                                   39013: {"service": "hana_sql",
                                           "instance_nr": "90"}}})
    assert len(nodes) == 1
    assert nodes[0].system_type == "HANA", (
        f"HANA host with an ICM port should stay HANA, got "
        f"{nodes[0].system_type}")


def test_genuine_saprouter_label_still_classifies_saprouter():
    """Guard the real-router path: when a saprouter service survives
    verification, the builder must still classify SAPROUTER."""
    nodes = _build({"host": "10.0.0.5",
                    "open_ports": {3299: {"service": "saprouter",
                                          "instance_nr": "99"}}})
    assert len(nodes) == 1
    assert nodes[0].system_type == "SAPROUTER"


# ===========================================================================
# Source pins — the fast_scan_host verify-drop (runs inside live Pass-1 scan,
# same hard-to-reach constraint the dpmon tests source-pin for)
# ===========================================================================

def test_fast_scan_host_gates_saprouter_on_handshake():
    src = inspect.getsource(sapmap_scanner)
    # the saprouter verify-drop block exists and mirrors the DIAG drop
    assert "_verify_saprouter(host, port" in src
    assert "dropping saprouter label" in src
    # the stack decision has an ICM-only branch, placed AFTER has_hana_port
    # so a HANA host that also exposes an ICM port stays HANA (the handshake
    # gate, not branch order, keeps a WD out of SAPROUTER).
    hana = src.index("elif has_hana_port:")
    icm = src.index("elif has_icm_only:")
    assert hana < icm, "has_hana_port must precede has_icm_only (HANA wins)"


# ===========================================================================
# _sapology_system_to_node — deep-scan handoff re-verification (Part 3)
# ===========================================================================

def _fake_sapology_system(system_type="SAPROUTER", router_port=3299):
    inst = types.SimpleNamespace(
        instance_nr="99", ip="10.0.0.9",
        ports={router_port: "saprouter"},
        services={"saprouter": {"port": router_port}},
        info={}, findings=[])
    return types.SimpleNamespace(
        sid="UNKNOWN", system_type=system_type, hostname="", os_type="Linux",
        db_type="", kernel="793", sap_release="", clients=[],
        instances=[inst])


def test_sapology_handoff_demotes_unconfirmed_saprouter(monkeypatch):
    monkeypatch.setattr(sapmap_scanner, "_verify_saprouter",
                        lambda *a, **k: False)
    node = sapmap_scanner._sapology_system_to_node(
        _fake_sapology_system("SAPROUTER"), "10.0.0.9")
    assert node.system_type == "SAP", (
        "an unconfirmed SAPROUTER from SAPology must be demoted")


def test_sapology_handoff_keeps_confirmed_saprouter(monkeypatch):
    monkeypatch.setattr(sapmap_scanner, "_verify_saprouter",
                        lambda *a, **k: True)
    node = sapmap_scanner._sapology_system_to_node(
        _fake_sapology_system("SAPROUTER"), "10.0.0.9")
    assert node.system_type == "SAPROUTER"


def test_sapology_handoff_leaves_non_saprouter_untouched(monkeypatch):
    # A non-SAPROUTER verdict must not trigger the handshake at all.
    called = {"n": 0}
    def _spy(*a, **k):
        called["n"] += 1
        return False
    monkeypatch.setattr(sapmap_scanner, "_verify_saprouter", _spy)
    node = sapmap_scanner._sapology_system_to_node(
        _fake_sapology_system("WEB_DISPATCHER"), "10.0.0.9")
    assert node.system_type == "WEB_DISPATCHER"
    assert called["n"] == 0
