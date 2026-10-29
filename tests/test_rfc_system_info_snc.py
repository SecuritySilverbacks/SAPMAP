#!/usr/bin/env python3
"""Tests for sapmap_rfc.get_rfc_system_info — the authenticated, SNC-aware
RFC_SYSTEM_INFO path (issue #167).

A truly anonymous RFC_SYSTEM_INFO is impossible over SNC (the SNC transport
comes up but the application-layer logon still runs), so this authenticated
helper is how SAPMAP reads system info on SNC-secured systems.  Verified live
against S/4HANA (kernel 793) over SNC on port 4800; these unit tests pin the
SNC gating and field extraction with a fake backend.
"""
from __future__ import annotations

import os

import pytest

import modules  # noqa: F401 — registers package paths
import sapmap_rfc
from sapmap_models import SAPNode, Credentials


_RFCSI_EXPORT = {
    "RFCSYSID": "S4H ",
    "RFCHOST2": "s4hanade",
    "RFCHOST": "ignored-when-host2-present",
    "RFCOPSYS": "Linux",
    "RFCDBSYS": "SYB",
    "RFCKERNRL": "793",
    "RFCSAPRL": "755",
    "RFCIPADDR": "192.168.2.209",
}


class _FakeConn:
    """Stand-in for the active RFCConnection backend."""
    last_params: dict = {}

    def __init__(self, sdk_path=None, **params):
        _FakeConn.last_params = dict(params)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def call(self, fm, *args, **kw):
        assert fm == "RFC_SYSTEM_INFO"
        return {"RFCSI_EXPORT": dict(_RFCSI_EXPORT)}


class _RaisingConn(_FakeConn):
    def call(self, fm, *args, **kw):
        raise RuntimeError("logon failed: Name or password is incorrect")


@pytest.fixture(autouse=True)
def _reset_snc():
    """Each test starts with a clean global SNC posture, and the process
    SECUDIR env is restored afterward (``_get_connection`` mirrors the
    configured secudir into os.environ when SNC is active)."""
    _saved_secudir = os.environ.get("SECUDIR")
    sapmap_rfc.set_snc_config(secudir="", sapcryptolib="", identity="")
    yield
    sapmap_rfc.set_snc_config(secudir="", sapcryptolib="", identity="")
    if _saved_secudir is None:
        os.environ.pop("SECUDIR", None)
    else:
        os.environ["SECUDIR"] = _saved_secudir


def _node(snc_name=""):
    return SAPNode(sid="S4H", ip="192.168.2.209", snc_partnername=snc_name)


def _creds():
    return Credentials(username="SAPMAP00", password="pw",
                       client="001", instance_nr="00")


def test_fields_extracted(monkeypatch):
    monkeypatch.setattr(sapmap_rfc, "_get_rfc_backend", lambda: _FakeConn)
    out = sapmap_rfc.get_rfc_system_info(_node(), _creds())
    assert out["error"] == ""
    assert out["sid"] == "S4H"                 # trimmed
    assert out["hostname"] == "s4hanade"       # RFCHOST2 preferred over RFCHOST
    assert out["os_type"] == "Linux"
    assert out["db_type"] == "SYB"
    assert out["kernel"] == "793"
    assert out["sap_release"] == "755"
    assert out["ip"] == "192.168.2.209"


def test_plain_when_no_snc_posture(monkeypatch):
    """No SNC config + no SNC name → snc=False, source=rfcsi_auth, and the
    connection params carry NO snc_lib."""
    monkeypatch.setattr(sapmap_rfc, "_get_rfc_backend", lambda: _FakeConn)
    out = sapmap_rfc.get_rfc_system_info(_node(), _creds())
    assert out["snc"] is False
    assert out["source"] == "rfcsi_auth"
    assert "snc_lib" not in _FakeConn.last_params


def test_snc_negotiated_when_posture_and_name_set(monkeypatch):
    """Full SNC posture + node SNC name → snc=True, source=rfcsi_snc_auth,
    and the connection params carry the SNC knobs (snc_lib drives saprfclib
    to the 4800 port)."""
    monkeypatch.setattr(sapmap_rfc, "_get_rfc_backend", lambda: _FakeConn)
    sapmap_rfc.set_snc_config(secudir="/sec",
                              sapcryptolib="/lib/libsapcrypto.so",
                              identity="p:CN=SAPMAP, O=lab")
    out = sapmap_rfc.get_rfc_system_info(
        _node("p:CN=S4H, OU=I0021320685, O=SAP Trust Community, C=DE"),
        _creds())
    assert out["snc"] is True
    assert out["source"] == "rfcsi_snc_auth"
    p = _FakeConn.last_params
    assert p.get("snc_lib") == "/lib/libsapcrypto.so"
    assert p.get("snc_myname") == "p:CN=SAPMAP, O=lab"
    assert p.get("snc_partnername", "").startswith("p:CN=S4H")


def test_no_snc_when_posture_set_but_no_node_name(monkeypatch):
    """Posture configured but the node has no SNC name → plain RFC (the gate
    requires BOTH), so no snc_lib is added."""
    monkeypatch.setattr(sapmap_rfc, "_get_rfc_backend", lambda: _FakeConn)
    sapmap_rfc.set_snc_config(secudir="/sec",
                              sapcryptolib="/lib/libsapcrypto.so",
                              identity="p:CN=SAPMAP, O=lab")
    out = sapmap_rfc.get_rfc_system_info(_node(""), _creds())
    assert out["snc"] is False
    assert out["source"] == "rfcsi_auth"
    assert "snc_lib" not in _FakeConn.last_params


def test_error_is_captured(monkeypatch):
    """A logon/connect failure is reported in 'error' with all data fields
    left blank — never raises."""
    monkeypatch.setattr(sapmap_rfc, "_get_rfc_backend", lambda: _RaisingConn)
    out = sapmap_rfc.get_rfc_system_info(_node(), _creds())
    assert out["error"]
    assert out["sid"] == "" and out["kernel"] == ""
    assert out["source"] == ""
