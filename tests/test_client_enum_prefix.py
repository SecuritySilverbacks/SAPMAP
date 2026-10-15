#!/usr/bin/env python3
"""Client-enumeration log lines must identify the target system.

When SAPMAP enumerates clients across several systems (often concurrently,
before the SID is known), the per-client ``Client NNN: not available`` lines
used to be bare — you couldn't tell which system each line belonged to.  They
are now prefixed with the SID when known, else ``host:port`` (the dispatcher
port disambiguates co-located SIDs on one host, e.g. 3200 vs 3202).
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "discovery"))

import sap_client_enum  # noqa: E402


class _Sock:
    def close(self):
        pass


@pytest.fixture
def offline(monkeypatch):
    """Stub the DIAG network layer so enumerate_clients runs without a socket."""
    monkeypatch.setattr(sap_client_enum, "_diag_connect",
                        lambda *a, **k: _Sock())
    monkeypatch.setattr(sap_client_enum, "ni_send", lambda *a, **k: None)
    monkeypatch.setattr(sap_client_enum, "ni_recv", lambda *a, **k: b"\x00" * 60)
    monkeypatch.setattr(sap_client_enum, "build_diag_init", lambda *a, **k: b"")
    monkeypatch.setattr(sap_client_enum, "_check_client_redirection",
                        lambda *a, **k: (False, None, None))


def _run(sid_hint, result_tuple):
    """Probe exactly client 000, returning result_tuple from probe_client."""
    return sid_hint, result_tuple


def test_client_lines_prefixed_with_host_port_when_sid_unknown(offline, monkeypatch, capsys):
    monkeypatch.setattr(sap_client_enum, "probe_client",
                        lambda *a, **k: ("000", False, ""))
    sap_client_enum.enumerate_clients(
        "10.10.1.6", 3202, start_client=0, end_client=0,
        verbose=True, sid_hint="")
    out = capsys.readouterr().out
    assert "10.10.1.6:3202: Client 000: not available" in out
    # the DIAG init line is prefixed too
    assert "10.10.1.6:3202: DIAG init OK" in out


def test_available_line_prefixed_with_host_port(offline, monkeypatch, capsys):
    monkeypatch.setattr(sap_client_enum, "probe_client",
                        lambda *a, **k: ("000", True, "available"))
    sap_client_enum.enumerate_clients(
        "10.10.1.6", 3200, start_client=0, end_client=0,
        verbose=True, sid_hint="")
    out = capsys.readouterr().out
    assert "10.10.1.6:3200: Client 000: AVAILABLE (available)" in out


def test_sid_prefix_preferred_when_known(offline, monkeypatch, capsys):
    monkeypatch.setattr(sap_client_enum, "probe_client",
                        lambda *a, **k: ("000", False, ""))
    sap_client_enum.enumerate_clients(
        "10.10.1.6", 3202, start_client=0, end_client=0,
        verbose=True, sid_hint="AE3")
    out = capsys.readouterr().out
    assert "AE3: Client 000: not available" in out
    # host:port must NOT be used once the SID is known
    assert "10.10.1.6:3202: Client 000" not in out


def test_two_colocated_instances_are_distinguishable(offline, monkeypatch, capsys):
    """The exact pain point: two SIDs on one host, SID not yet known — the
    dispatcher port in the prefix keeps their client lines apart."""
    monkeypatch.setattr(sap_client_enum, "probe_client",
                        lambda *a, **k: ("000", False, ""))
    sap_client_enum.enumerate_clients("10.10.1.6", 3200, start_client=0,
                                      end_client=0, verbose=True, sid_hint="")
    sap_client_enum.enumerate_clients("10.10.1.6", 3202, start_client=0,
                                      end_client=0, verbose=True, sid_hint="")
    out = capsys.readouterr().out
    assert "10.10.1.6:3200: Client 000: not available" in out
    assert "10.10.1.6:3202: Client 000: not available" in out
