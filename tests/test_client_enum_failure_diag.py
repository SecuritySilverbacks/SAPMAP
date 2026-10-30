#!/usr/bin/env python3
"""Issue #193 — client enumeration must explain itself when it fails.

The reporter saw ``No clients found (status=ok, probed=1000, errors=1000)``:
the DIAG init handshake worked, but every per-client logon probe errored, and
the tool reported neither a reason nor a usable client list.  ``probe_client``
already computes a precise ``detail`` per probe — these tests pin the behaviour
that turns that detail into an operator-facing diagnosis and a safe fallback:

  1. Early-abort — if the init works but 0/5 calibration logons answer, bail
     out before probing 1000 clients, with status=error + a cause.
  2. Backstop — if the full run errors on (nearly) every client and finds
     nothing, mark status=error, record the per-probe breakdown, and surface
     the dominant reason.
  3. Fallback — the scanner wrapper returns the guaranteed client "000" and
     prints the breakdown when enumeration fails this way.
  4. No false positive — a genuine run that gets definitive "not available"
     answers (errors==0) is left as a normal status=ok empty result.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "discovery"))

import sap_client_enum  # noqa: E402
import sapmap_scanner  # noqa: E402


class _Sock:
    def close(self):
        pass


@pytest.fixture
def offline_init(monkeypatch):
    """Stub the DIAG network layer so the init verification passes."""
    monkeypatch.setattr(sap_client_enum, "_diag_connect",
                        lambda *a, **k: _Sock())
    monkeypatch.setattr(sap_client_enum, "ni_send", lambda *a, **k: None)
    # 60 bytes >= the 50-byte init-verification threshold.
    monkeypatch.setattr(sap_client_enum, "ni_recv", lambda *a, **k: b"\x00" * 60)
    monkeypatch.setattr(sap_client_enum, "build_diag_init", lambda *a, **k: b"")


def _redir(result):
    """Build a _check_client_redirection stub returning a fixed 4-tuple."""
    return lambda *a, **k: result


# ---------------------------------------------------------------------------
# 1. Early-abort: init OK but zero calibration logons answered
# ---------------------------------------------------------------------------

def test_zero_calibration_response_aborts_early(offline_init, monkeypatch):
    # calib_succeeded = 0 -> dispatcher answers init but drops every logon.
    monkeypatch.setattr(sap_client_enum, "_check_client_redirection",
                        _redir((False, None, None, 0)))
    # probe_client must NOT be called once we decide to fail fast.
    called = {"n": 0}

    def _boom(*a, **k):
        called["n"] += 1
        return ("000", None, "no_login_response")

    monkeypatch.setattr(sap_client_enum, "probe_client", _boom)

    res = sap_client_enum.enumerate_clients("10.0.0.1", 3200,
                                            start_client=0, end_client=999)

    assert res["status"] == "error"
    assert res["clients"] == []
    assert "0/5 calibration logons" in res["error"]
    # No full 1000-probe run happened.
    assert called["n"] == 0
    assert res["probed"] == 5


# ---------------------------------------------------------------------------
# 2. Backstop: calibration answered, but the full run errors on everything
# ---------------------------------------------------------------------------

def test_all_probes_error_sets_status_error_and_reason(offline_init, monkeypatch):
    # calib_succeeded = 3 (>=1) so the early-abort does not fire; the full
    # probe loop runs and every client errors.
    monkeypatch.setattr(sap_client_enum, "_check_client_redirection",
                        _redir((False, None, None, 3)))
    monkeypatch.setattr(
        sap_client_enum, "probe_client",
        lambda h, p, c, *a, **k: ("%03d" % c, None, "no_login_response"))

    res = sap_client_enum.enumerate_clients("10.0.0.1", 3200,
                                            start_client=0, end_client=4)

    assert res["status"] == "error"
    assert res["clients"] == []
    assert res["probed"] == 5 and res["errors"] == 5
    assert "no_login_response" in res["error"]
    # The dominant-reason hint is included.
    assert "SNC" in res["error"]
    assert res["error_reasons"] == {"no_login_response": 5}


def test_error_reasons_breakdown_records_mixed_codes(offline_init, monkeypatch):
    monkeypatch.setattr(sap_client_enum, "_check_client_redirection",
                        _redir((False, None, None, 3)))

    # Alternate two failure codes across clients 0..3.
    def _mixed(h, p, c, *a, **k):
        detail = "no_login_response" if c % 2 == 0 else "timeout"
        return ("%03d" % c, None, detail)

    monkeypatch.setattr(sap_client_enum, "probe_client", _mixed)

    res = sap_client_enum.enumerate_clients("10.0.0.1", 3200,
                                            start_client=0, end_client=3)

    assert res["status"] == "error"
    assert res["error_reasons"] == {"no_login_response": 2, "timeout": 2}


# ---------------------------------------------------------------------------
# 3. Scanner wrapper: fall back to client 000 and print the breakdown
# ---------------------------------------------------------------------------

def test_scanner_wrapper_falls_back_to_000_and_prints_breakdown(monkeypatch, capsys):
    monkeypatch.setattr(sapmap_scanner, "enumerate_clients", lambda *a, **k: {
        "clients": [],
        "status": "error",
        "probed": 1000,
        "errors": 1000,
        "error": "client enumeration failed on h:3200 — 1000/1000 ...",
        "error_reasons": {"no_login_response": 1000},
    })

    clients = sapmap_scanner.enumerate_system_clients("host", 3200,
                                                      sid_hint="NPL")

    assert clients == ["000"]
    out = capsys.readouterr().out
    assert "No clients found (status=error" in out
    assert "reason:" in out
    assert "probe failures: no_login_response×1000" in out
    assert "falling back to guaranteed client '000'" in out


# ---------------------------------------------------------------------------
# 4. No false positive: definitive "not available" answers are not an error
# ---------------------------------------------------------------------------

def test_genuine_not_available_run_is_not_flagged_error(offline_init, monkeypatch):
    monkeypatch.setattr(sap_client_enum, "_check_client_redirection",
                        _redir((False, None, None, 3)))
    # Every probe returns a definitive "not available" (available is False),
    # which is a real answer, not an error.
    monkeypatch.setattr(
        sap_client_enum, "probe_client",
        lambda h, p, c, *a, **k: ("%03d" % c, False, "not_available"))

    res = sap_client_enum.enumerate_clients("10.0.0.1", 3200,
                                            start_client=0, end_client=4)

    assert res["status"] == "ok"
    assert res["errors"] == 0
    assert "error" not in res
    assert "error_reasons" not in res
    assert res["clients"] == []


def test_found_clients_keep_status_ok(offline_init, monkeypatch):
    monkeypatch.setattr(sap_client_enum, "_check_client_redirection",
                        _redir((False, None, None, 3)))
    # Client 000 available, the rest not available -> a healthy run.
    monkeypatch.setattr(
        sap_client_enum, "probe_client",
        lambda h, p, c, *a, **k: (("%03d" % c, True, "available") if c == 0
                                  else ("%03d" % c, False, "not_available")))

    res = sap_client_enum.enumerate_clients("10.0.0.1", 3200,
                                            start_client=0, end_client=4)

    assert res["status"] == "ok"
    assert res["clients"] == ["000"]
    assert "error" not in res
