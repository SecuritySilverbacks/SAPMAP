#!/usr/bin/env python3
"""Pins for the RFC backend auto-fallback shipped 2026-10-08.

Operator feedback: without --pure-rfc and without SAPNWRFC_HOME, the
connection test failed with:
  RFCError: SAP NW RFC SDK library (libsapnwrfc.dylib) not found

...instead of auto-falling back to the pure-Python saprfclib adapter
(which the --pure-rfc flag has used extensively for months).

Root cause: _get_rfc_backend() in sapmap_rfc.py tried to IMPORT
sap_rfc_ctypes.  That always succeeds (the module imports cleanly;
the SDK dlopen is deferred to RFCConnection.__init__), so the
auto-fallback branch that was supposed to try sap_rfc_pure on
C-SDK unavailability never fired.  The RFCError surfaced only at
connection-attempt time, past the point where the backend selection
had already committed.

Fix: added `is_sdk_loadable()` to sap_rfc_ctypes that ACTUALLY attempts
the dlopen (via _SDKLibrary.get()) and reports True/False.
Memoised per sdk_path so repeated backend selections don't thrash the
loader.  _get_rfc_backend() now consults is_sdk_loadable BEFORE
returning the C backend; on False, falls through to the pure branch
with a one-time operator-visible log message.
"""
from __future__ import annotations

import importlib
import sys

import pytest

import modules  # noqa: F401 — registers package paths


# ---------------------------------------------------------------------------
# is_sdk_loadable — the probe itself
# ---------------------------------------------------------------------------

def test_is_sdk_loadable_returns_bool():
    """Probe must return a bool, never raise.  Operator may call it
    before the SDK path is set."""
    from sap_rfc_ctypes import is_sdk_loadable
    result = is_sdk_loadable("")
    assert isinstance(result, bool), (
        f"is_sdk_loadable must return bool, got {type(result).__name__}")


def test_is_sdk_loadable_returns_false_on_bad_path(tmp_path, monkeypatch):
    """A non-existent sdk_path must probe False cleanly (no exception)."""
    import sap_rfc_ctypes as _mod
    # Reset the memoisation cache so this test is deterministic
    monkeypatch.setattr(_mod, "_SDK_LOADABLE_CACHE", {})
    # Also wipe any env var that would resolve to a REAL SDK path
    monkeypatch.delenv("SAPNWRFC_HOME", raising=False)
    bad = str(tmp_path / "does-not-exist")
    assert _mod.is_sdk_loadable(bad) is False, (
        "Non-existent sdk_path must probe False, not raise")


def test_is_sdk_loadable_is_memoised_per_sdk_path(tmp_path, monkeypatch):
    """Second call with the same sdk_path must return the cached result
    without re-attempting the dlopen — otherwise every connection pays
    the probe cost."""
    import sap_rfc_ctypes as _mod
    monkeypatch.setattr(_mod, "_SDK_LOADABLE_CACHE", {})
    monkeypatch.delenv("SAPNWRFC_HOME", raising=False)
    bad = str(tmp_path / "nope")

    # Count calls to _SDKLibrary.get to prove memoisation blocks repeats
    call_count = {"n": 0}
    real_get = _mod._SDKLibrary.get

    def _counting_get(sdk_path=None):
        call_count["n"] += 1
        return real_get(sdk_path)

    monkeypatch.setattr(_mod._SDKLibrary, "get", _counting_get)
    _mod.is_sdk_loadable(bad)
    _mod.is_sdk_loadable(bad)
    _mod.is_sdk_loadable(bad)
    assert call_count["n"] == 1, (
        f"is_sdk_loadable must memoise per sdk_path; _SDKLibrary.get "
        f"was called {call_count['n']} times for the same path")


# ---------------------------------------------------------------------------
# _get_rfc_backend — the selection
# ---------------------------------------------------------------------------

def _reload_sapmap_rfc():
    """Fresh import of sapmap_rfc so the module-level globals
    (_logged_auto_fallback) start clean for each test."""
    if "sapmap_rfc" in sys.modules:
        del sys.modules["sapmap_rfc"]
    import sapmap_rfc
    return sapmap_rfc


def test_backend_auto_falls_back_to_pure_when_sdk_unavailable(monkeypatch):
    """Core regression: when is_sdk_loadable returns False AND
    sap_rfc_pure is importable, _get_rfc_backend() must return the
    pure-Python RFCConnection (not raise, not return the C backend)."""
    srfc = _reload_sapmap_rfc()
    import sap_rfc_ctypes as _ctypes_mod
    import sap_rfc_pure as _pure_mod

    monkeypatch.setattr(_ctypes_mod, "is_sdk_loadable",
                        lambda sdk_path="": False)
    monkeypatch.setattr(srfc, "_use_pure_rfc", False)

    backend = srfc._get_rfc_backend()
    assert backend is _pure_mod.RFCConnection, (
        f"Expected pure RFCConnection on SDK-unavailable path, "
        f"got {backend!r}")


def test_backend_uses_ctypes_when_sdk_loadable(monkeypatch):
    """When the C SDK IS loadable, _get_rfc_backend() must return the
    C-SDK RFCConnection — the pure fallback is strictly a last resort."""
    srfc = _reload_sapmap_rfc()
    import sap_rfc_ctypes as _ctypes_mod

    monkeypatch.setattr(_ctypes_mod, "is_sdk_loadable",
                        lambda sdk_path="": True)
    monkeypatch.setattr(srfc, "_use_pure_rfc", False)

    backend = srfc._get_rfc_backend()
    assert backend is _ctypes_mod.RFCConnection, (
        f"Expected C-SDK RFCConnection when SDK is loadable, "
        f"got {backend!r}")


def test_backend_pure_rfc_flag_takes_precedence(monkeypatch):
    """--pure-rfc explicit arm must win even when the C SDK is
    loadable — the operator explicitly asked for the pure path."""
    srfc = _reload_sapmap_rfc()
    import sap_rfc_ctypes as _ctypes_mod
    import sap_rfc_pure as _pure_mod

    monkeypatch.setattr(_ctypes_mod, "is_sdk_loadable",
                        lambda sdk_path="": True)
    monkeypatch.setattr(srfc, "_use_pure_rfc", True)

    backend = srfc._get_rfc_backend()
    assert backend is _pure_mod.RFCConnection, (
        "--pure-rfc flag must force the pure backend regardless of "
        "C-SDK availability")


def test_backend_logs_once_on_auto_fallback(monkeypatch, caplog):
    """Operator must see a one-time informational message when the
    auto-fallback flips, so a silently-degraded path doesn't look
    like a mystery.  Must NOT log on every subsequent call — the
    _logged_auto_fallback flag is a once-per-process gate."""
    import logging
    srfc = _reload_sapmap_rfc()
    import sap_rfc_ctypes as _ctypes_mod

    monkeypatch.setattr(_ctypes_mod, "is_sdk_loadable",
                        lambda sdk_path="": False)
    monkeypatch.setattr(srfc, "_use_pure_rfc", False)
    srfc._logged_auto_fallback = False

    with caplog.at_level(logging.INFO, logger="sapmap_rfc"):
        srfc._get_rfc_backend()
        srfc._get_rfc_backend()
        srfc._get_rfc_backend()

    hits = [r for r in caplog.records
            if "auto-falling back" in r.getMessage()
            and "pure-Python" in r.getMessage()]
    assert len(hits) == 1, (
        f"Auto-fallback must log exactly ONCE per process (got "
        f"{len(hits)} log records).  Repeat spam trains operators to "
        f"ignore the message.")
    # Message points operator at the two silence-the-warning paths
    assert "--pure-rfc" in hits[0].getMessage()
    assert "SAPNWRFC_HOME" in hits[0].getMessage()


def test_backend_raises_clear_error_when_neither_available(monkeypatch):
    """When BOTH the C SDK is unavailable AND saprfclib isn't
    installed, operators must get a single clear error message that
    names BOTH remediation paths."""
    srfc = _reload_sapmap_rfc()
    import sap_rfc_ctypes as _ctypes_mod

    monkeypatch.setattr(_ctypes_mod, "is_sdk_loadable",
                        lambda sdk_path="": False)
    monkeypatch.setattr(srfc, "_use_pure_rfc", False)

    # Force "sap_rfc_pure not importable" by removing it from sys.modules
    # and injecting a sentinel that raises ImportError on next import.
    import builtins
    real_import = builtins.__import__

    def _blocked_import(name, *args, **kwargs):
        if name == "sap_rfc_pure":
            raise ImportError("blocked for test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)
    # Clear any cached module so the next import goes through our hook
    monkeypatch.delitem(sys.modules, "sap_rfc_pure", raising=False)

    with pytest.raises(ImportError) as exc:
        srfc._get_rfc_backend()
    msg = str(exc.value)
    assert "SAP NW RFC SDK" in msg, (
        f"Error must name the C SDK remediation: {msg!r}")
    assert "saprfclib" in msg, (
        f"Error must name the saprfclib remediation: {msg!r}")


# ---------------------------------------------------------------------------
# Backward compat — the probe must not break _get_connection() plumbing
# ---------------------------------------------------------------------------

def test_get_connection_still_passes_sdk_path_through(monkeypatch):
    """When the backend ends up being the C SDK, _get_connection() must
    still pass sdk_path to the RFCConnection constructor so operator's
    --sdk override takes effect.  Guard against a regression where the
    new probe path accidentally drops the kwarg."""
    srfc = _reload_sapmap_rfc()
    import sap_rfc_ctypes as _ctypes_mod

    monkeypatch.setattr(_ctypes_mod, "is_sdk_loadable",
                        lambda sdk_path="": True)
    monkeypatch.setattr(srfc, "_use_pure_rfc", False)
    srfc.set_sdk_path("/opt/nwrfcsdk/lib")

    captured = {}

    class _FakeConn:
        def __init__(self, **kwargs):
            captured.update(kwargs)
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    monkeypatch.setattr(_ctypes_mod, "RFCConnection", _FakeConn)

    from sapmap_models import SAPNode, Credentials
    node = SAPNode(sid="S4H", ip="192.168.2.209",
                   instances=[{"instance_nr": 0}])
    creds = Credentials(username="SAPMAP00", password="x",
                        client="001", instance_nr="00")
    srfc._get_connection(node, creds)
    assert captured.get("sdk_path") == "/opt/nwrfcsdk/lib", (
        f"_get_connection must pass sdk_path through to RFCConnection; "
        f"captured kwargs: {captured!r}")
