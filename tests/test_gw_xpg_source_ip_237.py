"""Issue #237 — extend the GW SAPXPG ncpic_lu source-IP pin to the three
non-user-create GW paths that #232 left auto-detecting:

  1. python3 discovery via `_probe_python3_via_gw` called directly from
     sapmap_gui (python-command resolution) and
  2. ... from sap_transport_import (transport import), and
  3. routed dbtablog-purge (`purge_dbtablog_via_gw_hdbsql` ->
     `_execute_sql_via_gateway`).

`_probe_python3_via_gw` now takes `source_ip` and is scope-guarded; when a
caller passes `node.gw_source_ip` the pin reaches the thread-local that every
nested build_p2 reads via `_ncpic_local_ip`, while an empty `source_ip` still
INHERITS the enclosing DB-writer entrypoint's pin (so the internal call from
`_execute_sql_via_gateway` is unaffected) and never leaks across calls.

Mechanism is observed at `_ncpic_local_ip` — the single function every
build_p2 site calls to turn the thread-local pin into the F_SAP_INIT local_ip.
"""
from pathlib import Path

import pytest

# sap_db_sql_writers does `from sapmap_exploit import _gw_connect` at import
# time while sapmap_exploit imports the writers at its bottom — importing the
# writers cold hits that cycle.  Import sapmap_exploit first to prime it.
import sapmap_exploit  # noqa: E402,F401
import sap_db_sql_writers as W


_MODULES = Path(W.__file__).parents[1]      # .../modules


@pytest.fixture
def capture_pin(monkeypatch):
    """Record the thread-local source_ip at the moment the probe runs its first
    SAPXPG exec (the /etc/hostname canary via `_cat_file_via_gw`).  That call
    happens inside the probe's pinned scope, and every nested build_p2 turns
    that same thread-local into the F_SAP_INIT local_ip via `_ncpic_local_ip`
    (proven in the #232 suite).  Returning '' makes the probe exit immediately
    with its fallback — no socket I/O, no network."""
    seen = {}

    def fake_cat(*a, **k):
        ctx = getattr(W._gw_src_ctx, "source_ip", "")
        seen["ctx"] = ctx                          # last call
        seen.setdefault("ctxs", []).append(ctx)    # every call (for leak test)
        # what the pin actually resolves to at build_p2 time (isascii-gated)
        seen["ncpic"] = W._ncpic_local_ip(a[0]) if a else ""
        return ""        # empty canary -> probe returns fallback at once

    monkeypatch.setattr(W, "_cat_file_via_gw", fake_cat)
    monkeypatch.setattr(W, "_PY3_CACHE", {})     # force a cache miss
    return seen


def _run_probe(sid, source_ip):
    W._probe_python3_via_gw(
        "10.0.0.5", 3300, "00", "hostzz", sid, "793",
        saprouter="/H/router/S/3299", source_ip=source_ip)


# --------------------------------------------------------------------------
# mechanism
# --------------------------------------------------------------------------

def test_probe_pins_ncpic_lu_from_explicit_source_ip(capture_pin):
    try:
        W._set_gw_source_ip("")                 # clean thread baseline
        _run_probe("ZZ1", "203.0.113.9")
        assert capture_pin["ctx"] == "203.0.113.9"
    finally:
        W._set_gw_source_ip("")


def test_probe_empty_source_ip_inherits_enclosing_pin(capture_pin):
    """A direct probe with source_ip='' must NOT clobber a pin already set by
    an enclosing entrypoint (the internal _execute_sql_via_gateway call)."""
    try:
        W._set_gw_source_ip("198.51.100.7")     # simulate entrypoint's pin
        _run_probe("ZZ2", "")
        assert capture_pin["ctx"] == "198.51.100.7"
    finally:
        W._set_gw_source_ip("")


def test_probe_restores_prior_pin_no_leak(capture_pin):
    """After an explicit-pin probe, the thread-local is restored to the prior
    value — so a later probe/op on the same long-lived thread isn't poisoned."""
    try:
        W._set_gw_source_ip("198.51.100.7")     # prior enclosing pin
        _run_probe("ZZ3", "203.0.113.9")        # probe pins its own IP...
        assert capture_pin["ctx"] == "203.0.113.9"
        # ...but on return the prior pin is restored, not left at the probe's.
        assert getattr(W._gw_src_ctx, "source_ip", "") == "198.51.100.7"
    finally:
        W._set_gw_source_ip("")


def test_probe_empty_source_ip_on_clean_thread_autodetects(capture_pin):
    """No enclosing pin + source_ip='' -> the pin is empty at build time, so
    _ncpic_local_ip auto-detects (no stale pin)."""
    try:
        W._set_gw_source_ip("")
        _run_probe("ZZ4", "")
        assert capture_pin["ctx"] == ""
    finally:
        W._set_gw_source_ip("")


def test_probe_non_ascii_source_ip_degrades_to_autodetect(capture_pin):
    """A non-ASCII pin entering through the probe's new publish must still be
    rejected by _ncpic_local_ip's isascii() guard (it can't form a CPIC LU) and
    fall back to auto-detect rather than stamp a bad ncpic_lu."""
    try:
        W._set_gw_source_ip("")
        _run_probe("ZZ5", "høst")
        assert capture_pin["ctx"] == "høst"          # raw pin published...
        assert capture_pin["ncpic"] != "høst"        # ...but not used as LU
    finally:
        W._set_gw_source_ip("")


def test_probe_no_leak_across_sequential_calls(capture_pin):
    """Models the long-lived --script/MCP worker: a pin set by one probe must
    not bleed into the next probe on the same thread."""
    try:
        W._set_gw_source_ip("")                      # fresh thread
        _run_probe("ZZ6", "203.0.113.9")             # call 1 pins its IP
        _run_probe("ZZ7", "")                        # call 2: no pin
        assert capture_pin["ctxs"] == ["203.0.113.9", ""]
    finally:
        W._set_gw_source_ip("")


# --------------------------------------------------------------------------
# signature / scope-guard
# --------------------------------------------------------------------------

def test_probe_signature_has_source_ip_and_scope_guard():
    src = Path(W.__file__).read_text()
    idx = src.find("def _probe_python3_via_gw(")
    assert idx != -1
    sig = src[idx:src.find(")", idx)]
    assert "source_ip" in sig
    # scope guard decorates it (restores the pin on return)
    head = src[max(0, idx - 80):idx]
    assert "@_scoped_gw_source_ip" in head


# --------------------------------------------------------------------------
# caller wiring (contract) — scoped to the actual call, not the whole file
# --------------------------------------------------------------------------

def _call_args(text, fn):
    """Balanced-paren argument text of the first `fn(...)` call in *text*.
    Skips a bare `import fn` (no following paren) and is robust to the call
    being wrapped across multiple lines."""
    i = text.find(fn + "(")
    assert i != -1, fn
    j = i + len(fn) + 1
    depth = 1
    while j < len(text) and depth:
        depth += {"(": 1, ")": -1}.get(text[j], 0)
        j += 1
    return text[i:j]


def test_gui_python_probe_threads_gw_source_ip():
    args = _call_args((_MODULES / "core" / "sapmap_gui.py").read_text(),
                      "_probe_python3_via_gw")
    assert "source_ip=" in args and "gw_source_ip" in args


def test_transport_import_threads_gw_source_ip():
    args = _call_args(
        (_MODULES / "exploitation" / "sap_transport_import.py").read_text(),
        "_probe_python3_via_gw")
    assert "source_ip=" in args and "gw_source_ip" in args


def test_dbtablog_purge_threads_gw_source_ip():
    args = _call_args((_MODULES / "postex" / "sap_dbtablog_purge.py").read_text(),
                      "_execute_sql_via_gateway")
    assert "source_ip=" in args and "gw_source_ip" in args


def test_internal_execute_sql_probe_call_inherits_by_omission():
    """The probe call INSIDE _execute_sql_via_gateway must NOT pass source_ip —
    it inherits the enclosing entrypoint's pin by design (issue #237).  Locks
    the intentional omission so a future 'helpful' edit is caught."""
    src = Path(W.__file__).read_text()
    start = src.find("def _execute_sql_via_gateway(")
    assert start != -1
    nxt = src.find("\ndef ", start + 1)
    body = src[start:nxt if nxt != -1 else len(src)]
    assert "_probe_python3_via_gw(" in body
    assert "source_ip" not in _call_args(body, "_probe_python3_via_gw")


# --------------------------------------------------------------------------
# runtime caller tests — exercise the real entry functions end to end
# --------------------------------------------------------------------------

class _StopProbe(BaseException):
    """Abort the caller right after the probe records its source_ip (bypasses
    the callers' `except Exception`)."""


def _recording_probe(seen):
    def rec(*a, **k):
        seen["source_ip"] = k.get("source_ip")
        raise _StopProbe()
    return rec


def test_detect_python_cmd_passes_gw_source_ip(monkeypatch):
    import sapmap_gui
    from sapmap_models import SAPNode
    node = SAPNode(sid="S4H", ip="10.0.0.1")
    node.gw_vulnerable = True
    node.gw_vulnerable_port = 3300
    node.gw_source_ip = "203.0.113.9"
    seen = {}
    monkeypatch.setattr(W, "_probe_python3_via_gw", _recording_probe(seen))
    with pytest.raises(_StopProbe):
        sapmap_gui._detect_python_cmd(node)
    assert seen["source_ip"] == "203.0.113.9"


def test_upload_binary_passes_gw_source_ip(monkeypatch):
    import sap_transport_import as T
    from sapmap_models import SAPNode
    node = SAPNode(sid="S4H", ip="10.0.0.1")
    node.gw_vulnerable_port = 3300
    node.gw_source_ip = "203.0.113.9"
    monkeypatch.setattr(T, "_os_type", lambda n: "linux")
    seen = {}
    monkeypatch.setattr(W, "_probe_python3_via_gw", _recording_probe(seen))
    with pytest.raises(_StopProbe):
        T._upload_binary(node, (lambda *a, **k: ""), b"payload",
                         "/tmp/x", "lbl", (lambda **k: None))
    assert seen["source_ip"] == "203.0.113.9"
