"""Issue #85 follow-up — persistent GLOBAL auto-lock whitelist that survives
leaving the application.  Covers:

  * Dotfile I/O round-trip (``load_global_lock_whitelist`` /
    ``save_global_lock_whitelist``), including atomic write + malformed
    file + missing file.
  * ``SAPMAPState.__post_init__`` + ``from_dict`` apply the global file's
    patterns into ``lock_whitelist`` and record them in the non-serialized
    ``global_lock_whitelist_patterns`` meta set.
  * API: ``POST /api/lock_whitelist`` honours ``scope='session'|'global'``;
    ``DELETE`` honours ``scope='session'|'global'|'all'`` with the
    documented defaults.  GET returns ``global_patterns``.
  * Scripting: ``lock_whitelist_add`` / ``lock_whitelist_remove`` accept
    ``scope`` and the ``global:`` shorthand.
  * MCP: ``lock_whitelist(action, pattern, scope)`` passes scope through.
  * Backward compat: a POST / DELETE without ``scope`` still behaves
    exactly as it did before this follow-up (every existing PR3 test
    still passes).
"""
from __future__ import annotations

import json
import os
import tempfile
import pathlib

import pytest

import sapmap_state as _state
import sapmap_lock as L
from sapmap_models import SAPMAPState, SAPNode
from sapmap_script import _map_step, _whitelist_scope


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_global_file(tmp_path, monkeypatch):
    """Divert the global whitelist dotfile to a tempdir so tests don't
    touch the operator's real ``states/.sapmap_lock_whitelist.json``."""
    path = tmp_path / ".sapmap_lock_whitelist.json"
    monkeypatch.setattr(_state, "LOCK_WHITELIST_FILE", str(path))
    return path


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

def test_missing_file_loads_empty(tmp_global_file):
    assert not tmp_global_file.exists()
    assert _state.load_global_lock_whitelist() == []


def test_save_then_load_roundtrip(tmp_global_file):
    _state.save_global_lock_whitelist(
        ["10.0.0.0/24", "corp.example", "ec2.amazonaws.com"],
        by="alice")
    # File on disk is valid JSON with the expected envelope.
    raw = json.loads(tmp_global_file.read_text())
    assert raw["version"] == 1
    assert raw["updated_by"] == "alice"
    assert raw["patterns"] == [
        "10.0.0.0/24", "corp.example", "ec2.amazonaws.com"]
    assert _state.load_global_lock_whitelist() == [
        "10.0.0.0/24", "corp.example", "ec2.amazonaws.com"]


def test_save_dedupes_and_strips(tmp_global_file):
    _state.save_global_lock_whitelist(
        ["corp.example", "  ", "", "CORP.example", "corp.example"],
        by="")
    # Case-insensitive dedup; whitespace entries dropped; order preserved.
    assert _state.load_global_lock_whitelist() == ["corp.example"]


def test_malformed_file_loads_empty(tmp_global_file):
    tmp_global_file.write_text("not valid json {{{")
    assert _state.load_global_lock_whitelist() == []


def test_wrong_shape_loads_empty(tmp_global_file):
    tmp_global_file.write_text(json.dumps({"patterns": "oops"}))
    assert _state.load_global_lock_whitelist() == []
    tmp_global_file.write_text(json.dumps(["bare", "list"]))
    assert _state.load_global_lock_whitelist() == []


def test_save_is_atomic(tmp_global_file):
    """A crash mid-write (``.tmp`` leftover) must not corrupt the live
    file — ``os.replace`` makes the swap atomic on POSIX."""
    _state.save_global_lock_whitelist(["original.example"])
    # Simulate a stale .tmp from a prior crashed write; next save must
    # succeed and overwrite the live file atomically.
    tmp = tmp_global_file.with_suffix(tmp_global_file.suffix + ".tmp")
    tmp.write_text("garbage from prior crash")
    _state.save_global_lock_whitelist(["new.example"])
    assert _state.load_global_lock_whitelist() == ["new.example"]


# ---------------------------------------------------------------------------
# apply_global_lock_whitelist — the engine-side merge
# ---------------------------------------------------------------------------

def test_fresh_state_folds_global_patterns(tmp_global_file):
    _state.save_global_lock_whitelist(
        ["mylab.example", "192.0.2.0/24"], by="")
    s = SAPMAPState()
    # Seeded defaults (from DEFAULT_LOCK_WHITELIST) survive AND the
    # global rules land.
    assert "ec2.amazonaws.com" in s.lock_whitelist
    assert "mylab.example" in s.lock_whitelist
    assert "192.0.2.0/24" in s.lock_whitelist
    # Meta set names the global-origin patterns (lower-cased).
    assert "mylab.example" in s.global_lock_whitelist_patterns
    assert "192.0.2.0/24" in s.global_lock_whitelist_patterns
    # A default-seeded pattern is NOT in the meta set (it came from the
    # dataclass default, not the file).
    assert "ec2.amazonaws.com" not in s.global_lock_whitelist_patterns


def test_case_insensitive_dedupe_when_default_already_covers(tmp_global_file):
    """A global entry that case-insensitively clashes with the default
    seed must not land twice — but the meta set must still record the
    provenance so a later remove can clear the dotfile."""
    _state.save_global_lock_whitelist(["EC2.amazonaws.com"])
    s = SAPMAPState()
    # Live list has ec2.amazonaws.com exactly ONCE (from the seed).
    lower = [p.lower() for p in s.lock_whitelist]
    assert lower.count("ec2.amazonaws.com") == 1
    # But the meta set knows it's global-origin.
    assert "ec2.amazonaws.com" in s.global_lock_whitelist_patterns


def test_from_dict_reapplies_global_over_saved_list(tmp_global_file):
    """The whole point of the follow-up: a `.sapmap` saved on another
    machine (without any global rules) must still pick up THIS operator's
    global rules on load."""
    _state.save_global_lock_whitelist(["my-permanent.example"])
    saved = {"nodes": {}, "lock_whitelist": ["engagement-only.example"]}
    s = SAPMAPState.from_dict(saved)
    assert "engagement-only.example" in s.lock_whitelist
    assert "my-permanent.example" in s.lock_whitelist
    assert "my-permanent.example" in s.global_lock_whitelist_patterns


def test_apply_is_idempotent(tmp_global_file):
    _state.save_global_lock_whitelist(["twice.example"])
    s = SAPMAPState()
    before = list(s.lock_whitelist)
    _state.apply_global_lock_whitelist(s)
    _state.apply_global_lock_whitelist(s)
    assert s.lock_whitelist == before


def test_empty_saved_whitelist_still_gets_global(tmp_global_file):
    """An operator who cleared the per-engagement whitelist must still
    have their permanent rules apply."""
    _state.save_global_lock_whitelist(["mylab.example"])
    s = SAPMAPState.from_dict({"nodes": {}, "lock_whitelist": []})
    assert "mylab.example" in s.lock_whitelist
    assert s.global_lock_whitelist_patterns == {"mylab.example"}


def test_matcher_picks_up_global_patterns(tmp_global_file):
    """End-to-end: a global rule auto-locks a matching discovered node
    via the existing ``apply_auto_lock`` path, unchanged."""
    _state.save_global_lock_whitelist(["mylab.example"])
    s = SAPMAPState()
    n = SAPNode(sid="LAB", ip="10.1.2.3", hostname="box01.mylab.example")
    s.add_node(n)
    assert L.is_locked(s, s.nodes["LAB"])


# ---------------------------------------------------------------------------
# No disk side-effects on serialization
# ---------------------------------------------------------------------------

def test_meta_set_is_not_serialized(tmp_global_file):
    _state.save_global_lock_whitelist(["persist.example"])
    s = SAPMAPState()
    assert "persist.example" in s.global_lock_whitelist_patterns
    payload = s.to_dict()
    # Non-serialized: no "global_lock_whitelist_patterns" leaks into the
    # engagement .sapmap file, so the operator's sharing of a .sapmap
    # doesn't leak which rules came from their private global config.
    assert "global_lock_whitelist_patterns" not in payload
    # The lock_whitelist key is still present and still includes the
    # global entry, because the live list is the union.
    assert "persist.example" in payload["lock_whitelist"]


# ---------------------------------------------------------------------------
# HTTP API — scope on POST / DELETE
# ---------------------------------------------------------------------------

@pytest.fixture
def api_app(tmp_global_file):
    """Spin a Bottle app wired to a fresh SAPMAPState for API tests."""
    import sapmap_gui
    api = sapmap_gui.SAPMAPApi()
    app = sapmap_gui.create_app(api)
    return sapmap_gui, api, app


def _wsgi(app, method, path, body=None):
    """Minimal WSGI request with JSON body — mirrors
    tests/test_lock_gate_coverage_85.py so the style is consistent."""
    import io
    raw = json.dumps(body).encode() if body is not None else b""
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "8080",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "CONTENT_TYPE": "application/json",
        "CONTENT_LENGTH": str(len(raw)),
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": "http",
        "wsgi.input": io.BytesIO(raw),
        "wsgi.errors": io.StringIO(),
        "wsgi.multithread": False,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
    }
    captured = {}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status

    chunks = app(environ, start_response)
    out = b"".join(
        c if isinstance(c, bytes) else str(c).encode() for c in chunks)
    code = int(captured.get("status", "200 OK").split()[0])
    try:
        return code, json.loads(out.decode("utf-8") or "{}")
    except Exception:
        return code, {}


def test_api_post_default_scope_is_session(api_app, tmp_global_file):
    _gui, _api, app = api_app
    code, d = _wsgi(app, "POST", "/api/lock_whitelist",
                    {"pattern": "session.example"})
    assert code == 200
    assert d["scope"] == "session"
    assert d["persisted_global"] is False
    # The global file is NOT touched.
    assert _state.load_global_lock_whitelist() == []
    assert "session.example" not in d["global_patterns"]


def test_api_post_scope_global_writes_file(api_app, tmp_global_file):
    _gui, _api, app = api_app
    code, d = _wsgi(app, "POST", "/api/lock_whitelist",
                    {"pattern": "persist.example", "scope": "global"})
    assert code == 200
    assert d["scope"] == "global"
    assert d["persisted_global"] is True
    assert "persist.example" in d["lock_whitelist"]
    assert "persist.example" in d["global_patterns"]
    # Round-trips to disk.
    assert _state.load_global_lock_whitelist() == ["persist.example"]


def test_api_post_invalid_scope_400(api_app, tmp_global_file):
    _gui, _api, app = api_app
    code, d = _wsgi(app, "POST", "/api/lock_whitelist",
                    {"pattern": "p", "scope": "forever"})
    assert code == 400
    assert d["error"] == "invalid_scope"


def test_api_delete_default_scope_is_session_backcompat(
        api_app, tmp_global_file):
    """Adversarial review (#4): the DELETE default scope is 'session' so a
    pre-follow-up external caller (curl / older playbook / older MCP
    client) that sends only ``{pattern}`` can never silently wipe an
    operator's permanent rule.  Removing a global rule requires an
    explicit ``scope='global'`` or ``scope='all'``."""
    _gui, _api, app = api_app
    _wsgi(app, "POST", "/api/lock_whitelist",
          {"pattern": "p.example", "scope": "global"})
    assert _state.load_global_lock_whitelist() == ["p.example"]
    code, d = _wsgi(app, "DELETE", "/api/lock_whitelist",
                    {"pattern": "p.example"})
    assert code == 200
    assert d["scope"] == "session"
    assert d["removed"] == 1
    assert d["removed_global"] is False
    assert "p.example" not in d["lock_whitelist"]
    # Global file UNTOUCHED — exactly the back-compat guarantee.  A fresh
    # load would re-graft the pattern next launch.
    assert _state.load_global_lock_whitelist() == ["p.example"]


def test_api_delete_scope_all_removes_from_both(api_app, tmp_global_file):
    """Explicit scope='all' (what the GUI Remove button sends) strips the
    pattern from the live list AND the dotfile."""
    _gui, _api, app = api_app
    _wsgi(app, "POST", "/api/lock_whitelist",
          {"pattern": "p.example", "scope": "global"})
    code, d = _wsgi(app, "DELETE", "/api/lock_whitelist",
                    {"pattern": "p.example", "scope": "all"})
    assert code == 200
    assert d["scope"] == "all"
    assert d["removed_global"] is True
    assert _state.load_global_lock_whitelist() == []


def test_api_delete_scope_global_also_removes_from_both(
        api_app, tmp_global_file):
    _gui, _api, app = api_app
    _wsgi(app, "POST", "/api/lock_whitelist",
          {"pattern": "p.example", "scope": "global"})
    code, d = _wsgi(app, "DELETE", "/api/lock_whitelist",
                    {"pattern": "p.example", "scope": "global"})
    assert code == 200
    assert d["removed_global"] is True
    assert _state.load_global_lock_whitelist() == []


def test_api_delete_invalid_scope_400(api_app, tmp_global_file):
    _gui, _api, app = api_app
    code, d = _wsgi(app, "DELETE", "/api/lock_whitelist",
                    {"pattern": "p", "scope": "forever"})
    assert code == 400
    assert d["error"] == "invalid_scope"


def test_api_get_returns_global_patterns_subset(api_app, tmp_global_file):
    _gui, _api, app = api_app
    _wsgi(app, "POST", "/api/lock_whitelist",
          {"pattern": "a.example", "scope": "global"})
    _wsgi(app, "POST", "/api/lock_whitelist",
          {"pattern": "b.example"})  # session
    code, d = _wsgi(app, "GET", "/api/lock_whitelist")
    assert code == 200
    assert "a.example" in d["lock_whitelist"]
    assert "b.example" in d["lock_whitelist"]
    assert d["global_patterns"] == ["a.example"]


def test_api_post_without_scope_body_is_backcompat(api_app, tmp_global_file):
    """A pre-follow-up caller sending just ``{pattern}`` must still see
    the old response shape fields it relied on."""
    _gui, _api, app = api_app
    code, d = _wsgi(app, "POST", "/api/lock_whitelist",
                    {"pattern": "x.example.com"})
    assert code == 200
    assert d["added"] is True
    assert "lock_whitelist" in d
    assert "auto_locked_hosts" in d


# ---------------------------------------------------------------------------
# Scripting + MCP surface
# ---------------------------------------------------------------------------

def test_scripting_add_passes_scope_global():
    method, path, body, wait = _map_step(
        {"action": "lock_whitelist_add",
         "pattern": "persist.example",
         "scope": "global"})
    assert method == "POST"
    assert path == "/api/lock_whitelist"
    assert body == {"pattern": "persist.example", "scope": "global"}


def test_scripting_add_global_shorthand():
    _m, _p, body, _w = _map_step(
        {"action": "lock_whitelist_add",
         "pattern": "p.example",
         "global": True})
    assert body == {"pattern": "p.example", "scope": "global"}


def test_scripting_add_omits_scope_when_quiet():
    """Playbooks written before this follow-up must not suddenly send
    an unknown field.  No scope + no global shorthand → body carries
    only ``pattern`` and the server default kicks in."""
    _m, _p, body, _w = _map_step(
        {"action": "lock_whitelist_add", "pattern": "p.example"})
    assert body == {"pattern": "p.example"}


def test_scripting_remove_scope_session():
    _m, _p, body, _w = _map_step(
        {"action": "lock_whitelist_remove",
         "pattern": "p.example",
         "scope": "session"})
    assert body == {"pattern": "p.example", "scope": "session"}


def test_scripting_remove_omits_scope_when_quiet():
    _m, _p, body, _w = _map_step(
        {"action": "lock_whitelist_remove", "pattern": "p.example"})
    assert body == {"pattern": "p.example"}


def test_whitelist_scope_helper():
    assert _whitelist_scope({"scope": "global"}) == "global"
    assert _whitelist_scope({"scope": "SESSION"}) == "session"
    assert _whitelist_scope({"global": True}) == "global"
    assert _whitelist_scope({"global": False}) == "session"
    assert _whitelist_scope({}) == ""


# ---------------------------------------------------------------------------
# Adversarial-review regression tests
# ---------------------------------------------------------------------------

def test_save_returns_false_on_write_failure(tmp_global_file, monkeypatch):
    """Review #1: ``save_global_lock_whitelist`` must return False when
    the disk write fails, so the GUI handler can report persistence
    truthfully instead of lying with ``persisted_global: True``."""
    # Point the target at an unwritable path.  We monkeypatch ``os.replace``
    # to raise, which is the final step of the atomic write, so the error
    # path is exercised end-to-end.
    import sapmap_state as S
    def _boom(*a, **kw):
        raise OSError("ENOSPC")
    monkeypatch.setattr(S.os, "replace", _boom)
    ok = S.save_global_lock_whitelist(["p.example"])
    assert ok is False


def test_api_persisted_global_false_when_save_fails(
        api_app, tmp_global_file, monkeypatch):
    """Review #1 end-to-end: POST scope=global that fails to persist
    returns ``persisted_global: False`` (no lying toast upstream)."""
    _gui, _api, app = api_app
    import sapmap_state as S
    def _boom(*a, **kw):
        raise OSError("read-only filesystem")
    monkeypatch.setattr(S.os, "replace", _boom)
    code, d = _wsgi(app, "POST", "/api/lock_whitelist",
                    {"pattern": "p.example", "scope": "global"})
    assert code == 200
    assert d["persisted_global"] is False
    # The pattern DID land in the live list (session-level) — the request
    # degrades, it doesn't fail outright.
    assert "p.example" in d["lock_whitelist"]


def test_api_non_string_scope_returns_400(api_app, tmp_global_file):
    """Review #2: a POST/DELETE body with a non-string ``scope`` must
    produce a clean 400 ``invalid_scope`` rather than crash."""
    _gui, _api, app = api_app
    # POST with scope: 123 (via raw JSON) → 400 (not 500 / AttributeError).
    code, d = _wsgi(app, "POST", "/api/lock_whitelist",
                    {"pattern": "p.example", "scope": 123})
    assert code == 400
    assert d["error"] == "invalid_scope"
    code, d = _wsgi(app, "DELETE", "/api/lock_whitelist",
                    {"pattern": "p.example", "scope": True})
    assert code == 400
    assert d["error"] == "invalid_scope"


def test_whitelist_scope_helper_coerces_non_string():
    """Review #2 (scripting side): _whitelist_scope must not raise when a
    playbook YAML author writes ``scope: 123`` — it should round-trip to
    ``"123"`` so the server rejects it with 400 rather than aborting the
    script step."""
    assert _whitelist_scope({"scope": 123}) == "123"
    assert _whitelist_scope({"scope": True}) == "true"
    assert _whitelist_scope({"scope": None}) == ""


def test_report_hides_global_patterns_from_markdown(tmp_global_file):
    """Review #7: the engagement report's 'Auto-lock whitelist rules'
    section must NOT leak the operator's private global patterns into
    the customer-facing markdown.  A note acknowledges that a global
    layer exists so the auto-lock activity isn't surprising."""
    from sapmap_report import _lock_section
    _state.save_global_lock_whitelist(["my-homelab.corp.internal"])
    s = SAPMAPState()
    # Need at least one engagement scoping decision so the section renders.
    L.lock_host(s, "203.0.113.5", reason="test", by="alice")
    s.lock_whitelist.append("customer-engagement.example")
    md = "\n".join(_lock_section(s))
    assert "customer-engagement.example" in md
    assert "my-homelab.corp.internal" not in md
    assert "persistent global whitelist" in md


def test_report_hides_global_patterns_from_html(tmp_global_file):
    """Review #7: same filter applied to the HTML report."""
    from sapmap_report import _html_lock_section
    _state.save_global_lock_whitelist(["my-homelab.corp.internal"])
    s = SAPMAPState()
    L.lock_host(s, "203.0.113.5", reason="test", by="alice")
    s.lock_whitelist.append("customer-engagement.example")
    html = _html_lock_section(s)
    assert "customer-engagement.example" in html
    assert "my-homelab.corp.internal" not in html
    assert "persistent global whitelist" in html


def test_pr3_tests_isolated_from_real_global_file(monkeypatch):
    """Review #3/#8: the autouse conftest fixture must redirect
    ``LOCK_WHITELIST_FILE`` to a per-test tmpdir so a developer who
    added patterns via the new 'Make permanent' checkbox doesn't see
    the pre-existing PR3 tests fail on their box."""
    # Without the fixture, writing patterns to states/.sapmap_lock_whitelist.json
    # would leak into every new SAPMAPState().  With it, state construction
    # sees an empty global file.
    # The fixture is autouse at module level, so it's already applied here.
    import sapmap_state as S
    # The path must not be the real project path.
    real = os.path.join(
        pathlib.Path(S.__file__).parent.parent.parent, "states",
        ".sapmap_lock_whitelist.json")
    assert S.LOCK_WHITELIST_FILE != real, (
        "conftest autouse fixture missing — tests are not isolated")


def test_mcp_tool_passes_scope_through():
    """The MCP tool constructs the HTTP body correctly for each scope."""
    import importlib
    mcp_mod = importlib.import_module("sapmap_mcp_server")
    captured = []

    def _fake_api(method, path, body=None):
        captured.append((method, path, body))
        return {"ok": True, "lock_whitelist": [], "global_patterns": []}

    original = mcp_mod._api
    mcp_mod._api = _fake_api
    try:
        _ = mcp_mod.lock_whitelist(
            action="add", pattern="p.example", scope="global")
        _ = mcp_mod.lock_whitelist(
            action="remove", pattern="p.example", scope="session")
        _ = mcp_mod.lock_whitelist(
            action="add", pattern="p.example")   # no scope → omit
    finally:
        mcp_mod._api = original
    assert captured == [
        ("POST", "/api/lock_whitelist",
         {"pattern": "p.example", "scope": "global"}),
        ("DELETE", "/api/lock_whitelist",
         {"pattern": "p.example", "scope": "session"}),
        ("POST", "/api/lock_whitelist",
         {"pattern": "p.example"}),
    ]
