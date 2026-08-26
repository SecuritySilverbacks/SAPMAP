"""Tests for read-only mode."""
import pytest

import sapmap_mode


@pytest.fixture(autouse=True)
def _reset_mode():
    """Every test starts with read-only off."""
    sapmap_mode.set_read_only(False)
    yield
    sapmap_mode.set_read_only(False)


def test_mode_default_off():
    assert sapmap_mode.is_read_only() is False


def test_mode_toggle():
    sapmap_mode.set_read_only(True)
    assert sapmap_mode.is_read_only() is True
    sapmap_mode.set_read_only(False)
    assert sapmap_mode.is_read_only() is False


def test_mode_accepts_truthy():
    """set_read_only coerces via bool()."""
    sapmap_mode.set_read_only(1)
    assert sapmap_mode.is_read_only() is True
    sapmap_mode.set_read_only("")
    assert sapmap_mode.is_read_only() is False


def test_gui_wires_mode_endpoint_and_hook():
    """Source-level check: create_app registers /api/mode and a
    before_request hook against a maintained WRITE_ROUTES set."""
    with open("modules/core/sapmap_gui.py", encoding="utf-8") as f:
        src = f.read()
    assert '@app.route("/api/mode")' in src, \
        "Missing /api/mode endpoint"
    assert '@app.hook("before_request")' in src, \
        "Missing before_request hook"
    assert "WRITE_ROUTES = frozenset({" in src, \
        "Missing WRITE_ROUTES set"
    # A few critical routes must be listed
    for route in (
        '"/api/actions/autopwn"',
        '"/api/actions/cleanup_all"',
        '"/api/node/<sid>/create_user"',
        '"/api/node/<sid>/sapcontrol_osexecute"',
        '"/api/node/<sid>/ransapware/encrypt"',
        '"/api/node/<sid>/forge_ticket"',
        '"/api/scc/<host>/extract_keystore"',
    ):
        assert route in src, f"Missing write route in WRITE_ROUTES: {route}"


def test_frontend_hides_write_ops_and_shows_badge():
    """Source-level check: the CSS rule, mode-badge, and initMode()
    poll all live in sapmap_html.py."""
    with open("modules/core/sapmap_html.py", encoding="utf-8") as f:
        src = f.read()
    assert "body.read-only .write-op { display: none !important; }" in src
    assert 'id="mode-badge"' in src
    assert "async function initMode()" in src
    assert "await api('GET', 'mode')" in src


def test_scriptrunner_list_destructive_steps():
    from sapmap_script import ScriptRunner, DESTRUCTIVE_ACTIONS
    r = ScriptRunner("http://127.0.0.1:8080", "/dev/null")
    r.steps = [
        {"action": "scan_network", "target": "10.0.0.0/24"},
        {"action": "check_gw", "target": "S4H"},
        {"action": next(iter(DESTRUCTIVE_ACTIONS)), "target": "T1"},
        {"action": "export_report"},
    ]
    offenders = r.list_destructive_steps()
    assert len(offenders) == 1
    assert "T1" in offenders[0]


def test_scriptrunner_list_destructive_empty_for_safe_script():
    from sapmap_script import ScriptRunner
    r = ScriptRunner("http://127.0.0.1:8080", "/dev/null")
    r.steps = [
        {"action": "scan_network", "target": "10.0.0.0/24"},
        {"action": "check_gw", "target": "S4H"},
        {"action": "check_ms", "target": "S4H"},
        {"action": "export_report"},
    ]
    assert r.list_destructive_steps() == []


def test_mcp_readonly_guard_returns_reply():
    """When the MCP cache says True, guard returns the reply."""
    from sapmap_mcp_server import (
        _read_only_guard, _READ_ONLY_CACHE, _READ_ONLY_REPLY,
    )
    _READ_ONLY_CACHE.update({"checked": True, "read_only": True})
    try:
        assert _read_only_guard() == _READ_ONLY_REPLY
    finally:
        _READ_ONLY_CACHE.update({"checked": False, "read_only": False})


def test_mcp_readonly_guard_passes_when_off():
    from sapmap_mcp_server import _read_only_guard, _READ_ONLY_CACHE
    _READ_ONLY_CACHE.update({"checked": True, "read_only": False})
    try:
        assert _read_only_guard() == ""
    finally:
        _READ_ONLY_CACHE.update({"checked": False, "read_only": False})


def test_loot_browser_disabled_by_default():
    assert sapmap_mode.is_loot_browser_enabled() is False
    assert sapmap_mode.loot_browser_token() == ""
    assert sapmap_mode.check_loot_browser_token("anything") is False


def test_loot_browser_enable_mints_token():
    # Reset first so we know the token is fresh
    import sapmap_mode as _mm
    _mm._loot_browser_enabled = False
    _mm._loot_browser_token = ""
    try:
        tok = sapmap_mode.enable_loot_browser()
        assert sapmap_mode.is_loot_browser_enabled() is True
        assert isinstance(tok, str) and len(tok) >= 32
        assert sapmap_mode.loot_browser_token() == tok
        assert sapmap_mode.check_loot_browser_token(tok) is True
        assert sapmap_mode.check_loot_browser_token("") is False
        assert sapmap_mode.check_loot_browser_token(tok + "x") is False
    finally:
        _mm._loot_browser_enabled = False
        _mm._loot_browser_token = ""


def test_gui_wires_loot_browser_endpoints():
    """Source-level check: loot list + download endpoints are registered."""
    with open("modules/core/sapmap_gui.py", encoding="utf-8") as f:
        src = f.read()
    assert '@app.route("/api/loot/list")' in src
    assert '@app.route("/api/loot/download")' in src
    assert "_loot_gate" in src
    assert "_resolve_loot_path" in src
    # Confirm the canonicalisation-against-loot-root guard is in place
    assert "os.path.commonpath" in src
    assert "os.path.realpath" in src
