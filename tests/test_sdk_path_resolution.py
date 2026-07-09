"""Startup: NW RFC SDK path resolution.

sapmap.py picks the SDK path in this order:

  1. ``--sdk`` CLI flag (per-run override)
  2. ``nwrfcsdk_path`` in ``settings.local.json`` (persisted from the
     Actions → Set NW RFC SDK Path menu)
  3. Nothing — fall back to system LD_LIBRARY_PATH / DYLD_*

These tests pin that order down so a future refactor can't silently
swap precedence (e.g. accidentally letting a stale settings.local.json
override a fresh --sdk on the CLI).
"""
from __future__ import annotations

import json
import os
import sys

import modules  # noqa: F401  (registers package paths)


def _import_sapmap_helper():
    """Import _resolve_sdk_path from sapmap.py.  The module isn't part
    of the modules/ tree, so we add the repo root to sys.path once."""
    repo_root = os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    import sapmap
    return sapmap._resolve_sdk_path


def test_cli_flag_wins_over_settings_file(tmp_path, monkeypatch):
    """A user who deliberately passes ``--sdk`` on the command line
    is overriding whatever is in settings.local.json for this one
    session.  The CLI flag MUST win even when both are present."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "settings.local.json").write_text(
        json.dumps({"nwrfcsdk_path": "/persisted/from/settings"}))

    _resolve_sdk_path = _import_sapmap_helper()
    path, source = _resolve_sdk_path("/explicit/from/cli")

    assert path == "/explicit/from/cli"
    assert source == "--sdk"


def test_settings_file_used_when_cli_flag_absent(tmp_path, monkeypatch):
    """The whole point of the setting: launching ``python3 sapmap.py``
    with no flags should pick up the operator's saved SDK path."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "settings.local.json").write_text(
        json.dumps({"nwrfcsdk_path": "/opt/nwrfcsdk/lib"}))

    _resolve_sdk_path = _import_sapmap_helper()
    path, source = _resolve_sdk_path(None)

    assert path == "/opt/nwrfcsdk/lib"
    assert source == "settings.local.json"


def test_empty_string_in_settings_falls_through(tmp_path, monkeypatch):
    """The GUI Save action allows clearing the setting by submitting
    an empty string; the file then persists ``"nwrfcsdk_path": ""``
    (or the key removed).  Both must fall through to the "no path"
    outcome — NOT be interpreted as a valid empty path."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "settings.local.json").write_text(
        json.dumps({"nwrfcsdk_path": ""}))

    _resolve_sdk_path = _import_sapmap_helper()
    path, source = _resolve_sdk_path(None)

    assert path == ""
    assert source == ""


def test_missing_settings_file_returns_empty(tmp_path, monkeypatch):
    """First-ever run — no settings.local.json exists yet.  The
    helper must not raise; it must return the "no path" outcome so
    startup continues with system LD_LIBRARY_PATH as the fallback."""
    monkeypatch.chdir(tmp_path)
    assert not (tmp_path / "settings.local.json").exists()

    _resolve_sdk_path = _import_sapmap_helper()
    path, source = _resolve_sdk_path(None)

    assert path == ""
    assert source == ""


def test_malformed_settings_file_returns_empty(tmp_path, monkeypatch):
    """A truncated / hand-edited settings file should not crash
    startup.  Preserve the CLI-flag path if given; otherwise fall
    through to the "no path" outcome and let the operator re-save
    via the GUI."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "settings.local.json").write_text("{not valid json")

    _resolve_sdk_path = _import_sapmap_helper()

    path, source = _resolve_sdk_path(None)
    assert (path, source) == ("", "")

    # And if --sdk is present, it still wins even with a broken file.
    path2, source2 = _resolve_sdk_path("/from/cli")
    assert (path2, source2) == ("/from/cli", "--sdk")


def test_other_settings_keys_are_ignored(tmp_path, monkeypatch):
    """A settings file that has hashes_com_api_key set but no
    nwrfcsdk_path must NOT accidentally use the API key as a path.
    Regression pin: this exact bug could happen if the key lookup
    ever gets refactored to a generic ``get first non-empty
    string``.  Explicit key name required."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "settings.local.json").write_text(
        json.dumps({"hashes_com_api_key": "abcd1234"}))

    _resolve_sdk_path = _import_sapmap_helper()
    path, source = _resolve_sdk_path(None)

    assert path == ""
    assert source == ""
