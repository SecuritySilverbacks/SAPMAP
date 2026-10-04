"""Global operating mode flags for SAPMAP.

Three toggles live here today:

* ``read_only`` gates every destructive action on both the HTTP
  surface (Bottle routes) and the MCP tool surface.

* ``loot_browser`` gates the read-only loot-download endpoint that
  lets a remote operator pull files out of ``loot/`` from a browser
  when SAPMAP is running on a jump host.  When enabled, a random
  per-run token is generated; the endpoint refuses requests without
  it.  Both the CLI flag AND the token must match — layered defence
  because loot holds password hashes, cleartext RFC destination
  passwords from SecStore, PII pulled from tables, etc.

* ``pwspray_armed`` gates the password-spraying engine (issue #69).
  Spraying hits USR02's bad-logon counter and risks landscape-wide
  lockout, so every pwspray entry point refuses with HTTP 403 unless
  the operator passed ``--allow-pwspray`` at startup.  No per-run
  token — the GUI just needs the boolean to show the ctx-menu entry
  and the backend reads the flag directly.

Kept as a tiny standalone module so any layer can import it without
dragging in the RFC / scanner / GUI packages.  Set once at startup
from ``sapmap.py`` after argparse; readers use the getter functions
throughout the codebase.  Never mutated at runtime after the CLI
banner is printed — a mid-run flip would leave a mixed UI state.
"""

import secrets

_read_only: bool = False
_loot_browser_enabled: bool = False
_loot_browser_token: str = ""
_pwspray_armed: bool = False


def set_read_only(value: bool) -> None:
    """Enable or disable read-only mode.  Called once at startup."""
    global _read_only
    _read_only = bool(value)


def is_read_only() -> bool:
    """Return True when destructive actions must be blocked."""
    return _read_only


def enable_loot_browser() -> str:
    """Enable the loot-browser endpoint and return the freshly-minted
    per-run token that must be included on every request.  Called
    once at startup from sapmap.py when --enable-loot-browser is set.
    """
    global _loot_browser_enabled, _loot_browser_token
    _loot_browser_enabled = True
    _loot_browser_token = secrets.token_urlsafe(24)
    return _loot_browser_token


def is_loot_browser_enabled() -> bool:
    return _loot_browser_enabled


def loot_browser_token() -> str:
    return _loot_browser_token


def check_loot_browser_token(candidate: str) -> bool:
    """Constant-time compare against the current per-run token.  Returns
    False when the browser is disabled OR the token doesn't match."""
    if not _loot_browser_enabled or not _loot_browser_token:
        return False
    if not candidate:
        return False
    return secrets.compare_digest(_loot_browser_token, candidate)


def set_pwspray_armed(value: bool) -> None:
    """Arm the password-spraying engine.  Called once at startup from
    sapmap.py when --allow-pwspray is passed.  OR-only semantics are
    not needed here — the flag is session-only and does not persist
    through .sapmap round-trips (unlike state.evasion.allow_evasion)."""
    global _pwspray_armed
    _pwspray_armed = bool(value)


def is_pwspray_armed() -> bool:
    """Return True when the operator has armed password spraying."""
    return _pwspray_armed
