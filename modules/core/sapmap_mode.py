"""Global operating mode flags for SAPMAP.

Currently exposes a single toggle — ``read_only`` — that gates every
destructive action on both the HTTP surface (Bottle routes) and the
MCP tool surface.  Kept as a tiny standalone module so any layer can
import it without dragging in the RFC / scanner / GUI packages.

Set once at startup from ``sapmap.py`` after argparse; readers use
``is_read_only()`` throughout the codebase.  Never mutated at runtime
after the CLI banner is printed — a mid-run flip would leave a mixed
UI state.
"""

_read_only: bool = False


def set_read_only(value: bool) -> None:
    """Enable or disable read-only mode.  Called once at startup."""
    global _read_only
    _read_only = bool(value)


def is_read_only() -> bool:
    """Return True when destructive actions must be blocked."""
    return _read_only
