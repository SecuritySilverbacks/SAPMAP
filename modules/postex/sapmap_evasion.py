"""Tier 2 OPSEC — passive minimisation primitives.

T2.1: DIAG terminal-name spoof.  When the Tier 1 telemetry probe has
detected ``rsau/ip_only=0`` (or ``off (default)``) on a target node, the
kernel will record whatever terminal-name string the DIAG client sends
in the SAL ``Source`` field.  Substituting a blender-friendly value
for the hardcoded ``"sapscanner"`` default makes attribution unreliable
in the audit trail without any active log tampering.

When the target's ``rsau/ip_only`` is ON (or unknown), the kernel
overrides the client-supplied name with the source IP — so the
substitution is pointless; we keep the inherited default and let the
caller log nothing.  No silent always-on spoofing.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


# Default fallback DIAG terminal name kept for callers that have no
# operator state object available (e.g. CLI-only scripts).  Operators
# can override via SAPMAPState.evasion.diag_terminal_name.
DEFAULT_DIAG_TERMINAL = "sapscanner"

# What we send when an active spoof is warranted.  Blender-friendly
# string that resembles a typical corporate workstation name.  Operator
# can override via EvasionConfig.diag_terminal_name.
DEFAULT_SPOOF_TERMINAL = "WS-NB-04"


@dataclass
class EvasionConfig:
    """Per-session OPSEC settings.

    All fields default to OFF / empty so behaviour is unchanged until
    the operator explicitly opts in or until Tier 1 detection auto-
    activates a primitive.
    """

    # Override for the DIAG terminal-name string used when a spoof is
    # warranted.  Empty → use ``DEFAULT_SPOOF_TERMINAL``.  Per session.
    diag_terminal_name: str = ""

    # Recorded so the GUI can show "last edited at".
    updated_at: str = ""

    def __post_init__(self):
        if not self.updated_at:
            self.updated_at = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "diag_terminal_name": self.diag_terminal_name,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "EvasionConfig":
        return cls(
            diag_terminal_name=d.get("diag_terminal_name", ""),
            updated_at=d.get("updated_at", ""),
        )


def effective_diag_terminal(node, evasion: EvasionConfig | None
                             ) -> tuple[str, bool]:
    """Return ``(terminal_name, spoof_active)`` for a DIAG op on *node*.

    ``spoof_active`` is True only when the Tier 1 probe positively
    detected ``rsau/ip_only`` in an OFF state on the target — that's
    the only configuration where the client-supplied terminal field
    actually wins.  Otherwise the kernel overrides what we send, so
    using the safe default ``DEFAULT_DIAG_TERMINAL`` is just as good.
    """
    tp = getattr(node, "telemetry_profile", None) if node else None
    ip_only = (getattr(tp, "sal_source_ip_only", "") or "").lower()
    is_off = ip_only.startswith("off")
    if not is_off:
        return DEFAULT_DIAG_TERMINAL, False
    override = (evasion.diag_terminal_name if evasion else "") or ""
    return (override.strip() or DEFAULT_SPOOF_TERMINAL), True
