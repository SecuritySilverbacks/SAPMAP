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

    # Forced OS-exec channel — "" (auto), "sxpg", or "gw_sapxpg".  Auto
    # means ``effective_os_exec_channel`` chooses based on what creds
    # and primitives are available on the target.
    os_exec_channel: str = ""

    # Recorded so the GUI can show "last edited at".
    updated_at: str = ""

    def __post_init__(self):
        if not self.updated_at:
            self.updated_at = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "diag_terminal_name": self.diag_terminal_name,
            "os_exec_channel": self.os_exec_channel,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "EvasionConfig":
        return cls(
            diag_terminal_name=d.get("diag_terminal_name", ""),
            os_exec_channel=d.get("os_exec_channel", ""),
            updated_at=d.get("updated_at", ""),
        )


def effective_os_exec_channel(node, creds, evasion: EvasionConfig | None
                                ) -> tuple[str, str]:
    """T2.3 — pick the quieter OS-exec channel.

    Returns ``(channel, reason)`` where channel is ``"sxpg"`` (one SAL
    event, no gateway log entries) or ``"gw_sapxpg"`` (3-5 events
    across SAL + gateway log).  ``reason`` is a short human-readable
    decision summary suitable for an INFO finding.

    Decision matrix:
      - No verified credential          → gw_sapxpg (only option)
      - No gateway-vulnerable node      → sxpg (gw path won't work)
      - Verified credential present     → sxpg (best-case 1 SAL event;
                                           caller's transparent
                                           fallback handles auth denials)
      - Operator override via evasion   → respected verbatim
    """
    override = (evasion.os_exec_channel if evasion else "") or ""
    if override in ("sxpg", "gw_sapxpg"):
        return override, f"operator override: {override}"

    has_creds = bool(creds and getattr(creds, "verified", False))
    gw_vulnerable = bool(getattr(node, "gw_vulnerable", False))

    if has_creds and gw_vulnerable:
        return "sxpg", (
            "verified credential held; SXPG writes ~1 SAL event vs "
            "~3-5 for GW SAPXPG (P1/P2/P3 plus gateway log entries)")
    if has_creds and not gw_vulnerable:
        return "sxpg", "verified credential held; GW SAPXPG path unavailable"
    if not has_creds and gw_vulnerable:
        return "gw_sapxpg", (
            "no verified credential; GW SAPXPG is the only OS-exec "
            "primitive available")
    return "gw_sapxpg", (
        "no verified credential and no detected gateway vuln; "
        "GW SAPXPG attempt is the last fallback")


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
