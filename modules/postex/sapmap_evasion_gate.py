"""Tier 3 entry-gate — refuses to run active-manipulation techniques
unless the operator has explicitly armed them via ``--allow-evasion``
AND a usable baseline snapshot exists for the target node.

Every Tier 3 technique entry point MUST start with::

    assert_evasion_allowed(state, node, technique="sal_filter_narrow")

which either returns silently (gate open) or raises
``EvasionGateError`` with a clear operator-facing reason.

A separate registry (``TIER3_TECHNIQUES``) maps technique IDs to short
labels and the per-technique opt-in flag they currently sit behind.
Today every Tier 3 technique sits behind the master ``allow_evasion``
flag.  When we add Tier 4 (full evidence cleanup) the registry grows
a second column (``allow_destructive``) without touching callsites.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


class EvasionGateError(RuntimeError):
    """Raised when a Tier 3+ technique is invoked without the operator
    having armed the evasion flag, or before a baseline snapshot was
    captured for the target node.

    Carries ``technique`` and ``reason`` attributes so the GUI handler
    can render a structured error to the operator instead of a bare
    string.
    """

    def __init__(self, technique: str, reason: str):
        super().__init__(f"[{technique}] {reason}")
        self.technique = technique
        self.reason = reason


@dataclass(frozen=True)
class Tier3Technique:
    """Registry entry for one Tier 3 technique.

    Attributes:
        id        — stable identifier (used in findings, audit log,
                    serialised baselines, GUI labels)
        label     — short human-readable name for finding text
        required_flag — name of the ``EvasionConfig`` boolean that must
                    be True before this technique runs.  v1 = the master
                    ``allow_evasion`` for all Tier 3 techniques.  When
                    Tier 4 lands we add a second flag here.
    """

    id: str
    label: str
    required_flag: str = "allow_evasion"


# Canonical Tier 3 catalogue.  Adding a new technique means:
#   1. Registering it here.
#   2. Calling assert_evasion_allowed(..., technique=<id>) at the top
#      of the implementation.
#   3. Implementing baseline capture + restore in
#      ``sapmap_evasion_baseline``.
TIER3_TECHNIQUES: dict = {
    t.id: t for t in (
        # 4.A.1 — SM19 filter narrowing during op
        Tier3Technique("sal_filter_narrow",
                        "SAL filter slot narrowing"),
        # 4.A.1b — UNAME swap on active SAL slot
        Tier3Technique("sal_uname_narrow",
                        "SAL slot UNAME swap (exclude operator user)"),
        # 4.A.2 — kernel param disable (rsau/enable, rsau/integrity)
        Tier3Technique("sal_kernel_param_disable",
                        "SAL kernel parameter disable"),
        # 4.A.3 — stat/level = 0
        Tier3Technique("stad_silence",
                        "STAD workload-statistics silencing"),
        # 4.A.4 — rec/client OFF for specific tables
        Tier3Technique("dbtablog_suppress",
                        "DBTABLOG table-logging suppression"),
        # 4.C.3 — rdisp/TRACE / ICM trace level dynamic flip
        Tier3Technique("icm_trace_flip",
                        "ICM / work-process trace-level flip"),
        # 4.C.4 — generic RZ11 dynamic-set primitive
        Tier3Technique("rz11_dynamic_set",
                        "RZ11 dynamic kernel-parameter set"),
        # 4.A.17 — TSL1D template row delete (legacy)
        Tier3Technique("tsl1d_template_delete",
                        "TSL1D SAL message-template delete"),
        # 4.B.1 / 4.B.5 — Java NWA severity / defaultTrace flip
        Tier3Technique("java_nwa_severity",
                        "Java NWA log severity flip"),
    )
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def technique_label(technique_id: str) -> str:
    """Return the human-readable label, or the id if unknown."""
    t = TIER3_TECHNIQUES.get(technique_id)
    return t.label if t else technique_id


def _evasion_from_state(state) -> Optional["EvasionConfig"]:
    """Lazy-import path that avoids a circular dep on sapmap_evasion."""
    if state is None:
        return None
    from sapmap_evasion import EvasionConfig
    return EvasionConfig.from_dict(getattr(state, "evasion", None) or {})


def assert_evasion_allowed(state, node, technique: str,
                            require_baseline: bool = True) -> None:
    """Gate function called at the top of every Tier 3 entry point.

    Raises ``EvasionGateError`` when the operator hasn't armed the
    technique.  Returns silently when the gate is open.

    Args:
        state:      ``SAPMAPState`` carrying the persisted evasion
                    config.  Pass ``None`` to refuse unconditionally
                    (CLI scripts without a state object don't get to
                    run Tier 3).
        node:       Target ``SAPNode``.  Used only when
                    ``require_baseline`` is True so the gate can check
                    a baseline exists for this specific system.
        technique:  Registered technique id (must appear in
                    ``TIER3_TECHNIQUES``).
        require_baseline:
                    When True (default) the gate also refuses if no
                    baseline has been captured.  Some techniques that
                    are themselves part of the baseline-capture flow
                    pass ``False`` to break the chicken-and-egg.
    """
    tech = TIER3_TECHNIQUES.get(technique)
    if tech is None:
        raise EvasionGateError(
            technique,
            f"Unknown technique id {technique!r} — not in TIER3_TECHNIQUES "
            "registry.  Register before invoking.")

    if state is None:
        raise EvasionGateError(
            technique,
            "No SAPMAPState available — Tier 3 must run inside the "
            "GUI / scripted flow that carries the operator-armed "
            "evasion config.")

    evasion = _evasion_from_state(state)
    if evasion is None or not getattr(evasion, tech.required_flag, False):
        raise EvasionGateError(
            technique,
            f"Refused: {tech.label} requires "
            f"--{tech.required_flag.replace('_', '-')} (currently OFF). "
            "Restart SAPMAP with the flag, or toggle it in Settings → "
            "Evasion before running this technique.")

    if require_baseline:
        # Tier 1 / Tier 2 modules dump baseline snapshots under
        # node._evasion_baseline (in-memory) or loot/baseline/<sid>/.
        # We accept either signal.
        has_node_baseline = bool(getattr(node, "_evasion_baseline", None))
        has_session_baseline = bool(evasion.baseline_captured_at)
        if not (has_node_baseline or has_session_baseline):
            raise EvasionGateError(
                technique,
                f"Refused: {tech.label} requires a pre-flight baseline "
                "for restore-on-exit.  Run Capture Evasion Baseline on "
                f"{getattr(node, 'sid', '<node>')} first.")


# ---------------------------------------------------------------------------
# Startup banner — printed by sapmap.py when --allow-evasion is in argv
# ---------------------------------------------------------------------------

EVASION_BANNER = (
    "=" * 72 + "\n"
    " ⚡  SAPMAP — EVASION MODE ARMED  ⚡\n"
    "=" * 72 + "\n"
    " Tier 3 active-manipulation techniques are now AVAILABLE in this\n"
    " session.  This means SAPMAP can, with explicit operator action:\n"
    "\n"
    "   * Disable / narrow the Security Audit Log\n"
    "   * Suppress DBTABLOG table-change logging\n"
    "   * Silence STAD workload statistics\n"
    "   * Flip kernel parameters (rsau/integrity, rsau/ip_only,\n"
    "     rec/client, stat/level, rdisp/TRACE, gw/logging) at runtime\n"
    "   * Delete SAL message templates via SE92\n"
    "   * Flip Java NWA log-severity at the server level\n"
    "\n"
    " Every Tier 3 action snapshots a baseline first and is restored\n"
    " on exit (or window-context completion).  Even so, a crash or kill\n"
    " before restore can leave the target in a non-baseline state.\n"
    "\n"
    " You MUST have explicit written authorization for active-evasion\n"
    " testing against the targets in scope.  Activity may produce SAL\n"
    " configuration-change events that defenders WILL see.\n"
    "=" * 72
)


def print_evasion_banner() -> None:
    """Emit the banner.  Called by sapmap.py at startup when the flag
    is set in argv.  Also re-emitted into the GUI console as a sticky
    warning."""
    print(EVASION_BANNER)
