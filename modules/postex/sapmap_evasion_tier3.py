"""Tier 3 active-manipulation entry points.

This module hosts one entry function per registered Tier 3 technique
(``sapmap_evasion_gate.TIER3_TECHNIQUES``).  Today every entry is a
**dry-run stub** that:

  1. Asserts the operator-armed gate
     (``assert_evasion_allowed``) — refuses with ``EvasionGateError``
     otherwise.
  2. Captures a baseline snapshot if none exists.
  3. Runs the body under ``evasion_window`` so restore-on-exit is
     wired correctly.
  4. Logs the would-be kernel mutation instead of actually issuing
     it.  The real ``RZL_PUT_VALUE`` / ``TH_PUT_PARAMETER`` /
     ``RSAU_PERS`` write primitives land in a follow-up commit.

The split — foundation now, write-primitive later — lets the gate
matrix, baseline capture, window context manager, and restore path
all be exercised end-to-end against a real system without arming
the actual kernel mutation.  Once we've confirmed the baseline JSON
on disk matches what's in shared memory and the restore log shows
the right pre-mutation values, we wire the writers.

Entry-point signature for every technique::

    tier3_<name>(state, node, **params) -> dict

returning ``{ok, technique, would_write, snapshot_loot, error}``.
"""

from __future__ import annotations

import logging
from typing import Optional

from sapmap_evasion_baseline import (capture_baseline, evasion_window)
from sapmap_evasion_gate import (assert_evasion_allowed,
                                   EvasionGateError, technique_label)

logger = logging.getLogger(__name__)


def _wrap_result(technique: str, ok: bool, **extra) -> dict:
    out = {"ok": ok, "technique": technique,
            "label": technique_label(technique)}
    out.update(extra)
    return out


def tier3_set_param(state, node, param: str, value: str,
                     creds=None) -> dict:
    """Stub for 4.A.2 / 4.C.4 — RZ11 dynamic kernel-parameter set.

    Asserts the gate, captures a baseline, then **dry-runs** the
    intended ``RZL_PUT_VALUE`` write inside an evasion window so
    restore-on-exit is exercised.  When the real writer lands, the
    body of this function gains the actual ``conn.call('RZL_PUT_VALUE',
    PARAMETER=param, VALUE=value)`` and ``would_write`` becomes
    ``"applied"``.
    """
    technique = "rz11_dynamic_set"
    try:
        assert_evasion_allowed(state, node, technique,
                                require_baseline=False)
    except EvasionGateError as e:
        return _wrap_result(technique, False, error=str(e),
                             would_write=None)

    snap = capture_baseline(node, creds=creds)
    if not snap.params:
        return _wrap_result(
            technique, False,
            error="baseline capture returned empty; refusing to mutate",
            would_write=None)

    original = snap.params.get(param)
    if isinstance(original, str) and original.startswith("__UNCAPTURED__"):
        return _wrap_result(
            technique, False,
            error=f"{param} could not be baseline-captured "
                   f"({original.split(':', 1)[-1].strip()}); refusing",
            would_write=None)

    try:
        with evasion_window(node, state, technique,
                             creds=creds,
                             touched_params=[param]):
            # === FUTURE: real writer goes here ===
            # conn.call("RZL_PUT_VALUE", PARAMETER=param, VALUE=value)
            print(f"[*] {snap.sid}: tier3_set_param (DRY-RUN) — would "
                  f"write {param}={value!r} "
                  f"(baseline {param}={original!r})")
        return _wrap_result(
            technique, True,
            param=param, requested_value=value,
            baseline_value=original,
            would_write="dry-run (writer not yet armed)",
            snapshot_loot=snap.loot_path)
    except EvasionGateError as e:
        return _wrap_result(technique, False, error=str(e),
                             would_write=None)


def tier3_capture_baseline_only(state, node, creds=None) -> dict:
    """Standalone baseline capture without invoking any mutation.

    Useful for the GUI's Pre-flight panel — the operator can confirm
    a baseline JSON exists for the target before arming any other
    Tier 3 technique.  Doesn't go through ``evasion_window`` because
    there's nothing to restore.
    """
    technique = "rz11_dynamic_set"   # arbitrary registered id used for the
                                       # gate; nothing actually mutates
    try:
        assert_evasion_allowed(state, node, technique,
                                require_baseline=False)
    except EvasionGateError as e:
        return {"ok": False, "technique": "baseline_capture",
                "error": str(e), "snapshot_loot": ""}

    snap = capture_baseline(node, creds=creds)
    if not snap.params:
        return {"ok": False, "technique": "baseline_capture",
                "error": "capture returned empty (no params readable)",
                "snapshot_loot": ""}

    # Mark on the session config that a baseline now exists.  This is
    # what unblocks the `require_baseline` check for other techniques.
    try:
        from sapmap_evasion import EvasionConfig
        cfg = EvasionConfig.from_dict(state.evasion or {})
        cfg.baseline_captured_at = snap.captured_at
        state.evasion = cfg.to_dict()
    except Exception as e:
        logger.warning(f"could not persist baseline timestamp: {e}")

    return {"ok": True, "technique": "baseline_capture",
            "sid": snap.sid, "captured_at": snap.captured_at,
            "snapshot_loot": snap.loot_path,
            "param_count": len(snap.params),
            "filter_row_count": len(snap.sal_filter_rows)}
