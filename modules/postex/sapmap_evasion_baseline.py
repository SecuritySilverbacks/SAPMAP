"""Tier 3 baseline snapshot + restore-on-exit primitive.

Every Tier 3 action that mutates target state runs inside an
``evasion_window(node, state, technique)`` context manager:

    with evasion_window(node, state, "stad_silence") as w:
        change_param(node, creds, "stat/level", "0")   # mutate
        # ... operator work that depends on STAD being off ...
    # __exit__ restores stat/level to the captured baseline value
    # exactly once, no matter how the body exited.

The window is implemented in three layers:

1. ``capture_baseline(node, creds)`` reads the current SAL config +
   profile parameter values + filter-slot table contents.  Stores a
   ``BaselineSnapshot`` on the node *and* writes a JSON copy to
   ``loot/baseline/<sid>/<timestamp>.json`` so a crash-restart can still
   roll the system back.

2. ``evasion_window`` is the context-manager.  Auto-captures on entry
   if the node has no snapshot.  Records the technique invocation on a
   thread-local stack so re-entrant techniques work.  On exit
   (including exception path) it calls ``restore_baseline`` for every
   touched key.

3. ``restore_baseline(node, creds, snapshot, only=...)`` writes the
   captured values back via ``change_param`` which wraps the RFC-
   enabled kernel FM ``TH_CHANGE_PARAMETER``.  Dynamic, in-memory only
   — no profile file rewrite, no kernel restart, no AUM/AUW.

   Important: ``TH_CHANGE_PARAMETER`` only works for parameters the
   kernel marks **dynamic** (e.g. ``rdisp/TRACE``, ``icm/trace_level``).
   Static parameters (most of ``rsau/*``, ``stat/level``, ``rec/client``)
   either return a non-zero RC or silently no-op — the parameter
   value in shared memory may update, but the kernel keeps using the
   startup-cached value.  Per-technique writers for the static
   parameter families use purpose-built FMs (``RSAU_UPD_AUDIT_CONFIG``
   for SAL, table-row writes for DBTABLOG, etc.) and don't go through
   ``change_param``.

This file only defines the data carriers + capture / write / restore
primitives; each Tier 3 technique imports and wraps itself in the
window.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger(__name__)


# Parameters captured by the baseline.  Mirrors what Tier 1 already
# reads; extending the list means adding entries here AND wiring the
# corresponding set primitive in the restore path.
_BASELINE_PARAMS = (
    "rsau/enable",
    "rsau/selection_slots",
    "rsau/integrity",
    "rsau/ip_only",
    "rec/client",
    "stat/level",
    "gw/logging",
    "rdisp/TRACE",
)


@dataclass
class BaselineSnapshot:
    """Captured state of a target node prior to Tier 3 mutation.

    Stored on the node in-memory and persisted under
    ``loot/baseline/<sid>/<timestamp>.json``.
    """

    sid: str = ""
    captured_at: str = ""
    params: dict = field(default_factory=dict)
    sal_filter_rows: list = field(default_factory=list)
    # Free-form bag for technique-specific snapshot data
    # (e.g. NWA log-config XML before flip).  Keyed by technique id.
    technique_state: dict = field(default_factory=dict)
    loot_path: str = ""

    def to_dict(self) -> dict:
        return {
            "sid": self.sid,
            "captured_at": self.captured_at,
            "params": dict(self.params),
            "sal_filter_rows": list(self.sal_filter_rows),
            "technique_state": dict(self.technique_state),
            "loot_path": self.loot_path,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "BaselineSnapshot":
        return cls(
            sid=d.get("sid", ""),
            captured_at=d.get("captured_at", ""),
            params=dict(d.get("params") or {}),
            sal_filter_rows=list(d.get("sal_filter_rows") or []),
            technique_state=dict(d.get("technique_state") or {}),
            loot_path=d.get("loot_path", ""),
        )


# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------

def capture_baseline(node, creds=None,
                      loot_root: str = "loot") -> BaselineSnapshot:
    """Snapshot the audit/trace config on ``node`` for restore-on-exit.

    Reads the same parameters Tier 1 probes (via ``TH_GET_PARAMETER``)
    plus the populated ``RSAU_PERS`` / ``RSAUPROF`` rows.  Stores the
    snapshot in-memory on ``node._evasion_baseline`` and writes a JSON
    copy under ``loot/baseline/<sid>/<timestamp>.json``.

    Idempotent: re-invoking on a node that already has a snapshot
    returns the existing one (we never want to overwrite a baseline
    with post-mutation state).
    """
    existing = getattr(node, "_evasion_baseline", None)
    if existing is not None:
        return existing

    import sapmap_rfc
    from sapmap_errors import format_rfc_exception

    snap = BaselineSnapshot(
        sid=getattr(node, "sid", "?"),
        captured_at=datetime.now().isoformat(),
    )

    try:
        with sapmap_rfc._get_connection(node, creds) as conn:
            # Profile parameters via TH_GET_PARAMETER — same primitive
            # the Tier 1 probe uses, accepted on every modern kernel
            # and not subject to S_DEVELOP.
            for pname in _BASELINE_PARAMS:
                try:
                    r = conn.call("TH_GET_PARAMETER",
                                   PARAMETER_NAME=pname)
                    val = (r.get("PARAMETER_VALUE")
                           or r.get("VALUE")
                           or r.get("RETURN_VALUE") or "")
                    if isinstance(val, bytes):
                        val = val.decode("utf-8", errors="replace")
                    snap.params[pname] = val.strip() if isinstance(val, str) else val
                except Exception as e:
                    # Record the failure so the operator sees what
                    # couldn't be baselined.  Mark with a sentinel that
                    # restore() recognises and refuses to act on.
                    snap.params[pname] = f"__UNCAPTURED__:{format_rfc_exception(e)[:80]}"

            # SAL filter rows — legacy RSAUPROF on older NetWeaver
            # kernels.  Modern S/4 keeps the active filter config in
            # kernel-managed storage and exposes it via the
            # RSAU_*_AUDIT_CONFIG FM family rather than a transparent
            # table.  Capturing that side is a separate primitive that
            # lands when we wire the SAL filter-narrow technique
            # against the kernel's real read/write FM (currently
            # ``RSAU_UPD_AUDIT_CONFIG`` on the write side).
            try:
                r = conn.call(
                    "RFC_READ_TABLE",
                    QUERY_TABLE="RSAUPROF",
                    DELIMITER="|",
                    ROWCOUNT=200,
                )
                rows = r.get("DATA", []) or []
                if rows:
                    snap.sal_filter_rows = [
                        (row.get("WA") or "") for row in rows]
            except Exception:
                # RSAUPROF absent on modern S/4 — leave filter capture
                # empty and let the per-technique writer handle the
                # kernel-managed path when it lands.
                pass
    except Exception as e:
        # Connect failed — don't return a half-baked snapshot.  The
        # gate check will refuse to run any Tier 3 technique because
        # node._evasion_baseline stays None.
        logger.warning(f"{snap.sid}: baseline capture failed at connect: "
                        f"{format_rfc_exception(e)}")
        return snap  # empty params; gate will refuse downstream

    # Persist to disk
    loot_dir = Path(loot_root) / "baseline" / snap.sid
    try:
        loot_dir.mkdir(parents=True, exist_ok=True)
        fname = f"baseline_{snap.captured_at.replace(':', '').replace('.', '_')}.json"
        path = loot_dir / fname
        path.write_text(json.dumps(snap.to_dict(), indent=2))
        snap.loot_path = str(path)
    except Exception as e:
        logger.warning(f"{snap.sid}: baseline loot write failed: {e}")

    node._evasion_baseline = snap
    return snap


# ---------------------------------------------------------------------------
# Writer — TH_CHANGE_PARAMETER
# ---------------------------------------------------------------------------

def change_param(node, creds, name: str, value: str) -> dict:
    """Dynamically write an SAP profile parameter via TH_CHANGE_PARAMETER.

    ``TH_CHANGE_PARAMETER`` is the RFC-enabled kernel FM that updates
    a parameter at runtime in shared memory.  No profile file is
    rewritten, no AUM/AUW SAL events are emitted, and the change
    survives until the instance restarts (or until restore_baseline
    rewrites it).  Parameter names are case-sensitive at the kernel
    boundary (same as TH_GET_PARAMETER on the read side).

    Returns a dict::

        {"ok": bool, "name": str, "value": str, "error": str}

    Raises nothing — even auth-denial / parameter-unknown failures
    are captured in the ``error`` field so the caller can decide
    whether to abort or continue.  The window context manager relies
    on this contract: a failed write is reported but doesn't stop
    restore from attempting the remaining params.
    """
    import sapmap_rfc
    from sapmap_errors import format_rfc_exception

    try:
        with sapmap_rfc._get_connection(node, creds) as conn:
            r = conn.call("TH_CHANGE_PARAMETER",
                           PARAMETER_NAME=name,
                           PARAMETER_VALUE=value)
            # TH_CHANGE_PARAMETER returns RC=0 on success.  Some
            # kernels also surface RETURN_CODE; treat any non-empty
            # non-zero rc as a failure.
            rc = r.get("RC", r.get("RETURN_CODE", "0"))
            rc_str = str(rc).strip()
            if rc_str not in ("", "0"):
                msg = (r.get("MESSAGE") or r.get("ERROR_MESSAGE")
                       or f"RC={rc_str}")
                return {"ok": False, "name": name, "value": value,
                        "error": str(msg)[:200]}
            return {"ok": True, "name": name, "value": value, "error": ""}
    except Exception as e:
        msg = format_rfc_exception(e).split("\n")[0][:200]
        return {"ok": False, "name": name, "value": value, "error": msg}


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------

def restore_baseline(node, creds, snapshot: BaselineSnapshot,
                      only: Optional[list] = None) -> dict:
    """Write the captured parameter values back to the target.

    Args:
        only: optional list of parameter names to restore (default =
              every captured key).  Used by the context manager to
              only touch what the technique actually changed.

    Returns a dict::

        {
            "restored": [list of param names successfully restored],
            "skipped":  [(param, reason) for params we couldn't write],
            "snapshot_path": <loot json file>,
        }

    Each write uses ``change_param`` (TH_CHANGE_PARAMETER).  A failed
    write is recorded under ``skipped`` so the operator sees which
    params were left in their mutated state; the remaining keys are
    still attempted.
    """
    out = {"restored": [], "skipped": [],
            "snapshot_path": snapshot.loot_path}

    if snapshot is None or not snapshot.params:
        out["skipped"].append(("<all>", "no baseline params captured"))
        return out

    targets = (list(only) if only is not None
               else list(snapshot.params.keys()))
    for pname in targets:
        original = snapshot.params.get(pname, "")
        if isinstance(original, str) and original.startswith("__UNCAPTURED__"):
            out["skipped"].append((pname, "param was uncapturable"))
            continue
        # Real write — TH_CHANGE_PARAMETER, dynamic, no profile rewrite.
        r = change_param(node, creds, pname, str(original))
        if r["ok"]:
            print(f"[+] {snapshot.sid}: evasion-restore — "
                  f"{pname}={original!r}")
            out["restored"].append(pname)
        else:
            print(f"[!] {snapshot.sid}: evasion-restore FAILED "
                  f"{pname}={original!r} — {r['error']}")
            out["skipped"].append((pname, r["error"]))

    return out


# ---------------------------------------------------------------------------
# Context manager — auto-capture, auto-restore
# ---------------------------------------------------------------------------

# Per-thread stack of (node, technique, snapshot, touched_params).
# A nested ``with evasion_window(...)`` block reuses the outer-most
# snapshot so we never double-capture, and restore only fires for the
# outermost frame.
_local = threading.local()


def _stack() -> list:
    if not hasattr(_local, "stack"):
        _local.stack = []
    return _local.stack


@contextmanager
def evasion_window(node, state, technique: str,
                    creds=None,
                    touched_params: Optional[list] = None) -> Iterator[dict]:
    """Run a Tier 3 mutation under a captured baseline.

    Usage::

        from sapmap_evasion_gate import assert_evasion_allowed
        from sapmap_evasion_baseline import evasion_window

        assert_evasion_allowed(state, node, technique="stad_silence")
        with evasion_window(node, state, "stad_silence",
                             touched_params=["stat/level"]) as w:
            # ... mutate ...
        # baseline auto-restored on exit

    The yielded value is a dict so call-sites can stash technique-
    specific snapshot data (e.g. NWA log-config XML) under
    ``snapshot.technique_state[technique]`` for restore later.
    """
    from sapmap_evasion_gate import assert_evasion_allowed
    # Re-assert the gate inside the window — defensive: a caller might
    # forget the call site assert.  Skip baseline requirement because
    # we're about to capture one.
    assert_evasion_allowed(state, node, technique, require_baseline=False)

    snap = capture_baseline(node, creds)
    if not snap.params:
        # Capture failed — refuse to proceed; nothing to restore to.
        from sapmap_evasion_gate import EvasionGateError
        raise EvasionGateError(
            technique,
            "Baseline capture returned empty; refusing to mutate state "
            "without a restore path.")

    frame = {
        "node": node, "technique": technique,
        "snapshot": snap,
        "touched_params": list(touched_params or []),
        "started_at": datetime.now().isoformat(),
    }
    _stack().append(frame)
    is_outermost = len(_stack()) == 1

    try:
        yield frame
    finally:
        # Always pop, even on exception
        _stack().pop()
        if is_outermost:
            try:
                restore_baseline(node, creds, snap,
                                  only=frame["touched_params"] or None)
            except Exception as e:
                logger.error(f"{snap.sid}: evasion-window restore "
                              f"failed for {technique}: {e}")
                print(f"[!] {snap.sid}: evasion-window restore "
                      f"FAILED for {technique}: {e}")


def active_window_count() -> int:
    """Returns the current depth of nested evasion windows on this
    thread.  Used by the GUI's status badge."""
    return len(_stack())
