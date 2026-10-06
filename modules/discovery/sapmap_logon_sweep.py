#!/usr/bin/env python3
# encoding: utf-8
"""
sapmap_logon_sweep — issue #68 PR4 landscape engine.

Iterates every ABAP node in a ``SAPMAPState`` that has an observed
32XX dispatcher and runs the PR3 ``scan_node`` orchestrator against
each one, sequentially, with inter-node jitter.  Writes a run-scoped
loot bundle under ``loot/logon_banners/<run_id>/`` and appends one
summary dict to ``state.logon_banner_runs`` when the sweep ends.

GUI contract (mirrored on the pwspray / AutoPwn precedents):

*   ``_status`` is a MODULE-GLOBAL dataclass instance.  The GUI route
    is a thin ~10-line delegate that returns ``get_status()``.  Only
    the one ``_bg`` thread spawned by the launch route mutates
    ``_status``; Bottle GET request threads only read.

*   The launch route must (a) 409-refuse when ``get_status().running``
    is already True — ``_bg`` unconditionally resets
    ``sapmap_stop.reset_stop()`` so a second launch would clobber a
    running sweep's STOP flag — and (b) call ``_reset_status(...)``
    SYNCHRONOUSLY before ``_bg`` hands off, so the first ``/status``
    poll from the frontend doesn't see ``running=False`` and early-
    return the poll loop.

*   STOP piggybacks on the single global ``/api/scan/stop`` channel
    (``sapmap_stop.is_stop_requested``).  No feature-specific stop
    route.

Cleartext hygiene
-----------------

The status singleton and the ``state.logon_banner_runs`` summaries
NEVER carry the raw matched text.  The side-panel source
(``node.logon_banner_findings``) carries the match on purpose — the
operator asked to see what was leaked — but every landscape-level
roll-up (status, runs history, engagement report row count) uses only
severity counts + sha256 fingerprints that PR3's route already
produces.
"""

from __future__ import annotations

import hashlib
import os
import random
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Phase ordering — the frontend's progress-panel keys off this.  Both
# sides are pinned by a test so a future rename on one half can't
# silently desync the UI.
# ---------------------------------------------------------------------------

PHASE_ORDER: Tuple[str, ...] = (
    "idle",
    "collect_targets",
    "scan",
    "report",
    "done",
)


# ---------------------------------------------------------------------------
# Config + status
# ---------------------------------------------------------------------------


@dataclass
class LogonSweepConfig:
    """Operator-facing knobs the GUI/MCP/script-step surfaces.

    ``single_sid`` empty / ``""`` = whole landscape; any value = scope
    the sweep to that one SID (same convention as pwspray).  ``sids``
    is the alternative multi-select path PR4 adds — if non-empty, the
    sweep iterates exactly that list in order (and ignores
    ``single_sid``).
    """

    single_sid: str = ""
    sids: List[str] = field(default_factory=list)
    custom_patterns: List[str] = field(default_factory=list)
    # Inter-node jitter so an operator can tell "SAPMAP is sweeping"
    # from "someone's spraying our dispatcher" when the SAL arrives
    # on each node.  Range picked to match pwspray's 1–2s inter-node
    # delay; set jitter_max_s=0 in tests to disable.
    jitter_min_s: float = 0.5
    jitter_max_s: float = 1.5
    # Per-node DIAG timeout.  10s is the pwspray / default_creds default.
    per_node_timeout_s: float = 10.0

    def normalised_scope(self) -> str:
        if self.sids:
            return f"sids:{len(self.sids)}"
        if self.single_sid:
            return f"single:{self.single_sid}"
        return "landscape"


@dataclass
class LogonSweepStatus:
    """Status singleton the GUI polls."""

    running: bool = False
    finished: bool = False
    phase: str = "idle"
    phase_progress: Tuple[int, int] = (0, 0)
    run_id: str = ""
    scope: str = ""
    targets_total: int = 0
    targets_done: int = 0
    findings_critical: int = 0
    findings_high: int = 0
    findings_medium: int = 0
    findings_info: int = 0
    errors: int = 0
    aborted: str = ""
    started_at: str = ""
    finished_at: str = ""
    log_tail: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        # json.dumps serialises a tuple as an array anyway, but
        # downstream Python callers of get_status() must see a list
        # per the pwspray contract and its pinning test.
        d["phase_progress"] = list(d["phase_progress"])
        return d


_LOG_TAIL_MAX = 200
_status: LogonSweepStatus = LogonSweepStatus()

# Guards the ``check running + seed running=True`` transition on the
# POST launch path.  Without it, two near-simultaneous launch requests
# could both observe ``running=False`` in the 409 guard, both call
# ``_reset_status`` and both spawn ``_bg`` threads — clobbering the
# single-writer invariant and resetting the global STOP flag mid-
# sweep.  Routes acquire this lock via ``acquire_launch_slot`` below.
_launch_lock = threading.Lock()


def get_status() -> dict:
    """Snapshot the status singleton for the GUI/MCP/scripts."""
    return _status.to_dict()


def _reset_status(**init) -> LogonSweepStatus:
    """Replace the module-global ``_status`` with a fresh running-shape.

    MUST be called from the launch route SYNCHRONOUSLY — before the
    ``_bg`` hand-off — so the frontend's first poll after launch sees
    ``running=True``.
    """
    global _status
    _status = LogonSweepStatus(running=True, phase="collect_targets", **init)
    return _status


def acquire_launch_slot(**init) -> bool:
    """Atomic "no sweep already running → mark it running + seed init
    args" transition.  Returns True when the slot was reserved, False
    when a sweep is already in flight.  Routes call this once before
    ``_bg(...)`` to close the 409-guard-vs-reset-status TOCTOU race.
    """
    with _launch_lock:
        if _status.running:
            return False
        _reset_status(**init)
        return True


def _set_phase(name: str) -> None:
    _status.phase = name


def _set_phase_progress(cur: int, total: int) -> None:
    _status.phase_progress = (int(cur), int(total))


def _bump_targets_done() -> None:
    _status.targets_done += 1


def _bump_errors() -> None:
    _status.errors += 1


def _append_log(line: str) -> None:
    _status.log_tail.append(line)
    if len(_status.log_tail) > _LOG_TAIL_MAX:
        del _status.log_tail[0:len(_status.log_tail) - _LOG_TAIL_MAX]


def _add_hits(hits_by_severity: dict) -> None:
    _status.findings_critical += int(hits_by_severity.get("CRITICAL", 0) or 0)
    _status.findings_high     += int(hits_by_severity.get("HIGH", 0) or 0)
    _status.findings_medium   += int(hits_by_severity.get("MEDIUM", 0) or 0)
    _status.findings_info     += int(hits_by_severity.get("INFO", 0) or 0)


def _finalise_status(aborted: str = "") -> None:
    _status.running = False
    _status.finished = True
    _status.phase = "done"
    _status.aborted = aborted or ""
    if not _status.finished_at:
        _status.finished_at = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Target enumeration
# ---------------------------------------------------------------------------


def _node_dispatcher_port(node) -> Tuple[int, str]:
    """Mirror of the per-node orchestrator's helper — (port, instance_nr)
    for the first dispatcher the scanner has observed, or (0, '') if
    none.  Does NOT blind-guess 3200+instance_nr."""
    for inst in (getattr(node, "instances", None) or []):
        ports = getattr(inst, "ports", {}) or {}
        for port, svc in ports.items():
            if not isinstance(port, int):
                continue
            if svc == "dispatcher" or (3200 <= port <= 3299):
                return port, getattr(inst, "instance_nr", "") or ""
    return 0, ""


def _is_abap(node) -> bool:
    return "ABAP" in (getattr(node, "system_type", "") or "").upper()


def enumerate_targets(state, cfg: LogonSweepConfig) -> List[dict]:
    """Walk the state and return the ordered list of nodes to scan.

    Each entry: ``{sid, host, port, instance_nr, saprouter, node}``.

    Scope rules:
      * ``cfg.sids`` non-empty → iterate exactly that list, in order,
        dropping any SID that isn't on the map / isn't ABAP / has no
        dispatcher.
      * ``cfg.single_sid`` set → iterate only that SID.
      * else → every node on the map that passes the ABAP + dispatcher
        filters.
    """
    want: Optional[List[str]] = None
    if cfg.sids:
        # De-dupe preserving operator order so the frontend's
        # sids_count stat matches the actual target count.
        want = list(dict.fromkeys(s for s in cfg.sids if s))
    elif cfg.single_sid:
        want = [cfg.single_sid]

    nodes_by_sid = dict(getattr(state, "nodes", {}) or {})
    order: List[str] = want if want is not None else sorted(nodes_by_sid.keys())

    targets: List[dict] = []
    for sid in order:
        node = nodes_by_sid.get(sid)
        if node is None:
            continue
        if not _is_abap(node):
            continue
        host = (getattr(node, "ip", "")
                or getattr(node, "hostname", "")
                or "")
        if not host:
            continue
        port, inst_nr = _node_dispatcher_port(node)
        if not port:
            continue
        targets.append({
            "sid": sid,
            "host": host,
            "port": port,
            "instance_nr": inst_nr,
            "saprouter": getattr(node, "saprouter", "") or "",
            "node": node,
        })
    return targets


# ---------------------------------------------------------------------------
# Run id / loot
# ---------------------------------------------------------------------------


def make_run_id() -> str:
    """``logonsweep_<YYYYMMDDTHHMMSSZ>_<6-hex>`` — mirrors pwspray's
    ``_make_run_id`` with monotonic-ns disambiguation so a double-click
    launch (defended against anyway by the 409 guard) can't collide."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tail = hashlib.sha256(
        f"{ts}:{os.getpid()}:{time.monotonic_ns()}".encode("utf-8")
    ).hexdigest()[:6]
    return f"logonsweep_{ts}_{tail}"


def _resolve_loot_dir(run_id: str) -> str:
    """``loot/logon_banners/<run_id>/`` via ensure_loot_dir; fallback
    to a scratch dir under /tmp if sapmap_state isn't importable (so
    unit tests outside the package don't need a loot/ writable).
    """
    try:
        from sapmap_state import ensure_loot_dir
    except Exception:
        base = os.path.join("/tmp", "sapmap_loot_logon_banners", run_id)
        os.makedirs(base, exist_ok=True)
        return base
    base = ensure_loot_dir(f"logon_banners/{run_id}")
    os.makedirs(base, exist_ok=True)
    return base


# ---------------------------------------------------------------------------
# Core orchestrator
# ---------------------------------------------------------------------------


def sweep_landscape(
        state,
        cfg: LogonSweepConfig,
        *,
        cancel_check: Optional[Callable[[], bool]] = None,
        on_node_finding: Optional[Callable[[str, dict, dict], None]] = None,
        _scan_node_fn: Optional[Callable[..., dict]] = None,
        _sleep_fn: Optional[Callable[[float], None]] = None,
        ) -> dict:
    """Run the sweep end-to-end.  Returns the per-run summary dict
    the caller should also append to ``state.logon_banner_runs``.

    ``on_node_finding(sid, finding, result)`` — if provided, called
    once per emittable finding so the GUI route can emit_finding +
    update node fields exactly as the per-node PR3 route does.  Keeps
    the engine decoupled from sapmap_findings / sapmap_gui so unit
    tests can drive it without those modules.

    ``_scan_node_fn`` / ``_sleep_fn`` are DI hooks for the tests;
    production code leaves them None and lazy-imports / uses real
    sleep.
    """
    # DI defaults
    if _scan_node_fn is None:
        from sap_logon_banner_scan import scan_node as _scan_node_fn
    if _sleep_fn is None:
        _sleep_fn = time.sleep

    # Capture before mutating _status so we can plumb a stable value
    # into every per-node scan.
    run_id = make_run_id()
    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    scope_label = cfg.normalised_scope()

    _status.run_id = run_id
    _status.scope = scope_label
    _status.started_at = started_at
    _append_log(f"[+] run_id={run_id} scope={scope_label}")

    # Phase 1 — target enumeration.
    _set_phase("collect_targets")
    targets = enumerate_targets(state, cfg)
    _status.targets_total = len(targets)
    _set_phase_progress(0, len(targets))
    _append_log(
        f"[+] eligible targets: {len(targets)}"
        f" (ABAP + 32XX dispatcher)")

    if cancel_check and cancel_check():
        _finalise_status(aborted="cancelled before scan")
        summary = _build_summary(
            run_id, started_at, scope_label, len(targets), 0, "",
            aborted="cancelled before scan")
        # Mirror the mid-sweep cancel branch: persist the summary to
        # state.logon_banner_runs so the GUI history tab + MCP /runs
        # see even the aborted-before-anything-scanned run.
        _append_run_to_state(state, summary)
        return summary

    # Phase 2 — per-node scan.
    _set_phase("scan")
    loot_dir = _resolve_loot_dir(run_id)
    per_node_results: List[dict] = []

    for i, t in enumerate(targets):
        if cancel_check and cancel_check():
            _append_log(f"[!] STOP honoured — stopping before {t['sid']}")
            _finalise_status(aborted="cancelled mid-sweep")
            summary = _build_summary(
                run_id, started_at, scope_label,
                len(targets), i, loot_dir,
                aborted="cancelled mid-sweep",
                per_node=per_node_results)
            _append_run_to_state(state, summary)
            return summary

        _set_phase_progress(i, len(targets))
        _append_log(
            f"[*] {t['sid']} :{t['port']} (inst {t['instance_nr']}) "
            f"— scanning")

        try:
            result = _scan_node_fn(
                t["host"], t["port"],
                sid=t["sid"],
                instance_nr=t["instance_nr"],
                saprouter=t["saprouter"],
                custom_patterns=cfg.custom_patterns or None,
                run_id=f"{run_id}__{t['sid']}",
                loot_dir=loot_dir,
                timeout=cfg.per_node_timeout_s,
                cancel_check=cancel_check,
            )
        except Exception as exc:
            # Build a synthetic result dict so downstream bookkeeping
            # + the host callback see a consistent shape (vs the
            # earlier `continue` which skipped the callback and the
            # inter-node jitter, hammering the dispatcher back-to-
            # back exactly like a password spray — the thing the
            # jitter was added to look different from).
            result = {
                "ok": False,
                "sid": t["sid"],
                "host": t["host"],
                "port": t["port"],
                "instance_nr": t["instance_nr"],
                "run_id": f"{run_id}__{t['sid']}",
                "ts": "",
                "elapsed_s": 0.0,
                "pair_count": 0,
                "raw_text_bytes": 0,
                "hits_by_severity":
                    {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0},
                "loot_text_path": "",
                "loot_json_path": "",
                "error_kind": "exception",
                "error": f"{type(exc).__name__}: {exc}",
                "findings": [],
            }
            _append_log(
                f"[-] {t['sid']}: scan raised "
                f"{type(exc).__name__}: {exc}")

        err_kind = result.get("error_kind")
        # Cancelled scans are NOT errors — they're the operator's
        # STOP arriving mid-flight.  Don't double-count them in the
        # error tally; the sweep's outer cancel-check will see the
        # same STOP flag and finalise the sweep on the next iter.
        if err_kind and err_kind != "cancelled":
            _bump_errors()
            _append_log(
                f"[-] {t['sid']}: error={err_kind} "
                f"({result.get('error') or ''})")
        elif err_kind == "cancelled":
            _append_log(
                f"[!] {t['sid']}: scan reported mid-flight cancel")
        else:
            _append_log(
                f"[+] {t['sid']}: {result.get('pair_count', 0)} field(s), "
                f"CRIT={result['hits_by_severity'].get('CRITICAL', 0)} "
                f"HIGH={result['hits_by_severity'].get('HIGH', 0)} "
                f"MED={result['hits_by_severity'].get('MEDIUM', 0)}")

        hits = result.get("hits_by_severity") or {}
        _add_hits(hits)
        per_node_results.append({
            "sid": t["sid"],
            "ok": result.get("ok", False),
            "error_kind": result.get("error_kind"),
            "error": result.get("error"),
            "hits_by_severity": dict(hits),
            "pair_count": result.get("pair_count", 0),
            "loot_text_path": result.get("loot_text_path", ""),
            "loot_json_path": result.get("loot_json_path", ""),
            "elapsed_s": result.get("elapsed_s", 0.0),
            "run_id": result.get("run_id", ""),
        })

        # Hand each finding to the host (route) so it can emit_finding
        # + update node.logon_banner_scan / logon_banner_findings
        # exactly as PR3's per-node route does.  Called on EVERY
        # iteration, including the exception path, so the per-node
        # side-panel reflects the crash (error_kind='exception')
        # instead of showing stale pre-crash data.
        if on_node_finding is not None:
            try:
                on_node_finding(t["sid"], result, t["node"])
            except Exception as cb_exc:  # pragma: no cover — defensive
                _append_log(
                    f"[-] {t['sid']}: on_node_finding callback raised "
                    f"{type(cb_exc).__name__}: {cb_exc}")

        _bump_targets_done()
        _set_phase_progress(i + 1, len(targets))

        # Inter-node jitter — only between nodes, not after the last.
        # Fires on every path (including exception) so a sweep whose
        # scans all fail doesn't burst the dispatcher back-to-back.
        if i < len(targets) - 1 and cfg.jitter_max_s > 0:
            delay = random.uniform(
                max(0.0, cfg.jitter_min_s),
                max(cfg.jitter_min_s, cfg.jitter_max_s))
            _sleep_fn(delay)

    # Phase 3 — report.
    _set_phase("report")
    _append_log(
        f"[+] sweep complete: targets={_status.targets_total} "
        f"CRIT={_status.findings_critical} "
        f"HIGH={_status.findings_high} "
        f"MED={_status.findings_medium} "
        f"errors={_status.errors}")

    summary = _build_summary(
        run_id, started_at, scope_label,
        len(targets), _status.targets_done, loot_dir,
        aborted="",
        per_node=per_node_results)
    _append_run_to_state(state, summary)
    _finalise_status(aborted="")
    return summary


# ---------------------------------------------------------------------------
# Summary + state append
# ---------------------------------------------------------------------------


def _build_summary(run_id: str, started_at: str, scope: str,
                    targets_total: int, targets_done: int,
                    loot_dir: str,
                    *,
                    aborted: str,
                    per_node: Optional[List[dict]] = None) -> dict:
    finished_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "run_id":         run_id,
        "started_at":     started_at,
        "finished_at":    finished_at,
        "scope":          scope,
        "targets_total":  int(targets_total),
        "targets_done":   int(targets_done),
        "findings_by_severity": {
            "CRITICAL": int(_status.findings_critical),
            "HIGH":     int(_status.findings_high),
            "MEDIUM":   int(_status.findings_medium),
            "INFO":     int(_status.findings_info),
        },
        "errors_count":  int(_status.errors),
        "loot_dir":      loot_dir or "",
        "aborted":       aborted or "",
        "per_node":      list(per_node or []),
    }


def _append_run_to_state(state, summary: dict) -> None:
    """Append the summary to ``state.logon_banner_runs``.  Python
    list.append is atomic under the GIL and the GET /runs route reads
    via ``list(state.logon_banner_runs or [])`` so no lock is needed
    for the current single-sweep-at-a-time pattern.
    """
    if state is None:
        return
    if not hasattr(state, "logon_banner_runs"):
        return
    try:
        state.logon_banner_runs.append(summary)
    except Exception:  # pragma: no cover — defensive
        pass
