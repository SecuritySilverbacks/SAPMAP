#!/usr/bin/env python3
# encoding: utf-8
"""
sap_logon_banner_scan — issue #68 PR3 glue layer.

Bridges the two libraries shipped in PR1 + PR2 into a single per-node
orchestrator the GUI route and the (future PR4) landscape sweep both call:

    PR1 ``sap_login_screen_texts.fetch_login_items``   (DIAG session)
    PR1 ``sap_login_screen_texts.collect_text_info``   (DYNT atom flatten)
    PR2 ``sap_logon_text_secrets.scan_text``           (regex catalogue)

``scan_node`` returns a structured dict the caller then (a) persists onto
the SAPNode so the GUI side-panel can read it back and (b) walks to emit
one ``emit_finding`` per hit.  All I/O and side effects live in this
module so the route handler stays route-shaped and the two libraries stay
pure.

Design notes
------------

*   fetch_login_items prints progress to stdout unconditionally (even
    with verbose=False).  Called from a background Bottle worker that
    is noisy enough already — this module redirects stdout around the
    call so the operator's console isn't blasted with
    "[*] Connecting to host:port" lines on every scan.

*   fetch_login_items raises OSError on connect-refused and ValueError
    on compressed DIAG responses; both are caught and surface as a
    ``{"ok": False, "error_kind": ..., "error": "..."}`` result rather
    than crashing the background thread.

*   Loot layout (one SID bucket, timestamped runs underneath):

        loot/logon_banners/<sid>/<ts>_<instance_nr>_<port>.txt
        loot/logon_banners/<sid>/<ts>_<instance_nr>_<port>.json

    .txt holds the raw DYNT-flattened field=value pairs the scanner
    saw; .json holds the findings list (same shape scan_text returns)
    plus the run metadata the GUI uses.  SIDs are filesystem-safe
    (uppercase letters + digits — SAP constraint), so no sanitisation
    needed before splicing them into the path.

*   Severity ladder follows ``sapmap_findings.SEVERITIES``
    (CRITICAL / HIGH / MEDIUM / INFO).  There is no LOW on the bus.

*   ATT&CK capability keys are declared in ``sapmap_attack.CAPABILITY_MAP``:

        recon.logon_banner_scan      - the scan action itself (T1082)
        creds.diag_login_screen_leak - clear-text credential disclosure
                                        on the banner (T1552.001)
        data.diag_login_screen_leak  - PII / infra data on the banner
                                        (T1213)

    ``scan_node`` tags each finding with the right key based on its
    ``category`` (credentials/token → creds.*; everything else →
    data.*; custom-pattern findings default to data.* unless the
    operator wrote their own prefix).
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import time
import types
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Capability-key routing — maps a scan_text finding's `category` to the
# right CAPABILITY_MAP key, so emit_finding resolves to the correct
# ATT&CK technique set at the route layer.
# ---------------------------------------------------------------------------

CAPABILITY_FOR_CATEGORY: Dict[str, str] = {
    "credentials":    "creds.diag_login_screen_leak",
    "token":          "creds.diag_login_screen_leak",
    "pii":            "data.diag_login_screen_leak",
    "network":        "data.diag_login_screen_leak",
    "custom":         "data.diag_login_screen_leak",
    "coverage":       "recon.logon_banner_scan",
    # NB: scan_text labels operator-regex compile errors as
    # category="custom" with error=True (NOT "parse_error") —
    # ``_route_capability`` below detects the error flag and
    # overrides the mapping back to the recon.* key so a bad
    # regex is not framed as a logon-banner leak.
}


def _route_capability(finding: dict) -> str:
    """Pick the capability key for one finding.  Routes custom-regex
    compile errors (``category == "custom"`` AND ``error is True``)
    to the recon.* key regardless of their nominal category — those
    are observations about the scanner itself, not a target leak.
    """
    cat = (finding.get("category") or "").lower()
    if finding.get("error") is True:
        return "recon.logon_banner_scan"
    return CAPABILITY_FOR_CATEGORY.get(cat, "data.diag_login_screen_leak")


# Severity strings accepted by ``sapmap_findings.emit_finding``.  Mirrored
# here so tests can assert the mapping without importing the whole bus.
_FINDINGS_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "INFO")


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def make_run_id(ts: Optional[str] = None) -> str:
    """Build a per-call correlation id.

    Shape ``logon_<YYYYMMDDTHHMMSSZ>_<6-hex>`` — mirrors the pwspray
    ``_make_run_id`` idiom so loot browsing feels consistent.  The
    6-hex tail is a sha256 slice of ``ts:pid:monotonic_ns``; the
    monotonic-nanosecond byte is what makes a rescan clicked twice
    inside the same wall-second still mint distinct ids (pwspray
    doesn't need this because its sweep mints one id up front, but
    the GUI per-node scanner can genuinely fire twice in <1s).
    """
    base_ts = ts or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tail = hashlib.sha256(
        f"{base_ts}:{os.getpid()}:{time.monotonic_ns()}"
        .encode("utf-8")).hexdigest()[:6]
    return f"logon_{base_ts}_{tail}"


def dispatcher_port_for(node) -> Tuple[int, str]:
    """Return ``(port, instance_nr)`` for the first dispatcher the scanner
    has observed on ``node``, or ``(0, "")`` if none.

    Mirrors ``sapmap_pwspray._node_dispatcher_port`` — we do NOT blind-
    guess ``3200 + instance_nr``; the port must have been labelled
    'dispatcher' or sit in 32XX by an earlier scan.
    """
    for inst in (getattr(node, "instances", None) or []):
        ports = getattr(inst, "ports", {}) or {}
        for port, svc in ports.items():
            if not isinstance(port, int):
                continue
            if svc == "dispatcher" or (3200 <= port <= 3299):
                return port, getattr(inst, "instance_nr", "") or ""
    return 0, ""


def is_abap_eligible(node) -> bool:
    """``True`` when ``node`` has an ABAP runtime that can serve a DIAG
    login screen.  Matches the pwspray / default_creds gate: upper-case
    + 'ABAP' substring so ``ABAP+JAVA`` dual-stacks stay eligible.
    """
    return "ABAP" in (getattr(node, "system_type", "") or "").upper()


def _flatten_items(pairs: Iterable[Tuple[str, str]]) -> str:
    """Join collect_text_info()'s (field, value) pairs into a single
    string the regex catalogue can walk.  Empty values are dropped so
    the catalogue's high-entropy / base64 heuristics don't match
    column labels; a tab between field and value keeps adjacency so
    ``_RE_USER_THEN_PASSWORD``'s 0..80-char window hits across the
    boundary.
    """
    chunks: List[str] = []
    for key, val in pairs:
        if not val:
            continue
        chunks.append(f"{key}\t{val}")
    return "\n".join(chunks)


def _random_terminal() -> str:
    """Local copy of ``sap_login_screen_texts._random_ip``.  The PR1
    library's version is module-private; duplicating 3 lines here keeps
    the import surface small and lets tests monkeypatch us independently.
    """
    import random
    return "%d.%d.%d.%d" % (random.randint(1, 223), random.randint(0, 255),
                             random.randint(0, 255), random.randint(1, 254))


def _write_loot(loot_dir: str,
                basename: str,
                raw_text: str,
                findings: List[dict],
                meta: dict) -> Tuple[str, str]:
    """Write ``<basename>.txt`` (raw banner text) and ``<basename>.json``
    (findings + metadata) into ``loot_dir``.  Returns ``(txt_path,
    json_path)``.
    """
    txt_path = os.path.join(loot_dir, f"{basename}.txt")
    json_path = os.path.join(loot_dir, f"{basename}.json")
    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write(raw_text or "")
    bundle = {
        "meta": meta,
        "findings": findings,
    }
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2, sort_keys=True)
    return txt_path, json_path


# ---------------------------------------------------------------------------
# Core orchestrator
# ---------------------------------------------------------------------------


def scan_node(host: str,
              port: int,
              *,
              sid: str = "",
              instance_nr: str = "",
              timeout: float = 10.0,
              saprouter: str = "",
              terminal: str = "",
              custom_patterns: Optional[Iterable[str]] = None,
              run_id: Optional[str] = None,
              loot_dir: Optional[str] = None,
              cancel_check: Optional[Callable[[], bool]] = None,
              _fetch_fn: Optional[Callable[..., Any]] = None,
              _collect_fn: Optional[Callable[..., Any]] = None,
              _scan_fn: Optional[Callable[..., Any]] = None,
              ) -> Dict[str, Any]:
    """Scrape the DIAG login banner of one node and classify its text.

    Returns a result dict with the shape:

        {
          "ok":              bool,
          "sid":             str,
          "host":            str,
          "port":            int,
          "instance_nr":     str,
          "run_id":          str,
          "ts":              str,     # ISO-8601 UTC
          "elapsed_s":       float,
          "raw_text_bytes":  int,
          "pair_count":      int,     # DYNT (field,value) pairs scanned
          "loot_text_path":  str,     # relative to CWD; "" when loot_dir None
          "loot_json_path":  str,
          "findings":        List[dict],  # scan_text output + capability key
          "hits_by_severity": Dict[str, int],
          "error_kind":      Optional[str],  # connect|short|compressed|exception
          "error":           Optional[str],  # human string
          "terminal":        str,
        }

    No ``emit_finding`` is called from here — the route handler does
    the bus write + node persistence.  This keeps the module unit-
    testable without pulling the findings module (or sapmap_state)
    into the test import graph.

    ``_fetch_fn`` / ``_collect_fn`` / ``_scan_fn`` are DI hooks for the
    unit tests; production code leaves them None and lazy-imports the
    real libraries.
    """
    t0 = time.monotonic()
    rid = run_id or make_run_id()
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    term = terminal or _random_terminal()

    # Lazy-import the real primitives.  Tests pass DI hooks instead.
    if _fetch_fn is None:
        try:
            from sap_login_screen_texts import fetch_login_items as _fetch_fn
        except Exception as exc:
            return _empty_result(
                sid, host, port, instance_nr, rid, ts, term, t0,
                error_kind="import", error=f"sap_login_screen_texts: {exc}")
    if _collect_fn is None:
        try:
            from sap_login_screen_texts import collect_text_info as _collect_fn
        except Exception as exc:
            return _empty_result(
                sid, host, port, instance_nr, rid, ts, term, t0,
                error_kind="import", error=f"collect_text_info: {exc}")
    if _scan_fn is None:
        try:
            from sap_logon_text_secrets import scan_text as _scan_fn
        except Exception as exc:
            return _empty_result(
                sid, host, port, instance_nr, rid, ts, term, t0,
                error_kind="import", error=f"sap_logon_text_secrets: {exc}")

    # Materialise custom_patterns once up front so a one-shot
    # iterable (generator) isn't exhausted before we count or forward
    # it a second time.
    custom_list = (list(custom_patterns)
                    if custom_patterns else None)

    if cancel_check and cancel_check():
        return _empty_result(
            sid, host, port, instance_nr, rid, ts, term, t0,
            error_kind="cancelled", error="scan cancelled before DIAG")

    opts = types.SimpleNamespace(
        route_string=saprouter or "",
        timeout=timeout,
        verbose=False,
    )

    items = None
    error_kind: Optional[str] = None
    error_msg: Optional[str] = None

    # Suppress the PR1 library's unconditional print()s so background
    # threads don't blast the operator's console.  Keep both stdout
    # and stderr clean; capture into a scratch buffer the test can
    # inspect if it wants.
    sink = io.StringIO()
    try:
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            items = _fetch_fn(host, port, opts, term)
    except OSError as exc:
        error_kind = "connect"
        error_msg = f"{type(exc).__name__}: {exc}"
    except ValueError as exc:
        # walk_items raises ValueError on compressed DIAG responses.
        error_kind = "compressed"
        error_msg = str(exc)
    except Exception as exc:  # pragma: no cover — defensive catch-all
        error_kind = "exception"
        error_msg = f"{type(exc).__name__}: {exc}"

    # Second cancel check after the DIAG round-trip — a mid-flight
    # STOP (operator hits the console STOP button while fetch_login_items
    # is still waiting on ni_recv) can at least abort the regex pass.
    if cancel_check and cancel_check():
        error_kind = error_kind or "cancelled"
        error_msg = error_msg or "scan cancelled mid-flight"

    pairs: List[Tuple[str, str]] = []
    if items is None and not error_kind:
        # fetch_login_items returns None on a too-short / missing response
        # (port is not a dispatcher, SNC enforced on this listener, etc.).
        error_kind = "short"
        error_msg = "no login screen received (short / missing DIAG response)"
    elif items is not None and error_kind != "cancelled":
        try:
            pairs = list(_collect_fn(items))
        except Exception as exc:  # pragma: no cover — defensive
            error_kind = "parse"
            error_msg = f"{type(exc).__name__}: {exc}"

    raw_text = _flatten_items(pairs) if pairs else ""

    context = {"sid": sid, "host": host, "port": port,
               "instance_nr": instance_nr, "run_id": rid}

    findings: List[dict] = []
    if (raw_text or error_kind is None) and error_kind != "cancelled":
        # Always run scan_text, even on empty text — pass
        # emit_info_on_empty=True so we get a coverage marker that
        # the GUI can show as "we checked this node".
        try:
            findings = _scan_fn(
                raw_text,
                custom_patterns=custom_list,
                context=context,
                emit_info_on_empty=True,
            )
        except Exception as exc:  # pragma: no cover — defensive
            error_kind = error_kind or "scan"
            error_msg = error_msg or f"{type(exc).__name__}: {exc}"
            findings = []

    # Tag each finding with the right capability key.  _route_capability
    # also demotes custom-regex compile-error findings (category==
    # "custom" + error=True) back to recon.* so a bad regex isn't
    # framed as a target leak.
    for f in findings:
        f["attack_capability"] = _route_capability(f)

    # Count only emittable findings so the summary pills don't show a
    # phantom INFO=1 on a clean banner (the coverage marker is counted
    # as INFO by scan_text but the route filters it out of the stored
    # finding list, which previously left the counter and the panel
    # body disagreeing).
    emittable = [f for f in findings
                 if (f.get("category") or "").lower() != "coverage"]
    hits_by_severity = _count_by_severity(emittable)

    loot_text_path = ""
    loot_json_path = ""
    if loot_dir and (raw_text or findings):
        basename = f"{rid}_{instance_nr or 'inst'}_{port}"
        try:
            loot_text_path, loot_json_path = _write_loot(
                loot_dir,
                basename,
                raw_text,
                findings,
                meta={
                    "sid": sid, "host": host, "port": port,
                    "instance_nr": instance_nr, "run_id": rid, "ts": ts,
                    "pair_count": len(pairs),
                    "raw_text_bytes": len(raw_text.encode("utf-8")),
                    "custom_pattern_count": len(custom_list or []),
                    "terminal": term,
                    "saprouter": bool(saprouter),
                    "error_kind": error_kind,
                },
            )
        except OSError as exc:  # pragma: no cover — disk full / perm denied
            error_kind = error_kind or "loot"
            error_msg = error_msg or f"loot write failed: {exc}"

    elapsed_s = round(time.monotonic() - t0, 3)

    return {
        "ok": error_kind is None,
        "sid": sid,
        "host": host,
        "port": port,
        "instance_nr": instance_nr,
        "run_id": rid,
        "ts": ts,
        "elapsed_s": elapsed_s,
        "raw_text_bytes": len(raw_text.encode("utf-8")) if raw_text else 0,
        "pair_count": len(pairs),
        "loot_text_path": loot_text_path,
        "loot_json_path": loot_json_path,
        "findings": findings,
        "hits_by_severity": hits_by_severity,
        "error_kind": error_kind,
        "error": error_msg,
        "terminal": term,
        "stdout_capture": sink.getvalue(),
    }


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _count_by_severity(findings: List[dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {s: 0 for s in _FINDINGS_SEVERITIES}
    for f in findings or []:
        sev = (f.get("severity") or "INFO").upper()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["INFO"] = counts.get("INFO", 0) + 1
    return counts


def _empty_result(sid: str, host: str, port: int, instance_nr: str,
                  run_id: str, ts: str, terminal: str, t0: float,
                  *, error_kind: str, error: str) -> Dict[str, Any]:
    return {
        "ok": False,
        "sid": sid,
        "host": host,
        "port": port,
        "instance_nr": instance_nr,
        "run_id": run_id,
        "ts": ts,
        "elapsed_s": round(time.monotonic() - t0, 3),
        "raw_text_bytes": 0,
        "pair_count": 0,
        "loot_text_path": "",
        "loot_json_path": "",
        "findings": [],
        "hits_by_severity": {s: 0 for s in _FINDINGS_SEVERITIES},
        "error_kind": error_kind,
        "error": error,
        "terminal": terminal,
        "stdout_capture": "",
    }
