"""Critical-finding bus for SAPMAP.

Independent of the GUI so scanner / exploit modules can call
``emit_finding(...)`` regardless of whether the pywebview frontend is
running.  The GUI attaches a listener at start-up so findings appear
inline in the banner, in the session drawer, and (highlighted) in the
console log.

Severities:
    CRITICAL  red     — pwned / SAP_ALL user / SecStore grabbed / RCE confirmed
    HIGH      orange  — vulnerability confirmed (GW / MS / SAProuter / CVE-2025-31324)
    MEDIUM    yellow  — elevated exposure short of full compromise
    INFO      blue    — informational chain / trust edge / impact hit

``emit_finding`` is cheap + idempotent: repeated calls with the same
(severity, node, msg) tuple within 60s are deduplicated.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Dict, List, Optional

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "INFO")

_findings: List[Dict] = []
_lock = threading.Lock()
_next_id = 1

_listeners: List[Callable[[Dict], None]] = []
_dedupe_window = 60.0          # seconds
_max_buffered = 500            # ring-buffer soft cap


def register_listener(fn: Callable[[Dict], None]) -> None:
    """Register a callback invoked synchronously for every new finding.

    The GUI uses this to feed the console-line renderer; CLI users get
    the stdout print regardless.  Exceptions in listeners are swallowed
    so a broken UI never stalls exploit progress.
    """
    _listeners.append(fn)


def emit_finding(severity: str, node: str, msg: str,
                 cve: Optional[str] = None,
                 ref: Optional[str] = None,
                 meta: Optional[Dict] = None) -> Optional[Dict]:
    """Publish a finding.  Returns the stored record, or None if dropped
    (e.g. severity rejected, or deduped against a recent identical entry).
    """
    sev = (severity or "").strip().upper()
    if sev not in SEVERITIES:
        sev = "INFO"
    node = (node or "").strip() or "?"
    msg = (msg or "").strip()
    if not msg:
        return None

    now = time.time()
    global _next_id
    with _lock:
        # Dedupe: skip if an identical entry was raised in the dedupe window.
        for existing in reversed(_findings):
            if now - existing["ts"] > _dedupe_window:
                break
            if (existing["severity"] == sev
                    and existing["node"] == node
                    and existing["msg"] == msg):
                return None

        record = {
            "id": _next_id,
            "ts": now,
            "severity": sev,
            "node": node,
            "msg": msg,
            "cve": cve or "",
            "ref": ref or "",
            "meta": dict(meta or {}),
        }
        _next_id += 1
        _findings.append(record)
        if len(_findings) > _max_buffered:
            # Drop the oldest — the API cursor is monotonic on id, not index.
            del _findings[:len(_findings) - _max_buffered]

    # 1. Visible to operators running the CLI scanner directly.
    emoji = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "INFO": "*"}[sev]
    try:
        print(f"[{emoji}FINDING {sev}{emoji}] {node}: {msg}"
              + (f"  ({cve})" if cve else ""))
    except Exception:
        pass

    # 2. GUI listeners — banner, drawer, console highlight.
    for fn in list(_listeners):
        try:
            fn(dict(record))
        except Exception:
            pass

    return record


def get_since(cursor_id: int) -> Dict:
    """Return {'findings': [...], 'cursor': <last id>} for polling APIs."""
    with _lock:
        newer = [dict(r) for r in _findings if r["id"] > cursor_id]
        last_id = _findings[-1]["id"] if _findings else cursor_id
    return {"findings": newer, "cursor": last_id}


def clear() -> None:
    """Wipe the findings buffer (called when a new scan begins)."""
    with _lock:
        _findings.clear()
