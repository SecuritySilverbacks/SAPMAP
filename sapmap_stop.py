#!/usr/bin/env python3
"""Process-wide stop signal for SAPMAP background operations.

The GUI's STOP button used to only cancel two things: the active scan
(via SAPMAPApi.cancel_event) and registered 10KBlaze betrusted runs.
Everything else — RFC bulk tests, secstore extracts, JSP deploys,
user-creation chains — kept running until completion.

This module exposes ONE process-wide threading.Event that the STOP
button sets and any long-running operation can poll at safe points.

Usage:
    from sapmap_stop import is_stop_requested, request_stop, reset_stop

    def long_running_loop():
        for item in big_list:
            if is_stop_requested():
                print("[!] Stop requested — bailing out of long loop")
                return
            do_work(item)

    # GUI:
    request_stop()   # STOP button
    reset_stop()    # Start of next scan / operation

The event is intentionally a single global rather than per-task so
NEW callers can poll it without plumbing a cancel_event through
half a dozen function-signature changes.  Per-task events (e.g.
scanner.cancel_event, betrusted_stop_event) remain in place and are
ALSO set by the STOP path so existing cancel-aware code still works.
"""

from __future__ import annotations

import threading

_GLOBAL_STOP: threading.Event = threading.Event()


def is_stop_requested() -> bool:
    """Return True if the operator has pressed STOP."""
    return _GLOBAL_STOP.is_set()


def request_stop() -> None:
    """Signal every poll-point to bail.  Idempotent."""
    _GLOBAL_STOP.set()


def reset_stop() -> None:
    """Clear the stop flag.  Call at the start of any user-initiated
    operation (scan, secstore extract, propagation) so prior STOP
    presses don't cancel the new run before it begins."""
    _GLOBAL_STOP.clear()


def stop_event() -> threading.Event:
    """Return the underlying event for callers that want to wait on
    it (e.g. loops with sleep — use ``stop_event().wait(secs)``
    instead of ``time.sleep(secs)`` so STOP cuts the wait short)."""
    return _GLOBAL_STOP


__all__ = [
    "is_stop_requested",
    "request_stop",
    "reset_stop",
    "stop_event",
]
