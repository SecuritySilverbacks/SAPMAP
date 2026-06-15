"""Read-only ABAP telemetry / audit-posture probe.

Tier 1 OPSEC enrichment described in
``docs/research/13_detection_evasion_plan.md`` §6.1.  Captures, over RFC
with operator credentials, what audit + trace surfaces are on or off on
an ABAP node so the operator can see the SOC posture **before** taking
any action.  No writes, no tampering — every primitive here is a plain
read.

Detections:
  D1 — SAL on/off + filter-slot count + scope (narrow vs broad)
  D2 — ``rsau/integrity`` (HMAC signing of .AUD files)
  D3 — ``rsau/ip_only`` (terminal-name spoof viability, Troopers14 §4.A.18)
  D4 — ``rec/client`` (DBTABLOG), ``stat/level`` (STAD),
        ``gw/log_level`` (gateway trace), ``rdisp/TRACE`` (work-process)

How profile parameter values are read:
  TPFYPROPTY is *not* a real transparent table — profile parameter
  runtime values live in kernel shared memory, not in any DDIC view.
  RFC_READ_TABLE on it raises ``AD 718 TABLE_WITHOUT_DATA``.

  Retrieval uses the RFC-enabled kernel FM ``TH_GET_PARAMETER`` (one
  round-trip per parameter, parameter name is **case-sensitive** —
  ``rec/client`` and ``REC/CLIENT`` are not the same key).  This is
  much lighter than ``RFC_ABAP_INSTALL_AND_RUN`` (no ABAP install,
  no AUM/AUW SAL events) and works on every modern kernel.

Failure modes:
  - No SAP_ALL  → ``AbapTelemetryProfile.error="unauth"``
  - Older kernel without ``RSAU_PERS`` → fall through to ``RSAUPROF``;
    when both are empty → ``sal_state`` falls back to the global
    ``rsau/enable`` value we got from C_SAPGPARAM
  - TH_GET_PARAMETER blocked / not exposed → params reported as
    "blocked"; SAL slot read still runs
  - Individual parameter raises → that one param is marked "unknown",
    the others continue
  - RFC call raises → cache the short error on the profile, do not crash
"""

from __future__ import annotations

import logging
from typing import Optional

from sapmap_errors import format_rfc_exception
from sapmap_models import AbapTelemetryProfile, Credentials, SAPNode
import sapmap_rfc

logger = logging.getLogger(__name__)

# Kernel-default values for the parameters we probe.  Used as a hint in
# the rendered finding when the parameter is unset (kernel default
# applies).  Sourced from SAP Notes referenced in the research plan.
_KERNEL_DEFAULTS = {
    "rsau/enable":      "0",   # OFF by default on stock kernels
    "rsau/integrity":   "1",   # ≥ 7.5: HMAC on by default
    "rsau/ip_only":     "1",   # ≥ 7.5x: client-supplied terminal name ignored
    "rec/client":       "OFF",
    "stat/level":       "1",
    "gw/log_level":     "1",
    "rdisp/TRACE":      "1",
}

# Params probed via C_SAPGPARAM (one ABAP report, one round-trip)
_PROBED_PARAMS = [
    "rsau/enable", "rsau/integrity", "rsau/ip_only",
    "rec/client", "stat/level", "gw/log_level", "rdisp/TRACE",
]


def read_abap_telemetry(node: SAPNode,
                        creds: Optional[Credentials] = None
                        ) -> AbapTelemetryProfile:
    """Probe an ABAP node's audit + trace configuration.

    Returns an :class:`AbapTelemetryProfile`.  Always returns a profile
    object; failures are recorded in ``profile.error`` rather than
    raised, so callers can pin the result onto the node either way.
    """
    profile = AbapTelemetryProfile()
    errors = []

    with _open_or_record_error(node, creds, errors) as conn:
        if conn is None:
            profile.error = "; ".join(errors)
            return profile

        # ---- D2/D3/D4: profile parameters via C_SAPGPARAM ----
        try:
            raw = _read_profile_params(conn)
            profile.raw_params = raw
            profile.sal_integrity = _bool_param(raw, "rsau/integrity")
            profile.sal_source_ip_only = _bool_param(raw, "rsau/ip_only")
            profile.rec_client = (
                _str_param(raw, "rec/client").upper() or "OFF")
            profile.stat_level = _str_param(raw, "stat/level")
            profile.gw_log_level = _str_param(raw, "gw/log_level")
            profile.rdisp_trace = _str_param(raw, "rdisp/TRACE")
        except Exception as e:
            msg = format_rfc_exception(e).split("\n")[0][:200]
            logger.debug(f"{node.sid}: C_SAPGPARAM read failed: {msg}")
            errors.append(f"params blocked ({msg})")
            profile.raw_params = {}
            for k in ("sal_integrity", "sal_source_ip_only", "rec_client",
                      "stat_level", "gw_log_level", "rdisp_trace"):
                setattr(profile, k, "blocked")

        # ---- D1: SAL state + filter slots ----
        sal_enable_param = profile.raw_params.get("rsau/enable", "")
        try:
            sal_state, n_slots, scope = _read_sal_config(
                conn, sal_enable_param)
            profile.sal_state = sal_state
            profile.sal_filter_slots = n_slots
            profile.sal_filter_scope = scope
        except Exception as e:
            msg = format_rfc_exception(e).split("\n")[0][:200]
            logger.debug(f"{node.sid}: SAL config read failed: {msg}")
            errors.append(f"SAL config blocked ({msg})")
            profile.sal_state = "unknown"

    profile.error = "; ".join(errors)
    return profile


# ---------------------------------------------------------------------------
# Connection helper — keeps the open/close lifecycle out of the main flow
# ---------------------------------------------------------------------------

class _ConnCM:
    def __init__(self, node, creds, errors):
        self._node = node
        self._creds = creds
        self._errors = errors
        self._cm = None
        self._conn = None

    def __enter__(self):
        try:
            self._cm = sapmap_rfc._get_connection(self._node, self._creds)
            self._conn = self._cm.__enter__()
            return self._conn
        except Exception as e:
            msg = format_rfc_exception(e).split("\n")[0][:200]
            logger.debug(f"{self._node.sid}: RFC connect failed: {msg}")
            self._errors.append(f"RFC connect failed: {msg}")
            return None

    def __exit__(self, et, ev, tb):
        if self._cm is not None:
            try:
                self._cm.__exit__(et, ev, tb)
            except Exception:
                pass


def _open_or_record_error(node, creds, errors):
    return _ConnCM(node, creds, errors)


# ---------------------------------------------------------------------------
# D2/D3/D4 — profile parameter values via TH_GET_PARAMETER
# ---------------------------------------------------------------------------

def _read_profile_params(conn) -> dict:
    """Return ``{parname: parvalue}`` for every probed parameter.

    Calls the RFC-enabled kernel FM ``TH_GET_PARAMETER`` once per name.
    Parameter names are **case-sensitive** — ``rec/client`` is *not*
    the same key as ``REC/CLIENT``; that's why ``_PROBED_PARAMS`` is
    hand-written in canonical form.

    Per-parameter failures are tolerated: if one name raises (e.g.
    kernel doesn't recognise it) the rest still complete.  An outright
    failure (FM missing entirely, or first call raises with a non-
    "parameter not found" reason) propagates so the caller can mark
    the whole D2/D3/D4 slice as blocked.

    Different kernel releases return the value under one of:
    ``PARAMETER_VALUE``, ``VALUE`` or ``RETURN_VALUE``.  We accept all
    three.
    """
    out = {}
    fm_failed_hard = False
    fm_error = ""
    for parname in _PROBED_PARAMS:
        try:
            r = conn.call("TH_GET_PARAMETER", PARAMETER_NAME=parname)
            value = (r.get("PARAMETER_VALUE")
                     or r.get("VALUE")
                     or r.get("RETURN_VALUE")
                     or "")
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace")
            out[parname] = value.strip() if isinstance(value, str) else value
        except Exception as e:
            msg = format_rfc_exception(e).split("\n")[0][:160]
            # A genuine "parameter not found" is fine — record empty,
            # let the default-aware renderer decide what to display.
            # A "function module not exposed" / "no auth" kills the
            # whole slice; remember it for the caller.
            low = msg.lower()
            if ("not found" in low or "does not exist" in low
                    or "parameter_unknown" in low):
                out[parname] = ""
                continue
            fm_failed_hard = True
            fm_error = msg
            break
    if fm_failed_hard and not out:
        raise RuntimeError(fm_error or "TH_GET_PARAMETER failed")
    return out


def _bool_param(raw: dict, name: str) -> str:
    """Normalise a numeric/bool-ish parameter value to ``on``/``off``.

    Unset → default-aware ``on``/``off``.  Anything we can't classify
    becomes ``unknown`` so the operator sees the raw value separately.
    """
    if name in raw and raw[name] != "":
        v = raw[name].strip().lower()
        if v in ("1", "x", "y", "on", "true"):
            return "on"
        if v in ("0", "n", "off", "false"):
            return "off"
        return f"unknown ({v!r})"
    default = _KERNEL_DEFAULTS.get(name, "")
    if default == "1":
        return "on (default)"
    if default == "0":
        return "off (default)"
    return "unset"


def _str_param(raw: dict, name: str) -> str:
    """Return the raw value, or ``"<default> (default)"`` if unset."""
    if name in raw and raw[name] != "":
        return raw[name]
    default = _KERNEL_DEFAULTS.get(name, "")
    return f"{default} (default)" if default else "unset"


# ---------------------------------------------------------------------------
# D1 — SAL state + filter scope
# ---------------------------------------------------------------------------

def _read_sal_config(conn, sal_enable_param: str) -> tuple:
    """Return ``(sal_state, n_filter_slots, scope)``.

    Modern path: ``RFC_READ_TABLE`` on ``RSAU_PERS`` (≥ 7.5).  Older
    NetWeaver path: ``RSAUPROF``.  When both come back empty we trust
    the ``rsau/enable`` value that ``read_profile_params`` already
    fetched (caller passes the raw value in).

    Scope classification:
      - any populated slot whose USERSEL='*' AND CLISEL='*'    → ``broad``
      - any populated slot otherwise                            → ``narrow``
      - zero populated slots                                    → ``""``
    """
    # Derive on/off from the kernel parameter we already read.
    v = (sal_enable_param or "").strip().lower()
    if v in ("1", "x", "on", "true"):
        sal_state = "on"
    elif v in ("0", "n", "off", "false"):
        sal_state = "off"
    elif v == "":
        sal_state = "off (default)"
    else:
        sal_state = f"unknown ({v!r})"

    # Filter slots — try modern RSAU_PERS first, then RSAUPROF.  We
    # gracefully treat both 'table not found' and 'no data' as "0 slots
    # populated" — that's a real and informative state.
    slot_rows = []
    for tab in ("RSAU_PERS", "RSAUPROF"):
        try:
            r = conn.call(
                "RFC_READ_TABLE",
                QUERY_TABLE=tab,
                DELIMITER="|",
                FIELDS=[{"FIELDNAME": "USERSEL"},
                        {"FIELDNAME": "CLISEL"}],
                ROWCOUNT=200,
            )
            slot_rows = r.get("DATA", []) or []
            if slot_rows:
                break
        except Exception:
            continue

    if not slot_rows:
        return (sal_state, 0, "")

    n_slots = len(slot_rows)
    scope = "narrow"
    for row in slot_rows:
        wa = (row.get("WA") or "")
        parts = [p.strip() for p in wa.split("|")]
        if len(parts) >= 2 and parts[0] in ("*", "") and parts[1] in ("*", ""):
            scope = "broad"
            break

    return (sal_state, n_slots, scope)
