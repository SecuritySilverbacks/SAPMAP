"""Read-only ABAP telemetry / audit-posture probe.

Tier 1 OPSEC enrichment described in
``docs/research/13_detection_evasion_plan.md`` §6.1.  Captures, over RFC
with operator credentials, what audit + trace surfaces are on or off on
an ABAP node so the operator can see the SOC posture **before** taking
any action.  No writes, no tampering — every primitive here is a plain
table or BAPI read.

Detections:
  D1 — SAL on/off + filter-slot count + scope (narrow vs broad)
  D2 — ``rsau/integrity`` (HMAC signing of .AUD files)
  D3 — ``rsau/ip_only`` (terminal-name spoof viability, Troopers14 §4.A.18)
  D4 — ``rec/client`` (DBTABLOG), ``stat/level`` (STAD),
        ``gw/log_level`` (gateway trace), ``rdisp/TRACE`` (work-process)

Failure modes:
  - No SAP_ALL  → ``AbapTelemetryProfile.error="unauth"``
  - Older kernel without ``RSAU_READ_CONFIG`` → fall through to
    ``RSAUPROF``; if that's empty too → ``sal_state="unknown_legacy"``
  - Missing ``TPFYPROPTY`` row for a param → reported as ``unset``
    (means the kernel default applies; default is encoded below)
  - RFC raises → cache the short error on the profile, do not crash
"""

from __future__ import annotations

import logging
from typing import Optional

from sapmap_errors import format_rfc_exception
from sapmap_models import AbapTelemetryProfile, Credentials, SAPNode
import sapmap_rfc

logger = logging.getLogger(__name__)

# Kernel-default values for the parameters we probe.  When TPFYPROPTY has
# no row for a param, this is what the running instance actually behaves
# as.  Sourced from SAP Notes referenced in the research plan.
_KERNEL_DEFAULTS = {
    "rsau/integrity":   "1",   # ≥ 7.5: HMAC on by default
    "rsau/ip_only":     "1",   # ≥ 7.5x: client-supplied terminal name ignored
    "rec/client":       "OFF",
    "stat/level":       "1",
    "gw/log_level":     "1",
    "rdisp/TRACE":      "1",
}

# Params batched into a single RFC_READ_TABLE call to TPFYPROPTY
_PROBED_PARAMS = list(_KERNEL_DEFAULTS.keys())


def read_abap_telemetry(node: SAPNode,
                        creds: Optional[Credentials] = None
                        ) -> AbapTelemetryProfile:
    """Probe an ABAP node's audit + trace configuration.

    Returns an :class:`AbapTelemetryProfile`.  Always returns a profile
    object; failures are recorded in ``profile.error`` rather than
    raised, so callers can pin the result onto the node either way.
    """
    profile = AbapTelemetryProfile()

    # ---- D2/D3/D4: profile parameters via TPFYPROPTY ----
    try:
        raw = _read_profile_params(node, creds)
    except Exception as e:
        msg = format_rfc_exception(e).split("\n")[0][:200]
        logger.debug(f"{node.sid}: TPFYPROPTY read failed: {msg}")
        profile.error = f"TPFYPROPTY read failed: {msg}"
        return profile

    profile.raw_params = raw
    profile.sal_integrity = _bool_param(raw, "rsau/integrity")
    profile.sal_source_ip_only = _bool_param(raw, "rsau/ip_only")
    profile.rec_client = _str_param(raw, "rec/client").upper() or "OFF"
    profile.stat_level = _str_param(raw, "stat/level")
    profile.gw_log_level = _str_param(raw, "gw/log_level")
    profile.rdisp_trace = _str_param(raw, "rdisp/TRACE")

    # ---- D1: SAL state + filter slots ----
    try:
        sal_state, n_slots, scope = _read_sal_config(node, creds)
    except Exception as e:
        msg = format_rfc_exception(e).split("\n")[0][:200]
        logger.debug(f"{node.sid}: SAL config read failed: {msg}")
        profile.sal_state = "unknown"
        profile.error = f"SAL config read failed: {msg}"
    else:
        profile.sal_state = sal_state
        profile.sal_filter_slots = n_slots
        profile.sal_filter_scope = scope

    return profile


# ---------------------------------------------------------------------------
# D2/D3/D4 — profile parameter snapshot
# ---------------------------------------------------------------------------

def _read_profile_params(node: SAPNode,
                         creds: Optional[Credentials]) -> dict:
    """Return ``{parname: parvalue}`` for every probed parameter.

    Strategy: one ``RFC_READ_TABLE`` on ``TPFYPROPTY`` with an
    ``OPTIONS`` IN-list covering every parameter we care about.  Params
    not returned by the kernel are absent from the result (caller will
    treat them as "unset" and back-fill the kernel default).

    ``TPFYPROPTY`` is the kernel-side view of currently-active profile
    properties — same shape as RZ10 / RSPARAM but exposed as a table.
    Fields: ``PARNAME`` (CHAR60), ``PARVALUE`` (CHAR200).
    """
    where_parts = [f"PARNAME = '{p}'" for p in _PROBED_PARAMS]
    where = " OR ".join(where_parts)
    with sapmap_rfc._get_connection(node, creds) as conn:
        result = conn.call(
            "RFC_READ_TABLE",
            QUERY_TABLE="TPFYPROPTY",
            DELIMITER="|",
            OPTIONS=[{"TEXT": where}],
            FIELDS=[{"FIELDNAME": "PARNAME"},
                    {"FIELDNAME": "PARVALUE"}],
        )

    out = {}
    for row in result.get("DATA", []) or []:
        wa = (row.get("WA") or "")
        parts = wa.split("|")
        if len(parts) < 2:
            continue
        parname = parts[0].strip()
        parvalue = parts[1].strip()
        if parname:
            out[parname] = parvalue
    return out


def _bool_param(raw: dict, name: str) -> str:
    """Normalise a numeric/bool-ish parameter value to ``on``/``off``.

    Unset → default-aware ``on``/``off``.  Anything we can't classify
    becomes ``unknown`` so the operator sees the raw value separately.
    """
    if name in raw:
        v = raw[name].strip().lower()
        if v in ("1", "x", "y", "on", "true"):
            return "on"
        if v in ("0", "", "n", "off", "false"):
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
    if name in raw:
        return raw[name]
    default = _KERNEL_DEFAULTS.get(name, "")
    return f"{default} (default)" if default else "unset"


# ---------------------------------------------------------------------------
# D1 — SAL state + filter scope
# ---------------------------------------------------------------------------

def _read_sal_config(node: SAPNode,
                     creds: Optional[Credentials]) -> tuple:
    """Return ``(sal_state, n_filter_slots, scope)``.

    Modern path: ``RFC_READ_TABLE`` on ``RSAU_PERS`` (≥ 7.5).  Older
    NetWeaver path: ``RSAUPROF``.  When both come back empty we trust
    the global ``rsau/enable`` parameter for the on/off signal and mark
    the slot scope ``unknown_legacy``.

    Scope classification:
      - any populated slot whose USERSEL='*' AND CLISEL='*'    → ``broad``
      - any populated slot otherwise                            → ``narrow``
      - zero populated slots                                    → ``""``
    """
    # rsau/enable governs the global on/off.  We read it from
    # TPFYPROPTY for free (also lets the caller see the raw value).
    sal_state = "unknown"
    with sapmap_rfc._get_connection(node, creds) as conn:
        try:
            r = conn.call(
                "RFC_READ_TABLE",
                QUERY_TABLE="TPFYPROPTY",
                DELIMITER="|",
                OPTIONS=[{"TEXT": "PARNAME = 'rsau/enable'"}],
                FIELDS=[{"FIELDNAME": "PARVALUE"}],
            )
            rows = r.get("DATA", []) or []
            if rows:
                val = (rows[0].get("WA") or "").strip().lower()
                sal_state = "on" if val in ("1", "x", "on", "true") else "off"
            else:
                # rsau/enable unset → default is OFF on most kernels but
                # SOX-hardened S/4 ships with it ON via security baseline
                sal_state = "off (default)"
        except Exception:
            sal_state = "unknown"

        # Filter slots — try modern RSAU_PERS first
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
        # Either the kernel has no SAL slots populated, or the tables
        # aren't readable on this release.  Reflect both honestly.
        return (sal_state if sal_state != "unknown" else "unknown_legacy",
                0, "")

    n_slots = len(slot_rows)
    scope = "narrow"
    for row in slot_rows:
        wa = (row.get("WA") or "")
        parts = [p.strip() for p in wa.split("|")]
        if len(parts) >= 2 and parts[0] in ("*", "") and parts[1] in ("*", ""):
            scope = "broad"
            break

    return (sal_state, n_slots, scope)
