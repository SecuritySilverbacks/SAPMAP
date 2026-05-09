#!/usr/bin/env python3
"""SCC Principal-Propagation analyser.

Static rule engine over an extracted SCC backup.  Surfaces "any cloud
user can be any on-prem user" misconfigs in the SCC-wide
``<principalPropagationConfiguration>`` block, plus the cloud-side
``trustcfg_<uuid>.xml`` IdP trust entries when present.

Pure functions — no live calls, no I/O beyond the zip parser the
caller hands in.  The two parser front doors live in
``sapmap_scc_keystore``:

    parse_pp_config_from_zip(zip_path)  -> {ok, mode, subject_patterns, ...}
    parse_pp_trust_from_zip(zip_path)   -> {ok, by_subaccount: {uuid: {idps:[]}}}

Schema reference:
    docs/research/09_principal_propagation_schema.md

The rules are deliberately conservative — every CRITICAL finding maps
to a documented impersonation primitive; HIGH/MEDIUM cover broader
trust-chain weaknesses.  False positives erode operator trust and
should be reduced by tightening the rule, never by silencing the
finding.
"""
from __future__ import annotations

from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Placeholder substitutions that are caller-controlled (cloud IdP claim
# the cloud user can usually influence).  user_uuid is the only one
# that's typically NOT caller-controlled — it's the cloud-side stable
# identifier.  groups is influenceable but only to the extent the cloud
# user already has those memberships.
CALLER_CONTROLLED_PLACEHOLDERS = {
    "${name}",
    "${email}",
    "${first_name}",
    "${last_name}",
}

# Placeholders that bind to a stable identifier the caller cannot
# trivially forge.  Mapping to these (alone or in combination with a
# tight condition) is generally fine.
STABLE_PLACEHOLDERS = {
    "${user_uuid}",
}

# Hardcoded values that map every cloud caller to a privileged on-prem
# user when used as a literal in the CN entry.  Compared
# case-insensitively.
PRIVILEGED_LITERALS = {
    "DDIC",
    "SAP*",
    "SAPSYS",
    "SAPMAP00",
    "SAPMAP01",
    "EARLYWATCH",
    "SOLMAN_BTC",
    "SOLMAN_ADMIN",
    "TMSADM",
    "SAP_BASIS_USER",
}

# Default upper limit for forwarded-cert validity period.  Anything
# above this widens the blast radius if the PP CA private key leaks
# (which SAPMAP can do via SSFS extract → MEDIUM finding pairs with the
# existing SSFS extract findings).
MAX_REASONABLE_VALIDITY_MINS = 240   # 4h

# ssoToleranceInHours: how long a forwarded MYSAPSSO2 ticket stays
# valid on the on-prem side.  Default in SCC is 2h; 8h+ is a smell.
MAX_REASONABLE_SSO_TOLERANCE_H = 8

# PP mode that fires the local-CA cert-mint path.  KERBEROS / SLS modes
# go through different trust paths; the analyser focuses on LOCAL
# because that's where the weak-template attack lives.
LOCAL_PP_MODE = "LOCAL"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _placeholders_in(value: str) -> list:
    """Extract ``${...}`` tokens from a template value (preserving order)."""
    out = []
    i = 0
    while True:
        s = value.find("${", i)
        if s < 0:
            break
        e = value.find("}", s + 2)
        if e < 0:
            break
        out.append(value[s:e + 1])
        i = e + 1
    return out


def _classify_dn_entry(entry: dict) -> dict:
    """Inspect one ``<entry>`` (key + value) and classify the value."""
    key = (entry.get("key") or "").strip().upper()
    value = (entry.get("value") or "").strip()
    placeholders = _placeholders_in(value)
    is_pure_placeholder = (len(placeholders) == 1
                           and placeholders[0] == value)
    has_caller_controlled = any(p in CALLER_CONTROLLED_PLACEHOLDERS
                                 for p in placeholders)
    has_stable_only = (placeholders
                       and all(p in STABLE_PLACEHOLDERS for p in placeholders))
    is_literal = not placeholders
    is_privileged_literal = (is_literal
                              and value.upper() in PRIVILEGED_LITERALS)
    return {
        "key":                   key,
        "value":                 value,
        "placeholders":          placeholders,
        "is_pure_placeholder":   is_pure_placeholder,
        "has_caller_controlled": has_caller_controlled,
        "has_stable_only":       has_stable_only,
        "is_literal":            is_literal,
        "is_privileged_literal": is_privileged_literal,
    }


def _has_pp_enabled_mapping(mappings: list) -> bool:
    """Return True if at least one mapping uses a PP auth mode."""
    if not mappings:
        return False
    try:
        from sapmap_scc_admin import _is_pp_auth_mode
    except Exception:
        # Standalone import path (e.g. running tests outside pytest's
        # sys.path setup) — fall back to a local list that mirrors the
        # canonical helper.
        local_pp = {"KERBEROS", "X509_GENERAL", "X509_CERTIFICATE",
                    "X509_CERTIFICATE_LOCAL", "NONE_CERTIFICATE_LOCAL"}
        def _is_pp_auth_mode(am):
            return bool(am) and am.strip().upper() in local_pp
    for m in mappings:
        if not isinstance(m, dict):
            continue
        if _is_pp_auth_mode(m.get("authentication_mode") or ""):
            return True
        if m.get("principal_propagation"):
            return True
    return False


def _count_pp_enabled_mappings(mappings: list) -> int:
    if not mappings:
        return 0
    try:
        from sapmap_scc_admin import _is_pp_auth_mode
    except Exception:
        return sum(1 for m in (mappings or [])
                   if isinstance(m, dict) and m.get("principal_propagation"))
    return sum(1 for m in mappings
               if isinstance(m, dict)
               and (_is_pp_auth_mode(m.get("authentication_mode") or "")
                    or m.get("principal_propagation")))


# ---------------------------------------------------------------------------
# Core rule engine
# ---------------------------------------------------------------------------

def analyze_subject_pattern(pattern: dict, mode: str) -> Optional[dict]:
    """Classify one ``<subjectPattern>`` element.

    Returns a finding dict or None (no severity = not flagged).  The
    finding shape is::

        {
          "severity":       "CRITICAL" | "HIGH" | "MEDIUM",
          "ref":            "scc.pp.weak.<reason>",
          "headline":       "<one-line summary, operator-readable>",
          "why":            ["<reason 1>", "<reason 2>", ...],
          "recommendation": "<one-line fix the operator can act on>",
          "raw":            {dn_entries, condition, description},
        }
    """
    entries = pattern.get("dn_entries") or []
    condition = (pattern.get("condition") or "").strip()
    classified = [_classify_dn_entry(e) for e in entries]

    # CN is the operator-facing field — that's what gets resolved to an
    # ABAP user via USREXTID on the on-prem side.
    cn_entries = [c for c in classified if c["key"] == "CN"]

    # The local-CA mint path is the only one where these patterns
    # actually drive cert minting.  KERBEROS/SLS modes use different
    # trust chains and the subject pattern is not directly attacker-
    # controlled in the same way.
    is_local = (mode or "").strip().upper() == LOCAL_PP_MODE

    # ---- CRITICAL: hardcoded privileged user as CN ----
    if cn_entries and cn_entries[0]["is_privileged_literal"]:
        priv = cn_entries[0]["value"].upper()
        return {
            "severity": "CRITICAL",
            "ref":      "scc.pp.weak.hardcoded_privileged",
            "headline": (
                f"PP rule maps every cloud user to privileged on-prem "
                f"user CN={priv}"),
            "why": [
                f"DN entry CN={priv!r} is a literal value with no "
                f"placeholder substitution.",
                f"Every cloud caller authenticated through the PP "
                f"path is forwarded as on-prem user {priv}.",
                f"{priv} is on the privileged-account list "
                f"(SAP_ALL or near-equivalent).",
            ],
            "recommendation": (
                "Replace the hardcoded CN with a placeholder bound to "
                "the cloud caller's stable identity (e.g. ${user_uuid}) "
                "AND restrict the rule with a <condition> tying it to "
                "a specific cloud user group / email domain."),
            "raw": dict(pattern),
        }

    # ---- CRITICAL: caller-controlled CN with no condition + LOCAL ----
    if (is_local
            and cn_entries
            and cn_entries[0]["has_caller_controlled"]
            and not condition):
        ph = cn_entries[0]["placeholders"]
        return {
            "severity": "CRITICAL",
            "ref":      "scc.pp.weak.caller_controlled_cn",
            "headline": (
                f"Caller-controlled CN={cn_entries[0]['value']!r} with "
                f"no condition under LOCAL PP mode"),
            "why": [
                f"CN is bound to the cloud-side IdP claim "
                f"{', '.join(ph)} — a value the cloud caller can "
                f"influence on most IdPs.",
                "<condition> is empty so no IdP / group / domain "
                "restriction is enforced before cert minting.",
                "principalPropagationMode=LOCAL means SCC mints the "
                "forwarded cert with its own PP CA — the on-prem ABAP "
                "system trusts that CA and resolves the CN via "
                "USREXTID.  Result: the cloud caller picks the "
                "on-prem user.",
            ],
            "recommendation": (
                "Either add a <condition> restricting the rule to a "
                "trusted cloud user group / email domain, or bind CN "
                "to a stable identifier such as ${user_uuid} and add "
                "an entry-level identity binding via a sibling DN "
                "entry (OU/O) plus <condition>."),
            "raw": dict(pattern),
        }

    # ---- HIGH: caller-controlled CN with condition (still risky) ----
    if (is_local
            and cn_entries
            and cn_entries[0]["has_caller_controlled"]
            and condition):
        ph = cn_entries[0]["placeholders"]
        return {
            "severity": "HIGH",
            "ref":      "scc.pp.weak.caller_controlled_cn_conditioned",
            "headline": (
                f"Caller-controlled CN={cn_entries[0]['value']!r} "
                f"despite a <condition>"),
            "why": [
                f"CN is bound to caller-controlled placeholder "
                f"{', '.join(ph)}.",
                f"<condition> is set ({condition!r}) which narrows "
                f"the rule, but the CN itself is still attacker-"
                f"controlled inside the allowed cloud-user set.",
                "Any cloud caller that satisfies the condition can "
                "still pick any on-prem CN in their identity claim.",
            ],
            "recommendation": (
                "Bind CN to ${user_uuid} (stable across IdP renames) "
                "or harden the on-prem USREXTID mapping so each "
                "cloud user resolves to exactly one ABAP user."),
            "raw": dict(pattern),
        }

    # ---- HIGH: caller-controlled CN under non-LOCAL mode ----
    if (cn_entries
            and cn_entries[0]["has_caller_controlled"]
            and not is_local):
        ph = cn_entries[0]["placeholders"]
        return {
            "severity": "HIGH",
            "ref":      "scc.pp.weak.caller_controlled_cn_nonlocal",
            "headline": (
                f"Caller-controlled CN={cn_entries[0]['value']!r} "
                f"(mode={mode or '?'})"),
            "why": [
                f"CN is bound to caller-controlled placeholder "
                f"{', '.join(ph)}.",
                f"principalPropagationMode is {mode or '(empty)'} — "
                "the SCC delegates cert minting elsewhere, so the "
                "blast radius depends on that issuer's trust scope.",
            ],
            "recommendation": (
                "Audit the issuer's signing scope; bind CN to a "
                "stable claim or add a <condition> tying the rule "
                "to a specific cloud user group."),
            "raw": dict(pattern),
        }

    return None


def analyze_pp_config(pp: dict, mappings: Optional[list] = None) -> list:
    """Run all rules over the parsed PP config + mapping list.

    ``pp`` is the dict returned by ``parse_pp_config_from_zip``.
    ``mappings`` is the list of ``SCCMapping.to_dict()`` entries (or
    raw mapping dicts).  Returns a list of finding dicts.
    """
    findings: list = []
    if not pp or not pp.get("ok"):
        return findings
    mode = pp.get("mode") or ""
    patterns = pp.get("subject_patterns") or []
    has_pp_mapping = _has_pp_enabled_mapping(mappings or [])
    pp_count = _count_pp_enabled_mappings(mappings or [])

    # Rule 1: empty subjectPatterns + at least one PP-using mapping.
    # SCC's documented behaviour with no pattern is "use a default"
    # which historically maps to the cloud user identity claim — i.e.
    # equivalent to ${name} unbound.
    if (mode.upper() == LOCAL_PP_MODE
            and not patterns
            and has_pp_mapping):
        findings.append({
            "severity": "CRITICAL",
            "ref":      "scc.pp.weak.empty_subject_patterns",
            "headline": (
                "PP enabled with EMPTY <subjectPatterns> and "
                f"{pp_count} mapping(s) using PP auth"),
            "why": [
                "<subjectPatterns> contains no <subjectPattern> "
                "entries, so SCC falls back to its default behaviour "
                "(cloud caller identity claim → on-prem CN, "
                "unconstrained).",
                f"{pp_count} mapping(s) on this SCC have an auth "
                "mode that drives the local-CA cert-mint path.",
            ],
            "recommendation": (
                "Configure at least one <subjectPattern> with a "
                "stable CN binding (e.g. ${user_uuid}) and a "
                "<condition> scoping the rule to a specific cloud "
                "user group."),
            "raw": {"dn_entries": [], "condition": "", "description": ""},
        })

    # Rule 2..N: per-pattern analysis (only when PP is actually used).
    if has_pp_mapping or not mappings:
        # If mappings is unknown (None or empty), still run per-pattern
        # analysis — operator might be analysing in advance of pulling
        # mappings.
        for sp in patterns:
            f = analyze_subject_pattern(sp, mode)
            if f:
                findings.append(f)

    # Rule N+1 (MEDIUM): long-lived forwarded certs.
    val_min = pp.get("validity_mins") or 0
    if val_min and val_min > MAX_REASONABLE_VALIDITY_MINS:
        findings.append({
            "severity": "MEDIUM",
            "ref":      "scc.pp.weak.long_validity",
            "headline": (
                f"PP forwarded-cert validity {val_min} min "
                f"(> {MAX_REASONABLE_VALIDITY_MINS} min default)"),
            "why": [
                f"certificateValidityPeriodInMins is {val_min}.",
                "Pairs with the SSFS lateral move: SAPMAP can "
                "extract the PP CA private key, and a long validity "
                "period extends the window during which a forged "
                "forwarded cert remains accepted.",
            ],
            "recommendation": (
                f"Lower certificateValidityPeriodInMins to "
                f"{MAX_REASONABLE_VALIDITY_MINS} or less unless an "
                "explicit operational reason justifies the wider "
                "window."),
            "raw": {"validity_mins": val_min},
        })

    # Rule N+2 (MEDIUM): wide ssoToleranceInHours.
    sso_h = pp.get("sso_tolerance_h") or 0
    if sso_h and sso_h > MAX_REASONABLE_SSO_TOLERANCE_H:
        findings.append({
            "severity": "MEDIUM",
            "ref":      "scc.pp.weak.long_sso_tolerance",
            "headline": (
                f"ssoToleranceInHours={sso_h} (> "
                f"{MAX_REASONABLE_SSO_TOLERANCE_H}h)"),
            "why": [
                f"ssoToleranceInHours is {sso_h}.",
                "A stolen MYSAPSSO2 ticket forwarded by SCC stays "
                "valid on the on-prem side for that duration.",
            ],
            "recommendation": (
                f"Lower ssoToleranceInHours to "
                f"{MAX_REASONABLE_SSO_TOLERANCE_H} or less."),
            "raw": {"sso_tolerance_h": sso_h},
        })

    return findings


def analyze_pp_trust(trust: dict) -> list:
    """Inspect parsed trustcfg_<uuid>.xml entries.

    ``trust`` is the dict returned by ``parse_pp_trust_from_zip``.
    Returns a list of finding dicts (one per subaccount that triggers
    a rule).
    """
    findings: list = []
    if not trust or not trust.get("ok"):
        return findings
    by_sub = trust.get("by_subaccount") or {}
    for sub_uuid, info in by_sub.items():
        idps = [i for i in (info.get("idps") or []) if i.get("enabled")]
        external = [i for i in idps if i.get("issuer_kind") == "external"]
        if external:
            findings.append({
                "severity": "HIGH",
                "ref":      "scc.pp.trust.external_idp",
                "headline": (
                    f"Subaccount {sub_uuid[:8]}… trusts an external "
                    f"IdP for inbound JWT validation"),
                "why": [
                    f"trustcfg_{sub_uuid}.xml has "
                    f"{len(external)} enabled idPConfiguration "
                    "entries that don't look like SAP-managed XSUAA "
                    "or IAS issuers.",
                    "External IdPs are the most common weak link — "
                    "if the customer-controlled IdP allows free-form "
                    "claims, the cloud-side identity that drives the "
                    "PP subject pattern is no longer trustworthy.",
                ],
                "recommendation": (
                    "Verify each external IdP's claim issuance "
                    "policy enforces strict subject / email "
                    "uniqueness."),
                "raw": {
                    "subaccount": sub_uuid,
                    "external_idps": [i["name"] for i in external],
                },
            })
        elif len(idps) > 1:
            kinds = sorted({i.get("issuer_kind") or "" for i in idps})
            findings.append({
                "severity": "MEDIUM",
                "ref":      "scc.pp.trust.multi_idp",
                "headline": (
                    f"Subaccount {sub_uuid[:8]}… trusts "
                    f"{len(idps)} IdPs ({'+'.join(kinds)})"),
                "why": [
                    f"{len(idps)} enabled idPConfiguration entries "
                    "of mixed kind.",
                    "Multiple trusted issuers widen the attack "
                    "surface for forged JWTs.  Common when both "
                    "XSUAA and IAS sign tokens for the same "
                    "subaccount; usually intentional but worth "
                    "verifying.",
                ],
                "recommendation": (
                    "Confirm each IdP entry is necessary; remove "
                    "stale ones."),
                "raw": {"subaccount": sub_uuid, "idp_kinds": kinds},
            })
    return findings


def analyze_backup(pp: dict, trust: Optional[dict] = None,
                    mappings: Optional[list] = None) -> dict:
    """Convenience entry point that runs both rule sets and bundles
    the result.

    Returns::

        {
          "ok":             True,
          "method":         "static-xml",
          "findings":       [<finding dict>, ...],
          "summary":        {"critical": N, "high": N, "medium": N},
          "pp_config":      <pp>,
          "trust":          <trust>,
          "analyzed_at":    "<iso ts>",
        }
    """
    from datetime import datetime, timezone
    findings = analyze_pp_config(pp, mappings=mappings)
    if trust:
        findings.extend(analyze_pp_trust(trust))
    summary = {"critical": 0, "high": 0, "medium": 0}
    for f in findings:
        sev = (f.get("severity") or "").lower()
        if sev in summary:
            summary[sev] += 1
    return {
        "ok":          True,
        "method":      "static-xml",
        "findings":    findings,
        "summary":     summary,
        "pp_config":   pp,
        "trust":       trust or {},
        "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
