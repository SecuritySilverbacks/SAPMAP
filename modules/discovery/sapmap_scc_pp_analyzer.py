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

# USREXTID.TYPE values that map a specific cert subject to a specific
# ABAP user.  Only DN and LD entries are directly reachable through
# an SCC PP-minted X.509:
#   DN  — DN of certificate  (X.500 distinguished name)
#   LD  — DN for directory logon (LDAP)
# Reference: SAP table USREXTID, transaction SE16 / VUSREXTID.
USRMAPPING_TYPES = frozenset({"DN", "LD"})

# CA — DN of an issuing CA.  These rows do NOT map a specific cert to
# a specific ABAP user; they declare "any cert signed by this CA is
# accepted, and the kernel then resolves the cert's CN to an ABAP
# user via login/certificate_mapping_rulebased".  Surfaced separately.
CA_TRUST_TYPES = frozenset({"CA"})

# Other USREXTID types that do NOT participate in SCC PP cert-based
# auth — listed here for completeness in the per-system summary.
NON_CERT_TYPES = frozenset({"HX", "ID", "KB", "MP", "NT", "SA", "X"})


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


def _extract_cn(extid: str) -> str:
    """Pull the CN value out of a DN string.

    USREXTID.EXTID is typically a full ``CN=<x>,OU=<y>,O=<z>`` DN, but
    when ``login/certificate_mapping_rulebased=1`` it can be a bare
    CN.  Normalise to just the CN value (case-insensitive on the key).
    """
    if not extid:
        return ""
    s = extid.strip()
    if "=" not in s:
        return s  # bare CN, kernel param mode
    # Walk DN segments — handle escaped commas inside CN values.
    parts = []
    buf = []
    esc = False
    for ch in s:
        if esc:
            buf.append(ch); esc = False
        elif ch == "\\":
            esc = True
        elif ch == ",":
            parts.append("".join(buf)); buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    for p in parts:
        kv = p.strip().split("=", 1)
        if len(kv) == 2 and kv[0].strip().upper() == "CN":
            return kv[1].strip()
    return ""


def analyze_pp_impersonation(pp: dict, usrextid_rows: list) -> dict:
    """Given the SCC's PP subject pattern + the on-prem USREXTID
    table, enumerate which ABAP users a cloud caller can impersonate.

    Returns::

        {
          "ok":              True,
          "rule_template":   "CN=${name}",
          "rule_caller_controlled": True | False,
          "matched_users":   [ {bname, extid_cn, extid_full, type, mandt}, ... ],
          "privileged_users": [ ... subset where BNAME is in PRIVILEGED_LITERALS ],
          "exploitability":  "trivial" | "constrained" | "blocked",
          "notes":           "...",
        }
    """
    out = {
        "ok": True, "rule_template": "", "rule_caller_controlled": False,
        "matched_users": [], "privileged_users": [],
        "exploitability": "blocked",
        "notes": "",
    }
    if not pp or not pp.get("ok"):
        out["notes"] = "PP config not parsed yet."
        return out
    patterns = pp.get("subject_patterns") or []
    if not patterns:
        # No patterns -> SCC default behaviour ≈ caller-controlled
        out["rule_template"] = "(empty subjectPatterns — default)"
        out["rule_caller_controlled"] = True
    else:
        # Take the first <subjectPattern> — production configs we've
        # seen have exactly one.  Multi-pattern setups should be the
        # subject of a future enhancement once we have a sample.
        sp = patterns[0]
        cn_entry = next((e for e in (sp.get("dn_entries") or [])
                         if (e.get("key") or "").upper() == "CN"), None)
        if cn_entry:
            classified = _classify_dn_entry(cn_entry)
            tpl = (cn_entry.get("value") or "").strip()
            out["rule_template"] = "CN=" + tpl
            out["rule_caller_controlled"] = bool(
                classified["has_caller_controlled"])
            out["rule_hardcoded_literal"] = classified["is_literal"]
        else:
            out["rule_template"] = "(no CN entry)"

    if not usrextid_rows:
        out["notes"] = (
            "USREXTID has not been read yet — run "
            "Data Extraction → Read USREXTID on the on-prem ABAP "
            "node to enumerate impersonation targets.")
        return out

    # Bucket the rows by TYPE.  Only DN / LD types map a specific
    # cert subject to a specific ABAP user via PP; CA entries are CA
    # trust declarations (require a separate USR02 cross-link to
    # enumerate impersonatable users); HX / KB / NT / etc. are
    # unrelated auth mechanisms.
    user_mapping_rows: list = []
    ca_trust_rows: list = []
    other_rows: list = []
    for row in usrextid_rows or []:
        if not isinstance(row, dict):
            continue
        bname = (row.get("BNAME") or "").strip()
        rtype = (row.get("TYPE") or "").strip().upper()
        if not bname:
            continue
        if rtype in USRMAPPING_TYPES:
            user_mapping_rows.append(row)
        elif rtype in CA_TRUST_TYPES:
            ca_trust_rows.append(row)
        else:
            other_rows.append(row)

    # Surface the type breakdown so the operator sees what the
    # analyser actually considered — matters when the verdict is
    # "blocked" but USREXTID has lots of (non-PP-reachable) rows.
    out["usrextid_buckets"] = {
        "user_mapping": len(user_mapping_rows),
        "ca_trust":     len(ca_trust_rows),
        "other":        len(other_rows),
    }

    # Score each user-mapping row.  CA-trust rows get a separate
    # advisory note further down.
    matched = []
    for row in user_mapping_rows:
        bname = (row.get("BNAME") or "").strip()
        extid = (row.get("EXTID") or "").strip()
        rtype = (row.get("TYPE") or "").strip().upper()
        mandt = (row.get("MANDT") or "").strip()
        cn = _extract_cn(extid)
        # Caller-controlled rule: every DN-typed entry whose DN
        # contains a CN= component is a potential impersonation
        # target — the cloud caller can claim any name / email that
        # matches its CN portion via the IdP claim.
        if out["rule_caller_controlled"]:
            if not cn:
                continue  # DN without CN= component — kernel skips it
            matched.append({
                "bname": bname, "extid_cn": cn,
                "extid_full": extid, "type": rtype, "mandt": mandt,
            })
        elif out.get("rule_hardcoded_literal"):
            # Hardcoded literal -> only the EXACT CN literal works.
            tpl = out["rule_template"].split("=", 1)[-1].strip()
            if cn.upper() == tpl.upper():
                matched.append({
                    "bname": bname, "extid_cn": cn,
                    "extid_full": extid, "type": rtype, "mandt": mandt,
                })

    out["matched_users"] = matched
    privs = [r for r in matched
             if r["bname"].upper() in PRIVILEGED_LITERALS]
    out["privileged_users"] = privs

    # CA-trust advisory — separate signal: when CA-typed rows exist,
    # the kernel resolves any cert signed by that CA via the cert's
    # CN against USR02 (with login/certificate_mapping_rulebased=1)
    # OR a USREXTID DN/LD entry.  If USR02 is broad and the rule is
    # caller-controlled, every ABAP user with a CN-matching login is
    # impersonatable — but we'd need USR02 data to enumerate.
    ca_advisory = ""
    if ca_trust_rows and out["rule_caller_controlled"]:
        ca_users = sorted({(r.get("BNAME") or "").strip()
                            for r in ca_trust_rows})
        ca_advisory = (
            f"Additionally, USREXTID declares CA trust for "
            f"{len(ca_trust_rows)} issuing CA(s) (BNAME(s): "
            f"{', '.join(ca_users)}).  When "
            f"login/certificate_mapping_rulebased=1 the kernel also "
            f"resolves the cert's CN against USR02 directly — so "
            f"every ABAP user whose login matches a name a cloud "
            f"caller can claim is *additionally* impersonatable.  "
            f"Run Download Hashes / Capability Analyser to enumerate "
            f"USR02.")

    # Verdict
    if matched:
        if privs:
            out["exploitability"] = "trivial"
            out["notes"] = (
                f"Cloud caller can impersonate "
                f"{len(matched)} ABAP user(s) on this system, "
                f"including {len(privs)} privileged account(s): "
                f"{', '.join(sorted(set(p['bname'] for p in privs)))}.")
        elif out["rule_caller_controlled"]:
            out["exploitability"] = "trivial"
            out["notes"] = (
                f"Cloud caller can impersonate "
                f"{len(matched)} ABAP user(s) on this system.  None "
                f"are on the privileged-literal allow-list, but every "
                f"matched user is a real ABAP login — blast radius "
                f"depends on each one's role assignments.")
        else:
            out["exploitability"] = "constrained"
            out["notes"] = (
                f"PP rule maps to a fixed CN; "
                f"{len(matched)} USREXTID entry(s) match.  Caller "
                f"becomes those users only — verify their roles.")
    else:
        if out["rule_caller_controlled"]:
            out["exploitability"] = "blocked"
            if not user_mapping_rows:
                # USREXTID is populated but only with CA / HX / KB /
                # NT / etc. — none of which produce a direct SCC PP
                # mapping target.
                bits = []
                if ca_trust_rows:
                    bits.append(
                        f"{len(ca_trust_rows)} CA-trust row(s) "
                        f"(TYPE=CA — defines which issuers are "
                        f"trusted, not a user mapping)")
                if other_rows:
                    type_summary = ", ".join(
                        sorted({(r.get('TYPE') or '').strip().upper()
                                for r in other_rows
                                if (r.get('TYPE') or '').strip()}))
                    bits.append(
                        f"{len(other_rows)} non-PP row(s) "
                        f"(TYPE={type_summary} — Kerberos / NT / "
                        f"SAML / cert-hash etc.)")
                out["notes"] = (
                    "USREXTID has no DN / LD typed entries (which "
                    "are what SCC's PP-minted X.509 certs resolve "
                    "against).  Found: " + "; ".join(bits or [
                        "no rows with a BNAME"]) + ".  No "
                    "impersonation is reachable through the SCC PP "
                    "path until an ABAP admin adds a USREXTID row "
                    "with TYPE=DN and a CN= component matching a "
                    "name a cloud caller can claim.")
            else:
                # We had DN/LD rows but none had a CN= component
                out["notes"] = (
                    f"USREXTID has {len(user_mapping_rows)} DN/LD "
                    f"row(s), but none contain a CN= component in "
                    f"their EXTID — the SCC PP rule (CN-bound) has "
                    f"nothing to resolve against.")
        else:
            out["exploitability"] = "blocked"
            out["notes"] = (
                "PP rule's CN literal does not match any USREXTID "
                "DN/LD entry — no impersonation reachable.")

    if ca_advisory:
        out["notes"] = (out["notes"] + "\n\n" + ca_advisory).strip()
    return out


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
