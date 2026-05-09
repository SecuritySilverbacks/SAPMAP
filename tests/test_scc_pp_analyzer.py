#!/usr/bin/env python3
"""Tests for sapmap_scc_pp_analyzer + the new PP-config parsers.

Fixture XMLs in tests/fixtures/scc_pp/ cover the rule patterns
documented in docs/research/09_principal_propagation_schema.md.
Each fixture is loaded directly (no zip wrapping) — the analyser
takes parsed dicts, so tests stay fast and decoupled from the zip
machinery.
"""
from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from typing import Optional


HERE = os.path.dirname(os.path.abspath(__file__))
FIXT = os.path.join(HERE, "fixtures", "scc_pp")


def _parse_pp_xml(filename: str) -> dict:
    """Build the same dict shape that parse_pp_config_from_zip returns,
    from a standalone scc_config.ini fixture (no zip wrapper)."""
    path = os.path.join(FIXT, filename)
    root = ET.parse(path).getroot()
    pp = root.find("principalPropagationConfiguration")
    assert pp is not None, f"fixture {filename} has no PP block"
    patterns = []
    for sp in pp.findall("subjectPatterns/subjectPattern"):
        entries = []
        for e in sp.findall("dnEntries/entry"):
            entries.append({
                "key":   (e.findtext("key") or "").strip(),
                "value": (e.findtext("value") or "").strip(),
            })
        patterns.append({
            "dn_entries":  entries,
            "condition":   (sp.findtext("condition") or "").strip(),
            "description": (sp.findtext("description") or "").strip(),
        })

    def _int(name, default=0):
        try:
            return int((pp.findtext(name) or "").strip() or default)
        except ValueError:
            return default

    return {
        "ok":              True,
        "mode":            (pp.findtext("principalPropagationMode") or "").strip(),
        "subject_patterns": patterns,
        "validity_mins":   _int("certificateValidityPeriodInMins"),
        "sso_tolerance_h": _int("ssoToleranceInHours"),
        "raw_xml":         "",
    }


def _parse_trust_xml(filename: str, sub_uuid: str) -> dict:
    """Build the parse_pp_trust_from_zip result for a single trustcfg.xml."""
    path = os.path.join(FIXT, filename)
    root = ET.parse(path).getroot()
    last_updated = (root.findtext("lastUpdated") or "").strip()
    idps = []
    for cfg in root.findall("configurations/idPConfiguration"):
        desc = (cfg.findtext("description") or "").strip()
        descl = desc.lower()
        if "xsuaa" in descl or "sap uaa" in descl:
            kind = "xsuaa"
        elif "ias" in descl or "identity authentication" in descl:
            kind = "ias"
        elif desc:
            kind = "external"
        else:
            kind = ""
        idps.append({
            "name":        (cfg.findtext("name") or "").strip(),
            "description": desc,
            "id":          (cfg.findtext("id") or "").strip(),
            "enabled":     (cfg.findtext("enabled") or "").strip().lower() == "true",
            "issuer_kind": kind,
        })
    return {
        "ok": True,
        "by_subaccount": {
            sub_uuid: {
                "region":       "cf.eu10.hana.ondemand.com",
                "last_updated": last_updated,
                "idps":         idps,
            }
        }
    }


def _mappings(*auth_modes) -> list:
    """Build a list of mapping dicts with the given auth modes."""
    return [{
        "authentication_mode": am,
        "principal_propagation": False,  # let analyser derive
        "virtual_host": "v", "virtual_port": 443,
        "internal_host": "i", "internal_port": 8080,
    } for am in auth_modes]


# ===========================================================================
# 1. _is_pp_auth_mode — covers the bugfix (NONE_CERTIFICATE_LOCAL etc.)
# ===========================================================================

def test_pp_auth_mode_detects_kerberos_and_x509_general():
    from sapmap_scc_admin import _is_pp_auth_mode
    assert _is_pp_auth_mode("KERBEROS") is True
    assert _is_pp_auth_mode("X509_GENERAL") is True


def test_pp_auth_mode_detects_local_variants():
    """The bugfix — these used to be missed and let weak rules slip
    through unflagged."""
    from sapmap_scc_admin import _is_pp_auth_mode
    assert _is_pp_auth_mode("NONE_CERTIFICATE_LOCAL") is True
    assert _is_pp_auth_mode("X509_CERTIFICATE_LOCAL") is True
    assert _is_pp_auth_mode("X509_CERTIFICATE") is True


def test_pp_auth_mode_skips_non_pp():
    from sapmap_scc_admin import _is_pp_auth_mode
    assert _is_pp_auth_mode("NONE") is False
    assert _is_pp_auth_mode("") is False
    assert _is_pp_auth_mode(None) is False


def test_pp_auth_mode_is_case_insensitive():
    from sapmap_scc_admin import _is_pp_auth_mode
    assert _is_pp_auth_mode("kerberos") is True
    assert _is_pp_auth_mode("none_certificate_local") is True


# ===========================================================================
# 2. analyze_pp_config — per-pattern rules
# ===========================================================================

def test_critical_caller_controlled_name_with_no_condition():
    from sapmap_scc_pp_analyzer import analyze_pp_config
    pp = _parse_pp_xml("scc_config_critical_name.ini")
    findings = analyze_pp_config(pp, mappings=_mappings("NONE_CERTIFICATE_LOCAL"))
    assert any(f["severity"] == "CRITICAL"
               and f["ref"] == "scc.pp.weak.caller_controlled_cn"
               for f in findings)


def test_critical_caller_controlled_email_with_no_condition():
    from sapmap_scc_pp_analyzer import analyze_pp_config
    pp = _parse_pp_xml("scc_config_high_email.ini")
    findings = analyze_pp_config(pp, mappings=_mappings("KERBEROS"))
    assert any(f["severity"] == "CRITICAL"
               and f["ref"] == "scc.pp.weak.caller_controlled_cn"
               for f in findings)


def test_critical_empty_subject_patterns():
    from sapmap_scc_pp_analyzer import analyze_pp_config
    pp = _parse_pp_xml("scc_config_critical_empty.ini")
    findings = analyze_pp_config(pp, mappings=_mappings("X509_CERTIFICATE_LOCAL"))
    assert any(f["severity"] == "CRITICAL"
               and f["ref"] == "scc.pp.weak.empty_subject_patterns"
               for f in findings)


def test_critical_hardcoded_privileged_ddic():
    from sapmap_scc_pp_analyzer import analyze_pp_config
    pp = _parse_pp_xml("scc_config_high_hardcoded_ddic.ini")
    findings = analyze_pp_config(pp, mappings=_mappings("KERBEROS"))
    crit = [f for f in findings
            if f["ref"] == "scc.pp.weak.hardcoded_privileged"]
    assert len(crit) == 1
    assert crit[0]["severity"] == "CRITICAL"
    assert "DDIC" in crit[0]["headline"]


def test_clean_scoped_pattern_yields_no_pp_finding():
    """Tight rule: stable placeholder (${user_uuid}), composite DN
    (CN/OU/O), explicit <condition> binding to a domain.  No PP rule
    finding should fire — this is the well-configured baseline."""
    from sapmap_scc_pp_analyzer import analyze_pp_config
    pp = _parse_pp_xml("scc_config_clean_scoped.ini")
    findings = analyze_pp_config(pp, mappings=_mappings("KERBEROS"))
    pp_findings = [f for f in findings
                   if f["ref"].startswith("scc.pp.weak.")]
    assert pp_findings == [], (
        f"clean fixture should not raise weak-rule findings, "
        f"got: {pp_findings}")


def test_medium_long_validity_and_sso_tolerance():
    from sapmap_scc_pp_analyzer import analyze_pp_config
    pp = _parse_pp_xml("scc_config_medium_long_validity.ini")
    findings = analyze_pp_config(pp, mappings=_mappings("KERBEROS"))
    refs = [f["ref"] for f in findings]
    assert "scc.pp.weak.long_validity" in refs
    assert "scc.pp.weak.long_sso_tolerance" in refs
    # And both should be MEDIUM
    for f in findings:
        if f["ref"] in ("scc.pp.weak.long_validity",
                         "scc.pp.weak.long_sso_tolerance"):
            assert f["severity"] == "MEDIUM"


# ===========================================================================
# 3. Mapping-context dependency — no PP mappings means no per-pattern fire
# ===========================================================================

def test_empty_subject_patterns_silent_when_no_pp_mappings():
    """If no mapping uses PP, the 'empty <subjectPatterns>' rule should
    not fire — there's literally nothing to attack."""
    from sapmap_scc_pp_analyzer import analyze_pp_config
    pp = _parse_pp_xml("scc_config_critical_empty.ini")
    findings = analyze_pp_config(pp, mappings=_mappings("NONE"))
    assert not any(f["ref"] == "scc.pp.weak.empty_subject_patterns"
                   for f in findings)


# ===========================================================================
# 4. analyze_pp_trust — IdP rules
# ===========================================================================

def test_single_xsuaa_trust_yields_no_finding():
    from sapmap_scc_pp_analyzer import analyze_pp_trust
    trust = _parse_trust_xml(
        "trustcfg_single_xsuaa.xml",
        "00000000-0000-0000-0000-000000000001")
    assert analyze_pp_trust(trust) == []


def test_multi_idp_xsuaa_plus_ias_yields_medium():
    from sapmap_scc_pp_analyzer import analyze_pp_trust
    trust = _parse_trust_xml(
        "trustcfg_xsuaa_plus_ias.xml",
        "00000000-0000-0000-0000-000000000002")
    findings = analyze_pp_trust(trust)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["ref"] == "scc.pp.trust.multi_idp"


# ===========================================================================
# 5. Round-trip parser ↔ live backup
# ===========================================================================

# ===========================================================================
# 6. analyze_pp_impersonation — USREXTID cross-link
# ===========================================================================

_USREXT_ROWS = [
    # Routine office users
    {"MANDT": "100", "BNAME": "ALICE",  "EXTID": "CN=alice@acme.example.com",      "TYPE": "DN", "SEQNO": "0"},
    {"MANDT": "100", "BNAME": "BOB",    "EXTID": "CN=bob@acme.example.com",        "TYPE": "DN", "SEQNO": "0"},
    # Privileged user with a CN entry — the killer signal
    {"MANDT": "100", "BNAME": "DDIC",   "EXTID": "CN=DDIC,OU=Basis,O=Acme",        "TYPE": "DN", "SEQNO": "0"},
    {"MANDT": "100", "BNAME": "SAP*",   "EXTID": "CN=SAP*,O=Acme",                 "TYPE": "DN", "SEQNO": "0"},
    # Service account
    {"MANDT": "100", "BNAME": "BATCH1", "EXTID": "CN=BATCH1,OU=BatchJobs,O=Acme",  "TYPE": "DN", "SEQNO": "0"},
]


def test_pp_impersonation_caller_controlled_rule_flags_everyone():
    """${name} rule + populated USREXTID = every row is impersonatable,
    privileged users surface as a separate list."""
    from sapmap_scc_pp_analyzer import analyze_pp_impersonation
    pp = _parse_pp_xml("scc_config_critical_name.ini")
    imp = analyze_pp_impersonation(pp, _USREXT_ROWS)
    assert imp["ok"] is True
    assert imp["rule_caller_controlled"] is True
    assert imp["exploitability"] == "trivial"
    assert len(imp["matched_users"]) == len(_USREXT_ROWS)
    priv_names = {p["bname"] for p in imp["privileged_users"]}
    assert "DDIC" in priv_names
    assert "SAP*" in priv_names


def test_pp_impersonation_hardcoded_rule_only_matches_literal():
    """Hardcoded CN=DDIC rule matches the single DDIC USREXTID row.
    Exploitability is still 'trivial' because every cloud caller maps
    to a privileged user — not 'constrained'."""
    from sapmap_scc_pp_analyzer import analyze_pp_impersonation
    pp = _parse_pp_xml("scc_config_high_hardcoded_ddic.ini")
    imp = analyze_pp_impersonation(pp, _USREXT_ROWS)
    assert imp["rule_caller_controlled"] is False
    matched = [m["bname"] for m in imp["matched_users"]]
    assert matched == ["DDIC"]
    # Privileged literal mapping = trivial (cloud caller IS DDIC)
    assert imp["exploitability"] == "trivial"
    assert any(p["bname"] == "DDIC" for p in imp["privileged_users"])


def test_pp_impersonation_hardcoded_to_unprivileged_is_constrained():
    """Hardcoded mapping to a non-privileged user is 'constrained' —
    every cloud caller becomes that one specific user, blast radius
    depends on that user's role assignments."""
    from sapmap_scc_pp_analyzer import analyze_pp_impersonation
    pp = {
        "ok": True, "mode": "LOCAL",
        "subject_patterns": [{"dn_entries": [{"key": "CN", "value": "BATCH1"}],
                                "condition": "", "description": ""}],
        "validity_mins": 60, "sso_tolerance_h": 2, "raw_xml": "",
    }
    imp = analyze_pp_impersonation(pp, _USREXT_ROWS)
    assert imp["rule_caller_controlled"] is False
    matched = [m["bname"] for m in imp["matched_users"]]
    assert matched == ["BATCH1"]
    assert imp["exploitability"] == "constrained"
    assert imp["privileged_users"] == []


def test_pp_impersonation_clean_rule_no_matches():
    """Stable ${user_uuid} CN rule + condition + no UUIDs in USREXTID
    = nothing impersonatable.  Caller-controlled is False so only an
    exact UUID literal would have matched."""
    from sapmap_scc_pp_analyzer import analyze_pp_impersonation
    pp = _parse_pp_xml("scc_config_clean_scoped.ini")
    imp = analyze_pp_impersonation(pp, _USREXT_ROWS)
    assert imp["rule_caller_controlled"] is False
    assert imp["exploitability"] == "blocked"
    assert imp["matched_users"] == []


def test_pp_impersonation_empty_usrextid_returns_helpful_note():
    from sapmap_scc_pp_analyzer import analyze_pp_impersonation
    pp = _parse_pp_xml("scc_config_critical_name.ini")
    imp = analyze_pp_impersonation(pp, [])
    assert imp["matched_users"] == []
    assert "USREXTID has not been read" in imp["notes"]


def test_extract_cn_handles_full_dn_and_bare_cn():
    from sapmap_scc_pp_analyzer import _extract_cn
    assert _extract_cn("CN=alice,OU=Eng,O=Acme") == "alice"
    assert _extract_cn("alice@example.com") == "alice@example.com"
    # Escaped comma inside CN (rare but valid)
    assert _extract_cn(r"CN=Smith\, John,O=Acme") == "Smith, John"
    assert _extract_cn("") == ""


def test_parser_roundtrip_against_live_backup_if_present():
    """Smoke test against the operator's real backup zips when they
    exist in the working tree.  Skipped silently when not — keeps
    CI deterministic."""
    repo_root = os.path.dirname(HERE)
    candidates = [
        os.path.join(repo_root, "loot", "scc", "192.168.2.209",
                     "scc_backup_192.168.2.209_20260505T102704.zip"),
        os.path.join(repo_root, "loot", "scc", "10.10.1.4",
                     "scc_backup_10.10.1.4_20260504T122840.zip"),
    ]
    candidates = [p for p in candidates if os.path.exists(p)]
    if not candidates:
        return  # skip
    from sapmap_scc_keystore import (
        parse_pp_config_from_zip, parse_pp_trust_from_zip,
    )
    from sapmap_scc_pp_analyzer import analyze_backup
    for z in candidates:
        pp = parse_pp_config_from_zip(z)
        assert pp.get("ok"), pp
        assert pp.get("mode") in ("LOCAL", "KERBEROS",
                                    "SECURE_LOGIN_SERVER", "")
        trust = parse_pp_trust_from_zip(z)
        assert trust.get("ok")
        bundle = analyze_backup(pp, trust)
        assert bundle["ok"]
        # At least the per-pattern rules should not crash on real data.
        assert isinstance(bundle["findings"], list)
        assert isinstance(bundle["summary"], dict)
