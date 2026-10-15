"""Compliance-framework tagging for SAPMAP findings (issue #28).

Findings carry RAW framework IDs ("SOX", "GDPR", "NIS2", "ISO27001", "DORA");
the human name, URL and control area are resolved at render time via this
catalog, so .sapmap state files stay small and this module is the single
source of truth.  This mirrors the MITRE ATT&CK catalog in
``modules.core.sapmap_attack`` one-for-one.

The mapping is anchored on the SAME capability keys as
``sapmap_attack.CAPABILITY_MAP``, so a finding that already passes
``attack_capability=...`` to ``emit_finding`` automatically picks up its
compliance tags too — no per-callsite change needed.

An empty list = the capability is deliberately un-mapped (informational, or no
clear regulatory implication) — identical convention to the ATT&CK map.  The
mapping is intentionally conservative: a framework is tagged only where the
capability plausibly evidences a control gap under it, not on every finding.

Frameworks shipped on day one (operator-selected, issue #28):
  SOX       — financial reporting integrity (ICFR / ITGC: access, SoD, change)
  GDPR      — personal-data confidentiality, integrity, breach accountability
  NIS2      — cyber risk management & incident readiness (essential/important)
  ISO27001  — ISO/IEC 27001:2022 ISMS (Annex A technical/organisational)
  DORA      — ICT risk & operational resilience for EU financial entities

The FRAMEWORKS registry is the only thing to touch to add PCI-DSS / NIST CSF /
DSAG-BSI later; no other code changes are required.
"""
from __future__ import annotations

from typing import Dict, Iterable, List

COMPLIANCE_VERSION = "2026.1"

# Stable render order (chips, coverage section, report).
FRAMEWORK_ORDER: List[str] = ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"]

FRAMEWORKS: Dict[str, Dict[str, str]] = {
    "SOX": {
        "name": "SOX",
        "full_name": "Sarbanes-Oxley Act (§404 — ICFR)",
        "url": "https://www.sec.gov/spotlight/sarbanes-oxley.htm",
        "control_area": ("Internal controls over financial reporting — access "
                         "control, segregation of duties, change management, "
                         "and audit-trail integrity on the SAP system of record"),
    },
    "GDPR": {
        "name": "GDPR",
        "full_name": "General Data Protection Regulation (EU) 2016/679",
        "url": "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
        "control_area": ("Confidentiality, integrity and accountability for "
                         "personal data — unauthorised access/exfiltration and "
                         "breach exposure (Art. 5, 32, 33/34)"),
    },
    "NIS2": {
        "name": "NIS2",
        "full_name": "NIS2 Directive (EU) 2022/2555",
        "url": "https://eur-lex.europa.eu/eli/dir/2022/2555/oj",
        "control_area": ("Cyber risk-management measures & incident readiness "
                         "for essential/important entities — access control, "
                         "vulnerability handling, detection (Art. 21)"),
    },
    "ISO27001": {
        "name": "ISO 27001",
        "full_name": "ISO/IEC 27001:2022 (Annex A)",
        "url": "https://www.iso.org/standard/27001",
        "control_area": ("ISMS technical & organisational controls — access "
                         "(A.5/A.8.2-5), vulnerability management (A.8.8), "
                         "cryptography/secrets (A.8.24), logging (A.8.15-16)"),
    },
    "DORA": {
        "name": "DORA",
        "full_name": "Digital Operational Resilience Act (EU) 2022/2554",
        "url": "https://eur-lex.europa.eu/eli/reg/2022/2554/oj",
        "control_area": ("ICT risk management & operational resilience for "
                         "financial entities — critical ICT vulnerabilities, "
                         "availability, and ICT third-party/connectivity risk"),
    },
}

# ---------------------------------------------------------------------------
# Capability -> framework mapping.  Keys MUST exist in
# sapmap_attack.CAPABILITY_MAP (enforced by tests).  Grouped by phase to match
# the ATT&CK map layout.
# ---------------------------------------------------------------------------
COMPLIANCE_MAP: Dict[str, List[str]] = {
    # --- Reconnaissance -----------------------------------------------------
    # Pure port scanning is SAPMAP's own mechanics — intentionally un-mapped.
    "recon.fast_scan":            [],
    "recon.deep_scan":            [],
    "recon.system_info":          ["NIS2", "ISO27001"],
    "recon.rfc_system_info_leak": ["NIS2", "ISO27001"],
    "recon.ms_info_disclosure":   ["NIS2", "ISO27001"],
    "recon.logon_banner_scan":    ["NIS2", "ISO27001"],
    "recon.diag_scrape":          ["NIS2", "ISO27001"],
    "recon.sapcontrol_query":     ["NIS2", "ISO27001"],
    "recon.snc_posture":          ["NIS2", "ISO27001"],
    "recon.client_enum":          ["NIS2", "ISO27001"],
    "recon.user_enum":            ["GDPR", "NIS2", "ISO27001"],
    "recon.brute_force_default":  ["SOX", "NIS2", "ISO27001"],
    "recon.ucon_status":          ["NIS2", "ISO27001"],
    "recon.tms_buffer":           ["SOX", "NIS2", "ISO27001"],
    "recon.tms_domain":           ["SOX", "NIS2", "ISO27001"],
    "recon.oa2c_read":            ["GDPR", "NIS2", "ISO27001"],
    "recon.usrextid_read":        ["GDPR", "NIS2", "ISO27001"],
    "recon.dbcon_probe":          ["NIS2", "ISO27001"],
    "recon.dbcon_describe":       ["NIS2", "ISO27001"],
    "recon.dbcon_enumerate":      ["NIS2", "ISO27001"],
    "recon.dbcon_resolve":        ["NIS2", "ISO27001"],
    "recon.dbcon_hana_sweep":     ["NIS2", "ISO27001"],
    "recon.scc_fingerprint":      ["NIS2", "ISO27001", "DORA"],
    "recon.scc_relay":            ["NIS2", "ISO27001", "DORA"],
    "recon.saprouter_info":       ["NIS2", "ISO27001", "DORA"],
    "recon.saprouter_route_enum": ["NIS2", "ISO27001", "DORA"],
    "recon.btp_subaccount_enum":  ["NIS2", "ISO27001", "DORA"],
    "recon.wd_fingerprint":       ["NIS2", "ISO27001"],
    "recon.wd_backends":          ["NIS2", "ISO27001"],

    # --- Credential access --------------------------------------------------
    "creds.abap_secstore":               ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "creds.java_secstore":               ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "creds.scc_keystore":                ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "creds.pse_loot":                    ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "creds.oa2c_secrets":                ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "creds.btp_destinations":            ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "creds.dbcon_auth_dump":             ["SOX", "GDPR", "NIS2", "ISO27001"],
    "creds.dbcon_usr02_dump":            ["SOX", "GDPR", "NIS2", "ISO27001"],
    "creds.user_password_hash":          ["SOX", "GDPR", "NIS2", "ISO27001"],
    "creds.ssh_private_key":             ["SOX", "GDPR", "NIS2", "ISO27001"],
    "creds.scc_users_xml":               ["SOX", "GDPR", "NIS2", "ISO27001"],
    "creds.wd_icmauth":                  ["SOX", "GDPR", "NIS2", "ISO27001"],
    "creds.password_reuse_cross_system": ["SOX", "NIS2", "ISO27001"],
    "creds.password_spray":              ["SOX", "NIS2", "ISO27001"],
    "creds.password_spray_purple_telemetry": ["SOX", "NIS2", "ISO27001"],
    "creds.default_probe":               ["SOX", "NIS2", "ISO27001"],
    "creds.diag_login_screen_leak":      ["NIS2", "ISO27001"],

    # --- Data / collection --------------------------------------------------
    "data.dbcon_dump":            ["SOX", "GDPR", "NIS2", "ISO27001"],
    "data.dbcon_custom_sql":      ["SOX", "GDPR", "NIS2", "ISO27001"],
    "data.dbcon_peek":            ["SOX", "GDPR", "NIS2", "ISO27001"],
    "data.read_table":            ["SOX", "GDPR", "NIS2", "ISO27001"],
    "data.wd_backend_table_read": ["SOX", "GDPR", "NIS2", "ISO27001"],
    "data.scc_users_dump":        ["SOX", "GDPR", "NIS2", "ISO27001"],
    "data.scc_users_dump_via_lpe": ["SOX", "GDPR", "NIS2", "ISO27001"],
    "data.tms_transport_history": ["SOX", "NIS2", "ISO27001"],
    "data.fs_download":           ["SOX", "GDPR", "NIS2", "ISO27001"],
    "data.fs_upload":             ["SOX", "NIS2", "ISO27001"],
    "data.pse_export":            ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "data.fs_list":               ["NIS2", "ISO27001"],
    "data.diag_login_screen_leak": ["NIS2", "ISO27001"],
    "data.loot_stage":            [],
    "data.capability_analyse":    [],

    # --- Initial access / exploitation (unauth RCE = total compromise) ------
    "exploit.sapxpg":            ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "exploit.10kblaze":          ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "exploit.cve_2020_6287":     ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "exploit.cve_2022_22536":    ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "exploit.cve_2025_31324":    ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "exploit.ms_betrusted":      ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "exploit.ms_ascs_gw_rogue":  ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],

    # --- Privilege escalation ----------------------------------------------
    "privesc.bapi_profiles":     ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "privesc.dpmon_sap_star":    ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "privesc.webgui_rsbdcos0":   ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],

    # --- OS local privilege escalation (host root = full compromise) --------
    "lpe.copyfail":              ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "lpe.dirtyfrag":             ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "lpe.efspotato":             ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "lpe.godpotato":             ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "lpe.miniplasma":            ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "lpe.peditcow":              ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],

    # --- Persistence --------------------------------------------------------
    "persist.create_user":          ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "persist.sap_all_assign":       ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "persist.web_shell":            ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "persist.ssh_key_plant":        ["SOX", "NIS2", "ISO27001", "DORA"],
    "persist.transport_addtobuffer": ["SOX", "NIS2", "ISO27001", "DORA"],
    "persist.transport_import":     ["SOX", "NIS2", "ISO27001", "DORA"],

    # --- Lateral movement ---------------------------------------------------
    "lateral.rfc_propagate":          ["SOX", "GDPR", "NIS2", "ISO27001"],
    "lateral.ticket_propagate_all":   ["SOX", "GDPR", "NIS2", "ISO27001"],
    "lateral.sapmap_user":            ["SOX", "GDPR", "NIS2", "ISO27001"],
    "lateral.tmsadm_rfc":             ["SOX", "NIS2", "ISO27001"],
    "lateral.sxpg_exec":              ["SOX", "NIS2", "ISO27001"],
    "lateral.internal_ip_spoof":      ["NIS2", "ISO27001"],
    "lateral.mysapsso2_forge":        ["SOX", "NIS2", "ISO27001"],
    "lateral.mysapsso2_replay":       ["SOX", "NIS2", "ISO27001"],
    "lateral.scc_tunnel_impersonate": ["SOX", "NIS2", "ISO27001", "DORA"],
    "lateral.cert_proxy_open":        ["NIS2", "ISO27001", "DORA"],
    "lateral.btp_cert_proxy":         ["NIS2", "ISO27001", "DORA"],
    "lateral.saprouter_tunnel":       ["NIS2", "ISO27001", "DORA"],
    "lateral.dbcon_direct":           ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "lateral.ssh_key_reuse":          ["SOX", "NIS2", "ISO27001", "DORA"],
    "lateral.wd_pivot":               ["NIS2", "ISO27001", "DORA"],

    # --- Defense evasion (impairing audit/detection controls) ---------------
    "evasion.rsau_disable":      ["SOX", "NIS2", "ISO27001", "DORA"],
    "evasion.ucon_disable":      ["SOX", "NIS2", "ISO27001", "DORA"],
    "evasion.death_star":        ["SOX", "NIS2", "ISO27001", "DORA"],

    # --- Impact: ransomware simulation (availability/resilience) ------------
    "ransapware.encrypt":        ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],
    "ransapware.decrypt":        ["SOX", "GDPR", "NIS2", "ISO27001", "DORA"],

    # --- SNC posture --------------------------------------------------------
    "snc.scan":                  ["NIS2", "ISO27001"],
}


# ---------------------------------------------------------------------------
# Resolution helpers (mirror sapmap_attack)
# ---------------------------------------------------------------------------

def _order_key(fid: str) -> int:
    try:
        return FRAMEWORK_ORDER.index(fid)
    except ValueError:
        return len(FRAMEWORK_ORDER)


def frameworks_for(capability_key: str) -> List[str]:
    """Return the framework IDs mapped to a capability.  Unknown or
    deliberately un-mapped keys return ``[]`` (silent — that is the correct
    behaviour for an informational capability)."""
    return list(COMPLIANCE_MAP.get(capability_key, []))


def framework_details(ids: Iterable[str]) -> List[Dict]:
    """Resolve framework IDs into full dicts ({id, name, full_name, url,
    control_area}), skipping unknowns, in canonical order."""
    uniq = []
    for fid in ids or []:
        if fid in FRAMEWORKS and fid not in uniq:
            uniq.append(fid)
    uniq.sort(key=_order_key)
    return [{"id": fid, **FRAMEWORKS[fid]} for fid in uniq]


def collect_from_findings(findings: Iterable) -> List[str]:
    """De-duplicated framework IDs across a Finding iterable, in canonical
    order.  Accepts dataclass Findings and dicts (state snapshots / bus
    records), mirroring sapmap_attack.collect_from_findings."""
    seen: List[str] = []
    for f in findings or []:
        if hasattr(f, "compliance_tags"):
            tags = f.compliance_tags or []
        elif isinstance(f, dict):
            tags = f.get("compliance_tags", []) or []
        else:
            continue
        for fid in tags:
            if fid not in seen:
                seen.append(fid)
    seen.sort(key=_order_key)
    return seen


def counts_from_findings(findings: Iterable) -> Dict[str, int]:
    """Per-framework count of findings carrying each tag (for the report's
    coverage section).  Keys are framework IDs; order is canonical."""
    counts: Dict[str, int] = {fid: 0 for fid in FRAMEWORK_ORDER}
    for f in findings or []:
        if hasattr(f, "compliance_tags"):
            tags = f.compliance_tags or []
        elif isinstance(f, dict):
            tags = f.get("compliance_tags", []) or []
        else:
            continue
        for fid in set(tags):
            if fid in counts:
                counts[fid] += 1
            else:
                counts[fid] = 1
    return {fid: n for fid, n in counts.items() if n > 0}
