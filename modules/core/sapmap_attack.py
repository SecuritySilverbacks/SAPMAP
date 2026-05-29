"""
sapmap_attack.py — MITRE ATT&CK Enterprise mapping for SAPMAP capabilities.

Pinned against ATT&CK Enterprise v15.1.  Three pieces:

    TACTICS         — the 12 enterprise tactics.
    TECHNIQUES      — only the techniques SAPMAP maps to.  We do NOT
                       ship MITRE's full STIX export.
    CAPABILITY_MAP  — { capability_key: [technique_ids] }.  This is the
                       single source of truth for what each SAPMAP
                       action maps to.  Adding a new exploit module
                       means adding one row here.

Capability keys follow ``<group>.<action_slug>`` convention:
    exploit.10kblaze
    creds.default_probe
    lpe.miniplasma
    snc.scan          (mapped to T1082 — see comment below)

Findings carry RAW technique IDs ("T1190", "T1078.001") — names, tactics
and URLs are looked up here at render-time to keep .sapmap state files
small and to maintain a single source of truth as ATT&CK evolves.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional

ATTACK_VERSION = "v15.1"
ATTACK_DOMAIN = "enterprise-attack"
NAVIGATOR_VERSION = "4.5"


# ---------------------------------------------------------------------------
# Tactics — the 12 enterprise tactics, MITRE's canonical order.
# ---------------------------------------------------------------------------

TACTICS: Dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

# Display order used by the heatmap grid (left→right) and report.
TACTIC_ORDER: List[str] = [
    "TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004",
    "TA0005", "TA0006", "TA0007", "TA0008", "TA0009", "TA0011",
    "TA0010", "TA0040",
]


# ---------------------------------------------------------------------------
# Techniques — only the ones SAPMAP maps to.
# Each entry: name, tactic ID, optional sub-of (for sub-techniques).
# ---------------------------------------------------------------------------

TECHNIQUES: Dict[str, Dict] = {
    # Discovery
    "T1046":     {"name": "Network Service Discovery",      "tactic": "TA0007"},
    "T1018":     {"name": "Remote System Discovery",        "tactic": "TA0007"},
    "T1082":     {"name": "System Information Discovery",   "tactic": "TA0007"},
    "T1087":     {"name": "Account Discovery",              "tactic": "TA0007"},
    "T1087.002": {"name": "Domain Account",                 "tactic": "TA0007", "sub_of": "T1087"},
    "T1518":     {"name": "Software Discovery",             "tactic": "TA0007"},
    "T1526":     {"name": "Cloud Service Discovery",        "tactic": "TA0007"},
    "T1592":     {"name": "Gather Victim Host Information", "tactic": "TA0043"},

    # Initial Access
    "T1190":     {"name": "Exploit Public-Facing Application", "tactic": "TA0001"},

    # Execution
    "T1059":     {"name": "Command and Scripting Interpreter", "tactic": "TA0002"},
    "T1059.006": {"name": "Python",                         "tactic": "TA0002", "sub_of": "T1059"},

    # Persistence
    "T1136":     {"name": "Create Account",                 "tactic": "TA0003"},
    "T1136.001": {"name": "Local Account",                  "tactic": "TA0003", "sub_of": "T1136"},
    "T1098":     {"name": "Account Manipulation",           "tactic": "TA0003"},
    "T1098.004": {"name": "SSH Authorized Keys",            "tactic": "TA0003", "sub_of": "T1098"},
    "T1505":     {"name": "Server Software Component",      "tactic": "TA0003"},
    "T1505.003": {"name": "Web Shell",                      "tactic": "TA0003", "sub_of": "T1505"},

    # Privilege Escalation
    "T1068":     {"name": "Exploitation for Privilege Escalation", "tactic": "TA0004"},

    # Defense Evasion
    "T1574":     {"name": "Hijack Execution Flow",          "tactic": "TA0005"},
    "T1550":     {"name": "Use Alternate Authentication Material", "tactic": "TA0005"},
    "T1550.004": {"name": "Web Session Cookie",             "tactic": "TA0005", "sub_of": "T1550"},

    # Credential Access
    "T1003":     {"name": "OS Credential Dumping",          "tactic": "TA0006"},
    "T1552":     {"name": "Unsecured Credentials",          "tactic": "TA0006"},
    "T1552.001": {"name": "Credentials In Files",           "tactic": "TA0006", "sub_of": "T1552"},
    "T1552.004": {"name": "Private Keys",                   "tactic": "TA0006", "sub_of": "T1552"},
    "T1555":     {"name": "Credentials from Password Stores", "tactic": "TA0006"},
    "T1606":     {"name": "Forge Web Credentials",          "tactic": "TA0006"},

    # Valid Accounts (cross-tactic in MITRE — kept under Initial Access here)
    "T1078":     {"name": "Valid Accounts",                 "tactic": "TA0001"},
    "T1078.001": {"name": "Default Accounts",               "tactic": "TA0001", "sub_of": "T1078"},
    "T1078.004": {"name": "Cloud Accounts",                 "tactic": "TA0001", "sub_of": "T1078"},

    # Lateral Movement
    "T1021":     {"name": "Remote Services",                "tactic": "TA0008"},
    "T1090":     {"name": "Proxy",                          "tactic": "TA0011"},
    "T1090.001": {"name": "Internal Proxy",                 "tactic": "TA0011", "sub_of": "T1090"},

    # Collection
    "T1213":     {"name": "Data from Information Repositories", "tactic": "TA0009"},
    "T1074":     {"name": "Data Staged",                    "tactic": "TA0009"},
}


# ---------------------------------------------------------------------------
# Capability map — single source of truth.
# Empty list = explicitly un-mapped (info-only, no ATT&CK fit).
# ---------------------------------------------------------------------------

CAPABILITY_MAP: Dict[str, List[str]] = {
    # ---- Discovery ----
    "recon.fast_scan":           ["T1046", "T1018", "T1082"],
    "recon.deep_scan":           ["T1046", "T1018", "T1082"],
    "recon.system_info":         ["T1082"],
    "recon.diag_scrape":         ["T1082"],
    "recon.sapcontrol_query":    ["T1082"],
    "recon.client_enum":         ["T1082"],
    "recon.user_enum":           ["T1087", "T1087.002"],
    "recon.wd_fingerprint":      ["T1046", "T1518"],
    "recon.wd_backends":         ["T1018"],
    "recon.scc_fingerprint":     ["T1526"],
    "recon.scc_relay":           ["T1018"],
    "recon.btp_subaccount_enum": ["T1526"],
    "recon.saprouter_info":      ["T1018", "T1592"],
    "snc.scan":                  ["T1082"],

    # ---- Initial Access / Execution ----
    "exploit.10kblaze":          ["T1190", "T1059"],
    "exploit.cve_2025_31324":    ["T1190", "T1505.003"],
    "exploit.cve_2020_6287":     ["T1190", "T1136.001"],
    "exploit.cve_2022_22536":    ["T1190", "T1574"],
    "exploit.ms_betrusted":      ["T1190", "T1078"],
    "exploit.sapxpg":            ["T1190", "T1059"],

    # ---- Privilege Escalation ----
    "privesc.dpmon_sap_star":    ["T1068", "T1078"],
    "privesc.bapi_profiles":     ["T1068", "T1098"],
    "privesc.webgui_rsbdcos0":   ["T1068", "T1059.006"],
    "lpe.copyfail":              ["T1068"],
    "lpe.dirtyfrag":             ["T1068"],
    "lpe.miniplasma":            ["T1068"],
    "lpe.godpotato":             ["T1068"],
    "lpe.efspotato":             ["T1068"],

    # ---- Credential Access ----
    "creds.default_probe":       ["T1078.001"],
    "creds.user_password_hash":  ["T1003"],
    "creds.abap_secstore":       ["T1555"],
    "creds.java_secstore":       ["T1555"],
    "creds.btp_destinations":    ["T1552.001"],
    "creds.scc_keystore":        ["T1555", "T1552.004"],
    "creds.scc_users_xml":       ["T1555"],
    "creds.pse_loot":            ["T1552.004"],
    "creds.oa2c_secrets":        ["T1555"],

    # ---- Lateral Movement ----
    "lateral.rfc_propagate":     ["T1021", "T1078"],
    "lateral.sapmap_user":       ["T1078", "T1136"],
    "lateral.mysapsso2_forge":   ["T1606"],
    "lateral.mysapsso2_replay":  ["T1550.004", "T1078"],
    "lateral.sxpg_exec":         ["T1021", "T1059"],
    "lateral.wd_pivot":          ["T1090", "T1021"],
    "lateral.saprouter_tunnel":  ["T1090.001"],
    "lateral.scc_tunnel_impersonate": ["T1078.004", "T1550"],
    "lateral.internal_ip_spoof": ["T1078"],

    # ---- Persistence ----
    "persist.create_user":       ["T1136.001", "T1098"],
    "persist.sap_all_assign":    ["T1098"],
    "persist.ssh_key_plant":     ["T1098.004"],
    "persist.web_shell":         ["T1505.003"],

    # ---- Collection ----
    "data.read_table":           ["T1213"],
    "data.capability_analyse":   ["T1213"],
    "data.scc_users_dump":       ["T1213"],
    "data.loot_stage":           ["T1074"],
}


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def lookup(tid: str) -> Optional[Dict]:
    """Return {id, name, tactic, tactic_name, url, sub_of} or None."""
    t = TECHNIQUES.get(tid)
    if not t:
        return None
    return {
        "id":          tid,
        "name":        t["name"],
        "tactic":      t["tactic"],
        "tactic_name": TACTICS.get(t["tactic"], ""),
        "url":         f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
        "sub_of":      t.get("sub_of", ""),
    }


def techniques_for(capability_key: str) -> List[str]:
    """Return the list of T-IDs mapped to a capability.  Unknown keys
    return [] (and we log nothing — silent absence is the correct
    behavior for an info-only capability).
    """
    return list(CAPABILITY_MAP.get(capability_key, []))


def technique_details(ids: Iterable[str]) -> List[Dict]:
    """Resolve a list of T-IDs into full dicts (skipping unknowns)."""
    out = []
    for tid in ids:
        info = lookup(tid)
        if info:
            out.append(info)
    return out


def aggregate_by_tactic(technique_ids: Iterable[str]) -> Dict[str, List[str]]:
    """Group T-IDs by tactic.  Returns {tactic_id: sorted([tids])}.

    Used by node detail "ATT&CK observed" section and the heatmap.
    """
    by_tactic: Dict[str, set] = {}
    for tid in technique_ids:
        info = lookup(tid)
        if not info:
            continue
        by_tactic.setdefault(info["tactic"], set()).add(tid)
    return {t: sorted(v) for t, v in by_tactic.items()}


def collect_from_findings(findings: Iterable) -> List[str]:
    """Walk a Finding iterable and return a de-duplicated list of T-IDs.

    Accepts both dataclass Finding instances and dicts (from
    SAPMAPState snapshots or the emit_finding bus records).
    """
    seen = []
    for f in findings or []:
        if hasattr(f, "attack_techniques"):
            tids = f.attack_techniques or []
        elif isinstance(f, dict):
            tids = f.get("attack_techniques", []) or []
        else:
            continue
        for tid in tids:
            if tid not in seen:
                seen.append(tid)
    return seen


# ---------------------------------------------------------------------------
# Navigator JSON layer (https://github.com/mitre-attack/attack-navigator)
# ---------------------------------------------------------------------------

# Severity → score for the gradient (1..5).  Severity is an IntEnum
# whose values mirror SAPMAP's: INFO=1, LOW=2, MEDIUM=3, HIGH=4,
# CRITICAL=5 — but we accept any int and clamp.
_SEV_SCORE = {1: 1, 2: 2, 3: 3, 4: 4, 5: 5}


def _score_for(sev_value: int) -> int:
    return max(1, min(5, int(sev_value or 1)))


def to_navigator_layer(state, *, name: str = "",
                       description: str = "") -> Dict:
    """Build an ATT&CK Navigator v4.5 layer JSON from a SAPMAPState.

    For each technique observed across all findings:
      * score = max severity of any Finding bearing the technique
      * comment lists the SIDs and CVEs that exercised it
    Cells light up using Navigator's built-in 1..5 gradient.

    Args:
        state: SAPMAPState instance (or any object exposing .nodes —
               a dict of {sid: SAPNode}).
        name, description: layer metadata for the Navigator UI.

    Returns a dict that ``json.dumps`` cleanly.
    """
    # Aggregate per-technique evidence: { tid: { "score": int,
    #                                            "evidence": [(sid, cve, sev), ...] } }
    bucket: Dict[str, Dict] = {}
    nodes = getattr(state, "nodes", {}) or {}
    for sid, node in nodes.items():
        node_sid = getattr(node, "sid", sid) or sid
        for f in getattr(node, "findings", []) or []:
            tids = getattr(f, "attack_techniques", None) or []
            sev  = int(getattr(f, "severity", 1) or 1)
            cve  = getattr(f, "detail", "") or ""  # detail often carries CVE
            for tid in tids:
                slot = bucket.setdefault(tid, {"score": 0, "evidence": []})
                if sev > slot["score"]:
                    slot["score"] = sev
                slot["evidence"].append((node_sid, cve, sev))

    techniques_list = []
    for tid, slot in bucket.items():
        info = lookup(tid)
        if not info:
            continue
        comment_lines = []
        for ev_sid, ev_cve, ev_sev in slot["evidence"][:8]:
            line = f"{ev_sid} (sev={ev_sev})"
            if ev_cve:
                line += f" — {ev_cve[:80]}"
            comment_lines.append(line)
        if len(slot["evidence"]) > 8:
            comment_lines.append(
                f"… +{len(slot['evidence']) - 8} more")
        techniques_list.append({
            "techniqueID": tid,
            "score":       _score_for(slot["score"]),
            "comment":     "\n".join(comment_lines),
            "enabled":     True,
        })

    return {
        "name":        name or "SAPMAP engagement",
        "description": (description
                        or f"Generated by SAPMAP — ATT&CK {ATTACK_VERSION}"),
        "domain":      ATTACK_DOMAIN,
        "versions": {
            "attack":    ATTACK_VERSION.lstrip("v"),
            "navigator": NAVIGATOR_VERSION,
            "layer":     "4.5",
        },
        "techniques": techniques_list,
        "gradient": {
            "colors":   ["#fee5d9", "#fcae91", "#fb6a4a", "#de2d26", "#a50f15"],
            "minValue": 1,
            "maxValue": 5,
        },
        "legendItems": [
            {"label": "INFO",     "color": "#fee5d9"},
            {"label": "LOW",      "color": "#fcae91"},
            {"label": "MEDIUM",   "color": "#fb6a4a"},
            {"label": "HIGH",     "color": "#de2d26"},
            {"label": "CRITICAL", "color": "#a50f15"},
        ],
        "metadata": [
            {"name": "tool",            "value": "SAPMAP"},
            {"name": "attack_version",  "value": ATTACK_VERSION},
        ],
    }


# ---------------------------------------------------------------------------
# Heatmap grid data — shared by the in-GUI modal and the report SVG.
# ---------------------------------------------------------------------------

def heatmap_grid(state) -> Dict:
    """Compute the heatmap matrix for rendering.

    Returns:
        {
            "columns": [{tactic_id, tactic_name, cells: [
                {tid, name, sub_of, score, sid_count, sids: [...]}, ...
            ]}, ...],
            "totals": {
                "techniques":    int,
                "tactics":       int,
                "findings":      int,
                "by_severity":   {1: n, 2: n, ...},
            }
        }
    """
    # bucket[tid] = {"score": int, "sids": set, "count": int}
    bucket: Dict[str, Dict] = {}
    sev_counts: Dict[int, int] = {}
    nodes = getattr(state, "nodes", {}) or {}
    total_findings = 0
    for sid, node in nodes.items():
        node_sid = getattr(node, "sid", sid) or sid
        for f in getattr(node, "findings", []) or []:
            tids = getattr(f, "attack_techniques", None) or []
            sev  = int(getattr(f, "severity", 1) or 1)
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            if tids:
                total_findings += 1
            for tid in tids:
                slot = bucket.setdefault(tid, {
                    "score": 0, "sids": set(), "count": 0})
                if sev > slot["score"]:
                    slot["score"] = sev
                slot["sids"].add(node_sid)
                slot["count"] += 1

    columns = []
    for tactic_id in TACTIC_ORDER:
        if tactic_id not in TACTICS:
            continue
        cells = []
        for tid, info in sorted(TECHNIQUES.items()):
            if info["tactic"] != tactic_id:
                continue
            slot = bucket.get(tid, {"score": 0, "sids": set(), "count": 0})
            cells.append({
                "id":         tid,
                "name":       info["name"],
                "sub_of":     info.get("sub_of", ""),
                "score":      slot["score"],
                "sid_count":  len(slot["sids"]),
                "sids":       sorted(slot["sids"]),
                "count":      slot["count"],
            })
        if cells:
            columns.append({
                "tactic_id":   tactic_id,
                "tactic_name": TACTICS[tactic_id],
                "cells":       cells,
            })

    return {
        "columns": columns,
        "totals": {
            "techniques":  len([s for s in bucket.values() if s["score"] > 0]),
            "tactics":     len([c for c in columns
                                if any(cell["score"] > 0
                                       for cell in c["cells"])]),
            "findings":    total_findings,
            "by_severity": sev_counts,
        },
        "attack_version": ATTACK_VERSION,
    }
