#!/usr/bin/env python3
"""Diff between two SAPMAPState snapshots.

Compares two ``.sapmap`` runs (or one saved state vs. an in-memory
state) and produces a structured delta dict, plus Markdown / HTML
renderings sharing the engagement-report's visual language.

What gets diffed:
  * SAP nodes              — added / removed / changed (pwned,
                              is_production, has_critical_finding,
                              credentials count, findings count)
  * Findings per node      — added (new vulnerabilities surfaced)
                              and removed (remediated)
  * RFC connections        — added / removed / changed (SAP_ALL,
                              tested, logon_successful)
  * Cloud Connectors       — added / removed / changed (pwned,
                              default_creds_live, version)
  * Trust chains           — added / removed (computed via
                              sapmap_chain.analyze_chains on each
                              snapshot)
  * Created users          — what SAPMAP added between runs
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Optional, Tuple

from sapmap_models import SAPMAPState


# ---------------------------------------------------------------------------
# Identity helpers — every entity has a stable key for matching
# across snapshots.
# ---------------------------------------------------------------------------

def _conn_key(c) -> Tuple[str, str, str]:
    """Identity of an RFCConnection across snapshots."""
    return (
        getattr(c, "source_sid", "") or (c.get("source_sid", "") if isinstance(c, dict) else ""),
        getattr(c, "target_sid", "") or (c.get("target_sid", "") if isinstance(c, dict) else ""),
        getattr(c, "destination_name", "") or (c.get("destination_name", "") if isinstance(c, dict) else ""),
    )


def _finding_key(sid: str, f) -> Tuple[str, str]:
    name = getattr(f, "name", "") if not isinstance(f, dict) else f.get("name", "")
    return (sid, name)


def _node_summary(n) -> dict:
    """Salient SAPNode fields for the diff payload."""
    return {
        "sid":              getattr(n, "sid", ""),
        "system_type":      getattr(n, "system_type", "") or "",
        "os_type":          getattr(n, "os_type", "") or "",
        "db_type":          getattr(n, "db_type", "") or "",
        "hostname":         getattr(n, "hostname", "") or getattr(n, "ip", ""),
        "is_production":    bool(getattr(n, "is_production", False)),
        "pwned":            bool(getattr(n, "pwned", False)),
        "has_critical_finding": bool(getattr(n, "has_critical_finding", False)),
        "credentials_count": len(getattr(n, "credentials", []) or []),
        "findings_count":    len(getattr(n, "findings", []) or []),
        "secstore_count":    len(getattr(n, "secstore_entries", []) or []),
        "java_secstore_count": len(getattr(n, "java_secstore_entries", []) or []),
        # DBCON pivot summary — number of edges + pwned edges +
        # discovered-via-dbcon flag (so a materialise-tag change
        # shows up in the diff view).
        "dbcon_edges_count": len(getattr(n, "dbcon_edges", []) or []),
        "dbcon_edges_pwned": sum(1 for e in getattr(n, "dbcon_edges", [])
                                  or [] if getattr(e, "pwned", False)),
        "discovered_via_dbcon": bool(getattr(n, "discovered_via_dbcon", False)),
        # CTS/TMS pivot (Bundle 1)
        "tms_destinations_count": len(getattr(n, "tms_destinations", []) or []),
        "tms_logons_ok": sum(1 for d in getattr(n, "tms_destinations", [])
                              or [] if getattr(d, "logon_ok", False)),
        "discovered_via_tms": bool(getattr(n, "discovered_via_tms", False)),
        "is_tms_controller": bool(getattr(n, "is_tms_controller", False)),
    }


def _conn_summary(c) -> dict:
    return {
        "source_sid":         getattr(c, "source_sid", "") or "",
        "target_sid":         getattr(c, "target_sid", "") or "",
        "destination_name":   getattr(c, "destination_name", "") or "",
        "rfc_user":           getattr(c, "rfc_user", "") or "",
        "client":             getattr(c, "client", "") or "",
        "has_sap_all":        bool(getattr(c, "has_sap_all", False)),
        "tested":             bool(getattr(c, "tested", False)),
        "logon_successful":   bool(getattr(c, "logon_successful", False)),
    }


def _scc_summary(s) -> dict:
    return {
        "host":               getattr(s, "host", ""),
        "version":            getattr(s, "version", "") or "",
        "pwned":              bool(getattr(s, "pwned", False)),
        "default_creds_live": bool(getattr(s, "default_creds_live", False)),
        "cves_suspected":     list(getattr(s, "cves_suspected", []) or []),
        "mappings_count":     len(getattr(s, "mappings", []) or []),
    }


def _finding_summary(sid: str, f) -> dict:
    sev = getattr(f, "severity", None)
    sev_name = getattr(sev, "name", str(sev)) if sev else "INFO"
    return {
        "sid":         sid,
        "name":        getattr(f, "name", ""),
        "severity":    sev_name,
        "description": (getattr(f, "description", "") or "")[:500],
    }


def _changed_node_fields(old: dict, new: dict) -> list:
    """Return a list of (field, old_val, new_val) tuples for fields
    whose value changed.  Only highlight the meaningful ones."""
    out = []
    for k in ("system_type", "os_type", "db_type", "hostname",
              "is_production", "pwned", "has_critical_finding",
              "credentials_count", "findings_count",
              "secstore_count", "java_secstore_count",
              "dbcon_edges_count", "dbcon_edges_pwned",
              "discovered_via_dbcon",
              "tms_destinations_count", "tms_logons_ok",
              "discovered_via_tms", "is_tms_controller"):
        if old.get(k) != new.get(k):
            out.append((k, old.get(k), new.get(k)))
    return out


def _changed_conn_fields(old: dict, new: dict) -> list:
    out = []
    for k in ("rfc_user", "client", "has_sap_all", "tested",
              "logon_successful"):
        if old.get(k) != new.get(k):
            out.append((k, old.get(k), new.get(k)))
    return out


def _changed_scc_fields(old: dict, new: dict) -> list:
    out = []
    for k in ("version", "pwned", "default_creds_live",
              "mappings_count"):
        if old.get(k) != new.get(k):
            out.append((k, old.get(k), new.get(k)))
    if set(old.get("cves_suspected", []) or []) != \
            set(new.get("cves_suspected", []) or []):
        out.append(("cves_suspected",
                    old.get("cves_suspected", []),
                    new.get("cves_suspected", [])))
    return out


# ---------------------------------------------------------------------------
# Core diff
# ---------------------------------------------------------------------------

def compute_state_diff(baseline: SAPMAPState,
                         current: SAPMAPState,
                         baseline_label: str = "baseline",
                         current_label: str = "current") -> dict:
    """Produce a structured diff between two SAPMAPState snapshots.

    Returns a dict suitable for JSON serialisation, Markdown rendering,
    or HTML rendering.  Pure function — no side effects.
    """
    diff = {
        "baseline_label": baseline_label,
        "current_label":  current_label,
        "baseline_timestamp": getattr(baseline, "timestamp", "") or "",
        "current_timestamp":  getattr(current, "timestamp", "") or "",
        "generated_at":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "nodes":       {"added": [], "removed": [], "changed": []},
        "findings":    {"added": [], "removed": []},
        "connections": {"added": [], "removed": [], "changed": []},
        "scc_nodes":   {"added": [], "removed": [], "changed": []},
        "trust_chains": {"added": [], "removed": []},
        "created_users": {"added": [], "removed": []},
        # Password-spraying runs (issue #69, PR5).  Added entries
        # are new SprayRun summaries keyed by run_id; removed is
        # the rare case where state_a and state_b come from
        # parallel engagements (or an operator ran reset_history
        # between snapshots).  locked_users_added surfaces the
        # defender-visible fallout.
        "spray_runs":   {"added": [], "removed": [],
                           "locked_users_added": []},
        "summary": {},
    }

    # --- Nodes ---
    base_sids = set(baseline.nodes.keys())
    curr_sids = set(current.nodes.keys())
    for sid in sorted(curr_sids - base_sids):
        diff["nodes"]["added"].append(_node_summary(current.nodes[sid]))
    for sid in sorted(base_sids - curr_sids):
        diff["nodes"]["removed"].append(_node_summary(baseline.nodes[sid]))
    for sid in sorted(curr_sids & base_sids):
        old = _node_summary(baseline.nodes[sid])
        new = _node_summary(current.nodes[sid])
        changes = _changed_node_fields(old, new)
        if changes:
            diff["nodes"]["changed"].append({
                "sid": sid,
                "before": old,
                "after":  new,
                "changes": [
                    {"field": f, "before": b, "after": a}
                    for (f, b, a) in changes
                ],
            })

    # --- Findings ---
    base_findings = {}
    for sid, n in baseline.nodes.items():
        for f in (getattr(n, "findings", []) or []):
            base_findings[_finding_key(sid, f)] = (sid, f)
    curr_findings = {}
    for sid, n in current.nodes.items():
        for f in (getattr(n, "findings", []) or []):
            curr_findings[_finding_key(sid, f)] = (sid, f)
    for k in sorted(set(curr_findings) - set(base_findings)):
        sid, f = curr_findings[k]
        diff["findings"]["added"].append(_finding_summary(sid, f))
    for k in sorted(set(base_findings) - set(curr_findings)):
        sid, f = base_findings[k]
        diff["findings"]["removed"].append(_finding_summary(sid, f))

    # --- Connections ---
    base_conns = {_conn_key(c): c for c in (baseline.connections or [])}
    curr_conns = {_conn_key(c): c for c in (current.connections or [])}
    for k in sorted(set(curr_conns) - set(base_conns)):
        diff["connections"]["added"].append(_conn_summary(curr_conns[k]))
    for k in sorted(set(base_conns) - set(curr_conns)):
        diff["connections"]["removed"].append(_conn_summary(base_conns[k]))
    for k in sorted(set(curr_conns) & set(base_conns)):
        old = _conn_summary(base_conns[k])
        new = _conn_summary(curr_conns[k])
        changes = _changed_conn_fields(old, new)
        if changes:
            diff["connections"]["changed"].append({
                "key": list(k),
                "before": old, "after": new,
                "changes": [
                    {"field": f, "before": b, "after": a}
                    for (f, b, a) in changes
                ],
            })

    # --- SCC nodes ---
    base_sccs = getattr(baseline, "scc_nodes", {}) or {}
    curr_sccs = getattr(current, "scc_nodes", {}) or {}
    for h in sorted(set(curr_sccs) - set(base_sccs)):
        diff["scc_nodes"]["added"].append(_scc_summary(curr_sccs[h]))
    for h in sorted(set(base_sccs) - set(curr_sccs)):
        diff["scc_nodes"]["removed"].append(_scc_summary(base_sccs[h]))
    for h in sorted(set(curr_sccs) & set(base_sccs)):
        old = _scc_summary(base_sccs[h])
        new = _scc_summary(curr_sccs[h])
        changes = _changed_scc_fields(old, new)
        if changes:
            diff["scc_nodes"]["changed"].append({
                "host": h,
                "before": old, "after": new,
                "changes": [
                    {"field": f, "before": b, "after": a}
                    for (f, b, a) in changes
                ],
            })

    # --- Trust chains (recomputed per snapshot) ---
    try:
        from sapmap_chain import analyze_chains
        base_chains = analyze_chains(baseline, max_depth=6,
                                       print_fn=lambda *a, **kw: None)
        curr_chains = analyze_chains(current, max_depth=6,
                                       print_fn=lambda *a, **kw: None)
    except Exception:
        base_chains = curr_chains = []
    base_chain_keys = {(c.start_sid, tuple(c.path_sids)): c for c in base_chains}
    curr_chain_keys = {(c.start_sid, tuple(c.path_sids)): c for c in curr_chains}

    def _chain_summary(c):
        return {
            "path":   list(c.path_sids),
            "hops":   c.total_hops,
            "risk":   c.risk_label,
            "ends_in_production": bool(c.end_is_production),
            "headline": c.headline,
        }

    for k in sorted(set(curr_chain_keys) - set(base_chain_keys)):
        diff["trust_chains"]["added"].append(
            _chain_summary(curr_chain_keys[k]))
    for k in sorted(set(base_chain_keys) - set(curr_chain_keys)):
        diff["trust_chains"]["removed"].append(
            _chain_summary(base_chain_keys[k]))

    # --- Created users (the SAPMAP-created accounts) ---
    def _user_key(u):
        return (
            getattr(u, "sid", "") or "",
            getattr(u, "username", "") or "",
            getattr(u, "client", "") or "",
        )

    def _user_summary(u):
        return {
            "sid":       getattr(u, "sid", ""),
            "username":  getattr(u, "username", ""),
            "client":    getattr(u, "client", ""),
            "method":    getattr(u, "method", ""),
            "created_at": getattr(u, "created_at", ""),
        }

    base_users = {_user_key(u): u for u in (getattr(baseline, "created_users", []) or [])}
    curr_users = {_user_key(u): u for u in (getattr(current, "created_users", []) or [])}
    for k in sorted(set(curr_users) - set(base_users)):
        diff["created_users"]["added"].append(_user_summary(curr_users[k]))
    for k in sorted(set(base_users) - set(curr_users)):
        diff["created_users"]["removed"].append(_user_summary(base_users[k]))

    # --- Password-spraying runs (issue #69, PR5) ---
    # state.spray_runs is a list of SprayRun.to_dict() entries.
    # Key by run_id for the delta; summarise only (never emit the
    # per-attempt rows — those live in loot/spray/<run_id>/
    # attempts.jsonl and would fan pw_sha256_prefix out across
    # engagements if dumped here).
    def _run_summary(r):
        cfg = r.get("config_snapshot", {}) or {}
        return {
            "run_id":        r.get("run_id", ""),
            "started_at":    r.get("started_at", ""),
            "finished_at":   r.get("finished_at", ""),
            "attempts_done": int(r.get("attempts_done", 0) or 0),
            "hits_count":    len(r.get("hits", []) or []),
            "locked_count":  len(r.get("locked_users", []) or []),
            "aborted":       r.get("aborted", "") or "",
            "purple_mode":   bool(cfg.get("purple_mode")),
            "dry_run":       bool(cfg.get("dry_run")),
            "scope":         str(cfg.get("scope_filter", {})),
            "purple_report_generated": bool(
                r.get("purple_report_generated")),
            "loot_path":     r.get("loot_path", "") or "",
        }

    base_runs = {r.get("run_id", ""): r
                  for r in (getattr(baseline, "spray_runs", []) or [])
                  if r.get("run_id")}
    curr_runs = {r.get("run_id", ""): r
                  for r in (getattr(current, "spray_runs", []) or [])
                  if r.get("run_id")}
    for k in sorted(set(curr_runs) - set(base_runs)):
        diff["spray_runs"]["added"].append(_run_summary(curr_runs[k]))
    for k in sorted(set(base_runs) - set(curr_runs)):
        diff["spray_runs"]["removed"].append(_run_summary(base_runs[k]))

    # Newly-locked users (defender-visible fallout).  Set-diff on
    # the keys of state.pwspray_locked_users.
    base_locked = set(
        (getattr(baseline, "pwspray_locked_users", {}) or {}).keys())
    curr_locked = set(
        (getattr(current, "pwspray_locked_users", {}) or {}).keys())
    for user in sorted(curr_locked - base_locked):
        entry = (getattr(current, "pwspray_locked_users", {})
                 or {}).get(user, {}) or {}
        rows = entry.get("locked_on") or []
        first = rows[0] if rows else []
        diff["spray_runs"]["locked_users_added"].append({
            "username":        user,
            "first_locked_sid": first[0] if len(first) >= 1 else "",
            "first_locked_at":  first[2] if len(first) >= 3 else "",
        })

    # --- Summary roll-up ---
    newly_pwned = [c["sid"] for c in diff["nodes"]["changed"]
                    if any(ch["field"] == "pwned" and ch["before"] is False
                           and ch["after"] is True for ch in c["changes"])]
    newly_critical = sum(1 for f in diff["findings"]["added"]
                          if f["severity"] == "CRITICAL")
    new_chains_to_prd = sum(1 for c in diff["trust_chains"]["added"]
                              if c["ends_in_production"])
    diff["summary"] = {
        "nodes_added":        len(diff["nodes"]["added"]),
        "nodes_removed":      len(diff["nodes"]["removed"]),
        "nodes_changed":      len(diff["nodes"]["changed"]),
        "findings_added":     len(diff["findings"]["added"]),
        "findings_removed":   len(diff["findings"]["removed"]),
        "newly_critical":     newly_critical,
        "newly_pwned_sids":   newly_pwned,
        "newly_pwned_count":  len(newly_pwned),
        "connections_added":  len(diff["connections"]["added"]),
        "connections_removed": len(diff["connections"]["removed"]),
        "trust_chains_added":  len(diff["trust_chains"]["added"]),
        "trust_chains_removed": len(diff["trust_chains"]["removed"]),
        "new_chains_to_prd":   new_chains_to_prd,
        "scc_added":           len(diff["scc_nodes"]["added"]),
        "scc_removed":         len(diff["scc_nodes"]["removed"]),
        "users_created":       len(diff["created_users"]["added"]),
        "users_removed":       len(diff["created_users"]["removed"]),
        # Password-spraying KPIs (PR5).
        "spray_runs_added":    len(diff["spray_runs"]["added"]),
        "spray_hits_added":    sum(
            r["hits_count"] for r in diff["spray_runs"]["added"]),
        "newly_locked_users":  len(
            diff["spray_runs"]["locked_users_added"]),
        "purple_runs_added":   sum(
            1 for r in diff["spray_runs"]["added"]
            if r.get("purple_mode")),
    }
    return diff


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------

def _md_esc(s) -> str:
    if s is None:
        return ""
    return str(s).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def build_diff_markdown(diff: dict) -> str:
    """Render the diff as a Markdown document."""
    s = diff["summary"]
    lines = [
        f"# SAPMAP Engagement Diff",
        "",
        f"_Generated {diff['generated_at']}._",
        "",
        f"**Baseline:** {_md_esc(diff['baseline_label'])} "
        f"(saved {_md_esc(diff['baseline_timestamp']) or 'unknown'})  ",
        f"**Current:**  {_md_esc(diff['current_label'])} "
        f"(saved {_md_esc(diff['current_timestamp']) or 'unknown'})",
        "",
        "---",
        "",
        "## Headline",
        "",
        "| Metric | Δ |",
        "| --- | --- |",
        f"| Nodes added         | {s['nodes_added']} |",
        f"| Nodes removed       | {s['nodes_removed']} |",
        f"| Nodes changed       | {s['nodes_changed']} |",
        f"| **Newly pwned**     | **{s['newly_pwned_count']}**"
        + (f" — {', '.join(s['newly_pwned_sids'])}"
           if s['newly_pwned_sids'] else "") + " |",
        f"| New CRITICAL findings | {s['newly_critical']} |",
        f"| Findings added      | {s['findings_added']} |",
        f"| Findings remediated | {s['findings_removed']} |",
        f"| RFC connections added   | {s['connections_added']} |",
        f"| RFC connections removed | {s['connections_removed']} |",
        f"| Trust chains added      | {s['trust_chains_added']} |",
        f"| Trust chains removed    | {s['trust_chains_removed']} |",
        f"| **New chains reaching PRD** | **{s['new_chains_to_prd']}** |",
        f"| SCCs added       | {s['scc_added']} |",
        f"| SCCs removed     | {s['scc_removed']} |",
        f"| SAPMAP users created (delta) | {s['users_created']} |",
        f"| SAPMAP users removed (delta) | {s['users_removed']} |",
        # Password-spraying KPIs (PR5).
        f"| Password-spray runs (delta) | {s.get('spray_runs_added', 0)} |",
        f"| Spray hits (delta) | {s.get('spray_hits_added', 0)} |",
        f"| **Newly-locked users (defender-visible)** | "
        f"**{s.get('newly_locked_users', 0)}** |",
        f"| Purple-mode runs (delta) | {s.get('purple_runs_added', 0)} |",
        "",
    ]

    # Section: nodes
    if diff["nodes"]["added"] or diff["nodes"]["removed"] or diff["nodes"]["changed"]:
        lines += ["---", "", "## SAP nodes", ""]
        if diff["nodes"]["added"]:
            lines.append(f"### ➕ Added ({len(diff['nodes']['added'])})")
            lines.append("")
            for n in diff["nodes"]["added"]:
                lines.append(
                    f"- **{_md_esc(n['sid'])}** "
                    f"({_md_esc(n['system_type'])}/{_md_esc(n['os_type'])}/"
                    f"{_md_esc(n['db_type'])}) on {_md_esc(n['hostname'])}"
                    + (" — ⚡ pwned" if n['pwned'] else "")
                    + (" — PRD" if n['is_production'] else "")
                )
            lines.append("")
        if diff["nodes"]["removed"]:
            lines.append(f"### ➖ Removed ({len(diff['nodes']['removed'])})")
            lines.append("")
            for n in diff["nodes"]["removed"]:
                lines.append(f"- **{_md_esc(n['sid'])}** ({_md_esc(n['hostname'])})")
            lines.append("")
        if diff["nodes"]["changed"]:
            lines.append(f"### Δ Changed ({len(diff['nodes']['changed'])})")
            lines.append("")
            for c in diff["nodes"]["changed"]:
                lines.append(f"#### {_md_esc(c['sid'])}")
                lines.append("")
                lines.append("| Field | Before | After |")
                lines.append("| --- | --- | --- |")
                for ch in c["changes"]:
                    lines.append(
                        f"| {_md_esc(ch['field'])} | "
                        f"{_md_esc(ch['before'])} | "
                        f"{_md_esc(ch['after'])} |"
                    )
                lines.append("")

    # Findings
    if diff["findings"]["added"] or diff["findings"]["removed"]:
        lines += ["---", "", "## Findings", ""]
        if diff["findings"]["added"]:
            lines.append(f"### ➕ New ({len(diff['findings']['added'])})")
            lines.append("")
            for f in diff["findings"]["added"]:
                lines.append(
                    f"- **{f['severity']}** · **{_md_esc(f['sid'])}** — "
                    f"{_md_esc(f['name'])}"
                )
            lines.append("")
        if diff["findings"]["removed"]:
            lines.append(f"### ➖ Remediated / gone ({len(diff['findings']['removed'])})")
            lines.append("")
            for f in diff["findings"]["removed"]:
                lines.append(
                    f"- **{f['severity']}** · **{_md_esc(f['sid'])}** — "
                    f"{_md_esc(f['name'])}"
                )
            lines.append("")

    # Trust chains
    if diff["trust_chains"]["added"] or diff["trust_chains"]["removed"]:
        lines += ["---", "", "## Trust chains", ""]
        if diff["trust_chains"]["added"]:
            lines.append(f"### ➕ New attack paths ({len(diff['trust_chains']['added'])})")
            lines.append("")
            for c in diff["trust_chains"]["added"]:
                prd = " — **ENDS IN PRD**" if c["ends_in_production"] else ""
                lines.append(
                    f"- {c['risk']} · {' → '.join(c['path'])}"
                    f" ({c['hops']} hops){prd}"
                )
            lines.append("")
        if diff["trust_chains"]["removed"]:
            lines.append(f"### ➖ Disappeared ({len(diff['trust_chains']['removed'])})")
            lines.append("")
            for c in diff["trust_chains"]["removed"]:
                lines.append(f"- {c['risk']} · {' → '.join(c['path'])}")
            lines.append("")

    # Connections
    if diff["connections"]["added"] or diff["connections"]["removed"]:
        lines += ["---", "", "## RFC connections", ""]
        if diff["connections"]["added"]:
            lines.append(f"### ➕ Added ({len(diff['connections']['added'])})")
            lines.append("")
            for c in diff["connections"]["added"]:
                badges = []
                if c["has_sap_all"]: badges.append("SAP_ALL")
                if c["logon_successful"]: badges.append("logon ok")
                bstr = (" [" + ", ".join(badges) + "]") if badges else ""
                lines.append(
                    f"- {_md_esc(c['source_sid'])} → {_md_esc(c['target_sid'])} "
                    f"via `{_md_esc(c['destination_name'])}` (user "
                    f"{_md_esc(c['rfc_user']) or '?'}){bstr}"
                )
            lines.append("")
        if diff["connections"]["removed"]:
            lines.append(f"### ➖ Removed ({len(diff['connections']['removed'])})")
            lines.append("")
            for c in diff["connections"]["removed"]:
                lines.append(
                    f"- {_md_esc(c['source_sid'])} → {_md_esc(c['target_sid'])} "
                    f"via `{_md_esc(c['destination_name'])}`"
                )
            lines.append("")

    # SCCs
    if diff["scc_nodes"]["added"] or diff["scc_nodes"]["removed"] or diff["scc_nodes"]["changed"]:
        lines += ["---", "", "## SAP Cloud Connectors", ""]
        for label, key in (("Added", "added"), ("Removed", "removed")):
            if diff["scc_nodes"][key]:
                lines.append(f"### {label} ({len(diff['scc_nodes'][key])})")
                lines.append("")
                for s in diff["scc_nodes"][key]:
                    lines.append(
                        f"- {_md_esc(s['host'])} "
                        f"v{_md_esc(s['version']) or '?'}"
                        + (" — ⚡ pwned" if s['pwned'] else "")
                    )
                lines.append("")
        if diff["scc_nodes"]["changed"]:
            lines.append(f"### Changed ({len(diff['scc_nodes']['changed'])})")
            lines.append("")
            for c in diff["scc_nodes"]["changed"]:
                lines.append(f"#### {_md_esc(c['host'])}")
                lines.append("")
                for ch in c["changes"]:
                    lines.append(
                        f"- `{ch['field']}`: {_md_esc(ch['before'])} → "
                        f"**{_md_esc(ch['after'])}**"
                    )
                lines.append("")

    # Created users
    if diff["created_users"]["added"] or diff["created_users"]["removed"]:
        lines += ["---", "", "## SAPMAP-created accounts (delta)", ""]
        if diff["created_users"]["added"]:
            lines.append(f"### ➕ Added ({len(diff['created_users']['added'])})")
            lines.append("")
            for u in diff["created_users"]["added"]:
                lines.append(
                    f"- {_md_esc(u['sid'])} / {_md_esc(u['username'])} / "
                    f"client {_md_esc(u['client'])} (method: "
                    f"{_md_esc(u['method'])})"
                )
            lines.append("")
        if diff["created_users"]["removed"]:
            lines.append(f"### ➖ Removed ({len(diff['created_users']['removed'])})")
            lines.append("")
            for u in diff["created_users"]["removed"]:
                lines.append(f"- {_md_esc(u['sid'])} / {_md_esc(u['username'])}")
            lines.append("")

    # Password-spraying runs (issue #69, PR5).
    sr = diff.get("spray_runs", {}) or {}
    if (sr.get("added") or sr.get("removed")
            or sr.get("locked_users_added")):
        lines += ["---", "", "## 🔓 Password spraying (delta)", ""]
        if sr.get("added"):
            lines.append(
                f"### ➕ New runs ({len(sr['added'])})")
            lines.append("")
            for r in sr["added"]:
                purple = " 🔮 purple" if r.get("purple_mode") else ""
                dry = " (dry-run)" if r.get("dry_run") else ""
                lines.append(
                    f"- `{_md_esc(r['run_id'])}` — "
                    f"{_md_esc(r['started_at'][:19])} → "
                    f"{_md_esc((r.get('finished_at', '') or '—')[:19])}"
                    f"{purple}{dry}"
                )
                lines.append(
                    f"  - **{r['attempts_done']}** attempt(s), "
                    f"**{r['hits_count']}** hit(s), "
                    f"**{r['locked_count']}** lockout(s)"
                    + (f" — aborted: `{_md_esc(r['aborted'])}`"
                       if r.get("aborted") else "")
                )
                if r.get("purple_report_generated") and r.get("loot_path"):
                    lines.append(
                        f"  - Blue-team deliverable: "
                        f"`{_md_esc(r['loot_path'])}/purple_report.{{md,html}}`"
                    )
            lines.append("")
        if sr.get("locked_users_added"):
            lines.append(
                f"### 🚨 Newly-locked users "
                f"({len(sr['locked_users_added'])})")
            lines.append("")
            for u in sr["locked_users_added"]:
                lines.append(
                    f"- **{_md_esc(u['username'])}** — first locked on "
                    f"`{_md_esc(u.get('first_locked_sid', ''))}` at "
                    f"{_md_esc(u.get('first_locked_at', ''))}"
                )
            lines.append("")
        if sr.get("removed"):
            # The rare case where reset_history ran between the two
            # snapshots OR state_a and state_b come from parallel
            # engagements.  Surface as an explicit operator-reset
            # note so the engagement report doesn't silently lose
            # the prior history.
            lines.append(
                f"### 🧹 Runs removed from history "
                f"({len(sr['removed'])})")
            lines.append("")
            lines.append(
                "_Likely cause: `reset_history` endpoint was called "
                "between the two snapshots, or the snapshots come "
                "from parallel engagements._")
            lines.append("")
            for r in sr["removed"]:
                lines.append(
                    f"- `{_md_esc(r['run_id'])}` — "
                    f"{_md_esc(r['started_at'][:19])} "
                    f"(**{r['attempts_done']}** attempt(s), "
                    f"**{r['hits_count']}** hit(s))"
                )
            lines.append("")

    lines += ["---", "", "_End of diff._", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML renderer — matches engagement-report visual style
# ---------------------------------------------------------------------------

def _hesc(s) -> str:
    if s is None:
        return ""
    return (str(s).replace("&", "&amp;")
                  .replace("<", "&lt;")
                  .replace(">", "&gt;")
                  .replace('"', "&quot;"))


def _delta_kpi(label: str, value: int, sub: str = "",
                positive_is_bad: bool = True) -> str:
    """KPI card for the diff hero strip — colour-coded by direction."""
    if value == 0:
        col = "#3fb950"          # green
    elif positive_is_bad:
        col = "#f85149" if value >= 5 else "#db6d28"
    else:
        col = "#0969da"
    return (
        f'<div class="kpi" style="border-left:4px solid {col}">'
        f'<div class="kpi-v">{value:+d}</div>'
        f'<div class="kpi-l">{_hesc(label)}</div>'
        + (f'<div class="kpi-s">{_hesc(sub)}</div>' if sub else '')
        + '</div>'
    )


def build_diff_html(diff: dict) -> str:
    """Render the diff as a self-contained HTML page (engagement-report
    visual style — embedded CSS, no external resources)."""
    s = diff["summary"]

    # Decide overall headline tone
    if s["new_chains_to_prd"] > 0 or s["newly_pwned_count"] > 0:
        band = ("MAJOR REGRESSION", "#f85149")
    elif s["newly_critical"] > 0 or s["findings_added"] > 0:
        band = ("New exposure", "#db6d28")
    elif s["findings_removed"] > 0 and s["findings_added"] == 0:
        band = ("Remediation progress", "#3fb950")
    else:
        band = ("No major change", "#8b949e")

    def _node_card_added(n):
        pwned_b = ('<span class="badge badge-pwned">⚡ PWNED</span>'
                    if n['pwned'] else '')
        prd_b = ('<span class="badge badge-prd">PRD</span>'
                  if n['is_production'] else '')
        return (
            f'<div class="entry">'
            f'<span class="sid-pill">{_hesc(n["sid"])}</span> '
            f'{_hesc(n["system_type"])} · {_hesc(n["hostname"])} '
            f'{pwned_b}{prd_b}'
            f'</div>'
        )

    def _node_card_removed(n):
        return (
            f'<div class="entry removed">'
            f'<span class="sid-pill">{_hesc(n["sid"])}</span> '
            f'{_hesc(n["hostname"])}'
            f'</div>'
        )

    def _node_card_changed(c):
        rows = "".join(
            f'<tr><td class="mono">{_hesc(ch["field"])}</td>'
            f'<td>{_hesc(ch["before"])}</td>'
            f'<td><b>{_hesc(ch["after"])}</b></td></tr>'
            for ch in c["changes"]
        )
        return (
            f'<div class="entry changed">'
            f'<div><span class="sid-pill">{_hesc(c["sid"])}</span></div>'
            f'<table class="grid mini">'
            f'<thead><tr><th>Field</th><th>Before</th><th>After</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
            f'</div>'
        )

    def _finding_card(f, kind):
        sev = f["severity"]
        sev_col = {
            "CRITICAL": "#f85149", "HIGH": "#db6d28",
            "MEDIUM":   "#d4a72c", "INFO": "#0969da",
            "LOW":      "#3fb950",
        }.get(sev, "#8b949e")
        op = "+" if kind == "added" else "−"
        return (
            f'<div class="entry {"added" if kind == "added" else "removed"}" '
            f'style="border-left:4px solid {sev_col}">'
            f'<span class="diff-op">{op}</span>'
            f'<span class="risk-pill" style="background:{sev_col}">{sev}</span> '
            f'<span class="sid-pill">{_hesc(f["sid"])}</span> '
            f'{_hesc(f["name"])}'
            f'</div>'
        )

    def _chain_card(c, kind):
        risk_col = {"CRITICAL":"#f85149","HIGH":"#db6d28",
                    "MEDIUM":"#d4a72c","LOW":"#3fb950"}.get(c["risk"],"#8b949e")
        op = "+" if kind == "added" else "−"
        prd = ('<span class="badge badge-prd">ENDS IN PRD</span>'
                if c["ends_in_production"] else '')
        return (
            f'<div class="entry {"added" if kind == "added" else "removed"}">'
            f'<span class="diff-op">{op}</span>'
            f'<span class="risk-pill" style="background:{risk_col}">'
            f'{c["risk"]}</span> '
            f'<span class="mono">{_hesc(" → ".join(c["path"]))}</span> '
            f'<span class="muted">({c["hops"]} hops)</span> '
            f'{prd}'
            f'</div>'
        )

    nodes_added_html = "".join(_node_card_added(n) for n in diff["nodes"]["added"]) \
        or '<div class="muted">none</div>'
    nodes_removed_html = "".join(_node_card_removed(n) for n in diff["nodes"]["removed"]) \
        or '<div class="muted">none</div>'
    nodes_changed_html = "".join(_node_card_changed(c) for c in diff["nodes"]["changed"]) \
        or '<div class="muted">none</div>'

    findings_added_html = "".join(_finding_card(f, "added")
                                    for f in diff["findings"]["added"]) \
        or '<div class="muted">none</div>'
    findings_removed_html = "".join(_finding_card(f, "removed")
                                      for f in diff["findings"]["removed"]) \
        or '<div class="muted">none</div>'

    chains_added_html = "".join(_chain_card(c, "added")
                                  for c in diff["trust_chains"]["added"]) \
        or '<div class="muted">none</div>'
    chains_removed_html = "".join(_chain_card(c, "removed")
                                    for c in diff["trust_chains"]["removed"]) \
        or '<div class="muted">none</div>'

    # Password-spraying runs (issue #69, PR5).
    sr = diff.get("spray_runs", {}) or {}
    spray_added_html = ""
    for r in sr.get("added", []):
        purple = ' <span class="badge">purple</span>' if r.get("purple_mode") else ''
        dry = ' <span class="muted">(dry-run)</span>' if r.get("dry_run") else ''
        spray_added_html += (
            '<div class="entry">'
            f'<code>{_hesc(r.get("run_id", ""))}</code> '
            f'{_hesc(r.get("started_at", "")[:19])} &rarr; '
            f'{_hesc((r.get("finished_at", "") or "—")[:19])}'
            f'{purple}{dry}<br>'
            f'<strong>{r.get("attempts_done", 0)}</strong> attempt(s), '
            f'<strong style="color:#f85149">{r.get("hits_count", 0)}</strong> hit(s), '
            f'<strong style="color:#f0883e">{r.get("locked_count", 0)}</strong> lockout(s)'
            + (f' &mdash; aborted: <code>{_hesc(r.get("aborted", ""))}</code>'
               if r.get("aborted") else '')
            + '</div>')
    spray_added_html = spray_added_html or '<div class="muted">none</div>'
    locked_added_html = ""
    for u in sr.get("locked_users_added", []):
        locked_added_html += (
            '<div class="entry">'
            f'<strong>{_hesc(u.get("username", ""))}</strong> &mdash; '
            f'first locked on <code>{_hesc(u.get("first_locked_sid", ""))}</code> '
            f'at {_hesc(u.get("first_locked_at", ""))}'
            '</div>')
    locked_added_html = locked_added_html or \
        '<div class="muted">none</div>'

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>SAPMAP — engagement diff</title>
<style>
  *{{box-sizing:border-box}}
  body{{margin:0;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
       background:#f5f7fa;color:#24292f;line-height:1.55}}
  .wrap{{max-width:1100px;margin:0 auto;padding:32px 28px}}
  .hero{{background:linear-gradient(135deg,#1f2937 0%,#0f1729 100%);
        color:#fff;border-radius:16px;padding:32px 36px;margin-bottom:28px;
        box-shadow:0 12px 32px rgba(15,23,41,.25);position:relative;overflow:hidden}}
  .hero::before{{content:"";position:absolute;right:-80px;top:-80px;width:280px;
        height:280px;background:radial-gradient(circle,{band[1]}55 0%,transparent 70%)}}
  .hero h1{{margin:0 0 6px;font-size:26px;font-weight:700}}
  .hero .meta{{color:#9ca3af;font-size:12px;margin-bottom:16px}}
  .hero .pair{{font-size:13px;color:#cbd5e1;margin-bottom:16px}}
  .hero .pair b{{color:#fff}}
  .risk-band{{display:inline-flex;align-items:center;gap:10px;padding:7px 16px;
        border-radius:999px;background:{band[1]};color:#fff;font-weight:700;
        letter-spacing:.5px;font-size:12px;text-transform:uppercase}}
  .risk-band::before{{content:"";width:8px;height:8px;border-radius:50%;
        background:#fff;box-shadow:0 0 0 4px #ffffff33}}
  .kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));
        gap:12px;margin:20px 0 30px}}
  .kpi{{background:#fff;border-radius:10px;padding:14px 16px;
        box-shadow:0 1px 3px rgba(0,0,0,.08);border-left:4px solid #d0d7de}}
  .kpi-v{{font-size:24px;font-weight:700;color:#1f2937;line-height:1.1;
        font-variant-numeric:tabular-nums}}
  .kpi-l{{font-size:11px;color:#6b7280;text-transform:uppercase;
        letter-spacing:.5px;margin-top:4px;font-weight:600}}
  .kpi-s{{font-size:11px;color:#9ca3af;margin-top:4px}}
  section{{background:#fff;border-radius:12px;padding:22px 26px;margin-bottom:22px;
        box-shadow:0 1px 3px rgba(0,0,0,.06)}}
  section h2{{margin:0 0 14px;font-size:17px;color:#1f2937;
        border-bottom:2px solid #f0f3f7;padding-bottom:10px}}
  section h3{{margin:14px 0 8px;font-size:13px;color:#57606a;
        text-transform:uppercase;letter-spacing:.5px}}
  .entry{{padding:8px 12px;margin:4px 0;background:#fafbfc;border-radius:6px;
        font-size:13px;display:flex;gap:8px;align-items:center;flex-wrap:wrap}}
  .entry.added{{background:#f0fdf4;border-left:3px solid #1a7f37}}
  .entry.removed{{background:#fef0f0;border-left:3px solid #b51c1c;
        text-decoration:line-through;text-decoration-color:#b51c1c44}}
  .entry.changed{{background:#fff8e1;border-left:3px solid #b08800}}
  .diff-op{{display:inline-block;width:18px;height:18px;line-height:18px;
        text-align:center;border-radius:4px;font-weight:700;font-size:13px}}
  .entry.added .diff-op{{background:#1a7f37;color:#fff}}
  .entry.removed .diff-op{{background:#b51c1c;color:#fff}}
  .sid-pill{{display:inline-block;padding:1px 7px;border-radius:4px;
        background:#0f1729;color:#fff;font-family:'SF Mono',monospace;
        font-size:11px;font-weight:700}}
  .risk-pill{{display:inline-block;padding:2px 8px;border-radius:4px;
        color:#fff;font-weight:600;font-size:10px;letter-spacing:.5px}}
  .badge{{display:inline-block;padding:1px 7px;border-radius:4px;
        font-size:9.5px;font-weight:600;letter-spacing:.4px;text-transform:uppercase}}
  .badge-pwned{{background:#fff0e6;color:#bf4f00;border:1px solid #ffd0b0}}
  .badge-prd{{background:#fbe5e5;color:#b51c1c;border:1px solid #f5b5b5}}
  .mono{{font-family:'SF Mono',Menlo,monospace;font-size:12px}}
  .muted{{color:#8b949e;font-style:italic;padding:4px 8px;font-size:12px}}
  table.grid.mini{{width:100%;border-collapse:collapse;font-size:12px;margin-top:6px}}
  table.grid.mini th{{text-align:left;padding:5px 8px;background:#f6f8fa;
        font-weight:600;color:#57606a;font-size:10px;text-transform:uppercase}}
  table.grid.mini td{{padding:5px 8px;border-bottom:1px solid #f0f3f7}}
  footer{{text-align:center;color:#8b949e;font-size:11px;margin-top:24px}}
  @media print{{body{{background:#fff}} section{{box-shadow:none;border:1px solid #e1e4e8}}}}
</style>
</head><body><div class="wrap">

  <div class="hero">
    <h1>SAPMAP — engagement diff</h1>
    <div class="meta">Generated {_hesc(diff['generated_at'])}</div>
    <div class="pair">
      <b>Baseline:</b> {_hesc(diff['baseline_label'])}
      <span class="muted">({_hesc(diff['baseline_timestamp']) or 'unknown'})</span><br>
      <b>Current: </b> {_hesc(diff['current_label'])}
      <span class="muted">({_hesc(diff['current_timestamp']) or 'unknown'})</span>
    </div>
    <span class="risk-band">{_hesc(band[0])}</span>
  </div>

  <div class="kpis">
    {_delta_kpi("Newly pwned",            s['newly_pwned_count'],
                 ", ".join(s['newly_pwned_sids']) or "")}
    {_delta_kpi("New CRITICAL findings",  s['newly_critical'])}
    {_delta_kpi("New chains -> PRD",      s['new_chains_to_prd'])}
    {_delta_kpi("Findings added",         s['findings_added'])}
    {_delta_kpi("Findings remediated",    -s['findings_removed'],
                 positive_is_bad=False)}
    {_delta_kpi("Nodes added",            s['nodes_added'])}
    {_delta_kpi("Nodes removed",          -s['nodes_removed'])}
    {_delta_kpi("Trust chains added",     s['trust_chains_added'])}
    {_delta_kpi("Trust chains removed",   -s['trust_chains_removed'],
                 positive_is_bad=False)}
    {_delta_kpi("Password-spray runs",    s.get('spray_runs_added', 0))}
    {_delta_kpi("Spray hits",             s.get('spray_hits_added', 0))}
    {_delta_kpi("Newly-locked users",     s.get('newly_locked_users', 0))}
    {_delta_kpi("Purple-mode runs",       s.get('purple_runs_added', 0))}
  </div>

  <section>
    <h2>🛑 New findings ({len(diff['findings']['added'])})</h2>
    {findings_added_html}
  </section>

  <section>
    <h2>✅ Findings remediated / disappeared ({len(diff['findings']['removed'])})</h2>
    {findings_removed_html}
  </section>

  <section>
    <h2>🔗 Trust chains</h2>
    <h3>New ({len(diff['trust_chains']['added'])})</h3>
    {chains_added_html}
    <h3>Disappeared ({len(diff['trust_chains']['removed'])})</h3>
    {chains_removed_html}
  </section>

  <section>
    <h2>🔓 Password spraying (issue #69)</h2>
    <h3>New runs ({len(sr.get("added", []))})</h3>
    {spray_added_html}
    <h3>Newly-locked users &mdash; defender signal ({len(sr.get("locked_users_added", []))})</h3>
    {locked_added_html}
  </section>

  <section>
    <h2>🗺️ SAP nodes</h2>
    <h3>Added ({len(diff['nodes']['added'])})</h3>
    {nodes_added_html}
    <h3>Removed ({len(diff['nodes']['removed'])})</h3>
    {nodes_removed_html}
    <h3>Changed ({len(diff['nodes']['changed'])})</h3>
    {nodes_changed_html}
  </section>

  <footer>SAPMAP — diff is a structural delta between two saved
    engagement snapshots.  No live data was queried at diff time.</footer>
</div></body></html>
"""
