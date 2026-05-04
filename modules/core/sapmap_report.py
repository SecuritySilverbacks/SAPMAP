#!/usr/bin/env python3
"""Engagement report builder.

Walks an SAPMAPState once and produces a self-contained Markdown report
suitable for handing to a stakeholder at the end of an engagement —
collapsing what an operator currently has to scroll through node-by-node
into a single document.

The output is intentionally portable Markdown (no GitHub-flavoured
extensions beyond tables) so it renders cleanly in any viewer or pastes
straight into a Word / Confluence page.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sapmap_models import SAPMAPState, SAPNode, RFCConnection, Severity


# ---------------------------------------------------------------------------
# Section helpers — each returns a list of Markdown lines, no trailing \n
# ---------------------------------------------------------------------------

def _stat_table(rows) -> list:
    """Build a 2-column 'metric : value' Markdown table."""
    out = ["| Metric | Value |", "| --- | --- |"]
    for label, val in rows:
        out.append(f"| {label} | {val} |")
    return out


def _esc(s) -> str:
    """Escape a value for Markdown table-cell use (collapse pipes + newlines)."""
    if s is None:
        return ""
    return str(s).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _executive_summary(state: SAPMAPState) -> list:
    """Top-of-report headline numbers — what to read in 30 seconds."""
    nodes = list(state.nodes.values())
    abap = sum(1 for n in nodes if "ABAP" in (n.system_type or "").upper())
    java = sum(1 for n in nodes if "JAVA" in (n.system_type or "").upper())
    routers = sum(1 for n in nodes
                  if (n.system_type or "").upper() == "SAPROUTER")
    pwned = [n for n in nodes if n.pwned]
    pwned_prd = [n for n in pwned if n.is_production]
    created = sum(len(n.created_users) for n in nodes)
    sap_all_creds = sum(
        1 for n in nodes for c in (n.credentials or []) if c.verified
        and any(p == "SAP_ALL" for conn in state.connections
                for p in (conn.profiles or [])
                if conn.target_sid == n.sid))
    secstore_total = sum(len(n.secstore_entries or []) for n in nodes)
    java_secstore_total = sum(len(n.java_secstore_entries or []) for n in nodes)
    scc_count = len(getattr(state, "scc_nodes", {}) or {})
    scc_pwned = sum(1 for s in (getattr(state, "scc_nodes", {}) or {}).values()
                    if getattr(s, "pwned", False)
                    or getattr(s, "default_creds_live", False))

    findings_total = sum(len(n.findings or []) for n in nodes)
    crit = sum(1 for n in nodes for f in (n.findings or [])
               if str(getattr(f, "severity", "")).endswith("CRITICAL")
               or getattr(f, "severity", None) == Severity.CRITICAL)
    high = sum(1 for n in nodes for f in (n.findings or [])
               if str(getattr(f, "severity", "")).endswith("HIGH")
               or getattr(f, "severity", None) == Severity.HIGH)

    pct_pwned = (100 * len(pwned) // len(nodes)) if nodes else 0

    out = ["## Executive summary", ""]
    out.extend(_stat_table([
        ("Total SAP nodes discovered",
         f"{len(nodes)} ({abap} ABAP, {java} Java, {routers} SAProuter)"),
        ("SAP Cloud Connectors",
         f"{scc_count} ({scc_pwned} with cracked admin)" if scc_count else "0"),
        ("Systems pwned",
         f"{len(pwned)} / {len(nodes)} ({pct_pwned}%)"),
        ("**Production systems pwned**",
         f"**{len(pwned_prd)}**" + (
             f" — {', '.join(n.sid for n in pwned_prd)}"
             if pwned_prd else "")),
        ("SAPMAP-created accounts", str(created)),
        ("Verified SAP_ALL credentials", str(sap_all_creds)),
        ("ABAP SecStore entries decrypted", str(secstore_total)),
        ("Java SecStore entries decrypted", str(java_secstore_total)),
        ("Findings",
         f"{findings_total} total — **{crit} CRITICAL**, {high} HIGH"),
    ]))
    out.append("")
    return out


def _findings_section(state: SAPMAPState) -> list:
    """List every CRITICAL + HIGH finding grouped by node."""
    out = ["## Findings", ""]
    for sev_label, sev_enum, sev_emoji in (
        ("Critical findings", Severity.CRITICAL, "🛑"),
        ("High findings",     Severity.HIGH,     "⚠️"),
    ):
        rows = []
        for sid, n in sorted(state.nodes.items()):
            for f in n.findings or []:
                f_sev = getattr(f, "severity", None)
                if f_sev == sev_enum or str(f_sev).endswith(sev_label.split()[0].upper()):
                    rows.append((sid, f))
        if not rows:
            continue
        out.append(f"### {sev_emoji} {sev_label} ({len(rows)})")
        out.append("")
        for sid, f in rows:
            out.append(f"#### {sid} — {_esc(f.name)}")
            if f.description:
                out.append("")
                out.append(_esc(f.description))
            if f.detail:
                out.append("")
                out.append(f"_Detail:_ {_esc(f.detail)}")
            if f.remediation:
                out.append("")
                out.append(f"**Remediation:** {_esc(f.remediation)}")
            out.append("")
    return out


def _trust_chains_section(state: SAPMAPState) -> list:
    """Run the chain analyser and emit ranked attack paths."""
    out = ["## Lateral movement / trust chains", ""]
    try:
        from sapmap_chain import analyze_chains
        # Suppress chain analyser's chatty print — we just want the data
        chains = analyze_chains(state, max_depth=6,
                                 print_fn=lambda *a, **kw: None)
    except Exception as e:
        out.append(f"_Chain analysis failed: {e}_")
        out.append("")
        return out

    if not chains:
        out.append("_No multi-hop attack chains found._")
        out.append("")
        return out

    prd_chains = [c for c in chains if c.end_is_production]
    out.append(f"Discovered **{len(chains)}** unique attack paths "
               f"({len(prd_chains)} reaching production).")
    out.append("")
    out.append("| Risk | Path | Hops | Ends in PRD | Entry |")
    out.append("| --- | --- | --- | --- | --- |")
    for c in chains[:30]:
        path = " → ".join(c.path_sids) or c.start_sid
        prd = "✓" if c.end_is_production else ""
        entry = _esc(c.entry_method)
        out.append(f"| {c.risk_label} | {path} | "
                   f"{c.total_hops} | {prd} | {entry} |")
    if len(chains) > 30:
        out.append("")
        out.append(f"_… and {len(chains) - 30} more (see JSON export for full list)._")
    out.append("")

    # Headline-style narrative for the top 10
    out.append("### Top attack paths (narrative)")
    out.append("")
    for i, c in enumerate(chains[:10], 1):
        out.append(f"{i}. **{c.risk_label}** — {_esc(c.headline)}")
    out.append("")
    return out


def _per_system_table(state: SAPMAPState) -> list:
    """One-row-per-node landscape inventory."""
    out = ["## Landscape inventory", ""]
    out.append("| SID | Type | OS | DB | Host | Pwned | PRD | "
               "Critical | RFC creds |")
    out.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for sid, n in sorted(state.nodes.items()):
        crit_count = sum(1 for f in (n.findings or [])
                          if getattr(f, "severity", None) == Severity.CRITICAL)
        rfc_creds = sum(1 for c in (n.credentials or []) if c.verified)
        pwned = "⚡" if n.pwned else ""
        prd = "✓" if n.is_production else ""
        out.append(
            f"| {sid} | {_esc(n.system_type)} | {_esc(n.os_type)} | "
            f"{_esc(n.db_type)} | {_esc(n.hostname or n.ip)} | "
            f"{pwned} | {prd} | {crit_count} | {rfc_creds} |"
        )
    out.append("")
    return out


def _credentials_section(state: SAPMAPState) -> list:
    """Recovered credentials per node — passwords masked."""
    out = ["## Recovered credentials", ""]
    out.append("Passwords masked in this report — full plaintext lives in "
               "`loot/secstore/`, `loot/hashes/`, and `loot/scc/<host>/"
               "hashes_cracked.txt`.")
    out.append("")
    out.append("| SID | Source | Username | Client | Verified |")
    out.append("| --- | --- | --- | --- | --- |")
    rows = 0
    for sid, n in sorted(state.nodes.items()):
        for c in n.created_users or []:
            ver = "Created"
            out.append(f"| {sid} | SAPMAP-created | {_esc(c.username)} | "
                       f"{_esc(c.client)} | {ver} |")
            rows += 1
        for c in n.credentials or []:
            ver = "✓" if c.verified else "?"
            out.append(f"| {sid} | Discovered | {_esc(c.username)} | "
                       f"{_esc(c.client)} | {ver} |")
            rows += 1
    if rows == 0:
        out = ["## Recovered credentials", "",
               "_No credentials recovered._", ""]
    else:
        out.append("")
    return out


def _scc_section(state: SAPMAPState) -> list:
    """Cloud Connector landscape, if any SCCs are mapped."""
    sccs = (getattr(state, "scc_nodes", {}) or {})
    if not sccs:
        return []
    out = ["## SAP Cloud Connectors", ""]
    out.append("| Host | Version | CVEs (suspected) | Default creds | "
               "Mappings |")
    out.append("| --- | --- | --- | --- | --- |")
    for host, sn in sorted(sccs.items()):
        cves = ", ".join(getattr(sn, "cves_suspected", []) or []) or "—"
        default = "**LIVE**" if getattr(sn, "default_creds_live", False) else "—"
        nmap = len(getattr(sn, "mappings", []) or [])
        out.append(f"| {host} | {_esc(getattr(sn, 'version', '') or '?')} | "
                   f"{_esc(cves)} | {default} | {nmap} |")
    out.append("")
    return out


def _recommendations_section(state: SAPMAPState) -> list:
    """De-duplicated remediation steps pulled from findings."""
    out = ["## Recommendations", ""]
    seen = set()
    bullets = []
    for n in state.nodes.values():
        for f in n.findings or []:
            r = (f.remediation or "").strip()
            if not r or r in seen:
                continue
            seen.add(r)
            bullets.append(f"- **{n.sid}** — {_esc(r)}")
    if not bullets:
        out.append("_No specific remediation steps emitted by findings._")
    else:
        out.extend(bullets)
    out.append("")
    return out


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def build_markdown_report(state: SAPMAPState,
                            engagement_name: Optional[str] = None) -> str:
    """Build a self-contained Markdown engagement report from the
    given SAPMAPState.

    Returns a single string of Markdown.  The caller is responsible
    for writing it to disk / streaming it back to the GUI.
    """
    title = engagement_name or "SAP Landscape Attack-Path Report"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sections = []
    sections.append(f"# {title}")
    sections.append("")
    sections.append(f"_Generated by SAPMAP at {now}._")
    sections.append("")
    sections.append("---")
    sections.append("")
    sections.extend(_executive_summary(state))
    sections.append("---")
    sections.append("")
    sections.extend(_findings_section(state))
    sections.append("---")
    sections.append("")
    sections.extend(_trust_chains_section(state))
    sections.append("---")
    sections.append("")
    sections.extend(_per_system_table(state))
    sections.append("---")
    sections.append("")
    sections.extend(_credentials_section(state))
    scc_section = _scc_section(state)
    if scc_section:
        sections.append("---")
        sections.append("")
        sections.extend(scc_section)
    sections.append("---")
    sections.append("")
    sections.extend(_recommendations_section(state))
    sections.append("---")
    sections.append("")
    sections.append("_End of report._")
    return "\n".join(sections) + "\n"
