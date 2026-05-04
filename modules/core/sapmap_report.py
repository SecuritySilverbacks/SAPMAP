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


# ---------------------------------------------------------------------------
# HTML report — self-contained, management-friendly, no external deps
# ---------------------------------------------------------------------------

def _hesc(s) -> str:
    """HTML-escape (no markdown, no pipes)."""
    if s is None:
        return ""
    return (str(s).replace("&", "&amp;")
                  .replace("<", "&lt;")
                  .replace(">", "&gt;")
                  .replace('"', "&quot;"))


def _kpi_card(label: str, value: str, sub: str = "", color: str = "") -> str:
    style = f";border-left:4px solid {color}" if color else ""
    return (
        f'<div class="kpi"{f" style=\"border-left:4px solid {color}\"" if color else ""}>'
        f'<div class="kpi-v">{_hesc(value)}</div>'
        f'<div class="kpi-l">{_hesc(label)}</div>'
        f'{f"<div class=\"kpi-s\">{_hesc(sub)}</div>" if sub else ""}'
        f'</div>'
    )


def build_html_report(state: SAPMAPState,
                        engagement_name: Optional[str] = None) -> str:
    """Build a single self-contained HTML page with embedded CSS.

    No JavaScript, no external resources — opens cleanly in any
    browser, prints to PDF without surprises, pastes straight into
    Confluence/Word with formatting preserved.
    """
    title = engagement_name or "SAP Landscape Attack-Path Report"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    nodes = list(state.nodes.values())
    abap = sum(1 for n in nodes if "ABAP" in (n.system_type or "").upper())
    java = sum(1 for n in nodes if "JAVA" in (n.system_type or "").upper())
    routers = sum(1 for n in nodes
                  if (n.system_type or "").upper() == "SAPROUTER")
    pwned = [n for n in nodes if n.pwned]
    pwned_prd = [n for n in pwned if n.is_production]
    pct_pwned = (100 * len(pwned) // len(nodes)) if nodes else 0
    created = sum(len(n.created_users) for n in nodes)
    secstore_total = sum(len(n.secstore_entries or []) for n in nodes)
    java_secstore_total = sum(len(n.java_secstore_entries or []) for n in nodes)
    sccs = (getattr(state, "scc_nodes", {}) or {})
    scc_pwned = sum(1 for s in sccs.values()
                    if getattr(s, "pwned", False)
                    or getattr(s, "default_creds_live", False))

    crit_findings = []
    high_findings = []
    for sid, n in sorted(state.nodes.items()):
        for f in n.findings or []:
            sev = getattr(f, "severity", None)
            if sev == Severity.CRITICAL:
                crit_findings.append((sid, f))
            elif sev == Severity.HIGH:
                high_findings.append((sid, f))

    # Risk band — dominates the hero strip
    if pwned_prd:
        risk_band = ("CRITICAL", "#f85149")
    elif crit_findings or pwned:
        risk_band = ("HIGH", "#db6d28")
    elif high_findings:
        risk_band = ("MEDIUM", "#d4a72c")
    elif nodes:
        risk_band = ("LOW", "#3fb950")
    else:
        risk_band = ("UNKNOWN", "#8b949e")

    # Trust chains
    chain_rows_html = ""
    chain_count = 0
    prd_chain_count = 0
    try:
        from sapmap_chain import analyze_chains
        chains = analyze_chains(state, max_depth=6,
                                 print_fn=lambda *a, **kw: None)
        chain_count = len(chains)
        prd_chain_count = sum(1 for c in chains if c.end_is_production)
        for c in chains[:30]:
            risk_color = {
                "CRITICAL": "#f85149",
                "HIGH":     "#db6d28",
                "MEDIUM":   "#d4a72c",
                "LOW":      "#3fb950",
            }.get(c.risk_label, "#8b949e")
            path = " → ".join(c.path_sids) or c.start_sid
            prd_badge = ('<span class="badge badge-prd">PRD</span>'
                          if c.end_is_production else "")
            chain_rows_html += (
                f'<tr>'
                f'<td><span class="risk-pill" style="background:{risk_color}">'
                f'{_hesc(c.risk_label)}</span></td>'
                f'<td class="mono">{_hesc(path)}</td>'
                f'<td class="num">{c.total_hops}</td>'
                f'<td>{prd_badge}</td>'
                f'<td>{_hesc(c.entry_method)}</td>'
                f'</tr>'
            )
    except Exception:
        pass
    if not chain_rows_html:
        chain_rows_html = (
            '<tr><td colspan="5" class="muted">'
            'No multi-hop attack chains found.</td></tr>'
        )

    # Findings cards
    def _finding_card(sid, f, sev_color):
        return (
            f'<div class="finding" style="border-left:4px solid {sev_color}">'
            f'<div class="finding-head">'
            f'<span class="sid-pill">{_hesc(sid)}</span>'
            f'<span class="finding-name">{_hesc(f.name)}</span>'
            f'</div>'
            + (f'<div class="finding-desc">{_hesc(f.description)}</div>'
               if f.description else '')
            + (f'<div class="finding-detail"><b>Detail:</b> '
               f'{_hesc(f.detail)}</div>' if f.detail else '')
            + (f'<div class="finding-rem"><b>Remediation:</b> '
               f'{_hesc(f.remediation)}</div>' if f.remediation else '')
            + '</div>'
        )

    crit_html = "".join(_finding_card(s, f, "#f85149")
                         for s, f in crit_findings) or \
                 '<div class="muted">No critical findings.</div>'
    high_html = "".join(_finding_card(s, f, "#db6d28")
                         for s, f in high_findings) or \
                 '<div class="muted">No high findings.</div>'

    # Inventory rows
    inv_rows = ""
    for sid, n in sorted(state.nodes.items()):
        crit_count = sum(1 for f in (n.findings or [])
                          if getattr(f, "severity", None) == Severity.CRITICAL)
        rfc_creds = sum(1 for c in (n.credentials or []) if c.verified)
        pwned_badge = ('<span class="badge badge-pwned">⚡ PWNED</span>'
                        if n.pwned else "")
        prd_badge = ('<span class="badge badge-prd">PRD</span>'
                      if n.is_production else "")
        crit_pill = (f'<span class="num-pill num-pill-bad">{crit_count}</span>'
                      if crit_count else
                      '<span class="num-pill num-pill-ok">0</span>')
        inv_rows += (
            f'<tr>'
            f'<td class="mono"><b>{_hesc(sid)}</b></td>'
            f'<td>{_hesc(n.system_type or "—")}</td>'
            f'<td>{_hesc(n.os_type or "—")}</td>'
            f'<td>{_hesc(n.db_type or "—")}</td>'
            f'<td class="mono">{_hesc(n.hostname or n.ip or "—")}</td>'
            f'<td>{pwned_badge}</td>'
            f'<td>{prd_badge}</td>'
            f'<td>{crit_pill}</td>'
            f'<td class="num">{rfc_creds}</td>'
            f'</tr>'
        )

    # SCC rows (only if any)
    scc_html = ""
    if sccs:
        scc_rows = ""
        for host, sn in sorted(sccs.items()):
            cves = ", ".join(getattr(sn, "cves_suspected", []) or []) or "—"
            default = ('<span class="badge badge-bad">LIVE</span>'
                        if getattr(sn, "default_creds_live", False) else "—")
            nmap = len(getattr(sn, "mappings", []) or [])
            scc_rows += (
                f'<tr>'
                f'<td class="mono">{_hesc(host)}</td>'
                f'<td>{_hesc(getattr(sn, "version", "") or "?")}</td>'
                f'<td>{_hesc(cves)}</td>'
                f'<td>{default}</td>'
                f'<td class="num">{nmap}</td>'
                f'</tr>'
            )
        scc_html = (
            '<section><h2>🔌 SAP Cloud Connectors</h2>'
            '<table class="grid"><thead><tr>'
            '<th>Host</th><th>Version</th><th>CVEs</th>'
            '<th>Default creds</th><th>Mappings</th>'
            '</tr></thead><tbody>' + scc_rows + '</tbody></table></section>'
        )

    # Recommendations
    seen = set()
    rec_items = []
    for n in state.nodes.values():
        for f in n.findings or []:
            r = (f.remediation or "").strip()
            if r and r not in seen:
                seen.add(r)
                rec_items.append(f'<li><b>{_hesc(n.sid)}</b> — {_hesc(r)}</li>')
    rec_html = ("<ol>" + "".join(rec_items) + "</ol>") if rec_items else \
                '<div class="muted">No specific remediation steps emitted.</div>'

    # Recovered creds (passwords masked)
    cred_rows = ""
    for sid, n in sorted(state.nodes.items()):
        for c in n.created_users or []:
            cred_rows += (
                f'<tr><td class="mono"><b>{_hesc(sid)}</b></td>'
                f'<td><span class="badge badge-bad">SAPMAP-created</span></td>'
                f'<td class="mono">{_hesc(c.username)}</td>'
                f'<td>{_hesc(c.client)}</td>'
                f'<td>Created</td></tr>'
            )
        for c in n.credentials or []:
            ver_badge = ('<span class="badge badge-ok">verified</span>'
                          if c.verified else
                          '<span class="badge badge-mid">unverified</span>')
            cred_rows += (
                f'<tr><td class="mono"><b>{_hesc(sid)}</b></td>'
                f'<td>Discovered</td>'
                f'<td class="mono">{_hesc(c.username)}</td>'
                f'<td>{_hesc(c.client)}</td>'
                f'<td>{ver_badge}</td></tr>'
            )
    cred_table = (
        '<table class="grid"><thead><tr><th>SID</th><th>Source</th>'
        '<th>Username</th><th>Client</th><th>Status</th></tr></thead>'
        f'<tbody>{cred_rows}</tbody></table>'
    ) if cred_rows else '<div class="muted">No credentials recovered.</div>'

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>{_hesc(title)}</title>
<style>
  *{{box-sizing:border-box}}
  body{{margin:0;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
       background:#f5f7fa;color:#24292f;line-height:1.55}}
  .wrap{{max-width:1180px;margin:0 auto;padding:32px 28px 64px}}
  /* Hero */
  .hero{{background:linear-gradient(135deg,#1f2937 0%,#0f1729 100%);
        color:#fff;border-radius:16px;padding:36px 40px;margin-bottom:32px;
        box-shadow:0 12px 32px rgba(15,23,41,.25);position:relative;overflow:hidden}}
  .hero::before{{content:"";position:absolute;right:-80px;top:-80px;width:280px;
        height:280px;background:radial-gradient(circle,{risk_band[1]}55 0%,transparent 70%)}}
  .hero h1{{margin:0 0 4px;font-size:30px;font-weight:700;letter-spacing:-0.5px}}
  .hero .meta{{color:#9ca3af;font-size:13px;margin-bottom:20px}}
  .risk-band{{display:inline-flex;align-items:center;gap:10px;padding:8px 18px;
        border-radius:999px;background:{risk_band[1]};color:#fff;font-weight:700;
        letter-spacing:.5px;font-size:13px;text-transform:uppercase;
        box-shadow:0 4px 12px {risk_band[1]}66}}
  .risk-band::before{{content:"";width:8px;height:8px;border-radius:50%;
        background:#fff;box-shadow:0 0 0 4px #ffffff33;animation:pulse 1.6s infinite}}
  @keyframes pulse{{0%,100%{{box-shadow:0 0 0 4px #ffffff33}} 50%{{box-shadow:0 0 0 9px #ffffff11}}}}
  /* KPIs */
  .kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
        gap:14px;margin:24px 0 36px}}
  .kpi{{background:#fff;border-radius:10px;padding:16px 18px;
        box-shadow:0 1px 3px rgba(0,0,0,.08);border-left:4px solid #d0d7de}}
  .kpi-v{{font-size:28px;font-weight:700;color:#1f2937;line-height:1.1}}
  .kpi-l{{font-size:11px;color:#6b7280;text-transform:uppercase;
        letter-spacing:.5px;margin-top:4px;font-weight:600}}
  .kpi-s{{font-size:11px;color:#9ca3af;margin-top:6px}}
  /* Sections */
  section{{background:#fff;border-radius:12px;padding:24px 28px;margin-bottom:24px;
        box-shadow:0 1px 3px rgba(0,0,0,.06)}}
  section h2{{margin:0 0 18px;font-size:18px;color:#1f2937;
        border-bottom:2px solid #f0f3f7;padding-bottom:10px}}
  /* Tables */
  table.grid{{width:100%;border-collapse:collapse;font-size:13px}}
  table.grid th{{text-align:left;padding:10px 12px;background:#f6f8fa;
        font-weight:600;color:#57606a;font-size:11px;text-transform:uppercase;
        letter-spacing:.5px;border-bottom:1px solid #e1e4e8}}
  table.grid td{{padding:10px 12px;border-bottom:1px solid #f0f3f7;vertical-align:top}}
  table.grid tr:hover td{{background:#fafbfc}}
  table.grid td.mono{{font-family:'SF Mono',Menlo,Monaco,Consolas,monospace;font-size:12px}}
  table.grid td.num{{text-align:center;font-variant-numeric:tabular-nums}}
  /* Pills + badges */
  .risk-pill{{display:inline-block;padding:3px 10px;border-radius:4px;
        color:#fff;font-weight:600;font-size:11px;letter-spacing:.5px}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:4px;
        font-size:10px;font-weight:600;letter-spacing:.4px;text-transform:uppercase}}
  .badge-pwned{{background:#fff0e6;color:#bf4f00;border:1px solid #ffd0b0}}
  .badge-prd{{background:#fbe5e5;color:#b51c1c;border:1px solid #f5b5b5}}
  .badge-bad{{background:#fbe5e5;color:#b51c1c}}
  .badge-ok{{background:#dafbe1;color:#1a7f37}}
  .badge-mid{{background:#fff8c5;color:#9a6700}}
  .sid-pill{{display:inline-block;padding:2px 8px;border-radius:4px;
        background:#0f1729;color:#fff;font-family:'SF Mono',Menlo,monospace;
        font-size:11px;font-weight:700;margin-right:8px}}
  .num-pill{{display:inline-block;min-width:28px;padding:2px 8px;
        border-radius:999px;font-size:11px;font-weight:700;text-align:center}}
  .num-pill-bad{{background:#fbe5e5;color:#b51c1c}}
  .num-pill-ok{{background:#dafbe1;color:#1a7f37}}
  /* Findings cards */
  .finding{{background:#fafbfc;border-radius:8px;padding:14px 18px;margin-bottom:10px}}
  .finding-head{{display:flex;align-items:center;margin-bottom:8px}}
  .finding-name{{font-weight:600;font-size:14px;color:#1f2937}}
  .finding-desc{{font-size:13px;color:#374151;margin:6px 0}}
  .finding-detail{{font-size:12px;color:#6b7280;margin-top:6px}}
  .finding-rem{{font-size:12px;color:#1a7f37;background:#f0fdf4;
        padding:8px 10px;border-radius:4px;margin-top:8px;
        border-left:3px solid #1a7f37}}
  .muted{{color:#8b949e;font-style:italic;padding:8px}}
  ol{{padding-left:22px;margin:0}} ol li{{margin-bottom:8px;font-size:14px}}
  footer{{text-align:center;color:#8b949e;font-size:11px;margin-top:32px}}
  @media print{{body{{background:#fff}} section{{box-shadow:none;border:1px solid #e1e4e8}}}}
</style>
</head><body>
<div class="wrap">

  <div class="hero">
    <h1>{_hesc(title)}</h1>
    <div class="meta">Generated by SAPMAP at {now}</div>
    <span class="risk-band">Overall risk: {risk_band[0]}</span>
  </div>

  <div class="kpis">
    {_kpi_card("Systems discovered", str(len(nodes)),
                f"{abap} ABAP · {java} Java · {routers} SAProuter",
                "#0969da")}
    {_kpi_card("Systems pwned", f"{len(pwned)}/{len(nodes)}",
                f"{pct_pwned}% of landscape",
                "#db6d28" if pwned else "#3fb950")}
    {_kpi_card("Production pwned", str(len(pwned_prd)),
                ", ".join(n.sid for n in pwned_prd) or "none",
                "#f85149" if pwned_prd else "#3fb950")}
    {_kpi_card("Critical findings", str(len(crit_findings)),
                f"{len(high_findings)} HIGH",
                "#f85149" if crit_findings else "#3fb950")}
    {_kpi_card("Trust chains", str(chain_count),
                f"{prd_chain_count} reach PRD",
                "#f85149" if prd_chain_count else "#0969da")}
    {_kpi_card("SAPMAP accounts created", str(created), "", "#6f42c1")}
    {_kpi_card("ABAP SecStore decrypted", str(secstore_total),
                "RFC / DB / CTS passwords", "#6f42c1")}
    {_kpi_card("Java SecStore decrypted", str(java_secstore_total),
                "SecStoreFS entries", "#6f42c1")}
    {_kpi_card("Cloud Connectors", f"{len(sccs)}",
                f"{scc_pwned} with cracked admin"
                if scc_pwned else
                ("0 compromised" if sccs else "none in scope"),
                "#f85149" if scc_pwned else
                ("#0969da" if sccs else "#d0d7de"))}
  </div>

  <section>
    <h2>🛑 Critical findings ({len(crit_findings)})</h2>
    {crit_html}
  </section>

  <section>
    <h2>⚠️ High findings ({len(high_findings)})</h2>
    {high_html}
  </section>

  <section>
    <h2>🔗 Lateral movement / trust chains ({chain_count})</h2>
    <table class="grid"><thead><tr>
      <th>Risk</th><th>Path</th><th>Hops</th><th>PRD</th><th>Entry</th>
    </tr></thead><tbody>{chain_rows_html}</tbody></table>
  </section>

  <section>
    <h2>🗺️ Landscape inventory</h2>
    <table class="grid"><thead><tr>
      <th>SID</th><th>Type</th><th>OS</th><th>DB</th><th>Host</th>
      <th>Status</th><th>Tier</th><th>Critical</th><th>RFC creds</th>
    </tr></thead><tbody>{inv_rows}</tbody></table>
  </section>

  <section>
    <h2>🔑 Recovered credentials</h2>
    <p style="font-size:12px;color:#6b7280;margin:0 0 12px">
      Passwords masked in this report — full plaintext lives in
      <code>loot/secstore/</code>, <code>loot/hashes/</code>, and
      <code>loot/scc/&lt;host&gt;/hashes_cracked.txt</code>.
    </p>
    {cred_table}
  </section>

  {scc_html}

  <section>
    <h2>📋 Recommendations</h2>
    {rec_html}
  </section>

  <footer>SAPMAP — SAP Landscape Attack-Path Mapper · Report data
    sourced from in-memory session state at generation time.</footer>
</div>
</body></html>
"""
