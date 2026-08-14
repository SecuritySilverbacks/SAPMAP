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
    btp_count = len(getattr(state, "btp_subaccounts", {}) or {})
    btp_pwned = sum(
        1 for b in (getattr(state, "btp_subaccounts", {}) or {}).values()
        if getattr(b, "pwned", False))
    conns_md = list(state.connections or [])
    conn_total_md = len(conns_md)
    conn_sap_all_md = sum(1 for c in conns_md
                           if getattr(c, "has_sap_all", False))
    conn_tested_ok_md = sum(1 for c in conns_md
                             if getattr(c, "logon_successful", False))

    findings_total = sum(len(n.findings or []) for n in nodes)
    crit = sum(1 for n in nodes for f in (n.findings or [])
               if str(getattr(f, "severity", "")).endswith("CRITICAL")
               or getattr(f, "severity", None) == Severity.CRITICAL)
    high = sum(1 for n in nodes for f in (n.findings or [])
               if str(getattr(f, "severity", "")).endswith("HIGH")
               or getattr(f, "severity", None) == Severity.HIGH)

    total_systems_md = len(nodes) + scc_count + btp_count
    total_pwned_md = len(pwned) + scc_pwned + btp_pwned
    pct_pwned = (100 * total_pwned_md // total_systems_md) if total_systems_md else 0

    out = ["## Executive summary", ""]
    out.extend(_stat_table([
        ("Total SAP nodes discovered",
         f"{len(nodes)} ({abap} ABAP, {java} Java, {routers} SAProuter)"),
        ("SAP Cloud Connectors",
         f"{scc_count} ({scc_pwned} with cracked admin)" if scc_count else "0"),
        ("BTP subaccounts",
         (f"{btp_count} ({btp_pwned} with cleartext destinations)"
          if btp_count else "0")),
        ("Connections (RFC + HTTP destinations)",
         (f"{conn_total_md} total — {conn_sap_all_md} grant SAP_ALL, "
          f"{conn_tested_ok_md} tested OK"
          if conn_total_md else "0")),
        ("Systems pwned",
         f"{total_pwned_md} / {total_systems_md} ({pct_pwned}%) — "
         f"{len(pwned)} SAP, {scc_pwned} SCC, {btp_pwned} BTP"),
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


def _render_structured_remediation(rem: dict, indent: str = "") -> str:
    """Render one structured Remediation block as inline Markdown.

    Used both inside per-finding sections (indented under the finding's
    own headline) and inside the Hardening checklist section (top level).
    """
    parts = []
    if rem.get("fix_summary"):
        parts.append(f"{indent}**Remediation — {_esc(rem['fix_summary'])}**")
    badges = []
    if rem.get("requires_restart"):
        badges.append("⚠️ restart needed")
    else:
        badges.append("🟢 online fix")
    if rem.get("effort_minutes"):
        badges.append(f"⏱ ~{rem['effort_minutes']} min")
    if rem.get("severity_if_delayed"):
        badges.append(f"🛑 if delayed: {rem['severity_if_delayed']}")
    if badges:
        parts.append(f"{indent}_{' · '.join(badges)}_")
    if rem.get("fix_steps"):
        parts.append(f"{indent}**Fix steps:**")
        for i, step in enumerate(rem["fix_steps"], 1):
            parts.append(f"{indent}{i}. {_esc(step)}")
    if rem.get("verification"):
        parts.append(f"{indent}**Verification:**")
        for i, step in enumerate(rem["verification"], 1):
            parts.append(f"{indent}{i}. {_esc(step)}")
    refs = rem.get("refs") or []
    if refs:
        refs_md = []
        for r in refs:
            if isinstance(r, (list, tuple)) and len(r) >= 2:
                refs_md.append(f"[{_esc(r[0])}]({_esc(r[1])})")
            elif isinstance(r, str):
                refs_md.append(_esc(r))
        if refs_md:
            parts.append(f"{indent}**References:** {' · '.join(refs_md)}")
    if rem.get("last_reviewed"):
        parts.append(f"{indent}_Catalog entry last reviewed "
                     f"{rem['last_reviewed']}._")
    return "\n".join(parts)


def _html_render_structured_remediation(rem: dict) -> str:
    """HTML equivalent of the GUI renderRemediationBlock — returns one
    self-contained <div> with fix summary, restart/effort/severity
    badges, numbered fix + verification lists, and clickable refs.

    Built without f-strings carrying embedded backslashes so the file
    parses on every Python interpreter the report is shipped on.
    """
    if not isinstance(rem, dict) or not rem.get("fix_summary"):
        return ""

    fix_summary = _hesc(rem["fix_summary"])
    # Badges
    badges = []
    if rem.get("requires_restart"):
        badges.append(
            '<span class="rem-badge rem-badge-restart" '
            'title="Applying this fix needs an instance restart">'
            'restart needed</span>')
    else:
        badges.append(
            '<span class="rem-badge rem-badge-online" '
            'title="No downtime required">online fix</span>')
    if rem.get("effort_minutes"):
        badges.append(
            '<span class="rem-badge" '
            'title="Rough wall-clock effort estimate (one engineer)">'
            "~" + str(int(rem["effort_minutes"])) + " min</span>")
    if rem.get("severity_if_delayed"):
        badges.append(
            '<span class="rem-badge rem-badge-delayed" '
            'title="Severity of the existing finding if the fix is '
            'delayed">if delayed: '
            + _hesc(rem["severity_if_delayed"]) + "</span>")

    parts = [
        '<div class="rem-block">',
        '<div class="rem-head">&#10004; Hardening: ',
        fix_summary,
        '</div>',
        '<div class="rem-badges">', "".join(badges), '</div>',
    ]
    steps = rem.get("fix_steps") or []
    if steps:
        parts.append('<div class="rem-sub"><b>Fix steps:</b><ol>')
        parts.extend('<li>' + _hesc(s) + '</li>' for s in steps)
        parts.append('</ol></div>')
    verify = rem.get("verification") or []
    if verify:
        parts.append('<div class="rem-sub"><b>Verification:</b><ol>')
        parts.extend('<li>' + _hesc(s) + '</li>' for s in verify)
        parts.append('</ol></div>')
    refs = rem.get("refs") or []
    if refs:
        ref_html = []
        for r in refs:
            if isinstance(r, (list, tuple)) and len(r) >= 2:
                label, url = r[0], r[1]
                if label and url:
                    ref_html.append(
                        '<a class="rem-ref" target="_blank" '
                        'rel="noopener noreferrer" href="'
                        + _hesc(url) + '">' + _hesc(label) + '</a>')
        if ref_html:
            parts.append('<div class="rem-sub"><b>References:</b> '
                          '<div class="rem-refs">'
                          + "".join(ref_html) + '</div></div>')
    if rem.get("last_reviewed"):
        parts.append('<div class="rem-stamp">Catalog entry last reviewed '
                      + _hesc(str(rem["last_reviewed"])) + '.</div>')
    parts.append('</div>')
    return "".join(parts)


# CSS for the HTML report — injected once into the <style> block.
_REM_BLOCK_CSS = """
.rem-block { margin:8px 0 0 0; padding:8px 12px;
  background:#ecfdf5; border:1px solid #a7f3d0;
  border-radius:6px; color:#064e3b; font-size:12px; line-height:1.45 }
.rem-head { color:#047857; font-weight:600; margin-bottom:4px }
.rem-badges { display:flex; gap:4px; flex-wrap:wrap; margin-bottom:6px }
.rem-badge { display:inline-block; font-family:monospace;
  font-size:10px; padding:1px 6px; border-radius:2px;
  background:#f3f4f6; color:#374151; border:1px solid #d1d5db;
  line-height:14px }
.rem-badge-restart { background:#fef3c7; color:#92400e; border-color:#fde68a }
.rem-badge-online  { background:#d1fae5; color:#065f46; border-color:#a7f3d0 }
.rem-badge-delayed { background:#fee2e2; color:#991b1b; border-color:#fecaca }
.rem-sub { margin-top:6px }
.rem-sub ol { margin:4px 0 4px 20px; padding:0 }
.rem-refs { display:flex; gap:4px; flex-wrap:wrap; margin-top:3px }
.rem-ref { display:inline-block; font-family:monospace; font-size:10px;
  padding:1px 6px; border-radius:2px;
  background:#e0e7ff; color:#3730a3; border:1px solid #c7d2fe;
  text-decoration:none }
.rem-ref:hover { background:#3730a3; color:#fff }
.rem-stamp { color:#6b7280; font-size:10px; margin-top:6px }
.hc-card { margin:10px 0; padding:10px 12px;
  background:#fff; border:1px solid #e5e7eb; border-radius:6px }
.hc-title { font-weight:600; color:#111827; margin-bottom:4px }
.hc-scope { color:#374151; font-size:11px; margin-bottom:6px }
"""


def _build_hardening_html(state: SAPMAPState) -> str:
    """HTML version of the Hardening checklist — same aggregation logic
    as the Markdown helper, rendered into bordered cards.  Returns ""
    when no structured remediation was found anywhere in the state."""
    bucket = {}   # fix_summary → {sids: set, rem: dict, max_sev: int}
    for sid, n in sorted(state.nodes.items()):
        for f in n.findings or []:
            rem = getattr(f, "remediation", None)
            if not isinstance(rem, dict) or not rem.get("fix_summary"):
                continue
            key = rem["fix_summary"]
            slot = bucket.setdefault(key, {"sids": set(), "rem": rem,
                                            "max_sev": 0})
            slot["sids"].add(sid)
            sev = int(getattr(f, "severity", 0) or 0)
            if sev > slot["max_sev"]:
                slot["max_sev"] = sev
    if not bucket:
        return ""

    ordered = sorted(
        bucket.items(),
        key=lambda kv: (-kv[1]["max_sev"], kv[0]))
    cards = []
    for idx, (summary, slot) in enumerate(ordered, 1):
        rem = slot["rem"]
        sids = ", ".join(sorted(slot["sids"]))
        cards.append(
            '<div class="hc-card">'
            + '<div class="hc-title">' + str(idx) + '. '
            + _hesc(summary) + '</div>'
            + '<div class="hc-scope"><b>Scope:</b> ' + _hesc(sids) + '</div>'
            + _html_render_structured_remediation(rem)
            + '</div>')
    return "".join(cards)


def _hardening_checklist_section(state: SAPMAPState) -> list:
    """Aggregate every structured remediation across the landscape into
    a deduped action checklist.  Replaces the older
    _derive_landscape_recommendations function which had hand-maintained
    text drifting away from the per-finding remediation blocks.
    """
    # Capability key → {sids: set, remediation: dict, max_sev: int}
    bucket = {}
    for sid, n in sorted(state.nodes.items()):
        for f in n.findings or []:
            rem = getattr(f, "remediation", None)
            if not isinstance(rem, dict) or not rem.get("fix_summary"):
                continue
            # We use the fix_summary as a stable de-dup key (a single
            # capability key contributes one summary; different
            # capability keys with the same summary collapse cleanly).
            key = rem["fix_summary"]
            slot = bucket.setdefault(key, {"sids": set(), "rem": rem,
                                            "max_sev": 0})
            slot["sids"].add(sid)
            sev = int(getattr(f, "severity", 0) or 0)
            if sev > slot["max_sev"]:
                slot["max_sev"] = sev

    if not bucket:
        return []

    out = ["## Hardening checklist", ""]
    out.append(
        "Aggregated fix-guidance for every CRITICAL / HIGH finding in "
        "this engagement.  Each entry deduplicates across systems — the "
        "scope column lists every SID that currently needs the fix."
    )
    out.append("")
    # Sort by max severity desc, then fix_summary alphabetic
    ordered = sorted(
        bucket.items(),
        key=lambda kv: (-kv[1]["max_sev"], kv[0]))
    for idx, (summary, slot) in enumerate(ordered, 1):
        rem = slot["rem"]
        sids = ", ".join(sorted(slot["sids"]))
        out.append(f"### {idx}. {_esc(summary)}")
        out.append("")
        out.append(f"**Scope:** {sids}")
        out.append("")
        out.append(_render_structured_remediation(rem, indent=""))
        out.append("")
        out.append("---")
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
                if isinstance(f.remediation, dict) and f.remediation.get("fix_summary"):
                    out.append("")
                    out.append(_render_structured_remediation(f.remediation,
                                                                indent="    "))
                else:
                    out.append("")
                    out.append(f"**Remediation:** {_esc(str(f.remediation))}")
            tids = getattr(f, "attack_techniques", None) or []
            if tids:
                try:
                    from sapmap_attack import lookup
                    parts = []
                    for tid in tids:
                        info = lookup(tid)
                        if info:
                            parts.append(f"[{tid}]({info['url']}) "
                                         f"{_esc(info['name'])}")
                        else:
                            parts.append(tid)
                    out.append("")
                    out.append(f"**ATT&CK:** {' · '.join(parts)}")
                except Exception:
                    pass
            out.append("")
    return out


def _attack_coverage_section(state: SAPMAPState) -> list:
    """Tactic-grouped summary of MITRE ATT&CK techniques exercised."""
    try:
        from sapmap_attack import (
            heatmap_grid, ATTACK_VERSION, TACTICS, lookup,
        )
    except Exception:
        return []

    grid = heatmap_grid(state)
    totals = grid.get("totals", {})
    if not totals.get("techniques"):
        return []   # nothing tagged — skip the section entirely

    out = ["## MITRE ATT&CK coverage", ""]
    out.append(
        f"This engagement exercised **{totals['techniques']} techniques** "
        f"across **{totals['tactics']} tactics** "
        f"(mapped against ATT&CK Enterprise {ATTACK_VERSION}). "
        f"Severity per cell reflects the highest-severity finding bearing "
        f"that technique.")
    out.append("")
    out.append("| Tactic | Techniques | SIDs touched |")
    out.append("| --- | --- | --- |")
    for col in grid.get("columns", []):
        observed = [c for c in col["cells"] if c["score"] > 0]
        if not observed:
            continue
        cells_md = []
        sids = set()
        for c in observed:
            info = lookup(c["id"])
            label = c["id"]
            if info:
                label = f"[{c['id']}]({info['url']})"
            cells_md.append(label)
            sids.update(c["sids"])
        out.append(
            f"| {col['tactic_name']} "
            f"| {' · '.join(cells_md)} "
            f"| {', '.join(sorted(sids))} |")
    out.append("")
    out.append(
        f"_Drop the matching `sapmap_attack_layer.json` into "
        f"[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) "
        f"for the interactive heatmap._")
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
    """Cloud Connector landscape, if any SCCs are mapped.

    Surfaces every SCCNode field that carries loot / risk signal:
    version + confirmed CVEs, HA topology, principal-propagation
    posture, captured admin credentials, extracted keystores,
    decrypted SSFS, mapped subaccounts.  A shallow one-line table
    per SCC would hide the crown-jewels (pp_ca_privkey_fp,
    unlocked_keystores, users_xml_loot_path) that are exactly what a
    stakeholder needs to see.
    """
    sccs = (getattr(state, "scc_nodes", {}) or {})
    if not sccs:
        return []
    out = ["## SAP Cloud Connectors", ""]

    # -- Landscape roll-up table --
    out.append("| Host | Version | HA | CVEs | Default creds | Mappings | "
               "SSFS | Keystore | PP weak | Creds captured |")
    out.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for host, sn in sorted(sccs.items()):
        conf = list(getattr(sn, "cves_confirmed", []) or [])
        susp = list(getattr(sn, "cves_suspected", []) or [])
        if conf:
            cves = "**" + ", ".join(conf) + "**"
            if susp:
                cves += f" ({len(susp)} suspected)"
        elif susp:
            cves = f"{len(susp)} suspected"
        else:
            cves = "—"
        default = ("**LIVE**"
                   if getattr(sn, "default_creds_live", False) else "—")
        nmap = len(getattr(sn, "mappings", []) or [])
        ssfs = ("✓" if getattr(sn, "ssfs_decrypted", False) else "—")
        ks = ("✓" if getattr(sn, "keystore_extracted", False) else "—")
        pp = getattr(sn, "pp_weak_count", 0)
        pp_cell = f"**{pp}**" if pp else "—"
        ncreds = len(getattr(sn, "credentials", []) or [])
        creds_cell = ("**" + str(ncreds) + "**" if ncreds else "—")
        ha = getattr(sn, "ha_role", "") or "—"
        ver = getattr(sn, "version", "") or "?"
        out.append(f"| {host} | {_esc(ver)} | {_esc(ha)} | {cves} | "
                   f"{default} | {nmap} | {ssfs} | {ks} | {pp_cell} | "
                   f"{creds_cell} |")
    out.append("")

    # -- Per-SCC detail (only when we actually have loot to surface) --
    for host, sn in sorted(sccs.items()):
        creds = list(getattr(sn, "credentials", []) or [])
        keystore = getattr(sn, "keystore_extracted", False)
        ssfs = getattr(sn, "ssfs_decrypted", False)
        pp_ca = getattr(sn, "pp_ca_privkey_fp", "") or ""
        tun_fp = getattr(sn, "tunnel_privkey_fp", "") or ""
        unlocked = list(getattr(sn, "unlocked_keystores", []) or [])
        ssfs_keys = list(getattr(sn, "ssfs_secrets_keys", []) or [])
        pp_ana = getattr(sn, "pp_analysis", {}) or {}
        sub_uuids = list(getattr(sn, "subaccount_uuids", []) or [])
        loc_ids = list(getattr(sn, "location_ids", []) or [])
        region = getattr(sn, "tunnel_region", "") or ""
        replayed = getattr(sn, "tunnel_replayed", False)
        users_xml = getattr(sn, "users_xml_loot_path", "") or ""
        ha_peer = getattr(sn, "ha_shadow_host", "") or ""
        has_detail = (creds or keystore or ssfs or pp_ca or tun_fp
                      or unlocked or ssfs_keys or pp_ana or sub_uuids
                      or loc_ids or users_xml or ha_peer or replayed)
        if not has_detail:
            continue

        out.append(f"### SCC {host} — details")
        out.append("")

        # HA / trust topology
        if ha_peer or region or sub_uuids or loc_ids:
            topo_rows = []
            if getattr(sn, "ha_role", ""):
                topo_rows.append(
                    ("HA role",
                     f"{_esc(sn.ha_role)}"
                     + (f" (peer: {_esc(ha_peer)} · "
                        f"{_esc(getattr(sn, 'ha_peer_role', '') or '?')})"
                        if ha_peer else "")))
            if region:
                topo_rows.append(("BTP tunnel region", _esc(region)))
            if sub_uuids:
                topo_rows.append(
                    ("Subaccounts trusted",
                     f"{len(sub_uuids)} — "
                     f"{_esc(', '.join(sub_uuids[:3]))}"
                     + ("…" if len(sub_uuids) > 3 else "")))
            if loc_ids:
                topo_rows.append(
                    ("Location IDs",
                     _esc(", ".join(loc_ids)) or "—"))
            if replayed:
                topo_rows.append(
                    ("Tunnel handshake",
                     "**replayed** (persistence achieved)"))
            out.extend(_stat_table(topo_rows))
            out.append("")

        # Crown-jewel artifacts
        crown_rows = []
        if keystore and getattr(sn, "keystore_loot_path", ""):
            crown_rows.append(
                ("Keystore",
                 f"extracted → `{_esc(sn.keystore_loot_path)}`"))
        if users_xml:
            crown_rows.append(
                ("Users.xml (plaintext)",
                 f"decrypted → `{_esc(users_xml)}`"))
        if tun_fp:
            crown_rows.append(
                ("Tunnel private key",
                 f"SHA-256 `{_esc(tun_fp[:16])}…` — system-identity"))
        if pp_ca:
            crown_rows.append(
                ("**PP CA private key**",
                 f"SHA-256 `{_esc(pp_ca[:16])}…` — **can mint client "
                 "certs for any subaccount user**"))
        if ssfs and (getattr(sn, "ssfs_secrets_path", "") or ssfs_keys):
            crown_rows.append(
                ("SSFS secrets",
                 f"decrypted → "
                 f"`{_esc(getattr(sn, 'ssfs_secrets_path', '') or '?')}`"
                 f" ({len(ssfs_keys)} keys)"))
        if crown_rows:
            out.append("**Crown-jewel artifacts:**")
            out.append("")
            out.extend(_stat_table(crown_rows))
            out.append("")

        # SSFS secret key names (names only — plaintext values stay
        # in the side file at 0600).
        if ssfs_keys:
            out.append(
                f"_SSFS secret keys captured ({len(ssfs_keys)}): "
                + _esc(", ".join(ssfs_keys[:20]))
                + ("…" if len(ssfs_keys) > 20 else "")
                + "_")
            out.append("")

        # Unlocked keystores (one line per cert)
        if unlocked:
            out.append("**Unlocked tunnel keystores:**")
            out.append("")
            out.append("| Path | Cert subject | SHA-256 |")
            out.append("| --- | --- | --- |")
            for k in unlocked[:20]:
                p = k.get("path", "") or "?"
                subj = k.get("cert_subject", "") or "?"
                fp = k.get("cert_sha256", "") or ""
                fp_short = (fp[:16] + "…") if fp else "—"
                out.append(f"| `{_esc(p)}` | {_esc(subj)} | "
                           f"`{_esc(fp_short)}` |")
            if len(unlocked) > 20:
                out.append(f"| …{len(unlocked) - 20} more | | |")
            out.append("")

        # Captured admin credentials
        if creds:
            out.append("**Captured admin credentials:**")
            out.append("")
            out.append("| User | Hash / marker | Verified |")
            out.append("| --- | --- | --- |")
            for c in creds:
                user = (getattr(c, "user", "")
                        or (isinstance(c, dict) and c.get("user"))
                        or "?")
                # Never emit the plaintext password — mark presence only.
                pw = (getattr(c, "password", "")
                      or (isinstance(c, dict) and c.get("password"))
                      or "")
                h = (getattr(c, "hash", "")
                     or (isinstance(c, dict) and c.get("hash"))
                     or "")
                verified = bool(
                    getattr(c, "verified", False)
                    or (isinstance(c, dict) and c.get("verified")))
                if pw:
                    marker = "plaintext captured"
                elif h:
                    marker = f"hash `{_esc(h[:24])}…`"
                else:
                    marker = "—"
                out.append(f"| `{_esc(user)}` | {marker} | "
                           f"{'✓' if verified else '—'} |")
            out.append("")

        # Principal-Propagation analyser verdict
        summary = pp_ana.get("summary") if isinstance(pp_ana, dict) else None
        findings = pp_ana.get("findings") if isinstance(pp_ana, dict) else None
        if summary or findings:
            crit = (summary or {}).get("critical", 0)
            high = (summary or {}).get("high", 0)
            med = (summary or {}).get("medium", 0)
            out.append(
                f"**Principal-Propagation analysis:** "
                f"{crit} CRITICAL · {high} HIGH · {med} MEDIUM "
                f"(analysed at {_esc(getattr(sn, 'pp_analysis_at', '') or '?')})")
            out.append("")
            if findings:
                out.append("| Severity | Finding |")
                out.append("| --- | --- |")
                for f in findings[:15]:
                    sev = f.get("severity", "?") if isinstance(f, dict) else "?"
                    hl = ((f.get("headline") or f.get("title") or "")
                          if isinstance(f, dict) else str(f))
                    out.append(f"| {_esc(sev)} | {_esc(hl)} |")
                if len(findings) > 15:
                    out.append(f"| … | {len(findings) - 15} more |")
                out.append("")

        # Confirmed CVEs (with severity from cve_details if present)
        cve_det = getattr(sn, "cve_details", []) or []
        if cve_det:
            out.append("**CVE assessment:**")
            out.append("")
            out.append("| CVE | Severity | Status | Headline |")
            out.append("| --- | --- | --- | --- |")
            for d in cve_det:
                if not isinstance(d, dict):
                    continue
                out.append(
                    f"| {_esc(d.get('cve', '?'))} | "
                    f"{_esc(d.get('severity', '?'))} | "
                    f"{_esc(d.get('status', '?'))} | "
                    f"{_esc(d.get('headline', ''))} |")
            out.append("")
    return out


def _capability_section(state: SAPMAPState) -> list:
    """User capability inventory — one paragraph per (user, client)
    pair we own.  This is the section CISOs print: it's the only
    place in the report that translates raw SAP_ALL into business
    English ("can read 14,382 salary records, 2,107 vendor IBANs,
    20.7M GL line items")."""
    rows = []
    for sid, n in sorted(state.nodes.items()):
        for r in (n.capability_results or []):
            rows.append((sid, r))
    if not rows:
        return []
    out = ["## User capability inventory", ""]
    out.append(
        "What each user we own can actually read or do, mapped from "
        "raw `AGR_USERS` / `AGR_1251` / `UST04` rows to business "
        "capabilities.  This is the practical blast-radius — far "
        "more decision-useful than `SAP_ALL: yes/no`.")
    out.append("")
    for sid, r in rows:
        caps = r.get("capabilities") or []
        sev = max((c.get("severity", 1) for c in caps), default=1)
        sev_label = {5: "CRITICAL", 4: "HIGH",
                     3: "MEDIUM", 2: "LOW", 1: "INFO"}.get(sev, "INFO")
        out.append(
            f"### {sev_label} — {r.get('username', '?')} on {sid} "
            f"client {r.get('client', '?')}")
        out.append("")
        out.append(_esc(r.get("summary") or ""))
        out.append("")
        out.append(f"_Blast-radius: {_esc(r.get('blast_radius', ''))}_")
        out.append("")
        if caps:
            out.append("| Auth object | Capability | Affected tables |")
            out.append("| --- | --- | --- |")
            for c in sorted(caps,
                             key=lambda x: -x.get("severity", 0)):
                tbls = ", ".join(c.get("tables", []) or []) or "—"
                out.append(
                    f"| `{_esc(c.get('auth_object', ''))}` | "
                    f"{_esc(c.get('capability', ''))} | "
                    f"{_esc(tbls)} |")
            out.append("")
    return out


def _btp_section(state: SAPMAPState) -> list:
    """BTP subaccounts — what the cloud side gave up to us.

    One row per subaccount with the headline numbers (destinations
    captured, cleartext recovered, on-prem nodes linked).  Skipped
    entirely when no subaccount has been enumerated."""
    subs = (getattr(state, "btp_subaccounts", {}) or {})
    if not subs:
        return []
    out = ["## SAP BTP subaccounts", ""]
    out.append("| Subdomain | Region | Destinations | Cleartext | "
               "Linked on-prem | Pwned |")
    out.append("| --- | --- | --- | --- | --- | --- |")
    for uuid, sub in sorted(
            subs.items(),
            key=lambda kv: (getattr(kv[1], "subdomain", "")
                             or kv[0])):
        dests = list(getattr(sub, "destinations", []) or [])
        clear = sum(1 for d in dests
                    if getattr(d, "cleartext_captured", False)
                    or (isinstance(d, dict) and d.get(
                        "cleartext_captured")))
        linked = sum(1 for d in dests
                     if (getattr(d, "linked_target_sid", "")
                         or (isinstance(d, dict)
                             and d.get("linked_target_sid"))))
        pwned_mark = "⚡" if getattr(sub, "pwned", False) else "—"
        sub_label = (getattr(sub, "subdomain", "")
                     or getattr(sub, "display_name", "")
                     or uuid[:8])
        out.append(
            f"| {_esc(sub_label)} | "
            f"{_esc(getattr(sub, 'region', '') or '?')} | "
            f"{len(dests)} | {clear} | {linked} | {pwned_mark} |")
    out.append("")
    return out


def _cloud_lateral_section(state: SAPMAPState) -> list:
    """Narrative summary of cloud ↔ on-prem lateral moves.

    Rolls up what the individual BTP-subaccount table, the
    cleartext-credentials table, and the cert-auth-destinations
    table each show in isolation, into one exec-friendly block:

      "Cert DFAULT on S4H → BTP tenant researchlab-yehctg7m →
       4 destinations pulled → sapadm@W74 + joris@S4H
       credentials in the clear."

    Emitted ONLY when there's a lateral chain to report — a
    landscape with no BTP-side credential capture doesn't get a
    hollow header.  Groups by subaccount so multi-tenant
    engagements produce one paragraph per tenant.

    Data sources:
      * state.btp_subaccounts — subaccount metadata + destination
        list (populated by the mint auto-enumerate step)
      * findings with ref="onprem.to.btp.token_minted*" and
        "btp.token_minted_via_local_cert" — mint provenance +
        cert thumbprints
      * findings with ref="btp.cleartext.captured" — cleartext
        counts per subaccount
      * state.connections BTP:<uuid8>→<sid> — post-sweep
        has_sap_all flags
    """
    subs = getattr(state, "btp_subaccounts", None) or {}
    # Skip when there's no BTP presence at all.
    if not subs:
        return []
    # Or when no subaccount has captured a real destination — an
    # operator who enumerated an empty subaccount doesn't need a
    # cloud-lateral section.
    total_dests = sum(
        len(list(getattr(s, "destinations", []) or []))
        for s in subs.values())
    if total_dests == 0:
        return []

    # Gather mint-provenance findings so we can name the source
    # side of each lateral move (which on-prem system's cert or
    # workstation-side key material issued the token).
    mint_findings_by_uuid: dict = {}
    for node in state.nodes.values():
        for f in getattr(node, "findings", []) or []:
            ref = getattr(f, "ref", "") or ""
            if not ref.startswith("onprem.to.btp.token_minted"):
                continue
            meta = getattr(f, "meta", {}) or {}
            uuid = (meta.get("region", "")   # fallback if zid missing
                    if not meta.get("zid") else meta.get("zid", ""))
            # meta.zid was added later; fall back to matching by
            # region + destination host if absent.
            mint_findings_by_uuid.setdefault(uuid, []).append(f)
    # Also pull the workstation-side mint findings (source_sid
    # is 'BTP:<uuid8>' so we scan the state-level findings bus
    # instead of a specific SAPNode).
    for f in getattr(state, "findings", None) or []:
        ref = getattr(f, "ref", "") or ""
        if ref == "btp.token_minted_via_local_cert":
            meta = getattr(f, "meta", {}) or {}
            zid = meta.get("region", "") or ""
            mint_findings_by_uuid.setdefault(zid, []).append(f)

    # Only emit for subaccounts that either have destinations OR a
    # mint finding — a subaccount SAPMAP knows about only through
    # an SM59 destination but never enumerated isn't lateral yet.
    interesting_subs = []
    for uuid, sub in subs.items():
        dests = list(getattr(sub, "destinations", []) or [])
        region = getattr(sub, "region", "") or ""
        finds = (mint_findings_by_uuid.get(uuid, [])
                  + mint_findings_by_uuid.get(region, []))
        if dests or finds:
            interesting_subs.append((uuid, sub, dests, finds))
    if not interesting_subs:
        return []

    out = ["## Cloud ↔ on-prem lateral moves", ""]
    out.append(
        f"SAPMAP established {len(interesting_subs)} cloud-side "
        f"lateral entry point(s).  Each represents a working chain "
        f"from on-prem cert-auth (or workstation-side cert files) "
        f"through SAP BTP's XSUAA + Destination Service to on-prem "
        f"back-ends whose credentials leaked in the clear.")
    out.append("")

    for uuid, sub, dests, mint_findings in interesting_subs:
        subdomain = (getattr(sub, "subdomain", "")
                      or getattr(sub, "display_name", "")
                      or uuid[:8])
        region = getattr(sub, "region", "") or "?"
        # Destination bookkeeping
        cleartext_count = sum(
            1 for d in dests
            if getattr(d, "cleartext_captured", False)
            or (isinstance(d, dict) and d.get("cleartext_captured")))
        linked_count = sum(
            1 for d in dests
            if (getattr(d, "linked_target_sid", "")
                 or (isinstance(d, dict)
                     and d.get("linked_target_sid"))))
        linked_sids = set()
        for d in dests:
            lts = (getattr(d, "linked_target_sid", "")
                    or (isinstance(d, dict)
                        and d.get("linked_target_sid")))
            if lts:
                linked_sids.add(lts)

        # Mint provenance
        mint_bullets = []
        for f in mint_findings:
            meta = getattr(f, "meta", {}) or {}
            ref = getattr(f, "ref", "") or ""
            thumbprint = meta.get("thumbprint", "")[:12]
            if "via_cert" in ref:
                src = (f"SM59 destination "
                        f"`{meta.get('destination', '?')}` "
                        f"on `{getattr(f, 'sid', '?')}` "
                        f"(PSE `{meta.get('pse', '?')}`)")
            elif "via_local_cert" in ref:
                src = (f"local cert file "
                        f"`{meta.get('cert_path', '?')}` on the "
                        f"SAPMAP host")
            else:
                src = "unknown mint path"
            mint_bullets.append(
                f"- **Token minted via** {src}; RFC-8705 x5t#S256 "
                f"prefix `{thumbprint}…`")

        # BTP → on-prem back-edges surfaced by the auto-sweep
        back_edges = [
            c for c in getattr(state, "connections", []) or []
            if c.source_sid == f"BTP:{uuid[:8]}"
               and c.target_sid]
        sap_all_hits = [c for c in back_edges if c.has_sap_all]

        out.append(f"### `{_esc(subdomain)}` (region `{_esc(region)}`)")
        out.append("")
        # One-liner exec summary
        pieces = [
            f"**{len(dests)} destination(s) enumerated**",
        ]
        if cleartext_count:
            pieces.append(
                f"**{cleartext_count} carrying cleartext credentials**")
        if linked_count:
            targets_txt = ", ".join(
                f"`{_esc(s)}`" for s in sorted(linked_sids))
            pieces.append(
                f"**{linked_count} linked to on-prem** ({targets_txt})")
        if sap_all_hits:
            pieces.append(
                f"**{len(sap_all_hits)} credential(s) confirmed with "
                f"SAP_ALL on the target**")
        out.append(" — ".join(pieces) + ".")
        out.append("")
        # Mint provenance bullets
        if mint_bullets:
            out.extend(mint_bullets)
            out.append("")
        # Back-edge table (only when we have anything to show)
        if back_edges:
            out.append("| Destination | Target | User | Client | "
                        "SAP_ALL? | Notes |")
            out.append(
                "| --- | --- | --- | --- | --- | --- |")
            for c in back_edges:
                target = state.get_node(c.target_sid)
                target_label = c.target_sid or "?"
                if target and (target.hostname or target.ip):
                    target_label += (f" ({target.hostname or target.ip})")
                sap_all = "⚡ **yes**" if c.has_sap_all else "—"
                note = ""
                if c.check_error:
                    note = _esc(c.check_error[:80])
                elif c.tested and c.logon_successful:
                    note = "logon OK"
                elif c.tested:
                    note = "credential rejected"
                else:
                    note = "not tested yet"
                out.append(
                    f"| `{_esc(c.destination_name or '?')}` | "
                    f"{_esc(target_label)} | "
                    f"`{_esc(c.rfc_user or '?')}` | "
                    f"{_esc(c.client or '?')} | "
                    f"{sap_all} | {note} |")
            out.append("")
        # Password reuse callout — often the loudest finding on a
        # BTP lateral.  If any two back-edges share a password
        # across DIFFERENT user names or target SIDs, name it.
        pw_users: dict = {}
        for c in back_edges:
            if c.secstore_password and c.rfc_user:
                pw_users.setdefault(c.secstore_password, set()).add(
                    (c.rfc_user, c.target_sid))
        reuse = {p: v for p, v in pw_users.items()
                  if len(v) > 1}
        if reuse:
            out.append("**Password reuse detected:**")
            for pw, pairs in reuse.items():
                pairs_str = ", ".join(
                    f"`{_esc(u)}@{_esc(s)}`" for u, s in sorted(pairs))
                out.append(
                    f"- The same password unlocks {pairs_str} — one "
                    f"leak, multiple systems compromised.")
            out.append("")

    return out


def _cert_auth_destinations_section(state: SAPMAPState) -> list:
    """Certificate-authenticated Type-G / Type-H HTTP destinations.

    These edges used to be invisible: SAPMAP dropped every G/H
    RFCDES row without ``%_PWD``, so cert-auth destinations to BTP
    or third-party SaaS were silently discarded.  The Phase 1
    parser change makes them first-class citizens; this section
    reports them so the engagement-report audience can see the
    kernel-proxied exploitation surface at a glance.

    One row per cert-auth edge, grouped by source system.  Empty
    section when the landscape has none (no header noise).
    """
    rows: list[tuple[str, str, str, str, str, bool]] = []
    for node in state.nodes.values():
        for c in state.get_connections_from(node.sid):
            if c.http_auth_type != "X509":
                continue
            is_btp = (getattr(c, "is_btp_dest", False)
                        or ".hana.ondemand.com" in (c.http_url or ""))
            rows.append((
                node.sid,
                c.destination_name or "?",
                c.http_url or "?",
                c.http_cert_pse or "?",
                c.target_sid or "",
                bool(is_btp),
            ))
    if not rows:
        return []

    n_btp = sum(1 for r in rows if r[5])
    out = ["## Certificate-authenticated HTTP destinations", ""]
    out.append(
        f"{len(rows)} X.509 client-certificate destination(s) discovered "
        f"across the landscape ({n_btp} pointing at BTP / "
        f"``*.hana.ondemand.com``).  These destinations do not carry a "
        f"stored password — authentication happens via a STRUST PSE on "
        f"the source system.  With ``S_RFC`` + ``S_ICF`` on that source, "
        f"an operator can proxy HTTP calls through "
        f"``HTTP_CLIENT_CREATE_BY_DESTINATION`` — the kernel performs "
        f"mutual-TLS transparently and the target sees requests as "
        f"coming from the SAP system itself.")
    out.append("")
    out.append("| Source | Destination | Target URL | PSE | Target node | BTP |")
    out.append("| --- | --- | --- | --- | --- | --- |")
    for src, dest, url, pse, tgt, is_btp in sorted(rows):
        out.append(
            f"| {_esc(src)} | {_esc(dest)} | {_esc(url)} | "
            f"`{_esc(pse)}` | {_esc(tgt) if tgt else '—'} | "
            f"{'☁️' if is_btp else '—'} |")
    out.append("")
    return out


def _impact_section(state: SAPMAPState) -> list:
    """Business-impact scenarios grouped by SID.  Only shows hits."""
    have = False
    out = ["## Business impact", ""]
    out.append(
        "Concrete blast-radius reads across finance / HR / vendor "
        "tables — the numbers to quote when quantifying exposure.  "
        "Empty-return scenarios omitted.")
    out.append("")
    for sid, n in sorted(state.nodes.items()):
        rows = []
        for r in (n.impact_results or []):
            if not isinstance(r, dict):
                continue
            if r.get("error") or (r.get("record_count", 0) or 0) <= 0:
                continue
            rows.append(r)
        if not rows:
            continue
        have = True
        out.append(f"### {sid}")
        out.append("")
        out.append("| Severity | Scenario | Headline | Records |")
        out.append("| --- | --- | --- | --- |")
        for r in rows:
            out.append(
                f"| {_esc(r.get('severity_label', '?'))} | "
                f"{_esc(r.get('icon', ''))} "
                f"{_esc(r.get('scenario', '?'))} | "
                f"{_esc(r.get('headline', ''))} | "
                f"{r.get('record_count', 0):,} |")
        out.append("")
    return out if have else []


def _secstore_section(state: SAPMAPState) -> list:
    """ABAP + Java SecStore extraction results across the landscape."""
    abap_rows, java_rows = [], []
    for sid, n in sorted(state.nodes.items()):
        for e in (n.secstore_entries or []):
            if isinstance(e, dict):
                abap_rows.append((sid, e))
        for e in (n.java_secstore_entries or []):
            if isinstance(e, dict):
                java_rows.append((sid, e))
    if not abap_rows and not java_rows:
        return []
    out = ["## Secure-Store recovery", ""]
    out.append(
        "Passwords cached inside SAP secure stores that SAPMAP was "
        "able to decrypt.  Each entry is a credential the operator "
        "can log in with (or a downstream system whose password we "
        "now hold).  Plaintext values live in `loot/secstore/`.")
    out.append("")
    if abap_rows:
        out.append(f"### ABAP SecStore (RSECTAB) — {len(abap_rows)} entries")
        out.append("")
        out.append("| SID | Ident | Category | Status |")
        out.append("| --- | --- | --- | --- |")
        for sid, e in abap_rows:
            status = ("**plaintext**" if e.get("password") else "no pw")
            out.append(
                f"| {sid} | `{_esc(e.get('ident', '?'))}` | "
                f"{_esc(e.get('category', '?'))} | {status} |")
        out.append("")
    if java_rows:
        out.append(f"### Java SecStoreFS — {len(java_rows)} entries")
        out.append("")
        out.append("| SID | Name | Kind | Downstream SID | Status |")
        out.append("| --- | --- | --- | --- | --- |")
        for sid, e in java_rows:
            status = ("**plaintext**" if e.get("value") else "no val")
            if e.get("is_downstream"):
                status += " (↓ downstream)"
            out.append(
                f"| {sid} | `{_esc(e.get('name', '?'))}` | "
                f"{_esc(e.get('kind', ''))} | "
                f"{_esc(e.get('target_sid', '') or '—')} | "
                f"{status} |")
        out.append("")
    return out


def _dbcon_section(state: SAPMAPState) -> list:
    """DBCON direct-DB pivot results (issue #21)."""
    edges = []
    for sid, n in sorted(state.nodes.items()):
        for e in (n.dbcon_edges or []):
            edges.append((sid, e))
    if not edges:
        return []
    out = ["## DBCON direct-DB pivot", ""]
    out.append(
        "External DB connections defined on the source ABAP whose "
        "passwords SAPMAP recovered from RSECTAB.  When the target "
        "is SAP-shape (USR02 present), SAPMAP can plant SAPMAP00 "
        "via direct SQL — no RFC hop, no SAPXPG on the target.  "
        "Non-SAP targets get a data-extraction path (SYS.M_TABLES "
        "enumeration, targeted SELECT dumps).")
    out.append("")
    out.append("| Source | DBCON | DBMS | Host:Port | User | "
                "SAP-shape? | Target SID | Pwned | USR02 loot |")
    out.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for sid, e in edges:
        shape = ("✅" if e.is_sap_shape
                  else ("⚠ inconclusive" if e.sap_shape_reason == "no_permission"
                        else ("❌" if e.tested else "?")))
        pwned = "⚡ **YES**" if e.pwned else ("—" if e.tested else "?")
        loot = f"`{e.usr02_hashes_loot_path}`" if e.usr02_hashes_loot_path else "—"
        out.append(
            f"| {sid} | `{_esc(e.con_name)}` | {_esc(e.dbms)} | "
            f"`{_esc(e.host)}:{e.port}` | `{_esc(e.user)}` | "
            f"{shape} | {_esc(e.target_sid or '—')} | {pwned} | "
            f"{loot} |")
    out.append("")
    # Materialise-target callout
    materialised = [n for n in state.nodes.values()
                    if getattr(n, "discovered_via_dbcon", False)]
    if materialised:
        out.append(f"### DBCON-materialised SAP nodes ({len(materialised)})")
        out.append("")
        out.append("SAP systems added to the map because a DBCON "
                    "pivot uncovered them:")
        out.append("")
        for n in sorted(materialised, key=lambda x: x.sid):
            out.append(
                f"- **{n.sid}** @ `{_esc(n.ip or n.hostname)}` — "
                f"discovered via `{_esc(n.dbcon_parent_sid)}` / "
                f"DBCON `{_esc(n.dbcon_parent_con_name)}`")
        out.append("")
    return out


def _tms_section(state: SAPMAPState) -> list:
    """CTS/TMS pivot results (Bundle 1)."""
    dests = []
    for sid, n in sorted(state.nodes.items()):
        for d in (getattr(n, "tms_destinations", None) or []):
            dests.append((sid, d))
    if not dests:
        return []
    out = ["## CTS/TMS pivot", ""]
    out.append(
        "Cross-system transport-management RFC destinations "
        "(`TMSADM@<SID>.DOMAIN_<X>`) whose passwords SAPMAP recovered "
        "from RSECTAB.  Each row is a system in the transport "
        "domain that SAPMAP can reach as TMSADM — cross-system "
        "transport rights.  The domain controller (marked "
        "**CTRL**) additionally owns the full TMS configuration.")
    out.append("")
    out.append("| Source | Target | Domain | Host | Logon | "
                "TMSADM roles | SAP_ALL | Buffer | Controller |")
    out.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for sid, d in dests:
        logon = ("✅" if d.logon_ok
                  else ("❌" if d.tested else "?"))
        sap_all = "⚡ **YES**" if d.tmsadm_has_sap_all else "—"
        ctrl = "🎯 **CTRL**" if d.is_controller else "—"
        roles = ", ".join(d.tmsadm_roles[:3]) if d.tmsadm_roles else "—"
        buf = d.buffer_count if d.buffer_count > 0 else "—"
        out.append(
            f"| {sid} | `TMSADM@{_esc(d.target_sid)}` | "
            f"`{_esc(d.domain)}` | `{_esc(d.target_host)}` | "
            f"{logon} | {_esc(roles)} | {sap_all} | {buf} | {ctrl} |")
    out.append("")
    materialised = [n for n in state.nodes.values()
                    if getattr(n, "discovered_via_tms", False)]
    if materialised:
        out.append(f"### TMS-materialised SAP nodes ({len(materialised)})")
        out.append("")
        for n in sorted(materialised, key=lambda x: x.sid):
            ctrl = " — **DOMAIN CONTROLLER**" if n.is_tms_controller else ""
            out.append(
                f"- **{n.sid}** @ `{_esc(n.ip or n.hostname)}` "
                f"(domain `{_esc(n.tms_domain)}`) — discovered via "
                f"`{_esc(n.tms_parent_sid)}`{ctrl}")
        out.append("")
    return out


def _created_users_section(state: SAPMAPState) -> list:
    """Every SAPMAP-created account across the landscape."""
    users = list(getattr(state, "created_users", []) or [])
    if not users:
        return []
    out = ["## SAPMAP-created accounts", ""]
    out.append(
        "Every account SAPMAP created during this engagement.  Use "
        '"Cleanup All Users" in the GUI or delete manually before '
        "handover.  Passwords redacted here; plaintext lives in the "
        "session `.sapmap` file.")
    out.append("")
    out.append("| SID | User | Client | Host | Inst | Method | Created |")
    out.append("| --- | --- | --- | --- | --- | --- | --- |")
    for u in sorted(users, key=lambda x: (x.sid, x.client, x.username)):
        out.append(
            f"| {u.sid} | `{_esc(u.username)}` | {u.client} | "
            f"`{_esc(u.hostname or u.ip or '?')}` | {u.instance_nr or '?'} | "
            f"{_esc(u.method)} | {(u.created_at or '')[:19]} |")
    out.append("")
    return out


def _persistence_section(state: SAPMAPState) -> list:
    """Forged tickets + dpmon SAP* + injected RFC destinations."""
    tickets = list(getattr(state, "forged_tickets", []) or [])
    created_dests = list(getattr(state, "created_destinations", []) or [])
    dpmon_sids = [n.sid for n in state.nodes.values()
                  if getattr(n, "dpmon_sap_star_used", False)]
    if not (tickets or created_dests or dpmon_sids):
        return []
    out = ["## Persistence footprint", ""]
    out.append(
        "Artifacts SAPMAP planted that outlive the current shell — "
        "forged MYSAPSSO2 tickets, dpmon SAP* activations, and RFC "
        "destinations injected into remote systems.  Every entry "
        "here needs an explicit cleanup step at handover.")
    out.append("")
    if dpmon_sids:
        out.append(f"### Virtual SAP* activated ({len(dpmon_sids)})")
        out.append("")
        out.append(
            "Kernel ≥ 790 dpmon primitive (SAP Note 3303172) — a one-time "
            f"password was issued for a virtual SAP* logon on: "
            f"**{_esc(', '.join(dpmon_sids))}**.")
        out.append("")
    if tickets:
        out.append(f"### Forged MYSAPSSO2 tickets ({len(tickets)})")
        out.append("")
        out.append("| Issuer | User | Client | Size | TTL | Replays | Forged at |")
        out.append("| --- | --- | --- | --- | --- | --- | --- |")
        for t in tickets:
            used = len(getattr(t, "used_on", []) or [])
            out.append(
                f"| {_esc(getattr(t, 'sid', '?'))} | "
                f"`{_esc(getattr(t, 'user', '?'))}` | "
                f"{_esc(getattr(t, 'client', '?'))} | "
                f"{getattr(t, 'ticket_size', 0)} B | "
                f"{getattr(t, 'validity_min', 0)} min | "
                f"{used} | "
                f"{(getattr(t, 'forged_at', '') or '')[:19]} |")
        out.append("")
    if created_dests:
        out.append(f"### Injected RFC destinations ({len(created_dests)})")
        out.append("")
        out.append("| Dest | Source SID | Target SID | Type | Created |")
        out.append("| --- | --- | --- | --- | --- |")
        for d in created_dests:
            if not isinstance(d, dict):
                continue
            out.append(
                f"| `{_esc(d.get('dest_name', '?'))}` | "
                f"{_esc(d.get('source_sid', '?'))} | "
                f"{_esc(d.get('target_sid', '?'))} | "
                f"{_esc(d.get('type', '?'))} | "
                f"{(d.get('created_at', '') or '')[:19]} |")
        out.append("")
    return out


def _evasion_section(state: SAPMAPState) -> list:
    """OPSEC posture — what evasion primitives were armed."""
    ev = getattr(state, "evasion", {}) or {}
    armed = bool(ev.get("allow_evasion"))
    diag = ev.get("diag_terminal_name") or ""
    channel = ev.get("os_exec_channel") or ""
    sso_users = ev.get("mysapsso2_users") or ""
    baseline_at = ev.get("baseline_captured_at") or ""
    if not (armed or diag or channel or sso_users or baseline_at):
        return []
    out = ["## OPSEC posture (evasion)", ""]
    out.append(
        "Evasion primitives armed for this engagement.  Attribution "
        "record — matters for blue-team debrief and red-team "
        "attribution honesty.")
    out.append("")
    rows = [("Tier 3 armed", "**YES**" if armed else "no")]
    if diag:
        rows.append(("DIAG terminal spoof", f"`{_esc(diag)}`"))
    if channel:
        rows.append(("Forced OS-exec channel", f"`{_esc(channel)}`"))
    if sso_users:
        rows.append(("MYSAPSSO2 fanout identities", f"`{_esc(sso_users)}`"))
    if baseline_at:
        rows.append(("Baseline captured", baseline_at[:19]))
    out.extend(_stat_table(rows))
    out.append("")
    return out


def _derive_landscape_recommendations(state: SAPMAPState) -> list:
    """Inspect the whole landscape state and produce structural
    remediation guidance — independent of whether individual findings
    happened to carry a remediation field.

    Returns a list of dicts: {category, scope, title, body, refs}.
    Each entry is a single concrete action for one or more SIDs.
    """
    nodes = list(state.nodes.values())
    sccs = list((getattr(state, "scc_nodes", {}) or {}).values())
    items = []

    # 1. Gateway ACL — applies to every node where gw_vulnerable=True
    gw_sids = sorted(n.sid for n in nodes if getattr(n, "gw_vulnerable", False))
    if gw_sids:
        items.append({
            "category": "Gateway hardening",
            "scope": ", ".join(gw_sids),
            "title": "Tighten SAP Gateway reginfo / secinfo ACLs",
            "body": (
                "Every listed system accepted unauthenticated SAPXPG "
                "registrations, allowing arbitrary OS command execution "
                "(10KBLAZE / CVE-2019-0344 family).  Edit the gateway "
                "ACL files (gw/reg_info, gw/sec_info) to enforce "
                "explicit allow-lists for both REGISTERED and started "
                "external programs, set gw/sim_mode = 0 and "
                "gw/acl_mode = 1, then restart the dispatcher.  Verify "
                "with `gwmon` that PROGRAM=sapxpg is rejected from any "
                "host that is not explicitly trusted."
            ),
            "refs": "SAP Note 1408081, 1444282, 1425765",
        })

    # 2. Message-server ACL — CVE-2020-6207 / 10KBLAZE betrusted prereq
    ms_sids = sorted(n.sid for n in nodes
                       if getattr(n, "ms_vulnerable", False))
    if ms_sids:
        items.append({
            "category": "Message Server hardening",
            "scope": ", ".join(ms_sids),
            "title": "Restrict Message Server internal port (39NN) to ACL",
            "body": (
                "These systems exposed the MS internal port (39NN) "
                "without an effective ACL, enabling 10KBLAZE betrusted "
                "(CVE-2020-6207).  Set ms/monitor = 0 only after "
                "creating ms/acl_info with an explicit HOST= allow-list "
                "for the application servers, and firewall the internal "
                "port off the management network.  39NN must NEVER be "
                "reachable from clients."
            ),
            "refs": "SAP Note 2841053, 2922964",
        })

    # 3. CVE-2025-31324 — VisualComposer JSP webshell
    vc_sids = sorted(n.sid for n in nodes
                       if getattr(n, "cve_2025_31324_vulnerable", False))
    if vc_sids:
        items.append({
            "category": "Java patching",
            "scope": ", ".join(vc_sids),
            "title": "Patch CVE-2025-31324 (VisualComposer metadatauploader)",
            "body": (
                "Authentication bypass in the VC metadatauploader servlet "
                "allows arbitrary JSP upload and unauthenticated RCE.  "
                "Apply the SAP Note for your kernel level immediately and "
                "audit /irj/ for any leftover JSP webshells (SAPMAP "
                "drops JSPs prefixed with 4-letter random names — search "
                "for files modified after the engagement window).  Until "
                "patched, take the affected /developmentserver/ context "
                "offline."
            ),
            "refs": "SAP Note 3594142",
        })

    # 3b. CVE-2022-22536 (ICMAD)
    icmad_live = sorted(n.sid for n in nodes
                          if getattr(n, "cve_2022_22536_vulnerable", False))
    icmad_patch = sorted(n.sid for n in nodes
                           if (getattr(n, "cve_2022_22536_checked", False)
                                and not getattr(n,
                                                  "cve_2022_22536_vulnerable",
                                                  False)
                                and any(getattr(f, "name", "").startswith(
                                    "CVE-2022-22536")
                                          for f in (n.findings or []))))
    icmad_bypassed_paths = {}
    icmad_heap_pwned = []
    for n in nodes:
        bypass_map = getattr(n, "cve_2022_22536_acl_bypass", None) or {}
        for path, info in bypass_map.items():
            if (info or {}).get("via") == "smuggle":
                icmad_bypassed_paths.setdefault(n.sid, []).append(path)
        if any(getattr(f, "name", "").endswith(
                  "HPROF heap dump captured")
                 for f in (n.findings or [])):
            icmad_heap_pwned.append(n.sid)

    if icmad_live or icmad_patch or icmad_bypassed_paths or icmad_heap_pwned:
        scope_parts = []
        if icmad_live:
            scope_parts.append("live: " + ", ".join(icmad_live))
        if icmad_patch:
            scope_parts.append("patch-only: " + ", ".join(icmad_patch))
        body = (
            "SAP Note 3123396 (CVE-2022-22536, CVSS 10.0) — HTTP "
            "request smuggling / concatenation in the ICM and Web "
            "Dispatcher.  An unauthenticated attacker can prepend "
            "arbitrary inner-request bytes onto a victim's HTTP "
            "request, bypassing wdisp/permission_table to reach "
            "administrative paths the gateway is supposed to block "
            "(/heapdump/, /CTC/ConfigServlet, /sld/, etc.)."
        )
        if icmad_live:
            body += (f"\n\nLive smuggle confirmed on: "
                      f"{', '.join(icmad_live)}.")
        if icmad_patch:
            body += (f"\n\nKernel patch hygiene only (no live signature "
                      f"observed — likely the deprecated workaround "
                      f"wdisp/additional_conn_close=1 is active): "
                      f"{', '.join(icmad_patch)}.")
        if icmad_bypassed_paths:
            body += "\n\nACL bypass confirmed on the following paths:"
            for sid, paths in sorted(icmad_bypassed_paths.items()):
                body += (f"\n  • {sid}: "
                          f"{', '.join(sorted(paths))}")
        elif icmad_live:
            # Smuggle confirmed but no path bypassed.  Make sure the
            # engagement report doesn't oversell the chain — be
            # explicit about why the on-the-wire bug doesn't
            # automatically chain to admin access in this topology.
            body += (
                "\n\nNote on directly demonstrable impact: the ACL "
                "bypass sweep tested 12 hand-picked admin paths and "
                "did NOT observe any status promotion (4XX/5XX → 2XX) "
                "on this deployment.  That outcome is consistent with "
                "a topology where this Web Dispatcher is the front-"
                "end (no upstream trusted proxy whose mTLS / SAP-"
                "trusted-reverse-proxy attestations the smuggle could "
                "inherit) AND the backend AS Java instances have "
                "reasonable trust configs (they do NOT auto-trust "
                "X-Forwarded-For: 127.0.0.1 headers from non-trusted-"
                "proxy sources — which is the SAPGateBreaker / "
                "exploit-db 52109 bypass primitive).\n\n"
                "This does NOT downgrade the finding.  SAP's CVSS "
                "10.0 rating and CISA KEV listing both attach to the "
                "wire-level bug itself, not to a specific chain.  "
                "Documented chains (per SAP Note 3123396) that "
                "remain reachable on this kernel without re-running "
                "the probe:\n"
                "  (a) Trust-spoof via future upstream gateway — if "
                "an F5 / nginx / another WD is added in front later, "
                "the smuggle immediately reaches admin paths gated "
                "by icm/trusted_reverse_proxy_*.\n"
                "  (b) Cache poisoning — if wdisp/cache_enabled is "
                "ever flipped on for cache performance, the smuggle "
                "can inject responses served to other clients.\n"
                "  (c) Session hijack — under concurrent legitimate "
                "user load, smuggled bytes prepend onto the next "
                "user's request, hijacking their session.  Race-"
                "conditional and not demonstrated here.")
        if icmad_heap_pwned:
            body += (f"\n\nHPROF heap dump captured on: "
                      f"{', '.join(icmad_heap_pwned)}.  These dumps "
                      f"contain SecStoreFS keyphrase bytes and JCo "
                      f"destination passwords in cleartext — "
                      f"engagement-day pwn.")
        body += (
            "\n\nApply the version-specific patch level listed in SAP "
            "Note 3123396 to BOTH SAP Kernel and SAP Web Dispatcher "
            "(7.22 ≥ PL1101, 7.49 ≥ PL1036, 7.53 ≥ PL915, 7.77 ≥ "
            "PL429, 7.81 ≥ PL227, 7.85 ≥ PL69, 7.86 ≥ PL15, 7.87 ≥ "
            "PL4, 8.04 ≥ PL207).  The workaround "
            "wdisp/additional_conn_close=1 (SAP Note 3138881) is "
            "deprecated per Note 3200257 and known to break AS Java "
            "backends per Note 3147927 — patching is the only "
            "durable fix."
        )
        items.append({
            "category": "Web Dispatcher / ICM patching",
            "scope": "; ".join(scope_parts) or "as listed",
            "title": ("Patch CVE-2022-22536 (ICMAD HTTP request "
                       "smuggling) on every Web Dispatcher and ICM"),
            "body": body,
            "refs": ("SAP Note 3123396 (patch table), 3138881 "
                      "(deprecated workaround), 3147927 (workaround "
                      "AS Java side-effects), 3200257 (workaround "
                      "deprecation)"),
        })

    # 4. SAProuter ACL
    routers = [n for n in nodes
               if (n.system_type or "").upper() == "SAPROUTER"]
    saprouter_info_leak = any(getattr(n, "saprouter_info", None) for n in routers)
    if routers:
        items.append({
            "category": "SAProuter hardening",
            "scope": ", ".join(sorted(n.sid for n in routers)),
            "title": "Apply restrictive saprouttab + disable info leak",
            "body": (
                "SAProuter answered ROUTER_ADM info requests"
                + (" (info leak confirmed during the engagement — "
                   "internal client list and routtab were extracted)"
                   if saprouter_info_leak else "")
                + ".  Edit `saprouttab` to allow only specific "
                "(source, target, port) tuples — never wildcard `*` for "
                "any field on production routers.  Run with `-K /path/"
                "to/SNCenv` to require SNC peer auth.  Add `-X 1` to "
                "block ROUTER_ADM info requests from unauthenticated "
                "callers.  Block port 3299 on the perimeter firewall to "
                "anyone outside the SAP support net."
            ),
            "refs": "SAP Note 1895350, 1853140",
        })

    # 5. Default credentials still live
    default_cred_sids = []
    for n in nodes:
        for c in (n.credentials or []):
            if (c.username or "").upper() in (
                "DDIC", "SAP*", "SAPCPIC", "EARLYWATCH", "TMSADM",
                "SAPSERVICE",
            ) and c.verified:
                default_cred_sids.append(n.sid)
                break
    if default_cred_sids:
        items.append({
            "category": "Default credentials",
            "scope": ", ".join(sorted(set(default_cred_sids))),
            "title": "Rotate every default account password and lock unused ones",
            "body": (
                "SAPMAP successfully logged on with one or more SAP "
                "default credentials (DDIC / SAP* / TMSADM / "
                "EARLYWATCH / SAPCPIC / SAPSERVICE).  Set strong unique "
                "passwords on every client (000, 001, custom), set "
                "USTYP=B for batch-only accounts, and lock SAP* via "
                "login/no_automatic_user_sapstar = 1.  Audit USR02 with "
                "RSUSR003 monthly."
            ),
            "refs": "SAP Note 622464, 1414256",
        })

    # 6. RFC SecStore exposure
    secstore_present = sum(len(n.secstore_entries or []) for n in nodes)
    java_secstore_present = sum(len(n.java_secstore_entries or [])
                                  for n in nodes)
    if secstore_present or java_secstore_present:
        items.append({
            "category": "Secure Store rotation",
            "scope": "all systems with extracted SecStore data",
            "title": "Rotate every credential exposed in the Secure Store dumps",
            "body": (
                f"SAPMAP decrypted {secstore_present} ABAP RSECTAB "
                f"entries and {java_secstore_present} Java SecStoreFS "
                "entries.  Each entry typically holds a service / "
                "RFC / DBCON / SMTP password used by automated jobs.  "
                "Rotate ALL of them: download the loot/secstore/ JSON "
                "files, identify each destination's owning user, and "
                "change the password through the destination's normal "
                "channel (SM59 for RFC, ConfigTool for Java JCo, "
                "DBA Cockpit for DBCON).  Then rekey RSECTAB with "
                "`rsecssfx changekey` (ABAP) or ConfigTool > Cluster-"
                "data > Secure Storage > Change Key (Java)."
            ),
            "refs": "SAP Note 2293011, 3153525",
        })

    # 7. SCC default credentials
    scc_default_live = [s for s in sccs
                          if getattr(s, "default_creds_live", False)]
    if scc_default_live:
        items.append({
            "category": "SAP Cloud Connector",
            "scope": ", ".join(getattr(s, "host", "?") for s in scc_default_live),
            "title": "Rotate Cloud Connector Administrator/manage credential",
            "body": (
                "SAPMAP authenticated to the Cloud Connector admin REST "
                "API with the factory default 'Administrator/manage'.  "
                "An attacker with this access reads every cloud-to-on-"
                "premise mapping, dumps the system keystore (every "
                "principal-propagation private key), and can pivot into "
                "the on-premise backends through the SCC tunnel.  Set a "
                "strong unique password and enable LDAP / SAML SSO if "
                "available."
            ),
            "refs": "SAP Note 2696233 (general SCC hardening guide)",
        })

    # 8. Production systems pwned — biggest fish, always surface
    prd_pwned = [n for n in nodes if n.is_production and n.pwned]
    if prd_pwned:
        items.append({
            "category": "Incident response",
            "scope": ", ".join(sorted(n.sid for n in prd_pwned)),
            "title": "Treat these production systems as compromised",
            "body": (
                "SAPMAP gained interactive access to production "
                "system(s) listed above.  Engage incident response: "
                "review SAL audit logs (transaction RSAU_READ_LOG) for "
                "any activity outside the engagement window, force a "
                "password reset on every dialog user, rotate every "
                "RFC destination password, audit USR02 last-login "
                "timestamps for anomalies, and rebuild any host where "
                "OS-level command execution was demonstrated."
            ),
            "refs": "SAP Note 2191612 (SAL hardening)",
        })

    # 9. Untested RFC trust edges that point AT production
    prd_sids = {n.sid for n in nodes if n.is_production}
    untested_into_prd = [c for c in (state.connections or [])
                          if c.target_sid in prd_sids
                          and not c.tested]
    if untested_into_prd:
        items.append({
            "category": "RFC trust review",
            "scope": ", ".join(sorted({c.source_sid + " -> " + c.target_sid
                                       for c in untested_into_prd})),
            "title": "Review RFC destinations pointing at production",
            "body": (
                f"{len(untested_into_prd)} RFC destination(s) "
                "configured on non-production systems target production "
                "as their endpoint.  These are LATERAL-MOVEMENT paths: "
                "anyone who pwns a non-prod system inherits the "
                "destination's stored credentials and can connect to "
                "prod with them.  Audit each destination's stored user "
                "via SM59 -> Logon & Security -> remove any with "
                "stored passwords, switch to trusted-system + ticketed "
                "logon, or — if you can't avoid stored creds — at "
                "least ensure the user is a tightly-scoped service "
                "user, never SAP_ALL."
            ),
            "refs": "SAP Note 128447, 2008727",
        })

    # 9b. SCC Principal-Propagation weak rules.  Surfaced when the PP
    # analyser found at least one CRITICAL/HIGH finding on any SCC —
    # weak <subjectPatterns> let any cloud user impersonate any
    # on-prem ABAP user under LOCAL PP mode.  See
    # docs/research/09_principal_propagation_schema.md.
    pp_weak_sccs = []
    for s in sccs:
        ppa = getattr(s, "pp_analysis", None) or {}
        summary = ppa.get("summary") or {}
        if (summary.get("critical", 0) + summary.get("high", 0)) > 0:
            pp_weak_sccs.append(s)
    if pp_weak_sccs:
        # Build a short bullet of each affected SCC's worst finding so
        # the report explains what the operator is fixing.
        bullets = []
        for s in pp_weak_sccs:
            ppa = getattr(s, "pp_analysis", {}) or {}
            findings = (ppa.get("findings") or [])
            critical = [f for f in findings if f.get("severity") == "CRITICAL"]
            high = [f for f in findings if f.get("severity") == "HIGH"]
            top = (critical or high)[:1]
            if not top:
                continue
            t = top[0]
            bullets.append(
                f"  • {getattr(s, 'host', '?')}: "
                f"{t.get('headline','?')} (ref: {t.get('ref','?')})")
        bullet_text = "\n".join(bullets)
        items.append({
            "category": "SAP Cloud Connector — Principal Propagation",
            "scope": ", ".join(getattr(s, "host", "?") for s in pp_weak_sccs),
            "title": "Tighten <subjectPatterns> in scc_config.ini",
            "body": (
                "The principal-propagation analyser flagged "
                f"{len(pp_weak_sccs)} Cloud Connector(s) with weak "
                "user-mapping rules. Under "
                "principalPropagationMode=LOCAL, SCC mints a "
                "forwarded X.509 cert with a Subject CN built from "
                "the cloud caller's identity claim and presents it "
                "to the on-prem ABAP system.  The on-prem system "
                "trusts SCC's PP CA via STRUSTSSO2 and resolves the "
                "CN to an ABAP user via USREXTID.  When the CN "
                "template binds to a caller-controlled placeholder "
                "(${name}, ${email}) without a constraining "
                "<condition>, any cloud user can pick any on-prem "
                "user.\n\n"
                f"Affected:\n{bullet_text}\n\n"
                "Recommendation: bind CN to a stable cloud-side "
                "identifier (e.g. ${user_uuid}); add a <condition> "
                "that scopes the rule to a specific cloud user "
                "group / verified email domain; pair this with a "
                "USREXTID review on the on-prem side so each cloud "
                "user maps to exactly one ABAP user."
            ),
            "refs": (
                "SAP Cloud Connector documentation > Configure "
                "Principal Propagation; "
                "docs/research/09_principal_propagation_schema.md"
            ),
        })

    # 9c. PP impersonation surface — concrete on-prem users a cloud
    # caller can impersonate when (a) a weak SCC PP rule is in place
    # AND (b) USREXTID has matching CN-style entries on the linked
    # ABAP system.  This is the chain that turns a CRITICAL config
    # finding into a one-shot pwn primitive.
    pp_imp_nodes = []
    for n in nodes:
        imp = getattr(n, "pp_impersonation", None) or {}
        if (imp.get("exploitability") in ("trivial", "constrained")
                and (imp.get("matched_users") or [])):
            pp_imp_nodes.append(n)
    if pp_imp_nodes:
        bullets = []
        for n in pp_imp_nodes:
            imp = n.pp_impersonation
            matched = imp.get("matched_users") or []
            privs = imp.get("privileged_users") or []
            priv_names = sorted({p["bname"] for p in privs}) if privs else []
            ver = getattr(n, "pp_verification", None) or {}
            confirmed = bool(getattr(n, "pp_verification_confirmed", False))
            head = (
                f"  • {n.sid} (via SCC {imp.get('scc_host','?')}): "
                f"{len(matched)} ABAP user(s) reachable via PP rule "
                f"{imp.get('rule_template','?')}.")
            if priv_names:
                head += (
                    f"  Privileged accounts: "
                    f"{', '.join(priv_names)}.")
            if confirmed:
                v_user = ver.get("user") or "<unknown user>"
                v_conf = ver.get("confidence") or "MEDIUM"
                head += (
                    f"  **LIVE-VERIFIED on "
                    f"{ver.get('verified_at','?')}**: probe landed "
                    f"as {v_user} (confidence {v_conf}, HTTP "
                    f"{ver.get('http_status','?')}, "
                    f"{ver.get('latency_ms','?')} ms).")
            bullets.append(head)
        items.append({
            "category": "SAP Cloud Connector — Principal Propagation",
            "scope": ", ".join(n.sid for n in pp_imp_nodes),
            "title": (
                ("Cloud→on-prem impersonation CONFIRMED through SCC "
                 "tunnel (live-verified, concrete user list)")
                if any(getattr(n, "pp_verification_confirmed", False)
                       for n in pp_imp_nodes)
                else
                ("Cloud→on-prem impersonation reachable through SCC "
                 "tunnel (concrete user list)")),
            "body": (
                "By combining the weak <subjectPatterns> rule on the "
                "linked SAP Cloud Connector with the on-prem USREXTID "
                "table, a cloud caller authenticated against the bound "
                "BTP subaccount can land on the on-prem ABAP system as "
                "any of the users below — without ever holding a "
                "valid on-prem credential.\n\n"
                f"Affected:\n{chr(10).join(bullets)}\n\n"
                "Recommendation: SAP Note 622464 (USREXTID hardening): "
                "remove generic CN→user mappings; restrict each cloud "
                "user to exactly one ABAP user via a stable "
                "identifier (UUID); pair this with the SCC-side fix "
                "(constrain <subjectPatterns> via <condition>).  "
                "Until both halves are fixed, treat the on-prem ABAP "
                "user list as compromised."
            ),
            "refs": (
                "SAP Note 622464; "
                "SAP Cloud Connector documentation > "
                "Configure Principal Propagation; "
                "docs/research/09_principal_propagation_schema.md"
            ),
        })

    # 10. Cracked SCC password hashes
    scc_pwned = [s for s in sccs
                  if getattr(s, "pwned", False)
                  or getattr(s, "default_creds_live", False)]
    if scc_pwned:
        items.append({
            "category": "SAP Cloud Connector",
            "scope": ", ".join(getattr(s, "host", "?") for s in scc_pwned),
            "title": "Rebuild SCC keystores after credential compromise",
            "body": (
                "Cloud Connectors marked PWNED had at least one "
                "Administrator hash crackable from users.xml — the "
                "operator could mint new admin sessions at any time.  "
                "After rotating the password, regenerate every "
                "subaccount tunnel keystore (scc_config/<region>/<uuid>/"
                "scc.p12) and the principal-propagation CA.  The "
                "previous keys must be considered exposed."
            ),
            "refs": "SAP Cloud Connector documentation > Disaster Recovery",
        })

    # ---------------------------------------------------------------
    # BTP (cloud-side) findings — both directions.  Surfaced when
    # state.btp_subaccounts has anything actionable, regardless of
    # whether on-prem nodes happen to exist on the map.
    # ---------------------------------------------------------------
    btp_subs = list((getattr(state, "btp_subaccounts", {})
                     or {}).values())

    # 11. Cleartext destinations on a BTP subaccount.  Anyone with
    # the same scope on the same subaccount can read these
    # passwords; rotating them is the only reliable mitigation.
    cleartext_subs = []
    cleartext_total = 0
    linked_total = 0
    for sub in btp_subs:
        dests = list(getattr(sub, "destinations", []) or [])
        cleartext_n = sum(1 for d in dests
                          if getattr(d, "cleartext_captured", False)
                          or (isinstance(d, dict)
                              and d.get("cleartext_captured")))
        linked_n = sum(1 for d in dests
                       if (getattr(d, "linked_target_sid", "")
                           or (isinstance(d, dict)
                               and d.get("linked_target_sid"))))
        if cleartext_n:
            cleartext_subs.append(sub)
            cleartext_total += cleartext_n
            linked_total += linked_n
    if cleartext_subs:
        labels = []
        for sub in cleartext_subs:
            labels.append(getattr(sub, "subdomain", "")
                          or getattr(sub, "display_name", "")
                          or getattr(sub, "uuid", "?")[:8])
        items.append({
            "category": "BTP destination service",
            "scope": ", ".join(sorted(set(labels))),
            "title": "Replace stored on-prem credentials in BTP "
                      "destinations with Principal Propagation",
            "body": (
                f"{cleartext_total} BTP destination(s) on "
                f"{len(cleartext_subs)} subaccount(s) hold cleartext "
                f"on-prem credentials retrievable by anyone with the "
                f"`destination_configuration.ApiAccess` scope (a "
                f"per-subaccount admin-equivalent claim).  "
                f"{linked_total} of those linked to a SAPMAP-known "
                f"on-prem SAPNode.  Migrate every Basic / "
                f"OAuth2Password destination to Principal "
                f"Propagation (X.509 mTLS to the Cloud Connector) "
                f"or OAuth2SAMLBearerAssertion against IAS so the "
                f"on-prem credential never leaves the on-prem "
                f"system.  Audit and minimise the BTP users with "
                f"the ApiAccess scope; this scope reads every "
                f"destination password in cleartext.  Rotate every "
                f"on-prem password that was leaked, then audit "
                f"USR02 last-login history for activity outside "
                f"the engagement window."
            ),
            "refs": ("SAP Help Portal — Configure Principal "
                      "Propagation; SAP Note 3021915"),
        })

    # 12. Service-key tokens / OAuth profiles on-prem that mint
    # BTP tokens.  Captured /OA2C/CS_<UUID>_NN secstore secrets are
    # equivalent to long-lived BTP service-key passwords — they
    # mint tokens at XSUAA without any extra checks.
    oauth_profile_sids = []
    for n in nodes:
        ent = list(getattr(n, "oauth2_profiles", []) or [])
        if not ent:
            # also count secstore_entries categorised as oauth2_client
            ent = [e for e in (n.secstore_entries or [])
                    if isinstance(e, dict)
                    and e.get("category") == "oauth2_client"]
        if ent:
            oauth_profile_sids.append(n.sid)
    if oauth_profile_sids:
        items.append({
            "category": "OA2C OAuth client config",
            "scope": ", ".join(sorted(oauth_profile_sids)),
            "title": "Treat OA2C client_secret leaks as BTP "
                      "service-key compromise",
            "body": (
                "These ABAP systems hold OAuth 2.0 Client config "
                "(transaction OA2C_CONFIG, table OA2C_CLIENT) "
                "whose client_secret was recoverable from RSECTAB "
                "(`/OA2C/CS_<UUID>_NN` rows).  Each "
                "(client_id, client_secret) pair is a long-lived "
                "credential that mints BTP access tokens at XSUAA "
                "with whatever scopes the destination service-key "
                "carries — typically destination read across the "
                "bound subaccount.  After rotating the on-prem "
                "credential and the SecStore key, also rotate the "
                "BTP-side service-key (`cf delete-service-key` + "
                "`cf create-service-key`) so the leaked secret "
                "stops working entirely.  Restrict S_TABU_DIS / "
                "S_RFC for OA2C_CLIENT to a short admin allow-list."
            ),
            "refs": ("SAP Note 3021915; BTP Destination Service "
                      "Security Guide"),
        })

    # 13. SCC ↔ BTP tunnel review — when an SCC links to a
    # subaccount that we proved had cleartext credentials, the
    # tunnel itself doubles as the lateral path.  Surface it.
    scc_btp_pairs = []
    for s in sccs:
        for u in (getattr(s, "subaccount_uuids", []) or []):
            for sub in btp_subs:
                if (getattr(sub, "uuid", "") == u
                        and getattr(sub, "pwned", False)):
                    scc_btp_pairs.append(
                        (getattr(s, "host", "?"),
                         getattr(sub, "subdomain", "")
                         or u[:8]))
    if scc_btp_pairs:
        scope = ", ".join(sorted({f"{h} ↔ {sd}"
                                    for h, sd in scc_btp_pairs}))
        items.append({
            "category": "SCC × BTP integration",
            "scope": scope,
            "title": "Review SCC location IDs and tighten "
                      "subaccount tunnel ACLs",
            "body": (
                "These Cloud Connectors tunnel into BTP "
                "subaccounts that had cleartext destination "
                "credentials.  An attacker who controls the SCC "
                "host can read every System Mapping (cloud → "
                "on-prem rule) and replay the tunnel-side "
                "credential into any of those backends.  Restrict "
                "SCC location IDs (one per subaccount with strict "
                "ACL), enforce mTLS principal propagation on every "
                "mapping, and disable any host:port mapping that "
                "doesn't have an explicit downstream-system check."
            ),
            "refs": ("SAP Cloud Connector — Subaccount Setup; "
                      "Hardening Guide"),
        })

    return items


def _recommendations_section(state: SAPMAPState) -> list:
    """Recommendations section — combines per-finding remediation text
    with the structural landscape recommendations derived from the
    state itself (so the section is comprehensive even when
    individual findings don't carry full remediation prose)."""
    out = ["## Recommendations", ""]

    derived = _derive_landscape_recommendations(state)

    # Per-finding bullets, deduped by remediation text
    seen = set()
    finding_bullets = []
    for n in state.nodes.values():
        for f in n.findings or []:
            r = (f.remediation or "").strip()
            if not r or r in seen:
                continue
            seen.add(r)
            finding_bullets.append(f"- **{n.sid}** — {_esc(r)}")

    if derived:
        out.append("### Landscape-wide structural remediations")
        out.append("")
        for i, r in enumerate(derived, 1):
            out.append(f"#### {i}. {r['title']}")
            out.append("")
            out.append(f"**Applies to:** {_esc(r['scope'])}  ")
            out.append(f"**Category:** {_esc(r['category'])}  ")
            out.append(f"**References:** {_esc(r['refs'])}")
            out.append("")
            out.append(_esc(r["body"]))
            out.append("")

    if finding_bullets:
        out.append("### Per-finding remediation")
        out.append("")
        out.extend(finding_bullets)
        out.append("")

    if not derived and not finding_bullets:
        out.append("_No remediation guidance applicable — landscape is "
                   "either empty or fully patched._")
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
    attack_section = _attack_coverage_section(state)
    if attack_section:
        sections.append("---")
        sections.append("")
        sections.extend(attack_section)
    sections.append("---")
    sections.append("")
    sections.extend(_trust_chains_section(state))
    sections.append("---")
    sections.append("")
    sections.extend(_per_system_table(state))
    sections.append("---")
    sections.append("")
    sections.extend(_credentials_section(state))
    cap_section = _capability_section(state)
    if cap_section:
        sections.append("---")
        sections.append("")
        sections.extend(cap_section)
    scc_section = _scc_section(state)
    if scc_section:
        sections.append("---")
        sections.append("")
        sections.extend(scc_section)
    btp_section = _btp_section(state)
    if btp_section:
        sections.append("---")
        sections.append("")
        sections.extend(btp_section)
    cloud_lat_section = _cloud_lateral_section(state)
    if cloud_lat_section:
        sections.append("---")
        sections.append("")
        sections.extend(cloud_lat_section)
    cert_dest_section = _cert_auth_destinations_section(state)
    if cert_dest_section:
        sections.append("---")
        sections.append("")
        sections.extend(cert_dest_section)
    for extra in (_impact_section(state),
                  _secstore_section(state),
                  _dbcon_section(state),
                  _tms_section(state),
                  _created_users_section(state),
                  _persistence_section(state),
                  _evasion_section(state)):
        if extra:
            sections.append("---")
            sections.append("")
            sections.extend(extra)
    # Hardening checklist supersedes the older _recommendations_section
    # — same author voice but driven by the central remediation catalog
    # (modules.core.sapmap_remediation) so the prose in this section and
    # the per-finding blocks above can never drift apart.  Falls back to
    # the legacy section when the catalog returns nothing (no structured
    # remediation on any finding — older .sapmap state files).
    hardening_section = _hardening_checklist_section(state)
    if hardening_section:
        sections.append("---")
        sections.append("")
        sections.extend(hardening_section)
    else:
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
    style = f' style="border-left:4px solid {color}"' if color else ""
    sub_html = (f'<div class="kpi-s">{_hesc(sub)}</div>'
                 if sub else "")
    return (
        f'<div class="kpi"{style}>'
        f'<div class="kpi-v">{_hesc(value)}</div>'
        f'<div class="kpi-l">{_hesc(label)}</div>'
        f'{sub_html}'
        f'</div>'
    )


def _build_landscape_svg(state: SAPMAPState) -> str:
    """Render an inline SVG snapshot of the landscape for the HTML report.

    Self-contained — no external resources, no JS.  Layouts:
      * Auto grid sized so every node fits without overlap.
      * SAP nodes drawn as rounded rectangles, colour-coded:
            ABAP   = blue,  Java = green,  Both = purple,
            HANA DB= red,   SAProuter = grey,  unknown = stone.
      * Cloud Connector nodes drawn as hexagons (matches map style).
      * Pwned nodes get an orange ⚡ overlay; production nodes a red
        outer halo.
      * RFC connections drawn as arrows; SAP_ALL edges in red, normal
        in grey.  The line is dashed when the destination logon is
        untested.
      * SVG is responsive (viewBox + width:100%) so it always fits
        the page width and scales when the report is printed to PDF.
    """
    sap_nodes = list(state.nodes.values())
    scc_nodes = list((getattr(state, "scc_nodes", {}) or {}).values())
    btp_subs = list(
        (getattr(state, "btp_subaccounts", {}) or {}).values())
    items = [("sap", n) for n in sorted(sap_nodes, key=lambda n: n.sid)]
    items += [("scc", s) for s in sorted(scc_nodes,
                                          key=lambda s: getattr(s, "host", ""))]
    # BTP subaccounts get listed alongside on-prem SAP / SCC; same
    # rounded-rect grid layout, distinct cloud silhouette + sky-blue
    # fill so the cloud tier is unmissable on the engagement map.
    items += [("btp", b) for b in sorted(
        btp_subs, key=lambda b: getattr(b, "uuid", ""))]

    if not items:
        return ('<div class="muted" style="text-align:center;padding:24px">'
                'No systems discovered yet — landscape map is empty.</div>')

    # ------------------------------------------------------------------
    # Auto-grid layout — choose a column count that gives a roughly
    # 16:9 frame for the count we have, so the picture is never too
    # tall or too wide.
    # ------------------------------------------------------------------
    import math
    n = len(items)
    cols = max(1, min(n, int(math.ceil(math.sqrt(n * 1.6)))))
    rows = int(math.ceil(n / cols))
    box_w, box_h = 170, 70
    h_gap, v_gap = 28, 36
    margin = 30
    width = margin * 2 + cols * box_w + (cols - 1) * h_gap
    height = margin * 2 + rows * box_h + (rows - 1) * v_gap

    # SID/host/uuid -> (cx, cy) so we can draw connection lines on top
    pos = {}
    for idx, (kind, node) in enumerate(items):
        col = idx % cols
        row = idx // cols
        cx = margin + col * (box_w + h_gap) + box_w / 2
        cy = margin + row * (box_h + v_gap) + box_h / 2
        if kind == "sap":
            key = node.sid
        elif kind == "scc":
            key = getattr(node, "host", "")
        else:   # btp
            key = getattr(node, "uuid", "")
        pos[(kind, key)] = (cx, cy)

    # ------------------------------------------------------------------
    # Connection layer (drawn FIRST so nodes overlay it)
    # ------------------------------------------------------------------
    # Resolve BTP-sentinel source SIDs ("BTP:<uuid8>") against the
    # btp_subaccounts dict so synthetic BTP -> on-prem edges actually
    # land on the report map (otherwise these chains were invisible
    # even though the chain analyser walked them).
    btp_pos_by_short_uuid: dict = {}
    for b in btp_subs:
        u = getattr(b, "uuid", "") or ""
        if u:
            btp_pos_by_short_uuid[u[:8].lower()] = pos.get(("btp", u))

    def _edge_pos(sid: str):
        if not sid:
            return None
        if sid.startswith("BTP:"):
            return btp_pos_by_short_uuid.get(sid[4:].lower())
        return pos.get(("sap", sid))

    edges_svg = []
    for c in (state.connections or []):
        src = _edge_pos(c.source_sid)
        dst = _edge_pos(c.target_sid)
        if not src or not dst or src == dst:
            continue
        sap_all = bool(getattr(c, "has_sap_all", False))
        tested = bool(getattr(c, "logon_successful", False))
        stroke = "#dc2626" if sap_all else "#94a3b8"
        sw = 2.2 if sap_all else 1.4
        dash = "" if tested else 'stroke-dasharray="5,4"'
        # Slight curve so parallel edges don't perfectly overlap.
        mx = (src[0] + dst[0]) / 2
        my = (src[1] + dst[1]) / 2 - 8
        edges_svg.append(
            f'<path d="M {src[0]:.1f} {src[1]:.1f} Q {mx:.1f} {my:.1f} '
            f'{dst[0]:.1f} {dst[1]:.1f}" stroke="{stroke}" '
            f'stroke-width="{sw}" fill="none" {dash} '
            f'marker-end="url(#arr-{"sapall" if sap_all else "norm"})"/>'
        )

    # ------------------------------------------------------------------
    # Node layer
    # ------------------------------------------------------------------
    def _sap_colour(node):
        t = (node.system_type or "").upper()
        db = (node.db_type or "").upper()
        if t == "SAPROUTER":
            return "#475569", "#1f2937"      # fill, stroke (grey)
        if "ABAP" in t and "JAVA" in t:
            return "#7c3aed", "#5b21b6"      # purple
        if "JAVA" in t:
            return "#15803d", "#166534"      # green
        if "ABAP" in t:
            return "#1d4ed8", "#1e3a8a"      # blue
        if "HANA" in t or db == "HDB":
            return "#b91c1c", "#7f1d1d"      # red
        return "#374151", "#1f2937"

    nodes_svg = []
    for kind, node in items:
        if kind == "sap":
            sid = node.sid
            host_text = node.hostname or node.ip or ""
            type_text = node.system_type or ""
            cx, cy = pos[("sap", sid)]
            fill, stroke = _sap_colour(node)
            x = cx - box_w / 2
            y = cy - box_h / 2
            # Production halo
            if getattr(node, "is_production", False):
                nodes_svg.append(
                    f'<rect x="{x-4:.1f}" y="{y-4:.1f}" '
                    f'width="{box_w+8}" height="{box_h+8}" rx="12" ry="12" '
                    f'fill="none" stroke="#dc2626" stroke-width="2.5"/>'
                )
            # Body
            nodes_svg.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" '
                f'width="{box_w}" height="{box_h}" rx="8" ry="8" '
                f'fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>'
            )
            # SID line
            nodes_svg.append(
                f'<text x="{cx:.1f}" y="{cy-12:.1f}" '
                f'fill="#fff" font-size="18" font-weight="700" '
                f'text-anchor="middle" font-family="-apple-system,Segoe UI,'
                f'Helvetica,Arial,sans-serif">{_hesc(sid)}</text>'
            )
            # Type / host meta
            nodes_svg.append(
                f'<text x="{cx:.1f}" y="{cy+6:.1f}" fill="#cbd5e1" '
                f'font-size="10.5" text-anchor="middle" '
                f'font-family="-apple-system,Segoe UI,Helvetica,Arial,'
                f'sans-serif">{_hesc(type_text)}</text>'
            )
            host_short = host_text if len(host_text) <= 22 else host_text[:21] + "…"
            nodes_svg.append(
                f'<text x="{cx:.1f}" y="{cy+22:.1f}" fill="#94a3b8" '
                f'font-size="10" text-anchor="middle" '
                f'font-family="-apple-system,Segoe UI,Helvetica,Arial,'
                f'sans-serif">{_hesc(host_short)}</text>'
            )
            # Pwned bolt
            if getattr(node, "pwned", False):
                nodes_svg.append(
                    f'<circle cx="{x+box_w-12:.1f}" cy="{y+12:.1f}" '
                    f'r="11" fill="#f59e0b" stroke="#fff" stroke-width="2"/>'
                )
                nodes_svg.append(
                    f'<text x="{x+box_w-12:.1f}" y="{y+16:.1f}" '
                    f'fill="#fff" font-size="13" font-weight="900" '
                    f'text-anchor="middle">⚡</text>'
                )
        elif kind == "scc":   # hexagonal frame
            host = getattr(node, "host", "")
            ver = getattr(node, "version", "") or "?"
            cx, cy = pos[("scc", host)]
            x, y = cx - box_w / 2, cy - box_h / 2
            # Hex points (flat-topped, fits in box_w x box_h)
            inset = 18
            hx = (
                f'{x+inset:.1f},{y:.1f} '
                f'{x+box_w-inset:.1f},{y:.1f} '
                f'{x+box_w:.1f},{y+box_h/2:.1f} '
                f'{x+box_w-inset:.1f},{y+box_h:.1f} '
                f'{x+inset:.1f},{y+box_h:.1f} '
                f'{x:.1f},{y+box_h/2:.1f}'
            )
            sn_pwned = (getattr(node, "pwned", False)
                         or getattr(node, "default_creds_live", False))
            fill = "#0e7490"   # teal
            stroke = "#155e75"
            nodes_svg.append(
                f'<polygon points="{hx}" fill="{fill}" '
                f'stroke="{stroke}" stroke-width="1.5"/>'
            )
            nodes_svg.append(
                f'<text x="{cx:.1f}" y="{cy-10:.1f}" '
                f'fill="#fff" font-size="14" font-weight="700" '
                f'text-anchor="middle" font-family="-apple-system,Segoe UI,'
                f'Helvetica,Arial,sans-serif">SCC</text>'
            )
            host_short = host if len(host) <= 22 else host[:21] + "…"
            nodes_svg.append(
                f'<text x="{cx:.1f}" y="{cy+6:.1f}" fill="#cbd5e1" '
                f'font-size="10" text-anchor="middle" '
                f'font-family="-apple-system,Segoe UI,Helvetica,Arial,'
                f'sans-serif">{_hesc(host_short)}</text>'
            )
            nodes_svg.append(
                f'<text x="{cx:.1f}" y="{cy+22:.1f}" fill="#94a3b8" '
                f'font-size="10" text-anchor="middle" '
                f'font-family="-apple-system,Segoe UI,Helvetica,Arial,'
                f'sans-serif">v{_hesc(ver)}</text>'
            )
            if sn_pwned:
                nodes_svg.append(
                    f'<circle cx="{x+box_w-14:.1f}" cy="{y+14:.1f}" '
                    f'r="11" fill="#f59e0b" stroke="#fff" stroke-width="2"/>'
                )
                nodes_svg.append(
                    f'<text x="{x+box_w-14:.1f}" y="{y+18:.1f}" '
                    f'fill="#fff" font-size="13" font-weight="900" '
                    f'text-anchor="middle">⚡</text>'
                )
        else:   # btp — cloud silhouette
            uuid = getattr(node, "uuid", "")
            label = (getattr(node, "display_name", "")
                     or getattr(node, "subdomain", "")
                     or uuid[:8])
            region = getattr(node, "region", "") or "?"
            cx, cy = pos[("btp", uuid)]
            x, y = cx - box_w / 2, cy - box_h / 2
            # Cloud silhouette — three humps on top, flat bottom.
            # Sized to fit the same box_w x box_h as the SAP / SCC
            # rectangles so the grid stays even.
            cloud_path = (
                f"M{x+24:.1f},{y+22:.1f} "
                f"C{x+8:.1f},{y+22:.1f} {x+8:.1f},{y+10:.1f} "
                f"{x+30:.1f},{y+12:.1f} "
                f"C{x+34:.1f},{y+2:.1f} {x+62:.1f},{y+2:.1f} "
                f"{x+70:.1f},{y+12:.1f} "
                f"C{x+78:.1f},{y+4:.1f} {x+108:.1f},{y+4:.1f} "
                f"{x+114:.1f},{y+14:.1f} "
                f"C{x+box_w-22:.1f},{y+12:.1f} "
                f"{x+box_w-6:.1f},{y+22:.1f} "
                f"{x+box_w-12:.1f},{y+34:.1f} "
                f"C{x+box_w-4:.1f},{y+48:.1f} "
                f"{x+box_w-22:.1f},{y+box_h-6:.1f} "
                f"{x+box_w-32:.1f},{y+box_h-12:.1f} "
                f"L{x+30:.1f},{y+box_h-12:.1f} "
                f"C{x+10:.1f},{y+box_h-4:.1f} "
                f"{x:.1f},{y+38:.1f} "
                f"{x+12:.1f},{y+30:.1f} "
                f"C{x+2:.1f},{y+24:.1f} {x+10:.1f},{y+18:.1f} "
                f"{x+24:.1f},{y+22:.1f} Z")
            bn_pwned = bool(getattr(node, "pwned", False))
            fill = "#0ea5e9"     # sky blue
            stroke = "#0369a1"
            nodes_svg.append(
                f'<path d="{cloud_path}" fill="{fill}" stroke="{stroke}" '
                f'stroke-width="1.5"/>')
            # Header text — "☁ BTP"
            nodes_svg.append(
                f'<text x="{cx:.1f}" y="{cy-12:.1f}" '
                f'fill="#fff" font-size="14" font-weight="700" '
                f'text-anchor="middle" font-family="-apple-system,Segoe UI,'
                f'Helvetica,Arial,sans-serif">☁ BTP</text>')
            label_short = label if len(label) <= 22 else label[:21] + "…"
            nodes_svg.append(
                f'<text x="{cx:.1f}" y="{cy+6:.1f}" fill="#e0f2fe" '
                f'font-size="10.5" text-anchor="middle" '
                f'font-family="-apple-system,Segoe UI,Helvetica,Arial,'
                f'sans-serif">{_hesc(label_short)}</text>')
            nodes_svg.append(
                f'<text x="{cx:.1f}" y="{cy+22:.1f}" fill="#bae6fd" '
                f'font-size="10" text-anchor="middle" '
                f'font-family="-apple-system,Segoe UI,Helvetica,Arial,'
                f'sans-serif">{_hesc(region)}</text>')
            if bn_pwned:
                nodes_svg.append(
                    f'<circle cx="{x+box_w-14:.1f}" cy="{y+14:.1f}" '
                    f'r="11" fill="#f59e0b" stroke="#fff" stroke-width="2"/>')
                nodes_svg.append(
                    f'<text x="{x+box_w-14:.1f}" y="{y+18:.1f}" '
                    f'fill="#fff" font-size="13" font-weight="900" '
                    f'text-anchor="middle">⚡</text>')

    # ------------------------------------------------------------------
    # Legend (small, lower-right)
    # ------------------------------------------------------------------
    legend = (
        f'<g transform="translate({width-310:.1f},{height-46:.1f})">'
        f'<rect x="0" y="0" width="298" height="36" rx="6" ry="6" '
        f'fill="#fff" stroke="#e5e7eb" stroke-width="1"/>'
        f'<rect x="10" y="10" width="14" height="14" rx="3" '
        f'fill="#1d4ed8"/><text x="30" y="22" font-size="10" '
        f'fill="#374151" font-family="-apple-system,Segoe UI,sans-serif">ABAP</text>'
        f'<rect x="68" y="10" width="14" height="14" rx="3" '
        f'fill="#15803d"/><text x="88" y="22" font-size="10" '
        f'fill="#374151" font-family="-apple-system,Segoe UI,sans-serif">Java</text>'
        f'<polygon points="124,10 134,10 138,17 134,24 124,24 120,17" '
        f'fill="#0e7490"/><text x="142" y="22" font-size="10" '
        f'fill="#374151" font-family="-apple-system,Segoe UI,sans-serif">SCC</text>'
        # Cloud glyph for BTP — small ☁ in sky blue
        f'<text x="172" y="22" font-size="14" fill="#0ea5e9">☁</text>'
        f'<text x="187" y="22" font-size="10" fill="#374151" '
        f'font-family="-apple-system,Segoe UI,sans-serif">BTP</text>'
        f'<circle cx="222" cy="17" r="6" fill="#f59e0b"/>'
        f'<text x="233" y="22" font-size="10" fill="#374151" '
        f'font-family="-apple-system,Segoe UI,sans-serif">⚡ pwned</text>'
        f'</g>'
    )

    # ------------------------------------------------------------------
    # Assemble — viewBox makes it scale to container width
    # ------------------------------------------------------------------
    arrow_defs = (
        '<defs>'
        '<marker id="arr-norm" viewBox="0 0 10 10" refX="10" refY="5" '
        'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        '<path d="M0,0 L10,5 L0,10 z" fill="#94a3b8"/></marker>'
        '<marker id="arr-sapall" viewBox="0 0 10 10" refX="10" refY="5" '
        'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        '<path d="M0,0 L10,5 L0,10 z" fill="#dc2626"/></marker>'
        '</defs>'
    )

    svg = (
        f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
        f'style="width:100%;height:auto;background:#f8fafc;border-radius:8px;'
        f'border:1px solid #e2e8f0">'
        + arrow_defs
        + "".join(edges_svg)
        + "".join(nodes_svg)
        + legend
        + '</svg>'
    )
    return svg


# ---------------------------------------------------------------------------
# HTML report sections — ported 1:1 from the equivalent Markdown builders
# so the HTML report has the same coverage.  Issue #31 root cause: build_
# html_report only rendered a subset (findings + chains + inventory + creds
# + capability + recommendations); the SCC, BTP, cloud-lateral, cert-auth
# and ATT&CK coverage sections existed in Markdown only.
# ---------------------------------------------------------------------------

def _html_attack_coverage_section(state: SAPMAPState) -> str:
    """MITRE ATT&CK coverage — tactic-grouped grid of exercised
    techniques.  Mirrors _attack_coverage_section (MD) so the HTML
    report matches its Markdown twin."""
    try:
        from sapmap_attack import (
            heatmap_grid, ATTACK_VERSION, lookup,
        )
    except Exception:
        return ""
    grid = heatmap_grid(state)
    totals = grid.get("totals", {})
    if not totals.get("techniques"):
        return ""

    rows = []
    for col in grid.get("columns", []):
        observed = [c for c in col["cells"] if c["score"] > 0]
        if not observed:
            continue
        tech_cells, sids = [], set()
        for c in observed:
            info = lookup(c["id"])
            if info:
                tech_cells.append(
                    f'<a href="{_hesc(info["url"])}" target="_blank" '
                    f'rel="noopener" style="color:#0969da;'
                    f'text-decoration:none">{_hesc(c["id"])}</a>')
            else:
                tech_cells.append(_hesc(c["id"]))
            sids.update(c["sids"])
        rows.append(
            f'<tr><td>{_hesc(col["tactic_name"])}</td>'
            f'<td>{" · ".join(tech_cells)}</td>'
            f'<td class="mono">{_hesc(", ".join(sorted(sids)))}</td>'
            f'</tr>')
    return (
        '<section id="sec-attack">'
        '<h2>🎯 MITRE ATT&amp;CK coverage</h2>'
        '<p style="font-size:12px;color:#6b7280;margin:0 0 12px">'
        f'This engagement exercised <b>{totals["techniques"]} techniques</b>'
        f' across <b>{totals["tactics"]} tactics</b> '
        f'(mapped against ATT&amp;CK Enterprise {_hesc(ATTACK_VERSION)}). '
        f'Drop the matching <code>sapmap_attack_layer.json</code> into '
        f'<a href="https://mitre-attack.github.io/attack-navigator/" '
        f'target="_blank" rel="noopener">ATT&amp;CK Navigator</a> for the '
        f'interactive heatmap.'
        '</p>'
        '<table class="grid"><thead><tr>'
        '<th>Tactic</th><th>Techniques</th><th>SIDs touched</th>'
        '</tr></thead><tbody>' + "".join(rows) + '</tbody></table>'
        '</section>')


def _html_medium_info_findings_section(state: SAPMAPState) -> str:
    """Findings section for MEDIUM + INFO severities.

    The HTML report already renders CRITICAL + HIGH inline in the
    hero block; MED / INFO used to fall through the cracks entirely
    even though they were surfaced in the GUI finding drawer.  This
    section mirrors the MD `_findings_section` for the two lower tiers.
    """
    med, info = [], []
    for sid, n in sorted(state.nodes.items()):
        for f in (n.findings or []):
            sev = getattr(f, "severity", None)
            if sev == Severity.MEDIUM:
                med.append((sid, f))
            elif sev == Severity.INFO or sev == Severity.LOW:
                info.append((sid, f))
    if not med and not info:
        return ""

    def _rows(items):
        out = ""
        for sid, f in items:
            det = (getattr(f, "detail", "") or "")[:200]
            rem = getattr(f, "remediation", "")
            if isinstance(rem, dict):
                rem = rem.get("fix_summary", "") or ""
            out += (
                f'<tr>'
                f'<td class="mono"><b>{_hesc(sid)}</b></td>'
                f'<td>{_hesc(getattr(f, "name", "") or "?")}</td>'
                f'<td>{_hesc(det)}</td>'
                f'<td>{_hesc(rem)}</td>'
                f'</tr>')
        return out

    parts = ['<section id="sec-medinfo">'
             '<h2>ℹ️ Medium &amp; informational findings</h2>']
    parts.append(
        '<p style="font-size:12px;color:#6b7280;margin:0 0 12px">'
        'Everything the scan flagged at MEDIUM / LOW / INFO — mostly '
        'hardening opportunities that are not immediately exploitable '
        'but should still be tracked.'
        '</p>')
    if med:
        parts.append(f'<h3 style="margin:14px 0 6px;font-size:13px">'
                     f'Medium ({len(med)})</h3>')
        parts.append(
            '<table class="grid" style="font-size:12px"><thead><tr>'
            '<th>SID</th><th>Finding</th><th>Detail</th><th>Remediation</th>'
            '</tr></thead><tbody>' + _rows(med) + '</tbody></table>')
    if info:
        parts.append(f'<h3 style="margin:14px 0 6px;font-size:13px">'
                     f'Low / Info ({len(info)})</h3>')
        parts.append(
            '<table class="grid" style="font-size:12px"><thead><tr>'
            '<th>SID</th><th>Finding</th><th>Detail</th><th>Remediation</th>'
            '</tr></thead><tbody>' + _rows(info) + '</tbody></table>')
    parts.append('</section>')
    return "".join(parts)


def _html_created_users_section(state: SAPMAPState) -> str:
    """Every SAPMAP-created / owned user across the landscape.

    One row per CreatedUser so the operator has a single cleanup
    reference at engagement end (which SID / client / method / when).
    """
    users = list(getattr(state, "created_users", []) or [])
    if not users:
        return ""
    rows = ""
    for u in sorted(users, key=lambda x: (x.sid, x.client, x.username)):
        rows += (
            f'<tr>'
            f'<td class="mono"><b>{_hesc(u.sid)}</b></td>'
            f'<td class="mono">{_hesc(u.username)}</td>'
            f'<td>{_hesc(u.client)}</td>'
            f'<td class="mono">{_hesc(u.hostname or u.ip or "?")}</td>'
            f'<td>{_hesc(u.instance_nr or "?")}</td>'
            f'<td>{_hesc(u.method)}</td>'
            f'<td class="mono" style="font-size:11px">'
            f'{_hesc((u.created_at or "")[:19])}</td>'
            f'</tr>')
    return (
        '<section id="sec-users"><h2>👤 SAPMAP-created accounts</h2>'
        '<p style="font-size:12px;color:#6b7280;margin:0 0 12px">'
        'Every account SAPMAP created during this engagement — one '
        'row per (SID, client) pair.  Use "Cleanup All Users" in the '
        'GUI or delete manually before handover.  Passwords redacted; '
        'plaintext lives in the session <code>.sapmap</code> file.'
        '</p>'
        '<table class="grid"><thead><tr>'
        '<th>SID</th><th>User</th><th>Client</th><th>Host</th>'
        '<th>Inst</th><th>Method</th><th>Created</th>'
        '</tr></thead><tbody>' + rows + '</tbody></table>'
        '</section>')


def _html_impact_section(state: SAPMAPState) -> str:
    """Business-impact scenarios that produced records.

    Only surfaces scenarios where record_count > 0 — no-hit reads are
    just noise for an executive audience.  Groups by SID so a
    stakeholder can see "on S4H we can read 14,382 salary records".
    """
    have_any = False
    blocks = []
    sev_color = {5: "#e74c3c", 4: "#e67e22",
                 3: "#f1c40f", 2: "#3498db", 1: "#95a5a6"}
    for sid, n in sorted(state.nodes.items()):
        rows = []
        for r in (n.impact_results or []):
            if not isinstance(r, dict):
                continue
            if r.get("error") or (r.get("record_count", 0) or 0) <= 0:
                continue
            have_any = True
            sev = r.get("severity", 1)
            col = sev_color.get(sev, "#95a5a6")
            rows.append(
                f'<tr>'
                f'<td><span class="badge" style="background:{col};'
                f'color:#fff;font-size:10px;padding:2px 6px;'
                f'border-radius:3px">'
                f'{_hesc(r.get("severity_label", "?"))}</span></td>'
                f'<td>{_hesc(r.get("icon", ""))} '
                f'{_hesc(r.get("scenario", "?"))}</td>'
                f'<td>{_hesc(r.get("headline", ""))}</td>'
                f'<td class="num">'
                f'{r.get("record_count", 0):,}</td>'
                f'</tr>')
        if rows:
            blocks.append(
                f'<h3 style="margin:14px 0 6px;font-size:13px">'
                f'{_hesc(sid)}</h3>'
                f'<table class="grid" style="font-size:12px">'
                f'<thead><tr>'
                f'<th>Severity</th><th>Scenario</th>'
                f'<th>Headline</th><th>Records</th>'
                f'</tr></thead><tbody>' + "".join(rows) +
                '</tbody></table>')
    if not have_any:
        return ""
    return (
        '<section id="sec-impact"><h2>💰 Business impact</h2>'
        '<p style="font-size:12px;color:#6b7280;margin:0 0 12px">'
        'Concrete blast-radius reads across finance / HR / vendor '
        'tables — the numbers a CISO can quote to quantify exposure.  '
        'Empty-return scenarios are omitted; only hits are shown.'
        '</p>' + "".join(blocks) + '</section>')


def _html_secstore_section(state: SAPMAPState) -> str:
    """ABAP + Java SecStore extraction results across the landscape."""
    abap_rows = []
    java_rows = []
    for sid, n in sorted(state.nodes.items()):
        for e in (n.secstore_entries or []):
            if not isinstance(e, dict):
                continue
            has_pw = bool(e.get("password"))
            abap_rows.append(
                f'<tr>'
                f'<td class="mono"><b>{_hesc(sid)}</b></td>'
                f'<td class="mono">{_hesc(e.get("ident", "?"))}</td>'
                f'<td>{_hesc(e.get("category", "?"))}</td>'
                f'<td>'
                + ('<span class="badge badge-bad">plaintext</span>'
                   if has_pw else '<span class="badge">no pw</span>')
                + '</td>'
                f'</tr>')
        for e in (n.java_secstore_entries or []):
            if not isinstance(e, dict):
                continue
            has_val = bool(e.get("value"))
            downstream = bool(e.get("is_downstream"))
            java_rows.append(
                f'<tr>'
                f'<td class="mono"><b>{_hesc(sid)}</b></td>'
                f'<td class="mono">{_hesc(e.get("name", "?"))}</td>'
                f'<td>{_hesc(e.get("kind", ""))}</td>'
                f'<td class="mono">'
                f'{_hesc(e.get("target_sid", "") or "—")}</td>'
                f'<td>'
                + ('<span class="badge badge-bad">plaintext</span>'
                   if has_val else '<span class="badge">no val</span>')
                + ('' if not downstream else
                   ' <span class="badge badge-mid">↓ downstream</span>')
                + '</td>'
                f'</tr>')
    if not abap_rows and not java_rows:
        return ""
    parts = ['<section id="sec-secstore"><h2>🔐 Secure-Store recovery</h2>'
             '<p style="font-size:12px;color:#6b7280;margin:0 0 12px">'
             'Passwords cached inside SAP secure stores that SAPMAP was '
             'able to decrypt.  Every entry represents a credential the '
             'operator can now log in with (or a downstream system whose '
             'password we now hold).  Plaintext values live in '
             '<code>loot/secstore/</code>.'
             '</p>']
    if abap_rows:
        parts.append(f'<h3 style="margin:14px 0 6px;font-size:13px">'
                     f'ABAP SecStore (RSECTAB) — {len(abap_rows)} entries</h3>'
                     f'<table class="grid" style="font-size:12px">'
                     f'<thead><tr><th>SID</th><th>Ident</th>'
                     f'<th>Category</th><th>Status</th>'
                     f'</tr></thead><tbody>' + "".join(abap_rows)
                     + '</tbody></table>')
    if java_rows:
        parts.append(f'<h3 style="margin:14px 0 6px;font-size:13px">'
                     f'Java SecStoreFS — {len(java_rows)} entries</h3>'
                     f'<table class="grid" style="font-size:12px">'
                     f'<thead><tr><th>SID</th><th>Name</th>'
                     f'<th>Kind</th><th>Downstream SID</th><th>Status</th>'
                     f'</tr></thead><tbody>' + "".join(java_rows)
                     + '</tbody></table>')
    parts.append('</section>')
    return "".join(parts)


def _html_persistence_section(state: SAPMAPState) -> str:
    """Persistence footprint — forged tickets, dpmon SAP* activations,
    injected RFC destinations.  Together these are what the operator
    needs to make sure to clean up (or, for a red-team engagement,
    what the defender needs to hunt for)."""
    tickets = list(getattr(state, "forged_tickets", []) or [])
    created_dests = list(getattr(state, "created_destinations", []) or [])
    dpmon_sids = [n.sid for n in state.nodes.values()
                  if getattr(n, "dpmon_sap_star_used", False)]
    if not (tickets or created_dests or dpmon_sids):
        return ""

    parts = ['<section id="sec-persistence"><h2>🕳️ Persistence footprint</h2>'
             '<p style="font-size:12px;color:#6b7280;margin:0 0 12px">'
             'Artifacts SAPMAP planted that outlive the current shell — '
             'forged MYSAPSSO2 tickets, dpmon SAP* activations, and RFC '
             'destinations injected into remote systems.  Every entry '
             'here needs an explicit cleanup step at handover.'
             '</p>']

    if dpmon_sids:
        parts.append(
            '<h3 style="margin:14px 0 6px;font-size:13px">'
            f'Virtual SAP* activated ({len(dpmon_sids)})</h3>'
            '<p style="font-size:12px;color:#374151;margin:4px 0">'
            'Kernel ≥ 790 dpmon primitive (SAP Note 3303172) — a one-time '
            'password was issued for a virtual SAP* logon on: '
            '<b>' + _hesc(", ".join(dpmon_sids)) + '</b>. '
            'The primitive auto-deactivates after use but leaves an '
            'audit trail; remind the customer to rotate SAP* on affected '
            'clients.</p>')

    if tickets:
        rows = ""
        for t in tickets:
            used = len(getattr(t, "used_on", []) or [])
            rows += (
                f'<tr>'
                f'<td class="mono"><b>{_hesc(getattr(t, "sid", "?"))}</b></td>'
                f'<td class="mono">{_hesc(getattr(t, "user", "?"))}</td>'
                f'<td>{_hesc(getattr(t, "client", "?"))}</td>'
                f'<td>{getattr(t, "ticket_size", 0)} B</td>'
                f'<td>{getattr(t, "validity_min", 0)} min</td>'
                f'<td class="num">{used}</td>'
                f'<td class="mono" style="font-size:11px">'
                f'{_hesc((getattr(t, "forged_at", "") or "")[:19])}</td>'
                f'</tr>')
        parts.append(
            f'<h3 style="margin:14px 0 6px;font-size:13px">'
            f'Forged MYSAPSSO2 tickets ({len(tickets)})</h3>'
            '<table class="grid" style="font-size:12px"><thead><tr>'
            '<th>Issuer</th><th>User</th><th>Client</th><th>Size</th>'
            '<th>TTL</th><th>Replays</th><th>Forged at</th>'
            '</tr></thead><tbody>' + rows + '</tbody></table>')

    if created_dests:
        rows = ""
        for d in created_dests:
            if not isinstance(d, dict):
                continue
            rows += (
                f'<tr>'
                f'<td class="mono">{_hesc(d.get("dest_name", "?"))}</td>'
                f'<td class="mono">{_hesc(d.get("source_sid", "?"))}</td>'
                f'<td class="mono">{_hesc(d.get("target_sid", "?"))}</td>'
                f'<td>{_hesc(d.get("type", "?"))}</td>'
                f'<td class="mono" style="font-size:11px">'
                f'{_hesc((d.get("created_at", "") or "")[:19])}</td>'
                f'</tr>')
        parts.append(
            f'<h3 style="margin:14px 0 6px;font-size:13px">'
            f'Injected RFC destinations ({len(created_dests)})</h3>'
            '<table class="grid" style="font-size:12px"><thead><tr>'
            '<th>Dest name</th><th>Source SID</th><th>Target SID</th>'
            '<th>Type</th><th>Created</th>'
            '</tr></thead><tbody>' + rows + '</tbody></table>')

    parts.append('</section>')
    return "".join(parts)


def _html_evasion_section(state: SAPMAPState) -> str:
    """OPSEC posture — what evasion primitives were armed for this
    engagement.  Section is emitted only when the operator explicitly
    opted into anything (default config = no section)."""
    ev = getattr(state, "evasion", {}) or {}
    if not ev:
        return ""
    armed = bool(ev.get("allow_evasion"))
    diag = ev.get("diag_terminal_name") or ""
    channel = ev.get("os_exec_channel") or ""
    sso_users = ev.get("mysapsso2_users") or ""
    baseline_at = ev.get("baseline_captured_at") or ""
    if not (armed or diag or channel or sso_users or baseline_at):
        return ""
    rows = []
    rows.append(("Tier 3 armed",
                 ('<span class="badge badge-bad">YES</span>'
                  if armed else
                  '<span class="badge badge-ok">no</span>')))
    if diag:
        rows.append(("DIAG terminal spoof", f'<code>{_hesc(diag)}</code>'))
    if channel:
        rows.append(("Forced OS-exec channel",
                     f'<code>{_hesc(channel)}</code>'))
    if sso_users:
        rows.append(("MYSAPSSO2 fanout identities",
                     f'<code>{_hesc(sso_users)}</code>'))
    if baseline_at:
        rows.append(("Baseline captured", _hesc(baseline_at[:19])))
    trs = "".join(f'<tr><td>{k}</td><td>{v}</td></tr>' for k, v in rows)
    return (
        '<section id="sec-opsec"><h2>🥷 OPSEC posture (evasion)</h2>'
        '<p style="font-size:12px;color:#6b7280;margin:0 0 12px">'
        'Evasion primitives armed for this engagement.  Attribution '
        'record — matters for both blue-team debrief and red-team '
        'attribution honesty.'
        '</p>'
        '<table class="grid" style="font-size:12px">'
        '<tbody>' + trs + '</tbody></table>'
        '</section>')


def _html_scc_section(state: SAPMAPState) -> str:
    """SCC landscape section — one row per Cloud Connector."""
    sccs = (getattr(state, "scc_nodes", {}) or {})
    if not sccs:
        return ""
    rows = []
    for host, sn in sorted(sccs.items()):
        cves_confirmed = getattr(sn, "cves_confirmed", []) or []
        cves_suspect = getattr(sn, "cves_suspected", []) or []
        cves_cell = ""
        if cves_confirmed:
            cves_cell += ('<span class="risk-pill" style="background:#c0392b">'
                          + _hesc(", ".join(cves_confirmed)) + '</span> ')
        if cves_suspect:
            cves_cell += ('<span class="badge" style="background:#f3d5c4;'
                          'color:#943e00">' + _hesc(", ".join(cves_suspect))
                          + '</span>')
        if not cves_cell:
            cves_cell = "—"
        default = ('<span class="risk-pill" style="background:#c0392b">LIVE</span>'
                    if getattr(sn, "default_creds_live", False) else "—")
        pwned = ('<span class="risk-pill" style="background:#8b0000">⚡ PWNED</span>'
                  if getattr(sn, "pwned", False) else "—")
        ks_extracted = "✅" if getattr(sn, "keystore_extracted", False) else "—"
        ssfs = "✅" if getattr(sn, "ssfs_decrypted", False) else "—"
        pp_weak = getattr(sn, "pp_weak_count", 0) or 0
        pp_cell = (f'<span class="badge" style="background:#f3d5c4;'
                   f'color:#943e00">{pp_weak} weak</span>'
                   if pp_weak else "—")
        creds_n = len(getattr(sn, "credentials", []) or [])
        creds_cell = (f'<span class="badge" style="background:#d4edda;'
                      f'color:#155724">{creds_n}</span>' if creds_n else "—")
        nmap = len(getattr(sn, "mappings", []) or [])
        rows.append(
            f'<tr>'
            f'<td class="mono"><b>{_hesc(host)}</b></td>'
            f'<td>{_hesc(getattr(sn, "version", "") or "?")}</td>'
            f'<td>{pwned}</td>'
            f'<td>{cves_cell}</td>'
            f'<td>{default}</td>'
            f'<td class="num">{creds_cell}</td>'
            f'<td class="num">{nmap}</td>'
            f'<td>{ks_extracted}</td>'
            f'<td>{ssfs}</td>'
            f'<td>{pp_cell}</td>'
            f'</tr>')
    # Per-SCC detail blocks — crown-jewel artifacts, unlocked
    # keystores, captured admin creds, PP analyser verdict, CVE detail.
    detail_blocks = []
    for host, sn in sorted(sccs.items()):
        creds = list(getattr(sn, "credentials", []) or [])
        keystore = getattr(sn, "keystore_extracted", False)
        ssfs = getattr(sn, "ssfs_decrypted", False)
        pp_ca = getattr(sn, "pp_ca_privkey_fp", "") or ""
        tun_fp = getattr(sn, "tunnel_privkey_fp", "") or ""
        unlocked = list(getattr(sn, "unlocked_keystores", []) or [])
        ssfs_keys = list(getattr(sn, "ssfs_secrets_keys", []) or [])
        pp_ana = getattr(sn, "pp_analysis", {}) or {}
        sub_uuids = list(getattr(sn, "subaccount_uuids", []) or [])
        loc_ids = list(getattr(sn, "location_ids", []) or [])
        region = getattr(sn, "tunnel_region", "") or ""
        replayed = getattr(sn, "tunnel_replayed", False)
        users_xml = getattr(sn, "users_xml_loot_path", "") or ""
        ha_role = getattr(sn, "ha_role", "") or ""
        ha_peer = getattr(sn, "ha_shadow_host", "") or ""
        cve_det = getattr(sn, "cve_details", []) or []
        if not (creds or keystore or ssfs or pp_ca or tun_fp or unlocked
                or ssfs_keys or pp_ana or sub_uuids or loc_ids
                or users_xml or ha_peer or replayed or cve_det):
            continue
        parts = [f'<h3 style="margin:18px 0 8px;font-size:14px">'
                 f'SCC {_hesc(host)} — details</h3>']

        # Topology / trust
        topo = []
        if ha_role:
            topo.append(
                (f"HA role", _hesc(ha_role) + (
                    f" (peer: <code>{_hesc(ha_peer)}</code> · "
                    f"{_hesc(getattr(sn, 'ha_peer_role', '') or '?')})"
                    if ha_peer else "")))
        if region:
            topo.append(("Tunnel region", _hesc(region)))
        if sub_uuids:
            topo.append(
                ("Subaccounts trusted",
                 f"{len(sub_uuids)} — "
                 f"{_hesc(', '.join(sub_uuids[:3]))}"
                 + ("…" if len(sub_uuids) > 3 else "")))
        if loc_ids:
            topo.append(
                ("Location IDs", _hesc(", ".join(loc_ids))))
        if replayed:
            topo.append(
                ("Tunnel handshake",
                 '<b style="color:#b91c1c">replayed</b> '
                 '(persistence achieved)'))
        if topo:
            trs = "".join(f'<tr><td>{k}</td><td>{v}</td></tr>'
                          for k, v in topo)
            parts.append(
                '<table class="grid" style="font-size:12px;'
                'margin-bottom:10px">'
                '<tbody>' + trs + '</tbody></table>')

        # Crown-jewel artifacts
        crown = []
        if keystore and getattr(sn, "keystore_loot_path", ""):
            crown.append(("Keystore",
                          "extracted → <code>"
                          + _hesc(sn.keystore_loot_path) + "</code>"))
        if users_xml:
            crown.append(("Users.xml (plaintext)",
                          "decrypted → <code>"
                          + _hesc(users_xml) + "</code>"))
        if tun_fp:
            crown.append(("Tunnel private key",
                          "SHA-256 <code>"
                          + _hesc(tun_fp[:16]) + "…</code>"))
        if pp_ca:
            crown.append(
                ("<b>PP CA private key</b>",
                 "SHA-256 <code>" + _hesc(pp_ca[:16]) + "…</code> — "
                 "<b style='color:#b91c1c'>can mint client certs for any "
                 "subaccount user</b>"))
        if ssfs and (getattr(sn, "ssfs_secrets_path", "") or ssfs_keys):
            crown.append(
                ("SSFS secrets",
                 "decrypted → <code>"
                 + _hesc(getattr(sn, "ssfs_secrets_path", "") or "?")
                 + "</code> "
                 + f"({len(ssfs_keys)} keys)"))
        if crown:
            trs = "".join(f'<tr><td>{k}</td><td>{v}</td></tr>'
                          for k, v in crown)
            parts.append(
                '<h4 style="margin:10px 0 4px;font-size:12px">'
                'Crown-jewel artifacts</h4>'
                '<table class="grid" style="font-size:12px;'
                'margin-bottom:10px">'
                '<tbody>' + trs + '</tbody></table>')

        # SSFS key names (names only)
        if ssfs_keys:
            parts.append(
                '<p style="font-size:12px;color:#374151;margin:6px 0">'
                f'<b>SSFS secret keys captured ({len(ssfs_keys)}):</b> '
                '<code>'
                + _hesc(", ".join(ssfs_keys[:20]))
                + ("…" if len(ssfs_keys) > 20 else "")
                + '</code></p>')

        # Unlocked keystores
        if unlocked:
            trs = ""
            for k in unlocked[:20]:
                p = k.get("path", "") or "?"
                subj = k.get("cert_subject", "") or "?"
                fp = k.get("cert_sha256", "") or ""
                fp_short = (fp[:16] + "…") if fp else "—"
                trs += (f'<tr><td class="mono">{_hesc(p)}</td>'
                        f'<td>{_hesc(subj)}</td>'
                        f'<td class="mono">{_hesc(fp_short)}</td></tr>')
            if len(unlocked) > 20:
                trs += (f'<tr><td colspan="3" style="color:#6b7280">'
                        f'…{len(unlocked) - 20} more</td></tr>')
            parts.append(
                '<h4 style="margin:10px 0 4px;font-size:12px">'
                'Unlocked tunnel keystores</h4>'
                '<table class="grid" style="font-size:12px;'
                'margin-bottom:10px"><thead><tr>'
                '<th>Path</th><th>Cert subject</th><th>SHA-256</th>'
                '</tr></thead><tbody>' + trs + '</tbody></table>')

        # Captured admin creds (marker only — never plaintext)
        if creds:
            trs = ""
            for c in creds:
                user = (getattr(c, "user", "")
                        or (isinstance(c, dict) and c.get("user"))
                        or "?")
                pw = (getattr(c, "password", "")
                      or (isinstance(c, dict) and c.get("password"))
                      or "")
                h = (getattr(c, "hash", "")
                     or (isinstance(c, dict) and c.get("hash"))
                     or "")
                verified = bool(
                    getattr(c, "verified", False)
                    or (isinstance(c, dict) and c.get("verified")))
                if pw:
                    marker = ('<span class="risk-pill" '
                              'style="background:#c0392b">plaintext</span>')
                elif h:
                    marker = ('<code>' + _hesc(h[:24]) + '…</code>')
                else:
                    marker = "—"
                trs += (f'<tr><td class="mono">{_hesc(user)}</td>'
                        f'<td>{marker}</td>'
                        f'<td>{"✓" if verified else "—"}</td></tr>')
            parts.append(
                '<h4 style="margin:10px 0 4px;font-size:12px">'
                'Captured admin credentials</h4>'
                '<table class="grid" style="font-size:12px;'
                'margin-bottom:10px"><thead><tr>'
                '<th>User</th><th>Hash / marker</th><th>Verified</th>'
                '</tr></thead><tbody>' + trs + '</tbody></table>')

        # Principal-Propagation analyser verdict
        summary = pp_ana.get("summary") if isinstance(pp_ana, dict) else None
        findings = (pp_ana.get("findings")
                    if isinstance(pp_ana, dict) else None)
        if summary or findings:
            crit = (summary or {}).get("critical", 0)
            high = (summary or {}).get("high", 0)
            med = (summary or {}).get("medium", 0)
            head = (
                '<h4 style="margin:10px 0 4px;font-size:12px">'
                'Principal-Propagation analysis</h4>'
                '<p style="font-size:12px;color:#374151;margin:4px 0">'
                f'{crit} CRITICAL · {high} HIGH · {med} MEDIUM '
                f'(analysed at {_hesc(getattr(sn, "pp_analysis_at", "") or "?")})'
                '</p>')
            parts.append(head)
            if findings:
                trs = ""
                for f in findings[:15]:
                    sev = (f.get("severity", "?")
                           if isinstance(f, dict) else "?")
                    hl = ((f.get("headline") or f.get("title") or "")
                          if isinstance(f, dict) else str(f))
                    trs += (f'<tr><td>{_hesc(sev)}</td>'
                            f'<td>{_hesc(hl)}</td></tr>')
                if len(findings) > 15:
                    trs += (f'<tr><td colspan="2" style="color:#6b7280">'
                            f'…{len(findings) - 15} more</td></tr>')
                parts.append(
                    '<table class="grid" style="font-size:12px;'
                    'margin-bottom:10px"><thead><tr>'
                    '<th>Severity</th><th>Finding</th>'
                    '</tr></thead><tbody>' + trs + '</tbody></table>')

        # CVE detail rows
        if cve_det:
            trs = ""
            for d in cve_det:
                if not isinstance(d, dict):
                    continue
                trs += (f'<tr><td class="mono">{_hesc(d.get("cve", "?"))}</td>'
                        f'<td>{_hesc(d.get("severity", "?"))}</td>'
                        f'<td>{_hesc(d.get("status", "?"))}</td>'
                        f'<td>{_hesc(d.get("headline", ""))}</td></tr>')
            parts.append(
                '<h4 style="margin:10px 0 4px;font-size:12px">'
                'CVE assessment</h4>'
                '<table class="grid" style="font-size:12px;'
                'margin-bottom:10px"><thead><tr>'
                '<th>CVE</th><th>Severity</th><th>Status</th>'
                '<th>Headline</th></tr></thead>'
                '<tbody>' + trs + '</tbody></table>')

        detail_blocks.append("".join(parts))

    return (
        '<section id="sec-scc">'
        '<h2>☁️ SAP Cloud Connectors</h2>'
        '<p style="font-size:12px;color:#6b7280;margin:0 0 12px">'
        'On-premise ↔ BTP tunnel gateways.  '
        '<b>Keystore</b> ✅ means the backup zip was pulled and parsed '
        '(crown-jewel material lives in <code>loot/scc/&lt;host&gt;/</code>).  '
        '<b>SSFS</b> ✅ means the secure-store file was decrypted (JAVA '
        'keystore / LDAP / Kerberos / proxy passwords recovered).  '
        '<b>PP weak</b> counts high/critical Principal-Propagation trust-rule '
        'issues surfaced by the PP analyser.'
        '</p>'
        '<table class="grid"><thead><tr>'
        '<th>Host</th><th>Version</th><th>Status</th>'
        '<th>CVEs</th><th>Default creds</th>'
        '<th>Creds captured</th><th>Mappings</th>'
        '<th>Keystore</th><th>SSFS</th><th>PP</th>'
        '</tr></thead><tbody>' + "".join(rows) + '</tbody></table>'
        + "".join(detail_blocks) +
        '</section>')


def _html_btp_section(state: SAPMAPState) -> str:
    """BTP subaccount inventory."""
    subs = (getattr(state, "btp_subaccounts", {}) or {})
    if not subs:
        return ""
    rows = []
    for uuid, sub in sorted(
            subs.items(),
            key=lambda kv: (getattr(kv[1], "subdomain", "") or kv[0])):
        dests = list(getattr(sub, "destinations", []) or [])
        clear = sum(1 for d in dests
                     if getattr(d, "cleartext_captured", False)
                     or (isinstance(d, dict) and d.get("cleartext_captured")))
        linked = sum(1 for d in dests
                      if (getattr(d, "linked_target_sid", "")
                          or (isinstance(d, dict)
                              and d.get("linked_target_sid"))))
        pwned = ('<span class="risk-pill" style="background:#8b0000">⚡</span>'
                  if getattr(sub, "pwned", False) else "—")
        cert = ("🔒" if getattr(sub, "cert_auth_trusted", False) else "—")
        sub_label = (getattr(sub, "subdomain", "")
                      or getattr(sub, "display_name", "")
                      or uuid[:8])
        clear_cell = (f'<span class="risk-pill" style="background:#c0392b">'
                      f'{clear}</span>' if clear else "—")
        linked_cell = (f'<span class="badge" style="background:#d4edda;'
                       f'color:#155724">{linked}</span>' if linked else "—")
        rows.append(
            f'<tr>'
            f'<td class="mono"><b>{_hesc(sub_label)}</b></td>'
            f'<td>{_hesc(getattr(sub, "region", "") or "?")}</td>'
            f'<td class="num">{len(dests)}</td>'
            f'<td class="num">{clear_cell}</td>'
            f'<td class="num">{linked_cell}</td>'
            f'<td>{cert}</td>'
            f'<td>{pwned}</td>'
            f'</tr>')
    return (
        '<section id="sec-btp">'
        '<h2>☁️ SAP BTP subaccounts</h2>'
        '<p style="font-size:12px;color:#6b7280;margin:0 0 12px">'
        'Cloud tenants reachable from this landscape.  <b>Cleartext</b> = '
        'BTP destinations with captured on-prem credentials in plain text; '
        '<b>Linked</b> = destinations resolved to a mapped on-prem SID.  '
        '<b>Cert-auth 🔒</b> = an on-prem X.509 identity successfully '
        'authenticated at the TLS layer against this tenant.'
        '</p>'
        '<table class="grid"><thead><tr>'
        '<th>Subdomain</th><th>Region</th><th>Destinations</th>'
        '<th>Cleartext</th><th>Linked</th><th>Cert-auth</th><th>Pwned</th>'
        '</tr></thead><tbody>' + "".join(rows) + '</tbody></table>'
        '</section>')


def _html_cloud_lateral_section(state: SAPMAPState) -> str:
    """Cloud ↔ on-prem lateral-move summary — HTML version of the
    same narrative logic used in the Markdown report."""
    subs = getattr(state, "btp_subaccounts", None) or {}
    if not subs:
        return ""
    total_dests = sum(
        len(list(getattr(s, "destinations", []) or []))
        for s in subs.values())
    if total_dests == 0:
        return ""

    # Same mint-provenance gathering as the MD path.
    mint_findings_by_uuid: dict = {}
    for node in state.nodes.values():
        for f in getattr(node, "findings", []) or []:
            ref = getattr(f, "ref", "") or ""
            if not ref.startswith("onprem.to.btp.token_minted"):
                continue
            meta = getattr(f, "meta", {}) or {}
            uuid = (meta.get("region", "")
                     if not meta.get("zid") else meta.get("zid", ""))
            mint_findings_by_uuid.setdefault(uuid, []).append(f)
    for f in getattr(state, "findings", None) or []:
        ref = getattr(f, "ref", "") or ""
        if ref == "btp.token_minted_via_local_cert":
            meta = getattr(f, "meta", {}) or {}
            zid = meta.get("region", "") or ""
            mint_findings_by_uuid.setdefault(zid, []).append(f)

    interesting = []
    for uuid, sub in subs.items():
        dests = list(getattr(sub, "destinations", []) or [])
        region = getattr(sub, "region", "") or ""
        finds = (mint_findings_by_uuid.get(uuid, [])
                  + mint_findings_by_uuid.get(region, []))
        if dests or finds:
            interesting.append((uuid, sub, dests, finds))
    if not interesting:
        return ""

    blocks = []
    for uuid, sub, dests, mint_findings in interesting:
        subdomain = (getattr(sub, "subdomain", "")
                      or getattr(sub, "display_name", "")
                      or uuid[:8])
        region = getattr(sub, "region", "") or "?"
        clear_ct = sum(
            1 for d in dests
            if getattr(d, "cleartext_captured", False)
            or (isinstance(d, dict) and d.get("cleartext_captured")))
        linked_ct = sum(
            1 for d in dests
            if (getattr(d, "linked_target_sid", "")
                 or (isinstance(d, dict)
                     and d.get("linked_target_sid"))))
        linked_sids = sorted({
            (getattr(d, "linked_target_sid", "")
             or (isinstance(d, dict) and d.get("linked_target_sid")))
            for d in dests
            if (getattr(d, "linked_target_sid", "")
                or (isinstance(d, dict) and d.get("linked_target_sid")))
        })
        # Back-edges to on-prem
        back_edges = [
            c for c in getattr(state, "connections", []) or []
            if c.source_sid == f"BTP:{uuid[:8]}" and c.target_sid]
        sap_all_hits = [c for c in back_edges if c.has_sap_all]

        # Headline
        pieces = [f'<b>{len(dests)}</b> destination(s) enumerated']
        if clear_ct:
            pieces.append(f'<b>{clear_ct}</b> carrying cleartext credentials')
        if linked_ct:
            targets_txt = ", ".join(
                f'<code>{_hesc(s)}</code>' for s in linked_sids)
            pieces.append(
                f'<b>{linked_ct}</b> linked to on-prem ({targets_txt})')
        if sap_all_hits:
            pieces.append(
                f'<b>{len(sap_all_hits)}</b> credential(s) confirmed with '
                f'<span class="risk-pill" style="background:#8b0000">'
                f'SAP_ALL</span> on the target')
        headline = " · ".join(pieces) + "."

        # Mint provenance
        mint_html = ""
        if mint_findings:
            bullets = []
            for f in mint_findings:
                meta = getattr(f, "meta", {}) or {}
                ref = getattr(f, "ref", "") or ""
                thumb = meta.get("thumbprint", "")[:12]
                if "via_cert" in ref:
                    src = (f'SM59 destination '
                           f'<code>{_hesc(meta.get("destination", "?"))}</code> '
                           f'on <code>{_hesc(getattr(f, "sid", "?"))}</code> '
                           f'(PSE <code>{_hesc(meta.get("pse", "?"))}</code>)')
                elif "via_local_cert" in ref:
                    src = (f'local cert file '
                           f'<code>{_hesc(meta.get("cert_path", "?"))}</code> '
                           f'on the SAPMAP host')
                else:
                    src = "unknown mint path"
                bullets.append(
                    f'<li>Token minted via {src}; RFC-8705 x5t#S256 prefix '
                    f'<code>{_hesc(thumb)}…</code></li>')
            mint_html = ('<ul style="margin:8px 0;padding-left:20px;'
                         'font-size:13px">' + "".join(bullets) + '</ul>')

        # Back-edge table
        edge_rows = []
        for c in back_edges:
            target = state.get_node(c.target_sid)
            target_label = c.target_sid or "?"
            if target and (target.hostname or target.ip):
                target_label += f' ({target.hostname or target.ip})'
            sap_all = ('<span class="risk-pill" style="background:#8b0000">'
                        'yes</span>' if c.has_sap_all else "—")
            if c.check_error:
                note = _hesc(c.check_error[:80])
            elif c.tested and c.logon_successful:
                note = "logon OK"
            elif c.tested:
                note = "credential rejected"
            else:
                note = "not tested"
            edge_rows.append(
                f'<tr>'
                f'<td class="mono"><code>{_hesc(c.destination_name or "?")}</code></td>'
                f'<td>{_hesc(target_label)}</td>'
                f'<td class="mono"><code>{_hesc(c.rfc_user or "?")}</code></td>'
                f'<td>{_hesc(c.client or "?")}</td>'
                f'<td>{sap_all}</td>'
                f'<td>{note}</td>'
                f'</tr>')
        edge_table_html = ""
        if edge_rows:
            edge_table_html = (
                '<table class="grid" style="margin-top:10px"><thead><tr>'
                '<th>Destination</th><th>Target</th><th>User</th><th>Client</th>'
                '<th>SAP_ALL</th><th>Notes</th></tr></thead><tbody>'
                + "".join(edge_rows) + '</tbody></table>')

        # Password reuse callout
        pw_users: dict = {}
        for c in back_edges:
            if c.secstore_password and c.rfc_user:
                pw_users.setdefault(c.secstore_password, set()).add(
                    (c.rfc_user, c.target_sid))
        reuse = {p: v for p, v in pw_users.items() if len(v) > 1}
        reuse_html = ""
        if reuse:
            reuse_bullets = []
            for pw, pairs in reuse.items():
                pairs_str = ", ".join(
                    f'<code>{_hesc(u)}@{_hesc(s)}</code>'
                    for u, s in sorted(pairs))
                reuse_bullets.append(
                    f'<li>The same password unlocks {pairs_str} — one '
                    f'leak, multiple systems compromised.</li>')
            reuse_html = (
                '<p style="margin-top:10px;color:#8b0000;font-weight:600">'
                '⚠️ Password reuse detected:</p>'
                '<ul style="margin:4px 0 8px;padding-left:20px;font-size:13px">'
                + "".join(reuse_bullets) + '</ul>')

        blocks.append(
            f'<div style="margin-bottom:20px;padding:14px 16px;'
            f'background:#fafbfc;border-left:3px solid #e07f00;'
            f'border-radius:4px">'
            f'<h3 style="margin:0 0 8px;font-size:14px">'
            f'<code>{_hesc(subdomain)}</code> '
            f'<span style="color:#6b7280;font-weight:400">'
            f'(region <code>{_hesc(region)}</code>)</span></h3>'
            f'<p style="margin:0;font-size:13px">{headline}</p>'
            f'{mint_html}{edge_table_html}{reuse_html}'
            f'</div>')

    return (
        '<section id="sec-cloud-lat">'
        '<h2>🌉 Cloud ↔ on-prem lateral moves</h2>'
        f'<p style="font-size:12px;color:#6b7280;margin:0 0 16px">'
        f'SAPMAP established <b>{len(interesting)}</b> cloud-side lateral '
        f'entry point(s).  Each represents a working chain from on-prem '
        f'cert-auth (or workstation-side cert files) through SAP BTP\'s '
        f'XSUAA + Destination Service to on-prem back-ends whose '
        f'credentials leaked in the clear.'
        f'</p>'
        + "".join(blocks) + '</section>')


def _html_cert_auth_destinations_section(state: SAPMAPState) -> str:
    """Cert-authenticated Type-G / H HTTP destinations."""
    rows_data: list[tuple[str, str, str, str, str, bool]] = []
    for node in state.nodes.values():
        for c in state.get_connections_from(node.sid):
            if c.http_auth_type != "X509":
                continue
            is_btp = (getattr(c, "is_btp_dest", False)
                        or ".hana.ondemand.com" in (c.http_url or ""))
            rows_data.append((
                node.sid,
                c.destination_name or "?",
                c.http_url or "?",
                c.http_cert_pse or "?",
                c.target_sid or "",
                bool(is_btp),
            ))
    if not rows_data:
        return ""
    n_btp = sum(1 for r in rows_data if r[5])
    rows = []
    for src, dest, url, pse, tgt, is_btp in sorted(rows_data):
        rows.append(
            f'<tr>'
            f'<td class="mono"><b>{_hesc(src)}</b></td>'
            f'<td class="mono">{_hesc(dest)}</td>'
            f'<td class="mono" style="font-size:11px;word-break:break-all;'
            f'max-width:340px">{_hesc(url)}</td>'
            f'<td class="mono"><code>{_hesc(pse)}</code></td>'
            f'<td>{_hesc(tgt) if tgt else "—"}</td>'
            f'<td>{"☁️" if is_btp else "—"}</td>'
            f'</tr>')
    return (
        '<section id="sec-certauth">'
        '<h2>🔐 Certificate-authenticated HTTP destinations</h2>'
        f'<p style="font-size:12px;color:#6b7280;margin:0 0 12px">'
        f'{len(rows_data)} X.509 client-cert destination(s) discovered '
        f'({n_btp} pointing at BTP / <code>*.hana.ondemand.com</code>).  '
        f'These carry <b>no stored password</b> — auth uses a STRUST PSE '
        f'on the source system.  With <code>S_RFC</code> + '
        f'<code>S_ICF</code> on that source, an operator proxies HTTP '
        f'through <code>HTTP_CLIENT_CREATE_BY_DESTINATION</code>: the '
        f'kernel performs mutual-TLS transparently and the target sees '
        f'requests as coming from the SAP system itself.'
        f'</p>'
        '<table class="grid"><thead><tr>'
        '<th>Source</th><th>Destination</th><th>Target URL</th>'
        '<th>PSE</th><th>Target node</th><th>BTP</th>'
        '</tr></thead><tbody>' + "".join(rows) + '</tbody></table>'
        '</section>')


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
    created = sum(len(n.created_users) for n in nodes)
    secstore_total = sum(len(n.secstore_entries or []) for n in nodes)
    java_secstore_total = sum(len(n.java_secstore_entries or []) for n in nodes)
    sccs = (getattr(state, "scc_nodes", {}) or {})
    scc_pwned = sum(1 for s in sccs.values()
                    if getattr(s, "pwned", False)
                    or getattr(s, "default_creds_live", False))
    btp_subs = (getattr(state, "btp_subaccounts", {}) or {})
    btp_pwned = sum(1 for b in btp_subs.values()
                     if getattr(b, "pwned", False))
    # KPI totals mirror the GUI status-bar semantics (state.stats()):
    # every box on the map is a "system", so SAP + SCC + BTP are all
    # counted.  Reporting SAP-only here made "1/6 pwned" show up while
    # the operator saw "4/10" in the app — a discrepancy caught in
    # engagement review.
    total_systems = len(nodes) + len(sccs) + len(btp_subs)
    total_pwned = len(pwned) + scc_pwned + btp_pwned
    pct_pwned = (100 * total_pwned // total_systems) if total_systems else 0
    # Edge counts.  "Total" includes every RFC / HTTP / synthetic
    # destination on the map; "SAP_ALL" surfaces the biggest-blast-
    # radius edges so the KPI card reads as a risk number, not just a
    # topology number.
    conns = list(state.connections or [])
    conn_total = len(conns)
    conn_sap_all = sum(1 for c in conns if getattr(c, "has_sap_all", False))
    conn_tested_ok = sum(1 for c in conns
                         if getattr(c, "logon_successful", False))

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
            + (
                # Structured remediation dict (catalog-attached) renders
                # as a full bordered card; legacy plain strings keep the
                # short single-line layout.
                _html_render_structured_remediation(f.remediation)
                if isinstance(f.remediation, dict)
                   and f.remediation.get("fix_summary")
                else (f'<div class="finding-rem"><b>Remediation:</b> '
                      f'{_hesc(str(f.remediation))}</div>'
                      if f.remediation else '')
              )
            + '</div>'
        )

    crit_html = "".join(_finding_card(s, f, "#f85149")
                         for s, f in crit_findings) or \
                 '<div class="muted">No critical findings.</div>'
    high_html = "".join(_finding_card(s, f, "#db6d28")
                         for s, f in high_findings) or \
                 '<div class="muted">No high findings.</div>'

    # Inventory rows — SAP nodes first, then SCC nodes appended
    # so management sees the whole landscape in one glance.
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
    # Cloud Connector rows folded into the same table.  Columns mapped:
    #   SID    -> "SCC"
    #   Type   -> "Cloud Connector"
    #   OS/DB  -> "—" (not applicable)
    #   Host   -> the SCC host
    #   Status -> ⚡ PWNED if default-creds live or pwned flag set
    #   Tier   -> SCC version (so the operator sees "2.16.2" inline)
    #   Crit   -> CVE-suspected count
    #   "RFC creds" column repurposed -> mapping count
    for host, sn in sorted(sccs.items()):
        sn_pwned = (getattr(sn, "pwned", False)
                     or getattr(sn, "default_creds_live", False))
        cve_count = len(getattr(sn, "cves_suspected", []) or [])
        nmap = len(getattr(sn, "mappings", []) or [])
        version = getattr(sn, "version", "") or "?"
        pwned_badge = ('<span class="badge badge-pwned">⚡ PWNED</span>'
                        if sn_pwned else "")
        crit_pill = (f'<span class="num-pill num-pill-bad">{cve_count}</span>'
                      if cve_count else
                      '<span class="num-pill num-pill-ok">0</span>')
        inv_rows += (
            f'<tr>'
            f'<td class="mono"><b>SCC</b></td>'
            f'<td>Cloud Connector</td>'
            f'<td>—</td>'
            f'<td>—</td>'
            f'<td class="mono">{_hesc(host)}</td>'
            f'<td>{pwned_badge}</td>'
            f'<td title="SCC version">{_hesc(version)}</td>'
            f'<td>{crit_pill}</td>'
            f'<td class="num" title="cloud-to-on-premise mappings">{nmap}</td>'
            f'</tr>'
        )

    # BTP subaccounts in the same inventory grid — keeps everything
    # the operator pwned visible in one table.  Cleartext-captured
    # destinations count as "Critical" in the grid (mirrors how the
    # GUI flags them); linked-on-prem count goes in the right-hand
    # numeric column for parity with SCC's "mappings" cell.
    btp_subs = (getattr(state, "btp_subaccounts", {}) or {})
    for uuid, sub in sorted(
            btp_subs.items(),
            key=lambda kv: (getattr(kv[1], "subdomain", "")
                             or kv[0])):
        dests = list(getattr(sub, "destinations", []) or [])
        cleartext_n = sum(1 for d in dests
                          if getattr(d, "cleartext_captured", False)
                          or (isinstance(d, dict)
                              and d.get("cleartext_captured")))
        linked_n = sum(1 for d in dests
                       if (getattr(d, "linked_target_sid", "")
                           or (isinstance(d, dict)
                               and d.get("linked_target_sid"))))
        sub_label = (getattr(sub, "subdomain", "")
                     or getattr(sub, "display_name", "")
                     or uuid[:8])
        bn_pwned = bool(getattr(sub, "pwned", False))
        pwned_badge = ('<span class="badge badge-pwned">⚡ PWNED</span>'
                        if bn_pwned else "")
        crit_pill = (
            f'<span class="num-pill num-pill-bad">{cleartext_n}</span>'
            if cleartext_n else
            '<span class="num-pill num-pill-ok">0</span>')
        inv_rows += (
            f'<tr>'
            f'<td class="mono"><b>BTP</b></td>'
            f'<td>BTP subaccount</td>'
            f'<td>—</td>'
            f'<td>—</td>'
            f'<td class="mono">{_hesc(sub_label)}</td>'
            f'<td>{pwned_badge}</td>'
            f'<td title="BTP region">'
            f'{_hesc(getattr(sub, "region", "") or "?")}</td>'
            f'<td>{crit_pill}</td>'
            f'<td class="num" title="destinations linked to on-prem">'
            f'{linked_n}</td>'
            f'</tr>'
        )

    # Recommendations: structural (derived from state) + per-finding
    derived = _derive_landscape_recommendations(state)
    cat_colors = {
        "Gateway hardening":         "#f85149",
        "Message Server hardening":  "#f85149",
        "Java patching":             "#f85149",
        "SAProuter hardening":       "#db6d28",
        "Default credentials":       "#db6d28",
        "Secure Store rotation":     "#db6d28",
        "SAP Cloud Connector":       "#db6d28",
        "Incident response":         "#f85149",
        "RFC trust review":          "#d4a72c",
    }
    derived_html = ""
    for r in derived:
        col = cat_colors.get(r["category"], "#0969da")
        derived_html += (
            f'<div class="reco" style="border-left:4px solid {col}">'
            f'<div class="reco-head">'
            f'<span class="reco-cat" style="background:{col}">'
            f'{_hesc(r["category"])}</span>'
            f'<span class="reco-title">{_hesc(r["title"])}</span>'
            f'</div>'
            f'<div class="reco-meta"><b>Applies to:</b> '
            f'{_hesc(r["scope"])} · <b>Refs:</b> {_hesc(r["refs"])}</div>'
            f'<div class="reco-body">{_hesc(r["body"])}</div>'
            f'</div>'
        )

    # Structured Hardening checklist — catalog-driven, supersedes the
    # older per-finding plain-string roll-up.  Aggregates by fix_summary
    # and lists every SID needing each fix.
    hardening_html = _build_hardening_html(state)

    # Legacy per-finding plain-string remediation roll-up — only included
    # as a fallback when no structured remediation is present (older
    # .sapmap state files predate the catalog).  Skips dict-shaped
    # remediations (those already rendered in Hardening checklist).
    seen = set()
    rec_items = []
    if not hardening_html:
        for n in state.nodes.values():
            for f in n.findings or []:
                r = f.remediation
                if isinstance(r, dict) or not isinstance(r, str):
                    continue
                r = (r or "").strip()
                if r and r not in seen:
                    seen.add(r)
                    rec_items.append(
                        '<li><b>' + _hesc(n.sid) + '</b> — '
                        + _hesc(r) + '</li>')
    finding_html = ("<ol>" + "".join(rec_items) + "</ol>") if rec_items else ""

    if hardening_html or derived_html or finding_html:
        rec_html = (
            (('<h3 style="margin:18px 0 10px;color:#374151;font-size:14px">'
              'Hardening checklist</h3>'
              + hardening_html)
             if hardening_html else "")
            + (('<h3 style="margin:18px 0 10px;color:#374151;font-size:14px">'
              'Landscape-wide structural remediations</h3>'
              + derived_html)
             if derived_html else "")
            + (('<h3 style="margin:24px 0 10px;color:#374151;font-size:14px">'
                'Per-finding remediation</h3>' + finding_html)
               if finding_html else "")
        )
    else:
        rec_html = ('<div class="muted">No remediation guidance applicable — '
                     'landscape is either empty or fully patched.</div>')

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

    # User capability inventory — translate raw SAP_ALL into business
    # English.  One block per (user, client) pair we own.  Skipped
    # entirely when the analyser hasn't run yet.
    cap_blocks = []
    cap_sev_colors = {5: "#e74c3c", 4: "#e67e22",
                       3: "#f1c40f", 2: "#3498db", 1: "#95a5a6"}
    cap_sev_labels = {5: "CRITICAL", 4: "HIGH",
                       3: "MEDIUM", 2: "LOW", 1: "INFO"}
    for sid, n in sorted(state.nodes.items()):
        for r in (n.capability_results or []):
            caps = r.get("capabilities") or []
            sev_max = max((c.get("severity", 1) for c in caps),
                            default=1)
            sev_color = cap_sev_colors.get(sev_max, "#95a5a6")
            sev_label = cap_sev_labels.get(sev_max, "INFO")
            user = _hesc(r.get("username", "?"))
            client = _hesc(r.get("client", "?"))
            blast = _hesc(r.get("blast_radius", ""))
            summary = _hesc(r.get("summary", ""))
            rows_html = ""
            for c in sorted(caps,
                            key=lambda x: -x.get("severity", 0)):
                col = cap_sev_colors.get(c.get("severity", 1),
                                          "#95a5a6")
                tbls = ", ".join(c.get("tables", []) or []) or "—"
                rows_html += (
                    f'<tr>'
                    f'<td><span class="badge" style="background:'
                    f'{col};color:#fff;font-size:10px;padding:'
                    f'2px 6px;border-radius:3px">'
                    f'{cap_sev_labels.get(c.get("severity", 1), "INFO")}'
                    f'</span></td>'
                    f'<td class="mono">{_hesc(c.get("auth_object", ""))}</td>'
                    f'<td>{_hesc(c.get("capability", ""))}</td>'
                    f'<td class="mono" style="font-size:11px">'
                    f'{_hesc(tbls)}</td>'
                    f'</tr>')
            cap_blocks.append(
                f'<div style="border-left:4px solid {sev_color};'
                f'padding:14px 18px;margin:14px 0;'
                f'background:#fbfbfd;border-radius:6px">'
                f'<div style="font-size:12px;font-weight:600;'
                f'color:{sev_color};text-transform:uppercase;'
                f'letter-spacing:.4px;margin-bottom:4px">'
                f'{sev_label} — {user} on {_hesc(sid)} client {client}'
                f'</div>'
                f'<p style="margin:0 0 6px;font-size:13.5px;'
                f'line-height:1.55">{summary}</p>'
                f'<p style="margin:0 0 10px;font-size:12px;'
                f'color:#6b7280;font-style:italic">'
                f'Blast-radius: {blast}</p>'
                f'<table class="grid" style="font-size:12px">'
                f'<thead><tr><th>Tier</th><th>Auth object</th>'
                f'<th>Capability</th><th>Affected tables</th>'
                f'</tr></thead><tbody>{rows_html}</tbody></table>'
                f'</div>')
    if cap_blocks:
        capability_html = (
            '<section id="sec-capability"><h2>📊 User capability inventory</h2>'
            '<p style="font-size:12px;color:#6b7280;margin:0 0 12px">'
            'What each user we own can actually do, mapped from raw '
            '<code>AGR_USERS</code> / <code>AGR_1251</code> / '
            '<code>UST04</code> rows to business capabilities.'
            '</p>' + "".join(cap_blocks) + '</section>')
    else:
        capability_html = ""

    # Cloud / trust-edge sections that Markdown had all along — porting
    # into HTML for issue #31 parity.  Each returns "" when the
    # underlying landscape state doesn't warrant the section, so empty
    # engagements don't accumulate empty section blocks.
    scc_section_html = _html_scc_section(state)
    btp_section_html = _html_btp_section(state)
    cloud_lat_section_html = _html_cloud_lateral_section(state)
    cert_dest_section_html = _html_cert_auth_destinations_section(state)
    attack_coverage_html = _html_attack_coverage_section(state)
    med_info_html = _html_medium_info_findings_section(state)
    created_users_html = _html_created_users_section(state)
    impact_html = _html_impact_section(state)
    secstore_html = _html_secstore_section(state)
    persistence_html = _html_persistence_section(state)
    evasion_html = _html_evasion_section(state)

    # Table of contents — one row per section that actually rendered.
    # Section IDs match the anchors on the <section id="..."> tags
    # below.  Inline sections (map, findings, chains, inventory, creds,
    # recommendations) always render; the rest are gated on their
    # builder returning non-empty HTML.
    _toc_entries = [
        ("sec-landscape-map", "🗺️ Landscape map",        True),
        ("sec-critical",      "🛑 Critical findings",     True),
        ("sec-high",          "⚠️ High findings",         True),
        ("sec-chains",        "🔗 Trust chains",          True),
        ("sec-inventory",     "🗺️ Landscape inventory",   True),
        ("sec-credentials",   "🔑 Recovered credentials", True),
        ("sec-capability",    "📊 User capability inventory",
                              bool(capability_html)),
        ("sec-scc",           "☁️ SAP Cloud Connectors",
                              bool(scc_section_html)),
        ("sec-btp",           "☁️ SAP BTP subaccounts",
                              bool(btp_section_html)),
        ("sec-cloud-lat",     "🌉 Cloud ↔ on-prem lateral moves",
                              bool(cloud_lat_section_html)),
        ("sec-certauth",      "🔐 Cert-auth HTTP destinations",
                              bool(cert_dest_section_html)),
        ("sec-medinfo",       "ℹ️ Medium & informational findings",
                              bool(med_info_html)),
        ("sec-impact",        "💰 Business impact",
                              bool(impact_html)),
        ("sec-secstore",      "🔐 Secure-Store recovery",
                              bool(secstore_html)),
        ("sec-users",         "👤 SAPMAP-created accounts",
                              bool(created_users_html)),
        ("sec-persistence",   "🕳️ Persistence footprint",
                              bool(persistence_html)),
        ("sec-attack",        "🎯 MITRE ATT&CK coverage",
                              bool(attack_coverage_html)),
        ("sec-opsec",         "🥷 OPSEC posture (evasion)",
                              bool(evasion_html)),
        ("sec-recommendations", "📋 Recommendations",    True),
    ]
    toc_items = "".join(
        f'<li><a href="#{sid}">{_hesc(label)}</a></li>'
        for sid, label, present in _toc_entries if present)
    toc_html = (
        '<nav class="toc" aria-label="Table of contents">'
        '<h2 style="margin:0 0 10px;font-size:14px;color:#374151;'
        'letter-spacing:.4px;text-transform:uppercase">Contents</h2>'
        '<ol style="margin:0;padding-left:22px;'
        'columns:2;column-gap:32px;line-height:1.7">'
        + toc_items + '</ol></nav>')

    # CSS block injected once into <style> for structured remediation
    # cards + Hardening-checklist cards.
    rem_block_css = _REM_BLOCK_CSS

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
  /* Table of contents */
  .toc{{background:#fff;border-radius:12px;padding:18px 24px;
        margin:0 0 24px;box-shadow:0 1px 3px rgba(0,0,0,.06);
        border-left:4px solid #0969da}}
  .toc a{{color:#0969da;text-decoration:none;font-size:13px}}
  .toc a:hover{{text-decoration:underline}}
  .toc li{{break-inside:avoid;margin-bottom:2px}}
  html{{scroll-behavior:smooth}}
  section{{scroll-margin-top:12px}}
  @media (max-width:640px){{.toc ol{{columns:1}}}}
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
  /* Structured remediation card (catalog-driven) — overrides the
     legacy .finding-rem look with a fuller bordered layout. */
{rem_block_css}
  .muted{{color:#8b949e;font-style:italic;padding:8px}}
  ol{{padding-left:22px;margin:0}} ol li{{margin-bottom:8px;font-size:14px}}
  .reco{{background:#fafbfc;border-radius:8px;padding:14px 18px;margin-bottom:12px}}
  .reco-head{{display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap}}
  .reco-cat{{display:inline-block;padding:3px 10px;border-radius:4px;
        color:#fff;font-weight:600;font-size:10px;letter-spacing:.5px;
        text-transform:uppercase}}
  .reco-title{{font-weight:600;font-size:14px;color:#1f2937}}
  .reco-meta{{font-size:11px;color:#6b7280;margin-bottom:8px}}
  .reco-body{{font-size:13px;color:#374151;line-height:1.55}}
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
    {_kpi_card("Systems discovered", str(total_systems),
                f"{abap} ABAP · {java} Java · {routers} SAProuter · "
                f"{len(sccs)} SCC · {len(btp_subs)} BTP",
                "#0969da")}
    {_kpi_card("Systems pwned", f"{total_pwned}/{total_systems}",
                f"{pct_pwned}% of landscape",
                "#db6d28" if total_pwned else "#3fb950")}
    {_kpi_card("Production pwned", str(len(pwned_prd)),
                ", ".join(n.sid for n in pwned_prd) or "none",
                "#f85149" if pwned_prd else "#3fb950")}
    {_kpi_card("Critical findings", str(len(crit_findings)),
                f"{len(high_findings)} HIGH",
                "#f85149" if crit_findings else "#3fb950")}
    {_kpi_card("Trust chains", str(chain_count),
                f"{prd_chain_count} reach PRD",
                "#f85149" if prd_chain_count else "#0969da")}
    {_kpi_card("Connections", str(conn_total),
                (f"{conn_sap_all} grant SAP_ALL · "
                 f"{conn_tested_ok} tested OK"
                 if conn_total else "no destinations captured"),
                "#f85149" if conn_sap_all else
                ("#0969da" if conn_total else "#d0d7de"))}
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
    {_kpi_card("BTP subaccounts", f"{len(btp_subs)}",
                (f"{btp_pwned} with cleartext destinations"
                 if btp_pwned else
                 ("0 cleartext captured" if btp_subs
                  else "none in scope")),
                "#f85149" if btp_pwned else
                ("#0969da" if btp_subs else "#d0d7de"))}
    {_kpi_card(
        "Cloud → on-prem laterals",
        f"{sum(1 for _c in conns if (_c.source_sid or '').startswith('BTP:') and _c.has_sap_all)}",
        (
          "confirmed cleartext + SAP_ALL"
          if any((c.source_sid or "").startswith("BTP:")
                 and c.has_sap_all for c in conns)
          else (f"{sum(1 for _c in conns if (_c.source_sid or '').startswith('BTP:') and _c.target_sid)}"
                 " BTP → on-prem edge(s) mapped"
                 if any((c.source_sid or '').startswith('BTP:')
                        for c in conns)
                 else "none captured")
        ),
        "#f85149"
        if any((c.source_sid or '').startswith('BTP:')
               and c.has_sap_all for c in conns)
        else ("#0969da"
              if any((c.source_sid or '').startswith('BTP:')
                     for c in conns)
              else "#d0d7de"))}
  </div>

  {toc_html}

  <section id="sec-landscape-map">
    <h2>🗺️ Landscape map</h2>
    <p style="font-size:12px;color:#6b7280;margin:0 0 14px">
      Auto-laid-out snapshot of every discovered system.  Pwned systems
      carry a ⚡ badge; production systems have a red halo.  Solid red
      arrows mark RFC trust edges that grant SAP_ALL on the target;
      dashed lines mark untested destinations.
    </p>
    {_build_landscape_svg(state)}
  </section>

  <section id="sec-critical">
    <h2>🛑 Critical findings ({len(crit_findings)})</h2>
    {crit_html}
  </section>

  <section id="sec-high">
    <h2>⚠️ High findings ({len(high_findings)})</h2>
    {high_html}
  </section>

  <section id="sec-chains">
    <h2>🔗 Lateral movement / trust chains ({chain_count})</h2>
    <table class="grid"><thead><tr>
      <th>Risk</th><th>Path</th><th>Hops</th><th>PRD</th><th>Entry</th>
    </tr></thead><tbody>{chain_rows_html}</tbody></table>
  </section>

  <section id="sec-inventory">
    <h2>🗺️ Landscape inventory</h2>
    <table class="grid"><thead><tr>
      <th>SID</th><th>Type</th><th>OS</th><th>DB</th><th>Host</th>
      <th>Status</th><th>Tier</th><th>Critical</th><th>RFC creds</th>
    </tr></thead><tbody>{inv_rows}</tbody></table>
  </section>

  <section id="sec-credentials">
    <h2>🔑 Recovered credentials</h2>
    <p style="font-size:12px;color:#6b7280;margin:0 0 12px">
      Passwords masked in this report — full plaintext lives in
      <code>loot/secstore/</code>, <code>loot/hashes/</code>, and
      <code>loot/scc/&lt;host&gt;/hashes_cracked.txt</code>.
    </p>
    {cred_table}
  </section>

  {capability_html}

  {scc_section_html}

  {btp_section_html}

  {cloud_lat_section_html}

  {cert_dest_section_html}

  {med_info_html}

  {impact_html}

  {secstore_html}

  {created_users_html}

  {persistence_html}

  {attack_coverage_html}

  {evasion_html}

  <section id="sec-recommendations">
    <h2>📋 Recommendations</h2>
    {rec_html}
  </section>

  <footer>SAPMAP — SAP Landscape Attack-Path Mapper · Report data
    sourced from in-memory session state at generation time.</footer>
</div>
</body></html>
"""
