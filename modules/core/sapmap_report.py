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

    pct_pwned = (100 * len(pwned) // len(nodes)) if nodes else 0

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
    btp_section = _btp_section(state)
    if btp_section:
        sections.append("---")
        sections.append("")
        sections.extend(btp_section)
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
    btp_subs = (getattr(state, "btp_subaccounts", {}) or {})
    btp_pwned = sum(1 for b in btp_subs.values()
                     if getattr(b, "pwned", False))
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

    seen = set()
    rec_items = []
    for n in state.nodes.values():
        for f in n.findings or []:
            r = (f.remediation or "").strip()
            if r and r not in seen:
                seen.add(r)
                rec_items.append(f'<li><b>{_hesc(n.sid)}</b> — {_hesc(r)}</li>')
    finding_html = ("<ol>" + "".join(rec_items) + "</ol>") if rec_items else ""

    if derived_html or finding_html:
        rec_html = (
            (('<h3 style="margin:18px 0 10px;color:#374151;font-size:14px">'
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
  </div>

  <section>
    <h2>🗺️ Landscape map</h2>
    <p style="font-size:12px;color:#6b7280;margin:0 0 14px">
      Auto-laid-out snapshot of every discovered system.  Pwned systems
      carry a ⚡ badge; production systems have a red halo.  Solid red
      arrows mark RFC trust edges that grant SAP_ALL on the target;
      dashed lines mark untested destinations.
    </p>
    {_build_landscape_svg(state)}
  </section>

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

  <section>
    <h2>📋 Recommendations</h2>
    {rec_html}
  </section>

  <footer>SAPMAP — SAP Landscape Attack-Path Mapper · Report data
    sourced from in-memory session state at generation time.</footer>
</div>
</body></html>
"""
