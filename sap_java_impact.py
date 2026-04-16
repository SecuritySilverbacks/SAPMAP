#!/usr/bin/env python3
"""
SAP Java Business Impact Assessment.

Parallel to sapmap_impact.py (which is ABAP-RFC driven), this module
inventories the deployed components of an AS Java stack via the
J2EE_CONFIGENTRY table reachable through our SecStore-decrypted JDBC
JSP, and runs lightweight pattern-matching scenarios against the
component name list to determine which business-impact stories apply
to this specific landscape.

Each scenario only **probes** — no exploitation, no destructive action.
The output is a board-room-language ImpactResult that says, in effect,
"if an attacker fully compromises the Java admin role on this node, X
will happen because component Y is installed".

Scenarios implemented (per user prioritisation, leaving out 1/3/4/6/9
which are exploit / data-extraction / disruptive actions covered
elsewhere):

  2.  PI / PO message tampering
  5.  NWDI / CTS+ supply-chain inject
  7.  HR self-service data exposure
  8.  KMC / Enterprise Search document repositories
  10. Audit-log tampering
"""

from __future__ import annotations

import logging
import re
from typing import Callable, Optional

from sapmap_models import SAPNode, Severity, SEVERITY_LABELS
from sapmap_impact import ImpactResult     # reuse the dataclass

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Scenario registry
# ---------------------------------------------------------------------------

# Each scenario is a callable: (component_names: list[str], extra: dict) -> ImpactResult|None
_SCENARIOS: list = []


def _register(name: str, category: str, severity: Severity, icon: str = ""):
    def decorator(func: Callable):
        _SCENARIOS.append((name, category, func.__doc__ or "",
                            severity, icon, func))
        return func
    return decorator


def list_scenarios() -> list:
    return [{"name": n, "category": c, "description": d.strip().splitlines()[0],
              "severity": int(s), "severity_label": SEVERITY_LABELS.get(s, ""),
              "icon": ic}
             for n, c, d, s, ic, _ in _SCENARIOS]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _matches(components: list, *patterns: str) -> list:
    """Return components whose lowercased name contains any of `patterns`."""
    out = []
    for c in components:
        cl = c.lower()
        if any(p.lower() in cl for p in patterns):
            out.append(c)
    return out


def _short(items: list, n: int = 6) -> list:
    """Sample of distinct names for executive display."""
    seen = []
    for x in items:
        if x not in seen:
            seen.append(x)
        if len(seen) >= n:
            break
    return seen


# ---------------------------------------------------------------------------
# Scenarios — Java variants of the prioritised business-impact list
# ---------------------------------------------------------------------------

@_register("PI/PO Message Tampering",
           "Java", Severity.CRITICAL, icon="\U0001F4B0")
def _pi_po_tampering(components: list, extra: dict) -> Optional[ImpactResult]:
    """Detect SAP Process Integration / Process Orchestration deployment.

    PI/PO routes payment files (SWIFT, ISO 20022, IDoc-to-bank), EDI
    messages, payroll outputs, and integration broker traffic through
    Java-side message mappings.  An attacker with admin can rewrite
    message mappings (BeneficiaryAccount, Amount, TaxID) or drop inline
    value-maps that silently alter outbound transactions — invisible
    to the ABAP side, financial impact unbounded.
    """
    hits = _matches(components,
                     "com.sap.aii.", "com.sap.xi.", "tc~aii~",
                     "tc~xi~", "PIDirectory", "PIMonitoring",
                     "IntegrationBuilder")
    if not hits:
        return None
    return ImpactResult(
        scenario="PI/PO Message Tampering",
        category="Java",
        severity=Severity.CRITICAL,
        icon="\U0001F4B0",
        headline=("SAP Process Integration / Orchestration is deployed — "
                  "outbound message flows can be silently modified"),
        record_count=len(hits),
        sample_records=_short(hits),
        business_message=(
            "An attacker with Java admin can rewrite PI/PO message "
            "mappings to redirect bank-payment beneficiaries, alter "
            "invoice amounts, or inject false EDI documents.  The "
            "downstream ABAP system has no visibility into the change "
            "— the message it sends and the message the bank receives "
            "differ.  Financial loss is bounded only by transaction "
            "limits, and forensic reconstruction requires correlating "
            "ERP and bank-side logs after the fact."
        ),
    )


@_register("NWDI / CTS+ Supply-Chain Inject",
           "Java", Severity.CRITICAL, icon="\U0001F4E6")
def _nwdi_cts_plus(components: list, extra: dict) -> Optional[ImpactResult]:
    """Detect Change & Transport Management deployment.

    NWDI and CTS+ stage transport packages on this Java engine before
    they're imported into production ABAP systems.  A compromised Java
    admin can poison transports, swap binaries, or inject ABAP code
    that's auto-released through the change-management workflow.
    """
    hits = _matches(components,
                     "tc~di~", "tc~lm~ctc~", "tc~cts~",
                     "ctsappl", "nwdi", "developmentinfrastructure",
                     "design~time")
    if not hits:
        return None
    sev = (Severity.CRITICAL if any("cts" in h.lower() or "nwdi" in h.lower()
                                       for h in hits)
            else Severity.HIGH)
    return ImpactResult(
        scenario="NWDI / CTS+ Supply-Chain Inject",
        category="Java",
        severity=sev,
        icon="\U0001F4E6",
        headline=("Transport / change-management infrastructure detected — "
                  "code can be staged to flow into production ABAP"),
        record_count=len(hits),
        sample_records=_short(hits),
        business_message=(
            "Transports staged on this Java engine flow into the "
            "production ABAP landscape via automated approval and "
            "release queues.  An attacker with Java admin can replace "
            "the contents of a queued transport with malicious ABAP, "
            "or add a new transport that auto-imports into PRD with "
            "the next scheduled run.  This converts a Java compromise "
            "into authenticated code execution on every downstream "
            "ABAP production system that the change-management process "
            "feeds — classic supply-chain attack with board-level "
            "implications."
        ),
    )


@_register("HR Self-Service Data Exposure",
           "Java", Severity.HIGH, icon="\U0001F4C4")
def _hr_ess_mss(components: list, extra: dict) -> Optional[ImpactResult]:
    """Detect ESS / MSS / HR / SuccessFactors-on-prem webapp deployment.

    Employee Self-Service, Manager Self-Service, and the on-prem
    SuccessFactors façade expose payroll, performance reviews,
    grievance letters, social-security numbers, and bank-account
    details for every employee.
    """
    hits = _matches(components,
                     "com.sap.pct.hr.", "tc~hcm~", "ess~", "mss~",
                     "hcm.sfsf", "successfactors", "pct.ess",
                     "pcui_gp", "pcuihrkm", "msshcm")
    if not hits:
        return None
    return ImpactResult(
        scenario="HR Self-Service Data Exposure",
        category="Java",
        severity=Severity.HIGH,
        icon="\U0001F4C4",
        headline=("Employee / Manager Self-Service deployed — payroll & "
                  "PII exposed"),
        record_count=len(hits),
        sample_records=_short(hits),
        business_message=(
            "ESS / MSS / SuccessFactors-on-prem expose every employee's "
            "payroll history, performance reviews, grievance letters, "
            "tax IDs, bank accounts and dependants.  A Java admin can "
            "impersonate any employee or directly query the underlying "
            "HCM datasource — full GDPR Article 9 (sensitive personal "
            "data) breach, mandatory 72-hour DPA notification, and "
            "potentially SOX-sensitive compensation disclosures."
        ),
    )


@_register("KMC / Document Repositories",
           "Java", Severity.HIGH, icon="\U0001F4DA")
def _kmc_documents(components: list, extra: dict) -> Optional[ImpactResult]:
    """Detect KMC, Knowledge Management, Collaboration, Enterprise Search.

    Portal-fronted document repositories typically hold contracts,
    M&A memos, board minutes, org charts.  A Portal admin role grants
    read-all access through the KMC API regardless of object-level
    permissions.
    """
    hits = _matches(components,
                     "com.sap.netweaver.coll.", "caf~km",
                     "com.sap.km.", "knowledgemanagement",
                     "tc~kmc~", "ep.coll", "tc~tm~ep~ear",
                     "trex", "enterprise.search")
    if not hits:
        return None
    return ImpactResult(
        scenario="KMC / Document Repositories",
        category="Java",
        severity=Severity.HIGH,
        icon="\U0001F4DA",
        headline=("Knowledge Management / collaboration repositories "
                  "deployed — portal-fronted document trove exposed"),
        record_count=len(hits),
        sample_records=_short(hits),
        business_message=(
            "Knowledge Management / KMC / TREX components front the "
            "company's document repositories — contracts, M&A memos, "
            "board minutes, org charts, sales pipeline, supplier "
            "agreements.  A Portal admin role bypasses object-level "
            "ACLs through the KMC API and Enterprise Search index, "
            "giving read-all to every document the Portal has ever "
            "touched.  High likelihood of recovering material non-"
            "public information that triggers regulator or "
            "shareholder-disclosure obligations."
        ),
    )


@_register("Audit-Log Tampering",
           "Java", Severity.HIGH, icon="\U0001F4DD")
def _audit_tampering(components: list, extra: dict) -> Optional[ImpactResult]:
    """Detect AS Java security audit log presence + forwarding configuration.

    The Security Audit Log on AS Java is configured via ConfigTool
    properties prefixed with `service.security.audit.`.  An attacker
    with Java admin can flip the destination, drop the file appender,
    or disable categories — primarily enabling everything else above
    to happen quietly.
    """
    audit_props = extra.get("audit_properties", [])
    has_components = bool(_matches(components,
                                       "tc~sec~", "tc~je~security",
                                       "com.sap.security.core.sda"))
    has_audit_props = any("audit" in p.lower() for p in audit_props)
    if not (has_components or has_audit_props):
        return None
    samples = audit_props[:6] if has_audit_props else _short(
        _matches(components, "tc~sec~"), 6)
    return ImpactResult(
        scenario="Audit-Log Tampering",
        category="Java",
        severity=Severity.HIGH,
        icon="\U0001F4DD",
        headline=("Security audit configuration is reachable — admin "
                  "can blind detection before any other action"),
        record_count=len(audit_props) or len(_matches(components, "tc~sec~")),
        sample_records=samples,
        business_message=(
            "The Java security audit log destination, file rotation, "
            "and category filters are owned by Java admin properties.  "
            "A compromised admin can flip the destination to a "
            "discarded path, disable the file appender, or down-filter "
            "categories so subsequent attacker actions don't appear in "
            "SIEM forwarders.  This is the classic enabler step that "
            "lets every other scenario in this list happen quietly — "
            "investigators see only the gap."
        ),
    )


# ---------------------------------------------------------------------------
# Top-level driver
# ---------------------------------------------------------------------------

def assess(components: list, audit_properties: list = None) -> list:
    """Run every registered scenario against the deployed-components list.

    Returns a list of ImpactResult, sorted by severity.
    """
    extra = {"audit_properties": audit_properties or []}
    results = []
    for name, cat, desc, sev, icon, func in _SCENARIOS:
        try:
            r = func(components, extra)
            if r is not None:
                results.append(r)
        except Exception as e:
            logger.exception(f"impact scenario {name!r} failed: {e}")
            results.append(ImpactResult(
                scenario=name, category=cat, severity=Severity.INFO,
                headline=f"Failed: {e}", error=str(e), icon=icon,
            ))
    results.sort(key=lambda r: -int(r.severity))
    return results
