#!/usr/bin/env python3
"""
SAPMAP Business Impact Assessment Engine

Demonstrates the business impact of an SAP breach by querying real data
from compromised systems. Each scenario reads specific tables and produces
a headline, record count, sample data, and business-language impact message.

Scenarios are registered via the @impact_scenario decorator — add new ones
by writing a single function, no other changes needed.

Usage:
    results = assess_all(node, creds)
    for r in results:
        print(f"{r.severity_label}: {r.headline}")
"""

import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

from sapmap_models import SAPNode, Credentials, Severity, SEVERITY_LABELS

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ImpactResult:
    scenario: str
    category: str
    severity: Severity
    headline: str
    record_count: int = 0
    sample_records: list = field(default_factory=list)
    business_message: str = ""
    error: str = ""
    icon: str = ""

    @property
    def severity_label(self) -> str:
        return SEVERITY_LABELS.get(self.severity, "UNKNOWN")

    def to_dict(self) -> dict:
        return {
            "scenario": self.scenario,
            "category": self.category,
            "severity": int(self.severity),
            "severity_label": self.severity_label,
            "headline": self.headline,
            "record_count": self.record_count,
            "sample_records": self.sample_records[:10],
            "business_message": self.business_message,
            "icon": self.icon,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Scenario registry
# ---------------------------------------------------------------------------

_SCENARIOS: list[tuple[str, str, str, Severity, str, Callable]] = []


def impact_scenario(name: str, category: str, severity: Severity,
                    icon: str = ""):
    """Decorator to register a business impact scenario."""
    def decorator(func: Callable):
        _SCENARIOS.append((name, category, func.__doc__ or "", severity, icon, func))
        return func
    return decorator


def list_scenarios() -> list[dict]:
    return [{"name": n, "category": c, "description": d,
             "severity": int(s), "severity_label": SEVERITY_LABELS.get(s, ""),
             "icon": ic}
            for n, c, d, s, ic, _ in _SCENARIOS]


# ---------------------------------------------------------------------------
# Table reader helper
# ---------------------------------------------------------------------------

def _read_table(conn, table: str, fields: list, where: str = "",
                max_rows: int = 500) -> list[dict]:
    """Read an SAP table via RFC_READ_TABLE. Returns list of dicts."""
    params = {
        "QUERY_TABLE": table,
        "DELIMITER": "|",
        "ROWCOUNT": max_rows,
        "FIELDS": [{"FIELDNAME": f} for f in fields],
    }
    if where:
        options = []
        while where:
            options.append({"TEXT": where[:72]})
            where = where[72:]
        params["OPTIONS"] = options

    try:
        result = conn.call("RFC_READ_TABLE", **params)
    except Exception as e:
        logger.debug(f"RFC_READ_TABLE {table} failed: {e}")
        return []

    field_meta = result.get("FIELDS", [])
    if not field_meta:
        return []
    col_names = [f.get("FIELDNAME", "") for f in field_meta]

    rows = []
    for row in result.get("DATA", []):
        wa = row.get("WA", "")
        vals = wa.split("|")
        d = {}
        for i, col in enumerate(col_names):
            d[col] = vals[i].strip() if i < len(vals) else ""
        rows.append(d)
    return rows


def _format_eur(value_str: str) -> str:
    """Format a numeric string as EUR amount."""
    if value_str is None:
        return ""
    try:
        v = float(str(value_str).replace(",", "."))
        if v >= 1_000_000:
            return f"\u20ac{v/1_000_000:.1f}M"
        if v >= 1_000:
            return f"\u20ac{v/1_000:.0f}K"
        return f"\u20ac{v:,.0f}"
    except (ValueError, TypeError):
        return value_str


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

@impact_scenario("salary_exfiltration", "HR / Employee Data", Severity.CRITICAL,
                 icon="\U0001F4B0")
def _salary_exfiltration(conn, node):
    """Export all employee names and annual salaries."""
    people = _read_table(conn, "PA0002", ["PERNR", "VORNA", "NACHN"], max_rows=9999)
    salaries = _read_table(conn, "PA0008", ["PERNR", "ANSAL", "DIVGV", "WAESSION"],
                           max_rows=9999)
    if not people and not salaries:
        return ImpactResult(
            scenario="salary_exfiltration", category="HR / Employee Data",
            severity=Severity.INFO, headline="No HR data found",
            icon="\U0001F4B0",
        )

    sal_map = {}
    for s in salaries:
        pernr = s.get("PERNR", "")
        try:
            annual = float(s.get("ANSAL", "0").replace(",", "."))
        except ValueError:
            annual = 0
        currency = s.get("WAESSION", "EUR").strip() or "EUR"
        if pernr and annual > 0:
            sal_map[pernr] = (annual, currency)

    records = []
    total_salary = 0
    for p in people:
        pernr = p.get("PERNR", "")
        name = f"{p.get('VORNA', '')} {p.get('NACHN', '')}".strip()
        if pernr in sal_map:
            annual, cur = sal_map[pernr]
            total_salary += annual
            records.append({
                "employee_id": pernr,
                "name": name,
                "annual_salary": f"{annual:,.0f}",
                "currency": cur,
            })

    if not records:
        records = [{"employee_id": p.get("PERNR",""), "name": f"{p.get('VORNA','')} {p.get('NACHN','')}".strip()} for p in people[:10]]

    n = len(records) or len(people)
    headline = f"{n} employee salaries exposed" if records else f"{len(people)} employees found (no salary data)"
    if total_salary > 0:
        headline = f"{n} employees \u2014 {_format_eur(str(total_salary))} total annual compensation"

    return ImpactResult(
        scenario="salary_exfiltration", category="HR / Employee Data",
        severity=Severity.CRITICAL, headline=headline,
        record_count=n, sample_records=records[:20],
        business_message="An attacker can export every employee's name and compensation in seconds \u2014 instant GDPR breach and reputational damage.",
        icon="\U0001F4B0",
    )


@impact_scenario("vendor_bank_fraud", "Financial Fraud", Severity.CRITICAL,
                 icon="\U0001F3E6")
def _vendor_bank_fraud(conn, node):
    """Expose vendor bank details — enables payment redirect fraud."""
    vendors = _read_table(conn, "LFA1", ["LIFNR", "NAME1", "ORT01", "LAND1"],
                          max_rows=500)
    bank_details = _read_table(conn, "LFBK", ["LIFNR", "BANKS", "BANKL", "BANKN"],
                               max_rows=500)

    if not vendors:
        return ImpactResult(
            scenario="vendor_bank_fraud", category="Financial Fraud",
            severity=Severity.INFO, headline="No vendor data found",
            icon="\U0001F3E6",
        )

    bank_map = {}
    for b in bank_details:
        lifnr = b.get("LIFNR", "")
        if lifnr:
            bank_map[lifnr] = {
                "bank_country": b.get("BANKS", ""),
                "bank_key": b.get("BANKL", ""),
                "bank_account": b.get("BANKN", ""),
            }

    records = []
    for v in vendors:
        lifnr = v.get("LIFNR", "")
        rec = {
            "vendor_id": lifnr,
            "name": v.get("NAME1", ""),
            "city": v.get("ORT01", ""),
            "country": v.get("LAND1", ""),
        }
        if lifnr in bank_map:
            rec.update(bank_map[lifnr])
        records.append(rec)

    with_bank = sum(1 for r in records if r.get("bank_account"))
    headline = f"{len(records)} vendors"
    if with_bank:
        headline += f" \u2014 {with_bank} with bank details exposed"

    return ImpactResult(
        scenario="vendor_bank_fraud", category="Financial Fraud",
        severity=Severity.CRITICAL if with_bank else Severity.HIGH,
        headline=headline,
        record_count=len(records), sample_records=records[:20],
        business_message="An attacker can view and modify vendor bank accounts \u2014 redirecting payments worth millions to attacker-controlled accounts.",
        icon="\U0001F3E6",
    )


@impact_scenario("purchase_order_exposure", "Procurement", Severity.HIGH,
                 icon="\U0001F4E6")
def _purchase_order_exposure(conn, node):
    """Expose purchase orders with values and vendor details."""
    po_headers = _read_table(conn, "EKKO",
                             ["EBELN", "LIFNR", "BEDAT", "WAERS"],
                             max_rows=500)
    po_items = _read_table(conn, "EKPO",
                           ["EBELN", "EBELP", "TXZ01", "MENGE", "NETPR"],
                           max_rows=2000)

    if not po_headers:
        return ImpactResult(
            scenario="purchase_order_exposure", category="Procurement",
            severity=Severity.INFO, headline="No purchase order data found",
            icon="\U0001F4E6",
        )

    item_map = {}
    total_value = 0
    for item in po_items:
        ebeln = item.get("EBELN", "")
        try:
            val = float(item.get("NETPR", "0").replace(",", "."))
        except ValueError:
            val = 0
        try:
            qty = float(item.get("MENGE", "0").replace(",", "."))
        except ValueError:
            qty = 1
        line_val = val * qty if qty > 0 else val
        total_value += line_val
        if ebeln not in item_map:
            item_map[ebeln] = []
        item_map[ebeln].append({
            "item": item.get("EBELP", ""),
            "description": item.get("TXZ01", ""),
            "quantity": item.get("MENGE", ""),
            "net_price": item.get("NETPR", ""),
        })

    records = []
    for h in po_headers:
        ebeln = h.get("EBELN", "")
        records.append({
            "po_number": ebeln,
            "vendor": h.get("LIFNR", ""),
            "date": h.get("BEDAT", ""),
            "currency": h.get("WAERS", "EUR"),
            "items": item_map.get(ebeln, []),
            "item_count": len(item_map.get(ebeln, [])),
        })

    headline = f"{len(records)} purchase orders \u2014 {_format_eur(str(total_value))} total value"

    return ImpactResult(
        scenario="purchase_order_exposure", category="Procurement",
        severity=Severity.HIGH, headline=headline,
        record_count=len(records), sample_records=records[:20],
        business_message="Purchase orders can be created, modified, or redirected to attacker-controlled vendors without approval.",
        icon="\U0001F4E6",
    )


@impact_scenario("user_account_takeover", "Identity & Access", Severity.CRITICAL,
                 icon="\U0001F464")
def _user_account_takeover(conn, node):
    """Enumerate all SAP users with password hashes and role assignments."""
    users = _read_table(conn, "USR02",
                        ["BNAME", "USTYP", "UFLAG", "TRDAT", "BCODE"],
                        max_rows=9999)
    roles = _read_table(conn, "AGR_USERS", ["UNAME", "AGR_NAME"],
                        max_rows=9999)

    if not users:
        return ImpactResult(
            scenario="user_account_takeover", category="Identity & Access",
            severity=Severity.INFO, headline="No user data accessible",
            icon="\U0001F464",
        )

    role_map = {}
    for r in roles:
        uname = r.get("UNAME", "")
        role = r.get("AGR_NAME", "")
        if uname not in role_map:
            role_map[uname] = []
        if role:
            role_map[uname].append(role)

    admin_count = 0
    with_hash = 0
    records = []
    for u in users:
        bname = u.get("BNAME", "")
        bcode = u.get("BCODE", "")
        user_roles = role_map.get(bname, [])
        is_admin = any("ADMIN" in r.upper() or "SAP_ALL" in r.upper()
                       or "S_A.SYSTEM" in r.upper() for r in user_roles)
        if is_admin:
            admin_count += 1
        if bcode and bcode.strip() and bcode.strip() != "00000000":
            with_hash += 1
        records.append({
            "username": bname,
            "type": u.get("USTYP", ""),
            "locked": "Yes" if u.get("UFLAG", "0") != "0" else "No",
            "last_logon": u.get("TRDAT", ""),
            "has_hash": "Yes" if (bcode and bcode.strip() and bcode.strip() != "00000000") else "No",
            "roles": user_roles[:5],
            "is_admin": is_admin,
        })

    headline = f"{len(records)} users enumerated"
    parts = []
    if admin_count:
        parts.append(f"{admin_count} admin accounts")
    if with_hash:
        parts.append(f"{with_hash} password hashes crackable")
    if parts:
        headline += f" \u2014 {', '.join(parts)}"

    return ImpactResult(
        scenario="user_account_takeover", category="Identity & Access",
        severity=Severity.CRITICAL, headline=headline,
        record_count=len(records), sample_records=records[:20],
        business_message="An attacker can enumerate all users, crack passwords offline, and identify which accounts have administrator access.",
        icon="\U0001F464",
    )


@impact_scenario("customer_data_breach", "Data Privacy / GDPR", Severity.HIGH,
                 icon="\U0001F465")
def _customer_data_breach(conn, node):
    """Export customer names and addresses — GDPR-reportable breach."""
    customers = _read_table(conn, "KNA1",
                            ["KUNNR", "NAME1", "STRAS", "ORT01", "PSTLZ", "LAND1"],
                            max_rows=500)

    if not customers:
        return ImpactResult(
            scenario="customer_data_breach", category="Data Privacy / GDPR",
            severity=Severity.INFO, headline="No customer data found",
            icon="\U0001F465",
        )

    records = []
    for c in customers:
        records.append({
            "customer_id": c.get("KUNNR", ""),
            "name": c.get("NAME1", ""),
            "street": c.get("STRAS", ""),
            "city": c.get("ORT01", ""),
            "postal_code": c.get("PSTLZ", ""),
            "country": c.get("LAND1", ""),
        })

    return ImpactResult(
        scenario="customer_data_breach", category="Data Privacy / GDPR",
        severity=Severity.HIGH,
        headline=f"{len(records)} customers with full PII \u2014 GDPR-reportable breach",
        record_count=len(records), sample_records=records[:20],
        business_message="Customer personally identifiable information can be mass-exported \u2014 a mandatory GDPR breach notification within 72 hours.",
        icon="\U0001F465",
    )


@impact_scenario("supply_chain_intel", "Supply Chain / IP", Severity.HIGH,
                 icon="\u2699\uFE0F")
def _supply_chain_intel(conn, node):
    """Expose material catalog, BOMs, and procurement strategy."""
    materials = _read_table(conn, "MARA", ["MATNR", "MTART", "MATKL"],
                            max_rows=500)
    mat_texts = _read_table(conn, "MAKT", ["MATNR", "MAKTX"],
                            max_rows=500)

    if not materials:
        return ImpactResult(
            scenario="supply_chain_intel", category="Supply Chain / IP",
            severity=Severity.INFO, headline="No material data found",
            icon="\u2699\uFE0F",
        )

    text_map = {m.get("MATNR", ""): m.get("MAKTX", "") for m in mat_texts}

    records = []
    for m in materials:
        matnr = m.get("MATNR", "")
        records.append({
            "material": matnr,
            "type": m.get("MTART", ""),
            "group": m.get("MATKL", ""),
            "description": text_map.get(matnr, ""),
        })

    return ImpactResult(
        scenario="supply_chain_intel", category="Supply Chain / IP",
        severity=Severity.HIGH,
        headline=f"{len(records)} materials \u2014 full product catalog exposed",
        record_count=len(records), sample_records=records[:20],
        business_message="Your entire product catalog, material descriptions, and procurement strategy \u2014 a competitor's dream on a USB stick.",
        icon="\u2699\uFE0F",
    )


@impact_scenario("sales_revenue", "Financial / Revenue", Severity.CRITICAL,
                 icon="\U0001F4C8")
def _sales_revenue(conn, node):
    """Export sales orders showing customer revenue and order pipeline."""
    orders = _read_table(conn, "VBAK",
                         ["VBELN", "KUNNR", "NETWR", "WAERK", "ERDAT"],
                         max_rows=500)
    if not orders:
        return ImpactResult(
            scenario="sales_revenue", category="Financial / Revenue",
            severity=Severity.INFO, headline="No sales order data found",
            icon="\U0001F4C8",
        )

    customers = _read_table(conn, "KNA1", ["KUNNR", "NAME1"], max_rows=500)
    cust_map = {c.get("KUNNR", ""): c.get("NAME1", "") for c in customers}

    total = 0
    records = []
    for o in orders:
        try:
            val = float(o.get("NETWR", "0").replace(",", "."))
        except ValueError:
            val = 0
        total += val
        kunnr = o.get("KUNNR", "")
        records.append({
            "order": o.get("VBELN", ""),
            "customer_id": kunnr,
            "customer_name": cust_map.get(kunnr, ""),
            "net_value": o.get("NETWR", ""),
            "currency": o.get("WAERK", "EUR"),
            "date": o.get("ERDAT", ""),
        })

    headline = f"{len(records)} sales orders \u2014 {_format_eur(str(total))} total revenue"

    return ImpactResult(
        scenario="sales_revenue", category="Financial / Revenue",
        severity=Severity.CRITICAL, headline=headline,
        record_count=len(records), sample_records=records[:20],
        business_message="Complete sales pipeline with customer names and order values \u2014 your entire commercial strategy exposed.",
        icon="\U0001F4C8",
    )


@impact_scenario("production_sabotage", "Operations / Manufacturing", Severity.HIGH,
                 icon="\U0001F3ED")
def _production_sabotage(conn, node):
    """Expose production orders — modification enables manufacturing disruption."""
    prod_orders = _read_table(conn, "AUFK",
                              ["AUFNR", "AUART", "ERDAT", "OBJNR"],
                              max_rows=500)
    if not prod_orders:
        planned = _read_table(conn, "PLAF",
                              ["PLNUM", "MATNR", "GSMNG", "PSTTR"],
                              max_rows=500)
        if planned:
            records = [{"planned_order": p.get("PLNUM",""), "material": p.get("MATNR",""),
                        "quantity": p.get("GSMNG",""), "start_date": p.get("PSTTR","")}
                       for p in planned]
            return ImpactResult(
                scenario="production_sabotage", category="Operations / Manufacturing",
                severity=Severity.HIGH,
                headline=f"{len(records)} planned orders \u2014 production schedule modifiable",
                record_count=len(records), sample_records=records[:20],
                business_message="Production schedules can be altered \u2014 causing delays, quality defects, or supply chain disruption.",
                icon="\U0001F3ED",
            )
        return ImpactResult(
            scenario="production_sabotage", category="Operations / Manufacturing",
            severity=Severity.INFO, headline="No production data found",
            icon="\U0001F3ED",
        )

    records = [{"order": o.get("AUFNR",""), "type": o.get("AUART",""),
                "created": o.get("ERDAT","")} for o in prod_orders]

    return ImpactResult(
        scenario="production_sabotage", category="Operations / Manufacturing",
        severity=Severity.HIGH,
        headline=f"{len(records)} production orders \u2014 modifiable without approval",
        record_count=len(records), sample_records=records[:20],
        business_message="Production orders can be altered to change quantities, routings, or dates \u2014 causing line shutdowns or quality defects reaching customers.",
        icon="\U0001F3ED",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def assess_one(node: SAPNode, creds: Credentials, scenario_name: str,
               conn=None) -> Optional[ImpactResult]:
    """Run a single impact scenario. Pass conn to reuse an RFC connection."""
    for name, cat, desc, sev, icon, func in _SCENARIOS:
        if name == scenario_name:
            try:
                if conn:
                    return func(conn, node)
                else:
                    import sapmap_rfc
                    with sapmap_rfc._get_connection(node, creds) as c:
                        return func(c, node)
            except Exception as e:
                return ImpactResult(
                    scenario=name, category=cat, severity=Severity.INFO,
                    headline=f"Assessment failed: {e}", error=str(e), icon=icon,
                )
    return None


def assess_all(node: SAPNode, creds: Credentials,
               conn=None, print_fn=None) -> list[ImpactResult]:
    """Run all registered impact scenarios against a node."""
    results = []
    pf = print_fn or print

    def _run(c):
        for name, cat, desc, sev, icon, func in _SCENARIOS:
            pf(f"[*] {node.sid}: Assessing {name}...")
            try:
                r = func(c, node)
                if r:
                    results.append(r)
                    label = r.severity_label
                    pf(f"  [{label}] {r.headline}")
            except Exception as e:
                pf(f"  [ERROR] {name}: {e}")
                results.append(ImpactResult(
                    scenario=name, category=cat, severity=Severity.INFO,
                    headline=f"Failed: {e}", error=str(e), icon=icon,
                ))

    if conn:
        _run(conn)
    else:
        import sapmap_rfc
        with sapmap_rfc._get_connection(node, creds) as c:
            _run(c)

    results.sort(key=lambda r: -int(r.severity))
    return results
