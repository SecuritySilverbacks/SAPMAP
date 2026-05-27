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
from dataclasses import dataclass, field, fields
from datetime import datetime
from enum import IntEnum
from typing import Any, Optional


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
    remediation: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "severity": int(self.severity),
            "severity_label": SEVERITY_LABELS.get(self.severity, "UNKNOWN"),
            "description": self.description,
            "remediation": self.remediation,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        return cls(
            name=d["name"],
            severity=Severity(d["severity"]),
            description=d.get("description", ""),
            remediation=d.get("remediation", ""),
            detail=d.get("detail", ""),
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
    clients: list = field(default_factory=list)     # [{"nr": "100", "category": "P"}, ...]
    is_production: bool = False
    findings: list = field(default_factory=list)    # [Finding, ...]
    has_critical_finding: bool = False
    pwned: bool = False
    credentials: list = field(default_factory=list) # [Credentials, ...]
    created_users: list = field(default_factory=list)  # [CreatedUser, ...]
    # Forged MYSAPSSO2 logon tickets — signed by THIS system's
    # SAPSYS.pse and usable across its STRUSTSSO2 trust subgraph.
    # See ForgedTicket / sap_mysapsso2.forge_ticket for details.
    forged_tickets: list = field(default_factory=list)  # [ForgedTicket, ...]
    # Last result of sap_profile_check.check_sso2_parameters().
    # Populated by the /api/node/<sid>/sso2_profile_check endpoint
    # (background job).  Shape matches check_sso2_parameters'
    # return value plus a ``started_at`` / ``completed_at`` ISO
    # timestamp so the GUI can tell "still running" from "done".
    # While the job is running, only ``started_at`` is set.
    sso2_check_result: dict = field(default_factory=dict)
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
    scc_links: list = field(default_factory=list)       # SCC hosts whose mappings reach this node
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
    linux_lpe_method: str = ""           # "copyfail" / "dirtyfrag" / ""

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
            "clients": self.clients,
            "is_production": self.is_production,
            "findings": [f.to_dict() for f in self.findings],
            "has_critical_finding": self.has_critical_finding,
            "pwned": self.pwned,
            "credentials": [c.to_dict() for c in self.credentials],
            "created_users": [u.to_dict() for u in self.created_users],
            "forged_tickets": [t.to_dict()
                               for t in self.forged_tickets],
            "sso2_check_result": dict(self.sso2_check_result),
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
            "scc_links": list(self.scc_links),
            "position": list(self.position) if self.position else None,
            "copyfail_vulnerable": self.copyfail_vulnerable,
            "copyfail_root_obtained": self.copyfail_root_obtained,
            "copyfail_kernel": self.copyfail_kernel,
            "dirtyfrag_vulnerable": self.dirtyfrag_vulnerable,
            "dirtyfrag_root_obtained": self.dirtyfrag_root_obtained,
            "dirtyfrag_kernel": self.dirtyfrag_kernel,
            "linux_lpe_method": self.linux_lpe_method,
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
            "oauth2_profiles": list(self.oauth2_profiles),
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
            clients=d.get("clients", []),
            is_production=d.get("is_production", False),
            findings=[Finding.from_dict(f) for f in d.get("findings", [])],
            has_critical_finding=d.get("has_critical_finding", False),
            pwned=d.get("pwned", False),
            credentials=[Credentials.from_dict(c) for c in d.get("credentials", [])],
            created_users=[CreatedUser.from_dict(u) for u in d.get("created_users", [])],
            forged_tickets=[ForgedTicket.from_dict(t)
                            for t in d.get("forged_tickets", [])],
            sso2_check_result=dict(d.get("sso2_check_result", {})),
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
            scc_links=list(d.get("scc_links", [])),
            position=tuple(d["position"]) if d.get("position") else None,
            copyfail_vulnerable=d.get("copyfail_vulnerable", False),
            copyfail_root_obtained=d.get("copyfail_root_obtained", False),
            copyfail_kernel=d.get("copyfail_kernel", ""),
            dirtyfrag_vulnerable=d.get("dirtyfrag_vulnerable", False),
            dirtyfrag_root_obtained=d.get("dirtyfrag_root_obtained", False),
            dirtyfrag_kernel=d.get("dirtyfrag_kernel", ""),
            linux_lpe_method=d.get("linux_lpe_method", ""),
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
            oauth2_profiles=list(d.get("oauth2_profiles", [])),
            capability_results=list(d.get("capability_results", [])),
            capability_row_counts=dict(
                d.get("capability_row_counts", {})),
        )
        return node


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

    # /SDF/RFC_CHECK results
    logon_successful: bool = False
    logon_tested: bool = False   # True after explicit logon test (Test RFCs)
    ping_ok: bool = False
    latency_ms: int = 0
    check_error: str = ""
    tested: bool = False

    # sapxpg remote test
    sapxpg_remote_works: bool = False

    # Connection type.  Default "rfc" covers classic Type-3 RFC plus
    # Type-T (where sapxpg_remote_works is the active marker).  "http"
    # is set for AS Java HTTP destinations pulled from J2EE_CONFIGENTRY
    # — Java→Java admin / service calls using BASICAUTH etc.
    conn_type: str = "rfc"          # "rfc" | "http"
    http_url: str = ""              # full target URL for HTTP destinations
    http_auth_type: str = ""        # BASICAUTHENTICATION | SSO2 | X509 | NONE
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

    def risk_level(self) -> str:
        """Return risk assessment for this connection."""
        if self.has_sap_all and self.logon_successful:
            return "CRITICAL"
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
            "conn_type": self.conn_type,
            "http_url": self.http_url,
            "http_auth_type": self.http_auth_type,
            "http_proxy": self.http_proxy,
            "http_target_platform": self.http_target_platform,
            "secstore_password": self.secstore_password,
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
    scc_nodes: dict = field(default_factory=dict)        # host -> SCCNode (Cloud Connectors)
    btp_subaccounts: dict = field(default_factory=dict)  # uuid -> BTPSubaccountNode
    scan_config: dict = field(default_factory=dict)
    timestamp: str = ""
    version: str = "1.0"

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    # -- Node management --

    def add_node(self, node: SAPNode) -> None:
        is_new = node.sid not in self.nodes
        self.nodes[node.sid] = node
        if is_new:
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

    # -- Connection management --

    def add_connection(self, conn: RFCConnection) -> None:
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
                idx = self.connections.index(existing)
                self.connections[idx] = conn
                break
        else:
            self.connections.append(conn)
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
                )
            except Exception:
                pass

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
        try:
            from sapmap_findings import emit_finding
            emit_finding(
                "CRITICAL", user.sid,
                f"User {user.username!r} created on client {user.client} "
                f"via {user.method} — system pwned",
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
                emit_finding(
                    "INFO", node.sid,
                    "Auto-downloading SecStore (RSECTAB) — triggered "
                    "by user creation; this is the high-value loot "
                    "operators always want first.",
                    ref="secstore.auto.download.start")
                print(f"[*] SecStore {node.sid} (auto): starting after "
                      f"user creation — using best credentials")
                results = download_and_decrypt(
                    node, creds, DEFAULT_KEY_HEX, state=self)
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
                        ref="secstore.auto.decrypted")
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
        # Count SAP nodes + SCCs + BTP subaccounts.  The map draws a
        # lightning bolt over any of those when their .pwned flag is
        # set, so the status-bar count has to include all three or
        # the operator sees an off-by-one (e.g. "Pwned: 1" while the
        # map shows 2 ⚡ symbols — one on S4H, one on the BTP cloud).
        scc_pwned = sum(1 for s in self.scc_nodes.values()
                        if getattr(s, "pwned", False))
        btp_pwned = sum(1 for b in (self.btp_subaccounts or {}).values()
                         if getattr(b, "pwned", False))
        return {
            "systems": len(self.nodes),
            "connections": len(self.connections),
            "pwned": (sum(1 for n in self.nodes.values() if n.pwned)
                      + scc_pwned + btp_pwned),
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
            "nodes": {sid: node.to_dict() for sid, node in self.nodes.items()},
            "connections": [c.to_dict() for c in self.connections],
            "created_users": [u.to_dict() for u in self.created_users],
            "created_destinations": self.created_destinations,
            "rfc_check_cache": self.rfc_check_cache,
            "forged_tickets": [t.to_dict()
                               for t in self.forged_tickets],
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
            rfc_check_cache=d.get("rfc_check_cache", {}),
        )
        for sid, node_d in d.get("nodes", {}).items():
            state.nodes[sid] = SAPNode.from_dict(node_d)
        state.connections = [RFCConnection.from_dict(c) for c in d.get("connections", [])]
        state.created_users = [CreatedUser.from_dict(u) for u in d.get("created_users", [])]
        state.created_destinations = d.get("created_destinations", [])
        state.forged_tickets = [ForgedTicket.from_dict(t)
                                for t in d.get("forged_tickets", [])]
        for host, scc_d in d.get("scc_nodes", {}).items():
            state.scc_nodes[host] = SCCNode.from_dict(scc_d)
        for uuid, sub_d in d.get("btp_subaccounts", {}).items():
            state.btp_subaccounts[uuid] = BTPSubaccountNode.from_dict(sub_d)
        return state

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_json(cls, json_str: str) -> SAPMAPState:
        return cls.from_dict(json.loads(json_str))
