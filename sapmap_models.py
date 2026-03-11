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
from dataclasses import dataclass, field
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

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "password": self.password,
            "client": self.client,
            "instance_nr": self.instance_nr,
            "verified": self.verified,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Credentials:
        return cls(**d)


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
    sapology_data: dict = field(default_factory=dict)
    gw_vulnerable: bool = False         # True if SAPXPG gateway exploit works
    position: Optional[tuple] = None    # (x, y) on map — None = auto-layout

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
            "sapology_data": self.sapology_data,
            "gw_vulnerable": self.gw_vulnerable,
            "position": list(self.position) if self.position else None,
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
            sapology_data=d.get("sapology_data", {}),
            gw_vulnerable=d.get("gw_vulnerable", False),
            position=tuple(d["position"]) if d.get("position") else None,
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
        }

    @classmethod
    def from_dict(cls, d: dict) -> RFCConnection:
        return cls(**d)


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
    scan_config: dict = field(default_factory=dict)
    timestamp: str = ""
    version: str = "1.0"

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    # -- Node management --

    def add_node(self, node: SAPNode) -> None:
        self.nodes[node.sid] = node
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
        """Remove a node and all associated connections/created users."""
        if sid not in self.nodes:
            return False
        del self.nodes[sid]
        self.connections = [c for c in self.connections
                           if c.source_sid != sid and c.target_sid != sid]
        self.created_users = [u for u in self.created_users if u.sid != sid]
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
        # Avoid duplicates
        for existing in self.connections:
            if (existing.source_sid == conn.source_sid and
                    existing.destination_name == conn.destination_name):
                # Update in place
                idx = self.connections.index(existing)
                self.connections[idx] = conn
                return
        self.connections.append(conn)

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

    # -- RFC check cache --

    def is_rfc_checked(self, destination_name: str) -> bool:
        return destination_name in self.rfc_check_cache

    def cache_rfc_check(self, destination_name: str, result: dict) -> None:
        self.rfc_check_cache[destination_name] = result

    def reset_rfc_cache(self) -> None:
        self.rfc_check_cache.clear()

    # -- Statistics --

    def stats(self) -> dict:
        return {
            "systems": len(self.nodes),
            "connections": len(self.connections),
            "pwned": sum(1 for n in self.nodes.values() if n.pwned),
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
        return state

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_json(cls, json_str: str) -> SAPMAPState:
        return cls.from_dict(json.loads(json_str))
