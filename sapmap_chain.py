#!/usr/bin/env python3
"""
SAPMAP Trust Chain Analysis — RFC lateral movement path discovery.

Finds multi-hop attack paths through the SAP landscape by traversing
RFC connections from exploitable entry points to high-value targets
(production systems). Produces ranked TrustChain objects with headlines
suitable for business stakeholder presentations.

Usage:
    chains = analyze_chains(state)
    for c in chains:
        print(f"{c.headline}  ({c.total_hops} hops, {c.risk_label})")
"""

import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from sapmap_models import SAPMAPState, SAPNode, Severity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ChainHop:
    """A single hop in an attack chain."""
    source_sid: str
    target_sid: str
    destination_name: str = ""
    rfc_user: str = ""
    has_sap_all: bool = False
    method: str = ""
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "source_sid": self.source_sid,
            "target_sid": self.target_sid,
            "destination_name": self.destination_name,
            "rfc_user": self.rfc_user,
            "has_sap_all": self.has_sap_all,
            "method": self.method,
            "description": self.description,
        }


@dataclass
class TrustChain:
    """A multi-hop attack path through the SAP landscape."""
    hops: list = field(default_factory=list)
    entry_method: str = ""
    start_sid: str = ""
    end_sid: str = ""
    end_is_production: bool = False
    sap_all_throughout: bool = False
    risk_label: str = "UNKNOWN"
    headline: str = ""
    business_impact: str = ""

    @property
    def total_hops(self) -> int:
        return len(self.hops)

    @property
    def path_sids(self) -> list:
        if not self.hops:
            return []
        sids = [self.hops[0].source_sid]
        for h in self.hops:
            sids.append(h.target_sid)
        return sids

    @property
    def severity(self) -> int:
        if self.end_is_production and self.sap_all_throughout:
            return 5  # CRITICAL
        if self.end_is_production:
            return 4  # HIGH
        if self.sap_all_throughout and self.total_hops >= 2:
            return 3  # MEDIUM
        return 2  # LOW

    def to_dict(self) -> dict:
        return {
            "hops": [h.to_dict() for h in self.hops],
            "entry_method": self.entry_method,
            "start_sid": self.start_sid,
            "end_sid": self.end_sid,
            "end_is_production": self.end_is_production,
            "sap_all_throughout": self.sap_all_throughout,
            "total_hops": self.total_hops,
            "path_sids": self.path_sids,
            "risk_label": self.risk_label,
            "severity": self.severity,
            "headline": self.headline,
            "business_impact": self.business_impact,
        }


# ---------------------------------------------------------------------------
# Entry point detection
# ---------------------------------------------------------------------------

def _entry_method(node: SAPNode) -> str:
    """Determine how an attacker could enter this node."""
    if node.pwned:
        methods = []
        for cu in node.created_users:
            methods.append(cu.method)
        if methods:
            return methods[0]
        return "compromised"
    if node.gw_vulnerable:
        return "gw_exploit"
    if node.ms_vulnerable:
        return "betrusted_10kblaze"
    if any(c.verified for c in node.credentials):
        return "credentials"
    return "unknown"


def _entry_description(method: str) -> str:
    descs = {
        "gw_exploit": "Unauthenticated GW exploit (SAPXPG)",
        "betrusted_10kblaze": "10KBlaze betrusted (CVE-2020-6207)",
        "credentials": "Known credentials",
        "compromised": "Already compromised",
        "rfc_destination": "RFC destination with SAP_ALL",
        "secstore_direct": "SecStore password extraction",
    }
    return descs.get(method, method)


# ---------------------------------------------------------------------------
# BFS chain discovery
# ---------------------------------------------------------------------------

def find_all_chains(state: SAPMAPState, max_depth: int = 6,
                    print_fn=None) -> list:
    """BFS from every exploitable node to discover all reachable chains.

    Returns a list of TrustChain objects, one for each unique path
    from an entry point to a distinct endpoint.
    """
    pf = print_fn or (lambda *a: None)

    # Build adjacency: sid → [(target_sid, RFCConnection), ...]
    adj = {}
    for conn in state.connections:
        src = conn.source_sid
        tgt = conn.target_sid
        if not src or not tgt or src == tgt:
            continue
        if not conn.logon_successful:
            continue
        if src not in adj:
            adj[src] = []
        adj[src].append((tgt, conn))

    # Find entry points
    entries = []
    for sid, node in state.nodes.items():
        if node.pwned or node.gw_vulnerable or node.ms_vulnerable:
            entries.append(node)
        elif any(c.verified for c in node.credentials):
            entries.append(node)

    if not entries:
        pf("[*] No entry points found (no compromised/exploitable systems)")
        return []

    pf(f"[*] Chain analysis: {len(entries)} entry points, "
       f"{sum(len(v) for v in adj.values())} traversable RFC links")

    chains = []
    seen_paths = set()

    for entry in entries:
        entry_sid = entry.sid
        entry_m = _entry_method(entry)

        # BFS: queue holds (current_sid, path_so_far)
        queue = deque()
        queue.append((entry_sid, []))
        visited_from_entry = {entry_sid}

        while queue:
            current_sid, path = queue.popleft()

            if len(path) >= max_depth:
                continue

            for target_sid, conn in adj.get(current_sid, []):
                if target_sid in visited_from_entry:
                    continue
                visited_from_entry.add(target_sid)

                hop = ChainHop(
                    source_sid=current_sid,
                    target_sid=target_sid,
                    destination_name=conn.destination_name or "",
                    rfc_user=conn.rfc_user or "",
                    has_sap_all=conn.has_sap_all,
                    method="BAPI (SAP_ALL)" if conn.has_sap_all else "RFC logon",
                    description=f"via {conn.destination_name}" if conn.destination_name else "",
                )
                new_path = path + [hop]

                # Record chain if it has 1+ hops
                path_key = (entry_sid, tuple(h.target_sid for h in new_path))
                if path_key not in seen_paths:
                    seen_paths.add(path_key)

                    target_node = state.nodes.get(target_sid)
                    all_sap_all = all(h.has_sap_all for h in new_path)

                    chain = TrustChain(
                        hops=new_path,
                        entry_method=entry_m,
                        start_sid=entry_sid,
                        end_sid=target_sid,
                        end_is_production=(target_node.is_production
                                           if target_node else False),
                        sap_all_throughout=all_sap_all,
                    )
                    _generate_headline(chain, state)
                    chains.append(chain)

                # Continue BFS if SAP_ALL allows further propagation
                if conn.has_sap_all:
                    queue.append((target_sid, new_path))

    return chains


# ---------------------------------------------------------------------------
# Chain ranking and filtering
# ---------------------------------------------------------------------------

def rank_chains(chains: list) -> list:
    """Sort chains: production targets first, then by severity, then by hops."""
    return sorted(chains, key=lambda c: (
        -int(c.end_is_production),
        -c.severity,
        -c.total_hops,
    ))


def filter_critical(chains: list) -> list:
    """Keep only chains that reach production or span 2+ hops with SAP_ALL."""
    return [c for c in chains
            if c.end_is_production
            or (c.total_hops >= 2 and c.sap_all_throughout)]


# ---------------------------------------------------------------------------
# Headline generation
# ---------------------------------------------------------------------------

_RISK_LABELS = {5: "CRITICAL", 4: "HIGH", 3: "MEDIUM", 2: "LOW", 1: "INFO"}


def _generate_headline(chain: TrustChain, state: SAPMAPState):
    """Generate a business-readable headline for a chain."""
    sids = chain.path_sids
    path_str = " \u2192 ".join(sids)
    chain.risk_label = _RISK_LABELS.get(chain.severity, "UNKNOWN")

    end_node = state.nodes.get(chain.end_sid)

    # Entry description
    entry_desc = _entry_description(chain.entry_method)

    if chain.end_is_production:
        chain.headline = (f"{path_str} \u2014 "
                          f"Production reached in {chain.total_hops} hops")
        # Business impact from impact_results if available
        impacts = []
        if end_node and end_node.impact_results:
            for ir in end_node.impact_results:
                if ir.get("record_count", 0) > 0:
                    impacts.append(ir.get("headline", ""))
        if impacts:
            chain.business_impact = "; ".join(impacts[:3])
        else:
            chain.business_impact = "Full production data accessible"
    elif chain.sap_all_throughout:
        chain.headline = (f"{path_str} \u2014 "
                          f"Full access chain ({chain.total_hops} hops, SAP_ALL)")
        chain.business_impact = "SAP_ALL on every hop \u2014 unrestricted access"
    else:
        chain.headline = (f"{path_str} \u2014 "
                          f"{chain.total_hops} hop{'s' if chain.total_hops > 1 else ''}")
        chain.business_impact = ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_chains(state: SAPMAPState, max_depth: int = 6,
                   print_fn=None) -> list:
    """Run full chain analysis and return ranked, filtered results."""
    pf = print_fn or print

    all_chains = find_all_chains(state, max_depth, print_fn=pf)
    if not all_chains:
        pf("[*] No attack chains found in the landscape")
        return []

    critical = filter_critical(all_chains)
    ranked = rank_chains(critical if critical else all_chains)

    # Deduplicate: keep only the longest chain per (start, end) pair
    best = {}
    for c in ranked:
        key = (c.start_sid, c.end_sid)
        if key not in best or c.total_hops > best[key].total_hops:
            best[key] = c
    result = rank_chains(list(best.values()))

    prod_chains = [c for c in result if c.end_is_production]
    pf(f"[+] Found {len(result)} unique attack chains "
       f"({len(prod_chains)} reaching production)")

    for i, c in enumerate(result[:5]):
        pf(f"  [{c.risk_label:8s}] {c.headline}")
        if c.business_impact:
            pf(f"             {c.business_impact[:80]}")

    try:
        from sapmap_findings import emit_finding
        for c in result[:5]:
            sev = "CRITICAL" if c.end_is_production else "HIGH"
            emit_finding(
                sev, c.end_sid or c.start_sid or "?",
                f"Attack chain: {c.headline} "
                f"({c.total_hops} hops, {c.risk_label})",
            )
    except Exception:
        pass

    return result
