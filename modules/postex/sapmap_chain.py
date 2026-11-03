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
    """A single hop in an attack chain.

    ``severity`` (5=CRITICAL .. 2=LOW) and ``untested`` score this one
    hop on its own — see :func:`_hop_severity`.  Whole-chain severity
    still lives on :class:`TrustChain`; these let a consumer colour each
    step, not just the chain as a whole.
    """
    source_sid: str
    target_sid: str
    destination_name: str = ""
    rfc_user: str = ""
    has_sap_all: bool = False
    method: str = ""
    description: str = ""
    severity: int = 2
    untested: bool = False

    def to_dict(self) -> dict:
        return {
            "source_sid": self.source_sid,
            "target_sid": self.target_sid,
            "destination_name": self.destination_name,
            "rfc_user": self.rfc_user,
            "has_sap_all": self.has_sap_all,
            "method": self.method,
            "description": self.description,
            "severity": self.severity,
            "untested": self.untested,
        }


# Per-hop severity rungs (mirror TrustChain's 5..2 ladder, scored for a
# single hop rather than the whole chain).
_HOP_SEV_CRITICAL = 5   # passwordless lateral movement
_HOP_SEV_HIGH = 4       # lands SAP_ALL-equivalent rights
_HOP_SEV_MEDIUM = 3     # authenticated RFC logon
_HOP_SEV_LOW = 2        # floor (also: a downgraded untested hop)


def _hop_severity(conn, is_trusted: bool, is_sso2: bool,
                  is_dbcon: bool, is_tms: bool) -> int:
    """Severity of a single attack hop, 5 (CRITICAL) down to 2 (LOW).

    The ranking tracks the technique the hop's ``method`` caption names,
    so the number and the label never drift apart:

    * trusted RFC or a forged MYSAPSSO2 ticket need **no password** and
      let the attacker act as any user — CRITICAL (5);
    * a hop that lands SAP_ALL-equivalent rights — a BAPI call with
      SAP_ALL, a direct-DB user plant (DBCON), or a TMS transport edge —
      HIGH (4);
    * a plain RFC logon that still has to authenticate — MEDIUM (3).

    An *untested* edge (the destination exists on the source's disk but
    the logon has not been proven) is only a candidate, so it is knocked
    down one rung, with LOW (2) as the floor.  Passwordless, DBCON and
    TMS edges are never treated as untested here — matching the caption
    logic, which does not tag them ``— UNTESTED`` either.

    Pure and side-effect-free: ``conn`` may be a real ``RFCConnection``
    or one of the synthetic edge objects the BFS builds, so every
    attribute read is guarded.
    """
    if is_trusted or is_sso2:
        sev = _HOP_SEV_CRITICAL
    elif getattr(conn, "has_sap_all", False) or is_dbcon or is_tms:
        sev = _HOP_SEV_HIGH
    else:
        sev = _HOP_SEV_MEDIUM
    untested = not getattr(conn, "tested", False)
    if untested and not (is_trusted or is_sso2 or is_dbcon or is_tms):
        sev = max(_HOP_SEV_LOW, sev - 1)
    return sev


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
    def has_trusted_hop(self) -> bool:
        return any("Trusted RFC" in (h.method or "") for h in self.hops)

    @property
    def has_sso2_hop(self) -> bool:
        return any("STRUSTSSO2" in (h.method or "") for h in self.hops)

    @property
    def severity(self) -> int:
        if self.end_is_production and (self.sap_all_throughout
                                       or self.has_trusted_hop
                                       or self.has_sso2_hop):
            return 5  # CRITICAL
        if self.end_is_production:
            return 4  # HIGH
        if (self.has_trusted_hop or self.has_sso2_hop) and self.total_hops >= 1:
            return 4  # HIGH — passwordless lateral movement
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
    # A node we hold a stolen SAPSYS PSE for is an entry point for
    # STRUSTSSO2-trusted receivers (we can forge tickets to them).
    if getattr(node, "forged_tickets", None):
        return "pse_stolen"
    return "unknown"


def _entry_description(method: str) -> str:
    descs = {
        "gw_exploit": "Unauthenticated GW exploit (SAPXPG)",
        "betrusted_10kblaze": "10KBlaze betrusted (CVE-2020-6207)",
        "credentials": "Known credentials",
        "compromised": "Already compromised",
        "rfc_destination": "RFC destination with SAP_ALL",
        "trusted_rfc": "Trusted RFC (passwordless)",
        "pse_stolen": "Stolen SAPSYS PSE — forge MYSAPSSO2 tickets",
        "secstore_direct": "SecStore password extraction",
        "btp_destination_leak":
            "BTP destination cleartext capture (cloud → on-prem)",
    }
    return descs.get(method, method)


# ---------------------------------------------------------------------------
# Graph construction — shared by chain discovery AND blast-radius
# ---------------------------------------------------------------------------
# The lateral-movement adjacency, the per-hop metadata (method caption /
# severity / untested flag) and the onward-propagation gate are the three
# pieces every graph walk over the landscape needs.  Factored out here so
# ``find_all_chains`` (path enumeration) and ``blast_radius`` /
# ``exposure_cone`` (reachable-set flood) traverse one identical graph with
# one identical set of captions — they can never drift.


def _build_adjacency(state: SAPMAPState) -> dict:
    """Build the lateral-movement adjacency: ``sid -> [(target_sid, edge)]``.

    Four edge sources, each an ``RFCConnection`` or a synthetic
    RFCConnection-shaped object so a caller never has to special-case the
    kind.  Pure — no printing, no mutation of ``state``.

    Edge inclusion policy (RFC connections):
      * ``trusted_system = True``  -> ALWAYS traverse (passwordless hop);
      * ``tested & logon_successful`` -> traverse (proven);
      * ``tested & not logon_successful`` -> skip (known-broken);
      * ``not tested`` -> traverse (untested candidate — the destination
        EXISTS on the source's disk, so it is a possible hop the operator
        has not validated yet).
    """
    adj: dict = {}
    for conn in state.connections:
        src = conn.source_sid
        tgt = conn.target_sid
        if not src or not tgt or src == tgt:
            continue
        if conn.trusted_system:
            pass  # always include trusted RFC edges
        elif conn.tested and not conn.logon_successful:
            continue
        if src not in adj:
            adj[src] = []
        adj[src].append((tgt, conn))

    # STRUSTSSO2 trust edges: when system T trusts issuer I, an attacker
    # holding I's SAPSYS PSE private key can forge tickets accepted by
    # T.  These are reverse edges (I -> T) in the lateral-movement graph
    # because the direction of attack is I-as-attacker reaches T.
    # We model them as synthetic RFCConnection-shaped edges with
    # trust_type='strustsso2' so the hop builder can label them.
    for rel in (state.trust_relations or []):
        issuer = (rel.issuer_sid or "").strip()
        trusting = (rel.trusting_sid or "").strip()
        if not issuer or not trusting or issuer == trusting:
            continue
        # Synthetic edge marker — uses a lightweight namespace object
        # so the BFS doesn't have to special-case None
        synthetic = type("StrustSso2Edge", (), {
            "source_sid": issuer,
            "target_sid": trusting,
            "destination_name": f"STRUSTSSO2 ({rel.discovered_via or 'trust'})",
            "rfc_user": rel.trusting_client or "*",
            "has_sap_all": False,
            "trusted_system": False,
            "trust_type": "strustsso2",
            "tested": False,
            "logon_successful": False,
            "client": rel.trusting_client or "",
        })()
        if issuer not in adj:
            adj[issuer] = []
        adj[issuer].append((trusting, synthetic))

    # DBCON direct-DB pivot edges (issue #21).  When source S has a
    # DBCON entry that points at target T's HANA AND we've probed it
    # SAP-shape reachable, that's a CRITICAL lateral edge: SAPMAP
    # can plant SAPMAP00 on T via direct SQL, no RFC/SAPXPG on T.
    # Represented as a synthetic RFCConnection-shaped edge so the
    # BFS + severity ranker treat it as a first-class hop.
    for src_node in state.nodes.values():
        for edge in (src_node.dbcon_edges or []):
            tgt_sid = (edge.target_sid or "").strip().upper()
            if not tgt_sid or tgt_sid == src_node.sid:
                continue
            if not edge.is_sap_shape:
                # non-SAP DBCON is data-extraction only, not a
                # user-plantable lateral hop — skip
                continue
            synthetic = type("DbconEdge", (), {
                "source_sid":       src_node.sid,
                "target_sid":       tgt_sid,
                "destination_name": f"DBCON/{edge.con_name}",
                "rfc_user":         edge.user or "*",
                # SAPMAP00 planted -> effectively SAP_ALL on target
                "has_sap_all":      bool(edge.pwned),
                "trusted_system":   False,
                "trust_type":       "dbcon_direct",
                "tested":           bool(edge.tested),
                "logon_successful": bool(edge.reachable),
                "client":           "000",
            })()
            if src_node.sid not in adj:
                adj[src_node.sid] = []
            adj[src_node.sid].append((tgt_sid, synthetic))

    # CTS/TMS TMSADM RFC destinations (CTS/TMS epic Bundle 1).
    # Every /RFC/TMSADM@<sid>.DOMAIN_<x> secstore entry the source
    # has is a lateral-movement edge to <sid> — even before we've
    # tested it, since we hold the password and can retry any time.
    # is_controller edges carry has_sap_all=True because the domain
    # controller confers write rights over TMS for the whole
    # transport landscape.
    for src_node in state.nodes.values():
        for dest in (getattr(src_node, "tms_destinations", None) or []):
            tgt_sid = (dest.target_sid or "").strip().upper()
            if not tgt_sid or tgt_sid == src_node.sid:
                continue
            synthetic = type("TmsEdge", (), {
                "source_sid":       src_node.sid,
                "target_sid":       tgt_sid,
                "destination_name":
                    f"TMSADM@{dest.target_sid}.{dest.domain}",
                "rfc_user":         "TMSADM",
                # Controller access + SAP_ALL TMSADM = full transport
                # rights.  Even non-SAP_ALL TMSADM can inject/import.
                "has_sap_all":      bool(dest.tmsadm_has_sap_all
                                          or dest.is_controller),
                "trusted_system":   False,
                "trust_type":       "tmsadm_rfc",
                "tested":           bool(dest.tested),
                "logon_successful": bool(dest.logon_ok),
                "client":           dest.target_client or "000",
            })()
            if src_node.sid not in adj:
                adj[src_node.sid] = []
            adj[src_node.sid].append((tgt_sid, synthetic))

    return adj


def _edge_kind(conn) -> tuple:
    """Classify an edge for captioning / severity / untested logic.

    Returns ``(is_trusted, is_sso2, is_dbcon, is_tms, hop_untested)``.
    ``hop_untested`` is the single predicate that drives the caption
    ``— UNTESTED`` suffix, the ``[untested]`` description tag, the severity
    clamp and the ``ChainHop.untested`` flag, so they can never drift.
    Pure; every attribute read is guarded for the synthetic edge objects.
    """
    is_trusted = bool(getattr(conn, "trusted_system", False))
    tt = getattr(conn, "trust_type", "")
    is_sso2 = (tt == "strustsso2")
    is_dbcon = (tt == "dbcon_direct")
    is_tms = (tt == "tmsadm_rfc")
    untested = not getattr(conn, "tested", False)
    hop_untested = (untested and not is_trusted and not is_sso2
                    and not is_dbcon and not is_tms)
    return is_trusted, is_sso2, is_dbcon, is_tms, hop_untested


def _make_hop(source_sid: str, target_sid: str, conn) -> ChainHop:
    """Build the :class:`ChainHop` for one edge — the single source of the
    technique caption, description tags and per-hop severity shared by the
    chain enumerator and the blast-radius flood."""
    is_trusted, is_sso2, is_dbcon, is_tms, hop_untested = _edge_kind(conn)
    has_sap_all = bool(getattr(conn, "has_sap_all", False))
    if is_tms:
        method = ("TMSADM RFC "
                   + ("(controller — landscape-wide transport rights)"
                      if has_sap_all
                      else "(cross-system transport rights)"))
    elif is_dbcon:
        method = ("DBCON direct SQL (SAP-shape "
                   + ("PWNED" if has_sap_all
                       else "reachable — planted user pending")
                   + ")")
    elif is_sso2:
        method = "Forged MYSAPSSO2 ticket (STRUSTSSO2)"
    elif is_trusted:
        method = "Trusted RFC (no password)"
    elif has_sap_all:
        method = "BAPI (SAP_ALL)"
    else:
        method = "RFC logon"
    if hop_untested:
        method += " — UNTESTED"
    dest_name = getattr(conn, "destination_name", "") or ""
    return ChainHop(
        source_sid=source_sid,
        target_sid=target_sid,
        destination_name=dest_name,
        rfc_user=getattr(conn, "rfc_user", "") or "",
        has_sap_all=has_sap_all,
        method=method,
        description=(
            (f"via {dest_name}" if dest_name else "")
            + (" [dbcon]" if is_dbcon else "")
            + (" [tms]" if is_tms else "")
            + (" [strustsso2]" if is_sso2 else "")
            + (" [trusted]" if is_trusted else "")
            + (" [untested]" if hop_untested else "")
        ).strip(),
        severity=_hop_severity(conn, is_trusted, is_sso2, is_dbcon, is_tms),
        untested=hop_untested,
    )


def _edge_propagates(conn) -> bool:
    """Whether owning an edge's *target* lets the attacker pivot onward.

    The BFS gate: SAP_ALL-equivalent rights, a trusted RFC (log in as any
    user), or a forged MYSAPSSO2 ticket all confer full control of the
    landing system, so the walk continues *past* it.  A plain RFC logon —
    or a merely-reachable DBCON/TMS edge — reaches the target but does not
    by itself grant onward pivot, so the walk stops there."""
    is_trusted, is_sso2, _, _, _ = _edge_kind(conn)
    return bool(getattr(conn, "has_sap_all", False) or is_trusted or is_sso2)


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

    # Adjacency: sid -> [(target_sid, edge), ...] built from RFC
    # connections + STRUSTSSO2 / DBCON / TMS synthetic edges.  See
    # _build_adjacency for the full edge-inclusion policy.
    adj = _build_adjacency(state)

    # Find entry points.  Each entry is a (sid, entry_method) pair so
    # we can mix on-prem SAPNode entries with BTP-subaccount entries
    # without forcing a fake SAPNode shim through the rest of the
    # pipeline.  BTP-source edges in state.connections use the
    # sentinel "BTP:<uuid8>" SID, which the BFS already walks happily
    # — we just need to seed BFS with those SIDs so they actually act
    # as starting points.
    entries: list = []   # [(sid, method), ...]
    for sid, node in state.nodes.items():
        if node.pwned or node.gw_vulnerable or node.ms_vulnerable:
            entries.append((sid, _entry_method(node)))
        elif any(c.verified for c in node.credentials):
            entries.append((sid, _entry_method(node)))
        elif getattr(node, "forged_tickets", None):
            # PSE-stolen nodes are entry points for STRUSTSSO2 trust
            entries.append((sid, "pse_stolen"))

    # BTP subaccounts with at least one cleartext destination captured
    # are entry points: anyone with the right BTP token (or the
    # service-key creds we just minted) can walk the synthetic
    # BTP:<uuid8> → on-prem edges and reach whatever those
    # destinations point at.  BTPSubaccountNode.pwned flips True the
    # moment link_destinations_to_onprem captures the first
    # cleartext credential.
    for uuid, sub in (state.btp_subaccounts or {}).items():
        if not getattr(sub, "pwned", False):
            continue
        entries.append((f"BTP:{uuid[:8]}", "btp_destination_leak"))

    if not entries:
        pf("[*] No entry points found (no compromised/exploitable systems)")
        return []

    pf(f"[*] Chain analysis: {len(entries)} entry points, "
       f"{sum(len(v) for v in adj.values())} traversable RFC links")

    chains = []
    seen_paths = set()

    for entry_sid, entry_m in entries:

        # Two distinct frontiers, because "reached" and "owned" differ:
        #   recorded — endpoints we've already emitted one chain to (one
        #              representative path per (entry, endpoint); the
        #              first, shortest BFS touch wins).
        #   expanded — nodes we've OWNED and already pushed onward from.
        #
        # The earlier single-visit BFS marked a node seen on its first
        # touch, *before* the _edge_propagates gate — so a node first
        # reached over a NON-propagating edge (a plain RFC logon that
        # reaches but does not own the box) was marked seen and never
        # expanded, even when a later propagating edge (SAP_ALL / trusted
        # RFC / forged MYSAPSSO2) owned it.  Every onward chain that
        # pivoted through such a node was silently dropped.  Separating
        # "reached" (recorded) from "owned" (expanded) lets a node be
        # enqueued when a propagating edge reaches it, regardless of an
        # earlier weaker touch — the same two-phase idea blast_radius()
        # uses for the flood.
        queue = deque()
        queue.append((entry_sid, []))
        recorded = {entry_sid}      # never emit the entry as an endpoint
        expanded: set = set()       # nodes already popped & pushed onward

        while queue:
            current_sid, path = queue.popleft()

            # Own (expand) each node at most once, over the first/shortest
            # owning path BFS dequeues.  A node may be enqueued several
            # times (reached by several propagating edges); this guard
            # dedups the expansion and breaks propagating cycles.
            if current_sid in expanded:
                continue
            expanded.add(current_sid)

            if len(path) >= max_depth:
                continue

            for target_sid, conn in adj.get(current_sid, []):
                # One shared builder yields the ChainHop (technique
                # caption + per-hop severity + untested flag) so chains
                # and the blast-radius flood never diverge.
                hop = _make_hop(current_sid, target_sid, conn)
                new_path = path + [hop]

                # Record one representative chain per (entry, endpoint),
                # over whatever edge first reaches it — reachability is
                # reported even for boxes we only touch but never own.
                path_key = (entry_sid, tuple(h.target_sid for h in new_path))
                if target_sid not in recorded and path_key not in seen_paths:
                    recorded.add(target_sid)
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

                # Continue BFS only when owning the target confers onward
                # pivot (SAP_ALL / trusted RFC / forged MYSAPSSO2) — see
                # _edge_propagates.  Enqueue even if the target was already
                # *recorded* over a weaker edge: recorded means "reached",
                # not "owned".  The expanded-guard above keeps the
                # re-enqueue cheap and loop-safe.
                if _edge_propagates(conn) and target_sid not in expanded:
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

    has_trusted_hop = any(
        "Trusted RFC" in (h.method or "") for h in chain.hops)
    has_sso2_hop = any(
        "STRUSTSSO2" in (h.method or "") for h in chain.hops)
    if has_sso2_hop:
        trusted_tag = " [STRUSTSSO2 ticket]"
    elif has_trusted_hop:
        trusted_tag = " [trusted RFC]"
    else:
        trusted_tag = ""

    if chain.end_is_production:
        chain.headline = (f"{path_str} \u2014 "
                          f"Production reached in {chain.total_hops} hops"
                          f"{trusted_tag}")
        impacts = []
        if end_node and end_node.impact_results:
            for ir in end_node.impact_results:
                if ir.get("record_count", 0) > 0:
                    impacts.append(ir.get("headline", ""))
        if impacts:
            chain.business_impact = "; ".join(impacts[:3])
        elif has_trusted_hop:
            chain.business_impact = ("Passwordless hop via trusted RFC "
                                     "\u2014 full production data accessible")
        else:
            chain.business_impact = "Full production data accessible"
    elif chain.sap_all_throughout:
        chain.headline = (f"{path_str} \u2014 "
                          f"Full access chain ({chain.total_hops} hops, SAP_ALL)"
                          f"{trusted_tag}")
        chain.business_impact = "SAP_ALL on every hop \u2014 unrestricted access"
    elif has_sso2_hop:
        chain.headline = (f"{path_str} \u2014 "
                          f"Forged ticket chain ({chain.total_hops} "
                          f"hop{'s' if chain.total_hops > 1 else ''}, "
                          f"STRUSTSSO2)")
        chain.business_impact = ("Cross-network lateral movement via "
                                 "forged MYSAPSSO2 ticket signed by "
                                 "stolen SAPSYS PSE")
    elif has_trusted_hop:
        chain.headline = (f"{path_str} \u2014 "
                          f"Trusted RFC chain ({chain.total_hops} "
                          f"hop{'s' if chain.total_hops > 1 else ''}, "
                          f"no password)")
        chain.business_impact = ("Passwordless lateral movement via "
                                 "trusted RFC assertion ticket")
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


# ---------------------------------------------------------------------------
# Blast radius — reachable-set flood (issue #197)
# ---------------------------------------------------------------------------
# Where find_all_chains *enumerates ranked paths* to high-value endpoints,
# the blast-radius flood answers the operator's "own this box, own all of
# *that*" question directly: from one system, which others fall — and from
# how far away could an attacker reach a crown jewel.  Both walk the one
# graph _build_adjacency builds with the one _edge_propagates gate, so the
# flood can never claim reach the chain ranker would not.


def _blast_result(anchor: str, mode: str, nodes: dict) -> dict:
    """Shape a reachable-node map into the JSON-safe flood result.

    ``nodes`` is ``{sid: {hop, method, severity, untested, via}}``; this
    groups it into distance rings and tallies the totals the GUI legend
    and the report summary read.
    """
    rings: dict = {}
    max_hop = 0
    for sid, meta in nodes.items():
        h = int(meta.get("hop", 0))
        rings.setdefault(h, []).append(sid)
        if h > max_hop:
            max_hop = h
    ring_list = [{"hop": h, "sids": sorted(rings[h])} for h in sorted(rings)]
    return {
        "anchor": anchor,
        "mode": mode,
        "rings": ring_list,
        "nodes": nodes,
        "reachable": len(nodes),
        "max_hop": max_hop,
    }


def blast_radius(state: SAPMAPState, start_sid: str,
                 max_depth: int = 6) -> dict:
    """Forward reachable set from ``start_sid``, ring by ring.

    Two distinct ideas drive the walk, and conflating them is a bug:

    * **Own** a system = arrive over a *propagating* edge (SAP_ALL / trusted
      / SSO2) so you fully control it and can use *its* outgoing edges.  The
      start is owned for free.
    * **Reach** a system = any owned system has an edge to it; the last hop
      need not propagate (a plain RFC logon still *reaches* the box).

    So a node can be reached over a weak edge yet still be owned over a
    stronger path elsewhere — and only ownership lets the walk continue past
    it.  This is computed in two phases:

      1. BFS over *propagating edges only* for ``own_dist`` (shortest
         all-propagating distance start -> node).
      2. one relaxation: every owned node's outgoing edges *reach* their
         targets, so ``reach_dist[v] = min(own_dist[u] + 1)`` over owned ``u``
         with an edge ``u -> v``.

    Collapsing the two into a single-visit BFS (marking a node seen on its
    first, possibly non-propagating, touch) silently drops systems that are
    reachable only through a longer owning path — a false negative this
    tool must not have.  The rings are shortest *reach* distances, and the
    set is exactly ``{v : exists owned u with edge u->v}`` — the inverse of
    :func:`exposure_cone`.

    Returns the :func:`_blast_result` dict (``mode="forward"``).  An
    unknown or empty ``start_sid`` yields a well-formed empty result.
    """
    start_sid = (start_sid or "").strip()
    adj = _build_adjacency(state)
    nodes: dict = {}
    if start_sid:
        # Phase 1 — own_dist: shortest all-propagating path from the start.
        own_dist = {start_sid: 0}
        q = deque([start_sid])
        while q:
            cur = q.popleft()
            d = own_dist[cur]
            if d >= max_depth:
                continue
            for tgt, conn in adj.get(cur, []):
                if _edge_propagates(conn) and tgt not in own_dist:
                    own_dist[tgt] = d + 1
                    q.append(tgt)
        # Phase 2 — reach: every owned node's edges reach their targets at
        # own_dist[u] + 1 (the last hop need not propagate).  Keep the
        # shortest reach per target, and that hop's metadata with it.
        for u, du in own_dist.items():
            if du >= max_depth:
                continue
            for tgt, conn in adj.get(u, []):
                if tgt == start_sid:
                    continue
                cand = du + 1
                prev = nodes.get(tgt)
                if prev is None or cand < prev["hop"]:
                    hop = _make_hop(u, tgt, conn)
                    nodes[tgt] = {
                        "hop": cand,
                        "method": hop.method,
                        "severity": hop.severity,
                        "untested": hop.untested,
                        "via": u,          # the system we pivoted FROM
                    }
    return _blast_result(start_sid, "forward", nodes)


def exposure_cone(state: SAPMAPState, target_sid: str,
                  max_depth: int = 6) -> dict:
    """Inverse reachable set — every system that can reach ``target_sid``.

    The "who can reach my crown jewel" view: reverse BFS over the same
    graph.  An attacker's forward path ``E -> ... -> J`` is valid when
    every hop *except the last one into J* confers onward pivot, so walking
    backwards the first reverse hop (the edges into J — those are an
    attacker's final hop) is always counted, and every deeper reverse hop
    is counted only when the forward edge propagates.  This makes the cone
    the exact set of systems ``S`` for which ``J`` is in
    ``blast_radius(S)``.

    Returns the :func:`_blast_result` dict (``mode="inverse"``); each
    node's ``via`` is the next system *toward* the crown jewel.
    """
    target_sid = (target_sid or "").strip()
    adj = _build_adjacency(state)
    # Reverse adjacency: tgt -> [(src, edge)] for each forward edge.
    radj: dict = {}
    for src, edges in adj.items():
        for tgt, conn in edges:
            radj.setdefault(tgt, []).append((src, conn))

    nodes: dict = {}
    if target_sid:
        queue = deque([(target_sid, 0)])
        visited = {target_sid}
        while queue:
            cur, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for src, conn in radj.get(cur, []):
                if src in visited:
                    continue
                # First reverse hop (edges into the crown jewel) is an
                # attacker's *last* forward hop — always allowed.  Deeper
                # reverse hops are non-final forward hops, so they count
                # only when the edge confers onward pivot.  A failed gate
                # skips this edge without marking src visited, so src can
                # still enter the cone via a propagating edge elsewhere.
                if depth >= 1 and not _edge_propagates(conn):
                    continue
                visited.add(src)
                hop = _make_hop(src, cur, conn)   # forward edge src -> cur
                nodes[src] = {
                    "hop": depth + 1,
                    "method": hop.method,
                    "severity": hop.severity,
                    "untested": hop.untested,
                    "via": cur,          # the next system TOWARD the jewel
                }
                queue.append((src, depth + 1))
    return _blast_result(target_sid, "inverse", nodes)
