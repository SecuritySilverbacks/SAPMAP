"""Issue #85 — host-scoped lock guardrail: the single policy module.

A locked HOST is excluded from ALL further automated contact (scan, probe,
RFC, vuln check, exploitation, propagation) while staying fully visible in
the map / inventory / diff / report.  This module is the ONE place the lock
logic lives (Option C): the host matcher, the state primitives (lock /
unlock / query), the shared ``actionable_nodes`` iterator every target-
selection loop must use, and the error + passive-route surface the HTTP
gate enforces.  Enforcement hooks elsewhere (the before_request gate, the
auto-lock funnel, the pre-scan filter, the in-process selection loops) are
thin and call into here.

Design notes
------------
* **Host-scoped, not per-SID** (the reporter's explicit call): on a shared
  host every node/SID is covered.  The lock state lives on ``SAPMAPState``
  (``locked_hosts`` / ``unlock_log``), NOT on a node, so it survives the
  wholesale node-replace in ``add_node`` for free — no #92-style per-node
  carry-forward needed.
* **Default-deny** at the gate: a node-scoped active route against a locked
  host is refused unless its route rule is in ``PASSIVE_ROUTES``.
* **Unlock requires a recorded reason** (team / compliance traceability).

The auto-lock whitelist (``whitelist_match`` / ``apply_auto_lock``) reuses
``host_matches`` here; it is driven from the node-creation funnel
(``SAPMAPState._auto_lock``) and the scanner pre-scan filter
(``sapmap_scanner.filter_scan_targets``).
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone


class LockedTargetError(Exception):
    """Raised when an active operation is attempted against a locked host."""

    def __init__(self, host: str = "", reason: str = ""):
        self.host = host
        self.reason = reason
        msg = f"target host {host!r} is locked (#85)"
        if reason:
            msg += f": {reason}"
        super().__init__(msg)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Host matching
# ---------------------------------------------------------------------------

def _is_ip_or_cidr(s: str) -> bool:
    s = (s or "").strip()
    if not s:
        return False
    try:
        if "/" in s:
            ipaddress.ip_network(s, strict=False)
        else:
            ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def host_matches(host: str, pattern: str) -> bool:
    """True if ``host`` is covered by ``pattern``.

    * IP / CIDR pattern → the host must be an IP inside it (hostname never
      matches an IP pattern, and vice-versa).
    * Hostname / domain pattern → **dot-anchored suffix** match:
      ``host == pattern`` or ``host`` ends with ``'.' + pattern``.  So a
      domain pattern ``sap.com`` matches ``apps.sap.com`` but NOT
      ``evilsap.com``; an exact host matches itself (and its subdomains,
      which are children of that locked host).

    Both sides are lower-cased and stripped.
    """
    h = (host or "").strip().lower()
    p = (pattern or "").strip().lower()
    if not h or not p:
        return False
    p_is_ip = _is_ip_or_cidr(p)
    h_is_ip = _is_ip_or_cidr(h)
    if p_is_ip:
        if not h_is_ip:
            return False
        try:
            net = ipaddress.ip_network(p, strict=False)
            return ipaddress.ip_address(h) in net
        except ValueError:
            return False
    # pattern is a hostname/domain
    if h_is_ip:
        return False
    return h == p or h.endswith("." + p)


def canonical_hosts(node) -> set:
    """Every host string a node answers on — the identities a lock must
    cover.  Walks the node-level hostname, the per-instance hostnames
    (``all_hostnames`` only returns the node-level one), and the reachable
    IPs (``all_ips`` already EXCLUDES ``reported_ip``, which is the
    self-reported / NAT address and a false-positive source for CIDR locks).

    Defensive by design: tolerates non-SAPNode shapes (SCC / BTP / host-
    control entities grow coverage in a later PR) by also reading any
    ``hostname`` / ``ip`` / ``host`` attribute directly.
    """
    hosts = set()

    def _add(v, lower=True):
        if isinstance(v, str) and v.strip():
            hosts.add(v.strip().lower() if lower else v.strip())

    # node-level + per-instance hostnames
    try:
        for h in (node.all_hostnames() or set()):
            _add(h)
    except Exception:
        _add(getattr(node, "hostname", ""))
    for inst in (getattr(node, "instances", None) or []):
        _add(getattr(inst, "hostname", ""))
    # reachable IPs (reported_ip already excluded by all_ips)
    try:
        for ip in (node.all_ips() or set()):
            _add(ip)
    except Exception:
        _add(getattr(node, "ip", ""))
    # defensive extras for non-SAPNode entities
    for attr in ("hostname", "ip", "host"):
        _add(getattr(node, attr, ""))
    return {h for h in hosts if h}


# ---------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------

def _records(state) -> list:
    return getattr(state, "locked_hosts", None) or []


def is_host_locked(state, host: str) -> bool:
    """True if a bare host string is covered by any lock record.  Used by
    the pre-scan filter (later PR) and direct host checks."""
    h = (host or "").strip().lower()
    if not h:
        return False
    h_is_ip = _is_ip_or_cidr(h)          # parse the host ONCE, not per record
    for rec in _records(state):
        patt = (rec.get("host") or "").strip()
        if not patt:
            continue
        # An IP host can only match an IP/CIDR record and a hostname only a
        # hostname record; skipping the mismatch avoids re-parsing the host
        # inside host_matches for every record on a big-CIDR pre-scan filter.
        if h_is_ip != _is_ip_or_cidr(patt):
            continue
        if host_matches(h, patt):
            return True
    return False


def whitelist_match(state, host: str):
    """Return the first ``lock_whitelist`` pattern that covers ``host``, else
    None.  Used by the auto-lock funnel and the scanner pre-scan filter.
    Matching is the same dot-anchored host / domain / CIDR logic as a lock
    record (``host_matches``)."""
    h = (host or "").strip().lower()
    if not h:
        return None
    h_is_ip = _is_ip_or_cidr(h)          # parse the host ONCE, not per pattern
    for patt in (getattr(state, "lock_whitelist", None) or []):
        p = str(patt).strip()
        if not p:
            continue
        # Skip the type-mismatched majority (IP host vs hostname pattern, or
        # vice-versa) without the full host_matches — a scan of a large CIDR
        # otherwise re-parses every IP against every hostname seed.
        if h_is_ip != _is_ip_or_cidr(p):
            continue
        if host_matches(h, p):
            return p
    return None


def has_ip_scoped_rules(state) -> bool:
    """True if ANY lock record host or whitelist pattern is an IP / CIDR.  When
    False, no bare-IP target can ever match (an IP only matches an IP/CIDR
    rule), so the scanner pre-scan filter can skip the per-IP lock/whitelist
    check entirely on a large CIDR sweep — the common case, since the shipped
    whitelist seed is all hostnames."""
    for rec in _records(state):
        if _is_ip_or_cidr((rec.get("host") or "").strip()):
            return True
    for patt in (getattr(state, "lock_whitelist", None) or []):
        if _is_ip_or_cidr(str(patt).strip()):
            return True
    return False


def locked_record_for(state, node):
    """The lock record covering any of the node's canonical hosts, else
    None.  The first matching record wins (manual locks are exact-host, so
    at most one normally matches)."""
    ch = canonical_hosts(node)
    for rec in _records(state):
        patt = (rec.get("host") or "").strip()
        if not patt:
            continue
        for h in ch:
            if host_matches(h, patt):
                return rec
    return None


def is_locked(state, node) -> bool:
    """True if ``node`` is on a locked host — the keystone check every
    enforcement point calls."""
    return locked_record_for(state, node) is not None


def actionable_nodes(state) -> list:
    """The SAP nodes NOT on a locked host — the ONE iterator that every
    target-selection loop (autopwn, propagate, the gui check_all_*) must use
    so a locked host is uniformly skipped."""
    return [n for n in getattr(state, "nodes", {}).values()
            if not is_locked(state, n)]


def pending_artifacts_for(state, node) -> int:
    """Count artifacts SAPMAP may have planted on this node's host (created
    users, forged tickets, created destinations).  Surfaced as a warning at
    lock time so the operator can choose to clean up FIRST — locking never
    cleans up automatically (the reporter's explicit call)."""
    sid = getattr(node, "sid", "")
    n = 0
    n += len(getattr(node, "created_users", None) or [])
    n += len(getattr(node, "forged_tickets", None) or [])
    for cu in (getattr(state, "created_users", None) or []):
        if getattr(cu, "sid", "") == sid:
            n += 1
    for d in (getattr(state, "created_destinations", None) or []):
        if isinstance(d, dict) and sid and (
                d.get("target_sid") == sid or d.get("source_sid") == sid):
            n += 1
    return n


# ---------------------------------------------------------------------------
# Mutate
# ---------------------------------------------------------------------------

def lock_host(state, host: str, reason: str = "", *, auto: bool = False,
              whitelist_pattern: str = "", by: str = "", now: str = ""):
    """Add (or refresh) a lock record for one host.  Idempotent: re-locking
    a host updates its metadata but keeps the original ``locked_at``.
    Returns the record, or None for an empty host."""
    h = (host or "").strip()
    if not h:
        return None
    hl = h.lower()
    recs = state.locked_hosts
    for rec in recs:
        if (rec.get("host") or "").strip().lower() == hl:
            if reason:
                rec["reason"] = reason
            rec["auto"] = bool(rec.get("auto")) or bool(auto)
            if whitelist_pattern:
                rec["whitelist_pattern"] = whitelist_pattern
            return rec
    rec = {
        "host": h,
        "reason": reason or "",
        "auto": bool(auto),
        "whitelist_pattern": whitelist_pattern or "",
        "locked_at": now or _now_iso(),
        "locked_by": by or "",
    }
    recs.append(rec)
    return rec


def lock_node(state, node, reason: str = "", *, by: str = "", now: str = ""):
    """Lock every canonical host of ``node`` (host-scoped).  Returns the list
    of records created/refreshed."""
    ts = now or _now_iso()
    return [lock_host(state, h, reason, auto=False, by=by, now=ts)
            for h in sorted(canonical_hosts(node))]


def apply_auto_lock(state, node) -> list:
    """Auto-lock every canonical host of ``node`` that matches the whitelist
    and is not ALREADY locked.  Returns the records created (empty when the
    node matches nothing or is already covered).

    Host-scoped like a manual lock: if ANY canonical host matches the
    whitelist the WHOLE box is locked (every canonical host — hostname AND
    reachable IP), so a bare-IP re-scan of a whitelisted box is filtered even
    though only its hostname matched the pattern.  The already-locked skip is
    deliberate: it preserves a manual lock's own reason/flag (never clobbers
    it with the auto reason) and keeps the call idempotent across repeated
    discovery.  Because the creation funnel calls this on every (re)discovery,
    a whitelisted host the operator manually unlocked — which removed its
    record — re-locks here on the next pass; removing the whitelist entry is
    what makes an unlock permanent."""
    hosts = sorted(canonical_hosts(node))
    matched = next((p for p in (whitelist_match(state, h) for h in hosts) if p),
                   None)
    if not matched:
        return []
    locked = []
    for h in hosts:
        if is_host_locked(state, h):
            continue                      # already covered (manual or auto)
        rec = lock_host(state, h,
                        reason=f"auto-locked (whitelist match: {matched})",
                        auto=True, whitelist_pattern=matched)
        if rec:
            locked.append(rec)
    return locked


def unlock_host(state, host: str, reason: str, *, by: str = "",
                now: str = "") -> int:
    """Remove the lock record(s) for ``host`` and append to ``unlock_log``.
    REQUIRES a non-empty reason (raises ValueError otherwise) — the recorded-
    reason guarantee.  Returns the number of records removed."""
    if not (reason or "").strip():
        raise ValueError("unlock requires a recorded reason (issue #85)")
    hl = (host or "").strip().lower()
    recs = state.locked_hosts
    kept, removed = [], 0
    for r in recs:
        if (r.get("host") or "").strip().lower() == hl:
            removed += 1
        else:
            kept.append(r)
    state.locked_hosts = kept
    if removed:
        state.unlock_log.append({
            "host": (host or "").strip(),
            "reason": reason.strip(),
            "at": now or _now_iso(),
            "by": by or "",
        })
    return removed


def unlock_node(state, node, reason: str, *, by: str = "", now: str = "") -> int:
    """Unlock every canonical host of ``node`` (host-scoped).  REQUIRES a
    reason.  Returns the number of records removed."""
    if not (reason or "").strip():
        raise ValueError("unlock requires a recorded reason (issue #85)")
    ts = now or _now_iso()
    return sum(unlock_host(state, h, reason, by=by, now=ts)
               for h in sorted(canonical_hosts(node)))


# ---------------------------------------------------------------------------
# BTP subaccount lock (UUID-keyed — issue #85, cloud/relay coverage)
# ---------------------------------------------------------------------------
# A BTP subaccount is identified ONLY by its UUID — it has no host/IP the
# host matcher can key on:
#   * its region-API host (api.cf.<region>.hana.ondemand.com) is SHARED by
#     every subaccount in the region, so locking it would quarantine them all;
#   * its destination URLs point at ON-PREM targets (independently host-
#     lockable), not at the subaccount itself.
# So a locked subaccount gets its own UUID-keyed store
# (state.locked_btp_subaccounts), parallel to locked_hosts, with the SAME
# recorded-reason unlock discipline.  The host whitelist does NOT apply (there
# is no host to match) — subaccounts are manual-lock only.  Enforcement is at
# the region-API destination/credential pull chokepoints, which resolve the
# subaccount UUID (path param, or offline from the destination-token claim)
# before any network contact.

def _btp_records(state) -> list:
    return getattr(state, "locked_btp_subaccounts", None) or []


def locked_btp_record_for(state, uuid: str):
    """The lock record for a BTP subaccount UUID, else None."""
    u = str(uuid or "").strip()      # str(): a crafted token claim may be non-str
    if not u:
        return None
    for rec in _btp_records(state):
        if (rec.get("uuid") or "").strip() == u:
            return rec
    return None


def is_btp_subaccount_locked(state, uuid: str) -> bool:
    """True if the BTP subaccount UUID is locked — the keystone check the
    region-API pull chokepoints call."""
    return locked_btp_record_for(state, uuid) is not None


def lock_btp_subaccount(state, uuid: str, reason: str = "", *, by: str = "",
                        now: str = ""):
    """Add (or refresh) a lock record for one BTP subaccount.  Idempotent:
    re-locking keeps the original ``locked_at``.  Returns the record, or None
    for an empty uuid."""
    u = str(uuid or "").strip()
    if not u:
        return None
    recs = state.locked_btp_subaccounts
    for rec in recs:
        if (rec.get("uuid") or "").strip() == u:
            if reason:
                rec["reason"] = reason
            return rec
    rec = {
        "uuid": u,
        "reason": reason or "",
        "locked_at": now or _now_iso(),
        "locked_by": by or "",
    }
    recs.append(rec)
    return rec


def unlock_btp_subaccount(state, uuid: str, reason: str, *, by: str = "",
                          now: str = "") -> int:
    """Remove the lock record for a BTP subaccount and append to
    ``unlock_log`` (keyed ``BTP:<uuid>`` so it shares the one audit trail).
    REQUIRES a non-empty reason — the recorded-reason guarantee.  Returns the
    number of records removed."""
    if not (reason or "").strip():
        raise ValueError("unlock requires a recorded reason (issue #85)")
    u = str(uuid or "").strip()
    recs = state.locked_btp_subaccounts
    kept, removed = [], 0
    for r in recs:
        if (r.get("uuid") or "").strip() == u:
            removed += 1
        else:
            kept.append(r)
    state.locked_btp_subaccounts = kept
    if removed:
        state.unlock_log.append({
            "host": f"BTP:{u}",
            "reason": reason.strip(),
            "at": now or _now_iso(),
            "by": by or "",
        })
    return removed


# ---------------------------------------------------------------------------
# HTTP-gate route classification (single source of truth)
# ---------------------------------------------------------------------------
# The before_request gate in sapmap_gui imports these.  Kept here (not in
# sapmap_gui) so the classification is in the one policy module AND the
# coverage test (tests/test_lock_gate_coverage_85.py) can import it to prove
# every node-scoped (<sid>) route is classified — the durable invariant.
#
# Classification fails CLOSED:
#   * every non-GET <sid> route is ACTIVE (denied on a locked host) EXCEPT
#     the small management allowlist below — a NEW active route is therefore
#     auto-denied with no per-route work;
#   * every GET <sid> route MUST be explicitly reviewed into PASSIVE_GET
#     (reads cached data → allowed) or ACTIVE_GET (contacts the target →
#     denied).  An un-reviewed GET is denied at runtime AND fails the
#     coverage test, so a read route can never silently leak contact.

# Non-GET node routes that stay usable on a LOCKED host (lock management).
PASSIVE_NONGET_ROUTES = frozenset({
    "/api/node/<sid>/lock",
    "/api/node/<sid>/unlock",
})

# GET node routes that CONTACT the target (RFC / live probe / secret dump)
# — denied on a locked host despite being GET.
ACTIVE_GET_ROUTES = frozenset({
    "/api/node/<sid>/fs/drives",
    "/api/node/<sid>/msinfo_dump",
    "/api/node/<sid>/ucon_status",
    "/api/node/<sid>/ssh_loot_keys",
    # impact/export looks read-only but its handler (_node_impact_export)
    # falls through to a LIVE RFC re-run (sapmap_impact.assess_one ->
    # _get_connection) on a cache miss — adversarial-review finding.  Treat
    # it as contact (fail closed); the operator can unlock to re-export a
    # scenario that was never cached.
    "/api/node/<sid>/impact/export",
    "/api/node/<sid>/impact/export/<scenario_name>",
})

# GET node routes that only read cached / local state — allowed on a locked
# host so a quarantined node stays fully viewable.  (``/impact`` itself is
# the view-only blast-radius read, computed from the graph — no live
# contact — so it stays passive; only its /export sibling re-runs RFC.)
PASSIVE_GET_ROUTES = frozenset({
    "/api/node/<sid>/evasion_baseline_param",
    "/api/node/<sid>/get_attacker_ip",
    "/api/node/<sid>/get_gw_source_ip",
    "/api/node/<sid>/impact",
    "/api/node/<sid>/ransapware/manifests",
    "/api/node/<sid>/tms_propagate_progress",
    "/api/node/<sid>/transport_progress",
})


def route_is_passive(rule: str, method: str) -> bool:
    """True if a node-scoped route is safe on a LOCKED host.  Fails closed:
    an un-reviewed GET (not in PASSIVE_GET_ROUTES) is NOT passive, and every
    other non-GET route is active unless in the management allowlist."""
    if rule in PASSIVE_NONGET_ROUTES:
        return True
    if (method or "").upper() == "GET":
        return rule in PASSIVE_GET_ROUTES
    return False


def route_is_reviewed(rule: str, method: str) -> bool:
    """True if a node-scoped route is explicitly classified.  Non-GET routes
    are active-by-default and need no per-route review; every GET route must
    appear in PASSIVE_GET_ROUTES or ACTIVE_GET_ROUTES.  The coverage test
    fails on any un-reviewed GET."""
    if (method or "").upper() != "GET":
        return True
    return rule in PASSIVE_GET_ROUTES or rule in ACTIVE_GET_ROUTES


# ---------------------------------------------------------------------------
# SCC host-scoped + BTP subaccount-scoped route classification (PR5)
# ---------------------------------------------------------------------------
# SCC routes are keyed on the connector host (``<host>``), BTP on the
# subaccount UUID (``<uuid>``).  These routes don't flow through the central
# <sid> before_request gate — each handler calls into this module directly
# (``_scc_locked_response`` for SCC, ``is_btp_subaccount_locked`` for BTP).
# Classifying them here keeps the single-source-of-truth property of PR1 and
# lets ``tests/test_lock_pr5_surfacing_85.py`` enforce the same completeness
# invariant on the cloud/relay surface: a NEW contact route that forgets its
# guard turns the suite red instead of silently leaking contact.

# SCC host routes that CONTACT the Cloud Connector (admin API / backup pull /
# unauth hash dump) — must be guarded with ``_scc_locked_response`` in-handler.
SCC_ACTIVE_HOST_ROUTES = frozenset({
    "/api/scc/<host>/probe_creds",
    "/api/scc/<host>/pull_mappings",
    "/api/scc/<host>/probe_mappings",
    "/api/scc/<host>/extract_keystore",
    "/api/scc/<host>/download_user_hashes",
})

# SCC host routes that do NOT contact the connector:
#   * lock/unlock are management (like <sid>/lock);
#   * set_credentials is a local store write (no network);
#   * analyse_pp / decrypt_ssfs read loot files;
#   * lookup_hashes_online reaches hashes.com, not the connector;
#   * DELETE just removes the row from the local map.
SCC_PASSIVE_HOST_ROUTES = frozenset({
    "/api/scc/<host>/lock",
    "/api/scc/<host>/unlock",
    "/api/scc/<host>/set_credentials",
    "/api/scc/<host>/analyse_pp",
    "/api/scc/<host>/decrypt_ssfs",
    "/api/scc/<host>/lookup_hashes_online",
    "/api/scc/<host>",                 # DELETE — local map removal
})

# BTP subaccount routes that CONTACT the cloud region API — must be guarded
# with ``is_btp_subaccount_locked`` in-handler.
BTP_ACTIVE_UUID_ROUTES = frozenset({
    "/api/btp/pull_destinations/<uuid>",
})

# BTP subaccount routes that do NOT contact the cloud region API:
#   * lock/unlock are management;
#   * DELETE just removes the row from the local map.
BTP_PASSIVE_UUID_ROUTES = frozenset({
    "/api/btp/subaccount/<uuid>/lock",
    "/api/btp/subaccount/<uuid>/unlock",
    "/api/btp/subaccount/<uuid>",      # DELETE — local map removal
})


def scc_host_route_is_reviewed(rule: str) -> bool:
    """True if an ``/api/scc/<host>/...`` route is explicitly classified
    (active-contact vs passive-local).  Un-classified routes fail the PR5
    completeness test so a new SCC route can never silently skip the lock
    guard."""
    return rule in SCC_ACTIVE_HOST_ROUTES or rule in SCC_PASSIVE_HOST_ROUTES


def btp_uuid_route_is_reviewed(rule: str) -> bool:
    """True if an ``/api/btp/.../<uuid>...`` route is explicitly classified.
    Same rationale as ``scc_host_route_is_reviewed``."""
    return rule in BTP_ACTIVE_UUID_ROUTES or rule in BTP_PASSIVE_UUID_ROUTES
