"""Unit tests for sapmap_pwspray (issue #69, PR1 scope).

Covers the lockout-safety invariants + the pool/target-matrix shape.
Everything is mocked: no sockets opened, no filesystem writes, no RFC.

House style: mock try_login via dependency injection (the engine
accepts a ``try_login_fn`` kwarg) rather than monkey-patching the
sap_default_creds module, so parallel test runs don't race.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from sapmap_models import (Credentials, InstanceInfo, SAPMAPState, SAPNode,
                            SCCNode)
from sap_default_creds import (SUCCESS, USER_LOCKED, NO_DIALOG_USER,
                                WRONG_PASSWORD)
import sapmap_pwspray as pw


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_target_node(sid: str, ip: str = "10.0.0.1",
                       system_type: str = "ABAP",
                       clients=None,
                       dispatcher_port: int = 3200) -> SAPNode:
    """A node that passes build_target_matrix's eligibility checks."""
    inst = InstanceInfo(instance_nr="00", ip=ip,
                        ports={dispatcher_port: "dispatcher",
                               3300: "gateway"})
    node = SAPNode(sid=sid, system_type=system_type, hostname="h", ip=ip)
    node.instances.append(inst)
    for c in (clients or ["000", "001"]):
        node.clients.append({"nr": c, "category": "P"})
    return node


class _FakeTryLogin:
    """Dependency-injected replacement for sap_default_creds.try_login.

    Looks up (user_upper, password, client) tuples in ``hits`` to decide
    which outcome to return.  Any other call returns WRONG_PASSWORD by
    default (or the configured ``default_result``).  All calls are
    recorded in ``self.calls`` for assertion.
    """
    def __init__(self, hits=None, locked_on=None, nodialog_on=None,
                 default_result=(WRONG_PASSWORD, "no match")):
        self.hits = {k: (SUCCESS, "ok") for k in (hits or [])}
        self.locked_on = set(locked_on or [])    # (user_upper, client) pairs
        self.nodialog_on = set(nodialog_on or [])
        self.default_result = default_result
        self.calls = []

    def __call__(self, host, port, client, user, password, **kw):
        self.calls.append({"host": host, "port": port, "client": client,
                           "user": user, "password": password, "kw": kw})
        u = (user or "").upper()
        if (u, client) in self.locked_on:
            return (USER_LOCKED, "locked")
        if (u, client) in self.nodialog_on:
            return (NO_DIALOG_USER, "service user")
        hit = self.hits.get((u, password, client))
        if hit:
            return hit
        return self.default_result


# ---------------------------------------------------------------------------
# Test 1 — pool collection unions all stores
# ---------------------------------------------------------------------------

def test_pool_collection_unions_all_stores():
    """landscape_password_pool walks node.credentials + oauth2_client
    secstore_entries + state.scc_nodes[*].credentials; dedups by
    (user.upper, password); orders verified-SAPMAP first."""
    state = SAPMAPState()
    n = _make_target_node("NPL")
    n.credentials = [
        Credentials(username="SAPMAP00", password="andy", client="001",
                    verified=True),
        Credentials(username="JORIS", password="pw1", client="001",
                    verified=False),
        # Same (user, password) as above → dedup; also drop empty cred.
        Credentials(username="joris", password="pw1", client="100"),
        Credentials(username="", password="x"),
    ]
    n.secstore_entries = [
        {"category": "oauth2_client", "username": "oauth-sa",
         "password": "sek"},
        {"category": "secstore_entry", "username": "ignored", "password": "x"},
    ]
    state.nodes["NPL"] = n
    scc = SCCNode(host="scc1.example")
    scc.credentials = [Credentials(username="scc_admin", password="sc-pw")]
    state.scc_nodes["scc1.example"] = scc

    pool = pw.landscape_password_pool(state)

    users = [(c.username.upper(), c.password) for c in pool]
    assert ("SAPMAP00", "andy") in users
    assert ("JORIS", "pw1") in users
    assert ("OAUTH-SA", "sek") in users
    assert ("SCC_ADMIN", "sc-pw") in users
    assert ("", "x") not in users
    # Dedup collapsed the two 'joris/pw1' entries
    assert sum(1 for u, p in users if (u, p) == ("JORIS", "pw1")) == 1
    # The dedup incremented reuse_count on the surviving entry
    joris = [c for c in pool if c.username.upper() == "JORIS"][0]
    assert joris.reuse_count == 2
    # Ordering: verified-SAPMAP first
    assert pool[0].username.upper() == "SAPMAP00"


# ---------------------------------------------------------------------------
# Test 2 — pool excludes wd_admin / scc / dbcon from DIAG by default
# ---------------------------------------------------------------------------

def test_pool_excludes_wd_admin_scc_db_by_default():
    """kind='wd_admin' and kind='scc' are HTTP-Basic creds, not DIAG;
    DBCON kernel creds (sapsa/sapsr3) are DB-level, not user accounts."""
    state = SAPMAPState()
    n = _make_target_node("NPL")
    n.credentials = [
        Credentials(username="WDADM", password="wd", kind="wd_admin"),
        Credentials(username="SCCADM", password="sc", kind="scc"),
        Credentials(username="JORIS", password="pw1"),
    ]
    # DBCON edges — minimal duck-typed objects so we don't need the
    # DBCONConnection dataclass constructor
    e = MagicMock()
    e.username = "sapsa"
    e.password = "secret"
    n.dbcon_edges = [e]
    state.nodes["NPL"] = n

    # Default — wd_admin + scc + dbcon all dropped
    pool = pw.landscape_password_pool(state)
    unames = {c.username.upper() for c in pool}
    assert "WDADM" not in unames
    assert "SCCADM" not in unames
    assert "SAPSA" not in unames
    assert "JORIS" in unames

    # include_db_connect=True reintroduces sapsa
    pool2 = pw.landscape_password_pool(state, include_db_connect=True)
    assert "SAPSA" in {c.username.upper() for c in pool2}


# ---------------------------------------------------------------------------
# Test 3 — short-circuit on first SUCCESS per (client, user)
# ---------------------------------------------------------------------------

def test_short_circuit_on_first_hit_per_user_client():
    """A pool of 15 passwords for user X; a hit on password #3.  Engine
    must stop at the hit — exactly 3 calls, not 15, not cap."""
    target = pw.SprayTarget(sid="NPL", host="1.1.1.1",
                             dispatcher_port=3200, clients=["001"])
    pool = [pw.SprayCandidate(username="X", password=f"pw{i}")
            for i in range(15)]
    fake = _FakeTryLogin(hits=[("X", "pw2", "001")])

    results = pw.check_sprayed_credentials(
        target.host, target.dispatcher_port, target.clients, pool,
        cap_per_user=15, early_exit_on_hit=True,
        inter_attempt_sleep_range=(0, 0),
        try_login_fn=fake, skip_users=set())

    x_calls = [c for c in fake.calls if c["user"] == "X"]
    assert len(x_calls) == 3, (
        f"short-circuit broken: expected 3 calls, got {len(x_calls)}")
    hits = [r for r in results if r.get("kind") == "hit"]
    assert len(hits) == 1
    assert hits[0]["password"] == "pw2"


# ---------------------------------------------------------------------------
# Test 4 — per-user cap enforcement
# ---------------------------------------------------------------------------

def test_per_user_cap_enforced():
    """cap_per_user=2 → at most 2 attempts per (client, user), even when
    the pool has more passwords for that user and none hit."""
    pool = [pw.SprayCandidate(username="BOB", password=f"pw{i}")
            for i in range(10)]
    fake = _FakeTryLogin()   # all WRONG_PASSWORD

    pw.check_sprayed_credentials(
        "h", 3200, ["001"], pool,
        cap_per_user=2, early_exit_on_hit=True,
        inter_attempt_sleep_range=(0, 0),
        try_login_fn=fake, skip_users=set())
    bob = [c for c in fake.calls if c["user"] == "BOB"]
    assert len(bob) == 2


# ---------------------------------------------------------------------------
# Test 5 — USER_LOCKED breaks remaining attempts for that user
# ---------------------------------------------------------------------------

def test_user_locked_breaks_remaining():
    """One USER_LOCKED observation stops further attempts for that user
    across the remaining passwords on this call."""
    pool = [pw.SprayCandidate(username="BOB", password=f"pw{i}")
            for i in range(5)]
    fake = _FakeTryLogin(locked_on=[("BOB", "001")])

    results = pw.check_sprayed_credentials(
        "h", 3200, ["001"], pool,
        cap_per_user=10, early_exit_on_hit=True,
        inter_attempt_sleep_range=(0, 0),
        try_login_fn=fake, skip_users=set())
    assert sum(1 for c in fake.calls if c["user"] == "BOB") == 1
    assert any(r.get("kind") == "locked" for r in results)


# ---------------------------------------------------------------------------
# Test 6 — landscape-wide locked-users set
# ---------------------------------------------------------------------------

def test_landscape_wide_locked_users_persists_round_trip():
    """A USER_LOCKED on target A for user X puts X into
    state.pwspray_locked_users; it survives a to_dict/from_dict
    round-trip; a fresh spray with X in pre_known_locked_users
    refuses X across every client without calling try_login."""
    state = SAPMAPState()
    pw._record_lockout_landscape_wide(state, "A", "001", "DDIC")
    assert "DDIC" in state.pwspray_locked_users
    # round-trip
    state2 = SAPMAPState.from_dict(state.to_dict())
    assert "DDIC" in state2.pwspray_locked_users

    pool = [pw.SprayCandidate(username="DDIC", password="19920706")]
    fake = _FakeTryLogin(default_result=(WRONG_PASSWORD, "nope"))
    results = pw.check_sprayed_credentials(
        "h", 3200, ["000", "100"], pool,
        cap_per_user=2, inter_attempt_sleep_range=(0, 0),
        pre_known_locked_users={"DDIC"},
        try_login_fn=fake, skip_users=set())
    assert fake.calls == []
    assert all(r.get("skipped_reason") == "landscape_locked"
               for r in results)


# ---------------------------------------------------------------------------
# Test 7 — skip-list honors SAP* / DDIC by default
# ---------------------------------------------------------------------------

def test_skip_list_honors_sap_star_and_ddic_by_default():
    """DEFAULT_SKIP_USERS blocks SAP*/DDIC on all clients when the
    operator didn't tick opt-in; the engine never calls try_login."""
    pool = [pw.SprayCandidate(username="SAP*", password="06071992"),
            pw.SprayCandidate(username="DDIC", password="19920706")]
    fake = _FakeTryLogin()
    skip = pw._effective_skip_users(set())
    assert "SAP*" in skip and "DDIC" in skip
    pw.check_sprayed_credentials(
        "h", 3200, ["000", "001"], pool,
        cap_per_user=2, inter_attempt_sleep_range=(0, 0),
        try_login_fn=fake, skip_users=skip)
    assert fake.calls == []


# ---------------------------------------------------------------------------
# Test 8 — dry-run opens zero sockets
# ---------------------------------------------------------------------------

def test_dry_run_opens_zero_sockets():
    """config.dry_run=True → spray_landscape returns a SprayRun with
    attempts_done=0 and NO calls to try_login.  The target matrix +
    pool are still resolved."""
    state = SAPMAPState()
    n = _make_target_node("NPL")
    n.credentials = [Credentials(username="JORIS", password="pw1",
                                  verified=True)]
    state.nodes["NPL"] = n
    fake = _FakeTryLogin()
    cfg = pw.SprayConfig(dry_run=True, cap_per_user=2)
    run = pw.spray_landscape(state, cfg, try_login_fn=fake)
    assert fake.calls == []
    assert run.attempts_done == 0
    # Even with accept_lockout_risk+dry_run=False, if cap=1 and the
    # pool is empty, we'd see zero calls — assert the gate works.
    cfg2 = pw.SprayConfig(dry_run=False, accept_lockout_risk=False,
                           cap_per_user=1)
    run2 = pw.spray_landscape(state, cfg2, try_login_fn=fake)
    assert run2.aborted == "dry_run_default_active"
    assert fake.calls == []


# ---------------------------------------------------------------------------
# Test 9 — dedup upgrades verified=False to True on hit
# ---------------------------------------------------------------------------

def test_dedup_upgrades_verified_false_to_true():
    """Pre-existing Credentials(username=X, client='100', password='p',
    verified=False) on the target gets upgraded in place when spray
    lands SUCCESS with matching (user, client, password).  Fixes an
    existing gap where node_check_default_creds appended a duplicate."""
    state = SAPMAPState()
    n = _make_target_node("NPL", clients=["001"])
    existing = Credentials(username="JORIS", password="pw1",
                            client="001", verified=False)
    n.credentials = [existing]
    state.nodes["NPL"] = n
    fake = _FakeTryLogin(hits=[("JORIS", "pw1", "001")])
    cfg = pw.SprayConfig(dry_run=False, accept_lockout_risk=True,
                          cap_per_user=1)
    run = pw.spray_landscape(state, cfg, try_login_fn=fake,
                              loot_dir_fn=lambda _: "")
    # Still exactly one JORIS credential on the node
    joris = [c for c in n.credentials
             if (c.username or "").upper() == "JORIS"]
    assert len(joris) == 1, "duplicate credential appended"
    assert joris[0].verified is True, "verified flag not upgraded"
    assert run.hits and run.hits[0]["user"] == "JORIS"


# ---------------------------------------------------------------------------
# Test 10 — rename_node_sid rewrites spray counter keys
# ---------------------------------------------------------------------------

def test_rename_node_sid_rewrites_spray_counter():
    """SAPMAPState.rename_node_sid('OLD','NEW') must rewrite keys in
    state.spray_attempts_counter from 'OLD|...' to 'NEW|...' AND
    rewrite sids inside pwspray_locked_users entries' locked_on
    rows.  Prevents the per-user budget from resetting after a
    placeholder→real-SID rename."""
    state = SAPMAPState()
    state.nodes["OLD"] = _make_target_node("OLD")
    state.spray_attempts_counter["OLD|001|DDIC"] = {"count": 1}
    state.pwspray_locked_users["DDIC"] = {
        "username": "DDIC",
        "locked_on": [["OLD", "001", "2026-01-01T00:00:00"]],
        "unlock_eta": None,
    }
    err = state.rename_node_sid("OLD", "NEW")
    assert err == ""
    assert "NEW|001|DDIC" in state.spray_attempts_counter
    assert "OLD|001|DDIC" not in state.spray_attempts_counter
    assert state.spray_attempts_counter["NEW|001|DDIC"]["count"] == 1
    assert state.pwspray_locked_users["DDIC"]["locked_on"][0][0] == "NEW"


# ---------------------------------------------------------------------------
# Test 11 — cross-target circuit breaker
# ---------------------------------------------------------------------------

def test_cross_target_circuit_breaker_trips_and_propagates():
    """max_total_locks_per_run=2 trips after the 2nd lockout.  The
    remaining target(s) get ``_propagate_locked_out=True`` and the
    SprayRun is marked ``aborted='cascade_abort'``.

    Uses three DIFFERENT usernames (one per target) so the stricter
    landscape-wide locked-user guard — which pre-emptively refuses a
    user after its first lock anywhere — doesn't short-circuit the
    sweep before the breaker's threshold is reached."""
    state = SAPMAPState()
    users = ["USER_A", "USER_B", "USER_C"]  # none in DEFAULT_SKIP_USERS
    for sid in ("A", "B", "C"):
        state.nodes[sid] = _make_target_node(sid, clients=["001"])
    cfg = pw.SprayConfig(
        dry_run=False, accept_lockout_risk=True, cap_per_user=1,
        max_total_locks_per_run=2,
        manual_wordlist=[(u, "pw1") for u in users],
    )
    # Each user locks when attempted on client "001"
    fake = _FakeTryLogin(locked_on=[(u, "001") for u in users])
    run = pw.spray_landscape(state, cfg, try_login_fn=fake,
                              loot_dir_fn=lambda _: "")
    # Expected: target A sprays all 3 users → 3 calls, 3 locks on A
    # alone trips the breaker.  Actually, each user hits USER_LOCKED
    # on the first attempt and the inner loop stops the user.  After
    # the first lock on A, total_locks_observed=1; after the second,
    # =2 (reaches threshold).  Engine continues to the third user on
    # A because the breaker only checks BETWEEN targets.  So A fires
    # 3 calls, breaker trips at the start of B, B+C make zero calls.
    assert len(fake.calls) == 3, (
        f"breaker should halt after target A completes; calls={fake.calls}")
    assert run.aborted == "cascade_abort"
    # Remaining targets have _propagate_locked_out set.
    assert bool(getattr(state.nodes["B"], "_propagate_locked_out", False))
    assert bool(getattr(state.nodes["C"], "_propagate_locked_out", False))


# ---------------------------------------------------------------------------
# Test 12 — compute_attempt_budget with/without probe
# ---------------------------------------------------------------------------

def test_compute_attempt_budget_floors_at_1_when_policy_unknown():
    """No probe → unknown-policy floor of 1 with a warning."""
    node = _make_target_node("NPL")
    out = pw.compute_attempt_budget(node, operator_cap=2, probe_fn=None)
    assert out["cap_per_user"] == 1
    assert out["cap_source"].startswith("unknown_policy")
    assert out["warnings"]


def test_compute_attempt_budget_uses_probe_when_available():
    """Probe returns fails_to_user_lock=5 + baseline_counter=1 →
    cap = max(1, 5-2-1) = 2, capped by MAX_CAP_PER_USER=2."""
    node = _make_target_node("NPL")
    out = pw.compute_attempt_budget(
        node, operator_cap=2,
        probe_fn=lambda _n: {"fails_to_user_lock": 5,
                              "baseline_counter": 1,
                              "baseline_counter_known": True})
    assert out["cap_per_user"] == 2
    assert "policy_known" in out["cap_source"]


def test_compute_attempt_budget_respects_ucon_block():
    """Probe reports ``status='ucon_blocked'`` → fall back to the
    unknown-policy floor with the UCON-specific cap_source."""
    node = _make_target_node("NPL")
    out = pw.compute_attempt_budget(
        node, operator_cap=2,
        probe_fn=lambda _n: {"status": "ucon_blocked"})
    assert out["cap_per_user"] == 1
    assert out["cap_source"] == "ucon_blocked_default_floor"


# ---------------------------------------------------------------------------
# Test 13 — ATT&CK capability resolves to real T-IDs
# ---------------------------------------------------------------------------

def test_attack_capabilities_resolve_to_real_techniques():
    """evasion-tier style check: the 3 new capability keys for
    password spraying must resolve to T-IDs that are in the
    TECHNIQUES catalogue."""
    from sapmap_attack import techniques_for, lookup
    for cap in ("creds.password_spray",
                "creds.password_reuse_cross_system",
                "creds.password_spray_purple_telemetry"):
        tids = techniques_for(cap)
        assert tids, f"capability {cap!r} has no T-IDs"
        for t in tids:
            assert lookup(t), f"T-ID {t} (from {cap}) not in TECHNIQUES"
    # T1110.003 must be the primary tag on creds.password_spray
    from sapmap_attack import techniques_for as _tf
    assert "T1110.003" in _tf("creds.password_spray")
