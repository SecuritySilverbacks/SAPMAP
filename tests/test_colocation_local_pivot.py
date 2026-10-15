#!/usr/bin/env python3
"""Tests for the same-host secret-harvest fallback (issue #70, increment 1).

When a co-located sibling's own RFC Gateway rejects a remote exploit, SAPMAP
falls back to reading the sibling's Secure Store off ``/usr/sap/<SIB>/...``
through the OWNED node's OS-exec channel on the shared host, decrypting it with
the existing SecStore primitives, and surfacing the DB-connect credentials it
yields.  These tests cover the wiring in ``sap_colocation`` — the SSFS/crypto
itself is covered by the SecStore tests, so it's stubbed here.
"""
from __future__ import annotations

import base64
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "postex"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "data_extraction"))

import sap_colocation  # noqa: E402
from sapmap_models import SAPNode  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _node(sid, ip="10.10.1.6", hostname="abex3", os_type="Linux"):
    return SAPNode(sid=sid, ip=ip, hostname=hostname, os_type=os_type)


@pytest.fixture
def captured_findings(monkeypatch):
    """Capture emit_finding calls (severity, node, msg) without the bus."""
    calls = []
    import sapmap_findings
    monkeypatch.setattr(
        sapmap_findings, "emit_finding",
        lambda sev, node, msg, *a, **k: calls.append((sev, node, msg)))
    return calls


@pytest.fixture
def loot_to_tmp(monkeypatch, tmp_path):
    """Redirect loot writes into a tmp dir so tests don't touch loot/."""
    import sapmap_state
    monkeypatch.setattr(sapmap_state, "ensure_loot_dir",
                        lambda subdir="": str(tmp_path))
    return tmp_path


def _stub_decrypt(monkeypatch, creds, key=b"\x00" * 24):
    """Stub the SecStore byte primitives harvest_colocated_secrets calls."""
    import sapmap_secstore
    monkeypatch.setattr(sapmap_secstore, "extract_ssfs_key",
                        lambda kb: key)
    monkeypatch.setattr(sapmap_secstore, "extract_sybase_kernel_creds",
                        lambda db, k=None: dict(creds))


def _exec_serving(files):
    """Build a run_exec(node, cmd, params) that returns base64 for paths whose
    suffix is in `files` (maps '.DAT'/'.KEY' -> raw bytes); else failure."""
    def run_exec(node, cmd, params):
        for suffix, raw in files.items():
            if params.endswith(suffix) or f"/{suffix.strip('.').lower()}/" in params:
                return {"success": True,
                        "output": [base64.b64encode(raw).decode()]}
        return {"success": False, "output": [], "error": "Permission denied"}
    return run_exec


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def test_sibling_ssfs_paths_unix_and_windows():
    kp, dp = sap_colocation._sibling_ssfs_paths("AE3", is_windows=False)
    assert kp[0] == "/usr/sap/AE3/SYS/global/security/rsecssfs/key/SSFS_AE3.KEY"
    assert dp[0] == "/usr/sap/AE3/SYS/global/security/rsecssfs/data/SSFS_AE3.DAT"
    assert any("/sapmnt/AE3/" in p for p in dp)  # fallback layout present

    kp_w, dp_w = sap_colocation._sibling_ssfs_paths("AE3", is_windows=True)
    assert kp_w[0].endswith("SSFS_AE3.KEY") and "\\usr\\sap\\AE3\\" in kp_w[0]
    assert dp_w[0].endswith("SSFS_AE3.DAT")


def test_same_host_matches_ip_or_hostname():
    a = _node("AE1", ip="10.10.1.6", hostname="abex3")
    b = _node("AE3", ip="10.10.1.6", hostname="abex3")
    c = _node("NPL", ip="192.168.2.106", hostname="vhcalnplci")
    assert sap_colocation._same_host(a, b) is True
    assert sap_colocation._same_host(a, c) is False
    # hostname-only overlap still counts
    d = _node("AE2", ip="10.10.9.9", hostname="abex3")
    assert sap_colocation._same_host(a, d) is True


def test_read_file_b64_decodes_and_fails_closed():
    payload = b"\x01\x02\x03binary-secure-store\xff"
    run_exec = _exec_serving({".DAT": payload})
    raw, path = sap_colocation._read_file_b64_via_os_exec(
        _node("AE1"), ["/usr/sap/AE3/.../SSFS_AE3.DAT"], run_exec, False)
    assert raw == payload and path.endswith(".DAT")

    # Every path denied -> (None, "")
    deny = lambda n, c, p: {"success": False, "output": [], "error": "denied"}
    raw2, path2 = sap_colocation._read_file_b64_via_os_exec(
        _node("AE1"), ["/usr/sap/AE3/x.DAT"], deny, False)
    assert raw2 is None and path2 == ""


# ---------------------------------------------------------------------------
# harvest_colocated_secrets
# ---------------------------------------------------------------------------

def test_harvest_recovers_db_creds_and_writes_loot(
        monkeypatch, captured_findings, loot_to_tmp):
    src, tgt = _node("AE1"), _node("AE3")
    _stub_decrypt(monkeypatch, {
        "sapsr3_user": "SAPAE3", "sapsr3_password": "Sup3rSecret!",
        "sapsa_user": "", "sapsa_password": "",
        "encrypted_missing_key": False, "source": "SSFS",
    })
    run_exec = _exec_serving({".KEY": b"K" * 40, ".DAT": b"D" * 200})

    res = sap_colocation.harvest_colocated_secrets(src, tgt, None, run_exec=run_exec)

    assert res["ok"] is True
    assert res["rsec_key_found"] is True
    assert [c["user"] for c in res["db_creds"]] == ["SAPAE3"]
    assert res["db_creds"][0]["has_password"] is True
    # Loot persisted
    assert res["loot_path"] and os.path.isfile(res["loot_path"])
    # A HIGH finding was surfaced for the recovered credential...
    highs = [m for sev, _, m in captured_findings if sev == "HIGH"]
    assert any("SAPAE3" in m and "AE3" in m for m in highs)
    # ...but the password must NEVER appear in any finding text.
    assert all("Sup3rSecret!" not in m for _, _, m in captured_findings)


def test_harvest_password_never_leaks_to_loot_filename(
        monkeypatch, captured_findings, loot_to_tmp):
    src, tgt = _node("AE1"), _node("AE3")
    _stub_decrypt(monkeypatch, {
        "sapsr3_user": "SAPAE3", "sapsr3_password": "pw", "sapsa_user": "",
        "sapsa_password": "", "encrypted_missing_key": False, "source": "SSFS",
    })
    run_exec = _exec_serving({".KEY": b"K" * 40, ".DAT": b"D" * 200})
    res = sap_colocation.harvest_colocated_secrets(src, tgt, None, run_exec=run_exec)
    # The loot file stores the password (operator loot, like SecStore) — but the
    # filename does not, and the console/finding path does not echo it.
    assert "pw" not in os.path.basename(res["loot_path"])


def test_harvest_permission_denied_is_nonfatal(
        monkeypatch, captured_findings, loot_to_tmp):
    src, tgt = _node("AE1"), _node("AE3")
    # decrypt stubs raise if ever called — a denied read must not reach them
    import sapmap_secstore
    monkeypatch.setattr(sapmap_secstore, "extract_sybase_kernel_creds",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("called")))
    deny = lambda n, c, p: {"success": False, "output": [], "error": "Permission denied"}

    res = sap_colocation.harvest_colocated_secrets(src, tgt, None, run_exec=deny)

    assert res["ok"] is False
    assert "could not read" in res["reason"]
    assert res["db_creds"] == [] and res["loot_path"] == ""
    assert any(sev == "INFO" for sev, _, _ in captured_findings)


def test_harvest_hana_sibling_reports_hdbuserstore(
        monkeypatch, captured_findings, loot_to_tmp):
    """SSFS readable + RSEC key recovered but no DB_CONNECT creds (the HANA
    case: connect creds live in the sibling-admin's hdbuserstore)."""
    src, tgt = _node("AE1"), _node("AE3")
    _stub_decrypt(monkeypatch, {
        "sapsr3_user": "", "sapsr3_password": "", "sapsa_user": "",
        "sapsa_password": "", "encrypted_missing_key": False, "source": "SSFS",
    })
    run_exec = _exec_serving({".KEY": b"K" * 40, ".DAT": b"D" * 200})

    res = sap_colocation.harvest_colocated_secrets(src, tgt, None, run_exec=run_exec)

    assert res["ok"] is True          # the RSEC key alone counts as a result
    assert res["db_creds"] == [] and res["loot_path"] == ""
    assert any("hdbuserstore" in m for _, _, m in captured_findings)


def test_harvest_rejects_cross_host_target(monkeypatch):
    src = _node("AE1", ip="10.10.1.6", hostname="abex3")
    tgt = _node("NPL", ip="192.168.2.106", hostname="vhcalnplci")
    called = []
    res = sap_colocation.harvest_colocated_secrets(
        src, tgt, None, run_exec=lambda *a, **k: called.append(1))
    assert res["ok"] is False and "same host" in res["reason"]
    assert called == []               # never touches the OS-exec channel


def test_harvest_rejects_self_target(monkeypatch):
    src = _node("AE1")
    tgt = _node("AE1")                # same SID
    called = []
    res = sap_colocation.harvest_colocated_secrets(
        src, tgt, None, run_exec=lambda *a, **k: called.append(1))
    assert res["ok"] is False and "source node" in res["reason"]
    assert called == []


# ---------------------------------------------------------------------------
# Review fixes (correctness lens)
# ---------------------------------------------------------------------------

def test_harvest_rejects_invalid_sid(monkeypatch):
    """A SID flows into OS paths + commands — a non-SID value is refused
    before any exec, regardless of same-host."""
    src = _node("AE1")
    tgt = _node("A;B", ip="10.10.1.6", hostname="abex3")  # same host, bad SID
    called = []
    res = sap_colocation.harvest_colocated_secrets(
        src, tgt, None, run_exec=lambda *a, **k: called.append(1))
    assert res["ok"] is False and "not a valid SID" in res["reason"]
    assert called == []


def test_harvest_is_windows_follows_source_not_target(monkeypatch,
                                                       captured_findings,
                                                       loot_to_tmp):
    """is_windows must follow the OS-exec host (src), not the sibling — which
    is often a placeholder with os_type=''.  A Windows src + empty-os_type
    sibling must drive the certutil (cmd.exe) read path, not Unix base64."""
    src = _node("AE1", os_type="Windows")
    tgt = _node("AE3", os_type="")        # placeholder-style empty os_type
    seen = []

    def rec(node, cmd, params):
        seen.append(cmd)
        return {"success": False, "output": [], "error": "denied"}

    sap_colocation.harvest_colocated_secrets(src, tgt, None, run_exec=rec)
    assert seen and all(c == "cmd" for c in seen), (
        f"expected Windows certutil path (cmd), got {seen}")


def test_harvest_key_readable_dat_denied_keeps_rsec_signal(
        monkeypatch, captured_findings, loot_to_tmp):
    """KEY readable but DAT denied: keep rsec_key_found + an honest reason
    instead of discarding the key and claiming 'could not read SSFS'."""
    src, tgt = _node("AE1"), _node("AE3")
    import sapmap_secstore
    monkeypatch.setattr(sapmap_secstore, "extract_ssfs_key",
                        lambda kb: b"\x00" * 24)

    def rec(node, cmd, params):
        if params.endswith(".KEY") or "/key/" in params:
            return {"success": True, "output": [base64.b64encode(b"K" * 40).decode()]}
        return {"success": False, "output": [], "error": "denied"}  # DAT denied

    res = sap_colocation.harvest_colocated_secrets(src, tgt, None, run_exec=rec)
    assert res["rsec_key_found"] is True
    assert "KEY" in res["reason"] and "DAT" in res["reason"]
    assert res["db_creds"] == []


# ---------------------------------------------------------------------------
# pivot_colocated — orchestration, target resolution, loop guard
# ---------------------------------------------------------------------------

class _State:
    def __init__(self, nodes):
        self.nodes = {n.sid: n for n in nodes}
        self.created = []

    def track_created_user(self, cu):
        self.created.append(cu)


def test_resolve_same_host_targets_picks_same_host_node():
    """DAA exists on two hosts; resolving from AE1@.6 must pick DAA on .6,
    never the DAA on .5 (the @-mangle pitfall)."""
    ae1 = _node("AE1", ip="10.10.1.6", hostname="abex3")
    ae1.colocated_sids = [{"sid": "DAA", "plotted": True}]
    daa5 = _node("DAA", ip="10.10.1.5", hostname="abex1")
    daa6 = _node("DAA@10.10.1.6", ip="10.10.1.6", hostname="abex3")
    state = _State([ae1, daa5, daa6])
    targets = sap_colocation._resolve_same_host_targets(ae1, state)
    assert targets == [daa6], f"expected [DAA@.6], got {[t.sid for t in targets]}"


def test_pivot_prefers_gateway_then_falls_back_to_harvest(monkeypatch):
    ae1 = _node("AE1", ip="10.10.1.6")
    ae1.colocated_sids = [{"sid": "AE3", "plotted": True}]
    ae3 = _node("AE3", ip="10.10.1.6")
    state = _State([ae1, ae3])
    import sapmap_exploit

    # Gateway succeeds -> harvest not attempted.
    monkeypatch.setattr(sapmap_exploit, "create_user_gw_exploit",
                        lambda t, s: {"user": "SAPMAP00"})
    monkeypatch.setattr(sapmap_exploit, "_post_exploit_enrichment",
                        lambda *a, **k: None)
    harvested = []
    monkeypatch.setattr(sap_colocation, "harvest_colocated_secrets",
                        lambda *a, **k: harvested.append(1) or {"ok": False})
    summ = sap_colocation.pivot_colocated(ae1, state)
    assert summ["owned"] == ["AE3"] and harvested == []

    # Gateway fails -> harvest fallback runs.
    ae3.pwned = False
    monkeypatch.setattr(sapmap_exploit, "create_user_gw_exploit",
                        lambda t, s: None)
    monkeypatch.setattr(sap_colocation, "harvest_colocated_secrets",
                        lambda *a, **k: {"ok": True, "db_creds": [{"user": "SAPAE3"}],
                                         "loot_path": "/tmp/x.json"})
    summ2 = sap_colocation.pivot_colocated(ae1, state)
    assert summ2["harvested"] == ["AE3"] and summ2["owned"] == []


def test_auto_pivot_loop_terminates_and_skips_owned(monkeypatch):
    """AE1 (already owned) auto-pivots to AE3; AE3's enrichment auto-pivots
    back to AE1 — which is skipped (pwned) + guarded (in-progress).  Must
    terminate with AE3 owned exactly once and AE1 never re-owned."""
    ae1 = _node("AE1", ip="10.10.1.6")
    ae1.colocated_sids = [{"sid": "AE3", "plotted": True}]
    ae1.pwned = True
    ae3 = _node("AE3", ip="10.10.1.6")
    ae3.colocated_sids = [{"sid": "AE1", "plotted": True}]
    state = _State([ae1, ae3])
    import sapmap_exploit

    calls = []

    def fake_create(t, s):
        calls.append(t.sid)
        t.pwned = True
        return {"user": "SAPMAP00"}

    def fake_enrich(t, s, proven_type=""):
        # mirrors the real hook: discovery+auto-pivot from the freshly-owned node
        sap_colocation.pivot_colocated(t, s, auto=True)

    monkeypatch.setattr(sapmap_exploit, "create_user_gw_exploit", fake_create)
    monkeypatch.setattr(sapmap_exploit, "_post_exploit_enrichment", fake_enrich)

    summ = sap_colocation.pivot_colocated(ae1, state, auto=True)
    assert calls == ["AE3"], f"AE3 owned once, AE1 never re-owned; got {calls}"
    assert summ["owned"] == ["AE3"]
    assert not sap_colocation._PIVOT_IN_PROGRESS  # cleaned up


def test_auto_pivot_in_progress_guard_blocks_reentry(monkeypatch):
    """A src already mid auto-pivot chain is not re-entered (backstop even if
    pwned-skip were to fail)."""
    ae1 = _node("AE1", ip="10.10.1.6")
    ae1.colocated_sids = [{"sid": "AE3", "plotted": True}]
    ae3 = _node("AE3", ip="10.10.1.6")
    state = _State([ae1, ae3])
    import sapmap_exploit
    calls = []
    monkeypatch.setattr(sapmap_exploit, "create_user_gw_exploit",
                        lambda t, s: calls.append(t.sid) or {"user": "x"})
    monkeypatch.setattr(sapmap_exploit, "_post_exploit_enrichment",
                        lambda *a, **k: None)

    sap_colocation._PIVOT_IN_PROGRESS.add("AE1")
    try:
        summ = sap_colocation.pivot_colocated(ae1, state, auto=True)
    finally:
        sap_colocation._PIVOT_IN_PROGRESS.discard("AE1")
    assert summ["owned"] == [] and calls == []
