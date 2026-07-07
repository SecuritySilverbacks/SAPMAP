"""Tests for the Virtual SAP Death Star (Julian Petersohn) integration.

Covers:
  * Registry: ``sal_death_star`` is a registered Tier 3 technique.
  * Gate: ``tier3_sal_death_star_launch`` refuses when ``--allow-evasion``
    is off; refuses on Windows targets; refuses on non-baselined nodes.
  * Deployment scripter: gzip/base64 payload, shell quoting, worker
    PID selection prefer ``_W<n>``.
  * Vendored source exists on disk.

No real target is spun up — everything is mocked so tests run in the
same environment as the rest of the SAPMAP suite.
"""
from __future__ import annotations

import os
import re
from unittest.mock import patch, MagicMock

import pytest

from sapmap_models import SAPMAPState, SAPNode
import sapmap_evasion
import sapmap_evasion_gate
import sapmap_evasion_tier3
import sapmap_death_star


# ---------------------------------------------------------------------------
# Vendored source
# ---------------------------------------------------------------------------

def test_vendored_source_exists():
    assert os.path.isfile(sapmap_death_star.HOOK_SOURCE_PATH), (
        f"expected sap_audit_hook.c at "
        f"{sapmap_death_star.HOOK_SOURCE_PATH!r}")


def test_vendored_source_has_expected_shape():
    with open(sapmap_death_star.HOOK_SOURCE_PATH, "rb") as fh:
        head = fh.read(4096)
    assert b"sap_audit_hook" in head
    assert b"ptrace" in head
    # Attribution header
    assert b"Julian Petersohn" in head
    assert b"virtual-sap-death-star" in head


# ---------------------------------------------------------------------------
# Gate registry
# ---------------------------------------------------------------------------

def test_death_star_registered_as_tier3():
    assert "sal_death_star" in sapmap_evasion_gate.TIER3_TECHNIQUES
    t = sapmap_evasion_gate.TIER3_TECHNIQUES["sal_death_star"]
    assert "Death Star" in t.label
    assert t.required_flag == "allow_evasion"


def test_death_star_label_lookup():
    assert "Death Star" in sapmap_evasion_gate.technique_label(
        "sal_death_star")


# ---------------------------------------------------------------------------
# Payload / helpers
# ---------------------------------------------------------------------------

def test_shellquote_escapes_single_quotes():
    assert sapmap_death_star._shellquote("plain") == "'plain'"
    # Embedded single quotes get resumed via '"'"'
    assert sapmap_death_star._shellquote("it's") == "'it'\"'\"'s'"


def test_gzip_b64_roundtrip():
    """The payload must decode back to the original bytes so the
    on-target ``base64 -d | gunzip`` produces byte-identical source."""
    import base64
    import gzip
    src = sapmap_death_star._read_source_bytes()
    b64 = sapmap_death_star._gzip_b64(src)
    decoded = gzip.decompress(base64.b64decode(b64))
    assert decoded == src


def test_gzip_b64_compresses_the_source():
    """The whole point of gzipping first is to fit a ~61 KB source
    into a manageable SXPG argv payload.  Sanity check the ratio."""
    src = sapmap_death_star._read_source_bytes()
    b64 = sapmap_death_star._gzip_b64(src)
    # Raw base64 of 61 KB → ~82 KB.  gzip should get us well under that.
    assert len(b64) < len(src) * 0.6, (
        f"gzip+b64 payload ({len(b64)} B) not smaller enough than raw "
        f"source ({len(src)} B) — check gzip level")


# ---------------------------------------------------------------------------
# find_worker_pid — prefer _W<n>, fall back to BTC/SPO/UP2
# ---------------------------------------------------------------------------

def _mk_node(sid="S4H", os_type="Linux"):
    return SAPNode(sid=sid, hostname="s4hanadev", ip="192.168.2.209",
                    os_type=os_type)


def test_find_worker_pid_prefers_dialog_worker():
    ps_out = [
        "  4711 dw.sapS4H_D00_DP dispatcher",
        "  4712 dw.sapS4H_D00_W0 worker 0",
        "  4713 dw.sapS4H_D00_W1 worker 1",
        "  4714 dw.sapS4H_D00_BTC batch",
    ]
    with patch("sapmap_death_star._run") as mock_run:
        mock_run.return_value = {"success": True, "output": ps_out,
                                  "error": ""}
        pid, comm = sapmap_death_star.find_worker_pid(_mk_node())
    assert pid == 4712
    assert comm.endswith("_W0")


def test_find_worker_pid_falls_back_to_btc_when_no_dialog():
    ps_out = [
        "  5001 dw.sapS4H_D00_DP dispatcher",
        "  5002 dw.sapS4H_D00_BTC batch",
        "  5003 dw.sapS4H_D00_SPO spool",
    ]
    with patch("sapmap_death_star._run") as mock_run:
        mock_run.return_value = {"success": True, "output": ps_out,
                                  "error": ""}
        pid, comm = sapmap_death_star.find_worker_pid(_mk_node())
    # First non-dispatcher wins the fallback.
    assert pid == 5002
    assert comm.endswith("_BTC")


def test_find_worker_pid_refuses_dispatcher():
    ps_out = ["  6001 dw.sapS4H_D00_DP dispatcher only"]
    with patch("sapmap_death_star._run") as mock_run:
        mock_run.return_value = {"success": True, "output": ps_out,
                                  "error": ""}
        with pytest.raises(sapmap_death_star.DeathStarError):
            sapmap_death_star.find_worker_pid(_mk_node())


def test_find_worker_pid_raises_when_ps_fails():
    with patch("sapmap_death_star._run") as mock_run:
        mock_run.return_value = {"success": False, "output": [],
                                  "error": "SXPG denied"}
        with pytest.raises(sapmap_death_star.DeathStarError,
                            match="ps failed"):
            sapmap_death_star.find_worker_pid(_mk_node())


# ---------------------------------------------------------------------------
# Tier 3 entry point — gate + OS guard
# ---------------------------------------------------------------------------

def _armed_state():
    state = SAPMAPState()
    state.evasion = {
        "allow_evasion": True,
        "baseline_captured_at": "2026-07-07T08:00:00",
        "diag_terminal_name": "",
        "os_exec_channel": "",
        "mysapsso2_users": "",
        "updated_at": "2026-07-07T08:00:00",
    }
    return state


def test_death_star_launch_refuses_without_evasion_arm():
    state = SAPMAPState()  # allow_evasion defaults False
    node = _mk_node()
    node._evasion_baseline = {"params": {"rsau/enable": "1"}}
    r = sapmap_evasion_tier3.tier3_sal_death_star_launch(state, node)
    assert r["ok"] is False
    assert "allow-evasion" in r["error"].lower() or (
        "not armed" in r["error"].lower())


def test_death_star_launch_refuses_on_windows_target():
    state = _armed_state()
    node = _mk_node(os_type="Windows NT")
    node._evasion_baseline = {"params": {}}
    r = sapmap_evasion_tier3.tier3_sal_death_star_launch(state, node)
    assert r["ok"] is False
    # The OS reason should mention Linux since that's the barrier.
    assert "windows" in r["error"].lower() or "linux" in r["error"].lower()


def test_death_star_launch_calls_deploy_when_armed():
    state = _armed_state()
    node = _mk_node()
    node._evasion_baseline = {"params": {}}

    fake_result = {
        "ok": True,
        "source_path": "/tmp/sap_audit_hook.c",
        "binary_path": "/tmp/sap_audit_hook",
        "target_pid": 4712,
        "target_comm": "dw.sapS4H_D00_W0",
        "hook_pid": 4900,
        "log_path": "/tmp/sap_audit_hook.log",
        "pidfile_path": "/tmp/sap_audit_hook.pid",
        "filter_classes": "AUW",
    }
    with patch("sapmap_death_star.deploy_and_launch",
                 return_value=fake_result) as mock_deploy:
        r = sapmap_evasion_tier3.tier3_sal_death_star_launch(
            state, node, filter_classes="AUW")
    mock_deploy.assert_called_once()
    assert r["ok"] is True
    assert r["hook_pid"] == 4900
    assert r["target_pid"] == 4712
    # Node state should be stashed for a paired stop.
    assert node._death_star_state["hook_pid"] == 4900
    assert node._death_star_state["filter_classes"] == "AUW"


def test_death_star_stop_removes_state_on_success():
    state = _armed_state()
    node = _mk_node()
    node._evasion_baseline = {"params": {}}
    node._death_star_state = {
        "hook_pid": 4900,
        "target_pid": 4712,
        "target_comm": "dw.sapS4H_D00_W0",
        "binary_path": "/tmp/sap_audit_hook",
        "pidfile_path": "/tmp/sap_audit_hook.pid",
        "log_path": "/tmp/sap_audit_hook.log",
        "filter_classes": "AUW",
    }
    with patch("sapmap_death_star.stop",
                 return_value={"ok": True, "pid": 4900,
                               "message": "stopped cleanly"}):
        r = sapmap_evasion_tier3.tier3_sal_death_star_stop(state, node)
    assert r["ok"] is True
    assert not hasattr(node, "_death_star_state")


def test_death_star_stop_is_idempotent_when_nothing_running():
    state = _armed_state()
    node = _mk_node()
    with patch("sapmap_death_star.stop",
                 return_value={"ok": False, "pid": None,
                               "message": "no hook process found — "
                                          "nothing to stop"}):
        r = sapmap_evasion_tier3.tier3_sal_death_star_stop(state, node)
    # Not-running is reported as ok=False but shouldn't raise / clobber
    # any node state.
    assert r["ok"] is False
    assert "nothing to stop" in (r.get("message") or "")
