"""Tests for the Tier 3 foundation — gate, baseline, window, one stub."""

import os
import tempfile
from unittest.mock import patch, MagicMock

import pytest

from sapmap_models import SAPMAPState, SAPNode
import sapmap_evasion
import sapmap_evasion_gate
import sapmap_evasion_baseline
import sapmap_evasion_tier3
from sapmap_evasion_gate import (assert_evasion_allowed,
                                   EvasionGateError, TIER3_TECHNIQUES,
                                   technique_label)


# ---------------------------------------------------------------------------
# EvasionConfig — Tier 3 fields
# ---------------------------------------------------------------------------

def test_evasion_config_defaults_disarm_tier3():
    cfg = sapmap_evasion.EvasionConfig()
    assert cfg.allow_evasion is False
    assert cfg.baseline_captured_at == ""


def test_evasion_config_roundtrip_preserves_tier3_fields():
    cfg = sapmap_evasion.EvasionConfig(
        allow_evasion=True,
        baseline_captured_at="2026-06-16T20:00:00")
    d = cfg.to_dict()
    cfg2 = sapmap_evasion.EvasionConfig.from_dict(d)
    assert cfg2.allow_evasion is True
    assert cfg2.baseline_captured_at == "2026-06-16T20:00:00"


# ---------------------------------------------------------------------------
# Gate registry
# ---------------------------------------------------------------------------

def test_registry_contains_expected_techniques():
    expected = {
        "sal_filter_narrow", "sal_kernel_param_disable", "stad_silence",
        "dbtablog_suppress", "icm_trace_flip", "rz11_dynamic_set",
        "tsl1d_template_delete", "java_nwa_severity",
    }
    assert expected <= set(TIER3_TECHNIQUES.keys())


def test_every_registered_technique_gates_on_allow_evasion():
    for t in TIER3_TECHNIQUES.values():
        assert t.required_flag == "allow_evasion"


def test_technique_label_returns_label_for_known_id():
    label = technique_label("stad_silence")
    assert "STAD" in label


def test_technique_label_falls_back_to_id_for_unknown():
    assert technique_label("unknown") == "unknown"


# ---------------------------------------------------------------------------
# Gate function — assert_evasion_allowed
# ---------------------------------------------------------------------------

def _node_with_baseline():
    n = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    n._evasion_baseline = sapmap_evasion_baseline.BaselineSnapshot(
        sid="S4H", captured_at="2026-06-16T20:00:00",
        params={"rsau/enable": "1"})
    return n


def test_gate_refuses_unknown_technique():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    with pytest.raises(EvasionGateError) as ei:
        assert_evasion_allowed(state, _node_with_baseline(),
                                "made_up_technique")
    assert "Unknown technique" in ei.value.reason


def test_gate_refuses_when_state_is_none():
    with pytest.raises(EvasionGateError) as ei:
        assert_evasion_allowed(None, _node_with_baseline(),
                                "stad_silence")
    assert "No SAPMAPState" in ei.value.reason


def test_gate_refuses_when_flag_disarmed():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": False}
    with pytest.raises(EvasionGateError) as ei:
        assert_evasion_allowed(state, _node_with_baseline(),
                                "stad_silence")
    assert "--allow-evasion" in ei.value.reason


def test_gate_refuses_when_no_baseline():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    n = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    # No _evasion_baseline, no baseline_captured_at
    with pytest.raises(EvasionGateError) as ei:
        assert_evasion_allowed(state, n, "stad_silence",
                                require_baseline=True)
    assert "baseline" in ei.value.reason.lower()


def test_gate_passes_when_flag_armed_and_baseline_present():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    n = _node_with_baseline()
    # Should not raise
    assert_evasion_allowed(state, n, "stad_silence")


def test_gate_baseline_skip_path_still_requires_flag():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": False}
    n = SAPNode(sid="X", hostname="x", ip="10.0.0.1")
    with pytest.raises(EvasionGateError):
        assert_evasion_allowed(state, n, "stad_silence",
                                require_baseline=False)


# ---------------------------------------------------------------------------
# Baseline capture — TH_GET_PARAMETER + RFC_READ_TABLE
# ---------------------------------------------------------------------------

def _patch_connection(mock_conn):
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=mock_conn)
    cm.__exit__ = MagicMock(return_value=False)
    import sapmap_rfc
    return patch.object(sapmap_rfc, "_get_connection", return_value=cm)


def test_baseline_capture_records_all_params_and_persists_loot(tmp_path):
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    captured = {}

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            captured[kw["PARAMETER_NAME"]] = True
            return {"PARAMETER_VALUE": "captured-" + kw["PARAMETER_NAME"]}
        if fm == "RFC_READ_TABLE":
            return {"DATA": [{"WA": "BCUSER|001"}, {"WA": "*|*"}]}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        snap = sapmap_evasion_baseline.capture_baseline(
            node, loot_root=str(tmp_path))

    assert snap.sid == "S4H"
    # Every probed parameter ended up in the snapshot
    for p in sapmap_evasion_baseline._BASELINE_PARAMS:
        assert snap.params[p] == "captured-" + p
    assert snap.sal_filter_rows == ["BCUSER|001", "*|*"]
    # Loot JSON written and path recorded
    assert snap.loot_path
    assert os.path.exists(snap.loot_path)
    # In-memory cached on node so re-invocation is idempotent
    assert node._evasion_baseline is snap


def test_baseline_capture_idempotent_on_second_call():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    pre_snap = sapmap_evasion_baseline.BaselineSnapshot(
        sid="S4H", captured_at="2026-06-16T20:00:00",
        params={"rsau/enable": "1"})
    node._evasion_baseline = pre_snap

    import sapmap_rfc
    with patch.object(sapmap_rfc, "_get_connection") as gc:
        snap = sapmap_evasion_baseline.capture_baseline(node)

    assert snap is pre_snap
    gc.assert_not_called()


def test_baseline_capture_marks_uncapturable_params():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            if kw["PARAMETER_NAME"] == "gw/logging":
                raise RuntimeError("AUTH_DENIED: gw/logging")
            return {"PARAMETER_VALUE": "ok"}
        return {"DATA": []}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn), tempfile.TemporaryDirectory() as td:
        snap = sapmap_evasion_baseline.capture_baseline(
            node, loot_root=td)

    assert snap.params["gw/logging"].startswith("__UNCAPTURED__")
    assert snap.params["rsau/enable"] == "ok"


# ---------------------------------------------------------------------------
# Restore — log-only dry-run for now
# ---------------------------------------------------------------------------

def test_restore_dry_runs_each_captured_param(capsys):
    snap = sapmap_evasion_baseline.BaselineSnapshot(
        sid="S4H", captured_at="2026-06-16T20:00:00",
        params={"rsau/enable": "1", "stat/level": "1",
                "gw/logging": "__UNCAPTURED__:auth denied"},
        loot_path="loot/baseline/S4H/test.json")
    out = sapmap_evasion_baseline.restore_baseline(
        node=None, creds=None, snapshot=snap)
    captured = capsys.readouterr().out
    assert "rsau/enable" in captured
    assert "dry-run" in captured.lower()
    assert "rsau/enable" in out["restored"]
    # Uncapturable params aren't restored
    assert ("gw/logging", "param was uncapturable") in out["skipped"]


def test_restore_only_writes_touched_subset():
    snap = sapmap_evasion_baseline.BaselineSnapshot(
        sid="S4H", captured_at="2026-06-16T20:00:00",
        params={"rsau/enable": "1", "stat/level": "1",
                "rdisp/TRACE": "1"})
    out = sapmap_evasion_baseline.restore_baseline(
        node=None, creds=None, snapshot=snap,
        only=["stat/level"])
    assert out["restored"] == ["stat/level"]


# ---------------------------------------------------------------------------
# Evasion window — auto-capture, auto-restore on exit
# ---------------------------------------------------------------------------

def test_window_refuses_when_gate_closed(tmp_path):
    state = SAPMAPState()
    state.evasion = {"allow_evasion": False}
    node = SAPNode(sid="X", hostname="x", ip="10.0.0.1")
    with pytest.raises(EvasionGateError):
        with sapmap_evasion_baseline.evasion_window(
                node, state, "stad_silence"):
            pass


def test_window_captures_baseline_and_restores_on_normal_exit(tmp_path):
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE": "baseline-" + kw["PARAMETER_NAME"]}
        return {"DATA": []}

    conn = MagicMock()
    conn.call.side_effect = _call
    restored = {}
    real_restore = sapmap_evasion_baseline.restore_baseline

    def wrapped_restore(*args, **kwargs):
        restored["called"] = True
        return real_restore(*args, **kwargs)

    with _patch_connection(conn), \
         patch.object(sapmap_evasion_baseline, "restore_baseline",
                      side_effect=wrapped_restore), \
         patch.object(sapmap_evasion_baseline, "_BASELINE_PARAMS",
                      ("stat/level",)):
        with sapmap_evasion_baseline.evasion_window(
                node, state, "stad_silence",
                touched_params=["stat/level"]) as w:
            assert w["technique"] == "stad_silence"
            assert w["snapshot"].params["stat/level"] == \
                "baseline-stat/level"
    assert restored.get("called") is True


def test_window_restores_even_on_exception():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    conn = MagicMock()
    conn.call.return_value = {"PARAMETER_VALUE": "ok"}

    restored = {}

    def fake_restore(*args, **kwargs):
        restored["called"] = True
        return {"restored": [], "skipped": [], "snapshot_path": ""}

    with _patch_connection(conn), \
         patch.object(sapmap_evasion_baseline, "restore_baseline",
                      side_effect=fake_restore):
        with pytest.raises(ValueError):
            with sapmap_evasion_baseline.evasion_window(
                    node, state, "stad_silence"):
                raise ValueError("body broke")
    assert restored.get("called") is True


# ---------------------------------------------------------------------------
# Tier 3 stub entry — tier3_set_param
# ---------------------------------------------------------------------------

def test_tier3_set_param_refuses_when_flag_disarmed():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": False}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    out = sapmap_evasion_tier3.tier3_set_param(
        state, node, "stat/level", "0")
    assert out["ok"] is False
    assert "--allow-evasion" in out["error"]


def test_tier3_set_param_dry_run_when_armed(capsys):
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    conn = MagicMock()
    conn.call.return_value = {"PARAMETER_VALUE": "1"}

    with _patch_connection(conn):
        out = sapmap_evasion_tier3.tier3_set_param(
            state, node, "stat/level", "0")

    assert out["ok"] is True
    assert out["technique"] == "rz11_dynamic_set"
    assert out["param"] == "stat/level"
    assert out["requested_value"] == "0"
    assert out["baseline_value"] == "1"
    assert "dry-run" in out["would_write"]


def test_tier3_capture_baseline_only_records_timestamp_on_state():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    conn = MagicMock()
    conn.call.return_value = {"PARAMETER_VALUE": "1"}

    with _patch_connection(conn):
        out = sapmap_evasion_tier3.tier3_capture_baseline_only(state, node)

    assert out["ok"] is True
    assert out["param_count"] > 0
    cfg = sapmap_evasion.EvasionConfig.from_dict(state.evasion)
    assert cfg.baseline_captured_at == out["captured_at"]
