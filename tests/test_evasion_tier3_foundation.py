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


def _lab_sal_response():
    """RSAU_API_GET_AUDIT_CONFIG response shape matching the live S4H
    output from the operator's lab (ED_VERSION=16, 3 active slots)."""
    return {
        "ED_VERSION": 16,
        "ED_ENABLE": "X",
        "ED_SLOTCNT": 3,
        "ED_USER_SELECTION": 1,
        "ED_DATE": "16.06.2026",
        "ED_MAXFILESIZE": 2146304,
        "ED_SIZEOFFILE": 395264,
        "ED_CURFILESIZE": 0,
        "ED_CURFILENUM": 2,
        "ED_POSITION": 2287,
        "ED_FILESTATUS": 1,
        "ET_SLOT_INFO": [
            {"PROFNAME": "$DYN$", "SLOTNO": "0001", "STATUS": "X",
             "MANDT": "*", "UNAME": "SAP#*", "SEVERITY": 2,
             "SEVERITY_LOW": "X", "CLASSES": 255,
             "CLASS_OTHER": "X", "CLASS_LOGIN": "X", "CLASS_TCD": "X",
             "CLASS_REP": "X", "CLASS_RFC_LOGIN": "X", "CLASS_USER": "X",
             "CLASS_SYST": "X", "CLASS_RFC": "X"},
            {"PROFNAME": "$DYN$", "SLOTNO": "0002", "STATUS": "X",
             "MANDT": "066", "UNAME": "*", "SEVERITY": 2,
             "SEVERITY_LOW": "X", "CLASSES": 255,
             "CLASS_OTHER": "X", "CLASS_LOGIN": "X", "CLASS_TCD": "X",
             "CLASS_REP": "X", "CLASS_RFC_LOGIN": "X", "CLASS_USER": "X",
             "CLASS_SYST": "X", "CLASS_RFC": "X"},
            {"PROFNAME": "$DYN$", "SLOTNO": "0011", "STATUS": "X",
             "MANDT": "*", "UNAME": "*", "SEVERITY": 0, "CLASSES": 0,
             "MSGVECT": "fcfefefcfc7cf8f8f4f4fcfcfcfcf4fcfcfcfcfc7cfcfcfcfcfcce8f8f8f8d878f8f8f800000000000000000000"},
        ],
    }


# ---------------------------------------------------------------------------
# RSAU_S_SLOT_INFO / SalConfig dataclass plumbing
# ---------------------------------------------------------------------------

def test_sal_slot_info_from_rfc_row_decodes_lab_first_slot():
    row = _lab_sal_response()["ET_SLOT_INFO"][0]
    s = sapmap_evasion_baseline.SalSlotInfo.from_rfc_row(row)
    assert s.profname == "$DYN$"
    assert s.slotno == "0001"
    assert s.status == "X"
    assert s.mandt == "*"
    assert s.uname == "SAP#*"
    assert s.severity == 2
    assert s.classes == 255
    assert s.class_login == "X"
    assert s.class_rfc == "X"


def test_sal_slot_info_handles_missing_fields():
    s = sapmap_evasion_baseline.SalSlotInfo.from_rfc_row({})
    assert s.status == ""
    assert s.severity == 0
    assert s.classes == 0


def test_sal_slot_info_bytes_msgvect_hex_encoded():
    row = {"PROFNAME": "$DYN$", "SLOTNO": "0011",
            "MSGVECT": bytes.fromhex("abcd1234")}
    s = sapmap_evasion_baseline.SalSlotInfo.from_rfc_row(row)
    assert s.msgvect == "abcd1234"


def test_sal_slot_info_roundtrip_to_dict_from_dict():
    row = _lab_sal_response()["ET_SLOT_INFO"][0]
    s = sapmap_evasion_baseline.SalSlotInfo.from_rfc_row(row)
    s2 = sapmap_evasion_baseline.SalSlotInfo.from_dict(s.to_dict())
    assert s2.to_dict() == s.to_dict()


def test_sal_config_decodes_all_ed_fields_and_slots():
    conn = MagicMock()
    conn.call.return_value = _lab_sal_response()
    cfg = sapmap_evasion_baseline._read_sal_config(conn)
    assert cfg is not None
    assert cfg.version == 16
    assert cfg.enable == "X"
    assert cfg.slot_count == 3
    assert cfg.max_file_size == 2146304
    assert cfg.position == 2287
    assert len(cfg.slots) == 3
    assert cfg.slots[0].uname == "SAP#*"
    assert cfg.slots[1].mandt == "066"
    # slot 0011's MSGVECT-only configuration
    assert cfg.slots[2].classes == 0


def test_sal_config_returns_none_when_fm_missing():
    conn = MagicMock()
    conn.call.side_effect = Exception("FU_NOT_FOUND: RSAU_API_GET_AUDIT_CONFIG")
    cfg = sapmap_evasion_baseline._read_sal_config(conn)
    assert cfg is None


def test_sal_config_roundtrip_through_baseline_snapshot():
    cfg = sapmap_evasion_baseline.SalConfig(
        version=16, enable="X", slot_count=2,
        slots=[sapmap_evasion_baseline.SalSlotInfo(
            profname="$DYN$", slotno="0001", status="X", uname="SAP#*",
            severity=2, classes=255)])
    snap = sapmap_evasion_baseline.BaselineSnapshot(
        sid="S4H", sal_config=cfg)
    d = snap.to_dict()
    snap2 = sapmap_evasion_baseline.BaselineSnapshot.from_dict(d)
    assert snap2.sal_config is not None
    assert snap2.sal_config.version == 16
    assert snap2.sal_config.slots[0].uname == "SAP#*"


# ---------------------------------------------------------------------------
# Baseline capture — combined param + SAL paths
# ---------------------------------------------------------------------------

def test_baseline_capture_records_params_sal_config_and_loot(tmp_path):
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE": "captured-" + kw["PARAMETER_NAME"]}
        if fm == "RSAU_API_GET_AUDIT_CONFIG":
            return _lab_sal_response()
        if fm == "RFC_READ_TABLE":
            # Should NOT be called: API succeeded so RSAUPROF fallback
            # is skipped.  Failing loudly makes the regression visible.
            raise AssertionError("RFC_READ_TABLE called despite API success")
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        snap = sapmap_evasion_baseline.capture_baseline(
            node, loot_root=str(tmp_path))

    assert snap.sid == "S4H"
    for p in sapmap_evasion_baseline._BASELINE_PARAMS:
        assert snap.params[p] == "captured-" + p
    # SAL captured via the modern API
    assert snap.sal_config is not None
    assert snap.sal_config.version == 16
    assert snap.sal_config.slot_count == 3
    assert len(snap.sal_config.slots) == 3
    # Legacy fallback NOT populated when the API succeeded
    assert snap.sal_filter_rows == []
    assert snap.loot_path
    assert os.path.exists(snap.loot_path)
    assert node._evasion_baseline is snap
    # JSON on disk must record its own path — provenance for any
    # tooling that consumes the loot later (regression: prior version
    # set loot_path AFTER writing the file, so on-disk JSON had "").
    import json as _json
    on_disk = _json.loads(open(snap.loot_path).read())
    assert on_disk["loot_path"] == snap.loot_path


def test_baseline_capture_falls_back_to_rsauprof_when_api_missing(tmp_path):
    """Older NetWeaver kernel: RSAU_API_GET_AUDIT_CONFIG returns
    FU_NOT_FOUND, so the capture falls through to the legacy
    RSAUPROF table-read path."""
    node = SAPNode(sid="OLD", hostname="o", ip="10.0.0.2")

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE": "1"}
        if fm == "RSAU_API_GET_AUDIT_CONFIG":
            raise Exception("FU_NOT_FOUND")
        if fm == "RFC_READ_TABLE":
            return {"DATA": [{"WA": "BCUSER|001"}, {"WA": "*|*"}]}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        snap = sapmap_evasion_baseline.capture_baseline(
            node, loot_root=str(tmp_path))

    assert snap.sal_config is None
    assert snap.sal_filter_rows == ["BCUSER|001", "*|*"]


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
# change_param — TH_CHANGE_PARAMETER writer
# ---------------------------------------------------------------------------

def test_change_param_invokes_th_change_parameter_with_correct_args():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    seen_args = {}

    def _call(fm, **kw):
        seen_args["fm"] = fm
        seen_args["kw"] = kw
        return {"RC": "0"}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        r = sapmap_evasion_baseline.change_param(
            node, None, "stat/level", "0")

    assert r["ok"] is True
    assert seen_args["fm"] == "TH_CHANGE_PARAMETER"
    assert seen_args["kw"]["PARAMETER_NAME"] == "stat/level"
    assert seen_args["kw"]["PARAMETER_VALUE"] == "0"


def test_change_param_reports_non_zero_rc_as_failure():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    conn = MagicMock()
    conn.call.return_value = {"RC": "4", "MESSAGE": "Read-only param"}
    with _patch_connection(conn):
        r = sapmap_evasion_baseline.change_param(
            node, None, "rsau/integrity", "0")
    assert r["ok"] is False
    assert "Read-only" in r["error"]


def test_change_param_captures_rfc_exception_without_raising():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    conn = MagicMock()
    conn.call.side_effect = Exception("AUTHORIZATION_FAILURE: S_ADMI_FCD")
    with _patch_connection(conn):
        r = sapmap_evasion_baseline.change_param(
            node, None, "rsau/enable", "0")
    assert r["ok"] is False
    assert "S_ADMI_FCD" in r["error"]


# ---------------------------------------------------------------------------
# Restore — real TH_CHANGE_PARAMETER writes
# ---------------------------------------------------------------------------

def test_restore_writes_each_captured_param_via_change_param():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    snap = sapmap_evasion_baseline.BaselineSnapshot(
        sid="S4H", captured_at="2026-06-16T20:00:00",
        params={"rsau/enable": "1", "stat/level": "1",
                "gw/logging": "__UNCAPTURED__:auth denied"},
        loot_path="loot/baseline/S4H/test.json")

    writes = []
    def fake_change(node_arg, creds, name, value):
        writes.append((name, value))
        return {"ok": True, "name": name, "value": value, "error": ""}

    with patch.object(sapmap_evasion_baseline, "change_param",
                       side_effect=fake_change):
        out = sapmap_evasion_baseline.restore_baseline(
            node, None, snap)

    # Both capturable params written, uncapturable one skipped
    assert ("rsau/enable", "1") in writes
    assert ("stat/level", "1") in writes
    assert ("gw/logging", "__UNCAPTURED__:auth denied") not in writes
    assert "rsau/enable" in out["restored"]
    assert "stat/level" in out["restored"]
    assert ("gw/logging", "param was uncapturable") in out["skipped"]


def test_restore_records_failed_writes_in_skipped():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    snap = sapmap_evasion_baseline.BaselineSnapshot(
        sid="S4H", captured_at="2026-06-16T20:00:00",
        params={"rsau/enable": "1", "stat/level": "1"})

    def fake_change(node_arg, creds, name, value):
        if name == "rsau/enable":
            return {"ok": False, "name": name, "value": value,
                    "error": "Read-only param"}
        return {"ok": True, "name": name, "value": value, "error": ""}

    with patch.object(sapmap_evasion_baseline, "change_param",
                       side_effect=fake_change):
        out = sapmap_evasion_baseline.restore_baseline(
            node, None, snap)

    assert "stat/level" in out["restored"]
    assert ("rsau/enable", "Read-only param") in out["skipped"]


def test_restore_only_writes_touched_subset():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    snap = sapmap_evasion_baseline.BaselineSnapshot(
        sid="S4H", captured_at="2026-06-16T20:00:00",
        params={"rsau/enable": "1", "stat/level": "1",
                "rdisp/TRACE": "1"})
    writes = []
    def fake_change(node_arg, creds, name, value):
        writes.append(name)
        return {"ok": True, "name": name, "value": value, "error": ""}
    with patch.object(sapmap_evasion_baseline, "change_param",
                       side_effect=fake_change):
        out = sapmap_evasion_baseline.restore_baseline(
            node, None, snap, only=["stat/level"])
    assert writes == ["stat/level"]
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


def test_tier3_set_param_writes_then_restores_via_th_change_parameter():
    """End-to-end: armed gate, baseline captured, parameter written
    via TH_CHANGE_PARAMETER, baseline value rewritten on window exit."""
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    # Sequence: TH_GET_PARAMETER reads during capture, then
    # TH_CHANGE_PARAMETER for the mutation, then more
    # TH_CHANGE_PARAMETER calls for restore.
    th_change_calls = []
    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE": "1"}
        if fm == "TH_CHANGE_PARAMETER":
            th_change_calls.append((kw["PARAMETER_NAME"],
                                     kw["PARAMETER_VALUE"]))
            return {"RC": "0"}
        if fm == "RFC_READ_TABLE":
            return {"DATA": []}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        out = sapmap_evasion_tier3.tier3_set_param(
            state, node, "stat/level", "0")

    assert out["ok"] is True
    assert out["applied"] is True
    assert out["param"] == "stat/level"
    assert out["requested_value"] == "0"
    assert out["baseline_value"] == "1"

    # Mutation should have happened (stat/level=0)
    assert ("stat/level", "0") in th_change_calls
    # Restore should have rewritten the baseline value back (stat/level=1)
    assert ("stat/level", "1") in th_change_calls
    # And ordering: mutation first, restore after
    mut_idx = th_change_calls.index(("stat/level", "0"))
    restore_idx = th_change_calls.index(("stat/level", "1"))
    assert mut_idx < restore_idx


def test_tier3_set_param_propagates_write_failure_and_still_restores():
    """If TH_CHANGE_PARAMETER fails during the mutation, the window
    still attempts to restore (no-op since we never changed anything,
    but the contract is "restore always runs on exit")."""
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    th_change_calls = []
    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE": "1"}
        if fm == "TH_CHANGE_PARAMETER":
            th_change_calls.append((kw["PARAMETER_NAME"],
                                     kw["PARAMETER_VALUE"]))
            # The mutation fails; restore is allowed to succeed
            if kw["PARAMETER_VALUE"] == "0":
                return {"RC": "4", "MESSAGE": "Read-only param"}
            return {"RC": "0"}
        return {"DATA": []}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        out = sapmap_evasion_tier3.tier3_set_param(
            state, node, "stat/level", "0")

    assert out["ok"] is False
    assert out["applied"] is False
    assert "Read-only" in out["error"]
    # Restore still ran (window contract)
    assert ("stat/level", "1") in th_change_calls


# ---------------------------------------------------------------------------
# Phase 2 — RSAU API surface discovery probe
# ---------------------------------------------------------------------------

def _interface_response(import_params, export_params,
                        tables_params=(), exception_params=()):
    """Build an RFC_GET_FUNCTION_INTERFACE response shape with the
    given parameter lists.  Uses the *real* RFC_FUNC_DESC field
    names (PARAMCLASS / EXID / TABNAME), verified against the live
    S/4 793 probe output."""
    rows = []
    for p in import_params:
        rows.append({"PARAMETER": p, "PARAMCLASS": "I",
                     "EXID": "C", "TABNAME": "", "OPTIONAL": ""})
    for p in export_params:
        rows.append({"PARAMETER": p, "PARAMCLASS": "E",
                     "EXID": "C", "TABNAME": "", "OPTIONAL": ""})
    for p in tables_params:
        rows.append({"PARAMETER": p, "PARAMCLASS": "T",
                     "EXID": "h", "TABNAME": "RSAUPROF_T",
                     "OPTIONAL": "X"})
    for p in exception_params:
        rows.append({"PARAMETER": p, "PARAMCLASS": "X",
                     "EXID": "", "TABNAME": "", "OPTIONAL": ""})
    return {"PARAMS": rows}


def test_probe_refuses_when_flag_disarmed():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": False}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    out = sapmap_evasion_tier3.probe_rsau_api_surface(state, node)
    assert out["ok"] is False
    assert "--allow-evasion" in out["error"]
    assert out["functions"] == []


def test_probe_dumps_signatures_for_existing_fms(tmp_path):
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    # Simulate kernel where:
    #   - RSAU_API_GET_AUDIT_CONFIG exists (the one we confirmed live)
    #   - RSAU_API_SET_PROFILE exists with its 8-param signature
    #   - RSAU_API_SET_PARAM exists
    #   - everything else returns FU_NOT_FOUND
    existing = {
        "RSAU_API_GET_AUDIT_CONFIG": _interface_response(
            import_params=[],
            export_params=["ED_VERSION", "ED_ENABLE", "ED_SLOTCNT",
                            "ED_MAXFILESIZE"],
            tables_params=["ET_SLOT_INFO"]),
        "RSAU_API_SET_PROFILE": _interface_response(
            import_params=["ID_NAME", "ID_SET_ACTIV",
                            "ID_UPD_DYN_CNF", "ID_DELETE_PROF"],
            export_params=[],
            tables_params=["IT_FILT", "IT_FILTX", "IT_FILT_TX"]),
        "RSAU_API_SET_PARAM": _interface_response(
            import_params=["ID_ACTIV", "ID_INTEGRITY", "ID_PEER_ADR",
                            "ID_MBYTE_DAY", "ID_SLOTS"],
            export_params=[]),
    }

    def _call(fm, **kw):
        if fm == "FUNCTION_EXISTS":
            name = kw.get("FUNCNAME", "")
            if name in existing:
                return {"FUNCNAME": name}
            raise Exception("FU_NOT_FOUND")
        if fm == "RFC_GET_FUNCTION_INTERFACE":
            name = kw.get("FUNCNAME", "")
            return existing[name]
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        out = sapmap_evasion_tier3.probe_rsau_api_surface(
            state, node, loot_root=str(tmp_path))

    assert out["ok"] is True
    assert out["found_count"] == 3
    assert out["total_checked"] > 3

    found = {r["name"]: r for r in out["functions"]}
    assert found["RSAU_API_GET_AUDIT_CONFIG"]["exists"]
    assert found["RSAU_API_SET_PROFILE"]["exists"]
    assert found["RSAU_API_SET_PARAM"]["exists"]
    # The SET_PROFILE signature lands in the result correctly
    sp = found["RSAU_API_SET_PROFILE"]["params"]
    sp_imports = [p["parameter"] for p in sp
                   if p["direction"] == "IMPORT"]
    sp_tables = [p["parameter"] for p in sp
                  if p["direction"] == "TABLES"]
    assert "ID_UPD_DYN_CNF" in sp_imports
    assert "ID_SET_ACTIV" in sp_imports
    assert "IT_FILT" in sp_tables

    # Missing FMs marked correctly
    missing = found["RSAU_UPD_AUDIT_CONFIG"]
    assert missing["exists"] is False
    assert "FU_NOT_FOUND" in missing["error"]

    # Loot file written and self-records its path
    import json as _json
    on_disk = _json.loads(open(out["loot_path"]).read())
    assert on_disk["loot_path"] == out["loot_path"]
    assert on_disk["sid"] == "S4H"
    assert any(f["name"] == "RSAU_API_SET_PROFILE"
                for f in on_disk["functions"])


def test_probe_handles_signature_read_failure_gracefully():
    """FUNCTION_EXISTS says yes but RFC_GET_FUNCTION_INTERFACE blows
    up (auth denial, kernel quirk) — record exists=True + error in
    the params-failed slot, don't crash."""
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    def _call(fm, **kw):
        if fm == "FUNCTION_EXISTS":
            if kw["FUNCNAME"] == "RSAU_API_GET_AUDIT_CONFIG":
                return {"FUNCNAME": kw["FUNCNAME"]}
            raise Exception("FU_NOT_FOUND")
        if fm == "RFC_GET_FUNCTION_INTERFACE":
            raise Exception("AUTHORIZATION_FAILURE: S_RFC")
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        out = sapmap_evasion_tier3.probe_rsau_api_surface(
            state, node, loot_root="/tmp/sapmap-test-probe")

    found = {r["name"]: r for r in out["functions"]}
    f = found["RSAU_API_GET_AUDIT_CONFIG"]
    assert f["exists"] is True
    assert "signature read failed" in f["error"]
    assert f["params"] == []


def test_read_dyn_profile_calls_get_profile_with_dyn_conf_flag():
    """read_dyn_profile must pass ID_NAME='$DYN$' and ID_DYN_CONF='X'
    so the kernel returns the in-memory dynamic config, not the
    persisted profile that survives a restart."""
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    seen = {}

    def _call(fm, **kw):
        if fm == "RSAU_API_GET_PROFILE":
            seen["fm"] = fm
            seen["kw"] = kw
            return {
                "ED_DATA_STR": "",
                "ET_FILT": [
                    {"PROFNAME": "$DYN$", "SLOTNO": "0001",
                     "STATUS": "X", "UNAME": "SAP#*"},
                ],
                "ET_FILTEX": [],
                "ET_TEXT": [],
                "ET_LOG": [],
            }
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        resp = sapmap_evasion_tier3.read_dyn_profile(node)

    assert seen["fm"] == "RSAU_API_GET_PROFILE"
    assert seen["kw"]["ID_NAME"] == "$DYN$"
    assert seen["kw"]["ID_DYN_CONF"] == "X"
    assert resp["ET_FILT"][0]["UNAME"] == "SAP#*"


def test_probe_dyn_profile_refuses_when_flag_disarmed():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": False}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    out = sapmap_evasion_tier3.tier3_probe_dyn_profile(state, node)
    assert out["ok"] is False
    assert "--allow-evasion" in out["error"]


def test_probe_dyn_profile_dumps_verbatim_response(tmp_path):
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    def _call(fm, **kw):
        if fm == "RSAU_API_GET_PROFILE":
            return {
                "ED_DATA_STR": "header-text",
                "ET_FILT": [
                    {"PROFNAME": "$DYN$", "SLOTNO": "0001",
                     "STATUS": "X", "UNAME": "SAP#*",
                     "MSGVECT": bytes.fromhex("abcd")},
                    {"PROFNAME": "$DYN$", "SLOTNO": "0002",
                     "STATUS": "X", "UNAME": "*"},
                ],
                "ET_FILTEX": [],
                "ET_TEXT": [{"PROFNAME": "$DYN$", "DESCRIPTION": "Dyn"}],
                "ET_LOG": [],
            }
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        out = sapmap_evasion_tier3.tier3_probe_dyn_profile(
            state, node, loot_root=str(tmp_path))

    assert out["ok"] is True
    assert out["profile_name"] == "$DYN$"
    assert out["et_filt_count"] == 2
    assert out["et_filtex_count"] == 0
    assert out["et_text_count"] == 1
    # Field names of the first ET_FILT row land in the finding summary
    assert "PROFNAME" in out["rsauprof_row_fields"]
    assert "SLOTNO" in out["rsauprof_row_fields"]
    assert "STATUS" in out["rsauprof_row_fields"]
    assert "UNAME" in out["rsauprof_row_fields"]

    # JSON loot file written; bytes hex-encoded; self-records its path
    import json as _json
    on_disk = _json.loads(open(out["loot_path"]).read())
    assert on_disk["loot_path"] == out["loot_path"]
    assert on_disk["response"]["ET_FILT"][0]["MSGVECT"] == "abcd"


def test_probe_dyn_profile_captures_rfc_exception_cleanly():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    def _call(fm, **kw):
        if fm == "RSAU_API_GET_PROFILE":
            raise Exception("NOT_FOUND: profile $DYN$")
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        out = sapmap_evasion_tier3.tier3_probe_dyn_profile(state, node)

    assert out["ok"] is False
    assert "RSAU_API_GET_PROFILE raised" in out["error"]
    assert "NOT_FOUND" in out["error"]


def test_probe_helper_summarises_params_by_direction():
    s = sapmap_evasion_tier3._summarise_params([
        {"parameter": "ID_NAME", "direction": "IMPORT"},
        {"parameter": "ID_SET_ACTIV", "direction": "IMPORT"},
        {"parameter": "IT_FILT", "direction": "TABLES"},
    ])
    assert "I=[ID_NAME,ID_SET_ACTIV]" in s
    assert "T=[IT_FILT]" in s


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
