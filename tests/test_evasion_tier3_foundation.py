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
        "dbtablog_purge", "icm_trace_flip", "rz11_dynamic_set",
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
    # CHECK_PARAMETER='1' is required for the kernel to actually
    # commit the runtime change (without it the call succeeds at the
    # RFC layer but the value is silently not applied — confirmed via
    # SE37 test on S/4 793).
    assert seen_args["kw"]["CHECK_PARAMETER"] == "1"


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

def test_restore_writes_each_capturable_dynamic_param():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    # Use ONLY dynamic params here.  Static rsau/* / stat/level
    # are exercised in test_restore_skips_known_static_params_silently.
    snap = sapmap_evasion_baseline.BaselineSnapshot(
        sid="S4H", captured_at="2026-06-16T20:00:00",
        params={"rdisp/TRACE": "1",
                "gw/logging": "ACTION=SsMPXZ",
                "icm/trace_level": "__UNCAPTURED__:auth denied"},
        loot_path="loot/baseline/S4H/test.json")

    writes = []
    def fake_change(node_arg, creds, name, value):
        writes.append((name, value))
        return {"ok": True, "name": name, "value": value, "error": ""}

    with patch.object(sapmap_evasion_baseline, "change_param",
                       side_effect=fake_change):
        out = sapmap_evasion_baseline.restore_baseline(
            node, None, snap)

    assert ("rdisp/TRACE", "1") in writes
    assert ("gw/logging", "ACTION=SsMPXZ") in writes
    assert ("icm/trace_level",
             "__UNCAPTURED__:auth denied") not in writes
    assert "rdisp/TRACE" in out["restored"]
    assert "gw/logging" in out["restored"]
    assert ("icm/trace_level",
             "param was uncapturable") in out["skipped"]


def test_restore_records_failed_writes_in_skipped():
    """Dynamic-param write failure from TH_CHANGE_PARAMETER lands in
    skipped[] with the kernel error.  Static params get filtered
    before that loop, so use rdisp/TRACE + gw/logging here."""
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    snap = sapmap_evasion_baseline.BaselineSnapshot(
        sid="S4H", captured_at="2026-06-16T20:00:00",
        params={"rdisp/TRACE": "1", "gw/logging": "ACTION=Ss"})

    def fake_change(node_arg, creds, name, value):
        if name == "rdisp/TRACE":
            return {"ok": False, "name": name, "value": value,
                    "error": "Read-only param"}
        return {"ok": True, "name": name, "value": value, "error": ""}

    with patch.object(sapmap_evasion_baseline, "change_param",
                       side_effect=fake_change):
        out = sapmap_evasion_baseline.restore_baseline(
            node, None, snap)

    assert "gw/logging" in out["restored"]
    assert ("rdisp/TRACE", "Read-only param") in out["skipped"]


def test_restore_skips_known_static_params_silently():
    """rsau/* / rec/client / stat/level are confirmed NOT runtime-
    changeable on S/4 793; restore must skip them quietly instead of
    spamming the operator with NOT_CHANGEABLE errors."""
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    snap = sapmap_evasion_baseline.BaselineSnapshot(
        sid="S4H", captured_at="2026-06-24T08:40:00",
        params={
            "rsau/enable": "1", "rsau/integrity": "1",
            "rec/client": "ALL", "stat/level": "1",
            "rdisp/TRACE": "1",
        })

    writes = []
    def fake_change(node_arg, creds, name, value):
        writes.append(name)
        return {"ok": True, "name": name, "value": value, "error": ""}

    with patch.object(sapmap_evasion_baseline, "change_param",
                       side_effect=fake_change):
        out = sapmap_evasion_baseline.restore_baseline(
            node, None, snap)

    # The static params went to skipped[] with a clear reason
    skipped_names = [n for n, _reason in out["skipped"]]
    for static in ("rsau/enable", "rsau/integrity",
                    "rec/client", "stat/level"):
        assert static in skipped_names
        reason = next(r for n, r in out["skipped"] if n == static)
        assert "static" in reason or "restart-only" in reason
    # change_param was NOT called for static params
    for static in ("rsau/enable", "rsau/integrity",
                    "rec/client", "stat/level"):
        assert static not in writes
    # rdisp/TRACE (dynamic) DID get attempted
    assert "rdisp/TRACE" in writes
    assert "rdisp/TRACE" in out["restored"]


def test_window_with_empty_touched_params_restores_nothing():
    """touched_params=[] means 'I touched no params' — restore must
    NOT iterate every captured param.  Regression for the lab bug
    where tier3_sal_slot_disable triggered a full param restore."""
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    change_param_calls = []

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE": "1"}
        if fm == "RSAU_API_GET_AUDIT_CONFIG":
            return _lab_sal_response()
        if fm == "RSAU_API_GET_PROFILE":
            return {"ED_DATA_STR": "",
                    "ET_FILT": _live_dyn_profile_rows(),
                    "ET_FILTEX": _live_dyn_filtex_rows(),
                    "ET_TEXT": [], "ET_LOG": []}
        if fm == "TH_CHANGE_PARAMETER":
            change_param_calls.append(kw)
            return {"RC": "0"}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        with sapmap_evasion_baseline.evasion_window(
                node, state, "sal_filter_narrow",
                touched_params=[]):
            pass

    # No params were touched → no param restore should fire
    assert change_param_calls == []


def test_window_with_none_touched_params_restores_everything():
    """touched_params=None (the default) preserves the legacy
    'restore every captured param' behaviour for techniques like
    tier3_set_param that don't track the touched set."""
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    change_param_calls = []

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE": "1"}
        if fm == "RSAU_API_GET_AUDIT_CONFIG":
            return _lab_sal_response()
        if fm == "RSAU_API_GET_PROFILE":
            return {"ED_DATA_STR": "",
                    "ET_FILT": _live_dyn_profile_rows(),
                    "ET_FILTEX": _live_dyn_filtex_rows(),
                    "ET_TEXT": [], "ET_LOG": []}
        if fm == "TH_CHANGE_PARAMETER":
            change_param_calls.append(kw)
            return {"RC": "0"}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        with sapmap_evasion_baseline.evasion_window(
                node, state, "rz11_dynamic_set",
                touched_params=None):
            pass

    # Restoring "everything" still skips known-static params, so
    # only the dynamic ones (rdisp/TRACE, gw/logging) get rewritten.
    changed_names = [c["PARAMETER_NAME"] for c in change_param_calls]
    assert "rdisp/TRACE" in changed_names
    assert "gw/logging" in changed_names
    # Static ones get filtered before TH_CHANGE_PARAMETER is even
    # attempted
    for static in ("rsau/enable", "rsau/integrity",
                    "rec/client", "stat/level"):
        assert static not in changed_names


def test_restore_only_writes_touched_subset():
    """only=[<list>] limits the param restore to those names.  Use
    only dynamic params here — static ones get filtered before
    change_param is called."""
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    snap = sapmap_evasion_baseline.BaselineSnapshot(
        sid="S4H", captured_at="2026-06-16T20:00:00",
        params={"gw/logging": "ACTION=Ss",
                "rdisp/TRACE": "1",
                "icm/trace_level": "1"})
    writes = []
    def fake_change(node_arg, creds, name, value):
        writes.append(name)
        return {"ok": True, "name": name, "value": value, "error": ""}
    with patch.object(sapmap_evasion_baseline, "change_param",
                       side_effect=fake_change):
        out = sapmap_evasion_baseline.restore_baseline(
            node, None, snap, only=["rdisp/TRACE"])
    assert writes == ["rdisp/TRACE"]
    assert out["restored"] == ["rdisp/TRACE"]


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

    # Stateful mock: TH_GET_PARAMETER returns whatever TH_CHANGE_PARAMETER
    # last wrote, so the verify-read after every change reflects the
    # mutation.  Initial value '1' matches what the real kernel would
    # have on a default S/4 install.
    th_change_calls = []
    state_vals = {"rdisp/TRACE": "1"}
    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE":
                     state_vals.get(kw["PARAMETER_NAME"], "1")}
        if fm == "TH_CHANGE_PARAMETER":
            th_change_calls.append((kw["PARAMETER_NAME"],
                                     kw["PARAMETER_VALUE"]))
            state_vals[kw["PARAMETER_NAME"]] = kw["PARAMETER_VALUE"]
            return {"RC": "0"}
        if fm == "RFC_READ_TABLE":
            return {"DATA": []}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        # rdisp/TRACE is one of the dynamic params (not in
        # _STATIC_PARAMS), so the restore loop actually fires for it.
        out = sapmap_evasion_tier3.tier3_set_param(
            state, node, "rdisp/TRACE", "3")

    assert out["ok"] is True
    assert out["applied"] is True
    assert out["param"] == "rdisp/TRACE"
    assert out["requested_value"] == "3"
    assert out["baseline_value"] == "1"
    # Verify-read after write confirmed the value committed
    assert out["live_after_write"] == "3"
    # Post-restore verify confirmed rollback
    assert out["live_after_restore"] == "1"

    # Mutation should have happened (rdisp/TRACE=3)
    assert ("rdisp/TRACE", "3") in th_change_calls
    # Restore should have rewritten the baseline value back (=1)
    assert ("rdisp/TRACE", "1") in th_change_calls
    # And ordering: mutation first, restore after
    mut_idx = th_change_calls.index(("rdisp/TRACE", "3"))
    restore_idx = th_change_calls.index(("rdisp/TRACE", "1"))
    assert mut_idx < restore_idx


def test_tier3_set_param_flags_silent_no_op_when_verify_read_disagrees():
    """If TH_CHANGE_PARAMETER returns RC=0 but the verify-read shows
    the baseline value (kernel silently rejected the change), the
    result should be applied=False with a clear error message."""
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            # Live value never changes — simulates a silent-no-op
            # kernel rejection where RC=0 is returned but the value
            # doesn't actually commit.
            return {"PARAMETER_VALUE": "1"}
        if fm == "TH_CHANGE_PARAMETER":
            return {"RC": "0"}
        return {"DATA": []}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        out = sapmap_evasion_tier3.tier3_set_param(
            state, node, "rdisp/TRACE", "3")

    # Writer returned RC=0 → ok=True, but applied=False because the
    # live value didn't reflect the mutation.
    assert out["ok"] is True
    assert out["applied"] is False
    assert "verify-read shows" in out["error"]
    assert out["live_after_write"] == "1"


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
            if kw["PARAMETER_VALUE"] == "3":
                return {"RC": "4", "MESSAGE": "Read-only param"}
            return {"RC": "0"}
        return {"DATA": []}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        # Dynamic param so the restore loop actually invokes
        # TH_CHANGE_PARAMETER (static params get filtered now).
        out = sapmap_evasion_tier3.tier3_set_param(
            state, node, "rdisp/TRACE", "3")

    assert out["ok"] is False
    assert out["applied"] is False
    assert "Read-only" in out["error"]
    # Restore still ran (window contract)
    assert ("rdisp/TRACE", "1") in th_change_calls


# ---------------------------------------------------------------------------
# Phase 3 step 2 — write_dyn_profile + tier3_sal_slot_disable
# ---------------------------------------------------------------------------

def _live_dyn_profile_rows(active_status=("X", "X", "X")):
    """Three-slot ET_FILT shaped exactly like the lab response."""
    return [
        {"PROFNAME": "$DYN$", "SLOTNO": "0001",
         "CURRPROF": "", "CLASSES": 255, "SEVERITY": 2,
         "CLIENT": "*", "UNAME": "SAP#*", "STATUS": active_status[0],
         "CUNAME": "", "CDATE": "00000000", "SELVAR": "00",
         "MSGVECT": b"\x00" * 64},
        {"PROFNAME": "$DYN$", "SLOTNO": "0002",
         "CURRPROF": "", "CLASSES": 255, "SEVERITY": 2,
         "CLIENT": "066", "UNAME": "*", "STATUS": active_status[1],
         "CUNAME": "", "CDATE": "00000000", "SELVAR": "00",
         "MSGVECT": b"\x00" * 64},
        {"PROFNAME": "$DYN$", "SLOTNO": "0003",
         "CURRPROF": "", "CLASSES": 0, "SEVERITY": 0,
         "CLIENT": "*", "UNAME": "*", "STATUS": active_status[2],
         "CUNAME": "", "CDATE": "00000000", "SELVAR": "11",
         "MSGVECT": b"\x00" * 64},
    ]


def _live_dyn_filtex_rows():
    return [{"PROFNAME": "$DYN$", "SLOTNO": s, "MSGVECT": b"\x00" * 160}
            for s in ("0001", "0002", "0003")]


def test_write_dyn_profile_requires_profile_name():
    """The writer must refuse a blank profile_name cleanly — the
    kernel rejects '$DYN$' and empty as 'not a valid audit profile
    name', and an unconfirmed default would just silently fail
    against every real S/4 system."""
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    r = sapmap_evasion_baseline.write_dyn_profile(
        node, None, "", _live_dyn_profile_rows(),
        _live_dyn_filtex_rows(), [])
    assert r["ok"] is False
    assert "profile_name required" in r["error"]


def test_write_dyn_profile_retags_profname_to_match_id_name():
    """Lab-confirmed silent-failure regression: rows came back from
    GET_PROFILE with PROFNAME='$DYN$' (the kernel's runtime label),
    but SET_PROFILE matches rows to slots by (PROFNAME, SLOTNO).
    If the rows still say '$DYN$' while we pass ID_NAME='SAPSEC',
    the kernel matches nothing and applies nothing — RC=0, empty
    ET_RESULT, kernel state unchanged.  Writer MUST retag every
    row's PROFNAME to match ID_NAME before sending."""
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    seen = {}

    def _call(fm, **kw):
        if fm == "RSAU_API_SET_PROFILE":
            seen["kw"] = kw
            return {"ET_RESULT": []}
        return {}

    # GET-shaped rows still labelled '$DYN$' as PROFNAME.
    rows = _live_dyn_profile_rows()
    assert all(r["PROFNAME"] == "$DYN$" for r in rows)

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        sapmap_evasion_baseline.write_dyn_profile(
            node, None, "SAPSEC", rows,
            _live_dyn_filtex_rows(), [])

    # Every row sent must now identify as SAPSEC, not $DYN$.
    sent_rows = seen["kw"]["IT_FILT"]
    assert all(r["PROFNAME"] == "SAPSEC" for r in sent_rows)
    sent_filtex = seen["kw"]["IT_FILTX"]
    assert all(r["PROFNAME"] == "SAPSEC" for r in sent_filtex)
    # And the SLOTNO values should be untouched
    assert [r["SLOTNO"] for r in sent_rows] == ["0001", "0002", "0003"]


def test_rows_retag_profname_helper_handles_missing_field():
    rows = [{"SLOTNO": "0001", "STATUS": "X"}]   # no PROFNAME column
    out = sapmap_evasion_baseline._rows_retag_profname(rows, "SAPSEC")
    # Helper only rewrites when the column exists; missing column
    # stays missing (kernel will fall back to its own default).
    assert "PROFNAME" not in out[0]


def test_rows_retag_profname_helper_with_empty_name_passes_through():
    rows = [{"PROFNAME": "$DYN$", "SLOTNO": "0001"}]
    out = sapmap_evasion_baseline._rows_retag_profname(rows, "")
    # Empty profile name = nothing to retag with; rows pass through
    # unchanged so the writer's own profile_name validation fires.
    assert out[0]["PROFNAME"] == "$DYN$"


def test_write_dyn_profile_calls_set_profile_with_dyn_only_flags():
    """The writer MUST pass ID_UPD_DYN_CNF='X' AND ID_SET_ACTIV=' '
    so the change is in-memory only and does NOT promote the dyn
    profile to the persisted active profile."""
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    seen = {}

    def _call(fm, **kw):
        if fm == "RSAU_API_SET_PROFILE":
            seen["fm"] = fm
            seen["kw"] = kw
            return {"ET_RESULT": []}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        r = sapmap_evasion_baseline.write_dyn_profile(
            node, None, "SAPSEC", _live_dyn_profile_rows(),
            _live_dyn_filtex_rows(), [])

    assert r["ok"] is True
    assert seen["kw"]["ID_NAME"] == "SAPSEC"
    assert seen["kw"]["ID_UPD_DYN_CNF"] == "X"
    assert seen["kw"]["ID_SET_ACTIV"] == " "
    assert len(seen["kw"]["IT_FILT"]) == 3
    assert len(seen["kw"]["IT_FILTX"]) == 3


def test_write_dyn_profile_hex_string_msgvect_decoded_to_bytes():
    """When the rows came from a deserialised JSON loot file the
    MSGVECT will be a hex string.  The writer must convert it back
    to bytes for the RAWSTRING parameter."""
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    seen = {}

    def _call(fm, **kw):
        if fm == "RSAU_API_SET_PROFILE":
            seen["kw"] = kw
            return {"ET_RESULT": []}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    rows = [{"PROFNAME": "$DYN$", "SLOTNO": "0001",
              "STATUS": "X", "MSGVECT": "deadbeef"}]
    with _patch_connection(conn):
        sapmap_evasion_baseline.write_dyn_profile(
            node, None, "SAPSEC", rows, None, None)

    assert seen["kw"]["IT_FILT"][0]["MSGVECT"] == bytes.fromhex("deadbeef")


def test_write_dyn_profile_surfaces_et_result_errors():
    """Kernel reports failures via ET_RESULT (BAPIRET2 rows), not via
    exceptions.  The writer must mark such calls as ok=False."""
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    conn = MagicMock()
    conn.call.return_value = {"ET_RESULT": [
        {"TYPE": "E", "ID": "SECAUDIT", "NUMBER": "045",
         "MESSAGE": "No authority for SAL config change"},
    ]}
    with _patch_connection(conn):
        r = sapmap_evasion_baseline.write_dyn_profile(
            node, None, "SAPSEC", _live_dyn_profile_rows(),
            _live_dyn_filtex_rows(), [])
    assert r["ok"] is False
    assert "No authority" in r["error"]
    assert len(r["errors"]) == 1


def test_capture_baseline_records_dyn_profile_rows():
    """capture_baseline must also call RSAU_API_GET_PROFILE and
    cache the ET_FILT/ET_FILTEX/ET_TEXT rows alongside sal_config."""
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE": "1"}
        if fm == "RSAU_API_GET_AUDIT_CONFIG":
            return _lab_sal_response()
        if fm == "RSAU_API_GET_PROFILE":
            return {"ED_DATA_STR": "",
                    "ET_FILT": _live_dyn_profile_rows(),
                    "ET_FILTEX": _live_dyn_filtex_rows(),
                    "ET_TEXT": [], "ET_LOG": []}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    import tempfile
    with _patch_connection(conn), tempfile.TemporaryDirectory() as td:
        snap = sapmap_evasion_baseline.capture_baseline(
            node, loot_root=td)

    assert len(snap.dyn_filt) == 3
    assert snap.dyn_filt[0]["UNAME"] == "SAP#*"
    assert len(snap.dyn_filtex) == 3


def test_baseline_snapshot_roundtrip_hex_encodes_bytes_msgvect():
    """to_dict / from_dict must hex-encode bytes MSGVECT for JSON
    survival; the round-trip leaves them as hex strings which
    write_dyn_profile then re-decodes on the next write."""
    snap = sapmap_evasion_baseline.BaselineSnapshot(
        sid="S4H", dyn_filt=_live_dyn_profile_rows(),
        dyn_filtex=_live_dyn_filtex_rows())
    d = snap.to_dict()
    # Bytes round-tripped as hex
    assert isinstance(d["dyn_filt"][0]["MSGVECT"], str)
    assert d["dyn_filt"][0]["MSGVECT"] == "00" * 64
    snap2 = sapmap_evasion_baseline.BaselineSnapshot.from_dict(d)
    assert len(snap2.dyn_filt) == 3
    assert snap2.dyn_filt[0]["UNAME"] == "SAP#*"


def test_window_restore_dyn_profile_when_touched_flag_set():
    """When the technique signals touched_dyn_profile=True, the
    window exit must call write_dyn_profile with the BASELINE rows
    (not the mutated rows)."""
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    # Pre-seed an in-memory baseline so the window doesn't have to
    # re-capture, and so sal_profile_name is set for restore.
    node._evasion_baseline = sapmap_evasion_baseline.BaselineSnapshot(
        sid="S4H", sal_profile_name="SAPSEC",
        params={"rdisp/TRACE": "1"},
        dyn_filt=_live_dyn_profile_rows(),
        dyn_filtex=_live_dyn_filtex_rows())

    set_profile_calls = []

    def _call(fm, **kw):
        if fm == "RSAU_API_SET_PROFILE":
            set_profile_calls.append(kw)
            return {"ET_RESULT": []}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        with sapmap_evasion_baseline.evasion_window(
                node, state, "sal_filter_narrow",
                touched_params=[],
                touched_dyn_profile=True):
            pass

    assert len(set_profile_calls) == 1   # restore-on-exit fired once
    assert set_profile_calls[0]["ID_NAME"] == "SAPSEC"
    restored_rows = set_profile_calls[0]["IT_FILT"]
    statuses = sorted(str(r.get("STATUS", "")).strip()
                       for r in restored_rows)
    assert statuses == ["X", "X", "X"]   # baseline had all 3 active


def test_window_restore_skips_dyn_profile_when_flag_not_set():
    """Default touched_dyn_profile=False means the window exit does
    NOT touch RSAU_API_SET_PROFILE — keeps non-SAL techniques
    cheap."""
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    set_profile_calls = []

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE": "1"}
        if fm == "RSAU_API_GET_AUDIT_CONFIG":
            return _lab_sal_response()
        if fm == "RSAU_API_GET_PROFILE":
            return {"ED_DATA_STR": "",
                    "ET_FILT": _live_dyn_profile_rows(),
                    "ET_FILTEX": _live_dyn_filtex_rows(),
                    "ET_TEXT": [], "ET_LOG": []}
        if fm == "RSAU_API_SET_PROFILE":
            set_profile_calls.append(kw)
            return {"ET_RESULT": []}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        with sapmap_evasion_baseline.evasion_window(
                node, state, "sal_filter_narrow"):
            pass

    assert set_profile_calls == []


# ---------------------------------------------------------------------------
# tier3_sal_slot_disable — first concrete Tier 3 technique
# ---------------------------------------------------------------------------

def test_normalize_slotnos_single_value_padded():
    assert sapmap_evasion_tier3._normalize_slotnos("1", []) == ["0001"]
    assert sapmap_evasion_tier3._normalize_slotnos(3, []) == ["0003"]
    assert sapmap_evasion_tier3._normalize_slotnos(
        "0007", []) == ["0007"]


def test_normalize_slotnos_comma_separated():
    out = sapmap_evasion_tier3._normalize_slotnos("1,2,3", [])
    assert out == ["0001", "0002", "0003"]
    # tolerates whitespace + already-padded entries
    out = sapmap_evasion_tier3._normalize_slotnos(" 0001 , 02 ", [])
    assert out == ["0001", "0002"]


def test_normalize_slotnos_list_input():
    out = sapmap_evasion_tier3._normalize_slotnos([1, "2", "0003"], [])
    assert out == ["0001", "0002", "0003"]


def test_normalize_slotnos_all_picks_active_only():
    """ALL must NOT target inactive placeholder slots — those are
    already empty and writing STATUS=' ' on them is a wasted write
    that also looks suspicious in the kernel's change tracking."""
    rows = [
        {"SLOTNO": "0001", "STATUS": "X"},
        {"SLOTNO": "0002", "STATUS": "X"},
        {"SLOTNO": "0003", "STATUS": "X"},
        {"SLOTNO": "0004", "STATUS": ""},   # placeholder
        {"SLOTNO": "0005", "STATUS": ""},
    ]
    out = sapmap_evasion_tier3._normalize_slotnos("ALL", rows)
    assert out == ["0001", "0002", "0003"]
    # case-insensitive
    assert sapmap_evasion_tier3._normalize_slotnos("all", rows) == [
        "0001", "0002", "0003"]


def test_normalize_slotnos_blank_returns_empty():
    assert sapmap_evasion_tier3._normalize_slotnos("", []) == []
    assert sapmap_evasion_tier3._normalize_slotnos(None, []) == []
    assert sapmap_evasion_tier3._normalize_slotnos("   ", []) == []


def test_tier3_sal_slot_disable_multi_slot_flips_all_requested():
    """Multi-slot input flips STATUS on every requested row and
    leaves the others untouched."""
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True,
                     "baseline_captured_at": "2026-06-24T10:00:00"}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    set_profile_calls = []

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE": "1"}
        if fm == "RSAU_API_GET_AUDIT_CONFIG":
            return _lab_sal_response()
        if fm == "RSAU_API_GET_PROFILE":
            return {"ED_DATA_STR": "",
                    "ET_FILT": _live_dyn_profile_rows(),
                    "ET_FILTEX": _live_dyn_filtex_rows(),
                    "ET_TEXT": [], "ET_LOG": []}
        if fm == "RSAU_API_SET_PROFILE":
            set_profile_calls.append(kw)
            return {"ET_RESULT": []}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        out = sapmap_evasion_tier3.tier3_sal_slot_disable(
            state, node, "1,2", profile_name="SAPSEC",
            hold_seconds=0)

    assert out["ok"] is True
    assert out["slotno"] == "0001,0002"

    # Mutation write — slots 1 + 2 inactive, slot 3 still active
    mut_rows = set_profile_calls[0]["IT_FILT"]
    by_slot = {r["SLOTNO"]: r["STATUS"] for r in mut_rows}
    assert by_slot["0001"] == " "
    assert by_slot["0002"] == " "
    assert by_slot["0003"] == "X"


def test_tier3_sal_slot_disable_all_targets_only_active_slots():
    """slotno='ALL' must pick every STATUS='X' slot and skip the
    inactive placeholders."""
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True,
                     "baseline_captured_at": "2026-06-24T10:00:00"}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    set_profile_calls = []

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE": "1"}
        if fm == "RSAU_API_GET_AUDIT_CONFIG":
            return _lab_sal_response()
        if fm == "RSAU_API_GET_PROFILE":
            return {"ED_DATA_STR": "",
                    "ET_FILT": _live_dyn_profile_rows(),
                    "ET_FILTEX": _live_dyn_filtex_rows(),
                    "ET_TEXT": [], "ET_LOG": []}
        if fm == "RSAU_API_SET_PROFILE":
            set_profile_calls.append(kw)
            return {"ET_RESULT": []}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        out = sapmap_evasion_tier3.tier3_sal_slot_disable(
            state, node, "ALL", profile_name="SAPSEC",
            hold_seconds=0)

    assert out["ok"] is True
    assert out["slotno"] == "0001,0002,0003"
    mut_rows = set_profile_calls[0]["IT_FILT"]
    by_slot = {r["SLOTNO"]: r["STATUS"] for r in mut_rows}
    # All three active slots now off
    assert by_slot["0001"] == " "
    assert by_slot["0002"] == " "
    assert by_slot["0003"] == " "


def test_tier3_sal_slot_disable_full_roundtrip():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True,
                     "baseline_captured_at": "2026-06-23T20:00:00"}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    set_profile_calls = []

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE": "1"}
        if fm == "RSAU_API_GET_AUDIT_CONFIG":
            return _lab_sal_response()
        if fm == "RSAU_API_GET_PROFILE":
            return {"ED_DATA_STR": "",
                    "ET_FILT": _live_dyn_profile_rows(),
                    "ET_FILTEX": _live_dyn_filtex_rows(),
                    "ET_TEXT": [], "ET_LOG": []}
        if fm == "RSAU_API_SET_PROFILE":
            set_profile_calls.append(kw)
            return {"ET_RESULT": []}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        out = sapmap_evasion_tier3.tier3_sal_slot_disable(
            state, node, "0001", profile_name="SAPSEC",
            hold_seconds=0)

    assert out["ok"] is True
    assert out["slotno"] == "0001"
    assert out["baseline_statuses"] == {"0001": "X"}
    assert out["before_active_count"] == 3

    # Two SET_PROFILE calls: mutation (slot 0001 inactive) +
    # window-exit restore (slot 0001 back to active).
    assert len(set_profile_calls) == 2
    # Both must use the operator-supplied profile name as ID_NAME.
    assert set_profile_calls[0]["ID_NAME"] == "SAPSEC"
    assert set_profile_calls[1]["ID_NAME"] == "SAPSEC"

    mut_rows = set_profile_calls[0]["IT_FILT"]
    slot1 = next(r for r in mut_rows if r["SLOTNO"] == "0001")
    assert slot1["STATUS"] == " "      # mutation flipped it off

    restore_rows = set_profile_calls[1]["IT_FILT"]
    slot1_r = next(r for r in restore_rows if r["SLOTNO"] == "0001")
    assert slot1_r["STATUS"] == "X"    # restored to baseline


def test_tier3_sal_slot_disable_refuses_blank_profile_name():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True,
                     "baseline_captured_at": "2026-06-23T20:00:00"}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE": "1"}
        if fm == "RSAU_API_GET_AUDIT_CONFIG":
            return _lab_sal_response()
        if fm == "RSAU_API_GET_PROFILE":
            return {"ED_DATA_STR": "",
                    "ET_FILT": _live_dyn_profile_rows(),
                    "ET_FILTEX": _live_dyn_filtex_rows(),
                    "ET_TEXT": [], "ET_LOG": []}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        out = sapmap_evasion_tier3.tier3_sal_slot_disable(
            state, node, "0001", profile_name="",
            hold_seconds=0)

    assert out["ok"] is False
    assert "profile name required" in out["error"].lower()


def test_tier3_sal_slot_disable_refuses_when_gate_closed():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": False}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    out = sapmap_evasion_tier3.tier3_sal_slot_disable(
        state, node, "0001", hold_seconds=0)
    assert out["ok"] is False
    assert "--allow-evasion" in out["error"]


def test_tier3_sal_slot_disable_rejects_unknown_slotno():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True,
                     "baseline_captured_at": "2026-06-23T20:00:00"}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE": "1"}
        if fm == "RSAU_API_GET_AUDIT_CONFIG":
            return _lab_sal_response()
        if fm == "RSAU_API_GET_PROFILE":
            return {"ED_DATA_STR": "",
                    "ET_FILT": _live_dyn_profile_rows(),
                    "ET_FILTEX": _live_dyn_filtex_rows(),
                    "ET_TEXT": [], "ET_LOG": []}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        out = sapmap_evasion_tier3.tier3_sal_slot_disable(
            state, node, "9999", profile_name="SAPSEC",
            hold_seconds=0)

    assert out["ok"] is False
    assert "not present" in out["error"]


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


def test_read_dyn_profile_dyn_default_passes_only_dyn_conf():
    """Default call (no profile_name) must pass ID_DYN_CONF='X' alone.
    The kernel rejects multi-action calls with SECAUDIT 058
    'Only one action is permitted' surfaced via ET_LOG."""
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
                "ET_FILTEX": [], "ET_TEXT": [], "ET_LOG": [],
            }
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        resp = sapmap_evasion_tier3.read_dyn_profile(node)

    # Only ID_DYN_CONF must be supplied; ID_NAME absent.
    assert seen["kw"] == {"ID_DYN_CONF": "X"}
    assert resp["ET_FILT"][0]["UNAME"] == "SAP#*"


def test_read_dyn_profile_named_profile_passes_only_id_name():
    """When a profile_name is given, ID_NAME alone — no ID_DYN_CONF
    — so the call doesn't trip the mutual-exclusion check."""
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    seen = {}

    def _call(fm, **kw):
        if fm == "RSAU_API_GET_PROFILE":
            seen["kw"] = kw
            return {"ED_DATA_STR": "", "ET_FILT": [],
                    "ET_FILTEX": [], "ET_TEXT": [], "ET_LOG": []}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        sapmap_evasion_tier3.read_dyn_profile(
            node, profile_name="SAP_NORMAL")

    assert seen["kw"] == {"ID_NAME": "SAP_NORMAL"}


def test_et_log_errors_extracts_type_e_rows():
    rows = [
        {"TYPE": "I", "MESSAGE": "info"},
        {"TYPE": "E", "ID": "SECAUDIT", "NUMBER": "058",
         "MESSAGE": "Only one action is permitted"},
        {"TYPE": "A", "MESSAGE": "abort"},
        {"TYPE": "S", "MESSAGE": "success"},
    ]
    errs = sapmap_evasion_tier3._et_log_errors(rows)
    assert len(errs) == 2
    assert errs[0]["ID"] == "SECAUDIT"
    assert errs[1]["TYPE"] == "A"


def test_probe_dyn_profile_refuses_when_flag_disarmed():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": False}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    out = sapmap_evasion_tier3.tier3_probe_dyn_profile(state, node)
    assert out["ok"] is False
    assert "--allow-evasion" in out["error"]


def test_probe_dyn_profile_marks_failure_when_et_log_carries_error():
    """The lab repro: kernel returned RC=0 + empty ET_FILT + an
    ET_LOG error row.  The probe must surface that as ok=False with
    the error message threaded into the response, not pretend the
    empty result was a success."""
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    def _call(fm, **kw):
        if fm == "RSAU_API_GET_PROFILE":
            return {
                "ED_DATA_STR": "",
                "ET_FILT": [], "ET_FILTEX": [], "ET_TEXT": [],
                "ET_LOG": [{
                    "TYPE": "E", "ID": "SECAUDIT", "NUMBER": "058",
                    "MESSAGE": "Only one action is permitted",
                }],
            }
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        out = sapmap_evasion_tier3.tier3_probe_dyn_profile(
            state, node, loot_root="/tmp/sapmap-test-probe-elog")

    assert out["ok"] is False
    assert len(out["et_log_errors"]) == 1
    assert "Only one action is permitted" in out["error"]


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
    # Default call has no profile_name → response uses "(dyn)" marker
    # so the operator sees the call mode in the finding line.
    assert out["profile_name"] == "(dyn)"
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


# ---------------------------------------------------------------------------
# Legacy SAL config — RSAU_GET/UPD_AUDIT_CONFIG (stealth writer)
# ---------------------------------------------------------------------------

def _legacy_slotinfo_rows(active_status=("X", "X", "X")):
    """Three positional RSAUINFO rows — no SLOTNO field."""
    return [
        {"ENABLE": "X", "SLOTCOUNT": 3, "STATUS": active_status[0],
         "LOW_BUTTON": "X", "MED_BUTTON": "X", "HGH_BUTTON": "",
         "POS": 2287, "VERSION": 16, "SHMDATE": "2026-06-24",
         "MAXFILESIZ": 2146304,
         "LOGIN": "X", "RFCLOGIN": "X", "TASTART": "X",
         "REPOSTART": "X", "USERSTAMM": "X", "RFCSTART": "X",
         "SONST": "X", "SYSTEM": "X",
         "UNAME": "SAP#*", "MANDT": "*",
         "SELVAR": b"\x00", "MSGVECT": b"\x00" * 64,
         "LIFETIME": 0, "DELETED": 0, "FILEMAX": 2146304,
         "FILENUMBER": 2, "CURFILSIZE": 0, "FILESTATUS": 1},
        {"ENABLE": "X", "SLOTCOUNT": 3, "STATUS": active_status[1],
         "LOW_BUTTON": "X", "MED_BUTTON": "X", "HGH_BUTTON": "",
         "POS": 0, "VERSION": 0, "SHMDATE": "",
         "MAXFILESIZ": 0,
         "LOGIN": "X", "RFCLOGIN": "X", "TASTART": "X",
         "REPOSTART": "X", "USERSTAMM": "X", "RFCSTART": "X",
         "SONST": "X", "SYSTEM": "X",
         "UNAME": "*", "MANDT": "066",
         "SELVAR": b"\x00", "MSGVECT": b"\x00" * 64,
         "LIFETIME": 0, "DELETED": 0, "FILEMAX": 0,
         "FILENUMBER": 0, "CURFILSIZE": 0, "FILESTATUS": 0},
        {"ENABLE": "X", "SLOTCOUNT": 3, "STATUS": active_status[2],
         "LOW_BUTTON": "", "MED_BUTTON": "", "HGH_BUTTON": "",
         "POS": 0, "VERSION": 0, "SHMDATE": "",
         "MAXFILESIZ": 0,
         "LOGIN": "", "RFCLOGIN": "", "TASTART": "",
         "REPOSTART": "", "USERSTAMM": "", "RFCSTART": "",
         "SONST": "", "SYSTEM": "",
         "UNAME": "*", "MANDT": "*",
         "SELVAR": b"\x11", "MSGVECT": b"\xfc" * 64,
         "LIFETIME": 0, "DELETED": 0, "FILEMAX": 0,
         "FILENUMBER": 0, "CURFILSIZE": 0, "FILESTATUS": 0},
    ]


def test_read_legacy_sal_config_returns_slotinfo():
    conn = MagicMock()
    rows = _legacy_slotinfo_rows()
    conn.call.return_value = {
        "ENABLE": "X", "SLOTCOUNT": 3, "SLOTINFO": rows,
        "VERSION": 16, "POSITION": 2287}
    r = sapmap_evasion_baseline.read_legacy_sal_config(conn)
    assert r["ok"] is True
    assert r["enable"] == "X"
    assert r["slotcount"] == 3
    assert len(r["slotinfo"]) == 3


def test_read_legacy_sal_config_handles_fm_not_found():
    conn = MagicMock()
    conn.call.side_effect = Exception("FU_NOT_FOUND blah")
    r = sapmap_evasion_baseline.read_legacy_sal_config(conn)
    assert r["ok"] is False
    assert "not found" in r["error"]


def test_write_legacy_sal_config_calls_upd_with_correct_params():
    conn = MagicMock()
    conn.call.return_value = {"E_EXCP_TEXT": ""}
    rows = _legacy_slotinfo_rows()
    r = sapmap_evasion_baseline.write_legacy_sal_config(
        conn, rows, enable="-")
    assert r["ok"] is True
    conn.call.assert_called_once()
    args = conn.call.call_args
    assert args[0][0] == "RSAU_UPD_AUDIT_CONFIG"
    assert args[1]["ENABLE"] == "-"
    assert len(args[1]["SLOTINFO"]) == 3


def test_write_legacy_sal_config_surfaces_exception_text():
    conn = MagicMock()
    conn.call.return_value = {"E_EXCP_TEXT": "Keine Berechtigung"}
    r = sapmap_evasion_baseline.write_legacy_sal_config(
        conn, [], enable="-")
    assert r["ok"] is False
    assert "Keine Berechtigung" in r["error"]


def test_write_legacy_sal_config_handles_shm_access_error():
    conn = MagicMock()
    conn.call.side_effect = Exception("SHM_ACCESS_ERROR raised")
    r = sapmap_evasion_baseline.write_legacy_sal_config(
        conn, [], enable="-")
    assert r["ok"] is False
    assert "SHM_ACCESS_ERROR" in r["error"]


def test_baseline_snapshot_roundtrip_preserves_legacy_slotinfo():
    rows = _legacy_slotinfo_rows()
    snap = sapmap_evasion_baseline.BaselineSnapshot(
        sid="S4H", captured_at="2026-06-24T16:00:00",
        params={"rsau/enable": "1"},
        legacy_slotinfo=rows)
    d = snap.to_dict()
    assert len(d["legacy_slotinfo"]) == 3
    # Bytes should be hex-encoded in the JSON-safe dict
    assert isinstance(d["legacy_slotinfo"][0]["SELVAR"], str)
    snap2 = sapmap_evasion_baseline.BaselineSnapshot.from_dict(d)
    assert len(snap2.legacy_slotinfo) == 3


def test_capture_baseline_reads_legacy_slotinfo():
    """capture_baseline should call RSAU_GET_AUDIT_CONFIG and store
    the positional SLOTINFO rows for the stealth writer."""
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    legacy_rows = _legacy_slotinfo_rows()

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE": "1"}
        if fm == "RSAU_API_GET_AUDIT_CONFIG":
            return _lab_sal_response()
        if fm == "RSAU_API_GET_PROFILE":
            return {"ET_FILT": [], "ET_FILTEX": [], "ET_TEXT": [],
                    "ET_LOG": []}
        if fm == "RSAU_GET_AUDIT_CONFIG":
            return {"ENABLE": "X", "SLOTCOUNT": 3,
                    "SLOTINFO": legacy_rows}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        snap = sapmap_evasion_baseline.capture_baseline(node)

    assert len(snap.legacy_slotinfo) == 3


def test_stealth_slot_disable_uses_legacy_writer():
    """When RSAU_GET/UPD_AUDIT_CONFIG are available, tier3_sal_slot_disable
    should use the SHM-only stealth path and return stealth_mode=True."""
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True,
                     "baseline_captured_at": "2026-06-24T10:00:00"}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    upd_calls = []

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE": "1"}
        if fm == "RSAU_API_GET_AUDIT_CONFIG":
            return _lab_sal_response()
        if fm == "RSAU_API_GET_PROFILE":
            return {"ET_FILT": _live_dyn_profile_rows(),
                    "ET_FILTEX": _live_dyn_filtex_rows(),
                    "ET_TEXT": [], "ET_LOG": []}
        if fm == "RSAU_GET_AUDIT_CONFIG":
            return {"ENABLE": "X", "SLOTCOUNT": 3,
                    "SLOTINFO": _legacy_slotinfo_rows()}
        if fm == "RSAU_UPD_AUDIT_CONFIG":
            upd_calls.append(kw)
            return {"E_EXCP_TEXT": ""}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        out = sapmap_evasion_tier3.tier3_sal_slot_disable(
            state, node, "1", hold_seconds=0)

    assert out["ok"] is True
    assert out.get("stealth_mode") is True
    # Should have called UPD twice: once to mutate, once to restore
    assert len(upd_calls) == 2
    # First call: slot 1 disabled
    mut_rows = upd_calls[0]["SLOTINFO"]
    assert mut_rows[0]["STATUS"] == " "
    assert mut_rows[1]["STATUS"] == "X"
    # Second call: restore (all original statuses back)
    rest_rows = upd_calls[1]["SLOTINFO"]
    assert rest_rows[0]["STATUS"] == "X"
    assert rest_rows[1]["STATUS"] == "X"


def test_stealth_slot_disable_all_flips_active_only():
    """ALL should disable every active slot via positional indexing."""
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True,
                     "baseline_captured_at": "2026-06-24T10:00:00"}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    upd_calls = []

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE": "1"}
        if fm == "RSAU_API_GET_AUDIT_CONFIG":
            return _lab_sal_response()
        if fm == "RSAU_API_GET_PROFILE":
            return {"ET_FILT": _live_dyn_profile_rows(),
                    "ET_FILTEX": [], "ET_TEXT": [], "ET_LOG": []}
        if fm == "RSAU_GET_AUDIT_CONFIG":
            return {"ENABLE": "X", "SLOTCOUNT": 3,
                    "SLOTINFO": _legacy_slotinfo_rows()}
        if fm == "RSAU_UPD_AUDIT_CONFIG":
            upd_calls.append(kw)
            return {"E_EXCP_TEXT": ""}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        out = sapmap_evasion_tier3.tier3_sal_slot_disable(
            state, node, "ALL", hold_seconds=0)

    assert out["ok"] is True
    assert out.get("stealth_mode") is True
    assert out["slotno"] == "0001,0002,0003"
    mut_rows = upd_calls[0]["SLOTINFO"]
    assert all(r["STATUS"] == " " for r in mut_rows)


def test_stealth_falls_back_to_api_when_legacy_fm_missing():
    """When RSAU_GET_AUDIT_CONFIG raises FU_NOT_FOUND, the function
    should fall back to the RSAU_API_SET_PROFILE path."""
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True,
                     "baseline_captured_at": "2026-06-24T10:00:00"}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    set_profile_calls = []

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE": "1"}
        if fm == "RSAU_API_GET_AUDIT_CONFIG":
            return _lab_sal_response()
        if fm == "RSAU_API_GET_PROFILE":
            return {"ET_FILT": _live_dyn_profile_rows(),
                    "ET_FILTEX": _live_dyn_filtex_rows(),
                    "ET_TEXT": [], "ET_LOG": []}
        if fm == "RSAU_GET_AUDIT_CONFIG":
            raise Exception("FU_NOT_FOUND RSAU_GET_AUDIT_CONFIG")
        if fm == "RSAU_API_SET_PROFILE":
            set_profile_calls.append(kw)
            return {"ET_RESULT": []}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        out = sapmap_evasion_tier3.tier3_sal_slot_disable(
            state, node, "1", profile_name="SAPSEC",
            hold_seconds=0)

    assert out["ok"] is True
    assert out.get("stealth_mode") is not True
    # Fallback used RSAU_API_SET_PROFILE
    assert len(set_profile_calls) >= 1


def test_stealth_slot_disable_no_profile_name_needed():
    """Stealth path should work without profile_name — the legacy
    writer doesn't reference any named profile."""
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True,
                     "baseline_captured_at": "2026-06-24T10:00:00"}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE": "1"}
        if fm == "RSAU_API_GET_AUDIT_CONFIG":
            return _lab_sal_response()
        if fm == "RSAU_API_GET_PROFILE":
            return {"ET_FILT": _live_dyn_profile_rows(),
                    "ET_FILTEX": [], "ET_TEXT": [], "ET_LOG": []}
        if fm == "RSAU_GET_AUDIT_CONFIG":
            return {"ENABLE": "X", "SLOTCOUNT": 3,
                    "SLOTINFO": _legacy_slotinfo_rows()}
        if fm == "RSAU_UPD_AUDIT_CONFIG":
            return {"E_EXCP_TEXT": ""}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        # No profile_name at all — stealth path shouldn't need it
        out = sapmap_evasion_tier3.tier3_sal_slot_disable(
            state, node, "1", profile_name="",
            hold_seconds=0)

    assert out["ok"] is True
    assert out.get("stealth_mode") is True


# ---------------------------------------------------------------------------
# Tier 3 — SAL UNAME narrow (slot-filter user swap, stealth path)
# ---------------------------------------------------------------------------

def test_sal_uname_narrow_swaps_uname_and_restores():
    """tier3_sal_uname_narrow should replace UNAME on the target slot,
    sleep, then restore the original baseline UNAME — all via the
    legacy stealth writer."""
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True,
                     "baseline_captured_at": "2026-06-24T10:00:00"}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    upd_calls = []

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE": "1"}
        if fm == "RSAU_API_GET_AUDIT_CONFIG":
            return _lab_sal_response()
        if fm == "RSAU_API_GET_PROFILE":
            return {"ET_FILT": _live_dyn_profile_rows(),
                    "ET_FILTEX": _live_dyn_filtex_rows(),
                    "ET_TEXT": [], "ET_LOG": []}
        if fm == "RSAU_GET_AUDIT_CONFIG":
            return {"ENABLE": "X", "SLOTCOUNT": 3,
                    "SLOTINFO": _legacy_slotinfo_rows()}
        if fm == "RSAU_UPD_AUDIT_CONFIG":
            upd_calls.append(kw)
            return {"E_EXCP_TEXT": ""}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        out = sapmap_evasion_tier3.tier3_sal_uname_narrow(
            state, node, "1",
            replacement_uname="JORIS", hold_seconds=0)

    assert out["ok"] is True
    assert out.get("stealth_mode") is True
    # Two UPD calls: mutate then restore
    assert len(upd_calls) == 2
    mut_rows = upd_calls[0]["SLOTINFO"]
    assert mut_rows[0]["UNAME"] == "JORIS"
    # Other slots untouched in mutation pass
    assert mut_rows[1]["UNAME"] == "*"
    # Restore puts the original UNAME back
    rest_rows = upd_calls[1]["SLOTINFO"]
    assert rest_rows[0]["UNAME"] == "SAP#*"
    # Baseline reported in result
    assert out.get("baseline_unames", {}).get("0001") == "SAP#*"
    assert out.get("replacement_uname") == "JORIS"


def test_sal_uname_narrow_requires_replacement_uname():
    """An empty replacement_uname should be rejected before any RFC
    call is made."""
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True,
                     "baseline_captured_at": "2026-06-24T10:00:00"}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    out = sapmap_evasion_tier3.tier3_sal_uname_narrow(
        state, node, "1", replacement_uname="", hold_seconds=0)

    assert out["ok"] is False
    assert "replacement_uname required" in out.get("error", "")


def test_sal_uname_narrow_refuses_when_gate_disarmed():
    """Without --allow-evasion the technique must refuse before
    touching any state."""
    state = SAPMAPState()
    state.evasion = {"allow_evasion": False}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    out = sapmap_evasion_tier3.tier3_sal_uname_narrow(
        state, node, "1", replacement_uname="JORIS", hold_seconds=0)

    assert out["ok"] is False


def test_sal_uname_narrow_all_targets_active_slots():
    """ALL should swap UNAME on every active slot, leaving inactive
    placeholder slots untouched."""
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True,
                     "baseline_captured_at": "2026-06-24T10:00:00"}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    upd_calls = []

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE": "1"}
        if fm == "RSAU_API_GET_AUDIT_CONFIG":
            return _lab_sal_response()
        if fm == "RSAU_API_GET_PROFILE":
            return {"ET_FILT": _live_dyn_profile_rows(),
                    "ET_FILTEX": [], "ET_TEXT": [], "ET_LOG": []}
        if fm == "RSAU_GET_AUDIT_CONFIG":
            return {"ENABLE": "X", "SLOTCOUNT": 3,
                    "SLOTINFO": _legacy_slotinfo_rows()}
        if fm == "RSAU_UPD_AUDIT_CONFIG":
            upd_calls.append(kw)
            return {"E_EXCP_TEXT": ""}
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        out = sapmap_evasion_tier3.tier3_sal_uname_narrow(
            state, node, "ALL",
            replacement_uname="A*", hold_seconds=0)

    assert out["ok"] is True
    assert out["slotno"] == "0001,0002,0003"
    mut_rows = upd_calls[0]["SLOTINFO"]
    # All three slots should have UNAME swapped
    assert all(r["UNAME"] == "A*" for r in mut_rows)
    # Restore returns originals
    rest_rows = upd_calls[1]["SLOTINFO"]
    assert rest_rows[0]["UNAME"] == "SAP#*"
    assert rest_rows[1]["UNAME"] == "*"


def test_sal_uname_narrow_returns_error_when_legacy_fm_missing():
    """Unlike slot-disable, the UNAME narrow path has no API fallback —
    it should return ok=False when the legacy reader is unavailable."""
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True,
                     "baseline_captured_at": "2026-06-24T10:00:00"}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")

    def _call(fm, **kw):
        if fm == "TH_GET_PARAMETER":
            return {"PARAMETER_VALUE": "1"}
        if fm == "RSAU_API_GET_AUDIT_CONFIG":
            return _lab_sal_response()
        if fm == "RSAU_API_GET_PROFILE":
            return {"ET_FILT": _live_dyn_profile_rows(),
                    "ET_FILTEX": [], "ET_TEXT": [], "ET_LOG": []}
        if fm == "RSAU_GET_AUDIT_CONFIG":
            raise Exception("FU_NOT_FOUND RSAU_GET_AUDIT_CONFIG")
        return {}

    conn = MagicMock()
    conn.call.side_effect = _call
    with _patch_connection(conn):
        out = sapmap_evasion_tier3.tier3_sal_uname_narrow(
            state, node, "1",
            replacement_uname="JORIS", hold_seconds=0)

    assert out["ok"] is False
    assert "stealth writer unavailable" in out.get("error", "")


# ---------------------------------------------------------------------------
# Java SAL suppress — sap_java_logctl helpers
# ---------------------------------------------------------------------------

import sap_java_logctl


def test_logctl_jsp_contains_all_target_categories():
    for cat in sap_java_logctl.JAVA_SAL_CATEGORIES:
        assert cat in sap_java_logctl.LOGCTL_JSP


def test_logctl_jsp_has_all_three_actions():
    jsp = sap_java_logctl.LOGCTL_JSP
    assert '"read"' in jsp
    assert '"suppress"' in jsp
    assert '"restore"' in jsp
    assert "LOGCTL_READY" in jsp


def test_logctl_jsp_imports_logging_api():
    assert "com.sap.tc.logging.*" in sap_java_logctl.LOGCTL_JSP


def test_baselines_to_wire_encodes_pipe_separated():
    cats = {"/System/Security/Audit": 4,
            "/System/Security/Audit/ACLs": 6}
    wire = sap_java_logctl.baselines_to_wire(cats)
    assert "/System/Security/Audit=4" in wire
    assert "/System/Security/Audit/ACLs=6" in wire
    assert "|" in wire


def test_baselines_to_wire_empty_dict():
    assert sap_java_logctl.baselines_to_wire({}) == ""


# ---------------------------------------------------------------------------
# invoke_logctl — response parsing
# ---------------------------------------------------------------------------

def _mock_urlopen(body, status=200):
    """Return a patch that makes urllib.request.urlopen return ``body``."""
    resp = MagicMock()
    resp.read.return_value = body.encode("utf-8")
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return patch("sap_java_logctl.urllib.request.urlopen", return_value=resp)


def test_invoke_logctl_read_parses_categories():
    body = ("/System/Security/Audit=4|"
            "/System/Security/Audit/ACLs=6|"
            "/System/Security/Audit/Configuration=4|"
            "/System/Security/Audit/PermissionCheck=4|"
            "/System/Security/Audit/PrincipalModification=4|"
            "/System/Security/Audit/UserMapping=4")
    with _mock_urlopen(body):
        r = sap_java_logctl.invoke_logctl("http://x:50000/irj/lc.jsp",
                                           "read")
    assert r["ok"] is True
    assert len(r["categories"]) == 6
    assert r["categories"]["/System/Security/Audit"] == 4
    assert r["categories"]["/System/Security/Audit/ACLs"] == 6


def test_invoke_logctl_read_error_category():
    body = "/System/Security/Audit=ERR:NullPointerException"
    with _mock_urlopen(body):
        r = sap_java_logctl.invoke_logctl("http://x:50000/irj/lc.jsp",
                                           "read")
    assert r["ok"] is False
    assert "ERR:" in r["error"]


def test_invoke_logctl_suppress_parses_ok_fail():
    body = "OK=6|FAIL=0"
    with _mock_urlopen(body):
        r = sap_java_logctl.invoke_logctl("http://x:50000/irj/lc.jsp",
                                           "suppress")
    assert r["ok"] is True
    assert r["suppress_ok"] == 6
    assert r["suppress_fail"] == 0


def test_invoke_logctl_suppress_with_failures():
    body = "OK=4|FAIL=2|ERR:/System/Security/Audit/ACLs:ClassNotFound"
    with _mock_urlopen(body):
        r = sap_java_logctl.invoke_logctl("http://x:50000/irj/lc.jsp",
                                           "suppress")
    assert r["ok"] is False
    assert r["suppress_ok"] == 4
    assert r["suppress_fail"] == 2
    assert "ERR:" in r["error"]


def test_invoke_logctl_restore_parses_ok_fail():
    body = "OK=6|FAIL=0"
    with _mock_urlopen(body):
        r = sap_java_logctl.invoke_logctl("http://x:50000/irj/lc.jsp",
                                           "restore",
                                           baselines="/a=4|/b=6")
    assert r["ok"] is True
    assert r["suppress_ok"] == 6


def test_invoke_logctl_status_checks_ready_marker():
    with _mock_urlopen("LOGCTL_READY"):
        r = sap_java_logctl.invoke_logctl("http://x:50000/irj/lc.jsp",
                                           "status")
    assert r["ok"] is True


def test_invoke_logctl_status_fails_on_unexpected_body():
    with _mock_urlopen("500 Internal Server Error"):
        r = sap_java_logctl.invoke_logctl("http://x:50000/irj/lc.jsp",
                                           "status")
    assert r["ok"] is False


def test_invoke_logctl_http_error():
    import urllib.error
    err = urllib.error.HTTPError("http://x", 404, "Not Found", {}, None)
    with patch("sap_java_logctl.urllib.request.urlopen", side_effect=err):
        r = sap_java_logctl.invoke_logctl("http://x:50000/irj/lc.jsp",
                                           "read")
    assert r["ok"] is False
    assert "HTTP 404" in r["error"]


def test_invoke_logctl_connection_error():
    with patch("sap_java_logctl.urllib.request.urlopen",
               side_effect=ConnectionRefusedError("refused")):
        r = sap_java_logctl.invoke_logctl("http://x:50000/irj/lc.jsp",
                                           "read")
    assert r["ok"] is False
    assert r["error"]


def test_invoke_logctl_unknown_action():
    with _mock_urlopen("something"):
        r = sap_java_logctl.invoke_logctl("http://x:50000/irj/lc.jsp",
                                           "bogus")
    assert r["ok"] is False
    assert "unknown action" in r["error"]


# ---------------------------------------------------------------------------
# tier3_java_sal_suppress — gate + flow
# ---------------------------------------------------------------------------

def test_java_sal_suppress_refuses_non_java_node():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    node.system_type = "ABAP"
    out = sapmap_evasion_tier3.tier3_java_sal_suppress(state, node)
    assert out["ok"] is False
    assert "not a Java" in out["error"]


def test_java_sal_suppress_refuses_when_evasion_disarmed():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": False}
    node = SAPNode(sid="J75", hostname="j75", ip="10.0.0.2")
    node.system_type = "JAVA"
    out = sapmap_evasion_tier3.tier3_java_sal_suppress(state, node)
    assert out["ok"] is False


def test_java_sal_suppress_refuses_when_deploy_fails():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="J75", hostname="j75", ip="10.0.0.2")
    node.system_type = "JAVA"

    with patch("sap_java_logctl.deploy_logctl_jsp",
               return_value="") as mock_dep, \
         patch("sap_java_logctl.invoke_logctl") as mock_inv, \
         patch("sap_java_logctl.baselines_to_wire"):
        out = sapmap_evasion_tier3.tier3_java_sal_suppress(state, node)

    assert out["ok"] is False
    assert "deployment failed" in out["error"]
    mock_inv.assert_not_called()


def _baseline_read_response():
    return {
        "ok": True, "action": "read", "raw": "",
        "categories": {
            "/System/Security/Audit": 4,
            "/System/Security/Audit/ACLs": 6,
            "/System/Security/Audit/Configuration": 4,
            "/System/Security/Audit/PermissionCheck": 4,
            "/System/Security/Audit/PrincipalModification": 4,
            "/System/Security/Audit/UserMapping": 4,
        },
        "suppress_ok": 0, "suppress_fail": 0, "error": "",
    }


def _suppress_response():
    return {
        "ok": True, "action": "suppress", "raw": "OK=6|FAIL=0",
        "categories": {}, "suppress_ok": 6, "suppress_fail": 0,
        "error": "",
    }


def _restore_response():
    return {
        "ok": True, "action": "restore", "raw": "OK=6|FAIL=0",
        "categories": {}, "suppress_ok": 6, "suppress_fail": 0,
        "error": "",
    }


def test_java_sal_suppress_full_flow():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="J75", hostname="j75", ip="10.0.0.2")
    node.system_type = "JAVA"

    call_log = []

    def _mock_invoke(url, action, **kw):
        call_log.append(action)
        if action == "read":
            return _baseline_read_response()
        elif action == "suppress":
            return _suppress_response()
        elif action == "restore":
            return _restore_response()
        return {"ok": True, "action": action, "raw": "", "categories": {},
                "suppress_ok": 0, "suppress_fail": 0, "error": ""}

    with patch("sap_java_logctl.deploy_logctl_jsp",
               return_value="http://10.0.0.2:50000/irj/lc.jsp"), \
         patch("sap_java_logctl.invoke_logctl",
               side_effect=_mock_invoke), \
         patch("sap_java_logctl.baselines_to_wire",
               return_value="/System/Security/Audit=4|/System/Security/Audit/ACLs=6"):
        out = sapmap_evasion_tier3.tier3_java_sal_suppress(
            state, node, hold_seconds=0)

    assert out["ok"] is True
    assert out["technique"] == "java_nwa_severity"
    assert out["suppress_ok"] == 6
    assert out["suppress_fail"] == 0
    assert out["jsp_url"] == "http://10.0.0.2:50000/irj/lc.jsp"
    assert "/System/Security/Audit" in out["baseline"]
    # Flow: read (baseline) → suppress → read (verify) → restore → read (post-verify)
    assert call_log == ["read", "suppress", "read", "restore", "read"]


def test_java_sal_suppress_returns_error_on_baseline_read_failure():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="J75", hostname="j75", ip="10.0.0.2")
    node.system_type = "JAVA"

    fail_read = {"ok": False, "action": "read", "raw": "",
                 "categories": {}, "suppress_ok": 0, "suppress_fail": 0,
                 "error": "connection timeout"}

    with patch("sap_java_logctl.deploy_logctl_jsp",
               return_value="http://10.0.0.2:50000/irj/lc.jsp"), \
         patch("sap_java_logctl.invoke_logctl",
               return_value=fail_read), \
         patch("sap_java_logctl.baselines_to_wire"):
        out = sapmap_evasion_tier3.tier3_java_sal_suppress(
            state, node, hold_seconds=0)

    assert out["ok"] is False
    assert "baseline read failed" in out["error"]


def test_java_sal_suppress_returns_error_on_suppress_failure():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="J75", hostname="j75", ip="10.0.0.2")
    node.system_type = "JAVA"

    call_count = [0]

    def _mock_invoke(url, action, **kw):
        call_count[0] += 1
        if action == "read":
            return _baseline_read_response()
        if action == "suppress":
            return {"ok": False, "action": "suppress", "raw": "OK=0|FAIL=6",
                    "categories": {}, "suppress_ok": 0, "suppress_fail": 6,
                    "error": "all categories failed"}
        return {"ok": True, "action": action, "raw": "", "categories": {},
                "suppress_ok": 0, "suppress_fail": 0, "error": ""}

    with patch("sap_java_logctl.deploy_logctl_jsp",
               return_value="http://10.0.0.2:50000/irj/lc.jsp"), \
         patch("sap_java_logctl.invoke_logctl",
               side_effect=_mock_invoke), \
         patch("sap_java_logctl.baselines_to_wire"):
        out = sapmap_evasion_tier3.tier3_java_sal_suppress(
            state, node, hold_seconds=0)

    assert out["ok"] is False
    assert "suppress failed" in out["error"]


# ---------------------------------------------------------------------------
# DBTABLOG purge — sap_dbtablog_purge helpers
# ---------------------------------------------------------------------------

import sap_dbtablog_purge


def test_baseline_abap_emits_sy_datum_and_sy_uzeit():
    abap = sap_dbtablog_purge._build_baseline_abap()
    src = "\n".join(abap)
    assert "lv_d = sy-datum" in src
    assert "lv_t = sy-uzeit" in src
    assert "BASE_DATE|" in src
    assert "BASE_TIME|" in src


def test_purge_abap_uses_logdate_logtime_not_logid():
    abap = sap_dbtablog_purge._build_purge_abap("20260626", "100537")
    src = "\n".join(abap)
    # LOGID comparison was the V1 bug — must NOT appear anywhere.
    assert "logid" not in src.lower()
    # WHERE clause uses LOGDATE/LOGTIME comparison.
    assert "logdate > lv_d" in src
    assert "logdate = lv_d AND logtime > lv_t" in src


def test_purge_abap_scope_all_tables_omits_range():
    abap = sap_dbtablog_purge._build_purge_abap("20260626", "100537")
    src = "\n".join(abap)
    assert "DELETE FROM dbtablog WHERE" in src
    assert "RANGE OF" not in src
    assert "VALUE '20260626'" in src
    assert "VALUE '100537'" in src
    assert "DELETED|" in src
    assert "REMAINING|" in src


def test_purge_abap_scope_tabname_filter_emits_range():
    abap = sap_dbtablog_purge._build_purge_abap(
        "20260626", "100537", tabname_filter=["USR02", "USR04"])
    src = "\n".join(abap)
    assert "RANGE OF dbtablog-tabname" in src
    assert "ls_tab-low = 'USR02'" in src
    assert "ls_tab-low = 'USR04'" in src
    assert "AND tabname IN lr_tabs" in src


def test_purge_abap_uppercases_and_strips_tabnames():
    abap = sap_dbtablog_purge._build_purge_abap(
        "20260626", "100537", tabname_filter=["  usr02  ", "T000"])
    src = "\n".join(abap)
    assert "'USR02'" in src
    assert "'T000'" in src


def test_purge_abap_rejects_invalid_tabname():
    with pytest.raises(ValueError):
        sap_dbtablog_purge._build_purge_abap(
            "20260626", "100537",
            tabname_filter=["USR02; DROP TABLE x"])


def test_purge_abap_rejects_oversized_filter_list():
    with pytest.raises(ValueError):
        sap_dbtablog_purge._build_purge_abap(
            "20260626", "100537",
            tabname_filter=[f"T{i:03d}" for i in range(50)])


def test_purge_abap_rejects_malformed_base_date():
    with pytest.raises(ValueError):
        sap_dbtablog_purge._build_purge_abap("2026-06-26", "100537")


def test_purge_abap_rejects_malformed_base_time():
    with pytest.raises(ValueError):
        sap_dbtablog_purge._build_purge_abap("20260626", "10:05:37")


def test_parse_kv_line_finds_marker_with_gap():
    lines = ["BASE_DATE|        20260626"]
    assert sap_dbtablog_purge._parse_kv_line(lines, "BASE_DATE") == \
        "20260626"


def test_parse_kv_line_returns_none_when_missing():
    assert sap_dbtablog_purge._parse_kv_line(["other line"],
                                                "BASE_DATE") is None


def test_parse_kv_line_handles_empty_value():
    lines = ["BASE_DATE|"]
    assert sap_dbtablog_purge._parse_kv_line(lines, "BASE_DATE") == ""


# ---------------------------------------------------------------------------
# read_max_logid / purge_dbtablog — RFC wrapper helpers
# ---------------------------------------------------------------------------

def _patch_run_abap_program(side_effect):
    """Patch sapmap_rfc._run_abap_program AND the connection context."""
    import sapmap_rfc
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=MagicMock())
    cm.__exit__ = MagicMock(return_value=False)
    return (patch.object(sapmap_rfc, "_get_connection", return_value=cm),
            patch.object(sapmap_rfc, "_run_abap_program",
                         side_effect=side_effect))


def test_read_baseline_timestamp_parses_lab_values():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    def _run(conn, abap, name):
        return {"success": True,
                "output": ["BASE_DATE|        20260626",
                           "BASE_TIME|        100537"],
                "fm_name": "RFC_ABAP_INSTALL_AND_RUN", "error": ""}
    cm_patch, run_patch = _patch_run_abap_program(_run)
    with cm_patch, run_patch:
        r = sap_dbtablog_purge.read_baseline_timestamp(node)
    assert r["ok"] is True
    assert r["base_date"] == "20260626"
    assert r["base_time"] == "100537"


def test_read_baseline_timestamp_rejects_malformed_date():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    def _run(conn, abap, name):
        return {"success": True,
                "output": ["BASE_DATE|        26.06.2026",
                           "BASE_TIME|        100537"],
                "fm_name": "RFC_ABAP_INSTALL_AND_RUN", "error": ""}
    cm_patch, run_patch = _patch_run_abap_program(_run)
    with cm_patch, run_patch:
        r = sap_dbtablog_purge.read_baseline_timestamp(node)
    assert r["ok"] is False
    assert "BASE_DATE" in r["error"]


def test_read_baseline_timestamp_surfaces_program_failure():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    def _run(conn, abap, name):
        return {"success": False, "output": [],
                "fm_name": "RFC_ABAP_INSTALL_AND_RUN",
                "error": "SYNTAX_ERROR_IN_PROGRAM"}
    cm_patch, run_patch = _patch_run_abap_program(_run)
    with cm_patch, run_patch:
        r = sap_dbtablog_purge.read_baseline_timestamp(node)
    assert r["ok"] is False
    assert "SYNTAX_ERROR" in r["error"]


def test_purge_dbtablog_parses_counts():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    def _run(conn, abap, name):
        return {"success": True,
                "output": ["DELETED|        42", "REMAINING|         0"],
                "fm_name": "RFC_ABAP_INSTALL_AND_RUN", "error": ""}
    cm_patch, run_patch = _patch_run_abap_program(_run)
    with cm_patch, run_patch:
        r = sap_dbtablog_purge.purge_dbtablog(node, "20260626", "100537")
    assert r["ok"] is True
    assert r["deleted_count"] == 42
    assert r["remaining_count"] == 0


def test_purge_dbtablog_flags_incomplete_delete():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    def _run(conn, abap, name):
        return {"success": True,
                "output": ["DELETED|         0", "REMAINING|         7"],
                "fm_name": "RFC_ABAP_INSTALL_AND_RUN", "error": ""}
    cm_patch, run_patch = _patch_run_abap_program(_run)
    with cm_patch, run_patch:
        r = sap_dbtablog_purge.purge_dbtablog(node, "20260626", "100537")
    assert r["ok"] is False
    assert "incomplete" in r["error"]
    assert r["remaining_count"] == 7


def test_purge_dbtablog_rejects_bad_filter_before_rfc():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    # Bad filter should fail at ABAP-build time without touching RFC.
    cm_patch, run_patch = _patch_run_abap_program(
        lambda *a, **kw: pytest.fail("RFC should not have been called"))
    with cm_patch, run_patch:
        r = sap_dbtablog_purge.purge_dbtablog(
            node, "20260626", "100537", tabname_filter=["BAD; DROP"])
    assert r["ok"] is False
    assert "invalid tabname" in r["error"]


# ---------------------------------------------------------------------------
# tier3_dbtablog_purge — gate + flow
# ---------------------------------------------------------------------------

def test_dbtablog_purge_refuses_non_abap_node():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="J75", hostname="j75", ip="10.0.0.2")
    node.system_type = "JAVA"
    out = sapmap_evasion_tier3.tier3_dbtablog_purge(state, node)
    assert out["ok"] is False
    assert "not an ABAP" in out["error"]


def test_dbtablog_purge_refuses_when_evasion_disarmed():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": False}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    node.system_type = "ABAP"
    out = sapmap_evasion_tier3.tier3_dbtablog_purge(state, node)
    assert out["ok"] is False


def test_dbtablog_purge_full_flow():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    node.system_type = "ABAP"

    base_resp = {"ok": True, "base_date": "20260626",
                 "base_time": "100537", "raw": [], "error": ""}
    purge_resp = {"ok": True, "deleted_count": 12, "remaining_count": 0,
                  "raw": [], "error": ""}

    with patch("sap_dbtablog_purge.read_baseline_timestamp",
               return_value=base_resp) as mock_read, \
         patch("sap_dbtablog_purge.purge_dbtablog",
               return_value=purge_resp) as mock_purge:
        out = sapmap_evasion_tier3.tier3_dbtablog_purge(
            state, node, hold_seconds=0)

    assert out["ok"] is True
    assert out["technique"] == "dbtablog_purge"
    assert out["base_date"] == "20260626"
    assert out["base_time"] == "100537"
    assert out["deleted_count"] == 12
    assert out["remaining_count"] == 0
    assert out["tabname_filter"] == []
    mock_read.assert_called_once()
    mock_purge.assert_called_once()


def test_dbtablog_purge_passes_tabname_filter_through():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    node.system_type = "ABAP"

    base_resp = {"ok": True, "base_date": "20260626",
                 "base_time": "100537", "raw": [], "error": ""}
    purge_resp = {"ok": True, "deleted_count": 3, "remaining_count": 0,
                  "raw": [], "error": ""}

    with patch("sap_dbtablog_purge.read_baseline_timestamp",
               return_value=base_resp), \
         patch("sap_dbtablog_purge.purge_dbtablog",
               return_value=purge_resp) as mock_purge:
        out = sapmap_evasion_tier3.tier3_dbtablog_purge(
            state, node, hold_seconds=0,
            tabname_filter=["USR02", "USR04"])

    assert out["ok"] is True
    assert out["tabname_filter"] == ["USR02", "USR04"]
    _args, kwargs = mock_purge.call_args
    assert kwargs.get("tabname_filter") == ["USR02", "USR04"]


def test_dbtablog_purge_returns_error_on_baseline_failure():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    node.system_type = "ABAP"

    fail_resp = {"ok": False, "base_date": "", "base_time": "",
                 "raw": [], "error": "NO_AUTH"}
    with patch("sap_dbtablog_purge.read_baseline_timestamp",
               return_value=fail_resp), \
         patch("sap_dbtablog_purge.purge_dbtablog") as mock_purge:
        out = sapmap_evasion_tier3.tier3_dbtablog_purge(
            state, node, hold_seconds=0)

    assert out["ok"] is False
    assert "baseline read failed" in out["error"]
    mock_purge.assert_not_called()


def test_dbtablog_purge_returns_error_on_purge_failure():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    node.system_type = "ABAP"

    base_resp = {"ok": True, "base_date": "20260626",
                 "base_time": "100537", "raw": [], "error": ""}
    fail_purge = {"ok": False, "deleted_count": 0, "remaining_count": -1,
                  "raw": [], "error": "DELETE blocked by S_TABU_DIS"}

    with patch("sap_dbtablog_purge.read_baseline_timestamp",
               return_value=base_resp), \
         patch("sap_dbtablog_purge.purge_dbtablog",
               return_value=fail_purge):
        out = sapmap_evasion_tier3.tier3_dbtablog_purge(
            state, node, hold_seconds=0)

    assert out["ok"] is False
    assert "purge failed" in out["error"]
    assert out.get("base_date") == "20260626"
    assert out.get("base_time") == "100537"


# ---------------------------------------------------------------------------
# GW SAPXPG → hdbsql delivery (HANA-only primary path)
# ---------------------------------------------------------------------------

def test_build_hana_delete_sql_all_tables():
    sql = sap_dbtablog_purge._build_hana_delete_sql(
        "20260626", "102632")
    assert sql.startswith("DELETE FROM SAPHANADB.DBTABLOG WHERE ")
    assert "LOGDATE > '20260626'" in sql
    assert "LOGDATE = '20260626' AND LOGTIME > '102632'" in sql
    assert "TABNAME IN" not in sql


def test_build_hana_delete_sql_with_tabname_filter():
    sql = sap_dbtablog_purge._build_hana_delete_sql(
        "20260626", "102632", tabname_filter=["RFCDES", "USR02"])
    assert "TABNAME IN ('RFCDES', 'USR02')" in sql


def test_build_hana_delete_sql_uppercases_tabnames():
    sql = sap_dbtablog_purge._build_hana_delete_sql(
        "20260626", "102632", tabname_filter=["  rfcdes  "])
    assert "'RFCDES'" in sql
    assert "rfcdes" not in sql


def test_build_hana_delete_sql_custom_schema():
    sql = sap_dbtablog_purge._build_hana_delete_sql(
        "20260626", "102632", schema="SAPSR3")
    assert "DELETE FROM SAPSR3.DBTABLOG" in sql


def test_build_hana_delete_sql_rejects_bad_schema():
    with pytest.raises(ValueError):
        sap_dbtablog_purge._build_hana_delete_sql(
            "20260626", "102632", schema="bad; DROP")


def test_build_hana_delete_sql_rejects_bad_date():
    with pytest.raises(ValueError):
        sap_dbtablog_purge._build_hana_delete_sql("26.06.2026", "102632")


def test_build_hana_delete_sql_rejects_bad_tabname():
    with pytest.raises(ValueError):
        sap_dbtablog_purge._build_hana_delete_sql(
            "20260626", "102632", tabname_filter=["RFC'DES"])


def test_purge_via_gw_refuses_non_hana_node():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    node.db_type = "ORA"
    node.gw_vulnerable = True
    node.gw_vulnerable_port = 3300
    r = sap_dbtablog_purge.purge_dbtablog_via_gw_hdbsql(
        node, "20260626", "102632")
    assert r["ok"] is False
    assert "HANA-only" in r["error"]


def test_purge_via_gw_refuses_when_not_gw_vulnerable():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    node.db_type = "HDB"
    node.gw_vulnerable = False
    r = sap_dbtablog_purge.purge_dbtablog_via_gw_hdbsql(
        node, "20260626", "102632")
    assert r["ok"] is False
    assert "not GW-vulnerable" in r["error"]


def _import_writers_safely():
    """sap_db_sql_writers has a circular dep with sapmap_exploit that
    only resolves cleanly when sapmap_exploit is loaded first (because
    it defines ``_gw_connect`` before its own import of the writer).
    Encapsulate the dance once so each test stays readable."""
    import sapmap_exploit  # noqa: F401  — primes the chain
    import sap_db_sql_writers as _w
    return _w


def test_purge_via_gw_calls_execute_sql_via_gateway():
    sap_db_sql_writers = _import_writers_safely()
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    node.db_type = "HDB"
    node.gw_vulnerable = True
    node.gw_vulnerable_port = 3300
    node.os_type = "LINUX"

    seen = {}

    def _fake_exec(host, gw_port, sid, hostname, sqls, db_type,
                    os_type, saprouter=""):
        seen["host"] = host
        seen["gw_port"] = gw_port
        seen["sqls"] = sqls
        seen["db_type"] = db_type
        return True

    with patch.object(sap_db_sql_writers, "_execute_sql_via_gateway",
                       side_effect=_fake_exec):
        r = sap_dbtablog_purge.purge_dbtablog_via_gw_hdbsql(
            node, "20260626", "102632", tabname_filter=["RFCDES"])

    assert r["ok"] is True
    assert r["via"] == "gw_hdbsql"
    assert r["deleted_count"] == -1
    assert seen["gw_port"] == 3300
    assert seen["db_type"] == "HDB"
    assert len(seen["sqls"]) == 1
    assert "RFCDES" in seen["sqls"][0]
    assert "20260626" in seen["sqls"][0]


def test_purge_via_gw_surfaces_gw_failure():
    sap_db_sql_writers = _import_writers_safely()
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    node.db_type = "HDB"
    node.gw_vulnerable = True
    node.gw_vulnerable_port = 3300

    with patch.object(sap_db_sql_writers, "_execute_sql_via_gateway",
                       return_value=False):
        r = sap_dbtablog_purge.purge_dbtablog_via_gw_hdbsql(
            node, "20260626", "102632")
    assert r["ok"] is False
    assert "reported failure" in r["error"]


# ---------------------------------------------------------------------------
# Dispatcher in tier3_dbtablog_purge: GW first on HANA+gw_vuln, RFC fallback
# ---------------------------------------------------------------------------

def test_dbtablog_purge_dispatches_gw_first_on_hana_gw_vuln():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    node.system_type = "ABAP"
    node.db_type = "HDB"
    node.gw_vulnerable = True
    node.gw_vulnerable_port = 3300

    base_resp = {"ok": True, "base_date": "20260626",
                 "base_time": "102632", "raw": [], "error": ""}
    gw_resp = {"ok": True, "deleted_count": -1, "remaining_count": -1,
               "raw": [], "error": "", "via": "gw_hdbsql"}
    verify_ok = {"ok": True, "count": 0, "raw": [], "error": ""}

    with patch("sap_dbtablog_purge.read_baseline_timestamp",
                return_value=base_resp), \
         patch("sap_dbtablog_purge.purge_dbtablog_via_gw_hdbsql",
                return_value=gw_resp) as mock_gw, \
         patch("sap_dbtablog_purge.count_dbtablog_since",
                return_value=verify_ok), \
         patch("sap_dbtablog_purge.purge_dbtablog") as mock_rfc:
        out = sapmap_evasion_tier3.tier3_dbtablog_purge(
            state, node, hold_seconds=0)

    assert out["ok"] is True
    assert out["via"] == "gw_hdbsql"
    mock_gw.assert_called_once()
    mock_rfc.assert_not_called()


def test_dbtablog_purge_falls_back_to_rfc_when_gw_fails():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    node.system_type = "ABAP"
    node.db_type = "HDB"
    node.gw_vulnerable = True
    node.gw_vulnerable_port = 3300

    base_resp = {"ok": True, "base_date": "20260626",
                 "base_time": "102632", "raw": [], "error": ""}
    gw_fail = {"ok": False, "deleted_count": -1, "remaining_count": -1,
               "raw": [], "error": "GW SAPXPG hdbsql DELETE reported failure",
               "via": "gw_hdbsql"}
    rfc_ok = {"ok": True, "deleted_count": 4, "remaining_count": 0,
              "raw": [], "error": "", "via": "rfc_install_and_run"}

    with patch("sap_dbtablog_purge.read_baseline_timestamp",
                return_value=base_resp), \
         patch("sap_dbtablog_purge.purge_dbtablog_via_gw_hdbsql",
                return_value=gw_fail) as mock_gw, \
         patch("sap_dbtablog_purge.purge_dbtablog",
                return_value=rfc_ok) as mock_rfc:
        out = sapmap_evasion_tier3.tier3_dbtablog_purge(
            state, node, hold_seconds=0)

    assert out["ok"] is True
    assert out["via"] == "rfc_install_and_run"
    assert out["deleted_count"] == 4
    mock_gw.assert_called_once()
    mock_rfc.assert_called_once()


def test_dbtablog_purge_skips_gw_when_not_hana():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    node.system_type = "ABAP"
    node.db_type = "ORA"
    node.gw_vulnerable = True
    node.gw_vulnerable_port = 3300

    base_resp = {"ok": True, "base_date": "20260626",
                 "base_time": "102632", "raw": [], "error": ""}
    rfc_ok = {"ok": True, "deleted_count": 2, "remaining_count": 0,
              "raw": [], "error": "", "via": "rfc_install_and_run"}

    with patch("sap_dbtablog_purge.read_baseline_timestamp",
                return_value=base_resp), \
         patch("sap_dbtablog_purge.purge_dbtablog_via_gw_hdbsql") as mock_gw, \
         patch("sap_dbtablog_purge.purge_dbtablog",
                return_value=rfc_ok) as mock_rfc:
        out = sapmap_evasion_tier3.tier3_dbtablog_purge(
            state, node, hold_seconds=0)

    assert out["ok"] is True
    assert out["via"] == "rfc_install_and_run"
    mock_gw.assert_not_called()
    mock_rfc.assert_called_once()


def test_dbtablog_purge_skips_gw_when_not_gw_vulnerable():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    node.system_type = "ABAP"
    node.db_type = "HDB"
    node.gw_vulnerable = False

    base_resp = {"ok": True, "base_date": "20260626",
                 "base_time": "102632", "raw": [], "error": ""}
    rfc_ok = {"ok": True, "deleted_count": 1, "remaining_count": 0,
              "raw": [], "error": "", "via": "rfc_install_and_run"}

    with patch("sap_dbtablog_purge.read_baseline_timestamp",
                return_value=base_resp), \
         patch("sap_dbtablog_purge.purge_dbtablog_via_gw_hdbsql") as mock_gw, \
         patch("sap_dbtablog_purge.purge_dbtablog",
                return_value=rfc_ok):
        out = sapmap_evasion_tier3.tier3_dbtablog_purge(
            state, node, hold_seconds=0)

    assert out["ok"] is True
    assert out["via"] == "rfc_install_and_run"
    mock_gw.assert_not_called()


# ---------------------------------------------------------------------------
# count_dbtablog_since — RFC verifier used after GW DELETE
# ---------------------------------------------------------------------------

def test_count_abap_uses_same_where_shape_as_purge():
    abap = sap_dbtablog_purge._build_count_abap("20260626", "102632")
    src = "\n".join(abap)
    assert "SELECT COUNT(*) FROM dbtablog INTO lv_c" in src
    assert "logdate > lv_d" in src
    assert "logdate = lv_d AND logtime > lv_t" in src
    assert "COUNT|" in src


def test_count_abap_with_tabname_filter():
    abap = sap_dbtablog_purge._build_count_abap(
        "20260626", "102632", tabname_filter=["RFCDES"])
    src = "\n".join(abap)
    assert "RANGE OF dbtablog-tabname" in src
    assert "ls_tab-low = 'RFCDES'" in src
    assert "AND tabname IN lr_tabs" in src


def test_count_abap_rejects_bad_inputs():
    with pytest.raises(ValueError):
        sap_dbtablog_purge._build_count_abap("bad", "102632")
    with pytest.raises(ValueError):
        sap_dbtablog_purge._build_count_abap("20260626", "bad")
    with pytest.raises(ValueError):
        sap_dbtablog_purge._build_count_abap(
            "20260626", "102632", tabname_filter=["X; DROP"])


def test_count_dbtablog_since_parses_zero():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    def _run(conn, abap, name):
        return {"success": True, "output": ["COUNT|         0"],
                "fm_name": "RFC_ABAP_INSTALL_AND_RUN", "error": ""}
    cm_patch, run_patch = _patch_run_abap_program(_run)
    with cm_patch, run_patch:
        r = sap_dbtablog_purge.count_dbtablog_since(
            node, "20260626", "102632")
    assert r["ok"] is True
    assert r["count"] == 0


def test_count_dbtablog_since_parses_nonzero():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    def _run(conn, abap, name):
        return {"success": True, "output": ["COUNT|         4"],
                "fm_name": "RFC_ABAP_INSTALL_AND_RUN", "error": ""}
    cm_patch, run_patch = _patch_run_abap_program(_run)
    with cm_patch, run_patch:
        r = sap_dbtablog_purge.count_dbtablog_since(
            node, "20260626", "102632")
    assert r["ok"] is True
    assert r["count"] == 4


def test_count_dbtablog_since_surfaces_program_failure():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    def _run(conn, abap, name):
        return {"success": False, "output": [],
                "fm_name": "RFC_ABAP_INSTALL_AND_RUN",
                "error": "NO_AUTH"}
    cm_patch, run_patch = _patch_run_abap_program(_run)
    with cm_patch, run_patch:
        r = sap_dbtablog_purge.count_dbtablog_since(
            node, "20260626", "102632")
    assert r["ok"] is False
    assert "NO_AUTH" in r["error"]


# ---------------------------------------------------------------------------
# Verify-after-GW: trust GW only when RFC count confirms 0 remaining
# ---------------------------------------------------------------------------

def _hana_gw_node():
    n = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    n.system_type = "ABAP"
    n.db_type = "HDB"
    n.gw_vulnerable = True
    n.gw_vulnerable_port = 3300
    return n


def test_dbtablog_purge_gw_success_verified_zero_skips_rfc():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = _hana_gw_node()

    base_resp = {"ok": True, "base_date": "20260626",
                 "base_time": "102632", "raw": [], "error": ""}
    gw_ok = {"ok": True, "deleted_count": -1, "remaining_count": -1,
             "raw": [], "error": "", "via": "gw_hdbsql"}
    verify_ok = {"ok": True, "count": 0, "raw": [], "error": ""}

    with patch("sap_dbtablog_purge.read_baseline_timestamp",
                return_value=base_resp), \
         patch("sap_dbtablog_purge.purge_dbtablog_via_gw_hdbsql",
                return_value=gw_ok) as mock_gw, \
         patch("sap_dbtablog_purge.count_dbtablog_since",
                return_value=verify_ok) as mock_verify, \
         patch("sap_dbtablog_purge.purge_dbtablog") as mock_rfc:
        out = sapmap_evasion_tier3.tier3_dbtablog_purge(
            state, node, hold_seconds=0)

    assert out["ok"] is True
    assert out["via"] == "gw_hdbsql"
    assert out["remaining_count"] == 0
    mock_gw.assert_called_once()
    mock_verify.assert_called_once()
    mock_rfc.assert_not_called()


def test_dbtablog_purge_gw_success_verified_nonzero_falls_back_to_rfc():
    """The S4H lab case: GW reports success but rows still present."""
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = _hana_gw_node()

    base_resp = {"ok": True, "base_date": "20260626",
                 "base_time": "121346", "raw": [], "error": ""}
    gw_ok = {"ok": True, "deleted_count": -1, "remaining_count": -1,
             "raw": [], "error": "", "via": "gw_hdbsql"}
    verify_nonzero = {"ok": True, "count": 4, "raw": [], "error": ""}
    rfc_ok = {"ok": True, "deleted_count": 4, "remaining_count": 0,
              "raw": [], "error": "", "via": "rfc_install_and_run"}

    with patch("sap_dbtablog_purge.read_baseline_timestamp",
                return_value=base_resp), \
         patch("sap_dbtablog_purge.purge_dbtablog_via_gw_hdbsql",
                return_value=gw_ok) as mock_gw, \
         patch("sap_dbtablog_purge.count_dbtablog_since",
                return_value=verify_nonzero) as mock_verify, \
         patch("sap_dbtablog_purge.purge_dbtablog",
                return_value=rfc_ok) as mock_rfc:
        out = sapmap_evasion_tier3.tier3_dbtablog_purge(
            state, node, hold_seconds=0, tabname_filter=["RFCDES"])

    assert out["ok"] is True
    assert out["via"] == "rfc_install_and_run"
    assert out["deleted_count"] == 4
    mock_gw.assert_called_once()
    mock_verify.assert_called_once()
    mock_rfc.assert_called_once()


def test_dbtablog_purge_falls_back_to_rfc_when_verify_errors():
    state = SAPMAPState()
    state.evasion = {"allow_evasion": True}
    node = _hana_gw_node()

    base_resp = {"ok": True, "base_date": "20260626",
                 "base_time": "121346", "raw": [], "error": ""}
    gw_ok = {"ok": True, "deleted_count": -1, "remaining_count": -1,
             "raw": [], "error": "", "via": "gw_hdbsql"}
    verify_err = {"ok": False, "count": -1, "raw": [],
                  "error": "RFC down"}
    rfc_ok = {"ok": True, "deleted_count": 2, "remaining_count": 0,
              "raw": [], "error": "", "via": "rfc_install_and_run"}

    with patch("sap_dbtablog_purge.read_baseline_timestamp",
                return_value=base_resp), \
         patch("sap_dbtablog_purge.purge_dbtablog_via_gw_hdbsql",
                return_value=gw_ok), \
         patch("sap_dbtablog_purge.count_dbtablog_since",
                return_value=verify_err), \
         patch("sap_dbtablog_purge.purge_dbtablog",
                return_value=rfc_ok) as mock_rfc:
        out = sapmap_evasion_tier3.tier3_dbtablog_purge(
            state, node, hold_seconds=0)

    assert out["ok"] is True
    assert out["via"] == "rfc_install_and_run"
    mock_rfc.assert_called_once()
