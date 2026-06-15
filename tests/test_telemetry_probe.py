"""Unit tests for the ABAP telemetry probe (Tier 1 OPSEC enrichment)."""

from unittest.mock import patch, MagicMock

import pytest

from sapmap_models import AbapTelemetryProfile, Credentials, SAPNode
import sapmap_telemetry


# ---------------------------------------------------------------------------
# Dataclass round-trip
# ---------------------------------------------------------------------------

def test_profile_to_dict_from_dict_roundtrip():
    p = AbapTelemetryProfile(
        sal_state="on",
        sal_filter_slots=4,
        sal_filter_scope="narrow",
        sal_integrity="on",
        sal_source_ip_only="off",
        rec_client="OFF",
        stat_level="1",
        gw_log_level="2",
        rdisp_trace="1",
        raw_params={"rsau/integrity": "1", "rsau/ip_only": "0"},
    )
    d = p.to_dict()
    p2 = AbapTelemetryProfile.from_dict(d)
    assert p2.to_dict() == d


def test_profile_default_state_is_unknown():
    p = AbapTelemetryProfile()
    assert p.sal_state == "unknown"
    assert p.sal_integrity == "unknown"
    assert p.sal_filter_slots == 0
    assert p.error == ""


def test_node_serialises_with_telemetry_profile():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    node.telemetry_profile = AbapTelemetryProfile(
        sal_state="on", sal_filter_slots=2, sal_filter_scope="narrow")
    d = node.to_dict()
    assert d["telemetry_profile"]["sal_state"] == "on"
    node2 = SAPNode.from_dict(d)
    assert node2.telemetry_profile is not None
    assert node2.telemetry_profile.sal_state == "on"
    assert node2.telemetry_profile.sal_filter_slots == 2


def test_node_serialises_without_telemetry_profile():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    d = node.to_dict()
    assert d["telemetry_profile"] is None
    node2 = SAPNode.from_dict(d)
    assert node2.telemetry_profile is None


# ---------------------------------------------------------------------------
# Param-value normalisers
# ---------------------------------------------------------------------------

def test_bool_param_returns_on_off_for_known_values():
    raw = {"rsau/integrity": "1", "rsau/ip_only": "0"}
    assert sapmap_telemetry._bool_param(raw, "rsau/integrity") == "on"
    assert sapmap_telemetry._bool_param(raw, "rsau/ip_only") == "off"


def test_bool_param_unset_falls_back_to_default():
    # rsau/integrity defaults to "1" (on) on recent kernels
    val = sapmap_telemetry._bool_param({}, "rsau/integrity")
    assert val == "on (default)"


def test_bool_param_unknown_value_preserved_for_inspection():
    raw = {"rsau/integrity": "weird"}
    val = sapmap_telemetry._bool_param(raw, "rsau/integrity")
    assert "weird" in val
    assert val.startswith("unknown")


def test_str_param_returns_raw_or_default_marker():
    raw = {"stat/level": "3"}
    assert sapmap_telemetry._str_param(raw, "stat/level") == "3"
    assert sapmap_telemetry._str_param({}, "stat/level") == "1 (default)"


# ---------------------------------------------------------------------------
# read_abap_telemetry — mocked RFC paths
# ---------------------------------------------------------------------------

def _make_rfc_table_response(rows):
    return {"DATA": [{"WA": wa} for wa in rows]}


def _build_mock_conn(handlers):
    """handlers: list of (matcher_fn, response_dict).

    Each ``conn.call(...)`` invocation walks the list, returns the first
    response whose matcher returns True for the kwargs.  Falling off the
    end raises so tests catch unexpected calls.
    """
    conn = MagicMock()

    def _call(fm_name, **kwargs):
        for matcher, response in handlers:
            if matcher(fm_name, kwargs):
                if isinstance(response, Exception):
                    raise response
                return response
        raise AssertionError(
            f"Unexpected RFC call: {fm_name}({kwargs!r})")

    conn.call.side_effect = _call
    return conn


def _patch_get_connection(conn):
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=conn)
    cm.__exit__ = MagicMock(return_value=False)
    return patch.object(sapmap_telemetry.sapmap_rfc,
                        "_get_connection", return_value=cm)


def test_read_abap_telemetry_full_path_on_modern_kernel():
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    creds = Credentials(username="SAPMAP00", password="x",
                        client="001", instance_nr="00")

    def match_param_batch(fm, kw):
        return (fm == "RFC_READ_TABLE"
                and kw.get("QUERY_TABLE") == "TPFYPROPTY"
                and "rsau/integrity" in (kw.get("OPTIONS") or [{}])[0]
                                                .get("TEXT", ""))

    def match_rsau_enable(fm, kw):
        return (fm == "RFC_READ_TABLE"
                and kw.get("QUERY_TABLE") == "TPFYPROPTY"
                and "rsau/enable" in (kw.get("OPTIONS") or [{}])[0]
                                              .get("TEXT", ""))

    def match_rsau_pers(fm, kw):
        return (fm == "RFC_READ_TABLE"
                and kw.get("QUERY_TABLE") == "RSAU_PERS")

    handlers = [
        (match_param_batch, _make_rfc_table_response([
            "rsau/integrity|1",
            "rsau/ip_only|0",      # ← spoofable
            "rec/client|ALL",
            "stat/level|1",
            "gw/log_level|2",
            "rdisp/TRACE|1",
        ])),
        (match_rsau_enable, _make_rfc_table_response(["1"])),
        (match_rsau_pers, _make_rfc_table_response([
            "BCUSER|001", "SAP*|001", "*|*",   # third row = broad slot
        ])),
    ]
    conn = _build_mock_conn(handlers)
    with _patch_get_connection(conn):
        p = sapmap_telemetry.read_abap_telemetry(node, creds)

    assert p.error == ""
    assert p.sal_state == "on"
    assert p.sal_filter_slots == 3
    assert p.sal_filter_scope == "broad"  # the *|* row trips broad
    assert p.sal_integrity == "on"
    assert p.sal_source_ip_only == "off"
    assert p.rec_client == "ALL"
    assert p.stat_level == "1"


def test_read_abap_telemetry_falls_back_to_rsauprof_on_older_kernel():
    node = SAPNode(sid="OLD", hostname="old", ip="10.0.0.2")

    def match_param(fm, kw):
        return (fm == "RFC_READ_TABLE"
                and kw.get("QUERY_TABLE") == "TPFYPROPTY"
                and "rsau/integrity" in (kw.get("OPTIONS") or [{}])[0]
                                                .get("TEXT", ""))

    def match_rsau_enable(fm, kw):
        return (fm == "RFC_READ_TABLE"
                and kw.get("QUERY_TABLE") == "TPFYPROPTY"
                and "rsau/enable" in (kw.get("OPTIONS") or [{}])[0]
                                              .get("TEXT", ""))

    def match_rsau_pers(fm, kw):
        return (fm == "RFC_READ_TABLE"
                and kw.get("QUERY_TABLE") == "RSAU_PERS")

    def match_rsauprof(fm, kw):
        return (fm == "RFC_READ_TABLE"
                and kw.get("QUERY_TABLE") == "RSAUPROF")

    handlers = [
        (match_param, _make_rfc_table_response(["rsau/integrity|1"])),
        (match_rsau_enable, _make_rfc_table_response(["1"])),
        (match_rsau_pers, Exception("TABLE_NOT_AVAILABLE")),
        (match_rsauprof, _make_rfc_table_response(["BCUSER|000"])),
    ]
    conn = _build_mock_conn(handlers)
    with _patch_get_connection(conn):
        p = sapmap_telemetry.read_abap_telemetry(node, creds=None)

    assert p.sal_state == "on"
    assert p.sal_filter_slots == 1
    assert p.sal_filter_scope == "narrow"


def test_read_abap_telemetry_no_sal_slots_marked_unknown_legacy():
    node = SAPNode(sid="X", hostname="x", ip="10.0.0.3")

    def match_param(fm, kw):
        return (fm == "RFC_READ_TABLE"
                and kw.get("QUERY_TABLE") == "TPFYPROPTY"
                and "rsau/integrity" in (kw.get("OPTIONS") or [{}])[0]
                                                .get("TEXT", ""))

    def match_rsau_enable(fm, kw):
        return (fm == "RFC_READ_TABLE"
                and kw.get("QUERY_TABLE") == "TPFYPROPTY"
                and "rsau/enable" in (kw.get("OPTIONS") or [{}])[0]
                                              .get("TEXT", ""))

    def match_either_table(fm, kw):
        return (fm == "RFC_READ_TABLE"
                and kw.get("QUERY_TABLE") in ("RSAU_PERS", "RSAUPROF"))

    handlers = [
        (match_param, _make_rfc_table_response([])),
        # rsau/enable also missing → "off (default)" branch
        (match_rsau_enable, _make_rfc_table_response([])),
        (match_either_table, _make_rfc_table_response([])),
        (match_either_table, _make_rfc_table_response([])),
    ]
    conn = _build_mock_conn(handlers)
    with _patch_get_connection(conn):
        p = sapmap_telemetry.read_abap_telemetry(node, creds=None)

    assert p.sal_filter_slots == 0
    assert p.sal_filter_scope == ""
    # off (default) is preserved — we don't downgrade a known-default
    # state to "unknown_legacy" when rsau/enable was actually probed
    assert p.sal_state == "off (default)"


def test_read_abap_telemetry_records_error_when_first_call_raises():
    node = SAPNode(sid="X", hostname="x", ip="10.0.0.4")

    def always_raise(fm, kw):
        return fm == "RFC_READ_TABLE"

    conn = _build_mock_conn([
        (always_raise, Exception("RFC_LOGON_FAILURE")),
    ])
    with _patch_get_connection(conn):
        p = sapmap_telemetry.read_abap_telemetry(node, creds=None)

    assert "TPFYPROPTY read failed" in p.error
    assert p.sal_state == "unknown"
