"""Tests for Tier 2 T2.1 — DIAG terminal-name spoof."""

import struct

from sapmap_models import (AbapTelemetryProfile, SAPMAPState, SAPNode)
import sapmap_evasion
from sapmap_evasion import (DEFAULT_DIAG_TERMINAL, DEFAULT_SPOOF_TERMINAL,
                             EvasionConfig, effective_diag_terminal)

import sap_client_enum


# ---------------------------------------------------------------------------
# EvasionConfig round-trip
# ---------------------------------------------------------------------------

def test_evasion_config_roundtrip_preserves_override():
    cfg = EvasionConfig(diag_terminal_name="FINOPS-WS-22")
    d = cfg.to_dict()
    cfg2 = EvasionConfig.from_dict(d)
    assert cfg2.diag_terminal_name == "FINOPS-WS-22"
    assert cfg2.updated_at == cfg.updated_at


def test_evasion_config_default_is_empty():
    cfg = EvasionConfig()
    assert cfg.diag_terminal_name == ""
    assert cfg.updated_at


def test_state_serialises_evasion_dict():
    s = SAPMAPState()
    s.evasion = {"diag_terminal_name": "WS-99"}
    d = s.to_dict()
    assert d["evasion"] == {"diag_terminal_name": "WS-99"}
    s2 = SAPMAPState.from_dict(d)
    assert s2.evasion == {"diag_terminal_name": "WS-99"}


# ---------------------------------------------------------------------------
# effective_diag_terminal — gating logic
# ---------------------------------------------------------------------------

def _node_with_ip_only(value):
    node = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    node.telemetry_profile = AbapTelemetryProfile(sal_source_ip_only=value)
    return node


def test_returns_default_terminal_when_ip_only_is_on():
    node = _node_with_ip_only("on")
    term, spoof = effective_diag_terminal(node, EvasionConfig())
    assert term == DEFAULT_DIAG_TERMINAL
    assert spoof is False


def test_returns_default_terminal_when_ip_only_unknown():
    node = SAPNode(sid="X", hostname="x", ip="10.0.0.2")
    term, spoof = effective_diag_terminal(node, EvasionConfig())
    assert term == DEFAULT_DIAG_TERMINAL
    assert spoof is False


def test_returns_spoof_terminal_when_ip_only_off():
    node = _node_with_ip_only("off")
    term, spoof = effective_diag_terminal(node, EvasionConfig())
    assert term == DEFAULT_SPOOF_TERMINAL
    assert spoof is True


def test_returns_spoof_terminal_when_ip_only_off_default():
    """The probe encodes 'off (default)' for unset rsau/ip_only —
    treated identically to 'off'."""
    node = _node_with_ip_only("off (default)")
    term, spoof = effective_diag_terminal(node, EvasionConfig())
    assert term == DEFAULT_SPOOF_TERMINAL
    assert spoof is True


def test_operator_override_used_when_set_and_spoofing_active():
    node = _node_with_ip_only("off")
    cfg = EvasionConfig(diag_terminal_name="LAPTOP-HR-04")
    term, spoof = effective_diag_terminal(node, cfg)
    assert term == "LAPTOP-HR-04"
    assert spoof is True


def test_operator_override_ignored_when_no_spoof_warranted():
    node = _node_with_ip_only("on")
    cfg = EvasionConfig(diag_terminal_name="LAPTOP-HR-04")
    term, spoof = effective_diag_terminal(node, cfg)
    # No spoof active — sticks with the safe inherited default to
    # avoid burning the override identity unnecessarily
    assert term == DEFAULT_DIAG_TERMINAL
    assert spoof is False


def test_none_node_returns_safe_default():
    term, spoof = effective_diag_terminal(None, EvasionConfig())
    assert term == DEFAULT_DIAG_TERMINAL
    assert spoof is False


# ---------------------------------------------------------------------------
# DIAG packet integration — the terminal string lands in the right bytes
# ---------------------------------------------------------------------------

def test_build_dp_header_writes_terminal_into_offset_81():
    dp = sap_client_enum.build_dp_header(terminal="FINOPS-WS-22")
    assert dp[81:96].rstrip(b"\x00") == b"FINOPS-WS-22"


def test_build_diag_init_includes_spoofed_terminal():
    pkt = sap_client_enum.build_diag_init(terminal="WS-NB-04")
    # The packet starts with the 200-byte DP header
    assert pkt[81:96].rstrip(b"\x00") == b"WS-NB-04"


def test_build_dp_header_truncates_long_terminal_to_15_chars():
    # Terminal field is 15 bytes wide
    dp = sap_client_enum.build_dp_header(terminal="A" * 30)
    assert dp[81:96] == b"A" * 15
