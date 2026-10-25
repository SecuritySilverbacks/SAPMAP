#!/usr/bin/env python3
"""Tests for _resolve_gateway_service() — SNC-aware gateway-port selection
for the sapxpg TCP/IP destination (issue #172).

Pre-#172, the File Browser's self-referencing SXPG destination (and the
manual Create-TCP/IP-destination action) only ever matched a `gateway`
(33NN) port. On an SNC landscape the gateway lives on gw/snc_port
(4800+NN) and 33NN is firewalled, so the destination pointed at a dead /
non-SNC port — the "mysterious connects to the non-SNC port" symptom.
"""
from __future__ import annotations

import pytest

import sapmap_rfc                                  # noqa: E402
from sapmap_models import SAPNode, InstanceInfo    # noqa: E402


@pytest.fixture
def _snc_reset():
    """Save/restore the module-global SNC posture around a test."""
    saved = dict(sapmap_rfc._snc_config)
    try:
        yield
    finally:
        sapmap_rfc.set_snc_config(**saved)


def _node(sid, ports, *, snc_name="", nr="00", ip="10.0.0.1"):
    return SAPNode(sid=sid, ip=ip, snc_partnername=snc_name,
                   instances=[InstanceInfo(instance_nr=nr, ip=ip,
                                           ports=ports)])


def test_non_snc_node_uses_plain_gateway(_snc_reset):
    sapmap_rfc.set_snc_config()   # no global SNC posture
    n = _node("A", {3200: "dispatcher", 3300: "gateway"})
    assert sapmap_rfc._resolve_gateway_service(n) == "3300"


def test_snc_node_prefers_snc_gateway_when_configured(_snc_reset):
    # Both gateways open; SNC fully configured + node has an SNC name.
    sapmap_rfc.set_snc_config(secudir="/s", sapcryptolib="/l.so",
                              identity="p/cstb:me")
    n = _node("B", {3300: "gateway", 4800: "gateway_snc"},
              snc_name="p/cstb:sapn2a")
    assert sapmap_rfc._resolve_gateway_service(n) == "4800"


def test_snc_name_without_global_config_falls_back_to_plain(_snc_reset):
    # Node carries an SNC name but the operator hasn't configured the
    # global posture -> gate is False -> plain gateway.
    sapmap_rfc.set_snc_config()
    n = _node("B2", {3300: "gateway", 4800: "gateway_snc"},
              snc_name="p/cstb:sapn2a")
    assert sapmap_rfc._resolve_gateway_service(n) == "3300"


def test_only_snc_gateway_open_is_used_regardless_of_gate(_snc_reset):
    # 33NN firewalled (not scanned); only the SNC gateway is open.
    sapmap_rfc.set_snc_config()   # even with the gate off
    n = _node("C", {4801: "gateway_snc"}, nr="01")
    assert sapmap_rfc._resolve_gateway_service(n) == "4801"


def test_no_ports_scanned_derives_from_instance_nr(_snc_reset):
    n = _node("D", {}, nr="02")
    assert sapmap_rfc._resolve_gateway_service(n, snc=True) == "4802"
    assert sapmap_rfc._resolve_gateway_service(n, snc=False) == "3302"


def test_dict_shaped_instances_do_not_crash(_snc_reset):
    # Instances / ports may be dict-shaped (landscape import, legacy state)
    # and instance_nr may be an int (see #166).  Must not raise.
    sapmap_rfc.set_snc_config(secudir="/s", sapcryptolib="/l.so",
                              identity="p/cstb:me")
    n = SAPNode(sid="E", ip="10.0.0.5", snc_partnername="p/cstb:e",
                instances=[{"instance_nr": 0,
                            "ports": {3300: "gateway", 4800: "gateway_snc"}}])
    assert sapmap_rfc._resolve_gateway_service(n) == "4800"
