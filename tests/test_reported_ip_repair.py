"""Tests for the reported-IP handling in `_correct_node_from_http` (follow-up
to #188 / issue "A4H plotted at internal 172.17.0.2").

RFC_SYSTEM_INFO reports the target's OWN view of its IP (RFCIPADDR), which on a
NAT'd/containerised landscape is frequently an internal address (e.g. Docker
172.17.x) that is not routable from the SAPMAP host.  #188 stopped the live
discovery path from clobbering the reachable node IP with that internal one and
started recording it as `reported_ip` instead.

This follow-up closes the *reload* gap: a `.sapmap` saved by a pre-#188 run
already has the internal address stored as the node IP.  Re-running discovery
must now self-heal such a node — promote the reachable IP and demote the
internal one to `reported_ip` — without clobbering an IP that was set
deliberately to something else.
"""
from __future__ import annotations

import modules  # noqa: F401 — registers package paths

from sapmap_models import SAPNode
from sapmap_gui import _correct_node_from_http


def test_empty_ip_filled_from_reachable():
    """A node with no IP yet takes the reachable address; the self-reported
    internal one lands in reported_ip."""
    n = SAPNode(sid="A4H")
    _correct_node_from_http(
        n, {"ip": "192.168.2.136", "reported_ip": "172.17.0.2"})
    assert n.ip == "192.168.2.136"
    assert n.reported_ip == "172.17.0.2"


def test_stale_internal_ip_is_repaired():
    """A node saved by a pre-fix run with the internal IP as its node IP is
    repaired on re-discovery — reachable promoted, internal demoted."""
    n = SAPNode(sid="A4H", ip="172.17.0.2")  # the pre-fix clobbered state
    _correct_node_from_http(
        n, {"ip": "192.168.2.136", "reported_ip": "172.17.0.2"})
    assert n.ip == "192.168.2.136"
    assert n.reported_ip == "172.17.0.2"


def test_already_reachable_ip_is_kept():
    """A node already on the reachable IP is left alone; the internal address
    is still filed as reported_ip."""
    n = SAPNode(sid="A4H", ip="192.168.2.136")
    _correct_node_from_http(
        n, {"ip": "192.168.2.136", "reported_ip": "172.17.0.2"})
    assert n.ip == "192.168.2.136"
    assert n.reported_ip == "172.17.0.2"


def test_unrelated_existing_ip_not_clobbered():
    """The repair only promotes when the stored IP is EXACTLY the reported
    internal one.  A different, deliberately-set IP must not be overwritten."""
    n = SAPNode(sid="A4H", ip="10.9.9.9")  # some other address we set on purpose
    _correct_node_from_http(
        n, {"ip": "192.168.2.136", "reported_ip": "172.17.0.2"})
    assert n.ip == "10.9.9.9"               # untouched
    assert n.reported_ip == "172.17.0.2"    # internal still recorded


def test_no_reported_ip_when_equal_to_node_ip():
    """When the only address reported equals the node IP, nothing spurious is
    stored as reported_ip (the UI shows the row only when they differ)."""
    n = SAPNode(sid="A4H", ip="192.168.2.136")
    _correct_node_from_http(
        n, {"ip": "192.168.2.136", "reported_ip": "192.168.2.136"})
    assert n.ip == "192.168.2.136"
    assert n.reported_ip == ""
