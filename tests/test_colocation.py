"""Tests for issue #70 — same-host SAP instance discovery.

discover_colocated_sids lists /usr/sap on an owned node, extracts the other
SIDs, marks the ones already plotted on the same host, and materializes dashed
placeholder nodes for the rest. The OS-command layer is stubbed via the
injectable run_cmd argument.
"""
from __future__ import annotations

import pytest

import modules  # noqa: F401 — registers package paths

import sap_colocation as C
from sapmap_models import SAPMAPState, SAPNode


# ---------------------------------------------------------------------------
# parse_colocated_sids
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("lines,own,expected", [
    (["NPL", "S4H", "trans", "hostctrl", "SYS", "tmp"], "ABC", ["NPL", "S4H"]),
    (["OWN", "S4H"], "OWN", ["S4H"]),                       # own SID dropped
    (["NPL", "S4H"], "NPL@10.0.0.5", ["S4H"]),              # own SID dropped even when the node key is @-mangled
    (["NPL  S4H  trans  SM1"], "ABC", ["NPL", "S4H", "SM1"]),  # multi-column
    (["npl", "Web", "A1", "ABCD"], "XXX", []),              # lowercase/short/long rejected
    (["S4H", "S4H", "S4H"], "XXX", ["S4H"]),                # de-duplicated
    ([], "XXX", []),
])
def test_parse(lines, own, expected):
    assert C.parse_colocated_sids(lines, own) == expected


# ---------------------------------------------------------------------------
# discover_colocated_sids
# ---------------------------------------------------------------------------

def _stub(output, success=True, error=""):
    def _run(node, command, params):
        return {"success": success, "output": list(output), "error": error,
                "channel": "stub"}
    return _run


def test_discover_correlates_and_materializes():
    state = SAPMAPState()
    own = SAPNode(sid="OWN", ip="10.0.0.5")
    plotted = SAPNode(sid="S4H", ip="10.0.0.5")   # already on the map, same host
    state.add_node(own)
    state.add_node(plotted)

    run = _stub(["OWN", "S4H", "NPL", "trans", "hostctrl", "SYS"])
    res = C.discover_colocated_sids(own, state, run_cmd=run)

    assert res["ok"] is True
    # S4H plotted, NPL new; own/trans/hostctrl/SYS excluded
    by_sid = {c["sid"]: c for c in res["colocated"]}
    assert set(by_sid) == {"S4H", "NPL"}
    assert by_sid["S4H"]["plotted"] is True
    assert by_sid["NPL"]["plotted"] is False
    assert res["placeholders_added"] == ["NPL"]
    # recorded on the owning node
    assert {c["sid"] for c in own.colocated_sids} == {"S4H", "NPL"}
    # NPL materialized as a same-host colocation placeholder
    npl = state.get_node("NPL")
    assert npl is not None
    assert npl.discovered_via_colocation is True
    assert npl.ip == "10.0.0.5"
    assert npl.linked_target_sid == "OWN"
    # S4H not duplicated
    assert state.get_node("S4H") is plotted


def test_hostname_only_peer_correlates_without_clobber():
    """A co-located SID plotted under a hostname (no intersecting IP) must
    correlate as plotted and NOT be overwritten by a dashed placeholder."""
    state = SAPMAPState()
    own = SAPNode(sid="OWN", ip="10.0.0.5", hostname="saphost")
    peer = SAPNode(sid="S4H", ip="", hostname="saphost")   # hostname-only, rich
    peer.pwned = True
    state.add_node(own)
    state.add_node(peer)

    res = C.discover_colocated_sids(own, state, run_cmd=_stub(["OWN", "S4H"]))

    by_sid = {c["sid"]: c for c in res["colocated"]}
    assert by_sid["S4H"]["plotted"] is True            # matched by hostname
    assert res["placeholders_added"] == []              # nothing materialized
    s4h = state.get_node("S4H")
    assert s4h is peer and s4h.pwned is True             # real node untouched
    assert s4h.discovered_via_colocation is False


def test_colocated_sids_not_aliased_through_serialization():
    n = SAPNode(sid="NPL")
    n.colocated_sids = [{"sid": "S4H", "ip": "10.0.0.5", "plotted": True}]
    n2 = SAPNode.from_dict(n.to_dict())
    assert n2.colocated_sids == n.colocated_sids
    n2.colocated_sids.append({"sid": "XYZ"})
    assert n.colocated_sids != n2.colocated_sids         # distinct list objects


def test_discover_non_fatal_when_no_channel():
    state = SAPMAPState()
    own = SAPNode(sid="OWN", ip="10.0.0.5")
    state.add_node(own)
    res = C.discover_colocated_sids(own, state,
                                    run_cmd=_stub([], success=False,
                                                  error="no exec channel"))
    assert res["ok"] is False
    assert "no exec channel" in res["reason"]
    assert own.colocated_sids == []
    assert state.get_node("OWN") is own  # nothing else added


def test_discover_empty_listing_records_nothing():
    state = SAPMAPState()
    own = SAPNode(sid="OWN", ip="10.0.0.5")
    state.add_node(own)
    res = C.discover_colocated_sids(own, state, run_cmd=_stub(["OWN", "trans"]))
    assert res["ok"] is True
    assert res["colocated"] == []
    assert own.colocated_sids == []


# ---------------------------------------------------------------------------
# serialization round-trip of the new SAPNode fields
# ---------------------------------------------------------------------------

def test_sapnode_colocation_fields_roundtrip():
    n = SAPNode(sid="NPL", ip="10.0.0.5")
    n.discovered_via_colocation = True
    n.colocated_sids = [{"sid": "S4H", "ip": "10.0.0.5", "plotted": True}]
    n2 = SAPNode.from_dict(n.to_dict())
    assert n2.discovered_via_colocation is True
    assert n2.colocated_sids == [{"sid": "S4H", "ip": "10.0.0.5", "plotted": True}]
