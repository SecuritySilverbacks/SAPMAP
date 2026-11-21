#!/usr/bin/env python3
"""Issue #92 — durable manual cleanup of non-relevant instances.

An operator can remove a wrongly-attributed / irrelevant SAP instance
from the System Details panel.  The removal must be DURABLE: the next
scan must not silently re-add it.  That durability rests on a new
persisted ``SAPNode.suppressed_instance_nrs`` set that:

  1. round-trips through to_dict/from_dict (the #218 symmetry lesson);
  2. is carried forward across ``SAPMAPState.add_node``'s wholesale
     node replace;
  3. is consulted by every instance *producer* (scan merge, deep-rescan
     wholesale replace, port-probe find-or-create, HTTP/SAPControl
     correction, MS app-server import) before it adds/overwrites.

These tests pin the model behaviour and the reachable (module-level)
producer gates.  The nested ``_merge_scan_into_existing`` gate is
covered indirectly by ``is_instance_suppressed`` (it is a one-line
``if existing.is_instance_suppressed(...)`` guard).
"""
import sys
import os
import json

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sapmap_models import InstanceInfo, SAPNode, SAPMAPState


def _node(sid="NPL", nrs=(("00", {3300: "gateway", 3200: "dispatcher"}),
                          ("04", {3304: "gateway"}))):
    n = SAPNode(sid=sid, hostname="h", ip="10.0.0.1")
    n.instances = [InstanceInfo(instance_nr=nr, ip="10.0.0.1", ports=dict(ports))
                   for nr, ports in nrs]
    return n


# ---------------------------------------------------------------------------
# Field + serialization
# ---------------------------------------------------------------------------

def test_field_defaults_empty_set():
    assert SAPNode(sid="X").suppressed_instance_nrs == set()


def test_to_dict_emits_sorted_list():
    n = _node()
    n.suppress_instance("04")
    n.suppress_instance("00")
    d = n.to_dict()
    assert d["suppressed_instance_nrs"] == ["00", "04"]  # sorted list, JSON-safe
    assert isinstance(d["suppressed_instance_nrs"], list)


def test_roundtrip_preserves_suppression():
    n = _node()
    n.suppress_instance("04")
    r = SAPNode.from_dict(json.loads(json.dumps(n.to_dict())))
    assert r.suppressed_instance_nrs == {"04"}


def test_from_dict_legacy_absent_defaults_empty():
    d = _node().to_dict()
    d.pop("suppressed_instance_nrs", None)
    assert SAPNode.from_dict(d).suppressed_instance_nrs == set()


def test_from_dict_explicit_null_defaults_empty():
    d = _node().to_dict()
    d["suppressed_instance_nrs"] = None
    assert SAPNode.from_dict(d).suppressed_instance_nrs == set()


def test_from_dict_normalizes_hand_edited_values():
    """A hand-edited .sapmap with a non-padded nr ('4') must still match
    a padded query ('04') — from_dict normalizes on load."""
    d = _node().to_dict()
    d["suppressed_instance_nrs"] = ["4", "XX"]
    r = SAPNode.from_dict(d)
    assert r.suppressed_instance_nrs == {"04", "XX"}
    assert r.is_instance_suppressed("04")
    assert r.is_instance_suppressed("4")


# ---------------------------------------------------------------------------
# suppress / unsuppress / prune / normalization
# ---------------------------------------------------------------------------

def test_suppress_removes_rows_and_records():
    n = _node()
    removed = n.suppress_instance("04")
    assert removed == 1
    assert [i.instance_nr for i in n.instances] == ["00"]
    assert n.suppressed_instance_nrs == {"04"}


def test_suppress_normalizes_input():
    n = _node()
    n.suppress_instance("4")          # non-padded
    assert n.suppressed_instance_nrs == {"04"}
    assert [i.instance_nr for i in n.instances] == ["00"]


def test_suppress_non_numeric_sentinel_passthrough():
    n = _node(nrs=(("00", {}), ("XX", {})))
    n.suppress_instance("XX")
    assert n.suppressed_instance_nrs == {"XX"}
    assert [i.instance_nr for i in n.instances] == ["00"]


def test_suppress_last_instance_leaves_empty_no_throw():
    n = _node(nrs=(("00", {3300: "gateway"}),))
    removed = n.suppress_instance("00")
    assert removed == 1
    assert n.instances == []
    assert n.suppressed_instance_nrs == {"00"}
    # downstream helpers must not throw on an empty list
    assert n.instance_nrs() == []


def test_unsuppress_lifts_gate_without_recreating_row():
    n = _node()
    n.suppress_instance("04")
    assert n.unsuppress_instance("04") is True
    assert not n.is_instance_suppressed("04")
    assert n.suppressed_instance_nrs == set()
    # row is NOT recreated — the next scan repopulates it
    assert "04" not in [i.instance_nr for i in n.instances]


def test_unsuppress_unknown_returns_false():
    assert _node().unsuppress_instance("09") is False


def test_prune_drops_suppressed_rows():
    n = _node()
    n.suppressed_instance_nrs = {"04"}          # set gate without removing
    pruned = n.prune_suppressed_instances()
    assert pruned == 1
    assert [i.instance_nr for i in n.instances] == ["00"]


def test_prune_noop_when_nothing_suppressed():
    n = _node()
    assert n.prune_suppressed_instances() == 0
    assert len(n.instances) == 2


# ---------------------------------------------------------------------------
# Stale cached-port reconciliation
# ---------------------------------------------------------------------------

def test_reconcile_clears_gw_port_but_keeps_bool_when_other_inst_has_gw():
    n = _node()                      # 00 (3300 gw) + 04 (3304 gw)
    n.gw_vulnerable = True
    n.gw_vulnerable_port = 3300
    n.suppress_instance("00")
    assert n.gw_vulnerable_port == 0        # pointed at removed 00 → cleared
    assert n.gw_vulnerable is True          # 04 still carries 3304 → flag stays


def test_reconcile_clears_gw_bool_when_no_gw_port_remains():
    n = _node(nrs=(("00", {3300: "gateway"}), ("04", {3204: "dispatcher"})))
    n.gw_vulnerable = True
    n.gw_vulnerable_port = 3300
    n.suppress_instance("00")
    assert n.gw_vulnerable_port == 0
    assert n.gw_vulnerable is False         # no 33xx left anywhere → flag cleared


def test_reconcile_clears_ms_port_and_bool():
    n = _node(nrs=(("00", {3600: "ms"}),))
    n.ms_port = 3600
    n.ms_vulnerable = True
    n.suppress_instance("00")
    assert n.ms_port == 0
    assert n.ms_vulnerable is False


def test_reconcile_clears_cve_2026_58240_ms_port():
    n = _node(nrs=(("00", {}),))
    n.cve_2026_58240_ms_port = 3600
    n.suppress_instance("00")
    assert n.cve_2026_58240_ms_port == 0


def test_reconcile_leaves_java_cve_ports_untouched():
    """VisualComposer / RECON Java ports do NOT encode the instance in
    their last two digits, so clearing by %100 would be wrong — they are
    deliberately left alone (re-derived on the next scan)."""
    n = _node(nrs=(("00", {}),))
    n.cve_2025_31324_port = 50000       # 50000 % 100 == 0 == int('00')…
    n.cve_2020_6287_port = 50000
    n.suppress_instance("00")
    assert n.cve_2025_31324_port == 50000   # …but still untouched by design
    assert n.cve_2020_6287_port == 50000


def test_reconcile_skips_non_numeric_nr():
    n = _node(nrs=(("00", {3300: "gateway"}), ("XX", {})))
    n.gw_vulnerable_port = 3300
    n.suppress_instance("XX")           # non-numeric → no port math
    assert n.gw_vulnerable_port == 3300


# ---------------------------------------------------------------------------
# add_node carry-forward across wholesale replace
# ---------------------------------------------------------------------------

def test_add_node_carries_suppression_forward_and_prunes():
    st = SAPMAPState()
    existing = _node()
    existing.suppress_instance("04")        # suppressed: {04}, instances: [00]
    st.add_node(existing)

    # A full re-discovery builds a FRESH node (empty suppression) with 04 back.
    fresh = _node()                         # instances: [00, 04], suppressed: {}
    st.add_node(fresh)

    got = st.get_node("NPL")
    assert got.suppressed_instance_nrs == {"04"}            # carried forward
    assert [i.instance_nr for i in got.instances] == ["00"]  # 04 pruned again


def test_add_node_unions_suppression_sets():
    st = SAPMAPState()
    a = _node()
    a.suppressed_instance_nrs = {"04"}
    st.add_node(a)
    b = _node()
    b.suppressed_instance_nrs = {"07"}
    st.add_node(b)
    assert st.get_node("NPL").suppressed_instance_nrs == {"04", "07"}


# ---------------------------------------------------------------------------
# Reachable (module-level) producer gates
# ---------------------------------------------------------------------------

def test_scanner_record_instance_port_skips_suppressed():
    import sapmap_scanner
    n = _node(nrs=(("00", {}),))
    n.suppress_instance("04")               # 04 removed + suppressed
    # a re-scan confirms an MS port on 04 → must NOT re-create the instance
    sapmap_scanner._record_instance_port(n, "04", 3604, "ms")
    assert "04" not in [i.instance_nr for i in n.instances]
    # an un-suppressed nr is still created normally
    sapmap_scanner._record_instance_port(n, "05", 3605, "ms")
    assert "05" in [i.instance_nr for i in n.instances]


def test_autopwn_correct_node_http_skips_suppressed_append():
    import sapmap_autopwn
    n = _node(nrs=(("00", {3300: "gateway"}),))
    n.suppress_instance("04")
    sapmap_autopwn._correct_node_http(n, {"instance_nr": "04"})
    assert "04" not in [i.instance_nr for i in n.instances]
    # a non-suppressed probe still appends
    sapmap_autopwn._correct_node_http(n, {"instance_nr": "06"})
    assert "06" in [i.instance_nr for i in n.instances]


def test_gui_correct_node_from_http_skips_suppressed_overwrite():
    import sapmap_gui
    n = _node(nrs=(("00", {3300: "gateway", 3200: "dispatcher"}),))
    n.suppress_instance("04")
    # probe wants to reindex the surviving 00 → 04; must be refused so the
    # removed nr is not resurrected onto instance[0].
    sapmap_gui._correct_node_from_http(n, {"instance_nr": "04"})
    assert n.instances[0].instance_nr == "00"
    # a non-suppressed correction still applies
    sapmap_gui._correct_node_from_http(n, {"instance_nr": "02"})
    assert n.instances[0].instance_nr == "02"


# ---------------------------------------------------------------------------
# Scripting engine surface
# ---------------------------------------------------------------------------

def test_script_remove_instance_action():
    import sapmap_script
    m = sapmap_script._map_step(
        {"action": "remove_instance", "target": "S4H", "instance_nr": "04"})
    assert m == ("POST", "/api/node/S4H/remove_instance",
                 {"instance_nr": "04"}, False)


def test_script_remove_instance_requires_nr():
    import sapmap_script
    with pytest.raises(ValueError):
        sapmap_script._map_step({"action": "remove_instance", "target": "S4H"})


# ---------------------------------------------------------------------------
# Post-review regression guards (adversarial review findings)
# ---------------------------------------------------------------------------

def test_unrelated_removal_keeps_scalar_only_gw_vuln():
    """Review #4 (high): the GW-vuln port usually lives ONLY in the node
    scalar (never mirrored into instance.ports).  Removing an UNRELATED
    instance must NOT drop the confirmed finding."""
    n = _node(nrs=(("00", {3200: "dispatcher"}), ("01", {3201: "dispatcher"})))
    n.gw_vulnerable = True
    n.gw_vulnerable_port = 3300           # scalar-only evidence, no inst carries it
    n.suppress_instance("01")            # remove the UNRELATED instance
    assert n.gw_vulnerable_port == 3300  # 3300 % 100 != 1 → untouched
    assert n.gw_vulnerable is True       # flag kept (locus still present)


def test_unrelated_removal_keeps_scalar_only_ms_vuln():
    """Review #4: same for the internal 39NN message-server vuln."""
    n = _node(nrs=(("00", {3900: "ms_internal"}), ("01", {3301: "gateway"})))
    n.ms_vulnerable = True
    n.ms_port = 3900
    n.suppress_instance("01")
    assert n.ms_port == 3900
    assert n.ms_vulnerable is True


def test_ms_reconcile_uses_internal_39NN_port():
    """Review #2: ms_port/ms_vulnerable track the INTERNAL 39NN port, not
    36NN.  Removing the MS instance (scalar matches) clears both."""
    n = _node(nrs=(("00", {3900: "ms_internal"}),))
    n.ms_port = 3900
    n.ms_vulnerable = True
    n.suppress_instance("00")
    assert n.ms_port == 0
    assert n.ms_vulnerable is False


def test_ms_vuln_kept_when_surviving_instance_has_39NN():
    n = _node(nrs=(("00", {3900: "ms_internal"}), ("01", {3901: "ms_internal"})))
    n.ms_port = 3900
    n.ms_vulnerable = True
    n.suppress_instance("00")
    assert n.ms_port == 0                # scalar matched 00 → cleared
    assert n.ms_vulnerable is True       # 3901 survives → flag kept


def test_reconcile_vuln_flags_clears_relit_bool_with_no_locus():
    """Review #5: deep_scan_single OR-merges gw_vulnerable from a fresh
    scan that re-found the (pruned) suppressed instance's gateway.
    reconcile_vuln_flags must clear it again (no surviving locus)."""
    n = _node(nrs=(("04", {3304: "gateway"}),))
    n.gw_vulnerable = True
    n.gw_vulnerable_port = 3304
    n.suppress_instance("04")                 # → False, port 0, empty list
    assert n.gw_vulnerable is False
    n.gw_vulnerable = True                     # simulate the OR-merge re-light
    n.reconcile_vuln_flags()                   # the scanner.py fix
    assert n.gw_vulnerable is False            # no locus (port 0, no 33xx) → cleared


def test_reconcile_vuln_flags_keeps_bool_with_surviving_port():
    n = _node(nrs=(("00", {3300: "gateway"}),))
    n.gw_vulnerable = True
    n.gw_vulnerable_port = 0                    # scalar unknown, instance has 3300
    n.reconcile_vuln_flags()
    assert n.gw_vulnerable is True             # surviving 3300 → kept


def test_mark_java_http_port_respects_suppression():
    """Review #1: the Java HTTP backfill must not resurrect a suppressed
    nr onto an instance-less node."""
    import sapmap_exploit
    n = SAPNode(sid="J2E", hostname="h", ip="10.0.0.1")
    n.suppress_instance("00")                  # instances empty, {00} suppressed
    sapmap_exploit._mark_java_http_port(n, 50000)   # 50000 → nr '00'
    assert "00" not in [i.instance_nr for i in n.instances]
    sapmap_exploit._mark_java_http_port(n, 50100)   # nr '01' (not suppressed)
    assert "01" in [i.instance_nr for i in n.instances]


def test_suppress_pseudo_instance_xx_still_works():
    """Review #3: the route allows alphanumeric sentinels (XX/WD); the
    model handles them."""
    n = _node(nrs=(("00", {}), ("XX", {})))
    assert n.suppress_instance("XX") == 1
    assert n.is_instance_suppressed("XX")
