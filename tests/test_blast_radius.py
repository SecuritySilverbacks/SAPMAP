"""Tests for the blast-radius flood (issue #197) in sapmap_chain.py.

The GUI blast-radius view answers "own this box, own all of *that*":

    * ``blast_radius(state, start)``  — forward reachable set, ring by ring
    * ``exposure_cone(state, jewel)`` — inverse: who can reach the jewel

Both walk the one graph ``_build_adjacency`` builds, with the one
``_edge_propagates`` gate the kill-chain ranker uses — so the flood can
never claim reach the ranked chains would not.  These tests pin down:

    * the shared graph helpers (adjacency shape, hop metadata, the gate),
    * forward rings + the propagation gate (a plain RFC logon reaches a
      box but does not let you pivot *past* it),
    * per-node metadata (hop / method / severity / untested / via),
    * the inverse cone and its exact equivalence with the forward flood
      (``J in blast_radius(S)``  <=>  ``S in exposure_cone(J)``),
    * depth clamping, and the empty / unknown-SID degenerate cases,
    * consistency with ``find_all_chains`` (same reachable set).

All tests are offline: they build mock SAPMAPState objects (synthetic
SIDs, RFC1918 placeholder IPs) and assert on plain dicts.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sapmap_chain import (
    find_all_chains,
    blast_radius, exposure_cone,
    _build_adjacency, _make_hop, _edge_propagates, _edge_kind,
    _HOP_SEV_CRITICAL, _HOP_SEV_HIGH, _HOP_SEV_MEDIUM, _HOP_SEV_LOW,
)
from sapmap_models import (
    SAPMAPState, SAPNode, RFCConnection,
    DBCONConnection, TMSDestination, TrustRelation,
)


# ---------------------------------------------------------------------------
# Landscape fixtures (synthetic SIDs; never published)
# ---------------------------------------------------------------------------

def _landscape_gated():
    """A multi-hop landscape that exercises the propagation gate.

        PWN --SAP_ALL (tested)----> MID   r1  HIGH   pivots onward
        PWN --plain RFC (tested)--> LEAF  r1  MEDIUM does NOT pivot onward
        MID --SAP_ALL (tested)----> PRD   r2  HIGH   (crown jewel)
        MID --plain RFC (UNTESTED)> CAND  r2  LOW    untested candidate
        PRD --trusted RFC---------> DR    r3  CRIT
        LEAF --plain RFC---------> HID    (edge exists, but LEAF is only
                                           reached over a plain RFC logon,
                                           never *owned*, so HID is
                                           unreachable from PWN)

    Every non-root node has in-degree 1 (a tree), so this fixture pins the
    ring / gate / metadata behaviour but NOT the forward<->inverse
    asymmetry — see _landscape_asymmetric for that.  From PWN the reachable
    set is {MID, LEAF, PRD, CAND, DR}; HID is *excluded* because LEAF is
    never owned.
    """
    state = SAPMAPState()
    pwn = SAPNode(sid="PWN", ip="10.0.0.1", hostname="pwn", pwned=True)
    state.add_node(pwn)
    state.add_node(SAPNode(sid="MID", ip="10.0.0.2", hostname="mid"))
    state.add_node(SAPNode(sid="LEAF", ip="10.0.0.3", hostname="leaf"))
    state.add_node(SAPNode(sid="PRD", ip="10.0.0.4", hostname="prd",
                           is_production=True))
    state.add_node(SAPNode(sid="CAND", ip="10.0.0.5", hostname="cand"))
    state.add_node(SAPNode(sid="DR", ip="10.0.0.6", hostname="dr",
                           is_production=True))
    state.add_node(SAPNode(sid="HID", ip="10.0.0.7", hostname="hid"))

    state.add_connection(RFCConnection(
        source_sid="PWN", source_host="pwn", target_sid="MID", target_host="mid",
        destination_name="D_MID", rfc_user="RFC",
        has_sap_all=True, tested=True, logon_successful=True))
    state.add_connection(RFCConnection(
        source_sid="PWN", source_host="pwn", target_sid="LEAF", target_host="leaf",
        destination_name="D_LEAF", rfc_user="RFC",
        has_sap_all=False, tested=True, logon_successful=True))
    state.add_connection(RFCConnection(
        source_sid="MID", source_host="mid", target_sid="PRD", target_host="prd",
        destination_name="D_PRD", rfc_user="RFC",
        has_sap_all=True, tested=True, logon_successful=True))
    state.add_connection(RFCConnection(
        source_sid="MID", source_host="mid", target_sid="CAND", target_host="cand",
        destination_name="D_CAND", rfc_user="RFC",
        has_sap_all=False, tested=False, logon_successful=False))
    state.add_connection(RFCConnection(
        source_sid="PRD", source_host="prd", target_sid="DR", target_host="dr",
        destination_name="D_DR", rfc_user="RFC",
        has_sap_all=False, trusted_system=True))
    state.add_connection(RFCConnection(
        source_sid="LEAF", source_host="leaf", target_sid="HID", target_host="hid",
        destination_name="D_HID", rfc_user="RFC",
        has_sap_all=False, tested=True, logon_successful=True))   # non-propagating
    return state


def _landscape_asymmetric():
    """A node reached first over a *non-propagating* edge but owned over a
    longer *propagating* path — the case a single-visit BFS silently drops.

        S --SAP_ALL--------> A    (prop)
        S --plain RFC------> X    (NON-prop; shortest touch of X, ring 1)
        A --SAP_ALL--------> X    (prop; this is what actually OWNS X)
        X --SAP_ALL--------> Y    (prop; Y is the crown jewel)

    Correct forward flood from S: {A(1), X(1), Y(3)} — X is reached at
    ring 1 over the weak S->X edge, but only the S->A->X owning path lets
    the walk continue to Y at ring 3.  A naive single-visit BFS marks X
    seen via S->X, never expands it, and WRONGLY omits Y.
    """
    state = SAPMAPState()
    s = SAPNode(sid="S", ip="10.0.0.1", hostname="s", pwned=True)
    state.add_node(s)
    state.add_node(SAPNode(sid="A", ip="10.0.0.2", hostname="a"))
    state.add_node(SAPNode(sid="X", ip="10.0.0.3", hostname="x"))
    state.add_node(SAPNode(sid="Y", ip="10.0.0.4", hostname="y",
                           is_production=True))
    state.add_connection(RFCConnection(
        source_sid="S", source_host="s", target_sid="A", target_host="a",
        destination_name="D_A", rfc_user="RFC",
        has_sap_all=True, tested=True, logon_successful=True))
    state.add_connection(RFCConnection(
        source_sid="S", source_host="s", target_sid="X", target_host="x",
        destination_name="D_X", rfc_user="RFC",
        has_sap_all=False, tested=True, logon_successful=True))  # non-prop
    state.add_connection(RFCConnection(
        source_sid="A", source_host="a", target_sid="X", target_host="x",
        destination_name="D_AX", rfc_user="RFC",
        has_sap_all=True, tested=True, logon_successful=True))
    state.add_connection(RFCConnection(
        source_sid="X", source_host="x", target_sid="Y", target_host="y",
        destination_name="D_Y", rfc_user="RFC",
        has_sap_all=True, tested=True, logon_successful=True))
    return state


def _landscape_synthetic_edges():
    """One entry with a distinct synthetic edge of each kind, so adjacency
    reuse can be asserted for STRUSTSSO2 / DBCON / TMS edges too."""
    state = SAPMAPState()
    iss = SAPNode(sid="ISS", ip="10.0.0.1", hostname="iss", pwned=True)
    state.add_node(iss)
    state.add_node(SAPNode(sid="TRU", ip="10.0.0.2", hostname="tru"))
    state.add_node(SAPNode(sid="ADB", ip="10.0.0.3", hostname="adb"))
    state.add_node(SAPNode(sid="ATM", ip="10.0.0.4", hostname="atm"))

    state.trust_relations = [TrustRelation(
        issuer_sid="ISS", trusting_sid="TRU", trusting_client="100",
        discovered_via="STRUST")]
    iss.dbcon_edges = [DBCONConnection(
        source_sid="ISS", con_name="C_ADB", dbms="HDB",
        host="adb", port=30215, user="saphanadb", password="pw",
        tested=False, reachable=True, is_sap_shape=True,
        target_sid="ADB", pwned=True)]
    iss.tms_destinations = [TMSDestination(
        source_sid="ISS", target_sid="ATM", target_host="atm",
        domain="DOMAIN_ISS", is_controller=True, password="x",
        tested=False, logon_ok=False, tmsadm_has_sap_all=False)]
    return state


def _meta(result, sid):
    return result["nodes"].get(sid)


# ---------------------------------------------------------------------------
# Shared graph helpers
# ---------------------------------------------------------------------------

class TestSharedGraphHelpers:

    def test_build_adjacency_shape(self):
        adj = _build_adjacency(_landscape_gated())
        # sid -> list of (target_sid, edge)
        assert set(dict(adj.get("PWN", [])).keys()) == {"MID", "LEAF"}
        assert set(dict(adj.get("MID", [])).keys()) == {"PRD", "CAND"}
        assert [t for t, _ in adj.get("PRD", [])] == ["DR"]

    def test_build_adjacency_includes_synthetic_edges(self):
        state = _landscape_synthetic_edges()
        assert state.connections == []          # no plain RFC edges at all
        adj = _build_adjacency(state)
        # yet all three synthetic edge kinds hang off the issuer/source SID:
        # STRUSTSSO2 (issuer->trusting), DBCON and TMS (source node).
        tgts = {t for t, _ in adj.get("ISS", [])}
        assert {"TRU", "ADB", "ATM"} <= tgts

    def test_edge_propagates_gate(self):
        adj = _build_adjacency(_landscape_gated())
        edges = dict(adj["PWN"])
        assert _edge_propagates(edges["MID"]) is True    # SAP_ALL
        assert _edge_propagates(edges["LEAF"]) is False   # plain RFC logon

    def test_edge_kind_classifies(self):
        adj = _build_adjacency(_landscape_synthetic_edges())
        by_tgt = dict(adj["ISS"])
        _, is_sso2, _, _, _ = _edge_kind(by_tgt["TRU"])
        _, _, is_dbcon, _, _ = _edge_kind(by_tgt["ADB"])
        _, _, _, is_tms, _ = _edge_kind(by_tgt["ATM"])
        assert is_sso2 and is_dbcon and is_tms


# ---------------------------------------------------------------------------
# Forward blast radius
# ---------------------------------------------------------------------------

class TestForwardBlastRadius:

    def setup_method(self):
        self.r = blast_radius(_landscape_gated(), "PWN")

    def test_mode_and_anchor(self):
        assert self.r["mode"] == "forward"
        assert self.r["anchor"] == "PWN"

    def test_reachable_set_excludes_start_and_gated_node(self):
        assert set(self.r["nodes"]) == {"MID", "LEAF", "PRD", "CAND", "DR"}
        assert "PWN" not in self.r["nodes"]      # start is the anchor
        assert "HID" not in self.r["nodes"]      # behind a non-pivot edge

    def test_rings_are_shortest_distance(self):
        rings = {rr["hop"]: set(rr["sids"]) for rr in self.r["rings"]}
        assert rings[1] == {"MID", "LEAF"}
        assert rings[2] == {"PRD", "CAND"}
        assert rings[3] == {"DR"}
        assert self.r["max_hop"] == 3
        assert self.r["reachable"] == 5

    def test_per_node_via_pointer(self):
        assert _meta(self.r, "MID")["via"] == "PWN"
        assert _meta(self.r, "PRD")["via"] == "MID"
        assert _meta(self.r, "DR")["via"] == "PRD"

    def test_per_node_severity_and_method(self):
        assert _meta(self.r, "MID")["severity"] == _HOP_SEV_HIGH
        assert _meta(self.r, "MID")["method"] == "BAPI (SAP_ALL)"
        assert _meta(self.r, "LEAF")["severity"] == _HOP_SEV_MEDIUM
        assert _meta(self.r, "LEAF")["method"] == "RFC logon"
        assert _meta(self.r, "DR")["severity"] == _HOP_SEV_CRITICAL
        assert _meta(self.r, "DR")["method"] == "Trusted RFC (no password)"

    def test_untested_candidate_is_clamped_and_flagged(self):
        cand = _meta(self.r, "CAND")
        assert cand["untested"] is True
        assert cand["severity"] == _HOP_SEV_LOW
        assert cand["method"].endswith("— UNTESTED")

    def test_depth_clamp(self):
        r1 = blast_radius(_landscape_gated(), "PWN", max_depth=1)
        assert set(r1["nodes"]) == {"MID", "LEAF"}
        assert r1["max_hop"] == 1
        r2 = blast_radius(_landscape_gated(), "PWN", max_depth=2)
        assert set(r2["nodes"]) == {"MID", "LEAF", "PRD", "CAND"}
        assert "DR" not in r2["nodes"]

    def test_unknown_or_empty_start_is_well_formed_empty(self):
        for bad in ("", "NOPE", None):
            r = blast_radius(_landscape_gated(), bad)
            assert r["nodes"] == {} and r["rings"] == []
            assert r["reachable"] == 0 and r["max_hop"] == 0
            assert r["mode"] == "forward"


# ---------------------------------------------------------------------------
# Inverse exposure cone
# ---------------------------------------------------------------------------

class TestExposureCone:

    def test_cone_to_crown_jewel(self):
        r = exposure_cone(_landscape_gated(), "PRD")
        assert r["mode"] == "inverse" and r["anchor"] == "PRD"
        # MID reaches PRD directly (last hop); PWN reaches via SAP_ALL->MID.
        assert set(r["nodes"]) == {"MID", "PWN"}
        rings = {rr["hop"]: set(rr["sids"]) for rr in r["rings"]}
        assert rings[1] == {"MID"}
        assert rings[2] == {"PWN"}

    def test_cone_via_points_toward_jewel(self):
        r = exposure_cone(_landscape_gated(), "PRD")
        assert _meta(r, "MID")["via"] == "PRD"   # MID's next step is PRD
        assert _meta(r, "PWN")["via"] == "MID"    # PWN's next step is MID

    def test_last_hop_into_jewel_is_unconstrained(self):
        # LEAF->HID is a *non-propagating* edge (has_sap_all=False), yet as
        # the LAST hop into the anchor it still counts — so LEAF is in HID's
        # cone.  PWN is NOT: PWN->LEAF is also non-propagating, and as a
        # *non-final* hop that confers no onward pivot it is gated out.
        # This pins the "first reverse hop unconstrained, deeper hops gated"
        # rule with an edge that would be excluded if it were a deeper hop.
        r = exposure_cone(_landscape_gated(), "HID")
        assert set(r["nodes"]) == {"LEAF"}
        assert "PWN" not in r["nodes"]

    def test_unknown_or_empty_target_is_empty(self):
        for bad in ("NOPE", "", None):
            r = exposure_cone(_landscape_gated(), bad)
            assert r["nodes"] == {} and r["rings"] == []
            assert r["reachable"] == 0 and r["mode"] == "inverse"


# ---------------------------------------------------------------------------
# Cross-cutting invariants
# ---------------------------------------------------------------------------

class TestInvariants:

    # The equivalence is exercised on BOTH the tree fixture AND the
    # asymmetric one.  The asymmetric graph is the load-bearing case: a
    # single-visit forward BFS passes on a tree (one path per node) but
    # fails here, so running the invariant only on a tree is false-green.
    @pytest.mark.parametrize("make", [_landscape_gated, _landscape_asymmetric])
    def test_forward_inverse_equivalence(self, make):
        """J in blast_radius(S)  <=>  S in exposure_cone(J), for all S, J."""
        state = make()
        sids = list(state.nodes.keys())
        for s in sids:
            reach = set(blast_radius(state, s).get("nodes", {}))
            for j in sids:
                if j == s:
                    continue
                cone = set(exposure_cone(state, j).get("nodes", {}))
                assert (j in reach) == (s in cone), (
                    f"mismatch S={s} J={j}: j_in_reach={j in reach} "
                    f"s_in_cone={s in cone}")

    def test_owning_path_reaches_node_behind_a_weak_first_touch(self):
        """The core fix: X is touched first over the weak S->X edge (ring 1)
        but owned via S->A->X, so the deep crown jewel Y IS reached."""
        r = blast_radius(_landscape_asymmetric(), "S")
        assert set(r["nodes"]) == {"A", "X", "Y"}
        assert _meta(r, "X")["hop"] == 1            # shortest *reach* of X
        assert _meta(r, "X")["via"] == "S"
        assert _meta(r, "Y")["hop"] == 3            # via the owning path
        assert _meta(r, "Y")["via"] == "X"
        # and the inverse agrees
        assert "S" in exposure_cone(_landscape_asymmetric(), "Y")["nodes"]

    def test_blast_is_at_least_as_complete_as_find_all_chains(self):
        """blast_radius never reaches *fewer* systems than find_all_chains
        enumerates from the same entry.  On the asymmetric graph it reaches
        strictly more: find_all_chains de-duplicates to one representative
        path per endpoint and dead-ends on X's weak first touch, so it omits
        Y — a pre-existing under-report in the chain enumerator (tracked
        separately).  This invariant holds whether or not that is fixed."""
        state = _landscape_asymmetric()
        chains = find_all_chains(state, print_fn=lambda *a: None)
        chain_ends = {c.end_sid for c in chains if c.start_sid == "S"}
        reach = set(blast_radius(state, "S").get("nodes", {}))
        assert reach >= chain_ends                  # at least as complete
        assert "Y" in reach                         # blast finds the jewel
        assert "Y" not in chain_ends                # chains currently do not

    def test_synthetic_edges_flood(self):
        """blast_radius walks STRUSTSSO2 / DBCON / TMS synthetic edges and
        carries their captions (not only plain RFC connections)."""
        state = _landscape_synthetic_edges()
        state.nodes["ISS"].pwned = True
        r = blast_radius(state, "ISS")
        assert {"TRU", "ADB", "ATM"} <= set(r["nodes"])
        assert r["nodes"]["TRU"]["method"] == "Forged MYSAPSSO2 ticket (STRUSTSSO2)"
        assert r["nodes"]["TRU"]["severity"] == _HOP_SEV_CRITICAL
        # and the inverse reaches back to the issuer
        assert "ISS" in exposure_cone(state, "TRU")["nodes"]

    def test_result_is_json_safe(self):
        import json
        for make in (_landscape_gated, _landscape_asymmetric,
                     _landscape_synthetic_edges):
            state = make()
            json.dumps(blast_radius(state, next(iter(state.nodes))))
            json.dumps(exposure_cone(state, next(iter(state.nodes))))


# ---------------------------------------------------------------------------
# Randomized differential test — blast_radius vs an independent reference
# ---------------------------------------------------------------------------
# The reference enumerates paths by DFS and applies the semantics directly
# ("to REACH v, every hop before the last must propagate; continue past v
# only if the edge into it propagates").  It shares _build_adjacency /
# _edge_propagates with the production code (graph construction + the gate
# are trusted and tested elsewhere) but its TRAVERSAL is structurally
# different from the two-phase BFS, so a bug in either shows up as a diff.

def _reference_reach(state, start, max_depth):
    """Independent reference for blast_radius: {sid: shortest_reach_hop}."""
    adj = _build_adjacency(state)
    reach = {}

    def dfs(node, depth, prefix_all_propagate):
        if depth >= max_depth:
            return
        for v, conn in adj.get(node, []):
            if prefix_all_propagate and v != start:
                reach[v] = min(reach.get(v, 10 ** 9), depth + 1)
            # continue PAST v only if the whole prefix incl. this edge owns
            if prefix_all_propagate and _edge_propagates(conn):
                dfs(v, depth + 1, True)

    dfs(start, 0, True)
    return reach


def _random_state(rng, n_nodes, n_edges):
    import string
    state = SAPMAPState()
    sids = [f"N{i}" for i in range(n_nodes)]
    for i, sid in enumerate(sids):
        state.add_node(SAPNode(sid=sid, ip=f"10.0.0.{i + 1}", hostname=sid.lower()))
    for e in range(n_edges):
        a, b = rng.choice(sids), rng.choice(sids)
        if a == b:
            continue
        trusted = rng.random() < 0.2
        sap_all = (not trusted) and rng.random() < 0.4
        tested = rng.random() < 0.6
        logon_ok = rng.random() < 0.7
        state.add_connection(RFCConnection(
            source_sid=a, source_host=a.lower(), target_sid=b, target_host=b.lower(),
            destination_name=f"D_{a}_{b}_{e}", rfc_user="RFC",
            has_sap_all=sap_all, trusted_system=trusted,
            tested=tested, logon_successful=logon_ok))
    return state


class TestRandomizedDifferential:

    def test_blast_matches_reference_and_inverse(self):
        import random
        rng = random.Random(20260197)   # fixed seed -> deterministic
        for _ in range(200):
            n = rng.randint(2, 6)
            state = _random_state(rng, n, rng.randint(1, 10))
            depth = rng.randint(1, 6)
            sids = list(state.nodes.keys())
            start = rng.choice(sids)

            got = blast_radius(state, start, depth)
            ref = _reference_reach(state, start, depth)
            # same reachable set
            assert set(got["nodes"]) == set(ref), (
                f"set mismatch start={start} depth={depth} "
                f"got={set(got['nodes'])} ref={set(ref)}")
            # same shortest-reach distance per node
            for sid, meta in got["nodes"].items():
                assert meta["hop"] == ref[sid], (
                    f"hop mismatch {sid}: got {meta['hop']} ref {ref[sid]}")

            # forward flood and inverse cone are mutually consistent
            for j in sids:
                if j == start:
                    continue
                in_reach = j in got["nodes"]
                in_cone = start in exposure_cone(state, j, depth)["nodes"]
                assert in_reach == in_cone, (
                    f"equiv mismatch start={start} j={j} depth={depth}")


# ---------------------------------------------------------------------------
# GUI route surface (static-source pins, matching the repo's route-test idiom)
# ---------------------------------------------------------------------------

class TestBlastRadiusRoute:

    @staticmethod
    def _gui_src():
        import pathlib
        root = pathlib.Path(__file__).resolve().parent.parent
        return (root / "modules" / "core" / "sapmap_gui.py").read_text(
            encoding="utf-8")

    def test_route_registered(self):
        src = self._gui_src()
        assert '@app.route("/api/actions/blast_radius", method="POST")' in src
        assert "def actions_blast_radius():" in src

    def test_route_reads_params_and_clamps_depth(self):
        src = self._gui_src()
        assert 'data.get("sid")' in src
        assert 'data.get("mode")' in src
        assert 'data.get("max_depth"' in src
        assert "max(1, min(max_depth, 12))" in src

    def test_route_dispatches_both_modes(self):
        src = self._gui_src()
        assert "sapmap_chain.blast_radius(api.state, sid, max_depth)" in src
        assert "sapmap_chain.exposure_cone(api.state, sid, max_depth)" in src
