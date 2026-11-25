#!/usr/bin/env python3
"""Issue #92 follow-up — ``SAPNode.forget_suppression`` (the 'forget' link).

After PR #229 shipped the durable *remove* + *restore* pair, a real-user
test caught the remaining limitation: once an instance is removed, the
only way back is restore (which re-adds the stale cached row) or
nothing (ban stays forever).  When the original removal was of a
MIS-ATTRIBUTED instance (e.g. port 443 on this host was wrongly folded
onto NN 01 because it actually belongs to a different SID), the
operator wants the ban cleared so a follow-up scan can re-discover
NN 01 from scratch — WITHOUT bringing the stale cached row back.

``forget_suppression`` is that third verb.  These tests pin:

  1. its semantics vs. ``unsuppress_instance`` (same ban clear, but
     NO row re-add — the deliberate difference);
  2. idempotency + safety on non-suppressed nrs;
  3. serialization neutrality (uses existing fields, no migration);
  4. isolation (forget on NN 01 doesn't touch NN 02);
  5. the real integration guard — after forget, a fresh re-discovery
     through ``SAPMAPState.add_node`` re-adds the instance normally;
  6. the no-touch rule on shared vuln scalars (same discipline as
     restore — forget must never materialise or clobber a finding);
  7. source-level wiring of the GUI route + HTML link + scripting
     action (same inspection pattern as test_instance_cleanup_92_surface).
"""
import sys
import os
import json
import inspect

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import modules  # noqa: F401 — registers package paths

from sapmap_models import InstanceInfo, SAPNode, SAPMAPState


def _node(sid="NPL", nrs=(("00", {3300: "gateway", 3200: "dispatcher"}),
                          ("04", {3304: "gateway"}))):
    n = SAPNode(sid=sid, hostname="h", ip="10.0.0.1")
    n.instances = [InstanceInfo(instance_nr=nr, ip="10.0.0.1", ports=dict(ports))
                   for nr, ports in nrs]
    return n


# ---------------------------------------------------------------------------
# Core semantics — the deliberate difference from unsuppress_instance
# ---------------------------------------------------------------------------

def test_forget_clears_ban_and_cache():
    n = _node()
    n.suppress_instance("04")
    assert "04" in n.suppressed_instance_nrs
    assert "04" in n.suppressed_instance_cache

    n.forget_suppression("04")

    assert n.suppressed_instance_nrs == set()
    assert n.suppressed_instance_cache == {}


def test_forget_does_not_touch_instances():
    """The headline semantic separating forget from unsuppress.  After
    suppress + forget, node.instances stays exactly as suppress left it
    — the removed row is NOT re-added (unlike unsuppress)."""
    n = _node()
    before = [i.instance_nr for i in n.instances]  # ['00', '04']
    n.suppress_instance("04")
    assert [i.instance_nr for i in n.instances] == ["00"]
    n.forget_suppression("04")
    assert [i.instance_nr for i in n.instances] == ["00"]
    assert "04" not in [i.instance_nr for i in n.instances]
    assert len(before) == 2  # sanity on the fixture


def test_forget_returns_was_suppressed_flag():
    """Matches the ``unsuppress_instance`` convention: True iff nr was
    previously in the ban set.  Gives the route + UI feedback on
    whether anything actually changed."""
    n = _node()
    n.suppress_instance("04")
    assert n.forget_suppression("04") is True
    # Second call: nr no longer suppressed → False
    assert n.forget_suppression("04") is False


def test_forget_is_idempotent():
    """Safe to call twice in a row — common race-y path when a poll
    refresh fires between the user clicking + the UI repaint."""
    n = _node()
    n.suppress_instance("04")
    n.forget_suppression("04")
    # Second forget: state unchanged, no exception.
    n.forget_suppression("04")
    assert n.suppressed_instance_nrs == set()
    assert n.suppressed_instance_cache == {}
    assert [i.instance_nr for i in n.instances] == ["00"]


def test_forget_on_never_suppressed_nr_is_noop():
    """Operator calls forget on an nr that was never suppressed.  No
    exception, returns False, state unchanged."""
    n = _node()
    assert n.forget_suppression("09") is False
    assert n.suppressed_instance_nrs == set()
    assert [i.instance_nr for i in n.instances] == ["00", "04"]


def test_forget_normalizes_nr():
    """'4' and '04' are the same nr — the normalizer handles both,
    matching suppress / unsuppress."""
    n = _node()
    n.suppress_instance("04")
    assert n.forget_suppression("4") is True          # non-padded input
    assert n.suppressed_instance_nrs == set()


def test_forget_accepts_pseudo_instance_sentinel():
    """XX / WD sentinels round-trip through forget just like real nrs."""
    n = _node(nrs=(("00", {}), ("XX", {})))
    n.suppress_instance("XX")
    assert n.is_instance_suppressed("XX")
    assert n.forget_suppression("XX") is True
    assert not n.is_instance_suppressed("XX")


# ---------------------------------------------------------------------------
# Isolation — forget on one nr must not touch another
# ---------------------------------------------------------------------------

def test_forget_one_nr_leaves_siblings_intact():
    n = _node()
    n.suppress_instance("00")
    n.suppress_instance("04")
    assert n.suppressed_instance_nrs == {"00", "04"}
    assert set(n.suppressed_instance_cache.keys()) == {"00", "04"}

    n.forget_suppression("04")

    assert "04" not in n.suppressed_instance_nrs
    assert "04" not in n.suppressed_instance_cache
    assert "00" in n.suppressed_instance_nrs
    assert "00" in n.suppressed_instance_cache


def test_restore_still_works_after_forget_of_sibling_nr():
    n = _node()
    n.suppress_instance("00")
    n.suppress_instance("04")
    n.forget_suppression("04")               # forget the sibling
    # Restore NN 00 → row comes back exactly as cached.
    assert n.unsuppress_instance("00") is True
    assert "00" in [i.instance_nr for i in n.instances]


# ---------------------------------------------------------------------------
# Serialization neutrality — uses existing fields, no migration
# ---------------------------------------------------------------------------

def test_forget_persists_through_roundtrip():
    """After suppress + forget, to_dict emits an empty suppression set +
    cache, and from_dict round-trips cleanly.  Forget leaves the
    .sapmap exactly as if the nr had never been suppressed."""
    n = _node()
    n.suppress_instance("04")
    n.forget_suppression("04")
    d = n.to_dict()
    assert d["suppressed_instance_nrs"] == []
    assert d["suppressed_instance_cache"] == {}
    r = SAPNode.from_dict(json.loads(json.dumps(d)))
    assert r.suppressed_instance_nrs == set()
    assert r.suppressed_instance_cache == {}


def test_forget_leaves_mixed_state_intact_for_sibling():
    """After forget on one nr + leaving another suppressed, the
    .sapmap carries exactly the surviving nr + its cached row."""
    n = _node()
    n.suppress_instance("00")
    n.suppress_instance("04")
    n.forget_suppression("04")               # forget only 04
    d = n.to_dict()
    assert d["suppressed_instance_nrs"] == ["00"]
    assert list(d["suppressed_instance_cache"].keys()) == ["00"]
    # And the cached row for 00 is intact + round-trips.
    r = SAPNode.from_dict(json.loads(json.dumps(d)))
    assert r.unsuppress_instance("00") is True
    assert "00" in [i.instance_nr for i in r.instances]


# ---------------------------------------------------------------------------
# The real integration guard — forget allows re-discovery
# ---------------------------------------------------------------------------

def test_forget_then_rediscovery_readds_instance():
    """The whole point of forget: after forget, a fresh scan may
    legitimately re-add the instance.  Proven here via the toughest
    producer path — a wholesale ``add_node`` replace (full-rediscovery
    style) — which otherwise re-prunes any nr still in the ban set."""
    st = SAPMAPState()
    orig = _node()
    orig.suppress_instance("04")
    st.add_node(orig)
    assert "04" in st.get_node("NPL").suppressed_instance_nrs

    # Operator clicks 'forget' on the live node.
    st.get_node("NPL").forget_suppression("04")

    # A full re-discovery builds a FRESH node (empty suppression) with
    # 04 back.  Without forget, add_node's carry-forward would re-prune
    # 04 again (that's the #229 durability guarantee); with forget, the
    # ban is gone and the fresh row survives.
    fresh = _node()                          # instances: [00, 04]
    st.add_node(fresh)

    got = st.get_node("NPL")
    assert got.suppressed_instance_nrs == set()
    assert [i.instance_nr for i in got.instances] == ["00", "04"]


def test_forget_then_scanner_record_instance_port_readds_row():
    """Same integration through a different (and realistic) producer:
    after forget, ``_record_instance_port`` is free to re-create the
    instance when a fresh port probe confirms one."""
    import sapmap_scanner
    n = _node(nrs=(("00", {}),))
    n.suppress_instance("04")
    # Baseline: suppressed → probe is skipped.
    sapmap_scanner._record_instance_port(n, "04", 3604, "ms")
    assert "04" not in [i.instance_nr for i in n.instances]

    n.forget_suppression("04")

    # After forget: the same probe now creates NN 04 cleanly.
    sapmap_scanner._record_instance_port(n, "04", 3604, "ms")
    assert "04" in [i.instance_nr for i in n.instances]


# ---------------------------------------------------------------------------
# The vuln-scalar discipline — forget never touches shared state
# ---------------------------------------------------------------------------

def test_forget_does_not_touch_gw_vuln_scalar():
    """Vuln scalars are shared node state, not per-instance.  Same
    discipline as restore (see suppress_instance docstring): forget
    must leave them exactly as the suppress call left them."""
    n = _node()
    n.gw_vulnerable = True
    n.gw_vulnerable_port = 3300             # scalar-only evidence
    n.suppress_instance("04")                # unrelated instance
    # suppress's reconciler left the scalar alone (3300 % 100 != 4).
    assert n.gw_vulnerable is True
    assert n.gw_vulnerable_port == 3300
    n.forget_suppression("04")
    assert n.gw_vulnerable is True           # still true
    assert n.gw_vulnerable_port == 3300      # still carries the port


def test_forget_does_not_restore_cleared_gw_vuln():
    """And the other direction: if suppress legitimately cleared the
    flag (the only locus was on the removed instance), forget must NOT
    resurrect it.  Only a re-scan may re-confirm a vuln."""
    n = _node(nrs=(("04", {3304: "gateway"}),))
    n.gw_vulnerable = True
    n.gw_vulnerable_port = 3304
    n.suppress_instance("04")                # suppress clears scalar + flag
    assert n.gw_vulnerable is False
    assert n.gw_vulnerable_port == 0
    n.forget_suppression("04")
    # Forget must not materialise the finding — still false, still 0.
    assert n.gw_vulnerable is False
    assert n.gw_vulnerable_port == 0


# ---------------------------------------------------------------------------
# Source-level wiring (same inspection pattern as _92_surface)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def gui_src():
    import sapmap_gui
    return inspect.getsource(sapmap_gui)


@pytest.fixture(scope="module")
def html():
    import sapmap_html
    return sapmap_html.get_html()


def _route_body(src, handler):
    start = src.find("def " + handler + "(")
    assert start != -1, "handler %s not found" % handler
    nxt = src.find("\n    @app.route", start)
    return src[start:(nxt if nxt != -1 else start + 2000)]


def _js_fn(html, name):
    start = html.find("function " + name + "(")
    assert start != -1, "JS function %s not found" % name
    nxt = html.find("\nfunction ", start + 1)
    return html[start:(nxt if nxt != -1 else start + 2000)]


class TestGUIRoute:

    def test_forget_route_defined(self, gui_src):
        assert '/api/node/<sid>/forget_suppression' in gui_src
        assert "def node_forget_suppression(sid):" in gui_src

    def test_forget_route_delegates_to_model(self, gui_src):
        body = _route_body(gui_src, "node_forget_suppression")
        assert "api.state.get_node(sid)" in body
        assert "node.forget_suppression(instance_nr)" in body
        assert '"forgotten"' in body
        assert '"remaining"' in body
        assert '"suppressed"' in body

    def test_forget_route_validates_instance_nr(self, gui_src):
        """Same stored-DOM-injection defence as remove/unsuppress."""
        body = _route_body(gui_src, "node_forget_suppression")
        assert "instance_nr.isalnum()" in body
        assert "len(instance_nr) <= 4" in body

    def test_forget_route_404_pattern(self, gui_src):
        body = _route_body(gui_src, "node_forget_suppression")
        assert 'f"Node {sid} not found"' in body

    def test_forget_route_does_not_touch_model_instances(self, gui_src):
        """The whole point of forget: the ROUTE must not invoke anything
        that re-adds a row (no suppress_instance, no unsuppress_instance,
        no direct .instances mutation).  Pin the handler body."""
        body = _route_body(gui_src, "node_forget_suppression")
        assert "node.unsuppress_instance(" not in body
        assert "node.suppress_instance(" not in body
        assert "node.instances.append" not in body
        assert "node.instances =" not in body


class TestHTMLSurface:

    def test_forget_link_rendered_on_suppressed_row(self, html):
        """The Suppressed row now carries BOTH restore and forget
        buttons, keyed off the same n.suppressed_instance_nrs list."""
        # row string must contain both onclicks in one template block
        assert "onclick=\"restoreInstance(" in html
        assert "onclick=\"forgetSuppression(" in html
        assert "suppressed_instance_nrs" in html

    def test_forget_js_handler_defined(self, html):
        assert "async function forgetSuppression(sid, instNr)" in html

    def test_forget_handler_route_and_confirm(self, html):
        body = _js_fn(html, "forgetSuppression")
        assert "node/${sid}/forget_suppression" in body
        # Confirm is mandatory (forget is final — restore stops working
        # for that NN once the cached row is discarded).
        assert "confirm(msg)" in body
        assert "Forget suppression of instance" in body
        assert "startPolling()" in body


# ---------------------------------------------------------------------------
# Scripting engine surface
# ---------------------------------------------------------------------------

def test_script_forget_suppression_action():
    import sapmap_script
    m = sapmap_script._map_step(
        {"action": "forget_suppression", "target": "S4H",
         "instance_nr": "04"})
    assert m == ("POST", "/api/node/S4H/forget_suppression",
                 {"instance_nr": "04"}, False)


def test_script_forget_suppression_requires_nr():
    import sapmap_script
    with pytest.raises(ValueError):
        sapmap_script._map_step(
            {"action": "forget_suppression", "target": "S4H"})


def test_script_forget_suppression_accepts_instance_alias():
    """``instance`` is accepted as an alias for ``instance_nr`` (matching
    the ``remove_instance`` action's own convention)."""
    import sapmap_script
    m = sapmap_script._map_step(
        {"action": "forget_suppression", "target": "S4H", "instance": "04"})
    assert m == ("POST", "/api/node/S4H/forget_suppression",
                 {"instance_nr": "04"}, False)


def test_script_forget_suppression_has_progress_label():
    import sapmap_script
    assert "forget_suppression" in sapmap_script._ACTION_LABELS


def test_script_forget_suppression_in_docstring():
    """Supported-actions docstring lists forget_suppression so operators
    find it via module help."""
    import sapmap_script
    assert "forget_suppression" in (sapmap_script.__doc__ or "")
