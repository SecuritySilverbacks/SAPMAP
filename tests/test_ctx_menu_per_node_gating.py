#!/usr/bin/env python3
"""Tests for per-node right-click ctx-menu entries that must be gated
on landscape state (operator feedback 2026-10-08).

Two entries previously appeared on every freshly-plotted node even when
they couldn't do anything useful:

1. "Spray Harvested Credentials" (data-action="password_spray") —
   appeared before any credentials had been harvested anywhere in the
   landscape, so clicking it opened a spray config that would try an
   empty pool.
2. "Set 10KBLAZE Attacker IP (NAT override)..." (data-action=
   "set_attacker_ip") — appeared before Check MS Betrusted had been
   run, so clicking it stored an override for a chain that could not
   fire.

Fix: both actions are added to the `hidden` dict inside showCtxMenu
with specific gating:

  password_spray:  hidden unless the landscape pool has at least one
                   candidate (any node credentials with a password,
                   any secstore_entries, any BTP subaccount, any SCC
                   node).  Operator-wordlist-only pools still read as
                   empty here because wordlists live server-side; the
                   top-nav Actions > Spray entry (data-action=
                   "map_password_spray") has NO such gate and remains
                   the way to drive a wordlist-only spray.

  set_attacker_ip: hidden unless n.ms_vulnerable is True (set by
                   check_ms_betrusted when the MS internal port
                   accepts an unauth LOGIN_2).

Both tests are source-level — the ctx-menu logic is JS and runs in a
browser, so we pin the gating expression in the Python-served HTML.
"""
from __future__ import annotations

import re

import pytest


def _html():
    import sapmap_html
    return sapmap_html.get_html()


# ===========================================================================
# password_spray — hidden unless pool has candidates
# ===========================================================================

def test_hasSprayCandidates_predicate_is_defined():
    """`hasSprayCandidates` must be computed inside showCtxMenu, before
    the `hidden` dict uses it.  Pin the IIFE that walks nodes +
    landscape-wide pool sources."""
    html = _html()
    # The IIFE assignment line
    assert "const hasSprayCandidates = (() => {" in html, (
        "hasSprayCandidates predicate missing from showCtxMenu — "
        "per-node Spray entry needs this gate")
    # Walks node credentials + secstore_entries + landscape BTP + SCC
    # Capture the IIFE body for sub-assertions
    m = re.search(
        r"const hasSprayCandidates = \(\(\) => \{(.*?)\}\)\(\);",
        html, re.DOTALL)
    assert m, "hasSprayCandidates IIFE body not found"
    body = m.group(1)
    assert "credentials" in body, (
        "Pool predicate must inspect node.credentials")
    assert "password" in body, (
        "Pool predicate must check for password on credentials "
        "(not just verified flag — operator may have unverified "
        "candidates worth spraying)")
    assert "secstore_entries" in body, (
        "Pool predicate must inspect node.secstore_entries")
    assert "btp_subaccounts" in body, (
        "Pool predicate must inspect landscape-wide BTP subaccounts")
    assert "scc_nodes" in body, (
        "Pool predicate must inspect landscape-wide SCC nodes")


def test_hasSprayCandidates_requires_both_username_and_password():
    """Operator feedback 2026-10-08: the first version of this
    predicate was too loose — any SCC or BTP presence flipped the
    gate on, even when neither had stored creds.  Backend's
    landscape_password_pool (modules/discovery/sapmap_pwspray.py
    _add() helper) only counts a candidate when BOTH username AND
    password are present; mirror that gate here."""
    m = re.search(
        r"const hasSprayCandidates = \(\(\) => \{(.*?)\}\)\(\);",
        _html(), re.DOTALL)
    assert m, "hasSprayCandidates IIFE body not found"
    body = m.group(1)
    # SCC walk must check credential.username AND credential.password
    # (not just scc_nodes.length).  Pin: both terms appear in a
    # .some() check against .credentials
    assert "sn.credentials" in body or "scc.credentials" in body, (
        "SCC walk must dive into sn.credentials[] — just checking "
        "scc_nodes presence is the pre-tightening regression")
    assert "c.username && c.password" in body or (
        "c && c.username" in body and "c.password" in body), (
        "SCC/node credential walk must require BOTH username and "
        "password (matches backend _add() gate)")
    # BTP walk must check destination.user AND destination.password
    assert "sub.destinations" in body, (
        "BTP walk must dive into sub.destinations[] — just checking "
        "btp_subaccounts presence is the pre-tightening regression")
    assert "d.user && d.password" in body or (
        "d && d.user" in body and "d.password" in body), (
        "BTP destination walk must require BOTH user and password "
        "(matches backend _add() gate)")


def test_hasSprayCandidates_skips_scc_kind_in_node_credentials():
    """Backend pool-builder explicitly skips node.credentials entries
    with kind='scc' (they belong in the SCC bucket, not the node
    bucket).  Mirror that skip in the frontend predicate so we don't
    double-count an SCC credential that was mis-attached to a node."""
    m = re.search(
        r"const hasSprayCandidates = \(\(\) => \{(.*?)\}\)\(\);",
        _html(), re.DOTALL)
    body = m.group(1)
    assert '!== "scc"' in body or "!== 'scc'" in body, (
        "node.credentials walk must skip kind='scc' entries "
        "(backend pool-builder skips them too — they count in the "
        "SCC bucket instead)")


def test_hasSprayCandidates_secstore_requires_oauth2_client_category():
    """Backend only counts secstore_entries with
    category='oauth2_client' (OA2C client secrets with cleartext
    password); other secstore entries aren't spray-usable creds.
    Mirror that filter in the frontend predicate."""
    m = re.search(
        r"const hasSprayCandidates = \(\(\) => \{(.*?)\}\)\(\);",
        _html(), re.DOTALL)
    body = m.group(1)
    assert '"oauth2_client"' in body or "'oauth2_client'" in body, (
        "secstore walk must filter on category='oauth2_client' — "
        "counting ALL secstore_entries would re-introduce the loose "
        "gate (operator has a dumped SecStore with 300 entries but "
        "none are OA2C creds → entry still shows)")


def _hidden_dict_body(html: str) -> str:
    """Isolate the `const hidden = {...}` block inside showCtxMenu so
    assertions don't accidentally match a same-named key in the sibling
    `rules` dict (both have 'password_spray':)."""
    m = re.search(r"const hidden = \{(.*?)\};", html, re.DOTALL)
    assert m, "const hidden = { ... } block not found in HTML"
    return m.group(1)


def test_password_spray_hidden_gate_includes_pool_check():
    """`hidden['password_spray']` must OR in `!hasSprayCandidates`
    alongside the existing `!isAbapStack` gate.  Fixed form:
      !isAbapStack || !hasSprayCandidates
    """
    hidden_body = _hidden_dict_body(_html())
    pat = re.compile(
        r"'password_spray':\s*([^,\n]+)",
        re.DOTALL)
    m = pat.search(hidden_body)
    assert m, "hidden['password_spray'] key not found in hidden dict"
    expr = m.group(1).strip()
    assert "!isAbapStack" in expr, (
        f"password_spray hidden gate lost the ABAP-stack check: {expr!r}")
    assert "!hasSprayCandidates" in expr, (
        f"password_spray hidden gate must also check hasSprayCandidates "
        f"so freshly-plotted nodes without any pool items don't see the "
        f"spray entry.  Current gate: {expr!r}")


def test_map_password_spray_landscape_entry_NOT_gated_on_candidates():
    """The MAP-background entry (data-action="map_password_spray")
    opens the config modal where operators can paste a wordlist to
    seed the pool — it must stay visible even when the pool is empty
    so wordlist-only workflows keep working.  Pin that no gate on
    hasSprayCandidates was accidentally added for the map entry."""
    html = _html()
    # map_password_spray appears in the map ctx-menu HTML — look for
    # its div.  The map ctx-menu is a static template (no per-node
    # show/hide logic), so there should be no hidden/rule gate for it.
    assert 'data-action="map_password_spray"' in html, (
        "map ctx-menu entry for landscape spray not found")
    # Guard: `hidden[...] = ... hasSprayCandidates ...` should NOT
    # also apply to the map action.  (The map action isn't in the
    # per-node `hidden` dict, so this is a defensive check.)
    assert "'map_password_spray'" not in re.search(
        r"const hidden = \{(.*?)\};", html, re.DOTALL
    ).group(1), (
        "map_password_spray must NOT be added to the per-node hidden "
        "dict — it's a map-background entry with no gating.")


# ===========================================================================
# set_attacker_ip — hidden unless MS is vulnerable on this node
# ===========================================================================

def test_set_attacker_ip_hidden_gate_requires_ms_vulnerable():
    """`hidden['set_attacker_ip']` must be `!hasMsVuln`.  Without this,
    the entry appears on every freshly-plotted node before Check MS
    Betrusted has fired — leading operators to configure an override
    for a chain that can't run."""
    hidden_body = _hidden_dict_body(_html())
    pat = re.compile(
        r"'set_attacker_ip':\s*([^,\n]+)",
        re.DOTALL)
    m = pat.search(hidden_body)
    assert m, (
        "hidden['set_attacker_ip'] key not found in showCtxMenu — "
        "per-node 'Set 10KBLAZE Attacker IP' entry has no hide gate")
    expr = m.group(1).strip()
    assert "!hasMsVuln" in expr, (
        f"set_attacker_ip hidden gate must be '!hasMsVuln' so the "
        f"entry only appears after check_ms_betrusted flips "
        f"ms_vulnerable=True.  Current gate: {expr!r}")


def test_set_attacker_ip_ctx_item_exists_and_hasnt_been_removed():
    """Pin that the per-node ctx-item for `set_attacker_ip` is still
    present in the HTML template — hiding it when !hasMsVuln is a
    gating change, not a removal."""
    html = _html()
    assert 'data-action="set_attacker_ip"' in html, (
        "data-action='set_attacker_ip' ctx-item must still be present "
        "in the HTML — it is HIDDEN until ms_vulnerable, not removed")


def test_hasMsVuln_predicate_still_defined():
    """The hidden gate for set_attacker_ip depends on `hasMsVuln`
    being computed in the same scope.  Pin that showCtxMenu still
    defines it.  Breaks loudly if someone deletes or renames the
    predicate without updating the hidden dict."""
    html = _html()
    assert "const hasMsVuln = n && n.ms_vulnerable;" in html, (
        "hasMsVuln predicate missing or renamed — set_attacker_ip "
        "hidden gate depends on it")


# ===========================================================================
# Regression: existing dispatcher gate on password_spray stays intact
# ===========================================================================

def test_password_spray_rules_still_require_dispatcher():
    """The disabled-state gate `rules['password_spray'] = hasDispPort`
    must stay in place — on an ABAP node with pool but no 32XX
    dispatcher reachable, the entry still shows but is greyed out.
    Operator keeps the explanatory tooltip."""
    html = _html()
    pat = re.compile(
        r"'password_spray':\s*hasDispPort",
        re.DOTALL)
    assert pat.search(html), (
        "rules['password_spray'] = hasDispPort gate lost — spray needs "
        "a DIAG dispatcher regardless of pool state")
