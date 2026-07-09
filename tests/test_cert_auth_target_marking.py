"""Cert-auth kernel-proxy: target-node status marking.

When the auto-probe (or the manual button) succeeds against a
cert-authenticated destination, the TARGET node should visibly
change on the map so the operator sees at a glance where the SAP
system's X.509 identity actually landed.

Two distinct target states, driven by the returned HTTP status:

  2xx  → target ``pwned=True`` + ``has_critical_finding=True``
         → red border (same as GW-exploit / SCC-cracked targets)
         → CRITICAL finding

  4xx / 5xx / other → target ``cert_auth_trusted=True`` (new flag)
                     → purple border (transport-trust breach only)
                     → HIGH finding

These tests pin the model side of that contract — the frontend
styling lives in sapmap_html.py and is exercised manually.
"""
from __future__ import annotations

import modules  # noqa: F401  (registers package paths)
from sapmap_models import SAPNode, BTPSubaccountNode


# ---------------------------------------------------------------------------
# SAPNode: new cert_auth_trusted flag round-trips
# ---------------------------------------------------------------------------

def test_sapnode_defaults_cert_auth_trusted_to_false():
    """A fresh SAPNode must NOT be cert-trusted — the flag only
    ever flips True after an explicit kernel-proxy probe returned
    a 4xx.  If this defaulted to True, every BTPDISC placeholder
    would render with a purple border out of the gate."""
    n = SAPNode(sid="BTPDISC_TEST")
    assert n.cert_auth_trusted is False


def test_sapnode_cert_auth_trusted_survives_save_load():
    """Session save/load must preserve the cert-auth-trusted
    marker or the state file would silently lose the visual
    indicator on every reload."""
    src = SAPNode(sid="BTPDISC_TEST", cert_auth_trusted=True)
    d = src.to_dict()
    assert d["cert_auth_trusted"] is True
    restored = SAPNode.from_dict(d)
    assert restored.cert_auth_trusted is True


def test_sapnode_pwned_wins_visually_over_cert_auth_trusted():
    """If a target is BOTH pwned and cert-trusted (2xx probe fired
    later replaced an earlier 4xx), the red pwned state MUST win
    over the purple cert-trusted state.  The frontend sanity check
    (sapmap_html.py) uses an ``if pwned … else if cert_auth_trusted
    …`` cascade — this test pins the model side of the contract:
    both flags being True is a legal, expected state."""
    n = SAPNode(sid="BTPDISC_TEST",
                cert_auth_trusted=True, pwned=True,
                has_critical_finding=True)
    d = n.to_dict()
    assert d["pwned"] is True
    assert d["cert_auth_trusted"] is True
    restored = SAPNode.from_dict(d)
    assert restored.pwned is True
    assert restored.cert_auth_trusted is True


# ---------------------------------------------------------------------------
# BTPSubaccountNode: same flags mirrored
# ---------------------------------------------------------------------------

def test_resolve_probe_target_finds_btp_tenant_by_hostname():
    """Regression pin for the "target stayed blue" bug (2026-07-09).

    BTP tenants are stored in ``state.btp_subaccounts`` keyed by
    full hostname (e.g. ``api.eu1.hana.ondemand.com``), NOT in
    ``state.nodes``.  The bare ``state.get_node(conn.target_sid)``
    lookup missed them, so a CRITICAL finding fired but the target
    tenant never flipped red.  ``_resolve_probe_target`` must
    check both dicts."""
    import sys, os
    sys.path.insert(0, os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")))
    from modules.core.sapmap_gui import _resolve_probe_target
    from sapmap_models import (
        SAPMAPState, BTPSubaccountNode, RFCConnection)

    state = SAPMAPState()
    tenant_uuid = "api.eu1.hana.ondemand.com"
    state.btp_subaccounts[tenant_uuid] = BTPSubaccountNode(
        uuid=tenant_uuid,
        display_name="api",
        subdomain="api",
        region="eu1")
    conn = RFCConnection(
        source_sid="AE1", source_host="10.10.1.6",
        destination_name="TEST_MARCH", rfc_type="G",
        conn_type="http", http_auth_type="X509",
        http_cert_pse="DFAULT",
        http_url="https://api.eu1.hana.ondemand.com",
        target_sid=tenant_uuid)

    tgt = _resolve_probe_target(state, conn)
    assert tgt is not None, (
        "expected the BTP subaccount lookup to succeed — state."
        "get_node alone would have returned None here")
    assert tgt.uuid == tenant_uuid


def test_resolve_probe_target_falls_back_to_hostname_match():
    """Even when the connection has no target_sid yet (pre-ping),
    the helper must still find the BTP tenant by parsing the URL.
    Prevents the "clicked Probe Cert-Auth before Retrieve RFCs
    finished" edge case."""
    import sys, os
    sys.path.insert(0, os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")))
    from modules.core.sapmap_gui import _resolve_probe_target
    from sapmap_models import (
        SAPMAPState, BTPSubaccountNode, RFCConnection)

    state = SAPMAPState()
    tenant_uuid = "api.eu1.hana.ondemand.com"
    state.btp_subaccounts[tenant_uuid] = BTPSubaccountNode(
        uuid=tenant_uuid, display_name="api")
    conn = RFCConnection(
        source_sid="AE1", source_host="10.10.1.6",
        destination_name="TEST_MARCH", rfc_type="G",
        conn_type="http", http_auth_type="X509",
        http_url="https://api.eu1.hana.ondemand.com",
        target_sid="")   # no target_sid → hostname fallback

    tgt = _resolve_probe_target(state, conn)
    assert tgt is not None
    assert tgt.uuid == tenant_uuid


def test_resolve_probe_target_finds_regular_sapnode():
    """SAPNode targets (BTPDISC_ placeholders, real ABAP systems)
    must still resolve — the fix mustn't break the pre-existing
    lookup path."""
    import sys, os
    sys.path.insert(0, os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")))
    from modules.core.sapmap_gui import _resolve_probe_target
    from sapmap_models import (
        SAPMAPState, SAPNode, RFCConnection)

    state = SAPMAPState()
    state.nodes["SB1"] = SAPNode(sid="SB1", ip="172.31.14.107")
    conn = RFCConnection(
        source_sid="AE1", source_host="10.10.1.6",
        destination_name="AE1_TO_SB1", rfc_type="3",
        target_sid="SB1")

    tgt = _resolve_probe_target(state, conn)
    assert tgt is not None
    assert tgt.sid == "SB1"


def test_btp_subaccount_node_carries_cert_auth_flags():
    """BTP subaccount tenants may also become the target of a
    kernel-proxied cert-auth probe (when SM59 destinations to
    api.eu*.hana.ondemand.com map to a real subaccount).  The
    model must carry the same flags so the frontend can style
    cloud nodes consistently with on-prem BTPDISC placeholders."""
    src = BTPSubaccountNode(
        uuid="76335d2d-b312-4d30-97d8-71f0",
        cert_auth_trusted=True,
        has_critical_finding=True)
    d = src.to_dict()
    assert d["cert_auth_trusted"] is True
    assert d["has_critical_finding"] is True
    restored = BTPSubaccountNode.from_dict(d)
    assert restored.cert_auth_trusted is True
    assert restored.has_critical_finding is True
