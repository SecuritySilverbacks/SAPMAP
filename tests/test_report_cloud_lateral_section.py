"""Report: dedicated 'Cloud ↔ on-prem lateral moves' section.

Rolls up cert-auth mints, BTP destination pulls, and BTP→on-prem
credential captures into one exec-friendly narrative in the
engagement report.  The individual BTP-subaccount table, cleartext-
credentials table, and cert-auth-destinations table each show
FRAGMENTS of the chain in isolation — this section names the
whole chain.

Pinned invariants:

  * A landscape with no BTP presence produces no cloud-lateral
    section (no hollow header).
  * A landscape with BTP subaccounts but no destinations captured
    also produces no section (enumeration hasn't happened yet).
  * The section renders when destinations exist AND/or mint
    findings exist.
  * Back-edges table lists rfc_user / SAP_ALL flag / test outcome.
  * Password-reuse callout fires when the same secstore_password
    unlocks multiple (user, target) pairs — this is the biggest
    finding on a typical BTP lateral.
"""
from __future__ import annotations

import modules  # noqa: F401
from sapmap_models import (
    SAPMAPState, SAPNode, RFCConnection, BTPSubaccountNode)
from sapmap_report import _cloud_lateral_section


# ---------------------------------------------------------------------------
# Empty-landscape cases
# ---------------------------------------------------------------------------

def test_no_btp_subaccounts_returns_empty():
    """A landscape with no BTP presence gets no section at all."""
    assert _cloud_lateral_section(SAPMAPState()) == []


def test_btp_subaccount_with_no_destinations_returns_empty():
    """A subaccount SAPMAP knows about only through a placeholder
    (URL materialisation) but never enumerated shouldn't drag a
    hollow 'Cloud ↔ on-prem lateral moves' header into the
    report."""
    state = SAPMAPState()
    state.btp_subaccounts["sub.example.hana.ondemand.com"] = (
        BTPSubaccountNode(
            uuid="sub.example.hana.ondemand.com",
            subdomain="sub", region="eu10", destinations=[]))
    assert _cloud_lateral_section(state) == []


# ---------------------------------------------------------------------------
# Happy path — the shape from the live run
# ---------------------------------------------------------------------------

def _live_shape_state():
    """Reproduce the operator's 2026-07-12 state: subaccount
    researchlab-yehctg7m, 2 back-edges to on-prem (W74 sapadm +
    S4H joris), same siroj1978! password across both."""
    state = SAPMAPState()

    # BTP subaccount
    sub = BTPSubaccountNode(
        uuid="90a90189-8c94-44ff-9f76-b50a42c0fd98",
        subdomain="researchlab-yehctg7m",
        region="eu10")
    # 4 destinations, 4 cleartext, 4 linked to on-prem
    class _Dest:
        def __init__(self, name, cleartext, linked_sid):
            self.name = name
            self.cleartext_captured = cleartext
            self.linked_target_sid = linked_sid
    sub.destinations = [
        _Dest("W74", True, "W74"),
        _Dest("BTP_to_S4H", True, "S4H"),
        _Dest("Test_Joris", True, "S4H"),
        _Dest("DemoDest", True, "S4H"),
    ]
    state.btp_subaccounts[sub.uuid] = sub

    # On-prem nodes
    state.nodes["W74"] = SAPNode(sid="W74", ip="192.168.2.29",
                                    hostname="WINWAS74",
                                    system_type="ABAP")
    state.nodes["S4H"] = SAPNode(sid="S4H", ip="192.168.2.209",
                                    hostname="s4hanadev",
                                    system_type="ABAP")

    # BTP→on-prem back-edges — post-sweep, SAP_ALL confirmed
    state.connections.append(RFCConnection(
        source_sid="BTP:90a90189",
        source_host="researchlab-yehctg7m",
        destination_name="W74",
        rfc_type="3", conn_type="rfc",
        target_sid="W74",
        rfc_user="sapadm",
        secstore_password="siroj1978!",
        client="001",
        tested=True, logon_successful=True, has_sap_all=True))
    state.connections.append(RFCConnection(
        source_sid="BTP:90a90189",
        source_host="researchlab-yehctg7m",
        destination_name="BTP_to_S4H",
        rfc_type="3", conn_type="rfc",
        target_sid="S4H",
        rfc_user="joris",
        secstore_password="siroj1978!",   # password reuse!
        client="001",
        tested=True, logon_successful=True, has_sap_all=True))
    return state


def test_live_shape_emits_section_with_header():
    md = "\n".join(_cloud_lateral_section(_live_shape_state()))
    assert "## Cloud ↔ on-prem lateral moves" in md


def test_live_shape_names_subaccount_and_region():
    md = "\n".join(_cloud_lateral_section(_live_shape_state()))
    assert "researchlab-yehctg7m" in md
    assert "eu10" in md


def test_live_shape_reports_destinations_cleartext_and_linked():
    md = "\n".join(_cloud_lateral_section(_live_shape_state()))
    # 4 destinations enumerated, 4 cleartext, 4 linked
    assert "4 destination(s) enumerated" in md
    assert "4 carrying cleartext credentials" in md
    assert "4 linked to on-prem" in md
    # Target SIDs enumerated
    assert "W74" in md
    assert "S4H" in md


def test_live_shape_reports_sap_all_count():
    md = "\n".join(_cloud_lateral_section(_live_shape_state()))
    # 2 back-edges both flagged has_sap_all
    assert "2 credential(s) confirmed with SAP_ALL" in md


def test_live_shape_flags_password_reuse():
    """siroj1978! unlocks both sapadm@W74 and joris@S4H — that's
    the biggest finding on this lateral.  The section calls it
    out explicitly."""
    md = "\n".join(_cloud_lateral_section(_live_shape_state()))
    assert "Password reuse detected" in md
    assert "sapadm" in md
    assert "joris" in md


def test_live_shape_back_edge_table_shape():
    md = "\n".join(_cloud_lateral_section(_live_shape_state()))
    # Back-edge table columns
    assert "| Destination | Target | User | Client | SAP_ALL? |" in md
    # SAP_ALL cell renders as ⚡ **yes** (Markdown bold + zap icon)
    assert "⚡ **yes**" in md
    # rfc_user cells rendered
    assert "`sapadm`" in md
    assert "`joris`" in md


def test_no_password_reuse_when_creds_are_distinct():
    """If two back-edges have different passwords (or one has no
    password at all), the reuse block must not fire — a false
    positive there would embarrass the report."""
    state = SAPMAPState()
    sub = BTPSubaccountNode(
        uuid="uuid1", subdomain="tenant", region="eu10")

    class _D:
        def __init__(self, name):
            self.name = name
            self.cleartext_captured = True
            self.linked_target_sid = "T"
    sub.destinations = [_D("A"), _D("B")]
    state.btp_subaccounts["uuid1"] = sub
    state.nodes["T"] = SAPNode(sid="T", system_type="ABAP")
    state.connections.append(RFCConnection(
        source_sid="BTP:uuid1", source_host="t",
        destination_name="A", rfc_type="3", conn_type="rfc",
        target_sid="T", rfc_user="u1",
        secstore_password="pwA"))
    state.connections.append(RFCConnection(
        source_sid="BTP:uuid1", source_host="t",
        destination_name="B", rfc_type="3", conn_type="rfc",
        target_sid="T", rfc_user="u2",
        secstore_password="pwB"))
    md = "\n".join(_cloud_lateral_section(state))
    assert "Password reuse detected" not in md
