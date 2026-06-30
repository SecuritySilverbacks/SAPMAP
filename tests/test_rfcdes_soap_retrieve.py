"""Tests for the SOAP-RFC variants of retrieve_rfc_connections /
retrieve_rfctrust / retrieve_rfcsysacl.

These exercise the row-parsing contract — same RFCConn + dict shapes
as the pyrfc paths — so the GUI handler can dispatch to either
transport without callers caring which one ran.

Mock SOAPRFCSession.read_table to return canned rows.  The actual
SOAP wire format is covered by tests/test_soap_rfc_session.py.
"""
from __future__ import annotations

import modules  # noqa: F401  registers package paths
import sapmap_rfc
from sapmap_models import SAPNode


class _MockSoapSession:
    """Minimal stand-in: returns whatever was preconfigured for each
    table name.  Records what was requested so tests can assert."""

    def __init__(self, replies: dict):
        self._replies = replies
        self.calls = []

    def read_table(self, table, fields=None, where=None,
                    max_rows=0, delimiter="|"):
        self.calls.append({
            "table": table, "fields": fields, "where": where,
            "max_rows": max_rows,
        })
        return self._replies.get(table, {
            "ok": False, "rows": [], "fields": [],
            "error": f"no mock reply for {table}"})


def _node():
    return SAPNode(sid="W74", system_type="ABAP",
                   hostname="WINWAS74", ip="192.168.2.29")


# ---------------------------------------------------------------------------
# RFCDES — Type-3 + Type-G/H discovery
# ---------------------------------------------------------------------------

def test_retrieve_rfc_connections_via_soap_filters_to_3_g_h():
    """The OPTIONS where-clause must restrict to RFCTYPE in {3, G, H}.
    Sending '' or no OPTIONS at all would pull every RFCDES row including
    Type-T (TCP/IP sapxpg), Type-L (logical) and others we don't want."""
    sess = _MockSoapSession({
        "RFCDES": {"ok": True, "rows": [], "fields": [], "error": ""}
    })
    sapmap_rfc.retrieve_rfc_connections_via_soap(_node(), sess)
    where = sess.calls[0]["where"]
    assert any("RFCTYPE = '3'" in w for w in where)
    assert any("RFCTYPE = 'G'" in w for w in where)
    assert any("RFCTYPE = 'H'" in w for w in where)


def test_retrieve_rfc_connections_via_soap_skips_type_gh_without_pwd():
    """Type-G/H destinations without %_PWD marker can't be turned into
    a credential — drop them to avoid polluting the map with rows the
    SecStore harvester will never reach."""
    sess = _MockSoapSession({"RFCDES": {"ok": True, "rows": [
        # Type-G WITH %_PWD — keep
        {"RFCDEST": "TO_BTP",  "RFCTYPE": "G",
         "RFCOPTIONS": "H=auth.eu10.hana.ondemand.com,S=443,"
                       "M=/oauth/token,Q=Y,U=svc,T=%_PWD"},
        # Type-G WITHOUT %_PWD — drop
        {"RFCDEST": "NO_PWD",  "RFCTYPE": "G",
         "RFCOPTIONS": "H=other.example.com,S=443,M=/api,Q=Y,U=svc"},
        # Type-3 always kept (trusted RFC has no %_PWD either)
        {"RFCDEST": "TO_PRD",  "RFCTYPE": "3",
         "RFCOPTIONS": "H=prd,S=00,M=001,U=joris"},
    ], "fields": [], "error": ""}})
    conns = sapmap_rfc.retrieve_rfc_connections_via_soap(_node(), sess)
    names = [c.destination_name for c in conns]
    assert "TO_BTP" in names
    assert "NO_PWD" not in names
    assert "TO_PRD" in names


def test_retrieve_rfc_connections_via_soap_marks_trusted_q_y():
    """Type-3 with Q=Y in options is a trusted-RFC destination — the
    SOAP path must set trusted_system=True the same way the pyrfc one
    does (via _rfcdes_is_trusted).  Without this, ATT&CK heatmap loses
    its trusted-RFC indicator on HTTP-only-discovered targets."""
    sess = _MockSoapSession({"RFCDES": {"ok": True, "rows": [
        {"RFCDEST": "PRD_TRUSTED", "RFCTYPE": "3",
         "RFCOPTIONS": "H=prdhost,S=00,M=001,U=svc,Q=Y"},
        {"RFCDEST": "DEV_NORMAL",  "RFCTYPE": "3",
         "RFCOPTIONS": "H=devhost,S=01,M=100,U=joris,T=%_PWD"},
    ], "fields": [], "error": ""}})
    conns = sapmap_rfc.retrieve_rfc_connections_via_soap(_node(), sess)
    by_name = {c.destination_name: c for c in conns}
    assert by_name["PRD_TRUSTED"].trusted_system is True
    assert by_name["PRD_TRUSTED"].trust_type == "trusted_rfc"
    assert by_name["DEV_NORMAL"].trusted_system is False


def test_retrieve_rfc_connections_via_soap_returns_empty_on_read_failure():
    """When the read_table call fails (S_TABU_DIS missing, table empty,
    transport error), the SOAP path must surface ok=False as an empty
    list — same shape as the pyrfc path's exception fallthrough."""
    sess = _MockSoapSession({"RFCDES": {
        "ok": False, "rows": [], "fields": [],
        "error": "RFC_AUTHORIZATION_FAILURE",
    }})
    conns = sapmap_rfc.retrieve_rfc_connections_via_soap(_node(), sess)
    assert conns == []


# ---------------------------------------------------------------------------
# RFCTRUST — outbound trust list
# ---------------------------------------------------------------------------

def test_retrieve_rfctrust_via_soap_normalises_dict_shape():
    """RFCTRUST returns 5 columns; the SOAP helper must produce dicts
    with the same lowercase keys (rfctrustid / rfctrustsy / etc.) the
    pyrfc path produces — call sites filter on those keys."""
    sess = _MockSoapSession({"RFCTRUST": {"ok": True, "rows": [
        {"RFCTRUSTID": "TWT", "RFCTRUSTSY": "S4H",
         "TLICENSE_NR": "0000000123", "LLICENSE_NR": "0000000456",
         "RFCMSGSRV": ""},
        {"RFCTRUSTID": "PRD", "RFCTRUSTSY": "S4H",
         "TLICENSE_NR": "0000000789", "LLICENSE_NR": "0000000000",
         "RFCMSGSRV": ""},
    ], "fields": [], "error": ""}})
    entries = sapmap_rfc.retrieve_rfctrust_via_soap(_node(), sess)
    assert len(entries) == 2
    assert entries[0]["rfctrustid"] == "TWT"
    assert entries[0]["rfctrustsy"] == "S4H"
    assert entries[1]["rfctrustid"] == "PRD"


def test_retrieve_rfctrust_via_soap_drops_empty_target_rows():
    """RFCTRUST often contains soft-deleted rows with empty RFCTRUSTID;
    these would crash the trust-chain analysis if propagated as targets."""
    sess = _MockSoapSession({"RFCTRUST": {"ok": True, "rows": [
        {"RFCTRUSTID": "TWT", "RFCTRUSTSY": "S4H"},
        {"RFCTRUSTID": "",    "RFCTRUSTSY": "S4H"},
        {"RFCTRUSTID": "PRD", "RFCTRUSTSY": "S4H"},
    ], "fields": [], "error": ""}})
    entries = sapmap_rfc.retrieve_rfctrust_via_soap(_node(), sess)
    assert [e["rfctrustid"] for e in entries] == ["TWT", "PRD"]


def test_retrieve_rfctrust_via_soap_handles_auth_quietly():
    """NOT_AUTHORIZED / TABLE_WITHOUT_DATA returns empty list without
    printing a scary [-] error — same UX as pyrfc path's [*] message."""
    sess = _MockSoapSession({"RFCTRUST": {
        "ok": False, "rows": [], "fields": [],
        "error": "NOT_AUTHORIZED for RFCTRUST",
    }})
    entries = sapmap_rfc.retrieve_rfctrust_via_soap(_node(), sess)
    assert entries == []


# ---------------------------------------------------------------------------
# RFCSYSACL — inbound trusted-caller list
# ---------------------------------------------------------------------------

def test_retrieve_rfcsysacl_via_soap_decodes_rfcequser_flag():
    """RFCEQUSER='Y' is the passwordless-lateral-movement indicator.
    The SOAP path must preserve it byte-for-byte; downstream attack-
    chain analysis branches on it."""
    sess = _MockSoapSession({"RFCSYSACL": {"ok": True, "rows": [
        {"RFCSYSID": "S4H", "RFCCLIENT": "100",
         "RFCEQUSER": "Y", "RFCUSER": "", "RFCSNC": "",
         "RFCSAMEUSR": ""},
        {"RFCSYSID": "DEV", "RFCCLIENT": "001",
         "RFCEQUSER": "N", "RFCUSER": "SVC_USER", "RFCSNC": "",
         "RFCSAMEUSR": ""},
    ], "fields": [], "error": ""}})
    entries = sapmap_rfc.retrieve_rfcsysacl_via_soap(_node(), sess)
    eq_y = [e for e in entries if e["rfcequser"] == "Y"]
    assert len(eq_y) == 1
    assert eq_y[0]["rfcsysid"] == "S4H"
    assert eq_y[0]["rfcclient"] == "100"


def test_retrieve_rfcsysacl_via_soap_drops_empty_rfcsysid_rows():
    """Same defensive filter as RFCTRUST — empty RFCSYSID is a stale
    row that would break inbound-trust-graph rendering."""
    sess = _MockSoapSession({"RFCSYSACL": {"ok": True, "rows": [
        {"RFCSYSID": "S4H", "RFCCLIENT": "100", "RFCEQUSER": "Y"},
        {"RFCSYSID": "",    "RFCCLIENT": "000", "RFCEQUSER": "N"},
    ], "fields": [], "error": ""}})
    entries = sapmap_rfc.retrieve_rfcsysacl_via_soap(_node(), sess)
    assert [e["rfcsysid"] for e in entries] == ["S4H"]
