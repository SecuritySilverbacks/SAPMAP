#!/usr/bin/env python3
"""Tests for the SNC fields on DEST_RFC_TCPIP_CREATE — part 2 of #172.

Pre-#172 the destination was created with no SNC fields at all, so even
when the gateway port was right (part 1) the registered-program
connection it would make was non-SNC and the SNC-enforcing gateway
refused it (SDEST E 017 at use).  Field names + shape confirmed in a
live lab by @supersache: SNC_ACTIVE="X" + nested SNC_PARAMETER struct
with SNC_QOP=8 (max) and SNC_PNAME=<partner>.

These tests fake the pyrfc connection and inspect the kwargs the code
hands to ``conn.call(DEST_RFC_TCPIP_CREATE, ...)``, so no SDK is
needed.  The SOAP side has its own envelope tests next door.
"""
from __future__ import annotations

import pytest

import sapmap_rfc                                           # noqa: E402
from sapmap_models import SAPNode, InstanceInfo, Credentials  # noqa: E402


# ---------------------------------------------------------------------------
# Fake connection that records every conn.call(...)
# ---------------------------------------------------------------------------

class _FakeConn:
    def __init__(self):
        self.calls = []  # [(fm_name, kwargs), ...]

    def call(self, fm, **kwargs):
        self.calls.append((fm, kwargs))
        # Mimic a successful DEST_RFC_TCPIP_CREATE response.
        return {"RETURN": {"TYPE": "S", "MESSAGE": "ok"}}

    # Context-manager shape so ``with _get_connection(...) as conn:`` works.
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def _snc_reset():
    """Save/restore the module-global SNC posture around a test."""
    saved = dict(sapmap_rfc._snc_config)
    try:
        yield
    finally:
        sapmap_rfc.set_snc_config(**saved)


@pytest.fixture
def _patched_conn(monkeypatch):
    """Patch _get_connection to hand out a _FakeConn, and return it."""
    fc = _FakeConn()

    def _fake_get_connection(node, creds=None, **kwargs):
        return fc

    monkeypatch.setattr(sapmap_rfc, "_get_connection", _fake_get_connection)
    return fc


# ---------------------------------------------------------------------------
# The non-SNC baseline: wire-compatible, nothing added
# ---------------------------------------------------------------------------

def test_no_snc_kwargs_without_partner_name(_snc_reset, _patched_conn):
    """No partner name passed → no SNC fields on the FM call."""
    sapmap_rfc.set_snc_config(secudir="/s", sapcryptolib="/l.so",
                              identity="p/cstb:me")
    node = SAPNode(sid="A", ip="10.0.0.1",
                   instances=[InstanceInfo(instance_nr="00", ip="10.0.0.1",
                                           ports={3300: "gateway"})])
    r = sapmap_rfc.create_tcpip_destination(
        node, target_host="10.0.0.1", target_sid="A",
        target_gw_port="3300", creds=Credentials("u", "p"))
    assert r["success"]
    assert len(_patched_conn.calls) == 1
    fm, kwargs = _patched_conn.calls[0]
    assert fm == sapmap_rfc.DEST_RFC_TCPIP_CREATE
    assert "SNC_ACTIVE" not in kwargs
    assert "SNC_PARAMETER" not in kwargs


def test_snc_kwargs_present_with_partnername_only(_snc_reset, _patched_conn):
    """Partner name passed and SAPMAP's OWN logon-level SNC posture is
    NOT configured — the destination's SNC fields describe the
    server→target leg (an SM59 property), which is independent of
    SAPMAP's own logon-level SNC posture.  Both legitimate on a mixed
    landscape: pyrfc creds for the source, SNC for the target.  Must
    stay in lockstep with the SOAP envelope's identical gate."""
    sapmap_rfc.set_snc_config()  # none of secudir/lib/identity set
    node = SAPNode(sid="B", ip="10.0.0.2",
                   snc_partnername="p/cstb:sapn2a",
                   instances=[InstanceInfo(instance_nr="00", ip="10.0.0.2",
                                           ports={3300: "gateway"})])
    r = sapmap_rfc.create_tcpip_destination(
        node, target_host="10.0.0.2", target_sid="B",
        target_gw_port="4800", creds=Credentials("u", "p"),
        snc_partnername="p/cstb:sapn2a")
    assert r["success"]
    fm, kwargs = _patched_conn.calls[0]
    assert kwargs.get("SNC_ACTIVE") == "X"
    assert kwargs.get("SNC_PARAMETER") == {
        "SNC_QOP": "8",
        "SNC_PNAME": "p/cstb:sapn2a",
    }


# ---------------------------------------------------------------------------
# The SNC path: both the activation flag and the nested structure
# ---------------------------------------------------------------------------

def test_snc_kwargs_present_when_fully_configured(_snc_reset, _patched_conn):
    """Global SNC posture configured AND partner name passed → the FM
    call carries SNC_ACTIVE="X" plus a nested SNC_PARAMETER structure
    with SNC_QOP="8" (max) and the SNC_PNAME from the caller.

    Shape verified by @supersache in a live SNC lab (issue #172).
    """
    sapmap_rfc.set_snc_config(secudir="/s", sapcryptolib="/l.so",
                              identity="p/cstb:me")
    node = SAPNode(sid="C", ip="10.0.0.3",
                   snc_partnername="p/cstb:sapn2a",
                   instances=[InstanceInfo(instance_nr="00", ip="10.0.0.3",
                                           ports={4800: "gateway_snc"})])
    r = sapmap_rfc.create_tcpip_destination(
        node, target_host="10.0.0.3", target_sid="C",
        target_gw_port="4800", creds=Credentials("u", "p"),
        snc_partnername="p/cstb:sapn2a")
    assert r["success"]
    fm, kwargs = _patched_conn.calls[0]
    assert fm == sapmap_rfc.DEST_RFC_TCPIP_CREATE
    assert kwargs["GATEWAY_SERVICE"] == "4800"
    assert kwargs.get("SNC_ACTIVE") == "X"
    assert kwargs.get("SNC_PARAMETER") == {
        "SNC_QOP": "8",
        "SNC_PNAME": "p/cstb:sapn2a",
    }


def test_snc_partnername_is_keyword_only(_snc_reset, _patched_conn):
    """snc_partnername is keyword-only so no positional caller
    accidentally shifts it into target_gw_port or creds."""
    sapmap_rfc.set_snc_config(secudir="/s", sapcryptolib="/l.so",
                              identity="p/cstb:me")
    node = SAPNode(sid="D", ip="10.0.0.4",
                   instances=[InstanceInfo(instance_nr="00", ip="10.0.0.4",
                                           ports={})])
    with pytest.raises(TypeError):
        # Positional attempt must fail; the kwargs path works.
        sapmap_rfc.create_tcpip_destination(
            node, "10.0.0.4", "D", "3300", None,  # too many positionals
            "p/cstb:x",
        )


# ---------------------------------------------------------------------------
# execute_local_command threads node.snc_partnername through — covers the
# self-ref sapxpg path (the authenticated OS-exec channel).  The existing
# tests in test_p3_features.py patch create_tcpip_destination but assert
# only call-count; nothing locks the snc_partnername hand-off from the
# wrapper down to the helper.  These do.
# ---------------------------------------------------------------------------

def test_execute_local_command_threads_snc_partnername_from_node(monkeypatch):
    """When the self-ref flow has to create a fresh dest, the node's
    own snc_partnername must flow into create_tcpip_destination so the
    resulting SM59 record carries SNC_ACTIVE / SNC_PARAMETER.  Without
    this hand-off the kwarg silently drops and the SNC-enforcing
    gateway refuses the registered-program connection (SDEST E 017)."""
    from unittest.mock import patch, MagicMock

    class _FakeConn2:
        def call(self, fm, **kwargs):
            # RFCDES scan: return "no matches" so execute_local_command
            # falls through to create_tcpip_destination.
            return {"DATA": []}

        def __enter__(self): return self
        def __exit__(self, *a): return False

    conn = _FakeConn2()
    monkeypatch.setattr(sapmap_rfc, "_get_connection", lambda *a, **k: conn)

    node = SAPNode(sid="N2A", ip="10.0.0.9",
                   hostname="sapn2a.kerby.com",
                   snc_partnername="p/cstb:CN=sapn2a, O=Kerby",
                   instances=[InstanceInfo(instance_nr="00", ip="10.0.0.9",
                                           ports={4800: "gateway_snc"})])

    with patch.object(sapmap_rfc, "create_tcpip_destination",
                      return_value={"success": True,
                                    "dest_name": "SAPMAP_N2A_X",
                                    "message": "ok"}) as mk_dest, \
         patch.object(sapmap_rfc, "execute_remote_command",
                      return_value={"success": True, "output": [],
                                    "error": ""}):
        sapmap_rfc.execute_local_command(
            node, "id", "", Credentials("u", "p"))

    mk_dest.assert_called_once()
    # The kwarg must carry the node's partner name verbatim.
    assert (mk_dest.call_args.kwargs.get("snc_partnername")
            == "p/cstb:CN=sapn2a, O=Kerby")


def test_execute_local_command_passes_empty_snc_partnername_on_plain_node(monkeypatch):
    """A node WITHOUT snc_partnername must thread an empty string
    (not raise, and not pick up the wrong attribute from a nearby
    object).  Keeps the plain-landscape self-ref sapxpg path
    wire-compatible with pre-#172."""
    from unittest.mock import patch

    class _FakeConn3:
        def call(self, fm, **kwargs):
            return {"DATA": []}

        def __enter__(self): return self
        def __exit__(self, *a): return False

    conn = _FakeConn3()
    monkeypatch.setattr(sapmap_rfc, "_get_connection", lambda *a, **k: conn)

    node = SAPNode(sid="W74", ip="10.0.0.10",
                   hostname="winwas740.corp",
                   instances=[InstanceInfo(instance_nr="00", ip="10.0.0.10",
                                           ports={3300: "gateway"})])
    # Deliberately: no snc_partnername set.
    assert not getattr(node, "snc_partnername", "")

    with patch.object(sapmap_rfc, "create_tcpip_destination",
                      return_value={"success": True,
                                    "dest_name": "SAPMAP_W74_X",
                                    "message": "ok"}) as mk_dest, \
         patch.object(sapmap_rfc, "execute_remote_command",
                      return_value={"success": True, "output": [],
                                    "error": ""}):
        sapmap_rfc.execute_local_command(
            node, "id", "", Credentials("u", "p"))

    mk_dest.assert_called_once()
    assert mk_dest.call_args.kwargs.get("snc_partnername") == ""
