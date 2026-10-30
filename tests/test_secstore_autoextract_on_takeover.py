#!/usr/bin/env python3
"""Issue #177 — taking over an ABAP system (GW user-create OR trusted-RFC /
propagate) must auto-download + decrypt its SecStore, so the RFC-destination
passwords are harvested without a separate manual "Download SecStore" click.

The hook lives in sapmap_exploit._post_exploit_enrichment, which every
takeover path funnels through.  These tests drive it with the network pieces
mocked and assert the SecStore extraction fires (and is skipped when the
store was already extracted, or the system isn't ABAP)."""
from __future__ import annotations

import modules  # noqa: F401 — registers package paths
import sapmap_exploit
import sapmap_secstore
import sapmap_gui
import sapmap_state
import sapmap_findings
from sapmap_models import SAPNode, SAPMAPState, Credentials


def _mock_network(monkeypatch, *, results):
    """Patch every out-of-process call the hook makes; return a calls dict."""
    calls = {}

    def _dl(node, creds, **kw):
        calls["dl"] = True
        return results

    monkeypatch.setattr(sapmap_secstore, "download_and_decrypt", _dl)
    monkeypatch.setattr(sapmap_secstore, "integrate_results",
                        lambda n, s, r: calls.__setitem__("integrate", True))
    monkeypatch.setattr(sapmap_secstore, "save_loot",
                        lambda sid, r, d: "/tmp/loot")
    monkeypatch.setattr(sapmap_gui, "resolve_soap_session_for_node",
                        lambda state, node, timeout=0: (None, None))
    monkeypatch.setattr(sapmap_state, "ensure_loot_dir", lambda x: "/tmp")
    monkeypatch.setattr(sapmap_findings, "emit_finding",
                        lambda *a, **k: calls.__setitem__("finding", True))
    return calls


def _abap_node(system_type="ABAP", **kw):
    # kernel+hostname+sid present so the authenticated RFC_SYSTEM_INFO refresh
    # is skipped; no gw_vulnerable/os_exec_channel so co-located discovery is
    # skipped — isolating the SecStore hook.
    n = SAPNode(sid="ABA", system_type=system_type, kernel="753",
                hostname="vhcalabaci", ip="192.168.2.136", **kw)
    n.credentials = [Credentials(username="SAPMAP00", password="x",
                                 client="001", instance_nr="00", verified=True)]
    return n


def test_auto_secstore_runs_on_abap_takeover(monkeypatch):
    calls = _mock_network(monkeypatch, results=[
        {"password": "pw", "dest_name": "TO_A4H", "category": "rfc", "error": ""}])
    sapmap_exploit._post_exploit_enrichment(
        _abap_node(), SAPMAPState(), proven_type="ABAP", skip_gateway_rfc=True)
    assert calls.get("dl"), "SecStore download_and_decrypt must auto-run on ABAP takeover"
    assert calls.get("integrate"), "results must be integrated onto the node"
    assert calls.get("finding"), "a CRITICAL finding must be emitted when passwords are recovered"


def test_auto_secstore_skipped_when_already_extracted(monkeypatch):
    calls = _mock_network(monkeypatch, results=[{"password": "pw"}])
    node = _abap_node()
    node.secstore_entries = [{"ident": "DB_CONNECT", "password": "y"}]
    sapmap_exploit._post_exploit_enrichment(
        node, SAPMAPState(), proven_type="ABAP", skip_gateway_rfc=True)
    assert "dl" not in calls, "must not re-extract when node already has SecStore entries"


def test_auto_secstore_skipped_for_non_abap(monkeypatch):
    calls = _mock_network(monkeypatch, results=[{"password": "pw"}])
    node = _abap_node(system_type="JAVA")
    sapmap_exploit._post_exploit_enrichment(
        node, SAPMAPState(), proven_type="JAVA", skip_gateway_rfc=True)
    assert "dl" not in calls, "ABAP RSECTAB SecStore extract must not run on a JAVA node"


def test_auto_secstore_no_finding_when_nothing_decrypted(monkeypatch):
    # entries returned but none decrypted → still integrated, no CRITICAL finding
    calls = _mock_network(monkeypatch, results=[
        {"ident": "X", "password": "", "error": "key mismatch"}])
    sapmap_exploit._post_exploit_enrichment(
        _abap_node(), SAPMAPState(), proven_type="ABAP", skip_gateway_rfc=True)
    assert calls.get("dl") and calls.get("integrate")
    assert "finding" not in calls, "no CRITICAL finding when nothing decrypted"
