#!/usr/bin/env python3
"""Tests for the implicit secstore download triggered when a user is
created on an ABAP node.

Operator expectation: every successful create-user (GW exploit /
betrusted chain / via SAP_ALL credential) auto-downloads RSECTAB,
because it's the highest-value loot and operators always run that
action next anyway.
"""
from __future__ import annotations

import threading
import time
from unittest.mock import patch


def _abap_node(sid="S4H"):
    from sapmap_models import SAPNode, InstanceInfo
    n = SAPNode(sid=sid, ip="10.0.0.5", hostname="s4h",
                 system_type="ABAP", os_type="Linux")
    n.instances.append(InstanceInfo(instance_nr="00", ip="10.0.0.5",
                                     ports={3300: "gateway"}))
    return n


def _java_node(sid="J75"):
    from sapmap_models import SAPNode, InstanceInfo
    n = SAPNode(sid=sid, ip="10.0.0.6", hostname="j75",
                 system_type="Java", os_type="Linux")
    n.instances.append(InstanceInfo(instance_nr="00", ip="10.0.0.6",
                                     ports={50004: "icm_http"}))
    return n


def _state_with(node):
    from sapmap_models import SAPMAPState
    state = SAPMAPState()
    state.nodes[node.sid] = node
    return state


def _user_for(node):
    from sapmap_models import CreatedUser
    return CreatedUser(
        sid=node.sid, hostname=node.hostname, ip=node.ip,
        username="SAPMAP00", password="x",
        client="100", instance_nr="00", method="gw_exploit")


def _wait_for(predicate, timeout=2.0):
    """Spin briefly until ``predicate()`` returns True.  Used to wait
    for the daemon thread to finish without sleeping for the worst
    case."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


# ===========================================================================
# Happy path — ABAP node + user creation triggers download
# ===========================================================================

def test_user_creation_on_abap_node_triggers_secstore_download():
    from sapmap_models import SAPMAPState
    node = _abap_node()
    state = _state_with(node)
    called = {"args": None, "done": threading.Event()}

    def fake_download(n, creds, key_hex, state=None):
        called["args"] = (n, creds, key_hex)
        called["done"].set()
        return [{"IDENT": "RFC/X", "password": "secret",
                  "error": ""}]

    with patch("sapmap_secstore.download_and_decrypt",
               side_effect=fake_download) as dl, \
         patch("sapmap_secstore.integrate_results") as integ, \
         patch("sapmap_secstore.save_loot",
               return_value="/tmp/fake.json") as loot, \
         patch("sapmap_state.ensure_loot_dir",
               return_value="/tmp"):
        state.track_created_user(_user_for(node))
        # The auto-download runs on a daemon thread — wait briefly.
        assert _wait_for(lambda: called["done"].is_set(), timeout=2.0)

    dl.assert_called_once()
    integ.assert_called_once()
    loot.assert_called_once()
    # The credentials passed in must come from best_credentials() —
    # which prefers the just-created user.
    n_arg, creds_arg, _ = called["args"]
    assert n_arg is node
    assert creds_arg.username == "SAPMAP00"
    assert creds_arg.verified is True


def test_auto_secstore_skipped_when_already_populated():
    """If node.secstore_entries is already populated from a previous
    run, the auto-download must not fire again.  Avoids duplicate
    work + concurrent writes when multiple users are created."""
    from sapmap_models import SAPMAPState
    node = _abap_node()
    node.secstore_entries = [{"IDENT": "RFC/PREV", "password": "p"}]
    state = _state_with(node)
    with patch("sapmap_secstore.download_and_decrypt") as dl:
        state.track_created_user(_user_for(node))
        # Give the daemon thread time to (not) fire.
        time.sleep(0.1)
    dl.assert_not_called()


def test_auto_secstore_skipped_for_java_nodes():
    """Java has its own secstore flow (download_java_secstore) — the
    ABAP-specific RSECTAB read is meaningless there."""
    node = _java_node()
    state = _state_with(node)
    with patch("sapmap_secstore.download_and_decrypt") as dl:
        state.track_created_user(_user_for(node))
        time.sleep(0.1)
    dl.assert_not_called()


def test_auto_secstore_failure_does_not_crash_caller():
    """If the secstore download raises, the create-user flow must
    still complete cleanly.  Exception is swallowed + logged."""
    node = _abap_node()
    state = _state_with(node)
    done = threading.Event()

    def boom(*_a, **_kw):
        try:
            raise RuntimeError("simulated RFC failure")
        finally:
            done.set()

    with patch("sapmap_secstore.download_and_decrypt", side_effect=boom):
        state.track_created_user(_user_for(node))   # must not raise
        assert _wait_for(done.is_set, timeout=2.0)

    # The user is still tracked, the node still pwned — caller path
    # didn't lose state because of the secstore failure.
    assert node.created_users and node.created_users[0].username == "SAPMAP00"
    assert node.pwned is True


def test_auto_secstore_skipped_when_no_credentials():
    """Edge case: best_credentials() returns None somehow (the user
    we just added was already there).  Auto-download should bail
    silently without crashing."""
    from sapmap_models import SAPMAPState
    node = _abap_node()
    state = _state_with(node)
    with patch.object(node, "best_credentials", return_value=None), \
         patch("sapmap_secstore.download_and_decrypt") as dl:
        state.track_created_user(_user_for(node))
        time.sleep(0.1)
    dl.assert_not_called()
