"""ScriptRunner: BTP action mappings.

Each BTP-related action in scripts/*.yaml maps to an HTTP endpoint
on the running SAPMAP server.  These tests pin down the contract
(method + path + payload) so a future refactor can't silently
break existing playbooks like demo_onprem_to_btp.yaml.
"""
from __future__ import annotations

import os
import tempfile

import modules  # noqa: F401  (registers package paths)
from sapmap_script import _map_step, _read_token, _ACTION_LABELS


def _step(action, **kw):
    s = {"action": action}
    s.update(kw)
    return s


# --- Cloud-side actions ----------------------------------------------

def test_btp_set_token_maps_to_set_token_endpoint():
    method, path, body, _ = _map_step(
        _step("btp_set_token", region="eu10-004", token="eyJqa3..."))
    assert method == "POST"
    assert path == "/api/btp/set_token"
    assert body == {"region": "eu10-004", "token": "eyJqa3..."}


def test_btp_set_token_supports_path_prefix_for_secret_files():
    """Long JWTs shouldn't have to live in YAML.  `path:<file>`
    loads the token from disk so playbooks can reference a token
    written by an earlier shell step."""
    with tempfile.NamedTemporaryFile(
            "w", delete=False, suffix=".jwt") as tmp:
        tmp.write("eyJq.aaa.bbb\n")
        tmp_path = tmp.name
    try:
        method, path, body, _ = _map_step(
            _step("btp_set_token", region="eu10",
                  token=f"path:{tmp_path}"))
        assert body["token"] == "eyJq.aaa.bbb"
    finally:
        os.unlink(tmp_path)


def test_btp_enumerate_maps_to_enumerate_endpoint():
    method, path, body, _ = _map_step(
        _step("btp_enumerate", region="eu10"))
    assert (method, path) == ("POST", "/api/btp/enumerate")
    assert body == {"region": "eu10"}


def test_btp_pull_destinations_for_token_maps_correctly():
    method, path, body, _ = _map_step(
        _step("btp_pull_destinations_for_token", region="eu10-004"))
    assert (method, path) == (
        "POST", "/api/btp/pull_destinations_for_token")
    assert body == {"region": "eu10-004"}


def test_btp_test_destination_carries_synthetic_edge_keys():
    """The synthetic BTP edge is keyed by (BTP:<uuid8>,
    BTP:<uuid8>::<dest_name>) — both must reach the endpoint
    verbatim or the connection lookup fails."""
    method, path, body, _ = _map_step(_step(
        "btp_test_destination",
        source_sid="BTP:90a90189",
        destination_name="BTP:90a90189::DemoDest"))
    assert (method, path) == ("POST", "/api/btp/test_destination")
    assert body == {
        "source_sid": "BTP:90a90189",
        "destination_name": "BTP:90a90189::DemoDest",
    }


def test_btp_create_user_on_target_carries_three_ids():
    method, path, body, _ = _map_step(_step(
        "btp_create_user_on_target",
        source_sid="BTP:90a90189",
        destination_name="BTP:90a90189::DemoDest",
        target_sid="S4H"))
    assert (method, path) == (
        "POST", "/api/btp/create_user_on_target")
    assert body == {
        "source_sid": "BTP:90a90189",
        "destination_name": "BTP:90a90189::DemoDest",
        "target_sid": "S4H",
    }


# --- On-prem → cloud lateral pivot ------------------------------------

def test_harvest_btp_creds_maps_to_per_node_endpoint():
    method, path, body, _ = _map_step(
        _step("harvest_btp_creds", target="S4H"))
    assert method == "POST"
    assert path == "/api/node/S4H/harvest_btp_creds"
    # No body needed — implicit OA2C refresh + harvest happens
    # server-side based on node state.
    assert body == {}


def test_mint_btp_token_carries_uaa_url_and_creds():
    method, path, body, _ = _map_step(_step(
        "mint_btp_token",
        target="S4H",
        uaa_url="https://x.authentication.eu10.hana.ondemand.com/oauth/token",
        client_id="sb-cid!b1",
        client_secret="raw-secret"))
    assert method == "POST"
    assert path == "/api/node/S4H/mint_btp_token"
    assert body["uaa_url"].endswith("/oauth/token")
    assert body["client_id"] == "sb-cid!b1"
    assert body["client_secret"] == "raw-secret"
    # from_harvest defaults to False so the existing manual flow
    # still works exactly as before.
    assert body.get("from_harvest") in (False, None, "")


def test_mint_btp_token_passes_from_harvest_flag():
    """`from_harvest: true` lets the demo playbook run end-to-end
    without the operator having to copy creds out of the harvest
    log into the mint step.  The action map must propagate it
    plus an optional candidate_index."""
    method, path, body, _ = _map_step(_step(
        "mint_btp_token",
        target="S4H",
        from_harvest=True,
        candidate_index=2))
    assert (method, path) == ("POST", "/api/node/S4H/mint_btp_token")
    assert body["from_harvest"] is True
    assert body["candidate_index"] == 2
    # Manual fields stay empty when from_harvest fills in for them.
    assert body["uaa_url"] == ""
    assert body["client_id"] == ""
    assert body["client_secret"] == ""


def test_mint_btp_token_supports_path_prefix_for_client_secret():
    with tempfile.NamedTemporaryFile(
            "w", delete=False, suffix=".secret") as tmp:
        tmp.write("the-secret-from-disk\n")
        tmp_path = tmp.name
    try:
        method, path, body, _ = _map_step(_step(
            "mint_btp_token",
            target="S4H",
            uaa_url="https://x/oauth/token",
            client_id="cid",
            client_secret=f"path:{tmp_path}"))
        assert body["client_secret"] == "the-secret-from-disk"
    finally:
        os.unlink(tmp_path)


# --- Action labels (so the GUI activity bar shows something useful) ---

def test_every_new_action_has_a_human_readable_label():
    for action in (
        "btp_set_token", "btp_enumerate",
        "btp_pull_destinations_for_token",
        "btp_test_destination", "btp_create_user_on_target",
        "harvest_btp_creds", "mint_btp_token",
    ):
        assert action in _ACTION_LABELS, \
            f"{action} missing from _ACTION_LABELS — GUI will " \
            f"show the raw action name in the activity bar"


# --- _read_token helper -----------------------------------------------

def test_read_token_passthrough_for_inline_values():
    assert _read_token("eyJq.aaa.bbb") == "eyJq.aaa.bbb"
    assert _read_token("") == ""


def test_read_token_returns_empty_when_path_target_missing():
    """Bad path: don't crash the entire playbook — return "" and
    let the endpoint reject it with a clearer error than a
    FileNotFoundError trace."""
    assert _read_token("path:/nonexistent/file") == ""
