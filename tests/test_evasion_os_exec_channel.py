"""Tests for Tier 2 T2.3 — OS-exec channel selection (SXPG vs GW SAPXPG)."""

from unittest.mock import patch, MagicMock

from sapmap_models import Credentials, SAPNode
import sapmap_evasion
from sapmap_evasion import (EvasionConfig, effective_os_exec_channel)


# ---------------------------------------------------------------------------
# effective_os_exec_channel — gating matrix
# ---------------------------------------------------------------------------

def _node(gw_vulnerable=False):
    n = SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1")
    n.gw_vulnerable = gw_vulnerable
    return n


def _verified_creds():
    return Credentials(username="SAPMAP00", password="x",
                       client="001", instance_nr="00", verified=True)


def test_picks_sxpg_when_creds_verified_and_gw_vulnerable():
    n = _node(gw_vulnerable=True)
    channel, reason = effective_os_exec_channel(
        n, _verified_creds(), EvasionConfig())
    assert channel == "sxpg"
    assert "SAL event" in reason


def test_picks_sxpg_when_creds_verified_and_no_gw_path():
    n = _node(gw_vulnerable=False)
    channel, reason = effective_os_exec_channel(
        n, _verified_creds(), EvasionConfig())
    assert channel == "sxpg"
    assert "GW SAPXPG path unavailable" in reason


def test_picks_gw_when_no_verified_creds_but_gw_vulnerable():
    n = _node(gw_vulnerable=True)
    channel, reason = effective_os_exec_channel(
        n, None, EvasionConfig())
    assert channel == "gw_sapxpg"
    assert "only OS-exec primitive" in reason


def test_picks_gw_fallback_when_neither_path_clearly_available():
    n = _node(gw_vulnerable=False)
    channel, reason = effective_os_exec_channel(
        n, None, EvasionConfig())
    assert channel == "gw_sapxpg"
    assert "last fallback" in reason


def test_unverified_credential_treated_as_no_credential():
    """has-cred but verified=False ⇒ caller hasn't proven auth works
    yet, so we don't pick SXPG and risk a denial loop."""
    n = _node(gw_vulnerable=True)
    creds = Credentials(username="x", password="x",
                        client="001", instance_nr="00", verified=False)
    channel, _ = effective_os_exec_channel(n, creds, EvasionConfig())
    assert channel == "gw_sapxpg"


def test_operator_override_wins_over_selector():
    n = _node(gw_vulnerable=True)
    cfg = EvasionConfig(os_exec_channel="gw_sapxpg")
    channel, reason = effective_os_exec_channel(
        n, _verified_creds(), cfg)
    assert channel == "gw_sapxpg"
    assert "override" in reason


def test_evasion_config_roundtrip_preserves_os_exec_channel():
    cfg = EvasionConfig(os_exec_channel="sxpg")
    d = cfg.to_dict()
    cfg2 = EvasionConfig.from_dict(d)
    assert cfg2.os_exec_channel == "sxpg"


# ---------------------------------------------------------------------------
# execute_os_command dispatcher
# ---------------------------------------------------------------------------

def test_dispatcher_routes_to_sxpg_when_selector_picks_it():
    import sapmap_exploit
    n = _node(gw_vulnerable=True)
    creds = _verified_creds()

    sxpg_response = {"success": True, "output": ["whoami: s4hadm"], "error": ""}
    with patch.object(sapmap_exploit.sapmap_rfc,
                      "execute_local_command",
                      return_value=sxpg_response) as sxpg_mock, \
         patch.object(sapmap_exploit, "execute_gw_command") as gw_mock:
        r = sapmap_exploit.execute_os_command(n, "whoami", "", creds=creds)

    assert r["success"] is True
    assert r["channel"] == "sxpg"
    assert sxpg_mock.call_count == 1
    assert gw_mock.call_count == 0


def test_dispatcher_falls_back_to_gw_when_sxpg_denied():
    """SXPG denied (no S_LOG_COM) → seamless GW SAPXPG fallback so the
    op still completes; reason text records the fallback chain."""
    import sapmap_exploit
    n = _node(gw_vulnerable=True)
    creds = _verified_creds()

    sxpg_denied = {"success": False, "output": [],
                   "error": "AUTHORIZATION_FAILURE: S_LOG_COM"}
    gw_ok = {"success": True, "output": ["whoami: s4hadm"], "error": ""}
    with patch.object(sapmap_exploit.sapmap_rfc,
                      "execute_local_command",
                      return_value=sxpg_denied), \
         patch.object(sapmap_exploit, "execute_gw_command",
                      return_value=gw_ok) as gw_mock:
        r = sapmap_exploit.execute_os_command(n, "whoami", "", creds=creds)

    assert r["success"] is True
    assert r["channel"] == "gw_sapxpg"
    assert "sxpg-fallback" in r["channel_reason"]
    assert "S_LOG_COM" in r["channel_reason"]
    assert gw_mock.call_count == 1


def test_dispatcher_routes_to_gw_when_no_creds():
    import sapmap_exploit
    n = _node(gw_vulnerable=True)

    gw_ok = {"success": True, "output": ["uid=...s4hadm"], "error": ""}
    with patch.object(sapmap_exploit, "execute_gw_command",
                      return_value=gw_ok) as gw_mock, \
         patch.object(sapmap_exploit.sapmap_rfc,
                      "execute_local_command") as sxpg_mock:
        r = sapmap_exploit.execute_os_command(n, "whoami", "")

    assert r["success"] is True
    assert r["channel"] == "gw_sapxpg"
    assert sxpg_mock.call_count == 0
    assert gw_mock.call_count == 1


def test_dispatcher_per_call_prefer_overrides_selector():
    import sapmap_exploit
    n = _node(gw_vulnerable=True)
    creds = _verified_creds()

    gw_ok = {"success": True, "output": ["forced gw"], "error": ""}
    with patch.object(sapmap_exploit, "execute_gw_command",
                      return_value=gw_ok) as gw_mock, \
         patch.object(sapmap_exploit.sapmap_rfc,
                      "execute_local_command") as sxpg_mock:
        r = sapmap_exploit.execute_os_command(
            n, "whoami", "", creds=creds, prefer="gw_sapxpg")

    assert r["channel"] == "gw_sapxpg"
    assert "prefer=gw_sapxpg" in r["channel_reason"]
    assert sxpg_mock.call_count == 0
    assert gw_mock.call_count == 1


def test_dispatcher_auto_resolves_creds_from_node_best_credentials():
    """When the caller doesn't pass creds, the dispatcher pulls them
    from node.best_credentials() so it can still pick SXPG."""
    import sapmap_exploit
    n = _node(gw_vulnerable=True)
    n.credentials = [_verified_creds()]

    sxpg_ok = {"success": True, "output": ["whoami: s4hadm"], "error": ""}
    with patch.object(sapmap_exploit.sapmap_rfc,
                      "execute_local_command",
                      return_value=sxpg_ok) as sxpg_mock, \
         patch.object(sapmap_exploit, "execute_gw_command") as gw_mock:
        r = sapmap_exploit.execute_os_command(n, "whoami", "")

    assert r["channel"] == "sxpg"
    assert sxpg_mock.call_count == 1
    assert gw_mock.call_count == 0
