"""Layered create-user reach probe (issue #23).

Covers:
  1. SAP_ALL fast-path — no target-side call
  2. Role-name heuristic — well-known admin roles
  3. ABAP AUTHORITY-CHECK — parses the WRITE output for four subrcs
  4. Canary create+delete stub — validated via BAPI-call mocking

These tests never touch the network; _get_connection + _run_abap_program
are patched so the probe runs entirely in-memory.
"""
from __future__ import annotations

from unittest.mock import patch, MagicMock

from sapmap_models import SAPNode, Credentials
from sapmap_rfc import (
    check_can_create_user, canary_create_user_probe,
    _KNOWN_ADMIN_ROLES,
)


def _fake_node() -> SAPNode:
    return SAPNode(sid="ERP", hostname="erp01", ip="10.0.0.1",
                    system_type="ABAP")


def test_layer1_sap_all_fastpath_short_circuits():
    """SAP_ALL profile present → no ABAP call, verdict from Layer 1."""
    with patch("sapmap_rfc._get_connection") as mgc:
        result = check_can_create_user(
            _fake_node(),
            existing_profiles=["SAP_ALL", "S_A.SYSTEM"],
            existing_roles=[],
        )
    assert mgc.call_count == 0, "Layer 1 must not open an RFC connection"
    assert result["can_create_user"] is True
    assert result["can_assign_sap_all"] is True
    assert result["probe"] == "sap_all"
    assert "SAP_ALL" in result["evidence"]


def test_layer2_role_heuristic_matches_wellknown_admin_role_fallback():
    """When Layer 1 misses but a well-known admin role is present AND
    ABAP AUTHORITY-CHECK is unavailable, the role heuristic verdict
    is preserved."""
    # ABAP path unavailable — layer 3 will hit the "blocked" branch and
    # keep the heuristic verdict.
    with patch("sapmap_rfc._get_connection",
                side_effect=RuntimeError("RFC_ABAP_INSTALL_AND_RUN missing")):
        result = check_can_create_user(
            _fake_node(),
            existing_profiles=[],
            existing_roles=["SAP_BC_USER_ADMIN"],
        )
    assert result["can_create_user"] is True
    assert result["probe"] == "role_heuristic"
    assert "SAP_BC_USER_ADMIN" in result["evidence"]
    # Advisory error message surfaces but doesn't clobber the verdict
    assert "heuristic verdict" in result["error"].lower()


def test_layer3_authority_check_grp_super_ok_pro_ok():
    """ABAP AUTHORITY-CHECK reports subrc=0 for S_USER_GRP SUPER +
    S_USER_PRO SAP_ALL — verdict: can create, can assign SAP_ALL."""
    fake_conn = MagicMock()
    mgr = MagicMock()
    mgr.__enter__.return_value = fake_conn
    mgr.__exit__.return_value = False
    with patch("sapmap_rfc._get_connection", return_value=mgr), \
         patch("sapmap_rfc._run_abap_program",
                return_value={"success": True, "output": [
                    "GRP_SUPER=            0",
                    "GRP_DEFAULT=          4",
                    "PRO_SAPALL=           0",
                    "AGR_ADMIN=            4",
                ], "fm_name": "RFC_ABAP_INSTALL_AND_RUN", "error": ""}):
        result = check_can_create_user(
            _fake_node(), existing_profiles=[], existing_roles=[])
    assert result["can_create_user"] is True
    assert result["can_assign_sap_all"] is True
    assert result["can_assign_role"] is False
    assert result["probe"] == "authority_check"
    assert "S_USER_GRP 01/SUPER" in result["evidence"]
    assert "S_USER_PRO 22/SAP_ALL" in result["evidence"]


def test_layer3_authority_check_all_denied():
    """subrc=4 across the board → verdict: cannot create user."""
    fake_conn = MagicMock()
    mgr = MagicMock()
    mgr.__enter__.return_value = fake_conn
    mgr.__exit__.return_value = False
    with patch("sapmap_rfc._get_connection", return_value=mgr), \
         patch("sapmap_rfc._run_abap_program",
                return_value={"success": True, "output": [
                    "GRP_SUPER=            4",
                    "GRP_DEFAULT=          4",
                    "PRO_SAPALL=           4",
                    "AGR_ADMIN=            4",
                ], "fm_name": "RFC_ABAP_INSTALL_AND_RUN", "error": ""}):
        result = check_can_create_user(
            _fake_node(), existing_profiles=[], existing_roles=[])
    assert result["can_create_user"] is False
    assert result["can_assign_sap_all"] is False
    assert result["can_assign_role"] is False
    assert result["probe"] == "authority_check"
    assert "no S_USER_" in result["evidence"]


def test_layer3_prefers_default_group_when_super_denied():
    """User restricted to CLASS='' (default group) but not SUPER — the
    reach probe reports S_USER_GRP 01/DEFAULT as evidence."""
    fake_conn = MagicMock()
    mgr = MagicMock()
    mgr.__enter__.return_value = fake_conn
    mgr.__exit__.return_value = False
    with patch("sapmap_rfc._get_connection", return_value=mgr), \
         patch("sapmap_rfc._run_abap_program",
                return_value={"success": True, "output": [
                    "GRP_SUPER=            4",
                    "GRP_DEFAULT=          0",
                    "PRO_SAPALL=           4",
                    "AGR_ADMIN=            4",
                ], "fm_name": "RFC_ABAP_INSTALL_AND_RUN", "error": ""}):
        result = check_can_create_user(
            _fake_node(), existing_profiles=[], existing_roles=[])
    assert result["can_create_user"] is True
    assert result["can_assign_sap_all"] is False
    assert "S_USER_GRP 01/DEFAULT" in result["evidence"]
    assert "S_USER_GRP 01/SUPER" not in result["evidence"]


def test_layer4_canary_create_success_then_delete():
    """Successful BAPI_USER_CREATE1 followed by successful BAPI_USER_DELETE
    → success=True and no lingering canary user."""
    fake_conn = MagicMock()
    # Two successful RETURN tables (no E/A messages) for create + delete
    fake_conn.call.return_value = {"RETURN": [
        {"TYPE": "S", "MESSAGE": "User created"}]}
    mgr = MagicMock()
    mgr.__enter__.return_value = fake_conn
    mgr.__exit__.return_value = False
    with patch("sapmap_rfc._get_connection", return_value=mgr):
        result = canary_create_user_probe(_fake_node(),
                                            username="TESTCANARY")
    assert result["success"] is True
    assert result["created"] is True
    assert result["deleted"] is True
    assert result["username"] == "TESTCANARY"
    assert result["error"] == ""


def test_layer4_canary_rejected_no_orphan():
    """BAPI_USER_CREATE1 returns E → success=False, created=False, no
    delete attempted (there's nothing to clean up)."""
    fake_conn = MagicMock()
    fake_conn.call.return_value = {"RETURN": [
        {"TYPE": "E",
          "MESSAGE": "No authorization to create user in group SUPER"}]}
    mgr = MagicMock()
    mgr.__enter__.return_value = fake_conn
    mgr.__exit__.return_value = False
    with patch("sapmap_rfc._get_connection", return_value=mgr):
        result = canary_create_user_probe(_fake_node(),
                                            username="CANARYX")
    assert result["success"] is False
    assert result["created"] is False
    assert result["deleted"] is False
    assert "No authorization" in result["error"]


def test_layer4_canary_created_but_delete_fails_flags_orphan():
    """Create OK, delete errors — we flag the orphan so the operator
    knows to clean up manually."""
    call_counter = {"n": 0}
    fake_conn = MagicMock()
    def _side_effect(*args, **kwargs):
        call_counter["n"] += 1
        if call_counter["n"] == 1:
            # First call = CREATE = success
            return {"RETURN": [{"TYPE": "S", "MESSAGE": "OK"}]}
        # Second call = DELETE = error
        return {"RETURN": [{"TYPE": "E",
                             "MESSAGE": "Session lost"}]}
    fake_conn.call.side_effect = _side_effect
    mgr = MagicMock()
    mgr.__enter__.return_value = fake_conn
    mgr.__exit__.return_value = False
    with patch("sapmap_rfc._get_connection", return_value=mgr):
        result = canary_create_user_probe(_fake_node(),
                                            username="ORPHAN01")
    assert result["created"] is True
    assert result["deleted"] is False
    assert result["success"] is False
    assert "Session lost" in result["error"] or "delete failed" in result["error"]


def test_known_admin_roles_include_common_names():
    """Guard against accidental removal of the well-known admin role
    list — must include the roles Basis engagements actually see."""
    assert "SAP_BC_USER_ADMIN" in _KNOWN_ADMIN_ROLES
    assert "SAP_BC_BASIS_ADMIN" in _KNOWN_ADMIN_ROLES


def test_layer3_prefers_source_side_path_when_available():
    """When source_node + destination are supplied, Layer 3 must route
    the ABAP execution through the source's SM59 destination (same
    working path as Test Connection).  Falls back to the direct
    connection only when the source path isn't specified."""
    source = SAPNode(sid="S4H", hostname="s4h", ip="192.168.2.209",
                      system_type="ABAP")
    target = SAPNode(sid="W74", hostname="w74", ip="192.168.2.29",
                      system_type="ABAP")
    fake_conn = MagicMock()
    mgr = MagicMock()
    mgr.__enter__.return_value = fake_conn
    mgr.__exit__.return_value = False
    # Direct-target path should NOT be called when the source path is
    # in play.  Patch both and assert.
    def _fake_dest_ok(_conn, _lines, _dest, _prog):
        return {"success": True, "output": [
            "GRP_SUPER=            0",
            "GRP_DEFAULT=          4",
            "PRO_SAPALL=           0",
            "AGR_ADMIN=            4",
        ], "fm_name": "RFC_ABAP_INSTALL_AND_RUN", "error": ""}
    with patch("sapmap_rfc._get_connection", return_value=mgr) as mgc, \
         patch("sapmap_rfc._run_abap_program_with_destination",
                side_effect=_fake_dest_ok) as m_dest, \
         patch("sapmap_rfc._run_abap_program") as m_direct:
        result = check_can_create_user(
            target, existing_profiles=[], existing_roles=[],
            source_node=source, destination="W74_T2",
            source_creds=Credentials(username="SAPADM",
                                      password="Whatever",
                                      client="000"))
    # Source path used, not the direct one
    assert m_dest.call_count == 1
    assert m_direct.call_count == 0
    assert result["can_create_user"] is True
    assert result["probe"] == "authority_check"


def test_layer3_direct_target_fallback_when_no_source():
    """Without source_node/destination, Layer 3 falls back to the
    old direct-RFC-to-target path."""
    target = SAPNode(sid="W74", hostname="w74", ip="10.0.0.1",
                      system_type="ABAP")
    fake_conn = MagicMock()
    mgr = MagicMock()
    mgr.__enter__.return_value = fake_conn
    mgr.__exit__.return_value = False
    with patch("sapmap_rfc._get_connection", return_value=mgr), \
         patch("sapmap_rfc._run_abap_program_with_destination") as m_dest, \
         patch("sapmap_rfc._run_abap_program",
                return_value={"success": True, "output": [
                    "GRP_SUPER=            0",
                    "GRP_DEFAULT=          4",
                    "PRO_SAPALL=           4",
                    "AGR_ADMIN=            4",
                ], "fm_name": "RFC_ABAP_INSTALL_AND_RUN", "error": ""}) as m_direct:
        result = check_can_create_user(
            target, existing_profiles=[], existing_roles=[])
    assert m_dest.call_count == 0
    assert m_direct.call_count == 1
    assert result["can_create_user"] is True
    assert result["can_assign_sap_all"] is False


def test_layer2_verdict_survives_layer3_failure_via_source_path():
    """T2's real-world scenario: SAP_BC_USER_ADMIN role is present so
    Layer 2 fires; Layer 3 blows up on the source path; final verdict
    stays "role_heuristic" instead of collapsing to None."""
    source = SAPNode(sid="S4H", hostname="s4h", ip="1.1.1.1",
                      system_type="ABAP")
    target = SAPNode(sid="W74", hostname="w74", ip="2.2.2.2",
                      system_type="ABAP")
    with patch("sapmap_rfc._get_connection",
                side_effect=RuntimeError("routing failed")):
        result = check_can_create_user(
            target,
            existing_profiles=["T-W4810024", "T-W4810025"],
            existing_roles=["SAP_BC_USER_ADMIN", "Z_RFCPING"],
            source_node=source, destination="W74_T2")
    # Heuristic verdict preserved despite Layer 3 blowing up
    assert result["can_create_user"] is True
    assert result["probe"] == "role_heuristic"
    assert "SAP_BC_USER_ADMIN" in result["evidence"]
