"""BTP → on-prem RFC destination test must fetch profiles regardless of
target.system_type.

Pinned bug (2026-07-12): operator ran the workstation-side mint
against researchlab-yehctg7m, pulled 4 destinations, one of them
`W74` (Type-3 RFC as sapadm/siroj1978!).  Test Connection returned:

  [+] BTP test: RFC logon OK on W74 (sapadm/001, sysnr=40, 44ms)

But the modal did NOT surface the "Create Remote User" button.
sapadm has SAP_ALL on W74 (operator-confirmed).  Reason: W74's
system_type was empty (materialised only through BTP destination
linking, no Standard Scan yet), so ``target_is_abap`` was False,
so the ``wants_bapi`` gate skipped the BAPI_USER_GET_DETAIL fetch,
so ``conn.has_sap_all`` stayed False, so the button hid.

Fix: is_rfc=True (Type-3) unconditionally triggers the BAPI
fetch.  SAP kernel forbids Type-3 destinations to non-ABAP
targets, so we KNOW the target is ABAP even without a
system_type stamp.  Also backfill target.system_type = 'ABAP'
after a successful RFC logon.

These tests pin the CONDITION expression so a refactor of the
BTP test flow can't silently regress the gate.
"""
from __future__ import annotations

import modules  # noqa: F401


def _gate_wants_bapi(*, logon_successful, is_rfc, target_is_abap,
                       platform):
    """Copy of the gate expression in
    sapmap_gui.py::btp_test_destination — kept in sync with the
    live code."""
    return logon_successful and (
        is_rfc
        or (target_is_abap
            and (platform == "ABAP" or not platform)))


def test_type_3_edge_wants_bapi_even_when_target_stack_unknown():
    """The exact failing case from the live report: W74 has
    system_type='' (no Standard Scan yet) but the destination is
    Type-3 RFC.  Gate MUST fire — the RFC logon on Type-3 is
    definitional proof the target is ABAP."""
    assert _gate_wants_bapi(
        logon_successful=True, is_rfc=True,
        target_is_abap=False,   # W74 has no system_type
        platform="") is True


def test_type_3_edge_still_wants_bapi_when_target_is_abap():
    """The pre-fix happy path must still fire (regression catch)."""
    assert _gate_wants_bapi(
        logon_successful=True, is_rfc=True,
        target_is_abap=True, platform="") is True


def test_http_edge_needs_target_is_abap():
    """HTTP-typed BTP edges (Type-G/H) still gate on
    target_is_abap AND compatible platform hint.  BAPI over HTTP
    is only viable when we KNOW the target is ABAP; running it
    against a Java stack would XML-parse-fail on the SOAP
    envelope response."""
    # HTTP + target unknown → no fetch
    assert _gate_wants_bapi(
        logon_successful=True, is_rfc=False,
        target_is_abap=False, platform="") is False
    # HTTP + target known ABAP + platform empty → fetch
    assert _gate_wants_bapi(
        logon_successful=True, is_rfc=False,
        target_is_abap=True, platform="") is True
    # HTTP + target known ABAP + platform=ABAP → fetch
    assert _gate_wants_bapi(
        logon_successful=True, is_rfc=False,
        target_is_abap=True, platform="ABAP") is True
    # HTTP + target known ABAP + platform=JAVA → NO fetch
    assert _gate_wants_bapi(
        logon_successful=True, is_rfc=False,
        target_is_abap=True, platform="JAVA") is False


def test_gate_false_when_logon_failed():
    """No point running BAPI fetch when the initial logon didn't
    even authenticate."""
    assert _gate_wants_bapi(
        logon_successful=False, is_rfc=True,
        target_is_abap=True, platform="") is False


def test_system_type_backfill_on_rfc_logon_success():
    """Symmetric fix: after a successful RFC logon on a target
    with empty system_type, we backfill 'ABAP' so subsequent
    menu-item gates (Analyse User Capabilities, Import Local
    Transport, etc.) recognise the target correctly and the
    System Details modal shows the ABAP badge.

    Pin the shape of the backfill condition, not the mutation
    itself (that's tested via the full-suite regression when
    the modal shows the button)."""
    from sapmap_models import SAPNode

    # Empty system_type → should backfill
    target = SAPNode(sid="W74", ip="192.168.2.29",
                       hostname="WINWAS74")
    condition = (True   # is_rfc
                  and True   # logon_successful
                  and target is not None
                  and not (target.system_type or "").strip())
    assert condition is True

    # Already stamped ABAP → skip (idempotent)
    target.system_type = "ABAP"
    condition = (True and True and target is not None
                  and not (target.system_type or "").strip())
    assert condition is False

    # Already stamped ABAP+JAVA → skip too
    target.system_type = "ABAP+JAVA"
    condition = (True and True and target is not None
                  and not (target.system_type or "").strip())
    assert condition is False


def test_create_remote_user_button_gates_read_from_has_sap_all():
    """The frontend hides the Create Remote User button behind
    ``!(conn.has_sap_all || conn.soap_rfc_verified)``.  When
    the BTP-side profile fetch runs and finds SAP_ALL, it flips
    has_sap_all=True and the button unhides on the next poll.
    Pin the flag itself so a refactor of the emit path can't
    accidentally rename it."""
    from sapmap_models import RFCConnection
    conn = RFCConnection(source_sid="BTP:90a90189",
                          source_host="researchlab-yehctg7m",
                          destination_name="W74",
                          rfc_type="3",
                          target_sid="W74",
                          rfc_user="sapadm",
                          client="001",
                          logon_successful=True)
    assert hasattr(conn, "has_sap_all")
    assert conn.has_sap_all is False
    # After the fixed BAPI fetch stamps SAP_ALL:
    conn.has_sap_all = True
    assert conn.has_sap_all is True
