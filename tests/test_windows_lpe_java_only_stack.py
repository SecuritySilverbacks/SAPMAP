"""Windows LPE messaging on Java-only stacks.

Pinned bug (2026-07-09): the Windows LPE picker in
``sapmap_miniplasma._make_exec`` treats "verified RFC credential →
SXPG_STEP_XPG_START" as a valid OS-exec primitive regardless of the
target stack.  On a pure Java system (e.g. SJJ, the operator's
Windows Java stack in the current landscape), SXPG_STEP_XPG_START is
not there — it's an ABAP function module — so the fallback path is
unreachable no matter what credential the operator presents.

The operator-facing message before the fix implied the opposite:

    "MiniPlasma needs one of: GW SAPXPG, CVE-2025-31324 JSP shell,
     OR a verified RFC credential (any SAPMAP-created user with
     SAP_ALL) for SXPG_STEP_XPG_START.  Run … or create a user
     first."

Which sends the operator chasing a doomed credential path.

Fix:
  1. ``_is_java_only_stack(node)`` predicate — only exact
     ``system_type == "JAVA"`` counts; ABAP+JAVA / unknown fall
     through to the full menu.
  2. ``_make_exec`` skips the SXPG path on Java-only nodes even if
     verified creds exist.
  3. ``_no_exec_primitive_reason(node, technique)`` builds the
     stack-aware message.

Shared with ``sapmap_efspotato`` and ``sapmap_godpotato`` — both
import the same helper.
"""
from __future__ import annotations

import modules  # noqa: F401  (registers package paths)
from sapmap_models import SAPNode, Credentials


# ---------------------------------------------------------------------------
# _is_java_only_stack predicate
# ---------------------------------------------------------------------------

def test_is_java_only_true_for_exact_java():
    from sapmap_miniplasma import _is_java_only_stack
    assert _is_java_only_stack(
        SAPNode(sid="SJJ", system_type="JAVA")) is True
    assert _is_java_only_stack(
        SAPNode(sid="SJJ", system_type="java")) is True


def test_is_java_only_false_for_abap_only():
    from sapmap_miniplasma import _is_java_only_stack
    assert _is_java_only_stack(
        SAPNode(sid="S4H", system_type="ABAP")) is False


def test_is_java_only_false_for_dual_stack():
    """ABAP+JAVA has ABAP, so SXPG_STEP_XPG_START is reachable."""
    from sapmap_miniplasma import _is_java_only_stack
    assert _is_java_only_stack(
        SAPNode(sid="TWT", system_type="ABAP+JAVA")) is False


def test_is_java_only_false_for_unknown_stack():
    """Unknown/empty system_type must fall through to the full menu
    — hiding the SXPG option when discovery hasn't populated the
    field would silently drop a valid path."""
    from sapmap_miniplasma import _is_java_only_stack
    assert _is_java_only_stack(SAPNode(sid="X", system_type="")) is False
    assert _is_java_only_stack(SAPNode(sid="X")) is False


# ---------------------------------------------------------------------------
# _no_exec_primitive_reason — stack-aware message
# ---------------------------------------------------------------------------

def test_reason_java_only_omits_sxpg():
    """The Java-only branch must not mention SAP_ALL or the FM
    name in the ``needs one of:`` clause — those imply a workable
    credential path that isn't there."""
    from sapmap_miniplasma import _no_exec_primitive_reason
    node = SAPNode(sid="SJJ", system_type="JAVA")
    msg = _no_exec_primitive_reason(node, "MiniPlasma")
    assert "Java-only stack" in msg
    assert "SXPG_STEP_XPG_START (ABAP FM) is not available" in msg
    # The ``needs one of:`` clause must NOT list SXPG as an option
    needs_line = msg.split(".")[0]
    assert "SXPG_STEP_XPG_START" not in needs_line
    assert "SAP_ALL" not in msg


def test_reason_java_only_still_names_gw_and_jsp():
    """The two working paths (gateway SAPXPG + CVE-2025-31324 JSP)
    must still be surfaced — those DO work on a Java stack."""
    from sapmap_miniplasma import _no_exec_primitive_reason
    msg = _no_exec_primitive_reason(
        SAPNode(sid="SJJ", system_type="JAVA"), "MiniPlasma")
    assert "GW SAPXPG" in msg
    assert "CVE-2025-31324 JSP shell" in msg


def test_reason_abap_only_includes_sxpg():
    """The original ABAP path stays — SXPG is a real fallback there."""
    from sapmap_miniplasma import _no_exec_primitive_reason
    msg = _no_exec_primitive_reason(
        SAPNode(sid="S4H", system_type="ABAP"), "MiniPlasma")
    assert "SXPG_STEP_XPG_START" in msg
    assert "SAPMAP-created user with SAP_ALL" in msg
    assert "Java-only" not in msg


def test_reason_dual_stack_includes_sxpg():
    """ABAP+JAVA nodes still expose the SXPG path."""
    from sapmap_miniplasma import _no_exec_primitive_reason
    msg = _no_exec_primitive_reason(
        SAPNode(sid="TWT", system_type="ABAP+JAVA"), "GodPotato")
    assert "SXPG_STEP_XPG_START" in msg
    assert "GodPotato" in msg   # technique name substitutes in


def test_reason_carries_technique_name():
    """Each technique gets its own name stitched into the sentence
    so a scroll-up doesn't confuse EfsPotato and MiniPlasma failures."""
    from sapmap_miniplasma import _no_exec_primitive_reason
    for tech in ("MiniPlasma", "EfsPotato", "GodPotato"):
        msg = _no_exec_primitive_reason(
            SAPNode(sid="X", system_type="ABAP"), tech)
        assert tech in msg


# ---------------------------------------------------------------------------
# _make_exec skips SXPG on Java-only stacks
# ---------------------------------------------------------------------------

def test_make_exec_skips_sxpg_on_java_only_even_with_creds():
    """The key regression pin: an SJJ node with verified SAP_ALL creds
    but no gw_vulnerable / cve_2025_31324_vulnerable must return
    (None, 0, "").  Pre-fix, _make_exec would offer SXPG here and
    the operator would watch every SXPG_STEP_XPG_START call fail with
    FU_NOT_FOUND — a clear waste of an engagement window."""
    from sapmap_miniplasma import _make_exec
    node = SAPNode(sid="SJJ", system_type="JAVA")
    node.credentials.append(Credentials(
        username="SAPMAP00", password="Andinyougo123!",
        client="000", verified=True))
    exec_fn, chunks, label = _make_exec(node, "SJJ", verbose=False)
    assert exec_fn is None
    assert label == ""


def test_make_exec_uses_sxpg_on_abap_stack_with_creds():
    """Symmetric sanity check: on ABAP, a verified cred still picks
    SXPG.  Prevents the fix from over-reaching and breaking the
    working path."""
    from sapmap_miniplasma import _make_exec
    node = SAPNode(sid="S4H", system_type="ABAP",
                    hostname="s4h", ip="10.0.0.1")
    node.credentials.append(Credentials(
        username="SAPMAP00", password="Andinyougo123!",
        client="000", verified=True))
    exec_fn, chunks, label = _make_exec(node, "S4H", verbose=False)
    assert exec_fn is not None
    assert label == "sxpg_rfc"
