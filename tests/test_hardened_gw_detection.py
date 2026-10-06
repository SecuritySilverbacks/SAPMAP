"""Pins for the hardened-Gateway F_SAP_INIT rejection detection
(issue surfaced on A4H kernel 916 / 10KBLAZE betrusted chain polling
for 1500 s instead of giving up when STARTED_PRG=sapxpg is reginfo-
blocked by SAP Note 2808158).

Covers:
  * parse_response flags gw_id=0 + short F_SAP_INIT reply as
    hardened_reject (prevents the extract_ascii_strings pass from
    treating the GW's internal CPIC counter as a valid conv_id)
  * The header-shape precondition (first two bytes = 06 CA for a
    primary F_SAP_INIT reply) keeps the check from false-positiving
    on drained follow-up frames
  * The signal does NOT fire for other steps (P1, P3) that
    legitimately have gw_id=0 in their reply envelopes
  * check_gw_vulnerable's return_detail=True shape surfaces
    hardened_reject up to sap_betrusted_chain's poll loop
  * The MS trust probe (ADM_SERVER_LONG_LIST) returns a well-formed
    result dict even when the MS is unreachable, so a diagnostic
    failure never kills the main attack path
"""
from __future__ import annotations

import pathlib
import re
import socket
import struct

import pytest

import modules  # noqa: F401 — registers package paths

from sap_gw_xpg_standalone import parse_response
from sap_ms_betrusted import probe_ms_server_list


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# parse_response — hardened-reject detection
# ---------------------------------------------------------------------------

def _hardened_frame() -> bytes:
    """The exact 24-byte frame A4H kernel 916 returned to F_SAP_INIT
    in the user's bug report (see conversation 2026-10-05)."""
    return bytes.fromhex(
        "06ca03000013000000000000000000000000000000000000"
    )


def test_parse_response_flags_a4h_hardened_reject():
    """24-byte 06-CA frame with gw_id=0 is the kernel-916
    hardening signature.  Must set error=True + hardened_reject=True
    AND clear any bogus conv_id so downstream code bails cleanly."""
    info = parse_response(_hardened_frame(), "F_SAP_INIT")
    assert info["error"] is True
    assert info["hardened_reject"] is True
    assert info["gw_id"] == 0
    assert info.get("conv_id") is None, (
        "parse_response must NOT return a conv_id for a hardened "
        "reject — the GW's CPIC counter leaking into the response "
        "is not a real session identifier")
    assert "hardened gateway" in info["error_msg"].lower()
    assert "2808158" in info["error_msg"], (
        "error_msg must cite SAP Note 2808158 so operators can "
        "look up the hardening")


def test_hardened_reject_also_matches_p2_alias():
    """step_name is 'P2' in sapmap_exploit._p1_p2 and 'F_SAP_INIT'
    in the standalone's loop — both must trigger the check."""
    info_p2 = parse_response(_hardened_frame(), "P2")
    assert info_p2["hardened_reject"] is True
    assert info_p2["error"] is True


def test_hardened_reject_requires_f_sap_init_header():
    """A frame of the same length + gw_id=0 but WITHOUT the 06-CA
    header must NOT trigger the hardened-reject check — this keeps
    the check from false-positiving on drained follow-up frames
    that happen to be short."""
    # 24 bytes starting with 07-xx (version 7 or some other opcode).
    bogus = bytes([0x07, 0x00]) + bytes(22)
    info = parse_response(bogus, "F_SAP_INIT")
    assert info.get("hardened_reject") is not True
    # Non-F_SAP_INIT shape → parser should NOT fast-path as error.
    assert info["error"] is False


def test_hardened_reject_does_not_fire_on_p1():
    """P1 responses can legitimately carry gw_id=0 in some kernels —
    the step_name gate must keep the hardening check off that path."""
    short_frame = bytes.fromhex(
        "06ca03000013000000000000000000000000000000000000"
    )
    # Same bytes as the A4H frame — but called from the P1 code path.
    info = parse_response(short_frame, "P1")
    assert info.get("hardened_reject") is not True


def test_hardened_reject_does_not_fire_on_p3():
    """P3 (SAPXPG_START_XPG_LONG) replies have their own envelope and
    their own error signals (*ERR* text).  The gw_id=0 check must
    not spuriously flip a legitimate P3 reply to hardened."""
    short_frame = _hardened_frame()
    info = parse_response(short_frame, "P3")
    assert info.get("hardened_reject") is not True


def test_hardened_reject_fires_on_long_frame_with_gw_id_zero():
    """A4H kernel 916 pads the reject envelope well past 64 bytes —
    long enough for extract_ascii_strings to find the CPIC counter
    the parser was mis-treating as a conv_id (user log 2026-10-06,
    conv_ids like 77096266 climbing monotonically across unrelated
    TCP connections).  The hardened signal must fire on gw_id==0
    regardless of frame length, so long as the F_SAP_INIT header
    shape matches."""
    header = bytes.fromhex("06ca03000013") + struct.pack("!H", 0x0000)
    # 400 bytes with an 8-digit ASCII counter embedded (what the GW's
    # internal CPIC counter looks like leaking into the reject envelope).
    body = bytes([0x00]) * 100 + b"77096266" + bytes([0x00]) * 284
    frame = header + body
    assert len(frame) == 400
    info = parse_response(frame, "F_SAP_INIT")
    assert info["hardened_reject"] is True
    assert info["error"] is True
    assert info["gw_id"] == 0
    # conv_id must be cleared even though the counter is present.
    assert info["conv_id"] is None


def test_hardened_reject_does_not_fire_on_long_f_sap_init_reply():
    """A vulnerable gateway's F_SAP_INIT reply is 420-520 bytes with a
    non-zero gw_id in the header.  Build a synthetic 400-byte reply
    with gw_id=0x1234 and confirm the check does NOT fire."""
    # Header: 06 CA 03 00 00 13 12 34 ... (gw_id = 0x1234 at [6:8])
    header = bytes.fromhex("06ca03000013") + struct.pack("!H", 0x1234)
    body = bytes([0x00]) * 392   # pad to 400 bytes total
    frame = header + body
    assert len(frame) == 400
    info = parse_response(frame, "F_SAP_INIT")
    assert info.get("hardened_reject") is not True
    assert info["gw_id"] == 0x1234
    assert info["error"] is False


def test_hardened_reject_does_not_fire_on_short_frame_with_nonzero_gw_id():
    """gw_id != 0 means the GW DID allocate state for us — the
    check must only fire when gw_id==0, period."""
    header = bytes.fromhex("06ca03000013") + struct.pack("!H", 0x0042)
    frame = header + bytes([0x00]) * 16   # 24 bytes, nonzero gw_id
    info = parse_response(frame, "F_SAP_INIT")
    assert info.get("hardened_reject") is not True


# ---------------------------------------------------------------------------
# check_gw_vulnerable return_detail=True — Fix #1 integration
# ---------------------------------------------------------------------------

def test_check_gw_vulnerable_return_detail_shape():
    """New kwarg return_detail=True returns a dict with the three
    keys sap_betrusted_chain's poll loop reads: vulnerable,
    hardened_reject, detail.  Shape must be stable so callers can
    key off it without defensive guards."""
    src = (REPO_ROOT / "modules" / "exploitation" / "sapmap_exploit.py"
           ).read_text(encoding="utf-8")
    # The shape is built in a tiny inline _result helper — pin the
    # keys so a refactor can't silently rename them.
    m = re.search(
        r"def _result\(vuln:[^)]*\):\s*(.*?)return bool\(vuln\)",
        src, re.DOTALL)
    assert m, "_result helper not found in check_gw_vulnerable"
    body = m.group(1)
    assert '"vulnerable":' in body
    assert '"hardened_reject":' in body
    assert '"detail":' in body


def test_check_gw_vulnerable_backward_compat_bool_return():
    """Existing callers that call check_gw_vulnerable(node) without
    the kwarg must still get a bare bool back."""
    src = (REPO_ROOT / "modules" / "exploitation" / "sapmap_exploit.py"
           ).read_text(encoding="utf-8")
    assert "def check_gw_vulnerable(node: SAPNode, *, return_detail: bool = False)" in src
    # The helper returns bool when return_detail is False.
    assert "return bool(vuln)" in src


def test_p2_hardened_reject_status_propagates_through_p1_p2():
    """_p1_p2 must return the new 'p2_hardened_reject' status (not
    the generic 'p2_err') when parse_response flags
    hardened_reject.  This lets check_gw_vulnerable surface the
    hardened signal in return_detail."""
    src = (REPO_ROOT / "modules" / "exploitation" / "sapmap_exploit.py"
           ).read_text(encoding="utf-8")
    assert 'return ("p2_hardened_reject"' in src
    # And check_gw_vulnerable's outer loop handles the new status.
    assert 'if status == "p2_hardened_reject":' in src
    assert '"hardened_reject": True' in src


# ---------------------------------------------------------------------------
# sap_betrusted_chain poll loop — early abort on hardened_reject
# ---------------------------------------------------------------------------

def test_betrusted_poll_loop_early_abort_on_hardened_reject():
    """The 25-minute poll must NOT keep running against a kernel 916
    gateway that reports hardened_reject.  Threshold = 2 consecutive
    hardened_reject probes before aborting."""
    src = (REPO_ROOT / "modules" / "exploitation" / "sap_betrusted_chain.py"
           ).read_text(encoding="utf-8")
    assert "HARDENED_REJECT_THRESHOLD = 2" in src
    assert "hardened_rejects += 1" in src
    assert "aborting poll after" in src
    assert "return_detail=True" in src


def test_betrusted_poll_loop_resets_counter_on_non_hardened_rejection():
    """A non-hardened error between hardened-reject probes must
    reset the counter — one accidental misclassification should not
    accumulate false confidence that the GW is hardened."""
    src = (REPO_ROOT / "modules" / "exploitation" / "sap_betrusted_chain.py"
           ).read_text(encoding="utf-8")
    # The reset happens inside the else-branch of the probe loop.
    assert "hardened_rejects = 0" in src
    assert "false confidence" in src


# ---------------------------------------------------------------------------
# probe_ms_server_list (Fix #3)
# ---------------------------------------------------------------------------

def test_probe_ms_server_list_returns_stable_dict_shape():
    """Every exit path (connect fail, LOGIN fail, timeout, success,
    exception) must return a dict with the same six keys so callers
    never need defensive guards."""
    # Hit an obviously-unreachable port to force the connect-fail path.
    result = probe_ms_server_list(
        "127.0.0.1", 1, needle="192.168.2.196", timeout=0.5)
    for key in ("connected", "sent", "received", "response_len",
                 "has_needle", "error"):
        assert key in result, f"missing key: {key}"
    assert result["connected"] is False
    assert result["sent"] is False
    assert result["received"] is False
    assert result["response_len"] == 0
    assert result["has_needle"] is False
    assert result["error"]   # non-empty error message


def test_probe_ms_server_list_separate_socket_architecture():
    """The betrusted thread's socket is server-role and cannot send
    ADM queries without triggering MS LOGOUT.  Pin: probe_ms_server_list
    takes host/port (not a socket), proving it opens its own
    connection with a benign client-role LOGIN_2."""
    import inspect
    sig = inspect.signature(probe_ms_server_list)
    assert list(sig.parameters.keys())[:2] == ["host", "port"]
    # Pin the default benign probe name — must NOT be the attacker's
    # injected app-server name.
    assert sig.parameters["probe_name"].default == "sapmap_probe"


def test_probe_ms_server_list_scans_for_dot_and_dash_forms():
    """Different kernels render IPs in the server-list response as
    either dotted-decimal ("192.168.2.196") or hyphenated
    ("192-168-2-196" — the ncpic_lu form).  The probe must check
    both so a kernel-rendering-variant doesn't miss the match."""
    src = (REPO_ROOT / "modules" / "exploitation" / "sap_ms_betrusted.py"
           ).read_text(encoding="utf-8")
    # Primary scan uses the raw needle bytes.
    assert "needle_b in resp:" in src
    # Fallback scan replaces dots with dashes.
    assert 'needle.replace(".", "-")' in src


def test_betrusted_chain_wires_in_trust_probe_before_poll():
    """sap_betrusted_chain must call probe_ms_server_list ONCE after
    Phase 1 settles and BEFORE entering the GW poll loop — operator
    gets an immediate verdict on whether the MS inject actually
    landed."""
    src = (REPO_ROOT / "modules" / "exploitation" / "sap_betrusted_chain.py"
           ).read_text(encoding="utf-8")
    assert "from sap_ms_betrusted import probe_ms_server_list" in src
    # The three distinct log paths — confirmation, miss, inconclusive.
    assert "MS table confirms injection" in src
    assert "does NOT contain" in src
    assert "MS SERVER_LONG_LIST probe" in src
    # Never kill the main attack path — the whole thing is in a try/
    # except that logs and continues.
    assert "MS trust probe skipped" in src


# ---------------------------------------------------------------------------
# attacker_ip source-mismatch auto-correct (A4H kernel 916 scenario,
# user log 2026-10-06) — betrusted() must swap the auto-detected
# routing-table IP for sock.getsockname()[0] when they differ, otherwise
# MS silently drops MOD_STATE and SMMS never shows our entry.
# ---------------------------------------------------------------------------

def test_betrusted_accepts_attacker_ip_auto_detected_kwarg():
    """The caller signals 'I auto-detected the IP via a routing-table
    lookup — feel free to override me with the actual socket source
    IP if they differ'.  Default is False so existing callers that
    pass an explicit attacker_ip are honoured verbatim."""
    import inspect
    import sap_ms_betrusted
    sig = inspect.signature(sap_ms_betrusted.betrusted)
    assert "attacker_ip_auto_detected" in sig.parameters
    assert sig.parameters["attacker_ip_auto_detected"].default is False


def test_betrusted_chain_sets_auto_detected_flag_on_auto_path():
    """When sap_betrusted_chain's try_betrusted_chain derives the IP
    via _get_local_ip_towards (operator passed empty), it must pass
    attacker_ip_auto_detected=True so betrusted() knows it can swap.
    When the operator passed an explicit IP, the flag stays False."""
    src = (REPO_ROOT / "modules" / "exploitation" / "sap_betrusted_chain.py"
           ).read_text(encoding="utf-8")
    # The auto-detected path sets the flag to True.
    assert "attacker_ip_auto_detected = False" in src
    assert "attacker_ip_auto_detected = True" in src
    # The flag is threaded through into the betrusted() call.
    assert "attacker_ip_auto_detected=attacker_ip_auto_detected" in src


def test_betrusted_swap_log_cites_sock_getsockname():
    """When betrusted() swaps the attacker_ip for the actual socket
    source, the log line must explain WHY (VPN / Docker-bridge /
    multi-route) so the operator understands the correction."""
    src = (REPO_ROOT / "modules" / "exploitation" / "sap_ms_betrusted.py"
           ).read_text(encoding="utf-8")
    assert "sock.getsockname" in src
    assert "auto-detected" in src
    assert "swapping dp_addr_from" in src
    # The explanatory hint must cite the common root causes.
    assert "VPN" in src


def test_betrusted_swaps_both_auto_and_explicit_by_default():
    """Follow-up (user log 2026-10-06, VPN scenario): the swap must
    fire regardless of whether attacker_ip was auto-detected or set
    explicitly by the operator.  A GUI operator who filled in the
    pre-populated routing-table IP has no way to know that was wrong
    — if we only warn, the betrusted injection fails every time.
    The MS binds registrations to the TCP source IP, so swapping is
    "correct by construction"."""
    src = (REPO_ROOT / "modules" / "exploitation" / "sap_ms_betrusted.py"
           ).read_text(encoding="utf-8")
    # Both reason strings — auto AND explicit — route to the SAME
    # swap action, not two different ones.
    assert "attacker_ip was auto-detected as" in src
    # String literals split across lines — collapse whitespace before
    # matching so the test does not depend on exact wrapping.
    import re as _re
    collapsed = _re.sub(r'"\s*\n\s*(f?)"', "", src)
    assert "does NOT match the actual TCP source IP" in collapsed
    assert "swapping dp_addr_from" in src
    # And the swap assignment happens unconditionally for the
    # non-force path.
    assert "attacker_ip = actual_src_ip" in src


def test_betrusted_force_attacker_ip_disables_swap():
    """Escape hatch for reverse-tunnel / NAT setups where the
    operator genuinely wants dp_addr_from to differ from the TCP
    source.  force_attacker_ip=True keeps their choice; default
    False triggers the swap."""
    import inspect
    import sap_ms_betrusted
    sig = inspect.signature(sap_ms_betrusted.betrusted)
    assert "force_attacker_ip" in sig.parameters
    assert sig.parameters["force_attacker_ip"].default is False
    src = (REPO_ROOT / "modules" / "exploitation" / "sap_ms_betrusted.py"
           ).read_text(encoding="utf-8")
    # The force branch logs that it is honoring the operator but
    # expects the MS to silently discard MOD_STATE.
    assert "force_attacker_ip=True so" in src
    assert "silently discard MOD_STATE" in src


def test_betrusted_chain_retries_trust_probe_with_probe_local_ip():
    """When the first SERVER_LONG_LIST lookup misses because
    attacker_ip is stale (betrusted's internal swap moved on but the
    chain still holds the pre-swap value), the chain must retry with
    the probe's own local_ip as the needle.  Otherwise the operator
    sees a confusing "does NOT contain" message immediately before
    the GW poll proves the exploit chain is actually working from
    the correct IP (user log 2026-10-06)."""
    src = (REPO_ROOT / "modules" / "exploitation" / "sap_betrusted_chain.py"
           ).read_text(encoding="utf-8")
    # The chain calls probe_ms_server_list a second time with
    # needle=_probe_local_ip when the first call missed.
    assert "_probe_secondary = _probe_ms(" in src
    assert "needle=_probe_local_ip" in src
    # Positive log path when the secondary needle lands.
    assert "the actual TCP source IP" in src
    assert "betrusted auto-swapped" in src


def test_betrusted_chain_final_message_differentiates_hardened_vs_timeout():
    """The final "trust never arrived" message must distinguish
    "we aborted on hardened_reject after N seconds" from "we timed
    out waiting for propagation after the full 1500s budget".
    Previously the message hard-coded max_wait and said "not trusted
    after 1500s" even when the hardened-reject path exited in 20s
    (user log 2026-10-06)."""
    src = (REPO_ROOT / "modules" / "exploitation" / "sap_betrusted_chain.py"
           ).read_text(encoding="utf-8")
    # The poll loop tracks why it exited.
    assert 'poll_exit_reason = "poll_timeout"' in src
    assert 'poll_exit_reason = "vulnerable"' in src
    assert 'poll_exit_reason = "hardened_reject"' in src
    # Final message branches on the reason.
    assert 'if poll_exit_reason == "hardened_reject":' in src
    assert "Target is NOT exploitable via unauth" in src
    assert "SAP Note 2808158" in src
    # And the timeout path reports the actual elapsed time, not
    # max_wait.
    assert 'Gateway not trusted after {elapsed}s' in src


def test_create_user_betrusted_chain_distinguishes_hardened_from_user_cancel():
    """When try_betrusted_chain self-aborts on hardened_reject, the
    outer create_user_betrusted_chain wrapper must NOT print the
    misleading "10KBLAZE chain cancelled by user" message.  It
    reads the poll_exit_reason stamp on the node to distinguish."""
    src = (REPO_ROOT / "modules" / "exploitation" / "sap_betrusted_chain.py"
           ).read_text(encoding="utf-8")
    # The stamp is written in both the hardened + user-cancel paths
    # of try_betrusted_chain so the outer wrapper always has data.
    assert '"_last_betrusted_poll_exit_reason"' in src
    assert '"hardened_reject"' in src
    assert '"user_cancel"' in src
    # The outer wrapper reads the stamp and skips the "cancelled by
    # user" + "Phase 2 anyway" paths when hardened_reject is the
    # real reason.
    assert "poll_reason = getattr(" in src
    assert 'poll_reason == "hardened_reject"' in src


def test_probe_ms_server_list_returns_local_ip_field():
    """The probe's own TCP source IP is a secondary needle candidate
    — if the user-provided needle doesn't match but the probe's own
    source IP does, that's a strong hint that the operator's
    attacker_ip is wrong.  Pin: probe_ms_server_list must return a
    local_ip key for the chain to use in its diagnostic message."""
    # Hit an unreachable port to confirm the key is always present,
    # not just on the happy path.
    result = probe_ms_server_list(
        "127.0.0.1", 1, needle="192.168.2.196", timeout=0.5)
    assert "local_ip" in result
    # On connect-fail the local_ip is empty (the socket never bound).
    assert result["local_ip"] == ""


def test_chain_surface_diagnostic_mismatch_hint():
    """When the probe's local_ip differs from attacker_ip AND the
    SERVER_LONG_LIST reply is LARGE enough to contain real entries
    AND still doesn't contain either needle, the chain must emit a
    "both IPs missing" hint explaining what the operator is looking
    at — but not tell them to "re-run with X" since betrusted now
    auto-swaps on its own (user log 2026-10-06)."""
    src = (REPO_ROOT / "modules" / "exploitation" / "sap_betrusted_chain.py"
           ).read_text(encoding="utf-8")
    assert "Probe's own TCP source was" in src
    # betrusted now does the swap automatically — operator doesn't
    # need to re-run with a different IP.  Match whitespace-insensitive
    # because the explanatory text wraps across string literals.
    import re as _re
    collapsed = _re.sub(r'"\s*\n\s*(f?)"', "", src)
    assert "betrusted should have auto-swapped" in collapsed


def test_chain_probe_short_reply_treated_as_inconclusive():
    """Follow-up (user log 2026-10-06): the MS strips the server
    list for unauthenticated LOGIN_2 probe clients, returning a
    short (~151 B) empty-ADM envelope regardless of whether the
    inject landed.  The chain must NOT misinterpret that as "inject
    never landed" — it is inconclusive.  Only a LARGE reply that is
    missing both needles is a strong "inject failed" signal.

    Threshold: 110 (MS header) + 36 (ADM extended header) + 104 (one
    SERVER_LONG_LIST record) = 250 B.  Below that, there is no room
    for even a single real entry."""
    src = (REPO_ROOT / "modules" / "exploitation" / "sap_betrusted_chain.py"
           ).read_text(encoding="utf-8")
    assert "SHORT_REPLY_THRESHOLD = 250" in src
    # The short-reply branch must emit a neutral informational
    # message, not the alarming "inject never landed" one.
    import re as _re
    collapsed = _re.sub(r'"\s*\n\s*(f?)"', "", src)
    assert "too short to contain any server-list entries" in collapsed
    assert "NEITHER a confirmation nor a denial of the inject" in collapsed
    # And must point the operator at the real signal: AD_GET_NILIST_
    # PORT further down the log.
    assert "AD_GET_NILIST_PORT" in src
    assert "authoritative registration-committed signal" in collapsed
