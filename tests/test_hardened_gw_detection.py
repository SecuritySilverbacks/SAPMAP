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
    # Error message now cites gw/sec_info (STARTED_PRG governed by secinfo,
    # not reginfo) — 2026-10-07 terminology correction after secinfo/reginfo
    # confusion was flagged.  Previous assertion required "hardened gateway"
    # literal; new message says "gateway ACL".
    assert "gateway acl" in info["error_msg"].lower()
    assert "sec_info" in info["error_msg"].lower()
    assert "2808158" in info["error_msg"], (
        "error_msg must cite SAP Note 2808158 so operators can "
        "look up the hardening")
    assert "dev_rd" in info["error_msg"].lower(), (
        "error_msg must point operators at dev_rd for the authoritative "
        "reject reason — our classifier is heuristic, dev_rd is ground truth")


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


def test_chain_hardened_reject_patient_until_nilist_or_120s():
    """Follow-up (user log 2026-10-06 — kernel 916 + fully open
    reginfo + VPN): on a vulnerable GW, the first few F_SAP_INIT
    responses after betrusted() finishes might ALSO carry gw_id=0
    because the MS hasn't propagated our IP into the GW trust list
    yet (MS NILIST cycle fires every 15-20 min on a cold MS).  To
    tell apart "GW is actually hardened" from "GW doesn't trust us
    yet", gate the hardened_reject count on either:
      - the MS firing AD_GET_NILIST_PORT at the betrusted socket
        (proof the MS is actively propagating), OR
      - a 120 s patience floor (safety net)."""
    src = (REPO_ROOT / "modules" / "exploitation" / "sap_betrusted_chain.py"
           ).read_text(encoding="utf-8")
    # The patience floor + the signal + the gate are all pinned.
    assert "HARDENED_REJECT_PATIENCE_SECS = 120" in src
    assert "nilist_fired_event = _threading_signal.Event()" in src
    assert "nilist_fired_event.is_set()" in src
    assert "patience_reached = elapsed >= HARDENED_REJECT_PATIENCE_SECS" in src
    # The pre-patience path tells the operator what we are waiting for.
    assert "treating as" in src
    assert "propagation not yet complete" in src


def test_betrusted_accepts_trust_signal_kwarg():
    """betrusted() takes a threading.Event-shaped trust_signal
    kwarg that it sets whenever AD_GET_NILIST_PORT is handled.
    The chain creates the event and reads it to time the
    hardened_reject verdict."""
    import inspect
    import sap_ms_betrusted
    sig = inspect.signature(sap_ms_betrusted.betrusted)
    assert "trust_signal" in sig.parameters
    assert sig.parameters["trust_signal"].default is None


def test_wait_and_reply_nilist_accepts_trust_signal_kwarg():
    """The _wait_and_reply_nilist helper is where every
    AD_GET_NILIST_PORT handling site inside _wait_and_reply_nilist
    reports in via trust_signal.set() — so operator sees the signal
    firing even on an early NILIST during MS_SET_LOGON."""
    import inspect
    import sap_ms_betrusted
    sig = inspect.signature(sap_ms_betrusted._wait_and_reply_nilist)
    assert "trust_signal" in sig.parameters
    assert sig.parameters["trust_signal"].default is None
    # Three AD_GET_NILIST_PORT handler sites plus the two in
    # betrusted()'s hold loop all signal via trust_signal.set() or
    # the _mark_nilist_fired helper that wraps it.
    src = (REPO_ROOT / "modules" / "exploitation" / "sap_ms_betrusted.py"
           ).read_text(encoding="utf-8")
    assert "def _mark_nilist_fired" in src
    assert src.count("_mark_nilist_fired(") >= 4  # def + 3 calls
    assert src.count("trust_signal.set()") >= 3  # 3 hold-loop sites


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


# ---------------------------------------------------------------------------
# APPC-trailer disambiguation (2026-10-07 classifier refinement)
# ---------------------------------------------------------------------------

def _hardened_frame_with_appc(appc_rc: int, sap_rc: int = 0) -> bytes:
    """Build an 80-byte F_SAP_INIT reject envelope with the APPC trailer
    at bytes 32-39 set to (appc_rc, sap_rc).  Byte 0-1 = 06 CA (SAPRFC
    v6 header + F_SAP_INIT reply opcode), bytes 6-7 = 00 00 (gw_id=0),
    rest zero-padded to 80 bytes (the shape NPL kernel 753 returns)."""
    frame = bytearray(80)
    frame[0] = 0x06   # SAPRFC version
    frame[1] = 0xCA   # F_SAP_INIT reply opcode
    # bytes[6:8] gw_id stays 00 00
    struct.pack_into("!I", frame, 32, appc_rc)
    struct.pack_into("!I", frame, 36, sap_rc)
    return bytes(frame)


def test_appc_rc_0x06_classifies_as_source_ip_not_trusted():
    """APPC_RC = 0x06 (CM_SECURITY_NOT_VALID) means the GW rejected our
    source IP, NOT that reginfo blocked the TP.  Classifier must NOT
    upgrade this to hardened_reject — the betrusted poll loop should
    keep polling because trust propagation may still land."""
    info = parse_response(_hardened_frame_with_appc(0x06), "F_SAP_INIT")
    assert info["error"] is True
    assert info["gw_id"] == 0
    assert info["appc_rc"] == 0x06
    assert info.get("gw_reject_reason") == "source_ip_not_trusted"
    assert info.get("hardened_reject") is not True, (
        "APPC_RC=0x06 is trust-list miss, NOT reginfo hardening — "
        "setting hardened_reject here would make the poll loop bail "
        "prematurely on a chain that could still land")
    assert "CM_SECURITY_NOT_VALID" in info["error_msg"]
    assert "internal_hosts" in info["error_msg"]


def test_appc_rc_0x09_classifies_as_secinfo_kernel_deny():
    """APPC_RC = 0x09 (CM_TPN_NOT_RECOGNIZED) is a definitive secinfo
    deny — the TP name is blocked at the kernel ACL evaluator (SAP Note
    2808158 touches gw/sec_info for STARTED_PRG, not reginfo)."""
    info = parse_response(_hardened_frame_with_appc(0x09), "F_SAP_INIT")
    assert info["appc_rc"] == 0x09
    assert info.get("gw_reject_reason") == "secinfo_kernel_deny"
    assert info.get("hardened_reject") is True
    assert "sapxpg" in info["error_msg"]
    assert "2808158" in info["error_msg"]
    assert "sec_info" in info["error_msg"]


def test_appc_rc_0x0a_classifies_as_secinfo_kernel_deny():
    """APPC_RC = 0x0A (CM_TP_NOT_AVAILABLE_NO_RETRY) is the sibling
    secinfo-deny return code — same classification as 0x09."""
    info = parse_response(_hardened_frame_with_appc(0x0A), "F_SAP_INIT")
    assert info["appc_rc"] == 0x0A
    assert info.get("gw_reject_reason") == "secinfo_kernel_deny"
    assert info.get("hardened_reject") is True


def test_appc_rc_zero_preserves_default_hardened_verdict():
    """APPC_RC=0 with gw_id=0 and NO canonical conv_id at offset 40
    (default frame has only zeros there) remains hardened_reject —
    this is the A4H kernel 916 original signature.  The default label
    is secinfo_default_or_unknown because gw/sec_info governs
    STARTED_PRG; reginfo is for RegisterByName."""
    info = parse_response(_hardened_frame_with_appc(0x00), "F_SAP_INIT")
    assert info["appc_rc"] == 0x00
    assert info.get("gw_reject_reason") == "secinfo_default_or_unknown"
    assert info.get("hardened_reject") is True, (
        "APPC_RC=0 with gw_id=0 and no canonical conv_id is the A4H "
        "kernel 916 hardened signature — must preserve hardened_reject")


def test_short_frame_without_appc_trailer_falls_back():
    """Frames shorter than 40 bytes (e.g., A4H kernel 916's 24-byte
    reject envelope) can't carry an APPC trailer AND can't carry a
    canonical conv_id at offset 40.  Classifier must gracefully fall
    back to the default hardened_reject verdict."""
    short_frame = bytes.fromhex(
        "06ca03000013000000000000000000000000000000000000"
    )
    assert len(short_frame) == 24
    info = parse_response(short_frame, "F_SAP_INIT")
    assert info["appc_rc"] is None
    assert info.get("gw_reject_reason") == "secinfo_default_or_unknown"
    assert info.get("hardened_reject") is True


# ---------------------------------------------------------------------------
# Canonical conv_id gate (2026-10-07 — critical false-positive fix)
#
# Verified live 2026-10-07 that NPL kernel 753 and S4H kernel 793 are
# BOTH exploitable via STARTED_PRG=sapxpg (uid=npladm / uid=s4hadm
# returned from unauth probes through SSH tunnels from 127.0.0.1).
# The pre-fix classifier was FALSE-POSITIVING on their success responses
# — it fired hardened_reject on gw_id=0 alone, before conv_id extraction
# ran, and discarded the valid conv_id at offset 40.  SAPMAP reported
# "Gateway NOT vulnerable" while sapxpg was actually being spawned on
# the target (dev_rd confirmed TP execution for both targets).
# ---------------------------------------------------------------------------

def _simmode_success_frame(conv_id: str) -> bytes:
    """Build the 80-byte F_SAP_INIT reply shape that gw/sim_mode=1 on a
    vulnerable kernel returns: gw_id=0 at bytes[6:8], APPC_RC=0 at
    bytes[32:36], and a legitimate 8-digit ASCII conv_id at the
    SAPCPICSUFFIX location (offset 40).  Shape confirmed on NPL 753 +
    S4H 793 via tunneled probe output 2026-10-07."""
    assert len(conv_id) == 8 and conv_id.isdigit()
    frame = bytearray(80)
    frame[0] = 0x06   # SAPRFC version
    frame[1] = 0xCA   # F_SAP_INIT reply opcode
    # bytes[6:8] gw_id stays 00 00
    # bytes[32:36] appc_rc = 0
    # bytes[36:40] sap_rc = 0
    frame[40:48] = conv_id.encode("ascii")  # canonical SAPCPICSUFFIX slot
    return bytes(frame)


def test_canonical_conv_id_at_offset_40_bypasses_hardened_reject():
    """gw/sim_mode=1 vulnerable gateways (NPL 753 + S4H 793 verified)
    return gw_id=0 WITH a valid 8-digit ASCII conv_id at offset 40.
    The classifier MUST let these through — the TP has been spawned
    and the exploit can continue to P3."""
    frame = _simmode_success_frame("89271532")
    info = parse_response(frame, "F_SAP_INIT")
    assert info["gw_id"] == 0
    assert info.get("hardened_reject") is not True, (
        "gw_id=0 WITH a canonical conv_id at offset 40 is a sim_mode=1 "
        "success — do NOT classify as hardened_reject or SAPMAP will "
        "report real vulnerable gateways as 'NOT vulnerable' (NPL + "
        "S4H false-positive observed live 2026-10-07, uid=<sid>adm "
        "actually returned from unauth probe)")
    assert info["conv_id"] == "89271532"
    assert info["error"] is False


def test_cpic_counter_at_deeper_offset_still_rejects():
    """A4H kernel 916 original bug: a CPIC counter leaked DEEPER in the
    reject envelope (offset 108 in the fixture) was mis-extracted as a
    conv_id and used to retry forever.  The new canonical-offset-40
    gate must still catch this case — the counter at offset 108 is NOT
    at the SAPCPICSUFFIX slot, so hardened_reject still fires."""
    header = bytes.fromhex("06ca03000013") + struct.pack("!H", 0x0000)
    # 8 bytes header + 32 bytes zero (through offset 40) + more zeros
    # + counter at offset 108, well past the SAPCPICSUFFIX location.
    body = bytes([0x00]) * 100 + b"77096266" + bytes([0x00]) * 284
    frame = header + body
    assert len(frame) == 400
    # Verify the counter is NOT at offset 40 (sanity check for the test)
    assert frame[40:48] == b"\x00" * 8
    info = parse_response(frame, "F_SAP_INIT")
    assert info.get("hardened_reject") is True, (
        "CPIC counter at offset 108 is NOT a canonical conv_id — the "
        "A4H kernel 916 reject envelope must still trigger hardened_"
        "reject even with the new offset-40 gate")


# ---------------------------------------------------------------------------
# Operator-facing output: distinguish "trust-propagation break" from
# "secinfo content block" (2026-10-07 — operator diagnosed S4H kernel
# 793 live: gw/sim_mode=0, ms_acl_info HOST=*, secinfo DOES permit
# TP=* for USER-HOST=internal/local, yet sapxpg fails because our
# source IP is not in GW internal_hosts.  Before this fix the error
# message blamed secinfo content; the fix adds the USER-HOST
# classification hint so operators know to check SMMS Server list +
# verify MS->GW NILIST propagation).
# ---------------------------------------------------------------------------

def test_secinfo_kernel_deny_error_msg_hints_at_user_host_classification():
    """APPC_RC=0x09/0x0A error_msg must warn operators that an identical
    reject symptom can come from TWO different root causes:
      1. secinfo content: no permit rule for TP=sapxpg (file is empty
         or restrictive) — real secinfo-deny
      2. USER-HOST classification: secinfo DOES permit for internal
         hosts but our source IP is not in GW internal_hosts (MS->GW
         NILIST didn't propagate us)
    Point operators at the two authoritative diagnostics: inspect
    secinfo on disk + SMMS Server list."""
    info = parse_response(_hardened_frame_with_appc(0x09), "F_SAP_INIT")
    msg = info["error_msg"]
    # Original signal must still be present (back-compat with existing
    # assertions in test_appc_rc_0x09_classifies_as_secinfo_kernel_deny)
    assert "sapxpg" in msg
    assert "2808158" in msg
    assert "sec_info" in msg
    # New operator-facing diagnostic hint must call out BOTH
    # possibilities + name the two authoritative diagnostics.
    assert "USER-HOST=internal" in msg or "USER-HOST=`internal`" in msg, (
        "error_msg must hint at USER-HOST classification as an "
        "alternative root cause — operator was burned 2026-10-07 "
        "assuming secinfo was the problem when secinfo actually "
        "permitted TP=* for USER-HOST=internal")
    assert "internal_hosts" in msg, (
        "error_msg must name 'internal_hosts' — the GW list the "
        "operator needs to understand is missing their source IP")
    assert "SMMS" in msg and "Server list" in msg, (
        "error_msg must point operator at SMMS -> Server list as the "
        "authoritative check for 'did my MS inject actually land'")


def test_secinfo_kernel_deny_error_msg_also_fires_for_appc_rc_0x0a():
    """Same hint block must appear for the sibling APPC_RC=0x0A
    (CM_TP_NOT_AVAILABLE_NO_RETRY) — one error_msg generator serves
    both so operators get consistent guidance regardless of which
    kernel return code the GW happens to emit."""
    info = parse_response(_hardened_frame_with_appc(0x0A), "F_SAP_INIT")
    msg = info["error_msg"]
    assert "USER-HOST=internal" in msg or "USER-HOST=`internal`" in msg
    assert "internal_hosts" in msg
    assert "SMMS" in msg


def test_p3_conv_not_found_post_retry_prints_trust_propagation_hint():
    """When _probe_gw_port_for_xpg sends a retry P3 and that retry
    ALSO fails with 'Conversation NNNNNNNN not found', the operator
    sees one of the most confusing SAPMAP outputs: P2 'succeeded' but
    P3 can't find the session.  Before this fix (2026-10-07) the
    operator was left to guess between (a) CPIC counter leak at offset
    40 that the canonical conv_id gate mis-classified, OR (b) MS->GW
    NILIST propagation break (our IP not in internal_hosts).  Pin
    that the fix adds a diagnostic hint block naming both causes +
    pointing at SMMS Server list + /usr/sap/<SID>/SYS/global/secinfo
    as the two concrete checks that discriminate them."""
    src = (REPO_ROOT / "modules" / "exploitation" / "sapmap_exploit.py"
           ).read_text(encoding="utf-8")
    # The hint block fires ONLY on the "Conversation...not found"
    # pattern (gated so unrelated P3 errors don't trigger it).
    assert '"not found" in err_msg.lower()' in src
    assert '"conversation" in err_msg.lower()' in src
    # Collapse adjacent string-literal continuations so the asserts
    # match the operator-visible one-line message even when the
    # Python source wraps it across lines.
    collapsed = re.sub(r'"\s*\n\s*f?"', "", src)
    # Both hypotheses named
    assert "CPIC counter leak" in collapsed
    assert "NILIST propagation did not land" in collapsed
    # Both authoritative diagnostics pointed at
    assert "SMMS -> Server list" in collapsed
    assert "/usr/sap/<SID>/SYS/global/secinfo" in collapsed
    assert "USER-HOST=internal permit rules" in collapsed
