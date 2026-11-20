"""Issue #221: DEST_RFC_TCPIP_CREATE failures must be negatively cached
on the source node so a looping caller (LPE binary chunk upload,
transport-import chunk loop, miniplasma per-command walk) does not
re-run the full RFCDES scan plus a doomed create attempt once per
iteration. The pentest observation was 5+ minutes of retries during a
single run against an S_RFC_ADM-less user.

Cache tuple shape: ``(err_msg, err_ts, already_printed, ttl_s)``. The
TTL is chosen per-error — persistent policy denials (FL046, SDEST
refusal, bad credentials) hold for the full ``_SXPG_CREATE_RETRY_TTL_S``;
anything else (transport/connection blip) holds for the short
``_SXPG_CREATE_RETRY_TTL_SHORT_S`` so a flaky link does not silently
lock SXPG for 5 minutes.

Invariants under test:

1. The negative cache attribute ``_sxpg_dest_cache_err`` is written the
   first time ``create_tcpip_destination`` returns ``success=False``.
2. The next ``execute_local_command`` call within the TTL short-circuits
   without opening any RFC connection AND without re-invoking
   ``create_tcpip_destination``.
3. The short-circuit returns an error that carries the cached message
   so callers can distinguish it from a non-cached failure.
4. The explanatory banner is printed exactly once per cache entry on
   stdout (never stderr) — a 100-chunk upload must not emit 100 copies.
5. After the TTL elapses the negative cache is dropped and the next
   call attempts a fresh create.
6. A successful ``create_tcpip_destination`` on a node whose negative
   cache was re-seeded mid-discovery clears that cache (positive wins
   on the actual success-path cleanup line, not on the TTL-expiry
   pre-clear).
7. ``clear_sxpg_dest_cache(node)`` removes both attributes and is
   idempotent across consecutive calls.
8. Transient errors (no known policy marker in the message) get the
   short TTL; policy denials (FL046 / SDEST E / no authorization / user
   is locked) get the full TTL.
9. The positive cache still wins when both caches are live — the TTL-
   active negative cache must not steal control from a cached success.

All tests patch ``_get_connection`` + ``create_tcpip_destination`` so
no socket is opened — invariants are structural, not network-dependent.
"""

import time
from unittest.mock import patch, MagicMock

import sapmap_rfc
from sapmap_models import Credentials, SAPNode, InstanceInfo


# ---------------------------------------------------------------------------
# Shared fixture plumbing — a minimal connection that returns "no RFCDES
# matches" so execute_local_command falls through to the create path.
# ---------------------------------------------------------------------------

class _NoRfcdesConn:
    def call(self, fm, **kwargs):
        if fm == "RFC_READ_TABLE":
            return {"DATA": []}
        return {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _node():
    return SAPNode(
        sid="N21",
        ip="10.0.0.21",
        hostname="sapn21.lab",
        instances=[InstanceInfo(instance_nr="00", ip="10.0.0.21",
                                ports={3300: "gateway"})],
    )


# ---------------------------------------------------------------------------
# 1. Negative cache attribute is written on create failure with the
#    tuple shape (msg, ts, already_printed=False, ttl_s).
# ---------------------------------------------------------------------------

def test_create_failure_populates_negative_cache_with_message_ts_and_ttl(monkeypatch):
    monkeypatch.setattr(sapmap_rfc, "_get_connection",
                        lambda *a, **k: _NoRfcdesConn())

    node = _node()
    # Defensive — fresh factory, nothing stale leaked from another test.
    assert not hasattr(node, "_sxpg_dest_cache_err")

    failing = {"success": False,
               "dest_name": "SAPMAP_N21_X",
               "message": "FL046 No authorization to call DEST_RFC_TCPIP_CREATE"}

    before = time.time()
    with patch.object(sapmap_rfc, "create_tcpip_destination",
                      return_value=failing):
        out = sapmap_rfc.execute_local_command(
            node, "id", "", Credentials("u", "p"))
    after = time.time()

    assert out["success"] is False
    assert "FL046" in out["error"]

    cached = getattr(node, "_sxpg_dest_cache_err", None)
    assert cached is not None, "negative cache was not set on failure"
    err_msg, err_ts, already_printed, ttl_s = cached
    assert err_msg == failing["message"]
    assert before <= err_ts <= after
    assert already_printed is False, "printed-flag must start False"
    # FL046 is a policy denial — full TTL.
    assert ttl_s == sapmap_rfc._SXPG_CREATE_RETRY_TTL_S


# ---------------------------------------------------------------------------
# 2. Subsequent call within TTL short-circuits and does NOT re-invoke
#    create_tcpip_destination OR open an RFC connection. Explicit pre/
#    post assertions on cache state pin that the short-circuit path
#    fires (not the positive-cache path).
# ---------------------------------------------------------------------------

def test_second_call_within_ttl_short_circuits_without_rfc(monkeypatch):
    conn_mock = MagicMock(wraps=_NoRfcdesConn())
    call_count = {"n": 0}

    def _tracking_get_conn(*a, **k):
        call_count["n"] += 1
        return conn_mock

    monkeypatch.setattr(sapmap_rfc, "_get_connection", _tracking_get_conn)

    node = _node()
    failing = {"success": False,
               "dest_name": "SAPMAP_N21_X",
               "message": "FL046 No authorization"}

    with patch.object(sapmap_rfc, "create_tcpip_destination",
                      return_value=failing) as mk_create:
        # First call: populates the cache (opens RFC for the RFCDES scan)
        sapmap_rfc.execute_local_command(
            node, "id", "", Credentials("u", "p"))
        first_rfc_opens = call_count["n"]
        assert mk_create.call_count == 1

        # Explicit pre-check: the short-circuit fires because the
        # NEGATIVE cache is set, not because the positive cache was
        # (incorrectly) populated on the failure path.
        assert not hasattr(node, "_sxpg_dest_cache"), (
            "failure path must NOT populate the positive cache")
        assert getattr(node, "_sxpg_dest_cache_err", None) is not None

        # Second call within TTL: short-circuit
        out2 = sapmap_rfc.execute_local_command(
            node, "id", "", Credentials("u", "p"))

        # NO additional _get_connection — the RFCDES scan is skipped.
        assert call_count["n"] == first_rfc_opens
        # NO additional create_tcpip_destination.
        assert mk_create.call_count == 1
        # Still no positive cache.
        assert not hasattr(node, "_sxpg_dest_cache")

    # The short-circuit error identifies itself as cached and carries
    # the original message substring.
    assert out2["success"] is False
    assert "cached" in out2["error"].lower()
    assert "FL046" in out2["error"]


# ---------------------------------------------------------------------------
# 3. The operator-visible banner is printed exactly once on stdout and
#    never on stderr — guards against both the repeat-per-chunk
#    regression AND an accidental dual-stream emission.
# ---------------------------------------------------------------------------

def test_skip_banner_prints_once_on_stdout_only(monkeypatch, capsys):
    monkeypatch.setattr(sapmap_rfc, "_get_connection",
                        lambda *a, **k: _NoRfcdesConn())

    node = _node()
    failing = {"success": False, "dest_name": "X",
               "message": "FL046 No authorization"}

    with patch.object(sapmap_rfc, "create_tcpip_destination",
                      return_value=failing):
        # First call: populates the cache
        sapmap_rfc.execute_local_command(
            node, "id", "", Credentials("u", "p"))
        # 10 more calls within TTL — simulate the LPE chunk-upload loop.
        for _ in range(10):
            sapmap_rfc.execute_local_command(
                node, "id", "", Credentials("u", "p"))

    cap = capsys.readouterr()
    banner_fragment = "Skipping TCP/IP dest create"
    assert cap.out.count(banner_fragment) == 1, (
        f"banner should appear exactly once on stdout, got "
        f"{cap.out.count(banner_fragment)} in: {cap.out!r}")
    assert cap.err.count(banner_fragment) == 0, (
        f"banner must never emit to stderr, got "
        f"{cap.err.count(banner_fragment)} in: {cap.err!r}")


# ---------------------------------------------------------------------------
# 4. TTL expiry drops the negative cache and the next call retries.
#    Explicitly pins that WITHOUT TTL expiry the short-circuit fires —
#    guards against a regression that removes the short-circuit entirely.
# ---------------------------------------------------------------------------

def test_ttl_expiry_clears_cache_and_allows_retry(monkeypatch):
    monkeypatch.setattr(sapmap_rfc, "_get_connection",
                        lambda *a, **k: _NoRfcdesConn())

    now_succeeds = {"success": True, "dest_name": "SAPMAP_N21_Y",
                    "message": "ok"}

    # Sub-case A: a FRESH ts (not expired) must cause short-circuit —
    # create_tcpip_destination NOT called. Locks the short-circuit's
    # existence at this test-layer so a regression that disables it
    # does not fall through silently to this file's TTL-expiry case.
    node_fresh = _node()
    node_fresh._sxpg_dest_cache_err = (
        "FL046", time.time(), True,
        sapmap_rfc._SXPG_CREATE_RETRY_TTL_S,
    )
    with patch.object(sapmap_rfc, "create_tcpip_destination",
                      return_value=now_succeeds) as mk_create_fresh:
        out_fresh = sapmap_rfc.execute_local_command(
            node_fresh, "id", "", Credentials("u", "p"))
    assert out_fresh["success"] is False, "fresh ts must short-circuit"
    mk_create_fresh.assert_not_called()

    # Sub-case B: a STALE ts (TTL+1s expired) must drop the cache and
    # retry the fresh create.
    node_stale = _node()
    node_stale._sxpg_dest_cache_err = (
        "FL046 No authorization",
        time.time() - sapmap_rfc._SXPG_CREATE_RETRY_TTL_S - 1,
        True,
        sapmap_rfc._SXPG_CREATE_RETRY_TTL_S,
    )

    with patch.object(sapmap_rfc, "create_tcpip_destination",
                      return_value=now_succeeds) as mk_create_stale, \
         patch.object(sapmap_rfc, "execute_remote_command",
                      return_value={"success": True, "output": [],
                                    "error": ""}):
        out_stale = sapmap_rfc.execute_local_command(
            node_stale, "id", "", Credentials("u", "p"))

    mk_create_stale.assert_called_once()
    assert out_stale["success"] is True

    assert not hasattr(node_stale, "_sxpg_dest_cache_err")
    assert node_stale._sxpg_dest_cache == "SAPMAP_N21_Y"


# ---------------------------------------------------------------------------
# 5. Success-path cleanup (the delattr on the success branch, NOT the
#    TTL-expiry pre-clear) actually runs. Re-seed the negative cache
#    mid-discovery — after the TTL-expiry pre-clear has already fired —
#    and confirm the success-branch clears it again.
# ---------------------------------------------------------------------------

def test_success_branch_clears_mid_discovery_reseed_of_negative_cache(monkeypatch):
    """The only way to reach the success-path cleanup of
    _sxpg_dest_cache_err is for the cache to be ABSENT at entry (any
    fresh-ts cache short-circuits, any stale-ts cache is pre-cleared
    at the top of execute_local_command). We simulate a race: the
    pre-clear fires, then DURING the RFCDES scan some other code path
    on the same node writes a new negative cache tuple (a concurrent
    caller that just failed). The successful create we are about to
    perform must still clear THAT tuple — otherwise a stale negative
    cache lingers after a known-good dest is in place."""
    node = _node()

    # No cache at entry — ensure the pre-clear branch does nothing.
    assert not hasattr(node, "_sxpg_dest_cache_err")

    now_succeeds = {"success": True, "dest_name": "SAPMAP_N21_Z",
                    "message": "ok"}

    def _mid_discovery_conn(*a, **k):
        # Side effect: inject a negative-cache tuple as if a sibling
        # caller lost a race and wrote one between pre-clear and our
        # success-path cleanup.
        node._sxpg_dest_cache_err = (
            "injected concurrent failure", time.time(), True,
            sapmap_rfc._SXPG_CREATE_RETRY_TTL_S,
        )
        return _NoRfcdesConn()

    monkeypatch.setattr(sapmap_rfc, "_get_connection", _mid_discovery_conn)

    with patch.object(sapmap_rfc, "create_tcpip_destination",
                      return_value=now_succeeds), \
         patch.object(sapmap_rfc, "execute_remote_command",
                      return_value={"success": True, "output": [],
                                    "error": ""}):
        # Just before the create call, the injected tuple must exist
        # (the injection happens inside _get_connection during the
        # RFCDES scan that execute_local_command runs first).
        sapmap_rfc.execute_local_command(
            node, "id", "", Credentials("u", "p"))

    # Success-path cleanup ran — injected tuple is gone.
    assert node._sxpg_dest_cache == "SAPMAP_N21_Z"
    assert not hasattr(node, "_sxpg_dest_cache_err")


# ---------------------------------------------------------------------------
# 6. clear_sxpg_dest_cache helper nukes both caches idempotently across
#    consecutive invocations from the same state.
# ---------------------------------------------------------------------------

def test_clear_sxpg_dest_cache_drops_both_attributes_idempotently():
    node = _node()
    # Neither attribute set — must not raise, even twice.
    sapmap_rfc.clear_sxpg_dest_cache(node)
    sapmap_rfc.clear_sxpg_dest_cache(node)
    assert not hasattr(node, "_sxpg_dest_cache")
    assert not hasattr(node, "_sxpg_dest_cache_err")

    # Both set — both dropped; second call still a no-op.
    node._sxpg_dest_cache = "SAPMAP_N21_A"
    node._sxpg_dest_cache_err = (
        "err", time.time(), True, sapmap_rfc._SXPG_CREATE_RETRY_TTL_S)
    sapmap_rfc.clear_sxpg_dest_cache(node)
    assert not hasattr(node, "_sxpg_dest_cache")
    assert not hasattr(node, "_sxpg_dest_cache_err")
    sapmap_rfc.clear_sxpg_dest_cache(node)       # idempotent
    assert not hasattr(node, "_sxpg_dest_cache")
    assert not hasattr(node, "_sxpg_dest_cache_err")

    # Partial state — only positive set.
    node._sxpg_dest_cache = "SAPMAP_N21_B"
    sapmap_rfc.clear_sxpg_dest_cache(node)
    assert not hasattr(node, "_sxpg_dest_cache")
    sapmap_rfc.clear_sxpg_dest_cache(node)
    assert not hasattr(node, "_sxpg_dest_cache")

    # Partial state — only negative set.
    node._sxpg_dest_cache_err = (
        "err", time.time(), False, sapmap_rfc._SXPG_CREATE_RETRY_TTL_SHORT_S)
    sapmap_rfc.clear_sxpg_dest_cache(node)
    assert not hasattr(node, "_sxpg_dest_cache_err")
    sapmap_rfc.clear_sxpg_dest_cache(node)
    assert not hasattr(node, "_sxpg_dest_cache_err")


# ---------------------------------------------------------------------------
# 7. TTL constants: sanity + two-tier semantics.
# ---------------------------------------------------------------------------

def test_sxpg_create_retry_ttls_positive_and_two_tier():
    assert isinstance(sapmap_rfc._SXPG_CREATE_RETRY_TTL_S, int)
    assert isinstance(sapmap_rfc._SXPG_CREATE_RETRY_TTL_SHORT_S, int)
    assert sapmap_rfc._SXPG_CREATE_RETRY_TTL_S > 0
    assert sapmap_rfc._SXPG_CREATE_RETRY_TTL_SHORT_S > 0
    # Short TTL must be strictly less than full TTL — otherwise the
    # two-tier scheme collapses to a single TTL.
    assert (sapmap_rfc._SXPG_CREATE_RETRY_TTL_SHORT_S
            < sapmap_rfc._SXPG_CREATE_RETRY_TTL_S)
    # Match the SNC posture classifier's 300 s so operator-visible
    # per-node short-circuits behave consistently.
    assert sapmap_rfc._SXPG_CREATE_RETRY_TTL_S == 300


# ---------------------------------------------------------------------------
# 8. Error classifier: policy denials → full TTL, everything else → short.
# ---------------------------------------------------------------------------

def test_classify_sxpg_create_error_ttl_policy_denials_get_full_window():
    full = sapmap_rfc._SXPG_CREATE_RETRY_TTL_S
    # Canonical SAP messages for authorization / policy denial.
    for msg in (
        "FL046 No authorization to call DEST_RFC_TCPIP_CREATE",
        "fl046 message mixed-case",
        "User has no authorization for object S_RFC_ADM",
        "RFC call rejected: NOT AUTHORIZED",
        "SDEST E 017 registered program refused",
        "SDEST E some other policy variant",
        "Name or password is incorrect",
        "User is locked",
    ):
        assert sapmap_rfc._classify_sxpg_create_error_ttl(msg) == full, (
            f"expected full TTL for policy-denial message: {msg!r}")


def test_classify_sxpg_create_error_ttl_transient_errors_get_short_window():
    short = sapmap_rfc._SXPG_CREATE_RETRY_TTL_SHORT_S
    for msg in (
        "",
        "connection reset by peer",
        "Connection refused",
        "RFC_COMMUNICATION_FAILURE: partner not available",
        "Timeout during RFC call",
        "saprouter TUNNEL closed unexpectedly",
        "Unknown SAP error SOMETHING_ELSE",
    ):
        assert sapmap_rfc._classify_sxpg_create_error_ttl(msg) == short, (
            f"expected short TTL for non-policy message: {msg!r}")


def test_transient_failure_only_caches_for_short_window(monkeypatch):
    """A transient transport error must not lock SXPG for the full 5
    minutes — the short-TTL branch keeps a flaky link from silencing
    the whole engagement window."""
    monkeypatch.setattr(sapmap_rfc, "_get_connection",
                        lambda *a, **k: _NoRfcdesConn())

    node = _node()
    transient = {"success": False, "dest_name": "X",
                 "message": "Connection refused"}
    with patch.object(sapmap_rfc, "create_tcpip_destination",
                      return_value=transient):
        sapmap_rfc.execute_local_command(
            node, "id", "", Credentials("u", "p"))

    _, _, _, ttl_s = node._sxpg_dest_cache_err
    assert ttl_s == sapmap_rfc._SXPG_CREATE_RETRY_TTL_SHORT_S


# ---------------------------------------------------------------------------
# 9. Positive cache still wins over an ACTIVE negative cache. Prevents a
#    rare race where a success-path write lands with a lingering
#    negative tuple from a concurrent caller: the next call must reuse
#    the positive dest, NOT short-circuit on the negative TTL.
# ---------------------------------------------------------------------------

def test_positive_cache_still_wins_over_active_negative_cache():
    node = _node()
    node._sxpg_dest_cache = "SAPMAP_N21_REUSE"
    # Fresh (NOT stale) negative cache — within the TTL window.
    node._sxpg_dest_cache_err = (
        "FL046", time.time(), False,
        sapmap_rfc._SXPG_CREATE_RETRY_TTL_S,
    )

    with patch.object(sapmap_rfc, "execute_remote_command",
                      return_value={"success": True, "output": ["ok"],
                                    "error": ""}) as mk_run:
        out = sapmap_rfc.execute_local_command(
            node, "id", "", Credentials("u", "p"))

    assert out["success"] is True
    mk_run.assert_called_once()
    # The dest the positive-cache path reused is the positive one, not
    # a shadow from the negative-cache path.
    assert mk_run.call_args.args[1] == "SAPMAP_N21_REUSE"
