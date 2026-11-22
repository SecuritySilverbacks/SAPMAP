#!/usr/bin/env python3
"""Issue #79 — operator source-IP override for the Gateway SAPXPG ncpic_lu.

When the SAPXPG flow is tunnelled through a SAProuter (or any NAT), the gateway
sees the *router's* IP as the connecting peer, not the local socket address.
If the gateway's reginfo is pinned to that router-visible IP, the auto-derived
``ncpic_lu`` in F_SAP_INIT (P2) does not match, registration silently fails, and
Step 3 (P3) hangs until timeout.  The fix lets the operator pin the source IP
(standalone ``--source-ip``; GUI per-node ``attacker_ip_override``).

These tests pin:
  * the precedence/warning contract of ``resolve_ncpic_source_ip``, and
  * that an explicit source IP actually reaches the F_SAP_INIT ncpic_lu field
    on the wire (not merely that a flag is stored).
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sap_gw_xpg_standalone import (  # noqa: E402
    build_p2,
    pad_right_null,
    resolve_ncpic_source_ip,
)


def _ncpic_lu_field(local_ip):
    """The 8-byte ncpic_lu field build_p2 stamps for a given source IP
    (dots -> hyphens, first 7 chars, NUL-padded to 8 — see build_p2)."""
    lu = (local_ip or "").replace(".", "-")[:7]
    return pad_right_null(lu, 8)


# ---------------------------------------------------------------------------
# resolve_ncpic_source_ip — precedence + routed warning
# ---------------------------------------------------------------------------

def test_explicit_override_wins_when_routed():
    ip, warn = resolve_ncpic_source_ip("203.0.113.9", "10.0.0.5", routed=True)
    assert ip == "203.0.113.9"
    assert warn == ""


def test_explicit_override_wins_when_direct():
    ip, warn = resolve_ncpic_source_ip("203.0.113.9", "10.0.0.5", routed=False)
    assert ip == "203.0.113.9"
    assert warn == ""


def test_explicit_override_is_whitespace_stripped():
    ip, warn = resolve_ncpic_source_ip("  203.0.113.9  ", "10.0.0.5", routed=True)
    assert ip == "203.0.113.9"
    assert warn == ""


def test_direct_no_override_uses_auto_without_warning():
    ip, warn = resolve_ncpic_source_ip("", "10.0.0.5", routed=False)
    assert ip == "10.0.0.5"
    assert warn == ""


def test_routed_no_override_falls_back_to_auto_but_warns():
    ip, warn = resolve_ncpic_source_ip("", "10.0.0.5", routed=True)
    assert ip == "10.0.0.5"           # still usable (direct-connect semantics)
    assert warn                        # but the operator is told it is likely wrong
    assert "--source-ip" in warn
    assert "#79" in warn
    assert "10.0.0.5" in warn          # names the auto value so the hint is concrete


def test_none_override_treated_as_absent():
    ip, warn = resolve_ncpic_source_ip(None, "10.0.0.5", routed=False)
    assert ip == "10.0.0.5"
    assert warn == ""


def test_non_ascii_override_is_rejected_and_falls_back():
    # A non-ASCII override would crash build_p2's ASCII encode; the helper must
    # fall back to the auto value and warn instead of propagating it.
    ip, warn = resolve_ncpic_source_ip("høst", "10.0.0.5", routed=True)
    assert ip == "10.0.0.5"
    assert warn
    assert "ignored" in warn.lower()


def test_ascii_override_passes_through_verbatim():
    # An ASCII value (even a non-dotted-quad) is the operator's explicit choice
    # and is honoured — build_p2 can encode it; validity vs reginfo is theirs.
    ip, warn = resolve_ncpic_source_ip("10.0.0.9", "10.0.0.5", routed=True)
    assert ip == "10.0.0.9"
    assert warn == ""


# ---------------------------------------------------------------------------
# The chosen source IP actually reaches the F_SAP_INIT ncpic_lu field
# ---------------------------------------------------------------------------

def test_source_ip_changes_ncpic_lu_on_the_wire():
    p2_auto = build_p2("10.0.0.1", local_ip="10.0.0.5", target_hostname="gwhost")
    p2_over = build_p2("10.0.0.1", local_ip="203.0.113.9", target_hostname="gwhost")
    assert len(p2_auto) == len(p2_over) == 452
    # Each frame carries its own source IP's ncpic_lu field...
    assert _ncpic_lu_field("10.0.0.5") in p2_auto
    assert _ncpic_lu_field("203.0.113.9") in p2_over
    # ...and the override frame replaced (not merely appended) the auto value.
    assert _ncpic_lu_field("10.0.0.5") not in p2_over


def test_resolved_override_flows_through_to_build_p2():
    """End-to-end: an operator override resolved via the helper is the value
    that lands in the packet (the whole point of the fix)."""
    src, _ = resolve_ncpic_source_ip("203.0.113.9", "10.0.0.5", routed=True)
    p2 = build_p2("10.0.0.1", local_ip=src, target_hostname="gwhost")
    assert _ncpic_lu_field("203.0.113.9") in p2
