"""Pins for the attacker-side hostname-resolution diagnostic shipped with
the dash-form _derive_appserver_name fix (PR #114, 2026-10-08).

Context: on an ABAP-integrated gateway (NW ABAP / S4H kernel 793), the GW's
"internal" keyword in secinfo resolves to the hostname list the ABAP work
process pushes via NILIST (RSMONGWY_SEND_NILIST, ~5 min cycle).  For an
incoming F_SAP_INIT from `attacker_ip` to classify as USER-HOST=internal
(and match a USER-HOST=internal secinfo permit rule), the GW does:
  1. reverse-DNS(attacker_ip) on the GW HOST
  2. string-match that hostname against the NILIST entries

Our NILIST entry is `our_name` (dash-form IP + SID + instance + random
suffix).  Unless the target's reverse-DNS of attacker_ip returns EXACTLY
`our_name`, the match fails and secinfo logs "no rule found".  SAPMAP
cannot test the target's resolver directly, but it CAN test its own
resolver — attacker-side NXDOMAIN is a strong signal the operator needs
one of three workarounds to unblock trust propagation.  This file pins
that the warning + the three workaround recipes appear whenever
attacker-side resolution fails.

These tests are source-level (grep the module source) rather than
behavioural (call betrusted() end-to-end) because the warning fires
inside the long-running hold loop and requires a live MS/GW to exercise.
Pin shape mirrors the existing `test_chain_surface_diagnostic_mismatch_hint`
in test_hardened_gw_detection.py.
"""
from __future__ import annotations

import pathlib
import re

import modules  # noqa: F401 — registers package paths


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = (REPO_ROOT / "modules" / "exploitation" / "sap_ms_betrusted.py"
       ).read_text(encoding="utf-8")

# Collapse adjacent Python string-literal continuations so the asserts
# can match the operator-visible one-line message even when the source
# wraps it across lines.
COLLAPSED = re.sub(r'"\s*\n\s*f?"', "", SRC)


def test_warning_fires_on_attacker_side_resolution_failure():
    """When socket.gethostbyname(our_name) raises or returns != attacker_ip,
    the diagnostic block must print a prominent WARNING pointing at the
    hostname-match-against-NILIST mechanism."""
    # The gate: attacker_resolves=False condition must be present
    assert "attacker_resolves = (resolved == attacker_ip)" in SRC
    assert "if not attacker_resolves:" in SRC
    # And the WARNING headline must mention 'registered hostname' + the
    # specific anti-pattern we're warning about (NXDOMAIN from attacker side)
    assert "WARNING: our registered hostname" in COLLAPSED
    assert "does NOT resolve" in COLLAPSED
    assert "NXDOMAIN" in COLLAPSED
    # Mechanism explanation
    assert "GW's NILIST->internal_hosts matching will fail" in COLLAPSED
    assert "NOT be classified as 'internal'" in COLLAPSED


def test_warning_lists_all_three_operator_workarounds():
    """Operator must see all three fix recipes (profile edit, /etc/hosts
    alias, explicit secinfo rule) with concrete commands — not a vague
    'check your config'.  Pin: each of the three workarounds appears with
    its specific keyword/payload."""
    # (1) target profile — gw/alternative_hostnames
    assert "gw/alternative_hostnames = " in COLLAPSED
    assert "classifies" in COLLAPSED and "'local'" in COLLAPSED
    # (2) target /etc/hosts alias
    assert "/etc/hosts" in COLLAPSED
    assert "reverse-DNS" in COLLAPSED
    # (3) target secinfo explicit permit
    assert "P USER=* USER-HOST=" in COLLAPSED
    assert "HOST=local TP=*" in COLLAPSED


def test_warning_does_NOT_fire_when_attacker_resolves():
    """The else branch (attacker-side resolution SUCCEEDS and matches
    attacker_ip) must NOT print the warning — printing it on every inject
    would train operators to ignore it.  Only print on failure, i.e. when
    we have a specific signal that NILIST matching is likely broken."""
    # The else branch must set the flag without printing the warning
    # body — only `attacker_resolves_our_name` + `resolution_warning_printed`
    # bookkeeping on the result dict.
    assert "else:\n            result[\"attacker_resolves_our_name\"] = True" in SRC
    assert "result[\"resolution_warning_printed\"] = False" in SRC
    # Guard: the WARNING headline must not appear outside the
    # `if not attacker_resolves:` block.  There's exactly one occurrence
    # of the WARNING headline string in the module.
    assert SRC.count("WARNING: our registered hostname") == 1


def test_result_dict_carries_diagnostic_flags():
    """The betrusted() result dict must carry two new keys so the chain
    layer (and tests) can read the diagnostic without re-running the
    resolution: attacker_resolves_our_name (bool), resolution_warning_
    printed (bool)."""
    assert 'result["attacker_resolves_our_name"] = False' in SRC
    assert 'result["attacker_resolves_our_name"] = True' in SRC
    assert 'result["resolution_warning_printed"] = True' in SRC
    assert 'result["resolution_warning_printed"] = False' in SRC


def test_warning_cites_the_authoritative_mechanism_doc():
    """The warning must point operators at the full mechanism (not just
    the symptom) so future operators can learn WHY their IP isn't
    classified internal rather than cargo-culting the three recipes."""
    # Point at the docstring of _derive_appserver_name where the full
    # NILIST / hostname-matching mechanism is documented.
    assert "_derive_appserver_name" in COLLAPSED


def test_derive_appserver_name_docstring_explains_dash_form_rationale():
    """Docstring must explain WHY we use dashes (not just that we do) —
    the previous dotted-IP docstring was factually wrong ('gethostbyname
    resolves raw IPs directly') and misled implementers.  Pin that the
    new docstring names the dot-split bug + the NILIST-matching mechanism
    + the three workarounds."""
    # Find the docstring block
    docstring_start = SRC.index('def _derive_appserver_name(')
    docstring_end = SRC.index('"""', SRC.index('"""', docstring_start) + 3) + 3
    docstring = SRC[docstring_start:docstring_end]
    # Format pin
    assert "<ip_with_dashes>" in docstring
    assert "192-168-2-11_S4H_00" in docstring  # the example in the docstring
    # Mechanism pin
    assert "parses any" in docstring and "FIRST dot" in docstring
    assert "NILIST" in docstring
    # Three-workaround pin
    assert "gw/alternative_hostnames" in docstring
    assert "/etc/hosts" in docstring
    assert "secinfo" in docstring
    # NO leftover false claim from the old docstring
    assert "gethostbyname() resolves" not in docstring, (
        "The old docstring claimed gethostbyname resolves dotted-IP "
        "hostnames directly, which is false (MS kernel parses on first "
        "dot).  The new docstring must not carry this claim.")
