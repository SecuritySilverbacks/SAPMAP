#!/usr/bin/env python3
"""Regression test: the Web Dispatcher fingerprint must NOT flag a
generic HTTP service that happens to return 401/403 for
/sap/wdisp/admin as a SAP WD.

Operator-reported: W1B on 10.10.1.27:80 plotted as WEB_DISPATCHER
but was actually a non-SAP service.  Root cause: the fingerprint
treated ANY 401/403 (without ICMENOSERVERFOUND/SYSTEMFOUND) on the
admin path as "definitive" WD evidence — but a generic HTTP server
with global basic auth, or one that returns 403 for unknown paths,
would match the same way.

Fix: require an SAP-specific corroborating marker — WWW-Authenticate
realm mentioning "WEB ADMIN" / "SAP*", OR an x-sap-icm-err-id
header anywhere, OR a Server header containing "SAP".
"""
from __future__ import annotations

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "discovery"))


def _wd_source():
    """Read the fingerprint_web_dispatcher source so we can assert
    structural invariants without spinning up a TCP server."""
    path = os.path.join(os.path.dirname(__file__), "..", "modules",
                         "discovery", "sapmap_scanner.py")
    with open(path, encoding="utf-8") as f:
        src = f.read()
    m = re.search(r"def fingerprint_web_dispatcher\(.*?\n(?=def \w)",
                  src, re.DOTALL)
    assert m, "fingerprint_web_dispatcher not found"
    return m.group(0)


def test_wd_fingerprint_requires_sap_marker_for_401_403():
    """A 401/403 response on /sap/wdisp/admin must NOT promote to
    is_wd=True unless an SAP-specific marker is also present
    (realm, ICM header, or SAP Server banner)."""
    body = _wd_source()
    # The promote-to-WD gate must require a sap_marker variable.
    assert "sap_marker" in body, (
        "Promotion of 401/403 to is_wd must consult a sap_marker — "
        "without it, generic auth-protected services false-positive")
    # The realm regex must look for 'WEB ADMIN' or 'SAP'.
    realm_match = re.search(
        r"WWW-Authenticate.*?WEB\\s\+ADMIN|SAP", body, re.DOTALL)
    assert realm_match, (
        "WD realm check must specifically test for the WD admin "
        "realm 'WEB ADMIN' (or any SAP-prefixed realm) instead of "
        "trusting any Basic-realm response")


def test_wd_fingerprint_check_not_just_status():
    """The 401/403 gate must combine status check with sap_marker —
    not be a standalone status-only branch."""
    body = _wd_source()
    # Find the if-block that sets is_wd around 401/403.
    m = re.search(
        r"if\s*\(?\s*probe_status\s+in\s+\(401,\s*403\).*?out\[\"is_wd\"\]\s*=\s*True",
        body, re.DOTALL)
    assert m, "401/403 → is_wd promotion block not found"
    gate = m.group(0)
    # The gate must reference sap_marker.
    assert "sap_marker" in gate, (
        "401/403 promotion must include sap_marker in its condition — "
        f"current gate: {gate[:200]}...")


def test_wd_fingerprint_realm_regex_excludes_generic_realms():
    """The realm regex must be specific to WEB ADMIN or SAP* — must
    not accept generic realms like 'Restricted', 'Login', 'protected'.
    The literal can be split across multiple adjacent string literals,
    so we search the whole function body."""
    body = _wd_source()
    # The m_wd_realm assignment must exist.
    assert "m_wd_realm" in body, (
        "WD realm regex (m_wd_realm) not found in fingerprint function")
    # The combined pattern must reference WEB ADMIN and SAP — and
    # must NOT be a bare 'Basic\\s+realm=' catch-all.
    realm_assign_idx = body.index("m_wd_realm")
    # Look ahead ~300 chars (the regex literal + concat strings sit
    # right after the assignment).
    window = body[realm_assign_idx:realm_assign_idx + 400]
    assert "WEB" in window and "ADMIN" in window, (
        f"WD realm regex must include 'WEB ADMIN' — got window: "
        f"{window[:200]}...")
    assert "SAP" in window, (
        f"WD realm regex should also accept SAP-prefixed realms — "
        f"got window: {window[:200]}...")
