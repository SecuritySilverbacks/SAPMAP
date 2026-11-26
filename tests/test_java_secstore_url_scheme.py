#!/usr/bin/env python3
"""Tests for Java SecStore JSP URL scheme/port resolution.

Regression: on J75 (Java-only, CVE-31324 NOT vulnerable), the CVE
scanner had probed port 50001 (HTTPS) and recorded it on the node
for "GUI display purposes" (cve_2025_31324_port=50001,
cve_2025_31324_https=True).  The SecStore runner blindly read
cve_2025_31324_port and built an `http://...:50001/...` URL — every
probe got "Connection reset by peer" because 50001 is HTTPS.

This module verifies the source-level invariants of the port
resolution logic.
"""
from __future__ import annotations

import os
import re
import sys

# Ensure modules are importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "data_extraction"))


def _runner_src():
    path = os.path.join(os.path.dirname(__file__), "..", "modules",
                         "data_extraction", "sap_java_secstore_runner.py")
    with open(path, encoding="utf-8") as f:
        return f.read()


def test_secstore_ignores_cve_port_when_not_vulnerable():
    """cve_2025_31324_port is recorded even when the node is NOT
    vulnerable (for GUI display).  The SecStore runner must skip it
    in that case, or it will try to deploy a JSP on the HTTPS port."""
    src = _runner_src()
    # Find the port-resolution block (function `extract_java_secstore`).
    m = re.search(r"def extract_java_secstore.*?# 1\..*?http_port = 0",
                  src, re.DOTALL)
    assert m, "port resolution block not found"
    body = src[m.end():m.end() + 1500]
    # Must guard cve_2025_31324_port read with cve_2025_31324_vulnerable.
    assert "cve_2025_31324_vulnerable" in body, (
        "SecStore runner must only use cve_2025_31324_port when the "
        "node is actually CVE-31324 vulnerable — otherwise the port "
        "may be HTTPS (50001) and the JSP probe gets Connection reset")


def test_secstore_picks_https_scheme_when_https_port_used():
    """When the CVE probe used HTTPS (cve_2025_31324_https=True), the
    JSP URL must use https://, not http://."""
    src = _runner_src()
    m = re.search(r"def extract_java_secstore.*?jsp_url\s*=",
                  src, re.DOTALL)
    assert m, "jsp_url construction not found"
    body = m.group(0)
    # The URL must use a variable scheme, not a hardcoded one.
    assert "jsp_scheme" in body, (
        "JSP URL must use a jsp_scheme variable (http/https) — "
        "hardcoded http:// fails on HTTPS-only Java ports")
    assert "cve_2025_31324_https" in body, (
        "SecStore runner must consult cve_2025_31324_https to pick "
        "the right URL scheme")


def test_secstore_prefers_java_http_over_https_service():
    """When falling back to inst.ports, prefer java_http (plain HTTP)
    over java_https — avoids the cert-verification path and the
    HTTP-to-HTTPS-port connection-reset trap.

    Issue #255 — the fallback was lifted out of this module into the
    shared helper ``sapmap_exploit._find_java_http_endpoint``.  This
    test now asserts (a) the delegation is wired up, and (b) the shared
    helper preserves the java_http-before-java_https preference, so
    secstore behaviour is unchanged.
    """
    # (a) Delegation: the runner must import/call the shared helper.
    src = _runner_src()
    m = re.search(r"def extract_java_secstore.*?Pick delivery path",
                  src, re.DOTALL)
    assert m, "port resolution block not found"
    body = m.group(0)
    assert "_find_java_http_endpoint" in body, (
        "SecStore runner should delegate Java-HTTP endpoint resolution "
        "to sapmap_exploit._find_java_http_endpoint (issue #255).")

    # (b) Behaviour: the shared helper picks the labelled java_http port
    # over java_https, so secstore still prefers HTTP over HTTPS.
    import os as _os
    import sys as _sys
    _sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), "..",
                                       "modules", "exploitation"))
    _sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), "..",
                                       "modules", "core"))
    from sapmap_models import SAPNode, InstanceInfo
    import sapmap_exploit as X
    n = SAPNode(sid="J", ip="10.0.0.1")
    # Both labels present on the same instance — java_http must win.
    n.instances = [InstanceInfo(instance_nr="00", ip="10.0.0.1",
                                 ports={50000: "java_http",
                                        50001: "java_https"})]
    host, port, https = X._find_java_http_endpoint(n)
    assert (port, https) == (50000, False), (
        f"_find_java_http_endpoint must pick java_http over java_https "
        f"— HTTP is simpler and avoids the Connection-reset trap on "
        f"the TLS port.  Got (port={port!r}, https={https!r}).")


def test_secstore_jsp_url_uses_dynamic_scheme():
    """The jsp_url f-string must inject the scheme variable, not
    hardcode http://."""
    src = _runner_src()
    # Find the line that assigns jsp_url.
    m = re.search(r"jsp_url\s*=\s*\(?\s*f?\"[^\"]+\"",
                  src)
    assert m, "jsp_url assignment not found"
    # Plus any continuation
    line_block = src[m.start():m.start() + 200]
    assert "{jsp_scheme}" in line_block or '{"http" if' in line_block, (
        f"jsp_url must use a dynamic scheme variable, not hardcoded "
        f"http:// — found: {line_block[:120]!r}")
