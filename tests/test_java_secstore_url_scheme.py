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
    HTTP-to-HTTPS-port connection-reset trap."""
    src = _runner_src()
    m = re.search(r"def extract_java_secstore.*?Pick delivery path",
                  src, re.DOTALL)
    assert m, "port resolution block not found"
    body = m.group(0)
    # java_http must be searched BEFORE java_https in the fallback.
    idx_http = body.find('"java_http"')
    idx_https = body.find('"java_https"')
    assert idx_http > 0, "java_http preference not found"
    assert idx_https > 0, "java_https fallback not found"
    assert idx_http < idx_https, (
        "java_http (HTTP) must be preferred over java_https (HTTPS) "
        "in the port fallback chain — HTTP is simpler and avoids the "
        "Connection-reset trap on the TLS port")


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
