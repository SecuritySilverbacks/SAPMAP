#!/usr/bin/env python3
"""
SAPMAP — SAP Cloud Connector (SCC) read-only fingerprint module.

Implements probes 1–6 of the detection ladder in
docs/research/08_cloud_connector_implementation_plan.md §A:

    1. TCP connect 8443/tcp                — already done by fast_scan_host
    2. TLS ClientHello + capture cert      — pull cert subject, ALPN
    3. HTTP GET /                          — 302 redirect to /scc/ui + Server header
    4. GET /scc/ui                         — title + Set-Cookie + JS-bundle filename
    5. Favicon hash (sha256 + mmh3)        — favicon.ico → version bucket
    6. Static asset enumeration            — refines minor version

No authentication, no exploit attempts.  Single function `scc_fingerprint(host,
port=8443, timeout=5.0)` returns an SCCFingerprint dict that the scanner
promotes into an SCCNode.
"""
from __future__ import annotations

import hashlib
import logging
import re
import socket
import ssl
from typing import Optional
from urllib import request as _urlreq, error as _urlerr

logger = logging.getLogger(__name__)


# Magic numbers in HTML/HTTP that strongly imply SCC.  Order matters: the
# cheapest, most-specific markers come first so callers can short-circuit.
_HTML_MARKERS = (
    "<title>Cloud Connector</title>",
    "<title>SAP Cloud Connector",
    "/scc/ui/resources/",
    "scc-ui",
)

_BUNDLE_RE = re.compile(
    r"""(?:src|href)\s*=\s*["']/scc/ui/resources/[^"']*?(?:bundle|main)[^"']*?\.([0-9a-f]{6,32})\.(?:js|css)""",
    re.IGNORECASE,
)
_VERSION_TAG_RE = re.compile(
    r"""(?:Version|VERSION|version)["'\s:>=-]+["']?(\d+\.\d+(?:\.\d+)?)""",
)


def _build_unverified_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except (NotImplementedError, AttributeError):
        pass
    return ctx


def _tls_fingerprint(host: str, port: int, timeout: float) -> dict:
    """Probe 2 — capture TLS handshake details + server certificate subject."""
    out = {"reachable": False, "alpn": "", "cipher": "", "tls_version": "",
           "cert_subject": "", "cert_issuer": "", "cert_san": []}
    ctx = _build_unverified_ctx()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                out["reachable"] = True
                out["tls_version"] = ssock.version() or ""
                cipher = ssock.cipher()
                if cipher:
                    out["cipher"] = cipher[0]
                try:
                    out["alpn"] = ssock.selected_alpn_protocol() or ""
                except Exception:
                    pass
                cert = ssock.getpeercert(binary_form=False) or {}
                if cert:
                    out["cert_subject"] = "/".join(
                        f"{k}={v}" for tup in cert.get("subject", ())
                        for k, v in tup
                    )
                    out["cert_issuer"] = "/".join(
                        f"{k}={v}" for tup in cert.get("issuer", ())
                        for k, v in tup
                    )
                    san = cert.get("subjectAltName", ())
                    out["cert_san"] = [v for _, v in san]
    except (socket.timeout, ConnectionRefusedError, ssl.SSLError, OSError) as e:
        logger.debug("SCC TLS probe failed for %s:%d (%s)", host, port, e)
    return out


def _http_get(host: str, port: int, path: str, timeout: float) -> tuple[int, dict, bytes]:
    """Issue a single HTTPS GET, accepting any TLS cert.  Returns (status, headers, body)."""
    ctx = _build_unverified_ctx()
    url = f"https://{host}:{port}{path}"
    try:
        req = _urlreq.Request(url, headers={
            "User-Agent": "SAPMAP-SCC-Fingerprint/1.0",
            "Accept": "*/*",
        })
        with _urlreq.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(64 * 1024)
            return resp.status, dict(resp.headers), body
    except _urlerr.HTTPError as e:
        body = b""
        try:
            body = e.read(64 * 1024)
        except Exception:
            pass
        return e.code, dict(getattr(e, "headers", {}) or {}), body
    except (_urlerr.URLError, socket.timeout, ConnectionResetError, OSError) as e:
        logger.debug("SCC HTTP probe failed for %s:%d%s (%s)", host, port, path, e)
        return 0, {}, b""


def _favicon_hashes(host: str, port: int, timeout: float) -> tuple[str, int]:
    """Probe 5 — fetch favicon and return (sha256_hex, mmh3_int).

    mmh3 is reported as a 32-bit *signed* integer (0 if mmh3 is unavailable),
    matching the Shodan favicon-hash convention used by other tools.
    """
    status, _, body = _http_get(host, port, "/scc/ui/resources/images/favicon.ico", timeout)
    if status != 200 or not body:
        return "", 0
    sha = hashlib.sha256(body).hexdigest()
    mmh = 0
    try:
        import mmh3  # type: ignore
        import base64 as _b64
        b64 = _b64.encodebytes(body)
        mmh = mmh3.hash(b64)
    except Exception:
        pass
    return sha, mmh


def scc_fingerprint(host: str, port: int = 8443, timeout: float = 5.0) -> Optional[dict]:
    """Run probes 2–6.  Probe 1 (TCP open) is the caller's responsibility
    (fast_scan_host already established the port is open).

    Returns ``None`` when the response definitively isn't SCC.  Returns a
    dict with the captured fingerprint otherwise:

        {
          "host": str, "port": int, "is_scc": bool,
          "tls": {...}, "server_header": str,
          "redirect_to_scc_ui": bool,
          "title_present": bool, "html_marker": str,
          "bundle_hash": str, "version": str, "version_source": str,
          "favicon_sha256": str, "favicon_mmh3": int,
          "set_cookie": str,
        }
    """
    out = {
        "host": host, "port": port, "is_scc": False,
        "tls": {}, "server_header": "",
        "redirect_to_scc_ui": False,
        "title_present": False, "html_marker": "",
        "bundle_hash": "", "version": "", "version_source": "",
        "favicon_sha256": "", "favicon_mmh3": 0,
        "set_cookie": "",
    }

    # Probe 2 — TLS handshake
    out["tls"] = _tls_fingerprint(host, port, timeout)
    if not out["tls"].get("reachable"):
        return None

    # Probe 3 — root probe: 302 redirect to /scc/ui is the canonical SCC behaviour
    status, headers, body = _http_get(host, port, "/", timeout)
    out["server_header"] = (headers.get("Server") or headers.get("server") or "")
    location = (headers.get("Location") or headers.get("location") or "")
    if status in (301, 302, 303, 307, 308) and "/scc/ui" in location:
        out["redirect_to_scc_ui"] = True

    # Probe 4 — fetch the SCC SPA shell
    status, headers, body = _http_get(host, port, "/scc/ui", timeout)
    if not out["server_header"]:
        out["server_header"] = (headers.get("Server") or headers.get("server") or "")
    sc = (headers.get("Set-Cookie") or headers.get("set-cookie") or "")
    out["set_cookie"] = sc[:200]
    text = body.decode("utf-8", errors="replace") if body else ""
    for m in _HTML_MARKERS:
        if m in text:
            out["html_marker"] = m
            out["title_present"] = True
            break
    bm = _BUNDLE_RE.search(text or "")
    if bm:
        out["bundle_hash"] = bm.group(1)
        out["version_source"] = "bundle"
    vm = _VERSION_TAG_RE.search(text or "")
    if vm and not out["version"]:
        out["version"] = vm.group(1)
        out["version_source"] = out["version_source"] or "html"

    # Heuristic: SCC if (a) HTML shows a title marker, OR (b) Server header
    # contains "Cloud Connector" / "SAP", OR (c) /scc/ui returned a Tomcat
    # JSESSIONID cookie alongside a 200/302 status with a JS bundle hash.
    server_l = out["server_header"].lower()
    is_scc = (
        out["title_present"]
        or "cloud connector" in server_l
        or out["redirect_to_scc_ui"]
        or (out["bundle_hash"] and "JSESSIONID" in sc)
    )
    if not is_scc:
        return None
    out["is_scc"] = True

    # Probe 5 — favicon
    sha, mmh = _favicon_hashes(host, port, timeout)
    out["favicon_sha256"] = sha
    out["favicon_mmh3"] = mmh

    # Probe 6 (light) — try /api/monitoring/versions; an unauthenticated
    # 401 is *good* (means SCC ≥ 2.13 with auth on); a 200 with JSON body is
    # the rare auth-disabled / bug case and lets us read the build directly.
    status, _, body = _http_get(host, port, "/api/monitoring/versions", timeout)
    if status == 200 and body:
        text = body.decode("utf-8", errors="replace")
        # Look for "connector":"<ver>" or "version":"<ver>" in JSON.
        m = re.search(r'"(?:connector|version)"\s*:\s*"([0-9.]+)"', text)
        if m:
            out["version"] = m.group(1)
            out["version_source"] = "api"

    return out
