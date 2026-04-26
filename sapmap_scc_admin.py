#!/usr/bin/env python3
"""
SAPMAP — SAP Cloud Connector authenticated REST helpers.

Implements the Week-2 capabilities of the SCC plan §F:

    * login(host, user, pwd, port=8443) → SCCAdminSession or None
    * pull_versions(session)            → version + build (REST is JSON when authed)
    * pull_subaccounts(session)         → list of subaccount UUIDs / regions
    * pull_mappings(session, sub_uuid)  → list of SCCMapping dicts
    * logout(session)

Authentication
--------------
Cloud Connector >= 2.x uses a Tomcat form-auth flow:

    1. GET any protected URL (e.g. /api/login) — sets a JSESSIONID cookie
       and serves the login HTML page.
    2. POST /j_security_check with j_username / j_password — Tomcat sets
       the authenticated marker on the existing JSESSIONID and 302s back
       to the original protected URL.  Failure re-renders the login form
       with HTTP 200 and no Location header.

Once authenticated, JSON responses come back from /api/* paths.  Some
versions add a CSRF token requirement on writes; this module is read-
only so we don't currently fetch one (we *do* surface the X-CSRF-Token
response header in the session for future write-path code).

This module is read-only: GETs only, no payloads beyond the single
``j_security_check`` POST.  Calling ``probe_default_creds()`` performs at
most one POST per (host, user, password) tuple.  Default-credential
probing is opt-in at the call site — the GUI gates it behind a toolbar
checkbox.
"""
from __future__ import annotations

import json
import logging
import re
import ssl
import urllib.parse
from dataclasses import dataclass, field
from http import cookiejar
from typing import Optional
from urllib import request as _urlreq, error as _urlerr

logger = logging.getLogger(__name__)

# Conservative defaults documented by SAP and used in setup wizards.  The
# 2.15+ installer forces a password change on first launch, so default
# creds being live in the wild is rare — but worth probing once to know.
DEFAULT_CREDENTIALS = (
    ("Administrator", "manage"),
)


@dataclass
class SCCAdminSession:
    host: str
    port: int = 8443
    base_url: str = ""
    cookie_jar: object = None       # http.cookiejar.CookieJar
    opener: object = None           # urllib.request.OpenerDirector
    csrf_token: str = ""
    user: str = ""
    authenticated: bool = False
    version: str = ""
    build: str = ""
    raw_versions: dict = field(default_factory=dict)


class _NoRedirect(_urlreq.HTTPRedirectHandler):
    """Tomcat 302s the j_security_check response back to the originally
    requested URL.  We need to inspect that 302 ourselves, not follow it.
    """
    def http_error_302(self, req, fp, code, msg, headers):
        return fp
    http_error_301 = http_error_303 = http_error_307 = http_error_302


def _build_session(host: str, port: int) -> SCCAdminSession:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    cj = cookiejar.CookieJar()
    op = _urlreq.build_opener(
        _urlreq.HTTPSHandler(context=ctx),
        _urlreq.HTTPCookieProcessor(cj),
        _NoRedirect(),
    )
    return SCCAdminSession(
        host=host, port=port,
        base_url=f"https://{host}:{port}",
        cookie_jar=cj, opener=op,
    )


def _request(sess: SCCAdminSession, path: str, method: str = "GET",
             data: Optional[bytes] = None, headers: Optional[dict] = None,
             timeout: float = 8.0):
    hdrs = {
        "User-Agent": "SAPMAP-SCC-Admin/1.0",
        "Accept": "application/json, text/plain, */*",
    }
    if headers:
        hdrs.update(headers)
    req = _urlreq.Request(sess.base_url + path, data=data, method=method, headers=hdrs)
    try:
        return sess.opener.open(req, timeout=timeout)
    except _urlerr.HTTPError as e:
        return e


def login(host: str, user: str, password: str,
          port: int = 8443, timeout: float = 8.0) -> Optional[SCCAdminSession]:
    """Form-auth against /j_security_check.  Returns an authenticated
    SCCAdminSession on success, ``None`` on credential rejection or
    transport failure.
    """
    sess = _build_session(host, port)
    sess.user = user

    # Seed JSESSIONID
    r = _request(sess, "/api/login", timeout=timeout)
    status = getattr(r, "status", 0) or getattr(r, "code", 0)
    if status not in (200, 302):
        logger.debug("SCC login seed failed for %s:%d status=%s", host, port, status)
        return None
    try:
        r.read(2048)
    except Exception:
        pass

    # POST credentials
    body = urllib.parse.urlencode({
        "j_username": user, "j_password": password,
    }).encode("utf-8")
    r = _request(sess, "/j_security_check", method="POST", data=body, headers={
        "Content-Type": "application/x-www-form-urlencoded",
    }, timeout=timeout)
    status = getattr(r, "status", 0) or getattr(r, "code", 0)
    location = ""
    try:
        location = r.headers.get("Location", "") or ""
    except Exception:
        pass
    csrf = ""
    try:
        csrf = r.headers.get("X-CSRF-Token", "") or ""
    except Exception:
        pass
    try:
        r.read(2048)
    except Exception:
        pass

    # Tomcat success → 302 with Location to /api/login (or original URL).
    # Tomcat failure → 200 with the login HTML re-served, no Location.
    if status in (301, 302, 303, 307, 308) and location:
        # Verify by fetching a known authenticated endpoint.
        v = _get_versions_raw(sess, timeout=timeout)
        if v is not None:
            sess.authenticated = True
            sess.csrf_token = csrf
            sess.raw_versions = v
            sess.version = v.get("connector") or v.get("version") or ""
            sess.build = v.get("build") or v.get("revision") or ""
            return sess
    return None


def _get_versions_raw(sess: SCCAdminSession, timeout: float = 8.0) -> Optional[dict]:
    """Fetch /api/monitoring/versions.  Returns a parsed dict if the
    response is JSON (i.e. we are authenticated), ``None`` otherwise.
    Some SCC builds gate this endpoint behind auth; an HTML body means
    "redirected back to login".
    """
    r = _request(sess, "/api/monitoring/versions", timeout=timeout)
    status = getattr(r, "status", 0) or getattr(r, "code", 0)
    ct = ""
    try:
        ct = (r.headers.get("Content-Type", "") or "").lower()
    except Exception:
        pass
    if status != 200 or "json" not in ct:
        return None
    try:
        body = r.read(64 * 1024)
        return json.loads(body.decode("utf-8", "replace"))
    except Exception as e:
        logger.debug("versions parse failed: %s", e)
        return None


def pull_versions(sess: SCCAdminSession, timeout: float = 8.0) -> dict:
    if not sess.authenticated:
        return {}
    return _get_versions_raw(sess, timeout=timeout) or {}


def pull_subaccounts(sess: SCCAdminSession, timeout: float = 8.0) -> list:
    """Return [{subaccount, region, locationID, displayName, ...}, ...].

    Endpoint shape varies between SCC versions; we try the modern path
    first, fall back to the legacy one.
    """
    if not sess.authenticated:
        return []
    for path in ("/api/configuration/subaccounts",
                 "/api/configuration/connections"):
        r = _request(sess, path, timeout=timeout)
        status = getattr(r, "status", 0) or getattr(r, "code", 0)
        ct = ""
        try:
            ct = (r.headers.get("Content-Type", "") or "").lower()
        except Exception:
            pass
        if status != 200 or "json" not in ct:
            continue
        try:
            data = json.loads(r.read(512 * 1024).decode("utf-8", "replace"))
        except Exception:
            continue
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for k in ("subaccounts", "items", "data"):
                if isinstance(data.get(k), list):
                    return data[k]
    return []


def pull_mappings(sess: SCCAdminSession, subaccount_uuid: str,
                  timeout: float = 8.0) -> list:
    """Return the cloud-to-on-premise mapping table for one subaccount.

    Each entry is shaped to match SCCMapping.from_dict() so the caller can
    persist directly.  Unknown fields in the raw payload are dropped.
    """
    if not sess.authenticated or not subaccount_uuid:
        return []
    quoted = urllib.parse.quote(subaccount_uuid, safe="")
    paths = (
        f"/api/configuration/subaccounts/{quoted}/cloudToOnPremise",
        f"/api/configuration/subaccounts/{quoted}/systemMappings",
    )
    raw = []
    for path in paths:
        r = _request(sess, path, timeout=timeout)
        status = getattr(r, "status", 0) or getattr(r, "code", 0)
        ct = ""
        try:
            ct = (r.headers.get("Content-Type", "") or "").lower()
        except Exception:
            pass
        if status == 200 and "json" in ct:
            try:
                data = json.loads(r.read(1024 * 1024).decode("utf-8", "replace"))
                if isinstance(data, list):
                    raw = data
                    break
                if isinstance(data, dict):
                    for k in ("systemMappings", "mappings", "items"):
                        if isinstance(data.get(k), list):
                            raw = data[k]
                            break
                    if raw:
                        break
            except Exception:
                continue
    out = []
    for m in raw:
        if not isinstance(m, dict):
            continue
        out.append({
            "virtual_host": m.get("virtualHost") or m.get("virtualUrl") or "",
            "virtual_port": int(m.get("virtualPort") or 0),
            "internal_host": m.get("internalHost") or m.get("localHost") or "",
            "internal_port": int(m.get("internalPort") or m.get("localPort") or 0),
            "protocol": m.get("protocol") or m.get("type") or "",
            "path_allowlist": m.get("resources") or m.get("pathAllowlist") or [],
            "path_wildcards": bool(m.get("pathWildcards", False)),
            "backend_type": m.get("backendType") or "",
            "principal_propagation": bool(m.get("authenticationMode") == "X509_GENERAL"
                                          or m.get("principalPropagation", False)),
        })
    return out


def logout(sess: SCCAdminSession, timeout: float = 4.0) -> bool:
    if not sess or not sess.authenticated:
        return True
    try:
        _request(sess, "/api/logout", method="POST", timeout=timeout)
    except Exception:
        pass
    sess.authenticated = False
    return True


def probe_default_creds(host: str, port: int = 8443, timeout: float = 6.0,
                        creds: Optional[list] = None
                        ) -> tuple[bool, Optional[SCCAdminSession], list]:
    """Walk DEFAULT_CREDENTIALS (or a caller-supplied list) and return
    ``(any_live, session_or_None, attempts)`` where attempts is a list of
    {"user": str, "live": bool} so the caller can emit per-attempt
    findings.  At most one POST per credential pair.
    """
    attempts = []
    for user, pwd in (creds or DEFAULT_CREDENTIALS):
        sess = login(host, user, pwd, port=port, timeout=timeout)
        live = bool(sess and sess.authenticated)
        attempts.append({"user": user, "live": live})
        if live:
            return True, sess, attempts
    return False, None, attempts
