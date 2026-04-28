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

import base64
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
    basic_auth: str = ""            # "Basic <b64(user:pwd)>" for /api/v1 calls
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
    sess.basic_auth = "Basic " + base64.b64encode(
        f"{user}:{password}".encode("utf-8")).decode("ascii")

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

    # Tomcat success → 302/303 with Location to /api/login (or original URL).
    # Tomcat failure → 200 with the login HTML re-served, no Location.
    form_ok = status in (301, 302, 303, 307, 308) and bool(location)

    # Independently verify by fetching /api/v1/configuration/subaccounts
    # with HTTP Basic — that endpoint is the authoritative configuration
    # source on 2.16+ builds and only honours Basic auth, so it's the
    # most reliable cred-validity check we have.
    cfg = _get_v1_subaccounts_raw(sess, timeout=timeout)
    if cfg is not None:
        sess.authenticated = True
        sess.csrf_token = csrf
        sess.raw_versions = {"subaccounts": cfg}
        v = _get_versions_raw(sess, timeout=timeout) or {}
        sess.version = v.get("connector") or v.get("version") or ""
        sess.build = v.get("build") or v.get("revision") or ""
        return sess
    if form_ok:
        # Fall back to monitoring/connections/backends for older builds
        # without the v1 config API.
        b = _get_backends_raw(sess, timeout=timeout)
        if b is not None:
            sess.authenticated = True
            sess.csrf_token = csrf
            sess.raw_versions = b
            v = _get_versions_raw(sess, timeout=timeout) or {}
            sess.version = v.get("connector") or v.get("version") or ""
            sess.build = v.get("build") or v.get("revision") or ""
            return sess
    return None


def _basic_headers(sess: SCCAdminSession) -> dict:
    return {"Authorization": sess.basic_auth} if sess.basic_auth else {}


def _get_v1_subaccounts_raw(sess: SCCAdminSession, timeout: float = 8.0) -> Optional[list]:
    """GET /api/v1/configuration/subaccounts with HTTP Basic.

    Returns the parsed JSON list (each entry has _links.systemMappings
    among others) when authenticated and the v1 configuration API is
    present; ``None`` otherwise (404 on older builds, 401 on bad creds,
    SAPUI5 HTML when filter rules block the request entirely).
    """
    r = _request(sess, "/api/v1/configuration/subaccounts",
                 headers=_basic_headers(sess), timeout=timeout)
    status = getattr(r, "status", 0) or getattr(r, "code", 0)
    ct = ""
    try:
        ct = (r.headers.get("Content-Type", "") or "").lower()
    except Exception:
        pass
    if status != 200 or "json" not in ct:
        return None
    try:
        body = r.read(2 * 1024 * 1024)
        data = json.loads(body.decode("utf-8", "replace"))
    except Exception as e:
        logger.debug("v1 subaccounts parse failed: %s", e)
        return None
    return data if isinstance(data, list) else None


def _get_backends_raw(sess: SCCAdminSession, timeout: float = 8.0) -> Optional[dict]:
    """Fetch /api/monitoring/connections/backends.  This endpoint is the
    authoritative post-auth probe on modern (2.16+) SCC builds: it
    returns JSON when authed and the SAPUI5 login HTML otherwise.  The
    payload contains the subaccount list inline along with their
    backendConnections (mappings), so a single GET covers verification,
    subaccount enumeration and mapping enumeration.
    """
    r = _request(sess, "/api/monitoring/connections/backends", timeout=timeout)
    status = getattr(r, "status", 0) or getattr(r, "code", 0)
    ct = ""
    try:
        ct = (r.headers.get("Content-Type", "") or "").lower()
    except Exception:
        pass
    if status != 200 or "json" not in ct:
        return None
    try:
        body = r.read(2 * 1024 * 1024)
        return json.loads(body.decode("utf-8", "replace"))
    except Exception as e:
        logger.debug("backends parse failed: %s", e)
        return None


def _get_versions_raw(sess: SCCAdminSession, timeout: float = 8.0) -> Optional[dict]:
    """Best-effort version fetch.  /api/monitoring/versions exists on
    some SCC builds but 404s on others; treat absence as "no version
    info" rather than auth failure.
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
    except Exception:
        return None


def pull_versions(sess: SCCAdminSession, timeout: float = 8.0) -> dict:
    if not sess.authenticated:
        return {}
    return _get_versions_raw(sess, timeout=timeout) or {}


def pull_subaccounts(sess: SCCAdminSession, timeout: float = 8.0) -> list:
    """Return [{subaccount, regionHost, locationID, _links?, ...}, ...].

    Prefers the v1 configuration API (Basic auth) since that endpoint is
    the authoritative source for subaccounts *and* their mapping links;
    falls back to the form-auth /api/monitoring/connections/backends
    payload (cached on the session at login time) for older builds.
    """
    if not sess.authenticated:
        return []
    cached = sess.raw_versions if isinstance(sess.raw_versions, dict) else None
    if cached and isinstance(cached.get("subaccounts"), list):
        # raw_versions["subaccounts"] is the v1 list (preferred) or the
        # monitoring backends list (fallback) depending on what login()
        # cached.  Both expose .subaccount + .regionHost on each entry.
        return cached["subaccounts"]
    fresh = _get_v1_subaccounts_raw(sess, timeout=timeout)
    if isinstance(fresh, list):
        sess.raw_versions = {"subaccounts": fresh}
        return fresh
    legacy = _get_backends_raw(sess, timeout=timeout)
    if isinstance(legacy, dict) and isinstance(legacy.get("subaccounts"), list):
        return legacy["subaccounts"]
    return []


def _safe_int(v, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _normalize_mapping(m: dict) -> dict:
    """Shape one raw systemMapping entry to match SCCMapping.from_dict().

    Field-name drift between SCC builds:
      v1 config API   : virtualHost, virtualPort (str), localHost, localPort
                        (str), protocol, backendType, authenticationMode,
                        sid, hostInHeader, totalResourcesCount,
                        enabledResourcesCount, allowedClients, blacklistedUsers
      legacy monitor  : virtualUrl, internalHost, internalPort, type
    """
    auth_mode = m.get("authenticationMode") or ""
    return {
        "virtual_host": m.get("virtualHost") or m.get("virtualUrl") or "",
        "virtual_port": _safe_int(m.get("virtualPort")),
        "internal_host": m.get("localHost") or m.get("internalHost") or "",
        "internal_port": _safe_int(m.get("localPort") or m.get("internalPort")),
        "protocol": m.get("protocol") or m.get("type") or "",
        "path_allowlist": m.get("resources") or m.get("pathAllowlist") or [],
        "path_wildcards": bool(m.get("pathWildcards", False)),
        "backend_type": m.get("backendType") or "",
        "principal_propagation": (auth_mode in ("X509_GENERAL", "KERBEROS")
                                  or bool(m.get("principalPropagation", False))),
        "authentication_mode": auth_mode,
        "sid": m.get("sid") or "",
        "host_in_header": m.get("hostInHeader") or "",
        "description": m.get("description") or "",
        "total_resources": _safe_int(m.get("totalResourcesCount")),
        "enabled_resources": _safe_int(m.get("enabledResourcesCount")),
    }


def _path_for_link(href: str, base_url: str) -> str:
    """Strip scheme://host:port from a HATEOAS href, return the path."""
    if not href:
        return ""
    if href.startswith(base_url):
        return href[len(base_url):] or "/"
    if href.startswith("http://") or href.startswith("https://"):
        return "/" + href.split("/", 3)[3] if "/" in href[8:] else ""
    return href if href.startswith("/") else "/" + href


def _fetch_resources(sess: SCCAdminSession, href: str, timeout: float) -> list:
    """GET a systemMappings/<vhost:vport>/resources link → list[str]."""
    path = _path_for_link(href, sess.base_url)
    if not path:
        return []
    r = _request(sess, path, headers=_basic_headers(sess), timeout=timeout)
    status = getattr(r, "status", 0) or getattr(r, "code", 0)
    ct = ""
    try:
        ct = (r.headers.get("Content-Type", "") or "").lower()
    except Exception:
        pass
    if status != 200 or "json" not in ct:
        return []
    try:
        data = json.loads(r.read(256 * 1024).decode("utf-8", "replace"))
    except Exception:
        return []
    out = []
    for entry in (data if isinstance(data, list) else []):
        if isinstance(entry, dict):
            exact = bool(entry.get("exactMatchOnly", False))
            policy_raw = entry.get("accessPolicy") or entry.get("policy") or ""
            # SCC v1 uses exactMatchOnly bool; older builds use accessPolicy str.
            policy = policy_raw or ("PATH" if exact else "PATH_AND_ALL_SUB_PATHS")
            out.append({
                "path": entry.get("id") or entry.get("path") or "",
                "policy": policy,
                "exact_match_only": exact,
                "enabled": bool(entry.get("enabled", True)),
                "description": entry.get("description") or "",
                "websocket_upgrade_allowed": bool(entry.get("websocketUpgradeAllowed", False)),
            })
        elif isinstance(entry, str):
            out.append({"path": entry, "policy": "PATH_AND_ALL_SUB_PATHS",
                        "exact_match_only": False, "enabled": True,
                        "description": "", "websocket_upgrade_allowed": False})
    return out


def pull_mappings(sess: SCCAdminSession, subaccount_uuid: str,
                  timeout: float = 8.0) -> list:
    """Return the cloud-to-on-premise mapping table for one subaccount.

    Strategy:
      1. /api/v1/configuration/subaccounts (Basic auth) → find the matching
         subaccount entry, follow its `_links.systemMappings.href`.
      2. For each mapping, follow `_links.resources.href` (if present and
         totalResourcesCount > 0) to expand the path allowlist.
      3. Fallback to /api/monitoring/connections/backends (form-auth) for
         older SCC builds that don't expose the v1 config API.
    """
    if not sess.authenticated or not subaccount_uuid:
        return []
    out: list = []

    subs = pull_subaccounts(sess, timeout=timeout)
    target = None
    for s in subs:
        if isinstance(s, dict) and s.get("subaccount") == subaccount_uuid:
            target = s
            break
    if target is None:
        return []

    links = target.get("_links") or {}
    sm_href = ""
    if isinstance(links.get("systemMappings"), dict):
        sm_href = links["systemMappings"].get("href") or ""

    if sm_href:
        path = _path_for_link(sm_href, sess.base_url)
        r = _request(sess, path, headers=_basic_headers(sess), timeout=timeout)
        status = getattr(r, "status", 0) or getattr(r, "code", 0)
        ct = ""
        try:
            ct = (r.headers.get("Content-Type", "") or "").lower()
        except Exception:
            pass
        if status == 200 and "json" in ct:
            try:
                raw = json.loads(r.read(2 * 1024 * 1024).decode("utf-8", "replace"))
            except Exception:
                raw = []
            entries = raw if isinstance(raw, list) else (
                raw.get("systemMappings") if isinstance(raw, dict) else None) or []
            for m in entries:
                if not isinstance(m, dict):
                    continue
                norm = _normalize_mapping(m)
                # Expand resources via the per-mapping link if present.
                m_links = m.get("_links") or {}
                res_href = ""
                if isinstance(m_links.get("resources"), dict):
                    res_href = m_links["resources"].get("href") or ""
                if res_href and norm.get("total_resources", 0) > 0:
                    norm["path_allowlist"] = _fetch_resources(sess, res_href, timeout)
                out.append(norm)
            if out:
                return out

    # Fallback: monitoring backends payload (older SCC builds).
    legacy = _get_backends_raw(sess, timeout=timeout)
    if isinstance(legacy, dict):
        for s in (legacy.get("subaccounts") or []):
            if isinstance(s, dict) and s.get("subaccount") == subaccount_uuid:
                for m in (s.get("backendConnections") or []):
                    if isinstance(m, dict):
                        out.append(_normalize_mapping(m))
                break
    return out


def pull_ha_state(sess: SCCAdminSession, timeout: float = 8.0) -> dict:
    """Return ``{role, peer_host, peer_role, raw}`` for the SCC's HA pair.

    Tries multiple endpoints because SCC builds disagree on where HA
    lives.  Known shapes (any one of these is a hit):
      * ``GET /api/v1/configuration/connector`` → ``{ha:{role,peer:{host,role}}}``
      * same endpoint → top-level ``{haRole, shadowHost, masterHost}``
      * ``GET /api/v1/configuration/connector/highAvailability`` → dedicated
        HA config with ``role``/``shadowHost``/``masterHost``/``masters``/``shadows``
      * ``GET /api/monitoring/connector/state`` (newer builds) → state with
        ``haRole`` + peer info

    Returns an empty dict on hard failure so callers can short-circuit.
    On success always returns ``raw`` containing the parsed payload that
    matched, so the caller can log it when no peer was found.
    """
    if not sess or not sess.authenticated:
        return {}

    def _get_json(path):
        try:
            url = f"{sess.base_url}{path}"
            req = _urlreq.Request(url, headers=_basic_headers(sess))
            with sess.opener.open(req, timeout=timeout) as r:
                body = r.read().decode("utf-8", errors="replace")
            return json.loads(body)
        except Exception:
            return None

    def _extract(data):
        """Pull (role, peer_host, peer_role) out of a heterogeneous payload."""
        if not isinstance(data, dict):
            return "", "", ""
        # Shape 1: nested ha.{role, peer.{host,role}, shadowHost, masterHost}
        ha = data.get("ha")
        candidates = []
        if isinstance(ha, dict):
            candidates.append(ha)
        # Shape 2: top-level (haRole/shadowHost/masterHost or role/peer)
        candidates.append(data)
        # Shape 3: highAvailability sub-object
        hav = data.get("highAvailability")
        if isinstance(hav, dict):
            candidates.append(hav)
        for c in candidates:
            role = (c.get("role") or c.get("haRole") or "").strip().lower()
            peer_host = ""
            peer_role = ""
            peer = c.get("peer")
            if isinstance(peer, dict):
                peer_host = (peer.get("host") or peer.get("hostname")
                             or peer.get("hostName") or "").strip()
                peer_role = (peer.get("role") or "").strip().lower()
            if not peer_host:
                # SCC sometimes lists shadows / masters as arrays
                shadows = c.get("shadows") or c.get("shadowHosts")
                masters = c.get("masters") or c.get("masterHosts")
                if isinstance(shadows, list) and shadows:
                    first = shadows[0]
                    peer_host = (first.get("host") if isinstance(first, dict)
                                 else str(first or "")).strip()
                    peer_role = peer_role or "shadow"
                elif isinstance(masters, list) and masters:
                    first = masters[0]
                    peer_host = (first.get("host") if isinstance(first, dict)
                                 else str(first or "")).strip()
                    peer_role = peer_role or "master"
            if not peer_host:
                peer_host = (c.get("shadowHost") or c.get("masterHost")
                             or c.get("shadowHostName")
                             or c.get("masterHostName") or "").strip()
                if peer_host and not peer_role:
                    peer_role = "shadow" if role == "master" else "master"
            if role or peer_host:
                return role, peer_host, peer_role
        return "", "", ""

    paths = [
        "/api/v1/configuration/connector",
        "/api/v1/configuration/connector/highAvailability",
        "/api/v1/configuration/highAvailability",
        "/api/monitoring/connector/state",
        "/api/v1/system/state",
    ]
    raw_collected = {}
    for p in paths:
        data = _get_json(p)
        if data is None:
            continue
        raw_collected[p] = data if not isinstance(data, dict) else (
            data.get("ha") or data.get("highAvailability") or
            {k: v for k, v in data.items()
             if "ha" in k.lower() or "shadow" in k.lower()
             or "master" in k.lower() or "role" in k.lower()
             or "peer" in k.lower()}
        )
        role, peer_host, peer_role = _extract(data)
        if peer_host:
            return {"role": role, "peer_host": peer_host,
                    "peer_role": peer_role, "raw": raw_collected}
    # No peer found anywhere — return the raw blobs we collected so the
    # caller can log them and we can debug what shape this build uses.
    return {"role": "", "peer_host": "", "peer_role": "",
            "raw": raw_collected}


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
