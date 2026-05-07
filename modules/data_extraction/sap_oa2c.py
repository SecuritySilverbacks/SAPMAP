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

Column names within these tables drift across kernel patches —
TOKEN_ENDPOINT vs TOKEN_URL vs OAUTH2_TOKEN_URL is one example.
Pre-listing fields trips ``RFC_READ_TABLE`` message AD718 the moment
ANY requested field doesn't exist on the target kernel; instead we
ask the kernel for ALL columns and use case-insensitive substring
matching to pick out what we need.

No live SAP traffic in this module's import path; the actual RFC
calls only fire when ``read_oa2c_profiles`` is invoked from the
endpoint with credentials.
"""
from __future__ import annotations

from typing import Optional

from sapmap_models import SAPNode, Credentials


# Heuristic column-name hints.  Order matters: more-specific patterns
# first so e.g. CLIENT_UUID wins over a row that also contains a
# bare CLIENT column.
_FIELD_HINTS = {
    "client_uuid":     ("CLIENT_UUID", "CONFIG_ID", "CONFIG_UUID"),
    "client_id":       ("CLIENT_ID",),
    "token_endpoint":  ("TOKEN_ENDPOINT", "TOKEN_URL",
                         "TOKEN_SERVICE_URL", "OAUTH2_TOKEN"),
    "auth_endpoint":   ("AUTHORIZATION_ENDPOINT", "AUTH_URL",
                         "AUTH_ENDPOINT"),
    "issuer":          ("ISSUER",),
    "auth_method":     ("CLIENT_AUTHENTICATION", "AUTH_METHOD",
                         "CLIENT_SECRET_METHOD"),
    "description":     ("DESCRIPTION", "PROF_NAME"),
    "profile":         ("PROFILE_UUID", "PROFILE", "PROF_ID"),
}

_GRANT_HINTS = ("GRANTTYPE", "GRANT_TYPE", "GRANT")

# Tables that have held OAuth 2.0 Client config across kernel/release
# lines.  Tried in order; the first one that returns rows wins.  When
# all of them are empty the operator at least sees a clear log of
# what was probed.
_CLIENT_TABLE_VARIANTS = (
    "OA2C_CLIENT",
    "OA2C_CONFIG",
    "OAUTH2_CLIENT_CONFIG",
)
_CLIENT_EXT_TABLE_VARIANTS = (
    "OA2C_CLIENT_EXT",
    "OA2C_CONFIG_EXT",
)


def _normalise_uuid(raw: str) -> str:
    """Lower-case, hyphen-free, hex-only — matches the form used in
    secstore keys (``/OA2C/CS_<32hex>_<NN>``)."""
    if not raw:
        return ""
    return raw.lower().replace("-", "").replace(" ", "").strip()


def _pick(row: dict, hint_tuple: tuple) -> str:
    """Find the first column on `row` whose name matches any hint
    (exact-match first, then substring), return its trimmed value.
    Returns "" when nothing matches or every match was empty."""
    upper = {k.upper(): k for k in row.keys()}
    for hint in hint_tuple:
        if hint in upper:
            v = (row[upper[hint]] or "").strip()
            if v:
                return v
    for hint in hint_tuple:
        for col_upper, col_orig in upper.items():
            if hint in col_upper:
                v = (row[col_orig] or "").strip()
                if v:
                    return v
    return ""


def _read_table_all_columns(node: SAPNode, table: str,
                              creds: Optional[Credentials]) -> tuple:
    """Read every column of `table` via sapmap_rfc.read_table without
    pre-listing fields, so kernel-specific column-name drift can't
    cause a RFC_READ_TABLE / AD718 hard failure.

    Returns ``(rows, error_str)``.  An empty `rows` list with empty
    error means the table genuinely has no data; populated `error`
    means the call itself raised (auth missing, table doesn't exist,
    etc.) so the caller can fall through to the next table variant.
    """
    import sapmap_rfc
    from sapmap_errors import format_rfc_exception
    try:
        rows = sapmap_rfc.read_table(node, table, fields=None,
                                       creds=creds, max_rows=500) or []
        return rows, ""
    except Exception as e:
        return [], format_rfc_exception(e)[:200]


def _try_read_first_populated(node: SAPNode, table_variants: tuple,
                                 creds: Optional[Credentials]) -> tuple:
    """Probe each `table_variants` candidate in order; the first one
    that returns ≥1 row wins.  Returns ``(table_name, rows)``.

    Logs every probe outcome (rows / empty / error) so the operator
    can tell whether a kernel mismatch, an auth issue or a truly
    empty config caused the no-yield.  If every candidate is empty
    or errored, returns ``("", [])``.
    """
    last_error = ""
    for tbl in table_variants:
        print(f"[*] {node.sid}: probing {tbl} (all columns)…")
        rows, err = _read_table_all_columns(node, tbl, creds)
        if err:
            print(f"[-] {node.sid}: {tbl} read failed — {err}")
            last_error = err
            continue
        if not rows:
            print(f"[*] {node.sid}: {tbl} exists but returned 0 rows")
            continue
        cols = sorted(rows[0].keys())
        print(f"[+] {node.sid}: {tbl} → {len(rows)} row(s); "
              f"columns: {', '.join(cols[:8])}"
              f"{' …' if len(cols) > 8 else ''}")
        return tbl, rows
    if last_error:
        print(f"[*] {node.sid}: every probed table errored — last: "
              f"{last_error}")
    return "", []


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
        grant_type:         from OA2C_CLIENT_EXT (when reachable)
        auth_method:        e.g. CLIENT_SECRET_BASIC
        description:        human-readable label (when present)
        profile_uuid:       links to OA2C_PROFILES (when populated)

    The matching ``client_secret`` is NOT included here — the harvester
    looks it up against ``node.secstore_entries`` by CLIENT_UUID at
    candidate-build time.
    """
    print(f"[*] {node.sid}: reading OAuth 2.0 client config "
          f"(transaction OA2C_CONFIG tables)")
    table, clients = _try_read_first_populated(
        node, _CLIENT_TABLE_VARIANTS, creds)
    if not clients:
        print(f"[*] {node.sid}: no OAuth client config visible across "
              f"{', '.join(_CLIENT_TABLE_VARIANTS)} — either the "
              f"system has no OAuth profiles configured, or this "
              f"kernel exposes them under a table name SAPMAP "
              f"doesn't probe yet (let us know in an issue if "
              f"OAUC2_CONFIG transaction shows profiles but this "
              f"call returns 0).")
        return []

    # Extension table is best-effort — when missing, grant_type just
    # stays empty and the operator can edit it manually before mint.
    print(f"[*] {node.sid}: looking up grant types in "
          f"{', '.join(_CLIENT_EXT_TABLE_VARIANTS)}…")
    _ext_table, ext_rows = _try_read_first_populated(
        node, _CLIENT_EXT_TABLE_VARIANTS, creds)
    grant_by_uuid: dict = {}
    for r in ext_rows:
        uuid = _normalise_uuid(_pick(r, ("CLIENT_UUID", "CONFIG_ID")))
        gt = _pick(r, _GRANT_HINTS)
        if uuid and gt:
            grant_by_uuid[uuid] = gt

    profiles = []
    for r in clients:
        uuid = _normalise_uuid(_pick(r, _FIELD_HINTS["client_uuid"]))
        if not uuid:
            continue
        profiles.append({
            "client_uuid":      uuid,
            "client_id":        _pick(r, _FIELD_HINTS["client_id"]),
            "token_endpoint":   _pick(r, _FIELD_HINTS["token_endpoint"]),
            "auth_endpoint":    _pick(r, _FIELD_HINTS["auth_endpoint"]),
            "issuer":           _pick(r, _FIELD_HINTS["issuer"]),
            "auth_method":      _pick(r, _FIELD_HINTS["auth_method"]),
            "description":      _pick(r, _FIELD_HINTS["description"]),
            "profile":          _pick(r, _FIELD_HINTS["profile"]),
            "grant_type":       grant_by_uuid.get(uuid, ""),
        })

    n_btp = sum(1 for p in profiles
                 if "hana.ondemand.com" in (p["token_endpoint"] or ""))
    n_no_token = sum(1 for p in profiles if not p["token_endpoint"])
    print(f"[+] {node.sid}: parsed {len(profiles)} OAuth profile(s) "
          f"from {table} ({n_btp} BTP-bound)")
    if n_no_token:
        print(f"[*] {node.sid}: {n_no_token} profile(s) had no "
              f"recognisable token endpoint column — kernel may "
              f"split the URL across separate columns.  "
              f"Original column names from row 0: "
              f"{', '.join(sorted(clients[0].keys())[:12])}")
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
        if "/OA2C/CS_" not in ident:
            continue
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
