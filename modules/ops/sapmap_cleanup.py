#!/usr/bin/env python3
"""
SAPMAP Cleanup — Delete created users and RFC destinations.

Ensures all SAPMAP-created artifacts can be reliably removed
from target systems after the assessment.
"""

import logging

from sapmap_models import SAPMAPState, SAPNode, CreatedUser
from sapmap_config import SAPMAP_USER_PREFIX
import sapmap_rfc

logger = logging.getLogger(__name__)


def cleanup_node_users(node: SAPNode, state: SAPMAPState) -> dict:
    """Delete all SAPMAP-created users from a single node.

    Returns dict: {deleted: [username, ...], failed: [username, ...]}

    Phase 3b: when the gateway port (33NN) is unreachable but we have
    a SOAP-RFC route to the node (e.g. an HTTP destination's verified
    creds), routes BAPI_USER_DELETE over SOAP instead of pyrfc.
    Otherwise cleanup on firewalled targets would hang 60s per user
    before failing.
    """
    result = {"deleted": [], "failed": []}

    if not node.created_users:
        print(f"[*] No created users to clean up in {node.sid}")
        return result

    # Resolve a SOAP-RFC session + route ONCE, not per user.  Avoids
    # re-probing the gateway socket on every deletion.
    from sapmap_gui import resolve_soap_session_for_node
    _soap_session, soap_route = resolve_soap_session_for_node(
        state, node)
    use_soap = _soap_session is not None
    if use_soap:
        print(f"[*] {node.sid}: gateway down — routing cleanup "
              f"via SOAP-RFC ({soap_route['host']}:"
              f"{soap_route['port']}, via "
              f"{soap_route['via_destination']})")

    creds = node.best_credentials()
    # dbcon_direct users are reversed via the DBCON's OWN creds, not
    # the source node's — don't refuse cleanup just because the
    # source is credless if all pending users are DBCON-planted.
    non_dbcon_pending = any(
        u.method != "dbcon_direct" for u in node.created_users)
    if non_dbcon_pending and not creds and not use_soap:
        print(f"[-] No credentials to connect to {node.sid} for cleanup"
              f" — non-DBCON users will remain, DBCON users still "
              f"cleanable via their own edge creds")
        result["failed"] = [u.username for u in node.created_users
                             if u.method != "dbcon_direct"]

    for user in list(node.created_users):
        print(f"[*] Deleting user {user.username} from {node.sid}"
              + (f" (method={user.method})" if user.method else "")
              + "...")
        # DBCON-direct users live on the TARGET HANA schema, not on
        # the source SAP.  Reverse via direct SQL through the same
        # DBCONConnection.
        if user.method == "dbcon_direct":
            success = _delete_user_via_dbcon(node, user)
        elif use_soap:
            from sap_soap_basic import delete_user_via_soap
            r = delete_user_via_soap(
                host=soap_route["host"], port=soap_route["port"],
                client=soap_route["client"],
                user=soap_route["user"],
                password=soap_route["password"],
                victim_username=user.username,
                https=soap_route["https"])
            success = r.get("success", False)
            if not success:
                print(f"[-] {node.sid}: "
                      f"{r.get('message', 'unknown error')}")
        else:
            success = sapmap_rfc.delete_user(
                node, user.username, creds)
        if success:
            result["deleted"].append(user.username)
            node.created_users.remove(user)
            # Also remove from global tracking
            state.created_users = [
                u for u in state.created_users
                if not (u.username == user.username and u.sid == node.sid)
            ]
        else:
            result["failed"].append(user.username)

    # Update pwned status
    if not node.created_users:
        # Only mark as not-pwned if there are no remaining created users
        # and no manually provided credentials
        if not any(c.verified for c in node.credentials):
            node.pwned = False

    return result


def _delete_user_via_dbcon(source_node: SAPNode,
                             user: CreatedUser) -> bool:
    """Reverse a dbcon_direct SAPMAP00 create by DELETE-ing the same
    17 rows across USR02/USR04/UST04/USRBF2 via the DBCONConnection
    the user was planted through.

    Finds the DBCONConnection on the source SAP by target_sid.
    Returns True on verified USR02 row-gone, False otherwise.
    """
    target_sid = (user.sid or "").upper().strip()
    if not target_sid:
        print(f"[-] {source_node.sid}: cleanup dbcon_direct: no "
              f"target_sid on CreatedUser {user.username}")
        return False
    edge = next(
        (e for e in (source_node.dbcon_edges or [])
         if (e.target_sid or "").upper() == target_sid), None)
    if edge is None:
        avail = [(e.con_name, e.target_sid)
                 for e in (source_node.dbcon_edges or [])]
        print(f"[-] {source_node.sid}: cleanup dbcon_direct: no "
              f"dbcon_edge with target_sid={target_sid} — "
              f"available: {avail}")
        return False

    try:
        from sap_dbcon_probe import _import_hdbcli, _resolve_sap_schema
    except Exception as e:
        print(f"[-] cleanup dbcon_direct: import failed: {e}")
        return False
    dbapi, err = _import_hdbcli()
    if dbapi is None:
        print(f"[-] cleanup dbcon_direct: {err}")
        return False
    if edge.dbms != "HDB":
        print(f"[-] cleanup dbcon_direct: v1 supports HDB only "
              f"(edge dbms={edge.dbms})")
        return False

    kwargs = {
        "address": edge.host, "port": edge.port,
        "user": edge.user, "password": edge.password,
        "autocommit": True, "communicationTimeout": 30000,
    }
    if edge.dbname: kwargs["databaseName"] = edge.dbname

    print(f"[*] {source_node.sid}: cleanup dbcon_direct — connecting "
          f"to {edge.host}:{edge.port} to DELETE {user.username} "
          f"from {target_sid}/{user.client}")
    conn = None
    try:
        conn = dbapi.connect(**kwargs)
        schema = _resolve_sap_schema(conn, target_sid=target_sid)
        if not schema:
            print(f"[-] cleanup dbcon_direct: schema for USR02 not "
                  f"found on {edge.host}")
            return False
        # Delete rows in reverse dependency order.  All four tables
        # keyed by (MANDT, BNAME).  A missing row on any is fine —
        # cleanup is idempotent.
        for tbl in ("USRBF2", "UST04", "USR04", "USR02"):
            cur = conn.cursor()
            try:
                cur.execute(
                    f'DELETE FROM "{schema}"."{tbl}" '
                    f'WHERE MANDT=? AND BNAME=?',
                    (user.client, user.username))
                print(f"    [+] {schema}.{tbl}: deleted rows for "
                      f"{user.username}")
            except Exception as _de:
                print(f"    [-] {schema}.{tbl}: delete raised "
                      f"{type(_de).__name__}: {str(_de)[:120]} "
                      f"(non-fatal)")
            finally:
                cur.close()

        # Verify: USR02 row gone?
        cur = conn.cursor()
        try:
            cur.execute(
                f'SELECT COUNT(*) FROM "{schema}"."USR02" '
                f'WHERE MANDT=? AND BNAME=?',
                (user.client, user.username))
            r = cur.fetchone()
            gone = (r and int(r[0]) == 0)
        finally:
            cur.close()
        if gone:
            print(f"[+] {source_node.sid}: cleanup dbcon_direct: "
                  f"{user.username} deleted + verified on "
                  f"{target_sid}/{user.client}")
        else:
            print(f"[-] {source_node.sid}: cleanup dbcon_direct: "
                  f"{user.username} still present in USR02 after "
                  f"DELETE — permissions?")
        return bool(gone)
    except Exception as e:
        print(f"[-] {source_node.sid}: cleanup dbcon_direct: "
              f"{type(e).__name__}: {e}")
        return False
    finally:
        try:
            if conn is not None: conn.close()
        except Exception: pass


def cleanup_all_users(state: SAPMAPState) -> dict:
    """Delete all SAPMAP-created users across all nodes.

    Returns dict: {total_deleted: int, total_failed: int, per_node: {sid: result}}
    """
    summary = {"total_deleted": 0, "total_failed": 0, "per_node": {}}

    nodes_with_users = [
        n for n in state.nodes.values() if n.created_users
    ]

    if not nodes_with_users:
        print("[*] No created users to clean up across any system")
        return summary

    print(f"[*] Cleaning up users across {len(nodes_with_users)} systems...")

    for node in nodes_with_users:
        result = cleanup_node_users(node, state)
        summary["per_node"][node.sid] = result
        summary["total_deleted"] += len(result["deleted"])
        summary["total_failed"] += len(result["failed"])

    print(f"[+] Cleanup complete: {summary['total_deleted']} deleted, "
          f"{summary['total_failed']} failed")

    return summary


def cleanup_destinations(node: SAPNode, state: SAPMAPState) -> int:
    """Remove SAPMAP-created TCP/IP destinations from a node.

    Returns count of deleted destinations.
    """
    deleted = 0
    creds = node.best_credentials()
    if not creds:
        return 0

    # Find SAPMAP-created destinations in connections
    sapmap_dests = [
        c for c in state.connections
        if c.source_sid == node.sid and
        c.destination_name.startswith("SAPMAP_TEST_")
    ]

    if not sapmap_dests:
        return 0

    print(f"[*] Cleaning up {len(sapmap_dests)} SAPMAP destinations in {node.sid}...")

    try:
        from sapmap_rfc import _get_rfc_backend
        RFCConnection = _get_rfc_backend()

        host = node.ip or node.hostname
        with RFCConnection(
            ashost=host,
            sysnr=creds.instance_nr,
            client=creds.client,
            user=creds.username,
            passwd=creds.password,
        ) as conn:
            for dest_conn in sapmap_dests:
                try:
                    conn.call(
                        "DEST_RFC_TCPIP_DELETE",
                        DESTINATION=dest_conn.destination_name,
                    )
                    deleted += 1
                    print(f"[+] Deleted destination {dest_conn.destination_name}")
                except Exception as e:
                    logger.debug(f"Could not delete dest {dest_conn.destination_name}: {e}")

    except Exception as e:
        logger.error(f"Destination cleanup failed for {node.sid}: {e}")

    return deleted


def list_created_users(state: SAPMAPState) -> list:
    """Get a summary of all created users across all systems."""
    users = []
    for user in state.created_users:
        users.append({
            "username": user.username,
            "sid": user.sid,
            "client": user.client,
            "hostname": user.hostname,
            "ip": user.ip,
            "method": user.method,
            "created_at": user.created_at,
        })
    return users
