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
    if not creds and not use_soap:
        print(f"[-] No credentials to connect to {node.sid} for cleanup")
        result["failed"] = [u.username for u in node.created_users]
        return result

    for user in list(node.created_users):
        print(f"[*] Deleting user {user.username} from {node.sid}...")
        if use_soap:
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
        from sap_rfc_ctypes import RFCConnection

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
