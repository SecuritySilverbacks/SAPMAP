"""Same-host SAP instance discovery (issue #70).

When one SAP system on a host has an OS-command channel, other SAP systems
installed on the SAME host each live under ``/usr/sap/<SID>``.  This module
lists ``/usr/sap`` through the node's existing OS-exec channel, extracts the
other SIDs, and correlates them with systems already plotted on the map at the
same host/IP.  Unseen SIDs are materialized as dashed placeholder nodes (same
treatment as the other ``discovered_via_*`` placeholders) so they render in the
shared host zone.

This only READS the directory listing — it does not act on the co-located
systems.  The operator-triggered "pivot" (which reuses the existing per-node
Gateway primitive) lives in the GUI layer.
"""
from __future__ import annotations

import re

# A valid SAP SID is exactly three characters: an upper-case letter followed by
# two upper-case letters or digits.  /usr/sap's non-system entries (trans,
# hostctrl, tmp, ccms, …) are lower-case or longer, so the upper-case gate
# already excludes them; SYS is excluded explicitly for safety.
_SID_RE = re.compile(r"^[A-Z][A-Z0-9]{2}$")
_RESERVED = {"SYS", "TMP"}


def _canonical_sid(raw: str) -> str:
    """The bare SID of a node key, stripping the ``@<anchor>`` mangle that
    add_node applies to same-SID-different-host collisions."""
    return (raw or "").split("@", 1)[0].strip().upper()


def parse_colocated_sids(output_lines, own_sid: str) -> list:
    """Extract foreign SAP SIDs from a ``ls /usr/sap`` listing.

    Tolerates one-per-line and multi-column output (splits on whitespace),
    de-duplicates, drops this node's own SID and the reserved non-system dirs,
    and preserves first-seen order.
    """
    own = _canonical_sid(own_sid)   # strip any @<anchor> mangle on the key
    seen = set()
    out = []
    for line in (output_lines or []):
        for tok in str(line).split():
            sid = tok.strip().strip("/")
            if not _SID_RE.match(sid):
                continue
            if sid == own or sid in _RESERVED or sid in seen:
                continue
            seen.add(sid)
            out.append(sid)
    return out


def _plotted_same_host(state, sid: str, own_ips: set, own_names: set):
    """Return an existing plotted node with this SID on the same host, or None.

    Matches on IP OR hostname — the same host identity ``add_node``'s key
    resolver uses to merge — so a node plotted under a hostname with no
    intersecting IP (XML / message-server imports) still correlates and is not
    mistaken for a new system.
    """
    for n in state.nodes.values():
        if _canonical_sid(getattr(n, "sid", "")) != sid:
            continue
        try:
            if (set(n.all_ips()) & own_ips) or (set(n.all_hostnames()) & own_names):
                return n
        except Exception:
            if (getattr(n, "ip", "") in own_ips
                    or (getattr(n, "hostname", "") or "").lower() in own_names):
                return n
    return None


def discover_colocated_sids(node, state, run_cmd=None) -> dict:
    """List /usr/sap on ``node`` and correlate the other SIDs with the map.

    ``run_cmd`` defaults to sapmap_exploit.run_os_command (injectable for
    tests); it must accept ``(node, command, params)`` and return a dict with
    ``success`` (bool) and ``output`` (list of lines).

    Side effects: sets ``node.colocated_sids``; adds a dashed placeholder node
    (``discovered_via_colocation=True``) for each unseen co-located SID; emits
    one INFO finding.  Best-effort and non-fatal.

    Returns ``{"ok", "colocated", "placeholders_added", "reason"}``.
    """
    if run_cmd is None:
        from sapmap_exploit import run_os_command as run_cmd  # lazy — avoid cycle

    res = run_cmd(node, "ls", "/usr/sap")
    if not res or not res.get("success"):
        reason = (res or {}).get("error") or "no OS-command channel / listing failed"
        return {"ok": False, "colocated": [], "placeholders_added": [], "reason": reason}

    sids = parse_colocated_sids(res.get("output") or [], getattr(node, "sid", ""))

    own_ips, own_names = set(), set()
    try:
        own_ips = set(node.all_ips())
        own_names = set(node.all_hostnames())
    except Exception:
        if getattr(node, "ip", ""):
            own_ips = {node.ip}
        if getattr(node, "hostname", ""):
            own_names = {node.hostname.lower()}
    anchor = node.ip or node.hostname or ""

    colocated = []
    placeholders_added = []
    for sid in sids:
        plotted = _plotted_same_host(state, sid, own_ips, own_names) is not None
        if not plotted:
            try:
                from sapmap_models import SAPNode
                ph = SAPNode(sid=sid, ip=node.ip or "", hostname=node.hostname or "")
                ph.discovered_via_colocation = True
                ph.linked_target_sid = getattr(node, "sid", "")
                # Never overwrite an existing node: if add_node's key resolver
                # would land on one already present (e.g. an anchorless
                # placeholder), treat the SID as already plotted instead.
                key = state._resolve_add_node_key(ph)
                if key in state.nodes:
                    plotted = True
                else:
                    state.add_node(ph)
                    placeholders_added.append(ph.sid)  # add_node may re-key
            except Exception:
                pass
        colocated.append({"sid": sid, "ip": anchor, "plotted": plotted})

    node.colocated_sids = colocated

    if sids:
        try:
            from sapmap_findings import emit_finding
            emit_finding(
                "INFO", getattr(node, "sid", "?"),
                f"Co-located SAP instances on {anchor or 'host'}: "
                f"{', '.join(sids)} — same-host lateral candidates reachable "
                f"via their own RFC Gateway (issue #70).",
                ref="colocation.discovered",
            )
        except Exception:
            pass

    return {"ok": True, "colocated": colocated,
            "placeholders_added": placeholders_added, "reason": ""}
