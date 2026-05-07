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
    add_system, set_credentials, scan, check_gw, check_ms, betrusted,
    betrusted_chain, create_user, create_user_via_rfc, retrieve_rfcs,
    test_rfcs, test_rfc_single, download_hashes, download_secstore,
    impact_assess, impact_show, impact_export, analyze_chains,
    check_all_gw, check_all_betrusted, propagate, deep_scan, lpe,
    highlight_chain, layout, sleep,
    # SAProuter
    set_saprouter, check_router_info, router_scan,
    # Java data extraction / business impact
    java_secstore, extract_java_hashes, read_java_destinations,
    download_java_table, impact_assess_java,
    # Java vulnerability checks
    check_cve_31324, check_cve_6287, check_all_cve_31324,
    # Java exploitation (requires --confirm on the CLI)
    exploit_cve_31324, create_user_java,
    # BTP — cloud-side enumeration with a stored token
    btp_set_token, btp_enumerate, btp_pull_destinations_for_token,
    btp_test_destination, btp_create_user_on_target,
    # BTP — on-prem → cloud lateral pivot
    harvest_btp_creds, mint_btp_token,
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
        return ("POST", f"/api/node/{target}/retrieve_rfcs", {}, True)

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

    if action == "check_copyfail":
        # Check if the host is vulnerable to CVE-2026-31431 (Copy Fail LPE).
        #   target: SAP node SID (must have OS-exec path, Linux only)
        return ("POST", f"/api/node/{target}/check_copyfail", {}, True)

    if action == "exploit_copyfail":
        # Execute a shell command as root via CVE-2026-31431 Copy Fail LPE.
        #   target:  SAP node SID
        #   command: shell command to run as root (default: "id")
        return ("POST", f"/api/node/{target}/exploit_copyfail", {
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

    if action == "mint_btp_token":
        # Exchange a captured (uaa_url, client_id, client_secret) at
        # XSUAA's /oauth/token for a BTP access token.  Stores the
        # result in api.btp_tokens keyed by the token's region (so
        # btp_pull_destinations_for_token can chain on top).
        #   target:        SAP node SID the secret was harvested from
        #   uaa_url:       XSUAA token endpoint (full URL or bare host)
        #   client_id:     OAuth client_id (from OA2C_CLIENT or paste)
        #   client_secret: OAuth client_secret (from /OA2C/CS_*_NN
        #                  or paste; supports path:<file>)
        return ("POST", f"/api/node/{target}/mint_btp_token", {
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
    short and the secret doesn't have to live in version control."""
    if isinstance(value, str) and value.startswith("path:"):
        path = value[5:].strip()
        try:
            with open(os.path.expanduser(path), "r") as fh:
                return fh.read().strip()
        except Exception as e:
            logger.warning(f"Could not read token from {path!r}: {e}")
            return ""
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
    "exploit_copyfail",       # patches /usr/bin/su page cache to exec as root
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
