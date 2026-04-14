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
    highlight_chain, sleep
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

    raise ValueError(f"Unknown action: {action}")


# ---------------------------------------------------------------------------
# Script execution
# ---------------------------------------------------------------------------

class ScriptRunner:
    """Execute a SAPMAP script against the local API server."""

    def __init__(self, base_url: str, script_path: str):
        self.base_url = base_url.rstrip("/")
        self.script_path = script_path
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
        self.steps = data["steps"]

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

            # Optional delay between steps
            delay = step.get("delay", 1)
            if delay > 0:
                time.sleep(delay)

        pf("")
        pf(f"[SCRIPT] === All {total} steps completed ===")
        return True
