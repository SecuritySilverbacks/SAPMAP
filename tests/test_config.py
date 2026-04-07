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
)
from sapmap_exploit import _cmd_caret_escape


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


def test_sql_generators_return_list():
    generators = [
        (sql_hana, ("S4H", "000", "SAPMAP00")),
        (sql_mssql_abap, ("S4H", "000", "SAPMAP00")),
        (sql_maxdb, ("S4H", "000", "SAPMAP00")),
        (sql_oracle, ("S4H", "000", "SAPMAP00")),
        (sql_db2, ("S4H", "000", "SAPMAP00")),
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
