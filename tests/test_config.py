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
