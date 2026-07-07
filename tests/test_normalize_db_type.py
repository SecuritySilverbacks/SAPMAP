"""Unit test for _normalize_db_type — long-form DB names → SXPG short codes."""
from sapmap_secstore import _normalize_db_type


def test_adabas_variants():
    assert _normalize_db_type("ADABAS D") == "ADA"
    assert _normalize_db_type("adabas d") == "ADA"
    assert _normalize_db_type("MAXDB") == "ADA"
    assert _normalize_db_type("ADA") == "ADA"


def test_hana_variants():
    assert _normalize_db_type("HANA") == "HDB"
    assert _normalize_db_type("HANA DATABASE") == "HDB"
    assert _normalize_db_type("HDB") == "HDB"


def test_mssql_variants():
    assert _normalize_db_type("MICROSOFT SQL SERVER") == "MSS"
    assert _normalize_db_type("MSS") == "MSS"
    assert _normalize_db_type("MSSQL") == "MSS"


def test_oracle_variants():
    assert _normalize_db_type("ORACLE") == "ORA"
    assert _normalize_db_type("ORA") == "ORA"


def test_db2_variants():
    assert _normalize_db_type("DB2") == "DB6"
    assert _normalize_db_type("DB6") == "DB6"
    assert _normalize_db_type("IBM DB2 z/OS") == "DB6"


def test_sybase_variants():
    assert _normalize_db_type("SYBASE ASE") == "SYB"
    assert _normalize_db_type("SYB") == "SYB"


def test_empty_and_unknown():
    assert _normalize_db_type("") == ""
    assert _normalize_db_type("WEIRD DB") == "WEIRD DB"
    # Whitespace trimmed
    assert _normalize_db_type("  HDB  ") == "HDB"
