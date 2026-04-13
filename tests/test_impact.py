"""Tests for sapmap_impact.py — business impact assessment engine.

All tests are offline (no network). They test the scenario registry,
data models, table reader helper, and EUR formatting.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sapmap_impact import (
    ImpactResult, list_scenarios, _format_eur, _read_table,
)
from sapmap_models import Severity


# ---------------------------------------------------------------------------
# ImpactResult
# ---------------------------------------------------------------------------

class TestImpactResult:

    def test_severity_label(self):
        r = ImpactResult(scenario="test", category="Test", severity=Severity.CRITICAL,
                         headline="Test headline")
        assert r.severity_label == "CRITICAL"

    def test_to_dict(self):
        r = ImpactResult(scenario="salary", category="HR", severity=Severity.HIGH,
                         headline="10 salaries", record_count=10,
                         business_message="Bad stuff", icon="X")
        d = r.to_dict()
        assert d["scenario"] == "salary"
        assert d["severity_label"] == "HIGH"
        assert d["record_count"] == 10
        assert d["icon"] == "X"
        assert d["headline"] == "10 salaries"

    def test_to_dict_sample_records_truncated(self):
        records = [{"id": i} for i in range(20)]
        r = ImpactResult(scenario="t", category="c", severity=Severity.INFO,
                         headline="h", sample_records=records)
        d = r.to_dict()
        assert len(d["sample_records"]) == 10  # truncated to 10

    def test_defaults(self):
        r = ImpactResult(scenario="t", category="c", severity=Severity.INFO,
                         headline="h")
        assert r.record_count == 0
        assert r.sample_records == []
        assert r.error == ""


# ---------------------------------------------------------------------------
# Scenario registry
# ---------------------------------------------------------------------------

class TestScenarioRegistry:

    def test_scenarios_registered(self):
        scenarios = list_scenarios()
        assert len(scenarios) >= 9

    def test_scenario_fields(self):
        scenarios = list_scenarios()
        for s in scenarios:
            assert "name" in s
            assert "category" in s
            assert "severity" in s
            assert "severity_label" in s
            assert "icon" in s

    def test_known_scenarios_present(self):
        names = {s["name"] for s in list_scenarios()}
        assert "salary_exfiltration" in names
        assert "vendor_bank_fraud" in names
        assert "purchase_order_exposure" in names
        assert "user_account_takeover" in names
        assert "customer_data_breach" in names
        assert "supply_chain_intel" in names
        assert "sales_revenue" in names
        assert "production_sabotage" in names
        assert "rfc_landscape_exposure" in names

    def test_unique_names(self):
        names = [s["name"] for s in list_scenarios()]
        assert len(names) == len(set(names))

    def test_all_have_icons(self):
        for s in list_scenarios():
            assert s["icon"], f"Scenario {s['name']} has no icon"

    def test_severity_values_valid(self):
        for s in list_scenarios():
            assert s["severity"] in (1, 2, 3, 4, 5)


# ---------------------------------------------------------------------------
# EUR formatting
# ---------------------------------------------------------------------------

class TestFormatEur:

    def test_millions(self):
        assert "M" in _format_eur("1500000")

    def test_thousands(self):
        assert "K" in _format_eur("50000")

    def test_small(self):
        r = _format_eur("500")
        assert "500" in r

    def test_with_comma_decimal(self):
        r = _format_eur("1234,56")
        assert "1" in r

    def test_invalid_returns_original(self):
        assert _format_eur("abc") == "abc"

    def test_none_returns_empty(self):
        assert _format_eur(None) == ""

    def test_euro_symbol(self):
        r = _format_eur("50000")
        assert "\u20ac" in r


# ---------------------------------------------------------------------------
# _read_table (mock RFC connection)
# ---------------------------------------------------------------------------

class TestReadTable:

    def test_parses_pipe_delimited(self):
        class MockConn:
            def call(self, fm, **kw):
                return {
                    "FIELDS": [{"FIELDNAME": "A"}, {"FIELDNAME": "B"}],
                    "DATA": [{"WA": "val1|val2"}, {"WA": "val3|val4"}],
                }
        rows = _read_table(MockConn(), "TEST", ["A", "B"])
        assert len(rows) == 2
        assert rows[0] == {"A": "val1", "B": "val2"}
        assert rows[1] == {"A": "val3", "B": "val4"}

    def test_strips_whitespace(self):
        class MockConn:
            def call(self, fm, **kw):
                return {
                    "FIELDS": [{"FIELDNAME": "X"}],
                    "DATA": [{"WA": "  hello  "}],
                }
        rows = _read_table(MockConn(), "T", ["X"])
        assert rows[0]["X"] == "hello"

    def test_empty_data(self):
        class MockConn:
            def call(self, fm, **kw):
                return {"FIELDS": [{"FIELDNAME": "X"}], "DATA": []}
        assert _read_table(MockConn(), "T", ["X"]) == []

    def test_no_fields(self):
        class MockConn:
            def call(self, fm, **kw):
                return {"FIELDS": [], "DATA": []}
        assert _read_table(MockConn(), "T", ["X"]) == []

    def test_exception_returns_empty(self):
        class MockConn:
            def call(self, fm, **kw):
                raise Exception("auth error")
        assert _read_table(MockConn(), "T", ["X"]) == []

    def test_where_clause(self):
        class MockConn:
            def call(self, fm, **kw):
                assert "OPTIONS" in kw
                assert kw["OPTIONS"][0]["TEXT"].startswith("MANDT")
                return {"FIELDS": [{"FIELDNAME": "A"}], "DATA": []}
        _read_table(MockConn(), "T", ["A"], where="MANDT = '001'")
