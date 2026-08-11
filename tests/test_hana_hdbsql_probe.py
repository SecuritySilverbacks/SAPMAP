"""HANA hdbsql pre-flight (GW SAPXPG user-creation path).

Standard installs keep hdbsql at /usr/sap/<SID>/hdbclient/hdbsql,
but trial VMs (like the SAP IDE image) put it under
/usr/sap/<SID>/SYS/exe/uc/linuxx86_64/hdbclient/hdbsql, and some
installs only expose it via <sidadm>'s profile PATH.

These tests lock in:
  1. _build_hana_wrapper_script honours a caller-supplied
     hdbsql_path (baked into the on-target shell wrapper).
  2. The wrapper falls back to the standard location when the
     caller doesn't supply one.
  3. _find_hdbsql_via_gw's script includes every candidate we
     probe on the target (standard, trial-VM, PATH-derived).
"""
from __future__ import annotations

import inspect

# sap_db_sql_writers ↔ sapmap_exploit have a circular import — the
# writer imports _gw_connect from sapmap_exploit, and sapmap_exploit
# in turn imports helpers from sap_db_sql_writers.  Priming with
# sapmap_exploit first makes the second import find its symbols.
import sapmap_exploit  # noqa: F401
from sap_db_sql_writers import (  # noqa: E402
    _build_hana_wrapper_script, _find_hdbsql_via_gw,
)


def test_wrapper_uses_supplied_hdbsql_path():
    script = _build_hana_wrapper_script(
        "IDE", "00",
        hdbsql_path="/usr/sap/IDE/SYS/exe/uc/linuxx86_64/hdbclient/hdbsql")
    assert (
        "H='/usr/sap/IDE/SYS/exe/uc/linuxx86_64/hdbclient/hdbsql'"
        in script
    )
    # Should NOT emit the standard fallback line when a path was given
    assert "H=/usr/sap/$S/hdbclient/hdbsql" not in script


def test_wrapper_falls_back_to_standard_path_when_none_supplied():
    script = _build_hana_wrapper_script("A4H", "00")
    assert "H=/usr/sap/$S/hdbclient/hdbsql" in script


def test_wrapper_still_carries_port_ladder():
    """The custom-path change must not break the port-ladder logic."""
    script = _build_hana_wrapper_script("IDE", "00", hdbsql_path="/x/hdbsql")
    # The 3<NN>15 → 3<NN>13 tenant lookup → 3<NN>41 fallback ladder
    assert "3${N}15" in script
    assert "3${N}13" in script
    assert "3${N}41" in script


def test_find_hdbsql_via_gw_source_lists_all_candidates():
    """The runtime probe script (fetched via source inspection since
    it's baked into the function body) must include every candidate
    path we plan to try on the target."""
    src = inspect.getsource(_find_hdbsql_via_gw)
    for candidate in (
        "/usr/sap/$S/hdbclient/hdbsql",
        "/usr/sap/$S/SYS/exe/uc/linuxx86_64/hdbclient/hdbsql",
        "/usr/sap/$S/SYS/exe/run/hdbsql",
        "/hana/shared/$S/hdbclient/hdbsql",
    ):
        assert candidate in src, (
            f"probe script missing candidate {candidate!r}")
    # PATH-fragment fallback must be there
    assert "grep -i hdbclient" in src
    # And the env-based fallback (for sidadm profiles whose PATH
    # export doesn't reach SAPXPG's login shell)
    assert "env|grep -oE" in src


def test_find_hdbsql_via_gw_probe_returns_empty_on_no_lines():
    """When the cat-file probe returns nothing (SAPXPG output capture
    failed), _find_hdbsql_via_gw must return "" so the caller aborts
    instead of running SQL against an unknown path."""
    from unittest.mock import patch
    with patch("sap_db_sql_writers._run_ext_prog_via_gw",
                return_value=True), \
         patch("sap_db_sql_writers._cat_file_via_gw",
                return_value=[]):
        result = _find_hdbsql_via_gw(
            "10.0.0.1", 3300, "00", "somehost", "IDE", "742")
    assert result == ""


def test_find_hdbsql_via_gw_parses_hdbsql_line():
    """When the probe file contains 'HDBSQL=/some/path', that path
    is returned verbatim."""
    from unittest.mock import patch
    with patch("sap_db_sql_writers._run_ext_prog_via_gw",
                return_value=True), \
         patch("sap_db_sql_writers._cat_file_via_gw",
                return_value=[
                    "[probe] candidates:",
                    "[probe] --- attempts ---",
                    "[probe] /usr/sap/IDE/hdbclient/hdbsql not executable",
                    "[probe] /usr/sap/IDE/SYS/exe/uc/linuxx86_64/hdbclient/hdbsql rc=0 out=hdbsql version 2.0",
                    "HDBSQL=/usr/sap/IDE/SYS/exe/uc/linuxx86_64/hdbclient/hdbsql",
                ]):
        result = _find_hdbsql_via_gw(
            "10.0.0.1", 3300, "00", "somehost", "IDE", "742")
    assert result == (
        "/usr/sap/IDE/SYS/exe/uc/linuxx86_64/hdbclient/hdbsql")
