"""HANA hdbsql discovery in the on-target wrapper (GW SAPXPG
user-creation path).

Standard installs keep hdbsql at /usr/sap/<SID>/hdbclient/hdbsql,
but trial VMs (like the SAP IDE image) put it under
/usr/sap/<SID>/SYS/exe/uc/linuxx86_64/hdbclient/hdbsql, and some
installs only expose it via <sidadm>'s profile PATH.

Discovery lives inside the on-target shell wrapper — SAPXPG's
stdout-capture channel can't reliably read a Python-side probe
back, so we let the wrapper resolve the path in its own shell
and just watch its exit code.

Tests lock in:
  1. _build_hana_wrapper_script honours a caller-supplied
     hdbsql_path (baked into the wrapper).
  2. Without a supplied path the wrapper emits a runtime
     candidate loop covering standard / trial-VM / PATH / env.
  3. Port ladder logic is unaffected by the hdbsql-path change.
  4. Legacy _find_hdbsql_via_gw entry point is a no-op stub
     returning "" (kept as a soft removal for any external caller).
"""
from __future__ import annotations

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
    # Should NOT emit the runtime probe loop when a path was given
    assert "for _H in" not in script


def test_wrapper_emits_runtime_probe_when_no_path_supplied():
    """Without a caller-supplied path, the wrapper resolves hdbsql
    at runtime — iterates every known layout, then falls back to
    parsing PATH and env for a hdbclient fragment."""
    script = _build_hana_wrapper_script("A4H", "00")
    # Standard + trial-VM + old-layout + shared-install candidates
    for candidate in (
        "/usr/sap/$S/hdbclient/hdbsql",
        "/usr/sap/$S/SYS/exe/uc/linuxx86_64/hdbclient/hdbsql",
        "/usr/sap/$S/SYS/exe/run/hdbsql",
        "/hana/shared/$S/hdbclient/hdbsql",
    ):
        assert candidate in script, (
            f"wrapper probe missing candidate {candidate!r}")
    # PATH parsing and env parsing fallbacks
    assert "grep -i hdbclient" in script
    assert "grep -oE '/[^: =]*hdbclient'" in script
    # Loop + first-executable-wins picker
    assert "for _H in" in script
    assert 'H="$_H"' in script


def test_wrapper_still_carries_port_ladder():
    """The custom-path change must not break the port-ladder logic."""
    script = _build_hana_wrapper_script("IDE", "00", hdbsql_path="/x/hdbsql")
    # The 3<NN>15 → 3<NN>13 tenant lookup → 3<NN>41 fallback ladder
    assert "3${N}15" in script
    assert "3${N}13" in script
    assert "3${N}41" in script


def test_wrapper_uses_probed_ports_first_when_supplied():
    """When SAPMAP has probed reachable HANA ports from its own
    network, those go at the top of the try-list — proven
    listening beats guessed by port convention."""
    script = _build_hana_wrapper_script(
        "IDE", "00",
        probed_ports=[(30215, "3NN15"), (30213, "3NN13")])
    assert "[try probed 30215]" in script
    assert "[try probed 30213]" in script


def test_find_hdbsql_via_gw_stub_returns_empty():
    """Legacy pre-flight was removed — the name is kept only as a
    no-op stub so any external caller doesn't crash."""
    assert _find_hdbsql_via_gw(
        "10.0.0.1", 3300, "00", "somehost", "IDE", "742") == ""
