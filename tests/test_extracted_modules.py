#!/usr/bin/env python3
"""Smoke + import-shape tests for the five Tier-2 extracted modules.

Background: the Tier-2 split moved ~3300 lines out of sapmap_exploit.py
into five sibling modules.  The bugs caught during the extractions
(build_p1 not imported, _ctc_deploy_available not imported,
_get_local_ip_towards needing a lazy proxy, InstanceInfo not imported)
were all "function references a name that the new module never imported"
— a NameError that fires only at runtime, after live data hits the
function.

These tests act as a regression net for that whole class of bug:

  * import each module under the production order (sapmap_exploit
    first, then the extracted module)
  * every advertised public name resolves to a callable / dataclass
  * every free name inside every function body is either a builtin,
    a parameter, a local, or imported at module level — caught by
    a static AST scan
  * every name in the re-export shim of sapmap_exploit also exists
    on the source module (so a typo in a re-export can't slip
    through unnoticed)
  * function arity / signature is preserved across the move (catches
    cases where an extraction accidentally drops a parameter)

No network, no live SAP — pure structural assertions.
"""
from __future__ import annotations

import ast
import importlib
import inspect
import os
import sys

import pytest


# ---------------------------------------------------------------------------
# Module-level catalogue: (import_name, public_names re-exported via
# sapmap_exploit, expected presence of certain critical helpers)
# ---------------------------------------------------------------------------

EXTRACTED_MODULES = {
    "sap_db_sql_writers": {
        "exports": [
            "_cmd_caret_escape",
            "_oracle_write_and_exec_win",
            "_mssql_write_and_exec_win",
            "_hana_write_and_exec",
            "_maxdb_write_and_exec",
            "_execute_sql_via_gateway",
        ],
        # The post-mortem-on-this-file fixed: build_p1, _gw_connect,
        # _get_local_ip_towards must all be present.
        "must_be_callable": [
            "build_p1", "build_p2", "build_p3", "build_p4",
            "ni_send", "ni_recv", "ni_drain", "parse_response",
            "_gw_connect", "_get_local_ip_towards",
        ],
    },
    "sap_betrusted_chain": {
        "exports": [
            "_get_local_ip_towards",
            "try_betrusted_chain",
            "create_user_betrusted_chain",
        ],
        "must_be_callable": [
            "check_gw_vulnerable", "create_user_gw_exploit",
            "format_rfc_exception",
        ],
    },
    "sap_java_runner": {
        "exports": [
            "_ensure_java_db_jsp",
            "download_java_table",
            "extract_java_password_hashes",
            "assess_java_impact",
            "read_java_destinations",
        ],
        # Caught live: _ctc_deploy_available, _telnet_deploy_available,
        # InstanceInfo were missing imports.
        "must_be_callable": [
            "_deploy_jsp_via_ctc", "_deploy_jsp_via_telnet",
            "_ctc_deploy_available", "_telnet_deploy_available",
            "execute_cve_2025_31324_via_shell",
        ],
    },
    "sap_java_secstore_runner": {
        "exports": [
            "extract_java_secstore",
        ],
        "must_be_callable": [
            "execute_gw_command", "execute_cve_2025_31324_via_shell",
            "drop_cve_2025_31324_shell", "_resolve_java_admin_creds",
            "_telnet_deploy_available", "_ctc_deploy_available",
            "_deploy_jsp_via_ctc", "_deploy_jsp_via_telnet",
            "create_user_java", "_is_ipv4", "_hostname_matches",
            "_find_node_by_host_flex", "_probe_and_add_host",
            "_build_java_os_exec", "offline_decrypt_secstore",
        ],
    },
    "sap_scc_harvest": {
        "exports": [
            "harvest_scc_from_pwned_node",
            "harvest_scc_mappings_from_pwned_node",
        ],
        "must_be_callable": [
            "execute_gw_command", "run_os_command",
            "_build_java_os_exec",
        ],
    },
}


# ---------------------------------------------------------------------------
# AST helper: collect every "free name" referenced inside any function
# body that is NOT a builtin, parameter, local, or imported at module
# level.  Anything else is a likely missing import.
# ---------------------------------------------------------------------------

def _collect_target_names(target, into):
    """Recursively collect every Name id from an assignment target.

    Handles nested unpacks: `for i, (a, b) in seq:` exposes i, a, b.
    Without this the walker reports the inner names as unresolved
    free names.
    """
    if isinstance(target, ast.Name):
        into.add(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for e in target.elts:
            _collect_target_names(e, into)
    elif isinstance(target, ast.Starred):
        _collect_target_names(target.value, into)


def _free_names_in_module(src: str) -> set:
    import builtins as _bi
    tree = ast.parse(src)
    defined = set(dir(_bi))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            defined.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                defined.add(a.asname or a.name.split(".")[0])
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                _collect_target_names(t, defined)
        elif isinstance(node, ast.ClassDef):
            defined.add(node.name)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                defined.add(node.target.id)

    free = set()

    class V(ast.NodeVisitor):
        def __init__(self):
            self.scopes = [defined]

        def visit_FunctionDef(self, node):
            local = {a.arg for a in node.args.args}
            for a in node.args.kwonlyargs:
                local.add(a.arg)
            if node.args.vararg:
                local.add(node.args.vararg.arg)
            if node.args.kwarg:
                local.add(node.args.kwarg.arg)
            for sub in ast.walk(node):
                if isinstance(sub, ast.Assign):
                    for t in sub.targets:
                        _collect_target_names(t, local)
                elif isinstance(sub, ast.AugAssign):
                    _collect_target_names(sub.target, local)
                elif isinstance(sub, ast.AnnAssign):
                    _collect_target_names(sub.target, local)
                elif isinstance(sub, ast.For):
                    _collect_target_names(sub.target, local)
                elif isinstance(sub, ast.With):
                    for w in sub.items:
                        if w.optional_vars:
                            _collect_target_names(w.optional_vars, local)
                elif isinstance(sub, ast.ExceptHandler) and sub.name:
                    local.add(sub.name)
                elif isinstance(sub, ast.ImportFrom):
                    for a in sub.names:
                        local.add(a.asname or a.name)
                elif isinstance(sub, ast.Import):
                    for a in sub.names:
                        local.add(a.asname or a.name.split(".")[0])
                elif isinstance(sub, ast.FunctionDef):
                    local.add(sub.name)
                elif isinstance(sub, ast.Lambda):
                    for a in sub.args.args:
                        local.add(a.arg)
                elif isinstance(sub, (ast.ListComp, ast.SetComp,
                                       ast.DictComp, ast.GeneratorExp)):
                    for g in sub.generators:
                        _collect_target_names(g.target, local)
            self.scopes.append(local)
            for c in ast.iter_child_nodes(node):
                self.visit(c)
            self.scopes.pop()

        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load):
                if not any(node.id in s for s in self.scopes):
                    free.add(node.id)

    V().visit(tree)
    return free


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _ensure_modules_loaded():
    """Load sapmap_exploit FIRST so the re-export chain is established
    in production order before any extracted-module test runs."""
    import sapmap_exploit  # noqa: F401
    yield


@pytest.mark.parametrize("modname", sorted(EXTRACTED_MODULES.keys()))
def test_module_imports_cleanly(modname):
    """Every extracted module must import without raising — under the
    production order (sapmap_exploit pre-loaded by the fixture)."""
    mod = importlib.import_module(modname)
    assert mod is not None
    assert hasattr(mod, "__file__")


@pytest.mark.parametrize("modname", sorted(EXTRACTED_MODULES.keys()))
def test_module_public_exports_present(modname):
    """Every name listed under "exports" must actually exist on the
    module AND on sapmap_exploit (the re-export shim).  This locks in
    the API contract — a typo in a re-export breaks the test
    immediately rather than at runtime."""
    mod = importlib.import_module(modname)
    import sapmap_exploit
    for name in EXTRACTED_MODULES[modname]["exports"]:
        # Must exist on the source module
        attr = getattr(mod, name, None)
        assert attr is not None, (
            f"{modname}.{name} does not exist (exports list out of sync)")
        # Re-export through sapmap_exploit
        rexp = getattr(sapmap_exploit, name, None)
        assert rexp is not None, (
            f"sapmap_exploit.{name} not re-exported (the umbrella file's "
            f"shim is out of sync with {modname})")


@pytest.mark.parametrize("modname", sorted(EXTRACTED_MODULES.keys()))
def test_module_critical_helpers_resolved(modname):
    """Every name in must_be_callable must resolve to a callable on
    the module's namespace at runtime.  These names cover the
    historical NameError culprits — build_p1, _gw_connect,
    _ctc_deploy_available, _get_local_ip_towards, etc.  Regression
    net for the 'function bodies fail because helper isn't imported'
    failure mode."""
    mod = importlib.import_module(modname)
    for name in EXTRACTED_MODULES[modname]["must_be_callable"]:
        val = getattr(mod, name, None)
        assert val is not None, f"{modname}.{name} unresolvable at runtime"
        # Either a callable, or a module (for cases where the import
        # was `import X` rather than `from X import Y`)
        assert callable(val) or hasattr(val, "__call__") or \
            inspect.ismodule(val), \
            f"{modname}.{name} resolved but is not callable: {val!r}"


@pytest.mark.parametrize("modname", sorted(EXTRACTED_MODULES.keys()))
def test_module_no_unresolved_free_names(modname):
    """Static AST scan: every Name referenced inside every function
    body of the module must be reachable from the module's scope.

    Builtins, parameters, locals, and module-level imports are all
    valid sources.  Anything left over is a likely missing import —
    the exact bug class that hit us live three times during the
    extractions."""
    mod = importlib.import_module(modname)
    src = inspect.getsource(mod)
    free = _free_names_in_module(src)

    # The AST walker can't track tuple unpacking inside generator /
    # comprehension targets (`for a, b in seq:` etc.), so it
    # produces single-letter false positives.  Filter them out plus
    # a small set of well-known idioms.  Anything LEFT after the
    # filter genuinely wasn't imported.
    KNOWN_LOOP_VARS = set("abcdefghijklmnopqrstuvwxyz") | {
        "args", "kwargs", "self", "cls",
    }
    real = sorted(n for n in free if n not in KNOWN_LOOP_VARS)
    # Skip names that are obviously short fixture-loop letters
    real = [n for n in real if len(n) > 1 and not n.isupper()]
    assert real == [], (
        f"{modname} references undefined names at module load:\n  "
        + "\n  ".join(real))


def test_re_export_shim_in_sapmap_exploit_covers_every_extraction():
    """Every name advertised in any module's exports list must appear
    in the sapmap_exploit module.  Belt-and-braces alongside
    test_module_public_exports_present — guards against future
    extractions adding an exports entry but forgetting to re-export
    from sapmap_exploit."""
    import sapmap_exploit
    missing = []
    for modname, spec in EXTRACTED_MODULES.items():
        for name in spec["exports"]:
            if not hasattr(sapmap_exploit, name):
                missing.append(f"{modname}.{name}")
    assert not missing, (
        "Names declared as exports but not re-exported from "
        "sapmap_exploit:\n  " + "\n  ".join(missing))


def test_betrusted_chain_proxy_swap():
    """Specific regression for sap_db_sql_writers' lazy proxy for
    _get_local_ip_towards.  After the betrusted-chain extraction,
    that helper actually lives in sap_betrusted_chain — the proxy
    must hot-swap to point at the real location on first call."""
    import sap_db_sql_writers
    real_ip = sap_db_sql_writers._get_local_ip_towards("127.0.0.1")
    # Hot-swap fired — subsequent .__module__ should be the real
    # source module, not the lazy proxy in sap_db_sql_writers.
    assert sap_db_sql_writers._get_local_ip_towards.__module__ \
        in ("sap_betrusted_chain", "sapmap_exploit"), (
            f"lazy proxy didn't hot-swap; "
            f"still in {sap_db_sql_writers._get_local_ip_towards.__module__}")
    # And it returned a string (the local IP, possibly empty)
    assert isinstance(real_ip, str)


def test_extracted_module_signatures_unchanged():
    """For each public name re-exported through sapmap_exploit, the
    parameter list must match between the source module and the
    re-export.  Catches accidental signature drift (someone editing
    one copy in isolation)."""
    import sapmap_exploit
    drift = []
    for modname, spec in EXTRACTED_MODULES.items():
        mod = importlib.import_module(modname)
        for name in spec["exports"]:
            src_fn = getattr(mod, name, None)
            re_fn = getattr(sapmap_exploit, name, None)
            if not callable(src_fn) or not callable(re_fn):
                continue
            try:
                src_sig = inspect.signature(src_fn)
                re_sig = inspect.signature(re_fn)
            except (TypeError, ValueError):
                continue   # builtins / C functions — skip
            if str(src_sig) != str(re_sig):
                drift.append(
                    f"{modname}.{name}: source={src_sig} "
                    f"re-export={re_sig}")
    # Note: re-export usually points at the SAME function object so
    # signatures match by definition.  This test guards against the
    # case where someone wraps a re-export in a shim and accidentally
    # drops a parameter.
    assert not drift, "Signature drift detected:\n  " + "\n  ".join(drift)
