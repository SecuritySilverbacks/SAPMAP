"""Issue #85 PR5 — surfacing pass for the host-lock guardrail.

The guardrail landed in PR1 and grew through PR2 (in-process selection
loops), PR3 (auto-lock whitelist + pre-scan filter) and PR4 (cloud/relay
entity lock + visibility).  PR5 is the final pass: make the guardrail
visible everywhere a SAPMAP feature should be:

* **Scripting engine** — lock_host / unlock_host / lock_scc / unlock_scc
  / lock_btp_subaccount / unlock_btp_subaccount / lock_whitelist_add /
  lock_whitelist_remove are first-class actions.
* **MCP server** — list_locked / lock_host / unlock_host / lock_scc_host
  / unlock_scc_host / lock_btp_subaccount / unlock_btp_subaccount /
  lock_whitelist are exposed as tools.
* **README** — a dedicated scoping section describing the guardrail and
  pointing at every surface.
* **Engagement report** — a prose scoping section listing every locked
  entity (hosts, BTP subaccounts, whitelist rules, unlock audit log),
  in both Markdown and HTML.
* **CI-completeness invariant** — the SCC ``<host>`` and BTP ``<uuid>``
  surfaces now enforce the same "every route is explicitly classified"
  rule PR1 introduced for ``<sid>``, so a new SCC/BTP route can no
  longer silently skip the guard.

Each surface has a source-pin test (so a rename or deletion turns the
suite red) plus a semantic test (so the surface actually does what it
claims).
"""
from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path

import pytest

import modules  # noqa: F401  (registers subpackage paths)
from sapmap_models import SAPMAPState, SAPNode, SCCNode, BTPSubaccountNode
from sapmap_gui import SAPMAPApi, create_app
import sapmap_lock as L
import sapmap_report


# ---------------------------------------------------------------------------
# Scripting engine — every lock verb maps to the right HTTP endpoint
# ---------------------------------------------------------------------------

@pytest.fixture
def map_step():
    from sapmap_script import _map_step
    return _map_step


def test_script_lock_host_maps_to_node_lock(map_step):
    method, path, payload, _wait = map_step({
        "action": "lock_host", "target": "S4H",
        "reason": "customer PRD — out of scope",
        "by": "op1",
    })
    assert method == "POST"
    assert path == "/api/node/S4H/lock"
    assert payload == {"reason": "customer PRD — out of scope", "by": "op1"}


def test_script_unlock_host_maps_to_node_unlock(map_step):
    method, path, payload, _ = map_step({
        "action": "unlock_host", "target": "S4H",
        "reason": "cleared by lead", "by": "op2",
    })
    assert method == "POST"
    assert path == "/api/node/S4H/unlock"
    assert payload["reason"] == "cleared by lead"


def test_script_lock_scc_maps_to_scc_lock(map_step):
    method, path, payload, _ = map_step({
        "action": "lock_scc", "target": "scc01.lab",
        "reason": "third-party connector",
    })
    assert method == "POST"
    assert path == "/api/scc/scc01.lab/lock"
    assert payload["reason"] == "third-party connector"


def test_script_unlock_scc(map_step):
    method, path, _p, _ = map_step({
        "action": "unlock_scc", "target": "scc01.lab", "reason": "ok"})
    assert (method, path) == ("POST", "/api/scc/scc01.lab/unlock")


def test_script_lock_btp_subaccount_maps_to_uuid_lock(map_step):
    method, path, payload, _ = map_step({
        "action": "lock_btp_subaccount", "target": "uuid-abc-123",
        "reason": "cloud quarantine", "by": "op3",
    })
    assert method == "POST"
    assert path == "/api/btp/subaccount/uuid-abc-123/lock"
    assert payload == {"reason": "cloud quarantine", "by": "op3"}


def test_script_unlock_btp_subaccount(map_step):
    method, path, _p, _ = map_step({
        "action": "unlock_btp_subaccount", "target": "uuid-abc-123",
        "reason": "lifted"})
    assert (method, path) == (
        "POST", "/api/btp/subaccount/uuid-abc-123/unlock")


def test_script_lock_whitelist_add(map_step):
    """The whitelist stores a flat list of pattern strings (PR3) — the
    backend endpoint accepts just ``{pattern}``."""
    method, path, payload, _ = map_step({
        "action": "lock_whitelist_add",
        "pattern": "ec2.amazonaws.com",
    })
    assert method == "POST"
    assert path == "/api/lock_whitelist"
    assert payload == {"pattern": "ec2.amazonaws.com"}


def test_script_lock_whitelist_remove_uses_DELETE(map_step):
    method, path, payload, _ = map_step({
        "action": "lock_whitelist_remove",
        "pattern": "ec2.amazonaws.com",
    })
    assert method == "DELETE"
    assert path == "/api/lock_whitelist"
    assert payload == {"pattern": "ec2.amazonaws.com"}


def test_script_header_docstring_advertises_lock_verbs():
    """The scripting engine's header docstring is the on-disk catalog of
    supported actions.  Every new lock verb must appear in it so operator-
    discovery (grep + the demo-playbook comment pass) picks them up."""
    src = Path("modules/automation/sapmap_script.py").read_text()
    # Split off the header docstring (between the first and second triple-
    # double-quote).  Robust against reordering of actions below.
    header = src.split('"""', 2)[1]
    for verb in ("lock_host", "unlock_host",
                 "lock_scc", "unlock_scc",
                 "lock_btp_subaccount", "unlock_btp_subaccount",
                 "lock_whitelist_add", "lock_whitelist_remove"):
        assert verb in header, (
            f"scripting header docstring missing {verb!r} — add it so "
            "the catalog stays complete")


# ---------------------------------------------------------------------------
# MCP server — every lock tool is wired through FastMCP
# ---------------------------------------------------------------------------

def _mcp_tool_names() -> set:
    """Walk the AST of sapmap_mcp_server.py, collecting every function that
    is decorated with ``@mcp.tool()`` — more robust than importing the
    module (FastMCP needs the mcp Python package installed to construct the
    server)."""
    src = Path("modules/mcp/sapmap_mcp_server.py").read_text()
    tree = ast.parse(src)
    out = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            # @mcp.tool() → ast.Call(ast.Attribute)
            if (isinstance(dec, ast.Call)
                    and isinstance(dec.func, ast.Attribute)
                    and dec.func.attr == "tool"):
                out.add(node.name)
    return out


def test_mcp_exposes_every_lock_tool():
    """Source-pin + semantic: each lock verb must appear as a top-level
    function decorated with @mcp.tool() so FastMCP registers it."""
    names = _mcp_tool_names()
    for expected in ("list_locked",
                     "lock_host", "unlock_host",
                     "lock_scc_host", "unlock_scc_host",
                     "lock_btp_subaccount", "unlock_btp_subaccount",
                     "lock_whitelist"):
        assert expected in names, (
            f"MCP server missing @mcp.tool() for {expected!r}")


def test_mcp_lock_tools_route_to_correct_endpoints():
    """Each MCP lock tool must hit the matching HTTP endpoint on the
    SAPMAP server.  Grep the source for the URL template so a route
    typo (or an accidental rename) turns the suite red."""
    src = Path("modules/mcp/sapmap_mcp_server.py").read_text()
    # Each tool → the URL fragment it must post to.
    for fragment in ("/api/node/{sid}/lock",
                     "/api/node/{sid}/unlock",
                     "/api/scc/",             # lock_scc_host / unlock_scc_host
                     "/lock",
                     "/unlock",
                     "/api/btp/subaccount/",  # lock/unlock BTP
                     "/api/lock_whitelist"):
        assert fragment in src, (
            f"MCP source missing endpoint fragment {fragment!r}")


def test_mcp_lock_whitelist_action_switch():
    """The lock_whitelist tool dispatches on an ``action`` param (list /
    add / remove) — source-pin the three branches so the catalog stays
    discoverable and a rename breaks the test."""
    src = Path("modules/mcp/sapmap_mcp_server.py").read_text()
    # all three branches present as string equality tests
    assert 'if a == "list"' in src
    assert 'if a == "add"' in src
    assert 'if a == "remove"' in src


# ---------------------------------------------------------------------------
# Report narrative — markdown + HTML scoping section
# ---------------------------------------------------------------------------

def _locked_state() -> SAPMAPState:
    """Seed a state with every lock dimension populated: one manual host
    lock (with recorded by + timestamp) + one auto-locked host (via the
    shipped whitelist) + a whitelist rule + a manually-locked BTP
    subaccount + one unlock-log entry."""
    s = SAPMAPState()
    s.add_node(SAPNode(sid="SB1", ip="10.0.0.1", hostname="box01.lab"))
    s.scc_nodes["box01.lab"] = SCCNode(host="box01.lab", ip="10.0.0.1")
    s.btp_subaccounts["uuid-abc-123"] = BTPSubaccountNode(
        uuid="uuid-abc-123", region="eu10", subdomain="acme")
    # Manual host lock — attribution AND timestamp recorded.
    L.lock_node(s, s.nodes["SB1"], "customer PRD — out of scope",
                by="op-alice", now="2026-11-28T10:00:00Z")
    # Auto-locked host — exactly how apply_auto_lock would stamp the
    # record (whitelist_pattern + auto=True, blank locked_by).
    L.lock_host(s, "ec2-x.lab", "auto-locked (whitelist match: ec2.amazonaws.com)",
                auto=True, whitelist_pattern="ec2.amazonaws.com",
                now="2026-11-28T09:00:00Z")
    # Whitelist rule the operator added up front — the field stores plain
    # pattern strings (PR3).
    s.lock_whitelist = ["ec2.amazonaws.com"]
    # BTP subaccount locked by UUID (manual — BTP has no whitelist).
    L.lock_btp_subaccount(s, "uuid-abc-123", "cloud quarantine",
                          by="op-bob", now="2026-11-28T11:00:00Z")
    # A prior unlock entry (audit log's own key spelling — by/at, not
    # locked_by/locked_at — matches what unlock_host writes).
    s.unlock_log.append({
        "host": "old.lab", "reason": "finished",
        "by": "op-prior", "at": "2026-11-27T22:00:00Z",
    })
    return s


def test_markdown_lock_section_renders_every_dimension():
    s = _locked_state()
    md = sapmap_report.build_markdown_report(s, engagement_name="E1")
    # Section heading + narrative
    assert "## Scoping & the host-lock guardrail" in md
    assert "Zero contact numbers on a locked entity" in md
    # Each sub-table heading
    assert "### Locked hosts" in md
    assert "### Locked BTP subaccounts" in md
    assert "### Auto-lock whitelist rules" in md
    assert "### Unlock audit log" in md
    # The specific values show up
    assert "customer PRD — out of scope" in md
    assert "uuid-abc-123" in md
    assert "ec2.amazonaws.com" in md
    assert "old.lab" in md
    # Operator attribution + timestamps — these are the columns the
    # adversarial review caught silently rendering as em-dashes.
    assert "op-alice" in md
    assert "2026-11-28T10:00:00Z" in md
    assert "op-bob" in md
    assert "2026-11-28T11:00:00Z" in md
    assert "op-prior" in md
    assert "2026-11-27T22:00:00Z" in md
    # Both source states must appear (auto-lock for the whitelist-matched
    # host, manual for the operator-driven lock).
    assert "auto-lock" in md
    assert "manual" in md


def test_markdown_lock_section_shows_whitelist_pattern_inside_auto_reason():
    """An auto-locked host's row must carry the matched whitelist pattern
    inside the reason cell — PR3 writes ``whitelist_pattern`` on the
    record, and the report surface must advertise which pattern
    triggered the quarantine (otherwise the reviewer can't tell *why*
    the host was auto-locked)."""
    s = _locked_state()
    md = sapmap_report.build_markdown_report(s, engagement_name="E1")
    # The ec2-x.lab row must include the whitelist pattern (either in the
    # original reason or appended by the renderer).
    rows_with_host = [l for l in md.splitlines() if "ec2-x.lab" in l]
    assert rows_with_host, "ec2-x.lab row missing from markdown"
    assert any("ec2.amazonaws.com" in l for l in rows_with_host)


def test_markdown_lock_section_omitted_when_nothing_locked():
    s = SAPMAPState()
    s.add_node(SAPNode(sid="SB1", ip="10.0.0.1"))
    md = sapmap_report.build_markdown_report(s, engagement_name="E1")
    assert "## Scoping & the host-lock guardrail" not in md


def test_html_lock_section_renders():
    s = _locked_state()
    html = sapmap_report.build_html_report(s, engagement_name="E1")
    # Section anchor + heading
    assert 'id="sec-lock-guardrail"' in html
    assert "Scoping &amp; the host-lock guardrail" in html
    # Table-of-contents row got added for the section
    assert "#sec-lock-guardrail" in html
    # Key contents
    assert "customer PRD" in html
    assert "uuid-abc-123" in html
    assert "ec2.amazonaws.com" in html
    assert "old.lab" in html
    # Operator attribution + timestamps (same mis-key bug caught by the
    # adversarial review — had been silently rendering as em-dashes).
    assert "op-alice" in html
    assert "2026-11-28T10:00:00Z" in html
    assert "op-bob" in html
    assert "op-prior" in html
    # Both source states render.
    assert ">auto-lock<" in html
    assert ">manual<" in html


def test_html_lock_section_omitted_when_nothing_locked():
    s = SAPMAPState()
    s.add_node(SAPNode(sid="SB1", ip="10.0.0.1"))
    html = sapmap_report.build_html_report(s, engagement_name="E1")
    assert 'id="sec-lock-guardrail"' not in html
    # And the TOC entry is NOT present either (gated on the section
    # rendering).
    assert "#sec-lock-guardrail" not in html


def test_lock_section_direct_builder_contract():
    """_lock_section is also callable directly (diff / dashboard reuse)."""
    s = _locked_state()
    out = sapmap_report._lock_section(s)
    assert isinstance(out, list)
    assert out[0] == "## Scoping & the host-lock guardrail"
    # Empty state → empty list (no header, no narrative).
    assert sapmap_report._lock_section(SAPMAPState()) == []


def test_html_lock_section_empty_returns_empty_string():
    assert sapmap_report._html_lock_section(SAPMAPState()) == ""


# ---------------------------------------------------------------------------
# README — scoping section is advertised
# ---------------------------------------------------------------------------

def test_readme_describes_lock_guardrail():
    readme = Path("README.md").read_text()
    assert "## Scoping — the lock guardrail" in readme
    # Each surface named (so a future rename or deletion fails the test)
    for s in ("Manual locks", "Auto-lock whitelist",
              "Scripted scenarios", "MCP server",
              "lock_host", "unlock_host", "lock_whitelist_add"):
        assert s in readme, f"README missing {s!r}"
    # Wiki Lock-Guardrail link present
    assert "wiki/Lock-Guardrail" in readme


# ---------------------------------------------------------------------------
# CI-completeness invariant — SCC <host> and BTP <uuid> routes
# ---------------------------------------------------------------------------

def _app():
    return create_app(SAPMAPApi())


def _routes_matching(app, pattern: str):
    """{rule: set(methods)} for every registered route that contains
    ``pattern`` in its rule."""
    out = {}
    for r in app.routes:
        if pattern in r.rule:
            out.setdefault(r.rule, set()).add(r.method)
    return out


def test_every_scc_host_route_is_explicitly_classified():
    """PR5 completeness invariant for the SCC surface: every registered
    ``/api/scc/<host>/*`` route must be in SCC_ACTIVE_HOST_ROUTES or
    SCC_PASSIVE_HOST_ROUTES.  A new route that forgets ``_scc_locked_
    response`` therefore turns the suite red instead of silently
    leaking contact against a locked SCC."""
    app = _app()
    unreviewed = []
    for rule in _routes_matching(app, "/api/scc/<host>"):
        if not L.scc_host_route_is_reviewed(rule):
            unreviewed.append(rule)
    assert not unreviewed, (
        "un-classified /api/scc/<host>/... route(s) — classify in "
        "sapmap_lock.SCC_ACTIVE_HOST_ROUTES or SCC_PASSIVE_HOST_ROUTES:\n  "
        + "\n  ".join(sorted(unreviewed)))


def test_every_btp_subaccount_route_is_explicitly_classified():
    """Same invariant for the BTP surface, keyed on ``<uuid>``."""
    app = _app()
    unreviewed = []
    for rule in _routes_matching(app, "<uuid>"):
        if not L.btp_uuid_route_is_reviewed(rule):
            unreviewed.append(rule)
    assert not unreviewed, (
        "un-classified /api/btp/.../<uuid>... route(s) — classify in "
        "sapmap_lock.BTP_ACTIVE_UUID_ROUTES or BTP_PASSIVE_UUID_ROUTES:\n  "
        + "\n  ".join(sorted(unreviewed)))


def test_scc_classification_references_only_real_routes():
    app = _app()
    rules = {r.rule for r in app.routes}
    for name, s in (("SCC_ACTIVE_HOST_ROUTES", L.SCC_ACTIVE_HOST_ROUTES),
                    ("SCC_PASSIVE_HOST_ROUTES", L.SCC_PASSIVE_HOST_ROUTES)):
        stale = [r for r in s if r not in rules]
        assert not stale, f"{name} references unregistered routes: {stale}"


def test_btp_classification_references_only_real_routes():
    app = _app()
    rules = {r.rule for r in app.routes}
    for name, s in (("BTP_ACTIVE_UUID_ROUTES", L.BTP_ACTIVE_UUID_ROUTES),
                    ("BTP_PASSIVE_UUID_ROUTES", L.BTP_PASSIVE_UUID_ROUTES)):
        stale = [r for r in s if r not in rules]
        assert not stale, f"{name} references unregistered routes: {stale}"


_NEXT_ROUTE_RE = re.compile(r'^\s*@app\.route\(', re.MULTILINE)


def _handler_body(src: str, decorator: str) -> str:
    """Return the handler source between ``decorator`` and the NEXT
    ``@app.route(`` decorator (or EOF).  Using a hard-stop at the next
    decorator prevents a false positive where a route without its own
    guard passes because the NEXT route's guard happens to fall inside a
    fixed-size window."""
    idx = src.find(decorator)
    assert idx >= 0, f"route decorator not found in source: {decorator}"
    # Step past the decorator itself before scanning so we don't match it.
    scan_from = idx + len(decorator)
    m = _NEXT_ROUTE_RE.search(src, scan_from)
    end = m.start() if m else len(src)
    return src[idx:end]


def test_scc_active_routes_have_lock_guard_in_handler():
    """Every SCC route in SCC_ACTIVE_HOST_ROUTES must call
    ``_scc_locked_response`` in its OWN handler body (stopping at the
    next route decorator — so a neighbour's guard can't mask a missing
    one).  Enforces the in-handler guard contract PR4 introduced."""
    src = Path("modules/core/sapmap_gui.py").read_text()
    unguarded = []
    for rule in sorted(L.SCC_ACTIVE_HOST_ROUTES):
        body = _handler_body(src, f'@app.route("{rule}", method="POST")')
        if "_scc_locked_response" not in body:
            unguarded.append(rule)
    assert not unguarded, (
        "SCC_ACTIVE_HOST_ROUTES route(s) missing in-handler "
        "_scc_locked_response guard: " + ", ".join(unguarded))


def test_btp_active_routes_have_uuid_guard_in_handler():
    """Every BTP route in BTP_ACTIVE_UUID_ROUTES must consult
    ``is_btp_subaccount_locked`` in its OWN handler body."""
    src = Path("modules/core/sapmap_gui.py").read_text()
    unguarded = []
    for rule in sorted(L.BTP_ACTIVE_UUID_ROUTES):
        body = _handler_body(src, f'@app.route("{rule}", method="POST")')
        if "is_btp_subaccount_locked" not in body:
            unguarded.append(rule)
    assert not unguarded, (
        "BTP_ACTIVE_UUID_ROUTES route(s) missing in-handler "
        "is_btp_subaccount_locked guard: " + ", ".join(unguarded))


# ---------------------------------------------------------------------------
# Feature-surfacing matrix — every PR5 surface actually lands
# ---------------------------------------------------------------------------

def test_feature_surfacing_matrix_is_complete():
    """One rollup test that proves the lock guardrail is visible on every
    surface the project's feature-surfacing checklist covers (scripting,
    MCP, README, report, wiki link).  The matrix is the invariant; the
    pointers are data."""
    script_src = Path("modules/automation/sapmap_script.py").read_text()
    mcp_src = Path("modules/mcp/sapmap_mcp_server.py").read_text()
    readme = Path("README.md").read_text()
    matrix = {
        "scripting-lock_host":   'action == "lock_host"' in script_src,
        "scripting-unlock_host": 'action == "unlock_host"' in script_src,
        "scripting-lock_scc":    'action == "lock_scc"' in script_src,
        "scripting-lock_btp":    'action == "lock_btp_subaccount"' in script_src,
        "scripting-whitelist":   'action == "lock_whitelist_add"' in script_src,
        "mcp-list_locked":       "def list_locked(" in mcp_src,
        "mcp-lock_host":         "def lock_host(" in mcp_src,
        "mcp-lock_scc":          "def lock_scc_host(" in mcp_src,
        "mcp-lock_btp":          "def lock_btp_subaccount(" in mcp_src,
        "mcp-lock_whitelist":    "def lock_whitelist(" in mcp_src,
        "readme-section":        "## Scoping — the lock guardrail" in readme,
        "readme-wiki-link":      "wiki/Lock-Guardrail" in readme,
        "report-markdown":       hasattr(sapmap_report, "_lock_section"),
        "report-html":           hasattr(sapmap_report, "_html_lock_section"),
    }
    missing = [k for k, ok in matrix.items() if not ok]
    assert not missing, (
        "feature-surfacing matrix incomplete — missing: "
        + ", ".join(missing))
