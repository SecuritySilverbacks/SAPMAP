#!/usr/bin/env python3
"""Issue #232 — GUI/autopwn parity for the GW SAPXPG ncpic_lu source IP.

#231 fixed the SAProuter/NAT ``ncpic_lu`` mismatch for the standalone script
(``--source-ip``).  #232 brings the same pin to the GUI / autopwn exploit path
via a *dedicated* per-node ``gw_source_ip`` field — deliberately SEPARATE from
``attacker_ip_override`` (the 10KBLAZE MS-betrusted TCP-source trust list),
whose remediation points at the LOCAL socket IP, the opposite of what
``ncpic_lu`` needs through a router.

These tests pin:
  * the ``gw_source_ip`` model field (default / roundtrip / old-file tolerance /
    independence from ``attacker_ip_override``),
  * the ``resolve_ncpic_source_ip`` ``override_hint`` plumbing (GUI callers must
    be told about the menu, NOT the ``--source-ip`` CLI flag),
  * that a pinned ``gw_source_ip`` reaches the on-the-wire F_SAP_INIT ncpic_lu,
  * the ``set_gw_source_ip`` / ``get_gw_source_ip`` routes (registration,
    WRITE_ROUTES membership, IPv4 validation, routed warning, and that the
    route never touches ``attacker_ip_override``),
  * the exploit-path threading (both build_p2 sites pin the resolved IP; the
    p2_timeout verdict carries a SAProuter qualifier),
  * the HTML surface (ctx-item, modal, handlers, create_user_gw-style gating).

Documentation-range IPs only (RFC 5737) — no lab addresses.
"""
import ast
import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sap_gw_xpg_standalone import (  # noqa: E402
    build_p2,
    pad_right_null,
    resolve_ncpic_source_ip,
)
# Import sapmap_exploit BEFORE sap_db_sql_writers: the two have a known
# order-sensitive circular import (writers do `from sapmap_exploit import
# _gw_connect` at top, sapmap_exploit imports the writers at the bottom after
# _gw_connect is defined).  Importing the exploit module first initializes the
# graph in the production order so a later `import sap_db_sql_writers` is safe.
import sapmap_exploit  # noqa: E402,F401
from sapmap_models import SAPNode  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
_GUI_HINT = 'the per-node "Set GW Source IP (SAProuter/NAT)" menu'
_ROUTE = "/H/198.51.100.7/S/3299"   # a SAProuter route string (doc-range)


def _ncpic_lu_field(local_ip):
    """The 8-byte ncpic_lu field build_p2 stamps for a source IP
    (dots -> hyphens, first 7 chars, NUL-padded to 8 — see build_p2)."""
    lu = (local_ip or "").replace(".", "-")[:7]
    return pad_right_null(lu, 8)


# ---------------------------------------------------------------------------
# Model — gw_source_ip field
# ---------------------------------------------------------------------------

def test_gw_source_ip_defaults_empty():
    n = SAPNode(sid="S4H")
    assert n.gw_source_ip == ""
    assert n.to_dict()["gw_source_ip"] == ""


def test_gw_source_ip_roundtrips():
    n = SAPNode(sid="S4H", ip="10.0.0.1")
    n.gw_source_ip = "203.0.113.9"
    restored = SAPNode.from_dict(n.to_dict())
    assert restored.gw_source_ip == "203.0.113.9"


def test_gw_source_ip_from_dict_tolerates_missing_key():
    # .sapmap files written before #232 have no gw_source_ip key.
    n = SAPNode.from_dict({"sid": "S4H"})
    assert n.gw_source_ip == ""


def test_gw_source_ip_is_independent_of_attacker_ip_override():
    """The whole point of #232: the two NAT knobs must not bleed into each
    other.  Setting the GW source IP must leave attacker_ip_override empty."""
    n = SAPNode(sid="S4H")
    n.gw_source_ip = "203.0.113.9"
    assert n.attacker_ip_override == ""
    d = n.to_dict()
    assert d["gw_source_ip"] == "203.0.113.9"
    assert d["attacker_ip_override"] == ""


# ---------------------------------------------------------------------------
# resolve_ncpic_source_ip — override_hint plumbing
# ---------------------------------------------------------------------------

def test_default_override_hint_is_standalone_flag():
    """Unchanged default keeps the standalone (#231) behaviour + tests green."""
    _, warn = resolve_ncpic_source_ip("", "10.0.0.5", routed=True)
    assert "--source-ip" in warn
    assert "#79" in warn


def test_routed_without_pin_warns_with_gui_hint():
    node = SAPNode(sid="S4H", ip="10.0.0.1", saprouter=_ROUTE)
    src, warn = resolve_ncpic_source_ip(
        getattr(node, "gw_source_ip", ""), "10.0.0.5",
        routed=bool(node.saprouter), override_hint=_GUI_HINT)
    assert src == "10.0.0.5"                 # still usable, direct-connect semantics
    assert warn                              # but operator is told it's likely wrong
    assert "Set GW Source IP" in warn
    assert "--source-ip" not in warn         # GUI must NOT be sent to a CLI flag
    assert "#79" in warn


def test_non_ascii_pin_rejected_with_gui_hint():
    src, warn = resolve_ncpic_source_ip(
        "høst", "10.0.0.5", routed=True, override_hint=_GUI_HINT)
    assert src == "10.0.0.5"
    assert "ignored" in warn.lower()
    assert "Set GW Source IP" in warn


def test_direct_connect_no_pin_is_silent():
    node = SAPNode(sid="S4H", ip="10.0.0.1")   # no saprouter
    src, warn = resolve_ncpic_source_ip(
        getattr(node, "gw_source_ip", ""), "10.0.0.5",
        routed=bool(node.saprouter), override_hint=_GUI_HINT)
    assert src == "10.0.0.5"
    assert warn == ""


# ---------------------------------------------------------------------------
# The pinned gw_source_ip reaches the on-the-wire F_SAP_INIT ncpic_lu
# ---------------------------------------------------------------------------

def test_pinned_gw_source_ip_reaches_ncpic_lu():
    node = SAPNode(sid="S4H", ip="10.0.0.1", saprouter=_ROUTE)
    node.gw_source_ip = "203.0.113.9"
    src, warn = resolve_ncpic_source_ip(
        node.gw_source_ip, "10.0.0.5",
        routed=bool(node.saprouter), override_hint=_GUI_HINT)
    assert src == "203.0.113.9"
    assert warn == ""
    p2 = build_p2(node.ip, local_ip=src, target_hostname="gwhost")
    assert len(p2) == 452
    assert _ncpic_lu_field("203.0.113.9") in p2     # the pinned IP landed...
    assert _ncpic_lu_field("10.0.0.5") not in p2     # ...and replaced the auto value


# ---------------------------------------------------------------------------
# GUI routes — source-contract pins (mirrors test_10kblaze_nat_probe.py)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def gui_src() -> str:
    return (REPO_ROOT / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")


def _route_body(src: str, decorator: str) -> str:
    idx = src.find(decorator)
    assert idx != -1, f"route not found: {decorator}"
    end = src.find("@app.route(", idx + 1)
    return src[idx:end]


def test_set_gw_source_ip_route_registered(gui_src: str):
    assert ('@app.route("/api/node/<sid>/set_gw_source_ip", method="POST")'
            in gui_src)
    assert "def node_set_gw_source_ip(sid):" in gui_src


def test_get_gw_source_ip_route_registered(gui_src: str):
    assert '@app.route("/api/node/<sid>/get_gw_source_ip")' in gui_src
    assert "def node_get_gw_source_ip(sid):" in gui_src


def test_set_gw_source_ip_in_write_routes(gui_src: str):
    """POST persists on the node → must be refused in --read-only mode."""
    m = re.search(r"WRITE_ROUTES = frozenset\(\{(.*?)\}\)", gui_src, re.DOTALL)
    assert m
    assert '"/api/node/<sid>/set_gw_source_ip"' in m.group(1)


def test_set_gw_source_ip_route_persists_and_validates(gui_src: str):
    body = _route_body(
        gui_src, '@app.route("/api/node/<sid>/set_gw_source_ip", method="POST")')
    assert "node.gw_source_ip = raw_ip" in body
    assert '"error": "bad_gw_source_ip"' in body
    assert "0 <= int(p) <= 255" in body
    # routed-without-pin warning on a clearing save
    assert "node.saprouter" in body
    assert "routed_warning" in body


def test_set_gw_source_ip_route_stays_separate_from_attacker_override(gui_src: str):
    body = _route_body(
        gui_src, '@app.route("/api/node/<sid>/set_gw_source_ip", method="POST")')
    assert "attacker_ip_override" not in body
    assert "attacker_ip_force" not in body


# ---------------------------------------------------------------------------
# Exploit path — both build_p2 sites pin the resolved IP; p2_timeout qualifier
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def exploit_src() -> str:
    return (REPO_ROOT / "modules" / "exploitation" / "sapmap_exploit.py").read_text(
        encoding="utf-8")


def test_exploit_imports_resolver(exploit_src: str):
    assert "resolve_ncpic_source_ip" in exploit_src


def test_both_build_p2_sites_use_resolved_src(exploit_src: str):
    # Both GW SAPXPG P2 builds pin via the resolved _gw_src, not the inline
    # auto IP (which is wrong through a SAProuter).
    assert exploit_src.count("local_ip=_gw_src") == 2
    assert "local_ip=_get_local_ip_towards(host) or host" not in exploit_src


def test_exploit_resolves_with_gw_source_ip_and_saprouter(exploit_src: str):
    assert 'getattr(node, "gw_source_ip", "")' in exploit_src
    assert "routed=bool(node.saprouter)" in exploit_src


def test_p2_timeout_verdict_has_saprouter_qualifier(exploit_src: str):
    idx = exploit_src.find("silently dropped by reginfo")
    assert idx != -1
    window = exploit_src[idx:idx + 1400]
    assert "ncpic_lu mismatch" in window
    assert "Set GW Source" in window


# ---------------------------------------------------------------------------
# HTML surface — contract pins
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def html_src() -> str:
    return (REPO_ROOT / "modules" / "core" / "sapmap_html.py").read_text(
        encoding="utf-8")


def test_html_has_gw_source_ip_ctx_item(html_src: str):
    assert 'data-action="set_gw_source_ip"' in html_src


def test_html_has_gw_source_ip_modal(html_src: str):
    assert 'id="set-gw-source-ip-modal"' in html_src
    assert 'id="set-gw-source-ip-value"' in html_src


def test_html_gw_source_ip_handlers_defined(html_src: str):
    assert "function showSetGwSourceIpModal(" in html_src
    assert "function saveSetGwSourceIp(" in html_src
    assert "case 'set_gw_source_ip':" in html_src


def test_html_gw_source_ip_posts_to_route(html_src: str):
    assert "node/${sid}/set_gw_source_ip" in html_src
    assert "node/${sid}/get_gw_source_ip" in html_src


def test_html_gw_source_ip_gated_like_create_user_gw(html_src: str):
    # Visible wherever GW SAPXPG is usable; hidden on SAProuter/WebDispatcher.
    m = re.search(r"'set_gw_source_ip':\s*isSaprouter \|\| isWebDispatcher",
                   html_src)
    assert m


# ---------------------------------------------------------------------------
# DB-backed GW SAPXPG writers honour the pin too (adversarial-review finding):
# the gw_source_ip menu is gated like create_user_gw, which dispatches to these
# DB writers — so a routed DB-backed create must NOT silently ignore the pin.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def dbwriter_src() -> str:
    return (REPO_ROOT / "modules" / "exploitation" / "sap_db_sql_writers.py").read_text(
        encoding="utf-8")


def test_dbwriters_route_all_build_p2_through_override_helper(dbwriter_src: str):
    # Every build_p2 ncpic source must go through the override-aware helper,
    # not inline auto-detect — else routed DB-backed runs reproduce #79.
    assert dbwriter_src.count("local_ip=_ncpic_local_ip(host)") == 7
    assert "local_ip=_get_local_ip_towards(host) or host" not in dbwriter_src


def test_dbwriter_entrypoints_accept_and_publish_source_ip(dbwriter_src: str):
    for fn in ("_oracle_write_and_exec_win", "_mssql_write_and_exec_win",
               "_execute_sql_via_gateway"):
        idx = dbwriter_src.find(f"def {fn}(")
        assert idx != -1, fn
        sig_end = dbwriter_src.find("):", idx)
        assert "source_ip" in dbwriter_src[idx:sig_end], fn
    # Each entrypoint publishes the pin to the thread before dispatching.
    # 3 DB-writer entrypoints + _probe_python3_via_gw's own conditional
    # publish (issue #237) = 4 call sites (exclude the single
    # `def _set_gw_source_ip(...)` line).
    calls = (dbwriter_src.count("_set_gw_source_ip(source_ip)")
             - dbwriter_src.count("def _set_gw_source_ip(source_ip)"))
    assert calls == 4


def test_exploit_threads_source_ip_into_db_writers(exploit_src: str):
    assert exploit_src.count("source_ip=_gw_src_pin") == 3


def test_ncpic_local_ip_honours_and_clears_override():
    import sap_db_sql_writers as db
    try:
        db._set_gw_source_ip("203.0.113.9")
        assert db._ncpic_local_ip("10.0.0.1") == "203.0.113.9"
        # Non-ASCII override cannot form a CPIC LU name → fall back to auto.
        db._set_gw_source_ip("høst")
        assert db._ncpic_local_ip("10.0.0.1") != "høst"
        # Cleared → must not return the stale pin from earlier in the thread.
        db._set_gw_source_ip("")
        assert db._ncpic_local_ip("10.0.0.1") != "203.0.113.9"
    finally:
        db._set_gw_source_ip("")


def test_dbwriter_entrypoints_are_scope_guarded(dbwriter_src: str):
    # The 3 DB-writer entrypoints + _probe_python3_via_gw (issue #237) all
    # carry the scope guard that restores the pin on exit.
    assert dbwriter_src.count("@_scoped_gw_source_ip") == 4


def test_scoped_gw_source_ip_restores_prior_value_no_stale_leak():
    """Regression for the adversarial-review finding: a pin set inside a
    scope-guarded entrypoint must NOT survive the call, or a later DIRECT
    (non-entrypoint) probe on the same long-lived thread (--script / MCP)
    reads one host's router IP as another host's ncpic_lu."""
    import sap_db_sql_writers as db
    try:
        db._set_gw_source_ip("")   # baseline clean thread state

        @db._scoped_gw_source_ip
        def _fake_entrypoint(source_ip=""):
            db._set_gw_source_ip(source_ip)        # entrypoints publish at top
            return db._ncpic_local_ip("10.0.0.1")  # nested build_p2 reads it

        inside = _fake_entrypoint(source_ip="203.0.113.9")
        assert inside == "203.0.113.9"                      # honored during call
        # After return a direct probe must see the restored (empty) context,
        # NOT the stale pin.
        assert getattr(db._gw_src_ctx, "source_ip", "") == ""
        assert db._ncpic_local_ip("192.0.2.50") != "203.0.113.9"
    finally:
        db._set_gw_source_ip("")
