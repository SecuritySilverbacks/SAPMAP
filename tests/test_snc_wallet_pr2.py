"""Issue #137 PR2 — looted-PSE SNC client identity, surfacing layer.

PR1 added the connection-layer (model + path chooser + probe).  PR2
surfaces it across every operator path: the forge chain auto-populates
the wallet, backend routes read/activate/clear it, the Configure SNC
modal and a node ctx-menu item drive the switch, a scripting verb /
MCP tool do the same without the GUI, and the engagement report
renders a 'SNC client identity' section.  These tests pin every one
of those seams so the feature isn't silently un-surfaced by a later
refactor.
"""
import json
import pathlib
import re

import pytest

import modules  # noqa: F401 — registers subpackage paths

from sapmap_models import (SAPMAPState, SNCCredential, SAPNode,
                            TrustRelation)
import sapmap_rfc


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


# ===========================================================================
# Model — reach helper (new on PR2)
# ===========================================================================

def test_reach_helper_dedup_and_excludes_source():
    st = SAPMAPState()
    st.trust_relations = [
        TrustRelation(trusting_sid="QAS", issuer_sid="DEV"),
        TrustRelation(trusting_sid="QAS", issuer_sid="DEV"),  # dup
        TrustRelation(trusting_sid="PRD", issuer_sid="DEV"),
        TrustRelation(trusting_sid="DEV", issuer_sid="DEV"),  # self — excluded
        TrustRelation(trusting_sid="PRD", issuer_sid="OTHER"),  # unrelated
        # Empty-issuer_sid row: cross-landscape trust records can land
        # with only the issuer DN known, so issuer_sid="".  A mutation
        # that broadened the match (e.g. `issuer_sid == src or not
        # issuer_sid`) would make such rows match EVERY looted identity
        # and silently inflate every wallet entry's reach — pin that it
        # doesn't.
        TrustRelation(trusting_sid="GHOST", issuer_sid=""),
    ]
    # Dedup + sort + no self + no cross-issuer + no empty-issuer bleed
    assert st.reach_targets_for_snc_identity("DEV") == ["PRD", "QAS"]
    # Empty / unknown source -> []
    assert st.reach_targets_for_snc_identity("") == []
    assert st.reach_targets_for_snc_identity("NOPE") == []
    # Case-sensitive: trust rows use SIDs verbatim
    assert st.reach_targets_for_snc_identity("dev") == []


# ===========================================================================
# Forge-chain populate — the one hook that makes the wallet usable
# ===========================================================================

def test_forge_chain_registers_snc_credential_block():
    """The forge chain's wallet-seed block is what makes the wallet
    anything but a dead model.  This pin asserts the hook still:
      * runs inside ``extract_and_forge_ticket`` (NOT at file scope — a
        helper function the forge never calls would be dead code and a
        file-wide grep would wrongly accept it),
      * uses the looted PSE loot_path + signer_dn,
      * constructs SNCCredential with source_sid=node.sid, pse_path
        pointing at <loot>/SAPSYS.pse, snc_identity='p:<signer_dn>',
      * calls state.add_snc_credential() so the GUI/report can see it,
      * is guarded (save_loot and signer_dn truthy) so it never
        crashes when the forge ran without disk persistence.
    Negative pin so a refactor can't silently de-populate the wallet.
    """
    import inspect
    import sapmap_exploit
    # Function-scope the grep: the populate block MUST live inside
    # extract_and_forge_ticket's body.  A file-wide grep would wrongly
    # pass if a refactor moved the block into a helper the forge never
    # calls (dead code).
    fn_src = inspect.getsource(sapmap_exploit.extract_and_forge_ticket)
    assert "state.add_snc_credential(" in fn_src, (
        "forge chain no longer seeds the SNC wallet — PR2 populate path "
        "has regressed; the feature becomes inert without it")
    # Use the right inputs
    assert "source_sid=node.sid" in fn_src
    assert 'snc_identity=f"p:{signer_dn}"' in fn_src
    # Guarded — never run when the forge ran with save_loot=False
    assert 'if (save_loot and pse_loot_dir and bundle.get("pse_bytes")' in fn_src
    assert "and signer_dn)" in fn_src
    # pse_path is built from the loot dir
    assert '_os_snc.path.join(pse_loot_dir, "SAPSYS.pse")' in fn_src


def test_forge_chain_populate_has_isfile_guard_against_dead_pse_path():
    """A failed save_to_loot still returns a loot_path (with "saved":False),
    and the caller sets bundle.loot_path from it without checking.  The
    populate hook must verify SAPSYS.pse actually landed on disk before
    adding to the wallet — otherwise the wallet holds a dead pse_path and
    the key-type probe silently routes every connect to cryptolib."""
    src = (REPO_ROOT / "modules" / "exploitation" / "sapmap_exploit.py"
           ).read_text(encoding="utf-8")
    # The guard IS present and raises (so the surrounding try/except logs
    # the skip rather than quietly seeding garbage)
    assert "if not _os_snc.path.isfile(_pse_file):" in src
    assert 'raise FileNotFoundError' in src


def test_forge_chain_reforge_disambiguates_no_overwrite():
    """Forge chain re-runs mint a new <SID>_<ts>/SAPSYS.pse every time.
    add_snc_credential sees a different pse_path -> #N suffix instead of
    overwriting the first entry.  Pins the dup-safety contract between
    the forge populate path and the model-level disambiguator."""
    st = SAPMAPState()
    a = st.add_snc_credential(SNCCredential(
        source_sid="S4H", pse_path="/loot/pse/S4H_20261111_120000/SAPSYS.pse",
        snc_identity="p:CN=S4H", pin=""))
    b = st.add_snc_credential(SNCCredential(
        source_sid="S4H", pse_path="/loot/pse/S4H_20261111_130000/SAPSYS.pse",
        snc_identity="p:CN=S4H", pin=""))
    assert a.cred_id == "S4H:SAPSYS"
    assert b.cred_id == "S4H:SAPSYS#2"
    assert len(st.snc_credentials) == 2    # neither is lost


def test_forge_chain_populate_builds_credential_matching_wallet_shape():
    """A programmatic rehearsal of the forge's populate block: given the
    same inputs (bundle.loot_path + signer_dn), the produced
    SNCCredential round-trips and lives on the wallet at the expected
    cred_id."""
    import tempfile
    from datetime import datetime
    with tempfile.TemporaryDirectory() as td:
        pse = pathlib.Path(td) / "SAPSYS.pse"
        pse.write_bytes(b"\x30\x00stub")
        cred_v2 = pathlib.Path(td) / "cred_v2"
        cred_v2.write_bytes(b"stub")
        st = SAPMAPState()
        # Replay the block's body with concrete values
        c = SNCCredential(
            source_sid="S4H",
            pse_path=str(pse),
            cred_v2_path=str(cred_v2),
            pin="",
            snc_identity="p:CN=S4H, O=SAP, C=DE",
            source_label="192.168.2.209",
            looted_at=datetime(2026, 11, 11, 12, 0, 0).isoformat(),
        )
        st.add_snc_credential(c)
        assert "S4H:SAPSYS" in st.snc_credentials
        got = st.snc_credentials["S4H:SAPSYS"]
        assert got.pse_path == str(pse)
        assert got.cred_v2_path == str(cred_v2)
        assert got.snc_identity == "p:CN=S4H, O=SAP, C=DE"


# ===========================================================================
# Backend routes — source-level pins + state-shape semantics
# ===========================================================================

def test_gui_source_declares_wallet_routes_and_pin_mask():
    src = (REPO_ROOT / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")
    # The three route decorators live in the SNC cluster
    assert '@app.route("/api/snc/wallet", method="GET")' in src
    assert '@app.route("/api/snc/wallet/activate", method="POST")' in src
    assert '@app.route("/api/snc/wallet/clear", method="POST")' in src
    # The listing drops PIN before leaving the backend
    assert 'd.pop("pin", None)' in src
    # Activate mirrors into sapmap_rfc (otherwise the identity doesn't
    # reach the connection layer — silent no-op bug waiting to happen)
    assert "set_active_snc_credential(cred_id)" in src
    assert "_mirror_snc_config(api.state)" in src
    # Clear uses the model helper with "" (reverts to operator posture)
    assert 'set_active_snc_credential("")' in src
    # /api/snc/status leaks the new active fields (so the modal can render)
    assert '"active_snc_cred_id"' in src
    assert '"active_snc_credential"' in src
    assert '"active_snc_path"' in src
    assert '"active_snc_reach"' in src


def test_get_state_dict_strips_pin_for_frontend():
    """The polling payload DROPS the PIN key entirely (same shape as the
    /api/snc/wallet GET route, so any future consumer sees one consistent
    convention).  The on-disk .sapmap round-trip (via state.to_dict)
    retains the real PIN — the mask is a frontend-only concern.
    """
    from sapmap_gui import SAPMAPApi
    api = SAPMAPApi()
    api.state.add_snc_credential(SNCCredential(
        source_sid="S4H", pse_path="/loot/SAPSYS.pse",
        snc_identity="p:CN=S4H", pin="SHHHSECRET"))
    d = api.get_state_dict()
    wallet = d.get("snc_credentials", {})
    assert "S4H:SAPSYS" in wallet
    # pin key dropped in the frontend view (not just masked to "***") —
    # a mask to "" or "***" is easy to miss; dropping the key makes
    # downstream `"pin" in cred` consistent with /api/snc/wallet.
    assert "pin" not in wallet["S4H:SAPSYS"]
    # And the secret value never appears anywhere in the frontend dict.
    assert "SHHHSECRET" not in json.dumps(d)
    # Other fields survive (we didn't accidentally strip more than pin).
    assert wallet["S4H:SAPSYS"]["source_sid"] == "S4H"
    assert wallet["S4H:SAPSYS"]["pse_path"] == "/loot/SAPSYS.pse"
    # The on-disk view is unchanged — state.to_dict still carries it.
    raw = api.state.to_dict()
    assert raw["snc_credentials"]["S4H:SAPSYS"]["pin"] == "SHHHSECRET"


def test_activate_resolves_source_sid_and_errors_on_ambiguity():
    """The route's source_sid→cred_id resolver: unique match wins,
    ambiguous input fails cleanly (not a silent wrong pick)."""
    src = (REPO_ROOT / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")
    # The resolver block lives in the activate route
    assert 'matches = [cid for cid, c' in src
    assert "if len(matches) == 1:" in src
    assert "ambiguous: source_sid" in src
    assert "no looted PSE for source_sid" in src


# ===========================================================================
# HTML — ctx-menu, gate, dispatcher, modal, JS
# ===========================================================================

def test_html_ctxmenu_item_and_gate_present():
    """Pins the ctx-menu item + its gating.  Whitespace-tolerant regex
    so cosmetic realignment of the big rules/hidden tables (which runs
    every time an unrelated item is added above) doesn't false-fail
    this.  Ordinary pattern across the rest of the HTML-pin tests."""
    html = (REPO_ROOT / "modules" / "core" / "sapmap_html.py").read_text(
        encoding="utf-8")
    # Menu item exists in the Settings group near set_snc_name
    assert 'data-action="use_pse_as_snc"' in html
    # Capability computed from the wallet (source_sid match) —
    # authoritative (the wallet IS the thing activate reads).
    assert re.search(r"walletCredForNode\s*=.*mapState\.snc_credentials", html)
    assert re.search(r"hasLootedPseInWallet\s*=\s*!!walletCredForNode", html)
    # Rules table: item ENABLED iff this node has a wallet entry.
    assert re.search(r"'use_pse_as_snc'\s*:\s*hasLootedPseInWallet\s*,",
                     html)
    # Hidden table: item HIDDEN when NOT applicable (so we don't show a
    # disabled ghost entry on every node).
    assert re.search(r"'use_pse_as_snc'\s*:\s*!hasLootedPseInWallet\s*,",
                     html)
    # Dispatcher case wires to the per-node activator.
    assert re.search(
        r"case\s+'use_pse_as_snc'\s*:\s*useLootedPseAsSncIdentity\(sid\)\s*;\s*break",
        html)


def test_html_configure_snc_modal_has_active_identity_block():
    html = (REPO_ROOT / "modules" / "core" / "sapmap_html.py").read_text(
        encoding="utf-8")
    # The three new rendering/switcher IDs
    for anchor in ("snc-active-identity-block", "snc-active-identity",
                   "snc-active-path", "snc-active-reach-row",
                   "snc-active-reach", "snc-wallet-select"):
        assert f'id="{anchor}"' in html, f"missing #{anchor} in modal"
    # Buttons wire to the new JS fns
    assert "activateSelectedSncWalletEntry()" in html
    assert "clearActiveSncIdentity()" in html


def test_html_defines_wallet_js_helpers():
    html = (REPO_ROOT / "modules" / "core" / "sapmap_html.py").read_text(
        encoding="utf-8")
    for fn in ("function renderActiveSncIdentity",
               "function populateSncWalletSelect",
               "function activateSelectedSncWalletEntry",
               "function clearActiveSncIdentity",
               "function useLootedPseAsSncIdentity"):
        assert fn in html, f"missing JS helper: {fn}"
    # The ctx-menu action calls the per-node activator
    assert "useLootedPseAsSncIdentity(sid)" in html
    # The reach row carries the "trust-graph hint, not an SNC ACL" caveat
    assert "trust-graph hint" in html


# ===========================================================================
# Scripting verb
# ===========================================================================

def test_scripting_verb_maps_to_activate_route():
    from sapmap_script import (_map_step, _ACTION_LABELS,
                                DESTRUCTIVE_ACTIONS)
    # cred_id form (canonical)
    m, p, b, wait = _map_step({"action": "set_snc_identity",
                               "cred_id": "S4H:SAPSYS"})
    assert (m, p, wait) == ("POST", "/api/snc/wallet/activate", False)
    assert b == {"cred_id": "S4H:SAPSYS", "source_sid": ""}
    # source_sid form (convenience); uppercased + stripped
    _, _, b2, _ = _map_step({"action": "set_snc_identity",
                             "source_sid": "  s4h "})
    assert b2 == {"cred_id": "", "source_sid": "S4H"}
    # Empty payload = revert to operator posture
    _, _, b3, _ = _map_step({"action": "set_snc_identity"})
    assert b3 == {"cred_id": "", "source_sid": ""}
    # Both cred_id and source_sid set: mapper forwards both verbatim;
    # the backend's resolver uses cred_id first and ignores source_sid
    # when cred_id is non-empty.  Pin the contract so a mutation that
    # silently drops one in the mapper is caught.
    _, _, b4, _ = _map_step({"action": "set_snc_identity",
                             "cred_id": "A:B", "source_sid": "  x "})
    assert b4 == {"cred_id": "A:B", "source_sid": "X"}
    # NOT destructive — identity selection opens no socket
    assert "set_snc_identity" not in DESTRUCTIVE_ACTIONS
    # Human label is registered so GUI step toasts have a nice name
    assert "set_snc_identity" in _ACTION_LABELS
    assert "SNC" in _ACTION_LABELS["set_snc_identity"]


def test_scripting_supported_actions_catalogue_lists_verb():
    """The module docstring lists it under the SNC-identity bucket so
    the self-documenting catalogue stays in sync."""
    src = (REPO_ROOT / "modules" / "automation" / "sapmap_script.py"
           ).read_text(encoding="utf-8")
    assert "set_snc_identity," in src
    assert "issue #137" in src


# ===========================================================================
# MCP tools
# ===========================================================================

def test_mcp_tools_registered_and_route_to_wallet_endpoints(monkeypatch):
    import sapmap_mcp_server as m
    # Capture every _api call the tools make
    monkeypatch.setattr(m, "_api",
                         lambda method, path, payload=None: {
                             "method": method, "path": path,
                             "payload": payload})
    # Capture the recorded call per tool
    out_list = json.loads(m.list_snc_identities())
    assert out_list == {"method": "GET", "path": "/api/snc/wallet",
                        "payload": None}
    out_set = json.loads(m.set_snc_identity(cred_id="S4H:SAPSYS"))
    assert out_set["path"] == "/api/snc/wallet/activate"
    assert out_set["payload"] == {"cred_id": "S4H:SAPSYS",
                                   "source_sid": ""}
    out_set2 = json.loads(m.set_snc_identity(source_sid="s4h"))
    assert out_set2["payload"] == {"cred_id": "", "source_sid": "S4H"}
    out_clear = json.loads(m.clear_snc_identity())
    assert out_clear == {"method": "POST",
                         "path": "/api/snc/wallet/clear", "payload": None}


def test_mcp_tools_decorated_for_registration():
    """Pin the @mcp.tool() decorator above each tool fn — without it the
    functions are still callable (so a decorator-less mutation would
    pass the _api-monkeypatched test above), but they vanish from the
    MCP client-visible surface.  Source-level pin covers the gap."""
    src = (REPO_ROOT / "modules" / "mcp" / "sapmap_mcp_server.py"
           ).read_text(encoding="utf-8")
    for fn in ("list_snc_identities", "set_snc_identity",
               "clear_snc_identity"):
        # A @mcp.tool() line IMMEDIATELY above the def (whitespace +
        # possibly a newline between, but no other decorator or code).
        assert re.search(rf"@mcp\.tool\(\)\s*\ndef {fn}\(", src), (
            f"@mcp.tool() decorator missing above def {fn} — "
            f"MCP clients won't see the tool even though it's callable")


def test_ctxmenu_multi_pse_opens_configure_modal_instead_of_silent_pick():
    """When one node yielded >1 looted PSEs (SNCCredential #N
    disambiguation), the ctx-menu MUST NOT silently pick iteration-order
    first — it redirects to the Configure SNC modal so the operator
    picks explicitly in the switcher.  Source-pin the two-branch logic."""
    html = (REPO_ROOT / "modules" / "core" / "sapmap_html.py").read_text(
        encoding="utf-8")
    # Filter-not-find: we count matches, not just read first.
    assert re.search(
        r"const matches\s*=\s*Object\.values\(wallet\)\.filter\(.*source_sid\s*===\s*sid",
        html)
    # On >1, open the modal (showConfigureSncModal) and bail — no POST.
    assert re.search(r"matches\.length\s*>\s*1", html)
    assert "showConfigureSncModal()" in html


# ===========================================================================
# Engagement report — MD + HTML
# ===========================================================================

def _wallet_state_for_report():
    st = SAPMAPState()
    st.trust_relations = [TrustRelation(trusting_sid="QAS",
                                         issuer_sid="DEV"),
                          TrustRelation(trusting_sid="PRD",
                                         issuer_sid="DEV")]
    st.add_snc_credential(SNCCredential(
        source_sid="DEV", pse_path="/loot/DEV/SAPSYS.pse",
        snc_identity="p:CN=DEV", key_is_rsa=True, pin="MYPIN",
        looted_at="2026-11-11T12:00:00"))
    st.add_snc_credential(SNCCredential(
        source_sid="QAS", pse_path="/loot/QAS/SAPSYS.pse",
        snc_identity="p:CN=QAS", key_is_rsa=False, pin="ANOTHERPIN",
        looted_at="2026-11-11T12:05:00"))
    st.set_active_snc_credential("DEV:SAPSYS")
    return st


def test_report_md_section_renders_wallet_and_marks_active():
    from sapmap_report import (_snc_identity_section,
                                build_markdown_report)
    st = _wallet_state_for_report()
    md = "\n".join(_snc_identity_section(st))
    assert "SNC client identity (looted PSEs)" in md
    assert "DEV" in md and "p:CN=DEV" in md
    assert "native (RSA)" in md
    assert "cryptolib (EC)" in md
    # Reach count renders the resolved targets
    assert "2 (PRD, QAS)" in md
    # Active row marked, inactive not
    assert re.search(r"\|\s*✓\s*\|\s*DEV\s*\|", md), "DEV row should be active"
    assert re.search(r"\|\s*—\s*\|\s*QAS\s*\|", md), "QAS row should be inactive"
    # Appears in the full assembled report (section is wired up)
    full = build_markdown_report(st)
    assert "SNC client identity (looted PSEs)" in full


def test_report_html_section_renders_and_toc_wires_up():
    from sapmap_report import (_html_snc_identity_section,
                                build_markdown_report)
    st = _wallet_state_for_report()
    html = _html_snc_identity_section(st)
    assert 'id="sec-snc-identity"' in html
    assert "DEV" in html and "p:CN=DEV" in html
    # Active row carries the highlight style
    assert "background:#fef3c7" in html
    # Empty wallet -> empty section (no header noise)
    assert _html_snc_identity_section(SAPMAPState()) == ""
    # TOC entry is wired so the section is linked from the ToC
    report_src = (REPO_ROOT / "modules" / "core" / "sapmap_report.py"
                  ).read_text(encoding="utf-8")
    assert '("sec-snc-identity",  "🔐 SNC client identity (looted PSEs)"' in report_src


def test_report_never_renders_the_pse_pin():
    """Secret-leak pin: whichever path the report takes, the PIN must
    not reach the rendered output.  Mirrors the cred_v2/pin discipline
    the rest of the report already observes."""
    from sapmap_report import (build_markdown_report,
                                _html_snc_identity_section)
    st = _wallet_state_for_report()
    assert "MYPIN" not in build_markdown_report(st)
    assert "MYPIN" not in _html_snc_identity_section(st)
    assert "ANOTHERPIN" not in build_markdown_report(st)
    assert "ANOTHERPIN" not in _html_snc_identity_section(st)


# ===========================================================================
# README — surfacing checklist pin
# ===========================================================================

def test_readme_links_to_snc_support_wiki():
    """The feature-surfacing checklist requires a user-facing docs
    pointer.  The README links to the SNC-Support wiki page, which
    carries the loot-a-PSE flow + the native/cryptolib paths."""
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "/SAPMAP/wiki/SNC-Support" in readme
    # And names the feature so a grep for "looted" lands on it
    assert "looted" in readme.lower()
