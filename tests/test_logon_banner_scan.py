"""
Tests for modules.data_extraction.sap_logon_banner_scan (issue #68 PR3).

Covers the per-node orchestrator that bridges PR1 ``fetch_login_items``
(DIAG session) + PR2 ``scan_text`` (regex catalogue) into a single call
the GUI route uses.  No real DIAG socket is opened — every test passes
in explicit ``_fetch_fn`` / ``_collect_fn`` / ``_scan_fn`` DI hooks.
"""

import json
import os
import re
import types

import pytest

# conftest adds every modules/* subpackage to sys.path, so flat imports
# work without touching the file layout.
import modules  # noqa: F401  (path registration)

from sap_logon_banner_scan import (
    CAPABILITY_FOR_CATEGORY,
    dispatcher_port_for,
    is_abap_eligible,
    make_run_id,
    scan_node,
    _count_by_severity,
    _flatten_items,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_items():
    """Opaque DIAG items blob — the orchestrator doesn't inspect it,
    just hands it to _collect_fn."""
    return [("item_a", "val_a"), ("item_b", "val_b")]


@pytest.fixture
def leaky_pairs():
    """DYNT (field, value) pairs that scan_text's catalogue classifies
    as CRITICAL / HIGH / MEDIUM / INFO respectively."""
    return [
        ("User",     "SAPMAP00"),
        ("Password", "Andinyougo123!"),
        ("Support",  "basis@example.com"),
        ("Hotline",  "+31 20 555 0101"),
        ("Notice",   "Welcome to the SAP system."),
    ]


# ---------------------------------------------------------------------------
# make_run_id
# ---------------------------------------------------------------------------

def test_make_run_id_shape_matches_logon_prefix_and_sha_tail():
    rid = make_run_id()
    assert rid.startswith("logon_"), rid
    # YYYYMMDDTHHMMSSZ + 6-hex tail joined by underscores
    tail = rid.split("_")[-1]
    assert re.fullmatch(r"[0-9a-f]{6}", tail), rid


def test_make_run_id_two_back_to_back_calls_do_not_collide():
    """Rescan button double-click is the realistic scenario this
    guards — monotonic_ns in the sha source makes same-second calls
    distinct."""
    seen = {make_run_id() for _ in range(200)}
    assert len(seen) == 200


# ---------------------------------------------------------------------------
# Node-shape helpers
# ---------------------------------------------------------------------------

def _node(instances=None, system_type="ABAP"):
    return types.SimpleNamespace(
        instances=instances or [],
        system_type=system_type,
    )


def test_dispatcher_port_returns_port_and_instance_from_dispatcher_label():
    inst = types.SimpleNamespace(instance_nr="00", ports={3200: "dispatcher"})
    assert dispatcher_port_for(_node([inst])) == (3200, "00")


def test_dispatcher_port_accepts_bare_32xx_port_without_dispatcher_label():
    inst = types.SimpleNamespace(instance_nr="05", ports={3205: "open"})
    assert dispatcher_port_for(_node([inst])) == (3205, "05")


def test_dispatcher_port_ignores_string_keys_from_json_reload():
    """Loaded state has int keys (from_dict casts them), but defensive
    code should still skip accidental str keys without crashing."""
    inst = types.SimpleNamespace(
        instance_nr="00", ports={"3200": "dispatcher"})
    assert dispatcher_port_for(_node([inst])) == (0, "")


def test_dispatcher_port_zero_when_no_dispatcher_seen():
    inst = types.SimpleNamespace(instance_nr="00", ports={1128: "ms_http"})
    assert dispatcher_port_for(_node([inst])) == (0, "")


def test_dispatcher_port_zero_when_no_instances_scanned():
    assert dispatcher_port_for(_node([])) == (0, "")


def test_is_abap_eligible_matches_pure_abap_dual_stack_lowercase():
    assert is_abap_eligible(_node(system_type="ABAP"))
    assert is_abap_eligible(_node(system_type="ABAP+JAVA"))
    assert is_abap_eligible(_node(system_type="abap"))


def test_is_abap_eligible_rejects_pure_java_bo_saprouter_empty():
    assert not is_abap_eligible(_node(system_type="JAVA"))
    assert not is_abap_eligible(_node(system_type="BUSINESSOBJECTS"))
    assert not is_abap_eligible(_node(system_type="SAPROUTER"))
    assert not is_abap_eligible(_node(system_type=""))
    assert not is_abap_eligible(_node(system_type=None))


# ---------------------------------------------------------------------------
# _flatten_items — the bridge between collect_text_info and scan_text
# ---------------------------------------------------------------------------

def test_flatten_items_drops_empty_values_and_tab_separates_pairs():
    text = _flatten_items([
        ("User",     "SAPMAP00"),
        ("Padding",  ""),       # empty value — dropped
        ("Password", "secret"),
    ])
    # Two surviving lines, field<TAB>value
    assert text == "User\tSAPMAP00\nPassword\tsecret"


def test_flatten_items_empty_input_yields_empty_string():
    assert _flatten_items([]) == ""


# ---------------------------------------------------------------------------
# scan_node — core orchestrator
# ---------------------------------------------------------------------------

def _fake_scan_text(text, custom_patterns=None, context=None,
                    emit_info_on_empty=False):
    """Stand-in for sap_logon_text_secrets.scan_text that assigns
    severities by hard-coded keywords — enough for the orchestrator
    tests without pulling the PR2 regex engine into the import graph."""
    out = []
    ctx = dict(context or {})
    if "SAPMAP00" in text and "Andinyougo123!" in text:
        out.append({
            "severity": "CRITICAL",
            "pattern_name": "user_password_adjacent",
            "category": "credentials",
            "match": "User\\tSAPMAP00",
            "snippet": "User\tSAPMAP00",
            "offset": 0, "context": dict(ctx),
        })
    if "basis@example.com" in text:
        out.append({
            "severity": "MEDIUM",
            "pattern_name": "email_address",
            "category": "pii",
            "match": "basis@example.com",
            "snippet": "Support basis@example.com",
            "offset": 20, "context": dict(ctx),
        })
    if "+31 20" in text:
        out.append({
            "severity": "MEDIUM",
            "pattern_name": "phone_e164",
            "category": "pii",
            "match": "+31 20 555 0101",
            "snippet": "Hotline +31 20 555 0101",
            "offset": 50, "context": dict(ctx),
        })
    if not out and emit_info_on_empty and ctx:
        out.append({
            "severity": "INFO",
            "pattern_name": "no_matches",
            "category": "coverage",
            "match": "",
            "snippet": "",
            "offset": 0, "context": dict(ctx),
        })
    return out


def test_scan_node_happy_path_persists_loot_and_tags_capability(
        tmp_path, fake_items, leaky_pairs):
    captured_calls = {}

    def _fetch(host, port, opts, terminal):
        captured_calls["fetch"] = (host, port, opts.timeout,
                                   opts.route_string, terminal)
        return fake_items

    def _collect(items):
        captured_calls["collect"] = len(items)
        return leaky_pairs

    r = scan_node(
        "10.0.0.1", 3200,
        sid="NPL", instance_nr="00",
        saprouter="/H/jump/S/3299/W/foo",
        terminal="1.2.3.4",
        timeout=4,
        loot_dir=str(tmp_path),
        _fetch_fn=_fetch,
        _collect_fn=_collect,
        _scan_fn=_fake_scan_text,
    )

    assert r["ok"] is True, r
    assert r["error_kind"] is None
    assert r["sid"] == "NPL"
    assert r["port"] == 3200
    assert r["instance_nr"] == "00"
    assert r["pair_count"] == len(leaky_pairs)
    assert r["raw_text_bytes"] > 0

    # Fetch received the host/port/options/terminal we handed it
    host, port, timeout, saprouter, terminal = captured_calls["fetch"]
    assert (host, port) == ("10.0.0.1", 3200)
    assert timeout == 4
    assert saprouter == "/H/jump/S/3299/W/foo"
    assert terminal == "1.2.3.4"

    # Severity-count shape
    assert r["hits_by_severity"]["CRITICAL"] == 1
    assert r["hits_by_severity"]["MEDIUM"] == 2
    # INFO coverage marker SHOULD NOT fire when real hits are present
    assert r["hits_by_severity"]["INFO"] == 0

    # Capability routing — credentials → creds., pii → data.
    cats = {f["pattern_name"]: f["attack_capability"] for f in r["findings"]}
    assert cats["user_password_adjacent"] == "creds.diag_login_screen_leak"
    assert cats["email_address"] == "data.diag_login_screen_leak"
    assert cats["phone_e164"] == "data.diag_login_screen_leak"

    # Loot files land as <run_id>_<inst>_<port>.{txt,json}
    assert os.path.isfile(r["loot_text_path"])
    assert os.path.isfile(r["loot_json_path"])
    txt = open(r["loot_text_path"], encoding="utf-8").read()
    assert "SAPMAP00" in txt
    bundle = json.load(open(r["loot_json_path"], encoding="utf-8"))
    assert bundle["meta"]["sid"] == "NPL"
    assert bundle["meta"]["pair_count"] == len(leaky_pairs)
    assert bundle["meta"]["saprouter"] is True
    assert len(bundle["findings"]) == len(r["findings"])


def test_scan_node_runs_scan_text_with_context_dict_passthrough(
        tmp_path, fake_items, leaky_pairs):
    """context={sid, host, port, instance_nr, run_id} must land on every
    finding so the route layer can read identity straight off each row
    without rediscovering it."""
    captured = {"ctx_seen": None}

    def _scan(text, custom_patterns=None, context=None, emit_info_on_empty=False):
        captured["ctx_seen"] = dict(context or {})
        return [{"severity": "HIGH", "pattern_name": "jwt_token",
                 "category": "token", "match": "a.b.c", "snippet": "a.b.c",
                 "offset": 0, "context": dict(context or {})}]

    r = scan_node(
        "10.0.0.1", 3200, sid="NPL", instance_nr="00",
        _fetch_fn=lambda *a, **kw: fake_items,
        _collect_fn=lambda it: leaky_pairs,
        _scan_fn=_scan,
    )
    assert r["ok"] is True
    seen = captured["ctx_seen"]
    assert seen["sid"] == "NPL"
    assert seen["host"] == "10.0.0.1"
    assert seen["port"] == 3200
    assert seen["instance_nr"] == "00"
    assert seen["run_id"].startswith("logon_")
    # token category → creds.* capability (JWT is a credential-shape leak)
    assert r["findings"][0]["attack_capability"] == "creds.diag_login_screen_leak"


def test_scan_node_passes_custom_patterns_through_to_scan_text(
        tmp_path, fake_items, leaky_pairs):
    captured = {"custom": None}

    def _scan(text, custom_patterns=None, context=None, emit_info_on_empty=False):
        captured["custom"] = list(custom_patterns or [])
        return []

    scan_node(
        "10.0.0.1", 3200, sid="NPL", instance_nr="00",
        custom_patterns=["CRITICAL: FOO_[A-Z]+", "", "# comment", "bar"],
        _fetch_fn=lambda *a, **kw: fake_items,
        _collect_fn=lambda it: leaky_pairs,
        _scan_fn=_scan,
    )
    # scan_node forwards the operator list verbatim — _compile_custom_patterns
    # (PR2) does the SEV: parsing / blank skip / comment handling.
    assert captured["custom"] == [
        "CRITICAL: FOO_[A-Z]+", "", "# comment", "bar"]


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------

def test_scan_node_connect_refused_surfaces_as_connect_error():
    def _fetch(host, port, opts, terminal):
        raise ConnectionRefusedError("refused")

    r = scan_node("10.0.0.1", 3200, _fetch_fn=_fetch,
                   _collect_fn=lambda it: [],
                   _scan_fn=_fake_scan_text)
    assert r["ok"] is False
    assert r["error_kind"] == "connect"
    assert "refused" in r["error"]
    assert r["pair_count"] == 0
    assert r["findings"] == []


def test_scan_node_short_response_surfaces_as_short_error():
    r = scan_node("10.0.0.1", 3200,
                   _fetch_fn=lambda *a, **kw: None,
                   _collect_fn=lambda it: [],
                   _scan_fn=_fake_scan_text)
    assert r["ok"] is False
    assert r["error_kind"] == "short"


def test_scan_node_compressed_diag_response_classified_as_compressed():
    def _fetch(host, port, opts, terminal):
        raise ValueError("compressed DIAG response is not supported")

    r = scan_node("10.0.0.1", 3200, _fetch_fn=_fetch,
                   _collect_fn=lambda it: [],
                   _scan_fn=_fake_scan_text)
    assert r["ok"] is False
    assert r["error_kind"] == "compressed"
    assert "compressed" in r["error"]


def test_scan_node_cancel_check_short_circuits_before_diag():
    def _fetch(host, port, opts, terminal):
        raise AssertionError("fetch must not be called when cancel is set")

    r = scan_node("10.0.0.1", 3200, cancel_check=lambda: True,
                   _fetch_fn=_fetch,
                   _collect_fn=lambda it: [],
                   _scan_fn=_fake_scan_text)
    assert r["error_kind"] == "cancelled"
    assert r["ok"] is False


def test_scan_node_captures_pr1_print_output_instead_of_blasting_stdout(
        fake_items, leaky_pairs, capsys):
    """fetch_login_items prints to stdout unconditionally; scan_node
    MUST redirect it so a background worker doesn't fill the operator's
    console on every scan."""
    def _fetch(host, port, opts, terminal):
        print("[*] Connecting to %s:%d" % (host, port))
        print("[*] Sending DIAG init")
        return fake_items

    r = scan_node("10.0.0.1", 3200, sid="NPL", instance_nr="00",
                   _fetch_fn=_fetch,
                   _collect_fn=lambda it: leaky_pairs,
                   _scan_fn=_fake_scan_text)
    # Everything the fake fetch printed must be in the captured buffer
    # on the result dict, NOT on real stdout.
    captured = capsys.readouterr()
    assert "[*] Connecting" not in captured.out
    assert "[*] Connecting" in r["stdout_capture"]


# ---------------------------------------------------------------------------
# Coverage marker + redaction invariants
# ---------------------------------------------------------------------------

def test_scan_node_emits_info_coverage_marker_on_clean_banner(
        tmp_path, fake_items):
    """emit_info_on_empty=True on the scan_text call should produce a
    coverage marker finding — scan_node routes it to the recon.*
    capability key so the ATT&CK heatmap distinguishes 'we checked'
    from 'we never looked'."""
    r = scan_node("10.0.0.1", 3200, sid="NPL", instance_nr="00",
                   _fetch_fn=lambda *a, **kw: fake_items,
                   _collect_fn=lambda it: [("Welcome", "Hello")],
                   _scan_fn=_fake_scan_text)
    assert r["ok"] is True
    # Coverage marker's category='coverage' → recon.logon_banner_scan
    assert len(r["findings"]) == 1
    assert r["findings"][0]["category"] == "coverage"
    assert r["findings"][0]["attack_capability"] == "recon.logon_banner_scan"
    assert r["findings"][0]["severity"] == "INFO"


def test_scan_node_no_cleartext_in_route_metadata_only_findings_carry_match(
        tmp_path, fake_items, leaky_pairs):
    """The route layer stores node.logon_banner_scan (the summary) and
    node.logon_banner_findings (the finding rows).  Only the findings
    carry the match text — the SUMMARY block never does.  Lock that
    invariant in."""
    r = scan_node("10.0.0.1", 3200, sid="NPL", instance_nr="00",
                   loot_dir=str(tmp_path),
                   _fetch_fn=lambda *a, **kw: fake_items,
                   _collect_fn=lambda it: leaky_pairs,
                   _scan_fn=_fake_scan_text)
    # scan_node itself has no "summary" field — the route builds the
    # summary subset — but we still assert hits_by_severity (which IS
    # the dict the route reads) has no cleartext in it.
    summary_blob = json.dumps(r["hits_by_severity"])
    assert "SAPMAP00" not in summary_blob
    assert "Andinyougo123" not in summary_blob
    assert "basis@example.com" not in summary_blob
    # And every finding row DOES carry its match (operator must see
    # exactly what was leaked).
    matches = {f["match"] for f in r["findings"]}
    assert any("SAPMAP00" in m for m in matches)


def test_count_by_severity_defaults_cover_full_ladder():
    counts = _count_by_severity([
        {"severity": "CRITICAL"},
        {"severity": "MEDIUM"},
        {"severity": "MEDIUM"},
        {"severity": "INFO"},
    ])
    assert counts == {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 2, "INFO": 1}


def test_count_by_severity_unknown_severity_coerces_to_info():
    counts = _count_by_severity([
        {"severity": "LOW"},        # not on the bus — should bucket into INFO
        {"severity": "warning"},    # case-sensitive — unknown
    ])
    assert counts["INFO"] >= 2


# ---------------------------------------------------------------------------
# Capability routing table — contract pin
# ---------------------------------------------------------------------------

def test_capability_for_category_covers_scan_text_catalogue():
    """Every category that scan_text can actually emit must have a
    routing entry.  Guards against the orchestrator silently
    defaulting to data.diag_login_screen_leak for a NEW category
    added to the PR2 catalogue later."""
    # scan_text (sap_logon_text_secrets) emits: credentials, token,
    # pii, network, custom, coverage.  parse_error is NOT in that
    # list — scan_text labels compile-error findings as
    # category="custom" with error=True, which is why
    # _route_capability (below) demotes them explicitly rather than
    # relying on a parse_error entry here.
    known = {"credentials", "token", "pii", "network",
             "custom", "coverage"}
    assert set(CAPABILITY_FOR_CATEGORY.keys()) >= known
    # Credential-shaped categories must route to creds.*
    for cat in ("credentials", "token"):
        assert CAPABILITY_FOR_CATEGORY[cat] == "creds.diag_login_screen_leak"
    # pii / network / custom route to data.*
    for cat in ("pii", "network", "custom"):
        assert CAPABILITY_FOR_CATEGORY[cat] == "data.diag_login_screen_leak"
    # coverage is an observation about the scanner, not the target
    # — it lands under recon.*
    assert CAPABILITY_FOR_CATEGORY["coverage"] == "recon.logon_banner_scan"


def test_route_capability_demotes_compile_errors_to_recon():
    """scan_text labels operator-regex compile-error findings as
    ``category="custom"`` with ``error=True`` — _route_capability
    must demote those to recon.logon_banner_scan so a bad regex
    isn't framed as a credential/data leak."""
    from sap_logon_banner_scan import _route_capability
    # A real custom match → data.*
    assert _route_capability(
        {"category": "custom", "match": "FOO123"}
    ) == "data.diag_login_screen_leak"
    # A compile-error finding → recon.* (demoted)
    assert _route_capability(
        {"category": "custom", "error": True,
         "match": "(bad regex", "severity": "INFO"}
    ) == "recon.logon_banner_scan"


# ---------------------------------------------------------------------------
# Integration-shape test — hit the REAL PR2 scan_text with real pairs
# ---------------------------------------------------------------------------

def test_scan_node_real_scan_text_catches_real_banner_leak_shape(
        tmp_path, fake_items):
    """One end-to-end-ish test that uses the REAL sap_logon_text_secrets
    scan_text (no mock) to confirm the orchestrator's text-flattening
    + context plumbing survives contact with the real regex engine.

    PR2's _RE_USER_THEN_PASSWORD intentionally forbids ``\\n`` between
    the user value and the password label — a banner where username
    and password are posted in SEPARATE DYNT atoms is NOT the admin-
    posted-creds case the catalogue is designed to flag.  The realistic
    leak case is admins pasting a FULL welcome message (one text atom)
    containing a credential adjacency; that's the fixture here."""
    pairs = [
        ("Welcome",
         "Please login as user sapmap00 with password Andinyougo123! "
         "Contact basis@example.com for access"),
        ("Hotline", "+31 20 555 0101 for after-hours support"),
    ]
    r = scan_node(
        "10.0.0.1", 3200, sid="NPL", instance_nr="00",
        loot_dir=str(tmp_path),
        _fetch_fn=lambda *a, **kw: fake_items,
        _collect_fn=lambda it: pairs,
        # NOTE: _scan_fn is None → scan_node lazy-imports the real
        # sap_logon_text_secrets.scan_text.
    )
    assert r["ok"] is True
    sevs = {f["severity"] for f in r["findings"]}
    assert "CRITICAL" in sevs  # user+password adjacency on one line
    # Email picked up at MEDIUM
    pattern_names = {f["pattern_name"] for f in r["findings"]}
    assert "email_address" in pattern_names
    assert "user_password_adjacent" in pattern_names
    # Every finding carries the context dict with our identity
    for f in r["findings"]:
        if f.get("category") == "coverage":
            continue
        assert f["context"]["sid"] == "NPL"
        assert f["context"]["host"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# Attack-mapping contract — the three keys resolve to real techniques
# ---------------------------------------------------------------------------

def test_capability_keys_resolve_to_known_techniques():
    """scan_node tags findings with attack_capability keys that must
    exist in sapmap_attack.CAPABILITY_MAP, and every T-ID those keys
    reference must exist in TECHNIQUES.  The dedicated catalog-
    integrity suite already covers this, but this test fails fast
    for the PR3-specific keys so a bad capability name breaks here
    with a clearer failure than through the generic test."""
    import sapmap_attack
    for cap in {
        "recon.logon_banner_scan",
        "creds.diag_login_screen_leak",
        "data.diag_login_screen_leak",
    }:
        assert cap in sapmap_attack.CAPABILITY_MAP, cap
        for tid in sapmap_attack.CAPABILITY_MAP[cap]:
            assert tid in sapmap_attack.TECHNIQUES, (cap, tid)


# ---------------------------------------------------------------------------
# Adversarial-review follow-ups (verified findings → pinned regressions)
# ---------------------------------------------------------------------------

def test_phantom_info_coverage_hit_does_not_inflate_counter(
        tmp_path, fake_items):
    """Review finding #3 — on a clean banner, scan_text's coverage
    marker SHOULD show up in `findings` (so the GUI can tell "we
    checked" from "we never looked") but MUST NOT inflate
    hits_by_severity.INFO, which drives the panel's INFO pill.
    """
    r = scan_node(
        "10.0.0.1", 3200, sid="NPL", instance_nr="00",
        _fetch_fn=lambda *a, **kw: fake_items,
        _collect_fn=lambda it: [("Welcome", "Hello world")],
        _scan_fn=_fake_scan_text,
    )
    # One coverage finding is present…
    cats = [f.get("category") for f in r["findings"]]
    assert "coverage" in cats
    # …but hits_by_severity.INFO (the pill the UI shows) is zero.
    assert r["hits_by_severity"]["INFO"] == 0


def test_custom_patterns_generator_not_exhausted_before_scan(
        fake_items, leaky_pairs):
    """Review finding #5 — if the operator passes an iterable (not a
    materialised list), scan_node must not consume it once in the
    loot-meta pass and leave scan_text with an empty iterator."""
    def _gen():
        yield "FOO_[A-Z]+"
        yield "BAR_[0-9]+"
    captured = {"patterns": None}

    def _scan(text, custom_patterns=None, context=None, emit_info_on_empty=False):
        # Materialise what we received so we can inspect the length.
        captured["patterns"] = list(custom_patterns or [])
        return []

    scan_node("10.0.0.1", 3200, sid="NPL", instance_nr="00",
               custom_patterns=_gen(),
               _fetch_fn=lambda *a, **kw: fake_items,
               _collect_fn=lambda it: leaky_pairs,
               _scan_fn=_scan)
    # Both generator items reach scan_text — not an empty list from
    # a pre-exhausted generator.
    assert captured["patterns"] == ["FOO_[A-Z]+", "BAR_[0-9]+"]


def test_second_cancel_check_after_fetch_short_circuits_regex_pass(
        fake_items, leaky_pairs):
    """Review finding #10 — cancel_check is probed BEFORE fetch_login_items
    (so a pre-flight STOP skips the socket) AND AFTER (so a STOP
    mid-fetch at least suppresses the regex pass and loot write)."""
    probes = {"calls": 0}

    def _cancel():
        probes["calls"] += 1
        # First probe (pre-flight) → False; second probe (post-fetch) → True
        return probes["calls"] >= 2

    r = scan_node("10.0.0.1", 3200, sid="NPL",
                   cancel_check=_cancel,
                   _fetch_fn=lambda *a, **kw: fake_items,
                   _collect_fn=lambda it: leaky_pairs,
                   _scan_fn=_fake_scan_text)
    # Cancel probe fires at least twice (pre + post).
    assert probes["calls"] >= 2
    # Second probe trips → scan ends as cancelled, no regex pass.
    assert r["error_kind"] == "cancelled"
    assert r["findings"] == []
    assert r["hits_by_severity"]["CRITICAL"] == 0


def test_scan_summary_subset_the_gui_route_builds_has_no_cleartext(
        tmp_path, fake_items, leaky_pairs):
    """Review finding #13 — the summary dict the route stores on
    node.logon_banner_scan is a strict subset of scan_node's result
    (NO raw match, snippet, pairs text).  Lock that invariant here
    by rebuilding the subset the route builds and asserting that
    json.dumps(summary) does not contain any of the leaked values
    scan_text saw."""
    r = scan_node("10.0.0.1", 3200, sid="NPL", instance_nr="00",
                   loot_dir=str(tmp_path),
                   _fetch_fn=lambda *a, **kw: fake_items,
                   _collect_fn=lambda it: leaky_pairs,
                   _scan_fn=_fake_scan_text)
    # The exact subset the GUI route builds — see
    # modules/core/sapmap_gui.py node_scan_logon_banners `_run`:
    # `node.logon_banner_scan = {...}`.
    summary = {
        "run_id":          r.get("run_id"),
        "ts":              r.get("ts"),
        "instance_nr":     r.get("instance_nr"),
        "port":            r.get("port"),
        "elapsed_s":       r.get("elapsed_s"),
        "pair_count":      r.get("pair_count"),
        "raw_text_bytes":  r.get("raw_text_bytes"),
        "hits_by_severity": r.get("hits_by_severity"),
        "loot_text_path":  r.get("loot_text_path"),
        "loot_json_path":  r.get("loot_json_path"),
        "error_kind":      r.get("error_kind"),
        "error":           r.get("error"),
    }
    blob = json.dumps(summary)
    for secret in ("SAPMAP00", "Andinyougo123!",
                    "basis@example.com", "+31 20 555 0101"):
        assert secret not in blob, (
            f"summary dict leaked cleartext: {secret}")
    # But node.logon_banner_findings DOES carry the match on purpose
    # (so the side-panel can show the operator what was leaked).
    assert any("SAPMAP00" in (f.get("match") or "") for f in r["findings"])


def test_path_safety_route_sanitises_sid_before_loot_dir():
    """Review finding #6 — a scanner-derived SID with slashes or
    dots cannot escape the loot bucket.  Guard the sanitisation
    pattern lives in the route source (static pin).
    """
    import pathlib
    src = (pathlib.Path(__file__).resolve().parent.parent
           / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")
    # Locate the scan_logon_banners route body.
    i = src.find(
        '@app.route("/api/node/<sid>/scan_logon_banners", method="POST")')
    assert i >= 0
    j = src.find('@app.route(', i + 1)
    body = src[i:j if j > 0 else len(src)]
    # Sanitation regex must exist (any character outside the safe
    # class is replaced).
    assert "safe_sid = _re.sub" in body
    assert "[^A-Za-z0-9_-]" in body
    # And the ensure_loot_dir path uses the sanitised sid, not the raw one.
    assert 'ensure_loot_dir(\n                        f"logon_banners/{safe_sid' in body or \
           'ensure_loot_dir(f"logon_banners/{safe_sid' in body
