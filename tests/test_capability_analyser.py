"""Capability analyser — turns AGR_USERS / AGR_1251 / UST04 rows
into business-language capability statements.  Tests cover:
  * the rule predicate matcher (exact / wildcard / prefix)
  * the resolver against synthetic AGR_1251 grants
  * blast-radius aggregation
  * end-to-end node analysis (mocked sapmap_rfc.read_table)
  * round-trip through SAPMAPState.to_dict / from_dict
"""
from __future__ import annotations

from unittest.mock import patch

import modules  # noqa: F401  (registers package paths)
from sapmap_capability_analyser import (
    _CAPABILITY_RULES, _match_predicate, _resolve_user_capabilities,
    _blast_radius, _english_summary, analyse, export_rules_yaml,
)
from sapmap_models import (SAPMAPState, SAPNode, Credentials,
                            CreatedUser, Severity)


# --- predicate matcher ---------------------------------------------

def test_match_predicate_exact_match():
    assert _match_predicate({"ACTVT": "01"}, {"ACTVT": "01"}) is True
    assert _match_predicate({"ACTVT": "01"}, {"ACTVT": "02"}) is False


def test_match_predicate_is_case_insensitive():
    """SAP returns LOW values in mixed case across kernel patches —
    the predicate must compare uppercased on both sides."""
    assert _match_predicate({"OBJTYPE": "DEBUG"},
                             {"OBJTYPE": "debug"}) is True


def test_match_predicate_wildcard_matches_any_value():
    assert _match_predicate({"COMMAND": "*"}, {"COMMAND": "ls"}) is True
    assert _match_predicate({"COMMAND": "*"}, {"COMMAND": ""}) is True


def test_match_predicate_prefix_glob():
    """Prefix glob ("PA*") matches values starting with PA."""
    assert _match_predicate({"INFTY": "00*"},
                             {"INFTY": "0008"}) is True
    assert _match_predicate({"INFTY": "00*"},
                             {"INFTY": "0142"}) is False


def test_match_predicate_missing_field_treated_as_blank():
    """A required predicate field absent from the row is treated
    as blank — wildcards still match, exact requirements fail."""
    assert _match_predicate({"X": "*"}, {}) is True
    assert _match_predicate({"X": "Y"}, {}) is False


# --- resolver against synthetic AGR_1251 rows ----------------------

def _grant(role, obj, field, low):
    return {"AGR_NAME": role, "OBJECT": obj,
            "FIELD": field, "LOW": low}


def test_resolver_finds_vendor_bank_edit():
    """F_LFA1_APP APPKZ=E is the wire-fraud capability — must
    surface as CRITICAL."""
    rows = [_grant("Z_AP_CLERK", "F_LFA1_APP", "APPKZ", "E")]
    caps = _resolve_user_capabilities(rows)
    bank_caps = [c for c in caps
                 if c["auth_object"] == "F_LFA1_APP"
                 and "Edit vendor bank" in c["capability"]]
    assert len(bank_caps) == 1
    assert bank_caps[0]["severity"] == int(Severity.CRITICAL)
    assert "LFBK" in bank_caps[0]["tables"]


def test_resolver_finds_debugger_with_replace():
    """S_DEVELOP OBJTYPE=DEBUG ACTVT=02 is RCE-equivalent.  The
    matcher must require BOTH fields on the same role grant
    (otherwise ACTVT=02 from one role + OBJTYPE=DEBUG from another
    role would fire spuriously)."""
    rows = [
        _grant("Z_DEBUG", "S_DEVELOP", "OBJTYPE", "DEBUG"),
        _grant("Z_DEBUG", "S_DEVELOP", "ACTVT", "02"),
    ]
    caps = _resolve_user_capabilities(rows)
    dbg = [c for c in caps if "Debugger" in c["capability"]]
    assert len(dbg) == 1


def test_resolver_does_not_cross_match_across_roles():
    """OBJTYPE=DEBUG via Role A and ACTVT=02 via Role B must NOT
    spuriously fire 'Debugger with replace'.  Both fields need to
    come from the same (object, role) grant."""
    rows = [
        _grant("Z_VIEWER", "S_DEVELOP", "OBJTYPE", "DEBUG"),
        _grant("Z_EDITOR", "S_DEVELOP", "ACTVT", "02"),
    ]
    caps = _resolve_user_capabilities(rows)
    dbg = [c for c in caps if "Debugger with replace" in c["capability"]]
    assert dbg == []


def test_resolver_dedupes_same_capability_from_multiple_roles():
    """A user with the same auth object granted by two roles
    shouldn't get the same capability listed twice."""
    rows = [
        _grant("Z_FIN_VIEWER", "S_TABU_DIS", "DICBERCLS", "FI"),
        _grant("Z_FIN_USER", "S_TABU_DIS", "DICBERCLS", "FI"),
    ]
    caps = _resolve_user_capabilities(rows)
    fi = [c for c in caps
          if c["auth_object"] == "S_TABU_DIS"
          and "Finance master read" in c["capability"]]
    assert len(fi) == 1


def test_resolver_finds_multiple_distinct_capabilities():
    """One role granting three different objects should produce
    three separate capability entries."""
    rows = [
        _grant("Z_PWNED", "F_LFA1_APP", "APPKZ", "E"),
        _grant("Z_PWNED", "S_DEVELOP", "OBJTYPE", "DEBUG"),
        _grant("Z_PWNED", "S_DEVELOP", "ACTVT", "02"),
        _grant("Z_PWNED", "S_LOG_COM", "COMMAND", "ls"),
        _grant("Z_PWNED", "S_LOG_COM", "OPSYSTEM", "Linux"),
    ]
    caps = _resolve_user_capabilities(rows)
    objs = {c["auth_object"] for c in caps}
    assert "F_LFA1_APP" in objs
    assert "S_DEVELOP" in objs
    assert "S_LOG_COM" in objs


# --- blast radius aggregation -------------------------------------

def test_blast_radius_three_critical_is_total_compromise():
    caps = [
        {"severity": int(Severity.CRITICAL)},
        {"severity": int(Severity.CRITICAL)},
        {"severity": int(Severity.CRITICAL)},
    ]
    label = _blast_radius(caps)
    assert "total" in label.lower()


def test_blast_radius_one_critical_is_severe():
    caps = [{"severity": int(Severity.CRITICAL)},
             {"severity": int(Severity.MEDIUM)}]
    assert "severe" in _blast_radius(caps).lower()


def test_blast_radius_no_caps_is_explicit():
    assert _blast_radius([]) == ("no privileged capabilities "
                                  "recovered")


def test_blast_radius_only_high_caps_substantial_or_limited():
    """≥3 HIGH = substantial; 1 HIGH = limited."""
    three = [{"severity": int(Severity.HIGH)}] * 3
    one = [{"severity": int(Severity.HIGH)}]
    assert "substantial" in _blast_radius(three).lower()
    assert "limited" in _blast_radius(one).lower()


# --- english summary ----------------------------------------------

def test_english_summary_uses_row_counts_when_present():
    """The dollar-quantification line ("LFBK = 2,107 IBANs") only
    appears when the row-count probe cached a value for that table.
    Uncached tables show their name only, never a fake number."""
    caps = [{
        "auth_object": "F_LFA1_APP",
        "capability": "Edit vendor bank details (LFBK)",
        "tables": ["LFBK", "LFA1"],
        "severity": int(Severity.CRITICAL),
        "why": "wire fraud",
    }]
    s = _english_summary("SAPMAP00", "S4H", "001", caps,
                          {"LFBK": 2107, "LFA1": 8421})
    assert "2,107 rows" in s
    assert "8,421 rows" in s
    assert "Edit vendor bank" in s


def test_english_summary_omits_count_when_missing_from_cache():
    caps = [{
        "auth_object": "F_LFA1_APP",
        "capability": "Edit vendor bank details (LFBK)",
        "tables": ["LFBK"],
        "severity": int(Severity.CRITICAL),
    }]
    s = _english_summary("SAPMAP00", "S4H", "001", caps, {})
    # Table named, but no fake count
    assert "LFBK" in s
    assert "0 rows" not in s
    assert "rows)" not in s


# --- end-to-end analyse() with mocked read_table ------------------

def test_analyse_end_to_end_creates_finding_and_result():
    """Synthetic node with one created user, one verified cred,
    and a mocked AGR_USERS / AGR_1251 response.  After analyse():
      * node.capability_results has one entry per (user, client)
      * node.findings has one entry per user
      * the highest-tier capability drives the Finding severity
    """
    state = SAPMAPState()
    node = SAPNode(sid="S4H", system_type="ABAP",
                    hostname="s4hanadev", ip="192.168.2.209",
                    is_production=True)
    state.add_node(node)
    node.created_users.append(CreatedUser(
        sid="S4H", username="SAPMAP00", client="001",
        hostname="s4hanadev", ip="192.168.2.209",
        instance_nr="00", method="gw_exploit"))

    def fake_read(node_arg, table_name, **kw):
        # AGR_USERS for SAPMAP00 → one role
        if table_name == "AGR_USERS":
            return [{"AGR_NAME": "Z_PWNED", "UNAME": "SAPMAP00"}]
        if table_name == "AGR_1251":
            # Two capabilities: vendor bank edit (CRIT) +
            # finance master read (HIGH).
            return [
                {"AGR_NAME": "Z_PWNED", "OBJECT": "F_LFA1_APP",
                 "FIELD": "APPKZ", "LOW": "E"},
                {"AGR_NAME": "Z_PWNED", "OBJECT": "S_TABU_DIS",
                 "FIELD": "DICBERCLS", "LOW": "FI"},
            ]
        return []

    with patch("sapmap_rfc.read_table", side_effect=fake_read):
        results = analyse(node)

    assert len(results) == 1
    r = results[0]
    assert r["username"] == "SAPMAP00"
    assert r["client"] == "001"
    objs = {c["auth_object"] for c in r["capabilities"]}
    assert "F_LFA1_APP" in objs
    assert "S_TABU_DIS" in objs
    assert "severe" in r["blast_radius"].lower()

    # Finding emitted on the node, severity = highest tier
    cap_findings = [f for f in node.findings
                     if f.name == "Role / profile capability inventory"]
    assert len(cap_findings) == 1
    assert cap_findings[0].severity == Severity.CRITICAL

    # Stored on the node for the report pipeline
    assert node.capability_results == results


def test_analyse_skips_non_abap_nodes():
    """Capability rules are ABAP-side; running against a Java-only
    box would just spam empty results."""
    node = SAPNode(sid="J75", system_type="JAVA")
    node.created_users.append(CreatedUser(
        sid="J75", username="J2EE_ADMIN", client="000",
        hostname="j75", ip="10.0.0.2", instance_nr="00",
        method="recon"))
    state = SAPMAPState()
    state.add_node(node)
    with patch("sapmap_rfc.read_table") as rt:
        results = analyse(node)
    assert results == []
    assert rt.called is False


def test_analyse_skips_when_no_users_to_analyse():
    """Pure-discovery node (no creds, no created users) ⇒ analyser
    no-ops cleanly."""
    state = SAPMAPState()
    node = SAPNode(sid="X", system_type="ABAP")
    state.add_node(node)
    with patch("sapmap_rfc.read_table") as rt:
        results = analyse(node)
    assert results == []
    assert rt.called is False


def test_analyse_synthesises_full_capability_set_for_sap_all_profile():
    """SAPMAP-created users land via BAPI_USER_PROFILES_ASSIGN with
    PROFILE=SAP_ALL — they have NO role assignments at all, so the
    role-based resolver alone produces zero capabilities (operator
    saw exactly this in the engagement report).  Detecting SAP_ALL
    in UST04 must synthesise the full rule-table as the user's
    capability set."""
    state = SAPMAPState()
    node = SAPNode(sid="S4H", system_type="ABAP",
                    hostname="s4hanadev", ip="192.168.2.209",
                    is_production=True)
    state.add_node(node)
    node.created_users.append(CreatedUser(
        sid="S4H", username="SAPMAP00", client="001",
        hostname="s4hanadev", ip="192.168.2.209",
        instance_nr="00", method="gw_exploit"))

    def fake_read(node_arg, table_name, **kw):
        if table_name == "AGR_USERS":
            # No roles — SAP_ALL was assigned via profile path
            return []
        if table_name == "UST04":
            return [{"BNAME": "SAPMAP00", "PROFILE": "SAP_ALL"}]
        return []

    with patch("sapmap_rfc.read_table", side_effect=fake_read):
        results = analyse(node)

    assert len(results) == 1
    r = results[0]
    # Full rule table synthesised — operator should see vendor-bank
    # edit, debugger-with-replace, finance master read, etc.
    objs = {c["auth_object"] for c in r["capabilities"]}
    assert "F_LFA1_APP" in objs
    assert "S_DEVELOP" in objs
    assert "S_TABU_DIS" in objs
    assert "S_RFC" in objs
    # Summary mentions the SAP_ALL grant explicitly
    assert "SAP_ALL" in r["summary"]
    # And every capability records the profile path in its `why`
    sample = r["capabilities"][0]
    assert "SAP_ALL profile" in sample["why"]
    # Finding emitted at CRITICAL severity (highest tier from any
    # synthesised capability)
    cap_findings = [f for f in node.findings
                     if f.name == "Role / profile capability inventory"]
    assert len(cap_findings) == 1
    assert cap_findings[0].severity == Severity.CRITICAL


def test_analyse_merges_role_caps_with_profile_caps():
    """A user with BOTH a role grant (S_TABU_DIS DICBERCLS=FI) AND
    SAP_ALL via profile should end up with the full profile-derived
    capability set, with the role-side `why` text preserved on the
    overlapping entries."""
    state = SAPMAPState()
    node = SAPNode(sid="S4H", system_type="ABAP")
    state.add_node(node)
    node.credentials.append(Credentials(
        username="JORIS", password="x", client="001", verified=True))

    def fake_read(node_arg, table_name, **kw):
        if table_name == "AGR_USERS":
            return [{"AGR_NAME": "Z_FI", "UNAME": "JORIS"}]
        if table_name == "AGR_1251":
            return [{"AGR_NAME": "Z_FI", "OBJECT": "S_TABU_DIS",
                     "FIELD": "DICBERCLS", "LOW": "FI"}]
        if table_name == "UST04":
            return [{"BNAME": "JORIS", "PROFILE": "SAP_ALL"}]
        return []

    with patch("sapmap_rfc.read_table", side_effect=fake_read):
        results = analyse(node)

    r = results[0]
    # Should have the FULL profile-derived set, not just the FI row
    assert len(r["capabilities"]) == len(_CAPABILITY_RULES)


def test_analyse_no_super_profile_no_synthesis():
    """Counter-test: a user holding only ordinary profiles (no
    SAP_ALL / SAP_NEW / S_A.SYSTEM) doesn't trigger synthesis.
    Only the role-based capabilities surface."""
    state = SAPMAPState()
    node = SAPNode(sid="S4H", system_type="ABAP")
    state.add_node(node)
    node.credentials.append(Credentials(
        username="HR_VIEWER", password="x", client="001", verified=True))

    def fake_read(node_arg, table_name, **kw):
        if table_name == "AGR_USERS":
            return [{"AGR_NAME": "Z_HR", "UNAME": "HR_VIEWER"}]
        if table_name == "AGR_1251":
            return [{"AGR_NAME": "Z_HR", "OBJECT": "P_ORGIN",
                     "FIELD": "INFTY", "LOW": "0008"}]
        if table_name == "UST04":
            return [{"BNAME": "HR_VIEWER", "PROFILE": "Z_HR_BASIC"}]
        return []

    with patch("sapmap_rfc.read_table", side_effect=fake_read):
        results = analyse(node)
    r = results[0]
    objs = {c["auth_object"] for c in r["capabilities"]}
    # Just the HR rule — no SAP_ALL synthesis
    assert objs == {"P_ORGIN"}
    assert "SAP_ALL" not in r["summary"]


def test_analyse_replaces_stale_results_for_same_user():
    """Re-running analyse() against the same user must overwrite
    the prior result, not stack a duplicate.  Operator may have
    revoked privileges between runs; the report should reflect
    current state."""
    state = SAPMAPState()
    node = SAPNode(sid="S4H", system_type="ABAP")
    state.add_node(node)
    node.credentials.append(Credentials(
        username="JORIS", password="x", client="001", verified=True))
    # Pre-populate a stale result with a fake capability
    node.capability_results = [{
        "username": "JORIS", "client": "001", "source": "credential",
        "capabilities": [
            {"auth_object": "OLD", "capability": "stale", "tables": [],
             "severity": 1}],
        "blast_radius": "stale", "summary": "stale",
    }]

    def fake_read(node_arg, table_name, **kw):
        if table_name == "AGR_USERS":
            return [{"AGR_NAME": "Z_NEW", "UNAME": "JORIS"}]
        if table_name == "AGR_1251":
            return [{"AGR_NAME": "Z_NEW", "OBJECT": "S_LOG_COM",
                     "FIELD": "COMMAND", "LOW": "*"},
                    {"AGR_NAME": "Z_NEW", "OBJECT": "S_LOG_COM",
                     "FIELD": "OPSYSTEM", "LOW": "*"}]
        return []

    with patch("sapmap_rfc.read_table", side_effect=fake_read):
        analyse(node)

    rs = [r for r in node.capability_results
          if r["username"] == "JORIS" and r["client"] == "001"]
    assert len(rs) == 1, ("stale result not replaced — found "
                            f"{len(rs)} entries")
    objs = {c["auth_object"] for c in rs[0]["capabilities"]}
    assert "OLD" not in objs
    assert "S_LOG_COM" in objs


# --- serialisation -------------------------------------------------

def test_capability_results_round_trip_through_state_serialisation():
    n = SAPNode(sid="S4H", system_type="ABAP",
                 hostname="s4h", ip="10.0.0.1")
    n.capability_results = [{
        "username": "SAPMAP00", "client": "001", "source": "created",
        "capabilities": [
            {"auth_object": "F_LFA1_APP", "fields": {"APPKZ": "E"},
             "capability": "Edit vendor bank details",
             "tables": ["LFBK"], "severity": 5}],
        "blast_radius": "severe",
        "summary": "User SAPMAP00 …",
    }]
    n.capability_row_counts = {"LFBK": 2107}
    d = n.to_dict()
    n2 = SAPNode.from_dict(d)
    assert n2.capability_results[0]["username"] == "SAPMAP00"
    assert n2.capability_row_counts["LFBK"] == 2107


# --- YAML export ---------------------------------------------------

def test_export_rules_yaml_emits_every_rule():
    """The YAML exporter is the contract operators extend with site-
    specific Z-objects.  Every rule in _CAPABILITY_RULES must show up
    in the output verbatim."""
    yml = export_rules_yaml()
    assert "rules:" in yml
    for obj, _pred, cap, _tables, _sev, _why in _CAPABILITY_RULES:
        assert obj in yml, f"YAML missing rule for {obj}"
        assert cap in yml or repr(cap) in yml, (
            f"YAML missing capability text {cap!r}")


def test_export_rules_yaml_includes_severity_legend_in_header():
    yml = export_rules_yaml()
    assert "5=CRITICAL" in yml
    assert "1=INFO" in yml
