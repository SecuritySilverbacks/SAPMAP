"""Tests for the modules.core.sapmap_remediation catalog + Finding /
emit_finding wiring."""
import json

import sapmap_attack
import sapmap_findings
import sapmap_remediation as rm
from sapmap_models import Finding, SAPMAPState, SAPNode, Severity


# ---------------------------------------------------------------------------
# Catalog integrity
# ---------------------------------------------------------------------------

def test_catalog_is_non_empty():
    assert len(rm.CATALOG) >= 15


def test_every_entry_has_summary_and_refs():
    """Every catalog entry must carry a one-line summary and at least
    one external reference — otherwise the report just says 'fix it'
    with no action."""
    bare = []
    for key, r in rm.CATALOG.items():
        if not r.fix_summary:
            bare.append((key, "no fix_summary"))
        if not r.refs:
            bare.append((key, "no refs"))
    assert not bare, f"catalog entries missing required fields: {bare}"


def test_every_capability_in_attack_map_has_remediation_or_explicit_exemption():
    """Either every capability key in sapmap_attack.CAPABILITY_MAP has a
    matching catalog entry, OR the key appears on the exemption list
    (info-only events with no security fix needed).  Keeps the two
    catalogs from drifting apart silently."""
    exempt = {
        # Info-only reconnaissance — observed by SAPMAP, no operator fix
        "recon.fast_scan", "recon.deep_scan", "recon.system_info",
        "recon.diag_scrape", "recon.sapcontrol_query",
        "recon.client_enum", "recon.user_enum",
        "recon.wd_fingerprint", "recon.wd_backends",
        "recon.scc_fingerprint", "recon.scc_relay",
        "recon.btp_subaccount_enum",
        # RFC_SYSTEM_INFO leak — pre-auth info-disclosure that SAP
        # accepts by design (SAP Note 927637 clarifies).  Awareness only.
        "recon.rfc_system_info_leak",
        # USREXTID / OA2C enumeration — read-only auth-table reads that
        # only work AFTER foothold.  The parent user-creation /
        # credential-access findings carry the actual fix.
        "recon.usrextid_read", "recon.oa2c_read",
        # WD backend-table read via authenticated WD admin — the WD
        # default-creds catalog entry already prescribes rotating the
        # WD admin password; no separate fix needed.
        "data.wd_backend_table_read",
        # SAProuter tunnel scan via NI_ROUTE — network-side discovery,
        # the fix is the standard SAProuter ACL hardening covered by
        # the existing saprouter-info catalog entry.
        "recon.saprouter_route_enum",
        # SNC posture check — passive read-only observation.  The
        # remediation (enable SNC + enforce) is a landscape-level
        # policy call, not a per-finding action.
        "recon.snc_posture",
        # Default-credential brute-force sweep against the ABAP kernel
        # — remediation for a HIT is "rotate the credentials" which
        # is already carried by creds.default_probe.  This key exists
        # to surface the SWEEP itself on the ATT&CK grid, not to
        # duplicate the vendor-fix guidance.
        "recon.brute_force_default",
        # PSE export via LPE / ticket-forge chain — the fix (rotate
        # SAPSYS.pse + refresh STRUSTSSO2 trust) is covered by the
        # ticket-forgery remediation the parent key carries.
        "data.pse_export",
        # Bulk ticket fanout — same remediation as single-ticket
        # replay (already exempt): rotate SAPSYS.pse.
        "lateral.ticket_propagate_all",
        # Mid-chain post-foothold capabilities; their parent persist/
        # lateral entry carries the operator fix.
        "exploit.sapxpg",
        "privesc.bapi_profiles", "privesc.webgui_rsbdcos0",
        "lateral.sapmap_user", "lateral.mysapsso2_replay",
        "lateral.sxpg_exec", "lateral.wd_pivot",
        "lateral.saprouter_tunnel", "lateral.scc_tunnel_impersonate",
        "lateral.internal_ip_spoof",
        # Cert-proxied HTTP lateral — post-foothold; fix is at the
        # STRUST + destination-config layer, covered by the SCC keystore
        # rotation catalog entry.
        "lateral.btp_cert_proxy", "lateral.cert_proxy_open",
        # LPE peditcow — same Linux-kernel-cred class as lpe.copyfail;
        # its parent catalog entry is the "keep kernel + libc patched"
        # advice already carried by copyfail/dirtyfrag.
        "lpe.peditcow",
        # WD icmauth extraction — remediation is "rotate WD admin
        # creds + rotate icmauth.txt", same shape as the WD default
        # creds entry; keep info-only until the WD catalog grows.
        "creds.wd_icmauth",
        # RanSAPware — operator-side impact demo, not a target
        # vulnerability with a vendor fix.  Awareness only.
        "ransapware.encrypt", "ransapware.decrypt",
        # Tier 3 evasion — operator-side OPSEC, no target fix.
        "evasion.death_star", "evasion.rsau_disable",
        # Persistence sub-actions covered by persist.create_user etc.
        "persist.sap_all_assign", "persist.ssh_key_plant",
        "persist.web_shell",
        # Cred-access modes covered by creds.abap_secstore / scc_keystore
        "creds.java_secstore", "creds.btp_destinations",
        "creds.scc_users_xml", "creds.oa2c_secrets",
        "creds.ssh_private_key",
        # SSH lateral movement — awareness-only, no vendor fix
        "lateral.ssh_key_reuse",
        # Collection — operator's own loot, not a target finding
        "data.read_table", "data.capability_analyse",
        "data.scc_users_dump", "data.scc_users_dump_via_lpe",
        "data.loot_stage",
        # DBCON direct-DB pivot (issue #21) — post-foothold; the
        # remediation (rotate the DBCON password, review who can
        # read RSECTAB) is landscape-policy not per-finding.
        "lateral.dbcon_direct", "data.dbcon_dump",
        # DBCON reconnaissance / enumeration / peek — same landscape
        # remediation as the parent lateral.dbcon_direct (rotate the
        # DBCON credential + tighten RSECTAB reads).  These keys
        # exist so the ATT&CK grid surfaces each discrete DBCON
        # action, not to duplicate vendor-fix guidance.
        "recon.dbcon_resolve", "recon.dbcon_probe",
        "recon.dbcon_hana_sweep", "recon.dbcon_enumerate",
        "recon.dbcon_describe",
        "data.dbcon_peek", "data.dbcon_custom_sql",
        "creds.dbcon_usr02_dump", "creds.dbcon_auth_dump",
        # CTS/TMS pivot (Bundle 1) — post-foothold reconnaissance
        # and cross-system logon.  The remediation (rotate TMSADM
        # password + tighten RSECTAB read auth + audit S_TRANSPRT
        # assignments) is landscape-policy not per-finding.  When
        # Bundle 2 (write primitives) ships, persist.transport_inject
        # will keep the same exemption note because the fix is still
        # policy-shape.
        "recon.tms_domain", "lateral.tmsadm_rfc",
        "recon.tms_buffer", "data.tms_transport_history",
    }
    missing = []
    for cap in sapmap_attack.CAPABILITY_MAP:
        if cap in rm.CATALOG or cap in exempt:
            continue
        missing.append(cap)
    assert not missing, (
        f"capability keys missing from BOTH remediation catalog AND "
        f"exemption list: {missing}.  Either add an entry to "
        f"sapmap_remediation.CATALOG or extend the exemption list with "
        f"a comment explaining why it's info-only.")


def test_severity_if_delayed_is_a_known_label():
    for key, r in rm.CATALOG.items():
        assert r.severity_if_delayed in ("CRITICAL", "HIGH", "MEDIUM", "LOW",
                                          "INFO"), (
            f"{key}: severity_if_delayed={r.severity_if_delayed!r}")


def test_effort_minutes_is_positive():
    for key, r in rm.CATALOG.items():
        assert r.effort_minutes > 0, f"{key} has zero effort_minutes"


def test_refs_are_well_formed_pairs():
    for key, r in rm.CATALOG.items():
        for ref in r.refs:
            assert isinstance(ref, tuple) and len(ref) == 2, \
                f"{key}: malformed ref {ref!r}"
            label, url = ref
            assert label and url
            assert url.startswith(("https://", "http://")), \
                f"{key}: ref url not http(s): {url}"


def test_round_trip_to_dict():
    r = rm.lookup("exploit.10kblaze")
    d = r.to_dict()
    s = json.dumps(d)            # must be JSON-clean
    revived = rm.Remediation.from_dict(json.loads(s))
    assert revived.fix_summary == r.fix_summary
    assert len(revived.fix_steps) == len(r.fix_steps)
    assert len(revived.refs) == len(r.refs)


# ---------------------------------------------------------------------------
# Wiring through emit_finding + bus mirror
# ---------------------------------------------------------------------------

def test_emit_finding_attaches_catalog_remediation():
    sapmap_findings.clear()
    rec = sapmap_findings.emit_finding(
        "CRITICAL", "S4H", "GW vuln test",
        attack_capability="exploit.10kblaze")
    assert rec is not None
    assert isinstance(rec["remediation"], dict)
    assert rec["remediation"]["fix_summary"]


def test_emit_finding_no_capability_leaves_remediation_empty():
    sapmap_findings.clear()
    rec = sapmap_findings.emit_finding(
        "CRITICAL", "S4H", "Unrelated event")
    assert rec is not None
    assert rec["remediation"] == {}


def test_bus_mirror_persists_structured_remediation():
    state = SAPMAPState()
    state.add_node(SAPNode(sid="S4H", ip="10.0.0.1"))
    sapmap_findings.attach_state(state)
    sapmap_findings.clear()

    sapmap_findings.emit_finding(
        "CRITICAL", "S4H", "ICMAD smuggle confirmed",
        attack_capability="exploit.cve_2022_22536")

    node = state.get_node("S4H")
    assert len(node.findings) == 1
    rem = node.findings[0].remediation
    assert isinstance(rem, dict)
    assert rem.get("fix_summary")
    assert any("3123396" in r[1] for r in rem.get("refs", []))
    sapmap_findings.attach_state(None)


def test_finding_dataclass_accepts_dict_remediation():
    rem = rm.lookup("creds.user_password_hash").to_dict()
    f = Finding(name="x", severity=Severity.CRITICAL, remediation=rem)
    d = f.to_dict()
    assert isinstance(d["remediation"], dict)
    revived = Finding.from_dict(d)
    assert isinstance(revived.remediation, dict)
    assert revived.remediation["fix_summary"]


def test_finding_dataclass_still_accepts_legacy_string():
    """Backward compatibility — every .sapmap state file we shipped
    pre-this-feature has remediation as a plain string."""
    f = Finding(name="x", severity=Severity.HIGH,
                 remediation="legacy plain string remediation")
    d = f.to_dict()
    assert d["remediation"] == "legacy plain string remediation"
    revived = Finding.from_dict(d)
    assert revived.remediation == "legacy plain string remediation"
