"""
sapmap_remediation.py — Hardening / fix-guidance catalog for SAPMAP findings.

Each entry maps a SAPMAP CAPABILITY_MAP key (the same one used by the
ATT&CK heatmap, defined in :mod:`sapmap_attack`) to a structured
``Remediation`` block: one-line fix summary, numbered concrete steps,
verification steps, deep-linked references, and effort / restart /
severity-if-delayed metadata.

The catalog is the single source of truth for "how do I close this
finding".  ``emit_finding(attack_capability=…)`` automatically attaches
the matching block to the bus record; the bus-mirror then persists the
structured remediation into ``SAPNode.findings`` so the GUI panel and
the engagement report both render it.

Content is written in SAPMAP's own voice (we summarise SAP Notes rather
than quoting them) so the catalog can be redistributed without licence
issues; for the authoritative text the references deep-link to
launchpad.support.sap.com or attack.mitre.org.

When a SAP Note gets superseded, bump LAST_REVIEWED on the affected
entry; the report flags any entry older than 12 months so the
maintainer knows to re-check the references.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


CATALOG_VERSION  = "2026-05-31"
LAST_REVIEWED    = "2026-05"


# ---------------------------------------------------------------------------
# Reference link helpers — wrapping the long URLs so the catalog itself
# stays readable.
# ---------------------------------------------------------------------------

def _note(number: int) -> Tuple[str, str]:
    """Build a (label, url) pair for a SAP Note."""
    return (f"SAP Note {number}",
            f"https://launchpad.support.sap.com/#/notes/{number}")


def _cve(cve_id: str) -> Tuple[str, str]:
    return (cve_id, f"https://nvd.nist.gov/vuln/detail/{cve_id}")


def _attack(tech_id: str) -> Tuple[str, str]:
    return (f"MITRE {tech_id}",
            f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Remediation:
    """A structured fix-guidance block for a class of finding."""

    fix_summary:         str            # one-line, scannable
    fix_steps:           List[str] = field(default_factory=list)
    verification:        List[str] = field(default_factory=list)
    refs:                List[Tuple[str, str]] = field(default_factory=list)
    requires_restart:    bool = False
    effort_minutes:      int = 30
    severity_if_delayed: str = "HIGH"   # HIGH or CRITICAL — what stays open
    last_reviewed:       str = LAST_REVIEWED

    def to_dict(self) -> Dict:
        return {
            "fix_summary":         self.fix_summary,
            "fix_steps":           list(self.fix_steps),
            "verification":        list(self.verification),
            "refs":                [list(r) for r in self.refs],
            "requires_restart":    bool(self.requires_restart),
            "effort_minutes":      int(self.effort_minutes),
            "severity_if_delayed": self.severity_if_delayed,
            "last_reviewed":       self.last_reviewed,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "Remediation":
        return cls(
            fix_summary=d.get("fix_summary", ""),
            fix_steps=list(d.get("fix_steps", [])),
            verification=list(d.get("verification", [])),
            refs=[tuple(r) for r in d.get("refs", []) if len(r) >= 2],
            requires_restart=bool(d.get("requires_restart", False)),
            effort_minutes=int(d.get("effort_minutes", 30)),
            severity_if_delayed=d.get("severity_if_delayed", "HIGH"),
            last_reviewed=d.get("last_reviewed", ""),
        )


# ---------------------------------------------------------------------------
# Catalog — one entry per capability key in CAPABILITY_MAP
#
# Capabilities NOT mapped here either fall back to no structured
# remediation (legacy plain-string remediation on Finding still
# renders), or are info-only events with no security fix needed
# (e.g. snc.scan, recon.fast_scan).
# ---------------------------------------------------------------------------

CATALOG: Dict[str, Remediation] = {

    # =========================================================================
    # Initial Access / Execution
    # =========================================================================

    "exploit.10kblaze": Remediation(
        fix_summary=(
            "Lock down the SAP Gateway: enforce reginfo / secinfo ACLs "
            "and disable sim_mode"
        ),
        fix_steps=[
            "Edit reginfo (path in profile parameter gw/reg_info) and "
            "secinfo (gw/sec_info) to add explicit P/D entries — every "
            "registered TP and every started external program must have "
            "an allow-line naming the source HOST and TP.  Replace any "
            "wildcard 'P TP=* HOST=*' lines with the actual application "
            "server hostnames.",
            "In the instance profile (DEFAULT.PFL or per-instance .PFL) "
            "set: gw/acl_mode = 1 (enforce ACLs), gw/sim_mode = 0 (stop "
            "logging-only mode), gw/reg_no_conn_info = 1.",
            "Activate the new ACL without a downtime by running `gwmon` "
            "and selecting Re-read ACL files, OR restart the dispatcher "
            "to ensure all worker processes pick up the new policy.",
            "Audit /usr/sap/<SID>/<INST>/work/dev_rd for prior unauthorised "
            "REGISTER_TP or SAPXPG calls during the gap window; rotate "
            "any system passwords reachable from the SAPXPG OS account.",
        ],
        verification=[
            "Re-run SAPMAP → right-click node → Exploitation → "
            "Check GW Vulnerabilities.  The gw_vulnerable badge must "
            "drop from red to clear and the per-port verifier should "
            "report sapxpg init rejected.",
            "From an external attacker host run `gwmon -gw_host <gw> "
            "-cmd 'pf=…' -V` and confirm REGISTER_TP for PROGRAM=sapxpg "
            "from your IP is rejected with a 'reginfo: deny' line in "
            "dev_rd.",
        ],
        refs=[
            _note(1408081),
            _note(1425765),
            _note(1444282),
            _attack("T1190"),
        ],
        requires_restart=False,    # gwmon Re-read avoids downtime
        effort_minutes=45,
        severity_if_delayed="CRITICAL",
    ),

    "exploit.ms_betrusted": Remediation(
        fix_summary=(
            "Firewall the Message Server internal port (39NN), enforce "
            "ms/acl_info, and disable open monitoring"
        ),
        fix_steps=[
            "On each ABAP/Java instance profile set: ms/monitor = 0 (no "
            "open monitor), ms/admin_port = 0 (close admin if not used), "
            "and configure ms/acl_info pointing to a host-allow file "
            "that lists only the application servers' IPs.",
            "Network-layer: block 39NN inbound at the perimeter and on "
            "the management VLAN — the message server internal port "
            "must never be reachable from a client/workstation network.",
            "If ms/server_ip_check is supported on your kernel, set it "
            "to 1 to additionally reject MS-internal traffic from "
            "unknown sources at the protocol layer.",
            "Verify there's no application directly relying on the "
            "internal port; legitimate MS clients use ms/http_port "
            "(81NN) which is auth'd.",
        ],
        verification=[
            "Re-run SAPMAP → Check All 10KBlaze (MS Betrusted).  The "
            "ms_vulnerable badge must clear; the per-node check should "
            "report 'ACL active, blocked' or 'port closed'.",
            "From a workstation that should NOT have MS access, run "
            "`nc -zv <ms-host> 39NN` — the connection must be refused "
            "or filtered.",
        ],
        refs=[
            _cve("CVE-2020-6207"),
            _attack("T1190"),
        ],
        requires_restart=True,    # ms/acl_info read at startup
        effort_minutes=60,
        severity_if_delayed="CRITICAL",
    ),

    "exploit.ms_ascs_gw_rogue": Remediation(
        fix_summary=(
            "Apply SAP Security Note 3759472 (CVE-2026-58240) — kernel "
            "binary patch; no workaround"
        ),
        fix_steps=[
            "Apply the fixed kernel patch level for your release: "
            "9.16 PL100, 9.18 PL032, 9.19 PL017, 9.20 PL007.  Older "
            "kernels (pre-9.x) don't have the vulnerable opcode family "
            "and are not affected by this note.",
            "The patch adds a post-parse check on the MS_ASCS_GW_LOGON "
            "opcode ('logon not made on the internal port' / 'logon "
            "not made from the ASCS host') — rogue registrations are "
            "rejected at the opcode layer regardless of ACL.",
            "Defence in depth: enable system/secure_communication = ON "
            "(or ms/enforce_secure_communication = ON) — this blocks "
            "plaintext MS_LOGIN_2 from any source and makes the "
            "vulnerable opcode unreachable without an SNC channel.  "
            "SAPMAP confirms this via SAPControl ParameterValue during "
            "the check phase and reports it as a compensating control.",
            "Network layer: firewall the internal MS port (39NN) to "
            "the application-server subnet only.  The external "
            "sapms<SID> port (36NN) can stay open for name lookup but "
            "should not accept mutating opcodes from arbitrary hosts.",
        ],
        verification=[
            "Re-run SAPMAP → Check All CVE-2026-58240.  A patched "
            "kernel produces evidence 'confirmed_patched' after the "
            "register step; unpatched produces 'confirmed_vulnerable' "
            "with a CRITICAL finding.",
            "Verify the kernel binary contains the patched trace "
            "strings: `strings msg_server | grep 'ASCS gateway "
            "logoff'` returns a hit only on PL100+ / PL032+ / PL017+ "
            "/ PL007+.",
        ],
        refs=[
            _cve("CVE-2026-58240"),
            _attack("T1190"),
            _attack("T1078"),
            _attack("T1557"),
        ],
        requires_restart=True,    # kernel patch → sapstartsrv restart
        effort_minutes=120,
        severity_if_delayed="CRITICAL",
    ),

    "exploit.cve_2025_31324": Remediation(
        fix_summary=(
            "Patch VisualComposer; remove dropped JSP webshells; restrict "
            "/developmentserver/ access"
        ),
        fix_steps=[
            "Apply the SAP Security Patch for VisualComposer per SAP "
            "Note 3594142 — version depends on the J2EE kernel of your "
            "AS Java install (find with /sap/public/info → SAPRel).",
            "Audit /irj/root/ on every AS Java instance for unexpected "
            "JSPs; SAPMAP drops JSPs with random 4-letter prefixes such "
            "as 'abcd_<timestamp>.jsp'.  Search for any *.jsp modified "
            "after the engagement window started and delete any not "
            "belonging to a known SAP component.",
            "Until the patch is fully deployed, take /developmentserver/ "
            "offline at the ICM rewrite layer (SICF deactivate the "
            "service tree or block the path at a reverse proxy).",
            "If you suspect the webshell ran arbitrary code: assume the "
            "AS Java service account is compromised; rotate any "
            "credentials that SAP service principal had (SecStoreFS, "
            "any RFC destinations using SSO, file-system PSEs).",
        ],
        verification=[
            "Re-run SAPMAP → Check All CVE-2025-31324.  The "
            "cve_2025_31324_vulnerable badge must drop.",
            "Curl the metadatauploader endpoint as an unauth user; "
            "expect HTTP 401/403 rather than the buggy 200 upload "
            "response.",
            "Diff /irj/root/ filesystem listing against a known-good "
            "baseline to confirm no leftover JSPs.",
        ],
        refs=[
            _note(3594142),
            _cve("CVE-2025-31324"),
            _attack("T1190"),
            _attack("T1505.003"),
        ],
        requires_restart=True,    # AS Java patch restart
        effort_minutes=120,
        severity_if_delayed="CRITICAL",
    ),

    "exploit.cve_2020_6287": Remediation(
        fix_summary=(
            "Patch the LM Configuration Wizard (RECON); audit for "
            "unauthorised admin accounts"
        ),
        fix_steps=[
            "Apply SAP Note 2934135 (master Note for CVE-2020-6287) at "
            "the patch level matching your kernel — covers both the "
            "/CTCWebService/ unauth bypass and the auto-create-admin "
            "logic.",
            "List all SAP* / J2EE administrator users created since "
            "the engagement window; look for SAPMAP-style names "
            "(SAPMAP00, JORIS, etc.) AND any unfamiliar names with "
            "Administrators role.  Disable / delete every account "
            "that wasn't legitimately provisioned.",
            "Until the patch is fully deployed, take /CTCWebService/ "
            "offline at the ICM rewrite layer or block the path on "
            "the reverse proxy.",
        ],
        verification=[
            "Re-run SAPMAP → Check All CVE-2020-6287 (RECON).  "
            "The cve_2020_6287_vulnerable badge must drop.",
            "POST a known-bad SOAP envelope to /CTCWebService/ as an "
            "unauth user; expect HTTP 401 or a SOAP fault, not the "
            "user-creation success response.",
        ],
        refs=[
            _note(2934135),
            _cve("CVE-2020-6287"),
            _attack("T1190"),
            _attack("T1136.001"),
        ],
        requires_restart=True,
        effort_minutes=120,
        severity_if_delayed="CRITICAL",
    ),

    "exploit.cve_2022_22536": Remediation(
        fix_summary=(
            "Patch ICM / Web Dispatcher (ICMAD HTTP smuggling); audit "
            "for upstream cache poisoning"
        ),
        fix_steps=[
            "Apply SAP Note 3123396 to every ICM/WD instance — kernel "
            "patch fixes the MPI Content-Length smuggling.  Confirm "
            "the kernel patch level matches the Note's required "
            "minimum before considering the fix complete.",
            "If wdisp/cache_enabled = 1 was observed during the "
            "engagement (SAPMAP flagged this as a chain enabler), "
            "review the WD cache state file in /usr/sap/<SID>/<INST>/"
            "data/wdisp_cache for poisoned entries and clear the "
            "cache if any suspicious entries exist.",
            "If ICMAD ACL bypass landed on the /heapdump/ path "
            "during the engagement: assume the AS Java heap was "
            "captured; rotate every secret that lived in that heap "
            "(SecStoreFS keys, JDBC passwords, SSO secrets, BTP "
            "destinations).",
        ],
        verification=[
            "Re-run SAPMAP → Check All CVE-2022-22536 (ICMAD).  "
            "The cve_2022_22536_vulnerable badge must drop.",
            "Hand-craft the canonical smuggle request and observe the "
            "second backend response is NOT received unauthenticated.",
        ],
        refs=[
            _note(3123396),
            _cve("CVE-2022-22536"),
            _attack("T1190"),
            _attack("T1574"),
        ],
        requires_restart=True,
        effort_minutes=90,
        severity_if_delayed="CRITICAL",
    ),

    # =========================================================================
    # Credential Access
    # =========================================================================

    "creds.default_probe": Remediation(
        fix_summary=(
            "Rotate the default credentials immediately and disable / "
            "lock the default accounts they belong to"
        ),
        fix_steps=[
            "Log in as the affected default user (SAP*, DDIC, TMSADM, "
            "EARLYWATCH, SAPCPIC, etc.) in every client where it exists "
            "and either DELETE the account where SAP doesn't require "
            "it, or change the password to a high-entropy random value "
            "AND set User type = System / Service so dialog logon is "
            "disabled.  For SAP* in client 000 keep the account but "
            "set login/no_automatic_user_sapstar = 1.",
            "Run report RSUSR003 — SAPMAP exercises the same checks.  "
            "Every line returning 'Default password set' is an open "
            "finding.",
            "Add ZSU01_DEFAULT_PWD_CHECK (or your basis-team's daily "
            "audit job) to spot regressions when a new client gets "
            "created.",
        ],
        verification=[
            "Re-run SAPMAP → Default Credentials Probe.  All previous "
            "matches must show 'rejected' on the next pass.",
            "Execute RSUSR003 from a basis user; output must say "
            "'no findings'.",
        ],
        refs=[
            _note(1414256),     # SAP* client-000 logon restriction
            _note(2293011),     # default-password hardening
            _attack("T1078.001"),
        ],
        requires_restart=False,
        effort_minutes=60,
        severity_if_delayed="CRITICAL",
    ),

    "creds.user_password_hash": Remediation(
        fix_summary=(
            "Treat every user as compromised: rotate all passwords, "
            "force CODVN H, and harden access to USR02"
        ),
        fix_steps=[
            "Force a password reset for every user in every client of "
            "the affected SID — SAPMAP captured the BCODE/PASSCODE/"
            "PWDSALTEDHASH fields, which offline crackers will resolve "
            "for any password below your password-policy minimum.",
            "Set login/password_downwards_compatibility = 0 and "
            "login/password_hash_algorithm = encoding=RFC2307, "
            "algorithm=iSSHA-512, iterations=10000, saltsize=128 "
            "so newly-set passwords are stored only as PWDSALTEDHASH "
            "(CODVN H) — no more half-hash BCODE for the cracker to "
            "feast on.",
            "Run report CLEANUP_PASSWORD_HASH_VALUES to remove the "
            "legacy BCODE/PASSCODE columns for users whose passwords "
            "have been rotated; this collapses the cracker's attack "
            "surface to the iSSHA-512 hash only.",
            "Restrict S_TABU_DIS / S_TABU_NAM authorisations so only a "
            "tightly-controlled list of basis admins can read USR02 / "
            "USRPWDHISTORY / USH02 — those are the tables SAPMAP "
            "extracted from.",
        ],
        verification=[
            "Re-run SAPMAP → Extract Hashes for Cracking after a "
            "non-admin RFC logon; expect S_TABU_DIS or RFC authorisation "
            "rejection on the USR02 read.",
            "Query USR02: every row's CODVN should be 'H' (or higher); "
            "no 'B' / 'D' / 'E' / 'F' / 'G' codes remain except for "
            "system-supplied compatibility rows.",
        ],
        refs=[
            _note(1458262),     # password hashing
            _note(2293011),     # password policy hardening
            _attack("T1003"),
        ],
        requires_restart=False,
        effort_minutes=180,    # touches every user
        severity_if_delayed="CRITICAL",
    ),

    "creds.abap_secstore": Remediation(
        fix_summary=(
            "Rotate every credential SAPMAP extracted from RSECTAB; "
            "restrict access to the secure store"
        ),
        fix_steps=[
            "Each row SAPMAP recovered from RSECTAB is a credential the "
            "operator now holds.  For each row: identify the destination "
            "(RFC dest, OA2C client, HTTPS dest, file-system creds) and "
            "rotate the corresponding password / client secret / key in "
            "the destination system.",
            "Replace the destination's stored secret via SM59 / OA2C_CONFIG "
            "/ STRUST etc.; SAPMAP-extracted values are now public to "
            "the engagement and any system that previously used them "
            "with the same value is at risk.",
            "Restrict S_TABU_DIS for table RSECTAB to the single SAP* / "
            "DDIC operator account.  Add an audit log alert on SE16 / "
            "SE16N / RFC_READ_TABLE access to RSECTAB.",
        ],
        verification=[
            "From a non-admin user attempt RFC_READ_TABLE on RSECTAB; "
            "expect authorisation failure.",
            "Re-run any RFC destination that was extracted with the new "
            "password; logon must succeed with the new value and fail "
            "with the old one.",
        ],
        refs=[
            _note(1485029),     # securing the secure store
            _attack("T1555"),
        ],
        requires_restart=False,
        effort_minutes=240,    # depends on number of credentials
        severity_if_delayed="CRITICAL",
    ),

    "creds.scc_keystore": Remediation(
        fix_summary=(
            "Treat the SCC private keys + users.xml as compromised; "
            "regenerate the keystore and the SCC admin password"
        ),
        fix_steps=[
            "Generate a new TLS keypair for the SCC<->BTP tunnel and "
            "re-pair the SCC with the subaccount (SCC admin UI → Cloud "
            "→ Subaccount → Edit).  The previous tunnel key is in the "
            "operator's hands.",
            "Replace the SCC's principal-propagation CA private key "
            "(SCC admin UI → Cloud → Connector → Principal Propagation "
            "→ Generate new CA).  Cycle every cloud-side trust "
            "configuration that referenced the old CA cert.",
            "Rotate the SCC admin user password (SCC admin UI → Settings "
            "→ User).  Replace the default Administrator/manage credential "
            "if it was in the catalogue.",
            "Audit SCC mappings (resources.xml / accessControl.xml) for "
            "unauthorised entries added during the engagement window.",
        ],
        verification=[
            "Confirm new TLS cert is presented when curling the SCC "
            "admin UI on :8443 (cert fingerprint changed).",
            "Subaccount → Cloud Connectors should show the new public "
            "key fingerprint on the BTP side.",
        ],
        refs=[
            ("SAP help — SCC hardening",
             "https://help.sap.com/docs/connectivity/sap-btp-connectivity-cf/cloud-connector"),
            _attack("T1555"),
            _attack("T1552.004"),
        ],
        requires_restart=False,
        effort_minutes=180,
        severity_if_delayed="HIGH",
    ),

    "creds.pse_loot": Remediation(
        fix_summary=(
            "Regenerate every PSE / SSO2 ticket signing key the operator "
            "extracted; rotate the SAPSYS keypair"
        ),
        fix_steps=[
            "For every PSE file SAPMAP recovered (SAPSYS, SSL server "
            "PSE, SSL client PSE, ticket signing PSE): generate a new "
            "keypair via STRUST and re-distribute the public cert to "
            "every trusting system.  Old keys must be considered "
            "compromised end-to-end.",
            "Rotate the MYSAPSSO2 ticket-signing key (the system's own "
            "SAPSYS) in STRUSTSSO2 — every system in the trust "
            "subgraph must re-trust the new cert.",
            "Invalidate any sessions established on the old key by "
            "raising login/ticket_only_by_https = 1 (force re-auth) or "
            "running RZ_INVALIDATE_TICKETS.",
        ],
        verification=[
            "Old SSO2 cookies signed with the previous key must now be "
            "rejected by every system in the trust subgraph.",
            "STRUST shows new fingerprints for SAPSYS / SSL.",
        ],
        refs=[
            _note(2724788),     # PSE rotation guidance
            _attack("T1552.004"),
            _attack("T1606"),
        ],
        requires_restart=False,
        effort_minutes=240,
        severity_if_delayed="CRITICAL",
    ),

    # =========================================================================
    # Lateral Movement / Persistence
    # =========================================================================

    "lateral.rfc_propagate": Remediation(
        fix_summary=(
            "Delete the SAPMAP-created users on the propagation target, "
            "tighten the source RFC destination's trust, and constrain "
            "the destination's logon user to least privilege"
        ),
        fix_steps=[
            "On every target where SAPMAP propagated, delete the created "
            "user (default SAPMAP00, or whichever name the operator "
            "chose) via SU01.  Also rotate the password of the source "
            "destination's RFC user if the destination is type-3 with "
            "stored credentials.",
            "Restrict the privileges of the user the RFC destination "
            "logs on with.  The destination's user in SM59 should NOT "
            "have SAP_ALL / SAP_NEW / S_USER_GRP / S_DEVELOP.  Replace "
            "with a tightly-scoped role that only carries the auth "
            "objects the destination actually needs (e.g. RFC_FB to a "
            "specific function group, S_RFC for the named function "
            "modules).  If the destination performs only BAPI calls, "
            "the logon user should be a Communications (C) user — not "
            "a Dialog (A) user — so it can't be reused for SAP GUI "
            "logon.",
            "Audit each Type-3 RFC destination on the SOURCE that "
            "permitted propagation (SM59) — destinations that store "
            "passwords / use TrustedRFC to a target with weak ACLs are "
            "the propagation primitive.  Either remove stored "
            "credentials and rely on SSO tickets, or convert the link "
            "to a service-bus pattern that doesn't grant SAP_ALL.",
            "On the TARGET review trusted-system entries in SMT1: "
            "remove any source SID that isn't strictly required.  "
            "TrustedRFC paths from a source with weak ACLs let the "
            "source compromise propagate to the target with zero auth.",
        ],
        verification=[
            "SU01 search for SAPMAP* / the SAPMAP user prefix on every "
            "node returns 'not found'.",
            "Re-run SAPMAP → Auto-Propagate; expect 'BAPI rejected: "
            "authorisation failure' on the destinations the operator "
            "previously exploited.",
        ],
        refs=[
            _note(128447),      # trusted RFC hardening
            _note(1444282),
            _attack("T1021"),
            _attack("T1078"),
        ],
        requires_restart=False,
        effort_minutes=120,
        severity_if_delayed="CRITICAL",
    ),

    "lateral.mysapsso2_forge": Remediation(
        fix_summary=(
            "Rotate the issuing system's SAPSYS keypair; invalidate "
            "every previously-issued MYSAPSSO2 ticket"
        ),
        fix_steps=[
            "Generate a new SAPSYS keypair on the system whose private "
            "key was used to forge (STRUSTSSO2 → SAPSYS → Replace).  "
            "Distribute the new public cert to every system listed in "
            "STRUSTSSO2's trust subgraph.",
            "Force every system in the subgraph to re-import the new "
            "issuer cert and remove the old fingerprint.  Until each "
            "consumer has the new public key, previously-forged "
            "tickets remain accepted there.",
            "Run RSAS_UTIL → cleanup invalid SSO2 tickets, or just "
            "wait out the configured ticket lifetime.  Forged tickets "
            "have a 12-hour validity by default — assume any session "
            "established within that window is the operator.",
        ],
        verification=[
            "Old ticket cookies fail with 'SSO2 cert not trusted' on "
            "every system in the subgraph.",
            "STRUSTSSO2 shows the new SAPSYS fingerprint.",
        ],
        refs=[
            _note(2724788),
            _attack("T1606"),
        ],
        requires_restart=False,
        effort_minutes=180,
        severity_if_delayed="CRITICAL",
    ),

    # =========================================================================
    # Persistence (transport import is the most extreme persistence we ship)
    # =========================================================================

    "persist.transport_addtobuffer": Remediation(
        fix_summary=(
            "Drop the staged transport from the STMS import buffer "
            "BEFORE anyone imports it"
        ),
        fix_steps=[
            "Identify the trkorr from the finding (e.g. A4HK900111).  "
            "On the target run `tp delfrombuffer <TRKORR> <SID> pf=…` "
            "to remove the entry from the buffer.  This neutralises "
            "the staging step — until import runs, no code is "
            "deployed.",
            "Delete the staged cofile + datafile from the target's "
            "/usr/sap/trans/{cofiles,data}/ directories so the staged "
            "transport can't be re-added by another route.",
            "Audit STMS Import Overview (STMS_QA) for any unexpected "
            "queue entries; the buffer can carry multiple staged "
            "transports.",
            "If you have GW-vulnerable systems on the same domain, "
            "follow the exploit.10kblaze remediation — the buffer "
            "add itself required SAPXPG OS-exec which means the "
            "gateway is the underlying primitive to close.",
        ],
        verification=[
            "`tp showbuffer <SID> pf=…` no longer lists the trkorr.",
            "/usr/sap/trans/cofiles/K<num>.<src_sid> and "
            "/usr/sap/trans/data/R<num>.<src_sid> are absent.",
        ],
        refs=[
            ("SAP help — STMS Import Queue management",
             "https://help.sap.com/docs/SAP_NETWEAVER/cts"),
            _attack("T1505"),
            _attack("T1213"),
        ],
        requires_restart=False,
        effort_minutes=15,
        severity_if_delayed="CRITICAL",   # the staged transport can still be imported by anyone
    ),

    "persist.transport_import": Remediation(
        fix_summary=(
            "Remove the imported transport's objects; verify no "
            "backdoor ABAP / role / table content survives"
        ),
        fix_steps=[
            "Identify the trkorr from the report's persist.transport_import "
            "finding (e.g. A4HK900111).  In SE03 view the transport's "
            "object list; every object the import created or modified "
            "must be inspected.",
            "Roll the affected objects back to the pre-import version "
            "(SE03 → Find Requests → restore previous version), OR "
            "manually delete each object created by the transport "
            "(SE38 for programs, PFCG for roles, SE11 for tables / DDIC).",
            "If the transport was a role transport: re-generate every "
            "user assignment for the affected roles after the rollback "
            "(PFCG → User Comparison) and audit AGR_USERS for unexpected "
            "role grants.",
            "Audit the system change history (DBTABLOG, /SDF/ table) "
            "for any data-dictionary changes the imported transport "
            "made — the import runs as a privileged ABAP context and "
            "can plant logon exits, BAdI implementations, or password "
            "hooks that survive object deletion.",
        ],
        verification=[
            "SE03 → Find Request shows the trkorr in 'IMPORTED' status "
            "BEFORE the rollback; AFTER the rollback every object "
            "should be 'inactive' or marked as restored.",
            "Re-run SAPMAP → Retrieve RFC Connections and Capability "
            "Analyser; expect no traces of the planted objects.",
        ],
        refs=[
            _attack("T1505"),
            _attack("T1059"),
            _attack("T1098"),
        ],
        requires_restart=False,    # rollback is online
        effort_minutes=240,        # depends on transport size
        severity_if_delayed="CRITICAL",
    ),

    "persist.create_user": Remediation(
        fix_summary=(
            "Delete the operator-created SAPMAP users; audit AGR_USERS "
            "for any role grants the operator made"
        ),
        fix_steps=[
            "On every system the report names: SU01 → search "
            "SAPMAP* (or your operator's preferred prefix) → DELETE "
            "every match in every client.  Also delete any "
            "non-SAPMAP user created during the engagement window.",
            "Query AGR_USERS for FROM_DAT after the engagement start; "
            "remove any role grant the operator added.  SAPMAP-created "
            "users routinely get SAP_ALL — that ROLE grant survives the "
            "user deletion if you only delete via SU01.",
            "Search USREXTID for any X.509 mapping added during the "
            "engagement window; certificate-based logon survives a "
            "password reset and a USR02 cleanup.",
        ],
        verification=[
            "USR02 has no rows matching the SAPMAP user prefix in any "
            "client.",
            "AGR_USERS has no rows with FROM_DAT > engagement-start AND "
            "username matching the prefix.",
        ],
        refs=[
            _attack("T1136.001"),
            _attack("T1098"),
        ],
        requires_restart=False,
        effort_minutes=60,
        severity_if_delayed="CRITICAL",
    ),

    # =========================================================================
    # Privilege Escalation
    # =========================================================================

    "privesc.dpmon_sap_star": Remediation(
        fix_summary=(
            "Disable dpmon virtual SAP* (kernel 790+); restrict OS-exec "
            "to <sid>adm with explicit auditing"
        ),
        fix_steps=[
            "Apply SAP Note 3303172 mitigation: set the kernel parameter "
            "rdisp/vserver/dpmon_sap_star = 0 in DEFAULT.PFL (default "
            "value on the patched kernel; explicit setting documents "
            "intent).  Without this, anyone with <sid>adm OS access can "
            "request a SAP* OTP for any client.",
            "Restrict OS access on the SAP host: only basis admins "
            "should be able to log in as <sid>adm.  Combined with the "
            "kernel parameter this closes the SAP* OTP loop.",
            "Enable OS-level audit (auditd / Windows Security Event "
            "Log) on every dpmon invocation so future use is logged.",
        ],
        verification=[
            "Re-run SAPMAP → dpmon SAP* creation against the node; "
            "expect 'dpmon SAP* disabled by kernel parameter'.",
            "RZ11 → rdisp/vserver/dpmon_sap_star = 0 (read-only post-"
            "boot).",
        ],
        refs=[
            _note(3303172),
            _attack("T1068"),
            _attack("T1078"),
        ],
        requires_restart=True,
        effort_minutes=30,
        severity_if_delayed="HIGH",
    ),

    # =========================================================================
    # Linux LPE — host-level kernel patches, not SAP-level config
    # =========================================================================

    "lpe.copyfail": Remediation(
        fix_summary=(
            "Patch the Linux kernel (CVE-2026-31431) to a fixed level; "
            "disable AF_ALG socket family if patch can't ship yet"
        ),
        fix_steps=[
            "Update the host's Linux kernel to a version that contains "
            "the CVE-2026-31431 fix for the af_alg AEAD copyfail.  Check "
            "vendor advisories: RHEL/SLES/Ubuntu each carry their own "
            "backport release notes.",
            "Until the kernel update ships, mitigate by disabling the "
            "AF_ALG socket family: add `install algif_skcipher /bin/true` "
            "to /etc/modprobe.d/sapmap-mitig.conf and remove any loaded "
            "algif_* modules (`rmmod algif_skcipher algif_aead`).",
            "Also remove Python3 from the SAPXPG exec path (the LPE "
            "chain rides python3) if you cannot patch and don't need it "
            "for ops.  Belt-and-braces, not a complete fix.",
        ],
        verification=[
            "Re-run SAPMAP → Check Linux LPE.  copyfail_vulnerable must "
            "drop to False.",
            "`uname -r` shows the patched version; `lsmod | grep algif` "
            "shows nothing if you used the modprobe mitigation.",
        ],
        refs=[
            _cve("CVE-2026-31431"),
            _attack("T1068"),
        ],
        requires_restart=True,
        effort_minutes=60,
        severity_if_delayed="HIGH",
    ),

    "lpe.dirtyfrag": Remediation(
        fix_summary=(
            "Patch the Linux kernel (xfrm-ESP + RxRPC) to a fixed level; "
            "disable RxRPC if not in use"
        ),
        fix_steps=[
            "Update the host's Linux kernel to a version that contains "
            "the dirty-frag patches for both xfrm-ESP and the RxRPC "
            "page-cache write primitive.  Check vendor backport notes.",
            "If RxRPC is not in use (it's only needed for AFS — most "
            "SAP installs don't use it), blacklist it: "
            "`install rxrpc /bin/true` in /etc/modprobe.d/.  Reduces "
            "the LPE surface by half regardless of kernel patch level.",
            "Restrict CAP_NET_ADMIN to root only (no setcap'd "
            "binaries should hold it).  CAP_NET_ADMIN is the prereq "
            "for the xfrm-ESP path and shouldn't leak to unprivileged "
            "users.",
        ],
        verification=[
            "Re-run SAPMAP → Check Linux LPE.  dirtyfrag_vulnerable must "
            "drop to False.",
        ],
        refs=[
            _attack("T1068"),
        ],
        requires_restart=True,
        effort_minutes=60,
        severity_if_delayed="HIGH",
    ),

    # =========================================================================
    # Windows LPE
    # =========================================================================

    "lpe.miniplasma": Remediation(
        fix_summary=(
            "Patch Windows (CVE-2020-17103 cldflt.sys) and apply Microsoft's "
            "WER scheduled-task hijack mitigation"
        ),
        fix_steps=[
            "Microsoft's original CVE-2020-17103 patch shipped in MS20-"
            "patches but the Nightmare-Eclipse 2025 reinvestigation "
            "showed cldflt.sys was silently un-patched on certain "
            "WSUS branches.  Update Windows to the latest cumulative "
            "AND verify cldflt.sys version (file properties → "
            "Details) is >= 10.0.19041.4291.",
            "Disable Cloud Files Filter Driver if no OneDrive / Files "
            "On-Demand is used: `sc.exe config cldflt start= disabled`.",
            "Harden Windows Error Reporting scheduled-task: remove "
            "Microsoft\\Windows\\Windows Error Reporting\\* tasks that "
            "the SAP service account can schedule, OR move the SAP "
            "service to its own non-SeImpersonate account.",
        ],
        verification=[
            "Re-run SAPMAP → Check Windows LPE.  miniplasma_vulnerable "
            "must drop to False.",
            "PowerShell: (Get-Item C:\\Windows\\System32\\drivers\\cldflt.sys"
            ").VersionInfo.FileVersion ≥ 10.0.19041.4291",
        ],
        refs=[
            _cve("CVE-2020-17103"),
            _attack("T1068"),
        ],
        requires_restart=True,
        effort_minutes=90,
        severity_if_delayed="HIGH",
    ),

    "lpe.efspotato": Remediation(
        fix_summary=(
            "Strip SeImpersonatePrivilege from SAP service accounts; "
            "harden MS-EFSRPC against lsass coercion"
        ),
        fix_steps=[
            "Run secpol.msc → Local Policies → User Rights Assignment "
            "→ Impersonate a client after authentication.  Remove "
            "<sid>adm / SAPService<SID> and limit to LocalSystem + "
            "explicitly-authorised service accounts.  SAP services "
            "DON'T need SeImpersonate for normal operation.",
            "Block outbound SMB / RPC from the SAP service account to "
            "the local lsass — Windows Defender Firewall outbound "
            "rule blocking dst=127.0.0.1 + dst-port=445 for the SAP "
            "service principal.  Breaks the EFSRPC coercion primitive "
            "without affecting legitimate SAP traffic.",
            "Apply the Microsoft NTLM relay mitigations (LDAP signing, "
            "SMB signing, ExtendedProtectionForAuthentication=2) as "
            "defense-in-depth — the EFSRPC path culminates in an NTLM "
            "relay to lsass.",
        ],
        verification=[
            "PowerShell as the SAP service account: "
            "`whoami /priv` must NOT list SeImpersonatePrivilege.",
            "Re-run SAPMAP → Check Windows LPE.  efspotato_has_impersonate "
            "must be False.",
        ],
        refs=[
            ("Microsoft KB5005413 — NTLM relay mitigations",
             "https://support.microsoft.com/help/5005413"),
            _attack("T1068"),
        ],
        requires_restart=False,
        effort_minutes=60,
        severity_if_delayed="HIGH",
    ),

    "lpe.godpotato": Remediation(
        fix_summary=(
            "Same as EfsPotato — strip SeImpersonatePrivilege from SAP "
            "service accounts"
        ),
        fix_steps=[
            "GodPotato chains the same SeImpersonate primitive as "
            "EfsPotato (DCOM unmarshal instead of MS-EFSRPC, but the "
            "endgame is identical).  The single mitigation that "
            "actually closes the chain is removing SeImpersonate from "
            "the SAP service account.",
            "Apply the same secpol.msc fix as for EfsPotato: "
            "User Rights Assignment → Impersonate a client → remove "
            "<sid>adm / SAPService<SID>.",
            "Audit DCOM-permission grants: comexp.msc → Component "
            "Services → Computers → DCOM Config → look for any "
            "components granting Activation rights to <sid>adm.",
        ],
        verification=[
            "whoami /priv on the SAP service account must not list "
            "SeImpersonatePrivilege.",
            "Re-run SAPMAP → Check Windows LPE.  godpotato_has_impersonate "
            "must be False.",
        ],
        refs=[
            _attack("T1068"),
        ],
        requires_restart=False,
        effort_minutes=60,
        severity_if_delayed="HIGH",
    ),

    # =========================================================================
    # Reconnaissance / posture-only
    # =========================================================================

    "recon.saprouter_info": Remediation(
        fix_summary=(
            "Restrict SAProuter admin queries (ROUTER_ADM) to the "
            "management network via saprouttab ACL lines"
        ),
        fix_steps=[
            "Add a deny-by-default line at the bottom of saprouttab "
            "and explicit allow-lines for the legitimate ROUTER_ADM "
            "callers (basis admin workstations).  ROUTER_ADM from "
            "anywhere else must be rejected.",
            "Restart the SAProuter service (`saprouter -r`) so the new "
            "saprouttab takes effect; verify with `saprouter -l` from "
            "the legitimate management host.",
        ],
        verification=[
            "Re-run SAPMAP → Check SAProuter Info Leak.  The saprouter_info "
            "vulnerable flag must drop to False; the per-node check "
            "should report 'admin rejected: password required'.",
            "From a non-management host run "
            "`niping -t -H <router> -S 3299 -X` and confirm the admin "
            "is refused.",
        ],
        refs=[
            ("SAP help — Securing SAProuter",
             "https://help.sap.com/docs/saprouter"),
            _attack("T1018"),
            _attack("T1592"),
        ],
        requires_restart=True,    # saprouter -r
        effort_minutes=30,
        severity_if_delayed="HIGH",
    ),

    "snc.scan": Remediation(
        fix_summary=(
            "Enable SNC on every dispatcher and SAProuter listening port "
            "and require snc/only_encrypted_gui = 1 on production"
        ),
        fix_steps=[
            "On every ABAP instance profile: set snc/enabled = 1, "
            "snc/data_protection/min = 3, snc/data_protection/max = 3, "
            "snc/data_protection/use = 3 (PRIVACY / Sealed).  Configure "
            "the SECUDIR-side X.509 PKI for the SNC mechanism your "
            "landscape uses (Kerberos, X.509 via CommonCryptoLib, or "
            "third-party).",
            "On production ABAP: set snc/only_encrypted_gui = 1 to "
            "REJECT plain DIAG.  Without this, an attacker can still "
            "negotiate plaintext even if SNC is configured.",
            "On every SAProuter add the SNC-specific saprouttab lines "
            "to require the SNC layer on routed connections "
            "(see SAP Note 2778688 for the route-table syntax).",
        ],
        verification=[
            "Re-run SAPMAP → Check All SNC Posture.  Every applicable "
            "node must show SNC: enabled, QoP 3/3/3, enforced.",
            "Curl the dispatcher with a plain DIAG init; expect the "
            "kernel to return a 'SNC required' error on a production "
            "system.",
        ],
        refs=[
            _note(2778688),     # SAP SNC configuration
            ("SAP help — SNC overview",
             "https://help.sap.com/docs/SAP_NETWEAVER/snc"),
            _attack("T1082"),
        ],
        requires_restart=True,
        effort_minutes=480,    # PKI setup is the slow part
        severity_if_delayed="HIGH",
    ),
}


# ---------------------------------------------------------------------------
# Public lookups
# ---------------------------------------------------------------------------

def lookup(capability_key: str) -> Optional[Remediation]:
    """Return the catalog entry for a capability key, or None if no
    structured remediation exists for it.  Callers should treat None
    as "leave the legacy plain-string Finding.remediation alone".
    """
    return CATALOG.get(capability_key)


def all_capabilities() -> List[str]:
    """List every capability key the catalog has structured guidance for."""
    return list(CATALOG.keys())


def to_dict(capability_key: str) -> Dict:
    """Convenience: lookup + serialise.  Empty dict when unmapped."""
    r = lookup(capability_key)
    return r.to_dict() if r else {}
