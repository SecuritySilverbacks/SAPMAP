"""
sapmap_attack.py — MITRE ATT&CK Enterprise mapping for SAPMAP capabilities.

Pinned against ATT&CK Enterprise v19.1 (released 2026-04-28).  Three pieces:

    TACTICS         — the 12 enterprise tactics.
    TECHNIQUES      — only the techniques SAPMAP maps to.  We do NOT
                       ship MITRE's full STIX export.
    CAPABILITY_MAP  — { capability_key: [technique_ids] }.  This is the
                       single source of truth for what each SAPMAP
                       action maps to.  Adding a new exploit module
                       means adding one row here.

Capability keys follow ``<group>.<action_slug>`` convention:
    exploit.10kblaze
    creds.default_probe
    lpe.miniplasma
    snc.scan          (mapped to T1082 — see comment below)

Findings carry RAW technique IDs ("T1190", "T1078.001") — names, tactics
and URLs are looked up here at render-time to keep .sapmap state files
small and to maintain a single source of truth as ATT&CK evolves.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional

ATTACK_VERSION = "v19.1"
ATTACK_DOMAIN = "enterprise-attack"
NAVIGATOR_VERSION = "4.5"

# v15.1 → v19.1 migration notes (April 2026 release):
#   * TA0005 was RENAMED from "Defense Evasion" to "Stealth".
#     A new sibling tactic TA0112 "Defense Impairment" was added
#     for techniques that intentionally weaken defensive controls
#     (firewall mods, tool disablement, etc.).  SAPMAP doesn't map
#     to TA0112 yet but it's listed here for forward compatibility.
#   * T1550 Use Alternate Authentication Material was MOVED from
#     TA0005 (Defense Evasion) to TA0008 (Lateral Movement).  Its
#     sub-techniques (incl. T1550.004 Web Session Cookie) follow.
#   * T1574 Hijack Execution Flow now lives under both TA0005
#     (Stealth) and TA0002 (Execution); we keep the primary mapping
#     to TA0005 for the heatmap grid since that's where it's
#     historically been catalogued.
#   * Several v19 additions (T1685 "Disable or Modify Tools" merger,
#     T1684 "Social Engineering" parent, T1682 "Query Public AI
#     Services") are not relevant to SAP/landscape attacks and are
#     intentionally not catalogued here.


# ---------------------------------------------------------------------------
# Tactics — the 12 enterprise tactics, MITRE's canonical order.
# ---------------------------------------------------------------------------

TACTICS: Dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Stealth",                # Renamed from "Defense Evasion" in v19
    "TA0112": "Defense Impairment",     # New in v19 (TA0005 sibling)
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

# Display order used by the heatmap grid (left→right) and report.
TACTIC_ORDER: List[str] = [
    "TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004",
    "TA0005", "TA0112", "TA0006", "TA0007", "TA0008", "TA0009", "TA0011",
    "TA0010", "TA0040",
]


# ---------------------------------------------------------------------------
# Techniques — only the ones SAPMAP maps to.
# Each entry: name, tactic ID, optional sub-of (for sub-techniques).
# ---------------------------------------------------------------------------

TECHNIQUES: Dict[str, Dict] = {
    # Discovery
    "T1046":     {"name": "Network Service Discovery",      "tactic": "TA0007"},
    "T1018":     {"name": "Remote System Discovery",        "tactic": "TA0007"},
    "T1082":     {"name": "System Information Discovery",   "tactic": "TA0007"},
    "T1087":     {"name": "Account Discovery",              "tactic": "TA0007"},
    "T1087.002": {"name": "Domain Account",                 "tactic": "TA0007", "sub_of": "T1087"},
    "T1518":     {"name": "Software Discovery",             "tactic": "TA0007"},
    "T1526":     {"name": "Cloud Service Discovery",        "tactic": "TA0007"},
    "T1592":     {"name": "Gather Victim Host Information", "tactic": "TA0043"},

    # Initial Access
    "T1190":     {"name": "Exploit Public-Facing Application", "tactic": "TA0001"},

    # Execution
    "T1059":     {"name": "Command and Scripting Interpreter", "tactic": "TA0002"},
    "T1059.006": {"name": "Python",                         "tactic": "TA0002", "sub_of": "T1059"},

    # Persistence
    "T1136":     {"name": "Create Account",                 "tactic": "TA0003"},
    "T1136.001": {"name": "Local Account",                  "tactic": "TA0003", "sub_of": "T1136"},
    "T1098":     {"name": "Account Manipulation",           "tactic": "TA0003"},
    "T1098.004": {"name": "SSH Authorized Keys",            "tactic": "TA0003", "sub_of": "T1098"},
    "T1505":     {"name": "Server Software Component",      "tactic": "TA0003"},
    "T1505.003": {"name": "Web Shell",                      "tactic": "TA0003", "sub_of": "T1505"},

    # Privilege Escalation
    "T1068":     {"name": "Exploitation for Privilege Escalation", "tactic": "TA0004"},
    # Access Token Manipulation — used by the Windows "potato" family
    # (GodPotato, EfsPotato).  These abuse SeImpersonatePrivilege to
    # steal a SYSTEM token via a COM/RPC round-trip rather than
    # exploiting a kernel bug.  Sub-technique .001 = Token Impersonation.
    "T1134":     {"name": "Access Token Manipulation",      "tactic": "TA0004"},
    "T1134.001": {"name": "Token Impersonation/Theft",      "tactic": "TA0004", "sub_of": "T1134"},
    # Kernel/user-space exploits like copyfail / dirtyfrag / peditcow /
    # miniplasma.  T1211 lives in TA0005 (Stealth) in MITRE — bypassing
    # kernel-level defenses — and complements T1068 for LPEs that
    # exploit vulnerabilities rather than misconfig.
    "T1211":     {"name": "Exploitation for Defense Evasion", "tactic": "TA0005"},

    # Stealth (formerly Defense Evasion — renamed in ATT&CK v19)
    "T1574":     {"name": "Hijack Execution Flow",          "tactic": "TA0005"},
    "T1562":     {"name": "Impair Defenses",                "tactic": "TA0005"},
    "T1562.001": {"name": "Disable or Modify Tools",        "tactic": "TA0005", "sub_of": "T1562"},
    "T1562.006": {"name": "Indicator Blocking",             "tactic": "TA0005", "sub_of": "T1562"},
    "T1055":     {"name": "Process Injection",              "tactic": "TA0005"},

    # Credential Access
    "T1003":     {"name": "OS Credential Dumping",          "tactic": "TA0006"},
    "T1110":     {"name": "Brute Force",                    "tactic": "TA0006"},
    "T1110.001": {"name": "Password Guessing",              "tactic": "TA0006", "sub_of": "T1110"},
    "T1552":     {"name": "Unsecured Credentials",          "tactic": "TA0006"},
    "T1552.001": {"name": "Credentials In Files",           "tactic": "TA0006", "sub_of": "T1552"},
    "T1552.004": {"name": "Private Keys",                   "tactic": "TA0006", "sub_of": "T1552"},
    "T1145":     {"name": "Private Keys (deprecated)",       "tactic": "TA0006"},
    "T1555":     {"name": "Credentials from Password Stores", "tactic": "TA0006"},
    "T1606":     {"name": "Forge Web Credentials",          "tactic": "TA0006"},

    # Valid Accounts (cross-tactic in MITRE — kept under Initial Access here)
    "T1078":     {"name": "Valid Accounts",                 "tactic": "TA0001"},
    "T1078.001": {"name": "Default Accounts",               "tactic": "TA0001", "sub_of": "T1078"},
    "T1078.004": {"name": "Cloud Accounts",                 "tactic": "TA0001", "sub_of": "T1078"},

    # Adversary-in-the-Middle (used for CVE-2026-58240 rogue ASCS
    # gateway registration — application servers route trusted
    # cross-instance traffic to the attacker-controlled endpoint).
    "T1557":     {"name": "Adversary-in-the-Middle",         "tactic": "TA0009"},

    # Lateral Movement
    "T1021":     {"name": "Remote Services",                "tactic": "TA0008"},
    "T1021.004": {"name": "SSH",                             "tactic": "TA0008", "sub_of": "T1021"},
    "T1210":     {"name": "Exploitation of Remote Services", "tactic": "TA0008"},
    # T1550 and its sub-techniques moved from TA0005 → TA0008 in ATT&CK v19.
    "T1550":     {"name": "Use Alternate Authentication Material", "tactic": "TA0008"},
    "T1550.004": {"name": "Web Session Cookie",             "tactic": "TA0008", "sub_of": "T1550"},
    "T1090":     {"name": "Proxy",                          "tactic": "TA0011"},
    "T1090.001": {"name": "Internal Proxy",                 "tactic": "TA0011", "sub_of": "T1090"},
    # Application-layer protocol (HTTPS) — populates TA0011 for
    # cert-proxy tunnels that were previously invisible on the C2 column.
    "T1071":     {"name": "Application Layer Protocol",     "tactic": "TA0011"},
    "T1071.001": {"name": "Web Protocols",                  "tactic": "TA0011", "sub_of": "T1071"},

    # Discovery — file-system enumeration via the file browser
    "T1083":     {"name": "File and Directory Discovery",   "tactic": "TA0007"},

    # Collection
    "T1213":     {"name": "Data from Information Repositories", "tactic": "TA0009"},
    "T1074":     {"name": "Data Staged",                    "tactic": "TA0009"},
    "T1005":     {"name": "Data from Local System",         "tactic": "TA0009"},
    "T1560":     {"name": "Archive Collected Data",         "tactic": "TA0009"},

    # Command and Control — file upload to target (ingress tool transfer)
    "T1105":     {"name": "Ingress Tool Transfer",          "tactic": "TA0011"},

    # Exfiltration — SCC backup zip / users.xml pull leaves the
    # target over the SCC admin HTTPS port; populates TA0010 which
    # would otherwise stay empty on the grid.
    "T1567":     {"name": "Exfiltration Over Web Service",  "tactic": "TA0010"},

    # Impact (ransapware writes ciphertext into productive tables —
    # dual-tagged as encryption-for-impact and stored-data manipulation
    # so both defensive lenses light up).
    "T1486":     {"name": "Data Encrypted for Impact",      "tactic": "TA0040"},
    "T1565":     {"name": "Data Manipulation",              "tactic": "TA0040"},
    "T1565.001": {"name": "Stored Data Manipulation",       "tactic": "TA0040", "sub_of": "T1565"},
}


# ---------------------------------------------------------------------------
# Capability map — single source of truth.
# Empty list = explicitly un-mapped (info-only, no ATT&CK fit).
# ---------------------------------------------------------------------------

CAPABILITY_MAP: Dict[str, List[str]] = {
    # ---- Discovery ----
    "recon.fast_scan":           ["T1046", "T1018", "T1082"],
    "recon.deep_scan":           ["T1046", "T1018", "T1082"],
    "recon.system_info":         ["T1082"],
    "recon.diag_scrape":         ["T1082"],
    "recon.sapcontrol_query":    ["T1082"],
    "recon.client_enum":         ["T1082"],
    "recon.user_enum":           ["T1087", "T1087.002"],
    "recon.wd_fingerprint":      ["T1046", "T1518"],
    "recon.wd_backends":         ["T1018"],
    "recon.scc_fingerprint":     ["T1526"],
    "recon.scc_relay":           ["T1018"],
    "recon.btp_subaccount_enum": ["T1526"],
    "recon.saprouter_info":      ["T1018", "T1592"],
    "snc.scan":                  ["T1082"],
    # SAProuter route enumeration via NI_ROUTE probing — reveals what
    # SIDs / ports are reachable through the router.  Discovery +
    # internal-proxy discovery.
    "recon.saprouter_route_enum": ["T1592", "T1090.001", "T1046"],
    # SNC posture check — no auth, no exploit, but observes crypto
    # config on the target.  System-info + network-service discovery.
    "recon.snc_posture":         ["T1082", "T1046"],
    # DIAG-based default-cred sweep against 16 SAP-shipped accounts.
    # Password-guessing (T1110.001) + attempting valid accounts
    # (T1078.001) — separate key from creds.default_probe (SCC) because
    # this one exercises the ABAP kernel auth stack, not the SCC web
    # form; distinct detection signatures.
    "recon.brute_force_default": ["T1110.001", "T1078.001", "T1078"],
    # Pre-auth kernel/hostname/instance leak via V6/V2/Chipik RFC probes.
    # This runs on every fresh scan target — first ATT&CK step in the
    # engagement, previously invisible on the grid.
    "recon.rfc_system_info_leak": ["T1592", "T1082"],
    # USREXTID / USR21 / USR02 dump for domain-account harvesting.
    "recon.usrextid_read":       ["T1087", "T1087.002"],
    # OA2C_CLIENT / OA2C_CONFIG dump — reveals which cloud services the
    # target has OAuth2 trust with.  Discovery of cloud service links.
    "recon.oa2c_read":           ["T1087", "T1526"],
    # Web Dispatcher /sap/wdisp/admin backend-table read — full landscape
    # topology (SID, MSHOST, MSPORT, SSL_ENCRYPT, SRCURL) via a single
    # authenticated HTTP GET.  Data-from-repositories + cloud-service
    # discovery in one shot.
    "data.wd_backend_table_read": ["T1213", "T1526"],

    # ---- Initial Access / Execution ----
    "exploit.10kblaze":          ["T1190", "T1059"],
    "exploit.cve_2025_31324":    ["T1190", "T1505.003"],
    "exploit.cve_2020_6287":     ["T1190", "T1136.001"],
    "exploit.cve_2022_22536":    ["T1190", "T1574"],
    "exploit.ms_betrusted":      ["T1190", "T1078"],
    # CVE-2026-58240 — MS ASCS_GW rogue registration.  Same shape as
    # ms_betrusted (T1190 exploit-public-facing + T1078 valid accounts
    # via trust-list pollution), plus T1557 "adversary-in-the-middle"
    # because the rogue ASCS entry redirects internal cross-instance
    # traffic (enqueue coordination, SSO2 ticket relay, internal RFC
    # callbacks) to the attacker-controlled endpoint.
    "exploit.ms_ascs_gw_rogue":  ["T1190", "T1078", "T1557"],
    "exploit.sapxpg":            ["T1190", "T1059"],

    # ---- Privilege Escalation ----
    "privesc.dpmon_sap_star":    ["T1068", "T1078"],
    "privesc.bapi_profiles":     ["T1068", "T1098"],
    "privesc.webgui_rsbdcos0":   ["T1068", "T1059.006"],
    # Linux kernel LPEs — copyfail (copy_from_user), dirtyfrag
    # (dirtypagetable-family), peditcow (dirty-cow variant).  All
    # three exploit kernel bugs, so dual-tag T1068 + T1211 to make
    # the "kernel exploit" nature visible on the Stealth column too.
    "lpe.copyfail":              ["T1068", "T1211"],
    "lpe.dirtyfrag":             ["T1068", "T1211"],
    "lpe.peditcow":              ["T1068", "T1211"],
    # Windows kernel LPE — same kernel-exploit shape as above.
    "lpe.miniplasma":            ["T1068", "T1211"],
    # Windows token-impersonation LPEs — the "Potato" family abuses
    # SeImpersonatePrivilege via a COM/RPC round-trip to steal a
    # SYSTEM token.  T1134.001 is the correct primary; T1068 stays
    # for grid-column parity with the kernel LPEs.
    "lpe.godpotato":             ["T1068", "T1134.001"],
    "lpe.efspotato":             ["T1068", "T1134.001"],

    # ---- Credential Access ----
    # Default-credential probing = attempting a small vendor-shipped
    # wordlist against the target.  T1078.001 for the "valid default
    # account" outcome + T1110.001 to populate the Brute Force column
    # even on a rejected sweep.
    "creds.default_probe":       ["T1078.001", "T1110.001"],
    "creds.user_password_hash":  ["T1003"],
    "creds.abap_secstore":       ["T1555"],
    "creds.java_secstore":       ["T1555"],
    "creds.btp_destinations":    ["T1552.001"],
    # SCC backup zip pulls over the SCC's own HTTPS admin port — that
    # is Exfiltration Over Web Service (T1567), on top of the credential-
    # access primitives.
    "creds.scc_keystore":        ["T1555", "T1552.004", "T1567"],
    "creds.scc_users_xml":       ["T1555"],
    "creds.pse_loot":            ["T1552.004"],
    # STRUST/SAPSYS PSE export — pulling the ABAP kernel's private-key
    # material via SSFS / LPE / MYSAPSSO2 signer chain.  Distinct from
    # pse_loot (which covers ad-hoc credential-file reads) because
    # this one is the specific ticket-forgery precursor.
    "data.pse_export":           ["T1552.004", "T1145"],
    "creds.ssh_private_key":     ["T1552.004", "T1145"],
    "creds.oa2c_secrets":        ["T1555"],
    # Web Dispatcher's icmauth.txt is an on-disk password file that
    # ICM parses at start-up — reading it (via WD admin creds or an
    # LPE) is Credentials in Files (T1552.001) with a Valid Accounts
    # (T1078) follow-through when the hashes get cracked.
    "creds.wd_icmauth":          ["T1552.001", "T1078"],

    # ---- Lateral Movement ----
    "lateral.rfc_propagate":     ["T1021", "T1078"],
    # DBCON direct-DB pivot (issue #21) — SAPMAP holds an external
    # DBCON credential recovered from RSECTAB and opens the target
    # database directly via a native driver (hdbcli / cx_Oracle /
    # pyodbc / ibm_db).  When the target schema is SAP-shaped, plants
    # SAPMAP00 via INSERT into USR02/USR04/UST04/USRBF2 — no RFC hop,
    # no SAPXPG on the target.
    "lateral.dbcon_direct":      ["T1210", "T1078", "T1136.001"],
    # DBCON non-SAP DB — driver-level table dump of the schema the
    # DBCON points at (business data, custom app tables, warehoused
    # exports).  T1213 for repository read, T1005 for local-system
    # data (the DB is a local resource from the ABAP's perspective).
    "data.dbcon_dump":           ["T1213", "T1005"],
    # DBCON pair — /DBCON/<name> secstore entry joined with a DBCON
    # table row to produce a live credential + host/port tuple.
    # Discovery of a service link + accessing password-protected data.
    "recon.dbcon_resolve":       ["T1082", "T1552.001"],
    # DBCON probe — driver-level connection + SAP-shape fingerprint
    # (USR02 presence, T000/M_HOST_INFORMATION SYSID readback).
    # Remote-service discovery + valid-account confirmation.
    "recon.dbcon_probe":         ["T1046", "T1078", "T1082"],
    # HANA reconnaissance sweep — M_LICENSE / M_HOST_INFORMATION /
    # M_DATABASE / M_SERVICES / SYS.USERS via direct driver.  System-
    # info + service + software discovery in one shot.
    "recon.dbcon_hana_sweep":    ["T1082", "T1518", "T1046"],
    # SYS.M_TABLES enumeration — discovery of every schema/table
    # visible to the DBCON user for planning subsequent dumps.
    "recon.dbcon_enumerate":     ["T1082", "T1518"],
    # SYS.TABLE_COLUMNS column browser — column-level table
    # metadata, precursor to targeted peeks.
    "recon.dbcon_describe":      ["T1082"],
    # Row-level peek — SELECT * LIMIT N with optional WHERE.  Same
    # data-access class as data.dbcon_dump but per-table shape.
    "data.dbcon_peek":           ["T1213", "T1005"],
    # Arbitrary read-only SELECT via direct driver — most permissive
    # DBCON action after peek.  Data-access repository read + local
    # data.  Blocked at write attempts, so no persistence tag.
    "data.dbcon_custom_sql":     ["T1213", "T1005"],
    # USR02 password-hash dump via direct SQL — same class as
    # creds.user_password_hash but distinct source (bypasses the
    # ABAP kernel).  Repository read + credential access.
    "creds.dbcon_usr02_dump":    ["T1003", "T1552.001", "T1213"],
    # USR04 / UST04 / USRBF2 auth-object dump — profile / role /
    # authorisation-buffer tables.  Enables offline "what can user
    # X do" analysis after the operator has the hashes.
    "creds.dbcon_auth_dump":     ["T1552", "T1213", "T1082"],
    # ---- CTS/TMS pivot (Bundle 1) ----
    # Enumerate the transport-domain topology (TMSCSYS + TMSMCONF)
    # and pair RSECTAB /RFC/TMSADM@... with domain members.
    # Discovery + credential-in-file.
    "recon.tms_domain":          ["T1082", "T1018", "T1552.001"],
    # TMSADM RFC logon to a domain member — remote services +
    # valid accounts.  Precondition for transport injection.
    "lateral.tmsadm_rfc":        ["T1021", "T1078"],
    # Read TMSBUFFER on target — pending imports.  Data from
    # information repositories.
    "recon.tms_buffer":          ["T1082", "T1213"],
    # Read E070 / E071 — recent transport history on target.
    # Data-from-repositories + system-info discovery.
    "data.tms_transport_history": ["T1213", "T1082"],
    "lateral.sapmap_user":       ["T1078", "T1136"],
    "lateral.mysapsso2_forge":   ["T1606"],
    "lateral.mysapsso2_replay":  ["T1550.004", "T1078"],
    # Bulk fanout of a forged ticket across every STRUSTSSO2-trusted
    # receiver.  Same primitives as mysapsso2_replay but at fleet
    # scale — a distinct capability key so the ATT&CK grid shows the
    # amplification step separately.  Adds T1021 (Remote Services)
    # because the fanout is a many-target lateral-movement wave.
    "lateral.ticket_propagate_all": ["T1550.004", "T1078", "T1021"],
    "lateral.sxpg_exec":         ["T1021", "T1059"],
    "lateral.wd_pivot":          ["T1090", "T1021"],
    "lateral.saprouter_tunnel":  ["T1090.001"],
    "lateral.scc_tunnel_impersonate": ["T1078.004", "T1550", "T1071.001"],
    # Kernel-proxied cert-auth = using a source ABAP's SAPSSLC PSE
    # (via HTTP_CLIENT_CREATE_BY_DESTINATION) to call a BTP / cloud
    # endpoint under the source system's cloud identity.  Lateral
    # movement + valid alternate auth material + HTTPS as C2 channel.
    "lateral.btp_cert_proxy":    ["T1550", "T1078.004", "T1071.001"],
    # Auto-probe of a cert-authenticated Type-G/H destination that
    # returned 2xx — proves the endpoint is trusted AND authorized
    # end-to-end.  Semantically the same as btp_cert_proxy but the
    # key exists as a separate name for finding provenance clarity.
    "lateral.cert_proxy_open":   ["T1550", "T1078.004", "T1071.001"],
    "lateral.internal_ip_spoof": ["T1078"],
    "lateral.ssh_key_reuse":     ["T1021.004", "T1078.001"],

    # ---- Persistence ----
    "persist.create_user":       ["T1136.001", "T1098"],
    "persist.sap_all_assign":    ["T1098"],
    "persist.ssh_key_plant":     ["T1098.004"],
    "persist.web_shell":         ["T1505.003"],
    # Transport upload + STMS register doesn't yet execute anything on
    # the target — counts as "stash plus pending persistence" + a write
    # to the data dictionary's information repository.
    "persist.transport_addtobuffer": ["T1505", "T1213"],
    # Full `tp import` runs the embedded ABAP — fresh server-side code,
    # arbitrary commands, and almost always role / account manipulation
    # (transports routinely ship AGR_* changes).
    "persist.transport_import":     ["T1505", "T1059", "T1098"],

    # ---- Collection ----
    "data.read_table":           ["T1213"],
    "data.capability_analyse":   ["T1213"],
    "data.scc_users_dump":       ["T1213", "T1567"],
    # Reading /opt/sap/scc/config/users.xml via sidadm → root pivot
    # chains: Privilege Escalation (T1068, the LPE itself) +
    # OS Credential Dumping (T1003, harvesting the bcrypt hashes) +
    # Data from Information Repositories (T1213, the SCC config
    # store itself).  Distinct capability from data.scc_users_dump
    # (REST backup) because the kill-chain step is different — this
    # one's gated on a working Linux LPE, the other on SCC admin web
    # creds.
    "data.scc_users_dump_via_lpe": ["T1068", "T1003", "T1213"],
    # Loot staging = writing collected data to a working dir on the
    # target before exfil.  When SAPMAP tars/zips before pulling it's
    # also Archive Collected Data (T1560).
    "data.loot_stage":           ["T1074", "T1560"],

    # ---- File Browser (Issue #37) ----
    # Interactive file-system browsing via TargetFS — lists directories,
    # downloads files from the target, uploads files to the target.
    # Each maps to a distinct ATT&CK technique:
    #   list  = T1083 File and Directory Discovery (TA0007)
    #   download = T1005 Data from Local System (TA0009)
    #   upload = T1105 Ingress Tool Transfer (TA0011)
    "data.fs_list":              ["T1083"],
    "data.fs_download":          ["T1005"],
    "data.fs_upload":            ["T1105"],

    # ---- Stealth / Defense Impairment (Tier 3) ----
    # Virtual SAP Death Star = live disp+work hook that swallows SAL /
    # DBTABLOG / ETD events matching a filter.  Ptrace-based process
    # injection, kernel-of-target patch that keeps the hooked bytes in
    # memory only.  ATT&CK: T1562 Impair Defenses (subtype: indicator
    # blocking) + T1055.008 Ptrace System Calls for the injection.
    "evasion.death_star":        ["T1562", "T1055"],
    # Static Tier 3 audit-log manipulation — RSAU slot disable, SAL
    # uname narrow, DBTABLOG purge, Java SAL suppress.  These all
    # touch defensive controls without ptrace, so no T1055 — just the
    # two T1562 sub-techniques that describe what actually happens.
    "evasion.rsau_disable":      ["T1562.001", "T1562.006"],

    # ---- Impact ----
    # Ransapware encrypts productive table fields in place — the DB
    # rows still exist, their contents are ciphertext until we decrypt
    # via the stored manifest.  Dual-tag: T1486 (Data Encrypted for
    # Impact) for the ransomware framing, T1565.001 (Stored Data
    # Manipulation) for the DB-row overwrite framing.  Decrypt is
    # the reversal — same tags apply because a defender monitoring
    # for T1486/T1565 should catch both operations.
    "ransapware.encrypt":        ["T1486", "T1565.001"],
    "ransapware.decrypt":        ["T1486", "T1565.001"],
}


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def lookup(tid: str) -> Optional[Dict]:
    """Return {id, name, tactic, tactic_name, url, sub_of} or None."""
    t = TECHNIQUES.get(tid)
    if not t:
        return None
    return {
        "id":          tid,
        "name":        t["name"],
        "tactic":      t["tactic"],
        "tactic_name": TACTICS.get(t["tactic"], ""),
        "url":         f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
        "sub_of":      t.get("sub_of", ""),
    }


def techniques_for(capability_key: str) -> List[str]:
    """Return the list of T-IDs mapped to a capability.  Unknown keys
    return [] (and we log nothing — silent absence is the correct
    behavior for an info-only capability).
    """
    return list(CAPABILITY_MAP.get(capability_key, []))


def technique_details(ids: Iterable[str]) -> List[Dict]:
    """Resolve a list of T-IDs into full dicts (skipping unknowns)."""
    out = []
    for tid in ids:
        info = lookup(tid)
        if info:
            out.append(info)
    return out


def aggregate_by_tactic(technique_ids: Iterable[str]) -> Dict[str, List[str]]:
    """Group T-IDs by tactic.  Returns {tactic_id: sorted([tids])}.

    Used by node detail "ATT&CK observed" section and the heatmap.
    """
    by_tactic: Dict[str, set] = {}
    for tid in technique_ids:
        info = lookup(tid)
        if not info:
            continue
        by_tactic.setdefault(info["tactic"], set()).add(tid)
    return {t: sorted(v) for t, v in by_tactic.items()}


def collect_from_findings(findings: Iterable) -> List[str]:
    """Walk a Finding iterable and return a de-duplicated list of T-IDs.

    Accepts both dataclass Finding instances and dicts (from
    SAPMAPState snapshots or the emit_finding bus records).
    """
    seen = []
    for f in findings or []:
        if hasattr(f, "attack_techniques"):
            tids = f.attack_techniques or []
        elif isinstance(f, dict):
            tids = f.get("attack_techniques", []) or []
        else:
            continue
        for tid in tids:
            if tid not in seen:
                seen.append(tid)
    return seen


# ---------------------------------------------------------------------------
# Navigator JSON layer (https://github.com/mitre-attack/attack-navigator)
# ---------------------------------------------------------------------------

# Severity → score for the gradient (1..5).  Severity is an IntEnum
# whose values mirror SAPMAP's: INFO=1, LOW=2, MEDIUM=3, HIGH=4,
# CRITICAL=5 — but we accept any int and clamp.
_SEV_SCORE = {1: 1, 2: 2, 3: 3, 4: 4, 5: 5}


def _score_for(sev_value: int) -> int:
    return max(1, min(5, int(sev_value or 1)))


def to_navigator_layer(state, *, name: str = "",
                       description: str = "") -> Dict:
    """Build an ATT&CK Navigator v4.5 layer JSON from a SAPMAPState.

    For each technique observed across all findings:
      * score = max severity of any Finding bearing the technique
      * comment lists the SIDs and CVEs that exercised it
    Cells light up using Navigator's built-in 1..5 gradient.

    Args:
        state: SAPMAPState instance (or any object exposing .nodes —
               a dict of {sid: SAPNode}).
        name, description: layer metadata for the Navigator UI.

    Returns a dict that ``json.dumps`` cleanly.
    """
    # Aggregate per-technique evidence: { tid: { "score": int,
    #                                            "evidence": [(sid, cve, sev), ...] } }
    bucket: Dict[str, Dict] = {}
    nodes = getattr(state, "nodes", {}) or {}
    for sid, node in nodes.items():
        node_sid = getattr(node, "sid", sid) or sid
        for f in getattr(node, "findings", []) or []:
            tids = getattr(f, "attack_techniques", None) or []
            sev  = int(getattr(f, "severity", 1) or 1)
            cve  = getattr(f, "detail", "") or ""  # detail often carries CVE
            for tid in tids:
                slot = bucket.setdefault(tid, {"score": 0, "evidence": []})
                if sev > slot["score"]:
                    slot["score"] = sev
                slot["evidence"].append((node_sid, cve, sev))

    techniques_list = []
    for tid, slot in bucket.items():
        info = lookup(tid)
        if not info:
            continue
        comment_lines = []
        for ev_sid, ev_cve, ev_sev in slot["evidence"][:8]:
            line = f"{ev_sid} (sev={ev_sev})"
            if ev_cve:
                line += f" — {ev_cve[:80]}"
            comment_lines.append(line)
        if len(slot["evidence"]) > 8:
            comment_lines.append(
                f"… +{len(slot['evidence']) - 8} more")
        techniques_list.append({
            "techniqueID": tid,
            "score":       _score_for(slot["score"]),
            "comment":     "\n".join(comment_lines),
            "enabled":     True,
        })

    return {
        "name":        name or "SAPMAP engagement",
        "description": (description
                        or f"Generated by SAPMAP — ATT&CK {ATTACK_VERSION}"),
        "domain":      ATTACK_DOMAIN,
        "versions": {
            "attack":    ATTACK_VERSION.lstrip("v"),
            "navigator": NAVIGATOR_VERSION,
            "layer":     "4.5",
        },
        "techniques": techniques_list,
        "gradient": {
            "colors":   ["#fee5d9", "#fcae91", "#fb6a4a", "#de2d26", "#a50f15"],
            "minValue": 1,
            "maxValue": 5,
        },
        "legendItems": [
            {"label": "INFO",     "color": "#fee5d9"},
            {"label": "LOW",      "color": "#fcae91"},
            {"label": "MEDIUM",   "color": "#fb6a4a"},
            {"label": "HIGH",     "color": "#de2d26"},
            {"label": "CRITICAL", "color": "#a50f15"},
        ],
        "metadata": [
            {"name": "tool",            "value": "SAPMAP"},
            {"name": "attack_version",  "value": ATTACK_VERSION},
        ],
    }


# ---------------------------------------------------------------------------
# Heatmap grid data — shared by the in-GUI modal and the report SVG.
# ---------------------------------------------------------------------------

def heatmap_grid(state) -> Dict:
    """Compute the heatmap matrix for rendering.

    Returns:
        {
            "columns": [{tactic_id, tactic_name, cells: [
                {tid, name, sub_of, score, sid_count, sids: [...]}, ...
            ]}, ...],
            "totals": {
                "techniques":    int,
                "tactics":       int,
                "findings":      int,
                "by_severity":   {1: n, 2: n, ...},
            }
        }
    """
    # bucket[tid] = {"score": int, "sids": set, "count": int}
    bucket: Dict[str, Dict] = {}
    sev_counts: Dict[int, int] = {}
    nodes = getattr(state, "nodes", {}) or {}
    total_findings = 0
    for sid, node in nodes.items():
        node_sid = getattr(node, "sid", sid) or sid
        for f in getattr(node, "findings", []) or []:
            tids = getattr(f, "attack_techniques", None) or []
            sev  = int(getattr(f, "severity", 1) or 1)
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            if tids:
                total_findings += 1
            for tid in tids:
                slot = bucket.setdefault(tid, {
                    "score": 0, "sids": set(), "count": 0})
                if sev > slot["score"]:
                    slot["score"] = sev
                slot["sids"].add(node_sid)
                slot["count"] += 1

    columns = []
    for tactic_id in TACTIC_ORDER:
        if tactic_id not in TACTICS:
            continue
        cells = []
        for tid, info in sorted(TECHNIQUES.items()):
            if info["tactic"] != tactic_id:
                continue
            slot = bucket.get(tid, {"score": 0, "sids": set(), "count": 0})
            cells.append({
                "id":         tid,
                "name":       info["name"],
                "sub_of":     info.get("sub_of", ""),
                "score":      slot["score"],
                "sid_count":  len(slot["sids"]),
                "sids":       sorted(slot["sids"]),
                "count":      slot["count"],
            })
        if cells:
            columns.append({
                "tactic_id":   tactic_id,
                "tactic_name": TACTICS[tactic_id],
                "cells":       cells,
            })

    return {
        "columns": columns,
        "totals": {
            "techniques":  len([s for s in bucket.values() if s["score"] > 0]),
            "tactics":     len([c for c in columns
                                if any(cell["score"] > 0
                                       for cell in c["cells"])]),
            "findings":    total_findings,
            "by_severity": sev_counts,
        },
        "attack_version": ATTACK_VERSION,
    }
