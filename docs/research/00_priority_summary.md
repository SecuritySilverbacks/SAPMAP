# Priority Summary — SAPMAP's Next Generation

Consolidated from the five research reports. Ranked by **impact ×
ease**, with a concrete phase-1 / phase-2 / phase-3 rollout plan.

---

## Answer to the "Java→ABAP from RECON UME admin" question

**No HTTP destinations-service API returns plaintext JCo passwords to
a UME admin.** SAP locked that down ~2010 (Notes 1562541, 1710977) —
`DestinationService.getJCoProperties()` blanks `jco.client.passwd`
even for authenticated admins. NWA always shows `********`.

**Four realistic Java→ABAP pivots instead** (see `02_java_to_abap_pivots.md`):

1. **CPACache XOR-0x74 decrypt** on PI/PO up to 7.5 SP14 — `com.sap.aii.af.service.cpa.CPAFactory` returns channel XML where passwords are base64 + XOR with static key `0x74`. **Highest-ROI single addition for PI targets like J75.**
2. **SAPLogonTicket forging** — extract `SAPLogonTicketKeypair` private key via JSP, mint MYSAPSSO2 for any user on any system trusting this AS Java via STRUSTSSO2. No password needed ever.
3. **`/logviewer/` authenticated log grep** — `defaultTrace.*.trc` routinely logs full JCo `Properties.toString()` at DEBUG with plaintext passwords. No JSP drop needed.
4. **AdapterMessageMonitoring SOAP** — `getMessageBytesJavaLangStringBoolean` returns raw stored payload bytes embedding outbound `Authorization: Basic`, WS-Security tokens, JDBC URLs with inline passwords.

---

## Top 15 additions — unified ranking

### Tier A — small effort, high impact (build first)

| # | Addition | Effort | Why |
|---|---|---|---|
| 1 | **CVE-2022-22536 ICMAD HTTP smuggler** | ~200 LOC new module | Unauth session-hijack → feeds stolen MYSAPSSO2 into existing RFC engine. ABAP + Java + Content Server + WebDisp. CISA KEV-listed, still unpatched on DMZ tiers. |
| 2 | **CVE-2025-42999 deserialization chain** | ~150 LOC added to `sap_cve_2025_31324.py` | Covers systems patched for 31324 but not 42999 (April 2025 vs May 2025 releases → 12-month tail). Reuses the upload primitive. |
| 3 | **PI CPACache dumper** (`sap_java_cpa_dump.py`) | ~260 LOC (200 Py + 60 JSP) | Decrypts every PI channel password (downstream ABAP/LDAP/JDBC/SFTP) via static XOR-0x74. Immediate Java→ABAP pivot on PI. |
| 4 | **SAPLogonTicket forger** (`sap_java_ticket_forge.py`) | ~400 LOC | Extract TicketKeystore private key via JSP, mint MYSAPSSO2 for any user, hop to every trusting ABAP. No password ever. Graph explosion. |
| 5 | **CVE-2025-42957 DMIS ABAP code injection** | ~150 LOC new `@lpe_method` | Low-priv → SAP_ALL on S/4HANA DMIS. One RFC call. Actively exploited Aug–Dec 2025. |
| 6 | **`/sap/public/info` pre-auth fingerprint** | ~80 LOC | Unauth kernel + SP + DB + SID + hostname. Drives patch-level logic for every other check. |
| 7 | **Role/profile capability analyzer** | ~300 LOC | Given any user, map `AGR_USERS`+`AGR_1251`+`UST04` to human-readable capabilities (*"this user can read BSEG = $1.4B, LFBK = 2,107 IBANs"*). Best customer-facing finding in the tool. |

### Tier B — medium effort, high value

| # | Addition | Effort | Why |
|---|---|---|---|
| 8 | **CVE-2025-42944 P4 deserialization** (`sap_cve_2025_42944.py`) | ~500 LOC | Second unauth Java RCE path (port 5NN04), for installs without Visual Composer. Base: codewhitesec scaffold. |
| 9 | **SAP Cloud Connector + BTP module** — see elaborate plan in [`08_cloud_connector_implementation_plan.md`](08_cloud_connector_implementation_plan.md) | ~6 wk | Fingerprint → default creds (`Administrator:manage`) → version-bucket CVEs → post-RCE JCEKS extraction → BTP destination cleartext capture → CISO-grade risk dashboard. New `SCCNode` / `BTPSubaccountNode` / `IASTenantNode` / `BTPDestination` / `SCCMapping` types. First public tool to chain on-prem → BTP. |
| 10 | **Authenticated `/logviewer/` credential scraper** (`sap_java_logviewer_grep.py`) | ~300 LOC | No JSP needed. UME admin + log read + regex = creds from defaultTrace. |
| 11 | **Trusted RFC hop** (new edge type) | ~250 LOC | Call BAPI on destination B from compromised A with `jco.client.trusted=1`. No password. Walks SolMan/CUA/TMS topology automatically. |
| 12 | **SAPControl/sapstartsrv `OSExecute`** | ~200 LOC | After SecStore yields `sidadm`, authenticated OS-cmd via sapstartsrv SOAP on every SAP host. Universal. |
| 13 | **STRUST/PSE extractor + SSO-trust edges** | ~350 LOC | Dump PSE via `SSFR_PSE_EXPORT`, decrypt with SecStore master key, forge MYSAPSSO2 for any user. Complement to #4. |

### Tier C — nice-to-have

| # | Addition | Effort | Why |
|---|---|---|---|
| 14 | **HANA module** (`sap_hana.py`: creds → privesc → `_SYS_REPO` code dump) | ~600 LOC | Biggest coverage gap. Every S/4 runs on HANA. Use `hdbcli`. |
| 15 | **Persistence menu** (ICF backdoor + cross-client users + SM36 DDIC job + transport injection) | ~500 LOC | Red-teams need this. Each technique is one BAPI call. |

---

## Recommended phased rollout

### Phase 1 — "make J75 work" (1 week)

Target the hardened-Java-admin scenario directly. Unblocks J75 data
extraction and opens ABAP pivots from any RECON-created Java admin.

- **#3** CPACache dumper
- **#4** SAPLogonTicket forger
- **#10** logviewer scraper

### Phase 2 — "broad-spectrum coverage" (2 weeks)

Adds the highest-impact CVEs SAPMAP is currently missing.

- **#1** ICMAD
- **#2** CVE-2025-42999 chain
- **#5** CVE-2025-42957 DMIS
- **#6** `/sap/public/info` pre-auth
- **#7** Capability analyzer

### Phase 3 — "differentiator" (2-3 weeks)

- **#9** Cloud Connector + BTP module — see elaborate plan in [`08_cloud_connector_implementation_plan.md`](08_cloud_connector_implementation_plan.md)
- **#8** P4 deserialization
- **#11** Trusted RFC hop

### Phase 4 — "engagement completeness"

- **#12** sapstartsrv OSExecute
- **#13** PSE extractor
- **#14** HANA module
- **#15** Persistence menu

---

## Key new CVEs to integrate (none currently in SAPMAP)

- **CVE-2022-22536** (ICMAD) — critical gap, both stacks, unauth
- **CVE-2025-42999** — chain partner to existing 31324
- **CVE-2025-42944** — unauth P4 RCE
- **CVE-2025-42957** — S/4HANA DMIS code injection
- **CVE-2020-6364** (Introscope EM) — SolMan chain
- **CVE-2018-2392** (IGS XMLCHART XXE) — unauth arbitrary file read → grab SecStore key pre-user
- **CVE-2023-49583 / CVE-2024-25645 / CVE-2024-33003** — SAP Cloud Connector attack chain
- **CVE-2018-2380** — CRM systems
- **CVE-2023-36922** — IS-OIL (niche but clean chain)

---

## Graph / data-model additions implied by this roadmap

New node types (in `sapmap_models.py`):

- `SCCNode` — SAP Cloud Connector instance
- `BTPSubaccountNode` — Cloud subaccount
- `IASTenantNode` — IAS tenant
- `HANA_DB_Node` — HANA database
- `SMD_AGENT_Node` — Solution Manager Diagnostic Agent

New edge types:

- `TRANSPORT_FLOW` — DEV→QAS→PRD from TMS topology
- `TRUSTED_RFC` — A→B with `RFCEQUSER=Y` / named trust
- `TRUSTS_ISSUER` — B trusts A's SAPSYS cert via STRUSTSSO2
- `SSO_FORGEABLE` — B is reachable from A via forged MYSAPSSO2
- `TUNNELS_TO` — SCC → BTPSubaccount
- `MAPS` — SCC → on-prem SAPNode (per destination mapping)
- `CALLBACK_REACHABLE` — RFC call-back abuse edge
- `MANAGED_BY_SOLMAN` / `CUA_CHILD_OF` — hub-and-spoke admin trust

New `Finding` categories:

- `auth.history.exfil`, `rfc.shell.escape.destination`,
  `sso2.privkey.exfil`, `tms.injection.possible`,
  `icf.sensitive.exposed`, `abap.hardcoded.credential`,
  `hana.repo.leak`, `persistence.installed`,
  `role.capability.inventory`, `ztable.credential`,
  `saprouter.permissive.route`, `scc.default.creds.live`.

---

## Cloud Connector elaborate plan

The Cloud Connector + BTP feature has its own deep implementation plan
(detection ladder, dataclasses, SVG node shapes, edge kinds, risk-score
matrix, compliance-tag map, 6-week roadmap, scope fence, CVE-verification
table) at [`08_cloud_connector_implementation_plan.md`](08_cloud_connector_implementation_plan.md).
It supersedes the §8.* sketch in `03_cloud_connector_btp.md` and replaces
the placeholder line about item #9 above.

---

## Already shipped (out of backlog scope)

For status awareness while the backlog above stays focused on *new*
work:

- **Linux root LPE** — both Copy Fail (CVE-2026-31431) and Dirty Frag
  (no CVE; embargo broke 2026, no upstream patch yet) ship via the
  unified `Check Linux Root LPE` / `Escalate to Root` menu items.
  Backend auto-picker (`sapmap_lpe_auto`) prefers Copy Fail when both
  are viable (pure-Python, smaller blast radius); falls back to Dirty
  Frag on Copy-Fail-immune kernels.  Override via
  `SAPMAP_LPE_FORCE=copyfail|dirtyfrag`.
- **Capability analyser** (#7).
- **Cloud Connector + BTP module** (#9) — see plan in
  `08_cloud_connector_implementation_plan.md`; major sub-items
  (fingerprint, default-creds probe, JCEKS extraction, BTP harvest +
  token mint) are landed.
- **SCC Principal-Propagation analyser** — static rule engine over
  the SCC backup zip's `<principalPropagationConfiguration>` and
  per-subaccount `trustcfg_<uuid>.xml` files. Flags
  `${name}`/`${email}` CN bindings with no `<condition>`, hardcoded
  privileged-user mappings (DDIC/SAP*), long forwarded-cert
  validity, and multi-IdP / external-IdP trust setups. Schema
  reference in
  [09_principal_propagation_schema.md](09_principal_propagation_schema.md).
  Auto-runs after every Extract Keystore; manual re-run via the
  SCC right-click menu.

## Caveats

- CVE numbers for 2024–2026 were compiled by research agents from
  memory + web search; verify against NVD / SAP Security Patch Day
  index before committing to an implementation.
- Attack *concepts* (default creds, JCEKS extraction, XOR-0x74 CPACache, 
  PSE extraction, principal-propagation forgery, destination-cleartext
  read) are version-agnostic and will remain relevant; specific CVE
  numbers and patch levels move.
- Everything under `Tier C` is valuable but can wait until SAPMAP's
  core operator experience is complete for the Tier A/B items.
