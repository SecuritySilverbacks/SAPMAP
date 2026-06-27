# Plan — Detection Evasion & Audit Tampering Primitives for SAPMAP

**Status:** research / planning. Not a build spec. No code, no commits.
The user (Joris) will read this, hand it to a SOC engineer, and decide what to build.

**Scope statement.** SAPMAP already drops noisy artefacts on every node it touches:
SAL events for BAPI_USER_CREATE1, USR02 / UST04 / USRBF2 inserts via the SQL writer,
CDHDR/CDPOS rows for profile assignments, SXPG_COMMAND_EXECUTE spool entries,
dpmon EUP-2 events, SecurityAudit.\<n>.log lines on the Java side, ICM access-log
entries on every CVE-2025-31324 chunk write, etc.  Most of this is **load-bearing**
for the audit trail of the engagement.  But on real red-team work — where the customer
deliberately wants to test SOC detection — an evasion mode is necessary, and on
covert ops the operator has to choose which residue to leave.

This document is the **catalogue** of what SAPMAP would have to do to minimise or remove
that residue, written so a defender can use the same catalogue as their detection backlog.
Every offensive primitive in §4 has a matching blue-team entry in §5.

> **Operator-safety constraint** — all evasion actions belong behind an explicit
> `--allow-evasion` gate with its own banner, exactly like the existing
> `--allow-destructive` flag.  The default SAPMAP run must **never** tamper with audit.

---

## 1. Telemetry inventory — ABAP side

| # | Channel | What it captures | Storage | Read auth | Modify auth | SIEM-forwarded? | S/4 2023 default |
|---|---|---|---|---|---|---|---|
| 1.1 | Security Audit Log (SAL) | Logon success/fail (AU1/AU2), RFC calls (AUK), user-master events (AUB/AUC/AUD), transaction starts (AU3), table accesses (AUP), config changes (AUZ) | `RSAU_BUF_DATA` (in-memory ring buffer), `$DIR_AUDIT/audit_yyyymmdd_<SID><n>` files, plus persistent `RSAU_PERS` (`SAL_LOG_EVENTS` ≥ 7.50) | SM20 / RSAU_READ_LOG; needs `S_ADMI_FCD AUDA` or `S_TABU_DIS SS` | `S_ADMI_FCD AUDA`, `S_TCODE RSAU_CONFIG`/SM19 | Almost always (ETD, Splunk SAP TA, Sentinel SAP Connector) | **On** by default since 7.50; ~25 classes selected; rotation daily; file mode `0700` owned by `<sid>adm` |
| 1.2 | System Log | Kernel-level events: WP dumps, segfaults, rdisp warnings, message-server errors | `$DIR_HOME/SLOG*` files + circular shared-memory; SM21 reads | SM21 / `S_ADMI_FCD ST22` | Read-only by design — `<sid>adm` can `cat`/`>` the file but kernel rewrites header on next event | Often via CCMS-to-SIEM bridge | Always on |
| 1.3 | ABAP Application Log (BAL) | App-defined events: TMS imports, batch jobs, BAPI returns, RFC errors | `BALHDR` (header), `BALDAT` (data, compressed), `BAL_INDX` | SLG1 / `BAL_LOG_*` BAPIs; `S_APPL_LOG` | `S_APPL_LOG ACTVT=06 (delete)` | Rarely — usually local only | Persistence varies by object; default 30 days |
| 1.4 | Change Documents (CDHDR/CDPOS) | Business-object change history: user-master (USH02/USH04/USH10/USH12 derived), customizing tables, role changes (AGR_DEFINE), profile assignments | `CDHDR`, `CDPOS` (compressed), `JCDS` (status changes) | SCDO / RSSCD100; `S_TABU_DIS CD` | `S_TABU_DIS CD ACTVT=06` or direct SQL | Hardly ever — local | Always recorded for objects with change-doc class registered |
| 1.5 | Table Logging (DBTABLOG) | Row-level inserts/updates/deletes for tables with **Log Data Changes** flag in SE13 | `DBTABLOG` | SCU3 / `S_TABU_DIS SS` | Controlled per-table via `rec/client` profile parameter; per-table flag in SE13 | Some customers forward; usually no | **Off** for most tables; on for ~60 customising tables on a stock S/4; **not** on USR02 by default |
| 1.6 | Read Access Logging (RAL) | Field-level reads of "sensitive" customer-defined fields (IBAN, salary, HCM PA0008) | `SRAL_LOG`, `SRAL_LOG_EXT`, archived via SARA `SRAL`/`SRAL_EXP` | SRALMONITOR / SRALMANAGER; `S_RAL_*` | `S_RAL_ADM` to flip configuration | Increasingly yes for GDPR posture | **Off** by default; on at enterprises with mature data protection |
| 1.7 | Workload Statistics | RFC call counts, dialog steps, tcode invocation, response times, user-per-tcode | `STAT*` files in `$DIR_DATA`, MONI table, STAD/ST03 readers | STAD / ST03N; `S_ADMI_FCD ST0R` | `stat/level` parameter; runtime via RZ11 | Mostly fed into Focused Run / ETD for behavioural analytics | `stat/level=1` default; granular timing on |
| 1.8 | User-master history | Password-change history (USR02 fields LASTLOGON, BCODE/PWDSALTEDHASH), role assignment history (USH02/USH04/USH10/USH12), profile history (UST04 / USR04) | Those tables directly | `S_USER_GRP` / `S_TABU_DIS US` | `S_USER_GRP` w/ `ACTVT=02`; SQL bypasses | Sometimes via SAP IGA / GRC EAM | All on, all the time |
| 1.9 | Transport logs | Who released, who imported, return code of each step | `E070`, `E071`, `E070A`, `TMSBUFFER`, `TMSCDOC`; file logs in `/usr/sap/trans/log/`, `tmp/`, `actlog/` | STMS / `S_TRANSPRT`; `S_CTS_ADMI` | `S_CTS_ADMI` table edit; OS-level filesystem | TMS forwards to SolMan; SolMan forwards to SIEM | Always on |
| 1.10 | HCM cluster audit | Payroll / HR access trails | `PCL2`, `PCL4` clusters; tables `T77UA`, `T77AW` | SE16 on cluster, `S_DEVELOP` | `S_TABU_DIS Pn` per infotype | Only HR-aware SIEMs | Always on at HR-deployed customers |
| 1.11 | SolMan / Focused Run data extraction | Periodic pull of SAL, STAD, BAL, transport history, syslog, security baseline drift via RFC | Stored on SolMan / FRUN host, not on monitored system | RFC user `SAPSUPPORT` / `SOLMAN_BTC` | Mostly unattainable from monitored system — SolMan owns the pull | Yes — that's the whole point | Standard at enterprises since 2019 (Maintenance Planner mandate) |
| 1.12 | ICM HTTP access log | One line per HTTP request: timestamp, source IP, method, URL, status, response size, user (post-auth) | File at `$(icm/HTTP/logging_0=PREFIX=/,LOGFILE=...)`; pattern usually `/usr/sap/<SID>/<INST>/log/http*.log` | OS-level read; SMICM | OS-level truncate; `icm/HTTP/logging_0` param change via RZ11 | Yes — often via Splunk forwarder on the SAP host | Off by default; **on at customers that use Fiori/WebGUI** |
| 1.13 | Gateway trace | RFC server registrations, secinfo/reginfo decisions, internal/external calls | `dev_rd` in `/usr/sap/<SID>/<INST>/work/`; `gw/log_level={0..3}` controls verbosity | OS-level | OS-level; RZ11 to change level live | Rarely — local only | `gw/log_level=1` default |
| 1.14 | Work-process trace | ABAP runtime, RFC call entry, AUTHORITY-CHECK results | `dev_w<n>` in `/usr/sap/<SID>/<INST>/work/`; verbosity via `rdisp/TRACE` (0..3) | OS-level | OS-level; RZ11 dynamic | Rare | Level 1 default |
| 1.15 | RFC trace (client-side) | Per-connection RFC payload | `dev_rfc<n>` in same work dir; controlled by `RFC_TRACE` env / `rdisp/TRACE` | OS-level | OS-level | Rare | Off by default; flipped on during troubleshooting |
| 1.16 | SAProuter log | Connect / disconnect / perm-denied events with timestamps | File set via `-G <file>` flag at startup; **off by default** | OS-level on the saprouter host | OS-level | Sometimes shipped via syslog | Off by default — defenders running mature setups force `-G` |
| 1.17 | Kernel filesystem logs `<sid>adm` can reach | `dev_*` traces, `stderr*` startup logs, `available.log`, `sapstartsrv.log` | `/usr/sap/<SID>/<INST>/work/` | `<sid>adm` (OS) | `<sid>adm` (OS) — full RW | Often via Filebeat / Splunk forwarder running as root | All on |
| 1.18 | NW Audit Provider Service / CCMS bridge | CCMS-Alert table `MTE_ALARMS`, sapcontrol `GetAlertTree` | Forwarded to SolMan, ETD | RZ20 | `S_RZL_ADM` | Yes | On by default |

**Cross-cutting note — `RSAU_PERS` / `SAL_LOG_EVENTS`.** Since 7.50, SAL can also persist to a table (`RSAU_CONFIG` → "Recording Target: File and Table" or "Table only"). Kernel 7.55+ supports `RSAU_CONFIG_LOG_RES` for log resilience. File-deletion evasion does **not** silence the table variant — they have to be deleted separately.

**Cross-cutting note — integrity.** `rsau/integrity=1` (active since 7.40, default off, default **on** in S/4 2023 secure baseline) HMAC-signs every flush of the SAL file. Tampered files surface as integrity errors in `RSAU_FILE_ADMIN`'s Check Integrity job. The HMAC key is held in `RSAU_KEYS` and is **re-creatable** by anyone with `S_ADMI_FCD AUDA` — which means an attacker with that role can also blank the key, re-sign a forged file, and bypass the check unless the verifier compares the key fingerprint to a known-good baseline.

**Cross-cutting note — file size cap.** Per Perez-Etchegoyen & Vandevanter (Troopers14, slide 19), the historical default for `rsau/max_diskspace/local` is **100 MB/day per instance**. The default behaviour when the cap is reached is **stop logging until the next day's file is created** (not wrap-around, not error-out). This is the primitive behind 4.A.19 — an attacker who can generate enough audit-eligible events (failed logons, RFC probes) within the early hours of a day can intentionally burn the cap and then operate audit-blind. Some kernels honour `rsau/wrap_around=1` to switch to overwrite-oldest behaviour; verify against the customer's actual instance profile because both wrap and stop have evasion implications.

**Cross-cutting note — terminal-name source.** Per Perez-Etchegoyen & Vandevanter (Troopers14, slide 16), the SAL record's source field is **client-supplied** unless `rsau/ip_only=1`. The kernel makes a best-effort to insert the terminal name as reported by the SAPGUI / RFC client; only if that is empty does it fall back to the IP address. This drives 4.A.18.

---

## 2. Telemetry inventory — Java side

| # | Channel | What it captures | Storage | Read auth | Modify auth | SIEM-forwarded? | NW 7.5/J 7.50 default |
|---|---|---|---|---|---|---|---|
| 2.1 | UME Security Audit | UME-layer logon, role changes, user-master events | `/usr/sap/<SID>/J<NR>/j2ee/cluster/server<n>/log/system/SecurityAudit.<idx>.log`, configured in NWA `/nwa/log-config` "SAP_SECURITY_AUDIT" location | NWA Administrator role; OS read | NWA "Log Configurations" TraceLevel flip; OS truncate | Yes — top-tier channel | On by default; INFO severity |
| 2.2 | Audit log | Component-specific audit (P4, ABAP-Java connection, JCo destination changes) | `audit/audit.<idx>.log` under same log root | Administrator; OS | NWA flip; OS | Yes | On |
| 2.3 | defaultTrace | Generic engine trace — covers exceptions, login attempts depending on TraceLevel | `defaultTrace.<idx>.trc/.log`, default ~10 MB rotated; controlled by NWA root-logger TraceLevel | Administrator; OS | TraceLevel flip via NWA or telnet `set_log_level` | Often, depending on volume | Severity = INFO default |
| 2.4 | server_<n>.log | Server-process console + start/stop/crash | `server<n>.log` in cluster log root | Administrator; OS | OS truncate | Sometimes | On |
| 2.5 | HTTP access log (ICM side) | Inbound HTTP per-request on the Java dispatcher | Same `icm/HTTP/logging_0` infrastructure as ABAP; file under `/usr/sap/<SID>/<INST>/log/` | OS; SMICM-equivalent on Java | OS truncate; ICM parameter | Yes | Often on for Fiori-exposed AS Java |
| 2.6 | log4j config | Routing rules from logger name to appender | `log-configurations.xml` per server; location-specific files in `log-configurations/` | Administrator (NWA "Log Configurations"); OS | Same — runtime via NWA reloads the appender | n/a (controls everything above) | Default config |
| 2.7 | Visual Composer audit | VC model deploy/edit, especially relevant for CVE-2025-31324 attack post-mortem | Under `vc/` log subdir + dedicated VC audit | Administrator; OS | OS truncate; VC-internal toggles | Sometimes | On at customers running VC |
| 2.8 | NWDS / Deploy logs | SDM / JDI deploys, telnet pushes | `deploy/*.log`, `cluster/*/log/SystemDeploy/` | Administrator; OS | OS truncate | Rare | On |
| 2.9 | Telnet / JMX console | Per-session commands typed into the telnet console (port 50008 + nr*100) | Console session logs in `cluster/<n>/log/sessions/` (when audit enabled) | Administrator | Direct OS | Mostly no — local-only | Off-by-default session logging |
| 2.10 | ICM trace for the J2EE engine | dev_icm equivalent on the Java side | `dev_icm`, `dev_icmf` in `work/` | OS | OS | Rare | Level 1 default |
| 2.11 | NWA runtime "Log Configurations" surface | Live-editable: per-location severity, appender bindings | In-memory until next persist; `/nwa/log-config` | Administrator role | Administrator role | n/a | Live-editable |
| 2.12 | OS owner of all Java logs | All log roots owned by `<sid>adm`, mode `0700` on hardened, `0750` typical | n/a | `<sid>adm` and root | `<sid>adm` (any process — including JSP webshell from CVE-31324) | n/a | n/a |

**SIEM forwarding mechanisms (Java side).**  In SIEM-mature shops:

- Splunk Universal Forwarder running as root on the AS Java host, monitoring `cluster/server*/log/`
- CEF gateway pulling NWA logs via the `/nwa/logaccess` REST API
- Direct syslog out via log4j `org.apache.log4j.net.SyslogAppender` (rare)
- SAP Enterprise Threat Detection (ETD) pulling via the *Log Collector* daemon on each host
- Focused Run *System Monitoring* pulling SecurityAudit.log via SAP Host Agent `GetEnvironment`

Each forwarder is its own kill-switch: stop the agent, log-truncate, restart the agent.  Most monitor file inodes — they re-pick a truncated file from offset 0 only if the inode changes, which is why **truncate-in-place** (`> file`) usually wins over `rm`+recreate for evasion. Confirm against the specific forwarder before relying on this.

---

## 3. Shared / infrastructure telemetry

| # | Channel | Notes |
|---|---|---|
| 3.1 | SAProuter trace + saprouttab logging | Trace file via `-G <path>` flag (off by default); saprouttab P/D rules can include a "log connection" `*` indicator. Customers run mature setups with `-G` and rotating log; absence of `-G` flag means SAProuter is forensically blind. |
| 3.2 | Cloud Connector audit | Files at `<scc_root>/log/audit/<subaccount>/audit-log_<ts>.csv`; rotates daily; SAP recommends external persistent storage. Default mode `0600` owned by `sccadmin`. Backup ZIP contains last `audit/` directory contents. |
| 3.3 | SAP Web Dispatcher access log | Same `icm/HTTP/logging_0` mechanism as ICM; sits in front of every Fiori entry; usually configured with X-Forwarded-For preservation and forwarded to WAF/CDN logs. |
| 3.4 | Linux OS — rsyslog / journald / auditd | `/var/log/messages`, `/var/log/secure`, journald binary store; auditd `audit.log` with syscall granularity. Forwarded by Filebeat/rsyslog to SIEM. |
| 3.5 | Windows OS — Event Log / Sysmon / ETW | Security log (4624/4625/4672/4688), Sysmon process-create/network/file-create, ETW providers; forwarded via WEC + Splunk UF. |
| 3.6 | HANA audit | Policy-based; default policies log `ALTER USER`, `GRANT`, `CONNECT`; targets: Linux syslog, CSV file under `hdb_audit/`, or `M_AUDIT_LOG` table. `AUDIT POLICY` definitions in `AUDIT_POLICIES`. |
| 3.7 | MSSQL trace | XEvent session `system_health` plus customer-defined sessions; `sql_log_in/out`, `audit_event`; SAPMAP SQL writer triggers `audit_login_change_password` event. |
| 3.8 | Oracle DBA_AUDIT_TRAIL / Unified Audit | `DBA_AUDIT_TRAIL`, `UNIFIED_AUDIT_TRAIL`; `audit_trail=DB,EXTENDED` standard for SAP on Oracle. |
| 3.9 | MaxDB | `dbmcli show log_segments`, `dbm.knl` log, `dbm.prt` protocol — sparse for forensics. |
| 3.10 | Network layer | Firewall flow logs, NSG/cloud equivalents; Suricata/Zeek often deployed on SAP DMZs; specific signatures for known CVEs (Snort SID coverage for 10KBLAZE, CVE-2025-31324). |
| 3.11 | Backup-system events | RMAN scripts, DB2 LOAD, HANA backup CLI: operator activity leaks into backup-host logs and BR\*Tools `backXXXX.log`. |

---

## 4. Evasion technique catalogue

Each entry uses this schema:

> **Mechanism · Authority · Reversibility · Bypasses · Residue · Detection · Applicability**

### 4.A ABAP-stack techniques

#### 4.A.1 SM19 / RSAU_CONFIG filter narrowing (drop classes/users during op)

- **Mechanism.** Modify the active SAL filter so the operator's user / target client / event class is excluded from selection. Two implementations: (a) static profile via `RSAU_CONFIG` "Save & Activate", (b) dynamic profile via `RSAU_CONFIG` → Reload runtime config. Filters are stored in `RSAUPROF` (static) and `RSAU_PERS_INFO` (dynamic).
- **Authority.** `S_TCODE RSAU_CONFIG` + `S_ADMI_FCD AUDA`. Direct SQL: `S_TABU_DIS` with the SS authgroup gives DB-level edit, bypassing the tcode.
- **Reversibility.** Snapshot `RSAUPROF` rows before edit, restore after. The filter reload itself is logged (event class AUZ), so timing matters — restore inside the operation window.
- **Bypasses.** §1.1 entirely **for the affected user/class**.
- **Residue.** Each filter change writes an AUZ "Audit configuration changed" event (kernel ≥ 7.40). Some kernels also write a syslog SY3 row. On kernel ≥ 7.55, `RSAU_CONFIG_LOG_RES` writes a separate persistence record that survives filter reset.
- **Detection.** SIEM rule on AUZ events from any user not on the SAL-admin allowlist; alert on `RSAUPROF` deltas; daily snapshot diff.
- **Applicability.** Kernel ≥ 7.40 for dynamic profiles; static profiles work back to 4.6C.

#### 4.A.2 SAL kernel-parameter disable (`rsau/enable=0`, `rsau/local/file=`, `rsau/integrity=0`)

- **Mechanism.** Flip kernel parameters at runtime via RZ11 (some non-persistent), or rewrite `DEFAULT.PFL` / instance profile then `RSPARAM` reload. `rsau/enable=0` disables SAL until restart; `rsau/local/file=` redirects the file to a tempfs path that gets unlinked; `rsau/integrity=0` disables HMAC so files can be rewritten.
- **Authority.** Runtime: `S_RZL_ADM ACTVT=01`. Persistent: OS write on profile files (`<sid>adm`).
- **Reversibility.** Snapshot `RSPARAM` output → restore. Persistent profile edits also need `transactions/instance restart` to fully reload; runtime flip via RZ11 reverts at next instance restart anyway.
- **Bypasses.** §1.1 entirely from the flip moment forward.
- **Residue.** SAP Note 3380209: setting `rsau/enable=0` on some kernels still emits AU3 logon events because the kernel re-checks per work-process startup, not per event. Always test the specific kernel. RZ11 changes themselves are CDHDR-logged in table `TPFYPROPTY`.
- **Detection.** Watch `TPFYPROPTY` change-doc; watch `dev_w*` for `rsau` parameter change strings; absence of SAL events for normally noisy users (DDIC, SAPSYS) is a strong heuristic.
- **Applicability.** All kernels; specific bug surface varies.

#### 4.A.3 STAD silencing (`stat/level=0`)

- **Mechanism.** RZ11 flip → STAD/ST03 stops recording new dialog steps and RFC calls in the `STAT*` files.
- **Authority.** `S_RZL_ADM ACTVT=01`.
- **Reversibility.** Snapshot → restore; STAD has ring-buffer character so missed minutes simply have no data, but the gap itself is detectable on aggregated dashboards.
- **Bypasses.** §1.7.
- **Residue.** `TPFYPROPTY` change row; ETD's behavioural baseline for the system shows a gap.
- **Detection.** "Empty hour" detector on ST03 hourly aggregates; `TPFYPROPTY` monitor.
- **Applicability.** Universal.

#### 4.A.4 DBTABLOG suppression for specific tables

- **Mechanism.** Per-table logging is controlled by the `Log Data Changes` flag in SE13 (stored in `DD09L.PROTOKOLL='X'`). Editing that field via SE11 fires CDHDR. SQL editing of `DD09L` bypasses CDHDR but invalidates the runtime buffer until next nametab activation. The cleaner approach is to flip `rec/client` to exclude the active client number — `rec/client = 001,200` excludes 100 from logging globally.
- **Authority.** Direct SQL: `S_TABU_DIS DS`. `rec/client` flip: `S_RZL_ADM`.
- **Reversibility.** Snapshot DD09L row OR snapshot `rec/client` value.
- **Bypasses.** §1.5 for the target table(s).
- **Residue.** RZ11 audit of `rec/client`; or DD09L change-doc if the SE13 path is used.
- **Detection.** Monitor `rec/client` parameter; alert on any deviation from `ALL` or the standard customer baseline. DD09L change monitor on the security-critical tables (USR02, UST04, USR04, RFCDES, AGR_USERS).
- **Applicability.** Universal; `rec/client` predates ECC.

#### 4.A.5 Change-document generation skip

- **Mechanism.** CDHDR/CDPOS rows are written only for objects with an active change-document object registered in `TCDOB`/`TCDRP`. Deactivating the object (via SCDO) for the duration of the op silences the trail. Per-field control is in `TCDRP`. A subtler variant: use BAPIs that bypass the standard update task (`CALL FUNCTION ... IN UPDATE TASK`) and instead write directly via SQL — many user-master BAPIs honour `S_TABU_DIS`.
- **Authority.** SCDO maintenance: `S_DEVELOP DEBUG` and `S_TCODE SCDO`. Direct SQL on USR04/UST04/USRBF2: `S_TABU_DIS US`.
- **Reversibility.** Re-activate the object; row-snapshot before edit.
- **Bypasses.** §1.4 for the chosen object.
- **Residue.** TCDOB change-doc on its own object (`SCDO` event leaks back into CDHDR).
- **Detection.** Watch TCDOB itself; the rollover is a self-referential indicator.
- **Applicability.** Universal.

#### 4.A.6 Decoy-event noise generator (drown signal)

- **Mechanism.** Burst-create harmless audit events to flush the SAL ring buffer or accelerate file rotation. Examples: thousands of failed-logon attempts on a non-existent user (AU2 events), repeated RFC pings of a function module that fires AUK, RAL hits on a registered field. The buffer fills, the file rotates, the SOC analyst's filter is overwhelmed, the real event is one of N where N is large.
- **Authority.** Just network reach; failed logons need no auth.
- **Reversibility.** None — the noise is the point. Operator must be honest that this is loud-but-noisy.
- **Bypasses.** Practical SOC review; doesn't silence channels.
- **Residue.** Massive AU2/AUK volume. Counter-intuitively, this is its own IoC.
- **Detection.** Anomaly detection on event-rate per type; alert when AU2 rate > N std dev above baseline.
- **Applicability.** Universal but operationally noisy; only useful when SOC has fixed-window human review.
- **Related.** See 4.A.19 ("SAL daily-size cap exhaustion") for the variant aimed at the 100 MB/day file cap rather than at SOC human review. Perez-Etchegoyen & Vandevanter (Troopers14, slides 19–21) frame this as the original "reach the limit" attack — drown-the-SOC and burn-the-cap are sister primitives but the detection and operator goals differ.

#### 4.A.7 Low-event-volume primitive selection

- **Mechanism.** When two paths exist to the same outcome, choose the path with fewer SAL events.
  - `BAPI_USER_CREATE1` → emits AUB + AUC (≥ 2 events) + CDHDR.
  - `BAPI_USER_PROFILES_ASSIGN` on an existing user → emits AUD only (1 event), no new USR02 row.
  - `RFC_ABAP_INSTALL_AND_RUN` for ABAP injection → emits AU5 (program executed) + sometimes nothing else for the inner SQL.
  - `SUSR_USER_CREATE_AS_COPY` (used by SAPMAP for stealthy clone) — emits the same AUB but copies role assignments without separate AUD events.
  - Avoid `BAPI_USER_CREATE1` followed by `BAPI_USER_PROFILES_ASSIGN` followed by `BAPI_TRANSACTION_COMMIT` — that's three commits, three timestamps.
- **Authority.** Method-specific; the selection logic itself needs no privilege.
- **Reversibility.** N/a — this is preference, not tampering.
- **Bypasses.** Volume-based detection, not the channel itself.
- **Residue.** Always something; aim for one event per intended action.
- **Detection.** Per-tcode/per-BAPI usage baselining — anomalous use of `BAPI_USER_PROFILES_ASSIGN` outside the standard IGA tooling.
- **Applicability.** Universal.

#### 4.A.8 Identity impersonation via assertion / MYSAPSSO2 ticket

- **Mechanism.** SAPMAP already forges MYSAPSSO2 tickets (see plan 12). For evasion: choose to impersonate a **noisy baseline identity** rather than `SAP*` / `DDIC`. A ticket for the `SOLMAN_BTC` or `RFCUSER` baseline service user generates AU3 events identical to thousands of legitimate ones, blending into noise.
- **Authority.** Whatever the PSE-extraction primitive needed (typically `<sid>adm` OS).
- **Reversibility.** N/a — ticket logon is auditable but per-identity.
- **Bypasses.** Identity-based detection (no "weird user logged in" alert).
- **Residue.** AU3 event for the **impersonated** identity. Some kernels log the technical user alongside; check the kernel.
- **Detection.** Behavioural baseline per service user — alert when `SOLMAN_BTC` logs in from an IP it has never used.
- **Applicability.** Requires kernel that accepts SSO2 logon (`login/accept_sso2_ticket=1`) and STRUSTSSO2 ACL entry.

#### 4.A.9 dpmon virtual SAP\* — identity attribution

- **Mechanism.** Already shipping (plan 11). For evasion-relevant detail: SAL's EUP-2 event for dpmon SAP\* activation attributes to the **OS user that ran dpmon** (`<sid>adm`), **not** the SAP user who later logs on with the OTP. Subsequent BAPI calls under the SAP\* session show `USER=SAP*` but the SU01 logon timestamp updates `SAP*` itself — which is suspicious in its own right.
- **Authority.** `<sid>adm` OS.
- **Reversibility.** Cannot remove the EUP-2 event short of SAL file truncation.
- **Bypasses.** Per-SAP-user behavioural baselining for the operator's identity.
- **Residue.** EUP-2 event; `USR02.TRDAT/LTIME` for SAP\* updated.
- **Detection.** EUP-2 events specifically (literally a single SIEM filter); USR02 last-logon date on SAP\* changing.
- **Applicability.** Kernel ≥ 790.

#### 4.A.10 Targeted SAL row deletion

- **Mechanism.** Three paths:
  - **(a) Filesystem.** Identify file via `RSAU_FILE_ADMIN` Display Files → OS-level `sed`/`dd` the offending rows out, or full truncate. Recompute HMAC if `rsau/integrity=1`.
  - **(b) Table.** `DELETE FROM RSAU_PERS WHERE ...` if SAL is in table mode. Needs `S_TABU_DIS SS` or direct DB.
  - **(c) Buffer flush.** `RSAU_FLUSH_BUFFER` on demand, then file delete before SIEM forwarder reads.
- **Authority.** (a) `<sid>adm` OS + `S_ADMI_FCD AUDA` (for the kernel API). (b) `S_TABU_DIS SS` or DB. (c) `S_ADMI_FCD AUDA` runtime.
- **Reversibility.** None — the goal is permanent removal.
- **Bypasses.** §1.1 retroactively.
- **Residue.** (a) HMAC mismatch surfaces in next `RSAU_FILE_ADMIN` integrity scan if `rsau/integrity=1` and HMAC key isn't rotated. (b) Audit DB-table edit appears in DBTABLOG **if** RSAU_PERS is logged (rare). (c) Buffer flush is itself a kernel event on ≥ 7.55.
- **Detection.** `rsau/integrity=1` + immutable HMAC key fingerprint; daily SAL row-count exfil to SIEM (SIEM notices missing rows even if file is clean); SIEM file-watcher on `$DIR_AUDIT`.
- **Applicability.** RSAU_PERS only on ≥ 7.50; `rsau/integrity` only on ≥ 7.40.

#### 4.A.11 SM18 / RSAUPURG accelerated rotation

- **Mechanism.** SAP's own SAL file cleanup tool calls `RSAU_CLEAR_AUDIT_LOG`; default minimum age = **3 days** (hard-coded protection). To rotate fresh: invoke `RSAU_TRUNCATE_LOG` (kernel ≥ 7.50 helper) or hand-roll via custom report using `CL_RSAU_FILE_ADMIN` after lowering the constant. The hard 3-day floor is a code constant inside `RSAU_CLEAR_AUDIT_LOG` — patchable via debugger (`/h` → `change` → `lv_min_age = 0`) by anyone with `S_DEVELOP DEBUG ACTVT=02`.
- **Authority.** Standard SM18: `S_ADMI_FCD AUDA`. Debugger bypass of 3-day floor: `S_DEVELOP DEBUG 02`.
- **Reversibility.** None.
- **Bypasses.** §1.1 retroactively.
- **Residue.** RSAUPURG run leaves an AUZ event ("audit log files deleted").
- **Detection.** AUZ events for RSAUPURG outside scheduled maintenance windows; debugger usage on RSAU_* function group (S_DEVELOP DEBUG 02 is itself a high-signal IoC if monitored).
- **Applicability.** Universal.

#### 4.A.12 USR* history scrub

- **Mechanism.** Direct DELETE on USH02/USH04/USH10/USH12 to remove password-history / role-assignment-history rows tied to the operator's session.
- **Authority.** `S_TABU_DIS US ACTVT=06` or DB-level.
- **Reversibility.** None.
- **Bypasses.** §1.8.
- **Residue.** DBTABLOG row IF those tables are in the `rec/client`-logged set (almost never).
- **Detection.** Daily row-count export of USH* tables; SoD audit on USH02 row-count drift.
- **Applicability.** Universal.

#### 4.A.13 CDHDR/CDPOS row deletion / objectid masking

- **Mechanism.** `DELETE FROM CDHDR WHERE CHANGENR IN (...)` plus matching CDPOS — but be careful: a CDPOS without CDHDR is itself an IoC. Better is `UPDATE CDHDR SET OBJECTID = '<benign>'` to make the row attribute to a different business object. Even better: change UNAME to a generic batch user.
- **Authority.** `S_TABU_DIS CD ACTVT=06` (rarely granted) or DB.
- **Reversibility.** None.
- **Bypasses.** §1.4.
- **Residue.** DBTABLOG IF CDHDR is logged (almost never).
- **Detection.** Append-only CDHDR replication to SIEM; CHANGENR sequence-gap detection.
- **Applicability.** Universal.

#### 4.A.14 dev_rfc / dev_w* trace truncation via OS exec

- **Mechanism.** From SXPG_STEP_XPG_START / GW SAPXPG / SSH-as-<sid>adm: `> /usr/sap/<SID>/<INST>/work/dev_rfc<n>` and similarly for `dev_w*`, `dev_disp`, `dev_rd`. Empty-out, not delete, so the kernel keeps writing to the same inode.
- **Authority.** `<sid>adm` OS.
- **Reversibility.** None — truncation only.
- **Bypasses.** §1.13/1.14/1.15.
- **Residue.** File-mod-time updates; filesystem auditing (auditd watch) catches the truncation; if a Filebeat-style forwarder tails the file by inode it loses position but re-syncs at byte 0.
- **Detection.** auditd `-w /usr/sap/<SID>/<INST>/work -p wa`; ETD baseline of expected dev_* growth rate (gap of 0 bytes per hour is suspicious).
- **Applicability.** Universal.

#### 4.A.15 Transport log scrub

- **Mechanism.** Transport-system file logs live in `/usr/sap/trans/log/`, `/usr/sap/trans/tmp/`, `/usr/sap/trans/actlog/`. After a malicious transport (see plan 05 §1.3, the "transport injection" path), truncate the matching `<TR>.log` files. Also clean `E070`, `E071` rows for the TR.
- **Authority.** OS user `<sid>adm` on the transport directory share host.
- **Reversibility.** None.
- **Bypasses.** §1.9.
- **Residue.** TR sequence gap (missing E070 entry surfaces as a numbering hole).
- **Detection.** SolMan TMS Forward Job already pulls E070; SIEM gap detection.
- **Applicability.** Universal.

#### 4.A.16 Solution Manager / Focused Run pull-collector hijack

- **Mechanism.** SolMan / FRUN pull telemetry from monitored systems via dedicated technical user (commonly `SAPSUPPORT`, `SOLMAN_<SID>_<CLNT>`, `SMD_*`). Deleting or locking the user breaks the pull; renaming its RFC destination on the central system silences forwarding without a "user deleted" event on the monitored system. Alternative: register a fake `SAPHostAgent` daemon that intercepts the pull and returns clean data.
- **Authority.** SU01 lock: `S_USER_GRP` on group `SUPER`. RFC destination rename: SM59. Host Agent interference: root.
- **Reversibility.** Unlock / rename back. The pull-gap creates an alert on the central system but **not** on the monitored system.
- **Bypasses.** §1.11.
- **Residue.** SolMan-side alert ("monitored system unreachable").
- **Detection.** Central-side pull-failure alert. Increasingly enterprises wire this back to PagerDuty.
- **Applicability.** Wherever SolMan / FRUN is deployed (almost everywhere).

#### 4.A.17 SAL message-template deletion via SE92 / TSL1D (legacy)

- **Mechanism.** Audit-log event types are described by template messages in table `TSL1D` (and dependent `TSL1T` text rows), maintained via transaction `SE92` (Edit System Log Messages). Per Perez-Etchegoyen & Vandevanter (Troopers14, *Attack #1 – Delete SAL messages*, slides 13–15), the SE92 / RSLG report bundle in pre-fix kernels does **not** enforce a strong authority check on the *delete* path: any user holding `S_TCODE SE92` could remove a template row. Once the template row is gone, the kernel still triggers the event, the kernel still allocates a slot, but **SM20 / RSAU_READ_LOG show nothing for that event ID** because the renderer has no template to substantiate. Net effect: surgical, per-event-type silencing without touching the SAL file itself. Also reachable via `S_DEVELOP DEBUG` on the same delete routine.
- **Authority.** Pre-fix: just `S_TCODE SE92`. Post-fix (SAP Note 1926485, December 2013): proper authority object required on the message group; `S_DEVELOP DEBUG` can still bypass it.
- **Reversibility.** Snapshot the matching `TSL1D` / `TSL1T` rows before deletion; re-insert after. The text rows are language-keyed (`SPRAS`) — snapshot every installed language.
- **Bypasses.** §1.1 surgically, per event-ID, **for all clients on the system at once** (TSL1D is client-independent).
- **Residue.** Pre-fix: the SE92 deletion itself often emits no SAL event because the template for SAL-config-change (AUZ) writes through a separate event ID that the same operator can also pre-delete. Post-fix: blocked, but `S_DEVELOP DEBUG` debugger walk leaves a `DEBUG` audit trace if `auth/check_value_write_on/off` is active. DBTABLOG on TSL1D is **off** by default.
- **Detection.** Daily row-count snapshot of TSL1D and TSL1T; alert on any decrease. Forwarded SAL feed by **event ID** rather than rendered text — a missing template doesn't suppress the raw event in the file. Verify SAP Note 1926485 is applied (kernel ≥ 7.31 SP-level dependent; the note is ABAP transport, not kernel patch).
- **Applicability.** Pre-fix on all kernels back to 4.6C. Post-fix: blocked unless `S_DEVELOP DEBUG 02` is granted. Re-verify on kernel 793 — the SAP Note has been re-issued multiple times and customers on extended-maintenance NW 7.40 ABAP layers may still be vulnerable.

#### 4.A.18 Terminal-name spoofing in SAL source field (`rsau/ip_only=0`)

- **Mechanism.** The SAL record's "Terminal Name" / source field is populated from the **client-supplied** `terminal` parameter on logon (DIAG `LICEN_NAME`, RFC `RFC_PARAM_TID`, HTTP `User-Agent`-equivalent on some web entry points). When `rsau/ip_only=0` (the kernel default), the kernel writes whatever the client said and only falls back to the IP address when the field is empty. Per Perez-Etchegoyen & Vandevanter (Troopers14, *Attack #2 – Hide source of attack*, slides 16–18), the operator can therefore log a logon as terminal `"INTERNAL-PAYROLL-01"` or as an arbitrary IP, breaking source-IP correlation in SIEM rules that key off the SAL source field rather than the parsed network-layer 5-tuple.
- **Authority.** None — the spoofing happens at logon, no SAP credentials needed for failed-logon events; for successful logons it's whatever credentials the operator already has.
- **Reversibility.** N/a — the value is written per-event; no global state changes.
- **Bypasses.** Source-correlation rules across §1.1, §1.7, §1.18 that rely on the SAL terminal field. Does **not** bypass network-layer telemetry (firewall flow logs, dev_rd, dev_icm).
- **Residue.** Mismatch between SAL source field and the (still-correctly-logged) IP-address fields in other channels — but only if the SIEM cross-joins them.
- **Detection.** Force `rsau/ip_only=1` (note: kernel synonyms `rsau/ip_only` and `rsau/local/file/host_ip_only` exist depending on release; check `RSAU_CONFIG` UI labels). Cross-validate SAL terminal against ICM access-log source IP, dev_rd handshake IP, and message-server connection log; mismatch is the IoC.
- **Applicability.** All kernels; the `rsau/ip_only` flag has been available since NW 7.0 (SAP Note 1497445). On S/4 secure baseline 2023 the param is **on** by default — but verify against the customer's actual `RSPARAM` because legacy upgrade paths frequently carry the old default forward.

#### 4.A.19 SAL daily-size cap exhaustion (kernel default = stop-logging-on-full)

- **Mechanism.** SAL files default to **100 MB/day per instance** (`rsau/max_diskspace/local` = `100M`, `rsau/max_diskspace/per_day` historically). When the daily cap is reached, the kernel's **default behaviour is to silently stop writing** — not to rotate or wrap. Per Perez-Etchegoyen & Vandevanter (Troopers14, *Attack #3 – Reaching the limit*, slides 19–21), an attacker who can trigger high-volume audit-eligible events — failed logons (AU2 from network), unauthorised RFC enumerations (AUK), repeated RAL hits, large-volume report starts (AU5) — can **deliberately exhaust the daily cap early in the day** and then operate audit-blind for the remainder of the day. Critically, several of the cap-burning events are **unauthenticated** (network-only AU2 failed logons against a non-existent user, message-server probes, gateway RFC probes), making this a pre-credential evasion primitive.
- **Authority.** None for the unauth cap-burn path; arbitrary low-priv for the authenticated path.
- **Reversibility.** None — the consumed quota is consumed.
- **Bypasses.** §1.1 entirely **for the rest of the day** on the affected instance, once the cap is hit.
- **Residue.** The last `audit_<yyyymmdd>_<SID><n>` file shows a sharp cliff at exactly the cap; SIEM-side event volume drops to zero from the cap moment forward; on kernel ≥ 7.50 the kernel writes a single AUZ event "audit log size limit reached" — but anyone watching the **count** sees the missing tail of the day. The flooding events themselves are also residue and look like a brute-force.
- **Detection.** (a) Size the SAL cap to **at minimum 1 GB/day per instance** on high-throughput systems and 256 MB on small systems; (b) configure `rsau/wrap_around=1` (alternate kernel behaviour: overwrite oldest events instead of stop) — but understand wrap-around itself becomes an evasion primitive because oldest events are exactly what the operator wants gone; (c) alert on the "SAL size limit reached" AUZ event with priority; (d) alert on AU2 failed-logon burst rate; (e) forward SAL real-time so the historical record on the forwarder side survives even when the local file caps out.
- **Applicability.** All kernels — default is unchanged in S/4 2023 ("stop logging" remains the default behaviour). Wrap-around vs stop-on-full is configurable per-instance.

### 4.B Java-stack techniques

#### 4.B.1 NWA "Log Configurations" severity flip

- **Mechanism.** Via `/nwa/log-config` UI or REST API, set the `SAP_SECURITY_AUDIT` location severity to `FATAL` for the duration of the op; restore to `INFO` afterwards. Also: per-package overrides on `defaultTrace` to mute the operator's class.
- **Authority.** NWA Administrator role (`Administrator` group in UME).
- **Reversibility.** Snapshot severities first (NWA exposes a "Save Configuration" XML export). Restore via the same UI.
- **Bypasses.** §2.1, §2.3 selectively.
- **Residue.** NWA itself logs the config change as a `Configuration Manager` event in `audit.<n>.log` (§2.2). Hide that via §2.2 truncation.
- **Detection.** Watch §2.2 for `LogConfigurator` events; alert on any non-baseline severity change.
- **Applicability.** All NW 7.0+.

#### 4.B.2 SecurityAudit.\<n>.log direct truncation

- **Mechanism.** From CVE-2025-31324 webshell or SXPG-equivalent: `> /usr/sap/<SID>/J<NR>/j2ee/cluster/server*/log/system/SecurityAudit.*.log`. Critically — **do not delete** the file. The log4j FileAppender holds an open FD on it; deletion leaves the FD writing to a phantom inode. Truncation in place keeps the FD valid; future events continue to append.
- **Authority.** `<sid>adm` OS or equivalent on the host.
- **Reversibility.** None.
- **Bypasses.** §2.1.
- **Residue.** File mtime / size jump; on some kernels the JVM's BufferedWriter caches a few KB so the truncated state shows a small reappearing tail.
- **Detection.** auditd file-watch; on-host file-size delta monitor; Filebeat-style forwarder logs a "log rotated to size=0" event.
- **Applicability.** All NW Java.

#### 4.B.3 Telnet console `set_log_level`

- **Mechanism.** SSH/telnet to admin console (default port `5<NR>008`), authenticate as `Administrator`, run `set_log_level "com.sap.security.core" FATAL`, then `set_log_level "com.sap.security.core" INFO` after.
- **Authority.** UME Administrator with `J2EE_ADMIN` action.
- **Reversibility.** Yes — same command restores.
- **Bypasses.** §2.3 for the selected package.
- **Residue.** Telnet session itself is logged in §2.9 if console-session audit is on (off by default).
- **Detection.** Console session audit; periodic `get_log_level` capture from a side channel into SIEM for diffing.
- **Applicability.** All NW Java with telnet console enabled (`telnet.port` default open).

#### 4.B.4 log4j XML hot-edit

- **Mechanism.** Edit `log-configurations.xml` to remove or replace the appender on the SAP_SECURITY_AUDIT location, then trigger `reloadLogConfiguration` via JMX or telnet `config update`. Alternative: replace the appender's `file=` attribute to point to `/dev/null` and reload.
- **Authority.** OS write on the cluster's `log-configurations/` dir, **plus** ability to trigger reload (UME Administrator).
- **Reversibility.** Snapshot the XML.
- **Bypasses.** Everything routed through the modified appender.
- **Residue.** File mtime; Config Manager event.
- **Detection.** AIDE/Tripwire-style FIM on `log-configurations/`; periodic checksum into SIEM.
- **Applicability.** All NW Java.

#### 4.B.5 defaultTrace mute by package

- **Mechanism.** Set TraceLevel = `NONE` for `com.sap.engine.services.security` or whatever package the op runs in. Less obvious than muting the root logger.
- **Authority.** NWA Administrator.
- **Reversibility.** Restore severity.
- **Bypasses.** §2.3 surgically.
- **Residue.** Config Manager event.
- **Detection.** Same as 4.B.1.
- **Applicability.** All NW Java.

#### 4.B.6 HTTP access log racing the forwarder

- **Mechanism.** Force ICM log rotation via `icmon → log → rotate`, immediately truncate the just-rotated file. Time between rotation and forwarder pickup is the window — on tail-by-inode forwarders, rotation creates a new inode and the forwarder reads zero bytes from it before deletion.
- **Authority.** `<sid>adm` OS; ICM admin (`S_ADMI_FCD ICMA`).
- **Reversibility.** None.
- **Bypasses.** §1.12 / §2.5 for the rotated file.
- **Residue.** Rotation event itself; missing log file numbered between two existing files.
- **Detection.** SIEM monitors per-second event-rate; gap of >X seconds during normal-traffic hours is suspicious.
- **Applicability.** All ICM versions.

#### 4.B.7 Visual Composer audit suppression

- **Mechanism.** CVE-2025-31324 path leaves VC audit entries for "model deployed". Two ways to suppress: (a) write the JSP shell to a location outside the VC model upload handler so VC audit never fires; (b) delete the matching row in VC's `VC_AUDIT_TRAIL` table on the Java DB before VC audit is exported.
- **Authority.** OS for (a); DB user for (b).
- **Reversibility.** None for (b).
- **Bypasses.** §2.7.
- **Residue.** DB-side audit if customer enabled it.
- **Detection.** Forward VC audit independently of VC; daily row-count diff.
- **Applicability.** Customers with VC (Java AS).

#### 4.B.8 SAP BusinessObjects temporary-audit gap (pre-ADS staging)

- **Mechanism.** SAP BusinessObjects (BO / BI Platform) has a **distributed audit architecture**: each tier (CMS, Job Server, Web Intelligence Processing Server, etc.) writes events locally to **unsigned temporary audit files** on disk, which are then collected asynchronously by the Audit Data Store (ADS) collector. Per Perez-Etchegoyen & Vandevanter (Troopers14, *Attack #4 – SAP BO Temporary audit*, slides 22–24), there are two exploitable gaps:
  - **(a) Temporal gap.** Between the moment an event is written to the temp file and the moment ADS collects it (default polling interval — minutes to hours depending on `Auditor.SourcePath` / `auditing.batchSize` config), the file is fully attacker-mutable on disk with OS-level rights.
  - **(b) No integrity check.** The temp files are plain CSV / proprietary log format with **no HMAC, no signature, no chained hash**. An attacker with OS write on the BO tier's data directory can: delete the temp file outright; edit individual rows to rewrite the actor / target / outcome fields; truncate the file to drop the tail of an in-progress capture; or rewrite the timestamp to shift the event outside the analyst's review window.
- **Authority.** OS user running the BO service (`bobjadmin` / `sap<sid>` / on Windows a domain service account). Reachable from any OS-exec primitive: CVE-2025-31324 if the BO tier shares the AS Java host; GW SAPXPG on the same host; SSH-as-service-account.
- **Reversibility.** None — the event simply never reaches ADS.
- **Bypasses.** BO ADS / audit-universe entirely for the operator's session, **before the event is centralised**. The fully-aggregated ADS database (which is what SIEM typically pulls from) never sees the event.
- **Residue.** File mtime delta on the temp file; size delta vs expected per-event size; if the operator edits rather than deletes, structural CSV-parser errors when ADS tries to import (some collector versions then quarantine the file in `_failed/` rather than retry, which is itself an IoC).
- **Detection.** (a) Forward the temp-file directory to an external FIM with **per-line append-only assumption** — any non-append modification is an IoC; (b) shorten ADS collection interval to seconds (operational cost: ADS DB churn); (c) protect the temp directory at OS level (mode 700 + ACL deny-write to everyone but the BO process token); (d) deploy a side-channel "audit reflector" daemon that tails the same temp files and ships a copy out-of-band to immutable storage; (e) correlate BO operations against AS Java SecurityAudit / ICM access log entries — gap between layers is suspicious.
- **Applicability.** All BO / BI Platform versions where the distributed-collector model is used (BO XI R2 through BI 4.3 SP04 on the BI Platform side). Cloud BI / BTP-hosted BI moves the collector to a SAP-managed component but the local-tier temp file still exists in the customer's pod for a few seconds before being shipped.

### 4.C Shared / infrastructure techniques

#### 4.C.1 SAProuter trace silencing

- **Mechanism.** If SAProuter was started with `-G <log>`, no in-process way to disable the log mid-flight — operator must SIGHUP after editing the systemd unit, OR truncate the log file. saprouttab entry `P -P "*" "*" "*" 0` can be added in front of legitimate rules to switch logging off for matching connections (the trailing `0` is the silent flag in some saprouter releases).
- **Authority.** OS user running saprouter (typically `saprouter` or `<sid>adm`).
- **Reversibility.** Restore saprouttab + send SIGHUP.
- **Bypasses.** §3.1.
- **Residue.** Truncated `-G` file; saprouttab mtime.
- **Detection.** FIM on saprouttab; SIEM gap detector on saprouter log volume.
- **Applicability.** All saprouter releases; the `0` silent flag is documented for ≥ saprouter 40.

#### 4.C.2 Cloud Connector audit log truncation

- **Mechanism.** Shell on the SCC host: `> log/audit/<subaccount>/audit-log_<ts>.csv`. SCC rotates on day boundary so truncation leaves the file format valid (header row + 0 data rows).
- **Authority.** OS user running SCC (`sccadmin` by default).
- **Reversibility.** None.
- **Bypasses.** §3.2.
- **Residue.** File size = header-only; SCC's own UI displays "0 entries today".
- **Detection.** Forward audit-log CSV to external SIEM continuously (SAP best practice but rarely implemented); UI-side row-count snapshot.
- **Applicability.** All SCC versions.

#### 4.C.3 ICM trace level flip

- **Mechanism.** `RZ11 → icm/trace_secured_data = 0` plus `rdisp/TRACE → 0` silences ICM trace.
- **Authority.** `S_RZL_ADM`.
- **Reversibility.** Restore.
- **Bypasses.** §1.12 / §2.5 / §2.10 selectively.
- **Residue.** TPFYPROPTY change-doc.
- **Detection.** Parameter-change watcher; baseline value snapshot.
- **Applicability.** Universal.

#### 4.C.4 Kernel-parameter dynamic-set via RZ11

- **Mechanism.** Generic primitive — any of the gw/log_level, rdisp/TRACE, stat/level, rsau/* parameters can be flipped at runtime for "evasion window" with restore.
- **Authority.** `S_RZL_ADM`.
- **Reversibility.** Snapshot-restore.
- **Bypasses.** Whichever channel the parameter governs.
- **Residue.** TPFYPROPTY change-doc — and that's the universal canary.
- **Detection.** Watch TPFYPROPTY; daily RSPARAM diff.
- **Applicability.** Universal.

#### 4.C.5 Time-window scheduling

- **Mechanism.** Run during the overnight backup window when SIEM forwarder is intentionally paused (some forwarders pause during HANA backup to avoid IO contention), or during the daily SAL log-rotation gap (a ~3 second window when the new file is being created).
- **Authority.** None — pure scheduling.
- **Reversibility.** N/a.
- **Bypasses.** Forwarder pickup, briefly.
- **Residue.** Same residue as if run during business hours, just unseen for longer.
- **Detection.** "Forwarder pause window" is itself a known operational gap that good SOCs tighten. Detect by correlating SAP-side event mtime vs forwarder-side arrival time.
- **Applicability.** Highly customer-specific; reconnaissance required.

#### 4.C.6 Quiet-channel selection

- **Mechanism.** Where multiple primitives accomplish the same goal, pick the one with the lower-volume audit class. Examples:
  - dpmon SAP\* (EUP-2, 1 event) vs `BAPI_USER_CREATE1` (AUB + AUC + CDHDR, 3+ rows)
  - MYSAPSSO2 forged ticket (AU3, 1 event, indistinguishable from real SSO) vs cold logon (AU1 + AUE password-mismatch on first attempt, 2+ events)
  - SXPG_STEP_XPG_START (single AU5) vs GW SAPXPG chunked (one AUK per RFC chunk = 40+ events for the SQL writer payload)
- **Authority.** Method-specific.
- **Reversibility.** N/a.
- **Bypasses.** Volume; not channel.
- **Residue.** Method-specific.
- **Detection.** Per-event-type baselining.
- **Applicability.** Method-specific.

#### 4.C.7 Decoy noise generation (cross-stack)

- **Mechanism.** Companion to 4.A.6: parallel RFC_PING storms from many service users + dummy HTTP probes against `/sap/public/ping` + dummy Java logon failures. Fill ring buffers across stacks simultaneously.
- **Authority.** None.
- **Reversibility.** N/a.
- **Bypasses.** Practical SOC review.
- **Residue.** Statistical anomaly.
- **Detection.** Event-rate anomaly detection.
- **Applicability.** Universal but loud.

---

## 5. Detection counter-measures (defender side)

This is the dual-use payoff: every technique catalogued in §4 has a row here.
Pseudocode is Splunk-flavoured SPL but trivially portable to Sentinel KQL or QRadar AQL.

### 5.1 Highest-leverage SIEM rules

| Technique | SIEM rule (pseudocode) | False-positive shape |
|---|---|---|
| 4.A.1 SAL filter narrowing | `index=sap_sal event=AUZ NOT user IN ($SAL_ADMIN_ALLOWLIST$)` | New SAL admin onboarded |
| 4.A.2 SAL kernel-param disable | `index=sap_sal source=TPFYPROPTY param=rsau/*` AND `param_value=0` | Documented maintenance |
| 4.A.3 STAD silencing | `count_per_hour(sap_stad) < 0.1 * baseline_avg` | Genuine quiet hour, weekend |
| 4.A.4 DBTABLOG suppression | `index=sap_param param=rec/client AND value!="ALL"` ALSO daily diff DD09L | Project cutover |
| 4.A.5 CDHDR object suppression | `monitor table=TCDOB for INSERT/DELETE/UPDATE` | SCDO maintenance |
| 4.A.6 / 4.C.7 Decoy noise | `event_rate(AU2) > 5σ over 14d baseline` | Brute-force from external |
| 4.A.7 Low-volume primitive | `BAPI_USER_PROFILES_ASSIGN` use outside IGA tooling list | New admin tooling rollout |
| 4.A.8 Ticket impersonation | `AU3 method=SSO AND user IN ($SERVICE_USER_LIST$) AND src_ip NOT IN (their baseline IPs)` | Service user moved hosts |
| 4.A.9 dpmon SAP\* | `EUP event purpose=2` — single filter | None really — EUP-2 is intentional |
| 4.A.10 Targeted SAL deletion | `RSAU_FILE_ADMIN integrity_check_failed` + side-channel SAL row-count export comparison | HMAC key rotation |
| 4.A.11 SM18/RSAUPURG | `AUZ event = "audit log files deleted" AND time NOT IN (maintenance_window)` AND `S_DEVELOP DEBUG 02 usage on function group RSAU` | Quarter-end cleanup |
| 4.A.12 USR* scrub | `daily row_count(USH02) decreased OR LASTLOGON missing for active users` | None — should be append-only |
| 4.A.13 CDHDR scrub | `CDHDR.CHANGENR sequence gaps` | Archival job (filtered) |
| 4.A.14 dev_* truncation | `auditd watch on /usr/sap/<SID>/<INST>/work/ for path=dev_*` + `inode_change OR size_drop` | Manual debugging |
| 4.A.15 Transport log scrub | `E070.TRKORR sequence gap` + `/usr/sap/trans/log/ FIM` | Old archived TRs |
| 4.A.16 SolMan pull hijack | Central-side: `monitored_system_unreachable AND not_in_planned_downtime` | Network outage |
| 4.A.17 SE92 / TSL1D template delete | `daily diff row_count(TSL1D)`; SAP Note 1926485 applied check; `S_DEVELOP DEBUG 02` usage on RSLG / RSAU function groups | Localisation rollout adding new languages |
| 4.A.18 Terminal-name spoofing | `rsau/ip_only=0` parameter check + cross-validate SAL terminal field against ICM access-log IP and dev_rd handshake IP | Genuine terminal-server hostname |
| 4.A.19 SAL daily-cap exhaustion | Real-time SAL forwarding (so cap on local file doesn't lose events) + alert on "SAL size limit reached" AUZ event + AU2 failed-logon burst rate detector | Massive legitimate brute-force from external |
| 4.B.1 / 4.B.5 NWA severity flip | `index=nwa source=audit.log type=LogConfigurator AND severity=FATAL` | Troubleshooting session |
| 4.B.2 SecurityAudit truncation | File-size-delta monitor + Filebeat "log truncated" event | Log4j rotation race |
| 4.B.3 Telnet `set_log_level` | Session audit + periodic `get_log_level` capture into SIEM | Active troubleshooting |
| 4.B.4 log4j hot-edit | FIM checksum on `log-configurations/` | Patch / SP update |
| 4.B.6 ICM log race | Per-second event-rate gap > 5σ + rotation-event timing analysis | Genuine traffic dip |
| 4.B.7 VC audit suppression | DB-side replication of `VC_AUDIT_TRAIL` | None |
| 4.B.8 BO temp audit gap | FIM with per-line append-only assumption on BO Auditor.SourcePath; shorten ADS collection interval; correlate BO ops vs AS Java SecurityAudit | Genuine ADS collector backlog |
| 4.C.1 SAProuter silencing | FIM on saprouttab + saprouter log-volume gap detector | Topology change |
| 4.C.2 SCC audit truncation | External CSV replication + SCC UI row-count snapshot | None |
| 4.C.3 / 4.C.4 RZ11 param flip | Real-time TPFYPROPTY change-doc forwarder + RSPARAM daily diff | Tuning |
| 4.C.5 Time-window | Correlate SAP-side mtime vs forwarder arrival; alert on lag > N min | Forwarder lag |
| 4.C.6 Quiet-channel | Per-channel baseline | New tooling |

### 5.2 Compensating controls

- **Immutable audit forwarders.** Push SAL/SecurityAudit/ICM events to a write-once syslog target (e.g. cryptographic chained logging, AWS CloudWatch with retention policy, GCP Cloud Logging with IAM-locked sink). The local SAP file is truncatable but the SIEM-side copy is not.
- **Append-only DB replication.** Stream CDHDR/CDPOS/USR*/E070 changes to an external append-only store (Debezium → Kafka → S3 with object-lock). Deletion on the SAP side is then a positive IoC — the row exists upstream but not on the system.
- **rsau/integrity=1 + offline HMAC key.** Generate HMAC key, store fingerprint in offline key vault, rotate only via documented MAC. Run `RSAU_FILE_ADMIN` integrity check daily from a separate system via RFC. Tampered files surface immediately.
- **TPFYPROPTY change forwarding.** Every kernel-parameter change is a CDHDR row in `TPFYPROPTY`. Forward this table's deltas as a high-priority feed.
- **RSPARAM daily diff watcher.** Cron job from an out-of-band system runs `RSPARAM` over RFC and diffs against the previous day. Drift of rsau/*, rec/client, stat/level, gw/log_level, rdisp/TRACE is alertable.
- **Service-user behaviour baseline.** For `SAPSUPPORT`, `SOLMAN_BTC`, `DDIC`, `SAP*`, `RFCUSER` etc., maintain per-user IP, tcode, and time-of-day baselines and alert on deviation. This is what defeats the MYSAPSSO2 evasion in 4.A.8.
- **SAL row-count exfil + integrity comparison.** Periodically `SELECT COUNT(*) FROM RSAU_PERS` via RFC; SIEM compares against own ingest count.
- **NWA configuration baseline.** Daily export of `/nwa/log-config` XML; diff against approved baseline; any drift alerts.
- **Filesystem auditing on `work/` and `log/`.** auditd `-w /usr/sap/<SID>/<INST>/work -p wa` on Linux; Sysmon EID 11 (FileCreate) + EID 23 (FileDelete) on Windows. Truncation of any `dev_*`, `SecurityAudit.*.log`, `defaultTrace.*.log` produces a high-signal event.
- **Out-of-band audit pull.** Have a system **outside** the SAP landscape (e.g. SolMan in a separate trust zone) periodically pull SAL via RFC. The pulled copy is immutable on the puller's side; deletion on the source is then detectable.

### 5.3 Configuration-drift hardening

- **Lock rsau/* and rec/client behind dual-control.** `S_RZL_ADM` segregated from `S_ADMI_FCD AUDA`; parameter changes require change-management ticket reference written into the comment.
- **`RSAU_CONFIG_LOG_RES`.** Kernel ≥ 7.55: enable resilience logging so SAL config changes survive filter-history clearing.
- **Disable SU01 emergency unlock paths.** `S_USER_GRP` for group `SUPER` revoked from all non-break-glass accounts; break-glass accounts have separate audit.
- **dpmon access control.** SAP Note 3303172 documents that any `<sid>adm` can activate SAP\*. Compensating control is per-host `<sid>adm` shell restriction (sudoers / restricted login shell) — exotic but valid for high-assurance shops.

### 5.4 How a mature SOC defeats these techniques anyway

- **Real-time SAL streaming to immutable sink.** Removes 4.A.10/4.A.11/4.A.14/4.B.2.
- **Append-only CDHDR/USR* replication.** Removes 4.A.12/4.A.13.
- **Out-of-band TPFYPROPTY + DD09L watcher.** Removes 4.A.1/4.A.2/4.A.3/4.A.4/4.C.3/4.C.4.
- **NWA config snapshot diff.** Removes 4.B.1/4.B.4/4.B.5.
- **FIM on saprouttab, log-configurations.xml, audit roots.** Removes 4.B.4/4.C.1.
- **Service-user behaviour analytics.** Removes 4.A.8.
- **EUP-2 single-filter alert.** Removes 4.A.9 by design — that one is loud-by-design from SAP itself.
- **CSV-replication of SCC audit.** Removes 4.C.2.

Techniques with **no realistic detection in standard SOC setups** — be explicit:

- **4.A.6 / 4.C.7 decoy noise.** A SOC drowning in 100k AU2 events per minute cannot meaningfully review them. Defenders need ML-based anomaly detection rather than rule-based alerting, which is rare. Honest answer: this works against most real SOCs today.
- **4.A.18 Terminal-name spoofing.** Without `rsau/ip_only=1`, the SAL source field is attacker-controlled and most SIEM correlation rules trust it without cross-validating against ICM access-log IP. Per Perez-Etchegoyen & Vandevanter (Troopers14, slide 16) this is "complete anonymity on the source of the attack" until the parameter is enabled by the customer. SAP Note 1497445 has been available since 2010 and is still not universally applied.
- **4.A.19 SAL daily-cap exhaustion** when the SOC pulls SAL via daily file collection rather than real-time. The cap event itself surfaces, but the **after-cap events the operator actually cares about never get written to file** — there is nothing for the SIEM to ingest later. Real-time forwarding fully defeats this; file-pull does not.
- **4.B.8 BO temporary-audit gap** in customers whose SIEM pulls only from ADS rather than tailing the per-tier temp files. The event never enters ADS, so it is invisible.
- **4.C.5 time-window scheduling.** If the forwarder is genuinely paused, the only mitigation is to fix the forwarder. Many enterprises won't.
- **4.A.7 / 4.C.6 quiet-channel selection.** No detection — operator just chooses a lower-volume primitive. Defenders mitigate by per-method baselining, which is operationally expensive.

---

## 6. SAPMAP integration plan

### 6.0 Pre-flight safety — baseline capture (mandatory for any tier ≥ 2)

Before any evasion action runs, SAPMAP **must** capture a baseline so the original config can be restored bit-for-bit:

- `loot/baseline/<sid>/sal_config.json` — full `RSAU_CONFIG` dump (parameters + filter slots + recording target).
- `loot/baseline/<sid>/tpfyproperty.csv` — RSPARAM snapshot of the parameters the evasion may touch (rsau/*, rec/client, stat/level, gw/log_level, rdisp/TRACE).
- `loot/baseline/<sid>/dd09l_log_flags.csv` — DD09L row for any table the op may touch.
- `loot/baseline/<sid>/nwa_log_config.xml` — NWA Log Configurations export.
- `loot/baseline/<sid>/file_inventory.csv` — sizes + mtimes + sha256 of `audit_*`, `dev_*`, `SecurityAudit.*.log`, `defaultTrace.*.log`, ICM access logs, SCC `audit-log_*.csv`, saprouttab.

If baseline capture fails, no tier-3/4 evasion may run. This is the principle of "don't tamper with what you can't put back".

### 6.1 Phased build plan

#### Tier 1 — read-only OPSEC enrichment

**Goal:** SAPMAP knows what telemetry exists, who reads it, and surfaces this in findings so the operator can decide whether to evade. No tampering.

| Technique | SAPMAP module(s) | LOC est | New deps | Reuses |
|---|---|---|---|---|
| Detect SAL on/off, filter slots, integrity flag | `modules/discovery/sapmap_telemetry.py` (new) | ~200 | none | `sapmap_rfc.read_table` (RSAUPROF), `RFC_READ_TABLE` |
| Detect rec/client / stat/level / gw/log_level / rdisp/TRACE values | same | ~80 | none | RSPARAM via `RFC_READ_TABLE`, existing `_call_pfl_get` |
| Detect `rsau/ip_only` value (4.A.18) | same | ~20 | none | RSPARAM read |
| Detect `rsau/max_diskspace/*` cap value + daily SAL file-size trend (4.A.19) | same | ~60 | none | RSPARAM + `RSAU_FILE_ADMIN` Display Files RFC |
| Detect SAP Note 1926485 application status (4.A.17) | same — check `TSL1D` row-count baseline + version of `RSLG_DELETE_MESSAGE` function module via `RFC_READ_TABLE` on `TFDIR` | ~40 | none | RFC_READ_TABLE |
| Detect Java-side severity matrix (NWA REST API) | `modules/discovery/sapmap_telemetry.py` | ~150 | `requests` (already used) | `sap_java_telnet` for the auth path |
| Detect BO Auditor.SourcePath + ADS collection interval (4.B.8) | `modules/discovery/sapmap_bo_audit.py` (new) | ~120 | none | BO CMS REST client (partial in existing modules) |
| Detect SCC audit retention | `modules/data_extraction/sapmap_scc_admin.py` extension | ~80 | none | existing SCC admin API client |
| Detect SAProuter `-G` flag presence | `modules/protocols/sap_router_info.py` extension | ~50 | none | n/a |
| Surface as `OPSEC_TELEMETRY` finding per node | `modules/core/sapmap_models.py`, `sapmap_html.py` | ~80 | none | finding system |

Total Tier 1: **~880 LOC** (was 640 pre-Troopers14), zero new deps, zero tampering. Pure read-only enrichment. Ship under default — no `--allow-evasion` needed because it doesn't change anything. **Two new high-value findings:**
- *"SAL terminal-name spoofing possible — `rsau/ip_only=0`"* (4.A.18 detection) — flags every customer who still trusts SAL source IPs.
- *"SAL cap reachable — daily limit X MB, peak observed Y MB"* (4.A.19 detection) — proactively warns of the file-cap evasion surface.

#### Tier 2 — passive minimisation (low-volume primitive selection)

**Goal:** Where SAPMAP today uses a noisy primitive, switch to the quieter one **automatically** when the operator hasn't said otherwise.

| Technique | SAPMAP module(s) | LOC est | Behaviour change |
|---|---|---|---|
| 4.A.7 prefer `BAPI_USER_PROFILES_ASSIGN` over `BAPI_USER_CREATE1`+assign | `modules/exploitation/sapmap_exploit.py` | ~120 | When operator already has a user, assign profile instead of new create |
| 4.A.7 prefer SXPG_STEP_XPG_START over chunked GW SAPXPG when authenticated path exists | `modules/exploitation/sapmap_autopwn.py` | ~80 | Re-rank Phase-2 priorities |
| 4.A.8 MYSAPSSO2 default to service-user impersonation, not SAP\* | `modules/exploitation/sap_mysapsso2.py` | ~50 | New default identity list |
| 4.A.18 Supply spoofed terminal name on every logon when `rsau/ip_only=0` detected | `modules/discovery/sapmap_rfc.py` + DIAG / RFC logon path | ~60 | Use a baseline-blending terminal name from a configurable list (default: `SAPGUI-CLIENT-01`); only active when Tier 1 detected `rsau/ip_only=0` |
| Decoy noise *disabled* by default | n/a | 0 | Active opt-in only |

Total Tier 2: **~310 LOC** (was 250 pre-Troopers14), no new deps. Behavioural change only; surfaces in finding text ("Quieter primitive selected — `BAPI_USER_PROFILES_ASSIGN`, 1 audit event, vs default `BAPI_USER_CREATE1` which writes 3"). Ship under default; document the change in CHANGELOG so reviewers understand the new audit footprint.

Note on 4.A.18: this primitive only works **if the customer hasn't fixed SAP Note 1497445** (default param off). The finding text must distinguish "terminal-name spoofing applied — customer is vulnerable to source-attribution evasion" from "terminal-name spoofing not possible — `rsau/ip_only=1` correctly set". Even if SAPMAP doesn't spoof, the customer should know which group they're in.

#### Tier 3 — active manipulation (gated)

**Goal:** Operator with `--allow-evasion` flag can request evasion before / during the op. All actions snapshot + restore. Banner mandatory.

| Technique | SAPMAP module | LOC est | New primitive needed |
|---|---|---|---|
| 4.A.1 SM19 filter narrowing | `modules/postex/sapmap_evade_sal.py` (new) | ~200 | RSAUPROF row CRUD |
| 4.A.2 SAL kernel-param disable (runtime) | `modules/postex/sapmap_evade_sal.py` | ~80 | RFC `RZL_PUT_VALUE` |
| 4.A.3 STAD silencing | `modules/postex/sapmap_evade_stat.py` (new) | ~80 | reuse RZL_PUT_VALUE |
| 4.A.4 DBTABLOG rec/client flip | `modules/postex/sapmap_evade_dbtablog.py` (new) | ~100 | reuse RZL_PUT_VALUE |
| 4.B.1 NWA severity flip | `modules/postex/sapmap_evade_java_nwa.py` (new) | ~200 | NWA REST client (partly exists) |
| 4.B.5 defaultTrace mute by package | same | ~80 | same |
| 4.C.3 ICM trace level flip | `modules/postex/sapmap_evade_sal.py` | ~50 | RZL_PUT_VALUE |
| 4.C.4 generic RZ11 dynamic-set | exposed as a reusable `evasion_window` context manager | ~150 | n/a |
| 4.A.17 TSL1D template delete (legacy CVE 1926485 bypass) | `modules/postex/sapmap_evade_sal.py` | ~80 | `RFC_READ_TABLE` snapshot + `RFC_ABAP_INSTALL_AND_RUN` insert-back; only enabled when Tier 1 detected SAP Note 1926485 NOT applied AND `S_DEVELOP DEBUG 02` is granted to the operator user, else module refuses to run |
| 4.A.19 SAL daily-cap exhaustion (auth or unauth flood path) | `modules/postex/sapmap_evade_sal_cap.py` (new) | ~120 | AU2 burst generator using existing logon-prober primitive in `sap_default_creds.py`; bounded by an explicit `--cap-burn-mb` operator flag (default OFF), with a banner that warns customer SOC will see a brute-force-shaped event |

Total Tier 3: **~1140 LOC** (was 940 pre-Troopers14), zero new deps. All actions must snapshot baseline (§6.0), run the op, then restore. Restore is a `try…finally` around every operator action.

**Ordering update.** Build sequence inside Tier 3 should now be: 4.A.1 (filter narrow) → 4.A.2 (kernel param) → 4.A.3 (STAD) → 4.A.4 (DBTABLOG) → **4.A.17 (TSL1D, only if customer is unpatched)** → 4.B.1/4.B.5 (NWA) → 4.C.3 (ICM trace) → 4.C.4 (generic RZ11) → **4.A.19 (cap exhaustion, highest blast radius, ship last)**. 4.A.19 is intentionally last because it's the loudest residue (looks like brute-force) and most likely to trigger an alert that interrupts the rest of the op.

#### Tier 4 — full evidence cleanup (gated, highest risk)

**Goal:** After-op residue scrub. Massively elevated risk of bricking — particularly truncating SecurityAudit.\<n>.log while the JVM holds the FD.

| Technique | SAPMAP module | LOC est | Risk |
|---|---|---|---|
| 4.A.10 SAL row deletion + HMAC re-sign | `modules/postex/sapmap_evade_cleanup.py` (new) | ~300 | High — corrupted file = SAP refuses to write more |
| 4.A.11 SM18 / RSAUPURG accelerated rotation (3-day debugger bypass) | same | ~150 | Medium — debugger usage IoC |
| 4.A.12 USR* scrub | same | ~120 | Medium — append-only replication catches it |
| 4.A.13 CDHDR/CDPOS scrub | same | ~120 | Medium |
| 4.A.14 dev_* truncation | reuse SXPG OS-exec | ~50 | Low — files are designed to rotate |
| 4.A.15 Transport log scrub | same | ~100 | High — TR sequence gap is obvious |
| 4.A.16 SolMan/FRUN pull-hijack | new module — out of scope for v1 | n/a | Out of scope |
| 4.B.2 SecurityAudit truncation | `modules/postex/sapmap_evade_cleanup.py` | ~80 | **Highest** — JVM crash risk |
| 4.B.4 log4j hot-edit | same | ~150 | High |
| 4.B.6 HTTP access log race | same | ~80 | Medium |
| 4.C.1 SAProuter trace silencing | same | ~80 | Medium |
| 4.C.2 SCC audit truncation | `modules/data_extraction/sapmap_scc_admin.py` extension | ~80 | Low |
| 4.B.8 BO temp-audit gap exploitation | `modules/postex/sapmap_evade_bo.py` (new) | ~150 | Medium — requires OS exec on the BO tier; depends on whether SAPMAP touched anything BO actually audits |

Total Tier 4: **~1460 LOC** (was 1310 pre-Troopers14). Gated behind `--allow-evasion --allow-destructive` (both flags) plus banner. Must be opt-in per technique; no "scrub everything" sweep.

### 6.2 Primitives SAPMAP already has (reuse)

- **GW SAPXPG OS exec** (`modules/exploitation/sap_gw_xpg_standalone.py` → `execute_gw_command`) — unauthenticated OS exec as `<sid>adm`. Drives 4.A.14, 4.B.2, 4.C.2.
- **CVE-2025-31324 JSP shell** (`modules/exploitation/sap_cve_2025_31324.py`) — unauthenticated OS exec on Java host. Drives 4.B.2, 4.B.4, 4.B.6 against Java-stack targets.
- **SXPG_STEP_XPG_START** (authenticated, via `lpe_webgui_sm49` etc.) — authenticated OS exec.
- **`RFC_READ_TABLE` / `read_table`** (`modules/discovery/sapmap_rfc.py`) — for RSAUPROF / TPFYPROPTY / DD09L / CDHDR reads.
- **MYSAPSSO2 ticket forgery** (`modules/exploitation/sap_mysapsso2.py`) — drives 4.A.8 identity-impersonation evasion.
- **dpmon SAP\* primitive** (`modules/exploitation/sap_dpmon_sapstar.py`) — already shipping; document its EUP-2 footprint in finding text.
- **NWA REST helpers** (partial in `sap_java_telnet.py`) — drives 4.B.1/4.B.5.
- **SCC admin client** (`modules/data_extraction/sapmap_scc_admin.py`) — drives 4.C.2.
- **`BAPI_USER_DELETE`** (already used for cleanup of created SAPMAP00 users) — pattern reusable for USR\* row removal.

### 6.3 Primitives we'd need to build new

- **`RZL_PUT_VALUE` RFC wrapper** for runtime parameter set (RZ11 over RFC). Needs error handling for non-runtime parameters (the kernel rejects sets on profile-only params).
- **`RSAU_FILE_ADMIN` RFC counterpart** for file deletion / HMAC manipulation. SAP doesn't expose this as a standard BAPI; we'd call `CL_RSAU_FILE_ADMIN`'s methods via `RFC_ABAP_INSTALL_AND_RUN` from a generated ABAP report.
- **HMAC key rotation primitive** for `rsau/integrity` bypass. ABAP report via `CL_RSAU_KEYS`.
- **NWA REST client** — partly exists; needs `/nwa/log-config` endpoints, severity setter, snapshot/restore.
- **Log4j XML editor** — XML parser to find/replace `<root>`/`<location>` severity nodes in `log-configurations.xml`, plus a reloader trigger via JMX or telnet `config update`.
- **Telnet `set_log_level` driver** — wrapping the existing `sap_java_telnet` session.
- **SAProuter saprouttab in-place edit + SIGHUP** — SIGHUP via `kill -HUP $(pidof saprouter)` over SSH/SXPG/CVE-31324 path.
- **`<sid>adm`-context inode-preserving truncate helper** — `> $file` is preferred over `rm`. Needs to detect SE-Linux confinement (some hardened envs deny `<sid>adm` write to its own log directory under confinement).

### 6.4 Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| SecurityAudit.\<n>.log truncation crashes JVM | Medium on certain log4j configs | JVM down → engine restart needed | Pre-flight check: inspect `fileappender` flags; if `bufferedIO=false` and `append=true`, truncation is safe; if `immediateFlush=false`, defer to log4j hot-edit instead |
| RSAU file truncation leaves integrity check failing forever | High if `rsau/integrity=1` | Daily integrity scan alerts SOC | Rotate the HMAC key during the same window (snapshot, generate new, re-sign affected files, restore key on next maintenance) — risky, surface to operator |
| RZ11 parameter restore fails | Low | Customer sees drifted parameter | Implement as `try…finally` context manager; on uncaught restore failure, emit a glaring red banner; also write the desired-restore-value into `loot/baseline/` so a human can fix |
| DD09L SQL edit invalidates nametab buffer | Medium | Tables behave oddly until next nametab generation | Avoid SE13 SQL direct edit; prefer rec/client toggle instead |
| Transport log scrub creates E070 sequence gap | High | Trivially detected | Don't ship 4.A.15 in v1; document only |
| dpmon EUP-2 event surfaces immediately | Certain | Documented and operator-knows | Surface in finding text + UI tooltip |
| Decoy noise saturates SIEM and causes operational pain | High if abused | Customer SOC angry | Gate behind `--allow-evasion --allow-disruptive` (new flag) |
| NWA log-config flip breaks NWA itself | Low if reversible | NWA UI hangs | Test on lab first; restore via filesystem if UI fails |
| SAProuter SIGHUP kills active connections | Medium | Operator loses tunnel | Schedule after SAPMAP completes own connections |

### 6.5 Testing strategy

1. **Lab S/4 2023 (192.168.2.209, kernel 793).** Per the user's notes, this is the canonical kernel. Test all Tier 1 detection logic.
2. **Tier 2 selection — A/B test.** Run AutoPwn twice on the same node, once with current primitive set, once with Tier 2 selection. Diff SAL output. Capture as fixture.
3. **Tier 3 snapshot/restore round-trip.** For each parameter SAPMAP would touch, write a property test: snapshot → flip → restore → snapshot, compare hashes. Must be byte-identical.
4. **Tier 4 destructive on disposable VM.** Spin up a throwaway S/4 sandbox, run each Tier 4 primitive, verify (a) the evidence is gone, (b) the system is still functioning, (c) the integrity-check residue is detectable from a side channel. Anything that bricks the sandbox stays at "planned but not implemented" in the SAPMAP commit log.
5. **Defender-side validation.** Set up the SIEM rules from §5.1 in the lab Splunk; run each Tier 3/4 technique; verify the defender rule fires. This is the dual-use proof point.
6. **Burn-down test.** Run a full SAPMAP AutoPwn with all Tier 3 enabled, then have the lab SOC analyst review SAL/SecurityAudit for residue. The fewer findings they report, the better the implementation. Repeat with all baselines forwarded to immutable sink — the analyst should see everything.

### 6.6 Documentation deliverables

- README section "Evasion mode" with explicit warnings.
- `docs/operator/evasion.md` — per-Tier operator guide.
- `docs/blue/detection_rules.md` — SIEM rule export of §5.1 in Sigma format for the customer to import.
- Finding text additions: each existing exploit-class finding gains an "audit footprint" sentence (e.g. "Creates AUB + AUC + CDHDR.USR02 row; will surface in SAL if AU class on; consider Tier 2 alternative `BAPI_USER_PROFILES_ASSIGN` if user exists.").

---

## 7. Open research questions

These need verification on the lab S4H or a real ≥ 793 system before building. Each is a known-unknown that could invalidate a design choice in §6.

1. **Kernel 793 SAL behaviour when `rsau/enable=0`.** SAP Note 3380209 says some kernels still emit AU3 events with the flag off. Reproduce on 793. If true, 4.A.2 needs to be replaced with `rsau/local/file=/dev/null` redirection or filter-emptying instead.
2. **Exact RSAU_CONFIG_LOG_RES table format.** ≥ 7.55 logs config-change resilience records to a separate table. Need the table name (suspected `RSAU_PERS_CONFIG`) and whether the operator can suppress writes to it from the same `S_ADMI_FCD AUDA` authority that controls SAL.
3. **HMAC key location and rotation primitive.** `RSAU_KEYS` table holds the key; the rotation BAPI / function module name (suspected `RSAU_KEY_CREATE` / `CL_RSAU_KEYS`) needs verification against an S/4 2023 system before 4.A.10 is feasible.
4. **`rsau/integrity` interaction with multiple AS instances.** When SAL is `rsau/local/file=` per-instance and one instance's file is tampered, does the integrity check on a centralised SAL aggregation see the drift? Need to test multi-instance setup.
5. **SCC backup ZIP encryption status of `audit/`.** The backlog item `project_scc_backup_cipher` is unresolved — if audit logs are encrypted in the backup with the unknown cipher, a backup-side restore is not a viable forensic path. Defenders need to know.
6. **NWA `/nwa/log-config` REST shape.** Public docs cover the UI; the underlying REST endpoints (suspected `/ctc/CTCWebService` plus `/nwa/logaccess/v2`) need to be enumerated against a live AS Java to know if PUT-severity is even possible via REST (vs requiring UI session).
7. **VC audit trail table name on AS Java.** Suspected `VC_AUDIT_TRAIL`; verify against an AS Java with Visual Composer installed.
8. **SAProuter saprouttab `0` silent-flag version availability.** Was documented for saprouter 40-era — verify against the user's lab saprouter version.
9. **Cloud ALM / Focused Run telemetry differences.** Cloud ALM (the new replacement for SolMan) pulls different feeds. Need to know whether 4.A.16 (SolMan pull hijack) translates 1:1 to Cloud ALM. Could invalidate the technique entirely if Cloud ALM uses cert-pinned mTLS that prevents impersonation.
10. **ETD anomaly-detection coverage.** SAP Enterprise Threat Detection ships with predefined patterns. Do any of those patterns specifically detect the techniques in §4.A.1-4.A.5? If yes, document which ETD patterns are tripped — that's a free defender win.
11. **`stat/level=0` runtime vs profile.** Some kernels treat `stat/level` as profile-only (restart required); others accept RZ11 runtime. Verify on 793.
12. **`auditd` coverage of SAP work directories at enterprise customers.** Anecdotal — most customers don't have auditd watches on `/usr/sap/<SID>/<INST>/work/`. Need to survey before assuming 4.A.14 is risky.
13. **`<sid>adm` shell restrictions.** Some high-assurance shops run `<sid>adm` under restricted bash with no `>` redirect privilege. Need to fingerprint this at scan time so the operator knows 4.A.14 isn't available.
14. **dpmon authority check on 793+.** Plan 11 §13.3 notes this as open. If SAP adds `auth/dpmon_sapstar_admin_required` in a future kernel, the EUP-2 evasion identity calculus changes.
15. **Forwarder pause-window discovery.** No way to programmatically detect this from inside SAP; needs out-of-band knowledge from the customer. Could be inferred from STAD gap analysis (large idle windows in the early morning) but that's circumstantial.

### 7.1 Open questions raised by the Troopers14 paper

The Perez-Etchegoyen & Vandevanter 2014 talk demonstrated four attacks against kernels in the NW 7.0x / 7.31 era. Each needs re-verification against the modern kernel SAPMAP targets (793 / S/4 2023). The paper itself does not cover kernels later than ~7.40, so every entry below is a known-unknown that the catalogue inherits.

16. **SE92 / TSL1D unauthorised delete on kernel 793.** SAP Note 1926485 was released December 2013 and is functionally complete on stock S/4 2023 ABAP transport bundles — but the `S_DEVELOP DEBUG ACTVT=02` bypass is presumably still live (the note added authority check on the delete path, not on the debugger). Need to: (a) confirm TSL1D row-delete is blocked from SE92 on a current S/4 system; (b) confirm a `/h` debugger walk past the auth check on `RSLG_DELETE_MESSAGE` still removes the row; (c) check whether `RSAU_*` event templates moved to a separate table on ≥ 7.50 (suspected: SAL kernel uses kernel-internal templates, not TSL1D, on ≥ 7.50 — if true, 4.A.17 is moot on modern systems but still alive on older 7.31 / NW 7.40 stragglers).

17. **`rsau/ip_only` synonyms and default.** The paper says "default disabled"; modern docs suggest the default flipped to `1` somewhere between NW 7.40 and S/4 1909. Need to: (a) confirm the exact kernel SP at which the default flipped; (b) enumerate all kernel param synonyms (`rsau/ip_only`, `rsau/local/file/host_ip_only`, possibly `rsau/audit/terminal_via_ip`); (c) check whether `RSAU_CONFIG` on ≥ 7.55 reflects the param or hides it behind a UI checkbox; (d) verify the SAL terminal-field write path on kernel 793 — does it still fall back to client-supplied data, or does the kernel now derive from session TCB?

18. **SAL daily-cap behaviour on kernel 793.** The "stop logging on cap reached" default is documented historically. Need to: (a) re-read the `rsau/wrap_around` parameter semantics on 793 (cap-then-stop vs cap-then-rotate vs cap-then-overwrite-oldest); (b) check whether `RSAU_CONFIG_LOG_RES` (≥ 7.55) preserves a "cap-reached" persistence record that survives the file cap; (c) re-test 4.A.19 on a sized 100 MB lab system with an AU2 brute-force generator and confirm the actual cliff time vs the documented behaviour.

19. **BO ADS temp-file integrity on BI 4.3.** The paper covers BO XI / BI 4.0-era distributed audit. Need to: (a) confirm the temp-file location and format on BI 4.3 SP04; (b) verify whether SAP added an HMAC / chain hash to the temp records in any SP between 4.0 and 4.3 (search for new SAP Notes mentioning "Audit Database Store integrity"); (c) check whether the BTP-managed BO collector closes the gap or just shifts it.

20. **Speculative techniques the user expected from Troopers14 that are NOT in the paper.** The brief mentioned several techniques the user thought were in the original talk but, after reading the 32-slide deck end-to-end, they are demonstrably **not present**: direct `OPEN DATASET / MODIFY` rewrite of `.AUD` files; `RSAU_FILE_ADMIN` forged-event HMAC re-sign; "stop the kernel from rolling over mid-op"; direct SAPSYSLOG raw write to bypass SM21; `BAL_LOG_DELETE` to suppress change documents; SAP\* logon attribution as OS user under dpmon; client 066 / 001 EarlyWatch attribution-laundering; trace-level race-to-rotate. Several of these are credible primitives that **may be researched separately** — they were likely confused with Troopers13 (the prior "SAP Forensics" talk by the same authors) or with separate Onapsis blog posts, or are operator folklore. Action: track each as its own research item below (a–h) and verify against Troopers13 slides, Onapsis blog posts, and Layer Seven / SecurityBridge writings before promoting to the §4 catalogue. Each currently has **zero confirmed source** and should not be implemented until sourced.
    - (a) `OPEN DATASET ... FOR UPDATE`/`MODIFY` against `audit_*` AUD files — plausible but needs a source.
    - (b) `RSAU_FILE_ADMIN` direct call to rewrite events with HMAC re-sign — code-credible but no public PoC located.
    - (c) Kernel anti-rollover trick — needs concrete kernel param or RFC.
    - (d) Direct SAPSYSLOG file write — would need bypassing kernel's `SLOG<NR>` writer process; plausible from `<sid>adm` OS.
    - (e) `BAL_LOG_DELETE` change-doc suppression — function module **does** exist, but standard auth check is `S_APPL_LOG ACTVT=06`; needs verification this bypasses CDHDR/CDPOS.
    - (f) SAP\* dpmon OS-identity attribution — partially captured already in 4.A.9; deeper variant claimed in folklore needs sourcing.
    - (g) Client 066 / 001 EarlyWatch attribution — EarlyWatch is real and 066 was historically the EarlyWatch client; the "attribution-laundering" pattern needs a primary source.
    - (h) Trace race-to-rotate — captured in spirit by 4.B.6 (HTTP log race) but the SAL-specific variant needs sourcing.

---

## 8. Self-review crosswalk (§4 → §5 completeness)

Every §4 entry must have a §5.1 row. Self-check pass:

- 4.A.1 ↔ 5.1 row 1 ✓
- 4.A.2 ↔ 5.1 row 2 ✓
- 4.A.3 ↔ 5.1 row 3 ✓
- 4.A.4 ↔ 5.1 row 4 ✓
- 4.A.5 ↔ 5.1 row 5 ✓
- 4.A.6 ↔ 5.1 row 6 ✓ (shared with 4.C.7)
- 4.A.7 ↔ 5.1 row 7 ✓
- 4.A.8 ↔ 5.1 row 8 ✓
- 4.A.9 ↔ 5.1 row 9 ✓
- 4.A.10 ↔ 5.1 row 10 ✓
- 4.A.11 ↔ 5.1 row 11 ✓
- 4.A.12 ↔ 5.1 row 12 ✓
- 4.A.13 ↔ 5.1 row 13 ✓
- 4.A.14 ↔ 5.1 row 14 ✓
- 4.A.15 ↔ 5.1 row 15 ✓
- 4.A.16 ↔ 5.1 row 16 ✓
- 4.A.17 ↔ 5.1 row 17 ✓ *(new — Troopers14 Attack #1)*
- 4.A.18 ↔ 5.1 row 18 ✓ *(new — Troopers14 Attack #2; flagged in §5.4 as weak detection)*
- 4.A.19 ↔ 5.1 row 19 ✓ *(new — Troopers14 Attack #3; flagged in §5.4 as weak detection when file-pull SIEM)*
- 4.B.1 ↔ 5.1 row 20 ✓ (shared with 4.B.5)
- 4.B.2 ↔ 5.1 row 21 ✓
- 4.B.3 ↔ 5.1 row 22 ✓
- 4.B.4 ↔ 5.1 row 23 ✓
- 4.B.5 ↔ 5.1 row 20 ✓
- 4.B.6 ↔ 5.1 row 24 ✓
- 4.B.7 ↔ 5.1 row 25 ✓
- 4.B.8 ↔ 5.1 row 26 ✓ *(new — Troopers14 Attack #4; flagged in §5.4 as weak detection without per-tier temp-file forwarding)*
- 4.C.1 ↔ 5.1 row 27 ✓
- 4.C.2 ↔ 5.1 row 28 ✓
- 4.C.3 ↔ 5.1 row 29 ✓
- 4.C.4 ↔ 5.1 row 29 ✓
- 4.C.5 ↔ 5.1 row 30 ✓ (also called out as "no realistic detection" in 5.4)
- 4.C.6 ↔ 5.1 row 31 ✓ (also called out as "no realistic detection" in 5.4)
- 4.C.7 ↔ 5.1 row 6 ✓

All **thirty-four** technique entries are mapped (was thirty pre-Troopers14: +4.A.17, +4.A.18, +4.A.19, +4.B.8). Six entries (4.A.6 / 4.A.18 / 4.A.19 / 4.B.8 / 4.C.5 / 4.C.6) are explicitly flagged in §5.4 as having weak or no detection in the standard SOC posture, which is the honest result.

Row numbers above refer to the §5.1 table after Troopers14 merge (three new rows inserted between the old row 16 and the original row 17, plus one new row for 4.B.8 after the original row 22).

---

## 9. References

Inline sources for the document. SAP-internal / customer docs are listed by SAP Note number where applicable; external blog posts are linked.

- SAP Note **3380209** — Security Audit Log still active when `rsau/enable=0`. <https://userapps.support.sap.com/sap/support/knowledge/en/3380209>
- SAP Note **539404** — FAQ Security Audit Log (pre-7.50)
- SAP Note **3334594** — SM18 obsolete, use RSAU_ADMIN. <https://userapps.support.sap.com/sap/support/knowledge/en/3334594>
- SAP Note **3303172** — Time-limited virtual SAP\* via dpmon (already in plan 11 references)
- SAP Note **2697280** — SAP Cloud Connector log location. <https://userapps.support.sap.com/sap/support/knowledge/en/2697280>
- SAP Note **2033317**, **1810913** — `rsau/integrity` HMAC behaviour
- SAP Community — *Analysis and Recommended Settings of the Security Audit Log (SM19/RSAU_CONFIG, SM20/RSAU_READ_LOG)*: <https://community.sap.com/t5/application-development-and-automation-blog-posts/analysis-and-recommended-settings-of-the-security-audit-log-sm19-rsau/ba-p/13297094>
- Daniel Berlin — *Protection of the Security Audit Log against deletion*: <https://www.daniel-berlin.de/security/sap-sec/protection-of-the-security-audit-log-against-deletion/>
- saptechnicalguru.com — *Audit log integrity protection*: <https://www.saptechnicalguru.com/audit-log-integrity-protection/>
- Layer Seven Security — *Recommended Settings for SAP Logging and Auditing*: <https://www.layersevensecurity.com/recommended-settings-for-sap-logging-and-auditing/>
- Onapsis — *I Know What You Read Last Summer: SAP Read Access Logging*: <https://onapsis.com/blog/i-know-what-you-read-last-summer-how-sap-read-access-logging-can-help-identify-data-theft/>
- SAP Help Portal — *Evaluating the Log File of SAProuter*: <https://help.sap.com/doc/saphelp_nw73ehp1/7.31.19/en-us/48/6cb2996c0707dce10000000a42189d/content.htm>
- SAP Help Portal — *Audit Logging (Cloud Connector)*: <https://help.sap.com/docs/r/cca91383641e40ffbe03bdc78f00f681/Cloud/en-US/63bd823990cb4d26a098869fe3a0a8a7.html>
- SAP Help Portal — *Logging and Tracing (NW Java)*: <https://help.sap.com/doc/saphelp_nw73ehp1/7.31.19/en-US/48/aeb18c5bb5356be10000000a421937/content.htm>
- SAP Knowledge Base **2801245** — How to get NetWeaver Java default trace from /nwa
- Layer Seven Security — *Securing the SAP Cloud Connector: A 2025 Guide*: <https://www.layersevensecurity.com/securing-the-sap-cloud-connector/>
- SAP-tcodes.org / SAP Datasheet — SRALMONITOR / SRAL_LOG references
- DAB Europe — *SAP Change Tables Part 2 — Tracking Changes*: <https://www.dab-europe.com/en/articles/sap-change-tables-part-2-what-tables-and-field-changes-are-actually-getting-logged-and-where/>
- SAP Help Portal — *Trace Logging (BC-CST)*: <https://help.sap.com/doc/saphelp_nw73ehp1/7.31.19/en-US/47/cfdbfcc3ad2972e10000000a42189b/content.htm>
- WithSecure Labs — *SAP Smashing (Internet Windows)*: <https://labs.withsecure.com/publications/sap-smashing-internet-windows>
- Internal cross-references — SAPMAP `docs/research/05_post_exploitation.md` §1.6 (audit clearing baseline); plan 11 (dpmon EUP-2 footprint); plan 12 (MYSAPSSO2 forgery as identity-impersonation primitive).
- **Perez-Etchegoyen, Juan and Vandevanter, Will — *Hiding the Breadcrumbs: Anti-forensics on SAP Systems*, Troopers Security Conference 2014, Heidelberg, March 2014.** Onapsis Inc., 32 slides. Source PDF: <https://troopers.de/media/filer_public/14/60/1460e5ce-7a34-4dfc-8191-9da9f633f4ff/troopers14-hiding_the_breadcrumbs_anti-forensics_on_sap_systems-juanperez-etchegoyenwill_vandevanter.pdf> (accessed 2026-06-15). Specifically references in this document:
    - 4.A.17 (TSL1D delete via SE92) — slides 13–15 (*Attack #1 – Delete SAL messages*); cites SAP Security Note **1926485** (December 2013).
    - 4.A.18 (terminal-name spoofing via `rsau/ip_only=0`) — slides 16–18 (*Attack #2 – Hide source of attack*); cites SAP Note **1497445**.
    - 4.A.19 (SAL daily-cap exhaustion / 100 MB/day default) — slides 19–21 (*Attack #3 – Reaching the limit*).
    - 4.B.8 (BO temporary-audit gap before ADS) — slides 22–24 (*Attack #4 – SAP BO Temporary audit*).
    - Log-locations table (cross-reference for §1, §2, §3 inventories) — slide 26.
- Perez-Etchegoyen, Juan and Sanchez, Nahuel — *Detecting white-collar cybercrime: SAP Forensics*, Troopers 2013 (referenced in the 2014 paper, slide 4 and slide 32). Not directly cited in §4 catalogue; relevant as the predecessor talk that introduced SAP-side forensics primitives — re-read needed for verification of speculative items listed in §7.1 entry 20.

---

*End of document. Awaiting operator review before any §6 build commits.*
