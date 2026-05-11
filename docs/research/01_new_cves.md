# New SAP CVEs to Add to SAPMAP (2018–2026)

Research agent: "Recent SAP CVEs survey"

Already covered by SAPMAP (skipped): 10KBLAZE / CVE-2019-0344,
CVE-2020-6207 MS betrusted, CVE-2025-31324, CVE-2020-6287 RECON,
CVE-2020-6286 CTC traversal, CVE-2012-2611 CTC ConfigServlet,
SecStore decrypt, BAPI user creation.

---

## Tier A — HIGH fit, actively exploited, compact to implement

### 1. CVE-2025-42999 — Visual Composer deserialization (chain partner to 31324)

- **Stack:** AS Java, NW 7.50, Visual Composer metadata uploader
- **Auth:** Privileged in isolation; **unauth when chained with CVE-2025-31324**
- **Exploit:** Combined chain uploads a serialized Java payload (ysoserial-style CommonsBeanutils1 / CommonsCollections gadget) to `/developmentserver/metadatauploader` with a serialized object body. SAP's April 2025 patch addressed 31324 only; 42999 came in May 2025 — many organizations have a 12-month patch lag.
- **PoC:** Leaked full chain on Telegram (ShinyHunters / Scattered Spider, Aug 2025); multiple GitHub forks; Onapsis writeup.
- **Patch status 2026:** Still widely exploitable. Unit 42 confirmed continued mass-scanning through late 2025.
- **Fit:** **HIGH.** Drops into existing `sap_cve_2025_31324.py` module. ~100-200 LOC.

### 2. CVE-2025-42944 — RMI-P4 insecure deserialization (unauth RCE)

- **Stack:** AS Java, RMI-P4 protocol (ports 5NN04 / 5NN06 / 5NN07, typically 50004/50006)
- **Auth:** **None** — CVSS 10.0
- **Exploit:** Crafted serialized object over the SAP P4 binary protocol. Base: [codewhitesec/sap-p4-java-deserialization-exploit](https://github.com/codewhitesec/sap-p4-java-deserialization-exploit) scaffold (custom SAP JVM serializer); swap in modern gadget chain. SAPMAP's scanner can add P4 port detection (instance+4 on 5NN04).
- **Patch status 2026:** Fixed Sep 2025 (SAP Note 3634501). Large installed base of unpatched kernels. P4 almost always internet-blocked but reachable across internal segments — perfect for SAPMAP's lateral-movement model.
- **Fit:** **HIGH.** Second unauth Java RCE path covering NW versions without Visual Composer deployed. Medium effort (new module, P4 framing from codewhitesec; 300-500 LOC).

### 3. CVE-2025-42957 — S/4HANA RFC ABAP code injection

- **Stack:** ABAP, S/4HANA Private/On-Prem, DMIS (SLT) component
- **Auth:** Any user with `S_RFC` + `S_DMIS` act=02 — equivalent to "any dialog user"
- **Exploit:** RFC call to the vulnerable DMIS function module with a parameter containing ABAP source; module EVAL-compiles without sanitization. Pairs with SAPMAP's existing SAPMAP00 creation — perfect second-stage escalation path.
- **PoC:** Technical analyses at SecurityBridge, Pathlock, Rescana (Aug 2025); function module names disclosed; in-the-wild exploitation confirmed by SecurityBridge Threat Labs.
- **Patch status 2026:** Fixed Aug 12 2025 (SAP Note 3627998). Active exploitation ongoing; many S/4HANA landscapes lag 3-6 months on DMIS patching.
- **Fit:** **HIGH.** Pairs naturally with SAPMAP's "create SAPMAP00 low-priv → escalate" flow. Small effort (~150 LOC) — new `@lpe_method` in `sapmap_lpe.py`.

### 4. CVE-2022-22536 — ICMAD memory-pipes HTTP smuggling

- **Stack:** Both (ABAP + Java + Content Server + Web Dispatcher)
- **Auth:** **None**
- **Exploit:** CL.TE or TE.CL desync against ICM on port 80NN / 44NN. Smuggle a request that hits an authenticated path by prepending to the victim's session. Weaponizable as: (a) leak SSO cookies / MYSAPSSO2 tickets, (b) hit `/sap/bc/gui/sap/its/webgui` authenticated to run transactions, (c) replay against `/sap/bc/soap/rfc`.
- **PoC:** Multiple on GitHub — [ZZ-SOCMAP/CVE-2022-22536](https://github.com/ZZ-SOCMAP/CVE-2022-22536), antx-code/CVE-2022-22536, BecodoExploit-mrCAT/SAPGateBreaker-Exploit, errorfiathck/icmad-exploit; Onapsis "ICMAD" writeup; CISA KEV-listed.
- **Patch status 2026:** Patch released Feb 2022. Despite age, SAPMAP-typical engagements still find unpatched Content Server and older Web Dispatcher instances because they sit in DMZ/isolated tiers that miss the main ABAP patch cycle.
- **Fit:** **HIGH** — but *not* for session theft (no public PoC reproduces that; race-bound, unreliable on engagement day). The realistic primitive is **ACL bypass via loopback-trusted smuggled inner request**, chaining to `/heapdump/` → SecStore-key recovery (existing SAPMAP primitive) and `/CTC/ConfigServlet` (RCE on unpatched J2EE). Pure stdlib HTTP, no SAP protocols. ~350 LOC over 3–4 days. **See implementation plan in [`10_icmad_implementation_plan.md`](10_icmad_implementation_plan.md).**

### 5. SAP Management Console (sapstartsrv) `OSExecute` — authenticated OS-cmd via SOAP

- **Stack:** Both (sapstartsrv ships on every SAP host)
- **Auth:** Any OS user with "ACL" entry — commonly `sapadm` / `sidadm`. **`GetProcessList` / `ReadLogFile` / `ListDeveloperTraces` are unauth** and leak SID/kernel/patch level.
- **Exploit:**
  1. **Unauth recon** — `GetProcessList`, `ReadLogFile`, `ListDeveloperTraces`, `GetAccessPointList` on port 5NN13/5NN14 to fingerprint SID, DB type, kernel rev, SAProuter settings, list logfiles (which can contain passwords on older kernels).
  2. **Authed RCE** — `OSExecute` SOAP (Metasploit `sap_mgmt_con_osexec_payload`) using recovered `sidadm` creds (often harvested from SecStore / tracefiles).
- **PoC:** Metasploit `auxiliary/scanner/sap/sap_mgmt_con_getprocesslist`, `exploit/multi/sap/sap_mgmt_con_osexec_payload`; ExploitDB 18032.
- **Patch status:** ACL controlled by `service/admin_users` profile param — broken configs persist. SAP has not fully closed the unauth endpoints.
- **Fit:** **HIGH.** Unauth fingerprinting would materially improve deep-scan. Small-medium (~300 LOC split across scanner and new `sap_sapcontrol_osexec.py`).

---

## Tier B — MEDIUM fit, useful but niche / requires preconditions

### 6. CVE-2024-41730 — BusinessObjects BI Platform SSO token bypass

- **Stack:** SAP BusinessObjects BI 4.3 (Java)
- **Auth:** None (if Enterprise auth SSO enabled — common)
- **Exploit:** `/biprws/logon/long` returns a logon token for any user without authentication. Use token to call CMC, extract repository contents, pivot to CMS DB.
- **Fit:** MEDIUM. BO often segregated but cross-connected via BW/HANA users. Small effort.

### 7. CVE-2023-36922 — IS-OIL OS command injection (authed)

- **Stack:** ABAP, IS-OIL component
- **Auth:** Any dialog user
- **Exploit:** Unprotected RFC/report parameter passes to `system()` via `CALL 'SYSTEM'`. Attacker submits `; id`-style payload.
- **Fit:** MEDIUM. Only fires on IS-OIL-equipped systems (utilities, chemicals). Small effort.

### 8. CVE-2023-41367 — WebDynpro Guided Procedures auth bypass

- **Stack:** AS Java, NW 7.50
- **Auth:** None
- **Exploit:** Missing auth check on `/webdynpro/resources/sap.com/tc~gp~admin_web/Admin#` — enumerate users, leak emails.
- **Fit:** MEDIUM. Low-impact by itself; feeds SAPMAP's `sap_default_creds.py` with a better userlist.

### 9. CVE-2020-6364 — Solution Manager Introscope EM cookie command injection

- **Stack:** CA Introscope Enterprise Manager (bundled with SolMan / Focused Run)
- **Auth:** **None** — CVSS 10.0
- **Exploit:** Modify cookie on Introscope EM web UI; server shells out with cookie content. RCE as EM service user.
- **PoC:** Onapsis advisory ONAPSIS-2021-0008.
- **Fit:** MEDIUM. SolMan environments only. Distinct port (8081 typical).

### 10. CVE-2018-2380 — SAP CRM Internet Sales log-injection → RCE

- **Stack:** AS Java + CRM (7.01–7.54)
- **Auth:** Any CRM user
- **Exploit:** Directory traversal writes attacker-controlled content into a log file under webapps (JSP write), request as JSP → RCE.
- **PoC:** [erpscanteam/CVE-2018-2380](https://github.com/erpscanteam/CVE-2018-2380)
- **Fit:** MEDIUM.

### 11. CVE-2016-9563 — BC-BMT-BPM-DSK XXE (AS Java)

- **Stack:** AS Java 7.5
- **Auth:** Any authenticated user
- **Exploit:** XXE reads files as J2EE_ADMIN equivalent — pulls `secstore.properties`, `SAPSSLS.pse`, `bootstrap.properties`. Chains after RECON.
- **Fit:** MEDIUM.

### 12. CVE-2018-2392 / CVE-2018-2393 — SAP IGS XMLCHART XXE

- **Stack:** SAP Internet Graphics Server (port 40NN / ICM-routed)
- **Auth:** **None**
- **Exploit:** Unauth POST to `/XMLCHART` with DOCTYPE entity pulls arbitrary files as IGS user (often sidadm).
- **PoC:** [Vladimir-Ivanov-Git/sap_igs_xxe](https://github.com/Vladimir-Ivanov-Git/sap_igs_xxe); Metasploit `auxiliary/admin/sap/sap_igs_xmlchart_xxe`.
- **Fit:** MEDIUM. Clean unauth file-read primitive lets SAPMAP grab SSFS key material without first creating a user.

### 13. CVE-2019-0330 — SAP Host Agent OS command injection

- **Stack:** SAP Host Agent (every SAP host, port 1128/1129)
- **Auth:** Authenticated host-agent user (`sapadm`)
- **Exploit:** SOAP with un-sanitized parameters hits shell. Post-auth only.
- **Fit:** MEDIUM. After SecStore dump, SAPMAP can try Host-Agent auth across landscape for universal OS-cmd.

### 14. CVE-2011-0444 / CVE-2010-5326 — J2EE Invoker Servlet

- **Stack:** AS Java ≤ 7.20 or any system with `UseInvokerServlet=true`
- **Auth:** **None**
- **Exploit:** `/invoker/EJBInvokerServlet` directly invokes arbitrary EJB methods bypassing servlet auth.
- **Fit:** MEDIUM-LOW. Legacy but still lurks on EOL NW 7.10/7.11/7.20 and custom apps that re-enable it.

---

## Tier C — skip / note only

- **CVE-2023-23857** (P4 missing-auth) — superseded by CVE-2025-42944.
- **CVE-2023-49583** — actually a Node.js `@sap/xssec` library (BTP/CAP), not classic NW.
- **CVE-2024-38812** — VMware vCenter, not SAP.
- **CVE-2022-29612** — same bug class as 2025-42957 (newer).
- **CVE-2021-33677 / 33679** — info-disclosure / brittle chain.
- **CVE-2021-38163** — superseded by 2025-31324 metadata uploader pattern.
- **CVE-2024-33006** — limited public detail; low confidence on PoC.
- **CVE-2024-22127** — SAP ASE DoS, not lateral-movement.
- **CVE-2017-9844** — superseded by 2025-42944 research.
- **CVE-2020-6284 / 6265** — SolMan; 6207 already covered.

---

## Cross-cutting findings

### Java technical users with default passwords (2024–2026 observations)

| User | Default | 2025? |
|---|---|---|
| `Administrator` (Java) | `administrator` / `manage` / blank | Yes on lab/DEV |
| `J2EE_ADMIN` | set at install | Often left as master |
| `SAPJSF` (Java→ABAP comm) | instance master password | **Extremely common** |
| `SOLMAN_ADMIN` / `SOLMAN_BTC` | master or `welcome` | Yes |
| `SAP*` (ABAP) | `06071992` / `PASS` / `admin` | Only on unconfigured clients |
| `DDIC` | `19920706` | Frequently default on sandbox |
| `EARLYWATCH` | `support` | Yes on client 066 |
| `TMSADM` | `PASSWORD` / `$1Pawd2&` | Yes on client 000 |
| `DB2<SID>` / `SAP<SID>` | instance master | Recoverable from SecStore |

### ICM / Web Dispatcher endpoint enumeration

- `/sap/public/info` — unauth on every ICM; returns SID, kernel rev, system number, DB type, timezone, RFC gateway info. **Add to SAPMAP fast-scan.** No CVE — it's by design.
- `/sap/public/bc/ur/Login/assets/corbu/sap_logo.png` — confirms ICM alive.
- `/sap/bc/webdynpro/sap/WDR_TEST_EVENTS` — if 200, WD open for authed attack surface.
- `/sap/bc/bsp/sap/system_public/` — BSP enumeration.
- `/sap/admin/public/index.html` — Web Dispatcher admin UI (password-protected by authfile; bruteforceable).

### ABAP RFC code-injection primitives

RFC isn't serialized-object based; "injection" class is uniformly **ABAP code injection via `INSERT REPORT` / `GENERATE SUBROUTINE POOL`** in function modules accepting source as a parameter. Known vulnerable FMs:

- `/SDMO/RUN_COMMAND`
- `RFC_ABAP_INSTALL_AND_RUN` (dev-only but often on by accident)
- `SUBST_EXECUTE_REPORT`
- `RSDMD_BATCH_CALL` (BW, SEC Consult 2023)
- DMIS function module behind CVE-2025-42957 (redacted name; `/1LT/` namespace)

A SAPMAP extension that tries the **authenticated RFC code-injection sweep** (given a toehold account) across 10-15 known-vulnerable FMs with a benign `WRITE 'sapmap'` payload would be high value.

---

## Final top-5 recommendation

| # | Add | Capability | Effort |
|---|---|---|---|
| 1 | **CVE-2022-22536 ICMAD smuggler** ([plan](10_icmad_implementation_plan.md)) | Unauth **ACL bypass** to internal admin surface — `/heapdump/` → SecStore key → JCo decrypt chain. Widest reach. (Session-hijack framing deprecated — see plan §A.) | **Small** ~350 LOC, 3–4 days |
| 2 | **CVE-2025-42999 chain into 31324** | Patch-tail exploitation 12+ months. Reuses upload primitive. | **Small** ~150 LOC |
| 3 | **CVE-2025-42957 DMIS as `@lpe_method`** | Turns SAPMAP00 into SAP_ALL on S/4HANA. Actively exploited. | **Small** ~150 LOC |
| 4 | **CVE-2025-42944 P4 module + port fingerprint** | Second unauth Java RCE. Internal-segment lateral gold. | **Medium** ~400-500 LOC |
| 5 | **SAPControl/sapstartsrv unauth recon + OSExecute** | `ReadLogFile`, `ListDeveloperTraces`, `GetAccessPointList` + `/sap/public/info`. | **Small-Medium** ~300 LOC |

**Bonus:** CVE-2018-2392 SAP IGS XXE — zero-cost arbitrary file-read lets SAPMAP grab `SSFS_<SID>.KEY`/`.DAT` without first creating a user — shortens the SecStore kill chain. ~100 LOC.

---

## Sources

- [ZZ-SOCMAP CVE-2022-22536 PoC](https://github.com/ZZ-SOCMAP/CVE-2022-22536)
- [Tenable ICMAD blog](https://www.tenable.com/blog/cve-2022-22536-sap-patches-internet-communication-manager-advanced-desync-icmad)
- [Onapsis CVE-2025-31324 active exploitation](https://onapsis.com/blog/active-exploitation-of-sap-vulnerability-cve-2025-31324/)
- [Help Net Security — leaked 31324+42999 chain](https://www.helpnetsecurity.com/2025/08/20/cve-2025-31324-cve-2025-42999-sap-netweaver-exploit-public/)
- [RedRays CVE-2025-42944 RMI-P4 RCE](https://redrays.io/blog/cve-2025-42944-critical-severity-remote-code-execution-in-sap-netweaver-rmi-p4/)
- [codewhitesec/sap-p4-java-deserialization-exploit](https://github.com/codewhitesec/sap-p4-java-deserialization-exploit)
- [SecurityBridge CVE-2025-42957 S/4HANA](https://securitybridge.com/blog/critical-sap-s-4hana-code-injection-vulnerability-cve-2025-42957/)
- [Metasploit SAP MgmtCon OSExecute](https://www.rapid7.com/db/modules/exploit/multi/sap/sap_mgmt_con_osexec_payload/)
- [RedRays CVE-2024-41730 BO](https://redrays.io/blog/critical-sap-businessobjects-authentication-vulnerability-cve-2024-41730/)
- [Onapsis CVE-2020-6364 Introscope EM](https://github.com/Onapsis/vulnerability_advisories/blob/main/2021/CVE-2020-6364/ONAPSIS-2021-0008-OS_Command_Injection_in_CA_Introscope_Enterprise_Manager.md)
- [erpscanteam CVE-2018-2380 CRM](https://github.com/erpscanteam/CVE-2018-2380)
- [Vladimir-Ivanov-Git/sap_igs_xxe](https://github.com/Vladimir-Ivanov-Git/sap_igs_xxe)
- [Onapsis Volume IV — J2EE Invoker Servlet](https://onapsis.com/resources/publications/volume-iv-invoker-servlet-dangerous-detour-sap-java-solutions/)
- [SEC Consult SAP ABAP RFC exploit chain](https://sec-consult.com/blog/detail/responsible-disclosure-of-an-exploit-chain-targeting-the-rfc-interface-implementation-in-sap-application-server-for-abap/)
- [SEC Consult BW RSDMD_BATCH_CALL code injection](https://sec-consult.com/blog/detail/sap-privilege-escalation-abap-code-injection-sap-business-warehouse/)
- [Troopers "unknown default SAP accounts"](https://troopers.de/media/filer_public/37/34/3734ebb3-989c-4750-9d48-ea478674991a/an_easy_way_into_your_sap_systems_v30.pdf)
- [OWASP pysap default SAP credentials](https://github.com/OWASP/pysap/blob/master/examples/default_sap_credentials)
- [chipik/SAP_RECON CVE-2020-6287/6286 PoC](https://github.com/chipik/SAP_RECON)
