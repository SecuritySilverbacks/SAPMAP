# SAP Initial-Access Research

Research agent: "Default creds / initial access misconfigurations"

SAPMAP already: default ABAP users via DIAG, MS info leak, SAProuter
info leak, GW check for 10KBLAZE.

---

## 1. Default credentials — full matrix (2024 state)

### 1.1 ABAP AS (NetWeaver ABAP)

| User | Default | Client | 2024 Status | Notes |
|---|---|---|---|---|
| `SAP*` | `06071992` | 000, 001, 066 | Still shipped; hardcoded fallback if user deleted and `login/no_automatic_user_sapstar=0` | **Most abused.** If deleted from USR02, hardcoded `PASS` re-enables with `SAP_ALL`. Kernel flag defaults to 1 since 7.40 SP but many old prod systems still run 0. |
| `SAP*` | `PASS` | any | Only when USR02 row missing + `no_automatic_user_sapstar=0` | Same as above |
| `DDIC` | `19920706` | 000, 001 | Still shipped on fresh install | Required for installs/upgrades. Often changed in PRD, **left default on DEV/QA/sandbox.** |
| `TMSADM` | `PASSWORD` (≤7.00) / `$1Pawd2&` (7.01+) / `admin` | 000 | Still there | RFC user for transports. Often still default — password change breaks STMS. Note 1414256. |
| `EARLYWATCH` | `SUPPORT` | 066 | Client 066 removed by Note 1749142 (2013), **but still present in ~30% of legacy systems.** | Read-only in theory; has `RFC_ABAP_INSTALL_AND_RUN` access on many. |
| `SAPCPIC` | `ADMIN` / `CPIC` | 000, 001 | Deprecated but present | Communication user. |
| `WF-BATCH` | `SAP_WAS_is_great` or `<sidadm>` | 000 | On some installs | Workflow batch user. |
| `J2EE_ADMIN` | random @ install on double stack | 000 | Still ships | |
| `SOLMAN_ADMIN` / `SOLMAN_BTC` | `<initial>` or `init1234` | 000 | Ships with SolMan | See §1.4 |
| `SMD_*` / `SMDAGT_<SID>` | auto-generated but often `init1234` / `welcome` / `<sidadm>` | | Still in use | Diag agents. |

**SAPMAP note:** existing DIAG login probe should also try `SAP*/PASS` against clients `000, 001, 066, 100, 200, 300, 800, 900` — hardcoded fallback only works when SAP* entry doesn't exist in USR02 for *that client*. 066 row is frequently orphaned.

### 1.2 AS Java (UME)

| User | Default | Notes |
|---|---|---|
| `Administrator` | sapinst default: `welcome1` or `<sidadm>` | Present on every Java install. Enum via `/useradmin`. |
| `J2EE_ADMIN` | same as `<sidadm>` | Still present. |
| `sap.system` | `sap` | Legacy demo from 6.40; still on old PI/XI. |
| `sap_demo` / `sapdemo` | `sap_demo` / `init` / `sap` | "Demo examples" component installed. |
| `J2E_ADMIN` / `<SID>_ADM` | `<sidadm>` | Per-SID admin. |
| `CTCUSER` | `admin` or none (before Note 1589525) | Config Tool Center. **Very high impact** — full JMX mgmt. |
| `PIAPPLUSER` / `PIISUSER` / `PILDUSER` / `PIRWBUSER` / `PIDIRUSER` | `<init>` / `sap` | PI/PO installs. |
| `xmluser`, `xiappluser`, `xiisuser` | various | PI. |

### 1.3 HANA

| User | Default | Status |
|---|---|---|
| `SYSTEM` | `manager`, `Manager1`, `Welcome1`, `<sidadm>` | Always present, **should be disabled post-install** — most orgs leave enabled. |
| `SAPHANADB` | `<initial>` | Schema owner; enabled if grants given. |
| `_SYS_REPO` | technical | Can't login but full-object grants. |
| `DBACOCKPIT` | tech | |
| `XSSQLCC_AUTO_USER_*` | random | |
| `SAP<SID>` / `SAPABAP1` / `SAPHANADB` | random at ABAP-on-HANA install | Visible in HANA studio. |
| `XSA_ADMIN`, `XSA_DEV`, `XSA_AUDIT` | `Manager1` / `Welcome1` | XSA stack. |
| `COCKPIT_ADMIN` | `Welcome1` | HANA cockpit. |

**HANA SQL port** = `3<NN>15` / `3<NN>41` (systemdb). Hsqldbc probe: `SELECT * FROM DUMMY`. Error message differs for bad user vs bad pass.

### 1.4 Solution Manager 7.2

| User | Default |
|---|---|
| `SOLMAN_ADMIN` | `init1234` / `welcome1` |
| `SOLMAN_BTC` | `init1234` |
| `SMD_ADMIN` / `SMD_BI_RFC` / `SMD_RFC` | `init1234` |
| `SAPSUPPORT` | `SAPSUPPORT` / `init1234` |
| `CONTENTSERV` | `contentserv` |
| `BWREMOTE` | RFC dest |

### 1.5 SAP BusinessObjects BI

| User | Default |
|---|---|
| `Administrator` | **blank** (installer default) |
| `Guest` | blank (disabled by default since BI 4.2 SP4) |
| `QAAWS` | blank |
| CMC / Tomcat admin | `admin` / `shohbuS` on older versions |
| Installer OS accounts | `bisadm`, `boadmin` |

### 1.6 SAP MDM / MDG

- `Admin` / blank
- `Application` / blank

### 1.7 SAP Content Server / Cache Server

- Protocol: `/ContentServer/ContentServer.dll?...`
- Auth via shared secret — if `ContRep` config default, admin URL `contrepinfo` anonymous.
- `admin` / `admin` on Sybase-based installs.

### 1.8 SAP Host Agent (saphostctrl / SAPControl SOAP)

- Port `1128/tcp` (HTTP) / `1129/tcp` (HTTPS).
- Anonymous: `GetVersionInfo`, `GetInstanceProperties`, `ListLogFiles`, `ReadLogFile`, `ParameterValue` (depends on ACL).
- Auth (Start/Stop/OSExecute): `<sidadm>` + OS password. Often `<sidadm>` / `<sidadm>` or weak.

### 1.9 MaxDB / liveCache

| User | Default |
|---|---|
| `SUPERDBA` | blank |
| `DBM` | blank |
| `CONTROL` | `CONTROL` |
| `DBADMIN` | initial during install |
| `SAPR3` | `SAP` |

### 1.10 BTP / XSUAA

- `admin` / `manage` from `xs-security.json` dev templates pushed to prod.
- Service-key credentials checked into GitHub (search during recon).
- Cloud Foundry `cf login -a api.cf.<region>.hana.ondemand.com` with service broker defaults.

### 1.11 SAP MII / OEE / PCM

- MII: `Administrator` / `manage` (pre-15.x), `SAP_XMII_Administrator` / `welcome`.
- OEE: `oeeadmin` / `oeeadmin`.
- PCM: `pcm_admin` / `pcm_admin`.

### 1.12 SAP Web Dispatcher

- `/sap/wdisp/admin` — defaults denied since 7.49; older: `icm/HTTP/admin_0 = PREFIX=/sap/wdisp/admin` with no auth returns queue stats.

---

## 2. Pre-auth info-disclosure endpoints

### 2.1 ICF (ABAP HTTP)

| Path | Leaks | Detect string | Fix |
|---|---|---|---|
| `/sap/public/info` | SOAP XML: kernel rel, SP, patch, host, DB, OS, lang | `<rfcsi:RFC_SI_EXPORT>` | Note 1394100. **Goldmine.** |
| `/sap/public/myssocntl` | SSO/UME config XML | `<sso_config>` / `<ssocntl>` | Note 1417568 |
| `/sap/public/bc/icons` / `/sap/public/bc/icons_rep` | Icon repo — confirms ICF live | `<!-- Icon ` | |
| `/sap/public/bc/ur/Login/assets/corbu/` | UR theme files — theme version = NW release | `corbu/` path | |
| `/sap/public/bc/ur/nw5/themes/~cache-<hash>/` | cached theme hash = NW release | hash mapping | |
| `/sap/public/bc/its/mimes/webgui/99/~caches/` | ITS webgui mime | 200 | |
| `/sap/public/ping` | empty 200 — active ICF | `Server: SAP NetWeaver...` | |
| `/sap/bc/ping` | 401 unless whitelisted; leaks `Server:` header | `Server:` value | |
| `/sap/bc/soap/wsdl?services=RFC_SYSTEM_INFO` | Auth usually; 401 body reveals system | `sap-server` header | |
| `/sap/bc/soap/rfc` | SOAP endpoint; 500 on bad envelope leaks kernel | `HTTP/1.1 500` + `abap` | |
| `/sap/bc/gui/sap/its/webgui` | Login — HTML version string | `<meta name="SAP"` | |
| `/sap/bc/webdynpro/sap/WDR_TEST_EVENTS/?sap-system-login=X` | User-enum via WD login; timing | | Note 2258786 |
| `/sap/bc/bsp/sap/system/connect` | BSP system ping | `<bsp-connect/>` / 200 | |
| `/sap/bc/bsp/sap/it00` | BSP tutorial — often left on | tutorial landing | |
| `/sap/bc/gui/sap/its/webgui/?sap-client=XXX` | Client enumeration — valid 200, invalid 404 | differential | |
| `/sap/bc/adt/core/discovery` | ADT discovery doc **often unauth** | `<atom:category scheme` | Note 1925554 |
| `/sap/bc/adt/discovery` | alias | | |
| `/sap/bc/adt/system/users/<name>` | User probe (differential on 401 vs 404) | | |
| `/sap/bc/ui2/start_up` | Fiori launchpad startup JSON incl. user, language | `"user":` | |
| `/sap/bc/ui5_ui5/sap/arsrvc_upb_admn/` | UI5 admin | | |
| `/sap/bc/webdynpro/sap/sd_vd_maintain_ov` | customer master WD — enum | | |
| `/sap/hrrcf_a_unreg_job_search` | unreg HR job search — ext user creation | | |
| `/sap/bc/SRTRFC/` | SOAP RFC runtime | | |
| `/sap/bc/srt/rfc/sap/*` | SOAP RFC services — wsdl `?wsdl=1.1&sap-client=NNN` | `<wsdl:definitions` | |
| `/sap/bc/soap/wsdl11?services=*` | wildcard service dump | list of functions | |
| `/sap/bc/bsp/sap/bsp_veri/` | BSP verification sample apps | | |
| `/sap/bc/workflow/` | workflow inbox | | |
| `/sc_res/` | Simple-Cloud resources on newer kernels | | |
| `/sap/public/bc/icf/logoff` | `<sid>~<instance>~<host>` sometimes in set-cookie | `MYSAPSSO2` | |
| `/sap/public/bc/sec/useridcheck` | user existence probe (historically no auth required) | `<result>USER_EXISTS</result>` | Note 2258786 |
| `/sap/public/icman` | ICM status — default deny since 7.40, present on legacy | `<ICMSTAT>` | |

### 2.2 Message Server

- TCP `3600 + NN` internal, `3900 + NN` external.
- `/msgserver/text/logon` — list of app servers.
- `/msgserver/text/lgsrv` — load-balanced server name.
- `/msgserver/text/groups` — logon groups.
- Pre Note 1421005 these HTTP endpoints answered on external port. Still on *very* many systems.

### 2.3 SAProuter

- Port `3299/tcp`.
- NI packet `ROUTER_ADM` (cmd 2) returns route permission table.
- `saprouter -L` equivalent leaks hostnames.
- `niping -c -H` test.

### 2.4 Gateway

- Port `3300 + NN`.
- **GWMON** anonymous: reg_info / sec_info / cb_info lists — usable for 10KBLAZE.
- SOAP on `3300+NN`: `/SAPOscolHandler` etc. on old kernels.

### 2.5 AS Java

| Path | Leaks |
|---|---|
| `/` | Redirects to `/irj/portal` / NWA — reveals stack |
| `/nwa/` | NetWeaver Administrator — login + build |
| `/useradmin/` | UME — user enum on error differential |
| `/index.html` | default tomcat-like index with SAP logo |
| `/sld/` | System Landscape Directory — `/sld/cimom` anonymous often |
| `/mmr/monitor` | metadata repo |
| `/pmi-stat/` | perf metrics |
| `/sap/monitoring/SystemInfo` | **already in SAPMAP** — SID, hostname, release |
| `/sap/monitoring/ComponentInfo` | full SC list |
| `/sap/monitoring/PerfOverview` | perf |
| `/webdynpro/resources/sap.com/tc~lm~itsam~ui~mainframe~wd/...` | ITSAM paths |
| `/ctc/servlet/ConfigServlet?param=com.sap.ctc.util.ConfigServlet;GETDBINFO` | **CVE-2020-6287 RECON** — anonymous, full DB info | Note 2934135 |
| `/CTCWebService/CTCWebServiceBean?wsdl` | CTC WS — CVE-2020-6287 | Note 2934135 |
| `/UDDISecurityService/UDDISecurityImplBean?wsdl` | leaks | |
| `/ROOT/` | default Tomcat | |
| `/logon/logonServlet` | UME logon; error `Authentication did not succeed` vs `User does not exist` — user enum | |
| `/irj/portal` | Portal; title has build number | |
| `/rwb/` | Runtime Workbench (PI) | |
| `/mdt/` | Message Display Tool (PI) — **CVE-2017-9844 path traversal** if unpatched | Note 2468187 |
| `/XIMonitor/`, `/XISOAPAdapter/MessageServlet?channel=...`, `/XIRWBWebService/` | PI/PO — often anon | |
| `/slc/` / `/tcc/` | Landscape/Transport | |
| `/webdynpro/dispatcher/sap.com/tc~lm~webadmin~mainframe~wd/WebAdminApp` | web admin | |
| `/ipc-ddic/ipc/servlet/UserDispatcher` | IPC | |
| `/PolicyConfiguration/PolicyConfigurationBean?wsdl` | WS policy — one of 11 CTC services in CVE-2020-6287 | |

### 2.6 SAP Web Dispatcher

- `/sap/wdisp/admin/public/default.html` — admin UI.
- `/sap/admin/public/default.html` — alt.
- `/sap/wdisp/info` — anonymous info page (old).

### 2.7 `sapinst` GUI (SWPM)

- TCP `4239` / `4241` (HTTPS).
- `/sapinst/` login page — credential is OS admin password of user launching sapinst.
- Running unattended on prod: credential recovery or brute-force.

### 2.8 Focused Run / ChaRM agent endpoints

- `/sap/bc/fnd/dsh/*` — Focused Run diagnostic hub.
- `/sap/bc/lhdb/*` — landscape.

---

## 3. User enumeration

### 3.1 ABAP DIAG / RFC path

**Lockout safety:** `login/fails_to_user_lock` default 5 since 7.40. Pre-7.40 was 12 but many orgs set 3. **Always 1 attempt only, then mark "needs separate observation round."**

Techniques:

1. **`/sap/public/bc/sec/useridcheck`** — pre-Note-2258786 kernels returned XML `<result>USER_EXISTS|USER_UNKNOWN</result>` without consuming lockout slot. Patched but still on kernels <7.45 and many 7.5x that didn't apply 2258786.

2. **WebGUI timing**: `/sap/bc/gui/sap/its/webgui` — POST `sap-user=X&sap-password=WRONG`.
   - Unknown user: ~50ms (kernel short-circuit).
   - Known user, wrong password: ~250ms (SUSR_LOGIN_CHECK_RFC runs; hash compare; DB roundtrip; audit log write).
   - ΔT ~150-200ms reliable over LAN.
   - **Don't advance the lock counter** by deliberately empty password on first probe — some kernels return `E:00:398` *before* counting. Test first on throwaway name.

3. **DIAG login response code**:
   - `SUSR_LOGIN_CHECK_RFC` → return 0/1/2/3:
     - 1 = user unknown
     - 2 = wrong password
     - 3 = user locked
     - 4 = password expired (still valid creds!)
     - 5 = password initial (valid — useful!)
   - Differential visible in DIAG reply. SAPMAP's existing probe can extract.

4. **`/sap/bc/adt/system/users/<USER>`** — 404 for unknown, 401/403 for existing. Doesn't trigger lockout when user unknown (no auth attempt).

5. **Java UME `/useradmin/`** — response XML `<exception>...no such user</exception>` vs `...authentication failed`. Different HTTP status: 401 vs 403 on some versions.

6. **HANA** — `hdbsql -n host:3<NN>15 -u BAD -p X`:
   - `authentication failed` (code 10) for both valid/invalid since SPS04.
   - But `SYSTEM` tenant still shows `user name` vs `invalid username or password`. Timing: bcrypt cost ~180ms for known user, ~5ms for unknown.

7. **SOAP RFC `/sap/bc/soap/rfc`** — envelope with `<sap-user>` — auth failure message in fault has `SRM_USER_NOT_FOUND` vs `SRM_PWD_INCORRECT` on old kernels.

8. **`/sap/bc/gui/sap/its/webgui?sap-system-login-basic_auth=X`** — forces Basic; WWW-Authenticate realm contains SID; 401 body HTML has different `<center>` paragraph for unknown vs locked.

9. **Password-policy probe**: submit empty password → if response is "enter password" rather than "login failed", user may exist with SSO-only config.

**Safe enum rule for SAPMAP:** For each candidate user, send **exactly one** probe per 24h using timing on `/sap/bc/gui/sap/its/webgui` with throwaway long wrong password. Record timing and deltas; never exceed 1 attempt against same user before Report state.

### 3.2 User dictionary

Beyond defaults above, enumerate:

- Technical: `CUAADMIN`, `CUA_RFC_<SID>`, `BWREMOTE`, `PIUSER`, `PISUPER`, `SAPSERVICE<SID>`, `RFCUSER`, `ALEREMOTE`, `GRCUSER`, `SMDAGT_<SID>`, `SAPJSF`, `SAPJSF_<SID>`.
- Business: `BASIS`, `BASISADMIN`, `ABAPER`, `ADMIN`, `FUNCUSER`, `TESTUSER`, `TEST01`-`TEST05`.
- Named: HR data if breached elsewhere.

---

## 4. Config weakness probes (passive / read-only)

### 4.1 via `/sap/public/info`

Single call returns unauth:

- `<rfcsi:RFCSI_EXPORT>`: kernel release, patch level, DB host, hostname, system ID, timezone, installation number.

Decision table:

- Kernel < 7.49 P200 → vulnerable to CVE-2020-6287 (RECON).
- Kernel 7.77 < P211 / 7.81 < P78 / 7.22 EXT < P51 → CVE-2022-22536 (ICMAD).
- Kernel < 7.53 P1323 → Invoker Servlet default policy risk (Java).
- Kernel 7.22 or 7.20 ext2 → EOM; assume everything.

### 4.2 via RFC (post-auth)

With any creds, `RFC_READ_TABLE` on `TPFET` / `RSPFPAR` or `RSPARAM`:

| Parameter | Bad value | Finding |
|---|---|---|
| `gw/reg_info` absent / `P TP=* HOST=* ACCESS=*` | 10KBLAZE ready | handled |
| `gw/sec_info` same | | |
| `login/no_automatic_user_sapstar` | 0 | **Critical** — SAP* fallback live |
| `login/min_password_lng` | < 8 | Finding |
| `login/password_expiration_time` | 0 | never-expiring |
| `login/fails_to_user_lock` | > 10 | Brute-forceable |
| `login/fails_to_session_end` | 0 | No throttle |
| `login/password_downwards_compatibility` | >0 | MD5/BCODE hashes stored |
| `login/password_hash_algorithm` | `iSSHA-1` or missing | should be `iSSHA-512` |
| `rdisp/gui_auto_logout` | 0 or >7200 | sessions linger |
| `rsau/enable` | 0 | audit off |
| `rsau/local/file` | missing | |
| `snc/enable` | 0 | DIAG unencrypted |
| `ssl/ciphersuites` | weak | |
| `icm/HTTP/logging_0` | default or excessive | data leak |
| `http/security_session_timeout` | -1 / huge | infinite session |
| `icm/HTTPS/trust_client_with_issuer` | `*` or wildcard issuer | any client cert accepted |
| `icm/HTTPS/verify_client` | 0 | |
| `ms/acl_info` | missing | MS ACL disabled |
| `ms/monitor` | 1 | MS monitor on external |
| `ms/admin_port` | 0 | admin port disabled = ok, but `3600+NN` still reachable |
| `service/protectedwebmethods` | not `SDEFAULT` | SAPControl risk |
| `sapgui/user_scripting` | TRUE | scripting enabled → mass extraction |
| `auth/rfc_authority_check` | < 6 | RFC ACL off |
| `auth/object_disabling_active` | Y | auth objects disabled |
| `wdisp/admin_allow_cache_monitor_access` | 1 | |

**Code sketch:**

```python
conn.call('RFC_READ_TABLE', QUERY_TABLE='TPFET',
          OPTIONS=[{"TEXT":"PARNAME LIKE 'login/%'"}],
          FIELDS=[{'FIELDNAME':'PARNAME'},{'FIELDNAME':'PARVALUE'}])
```

### 4.3 Remote unauth ICMAD (CVE-2022-22536) detection

No stable unauth fingerprint for patch itself. Heuristic:

1. `/sap/public/info` → kernel/patch.
2. Lookup against authoritative table from **SAP Note 3123396 v22
   (2022-03-22)** — fixed at patch level ≥:
   - Kernel 7.22 / 7.22 EXT / 7.22 EX2 → **1101** (rolling: 1115)
   - Kernel 7.49 → **1036**
   - Kernel 7.53 (incl. Content Server 7.53) → **915**
   - Kernel 7.77 → **429**
   - Kernel 7.81 → **227**
   - Kernel 7.85 → **69**
   - Kernel 7.86 → **15**
   - Kernel 7.87 → **4**
   - Kernel 8.04 64-BIT UNICODE → **207**
   - Web Dispatcher branches: same per-version number as above
     (7.22_EXT WD = 1115; 7.49 = 1036; 7.53 = 915; 7.77 = 429;
     7.81 = 227; 7.85 = 69)
   - Pre-7.22 kernels: out of maintenance → assume vulnerable
3. If below → "vulnerable to CVE-2022-22536 — SAP Note 3123396".

> **Topology caveat (from SAP Note 3123396 §Reason and
> Prerequisites):** the bug only exploits when an HTTP gateway
> (Web Dispatcher or 3rd-party reverse proxy) sits between the
> client and the ICM. "Direct access to SAP application servers is
> not vulnerable" — though the kernel still ships the buggy MPI
> code, so the patch-level finding stands regardless of topology.
> Severity should escalate when SAPMAP can prove a gateway is in
> the path.

Actively probing for the bug (crafted pipelined request) is exploit,
not check. See [10_icmad_implementation_plan.md](10_icmad_implementation_plan.md)
for the exploitation plan (detection, ACL bypass, heap-dump chain).

### 4.4 CVE-2020-6287 (RECON) unauth fingerprint

HEAD `/CTCWebService/CTCWebServiceBean?wsdl`:

- HTTP 200 + `<wsdl:definitions` → endpoint live; 11 vulnerable services.
- Kernel patch from /sap/public/info < Note 2934135 patch → high confidence.

### 4.5 Anonymous SAProuter info

`niping` packet with cmd 0x2 + parm `ROUTER_ADM` with subcmd `INFO` returns route table. SAPMAP does this.

### 4.6 Invoker Servlet

`/invoker/` or append `InvokerServlet` to any servlet URL. Detect: GET `/webdynpro/dispatcher/InvokerServlet` → 200 with servlet-not-found vs 404. Note 1445998 disables globally (default off since 7.20 EhP2), but individual apps still enable.

---

## 5. Auth bypasses still found

### 5.1 CVE-2020-6207 (bMsBetrusted / SolMan missing auth)

- Handled by SAPMAP.
- `/EemAdminService/EemAdmin` on SolMan Java — anon admin.

### 5.2 CVE-2020-6287 (RECON)

- Anonymous user creation via `/CTCWebService/CTCWebServiceBean`.
- SAPMAP has `sap_cve_2020_6287.py`.

### 5.3 CVE-2022-22536 (ICMAD)

- Memory-pipe response/request smuggling across ICM work processes.
- Detection: timing + `content-length`/`transfer-encoding` desync.

### 5.4 CVE-2021-33690 (SSRF in SolMan diagnostics)

- `/smd/backendservicecall/` anon SSRF from SolMan into customer landscape.

### 5.5 CVE-2021-21465 (HANA XSA — path traversal)

### 5.6 CVE-2022-22533 (memory leak in AS Java → session theft)

### 5.7 CVE-2023-23857 (unauth RCE on NW AS Java via CORBA P4 port 50004)

- Port 5<NN>04 accessible → P4 invoker → deserialize-to-RCE via GSSCredential.

### 5.8 CVE-2025-31324 / 31330 (Visual Composer metadata uploader RCE, unauth)

- SAPMAP has `sap_cve_2025_31324.py`.

### 5.9 CVE-2020-6286 (path traversal in `/sap/public/bc/icf/logoff` on SP 7.40)

### 5.10 CVE-2016-3976 / 2017-9844 (NW Java XXE/deserial via InvokerServlet)

### 5.11 RFC callback / function-group ACL weakness

- Legacy: RFC-enabled FM callable with no SU24/SU53 auth beyond `S_RFC` on function group. If target calls *back* to attacker RFC server and trusts it (bidirectional trust via RFCTRUST/sm59), attacker calls arbitrary FMs. CVE-2009-3977 class still on many systems.
- Probes: `RFC_PING`, `SUSR_USER_CHANGE_PASSWORD_RFC` (auth needed but weak), `BAPI_USER_*`, `SXPG_CALL_SYSTEM`, `TH_REMOTE_TRANSACTION`.

### 5.12 X-SAP-PassPort / sap-passport header trust

- `sap-passport` header historically trusted for auditing; on misconfigured reverse-proxy chain with `icm/trusted_reverse_proxy_<n>`, attacker-supplied `sap-user` could be honored if `icm/HTTP/auth_<n> PERMFILE=` unprotected. Rare.

### 5.13 `sap-trusted-system` / bMsTrust in RZ20 / Focused Run

- Trust relation DB leaked via SLD or LMDB anonymous.

### 5.14 SMD Agent unauth

- Port 504<NN> P4 — CVE-2019-0330 OS cmd injection via OSCMD when agent registered with default.

---

## 6. Version / patch fingerprinting

### 6.1 Kernel

`/sap/public/info` → `rfcsi_export.release` = `7.53`, `kernrel` = `7.53`, `KERNEL_PATCH_LEVEL`. Map to SAP Note DB; SAPMAP should carry JSON CVE↔patch map refreshable from launchpad.support.sap.com.

### 6.2 HTTP headers

- `Server: SAP NetWeaver Application Server 7.53 / ICM 7.5300` — ICM version.
- `Server: SAP J2EE Engine/7.50` — Java stack.
- `Set-Cookie: sap-usercontext=sap-client=100` — client ID.
- `Set-Cookie: SAP_SESSIONID_<SID>_<CLIENT>=` — SID + client.
- `Set-Cookie: saplb_*=<server>_<SID>_<NR>` — LB server name + instance.

### 6.3 ICM

- Header `sap-perf-fesrec` → perf trace stamp → kernel patch.
- Response on bad HTTP version: `HTTP/1.1 505` body with ICM build.

### 6.4 Error-string differentials

- "Speicherplatzüberlauf" vs "Memory overflow" — system default language, often 'DE'.
- `ICM_HTTP_INTERNAL_ERROR` page body has build date.
- `sap-system-login-basic_auth` redirects differ per SP.

### 6.5 Web Dispatcher

- `/sap/wdisp/admin/public/default.html` → HTML title `SAP Web Dispatcher 7.89`.

### 6.6 Kernel-to-CVE table (abbrev)

| Kernel | Last known-bad patch | CVEs |
|---|---|---|
| pre-7.22 | out of maintenance — assume any | CVE-2022-22536, 2020-6287 |
| 7.22 / 7.22 EXT / 7.22 EX2 | < 1101 | CVE-2022-22536, 2020-6287 |
| 7.49 | < 1036 | ICMAD |
| 7.53 | < 915 | ICMAD |
| 7.77 | < 429 | ICMAD |
| 7.81 | < 227 | ICMAD |
| 7.85 | < 69 | ICMAD |
| 7.86 | < 15 | ICMAD |
| 7.87 | < 4 | ICMAD |
| 8.04 64-BIT UC | < 207 | ICMAD |
| 7.89 | < early | recent fixes |
| 7.94 | < 0 | Visual Composer RCE 2025-31324 at VCFRAMEWORK 7.50 SP27 |

ICMAD patch numbers above: SAP Note 3123396 v22 (authoritative).

---

## 7. Internet exposure — Shodan / Fofa / Censys

### 7.1 Shodan

```
port:3299 "NI_RTERR"                     # SAProuter
port:3299 "saprouter"
port:3200 "NI_INTERNAL"                  # dispatcher
port:3300                                 # gateway
port:3600 "HTTP/1.0 200" "msgserver"     # message server http
port:8000 "SAP NetWeaver"
port:50000 "SAP J2EE"
port:50013,50014 "SAPControl"            # host agent SOAP
port:1128 "SAP Host Agent"
title:"SAP NetWeaver"
title:"SAP Web Dispatcher"
title:"SAPMMC"
title:"SAP NetWeaver Administrator"
http.html:"/sap/public/bc/ur"
http.favicon.hash:-266008933             # SAP Fiori launchpad favicon
http.favicon.hash:-1829986074            # SAP Logon favicon
html:"logonForm" "sap-system-login"
"SAP EP" port:50000
```

### 7.2 Fofa

```
app="SAP-NetWeaver"
app="SAP-SAProuter"
body="sap-login" && port="8000"
title="SAP Web Dispatcher"
port="3299"
```

### 7.3 Censys

```
services.service_name: SAP_ROUTER
services.http.response.html_title: "SAP NetWeaver Portal"
services.banner: "SAP NetWeaver"
```

### 7.4 Rough counts (2024 observations)

- ~3,500 SAProuters on port 3299 globally.
- ~12,000-15,000 SAP NW ICM instances on 8000/8001/50000 with `/sap/public/info` answering.
- ~1,200 message servers exposing 3600/3900 externally.
- ~600 systems answering `/CTCWebService/CTCWebServiceBean?wsdl` unauth (CVE-2020-6287 exposure 4+ years post-disclosure).
- Hundreds of `/developmentserver/metadatauploader` still exposed post-CVE-2025-31324 (Onapsis April 2025: >500 confirmed compromised).

---

## 8. Post-auth business-risk checks

Once SAPMAP has ABAP credentials, pull authorization assignments:

| Check | Table/FM | Risk |
|---|---|---|
| Who holds `SAP_ALL`? | AGR_USERS + AGR_PROF | obvious |
| Who can post to accounts `F_BKPF_BUK`? | AGR_1251 | banking risk |
| Who can run F110 payment run? | `F_REGU_KOA` / `F_REGU_BUK` | |
| Who can maintain vendor bank (FK02)? | `F_LFA1_AEN` field `BANK*` | invoice fraud |
| HR master data read `P_ORGIN` | AGR_1251 | PII |
| Debugger with replace (`S_DEVELOP` ACTVT 02 + DEBUG) | AGR_1251 | RCE-equivalent |
| SE16/SM30 wide | `S_TABU_DIS DICBERCLS=*` | data |
| RFC destinations with stored creds | RFCDES — trust + stored pwd to PRD | lateral |
| Table `USR02` read | `S_TABU_NAM USR02` | hash dump |

```python
# SAP_ALL holders
rows = conn.call('RFC_READ_TABLE',
    QUERY_TABLE='AGR_USERS',
    OPTIONS=[{"TEXT":"AGR_NAME = 'SAP_ALL'"}],
    FIELDS=[{'FIELDNAME':'UNAME'}])
```

---

## TOP 10 pre-auth / first-touch checks for SAPMAP

### #1 — `/sap/public/info` SOAP probe (unauth system fingerprint)

Drives patch-level logic for every other check.

```python
r = requests.get(f"http://{host}:{port}/sap/public/info", timeout=5)
# parse RFCSI_EXPORT: RFCSYSID, RFCDBHOST, RFCHOST, RFCKERNRL, RFCSAPRL, RFCIPADDR
```

### #2 — `/CTCWebService/CTCWebServiceBean?wsdl` (CVE-2020-6287)

```python
r = requests.get(f"http://{host}:{port}/CTCWebService/CTCWebServiceBean?wsdl",
                 timeout=5, verify=False)
vulnerable = r.status_code == 200 and b"<wsdl:definitions" in r.content
```

If vulnerable AND kernel < patched → finding. SAPMAP already has exploit; add independent detector.

### #3 — Kernel-to-CVE ICMAD check (CVE-2022-22536)

Pure table lookup on #1 output. Numbers from SAP Note 3123396 v22
(authoritative). Detection (the 2-response signature on a keep-alive
socket) is shipped as a separate exploit-grade probe — see
[10_icmad_implementation_plan.md](10_icmad_implementation_plan.md).

```python
ICMAD_FIXED = {
  '7.22':1101,'7.22EXT':1101,'7.22EX2':1101,
  '7.49':1036,'7.53':915,'7.77':429,
  '7.81':227,'7.85':69,'7.86':15,'7.87':4,
  '8.04':207,
}
if kernrel in ICMAD_FIXED and int(patchlvl) < ICMAD_FIXED[kernrel]:
    yield finding("CVE-2022-22536 ICMAD — SAP Note 3123396 missing")
```

### #4 — Message Server HTTP monitor leak

```python
r = requests.get(f"http://{host}:{3600+inst}/msgserver/text/logon", timeout=5)
if r.status_code == 200 and b'\t' in r.content:
    servers = [l.split()[0] for l in r.text.splitlines() if l.strip()]
    yield finding("MS HTTP monitor open", extras={"app_servers": servers})
```

Returned server names → add nodes, schedule further probes. Also `/msgserver/text/lgsrv`, `/msgserver/text/groups`.

### #5 — `/sap/public/bc/sec/useridcheck` (unauth, no lockout)

```python
payload = f'<?xml version="1.0"?><u><USER>{user}</USER></u>'
r = requests.post(f"http://{host}:{port}/sap/public/bc/sec/useridcheck",
                  data=payload, headers={'Content-Type':'text/xml'}, timeout=5)
exists = b'USER_EXISTS' in r.content
```

If endpoint answers on 2024 system → "Note 2258786 missing". Use to confirm default-creds user existence before DIAG login — don't burn lockout slots on non-existent accounts.

### #6 — `/sap/bc/adt/core/discovery` unauth ADT

```python
r = requests.get(f"http://{host}:{port}/sap/bc/adt/core/discovery",
                 timeout=5, auth=None)
if r.status_code == 200 and b"<atom:category" in r.content:
    yield finding("ADT discovery anonymous", extras={"services": parse_atom(r.text)})
```

Leaks service inventory + enables `/sap/bc/adt/system/*` probes.

### #7 — `/sap/monitoring/SystemInfo` + `/sap/monitoring/ComponentInfo` (Java)

First already in SAPMAP. Add ComponentInfo — full SC patch matrix:

```python
r = requests.get(f"http://{host}:{port}/sap/monitoring/ComponentInfo", timeout=5)
# Parse HTML table of support-package components → map each to CVEs
```

### #8 — SAP Host Agent anonymous SOAP

```python
body = """<?xml version="1.0"?><SOAP-ENV:Envelope ...>
 <ns1:GetVersionInfo xmlns:ns1="urn:SAPControl"/></SOAP-ENV:Envelope>"""
r = requests.post(f"http://{host}:1128/SAPHostControl", data=body,
                  headers={'SOAPAction':'""'}, timeout=5)
if b'<item>' in r.content:
    # also: GetCurrentInstance, ListInstances, ParameterValue, GetEnvironment, ListLogFiles
    yield finding("SAP Host Agent anonymous SAPControl methods")
```

Same for 5<NN>13/5<NN>14 on each instance. Anonymous methods expose instance list, envs, params → feeds graph.

### #9 — `/sap/public/myssocntl` SSO config

```python
r = requests.get(f"http://{host}:{port}/sap/public/myssocntl", timeout=5)
if r.status_code == 200 and b'<sso' in r.content.lower():
    yield finding("SSO config leaked — Note 1417568")
```

### #10 — Timing-based `/sap/bc/gui/sap/its/webgui` user enumeration (safe, 1-shot)

For each default user:

```python
t0 = time.perf_counter()
r = requests.get(f"http://{host}:{port}/sap/bc/gui/sap/its/webgui",
                 auth=(user, 'xxxxxxxxxxxxxxxxxxxx'),
                 params={'sap-client': client}, timeout=5)
dt = time.perf_counter() - t0
# baseline: one probe with known-nonexistent 'SAPMAP_CANARY_XXYZ'
# if dt > baseline + 120ms → user likely exists; do NOT retry.
```

Emits one finding per probable-existing user without exceeding 1 lockout slot.

---

### Implementation notes

- Checks #1, #3 are **pure-computation** after existing ICM probe — filters on data SAPMAP already collects.
- Checks #2, #5, #6, #7, #8, #9 are each a single HTTP request; fit `sap_router_info.py` / `sap_ms_betrusted.py` pattern; <50 lines each.
- Check #4 extends existing MS module with two URLs.
- Check #10 needs per-target rate-limit and canary baseline; 80% of code is careful state tracking to avoid lockouts.

Collectively: **one unauth HTTP scan pass** = system fingerprint + RECON exposure + ICMAD likelihood + MS app-server list + user-enum baseline + ADT service inventory + Java component matrix + Host Agent inventory + SSO config leak + validated list of likely-existing users — **before a single credential is tried.**
