# SAP SSO Ticket Forging & Trust-Relationship Abuse

Research agent: "SSO / Trust / ticket-based lateral movement"

SAPMAP already: reads ABAP SecStore (RSECTAB), reads Java SecStore
(SecStoreFS + J2EE_CONFIGENTRY), walks JCo destinations + plots RFC
edges, creates SAPMAP00 via BAPI with SAP_ALL when RFC access exists.

---

## 1. MYSAPSSO2 — SAP Logon Ticket Forgery

### 1.1 Wire format and crypto structure

**MYSAPSSO2 cookie** = Base64-encoded PKCS#7 SignedData (+ optionally EnvelopedData) wrapping proprietary SAP-ticket payload:

```
MYSAPSSO2 = Base64( ticketHeader || PKCS7_SignedData( infoUnitList ) )
```

**ticketHeader** (8 bytes):
- `codeVersion` (1 byte, normally `0x02`)
- `length` (2 bytes, big-endian)
- Followed by list of **InfoUnits** (TLV: 1-byte ID, 2-byte length, value).

**InfoUnit IDs** (from `ssoext.c` and pysap):
- `0x01` = user id (SAP user name)
- `0x02` = issuing client (MANDT)
- `0x03` = issuing system (SYSID)
- `0x04` = creation time (YYYYMMDDhhmmss, ASCII)
- `0x05` = valid time (minutes, 4-byte int)
- `0x06` = RFC flag
- `0x07` = auth scheme (`default`, `basic`, `x509`)
- `0x08` = portal data
- `0x09` = language
- `0x0A` = recipient client / system (optional, for recipient-aware tickets)
- `0xFF` = signature (CMS/PKCS#7 SignedData over preceding ticket body)

**Signature InfoUnit (0xFF)** — CMS SignedData (RFC 5652):
- `digestAlgorithm` = usually `sha256` (older: `sha1` / `md5`)
- `signatureAlgorithm` = `rsaEncryption`
- `signerInfos.sid` = issuer DN + serial from system's own PSE certificate (`CN=<SID>, OU=J2EE, O=SAP Trust Community, C=DE`)
- `encapContentInfo` = reference only; signed data is ticket body.

### 1.2 Signing key location

Signing by **SSF layer** (Secure Store & Forward) calling CommonCryptoLib (`libsapcrypto.so` / `sapcrypto.dll`). Key material in **system PSE**:

- **ABAP system**: `SAPSYS.pse` in `$(DIR_INSTANCE)/sec/` — i.e. `/usr/sap/<SID>/D<NN>/sec/SAPSYS.pse`. STRUST calls this **"System PSE"**. Signing cert subject used as `issuerDN` in ticket's CMS SignerInfo.
- **Java system (AS Java)**: **ticketKeystore** view, persisted to `/usr/sap/<SID>/<INSTANCE>/sec/TicketKeystore`. Key alias `SAPLogonTicketKeypair` (historically `SAPLogonTicketKeypair-cert`).
- **Cred file** to open PSE non-interactively: **`cred_v2`** in same `sec/` dir, encrypted with key derived from `<sid>adm`'s credentials. SAP Notes 1525059 (cred_v2 format), 441946 (SSO ticket basics).

### 1.3 Key extraction for offline forgery

**Yes, key can be lifted with OS exec as `<sid>adm`.** PSE is encrypted PKCS#12-like container with passphrase stored in `cred_v2`, readable by `<sid>adm`:

1. Read `/usr/sap/<SID>/<INST>/sec/cred_v2` and `SAPSYS.pse`.
2. Either:
   - `sapgenpse open_pse -p SAPSYS.pse` on target (derives passphrase from cred_v2 automatically as `<sid>adm`), or
   - **pysap** `pysap.SAPCredv2` parser (supports LPS off / LPS FILE / LPS DPAPI) recovers PSE passphrase offline, parse PKCS#12 with OpenSSL / `cryptography`.
3. Once RSA private key is held, sign **arbitrary MYSAPSSO2 tickets** with whatever user/SYSID/client InfoUnits. No per-ticket server nonce; tickets are self-contained.

**Community implementations:**

- **pysap** (SecureAuth, formerly CoreSecurity) — `pysap/SAPSSFS.py`, `pysap/SAPCredv2.py`, `pysap/SAPLPS.py`. Parses and partially generates SSO2 tickets.
- **tijme/sapncs** — NCS/RFC parser, includes ticket-structure notes.
- **sansaninc/SAPSSOScanner** — scans portals for weak ticket config.
- **brsdncr/SAPFrog** — general SAP recon.
- Martin Gallo's BlackHat EU 2012 **"Uncovering SAP vulnerabilities"** and OPCDE/Troopers follow-ups demonstrate `build_sso_ticket()`.

**No clean one-shot public `build_mysapsso2()`** in stock pysap — assemble InfoUnits and call `pysap.utils.crypto.pkcs7_sign()` with PSE key. ~60 lines Python.

### 1.4 Trust (STRUSTSSO2)

- **STRUSTSSO2** manages trusted issuer list. Each entry = X.509 cert of issuing system's SAPSYS PSE + tuple `(SYSID, CLIENT)` receiver will accept in InfoUnits 0x02/0x03.
- Setup = **public-key exchange**: export `SAPSYS.pse` cert from B, import on A (and vice versa if mutual). Pure public-key; no shared secret.
- SAP Notes: **612670**, **1043694**, **2338952** (SHA-256), **701205** (multiple issuers), **1532825** (WebDynpro).

### 1.5 Lateral-movement chain

RCE system A, system B has imported A's SAPSYS cert in STRUSTSSO2 → with A's SAPSYS private key forge MYSAPSSO2 claiming `(user=ANY, sysid=A, client=<A-client>)` that B accepts as valid logon — provided user exists on B (or mapped via USREXTID). No shared secret needed.

Full chain:

1. 10KBLAZE / gw RCE on A as `<sid>adm`.
2. Dump `SAPSYS.pse` + `cred_v2`, extract RSA key offline via pysap.
3. Read STRUSTSSO2 entries on A — but STRUSTSSO2 stores **inbound** trusted issuers only. For **outbound** targets (systems trusting A), enumerate B systems by reading SM59 RFC destinations, TMS topology (DC knows full system list), CUA child table `USZBVLNDRCV`.
4. Forge ticket for `user=DDIC, client=000, sysid=A`.
5. Present cookie to B on `/sap/bc/gui/sap/its/webgui` or any HTTP-enabled handler; B validates signature against A's cert in STRUSTSSO2, logs you in as DDIC on B.

---

## 2. SAP Assertion Tickets

- Close cousin of MYSAPSSO2 but **one-time / short-lived** (default 2 min). Carried in HTTP header `MYSAPSSO2` or over RFC as credential on `RFC_AUTHORITY_CHECK`-equivalent callback.
- **Same PKCS#7-signed InfoUnit blob** with `authScheme=assertion` (InfoUnit 0x07) and recipient pinned via InfoUnit 0x0A (`RECIPIENT_CLIENT` / `RECIPIENT_SYSID`).
- Generation: `SSFC_ISSUE_ASSERTION_TICKET`. Validation: `SSFC_EVALUATE_TICKET`.
- Same signing key (SAPSYS PSE). Same CommonCryptoLib path (`SsfSign` / `SsfVerify`). Forging works identically — set recipient pair + `authScheme=assertion`.
- Trust: STRUSTSSO2 (same table, same cert).
- SAP Notes: **1327797**, **1352008** (SHA-256 upgrade).

---

## 3. SAP Kerberos / SPNEGO

- SPNEGO login module (AS Java `com.sap.security.core.server.jaas.SPNegoLoginModule`, AS ABAP via `SNC_LIB=sapcrypto` + SPNego) consumes standard Kerberos AP-REQ.
- Forging = standard AD attacks:
  - Domain admin → **Golden ticket** against SAP service account's SPN (`SAP/<hostname>` or `HTTP/<hostname>`).
  - Compromise SAP machine account or SPN service account → **Silver ticket** for that SPN.
  - **S4U2self / S4U2proxy** if SAP service account has unconstrained or constrained delegation (often set for SSO-to-backend).
- No PSE/SSF key involved; sapcrypto wraps GSSAPI. `gsskrb5.dll` / `libgsskrb5.so` in CommonCryptoLib. Keytab (if deployed) at `/usr/sap/<SID>/<INST>/sec/krb5.keytab` or pulled from machine account.
- Tools: **Rubeus** (silver/golden), **mimikatz** `kerberos::golden`. No SAP-specific tool needed.
- SAP Notes: **1488409**, **1725390**, **2884906** (SPNego 2.0).

---

## 4. RFC Trust — trusted_system_table / RFCDES / SMT1/SMT2

### 4.1 What the trust is

- **Type 3 / Type H** RFC destinations with **"Trusted System"** flag (SM59 → Logon & Security → "Current User" + "Trusted System = Yes") use **assertion-ticket callback**: when A calls `CALL FUNCTION ... DESTINATION 'TO_B'`, caller's SYSID/client/user/timestamp packed into assertion ticket signed by A's SAPSYS PSE, sent over RFC. B validates against STRUSTSSO2; if user exists with SM59 ACL (SMT1/SMT2 or table `RFCTRUST`), logs in as that user **with no password**.
- ACL table on B: **`RFCSYSACL`** (via SMT1). Columns: `RFCSYSID`, `RFCCLIENT`, `RFCDEST`, `RFCTCODE`, `RFCUSER`, `RFCSNC`, `RFCEQUSER`. **`RFCEQUSER = 'Y'` = any user from A can log in as same-named user on B.** The juicy one.
- SAP Notes: **128447** (classic), **2008727** (hardening), **3089413**, **3273480** (CVE-2022-27668 / 2020-6287-adjacent — TRFC privilege escalation), **3089413 / 3304520 / CVE-2024-33006**-adjacent (trusted-RFC tightening).

### 4.2 Exploitation paths from SAPMAP's foothold

Given SAPMAP has SAP_ALL on A:

- **No PSE extraction needed** — call `CALL FUNCTION 'BAPI_USER_CREATE1' DESTINATION 'TO_B'` from ABAP; kernel generates assertion ticket. If B's RFCSYSACL says `RFCEQUSER=Y` for A's SYSID and user on A matches high-priv user on B → in.
- If `RFCEQUSER=N` and entries user-specific, read **`RFCSYSACL`** on B (via reverse destination if exists; otherwise forge ticket per §1.5 and read). Then create local user on A with that name, log in as it, call through.
- **Reading trusted destinations on A**: table **`RFCDES`** (content base64-encoded, passwords blown out unless special rights — but flags telling you destination is **trusted** and **without stored password** are in clear). Table **`RFCATTRIB`** has trusted-system flag. Table **`RFCCHECK`** holds per-destination callback certs.
- **Bidirectional trust discovery**: A's `RFCDES` = **outbound** trust (who A calls); B's `RFCSYSACL` = **inbound** trust (who B accepts from). For mapping, want both.

### 4.3 HTTP "Trusted" RFC via `/sap/bc/srt/`

- Same model for **SOAP/HTTP** endpoints. Client sends X.509 client certificate matching its SAPSYS cert; server validates via STRUSTSSO2 / `/sap/bc/sec/` anchors.
- Attackers with SAPSYS private key can present it in TLS client auth to trusting system's `/sap/bc/srt/rfc/sap/<fm-name>?sap-client=<n>`. SOAP body = function-module call. Logged in **ICM_HTTPS_CLIENT_AUTH** trace.
- Path: `/sap/bc/srt/rfc/sap/bapi_user_create1?sap-client=100` etc.

---

## 5. SAP Passport header forwarding

- **SAP Passport** (`SAP-PASSPORT` header) is **distributed tracing**, not auth in modern kernels (>= 7.40). Carries correlation ID, component, action, user.
- **Forgery has limited auth impact** in modern but on older 6.x/7.0x AS Java + PI, some custom modules trusted passport's `UserID` field for authz. Still seen in old PI / XI adapters / custom BSP apps.
- Format: ASN.1 DER. Not signed. Spoofing trivial — set the header. Detection: ICM trace logs originating IP.
- SAP Notes: **1273602**, **1318906** — discuss as trace only.

---

## 6. File locations & offline decryption

Full path list:

| File | Purpose | Passphrase |
|---|---|---|
| `/usr/sap/<SID>/<INST>/sec/SAPSYS.pse` | Signs MYSAPSSO2, assertion tickets, trusted-RFC callbacks | `cred_v2` same dir |
| `/usr/sap/<SID>/<INST>/sec/SAPSSLS.pse` | TLS server cert for ICM HTTPS | `cred_v2` |
| `/usr/sap/<SID>/<INST>/sec/SAPSSLC.pse` | TLS client cert for outbound HTTPS (trusted HTTP RFC) | `cred_v2` |
| `/usr/sap/<SID>/<INST>/sec/SAPSNCS.pse` | SNC (Kerberos/X.509 over RFC) | `cred_v2` |
| `/usr/sap/<SID>/<INST>/sec/cred_v2` | Encrypted PIN store — wraps all above | `<sid>adm` OS creds (DPAPI on Win, KDF on Unix) |
| `/usr/sap/<SID>/SYS/global/security/data/SecStore.properties` | Java SecStore master-key ref | `SecStore.key` + OS acct |
| `/usr/sap/<SID>/SYS/global/security/data/SecStore.key` | Java SecStore key | Java keystore pass, sometimes default `sapsap` |
| `/usr/sap/<SID>/<INST>/sec/TicketKeystore` (Java) | Java logon-ticket signer | ConfigTool master pwd |
| `/usr/sap/<SID>/<INST>/j2ee/configtool/*keystore*` | ConfigTool master | Default pwd or ConfigTool.bat pass |
| `/usr/sap/<SID>/<INST>/work/sec/` | Runtime copies (rare, mostly empty) | same |
| `%ProgramFiles%\SAP\SAP_JVM\sapjvm*\lib\security\cacerts` | Java trust store for JCo | default `changeit` |

**Offline decryption tools:**

- **pysap** (`pysap.SAPCredv2`, `pysap.SAPPSE`, `pysap.SAPLPS`) — handles LPS OFF/FILE/DPAPI.
- **SAPSSFS / saparc** — old Perl scripts, limited.
- **SecureAuth/pysap** fork — best-maintained PSE parser.
- **Joris van der Schot's "SAPCredExtract"** (`joostjansen/sapcredv2`) — pysap helper.
- **sansaninc / HackingSAP** writeups by Yvan Genuer (Onapsis) show full OpenSSL path after pysap prints recovered PIN: `openssl pkcs12 -in SAPSYS.pse -passin pass:<pin>`.

**SAP kernel NOT required** — PSE is PKCS#12 with SAP-specific PBE variant handled by pysap.

---

## 7. Cross-landscape trust: TMS, CUA, SolMan

- **TMS (Transport Management System)**: domain controller has RFC destinations `TMSADM@<SID>.DOMAIN_<DC>` to every member. TMSADM exists on every system with default `PASSWORD` / `$1Pawd2&` (Note **1414256**). Compromise TMS DC → RFC trust to every member. TMS doesn't auto-create STRUSTSSO2 trust but does create trusted-RFC entries in `RFCSYSACL`.
- **CUA (Central User Administration)**: CUA master has **outbound** trusted RFC to every child (dest `<SID>CLNT<CLIENT>`), child has **inbound** trusted RFC to master (dest `CUA` or `ZCUA`). Tables: `USZBVLNDRCV` (children on master), `USZBVSYS` (master on child). Compromising CUA master owns every child.
- **Solution Manager**: `SM_<SID>CLNT<CLIENT>_READ`/`_TRUSTED`/`_BACK` destinations. SolMan has trusted RFC to **every managed system**, often with SAP_ALL-equivalent user `SOLMAN_BTC` / `SMD_RFC`. **Single best lateral-movement hub in most estates.**
- **STMS parallel to STRUSTSSO2**: TMS creates entries in `TMSCDOM`, `TMSSYS`, `TMSCSYS`, `TMSMCONF` — edges SAPMAP should plot.

---

## 8. SAML 2.0 IdP forging

- AS Java as **SAML 2.0 IdP** (transaction SAML2 on ABAP; NWA → Security → SAML 2.0 on Java) stores IdP signing key in **Java keystore view `SAMLServiceProvider`** or `SAML2IdP` — Java KeyStorage persisted to DB + local cache.
- ABAP IdP (AS ABAP >= 7.4): signing key is PSE in STRUST under node **"SAML 2.0"**. Path: `/usr/sap/<SID>/<INST>/sec/SAML2_IdP.pse` (or DB table `STRUSTCRYPT`).
- OS RCE + SAML IdP PSE → forge **SAML Response** assertions for any `NameID`, signed validly. SPs trusting the IdP accept — attacks **federated** apps (Fiori Launchpad, Concur, Ariba, SuccessFactors, Azure AD federation).
- Tools: **python3-saml**, **SAMLRaider**, **SAML Breaker**. Once RSA key owned, signing SAML assertion is trivial.
- SAP Notes: **1254821**, **2671160**, **1513614**.

---

## 9. GW_CALL_BACK / asynchronous callback abuse

- Gateway callback (`CALL FUNCTION ... STARTING NEW TASK ... PERFORMING <form> ON END OF TASK`) lets B call back into A's calling session. Auth uses existing RFC session cookie; callback bypasses `reg_info`/`sec_info` (gateway considers it part of existing conversation).
- **CVE-2019-0330** and older **"RFC callback"** class (SAP Note **2321818**): malicious B calls arbitrary FMs on A as calling user. Defense: `rfc/callback_security_method` + callback whitelist (table `RFCCBWHITELIST`).
- **Abuse for SAPMAP**: RCE low-value B with inbound RFCs from high-value A, callback whitelisting disabled on A → **pull** A into executing function modules for you — reverse trust flow. Real edge type: "callback-reachable from B".
- OMEX / qRFC / bgRFC use similar callback semantics.

---

## Detection artifacts

| Action | Artifact |
|---|---|
| MYSAPSSO2 issued | SM20 event **AU5** "Logon successful (Type=S for SSO ticket)", `SLOGSEQ`, SAL message **AUO** |
| Assertion ticket used | SM20 event **AU6**, kernel trace `dev_w*` SsfVerify entries |
| Trusted RFC logon | SM20 **AUK / AUW** "RFC logon by trusted system", field `RFCSYSID` populated |
| SAML assertion accepted (SP) | SM20 **AUZ**, table `SAML2_CTX` |
| PSE read on filesystem | OS auditd `open(SAPSYS.pse)`, typically no SAP-side log |
| sapgenpse usage | no SAP log; only `<sid>adm` shell history |
| SPNego logon | SM20 AU1 with `AUTH=SPNEGO` |

**Relevant CVEs:**

- **CVE-2020-6287** (RECON) — AS Java config user creation (related but not trust-forge)
- **CVE-2019-0330** — OSCommand via RFC callback
- **CVE-2022-27668** — trusted-RFC auth bypass
- **CVE-2021-33677 / 33684** — SAML assertion spoofing in NetWeaver
- **CVE-2018-2368** — SsfVerify bypass in CommonCryptoLib (pre-patch: forge without valid key!)
- **CVE-2017-8918** — Logon ticket validation missing signature check in some PI scenarios

---

## SAPMAP integration per technique

| Technique | Integration |
|---|---|
| MYSAPSSO2 forge | **New menu action** "Forge SSO Ticket" — inputs: target SID/client/user, PSE file. Uses pysap offline. New **credential type** `SSO_TICKET`. New **edge type** `TRUSTS_ISSUER` (B → A, read from STRUSTSSO2). |
| Assertion ticket forge | Sub-case of MYSAPSSO2 menu — toggle "assertion" + recipient pinning. |
| Trusted RFC hop | **New edge type** `TRUSTED_RFC` (A → B, from `RFCDES`+`RFCATTRIB` on A) + `TRUSTS_RFC_FROM` (B → A, from `RFCSYSACL` on B). New action "Hop via trusted RFC" — `CALL FUNCTION` over JCo with `trustedSystem=1`. No password. |
| TMS trust | **New edge type** `TMS_DOMAIN_MEMBER` (DC → member) from `TMSCDOM`/`TMSSYS` on DC. |
| CUA trust | **New edge type** `CUA_CHILD_OF` from `USZBVLNDRCV`/`USZBVSYS`. |
| SolMan trust | **New edge type** `MANAGED_BY_SOLMAN` from `DIAGLS_MANAGED_SYS` + destinations `SM_*` on managed side. |
| SAML IdP forge | **New credential type** `SAML_IDP_KEY`. New action "Forge SAML Assertion". New **edge type** `SAML_TRUSTS`. |
| Kerberos / SPNego | Edge `SPNEGO_TRUSTS_AD` + NODE metadata; out-of-band (Rubeus). |
| PSE extraction | **New action** "Extract PSE keys" — runs on OS-compromised node, drops into local store, invokes pysap Cred/PSE decoders. **New credential type** `PSE_PRIVATE_KEY`. |
| Callback abuse | **New edge type** `CALLBACK_REACHABLE` (probe A for `rfc/callback_security_method` and `RFCCBWHITELIST`). |
| SAP Passport | Low priority; informational edge only on old PI. |

---

## Top 3 lateral-movement additions

Ranked by **incremental mapping benefit**:

### #1 — Trusted-RFC hop (edges `TRUSTED_RFC` + `TRUSTS_RFC_FROM`, action "Hop via Trusted RFC")

- **Highest ROI**: real SAP estate has dozens of trusted-RFC destinations (TMS, CUA, SolMan, custom). No PSE extraction, no crypto — `CALL FUNCTION ... DESTINATION` with `trustedSystem=1`. JCo supports via `jco.client.trusted=1`.
- **Data needed**: A's `RFCDES + RFCATTRIB` for outbound trusted destinations; B's `RFCSYSACL` for further forward trust.
- **Prereqs**: SAP_ALL (or `S_RFC` for target FM) on A; matching user must exist on B OR `RFCEQUSER=Y`.
- **Detection**: SM20 AUK on B, but SAPMAP's edges dramatically richer.

### #2 — MYSAPSSO2 / Assertion-ticket forge with extracted SAPSYS PSE

- **Why #2**: needs OS RCE (have via 10KBLAZE on W74/TWT); once key owned, reach **every** STRUSTSSO2-trusting system — crosses firewall / landscape boundaries RFC trust doesn't.
- **Pipeline**: 10KBLAZE-SAPXPG on A → read `SAPSYS.pse` + `cred_v2` → pysap decode offline → forge ticket → present to B's `/sap/bc/gui/sap/its/webgui` with `MYSAPSSO2=<blob>` cookie.
- **New credential** `PSE_PRIVATE_KEY` persists extracted RSA key tied to issuer cert; **new edge** `TRUSTS_ISSUER` sourced by reading STRUSTSSO2 (`SSF_PSE_APPLIC`, `USRACL`, `STRUSTCRYPT`) on every mapped system.
- Single primitive collapses most STRUSTSSO2 landscapes to one-hop reachable.

### #3 — SolMan / CUA / TMS trust-hub enumeration as first-class edges

- **Why #3**: high-fanout nodes. Compromised SolMan = every managed system owned. SAPMAP should **colour** SolMan/CUA/TMS DC nodes distinctly, pre-populate outbound edges to all managed/child/domain-member systems, and **automatically attempt** trusted-RFC hop when destinations present. Even if #1 handles mechanics, recognising these hubs specifically lets SAPMAP prioritise them in shortest-path calculations.
- Tables: `DIAGLS_MANAGED_SYS` / `SMSY_SYSTEM`, `USZBVLNDRCV`, `TMSCDOM`, `TMSSYS`, `TMSMCONF`.

---

Implementing these three turns a single 10KBLAZE OS RCE into a fully-plotted graph of **every** system reachable without ever needing a stored password.
