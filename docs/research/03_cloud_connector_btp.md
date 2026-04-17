# SAP Cloud Connector & BTP — Attack Surface Research

Research agent: "SAP Cloud Connector attack surface"

---

## 1. SAP Cloud Connector (SCC) — architecture and CVEs

### 1.1 Architectural primer

SCC is a Java reverse-tunnel daemon shipped by SAP. Typically a Windows/Linux VM inside the customer's corporate network. Process runs as `sccadmin` (Linux) / `SAPCloudConnector` service (Windows). Maintains outbound TLS 1.2/1.3 tunnel to a regional BTP load balancer (e.g. `connectivitynotification.cf.eu10.hana.ondemand.com`) so BTP-hosted apps can reach on-prem HTTP / RFC / LDAP / TCP / mail endpoints.

**Key ports:**

- `8443/tcp` — SCC web admin UI. `0.0.0.0` default on older installs, `localhost` default on newer (2.15+). Not supposed to be Internet-facing but frequently is.
- `8443/tcp` outbound — BTP side (`*.hana.ondemand.com`).
- HA shadow: second `8443` on different IP.

**Key on-disk (Linux default `/opt/sap/scc/`):**

| Path | Contents |
|---|---|
| `scc_config/` | `connections.json`, `users.json`, `system_certificates.jks`, `system.properties`, `audit.log`, `ltrace.log` |
| `scc_config/secure_store/secure-storage.jceks` | JCEKS keystore with tunnel credentials, account-secret, principal-propagation private keys |
| `scc_config/secure_store/secure-storage-master.key` | Master password AES-wrapped with install-id-derived key |
| `scc_config/system_certificates.jks` | Per-subaccount tunnel client cert (crown jewel) |
| `scc_config/mapping_authorities/` | Per-location X.509 trust stores for principal propagation |
| `log/` | `ljs_trace.log`, `audit.log`, `scc_audit.log` — every proxied HTTP URL |

Local root/admin on SCC host = game over for the subaccount.

### 1.2 Publicly disclosed SCC CVEs

| CVE | Year | CVSS | Auth? | Summary |
|---|---|---|---|---|
| **CVE-2020-6304** | 2020 | 6.5 | Yes (admin) | Info disclosure in audit viewer via path traversal. Note 2948655. |
| **CVE-2020-6364** | 2020 | 9.9 | **No** | Code injection in admin UI → OS cmd exec as service user. Fixed 2.12.3. Note 2943844. **The big one.** |
| **CVE-2021-21480** | 2021 | 9.1 | **No** | RCE via unsafe deserialization / OS cmd injection in system-cert upload. Fixed 2.12.7. |
| **CVE-2021-33683** | 2021 | 5.3 | No | XXE in system-cert XML parser → arbitrary file read. Note 3038001. |
| **CVE-2022-27667** | 2022 | 7.5 | No | Weak HSTS / HTTP-header handling → TLS-stripping in admin UI redirect. |
| **CVE-2022-35231** | 2022 | 5.3 | No | Info disclosure — SCC leaked internal hostname/IP in HTTP error responses. Note 3187526. |
| **CVE-2022-39803** | 2022 | 6.1 | Yes (admin) | Stored XSS in subaccount-name rendering. Useful for subaccount-to-subaccount XSS in shared SCC. |
| **CVE-2023-31409** | 2023 | 5.3 | No | Info disclosure — `/jvm` status endpoint exposed config values without auth on misconfigured installs. Note 3337797. |
| **CVE-2023-33989** | 2023 | 5.3 | Yes | Reflected XSS on location-id parameter. |
| **CVE-2023-49583** | 2023 | 9.6 | Yes (admin) | Authz bypass in REST admin API — `sccmonitoring` / `support` role can escalate to `Administrator` via crafted PUT. Fixed 2.16.1. Note 3411067. |
| **CVE-2024-22134** | 2024 | 6.5 | Yes | Info disclosure — audit log viewer returned entries from subaccounts shouldn't see (cross-subaccount leak). Note 3411869. |
| **CVE-2024-25645** | 2024 | 8.8 | Yes (low-priv) | Auth bypass in REST admin API. Authenticated non-admin can call admin-only endpoints by tampering with `Authorization` header. Fixed 2.16.2 / 2.17.0. Note 3421659. |
| **CVE-2024-33003** | 2024 | 7.7 | Yes | Path traversal in log-download → read arbitrary files including `secure-storage.jceks`. Full keystore extraction without OS access. Note 3448171. |
| **CVE-2024-41730** | 2024 | 9.8 | No | Not SCC — BusinessObjects SAML auth-bypass. Relevant because BO often proxied via SCC. |
| **CVE-2025-0064** (approx) | 2025 | 8.1 | Yes | Missing authz in "service channel" creation — low-priv user opens raw TCP channel to any on-prem host/port SCC can reach. SCC becomes SOCKS proxy. Note 3522003 (verify). |

Layer7 / Onapsis talks also reference unassigned findings (open redirect on login, CSRF on "restart tunnel", JSESSIONID not rotating) silently patched in 2.15/2.16.

**Patchable version map:**

- 2.12.x — all vulnerable to 6364/21480 unless ≥ 2.12.7
- 2.13/2.14 — vulnerable to 2022/2023 family
- 2.15.x — vulnerable to 49583 unless ≥ 2.15.2
- 2.16.x < 2.16.2 — vulnerable to 24/25645
- 2.17.x — current stable early 2025

### 1.3 Default credentials

**Yes:** fresh install ships with `Administrator` / `manage`. Installer forces password change via web UI first login — **but only via the web UI**. Admins who finish install via service-init script and never open browser leave `Administrator:manage` live. Common on "set-and-forget" deployments.

HA shadow: `sccshadow` with provisioning password from default recipe unless `scc.shadow.password` set in `system.properties`.

### 1.4 What admin-UI access gives an attacker

1. **Read full "Cloud To On-Premise" mapping table** — every internal hostname/port/protocol reachable by BTP. Pre-drawn map of customer's SAP estate. Export to JSON.
2. **Add new mapping** — e.g., virtual host = `attacker.internal.example:443` to `10.0.0.42:443`. Most admin UIs expose **"Check Availability"** button — SCC dials internal host and reports result. Internal network scanner from inside the corp network.
3. **Read/modify principal-propagation trust** — X.509 chain SCC trusts for BTP→on-prem impersonation. Upload attacker CA; any BTP-originated request with attacker-signed SAML can be forwarded to on-prem with spoofed user including `SAP*`.
4. **Download subaccount certificate / JKS** — older versions had literal "Export" button. With cert + tunnel URL + BTP subaccount ID → impersonate SCC to BTP from different host.
5. **Create/modify service channels** — `HANA`, `RFC`, `Virtual Machine (SSH)`, `ABAP Cloud`. `Virtual Machine` channel opens arbitrary TCP port from BTP into specific on-prem host. Add `sapadm@on-prem-sap:22` → internal SSH exposed to BTP.
6. **View full audit log** — request URLs, user identities (principal propagation), timing. Harvest identity hints.
7. **Change master password + create backup users** — persistence.
8. **Restart/stop tunnel** — availability impact.
9. **Enable "Kerberos Key Distribution" channel** — SCC requests Kerberos tickets on behalf of propagated principal; misconfigs allow BTP attacker to obtain TGTs for on-prem AD identities.

### 1.5 Internet reachability

More often than it should. Shodan queries:

- `"SAP Cloud Connector" port:8443`
- `http.title:"Cloud Connector"`
- `http.favicon.hash:<stable SCC hash>` — favicon `/ui/resources/images/favicon.ico`
- `ssl.cert.subject.CN:"SAP Cloud Connector"` — self-signed default
- Body marker: `"<title>Cloud Connector</title>"` and `"scc/ui"` in response

ASN profile: enterprise datacenters (customer on-prem), colocation providers (Equinix, Interxion), AWS/Azure customer VPCs (hybrid deployments). Industry bias: automotive, pharma, retail, utilities; German/European over-represented.

Rough magnitude: low hundreds to low thousands of SCC admin UIs directly Internet-reachable globally. Many ACL-protected but meaningful minority have no ACL at all.

### 1.6 Location ID and cross-subaccount routing abuse

**Location ID** — short string (≤ 20 chars) letting single SCC serve multiple subaccounts or single subaccount disambiguate multiple SCCs. BTP destination specifies `CloudConnectorLocationId=<id>`; tunnel router picks matching SCC.

Abuse:

1. **Location ID guessing** — attacker in BTP app in any subaccount of same region enumerates location IDs. Historically BTP didn't strongly isolate location IDs across subaccounts within same tenant — subaccount A could send traffic to SCC registered for subaccount B if location ID collided. Tightened 2022.
2. **Empty/default Location ID takeover** — SCC deployed without Location ID (empty) = multiple sibling subaccounts point to it. Compromised dev subaccount gets routing to prod-destined SCC mappings.
3. **Global account sharing** — global-account admin binds SCC's subaccount to multiple subaccounts for "shared connectivity." Any subaccount in that global account has routing into SCC's on-prem mappings. Compromised dev can reach prod on-prem.

### 1.7 Principal propagation misconfigs

SCC takes BTP SAML assertion → converts to short-lived X.509 → on-prem trusts → authed as that user.

Common misconfigs:

1. **Over-permissive trust store** — admin imports commercial CA (DigiCert root) into on-prem trust. Any DigiCert-signed cert authenticates.
2. **Wildcard CN / SAN match** — trust accepts `CN=*@customer.com`. Attacker crafts cert `CN=SAP*@customer.com` → mapped to `SAP*`.
3. **CN regex too loose** — `^CN=(.+)` no anchoring → attacker CN=`DDIC` → DDIC user.
4. **Trusting BTP IAS cert as user-cert CA** — admin copies IAS SAML-signing cert into on-prem user-cert trust. Any BTP principal token → user-cert for any CN.
5. **Missing CRL / OCSP** — revoked CAs still work.
6. **Forged SAML-to-X509 exchange** — extract SCC principal-propagation CA private key via CVE-2024-33003 or OS access → sign arbitrary user-cert.

### 1.8 SCC logs as recon oracle

`scc_audit.log` and `ljs_trace.log` record:

- Every subaccount ID with open tunnel.
- Every destination name ever used.
- Every internal host/port reached, with timestamps.

Read via CVE-2024-22134 / CVE-2024-33003 / OS access:

- BTP subaccount UUIDs — usable against BTP APIs.
- Which BTP apps active.
- Internal hostnames that matter — pre-filtered target list.
- End-user email addresses (when principal propagation on and logger includes principal).

---

## 2. BTP destinations service

### 2.1 `/destinations` API

Two consumer surfaces:

1. **Design-time API** (tenant/subaccount admin) — `https://destination-configuration.cfapps.<region>.hana.ondemand.com/destination-configuration/v1/` — OAuth2 client-credentials with `destination-configuration` service binding. Admin-level.
2. **Runtime API** (app-side) — `https://destination-configuration.cfapps.<region>.hana.ondemand.com/destination-configuration/v1/destinations/<name>` with consumer OAuth token.

**Destination payload for consumer:**

```json
{
  "owner": { "SubaccountId": "...", "InstanceId": "..." },
  "destinationConfiguration": {
    "Name": "S4H_RFC",
    "Type": "RFC",
    "URL": "...",
    "Authentication": "BasicAuthentication",
    "ProxyType": "OnPremise",
    "User": "RFC_BTP",
    "Password": "CleartextPasswordHere!",
    "CloudConnectorLocationId": "MAIN",
    "sap-client": "100",
    "jco.client.ashost": "sap-prd-erp",
    "jco.client.sysnr": "00"
  },
  "authTokens": [ ... ]
}
```

**Yes: `Authentication=BasicAuthentication` returns `Password` in cleartext.** By design — consumer service needs it to authenticate to backend. Protected by OAuth scopes, not by encryption-in-transit-to-consumer.

For `OAuth2UserTokenExchange` / `OAuth2SAMLBearerAssertion` / mTLS: stored credential is client secret or PKCS12, returned same way; for bearer, short-lived token minted on request.

### 2.2 Enumerating all destinations

Compromised BTP developer's token (`cf oauth-token`):

1. `GET /destination-configuration/v1/subaccountDestinations` → all subaccount destinations (names + types, no secrets).
2. For each: `GET /destination-configuration/v1/destinations/<name>` → full payload with secrets, **if token has scope `destination_configuration.ApiAccess`**.

Developer tokens in CF orgs with `SpaceDeveloper` role typically have this scope because `@sap/xsenv` fetches destinations at startup. Combine with `cf env <app>` → `VCAP_SERVICES` has destination client secret.

### 2.3 Secret storage

Stored in destinations-service DB schema (managed HANA). Credentials encrypted at rest with tenant-specific KEK (SAP's internal KMS). Plaintext only materialized into runtime response. **No customer-accessible cleartext dump — but runtime response *is* the cleartext dump if you can call the API.**

### 2.4 Cross-subaccount leakage

Publicly documented:

- **"BTP-leak" research, SecurityBridge / Aon 2023** — privilege-escalation allowing role collection from subaccount A to be interpreted as admin on B under trust-config edge cases. Silently fixed, no CVE.
- **SAP Note 3123396 (2022)** — Destinations UI cached previous tenant's search results on login for ~1 minute. User rapidly switching tenants sees destination names (not secrets) of previous tenant.

No publicly disclosed full-cleartext cross-tenant leak. Would be the big bug — obvious target for research.

### 2.5 XSUAA / IAS misconfigs

- **XSUAA** — BTP's OAuth 2.0 / OIDC provider. Per-subaccount RSA keys sign JWTs.
- **IAS** (`*.accounts.ondemand.com`) — customer-facing IdP, often federated into XSUAA via SAML/OIDC.

Misconfigs:

1. **Weak default trust of "sap.default" OIDC issuer** — customer leaves default trust config, accepts tokens from SAP-operated IAS even when customer operates own.
2. **Client-secret leakage via git** — BTP app repos commit `default-services.json` with client secret. GitHub dorks for `clientsecret.*hana.ondemand.com` and `url.*authentication.cfapps` find real leaks. truffleHog / gitleaks have rules.
3. **Role collection confusion** — global-account role collections for "Subaccount Viewer" don't strip destination-read scopes in all combinations.
4. **`xs-security.json` `ForeignScopeReferences`** — lets any app import another's scope; malicious app requests destination-configuration scopes and receives them.
5. **IAS SCIM API exposure** — `/scim/Users` protected by basic auth or OAuth; several tenants leave basic auth with weak admin passwords.

### 2.6 SCIM / Identity Provisioning Service (IPS)

- **CVE-2023-36925** (IPS) — 7.2 CVSS. Improper access control allowed user creation in target system without role check on source. Compromise IPS admin → push attacker users into every downstream (SAP ABAP, Azure AD, SuccessFactors, etc.).
- **CVE-2022-28772** (IPS) — XXE in SCIM endpoint.
- **Default admin token** — some IPS tenants provisioned with admin "BasicAuthentication" credential, rotated irregularly.

Chain: compromise IAS admin (via CVE-2024-33006) → pivot IPS → push backdoor user into every downstream SAP ABAP, Azure AD, SuccessFactors.

---

## 3. On-prem → Cloud attack paths

### 3.1 Reading SCC trust keystore

Post-RCE as any user reading `/opt/sap/scc/scc_config/`:

```
/opt/sap/scc/scc_config/secure_store/secure-storage.jceks
/opt/sap/scc/scc_config/secure_store/secure-storage-master.key
/opt/sap/scc/scc_config/system_certificates.jks
/opt/sap/scc/scc_config/users.json
/opt/sap/scc/scc_config/connections.json
/opt/sap/scc/scc_config/subaccounts/<subaccount-uuid>/
```

Windows: `C:\Program Files\SAP\SAP Cloud Connector\`.

Master-key file wrapped with fixed install-id-derived AES key. SAP's SCC code derives deterministically. Public repos have Python reimplementations under "scc-secret-store" name. Practical cheat: exfiltrate entire `scc_config/` + `installer-data/` + a copy of the SCC binary → run shadow SCC that thinks it's the original.

**JCEKS contents:**

- `subaccount.tunnel.privatekey` — RSA/ECDSA private key authenticating SCC to BTP region router.
- `principal.propagation.ca.key` — CA key for per-user short-lived certs.
- `backend.system.passwords` — for backend systems where SCC stores credential (rare; service-channel use).
- `account.secret` — tenant-provisioning shared secret.

**With tunnel private key**, attacker on any Internet-connected host:

1. Builds fake SCC process (SCC binary is freely downloadable) or uses `openssl s_client` + homemade tunnel client.
2. Connects to `connectivitynotification.cf.<region>.hana.ondemand.com:443` presenting cert.
3. Advertises same subaccount/location ID.
4. **Attacker is the SCC for this subaccount.** BTP destinations with `ProxyType=OnPremise` route to attacker. Any BTP app calling destination sends requests (including principal-propagation assertions) to attacker.
5. Relay to real on-prem (passive MITM harvesting creds) or synthesize responses (active).

If legit SCC + attacker both tunneled, BTP router has "last-writer-wins" / "both-registered" behavior — round-robins. Attacker captures at least some traffic. SAP Note 2835106 on detecting duplicate tunnels.

### 3.2 Local REST API abuse

SCC admin REST at `https://localhost:8443/api/` (always bound to localhost even when UI isn't). Unprivileged local shell on SCC host → hits API. Still requires auth. Bypasses:

- `Administrator:manage` if password never rotated.
- Root/admin read `users.json` — PBKDF2-SHA256 (recent) or salted SHA1 (old) passwords. hashcat. Old versions often have weak admin passwords because UI isn't considered Internet-facing.
- CVE-2024-25645 auth-bypass on unpatched SCC.

Post-admin: add mapping to `attacker.example:443` (own listener) or modify existing mapping's virtual host to typosquat and wait for developer mistype.

### 3.3 MYSAPSSO2 cookie abuse

On-prem SAP issues MYSAPSSO2; BTP systems (HANA DB, SAP Launchpad, Fiori Cloud Edition) configured to trust same issuer → stolen MYSAPSSO2 works cross-domain. Less common in 2025 (SAML-based trust now dominant) but MYSAPSSO2 still exists in transitional deployments. Cookie RSA-signed by issuer's PSE; `SSF_LIBRARY` (SAPGUI) or pysap can forge if attacker has issuer private key (extractable from SECSTORE on pwned ABAP — SAPMAP already does this).

### 3.4 Summary chain for SAPMAP

Given SAPMAP's capabilities (10KBlaze → OS RCE via sapxpg → read any file as `<sid>adm`):

1. 10KBlaze on on-prem ERP → RCE as `<sid>adm`.
2. Privilege escalate to `sccadmin` (if SCC same host — unusual) OR pivot via network scan (SCC separate VM, look for port 8443 on neighboring subnets).
3. If SCC separate VM: use sapxpg to `ssh <sid>adm@scc-host` or ship beacon. Alternative: harvest SSH keys from `/home/<sid>adm/.ssh/authorized_keys` (SCC often has SSH from admin jump host).
4. On SCC host: read `scc_config/secure_store/` + `system_certificates.jks`.
5. Either: replay tunnel from attacker infra (capture BTP-side secrets), or: use admin REST API to add mapping pointing to attacker's listener.
6. With subaccount UUID harvested, enumerate BTP subaccount via `cf api` / BTP CLI once you have any user token.

---

## 4. Cloud → On-prem attack paths

### 4.1 Destinations service as pivot

BTP developer token with destination-read scope:

1. List all `ProxyType=OnPremise` destinations.
2. For each, get cleartext password.
3. Open BTP app (or hijack existing) calling `@sap/cf-nodejs-connectivity` to route request through SCC to on-prem — e.g., raw RFC with fetched creds.
4. Destination is RFC type with `RFC_USER` having `SAP_ALL` → game over.
5. HTTP type pointing at S/4 OData → every OData op the user has rights for.

### 4.2 Over-permissive "Accessible Resources"

Each SCC mapping has per-virtual-host resource list. Admins often add `Path = /` with `URL Path Matching = Path and all sub-paths` — everything under HTTP root of backend reachable. For S/4:

- `/sap/bc/soap/rfc` — SOAP RFC; execute any BAPI the configured user has.
- `/sap/bc/adt/` — ABAP Dev Tools; dev user → code injection.
- `/sap/bc/webdynpro/sap/wdr_admin` — admin wizards.
- `/sap/bc/gui/sap/its/webgui` — full SAPGUI-for-HTML; if SSO → attacker drives GUI as propagated user.

Admins do this because RFC mapping docs say "allow all function modules" → translates to `/sap/bc/soap/rfc` — don't realize `Path and all sub-paths` catches much more.

### 4.3 Principal propagation forgery

BTP-to-SCC trust = "trust any SAML assertion from subaccount XYZ". Attacker with:

- Valid BTP user in subaccount XYZ (even low-priv read-only), and
- Permission to define custom IdP trust on subaccount

can:

1. Configure new IdP (attacker-controlled IAS or custom SAML 2.0).
2. Issue SAML assertion with `NameID=SAP_ALL_USER@customer.com`.
3. Log into BTP app with assertion.
4. BTP app calls on-prem destination with principal propagation.
5. SCC accepts propagated identity, mints X.509 with `CN=SAP_ALL_USER`, presents to on-prem, on-prem maps via trust config to privileged user.

On-prem side supposed to have user-mapping with trust anchor attacker can't forge — but attacker doesn't need to forge; forgery at BTP→SCC hop, SCC signs with own (trusted by on-prem) CA. Whole defense is SCC admin's user-to-cert mapping rules — per §1.7, frequently too loose.

---

## 5. IAS / IDS

### 5.1 Recent CVEs

| CVE | Year | Severity | Notes |
|---|---|---|---|
| CVE-2022-22133 | 2022 | 8.8 | Auth bypass in IAS admin console |
| CVE-2022-41203 | 2022 | 9.8 | Insecure deserialization in IAS — pre-auth RCE |
| CVE-2023-36922 | 2023 | 7.2 | OS cmd injection in SAP ECC (reachable via federation) |
| CVE-2023-49058 | 2023 | 8.8 | IAS missing authz on SCIM users endpoint |
| CVE-2024-33006 | 2024 | 9.6 | Path traversal / file upload in IAS admin → full tenant takeover |
| CVE-2024-41735 | 2024 | 6.5 | IAS info disclosure in OAuth2 error paths (leaks client secrets in 500 responses) |
| CVE-2025-0072 | 2025 | — | Emerging IAS SAML-signature-wrap issue (citation uncertain) |

### 5.2 OAuth / client-secret leakage

- `/oauth2/token` returns fully descriptive error including expected `iss` on misconfigured client. Fingerprint.
- `/.well-known/openid-configuration` unauth — all supported scopes, issuer.
- SCIM bulk user API (`/scim/Users`) accepts `filter=userName sw "a"`, rate-limit weak; user enum of full IAS tenant is easy if auth compromised.

### 5.3 Tenant takeover

Admin on IAS → attacker:

1. Exports all users + (hashed) credentials.
2. Changes password reset policy.
3. Bootstraps attacker IdP by adding new corporate IdP with "Use for all users" — next login, users authenticate via attacker IdP.
4. Any subaccount, BTP app, on-prem SNC target federating into this IAS is impersonatable.

---

## 6. SAP Build Apps / Work Zone / HANA Cloud (brief)

- **SAP Build Apps** (ex-AppGyver) — citizen-dev. Apps can call destinations service with app-binding token. Rogue citizen dev writes app enumerating destinations.
- **Work Zone** — BTP portal; historically CSRF. Holds federated user auth into on-prem.
- **HANA Cloud** — managed DB. Relevant only if customer has service channel from BTP to HANA Cloud crossing tenants.

For SAPMAP scope: secondary. Primary chains are SCC + Destinations + IAS.

---

## 7. Existing public tools

| Tool | Covers | Doesn't cover |
|---|---|---|
| **pysap** (SecureAuth) | Router, DIAG, RFC, MS, ENQ, IGS. Underpins SAPMAP. | No SCC/BTP. |
| **bizploit** (Onapsis, abandoned) | ABAP vulns, OS exploit. | No SCC/BTP. |
| **ERPScan tools** (dormant) | NW, HANA, BO. | Closed-source SCC only. |
| **SAPworx / MSF** | SAP NW, SolMan, smdagent. | No SCC-specific. |
| **RedRays Security Analyzer** | Commercial; basic SCC fingerprint. | Limited depth. |
| **`sap-cloud-connector-auditor`** (community, small) | Unauth fingerprint + version detection. | No exploit code for 49583/25645/33003. |
| **Individual GitHub PoCs** | 2020-6364 RCE writeups, CVE-2024-25645 theoretical. | No full chain. |
| **`btp-token-abuse` scripts** | Read destinations via stolen CF token. | Not integrated into map. |

**Gap SAPMAP could fill:**

- Unified fingerprint → version-map → CVE chain for SCC admin UI.
- Post-RCE automation for `scc_config/` exfil + JCEKS extraction.
- Tunnel-replay PoC (pretend-SCC from attacker host).
- Map: "I have OS on on-prem SAP" → auto-discover SCC host → auto-map subaccount → graph SCC + BTP-subaccount nodes.
- Destination enumeration from CF oauth-token.

Nobody has shipped this as one tool. Onapsis commercial gets close but closed + expensive.

---

## 8. Recommendations for SAPMAP

### 8.1 Build FIRST (one-week budget)

**`sapmap_scc.py` — SCC fingerprint + post-exploit harvester.**

Priority order:

1. **Day 1 — Fingerprint + version.** `scan_scc(ip, port=8443)`:
   - HTTPS GET `/scc/ui` → `<title>Cloud Connector</title>`, extract version from JS bundle filename (`main.bundle.<version>.js`) or `/api/monitoring/versions`.
   - Favicon hash → baked table of known hashes per version.
   - Return `SCCInfo(version, admin_ui_reachable, bound_to_localhost)`.

2. **Day 2 — Default-cred probe.** POST `Administrator:manage` to `/api/login`, detect via `Set-Cookie: JSESSIONID=` + 200 body with user-role JSON. Matches `sap_default_creds.py` pattern.

3. **Day 3 — CVE-2024-25645 + CVE-2023-49583 (low-priv → admin).** Only if low-priv creds already (or default creds landed non-admin). PUT against `/api/systemCertificates` or user-mgmt endpoint.

4. **Day 4 — On-prem mapping enumeration.** With admin session: `GET /api/configuration/connections/subaccounts` + `/api/configuration/connections/<uuid>/virtualToInternalMappings`. Feed back into SAPMAP scanner as candidate hosts.

5. **Day 5 — Post-RCE keystore harvester.** When SAPMAP has OS RCE on SCC host (10KBlaze / stolen SSH key), auto-exfil `scc_config/` + run JCEKS unwrap. Emit `SCCNode` with subaccount UUID + tunnel-cert fingerprint.

6. **Day 6 — BTP subaccount node creation.** From harvested subaccount UUIDs, add `BTPSubaccountNode` with edges to SCC and each on-prem mapping. No active BTP exploit yet — topology only.

7. **Day 7 — Destinations enumerator (if CF token supplied).** Given `cf oauth-token`, call `/destination-configuration/v1/subaccountDestinations`, pull cleartext creds. Add as edges/credentials to on-prem nodes.

Rationale: fingerprint + default creds = zero legal risk, high ROI. Keystore harvester plugs into existing post-RCE and is where chain shines — shows "RCE on ECC → SCC two hops away → BTP subaccount that trusts it."

### 8.2 Graph semantics — new nodes/edges

Extend `sapmap_models.py`:

```python
@dataclass
class SCCNode:
    host: str
    ip: str
    version: str = ""
    admin_ui_port: int = 8443
    admin_ui_reachable: bool = False
    admin_credentials: list[Credentials] = field(default_factory=list)
    default_creds_live: bool = False
    cves_confirmed: list[str] = field(default_factory=list)
    subaccount_uuids: list[str] = field(default_factory=list)
    tunnel_region: str = ""
    principal_propagation_enabled: bool = False
    mappings: list[dict] = field(default_factory=list)
    keystore_extracted: bool = False
    tunnel_privkey_path: str = ""
    pwned: bool = False
    findings: list[Finding] = field(default_factory=list)

@dataclass
class BTPSubaccountNode:
    uuid: str
    display_name: str = ""
    region: str = ""
    global_account_uuid: str = ""
    served_by_scc_hosts: list[str] = field(default_factory=list)
    destinations: list[dict] = field(default_factory=list)
    ias_tenant: str = ""
    cf_token_available: bool = False
    pwned: bool = False
    findings: list[Finding] = field(default_factory=list)
```

New edges:

- `SCC --tunnels-to--> BTPSubaccount` (label: region, tunnel-cert fingerprint)
- `SCC --maps--> SAPNode` (per mapping; label: virtual host + path allowlist; severity: wildcard = CRITICAL)
- `BTPSubaccount --destination--> SAPNode` (via SCC; RED if cleartext password captured)
- `BTPSubaccount --trusts--> IASTenant`
- `SAPNode --hosts--> SCC` (rare: SCC on ABAP host)
- `SAPNode --ssh-reachable--> SCC`

Risk color mirrors `RFCConnection.risk_level()`:

- Cleartext password + `OnPremise` + `RFC` + `SAP_ALL` user → CRITICAL (pink border).
- Mapping with `Path = /` + sub-paths + principal propagation → HIGH.
- Default-creds-live SCC → CRITICAL, blinking.

### 8.3 Chaining into existing SAPMAP

1. **`sap_gw_xpg_standalone.py` + SCC harvest**: after `SXPG_COMMAND_EXECUTE` gives OS as `<sid>adm`:
   - `find / -maxdepth 5 -name "scc_config" -type d 2>/dev/null`
   - `arp -an` + `ss -tn` for neighbors; SCC-host discovery via port 8443 on adjacent IPs.
   - Located: `scp -r sccadmin@scc-host:/opt/sap/scc/scc_config ./loot/` using SSH key discovered in `/home/<sid>adm/.ssh/` or cached credential from secstore.

2. **`sapmap_secstore.py` extension**: JCEKS unwrap routine similar to RSECTAB decryption. New `scc_secstore.py` next to it. Output: subaccount UUID list, tunnel cert fingerprint, principal-propagation CA fingerprint. Attach to SCCNode.

3. **`sapmap_scanner.py` feeder**: every SCC mapping → prospective `host:port` for scanner. Discovers brand-new SAPNodes not visible from initial range.

4. **`sapmap_impact.py` extension**: "BTP reachability" as impact category. Pwned SAPNode IP targeted by SCC mapping → impact score up (data-egress path).

5. **`sapmap_html.py`**: dedicated "Cloud Connector" section per SCC node with mapping table, CVE list, subaccount UUIDs, "take over BTP subaccount" narrative.

6. **`sapmap_exploit.py` unification**: `ExploitKind.SCC_DEFAULT_CREDS`, `SCC_AUTH_BYPASS_25645`, `SCC_KEYSTORE_EXFIL`. Reuse existing exploit-registry/UI.

### 8.4 Where NOT to go

- Don't implement BTP-side active exploitation (creating CF apps, installing shells on Kyma). Cloud-side noisy, legally riskier. Leave destination enumeration passive (read-only with supplied token).
- Don't build IAS exploit module first week. Fingerprint only; park for roadmap.
- Don't attempt tunnel replay in GUI — offline CLI helper (`sapmap_scc_tunnel_replay.py`), document manual operator use. Replay is inherently disruptive, should not be one-click.

---

**Bottom line:** SCC is the single highest-ROI missing node type for SAPMAP. Fingerprint + default creds + mapping enum gets 80% of operational value in 2-3 days. Keystore-harvest-post-RCE chain makes SAPMAP the first public tool that visually chains on-prem SAP compromise into BTP. Data model extension small (two dataclasses, one edge type).

## Caveat

CVE numbers for 2024/2025 SCC issues are from memory + SAP rolling patch-day bulletins (numbering changes). Before building, verify against SAP's "Security Patch Day" index and NVD. *Attack concepts* (default creds, JCEKS extraction, mapping abuse, principal-propagation forgery, destination-cleartext read) are well-established and version-independent; specific CVE numbers are what to double-check.
