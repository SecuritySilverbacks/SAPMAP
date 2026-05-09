# Phase 0: SCC Principal-Propagation XML Schema (verified)

Source: 5 SCC backup zips across 2 customers (`192.168.2.209` SCC 2.19.0.2 with
2 subaccounts; `10.10.1.4` SCC 2.18.0 with 9 subaccounts). Schema is consistent
across both versions.

## TL;DR — where PP rules live

**The PP user-mapping rules are SCC-WIDE.** They live at the top-level
`scc_config/scc_config.ini` under `<principalPropagationConfiguration>`.
They are **not per-subaccount, not per-mapping**.

This is significant: one weak rule contaminates *every* PP-enabled mapping
across *every* subaccount on the SCC. The original plan assumed per-mapping
rules; the analyser scope shrinks accordingly.

## Confirmed schema

```xml
<commonConfigData>
  <principalPropagationConfiguration>
    <subjectPatterns>
      <subjectPattern>
        <dnEntries>
          <entry>
            <key>CN</key>            <!-- DN attribute: CN/OU/O/E/L/ST/C/UID/DC/T -->
            <value>${name}</value>   <!-- template — see placeholder list below -->
          </entry>
          <!-- ...more entries compose the full DN... -->
        </dnEntries>
        <condition/>                 <!-- optional XPath-ish gating expression (always empty in samples) -->
        <description/>               <!-- 2.18+ only -->
      </subjectPattern>
      <!-- multiple <subjectPattern> elements possible (none observed in samples) -->
    </subjectPatterns>
    <certificateValidityPeriodInMins>60</certificateValidityPeriodInMins>
    <principalPropagationMode>LOCAL</principalPropagationMode>
    <secureLoginServerConfiguration>
      <apiVersion>2</apiVersion>
      <clientAuthPort>0</clientAuthPort>
      <protocol>https</protocol>
      <sslPort>0</sslPort>
    </secureLoginServerConfiguration>
    <ssoToleranceInHours>2</ssoToleranceInHours>
  </principalPropagationConfiguration>
</commonConfigData>
```

## Placeholder catalogue

The `<value>` element supports `${...}` substitution from the cloud-side
identity. Sample backups use `${name}` and `${email}`; SCC documentation
also defines:

| Placeholder | Source | Caller-controlled? |
|---|---|---|
| `${name}` | login name from cloud-side IdP | Yes (whatever the IdP claims) |
| `${email}` | email claim | Partially (IdP-dependent) |
| `${first_name}` / `${last_name}` | given/family name | Yes |
| `${user_uuid}` | UUID from cloud | No (IdP-bound) |
| `${groups}` | group list | Caller-influenced |
| Literal text | static string | No |

Mixed templates (`${first_name}.${last_name}@corp.example.com`) appear in SAP
documentation but not in sample backups.

## `principalPropagationMode` enum

Values observed in samples + SCC documentation:

- `LOCAL` — SCC mints forwarded certs with its **own internal CA** (PP CA in
  the SSFS). Default. **All samples use this.**
- `KERBEROS` — Kerberos constrained delegation, no cert minting (rare).
- `SECURE_LOGIN_SERVER` — external Secure Login Server signs the certs.
- `DISABLED` / unset — PP unavailable.

`LOCAL` is the dangerous one for the weak-rule analyser, because the SCC
itself synthesises the cert and the on-prem ABAP system trusts the SCC PP CA
unconditionally (operator wires this up via STRUSTSSO2 + USREXTID).

## `<authenticationMode>` on systemMappings — broader than current detection

The current SAPMAP code (`sapmap_scc_admin.py:329`) flags PP only when the
mapping `authenticationMode` is `KERBEROS` or `X509_GENERAL`. **Real backups
show this list is incomplete.** Mode counts across the 10.10.1.4 sample (28
mappings):

| Mode | Count | Uses LOCAL PP CA? |
|---|---|---|
| `NONE_CERTIFICATE_LOCAL` | 14 | **YES** — caller is unauth, but SCC still mints a cert with `subjectPattern` and forwards |
| `X509_CERTIFICATE_LOCAL` | 4 | **YES** — caller presents X.509, SCC validates, then mints a fresh local cert |
| `KERBEROS` | 6 | YES — Kerberos delegation produces an asserted cloud principal |
| `X509_CERTIFICATE` | 1 | Sometimes (depends on `principalPropagationMode`) |
| `NONE` | 1 | No PP (forwarding raw, on-prem auths the caller directly) |

**Implication for the analyser**: any mapping whose `authenticationMode` ends
with `_LOCAL` (or is `KERBEROS`/`X509_GENERAL`) is in scope for the
weak-rule findings. The current PP-detection set in
`sapmap_scc_admin._normalize_mapping` and
`sapmap_scc_keystore.parse_mappings_*` is **incomplete and underflags
findings today**. This is a related bug worth fixing in the same change set.

## Per-subaccount `trustcfg_<uuid>.xml` (SCC 2.18+, optional)

Where present, `scc_config/<region>/<uuid>/trustcfg_<uuid>.xml` contains the
cloud-side IdP signing keys SCC trusts for inbound JWT validation:

```xml
<trustConfiguration>
  <lastUpdated>2025-09-08 18:07:30:111</lastUpdated>
  <configurations>
    <idPConfiguration>
      <name>Subaccount=<uuid>, kid=default-jwt-key-…</name>
      <description>JSON Web Token (JWT) key, used by the SAP UAA (XSUAA) …</description>
      <enabled>true</enabled>
      <id>-2064206234</id>
      <publicKey>-----BEGIN PUBLIC KEY----- … -----END PUBLIC KEY-----</publicKey>
    </idPConfiguration>
    <!-- multiple entries possible: e.g. one XSUAA + one IAS -->
  </configurations>
</trustConfiguration>
```

Presence is conditional on `<autoSyncTrust>true</autoSyncTrust>` in the
per-subaccount `scc_config.ini`. The 192.168.2.209 backups have it disabled
(`autoSyncTrust=false`) so no `trustcfg_*.xml` files exist there.

The analyser should:

- Treat `trustcfg_<uuid>.xml` as **optional** — not all backups have it.
- Count enabled `<idPConfiguration>` entries per subaccount.
- Flag MEDIUM when more than one IdP is trusted (broader attack surface;
  legitimate cases exist e.g. XSUAA + IAS).
- Flag HIGH when an enabled IdP's `<description>` says *external* IdP
  (vs SAP-managed XSUAA/IAS) — the customer's own IdP is the most common
  weak link in the chain.

## What's NOT in the backup zip

For honesty about the analyser's reach:

- **No regex literals.** SCC's PP rules are template substitution with
  `${name}` placeholders, not full regex like LDAP user mappings or
  Apache `mod_auth_cert`. The "weak CN regex" framing in the original
  backlog item is technically wrong — there are no regexes here. The
  weakness is "caller-controlled placeholder + no condition + no
  trust-bound IdP."
- **No reverse-mapping table.** Whether `${name}` produces a CN that
  matches a real on-prem ABAP user depends on the on-prem `USREXTID`
  table, which is a separate analyser pass entirely (existing code
  already touches USR02/USR04 — could be extended to USREXTID).
- **No issuer/CA whitelist on `<subjectPatterns>`.** The trust comes from
  `principalPropagationMode=LOCAL` (SCC mints with its own CA, on-prem
  trusts that CA) — the cloud-side IdP trust lives in `trustcfg_*.xml`
  per subaccount.

## Revised analyser scope

Given the above, the analyser becomes simpler than originally drafted:

### Rules — Tier 1 (CRITICAL)

For each `<subjectPattern>` in the global PP block:

1. **Empty subject pattern** — no `<dnEntries>` or `<entry>` missing.
   SCC default is "any cert subject works", which combined with
   `principalPropagationMode=LOCAL` means literally any cloud caller
   gets any on-prem user.
2. **Single `${name}` mapped to CN** — the most common misconfig. Cloud
   IdP claim "name" becomes the on-prem CN; if the on-prem `USREXTID`
   has any common-name overlaps with cloud-side names, attacker can
   impersonate.
3. **Empty `<condition>`** AND `${name}`/`${email}` placeholder AND
   `principalPropagationMode=LOCAL` AND any mapping with
   `_LOCAL`/`KERBEROS` auth.

### Rules — Tier 2 (HIGH)

4. **Hardcoded privileged user** — `<value>DDIC</value>`,
   `<value>SAP*</value>`, `<value>SAPSYS</value>`, etc. as a literal.
   Every cloud user runs as the named privileged on-prem user.
5. **`${email}` with no domain check in `<condition>`** — the IdP usually
   verifies email format but not domain ownership; a cloud user with a
   crafted email claim can still pick any on-prem CN that matches.
6. **Two or more enabled `<idPConfiguration>` entries in
   `trustcfg_<uuid>.xml`** when at least one is non-SAP-managed — broader
   attack surface for forged JWTs.

### Rules — Tier 3 (MEDIUM)

7. **`certificateValidityPeriodInMins` > 240** — long-lived forwarded
   certs increase blast radius if the PP CA private key leaks (we already
   capture this key via SSFS; this finding pairs with that lateral move).
8. **`ssoToleranceInHours` > 8** — extends the window during which a
   stolen MYSAPSSO2 ticket forwarded by SCC remains valid on the
   on-prem side.

## Updated implementation map

The analyser becomes ~150 LOC (was ~250) because regex tokenisation isn't
needed. The integration footprint stays roughly the same:

- New parse function in [modules/data_extraction/sapmap_scc_keystore.py](modules/data_extraction/sapmap_scc_keystore.py):
  `parse_pp_config_from_zip(zip_path) -> dict` returning the structured
  PP config (subjectPatterns + mode + validity + sso).
- New parse function for `trustcfg_<uuid>.xml`:
  `parse_pp_trust_from_zip(zip_path) -> {uuid: {idps: [...], lastUpdated: ...}}`.
- New rule engine in `modules/discovery/sapmap_scc_pp_analyzer.py`:
  pure function `analyze(pp_config, mappings, trust_per_subaccount) -> list[finding-dict]`.
- [modules/data_extraction/sapmap_scc_admin.py:329](modules/data_extraction/sapmap_scc_admin.py:329)
  and [modules/data_extraction/sapmap_scc_keystore.py:254](modules/data_extraction/sapmap_scc_keystore.py:254):
  fix the PP-mode detection set to include `*_LOCAL` modes (related bug).
- Glue + GUI surfacing as outlined in the original plan §6/§7.

## Test fixtures

The 5 sample backups are sufficient material to seed unit tests. Plan to
include 2-3 anonymised XML snippets directly in
`tests/fixtures/scc_pp_*.xml` (no UUIDs/keys leaked) covering:

- single `${name}` CN rule (CRITICAL)
- `${email}` + empty condition (CRITICAL/HIGH)
- well-scoped multi-entry DN with literal OU + condition (no finding)
- hardcoded `<value>DDIC</value>` (HIGH)
- multi-IdP trustcfg (MEDIUM)
