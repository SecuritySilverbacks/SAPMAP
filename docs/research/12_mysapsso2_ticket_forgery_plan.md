# Plan — Add MYSAPSSO2 Logon-Ticket Forgery to SAPMAP

## 1. Why this matters

SAPMAP's current lateral-movement chain is **per-hop expensive**: on every downstream system reached via an RFC trust edge, we must drop a SAPMAP00 user (via BAPI_USER_CREATE1 / SQL writer / dpmon SAP\* / …) before we can act.  That's:

- 1 user-create RFC round-trip per node
- 1 audit-log entry (CUS / EUP / SU24) per node
- New row in USR02 / UST04 / USRBF2 per node — easy SoC IoC
- Subject to per-node password / lock / SCC4 policy

**MYSAPSSO2 forgery changes the math fundamentally.**  Once SAPMAP has OS-exec on **one** SAP system in the trust subgraph, the operator extracts that system's **SAPSYS.pse + cred_v2 PIN** in a single read.  From there:

- Forge a ticket impersonating **any** user (`SAP*`, `DDIC`, a known admin, an arbitrary BNAME) — no user creation needed
- **One PSE = ticket logon to every system in the STRUSTSSO2 trust subgraph**.  In practice, the STRUSTSSO2 ACL trust set ⊇ the RFC trust set (Solution Manager, GRC, etc. trust everyone), so a single ticket replays across **the whole landscape**
- No write to the downstream system — no `BAPI_USER_CREATE1`, no `SQL INSERT INTO USR02`, no SAPMAP00 to clean up later
- No audit-log entry on the **issuer** (we extracted the PSE; we never called any user-creation BAPI on it).  Downstream systems do log "SSO ticket logon" but it looks identical to a routine SSO event from the SolMan / portal — easy to blend into baseline noise

The end state: one pwned system can be turned into landscape-wide `SAP*` impersonation with zero new accounts created.  This is the cleanest persistence + lateral-movement primitive SAP offers, and SAPMAP doesn't have it yet.

## 2. Technical foundation (from research)

### 2.1 Wire format

MYSAPSSO2 is **not** ASN.1 — it's a custom `[magic][codepage][TLV...][PKCS#7-sig]` blob, then base64-encoded for HTTP / cookie transport.  Only the trailing signature is ASN.1 (PKCS#7 SignedData).

```
Ticket = 0x02 || codepage(4B ASCII) || InfoUnit* || SignatureUnit

InfoUnit = ID(1B) || len(2B BE) || payload(len B)
```

**InfoUnit IDs** (verbatim from `avadillo/SAPLogon`):

| Hex  | Field                | Purpose                                        |
|------|----------------------|------------------------------------------------|
| 0x01 | User                 | ABAP BNAME (codepage-encoded, ≤12 chars)       |
| 0x02 | CreateClient         | Issuing MANDT (3 ASCII digits)                 |
| 0x03 | CreateSID            | Issuing SYSID (≤8 chars)                       |
| 0x04 | CreateTime           | UTC "yyyyMMddHHmm" (12 chars)                  |
| 0x05 | ValidTimeInH         | uint32 BE — hours                              |
| 0x06 | RFC                  | 'X' / ' ' (single ASCII byte)                  |
| 0x07 | ValidTimeInM         | uint32 BE — minutes                            |
| 0x08 | Flags                | 1B — bit 0 = do-not-cache                      |
| 0x09 | Language             | SAP 1-char language code                       |
| 0x0A-0x0E | UTF8 mirrors    | Informational UTF-8 mirrors of 0x01-0x04, 0x09 |
| 0x0F | RecipientClient      | Assertion-ticket only target MANDT             |
| 0x10 | RecipientSID         | Assertion-ticket only target SYSID             |
| 0x20 | PortalUser           | "portal:<user>"                                |
| 0x88 | AuthScheme           | ASCII "default" / "basicauthentication" / …    |
| 0xFF | Signature            | PKCS#7 SignedData over the prefix              |

Codepage label `"4103"` = UTF-16LE-no-BOM (the SAP default); `"1100"` Latin-1; `"4110"` UTF-8.

**Validity**: no absolute "valid-to" — `CreateTime + ValidTimeInH*3600 + ValidTimeInM*60`.  Default 5 min (LogonTicket) / 2 min (AssertionTicket).

**Open ticket vs. recipient-pinned**: omitting 0x0F+0x10 makes the ticket portable across the entire trust subgraph.  Pinning them restricts to one target.

### 2.2 Signing — PKCS#7 SignedData (CMS)

- Detached CMS over the ticket prefix
- Default digest: SHA-256 for RSA keys (SHA-1 only for legacy DSA)
- `IncludeOption = EndCertOnly`-or-`None`.  With cert embedded: ~1.5 KB ticket; without: ~300 B + receiver must already trust by IssuerAndSerialNumber.  Production SAP defaults to NOT embedding (`login/create_sso2_ticket = 2`).
- Signed attributes include `Pkcs9SigningTime` (Pkcs9 OID 1.2.840.113549.1.9.5)

### 2.3 The signing key: SAPSYS.pse + cred_v2

- **SAPSYS.pse** lives at `$DIR_INSTANCE/sec/SAPSYS.pse` (Linux: `/usr/sap/<SID>/<INST>/sec/SAPSYS.pse`)
- SAP-proprietary PSE binary (ASN.1 envelope around a PKCS#12-style bag — see `OWASP/pysap`'s `SAPPSE.py`)
- Holds the system's RSA/DSA/EC private key + self-signed cert + CA chain
- Protected by a "PIN" (really a password)

**The PIN** can live in three places:

1. **`$SECUDIR/cred_v2`** (default) — SSO credential file, ASN.1-wrapped, 3DES-encrypted (or PBES2-AES256-SHA256 on newer kernels).  The encryption key is **derived from the OS user name running the workprocess** — so any process running as `<sid>adm` can read+decrypt this file with no further authentication.  This is the lateral-movement gift.
2. **LPS (Local Protected Storage)** — adds DPAPI (Windows) or TPM (Linux); still recoverable as `<sid>adm`
3. **RSECTAB / SSF API** — DB-stored variant when `ssf/ssfapi_lib=sapsecu.so`

`<sid>adm` access is **always sufficient** to recover the PIN.  SAPMAP already has OS exec as `<sid>adm` via every existing exploit path (GW SAPXPG, CVE-2025-31324, dpmon, SXPG).

### 2.4 Trust on the receiver

Three things must be true for the receiver to accept a forged ticket:

1. `login/accept_sso2_ticket = 1` (default if SSO is configured)
2. **STRUSTSSO2 ACL** row exists binding `(IssuerSID, IssuerClient, SubjectDN)` to a trusted cert — i.e., the receiver's SAPSYS.pse "Certificate List" contains the issuer's cert
3. The ticket's User field either exists as a USR02 BNAME on the receiver, OR an USREXTID mapping exists.  For SAP\* / DDIC / a guessed BNAME this is automatic — they exist on every NW system

Trust is **per-receiver**, not per-client.  Once receiver trusts `(SID, CLIENT, cert)`, the ticket replays into any client on that receiver.

### 2.5 Delivery mechanisms

**A. SAP GUI shortcut (`.sap` file)** — INI-style text file:

```ini
[System]
Name=PRD
Description=PRD via forged ticket
Client=100
SystemNumber=00
Server=prdhost.example.com
[User]
Name=
at=MYSAPSSO2%3D<URL-encoded-base64-ticket>
[Function]
Command=SU01
Title=Lateral
[Configuration]
GuiSize=Maximized
```

The `at=` value is the literal cookie string `MYSAPSSO2=<value>`, URL-encoded.  At GUI launch the cookie is injected before the Diag handshake, triggering ticket logon.

**B. HTTP cookie for WebGUI / Fiori / ICF** — `Cookie: MYSAPSSO2=<URL-encoded-base64-ticket>` on any `/sap/bc/*` request.  No other auth needed.

**C. RFC via `pyrfc`** — `Connection(ashost=..., sysnr='00', client='100', mysapsso2=base64_ticket, lang='EN')`.  No password.

### 2.6 Detection footprint on receivers

- Security Audit Log message **AU3** — "Logon successful (type=H, method=A) with SSO ticket"
- Verification failure path: **AUW** — "SSO ticket verification failed"
- Defender anomalies: AU3 from a system with no corresponding outgoing logon, `User=SAP*/DDIC` via SSO (which essentially never happens legitimately), CreateTime clock skew

## 3. Architecture

```
modules/postex/sap_pse_loot.py        ← NEW: extract SAPSYS.pse + cred_v2
  ├─ extract_pse_bundle(node, exec_fn) -> dict
  │     reads $SECUDIR/SAPSYS.pse + $SECUDIR/cred_v2 via base64-stream-read
  │     pattern (same as the existing SecStore + SCC SSFS extractors)
  ├─ decrypt_cred_v2(blob, sidadm_user) -> str   (the PSE PIN)
  └─ extract_signing_key(pse_blob, pin) -> {cert: x509, priv: RSAPrivateKey,
                                            issuer_dn: str, serial: int,
                                            ...}

modules/exploitation/sap_mysapsso2.py  ← NEW: ticket builder + signer
  ├─ build_ticket(user, client, sid, validity_min=120,
  │               language="E", recipient=None,
  │               include_cert=False) -> bytes
  │     constructs the TLV prefix
  ├─ sign_ticket(prefix_bytes, priv_key, cert,
  │              include_cert=False, digest="sha256") -> bytes
  │     wraps in PKCS#7 SignedData, appends as 0xFF InfoUnit
  ├─ parse_ticket(ticket_bytes) -> dict
  │     for testing + roundtrip verification + display
  └─ encode_for_cookie(ticket_bytes) -> str
        base64 + URL-encode

modules/exploitation/sap_ticket_delivery.py  ← NEW: artifact writers
  ├─ make_sapgui_shortcut(node, ticket, user, tcode="SU01") -> Path
  │     writes loot/tickets/<sid>_<user>.sap
  ├─ make_curl_command(node, ticket, path="/sap/bc/gui/sap/its/webgui") -> str
  │     for HTTP cookie testing
  └─ pyrfc_connection_kwargs(node, ticket, user) -> dict
        for downstream RFC propagation use

modules/core/sapmap_models.py          ← EDIT: add SAPNode.forged_tickets
  ├─ @dataclass class ForgedTicket(...)
  │     issuer_sid, issuer_client, user, created_at, validity_min,
  │     cookie_b64, shortcut_path, source: "extracted_from_<sid>"
  └─ SAPNode.forged_tickets: list[ForgedTicket]  +  to_dict/from_dict

modules/exploitation/sapmap_exploit.py ← EDIT: enrichment + propagation
  ├─ extract_and_forge_ticket(node, state, target_user="SAP*") -> ForgedTicket
  │     orchestrator: extract PSE → forge ticket → cache on node
  └─ propagate_via_forged_ticket(source_node, ticket, state) -> [CreatedUser]
        for each STRUSTSSO2-trusted receiver:
          try logon with the ticket via pyrfc
          if successful → reach as the impersonated user
          optionally: still create SAPMAP00 there for persistence

modules/core/sapmap_gui.py              ← EDIT: backend endpoints
  ├─ POST /api/node/<sid>/forge_ticket  {user, client, validity_min, ...}
  ├─ GET  /api/ticket/<id>/download     → returns the .sap shortcut
  └─ POST /api/node/<sid>/propagate_ticket  {ticket_id, target_sid}

modules/core/sapmap_html.py             ← EDIT: right-click menu + modal
  └─ "⚡ Forge MYSAPSSO2 Ticket (impersonate any user)" context-menu entry
        opens a modal: target user (default SAP*), client, validity
        then surfaces the resulting .sap shortcut + curl command
        + button "Propagate to all STRUSTSSO2-trusted systems"

modules/exploitation/sapmap_autopwn.py  ← EDIT: AutoPwn integration
  └─ New Phase 4c "TicketForge" — runs after Phase 4 propagation:
        for each pwned ABAP node:
          extract SAPSYS.pse + cred_v2
          forge ticket for SAP*
          attempt logon to every state.connections target_sid
          add reachable receivers as pwned nodes
```

## 4. Implementation phases (10-12 commits)

### Phase A — PSE extraction primitive (commits 1-3)

**Commit 1** — `sap_pse_loot.extract_pse_bundle` + tests
- Read `$SECUDIR/SAPSYS.pse` + `$SECUDIR/cred_v2` via the existing base64-stream-read pattern (`sapmap_copyfail._read_b64` at line 289)
- Add a helper that runs `ls $SECUDIR` to discover what's there
- `$SECUDIR` resolves to `/usr/sap/<SID>/<INST>/sec/` for instance PSE; `/usr/sap/<SID>/SYS/global/security/data/` for global
- Returns `{pse_bytes, cred_v2_bytes, secudir, sidadm_user, error}`
- Tests: source-level + fixture-driven (synthetic 256-byte placeholder for the bytes)

**Commit 2** — `sap_pse_loot.decrypt_cred_v2`
- Port the cred_v2 parsing logic from `OWASP/pysap`'s `SAPCredv2.py`
- ASN.1 outer envelope → 3DES-encrypted payload → key = `derive_key(sidadm_user)`
- Use existing `cryptography` library (already imported in `sapmap_scc_keystore.py:862`)
- Handle the PBES2-AES256-SHA256 variant for newer kernels
- Tests: round-trip with a synthetic cred_v2 blob built by the same code

**Commit 3** — `sap_pse_loot.extract_signing_key`
- PSE binary parser: SAP wraps PKCS#12 in its own ASN.1 envelope (see `pysap.SAPPSE.py`)
- Decrypt the inner PKCS#12 with the PIN from commit 2
- Return RSA/DSA/EC private key + signer cert (X.509) + Issuer DN + serial
- Tests: parse a synthetic PSE generated locally with `sapgenpse` (skipped if `sapgenpse` not installed; the parser logic is tested with the static byte layout)

### Phase B — Ticket forger (commits 4-5)

**Commit 4** — `sap_mysapsso2.build_ticket` + `parse_ticket` + tests
- Pure-Python TLV builder/parser — no external deps beyond `struct`
- Build: take (user, client, sid, validity_min, language, recipient=None, include_cert=False) → bytes
- Parse: bytes → dict for round-trip + display
- Tests:
  - Build → parse round-trip preserves every field
  - Fixture: a known ticket dump (e.g., from `pysap` or `avadillo/SAPLogon` tests) parses to the expected values
  - Codepage variants (4103 UTF-16LE, 4110 UTF-8, 1100 Latin-1)
  - Open vs recipient-pinned

**Commit 5** — `sap_mysapsso2.sign_ticket` + `encode_for_cookie`
- PKCS#7 SignedData via `cryptography.hazmat.primitives.serialization.pkcs7.PKCS7SignatureBuilder`
- Detached signature, optional cert embedding, configurable digest (default SHA-256)
- Append as 0xFF InfoUnit
- Tests: sign → verify round-trip with a self-signed test RSA cert

### Phase C — Delivery artifacts (commit 6)

**Commit 6** — `sap_ticket_delivery` + tests
- `.sap` shortcut writer (text-format INI with `at=` line)
- `curl` command builder for WebGUI cookie test
- `pyrfc` kwargs builder
- Loot dir: `loot/tickets/<sid>_<user>_<timestamp>.{sap,json}`
- The JSON sidecar holds the parsed ticket + metadata + the cookie value for re-use
- Tests: artifact format invariants (ini headers, URL-encoding correctness)

### Phase D — State model + orchestrator (commits 7-8)

**Commit 7** — `SAPNode.forged_tickets` + `ForgedTicket` dataclass
- Mirror the `CreatedUser` model pattern (`sapmap_models.py:167`)
- to_dict / from_dict / back-compat for old `.sapmap` files
- Tests: round-trip + default-empty

**Commit 8** — `extract_and_forge_ticket` orchestrator in `sapmap_exploit.py`
- Wraps the extract-PSE → decrypt-PIN → parse-key → forge-ticket flow
- Caches the result on `node.forged_tickets`
- Surfaces a CRITICAL finding ("System PSE extracted; forged ticket impersonates `<user>` valid `<N>` min")
- Tests: orchestrator-level source invariants + behavioral with mocked exec_fn

### Phase E — Propagation (commit 9)

**Commit 9** — `propagate_via_forged_ticket`
- Iterate `state.connections` from the source SID
- For each target with STRUSTSSO2 trust (heuristically: same trust subgraph that already accepts RFC), attempt `pyrfc.Connection(..., mysapsso2=ticket)` logon
- If logon succeeds, the target is **reachable as the impersonated user** without any user creation
- Optionally trigger downstream user-creation for persistence (existing flow)
- Tests: source-level for the iteration, behavioral with mocked pyrfc

### Phase F — UI integration (commit 10)

**Commit 10** — GUI: context-menu entry + modal + endpoints
- Right-click ABAP node with OS-exec → **⚡ Forge MYSAPSSO2 Ticket**
- Modal: target user (default `SAP*`), client (default `000`), validity (default 30 min)
- Output: download link for the `.sap` shortcut + visible cookie + "Propagate to trusted systems" button
- Backend: `POST /api/node/<sid>/forge_ticket`, `GET /api/ticket/<id>/download`
- Tests: HTML invariants + JS forwarding

### Phase G — AutoPwn integration (commit 11)

**Commit 11** — AutoPwn Phase 4c "Ticket Forge & Propagate"
- New `AutoPwnConfig.try_ticket_forgery: bool = True`
- After phase 4 propagation: for each pwned ABAP node, attempt PSE extract → forge → broadcast logon
- Visible in the AutoPwn progress panel as a separate phase
- Tests: source-level priority order + config flag wiring

### Phase H — Docs (commit 12)

**Commit 12** — README + CLAUDE.md updates
- Features → Lateral Movement: new "MYSAPSSO2 forgery" bullet
- New dedicated section explaining the technique, threat model, audit footprint, defender guidance (STRUSTSSO2 hygiene, audit-log monitoring AU3 for `User=SAP*`)
- Architecture map: `modules/postex/sap_pse_loot.py` + `modules/exploitation/sap_mysapsso2.py` + `modules/exploitation/sap_ticket_delivery.py`

## 5. Reusable primitives from the codebase audit

Per the codebase research:

| Need | What ships | Where |
|---|---|---|
| Read arbitrary file as `<sid>adm` | `_read_b64()` chunked pattern | `modules/exploitation/sapmap_copyfail.py:289` |
| 3DES / DES for cred_v2 | `pycryptodome` already imported | `modules/data_extraction/sapmap_secstore.py:33` |
| RSA / EC / PBKDF2 / PKCS#7 | `cryptography` lib already integrated | `modules/data_extraction/sapmap_scc_keystore.py:862` |
| PSE-related categorisation | RSECTAB regex `_RE_STRUST` (partial) | `modules/data_extraction/sapmap_secstore.py:253` |
| Existing MYSAPSSO2 cookie awareness | `_whoami_from_response()` decodes cookies | `modules/exploitation/sap_pp_probe.py:180` |
| Loot dir layout | `LOOT_DIR/tickets` subdirectory | `modules/core/sapmap_state.py:35` |
| Created-user-style model | `CreatedUser` dataclass to mirror | `modules/core/sapmap_models.py:167` |
| WebGUI session helpers | `_webgui_session()` for cookie-injection delivery | `modules/postex/sapmap_lpe.py:130` |
| Test patterns | source-level invariants + fixture parsing | `tests/test_sap_dpmon_sapstar.py` |

## 6. Net-new code needed

The only **genuinely new** code is:

1. **SAP PSE binary parser** (~150 LOC).  Port from `OWASP/pysap`'s `SAPPSE.py`.  ~ASN.1 outer envelope + PKCS#12 inner.
2. **cred_v2 decryptor** (~80 LOC).  Port from `pysap`'s `SAPCredv2.py`.  3DES + the sidadm-name key-derivation quirk.
3. **TLV ticket builder + parser** (~120 LOC).  Pure-Python, just `struct`.
4. **PKCS#7 SignedData wrapper** (~50 LOC).  Use `cryptography.hazmat.primitives.serialization.pkcs7`.
5. **`.sap` shortcut writer** (~30 LOC).  Trivial INI.

Total ~430 LOC core + ~600 LOC tests + ~300 LOC orchestration/integration = **~1300-1500 LOC** across 12 commits.

## 7. Threat-model + ethics gating

This is a high-impact primitive.  It should:

- Be gated behind the same engagement-authorisation banner as the existing exploit modules
- Default the forged ticket's user to **the actual node admin** (operator picks; SAP\* / DDIC must be explicit operator selection, not auto-default — to avoid accidental cross-system DDIC impersonation in a routine assessment)
- Set the default validity to a SHORT window (30 min) so a leaked ticket loses value fast
- Audit-log impact: surface clearly in the UI that EVERY use of the forged ticket on a downstream system fires an AU3 record — operator needs to know
- The DOC must include a defender-perspective section: "If you're a defender reading this, here's how to detect it" (STRUSTSSO2 hygiene, AU3 monitoring on `User=SAP*/DDIC`, anomaly detection on tickets without preceding logon)

## 8. Open questions to resolve during implementation

1. **PSE binary format compat**: does `pysap.SAPPSE` work cleanly with kernel 793 PSEs, or has SAP changed the inner envelope?  Validate against the operator's S4D / S4H PSEs.
2. **cred_v2 algorithm dispatch**: which kernel versions ship the PBES2-AES256-SHA256 variant vs. 3DES?  Likely kernel 753+ but needs confirmation.
3. **PKCS#7 padding**: `cryptography`'s `PKCS7SignatureBuilder` defaults — verify against a known-good ticket from a real PSE.
4. **STRUSTSSO2 trust subgraph discovery**: do we need a new `RFC_READ_TABLE` against table `STRUSTSSO2`, or can we infer trust from the existing RFC trust edges?  (Answer: STRUSTSSO2 ⊇ RFC trust in practice but not always — explicit read is more reliable.)
5. **Java AS Java support**: AS Java uses the same cookie name but a DIFFERENT trust store (`TicketKeystore` keystore view in UME).  Should v1 cover Java targets or punt to a follow-up?  Punt for v1 — focus on ABAP.

## 9. Reference implementation: `synacktiv/sap_logon_ticket`

**<https://github.com/synacktiv/sap_logon_ticket>** is a published, working
MYSAPSSO2 forger by the Synacktiv team.  Three files, ~minimal — confirms our
wire format and gives us a known-good validator for tests.

### What synacktiv ships

| File | Purpose |
|---|---|
| `SAPLogonTicket.py` | Core library — scapy `Packet`/`PacketField` schemas for SAPInfoUnit, SAPLogonTicketDataToSign, SAPLogonTicket |
| `forge_sap_logon_ticket.py` | CLI: `--username --client --system --duration --cert --key --format` |
| `decode_sap_logon_ticket.py` | CLI: parse + dump existing tickets |
| `requirements.txt` | `scapy`, `asn1crypto`, `pycryptodome` |

### Verbatim InfoUnit constants from `SAPLogonTicket.py`

```python
ID_USER              = 1
ID_CREATE_CLIENT     = 2
ID_CREATE_NAME       = 3
ID_CREATE_TIME       = 4
ID_VALID_TIME        = 5
ID_RFC               = 6
ID_VALID_TIME_MIN    = 7
ID_FLAGS             = 8
ID_LANGUAGE          = 9
ID_USER_UTF          = 10
ID_CREATE_CLIENT_UTF = 11
ID_CREATE_NAME_UTF   = 12
ID_CREATE_TIME_UTF   = 13
ID_LANGUAGE_UTF      = 14
ID_RECIPIENT_CLIENT  = 15
ID_RECIPIENT_SID     = 16
ID_AUTHSCHEME        = 136
ID_SIGNATURE         = 255
```

**100% match** with our research dossier — wire format is confirmed.  Default
codepage is `"4103"` (UTF-16LE) and the signature unit (0xFF) wraps a PKCS#7
SignedData blob.  Source comment cites
`help.sap.com/.../com/sap/security/api/ticket/InfoUnit.html`.

### What synacktiv does NOT cover (the half SAPMAP must add)

The Synacktiv CLI takes **already-extracted** `--cert` and `--key` files as
input.  It has no PSE binary parser, no `cred_v2` decryptor, no helper for
extracting the signing material from a live SAP host.  That's the
**unique-to-SAPMAP** half of this feature — leveraging our existing
`<sid>adm` OS-exec primitives (GW SAPXPG / dpmon / CVE-31324 / SXPG / WebGUI
RSBDCOS0) to harvest SAPSYS.pse + cred_v2 from a compromised system, decrypt
both, and emit the cert + key our forger needs.

It also doesn't cover the **delivery side** (.sap shortcut writing, WebGUI
cookie injection, pyrfc connection wiring) or the **integration side**
(SAPNode state, AutoPwn slot, right-click menu, propagation across the
STRUSTSSO2 trust subgraph).

### Notable implementation choices to copy / not copy

- **Use `scapy` PacketField schemas vs. pure-struct**: synacktiv uses scapy
  for the packet/TLV declarations.  Elegant but adds scapy as a dep
  (~heavyweight).  Recommendation: **stay with pure `struct`** for SAPMAP
  — TLV is trivially small (~120 LOC) and avoids a new dependency.  Use
  synacktiv as a parser-roundtrip oracle in tests instead.

- **`asn1crypto` for PKCS#7**: synacktiv picks `asn1crypto`; SAPMAP already
  imports `cryptography` (per the audit).  Use `cryptography.hazmat.
  primitives.serialization.pkcs7.PKCS7SignatureBuilder` — same result, no
  new dep.

- **DSA-SHA1 vs RSA-SHA256**: synacktiv's forge tool defaults to
  **DSA/SHA1** signing per the documented flow.  That's a legacy SAP
  default; modern PSEs (sapgenpse on 7.5x+ kernels) generate RSA.  Our
  implementation must read the PSE's key type and pick the matching algo:
  RSA → SHA-256, DSA → SHA-1, EC → SHA-256/384/512 by curve.

- **Output format**: synacktiv's `--format=MYSAPSSO2` does base64 + URL-
  encoding for cookie use.  Mirror this; also emit raw bytes for pyrfc /
  the `.sap` shortcut.

### License compatibility

**Synacktiv's repo is GPL-3.0**.  Our plan does NOT vendor any of their
code into SAPMAP — we use it strictly as a:

1. **Wire-format reference** — confirms the InfoUnit IDs + codepage constant
2. **Roundtrip oracle for tests** — generate a known-good ticket with
   their CLI, parse it with our parser, ensure field-for-field match
3. **Behavioural sanity check** — sign with their tool against the same
   PSE we use, compare PKCS#7 byte-for-byte

Clean-room reimplementation in our own code keeps SAPMAP free of GPL
copyleft obligations and lets us integrate at the level of dependency
choice + state model + UI that wouldn't be possible vendoring a CLI tool.

The companion PSE extraction code we'll port from `OWASP/pysap` (Apache
2.0, vendor-safe).

### Net effect on the plan

- **Wire format**: confirmed, no changes to commits 4-5 in section 4
- **PSE extraction half**: unchanged — synacktiv doesn't cover this so the
  port from `pysap` is still net-new SAPMAP code
- **Test strategy**: add a new pytest test class using synacktiv's tool as
  an external oracle (call out via subprocess if installed in the dev env,
  skip otherwise) — gives us field-for-field parity validation against a
  known-good implementation
- **Confidence**: ~much higher.  We now have a published forger to
  cross-check every wire-format bit; we won't be guessing on the encoding
  of any TLV field
- **Estimated LOC**: drops slightly from ~1500 to ~1300 — we can lean on
  synacktiv-style scapy patterns for inspiration but stay with `struct`,
  and the validation tests are more powerful with the oracle available

## 10. Sources

All wire-format constants, signing details, and trust-chain logic in section 2 are extracted from the technical research dossier (see source list at end of `docs/research/12_mysapsso2_research.md` companion).  Primary sources:

- `avadillo/SAPLogon` — canonical InfoUnitID enum, signing flow
- `OWASP/pysap` — SAPPSE / SAPCredv2 / SAPLPS parsing
- Martin Gallo, "Hunting Crypto Secrets in SAP Systems" (Core Security 2018)
- SAP KBA 3305584 / 3210987 / 2489523 (Logon Ticket / System PSE behaviour)
- SAP profile parameters: `login/create_sso2_ticket`, `login/accept_sso2_ticket`, `ssf/ssfapi_lib`
- SAP help: STRUSTSSO2 transaction, USREXTID mapping
- SAP Note 869962 (`sapssoext` library)
