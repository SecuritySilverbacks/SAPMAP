# CVE-2022-22536 (ICMAD) — SAPMAP Implementation Plan

Operationalizes the ICMAD entry sketched in
[`01_new_cves.md`](01_new_cves.md) §4 and
[`06_initial_access.md`](06_initial_access.md) §4.3 / §5.3. The dossier
covers *what's exploitable*; this file covers *how SAPMAP detects,
exploits, models, scores, and ships it* — and crucially, **corrects the
"session theft" framing** that the priority summary entry inherited from
the Onapsis marketing material.

The roadmap pointer in [`00_priority_summary.md`](00_priority_summary.md)
(item #1, Phase-2) is superseded by this plan.

Target output: **~350 LOC of new Python** in one new module
`sap_cve_2022_22536.py`, plus ~80 LOC of glue in `sapmap_scanner.py` /
`sapmap_gui.py` / context-menu wiring, one new finding category, one new
node-attribute flag, no new model classes. Build window: **3–4 days**,
not 1 week.

---

## Table of contents

- [A. Revised threat model — what ICMAD actually gives an attacker](#a-revised-threat-model)
- [B. The MPI desync primitive — byte-level](#b-the-mpi-desync-primitive)
- [C. Detection ladder](#c-detection-ladder)
- [D. Exploitation modes — what we ship, what we skip](#d-exploitation-modes)
- [E. Curated path catalogue for ACL-bypass mode](#e-curated-path-catalogue)
- [F. Findings + node attributes + context-menu wiring](#f-findings-node-attributes-context-menu)
- [G. Safety, blast radius, engagement etiquette](#g-safety-blast-radius-engagement-etiquette)
- [H. Day-by-day implementation plan](#h-day-by-day-implementation-plan)
- [I. Verification / open questions](#i-verification--open-questions)
- [J. References — re-read before coding](#j-references)

---

## A. Revised threat model

The priority summary entry calls ICMAD a "session hijack → MYSAPSSO2
into the RFC engine" lever. **This framing is wrong as a build target.**
After re-reading every public PoC and the Onapsis whitepaper:

- **No public PoC steals another user's session.** The "memory pipe
  desync can land an attacker response in a concurrent user's socket"
  claim is plausible from the bug shape but has never been demonstrated
  end-to-end in code. Onapsis showed it in an internal threat report;
  nobody has reproduced it. Building it would be a multi-week race-condition
  exploit-dev project, with engagement-day reliability close to zero.
- **The real, reproducible primitive is ACL bypass.** Smuggle a *second*
  HTTP request inside the body of an oversized first request; the ICM
  parses the inner request as if it originated from loopback
  (`X-Forwarded-For: 127.0.0.1` is honoured because the work process
  thinks the request came from the local ICM). That gets you
  unauthenticated access to surface that is supposed to be reachable
  only from the ICM host itself: `/sap/admin/*`, `/heapdump/`,
  `/ctc/ConfigServlet`, `/sld/*`, `/sap/bc/webdynpro/sap/itadmin`.
- **One of those surfaces — `/heapdump/` on AS Java — leaks the
  SecStore master key inside the Java heap.** That is the chain the
  tool should advertise: "ICMAD → heap dump → SecStore key → JCo
  password decryption → ABAP pivot". It uses primitives SAPMAP already
  ships (`sapmap_exploit.offline_decrypt_secstore`).
- **`/CTC/ConfigServlet` is RCE-equivalent** on AS Java instances that
  also lag CVE-2020-6287 — and CVE-2020-6287 already has its own SAPMAP
  module. ICMAD is the way to reach those servlets when they sit behind
  a Web Dispatcher with an ACL.

**Revised one-line pitch for the GUI tooltip:**
*"Internet-facing ICM/WebDispatcher with no auth gets the same view of
internal admin surface as a process running on localhost. No session
required, no victim traffic required, one-shot deterministic."*

**Important caveat from SAP Note 3123396 (v22, 2022-03-22):** the bug
only materialises into an exploit *when a gateway sits in front of the
ICM* (SAP Web Dispatcher, 3rd-party load balancer, reverse proxy).
"Direct access to SAP application servers is not vulnerable" — though
detection (the 2-response signature on a keep-alive socket) still
works against direct ICM because the ICM is both gateway and backend
in that case. See §C.2 for the topology table that drives the
severity logic.

---

## B. The MPI desync primitive

ICMAD is *not* a textbook CL.TE / TE.CL smuggle. The mechanism is:

1. ICM shares a fixed-size memory pipe (MPI) with each work process.
   Default request-side ring buffer ≈ 64 KB, hard cap ≈ 82 KB.
2. When the request body exceeds the buffer **and** the ICM
   short-circuits the request (serves a static asset, redirect, or
   admin page itself instead of forwarding), the ICM forgets to
   drain/reset the pipe.
3. The unread tail of the body — under attacker control — stays in the
   ring buffer.
4. The next reader on that pipe (either the work process picking up the
   next pipelined request, or the work process serving the next
   connection) parses the leftover bytes as the start of a new request.

Result: a single TCP socket carrying one *outer* request from the
attacker yields **two** HTTP responses on the wire — one to the outer
request, one to the *inner* request that nobody on the network actually
sent.

The canonical detection payload (lifted from
`Onapsis/onapsis_icmad_scanner/src/ICMAD_scanner.py`):

```
GET /sap/admin/public/default.html?aaa HTTP/1.1\r\n
Host: <target>\r\n
User-Agent: <anything>\r\n
Content-Length: 82646\r\n
Connection: keep-alive\r\n
\r\n
AAAAAA...A      <-- 82642 bytes of 'A' padding
\r\n\r\n
GET / HTTP/1.1\r\n
Host: <target>\r\n
\r\n
```

Fallback resources if the first 404s:

- `/sap/public/bc/ur/Login/assets/corbu/sap_logo.png`
- `/sap/public/bc/ur/nw5/themes/sap_corbu/img/sap.png`

**No `Transfer-Encoding` is involved.** Early reports that called this a
TE.CL bug were wrong; SAP's ICM rejects raw `Transfer-Encoding: chunked`
with a 408 before it can desync.

**Detection signal:** parse the byte stream with
`r'HTTP/\S+ (\d{3})'` — vulnerable target returns ≥2 responses on the
same socket, the *second* one's status is `400` or `5xx`. A patched
target returns exactly 1 response and closes the connection.

---

## C. Detection ladder

Cheapest → most expensive, implemented in a new
`sap_cve_2022_22536.py` and called from
`enrich_system_info()` (line 1398 in `sapmap_scanner.py`, immediately
after the new `/sap/public/info` hook so we have kernel + patch level
in hand).

| # | Probe | Cost | What it confirms | Short-circuit? |
|---|---|---|---|---|
| 1 | Kernel/patch lookup against ICMAD-fixed table (from `/sap/public/info` we already pulled) | 0 RTT | "patch missing" — guess only, no exploit run | Yes if patch ≥ table |
| 2 | TCP connect to ICM HTTP port (8000+NN or SAPControl-discovered) | 1 RTT | Port open | Yes if closed |
| 3 | `GET /sap/admin/public/default.html` baseline (no smuggle) | 1 RTT | Probe target is reachable; record status | Yes if 5xx — server too sick to test |
| 4 | Single-socket smuggle probe (the 82646-byte payload above) | 1 RTT | ≥2 responses ⇒ vulnerable; 1 response + clean close ⇒ patched | Final answer |
| 5 | (Exploit mode only) ACL-bypass probe against a curated path list | N RTT, opt-in | Which internal admin paths are reachable through the desync | — |

Probe 1 catches the long tail of patched-but-unsure systems without
firing a single byte of malformed HTTP, which is what we want by
default on engagements where the customer hasn't explicitly authorised
exploit-grade probing.

Probe 4 is the only one that fires the actual desync. It is:

- **One TCP socket**, no retries — re-firing on the same TCP tuple is
  what creates collateral risk on production ICMs (a desync that
  lingers across requests can affect *subsequent legitimate users*).
- **`Connection: close` on the outer request, but `keep-alive`-style
  pipelining inside the body.** This is the trick — the outer connection
  is single-use, but the inner smuggled request still hits the work-process
  pipe.
- **Wrapped in TLS via `ssl.create_default_context()` with
  `check_hostname=False`, `verify_mode=CERT_NONE`** when the discovered
  port is HTTPS (`https_p` from SAPControl). SAProuter tunnelling: same
  pattern as `query_public_info()` — `connect_through_saprouter()` then
  optionally wrap with SSL.

### C.1 Kernel patch boundary

Authoritative numbers from **SAP Note 3123396 v22 (2022-03-22)** —
"Support Package Patches" table. Fixed at patch level **≥ the number
below**. Both earlier sources we had (`06_initial_access.md` and the
research-agent crawl) were wrong — neither matches the actual note.

| Component | Kernel / WD branch | Fixed at PL ≥ |
|---|---|---|
| KERNEL | 7.22 (also 7.22 EXT, 7.22 EX2; 64-BIT and UC variants) | **1101** (rolling: 1115) |
| WEBDISP | 7.22_EXT | **1115** |
| KERNEL | 7.49 (also KRNL64NUC, KRNL64UC variants) | **1036** |
| WEBDISP | 7.49 | **1036** |
| KERNEL | 7.53 (also CONTSERV 7.53) | **915** |
| WEBDISP | 7.53 | **915** |
| KERNEL | 7.77 | **429** |
| WEBDISP | 7.77 | **429** |
| KERNEL | 7.81 | **227** |
| WEBDISP | 7.81 | **227** |
| KERNEL | 7.85 | **69** |
| WEBDISP | 7.85 | **69** |
| KERNEL | 7.86 | **15** |
| KERNEL | 7.87 | **4** |
| KERNEL | 8.04 64-BIT UNICODE | **207** |

**Out-of-maintenance:** pre-7.22 kernels are *not* covered by this
note — assume vulnerable. SAP's wording: *"Versions of SAP Kernel and
SAP Web Dispatcher that are out of maintenance and therefore not
covered by this note are affected by the vulnerability."*

Use these numbers in `ICMAD_FIXED_PATCHES`. Emit `info` severity when
the only evidence is the patch-table lookup. Promote to `high` only
when probe 4 succeeds, and to `critical` when probe D.2 confirms ACL
bypass to a high-value path.

### C.2 Vulnerability scope — gateway-in-front constraint

SAP Note 3123396 is explicit about *when* the bug actually
materialises into an exploit:

> *"The vulnerability exists when HTTP(S) clients (like browsers or
> other systems) access the SAP application server or SAP Web
> Dispatcher* **through** *an HTTP gateway that terminates TLS (in
> case of HTTPS) and processes the HTTP requests. […] Direct access
> to SAP application servers is not vulnerable."*

The five scenarios from the note:

| # | Topology | Vulnerable component(s) |
|---|---|---|
| 1 | client → app server (direct) | **none** — "not vulnerable" |
| 2 | client → SAP WebDisp → app server | app server |
| 3 | client → WebDisp1 → WebDisp2 → app server | WebDisp2 + app server |
| 4 | client → 3rd-party gateway → SAP WebDisp → app server | WebDisp + app server |
| 5 | client → 3rd-party gateway → app server | app server |

**This nuances the build plan in two ways:**

1. **Detection (D.1) can still fire on direct ICM** because the
   ICM itself behaves as both gateway and backend across a single
   keep-alive socket — the MPI buffer pollution still produces the
   2-response signature on the wire. The Onapsis scanner relies on
   exactly this and works against direct ICM in practice. So D.1
   remains useful as a "is the kernel patched?" oracle even on
   topology #1.
2. **Exploitation (D.2 / D.3) needs a gateway in the path.** The
   `X-Forwarded-For: 127.0.0.1` loopback-trust trick that gets the
   smuggled inner request promoted to "ICM-local" only works when
   the backend trusts a *real* upstream gateway — its own ICM
   parsing-from-its-own-pipe doesn't grant that trust.

Engagement-report wording therefore has to differentiate "kernel
unpatched (PL behind 3123396)" from "kernel unpatched AND
reachable-through-gateway". The former is a finding; the latter is
the actual exploit chain. Default reporting: emit the **higher**
severity only when SAPMAP can prove a gateway sits in front (e.g.
the discovered ICM port also responds at a separate WD port, or
the engagement scope includes a 3rd-party LB).

---

## D. Exploitation modes

Three modes, gated by the operator's intent. Default: detect-only.

### D.1 `detect` — ship this, default-on

What it does: probes 1–4 above. Emits one finding per vulnerable host.
No collateral risk: the smuggled inner request is `GET /`, which the
work process serves (or 400s) without side effects.

What it does NOT do: hit internal admin surface, no path enumeration,
no auth bypass attempts.

Where it runs: automatically as part of `enrich_system_info()` on every
ABAP system that exposes an ICM HTTP/HTTPS port. Reuses the port
already discovered by SAPControl or fallback ICM defaults — no
extra port-scanning.

### D.2 `acl-bypass` — ship this, opt-in via context menu

What it does: for each path in the curated catalogue (§E), send a
SAPGateBreaker-style chunked-trailer payload:

```
POST /sap/admin/public/default.html HTTP/1.1\r\n
Host: <target>\r\n
Transfer-Encoding: chunked\r\n
Connection: keep-alive\r\n
\r\n
0\r\n
\r\n
GET <internal-path> HTTP/1.1\r\n
Host: 127.0.0.1\r\n
X-Forwarded-For: 127.0.0.1\r\n
\r\n
```

(Note: ICMAD scanner uses CL-based padding for *detection* because TE
gets rejected by the front; SAPGateBreaker uses TE-based chunked
trailer for *exploit* because that's what carries the inner request
through to the work process. Both shapes desync the same MPI bug
because the front and back parsers disagree about which one terminates
the outer request.)

Cross-reference the response status of the smuggled inner request
against an unsmuggled baseline:

- Baseline `GET /sap/admin/...` from the same client IP → expect 403 /
  redirect to login.
- Smuggled `GET /sap/admin/...` via the desync → 200 ⇒ ACL-bypass
  confirmed.

Path catalogue (§E) is intentionally small (≤ 12 entries) and curated;
no fuzzing, no wordlist sweep, no `dirbuster`. We're a pentest tool,
not a scanner.

What it does NOT do: store / exfiltrate the body of any leaked admin
page beyond what's needed to confirm the bypass (HTTP status code +
first ~256 bytes of body for the report). No heap dumps actually
downloaded by default — see §G.

### D.3 `heapdump-pull` — ship this, gated behind a confirm prompt

The one case where we DO pull the body: when `/heapdump/` returns 200,
offer to download the heap dump (typically 200 MB – 4 GB), run it
through SAPMAP's existing
`tools/ssfs_decrypt/` / `sap_java_secstore_offline.py` extraction
pipeline, recover the SecStore master key, and feed it into the
existing JCo-password decryption flow. **This is the chain that makes
ICMAD worth the implementation cost.**

Gated behind an explicit confirm dialog — heap-dump download is
expensive, slow, and noisy on the wire. Default disabled.

### D.4 What we explicitly do NOT build

- **Session / MYSAPSSO2 theft from concurrent legit users.** No public
  PoC; race-condition-bound; engagement-day reliability ≈ 0 %. The
  priority-summary blurb framing this as the main lever is **deprecated
  by this plan**.
- **Cache poisoning of `/sap/public/...` static assets.** Requires
  Web Dispatcher caching enabled (not default for authenticated
  content), high collateral risk, no clean way to clean up. Skip.
- **Response-queue poisoning to land stored-XSS in a victim's
  browser.** Same problem as session theft — theoretical, no PoC, not
  demoable in a 5-day engagement.
- **CSRF token bypass via desync.** Implied in advisories, never
  demonstrated end-to-end.
- **Detection-by-timing fingerprint** (sending half a Content-Length
  body and measuring RTT). Less reliable than the response-count
  fingerprint and noisier on the wire. The Onapsis scanner does NOT
  use timing; we don't either.

---

## E. Curated path catalogue

Twelve paths, hand-picked, each with a one-line rationale and the
follow-on primitive SAPMAP already has:

| Path | Why it matters | Downstream chain |
|---|---|---|
| `/heapdump/` (AS Java) | Heap dump contains SecStore master key | → `sap_java_secstore_offline.py` |
| `/sap/admin/` | ICM admin UI; lists active sessions, ICF nodes | Recon only — no further chain |
| `/sap/admin/public/default.html` (used as the *outer* request anchor in the smuggle) | Confirms ICM is the target, not a fronted app | n/a |
| `/CTC/ConfigServlet` | Java config servlet — `EXECUTE_CMD` action = RCE on unpatched J2EE | → already in `sap_cve_2020_6287.py`; ICMAD reaches it when behind WebDisp |
| `/ctc/SAPMyApplications/jsps/listAllApps.jsp` | Lists installed J2EE apps, leaks SCS hostnames | → drives `_detect_and_set_system_type` |
| `/sld/` | System Landscape Directory UI; lists every ABAP+Java system in the landscape | → free landscape map, no auth |
| `/sap/bc/webdynpro/sap/itadmin` | WebDynpro admin servlet — user enum on unpatched | → user list feeds `sap_default_creds.py` |
| `/run/jsp/index.jsp` (AS Java) | NWA-style admin entry; presence ⇒ AS Java internal admin reachable | Recon |
| `/nwa/` | NWA web UI; auth gate; presence + auth-required ⇒ confirms Java tier | Recon |
| `/UserAdmin/` (AS Java UME) | UME admin entry — auth required, presence ⇒ pivot target | → feeds RECON / SAPLogonTicket forging |
| `/EemAdminService/EemAdmin` | SolMan EEM unauth admin (CVE-2020-6207) on SolMan | → already in `sap_cve_2020_6207` |
| `/scc/` (SCC admin UI) | Confirms an SCC behind the ICM — rare but high-value | → triggers `sapmap_scc_fingerprint` chain |

The list is intentionally small — wider sweeps add noise without
adding kill-chain depth. The job of the ICMAD module is to **prove the
bypass works** and **hand control to existing SAPMAP modules**, not to
re-implement everything.

---

## F. Findings, node attributes, context-menu wiring

### F.1 New finding category

`icmad.desync.confirmed`

- Severity: **HIGH** when probe 4 confirms; **MEDIUM** when only the
  kernel patch table flags it.
- Title: *"ICM HTTP request smuggling (CVE-2022-22536)"*
- Detail: kernel + patch level + probe response.
- Remediation: SAP Note 3123427 (kernel) + 3123396 (Web Dispatcher) +
  workaround `wdisp/additional_conn_close=1` if patch can't ship
  immediately.

`icmad.acl.bypass.confirmed`

- Severity: **CRITICAL** when smuggled path returns 200 for an
  authenticated admin endpoint; **HIGH** for sensitive-but-non-admin
  paths.
- Per-path detail. Promotes the node's `has_critical_finding` flag.

`icmad.heapdump.captured`

- Severity: **CRITICAL**. Pwned-state.
- Detail: file path of saved heap dump + size + whether SecStore key
  recovery succeeded.

### F.2 SAPNode attributes (no new model fields needed)

Reuse existing pattern from `cve_2020_6287_port` / `cve_2020_6287_evidence`:

- `cve_2022_22536_port: int` — the ICM port the desync was confirmed on
- `cve_2022_22536_https: bool` — was the probe over HTTPS
- `cve_2022_22536_evidence: str` — first ~256 bytes of the second
  HTTP response (for the report)
- `cve_2022_22536_acl_bypass: dict` — `{path: status_code}` for the
  curated catalogue, populated only when D.2 runs

### F.3 Context-menu wiring

Add to the ABAP-node right-click menu (gated on `system_type in
{"ABAP", "ABAP+JAVA", "JAVA"}` — pure-ABAP is in scope because the ICM
runs there too, and pure-Java is in scope for the heap-dump chain):

- **Exploitation → ⚡ Check ICMAD (CVE-2022-22536)** — runs detect mode
  (always safe-ish, opt-in only because of the wire-noise)
- **Exploitation → ⚡ ICMAD → ACL-bypass sweep** — runs D.2, gated on
  prior detect success
- **Exploitation → ⚡ ICMAD → Pull heap dump** — runs D.3, gated on D.2
  showing `/heapdump/` reachable, gated on explicit confirm prompt

Edge case for **standalone Web Dispatcher** nodes (which `SAPNode` doesn't
currently distinguish from app-server nodes — see §I): same menu items.
The desync works against a Web Dispatcher in front of the actual ICM
just as well.

### F.4 GUI — visual indicator

In `sapmap_html.py`, when `cve_2022_22536_port` is set, draw a small
indicator on the SVG node similar to the existing CVE-2020-6287 badge.
Suggested glyph: an "MPI" tag (matches the Onapsis branding so anyone
who knows the bug recognises it immediately).

### F.5 Engagement report

Section template, dropped into the existing engagement-report flow in
`sapmap_engagement_report.py`:

```
## ICMAD (CVE-2022-22536)

- Confirmed: {N} ABAP / Java / Web Dispatcher hosts
- ACL bypass to internal admin surface: {paths_table}
- Heap dump captured: {heapdump_file or "not pulled"}
- Chained recovery: {secstore_key or "none"} → JCo passwords: {n}

Customer impact: an unauthenticated attacker on the same network as
{first_target} would, without any valid SAP credential, reach
administrative surface that the network architecture intends to keep
internal-only. This includes {worst_path}, which {worst_path_impact}.
```

Reuse the existing markdown→HTML pipeline; no new templates.

---

## G. Safety, blast radius, engagement etiquette

ICMAD is a desync bug. Misfire stories from the smuggling literature
(notably Albinowax's HTTP/2 desync work) are real: a desync that
lingers in the front-end can affect *the next legitimate user*. SAP's
MPI implementation is per-pipe-per-work-process, so the blast radius
is narrower than HTTP/1.1 keep-alive smuggling against nginx, but the
risk is non-zero.

Rules baked into the module:

1. **One probe per host per scan.** No retries on success or failure.
   If probe 4 is ambiguous (1 response but close-without-reset), flag
   `inconclusive` rather than re-running.
2. **`Connection: close` on the outer request always.** We don't
   pipeline more than one smuggled inner request per TCP connection.
3. **Throttle: 1 ICMAD probe per ICM per 30 seconds.** Engagement-day
   parallelism is fine across hosts; back off hard against any single
   ICM.
4. **Refuse to run against `cve_2022_22536_port` once it's already
   confirmed.** Re-running gains no information and adds risk.
5. **No heap dump pulled without explicit GUI confirm.** Heap-dump
   downloads can take minutes and saturate the link.
6. **Log every smuggled byte** to the per-engagement log directory so
   the customer can reconstruct exactly what was sent if a stability
   incident is investigated post-engagement.
7. **Out-of-hours gating** (future, not v1): a config flag refusing to
   run ICMAD probes against systems labelled `prod` outside the
   customer's declared maintenance window.

---

## H. Day-by-day implementation plan

Build window: **3 working days for D.1 + D.2**, **+1 day for D.3** if
the heap-dump chain is in scope.

### Day 1 — Detection (D.1)

- New module `sap_cve_2022_22536.py` (~150 LOC):
  - `_build_detect_payload(host, port)` — returns the canonical
    Onapsis-style request bytes.
  - `_count_responses(buf)` — regex on `HTTP/\S+ (\d{3})`, returns
    list of statuses.
  - `probe_icmad(host, port, https=False, saprouter="", timeout=10)`
    → returns dict `{vulnerable: bool, responses: list[int],
    evidence: bytes, error: str}`.
  - Patch-table dict `ICMAD_FIXED_PATCHES` (use the
    `06_initial_access.md` numbers, with `# TODO §I` comment).
- Hook into `enrich_system_info()` in `sapmap_scanner.py`: after the
  `/sap/public/info` block, if `info["http_ports"]` non-empty and not a
  Java-only stack, call `probe_icmad()` on the first available HTTP
  port. Populate `info["cve_2022_22536_port"]` / `_https` / `_evidence`.
- Wire emission of `icmad.desync.confirmed` finding via
  `sapmap_findings.emit_finding()`.
- Tests: parser unit tests (single response vs ≥2 responses vs
  malformed), patch-boundary tests for every kernel in the table.

### Day 2 — ACL bypass (D.2)

- Extend `sap_cve_2022_22536.py` (~120 LOC additional):
  - `_build_acl_bypass_payload(target_path, host, port)` — the
    chunked-trailer variant with `X-Forwarded-For: 127.0.0.1`.
  - `run_acl_bypass(host, port, paths, …)` returning
    `{path: (status, body_snippet)}`.
  - `_baseline_request(host, port, path, …)` — same path without
    smuggle, for status comparison.
- Curated path catalogue (§E) as a module constant.
- GUI handler `/api/node/<sid>/icmad_acl_bypass` — pattern matches the
  existing `node_check_gw` shape in `sapmap_gui.py:3933`.
- Context-menu entries in `sapmap_html.py` — gate on
  `cve_2022_22536_port`.
- Tests: synthetic fixture responses, path-status mapping, refusal to
  run when desync not yet confirmed.

### Day 3 — Reporting, GUI badges, throttling, engagement-report section

- Visual indicator on the node SVG (matches CVE-2020-6287 badge
  pattern).
- Engagement-report markdown section.
- Throttle wrapper (one ICMAD probe per ICM per 30 s; reuse the
  existing `sapmap_pacer` if it has the API, else build a tiny
  per-host lock).
- Integration test: full flow on a recorded fixture.

### Day 4 (optional) — Heap-dump chain (D.3)

- `node_icmad_heapdump_pull` GUI handler.
- Streaming download with progress; gates on size; ABORT after 2 GB
  unless operator overrides.
- Pipe into `sap_java_secstore_offline.recover_master_key_from_heap()`
  (already exists per `07_java_secstore_recovery.md`).
- If key recovers, feed into the existing JCo decrypt → ABAP pivot
  flow; new finding `icmad.heapdump.captured` with chain details.

---

## I. Verification / open questions

1. ~~**Patch-boundary table.**~~ **RESOLVED 2026-05-11.** SAP Note
   3123396 v22 was pulled directly and the authoritative numbers are
   now in §C.1. Both earlier sources (`06_initial_access.md` hand-entry
   and the research-agent crawl) were wrong. The numbers in §C.1 are
   ground truth — also update `06_initial_access.md` §4.3 when shipping
   the code.
2. **Standalone Web Dispatcher detection.** SAPMAP's `SAPNode` model
   doesn't currently have a `is_web_dispatcher` flag. The TLS-fingerprint
   pattern from
   [`08_cloud_connector_implementation_plan.md`](08_cloud_connector_implementation_plan.md)
   §A.1 may be adaptable — Web Dispatcher ships with the same
   sapwebdisp + ICM stack. Recommend adding `node.is_web_dispatcher`
   bool to `SAPNode` and a fingerprint that compares
   `Server: SAP NetWeaver Application Server <ver> / ICM <ver>` vs.
   `Server: SAP Web Dispatcher <ver>`.
3. **Content Server.** Same vulnerable ICM, separate patch cycle,
   typically firewalled but reachable from app servers. Should the
   ICMAD module also fingerprint a Content Server signature? Out of
   scope for v1 — flag for v2.
4. **MPI buffer size variants.** Onapsis tested 82646 bytes. Some
   tuned ICMs configure `rdisp/buffer_size_max` higher; the smuggle
   may not trigger. Plan: keep 82646 as the v1 magic number; add a
   `--buffer-size` operator flag in v2 if a real-world engagement
   shows misfires.
5. **HTTPS-only ICMs.** Probe via SSL-wrapped socket. SNI handling:
   send `<target_host>` as SNI by default; allow override via
   `node.virtual_host` (we already track that for the SCC PP probe).
6. **SAProuter tunnelling.** The desync should survive a SAProuter
   tunnel since the router is transparent at the TCP-byte level. Need
   one engagement-day validation pass — not blocking for v1.

---

## J. References

Re-read these before opening the editor — the byte-level details
matter.

- **Onapsis canonical scanner.** [github.com/Onapsis/onapsis_icmad_scanner](https://github.com/Onapsis/onapsis_icmad_scanner)
  → read `src/ICMAD_scanner.py`. Every other public PoC is a fork.
- **SAPGateBreaker (only public weaponisation).** [github.com/BecodoExploit-mrCAT/SAPGateBreaker-Exploit](https://github.com/BecodoExploit-mrCAT/SAPGateBreaker-Exploit)
  → the `build_smuggled_request()` function is the template for D.2.
- **Burp-Repeater payload mirrors.** [github.com/tess-ss/SAP-memory-pipes-desynchronization-vulnerability-MPI-CVE-2022-22536](https://github.com/tess-ss/SAP-memory-pipes-desynchronization-vulnerability-MPI-CVE-2022-22536)
  → `burp-request-1.md` / `burp-request-2.md` for manual reproduction.
- **Exploit-DB 52109.** [exploit-db.com/exploits/52109](https://www.exploit-db.com/exploits/52109)
  → cleanest writeup of the status-code delta (direct 403 vs smuggled 200).
- **Onapsis whitepaper.** [onapsis.com/icmad-vulnerabilities](https://onapsis.com/icmad-vulnerabilities/)
  → the original advisory, MPI mechanism diagram.
- **Tenable analysis.** [tenable.com/blog/cve-2022-22536-sap-patches-internet-communication-manager-advanced-desync-icmad](https://www.tenable.com/blog/cve-2022-22536-sap-patches-internet-communication-manager-advanced-desync-icmad)
  → second-source confirmation of impact framing.
- **SecurityBridge breakdown.** [securitybridge.com/blog/details-about-sap-vulnerability-cve-2022-22536-request-smuggling](https://securitybridge.com/blog/details-about-sap-vulnerability-cve-2022-22536-request-smuggling/)
  → byte-level Wireshark trace; useful for the parser unit test.
- **CISA KEV listing.** [cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2022-22536)
  → due-date / "in-the-wild" framing for the engagement-report intro.
- **NVD.** [nvd.nist.gov/vuln/detail/CVE-2022-22536](https://nvd.nist.gov/vuln/detail/cve-2022-22536)
  → CVSS 10.0, vendor advisory link.
- **SAP Notes (launchpad-gated, customer login required):**
  3123396 (patch), 3138881 (Web Dispatcher-only mitigation), 3137885
  (kernel fix boundary).

Skip:

- `github.com/ZZ-SOCMAP/CVE-2022-22536`, `github.com/antx-code/CVE-2022-22536`,
  `github.com/errorfiathck/icmad-exploit` — byte-identical Onapsis-scanner
  forks. Nothing new in any of them.

---

## Bottom line

ICMAD is worth building, but **not as a session hijacker**. Build:

- **Detection** — kernel-patch table + single-shot 82646-byte smuggle probe.
- **ACL bypass** — chunked-trailer smuggle with `X-Forwarded-For:
  127.0.0.1`, sweeps a curated 12-path catalogue.
- **Heap-dump → SecStore key chain** — optional, the one
  high-impact follow-on that justifies the engineering cost.

Skip session theft, cache poisoning, response-queue poisoning,
CSRF bypass — all theoretical, none demoable on engagement day.

Build cost: 3 days for the core, 4 days with the heap-dump chain.
Expected hit rate on internet-facing engagements: 15–30 %. Expected
hit rate on internal engagements (separately-patched DMZ tiers,
Content Server, sandbox/QA systems): 40–60 %.
