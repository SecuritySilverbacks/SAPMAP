# Plan — Add dpmon Virtual SAP* Activation as an LPE / Exploit Primitive

## 1. Background

**Source:** SAP Note 3303172 — *Time-limited client-specific activation of the virtual super-user SAP\**.
**Community write-up:** <https://community.sap.com/t5/technology-blog-posts-by-members/limited-time-activation-of-virtual-super-user-sap/ba-p/14104637>

From the article (verbatim):

> Time-limited client-specific activation of the virtual super-user SAP\*, available as of kernel release 790:
> 1. Logon to the operating system of an application server using `<sid>adm` user.
> 2. Start the interactive tool `dpmon` with menu option `u` to activate the virtual client-specific super-user SAP\* in a chosen client. Define a period of between 10 and 30 minutes as validity. You will obtain a one-time password after successful activation.
> 3. Logon using user SAP\* and the one-time password you have obtained on any currently running application server.

Key constraints:
- **Kernel ≥ 790 only** (rolled out 2024).
- Runs as `<sid>adm` (or root) at OS level.
- Per-client; max **20 virtual SAP\* in parallel** across different clients.
- Validity window **10–30 minutes**, chosen at activation.
- **Any** password-based logon attempt for SAP\* (success OR failure) invalidates the OTP immediately — so the OTP must be used in one clean RFC connection, no retries.
- Audit-logged as **EUP event, purpose 2** — not stealthy.
- Supersedes an existing real SAP\* and an emergency SAP\* in the same client while active.
- No application-server restart needed — pure runtime feature, no static profile parameter.
- The same activation also lets the operator **list** existing virtual super-users and **delete** them before expiry (also from `dpmon`).

## 2. Why it matters for SAPMAP

The classic chain from OS-exec → permanent SAP_ALL today is:

```
GW SAPXPG / SXPG / CVE-31324 shell   →   DB-specific SQL writer
                                          (USR02 + UST04 + USRBF2 inserts)
                                          per DB dialect (HDB/MSS/ORA/MaxDB/DB2)
                                  →   verify via RFC logon
```

Brittle bits today:
- Six DB dialects to maintain in `modules/exploitation/sap_db_sql_writers.py`.
- CODVN / hash format matrix per kernel (B vs G vs I).
- Database paths sometimes blocked by SCC4 client lock or DBCO routing.
- Multiple OS commands per system → big SAPXPG chunk budget on the GW path.

The dpmon path collapses all that to:

```
OS exec as <sid>adm   →   dpmon (one invocation)
                      →   OTP captured from stdout
                      →   RFC logon as SAP*/<OTP>/<client>  ← single attempt
                      →   BAPI_USER_CREATE1 — permanent SAPMAP00 with SAP_ALL
                      →   done
```

Benefits:
- **DB-agnostic** — works on any backend (HANA, ASE, Oracle, MaxDB, MSSQL, DB2).
- **Kernel-blessed** — SAP itself documents and supports this. Won't be patched out the way unauthenticated CVEs get patched.
- **Faster on GW path** — single dpmon call vs. ~40 SAPXPG chunks for the SQL writer payload.
- **Cleaner state** — one OTP, one BAPI call. No leftover DB rows on the production tables before BAPI commits.
- **Higher reliability on hardened systems** — bypasses S_RFC, S_TCODE, S_LOG_COM authorization checks because the BAPI session is opened as SAP\* (which has all authorizations implicit).

Operational cost:
- **Audit log entry** (EUP purpose 2). Honest with the operator: this is documented and not stealthy.
- **Kernel ≥ 790** gate excludes ~70% of installed base today. Pre-flight check makes this graceful.

## 2a. Stack eligibility — ABAP only

This feature is an **ABAP-stack** primitive end-to-end:

- `dpmon` is the SAP dispatcher monitor — ABAP work-process tool, lives in `/usr/sap/<SID>/<INST>/exe/` of an ABAP application server.
- `SAP*` is an ABAP user (stored in `USR02`, looked up via the ABAP login layer).
- The post-OTP step calls `BAPI_USER_CREATE1` over RFC — an ABAP RFC function.  Java AS has no RFC stack.

So the eligibility gate is **`"ABAP" in (node.system_type or "").upper()`** — accepts:

- `ABAP`
- `ABAP+JAVA` (dual-stack — ABAP side is reachable)

and **rejects**:

- `JAVA` (pure Java AS — no ABAP runtime, nothing to activate)
- `HANA` (HANA-only database hosts)
- `WEB_DISPATCHER`, `SAPROUTER` (no app-server runtime)

## 2b. OS-exec channels — ABAP-side only

The CVE-2025-31324 JSP webshell channel (Java-stack RCE) is **deliberately excluded** as a delivery vector for dpmon, even on dual-stack systems where it might technically work.  Reasons:

- Conceptual clarity — dpmon is ABAP-side, the JSP runs in the Java VM; mixing them adds branching for a path that doesn't make the feature more useful.
- On dual-stack the ABAP gateway is reachable anyway, so GW SAPXPG covers the unauthenticated case.
- Simpler test surface — three channels to validate (GW / SXPG / WebGUI), not four.

The relevant channels are therefore:

| Channel | Auth | Notes |
|---|---|---|
| **GW SAPXPG** (`execute_gw_command`) | Unauth | Tier-1 path on GW-vulnerable nodes |
| **SXPG_STEP_XPG_START** (RFC) | Authenticated, needs S_LOG_COM | Used when we already have creds |
| **WebGUI RSBDCOS0** (HTTP) | Authenticated, needs SE38/RSBDCOS0 tcode | Used in the LPE path (mirrors existing `lpe_webgui_sm49`) |

## 3. Two integration points

The primitive is the same, but it slots into two flows:

### 3a. **LPE method** (`@lpe_method`)

Use case: operator has **authenticated creds without SAP_ALL** on a node, but the user has `S_LOG_COM` (SM49) or can submit RSBDCOS0 / SE38 — i.e., authenticated OS-exec.

Flow:
1. WebGUI session → SE38/RSBDCOS0 → run `dpmon` (existing infrastructure already shipped in `lpe_webgui_sm49`).
2. Parse OTP from RSBDCOS0 stdout.
3. Open RFC connection as `SAP*` / `<OTP>` / `<client>`.
4. `BAPI_USER_PROFILES_ASSIGN(USERNAME=<original_user>, PROFILES=[SAP_ALL, SAP_NEW])`.
5. Commit. Discard SAP* session.

Priority: between `bapi_profiles_assign` (10) and `webgui_sm49` (50) — say **20**. Tried after the cheap BAPI shot (in case the user already has S_RFC for the function group) but before the heavier WebGUI SQL chain.

### 3b. **Phase-2 exploit method** (Phase 2 of AutoPwn / right-click *Create User via dpmon*)

Use case: operator has **OS-exec via any means** — GW SAPXPG (unauth), CVE-2025-31324 webshell (unauth), or existing creds with SM49. Wants a fresh `SAPMAP00` with SAP_ALL on the node, no DB writer needed.

Flow:
1. Detect kernel ≥ 790.
2. Acquire OS-exec primitive (`exec_fn(cmd) -> stdout`) — wrap whichever channel is available.
3. Run `dpmon` via `exec_fn`, parse OTP.
4. RFC logon as SAP*/<OTP>/<client> → `BAPI_USER_CREATE1` for SAPMAP00 with SAP_ALL.
5. Return `CreatedUser`.

AutoPwn priority chain (current order: GW-ABAP / CVE-31324 / RECON / GW-Java / 10KBlaze) gets a new path. Where it fits depends on what we have:
- On ABAP nodes with kernel ≥ 790 AND a working OS-exec source → tier-1 path (faster, cleaner than GW SQL inserts).
- If kernel < 790 → skip; fall back to existing chain.

## 4. Architecture

```
modules/exploitation/sap_dpmon_sapstar.py    ← NEW core primitive
  ├─ activate_virtual_sap_star(exec_fn, sid, instance_nr,
  │                             client, duration_min=10) -> dict
  ├─ parse_dpmon_output(stdout) -> dict                ← regex parser
  ├─ list_virtual_sap_stars(exec_fn, sid, instance_nr) -> list
  ├─ delete_virtual_sap_star(exec_fn, sid, instance_nr,
  │                          client) -> bool
  └─ _build_dpmon_input_script(action, client, duration_min) -> str

modules/exploitation/sapmap_exploit.py       ← thin wrapper
  └─ create_user_via_dpmon_sap_star(node, state) -> CreatedUser | None
       — picks an exec channel, calls activate_virtual_sap_star,
         then BAPI_USER_CREATE1 as SAP*/<OTP>/<client>.

modules/postex/sapmap_lpe.py                 ← LPE registration
  └─ @lpe_method("dpmon_sap_star", priority=20)
     lpe_dpmon_sap_star(node, creds)
       — uses WebGUI RSBDCOS0 to run dpmon, then RFC logon as SAP*/<OTP>,
         then BAPI_USER_PROFILES_ASSIGN on `creds.username`.

modules/discovery/sapmap_scanner.py          ← detection
  └─ Set node.dpmon_sap_star_available = True when kernel >= 790.

modules/exploitation/sapmap_autopwn.py       ← AutoPwn integration
  └─ Phase 2: new priority slot for "try dpmon SAP*".

modules/core/sapmap_html.py                  ← UI
  └─ AutoPwn modal: new checkbox "Activate virtual SAP* via dpmon".
  └─ Right-click ABAP node menu: "Create User via dpmon (kernel ≥ 790)".
```

## 5. The dpmon driving problem

`dpmon` is interactive — menu-driven. We need to feed it `u`, then `<client>`, then `<duration>`, then `q` (quit). Three robustness tiers:

1. **Tier 1 — piped stdin (preferred):**
   ```sh
   printf 'u\n%s\n%d\nq\n' '<client>' <duration> | /usr/sap/<SID>/<INST>/exe/dpmon
   ```
   Works on most kernels — `dpmon` doesn't strictly require a TTY.

2. **Tier 2 — heredoc with explicit flush:**
   ```sh
   /usr/sap/<SID>/<INST>/exe/dpmon <<'EOF'
   u
   <client>
   <duration>
   q
   EOF
   ```

3. **Tier 3 — `script -q -c` PTY wrapper (Linux fallback):**
   If dpmon checks for TTY:
   ```sh
   script -q -c "echo -e 'u\n<client>\n<duration>\nq' | /usr/sap/<SID>/<INST>/exe/dpmon" /dev/null
   ```

Implementation tries Tier 1 first; on empty/error output, escalates to Tier 2, then Tier 3. The result is captured in stdout and parsed.

### 5a. dpmon path resolution

Standard locations on app servers:
- Linux: `/usr/sap/<SID>/<INST>/exe/dpmon`  (e.g. `/usr/sap/S4H/D00/exe/dpmon`)
- Linux: `/sapmnt/<SID>/exe/dpmon`  (shared kernel directory)
- Windows: `D:\usr\sap\<SID>\<INST>\exe\dpmon.exe`

Strategy: try each in order. The instance number comes from `node.instances[0].instance_nr`. If multiple instances exist, prefer one that we already have OS-exec on.

### 5b. OTP parsing

The article's screenshots (referenced but not parseable from the community text) suggest output like:

```
Virtual super-user SAP* successfully activated in client 100.
One-time password: A3kp9wQz!7Lm
Valid until: 14:25:30 (10 minutes from now).
```

Implement a tolerant regex parser:

```python
_DPMON_OTP_RE = re.compile(
    r"(?:one[-\s]?time\s+password|temporary\s+password|password)\s*[:=]\s*"
    r"([A-Za-z0-9!@#$%^&*()_+={}\[\]:;<>?,./~`|\\-]{8,32})",
    re.IGNORECASE,
)
_DPMON_VALID_UNTIL_RE = re.compile(
    r"valid\s+until\s*[:=]?\s*(\d{1,2}:\d{2}(?::\d{2})?)",
    re.IGNORECASE,
)
_DPMON_CLIENT_RE = re.compile(
    r"client\s+(\d{3})", re.IGNORECASE,
)
_DPMON_SUCCESS_RE = re.compile(
    r"(?:successfully\s+activated|activation\s+successful|virtual\s+super[\s-]?user\s+SAP\*\s+activated)",
    re.IGNORECASE,
)
```

Keep raw stdout in the returned dict for debugging and audit. If parsing fails, surface the raw output to the operator so the regex can be tightened in a hot-fix release.

## 6. Pre-flight detection

Add `dpmon_sap_star_available: bool` to `SAPNode`:
- Set `True` when **all** of the following hold:
  1. `kernel >= "790"`
  2. `"ABAP" in (node.system_type or "").upper()` — accepts `ABAP` and `ABAP+JAVA`, rejects pure `JAVA`, `HANA`, `WEB_DISPATCHER`, `SAPROUTER`.
- Detection happens during deep scan (kernel comes from RFC_SYSTEM_INFO / SAPControl `GetVersionInfo`).
- Already populated as `node.kernel` (string like `"753"`, `"790"`, `"793"`, etc.).
- Comparison: numeric-aware — strip leading zeros, treat as int. `"7_90"` style strings also valid (rare).

Gate every method on this flag:
```python
def lpe_dpmon_sap_star(node, creds):
    if not _kernel_ge(node.kernel, 790):
        return False
    ...
```

Helper:
```python
def _kernel_ge(kernel_str: str, target: int) -> bool:
    """`kernel_str` is "753" / "790" / "7.90" / "7_90".  Returns True
    if numeric >= `target`."""
    if not kernel_str:
        return False
    digits = re.sub(r"\D", "", kernel_str)
    try:
        return int(digits) >= target
    except ValueError:
        return False
```

## 7. Post-OTP flow — the critical single-shot

Because **any** password-based logon attempt invalidates the OTP, the BAPI step must be a single clean RFC call with no retries on bad credentials. Implementation:

```python
def _activate_and_create_user(exec_fn, node, state, target_user):
    # 1. Activate via dpmon
    act = sap_dpmon_sapstar.activate_virtual_sap_star(
        exec_fn=exec_fn,
        sid=node.sid,
        instance_nr=_pick_instance_nr(node),
        client=_pick_client(node),
        duration_min=10,
    )
    if not act["success"]:
        return None  # OTP not obtained, abort

    # 2. Single RFC call as SAP* / OTP — NO retry, NO probing.
    sap_star_creds = Credentials(
        username="SAP*",
        password=act["otp"],
        client=act["client"],
        instance_nr=act["instance_nr"],
        verified=False,
    )
    try:
        with sapmap_rfc._get_connection(node, sap_star_creds) as conn:
            # 3. Create persistent SAPMAP00 with SAP_ALL.
            r = conn.call("BAPI_USER_CREATE1",
                          USERNAME=target_user,
                          PASSWORD={"BAPIPWD": sapmap_config.SAPMAP_PASSWORD},
                          ADDRESS={"FIRSTNAME": "SAPMAP", ...},
                          LOGONDATA={"USTYP": "S", "CLASS": ""},
                          PROFILES=[{"BAPIPROF": "SAP_ALL"},
                                    {"BAPIPROF": "SAP_NEW"}])
            # check RETURN, commit, etc.
            conn.call("BAPI_TRANSACTION_COMMIT", WAIT="X")
    except Exception as e:
        # OTP is now burned regardless — log and surface.
        return None
    return CreatedUser(username=target_user, ..., method="dpmon_sap_star")
```

Client selection (`_pick_client`):
- Prefer clients already in `node.clients` (we know they exist).
- Fall back to `001`, `100`, `200`.
- The article doesn't specify a hard ceiling on which clients accept activation — any valid client works.

Instance selection (`_pick_instance_nr`):
- Use the one OS-exec is bound to (e.g., if we got OS-exec via SAPXPG on instance `00`, pass `00`).
- For the dpmon binary path, `/usr/sap/<SID>/<INST>/exe/` follows the same instance.

## 8. AutoPwn integration

Add to `AutoPwnConfig`:
```python
try_dpmon_sap_star: bool = True   # Phase-2 path, kernel ≥ 790 only
```

Add modal checkbox:
```html
<label class="autopwn-cb">
  <input type="checkbox" id="apwn-dpmon-sapstar" checked>
  dpmon virtual SAP* (kernel ≥ 790)
</label>
```

Phase 2 priority chain becomes:
1. GW SAPXPG (ABAP / dual-stack) — fastest unauth OS-exec path
2. **dpmon SAP\*** (kernel ≥ 790, ABAP-side, OS-exec available) — DB-agnostic, blessed by SAP ← **NEW**
3. CVE-2025-31324 (Java HTTP open)
4. CVE-2020-6287 RECON (Java)
5. GW-Java (Java + GW vuln)
6. 10KBlaze betrusted

Rationale for slot 2: when kernel ≥ 790 AND we already have GW SAPXPG OS-exec on an ABAP / dual-stack node, dpmon is strictly better than the SQL writer chain — same OS-exec, fewer commands, no DB-dialect risk.  So it slots in right after the basic GW check.

The dpmon slot is **only consulted for ABAP / dual-stack nodes** (`"ABAP" in node.system_type`).  On pure-Java nodes phase 2 jumps straight from slot 1 (no GW-ABAP available) to slot 3 (CVE-2025-31324).

The OS-exec source feeding dpmon comes from the GW SAPXPG channel (or, in the authenticated re-run case, an existing SXPG capability).  The Java CVE-31324 JSP webshell is **not** used to drive dpmon — even on dual-stack, the ABAP gateway is reachable for GW SAPXPG, which is the clean path.

## 9. Edge cases & failure modes

| Condition | Handling |
|---|---|
| `node.kernel < "790"` | Skip method outright; print `[*] {sid}: dpmon SAP* needs kernel ≥ 790 (have {kernel})`. |
| 20 virtual SAP\* already active (rare) | dpmon will error — parse the error from stdout, surface `[ACTION_NEEDED]` flag, fall through to next exploit. |
| Client picked is locked (CCCFLG=X / system msg locked) | Activation may still succeed but BAPI will fail. Retry once with a different client. |
| dpmon binary not in standard path | Fall through after probing 3 paths; surface "dpmon not found at /usr/sap/SID/INST/exe/, /sapmnt/SID/exe/, <PATH>". Operator can override via `node.dpmon_path`. |
| OS-exec primitive needs TTY (rare hardened envs) | Tier 3 PTY wrapper via `script -q -c`. |
| OTP parsing failed | Return failure with the full raw stdout in `error` and `stdout` keys so operator sees what dpmon produced; tighten regex in a follow-up. |
| BAPI call after OTP failed | The OTP is burned regardless. Log + return None. Next AutoPwn wave will re-activate (new OTP) if other conditions hold. |
| Audit log entry visible to SOC | This is documented and not stealthy. Mention in finding text + README so operator knows the EUP audit record is there. |
| Existing real SAP\* in the client | Virtual SAP\* supersedes for its validity window. No conflict — but worth a finding-level note. |
| Concurrent activations from competing operators | Hardly a real concern; 20-parallel limit is generous. |

## 10. Test plan

### Unit / source-level
- `test_dpmon_module_registered` — module importable, functions exposed.
- `test_lpe_method_registered_with_kernel_gate` — `@lpe_method` decorator runs, method appears in `get_lpe_methods()`, priority=20.
- `test_kernel_version_helper` — `_kernel_ge("790", 790)`, `_kernel_ge("753", 790)`, `_kernel_ge("7.90", 790)`, edge cases.

### OTP parser (no network)
- Fixtures: snippets of synthetic dpmon output in `tests/fixtures/dpmon_output/`:
  - `success.txt` — `One-time password: <pwd>` + client + valid_until.
  - `success_germanlocale.txt` — `Einmalpasswort: <pwd>` (if dpmon is locale-aware).
  - `error_max20.txt` — error path when 20 virtual SAP* exist.
  - `error_invalid_client.txt`.
  - `error_kernel_too_old.txt`.
- `test_parse_dpmon_output_extracts_otp` — happy path.
- `test_parse_dpmon_output_handles_error_lines` — sets `success=False`, surfaces error.
- `test_parse_dpmon_output_no_otp_fails_cleanly` — empty / garbage input.

### Behavioral (mocked exec_fn)
- Mock `exec_fn` returns a canned dpmon transcript.
- Verify `activate_virtual_sap_star` returns the right dict shape.
- Verify it tries Tier 1 first, then Tier 2 / Tier 3 on Tier 1 empty stdout.

### Integration (mocked RFC)
- Mock `_get_connection` so the SAP* logon "succeeds".
- Verify `create_user_via_dpmon_sap_star` calls `BAPI_USER_CREATE1` then `BAPI_TRANSACTION_COMMIT`.
- Verify the returned `CreatedUser` has `method="dpmon_sap_star"`.

### Negative
- Kernel = `"753"` → method returns False without invoking exec_fn.
- exec_fn raises → method returns False cleanly.
- exec_fn returns empty output → method returns False.

### AutoPwn integration
- Phase 2 priority ordering test: dpmon SAP* comes after GW-ABAP, before CVE-31324.
- Source-level: `try_dpmon_sap_star` config flag consulted in phase 2.
- Modal checkbox `apwn-dpmon-sapstar` exists and flows through `launchAutoPwn()` to backend.

Total: ~12 new tests.

## 11. Documentation updates

- **README.md**:
  - Features → Local Privilege Escalation: add bullet for "dpmon Virtual SAP\* (kernel ≥ 790)".
  - Features → Exploitation: add bullet for "dpmon SAP\* user creation".
  - LPE section: new subsection describing the method.
  - AutoPwn section: update Phase-2 priority chain table to include dpmon SAP\*.
- **CLAUDE.md**:
  - Architecture → Exploitation: mention `sap_dpmon_sapstar.py`.
- **`docs/research/11_dpmon_virtual_sapstar_plan.md`** (this file): the plan itself, kept for reference.

## 12. Commit cadence

Break into reviewable chunks so each commit is small enough to read:

1. **`feat: scaffold sap_dpmon_sapstar with OTP parser + tests`**
   - New file `modules/exploitation/sap_dpmon_sapstar.py` with parser + tier-1 driver only.
   - Fixtures + parser tests.
   - No callers wired yet.

2. **`feat: add _kernel_ge helper + dpmon_sap_star_available flag on SAPNode`**
   - Model field.
   - Helper in `sapmap_models.py` or shared utility.
   - Scanner sets the flag when kernel ≥ 790.
   - 2 model tests + 1 scanner test.

3. **`feat: dpmon SAP* LPE method (priority 20)`**
   - Registers via `@lpe_method` in `sapmap_lpe.py`.
   - Uses existing WebGUI RSBDCOS0 exec path.
   - BAPI_USER_PROFILES_ASSIGN on the original user.
   - 2 LPE method tests + behavioral.

4. **`feat: create_user_via_dpmon_sap_star in sapmap_exploit`**
   - Phase-2 exploit path that uses any available OS-exec.
   - Returns CreatedUser.
   - 3 integration tests.

5. **`feat: AutoPwn — slot dpmon SAP* into Phase 2 priority chain`**
   - `AutoPwnConfig.try_dpmon_sap_star`.
   - Phase 2 block: dpmon between GW-ABAP and CVE-31324.
   - Modal checkbox + JS plumbing.
   - 3 AutoPwn tests.

6. **`docs: README + CLAUDE.md updates for dpmon SAP*`**

Total: ~6 commits, ~12 tests, ~600-800 LOC.

## 13. Open questions to answer during implementation

1. **dpmon non-interactive flags** — does kernel 793+ ship a `dpmon -u <client> -d <minutes>` shortcut? If yes, prefer it over the interactive menu driver. Need to check on a live ≥790 system or in SAP docs.
2. **Exact OTP regex** — confirm against real dpmon output before merging. The regex above is best-effort.
3. **AUTHORITY-CHECK on dpmon** — the SAP Note implies "any `<sid>adm`" can run it. No SAP authorization check happens at the kernel level. Verify on a real system.
4. **Behavior when dpmon stdout is buffered** — some kernels buffer; the menu prompts may not flush until after EOF on stdin. Tier 2 (heredoc) should handle this. Test on actual 790+ landscape.
5. **Locale / language sensitivity** — if dpmon's strings change with `LANG=de_DE`, the regex needs alternative anchors. Easy fix: set `LANG=C` in the exec wrapper.

## 14. Risks

- **Audit visibility**: EUP purpose 2 events. Document this prominently. Operators on red-team engagements should know it generates a high-signal log.
- **Time pressure**: 10-30 min window. If BAPI is slow (large user table on big systems), the OTP may expire. Use 30 min on slow systems.
- **OTP reuse race**: if any monitoring tool also tries SAP\* logon during our window, OTP is invalidated. Activate-then-use-immediately is the only safe pattern.
- **Future kernel hardening**: SAP may add an extra `auth/dpmon_sapstar_admin_required` parameter in future kernels. The method should fail gracefully (parse error string, surface to operator).
