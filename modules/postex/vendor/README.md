# SAPMAP — vendored third-party sources + pre-built binaries

Third-party source files SAPMAP deploys onto remote SAP hosts as part of
post-exploitation workflows.  Every C source file below is copied here
verbatim from its upstream (only a short attribution header is added).
If you are redistributing SAPMAP, verify each upstream's license terms
independently.

## `sap_audit_hook.c` — "Virtual SAP Death Star"

**Upstream:** https://github.com/randomstr1ng/virtual-sap-death-star
**Author:** Julian Petersohn (`@randomstr1ng`)

An in-memory ptrace hook that attaches to running `disp+work` work-processes
and plants INT3 breakpoints on the SAL (Security Audit Log) write sites in
the `rsauwr1ex` function.  In `--suppress` mode it silently drops matching
audit records across all three sinks (fwrite to disk, `write_event_to_DB`,
`EtdSendEvent` for the SAP Event & Trace Domain feed).  In `--monitor` mode
it observes only.

**Requires:** local shell as `<sid>adm` on the target SAP host, and
`kernel.yama.ptrace_scope <= 1`.

**Confirmed not a 0-day:** SAP confirmed to Julian that this is a
post-exploitation technique, not a novel vulnerability — running it already
requires the full OS-level foothold that any SAP-hardened environment
should protect against.  See the upstream README for SAP's statement.

## `sap_audit_hook.linux-x86_64` — pre-built binary

A statically-linked build of `sap_audit_hook.c` for Linux x86_64.  When
present, `sapmap_death_star` prefers this file over the compile-on-target
flow — the deploy step becomes:

```
upload binary → make executable → launch  (no gcc on target needed)
```

SAP application servers are commonly hardened without a compiler
installed (`gcc: command not found`, exit code 127).  Shipping the
pre-built binary makes deployment work regardless.

### Building

Requires a Linux host with `gcc` + static libc (Debian/Ubuntu:
`sudo apt install build-essential`; RHEL/CentOS:
`sudo yum install gcc glibc-static`) or `musl-gcc`
(`sudo apt install musl-tools`).  Then:

```bash
cd modules/postex/vendor/
./build_sap_audit_hook.sh              # auto-picks musl-gcc if present, else gcc -static
```

Explicit modes:

```bash
./build_sap_audit_hook.sh musl         # musl-gcc — smallest + most portable
./build_sap_audit_hook.sh glibc        # gcc -static — works on hosts with any modern glibc
./build_sap_audit_hook.sh dynamic      # gcc (no -static) — only runs where build host's glibc matches
```

The build script sanity-checks the binary (invokes `--help`) and prints
`ldd` output so you can confirm portability before committing.

### Portability notes

* **musl-gcc build** (recommended): fully self-contained, ~100-150 KB,
  runs on any Linux x86_64 kernel that supports `process_vm_readv`
  (kernel ≥ 3.2, i.e. essentially every SAP-supported OS).  No glibc
  version dependency.
* **`gcc -static` build**: links against build host's glibc statically
  (~800 KB - 1 MB).  Works across most glibc versions since we don't
  call anything that requires NSS dynamic loading.  Larger, but easier
  to build (no extra tooling).
* **Dynamic build**: needs the target's glibc to be ABI-compatible with
  the build host's — only for lab use.

The vendored `sap_audit_hook.linux-x86_64` (if committed to the repo) is
typically built with `musl-gcc` for maximum portability.  Verify with
`file` + `ldd` if you're redistributing.

### Rebuild triggers

Rebuild whenever `sap_audit_hook.c` changes.  The build script prints
the exact `git add` / `git commit` commands to run when done.

## Integration

Integrated in SAPMAP as the Tier 3 evasion technique `sal_death_star`
(entry point `sapmap_death_star.py`, GUI action "SAL In-Memory Hook
Suppress (Death Star)" under the Evasion submenu).  Guarded by
`--allow-evasion` like every other Tier 3 technique.

At runtime, `sapmap_death_star.deploy_and_launch()` picks its path:

1. If `sap_audit_hook.linux-x86_64` is present in this vendor dir →
   upload it directly, `chmod +x`, launch.  Fast + no compiler needed.
2. Otherwise → upload `sap_audit_hook.c`, try `gcc` / `cc` / `clang`
   in PATH + common install paths, launch the compiled binary.
3. If neither works → clear error message with install commands
   (`zypper install gcc`, `apt install build-essential`, etc.).
