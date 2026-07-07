# SAPMAP — vendored third-party sources

Third-party source files SAPMAP deploys onto remote SAP hosts as part of
post-exploitation workflows.  Every file below is copied here verbatim from
its upstream (only a short attribution header is added).  If you are
redistributing SAPMAP, verify each upstream's license terms independently.

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

Integrated in SAPMAP as the Tier 3 evasion technique `sal_death_star`
(entry point `sapmap_death_star.py`, GUI action "SAL In-Memory Hook
Suppress (Death Star)" under the Evasion submenu).  Guarded by
`--allow-evasion` and a captured baseline like every other Tier 3
technique.
