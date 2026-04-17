# SAPMAP — Research Archive

Five parallel deep-research streams commissioned April 2026 to identify
the next generation of attack primitives to add to SAPMAP. Each report
below is an independent research dossier; the consolidated priority
list lives in `00_priority_summary.md`.

| # | Topic | File |
|---|---|---|
| 0 | **Prioritized implementation roadmap** (read this first) | [`00_priority_summary.md`](00_priority_summary.md) |
| 1 | New SAP CVEs 2018-2026 (beyond what SAPMAP already covers) | [`01_new_cves.md`](01_new_cves.md) |
| 2 | Java→ABAP pivots from a RECON-created UME admin (hardened Java) | [`02_java_to_abap_pivots.md`](02_java_to_abap_pivots.md) |
| 3 | SAP Cloud Connector & BTP attack surface | [`03_cloud_connector_btp.md`](03_cloud_connector_btp.md) |
| 4 | SSO ticket forging & trust-relationship abuse (lateral movement) | [`04_sso_trust_lateral_movement.md`](04_sso_trust_lateral_movement.md) |
| 5 | Post-exploitation / data-extraction techniques (ABAP + Java + HANA) | [`05_post_exploitation.md`](05_post_exploitation.md) |
| 6 | Initial-access: default creds, pre-auth info disclosure, weak-config probes | [`06_initial_access.md`](06_initial_access.md) |

## Research method

Each report was produced by an independent research agent with full
web access, briefed with the current SAPMAP capability set and
instructed to find **novel** attack primitives (not duplicates of
what the tool already implements). All reports include CVE
references, SAP Note numbers, public PoC links, and concrete
integration recommendations with effort estimates.

## Status

These are research artefacts, not specifications. Entries are graded
by the originating agent; CVE numbers for 2024–2026 were written from
memory and should be verified against the current NVD / SAP Security
Patch Day index before implementation.

The `00_priority_summary.md` document distils the five reports into a
single ranked list of 15 additions, grouped by effort tier, with an
explicit phase-1 / phase-2 / phase-3 implementation plan.
