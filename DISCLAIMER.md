# SAPMAP — Disclaimer

**Use at your own risk.**

SAPMAP (SAP Landscape Attack-Path Mapper) implements real, working
exploits against SAP NetWeaver ABAP and Java stacks, including:

- RFC Gateway remote command execution (10KBlaze / CVE-2020-6207 family)
- Message Server authentication bypass (betrusted)
- CVE-2025-31324 — VisualComposer metadatauploader unauth RCE
- CVE-2020-6287 — LM Configuration Wizard unauth admin user creation (RECON)
- CVE-2020-6286 — CTCWebService `queryProtocol` traversal
- ABAP BAPI-level user creation, role assignment, SecStore extraction
- Java UME user creation, SecStore decryption, and credential propagation
- **Linux root LPE** — Copy Fail (CVE-2026-31431) and Dirty Frag (no
  CVE; embargo broken pre-disclosure 2026; no upstream patch at time
  of writing).  Both temporarily patch `/usr/bin/su` in the kernel
  page cache to obtain `uid=0`.

Running any of these against a system you do not own, or do not have
**explicit, written authorization** to test, is **illegal** in most
jurisdictions and may:

- cause data loss or unauthorized disclosure,
- lock out legitimate accounts,
- interrupt business operations,
- trigger SIEM / SOC incidents and audit findings,
- and expose you to civil or criminal liability.

## Intended uses

SAPMAP is provided **solely** for:

1. **Authorized penetration tests and red-team engagements** under a
   signed statement of work that explicitly permits SAP NetWeaver
   testing.
2. **Defensive security research** on systems you personally own or
   administer.
3. **Educational study** of SAP attack surfaces, patch effectiveness,
   and detection opportunities.
4. **SOC / blue-team detection-engineering exercises** against a lab
   environment you control.

## Your responsibilities

By running this tool you accept that you are responsible for:

- having written authorization before executing any scan, check,
  or exploit against any system,
- the scope of what you touch (targets, credentials, artifacts),
- the consequences of any action you take with this tool,
- cleaning up artifacts you create — `SAPMAP00` users, dropped JSP
  webshells, TCP/IP destinations, modified `secinfo` / `reginfo`
  profiles — when you are done. Use **Actions → Cleanup All Users**
  in the GUI.

## No warranty

SAPMAP is provided **"as is"**, without warranty of any kind, express
or implied, including but not limited to the warranties of
merchantability, fitness for a particular purpose, and non-infringement.
The authors and contributors accept **no liability** for any claim,
damages, or other liability arising from the use or misuse of this
software.

## Jurisdiction

Laws governing computer security testing vary by jurisdiction. Users are
responsible for understanding and complying with all applicable local,
national, and international laws — including the Computer Fraud and Abuse
Act (US), Computer Misuse Act (UK), and equivalent legislation in their
country of operation.

## Reporting responsibly

If you discover a new vulnerability using SAPMAP or its research, please
disclose it responsibly to the vendor (SAP SE) via
<https://support.sap.com/en/my-support/product-security-response.html>
or your customer's internal security channel before public disclosure.

## License

See `LICENSE` for distribution terms.
