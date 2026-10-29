# SAPMAP — SAP Landscape Attack Path Mapper

```
   _____ ___    ____  __  ______    ____
  / ___//   |  / __ \/  |/  /   |  / __ \
  \__ \/ /| | / /_/ / /|_/ / /| | / /_/ /
 ___/ / ___ |/ ____/ /  / / ___ |/ ____/
/____/_/  |_/_/   /_/  /_/_/  |_/_/
```

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Docker Publish](https://github.com/SecuritySilverbacks/SAPMAP/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/SecuritySilverbacks/SAPMAP/actions/workflows/docker-publish.yml)
[![GitHub stars](https://img.shields.io/github/stars/SecuritySilverbacks/SAPMAP?style=social)](https://github.com/SecuritySilverbacks/SAPMAP/stargazers)

**Like BloodHound for Active Directory, but for SAP.**

SAPMAP discovers SAP systems on a network, maps RFC connections between them, exploits
gateway vulnerabilities and weak configurations, and charts lateral movement paths across
the entire SAP landscape — all from an interactive web-based map.

> ## ⚠️ Disclaimer — Use at your own risk
>
> SAPMAP implements **real, working exploits** against SAP systems. Running it against a
> system you do not own or do not have explicit written permission to test is **illegal**
> in most jurisdictions and may cause data loss, account lockouts, outages, and audit findings.
>
> **Intended solely for:** authorized penetration tests, defensive research on systems you
> own, educational study of SAP attack surfaces, and SOC / blue-team detection-engineering
> exercises. **No warranty.** See [`DISCLAIMER.md`](DISCLAIMER.md) for the full text.

## Quick start

Requires Python 3.8+ (3.12+ to use the recommended `saprfclib` RFC backend).

```bash
git clone https://github.com/SecuritySilverbacks/SAPMAP.git
cd SAPMAP
python3 -m venv .venv && source .venv/bin/activate
pip3 install -r requirements.txt
python3 sapmap.py --pure-rfc          # launch the GUI on the recommended pure-Python backend
```

`--pure-rfc` uses [`saprfclib`](https://github.com/randomstr1ng/saprfclib) — a zero-native-dependency
RFC backend, no SAP NW RFC SDK download required. The native SDK remains supported as an
alternative. See the wiki for the SDK path, Docker, read-only mode, and CLI options.

## Documentation

Full documentation lives in the **[SAPMAP Wiki](https://github.com/SecuritySilverbacks/SAPMAP/wiki)**:

- [Installation](https://github.com/SecuritySilverbacks/SAPMAP/wiki/Installation) · [Launch & CLI Options](https://github.com/SecuritySilverbacks/SAPMAP/wiki/Launch-and-CLI-Options) · [Pure-Python RFC Backend](https://github.com/SecuritySilverbacks/SAPMAP/wiki/Pure-Python-RFC-Backend)
- [Web GUI](https://github.com/SecuritySilverbacks/SAPMAP/wiki/Web-GUI) · [Scanning](https://github.com/SecuritySilverbacks/SAPMAP/wiki/Scanning) · [Read-Only Mode](https://github.com/SecuritySilverbacks/SAPMAP/wiki/Read-Only-Mode) · [Configuration](https://github.com/SecuritySilverbacks/SAPMAP/wiki/Configuration)
- [Capabilities](https://github.com/SecuritySilverbacks/SAPMAP/wiki/Discovery-and-Enumeration) — discovery, exploitation, [AutoPwn](https://github.com/SecuritySilverbacks/SAPMAP/wiki/AutoPwn), LPE, lateral movement, BTP/SCC, evasion, and more
- [Scripted Scenarios](https://github.com/SecuritySilverbacks/SAPMAP/wiki/Scripted-Scenarios) · [MCP Server](https://github.com/SecuritySilverbacks/SAPMAP/wiki/MCP-Server)
- [Detection & Defense](https://github.com/SecuritySilverbacks/SAPMAP/wiki/Detection-and-Defense) (blue team) · [Architecture](https://github.com/SecuritySilverbacks/SAPMAP/wiki/Architecture) · [Testing](https://github.com/SecuritySilverbacks/SAPMAP/wiki/Testing)

## In the press

- **Onapsis, 2026** — [SAPMAP: mapping the SAP attack surface](https://onapsis.com/blog/sapmap/)

---

## Credits & Prior Art

SAPMAP stands on a decade of public SAP-security research.  The people
and projects below deserve explicit credit — without their wire-format
reversing, exploit primitives, and published PoCs, SAPMAP would not
exist.  Verbatim ports are itemised in [NOTICE](NOTICE); this section
is the human-readable version.

### Protocol libraries & wire-format reverse-engineering

- **[OWASP pysap](https://github.com/OWASP/pysap)** — Martin Gallo
  (SecureAuth Labs / OWASP CBAS).  The reference SAP protocol library.
  SAPMAP ports RSEC/DES S-boxes, iperm/fperm tables, SNC frames,
  SAPRouter info layout, DIAG constants, SAPMS opcodes, SSFS record
  structure, and the GW_NORMAL_CLIENT payload template from it.
  Verbatim ports stay under GPLv2-or-later — see [NOTICE](NOTICE).
  `tools/sap_decompress/sap_decompress` is a static ELF built from
  pysap's `pysapcompress`.
- **[SAP-archive/PyRFC](https://github.com/SAP/PyRFC)** and
  **jdsricardo/SAP-RFC-Python-without-PyRFC** — ctypes-level layout
  research behind SAPMAP's NW RFC SDK wrapper.
- **[Wireshark SAP dissector](https://github.com/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark)** (also Martin Gallo) —
  `packet-saprfc.c` and `packet-saprouter.c` used as protocol
  references.

### Pure-Python RFC & anonymous CPIC recon

- **[randomstr1ng/saprfclib](https://github.com/randomstr1ng/saprfclib)**
  — Julian Petersohn.  Pure-Python authenticated RFC library; optional
  SAPMAP backend, enabled via `--pure-rfc`.
- **[randomstr1ng/sap-rfm-enum](https://github.com/randomstr1ng/sap-rfm-enum)** —
  Julian Petersohn.  Reverse-engineered the 80-byte APPC v6 header
  against kernel 7.93 and showed that `RFC_SYSTEM_INFO` / `RFC_PING` /
  `SYSTEM_INVISIBLE_GUI` can be dispatched pre-logon.  SAPMAP's stdlib
  probe (`tools/rfc_sysinfo.py`, `modules/protocols/sap_rfc_sysinfo_probe.py`)
  is a de-pysap'd single-FM extraction of Julian's work.
- **[chipik/SAP_RECON](https://github.com/chipik/SAP_RECON)** — Dmitry
  Chastuhin.  F_SAP_INIT / F_SAP_SEND kernel-release leak layout used
  in SAPMAP's gateway probes.  SOAP LM Configuration Wizard templates
  and user-attribute structures for CVE-2020-6287 are ported verbatim.
- **[gelim/nmap-sap](https://github.com/gelim/nmap-sap)** — Mathieu Geli
  (`gelim`).  Gateway startrfc CPIC handshake reused as the
  gateway-detection payload.
- **[gelim/sap_ms](https://github.com/gelim/sap_ms)** and
  **[gelim/sap-pse-tools](https://github.com/gelim/sap-pse-tools)** —
  also Mathieu Geli.  Message Server MS_LOGON_DIAG/RFC opcodes and
  PSE PKCS#7 structure references.
- **[usdAG/sncscan](https://github.com/usdAG/sncscan)** — SNC posture
  scanner.  The 97-byte GSS token and ext-fields blobs are copied
  verbatim into `modules/protocols/sap_snc.py`.

### Exploit primitives & vulnerability research

- **[Onapsis](https://onapsis.com/)** — RECON (CVE-2020-6287), 10KBLAZE
  / CVE-2019-0344, ICMAD / CVE-2022-22536.  Canonical PoCs and
  advisory references shape the ICMAD, Message-Server, and
  VisualComposer (CVE-2025-31324) implementations.
- **[chipik/SAP_EEM_CVE-2021-21466](https://github.com/chipik/SAP_EEM_CVE-2021-21466)**
  — Dmitry Chastuhin.  EEM broadcast reference for post-ex.
- **[BecodoExploit-mrCAT/SAPGateBreaker-Exploit](https://github.com/BecodoExploit-mrCAT/SAPGateBreaker-Exploit)** —
  TE-chunked smuggle template for CVE-2022-22536.
- **[tess-ss/SAP-MPI-CVE-2022-22536](https://github.com/tess-ss/SAP-memory-pipes-desynchronization-vulnerability-MPI-CVE-2022-22536)**
  and **[ZZ-SOCMAP/CVE-2022-22536](https://github.com/ZZ-SOCMAP/CVE-2022-22536)** —
  additional PoC references.
- **[erpscanteam/SecStoreDec](https://github.com/erpscanteam/SecStoreDec)**
  — ERPScan (former SAP research team).  Java SecStore 3DES/AES CBC +
  PBKDF2 offline break ported under MIT into
  `modules/data_extraction/sap_java_secstore_offline.py`.  Their 2014
  talk *"All your SAP passwords belong to us"* remains the reference
  on SAP hash storage.
- **[erpscanteam/CVE-2018-2380](https://github.com/erpscanteam/CVE-2018-2380)**
  — CRM path reference for the SAPCAR / RSECTAB chain.
- **[redrays.io — SAP Note 3759472 / CVE-2026-58240](https://redrays.io/blog/sap-note-3759472-message-server-ascs-gateway-cve-2026-58240/)**
  — Julian Petersohn / RedRays.  Kernel-binary diff and public
  write-up of the Message Server ASCS_GW rogue-registration
  vulnerability (CVSS 9.8, September 2026 SAP Patch Day).
  The screenshot's partial payload fragment (`030000000000007a691000…`)
  seeded SAPMAP's fuzzer; the winning 57-byte shape
  (`03 | 00×6 | port_be | host_40 | ip_4 | pid_be_4`) was
  reverse-engineered live against an unpatched target and shipped
  as a full check + register + cleanup PoC in
  `modules/exploitation/sap_cve_2026_58240.py`.  First confirmed
  end-to-end exploit against kernel 9.16 PL75 on 2026-09-12.

### SSO2 ticket forgery

- **[synacktiv/sap_logon_ticket](https://github.com/synacktiv/sap_logon_ticket)**
  — Synacktiv (GPL-3.0).  Wire-format reference and test oracle for
  MYSAPSSO2 forging.  SAPMAP's implementation is a clean-room
  reimplementation — no code vendored.

### SAP Cloud Connector

- **[redrays-io/SAP_Cloud_Connector_SSFS_Decryption](https://github.com/redrays-io/SAP_Cloud_Connector_SSFS_Decryption)**
  — JNI wrapper around `libsapscc20jni.getRecord()`.  Vendored under
  `tools/ssfs_decrypt/` and called at runtime for SCC SSFS decryption.

### Windows LPE gadgets (vendored)

- **[GodPotato](https://github.com/BeichenDream/GodPotato)** —
  BeichenDream (Apache-2.0).  Vendored under `tools/godpotato/`.
- **[EfsPotato](https://github.com/zcgonvh/EfsPotato)** — zcgonvh.
  MS-EFSRPC coercion primitive; vendored under `tools/efspotato/`.
- **MiniPlasma** — CVE-2020-17103 (`cldflt.sys`
  HsmOsBlockPlaceholderAccess race), originally reported by **James
  Forshaw / Google Project Zero (2020)**; weaponised PoC by
  **[Nightmare-Eclipse/MiniPlasma](https://github.com/Nightmare-Eclipse/MiniPlasma)**
  (2025).  Vendored under `tools/miniplasma/` with modifications.
- Bundled NuGet deps for the .NET blobs: Costura.Fody, NtApiDotNet,
  TaskScheduler; obfuscation via ConfuserEx.

### Linux LPE gadgets (vendored)

- **[V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag)** — Hyunwoo
  Kim (`@v4bel`).  xfrm-ESP + RxRPC page-cache-write chain.  Vendored
  fork in `tools/dirtyfrag/` (only `shell_elf` + no-PTY changes).
- **[sgkdev/packet_edit_meme](https://github.com/sgkdev/packet_edit_meme)**
  — `@sgkdev`.  `act_pedit` partial-COW (CVE-2026-46331).  Vendored
  under `tools/peditcow/src/upstream/`.
- **"Copy Fail"** (CVE-2026-31431) — AF_ALG AEAD in-place scratch-write
  primitive.  Runner at `modules/exploitation/sapmap_copyfail.py`.
  Upstream author credit outstanding — please open an issue if you
  are that author.

### Post-exploitation

- **[randomstr1ng/virtual-sap-death-star](https://github.com/randomstr1ng/virtual-sap-death-star)**
  — Julian Petersohn.  In-memory ptrace hook against `disp+work` SAL
  sinks.  Vendored verbatim as `modules/postex/vendor/sap_audit_hook.c`
  plus a pre-built binary.
- **[Metasploit sap_router_info_request.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/sap/sap_router_info_request.rb)**
  and **`sap_mgmt_con_osexec_payload`** — router-info wire reference
  and sapstartsrv OSExecute chain reference.

### Sibling project

- **[kloris/SAPology](https://github.com/kloris/SAPology)** — the
  sibling deep-scan project (same author).  Optional Deep-Mode
  backend; SAPMAP borrows its severity vocabulary, pill-colour
  convention, Bottle + pywebview architecture, and the
  `SAPSystem → SAPNode` model.

### Frameworks & documentation

- **[MITRE ATT&CK](https://attack.mitre.org/)** /
  **[ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator)**
  — the tactic-grouped coverage grid in engagement reports.
- **SAP OSS Notes** cited directly in code / findings: 2115486 (SSFS
  format), 2934135 (RECON master), 3424610 (SCC cert validation),
  3611345 (SCC Aug-2025), 3634501 (P4 fix), 3303172 (dpmon SAPSTAR).
- **Troopers** and **SEC Consult** research (default credentials; RFC
  exploit chain; BW `RSDMD_BATCH_CALL` code injection).

---

## License

SAPMAP is licensed under the GNU General Public License v3.0 (or, at
your option, any later version) — see [LICENSE](LICENSE) and
[NOTICE](NOTICE) for details, including third-party code ported from
the [pysap](https://github.com/OWASP/pysap) project (GPLv2-or-later).

For authorized security testing only. Unauthorized access to computer systems is illegal. See [DISCLAIMER.md](DISCLAIMER.md).
