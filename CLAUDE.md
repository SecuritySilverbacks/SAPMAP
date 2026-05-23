# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

SAPMAP (SAP Landscape Attack Path Mapper) is a security research tool for SAP NetWeaver environments. It discovers SAP systems, maps RFC trust relationships, executes known exploits (Gateway SAPXPG/10KBLAZE, MS betrusted, CVE-2025-31324, etc.), and visualizes the attack surface as an interactive web map. Requires written authorization before use — see `DISCLAIMER.md`.

## Commands

```bash
# Install dependencies
pip3 install -r requirements.txt

# Optional: enable authenticated RFC operations
export LD_LIBRARY_PATH=/opt/nwrfcsdk/lib:$LD_LIBRARY_PATH

# Launch with GUI (pywebview or browser fallback)
python3 sapmap.py

# Launch with SAP NW RFC SDK path
python3 sapmap.py --sdk /opt/nwrfcsdk/lib

# CLI-only (no GUI)
python3 sapmap.py --no-gui --targets 10.0.0.0/24 --fast

# Run a scripted scenario
python3 sapmap.py --script scripts/demo_10kblaze.yaml

# Run all tests
pytest tests/

# Run a single test file
pytest tests/test_models.py

# Run a single test
pytest tests/test_models.py::test_credentials_roundtrip
```

No build step, no linting config, no pre-commit hooks.

## Architecture

### Entry & State

- **`sapmap.py`** — CLI parsing, Bottle HTTP server launch, GUI window management
- **`modules/core/sapmap_state.py`** — Session persistence via `.sapmap` JSON files; RFC cache; loot directory management
- **`modules/core/sapmap_models.py`** — Core dataclasses (`SAPNode`, `RFCConnection`, `Credentials`, `SAPMAPState`); all support `to_dict()` / `from_dict()` for JSON serialization

### GUI & Visualization

- **`modules/core/sapmap_gui.py`** — 60+ Bottle REST API routes; spawns background threads for long-running operations; GUI polls for state changes (no callbacks)
- **`modules/core/sapmap_html.py`** — Single-page app with SVG-based interactive map; drag-drop node repositioning; no external JS dependencies
- **`modules/core/sapmap_report.py`** — Engagement reports (Markdown + self-contained HTML) with KPI cards, SVG landscape snapshot, trust-chain analysis
- **`modules/core/sapmap_diff.py`** — Color-coded diff between two `.sapmap` snapshots

### Discovery

- **`modules/discovery/sapmap_scanner.py`** — Fast mode (dispatcher 32XX + gateway 33XX ports only) or deep mode via SAPology integration
- **`modules/discovery/sapmap_rfc.py`** — Authenticated RFC operations: BAPI calls, `RFC_READ_TABLE`, destination management, user creation
- **`modules/discovery/sap_default_creds.py`** — 16 default credential tests via DIAG; sequential to minimize lockout risk
- **`modules/discovery/sapmap_scc_*.py`** — SAP Cloud Connector TLS fingerprint, version detection, CVE bucketing, relay reachability

### Exploitation

- **`modules/exploitation/sapmap_exploit.py`** — Orchestrator for user creation + propagation across the landscape
- **`modules/exploitation/sap_gw_xpg_standalone.py`** — Pure-Python 10KBLAZE Gateway SAPXPG exploit (unauthenticated OS command execution)
- **`modules/exploitation/sap_ms_betrusted.py` + `sap_betrusted_chain.py`** — Message Server internal port exploitation (CVE-2020-6207)
- **`modules/exploitation/sap_cve_2025_31324.py`** — VisualComposer JSP webshell deployment via chunked-base64 file writes
- **`modules/exploitation/sap_db_sql_writers.py`** — Multi-DB SQL generator (HANA, MSSQL, Oracle, MaxDB, DB2) for user creation via OS command injection
- **`modules/exploitation/sap_dpmon_sapstar.py`** — dpmon virtual SAP\* activation primitive (SAP Note 3303172, kernel ≥ 790, ABAP-only).  Pure-shell pipeline that walks `dpmon`'s menu via piped stdin, captures the one-time password, returns a parsed dict.  Caller-supplied `exec_fn(cmd) -> str` adapts to any OS-exec channel (GW SAPXPG for unauth Phase-2 exploit, SXPG_STEP_XPG_START for authenticated LPE)

### Post-Exploitation & Lateral Movement

- **`modules/postex/sapmap_lpe.py`** — LPE framework with decorator-registered methods; key methods: `bapi_profiles_assign` (direct RFC → SAP_ALL) and `webgui_rsbdcos0` (WebGUI SQL injection, bypasses S_RFC by running in dialog mode)
- **`modules/postex/sapmap_chain.py`** — BFS over RFC adjacency graph from entry points; ranks paths by severity (CRITICAL/HIGH/MEDIUM/LOW)

### Data Extraction

- **`modules/data_extraction/sapmap_secstore.py`** — ABAP RSECTAB decryption using SAP's proprietary RSECCipher (8-round Feistel over 3DES); 5-method fallback chain
- **`modules/data_extraction/sap_java_secstore*.py`** — Java SecStoreFS decryption; server-side JSP + offline 3DES
- **`modules/data_extraction/sap_btp.py`** — SAP BTP token parsing; destination-service enumeration; cleartext credential extraction; unknown backends materialize as `BTPDISC_*` placeholder nodes
- **`modules/data_extraction/sap_oa2c.py`** — ABAP OA2C OAuth2 profile mining via DDIF_FIELDINFO_GET → RFC_READ_TABLE → RFC_ABAP_INSTALL_AND_RUN fallback chain

### Protocols

- **`modules/protocols/sap_rfc_ctypes.py`** — ctypes wrapper for SAP NW RFC SDK; lazy-loaded so unauthenticated features work without it
- **`modules/protocols/sap_rsec_cipher.py`** — SAP RSECCipher with proprietary DES S-boxes
- **`modules/protocols/sap_saprouter.py`** — SAProuter NI_ROUTE tunnel; transparently wraps all RFC/scan/exploit operations
- **`modules/protocols/sap_rfc_system_info.py`** — Unauthenticated probing via three methods: V6 single-packet, V2 error-leak, Chipik-style

### Module Path Registration

`modules/__init__.py` appends every subpackage directory to `sys.path` at import time. This allows flat imports (`from sapmap_models import ...`) anywhere in the codebase regardless of caller location. Tests rely on `tests/conftest.py` doing the same path registration.

## Key Conventions

**Single SAPMAP user/password:** All exploit methods use a hardcoded credential (`SAPMAP00` / `Andinyougo123!`) with pre-computed password hashes embedded in `modules/core/sapmap_config.py`. This avoids needing the RFC SDK just to hash a password.

**Multi-method fallback chains:** When a primary method fails (e.g. SecStore extraction, RFC probing), code silently tries the next method rather than erroring. Understand the full chain before concluding a method is "broken."

**Lazy imports:** `pyrfc`, `pyyaml`, `pyjks`, `pywebview`, and `pycryptodome` are only imported when the feature requiring them is invoked. Import errors surface at use time, not startup.

**State file format:** `.sapmap` files are plain JSON — safe to inspect and manually edit. Auto-saved on exit; Ctrl+S triggers a manual save via the GUI.

**Artifacts:** `states/` (session files) and `loot/` (extracted secrets, hashes, reports) are gitignored and created at runtime.
