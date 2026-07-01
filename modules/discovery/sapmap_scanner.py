#!/usr/bin/env python3
"""
SAPMAP Scanner — Network discovery of SAP systems.

Wraps SAPology scanning functions and the standalone helper modules
(sap_rfc_system_info, sap_client_enum) to discover SAP systems on a
network and populate SAPNode objects for the map.

Supports two modes:
  - Fast scan: dispatcher 32XX, then gateway 33XX + HANA for found instances
  - Deep scan: full SAPology scan with all ports, fingerprinting, and vuln checks
"""

import ipaddress
import logging
import os
import re
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from sapmap_models import SAPNode, InstanceInfo, Finding, Severity, SCCNode
from sapmap_config import (
    DEFAULT_INSTANCE_RANGE, DEFAULT_THREADS, DEFAULT_TIMEOUT,
    FAST_SCAN_PORT_PATTERNS, WELL_KNOWN_WD_PORTS,
)


def _attack_for(capability_key: str) -> list:
    """Resolve a sapmap_attack capability key → list of T-IDs (or [])."""
    try:
        from sapmap_attack import techniques_for
        return techniques_for(capability_key)
    except Exception:
        return []

logger = logging.getLogger(__name__)

# Add SAPology (sister project, sits next to SAPMAP root) to path for
# imports.  This file now lives in modules/discovery/, so the SAPology
# directory is three levels up.
_sapology_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "..", "..", "..", "SAPology")
if os.path.isdir(_sapology_dir) and _sapology_dir not in sys.path:
    sys.path.insert(0, _sapology_dir)

# Import from existing modules in SAPMAP directory
from sap_rfc_system_info import probe_sap_system
from sap_client_enum import enumerate_clients
from sapmap_findings import emit_finding


# ---------------------------------------------------------------------------
# SAP port → instance number derivation
# ---------------------------------------------------------------------------

def _derive_instance_from_wd_port(port: int) -> str:
    """Map a SAP HTTP/HTTPS port to its instance number, when it follows
    SAP's 80NN / 443NN convention.

    Returns the two-digit instance number (e.g. "11" for port 8011 or
    44311) or "" when the port doesn't follow the formula.  Used to
    fold a WD's HTTP/HTTPS port into the same SAPNode as the
    matching SAPControl port (5XX13) on the same instance — a real
    operator regression was two separate nodes for one host: SW1 on
    port 51113 (inst 11) and W6B on port 8011 (also inst 11).

    Out-of-pattern ports (80, 443, 8080, 8443, 50000, 50001) return
    "" so the existing "WD" placeholder logic still creates a
    standalone WD node for those — those genuinely don't map to an
    instance number, they're just the production-facing canonical
    HTTP/HTTPS choices.
    """
    # 80NN HTTP — instances 00..97 (kernel limit on instance number)
    if 8000 <= port <= 8097:
        return f"{port - 8000:02d}"
    # 443NN HTTPS — instances 00..97
    if 44300 <= port <= 44397:
        return f"{port - 44300:02d}"
    return ""


# ---------------------------------------------------------------------------
# Target parsing (IP ranges, subnets, files)
# ---------------------------------------------------------------------------

def parse_targets(target_str: str) -> list:
    """Parse target specification into a list of IP addresses.

    Supports:
      - Single IP: "192.168.1.1"
      - CIDR subnet: "192.168.1.0/24"
      - Range: "192.168.1.1-192.168.1.254"
      - Comma-separated: "192.168.1.1,192.168.1.2"
      - File path (one target per line): "@targets.txt" or "/path/to/file"
    """
    targets = []

    # File input
    if target_str.startswith("@") or (os.path.isfile(target_str)):
        filepath = target_str.lstrip("@")
        try:
            with open(filepath, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.extend(parse_targets(line))
            print(f"[*] Loaded {len(targets)} targets from {filepath}")
        except Exception as e:
            print(f"[-] Could not read target file {filepath}: {e}")
            logger.error(f"Could not read target file {filepath}: {e}")
        return targets

    # Comma-separated
    if "," in target_str:
        for part in target_str.split(","):
            targets.extend(parse_targets(part.strip()))
        return targets

    target_str = target_str.strip()

    # CIDR notation
    if "/" in target_str:
        try:
            network = ipaddress.ip_network(target_str, strict=False)
            for host in network.hosts():
                targets.append(str(host))
            print(f"[*] Expanded {target_str} to {len(targets)} hosts")
        except ValueError as e:
            print(f"[-] Invalid CIDR: {target_str}: {e}")
            logger.error(f"Invalid CIDR: {target_str}: {e}")
        return targets

    # IP range (dash notation)
    if "-" in target_str and not target_str.startswith("-"):
        parts = target_str.split("-")
        if len(parts) == 2:
            try:
                start = ipaddress.ip_address(parts[0].strip())
                end_part = parts[1].strip()
                # Support both "192.168.1.1-254" and "192.168.1.1-192.168.1.254"
                if "." in end_part:
                    end = ipaddress.ip_address(end_part)
                else:
                    # Short form: last octet only
                    octets = str(start).split(".")
                    octets[-1] = end_part
                    end = ipaddress.ip_address(".".join(octets))

                current = int(start)
                while current <= int(end):
                    targets.append(str(ipaddress.ip_address(current)))
                    current += 1
                print(f"[*] Expanded range {target_str} to {len(targets)} hosts")
            except ValueError as e:
                print(f"[-] Invalid range: {target_str}: {e}")
                logger.error(f"Invalid range: {target_str}: {e}")
            return targets

    # Hostname or single IP
    try:
        ipaddress.ip_address(target_str)
        targets.append(target_str)
    except ValueError:
        # Try DNS resolution
        try:
            ip = socket.gethostbyname(target_str)
            print(f"[*] Resolved {target_str} -> {ip}")
            targets.append(ip)
        except socket.gaierror:
            print(f"[-] Could not resolve hostname: {target_str}")
            logger.error(f"Could not resolve hostname: {target_str}")

    return targets


# ---------------------------------------------------------------------------
# Host alive detection
# ---------------------------------------------------------------------------

ALIVE_PROBE_PORTS = [3200, 3300, 3201, 3301, 8000, 50013, 443, 22]
ALIVE_TIMEOUT = 0.5  # seconds — short TCP timeout for alive probes


def _is_host_alive(host: str, timeout: float = None) -> bool:
    """Quick check if a host is reachable.

    Runs ICMP ping and TCP probes in parallel threads so a single dead
    host takes at most ~timeout seconds instead of sequentially
    accumulating timeouts.  Returns True on first success.
    """
    if timeout is None:
        timeout = ALIVE_TIMEOUT
    found = threading.Event()

    def _ping():
        try:
            import subprocess
            # Use ceil of timeout for -W (integer seconds, min 1)
            wait_sec = str(max(1, int(timeout + 0.5)))
            ret = subprocess.call(
                ["ping", "-c", "1", "-W", wait_sec, host],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=timeout + 0.3,
            )
            if ret == 0:
                found.set()
        except Exception:
            pass

    def _tcp(port):
        if found.is_set():
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                found.set()
        except Exception:
            pass

    # Launch ping + all TCP probes concurrently
    workers = [threading.Thread(target=_ping, daemon=True)]
    for p in ALIVE_PROBE_PORTS:
        workers.append(threading.Thread(target=_tcp, args=(p,), daemon=True))
    for w in workers:
        w.start()

    # Wait for first success or all to finish.
    # Dead hosts are bounded by the TCP timeout; we add a small margin
    # so the join loop doesn't exit before TCP probes finish cleanly.
    deadline = time.time() + timeout + 0.15
    for w in workers:
        remaining = deadline - time.time()
        if remaining <= 0 or found.is_set():
            break
        w.join(timeout=remaining)

    return found.is_set()


def alive_sweep(targets: list, threads: int = 100,
                cancel_event: threading.Event = None) -> list:
    """Parallel alive detection across all targets.

    Probes up to 100 hosts concurrently.  Each host probe runs ping +
    TCP connects in parallel internally, so even a /24 with 250 dead
    hosts completes in ~3-5 seconds.

    Returns list of hosts that responded to ping or TCP probe.
    """
    alive = []
    total = len(targets)
    scanned = [0]
    lock = threading.Lock()

    print(f"[*] Alive sweep: probing {total} hosts "
          f"(parallel ping + TCP on {len(ALIVE_PROBE_PORTS)} ports, "
          f"timeout={ALIVE_TIMEOUT}s) ...")

    t0 = time.time()

    def _check(host):
        if cancel_event and cancel_event.is_set():
            return
        ok = _is_host_alive(host)
        with lock:
            scanned[0] += 1
            if ok:
                alive.append(host)
                print(f"[+]   {host} is alive  "
                      f"({scanned[0]}/{total}, {len(alive)} alive so far)")
            elif scanned[0] % 25 == 0 or scanned[0] == total:
                print(f"[*]   Probed {scanned[0]}/{total} hosts "
                      f"({len(alive)} alive so far)")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(_check, h) for h in targets]
        for f in as_completed(futures):
            if cancel_event and cancel_event.is_set():
                break
            f.result()  # propagate exceptions
        # executor.__exit__ waits; workers check cancel so they exit fast

    elapsed = time.time() - t0
    if cancel_event and cancel_event.is_set():
        print(f"[!] Alive sweep cancelled after {elapsed:.1f}s "
              f"({len(alive)} alive found so far)")
    else:
        print(f"[+] Alive sweep done in {elapsed:.1f}s: "
              f"{len(alive)}/{total} hosts alive")
    return alive


# ---------------------------------------------------------------------------
# Port scanning & DIAG protocol verification
# ---------------------------------------------------------------------------

def _scan_port(host: str, port: int, timeout: float = 3.0,
               saprouter: str = "") -> bool:
    """Check if a TCP port is open (optionally via SAProuter tunnel)."""
    try:
        if saprouter:
            from sap_saprouter import connect_through_saprouter, build_route_for_port
            route = build_route_for_port(saprouter, host, port)
            sock = connect_through_saprouter(route, timeout)
            sock.close()
            return True
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
    except Exception:
        return False


# SAP DIAG init probe (from nmap-sap / SAPology) — used to verify dispatcher
import re as _re
_SAP_DIAG_PROBE = bytes.fromhex(
    "00000106ffffffff0a000000000000ffffffffffffffffffffffffffffffffffff"
    "ff3e00000000ffffffffffff20202020202020202020202020202020202020202020"
    "2020202020202020202020202020202020200000000000000000000000000000000000"
    "000000000000000020202020202020202020202020202020202020200000000000000000"
    "ffffffff0000000001000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000010"
    "000000000000100402000c000000800000044c0000138910040b0020ff7ffe2d"
    "dab737d674087e1305971597eff23f8d0770ff0f0000000000000000"
)
# Response pattern: NI header (4 bytes) + DIAG marker 00 00 11 00 00 01 00 00
_SAP_DIAG_RESP_RE = _re.compile(
    b'^\\x00\\x00..\\x00\\x00\\x11\\x00\\x00\\x01\\x00\\x00', _re.DOTALL
)


def _verify_sap_diag(host: str, port: int, timeout: float = 2.0) -> bool:
    """Verify a port speaks SAP DIAG protocol (not just TCP-open).

    Sends the SAP DIAG init probe and checks the response:
      1. Strict match: nmap signature (00 00 XX XX 00 00 11 00 00 01 00 00)
      2. Broad match:  valid NI framing with a large payload (>100 bytes),
         which newer S/4HANA dispatchers return with a different DIAG
         message type (0x00 instead of 0x11).

    Returns False for non-SAP services that happen to listen on 32XX ports.
    """
    import struct as _struct
    connection_reset = False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(_SAP_DIAG_PROBE)
        resp = b""
        try:
            while len(resp) < 512:
                chunk = s.recv(512)
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass
        except ConnectionResetError:
            connection_reset = True
        s.close()
    except ConnectionResetError:
        # Server actively rejected our DIAG probe — not SAP
        return False
    except Exception:
        return False

    # Connection reset after probe = definitely not SAP DIAG
    if connection_reset:
        return False

    # Timeout with no data = not SAP DIAG.
    # SAP dispatchers always respond to the DIAG init probe.
    # Services like SAProuter accept the connection but don't respond
    # (they expect NI_ROUTE, not DIAG), causing an empty response.
    if len(resp) == 0:
        return False

    if len(resp) < 4:
        return False

    # Strict nmap match (classic DIAG init response)
    if len(resp) >= 12 and _SAP_DIAG_RESP_RE.match(resp) is not None:
        return True

    # Broad match: valid NI frame with a substantial payload.
    # SAP DIAG dispatchers return 1000+ byte init responses.
    # Non-SAP services return tiny responses or non-NI data.
    ni_len = _struct.unpack("!I", resp[:4])[0]
    if ni_len >= 100 and (len(resp) - 4) >= min(ni_len, 500):
        return True

    # Response present but doesn't look like SAP DIAG — reject
    return False


# ---------------------------------------------------------------------------
# SAP Gateway fingerprint (verifies 33XX / 48XX is really an SAP GW)
#
# Based on the nmap-sap project (gelim/nmap-sap, nmap-service-probes
# lines 24-35) which ships two probes for SAP Gateway detection.  We
# use probe 2 (the startrfc CPIC handshake), because its match
# signature is more discriminating than probe 1's "any-NI-frame-with-
# zero-payload" pattern.
#
# Probe payload: 4-byte NI length (0x40 = 64) + 64-byte CPIC connect.
# Match: response starts with the 10-byte echo
# ``\x00\x00\x00\x40\x02\x03\xac\x10\x00\x77`` — non-SAP services
# (RDP on 3389, custom listeners, etc.) won't reply with this prefix.
#
# Used for both plain gateway (33XX) and the SNC-enabled gateway port
# (48XX).  When SNC is enforced, the plain probe will be dropped by
# the gateway's SNC pre-handshake check; we still record the open
# port but tag it as ``gateway_snc`` without ``_verified`` suffix —
# the SNC handshake itself is out of scope for the scanner.
# ---------------------------------------------------------------------------

_SAPGW_PROBE = (
    b"\x00\x00\x00\x40"                       # NI length = 64 bytes
    b"\x02\x03\xac\x10\x00\x77\x00\x00\x00\x00"
    b"startrfc\x00\x00"
    b"1100\x00\x00\x00\x00\x00\x00"
    b"default_startrfc        "
    b"\x06\xcb\xff\xff\x00\x00\x00\x00\x00\x00"
)
assert len(_SAPGW_PROBE) == 68, f"SAPGW probe is {len(_SAPGW_PROBE)} bytes, expected 68"

_SAPGW_MATCH = b"\x00\x00\x00\x40\x02\x03\xac\x10\x00\x77"


def _verify_sap_gateway(host: str, port: int, timeout: float = 2.0,
                        saprouter: str = "") -> bool:
    """Send the nmap-sap SAPGW probe; True iff the response echoes the
    expected gateway signature in the first 10 bytes.

    Returns False for:
      - Non-SAP services on 33XX (e.g. RDP on 3389, custom listeners)
      - SNC-enforced gateways that drop the plain probe silently
      - Network errors / timeouts

    A False on a 48XX port does NOT mean "not a gateway" — it usually
    means "SNC required, can't fingerprint at plain-TCP layer".
    """
    sock = None
    try:
        if saprouter:
            from sap_saprouter import connect_through_saprouter
            sock = connect_through_saprouter(
                saprouter + f"/H/{host}/S/{port}",
                timeout=timeout, talk_mode=1,
            )
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
        sock.sendall(_SAPGW_PROBE)
        resp = b""
        try:
            while len(resp) < 64:
                chunk = sock.recv(64 - len(resp))
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass
        return resp.startswith(_SAPGW_MATCH)
    except Exception:
        return False
    finally:
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass


# Canonical DIAG routing string — dispatchers embed "<SID>/<host>_<SID>_<NN>"
# in the DIAG init response.  Used as a SID fallback when only 32XX is open
# (no SAPControl on 5XX13, no gateway on 33XX for RFC_SYSTEM_INFO).
_DIAG_ROUTE_RE = _re.compile(
    rb'([A-Z][A-Z0-9]{2})/([A-Za-z0-9][A-Za-z0-9._-]{0,63})_\1_(\d{2})'
)


def _query_diag_dispatcher_info(host: str, port: int,
                                 timeout: float = 3.0,
                                 saprouter: str = "") -> tuple:
    """Send the full DIAG init probe and parse (sid, hostname, inst) out.

    Modelled on the nmap SAPDISP probe (which only identifies the service
    via the '**DPTMMSG**' marker on an empty NI packet), but uses the
    richer DIAG init probe from SAPology — that response embeds the SID +
    hostname + instance number as an uppercase routing string
    '<SID>/<hostname>_<SID>_<NN>'.

    When *saprouter* is set, delegates to sap_rfc_system_info.probe_diag_login
    (pysap-style TERM_INI + ST_R3INFO[DBNAME] login-screen scrape) because
    that path already supports SAProuter tunnelling and extracts the SID
    from the DBNAME item even on systems where the short routing regex
    doesn't match.

    Returns (sid, hostname, inst_nr) on success, or ("", "", "") if the
    probe failed or no SID could be extracted.
    """
    # SAProuter path — use the pysap-style login-screen scraper, which
    # knows how to tunnel and has the richer DBNAME-based SID extraction.
    if saprouter:
        try:
            from sap_saprouter import parse_route_string
            from sap_rfc_system_info import probe_diag_login
            hops = parse_route_string(saprouter + f"/H/{host}/S/{port}")
            router_tuple = (hops[0]["host"], int(hops[0]["port"]))
            info = probe_diag_login(host, port, timeout=timeout,
                                    verbose=False, router=router_tuple) or {}
        except Exception:
            return ("", "", "")
        sid = (info.get("RFCSYSID") or "").strip().upper()
        if not sid:
            return ("", "", "")
        hn  = (info.get("hostname") or info.get("CPUNAME") or "").strip()
        if hn:
            hn = hn.split(".")[0]
        inst = str(info.get("instance_number") or f"{port % 100:02d}")
        return (sid, hn, inst)

    # Direct path — lightweight DIAG init probe with routing-string regex.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(_SAP_DIAG_PROBE)
        resp = b""
        try:
            # DIAG init response is typically 5-8 KB; cap at 16 KB so a
            # chatty / malformed response doesn't stall us indefinitely.
            while len(resp) < 16384:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass
        s.close()
    except Exception:
        return ("", "", "")

    m = _DIAG_ROUTE_RE.search(resp)
    if m:
        return (m.group(1).decode("ascii", "ignore"),
                m.group(2).decode("ascii", "ignore"),
                m.group(3).decode("ascii", "ignore"))

    # Direct-path fallback: the routing-string regex didn't hit — try the
    # pysap DBNAME scrape locally too so locked-down systems still leak
    # their SID via the login screen.
    try:
        from sap_rfc_system_info import probe_diag_login
        info = probe_diag_login(host, port, timeout=timeout,
                                verbose=False, router=None) or {}
    except Exception:
        return ("", "", "")
    sid = (info.get("RFCSYSID") or "").strip().upper()
    if not sid:
        return ("", "", "")
    hn  = (info.get("hostname") or info.get("CPUNAME") or "").strip()
    if hn:
        hn = hn.split(".")[0]
    inst = str(info.get("instance_number") or f"{port % 100:02d}")
    return (sid, hn, inst)


# MS HTTP "release" banner — "SAP Message Server, release 793 (S4H)" —
# embeds the SID in parentheses.  Used as a second extraction path when
# the text/logon body doesn't contain the routing string.
_MS_RELEASE_SID_RE = _re.compile(
    rb'SAP Message Server, release \d+\s*\(([A-Z][A-Z0-9]{2})\)', _re.IGNORECASE
)

# MS HTTP logon body — server identifier "<host>_<SID>_<NN>" without
# the leading "SID/" prefix that the DIAG response carries.  Matches
# "s4hanadev_S4H_00" in the plain-text /msgserver/text/logon body.
_MS_ROUTE_RE = _re.compile(
    rb'(?:^|[\s\n])([A-Za-z0-9][A-Za-z0-9._-]{0,63})_([A-Z][A-Z0-9]{2})_(\d{2})\b'
)


def _query_ms_http_info(host: str, inst_nr: int,
                        timeout: float = 3.0,
                        saprouter: str = "") -> tuple:
    """Query the MS HTTP port (81XX) for unauthenticated server info.

    The MS-internal (36XX) and MS-external (39XX) binary ports reject
    anonymous admin queries on locked-down kernels, but the MS HTTP
    port at 8100+NN exposes /msgserver/text/logon to everyone.  The
    plain-text body contains the routing string '<host>_<SID>_<NN>'
    and the HTTP 'server:' header contains 'release X (SID)'.

    When *saprouter* is set, the HTTP GET is tunnelled through the
    SAProuter using a raw (NI_RAW_IO) NI_ROUTE channel so the probe
    works against internal hosts.

    Returns (sid, hostname, inst_nr_str) on success, or ("", "", "").
    Called as a fallback when MS ports are open but the gateway and
    SAPControl metadata channels are firewalled.
    """
    port = 8100 + inst_nr
    try:
        if saprouter:
            from sap_saprouter import connect_through_saprouter
            s = connect_through_saprouter(
                saprouter + f"/H/{host}/S/{port}",
                timeout=timeout, talk_mode=1,
            )
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
        s.sendall(
            b"GET /msgserver/text/logon HTTP/1.0\r\n"
            b"Host: x\r\n\r\n"
        )
        resp = b""
        while len(resp) < 16384:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            resp += chunk
        try:
            s.close()
        except Exception:
            pass
    except Exception:
        return ("", "", "")

    if not resp:
        return ("", "", "")

    # Preferred: MS body contains "<host>_<SID>_<NN>" on its own line
    m = _MS_ROUTE_RE.search(resp)
    if m:
        return (m.group(2).decode("ascii", "ignore"),   # SID
                m.group(1).decode("ascii", "ignore"),   # hostname
                m.group(3).decode("ascii", "ignore"))   # inst

    # Fallback: SID from "server: SAP Message Server, release N (SID)" header
    m = _MS_RELEASE_SID_RE.search(resp)
    if m:
        return (m.group(1).decode("ascii", "ignore"),
                "",
                f"{inst_nr:02d}")

    return ("", "", "")


# Ports that collide with SAP port formulas but are NOT standard SAP services.
# 3389 = RDP (instance 89 gateway would be 3300+89=3389) — currently not scanned
NON_SAP_PORTS = set()

# SAProuter port — scanned separately, not as a dispatcher
SAPROUTER_PORT = 3299

# SAP Cloud Connector admin UI default port — fingerprinted (not enumerated as SAP)
SCC_DEFAULT_PORT = 8443


def _build_port_list(instance_range, include_hana=False, skip_non_sap=True):
    """Build list of (port, service, instance_nr) tuples for scanning.

    Includes dispatcher (32XX) for fast discovery.
    Gateway (33XX) and HANA SQL (3XX13/3XX15) are scanned in Pass 2
    only for instances where a dispatcher was found.
    """
    ports = []
    for inst_nr in range(instance_range[0], instance_range[1] + 1):
        inst_str = f"{inst_nr:02d}"
        # Dispatcher (32XX) and Gateway (33XX)
        for svc_name, base_port in FAST_SCAN_PORT_PATTERNS.items():
            port = base_port + inst_nr
            if skip_non_sap and port in NON_SAP_PORTS:
                continue
            # Port 3299 = SAProuter — label as "saprouter" not "dispatcher"
            if port == SAPROUTER_PORT and svc_name == "dispatcher":
                ports.append((port, "saprouter", "99"))
                continue
            ports.append((port, svc_name, inst_str))
        # HANA SQL ports: 3XX13 (SystemDB) and 3XX15 (first tenant)
        if include_hana:
            hana_sysdb = 30000 + inst_nr * 100 + 13
            hana_tenant = 30000 + inst_nr * 100 + 15
            ports.append((hana_sysdb, "hana_sql", inst_str))
            ports.append((hana_tenant, "hana_sql", inst_str))
    return ports


def fast_scan_host(host: str, instance_range: tuple = DEFAULT_INSTANCE_RANGE,
                   timeout: float = DEFAULT_TIMEOUT, threads: int = DEFAULT_THREADS,
                   cancel_event: threading.Event = None,
                   skip_quick_check: bool = False) -> dict:
    """Fast scan a single host for SAP ports.

    Two-pass approach:
      Pass 1: Scan dispatcher (32XX), SAPHostControl (1128/1129)
      Pass 2: If SAP found, scan gateway (33XX) + HANA SQL (3XX13/3XX15) for detected instances

    Verifies dispatcher ports with SAP DIAG protocol probe to eliminate
    false positives from non-SAP services on 32XX ports.

    Returns dict: {
        "host": str,
        "open_ports": {port: {"service": str, "instance_nr": str}},
        "has_sap": bool
    }
    """
    result = {"host": host, "open_ports": {}, "has_sap": False}

    # Quick pre-check: probe SAP dispatcher ports (3200-3299), gateway,
    # HTTP, SAPControl and SAPHostControl with a short timeout.
    # If none respond, skip the full scan.  All ports are probed in
    # parallel so wall-clock time equals the timeout (~1.5s max).
    # Skipped for single-target scans where the time saving is negligible.
    if cancel_event and cancel_event.is_set():
        return result
    if not skip_quick_check:
        # Quick probe set: dispatcher range (3200-3299) + SAPControl 5XX13
        # + SAPHostControl (1128) + the WD well-known ports.  The WD
        # ports go in here so a host that ONLY runs a hardened DMZ WD
        # (no dispatcher port, no SAPControl) still trips the quick
        # check and gets a full scan.
        QUICK_PORTS = (
            list(range(3200, 3300))
            + [50013, 50113, 50213, 50313, 54213, 1128]
            + list(WELL_KNOWN_WD_PORTS)
        )
        quick_timeout = min(timeout, 1.5)
        quick_hit = False
        qe = ThreadPoolExecutor(max_workers=min(len(QUICK_PORTS), 20))
        qf = [qe.submit(_scan_port, host, p, quick_timeout) for p in QUICK_PORTS]
        for f in as_completed(qf):
            if cancel_event and cancel_event.is_set():
                break
            if f.result():
                quick_hit = True
                break
        qe.shutdown(wait=False)
        if cancel_event and cancel_event.is_set():
            return result
        if not quick_hit:
            print(f"[*] {host}: Quick probe ({len(QUICK_PORTS)} ports) — "
                  f"no response, skipping full scan")
            return result

    _cancelled = lambda: cancel_event and cancel_event.is_set()

    def _do_scan(port_list, label="scan"):
        hits = {}
        total = len(port_list)
        # Aim for ~4 progress ticks per pass, clamped between 25 and 200 ports.
        tick_every = max(25, min(200, total // 4 or 1))
        done = 0
        t_pass = time.time()

        def _check(args):
            port, svc, inst = args
            if _cancelled():
                return None
            if _scan_port(host, port, timeout):
                return (port, svc, inst)
            return None
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(_check, a) for a in port_list]
            for f in as_completed(futures):
                if _cancelled():
                    break
                r = f.result()
                done += 1
                if r:
                    hits[r[0]] = {"service": r[1], "instance_nr": r[2]}
                    # Live discovery — print immediately so the user sees
                    # something happen during a long pass.
                    print(f"[+]   {host}:{r[0]:<6} OPEN  "
                          f"({r[1]}, inst {r[2]})")
                if done % tick_every == 0 and done < total:
                    elapsed = time.time() - t_pass
                    print(f"[*]   {host}: {label} {done}/{total} probed, "
                          f"{len(hits)} open  [{elapsed:.1f}s]")
        return hits

    # Pass 1: Dispatcher + SAPControl + fixed ports (fast — ~300 ports)
    ports_pass1 = _build_port_list(instance_range, include_hana=False)
    # SAPControl HTTP ports (5XX13) — detects ABAP, JAVA, and double-stack
    for inst_nr in range(instance_range[0], instance_range[1] + 1):
        ports_pass1.append((50013 + inst_nr * 100, "sapcontrol", f"{inst_nr:02d}"))
    ports_pass1.append((1128, "saphost_http", "XX"))
    ports_pass1.append((1129, "saphost_https", "XX"))
    # SAP Cloud Connector admin UI (8443/tcp) — fingerprinted in a follow-up
    # phase, not promoted to a SAPNode here.  Including it in Pass 1 ensures
    # a host that ONLY runs SCC (no dispatcher 32XX) is still recognised by
    # the scanner; the quick-probe above already lists 8443 to keep alive.
    ports_pass1.append((SCC_DEFAULT_PORT, "scc_admin", "XX"))
    # SAP Web Dispatcher well-known ports — see WELL_KNOWN_WD_PORTS in
    # sapmap_config.py.  Added to Pass 1 so a hardened DMZ WD (no 32XX,
    # no SAPControl) still gets discovered.  Each port goes in as
    # "wd_candidate" with instance "WD" (no real instance number — the
    # WD doesn't expose one over plain HTTP).  Post-scan we run
    # fingerprint_web_dispatcher() to confirm each candidate is really
    # a SAP WD (vs. an arbitrary HTTP service that happens to listen
    # on the same port) and promote confirmed ones to is_web_dispatcher.
    for wd_port in WELL_KNOWN_WD_PORTS:
        ports_pass1.append((wd_port, "wd_candidate", "WD"))

    if _cancelled():
        return result
    print(f"[*] {host}: Pass 1: scanning {len(ports_pass1)} ports "
          f"(dispatcher 32XX, SAPHostControl) ...")
    t0 = time.time()
    hits1 = _do_scan(ports_pass1, label="Pass 1")
    if _cancelled():
        return result
    result["open_ports"].update(hits1)
    print(f"[*] {host}: Pass 1 done in {time.time() - t0:.1f}s — "
          f"{len(hits1)} open port(s)")

    # Verify dispatcher ports with DIAG protocol probe
    disp_ports = [p for p, info in result["open_ports"].items()
                  if info["service"] == "dispatcher"]
    if disp_ports and not _cancelled():
        print(f"[*] {host}: Verifying {len(disp_ports)} dispatcher port(s) "
              f"with SAP DIAG protocol probe ...")
    for port in list(disp_ports):
        if _cancelled():
            break
        if not _verify_sap_diag(host, port, timeout=min(timeout, 2.0)):
            del result["open_ports"][port]

    # Verify WD-candidate ports (80/443/8000/8080/8443/44300/50000/50001
    # and friends).  Any TCP service may listen on those ports, so we
    # MUST fingerprint each one as a real SAP WD/ICM before promoting
    # it into a SAPNode — otherwise a plain nginx on port 443 would
    # become a false positive "SAP WD" node.
    wd_candidate_ports = [p for p, info in result["open_ports"].items()
                            if info["service"] == "wd_candidate"]
    if wd_candidate_ports and not _cancelled():
        print(f"[*] {host}: Fingerprinting {len(wd_candidate_ports)} "
              f"WD-candidate port(s) with /sap/wdisp/admin probe ...")
        # WD-fingerprint takes ~3-5s per port; cap concurrency at 4 so a
        # host with all 9 WD candidates open doesn't burn 9 × 5s serially.
        result.setdefault("wd_info", {})
        with ThreadPoolExecutor(max_workers=4) as wexec:
            future_map = {}
            for p in wd_candidate_ports:
                # HTTPS heuristic: 443, 8443, 44300, 50001 are TLS by default
                is_https = p in (443, 8443, 44300, 50001)
                future_map[wexec.submit(
                    fingerprint_web_dispatcher, host, p,
                    https=is_https,
                    timeout=min(timeout, 4),
                    saprouter="",     # WD fingerprint goes direct
                )] = (p, is_https)
            for fut in as_completed(future_map):
                if _cancelled():
                    break
                p, is_https = future_map[fut]
                try:
                    fp = fut.result()
                except Exception as e:
                    print(f"[-]   {host}:{p}  WD fingerprint error: {e}")
                    if p == SCC_DEFAULT_PORT:
                        # 8443 was registered TWICE on the candidate
                        # list (once as 'scc_admin' at line ~722 then
                        # again as 'wd_candidate' inside the
                        # WELL_KNOWN_WD_PORTS loop, since 8443 is in
                        # both pools).  Last-write-wins made the WD
                        # tag take precedence, so the WD fingerprint
                        # ran.  If it errored on an SCC (very common -
                        # the SCC admin UI doesn't speak the WD
                        # /sap/wdisp/admin probe path), KEEP the port
                        # in open_ports tagged as 'scc_admin' so
                        # _maybe_build_scc_node downstream can do its
                        # SCC-specific fingerprint.  Operator-reported
                        # regression: without this, SCC at
                        # 192.168.2.209:8443 was never detected
                        # because WD fingerprint failed → port was
                        # dropped → SCC fingerprint never ran.
                        result["open_ports"][p]["service"] = "scc_admin"
                    else:
                        del result["open_ports"][p]
                    continue
                if fp["is_wd"]:
                    # Confirmed SAP WD — rename service to reflect
                    # confidence + protocol so downstream code knows.
                    svc = f"wd_{'https' if is_https else 'http'}"
                    result["open_ports"][p]["service"] = svc
                    result["wd_info"][p] = fp
                    # If the port follows SAP's 80NN / 443NN instance
                    # formula, derive the real instance number from it
                    # (8011 → 11, 44311 → 11) and re-tag the candidate's
                    # instance_nr.  Without this, the WD's port lives
                    # under the placeholder instance "WD" and the node-
                    # builder synthesises a separate "Wxx" node even
                    # when the same instance has SAPControl on 5XX13
                    # already feeding a real SID — operator-reported
                    # 172.31.14.107 regression: SW1 (inst 11, port
                    # 51113) and W6B (port 8011) shown as two separate
                    # systems despite being the same instance 11 WD.
                    derived_inst = _derive_instance_from_wd_port(p)
                    if derived_inst:
                        result["open_ports"][p]["instance_nr"] = derived_inst
                    ver = f" v{fp['wd_version']}" if fp["wd_version"] else ""
                    inst_tag = (f" inst={derived_inst}"
                                if derived_inst else "")
                    print(f"[+]   {host}:{p:<6} CONFIRMED SAP Web "
                          f"Dispatcher{ver}{inst_tag}  ({fp['evidence']}, "
                          f"confidence={fp['confidence']})")
                    # NOTE: cache detection + backend topology discovery
                    # are NOT run here.  Both send 3-17 GET probes
                    # through the WD which warms the backend connection
                    # pool, making the subsequent ICMAD smuggle probe
                    # miss (the bug fires on first request to a freshly
                    # established backend connection, see plan §G race
                    # caveat).  Operator can run them on-demand from
                    # the "Rediscover WD topology" right-click menu.
                    print(f"[*]   {host}:{p:<6} cache + backend "
                          f"discovery skipped (right-click → 'Rediscover "
                          f"WD topology' to run; keeps WD pool idle "
                          f"so the ICMAD smuggle fires cleanly)")
                elif fp["is_sap_icm"]:
                    # SAP ICM but not specifically WD — could be an app
                    # server's ICM exposed on a non-standard port.  Keep
                    # the port but label it appropriately; downstream
                    # node-builder will treat as a Java/ABAP ICM port.
                    svc = f"icm_{'https' if is_https else 'http'}"
                    result["open_ports"][p]["service"] = svc
                    result["wd_info"][p] = fp
                    # 80NN / 443NN — same instance-derivation as the WD
                    # branch above so an ICM on 8011 folds into the same
                    # SAPNode as that instance's SAPControl on 51113.
                    derived_inst = _derive_instance_from_wd_port(p)
                    if derived_inst:
                        result["open_ports"][p]["instance_nr"] = derived_inst
                    inst_tag = (f" inst={derived_inst}"
                                if derived_inst else "")
                    print(f"[+]   {host}:{p:<6} SAP ICM (not WD){inst_tag}  "
                          f"({fp['evidence']})")
                else:
                    # Non-SAP service squatting the port (nginx, IIS,
                    # apache, etc.) — drop it from open_ports so we
                    # don't synthesise a false-positive node.
                    srv = fp["server_header"] or "<no Server header>"
                    if p == SCC_DEFAULT_PORT:
                        # See the WD fingerprint-error branch above
                        # for the full explanation: 8443 also serves
                        # as the SAP Cloud Connector admin UI port.
                        # SCC doesn't return SAP WD or SAP ICM
                        # headers (it speaks its own admin-shell
                        # HTTP API), so the WD fingerprint flags it
                        # as "non-SAP service" — but that's exactly
                        # what we expect for an SCC.  Keep the port
                        # tagged as 'scc_admin' so the downstream
                        # _maybe_build_scc_node check can run its
                        # SCC-specific fingerprint.  Build-nodes
                        # filters scc_admin out of the gateway /
                        # dispatcher loops, so no false-positive
                        # SAPNode is synthesised here.
                        print(f"[*]   {host}:{p:<6} not a SAP WD/ICM "
                              f"(Server: {srv[:50]}); deferring to "
                              f"SCC fingerprint")
                        result["open_ports"][p]["service"] = "scc_admin"
                    else:
                        print(f"[-]   {host}:{p:<6} non-SAP service "
                              f"({srv[:50]})  — dropping")
                        del result["open_ports"][p]

    if _cancelled():
        return result
    result["has_sap"] = len(result["open_ports"]) > 0

    # Pass 2: Gateway + HANA SQL ports — only for discovered instances
    if result["has_sap"] and not _cancelled():
        # Pseudo-instances "XX" (SAPControl/host-agent) and "WD"
        # (Web Dispatcher candidate ports) have no instance number;
        # we can't derive 33XX/3XX13/50000+nn*100 from them and
        # int() would blow up.  Skip them — those instance buckets
        # were never going to need a Pass 2 anyway.
        found_instances = sorted(set(
            v["instance_nr"] for v in result["open_ports"].values()
            if v["instance_nr"] not in ("XX", "WD")
            and (v["instance_nr"] or "").isdigit()
        ))
        pass2_ports = []
        for inst_str in found_instances:
            inst_nr = int(inst_str)
            pass2_ports.append((3300 + inst_nr, "gateway", inst_str))
            # SAP Gateway SNC port (gw/snc_port) — 4800+NN.  Opens up when
            # the operator sets snc/enable=1 on the system.  Fingerprinted
            # post-scan via the nmap-sap SAPGW probe; SNC-enforced ports
            # may not echo the signature but stay tagged as gateway_snc.
            pass2_ports.append((4800 + inst_nr, "gateway_snc", inst_str))
            pass2_ports.append((3900 + inst_nr, "ms_internal", inst_str))  # betrusted
            pass2_ports.append((30000 + inst_nr * 100 + 13, "hana_sql", inst_str))
            pass2_ports.append((30000 + inst_nr * 100 + 15, "hana_sql", inst_str))
            # Java HTTP / HTTPS dispatcher ports (icm) — by SAP convention
            # 50000+nn*100 (HTTP) and +1 (HTTPS).  Cheap fallback for when
            # SAPControl is firewalled or refuses GetInstanceProperties.
            pass2_ports.append((50000 + inst_nr * 100,     "java_http",  inst_str))
            pass2_ports.append((50000 + inst_nr * 100 + 1, "java_https", inst_str))

        print(f"[*] {host}: Pass 2: scanning {len(pass2_ports)} ports "
              f"(gateway 33XX, gateway SNC 48XX, HANA 3XX13/3XX15, "
              f"Java 5NN00/01) for {len(found_instances)} instance(s) ...")
        t0 = time.time()
        hits2 = _do_scan(pass2_ports, label="Pass 2")
        if not _cancelled():
            result["open_ports"].update(hits2)
            print(f"[*] {host}: Pass 2 done in {time.time() - t0:.1f}s — "
                  f"{len(hits2)} port(s) open")

        # Verify each open gateway / gateway_snc port really speaks the
        # SAP gateway protocol — avoids false positives like RDP on 3389
        # (which our 3300+NN formula would have flagged for instance 89).
        # Behaviour split:
        #   33XX → fingerprint required, port DROPPED when verify fails
        #          (false-positive rejection — there is no legitimate
        #          reason for a SAP gateway listener to drop the probe)
        #   48XX → fingerprint preferred, port KEPT when verify fails
        #          (SNC enforcement may silently drop the plain probe;
        #          we still want to record the open port so the operator
        #          sees the SNC gateway exists)
        gw_ports = [(p, info["service"]) for p, info in result["open_ports"].items()
                    if info["service"] in ("gateway", "gateway_snc")]
        if gw_ports and not _cancelled():
            print(f"[*] {host}: Verifying {len(gw_ports)} gateway port(s) "
                  f"with SAP CPIC startrfc probe ...")
            for port, svc in gw_ports:
                if _cancelled():
                    break
                verified = _verify_sap_gateway(host, port,
                                               timeout=min(timeout, 2.0))
                if verified:
                    result["open_ports"][port]["service"] = (
                        "gateway" if svc == "gateway" else "gateway_snc_verified")
                    print(f"[+]   {host}:{port:<6} SAP gateway fingerprint "
                          f"confirmed ({svc})")
                elif svc == "gateway":
                    # False positive — drop the port
                    del result["open_ports"][port]
                    print(f"[-]   {host}:{port:<6} did not respond to SAP "
                          f"CPIC probe — dropped (likely non-SAP service)")
                else:
                    # gateway_snc → keep but note SNC likely enforced
                    print(f"[*]   {host}:{port:<6} no SAP echo on plain "
                          f"probe — SNC likely enforced, kept as gateway_snc")

    return result


def fast_scan_network(targets: list, instance_range: tuple = DEFAULT_INSTANCE_RANGE,
                      timeout: float = DEFAULT_TIMEOUT, threads: int = DEFAULT_THREADS,
                      cancel_event: threading.Event = None,
                      progress_callback=None, skip_alive: bool = False,
                      concurrent_hosts: int = 5, port_timeout: float = 3.0) -> list:
    """Fast scan multiple hosts for SAP systems.

    Three-stage approach for speed:
      1. Alive sweep — parallel ping + TCP probes to eliminate dead hosts (~3s)
      2. Parallel SAP port scan — scan all alive hosts concurrently
      3. Collect results

    Args:
        targets: list of IP addresses
        instance_range: (start, end) instance numbers to scan
        timeout: socket timeout per port
        threads: threads per host for port scanning
        cancel_event: threading.Event to signal cancellation
        progress_callback: callable(scanned, total, host, found_count)

    Returns:
        list of dicts from fast_scan_host() where has_sap=True
    """
    total = len(targets)
    num_ports = (instance_range[1] - instance_range[0] + 1) * len(FAST_SCAN_PORT_PATTERNS)

    print(f"[*] === PHASE 1: Fast Port Scan ===")
    print(f"[*] Targets: {total} hosts")
    print(f"[*] Ports per host: {num_ports} "
          f"(instances {instance_range[0]:02d}-{instance_range[1]:02d}, "
          f"dispatcher 32XX)")
    print(f"[*] Timeout: {timeout}s, Threads: {threads}")

    scan_start = time.time()

    # --- Stage 1: Alive sweep (skip for small target lists or if disabled) ---
    # Use threshold of 10+ targets: for small lists the full port scan is
    # fast enough, and alive sweep can miss hosts whose SAP instance ports
    # (e.g. 3210/3310 for instance 10) don't overlap the probe port list.
    if not skip_alive and total > 10:
        print(f"")
        alive_hosts = alive_sweep(targets, threads=min(total, 100),
                                  cancel_event=cancel_event)
        if cancel_event and cancel_event.is_set():
            return []
        if not alive_hosts:
            print(f"[*] No alive hosts found in {total} targets")
            return []
        skipped = total - len(alive_hosts)
        if skipped > 0:
            print(f"[*] Skipping {skipped} unreachable hosts")
        print(f"")
    else:
        alive_hosts = list(targets)

    # --- Stage 2: Parallel host scan ---
    # Scan multiple hosts concurrently (controlled by concurrent_hosts).
    # Each host still gets its own thread pool for port scanning so that
    # per-host parallelism stays high.  With concurrent_hosts=5 a /24
    # with 15 alive hosts completes in ~24s instead of ~120s.
    found = []
    found_lock = threading.Lock()
    host_count = len(alive_hosts)
    port_threads = min(threads, 20)
    port_timeout = min(timeout, port_timeout)
    completed = [0]
    completed_lock = threading.Lock()

    # Auto-scale concurrency: for small target lists, limit parallel hosts
    # to avoid overwhelming the network with too many simultaneous connections
    max_parallel = max(concurrent_hosts, 1)
    if host_count <= 10:
        max_parallel = min(max_parallel, 2)
    print(f"[*] SAP port scanning {host_count} alive hosts "
          f"({max_parallel} concurrent, {port_threads} threads/host, "
          f"port timeout={port_timeout}s) ...")

    def _scan_one(idx, host):
        if cancel_event and cancel_event.is_set():
            return
        print(f"[*]   [{idx+1}/{host_count}] Scanning {host} ...")
        r = fast_scan_host(host, instance_range, port_timeout, port_threads,
                           cancel_event, skip_quick_check=(host_count <= 10))
        if cancel_event and cancel_event.is_set():
            return
        with completed_lock:
            completed[0] += 1
            nr = completed[0]
        elapsed = time.time() - scan_start

        if r["has_sap"]:
            services = {}
            for p, info in r["open_ports"].items():
                svc = info["service"]
                inst = info["instance_nr"]
                services.setdefault(svc, []).append(f"{p} (inst {inst})")
            svc_str = "; ".join(
                f"{s}: {', '.join(ps)}" for s, ps in sorted(services.items())
            )
            with found_lock:
                found.append(r)
            print(f"[+] [{nr}/{host_count}] {host} — SAP found: "
                  f"{svc_str}  ({elapsed:.1f}s)")
        else:
            print(f"[*] [{nr}/{host_count}] {host} — no SAP  "
                  f"({elapsed:.1f}s)")

        if progress_callback:
            with found_lock:
                fc = len(found)
            progress_callback(nr, host_count, host, fc)

    with ThreadPoolExecutor(max_workers=max_parallel) as executor:
        futures = [executor.submit(_scan_one, i, h)
                   for i, h in enumerate(alive_hosts)]
        for f in as_completed(futures):
            if cancel_event and cancel_event.is_set():
                break
            f.result()
        # executor.__exit__ waits for running threads; workers check cancel
        # so they finish within one socket timeout (~2s)

    if cancel_event and cancel_event.is_set():
        print(f"[!] Port scan cancelled")
        return found

    # Print found details
    if found:
        print(f"")
        for r in found:
            host = r["host"]
            services = {}
            for p, info in r["open_ports"].items():
                svc = info["service"]
                inst = info["instance_nr"]
                services.setdefault(svc, []).append(f"{p} (inst {inst})")
            print(f"[+] {host}:")
            for svc, port_list in sorted(services.items()):
                print(f"      {svc}: {', '.join(port_list)}")

    elapsed = time.time() - scan_start
    print(f"")
    print(f"[+] Port scan complete in {elapsed:.1f}s: "
          f"{len(found)} SAP hosts found out of {total} targets "
          f"({host_count} alive)")
    return found


# ---------------------------------------------------------------------------
# MS betrusted ACL check (CVE-2020-6207)
# ---------------------------------------------------------------------------

def check_ms_betrusted(node: SAPNode, timeout: float = 8.0) -> bool:
    """Check all MS internal ports on a node for CVE-2020-6207 (betrusted).

    Probes each known instance's MS internal port (39NN).  Updates:
      node.ms_port          — first open MS port found
      node.ms_vulnerable    — True if MS accepts unauthenticated login
      node.ms_acl_protected — True if port reachable but ACL blocks our IP

    Returns True if any MS port was found (open OR ACL-protected).
    """
    try:
        from sap_ms_betrusted import sapmap_check_ms
    except ImportError:
        logger.warning("sap_ms_betrusted not available — skipping MS check")
        return False

    host = node.ip or node.hostname
    if not host:
        return False

    # Collect all candidate instance numbers from known ports
    candidate_instances = set()
    for inst in node.instances:
        try:
            candidate_instances.add(int(inst.instance_nr))
        except (ValueError, TypeError):
            pass
        for port in inst.ports:
            try:
                p = int(port)
                # Gateway 33XX → instance XX; dispatcher 32XX → instance XX
                if 3300 <= p <= 3399:
                    candidate_instances.add(p - 3300)
                elif 3200 <= p <= 3299:
                    candidate_instances.add(p - 3200)
                elif 3900 <= p <= 3999:
                    candidate_instances.add(p - 3900)
            except (ValueError, TypeError):
                pass

    # If nothing known yet, probe common instances
    if not candidate_instances:
        candidate_instances = {0, 1, 2}

    found_any = False
    for inst_nr in sorted(candidate_instances):
        try:
            import sapmap_stop
            if sapmap_stop.is_stop_requested():
                return found_any
        except ImportError:
            pass
        result = sapmap_check_ms(host, inst_nr, timeout)
        ms_p = result["port"]

        if result["accessible"]:
            found_any = True
            node.ms_port = ms_p
            node.ms_vulnerable    = result["vulnerable"]
            node.ms_acl_protected = result.get("acl_protected", False)

            if result["vulnerable"]:
                logger.info(f"{node.sid}: MS port {ms_p} VULNERABLE (CVE-2020-6207) "
                            f"— no ACL, betrusted attack possible")
                emit_finding(
                    "HIGH", node.sid,
                    f"MS port {ms_p} accepts unauthenticated login — "
                    f"10KBLAZE betrusted attack path open",
                    cve="CVE-2020-6207",
                    attack_capability="exploit.ms_betrusted",
                )
                node.findings.append(Finding(
                    name="MS Internal Port Without ACL (CVE-2020-6207)",
                    severity=Severity.CRITICAL,
                    attack_techniques=_attack_for("exploit.ms_betrusted"),
                    description=(
                        "SAP Message Server internal port is accessible without "
                        "authentication (no access control list configured). "
                        "An attacker can register a fake dispatcher and inject their "
                        "IP into the SAP Gateway's trusted host list (10KBLAZE betrusted), "
                        "enabling unauthenticated OS command execution via SAPXPG."
                    ),
                    remediation=(
                        "1. Firewall port 39NN to allow only SAP hosts. "
                        "2. Configure ms/acl_info and ms/server_ip_check in DEFAULT.PFL. "
                        "3. Apply SAP Security Note 2821575."
                    ),
                    detail=f"Port {ms_p} open; MS name: {result.get('ms_name', '')}",
                ))
                node.has_critical_finding = True
                break  # found a vulnerable MS — no need to probe more
            elif result["acl_protected"]:
                logger.info(f"{node.sid}: MS port {ms_p} accessible but ACL-protected "
                            f"(errorno={result.get('errorno', '?')})")
                # Only add finding if not already present
                if not any(f.name == "MS Internal Port Exposed" for f in node.findings):
                    node.findings.append(Finding(
                        name="MS Internal Port Exposed (ACL Active)",
                        severity=Severity.MEDIUM,
                        attack_techniques=_attack_for("recon.fast_scan"),
                        description=(
                            "SAP Message Server internal port is reachable from the network "
                            "but has an ACL configured that blocks unauthenticated login. "
                            "The port itself should not be accessible from outside the SAP landscape."
                        ),
                        remediation="Firewall port 39NN to SAP hosts only.",
                        detail=f"Port {ms_p} reachable; ACL blocks login from this IP",
                    ))
                break

    return found_any


# ---------------------------------------------------------------------------
# CVE-2025-31324 — Java VisualComposer metadatauploader unauth RCE
# ---------------------------------------------------------------------------

def check_cve_2025_31324(node: SAPNode, timeout: float = 10.0) -> bool:
    """Probe Java ports for CVE-2025-31324 (Visual Composer metadatauploader).

    Only runs against Java / double-stack nodes — returns False immediately for
    pure-ABAP systems where the endpoint is not hosted.

    Updates:
      node.cve_2025_31324_checked    — set True after any probe attempt
      node.cve_2025_31324_vulnerable — True on positive detection
      node.cve_2025_31324_port       — HTTP port that detected the vuln
      node.cve_2025_31324_https      — True if probed via HTTPS
      node.cve_2025_31324_evidence   — short reason string

    Returns True if a vulnerable port was found.
    """
    try:
        from sap_cve_2025_31324 import check_cve_2025_31324 as _probe
    except ImportError:
        logger.warning("sap_cve_2025_31324 not available — skipping")
        return False

    sys_type = (node.system_type or "").upper()
    if not sys_type:
        logger.debug(f"{node.sid}: system_type unknown, skipping CVE-2025-31324 probe")
        return False
    if "JAVA" not in sys_type:
        logger.debug(f"{node.sid}: not a Java stack ({sys_type}) — "
                     "skipping CVE-2025-31324")
        return False

    host = node.ip or node.hostname
    if not host:
        return False

    node.cve_2025_31324_checked = True

    # Candidate HTTP ports: 50000 + nn*100 (plain), 50000 + nn*100 + 1 (HTTPS).
    # Prefer ports already known to be open.
    candidates = []
    for inst in node.instances:
        try:
            nr = int(inst.instance_nr)
        except (ValueError, TypeError):
            continue
        base = 50000 + nr * 100
        for p, use_https in [(base, False), (base + 1, True)]:
            if p in inst.ports or (p, use_https) not in candidates:
                candidates.append((p, use_https))
    if not candidates:
        # No instances known — probe common Java ports as a last resort.
        for nr in (0, 1, 2, 3):
            base = 50000 + nr * 100
            candidates.append((base, False))
            candidates.append((base + 1, True))

    for port, use_https in candidates:
        try:
            import sapmap_stop
            if sapmap_stop.is_stop_requested():
                return False
        except ImportError:
            pass
        if not _scan_port(host, port, timeout=2.0):
            continue
        logger.info(f"{node.sid}: probing {host}:{port} "
                    f"{'(HTTPS)' if use_https else ''} for CVE-2025-31324")
        r = _probe(host, port, use_https=use_https, timeout=timeout)
        if not r.get("reachable"):
            continue
        if r.get("vulnerable"):
            node.cve_2025_31324_vulnerable = True
            node.cve_2025_31324_port = port
            node.cve_2025_31324_https = use_https
            node.cve_2025_31324_evidence = r.get("evidence", "")
            logger.info(f"{node.sid}: VULNERABLE to CVE-2025-31324 on port {port}")
            emit_finding(
                "CRITICAL", node.sid,
                f"CVE-2025-31324 metadatauploader unauth RCE on port {port}",
                cve="CVE-2025-31324",
                attack_capability="exploit.cve_2025_31324",
            )
            if not any(f.name.startswith("CVE-2025-31324") for f in node.findings):
                node.findings.append(Finding(
                    name="CVE-2025-31324 — VisualComposer Metadatauploader RCE",
                    severity=Severity.CRITICAL,
                    attack_techniques=_attack_for("exploit.cve_2025_31324"),
                    description=(
                        "SAP NetWeaver Visual Composer exposes "
                        "/developmentserver/metadatauploader without "
                        "authentication.  An attacker can upload a zipped "
                        ".properties payload containing a Java deserialisation "
                        "gadget (TemplatesImpl) and obtain arbitrary OS "
                        "command execution as the SAP Java process user."
                    ),
                    remediation=(
                        "Apply SAP Security Note 3594142 (April 2025). "
                        "Disable Visual Composer if not in use. "
                        "Restrict network access to the Java HTTP port."
                    ),
                    detail=f"Port {port} · {r.get('evidence', '')}",
                ))
                node.has_critical_finding = True
            return True
        else:
            # Record the first reachable-but-not-vulnerable result so the GUI
            # can show the reason (useful after patching).
            node.cve_2025_31324_port = port
            node.cve_2025_31324_https = use_https
            node.cve_2025_31324_evidence = r.get("evidence", "")

    return False


# ---------------------------------------------------------------------------
# CVE-2020-6287 (RECON) — LM Configuration Wizard unauth user creation
# ---------------------------------------------------------------------------

def check_cve_2020_6287(node: SAPNode, timeout: float = 10.0) -> bool:
    """Probe Java ports for CVE-2020-6287 (RECON).

    HEAD /CTCWebService/CTCWebServiceBean → 200 = vulnerable.

    Only runs against Java / double-stack systems.  Port selection reuses
    the same instance-based HTTP-port candidates as check_cve_2025_31324.
    """
    try:
        from sap_cve_2020_6287 import check_cve_2020_6287 as _probe
    except ImportError:
        logger.warning("sap_cve_2020_6287 not available — skipping")
        return False

    sys_type = (node.system_type or "").upper()
    if "JAVA" not in sys_type:
        return False

    host = node.ip or node.hostname
    if not host:
        return False

    node.cve_2020_6287_checked = True

    candidates = []
    for inst in node.instances:
        try:
            nr = int(inst.instance_nr)
        except (ValueError, TypeError):
            continue
        base = 50000 + nr * 100
        for p, use_https in [(base, False), (base + 1, True)]:
            candidates.append((p, use_https))
    if not candidates:
        for nr in (0, 1, 2, 3):
            base = 50000 + nr * 100
            candidates.append((base, False))
            candidates.append((base + 1, True))

    for port, use_https in candidates:
        try:
            import sapmap_stop
            if sapmap_stop.is_stop_requested():
                return False
        except ImportError:
            pass
        if not _scan_port(host, port, timeout=2.0):
            continue
        r = _probe(host, port, use_https=use_https, timeout=timeout)
        if not r.get("reachable"):
            continue
        if r.get("vulnerable"):
            node.cve_2020_6287_vulnerable = True
            node.cve_2020_6287_port = port
            node.cve_2020_6287_https = use_https
            node.cve_2020_6287_evidence = r.get("evidence", "")
            emit_finding(
                "CRITICAL", node.sid,
                f"CVE-2020-6287 RECON unauth admin-user creation on port {port}",
                cve="CVE-2020-6287",
                attack_capability="exploit.cve_2020_6287",
            )
            if not any(f.name.startswith("CVE-2020-6287")
                        for f in node.findings):
                node.findings.append(Finding(
                    name="CVE-2020-6287 — RECON (LM Config Wizard unauth)",
                    severity=Severity.CRITICAL,
                    attack_techniques=_attack_for("exploit.cve_2020_6287"),
                    description=(
                        "SAP NetWeaver AS Java LM Configuration Wizard "
                        "exposes /CTCWebService/CTCWebServiceBean without "
                        "authentication.  An attacker can create an "
                        "Administrator-role UME user and gain full admin "
                        "access to the Java engine — no credentials, no "
                        "exploit chain, just a single SOAP POST."
                    ),
                    remediation=(
                        "Apply SAP Security Note 2934135 (July 2020). "
                        "Remove or restrict access to the CTCWebService "
                        "and LMConfigurationWizard endpoints."
                    ),
                    detail=f"Port {port} · {r.get('evidence', '')}",
                ))
                node.has_critical_finding = True
            return True
        else:
            node.cve_2020_6287_port = port
            node.cve_2020_6287_https = use_https
            node.cve_2020_6287_evidence = r.get("evidence", "")

    return False


def check_cve_2022_22536(node: SAPNode, timeout: float = 12.0,
                          outer_path: str = "") -> bool:
    """Probe a node for CVE-2022-22536 (ICMAD) — HTTP request smuggling.

    Combines two signals (per the locked design — see
    docs/research/10_icmad_implementation_plan.md §F.1):

      1. Patch-table lookup against SAP Note 3123396 v22's kernel boundaries.
         Fires whenever the node's kernel release + patch level are below
         the fix line.  Severity: info.
      2. Live smuggle probe (Onapsis-canonical CL=82646 payload) against
         every discovered ICM HTTP/HTTPS port.  A 2-response signature on a
         single TCP socket confirms the bug fires on the wire.  Severity:
         high (or critical if it later chains via D.2/D.3).

    The two halves are independent — patch-table can fire without a live
    signal (kernel info from RFC_SYSTEM_INFO + an unreachable ICM), and
    the live probe can fire even when we have no kernel info (operator
    runs against an unknown WD).  ``severity`` in the finding is set per
    the locked policy: info on patch-only, high on smuggle confirm.

    Per locked decision 1, this runs strictly opt-in from the context-menu
    action — no auto-fire from enrich_system_info() or any scanner pass.

    Returns True iff something was flagged (either signal).
    """
    try:
        from sap_cve_2022_22536 import assess_icmad
    except ImportError:
        logger.warning("sap_cve_2022_22536 not available — skipping")
        return False

    host = node.ip or node.hostname
    if not host:
        return False

    # Build the list of (port, https) candidates to probe.  Prefer ports
    # we already know are ICM HTTP (set by SAPControl during fingerprint
    # or by enrich_system_info()); fall back to standard 8000+NN / 5XX00
    # defaults when nothing better is known.
    candidates = []
    for inst in node.instances:
        for port, svc in (inst.ports or {}).items():
            svc_low = (svc or "").lower()
            if any(tag in svc_low for tag in ("icm", "http", "wd",
                                                "webdisp")):
                use_https = (svc_low.find("https") != -1
                              or 44300 <= port <= 44399
                              or 50000 <= port <= 59999 and port % 100 == 1)
                candidates.append((port, use_https))
    if not candidates:
        for inst in node.instances:
            try:
                nr = int(inst.instance_nr)
            except (ValueError, TypeError):
                continue
            candidates.append((8000 + nr, False))         # default ICM HTTP
            candidates.append((44300 + nr, True))         # default ICM HTTPS
            candidates.append((50000 + nr * 100, False))  # AS Java HTTP
            candidates.append((50001 + nr * 100, True))   # AS Java HTTPS
    if not candidates:
        candidates = [(8000, False), (44300, True), (50000, False)]

    node.cve_2022_22536_checked = True
    saprouter = node.saprouter or ""
    found_any = False

    for port, use_https in candidates:
        if not _scan_port(host, port, timeout=2.0):
            continue
        try:
            # When the operator didn't override outer_path, leave it
            # unset so assess_icmad / probe_icmad fall through to the
            # canonical /sap/wzip?aaa default.  Critical: do NOT pass
            # "/sap/admin/public/default.html" here — that path is
            # served LOCALLY by most WDs with connection: close, which
            # closes the socket before the smuggle re-parse can fire.
            kwargs = dict(
                https=use_https, saprouter=saprouter,
                timeout=timeout,
                kernel_release=node.kernel or "",
                kernel_patch=getattr(node, "kernel_patch", "") or "",
                is_web_dispatcher=node.is_web_dispatcher,
                verbose=True,
            )
            if outer_path:
                kwargs["outer_path"] = outer_path
            v = assess_icmad(host, port, **kwargs)
        except Exception as e:
            logger.warning("ICMAD probe error on %s:%d — %s",
                            host, port, e)
            continue

        sev = v.get("severity") or ""
        probe = v.get("probe") or {}
        patch = v.get("patch_status") or {}

        if probe.get("vulnerable"):
            node.cve_2022_22536_vulnerable = True
            node.cve_2022_22536_port = port
            node.cve_2022_22536_https = use_https
            node.cve_2022_22536_evidence = (
                probe.get("raw_head", b"")[:256].decode(
                    "iso-8859-1", errors="replace")
            )
            # Severity escalation: HIGH by default, CRITICAL when the
            # WD cache is enabled (ICMAD chain (b) is then directly
            # exploitable — smuggled responses get cached and served
            # to other clients).
            sev_label = ("CRITICAL"
                          if getattr(node, "wd_cache_enabled", False)
                          else "HIGH")
            emit_finding(sev_label, node.sid,
                          f"CVE-2022-22536 (ICMAD) smuggle confirmed on "
                          f"port {port}"
                          + (" — cache-poisoning chain reachable "
                             "(wdisp/cache_enabled=1 observed)"
                             if sev_label == "CRITICAL" else ""),
                          cve="CVE-2022-22536",
                          attack_capability="exploit.cve_2022_22536")
            if not any(f.name.startswith("CVE-2022-22536")
                          for f in node.findings):
                finding_sev = (Severity.CRITICAL
                                if getattr(node, "wd_cache_enabled", False)
                                else Severity.HIGH)
                finding_name = (
                    "CVE-2022-22536 (ICMAD) — smuggle confirmed + "
                    "WD cache enabled (cache-poisoning chain "
                    "reachable)"
                    if finding_sev == Severity.CRITICAL
                    else "CVE-2022-22536 (ICMAD) — smuggle confirmed "
                          "on the wire"
                )
                node.findings.append(Finding(
                    name=finding_name,
                    severity=finding_sev,
                    attack_techniques=_attack_for("exploit.cve_2022_22536"),
                    description=(
                        "SAP NetWeaver / Web Dispatcher ICM mis-handles "
                        "memory pipe (MPI) buffer boundaries, allowing "
                        "an unauthenticated attacker to prepend "
                        "arbitrary bytes onto a follow-up HTTP request. "
                        " The live smuggle probe observed ≥ 2 HTTP "
                        "responses on a single TCP socket — the "
                        "canonical wire-level vulnerability signature. "
                        " SAP rates this CVSS 10.0 and CISA listed it "
                        "in the Known Exploited Vulnerabilities "
                        "catalogue (due-date enforcement for U.S. "
                        "federal civilian agencies).\n\n"
                        "── On-the-wire bug vs. directly demonstrable "
                        "impact ──\n\n"
                        "Detection above proves the bug is exploitable "
                        "on the wire.  Which secondary impacts chain "
                        "from there depends on the deployment "
                        "topology.  SAP Note 3123396 lists three "
                        "documented scenarios; the realistic "
                        "engagement-day exploit chain for each is:\n\n"
                        "  (a) Front-end gateway upstream of this WD "
                        "(e.g. F5, nginx, another WD) — trust-spoof "
                        "chain: smuggle a request the WD treats as "
                        "originating from the upstream proxy, "
                        "inheriting that proxy's mTLS / SAP-trusted-"
                        "reverse-proxy attestations.  Reaches "
                        "/sap/wdisp/admin and any service gated by "
                        "icm/trusted_reverse_proxy_*.  Confirm by "
                        "running ACL Bypass Sweep and watching for "
                        "smuggled responses with admin-grade content.\n\n"
                        "  (b) WD with cache enabled "
                        "(wdisp/cache_enabled=1) — cache-poisoning "
                        "chain: smuggle a tampered response into the "
                        "WD's cache, served to subsequent legitimate "
                        "users.  Confirm by checking the WD's cache "
                        "config; if disabled, this chain doesn't apply.\n\n"
                        "  (c) WD with concurrent legitimate users — "
                        "session-hijack chain: smuggle prepends bytes "
                        "onto the NEXT user's request, hijacking their "
                        "session cookie / SAPLogonTicket.  Race-"
                        "conditional; not directly demonstrable "
                        "without volunteer traffic.\n\n"
                        "If NONE of (a)-(c) apply to this deployment "
                        "(single WD, no upstream gateway, cache off, "
                        "no concurrent users), the smuggle is still a "
                        "confirmed vulnerability — SAP itself does not "
                        "carve out exceptions to the CVSS 10.0 rating "
                        "based on topology, because future config "
                        "changes (adding an F5 in front, enabling "
                        "cache, going live with real users) "
                        "immediately unlock the chains.\n\n"
                        "Notably, the X-Forwarded-For: 127.0.0.1 "
                        "loopback-trust spoof primitive used by the "
                        "ACL Bypass Sweep (per SAPGateBreaker / "
                        "exploit-db 52109) only fires when the BACKEND "
                        "trusts loopback XFF headers — a properly "
                        "configured AS Java will reject those headers "
                        "from non-trusted-proxy sources, so a clean "
                        "'no path bypassed' from the sweep does NOT "
                        "mean the WD is safe.  It means the backend's "
                        "trust config is reasonable AND the only "
                        "missing piece is the WD's smuggle vulnerability."
                    ),
                    remediation=(
                        "Apply SAP Note 3123396: patch SAP Kernel and "
                        "SAP Web Dispatcher to the version-specific "
                        "PL listed in the note (7.22 ≥ 1101, 7.49 ≥ "
                        "1036, 7.53 ≥ 915, 7.77 ≥ 429, 7.81 ≥ 227, "
                        "7.85 ≥ 69, 7.86 ≥ 15, 7.87 ≥ 4, 8.04 ≥ 207).  "
                        "Workaround 3138881 sets "
                        "wdisp/additional_conn_close=1 but is being "
                        "deprecated per Note 3200257 and known to "
                        "break AS Java backends per Note 3147927.  "
                        "Patching is the only long-term fix."
                    ),
                    detail=(f"Port {port}{'/HTTPS' if use_https else '/HTTP'} "
                            f"· {probe.get('evidence', '')}"),
                ))
            found_any = True
            return True

        # No live signature, but patch-table flagged it as vulnerable.
        # Emit an info-severity finding so the operator sees patch hygiene.
        if (sev == "info" and patch.get("status") == "vulnerable"
                and not node.cve_2022_22536_vulnerable):
            node.cve_2022_22536_port = port
            node.cve_2022_22536_https = use_https
            node.cve_2022_22536_evidence = v.get("summary", "")
            emit_finding("INFO", node.sid,
                          v.get("summary",
                                 "CVE-2022-22536 (ICMAD) patch hygiene"),
                          cve="CVE-2022-22536",
                          attack_capability="exploit.cve_2022_22536")
            if not any(f.name.startswith("CVE-2022-22536")
                          for f in node.findings):
                node.findings.append(Finding(
                    name=("CVE-2022-22536 (ICMAD) — kernel patch hygiene"),
                    severity=Severity.INFO,
                    attack_techniques=_attack_for("exploit.cve_2022_22536"),
                    description=(
                        f"Kernel {patch.get('release', '?')}"
                        f"{' ' + patch.get('variant', '') if patch.get('variant') else ''} "
                        f"PL {patch.get('pl', '?')} is behind the fix "
                        f"boundary (≥ {patch.get('fixed_at', '?')}) for "
                        f"CVE-2022-22536 (ICMAD).  The live smuggle probe "
                        f"did not produce a 2-response signature in the "
                        f"retry budget.\n\n"
                        f"This does NOT mean the WD is patched — the "
                        f"ICMAD smuggle is race-conditional on every "
                        f"public PoC (Onapsis, SAPGateBreaker, exploit-db "
                        f"52109).  Hit rate empirically depends on the "
                        f"WD's internal backend connection-pool state: "
                        f"on a fresh backend connection (60-90s idle), "
                        f"the bug typically fires on the first attempt; "
                        f"during heavy keep-alive activity, hit rate "
                        f"drops to single digits per attempt.  Repeating "
                        f"the probe after a quiet period commonly turns "
                        f"a 'miss' into a confirmed signature.\n\n"
                        f"Other reasons for a quiet probe even on a "
                        f"vulnerable kernel:\n"
                        f"  (a) wdisp/additional_conn_close=1 is set "
                        f"(SAP Note 3138881 workaround — being deprecated "
                        f"per Note 3200257);\n"
                        f"  (b) the WD's URL filter denied the probe's "
                        f"outer path (try outer_path= a path the WD "
                        f"actually forwards to the backend; the default "
                        f"/sap/wzip is the Onapsis canonical and works "
                        f"on most NW configs).\n\n"
                        f"Patch level is unambiguously below SAP's "
                        f"declared fix line — patching to the boundary "
                        f"in 3123396 is the only durable fix."
                    ),
                    remediation=(
                        "Apply SAP Note 3123396 to bring the kernel to "
                        "the per-release fix PL (table in the note's "
                        "'Support Package Patches' section)."
                    ),
                    detail=(f"Port {port}{'/HTTPS' if use_https else '/HTTP'} "
                            f"· {probe.get('evidence', '')}"),
                ))
            found_any = True
            # Don't return — keep probing other ports in case one fires
            # the live signature, which promotes to HIGH.

        # Confirmed-WD-but-kernel-unknown branch.  When the WD has its
        # Server header suppressed (icm/HTTP/server_header_suppression=1)
        # and no kernel info reached us via RFC_SYSTEM_INFO / SAPControl,
        # the patch-table lookup returns "unknown" and the previous
        # branch above doesn't fire.  But this IS a confirmed WD — the
        # scanner ran fingerprint_web_dispatcher and labelled it.  Don't
        # let it fall through to silent "not vulnerable" just because
        # we can't extract a PL number — emit an info finding so the
        # operator sees the suspect node.
        elif (node.is_web_dispatcher
                and patch.get("status") == "unknown"
                and not probe.get("vulnerable")
                and not node.cve_2022_22536_vulnerable):
            node.cve_2022_22536_port = port
            node.cve_2022_22536_https = use_https
            node.cve_2022_22536_evidence = (
                "Confirmed Web Dispatcher; kernel/PL could not be "
                "extracted from server headers (likely suppressed via "
                "icm/HTTP/server_header_suppression=1).  Live smuggle "
                "probe inconclusive — ICMAD is race-conditional and a "
                "single negative is not proof of mitigation."
            )
            emit_finding(
                "INFO", node.sid,
                "CVE-2022-22536 (ICMAD) suspect — confirmed Web "
                "Dispatcher, kernel/PL unknown",
                cve="CVE-2022-22536",
                attack_capability="exploit.cve_2022_22536",
            )
            if not any(f.name.startswith("CVE-2022-22536")
                          for f in node.findings):
                node.findings.append(Finding(
                    name=("CVE-2022-22536 (ICMAD) — suspect "
                           "(confirmed WD, kernel unverified)"),
                    severity=Severity.INFO,
                    attack_techniques=_attack_for("exploit.cve_2022_22536"),
                    description=(
                        "This host is a confirmed SAP Web Dispatcher "
                        "(via /sap/wdisp/admin probe or Server banner), "
                        "but the kernel release + patch level couldn't "
                        "be determined automatically — the Server "
                        "header is likely suppressed via "
                        "icm/HTTP/server_header_suppression=1.\n\n"
                        "The live smuggle probe did not fire on this "
                        "attempt, but ICMAD is race-conditional and a "
                        "single negative attempt is not proof of "
                        "mitigation.  Manually verify the WD's patch "
                        "level by running `sapwebdisp -V` on the WD "
                        "host or asking the customer; cross-reference "
                        "against SAP Note 3123396 (7.22 ≥ PL1101, "
                        "7.49 ≥ PL1036, 7.53 ≥ PL915, 7.77 ≥ PL429, "
                        "7.81 ≥ PL227, 7.85 ≥ PL69, 7.86 ≥ PL15, "
                        "7.87 ≥ PL4, 8.04 ≥ PL207).\n\n"
                        "Alternatively: re-fire the ICMAD probe after "
                        "60 s of idle (the WD's backend connection "
                        "pool needs to be quiet for the smuggle to "
                        "re-parse), or try a different outer_path "
                        "that's known to forward to a backend on this "
                        "WD's wdisp/system_X config."
                    ),
                    remediation=(
                        "Apply SAP Note 3123396 if the WD's kernel "
                        "patch level is below the fix boundary."
                    ),
                    detail=(f"Port {port}{'/HTTPS' if use_https else '/HTTP'} "
                            f"· {probe.get('evidence', '')}"),
                ))
            found_any = True

    return found_any


# ---------------------------------------------------------------------------
# System info enrichment (unauthenticated)
# ---------------------------------------------------------------------------

def enrich_system_info(host: str, gw_port: int, timeout: float = 10,
                       verbose: bool = False,
                       instance_nrs: list = None,
                       sid_hint: str = "",
                       saprouter: str = "") -> dict:
    """Call RFC_SYSTEM_INFO (unauthenticated) to get OS, DB, kernel, hostname, SID.

    Args:
        instance_nrs: Explicit instance numbers to try for SAPControl (prioritized).
        sid_hint: Optional SID to use as log prefix (for already-known systems).
        saprouter: Optional SAProuter route string prefix for reaching the system.
    Returns dict with fields: sid, hostname, os, db_type, kernel, sap_release, ip, etc.
    """
    tag = sid_hint or host  # log prefix: SID if known, else IP

    info = {
        "sid": "",
        "hostname": "",
        "os_type": "",
        "db_type": "",
        "kernel": "",
        "sap_release": "",
        "ip": host,
    }

    # If the caller already discovered this host's SID on a previous
    # instance, pre-seed it here so the DIAG / MS-HTTP SID-fallback
    # cascade short-circuits (they're all gated on `not info["sid"]`).
    # sid_hint is a real SID string (e.g. "W74") — anything that looks
    # like the synthetic "UNK_..." / IP-derived name is not a real SID
    # and should NOT short-circuit the fallbacks.
    if sid_hint and _re.match(r"^[A-Z][A-Z0-9]{2}$", sid_hint):
        info["sid"] = sid_hint

    # Parse SAProuter string into (host, port) tuple for probe_sap_system
    router_tuple = None
    if saprouter:
        try:
            from sap_saprouter import parse_route_string
            hops = parse_route_string(saprouter + f"/H/{host}/S/{gw_port}")
            router_tuple = (hops[0]["host"], int(hops[0]["port"]))
            print(f"[*] {tag}: Probing RFC_SYSTEM_INFO on {host}:{gw_port} "
                  f"via SAProuter {router_tuple[0]}:{router_tuple[1]} ...")
        except Exception as e:
            print(f"[-] {tag}: Invalid SAProuter string: {e}")
    else:
        print(f"[*] {tag}: Probing RFC_SYSTEM_INFO on {host}:{gw_port} ...")

    # Through a SAProuter every failed RFC method establishes a fresh
    # NI_ROUTE tunnel, so the default 10s × 3-methods chain can easily
    # reach 30s on a locked-down system.  Cap the per-method timeout at
    # 5s over the tunnel — local RFC paths keep the full timeout.
    rfc_timeout = min(timeout, 5) if saprouter else timeout

    try:
        result = probe_sap_system(host, gw_port, timeout=rfc_timeout,
                                  verbose=verbose, router=router_tuple)
        status = result.get("status", "unknown")

        # Extract from standard RFCSI_EXPORT fields first
        if status in ("rfc_success", "info_extracted", "partial_info",
                       "ok", "partial"):
            info["sid"] = result.get("RFCSYSID", "").strip()
            info["hostname"] = (result.get("RFCHOST2", "") or
                                result.get("RFCHOST", "")).strip()
            info["os_type"] = result.get("RFCOPSYS", "").strip()
            info["db_type"] = result.get("RFCDBSYS", "").strip()
            info["kernel"] = result.get("RFCKERNRL", "").strip()
            info["sap_release"] = result.get("RFCSAPRL", "").strip()
            rfcip = (result.get("RFCIPV6ADDR", "") or
                     result.get("RFCIPADDR", "")).strip()
            if rfcip:
                info["ip"] = rfcip

        # Fallback: extract from gateway error parsing fields (chipik method).
        # These are populated when the v6/v2 full RFCSI parse fails but the
        # gateway still leaks info in error messages.
        if not info["sid"]:
            # Try to derive SID from hostname (format: hostname_SID_NN or just SID in gw name)
            gw_name = result.get("gateway_name", "")  # e.g. "sapgw00"
            hostname_full = result.get("hostname", "")  # e.g. "s4hanadev.mooo.com"
            if hostname_full and not info["hostname"]:
                info["hostname"] = hostname_full.split(".")[0]  # short hostname
        if not info["kernel"]:
            info["kernel"] = result.get("kernel_release", "").strip()
        if not info["os_type"]:
            info["os_type"] = result.get("os_hint", "").strip()
        if not info["sap_release"]:
            info["sap_release"] = result.get("sap_release_approx", "").strip()
        # Try to extract SID from hostname pattern: <host>_<SID>_<inst>
        # or from the hostname itself if it follows SAP naming conventions
        if not info["sid"] and info["hostname"]:
            hn = info["hostname"].lower()
            # Common SAP naming: the SID is often embedded, e.g. "s4hanadev" -> S4H
            # Check instance number from result
            inst_nr = result.get("instance_number", "")
            gw_svc = result.get("gw_service", "")  # e.g. "sapgw00"
            if gw_svc and gw_svc.startswith("sapgw"):
                inst_nr = inst_nr or gw_svc[5:]

        if info["sid"] or info["hostname"] or info["kernel"]:
            # Update tag with discovered SID for subsequent messages
            if info["sid"]:
                tag = info["sid"]
            print(f"[+] {tag}: RFC_SYSTEM_INFO ({status}): SID={info['sid'] or '?'}, "
                  f"Host={info['hostname'] or '?'}, OS={info['os_type'] or '?'}, "
                  f"DB={info['db_type'] or '?'}, Kernel={info['kernel'] or '?'}, "
                  f"Release={info['sap_release'] or '?'}")
        else:
            methods = result.get("methods_tried", [])
            methods_ok = result.get("methods_success", [])
            print(f"[!] {tag}: RFC_SYSTEM_INFO: no data extracted (status={status}, "
                  f"methods tried={methods}, success={methods_ok})")

    except Exception as e:
        print(f"[-] {tag}: RFC_SYSTEM_INFO error on {host}:{gw_port}: {e}")
        logger.debug(f"RFC_SYSTEM_INFO failed for {host}:{gw_port}: {e}")

    # Build ordered instance number list for SAPControl queries
    _seen = set()
    ordered_nrs = []
    for nr in (instance_nrs or []):
        n = int(nr) if isinstance(nr, str) and nr.isdigit() else nr
        if isinstance(n, int) and n not in _seen:
            _seen.add(n)
            ordered_nrs.append(n)
    if 3300 <= gw_port <= 3399:
        gw_nr = gw_port % 100
        if gw_nr not in _seen:
            _seen.add(gw_nr)
            ordered_nrs.append(gw_nr)
    if 0 not in _seen:
        ordered_nrs.append(0)

    # Query SAPControl SOAP on 5XX13 for SID, DB type, and ABAP/JAVA detection.
    # Always run this even if SID/db_type are known, because the ABAP/JAVA
    # stack detection (is_abap, is_java) only comes from SAPControl properties.
    # Accumulate HTTP/HTTPS ports discovered across instances.
    #
    # CRITICAL: only honor the ABAP/JAVA flags when the SID returned by THIS
    # SAPControl matches the SID we already established for the current
    # enrichment context.  On hosts that run multiple SIDs (e.g. SM1 at inst
    # 00-01 and SJ1 at inst 02-03 on the same box) we'd otherwise OR SM1's
    # ABAP flag into SJ1's info dict, mis-labelling SJ1 as ABAP+JAVA.
    info.setdefault("http_ports", {})   # {inst_nr: (http_port, https_port)}
    sc_to = min(timeout, 5 if saprouter else 3)
    for inst_nr in ordered_nrs:
        sc_port = 50000 + inst_nr * 100 + 13
        sid, is_java, is_abap, db_type, icm_http, icm_https = \
            _query_sapcontrol_sid(host, sc_port, timeout=sc_to,
                                   saprouter=saprouter)
        if sid and not info["sid"]:
            info["sid"] = sid
            tag = sid  # update tag with discovered SID
            print(f"[+] {tag}: SID from SAPControl ({host}:{sc_port}): {sid}")
        # Only accumulate stack flags from a SAPControl whose SID matches the
        # one this enrichment is about.  Skip silently when SIDs differ.
        sid_matches = (
            (sid and info["sid"] and sid.upper() == info["sid"].upper())
            or (sid and not info["sid"])
        )
        if (is_java or is_abap) and not sid_matches:
            print(f"[*] {info['sid'] or tag}: ignoring stack reading from "
                  f"{host}:{sc_port} — that SAPControl reports SID={sid} "
                  f"(different system on the same host)")
            # Still pick up SID-agnostic data we might use later
            if db_type and not info.get("db_type"):
                pass  # do NOT take db_type from a different SID either
        elif is_java or is_abap:
            info["_is_java"] = info.get("_is_java", False) or is_java
            info["_is_abap"] = info.get("_is_abap", False) or is_abap
            decided_by = getattr(_query_sapcontrol_sid,
                                   "_last_decided_by", "")
            print(f"[+] {tag}: Stack from SAPControl ({host}:{sc_port}):"
                  f"{'  [ABAP]' if is_abap else ''}"
                  f"{'  [JAVA]' if is_java else ''}"
                  f"  (SID match{', ' + decided_by if decided_by else ''})")
        # Same SID-scoping rule for db_type and ICM ports — these belong
        # to the SID running on this instance, not the one we're enriching.
        if db_type and not info["db_type"] and sid_matches:
            info["db_type"] = db_type
            print(f"[+] {tag}: DB type from SAPControl ({host}:{sc_port}): "
                  f"{db_type}")
        if (icm_http or icm_https) and sid_matches:
            info["http_ports"][inst_nr] = (icm_http, icm_https)
            bits = []
            if icm_http:  bits.append(f"HTTP:{icm_http}")
            if icm_https: bits.append(f"HTTPS:{icm_https}")
            print(f"[+] {tag}: ICM ports for instance {inst_nr:02d} "
                  f"from SAPControl ({host}:{sc_port}): {', '.join(bits)}")
        # For double-stack, ABAP and JAVA run on different instances.
        # Keep querying until we have SID + db_type + both stack flags checked,
        # or all instances are exhausted.
        if (info["sid"] and info["db_type"]
                and info.get("_is_java") and info.get("_is_abap")):
            break  # Found both stacks, no need to continue

    # /sap/public/info pre-auth fingerprint — fills any RFCSI fields the
    # gateway probe couldn't extract.  ABAP-only ICF service: a Java
    # stack returns 404 on this path, so we skip when SAPControl has
    # already pinned the stack to Java-only.  When SAPControl never
    # exposed an ICM port (firewalled, no SAPControl, …) fall back to
    # the standard ABAP ICM defaults (80NN and 5XX80).
    is_java_only = info.get("_is_java") and not info.get("_is_abap")
    if is_java_only:
        print(f"[*] {tag}: skipping /sap/public/info — SAPControl reports "
              f"Java-only stack (ABAP ICF path not bound)")
    else:
        # Each candidate: (inst_nr, port, source, use_https).  For every
        # SAPControl-reported HTTP port we ALSO queue an HTTPS attempt
        # on the same port — covers the common case where SAPControl
        # advertises port 80NN as "HTTP" but ICM is actually configured
        # for TLS-only on that slot.
        pi_targets = []
        for inst_nr, (http_p, https_p) in (
                info.get("http_ports") or {}).items():
            if http_p:
                pi_targets.append((inst_nr, int(http_p), "sapcontrol",       False))
                pi_targets.append((inst_nr, int(http_p), "sapcontrol-tls",   True))
            if https_p:
                pi_targets.append((inst_nr, int(https_p), "sapcontrol-https", True))
        if not pi_targets:
            for inst_nr in ordered_nrs:
                # ABAP HTTP defaults
                pi_targets.append((inst_nr, 8000 + inst_nr,         "default-80NN",  False))
                pi_targets.append((inst_nr, 50080 + inst_nr * 100,  "default-5XX80", False))
                # ABAP HTTPS defaults (443NN and 5XX01)
                pi_targets.append((inst_nr, 44300 + inst_nr,        "default-443NN", True))
                pi_targets.append((inst_nr, 50001 + inst_nr * 100,  "default-5XX01", True))
            print(f"[*] {tag}: SAPControl exposed no ICM HTTP port — "
                  f"falling back to default ICM ports "
                  f"({', '.join(f'{p}({chr(115) if h else chr(104)})' for _, p, _, h in pi_targets)}) "
                  f"for /sap/public/info")
        else:
            def _fmt_target(t):
                _, p, _src, h = t
                return f"{p}(https)" if h else f"{p}(http)"
            print(f"[*] {tag}: probing /sap/public/info on "
                  f"{len(pi_targets)} ICM port(s) from SAPControl: "
                  f"{', '.join(_fmt_target(t) for t in pi_targets)}")
        pi_to = min(timeout, 5)
        any_success = False
        for inst_nr, port, port_src, use_https in pi_targets:
            scheme = "https" if use_https else "http"
            print(f"[*] {tag}: GET {scheme}://{host}:{port}/sap/public/info "
                  f"(inst {inst_nr:02d}, source={port_src}, "
                  f"timeout={pi_to}s)"
                  f"{' via SAProuter' if saprouter else ''}")
            pi = query_public_info(host, port, timeout=pi_to,
                                    saprouter=saprouter,
                                    use_https=use_https)
            status = getattr(query_public_info, "_last_status", "?")
            if not pi:
                print(f"[-] {tag}: /sap/public/info ({scheme}://{host}:{port}): "
                      f"{status}")
                continue
            for k in ("sid", "hostname", "os_type", "db_type",
                       "kernel", "sap_release", "ip"):
                if pi.get(k) and not info.get(k):
                    info[k] = pi[k]
            if pi.get("db_host") and not info.get("db_host"):
                info["db_host"] = pi["db_host"]
            if pi.get("timezone") and not info.get("timezone"):
                info["timezone"] = pi["timezone"]
            if info["sid"]:
                tag = info["sid"]
            # /sap/public/info answering is a positive ABAP signal — Java
            # stacks don't bind this ICF path.
            info["_is_abap"] = True
            info["_public_info_source"] = f"{scheme}://{host}:{port}"
            any_success = True
            print(f"[+] {tag}: /sap/public/info ({scheme}://{host}:{port}): "
                  f"SID={pi.get('sid') or '?'}, "
                  f"Host={pi.get('hostname') or '?'}, "
                  f"OS={pi.get('os_type') or '?'}, "
                  f"DB={pi.get('db_type') or '?'}, "
                  f"Kernel={pi.get('kernel') or '?'}, "
                  f"Release={pi.get('sap_release') or '?'}"
                  + (f", DBHost={pi['db_host']}" if pi.get('db_host')
                     else "")
                  + (f", TZ={pi['timezone']}" if pi.get('timezone')
                     else ""))
            break
        if not any_success and pi_targets:
            print(f"[-] {tag}: /sap/public/info exhausted "
                  f"{len(pi_targets)} candidate port(s) — no usable "
                  f"response")

    # SID still unknown?  Fall back to the DIAG dispatcher probe on 32XX.
    # This is the only metadata channel left when the gateway (33XX) and
    # SAPControl (5XX13) are both firewalled but the dispatcher port is
    # reachable — the DIAG init response embeds "<SID>/<host>_<SID>_<NN>",
    # and the pysap-style login-screen scrape additionally extracts the
    # DBNAME item as a SID.  Both paths are router-aware.
    if not info["sid"]:
        diag_to = min(timeout, 6 if saprouter else 3)
        for inst_nr in ordered_nrs:
            disp_port = 3200 + inst_nr
            print(f"[*] {tag}: Probing DIAG dispatcher {host}:{disp_port}"
                  f"{' via SAProuter' if saprouter else ''} "
                  f"for SID (timeout={diag_to}s) ...")
            sid, disp_host, disp_inst = _query_diag_dispatcher_info(
                host, disp_port, timeout=diag_to, saprouter=saprouter)
            if sid:
                info["sid"] = sid
                tag = sid
                if disp_host and not info["hostname"]:
                    info["hostname"] = disp_host
                print(f"[+] {tag}: SID from DIAG dispatcher "
                      f"({host}:{disp_port}): SID={sid}, "
                      f"Host={disp_host or '?'}, Inst={disp_inst or '?'}")
                break
            else:
                print(f"[-] {tag}: DIAG {host}:{disp_port} yielded no SID")

    # Still no SID?  Try the MS HTTP port (81XX) as a second fallback.
    # This is the path for systems where 32XX is firewalled but 36XX /
    # 39XX (message server) is open — the MS HTTP port on the same
    # instance serves /msgserver/text/logon anonymously and its body
    # contains "<host>_<SID>_<NN>" plus a "release N (SID)" banner.
    if not info["sid"]:
        ms_to = min(timeout, 6 if saprouter else 3)
        for inst_nr in ordered_nrs:
            ms_port = 8100 + inst_nr
            print(f"[*] {tag}: Probing MS HTTP {host}:{ms_port}"
                  f"{' via SAProuter' if saprouter else ''} "
                  f"for SID (timeout={ms_to}s) ...")
            sid, ms_host, ms_inst = _query_ms_http_info(
                host, inst_nr, timeout=ms_to, saprouter=saprouter)
            if sid:
                info["sid"] = sid
                tag = sid
                if ms_host and not info["hostname"]:
                    info["hostname"] = ms_host
                print(f"[+] {tag}: SID from MS HTTP "
                      f"({host}:{ms_port}): SID={sid}, "
                      f"Host={ms_host or '?'}, Inst={ms_inst or '?'}")
                break
            else:
                print(f"[-] {tag}: MS HTTP {host}:{ms_port} yielded no SID")

    # If OS still unknown, try SAPControl GetProcessList (.EXE = Windows)
    if not info["os_type"]:
        for inst_nr in ordered_nrs:
            sc_port = 50000 + inst_nr * 100 + 13
            os_type = _query_sapcontrol_os(host, sc_port, timeout=sc_to,
                                           saprouter=saprouter)
            if os_type:
                info["os_type"] = os_type
                print(f"[+] {tag}: OS type from SAPControl ({host}:{sc_port}): "
                      f"{os_type}")
                break

    # Last resort: infer DB from product name
    if not info["db_type"]:
        try:
            product = result.get("sap_product", "")
            if "HANA" in product.upper():
                info["db_type"] = "HDB"
                print(f"[!] {tag}: DB type inferred from product name '{product}'"
                      f" (weak heuristic, may be wrong)")
        except Exception:
            pass

    # Probe HANA SQL ports on the same host (3XX13/3XX15 where XX = instance).
    # Only check a few likely instance numbers to keep it fast.
    if not info["db_type"]:
        import socket
        # Derive instance numbers to try from the gateway port and common defaults
        inst_candidates = {0, 1, 2, 3}
        if gw_port and 3300 <= gw_port <= 3399:
            inst_candidates.add(gw_port - 3300)
        for inst in sorted(inst_candidates):
            for port_offset in (13, 15):
                hana_port = 30000 + inst * 100 + port_offset
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)
                    s.connect((host, hana_port))
                    s.close()
                    info["db_type"] = "HDB"
                    print(f"[+] {tag}: HANA detected: port {hana_port} is open "
                          f"(instance {inst:02d})")
                    break
                except Exception:
                    pass
            if info["db_type"]:
                break

    return info


def _query_sapcontrol_sid(host: str, port: int, timeout: float = 3,
                          saprouter: str = "") -> tuple:
    """Quick SAPControl SOAP query to extract SID, system type, and DB type.

    Returns (sid, is_java, is_abap, db_type, http_port, https_port) tuple.
    http_port / https_port come from the 'ICM' / 'ICMS' properties which are
    URLs like 'HTTP://host:50200/...' — parsed and returned as ints, 0 when
    not present.  Java stacks always publish these; ABAP stacks publish them
    too when ICM is configured.
    """
    import re as _re
    sid = ""
    is_java = False
    is_abap = False
    db_type = ""
    http_port = 0
    https_port = 0

    # Map SAPControl "Database" values to RFCDBSYS-style codes
    _DB_MAP = {
        "sapdb": "ADA", "maxdb": "ADA", "ada": "ADA",
        "hdb": "HDB", "hana": "HDB",
        "ora": "ORA", "oracle": "ORA",
        "mss": "MSS", "mssql": "MSS",
        "db6": "DB6", "db2": "DB6",
    }

    try:
        if saprouter:
            from sap_saprouter import connect_through_saprouter
            sock = connect_through_saprouter(
                saprouter + f"/H/{host}/S/{port}",
                timeout=timeout, talk_mode=1,
            )
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
        body = (
            '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
            '<SOAP-ENV:Body><ns1:GetInstanceProperties xmlns:ns1="urn:SAPControl">'
            '</ns1:GetInstanceProperties></SOAP-ENV:Body></SOAP-ENV:Envelope>'
        )
        req = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Content-Type: text/xml\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n{body}"
        )
        sock.sendall(req.encode())
        resp = b""
        try:
            while len(resp) < 32768:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass
        sock.close()
        text = resp.decode("utf-8", errors="replace")

        # Build property dict
        props = _re.findall(r'<property>([^<]+)</property>', text)
        vals = _re.findall(r'<value>([^<]*)</value>', text)
        prop_dict = dict(zip(props, vals))

        # 1. SAPSYSTEMNAME (best source)
        if "SAPSYSTEMNAME" in prop_dict:
            sid = prop_dict["SAPSYSTEMNAME"].strip()

        # 2. DB Connection string fallback: DBName=XXX
        if not sid:
            for key in ("ABAP DB Connection", "J2EE DB Connection"):
                val = prop_dict.get(key, "")
                m = _re.search(r'DBName=(\w+)', val)
                if m:
                    sid = m.group(1).strip()
                    break

        # Extract database type from connection strings or standalone property
        # Format: "Database=SAPDB,DBHost=...,DBName=..." in ABAP/J2EE DB Connection
        for key in ("ABAP DB Connection", "J2EE DB Connection"):
            val = prop_dict.get(key, "")
            m = _re.search(r'Database=(\w+)', val)
            if m:
                raw_db = m.group(1).strip()
                db_type = _DB_MAP.get(raw_db.lower(), raw_db.upper())
                break
        # Fallback: standalone "Database" property
        if not db_type:
            raw_db = prop_dict.get("Database", "").strip()
            if raw_db:
                db_type = _DB_MAP.get(raw_db.lower(), raw_db.upper())

        # Detect ABAP vs JAVA — INSTANCE_NAME prefix is authoritative
        # because some kernels expose an empty "ABAP WP Table" key on
        # Java-only instances, which used to mis-classify clean Java
        # systems as "ABAP+JAVA" (seen on SJ1: J02 + SCS03 cluster).
        inst_name = prop_dict.get("INSTANCE_NAME", "")
        # ABAP-side instance prefixes:
        #   D / DVEBMGS = ABAP application server
        #   ASCS         = ABAP Central Services
        # Java-side instance prefixes:
        #   J / SCS / ERS = Java application server / Central Services /
        #                   Enqueue Replication Server (Java-side)
        ABAP_PREFIXES = ("DVEBMGS", "ASCS", "D")
        JAVA_PREFIXES = ("SCS", "ERS", "J")
        decided_by = ""
        if inst_name:
            # Order matters: check longer prefixes first so DVEBMGS isn't
            # caught by D, and SCS isn't caught by S-anything.
            if any(inst_name.startswith(p) for p in JAVA_PREFIXES):
                is_java = True
                decided_by = f"INSTANCE_NAME={inst_name!r} (Java prefix)"
            elif any(inst_name.startswith(p) for p in ABAP_PREFIXES):
                is_abap = True
                decided_by = f"INSTANCE_NAME={inst_name!r} (ABAP prefix)"
            else:
                # INSTANCE_NAME present but unknown prefix — fall back
                if "ABAP WP Table" in prop_dict:
                    is_abap = True
                    decided_by = (f"INSTANCE_NAME={inst_name!r} (unknown "
                                   f"prefix); 'ABAP WP Table' present")
                if any("J2EE" in p for p in prop_dict):
                    is_java = True
                    decided_by = (f"INSTANCE_NAME={inst_name!r} (unknown "
                                   f"prefix); J2EE keys present")
        else:
            # Fallback when INSTANCE_NAME is missing — older kernels and
            # half-initialised instances occasionally hide it.
            if "ABAP WP Table" in prop_dict:
                is_abap = True
                decided_by = "no INSTANCE_NAME; 'ABAP WP Table' key present"
            if any("J2EE" in p for p in prop_dict):
                is_java = True
                decided_by = "no INSTANCE_NAME; J2EE keys present"
        # Stash for callers that want to log the reasoning.  Not part of
        # the public tuple return because legacy callers don't unpack it.
        _query_sapcontrol_sid._last_decided_by = decided_by

        # Extract HTTP / HTTPS ports from the ICM and ICMS URL properties
        # (e.g. "HTTP://sapsjj:50200/sap/admin/public/index.html").
        for key, attr in (("ICM", "http_port"), ("ICMS", "https_port")):
            url = prop_dict.get(key, "")
            m = _re.search(r'://[^/:]+:(\d+)', url)
            if m:
                val = int(m.group(1))
                if attr == "http_port":
                    http_port = val
                else:
                    https_port = val

    except Exception:
        pass
    return (sid, is_java, is_abap, db_type, http_port, https_port)


def query_public_info(host: str, http_port: int,
                       timeout: float = 5,
                       saprouter: str = "",
                       use_https: bool = False) -> dict:
    """GET /sap/public/info on an ABAP ICM port — returns parsed system info.

    `/sap/public/info` is an ICF service on NetWeaver ABAP that returns
    a SOAP envelope wrapping RFCSI_EXPORT (same shape as authenticated
    RFC_SYSTEM_INFO), pre-auth on most kernels.  Java stacks do not bind
    this path (404), so a successful parse is also a positive ABAP
    signal.

    Pass ``use_https=True`` to wrap the socket in TLS (with cert
    verification disabled — SAP ICM self-signs by default).  Useful
    when SAPControl reports the HTTPS port, or when an operator has
    swapped a normally-HTTP port to TLS-only.

    Returns dict with whichever keys were populated: sid, hostname,
    os_type, db_type, kernel, sap_release, ip, db_host, timezone.
    Returns {} on any failure (port closed, non-200, non-SAP body,
    parse error).
    """
    import re as _re

    # Stash a short status code on the function object for callers that
    # want to log the failure reason.  Mirrors the
    # _query_sapcontrol_sid._last_decided_by pattern used elsewhere
    # in this module.
    query_public_info._last_status = "init"

    try:
        if saprouter:
            from sap_saprouter import connect_through_saprouter
            sock = connect_through_saprouter(
                saprouter + f"/H/{host}/S/{http_port}",
                timeout=timeout, talk_mode=1,
            )
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, http_port))
        if use_https:
            # SAP ICM almost always uses self-signed certs in non-prod
            # and even prod systems usually run an internal CA — disable
            # verification so the probe stays a low-friction info-only
            # check.  We never send credentials over this connection.
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        # Plain GET — ABAP ICF returns the SOAP envelope without auth on
        # most kernels.  Use HTTP/1.0 + Connection: close so the server
        # signals end-of-body by closing the socket (no chunked parsing).
        req = (
            f"GET /sap/public/info HTTP/1.0\r\n"
            f"Host: {host}:{http_port}\r\n"
            f"User-Agent: sapmap\r\n"
            f"Accept: text/xml,*/*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        sock.sendall(req.encode())
        resp = b""
        try:
            while len(resp) < 65536:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass
        try:
            sock.close()
        except Exception:
            pass
    except (ConnectionRefusedError, OSError) as e:
        query_public_info._last_status = f"connect_failed:{type(e).__name__}"
        return {}
    except Exception as e:
        query_public_info._last_status = f"error:{type(e).__name__}"
        return {}

    if not resp:
        query_public_info._last_status = "no_response"
        return {}

    # Split header / body
    sep = resp.find(b"\r\n\r\n")
    if sep < 0:
        query_public_info._last_status = "malformed_response"
        return {}
    head = resp[:sep].decode("iso-8859-1", errors="replace")
    body_bytes = resp[sep + 4:]

    # Only accept HTTP 200.  404 = ABAP service is hidden or this is a
    # Java stack; 401 = old kernels that gate /sap/public/* behind auth
    # (pre-Note 1486029).
    status_line = head.split("\r\n", 1)[0]
    m_status = _re.search(r"HTTP/\S+\s+(\d{3})", status_line)
    http_code = m_status.group(1) if m_status else "???"
    if " 200" not in status_line:
        query_public_info._last_status = f"http_{http_code}"
        return {}
    if b"RFCSI_EXPORT" not in body_bytes and b"RFCSYSID" not in body_bytes:
        query_public_info._last_status = "http_200_no_rfcsi"
        return {}

    body = body_bytes.decode("iso-8859-1", errors="replace")

    def _field(name: str) -> str:
        # Namespace prefixes vary across kernels ("rfc:", "n0:", default).
        # Strip any namespace prefix off the tag name when matching.
        m = _re.search(
            rf'<(?:[A-Za-z0-9_]+:)?{name}(?:\s[^>]*)?>([^<]*)'
            rf'</(?:[A-Za-z0-9_]+:)?{name}>',
            body)
        return m.group(1).strip() if m else ""

    out = {
        "sid": _field("RFCSYSID"),
        "hostname": _field("RFCHOST2") or _field("RFCHOST"),
        "os_type": _field("RFCOPSYS"),
        "db_type": _field("RFCDBSYS"),
        "kernel": _field("RFCKERNRL"),
        "sap_release": _field("RFCSAPRL"),
        "ip": _field("RFCIPV6ADDR") or _field("RFCIPADDR"),
        "db_host": _field("RFCDBHOST"),
        "timezone": _field("RFCTZONE"),
    }
    query_public_info._last_status = "ok"
    return {k: v for k, v in out.items() if v}


# ---------------------------------------------------------------------------
# Web Dispatcher fingerprint
# ---------------------------------------------------------------------------
#
# CVE-2022-22536 (ICMAD) only exploits to its full chain when an HTTP
# gateway sits in front (Web Dispatcher or 3rd-party reverse proxy).
# We surface that distinction in the node model via
# ``SAPNode.is_web_dispatcher`` so the ICMAD severity logic can promote
# "patch missing" from info → high only when there's a real gateway.
#
# Confidence ladder for the signals below, strongest → weakest:
#   * server_banner          — Server: SAP Web Dispatcher <version>
#                                literally identifies the binary.  Most
#                                reliable when present, but suppressed
#                                by `icm/HTTP/server_header_suppression=1`.
#   * wdisp_admin_realm      — /sap/wdisp/admin returns 401 with
#                                WWW-Authenticate Basic realm; the
#                                /sap/wdisp/* prefix is specifically a
#                                WD admin handler (NOT bound by app-
#                                server ICMs).  Strong hint even when
#                                Server is suppressed.
#   * icm_no_server_err      — 503 + x-sap-icm-err-id: ICMENOSERVERFOUND
#                                on a path with no SRCURL match.  Both
#                                WD and ICM emit this; weaker hint
#                                without corroboration.
#   * sap_icm_err_id_present — any x-sap-icm-err-id header value is
#                                proof we're talking to a SAP ICM/WD,
#                                without telling us which.

_WD_PATTERNS = (
    (re.compile(rb"\r\nServer:\s*SAP\s+Web\s+Dispatcher", re.I),
        "server_banner"),
    # The WD's own error pages carry this comment in the body even
    # when icm/HTTP/server_header_suppression=1 strips the Server
    # header.  Most reliable signal when the WD has been hardened.
    (re.compile(rb"This\s+error\s+page\s+was\s+generated\s+by\s+SAP\s+"
                  rb"Web\s+Dispatcher", re.I),
        "error_page_comment"),
    # Both ICMENOSERVERFOUND and ICMENOSYSTEMFOUND are WD-specific
    # error IDs:
    #   ICMENOSERVERFOUND  — no app server in the load-balancing group
    #   ICMENOSYSTEMFOUND  — no wdisp/system_X matched the URI
    # Both indicate "this is a WD that knows about routing tables",
    # which app-server ICMs don't have.
    (re.compile(rb"x-sap-icm-err-id:\s*ICMENO(?:SERVER|SYSTEM)FOUND",
                  re.I),
        "icm_no_server_err"),
    # Redirect to /sap/wdisp/admin/public/default.html is also a
    # WD-specific binding — only WDs have this admin handler.
    (re.compile(rb"\r\nLocation:\s*[^\r\n]*?/sap/wdisp/admin/public/",
                  re.I),
        "wdisp_admin_redirect"),
)

_WD_VERSION_RE = re.compile(
    rb"SAP\s+Web\s+Dispatcher[\s/]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)
_KERNEL_RELEASE_RE = re.compile(
    rb"sapwebdisp[^0-9]*([0-9]{3})\b", re.I)


def fingerprint_web_dispatcher(host: str, port: int,
                                 *, https: bool = False,
                                 timeout: float = 5,
                                 saprouter: str = "") -> dict:
    """HTTP-fingerprint a host:port pair as a Web Dispatcher.

    Returns a dict:
        {
          "is_wd": bool,        — True iff any WD-specific signal matched
          "confidence": str,    — "high" | "medium" | "low" | ""
          "evidence": str,      — short label naming the matched signal
          "server_header": str, — full Server: header if not suppressed
          "wd_version": str,    — "7.53.0" / "7.77.123" — extracted from
                                  the Server banner if present
          "status": int,        — HTTP status on the first probe
          "via": str,           — "direct" | "saprouter"
          "is_sap_icm": bool,   — True iff ANY x-sap-icm-err-id seen
                                  (confirms a SAP ICM, even when we
                                  can't tell WD vs app-server ICM apart)
        }

    Three probes, executed in order — stop early on first definitive hit:
      1. ``GET /`` — most WDs answer with a ``Server: SAP Web Dispatcher
         <version>`` banner unless the header is suppressed.
      2. ``GET /sap/wdisp/admin`` — the WD's own admin handler.  This
         path is specifically bound to WD (NOT to AS Java / AS ABAP
         ICMs), so a 401/403 (auth required) is a strong WD signal.
         403 with ICMENOSERVERFOUND means /sap/wdisp/admin isn't
         routed and we're talking to an ICM, not a WD.
      3. ``GET /sapmap-no-such-path-<random>`` — designed to miss any
         backend group; a WD answers 503 with ``x-sap-icm-err-id:
         ICMENOSERVERFOUND``, while a non-SAP service won't.

    Confidence:
      * high   — server_banner OR wdisp_admin_realm matched.
      * medium — icm_no_server_err on the bogus-path probe.
      * low    — only is_sap_icm (proves SAP ICM but not WD).
      * ""     — no SAP signals at all (probably a non-SAP HTTP svc).
    """
    out = {"is_wd": False, "confidence": "", "evidence": "",
            "server_header": "", "wd_version": "", "status": 0,
            "via": "saprouter" if saprouter else "direct",
            "is_sap_icm": False,
            # RFCSI_EXPORT fields lifted from /sap/public/info when the
            # target is an ABAP ICM.  When populated, the node-builder
            # uses the real SID instead of synthesising a Wxx
            # placeholder from the host IP's last-octet hex.  All empty
            # for pure WDs and Java stacks (those paths 404 or don't
            # answer /sap/public/info).
            "sid": "", "hostname": "", "kernel": "",
            "sap_release": "", "os_type": "", "db_type": "",
            # Two-digit SAP instance number lifted from RFCDEST — the
            # RFCSI_EXPORT destination name is conventionally
            # "<HOST>_<SID>_<NN>", so the trailing _NN is the instance.
            # Populated only when /sap/public/info answered; empty
            # otherwise.  Used by the node-builder to replace the
            # port-scanner's "WD" placeholder instance_nr with the
            # real one (e.g. port 80 → inst 00 for a W74 ICM).
            "instance_nr": ""}

    paths = [
        "/",
        # The 301 from /sap/wdisp/admin matches via _WD_PATTERNS's
        # Location: header regex.  The final /default.html catches the
        # real 401 Basic realm when the WD is fully configured.
        "/sap/wdisp/admin",
        "/sap/wdisp/admin/public/default.html",
        "/sapmap-no-such-path-fingerprint-9b3f7c",
        # ICM-specific probes — these fire even when the operator has
        # set icm/HTTP/server_header_suppression=2 AND hidden the
        # ICMENOSERVERFOUND error page.  Without them, an ABAP ICM
        # serving HTTPS-only on 443 (no dispatcher, no gateway, no
        # /sap/wdisp/admin handler) silently fails the fingerprint and
        # the operator sees a "no SAP" verdict on a real SAP system.
        #
        # /sap/public/info — unauthenticated SOAP-wrapped RFCSI_EXPORT
        # on every NetWeaver ABAP kernel; returns 200 OK with
        # <RFCSYSID>SID</RFCSYSID> in the body.  Java stacks 404.
        #
        # /sap/public/ping — minimal ICF service.  Returns 200 with a
        # body matching "Server reached successfully" on a healthy ABAP
        # ICM.  Note this path is sometimes disabled in production —
        # not authoritative on its own, only corroborates.
        #
        # /sap/bc/soap/rfc — the SOAP-RFC bridge.  Hidden behind Basic
        # auth on ABAP systems with the realm string
        # "SAP NetWeaver Application Server [SID/CLNT]" — a literal
        # SAP signature that no other product emits.
        "/sap/public/info",
        "/sap/public/ping",
        "/sap/bc/soap/rfc",
    ]

    for path in paths:
        try:
            if saprouter:
                from sap_saprouter import connect_through_saprouter
                sock = connect_through_saprouter(
                    saprouter + f"/H/{host}/S/{port}",
                    timeout=timeout, talk_mode=1,
                )
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((host, port))
            if https:
                import ssl as _ssl
                ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                try:
                    ctx.minimum_version = _ssl.TLSVersion.TLSv1
                except (AttributeError, ValueError):
                    pass
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(
                f"GET {path} HTTP/1.0\r\n"
                f"Host: {host}:{port}\r\n"
                f"User-Agent: sapmap-wd-fp\r\n"
                f"Connection: close\r\n\r\n".encode("iso-8859-1")
            )
            resp = b""
            try:
                while len(resp) < 8192:
                    chunk = sock.recv(2048)
                    if not chunk:
                        break
                    resp += chunk
            except socket.timeout:
                pass
            try:
                sock.close()
            except Exception:
                pass
        except Exception:
            continue

        if not resp:
            continue

        # Extract status + Server header (first probe wins)
        m_status = re.search(rb"HTTP/\S+\s+(\d{3})", resp)
        if m_status and not out["status"]:
            out["status"] = int(m_status.group(1))
        m_server = re.search(rb"\r\nServer:\s*([^\r\n]+)", resp)
        if m_server and not out["server_header"]:
            out["server_header"] = m_server.group(1).decode(
                "iso-8859-1", errors="replace").strip()
        # WD version from the Server banner
        m_ver = _WD_VERSION_RE.search(resp)
        if m_ver and not out["wd_version"]:
            out["wd_version"] = m_ver.group(1).decode("ascii",
                                                         errors="replace")
        # SAP ICM marker (weakest signal — tells us SAP, not WD/ICM)
        if b"x-sap-icm-err-id:" in resp.lower() or b"X-SAP-ICM-ERR-ID:" in resp:
            out["is_sap_icm"] = True
        # ICM signals that survive icm/HTTP/server_header_suppression=2:
        #
        # 1. /sap/public/info body carries <RFCSYSID> + <RFCSAPRL> +
        #    other RFCSI_EXPORT fields, wrapped in a SOAP envelope.
        #    These tag names are SAP-proprietary — no other product
        #    emits them.
        #
        # 2. WWW-Authenticate: Basic realm="SAP NetWeaver Application
        #    Server <SID>/<CLNT>"  — emitted by ABAP ICMs on any path
        #    that needs auth (/sap/bc/*).  The realm string is a
        #    literal SAP signature.
        #
        # 3. x-csrf-token header (any value) — SAP ABAP CSRF protection,
        #    emitted by /sap/bc/* on first GET.  Some hardened ICMs
        #    suppress server_header_suppression=2 AND ICMENO error pages
        #    but still need to ship CSRF tokens for the WebGUI flow.
        resp_low = resp.lower()
        if (b"<rfcsysid>" in resp_low
                or b"rfcsi_export" in resp_low
                or b"sap netweaver application server"
                    in resp_low):
            out["is_sap_icm"] = True
        # Lift RFCSI_EXPORT fields out of /sap/public/info's SOAP body.
        # Namespace prefixes vary across kernels (rfc:, n0:, default)
        # — strip any prefix off the tag name when matching, mirroring
        # the identical logic in query_public_info().  Once populated,
        # the node-builder promotes these into the SAPNode so the
        # operator sees the real SID + kernel + OS + DB on first draw,
        # avoiding the Wxx / UNK_<ip> placeholder path.
        if (path == "/sap/public/info"
                and b"<rfcsysid" in resp_low):
            def _field(name: str) -> str:
                pat = (rb"<(?:[A-Za-z0-9_]+:)?" + name.encode()
                       + rb"(?:\s[^>]*)?>([^<]*)</(?:[A-Za-z0-9_]+:)?"
                       + name.encode() + rb">")
                m = re.search(pat, resp, re.I)
                return (m.group(1).decode("iso-8859-1", "replace")
                        .strip() if m else "")
            if not out["sid"]:
                out["sid"] = _field("RFCSYSID")
            if not out["hostname"]:
                out["hostname"] = (_field("RFCHOST2")
                                    or _field("RFCHOST"))
            if not out["os_type"]:
                out["os_type"] = _field("RFCOPSYS")
            if not out["db_type"]:
                out["db_type"] = _field("RFCDBSYS")
            if not out["kernel"]:
                out["kernel"] = _field("RFCKERNRL")
            if not out["sap_release"]:
                out["sap_release"] = _field("RFCSAPRL")
            if not out["instance_nr"]:
                # RFCDEST convention: "<HOST>_<SID>_<NN>".  The
                # trailing _NN is the real two-digit instance number.
                _rd = _field("RFCDEST")
                if _rd:
                    _mi = re.search(r'_(\d{2})$', _rd)
                    if _mi:
                        out["instance_nr"] = _mi.group(1)
        if b"\r\nx-csrf-token:" in resp_low:
            out["is_sap_icm"] = True
        # /sap/public/ping body — "Server reached successfully" is the
        # standard ICM response on a 200.  Match on the canonical
        # phrase to avoid generic 200 OK pages being mis-flagged.
        if (path == "/sap/public/ping"
                and b"server reached successfully" in resp_low):
            out["is_sap_icm"] = True
        # Strong signals — definitive
        for pat, label in _WD_PATTERNS:
            if pat.search(resp):
                out["is_wd"] = True
                out["evidence"] = label
                out["confidence"] = (
                    "high" if label == "server_banner" else "medium")
                # server_banner is fully definitive; bail
                if label == "server_banner":
                    return out
        # /sap/wdisp/admin gives a 301 redirect on most WD configs
        # (matched via _WD_PATTERNS Location: regex above);
        # /sap/wdisp/admin/public/default.html is where the actual auth
        # gate sits — 401 with WWW-Authenticate: Basic realm="WEB ADMIN"
        # is the definitive signal.  If we got ICMENO(SERVER|SYSTEM)FOUND
        # on either path, it means the path is NOT bound — this server
        # isn't a WD (or the WD is hardened past identifying itself
        # via the admin handler).
        #
        # CRITICAL: a 401/403 alone is NOT enough — any generic web
        # service with global basic auth (or that returns 403 for
        # unknown paths) would otherwise be flagged as a WD.  Require
        # the auth realm to mention SAP/WEB ADMIN, OR a corroborating
        # SAP-ICM marker (x-sap-icm-err-id header / SAP server banner).
        # Operator-reported false positive: non-SAP HTTP service on
        # port 80 was promoted to W1B WEB_DISPATCHER because it
        # returned 403 for /sap/wdisp/admin and no ICM error.
        if path in ("/sap/wdisp/admin",
                     "/sap/wdisp/admin/public/default.html"):
            probe_status = int(m_status.group(1)) if m_status else 0
            has_icm_err = (b"ICMENOSERVERFOUND" in resp
                            or b"ICMENOSYSTEMFOUND" in resp)
            # WD admin uses Basic realm="WEB ADMIN" specifically.
            # Realms like realm="Restricted" / realm="protected" /
            # realm="Login" are generic web servers, not WDs.
            m_wd_realm = re.search(
                rb'WWW-Authenticate:\s*Basic\s+realm\s*=\s*"?'
                rb'(?:WEB\s+ADMIN|SAP[^"\r\n]*)',
                resp, re.I)
            sap_marker = (m_wd_realm
                          or out["is_sap_icm"]
                          or (b"SAP" in (out["server_header"] or "")
                              .encode("iso-8859-1", "replace")))
            if (probe_status in (401, 403)
                    and not has_icm_err
                    and sap_marker):
                out["is_wd"] = True
                out["evidence"] = "wdisp_admin_realm"
                out["confidence"] = "high"
                # Definitive — no more probes needed
                return out

    # Belt-and-braces final gate:
    # A confirmed WD must have emitted at least ONE unambiguous
    # SAP-ICM signal across its probes — either:
    #   (a) the `server_banner` pattern matched (literally
    #       "Server: SAP Web Dispatcher" — that returned early
    #       above so it doesn't reach this point), or
    #   (b) an `x-sap-icm-err-id` header appeared in ANY probe's
    #       response (out["is_sap_icm"] is True).
    # The bogus-path probe `/sapmap-no-such-path-...` is designed
    # to elicit `x-sap-icm-err-id: ICMENOSERVERFOUND` from any
    # real WD/ICM — so real WDs reliably satisfy this gate.
    #
    # Why the gate: softer patterns (`wdisp_admin_redirect`,
    # `error_page_comment`) can theoretically match a non-SAP
    # server that happens to return a Location header containing
    # `/sap/wdisp/admin/public/` or a body containing
    # "SAP Web Dispatcher" (e.g. a documentation proxy, a captured
    # error page, a honeypot).  Without an x-sap-icm-err-id
    # somewhere in the session, we can't be sure it's a real WD.
    # Operator-reported false positive: W1B at 10.10.1.27:80
    # plotted as WEB_DISPATCHER from a non-SAP service.
    if out["is_wd"] and out["evidence"] != "server_banner":
        if not out["is_sap_icm"]:
            # Demote — pattern matched but no SAP-ICM corroboration
            # anywhere across all four probes.  This is a non-SAP
            # service squatting on a WD-candidate port.
            out["is_wd"] = False
            out["confidence"] = ""
            out["evidence"] = ""

    if out["is_wd"]:
        return out

    # No definitive WD signal — set the SAP-ICM-only "low" confidence
    # so the operator sees we hit *something* SAP, just not specifically
    # a WD.
    if out["is_sap_icm"]:
        out["confidence"] = "low"
        out["evidence"] = "sap_icm_err_id_present"
    return out


# ---------------------------------------------------------------------------
# Web Dispatcher cache detection
# ---------------------------------------------------------------------------
#
# `wdisp/cache_enabled=1` is the parameter that turns on HTTP response
# caching in the WD.  When ON, the WD caches backend responses based on
# `sap-cache-control` directives the backend ships (e.g.
# `sap-cache-control: +86400`).  This MATTERS for ICMAD because it
# unlocks documented exploit chain (b) — cache poisoning, where a
# smuggled response gets cached and served to legitimate users.
#
# Detection (unauthenticated):
#   1. Pick a path the WD forwards to backend that we expect to be
#      cacheable (the SAP logon-page assets carry `sap-cache-control:
#      +86400` by default on virtually every NW Java backend).
#   2. Fire two identical GETs with a brief gap.
#   3. Compare responses for cache evidence:
#       * RFC-7234 `Age: N` header with N>0 on the SECOND response →
#         definitive HIT.
#       * `x-cache: HIT` / `x-cache-status` (some kernels add this).
#       * Significantly faster second response time (T2 < 30% of T1)
#         → medium confidence (could also be TCP keep-alive warmup).
#       * Same exact response body + matching `Last-Modified` header →
#         only weak — backends serving static assets always return
#         same body.
#
# Returns a dict matching the same shape as fingerprint_web_dispatcher
# so the scan-result pipeline can carry it forward consistently.

# Paths that almost always carry `sap-cache-control: +86400` on a
# default AS Java backend.  Probed in order until one returns 200.
_WD_CACHE_PROBES = (
    "/sap/public/bc/ur/Login/assets/corbu/sap_logo.png",
    "/logon_ui_resources/layout/sap_logo.png",
    "/sap/public/bc/ur/Login/assets/sap/sap_logo.gif",
)


def detect_wd_cache(host: str, port: int, *,
                      https: bool = False,
                      timeout: float = 5,
                      saprouter: str = "") -> dict:
    """Detect whether the WD has HTTP caching enabled.

    Returns:
        {
          "enabled": bool,
          "confidence": "high" | "medium" | "low" | "",
          "evidence": str,        — short label naming the matched signal
          "age_seconds": int,     — value of Age: header on hit (0 if none)
          "probe_path": str,      — which DETECT_PATH actually responded 200
          "t1_ms": int,           — first-request round-trip time
          "t2_ms": int,           — second-request round-trip time
        }
    """
    import time as _time
    out = {"enabled": False, "confidence": "", "evidence": "",
            "age_seconds": 0, "probe_path": "", "t1_ms": 0, "t2_ms": 0}

    # Find a probe path that the WD will forward AND that should be
    # cacheable.  Returns the first one that 200's.
    probe_path = ""
    for path in _WD_CACHE_PROBES:
        try:
            sock = _open_socket_for_wd(host, port, https=https,
                                          timeout=timeout,
                                          saprouter=saprouter)
        except Exception:
            continue
        try:
            sock.sendall(
                f"GET {path} HTTP/1.0\r\n"
                f"Host: {host}:{port}\r\n"
                f"Connection: close\r\n\r\n".encode("iso-8859-1")
            )
            buf = b""
            while len(buf) < 4096:
                try:
                    c = sock.recv(2048)
                except (socket.timeout, ConnectionResetError,
                         ssl.SSLEOFError):
                    break
                if not c:
                    break
                buf += c
        finally:
            try: sock.close()
            except Exception: pass
        m = re.search(rb"HTTP/\S+\s+(\d{3})", buf)
        if m and m.group(1) == b"200":
            probe_path = path
            break
    if not probe_path:
        out["evidence"] = "no_cacheable_path_found"
        return out
    out["probe_path"] = probe_path

    # Helper: one GET; returns (elapsed_ms, response_bytes).
    def _fetch():
        t0 = _time.time()
        try:
            sock = _open_socket_for_wd(host, port, https=https,
                                          timeout=timeout,
                                          saprouter=saprouter)
        except Exception:
            return 0, b""
        try:
            sock.sendall(
                f"GET {probe_path} HTTP/1.0\r\n"
                f"Host: {host}:{port}\r\n"
                f"Connection: close\r\n\r\n".encode("iso-8859-1")
            )
            buf = b""
            while len(buf) < 16384:
                try:
                    c = sock.recv(4096)
                except (socket.timeout, ConnectionResetError,
                         ssl.SSLEOFError):
                    break
                if not c:
                    break
                buf += c
        finally:
            try: sock.close()
            except Exception: pass
        return int((_time.time() - t0) * 1000), buf

    out["t1_ms"], buf1 = _fetch()
    _time.sleep(1.2)
    out["t2_ms"], buf2 = _fetch()
    if not buf2:
        return out

    # Signal 1: Age: N (N > 0) on the second response → cache HIT
    m_age = re.search(rb"\r\n[Aa]ge:\s*(\d+)", buf2)
    if m_age:
        age_val = int(m_age.group(1))
        if age_val > 0:
            out["enabled"] = True
            out["confidence"] = "high"
            out["evidence"] = f"age_header:{age_val}"
            out["age_seconds"] = age_val
            return out
    # Signal 2: x-cache: HIT (some WD versions add this)
    m_xc = re.search(rb"\r\n[Xx]-[Cc]ache:\s*([^\r\n]+)", buf2)
    if m_xc and b"HIT" in m_xc.group(1).upper():
        out["enabled"] = True
        out["confidence"] = "high"
        out["evidence"] = ("x_cache_hit:" +
                            m_xc.group(1).decode("iso-8859-1",
                                                  errors="replace").strip())
        return out
    # Signal 3: significantly faster second response — medium confidence
    if (out["t1_ms"] >= 50 and out["t2_ms"] > 0
            and out["t2_ms"] < out["t1_ms"] * 0.35):
        out["enabled"] = True
        out["confidence"] = "medium"
        out["evidence"] = (f"timing_ratio:t1={out['t1_ms']}ms,"
                            f"t2={out['t2_ms']}ms")
        return out
    # No cache signal — cache is off OR this path isn't cached
    out["evidence"] = "no_cache_signal"
    return out


def _open_socket_for_wd(host: str, port: int, *,
                          https: bool, timeout: float,
                          saprouter: str) -> socket.socket:
    """Internal helper — same socket setup as fingerprint_web_dispatcher.

    Pulled out so the cache detection + backend discovery can reuse the
    SAProuter + SSL wrapping without duplicating the boilerplate.
    """
    if saprouter:
        from sap_saprouter import connect_through_saprouter
        sock = connect_through_saprouter(
            saprouter + f"/H/{host}/S/{port}",
            timeout=timeout, talk_mode=1,
        )
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
    if https:
        import ssl as _ssl
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        try:
            ctx.minimum_version = _ssl.TLSVersion.TLSv1
        except (AttributeError, ValueError):
            pass
        sock = ctx.wrap_socket(sock, server_hostname=host)
    return sock


# ---------------------------------------------------------------------------
# WD-to-backend edge discovery
# ---------------------------------------------------------------------------
#
# Probe a curated set of SAP-canonical URL prefixes through the WD and
# observe which prefixes get forwarded (versus served locally with the
# WD's own 503).  Forwarded responses carry the backend's `Server:`
# header (e.g. "SAP NetWeaver Application Server 7.54 / AS Java 7.50")
# — we group prefixes by that signature, treating each unique signature
# as one backend.  This works WITHOUT authentication on the WD's admin
# UI: the WD exposes every backend it touches just by responding from
# it, and the `Server:` header is the discriminator.
#
# Edge cases handled:
#   * `connection: close` responses from the WD's local handlers
#     (e.g. `/sap/admin/public/default.html`) are filtered out — they
#     don't represent a real backend.
#   * `503 ICMENOSERVERFOUND` / `ICMENOSYSTEMFOUND` are filtered out —
#     the WD's URL filter rejected before any backend was touched.
#   * Stripped `Server:` headers (when the backend ALSO suppresses)
#     get bucketed under an "unidentified backend" signature so the
#     operator at least sees that the prefix forwarded somewhere.

# Curated probe paths — covers ABAP, Java, SCC, SLD, NWA, Webdynpro.
# Order matters: paths most likely to give a unique backend response
# come first.
_WD_BACKEND_PROBE_PATHS = (
    "/sap/wzip?aaa",                            # canonical 404-friendly
    "/sap/public/info",                          # ABAP RFCSI_EXPORT mirror
    "/sap/public/bc/ur/Login/assets/corbu/sap_logo.png",
    "/sap/bc/ping",                              # ABAP ping
    "/sap/bc/webdynpro/sap/itadmin",             # WebDynpro admin
    "/heapdump/",                                # AS Java heapdump
    "/heapdump",                                 # AS Java (no slash variant)
    "/nwa/",                                     # NetWeaver Admin
    "/UserAdmin/",                               # AS Java UME
    "/sld/",                                     # System Landscape Directory
    "/logon_ui_resources/",                      # Java logon assets
    "/sapmc/sapmc.html",                         # SAP Management Console
    "/CTC/ConfigServlet",                        # Java CTC
    "/EemAdminService/EemAdmin",                 # SolMan EEM
    "/scc/",                                     # SAP Cloud Connector
    "/run/jsp/index.jsp",                        # Java JSP runtime
    "/webdynpro/dispatcher/",                    # WebDynpro entry
)


def discover_wd_backends(host: str, port: int, *,
                            https: bool = False,
                            timeout: float = 5,
                            saprouter: str = "",
                            verbose: bool = True) -> dict:
    """Probe SAP-canonical URL prefixes and group responses by backend.

    Returns:
        {
          "wd_endpoint": "<host>:<port>",
          "https": bool,
          "prefix_results": {
              prefix: {
                  "status": int,
                  "server_header": str,        — "" when suppressed
                  "served_by": "wd_local" | "backend" | "wd_rejected",
                  "elapsed_ms": int,
              },
              ...
          },
          "backends": [
              {
                  "signature": str,             — Server header text
                                                  OR "<suppressed>"
                                                  (one bucket per
                                                  unique backend)
                  "url_prefixes": list[str],   — prefixes that route
                                                  to this backend
                  "server_header": str,
                  "wd_version_hint": str,      — extracted from header
                  "likely_sid": str,            — heuristic guess from
                                                  banner or prefix
                  "is_suppressed": bool,
              },
              ...
          ],
          "wd_local_prefixes": list[str],      — paths served by the WD
                                                  itself (Connection: close)
          "wd_rejected_prefixes": list[str],   — 503 ICMENO… paths
        }
    """
    if verbose:
        scheme = "https" if https else "http"
        print(f"[*] WD backends: discovering on {scheme}://{host}:{port} "
              f"(probing {len(_WD_BACKEND_PROBE_PATHS)} canonical "
              f"prefixes)")

    out = {
        "wd_endpoint": f"{host}:{port}",
        "https": https,
        "prefix_results": {},
        "backends": [],
        "wd_local_prefixes": [],
        "wd_rejected_prefixes": [],
    }

    # Per-signature bucket: signature → list of prefixes
    from collections import defaultdict, OrderedDict
    by_signature = OrderedDict()
    backend_headers = {}    # signature → first observed Server header

    for path in _WD_BACKEND_PROBE_PATHS:
        import time as _t
        t0 = _t.time()
        try:
            sock = _open_socket_for_wd(host, port, https=https,
                                          timeout=timeout,
                                          saprouter=saprouter)
        except Exception as e:
            out["prefix_results"][path] = {
                "status": 0, "server_header": "",
                "served_by": "error",
                "elapsed_ms": int((_t.time() - t0) * 1000),
                "error": type(e).__name__,
            }
            continue

        try:
            sock.sendall(
                f"GET {path} HTTP/1.0\r\n"
                f"Host: {host}:{port}\r\n"
                f"User-Agent: sapmap-wd-bk\r\n"
                f"Connection: close\r\n\r\n".encode("iso-8859-1")
            )
            buf = b""
            while len(buf) < 8192:
                try:
                    c = sock.recv(2048)
                except (socket.timeout, ConnectionResetError,
                         ssl.SSLEOFError):
                    break
                if not c:
                    break
                buf += c
        finally:
            try: sock.close()
            except Exception: pass

        elapsed = int((_t.time() - t0) * 1000)
        m_status = re.search(rb"HTTP/\S+\s+(\d{3})", buf)
        status = int(m_status.group(1)) if m_status else 0
        m_server = re.search(rb"\r\n[Ss]erver:\s*([^\r\n]+)", buf)
        server_hdr = (m_server.group(1).decode("iso-8859-1",
                                                  errors="replace").strip()
                        if m_server else "")
        # Classify the response source
        is_wd_rejected = (status == 503
                            and (b"ICMENOSERVERFOUND" in buf
                                 or b"ICMENOSYSTEMFOUND" in buf))
        is_wd_local = (
            not is_wd_rejected and
            (b"This error page was generated by SAP Web Dispatcher"
                in buf
                or b"SAP Web Dispatcher" in (server_hdr.encode()
                                                if server_hdr else b""))
        )
        # Connection: close in the response from a 200 path = WD-local
        # static handler (forces close on its own static responses).
        if (not is_wd_rejected and not is_wd_local
                and status == 200
                and re.search(rb"\r\n[Cc]onnection:\s*close",
                                buf.split(b"\r\n\r\n", 1)[0]
                                if b"\r\n\r\n" in buf else buf)
                and b"sap-cache-control" not in buf.lower()):
            # Connection: close without backend cache headers — looks
            # WD-local.  But if the Server header names a NetWeaver
            # AS, treat as backend.
            if "Application Server" not in server_hdr:
                is_wd_local = True

        if is_wd_rejected:
            served_by = "wd_rejected"
            out["wd_rejected_prefixes"].append(path)
        elif is_wd_local:
            served_by = "wd_local"
            out["wd_local_prefixes"].append(path)
        else:
            served_by = "backend"
            sig = server_hdr or "<suppressed>"
            by_signature.setdefault(sig, []).append(path)
            backend_headers[sig] = server_hdr

        out["prefix_results"][path] = {
            "status": status, "server_header": server_hdr,
            "served_by": served_by, "elapsed_ms": elapsed,
        }
        if verbose:
            verdict = {
                "wd_rejected": "REJECTED  (WD URL filter)",
                "wd_local":    "WD-LOCAL  (static handler)",
                "backend":     f"BACKEND   ({server_hdr[:60] or 'suppressed'})",
                "error":       "ERROR",
            }.get(served_by, served_by)
            print(f"[*]   {path:55s} {status:>3}  {verdict}")

    # Assemble backend records
    for sig, prefixes in by_signature.items():
        srv = backend_headers[sig]
        is_supp = sig == "<suppressed>"
        # Heuristic SID extraction from prefixes the backend serves —
        # not always present, but cheap signal.
        likely_sid = ""
        # Heuristic kernel/release extraction from "SAP NetWeaver
        # Application Server X.YZ / AS Java X.YY" banner.
        m_ver = re.search(r"AS\s+(?:Java|ABAP)\s+([0-9]+\.[0-9]+)", srv)
        wd_version_hint = m_ver.group(1).replace(".", "") if m_ver else ""
        out["backends"].append({
            "signature": sig,
            "url_prefixes": list(prefixes),
            "server_header": srv,
            "wd_version_hint": wd_version_hint,
            "likely_sid": likely_sid,
            "is_suppressed": is_supp,
        })

    if verbose:
        print(f"[+] WD backends: discovered {len(out['backends'])} "
              f"distinct backend(s), {len(out['wd_local_prefixes'])} "
              f"WD-local, {len(out['wd_rejected_prefixes'])} rejected")
        for bk in out["backends"]:
            print(f"      • {bk['server_header'] or '<suppressed>':60s} "
                  f"({len(bk['url_prefixes'])} prefix(es))")
    return out


def _query_sapstart_banner(host: str, port: int,
                              timeout: float = 3,
                              use_ssl: bool = False) -> dict:
    """Fallback SID grab via plain HTTP GET on a sapstartsrv port.

    `sapstartsrv` responds to GET / with an HTML process-list page that
    typically contains strings like:

        <title>SAP Management Console J45/00 - ...</title>
        SAPControl (SID=J45, Nr=00)

    Nmap's service-probe matcher parses exactly this to produce the
    "SAP Management Console (SID J45, NR 00)" service line.  We
    reimplement the match so we can fall back to banner-scraping when
    SOAP GetInstanceProperties is refused or returns nothing.
    """
    import re as _re
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if use_ssl:
            try:
                import ssl as _ssl
                ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            except Exception:
                sock.close()
                return None
        sock.sendall(
            f"GET / HTTP/1.0\r\nHost: {host}:{port}\r\n"
            f"User-Agent: sapmap\r\n\r\n".encode())
        resp = b""
        try:
            while len(resp) < 32768:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass
        sock.close()
        text = resp.decode("utf-8", errors="replace")

        # Patterns observed in sapstartsrv responses (across 7.0x–7.5x
        # kernels).  Try each until one hits.
        patterns = [
            # "SAPControl (SID=J45, Nr=00)"  — preferred, most specific
            r"SID\s*=\s*([A-Z][A-Z0-9]{2})[^A-Za-z0-9]+(?:Nr|NR)\s*=\s*(\d{1,2})",
            # "<title>SAP Management Console J45/00"
            r"Management Console\s+([A-Z][A-Z0-9]{2})/(\d{1,2})",
            # "SAP Management Console (SID J45, NR 00)"  (nmap-style)
            r"SID\s+([A-Z][A-Z0-9]{2})\s*,\s*NR\s+(\d{1,2})",
            # "SAPSystemName: J45\r\nSAPSystemInstance: 00"  (header)
            r"SAPSystemName:\s*([A-Z][A-Z0-9]{2}).*?SAPSystemInstance:\s*(\d{1,2})",
        ]
        for pat in patterns:
            m = _re.search(pat, text, _re.IGNORECASE | _re.DOTALL)
            if m:
                sid = m.group(1).upper()
                inst = f"{int(m.group(2)):02d}"
                return {"sid": sid, "instance_nr": inst,
                         "is_abap": False, "is_java": False,
                         "db_type": "", "os_type": "",
                         "http_port": 0, "https_port": 0,
                         "banner_source": "sapstart_http"}
        # SID-only match (NR not captured) — still better than nothing.
        m = _re.search(r"SID[=\s]+([A-Z][A-Z0-9]{2})",
                        text, _re.IGNORECASE)
        if m:
            return {"sid": m.group(1).upper(), "instance_nr": "00",
                     "is_abap": False, "is_java": False,
                     "db_type": "", "os_type": "",
                     "http_port": 0, "https_port": 0,
                     "banner_source": "sapstart_http_sid_only"}
    except Exception:
        pass
    return None


def _query_msghttp_banner(host: str, port: int,
                             timeout: float = 3) -> dict:
    """Fallback SID grab via SAP message server HTTP (81NN).

    `msghttp` answers GET /msgserver/text/logon with a plain-text list
    of logon servers, one per line in the form:

        J45_00_srv01j45 srv01j45 3201 DIAG

    First token is <SID>_<INST>_<HOST>.  Also the HTTP Server: header
    on 81NN / 8080 reads "SAP Message Server httpd release 745" —
    useful but doesn't include the SID, so we primarily rely on the
    logon list.  GET / also works on many builds and returns similar.
    """
    import re as _re
    # Try the msgserver-specific endpoint first, fall back to root.
    for path in ("/msgserver/text/logon", "/", "/msgserver/text/lgon"):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(
                f"GET {path} HTTP/1.0\r\nHost: {host}:{port}\r\n"
                f"User-Agent: sapmap\r\n\r\n".encode())
            resp = b""
            try:
                while len(resp) < 32768:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
            except socket.timeout:
                pass
            sock.close()
            text = resp.decode("utf-8", errors="replace")
            # Msgserver logon-list line: "<SID>_<NR>_<host>  <host>  <port>  DIAG"
            m = _re.search(
                r"^([A-Z][A-Z0-9]{2})_(\d{2})_\S+\s+\S+\s+\d+\s+\S+",
                text, _re.MULTILINE)
            if m:
                return {"sid": m.group(1).upper(),
                         "instance_nr": m.group(2),
                         "is_abap": False, "is_java": False,
                         "db_type": "", "os_type": "",
                         "http_port": 0, "https_port": 0,
                         "banner_source": "msghttp_logon"}
            # Header-style "SAP Message Server httpd release XXX" —
            # carries release but not SID; combine with SID fallback.
            if "SAP Message Server" in text:
                m = _re.search(r"SID[=\s]+([A-Z][A-Z0-9]{2})",
                                text, _re.IGNORECASE)
                if m:
                    return {"sid": m.group(1).upper(),
                             "instance_nr": "00",
                             "is_abap": False, "is_java": False,
                             "db_type": "", "os_type": "",
                             "http_port": 0, "https_port": 0,
                             "banner_source": "msghttp_header"}
        except Exception:
            continue
    return None


def quick_probe_sid(host: str, saprouter: str = None,
                      timeout: float = 2,
                      instance_hint: int = None,
                      total_budget: float = 10.0) -> dict:
    """Fast SAPControl probe to discover the SID of a host not yet on
    the map.  Used by the secstore/JCo extraction path when a recovered
    destination points at a host whose SID we can't derive from
    J2EE_CONFIGENTRY metadata (typical for WEBADMIN, DEST3BSNJ, and
    any destination that stores only ashost).

    Strategy (cheapest → most expensive):

    * Port 1128 — SAP Host Agent (if reachable).  GetSystemInstanceList
      returns every live SAPSYSTEMNAME on that host in one call.  But
      1128 is often firewalled from non-SAP networks, so we fall back
      to per-instance ports.

    * Ports 500NN3 (NN=00..04) — per-instance sapcontrol HTTP.  First
      one that answers with a non-empty SAPSYSTEMNAME wins.

    * Ports 500NN4 (HTTPS variants) — same via HTTPS if plain HTTP
      refused.

    Returns a dict or None.  On success:
      { sid, instance_nr, is_abap, is_java, http_port, https_port,
        db_type, os_type, source_port }
    """
    if not host:
        return None

    # Order of probe ports — host agent first (one call returns every
    # instance's SID), then per-instance pairs HTTP/HTTPS 00-04.
    tried_insts = [f"{instance_hint:02d}"] if instance_hint is not None else []
    for n in (0, 1, 2, 3, 4):
        k = f"{n:02d}"
        if k not in tried_insts:
            tried_insts.append(k)

    probe_ports = []
    # SAP Host Agent — special handling below (different SOAP method)
    probe_ports.append((1128, "host_agent_http", "XX"))
    # Per-instance sapcontrol + message-server HTTP.  For each instance
    # we try four ports in priority order:
    #   sapcontrol HTTP  (500NN3)  — SOAP + banner, richest info
    #   sapcontrol HTTPS (500NN4)  — same, over TLS
    #   msghttp           (81NN)    — msgserver logon list, has SID+NR
    for inst in tried_insts:
        n = int(inst)
        probe_ports.append((50013 + n * 100, "sapcontrol", inst))
        probe_ports.append((50014 + n * 100, "sapcontrol_https", inst))
        probe_ports.append((8100 + n,         "msghttp", inst))

    import time as _time
    deadline = _time.monotonic() + float(total_budget)

    def _remaining_timeout():
        left = deadline - _time.monotonic()
        if left <= 0:
            return 0
        return max(0.4, min(timeout, left))

    for port, kind, inst in probe_ports:
        if _time.monotonic() >= deadline:
            break
        per_port = _remaining_timeout()
        if per_port <= 0:
            break
        if kind == "host_agent_http":
            got = _query_host_agent_systems(host, port, timeout=per_port)
            if got and got.get("sid"):
                got["source_port"] = port
                got.setdefault("instance_nr", inst)
                return got
            # Fallback to banner-scrape — host agent root page also has
            # "SID SAP, Nr 99" for the host agent itself, but if the
            # real agent for another instance is on 1128 the banner
            # will carry that SID instead.
            got = _query_sapstart_banner(host, port, timeout=per_port)
            if got and got.get("sid") and got["sid"] != "SAP":
                got["source_port"] = port
                return got
            continue

        if kind == "msghttp":
            got = _query_msghttp_banner(host, port, timeout=per_port)
            if got and got.get("sid"):
                got["source_port"] = port
                return got
            continue

        # sapcontrol / sapcontrol_https — banner-scrape FIRST (one plain
        # HTTP GET, nmap-style SID regex); SOAP GetInstanceProperties
        # as enrichment fallback when the banner doesn't carry enough
        # info.  Banner is almost always faster AND works even on
        # instances that refuse unauthenticated SOAP.  When both
        # return a SID we prefer SOAP (stack type / DB / ICM URLs).
        use_ssl = (kind == "sapcontrol_https")
        banner_hit = _query_sapstart_banner(host, port, timeout=per_port,
                                                 use_ssl=use_ssl)

        # Only attempt SOAP on plain-HTTP variant — SOAP-over-HTTPS
        # is rarely exposed and doubles the connect time.
        soap_sid = ""
        soap_info = None
        if not use_ssl:
            try:
                sid_val, is_java, is_abap, db_type, http_port, https_port = (
                    _query_sapcontrol_sid(host, port, timeout=per_port))
                if sid_val:
                    soap_sid = sid_val
                    soap_info = {
                        "sid": sid_val,
                        "instance_nr": inst,
                        "is_abap": bool(is_abap),
                        "is_java": bool(is_java),
                        "db_type": db_type,
                        "http_port": http_port,
                        "https_port": https_port,
                    }
            except Exception:
                pass

        # SOAP (richer) wins when both succeed; banner wins when only
        # it succeeded; OS-type enrichment is always attempted once.
        if soap_info:
            os_type = _query_sapcontrol_os(host, port, timeout=per_port) or ""
            soap_info["os_type"] = os_type
            soap_info["source_port"] = port
            # Prefer banner's instance_nr when it's more specific (banner
            # reads from the page title, SOAP returns generic "00").
            if banner_hit and banner_hit.get("instance_nr") not in ("", "00"):
                soap_info["instance_nr"] = banner_hit["instance_nr"]
            return soap_info

        if banner_hit and banner_hit.get("sid"):
            banner_hit["source_port"] = port
            return banner_hit
    return None


def _query_host_agent_systems(host: str, port: int,
                                 timeout: float = 3) -> dict:
    """Query SAP Host Agent (1128) for the SID list via
    GetSystemInstanceList.  Returns a dict with the first system's
    SID + lowest instance number, or None.  The host agent runs as
    'saphostctrl' and returns info for every SAP system on the box
    without authentication on an unhardened install.
    """
    import re as _re
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        body = (
            '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
            '<SOAP-ENV:Body><ns1:GetSystemInstanceList xmlns:ns1="urn:SAPControl">'
            '</ns1:GetSystemInstanceList></SOAP-ENV:Body></SOAP-ENV:Envelope>'
        )
        req = (f"POST / HTTP/1.1\r\nHost: {host}:{port}\r\n"
                f"Content-Type: text/xml\r\nContent-Length: {len(body)}\r\n"
                f"\r\n{body}")
        sock.sendall(req.encode())
        resp = b""
        try:
            while len(resp) < 32768:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass
        sock.close()
        text = resp.decode("utf-8", errors="replace")
        # Each instance returns an <item> block with SAPSYSTEMNAME and
        # instanceNr; pull the first populated pair we see.
        hits = _re.findall(
            r"<item>(.*?)</item>", text, flags=_re.DOTALL)
        for item in hits:
            m_sid = _re.search(r"<hostname>[^<]*</hostname>.*?"
                                r"<instanceNr>(\d+)</instanceNr>.*?"
                                r"<httpPort>(\d*)</httpPort>.*?"
                                r"<httpsPort>(\d*)</httpsPort>",
                                item, flags=_re.DOTALL)
            # Find SAPSYSTEMNAME separately — layout varies per kernel
            sid_m = _re.search(r"<SAPSYSTEMNAME>([^<]+)</SAPSYSTEMNAME>",
                                item) or _re.search(
                r"<sapSystem[Nn]ame>([^<]+)</", item)
            if sid_m and sid_m.group(1).strip():
                sid = sid_m.group(1).strip()
                if m_sid:
                    inst = f"{int(m_sid.group(1)):02d}"
                    http_port = int(m_sid.group(2) or 0)
                    https_port = int(m_sid.group(3) or 0)
                else:
                    inst = "00"
                    http_port = 0
                    https_port = 0
                return {
                    "sid": sid, "instance_nr": inst,
                    "is_abap": False, "is_java": False,
                    "db_type": "", "os_type": "",
                    "http_port": http_port, "https_port": https_port,
                }
    except Exception:
        pass
    return None


def _query_sapcontrol_os(host: str, port: int, timeout: float = 3,
                         saprouter: str = "") -> str:
    """Detect OS type via SAPControl GetProcessList.

    Process names ending with .EXE indicate Windows; otherwise Linux/Unix.
    GetProcessList is usually available without authentication.

    Returns os_type string ("Linux", "Windows") or "" if detection fails.
    """
    import re as _re
    try:
        if saprouter:
            from sap_saprouter import connect_through_saprouter
            sock = connect_through_saprouter(
                saprouter + f"/H/{host}/S/{port}",
                timeout=timeout, talk_mode=1,
            )
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
        body = (
            '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
            '<SOAP-ENV:Body><ns1:GetProcessList xmlns:ns1="urn:SAPControl">'
            '</ns1:GetProcessList></SOAP-ENV:Body></SOAP-ENV:Envelope>'
        )
        req = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Content-Type: text/xml\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n{body}"
        )
        sock.sendall(req.encode())
        resp = b""
        try:
            while len(resp) < 32768:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass
        sock.close()
        text = resp.decode("utf-8", errors="replace")

        if "401" in text[:80]:
            return ""

        names = _re.findall(r'<name>([^<]+)</name>', text)
        if not names:
            return ""

        if any(n.upper().endswith(".EXE") for n in names):
            return "Windows"
        return "Linux"
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Client enumeration
# ---------------------------------------------------------------------------

def enumerate_system_clients(host: str, disp_port: int, timeout: float = 5,
                             max_workers: int = 20, verbose: bool = False,
                             sid_hint: str = "", saprouter: str = "",
                             terminal: str = "sapscanner") -> list:
    """Enumerate SAP clients via DIAG protocol.

    Args:
        sid_hint: Optional SID to use as log prefix (for already-known systems).
        saprouter: Optional SAProuter route string prefix.
        terminal: DIAG terminal-name string (Tier 2 T2.1 spoof support).
    Returns list of client number strings, e.g. ["000", "001", "100"].
    """
    tag = sid_hint or host
    print(f"[*] {tag}: Enumerating clients on {host}:{disp_port} via DIAG"
          f"{' (via SAProuter)' if saprouter else ''} ...")
    try:
        result = enumerate_clients(host, disp_port, timeout=timeout,
                                   max_workers=max_workers, verbose=verbose,
                                   saprouter=saprouter,
                                   sid_hint=sid_hint, terminal=terminal)
        clients = result.get("clients", [])
        status = result.get("status", "unknown")
        probed = result.get("probed", 0)
        errors = result.get("errors", 0)
        if clients:
            print(f"[+] {tag}: Found {len(clients)} clients: {', '.join(clients[:15])}"
                  f"{'...' if len(clients) > 15 else ''}"
                  f" (probed={probed}, errors={errors})")
        else:
            print(f"[*] {tag}: No clients found (status={status}, "
                  f"probed={probed}, errors={errors})")
        return clients
    except Exception as e:
        print(f"[-] {tag}: Client enumeration error on {host}:{disp_port}: {e}")
        logger.debug(f"Client enum failed for {host}:{disp_port}: {e}")
        return []


# ---------------------------------------------------------------------------
# Build SCCNode from scan result (Cloud Connector fingerprint)
# ---------------------------------------------------------------------------

def _maybe_build_scc_node(scan_result: dict, timeout: float = 5.0,
                          probe_default_creds: bool = False) -> SCCNode:
    """If 8443/tcp is open and looks like SCC, run the read-only fingerprint
    module and return a populated SCCNode.  Returns ``None`` when the host
    isn't an SCC (or 8443 is closed / fingerprint inconclusive).

    When ``probe_default_creds`` is True, additionally attempts a single
    form-auth POST per credential pair from
    ``sapmap_scc_admin.DEFAULT_CREDENTIALS`` and emits a finding either way.
    """
    host = scan_result.get("host", "")
    open_ports = scan_result.get("open_ports", {})
    if SCC_DEFAULT_PORT not in open_ports:
        return None

    try:
        from sapmap_scc_fingerprint import scc_fingerprint
    except ImportError as e:
        logger.debug("SCC fingerprint module unavailable: %s", e)
        return None

    fp = scc_fingerprint(host, port=SCC_DEFAULT_PORT, timeout=timeout)
    if not fp or not fp.get("is_scc"):
        return None

    node = SCCNode(
        host=host,
        ip=host,
        admin_ui_port=SCC_DEFAULT_PORT,
        version=fp.get("version", ""),
        version_source=fp.get("version_source", ""),
        bundle_hash=fp.get("bundle_hash", ""),
        favicon_sha256=fp.get("favicon_sha256", ""),
        favicon_mmh3=fp.get("favicon_mmh3", 0),
        tls_fingerprint=fp.get("tls", {}) or {},
        server_header=fp.get("server_header", ""),
        admin_ui_reachable=True,
    )
    print(f"[+] {host}: SAP Cloud Connector detected on :{SCC_DEFAULT_PORT}"
          f"{' v' + node.version if node.version else ''} "
          f"[server={node.server_header or '?'}]")

    ver_label = f" v{node.version}" if node.version else ""
    tls_v = (node.tls_fingerprint or {}).get("tls_version", "")
    emit_finding("INFO", host,
                 f"SAP Cloud Connector discovered on :{SCC_DEFAULT_PORT}{ver_label}"
                 f" (TLS {tls_v or '?'}, Server: {node.server_header or '?'})",
                 ref="scc.discovered",
                 meta={"port": SCC_DEFAULT_PORT,
                       "version": node.version,
                       "version_source": node.version_source,
                       "tls_version": tls_v,
                       "server": node.server_header})

    # Passive CVE buckets — version-range lookup with bundle-hash promotion.
    if node.version:
        try:
            from sapmap_scc_cve_buckets import score as _cve_score
            res = _cve_score(node.version, node.bundle_hash or "")
            node.cves_confirmed = list(res["confirmed"])
            node.cves_suspected = list(res["suspected"])
            node.cve_details = list(res["details"])
            for c in res["details"]:
                status = c.get("status", "suspected")
                tag = "CONFIRMED" if status == "confirmed" else "suspected"
                emit_finding(c["severity"], host,
                             f"SCC {node.version} [{tag}]: {c['headline']}",
                             cve=c["cve"], ref=c.get("ref", ""))
        except Exception as e:
            logger.debug("CVE bucket lookup failed for %s: %s", host, e)

    # Opt-in default-credential probe (one POST per pair, no brute force).
    if probe_default_creds:
        try:
            from sapmap_scc_admin import probe_default_creds as _probe, logout
            live, sess, attempts = _probe(host, port=SCC_DEFAULT_PORT, timeout=timeout)
            if live and sess:
                node.default_creds_live = True
                node.admin_session_obtained = True
                node.pwned = True
                if sess.version:
                    node.version = sess.version
                    node.version_source = "api"
                emit_finding("CRITICAL", host,
                             f"SCC default credentials live: {sess.user}/manage",
                             ref="scc.default.creds.live")
                logout(sess)
            else:
                tried = ", ".join(a["user"] for a in attempts) or "none"
                emit_finding("HIGH", host,
                             f"SCC default-cred probe ran (rejected): tried {tried}",
                             ref="scc.default.creds.absent.but.probed")
        except Exception as e:
            logger.debug("Default-creds probe failed for %s: %s", host, e)

    return node


# ---------------------------------------------------------------------------
# Build SAPNode from scan results
# ---------------------------------------------------------------------------

def _build_nodes_from_fast_scan(scan_result: dict, timeout: float = 10,
                                verbose: bool = False,
                                saprouter: str = "") -> list:
    """Build one or more SAPNodes from fast scan results + system info enrichment.

    Queries each discovered instance's gateway individually so that multiple SAP
    systems sharing the same IP address (different SIDs on different instance
    numbers) are detected as separate nodes rather than being collapsed into one.

    Args:
        saprouter: Optional SAProuter route prefix.  When set, all enrichment
                   (RFC_SYSTEM_INFO, client enum) is performed through the tunnel.
    """
    from collections import defaultdict

    host = scan_result["host"]
    # Filter out ports that belong exclusively to the SCC fingerprint
    # path.  When 8443 fails the WD fingerprint, it's retagged as
    # 'scc_admin' (see Pass-1 fingerprinting around line ~870) — that
    # port is then handed to _maybe_build_scc_node, which decides
    # whether to plot an SCCNode.  The SAP node builder must NOT
    # synthesise a UNK_* SAPNode purely from leftover scc_admin ports
    # — that produces false positives for non-SAP services squatting
    # on 8443 (Fortinet, custom admin UIs, etc.) when the SCC
    # fingerprint correctly rejects them.
    open_ports = {p: info for p, info in scan_result["open_ports"].items()
                  if info["service"] != "scc_admin"}
    if not open_ports:
        return []

    # Additional guard: if the only ports left after filtering are
    # SAP-Host-Agent endpoints (1128/1129), the host is not a SAP
    # system in the operational sense — it's just running the
    # management agent.  Without a SID / dispatcher / gateway /
    # SAPControl signal there is nothing to plot on the landscape
    # map; the resulting UNK_<ip> node only creates visual clutter
    # next to a co-located SCC (operator-reported: 10.10.1.4 showed
    # both an SCC node and a UNK_10_10_1_4 node carrying just
    # 1128/1129 + 8443).  The SCC fingerprint path is unaffected —
    # it reads the original scan_result, so an SCCNode still gets
    # plotted when 8443 is a real SCC.
    METADATA_ONLY_SERVICES = {"saphost_http", "saphost_https"}
    remaining_services = {info["service"] for info in open_ports.values()}
    if remaining_services and remaining_services.issubset(
            METADATA_ONLY_SERVICES):
        print(f"[*] {host}: only SAP Host Agent ports open "
              f"({sorted(remaining_services)}) — no SAP system to "
              f"plot; skipping UNK_* node synthesis")
        return []

    # Collect instance numbers
    instance_nrs = sorted(set(
        v["instance_nr"] for v in open_ports.values()
    ))

    # Phase A: Query SID for EACH instance individually
    instance_sid_map = {}   # {instance_nr: sid}
    instance_sysinfo = {}   # {instance_nr: sys_info dict}

    # Track first SID discovered on this host so later per-instance
    # enrichments can short-circuit the DIAG/MS-HTTP SID fallbacks.
    known_host_sid = ""

    for inst_nr in instance_nrs:
        # Find gateway port belonging to this instance
        gw_port = None
        for port, info in sorted(open_ports.items()):
            if info["service"] == "gateway" and info["instance_nr"] == inst_nr:
                gw_port = port
                break

        # Try gateway port for this instance
        if gw_port:
            sys_info = enrich_system_info(host, gw_port, timeout=timeout,
                                          verbose=verbose,
                                          sid_hint=known_host_sid,
                                          saprouter=saprouter)
            if sys_info.get("sid"):
                instance_sid_map[inst_nr] = sys_info["sid"]
                instance_sysinfo[inst_nr] = sys_info
                if not known_host_sid:
                    known_host_sid = sys_info["sid"]
                continue

        # No gateway open (or gateway enrichment yielded no SID) — try the
        # dispatcher+100 formula, but skip when it would land on the same
        # port we already probed (wasted ~25s of fallback timeouts over a
        # SAProuter).  Also keep the partial sys_info from the first call
        # so hostname / kernel / OS aren't lost when only the SID is missing.
        first_sys_info = sys_info if gw_port else None
        for port, info in sorted(open_ports.items()):
            if info["service"] == "dispatcher" and info["instance_nr"] == inst_nr:
                derived_gw = port + 100  # 32XX -> 33XX
                if derived_gw == gw_port:
                    print(f"[*] {host}: dispatcher+100 ({derived_gw}) == "
                          f"gateway already tried — skipping redundant retry")
                    break
                print(f"[*] {host}: No gateway for instance {inst_nr}, trying dispatcher+100 = {derived_gw}")
                sys_info = enrich_system_info(host, derived_gw, timeout=timeout,
                                              verbose=verbose,
                                              sid_hint=known_host_sid,
                                              saprouter=saprouter)
                if sys_info.get("sid"):
                    instance_sid_map[inst_nr] = sys_info["sid"]
                    instance_sysinfo[inst_nr] = sys_info
                    if not known_host_sid:
                        known_host_sid = sys_info["sid"]
                break
        # Preserve what we learned from the first enrichment so downstream
        # node-build can still show hostname/kernel/OS even without a SID.
        if (inst_nr not in instance_sysinfo) and first_sys_info and any(
                first_sys_info.get(k) for k in
                ("hostname", "kernel", "os_type", "sap_release")):
            instance_sysinfo[inst_nr] = first_sys_info

        if inst_nr in instance_sid_map:
            continue

        # Try SAPControl as last resort for this instance — pure Java stacks
        # without an open ABAP gateway end up here, and the node would otherwise
        # land on the map with empty OS/DB/kernel fields.  Capture db_type
        # (returned by _query_sapcontrol_sid) and os_type (via _query_sapcontrol_os)
        # so the downstream node-build reads them.
        if inst_nr.isdigit():
            sc_port = 50000 + int(inst_nr) * 100 + 13
            sc_sid, sc_j, sc_a, sc_db, sc_http, sc_https = \
                _query_sapcontrol_sid(host, sc_port, timeout=min(timeout, 3))
            if sc_sid:
                instance_sid_map[inst_nr] = sc_sid
                sc_os = _query_sapcontrol_os(
                    host, sc_port, timeout=min(timeout, 3)) or ""
                instance_sysinfo[inst_nr] = {
                    "sid": sc_sid,
                    "_is_java": sc_j, "_is_abap": sc_a,
                    "db_type": sc_db or "",
                    "os_type": sc_os,
                    "icm_http": sc_http,
                    "icm_https": sc_https,
                }
                bits = []
                if sc_j: bits.append("JAVA")
                if sc_a: bits.append("ABAP")
                if sc_db: bits.append(f"DB={sc_db}")
                if sc_os: bits.append(f"OS={sc_os}")
                print(f"[+] {host}: SID from SAPControl ({host}:{sc_port}): "
                      f"{sc_sid}  [{', '.join(bits) if bits else '?'}]")

    # Phase A1.5: promote SID discovered by fingerprint_web_dispatcher
    # from /sap/public/info into instance_sid_map + instance_sysinfo.
    # A host that ONLY exposes an ICM (say port 80 or 443, with the
    # dispatcher / gateway / SAPControl all firewalled) reaches this
    # point with instance_sid_map still empty for its WD-tagged
    # instance.  Without this pass, Phase A3 would synthesise a Wxx
    # placeholder even though the WD fingerprint just lifted the real
    # SID out of RFCSI_EXPORT.  Operator-reported: 192.168.2.29:80
    # (W74) was plotting as W1D because Phase A3 fired first.
    wd_info = scan_result.get("wd_info", {}) or {}
    for p, fp in wd_info.items():
        real_sid = (fp.get("sid") or "").strip()
        if not real_sid:
            continue
        port_info = open_ports.get(p)
        if not port_info:
            continue
        # When /sap/public/info returned RFCDEST with the "_NN"
        # instance suffix, replace the port-scanner's "WD" placeholder
        # instance_nr with the real one.  Also update the parent list
        # of instance_nrs so downstream phases group correctly.
        real_inst = (fp.get("instance_nr") or "").strip()
        placeholder_inst = port_info.get("instance_nr", "")
        if real_inst and placeholder_inst == "WD":
            port_info["instance_nr"] = real_inst
            if placeholder_inst in instance_nrs:
                instance_nrs.remove(placeholder_inst)
            if real_inst not in instance_nrs:
                instance_nrs.append(real_inst)
            instance_nrs.sort()
        inst_nr = port_info.get("instance_nr", "")
        if not inst_nr or inst_nr in instance_sid_map:
            continue
        instance_sid_map[inst_nr] = real_sid
        merged = {
            "sid": real_sid,
            "hostname": fp.get("hostname", ""),
            "os_type": fp.get("os_type", ""),
            "db_type": fp.get("db_type", ""),
            "kernel": fp.get("kernel", ""),
            "sap_release": fp.get("sap_release", ""),
            "_is_abap": True,
        }
        existing = instance_sysinfo.get(inst_nr) or {}
        for k, v in merged.items():
            if v and not existing.get(k):
                existing[k] = v
        instance_sysinfo[inst_nr] = existing
        if not known_host_sid:
            known_host_sid = real_sid
        print(f"[+] {host}:{p}: SID from /sap/public/info: {real_sid} "
              f"[{fp.get('sap_release') or '?'} kernel="
              f"{fp.get('kernel') or '?'} OS={fp.get('os_type') or '?'} "
              f"DB={fp.get('db_type') or '?'}]")

    # Phase A2: Split off SAProuter-only instances into their own synthetic
    # SID *before* the default-SID fallback, so port 3299 on a host that
    # also has real SAP instances doesn't get folded into the SAP SID's
    # node.  A SAProuter belongs on the map as its own box.
    #
    # SID scheme: "R" + hex of IPv4 last octet (e.g. 192.168.2.209 → "RD1",
    # 192.168.2.210 → "RD2").  Unique per-host within a /24 and stable
    # across runs (crc32 fallback for non-IPv4 inputs so hostnames also
    # map to a reproducible SID).  To pin a custom SID for scripting,
    # register the router up-front with `add_system sid: <SID> ip: <IP>
    # instance: "99"` — the scanner reuses an existing node at that IP
    # rather than synthesising a new one.
    def _router_sid_for(ip_str: str) -> str:
        try:
            last = int(ip_str.split(".")[-1]) & 0xFF
        except Exception:
            import zlib
            last = zlib.crc32(ip_str.encode("utf-8", "replace")) & 0xFF
        return f"R{last:02X}"

    router_sid = None
    for inst_nr in list(instance_nrs):
        inst_services = {
            info["service"] for port, info in open_ports.items()
            if info["instance_nr"] == inst_nr
        }
        if inst_services == {"saprouter"} and inst_nr not in instance_sid_map:
            router_sid = router_sid or _router_sid_for(host)
            instance_sid_map[inst_nr] = router_sid

    # Phase A3: WD-only / ICM-only instances.  A host that runs ONLY a
    # Web Dispatcher (no co-located ABAP/Java instance) or that only
    # exposes a hardened ICM port (e.g. ABAP/Java with the dispatcher
    # firewalled and only HTTPS 443 reachable) doesn't expose a 32XX
    # dispatcher or 5XX13 SAPControl, so the SID-discovery cascade
    # above yields nothing.  Synthesise a stable per-host SID of the
    # form "W" + last-octet-hex so the system lands on the map as its
    # own node (matching the saprouter convention) and gets
    # fingerprinted downstream — for ICM-only ports the downstream
    # /sap/public/info correction will rename the placeholder to the
    # real SID once the HTTP probe lands.
    #
    # ICM-only nuance: WD ports and standalone-HTTPS ABAP hosts belong
    # on the map as their own boxes, but a stray ICM port co-located
    # with an already-discovered SAP system (e.g. 8080 sitting on a
    # host that already has S4D on inst 02) is almost always the same
    # system's ICM under a non-canonical instance number, not a fresh
    # box.  Only synthesise a Wxx SID for an ICM-only instance when
    # NO other real SID exists on this host — otherwise let Phase B
    # fold the ICM port into the host's default_sid (the first known
    # non-router SID).  Operator-reported false positive: S4D + ICM
    # on 8080 at 192.168.2.209 produced a phantom WD1 node.
    non_router_sids_present = any(
        s != router_sid for s in instance_sid_map.values()
    )
    wd_sid = None
    wd_services_set = {"wd_http", "wd_https"}
    icm_services_set = {"icm_http", "icm_https"}
    wd_or_icm_set = wd_services_set | icm_services_set
    for inst_nr in list(instance_nrs):
        inst_services = {
            info["service"] for port, info in open_ports.items()
            if info["instance_nr"] == inst_nr
        }
        if inst_nr in instance_sid_map:
            continue
        is_pure_wd = (inst_services & wd_services_set
                       and not (inst_services - wd_or_icm_set))
        is_pure_icm = (inst_services
                        and not (inst_services & wd_services_set)
                        and inst_services.issubset(icm_services_set))
        if not (is_pure_wd or (is_pure_icm and not non_router_sids_present)):
            continue
        try:
            last = int(host.split(".")[-1]) & 0xFF
        except Exception:
            import zlib
            last = zlib.crc32(host.encode("utf-8", "replace")) & 0xFF
        wd_sid = wd_sid or f"W{last:02X}"
        instance_sid_map[inst_nr] = wd_sid

    # Phase B: Assign unresolved instances to the first known SID (or UNK).
    # Skip router_sid when picking the default — the router should never
    # become the host for orphan instances on the same IP.
    default_sid = next(
        (s for s in instance_sid_map.values() if s != router_sid),
        f"UNK_{host.replace('.', '_')}",
    )
    for inst_nr in instance_nrs:
        if inst_nr not in instance_sid_map:
            instance_sid_map[inst_nr] = default_sid

    # Phase C: Group instances by their SID
    sid_instances = defaultdict(list)
    for inst_nr in instance_nrs:
        sid_instances[instance_sid_map[inst_nr]].append(inst_nr)

    # Phase D: Build one SAPNode per discovered SID
    nodes = []
    for sid, inst_nrs_for_sid in sid_instances.items():
        # Merge enrichment data across all instances of this SID.  On dual-
        # stack or pure-Java systems the ABAP gateway (kernel/release) and
        # the Java dispatcher (SAPControl OS/DB) sit on different instances,
        # so a simple "take the first" picks one and leaves the other's
        # fields empty.  Prefer non-empty values.
        sys_info = {}
        for inr in inst_nrs_for_sid:
            s = instance_sysinfo.get(inr) or {}
            if not s.get("sid"):
                continue
            for k, v in s.items():
                if v and not sys_info.get(k):
                    sys_info[k] = v

        sc_is_java = sys_info.get("_is_java", False)
        sc_is_abap = sys_info.get("_is_abap", False)

        # Build InstanceInfo objects for only this SID's instances
        instances = []
        for inst_nr in inst_nrs_for_sid:
            inst_ports = {
                port: info["service"]
                for port, info in open_ports.items()
                if info["instance_nr"] == inst_nr
            }
            # Record HTTP/HTTPS ports we learned from the SAPControl
            # GetInstanceProperties -> ICM / ICMS URLs for this instance,
            # so downstream code (e.g. create_user_java via GW SAPXPG) can
            # find the Java dispatcher URL without relying on the
            # 50000+nn*100 convention.
            isi = instance_sysinfo.get(inst_nr) or {}
            icm_http = isi.get("icm_http", 0)
            icm_https = isi.get("icm_https", 0)
            if icm_http and icm_http not in inst_ports:
                inst_ports[icm_http] = "java_http"
            if icm_https and icm_https not in inst_ports:
                inst_ports[icm_https] = "java_https"
            instances.append(InstanceInfo(
                instance_nr=inst_nr,
                ip=host,
                ports=inst_ports,
            ))

        # Detect HANA from this SID's instance ports
        sid_port_services = [
            open_ports[p]["service"]
            for p in open_ports
            if open_ports[p]["instance_nr"] in inst_nrs_for_sid
        ]
        has_hana_port = "hana_sql" in sid_port_services
        db_type = sys_info.get("db_type", "")
        if has_hana_port and not db_type:
            db_type = "HDB"
            print(f"[+] {sid}: HANA database detected via SQL port")

        # Determine system type from this SID's ports + SAPControl hints
        has_dispatcher = "dispatcher" in sid_port_services
        has_saprouter = "saprouter" in sid_port_services
        has_saphost = any(s in ("saphost_http", "saphost_https") for s in sid_port_services)
        has_wd = any(s in ("wd_http", "wd_https") for s in sid_port_services)
        has_icm_only = (not has_dispatcher
                          and any(s in ("icm_http", "icm_https")
                                    for s in sid_port_services))
        type_parts = []
        if sc_is_abap or has_dispatcher:
            type_parts.append("ABAP")
        if sc_is_java:
            type_parts.append("JAVA")
        if type_parts:
            system_type = "+".join(type_parts)
        elif has_wd:
            system_type = "WEB_DISPATCHER"
        elif has_saprouter:
            system_type = "SAPROUTER"
        elif has_hana_port:
            system_type = "HANA"
        elif has_saphost:
            system_type = "SAP"
        else:
            system_type = "SAP"
        # SAPControl is the authority on ABAP vs JAVA when available.
        if sc_is_java and not sc_is_abap:
            system_type = "JAVA"

        # Verbose explanation of the stack decision — useful for spotting
        # cross-SID contamination on multi-SID hosts and for understanding
        # why the badge ended up the way it did.
        reasons = []
        if sc_is_abap:
            reasons.append("sc_is_abap=True (SAPControl reported ABAP for "
                            "an instance owned by this SID)")
        if sc_is_java:
            reasons.append("sc_is_java=True (SAPControl reported JAVA for "
                            "an instance owned by this SID)")
        if has_dispatcher:
            reasons.append(f"has_dispatcher=True (port 32xx open: "
                            f"{[p for p,s in open_ports.items() if s['service']=='dispatcher' and s['instance_nr'] in inst_nrs_for_sid]})")
        if has_saprouter:
            reasons.append("has_saprouter=True (port 3299 open)")
        if has_hana_port:
            reasons.append("has_hana_port=True (HANA SQL port detected)")
        if has_saphost:
            reasons.append("has_saphost=True (SAP Host Agent port 1128/1129)")
        if not reasons:
            reasons.append("no positive signal — defaulted to 'SAP'")
        print(f"[*] {sid}: stack decision -> '{system_type}' "
              f"(instances {','.join(inst_nrs_for_sid)})")
        for r in reasons:
            print(f"[*] {sid}:   reason: {r}")

        # Enumerate clients from this SID's dispatcher ports
        clients = []
        for port, info in sorted(open_ports.items()):
            if (info["service"] == "dispatcher"
                    and info["instance_nr"] in inst_nrs_for_sid):
                client_list = enumerate_system_clients(host, port, timeout=timeout,
                                                       verbose=verbose,
                                                       saprouter=saprouter)
                if client_list:
                    clients = [{"nr": c, "category": ""} for c in client_list]
                    break

        node = SAPNode(
            sid=sid,
            system_type=system_type,
            hostname=sys_info.get("hostname", ""),
            ip=host,
            instances=instances,
            os_type=sys_info.get("os_type", ""),
            db_type=db_type or sys_info.get("db_type", ""),
            kernel=sys_info.get("kernel", ""),
            sap_release=sys_info.get("sap_release", ""),
            clients=clients,
        )
        # Tag confirmed Web Dispatchers (drives ICMAD severity ladder
        # in check_cve_2022_22536 + GUI menu gating in sapmap_html).
        # Also stash the kernel/version extracted from the WD's Server
        # banner if we got it — feeds the patch-table verdict.
        wd_info_map = scan_result.get("wd_info", {}) if isinstance(
            scan_result, dict) else {}
        for inst in instances:
            for p in inst.ports:
                if p in wd_info_map and wd_info_map[p].get("is_wd"):
                    node.is_web_dispatcher = True
                    fp = wd_info_map[p]
                    if fp.get("wd_version") and not node.kernel:
                        # WD version is reported like "7.53.0" — keep
                        # only the major.minor for the kernel field.
                        try:
                            node.kernel = fp["wd_version"].split(".")[0] \
                                + fp["wd_version"].split(".")[1]
                        except (IndexError, AttributeError):
                            pass
                    # Stamp cache state + discovered backends onto the
                    # node so the GUI / report / ICMAD severity logic
                    # can use them without re-probing.
                    cache_info = fp.get("cache") or {}
                    if cache_info.get("enabled"):
                        node.wd_cache_enabled = True
                        node.wd_cache_evidence = cache_info.get(
                            "evidence", "")
                    backends_info = fp.get("backends") or {}
                    raw_backends = backends_info.get("backends", []) or []
                    if raw_backends:
                        node.wd_backends = [
                            dict(b, linked_node_sid="")
                            for b in raw_backends
                        ]
                    break
            if node.is_web_dispatcher:
                break
        # Attach saprouter prefix so all subsequent operations (exploit, RFC,
        # secstore, SXPG) automatically route through the tunnel.
        if saprouter:
            node.saprouter = saprouter

        # Tag dpmon virtual SAP* eligibility (kernel >= 790 AND ABAP
        # stack present).  SAP Note 3303172 — gates a kernel-blessed
        # path from OS-exec to a SAP* one-time password.  ABAP-only
        # feature, so pure-Java / HANA / WD / SAProuter nodes never
        # qualify even on a 790+ kernel.
        try:
            from sap_dpmon_sapstar import is_dpmon_sap_star_available
            node.dpmon_sap_star_available = is_dpmon_sap_star_available(
                node.kernel, node.system_type)
        except Exception:
            # Module not importable yet (test isolation) — leave default
            node.dpmon_sap_star_available = False

        # SNC posture probe — info only, no Finding raised.  Pick the right
        # carrier based on system_type: dispatcher (DIAG) for app servers,
        # router port for SAProuter nodes.  Failures are silently swallowed
        # so an offline SNC check never blocks a successful discovery.
        try:
            snc_port = 0
            snc_protocol = ""
            if system_type == "SAPROUTER":
                for p, pinfo in open_ports.items():
                    if pinfo["service"] == "saprouter":
                        snc_port = p
                        snc_protocol = "router"
                        break
            else:
                # Prefer this SID's own dispatcher (3200-3299)
                for p, pinfo in sorted(open_ports.items()):
                    if (pinfo["service"] == "dispatcher"
                            and pinfo["instance_nr"] in inst_nrs_for_sid):
                        snc_port = p
                        snc_protocol = "diag"
                        break

            if snc_port and snc_protocol:
                from sap_snc import (
                    scan_snc_diag, scan_snc_router, format_summary,
                )
                if snc_protocol == "diag":
                    node.snc_info = scan_snc_diag(
                        host, snc_port, timeout=min(timeout, 6),
                        saprouter=saprouter)
                else:
                    node.snc_info = scan_snc_router(
                        host, snc_port, timeout=min(timeout, 6),
                        saprouter=saprouter)
                print(f"[+] {sid}: {format_summary(node.snc_info)} "
                      f"(probed {snc_protocol}://{host}:{snc_port})")
        except Exception as e:
            # Probe is best-effort — don't let it block node creation.
            logger.debug(f"SNC probe failed for {sid} on {host}: {e}")

        nodes.append(node)

    return nodes


def match_wd_backends_to_nodes(nodes: list,
                                  promote_unmatched: bool = False) -> list:
    """Post-scan pass: link each WD's wd_backends entries to existing
    SAPNodes on the map.

    For each (WD-node, backend-entry) pair, set
    backend["linked_node_sid"] to the SID of the SAPNode that most
    likely IS this backend.  Match heuristics, in order:

      1. The same IP appears in another node's instances.ports (rare
         on truly standalone WDs but common on co-located lab setups).
      2. The Server-header signature contains a SAPNode's
         sap_release / kernel.
      3. The Server-header signature contains a SAPNode's hostname
         (rare — most banners don't leak hostnames).

    Unmatched backends — i.e. the WD revealed there's a backend it
    talks to, but the wire-level data is too thin to identify it as
    an existing on-map SAPNode — are LEFT WITH linked_node_sid=""
    by default.  Engagement-day reality: a Server-header bucket
    ("AS Java 7.50") is too generic to deserve a synthetic node on
    the map — the WD's wd_backends list (visible in the node-details
    panel) carries the same information without cluttering the SVG.
    Real-SID placeholders are created only by the admin-table
    extraction path (_enrich_wd_backends_from_admin_table) which
    has authoritative SID + MSHOST + MSPORT.

    Pass ``promote_unmatched=True`` to opt into the legacy behaviour
    where each unmatched backend gets a synthetic placeholder SAPNode
    with a B-prefix SID (e.g. ``B0B1`` for WD ``W0B``'s first
    unmatched backend).  Kept as an option for operators who want
    *some* visual signal even when the bucket is generic.

    Returns the list of newly-created placeholder SAPNodes (empty
    when promote_unmatched=False or every backend already linked).
    Caller is responsible for adding them to whatever state
    container holds the map.
    """
    if not nodes:
        return []
    new_nodes: list = []
    # Snapshot the current node set so each placeholder gets a unique
    # SID based on a counter local to the source WD.
    existing_sids = {n.sid for n in nodes}
    for wd in nodes:
        if not getattr(wd, "is_web_dispatcher", False):
            continue
        backends = getattr(wd, "wd_backends", []) or []
        # Per-WD index for synthetic-SID synthesis ("BK0B1", "BK0B2"...)
        synth_idx = 0
        # Strip the "W" prefix off the WD's SID for the placeholder
        # prefix.  e.g. WD "W0B" -> placeholder "B0B<n>"; WD "WDP"
        # (operator-typed) -> placeholder "BDP<n>".
        wd_sid = wd.sid or "WD"
        prefix_hex = wd_sid[1:3] if len(wd_sid) >= 3 else "XX"
        for bk in backends:
            sig = bk.get("server_header", "") or ""
            if not sig:
                continue
            # Strategy 1+2: look for a SAPNode whose release/kernel
            # appears in the Server string.  "SAP NetWeaver
            # Application Server 7.54 / AS Java 7.50" should match
            # any Java node with sap_release=750 OR kernel=754.
            sig_lower = sig.lower()
            matched = False
            for other in nodes:
                if other is wd:
                    continue
                hits = []
                # Look for "AS Java X.YY" / "AS ABAP X.YY" tokens
                for key in (other.sap_release, other.kernel):
                    if not key:
                        continue
                    if (key.isdigit() and len(key) in (3, 4)):
                        dotted = f"{key[0]}.{key[1:]}"
                        if dotted in sig:
                            hits.append(dotted)
                # Strategy 3: hostname substring match (when available)
                if (other.hostname
                        and other.hostname.lower() in sig_lower
                        and len(other.hostname) > 3):
                    hits.append(other.hostname)
                if hits:
                    bk["linked_node_sid"] = other.sid
                    matched = True
                    break
            if matched or not promote_unmatched:
                continue
            # Synthesise a placeholder node for this backend.  The
            # SID has a leading "B" so it can't collide with the
            # router (R-prefix), WD (W-prefix), or real-system SIDs.
            synth_idx += 1
            candidate_sid = f"B{prefix_hex}{synth_idx}"
            # Bump if collision (rare, but guard anyway)
            while candidate_sid in existing_sids:
                synth_idx += 1
                candidate_sid = f"B{prefix_hex}{synth_idx}"
            existing_sids.add(candidate_sid)
            # Pull stack hint from the Server header
            stype = "SAP"
            if "AS Java" in sig:
                stype = "JAVA"
            elif "AS ABAP" in sig:
                stype = "ABAP"
            # Kernel: prefer the wd_version_hint already extracted
            kernel = bk.get("wd_version_hint", "") or ""
            placeholder = SAPNode(
                sid=candidate_sid,
                system_type=stype,
                hostname="",        # unknown — only the WD knows
                ip="",              # unknown
                instances=[],       # nothing scanned directly
                kernel=kernel,
            )
            placeholder.discovered_via_wd_sid = wd_sid
            bk["linked_node_sid"] = candidate_sid
            new_nodes.append(placeholder)
    return new_nodes


def discover_systems(targets: list, instance_range: tuple = DEFAULT_INSTANCE_RANGE,
                     timeout: float = DEFAULT_TIMEOUT, threads: int = DEFAULT_THREADS,
                     fast_mode: bool = True, cancel_event: threading.Event = None,
                     progress_callback=None, verbose: bool = False,
                     skip_alive: bool = False, concurrent_hosts: int = 5,
                     port_timeout: float = 3.0,
                     node_callback=None,
                     scc_callback=None,
                     scc_probe_default_creds: bool = False) -> list:
    """Main entry point: discover SAP systems on the network.

    Args:
        targets: list of IP addresses (from parse_targets)
        instance_range: (start, end) instance numbers
        timeout: socket timeout
        threads: scan threads
        fast_mode: if True, only scan 32XX/33XX ports
        cancel_event: cancellation signal
        progress_callback: callable for progress updates
        verbose: print detailed output
        skip_alive: skip the alive sweep (scan all targets)
        concurrent_hosts: max hosts to port-scan in parallel
        port_timeout: TCP timeout for port probes
        node_callback: callable(SAPNode) invoked as each system is discovered
        scc_callback:  callable(SCCNode) invoked as each Cloud Connector is fingerprinted

    Returns:
        list of SAPNode objects
    """
    nodes = []
    # SCC nodes are routed straight to the caller via scc_callback; we
    # also keep a local list so the discovery summary at the end can
    # report SAP + SCC counts together (the GUI's caller doesn't share
    # back its accumulated state from inside this function).
    scc_nodes_local = []
    total_start = time.time()

    print(f"[*] ========================================")
    print(f"[*]  SAPMAP Discovery — {'Fast' if fast_mode else 'Deep'} Scan")
    print(f"[*]  {len(targets)} target(s), "
          f"instances {instance_range[0]:02d}-{instance_range[1]:02d}")
    print(f"[*] ========================================")

    if fast_mode:
        # Phase 1: Fast port scan
        scan_results = fast_scan_network(
            targets, instance_range, timeout, threads,
            cancel_event, progress_callback,
            skip_alive=skip_alive,
            concurrent_hosts=concurrent_hosts,
            port_timeout=port_timeout,
        )

        if not scan_results:
            print(f"[*] No SAP systems found during port scan")
            return nodes

        # Phase 2: Enrich each found host with system info + client enum
        print(f"")
        print(f"[*] === PHASE 2: System Enrichment ===")
        print(f"[*] Enriching {len(scan_results)} discovered SAP host(s) "
              f"with RFC_SYSTEM_INFO + client enumeration ...")
        print(f"")

        for idx, result in enumerate(scan_results):
            if cancel_event and cancel_event.is_set():
                print("[!] Scan cancelled by user")
                break
            host = result["host"]
            port_count = len(result["open_ports"])
            print(f"[*] {host}: --- Host {idx + 1}/{len(scan_results)}: "
                  f"{host} ({port_count} open ports) ---")

            host_nodes = _build_nodes_from_fast_scan(result, timeout=timeout, verbose=verbose)
            nodes.extend(host_nodes)

            # Notify caller immediately so nodes appear on the map progressively
            if node_callback:
                for node in host_nodes:
                    node_callback(node)

            # SCC fingerprint — independent of SAP node enrichment so a host
            # that is *only* a Cloud Connector still surfaces on the map.
            scc_node = _maybe_build_scc_node(
                result, timeout=min(timeout, 5.0),
                probe_default_creds=scc_probe_default_creds,
            )
            if scc_node:
                scc_nodes_local.append(scc_node)
                if scc_callback:
                    try:
                        scc_callback(scc_node)
                    except Exception as e:
                        logger.debug("scc_callback failed for %s: %s", host, e)

            # Summary line per discovered system on this host
            for node in host_nodes:
                client_count = len(node.clients)
                inst_list = ", ".join(node.instance_nrs()) or "?"
                print(f"[+] {node.sid}: => {node.system_type} | "
                      f"Host: {node.hostname or '?'} | "
                      f"OS: {node.os_type or '?'} | "
                      f"DB: {node.db_type or '?'} | "
                      f"Kernel: {node.kernel or '?'} | "
                      f"Instances: [{inst_list}] | "
                      f"Clients: {client_count}")
            print(f"")
    else:
        # Deep scan: use SAPology if available
        try:
            import SAPology
            _deep_scan_with_sapology(targets, instance_range, timeout, threads,
                                     cancel_event, progress_callback, nodes)
        except ImportError:
            logger.warning("SAPology not available, falling back to fast scan + enrichment")
            print("[!] SAPology not importable, falling back to fast scan with enrichment")
            return discover_systems(targets, instance_range, timeout, threads,
                                    fast_mode=True, cancel_event=cancel_event,
                                    progress_callback=progress_callback, verbose=verbose,
                                    node_callback=node_callback)

    # Mark systems with critical findings
    for node in nodes:
        if node.findings:
            max_sev = max(f.severity for f in node.findings)
            if max_sev >= Severity.CRITICAL:
                node.has_critical_finding = True

    elapsed = time.time() - total_start
    print(f"[*] ========================================")
    print(f"[+]  Discovery complete in {elapsed:.1f}s")
    total_found = len(nodes) + len(scc_nodes_local)
    print(f"[+]  Systems found: {total_found} "
          f"(SAP: {len(nodes)}, SCC: {len(scc_nodes_local)})")
    for node in nodes:
        flag = ""
        if node.has_critical_finding:
            flag = " [CRITICAL]"
        if node.gw_vulnerable:
            flag += " [GW VULN]"
        print(f"[+]    {node.sid:8s} {node.system_type:12s} "
              f"{node.ip:15s} {node.hostname:20s} "
              f"K:{node.kernel:4s} DB:{node.db_type:4s} "
              f"Clients:{len(node.clients)}{flag}")
    for scc in scc_nodes_local:
        host = getattr(scc, "host", "") or getattr(scc, "ip", "")
        version = getattr(scc, "version", "") or "?"
        print(f"[+]    {'SCC':8s} {'CLOUD_CONN':12s} "
              f"{host:15s} {'':20s} "
              f"V:{version:4s}")
    print(f"[*] ========================================")

    # Cross-link WD-to-backend edges across the discovered nodes.
    # NOTE: promote_unmatched=False — Server-header buckets are too
    # generic to deserve synthetic placeholder nodes on the map.
    # Real-SID placeholders come from the admin-table extraction
    # path (operator-triggered via "Add WD admin credentials").
    placeholders = match_wd_backends_to_nodes(nodes,
                                                 promote_unmatched=False)
    if placeholders:
        print(f"[+] Promoted {len(placeholders)} WD-discovered backend(s) "
              f"to placeholder node(s):")
        for p in placeholders:
            print(f"      • {p.sid} ({p.system_type}, kernel={p.kernel or '?'})"
                  f"  -- discovered via {p.discovered_via_wd_sid}")
        nodes.extend(placeholders)

    return nodes


def _sapology_system_to_node(sys_obj, target_ip: str) -> SAPNode:
    """Convert a SAPology SAPSystem object to a SAPMAP SAPNode."""

    instances = []
    for inst in sys_obj.instances:
        instances.append(InstanceInfo(
            instance_nr=inst.instance_nr,
            ip=inst.ip or target_ip,
            ports=dict(inst.ports),
            services=dict(inst.services),
            info=dict(inst.info),
        ))

    # Convert SAPology findings to SAPMAP findings
    findings = []
    sev_map = {0: Severity.CRITICAL, 1: Severity.HIGH, 2: Severity.MEDIUM,
               3: Severity.LOW, 4: Severity.INFO}
    gw_vulnerable = False
    for inst in sys_obj.instances:
        for f in inst.findings:
            sev = sev_map.get(int(f.severity), Severity.INFO)
            findings.append(Finding(
                name=f.name,
                severity=sev,
                description=getattr(f, 'description', ''),
                remediation=getattr(f, 'remediation', ''),
                detail=getattr(f, 'detail', ''),
            ))
            if "SAPXPG" in f.name:
                gw_vulnerable = True
                emit_finding(
                    "HIGH", sys_obj.sid or "?",
                    "Gateway accepts SAPXPG register_ep — "
                    "unauthenticated OS command execution possible",
                    cve="SAP Note 1408081 (Gateway ACL)",
                )

    # Determine DB type — SAPology sets db_type and has_hana/has_maxdb/etc.
    # Normalize variants like "ADABAS D" -> "ADA"
    from sapmap_config import normalize_db_type as _norm_db
    db_type = _norm_db(sys_obj.db_type) if sys_obj.db_type else ""
    if not db_type:
        # Infer from has_* flags
        if getattr(sys_obj, 'has_hana', False):
            db_type = "HDB"
        elif getattr(sys_obj, 'has_maxdb', False):
            db_type = "ADA"
        elif getattr(sys_obj, 'has_mssql', False):
            db_type = "MSS"
        elif getattr(sys_obj, 'has_oracle', False):
            db_type = "ORA"
        elif getattr(sys_obj, 'has_db2', False):
            db_type = "DB6"

    # Clients
    clients = [{"nr": c, "category": ""} for c in (sys_obj.clients or [])]

    node = SAPNode(
        sid=sys_obj.sid if sys_obj.sid != "UNKNOWN" else f"UNK_{target_ip.replace('.', '_')}",
        system_type=sys_obj.system_type or "SAP",
        hostname=sys_obj.hostname or "",
        ip=target_ip,
        instances=instances,
        os_type=sys_obj.os_type or "",
        db_type=db_type,
        kernel=sys_obj.kernel or "",
        sap_release=getattr(sys_obj, 'sap_release', '') or "",
        clients=clients,
        findings=findings,
        has_critical_finding=any(f.severity >= Severity.CRITICAL for f in findings),
        gw_vulnerable=gw_vulnerable,
    )
    # Tag dpmon SAP* eligibility — same logic as the fast-scan path.
    try:
        from sap_dpmon_sapstar import is_dpmon_sap_star_available
        node.dpmon_sap_star_available = is_dpmon_sap_star_available(
            node.kernel, node.system_type)
    except Exception:
        node.dpmon_sap_star_available = False
    return node


def _deep_scan_with_sapology(targets, instance_range, timeout, threads,
                              cancel_event, progress_callback, nodes):
    """Run full SAPology discover_systems + assess_vulnerabilities.

    Uses SAPology's own functions which handle all detection properly:
    OS type, DB type, system type (ABAP/JAVA/ABAP+JAVA), database port
    fingerprinting (HANA, MaxDB, MSSQL, Oracle, DB2), SAPControl queries,
    /sap/public/info probing, RFC_SYSTEM_INFO, client enumeration, and
    all vulnerability checks including gateway SAPXPG.
    """
    import SAPology

    instances = list(range(instance_range[0], instance_range[1] + 1))
    total_start = time.time()

    print(f"")
    print(f"[*] ============================================================")
    print(f"[*]  SAPology Deep Scan — Phase 1: Discovery & Fingerprinting")
    print(f"[*] ============================================================")
    print(f"[*] Targets:    {len(targets)} host(s)")
    print(f"[*] Instances:  {instance_range[0]:02d}-{instance_range[1]:02d} "
          f"({len(instances)} instance numbers)")
    print(f"[*] Timeout:    {timeout}s, Threads: {threads}")
    print(f"[*]")
    print(f"[*] This phase will:")
    print(f"[*]   1. Check host reachability (alive detection)")
    print(f"[*]   2. Port scan: dispatcher (32XX), gateway (33XX), SAPControl (5XX13),")
    print(f"[*]      ICM HTTP (8XXX), HANA SQL (3XX13/15), MaxDB (7210),")
    print(f"[*]      MSSQL (1433), Oracle (1521), and more")
    print(f"[*]   3. Fingerprint each service (SAPControl SOAP, DIAG, RFC_SYSTEM_INFO)")
    print(f"[*]   4. Detect OS, database type, kernel, SAP release")
    print(f"[*]   5. Enumerate SAP clients via DIAG protocol")
    print(f"[*]   6. Detect system type (ABAP, JAVA, ABAP+JAVA, BO, ...)")
    print(f"[*]")
    print(f"[*] Starting SAPology discover_systems() ...")
    print(f"")

    try:
        # Phase 1: SAPology discover_systems — full port scan, fingerprinting,
        # SAPControl queries, RFC_SYSTEM_INFO, client enumeration, OS/DB detection

        # Heartbeat thread so the user sees progress during long SAPology calls
        def _heartbeat(label, stop_evt):
            n = 0
            while not stop_evt.wait(10):
                n += 10
                if cancel_event and cancel_event.is_set():
                    break
                print(f"[*] ... {label} still running ({n}s elapsed)")
        heartbeat_stop = threading.Event()
        hb = threading.Thread(target=_heartbeat, args=("Phase 1", heartbeat_stop),
                              daemon=True)
        hb.start()

        landscape = SAPology.discover_systems(
            targets, instances, timeout=timeout, threads=threads,
            verbose=True,
            cancel_check=lambda: cancel_event.is_set() if cancel_event else False,
            client_enum=True,
        )
        heartbeat_stop.set()

        if cancel_event and cancel_event.is_set():
            return

        phase1_elapsed = time.time() - total_start

        if not landscape:
            print(f"")
            print(f"[*] No SAP systems discovered after {phase1_elapsed:.1f}s")
            return

        print(f"")
        print(f"[+] ============================================================")
        print(f"[+]  Phase 1 complete in {phase1_elapsed:.1f}s — "
              f"{len(landscape)} SAP system(s) found")
        print(f"[+] ============================================================")
        for sys_obj in landscape:
            inst_nrs = sorted(set(i.instance_nr for i in sys_obj.instances
                                  if i.instance_nr != "XX"))
            port_count = sum(len(i.ports) for i in sys_obj.instances)
            db_flags = []
            for label, attr in [("HANA", "has_hana"), ("MaxDB", "has_maxdb"),
                                ("MSSQL", "has_mssql"), ("Oracle", "has_oracle"),
                                ("DB2", "has_db2")]:
                if getattr(sys_obj, attr, False):
                    db_flags.append(label)
            print(f"[+]   {sys_obj.sid:8s} | {sys_obj.system_type or '?':12s} | "
                  f"Host: {sys_obj.hostname or '?':15s} | "
                  f"OS: {sys_obj.os_type or '?':12s} | "
                  f"DB: {sys_obj.db_type or '?':4s}"
                  f"{' (' + '/'.join(db_flags) + ')' if db_flags else '':8s} | "
                  f"Kernel: {sys_obj.kernel or '?':4s} | "
                  f"Inst: [{','.join(inst_nrs)}] | "
                  f"Ports: {port_count} | "
                  f"Clients: {len(sys_obj.clients)}")

        print(f"")
        print(f"[*] ============================================================")
        print(f"[*]  SAPology Deep Scan — Phase 2: Vulnerability Assessment")
        print(f"[*] ============================================================")
        print(f"[*] Checking {len(landscape)} system(s) for vulnerabilities:")
        print(f"[*]   - Gateway SAPXPG remote command execution")
        print(f"[*]   - Gateway monitor ACL enforcement")
        print(f"[*]   - Message Server ACL enforcement")
        print(f"[*]   - SAPControl unprotected methods")
        print(f"[*]   - Known CVEs (RECON, ICMAD, etc.)")
        print(f"[*]   - SSL/TLS weak configurations")
        print(f"[*]   - HTTP path scanning for info disclosure")
        print(f"[*]")
        print(f"[*] Starting vulnerability assessment ...")
        print(f"")

        phase2_start = time.time()
        heartbeat_stop = threading.Event()
        hb = threading.Thread(target=_heartbeat, args=("Phase 2", heartbeat_stop),
                              daemon=True)
        hb.start()
        landscape = SAPology.assess_vulnerabilities(
            landscape, gw_cmd="whoami", timeout=timeout + 2,
            verbose=True, url_scan=False,
            cancel_check=lambda: cancel_event.is_set() if cancel_event else False,
        )
        heartbeat_stop.set()

        if cancel_event and cancel_event.is_set():
            return

        phase2_elapsed = time.time() - phase2_start
        total_findings = sum(len(inst.findings) for sys_obj in landscape
                             for inst in sys_obj.instances)

        print(f"")
        print(f"[+] ============================================================")
        print(f"[+]  Phase 2 complete in {phase2_elapsed:.1f}s — "
              f"{total_findings} finding(s)")
        print(f"[+] ============================================================")

        # Convert SAPology SAPSystem objects to SAPMAP SAPNode objects
        print(f"")
        print(f"[*] Converting {len(landscape)} SAPology systems to SAPMAP nodes ...")
        for sys_obj in landscape:
            target_ip = ""
            for inst in sys_obj.instances:
                if inst.ip:
                    target_ip = inst.ip
                    break

            node = _sapology_system_to_node(sys_obj, target_ip)
            nodes.append(node)

            # Determine DB info for display
            db_labels = []
            for label, attr in [("HANA", "has_hana"), ("MaxDB", "has_maxdb"),
                                ("MSSQL", "has_mssql"), ("Oracle", "has_oracle"),
                                ("DB2", "has_db2")]:
                if getattr(sys_obj, attr, False):
                    db_labels.append(label)
            db_str = node.db_type or ""
            if db_labels:
                db_str += f" ({'/'.join(db_labels)})"

            finding_count = len(node.findings)
            crit_count = sum(1 for f in node.findings if f.severity >= Severity.CRITICAL)

            print(f"[+] => {node.sid:8s} | {node.system_type:12s} | "
                  f"Host: {node.hostname or '?':20s} | "
                  f"OS: {node.os_type or '?':15s} | "
                  f"DB: {db_str or '?':15s} | "
                  f"Kernel: {node.kernel or '?':4s} | "
                  f"Clients: {len(node.clients):2d} | "
                  f"Findings: {finding_count}"
                  f"{f' ({crit_count} critical)' if crit_count else ''}")

        if progress_callback:
            progress_callback(len(targets), len(targets), "", len(nodes))

    except Exception as e:
        logger.error(f"SAPology deep scan failed: {e}")
        print(f"[-] SAPology deep scan failed for {targets}: {e}")
        import traceback
        traceback.print_exc()


def deep_scan_single(node: SAPNode, timeout: float = DEFAULT_TIMEOUT,
                     threads: int = DEFAULT_THREADS,
                     cancel_event: threading.Event = None) -> SAPNode:
    """Perform a deep scan on a single already-discovered system.

    This is called from the context menu "Deep Scan" option.
    Uses SAPology discover_systems + assess_vulnerabilities for full
    OS, DB, system type detection and vulnerability checking.
    Updates the node in-place.
    """
    host = node.ip or node.hostname
    if not host:
        print(f"[-] {node.sid}: No IP/hostname, cannot deep scan")
        return node

    print(f"")
    print(f"[*] ============================================================")
    print(f"[*]  Deep Scan: {node.sid} ({host})")
    print(f"[*] ============================================================")

    try:
        import SAPology

        instances = [int(i.instance_nr) for i in node.instances
                     if i.instance_nr.isdigit()]
        if not instances:
            instances = list(range(0, 100))

        print(f"[*] {node.sid}: Phase 1: SAPology Discovery & Fingerprinting")
        print(f"[*] {node.sid}: Target: {host}, Instances: {min(instances):02d}-{max(instances):02d}")
        print(f"[*] {node.sid}: Port scanning, SAPControl queries, RFC_SYSTEM_INFO,")
        print(f"[*] {node.sid}: OS/DB detection, client enumeration ...")
        print(f"")

        # Phase 1: Discovery
        # skip_alive=True because the system is already on the map —
        # cloud hosts may block ICMP and the alive sweep's TCP probes
        landscape = SAPology.discover_systems(
            [host], instances, timeout=timeout, threads=threads,
            verbose=True, skip_alive=True,
            cancel_check=lambda: cancel_event.is_set() if cancel_event else False,
            client_enum=True,
        )

        if not landscape:
            print(f"[*] {node.sid}: SAPology found no SAP system on {host}")
            return node

        sys_obj = landscape[0]
        print(f"")
        print(f"[+] {node.sid}: Phase 1 complete: {sys_obj.sid} found")
        print(f"[+] {node.sid}: Type: {sys_obj.system_type}, OS: {sys_obj.os_type}, "
              f"DB: {sys_obj.db_type}, Kernel: {sys_obj.kernel}")
        print(f"[+] {node.sid}: Host: {sys_obj.hostname}, Clients: {len(sys_obj.clients)}")
        print(f"")

        # Phase 2: Vulnerability assessment
        print(f"[*] {node.sid}: Phase 2: Vulnerability Assessment")
        print(f"[*] {node.sid}: Gateway SAPXPG, MS ACL, SAPControl, CVEs, SSL/TLS ...")
        print(f"")
        landscape = SAPology.assess_vulnerabilities(
            landscape, gw_cmd="whoami", timeout=timeout + 2,
            verbose=True, url_scan=False,
            cancel_check=lambda: cancel_event.is_set() if cancel_event else False,
        )

        # Convert the first result and update node in-place
        sys_obj = landscape[0]
        fresh = _sapology_system_to_node(sys_obj, host)

        # Update node fields from the fresh scan
        node.system_type = fresh.system_type or node.system_type
        node.hostname = fresh.hostname or node.hostname
        node.os_type = fresh.os_type or node.os_type
        node.db_type = fresh.db_type or node.db_type
        node.kernel = fresh.kernel or node.kernel
        node.sap_release = fresh.sap_release or node.sap_release
        node.instances = fresh.instances or node.instances
        node.clients = fresh.clients or node.clients
        node.gw_vulnerable = fresh.gw_vulnerable or node.gw_vulnerable
        # Merge findings (avoid duplicates by name)
        existing_names = {f.name for f in node.findings}
        for f in fresh.findings:
            if f.name not in existing_names:
                node.findings.append(f)
        node.has_critical_finding = any(
            f.severity >= Severity.CRITICAL for f in node.findings
        )
        node.sapology_data = sys_obj.to_dict() if hasattr(sys_obj, 'to_dict') else {}

        # DB detection summary
        db_labels = []
        for label, attr in [("HANA", "has_hana"), ("MaxDB", "has_maxdb"),
                            ("MSSQL", "has_mssql"), ("Oracle", "has_oracle"),
                            ("DB2", "has_db2")]:
            if getattr(sys_obj, attr, False):
                db_labels.append(label)

        print(f"[+] {node.sid}: Deep scan complete:")
        print(f"[+] {node.sid}: System type: {node.system_type}")
        print(f"[+] {node.sid}: OS:          {node.os_type}")
        print(f"[+] {node.sid}: DB:          {node.db_type}"
              f"{' (' + '/'.join(db_labels) + ')' if db_labels else ''}")
        print(f"[+] {node.sid}: Kernel:      {node.kernel}")
        print(f"[+] {node.sid}: Hostname:    {node.hostname}")
        print(f"[+] {node.sid}: Clients:     {len(node.clients)}")
        print(f"[+] {node.sid}: Findings:    {len(node.findings)}")
        if node.gw_vulnerable:
            print(f"[!] {node.sid}: Gateway SAPXPG VULNERABLE")

    except ImportError:
        print("[!] SAPology not available for deep scanning")
    except Exception as e:
        logger.error(f"Deep scan error for {node.sid}: {e}")
        print(f"[-] {node.sid}: Deep scan error: {e}")
        import traceback
        traceback.print_exc()

    return node


# ---------------------------------------------------------------------------
# SAProuter internal network scanning
# ---------------------------------------------------------------------------

def extract_targets_from_router_info(router_info: dict) -> list:
    """Extract internal IP addresses from a saprouter_info_request() result.

    The SAProuter info leak (ROUTER_ADM) exposes connected clients and the
    routing table, both of which contain internal host addresses.  This
    function parses both to produce a deduplicated list of candidate scan
    targets for scan_network_via_saprouter().

    Args:
        router_info: dict returned by sap_router_info.saprouter_info_request()

    Returns:
        Sorted list of unique IP address strings.
    """
    import ipaddress as _ipa
    import re as _re

    ips = set()

    # 1. Connected clients list — each entry has a "host" field
    for client in router_info.get("clients", []):
        addr = (client.get("host") or client.get("ip") or "").strip()
        if addr:
            try:
                _ipa.ip_address(addr)
                ips.add(addr)
            except ValueError:
                pass  # hostname, not IP — skip (use remote resolution instead)

    # 2. Raw info lines — look for /H/<ip>/ patterns from the routing table
    _h_re = _re.compile(r"/[Hh]/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/")
    for line in router_info.get("raw_info", []):
        for match in _h_re.finditer(line):
            addr = match.group(1)
            try:
                _ipa.ip_address(addr)
                ips.add(addr)
            except ValueError:
                pass

    return sorted(ips, key=lambda ip: tuple(int(x) for x in ip.split(".")))


def _sap_ports_for_instance_range(
        instance_range: tuple = (0, 10),
        include_hana: bool = False,
        include_java: bool = False,
        include_msgserver: bool = True,
) -> list:
    """Build the list of SAP ports to probe per host when scanning via SAProuter.

    Returns list of (port, service_name, instance_str) tuples.
    The instance range is intentionally smaller than the direct scan default
    (0-99) because each probe requires a round-trip to the SAProuter.

    Args:
        instance_range:   (start, end) instance numbers inclusive
        include_hana:     Also probe HANA SQL ports (3NN13 / 3NN15)
        include_java:     Also probe JAVA dispatcher (5NN00) and P4 (5NN04)
        include_msgserver: Also probe Message Server port (36NN)
    """
    inst_start, inst_end = instance_range
    ports = []
    for inst_nr in range(inst_start, inst_end + 1):
        inst_str = f"{inst_nr:02d}"
        ports.append((3200 + inst_nr, "dispatcher", inst_str))
        ports.append((3300 + inst_nr, "gateway",    inst_str))
        if include_msgserver:
            ports.append((3600 + inst_nr, "msgserver", inst_str))
        ports.append((50013 + inst_nr * 100, "sapcontrol", inst_str))
        if include_hana:
            ports.append((30000 + inst_nr * 100 + 13, "hana_sql", inst_str))
            ports.append((30000 + inst_nr * 100 + 15, "hana_sql", inst_str))
        if include_java:
            ports.append((50000 + inst_nr * 100,      "java_http", inst_str))
            ports.append((50000 + inst_nr * 100 + 4,  "java_p4",   inst_str))

    # Fixed ports (not instance-specific)
    ports.append((1128,  "saphost_http",  "XX"))
    ports.append((1129,  "saphost_https", "XX"))
    ports.append((3299,  "saprouter",     "99"))  # detect chained routers

    return ports


def scan_host_via_saprouter(
        saprouter_prefix: str,
        target_host: str,
        ports: list,
        timeout: float = 5.0,
        concurrency: int = 10,
        cancel_event: threading.Event = None,
        verbose: bool = True,
) -> dict:
    """Scan one internal host through a SAProuter.

    For each (port, service, instance_str) in *ports*, sends a single
    NI_ROUTE probe and classifies the response as open / closed /
    acl_denied / filtered / unknown_host.

    Only open ports are used for node construction.  acl_denied ports are
    retained separately so the GUI can display the SAProuter ACL map —
    a denied response proves the host exists even when nothing is open.

    Args:
        saprouter_prefix: Route prefix, e.g. "/H/1.2.3.4/S/3299/W/pass"
        target_host:      Internal IP or hostname to scan
        ports:            List of (port, service_name, instance_str) tuples
        timeout:          Per-probe socket timeout
        concurrency:      Max simultaneous probes (keep ≤10 to avoid flooding
                          the shared SAProuter)
        cancel_event:     Optional cancellation signal

    Returns dict matching fast_scan_host() output, plus:
        acl_denied_ports: list of ints — ports blocked by SAProuter ACL
        probe_counts:     dict with open/closed/acl_denied/filtered counts
    """
    from sap_saprouter import probe_port_via_saprouter
    from sap_saprouter import (PROBE_OPEN, PROBE_CLOSED,
                               PROBE_ACL_DENIED, PROBE_FILTERED,
                               PROBE_UNKNOWN_HOST)

    result = {
        "host": target_host,
        "open_ports": {},
        "acl_denied_ports": [],
        "has_sap": False,
        "probe_counts": {PROBE_OPEN: 0, PROBE_CLOSED: 0,
                         PROBE_ACL_DENIED: 0, PROBE_FILTERED: 0,
                         PROBE_UNKNOWN_HOST: 0, "error": 0},
    }

    _cancelled = lambda: cancel_event and cancel_event.is_set()

    def _probe(args):
        port, service, inst_str = args
        if _cancelled():
            return None
        r = probe_port_via_saprouter(saprouter_prefix, target_host, port, timeout)
        return (port, service, inst_str, r["status"], r.get("message", ""))

    total_count = len(ports)
    done_count = 0
    tick_every = max(10, total_count // 8)  # ~8 status lines per host
    t_start = time.time()

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(_probe, p) for p in ports]
        for f in as_completed(futures):
            if _cancelled():
                break
            res = f.result()
            done_count += 1
            if res is None:
                continue
            port, service, inst_str, status, msg = res
            result["probe_counts"][status] = result["probe_counts"].get(status, 0) + 1

            if status == PROBE_OPEN:
                result["open_ports"][port] = {"service": service,
                                              "instance_nr": inst_str}
                if verbose:
                    print(f"[+]   {target_host}:{port:<6} OPEN       "
                          f"({service}, inst {inst_str})")
            elif status == PROBE_ACL_DENIED:
                result["acl_denied_ports"].append(port)
                if verbose:
                    print(f"[~]   {target_host}:{port:<6} ACL-denied "
                          f"({service}, inst {inst_str})")

            if verbose and (done_count % tick_every == 0
                            or done_count == total_count):
                pc = result["probe_counts"]
                el = time.time() - t_start
                print(f"[*]   {target_host}: {done_count}/{total_count} probed "
                      f"— open={pc.get(PROBE_OPEN,0)} "
                      f"acl={pc.get(PROBE_ACL_DENIED,0)} "
                      f"filtered={pc.get(PROBE_FILTERED,0)} "
                      f"closed={pc.get(PROBE_CLOSED,0)}  [{el:.1f}s]")

    result["has_sap"] = bool(result["open_ports"])
    return result


def scan_network_via_saprouter(
        saprouter_prefix: str,
        targets: list,
        instance_range: tuple = (0, 10),
        timeout: float = 5.0,
        concurrency: int = 10,
        mode: str = "sap",
        cancel_event: threading.Event = None,
        progress_callback=None,
        node_callback=None,
        verbose: bool = True,
) -> list:
    """Scan an internal network through a SAProuter and build SAPNode objects.

    This is the SAProuter equivalent of discover_systems().  It probes
    internal hosts via probe_port_via_saprouter() — without a live-host
    sweep (impossible through a router) — then enriches discovered SAP
    systems with RFC_SYSTEM_INFO and client enumeration, all routed
    through the same SAProuter tunnel.

    Args:
        saprouter_prefix: Route prefix up to (not including) the target,
                          e.g. "/H/10.0.0.1/S/3299/W/secret"
        targets:          List of internal IP strings (use parse_targets() or
                          extract_targets_from_router_info() to build this)
        instance_range:   (start, end) SAP instance numbers to probe
        timeout:          Per-probe socket timeout in seconds
        concurrency:      Simultaneous probes per host (≤10 recommended)
        mode:             "sap"  — dispatcher + gateway + msgserver + sapcontrol
                          "full" — also HANA SQL and JAVA ports
        cancel_event:     Cancellation signal
        progress_callback: callable(done, total) for progress updates
        node_callback:    callable(SAPNode) invoked as each node is discovered
        verbose:          Extra logging

    Returns:
        List of SAPNode objects with node.saprouter set so all subsequent
        operations (RFC, exploitation, SecStore) route through the tunnel.
    """
    include_hana = (mode == "full")
    include_java = (mode == "full")
    ports = _sap_ports_for_instance_range(
        instance_range, include_hana=include_hana, include_java=include_java
    )

    total = len(targets)
    svc_set = sorted({svc for _, svc, _ in ports})
    svc_summary = ", ".join(svc_set) if len(svc_set) <= 8 else f"{len(svc_set)} service types"
    print(f"[*] ========================================")
    print(f"[*]  SAProuter Internal Scan")
    print(f"[*]  Router: {saprouter_prefix}")
    print(f"[*]  {total} target(s), {len(ports)} ports/host, "
          f"instances {instance_range[0]:02d}-{instance_range[1]:02d}, "
          f"mode={mode}")
    print(f"[*]  Services: {svc_summary}")
    print(f"[*]  Timeout={timeout}s, concurrency={concurrency}, "
          f"verbose={verbose}")
    print(f"[*] ========================================")

    nodes = []
    scan_results_with_sap = []
    total_start = time.time()

    for idx, host in enumerate(targets):
        if cancel_event and cancel_event.is_set():
            print("[!] Router scan cancelled")
            break

        if progress_callback:
            progress_callback(idx, total)

        print(f"[*] {host}: Probing {len(ports)} ports via SAProuter "
              f"({idx + 1}/{total}) ...")
        t0 = time.time()
        host_result = scan_host_via_saprouter(
            saprouter_prefix, host, ports, timeout,
            concurrency, cancel_event,
            verbose=verbose,
        )
        elapsed = time.time() - t0
        counts = host_result["probe_counts"]

        if host_result["has_sap"]:
            n_open = len(host_result["open_ports"])
            n_acl  = len(host_result["acl_denied_ports"])
            print(f"[+] {host}: {n_open} open SAP port(s), "
                  f"{n_acl} ACL-denied"
                  f"{', ' + str(counts.get('filtered', 0)) + ' filtered' if counts.get('filtered') else ''}"
                  f"  [{elapsed:.1f}s]")
            scan_results_with_sap.append(host_result)

        elif host_result["acl_denied_ports"]:
            # ACL denied responses prove the SAProuter knows this host —
            # report it even though no ports are open.
            n_acl = len(host_result["acl_denied_ports"])
            print(f"[~] {host}: No open ports but {n_acl} port(s) ACL-denied "
                  f"(host known to SAProuter)  [{elapsed:.1f}s]")
            scan_results_with_sap.append(host_result)

        else:
            open_c    = counts.get(PROBE_OPEN if False else "open", 0)
            filtered_c = counts.get("filtered", 0)
            if verbose:
                print(f"[*] {host}: No SAP found — "
                      f"filtered={filtered_c}  [{elapsed:.1f}s]")

    if progress_callback:
        progress_callback(total, total)

    if not scan_results_with_sap:
        print(f"[*] No SAP systems found via SAProuter scan")
        return nodes

    # Enrich each discovered host with RFC_SYSTEM_INFO + client enumeration,
    # all routed through the same SAProuter prefix.
    print(f"")
    print(f"[*] === PHASE 2: Enrichment (via SAProuter) ===")
    print(f"[*] Enriching {len(scan_results_with_sap)} host(s) with "
          f"RFC_SYSTEM_INFO + client enum ...")

    for idx, host_result in enumerate(scan_results_with_sap):
        if cancel_event and cancel_event.is_set():
            break

        host = host_result["host"]
        print(f"[*] {host}: --- Host {idx + 1}/{len(scan_results_with_sap)} ---")

        if not host_result["open_ports"]:
            # ACL-denied only — build minimal node so map shows the host
            acl_ports = host_result["acl_denied_ports"]
            node = SAPNode(
                sid=f"ACL_{host.replace('.', '_')}",
                system_type="SAP?",
                ip=host,
                hostname="",
            )
            node.saprouter = saprouter_prefix
            # Store ACL info as a finding
            from sapmap_models import Finding, Severity
            node.findings.append(Finding(
                name="SAP ports ACL-denied by SAProuter",
                attack_techniques=_attack_for("recon.saprouter_info"),
                description=(
                    f"SAProuter blocks access to {len(acl_ports)} SAP port(s) "
                    f"on this host: {', '.join(str(p) for p in sorted(acl_ports)[:20])}. "
                    f"The host is known to the SAProuter routing table."
                ),
                severity=Severity.INFO,
                remediation=(
                    "Confirm with the SAP basis team that this ACL behaviour "
                    "is intended.  If the host is meant to be reachable from "
                    "this side of the SAProuter, edit `saprouttab` to add an "
                    "explicit allow-line for the required (source, target, "
                    "port) tuple.  If not, this finding is informational — "
                    "leave the ACL in place."
                ),
                detail=f"Denied ports: {', '.join(str(p) for p in sorted(acl_ports))}",
            ))
            nodes.append(node)
            if node_callback:
                node_callback(node)
            continue

        host_nodes = _build_nodes_from_fast_scan(
            host_result, timeout=timeout, verbose=verbose,
            saprouter=saprouter_prefix,
        )

        # Attach ACL-denied port info as findings on each node
        acl_ports = host_result.get("acl_denied_ports", [])
        for node in host_nodes:
            if acl_ports:
                from sapmap_models import Finding, Severity
                node.findings.append(Finding(
                    name="SAProuter ACL partially blocks this host",
                    attack_techniques=_attack_for("recon.saprouter_info"),
                    description=(
                        f"SAProuter ACL denies access to {len(acl_ports)} "
                        f"port(s): {', '.join(str(p) for p in sorted(acl_ports)[:20])}. "
                        f"Other ports are accessible."
                    ),
                    severity=Severity.INFO,
                    remediation=(
                        "Audit the saprouttab — the partial-allow pattern "
                        "is unusual and often unintentional.  Either "
                        "restrict the host fully (drop the open ports too) "
                        "or open it fully if the use case requires it.  "
                        "Half-open exposure surfaces in scans as a "
                        "fingerprint of internal topology."
                    ),
                    detail=f"Denied ports: {', '.join(str(p) for p in sorted(acl_ports))}",
                ))

        nodes.extend(host_nodes)
        for node in host_nodes:
            if node_callback:
                node_callback(node)

        for node in host_nodes:
            inst_list = ", ".join(node.instance_nrs()) or "?"
            print(f"[+] {node.sid}: => {node.system_type} | "
                  f"Host: {node.hostname or '?'} | "
                  f"OS: {node.os_type or '?'} | "
                  f"Kernel: {node.kernel or '?'} | "
                  f"Instances: [{inst_list}] | "
                  f"Clients: {len(node.clients)} | "
                  f"SAProuter: ✓")
        print()

    elapsed = time.time() - total_start
    print(f"[*] ========================================")
    print(f"[+]  SAProuter scan complete in {elapsed:.1f}s")
    print(f"[+]  SAP systems found: {len(nodes)}")
    print(f"[*] ========================================")

    return nodes
