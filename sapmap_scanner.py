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
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from sapmap_models import SAPNode, InstanceInfo, Finding, Severity
from sapmap_config import (
    DEFAULT_INSTANCE_RANGE, DEFAULT_THREADS, DEFAULT_TIMEOUT,
    FAST_SCAN_PORT_PATTERNS,
)

logger = logging.getLogger(__name__)

# Add SAPology to path for imports
_sapology_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "SAPology")
if os.path.isdir(_sapology_dir) and _sapology_dir not in sys.path:
    sys.path.insert(0, _sapology_dir)

# Import from existing modules in SAPMAP directory
from sap_rfc_system_info import probe_sap_system
from sap_client_enum import enumerate_clients


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


# Ports that collide with SAP port formulas but are NOT standard SAP services.
# 3389 = RDP (instance 89 gateway would be 3300+89=3389) — currently not scanned
NON_SAP_PORTS = set()

# SAProuter port — scanned separately, not as a dispatcher
SAPROUTER_PORT = 3299


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
        QUICK_PORTS = list(range(3200, 3300)) + [8000, 50013, 50113, 50213, 50313, 54213, 1128]
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

    def _do_scan(port_list):
        hits = {}
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
                if r:
                    hits[r[0]] = {"service": r[1], "instance_nr": r[2]}
        return hits

    # Pass 1: Dispatcher + SAPControl + fixed ports (fast — ~300 ports)
    ports_pass1 = _build_port_list(instance_range, include_hana=False)
    # SAPControl HTTP ports (5XX13) — detects ABAP, JAVA, and double-stack
    for inst_nr in range(instance_range[0], instance_range[1] + 1):
        ports_pass1.append((50013 + inst_nr * 100, "sapcontrol", f"{inst_nr:02d}"))
    ports_pass1.append((1128, "saphost_http", "XX"))
    ports_pass1.append((1129, "saphost_https", "XX"))

    if _cancelled():
        return result
    print(f"[*] {host}: Pass 1: scanning {len(ports_pass1)} ports "
          f"(dispatcher 32XX, SAPHostControl) ...")
    t0 = time.time()
    hits1 = _do_scan(ports_pass1)
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

    if _cancelled():
        return result
    result["has_sap"] = len(result["open_ports"]) > 0

    # Pass 2: Gateway + HANA SQL ports — only for discovered instances
    if result["has_sap"] and not _cancelled():
        found_instances = sorted(set(
            v["instance_nr"] for v in result["open_ports"].values()
            if v["instance_nr"] != "XX"
        ))
        pass2_ports = []
        for inst_str in found_instances:
            inst_nr = int(inst_str)
            pass2_ports.append((3300 + inst_nr, "gateway", inst_str))
            pass2_ports.append((3900 + inst_nr, "ms_internal", inst_str))  # betrusted
            pass2_ports.append((30000 + inst_nr * 100 + 13, "hana_sql", inst_str))
            pass2_ports.append((30000 + inst_nr * 100 + 15, "hana_sql", inst_str))
            # Java HTTP / HTTPS dispatcher ports (icm) — by SAP convention
            # 50000+nn*100 (HTTP) and +1 (HTTPS).  Cheap fallback for when
            # SAPControl is firewalled or refuses GetInstanceProperties.
            pass2_ports.append((50000 + inst_nr * 100,     "java_http",  inst_str))
            pass2_ports.append((50000 + inst_nr * 100 + 1, "java_https", inst_str))

        print(f"[*] {host}: Pass 2: scanning {len(pass2_ports)} ports "
              f"(gateway 33XX, HANA 3XX13/3XX15, Java 5NN00/01) for "
              f"{len(found_instances)} instance(s) ...")
        t0 = time.time()
        hits2 = _do_scan(pass2_ports)
        if not _cancelled():
            result["open_ports"].update(hits2)
            print(f"[*] {host}: Pass 2 done in {time.time() - t0:.1f}s — "
                  f"{len(hits2)} port(s) open")

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
                node.findings.append(Finding(
                    name="MS Internal Port Without ACL (CVE-2020-6207)",
                    severity=Severity.CRITICAL,
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
            if not any(f.name.startswith("CVE-2025-31324") for f in node.findings):
                node.findings.append(Finding(
                    name="CVE-2025-31324 — VisualComposer Metadatauploader RCE",
                    severity=Severity.CRITICAL,
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

    try:
        result = probe_sap_system(host, gw_port, timeout=timeout, verbose=verbose,
                                  router=router_tuple)
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
    info.setdefault("http_ports", {})   # {inst_nr: (http_port, https_port)}
    for inst_nr in ordered_nrs:
        sc_port = 50000 + inst_nr * 100 + 13
        sid, is_java, is_abap, db_type, icm_http, icm_https = \
            _query_sapcontrol_sid(host, sc_port, timeout=min(timeout, 3))
        if sid and not info["sid"]:
            info["sid"] = sid
            tag = sid  # update tag with discovered SID
            print(f"[+] {tag}: SID from SAPControl ({host}:{sc_port}): {sid}")
        if is_java or is_abap:
            info["_is_java"] = info.get("_is_java", False) or is_java
            info["_is_abap"] = info.get("_is_abap", False) or is_abap
            print(f"[+] {tag}: Stack from SAPControl ({host}:{sc_port}):"
                  f"{'  [ABAP]' if is_abap else ''}"
                  f"{'  [JAVA]' if is_java else ''}")
        if db_type and not info["db_type"]:
            info["db_type"] = db_type
            print(f"[+] {tag}: DB type from SAPControl ({host}:{sc_port}): "
                  f"{db_type}")
        if icm_http or icm_https:
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

    # If OS still unknown, try SAPControl GetProcessList (.EXE = Windows)
    if not info["os_type"]:
        for inst_nr in ordered_nrs:
            sc_port = 50000 + inst_nr * 100 + 13
            os_type = _query_sapcontrol_os(host, sc_port, timeout=min(timeout, 3))
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


def _query_sapcontrol_sid(host: str, port: int, timeout: float = 3) -> tuple:
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

        # Detect ABAP vs JAVA from properties
        if "ABAP WP Table" in prop_dict:
            is_abap = True
        if any("J2EE" in p for p in prop_dict):
            is_java = True
        # SCS (SAP Central Services) and message server = Java infrastructure
        inst_name = prop_dict.get("INSTANCE_NAME", "")
        if inst_name.startswith("SCS") or inst_name.startswith("J"):
            is_java = True

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


def _query_sapcontrol_os(host: str, port: int, timeout: float = 3) -> str:
    """Detect OS type via SAPControl GetProcessList.

    Process names ending with .EXE indicate Windows; otherwise Linux/Unix.
    GetProcessList is usually available without authentication.

    Returns os_type string ("Linux", "Windows") or "" if detection fails.
    """
    import re as _re
    try:
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
                             sid_hint: str = "", saprouter: str = "") -> list:
    """Enumerate SAP clients via DIAG protocol.

    Args:
        sid_hint: Optional SID to use as log prefix (for already-known systems).
        saprouter: Optional SAProuter route string prefix.
    Returns list of client number strings, e.g. ["000", "001", "100"].
    """
    tag = sid_hint or host
    print(f"[*] {tag}: Enumerating clients on {host}:{disp_port} via DIAG"
          f"{' (via SAProuter)' if saprouter else ''} ...")
    try:
        result = enumerate_clients(host, disp_port, timeout=timeout,
                                   max_workers=max_workers, verbose=verbose,
                                   saprouter=saprouter)
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
    open_ports = scan_result["open_ports"]

    # Collect instance numbers
    instance_nrs = sorted(set(
        v["instance_nr"] for v in open_ports.values()
    ))

    # Phase A: Query SID for EACH instance individually
    instance_sid_map = {}   # {instance_nr: sid}
    instance_sysinfo = {}   # {instance_nr: sys_info dict}

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
                                          verbose=verbose, saprouter=saprouter)
            if sys_info.get("sid"):
                instance_sid_map[inst_nr] = sys_info["sid"]
                instance_sysinfo[inst_nr] = sys_info
                continue

        # No gateway open for this instance — try dispatcher+100
        for port, info in sorted(open_ports.items()):
            if info["service"] == "dispatcher" and info["instance_nr"] == inst_nr:
                derived_gw = port + 100  # 32XX -> 33XX
                print(f"[*] {host}: No gateway for instance {inst_nr}, trying dispatcher+100 = {derived_gw}")
                sys_info = enrich_system_info(host, derived_gw, timeout=timeout,
                                              verbose=verbose, saprouter=saprouter)
                if sys_info.get("sid"):
                    instance_sid_map[inst_nr] = sys_info["sid"]
                    instance_sysinfo[inst_nr] = sys_info
                break

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

    # Phase B: Assign unresolved instances to the first known SID (or UNK)
    default_sid = next(iter(instance_sid_map.values()), f"UNK_{host.replace('.', '_')}")
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
        type_parts = []
        if sc_is_abap or has_dispatcher:
            type_parts.append("ABAP")
        if sc_is_java:
            type_parts.append("JAVA")
        if type_parts:
            system_type = "+".join(type_parts)
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
        # Attach saprouter prefix so all subsequent operations (exploit, RFC,
        # secstore, SXPG) automatically route through the tunnel.
        if saprouter:
            node.saprouter = saprouter
        nodes.append(node)

    return nodes


def discover_systems(targets: list, instance_range: tuple = DEFAULT_INSTANCE_RANGE,
                     timeout: float = DEFAULT_TIMEOUT, threads: int = DEFAULT_THREADS,
                     fast_mode: bool = True, cancel_event: threading.Event = None,
                     progress_callback=None, verbose: bool = False,
                     skip_alive: bool = False, concurrent_hosts: int = 5,
                     port_timeout: float = 3.0,
                     node_callback=None) -> list:
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

    Returns:
        list of SAPNode objects
    """
    nodes = []
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
    print(f"[+]  SAP systems found: {len(nodes)}")
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
    print(f"[*] ========================================")

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

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(_probe, p) for p in ports]
        for f in as_completed(futures):
            if _cancelled():
                break
            res = f.result()
            if res is None:
                continue
            port, service, inst_str, status, msg = res
            result["probe_counts"][status] = result["probe_counts"].get(status, 0) + 1

            if status == PROBE_OPEN:
                result["open_ports"][port] = {"service": service,
                                              "instance_nr": inst_str}
            elif status == PROBE_ACL_DENIED:
                result["acl_denied_ports"].append(port)

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
        verbose: bool = False,
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
    print(f"[*] ========================================")
    print(f"[*]  SAProuter Internal Scan")
    print(f"[*]  Router: {saprouter_prefix}")
    print(f"[*]  {total} target(s), {len(ports)} ports/host, "
          f"instances {instance_range[0]:02d}-{instance_range[1]:02d}, "
          f"mode={mode}")
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
                title="SAP ports ACL-denied by SAProuter",
                description=(
                    f"SAProuter blocks access to {len(acl_ports)} SAP port(s) "
                    f"on this host: {', '.join(str(p) for p in sorted(acl_ports)[:20])}. "
                    f"The host is known to the SAProuter routing table."
                ),
                severity=Severity.INFO,
                category="Network",
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
                    title="SAProuter ACL partially blocks this host",
                    description=(
                        f"SAProuter ACL denies access to {len(acl_ports)} "
                        f"port(s): {', '.join(str(p) for p in sorted(acl_ports)[:20])}. "
                        f"Other ports are accessible."
                    ),
                    severity=Severity.INFO,
                    category="Network",
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
