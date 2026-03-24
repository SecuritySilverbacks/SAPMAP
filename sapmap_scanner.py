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

def _scan_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """Check if a TCP port is open."""
    try:
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

    # Timeout with no data = inconclusive (dispatcher might be busy).
    # Treat as "probably SAP" to avoid false negatives.
    if len(resp) == 0:
        return True

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


# Ports that collide with SAP port formulas but are NOT SAP services
NON_SAP_PORTS = set()  # Previously had 3389 (RDP = gateway 3300+89), no longer needed


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
            print(f"[*]     Quick probe ({len(QUICK_PORTS)} ports) — "
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
    print(f"[*]     Pass 1: scanning {len(ports_pass1)} ports "
          f"(dispatcher 32XX, SAPHostControl) ...")
    t0 = time.time()
    hits1 = _do_scan(ports_pass1)
    if _cancelled():
        return result
    result["open_ports"].update(hits1)
    print(f"[*]     Pass 1 done in {time.time() - t0:.1f}s — "
          f"{len(hits1)} open port(s)")

    # Verify dispatcher ports with DIAG protocol probe
    disp_ports = [p for p, info in result["open_ports"].items()
                  if info["service"] == "dispatcher"]
    if disp_ports and not _cancelled():
        print(f"[*]     Verifying {len(disp_ports)} dispatcher port(s) "
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
            pass2_ports.append((30000 + inst_nr * 100 + 13, "hana_sql", inst_str))
            pass2_ports.append((30000 + inst_nr * 100 + 15, "hana_sql", inst_str))

        print(f"[*]     Pass 2: scanning {len(pass2_ports)} ports "
              f"(gateway 33XX, HANA 3XX13/3XX15) for {len(found_instances)} instance(s) ...")
        t0 = time.time()
        hits2 = _do_scan(pass2_ports)
        if not _cancelled():
            result["open_ports"].update(hits2)
            print(f"[*]     Pass 2 done in {time.time() - t0:.1f}s — "
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
# System info enrichment (unauthenticated)
# ---------------------------------------------------------------------------

def enrich_system_info(host: str, gw_port: int, timeout: float = 10,
                       verbose: bool = False,
                       instance_nrs: list = None) -> dict:
    """Call RFC_SYSTEM_INFO (unauthenticated) to get OS, DB, kernel, hostname, SID.

    Args:
        instance_nrs: Explicit instance numbers to try for SAPControl (prioritized).
    Returns dict with fields: sid, hostname, os, db_type, kernel, sap_release, ip, etc.
    """
    info = {
        "sid": "",
        "hostname": "",
        "os_type": "",
        "db_type": "",
        "kernel": "",
        "sap_release": "",
        "ip": host,
    }

    print(f"[*]   Probing RFC_SYSTEM_INFO on {host}:{gw_port} ...")
    try:
        result = probe_sap_system(host, gw_port, timeout=timeout, verbose=verbose)
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
            print(f"[+]   RFC_SYSTEM_INFO ({status}): SID={info['sid'] or '?'}, "
                  f"Host={info['hostname'] or '?'}, OS={info['os_type'] or '?'}, "
                  f"DB={info['db_type'] or '?'}, Kernel={info['kernel'] or '?'}, "
                  f"Release={info['sap_release'] or '?'}")
        else:
            methods = result.get("methods_tried", [])
            methods_ok = result.get("methods_success", [])
            print(f"[!]   RFC_SYSTEM_INFO: no data extracted (status={status}, "
                  f"methods tried={methods}, success={methods_ok})")

    except Exception as e:
        print(f"[-]   RFC_SYSTEM_INFO error on {host}:{gw_port}: {e}")
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
    for inst_nr in ordered_nrs:
        sc_port = 50000 + inst_nr * 100 + 13
        sid, is_java, is_abap, db_type = _query_sapcontrol_sid(
            host, sc_port, timeout=min(timeout, 3)
        )
        if sid and not info["sid"]:
            info["sid"] = sid
            print(f"[+]   SID from SAPControl ({host}:{sc_port}): {sid}")
        if is_java or is_abap:
            info["_is_java"] = info.get("_is_java", False) or is_java
            info["_is_abap"] = info.get("_is_abap", False) or is_abap
            print(f"[+]   Stack from SAPControl ({host}:{sc_port}):"
                  f"{'  [ABAP]' if is_abap else ''}"
                  f"{'  [JAVA]' if is_java else ''}")
        if db_type and not info["db_type"]:
            info["db_type"] = db_type
            print(f"[+]   DB type from SAPControl ({host}:{sc_port}): "
                  f"{db_type}")
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
                print(f"[+]   OS type from SAPControl ({host}:{sc_port}): "
                      f"{os_type}")
                break

    # Last resort: infer DB from product name (weak - kernel range is not proof)
    if not info["db_type"]:
        try:
            product = result.get("sap_product", "")
            if "HANA" in product.upper():
                info["db_type"] = "HDB"
                print(f"[!]   DB type inferred from product name '{product}'"
                      f" (weak heuristic, may be wrong)")
        except Exception:
            pass

    return info


def _query_sapcontrol_sid(host: str, port: int, timeout: float = 3) -> tuple:
    """Quick SAPControl SOAP query to extract SID, system type, and DB type.

    Returns (sid, is_java, is_abap, db_type) tuple.
    SID is extracted from (in priority order):
      1. SAPSYSTEMNAME property
      2. ABAP/J2EE DB Connection string (DBName=XXX)
      3. INSTANCE_NAME prefix (e.g. DVEBMGS00 -> SID from hostname)
    DB type is extracted from the "Database" property (e.g. "SAPdb" -> "ADA").
    """
    import re as _re
    sid = ""
    is_java = False
    is_abap = False
    db_type = ""

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

    except Exception:
        pass
    return (sid, is_java, is_abap, db_type)


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
                             max_workers: int = 20, verbose: bool = False) -> list:
    """Enumerate SAP clients via DIAG protocol.

    Returns list of client number strings, e.g. ["000", "001", "100"].
    """
    print(f"[*]   Enumerating clients on {host}:{disp_port} via DIAG ...")
    try:
        result = enumerate_clients(host, disp_port, timeout=timeout,
                                   max_workers=max_workers, verbose=verbose)
        clients = result.get("clients", [])
        status = result.get("status", "unknown")
        probed = result.get("probed", 0)
        errors = result.get("errors", 0)
        if clients:
            print(f"[+]   Found {len(clients)} clients: {', '.join(clients[:15])}"
                  f"{'...' if len(clients) > 15 else ''}"
                  f" (probed={probed}, errors={errors})")
        else:
            print(f"[*]   No clients found (status={status}, "
                  f"probed={probed}, errors={errors})")
        return clients
    except Exception as e:
        print(f"[-]   Client enumeration error on {host}:{disp_port}: {e}")
        logger.debug(f"Client enum failed for {host}:{disp_port}: {e}")
        return []


# ---------------------------------------------------------------------------
# Build SAPNode from scan results
# ---------------------------------------------------------------------------

def _build_nodes_from_fast_scan(scan_result: dict, timeout: float = 10,
                                verbose: bool = False) -> list:
    """Build one or more SAPNodes from fast scan results + system info enrichment.

    Queries each discovered instance's gateway individually so that multiple SAP
    systems sharing the same IP address (different SIDs on different instance
    numbers) are detected as separate nodes rather than being collapsed into one.
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
            sys_info = enrich_system_info(host, gw_port, timeout=timeout, verbose=verbose)
            if sys_info.get("sid"):
                instance_sid_map[inst_nr] = sys_info["sid"]
                instance_sysinfo[inst_nr] = sys_info
                continue

        # No gateway open for this instance — try dispatcher+100
        for port, info in sorted(open_ports.items()):
            if info["service"] == "dispatcher" and info["instance_nr"] == inst_nr:
                derived_gw = port + 100  # 32XX -> 33XX
                print(f"[*]   No gateway for instance {inst_nr}, trying dispatcher+100 = {derived_gw}")
                sys_info = enrich_system_info(host, derived_gw, timeout=timeout, verbose=verbose)
                if sys_info.get("sid"):
                    instance_sid_map[inst_nr] = sys_info["sid"]
                    instance_sysinfo[inst_nr] = sys_info
                break

        if inst_nr in instance_sid_map:
            continue

        # Try SAPControl as last resort for this instance
        if inst_nr.isdigit():
            sc_port = 50000 + int(inst_nr) * 100 + 13
            sc_sid, sc_j, sc_a, _ = _query_sapcontrol_sid(
                host, sc_port, timeout=min(timeout, 3)
            )
            if sc_sid:
                instance_sid_map[inst_nr] = sc_sid
                instance_sysinfo[inst_nr] = {
                    "sid": sc_sid, "_is_java": sc_j, "_is_abap": sc_a
                }
                print(f"[+]   SID from SAPControl ({host}:{sc_port}): {sc_sid}"
                      f"{'  [JAVA]' if sc_j else ''}"
                      f"{'  [ABAP]' if sc_a else ''}")

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
        # Pick enrichment data from the first instance in this group that has it
        sys_info = {}
        for inr in inst_nrs_for_sid:
            if inr in instance_sysinfo and instance_sysinfo[inr].get("sid"):
                sys_info = instance_sysinfo[inr]
                break

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
            print(f"[+]   HANA database detected via SQL port (SID: {sid})")

        # Determine system type from this SID's ports + SAPControl hints
        has_dispatcher = "dispatcher" in sid_port_services
        has_saphost = any(s in ("saphost_http", "saphost_https") for s in sid_port_services)
        type_parts = []
        if sc_is_abap or has_dispatcher:
            type_parts.append("ABAP")
        if sc_is_java:
            type_parts.append("JAVA")
        if type_parts:
            system_type = "+".join(type_parts)
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
                                                       verbose=verbose)
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
            print(f"[*] --- Host {idx + 1}/{len(scan_results)}: "
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
                print(f"[+] => {node.sid} | {node.system_type} | "
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
        print(f"[-] SAPology deep scan failed: {e}")
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
        print(f"[-] No IP/hostname for {node.sid}, cannot deep scan")
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

        print(f"[*] Phase 1: SAPology Discovery & Fingerprinting")
        print(f"[*]   Target: {host}, Instances: {min(instances):02d}-{max(instances):02d}")
        print(f"[*]   Port scanning, SAPControl queries, RFC_SYSTEM_INFO,")
        print(f"[*]   OS/DB detection, client enumeration ...")
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
            print(f"[*] SAPology found no SAP system on {host}")
            return node

        sys_obj = landscape[0]
        print(f"")
        print(f"[+] Phase 1 complete: {sys_obj.sid} found")
        print(f"[+]   Type: {sys_obj.system_type}, OS: {sys_obj.os_type}, "
              f"DB: {sys_obj.db_type}, Kernel: {sys_obj.kernel}")
        print(f"[+]   Host: {sys_obj.hostname}, Clients: {len(sys_obj.clients)}")
        print(f"")

        # Phase 2: Vulnerability assessment
        print(f"[*] Phase 2: Vulnerability Assessment")
        print(f"[*]   Gateway SAPXPG, MS ACL, SAPControl, CVEs, SSL/TLS ...")
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

        print(f"[+] Deep scan complete for {node.sid}:")
        print(f"    System type: {node.system_type}")
        print(f"    OS:          {node.os_type}")
        print(f"    DB:          {node.db_type}"
              f"{' (' + '/'.join(db_labels) + ')' if db_labels else ''}")
        print(f"    Kernel:      {node.kernel}")
        print(f"    Hostname:    {node.hostname}")
        print(f"    Clients:     {len(node.clients)}")
        print(f"    Findings:    {len(node.findings)}")
        if node.gw_vulnerable:
            print(f"    [!] Gateway SAPXPG VULNERABLE")

    except ImportError:
        print("[!] SAPology not available for deep scanning")
    except Exception as e:
        logger.error(f"Deep scan error for {node.sid}: {e}")
        print(f"[-] Deep scan error: {e}")
        import traceback
        traceback.print_exc()

    return node
