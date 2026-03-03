#!/usr/bin/env python3
"""
SAPMAP Scanner — Network discovery of SAP systems.

Wraps SAPology scanning functions and the standalone helper modules
(sap_rfc_system_info, sap_client_enum) to discover SAP systems on a
network and populate SAPNode objects for the map.

Supports two modes:
  - Fast scan: ports 32XX/33XX only (dispatcher + gateway) for quick discovery
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


def _is_host_alive(host: str, timeout: float = ALIVE_TIMEOUT) -> bool:
    """Quick check if a host is reachable.

    Runs ICMP ping and TCP probes in parallel threads so a single dead
    host takes at most ~0.5-0.8s instead of sequentially accumulating
    timeouts.  Returns True on first success.
    """
    found = threading.Event()

    def _ping():
        try:
            import subprocess
            ret = subprocess.call(
                ["ping", "-c", "1", "-W", "1", host],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=1.0,
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

    # Wait for first success or all to finish (whichever is sooner)
    # Max wait = slightly over TCP timeout so dead hosts don't block long
    deadline = time.time() + timeout + 0.6
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

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(_check, h) for h in targets]
        for f in as_completed(futures):
            if cancel_event and cancel_event.is_set():
                break
            f.result()  # propagate exceptions

    elapsed = time.time() - t0
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
NON_SAP_PORTS = {3389}  # Windows RDP = gateway base 3300 + instance 89


def _build_port_list(instance_range, include_hana=False, skip_non_sap=True):
    """Build list of (port, service, instance_nr) tuples for scanning.

    Always includes dispatcher (32XX) and gateway (33XX).
    HANA SQL (3XX13/3XX15) only included when include_hana=True to avoid
    doubling the port count (adds 200 extra ports for 100 instances).
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
                   cancel_event: threading.Event = None) -> dict:
    """Fast scan a single host for SAP ports.

    Two-pass approach:
      Pass 1: Scan dispatcher (32XX), gateway (33XX), SAPHostControl (1128/1129)
      Pass 2: If SAP found, scan HANA SQL (3XX13/3XX15) for detected instances

    Verifies dispatcher ports with SAP DIAG protocol probe to eliminate
    false positives from non-SAP services on 32XX ports.

    Returns dict: {
        "host": str,
        "open_ports": {port: {"service": str, "instance_nr": str}},
        "has_sap": bool
    }
    """
    result = {"host": host, "open_ports": {}, "has_sap": False}

    def _do_scan(port_list):
        hits = {}
        def _check(args):
            port, svc, inst = args
            if cancel_event and cancel_event.is_set():
                return None
            if _scan_port(host, port, timeout):
                return (port, svc, inst)
            return None
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(_check, a) for a in port_list]
            for f in as_completed(futures):
                if cancel_event and cancel_event.is_set():
                    break
                r = f.result()
                if r:
                    hits[r[0]] = {"service": r[1], "instance_nr": r[2]}
        return hits

    # Pass 1: Dispatcher + Gateway + fixed ports (fast — ~200 ports)
    ports_pass1 = _build_port_list(instance_range, include_hana=False)
    ports_pass1.append((1128, "saphost_http", "XX"))
    ports_pass1.append((1129, "saphost_https", "XX"))

    hits1 = _do_scan(ports_pass1)
    result["open_ports"].update(hits1)

    # Verify dispatcher ports with DIAG protocol probe
    disp_ports = [p for p, info in result["open_ports"].items()
                  if info["service"] == "dispatcher"]
    for port in disp_ports:
        if not _verify_sap_diag(host, port, timeout=min(timeout, 2.0)):
            del result["open_ports"][port]

    result["has_sap"] = len(result["open_ports"]) > 0

    # Pass 2: HANA SQL ports — only if SAP was found
    if result["has_sap"]:
        # Scan HANA ports for all instances in range
        hana_ports = []
        for inst_nr in range(instance_range[0], instance_range[1] + 1):
            inst_str = f"{inst_nr:02d}"
            hana_ports.append((30000 + inst_nr * 100 + 13, "hana_sql", inst_str))
            hana_ports.append((30000 + inst_nr * 100 + 15, "hana_sql", inst_str))

        hits2 = _do_scan(hana_ports)
        result["open_ports"].update(hits2)

    return result


def fast_scan_network(targets: list, instance_range: tuple = DEFAULT_INSTANCE_RANGE,
                      timeout: float = DEFAULT_TIMEOUT, threads: int = DEFAULT_THREADS,
                      cancel_event: threading.Event = None,
                      progress_callback=None, skip_alive: bool = False,
                      concurrent_hosts: int = 2, port_timeout: float = 2.0) -> list:
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
          f"dispatcher 32XX + gateway 33XX)")
    print(f"[*] Timeout: {timeout}s, Threads: {threads}")

    scan_start = time.time()

    # --- Stage 1: Alive sweep (skip for small target lists or if disabled) ---
    if not skip_alive and total > 3:
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

    # --- Stage 2: Sequential host scan with high per-host parallelism ---
    # Scanning one host at a time avoids socket contention between hosts
    # that causes missed ports. Each host gets 50 threads, so even hosts
    # with firewalled ports (200 ports * 2s timeout / 50 threads = 8s)
    # complete quickly.  The alive sweep already reduced 254 hosts to ~14,
    # so sequential scanning totals ~60-80s for a /24.
    found = []
    host_count = len(alive_hosts)
    port_threads = max(threads, 50)
    port_timeout = min(timeout, port_timeout)

    print(f"[*] SAP port scanning {host_count} alive hosts "
          f"({port_threads} threads/host, port timeout={port_timeout}s) ...")

    for idx, host in enumerate(alive_hosts):
        if cancel_event and cancel_event.is_set():
            print("[!] Scan cancelled")
            break

        r = fast_scan_host(host, instance_range, port_timeout, port_threads, cancel_event)
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
            print(f"[+] [{idx+1}/{host_count}] {host} — SAP found: "
                  f"{svc_str}  (total {elapsed:.1f}s)")
            found.append(r)
        else:
            print(f"[*] [{idx+1}/{host_count}] {host} — no SAP  "
                  f"(total {elapsed:.1f}s)")

        if progress_callback:
            progress_callback(idx + 1, host_count, host, len(found))

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
                       verbose: bool = False) -> dict:
    """Call RFC_SYSTEM_INFO (unauthenticated) to get OS, DB, kernel, hostname, SID.

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

            print(f"[+]   RFC_SYSTEM_INFO ({status}): SID={info['sid']}, "
                  f"Host={info['hostname']}, OS={info['os_type']}, "
                  f"DB={info['db_type']}, Kernel={info['kernel']}, "
                  f"Release={info['sap_release']}")
        else:
            # Even if the full parse failed, try to extract partial info
            for key in ("RFCSYSID", "RFCHOST2", "RFCHOST", "RFCOPSYS",
                        "RFCDBSYS", "RFCKERNRL", "RFCSAPRL"):
                val = result.get(key, "").strip()
                if val:
                    if key == "RFCSYSID":
                        info["sid"] = val
                    elif key in ("RFCHOST2", "RFCHOST"):
                        if not info["hostname"]:
                            info["hostname"] = val
                    elif key == "RFCOPSYS":
                        info["os_type"] = val
                    elif key == "RFCDBSYS":
                        info["db_type"] = val
                    elif key == "RFCKERNRL":
                        info["kernel"] = val
                    elif key == "RFCSAPRL":
                        info["sap_release"] = val

            if info["sid"]:
                print(f"[*]   RFC_SYSTEM_INFO ({status}): partial data — "
                      f"SID={info['sid']}, Host={info['hostname']}")
            else:
                methods = result.get("methods_tried", [])
                methods_ok = result.get("methods_success", [])
                print(f"[!]   RFC_SYSTEM_INFO failed (status={status}, "
                      f"methods tried={methods}, success={methods_ok})")

    except Exception as e:
        print(f"[-]   RFC_SYSTEM_INFO error on {host}:{gw_port}: {e}")
        logger.debug(f"RFC_SYSTEM_INFO failed for {host}:{gw_port}: {e}")

    return info


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

def _build_node_from_fast_scan(scan_result: dict, timeout: float = 10,
                               verbose: bool = False) -> SAPNode:
    """Build a SAPNode from fast scan results + system info enrichment."""
    host = scan_result["host"]
    open_ports = scan_result["open_ports"]

    # Collect instance numbers
    instance_nrs = sorted(set(
        v["instance_nr"] for v in open_ports.values()
    ))

    # Try to get system info from the first gateway port found
    sys_info = {}
    for port, info in sorted(open_ports.items()):
        if info["service"] == "gateway":
            sys_info = enrich_system_info(host, port, timeout=timeout, verbose=verbose)
            break

    # If no gateway, try dispatcher port + 100 (gateway is typically disp + 100)
    if not sys_info.get("sid"):
        for port, info in sorted(open_ports.items()):
            if info["service"] == "dispatcher":
                gw_port = port + 100  # 32XX -> 33XX
                print(f"[*]   No gateway found, trying dispatcher+100 = {gw_port}")
                sys_info = enrich_system_info(host, gw_port, timeout=timeout, verbose=verbose)
                if sys_info.get("sid"):
                    break

    sid = sys_info.get("sid", "") or f"UNK_{host.replace('.', '_')}"

    # Build instance info objects
    instances = []
    for inst_nr in instance_nrs:
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

    # Detect HANA from open ports (3XX13/3XX15) or RFC_SYSTEM_INFO (RFCDBSYS=HDB)
    has_hana_port = any(v["service"] == "hana_sql" for v in open_ports.values())
    db_type = sys_info.get("db_type", "")
    if has_hana_port and not db_type:
        db_type = "HDB"
        print(f"[+]   HANA database detected via SQL port")

    # Determine system type based on ports
    has_dispatcher = any(v["service"] == "dispatcher" for v in open_ports.values())
    has_saphost = any(v["service"] in ("saphost_http", "saphost_https")
                      for v in open_ports.values())
    if has_dispatcher:
        system_type = "ABAP"
    elif has_hana_port:
        system_type = "HANA"
    elif has_saphost:
        system_type = "SAP"
    else:
        system_type = "SAP"

    # Enumerate clients from first dispatcher port
    clients = []
    for port, info in sorted(open_ports.items()):
        if info["service"] == "dispatcher":
            client_list = enumerate_system_clients(host, port, timeout=timeout,
                                                   verbose=verbose)
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

    return node


def discover_systems(targets: list, instance_range: tuple = DEFAULT_INSTANCE_RANGE,
                     timeout: float = DEFAULT_TIMEOUT, threads: int = DEFAULT_THREADS,
                     fast_mode: bool = True, cancel_event: threading.Event = None,
                     progress_callback=None, verbose: bool = False,
                     skip_alive: bool = False, concurrent_hosts: int = 2,
                     port_timeout: float = 2.0) -> list:
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

            node = _build_node_from_fast_scan(result, timeout=timeout, verbose=verbose)
            nodes.append(node)

            # Summary line for this node
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
                                    progress_callback=progress_callback, verbose=verbose)

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
    db_type = sys_obj.db_type or ""
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
        landscape = SAPology.discover_systems(
            targets, instances, timeout=timeout, threads=threads,
            verbose=True,
            cancel_check=lambda: cancel_event.is_set() if cancel_event else False,
            client_enum=True,
        )

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
        landscape = SAPology.assess_vulnerabilities(
            landscape, gw_cmd="whoami", timeout=timeout + 2,
            verbose=True,
            cancel_check=lambda: cancel_event.is_set() if cancel_event else False,
        )

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
        landscape = SAPology.discover_systems(
            [host], instances, timeout=timeout, threads=threads,
            verbose=True,
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
            verbose=True,
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
