#!/usr/bin/env python3
"""
SAP Default Credential Check via DIAG Protocol

Tests well-known SAP default user/password combinations against discovered
systems by sending DIAG login attempts to the SAP Dispatcher port (32XX).

WARNING: Failed login attempts can lock SAP accounts. This check is opt-in only.

Uses the proven DIAG packet construction from sap_client_enum.py (no code
duplication — imports build_diag_init, build_diag_login_packet, ni_send, ni_recv).

Usage:
    python3 sap_default_creds.py -t <host>:<port> -c 000,001,066
    python3 sap_default_creds.py -t <host>:<port> -c 000,001 -v

Author: Joris van de Vis
"""

import socket
import re
import sys
import time
import argparse

try:
    from sap_client_enum import (build_diag_init, build_diag_login_packet,
                                  ni_send, ni_recv)
except ImportError:
    from files.sap_client_enum import (build_diag_init, build_diag_login_packet,
                                        ni_send, ni_recv)


# ============================================================================
# Default Credentials Table
# ============================================================================

# Each entry: (severity, username, password, clients)
# clients: "ALL" = test on all enumerated clients, or specific client string
DEFAULT_CREDENTIALS = [
    ("CRITICAL", "SAP*",         "06071992",  "ALL"),
    ("CRITICAL", "SAP*",         "PASS",      "ALL"),
    ("CRITICAL", "DDIC",         "19920706",  "ALL"),
    ("CRITICAL", "IDEADM",       "admin",     "ALL"),
    ("CRITICAL", "idadmin",      "ides123",   "ALL"),
    ("HIGH",     "EARLYWATCH",   "SUPPORT",   "066"),
    ("MEDIUM",   "TMSADM",       "PASSWORD",  "ALL"),
    ("MEDIUM",   "TMSADM",       "$1Pawd2&",  "ALL"),
    ("MEDIUM",   "SAPCPIC",      "ADMIN",     "ALL"),
    ("HIGH",     "SMD_ADMIN",    "init1234",  "ALL"),
    ("HIGH",     "SMD_BI_RFC",   "init1234",  "ALL"),
    ("HIGH",     "SMD_RFC",      "init1234",  "ALL"),
    ("HIGH",     "SOLMAN_ADMIN", "init1234",  "ALL"),
    ("HIGH",     "SOLMAN_BTC",   "init1234",  "ALL"),
    ("HIGH",     "SAPSUPPORT",   "init1234",  "ALL"),
    ("MEDIUM",   "CONTENTSERV",  "init1234",  "ALL"),
    ("MEDIUM",   "SMD_AGT",      "init1234",  "ALL"),
]


# ============================================================================
# Login Response Classification
# ============================================================================

# Result codes
SUCCESS = "SUCCESS"
PASSWORD_CHANGE = "PASSWORD_CHANGE"
NO_AUTH_LOGON = "NO_AUTH_LOGON"
WRONG_PASSWORD = "WRONG_PASSWORD"
USER_LOCKED = "USER_LOCKED"
USER_NOT_EXIST = "USER_NOT_EXIST"
CLIENT_UNAVAIL = "CLIENT_UNAVAIL"
NO_DIALOG_USER = "NO_DIALOG_USER"
ERROR = "ERROR"

# Patterns matched against raw DIAG response bytes.
# Order matters: more specific patterns first.
#
# LANGUAGE NOTE (issue #36): SAP renders error text in the logon
# language, so English patterns silently miss on German, French,
# Spanish, Japanese systems.  We recognise errors via the
# language-independent SAP message class+number (below) first, and
# use these text patterns only as a fast fallback for English
# systems (and as a way to keep the older test corpus green).
_PATTERNS = [
    (re.compile(rb'Enter a new password', re.IGNORECASE),            PASSWORD_CHANGE),
    (re.compile(rb'No authorization to logon', re.IGNORECASE),       NO_AUTH_LOGON),
    (re.compile(rb'Name or password is incorrect', re.IGNORECASE),   WRONG_PASSWORD),
    (re.compile(rb'Password logon no longer possible', re.IGNORECASE), USER_LOCKED),
    (re.compile(rb'Log on with a dialog user', re.IGNORECASE),       NO_DIALOG_USER),
    (re.compile(rb'User .{1,40} is locked', re.IGNORECASE),         USER_LOCKED),
    (re.compile(rb'User .{1,40} does not exist', re.IGNORECASE),    USER_NOT_EXIST),
    (re.compile(rb'Client \d{3} is not available', re.IGNORECASE),  CLIENT_UNAVAIL),
    (re.compile(rb'Client does not exist', re.IGNORECASE),          CLIENT_UNAVAIL),
    # German (SAP GUI default on DACH systems) — covers ~half of
    # SAP's install base by count.  Same message-class-00 numbers,
    # just localised — kept as a fast-path complement to the
    # numbered-message match below.
    (re.compile(rb'Passwort ist abgelaufen', re.IGNORECASE),         PASSWORD_CHANGE),
    (re.compile(rb'Name oder Kennwort ist nicht korrekt', re.IGNORECASE), WRONG_PASSWORD),
    (re.compile(rb'Benutzer .{1,40} ist gesperrt', re.IGNORECASE),   USER_LOCKED),
    (re.compile(rb'Benutzer .{1,40} existiert nicht', re.IGNORECASE), USER_NOT_EXIST),
    (re.compile(rb'Mandant \d{3} ist nicht verf', re.IGNORECASE),    CLIENT_UNAVAIL),
    (re.compile(rb'Keine Berechtigung zur Anmeldung', re.IGNORECASE), NO_AUTH_LOGON),
]

# SAP message class + number matches — LANGUAGE-INDEPENDENT.
# The DIAG response encodes the error as a compact
# ``E\x00<class>\x00<number>\x00`` triple regardless of logon
# language.  Class 00 is the SAP system message class; the numbers
# below are stable across every SAP release and language pack.
# Reference: SE91, message class 00.
#
# From the issue #36 capture: ``E\x0000 \x00152\x00`` = wrong pw.
# The class field is padded to width, so allow trailing spaces
# before the null terminator.
_MSG_00_NUM = {
    b"042": USER_LOCKED,       # "User &1 is locked"
    b"046": PASSWORD_CHANGE,   # "Please choose a new password"
    b"152": WRONG_PASSWORD,    # "Name or password is incorrect"
    b"197": CLIENT_UNAVAIL,    # "Client &1 is not defined"
    b"198": USER_NOT_EXIST,    # "User &1 does not exist"
    b"199": NO_AUTH_LOGON,     # "No authorization to logon as this user"
    b"320": WRONG_PASSWORD,    # "Password has been changed by the administrator"
}
_MSG_00_RE = re.compile(
    rb"E\x00"          # severity 'E' (error) + null terminator
    rb"00[ \x00]+"     # message class '00' (padded, then null)
    rb"(\d{3})"        # capture the 3-digit number
    rb"[\x00 ]")       # null or space after
# Additional per-class matches for common non-00 login errors
# (kept small — most login errors are in class 00).
_MSG_OTHER_RE = re.compile(
    rb"E\x00(\d{2})[ \x00]+(\d{3})[\x00 ]")
_MSG_OTHER = {
    (b"SU", b"01"): NO_DIALOG_USER,   # class SU (user admin) — not authorised as dialog
}

# Login-screen input-field markers.  These RSYST-* dynpro field
# names are ONLY present when the DIAG response is re-displaying the
# logon dynpro — i.e. when logon was rejected and the user is being
# asked to try again.  A SUCCESSFUL logon returns the SAP Easy Access
# menu screen which contains NONE of these fields.
_LOGIN_SCREEN_RE = re.compile(
    rb"RSYST-(?:MANDT|BNAME|BCODE|LANGU|NEW_PASSWD|REPEAT_PW|SAPKENN|SAPUSER)")

# Results that mean the password was confirmed correct (= finding).
# NO_DIALOG_USER is NOT included: SAP rejects the user type BEFORE
# checking the password, so it does not confirm the password is correct.
FINDING_RESULTS = {SUCCESS, PASSWORD_CHANGE, NO_AUTH_LOGON}

RESULT_DESCRIPTIONS = {
    SUCCESS:         "Successful login",
    PASSWORD_CHANGE: "Password correct but expired (change required)",
    NO_AUTH_LOGON:   "Password correct but no dialog authorization",
    WRONG_PASSWORD:  "Wrong password",
    USER_LOCKED:     "User is locked",
    USER_NOT_EXIST:  "User does not exist",
    CLIENT_UNAVAIL:  "Client not available",
    NO_DIALOG_USER:  "Not a dialog user (password not checked by SAP)",
    ERROR:           "Connection error",
}

# Regex to detect SAP DIAG error text: an "E: " prefix followed by
# the error text.  Historical anchor ``[^A-Za-z]`` (issue #36)
# assumed the preceding DIAG length byte would always be
# non-alphabetic — but that byte is simply the *length* of the
# following string and can land anywhere in 0x00-0xFF including
# 0x41-0x5A ('A'-'Z') or 0x61-0x7A ('a'-'z').  When the message text
# is 65-90 chars (0x41-0x5A) or 97-122 chars (0x61-0x7A) the length
# prefix accidentally looks like a letter and the regex silently
# misses.  The German capture in the issue triggers exactly this:
# length prefix 0x47 = 'G'.
#
# Fix: drop the length-byte anchor.  We keep false-positive risk low
# by requiring 4+ characters after "E: " and only using this regex
# as a fallback — the language-independent numbered-message match
# and the login-screen field check both run first.
_DIAG_ERROR_RE = re.compile(rb'E: [\x20-\x7e]{4,120}')


def classify_login_response(resp_bytes):
    """Classify a DIAG login response into a result code.

    Returns (result_code, detail_string).

    Order of checks:
      1. Language-independent SAP message class+number match
         (E\\x00<class>\\x00<num>\\x00 triple in the DIAG frame).
         Works on English, German, French, Japanese, ... alike.
      2. English + German text patterns — fast path for known
         localizations; kept for backwards compatibility.
      3. Generic "E: <text>" DIAG error detection — anchor bug fixed.
      4. Login-screen field detection — if RSYST-BNAME / -BCODE /
         -MANDT / -LANGU appear, the server is re-rendering the
         logon dynpro (rejected).  Previously masked as SUCCESS by
         the size heuristic.
      5. Size heuristic — only after all rejection signals excluded.
    """
    if not resp_bytes:
        return (ERROR, "Empty response")

    # 1. Language-independent SAP message class+number
    m = _MSG_00_RE.search(resp_bytes)
    if m and m.group(1) in _MSG_00_NUM:
        result = _MSG_00_NUM[m.group(1)]
        return (result,
                f"{RESULT_DESCRIPTIONS[result]} (SAP msg 00-"
                f"{m.group(1).decode('ascii', 'replace')})")
    m = _MSG_OTHER_RE.search(resp_bytes)
    if m:
        key = (m.group(1), m.group(2))
        if key in _MSG_OTHER:
            result = _MSG_OTHER[key]
            return (result,
                    f"{RESULT_DESCRIPTIONS[result]} (SAP msg "
                    f"{key[0].decode('ascii', 'replace')}-"
                    f"{key[1].decode('ascii', 'replace')})")

    # 2. Known text patterns (English + German)
    for pattern, result in _PATTERNS:
        if pattern.search(resp_bytes):
            return (result, RESULT_DESCRIPTIONS[result])

    # 3. Generic DIAG "E: ..." error text (anchor-bug fixed)
    m = _DIAG_ERROR_RE.search(resp_bytes)
    if m:
        try:
            err_text = m.group(0).decode('utf-8', errors='replace').strip()
        except Exception:
            err_text = "SAP error screen"
        return (WRONG_PASSWORD, "Login rejected (%s)" % err_text)

    # 4. Login-screen field detection — if the server is re-rendering
    # the logon dynpro, RSYST-* input field names appear in the DIAG
    # payload.  A successful logon lands on SAP Easy Access which
    # contains NONE of these fields.
    if _LOGIN_SCREEN_RE.search(resp_bytes):
        return (WRONG_PASSWORD,
                "Login rejected (re-displayed logon dynpro — likely "
                "a non-English/German localization we don't yet have "
                "a text pattern for; the SAP msg-number match should "
                "have caught this — please open an issue with the "
                "raw response)")

    # 5. Size heuristic — real success returns SAP Easy Access
    # (~2 KB+ with no error markers and no login-screen fields).
    if len(resp_bytes) > 200:
        return (SUCCESS, RESULT_DESCRIPTIONS[SUCCESS])

    return (ERROR, "Inconclusive response (%d bytes)" % len(resp_bytes))


# ============================================================================
# Single Login Attempt
# ============================================================================

def try_login(host, port, client, user, password, timeout=5, saprouter="",
              terminal="sapscanner"):
    """Attempt a single DIAG login. One TCP connection per attempt.

    Args:
        saprouter: Optional SAProuter route string prefix for tunneled access.
        terminal: DIAG terminal-name string the server records in SAL
            Source/Terminal fields when rsau/ip_only=0 on the target.

    Returns (result_code, detail_string).
    """
    sock = None
    try:
        if saprouter:
            from sap_saprouter import connect_through_saprouter, build_route_for_port
            route = build_route_for_port(saprouter, host, port)
            sock = connect_through_saprouter(route, timeout=timeout)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

        # DIAG init handshake
        ni_send(sock, build_diag_init(terminal))
        resp = ni_recv(sock, timeout)
        if not resp or len(resp) < 100:
            return (ERROR, "DIAG init failed")

        # Send login packet
        client_str = client if isinstance(client, str) else "%03d" % client
        login_pkt = build_diag_login_packet(client_str, user, password)
        ni_send(sock, login_pkt)

        # Receive and classify response
        resp2 = ni_recv(sock, timeout + 2)
        return classify_login_response(resp2)

    except ConnectionRefusedError:
        return (ERROR, "Connection refused")
    except socket.timeout:
        return (ERROR, "Connection timeout")
    except OSError as e:
        return (ERROR, str(e))
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ============================================================================
# Full Default Credential Check
# ============================================================================

def check_default_credentials(host, port, clients, timeout=5, verbose=False,
                               cancel_check=None, saprouter="",
                               terminal="sapscanner"):
    """Check all default credentials against the given host/port/clients.

    Iterates credentials sequentially (no threading — avoids flooding/lockout).

    Args:
        host: target IP or hostname
        port: SAP Dispatcher port (e.g. 3200)
        clients: list of client strings (e.g. ["000", "001", "066"])
        timeout: per-connection timeout
        verbose: print progress for misses
        cancel_check: callable returning True to abort

    Returns:
        list of dicts: [{"username", "password", "client", "result", "severity", "detail"}]
        Only entries where the password was correct (SUCCESS, PASSWORD_CHANGE, NO_AUTH_LOGON).
    """
    findings = []
    locked_users = set()
    skip_users = set()  # users to skip entirely (locked, non-dialog type)

    for severity, user, password, target_clients in DEFAULT_CREDENTIALS:
        if cancel_check and cancel_check():
            break

        # Skip if user is already locked or known non-dialog type
        if user in skip_users:
            if verbose:
                print("  [-] Skipping %s (locked or non-dialog user)" % user)
            continue

        # Determine which clients to test
        if target_clients == "ALL":
            test_clients = clients
        else:
            # Specific client (e.g. "066") — only test if enumerated
            if target_clients in clients:
                test_clients = [target_clients]
            else:
                continue

        for client in test_clients:
            if cancel_check and cancel_check():
                break

            # Stop probing this user if locked or non-dialog
            if user in skip_users:
                break

            result, detail = try_login(host, port, client, user, password, timeout,
                                      saprouter=saprouter, terminal=terminal)

            if result == USER_LOCKED:
                skip_users.add(user)
                if verbose:
                    print("  [!] %s is locked on client %s — skipping further attempts" %
                          (user, client))
                break

            if result == NO_DIALOG_USER:
                skip_users.add(user)
                if verbose:
                    print("  [!] %s is not a dialog user on client %s — "
                          "password not verified, skipping" % (user, client))
                break

            if result in FINDING_RESULTS:
                print("  [+] DEFAULT CREDENTIAL: %s / %s on client %s (%s)" %
                      (user, password, client, detail))
                findings.append({
                    "username": user,
                    "password": password,
                    "client": client,
                    "result": result,
                    "severity": severity,
                    "detail": detail,
                })
            elif verbose:
                print("  [-] %s / %s on client %s: %s" %
                      (user, password, client, detail))

    return findings


# ============================================================================
# Standalone CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="SAP Default Credential Check via DIAG Protocol",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
WARNING: Failed login attempts can lock SAP accounts!
         Only use this tool with explicit authorization.

Examples:
  %(prog)s -t 192.168.1.100:3200 -c 000,001,066
  %(prog)s -t 192.168.1.100 -p 3200 -c 000 -v
        """)
    parser.add_argument("-t", "--target", required=True,
                        help="Target host or host:port")
    parser.add_argument("-p", "--port", type=int, default=None,
                        help="SAP Dispatcher port (default: from target)")
    parser.add_argument("-c", "--clients", required=True,
                        help="Comma-separated client numbers (e.g. 000,001,066)")
    parser.add_argument("--timeout", type=int, default=5,
                        help="Per-connection timeout in seconds (default: 5)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output (show all attempts)")

    args = parser.parse_args()

    # Parse target
    target = args.target
    if ":" in target:
        host, port_str = target.rsplit(":", 1)
        port = args.port or int(port_str)
    else:
        host = target
        port = args.port or 3200

    # Parse clients
    clients = [c.strip().zfill(3) for c in args.clients.split(",")]

    print("=" * 60)
    print("SAP Default Credential Check via DIAG Protocol")
    print("=" * 60)
    print("Target:  %s:%d" % (host, port))
    print("Clients: %s" % ", ".join(clients))
    print()
    print("WARNING: Failed login attempts can lock SAP accounts!")
    print()

    t0 = time.time()
    results = check_default_credentials(host, port, clients,
                                         timeout=args.timeout,
                                         verbose=args.verbose)
    elapsed = time.time() - t0

    print()
    print("-" * 60)
    if results:
        print("Found %d default credential(s):" % len(results))
        for r in results:
            print("  [%s] %s / %s on client %s (%s)" %
                  (r["severity"], r["username"], r["password"],
                   r["client"], r["detail"]))
    else:
        print("No default credentials found.")
    print("Time: %.1fs" % elapsed)
    print("-" * 60)

    return 0 if not results else 2


if __name__ == "__main__":
    sys.exit(main())
