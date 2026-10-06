#!/usr/bin/env python3
# encoding: utf-8
"""
diag_login_screen_info (scapy-free port)

Gathers the information a SAP NetWeaver Application Server exposes during the
DIAG login handshake (hostname, instance, database name, default client,
login-screen text, ...).

This is a dependency-free re-implementation of pysap's
``examples/diag_login_screen_info.py``. Instead of building the packets with
scapy/pysap it assembles the raw SAP DIAG bytes by hand (``struct``) and talks
to the dispatcher over a plain socket, reusing the connection/NI helpers from
``sap_client_enum.py`` (``_diag_connect``, ``ni_send``, ``ni_recv``). This also
provides SAProuter support out of the box.

Flow:
  1. TCP connect to the SAP Dispatcher port (32XX), optionally through a
     SAProuter.
  2. Send a DIAG TERM_INI packet (DP header + DIAG header + ST_USER items).
  3. Read the NI-framed login-screen response.
  4. Walk the DIAG items and render:
       - technical server info (DBNAME, CPUNAME, KERNEL_VERSION, CLIENT, ...)
       - the text rendered on the login screen (DYNT atoms)

Usage:
    python3 sap_login_screen_texts.py -f <targets file> [-v]
    python3 sap_login_screen_texts.py -f <targets file> \\
        --route-string "/H/<router>/S/3299/W/<pass>"
    python3 sap_login_screen_texts.py -f <targets file> --search SAP PROD

The targets file holds one target per line, each either ``host:port`` or
``/H/host/S/port``. Without --search the login-screen text is dumped; with
--search the text is scanned for the given terms and hits (or "no matches")
are reported per target.

Author: port of Martin Gallo's (@martingalloar) pysap example.
"""

import socket
import struct
import random
import argparse
from collections import OrderedDict

# Reuse the connection and NI-framing helpers from the client-enum module.
#
# Dual-path import: SAPMAP loads modules both via the top-level
# ``modules/*`` sys.path injection (regular dev / CLI runs) AND via the
# packaged ``files.*`` layout used by the Bottle GUI backend when
# ``modules/__init__.py`` has not been imported yet.  The sibling
# ``sap_default_creds.py`` already uses this exact pattern — mirror it so
# the GUI's lazy import does not crash with ``ModuleNotFoundError`` the
# first time an operator triggers a logon-screen scan from the UI.
try:
    from sap_client_enum import _diag_connect, ni_send, ni_recv
except ImportError:
    from files.sap_client_enum import _diag_connect, ni_send, ni_recv


# ============================================================================
# DIAG protocol constants (from pysap SAPDiag.py / SAPDiagItems.py)
# ============================================================================

# Item types (diag_item_types)
DIAG_ITEM_SES = 0x01
DIAG_ITEM_EOM = 0x0C
DIAG_ITEM_APPL = 0x10
DIAG_ITEM_XMLBLOB = 0x11
DIAG_ITEM_APPL4 = 0x12

# Fixed sizes for the non-APPL/APPL4 item types (diag_item_get_length)
DIAG_ITEM_SIZES = {
    0x01: 16,   # SES
    0x02: 20,   # ICO
    0x03: 3,    # TIT
    0x07: 76,   # DiagMessage
    0x08: 0,    # OKC
    0x09: 22,   # CHL
    0x0a: 3,    # SFE
    0x0b: 2,    # SBA
    0x0c: 0,    # EOM
    0x13: 2,    # SLC
    0x15: 36,   # SBA2
}

# APPL/APPL4 IDs (diag_appl_ids)
DIAG_APPL_ST_USER = 0x04
DIAG_APPL_DYNN = 0x05
DIAG_APPL_ST_R3INFO = 0x06
DIAG_APPL_DYNT = 0x09
DIAG_APPL_VARINFO = 0x0c

# SIDs of interest (diag_appl_sids)
DIAG_USER_CONNECT = 0x02
DIAG_USER_SUPPORTDATA = 0x0b
DIAG_USER_LANGUAGE = 0x1b
DIAG_R3INFO_DBNAME = 0x02
DIAG_R3INFO_CPUNAME = 0x03
DIAG_R3INFO_CLIENT = 0x0c
DIAG_R3INFO_KERNEL_VERSION = 0x29
DIAG_VARINFO_SESSION_TITLE = 0x09
DIAG_VARINFO_SESSION_ICON = 0x0a
DIAG_DYNT_ATOM = 0x02

# Dynt atom etypes carrying displayable text (diag_atom_etypes)
ATOM_FNAME = 114                 # name_text (field name, e.g. RSYST-MANDT)
ATOM_FIELD1 = (121, 122, 123)    # EFIELD_1 / OFIELD_1 / KEYWORD_1
ATOM_FIELD2 = (130, 131, 132)    # EFIELD_2 / OFIELD_2 / KEYWORD_2

# ST_USER/SUPPORTDATA capability bitmask (SAP GUI 7.02, from pysap)
DIAG_SUPPORT_DATA = bytes.fromhex(
    "ff7ffe2ddab737d674087e1305971597eff23f8d0770ff0f0000000000000000"
)

# GUI language code -> human readable name
gui_lang = {
    "0": "Serbian", "1": "Chinese", "2": "Thai", "3": "Korean",
    "4": "Romanian", "5": "Slovenian", "6": "Croatian", "7": "Malaysian",
    "8": "Ukrainian", "9": "Estonian", "A": "Arabic", "B": "Hebrew",
    "C": "Czech", "D": "German", "E": "English", "F": "French",
    "G": "Greek", "H": "Hungarian", "I": "Italian", "J": "Japanese",
    "K": "Danish", "L": "Polish", "M": "trad.", "N": "Dutch",
    "O": "Norwegian", "P": "Portuguese", "Q": "Slovakian", "R": "Russian",
    "S": "Spanish", "T": "Turkish", "U": "Finnish", "V": "Swedish",
    "W": "Bulgarian", "X": "Lithuanian", "Y": "Latvian", "Z": "reserve",
    "a": "Afrikaans", "b": "Icelandic", "c": "Catalan", "d": "(Latin)",
    "i": "Indonesian",
}

KEY_LEN = 20
VAL_LEN = 60


# ============================================================================
# DIAG init packet construction (reproduces pysap's TERM_INI request)
# ============================================================================

def build_dp_header(terminal):
    """Build the 200-byte SAPDiagDP header (layout from pysap SAPDiag.py).

    Only the DIAG init packet carries the DP header.
    """
    dp = bytearray(200)
    struct.pack_into("!i", dp, 0, -1)     # request_id = -1
    dp[4] = 0x0A                           # retcode
    struct.pack_into("!i", dp, 11, -1)    # tid = -1
    struct.pack_into("!h", dp, 15, -1)    # uid = -1
    dp[17] = 0xFF                          # mode
    struct.pack_into("!i", dp, 18, -1)    # wp_id = -1
    struct.pack_into("!i", dp, 22, -1)    # wp_ca_blk = -1
    struct.pack_into("!i", dp, 26, -1)    # appc_ca_blk = -1
    # dp[30:34] -> length field, filled in by the caller (little-endian)
    struct.pack_into("!i", dp, 35, -1)    # unused1 = -1
    struct.pack_into("!h", dp, 39, -1)    # rq_id = -1
    dp[41:81] = b"\x20" * 40              # unused2 = spaces
    term = terminal.encode("ascii", "replace")[:15].ljust(15, b"\x00")
    dp[81:96] = term                       # terminal name
    dp[106:126] = b"\x20" * 20            # unused4 = spaces
    struct.pack_into("!i", dp, 134, -1)   # unused7 = -1
    dp[142] = 0x01                         # unused9
    return dp


def build_diag_init(terminal):
    """Build the DIAG TERM_INI packet (DP header + DIAG header + ST_USER items).

    Byte-compatible with the request emitted by pysap's SAPDiagConnection.init().
    """
    # DIAG header (8 bytes): mode, com_flag, mode_stat, err_no, msg_type,
    # msg_info, msg_rc, compress. The init handshake sets the TERM_INI flag
    # (0x10) in com_flag (byte index 1, offset 0xc9 on the wire).
    diag_hdr = bytearray(8)
    diag_hdr[1] = 0x10

    # Item 1: ST_USER/CONNECT -> protocol_version=200 (uncompressed),
    #         code_page=1100, ws_type=5001
    item1 = bytearray([DIAG_ITEM_APPL, DIAG_APPL_ST_USER, DIAG_USER_CONNECT])
    item1 += struct.pack("!H", 12)
    item1 += struct.pack("!III", 200, 1100, 5001)

    # Item 2: ST_USER/SUPPORTDATA -> 32-byte capability bitmask
    item2 = bytearray([DIAG_ITEM_APPL, DIAG_APPL_ST_USER, DIAG_USER_SUPPORTDATA])
    item2 += struct.pack("!H", len(DIAG_SUPPORT_DATA))
    item2 += DIAG_SUPPORT_DATA

    diag_data = bytes(diag_hdr) + bytes(item1) + bytes(item2)

    dp = build_dp_header(terminal)
    struct.pack_into("<I", dp, 30, len(diag_data))  # DP length (little-endian)
    return bytes(dp) + diag_data


# ============================================================================
# DIAG response parsing
# ============================================================================

def walk_items(payload):
    """Walk the DIAG items of a response payload.

    ``payload`` is the NI payload (DIAG header + items). Yields tuples
    ``(item_type, item_id, item_sid, value)``; item_id/item_sid are ``None``
    for non-APPL items.
    """
    if len(payload) < 8:
        return
    # Skip the 8-byte DIAG header. Compressed responses (compress byte != 0)
    # are not supported here (login screens are uncompressed, proto 200).
    if payload[7] != 0:
        raise ValueError("compressed DIAG response is not supported")
    blob = payload[8:]

    i, n = 0, len(blob)
    while i < n:
        itype = blob[i]
        i += 1
        if itype == DIAG_ITEM_EOM:
            break
        if itype in (DIAG_ITEM_APPL, DIAG_ITEM_APPL4):
            if i + 2 > n:
                break
            iid, sid = blob[i], blob[i + 1]
            i += 2
            if itype == DIAG_ITEM_APPL:
                ln = struct.unpack_from("!H", blob, i)[0]
                i += 2
            else:
                ln = struct.unpack_from("!I", blob, i)[0]
                i += 4
            yield (itype, iid, sid, blob[i:i + ln])
            i += ln
        elif itype == DIAG_ITEM_XMLBLOB:
            ln = struct.unpack_from("!I", blob, i)[0]
            i += 4
            yield (itype, None, None, blob[i:i + ln])
            i += ln
        else:
            size = DIAG_ITEM_SIZES.get(itype)
            if size is None:
                break  # unknown item type -> can't safely continue
            yield (itype, None, None, blob[i:i + size])
            i += size


def parse_dynt_atoms(value):
    """Parse a DYNT_ATOM item value into a list of atoms.

    Yields dicts with ``row``, ``col`` and the decoded ``name_text`` /
    ``field_text`` (whichever text field the atom carries).
    """
    i, n = 0, len(value)
    while i + 2 <= n:
        atom_length = struct.unpack_from("!H", value, i)[0]
        if atom_length < 13 or i + atom_length > n:
            break
        atom = value[i:i + atom_length]
        etype = atom[4]
        row = struct.unpack_from("!H", atom, 8)[0]
        col = struct.unpack_from("!H", atom, 10)[0]

        # Common header is 13 bytes; text location depends on the etype.
        name_text = b""
        field_text = b""
        if etype == ATOM_FNAME:
            name_text = atom[13:atom_length]
        elif etype in ATOM_FIELD1:
            # field1_flag1(1) dlen(1) mlen(1) maxnrchars(2) text(dlen)
            dlen = atom[14]
            field_text = atom[18:18 + dlen]
        elif etype in ATOM_FIELD2:
            # field2_flag1(2) dlen(1) mlen(1) maxnrchars(2) text(dlen)
            dlen = atom[15]
            field_text = atom[19:19 + dlen]

        yield {"row": row, "col": col, "name_text": name_text,
               "field_text": field_text}
        i += atom_length


# ============================================================================
# Value formatting / rendering (mirrors the original example)
# ============================================================================

def _decode_dyn_text(value):
    """Decode a DYNT-atom text payload to str, tolerating UTF-16LE kernels.

    The DIAG protocol advertises codepage=1100 (Latin-1 / UTF-8 lookalike)
    in the TERM_INI handshake, but modern SAP Unicode kernels (7.5x+)
    frequently return DYNT atom text as UTF-16LE on the wire regardless
    of that advertised codepage.  A naive ``value.decode('utf-8',
    errors='replace')`` turns the latter into ``"S\\x00A\\x00P\\x00..."``
    — the embedded NULs survive and the secrets regex catalogue misses
    every match.

    Discriminating heuristic: in UTF-16LE-encoded ASCII text, byte 1
    (the high byte of the first code unit) is ALWAYS 0, byte 3 is 0,
    byte 5 is 0, ...  In classic UTF-8 ASCII with NUL padding
    (DIAG fixed-width fields like DBNAME) the trailing bytes are
    NUL but byte 1 is NOT.  Checking ``data[1] == 0`` AND
    ``data[0]`` printable-ASCII catches real UTF-16LE text with no
    false positives on NUL-padded UTF-8 strings.

    Both decoders use ``errors='replace'`` so the function never
    raises; trailing NULs are stripped.
    """
    if not isinstance(value, (bytes, bytearray)):
        return value
    data = bytes(value)
    looks_utf16 = (
        len(data) >= 4
        and len(data) % 2 == 0
        and 0x20 <= data[0] <= 0x7E
        and data[1] == 0           # UTF-16LE ASCII char: high byte == 0
    )
    if looks_utf16:
        return data.decode("utf-16-le", errors="replace").rstrip("\x00")
    return data.decode("utf-8", errors="replace").rstrip("\x00")


def _to_str(value):
    """Decode item bytes to a string, dropping trailing NULs.

    Delegates to ``_decode_dyn_text`` so every call site that renders
    DIAG item bytes also gets the UTF-16LE / Unicode-kernel fallback —
    not just the DYNT atoms behind ``collect_text_info``.  SERV_INFO
    fields (DBNAME, CPUNAME, KERNEL_VERSION, LANGUAGE, SESSION_TITLE,
    SESSION_ICON) also come across as UTF-16LE on Unicode kernels and
    would otherwise print as ``"A\\x00B\\x00C"`` instead of ``"ABC"``.
    """
    return _decode_dyn_text(value)


def _fmt_language(value):
    code = _to_str(value)
    return gui_lang.get(code, "Language unknown (%s)" % code)


def _fmt_kernel(value):
    return ".".join(_to_str(value).split("\x00"))


# (item_id, item_sid) -> (label, formatter). Grouped by id in the same order
# pysap's get_item(["APPL"], ["ST_R3INFO", "ST_USER", "VARINFO"]) returns them.
SERV_INFO = OrderedDict([
    (DIAG_APPL_ST_R3INFO, OrderedDict([
        (DIAG_R3INFO_DBNAME, ("DBNAME", _to_str)),
        (DIAG_R3INFO_CPUNAME, ("CPUNAME", _to_str)),
        (DIAG_R3INFO_CLIENT, ("CLIENT", _to_str)),
        (DIAG_R3INFO_KERNEL_VERSION, ("KERNEL_VERSION", _fmt_kernel)),
    ])),
    (DIAG_APPL_ST_USER, OrderedDict([
        (DIAG_USER_LANGUAGE, ("LANGUAGE", _fmt_language)),
    ])),
    (DIAG_APPL_VARINFO, OrderedDict([
        (DIAG_VARINFO_SESSION_TITLE, ("SESSION_TITLE", _to_str)),
        (DIAG_VARINFO_SESSION_ICON, ("SESSION_ICON", _to_str)),
    ])),
])


def show_serv_info(items):
    """Print the technical server information from the login screen."""
    appl = [(iid, sid, val) for (itype, iid, sid, val) in items
            if itype == DIAG_ITEM_APPL]
    for want_id, sids in SERV_INFO.items():
        for iid, sid, val in appl:
            if iid == want_id and sid in sids:
                label, fmt = sids[sid]
                print(label.ljust(KEY_LEN) + "\t" + ("%s" % fmt(val)).ljust(VAL_LEN))


def collect_text_info(items):
    """Collect the login-screen text (DYNT atoms) as a list of (field, value).

    This is the data behind ``show_text_info`` / ``search_text_info`` so it can
    either be printed or searched for terms.
    """
    results = []
    for itype, iid, sid, val in items:
        if not (itype == DIAG_ITEM_APPL4 and iid == DIAG_APPL_DYNT
                and sid == DIAG_DYNT_ATOM):
            continue

        # First pass: collect var (field name) and value per screen position.
        dico = OrderedDict()
        for atom in parse_dynt_atoms(val):
            var = _to_str(atom["name_text"]) if atom["name_text"] else ""
            # Route the DYNT atom field_text through the same Unicode-
            # kernel-aware decoder (see ``_decode_dyn_text``) so operator-
            # posted banner strings on 7.5x+ systems don't come across
            # as ``"S\x00A\x00P\x00..."``.
            value = _decode_dyn_text(atom["field_text"]) \
                if atom["field_text"] else ""
            key = "%s_%s" % (atom["row"], atom["col"])
            if key not in dico:
                dico[key] = {"var": key, "value": value}
            if value:
                dico[key]["value"] = value.strip()
            if var:
                dico[key]["var"] = var

        # Second pass: bind the field name (left) to its value (right).
        for pos in dico:
            results.append((dico[pos]["var"], dico[pos]["value"]))
    return results


def show_text_info(items):
    """Print the text rendered on the login screen (DYNT atoms)."""
    for k, v in collect_text_info(items):
        if v:
            print(("%s" % k).ljust(KEY_LEN) + "\t" + ("%s" % v).ljust(VAL_LEN))


def search_text_info(items, terms):
    """Search the login-screen text for ``terms`` (case-insensitive).

    Returns a list of ``(term, field, value)`` tuples, one per match.
    """
    hits = []
    for k, v in collect_text_info(items):
        haystack = ("%s %s" % (k, v)).lower()
        for term in terms:
            if term.lower() in haystack:
                hits.append((term, k, v))
    return hits


# ============================================================================
# Hexdump helper (optional verbose output, matches pysap's debug format)
# ============================================================================

def hexdump(data):
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexs = " ".join("%02X" % b for b in chunk)
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print("%04X  %-47s  %s" % (off, hexs, ascii_))


# ============================================================================
# Main
# ============================================================================

def _random_ip():
    """Return a random IPv4 address string, used as the DIAG terminal name."""
    return "%d.%d.%d.%d" % (random.randint(1, 223), random.randint(0, 255),
                            random.randint(0, 255), random.randint(1, 254))


def parse_target_line(line):
    """Parse one line of the targets file into ``(host, port)``.

    Two forms are accepted:
      * ``host:port``
      * ``/H/host/S/port`` (NI route notation)

    Blank lines and ``#`` comments return ``None``. A malformed line raises
    ``ValueError``.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    if line.startswith("/"):
        # NI route notation: /H/<host>/S/<port>[/...]. Walk the tag/value pairs
        # and keep the last H (host) and S (port) seen.
        tokens = [t for t in line.split("/") if t != ""]
        host = port = None
        for i in range(0, len(tokens) - 1, 2):
            tag = tokens[i].upper()
            if tag == "H":
                host = tokens[i + 1]
            elif tag == "S":
                port = tokens[i + 1]
        if host is None or port is None:
            raise ValueError("cannot parse route-style target: %r" % line)
        return host, int(port)

    if ":" not in line:
        raise ValueError("expected host:port or /H/host/S/port: %r" % line)
    host, _, port = line.rpartition(":")
    if not host:
        raise ValueError("missing host in: %r" % line)
    return host, int(port)


def parse_options():
    description = ("Gather the information a SAP NetWeaver Application Server "
                  "provides during the DIAG login process (hostname, instance, "
                  "database name, default client, login-screen text, ...). "
                  "Scapy-free re-implementation of pysap's "
                  "diag_login_screen_info.py example.")
    parser = argparse.ArgumentParser(description=description)
    target = parser.add_argument_group("Target")
    target.add_argument("-f", "--targets-file", dest="targets_file", required=True,
                        help="File with one target per line, each either "
                             "host:port or /H/host/S/port")
    target.add_argument("--route-string", dest="route_string", default="",
                        help="SAProuter route prefix for connecting through a "
                             "SAP Router (e.g. /H/<router>/S/3299/W/<pass>)")
    misc = parser.add_argument_group("Misc options")
    misc.add_argument("--search", dest="search", nargs="+", metavar="TERM",
                      default=None,
                      help="Instead of dumping the login-screen text, search it "
                           "for these terms (case-insensitive) and report hits "
                           "per target")
    misc.add_argument("--terminal", dest="terminal", default=None,
                      help="Terminal name (default: local hostname)")
    misc.add_argument("--timeout", dest="timeout", type=int, default=10,
                      help="Connection timeout in seconds [%(default)d]")
    misc.add_argument("-v", "--verbose", dest="verbose", action="store_true",
                      help="Verbose output (hexdump request/response)")
    return parser.parse_args()


def fetch_login_items(host, port, options, terminal):
    """Run the DIAG login handshake against one target and return its items.

    This is the reusable core of the module: it connects (optionally through a
    SAProuter), sends the TERM_INI packet, reads the login screen and returns
    the parsed DIAG items as a list of ``(item_type, item_id, item_sid, value)``
    tuples. Returns ``None`` when the response is missing or too short to be a
    usable DIAG login screen.

    ``options`` only needs the ``route_string``, ``timeout`` and ``verbose``
    attributes, so callers outside the CLI can pass a lightweight namespace
    (e.g. ``types.SimpleNamespace(route_string="", timeout=10, verbose=False)``).
    """
    if options.route_string:
        print("[*] Connecting to %s:%d through SAProuter" % (host, port))
    else:
        print("[*] Connecting to %s:%d" % (host, port))
    sock = _diag_connect(host, port, options.timeout,
                         saprouter=options.route_string)

    try:
        # Send the init packet and read the login screen.
        init = build_diag_init(terminal)
        if options.verbose:
            print("[*] Sending %d bytes DIAG init (+4 NI header)" % len(init))
            hexdump(init)
        ni_send(sock, init)

        login_screen = ni_recv(sock, options.timeout)
        if options.verbose:
            print("[*] Received %d bytes login screen" % len(login_screen))
            hexdump(login_screen)

        if not login_screen or len(login_screen) < 50:
            print("[!] No / short login-screen response (%d bytes). The port "
                  "may not be a DIAG dispatcher, or SNC is enforced."
                  % len(login_screen))
            return None

        # ``walk_items`` raises ValueError on a compressed DIAG response
        # (byte 7 of the DIAG header != 0).  The pysap-era CLI tolerated
        # that because an uncaught exception just exited; from the GUI's
        # ``_bg`` worker it would kill the background task and leave the
        # operator with no diagnostic.  Catch it here and return None so
        # the caller surfaces a clean "compressed response, skipped"
        # verdict instead of crashing the whole scan.
        try:
            return list(walk_items(login_screen))
        except ValueError as exc:
            print("[!] DIAG response is not a parseable login screen "
                  "(%s).  Likely a compressed DIAG payload or an "
                  "unknown item type the parser cannot skip past; "
                  "treat as non-login-screen and move on." % exc)
            return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def process_target(host, port, options, terminal):
    """Run the DIAG handshake against one target and dump or search its text.

    Returns ``True`` on a usable login-screen response, ``False`` otherwise.
    """
    items = fetch_login_items(host, port, options, terminal)
    if items is None:
        return False

    if options.search:
        hits = search_text_info(items, options.search)
        if hits:
            print("[+] Matches for: %s" % ", ".join(options.search))
            for term, k, v in hits:
                print("    %-14s %s\t%s" % ("[%s]" % term, k, v))
        else:
            print("[-] No matches for: %s" % ", ".join(options.search))
    else:
        print("\n[+] Dumping technical information")
        show_serv_info(items)

        print("\n[+] Login Screen text")
        show_text_info(items)
        print("-" * KEY_LEN + "-" * VAL_LEN)
    return True


def main():
    options = parse_options()
    # Use a random IP address as the terminal name instead of the real
    # hostname, to avoid leaking the local machine's identity to the server.
    terminal = options.terminal or _random_ip()

    try:
        with open(options.targets_file, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError as exc:
        print("[!] Cannot open targets file %r: %s" % (options.targets_file, exc))
        return 1

    rc = 0
    for lineno, raw in enumerate(lines, 1):
        try:
            parsed = parse_target_line(raw)
        except ValueError as exc:
            print("[!] Skipping line %d: %s" % (lineno, exc))
            rc = 1
            continue
        if parsed is None:
            continue

        host, port = parsed
        print("\n" + "=" * (KEY_LEN + VAL_LEN))
        try:
            if not process_target(host, port, options, terminal):
                rc = 1
        except (OSError, ValueError) as exc:
            print("[!] %s:%d failed: %s" % (host, port, exc))
            rc = 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
