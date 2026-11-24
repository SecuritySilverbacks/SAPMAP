"""Issue #233 — recover the individual RSECTAB key from SSFS when there is no
`SSFS_<SID>.KEY` file, and never trust a wrongly-decrypted record.

When the DB secure store uses an individual key (TA SECSTORE), that RSECTAB key
is stored in the SSFS DAT under `SECSTORE_DB/KEY/…`.  With no `.KEY` file on
disk the SAP kernel falls back to the well-known default key (DEFAULT_KEY_HEX);
`download_and_decrypt` must use it so the record is read.  But `parse_ssfs_dat`
silently yields garbage on a wrong key, so we now gate on the decrypted
payload's embedded SHA1 integrity hash (`_ssfs_payload_valid`).

These tests exercise the real RSEC cipher + `parse_ssfs_dat` round-trip and the
key-selection / key-recovery helpers.  Note: the integrity-formula tests prove
SELF-CONSISTENCY (our-encode -> our-decode -> our-validate agree) and that the
implementation matches the pysap `SAPSSFSDecryptedPayload.valid` spec — they do
NOT prove conformance to bytes a real SAP kernel writes.  A golden vector from a
live capture (NPL/ABA) should be added when one is available; live confirmation
on 192.168.2.209 is the end-to-end check.
"""
import hashlib

import pytest

import sapmap_secstore as S
from sap_rsec_cipher import RSECCipher, rsec_decrypt


# --------------------------------------------------------------------------
# helpers: RSEC encrypt (inverse of rsec_decrypt's D(k3)->E(k2)->D(k1)) and
# synthetic SSFS payload / DAT record builders
# --------------------------------------------------------------------------

def _rsec_encrypt(blob: bytes, key: bytes) -> bytes:
    """Inverse of rsec_decrypt: E(k1) -> D(k2) -> E(k3)."""
    bl, kl = list(blob), list(key)
    k1, k2, k3 = kl[0:8], kl[8:16], kl[16:24]
    c = RSECCipher()
    r1 = c.crypt(RSECCipher.MODE_ENCODE, bl, k1, len(bl))
    r2 = c.crypt(RSECCipher.MODE_DECODE, r1, k2, len(r1))
    r3 = c.crypt(RSECCipher.MODE_ENCODE, r2, k3, len(r2))
    return bytes(r3)


def _make_payload(value: bytes) -> bytes:
    """Build a valid decrypted SAPSSFSDecryptedPayload carrying `value`:
    [0:8] preamble, [8:12] length, [12:32] SHA1 hash, [32:] value+padding,
    hash = SHA1(payload[0:12] + payload[32:]).  Padded to an 8-byte block."""
    preamble = b"\x00" * 8
    length = len(value).to_bytes(4, "big")
    payload = preamble + length + (b"\x00" * 20) + value   # placeholder hash
    if len(payload) % 8:
        payload += b"\x00" * (8 - len(payload) % 8)
    h = hashlib.sha1(payload[0:12] + payload[32:]).digest()
    return payload[:12] + h + payload[32:]


def _make_record(ident: str, data: bytes) -> bytes:
    """Build one SSFS DAT record (176-byte header + data) that parse_ssfs_dat
    will decrypt (is_plaintext=0)."""
    rec = bytearray(176)
    rec[0:12] = b"RSecSSFsData"
    rec[16] = 1                                   # type
    rec[24:88] = ident.encode("ascii")[:64].ljust(64, b" ")
    # is_deleted (144) / is_plaintext (145) stay 0; hmac (156:176) stays 0
    rec[12:16] = (176 + len(data)).to_bytes(4, "big")
    return bytes(rec) + data


_IDENT = "SECSTORE_DB/KEY/20250101_000000_TST_INSTALLER"
# RSECCipher is DES-based, so the low bit of each key byte is an ignored parity
# bit — a wrong key that differs ONLY in parity bits decrypts identically.  This
# wrong key is wholly unrelated (differs in effective key bits), so it is "wrong
# enough" to produce different plaintext and fail the integrity check.
_WRONG_KEY = bytes.fromhex("112233445566778899aabbccddeeff00112233445566778a")
_KEY24 = b"K" * 24


# --------------------------------------------------------------------------
# _ssfs_payload_valid — the integrity formula
# --------------------------------------------------------------------------

def test_payload_valid_accepts_correct_hash():
    assert S._ssfs_payload_valid(_make_payload(b"A" * 24)) is True


def test_payload_valid_rejects_value_mutation():
    p = bytearray(_make_payload(b"A" * 24))
    p[40] ^= 0x01                                 # flip a byte in the value
    assert S._ssfs_payload_valid(bytes(p)) is False


def test_payload_valid_rejects_hash_mutation():
    p = bytearray(_make_payload(b"A" * 24))
    p[12] ^= 0x01                                 # flip a byte in the hash
    assert S._ssfs_payload_valid(bytes(p)) is False


def test_payload_valid_too_short():
    assert S._ssfs_payload_valid(b"\x00" * 20) is False


# --------------------------------------------------------------------------
# round-trip through the REAL cipher + parse_ssfs_dat
# --------------------------------------------------------------------------

def test_rsec_encrypt_roundtrips():
    key = bytes.fromhex(S.DEFAULT_KEY_HEX)
    p = _make_payload(b"K" * 24)
    assert rsec_decrypt(_rsec_encrypt(p, key), key) == p


def _parsed(dat, key):
    return {ident: bytes.fromhex(h) for ident, h in S.parse_ssfs_dat(dat, key)}


def test_correct_default_key_validates_the_record():
    """No-key-file #233 case: the SECSTORE_DB/KEY record, encrypted with the
    SAP default key, decrypts and passes the integrity check."""
    key = bytes.fromhex(S.DEFAULT_KEY_HEX)
    payload = _make_payload(b"\x00" + b"K" * 24)   # 1-byte prefix + 24-byte key
    dat = _make_record(_IDENT, _rsec_encrypt(payload, key))
    rec = _parsed(dat, key)
    assert _IDENT in rec
    assert S._ssfs_payload_valid(rec[_IDENT]) is True
    # the 24-byte individual key is recoverable at the documented offset
    assert rec[_IDENT][33:57] == b"K" * 24


def test_wrong_key_fails_validation_no_garbage_adopted():
    """A wrong SSFS key decrypts to garbage that must FAIL the integrity gate,
    so the caller keeps the default instead of adopting a garbage RSECTAB key."""
    key = bytes.fromhex(S.DEFAULT_KEY_HEX)
    payload = _make_payload(b"\x00" + b"K" * 24)
    dat = _make_record(_IDENT, _rsec_encrypt(payload, key))
    rec = _parsed(dat, _WRONG_KEY)                 # decrypt with the WRONG key
    assert _IDENT in rec
    assert S._ssfs_payload_valid(rec[_IDENT]) is False


# --------------------------------------------------------------------------
# _ssfs_payload_valid edge cases
# --------------------------------------------------------------------------

def test_payload_valid_exactly_32_bytes_empty_value():
    assert S._ssfs_payload_valid(_make_payload(b"")) is True


def test_payload_valid_ignores_length_field_no_crash():
    # A huge declared length but a consistent hash still validates (the check
    # hashes the actual bytes, never trusting the length field) and never OOBs.
    p = bytearray(_make_payload(b"\x00" + _KEY24))
    p[8:12] = (0xFFFFFFFF).to_bytes(4, "big")
    p[12:32] = hashlib.sha1(bytes(p[0:12]) + bytes(p[32:])).digest()
    assert S._ssfs_payload_valid(bytes(p)) is True


# --------------------------------------------------------------------------
# _select_ssfs_key — three branches
# --------------------------------------------------------------------------

def test_select_ssfs_key_no_key_file_uses_default():
    k, src, used = S._select_ssfs_key(None)
    assert k == bytes.fromhex(S.DEFAULT_KEY_HEX)
    assert used is True and "default" in src.lower()


def test_select_ssfs_key_individual_from_key_file():
    kf = bytearray(92)
    kf[0:11] = b"RSecSSFsKey"
    kf[12:36] = b"I" * 24
    k, src, used = S._select_ssfs_key(bytes(kf))
    assert k == b"I" * 24 and used is False and "individual" in src.lower()


def test_select_ssfs_key_unparseable_falls_back_to_default():
    # issue #233 case (b): .KEY file present but extract_ssfs_key raises.
    k, src, used = S._select_ssfs_key(b"garbage not a key file")
    assert k == bytes.fromhex(S.DEFAULT_KEY_HEX) and used is True


# --------------------------------------------------------------------------
# _recover_rsectab_key_from_ssfs — gate scoped to the default-key path
# --------------------------------------------------------------------------

def _rec(value: bytes, corrupt: bool = False):
    p = bytearray(_make_payload(value))
    if corrupt:
        p[32] ^= 0x01     # flip the 1-byte prefix: breaks the hash, key [33:57] intact
    return (_IDENT, bytes(p).hex().upper())


def test_recover_default_path_valid_adopts():
    key, adopted = S._recover_rsectab_key_from_ssfs(
        [_rec(b"\x00" + _KEY24)], S.DEFAULT_KEY_HEX, used_default=True)
    assert adopted is True and key == _KEY24.hex()


def test_recover_default_path_invalid_keeps_default():
    key, adopted = S._recover_rsectab_key_from_ssfs(
        [_rec(b"\x00" + _KEY24, corrupt=True)], S.DEFAULT_KEY_HEX,
        used_default=True)
    assert adopted is False and key == S.DEFAULT_KEY_HEX


def test_recover_individual_path_invalid_still_adopts_no_regression():
    # On the individual-key path (from the system's own .KEY file) a failing
    # hash must NOT block adoption — preserves pre-#233 behaviour.
    key, adopted = S._recover_rsectab_key_from_ssfs(
        [_rec(b"\x00" + _KEY24, corrupt=True)], S.DEFAULT_KEY_HEX,
        used_default=False)
    assert adopted is True and key == _KEY24.hex()


def test_recover_default_path_continue_skips_bad_takes_later_good():
    recs = [_rec(b"\x00" + _KEY24, corrupt=True),
            _rec(b"\x00" + b"G" * 24)]
    key, adopted = S._recover_rsectab_key_from_ssfs(
        recs, S.DEFAULT_KEY_HEX, used_default=True)
    assert adopted is True and key == (b"G" * 24).hex()


def test_recover_no_secstore_db_key_record_returns_default():
    recs = [("DB_CONNECT/SYB/SADB_PASSWORD", _make_payload(b"x").hex().upper())]
    key, adopted = S._recover_rsectab_key_from_ssfs(
        recs, S.DEFAULT_KEY_HEX, used_default=True)
    assert adopted is False and key == S.DEFAULT_KEY_HEX
