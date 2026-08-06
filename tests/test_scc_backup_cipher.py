"""SCC backup-zip cipher (issue #13, Approach E).

Reverse-engineered from BackupSecret.class / SecTools.class shipped
with SCC 2.19.0.2:

  esalt.bin (44B) = 12-byte nonce || AES-GCM(k=SHA-256(pw)) of 16-byte salt || 16-byte tag
  content file    = 12-byte nonce || AES-GCM(k=PBKDF2-SHA1(pw, salt, 65536, 16)) || 16-byte tag

Vector: encrypts the string
    "hello world\n"
with password "test123" using a known salt + nonce so the ciphertext is
deterministic and can be hard-coded here as a regression fixture.
"""
from __future__ import annotations

import hashlib
import io
import os
import struct
import tempfile
import zipfile

import pytest

# Guard: the crypto package should always be available (dependency of
# SAPMAP), but skip cleanly if the test env is minimal.
crypto = pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


PASSWORD = b"test123"
KNOWN_SALT = bytes(range(16))                # 00 01 02 … 0F
KNOWN_ESALT_NONCE = bytes(range(12))         # 00 01 02 … 0B
KNOWN_CONTENT_NONCE = bytes(reversed(range(12)))
PLAINTEXT = b"hello world\n"


def _build_test_backup_zip() -> bytes:
    """Build a minimal SCC-shaped backup zip with known nonces/salt so
    the ciphertext is reproducible."""
    # 1. esalt.bin = nonce || AES-GCM(SHA-256(pw), salt)
    salt_key = hashlib.sha256(PASSWORD).digest()
    esalt_body = AESGCM(salt_key).encrypt(
        KNOWN_ESALT_NONCE, KNOWN_SALT, None)
    esalt = KNOWN_ESALT_NONCE + esalt_body   # 12 + 16 + 16 = 44 bytes
    assert len(esalt) == 44

    # 2. content key = PBKDF2-SHA1(pw, salt, 65536, 16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA1(), length=16,
                      salt=KNOWN_SALT, iterations=65536)
    content_key = kdf.derive(PASSWORD)

    # 3. users.xml = nonce || AES-GCM(content_key, plaintext)
    users_body = AESGCM(content_key).encrypt(
        KNOWN_CONTENT_NONCE, PLAINTEXT, None)
    users = KNOWN_CONTENT_NONCE + users_body

    # 4. Zip everything up
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("esalt.bin", esalt)
        zf.writestr("config/users.xml", users)
    return buf.getvalue()


def test_backup_secret_approach_e_decrypts_known_vector(tmp_path):
    """Approach E must recover the plaintext from a known-key backup zip."""
    from sapmap_scc_keystore import try_decrypt_users_xml

    zip_bytes = _build_test_backup_zip()
    zip_path = tmp_path / "scc_backup.zip"
    zip_path.write_bytes(zip_bytes)

    loot_dir = tmp_path / "loot"
    out = try_decrypt_users_xml(str(zip_path), PASSWORD.decode(),
                                 str(loot_dir))
    assert out is not None, "decrypt returned None for a valid backup"
    assert os.path.exists(out)
    with open(out, "rb") as fh:
        recovered = fh.read()
    assert recovered == PLAINTEXT, (
        f"plaintext mismatch: got {recovered!r} expected {PLAINTEXT!r}")


def test_backup_secret_approach_e_wrong_password_returns_none(tmp_path):
    """Wrong password should produce None (GCM auth-tag verify fails)."""
    from sapmap_scc_keystore import try_decrypt_users_xml
    zip_path = tmp_path / "scc_backup.zip"
    zip_path.write_bytes(_build_test_backup_zip())
    loot_dir = tmp_path / "loot"
    assert try_decrypt_users_xml(
        str(zip_path), "wrong_password", str(loot_dir)) is None
